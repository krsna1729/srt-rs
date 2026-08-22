//! Minimal, blocking, single-connection UDP driver for interop testing.
//!
//! Deliberately NOT the eventual Phase 6/7 production Driver (no epoll,
//! no thread pool, no shard/poller reuse) -- this exists only to pump one
//! `SrtConnection` against a real UDP socket long enough to prove wire-level
//! interop against real libsrt. See docs/srt-pure-rust-plan.md Phase 3.

use shiguredo_srt::{ConnectionEvent, ConnectionOutput, SrtConnection, TimerId, Timestamp};
use std::collections::HashMap;
use std::net::UdpSocket;
use std::time::Instant;

pub struct DriverResult {
    pub connected: bool,
    pub events: Vec<String>,
    pub received_payloads: Vec<Vec<u8>>,
}

/// Drive `conn` against `socket` until `Connected`, a fatal error/disconnect,
/// or `deadline` elapses. `on_connect`, if given, runs once right after
/// entering `Connected` (e.g. to send a payload). After connecting, the
/// driver keeps running for `post_connect_linger` before returning, so it
/// can actually observe `DataReceived` events (collected into
/// `DriverResult::received_payloads`) instead of exiting the instant the
/// handshake completes.
pub fn run(
    conn: &mut SrtConnection,
    socket: &UdpSocket,
    start: Instant,
    deadline: std::time::Duration,
    post_connect_linger: std::time::Duration,
    mut on_connect: impl FnMut(&mut SrtConnection, &UdpSocket, Timestamp),
) -> DriverResult {
    let mut timers: HashMap<TimerId, Timestamp> = HashMap::new();
    let mut events = Vec::new();
    let mut received_payloads = Vec::new();
    let mut connected = false;
    let mut connect_action_done = false;
    let mut linger_until: Option<Instant> = None;
    socket
        .set_read_timeout(Some(std::time::Duration::from_millis(50)))
        .expect("set_read_timeout");

    let now = |start: Instant| Timestamp::from_micros(start.elapsed().as_micros() as u64);

    drain_outputs(conn, socket, &mut timers, now(start));

    let mut buf = [0u8; 2048];
    loop {
        if start.elapsed() >= deadline {
            events.push("TIMEOUT".to_string());
            break;
        }

        match socket.recv(&mut buf) {
            Ok(n) => {
                let t = now(start);
                if let Err(e) = conn.feed_recv_buf(&buf[..n], t) {
                    events.push(format!("feed_recv_buf error: {e}"));
                }
            }
            Err(e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut => {}
            Err(e) => {
                events.push(format!("recv error: {e}"));
                break;
            }
        }

        let t = now(start);
        let due: Vec<TimerId> = timers
            .iter()
            .filter(|(_, deadline)| t.as_micros() >= deadline.as_micros())
            .map(|(id, _)| *id)
            .collect();
        for id in due {
            timers.remove(&id);
            if let Err(e) = conn.handle_timer(id, t) {
                events.push(format!("handle_timer({id:?}) error: {e}"));
            }
        }

        drain_outputs(conn, socket, &mut timers, t);

        while let Some(ev) = conn.poll_event() {
            match &ev {
                ConnectionEvent::Connected => {
                    connected = true;
                    events.push("Connected".to_string());
                }
                ConnectionEvent::DataReceived { payload, .. } => {
                    events.push(format!("DataReceived({} bytes)", payload.len()));
                    received_payloads.push(payload.clone());
                }
                ConnectionEvent::Disconnected { reason } => {
                    events.push(format!("Disconnected: {reason}"));
                }
                ConnectionEvent::Error(msg) => {
                    events.push(format!("Error: {msg}"));
                }
                other => events.push(format!("{other:?}")),
            }
        }

        if connected && !connect_action_done {
            connect_action_done = true;
            let t = now(start);
            on_connect(conn, socket, t);
            drain_outputs(conn, socket, &mut timers, t);
            linger_until = Some(Instant::now() + post_connect_linger);
        }

        if let Some(until) = linger_until
            && Instant::now() >= until
        {
            break;
        }
    }

    DriverResult {
        connected,
        events,
        received_payloads,
    }
}

/// Exposed so long-running drivers (e.g. the loss-caller/loss-listener
/// sustained-throughput binaries) can reuse the same output-pumping logic
/// instead of duplicating it.
pub fn drain_outputs(
    conn: &mut SrtConnection,
    socket: &UdpSocket,
    timers: &mut HashMap<TimerId, Timestamp>,
    now: Timestamp,
) {
    while let Some(out) = conn.poll_output() {
        match out {
            ConnectionOutput::SendPacket(bytes) => {
                let _ = socket.send(&bytes);
            }
            ConnectionOutput::SetTimer {
                id,
                duration_micros,
            } => {
                timers.insert(id, now.add_micros(duration_micros));
            }
            ConnectionOutput::ClearTimer { id } => {
                timers.remove(&id);
            }
        }
    }
}
