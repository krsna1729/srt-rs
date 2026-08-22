//! Shared adapter plumbing between srt-protocol (sans-I/O) and
//! runtime-specific I/O.
//!
//! # Architecture
//!
//! Two layers:
//!
//! 1. **Shared utilities** (always compiled, no runtime deps): `is_ready`,
//!    `NativeTimer` type alias, `ManualTimerStore`. Protocol-level primitives
//!    that all runtimes need.
//!
//! 2. **Per-runtime `Conn` structs** (feature-gated): each wraps
//!    `SrtConnection` + runtime-specific socket + runtime-specific timer.
//!    Provides `fire_expired`, `drain_outputs`, `send_paced`,
//!    `recv_with_timeout`.
//!
//! # Design principle: no lowest common denominator
//!
//! Each runtime's `Conn` uses native primitives directly:
//! - mio: `ManualTimerStore` (no native timer wheel)
//! - tokio: `Pin<Box<tokio::time::Sleep>>` per connection
//! - smol: `Pin<Box<dyn Future>>` wrapping `smol::Timer`
//! - monoio: `Pin<Box<dyn Future>>` wrapping `monoio::time::sleep`
//! - glommio: `Pin<Box<dyn Future>>` wrapping `glommio::timer::sleep`
//! - compio: `Pin<Box<dyn Future>>` wrapping `compio::time::sleep`
//!
//! The `is_ready` noop-waker poll pattern is shared because it's genuinely
//! identical across all 5 async runtimes.

use shiguredo_srt::{ConnectionOutput, SrtConnection, TimerId, Timestamp};
use std::collections::HashMap;
use std::pin::Pin;
use std::task::{Context, Poll, RawWaker, RawWakerVTable};

// ---------------------------------------------------------------------------
// Shared utilities — always compiled, no runtime deps
// ---------------------------------------------------------------------------

/// Type alias for native timers across all async runtimes.
///
/// All async runtimes store their per-connection timer as
/// `Pin<Box<dyn Future<Output = ()>>>`. The concrete future type differs
/// per runtime, but they all coerce to this trait object.
pub type NativeTimer = Pin<Box<dyn std::future::Future<Output = ()>>>;

/// Check if a pinned future is ready by polling with a noop waker.
///
/// This is the core primitive for native timer expiry detection across all
/// async runtimes. The noop waker ensures the poll has no side effects.
pub fn is_ready(pin: &mut NativeTimer) -> bool {
    fn no_op(_: *const ()) {}
    fn clone(_: *const ()) -> RawWaker {
        RawWaker::new(std::ptr::null(), &VTABLE)
    }
    static VTABLE: RawWakerVTable = RawWakerVTable::new(clone, no_op, no_op, no_op);
    let waker = unsafe { std::task::Waker::from_raw(RawWaker::new(std::ptr::null(), &VTABLE)) };
    let mut cx = Context::from_waker(&waker);
    pin.as_mut().poll(&mut cx) == Poll::Ready(())
}

// ---------------------------------------------------------------------------
// ManualTimerStore — correct for mio, fallback for others
// ---------------------------------------------------------------------------

/// Manual timer store — the fallback for runtimes without a built-in timer
/// engine (mio) or for code that wants explicit control over timer lifecycle.
///
/// Simple `HashMap<TimerId, Timestamp>` with O(n) scan on fire.
/// Runtimes with native timer engines should use their own primitives.
pub struct ManualTimerStore {
    timers: HashMap<TimerId, Timestamp>,
}

impl ManualTimerStore {
    pub fn new() -> Self {
        Self {
            timers: HashMap::new(),
        }
    }

    /// Fire all timers whose deadline has passed.
    pub fn fire_expired(&mut self, now: Timestamp, conn: &mut SrtConnection) {
        let due = self.due_timers(now);
        for id in due {
            let _ = conn.handle_timer(id, now);
        }
    }

    /// Find and remove all expired timer IDs.
    pub fn due_timers(&mut self, now: Timestamp) -> Vec<TimerId> {
        let due: Vec<TimerId> = self
            .timers
            .iter()
            .filter(|(_, d)| now.as_micros() >= d.as_micros())
            .map(|(id, _)| *id)
            .collect();
        for id in &due {
            self.timers.remove(id);
        }
        due
    }

    /// Apply a `SetTimer` or `ClearTimer` output from `poll_output()`.
    pub fn apply_output(&mut self, output: &ConnectionOutput, now: Timestamp) {
        match output {
            ConnectionOutput::SetTimer {
                id,
                duration_micros,
            } => {
                self.timers.insert(*id, now.add_micros(*duration_micros));
            }
            ConnectionOutput::ClearTimer { id } => {
                self.timers.remove(id);
            }
            _ => {}
        }
    }

    /// Drain all pending outputs, applying timers and sending packets.
    /// The `send` closure is called once per `SendPacket` output.
    pub fn drain_outputs<F>(
        conn: &mut SrtConnection,
        timers: &mut Self,
        now: Timestamp,
        mut send: F,
    ) where
        F: FnMut(Vec<u8>),
    {
        while let Some(out) = conn.poll_output() {
            match out {
                ConnectionOutput::SendPacket(bytes) => send(bytes),
                output => timers.apply_output(&output, now),
            }
        }
    }

    /// Microseconds until the next timer fires.
    pub fn time_until_earliest(&self, now: Timestamp, default_us: u64) -> u64 {
        self.timers
            .values()
            .map(|d| d.as_micros().saturating_sub(now.as_micros()))
            .min()
            .unwrap_or(default_us)
    }
}

impl Default for ManualTimerStore {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Per-runtime Conn structs
// ---------------------------------------------------------------------------

#[cfg(feature = "mio")]
pub mod mio_transport {
    use super::ManualTimerStore;
    use libc;
    use shiguredo_srt::{ConnectionOutput, SrtConnection, Timestamp};
    use std::time::Duration;

    /// Per-connection state for mio: protocol + owned socket + manual timers.
    pub struct Conn {
        pub conn: SrtConnection,
        pub socket: mio::net::UdpSocket,
        pub timers: ManualTimerStore,
    }

    impl Conn {
        pub fn new(conn: SrtConnection, socket: mio::net::UdpSocket) -> Self {
            Self {
                conn,
                socket,
                timers: ManualTimerStore::new(),
            }
        }

        /// Fire expired manual timers.
        pub fn fire_expired(&mut self, now: Timestamp) {
            self.timers.fire_expired(now, &mut self.conn);
        }

        /// Drain all pending outputs: send packets, manage manual timers.
        /// Batches `SendPacket`s via `sendmmsg` (one syscall for up to 32
        /// datagrams). Returns true if any batch failed with
        /// `ConnectionRefused` (poisoned socket).
        pub fn drain_outputs(&mut self, now: Timestamp) -> bool {
            let mut batch: Vec<Vec<u8>> = Vec::with_capacity(32);
            let mut refused = false;
            while let Some(out) = self.conn.poll_output() {
                match out {
                    ConnectionOutput::SendPacket(bytes) => {
                        batch.push(bytes);
                        if batch.len() == 32 {
                            refused |= Self::flush_batch(&self.socket, &mut batch);
                        }
                    }
                    ConnectionOutput::SetTimer { .. } | ConnectionOutput::ClearTimer { .. } => {
                        self.timers.apply_output(&out, now);
                    }
                }
            }
            refused |= Self::flush_batch(&self.socket, &mut batch);
            refused
        }

        fn flush_batch(socket: &mio::net::UdpSocket, batch: &mut Vec<Vec<u8>>) -> bool {
            if batch.is_empty() {
                return false;
            }
            let mut msgs: Vec<libc::mmsghdr> = Vec::with_capacity(batch.len());
            let mut iovs: Vec<libc::iovec> = Vec::with_capacity(batch.len());
            for buf in batch.iter() {
                iovs.push(libc::iovec {
                    iov_base: buf.as_ptr() as *mut _,
                    iov_len: buf.len(),
                });
                msgs.push(libc::mmsghdr {
                    msg_hdr: unsafe { std::mem::zeroed() },
                    msg_len: 0,
                });
            }
            for (msg, iov) in msgs.iter_mut().zip(iovs.iter()) {
                msg.msg_hdr.msg_iov = iov as *const _ as *mut _;
                msg.msg_hdr.msg_iovlen = 1;
            }
            let fd = {
                use std::os::fd::AsRawFd;
                socket.as_raw_fd()
            };
            let sent = unsafe {
                libc::sendmmsg(
                    fd,
                    msgs.as_mut_ptr(),
                    batch.len() as u32,
                    libc::MSG_DONTWAIT,
                )
            };
            batch.clear();
            sent < 0
        }

        /// Compute poll timeout from next timer deadline.
        pub fn poll_timeout(&self, default: Duration, now: Timestamp) -> Duration {
            Duration::from_micros(
                self.timers
                    .time_until_earliest(now, default.as_micros() as u64),
            )
        }
    }
}

#[cfg(feature = "tokio")]
pub mod tokio_transport {
    use super::{NativeTimer, is_ready};
    use shiguredo_srt::{ConnectionEvent, ConnectionOutput, SrtConnection, Timestamp};
    use std::time::{Duration, Instant};
    use tokio::net::UdpSocket;

    /// Per-connection state for tokio: protocol + async socket + native timer.
    pub struct Conn {
        pub conn: SrtConnection,
        pub sock: UdpSocket,
        timer: Option<NativeTimer>,
    }

    impl Conn {
        pub fn new(conn: SrtConnection, sock: UdpSocket) -> Self {
            Self {
                conn,
                sock,
                timer: None,
            }
        }

        /// Poll the native timer to see if it has fired.
        pub fn fire_expired(&mut self) {
            if let Some(ref mut timer) = self.timer {
                if is_ready(timer) {
                    self.timer = None;
                }
            }
        }

        /// Drain all protocol outputs with native tokio timer management.
        pub async fn drain_outputs(&mut self, _now: Timestamp) {
            while let Some(out) = self.conn.poll_output() {
                match out {
                    ConnectionOutput::SendPacket(bytes) => {
                        let _ = self.sock.send(&bytes).await;
                    }
                    ConnectionOutput::SetTimer {
                        id: _,
                        duration_micros,
                    } => {
                        let deadline = Instant::now() + Duration::from_micros(duration_micros);
                        self.timer = Some(Box::pin(tokio::time::sleep_until(deadline.into())));
                    }
                    ConnectionOutput::ClearTimer { id: _ } => {
                        self.timer = None;
                    }
                }
            }
        }

        /// Recv with timeout, feed to protocol.
        pub async fn recv_with_timeout(
            &mut self,
            buf: &mut [u8],
            timeout: Duration,
            now: Timestamp,
        ) {
            if let Ok(Ok(n)) = tokio::time::timeout(timeout, self.sock.recv(buf)).await {
                let _ = self.conn.feed_recv_buf(&buf[..n], now);
            }
        }

        /// Send one paced packet.
        pub async fn send_paced(&mut self, payload: &[u8], now: Timestamp) -> Result<(), ()> {
            if !self.conn.can_send_with_pacing(now) {
                return Err(());
            }
            self.conn.send(payload, now).map_err(|_| ())?;
            self.drain_outputs(now).await;
            Ok(())
        }

        /// Full event-loop tick: fire timers, recv, drain, send paced.
        pub async fn tick(&mut self, buf: &mut [u8], payload: &[u8], now: Timestamp) -> TickResult {
            self.fire_expired();
            self.recv_with_timeout(buf, Duration::from_micros(100), now)
                .await;
            self.drain_outputs(now).await;

            let mut sent = 0u64;
            while self.send_paced(payload, now).await.is_ok() {
                sent += 1;
            }

            let mut events = Vec::new();
            while let Some(ev) = self.conn.poll_event() {
                events.push(ev);
            }

            TickResult { sent, events }
        }
    }

    pub struct TickResult {
        pub sent: u64,
        pub events: Vec<ConnectionEvent>,
    }
}

#[cfg(feature = "smol")]
pub mod smol_transport {
    use super::{NativeTimer, is_ready};
    use shiguredo_srt::{ConnectionEvent, ConnectionOutput, SrtConnection, Timestamp};
    use std::time::Duration;

    pub type UdpSocket = smol::Async<std::net::UdpSocket>;

    /// Per-connection state for smol: protocol + async socket + native timer.
    pub struct Conn {
        pub conn: SrtConnection,
        pub sock: UdpSocket,
        timer: Option<NativeTimer>,
    }

    impl Conn {
        pub fn new(conn: SrtConnection, sock: UdpSocket) -> Self {
            Self {
                conn,
                sock,
                timer: None,
            }
        }

        pub fn fire_expired(&mut self) {
            if let Some(ref mut timer) = self.timer {
                if is_ready(timer) {
                    self.timer = None;
                }
            }
        }

        pub async fn drain_outputs(&mut self, _now: Timestamp) {
            while let Some(out) = self.conn.poll_output() {
                match out {
                    ConnectionOutput::SendPacket(bytes) => {
                        let _ = self.sock.write_with(|inner| inner.send(&bytes)).await;
                    }
                    ConnectionOutput::SetTimer {
                        id: _,
                        duration_micros,
                    } => {
                        let d = Duration::from_micros(duration_micros);
                        self.timer = Some(Box::pin(async move {
                            smol::Timer::after(d).await;
                        }));
                    }
                    ConnectionOutput::ClearTimer { id: _ } => {
                        self.timer = None;
                    }
                }
            }
        }

        pub async fn recv_with_timeout(
            &mut self,
            buf: &mut [u8],
            timeout: Duration,
            now: Timestamp,
        ) {
            let recv_fut = async { self.sock.recv(buf).await.ok() };
            let timer_fut = async {
                smol::Timer::after(timeout).await;
                None
            };
            if let Some(n) = futures_lite::future::or(recv_fut, timer_fut).await {
                let _ = self.conn.feed_recv_buf(&buf[..n], now);
            }
        }

        pub fn try_recv(&self, buf: &mut [u8]) -> Option<std::io::Result<usize>> {
            match self.sock.get_ref().recv(buf) {
                Ok(n) => Some(Ok(n)),
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => None,
                Err(e) => Some(Err(e)),
            }
        }

        pub async fn send_paced(&mut self, payload: &[u8], now: Timestamp) -> Result<(), ()> {
            if !self.conn.can_send_with_pacing(now) {
                return Err(());
            }
            self.conn.send(payload, now).map_err(|_| ())?;
            self.drain_outputs(now).await;
            Ok(())
        }

        pub async fn tick(&mut self, buf: &mut [u8], payload: &[u8], now: Timestamp) -> TickResult {
            self.fire_expired();
            self.recv_with_timeout(buf, Duration::from_micros(100), now)
                .await;
            self.drain_outputs(now).await;

            let mut sent = 0u64;
            while self.send_paced(payload, now).await.is_ok() {
                sent += 1;
            }

            let mut events = Vec::new();
            while let Some(ev) = self.conn.poll_event() {
                events.push(ev);
            }

            TickResult { sent, events }
        }
    }

    pub struct TickResult {
        pub sent: u64,
        pub events: Vec<ConnectionEvent>,
    }
}

#[cfg(feature = "monoio")]
pub mod monoio_transport {
    use super::{NativeTimer, is_ready};
    use shiguredo_srt::{ConnectionEvent, ConnectionOutput, SrtConnection, Timestamp};
    use std::time::Duration;

    /// Per-connection state for monoio: protocol + owned-buffer socket + native timer.
    pub struct Conn {
        pub conn: SrtConnection,
        pub sock: monoio::net::udp::UdpSocket,
        timer: Option<NativeTimer>,
    }

    impl Conn {
        pub fn new(conn: SrtConnection, sock: monoio::net::udp::UdpSocket) -> Self {
            Self {
                conn,
                sock,
                timer: None,
            }
        }

        pub fn fire_expired(&mut self) {
            if let Some(ref mut timer) = self.timer {
                if is_ready(timer) {
                    self.timer = None;
                }
            }
        }

        pub async fn drain_outputs(&mut self, _now: Timestamp) {
            while let Some(out) = self.conn.poll_output() {
                match out {
                    ConnectionOutput::SendPacket(bytes) => {
                        let (_res, _buf) = self.sock.send(bytes).await;
                    }
                    ConnectionOutput::SetTimer {
                        id: _,
                        duration_micros,
                    } => {
                        let d = Duration::from_micros(duration_micros);
                        self.timer = Some(Box::pin(async move {
                            monoio::time::sleep(d).await;
                        }));
                    }
                    ConnectionOutput::ClearTimer { id: _ } => {
                        self.timer = None;
                    }
                }
            }
        }

        pub async fn recv_with_timeout(&mut self, timeout: Duration, now: Timestamp) {
            if let Ok((Ok(n), buf)) =
                monoio::time::timeout(timeout, self.sock.recv(vec![0u8; 2048])).await
            {
                let _ = self.conn.feed_recv_buf(&buf[..n], now);
            }
        }

        pub async fn send_paced(&mut self, payload: &[u8], now: Timestamp) -> Result<(), ()> {
            if !self.conn.can_send_with_pacing(now) {
                return Err(());
            }
            self.conn.send(payload, now).map_err(|_| ())?;
            self.drain_outputs(now).await;
            Ok(())
        }

        pub async fn tick(&mut self, payload: &[u8], now: Timestamp) -> TickResult {
            self.fire_expired();
            self.recv_with_timeout(Duration::from_micros(100), now)
                .await;
            self.drain_outputs(now).await;

            let mut sent = 0u64;
            while self.send_paced(payload, now).await.is_ok() {
                sent += 1;
            }

            let mut events = Vec::new();
            while let Some(ev) = self.conn.poll_event() {
                events.push(ev);
            }

            TickResult { sent, events }
        }
    }

    pub struct TickResult {
        pub sent: u64,
        pub events: Vec<ConnectionEvent>,
    }
}

#[cfg(feature = "glommio")]
pub mod glommio_transport {
    use super::{NativeTimer, is_ready};
    use shiguredo_srt::{ConnectionEvent, ConnectionOutput, SrtConnection, Timestamp};
    use std::time::Duration;

    /// Per-connection state for glommio: protocol + borrowed-buffer socket + native timer.
    pub struct Conn {
        pub conn: SrtConnection,
        pub sock: glommio::net::UdpSocket,
        timer: Option<NativeTimer>,
    }

    impl Conn {
        pub fn new(conn: SrtConnection, sock: glommio::net::UdpSocket) -> Self {
            Self {
                conn,
                sock,
                timer: None,
            }
        }

        pub fn fire_expired(&mut self) {
            if let Some(ref mut timer) = self.timer {
                if is_ready(timer) {
                    self.timer = None;
                }
            }
        }

        pub async fn drain_outputs(&mut self, _now: Timestamp) {
            while let Some(out) = self.conn.poll_output() {
                match out {
                    ConnectionOutput::SendPacket(bytes) => {
                        let _ = self.sock.send(&bytes).await;
                    }
                    ConnectionOutput::SetTimer {
                        id: _,
                        duration_micros,
                    } => {
                        let d = Duration::from_micros(duration_micros);
                        self.timer = Some(Box::pin(async move {
                            glommio::timer::sleep(d).await;
                        }));
                    }
                    ConnectionOutput::ClearTimer { id: _ } => {
                        self.timer = None;
                    }
                }
            }
        }

        pub async fn recv_with_timeout(
            &mut self,
            buf: &mut [u8],
            timeout: Duration,
            now: Timestamp,
        ) {
            let recv_fut = async { self.sock.recv_from(buf).await.ok() };
            let timer_fut = async {
                glommio::timer::sleep(timeout).await;
                None
            };
            if let Some((n, _addr)) = futures_lite::future::or(recv_fut, timer_fut).await {
                let _ = self.conn.feed_recv_buf(&buf[..n], now);
            }
        }

        pub fn try_recv(
            &self,
            buf: &mut [u8],
        ) -> Option<std::io::Result<(usize, std::net::SocketAddr)>> {
            match futures_lite::future::block_on(futures_lite::future::poll_once(
                self.sock.recv_from(buf),
            )) {
                Some(Ok((n, addr))) => Some(Ok((n, addr))),
                Some(Err(e)) => Some(Err(e.into())),
                None => None,
            }
        }

        pub async fn send_paced(&mut self, payload: &[u8], now: Timestamp) -> Result<(), ()> {
            if !self.conn.can_send_with_pacing(now) {
                return Err(());
            }
            self.conn.send(payload, now).map_err(|_| ())?;
            self.drain_outputs(now).await;
            Ok(())
        }

        pub async fn tick(&mut self, buf: &mut [u8], payload: &[u8], now: Timestamp) -> TickResult {
            self.fire_expired();
            self.recv_with_timeout(buf, Duration::from_micros(100), now)
                .await;
            self.drain_outputs(now).await;

            let mut sent = 0u64;
            while self.send_paced(payload, now).await.is_ok() {
                sent += 1;
            }

            let mut events = Vec::new();
            while let Some(ev) = self.conn.poll_event() {
                events.push(ev);
            }

            TickResult { sent, events }
        }
    }

    pub struct TickResult {
        pub sent: u64,
        pub events: Vec<ConnectionEvent>,
    }
}

#[cfg(feature = "compio")]
pub mod compio_transport {
    use super::{NativeTimer, is_ready};
    use shiguredo_srt::{ConnectionEvent, ConnectionOutput, SrtConnection, Timestamp};
    use std::time::Duration;

    /// Per-connection state for compio: protocol + owned-buffer socket + native timer.
    pub struct Conn {
        pub conn: SrtConnection,
        pub sock: compio::net::UdpSocket,
        timer: Option<NativeTimer>,
    }

    impl Conn {
        pub fn new(conn: SrtConnection, sock: compio::net::UdpSocket) -> Self {
            Self {
                conn,
                sock,
                timer: None,
            }
        }

        pub fn fire_expired(&mut self) {
            if let Some(ref mut timer) = self.timer {
                if is_ready(timer) {
                    self.timer = None;
                }
            }
        }

        pub async fn drain_outputs(&mut self, _now: Timestamp) {
            while let Some(out) = self.conn.poll_output() {
                match out {
                    ConnectionOutput::SendPacket(bytes) => {
                        let _ = self.sock.send(bytes).await;
                    }
                    ConnectionOutput::SetTimer {
                        id: _,
                        duration_micros,
                    } => {
                        let d = Duration::from_micros(duration_micros);
                        self.timer = Some(Box::pin(async move {
                            compio::time::sleep(d).await;
                        }));
                    }
                    ConnectionOutput::ClearTimer { id: _ } => {
                        self.timer = None;
                    }
                }
            }
        }

        pub async fn send_paced(&mut self, payload: &[u8], now: Timestamp) -> Result<(), ()> {
            if !self.conn.can_send_with_pacing(now) {
                return Err(());
            }
            self.conn.send(payload, now).map_err(|_| ())?;
            self.drain_outputs(now).await;
            Ok(())
        }

        pub async fn tick(&mut self, payload: &[u8], now: Timestamp) -> TickResult {
            self.fire_expired();
            self.drain_outputs(now).await;

            let mut sent = 0u64;
            while self.send_paced(payload, now).await.is_ok() {
                sent += 1;
            }

            let mut events = Vec::new();
            while let Some(ev) = self.conn.poll_event() {
                events.push(ev);
            }

            TickResult { sent, events }
        }
    }

    pub struct TickResult {
        pub sent: u64,
        pub events: Vec<ConnectionEvent>,
    }
}
