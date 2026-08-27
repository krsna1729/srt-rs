use shiguredo_srt::SrtConnection;

/// A connection handed from the acceptor that completed its handshake to
/// the thread that will service it.
///
/// The socket is a plain `std::net::UdpSocket` and the protocol state is
/// a bare `SrtConnection` on purpose: both are `Send`, whereas every
/// runtime's own `Conn` wrapper holds a native timer future that is not.
/// Shipping the parts and rebuilding the wrapper on the receiving thread
/// makes the cross-thread move correct by construction rather than by
/// convention -- there is no way to accidentally put a `!Send` timer in
/// this struct, because the type does not have a field for one.
pub struct Handoff {
    pub socket: std::net::UdpSocket,
    pub conn: SrtConnection,
}

/// What one acceptor sends to another, or to a dedicated worker.
///
/// This is the whole acceptor-to-worker protocol for the reuseport
/// ingress strategies, in one definition rather than one per runtime
/// adapter.
pub enum WorkerMessage {
    /// Take ownership of this fully-established connection.
    Handoff(Box<Handoff>),
    /// A handshake datagram the kernel delivered to the wrong acceptor.
    /// Its SYN cookie names the acceptor that owns the half-open
    /// handshake, so it is forwarded there rather than answered locally
    /// (cookie validation would reject it) or dropped (which costs a
    /// handshake retry). See `srt_lifecycle::cookie_for_worker`.
    Handshake {
        peer: std::net::SocketAddr,
        data: Vec<u8>,
    },
    /// Admission is over and `total` connections were sent in all, so a
    /// worker can tell "no more are coming" from "none have arrived yet"
    /// instead of guessing from a wall clock. Only the single-acceptor
    /// strategy sends this; where every acceptor is also a worker there
    /// is no separate admission-done moment to report.
    Finished { total: usize },
}
