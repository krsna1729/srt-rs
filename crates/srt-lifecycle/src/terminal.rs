//! Runtime-independent terminal-state policy.

use std::time::{Duration, Instant};

/// Is a connection done -- either it never completed its handshake within
/// the connect window, it ran its full stream and hit its own deadline,
/// or it went idle past `idle_grace` -- such that a worker no longer
/// needs to service it to make progress?
///
/// Pure connection-lifecycle policy, independent of transport: any
/// listener tracking a connection from admission through completion
/// (whether or not it ever gets a dedicated promoted socket) needs this
/// exact three-way check, and every one of ours used to reimplement it
/// by hand.
///
/// - `stream_deadline`: `None` until the connection's first `Connected`
///   event; the caller sets it then (typically `now + stream_length`).
///   While `None`, the only way to become terminal is running out the
///   connect window (`now >= connect_deadline`) without ever connecting.
/// - `connected`: the transport's *live* connected flag (false once a
///   `Disconnected` event fires) -- distinct from "ever connected"
///   (`stream_deadline.is_some()`), which callers should use instead for
///   final success/delivery reporting: a session that streamed
///   everything and then legitimately tripped the peer's own idle
///   timeout is still a successful connection, not a failed one.
#[must_use]
pub fn is_terminal(
    connected: bool,
    stream_deadline: Option<Instant>,
    last_data_at: Instant,
    now: Instant,
    connect_deadline: Instant,
    idle_grace: Duration,
) -> bool {
    match stream_deadline {
        Some(deadline) => {
            !connected
                || now >= deadline
                || now.saturating_duration_since(last_data_at) >= idle_grace
        }
        None => now >= connect_deadline,
    }
}
