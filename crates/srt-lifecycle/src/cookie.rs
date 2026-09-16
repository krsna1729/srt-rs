//! SYN-cookie worker ownership encoding.

/// Most workers whose index can be carried in a SYN cookie.
///
/// The index occupies the low byte, so a deployment with more acceptor
/// threads than this cannot use cookie routing and must fall back to
/// leaving flows wherever the kernel put them.
pub const MAX_COOKIE_WORKERS: usize = 256;

/// Build the SYN cookie a listener should issue for a peer, with the
/// owning worker's index encoded in its low byte.
///
/// SRT's handshake is INDUCTION -> response -> CONCLUSION -> response.
/// The listener chooses the cookie in the INDUCTION response and the
/// caller echoes it in CONCLUSION, so with several acceptors sharing one
/// SO_REUSEPORT port, the cookie is what lets whichever acceptor the
/// kernel happens to hand the CONCLUSION to discover who owns the
/// half-open handshake and forward it there. Without it, a group change
/// between the two caller packets (which promoting a connection causes --
/// see crates/srt-transport/tests/reuseport_rehash.rs) strands the
/// handshake on an acceptor holding no state for it.
///
/// `peer_hash` supplies the upper 24 bits so cookies still differ per
/// peer rather than being a constant per worker. This is routing
/// metadata, not a security boundary: the cookie remains as guessable as
/// whatever `peer_hash` provides.
#[must_use]
pub fn cookie_for_worker(worker: usize, peer_hash: u32) -> u32 {
    (peer_hash & 0xFFFF_FF00) | ((worker as u32) & 0xFF)
}

/// Recover the owning worker index from a cookie seen on the wire.
///
/// Returns `None` when the encoded index is not a valid worker for this
/// listener, which covers both a cookie this listener never issued and a
/// `worker_count` beyond [`MAX_COOKIE_WORKERS`]. Callers should treat
/// `None` as "no routing information" and handle the datagram locally
/// rather than dropping it.
#[must_use]
pub fn worker_from_cookie(cookie: u32, worker_count: usize) -> Option<usize> {
    if worker_count == 0 || worker_count > MAX_COOKIE_WORKERS {
        return None;
    }
    let worker = (cookie & 0xFF) as usize;
    (worker < worker_count).then_some(worker)
}
