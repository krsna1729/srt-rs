//! SYN cookies: a listener's stateless answer to INDUCTION.
//!
//! SRT's handshake is INDUCTION -> response -> CONCLUSION -> response. The
//! listener chooses the cookie in the INDUCTION response and the caller
//! echoes it in CONCLUSION, so the listener can answer INDUCTION from no
//! state at all and keep none until a CONCLUSION proves the caller received
//! that answer at the address it claims (libsrt `processConnectRequest`,
//! core.cpp:11755-11850, with its `bake()` cookie). A cookie is a keyed MAC
//! over the caller's address, its socket ID and a coarse time bucket, so it
//! cannot be guessed from the wire and expires on its own.
//!
//! With several acceptors sharing one `SO_REUSEPORT` port, the kernel can
//! hand the CONCLUSION to a different acceptor than the INDUCTION (promoting
//! a connection rehashes the group -- see
//! crates/srt-transport/tests/reuseport_rehash.rs). The issuing acceptor's
//! index is therefore mixed into the cookie: any acceptor holding the same
//! key recovers it while verifying, and forwards the CONCLUSION there.

use std::net::{IpAddr, SocketAddr};

use hmac::{Hmac, KeyInit, Mac};
use sha1::Sha1;

/// Most acceptors one cookie key serves. A forged cookie verifies for one
/// of `worker_count` indexes in each of two buckets, so the cap keeps a
/// blind guess at no better than 2 * 256 in 2^32.
pub const MAX_COOKIE_WORKERS: usize = 256;

/// Length of a cookie time bucket in seconds. A cookie verifies in the
/// bucket it was issued in and the next one, so it lives between one and
/// two buckets: libsrt bakes per minute and also accepts the previous
/// minute's cookie (core.cpp:11630, 11829-11840).
pub const COOKIE_BUCKET_SECS: u64 = 60;

/// The secret behind a listener's SYN cookies.
///
/// Takes values and returns decisions: the caller supplies the secret and
/// the current bucket (`elapsed_seconds / COOKIE_BUCKET_SECS` on a clock
/// every acceptor sharing the key agrees on).
#[derive(Clone)]
pub struct CookieKey {
    mac: Hmac<Sha1>,
}

impl CookieKey {
    /// A key from 32 secret bytes; use fresh OS randomness.
    #[must_use]
    pub fn new(secret: &[u8; 32]) -> Self {
        Self {
            mac: Hmac::<Sha1>::new_from_slice(secret).expect("HMAC takes a key of any length"),
        }
    }

    /// The cookie acceptor `worker` issues to the caller socket
    /// `caller_socket_id` at `peer` during `bucket`.
    #[must_use]
    pub fn issue(
        &self,
        worker: usize,
        peer: SocketAddr,
        caller_socket_id: u32,
        bucket: u64,
    ) -> u32 {
        self.tag(peer, caller_socket_id, bucket) ^ worker as u32
    }

    /// The acceptor that issued `cookie` to `caller_socket_id` at `peer`,
    /// if one of `worker_count` acceptors issued it during `bucket` or the
    /// bucket before. `None` for a forged, expired or replayed-elsewhere
    /// cookie: one issued to another address or caller socket.
    #[must_use]
    pub fn verify(
        &self,
        cookie: u32,
        peer: SocketAddr,
        caller_socket_id: u32,
        bucket: u64,
        worker_count: usize,
    ) -> Option<usize> {
        let worker_count = worker_count.min(MAX_COOKIE_WORKERS);
        [bucket, bucket.wrapping_sub(1)]
            .into_iter()
            .find_map(|bucket| {
                let worker = (cookie ^ self.tag(peer, caller_socket_id, bucket)) as usize;
                (worker < worker_count).then_some(worker)
            })
    }

    fn tag(&self, peer: SocketAddr, caller_socket_id: u32, bucket: u64) -> u32 {
        let mut mac = self.mac.clone();
        match peer.ip() {
            IpAddr::V4(ip) => {
                mac.update(&[4]);
                mac.update(&ip.octets());
            }
            IpAddr::V6(ip) => {
                mac.update(&[6]);
                mac.update(&ip.octets());
            }
        }
        mac.update(&peer.port().to_be_bytes());
        mac.update(&caller_socket_id.to_be_bytes());
        mac.update(&bucket.to_be_bytes());
        let tag = mac.finalize().into_bytes();
        u32::from_be_bytes([tag[0], tag[1], tag[2], tag[3]])
    }
}

impl std::fmt::Debug for CookieKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("CookieKey { .. }")
    }
}
