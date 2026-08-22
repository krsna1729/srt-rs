#![no_main]

use libfuzzer_sys::fuzz_target;
use shiguredo_srt::{ConnectionOptions, SrtConnection, Timestamp};

// Drives one listener connection across a *sequence* of datagrams sliced
// out of the fuzz input, rather than decoding a single packet in
// isolation like the other two targets. State-dependent bugs -- e.g. the
// receiver's loss-detection/delivery logic only misbehaves for a specific
// *sequence* of sequence numbers arriving over an already-established
// connection -- are structurally unreachable from a single-packet decode
// fuzzer, since decode never gets the connection past the handshake.
//
// Each 2-byte little-endian length prefix bounds the next chunk fed to
// `feed_recv_buf`; a truncated trailing prefix or chunk just ends the
// run early. No output is ever assumed well-formed or checked; the only
// property under test is "this never panics", so errors from decode,
// crypto, or protocol-state mismatches are silently discarded exactly
// like production does via feed_recv_buf's `Result`.
fuzz_target!(|data: &[u8]| {
    let mut conn = SrtConnection::new_listener(ConnectionOptions::default());
    let mut now_us: u64 = 0;
    let mut rest = data;
    while rest.len() >= 2 {
        let len = u16::from_le_bytes([rest[0], rest[1]]) as usize;
        rest = &rest[2..];
        let take = len.min(rest.len());
        let (chunk, remainder) = rest.split_at(take);
        rest = remainder;

        now_us = now_us.saturating_add(1_000);
        let _ = conn.feed_recv_buf(chunk, Timestamp::from_micros(now_us));
        while conn.poll_event().is_some() {}
        while conn.poll_output().is_some() {}
    }
});
