//! Transport-layer destination-aware final-storage sink for outgoing datagrams.

use std::net::SocketAddr;

/// Result of attempting to push a datagram into a [`DatagramSink`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PushResult {
    /// The datagram was accepted and written directly into final storage.
    Pushed { len: usize },
    /// The sink cannot accept the datagram (e.g. pool capacity exhausted or in-flight limit reached).
    /// The unwritten output remains untouched in the protocol queue.
    Exhausted,
}

/// A transport-layer destination-aware final-storage sink for outgoing datagrams.
pub trait DatagramSink {
    /// Supply a peer address and expected wire length, then fill the final buffer
    /// directly with `fill`.
    ///
    /// If the sink is exhausted or cannot accept the packet, `fill` must NOT be called,
    /// and `PushResult::Exhausted` must be returned so the protocol output remains untouched.
    fn push_datagram<F>(
        &mut self,
        peer: SocketAddr,
        wire_len: usize,
        fill: F,
    ) -> Result<PushResult, srt_proto::Error>
    where
        F: FnOnce(&mut [u8]) -> Result<usize, srt_proto::Error>;
}

impl DatagramSink for Vec<(SocketAddr, Vec<u8>)> {
    fn push_datagram<F>(
        &mut self,
        peer: SocketAddr,
        wire_len: usize,
        fill: F,
    ) -> Result<PushResult, srt_proto::Error>
    where
        F: FnOnce(&mut [u8]) -> Result<usize, srt_proto::Error>,
    {
        let mut buf = vec![0u8; wire_len];
        let len = fill(&mut buf)?;
        buf.truncate(len);
        self.push((peer, buf));
        Ok(PushResult::Pushed { len })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct FiniteSink {
        capacity: usize,
        pushed: Vec<(SocketAddr, Vec<u8>)>,
    }

    impl DatagramSink for FiniteSink {
        fn push_datagram<F>(
            &mut self,
            peer: SocketAddr,
            wire_len: usize,
            fill: F,
        ) -> Result<PushResult, srt_proto::Error>
        where
            F: FnOnce(&mut [u8]) -> Result<usize, srt_proto::Error>,
        {
            if self.pushed.len() >= self.capacity {
                return Ok(PushResult::Exhausted);
            }
            let mut storage = vec![0u8; wire_len];
            let len = fill(&mut storage)?;
            storage.truncate(len);
            self.pushed.push((peer, storage));
            Ok(PushResult::Pushed { len })
        }
    }

    #[test]
    fn finite_sink_returns_exhausted_when_full() {
        let mut sink = FiniteSink {
            capacity: 1,
            pushed: Vec::new(),
        };
        let peer: SocketAddr = "127.0.0.1:9000".parse().unwrap();
        let res1 = sink
            .push_datagram(peer, 4, |buf| {
                buf[..4].copy_from_slice(b"test");
                Ok(4)
            })
            .unwrap();
        assert_eq!(res1, PushResult::Pushed { len: 4 });

        let mut fill_called = false;
        let res2 = sink
            .push_datagram(peer, 4, |_buf| {
                fill_called = true;
                Ok(4)
            })
            .unwrap();
        assert_eq!(res2, PushResult::Exhausted);
        assert!(
            !fill_called,
            "fill must NOT be called when sink is exhausted"
        );
    }
}
