//! Reusable readiness-runtime batched UDP I/O.
//!
//! Low-level `recvmmsg`/`sendmmsg` wrappers live in [`crate::socket_io`].
//! This module is the adapter layer those wrappers were missing: a reusable
//! receive scratch, a destined-send helper that keeps the unsent suffix,
//! and the connected-socket output pump the readiness `Conn` types share.
//!
//! Completion runtimes (Monoio/Compio/Glommio) stay on their native
//! one-buffer I/O; they do not use these helpers.

use crate::{
    ManualTimerStore, OutputDrainBudget, OutputDrainReport, OutputDrainStatus, collect_output_work,
    prepend_outputs, recvmsg_batch,
};
use shiguredo_srt::{ConnectionOutput, SrtConnection, Timestamp};
use std::collections::VecDeque;
use std::io;
use std::net::SocketAddr;
use std::os::fd::RawFd;

/// Scratch for one `recvmmsg` drain. Capacity is fixed so a readiness
/// loop can reuse the same slots across every wake.
pub struct RecvBatch {
    bufs: Vec<Vec<u8>>,
    sizes: Vec<usize>,
    addrs: Vec<Option<SocketAddr>>,
    truncated: Vec<bool>,
}

impl RecvBatch {
    /// Datagrams one `recvmmsg` is willing to fill. Matches the bench
    /// fast path that this type was extracted from.
    pub const DEFAULT_CAPACITY: usize = 32;
    pub const DEFAULT_BUF_LEN: usize = 2048;

    #[must_use]
    pub fn new() -> Self {
        Self::with_capacity(Self::DEFAULT_CAPACITY, Self::DEFAULT_BUF_LEN)
    }

    #[must_use]
    pub fn with_capacity(datagrams: usize, buf_len: usize) -> Self {
        let datagrams = datagrams.max(1);
        let buf_len = buf_len.max(1);
        Self {
            bufs: (0..datagrams).map(|_| vec![0u8; buf_len]).collect(),
            sizes: vec![0; datagrams],
            addrs: vec![None; datagrams],
            truncated: vec![false; datagrams],
        }
    }

    #[must_use]
    pub fn capacity(&self) -> usize {
        self.bufs.len()
    }

    /// One `recvmmsg`, asking the kernel for at most `limit` datagrams
    /// (further capped to this batch's capacity) rather than always the
    /// full capacity -- so a caller enforcing a remaining budget of, say,
    /// one more datagram cannot have the kernel hand back a whole capacity
    /// batch and overshoot it (T02). Returns the datagrams received; `0`
    /// is `WouldBlock`. `limit == 0` returns `Ok(0)` without a syscall.
    pub fn recv(&mut self, fd: RawFd, limit: usize) -> io::Result<usize> {
        let n = limit.min(self.bufs.len());
        if n == 0 {
            return Ok(0);
        }
        recvmsg_batch(
            fd,
            &mut self.bufs[..n],
            &mut self.sizes[..n],
            &mut self.addrs[..n],
            &mut self.truncated[..n],
        )
    }

    /// Entries of the first `n` datagrams from the last [`Self::recv`]:
    /// sender, the (always in-bounds) received bytes, and whether the
    /// kernel reported `MSG_TRUNC` for that datagram (T01) -- a `true`
    /// entry's bytes are only the datagram's leading prefix, never a
    /// complete packet, and callers must not feed it to the protocol.
    pub fn iter(&self, n: usize) -> impl Iterator<Item = (Option<SocketAddr>, &[u8], bool)> {
        self.bufs
            .iter()
            .zip(self.sizes.iter())
            .zip(self.addrs.iter())
            .zip(self.truncated.iter())
            .take(n.min(self.bufs.len()))
            .map(|(((buf, size), addr), truncated)| (*addr, &buf[..*size], *truncated))
    }
}

impl Default for RecvBatch {
    fn default() -> Self {
        Self::new()
    }
}

/// Per-wake bound on batched receive so a busy socket cannot starve
/// timers and sibling work. Both fields are enforced exactly (T02): a
/// drain never performs more than `max_rounds` `recvmmsg` calls, never
/// feeds more than `max_datagrams` datagrams to the protocol, and a
/// `recvmmsg` call itself never asks the kernel for more than the
/// remaining datagram budget. `0` in either field means "do no receive
/// work this call" -- not "at least one", so a caller that genuinely
/// wants to pause receiving gets that, truthfully, rather than a silently
/// forced minimum.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RecvBudget {
    /// Maximum number of `recvmmsg` syscalls. `0` performs none.
    pub max_rounds: usize,
    /// Maximum number of (non-truncated) datagrams fed to the protocol.
    /// `0` feeds none.
    pub max_datagrams: usize,
}

impl RecvBudget {
    #[must_use]
    pub const fn new(max_rounds: usize, max_datagrams: usize) -> Self {
        Self {
            max_rounds,
            max_datagrams,
        }
    }

    /// One readiness visit: `rounds` `recvmmsg` calls, each up to
    /// [`RecvBatch::DEFAULT_CAPACITY`] datagrams.
    #[must_use]
    pub const fn from_rounds(rounds: usize) -> Self {
        Self::new(rounds, rounds.saturating_mul(RecvBatch::DEFAULT_CAPACITY))
    }

    /// Keep calling `recvmmsg` until the socket returns 0 (EAGAIN) or a
    /// short batch. epoll ET plus a round cap leaves datagrams in the
    /// kernel with no further READABLE, which is how a one-socket pool
    /// drops millions to `udp_rcvbuf_err` while userspace sits in poll.
    #[must_use]
    pub const fn until_would_block() -> Self {
        Self::new(usize::MAX, usize::MAX)
    }
}

impl Default for RecvBudget {
    fn default() -> Self {
        Self::from_rounds(2)
    }
}

/// Work completed by one bounded receive drain.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RecvDrainReport {
    pub datagrams: usize,
    pub syscalls: usize,
    pub would_block: bool,
    /// Datagrams the kernel reported as `MSG_TRUNC`, excluded from
    /// `datagrams` and never fed to the protocol (T01).
    pub truncated: usize,
}

/// Result of offering a destined batch to `sendmmsg`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SendFlushReport {
    pub sent: usize,
    pub would_block: bool,
}

/// Cumulative batched I/O counters for a readiness adapter.
///
/// Ratios are computed, not stored: datagrams per readiness wake,
/// datagrams per `recvmmsg`, packets per output-drain visit, and the
/// fraction of send visits that hit `WouldBlock`.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct BatchIoStats {
    pub recv_wakes: u64,
    pub recv_datagrams: u64,
    pub recv_syscalls: u64,
    pub recv_would_block: u64,
    /// Datagrams discarded as `MSG_TRUNC` (T01): oversized for the
    /// receive buffer, so their bytes were never a complete packet.
    pub recv_truncated: u64,
    pub send_visits: u64,
    pub send_packets: u64,
    pub send_syscalls: u64,
    pub send_would_block: u64,
}

impl BatchIoStats {
    pub fn record_recv(&mut self, report: RecvDrainReport) {
        self.recv_wakes = self.recv_wakes.saturating_add(1);
        self.recv_datagrams = self.recv_datagrams.saturating_add(report.datagrams as u64);
        self.recv_syscalls = self.recv_syscalls.saturating_add(report.syscalls as u64);
        self.recv_truncated = self.recv_truncated.saturating_add(report.truncated as u64);
        if report.would_block {
            self.recv_would_block = self.recv_would_block.saturating_add(1);
        }
    }

    pub fn record_send(&mut self, report: &OutputDrainReport) {
        self.send_visits = self.send_visits.saturating_add(1);
        self.send_packets = self.send_packets.saturating_add(report.packets as u64);
        self.send_syscalls = self.send_syscalls.saturating_add(report.syscalls as u64);
        if report.would_block {
            self.send_would_block = self.send_would_block.saturating_add(1);
        }
    }

    #[must_use]
    pub fn datagrams_per_wake(&self) -> f64 {
        ratio(self.recv_datagrams, self.recv_wakes)
    }

    #[must_use]
    pub fn datagrams_per_syscall(&self) -> f64 {
        ratio(self.recv_datagrams, self.recv_syscalls)
    }

    #[must_use]
    pub fn packets_per_visit(&self) -> f64 {
        ratio(self.send_packets, self.send_visits)
    }

    #[must_use]
    pub fn would_block_rate(&self) -> f64 {
        ratio(self.send_would_block, self.send_visits)
    }
}

fn ratio(numerator: u64, denom: u64) -> f64 {
    if denom == 0 {
        0.0
    } else {
        numerator as f64 / denom as f64
    }
}

/// Drain a non-blocking fd with `recvmmsg` until empty, a short read, or
/// the budget. Every datagram from a syscall is fed before the next
/// syscall starts, so a mid-batch protocol error cannot drop already-
/// dequeued payloads.
pub fn drain_recv_fd(
    fd: RawFd,
    batch: &mut RecvBatch,
    budget: RecvBudget,
    mut on_datagram: impl FnMut(Option<SocketAddr>, &[u8]),
) -> io::Result<RecvDrainReport> {
    let mut report = RecvDrainReport::default();
    for _ in 0..budget.max_rounds {
        if report.datagrams >= budget.max_datagrams {
            break;
        }
        let requested = (budget.max_datagrams - report.datagrams).min(batch.capacity());
        let received = batch.recv(fd, requested)?;
        if received == 0 {
            report.would_block = true;
            break;
        }
        report.syscalls += 1;
        for (addr, data, truncated) in batch.iter(received) {
            if truncated {
                report.truncated += 1;
                continue;
            }
            on_datagram(addr, data);
            report.datagrams += 1;
        }
        if received < requested {
            break;
        }
    }
    Ok(report)
}

/// Apply a `sendmmsg` result to an owned destined queue.
///
/// Accepted datagrams are drained from the front. The unsent suffix stays
/// in original order. `Ok(0)` and `WouldBlock` both mean the kernel took
/// nothing and the whole queue remains.
pub fn apply_send_result<T>(
    packets: &mut Vec<T>,
    result: io::Result<usize>,
) -> io::Result<SendFlushReport> {
    match result {
        Ok(sent) if sent <= packets.len() => {
            let original = packets.len();
            packets.drain(..sent);
            Ok(SendFlushReport {
                sent,
                would_block: sent < original,
            })
        }
        Ok(_) => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "sendmmsg reported more datagrams than supplied",
        )),
        Err(error) if error.kind() == io::ErrorKind::WouldBlock => Ok(SendFlushReport {
            sent: 0,
            would_block: true,
        }),
        Err(error) => Err(error),
    }
}

/// Send a destined batch and leave any unsent suffix in `packets`.
pub fn flush_destined(
    fd: RawFd,
    packets: &mut Vec<(SocketAddr, Vec<u8>)>,
) -> io::Result<SendFlushReport> {
    if packets.is_empty() {
        return Ok(SendFlushReport::default());
    }
    apply_send_result(packets, crate::sendmsg_batch(fd, packets))
}

fn collect_packet_batch(work: &mut VecDeque<ConnectionOutput>, first: Vec<u8>) -> Vec<Vec<u8>> {
    let mut batch = vec![first];
    while matches!(work.front(), Some(ConnectionOutput::SendPacket(_))) {
        let Some(ConnectionOutput::SendPacket(packet)) = work.pop_front() else {
            unreachable!();
        };
        batch.push(packet);
    }
    batch
}

fn requeue_packet_work(
    pending: &mut VecDeque<ConnectionOutput>,
    work: VecDeque<ConnectionOutput>,
    batch: Vec<Vec<u8>>,
    sent: usize,
) {
    prepend_outputs(pending, work.into_iter());
    prepend_outputs(
        pending,
        batch
            .into_iter()
            .skip(sent)
            .map(ConnectionOutput::SendPacket),
    );
}

pub(crate) fn send_packet_batch<F>(
    batch: Vec<Vec<u8>>,
    work: &mut VecDeque<ConnectionOutput>,
    pending: &mut VecDeque<ConnectionOutput>,
    report: &mut OutputDrainReport,
    mut send_batch: F,
) -> io::Result<bool>
where
    F: FnMut(&[Vec<u8>]) -> io::Result<usize>,
{
    report.syscalls += 1;
    match send_batch(&batch) {
        Ok(sent) if sent <= batch.len() => {
            report.actions += sent;
            report.packets += sent;
            report.bytes += batch[..sent].iter().map(Vec::len).sum::<usize>();
            if sent < batch.len() {
                requeue_packet_work(pending, std::mem::take(work), batch, sent);
                report.status = OutputDrainStatus::Backpressured;
                report.would_block = true;
                return Ok(false);
            }
        }
        Ok(_) => {
            requeue_packet_work(pending, std::mem::take(work), batch, 0);
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "sendmmsg reported more datagrams than supplied",
            ));
        }
        Err(error) => {
            requeue_packet_work(pending, std::mem::take(work), batch, 0);
            if error.kind() == io::ErrorKind::WouldBlock {
                report.status = OutputDrainStatus::Backpressured;
                report.would_block = true;
                return Ok(false);
            }
            return Err(error);
        }
    }
    Ok(true)
}

/// Drain already-collected output work through a connected sendmmsg.
pub(crate) fn drain_output_work<F>(
    mut work: VecDeque<ConnectionOutput>,
    pending: &mut VecDeque<ConnectionOutput>,
    timers: &mut ManualTimerStore,
    now: Timestamp,
    mut report: OutputDrainReport,
    mut send_batch: F,
) -> io::Result<OutputDrainReport>
where
    F: FnMut(&[Vec<u8>]) -> io::Result<usize>,
{
    while let Some(output) = work.pop_front() {
        match output {
            ConnectionOutput::SendPacket(packet) => {
                let batch = collect_packet_batch(&mut work, packet);
                if !send_packet_batch(batch, &mut work, pending, &mut report, &mut send_batch)? {
                    return Ok(report);
                }
            }
            timer => {
                timers.apply_output(&timer, now);
                report.actions += 1;
            }
        }
    }
    Ok(report)
}

/// Collect protocol output and send consecutive packets with `sendmmsg`.
pub(crate) fn drain_connected_outputs<F>(
    conn: &mut SrtConnection,
    timers: &mut ManualTimerStore,
    pending: &mut VecDeque<ConnectionOutput>,
    now: Timestamp,
    budget: OutputDrainBudget,
    send_batch: F,
) -> io::Result<OutputDrainReport>
where
    F: FnMut(&[Vec<u8>]) -> io::Result<usize>,
{
    let (work, budget_exhausted) = collect_output_work(conn, pending, budget);
    let report = OutputDrainReport {
        status: if budget_exhausted {
            OutputDrainStatus::BudgetExhausted
        } else {
            OutputDrainStatus::Drained
        },
        ..OutputDrainReport::default()
    };
    drain_output_work(work, pending, timers, now, report, send_batch)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::*;
    use shiguredo_srt::{ConnectionOptions, ConnectionOutput, TimerId, Timestamp};
    use std::collections::VecDeque;
    use std::io;

    fn pkt(value: u8) -> (SocketAddr, Vec<u8>) {
        (SocketAddr::from(([127, 0, 0, 1], 9000)), vec![value])
    }

    fn ids(packets: &[(SocketAddr, Vec<u8>)]) -> Vec<u8> {
        packets.iter().map(|(_, p)| p[0]).collect()
    }

    fn caller_with_output() -> SrtConnection {
        let mut conn = SrtConnection::new_caller(ConnectionOptions::default());
        conn.connect(Timestamp::from_micros(0))
            .expect("connect starts");
        conn
    }

    #[test]
    fn partial_send_preserves_unsent_suffix_in_order() {
        let mut packets = vec![pkt(1), pkt(2), pkt(3), pkt(4)];
        let report = apply_send_result(&mut packets, Ok(2)).expect("partial send");
        assert_eq!(report.sent, 2);
        assert!(report.would_block);
        assert_eq!(ids(&packets), [3, 4]);
    }

    #[test]
    fn eagain_ok_zero_preserves_entire_unsent_suffix() {
        let mut packets = vec![pkt(1), pkt(2), pkt(3)];
        let report = apply_send_result(&mut packets, Ok(0)).expect("EAGAIN is Ok(0)");
        assert_eq!(report.sent, 0);
        assert!(report.would_block);
        assert_eq!(ids(&packets), [1, 2, 3]);
    }

    #[test]
    fn eagain_error_preserves_entire_unsent_suffix() {
        let mut packets = vec![pkt(1), pkt(2)];
        let report = apply_send_result(&mut packets, Err(io::ErrorKind::WouldBlock.into()))
            .expect("WouldBlock is a yield");
        assert_eq!(report.sent, 0);
        assert!(report.would_block);
        assert_eq!(ids(&packets), [1, 2]);
    }

    #[test]
    fn full_send_clears_the_queue() {
        let mut packets = vec![pkt(1), pkt(2)];
        let report = apply_send_result(&mut packets, Ok(2)).expect("full send");
        assert_eq!(report.sent, 2);
        assert!(!report.would_block);
        assert!(packets.is_empty());
    }

    #[test]
    fn oversize_send_count_leaves_the_queue_untouched() {
        let mut packets = vec![pkt(1)];
        let error = apply_send_result(&mut packets, Ok(3)).expect_err("oversize");
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert_eq!(ids(&packets), [1]);
    }

    #[test]
    fn flush_destined_delivers_and_clears_on_loopback() {
        use std::os::fd::AsRawFd;
        let receiver = std::net::UdpSocket::bind("127.0.0.1:0").expect("receiver");
        receiver.set_nonblocking(true).expect("nonblocking");
        let dest = receiver.local_addr().expect("addr");
        let sender = std::net::UdpSocket::bind("127.0.0.1:0").expect("sender");
        sender.set_nonblocking(true).expect("nonblocking");

        let mut packets = vec![
            (dest, b"one".to_vec()),
            (dest, b"two".to_vec()),
            (dest, b"three".to_vec()),
        ];
        let report = flush_destined(sender.as_raw_fd(), &mut packets).expect("flush");
        assert_eq!(report.sent, 3);
        assert!(!report.would_block);
        assert!(packets.is_empty());

        let mut buf = [0u8; 64];
        for expected in [b"one".as_slice(), b"two", b"three"] {
            let n = receiver.recv(&mut buf).expect("recv");
            assert_eq!(&buf[..n], expected);
        }
    }

    #[test]
    fn drain_recv_fd_feeds_a_loopback_burst() {
        use std::os::fd::AsRawFd;
        let receiver = std::net::UdpSocket::bind("127.0.0.1:0").expect("receiver");
        receiver.set_nonblocking(true).expect("nonblocking");
        let dest = receiver.local_addr().expect("addr");
        let sender = std::net::UdpSocket::bind("127.0.0.1:0").expect("sender");
        for payload in [b"a".as_slice(), b"b", b"c"] {
            sender.send_to(payload, dest).expect("send");
        }

        let mut batch = RecvBatch::new();
        let mut got = Vec::new();
        let report = drain_recv_fd(
            receiver.as_raw_fd(),
            &mut batch,
            RecvBudget::from_rounds(1),
            |addr, data| {
                assert!(addr.is_some());
                got.push(data.to_vec());
            },
        )
        .expect("drain");
        assert_eq!(report.datagrams, 3);
        assert_eq!(report.syscalls, 1);
        assert_eq!(got, [b"a".to_vec(), b"b".to_vec(), b"c".to_vec()]);
    }

    #[test]
    fn until_would_block_drains_past_a_round_cap() {
        use std::os::fd::AsRawFd;
        let receiver = std::net::UdpSocket::bind("127.0.0.1:0").expect("receiver");
        receiver.set_nonblocking(true).expect("nonblocking");
        let dest = receiver.local_addr().expect("addr");
        let sender = std::net::UdpSocket::bind("127.0.0.1:0").expect("sender");
        assert_eq!(
            RecvBudget::from_rounds(32).max_datagrams,
            RecvBatch::DEFAULT_CAPACITY * 32
        );
        assert_eq!(RecvBudget::until_would_block().max_rounds, usize::MAX);
        const N: usize = RecvBatch::DEFAULT_CAPACITY + 16;
        for i in 0..N {
            sender.send_to(&[i as u8], dest).expect("send");
        }

        let mut batch = RecvBatch::new();
        let mut capped = 0usize;
        drain_recv_fd(
            receiver.as_raw_fd(),
            &mut batch,
            RecvBudget::from_rounds(1),
            |_, _| capped += 1,
        )
        .expect("capped drain");
        assert_eq!(capped, RecvBatch::DEFAULT_CAPACITY);

        let mut rest = 0usize;
        drain_recv_fd(
            receiver.as_raw_fd(),
            &mut batch,
            RecvBudget::until_would_block(),
            |_, _| rest += 1,
        )
        .expect("remainder drain");
        assert_eq!(capped + rest, N);

        for i in 0..N {
            sender.send_to(&[i as u8], dest).expect("send");
        }
        let mut all = 0usize;
        drain_recv_fd(
            receiver.as_raw_fd(),
            &mut batch,
            RecvBudget::until_would_block(),
            |_, _| all += 1,
        )
        .expect("full drain");
        assert_eq!(all, N);
    }

    /// T02: `recvmsg_batch` used to always be asked for a whole
    /// `RecvBatch::capacity()` batch regardless of how much of the budget
    /// remained, so a budget smaller than the batch capacity (or smaller
    /// than what the kernel had queued) could be overshot within a single
    /// `recvmmsg` call -- the per-round check only ever ran *between*
    /// syscalls, never inside one. Every budget the acceptance criteria
    /// names must instead be an exact, per-call ceiling: never more
    /// datagrams delivered than the budget allows, and -- since exceeding
    /// it was the bug, not skipping -- calling again with the same small
    /// budget must still deliver every remaining datagram exactly once.
    #[test]
    fn recv_budget_is_never_exceeded_even_when_more_is_queued_than_the_budget_allows() {
        use std::os::fd::AsRawFd;
        for max_datagrams in [1usize, 31, 32, 33, 64] {
            let receiver = std::net::UdpSocket::bind("127.0.0.1:0").expect("receiver");
            receiver.set_nonblocking(true).expect("nonblocking");
            let dest = receiver.local_addr().expect("addr");
            let sender = std::net::UdpSocket::bind("127.0.0.1:0").expect("sender");

            const TOTAL: usize = 100;
            for i in 0..TOTAL {
                sender.send_to(&[i as u8], dest).expect("send");
            }

            let mut batch = RecvBatch::new();
            let mut delivered = Vec::new();
            loop {
                let mut this_round = Vec::new();
                let report = drain_recv_fd(
                    receiver.as_raw_fd(),
                    &mut batch,
                    RecvBudget::new(usize::MAX, max_datagrams),
                    |_, data| this_round.push(data[0]),
                )
                .expect("drain");
                assert!(
                    report.datagrams <= max_datagrams,
                    "budget {max_datagrams}: a single drain reported {} datagrams",
                    report.datagrams
                );
                assert!(
                    this_round.len() <= max_datagrams,
                    "budget {max_datagrams}: on_datagram ran {} times, over budget",
                    this_round.len()
                );
                if this_round.is_empty() {
                    assert!(
                        report.would_block,
                        "budget {max_datagrams}: an empty round must mean WouldBlock"
                    );
                    break;
                }
                delivered.extend(this_round);
                if delivered.len() >= TOTAL {
                    break;
                }
            }
            assert_eq!(
                delivered,
                (0..TOTAL as u8).collect::<Vec<_>>(),
                "budget {max_datagrams}: every datagram must be delivered exactly once, in order"
            );
        }
    }

    /// T02: a `RecvBudget` of zero must mean "do no receive work this
    /// call" -- not a silently forced minimum of one round/one datagram.
    /// Previously `drain_recv_fd` clamped both fields to `.max(1)`, so a
    /// caller that explicitly asked for zero work (e.g. to pause
    /// receiving under backpressure) still got one `recvmmsg` call and
    /// had a datagram silently dequeued and delivered.
    #[test]
    fn zero_budget_performs_no_receive_work_and_drops_nothing() {
        use std::os::fd::AsRawFd;
        let receiver = std::net::UdpSocket::bind("127.0.0.1:0").expect("receiver");
        receiver.set_nonblocking(true).expect("nonblocking");
        let dest = receiver.local_addr().expect("addr");
        let sender = std::net::UdpSocket::bind("127.0.0.1:0").expect("sender");
        sender.send_to(b"queued", dest).expect("send");

        let mut batch = RecvBatch::new();

        let mut zero_rounds_calls = 0usize;
        let report = drain_recv_fd(
            receiver.as_raw_fd(),
            &mut batch,
            RecvBudget::new(0, usize::MAX),
            |_, _| zero_rounds_calls += 1,
        )
        .expect("zero max_rounds drain");
        assert_eq!(report, RecvDrainReport::default());
        assert_eq!(zero_rounds_calls, 0);

        let mut zero_datagrams_calls = 0usize;
        let report = drain_recv_fd(
            receiver.as_raw_fd(),
            &mut batch,
            RecvBudget::new(usize::MAX, 0),
            |_, _| zero_datagrams_calls += 1,
        )
        .expect("zero max_datagrams drain");
        assert_eq!(report, RecvDrainReport::default());
        assert_eq!(zero_datagrams_calls, 0);

        // The datagram neither call touched must still be there.
        let mut got = Vec::new();
        drain_recv_fd(
            receiver.as_raw_fd(),
            &mut batch,
            RecvBudget::until_would_block(),
            |_, data| got.push(data.to_vec()),
        )
        .expect("real drain");
        assert_eq!(got, vec![b"queued".to_vec()]);
    }

    #[test]
    fn batch_io_stats_ratios_are_computed() {
        let mut stats = BatchIoStats::default();
        assert_eq!(stats.datagrams_per_wake(), 0.0);
        stats.record_recv(RecvDrainReport {
            datagrams: 8,
            syscalls: 2,
            would_block: true,
            truncated: 0,
        });
        stats.record_recv(RecvDrainReport {
            datagrams: 4,
            syscalls: 1,
            would_block: false,
            truncated: 0,
        });
        assert_eq!(stats.datagrams_per_wake(), 6.0);
        assert_eq!(stats.datagrams_per_syscall(), 4.0);
        assert_eq!(stats.recv_would_block, 1);

        let mut send = OutputDrainReport {
            packets: 10,
            syscalls: 2,
            would_block: true,
            ..OutputDrainReport::default()
        };
        stats.record_send(&send);
        send.would_block = false;
        send.packets = 6;
        stats.record_send(&send);
        assert_eq!(stats.packets_per_visit(), 8.0);
        assert_eq!(stats.would_block_rate(), 0.5);
    }

    #[test]
    fn would_block_retains_packet_and_following_timer() {
        let mut conn = caller_with_output();
        let mut timers = ManualTimerStore::new();
        let mut pending = VecDeque::new();
        let mut attempts = 0;
        let report = drain_connected_outputs(
            &mut conn,
            &mut timers,
            &mut pending,
            Timestamp::from_micros(0),
            OutputDrainBudget::default(),
            |_| {
                attempts += 1;
                Err(io::Error::from(io::ErrorKind::WouldBlock))
            },
        )
        .expect("WouldBlock is a yield, not packet loss");
        assert_eq!(report.status, OutputDrainStatus::Backpressured);
        assert!(report.would_block);
        assert_eq!(attempts, 1);
        assert_eq!(pending.len(), 2);

        let report = drain_connected_outputs(
            &mut conn,
            &mut timers,
            &mut pending,
            Timestamp::from_micros(1),
            OutputDrainBudget::default(),
            |batch| Ok(batch.len()),
        )
        .expect("retry succeeds");
        assert_eq!(report.status, OutputDrainStatus::Drained);
        assert_eq!(report.packets, 1);
        assert!(pending.is_empty());
        assert_ne!(timers.time_until_earliest(Timestamp::from_micros(1), 0), 0);
    }

    #[test]
    fn partial_send_retains_unsent_tail_in_order() {
        let mut conn = SrtConnection::new_caller(ConnectionOptions::default());
        let mut timers = ManualTimerStore::new();
        let mut pending = VecDeque::from([
            ConnectionOutput::SendPacket(vec![1]),
            ConnectionOutput::SendPacket(vec![2]),
            ConnectionOutput::SendPacket(vec![3]),
        ]);
        let report = drain_connected_outputs(
            &mut conn,
            &mut timers,
            &mut pending,
            Timestamp::default(),
            OutputDrainBudget::default(),
            |_| Ok(1),
        )
        .expect("partial send yields");
        assert_eq!(report.packets, 1);
        assert_eq!(report.status, OutputDrainStatus::Backpressured);
        assert!(report.would_block);
        assert_eq!(
            pending.into_iter().collect::<Vec<_>>(),
            vec![
                ConnectionOutput::SendPacket(vec![2]),
                ConnectionOutput::SendPacket(vec![3]),
            ]
        );
    }

    #[test]
    fn packet_and_byte_budget_yields_with_tail_queued() {
        let mut conn = SrtConnection::new_caller(ConnectionOptions::default());
        let mut timers = ManualTimerStore::new();
        let mut pending = VecDeque::from([
            ConnectionOutput::SendPacket(vec![1, 1]),
            ConnectionOutput::SendPacket(vec![2, 2]),
        ]);
        let report = drain_connected_outputs(
            &mut conn,
            &mut timers,
            &mut pending,
            Timestamp::default(),
            OutputDrainBudget::new(8, 8, 2),
            |batch| Ok(batch.len()),
        )
        .expect("bounded send succeeds");

        assert_eq!(report.status, OutputDrainStatus::BudgetExhausted);
        assert_eq!(report.packets, 1);
        assert_eq!(report.bytes, 2);
        assert_eq!(
            pending,
            VecDeque::from([ConnectionOutput::SendPacket(vec![2, 2])])
        );
    }

    #[test]
    fn invalid_batch_count_requeues_packets_before_following_work() {
        let batch = vec![vec![1], vec![2]];
        let mut work = VecDeque::from([ConnectionOutput::ClearTimer { id: TimerId::Ack }]);
        let mut pending = VecDeque::from([ConnectionOutput::SendPacket(vec![3])]);
        let mut report = OutputDrainReport::default();

        let error =
            send_packet_batch(batch, &mut work, &mut pending, &mut report, |_| Ok(3)).unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(work.is_empty());
        assert_eq!(report.syscalls, 1);
        assert_eq!(report.packets, 0);
        assert_eq!(
            pending,
            VecDeque::from([
                ConnectionOutput::SendPacket(vec![1]),
                ConnectionOutput::SendPacket(vec![2]),
                ConnectionOutput::ClearTimer { id: TimerId::Ack },
                ConnectionOutput::SendPacket(vec![3]),
            ])
        );
    }

    #[test]
    fn non_would_block_batch_error_requeues_packets_before_following_work() {
        let batch = vec![vec![1], vec![2]];
        let mut work = VecDeque::from([ConnectionOutput::ClearTimer { id: TimerId::Ack }]);
        let mut pending = VecDeque::from([ConnectionOutput::SendPacket(vec![3])]);
        let mut report = OutputDrainReport::default();

        let error = send_packet_batch(batch, &mut work, &mut pending, &mut report, |_| {
            Err(io::Error::from(io::ErrorKind::BrokenPipe))
        })
        .unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::BrokenPipe);
        assert!(work.is_empty());
        assert_eq!(report.syscalls, 1);
        assert_eq!(
            pending,
            VecDeque::from([
                ConnectionOutput::SendPacket(vec![1]),
                ConnectionOutput::SendPacket(vec![2]),
                ConnectionOutput::ClearTimer { id: TimerId::Ack },
                ConnectionOutput::SendPacket(vec![3]),
            ])
        );
    }
}
