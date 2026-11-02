//! Reusable readiness-runtime batched UDP I/O.
//!
//! Low-level `recvmmsg`/`sendmmsg` wrappers live in [`crate::socket_io`].
//! This module is the adapter layer those wrappers were missing: a reusable
//! receive scratch, a destined-send helper that keeps the unsent suffix,
//! and the connected-socket output pump the readiness `Conn` types share.
//!
//! The completion runtime (Compio) stays on its native one-buffer I/O; it
//! does not use these helpers.

use crate::socket_io::{RecvMeta, recvmsg_batch_into};
use crate::{
    ManualTimerStore, OutputDrainBudget, OutputDrainReport, OutputDrainStatus, collect_output_work,
    prepend_outputs,
};
use bytes::{Bytes, BytesMut};
use srt_proto::{ConnectionOutput, SrtConnection, Timestamp};
use std::collections::VecDeque;
use std::io;
use std::net::SocketAddr;
use std::os::fd::RawFd;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Scratch for one `recvmmsg` drain. Capacity is fixed so a readiness
/// loop can reuse the same slots across every wake.
pub struct RecvBatch {
    bufs: Vec<Vec<u8>>,
    sizes: Vec<usize>,
    addrs: Vec<Option<SocketAddr>>,
    truncated: Vec<bool>,
    /// Empty unless the batch reads kernel metadata ([`Self::with_arrival_stamps`]):
    /// a control buffer per message measurably slows a plain receive.
    meta: Vec<RecvMeta>,
    /// The `now` of the last drain: no later arrival is stamped earlier.
    floor: Timestamp,
}

/// Converts kernel arrival stamps (realtime clock) to the protocol clock of
/// one receive round, so a datagram that waited in the socket queue is fed
/// with the time it arrived, not the time the loop got to it.
///
/// A stamp becomes `now` minus its age, clamped to no earlier than the
/// previous drain's `now` (a time the runtime may already have fed the
/// connection) and to no earlier than the previous arrival of this round.
/// A missing stamp reads as `now`; a stamp from across a realtime clock step
/// lands on one of the clamps.
struct ArrivalClock {
    now: u64,
    /// Read on the first stamped datagram, after its `recvmmsg`, so an
    /// unstamped socket never pays for the clock.
    realtime_now: Option<Duration>,
    last: u64,
}

impl ArrivalClock {
    fn new(now: Timestamp, floor: Timestamp) -> Self {
        let now = now.as_micros();
        Self {
            now,
            realtime_now: None,
            last: floor.as_micros().min(now),
        }
    }

    fn arrival(&mut self, meta: RecvMeta) -> Timestamp {
        let age = meta.arrival_realtime.map_or(0, |stamp| {
            let realtime_now = *self.realtime_now.get_or_insert_with(|| {
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
            });
            u64::try_from(realtime_now.saturating_sub(stamp).as_micros()).unwrap_or(u64::MAX)
        });
        self.last = self.now.saturating_sub(age).max(self.last);
        Timestamp::from_micros(self.last)
    }
}

impl RecvBatch {
    /// Datagrams one `recvmmsg` is willing to fill. Matches the bench
    /// fast path that this type was extracted from.
    pub const DEFAULT_CAPACITY: usize = 32;
    pub const DEFAULT_BUF_LEN: usize = 2048;
    /// Hard cap for receive scratch slots allocated by one batch helper.
    /// Larger values multiply fixed datagram buffers and are almost always a
    /// configuration error; callers can use multiple bounded rounds instead.
    pub const MAX_CAPACITY: usize = 1024;
    /// Hard cap for one receive scratch buffer. UDP datagrams larger than
    /// this are reported as truncated by the kernel and never fed to SRT.
    pub const MAX_BUF_LEN: usize = srt_proto::wire::MAX_DATAGRAM_SIZE;

    #[must_use]
    pub fn new() -> Self {
        Self::with_capacity(Self::DEFAULT_CAPACITY, Self::DEFAULT_BUF_LEN)
    }

    #[must_use]
    pub fn with_capacity(datagrams: usize, buf_len: usize) -> Self {
        let datagrams = datagrams.clamp(1, Self::MAX_CAPACITY);
        let buf_len = buf_len.clamp(1, Self::MAX_BUF_LEN);
        Self {
            bufs: (0..datagrams).map(|_| vec![0u8; buf_len]).collect(),
            sizes: vec![0; datagrams],
            addrs: vec![None; datagrams],
            truncated: vec![false; datagrams],
            meta: Vec::new(),
            floor: Timestamp::from_micros(0),
        }
    }

    /// Read each datagram's arrival stamp (when `on`); the socket must have
    /// [`crate::socket_io::enable_receive_timestamps`]. Unread, every
    /// datagram arrives at the drain's `now`.
    #[must_use]
    pub fn with_arrival_stamps(mut self, on: bool) -> Self {
        self.meta = if on {
            vec![RecvMeta::default(); self.bufs.len()]
        } else {
            Vec::new()
        };
        self
    }

    #[must_use]
    pub fn capacity(&self) -> usize {
        self.bufs.len()
    }

    /// Bytes each receive slot holds; a longer datagram is truncated.
    #[must_use]
    pub fn slot_len(&self) -> usize {
        self.bufs.first().map_or(0, Vec::len)
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
        let meta_len = n.min(self.meta.len());
        recvmsg_batch_into(
            fd,
            self.bufs[..n].iter_mut().map(Vec::as_mut_slice),
            &mut self.sizes[..n],
            &mut self.addrs[..n],
            &mut self.truncated[..n],
            &mut self.meta[..meta_len],
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

    /// Kernel metadata (arrival stamp, GRO segment size) of datagram `i` from
    /// the last [`Self::recv`].
    #[must_use]
    pub fn meta(&self, i: usize) -> RecvMeta {
        self.meta.get(i).copied().unwrap_or_default()
    }
}

impl Default for RecvBatch {
    fn default() -> Self {
        Self::new()
    }
}

/// Zero-copy counterpart of [`RecvBatch`]: `recvmmsg` lands each datagram in
/// its own slot of a shared, zero-initialised chunk, and the datagram is
/// handed out as a frozen `Bytes` of that slot. Paired with
/// `SrtConnection::feed_recv_bytes`, a DATA payload reaches the receive
/// buffer and the application without being copied.
///
/// Trade-off: a delivered payload keeps its whole chunk alive until every
/// datagram cut from it is dropped, and each datagram occupies a full slot
/// (`slot_len`) while held. A chunk is allocated only when the current one
/// has no room for a full batch, so allocation is per chunk, not per
/// datagram. Completion runtimes whose kernel-provided buffers must be
/// returned at once (Compio managed RX) keep the copying path.
///
/// A batch built by [`Self::with_gro`] also accepts GRO-coalesced messages
/// (the socket needs [`crate::socket_io::enable_udp_gro`]):
/// [`drain_recv_fd_bytes`] splits each into its logical datagrams, which all
/// share the message's arrival stamp. A coalesced message can be 64 KiB, so
/// such a batch receives into one reused scratch buffer and copies each
/// message, at its real size, into the chunk: one copy, but a held payload
/// pins only its own bytes rather than a 64 KiB slot.
pub struct BytesRecvBatch {
    chunk: BytesMut,
    slot_len: usize,
    capacity: usize,
    chunk_slots: usize,
    /// `capacity` slots of `slot_len` bytes for a GRO batch; empty otherwise.
    gro_scratch: Vec<u8>,
    sizes: Vec<usize>,
    addrs: Vec<Option<SocketAddr>>,
    truncated: Vec<bool>,
    /// Empty unless the batch reads kernel metadata, as in [`RecvBatch`].
    meta: Vec<RecvMeta>,
    received: Vec<Bytes>,
    /// Segments of a coalesced message left over when the datagram budget
    /// ran out, fed first by the next drain of the same socket.
    carried: VecDeque<Carried>,
    floor: Timestamp,
}

struct Carried {
    fd: RawFd,
    addr: Option<SocketAddr>,
    datagram: Bytes,
    arrival: Timestamp,
}

impl BytesRecvBatch {
    /// Slots per chunk: several full batches before a new allocation.
    pub const DEFAULT_CHUNK_SLOTS: usize = 128;

    #[must_use]
    pub fn new() -> Self {
        Self::with_capacity(RecvBatch::DEFAULT_CAPACITY, RecvBatch::DEFAULT_BUF_LEN)
    }

    #[must_use]
    pub fn with_capacity(datagrams: usize, slot_len: usize) -> Self {
        let capacity = datagrams.clamp(1, RecvBatch::MAX_CAPACITY);
        let slot_len = slot_len.clamp(1, RecvBatch::MAX_BUF_LEN);
        Self {
            chunk: BytesMut::new(),
            slot_len,
            capacity,
            chunk_slots: Self::DEFAULT_CHUNK_SLOTS.max(capacity),
            gro_scratch: Vec::new(),
            sizes: vec![0; capacity],
            addrs: vec![None; capacity],
            truncated: vec![false; capacity],
            meta: Vec::new(),
            received: Vec::with_capacity(capacity),
            carried: VecDeque::new(),
            floor: Timestamp::from_micros(0),
        }
    }

    /// Read each datagram's arrival stamp (when `on`), as
    /// [`RecvBatch::with_arrival_stamps`].
    #[must_use]
    pub fn with_arrival_stamps(mut self, on: bool) -> Self {
        self.meta = if on {
            vec![RecvMeta::default(); self.capacity]
        } else {
            Vec::new()
        };
        self
    }

    /// A batch that accepts whole GRO-coalesced messages
    /// ([`srt_proto::wire::MAX_DATAGRAM_SIZE`] bytes each). It always reads
    /// metadata, which carries each message's segment size.
    #[must_use]
    pub fn with_gro(datagrams: usize) -> Self {
        let mut batch =
            Self::with_capacity(datagrams, RecvBatch::MAX_BUF_LEN).with_arrival_stamps(true);
        batch.gro_scratch = vec![0; batch.capacity * batch.slot_len];
        batch
    }

    /// The zero-copy scratch for a socket a runtime binds and drains itself:
    /// with `transport.receive_gro`, `UDP_GRO` is enabled on `fd` and the
    /// batch holds whole coalesced messages.
    pub(crate) fn for_transport(
        fd: RawFd,
        transport: &crate::ResolvedTransportConfig,
    ) -> io::Result<Self> {
        let datagrams = transport.recv_batch_capacity();
        if transport.receive_gro {
            crate::socket_io::enable_udp_gro(fd)?;
            return Ok(Self::with_gro(datagrams));
        }
        Ok(Self::with_capacity(datagrams, RecvBatch::DEFAULT_BUF_LEN)
            .with_arrival_stamps(transport.receive_timestamps))
    }

    /// Metadata of received entry `i`; unstamped when the batch reads none.
    fn meta_of(&self, i: usize) -> RecvMeta {
        self.meta.get(i).copied().unwrap_or_default()
    }

    #[must_use]
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// One `recvmmsg` for at most `limit` datagrams (capped to capacity);
    /// `0` is `WouldBlock`. Received datagrams are then available from
    /// [`Self::take`].
    pub fn recv(&mut self, fd: RawFd, limit: usize) -> io::Result<usize> {
        self.received.clear();
        let n = limit.min(self.capacity);
        if n == 0 {
            return Ok(0);
        }
        if !self.gro_scratch.is_empty() {
            return self.recv_compacted(fd, n);
        }
        if self.chunk.len() < n * self.slot_len {
            self.chunk = BytesMut::zeroed(self.chunk_slots * self.slot_len);
        }
        let slot_len = self.slot_len;
        let meta_len = n.min(self.meta.len());
        let received = recvmsg_batch_into(
            fd,
            self.chunk[..n * slot_len].chunks_mut(slot_len),
            &mut self.sizes[..n],
            &mut self.addrs[..n],
            &mut self.truncated[..n],
            &mut self.meta[..meta_len],
        )?;
        for &size in &self.sizes[..received] {
            let mut slot = self.chunk.split_to(slot_len);
            slot.truncate(size);
            self.received.push(slot.freeze());
        }
        Ok(received)
    }

    /// [`Self::recv`] for a GRO batch: receive into the scratch, then copy
    /// each message at its real size into the chunk, a fresh chunk of
    /// `chunk_slots` default slots once the current one is full.
    fn recv_compacted(&mut self, fd: RawFd, n: usize) -> io::Result<usize> {
        let slot_len = self.slot_len;
        let meta_len = n.min(self.meta.len());
        let received = recvmsg_batch_into(
            fd,
            self.gro_scratch[..n * slot_len].chunks_mut(slot_len),
            &mut self.sizes[..n],
            &mut self.addrs[..n],
            &mut self.truncated[..n],
            &mut self.meta[..meta_len],
        )?;
        let chunk_bytes = self.chunk_slots * RecvBatch::DEFAULT_BUF_LEN;
        for (slot, &size) in self
            .gro_scratch
            .chunks(slot_len)
            .zip(&self.sizes[..received])
        {
            if self.chunk.capacity() < size {
                self.chunk = BytesMut::with_capacity(chunk_bytes.max(size));
            }
            self.chunk.extend_from_slice(&slot[..size]);
            self.received.push(self.chunk.split_to(size).freeze());
        }
        Ok(received)
    }

    /// The datagrams of the last [`Self::recv`], moved out: sender, the
    /// datagram, whether the kernel reported `MSG_TRUNC` (a truncated
    /// datagram is never a complete packet), and its kernel metadata.
    pub fn take(
        &mut self,
    ) -> impl Iterator<Item = (Option<SocketAddr>, Bytes, bool, RecvMeta)> + '_ {
        self.received
            .drain(..)
            .zip(self.addrs.iter().copied())
            .zip(self.truncated.iter().copied())
            .zip(
                self.meta
                    .iter()
                    .copied()
                    .chain(std::iter::repeat(RecvMeta::default())),
            )
            .map(|(((datagram, addr), truncated), meta)| (addr, datagram, truncated, meta))
    }

    /// Feed this socket's carried segments, oldest first, while the budget
    /// lasts. Returns how many were fed.
    fn feed_carried(
        &mut self,
        fd: RawFd,
        limit: usize,
        on_datagram: &mut impl FnMut(Option<SocketAddr>, Bytes, Timestamp),
    ) -> usize {
        let mut fed = 0;
        let mut index = 0;
        while fed < limit && index < self.carried.len() {
            if self.carried[index].fd != fd {
                index += 1;
                continue;
            }
            let Carried {
                addr,
                datagram,
                arrival,
                ..
            } = self.carried.remove(index).expect("index is in bounds");
            on_datagram(addr, datagram, arrival.max(self.floor));
            fed += 1;
        }
        fed
    }

    /// Feed the messages of the last [`Self::recv`], splitting coalesced
    /// ones, until `limit` datagrams are used up (a truncated message uses
    /// one, unfed). Segments past the limit are carried for `fd`. Returns
    /// the datagrams fed and the truncated messages.
    fn feed_received(
        &mut self,
        fd: RawFd,
        now: Timestamp,
        limit: usize,
        on_datagram: &mut impl FnMut(Option<SocketAddr>, Bytes, Timestamp),
    ) -> (usize, usize) {
        let mut clock = ArrivalClock::new(now, self.floor);
        let mut received = std::mem::take(&mut self.received);
        let (mut fed, mut truncated) = (0, 0);
        for (index, datagram) in received.drain(..).enumerate() {
            if self.truncated[index] {
                truncated += 1;
                continue;
            }
            let (addr, meta) = (self.addrs[index], self.meta_of(index));
            let arrival = clock.arrival(meta);
            for segment in segments(datagram, meta.segment_size) {
                if fed + truncated < limit {
                    on_datagram(addr, segment, arrival);
                    fed += 1;
                } else {
                    self.carried.push_back(Carried {
                        fd,
                        addr,
                        datagram: segment,
                        arrival,
                    });
                }
            }
        }
        self.received = received;
        (fed, truncated)
    }
}

impl Default for BytesRecvBatch {
    fn default() -> Self {
        Self::new()
    }
}

/// The logical datagrams of one received message: the whole message, or
/// for a GRO-coalesced one, each `segment_size` slice (the last may be
/// shorter), all zero-copy.
fn segments(datagram: Bytes, segment_size: Option<u16>) -> impl Iterator<Item = Bytes> {
    let size = segment_size.map_or(datagram.len(), usize::from).max(1);
    let count = datagram.len().div_ceil(size).max(1);
    (0..count).map(move |i| datagram.slice(i * size..((i + 1) * size).min(datagram.len())))
}

/// [`drain_recv_fd`] over a [`BytesRecvBatch`]: each complete datagram is
/// handed over as an owned `Bytes` slice of the receive chunk, with its
/// arrival time on the clock of `now`. A GRO-coalesced message counts as its
/// logical datagrams against the budget; segments past the budget wait in
/// the batch for this socket's next drain.
pub fn drain_recv_fd_bytes(
    fd: RawFd,
    batch: &mut BytesRecvBatch,
    budget: RecvBudget,
    now: Timestamp,
    on_datagram: impl FnMut(Option<SocketAddr>, Bytes, Timestamp),
) -> io::Result<RecvDrainReport> {
    let batch_capacity = batch.capacity();
    let recv = |batch: &mut BytesRecvBatch, limit| batch.recv(fd, limit);
    drain_recv_bytes_with(fd, batch, budget, batch_capacity, now, recv, on_datagram)
}

/// [`drain_recv_fd_bytes`] with the receive step supplied by the caller
/// (`Ok(0)` is `WouldBlock`), so a runtime can wrap the syscall in its own
/// readiness bookkeeping. `fd` keys carried segments to their socket.
pub(crate) fn drain_recv_bytes_with(
    fd: RawFd,
    batch: &mut BytesRecvBatch,
    budget: RecvBudget,
    batch_capacity: usize,
    now: Timestamp,
    mut recv: impl FnMut(&mut BytesRecvBatch, usize) -> io::Result<usize>,
    mut on_datagram: impl FnMut(Option<SocketAddr>, Bytes, Timestamp),
) -> io::Result<RecvDrainReport> {
    let mut report = RecvDrainReport::default();
    if budget.max_rounds == 0 || budget.max_datagrams == 0 {
        return Ok(report);
    }
    report.datagrams = batch.feed_carried(fd, budget.max_datagrams, &mut on_datagram);
    // Fed and truncated datagrams both use up the budget, so a queue of
    // truncated messages cannot make one wake do unbounded kernel work.
    let mut used = report.datagrams;
    let batch_capacity = batch_capacity.clamp(1, batch.capacity());
    for _ in 0..budget.max_rounds {
        if used >= budget.max_datagrams {
            break;
        }
        let requested = (budget.max_datagrams - used).min(batch_capacity);
        let received = recv(batch, requested)?;
        if received == 0 {
            report.would_block = true;
            break;
        }
        report.syscalls += 1;
        let limit = budget.max_datagrams - used;
        let (fed, truncated) = batch.feed_received(fd, now, limit, &mut on_datagram);
        report.datagrams += fed;
        report.truncated += truncated;
        used += fed + truncated;
        if received < requested {
            break;
        }
    }
    batch.floor = batch.floor.max(now);
    Ok(report)
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

    /// One readiness visit expressed as receive rounds. Each round permits up
    /// to [`RecvBatch::DEFAULT_CAPACITY`] datagrams.
    #[must_use]
    pub const fn from_rounds(rounds: usize) -> Self {
        Self::new(rounds, rounds.saturating_mul(RecvBatch::DEFAULT_CAPACITY))
    }

    /// Build a budget for a datagram quantum using the actual receive batch
    /// capacity. The syscall count is derived, so batching and non-batching
    /// paths expose the same maximum number of datagrams to the protocol.
    #[must_use]
    pub const fn for_datagrams(max_datagrams: usize, batch_capacity: usize) -> Self {
        let capacity = if batch_capacity == 0 {
            1
        } else {
            batch_capacity
        };
        let rounds = max_datagrams.saturating_add(capacity.saturating_sub(1)) / capacity;
        Self::new(rounds, max_datagrams)
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
/// dequeued payloads. Each datagram comes with its kernel arrival time on
/// the clock of `now`: never later than `now`, never earlier than the
/// previous drain's `now`, non-decreasing, and `now` when unstamped.
pub fn drain_recv_fd(
    fd: RawFd,
    batch: &mut RecvBatch,
    budget: RecvBudget,
    now: Timestamp,
    on_datagram: impl FnMut(Option<SocketAddr>, &[u8], Timestamp),
) -> io::Result<RecvDrainReport> {
    let batch_capacity = batch.capacity();
    drain_recv_fd_with_capacity(fd, batch, budget, batch_capacity, now, on_datagram)
}

/// Drain a non-blocking fd with a per-visit scratch limit. The backing
/// [`RecvBatch`] may be shared at the owner level, but `batch_capacity` keeps
/// each leg's resolved batching policy effective instead of silently using
/// the largest sibling capacity.
pub(crate) fn drain_recv_fd_with_capacity(
    fd: RawFd,
    batch: &mut RecvBatch,
    budget: RecvBudget,
    batch_capacity: usize,
    now: Timestamp,
    on_datagram: impl FnMut(Option<SocketAddr>, &[u8], Timestamp),
) -> io::Result<RecvDrainReport> {
    let recv = |batch: &mut RecvBatch, limit| batch.recv(fd, limit);
    drain_recv_with(batch, budget, batch_capacity, now, recv, on_datagram)
}

/// [`drain_recv_fd_with_capacity`] with the receive step supplied by the
/// caller (`Ok(0)` is `WouldBlock`).
pub(crate) fn drain_recv_with(
    batch: &mut RecvBatch,
    budget: RecvBudget,
    batch_capacity: usize,
    now: Timestamp,
    mut recv: impl FnMut(&mut RecvBatch, usize) -> io::Result<usize>,
    mut on_datagram: impl FnMut(Option<SocketAddr>, &[u8], Timestamp),
) -> io::Result<RecvDrainReport> {
    let mut report = RecvDrainReport::default();
    // Preserve the low-level pause contract of a zero budget. In particular,
    // do not turn a zero datagram limit into a zero-length probe that reports
    // `WouldBlock`; no receive work happened at all.
    if budget.max_rounds == 0 || budget.max_datagrams == 0 {
        return Ok(report);
    }
    // `report.datagrams` intentionally counts only complete datagrams fed to
    // the protocol. Keep a separate dequeue count so a queue full of
    // truncated packets cannot make one wake consume unbounded kernel work
    // while the visible datagram count stays at zero.
    let batch_capacity = batch_capacity.clamp(1, batch.capacity());
    let mut dequeued = 0usize;
    for _ in 0..budget.max_rounds {
        if dequeued >= budget.max_datagrams {
            break;
        }
        let requested = (budget.max_datagrams - dequeued).min(batch_capacity);
        let received = recv(batch, requested)?;
        if received == 0 {
            report.would_block = true;
            break;
        }
        report.syscalls += 1;
        let mut clock = ArrivalClock::new(now, batch.floor);
        for (index, (addr, data, truncated)) in batch.iter(received).enumerate() {
            dequeued += 1;
            if truncated {
                report.truncated += 1;
                continue;
            }
            on_datagram(addr, data, clock.arrival(batch.meta(index)));
            report.datagrams += 1;
        }
        if received < requested {
            break;
        }
    }
    batch.floor = batch.floor.max(now);
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

#[cfg(any(feature = "mio", feature = "tokio"))]
pub(crate) fn destined_send_limit(
    packets: &[(SocketAddr, Vec<u8>)],
    budget: OutputDrainBudget,
) -> usize {
    let mut limit = packets.len().min(budget.max_actions);
    limit = limit.min(budget.max_packets);
    if budget.max_bytes == 0 {
        return 0;
    }
    let mut bytes = 0usize;
    let mut count = 0usize;
    while count < limit {
        let next = bytes.saturating_add(packets[count].1.len());
        // Permit one oversized datagram so a packet larger than the
        // remaining byte allowance cannot strand the queue forever.
        if count > 0 && next > budget.max_bytes {
            break;
        }
        bytes = next;
        count += 1;
    }
    count
}

#[cfg(feature = "mio")]
pub(crate) fn flush_destined_bounded(
    fd: RawFd,
    packets: &mut Vec<(SocketAddr, Vec<u8>)>,
    budget: OutputDrainBudget,
) -> io::Result<SendFlushReport> {
    let limit = destined_send_limit(packets, budget);
    if limit == 0 {
        return Ok(SendFlushReport::default());
    }
    match crate::sendmsg_batch(fd, &packets[..limit]) {
        Ok(sent) if sent <= limit => {
            packets.drain(..sent);
            Ok(SendFlushReport {
                sent,
                would_block: sent < limit,
            })
        }
        Ok(_) => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "sendmmsg reported more datagrams than supplied",
        )),
        Err(error) if error.kind() == io::ErrorKind::WouldBlock => Ok(SendFlushReport {
            would_block: true,
            ..SendFlushReport::default()
        }),
        Err(error) => Err(error),
    }
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
    let (work, budget_exhausted) = collect_output_work(conn, pending, budget)
        .map_err(|error| io::Error::other(error.to_string()))?;
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
    use srt_proto::{ConnectionOptions, ConnectionOutput, TimerId, Timestamp};
    use std::collections::VecDeque;
    use std::io;

    fn pkt(value: u8) -> (SocketAddr, Vec<u8>) {
        (SocketAddr::from(([127, 0, 0, 1], 9000)), vec![value])
    }

    #[cfg(any(feature = "mio", feature = "tokio"))]
    #[test]
    fn destined_send_limit_honors_action_packet_and_byte_caps() {
        let packets = vec![
            (SocketAddr::from(([127, 0, 0, 1], 9000)), vec![0; 4]),
            (SocketAddr::from(([127, 0, 0, 1], 9000)), vec![0; 4]),
            (SocketAddr::from(([127, 0, 0, 1], 9000)), vec![0; 4]),
        ];
        assert_eq!(
            destined_send_limit(&packets, OutputDrainBudget::new(2, 2, 5)),
            1
        );
        assert_eq!(
            destined_send_limit(&packets, OutputDrainBudget::new(2, 0, 5)),
            0
        );
        assert_eq!(
            destined_send_limit(&packets, OutputDrainBudget::new(2, 2, 0)),
            0
        );
        let mut remaining = OutputDrainBudget::new(4, 1, 8);
        remaining.consume(0, 1, 4);
        assert_eq!(remaining.max_actions, 4);
        assert_eq!(remaining.max_packets, 0);
        assert_eq!(remaining.max_bytes, 4);
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
    fn exhausted_action_budget_does_not_collect_one_extra_output() {
        let mut conn = caller_with_output();
        let mut pending = VecDeque::new();
        let (work, exhausted) =
            collect_output_work(&mut conn, &mut pending, OutputDrainBudget::new(0, 1, 1024))
                .expect("collection is infallible here");
        assert!(work.is_empty());
        assert!(exhausted);
        assert!(
            conn.poll_output()
                .expect("exact-size output materializes")
                .is_some(),
            "the output must remain queued"
        );
    }

    #[test]
    fn receive_batch_clamps_adversarial_capacity() {
        let batch = RecvBatch::with_capacity(usize::MAX, 1);
        assert_eq!(batch.capacity(), RecvBatch::MAX_CAPACITY);
        let wide = RecvBatch::with_capacity(1, usize::MAX);
        assert_eq!(wide.bufs[0].len(), RecvBatch::MAX_BUF_LEN);
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
            Timestamp::from_micros(0),
            |addr, data, _| {
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
    fn finite_budget_drains_past_a_round_cap() {
        use std::os::fd::AsRawFd;
        let receiver = std::net::UdpSocket::bind("127.0.0.1:0").expect("receiver");
        receiver.set_nonblocking(true).expect("nonblocking");
        let dest = receiver.local_addr().expect("addr");
        let sender = std::net::UdpSocket::bind("127.0.0.1:0").expect("sender");
        assert_eq!(
            RecvBudget::from_rounds(32).max_datagrams,
            RecvBatch::DEFAULT_CAPACITY * 32
        );
        const N: usize = RecvBatch::DEFAULT_CAPACITY + 16;
        for i in 0..N {
            sender.send_to(&[i as u8], dest).expect("send");
        }

        let mut batch = RecvBatch::new();
        let batch_capacity = batch.capacity();
        let mut capped = 0usize;
        drain_recv_fd(
            receiver.as_raw_fd(),
            &mut batch,
            RecvBudget::from_rounds(1),
            Timestamp::from_micros(0),
            |_, _, _| capped += 1,
        )
        .expect("capped drain");
        assert_eq!(capped, RecvBatch::DEFAULT_CAPACITY);

        let mut rest = 0usize;
        drain_recv_fd(
            receiver.as_raw_fd(),
            &mut batch,
            RecvBudget::for_datagrams(N, batch_capacity),
            Timestamp::from_micros(0),
            |_, _, _| rest += 1,
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
            RecvBudget::for_datagrams(N, batch_capacity),
            Timestamp::from_micros(0),
            |_, _, _| all += 1,
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
            let batch_capacity = batch.capacity();
            let mut delivered = Vec::new();
            loop {
                let mut this_round = Vec::new();
                let report = drain_recv_fd(
                    receiver.as_raw_fd(),
                    &mut batch,
                    RecvBudget::for_datagrams(max_datagrams, batch_capacity),
                    Timestamp::from_micros(0),
                    |_, data, _| this_round.push(data[0]),
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
        let batch_capacity = batch.capacity();

        let mut zero_rounds_calls = 0usize;
        let report = drain_recv_fd(
            receiver.as_raw_fd(),
            &mut batch,
            RecvBudget::new(0, usize::MAX),
            Timestamp::from_micros(0),
            |_, _, _| zero_rounds_calls += 1,
        )
        .expect("zero max_rounds drain");
        assert_eq!(report, RecvDrainReport::default());
        assert_eq!(zero_rounds_calls, 0);

        let mut zero_datagrams_calls = 0usize;
        let report = drain_recv_fd(
            receiver.as_raw_fd(),
            &mut batch,
            RecvBudget::new(usize::MAX, 0),
            Timestamp::from_micros(0),
            |_, _, _| zero_datagrams_calls += 1,
        )
        .expect("zero max_datagrams drain");
        assert_eq!(report, RecvDrainReport::default());
        assert_eq!(zero_datagrams_calls, 0);

        // The datagram neither call touched must still be there.
        let mut got = Vec::new();
        drain_recv_fd(
            receiver.as_raw_fd(),
            &mut batch,
            RecvBudget::for_datagrams(1, batch_capacity),
            Timestamp::from_micros(0),
            |_, data, _| got.push(data.to_vec()),
        )
        .expect("real drain");
        assert_eq!(got, vec![b"queued".to_vec()]);
    }

    #[test]
    fn truncated_dequeues_consume_the_receive_budget_without_feeding_protocol() {
        use std::os::fd::AsRawFd;
        let receiver = std::net::UdpSocket::bind("127.0.0.1:0").expect("receiver");
        receiver.set_nonblocking(true).expect("nonblocking");
        let dest = receiver.local_addr().expect("addr");
        let sender = std::net::UdpSocket::bind("127.0.0.1:0").expect("sender");
        sender
            .send_to(&vec![0xA5; RecvBatch::DEFAULT_BUF_LEN + 1], dest)
            .expect("oversized datagram");
        sender
            .send_to(b"complete", dest)
            .expect("complete datagram");

        let mut batch = RecvBatch::new();
        let mut delivered = Vec::new();
        let first = drain_recv_fd(
            receiver.as_raw_fd(),
            &mut batch,
            RecvBudget::new(1, 1),
            Timestamp::from_micros(0),
            |_, data, _| delivered.push(data.to_vec()),
        )
        .expect("truncated drain");
        assert_eq!(first.datagrams, 0);
        assert_eq!(first.truncated, 1);
        assert!(delivered.is_empty());

        let second = drain_recv_fd(
            receiver.as_raw_fd(),
            &mut batch,
            RecvBudget::new(1, 1),
            Timestamp::from_micros(0),
            |_, data, _| delivered.push(data.to_vec()),
        )
        .expect("remaining drain");
        assert_eq!(second.datagrams, 1);
        assert_eq!(delivered, vec![b"complete".to_vec()]);
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

    #[test]
    fn bytes_drain_hands_over_datagrams_without_copying_and_shares_a_chunk() {
        use std::os::fd::AsRawFd;
        let receiver = std::net::UdpSocket::bind("127.0.0.1:0").expect("receiver");
        receiver.set_nonblocking(true).expect("nonblocking");
        let dest = receiver.local_addr().expect("addr");
        let sender = std::net::UdpSocket::bind("127.0.0.1:0").expect("sender");
        for payload in [b"one".as_slice(), b"two", b"three"] {
            sender.send_to(payload, dest).expect("send");
        }

        let mut batch = BytesRecvBatch::with_capacity(8, 64);
        let mut got = Vec::new();
        let report = drain_recv_fd_bytes(
            receiver.as_raw_fd(),
            &mut batch,
            RecvBudget::from_rounds(1),
            Timestamp::from_micros(0),
            |addr, datagram, _| {
                assert!(addr.is_some());
                got.push(datagram);
            },
        )
        .expect("drain");
        assert_eq!(report.datagrams, 3);
        assert_eq!(got, [&b"one"[..], b"two", b"three"]);
        // Consecutive slots of one chunk: no per-datagram allocation.
        assert_eq!(got[0].as_ptr().wrapping_add(64), got[1].as_ptr());
        assert_eq!(got[1].as_ptr().wrapping_add(64), got[2].as_ptr());
    }

    #[test]
    fn bytes_drain_skips_truncated_datagrams_and_honours_the_budget() {
        use std::os::fd::AsRawFd;
        let receiver = std::net::UdpSocket::bind("127.0.0.1:0").expect("receiver");
        receiver.set_nonblocking(true).expect("nonblocking");
        let dest = receiver.local_addr().expect("addr");
        let sender = std::net::UdpSocket::bind("127.0.0.1:0").expect("sender");
        sender
            .send_to(&[0xA5; 65], dest)
            .expect("oversized for a 64-byte slot");
        for i in 0..5u8 {
            sender.send_to(&[i], dest).expect("send");
        }

        let mut batch = BytesRecvBatch::with_capacity(8, 64);
        let mut got = Vec::new();
        let report = drain_recv_fd_bytes(
            receiver.as_raw_fd(),
            &mut batch,
            RecvBudget::new(8, 3),
            Timestamp::from_micros(0),
            |_, datagram, _| got.push(datagram[0]),
        )
        .expect("drain");
        assert_eq!(report.truncated, 1);
        assert_eq!(report.datagrams, 2);
        assert_eq!(got, [0, 1]);

        let mut rest = Vec::new();
        let capacity = batch.capacity();
        drain_recv_fd_bytes(
            receiver.as_raw_fd(),
            &mut batch,
            RecvBudget::for_datagrams(16, capacity),
            Timestamp::from_micros(0),
            |_, datagram, _| rest.push(datagram[0]),
        )
        .expect("drain rest");
        assert_eq!(rest, [2, 3, 4]);
    }

    /// A GRO-receiving socket and a sender whose every larger send leaves as
    /// one GSO packet of `segment`-byte datagrams, which loopback hands to
    /// the GRO socket still coalesced.
    fn gro_pair(segment: u16) -> (std::net::UdpSocket, std::net::UdpSocket) {
        use std::os::fd::AsRawFd;
        let receiver = std::net::UdpSocket::bind("127.0.0.1:0").expect("receiver");
        receiver.set_nonblocking(true).expect("nonblocking");
        crate::socket_io::enable_udp_gro(receiver.as_raw_fd()).expect("UDP_GRO");
        crate::socket_io::enable_receive_timestamps(receiver.as_raw_fd()).expect("SO_TIMESTAMPNS");
        let sender = std::net::UdpSocket::bind("127.0.0.1:0").expect("sender");
        sender
            .connect(receiver.local_addr().expect("addr"))
            .expect("connect");
        let segment = libc::c_int::from(segment);
        // SAFETY: `segment` is a live c_int whose size is passed with it.
        let set = unsafe {
            libc::setsockopt(
                sender.as_raw_fd(),
                libc::SOL_UDP,
                libc::UDP_SEGMENT,
                (&segment as *const libc::c_int).cast(),
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            )
        };
        assert_eq!(set, 0, "UDP_SEGMENT: {}", io::Error::last_os_error());
        (receiver, sender)
    }

    /// 100, 100 and 50 bytes of 0, 1 and 2.
    fn three_segments() -> Vec<u8> {
        [0u8, 1, 2]
            .iter()
            .zip([100, 100, 50])
            .flat_map(|(&byte, len)| std::iter::repeat_n(byte, len))
            .collect()
    }

    #[test]
    fn gro_receive_splits_into_segments_with_one_arrival_stamp() {
        use std::os::fd::AsRawFd;
        let (receiver, sender) = gro_pair(100);
        let mut batch = BytesRecvBatch::with_gro(4);

        sender.send(&three_segments()).expect("send");
        assert_eq!(
            batch.recv(receiver.as_raw_fd(), 4).expect("recv"),
            1,
            "one coalesced message"
        );
        let (_, message, truncated, meta) = batch.take().next().expect("message");
        assert!(!truncated);
        assert_eq!(message.len(), 250);
        assert_eq!(meta.segment_size, Some(100));
        assert!(
            meta.arrival_realtime.is_some(),
            "the kernel stamped the arrival"
        );

        sender.send(&three_segments()).expect("send");
        let now = Timestamp::from_micros(60_000_000);
        let mut got = Vec::new();
        let report = drain_recv_fd_bytes(
            receiver.as_raw_fd(),
            &mut batch,
            RecvBudget::from_rounds(1),
            now,
            |_, datagram, at| got.push((datagram, at)),
        )
        .expect("drain");
        assert_eq!(report.syscalls, 1);
        assert_eq!(report.datagrams, 3);
        let lens: Vec<_> = got.iter().map(|(d, _)| (d[0], d.len())).collect();
        assert_eq!(lens, [(0, 100), (1, 100), (2, 50)]);
        assert!(
            got.iter().all(|(_, at)| *at == got[0].1),
            "one stamp: {got:?}"
        );
        assert!(got[0].1 <= now);
    }

    #[test]
    fn gro_segments_past_the_budget_wait_for_their_own_socket() {
        use std::os::fd::AsRawFd;
        let (receiver, sender) = gro_pair(100);
        let (other, _other_sender) = gro_pair(100);
        let mut batch = BytesRecvBatch::with_gro(4);
        sender.send(&three_segments()).expect("send");

        let mut first = Vec::new();
        let report = drain_recv_fd_bytes(
            receiver.as_raw_fd(),
            &mut batch,
            RecvBudget::new(8, 2),
            Timestamp::from_micros(1_000),
            |_, datagram, _| first.push(datagram[0]),
        )
        .expect("drain");
        assert_eq!(
            report.datagrams, 2,
            "the budget is exact in logical datagrams"
        );
        assert_eq!(first, [0, 1]);

        let mut stranger = 0usize;
        drain_recv_fd_bytes(
            other.as_raw_fd(),
            &mut batch,
            RecvBudget::from_rounds(1),
            Timestamp::from_micros(2_000),
            |_, _, _| stranger += 1,
        )
        .expect("other drain");
        assert_eq!(
            stranger, 0,
            "another socket's drain does not take the carried segment"
        );

        let mut rest = Vec::new();
        let report = drain_recv_fd_bytes(
            receiver.as_raw_fd(),
            &mut batch,
            RecvBudget::from_rounds(1),
            Timestamp::from_micros(3_000),
            |_, datagram, at| rest.push((datagram[0], datagram.len(), at)),
        )
        .expect("drain rest");
        assert_eq!(report.datagrams, 1);
        assert!(report.would_block);
        assert_eq!(
            rest,
            [(2, 50, Timestamp::from_micros(2_000))],
            "fed at the floor"
        );
    }

    #[test]
    fn arrival_stamps_precede_processing_within_the_clamps() {
        let realtime = || {
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("after epoch")
        };
        let stamped = |ago: Duration| RecvMeta {
            arrival_realtime: Some(realtime() - ago),
            segment_size: None,
        };
        let now = Timestamp::from_micros(10_000_000);

        let mut clock = ArrivalClock::new(now, Timestamp::from_micros(0));
        let waited = clock.arrival(stamped(Duration::from_millis(5)));
        assert!(
            waited.as_micros() <= 10_000_000 - 5_000,
            "{waited:?} keeps its queue wait"
        );
        assert!(
            waited.as_micros() > 9_000_000,
            "{waited:?} is the stamp's age before now"
        );
        let unstamped = clock.arrival(RecvMeta::default());
        assert_eq!(unstamped, now, "no stamp reads as now");
        let older = clock.arrival(stamped(Duration::from_millis(7)));
        assert_eq!(older, now, "arrivals never go backwards within a round");

        let floor = Timestamp::from_micros(9_999_000);
        let mut clock = ArrivalClock::new(now, floor);
        let early = clock.arrival(stamped(Duration::from_millis(5)));
        assert_eq!(early, floor, "no earlier than the previous drain's now");
        let future = clock.arrival(RecvMeta {
            arrival_realtime: Some(realtime() + Duration::from_secs(1)),
            segment_size: None,
        });
        assert_eq!(
            future, now,
            "a stamp after the clock read is never later than now"
        );
    }
}
