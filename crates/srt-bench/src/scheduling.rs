//! Bounded scheduling telemetry for Tokio receive and outbound retry work.

use std::io;
use std::net::SocketAddr;
use std::time::Duration;

/// Default outbound retry horizon, in milliseconds of offered load.
///
/// Same shape and same reason as the datapath queue horizon: a bare
/// `4096` is a hidden workload constant that means several seconds of
/// buffering at one source rate and a fraction of a second at another.
pub const DEFAULT_OUTBOUND_RETRY_HORIZON_MS: u64 = 250;
const LATENESS_BUCKETS: usize = 32;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum WouldBlockPolicy {
    #[default]
    Retain,
    Drop,
}

impl WouldBlockPolicy {
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "retain" => Some(Self::Retain),
            "drop" => Some(Self::Drop),
            _ => None,
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Retain => "retain",
            Self::Drop => "drop",
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RetryStats {
    /// Capacity of ONE retry queue.
    pub capacity: usize,
    /// How many retry queues this snapshot accounts for.
    pub queues: usize,
    /// Sum of every retry queue's capacity.
    ///
    /// A real sum rather than `capacity * queues`: capacity is uniform
    /// within a process today, but a summed total stays correct if that
    /// ever stops being true, and this type's whole job is telemetry that
    /// cannot quietly mislead.
    pub total_capacity: usize,
    /// The deepest any SINGLE retry queue got.
    pub high_water: usize,
    pub would_block: u64,
    /// Datagrams rejected because the retry queue was at capacity. The
    /// *reason*; these are also counted in `local_dropped`.
    pub overflow: u64,
    /// Total datagrams the harness dropped locally, for any reason
    /// (capacity overflow, or a drop-on-WouldBlock policy discarding the
    /// tail). A superset of `overflow`, never to be added to it.
    pub local_dropped: u64,
}

impl RetryStats {
    pub fn merge(&mut self, other: Self) {
        self.capacity = self.capacity.max(other.capacity);
        self.queues = self.queues.saturating_add(other.queues);
        self.total_capacity = self.total_capacity.saturating_add(other.total_capacity);
        self.high_water = self.high_water.max(other.high_water);
        self.would_block = self.would_block.saturating_add(other.would_block);
        self.overflow = self.overflow.saturating_add(other.overflow);
        self.local_dropped = self.local_dropped.saturating_add(other.local_dropped);
    }
}

/// Shared-socket datagrams retained after a nonblocking send yields.
///
/// Used by every shared-egress send path, so "output the harness is
/// holding on to" has one bounded, instrumented implementation rather
/// than one per runtime. A plain `VecDeque` that is only ever drained
/// until the socket yields has no bound at all across ticks: whenever the
/// socket accepts less than the sender produces, the difference
/// accumulates for the rest of the run.
pub struct RetryQueue {
    items: Vec<(SocketAddr, Vec<u8>)>,
    policy: WouldBlockPolicy,
    stats: RetryStats,
}

impl RetryQueue {
    pub fn new(policy: WouldBlockPolicy, capacity: usize) -> Self {
        let capacity = capacity.max(1);
        Self {
            items: Vec::with_capacity(capacity),
            policy,
            stats: RetryStats {
                capacity,
                queues: 1,
                total_capacity: capacity,
                ..RetryStats::default()
            },
        }
    }

    /// Hand this tick's freshly generated output to the queue.
    ///
    /// Takes the whole batch. The bound this type enforces is on output
    /// *retained across ticks* -- work the socket has already refused --
    /// not on how much a tick may produce. Capping the batch here instead
    /// discarded datagrams the socket had never been offered and would
    /// have accepted: at 200 connections a pooled listener generates far
    /// more than one queue-depth of ACKs per tick, and the cap threw a
    /// quarter of a million of them away without a single `WouldBlock`.
    ///
    /// Transient occupancy is therefore one tick's generation, which is
    /// bounded by the connection count; steady-state occupancy is bounded
    /// by `capacity`, enforced in [`Self::flush_with`] once the socket has
    /// had its chance.
    pub fn append(&mut self, generated: &mut Vec<(SocketAddr, Vec<u8>)>) {
        debug_assert!(
            self.items.len() <= self.stats.capacity,
            "append called again without an intervening flush_with; the capacity bound is enforced after the socket has had its chance"
        );
        self.items.append(generated);
    }

    /// Enforce the retention bound after the socket has had its chance.
    ///
    /// Whatever is still here could not be sent, so this is the queue's
    /// real occupancy; anything past `capacity` is dropped and counted.
    fn trim_to_capacity(&mut self) {
        let capacity = self.stats.capacity;
        // Recorded here rather than in `append` so it means what its name
        // and its column say: how deep the RETAINED queue got, measured
        // against `retry_cap_per_queue`. Recording it on the way in
        // measured one tick's generation instead, which at 200
        // connections is orders of magnitude above the capacity it is
        // printed next to.
        self.stats.high_water = self.stats.high_water.max(self.items.len().min(capacity));
        if self.items.len() <= capacity {
            return;
        }
        let excess = (self.items.len() - capacity) as u64;
        // Keep the OLDEST datagrams: they are earliest in protocol order,
        // and dropping from the front would reorder what does get sent.
        self.items.truncate(capacity);
        // `overflow` is the REASON these datagrams were lost;
        // `local_dropped` is the running total of datagrams the harness
        // dropped locally, for any reason. The total is a superset, so a
        // reader must never add the two -- doing so counted every
        // overflowed datagram twice.
        self.stats.overflow = self.stats.overflow.saturating_add(excess);
        self.stats.local_dropped = self.stats.local_dropped.saturating_add(excess);
    }

    /// Offer everything queued to `send`, which returns how many
    /// datagrams the socket took.
    ///
    /// `send` receives the owned queue slice rather than a borrowed
    /// `&[(SocketAddr, &[u8])]` view. Building that view allocated a
    /// `Vec` on every flush -- fine for a caller that has to materialise
    /// one anyway for `sendmmsg`, but pure waste for mio's shared sender,
    /// which sends one datagram at a time and had been allocation-free
    /// per tick before it started sharing this queue. A benchmark
    /// harness paying an allocation per wakeup is measuring itself.
    pub fn flush_with(
        &mut self,
        mut send: impl FnMut(&[(SocketAddr, Vec<u8>)]) -> io::Result<usize>,
    ) -> io::Result<()> {
        if self.items.is_empty() {
            return Ok(());
        }
        let attempted = self.items.len();
        let result = send(&self.items);
        match result {
            Ok(sent) if sent <= self.items.len() => {
                self.items.drain(..sent);
                if sent < attempted {
                    self.record_would_block();
                }
                self.trim_to_capacity();
                Ok(())
            }
            Ok(_) => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "sendmmsg reported more datagrams than supplied",
            )),
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                self.record_would_block();
                self.trim_to_capacity();
                Ok(())
            }
            Err(error) => Err(error),
        }
    }

    fn record_would_block(&mut self) {
        self.stats.would_block = self.stats.would_block.saturating_add(1);
        if self.policy == WouldBlockPolicy::Drop {
            self.stats.local_dropped = self
                .stats
                .local_dropped
                .saturating_add(self.items.len() as u64);
            self.items.clear();
        }
    }

    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    pub fn stats(&self) -> RetryStats {
        self.stats
    }

    pub fn discard_all(&mut self) {
        self.stats.local_dropped = self
            .stats
            .local_dropped
            .saturating_add(self.items.len() as u64);
        self.items.clear();
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RecvSchedulingStats {
    pub packets: u64,
    pub syscalls: u64,
    lateness: [u64; LATENESS_BUCKETS],
    lateness_samples: u64,
    pub lateness_max_us: u64,
}

impl Default for RecvSchedulingStats {
    fn default() -> Self {
        Self {
            packets: 0,
            syscalls: 0,
            lateness: [0; LATENESS_BUCKETS],
            lateness_samples: 0,
            lateness_max_us: 0,
        }
    }
}

impl RecvSchedulingStats {
    pub fn record_recv(&mut self, packets: usize) {
        self.syscalls = self.syscalls.saturating_add(1);
        self.packets = self.packets.saturating_add(packets as u64);
    }

    pub fn record_lateness(&mut self, lateness: Duration) {
        let micros = lateness.as_micros().min(u64::MAX as u128) as u64;
        let bucket = if micros == 0 {
            0
        } else {
            (u64::BITS - micros.leading_zeros()) as usize
        }
        .min(LATENESS_BUCKETS - 1);
        self.lateness[bucket] = self.lateness[bucket].saturating_add(1);
        self.lateness_samples = self.lateness_samples.saturating_add(1);
        self.lateness_max_us = self.lateness_max_us.max(micros);
    }

    pub fn merge(&mut self, other: Self) {
        self.packets = self.packets.saturating_add(other.packets);
        self.syscalls = self.syscalls.saturating_add(other.syscalls);
        self.lateness_samples = self.lateness_samples.saturating_add(other.lateness_samples);
        self.lateness_max_us = self.lateness_max_us.max(other.lateness_max_us);
        for (mine, theirs) in self.lateness.iter_mut().zip(other.lateness) {
            *mine = mine.saturating_add(theirs);
        }
    }

    /// Upper bound on the requested percentile of timer lateness.
    ///
    /// This is a power-of-two histogram, so what it can honestly report
    /// is the *upper edge of the bucket* the percentile falls in, not the
    /// percentile itself -- hence the name. The bucket edge is clamped to
    /// the measured maximum, because an unclamped edge could exceed it:
    /// six samples topping out at 100 us reported a p95 of 128 us, and a
    /// "p99" larger than the observed maximum is not a number anyone can
    /// reason about. Clamping keeps it a valid upper bound (the true
    /// percentile is never above the maximum either) and keeps the
    /// reported values mutually consistent.
    pub fn percentile_bucket_us(&self, percentile: u64) -> u64 {
        if self.lateness_samples == 0 {
            return 0;
        }
        let rank = self
            .lateness_samples
            .saturating_mul(percentile)
            .div_ceil(100)
            .max(1);
        let mut seen = 0_u64;
        for (bucket, count) in self.lateness.iter().copied().enumerate() {
            seen = seen.saturating_add(count);
            if seen >= rank {
                let edge = if bucket == 0 { 0 } else { 1_u64 << bucket };
                return edge.min(self.lateness_max_us);
            }
        }
        self.lateness_max_us
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    /// Capacity is derived from workload in production; tests pin a small
    /// value so the bound is reachable.
    const TEST_CAPACITY: usize = 4096;

    fn packet(value: u8) -> (SocketAddr, Vec<u8>) {
        (SocketAddr::from(([127, 0, 0, 1], 9000)), vec![value])
    }

    #[test]
    fn retain_and_drop_are_distinct_under_would_block() {
        let mut retained = RetryQueue::new(WouldBlockPolicy::Retain, TEST_CAPACITY);
        retained.append(&mut vec![packet(1), packet(2)]);
        retained
            .flush_with(|_| Err(io::ErrorKind::WouldBlock.into()))
            .unwrap();
        assert!(!retained.is_empty());
        assert_eq!(retained.stats().would_block, 1);
        assert_eq!(retained.stats().local_dropped, 0);

        let mut dropped = RetryQueue::new(WouldBlockPolicy::Drop, TEST_CAPACITY);
        dropped.append(&mut vec![packet(1), packet(2)]);
        dropped
            .flush_with(|_| Err(io::ErrorKind::WouldBlock.into()))
            .unwrap();
        assert!(dropped.is_empty());
        assert_eq!(dropped.stats().would_block, 1);
        assert_eq!(dropped.stats().local_dropped, 2);
    }

    /// The bound is on output RETAINED ACROSS TICKS, not on how much one
    /// tick may generate. Capping the batch on the way in discarded
    /// datagrams the socket had never been offered -- and would have
    /// accepted -- which is how a pooled listener silently lost a quarter
    /// of a million acknowledgements without one `WouldBlock`.
    #[test]
    fn work_the_socket_accepts_is_never_dropped_even_above_capacity() {
        let mut queue = RetryQueue::new(WouldBlockPolicy::Retain, 8);
        let mut generated = (0..64).map(|value| packet(value as u8)).collect();
        queue.append(&mut generated);
        // The socket takes everything offered.
        queue.flush_with(|batch| Ok(batch.len())).unwrap();
        assert!(queue.is_empty());
        assert_eq!(queue.stats().overflow, 0, "nothing was refused");
        assert_eq!(queue.stats().local_dropped, 0);
        assert_eq!(queue.stats().would_block, 0);
    }

    /// What the socket refuses is bounded, and the excess is counted.
    #[test]
    fn retained_work_is_bounded_once_the_socket_has_refused_it() {
        let mut queue = RetryQueue::new(WouldBlockPolicy::Retain, 8);
        let mut generated = (0..64).map(|value| packet(value as u8)).collect();
        queue.append(&mut generated);
        // The socket takes nothing.
        queue
            .flush_with(|_| Err(io::ErrorKind::WouldBlock.into()))
            .unwrap();
        assert_eq!(queue.items.len(), 8, "retention is bounded");
        assert_eq!(queue.stats().overflow, 56);
        assert_eq!(queue.stats().local_dropped, 56);
        assert_eq!(queue.stats().would_block, 1);
    }

    /// Retention must not reorder: SRT output is protocol-ordered, so the
    /// datagrams kept are the oldest, not the newest.
    #[test]
    fn trimming_keeps_the_oldest_datagrams() {
        let mut queue = RetryQueue::new(WouldBlockPolicy::Retain, 3);
        let mut generated = (0..10).map(|value| packet(value as u8)).collect();
        queue.append(&mut generated);
        queue
            .flush_with(|_| Err(io::ErrorKind::WouldBlock.into()))
            .unwrap();
        let kept: Vec<u8> = queue.items.iter().map(|(_, p)| p[0]).collect();
        assert_eq!(kept, vec![0, 1, 2]);
    }

    proptest! {
        /// However much is generated and however little the socket takes,
        /// what is still retained after a flush never exceeds capacity,
        /// and every dropped datagram is accounted for exactly once.
        #[test]
        fn retained_work_never_exceeds_capacity_after_a_flush(
            batches in proptest::collection::vec(
                (proptest::collection::vec(any::<u8>(), 0..500), 0usize..500),
                1..12,
            ),
            capacity in 1usize..64,
        ) {
            let mut queue = RetryQueue::new(WouldBlockPolicy::Retain, capacity);
            let mut offered = 0u64;
            let mut accepted = 0u64;
            for (generated, take) in batches {
                offered += generated.len() as u64;
                let mut packets = generated.into_iter().map(packet).collect();
                queue.append(&mut packets);
                queue.flush_with(|batch| {
                    let sent = take.min(batch.len());
                    accepted += sent as u64;
                    Ok(sent)
                }).unwrap();
                prop_assert!(
                    queue.items.len() <= capacity,
                    "retained {} > capacity {}", queue.items.len(), capacity
                );
            }
            let stats = queue.stats();
            // Every datagram is sent, still retained, or counted dropped.
            prop_assert_eq!(
                offered,
                accepted + queue.items.len() as u64 + stats.overflow
            );
            prop_assert_eq!(stats.overflow, stats.local_dropped);
        }
    }

    #[test]
    fn lateness_percentiles_use_a_fixed_histogram() {
        let mut stats = RecvSchedulingStats::default();
        for micros in [1, 2, 3, 8, 20, 100] {
            stats.record_lateness(Duration::from_micros(micros));
        }
        assert_eq!(stats.percentile_bucket_us(50), 4);
        assert_eq!(stats.lateness_max_us, 100);
        // The p95 sample falls in the 65..=128 bucket, whose edge is 128 --
        // above the largest value actually observed. Reporting that as a
        // percentile of a distribution whose maximum is 100 is not a
        // number anyone can reason about, so it clamps.
        assert_eq!(stats.percentile_bucket_us(95), 100);
    }

    proptest! {
        /// No reported percentile bound may exceed the measured maximum,
        /// and the bounds must be monotonic in the percentile.
        #[test]
        fn percentile_bounds_never_exceed_the_measured_maximum(
            samples in proptest::collection::vec(0u64..5_000_000, 1..200),
        ) {
            let mut stats = RecvSchedulingStats::default();
            for micros in &samples {
                stats.record_lateness(Duration::from_micros(*micros));
            }
            let max = stats.lateness_max_us;
            prop_assert_eq!(max, *samples.iter().max().expect("non-empty"));
            let (p50, p95, p99) = (
                stats.percentile_bucket_us(50),
                stats.percentile_bucket_us(95),
                stats.percentile_bucket_us(99),
            );
            prop_assert!(p99 <= max, "p99 {} > max {}", p99, max);
            prop_assert!(p95 <= p99, "p95 {} > p99 {}", p95, p99);
            prop_assert!(p50 <= p95, "p50 {} > p95 {}", p50, p95);
        }
    }
}
