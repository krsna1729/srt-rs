//! Bounded, nonblocking channels for benchmark-owned packet datapaths.
//!
//! # Reading the telemetry
//!
//! A benchmark process owns many of these queues at once -- one per
//! reader socket -- so every figure has to say *which* scope it is
//! measuring. Merging per-queue snapshots and reporting the maximum under
//! a name like "high water" reads as process state while meaning "the
//! worst any single queue got", and at 1000 connections those are wildly
//! different claims: hundreds of queues can each hold a large backlog
//! while no individual maximum looks alarming.
//!
//! So [`QueueStats`] separates them explicitly:
//!
//! - `capacity_per_queue` / `queues` / `total_capacity` -- the size of one
//!   queue, how many exist, and the whole benchmark-owned buffer pool.
//! - `peak_depth_max` -- the deepest any *single* queue got.
//! - `peak_depth_sum` -- the sum of every queue's own peak, an upper
//!   bound on how much the harness ever held at once.

use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, mpsc};

/// Default queue horizon: how much of the offered workload one datapath
/// queue may hold, in milliseconds.
///
/// Replaces a bare `4096`, which was a hidden workload constant -- at
/// 8 Mbit/s and 1316-byte payloads it is several seconds of one stream's
/// data, and at lower rates far longer, so the same number meant a wildly
/// different amount of buffering from cell to cell. A horizon is bounded
/// by *rate and fan-in*, never by run duration, and is directly
/// interpretable: "this queue may absorb a quarter second of the load
/// aimed at it before the harness is the thing that is behind".
pub const DEFAULT_DATAPATH_QUEUE_HORIZON_MS: u64 = 250;

/// Smallest and largest derived queue capacity.
///
/// The floor keeps a very slow source from producing a queue too small to
/// absorb ordinary reader/loop interleaving; the ceiling keeps a
/// high-rate, high-fan-in cell from deriving a buffer pool large enough
/// to be the experiment.
const MIN_DATAPATH_QUEUE_CAPACITY: usize = 64;
const MAX_DATAPATH_QUEUE_CAPACITY: usize = 65_536;

/// Capacity for one datapath queue: `horizon x fan-in x source rate`.
///
/// `peers_served` is how many senders' traffic arrives on the socket
/// feeding this queue -- one for a per-connection socket, `conns / K` for
/// a pooled one -- so a queue is sized by the load actually aimed at it
/// rather than by a constant that ignored topology entirely.
#[must_use]
pub fn datapath_queue_capacity(
    source_bitrate_bps: u64,
    peers_served: usize,
    horizon_ms: u64,
) -> usize {
    // Shares `packets_per_second` with the source backlog rule: both are a
    // horizon of the offered load, and they must not be able to disagree
    // about what that load is.
    let packets_per_sec = crate::source::packets_per_second(source_bitrate_bps);
    let capacity = packets_per_sec * peers_served.max(1) as u128 * u128::from(horizon_ms) / 1000;
    capacity.clamp(
        MIN_DATAPATH_QUEUE_CAPACITY as u128,
        MAX_DATAPATH_QUEUE_CAPACITY as u128,
    ) as usize
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct QueueStats {
    /// How many bounded queues this snapshot accounts for.
    pub queues: usize,
    /// Capacity of ONE queue. Uniform within a process by construction.
    pub capacity_per_queue: usize,
    /// Sum of every queue's capacity: the benchmark-owned buffer pool.
    ///
    /// A real sum rather than `capacity_per_queue * queues`: capacity is
    /// uniform within a process today, but a summed total stays correct
    /// if that ever stops being true, and this type's whole job is
    /// telemetry that cannot quietly mislead.
    pub total_capacity: usize,
    /// The deepest any SINGLE queue got.
    pub peak_depth_max: usize,
    /// Sum of every queue's own peak depth.
    ///
    /// An UPPER BOUND on how much the harness ever held at once, not the
    /// measured simultaneous total: the peaks need not have coincided. A
    /// true running total would need a process-global counter updated on
    /// every enqueue and dequeue, which puts two contended atomics on the
    /// per-packet path of a tool whose entire purpose is measuring that
    /// path. An upper bound answers the question that matters -- "could
    /// the harness have been accumulating across many queues?" -- for
    /// free.
    pub peak_depth_sum: usize,
    pub full_events: u64,
    /// Items rejected because the queue was at capacity. This is the
    /// capacity signal, and a clean cell requires it to be zero.
    pub dropped_or_rejected: u64,
    /// Sends that failed because the consumer was already gone.
    ///
    /// Counted separately and deliberately kept out of the cleanliness
    /// predicate: a disconnected consumer is a shutdown-ordering fact,
    /// not evidence that the queue was too small, and folding the two
    /// together would make teardown races look like overload.
    pub disconnected: u64,
}

impl QueueStats {
    pub fn merge(&mut self, other: Self) {
        self.queues = self.queues.saturating_add(other.queues);
        self.capacity_per_queue = self.capacity_per_queue.max(other.capacity_per_queue);
        self.total_capacity = self.total_capacity.saturating_add(other.total_capacity);
        self.peak_depth_max = self.peak_depth_max.max(other.peak_depth_max);
        self.peak_depth_sum = self.peak_depth_sum.saturating_add(other.peak_depth_sum);
        self.full_events = self.full_events.saturating_add(other.full_events);
        self.dropped_or_rejected = self
            .dropped_or_rejected
            .saturating_add(other.dropped_or_rejected);
        self.disconnected = self.disconnected.saturating_add(other.disconnected);
    }
}

#[derive(Debug)]
struct Counters {
    capacity: usize,
    depth: AtomicUsize,
    high_water: AtomicUsize,
    full_events: AtomicU64,
    dropped_or_rejected: AtomicU64,
    disconnected: AtomicU64,
}

impl Counters {
    fn snapshot(&self) -> QueueStats {
        QueueStats {
            queues: 1,
            capacity_per_queue: self.capacity,
            total_capacity: self.capacity,
            peak_depth_max: self.high_water.load(Ordering::Relaxed),
            peak_depth_sum: self.high_water.load(Ordering::Relaxed),
            full_events: self.full_events.load(Ordering::Relaxed),
            dropped_or_rejected: self.dropped_or_rejected.load(Ordering::Relaxed),
            disconnected: self.disconnected.load(Ordering::Relaxed),
        }
    }
}

/// Producer half of a bounded packet channel. `try_send` never parks a
/// single-thread runtime when the consumer falls behind.
#[derive(Clone, Debug)]
pub struct BoundedSender<T> {
    inner: mpsc::SyncSender<T>,
    counters: Arc<Counters>,
}

#[derive(Debug)]
pub struct BoundedReceiver<T> {
    inner: mpsc::Receiver<T>,
    counters: Arc<Counters>,
}

pub fn bounded_channel<T>(capacity: usize) -> (BoundedSender<T>, BoundedReceiver<T>) {
    let capacity = capacity.max(1);
    let (sender, receiver) = mpsc::sync_channel(capacity);
    let counters = Arc::new(Counters {
        capacity,
        depth: AtomicUsize::new(0),
        high_water: AtomicUsize::new(0),
        full_events: AtomicU64::new(0),
        dropped_or_rejected: AtomicU64::new(0),
        disconnected: AtomicU64::new(0),
    });
    (
        BoundedSender {
            inner: sender,
            counters: counters.clone(),
        },
        BoundedReceiver {
            inner: receiver,
            counters,
        },
    )
}

impl<T> BoundedSender<T> {
    pub fn try_send(&self, item: T) -> Result<(), mpsc::TrySendError<T>> {
        // Claim the slot BEFORE the item becomes visible to the consumer.
        // These channels are cross-thread, so publishing first and
        // counting afterwards leaves a window in which the consumer has
        // already dequeued the item and decremented a counter still at
        // zero -- which trips the receiver's debug assertion and wraps
        // the depth on the way back up.
        let depth = self.counters.depth.fetch_add(1, Ordering::Relaxed) + 1;
        // Clamped: claiming the slot first means a rejected send
        // transiently counts one past capacity, and a high-water mark
        // above the capacity it is printed next to is not a readable
        // number.
        self.counters
            .high_water
            .fetch_max(depth.min(self.counters.capacity), Ordering::Relaxed);
        match self.inner.try_send(item) {
            Ok(()) => Ok(()),
            Err(mpsc::TrySendError::Full(item)) => {
                self.counters.depth.fetch_sub(1, Ordering::Relaxed);
                self.counters.full_events.fetch_add(1, Ordering::Relaxed);
                self.counters
                    .dropped_or_rejected
                    .fetch_add(1, Ordering::Relaxed);
                Err(mpsc::TrySendError::Full(item))
            }
            // The consumer is gone: the item is lost, but not because the
            // queue was too small. Kept out of the capacity counter so a
            // teardown race cannot read as overload.
            Err(mpsc::TrySendError::Disconnected(item)) => {
                self.counters.depth.fetch_sub(1, Ordering::Relaxed);
                self.counters.disconnected.fetch_add(1, Ordering::Relaxed);
                Err(mpsc::TrySendError::Disconnected(item))
            }
        }
    }

    #[must_use]
    pub fn stats(&self) -> QueueStats {
        self.counters.snapshot()
    }
}

impl<T> BoundedReceiver<T> {
    pub fn try_recv(&self) -> Result<T, mpsc::TryRecvError> {
        let item = self.inner.try_recv()?;
        let previous = self.counters.depth.fetch_sub(1, Ordering::Relaxed);
        debug_assert!(previous > 0);
        Ok(item)
    }

    #[must_use]
    pub fn stats(&self) -> QueueStats {
        self.counters.snapshot()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn full_queue_is_bounded_visible_and_nonblocking() {
        let (sender, receiver) = bounded_channel(2);
        assert!(sender.try_send(1).is_ok());
        assert!(sender.try_send(2).is_ok());
        assert!(matches!(
            sender.try_send(3),
            Err(mpsc::TrySendError::Full(3))
        ));
        assert_eq!(receiver.try_recv(), Ok(1));
        assert_eq!(receiver.try_recv(), Ok(2));
        assert_eq!(receiver.try_recv(), Err(mpsc::TryRecvError::Empty));
    }

    #[test]
    fn a_full_queue_reports_every_scope_it_measures() {
        let (sender, receiver) = bounded_channel(2);
        assert!(sender.try_send(1).is_ok());
        assert!(sender.try_send(2).is_ok());
        assert!(sender.try_send(3).is_err());
        let stats = receiver.stats();
        assert_eq!(stats.queues, 1);
        assert_eq!(stats.capacity_per_queue, 2);
        assert_eq!(stats.total_capacity, 2);
        assert_eq!(stats.peak_depth_max, 2);
        assert_eq!(stats.full_events, 1);
        assert_eq!(stats.dropped_or_rejected, 1);
        assert_eq!(stats.disconnected, 0);
        // One queue, so the sum of per-queue peaks is that queue's peak.
        assert_eq!(stats.peak_depth_sum, stats.peak_depth_max);
    }

    /// A dropped consumer loses the item, but not because the queue was
    /// too small. Folding the two together would make an ordinary
    /// teardown race read as overload and fail an otherwise clean cell.
    #[test]
    fn a_disconnected_consumer_is_counted_apart_from_capacity_rejection() {
        let (sender, receiver) = bounded_channel(4);
        drop(receiver);
        assert!(matches!(
            sender.try_send(1),
            Err(mpsc::TrySendError::Disconnected(1))
        ));
        let stats = sender.stats();
        assert_eq!(stats.disconnected, 1);
        assert_eq!(stats.dropped_or_rejected, 0, "not a capacity rejection");
        assert_eq!(stats.full_events, 0);
    }

    /// Merging must keep per-queue and process-wide figures apart:
    /// capacities add up, single-queue peaks take the maximum, and the
    /// process-wide peak is already global so it is not summed.
    #[test]
    fn merging_keeps_per_queue_and_aggregate_scopes_distinct() {
        let mut merged = QueueStats {
            queues: 1,
            capacity_per_queue: 64,
            total_capacity: 64,
            peak_depth_max: 10,
            peak_depth_sum: 10,
            full_events: 1,
            dropped_or_rejected: 1,
            disconnected: 0,
        };
        merged.merge(QueueStats {
            queues: 1,
            capacity_per_queue: 64,
            total_capacity: 64,
            peak_depth_max: 25,
            peak_depth_sum: 25,
            full_events: 2,
            dropped_or_rejected: 2,
            disconnected: 3,
        });
        assert_eq!(merged.queues, 2);
        assert_eq!(merged.capacity_per_queue, 64, "one queue's size");
        assert_eq!(merged.total_capacity, 128, "the whole buffer pool");
        assert_eq!(merged.peak_depth_max, 25, "worst single queue");
        assert_eq!(
            merged.peak_depth_sum, 35,
            "upper bound on what both queues held at once"
        );
        assert_eq!(merged.full_events, 3);
        assert_eq!(merged.dropped_or_rejected, 3);
        assert_eq!(merged.disconnected, 3);
    }

    /// Queue capacity is derived from workload, not a constant: it scales
    /// with source rate, with the socket's fan-in, and with the horizon,
    /// and never with run duration.
    #[test]
    fn capacity_is_a_horizon_of_the_load_aimed_at_the_queue() {
        // 8 Mbit/s of 1316-byte payloads is 759 pkt/s. One peer, 250 ms.
        assert_eq!(datapath_queue_capacity(8_000_000, 1, 250), 189);
        // Ten peers on one pooled socket: ten times the fan-in.
        assert_eq!(datapath_queue_capacity(8_000_000, 10, 250), 1897);
        // Twice the horizon, twice the buffer.
        assert_eq!(datapath_queue_capacity(8_000_000, 10, 500), 3795);
        // Floors and ceilings, so a pathological cell cannot derive a
        // buffer pool large enough to become the experiment.
        assert_eq!(datapath_queue_capacity(1_000, 1, 250), 64);
        assert_eq!(datapath_queue_capacity(u64::MAX, 4096, 10_000), 65_536);
    }

    proptest! {
        #[test]
        fn arbitrary_push_pop_sequences_match_a_bounded_model(
            capacity in 1usize..64,
            operations in proptest::collection::vec(proptest::bool::ANY, 0..512),
        ) {
            let (sender, receiver) = bounded_channel(capacity);
            let mut model = std::collections::VecDeque::new();
            let mut rejected = 0_u64;
            for push in operations {
                if push {
                    let value = model.len();
                    if model.len() == capacity {
                        prop_assert!(matches!(sender.try_send(value), Err(mpsc::TrySendError::Full(_))));
                        rejected += 1;
                    } else {
                        prop_assert!(sender.try_send(value).is_ok());
                        model.push_back(value);
                    }
                } else if let Some(expected) = model.pop_front() {
                    prop_assert_eq!(receiver.try_recv(), Ok(expected));
                } else {
                    prop_assert_eq!(receiver.try_recv(), Err(mpsc::TryRecvError::Empty));
                }
                let stats = receiver.stats();
                prop_assert!(stats.peak_depth_max <= capacity);
                prop_assert_eq!(stats.full_events, rejected);
                prop_assert_eq!(stats.dropped_or_rejected, rejected);
            }
        }
    }
}
