//! F02: a bounded, multi-subscriber publication bus for live fan-out.
//!
//! Unlike a work-stealing SPMC queue (this crate's `queue.rs`-shaped
//! patterns elsewhere are all single-consumer, first-taker-wins), every
//! [`Subscription`] independently observes every item a [`Publisher`]
//! publishes -- broadcast, not competing consumption. Retention is bounded
//! by item count, total bytes, and age together; whichever bound is hit
//! first evicts the oldest retained item next. A subscription that falls
//! behind the retention window is never silently fed stale or missing
//! data: its next [`Subscription::try_recv`] reports exactly how many
//! items it missed via [`RecvOutcome::Lagged`], then resumes from the
//! oldest item still retained.
//!
//! This crate already calls one independent unit of fan-out concurrency a
//! "shard" elsewhere (see `tokio_transport::Facade`'s own doc comment: "one
//! `Facade` is one shard"). To avoid colliding that established meaning
//! with this module's own vocabulary, a consumer of the bus is called a
//! [`Subscription`] here, not a shard -- one shard (a `Facade`, a relay
//! worker, whatever the application's own unit of concurrency is) is
//! expected to own exactly one `Subscription`.
//!
//! A proven-safe reference implementation (per this card's own charter: no
//! unreviewed lock-free atomic-pointer reclamation): a single
//! `Mutex`-protected ring buffer built from `VecDeque`, no unsafe code
//! anywhere in this module.

use std::collections::{HashSet, VecDeque};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

/// Lock the bus's inner state, recovering from poisoning rather than
/// propagating it: every mutation this module makes while holding the
/// lock either completes before any panic point or restores `Inner`'s
/// invariants first (e.g. `retained_bytes` is decremented before an
/// evicted `Entry<T>` is dropped), so a panic in an unrelated `T::Drop`
/// while the lock is held must not permanently brick every other handle
/// sharing this bus.
fn lock<T>(inner: &Mutex<Inner<T>>) -> MutexGuard<'_, Inner<T>> {
    inner.lock().unwrap_or_else(PoisonError::into_inner)
}

/// One item as retained on the bus, and as delivered to a subscriber.
/// Cheaply cloned (the payload itself is `Arc`-backed) so every
/// subscription that reads it shares the same allocation; eviction from
/// the bus's own ring only drops the bus's reference, never mutates or
/// invalidates a copy a subscriber is still holding.
#[derive(Clone)]
pub struct Published<T> {
    /// Monotonically increasing publish sequence number, starting at 0 for
    /// the first item a given [`PublicationBus`] ever publishes.
    pub sequence: u64,
    /// When [`Publisher::publish`] was called for this item, in the same
    /// process's `Instant` clock -- used only for this bus's own
    /// age-based retention, not exposed cross-process.
    pub published_at: Instant,
    pub item: Arc<T>,
}

impl<T> std::fmt::Debug for Published<T> {
    /// Deliberately does not require `T: Debug` and does not print
    /// `item`'s content -- a payload type has no obligation to be
    /// debug-printable just because it passed through a bus, and this is
    /// meant for use in coarse test/log output, not a full item dump.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Published")
            .field("sequence", &self.sequence)
            .field("published_at", &self.published_at)
            .finish_non_exhaustive()
    }
}

/// The result of one [`Subscription::try_recv`] call.
#[derive(Debug)]
pub enum RecvOutcome<T> {
    /// The next item in sequence, in publish order.
    Item(Published<T>),
    /// No new item since this subscription's last successful receive.
    Empty,
    /// This subscription fell far enough behind the bus's bounded
    /// retention that `skipped` items were evicted before it could read
    /// them. The subscription's cursor has already been advanced to the
    /// oldest item still retained (or to the current tail, if nothing is
    /// retained at all) -- the next `try_recv` resumes from there, not
    /// from where this subscription left off.
    Lagged { skipped: u64 },
    /// Every [`Publisher`] handle for this bus has been dropped, and this
    /// subscription has drained every item that was ever retained: no
    /// further items will ever arrive.
    Closed,
}

/// A snapshot of one bus's lifetime counters, for observability --
/// mirrors this workspace's `QueueStats` convention (`srt-bench`'s
/// `queue.rs`) of a plain `Copy` snapshot struct rather than exposing
/// live atomics.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct BusStats {
    /// Total items ever published, including any since evicted.
    pub published: u64,
    /// Total items ever evicted by retention before every subscriber
    /// that could have read them did.
    pub evicted: u64,
}

struct Entry<T> {
    sequence: u64,
    published_at: Instant,
    bytes: usize,
    item: Arc<T>,
}

struct Inner<T> {
    ring: VecDeque<Entry<T>>,
    next_sequence: u64,
    retained_bytes: usize,
    total_evicted: u64,
    next_subscription_id: u64,
    /// IDs of every live subscription. Removed on unsubscribe (via
    /// `Subscription`'s `Drop`). Retention itself is independent of any
    /// subscription's read position (a slow subscriber cannot hold
    /// eviction open -- it falls behind and is told so via `Lagged`
    /// instead); this set exists purely so [`PublicationBus::subscriber_count`]
    /// has something to count.
    cursors: HashSet<u64>,
    live_publishers: usize,
}

impl<T> Inner<T> {
    /// Evict from the front of the ring until every retention bound
    /// (item count, total bytes, age) holds, or only the newest item is
    /// left. The byte and age bounds never evict the sole remaining
    /// item -- a single item larger than `retain_bytes`, or older than
    /// `retain_age` by the time the next item arrives, must still be
    /// delivered at least once rather than vanish before any subscriber
    /// can read it. Only the item-count bound (`retain_items == 0`) can
    /// evict down to empty.
    fn enforce_retention(
        &mut self,
        retain_items: usize,
        retain_bytes: usize,
        retain_age: Duration,
        now: Instant,
    ) {
        while let Some(front) = self.ring.front() {
            let over_items = self.ring.len() > retain_items;
            let over_bytes = self.retained_bytes > retain_bytes;
            let over_age = now.saturating_duration_since(front.published_at) > retain_age;
            if !(over_items || over_bytes || over_age) {
                break;
            }
            if self.ring.len() == 1 && !over_items {
                break;
            }
            let evicted = self.ring.pop_front().expect("front just checked Some");
            self.retained_bytes -= evicted.bytes;
            self.total_evicted += 1;
        }
    }

    fn oldest_retained_sequence(&self) -> u64 {
        self.ring
            .front()
            .map_or(self.next_sequence, |entry| entry.sequence)
    }
}

/// The shared bus itself: a cheap, `Clone`-able handle (internally
/// `Arc`-based) used to create new [`Subscription`]s. Does not itself
/// publish -- see [`Publisher`].
pub struct PublicationBus<T> {
    inner: Arc<Mutex<Inner<T>>>,
    retain_items: usize,
    retain_bytes: usize,
    retain_age: Duration,
}

impl<T> Clone for PublicationBus<T> {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
            retain_items: self.retain_items,
            retain_bytes: self.retain_bytes,
            retain_age: self.retain_age,
        }
    }
}

/// The producer handle for one [`PublicationBus`]. Cloning a `Publisher`
/// shares the same underlying bus (multiple producer handles are allowed,
/// though this card's own scope assumes a single logical source); the bus
/// is only considered closed once every clone has been dropped.
pub struct Publisher<T> {
    bus: PublicationBus<T>,
}

impl<T> Clone for Publisher<T> {
    fn clone(&self) -> Self {
        lock(&self.bus.inner).live_publishers += 1;
        Self {
            bus: self.bus.clone(),
        }
    }
}

impl<T> Drop for Publisher<T> {
    fn drop(&mut self) {
        let mut inner = lock(&self.bus.inner);
        inner.live_publishers = inner.live_publishers.saturating_sub(1);
    }
}

/// One subscription's independent read cursor into a [`PublicationBus`].
/// Dropping a `Subscription` unsubscribes it: its cursor is removed
/// immediately, so it can never hold the bus's retention open once gone.
pub struct Subscription<T> {
    bus: PublicationBus<T>,
    id: u64,
    next_sequence: u64,
}

impl<T> Drop for Subscription<T> {
    fn drop(&mut self) {
        lock(&self.bus.inner).cursors.remove(&self.id);
    }
}

impl<T> PublicationBus<T> {
    /// Build a new bus and its sole initial [`Publisher`] handle.
    /// `retain_items`/`retain_bytes`/`retain_age` bound retention jointly:
    /// an item is evicted once ANY one of them is exceeded, whichever
    /// comes first. Pass `usize::MAX`/[`Duration::MAX`] for a bound that
    /// should never itself trigger eviction.
    #[must_use]
    pub fn new(
        retain_items: usize,
        retain_bytes: usize,
        retain_age: Duration,
    ) -> (Publisher<T>, Self) {
        let bus = Self {
            inner: Arc::new(Mutex::new(Inner {
                ring: VecDeque::new(),
                next_sequence: 0,
                retained_bytes: 0,
                total_evicted: 0,
                next_subscription_id: 0,
                cursors: HashSet::new(),
                live_publishers: 1,
            })),
            retain_items,
            retain_bytes,
            retain_age,
        };
        let publisher = Publisher { bus: bus.clone() };
        (publisher, bus)
    }

    /// Start a new subscription. It observes every item published from
    /// this point forward -- not anything already retained before this
    /// call, matching the usual "join a live broadcast" semantics a
    /// resubscribing shard expects (a shard that wants replay of
    /// already-retained items can be added later without changing this
    /// default).
    #[must_use]
    pub fn subscribe(&self) -> Subscription<T> {
        let mut inner = lock(&self.inner);
        let id = inner.next_subscription_id;
        inner.next_subscription_id += 1;
        let next_sequence = inner.next_sequence;
        inner.cursors.insert(id);
        Subscription {
            bus: self.clone(),
            id,
            next_sequence,
        }
    }

    /// Number of subscriptions currently live.
    #[must_use]
    pub fn subscriber_count(&self) -> usize {
        lock(&self.inner).cursors.len()
    }

    /// A snapshot of this bus's lifetime publish/eviction counters.
    #[must_use]
    pub fn stats(&self) -> BusStats {
        let inner = lock(&self.inner);
        BusStats {
            published: inner.next_sequence,
            evicted: inner.total_evicted,
        }
    }
}

impl<T> Publisher<T> {
    /// Publish one item, evicting whatever retention bounds now require.
    /// `byte_len` is the caller's own accounting of `item`'s size (this
    /// module has no way to measure an arbitrary `T` itself); pass `0` if
    /// byte-bounded retention is not meaningful for this bus's payload
    /// type. Returns the sequence number just assigned.
    pub fn publish(&self, item: T, byte_len: usize) -> u64 {
        let now = Instant::now();
        let mut inner = lock(&self.bus.inner);
        let sequence = inner.next_sequence;
        inner.next_sequence += 1;
        inner.retained_bytes += byte_len;
        inner.ring.push_back(Entry {
            sequence,
            published_at: now,
            bytes: byte_len,
            item: Arc::new(item),
        });
        inner.enforce_retention(
            self.bus.retain_items,
            self.bus.retain_bytes,
            self.bus.retain_age,
            now,
        );
        sequence
    }

    /// Convenience for a caller that only holds a `Publisher` handle and
    /// would otherwise need to thread the matching `PublicationBus`
    /// around separately just to add a reader.
    #[must_use]
    pub fn subscribe(&self) -> Subscription<T> {
        self.bus.subscribe()
    }
}

impl<T> Subscription<T> {
    /// Receive the next item in publish order, or report why none is
    /// available right now (see [`RecvOutcome`]).
    pub fn try_recv(&mut self) -> RecvOutcome<T> {
        let now = Instant::now();
        let mut inner = lock(&self.bus.inner);
        inner.enforce_retention(
            self.bus.retain_items,
            self.bus.retain_bytes,
            self.bus.retain_age,
            now,
        );

        let oldest_retained = inner.oldest_retained_sequence();
        if self.next_sequence < oldest_retained {
            let skipped = oldest_retained - self.next_sequence;
            self.next_sequence = oldest_retained;
            return RecvOutcome::Lagged { skipped };
        }

        // Already known `>= oldest_retained` (the Lagged branch above
        // returns otherwise), so this is always a valid, non-negative
        // offset into the ring.
        let ring_index = (self.next_sequence - oldest_retained) as usize;
        let Some(entry) = inner.ring.get(ring_index) else {
            if inner.live_publishers == 0 {
                return RecvOutcome::Closed;
            }
            return RecvOutcome::Empty;
        };
        let published = Published {
            sequence: entry.sequence,
            published_at: entry.published_at,
            item: Arc::clone(&entry.item),
        };
        self.next_sequence += 1;
        RecvOutcome::Item(published)
    }

    /// How many published items this subscription has not yet read,
    /// including any it will report as `Lagged` on its next `try_recv`
    /// (an already-evicted item is not distinguished from a still-pending
    /// one by this count alone -- it is a coarse "how far behind" metric
    /// for observability, not a promise every counted item is still
    /// retrievable).
    #[must_use]
    pub fn lag(&self) -> u64 {
        lock(&self.bus.inner)
            .next_sequence
            .saturating_sub(self.next_sequence)
    }

    /// Explicitly unsubscribe. Equivalent to dropping this `Subscription`,
    /// spelled out for a caller that wants the intent visible at the call
    /// site.
    pub fn unsubscribe(self) {
        drop(self);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn multiple_subscriptions_each_observe_every_publication() {
        let (publisher, bus) =
            PublicationBus::<Vec<u8>>::new(16, 1_000_000, Duration::from_secs(60));
        let mut a = bus.subscribe();
        let mut b = bus.subscribe();

        publisher.publish(b"first".to_vec(), 5);
        publisher.publish(b"second".to_vec(), 6);

        for sub in [&mut a, &mut b] {
            let RecvOutcome::Item(first) = sub.try_recv() else {
                panic!("expected first item");
            };
            assert_eq!(first.item.as_slice(), b"first");
            let RecvOutcome::Item(second) = sub.try_recv() else {
                panic!("expected second item");
            };
            assert_eq!(second.item.as_slice(), b"second");
            assert!(matches!(sub.try_recv(), RecvOutcome::Empty));
        }
    }

    #[test]
    fn a_stalled_subscription_reports_explicit_lag_not_corrupted_data() {
        let (publisher, bus) = PublicationBus::<u32>::new(2, usize::MAX, Duration::from_secs(60));
        let mut slow = bus.subscribe();

        // Fill past the 2-item retention bound without the subscription
        // ever reading -- items 0 and 1 must be evicted once item 3
        // arrives (ring holds at most 2: {2, 3}).
        for i in 0..4u32 {
            publisher.publish(i, 4);
        }

        match slow.try_recv() {
            RecvOutcome::Lagged { skipped } => assert_eq!(skipped, 2),
            other => panic!("expected Lagged, got {other:?}"),
        }
        // Resumes from the oldest still-retained item (sequence 2), not
        // from a stale or corrupted position.
        let RecvOutcome::Item(item) = slow.try_recv() else {
            panic!("expected an item after lag recovery");
        };
        assert_eq!(*item.item, 2);
        let RecvOutcome::Item(item) = slow.try_recv() else {
            panic!("expected the final retained item");
        };
        assert_eq!(*item.item, 3);
    }

    /// Acceptance: "stalled shard lag is explicit" -- a subscription must
    /// be able to report how far behind it is at any time, not only
    /// discover it via a `Lagged` result on its next `try_recv`.
    #[test]
    fn lag_reports_how_far_behind_a_subscription_is_before_it_next_receives() {
        let (publisher, bus) = PublicationBus::<u32>::new(100, usize::MAX, Duration::from_secs(60));
        let mut sub = bus.subscribe();
        assert_eq!(sub.lag(), 0, "a fresh subscription starts with no lag");

        for i in 0..5u32 {
            publisher.publish(i, 4);
        }
        assert_eq!(sub.lag(), 5, "lag must reflect every unread publication");

        let RecvOutcome::Item(_) = sub.try_recv() else {
            panic!("expected an item");
        };
        assert_eq!(sub.lag(), 4, "lag must decrease as items are read");

        while !matches!(sub.try_recv(), RecvOutcome::Empty) {}
        assert_eq!(sub.lag(), 0, "lag returns to zero once fully caught up");
    }

    #[test]
    fn producer_progress_and_memory_stay_bounded_even_with_no_readers() {
        let (publisher, bus) = PublicationBus::<u32>::new(4, usize::MAX, Duration::from_secs(60));
        for i in 0..1000u32 {
            publisher.publish(i, 4);
        }
        // The ring itself never grows past `retain_items`, regardless of
        // how many items were ever published or whether anything read
        // them -- a slow/absent subscriber cannot make the producer's own
        // memory grow without bound.
        let inner = bus.inner.lock().unwrap();
        assert!(inner.ring.len() <= 4);
        drop(inner);
        // A late subscriber joins at the tail (see
        // `resubscribing_starts_fresh_from_the_current_tail_...` below),
        // so it correctly sees nothing pending -- not a crash, and not a
        // replay of everything it missed before it existed.
        let mut late = bus.subscribe();
        match late.try_recv() {
            RecvOutcome::Empty => {} // caught up to tail already, nothing more was published
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn byte_bound_evicts_even_under_the_item_count_bound() {
        let (publisher, bus) = PublicationBus::<Vec<u8>>::new(100, 10, Duration::from_secs(60));
        publisher.publish(vec![0; 6], 6);
        publisher.publish(vec![0; 6], 6);
        // Total published bytes (12) exceeds the 10-byte bound, so the
        // first entry must already be evicted despite being well under
        // the 100-item bound.
        let inner = bus.inner.lock().unwrap();
        assert_eq!(inner.ring.len(), 1);
        assert_eq!(inner.ring.front().unwrap().sequence, 1);
    }

    #[test]
    fn age_bound_evicts_stale_items_on_the_next_publish() {
        let (publisher, bus) =
            PublicationBus::<u32>::new(100, usize::MAX, Duration::from_millis(1));
        publisher.publish(1, 4);
        std::thread::sleep(Duration::from_millis(20));
        publisher.publish(2, 4);
        let inner = bus.inner.lock().unwrap();
        assert_eq!(
            inner.ring.len(),
            1,
            "the stale first item must have aged out"
        );
        assert_eq!(inner.ring.front().unwrap().sequence, 1);
    }

    #[test]
    fn unsubscribe_releases_its_cursor_and_does_not_affect_other_subscriptions() {
        let (publisher, bus) = PublicationBus::<u32>::new(2, usize::MAX, Duration::from_secs(60));
        let departing = bus.subscribe();
        let mut staying = bus.subscribe();
        assert_eq!(bus.subscriber_count(), 2);

        departing.unsubscribe();
        assert_eq!(bus.subscriber_count(), 1);

        publisher.publish(1, 4);
        let RecvOutcome::Item(item) = staying.try_recv() else {
            panic!("expected an item");
        };
        assert_eq!(*item.item, 1);
    }

    #[test]
    fn resubscribing_starts_fresh_from_the_current_tail_not_from_retained_history() {
        let (publisher, bus) = PublicationBus::<u32>::new(10, usize::MAX, Duration::from_secs(60));
        publisher.publish(1, 4);
        publisher.publish(2, 4);

        let mut fresh = bus.subscribe();
        assert!(
            matches!(fresh.try_recv(), RecvOutcome::Empty),
            "a new subscription must not replay history published before it joined"
        );

        publisher.publish(3, 4);
        let RecvOutcome::Item(item) = fresh.try_recv() else {
            panic!("expected the item published after subscribing");
        };
        assert_eq!(*item.item, 3);
    }

    #[test]
    fn dropping_every_publisher_eventually_reports_closed() {
        let (publisher, bus) = PublicationBus::<u32>::new(10, usize::MAX, Duration::from_secs(60));
        let mut sub = bus.subscribe();
        publisher.publish(1, 4);
        drop(publisher);

        let RecvOutcome::Item(item) = sub.try_recv() else {
            panic!("the item published before the source closed must still be delivered");
        };
        assert_eq!(*item.item, 1);
        assert!(
            matches!(sub.try_recv(), RecvOutcome::Closed),
            "once every retained item is drained and every Publisher is gone, \
             a subscription must observe Closed, not Empty forever"
        );
    }

    #[test]
    fn safe_references_outlive_overwritten_slots() {
        let (publisher, bus) =
            PublicationBus::<Vec<u8>>::new(1, usize::MAX, Duration::from_secs(60));
        let mut sub = bus.subscribe();
        publisher.publish(b"kept".to_vec(), 4);
        let RecvOutcome::Item(held) = sub.try_recv() else {
            panic!("expected the first item");
        };
        // Evict the slot `held` came from by publishing past the
        // 1-item retention bound.
        publisher.publish(b"overwrites".to_vec(), 10);
        publisher.publish(b"overwrites again".to_vec(), 16);
        // The subscriber's own Arc-backed copy is completely unaffected
        // by the bus internally evicting/overwriting its ring slot.
        assert_eq!(held.item.as_slice(), b"kept");
    }

    /// Stress: a real producer thread publishing thousands of items
    /// concurrently with a consumer thread reading them, through many
    /// eviction cycles (the ring's own `VecDeque` grows and shrinks
    /// repeatedly rather than wrapping in place, but this still exercises
    /// sustained concurrent access under the shared `Mutex` -- the actual
    /// linearization point this card's own review checklist calls out).
    /// Every item the subscriber actually receives must be strictly
    /// increasing (no duplication, no reordering), and the total of what
    /// it received plus what it was ever told it lagged past can never
    /// exceed what the producer actually published.
    #[test]
    fn concurrent_publish_and_subscribe_stress_never_duplicates_or_reorders() {
        use std::thread;

        const ITEMS: u64 = 5_000;
        let (publisher, bus) = PublicationBus::<u64>::new(64, usize::MAX, Duration::from_secs(60));
        let mut sub = bus.subscribe();

        let producer = thread::spawn(move || {
            for i in 0..ITEMS {
                publisher.publish(i, 8);
            }
        });

        let mut received = Vec::new();
        let mut lagged_total = 0u64;
        loop {
            match sub.try_recv() {
                RecvOutcome::Item(item) => received.push(*item.item),
                RecvOutcome::Lagged { skipped } => lagged_total += skipped,
                RecvOutcome::Empty => {
                    if producer.is_finished() {
                        break;
                    }
                    thread::yield_now();
                }
                RecvOutcome::Closed => break,
            }
        }
        // Drain whatever the producer finished publishing just before it
        // exited but this consumer hadn't yet read.
        loop {
            match sub.try_recv() {
                RecvOutcome::Item(item) => received.push(*item.item),
                RecvOutcome::Lagged { skipped } => lagged_total += skipped,
                RecvOutcome::Empty | RecvOutcome::Closed => break,
            }
        }
        producer.join().expect("producer thread must not panic");

        for window in received.windows(2) {
            assert!(
                window[1] > window[0],
                "received items must be strictly increasing, got {window:?}"
            );
        }
        // Every sequence number the producer assigned (0..ITEMS) is
        // accounted for exactly once: either delivered as an `Item` or
        // reported as part of a `Lagged { skipped }` -- an equality, not
        // just an upper bound, since both loops only stop once this
        // subscription's cursor has caught all the way up to `ITEMS`
        // (via `Empty` after the producer finished, or `Closed`).
        assert_eq!(
            received.len() as u64 + lagged_total,
            ITEMS,
            "received ({}) + lagged ({lagged_total}) must exactly account for \
             everything published ({ITEMS}) -- neither more nor less",
            received.len()
        );
    }

    #[test]
    fn a_second_publisher_keeps_the_bus_open_after_the_first_is_dropped() {
        let (first, bus) = PublicationBus::<u32>::new(10, usize::MAX, Duration::from_secs(60));
        let second = first.clone();
        let mut sub = bus.subscribe();

        drop(first);
        second.publish(1, 4);

        // The bus must not report `Closed` while a clone of the original
        // `Publisher` is still alive and publishing, even though the
        // handle the bus was originally constructed with is gone.
        let RecvOutcome::Item(item) = sub.try_recv() else {
            panic!("expected an item: a live Publisher clone remains");
        };
        assert_eq!(*item.item, 1);
        assert!(
            matches!(sub.try_recv(), RecvOutcome::Empty),
            "not Closed: `second` is still alive"
        );
    }

    #[test]
    fn byte_bound_eviction_is_reported_to_a_subscriber_as_explicit_lag() {
        let (publisher, bus) = PublicationBus::<Vec<u8>>::new(100, 10, Duration::from_secs(60));
        let mut sub = bus.subscribe();
        publisher.publish(vec![0; 6], 6);
        publisher.publish(vec![0; 6], 6); // pushes total past the 10-byte bound

        match sub.try_recv() {
            RecvOutcome::Lagged { skipped } => assert_eq!(skipped, 1),
            other => panic!("expected Lagged from a byte-bound eviction, got {other:?}"),
        }
        let RecvOutcome::Item(item) = sub.try_recv() else {
            panic!("expected the still-retained second item");
        };
        assert_eq!(item.sequence, 1);
    }

    #[test]
    fn age_bound_eviction_is_reported_to_a_subscriber_as_explicit_lag() {
        let (publisher, bus) =
            PublicationBus::<u32>::new(100, usize::MAX, Duration::from_millis(1));
        let mut sub = bus.subscribe();
        publisher.publish(1, 4);
        std::thread::sleep(Duration::from_millis(20));
        publisher.publish(2, 4); // ages the first item out on this publish

        match sub.try_recv() {
            RecvOutcome::Lagged { skipped } => assert_eq!(skipped, 1),
            other => panic!("expected Lagged from an age-bound eviction, got {other:?}"),
        }
        let RecvOutcome::Item(item) = sub.try_recv() else {
            panic!("expected the still-retained second item");
        };
        assert_eq!(*item.item, 2);
    }

    #[test]
    fn an_item_larger_than_the_byte_bound_is_still_delivered_once() {
        // A shard configured with a byte bound smaller than one jumbo
        // payload must not silently drop every single item it is ever
        // given -- the sole retained item is delivered at least once
        // before any later publish can evict it.
        let (publisher, bus) = PublicationBus::<Vec<u8>>::new(100, 10, Duration::from_secs(60));
        let mut sub = bus.subscribe();
        publisher.publish(vec![0; 50], 50);

        let RecvOutcome::Item(item) = sub.try_recv() else {
            panic!("an oversized-for-its-bound item must still be delivered");
        };
        assert_eq!(item.item.len(), 50);
    }

    #[test]
    fn stats_reports_lifetime_publish_and_eviction_counts() {
        let (publisher, bus) = PublicationBus::<u32>::new(1, usize::MAX, Duration::from_secs(60));
        assert_eq!(bus.stats(), BusStats::default());

        publisher.publish(1, 4);
        publisher.publish(2, 4); // evicts sequence 0 under the 1-item bound

        let stats = bus.stats();
        assert_eq!(stats.published, 2);
        assert_eq!(stats.evicted, 1);
    }

    #[test]
    fn publisher_subscribe_is_equivalent_to_bus_subscribe() {
        let (publisher, _bus) = PublicationBus::<u32>::new(10, usize::MAX, Duration::from_secs(60));
        let mut sub = publisher.subscribe();
        publisher.publish(1, 4);
        let RecvOutcome::Item(item) = sub.try_recv() else {
            panic!("expected an item via a Publisher-minted subscription");
        };
        assert_eq!(*item.item, 1);
    }
}
