//! Per-thread counters of loop work done by transport entry points.
//!
//! Each counter is incremented inside the loop that does the work, once per
//! iteration, so a test can bound what one admission, service visit,
//! maintenance pass or retirement did by taking a [`WorkCounters::snapshot`]
//! before and after it. Counters are thread-local, so parallel tests do not
//! interfere.
//!
//! The module and every counting site exist only in this crate's own unit
//! tests: production builds, benches and dependents carry none of it.

use std::cell::Cell;

/// One kind of counted work.
#[derive(Debug, Clone, Copy)]
pub(crate) enum Counter {
    ArenaSlotProbes,
    RouteIndexProbes,
    HeapEntriesVisited,
    HeapEntriesCloned,
    PromotedSlotProbes,
    RetirementProbes,
    ReceiverStatEntries,
}

const COUNTERS: usize = Counter::ReceiverStatEntries as usize + 1;

thread_local! {
    static WORK: [Cell<u64>; COUNTERS] = const { [const { Cell::new(0) }; COUNTERS] };
}

pub(crate) fn add(counter: Counter, units: u64) {
    WORK.with(|work| {
        let cell = &work[counter as usize];
        cell.set(cell.get().saturating_add(units));
    });
}

/// A scalar snapshot of this thread's work counters.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct WorkCounters {
    /// Dense-arena slots visited by a whole-arena walk, empty slots included.
    pub arena_slot_probes: u64,
    /// Listener route-index lookups (address, caller ID, cookie).
    pub route_index_probes: u64,
    /// Deadline-heap entries popped, inspected at the head, or moved by a sift.
    pub heap_entries_visited: u64,
    /// Deadline-heap keys cloned into a rebuilt heap.
    pub heap_entries_cloned: u64,
    /// Promoted-socket slots examined for receive readiness or drained.
    pub promoted_slot_probes: u64,
    /// Index entries a retirement examined or removed to forget one session:
    /// failure, fault and resolution queue entries and routes.
    pub retirement_probes: u64,
    /// Receive-buffer entries walked to sample a connection's receiver
    /// counters.
    pub receiver_stat_entries: u64,
}

impl WorkCounters {
    /// This thread's counters now.
    #[must_use]
    pub(crate) fn snapshot() -> Self {
        WORK.with(|work| {
            let get = |counter: Counter| work[counter as usize].get();
            Self {
                arena_slot_probes: get(Counter::ArenaSlotProbes),
                route_index_probes: get(Counter::RouteIndexProbes),
                heap_entries_visited: get(Counter::HeapEntriesVisited),
                heap_entries_cloned: get(Counter::HeapEntriesCloned),
                promoted_slot_probes: get(Counter::PromotedSlotProbes),
                retirement_probes: get(Counter::RetirementProbes),
                receiver_stat_entries: get(Counter::ReceiverStatEntries),
            }
        })
    }

    /// Work done since `before`, a snapshot taken earlier on this thread.
    #[must_use]
    pub(crate) fn since(before: Self) -> Self {
        let now = Self::snapshot();
        Self {
            arena_slot_probes: now.arena_slot_probes - before.arena_slot_probes,
            route_index_probes: now.route_index_probes - before.route_index_probes,
            heap_entries_visited: now.heap_entries_visited - before.heap_entries_visited,
            heap_entries_cloned: now.heap_entries_cloned - before.heap_entries_cloned,
            promoted_slot_probes: now.promoted_slot_probes - before.promoted_slot_probes,
            retirement_probes: now.retirement_probes - before.retirement_probes,
            receiver_stat_entries: now.receiver_stat_entries - before.receiver_stat_entries,
        }
    }

    /// Run `f` and return its result with the work it did.
    pub(crate) fn measure<T>(f: impl FnOnce() -> T) -> (T, Self) {
        let before = Self::snapshot();
        let result = f();
        (result, Self::since(before))
    }
}
