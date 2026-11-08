//! Per-thread counters of loop work done by protocol entry points.
//!
//! Each counter is incremented inside the loop that does the work, once per
//! iteration, so a test can bound what one `feed_recv_*`, `handle_timer`,
//! `poll_output_into`, `send` or group poll did by taking a
//! [`WorkCounters::snapshot`] before and after it. Counters are
//! thread-local, so parallel tests do not interfere. Take the snapshot
//! before calling a statistics method: statistics walk retained state on
//! purpose and are not part of any bounded path.
//!
//! The counting sites expand to nothing unless the crate is built for its own
//! unit tests: benches and dependents' tests run the uncounted code.

use std::cell::Cell;

/// One kind of counted work.
#[derive(Debug, Clone, Copy)]
pub(crate) enum Counter {
    PacketSlotProbes,
    BitmapDataWords,
    BitmapSummaryWords,
    SuccessorProbes,
    DeadlineProbes,
    LossEntriesVisited,
    FrontierSteps,
    PendingKeysVisited,
    ReleasedChunks,
    SenderSlotProbes,
    SenderRecordProbes,
    OutputQueueVisits,
}

const COUNTERS: usize = Counter::OutputQueueVisits as usize + 1;

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
pub struct WorkCounters {
    /// Receive packet-window slot, page and page-index probes.
    pub packet_slot_probes: u64,
    /// Data words of a receive bitmap (loss list or packet liveness) read or
    /// written.
    pub bitmap_data_words: u64,
    /// Summary (index) words of a receive bitmap read or written.
    pub bitmap_summary_words: u64,
    /// Lookups of the retained packet after a missing position.
    pub successor_probes: u64,
    /// TSBPD delivery-deadline evaluations.
    pub deadline_probes: u64,
    /// Individual loss positions enumerated.
    pub loss_entries_visited: u64,
    /// Single-position steps of the expected-sequence frontier.
    pub frontier_steps: u64,
    /// Group pending-payload keys inspected.
    pub pending_keys_visited: u64,
    /// Retained payloads physically released.
    pub released_chunks: u64,
    /// Send packet-window slots read or written inside a loop.
    pub sender_slot_probes: u64,
    /// Dropped-message records inspected.
    pub sender_record_probes: u64,
    /// Queued output actions inspected.
    pub output_queue_visits: u64,
}

impl WorkCounters {
    /// This thread's counters now.
    #[must_use]
    pub fn snapshot() -> Self {
        WORK.with(|work| {
            let get = |counter: Counter| work[counter as usize].get();
            Self {
                packet_slot_probes: get(Counter::PacketSlotProbes),
                bitmap_data_words: get(Counter::BitmapDataWords),
                bitmap_summary_words: get(Counter::BitmapSummaryWords),
                successor_probes: get(Counter::SuccessorProbes),
                deadline_probes: get(Counter::DeadlineProbes),
                loss_entries_visited: get(Counter::LossEntriesVisited),
                frontier_steps: get(Counter::FrontierSteps),
                pending_keys_visited: get(Counter::PendingKeysVisited),
                released_chunks: get(Counter::ReleasedChunks),
                sender_slot_probes: get(Counter::SenderSlotProbes),
                sender_record_probes: get(Counter::SenderRecordProbes),
                output_queue_visits: get(Counter::OutputQueueVisits),
            }
        })
    }

    /// Zero this thread's counters.
    pub fn reset() {
        WORK.with(|work| work.iter().for_each(|cell| cell.set(0)));
    }

    /// Work done since `before`, a snapshot taken earlier on this thread.
    #[must_use]
    pub fn since(before: Self) -> Self {
        let now = Self::snapshot();
        Self {
            packet_slot_probes: now.packet_slot_probes - before.packet_slot_probes,
            bitmap_data_words: now.bitmap_data_words - before.bitmap_data_words,
            bitmap_summary_words: now.bitmap_summary_words - before.bitmap_summary_words,
            successor_probes: now.successor_probes - before.successor_probes,
            deadline_probes: now.deadline_probes - before.deadline_probes,
            loss_entries_visited: now.loss_entries_visited - before.loss_entries_visited,
            frontier_steps: now.frontier_steps - before.frontier_steps,
            pending_keys_visited: now.pending_keys_visited - before.pending_keys_visited,
            released_chunks: now.released_chunks - before.released_chunks,
            sender_slot_probes: now.sender_slot_probes - before.sender_slot_probes,
            sender_record_probes: now.sender_record_probes - before.sender_record_probes,
            output_queue_visits: now.output_queue_visits - before.output_queue_visits,
        }
    }

    /// Run `f` and return its result with the work it did.
    pub fn measure<T>(f: impl FnOnce() -> T) -> (T, Self) {
        let before = Self::snapshot();
        let result = f();
        (result, Self::since(before))
    }

    /// Bitmap words of either level.
    #[must_use]
    pub fn bitmap_words(&self) -> u64 {
        self.bitmap_data_words + self.bitmap_summary_words
    }
}
