//! Per-socket wakeups for a task that polls many sockets' readiness.
//!
//! An Owner holding one connected socket per promoted session must not
//! visit every socket to learn which one became readable: that is work per
//! service visit (or wait) proportional to the promoted population. Instead
//! each socket's readiness is polled with its own [`Waker`], which records
//! the socket's slot in a shared list and then wakes the Owner's task. The
//! Owner re-polls only the slots that list names, plus the ones it drained
//! itself, so finding receive work costs O(sockets that changed state).

use std::sync::{Arc, Mutex, PoisonError};
use std::task::{Wake, Waker};

#[derive(Default)]
struct Shared {
    /// Slots whose readiness poll completed since the last
    /// [`SlotWakeups::take_woken`].
    woken: Mutex<Vec<usize>>,
    /// The task to wake when a slot's readiness completes.
    task: Mutex<Option<Waker>>,
}

struct SlotWake {
    slot: usize,
    shared: Arc<Shared>,
}

impl Wake for SlotWake {
    fn wake(self: Arc<Self>) {
        self.wake_by_ref();
    }

    fn wake_by_ref(self: &Arc<Self>) {
        self.shared
            .woken
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(self.slot);
        let task = self
            .shared
            .task
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone();
        if let Some(task) = task {
            task.wake();
        }
    }
}

/// The wakeup list shared by one Owner's promoted sockets.
#[derive(Default)]
pub(crate) struct SlotWakeups {
    shared: Arc<Shared>,
}

impl SlotWakeups {
    /// The waker to poll slot `slot`'s readiness with.
    pub(crate) fn waker(&self, slot: usize) -> Waker {
        Waker::from(Arc::new(SlotWake {
            slot,
            shared: Arc::clone(&self.shared),
        }))
    }

    /// Wake `task` when any slot's readiness completes.
    pub(crate) fn register_task(&self, task: &Waker) {
        let mut current = self
            .shared
            .task
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if !current
            .as_ref()
            .is_some_and(|current| current.will_wake(task))
        {
            *current = Some(task.clone());
        }
    }

    /// Move the slots woken since the last call into `into`.
    pub(crate) fn take_woken(&self, into: &mut Vec<usize>) {
        into.append(
            &mut self
                .shared
                .woken
                .lock()
                .unwrap_or_else(PoisonError::into_inner),
        );
    }

    /// Whether any slot was woken since the last [`Self::take_woken`].
    #[cfg(any(test, feature = "tokio"))]
    pub(crate) fn has_woken(&self) -> bool {
        !self
            .shared
            .woken
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct CountingWake(AtomicUsize);

    impl Wake for CountingWake {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
    }

    #[test]
    fn a_slot_wake_records_the_slot_and_wakes_the_task() {
        let wakeups = SlotWakeups::default();
        let task = Arc::new(CountingWake(AtomicUsize::new(0)));
        wakeups.register_task(&Waker::from(Arc::clone(&task)));
        assert!(!wakeups.has_woken());
        wakeups.waker(7).wake_by_ref();
        wakeups.waker(3).wake();
        assert!(wakeups.has_woken());
        let mut woken = Vec::new();
        wakeups.take_woken(&mut woken);
        assert_eq!(woken, vec![7, 3]);
        assert!(!wakeups.has_woken());
        assert_eq!(task.0.load(Ordering::Relaxed), 2);
    }
}
