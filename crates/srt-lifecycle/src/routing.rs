//! Worker ownership and logical-group routing policy.

use std::collections::HashMap;
use std::hash::Hash;

use crate::identity::{GroupAffinity, LogicalGroupKey};

/// Worker assignment policy for newly admitted transport tuples.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RoutingMode {
    RoundRobin,
    LeastTuples,
}

/// Clamp a requested worker count to a non-zero host budget.
#[must_use]
pub fn worker_count(requested: usize, available_parallelism: usize) -> usize {
    requested.max(1).min(available_parallelism.max(1))
}

/// Owns tuple and logical-group assignment state without owning the workers.
///
/// `K` is the application/runtime's transport key. this repo uses the peer
/// socket tuple; the harness uses its tuple plus the protocol socket ID. The
/// policy therefore cannot accidentally impose one runtime's key shape on the
/// other.
pub struct WorkerRouter<K> {
    tuple_workers: HashMap<K, usize>,
    tuple_groups: HashMap<K, LogicalGroupKey>,
    group_workers: HashMap<LogicalGroupKey, usize>,
    group_tuple_counts: HashMap<LogicalGroupKey, usize>,
    worker_tuple_counts: Vec<usize>,
    next_worker: usize,
}

impl<K> WorkerRouter<K>
where
    K: Eq + Hash + Clone,
{
    /// Create routing state for `worker_count` logical workers.
    #[must_use]
    pub fn new(worker_count: usize) -> Self {
        Self {
            tuple_workers: HashMap::new(),
            tuple_groups: HashMap::new(),
            group_workers: HashMap::new(),
            group_tuple_counts: HashMap::new(),
            worker_tuple_counts: vec![0; worker_count.max(1)],
            next_worker: 0,
        }
    }

    /// Assign a transport key, preserving any existing tuple or group owner.
    pub fn assign(&mut self, key: K, group: Option<GroupAffinity>, mode: RoutingMode) -> usize {
        if let Some(worker) = self.tuple_workers.get(&key).copied() {
            if let Some(group) = group {
                self.register_group(key, worker, group);
            }
            return worker;
        }

        let worker = group
            .as_ref()
            .and_then(|affinity| self.group_workers.get(&affinity.logical_key()).copied())
            .unwrap_or_else(|| self.select_worker(mode));
        self.tuple_workers.insert(key.clone(), worker);
        self.worker_tuple_counts[worker] = self.worker_tuple_counts[worker].saturating_add(1);
        if let Some(group) = group {
            self.register_group(key, worker, group);
        }
        worker
    }

    /// Release one transport key and drop its logical group when its final
    /// physical leg disconnects.
    pub fn release(&mut self, key: &K) -> Option<LogicalGroupKey> {
        let worker = self.tuple_workers.remove(key)?;
        self.worker_tuple_counts[worker] = self.worker_tuple_counts[worker].saturating_sub(1);
        if let Some(group_key) = self.tuple_groups.remove(key)
            && let Some(count) = self.group_tuple_counts.get_mut(&group_key)
        {
            *count = count.saturating_sub(1);
            if *count == 0 {
                self.group_tuple_counts.remove(&group_key);
                self.group_workers.remove(&group_key);
                return Some(group_key);
            }
        }
        None
    }

    /// Number of currently owned transport keys.
    #[must_use]
    pub fn active_tuple_count(&self) -> usize {
        self.tuple_workers.len()
    }

    /// Number of currently retained logical groups.
    #[must_use]
    pub fn active_group_count(&self) -> usize {
        self.group_workers.len()
    }

    fn register_group(&mut self, key: K, worker: usize, group: GroupAffinity) {
        if self.tuple_groups.contains_key(&key) {
            return;
        }
        let group_key = group.logical_key();
        self.group_workers
            .entry(group_key.clone())
            .or_insert(worker);
        self.group_tuple_counts
            .entry(group_key.clone())
            .and_modify(|count| *count = count.saturating_add(1))
            .or_insert(1);
        self.tuple_groups.insert(key, group_key);
    }

    fn select_worker(&mut self, mode: RoutingMode) -> usize {
        let worker = match mode {
            RoutingMode::RoundRobin => self.next_worker % self.worker_tuple_counts.len(),
            RoutingMode::LeastTuples => {
                let mut selected = self.next_worker % self.worker_tuple_counts.len();
                for offset in 1..self.worker_tuple_counts.len() {
                    let candidate = (self.next_worker + offset) % self.worker_tuple_counts.len();
                    if self.worker_tuple_counts[candidate] < self.worker_tuple_counts[selected] {
                        selected = candidate;
                    }
                }
                selected
            }
        };
        self.next_worker = worker.wrapping_add(1);
        worker
    }
}
