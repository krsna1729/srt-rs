//! Runtime-neutral SRT admission and worker-affinity policy.
//!
//! This crate deliberately stops at the lifecycle boundary. It owns the
//! logical identity and assignment invariants that must be shared by a
//! listener and its workers, but it does not own sockets, clocks, threads,
//! event loops, media delivery, or authorization.

use std::collections::HashMap;
use std::hash::Hash;
use std::time::{Duration, Instant};

use shiguredo_srt::{GroupExtensionData, HandshakePacket, HandshakeType, SrtPacket};

/// Group metadata observed during handshake admission.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupAffinity {
    pub group_id: u32,
    pub stream_id: Option<String>,
    pub extension: GroupExtensionData,
}

/// Handshake identity available before the protocol Core processes conclusion.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HandshakeIdentity {
    pub is_conclusion: bool,
    pub stream_id: Option<String>,
    pub group: Option<GroupAffinity>,
    /// The SYN cookie carried by this datagram. On a CONCLUSION this is
    /// the value the listener issued during INDUCTION and the caller
    /// echoed back, which makes it the one field on the wire that can
    /// carry listener-chosen routing information through the handshake.
    /// See [`cookie_for_worker`].
    pub syn_cookie: u32,
}

impl GroupAffinity {
    /// Return the stable logical identity used to keep all physical legs on
    /// one worker. The wire StreamID is normalized only at this boundary.
    #[must_use]
    pub fn logical_key(&self) -> LogicalGroupKey {
        LogicalGroupKey {
            group_id: self.group_id,
            stream_id: normalize_stream_id(self.stream_id.clone()),
        }
    }
}

/// Stable identity for one logical bonded publisher.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct LogicalGroupKey {
    pub group_id: u32,
    pub stream_id: Option<String>,
}

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

/// Is a connection done -- either it never completed its handshake within
/// the connect window, it ran its full stream and hit its own deadline,
/// or it went idle past `idle_grace` -- such that a worker no longer
/// needs to service it to make progress?
///
/// Pure connection-lifecycle policy, independent of transport: any
/// listener tracking a connection from admission through completion
/// (whether or not it ever gets a dedicated promoted socket) needs this
/// exact three-way check, and every one of ours used to reimplement it
/// by hand.
///
/// - `stream_deadline`: `None` until the connection's first `Connected`
///   event; the caller sets it then (typically `now + stream_length`).
///   While `None`, the only way to become terminal is running out the
///   connect window (`now >= connect_deadline`) without ever connecting.
/// - `connected`: the transport's *live* connected flag (false once a
///   `Disconnected` event fires) -- distinct from "ever connected"
///   (`stream_deadline.is_some()`), which callers should use instead for
///   final success/delivery reporting: a session that streamed
///   everything and then legitimately tripped the peer's own idle
///   timeout is still a successful connection, not a failed one.
#[must_use]
pub fn is_terminal(
    connected: bool,
    stream_deadline: Option<Instant>,
    last_data_at: Instant,
    now: Instant,
    connect_deadline: Instant,
    idle_grace: Duration,
) -> bool {
    match stream_deadline {
        Some(deadline) => {
            !connected
                || now >= deadline
                || now.saturating_duration_since(last_data_at) >= idle_grace
        }
        None => now >= connect_deadline,
    }
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

/// Normalize a wire StreamID for logical group affinity.
#[must_use]
pub fn normalize_stream_id(stream_id: Option<String>) -> Option<String> {
    stream_id.and_then(|stream_id| {
        let normalized = stream_id.trim_matches('\0').trim().to_string();
        (!normalized.is_empty()).then_some(normalized)
    })
}

/// Most workers whose index can be carried in a SYN cookie.
///
/// The index occupies the low byte, so a deployment with more acceptor
/// threads than this cannot use cookie routing and must fall back to
/// leaving flows wherever the kernel put them.
pub const MAX_COOKIE_WORKERS: usize = 256;

/// Build the SYN cookie a listener should issue for a peer, with the
/// owning worker's index encoded in its low byte.
///
/// SRT's handshake is INDUCTION -> response -> CONCLUSION -> response.
/// The listener chooses the cookie in the INDUCTION response and the
/// caller echoes it in CONCLUSION, so with several acceptors sharing one
/// SO_REUSEPORT port, the cookie is what lets whichever acceptor the
/// kernel happens to hand the CONCLUSION to discover who owns the
/// half-open handshake and forward it there. Without it, a group change
/// between the two caller packets (which promoting a connection causes --
/// see crates/srt-transport/tests/reuseport_rehash.rs) strands the
/// handshake on an acceptor holding no state for it.
///
/// `peer_hash` supplies the upper 24 bits so cookies still differ per
/// peer rather than being a constant per worker. This is routing
/// metadata, not a security boundary: the cookie remains as guessable as
/// whatever `peer_hash` provides.
#[must_use]
pub fn cookie_for_worker(worker: usize, peer_hash: u32) -> u32 {
    (peer_hash & 0xFFFF_FF00) | ((worker as u32) & 0xFF)
}

/// Recover the owning worker index from a cookie seen on the wire.
///
/// Returns `None` when the encoded index is not a valid worker for this
/// listener, which covers both a cookie this listener never issued and a
/// `worker_count` beyond [`MAX_COOKIE_WORKERS`]. Callers should treat
/// `None` as "no routing information" and handle the datagram locally
/// rather than dropping it.
#[must_use]
pub fn worker_from_cookie(cookie: u32, worker_count: usize) -> Option<usize> {
    if worker_count == 0 || worker_count > MAX_COOKIE_WORKERS {
        return None;
    }
    let worker = (cookie & 0xFF) as usize;
    (worker < worker_count).then_some(worker)
}

/// Extract the handshake phase and optional GROUP affinity from one datagram.
#[must_use]
pub fn handshake_route(packet: &[u8]) -> Option<(bool, Option<GroupAffinity>)> {
    let identity = handshake_identity(packet)?;
    Some((identity.is_conclusion, identity.group))
}

/// Decode the StreamID and GROUP identity from a handshake datagram.
#[must_use]
pub fn handshake_identity(packet: &[u8]) -> Option<HandshakeIdentity> {
    let SrtPacket::Control(control) = SrtPacket::decode(packet).ok()? else {
        return None;
    };
    let handshake = HandshakePacket::decode(&control).ok()?;
    let is_conclusion = matches!(handshake.handshake_type, HandshakeType::Conclusion);
    let stream_id = handshake.get_sid_extension();
    let group = handshake
        .get_group_extension()
        .map(|extension| GroupAffinity {
            group_id: extension.group_id,
            stream_id: stream_id.clone(),
            extension,
        });
    Some(HandshakeIdentity {
        is_conclusion,
        stream_id,
        group,
        syn_cookie: handshake.syn_cookie,
    })
}

/// Convenience for callers that only need GROUP metadata from a datagram.
#[must_use]
pub fn group_extension_from_packet(packet: &[u8]) -> Option<(GroupExtensionData, Option<String>)> {
    let (_, affinity) = handshake_route(packet)?;
    let affinity = affinity?;
    Some((affinity.extension, affinity.stream_id))
}

#[cfg(test)]
mod cookie_tests {
    use super::*;

    #[test]
    fn cookie_round_trips_the_owning_worker() {
        for workers in [1usize, 2, 4, 17, 64, 256] {
            for worker in 0..workers {
                let cookie = cookie_for_worker(worker, 0xDEAD_BE00);
                assert_eq!(
                    worker_from_cookie(cookie, workers),
                    Some(worker),
                    "worker {worker} of {workers} did not survive the cookie round trip"
                );
            }
        }
    }

    #[test]
    fn cookie_keeps_peer_entropy_outside_the_index_byte() {
        // Two peers on the same worker must still get distinct cookies,
        // or the cookie stops being per-connection at all.
        let a = cookie_for_worker(3, 0x1111_1100);
        let b = cookie_for_worker(3, 0x2222_2200);
        assert_ne!(a, b);
        assert_eq!(a & 0xFF, 3);
        assert_eq!(b & 0xFF, 3);
    }

    #[test]
    fn cookie_index_beyond_worker_count_is_not_routable() {
        // A cookie this listener never issued (or one from a previous
        // run with more workers) must not route to a nonexistent worker.
        let cookie = cookie_for_worker(9, 0);
        assert_eq!(worker_from_cookie(cookie, 4), None);
    }

    #[test]
    fn cookie_routing_is_declined_for_unsupported_worker_counts() {
        assert_eq!(worker_from_cookie(0, 0), None);
        assert_eq!(worker_from_cookie(0, MAX_COOKIE_WORKERS + 1), None);
        // Exactly at the limit is still fine.
        assert_eq!(
            worker_from_cookie(cookie_for_worker(255, 0), 256),
            Some(255)
        );
    }
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;

    use super::*;
    use shiguredo_srt::{GroupType, SRTGROUP_MASK};

    #[test]
    fn is_terminal_never_connected_waits_for_connect_window() {
        let now = Instant::now();
        let connect_deadline = now + Duration::from_secs(5);
        assert!(!is_terminal(
            false,
            None,
            now,
            now,
            connect_deadline,
            Duration::from_secs(10)
        ));
        assert!(is_terminal(
            false,
            None,
            now,
            connect_deadline,
            connect_deadline,
            Duration::from_secs(10)
        ));
    }

    #[test]
    fn is_terminal_connected_and_streaming_is_not_terminal() {
        let now = Instant::now();
        let stream_deadline = now + Duration::from_secs(10);
        assert!(!is_terminal(
            true,
            Some(stream_deadline),
            now,
            now,
            now,
            Duration::from_secs(10)
        ));
    }

    #[test]
    fn is_terminal_disconnected_is_terminal_even_before_its_deadline() {
        let now = Instant::now();
        let stream_deadline = now + Duration::from_secs(10);
        assert!(is_terminal(
            false, // live connected flag flipped false
            Some(stream_deadline),
            now,
            now,
            now,
            Duration::from_secs(10)
        ));
    }

    #[test]
    fn is_terminal_past_stream_deadline_is_terminal() {
        let now = Instant::now();
        let stream_deadline = now;
        assert!(is_terminal(
            true,
            Some(stream_deadline),
            now,
            now,
            now,
            Duration::from_secs(10)
        ));
    }

    #[test]
    fn is_terminal_idle_past_grace_is_terminal_even_before_stream_deadline() {
        let now = Instant::now();
        let stream_deadline = now + Duration::from_secs(60);
        let last_data_at = now;
        let idle_grace = Duration::from_secs(10);
        assert!(!is_terminal(
            true,
            Some(stream_deadline),
            last_data_at,
            now + Duration::from_secs(9),
            now,
            idle_grace
        ));
        assert!(is_terminal(
            true,
            Some(stream_deadline),
            last_data_at,
            now + Duration::from_secs(10),
            now,
            idle_grace
        ));
    }

    fn group(stream_id: Option<&str>) -> GroupAffinity {
        GroupAffinity {
            group_id: SRTGROUP_MASK | 0x42,
            stream_id: stream_id.map(str::to_owned),
            extension: GroupExtensionData {
                group_id: SRTGROUP_MASK | 0x42,
                group_type: GroupType::Broadcast,
                flags: 0,
                weight: 7,
            },
        }
    }

    #[test]
    fn group_affinity_survives_member_disconnect_and_reuses_worker() {
        let mut router = WorkerRouter::new(4);
        let first = SocketAddr::from(([127, 0, 0, 1], 20_001));
        let second = SocketAddr::from(([192, 0, 2, 1], 20_002));
        let third = SocketAddr::from(([198, 51, 100, 1], 20_003));
        let affinity = group(Some("publish:camera\0"));

        let first_worker = router.assign(first, Some(affinity.clone()), RoutingMode::RoundRobin);
        let second_worker = router.assign(second, Some(affinity.clone()), RoutingMode::LeastTuples);
        assert_eq!(second_worker, first_worker);
        assert_eq!(router.release(&first), None);

        let third_worker = router.assign(third, Some(affinity.clone()), RoutingMode::RoundRobin);
        assert_eq!(third_worker, second_worker);
        assert_eq!(router.release(&second), None);
        assert_eq!(router.release(&third), Some(affinity.logical_key()));
        assert_eq!(router.active_tuple_count(), 0);
        assert_eq!(router.active_group_count(), 0);
    }

    #[test]
    fn stream_id_is_part_of_logical_group_identity() {
        let mut router = WorkerRouter::new(2);
        let first = SocketAddr::from(([127, 0, 0, 1], 21_001));
        let second = SocketAddr::from(([127, 0, 0, 1], 21_002));
        let first_worker = router.assign(first, Some(group(Some("one"))), RoutingMode::RoundRobin);
        let second_worker =
            router.assign(second, Some(group(Some("two"))), RoutingMode::RoundRobin);
        assert_ne!(first_worker, second_worker);
    }

    #[test]
    fn worker_count_never_reaches_zero_or_exceeds_budget() {
        assert_eq!(worker_count(0, 8), 1);
        assert_eq!(worker_count(2, 8), 2);
        assert_eq!(worker_count(99, 4), 4);
        assert_eq!(worker_count(99, 0), 1);
    }

    #[test]
    fn conclusion_identity_exposes_stream_without_group_metadata() {
        let mut handshake = HandshakePacket::new_conclusion_request(1, 2, 3, 0, false);
        handshake.add_sid_extension("publish:camera");
        let mut packet = Vec::new();
        handshake.encode(0, 0).encode(&mut packet);

        let identity = super::handshake_identity(&packet).expect("handshake identity");
        assert!(identity.is_conclusion);
        assert_eq!(identity.stream_id.as_deref(), Some("publish:camera"));
        assert!(identity.group.is_none());
    }
}

/// `WorkerRouter` invariants, checked against random sequences of
/// assign/release ops rather than fixed scenarios. The property under test
/// throughout is the crate's whole reason to exist: once a logical group
/// has an owner, every physical leg of that group must land on the same
/// worker, no matter the interleaving of assigns and releases across other
/// keys and groups.
#[cfg(test)]
mod proptests {
    use super::*;
    use proptest::prelude::*;
    use shiguredo_srt::GroupType;
    use std::collections::{HashMap, HashSet};

    fn affinity(group_id: u8) -> GroupAffinity {
        GroupAffinity {
            group_id: group_id as u32,
            stream_id: None,
            extension: GroupExtensionData {
                group_id: group_id as u32,
                group_type: GroupType::Broadcast,
                flags: 0,
                weight: 0,
            },
        }
    }

    #[derive(Debug, Clone)]
    enum Op {
        Assign {
            key: u8,
            group_id: Option<u8>,
            round_robin: bool,
        },
        Release {
            key: u8,
        },
    }

    fn op_strategy() -> impl Strategy<Value = Op> {
        prop_oneof![
            (0u8..6, proptest::option::of(0u8..3), any::<bool>()).prop_map(
                |(key, group_id, round_robin)| Op::Assign {
                    key,
                    group_id,
                    round_robin,
                }
            ),
            (0u8..6).prop_map(|key| Op::Release { key }),
        ]
    }

    proptest! {
        #[test]
        fn worker_router_upholds_invariants(
            ops in proptest::collection::vec(op_strategy(), 1..200),
            worker_count in 1usize..5,
        ) {
            let mut router: WorkerRouter<u8> = WorkerRouter::new(worker_count);
            // Shadow model, checked against the router's own counters at
            // the end and used to compute the expected outcome of each op
            // as we go.
            let mut tuple_worker: HashMap<u8, usize> = HashMap::new();
            let mut tuple_group: HashMap<u8, u8> = HashMap::new();
            let mut group_worker: HashMap<u8, usize> = HashMap::new();
            let mut group_members: HashMap<u8, HashSet<u8>> = HashMap::new();

            for op in ops {
                match op {
                    Op::Assign { key, group_id, round_robin } => {
                        let mode = if round_robin {
                            RoutingMode::RoundRobin
                        } else {
                            RoutingMode::LeastTuples
                        };
                        let worker = router.assign(key, group_id.map(affinity), mode);
                        prop_assert!(worker < worker_count);

                        let is_new_tuple = !tuple_worker.contains_key(&key);
                        if is_new_tuple {
                            // New tuple joining an already-owned group must
                            // land on that group's existing owner, never a
                            // freshly scheduled worker.
                            if let Some(gid) = group_id
                                && let Some(&owner) = group_worker.get(&gid)
                            {
                                prop_assert_eq!(worker, owner);
                            }
                            tuple_worker.insert(key, worker);
                        } else {
                            // An already-owned tuple's worker never moves,
                            // regardless of what group (if any) is passed
                            // on a later assign for the same key.
                            prop_assert_eq!(worker, tuple_worker[&key]);
                        }

                        // First time this key is associated with a group
                        // (mirrors `register_group`'s own idempotency
                        // guard): record it.
                        if let Some(gid) = group_id
                            && !tuple_group.contains_key(&key)
                        {
                            group_worker.entry(gid).or_insert(worker);
                            tuple_group.insert(key, gid);
                            group_members.entry(gid).or_default().insert(key);
                        }
                    }
                    Op::Release { key } => {
                        let existed = tuple_worker.remove(&key).is_some();
                        let released_group = router.release(&key);

                        if !existed {
                            prop_assert_eq!(released_group, None);
                            continue;
                        }
                        match tuple_group.remove(&key) {
                            None => prop_assert_eq!(released_group, None),
                            Some(gid) => {
                                let now_empty = {
                                    let members =
                                        group_members.get_mut(&gid).expect("group was tracked");
                                    members.remove(&key);
                                    members.is_empty()
                                };
                                if now_empty {
                                    group_members.remove(&gid);
                                    group_worker.remove(&gid);
                                    prop_assert!(released_group.is_some());
                                } else {
                                    prop_assert_eq!(released_group, None);
                                }
                            }
                        }
                    }
                }
            }

            prop_assert_eq!(router.active_tuple_count(), tuple_worker.len());
            prop_assert_eq!(router.active_group_count(), group_worker.len());
        }
    }
}
