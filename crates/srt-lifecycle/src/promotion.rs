//! Admission promotion and reuseport planning policy.

use std::hash::Hash;

use crate::identity::GroupAffinity;
use crate::routing::{RoutingMode, WorkerRouter};

/// Which connections get their own connected socket (and, on a runtime
/// with a task scheduler, their own task) at their first `Connected`.
///
/// The modes nest: `Never` ⊂ `Relocate` ⊂ `Bonded` ⊂ `All`, each adding
/// one population to the set that gets promoted. They exist as a knob
/// rather than a decision because the tradeoff is genuinely
/// runtime-dependent -- promotion buys independent scheduling, which only
/// helps a runtime that has a scheduler to exploit, and costs socket
/// churn plus SO_REUSEPORT group perturbation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Promotion {
    /// Nothing ever promotes, and group affinity is abandoned: bonded
    /// legs stay wherever the kernel hashed them. The diagnostic control
    /// that says what affinity plus relocation actually buy.
    Never,
    /// Only a bonded leg whose group owner is a *different* worker.
    /// Irreducible: moving a connection between reactors requires an fd
    /// the destination can register.
    Relocate,
    /// Every bonded leg, including ones already on their owner.
    Bonded,
    /// Every connection.
    All,
}

/// What should happen to a connection that has just reached `Connected`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PromotionDecision {
    /// Keep servicing it off the shared listener. No new socket, so the
    /// reuseport group is undisturbed. Demux is by SRT socket ID, which
    /// is what lets N sessions share one UDP 4-tuple.
    StayOnListener,
    /// Give it a private connected socket on this same worker.
    PromoteHere,
    /// Hand it to another worker, which requires a private connected
    /// socket to send across. The index is never this worker's own.
    RelocateTo(usize),
}

impl PromotionDecision {
    /// Whether this decision creates a private socket, and so perturbs
    /// the SO_REUSEPORT group. The thing every cost model here keys on.
    #[must_use]
    pub fn promotes(self) -> bool {
        !matches!(self, Self::StayOnListener)
    }
}

/// Decide a just-connected transport key's fate under `mode`.
///
/// This is the whole admission promotion ladder, in one place. It used to
/// live as six hand-copies inside the per-runtime acceptors, which is
/// exactly how their telemetry drifted apart unnoticed (one backend
/// counted relocations as promotions, five did not, so identical-looking
/// log lines meant different things). The I/O differs per runtime; this
/// decision does not.
///
/// `group` is the peer's handshake GROUP extension, if any. It is
/// consulted -- and the router touched -- only when `mode` is something
/// other than [`Promotion::Never`]; under `Never` the router is
/// deliberately never asked, so affinity state stays empty and legs stay
/// where the kernel put them.
pub fn decide_promotion<K>(
    mode: Promotion,
    key: K,
    group: Option<GroupAffinity>,
    worker_index: usize,
    router: &mut WorkerRouter<K>,
    routing: RoutingMode,
    exclusive_udp_tuple: bool,
) -> PromotionDecision
where
    K: Eq + Hash + Clone,
{
    // `connect()` matches the whole UDP 4-tuple. N SRT connections on one
    // shared-sender socket share that tuple, so the first promote steals
    // every later handshake. PeerTable already demuxes by socket ID.
    if !exclusive_udp_tuple {
        return PromotionDecision::StayOnListener;
    }
    // A bonded leg asks the router where its group already lives.
    // Unbonded connections, and everything under `Never`, have no
    // affinity to honour and so no owner.
    let owner = match group {
        Some(group) if mode != Promotion::Never => Some(router.assign(key, Some(group), routing)),
        _ => None,
    };

    match owner {
        // Physically elsewhere: relocate regardless of mode, because the
        // affinity cannot be satisfied where the connection currently is.
        Some(owner) if owner != worker_index => PromotionDecision::RelocateTo(owner),
        // Bonded and already on its owner: the affinity is satisfied
        // right here, so promoting is optional and mode decides.
        Some(_) => match mode {
            Promotion::Bonded | Promotion::All => PromotionDecision::PromoteHere,
            _ => PromotionDecision::StayOnListener,
        },
        // Unbonded (or `Never`): only `All` promotes.
        None => match mode {
            Promotion::All => PromotionDecision::PromoteHere,
            _ => PromotionDecision::StayOnListener,
        },
    }
}

/// How a reuseport-single listener should be realized.
///
/// Connected workers `connect()` a private socket onto the peer 4-tuple.
/// Shared-socket senders put every SRT session on one tuple; Linux then
/// delivers later handshakes to the first connected socket. One
/// unconnected reuseport member plus socket-ID demux is the shape that
/// still works. This is the kernel fork, not a watered-down common I/O
/// path: each runtime still runs its own connected-worker or unconnected
/// acceptor.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReuseportSinglePlan {
    ConnectedWorkers(usize),
    UnconnectedListener,
}

/// Plan a reuseport-single listener from the same tuple-ownership bit
/// [`decide_promotion`] uses. Callers that `connect()` a promoted socket
/// must take [`ReuseportSinglePlan::ConnectedWorkers`] only.
#[must_use]
pub fn plan_reuseport_single(workers: usize, exclusive_udp_tuple: bool) -> ReuseportSinglePlan {
    if exclusive_udp_tuple {
        ReuseportSinglePlan::ConnectedWorkers(workers.max(1))
    } else {
        ReuseportSinglePlan::UnconnectedListener
    }
}
