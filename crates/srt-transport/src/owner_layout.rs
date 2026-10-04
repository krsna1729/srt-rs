//! Listener layouts that span several Owners (one Owner per thread, one
//! socket each), identical for every runtime's Owner.
//!
//! [`owner_plans`] splits the topology chosen in a [`crate::ListenerConfig`]
//! into one [`OwnerListenerPlan`] per Owner, and each runtime's
//! `Owner::listen_planned` attaches one plan, so the application's layout
//! choice reaches the runtime unchanged. The Owners of one layout exchange
//! [`ListenerTransfer`]s, which the application carries between threads:
//! CONCLUSIONs the kernel delivered to the wrong reuseport member (routed by
//! the SYN cookie, [`srt_lifecycle::cookie_for_worker`]), bonded legs
//! relocated to the Owner that holds their group, and the slot releases that
//! keep socket IDs unique across the layout.

use std::collections::VecDeque;
use std::net::{SocketAddr, UdpSocket};

use crate::admission::{Admit, PromotionWork, RelocatedLeg, SharedWorkerRouter, TableRelocation};
use crate::reuseport_group::{MemberClaim, ReusePortGroup};
use crate::{ConfigError, IngressTelemetry, ResolvedListenerTopology, RuntimeBuildError};

/// Most CONCLUSIONs one Owner holds for other acceptor-group members before
/// the application drains them; more are counted as dropped and cost the
/// caller a handshake retry. Sessions and slot releases are never dropped.
pub(crate) const LISTENER_FORWARD_CAPACITY: usize = 256;

/// One Owner's place in a `SO_REUSEPORT` acceptor group: `count` Owners,
/// each on its own thread with its own socket on one port.
///
/// The kernel spreads datagrams across the group by 4-tuple hash, and the
/// group can rehash between a caller's INDUCTION and CONCLUSION. The
/// listener therefore encodes `index` in every SYN cookie it issues, and a
/// CONCLUSION that arrives at another member is surfaced as a
/// [`ListenerTransfer`] for the member that holds its half-open state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReusePortMember {
    index: usize,
    count: usize,
}

impl ReusePortMember {
    /// Member `index` of `count` (`1..=MAX_COOKIE_WORKERS` members; the
    /// cookie carries the index in one byte).
    pub fn new(index: usize, count: usize) -> Result<Self, ConfigError> {
        if !(1..=srt_lifecycle::MAX_COOKIE_WORKERS).contains(&count) || index >= count {
            return Err(ConfigError::new(
                "listener.reuse_port_member",
                format!(
                    "member {index} of {count}: need 1..={} members and index < count",
                    srt_lifecycle::MAX_COOKIE_WORKERS
                ),
            ));
        }
        Ok(Self { index, count })
    }

    #[must_use]
    pub fn index(self) -> usize {
        self.index
    }

    #[must_use]
    pub fn count(self) -> usize {
        self.count
    }
}

/// A message from one Owner of a listener layout to another. The
/// application only routes it: deliver it to member `to` with that Owner's
/// `accept_listener_transfer`. The payload is opaque.
pub struct ListenerTransfer {
    pub to: usize,
    kind: TransferKind,
}

enum TransferKind {
    /// A CONCLUSION whose SYN cookie names member `to`, which holds the
    /// half-open handshake and resolves admission policy.
    Handshake { peer: SocketAddr, data: Vec<u8> },
    /// An established bonded leg moving to the member that holds its group,
    /// with its connected socket.
    Session {
        leg: Box<RelocatedLeg>,
        socket: UdpSocket,
    },
    /// A session relocated from member `to` ended; its slot is free there.
    SlotReleased { slot: u32 },
}

impl ListenerTransfer {
    /// A CONCLUSION forward. Handshake forwards are the only transfers the
    /// transport may drop under backlog (the caller retries).
    #[must_use]
    pub fn is_handshake(&self) -> bool {
        matches!(self.kind, TransferKind::Handshake { .. })
    }

    /// A relocated session.
    #[must_use]
    pub fn is_session(&self) -> bool {
        matches!(self.kind, TransferKind::Session { .. })
    }
}

impl std::fmt::Debug for ListenerTransfer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let kind = match &self.kind {
            TransferKind::Handshake { .. } => "handshake",
            TransferKind::Session { .. } => "session",
            TransferKind::SlotReleased { .. } => "slot-released",
        };
        f.debug_struct("ListenerTransfer")
            .field("to", &self.to)
            .field("kind", &kind)
            .finish()
    }
}

/// One Owner's share of a listener topology: where it binds and, for a
/// reuseport group, which member it is. Produced by [`owner_plans`] and
/// consumed by each runtime's `Owner::listen_planned`.
#[derive(Clone)]
pub struct OwnerListenerPlan {
    pub(crate) config: crate::ListenerConfig,
    member: Option<ReusePortMember>,
    bind: SocketAddr,
    /// The layout's shared router, when its promotion policy relocates.
    router: Option<SharedWorkerRouter>,
    /// Membership of a reuseport layout's kernel group, shared by its plans.
    group: Option<std::sync::Arc<ReusePortGroup>>,
}

impl std::fmt::Debug for OwnerListenerPlan {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OwnerListenerPlan")
            .field("member", &self.member)
            .field("bind", &self.bind)
            .field("relocates", &self.router.is_some())
            .finish_non_exhaustive()
    }
}

impl OwnerListenerPlan {
    /// Address this Owner's socket binds.
    #[must_use]
    pub fn bind(&self) -> SocketAddr {
        self.bind
    }

    /// Reuseport group membership, `None` for PerPort and shared-pool plans.
    #[must_use]
    pub fn member(&self) -> Option<ReusePortMember> {
        self.member
    }
}

/// Split a listener topology into one plan per Owner, for the Owner of
/// `flavor`:
///
/// * `PerPort`: one Owner.
/// * `ReusePortMulti { acceptors: K }`: K members of one `SO_REUSEPORT`
///   group on one port, cookie-routed. With promotion `Relocate`, a bonded
///   leg the kernel hashed away from its group's member moves there (as a
///   [`ListenerTransfer`]), so one bonded publisher stays one stream.
/// * `SharedPool { listeners: K }`: K Owners on ports `P..P+K`.
///
/// `ReusePortSingle`, and promotion `Bonded`/`All` (local promotion) are
/// refused here rather than silently changed; so is promotion on any
/// topology but `ReusePortMulti`. Reuseport and shared-pool layouts with
/// more than one Owner need an explicit port.
pub fn owner_plans(
    config: &crate::ListenerConfig,
    flavor: crate::RuntimeFlavor,
) -> Result<Vec<OwnerListenerPlan>, RuntimeBuildError> {
    let prepared = config.prepare(flavor)?;
    let promotion = prepared.transport.promotion;
    let relocating_group = matches!(
        prepared.transport.topology,
        ResolvedListenerTopology::ReusePortMulti { .. }
    );
    match promotion {
        srt_lifecycle::Promotion::Never => {}
        srt_lifecycle::Promotion::Relocate if relocating_group => {}
        _ => {
            return Err(ConfigError::new(
                "listener.transport.promotion",
                "Owners relocate bonded legs within a ReusePortMulti group \
                 (promotion Relocate); local promotion (Bonded/All) and promotion \
                 on other topologies are not supported; set promotion to Never or Relocate",
            )
            .into());
        }
    }
    let router = (promotion != srt_lifecycle::Promotion::Never).then(|| {
        let count = prepared.transport.topology.listener_socket_count().get();
        std::sync::Arc::new(std::sync::Mutex::new(srt_lifecycle::WorkerRouter::new(
            count,
        )))
    });
    let bind = prepared.bind;
    // One membership record per reuseport layout: the barrier, the
    // one-claim-per-member rule and the one-layout-per-address rule.
    let group = match prepared.transport.topology {
        ResolvedListenerTopology::ReusePortMulti { acceptors } => {
            Some(ReusePortGroup::new(bind, acceptors.get()))
        }
        _ => None,
    };
    let plan = |member, bind| OwnerListenerPlan {
        config: config.clone(),
        member,
        bind,
        router: router.clone(),
        group: group.clone(),
    };
    let explicit_port = |owners: usize| {
        if owners > 1 && bind.port() == 0 {
            Err(RuntimeBuildError::from(ConfigError::new(
                "listener.bind",
                "a multi-Owner listener needs an explicit port so every Owner binds a known one",
            )))
        } else {
            Ok(())
        }
    };
    match prepared.transport.topology {
        ResolvedListenerTopology::PerPort => Ok(vec![plan(None, bind)]),
        ResolvedListenerTopology::ReusePortMulti { acceptors } => {
            let count = acceptors.get();
            explicit_port(count)?;
            (0..count)
                .map(|index| Ok(plan(Some(ReusePortMember::new(index, count)?), bind)))
                .collect()
        }
        ResolvedListenerTopology::SharedPool { listeners } => {
            let count = listeners.get();
            explicit_port(count)?;
            (0..count)
                .map(|index| {
                    let port = u16::try_from(index)
                        .ok()
                        .and_then(|offset| bind.port().checked_add(offset))
                        .ok_or_else(|| {
                            ConfigError::new(
                                "listener.transport.topology",
                                "shared-pool ports exceed 65535",
                            )
                        })?;
                    Ok(plan(None, SocketAddr::new(bind.ip(), port)))
                })
                .collect()
        }
        ResolvedListenerTopology::ReusePortSingle { .. } => {
            Err(RuntimeBuildError::from(ConfigError::new(
                "listener.transport.topology",
                "ReusePortSingle hands every session from one acceptor to worker \
                 Owners, which needs a relocation target the Owners do not have yet",
            )))
        }
    }
}

/// A plain attach is PerPort without promotion; a planned attach must match
/// the topology its plan came from (the config is re-prepared on the
/// Owner's own thread), and only a plan from [`owner_plans`] carries the
/// router promotion needs.
pub(crate) fn check_listener_topology(
    plan: Option<&OwnerListenerPlan>,
    prepared: &crate::PreparedListener,
) -> Result<Option<MemberClaim>, RuntimeBuildError> {
    let ok = match (plan.map(|plan| plan.member), prepared.transport.topology) {
        (None | Some(None), ResolvedListenerTopology::PerPort) => true,
        (Some(Some(member)), ResolvedListenerTopology::ReusePortMulti { acceptors }) => {
            acceptors.get() == member.count()
        }
        (Some(None), ResolvedListenerTopology::SharedPool { .. }) => true,
        _ => false,
    };
    if !ok {
        return Err(RuntimeBuildError::from(ConfigError::new(
            "listener.transport.topology",
            "Owner::listen drives one PerPort socket; split other topologies \
             with owner_plans and attach each plan with Owner::listen_planned",
        )));
    }
    let routed = plan.is_some_and(|plan| plan.router.is_some());
    if prepared.transport.promotion != srt_lifecycle::Promotion::Never && !routed {
        return Err(ConfigError::new(
            "listener.transport.promotion",
            "promotion needs the layout router from owner_plans; attach the plan \
             with Owner::listen_planned, or set promotion to Never",
        )
        .into());
    }
    // Reserve this member before its socket joins the kernel group.
    plan.and_then(|plan| Some((plan.group.as_ref()?, plan.member?)))
        .map(|(group, member)| group.claim(member.index))
        .transpose()
}

/// Requested socket memory for this Owner's listener: a planned Owner binds
/// one socket, not the whole layout.
pub(crate) fn listener_socket_bytes(
    prepared: &crate::PreparedListener,
    plan: Option<&OwnerListenerPlan>,
) -> usize {
    if plan.is_some() {
        prepared.transport.socket_buffer_bytes.saturating_mul(4)
    } else {
        prepared.requested_socket_memory_bytes()
    }
}

/// Bind this Owner's one listener socket.
pub(crate) fn bind_listener_socket(
    prepared: &crate::PreparedListener,
    plan: Option<&OwnerListenerPlan>,
) -> std::io::Result<UdpSocket> {
    match plan {
        Some(plan) => prepared.bind_owner_socket(plan.bind),
        None => prepared.bind_sockets()?.drain(..).next().ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::InvalidInput, "listener bound no socket")
        }),
    }
}

/// This Owner's listener table: partitioned and policy-attached when its
/// plan relocates, otherwise the plain table [`crate::PreparedListener`]
/// builds.
pub(crate) fn listener_table(
    prepared: &crate::PreparedListener,
    plan: Option<&OwnerListenerPlan>,
) -> crate::PeerTable {
    let Some((plan, router)) = plan.and_then(|plan| Some((plan, plan.router.clone()?))) else {
        return prepared.peer_table();
    };
    let (index, count) = plan
        .member
        .map_or((0, 1), |member| (member.index, member.count));
    let mut table = crate::PeerTable::with_partition(prepared.admission.limits, index, count);
    table.set_relocation(TableRelocation {
        mode: prepared.transport.promotion,
        member: index,
        router,
        exclusive: prepared.transport.exclusive,
    });
    table
}

/// Where this Owner binds a promoted session's connected socket.
#[derive(Clone, Copy)]
struct PromotionIo {
    bind: SocketAddr,
    buffer_bytes: usize,
}

/// Layout state of one listener: its member index, the transfers it owes
/// other members, and the connected sockets it must start driving. A lone
/// listener is member 0 of 1 and never transfers.
pub(crate) struct ListenerRouting {
    pub(crate) index: usize,
    pub(crate) count: usize,
    transfers: VecDeque<ListenerTransfer>,
    queued_handshakes: usize,
    dropped: u64,
    promotion: Option<PromotionIo>,
    /// Connected sockets adopted or promoted here, for the runtime to
    /// register once the table confirms the session is still there.
    promoted: Vec<(crate::admission::PhysicalPeerKey, UdpSocket)>,
    released: Vec<(usize, u32)>,
    /// This member's place in its reuseport group, held for the listener's
    /// life; `None` outside a reuseport layout.
    claim: Option<MemberClaim>,
    /// Cached once the group is complete, so a running listener pays no
    /// atomic load per datagram.
    group_complete: bool,
}

impl ListenerRouting {
    /// `claim` comes from [`check_listener_topology`]; the listener's socket
    /// is bound by now, so the member counts as bound.
    pub(crate) fn new(
        prepared: &crate::PreparedListener,
        plan: Option<&OwnerListenerPlan>,
        mut claim: Option<MemberClaim>,
    ) -> Self {
        if let Some(claim) = claim.as_mut() {
            claim.mark_bound();
        }
        let member = plan.and_then(OwnerListenerPlan::member);
        let (index, count) = member.map_or((0, 1), |member| (member.index, member.count));
        let promotion = plan
            .filter(|plan| plan.router.is_some())
            .map(|plan| PromotionIo {
                bind: plan.bind,
                buffer_bytes: prepared.transport.socket_buffer_bytes,
            });
        Self {
            index,
            count,
            transfers: VecDeque::new(),
            queued_handshakes: 0,
            dropped: 0,
            promotion,
            promoted: Vec::new(),
            released: Vec::new(),
            group_complete: claim.is_none(),
            claim,
        }
    }

    /// Whether this member may admit: every member of its reuseport group is
    /// bound, so no session can be rehashed by a later bind. A datagram that
    /// arrives earlier is dropped and counted; its caller retries.
    #[inline]
    fn group_ready(&mut self, telemetry: &IngressTelemetry) -> bool {
        if !self.group_complete {
            self.group_complete = self
                .claim
                .as_ref()
                .is_none_or(|claim| claim.group().is_complete());
            if !self.group_complete {
                telemetry.record_layout_incomplete_drop();
            }
        }
        self.group_complete
    }

    /// Queue a CONCLUSION admission said belongs to another member.
    fn record(
        &mut self,
        admitted: &Admit,
        peer: SocketAddr,
        data: &[u8],
        telemetry: &IngressTelemetry,
    ) {
        let Admit::ForwardTo(to) = *admitted else {
            return;
        };
        if self.queued_handshakes < LISTENER_FORWARD_CAPACITY {
            self.queued_handshakes += 1;
            self.transfers.push_back(ListenerTransfer {
                to,
                kind: TransferKind::Handshake {
                    peer,
                    data: data.to_vec(),
                },
            });
        } else {
            self.dropped += 1;
            telemetry.record_cookie_route_failure();
        }
    }

    /// Carry out the promotions admission just decided: bind each session's
    /// connected socket, keep it here or queue the session for its member.
    #[inline]
    fn after_admission(&mut self, table: &mut crate::PeerTable, telemetry: &IngressTelemetry) {
        if !table.has_pending_promotions() {
            return;
        }
        let Some(io) = self.promotion else {
            return;
        };
        let (transfers, promoted) = (&mut self.transfers, &mut self.promoted);
        let failed = table.take_promotions(
            |peer| crate::config::bind_promoted_socket(io.bind, io.buffer_bytes, peer).ok(),
            |work, socket| match work {
                PromotionWork::PromoteHere(physical) => {
                    telemetry.record_local_promotion();
                    promoted.push((physical, socket));
                }
                PromotionWork::Relocate(leg) => {
                    telemetry.record_handoff();
                    transfers.push_back(ListenerTransfer {
                        to: leg.to,
                        kind: TransferKind::Session { leg, socket },
                    });
                }
            },
        );
        telemetry.record_promotion_failures(failed);
    }

    /// Admit one listener datagram the receive path owns as `Bytes`, as this
    /// group member. Only a multi-member group keeps a handle for a possible
    /// forward (a refcount, never a copy).
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn admit_bytes(
        &mut self,
        table: &mut crate::PeerTable,
        resolver: Option<&crate::ListenerAdmissionResolver>,
        peer: SocketAddr,
        data: bytes::Bytes,
        now: srt_proto::Timestamp,
        options: &crate::AdmissionOptions,
        telemetry: &IngressTelemetry,
    ) {
        if !self.group_ready(telemetry) {
            return;
        }
        let keep = (self.count > 1).then(|| data.clone());
        let admitted = table.admit_bytes_with_listener_resolver(
            resolver, peer, data, now, options, self.index, self.count, telemetry,
        );
        if let Some(data) = keep {
            self.record(&admitted, peer, &data, telemetry);
        }
        self.after_admission(table, telemetry);
    }

    /// Admit one borrowed listener datagram as this group member (receive
    /// paths without owned buffers, and forwarded CONCLUSIONs).
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn admit(
        &mut self,
        table: &mut crate::PeerTable,
        resolver: Option<&crate::ListenerAdmissionResolver>,
        peer: SocketAddr,
        data: &[u8],
        now: srt_proto::Timestamp,
        options: &crate::AdmissionOptions,
        telemetry: &IngressTelemetry,
    ) {
        if !self.group_ready(telemetry) {
            return;
        }
        let admitted = table.admit_with_listener_resolver(
            resolver, peer, data, now, options, self.index, self.count, telemetry,
        );
        self.record(&admitted, peer, data, telemetry);
        self.after_admission(table, telemetry);
    }

    /// Apply a transfer another member sent this one.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn accept(
        &mut self,
        transfer: ListenerTransfer,
        table: &mut crate::PeerTable,
        resolver: Option<&crate::ListenerAdmissionResolver>,
        now: srt_proto::Timestamp,
        options: &crate::AdmissionOptions,
        telemetry: &IngressTelemetry,
    ) {
        match transfer.kind {
            TransferKind::Handshake { peer, data } => {
                self.admit(table, resolver, peer, &data, now, options, telemetry);
            }
            TransferKind::Session { leg, socket } => {
                let physical = crate::admission::PhysicalPeerKey {
                    address: leg.address,
                    local_socket_id: leg.socket_id,
                };
                match table.adopt(leg) {
                    Ok(()) => self.promoted.push((physical, socket)),
                    Err(leg) => {
                        // Full here: the session ends, and its home slot
                        // must not stay lent.
                        telemetry.record_promotion_failures(1);
                        let slot = table.slot_index_for_socket_id(leg.socket_id) as u32;
                        self.transfers.push_back(ListenerTransfer {
                            to: leg.home,
                            kind: TransferKind::SlotReleased { slot },
                        });
                    }
                }
            }
            TransferKind::SlotReleased { slot } => {
                table.reclaim_lent_slot(slot);
            }
        }
    }

    /// Whether connected sockets wait for the runtime to register them.
    #[inline]
    pub(crate) fn has_promoted(&self) -> bool {
        !self.promoted.is_empty()
    }

    /// Connected sockets the runtime must start driving, after it has closed
    /// the sockets of freed peers (`PeerTable::take_freed_addresses`); one
    /// whose session already left the table is dropped here.
    pub(crate) fn take_promoted<'a>(
        &'a mut self,
        table: &'a crate::PeerTable,
    ) -> impl Iterator<Item = (SocketAddr, UdpSocket)> + 'a {
        self.promoted
            .drain(..)
            .filter(|(physical, _)| table.holds(physical))
            .map(|(physical, socket)| (physical.address, socket))
    }

    /// Every transfer owed to other members, slot releases included.
    pub(crate) fn drain_into(
        &mut self,
        table: &mut crate::PeerTable,
        out: &mut Vec<ListenerTransfer>,
    ) {
        table.take_released_slots(&mut self.released);
        for (to, slot) in self.released.drain(..) {
            self.transfers.push_back(ListenerTransfer {
                to,
                kind: TransferKind::SlotReleased { slot },
            });
        }
        self.queued_handshakes = 0;
        out.extend(self.transfers.drain(..));
    }

    pub(crate) fn dropped(&self) -> u64 {
        self.dropped
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const FLAVORS: [crate::RuntimeFlavor; 3] = [
        crate::RuntimeFlavor::Mio,
        crate::RuntimeFlavor::Tokio,
        crate::RuntimeFlavor::Compio,
    ];

    fn count(n: usize) -> crate::WorkerCount {
        crate::WorkerCount::Count(std::num::NonZeroUsize::new(n).expect("count"))
    }

    fn config(
        port: u16,
        topology: crate::ListenerTopology,
        promotion: crate::PromotionPolicy,
    ) -> crate::ListenerConfig {
        crate::ListenerConfig::builder(SocketAddr::from(([127, 0, 0, 1], port)))
            .topology(topology)
            .configure_transport(|transport| transport.promotion = promotion)
            .build()
            .expect("listener config")
    }

    /// The configured topology decides the Owner layout, identically for
    /// every runtime; nothing is rewritten.
    #[test]
    fn plans_follow_the_configured_topology_on_every_runtime() {
        let port = 40_000;
        for flavor in FLAVORS {
            let per_port = owner_plans(
                &config(
                    port,
                    crate::ListenerTopology::PerPort,
                    crate::PromotionPolicy::Never,
                ),
                flavor,
            )
            .expect("per-port plan");
            assert_eq!(per_port.len(), 1);
            assert_eq!(per_port[0].member(), None);

            let group = owner_plans(
                &config(
                    port,
                    crate::ListenerTopology::ReusePortMulti {
                        acceptors: count(3),
                    },
                    crate::PromotionPolicy::Never,
                ),
                flavor,
            )
            .expect("reuseport plans");
            let members: Vec<_> = group
                .iter()
                .map(|plan| plan.member().map(|m| (m.index(), m.count())))
                .collect();
            assert_eq!(members, [Some((0, 3)), Some((1, 3)), Some((2, 3))]);
            assert!(group.iter().all(|plan| plan.bind().port() == port));

            let pool = owner_plans(
                &config(
                    port,
                    crate::ListenerTopology::SharedPool {
                        listeners: count(3),
                    },
                    crate::PromotionPolicy::Never,
                ),
                flavor,
            )
            .expect("shared-pool plans");
            let ports: Vec<_> = pool.iter().map(|plan| plan.bind().port()).collect();
            assert_eq!(ports, [port, port + 1, port + 2]);
            assert!(pool.iter().all(|plan| plan.member().is_none()));
        }
    }

    /// `Relocate` on a reuseport group gives every plan one shared router;
    /// local promotion, promotion elsewhere, and `ReusePortSingle` are
    /// refused, not downgraded.
    #[test]
    fn only_reuseport_groups_relocate_and_share_one_router() {
        for flavor in FLAVORS {
            let group = |promotion| {
                config(
                    40_010,
                    crate::ListenerTopology::ReusePortMulti {
                        acceptors: count(2),
                    },
                    promotion,
                )
            };
            let plans = owner_plans(&group(crate::PromotionPolicy::Relocate), flavor)
                .expect("relocating group plans");
            let routers: Vec<_> = plans
                .iter()
                .map(|plan| plan.router.clone().expect("relocating plan has a router"))
                .collect();
            assert!(std::sync::Arc::ptr_eq(&routers[0], &routers[1]));
            let never = owner_plans(&group(crate::PromotionPolicy::Never), flavor)
                .expect("non-relocating group plans");
            assert!(never.iter().all(|plan| plan.router.is_none()));
            for local in [crate::PromotionPolicy::Bonded, crate::PromotionPolicy::All] {
                assert!(owner_plans(&group(local), flavor).is_err());
            }
            let per_port_relocate = config(
                40_010,
                crate::ListenerTopology::PerPort,
                crate::PromotionPolicy::Relocate,
            );
            assert!(owner_plans(&per_port_relocate, flavor).is_err());
            let single = config(
                40_010,
                crate::ListenerTopology::ReusePortSingle { workers: count(2) },
                crate::PromotionPolicy::Never,
            );
            assert!(owner_plans(&single, flavor).is_err());
            // A multi-Owner layout on an ephemeral port has no port to share.
            let ephemeral = config(
                0,
                crate::ListenerTopology::ReusePortMulti {
                    acceptors: count(2),
                },
                crate::PromotionPolicy::Never,
            );
            assert!(owner_plans(&ephemeral, flavor).is_err());
        }
    }

    #[test]
    fn member_index_must_fit_the_group_and_the_cookie() {
        assert!(ReusePortMember::new(0, 0).is_err());
        assert!(ReusePortMember::new(2, 2).is_err());
        assert!(ReusePortMember::new(0, srt_lifecycle::MAX_COOKIE_WORKERS + 1).is_err());
        let last = ReusePortMember::new(255, 256).expect("cookie carries 256 members");
        assert_eq!((last.index(), last.count()), (255, 256));
    }

    /// Transfers exist to cross Owner threads.
    #[test]
    fn transfers_and_plans_cross_threads() {
        fn assert_send<T: Send>() {}
        assert_send::<ListenerTransfer>();
        assert_send::<OwnerListenerPlan>();
    }

    type Case = (
        crate::RuntimeFlavor,
        crate::ListenerTopology,
        crate::SocketOwnership,
        crate::PromotionPolicy,
        crate::CookieRoutingPolicy,
    );

    /// Every runtime × topology × ownership × promotion × cookie routing.
    fn layout_cases() -> Vec<Case> {
        use crate::{CookieRoutingPolicy as C, ListenerTopology as T, PromotionPolicy as P};
        let topologies = [
            T::PerPort,
            T::ReusePortMulti {
                acceptors: count(2),
            },
            T::ReusePortSingle { workers: count(2) },
            T::SharedPool {
                listeners: count(2),
            },
        ];
        let ownerships = [
            crate::SocketOwnership::Exclusive,
            crate::SocketOwnership::Shared,
        ];
        let promotions = [P::Auto, P::Never, P::Relocate, P::Bonded, P::All];
        let cookies = [C::Auto, C::Enabled, C::Disabled];
        let mut cases = Vec::new();
        for flavor in FLAVORS {
            for topology in topologies {
                for ownership in ownerships {
                    for promotion in promotions {
                        for cookie in cookies {
                            cases.push((flavor, topology, ownership, promotion, cookie));
                        }
                    }
                }
            }
        }
        cases
    }

    /// A port with the next one free too (shared pools bind `P..P+K`).
    fn two_free_ports() -> u16 {
        loop {
            let port = relocation_test_support::free_port();
            if port < u16::MAX && UdpSocket::bind(("127.0.0.1", port + 1)).is_ok() {
                return port;
            }
        }
    }

    /// Attach every plan to a fresh Owner of `flavor`, all alive at once.
    #[cfg(all(feature = "mio", feature = "tokio", feature = "compio"))]
    fn attach_all(
        flavor: crate::RuntimeFlavor,
        plans: &[OwnerListenerPlan],
        tokio: &tokio::runtime::Runtime,
        compio: &compio::runtime::Runtime,
    ) -> Result<(), String> {
        match flavor {
            crate::RuntimeFlavor::Mio => {
                let mut owners = Vec::new();
                for plan in plans {
                    let mut owner =
                        crate::mio_transport::Owner::new().map_err(|e| e.to_string())?;
                    owner
                        .listen_planned(plan, None)
                        .map_err(|e| e.to_string())?;
                    owners.push(owner);
                }
                Ok(())
            }
            crate::RuntimeFlavor::Tokio => {
                let _reactor = tokio.enter();
                let mut owners = Vec::new();
                for plan in plans {
                    let mut owner = crate::tokio_transport::Owner::new();
                    owner
                        .listen_planned(plan, None)
                        .map_err(|e| e.to_string())?;
                    owners.push(owner);
                }
                Ok(())
            }
            crate::RuntimeFlavor::Compio => compio.block_on(async {
                let mut owners = Vec::new();
                for plan in plans {
                    let mut owner = crate::compio_transport::Owner::new(64);
                    owner
                        .listen_planned(plan, None)
                        .map_err(|e| e.to_string())?;
                    owners.push(owner);
                }
                Ok(())
            }),
            crate::RuntimeFlavor::Custom(_) => unreachable!("layout_cases uses the three Owners"),
        }
    }

    /// The layouts the Owners document as unsupported (owner-contract.md):
    /// `ReusePortSingle`, and any promotion but `Relocate` on `ReusePortMulti`.
    fn documented_refusal(prepared: &crate::PreparedListener) -> bool {
        let topology = prepared.transport.topology;
        let relocating_group = prepared.transport.promotion == srt_lifecycle::Promotion::Relocate
            && matches!(topology, ResolvedListenerTopology::ReusePortMulti { .. });
        matches!(topology, ResolvedListenerTopology::ReusePortSingle { .. })
            || !(prepared.transport.promotion == srt_lifecycle::Promotion::Never
                || relocating_group)
    }

    /// No runtime refuses a plan `owner_plans` gave it, no config that
    /// `ListenerConfig::prepare` refuses yields plans, and the only other
    /// refusals are the documented unsupported layouts.
    #[cfg(all(feature = "mio", feature = "tokio", feature = "compio"))]
    #[test]
    fn every_plan_attaches_and_every_refusal_is_resolve_or_documented() {
        let tokio = tokio::runtime::Builder::new_current_thread()
            .enable_io()
            .build()
            .expect("tokio runtime");
        let compio = compio::runtime::Runtime::new().expect("compio runtime");
        for (flavor, topology, ownership, promotion, cookie) in layout_cases() {
            let case = format!("{flavor:?} {topology:?} {ownership:?} {promotion:?} {cookie:?}");
            let mut config = config(two_free_ports(), topology, promotion);
            config.transport.ownership = ownership;
            config.admission.cookie_routing = cookie;
            let prepared = config.prepare(flavor);
            match (owner_plans(&config, flavor), prepared) {
                (Ok(plans), Ok(prepared)) => {
                    let sockets = prepared.transport.topology.listener_socket_count().get();
                    assert_eq!(plans.len(), sockets, "{case}: one plan per socket");
                    if let Err(error) = attach_all(flavor, &plans, &tokio, &compio) {
                        panic!("{case}: a plan was refused on attach: {error}");
                    }
                }
                (Ok(_), Err(error)) => panic!("{case}: plans from a refused config: {error}"),
                (Err(_), Ok(prepared)) => assert!(
                    documented_refusal(&prepared),
                    "{case}: a supported layout was refused"
                ),
                (Err(_), Err(_)) => {}
            }
        }
    }
}

/// A bonded publisher the way libsrt makes one: each leg its own SRT
/// session on its own UDP socket (so its own 4-tuple, which the kernel may
/// hash to any reuseport member), all legs carrying one GROUP extension.
/// Shared by the Mio, Tokio and Compio relocation tests.
#[cfg(test)]
pub(crate) mod relocation_test_support {
    use std::net::{SocketAddr, UdpSocket};

    use srt_proto::{ConnectionOutput, SrtConnection, Timestamp};

    pub(crate) const GROUPS: usize = 16;

    /// One extra unconnected socket in the loopback reuseport group on
    /// `port`, as a promotion's `bind` adds before its `connect`: the group
    /// rehashes while it exists.
    pub(crate) fn transient_group_member(port: u16) -> UdpSocket {
        let socket = socket2::Socket::new(
            socket2::Domain::IPV4,
            socket2::Type::DGRAM,
            Some(socket2::Protocol::UDP),
        )
        .expect("socket");
        socket.set_reuse_port(true).expect("SO_REUSEPORT");
        socket
            .bind(&SocketAddr::from(([127, 0, 0, 1], port)).into())
            .expect("joins the group");
        socket.into()
    }

    pub(crate) fn free_port() -> u16 {
        UdpSocket::bind("127.0.0.1:0")
            .and_then(|socket| socket.local_addr())
            .expect("ephemeral port")
            .port()
    }

    /// A two-member reuseport group that relocates bonded legs.
    pub(crate) fn relocating_group(port: u16) -> crate::ListenerConfig {
        crate::ListenerConfig::builder(SocketAddr::from(([127, 0, 0, 1], port)))
            .topology(crate::ListenerTopology::ReusePortMulti {
                acceptors: crate::WorkerCount::Count(
                    std::num::NonZeroUsize::new(2).expect("two members"),
                ),
            })
            .configure_transport(|transport| {
                transport.promotion = crate::PromotionPolicy::Relocate;
            })
            .bonded_inputs(crate::BondedInputPolicy::Accept)
            .build()
            .expect("relocating listener config")
    }

    struct RawLeg {
        conn: SrtConnection,
        socket: UdpSocket,
        timers: crate::ManualTimerStore,
    }

    pub(crate) struct RawBondedPublisher {
        legs: Vec<RawLeg>,
    }

    impl RawBondedPublisher {
        pub(crate) fn new(index: u32, listener: SocketAddr, now: Timestamp) -> Self {
            let extension = srt_proto::handshake::GroupExtensionData {
                group_id: srt_proto::handshake::SRTGROUP_MASK | (100 + index),
                group_type: srt_proto::handshake::GroupType::Broadcast,
                flags: 0,
                weight: 1,
            };
            let legs = (0..2)
                .map(|leg| {
                    let socket = UdpSocket::bind("127.0.0.1:0").expect("leg socket");
                    socket.set_nonblocking(true).expect("nonblocking");
                    socket.connect(listener).expect("leg connects");
                    let mut conn = SrtConnection::new_caller(srt_proto::ConnectionOptions {
                        socket_id: 5_000 + index * 2 + leg,
                        initial_seq: Some(700),
                        group_extension: Some(extension),
                        ..srt_proto::ConnectionOptions::default()
                    });
                    conn.connect(now).expect("caller starts handshake");
                    RawLeg {
                        conn,
                        socket,
                        timers: crate::ManualTimerStore::new(),
                    }
                })
                .collect();
            Self { legs }
        }

        /// One visit: fire timers, receive, send.
        pub(crate) fn pump(&mut self, now: Timestamp) {
            let mut buf = [0u8; 2048];
            for leg in &mut self.legs {
                leg.timers.fire_expired(now, &mut leg.conn);
                while let Ok(len) = leg.socket.recv(&mut buf) {
                    let _ = leg.conn.feed_recv_buf(&buf[..len], now);
                }
                while let Ok(Some(output)) = leg.conn.poll_output() {
                    match output {
                        ConnectionOutput::SendPacket(bytes) => {
                            let _ = leg.socket.send(&bytes);
                        }
                        other => leg.timers.apply_output(&other, now),
                    }
                }
            }
        }

        pub(crate) fn connected(&self) -> bool {
            self.legs
                .iter()
                .all(|leg| leg.conn.state() == srt_proto::ConnectionState::Connected)
        }

        /// The same payload on every leg (Broadcast).
        pub(crate) fn send(&mut self, payload: &[u8], now: Timestamp) {
            for leg in &mut self.legs {
                let _ = leg.conn.send(payload, now);
            }
        }

        /// ACKs every leg received: each leg's replies reach it, so the
        /// listener answers each 4-tuple from the socket the caller dialled.
        pub(crate) fn every_leg_acked(&self) -> bool {
            self.legs.iter().all(|leg| {
                leg.conn
                    .stats()
                    .sender
                    .is_some_and(|sender| sender.total_acks_received > 0)
            })
        }
    }

    /// One bonded stream per publisher, each with both legs on one Owner and
    /// data received on both legs (the relocated leg arrives through its
    /// connected socket).
    fn assert_bonds_whole(groups: &[Option<crate::LogicalPeerStats>]) {
        assert_eq!(
            groups.len(),
            GROUPS,
            "one Connected stream per bonded publisher, not one per leg"
        );
        for stats in groups {
            let Some(crate::LogicalPeerStats::Group(stats)) = stats else {
                panic!("every stream is a bonded group: {stats:?}");
            };
            assert_eq!(stats.legs.len(), 2, "both legs on the group's Owner");
            for leg in &stats.legs {
                assert!(
                    leg.connection
                        .receiver
                        .is_some_and(|receiver| receiver.total_data_packets_received > 0),
                    "every leg delivers data: {leg:?}"
                );
            }
        }
    }

    /// One relocation scenario, driven step by step: `GROUPS` raw bonded
    /// publishers against a two-member group. Each runtime's test supplies
    /// only how its Owners are serviced and how transfers are delivered.
    pub(crate) struct RelocationRun {
        publishers: Vec<RawBondedPublisher>,
        streams: Vec<(usize, crate::LogicalPeerId)>,
        sessions_moved: usize,
        sent: u32,
        settle: u32,
        deadline: std::time::Instant,
    }

    impl RelocationRun {
        pub(crate) fn new(port: u16, now: Timestamp) -> Self {
            let listener = SocketAddr::from(([127, 0, 0, 1], port));
            Self {
                publishers: (0..GROUPS as u32)
                    .map(|index| RawBondedPublisher::new(index, listener, now))
                    .collect(),
                streams: Vec::new(),
                sessions_moved: 0,
                sent: 0,
                settle: 0,
                deadline: std::time::Instant::now() + std::time::Duration::from_secs(10),
            }
        }

        /// Until every publisher has sent 20 payloads and 50 rounds settled.
        pub(crate) fn active(&self) -> bool {
            std::time::Instant::now() < self.deadline && self.settle < 50
        }

        pub(crate) fn pump_publishers(&mut self, now: Timestamp) {
            for publisher in &mut self.publishers {
                publisher.pump(now);
            }
        }

        /// Record the streams member `member` reports as connected.
        pub(crate) fn note_events(&mut self, member: usize, events: &[crate::AdmissionEvent]) {
            self.streams.extend(
                events
                    .iter()
                    .filter(|event| matches!(event.event, srt_proto::ConnectionEvent::Connected))
                    .map(|event| (member, event.logical_peer)),
            );
        }

        pub(crate) fn note_transfers(&mut self, transfers: &[crate::ListenerTransfer]) {
            self.sessions_moved += transfers.iter().filter(|t| t.is_session()).count();
        }

        /// Once every publisher is connected, send one payload per round.
        pub(crate) fn after_round(&mut self, now: Timestamp) {
            if !self.publishers.iter().all(RawBondedPublisher::connected) {
                return;
            }
            if self.sent < 20 {
                let payload = self.sent.to_be_bytes();
                for publisher in &mut self.publishers {
                    publisher.send(&payload, now);
                }
                self.sent += 1;
            } else {
                self.settle += 1;
            }
        }

        /// `(member, stream)` for every connected stream seen.
        pub(crate) fn streams(&self) -> &[(usize, crate::LogicalPeerId)] {
            &self.streams
        }

        /// `stats` are the members' stats for [`Self::streams`], in order.
        pub(crate) fn finish(&self, stats: &[Option<crate::LogicalPeerStats>]) {
            assert_bonds_whole(stats);
            assert!(
                self.sessions_moved > 0,
                "some leg hashed away from its group's member"
            );
            assert!(
                self.publishers
                    .iter()
                    .all(RawBondedPublisher::every_leg_acked),
                "every leg's replies reach it"
            );
        }
    }
}
