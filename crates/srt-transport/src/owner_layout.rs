//! Listener layouts that span several Owners (one Owner per thread, one
//! socket each), identical for every runtime's Owner.
//!
//! [`owner_plans`] splits the topology chosen in a [`crate::ListenerConfig`]
//! into one [`OwnerListenerPlan`] per Owner, and each runtime's
//! `Owner::listen_planned` attaches one plan, so the application's layout
//! choice reaches the runtime unchanged. Reuseport group members route
//! CONCLUSIONs to the member that holds the half-open handshake through the
//! SYN cookie ([`srt_lifecycle::cookie_for_worker`]); the CONCLUSIONs a member
//! receives for another member come out as [`ForwardedHandshake`]s for the
//! application to carry across threads.

use std::collections::VecDeque;
use std::net::{SocketAddr, UdpSocket};

use crate::admission::Admit;
use crate::{ConfigError, IngressTelemetry, ResolvedListenerTopology, RuntimeBuildError};

/// Most CONCLUSIONs one Owner holds for other acceptor-group members before
/// the application drains them; more are counted as dropped and cost the
/// caller a handshake retry.
pub(crate) const LISTENER_FORWARD_CAPACITY: usize = 256;

/// One Owner's place in a `SO_REUSEPORT` acceptor group: `count` Owners,
/// each on its own thread with its own socket on one port.
///
/// The kernel spreads datagrams across the group by 4-tuple hash, and the
/// group can rehash between a caller's INDUCTION and CONCLUSION. The
/// listener therefore encodes `index` in every SYN cookie it issues, and a
/// CONCLUSION that arrives at another member is surfaced as a
/// [`ForwardedHandshake`] for the member that holds its half-open state.
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

/// A CONCLUSION whose SYN cookie names another member of this Owner's
/// acceptor group. Deliver it to member `to` with that Owner's
/// `inject_listener_handshake`; that member holds the half-open handshake and
/// resolves admission policy there.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ForwardedHandshake {
    pub to: usize,
    pub peer: SocketAddr,
    pub data: Vec<u8>,
}

/// One Owner's share of a listener topology: where it binds and, for a
/// reuseport group, which member it is. Produced by [`owner_plans`] and
/// consumed by each runtime's `Owner::listen_planned`.
#[derive(Clone, Debug)]
pub struct OwnerListenerPlan {
    pub(crate) config: crate::ListenerConfig,
    member: Option<ReusePortMember>,
    bind: SocketAddr,
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
///   group on one port, cookie-routed.
/// * `SharedPool { listeners: K }`: K Owners on ports `P..P+K`.
///
/// `ReusePortSingle` and promotion other than `Never` move sessions between
/// Owners, which needs a relocation target the Owners do not have yet; they
/// are refused here rather than silently changed. Reuseport and shared-pool
/// layouts with more than one Owner need an explicit port.
pub fn owner_plans(
    config: &crate::ListenerConfig,
    flavor: crate::RuntimeFlavor,
) -> Result<Vec<OwnerListenerPlan>, RuntimeBuildError> {
    let prepared = config.prepare(flavor)?;
    if prepared.transport.promotion != srt_lifecycle::Promotion::Never {
        return Err(ConfigError::new(
            "listener.transport.promotion",
            "promotion moves sessions between Owners, which needs a relocation \
             target the Owners do not have yet; set promotion to Never",
        )
        .into());
    }
    let bind = prepared.bind;
    let plan = |member, bind| OwnerListenerPlan {
        config: config.clone(),
        member,
        bind,
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

/// A plain attach is PerPort; a planned attach must match the topology its
/// plan came from (the config is re-prepared on the Owner's own thread).
pub(crate) fn check_listener_topology(
    plan: Option<&OwnerListenerPlan>,
    topology: ResolvedListenerTopology,
) -> Result<(), RuntimeBuildError> {
    let ok = match (plan.map(|plan| plan.member), topology) {
        (None | Some(None), ResolvedListenerTopology::PerPort) => true,
        (Some(Some(member)), ResolvedListenerTopology::ReusePortMulti { acceptors }) => {
            acceptors.get() == member.count()
        }
        (Some(None), ResolvedListenerTopology::SharedPool { .. }) => true,
        _ => false,
    };
    if ok {
        Ok(())
    } else {
        Err(RuntimeBuildError::from(ConfigError::new(
            "listener.transport.topology",
            "Owner::listen drives one PerPort socket; split other topologies \
             with owner_plans and attach each plan with Owner::listen_planned",
        )))
    }
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

/// Acceptor-group state of one listener: a lone listener is member 0 of 1
/// and never forwards.
pub(crate) struct ListenerRouting {
    pub(crate) index: usize,
    pub(crate) count: usize,
    forwards: VecDeque<ForwardedHandshake>,
    dropped: u64,
}

impl ListenerRouting {
    pub(crate) fn new(member: Option<ReusePortMember>) -> Self {
        let (index, count) = member.map_or((0, 1), |member| (member.index, member.count));
        Self {
            index,
            count,
            forwards: VecDeque::new(),
            dropped: 0,
        }
    }

    /// Queue a CONCLUSION admission said belongs to another member.
    pub(crate) fn record(
        &mut self,
        admitted: &Admit,
        peer: SocketAddr,
        data: &[u8],
        telemetry: &IngressTelemetry,
    ) {
        let Admit::ForwardTo(to) = *admitted else {
            return;
        };
        if self.forwards.len() < LISTENER_FORWARD_CAPACITY {
            self.forwards.push_back(ForwardedHandshake {
                to,
                peer,
                data: data.to_vec(),
            });
        } else {
            self.dropped += 1;
            telemetry.record_cookie_route_failure();
        }
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
        let keep = (self.count > 1).then(|| data.clone());
        let admitted = table.admit_bytes_with_listener_resolver(
            resolver, peer, data, now, options, self.index, self.count, telemetry,
        );
        if let Some(data) = keep {
            self.record(&admitted, peer, &data, telemetry);
        }
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
        let admitted = table.admit_with_listener_resolver(
            resolver, peer, data, now, options, self.index, self.count, telemetry,
        );
        self.record(&admitted, peer, data, telemetry);
    }

    pub(crate) fn drain_into(&mut self, out: &mut Vec<ForwardedHandshake>) {
        out.extend(self.forwards.drain(..));
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

    /// Layouts that move sessions between Owners are refused, not downgraded.
    #[test]
    fn relocating_layouts_are_refused_until_owners_can_relocate() {
        for flavor in FLAVORS {
            let relocate = config(
                40_010,
                crate::ListenerTopology::ReusePortMulti {
                    acceptors: count(2),
                },
                crate::PromotionPolicy::Relocate,
            );
            assert!(owner_plans(&relocate, flavor).is_err());
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
}
