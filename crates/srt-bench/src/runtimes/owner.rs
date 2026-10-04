//! `runtime=owner`: the receiver is the production compio [`Owner`] on its
//! production attach path, so ingest-scaling numbers describe the listener
//! applications actually run, not a bench adapter.
//!
//! The listener layout comes from the cell: `--ingress` picks the topology
//! (`shared-pool:K` = K Owners on K ports, `reuseport-multi:K` = K Owners in
//! one `SO_REUSEPORT` group on one port), `--promotion` and
//! `--cookie-routing` go to the transport unchanged. [`owner_plans`] splits
//! the layout into one plan per Owner, each Owner runs on its own thread
//! with its own production runtime, and the Owners exchange
//! [`ListenerTransfer`]s through per-Owner inboxes, exactly as an
//! application must. A layout the transport refuses is reported and the
//! process exits 2; the bench never substitutes another layout.
//!
//! `per-port` is refused here: in srt-bench it means one port per
//! connection, which no production listener does. Use `reuseport-multi:1`
//! (or `shared-pool:1`) for a single Owner.
//!
//! Receiver only. The sender side of a cell runs any other runtime.

use crate::{Aggregate, BenchConfig, ConnStats, Ingress};
use srt_proto::{ConnectionEvent, DisconnectReason, Timestamp};
use srt_transport::advanced::admission::{AdmissionEvent, LogicalPeerId, LogicalPeerStats};
use srt_transport::compio::{
    Owner, OwnerServiceBudget, ProductionRuntimeConfig, RxModePolicy, observe_production_runtime,
    production_runtime_builder,
};
use srt_transport::{
    CookieRoutingPolicy, ListenerConfig, ListenerTransfer, OwnerListenerPlan, RuntimeFlavor,
    owner_plans,
};
use std::collections::HashMap;
use std::sync::mpsc;
use std::time::{Duration, Instant};

/// TX lanes per Owner. A listener sends only ACK/NAK/handshake traffic.
const TX_CAPACITY: usize = 64;
/// Longest park when nothing is due; the stop flag is checked after it.
const IDLE_PARK: Duration = Duration::from_millis(50);
/// How often live peers' protocol counters are copied into the result. A
/// peer that ends between refreshes keeps the counters of the last one.
const STATS_REFRESH: Duration = Duration::from_secs(1);

/// The transport layout a cell asks for, or why the bench cannot run it.
pub(crate) fn listener_config(cfg: &BenchConfig) -> Result<ListenerConfig, String> {
    let topology = match cfg.ingress {
        Ingress::PerPort => {
            return Err(
                "runtime=owner: per-port means one port per connection in srt-bench; \
                        use reuseport-multi:1 or shared-pool:1 for one Owner"
                    .into(),
            );
        }
        _ => cfg.endpoint_plan().topology,
    };
    let plan = cfg.endpoint_plan();
    let mut config = ListenerConfig::builder(cfg.addr_for(0))
        .build()
        .map_err(|error| error.to_string())?;
    config.session = cfg.session_config();
    config.transport.topology = topology;
    config.transport.ownership = plan.ownership;
    config.transport.promotion = plan.promotion;
    if let Some(bytes) = std::num::NonZeroUsize::new(cfg.sock_buf_bytes) {
        config.transport.socket_buffers = srt_transport::SocketBufferConfig::Bytes(bytes);
    }
    config.admission.cookie_routing = if cfg.cookie_routing {
        CookieRoutingPolicy::Enabled
    } else {
        CookieRoutingPolicy::Disabled
    };
    Ok(config)
}

pub fn run(cfg: BenchConfig) {
    if cfg.mode != crate::Mode::Receiver {
        eprintln!("srt-bench: runtime=owner is a receiver; run the sender on another runtime");
        std::process::exit(2);
    }
    let planned = listener_config(&cfg).and_then(|config| {
        let payload = config
            .session
            .payload_size
            .resolve()
            .map_err(|e| e.to_string())?;
        let plans = owner_plans(&config, RuntimeFlavor::Compio).map_err(|e| e.to_string())?;
        Ok((
            plans,
            srt_transport::compio::required_session_wire_ceiling(payload.get(), None),
        ))
    });
    let (plans, wire_ceiling) = match planned {
        Ok(planned) => planned,
        Err(error) => {
            eprintln!("srt-bench: listener layout refused: {error}");
            std::process::exit(2);
        }
    };
    crate::shutdown::install();
    let start = Instant::now();
    let deadline = start + Duration::from_secs_f64(cfg.duration_secs);
    let (inboxes, receivers): (Vec<_>, Vec<_>) = (0..plans.len())
        .map(|_| mpsc::channel::<ListenerTransfer>())
        .unzip();
    let (ready_tx, ready_rx) = mpsc::channel::<Result<(), String>>();
    let workers: Vec<_> = plans
        .into_iter()
        .zip(receivers)
        .enumerate()
        .map(|(index, (plan, inbox))| {
            let members = inboxes.clone();
            let ready = ready_tx.clone();
            std::thread::Builder::new()
                .name(format!("owner-{index}"))
                .spawn(move || {
                    serve(
                        &plan,
                        wire_ceiling,
                        &inbox,
                        &members,
                        &ready,
                        start,
                        deadline,
                    )
                })
                .expect("spawn Owner thread")
        })
        .collect();
    drop(ready_tx);
    // Every member is bound before the sender is told to start. Count the
    // replies: each Owner thread keeps its sender for its whole life, so
    // waiting for the channel to close would wait for the run to end.
    for _ in 0..workers.len() {
        let ready = ready_rx
            .recv()
            .unwrap_or_else(|_| Err("an Owner thread exited before attaching".into()));
        if let Err(error) = ready {
            eprintln!("srt-bench: Owner failed to attach: {error}");
            std::process::exit(2);
        }
    }
    println!("LISTENING");

    let mut agg = Aggregate::new(cfg);
    for worker in workers {
        let outcome = worker.join().expect("Owner thread panicked");
        for stats in outcome.peers.into_values() {
            agg.add(stats);
        }
    }
    agg.print(start);
    if !agg.any_connected {
        std::process::exit(1);
    }
}

struct Outcome {
    peers: HashMap<LogicalPeerId, ConnStats>,
}

fn serve(
    plan: &OwnerListenerPlan,
    wire_ceiling: usize,
    inbox: &mpsc::Receiver<ListenerTransfer>,
    members: &[mpsc::Sender<ListenerTransfer>],
    ready: &mpsc::Sender<Result<(), String>>,
    start: Instant,
    deadline: Instant,
) -> Outcome {
    let mut outcome = Outcome {
        peers: HashMap::new(),
    };
    let attached = attach(plan, wire_ceiling);
    let (runtime, mut owner) = match attached {
        Ok(attached) => {
            let _ = ready.send(Ok(()));
            attached
        }
        Err(error) => {
            let _ = ready.send(Err(error));
            return outcome;
        }
    };
    let timestamp = || Timestamp::from_micros(start.elapsed().as_micros() as u64);
    let mut transfers = Vec::new();
    let mut events: Vec<AdmissionEvent> = Vec::new();
    let mut next_refresh = Instant::now() + STATS_REFRESH;
    while !crate::shutdown::requested() && Instant::now() < deadline {
        runtime.enter(|| {
            runtime.poll_with(Some(Duration::ZERO));
            runtime.run();
        });
        let now = timestamp();
        while let Ok(transfer) = inbox.try_recv() {
            owner.accept_listener_transfer(transfer, now);
        }
        let report = runtime.block_on(owner.service(now, OwnerServiceBudget::default()));
        route_transfers(&mut owner, &mut transfers, members);
        if let Some(fault) = owner.fault() {
            eprintln!("srt-bench: Owner faulted: {fault:?}");
            break;
        }
        owner.poll_listener_events(&mut events);
        for event in events.drain(..) {
            record(&mut outcome.peers, event.logical_peer, event.event);
        }
        if Instant::now() >= next_refresh {
            refresh_protocol_stats(&mut owner, &mut outcome.peers);
            next_refresh = Instant::now() + STATS_REFRESH;
        }
        if !report.work_remaining {
            park(&runtime, &mut owner, now);
        }
    }
    refresh_protocol_stats(&mut owner, &mut outcome.peers);
    runtime.block_on(owner.shutdown_and_drain(Duration::from_secs(2)));
    outcome
}

/// This thread's production runtime and its Owner attached to `plan`, on the
/// managed receive path when the host supports it.
fn attach(
    plan: &OwnerListenerPlan,
    wire_ceiling: usize,
) -> Result<(compio::runtime::Runtime, Owner), String> {
    let runtime = production_runtime_builder(ProductionRuntimeConfig::for_owner(
        TX_CAPACITY,
        wire_ceiling,
    ))?
    .build()
    .map_err(|error| error.to_string())?;
    let profile = runtime.block_on(observe_production_runtime(
        &runtime,
        TX_CAPACITY,
        wire_ceiling,
    ));
    let mut owner = Owner::new_with_ceiling(TX_CAPACITY, wire_ceiling);
    owner
        .set_rx_substrate(profile.managed_rx_substrate())
        .map_err(|error| error.to_string())?;
    owner.set_rx_mode_policy(RxModePolicy::ManagedPreferred);
    runtime
        .block_on(async { owner.listen_planned(plan, None) })
        .map_err(|error| error.to_string())?;
    Ok((runtime, owner))
}

/// Hand the transfers this Owner owes to their members' inboxes.
fn route_transfers(
    owner: &mut Owner,
    transfers: &mut Vec<ListenerTransfer>,
    members: &[mpsc::Sender<ListenerTransfer>],
) {
    owner.poll_listener_transfers(transfers);
    for transfer in transfers.drain(..) {
        if let Some(member) = members.get(transfer.to) {
            let _ = member.send(transfer);
        }
    }
}

/// Sleep until the Owner's next deadline or activity, at most `IDLE_PARK`.
fn park(runtime: &compio::runtime::Runtime, owner: &mut Owner, now: Timestamp) {
    let idle_us = IDLE_PARK.as_micros() as u64;
    let wait = Duration::from_micros(owner.time_until_next_deadline(now, idle_us)).min(IDLE_PARK);
    runtime.block_on(owner.wait_for_activity(wait));
}

/// Copy each live direct peer's loss, duplicate and RTT counters into its
/// result row. Delivered packets are counted from events instead, because a
/// peer's entry is gone by the time its close is observed and a periodic copy
/// would lose the last interval.
fn refresh_protocol_stats(owner: &mut Owner, peers: &mut HashMap<LogicalPeerId, ConnStats>) {
    for (id, stats) in peers.iter_mut() {
        let Some(LogicalPeerStats::Direct(conn)) =
            owner.listener_peer_mut(*id).and_then(|entry| entry.stats())
        else {
            continue;
        };
        if let Some(receiver) = conn.receiver {
            stats.secondary_a = receiver.total_lost;
            stats.secondary_b = receiver.total_duplicates;
            stats.rtt_us = receiver.rtt as u64;
        }
    }
}

/// Fold one listener event into its logical peer's stats.
fn record<K: std::hash::Hash + Eq>(
    peers: &mut HashMap<K, ConnStats>,
    key: K,
    event: ConnectionEvent,
) {
    let stats = peers.entry(key).or_default();
    match event {
        ConnectionEvent::Connected => {
            stats.connected = true;
            stats.has_stats = true;
        }
        ConnectionEvent::DataReceived { packet_count, .. } => {
            stats.data_events += 1;
            stats.core_total += u64::from(packet_count);
        }
        ConnectionEvent::Disconnected { reason } => {
            stats.torn_down = reason != DisconnectReason::PeerShutdown;
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use srt_transport::ListenerTopology;

    fn cfg(ingress: Ingress) -> BenchConfig {
        let mut cfg = crate::tests::config();
        cfg.encryption = crate::Encryption::Plain;
        cfg.ingress = ingress;
        cfg
    }

    #[test]
    fn per_port_is_refused_and_shared_layouts_map_to_transport_topologies() {
        assert!(listener_config(&cfg(Ingress::PerPort)).is_err());
        let multi = listener_config(&cfg(Ingress::ReuseportMulti(4))).unwrap();
        assert!(matches!(
            multi.transport.topology,
            ListenerTopology::ReusePortMulti { .. }
        ));
        let pool = listener_config(&cfg(Ingress::SharedPool(2))).unwrap();
        assert!(matches!(
            pool.transport.topology,
            ListenerTopology::SharedPool { .. }
        ));
    }

    #[test]
    fn cookie_routing_switch_reaches_the_transport() {
        let mut off = cfg(Ingress::ReuseportMulti(2));
        off.cookie_routing = false;
        assert_eq!(
            listener_config(&off).unwrap().admission.cookie_routing,
            CookieRoutingPolicy::Disabled
        );
    }

    fn data(packet_count: u32) -> ConnectionEvent {
        ConnectionEvent::DataReceived {
            payload: bytes::Bytes::from_static(b"x"),
            sequence_number: 0,
            message_number: 0,
            timestamp: 0,
            source_time: Timestamp::from_micros(0),
            packet_count,
        }
    }

    #[test]
    fn events_fold_into_per_peer_delivery_and_teardown() {
        let mut peers = HashMap::new();
        record(&mut peers, 7u64, ConnectionEvent::Connected);
        for _ in 0..3 {
            record(&mut peers, 7, data(2));
        }
        record(
            &mut peers,
            7,
            ConnectionEvent::Disconnected {
                reason: DisconnectReason::InactivityTimeout,
            },
        );
        record(
            &mut peers,
            8,
            ConnectionEvent::Disconnected {
                reason: DisconnectReason::PeerShutdown,
            },
        );
        assert!(peers[&7].connected && peers[&7].torn_down);
        assert!(!peers[&8].connected && !peers[&8].torn_down);
        assert_eq!((peers[&7].data_events, peers[&7].core_total), (3, 6));
        assert!(
            peers[&7].has_stats,
            "a connected peer is an established row"
        );
    }
}
