//! Direct measurement of Linux's SO_REUSEPORT rerouting behavior.
//!
//! These tests exist to answer one question with data instead of
//! inference: when a listener promotes a connection to its own dedicated
//! socket on a shared SO_REUSEPORT port, which syscall (if any) disturbs
//! the *other* flows already hashed to that port, and how badly?
//!
//! This matters because srt-bench's `ReuseportMulti` (#4) ingress strategy
//! has to decide whether promoting a connection is safe. An earlier
//! attempt to promote *every* connection once it reached `Connected`
//! measured catastrophically (see the module docs in
//! crates/srt-bench/src/runtimes/mio.rs), and the suspected mechanism was
//! `bind(SO_REUSEPORT)` perturbing the group hash. "Suspected" isn't good
//! enough to design around, hence these tests.
//!
//! There is deliberately no SRT, no async runtime, and no srt-bench code
//! here -- just `std::net` and the shared `bind_reuseport` helper. That's
//! the point: whatever these tests measure is *kernel* behavior, identical
//! for every async runtime in the workspace, since mio/tokio/smol/monoio/
//! glommio/compio all reach the same `bind(2)`/`connect(2)` syscalls
//! underneath. A runtime can change how it waits for readiness or
//! completion; it cannot change how the kernel hashes a UDP flow to a
//! reuseport group member.

use std::io;
use std::net::{SocketAddr, UdpSocket};
use std::time::Duration;

/// Number of acceptor sockets sharing the port, matching the K=4 that
/// srt-bench's baseline sweeps use.
const GROUP_SIZE: usize = 4;

/// How many independent client flows to track. Each flow is its own
/// source port, so each hashes independently; a population this size
/// makes "what fraction moved" a meaningful number rather than a coin
/// flip.
const FLOWS: usize = 48;

/// Bind one member of the group. Port 0 asks the kernel to pick; every
/// subsequent member must pass the resulting port explicitly.
fn bind_member(port: u16) -> io::Result<UdpSocket> {
    srt_transport::bind_reuseport(port, srt_transport::SOCK_BUF_BYTES)
}

/// Throw away anything queued on every listener so a later probe can't
/// mistake a stale datagram for the one it just sent.
fn drain_all(listeners: &[UdpSocket]) {
    let mut buf = [0u8; 128];
    for listener in listeners {
        while listener.recv_from(&mut buf).is_ok() {}
    }
}

/// Send one datagram on `flow` and report which listener the kernel
/// delivered it to. `None` means nobody got it (dropped, or still in
/// flight past our patience).
fn probe(flow: &UdpSocket, listeners: &[UdpSocket]) -> Option<usize> {
    if flow.send(b"probe").is_err() {
        return None;
    }
    // Loopback delivery is essentially immediate, but the sockets are
    // non-blocking, so poll briefly rather than assuming it has landed.
    for _ in 0..50 {
        let mut buf = [0u8; 128];
        for (index, listener) in listeners.iter().enumerate() {
            if listener.recv_from(&mut buf).is_ok() {
                return Some(index);
            }
        }
        std::thread::sleep(Duration::from_millis(1));
    }
    None
}

/// Establish where each flow currently lands.
fn map_homes(flows: &[UdpSocket], listeners: &[UdpSocket]) -> Vec<Option<usize>> {
    drain_all(listeners);
    flows.iter().map(|f| probe(f, listeners)).collect()
}

/// Count how many flows land somewhere other than where they used to.
/// Flows that fail to arrive at all are counted separately -- an
/// undelivered probe is a different (worse) failure than a rerouted one.
fn count_moves(before: &[Option<usize>], after: &[Option<usize>]) -> (usize, usize) {
    let mut moved = 0;
    let mut lost = 0;
    for (b, a) in before.iter().zip(after.iter()) {
        match (b, a) {
            (Some(x), Some(y)) if x != y => moved += 1,
            (Some(_), None) => lost += 1,
            _ => {}
        }
    }
    (moved, lost)
}

fn setup() -> (Vec<UdpSocket>, Vec<UdpSocket>, u16) {
    let first = bind_member(0).expect("bind first reuseport member");
    let port = first.local_addr().expect("local_addr").port();
    let mut listeners = vec![first];
    for _ in 1..GROUP_SIZE {
        listeners.push(bind_member(port).expect("bind reuseport member"));
    }

    let target: SocketAddr = format!("127.0.0.1:{port}").parse().expect("target addr");
    let mut flows = Vec::with_capacity(FLOWS);
    for _ in 0..FLOWS {
        let flow = UdpSocket::bind("127.0.0.1:0").expect("bind flow");
        flow.connect(target).expect("connect flow");
        flows.push(flow);
    }
    (listeners, flows, port)
}

/// Baseline: without touching the group, a flow's landing spot must be
/// stable. If this failed, every other measurement here would be noise.
#[test]
fn flow_placement_is_stable_while_the_group_is_untouched() {
    let (listeners, flows, _port) = setup();

    let first = map_homes(&flows, &listeners);
    let second = map_homes(&flows, &listeners);
    let (moved, lost) = count_moves(&first, &second);

    let delivered = first.iter().filter(|h| h.is_some()).count();
    assert!(
        delivered > FLOWS / 2,
        "probe harness is broken: only {delivered}/{FLOWS} flows delivered at all"
    );
    assert_eq!(
        (moved, lost),
        (0, 0),
        "flows moved with no group change: {moved} moved, {lost} lost \
         -- the rest of this file's measurements can't be trusted"
    );
}

/// THE question: does adding a member reroute flows that were already
/// established before it existed?
#[test]
fn binding_a_new_member_reroutes_existing_flows() {
    let (mut listeners, flows, port) = setup();

    let before = map_homes(&flows, &listeners);

    // The promotion step srt-bench performs, in isolation: one more
    // socket joins the group. Nothing is connected yet.
    let promoted = bind_member(port).expect("bind promoted socket");
    listeners.push(promoted);

    let after = map_homes(&flows, &listeners);
    let (moved, lost) = count_moves(&before, &after);

    eprintln!(
        "[reuseport] bind(): {moved}/{FLOWS} existing flows rerouted, {lost} undelivered \
         (group {GROUP_SIZE} -> {})",
        GROUP_SIZE + 1
    );

    // This is the finding the whole #4 design hinges on. A single bind
    // displacing a large share of unrelated, already-placed flows is
    // exactly why a listener cannot promote connections freely while
    // other handshakes are in flight.
    assert!(
        moved > 0,
        "expected bind() to reroute at least some existing flows, but none moved -- \
         if this ever fails on a supported kernel, the promotion design in \
         srt-bench's ReuseportMulti can be revisited"
    );
}

/// The other half of a promotion: after `bind`, srt-bench immediately
/// `connect`s the new socket to its peer. A connected UDP socket is
/// matched by exact 4-tuple ahead of the reuseport hash, so this step may
/// *also* change what the group looks like for everyone else.
#[test]
fn connecting_a_promoted_socket_reroutes_existing_flows_again() {
    let (mut listeners, flows, port) = setup();

    let promoted = bind_member(port).expect("bind promoted socket");
    listeners.push(promoted);

    // Measure from *after* the bind, so this test attributes only what
    // connect() itself does.
    let before = map_homes(&flows, &listeners);

    // Connect the promoted socket to a peer that isn't any of our flows,
    // mirroring how srt-bench connects it to the one caller it now owns.
    let unrelated = UdpSocket::bind("127.0.0.1:0").expect("bind unrelated peer");
    let unrelated_addr = unrelated.local_addr().expect("local_addr");
    listeners
        .last()
        .expect("promoted socket")
        .connect(unrelated_addr)
        .expect("connect promoted socket");

    let after = map_homes(&flows, &listeners);
    let (moved, lost) = count_moves(&before, &after);

    eprintln!("[reuseport] connect(): {moved}/{FLOWS} existing flows rerouted, {lost} undelivered");

    // No assertion on direction here: whether connect() detaches the
    // socket from the reuseport group (and so perturbs the hash a second
    // time) is precisely what this test is here to report. The printed
    // number is the deliverable; a hard assert either way would encode an
    // assumption this file exists to avoid making.
}

/// What a promotion actually costs, end to end, at the scale srt-bench
/// runs: promote repeatedly and watch the cumulative disruption. This is
/// the number that explains why promoting every connection during a
/// connection storm stalled the listener outright.
#[test]
fn repeated_promotions_compound_the_disruption() {
    let (mut listeners, flows, port) = setup();

    let mut homes = map_homes(&flows, &listeners);
    let mut total_moved = 0;
    const PROMOTIONS: usize = 8;

    for step in 1..=PROMOTIONS {
        let promoted = bind_member(port).expect("bind promoted socket");
        listeners.push(promoted);

        let after = map_homes(&flows, &listeners);
        let (moved, lost) = count_moves(&homes, &after);
        total_moved += moved;
        eprintln!(
            "[reuseport] promotion {step}: {moved}/{FLOWS} rerouted, {lost} undelivered \
             (group size {})",
            listeners.len()
        );
        homes = after;
    }

    eprintln!(
        "[reuseport] {PROMOTIONS} promotions caused {total_moved} total flow reroutes \
         across {FLOWS} flows"
    );

    // Each reroute during a real run is a mid-handshake flow landing on an
    // acceptor with no state for it. At srt-bench's scale that is what
    // turned into stalled handshakes.
    assert!(
        total_moved > 0,
        "expected repeated promotions to reroute flows; none moved"
    );
}

/// Is a promotion's disruption transient or permanent?
///
/// If `connect()` detaches the promoted socket from the group, then a
/// completed promotion takes the group 4 -> 5 -> 4, and flows displaced by
/// the bind should land back where they started once the connect lands.
/// That would make the damage a narrow *window* (packets arriving between
/// the two syscalls) rather than a lasting reshuffle -- a completely
/// different engineering problem, and the difference between "keep the
/// window short" and "never grow the group at all".
#[test]
fn a_completed_promotion_restores_original_flow_placement() {
    let (mut listeners, flows, port) = setup();

    let before = map_homes(&flows, &listeners);

    let promoted = bind_member(port).expect("bind promoted socket");
    listeners.push(promoted);
    let during = map_homes(&flows, &listeners);

    let unrelated = UdpSocket::bind("127.0.0.1:0").expect("bind unrelated peer");
    let unrelated_addr = unrelated.local_addr().expect("local_addr");
    listeners
        .last()
        .expect("promoted socket")
        .connect(unrelated_addr)
        .expect("connect promoted socket");
    let after = map_homes(&flows, &listeners);

    let (moved_by_bind, _) = count_moves(&before, &during);
    let (moved_by_connect, _) = count_moves(&during, &after);
    let (net_moved, net_lost) = count_moves(&before, &after);

    eprintln!(
        "[reuseport] promotion window: bind moved {moved_by_bind}/{FLOWS}, \
         connect moved {moved_by_connect}/{FLOWS}, NET vs original: \
         {net_moved} moved / {net_lost} lost"
    );

    // Reported, not asserted in either direction: this is the measurement
    // that tells a future reader whether shortening the bind->connect
    // window is a viable mitigation at all.
    if net_moved == 0 {
        eprintln!(
            "[reuseport] => disruption is TRANSIENT: only datagrams arriving \
             inside the bind->connect window are misrouted"
        );
    } else {
        eprintln!(
            "[reuseport] => disruption is PERSISTENT: {net_moved}/{FLOWS} flows \
             remain on a different member after the promotion completes"
        );
    }
}

/// The positive control, and the reason the tests above are worth having
/// rather than just concluding "SO_REUSEPORT is unusable at scale".
///
/// Group size is only dangerous when it changes *while flows are in
/// flight*. A large group established up front, before any client exists,
/// disturbs nothing -- there is nothing yet to disturb. So the supported
/// way to get more parallel acceptors is to bind them all at startup
/// (srt-bench's `--ingress reuseport-multi=K` knob), not to grow the group
/// per-connection at runtime.
#[test]
fn a_large_group_bound_before_any_traffic_is_harmless() {
    // Deliberately far larger than GROUP_SIZE, and larger than the group
    // the promotion tests above grow to -- if raw group size were the
    // problem, this is where it would show.
    const BIG_GROUP: usize = 16;

    let first = bind_member(0).expect("bind first reuseport member");
    let port = first.local_addr().expect("local_addr").port();
    let mut listeners = vec![first];
    for _ in 1..BIG_GROUP {
        listeners.push(bind_member(port).expect("bind reuseport member"));
    }

    // Only now do any flows appear.
    let target: SocketAddr = format!("127.0.0.1:{port}").parse().expect("target addr");
    let mut flows = Vec::with_capacity(FLOWS);
    for _ in 0..FLOWS {
        let flow = UdpSocket::bind("127.0.0.1:0").expect("bind flow");
        flow.connect(target).expect("connect flow");
        flows.push(flow);
    }

    let before = map_homes(&flows, &listeners);
    let after = map_homes(&flows, &listeners);
    let (moved, lost) = count_moves(&before, &after);

    let delivered = before.iter().filter(|h| h.is_some()).count();
    eprintln!(
        "[reuseport] group of {BIG_GROUP} bound before traffic: {moved}/{FLOWS} rerouted, \
         {lost} undelivered, {delivered}/{FLOWS} delivered"
    );

    assert_eq!(
        (moved, lost),
        (0, 0),
        "a group bound entirely before any traffic should be perfectly stable"
    );
}
