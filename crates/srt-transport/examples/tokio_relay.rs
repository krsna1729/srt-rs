//! F01: preserving a message's original source age across a relay hop,
//! using only public `srt_transport::tokio_transport::Facade` API.
//!
//! Three `Facade`s stand in for three independent processes/machines:
//! `source` (a caller only), `relay` (a listener accepting from `source`,
//! and a caller connecting onward to `destination`), and `destination` (a
//! listener). Each `Facade` has its own independent clock -- there is no
//! shared wall clock between them, exactly as in a real deployment.
//!
//! `Session::recv()` returns a [`ReceivedMessage`] carrying `source_time`:
//! when the sender queued this data, in the *receiving* connection's own
//! clock domain. That domain does not survive a re-send on a different
//! connection, so a relay forwarding data onward must carry the elapsed
//! age forward as its own application-level metadata (here, an 8-byte
//! little-endian micros prefix) rather than expecting the wire protocol to
//! preserve it across hops. This example deliberately injects a delay
//! both before and after the relay's own republish, and shows both
//! delays present in the age finally observed at the destination -- not
//! reset to just the most recent hop's transit time.

use srt_transport::tokio_transport::{Facade, ReceivedMessage};
use srt_transport::{CallerConfig, ListenerConfig, ListenerTopology, SocketOwnership};
use std::time::Duration;

fn listener_config() -> ListenerConfig {
    ListenerConfig::builder("127.0.0.1:0".parse().unwrap())
        .topology(ListenerTopology::PerPort)
        .build()
        .expect("listener config")
}

fn shared_caller_config(remote: std::net::SocketAddr) -> CallerConfig {
    CallerConfig::builder(remote)
        .ownership(SocketOwnership::Shared)
        .build()
        .expect("caller config")
}

/// `[age_micros: u64 little-endian][payload]` -- the relay's own
/// application-level envelope carrying "how old was this when I forwarded
/// it" forward across the hop to `destination`, since the wire protocol's
/// per-connection timestamp cannot.
fn encode_envelope(age_so_far: Duration, payload: &[u8]) -> Vec<u8> {
    let mut envelope = (age_so_far.as_micros() as u64).to_le_bytes().to_vec();
    envelope.extend_from_slice(payload);
    envelope
}

fn decode_envelope(envelope: &[u8]) -> (Duration, &[u8]) {
    let (age_bytes, payload) = envelope.split_at(8);
    let age_micros = u64::from_le_bytes(age_bytes.try_into().expect("8-byte age prefix"));
    (Duration::from_micros(age_micros), payload)
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let deadline = Duration::from_secs(5);

    let (source, source_driver) = Facade::spawn(None)?;
    let (mut relay, relay_driver) = Facade::spawn(Some(&listener_config()))?;
    let relay_listen_addr = relay.listener_local_addr().expect("relay listener bound");
    let (mut destination, destination_driver) = Facade::spawn(Some(&listener_config()))?;
    let destination_listen_addr = destination
        .listener_local_addr()
        .expect("destination listener bound");

    let source_session = tokio::time::timeout(
        deadline,
        source.connect(&shared_caller_config(relay_listen_addr)),
    )
    .await??;
    let mut relay_ingress = tokio::time::timeout(deadline, relay.accept())
        .await?
        .expect("relay's driver task is still running");
    let relay_egress = tokio::time::timeout(
        deadline,
        relay.connect(&shared_caller_config(destination_listen_addr)),
    )
    .await??;
    let mut destination_session = tokio::time::timeout(deadline, destination.accept())
        .await?
        .expect("destination's driver task is still running");
    println!("source -> relay -> destination all connected");

    tokio::time::timeout(deadline, source_session.send(b"live payload".to_vec())).await??;
    let received: ReceivedMessage = tokio::time::timeout(deadline, relay_ingress.recv())
        .await?
        .expect("relay receives from source");
    println!(
        "relay received it {:?} after source queued it",
        received.age(relay.now())
    );

    // Delay injected BEFORE the relay republishes: processing/queueing
    // time at the relay itself.
    tokio::time::sleep(Duration::from_millis(150)).await;
    let age_before_republish = received.age(relay.now());
    println!("relay republishing after holding it for {age_before_republish:?}");
    let envelope = encode_envelope(age_before_republish, &received.payload);
    tokio::time::timeout(deadline, relay_egress.send(envelope)).await??;

    // Delay injected AFTER publication: a slow consumer at the
    // destination.
    tokio::time::sleep(Duration::from_millis(150)).await;
    let forwarded = tokio::time::timeout(deadline, destination_session.recv())
        .await?
        .expect("destination receives from relay");
    let (carried_age, original_payload) = decode_envelope(&forwarded.payload);
    // `forwarded.source_time` is when the RELAY queued this on the
    // relay-to-destination connection -- i.e. transit time on this one
    // hop, independent of `carried_age`. Note `carried_age`'s window ends
    // when the relay called `.age()`, but `transit_age`'s window only
    // starts once the driver task actually processes the resulting
    // `Command::Send` -- so `total_age` omits the relay's own
    // command-channel latency between those two points. It is therefore a
    // conservative lower bound on true end-to-end age, never an
    // overestimate.
    let transit_age = forwarded.age(destination.now());
    let total_age = carried_age + transit_age;

    assert_eq!(original_payload, b"live payload");
    println!(
        "destination received it: age carried from before republish = {carried_age:?}, \
         transit age on this hop = {transit_age:?}, total observed age = {total_age:?}"
    );
    assert!(
        total_age >= Duration::from_millis(280),
        "both injected delays (150ms each) must show up in the total age, \
         not be reset at the republish: got {total_age:?}"
    );

    drop(source);
    drop(relay);
    drop(destination);
    drop(source_session);
    drop(relay_ingress);
    drop(relay_egress);
    drop(destination_session);
    source_driver.await?;
    relay_driver.await?;
    destination_driver.await?;
    println!("every driver task shut down cleanly");

    Ok(())
}
