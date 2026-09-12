//! A03: a minimal, production-facing demonstration of
//! `srt_transport::mio_transport::Owner` -- one Mio-driven listener and one
//! Mio-driven, shared-socket caller side, in one process, using only public
//! transport/protocol API (no srt-bench internals).
//!
//! What it does, in order: bind a listener; connect a caller to it on this
//! owner's shared egress socket; drive both sides to a real SRT handshake;
//! send a known message and confirm the listener receives it verbatim;
//! close the caller in an orderly way and confirm the listener observes it;
//! then demonstrate one error path (attempting to `listen` a second time).

use shiguredo_srt::{ConnectionEvent, Timestamp};
use srt_transport::mio_transport::Owner;
use srt_transport::{
    CallerConfig, ListenerConfig, ListenerTopology, LogicalCallerState, OutputDrainBudget,
    SocketOwnership,
};
use std::time::{Duration, Instant};

fn now_ts(start: Instant) -> Timestamp {
    Timestamp::from_micros(start.elapsed().as_micros() as u64)
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let start = Instant::now();
    let mut owner = Owner::new()?;

    // Bind the listener on an ephemeral loopback port. `PerPort` is this
    // example's whole point: `Owner` drives exactly one listener socket.
    let listener_config = ListenerConfig::builder("127.0.0.1:0".parse()?)
        .topology(ListenerTopology::PerPort)
        .build()?;
    owner.listen(&listener_config)?;
    let listen_addr = owner.listener_local_addr().expect("just bound above");
    println!("listening on {listen_addr}");

    // Error handling: a second `listen()` call is rejected rather than
    // silently leaking the first socket's mio registration.
    match owner.listen(&listener_config) {
        Ok(()) => unreachable!("Owner::listen must reject a second call"),
        Err(error) => println!("expected error calling listen() twice: {error}"),
    }

    // Connect a caller to our own listener. `Owner::connect` requires
    // `SocketOwnership::Shared`: every session `connect()`ed through the
    // same `Owner` shares its one egress socket (K01).
    let caller_config = CallerConfig::builder(listen_addr)
        .ownership(SocketOwnership::Shared)
        .build()?;
    // `Owner`'s caller pool policy defaults to effectively unbounded (A04),
    // so `connect()` always admits immediately unless the application opts
    // into real max_in_flight/attempt_deadline enforcement via
    // `set_caller_pool_policy` before its first `connect()` call.
    let srt_transport::PoolOutcome::Admitted(caller_id) =
        owner.connect(&caller_config, now_ts(start))?
    else {
        unreachable!("default pool policy is unbounded, so connect() must admit immediately")
    };

    // Drive both sides until the listener admits the caller AND the caller
    // itself reports Connected -- the listener side reaches Connected on
    // the incoming CONCLUSION before the caller's own handshake round trip
    // completes, so checking only one side's state races `send()` against
    // the other side's still-in-flight handshake.
    let mut peer_id = None;
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        let wait_us = owner.time_until_next_deadline(now_ts(start), 20_000);
        owner.poll_io(Some(Duration::from_micros(wait_us)), || now_ts(start))?;
        let now = now_ts(start);
        owner.drive(now, OutputDrainBudget::default())?;
        let mut events = Vec::new();
        owner.poll_listener_events(&mut events);
        for event in events {
            if let ConnectionEvent::Connected = event.event {
                peer_id = Some(event.logical_peer);
            }
        }
        if peer_id.is_some()
            && owner.caller_mut(caller_id).and_then(|c| c.state())
                == Some(LogicalCallerState::Connected)
        {
            break;
        }
    }
    let peer_id = peer_id.expect("caller connected within the deadline");
    println!("listener admitted the caller as {peer_id:?}");

    // Send a known message from the caller and confirm the listener
    // receives it verbatim.
    let message = b"hello from the shared caller socket";
    owner
        .caller_mut(caller_id)
        .expect("caller session still exists")
        .send(message, now_ts(start))?;

    let mut received = None;
    let deadline = Instant::now() + Duration::from_secs(5);
    while received.is_none() && Instant::now() < deadline {
        let wait_us = owner.time_until_next_deadline(now_ts(start), 20_000);
        owner.poll_io(Some(Duration::from_micros(wait_us)), || now_ts(start))?;
        let now = now_ts(start);
        owner.drive(now, OutputDrainBudget::default())?;
        let mut events = Vec::new();
        owner.poll_listener_events(&mut events);
        for event in events {
            if event.logical_peer == peer_id
                && let ConnectionEvent::DataReceived { payload, .. } = event.event
            {
                received = Some(payload.to_vec());
            }
        }
    }
    let received = received.expect("payload arrived within the deadline");
    assert_eq!(received, message);
    println!(
        "listener received {} bytes verbatim: {:?}",
        received.len(),
        String::from_utf8_lossy(&received)
    );

    // Orderly close: the caller disconnects; the listener must observe it.
    owner
        .caller_mut(caller_id)
        .expect("caller session still exists")
        .disconnect(now_ts(start));

    let mut closed = false;
    let deadline = Instant::now() + Duration::from_secs(5);
    while !closed && Instant::now() < deadline {
        let wait_us = owner.time_until_next_deadline(now_ts(start), 20_000);
        owner.poll_io(Some(Duration::from_micros(wait_us)), || now_ts(start))?;
        let now = now_ts(start);
        owner.drive(now, OutputDrainBudget::default())?;
        let mut events = Vec::new();
        owner.poll_listener_events(&mut events);
        for event in events {
            if event.logical_peer == peer_id
                && matches!(event.event, ConnectionEvent::Disconnected { .. })
            {
                closed = true;
            }
        }
    }
    assert!(closed, "listener must observe the caller's orderly close");
    println!("caller closed in an orderly way; listener observed it");

    Ok(())
}
