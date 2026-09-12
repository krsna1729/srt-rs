//! A05: a minimal, production-facing demonstration of
//! `srt_transport::tokio_transport::Facade` -- the managed, ergonomic async
//! wrapper around one Mio-equivalent Tokio-native `Owner`, using only public
//! transport/protocol API (no srt-bench internals).
//!
//! What it does, in order: spawn a `Facade` with a listener bound; connect
//! a caller to it on the facade's shared egress socket; `accept()` the
//! admitted session on the listener side; send a known message and confirm
//! it arrives verbatim via `recv()`; close the caller in an orderly way and
//! confirm `recv()` resolves to `None`; then shut the facade down and join
//! its driver task.

use srt_transport::tokio_transport::Facade;
use srt_transport::{CallerConfig, ListenerConfig, ListenerTopology, SocketOwnership};
use std::time::Duration;

// `current_thread`, not the default multi-threaded flavor: this crate's
// `tokio` feature enables only `rt` (checkpoint 3's "only the Tokio
// features actually needed"), not `rt-multi-thread`.
#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let listener_config = ListenerConfig::builder("127.0.0.1:0".parse()?)
        .topology(ListenerTopology::PerPort)
        .build()?;
    let (mut facade, driver) = Facade::spawn(Some(&listener_config))?;
    let listen_addr = facade.listener_local_addr().expect("just bound above");
    println!("listening on {listen_addr}");

    // Connect a caller to our own listener. `Facade::connect` requires
    // `SocketOwnership::Shared`, same as the underlying `Owner` (K01):
    // every session it originates shares one egress socket.
    let caller_config = CallerConfig::builder(listen_addr)
        .ownership(SocketOwnership::Shared)
        .build()?;
    let deadline = Duration::from_secs(5);

    // `connect()` and `accept()` both resolve only once the handshake
    // actually reaches Connected, so send/recv immediately after either is
    // safe -- no manual poll loop, unlike the Mio Owner example this
    // mirrors.
    let caller_session = tokio::time::timeout(deadline, facade.connect(&caller_config)).await??;
    let mut listener_session = tokio::time::timeout(deadline, facade.accept())
        .await?
        .expect("the facade's driver task is still running");
    println!("caller connected and the listener accepted it");

    let message = b"hello from the Tokio facade";
    tokio::time::timeout(deadline, caller_session.send(message.to_vec())).await??;
    let received = tokio::time::timeout(deadline, listener_session.recv())
        .await?
        .expect("the payload arrives before the session closes");
    assert_eq!(received.payload.as_ref(), message);
    println!(
        "listener received {} bytes verbatim: {:?} ({:?} old -- see the tokio_relay \
         example for preserving this age across a forwarding hop)",
        received.payload.len(),
        String::from_utf8_lossy(&received.payload),
        received.age(facade.now()),
    );

    // Orderly close: the caller disconnects; the listener's session
    // observes it as recv() resolving to None.
    caller_session.close();
    let closed = tokio::time::timeout(deadline, listener_session.recv()).await?;
    assert!(
        closed.is_none(),
        "listener session's recv() must resolve to None once the caller closes"
    );
    println!("caller closed in an orderly way; listener observed it");

    // Graceful shutdown: drop every Facade/Session handle -- each Session
    // holds its own command-channel sender, so all of them, not just the
    // Facade, must go before the driver task can observe "nothing external
    // wants me anymore" and stop on its own -- then join the driver task
    // to see that it actually did.
    drop(facade);
    drop(caller_session);
    drop(listener_session);
    driver.await?;
    println!("driver task shut down cleanly");

    Ok(())
}
