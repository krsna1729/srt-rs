//! monoio adapter: task-per-connection via `monoio::spawn` — monoio is
//! thread-per-core with completion-based (owned-buffer) I/O and no
//! non-blocking try_recv, so each task owns its blocking recv. Native
//! io_uring timers live inside Conn.
//!
//! Receive shape (proven): ONE datagram per loop iteration via a blocking
//! timeout-wrapped recv, protocol maintenance after each. Timeouts only
//! ever fire when idle, so in-flight recvs are essentially never cancelled.

use crate::{Aggregate, ConnStats, LossConfig};
use shiguredo_srt::{ConnectionEvent, ConnectionOptions, SrtConnection};
use srt_transport::monoio_transport::Conn;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

pub fn run(cfg: LossConfig) {
    let mut rt = monoio::RuntimeBuilder::<monoio::IoUringDriver>::new()
        .enable_timer()
        .build()
        .expect("monoio io_uring runtime");
    rt.block_on(drive(cfg));
}

async fn drive(cfg: LossConfig) {
    let start = Instant::now();
    if cfg.mode == crate::Mode::Receiver {
        println!("LISTENING");
        if cfg.connections > 1 {
            eprintln!(
                "[bench-monoio] scale: ports {}-{}",
                cfg.port,
                cfg.port + cfg.connections as u16 - 1
            );
        }
    }

    let mut handles = Vec::with_capacity(cfg.connections);
    for i in 0..cfg.connections {
        let endpoint = cfg.addr_for(i);
        let c2 = cfg.clone();
        handles.push(monoio::spawn(async move {
            match c2.mode {
                crate::Mode::Sender => sender_task(c2, endpoint, start).await,
                crate::Mode::Receiver => receiver_task(c2, endpoint.port(), start).await,
            }
        }));
    }

    let mut agg = Aggregate::new(cfg.clone());
    for h in handles {
        let stats = h.await;
        agg.add(stats);
    }
    agg.print(start);

    if !agg.any_connected {
        std::process::exit(1);
    }
}

async fn sender_task(cfg: LossConfig, endpoint: SocketAddr, start: Instant) -> ConnStats {
    let socket = monoio::net::udp::UdpSocket::bind("0.0.0.0:0").expect("bind");
    socket.connect(endpoint).await.expect("connect");

    let options = ConnectionOptions {
        socket_id: std::process::id(),
        tsbpd_delay: cfg.latency_ms,
        max_bandwidth_bytes_per_sec: Some(cfg.bitrate_bps / 8),
        ..Default::default()
    };
    let mut conn = SrtConnection::new_caller(options);
    conn.connect(crate::now_ts(start))
        .expect("connect() should queue INDUCTION");

    let mut driver = Conn::new(conn, socket);
    driver.drain_outputs(crate::now_ts(start)).await;

    let payload = vec![0x42u8; crate::PAYLOAD_SIZE];
    let mut stats = ConnStats::default();
    let mut stream_deadline: Option<Instant> = None;
    let connect_deadline = start + crate::INTEROP_CONNECT_TIMEOUT;

    loop {
        if !stats.connected && Instant::now() >= connect_deadline {
            eprintln!("[bench-monoio] connect timed out, state={:?}", driver.conn.state());
            break;
        }
        if let Some(d) = stream_deadline
            && Instant::now() >= d
        {
            break;
        }

        // Block until the next paced send is due (bounded by MAX_WAIT).
        // A fresh buffer per attempt -- io_uring ops can't be safely
        // cancelled mid-flight, so a timed-out recv's buffer is simply
        // abandoned rather than reused.
        let wait = if stats.connected {
            Duration::from_micros(driver.conn.time_until_send(crate::now_ts(start)))
                .min(crate::MAX_WAIT)
        } else {
            crate::MAX_WAIT
        };
        if let Ok((Ok(n), buf)) =
            monoio::time::timeout(wait, driver.sock.recv(vec![0u8; 2048])).await
        {
            let t = crate::now_ts(start);
            let _ = driver.conn.feed_recv_buf(&buf[..n], t);
        }

        let t = crate::now_ts(start);
        driver.fire_expired();
        driver.drain_outputs(t).await;

        while let Some(ev) = driver.conn.poll_event() {
            match ev {
                ConnectionEvent::Connected => {
                    stats.connected = true;
                    if cfg.verbose() {
                        println!("CONNECTED");
                    }
                    stream_deadline =
                        Some(Instant::now() + Duration::from_secs_f64(cfg.duration_secs));
                }
                ConnectionEvent::Disconnected { reason } => {
                    eprintln!("[bench-monoio] disconnected: {reason}");
                    stream_deadline = Some(Instant::now());
                }
                ConnectionEvent::Error(msg) => {
                    eprintln!("[bench-monoio] error: {msg}");
                }
                _ => {}
            }
        }

        if stats.connected {
            loop {
                let t = crate::now_ts(start);
                if driver.send_paced(&payload, t).await.is_err() {
                    break;
                }
                stats.data_events += 1;
            }
        }
    }

    if let Some(s) = driver.conn.sender_stats() {
        stats.has_stats = true;
        stats.core_total = s.total_sent;
        stats.secondary_a = s.total_retransmits as u64;
        stats.secondary_b = s.packets_in_loss_list as u64;
    }
    stats
}

async fn receiver_task(cfg: LossConfig, listen_port: u16, start: Instant) -> ConnStats {
    let socket = monoio::net::udp::UdpSocket::bind(SocketAddr::from(([0, 0, 0, 0], listen_port)))
        .expect("bind");

    let options = ConnectionOptions {
        socket_id: std::process::id(),
        tsbpd_delay: cfg.latency_ms,
        ..Default::default()
    };
    let conn = SrtConnection::new_listener(options);
    let mut driver = Conn::new(conn, socket);

    let mut stats = ConnStats::default();
    let mut stream_deadline: Option<Instant> = None;
    let connect_deadline = Instant::now() + crate::INTEROP_CONNECT_TIMEOUT;
    let mut peer: Option<SocketAddr> = None;

    loop {
        if !stats.connected && Instant::now() >= connect_deadline {
            eprintln!("[bench-monoio] connect timed out, state={:?}", driver.conn.state());
            break;
        }
        if let Some(d) = stream_deadline
            && Instant::now() >= d
        {
            break;
        }

        // One datagram per iteration: recv_from until the first packet
        // reveals the peer, then connect the socket (drain_outputs uses
        // connected send). Maintenance runs after every packet.
        if let Ok((res, buf)) =
            monoio::time::timeout(crate::MAX_WAIT, driver.sock.recv_from(vec![0u8; 2048])).await
            && let Ok((n, addr)) = res
        {
            if peer.is_none() {
                if let Err(e) = driver.sock.connect(addr).await {
                    eprintln!("[bench-monoio] connect to peer failed: {e}");
                } else {
                    peer = Some(addr);
                }
            }
            let t = crate::now_ts(start);
            let _ = driver.conn.feed_recv_buf(&buf[..n], t);
        }

        let t = crate::now_ts(start);
        driver.fire_expired();
        driver.drain_outputs(t).await;

        while let Some(ev) = driver.conn.poll_event() {
            match ev {
                ConnectionEvent::Connected => {
                    stats.connected = true;
                    if cfg.verbose() {
                        println!("CONNECTED");
                    }
                    stream_deadline =
                        Some(Instant::now() + Duration::from_secs_f64(cfg.duration_secs));
                }
                ConnectionEvent::DataReceived { .. } => {
                    stats.data_events += 1;
                }
                ConnectionEvent::Disconnected { reason } => {
                    eprintln!("[bench-monoio] disconnected: {reason}");
                    stream_deadline = Some(Instant::now());
                }
                ConnectionEvent::Error(msg) => {
                    eprintln!("[bench-monoio] error: {msg}");
                }
                _ => {}
            }
        }
    }

    if let Some(s) = driver.conn.receiver_stats() {
        stats.has_stats = true;
        stats.core_total = s.total_received;
        stats.secondary_a = s.total_lost;
        stats.secondary_b = s.total_duplicates;
        stats.rtt_us = s.rtt as u64;
    }
    stats
}
