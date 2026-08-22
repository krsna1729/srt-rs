//! compio adapter: task-per-connection via `compio::runtime::spawn` —
//! compio's designed primitive. Completion-based (owned-buffer) I/O has no
//! non-blocking try_recv, so each connection gets a detached continuous
//! reader feeding a channel plus the protocol loop. The pacing loop never
//! cancels a receive operation — cancel churn collapses io_uring
//! throughput at scale. Native `compio::time::sleep` timers live inside
//! Conn.

use crate::{Aggregate, ConnStats, LossConfig};
use compio::buf::BufResult;
use shiguredo_srt::{ConnectionEvent, ConnectionOptions, SrtConnection};
use srt_transport::compio_transport::Conn;
use std::net::SocketAddr;
use std::sync::mpsc;
use std::time::{Duration, Instant};

pub fn run(cfg: LossConfig) {
    let rt = compio::runtime::Runtime::builder()
        .build()
        .expect("compio runtime");
    rt.block_on(drive(cfg));
}

async fn drive(cfg: LossConfig) {
    let start = Instant::now();
    if cfg.mode == crate::Mode::Receiver {
        println!("LISTENING");
        if cfg.connections > 1 {
            eprintln!(
                "[bench-compio] scale: ports {}-{}",
                cfg.port,
                cfg.port + cfg.connections as u16 - 1
            );
        }
    }

    let mut handles = Vec::with_capacity(cfg.connections);
    for i in 0..cfg.connections {
        let endpoint = cfg.addr_for(i);
        let c2 = cfg.clone();
        handles.push(compio::runtime::spawn(async move {
            match c2.mode {
                crate::Mode::Sender => sender_task(c2, endpoint, start).await,
                crate::Mode::Receiver => receiver_task(c2, endpoint.port(), start).await,
            }
        }));
    }

    let mut agg = Aggregate::new(cfg.clone());
    for h in handles {
        if let Ok(stats) = h.await {
            agg.add(stats);
        }
    }
    agg.print(start);

    if !agg.any_connected {
        std::process::exit(1);
    }
}

async fn sender_task(cfg: LossConfig, endpoint: SocketAddr, start: Instant) -> ConnStats {
    let socket = compio::net::UdpSocket::bind("0.0.0.0:0")
        .await
        .expect("bind");
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

    // Continuous reader: keeps one owned-buffer recv in flight at a time,
    // never cancelled, forwarding payloads over the channel.
    let (received_sender, received_receiver) = mpsc::channel();
    let received_socket = driver.sock.clone();
    let _reader = compio::runtime::spawn(async move {
        loop {
            let BufResult(result, buffer) = received_socket.recv(vec![0u8; 2048]).await;
            let Ok(size) = result else {
                break;
            };
            if received_sender.send(buffer[..size].to_vec()).is_err() {
                break;
            }
        }
    });
    driver.drain_outputs(crate::now_ts(start)).await;

    let payload = vec![0x42u8; crate::PAYLOAD_SIZE];
    let mut stats = ConnStats::default();
    let mut stream_deadline: Option<Instant> = None;
    let connect_deadline = start + crate::INTEROP_CONNECT_TIMEOUT;

    loop {
        if !stats.connected && Instant::now() >= connect_deadline {
            eprintln!(
                "[bench-compio] connect timed out, state={:?}",
                driver.conn.state()
            );
            break;
        }
        if let Some(d) = stream_deadline
            && Instant::now() >= d
        {
            break;
        }

        // Sleep until the next paced send is due; the reader keeps draining
        // the socket into the channel meanwhile.
        let wait = if stats.connected {
            Duration::from_micros(driver.conn.time_until_send(crate::now_ts(start)))
                .min(crate::MAX_WAIT)
        } else {
            crate::MAX_WAIT
        };
        compio::time::sleep(wait).await;

        while let Ok(buf) = received_receiver.try_recv() {
            let t = crate::now_ts(start);
            let _ = driver.conn.feed_recv_buf(&buf, t);
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
                    eprintln!("[bench-compio] disconnected: {reason}");
                    stream_deadline = Some(Instant::now());
                }
                ConnectionEvent::Error(msg) => {
                    eprintln!("[bench-compio] error: {msg}");
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
    let socket = compio::net::UdpSocket::bind(SocketAddr::from(([0, 0, 0, 0], listen_port)))
        .await
        .expect("bind");

    let options = ConnectionOptions {
        socket_id: std::process::id(),
        tsbpd_delay: cfg.latency_ms,
        ..Default::default()
    };
    let conn = SrtConnection::new_listener(options);
    let mut driver = Conn::new(conn, socket);
    driver.drain_outputs(crate::now_ts(start)).await;

    // Reader task: first packet discovers the peer and connects the socket
    // (drain_outputs uses connected send), then forwards payloads.
    let (received_sender, received_receiver) = mpsc::channel();
    let received_socket = driver.sock.clone();
    let _reader = compio::runtime::spawn(async move {
        let mut first = true;
        loop {
            let BufResult(result, buffer) = received_socket.recv_from(vec![0u8; 2048]).await;
            let Ok((size, addr)) = result else {
                break;
            };
            if first && received_socket.connect(addr).await.is_err() {
                break;
            }
            first = false;
            if received_sender.send(buffer[..size].to_vec()).is_err() {
                break;
            }
        }
    });

    let mut stats = ConnStats::default();
    let mut stream_deadline: Option<Instant> = None;
    let connect_deadline = Instant::now() + crate::INTEROP_CONNECT_TIMEOUT;

    loop {
        if !stats.connected && Instant::now() >= connect_deadline {
            eprintln!(
                "[bench-compio] connect timed out, state={:?}",
                driver.conn.state()
            );
            break;
        }
        if let Some(d) = stream_deadline
            && Instant::now() >= d
        {
            break;
        }

        // The reader drains the socket continuously; this side only pays
        // for protocol maintenance once per MAX_WAIT.
        compio::time::sleep(crate::MAX_WAIT).await;

        while let Ok(packet) = received_receiver.try_recv() {
            let t = crate::now_ts(start);
            let _ = driver.conn.feed_recv_buf(&packet, t);
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
                    eprintln!("[bench-compio] disconnected: {reason}");
                    stream_deadline = Some(Instant::now());
                }
                ConnectionEvent::Error(msg) => {
                    eprintln!("[bench-compio] error: {msg}");
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
