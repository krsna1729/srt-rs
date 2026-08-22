//! smol adapter: task-per-connection on an `async_executor::LocalExecutor`
//! (smol's own block_on executor requires Send; Conn's native timers are
//! !Send). Native `smol::Timer` timers live inside Conn.

use crate::{Aggregate, ConnStats, LossConfig};
use shiguredo_srt::{ConnectionEvent, ConnectionOptions, SrtConnection};
use srt_transport::smol_transport::{Conn, UdpSocket};
use std::net::SocketAddr;
use std::time::{Duration, Instant};

pub fn run(cfg: LossConfig) {
    smol::block_on(drive(cfg));
}

async fn drive(cfg: LossConfig) {
    let start = Instant::now();
    if cfg.mode == crate::Mode::Receiver {
        println!("LISTENING");
        if cfg.connections > 1 {
            eprintln!(
                "[loss-smol] scale: ports {}-{}",
                cfg.port,
                cfg.port + cfg.connections as u16 - 1
            );
        }
    }

    let ex = async_executor::LocalExecutor::new();
    let mut handles = Vec::with_capacity(cfg.connections);
    for i in 0..cfg.connections {
        let endpoint = cfg.addr_for(i);
        let c2 = cfg.clone();
        handles.push(ex.spawn(async move {
            match c2.mode {
                crate::Mode::Sender => sender_task(c2, endpoint, start).await,
                crate::Mode::Receiver => receiver_task(c2, endpoint.port(), start).await,
            }
        }));
    }

    // Drive the executor until every task has reported its result.
    let mut agg = Aggregate::new(cfg.clone());
    ex.run(async {
        for h in handles {
            agg.add(h.await);
        }
    })
    .await;
    agg.print(start);

    if !agg.any_connected {
        std::process::exit(1);
    }
}

async fn sender_task(cfg: LossConfig, endpoint: SocketAddr, start: Instant) -> ConnStats {
    let socket = UdpSocket::bind(SocketAddr::from(([0, 0, 0, 0], 0))).expect("bind");
    socket.get_ref().connect(endpoint).expect("connect");

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
    let mut buf = [0u8; 2048];

    loop {
        if !stats.connected && Instant::now() >= connect_deadline {
            eprintln!("[loss-smol] connect timed out, state={:?}", driver.conn.state());
            break;
        }
        if let Some(d) = stream_deadline
            && Instant::now() >= d
        {
            break;
        }

        let wait = if stats.connected {
            Duration::from_micros(driver.conn.time_until_send(crate::now_ts(start)))
                .min(crate::MAX_WAIT)
        } else {
            crate::MAX_WAIT
        };
        let block_for = wait.saturating_sub(crate::TAIL_SPIN);
        if block_for > Duration::ZERO {
            driver
                .recv_with_timeout(&mut buf, block_for, crate::now_ts(start))
                .await;
        }

        while let Some(res) = driver.try_recv(&mut buf) {
            match res {
                Ok(n) => {
                    let t = crate::now_ts(start);
                    let _ = driver.conn.feed_recv_buf(&buf[..n], t);
                }
                Err(_) => break,
            }
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
                    eprintln!("[loss-smol] disconnected: {reason}");
                    stream_deadline = Some(Instant::now());
                }
                ConnectionEvent::Error(msg) => {
                    eprintln!("[loss-smol] error: {msg}");
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
    let socket = UdpSocket::bind(SocketAddr::from(([0, 0, 0, 0], listen_port))).expect("bind");

    let options = ConnectionOptions {
        socket_id: std::process::id(),
        tsbpd_delay: cfg.latency_ms,
        ..Default::default()
    };
    let conn = SrtConnection::new_listener(options);
    let mut driver = Conn::new(conn, socket);
    driver.drain_outputs(crate::now_ts(start)).await;

    let mut stats = ConnStats::default();
    let mut stream_deadline: Option<Instant> = None;
    let connect_deadline = Instant::now() + crate::INTEROP_CONNECT_TIMEOUT;
    let mut peer: Option<SocketAddr> = None;
    let mut buf = [0u8; 2048];

    loop {
        if !stats.connected && Instant::now() >= connect_deadline {
            eprintln!("[loss-smol] connect timed out, state={:?}", driver.conn.state());
            break;
        }
        if let Some(d) = stream_deadline
            && Instant::now() >= d
        {
            break;
        }

        if peer.is_none() {
            // Unconnected phase: first datagram reveals the caller; connect
            // before anything else (drain_outputs uses connected send).
            let recv_fut = async { driver.sock.recv_from(&mut buf).await.ok() };
            let timer_fut = async {
                smol::Timer::after(crate::MAX_WAIT).await;
                None
            };
            if let Some((n, addr)) = futures_lite::future::or(recv_fut, timer_fut).await {
                if driver.sock.get_ref().connect(addr).is_err() {
                    eprintln!("[loss-smol] connect to peer failed");
                    continue;
                }
                peer = Some(addr);
                let t = crate::now_ts(start);
                let _ = driver.conn.feed_recv_buf(&buf[..n], t);
            }
        } else {
            // Bounded wait keeps the task from busy-spinning when idle.
            driver
                .recv_with_timeout(&mut buf, crate::MAX_WAIT, crate::now_ts(start))
                .await;

            while let Some(res) = driver.try_recv(&mut buf) {
                match res {
                    Ok(n) => {
                        let t = crate::now_ts(start);
                        let _ = driver.conn.feed_recv_buf(&buf[..n], t);
                    }
                    Err(_) => break,
                }
            }

            let t = crate::now_ts(start);
            driver.fire_expired();
            driver.drain_outputs(t).await;
        }

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
                    eprintln!("[loss-smol] disconnected: {reason}");
                    stream_deadline = Some(Instant::now());
                }
                ConnectionEvent::Error(msg) => {
                    eprintln!("[loss-smol] error: {msg}");
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
