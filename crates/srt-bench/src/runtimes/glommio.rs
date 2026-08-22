//! glommio adapter: task-per-connection via `glommio::spawn_local` —
//! glommio's designed thread-per-core primitive. Linux-only (io_uring).
//! Native `glommio::timer::sleep` timers live inside Conn.
//!
//! KNOWN LIMITATION (measured, N>=300): the listener starves under load —
//! kernel buffers overflow, sequence gaps trigger NAK storms, RTT inflates
//! to hundreds of ms. Diagnosis: every loop iteration re-creates the recv
//! future (`or(recv_from, sleep)`), submitting a fresh io_uring op per
//! datagram; at 455k pps aggregate this saturates glommio's default
//! submission queue. Candidate fixes, untested:
//!   1. `LocalExecutorBuilder::io_memory(n)` — public API knob for the SQ
//!      ring size (no glommio source changes needed).
//!   2. Batch recvs per wakeup via `poll_once` (executor-safe, unlike the
//!      removed try_recv whose futures_lite::block_on parks the whole
//!      executor thread — never reintroduce it here).

use crate::{Aggregate, ConnStats, LossConfig};
use shiguredo_srt::{ConnectionEvent, ConnectionOptions, SrtConnection};
use srt_transport::glommio_transport::Conn;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

pub fn run(cfg: LossConfig) {
    let c2 = cfg.clone();
    // Ring sizing expedition: the default submission queue (small) is the
    // prime suspect for listener starvation at N>=300 -- 300 tasks each
    // submitting a fresh recv SQE per datagram at 455k pps aggregate
    // saturates it. io_memory() sizes the SQ/CQ rings via glommio's public
    // builder API (no source modification).
    let any_connected = glommio::LocalExecutorBuilder::default()
        .io_memory(4096)
        .spawn(move || async move { drive(c2).await })
        .expect("failed to spawn glommio LocalExecutor")
        .join()
        .expect("glommio task panicked");

    if !any_connected {
        std::process::exit(1);
    }
}

async fn drive(cfg: LossConfig) -> bool {
    let start = Instant::now();
    if cfg.mode == crate::Mode::Receiver {
        println!("LISTENING");
        if cfg.connections > 1 {
            eprintln!(
                "[loss-glommio] scale: ports {}-{}",
                cfg.port,
                cfg.port + cfg.connections as u16 - 1
            );
        }
    }

    let mut handles = Vec::with_capacity(cfg.connections);
    for i in 0..cfg.connections {
        let endpoint = cfg.addr_for(i);
        let c2 = cfg.clone();
        handles.push(glommio::spawn_local(async move {
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

    agg.any_connected
}

async fn sender_task(cfg: LossConfig, endpoint: SocketAddr, start: Instant) -> ConnStats {
    let socket = glommio::net::UdpSocket::bind("0.0.0.0:0").expect("bind");
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
    let mut buf = [0u8; 2048];

    loop {
        if !stats.connected && Instant::now() >= connect_deadline {
            eprintln!("[loss-glommio] connect timed out, state={:?}", driver.conn.state());
            break;
        }
        if let Some(d) = stream_deadline
            && Instant::now() >= d
        {
            break;
        }

        // One datagram per iteration. NOTE: never use Conn::try_recv here --
        // it parks the executor thread (futures_lite::block_on), starving
        // every other task under load. The or(sleep) arm only fires when
        // idle, so in-flight recvs are essentially never cancelled.
        let recv_fut = async { driver.sock.recv_from(&mut buf).await.ok() };
        let timer_fut = async {
            glommio::timer::sleep(crate::MAX_WAIT).await;
            None
        };
        if let Some((n, _addr)) = futures_lite::future::or(recv_fut, timer_fut).await {
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
                    eprintln!("[loss-glommio] disconnected: {reason}");
                    stream_deadline = Some(Instant::now());
                }
                ConnectionEvent::Error(msg) => {
                    eprintln!("[loss-glommio] error: {msg}");
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
    let socket =
        glommio::net::UdpSocket::bind(SocketAddr::from(([0, 0, 0, 0], listen_port))).expect("bind");

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
    let mut handshook = false;
    let mut buf = [0u8; 2048];

    loop {
        if !stats.connected && Instant::now() >= connect_deadline {
            eprintln!("[loss-glommio] connect timed out, state={:?}", driver.conn.state());
            break;
        }
        if let Some(d) = stream_deadline
            && Instant::now() >= d
        {
            break;
        }

        // One datagram per iteration. First datagram reveals the caller;
        // connect before anything else (drain_outputs uses connected send).
        // NOTE: never use Conn::try_recv here -- it parks the executor
        // thread, starving every other task under load.
        let recv_fut = async { driver.sock.recv_from(&mut buf).await.ok() };
        let timer_fut = async {
            glommio::timer::sleep(crate::MAX_WAIT).await;
            None
        };
        if let Some((n, addr)) = futures_lite::future::or(recv_fut, timer_fut).await {
            if !handshook && driver.sock.connect(addr).await.is_err() {
                eprintln!("[loss-glommio] connect to peer failed");
                continue;
            }
            handshook = true;
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
                    eprintln!("[loss-glommio] disconnected: {reason}");
                    stream_deadline = Some(Instant::now());
                }
                ConnectionEvent::Error(msg) => {
                    eprintln!("[loss-glommio] error: {msg}");
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
