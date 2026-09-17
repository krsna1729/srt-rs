//! Datapath floor: what one core can actually do, measured, not assumed.
//!
//! The scaling report claimed a shard's cost was "the copies" at 4.6 ns/byte
//! (217 MB/s). That claim had two holes, and this bench exists to close them:
//!
//! * the payload-size sweep held the wire datagram count *and* the wire bytes
//!   constant, so it established "not per application payload" and nothing
//!   finer -- it never showed copying was the cost;
//! * 217 MB/s is ~80x slower than a single-core 1316-byte `memcpy` on this
//!   host, so "copying" was the wrong word for whatever it does measure.
//!
//! Four floors, all single-threaded, one core, sender and receiver in this
//! process, measured with `getrusage` CPU deltas *and* verified datagram
//! counts, because a blocking socket that backpressures would otherwise report
//! a beautiful number for a send that never happened:
//!
//! 1. `FLOOR_MEMCPY` -- single-core copy cost and bandwidth by size.
//! 2. `arm=io_uring_1op` -- Compio `send_to`, one operation awaited at a time
//!    (a full submit/completion round trip per datagram).
//! 3. `arm=io_uring_pipeline` -- Compio `send_to` with `K` operations in
//!    flight, which is the structure the Owner's TX lanes use.
//! 4. `arm=sendmmsg` -- batched syscall submission, 1/16/64 datagrams per
//!    call, which is the shape the report calls out of scope.
//!
//! Arms 2-4 are run per *runtime*, not just for Compio: `compio` submits
//! through io_uring, `tokio` through its reactor (`epoll` readiness plus a
//! `send_to`), and `mio` through an explicit `Poll` writability wait. The
//! three-runtime set is the shipped set, so a floor claimed for one of them
//! and not the others is not a floor for the project -- and if they differ,
//! the difference is exactly the per-datagram submission cost this report is
//! about.
//!
//! Run with:
//!
//! ```text
//! cargo bench -p srt-bench --bench udp_datapath_floor
//! ```

use std::net::{SocketAddr, UdpSocket};
use std::time::Instant;

use srt_bench::cpu_stats::process_stats;

/// Payload sizes under test: the qualification payload and the size the
/// payload sweep compared it against.
const PAYLOAD_SIZES: [usize; 2] = [700, 1316];
/// Datagrams per arm, so every arm moves the same bytes at a given size.
const DATAGRAMS: usize = 60_000;
const ROUNDS: usize = 3;
/// Batch widths for the `sendmmsg` arm.
const BATCHES: [usize; 3] = [1, 16, 64];
/// In-flight depth for the pipelined Compio arm (the Owner's lane count).
const PIPELINE_K: usize = 64;
/// Runtimes the submit-path arms are measured for. Same three the transport
/// ships: mio (readiness reference), tokio (managed async), compio (io_uring).
const RUNTIMES: [&str; 3] = ["mio", "tokio", "compio"];
const COPY_SIZES: [usize; 5] = [64, 700, 1316, 4096, 65_536];
const COPY_ITERS: usize = 200_000;
const LARGE_COPY_ITERS: usize = 4_000;

/// Outcome of one arm: what it actually moved, and what it cost.
struct Arm {
    sent: usize,
    cpu_ms: f64,
    wall_s: f64,
}

impl Arm {
    fn us_cpu_per_datagram(&self) -> f64 {
        self.cpu_ms * 1000.0 / self.sent.max(1) as f64
    }

    fn ns_cpu_per_byte(&self, bytes: usize) -> f64 {
        self.cpu_ms * 1e6 / self.sent.max(1) as f64 / bytes as f64
    }

    /// Wall-clock payload bandwidth. CPU-per-datagram can look excellent when
    /// a socket backpressures, so this is the number that catches that.
    fn gb_per_s(&self, bytes: usize) -> f64 {
        self.sent as f64 * bytes as f64 / self.wall_s.max(1e-9) / 1e9
    }

    fn datagrams_per_s(&self) -> f64 {
        self.sent as f64 / self.wall_s.max(1e-9)
    }
}

fn median(mut v: Vec<f64>) -> f64 {
    v.sort_by(|a, b| a.partial_cmp(b).unwrap());
    v[v.len() / 2]
}

fn cpu_ms_now() -> f64 {
    let s = process_stats();
    s.cpu_user_ms + s.cpu_sys_ms
}

fn print_arm(name: &str, bytes: usize, extra: &str, a: &Arm) {
    println!(
        "FLOOR arm={} bytes={} {} sent={} us_cpu_per_datagram={:.3} ns_cpu_per_byte={:.3} \
         datagrams_per_s={:.0} gb_per_s={:.2} cpu_ms={:.1} wall_s={:.3}",
        name,
        bytes,
        extra,
        a.sent,
        a.us_cpu_per_datagram(),
        a.ns_cpu_per_byte(bytes),
        a.datagrams_per_s(),
        a.gb_per_s(bytes),
        a.cpu_ms,
        a.wall_s,
    );
}

// --------------------------------------------------------------------------
// 1. memcpy
// --------------------------------------------------------------------------

fn copy_ns_per_iter(src: &[u8], dst: &mut [u8], iters: usize) -> f64 {
    let start = Instant::now();
    for _ in 0..iters {
        // SAFETY: `src` and `dst` are distinct buffers of equal length
        // (allocated together above), so the ranges cannot overlap.
        unsafe {
            std::ptr::copy_nonoverlapping(src.as_ptr(), dst.as_mut_ptr(), src.len());
        }
        std::hint::black_box(&dst[0]);
    }
    start.elapsed().as_secs_f64() * 1e9 / iters as f64
}

fn memcpy_arm() {
    for size in COPY_SIZES {
        let src = vec![0x5Au8; size];
        let mut dst = vec![0u8; size];
        let iters = if size >= 65_536 {
            LARGE_COPY_ITERS
        } else {
            COPY_ITERS
        };
        let _ = copy_ns_per_iter(&src, &mut dst, iters / 10 + 1);
        let ns = median(
            (0..ROUNDS)
                .map(|_| copy_ns_per_iter(&src, &mut dst, iters))
                .collect(),
        );
        println!(
            "FLOOR_MEMCPY bytes={} ns_per_copy={:.2} gb_per_s={:.2}",
            size,
            ns,
            size as f64 / ns
        );
    }
}

// --------------------------------------------------------------------------
// 2/3. Compio io_uring arms
// --------------------------------------------------------------------------

/// One operation awaited at a time: a full submit/completion round trip per
/// datagram.
fn arm_io_uring_serial(peer: SocketAddr, bytes: usize) -> Arm {
    use compio::net::UdpSocket;
    let runtime = compio::runtime::Runtime::new().expect("compio runtime");
    let payload = bytes::Bytes::from(vec![0x5Au8; bytes]);
    runtime.block_on(async move {
        let sock = UdpSocket::bind("127.0.0.1:0").await.expect("bind");
        let cpu0 = cpu_ms_now();
        let wall0 = Instant::now();
        let mut sent = 0usize;
        while sent < DATAGRAMS {
            let out = sock.send_to(payload.clone(), peer).await;
            match out.0 {
                Ok(_) => sent += 1,
                Err(_) => break,
            }
        }
        let wall_s = wall0.elapsed().as_secs_f64();
        Arm {
            sent,
            cpu_ms: cpu_ms_now() - cpu0,
            wall_s,
        }
    })
}

/// `K` operations in flight: the structure the Owner's TX lanes use. If
/// pipelining recovers the kernel's marginal cost, the serial arm's figure is
/// an artifact of the harness, not a property of the datapath.
fn arm_io_uring_pipeline(peer: SocketAddr, bytes: usize, k: usize) -> Arm {
    use compio::net::UdpSocket;
    use futures_util::stream::{FuturesUnordered, StreamExt};
    let runtime = compio::runtime::Runtime::new().expect("compio runtime");
    let payload = bytes::Bytes::from(vec![0x5Au8; bytes]);
    runtime.block_on(async move {
        let sock = std::rc::Rc::new(UdpSocket::bind("127.0.0.1:0").await.expect("bind"));
        let cpu0 = cpu_ms_now();
        let wall0 = Instant::now();
        let mut sent = 0usize;
        let mut inflight = FuturesUnordered::new();
        while sent < DATAGRAMS {
            while inflight.len() < k {
                let sock = sock.clone();
                let buf = payload.clone();
                inflight.push(async move { sock.send_to(buf, peer).await });
                sent += 1;
            }
            match inflight.next().await {
                Some(out) if out.0.is_ok() => {}
                _ => break,
            }
        }
        while inflight.next().await.is_some() {}
        let wall_s = wall0.elapsed().as_secs_f64();
        Arm {
            sent,
            cpu_ms: cpu_ms_now() - cpu0,
            wall_s,
        }
    })
}

// --------------------------------------------------------------------------
// 4. sendmmsg
// --------------------------------------------------------------------------

/// A real `sockaddr_in` for `msg_name`. (`SocketAddr` is a Rust enum; casting
/// it to `sockaddr*` yields EMSGSIZE, which is how the first version of this
/// arm managed to send exactly nothing.)
fn sockaddr_in(addr: &SocketAddr) -> libc::sockaddr_in {
    let v4 = match addr {
        SocketAddr::V4(v4) => *v4,
        SocketAddr::V6(_) => panic!("this arm is IPv4-only"),
    };
    // SAFETY: all-zero is a valid `sockaddr_in`; every field is set below.
    let mut sa: libc::sockaddr_in = unsafe { std::mem::zeroed() };
    sa.sin_family = libc::AF_INET as u16;
    sa.sin_port = v4.port().to_be();
    sa.sin_addr.s_addr = u32::from(*v4.ip()).to_be();
    sa
}

/// `datagrams` datagrams of `bytes`, `batch` per `sendmmsg` call. Sends
/// without blocking (`MSG_DONTWAIT`) so a slow receiver shows up as `sent`
/// below the target instead of as a mysteriously cheap rate.
fn arm_sendmmsg(sock: &UdpSocket, peer: SocketAddr, bytes: usize, batch: usize) -> Arm {
    let mut payloads: Vec<Vec<u8>> = vec![vec![0x5Au8; bytes]; batch];
    // A real `iovec` per message. Pointing `msg_iov` at the payload bytes
    // instead of at an iovec array makes the kernel read the payload as
    // `{iov_base, iov_len}` and return EMSGSIZE -- which is exactly what the
    // first two versions of this arm did, sending nothing while looking
    // plausible.
    let mut iovecs: Vec<libc::iovec> = payloads
        .iter_mut()
        .map(|p| libc::iovec {
            iov_base: p.as_mut_ptr().cast(),
            iov_len: bytes,
        })
        .collect();
    // SAFETY: all-zero is a valid `mmsghdr`; every field used is set below.
    let mut msgs: Vec<libc::mmsghdr> = vec![unsafe { std::mem::zeroed() }; batch];
    // One address struct reused by every message, so the arm prices the
    // syscall and the kernel's per-datagram work, not address marshalling.
    let mut sa = sockaddr_in(&peer);
    for i in 0..batch {
        msgs[i].msg_hdr.msg_name = (&mut sa as *mut libc::sockaddr_in).cast();
        msgs[i].msg_hdr.msg_namelen = std::mem::size_of::<libc::sockaddr_in>() as u32;
        msgs[i].msg_hdr.msg_iov = &mut iovecs[i] as *mut libc::iovec;
        msgs[i].msg_hdr.msg_iovlen = 1;
    }
    let fd = std::os::fd::AsRawFd::as_raw_fd(sock);
    let cpu0 = cpu_ms_now();
    let wall0 = Instant::now();
    let mut sent = 0usize;
    // Blocking sends: a `MSG_DONTWAIT` retry loop turns socket backpressure
    // into a spin that both distorts the CPU figure and can hang the run, and
    // a real sender cannot avoid backpressure anyway.
    while sent < DATAGRAMS {
        // SAFETY: `msgs` has `batch` initialised entries with valid iovecs into
        // `payloads`, which outlive the call.
        let rc = unsafe { libc::sendmmsg(fd, msgs.as_mut_ptr(), batch as u32, 0) };
        if rc <= 0 {
            if sent == 0 {
                eprintln!(
                    "FLOOR_ERROR sendmmsg batch={batch} bytes={bytes} errno={}",
                    std::io::Error::last_os_error()
                );
            }
            break;
        }
        sent += rc as usize;
    }
    let wall_s = wall0.elapsed().as_secs_f64();
    Arm {
        sent,
        cpu_ms: cpu_ms_now() - cpu0,
        wall_s,
    }
}

// --------------------------------------------------------------------------
// 2b. tokio and mio submit paths (same one-datagram-per-operation shape)
// --------------------------------------------------------------------------

/// Tokio `send_to`, one await per datagram: reactor readiness plus the send.
fn arm_tokio_send_to(peer: SocketAddr, bytes: usize) -> Arm {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");
    runtime.block_on(async move {
        let sock = tokio::net::UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let payload = vec![0x5Au8; bytes];
        let cpu0 = cpu_ms_now();
        let wall0 = Instant::now();
        let mut sent = 0usize;
        while sent < DATAGRAMS {
            match sock.send_to(&payload, peer).await {
                Ok(_) => sent += 1,
                Err(_) => break,
            }
        }
        let wall_s = wall0.elapsed().as_secs_f64();
        Arm {
            sent,
            cpu_ms: cpu_ms_now() - cpu0,
            wall_s,
        }
    })
}

/// Mio: explicit `Poll` writability wait, then `send_to`. This is the
/// readiness reference path -- one poll iteration (and usually one `epoll`
/// syscall) per datagram, which is what "readiness" costs.
fn arm_mio_send_to(peer: SocketAddr, bytes: usize) -> Arm {
    use mio::{Events, Interest, Poll, Token};
    let mut poll = Poll::new().expect("poll");
    let mut events = Events::with_capacity(64);
    let mut sock = mio::net::UdpSocket::bind("127.0.0.1:0".parse().unwrap()).expect("bind");
    poll.registry()
        .register(&mut sock, Token(0), Interest::WRITABLE)
        .expect("register");
    let payload = vec![0x5Au8; bytes];
    let cpu0 = cpu_ms_now();
    let wall0 = Instant::now();
    let mut sent = 0usize;
    while sent < DATAGRAMS {
        match sock.send_to(&payload, peer) {
            Ok(_) => sent += 1,
            // mio's `Poll` is edge-triggered: waiting for writability before
            // every send blocks forever after the first event, because the
            // socket stays writable and no new edge arrives. Waiting only on
            // `WouldBlock` is what readiness-based code actually does, and it
            // is also the only version that terminates.
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                if poll.poll(&mut events, None).is_err() {
                    break;
                }
            }
            Err(_) => break,
        }
    }
    let wall_s = wall0.elapsed().as_secs_f64();
    Arm {
        sent,
        cpu_ms: cpu_ms_now() - cpu0,
        wall_s,
    }
}

/// Per-syscall cost, nothing else: `getpid` in a tight loop. Kernel
/// entry/exit through the same mitigated path every UDP syscall takes, with no
/// socket, buffer or queue work -- the term a batch of `b` datagrams amortises
/// by `1/b`.
fn null_syscall_arm(iters: usize) -> f64 {
    let cpu0 = cpu_ms_now();
    for _ in 0..iters {
        // SAFETY: `getpid` takes no arguments and cannot fail.
        unsafe {
            libc::syscall(libc::SYS_getpid);
        }
    }
    let cpu1 = cpu_ms_now();
    cpu1 - cpu0
}

fn main() {
    println!(
        "# udp_datapath_floor os={} cpus={} datagrams_per_arm={} rounds={} pipeline_k={}",
        std::env::consts::OS,
        std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(0),
        DATAGRAMS,
        ROUNDS,
        PIPELINE_K
    );

    memcpy_arm();

    // 2,000,000 null syscalls; median of 3 rounds.
    const NULL_SYSCALLS: usize = 2_000_000;
    let _ = null_syscall_arm(NULL_SYSCALLS / 10);
    let null_ns = median(
        (0..3)
            .map(|_| null_syscall_arm(NULL_SYSCALLS) * 1e6 / NULL_SYSCALLS as f64)
            .collect(),
    );
    println!(
        "FLOOR arm=null_syscall syscalls={} ns_per_syscall={:.1}",
        NULL_SYSCALLS, null_ns
    );

    for bytes in PAYLOAD_SIZES {
        // A live receiver, so loopback does not turn every datagram into an
        // ICMP port-unreachable and move the cost somewhere else entirely.
        // Blocking, no read timeout, and errors ignored: a receiver that
        // exits on a transient timeout leaves the sender spinning against a
        // full socket buffer, which reads as an infinite hang rather than as
        // a measurement. The thread is detached (a dropped `JoinHandle` does
        // not join) and the process exit reclaims it.
        let rx = UdpSocket::bind("127.0.0.1:0").expect("bind rx");
        let peer = rx.local_addr().expect("addr");
        let rx_thread = std::thread::spawn(move || {
            let mut buf = vec![0u8; 65_536];
            loop {
                if rx.recv_from(&mut buf).is_err() {
                    continue;
                }
            }
        });

        for runtime in RUNTIMES {
            let name = match runtime {
                "compio" => "io_uring_1op",
                "tokio" => "tokio_send_to_1op",
                _ => "mio_poll_send_to_1op",
            };
            let run = || match runtime {
                "compio" => arm_io_uring_serial(peer, bytes),
                "tokio" => arm_tokio_send_to(peer, bytes),
                _ => arm_mio_send_to(peer, bytes),
            };
            let _ = run();
            let a = median_arm((0..ROUNDS).map(|_| run()).collect());
            print_arm(name, bytes, &format!("runtime={runtime} concurrency=1"), &a);
        }

        let _ = arm_io_uring_pipeline(peer, bytes, PIPELINE_K);
        let a = median_arm(
            (0..ROUNDS)
                .map(|_| arm_io_uring_pipeline(peer, bytes, PIPELINE_K))
                .collect(),
        );
        print_arm(
            "io_uring_pipeline",
            bytes,
            &format!("runtime=compio concurrency={PIPELINE_K}"),
            &a,
        );

        for batch in BATCHES {
            // Deliberately *not* connected: `sendmmsg` with a per-message
            // `msg_name` is the shape an Owner shard needs (one syscall, many
            // destinations), and a connected socket rejects it (`EISCONN`).
            let sock = UdpSocket::bind("127.0.0.1:0").expect("bind");
            let _ = arm_sendmmsg(&sock, peer, bytes, batch);
            let a = median_arm(
                (0..ROUNDS)
                    .map(|_| arm_sendmmsg(&sock, peer, bytes, batch))
                    .collect(),
            );
            print_arm("sendmmsg", bytes, &format!("batch={batch}"), &a);
        }

        std::mem::drop(rx_thread);
    }
}

/// Median arm by `us_cpu_per_datagram`, keeping that arm's whole measurement.
fn median_arm(v: Vec<Arm>) -> Arm {
    let key = median(v.iter().map(|a| a.us_cpu_per_datagram()).collect());
    let mut v = v;
    v.sort_by(|a, b| {
        (a.us_cpu_per_datagram() - key)
            .abs()
            .partial_cmp(&(b.us_cpu_per_datagram() - key).abs())
            .unwrap()
    });
    v.remove(0)
}
