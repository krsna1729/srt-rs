//! Unified loss/scale driver: one shared orchestration layer, one adapter
//! file per runtime. Loss mode and scale mode are the SAME code everywhere:
//! loss runs one connection, scale runs N. Only the STATS schema differs.
//!
//! # Scaling architecture (core/thread/worker model per runtime)
//!
//! | Runtime | Threads/workers      | Connection mapping            | Timers                          |
//! |---------|----------------------|-------------------------------|---------------------------------|
//! | mio     | no runtime, raw epoll| 1 thread : N sockets (`Token(i)` on one `Poll`) | software `ManualTimerStore` scans, gated to active conns |
//! | tokio   | cooperative tasks    | 1 thread : N spawned tasks (`spawn_local` + `LocalSet`) | native wheel, 1 `Sleep` future/conn |
//! | smol    | cooperative tasks    | 1 thread : N tasks (`async_executor::LocalExecutor`; smol's own block_on needs `Send`) | `smol::Timer` futures/conn |
//! | monoio  | thread-per-core      | 1 core : N tasks, completion-based, blocking recvs own their socket | io_uring kernel timeouts |
//! | glommio | thread-per-core      | 1 core : N tasks, shared submission ring | `glommio::timer` wheel          |
//! | compio  | thread-per-core      | 1 thread : 2N tasks (protocol task + never-cancelled reader task/channel) | `compio::time::sleep` |
//!
//! # Measured scaling knee (loopback bakeoff, 8 Mbps/conn)
//!
//! - **<= 300 conns**: task-per-connection models win — best latency
//!   isolation, zero retransmits for tokio/smol/monoio/compio; mio close
//!   behind after its buffer-sizing/timer-gating fixes.
//! - **600 conns**: **mio's flat epoll loop is the only architecture that
//!   sustains full line-rate (4,547,686 sent = received, zero loss)**.
//!   Per-task framework wakeup cost dominates at this density; the
//!   hierarchy inverts. Task-per-conn runtimes hit flow-window stalls
//!   (sender buffers ~8192 pkts x 1316 B x N when ACK turnaround lags --
//!   the source of their GB-scale RSS at 600).
//!
//! Pushing the knee further (per-runtime leads):
//! - tokio/smol: listener drains one datagram per wake; batching extra
//!   ready reads per wake (readiness APIs allow non-blocking re-reads)
//!   would cut wakeups ~10x at high pps.
//! - monoio/compio RSS at 600: sender buffers grow to the flow window when
//!   ACK turnaround lags; faster ACK drain (reader priority) shrinks it.
//! - glommio: SQ-ring saturation suspected; see its module header for the
//!   io_memory/poll_once plan.

pub mod compio;
#[cfg(target_os = "linux")]
pub mod glommio;
pub mod mio;
pub mod monoio;
pub mod smol;
pub mod tokio;

use crate::{LossConfig, Runtime};

/// Dispatch to the selected runtime's driver.
pub fn run(cfg: LossConfig) {
    match cfg.runtime {
        Runtime::Mio => mio::run(cfg),
        Runtime::Tokio => tokio::run(cfg),
        Runtime::Smol => smol::run(cfg),
        Runtime::Monoio => monoio::run(cfg),
        Runtime::Glommio => {
            #[cfg(target_os = "linux")]
            glommio::run(cfg);
            #[cfg(not(target_os = "linux"))]
            {
                let _ = cfg;
                eprintln!("srt-bench: glommio is Linux-only (io_uring)");
                std::process::exit(2);
            }
        }
        Runtime::Compio => compio::run(cfg),
    }
}

/// Destination address of a sender connection i.
pub fn sender_endpoint(cfg: &LossConfig, i: usize) -> std::net::SocketAddr {
    cfg.addr_for(i)
}
