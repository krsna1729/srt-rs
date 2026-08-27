use crate::{
    ManualTimerStore, OutputDrainBudget, OutputDrainReport, OutputDrainStatus, collect_output_work,
    prepend_outputs,
};
use libc;
use shiguredo_srt::{ConnectionOutput, SrtConnection, Timestamp};
use std::collections::VecDeque;
use std::io;
use std::time::Duration;

/// Per-connection state for mio: protocol + owned socket + manual timers.
pub struct Conn {
    pub conn: SrtConnection,
    pub socket: mio::net::UdpSocket,
    pub timers: ManualTimerStore,
    pending_outputs: VecDeque<ConnectionOutput>,
}

impl Conn {
    pub fn new(conn: SrtConnection, socket: mio::net::UdpSocket) -> Self {
        Self {
            conn,
            socket,
            timers: ManualTimerStore::new(),
            pending_outputs: VecDeque::new(),
        }
    }

    /// Fire expired manual timers.
    pub fn fire_expired(&mut self, now: Timestamp) {
        self.timers.fire_expired(now, &mut self.conn);
    }

    /// Compatibility wrapper using [`OutputDrainBudget::default`].
    /// Returns true only for `ECONNREFUSED`; transient failures remain
    /// queued for the next tick.
    pub fn drain_outputs(&mut self, now: Timestamp) -> bool {
        self.drain_outputs_bounded(now, OutputDrainBudget::default())
            .is_err_and(|error| error.kind() == io::ErrorKind::ConnectionRefused)
    }

    /// Drain a bounded amount of output, retaining every unsent datagram
    /// in protocol order on `WouldBlock`, partial `sendmmsg`, or error.
    pub fn drain_outputs_bounded(
        &mut self,
        now: Timestamp,
        budget: OutputDrainBudget,
    ) -> io::Result<OutputDrainReport> {
        drain_outputs_with(
            &mut self.conn,
            &mut self.timers,
            &mut self.pending_outputs,
            now,
            budget,
            |batch| Self::send_batch(&self.socket, batch),
        )
    }

    #[must_use]
    pub fn has_pending_outputs(&self) -> bool {
        !self.pending_outputs.is_empty()
    }

    /// mmsghdr/iovec scratch, reused across calls on this thread
    /// (hot path: `drain_outputs` runs every event-loop tick per
    /// connection). Capacity stabilizes at the batch cap (32) after
    /// the first few calls, giving zero-allocation steady state --
    /// mirrors `recvmsg_batch`'s scratch in srt-bench.
    fn send_batch(socket: &mio::net::UdpSocket, batch: &[Vec<u8>]) -> io::Result<usize> {
        use std::cell::RefCell;
        thread_local! {
            static SCRATCH: RefCell<(Vec<libc::mmsghdr>, Vec<libc::iovec>)> =
                const { RefCell::new((Vec::new(), Vec::new())) };
        }
        if batch.is_empty() {
            return Ok(0);
        }
        SCRATCH.with(|scratch| {
            let (msgs, iovs) = &mut *scratch.borrow_mut();
            msgs.clear();
            iovs.clear();
            for buf in batch.iter() {
                iovs.push(libc::iovec {
                    iov_base: buf.as_ptr() as *mut _,
                    iov_len: buf.len(),
                });
                msgs.push(libc::mmsghdr {
                    // SAFETY: all-zero is a valid empty `msghdr`; the
                    // iovec pointer and count are assigned below.
                    msg_hdr: unsafe { std::mem::zeroed() },
                    msg_len: 0,
                });
            }
            for (msg, iov) in msgs.iter_mut().zip(iovs.iter()) {
                msg.msg_hdr.msg_iov = iov as *const _ as *mut _;
                msg.msg_hdr.msg_iovlen = 1;
            }
            let fd = {
                use std::os::fd::AsRawFd;
                socket.as_raw_fd()
            };
            let count = u32::try_from(batch.len()).map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidInput, "send batch exceeds u32")
            })?;
            // SAFETY: `msgs` and `iovs` have exactly `batch.len()` live
            // elements. Each iovec points into an immutable packet Vec
            // that outlives this synchronous syscall; pointers are set
            // only after both scratch vectors finish growing.
            let sent = unsafe { libc::sendmmsg(fd, msgs.as_mut_ptr(), count, libc::MSG_DONTWAIT) };
            if sent < 0 {
                Err(io::Error::last_os_error())
            } else {
                Ok(sent as usize)
            }
        })
    }

    /// Compute poll timeout from next timer deadline.
    pub fn poll_timeout(&self, default: Duration, now: Timestamp) -> Duration {
        Duration::from_micros(
            self.timers
                .time_until_earliest(now, default.as_micros() as u64),
        )
    }
}

/// Resolve, bind, and convert a complete listener configuration to mio
/// sockets. Applications retain the prepared policy and may drive their
/// own poll/worker architecture around it.
pub fn bind_listener(
    config: &crate::ListenerConfig,
) -> Result<crate::RuntimeListener<mio::net::UdpSocket>, crate::RuntimeBuildError> {
    let prepared = config.prepare(crate::RuntimeFlavor::Mio)?;
    let sockets = prepared
        .bind_sockets()?
        .into_iter()
        .map(mio::net::UdpSocket::from_std)
        .collect();
    Ok(crate::RuntimeListener { prepared, sockets })
}

/// Build one configured caller connection and connected mio socket.
pub fn caller(
    config: &crate::CallerConfig,
    now: Timestamp,
) -> Result<Conn, crate::RuntimeBuildError> {
    let prepared = config.prepare(crate::RuntimeFlavor::Mio)?;
    let socket = mio::net::UdpSocket::from_std(prepared.bind_socket()?);
    Ok(Conn::new(prepared.connection(now)?, socket))
}

fn drain_outputs_with<F>(
    conn: &mut SrtConnection,
    timers: &mut ManualTimerStore,
    pending: &mut VecDeque<ConnectionOutput>,
    now: Timestamp,
    budget: OutputDrainBudget,
    mut send_batch: F,
) -> io::Result<OutputDrainReport>
where
    F: FnMut(&[Vec<u8>]) -> io::Result<usize>,
{
    let (mut work, budget_exhausted) = collect_output_work(conn, pending, budget);
    let mut report = OutputDrainReport {
        status: if budget_exhausted {
            OutputDrainStatus::BudgetExhausted
        } else {
            OutputDrainStatus::Drained
        },
        ..OutputDrainReport::default()
    };

    while let Some(output) = work.pop_front() {
        match output {
            ConnectionOutput::SendPacket(packet) => {
                let mut batch = vec![packet];
                while matches!(work.front(), Some(ConnectionOutput::SendPacket(_))) {
                    let Some(ConnectionOutput::SendPacket(packet)) = work.pop_front() else {
                        unreachable!();
                    };
                    batch.push(packet);
                }

                match send_batch(&batch) {
                    Ok(sent) if sent <= batch.len() => {
                        report.actions += sent;
                        report.packets += sent;
                        report.bytes += batch[..sent].iter().map(Vec::len).sum::<usize>();
                        if sent < batch.len() {
                            prepend_outputs(pending, work.into_iter());
                            prepend_outputs(
                                pending,
                                batch
                                    .into_iter()
                                    .skip(sent)
                                    .map(ConnectionOutput::SendPacket),
                            );
                            report.status = OutputDrainStatus::Backpressured;
                            return Ok(report);
                        }
                    }
                    Ok(_) => {
                        prepend_outputs(pending, work.into_iter());
                        prepend_outputs(
                            pending,
                            batch.into_iter().map(ConnectionOutput::SendPacket),
                        );
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "sendmmsg reported more datagrams than supplied",
                        ));
                    }
                    Err(error) => {
                        prepend_outputs(pending, work.into_iter());
                        prepend_outputs(
                            pending,
                            batch.into_iter().map(ConnectionOutput::SendPacket),
                        );
                        if error.kind() == io::ErrorKind::WouldBlock {
                            report.status = OutputDrainStatus::Backpressured;
                            return Ok(report);
                        }
                        return Err(error);
                    }
                }
            }
            timer => {
                timers.apply_output(&timer, now);
                report.actions += 1;
            }
        }
    }

    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::drain_outputs_with;
    use crate::*;
    use shiguredo_srt::{ConnectionOptions, ConnectionOutput, Timestamp};
    use std::collections::VecDeque;
    use std::io;

    fn caller_with_output() -> SrtConnection {
        let mut conn = SrtConnection::new_caller(ConnectionOptions::default());
        conn.connect(Timestamp::from_micros(0))
            .expect("connect starts");
        conn
    }

    #[test]
    fn would_block_retains_packet_and_following_timer() {
        let mut conn = caller_with_output();
        let mut timers = ManualTimerStore::new();
        let mut pending = VecDeque::new();
        let mut attempts = 0;
        let report = drain_outputs_with(
            &mut conn,
            &mut timers,
            &mut pending,
            Timestamp::from_micros(0),
            OutputDrainBudget::default(),
            |_| {
                attempts += 1;
                Err(io::Error::from(io::ErrorKind::WouldBlock))
            },
        )
        .expect("WouldBlock is a yield, not packet loss");
        assert_eq!(report.status, OutputDrainStatus::Backpressured);
        assert_eq!(attempts, 1);
        assert_eq!(pending.len(), 2);

        let report = drain_outputs_with(
            &mut conn,
            &mut timers,
            &mut pending,
            Timestamp::from_micros(1),
            OutputDrainBudget::default(),
            |batch| Ok(batch.len()),
        )
        .expect("retry succeeds");
        assert_eq!(report.status, OutputDrainStatus::Drained);
        assert_eq!(report.packets, 1);
        assert!(pending.is_empty());
        assert_ne!(timers.time_until_earliest(Timestamp::from_micros(1), 0), 0);
    }

    #[test]
    fn partial_send_retains_unsent_tail_in_order() {
        let mut conn = SrtConnection::new_caller(ConnectionOptions::default());
        let mut timers = ManualTimerStore::new();
        let mut pending = VecDeque::from([
            ConnectionOutput::SendPacket(vec![1]),
            ConnectionOutput::SendPacket(vec![2]),
            ConnectionOutput::SendPacket(vec![3]),
        ]);
        let report = drain_outputs_with(
            &mut conn,
            &mut timers,
            &mut pending,
            Timestamp::default(),
            OutputDrainBudget::default(),
            |_| Ok(1),
        )
        .expect("partial send yields");
        assert_eq!(report.packets, 1);
        assert_eq!(report.status, OutputDrainStatus::Backpressured);
        assert_eq!(
            pending.into_iter().collect::<Vec<_>>(),
            vec![
                ConnectionOutput::SendPacket(vec![2]),
                ConnectionOutput::SendPacket(vec![3]),
            ]
        );
    }

    #[test]
    fn packet_and_byte_budget_yields_with_tail_queued() {
        let mut conn = SrtConnection::new_caller(ConnectionOptions::default());
        let mut timers = ManualTimerStore::new();
        let mut pending = VecDeque::from([
            ConnectionOutput::SendPacket(vec![1, 1]),
            ConnectionOutput::SendPacket(vec![2, 2]),
        ]);
        let report = drain_outputs_with(
            &mut conn,
            &mut timers,
            &mut pending,
            Timestamp::default(),
            OutputDrainBudget::new(8, 8, 2),
            |batch| Ok(batch.len()),
        )
        .expect("bounded send succeeds");

        assert_eq!(report.status, OutputDrainStatus::BudgetExhausted);
        assert_eq!(report.packets, 1);
        assert_eq!(report.bytes, 2);
        assert_eq!(
            pending,
            VecDeque::from([ConnectionOutput::SendPacket(vec![2, 2])])
        );
    }
}
