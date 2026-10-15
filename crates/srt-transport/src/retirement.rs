use srt_proto::{ConnectionRetirement, GroupRetirement, SrtConnection, SrtGroup};
use std::collections::VecDeque;

enum RetiringProtocol {
    Direct(Box<ConnectionRetirement>),
    Group(Box<GroupRetirement>),
}

struct Job {
    protocol: RetiringProtocol,
    established: usize,
    half_open: usize,
    window_bytes: u64,
}

/// Storage remains charged to the originating table until physical reclamation
/// completes. Admission counts include these jobs, so churn cannot grow this
/// queue past the table's existing finite session/peer capacity.
pub(crate) struct RetiredProtocols {
    jobs: VecDeque<Job>,
    pub(crate) established: usize,
    pub(crate) half_open: usize,
    pub(crate) window_bytes: u64,
}

impl RetiredProtocols {
    pub(crate) fn new(capacity: usize) -> Self {
        Self {
            jobs: VecDeque::with_capacity(capacity),
            established: 0,
            half_open: 0,
            window_bytes: 0,
        }
    }

    pub(crate) fn sessions(&self) -> usize {
        self.jobs.len()
    }

    pub(crate) fn push_direct(
        &mut self,
        connection: SrtConnection,
        established: bool,
        window_bytes: u64,
    ) {
        self.push(
            RetiringProtocol::Direct(Box::new(connection.into_retirement())),
            usize::from(established),
            usize::from(!established),
            window_bytes,
        );
    }

    pub(crate) fn push_group(
        &mut self,
        group: SrtGroup,
        established: usize,
        half_open: usize,
        window_bytes: u64,
    ) {
        self.push(
            RetiringProtocol::Group(Box::new(group.into_retirement())),
            established,
            half_open,
            window_bytes,
        );
    }

    fn push(
        &mut self,
        protocol: RetiringProtocol,
        established: usize,
        half_open: usize,
        window_bytes: u64,
    ) {
        self.established += established;
        self.half_open += half_open;
        self.window_bytes += window_bytes;
        self.jobs.push_back(Job {
            protocol,
            established,
            half_open,
            window_bytes,
        });
    }

    pub(crate) fn reclaim(&mut self, max_actions: usize) -> usize {
        let mut used = 0;
        while used < max_actions {
            let Some(job) = self.jobs.front_mut() else {
                break;
            };
            let (released, complete) = match &mut job.protocol {
                RetiringProtocol::Direct(core) => {
                    let released = core.reclaim(max_actions - used);
                    (released, core.is_complete())
                }
                RetiringProtocol::Group(group) => {
                    let released = group.reclaim(max_actions - used);
                    (released, group.is_complete())
                }
            };
            used += released;
            if complete && used < max_actions {
                let job = self.jobs.pop_front().expect("retired job retained");
                self.established -= job.established;
                self.half_open -= job.half_open;
                self.window_bytes -= job.window_bytes;
                drop(job);
                used += 1;
            }
        }
        used
    }
}
