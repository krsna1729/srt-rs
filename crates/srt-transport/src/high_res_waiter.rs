//! Shared high-resolution transport scheduling waiter (issue #82 route A2).
//!
//! One instance is owned by one worker. Connections are sharded onto that
//! worker; this type does not introduce shared dataplane state and does not
//! accumulate pacing debt (Route B is out of scope).
//!
//! ```text
//! A1  per-connection Tokio tail-spin     — rejected on CPU at N=30
//! A2  one waiter / worker, no spin       — this type
//! B   coarse wake + accumulated debt     — not implemented here
//! ```
//!
//! Wait path, matching the measured A2 challenger:
//!
//! 1. peek the next absolute `CLOCK_MONOTONIC` deadline from a min-heap;
//! 2. block in `epoll_pwait2` (nanosecond timeout) or an absolute `timerfd`;
//! 3. after **one** wake, return every connection that is due, plus ready fds.
//!
//! A deadline that is already due uses a single non-blocking poll (`timeout =
//! 0`). The waiter never busy-waits for time to advance.

use std::collections::{HashMap, HashSet};
use std::hash::Hash;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::time::Duration;

use crate::deadline_heap::DeadlineHeap;

const TIMER_TOKEN: u64 = 0;
const FIRST_CONN_TOKEN: u64 = 1;

/// Absolute `CLOCK_MONOTONIC` instant, in nanoseconds.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct MonotonicDeadline {
    nanos: u64,
}

impl MonotonicDeadline {
    #[must_use]
    pub const fn from_nanos(nanos: u64) -> Self {
        Self { nanos }
    }

    #[must_use]
    pub const fn as_nanos(self) -> u64 {
        self.nanos
    }

    #[must_use]
    pub fn now() -> Self {
        monotonic_now()
    }

    #[must_use]
    pub fn saturating_add(self, duration: Duration) -> Self {
        let extra = duration_to_nanos(duration);
        Self {
            nanos: self.nanos.saturating_add(extra),
        }
    }

    /// Absolute deadline `duration` from the current monotonic clock.
    #[must_use]
    pub fn after(duration: Duration) -> Self {
        Self::now().saturating_add(duration)
    }

    #[must_use]
    pub fn saturating_duration_since(self, earlier: Self) -> Duration {
        Duration::from_nanos(self.nanos.saturating_sub(earlier.nanos))
    }
}

/// How the worker will block for the next scheduling step.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PlannedWait {
    /// Next deadline is due now. One non-blocking poll, then return.
    Immediate,
    /// Block until this absolute instant (or an earlier fd).
    Until(MonotonicDeadline),
    /// No deadline; block up to this idle cap for socket readiness.
    Idle(Duration),
    /// No deadline and no idle cap; block until an fd is ready.
    Infinite,
}

impl PlannedWait {
    /// Relative timeout for `epoll_pwait2`. `None` means an infinite wait.
    #[must_use]
    pub fn timeout_ns(self, now: MonotonicDeadline) -> Option<u64> {
        match self {
            Self::Immediate => Some(0),
            Self::Until(deadline) => Some(deadline.as_nanos().saturating_sub(now.as_nanos())),
            Self::Idle(duration) => Some(duration_to_nanos(duration)),
            Self::Infinite => None,
        }
    }

    #[must_use]
    pub fn is_immediate(self) -> bool {
        matches!(self, Self::Immediate)
    }
}

/// Choose the next wait from the earliest live deadline.
///
/// Due-now maps to [`PlannedWait::Immediate`], never to a spin loop. This is
/// the function the no-spin tests pin; the waiter parks at most once per
/// [`HighResWaiter::wait`] using this plan.
#[must_use]
pub fn plan_wait(
    now: MonotonicDeadline,
    next: Option<MonotonicDeadline>,
    idle: Option<Duration>,
) -> PlannedWait {
    match next {
        Some(deadline) if deadline.as_nanos() <= now.as_nanos() => PlannedWait::Immediate,
        Some(deadline) => PlannedWait::Until(deadline),
        None => idle.map(PlannedWait::Idle).unwrap_or(PlannedWait::Infinite),
    }
}

/// Kernel wait primitive selected at construction.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WaitBackend {
    /// Linux 5.11+ `epoll_pwait2` with a `timespec` timeout.
    EpollPwait2,
    /// Absolute `CLOCK_MONOTONIC` `timerfd` plus `epoll_wait`.
    AbsoluteTimerFd,
}

/// Result of one worker wait. `due` / `ready` are filled by the call.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WaitOutcome {
    pub backend: WaitBackend,
    pub planned: PlannedWait,
    pub due_count: usize,
    pub ready_count: usize,
    /// Always 1: A2 parks once per `wait`, including the Immediate case.
    pub park_count: usize,
}

/// One high-resolution scheduling waiter per transport worker.
pub struct HighResWaiter<K> {
    epoll: OwnedFd,
    timer: Option<OwnedFd>,
    backend: WaitBackend,
    heap: DeadlineHeap<K>,
    by_key: HashMap<K, (RawFd, u64)>,
    by_token: HashMap<u64, K>,
    next_token: u64,
    events: Vec<libc::epoll_event>,
}

impl<K> HighResWaiter<K>
where
    K: Clone + Eq + Hash,
{
    pub fn new() -> io::Result<Self> {
        Self::with_backend(detect_backend()?)
    }

    /// Build a waiter on a specific backend. `EpollPwait2` fails if the
    /// running kernel does not provide `epoll_pwait2`.
    pub fn with_backend(backend: WaitBackend) -> io::Result<Self> {
        if backend == WaitBackend::EpollPwait2 && !epoll_pwait2_available() {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "epoll_pwait2 is not available on this kernel",
            ));
        }
        let epoll = create_epoll()?;
        let timer = if backend == WaitBackend::AbsoluteTimerFd {
            let timer = create_timerfd()?;
            epoll_ctl(
                epoll.as_raw_fd(),
                libc::EPOLL_CTL_ADD,
                timer.as_raw_fd(),
                TIMER_TOKEN,
                libc::EPOLLIN,
            )?;
            Some(timer)
        } else {
            None
        };
        Ok(Self {
            epoll,
            timer,
            backend,
            heap: DeadlineHeap::new(),
            by_key: HashMap::new(),
            by_token: HashMap::new(),
            next_token: FIRST_CONN_TOKEN,
            events: vec![empty_event(); 64],
        })
    }

    #[must_use]
    pub fn backend(&self) -> WaitBackend {
        self.backend
    }

    /// Watch `fd` for readability under `key`. Idempotent for the same fd.
    pub fn register(&mut self, key: K, fd: RawFd) -> io::Result<()> {
        if let Some(&(old_fd, token)) = self.by_key.get(&key) {
            if old_fd == fd {
                return Ok(());
            }
            epoll_ctl(
                self.epoll.as_raw_fd(),
                libc::EPOLL_CTL_DEL,
                old_fd,
                token,
                0,
            )?;
            epoll_ctl(
                self.epoll.as_raw_fd(),
                libc::EPOLL_CTL_ADD,
                fd,
                token,
                libc::EPOLLIN,
            )?;
            self.by_key.insert(key, (fd, token));
            return Ok(());
        }
        let token = self.next_token;
        self.next_token = self.next_token.saturating_add(1);
        epoll_ctl(
            self.epoll.as_raw_fd(),
            libc::EPOLL_CTL_ADD,
            fd,
            token,
            libc::EPOLLIN,
        )?;
        self.by_token.insert(token, key.clone());
        self.by_key.insert(key, (fd, token));
        Ok(())
    }

    pub fn deregister(&mut self, key: &K) -> io::Result<()> {
        self.heap.remove(key);
        let Some((fd, token)) = self.by_key.remove(key) else {
            return Ok(());
        };
        self.by_token.remove(&token);
        epoll_ctl(self.epoll.as_raw_fd(), libc::EPOLL_CTL_DEL, fd, token, 0)
    }

    pub fn set_deadline(&mut self, key: K, deadline: MonotonicDeadline) {
        self.heap.set(key, deadline);
    }

    pub fn clear_deadline(&mut self, key: &K) {
        self.heap.remove(key);
    }

    #[must_use]
    pub fn next_deadline(&mut self) -> Option<MonotonicDeadline> {
        self.heap.peek_min()
    }

    #[must_use]
    pub fn deadline_len(&self) -> usize {
        self.heap.len()
    }

    /// Park once, then fill `due` (every expired deadline) and `ready` fds.
    pub fn wait(&mut self, due: &mut Vec<K>, ready: &mut Vec<K>) -> io::Result<WaitOutcome> {
        self.wait_with_idle(None, due, ready)
    }

    /// Like [`Self::wait`], but cap an idle (no-deadline) wait.
    pub fn wait_with_idle(
        &mut self,
        idle: Option<Duration>,
        due: &mut Vec<K>,
        ready: &mut Vec<K>,
    ) -> io::Result<WaitOutcome> {
        due.clear();
        ready.clear();
        if self.by_key.is_empty() && self.heap.is_empty() {
            return Ok(WaitOutcome {
                backend: self.backend,
                planned: PlannedWait::Immediate,
                due_count: 0,
                ready_count: 0,
                park_count: 0,
            });
        }
        let now = MonotonicDeadline::now();
        let planned = plan_wait(now, self.heap.peek_min(), idle);
        let n_events = self.park(planned)?;
        collect_ready(&self.events[..n_events], &self.by_token, ready);
        if let Some(timer) = self.timer.as_ref() {
            drain_timerfd(timer.as_raw_fd());
        }
        self.heap.pop_due(MonotonicDeadline::now(), due);
        Ok(WaitOutcome {
            backend: self.backend,
            planned,
            due_count: due.len(),
            ready_count: ready.len(),
            park_count: 1,
        })
    }

    fn park(&mut self, planned: PlannedWait) -> io::Result<usize> {
        match self.backend {
            WaitBackend::EpollPwait2 => {
                park_pwait2(self.epoll.as_raw_fd(), &mut self.events, planned)
            }
            WaitBackend::AbsoluteTimerFd => {
                let timer = self
                    .timer
                    .as_ref()
                    .expect("timerfd backend always owns a timer");
                arm_timerfd(timer.as_raw_fd(), planned)?;
                park_epoll_wait(self.epoll.as_raw_fd(), &mut self.events, planned)
            }
        }
    }
}

/// Plan a wait from a relative delay against `now`.
#[must_use]
pub fn deadline_from_wait(now: MonotonicDeadline, wait: Duration) -> MonotonicDeadline {
    now.saturating_add(wait)
}

fn duration_to_nanos(duration: Duration) -> u64 {
    u64::try_from(duration.as_nanos()).unwrap_or(u64::MAX)
}

fn monotonic_now() -> MonotonicDeadline {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: `ts` is a valid timespec; CLOCK_MONOTONIC is a live clock.
    let rc = unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) };
    if rc != 0 {
        return MonotonicDeadline::from_nanos(0);
    }
    MonotonicDeadline::from_nanos(timespec_to_nanos(&ts))
}

fn timespec_to_nanos(ts: &libc::timespec) -> u64 {
    let sec = u64::try_from(ts.tv_sec).unwrap_or(0);
    let nsec = u64::try_from(ts.tv_nsec).unwrap_or(0);
    sec.saturating_mul(1_000_000_000).saturating_add(nsec)
}

fn nanos_to_timespec(nanos: u64) -> libc::timespec {
    libc::timespec {
        tv_sec: (nanos / 1_000_000_000) as libc::time_t,
        tv_nsec: (nanos % 1_000_000_000) as libc::c_long,
    }
}

fn planned_timespec(now: MonotonicDeadline, planned: PlannedWait) -> Option<libc::timespec> {
    planned.timeout_ns(now).map(nanos_to_timespec)
}

fn detect_backend() -> io::Result<WaitBackend> {
    if epoll_pwait2_available() {
        Ok(WaitBackend::EpollPwait2)
    } else {
        Ok(WaitBackend::AbsoluteTimerFd)
    }
}

fn epoll_pwait2_available() -> bool {
    let Ok(epoll) = create_epoll() else {
        return false;
    };
    let mut event = empty_event();
    let timeout = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: `epoll` is a live epoll fd; `event` is writable storage for one
    // event; `timeout` is a valid timespec. A zero max-wait probe is enough
    // to distinguish ENOSYS from a supported syscall.
    let rc =
        unsafe { libc::epoll_pwait2(epoll.as_raw_fd(), &mut event, 1, &timeout, std::ptr::null()) };
    rc >= 0 || io::Error::last_os_error().raw_os_error() != Some(libc::ENOSYS)
}

fn create_epoll() -> io::Result<OwnedFd> {
    // SAFETY: EPOLL_CLOEXEC is a valid flag; a negative rc is an OS error.
    let fd = unsafe { libc::epoll_create1(libc::EPOLL_CLOEXEC) };
    owned_fd(fd)
}

fn create_timerfd() -> io::Result<OwnedFd> {
    // SAFETY: CLOCK_MONOTONIC + CLOEXEC/NONBLOCK are valid timerfd flags.
    let fd = unsafe {
        libc::timerfd_create(
            libc::CLOCK_MONOTONIC,
            libc::TFD_CLOEXEC | libc::TFD_NONBLOCK,
        )
    };
    owned_fd(fd)
}

fn owned_fd(fd: RawFd) -> io::Result<OwnedFd> {
    if fd < 0 {
        Err(io::Error::last_os_error())
    } else {
        // SAFETY: `fd` is a freshly created owned descriptor.
        Ok(unsafe { OwnedFd::from_raw_fd(fd) })
    }
}

fn empty_event() -> libc::epoll_event {
    libc::epoll_event { events: 0, u64: 0 }
}

fn epoll_ctl(epfd: RawFd, op: libc::c_int, fd: RawFd, token: u64, events: i32) -> io::Result<()> {
    let mut event = libc::epoll_event {
        events: events as u32,
        u64: token,
    };
    // SAFETY: `epfd` is this waiter's epoll; `fd` is caller-owned and live for
    // ADD/MOD. DEL ignores `event` contents. The kernel does not retain the
    // pointer after return.
    let rc = unsafe { libc::epoll_ctl(epfd, op, fd, &mut event) };
    if rc == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

fn park_pwait2(
    epfd: RawFd,
    events: &mut [libc::epoll_event],
    planned: PlannedWait,
) -> io::Result<usize> {
    let now = MonotonicDeadline::now();
    let timeout = planned_timespec(now, planned);
    let timeout_ptr = timeout
        .as_ref()
        .map_or(std::ptr::null(), std::ptr::from_ref);
    epoll_loop(|| {
        // SAFETY: `epfd` is a live epoll; `events` is writable for `len`
        // entries; `timeout_ptr` is either null (infinite) or a valid timespec
        // that outlives the call.
        unsafe {
            libc::epoll_pwait2(
                epfd,
                events.as_mut_ptr(),
                events.len() as libc::c_int,
                timeout_ptr,
                std::ptr::null(),
            )
        }
    })
}

fn park_epoll_wait(
    epfd: RawFd,
    events: &mut [libc::epoll_event],
    planned: PlannedWait,
) -> io::Result<usize> {
    // Absolute timerfd is the high-res wake source. Immediate is a single
    // non-blocking poll; every other plan blocks until timerfd or a socket.
    let timeout_ms = if planned.is_immediate() { 0 } else { -1 };
    epoll_loop(|| {
        // SAFETY: `epfd` is a live epoll; `events` is writable for `len` entries.
        unsafe {
            libc::epoll_wait(
                epfd,
                events.as_mut_ptr(),
                events.len() as libc::c_int,
                timeout_ms,
            )
        }
    })
}

fn epoll_loop(mut syscall: impl FnMut() -> libc::c_int) -> io::Result<usize> {
    loop {
        let rc = syscall();
        if rc >= 0 {
            return Ok(rc as usize);
        }
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::Interrupted {
            return Err(error);
        }
    }
}

fn arm_timerfd(fd: RawFd, planned: PlannedWait) -> io::Result<()> {
    let it_value = match planned {
        PlannedWait::Immediate => libc::timespec {
            tv_sec: 0,
            tv_nsec: 1,
        },
        PlannedWait::Until(deadline) => nanos_to_timespec(deadline.as_nanos().max(1)),
        PlannedWait::Idle(duration) => {
            let now = MonotonicDeadline::now();
            nanos_to_timespec(now.saturating_add(duration).as_nanos().max(1))
        }
        PlannedWait::Infinite => libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        },
    };
    let spec = libc::itimerspec {
        it_interval: libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        },
        it_value,
    };
    let flags = match planned {
        PlannedWait::Immediate | PlannedWait::Infinite => 0,
        PlannedWait::Until(_) | PlannedWait::Idle(_) => libc::TFD_TIMER_ABSTIME,
    };
    // SAFETY: `fd` is this waiter's timerfd; `spec` is a valid itimerspec.
    let rc = unsafe { libc::timerfd_settime(fd, flags, &spec, std::ptr::null_mut()) };
    if rc == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

fn drain_timerfd(fd: RawFd) {
    let mut buf = [0u8; 8];
    // SAFETY: `fd` is a live timerfd; `buf` is 8 bytes, the kernel's expiry
    // counter width. EAGAIN means it was not the wake source.
    let _ = unsafe { libc::read(fd, buf.as_mut_ptr().cast(), buf.len()) };
}

fn collect_ready<K: Clone + Eq + Hash>(
    events: &[libc::epoll_event],
    by_token: &HashMap<u64, K>,
    ready: &mut Vec<K>,
) {
    let mut seen = HashSet::<K>::new();
    for event in events {
        let token = event.u64;
        if token == TIMER_TOKEN {
            continue;
        }
        if let Some(key) = by_token.get(&token)
            && seen.insert(key.clone())
        {
            ready.push(key.clone());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ns(n: u64) -> MonotonicDeadline {
        MonotonicDeadline::from_nanos(n)
    }

    #[test]
    fn plan_wait_due_now_is_immediate_not_a_spin() {
        assert_eq!(
            plan_wait(ns(100), Some(ns(100)), None),
            PlannedWait::Immediate
        );
        assert_eq!(
            plan_wait(ns(150), Some(ns(100)), None),
            PlannedWait::Immediate
        );
        assert_eq!(
            plan_wait(ns(100), Some(ns(100)), None).timeout_ns(ns(100)),
            Some(0)
        );
    }

    #[test]
    fn plan_wait_future_uses_remaining_nanos() {
        let planned = plan_wait(ns(100), Some(ns(1_000_100)), None);
        assert_eq!(planned, PlannedWait::Until(ns(1_000_100)));
        assert_eq!(planned.timeout_ns(ns(100)), Some(1_000_000));
    }

    #[test]
    fn plan_wait_idle_and_infinite() {
        assert_eq!(
            plan_wait(ns(0), None, Some(Duration::from_millis(20))),
            PlannedWait::Idle(Duration::from_millis(20))
        );
        assert_eq!(plan_wait(ns(0), None, None), PlannedWait::Infinite);
        assert_eq!(PlannedWait::Infinite.timeout_ns(ns(0)), None);
    }

    #[test]
    fn empty_waiter_does_not_park() {
        let mut waiter = HighResWaiter::<u32>::new().expect("waiter");
        let mut due = Vec::new();
        let mut ready = Vec::new();
        let outcome = waiter.wait(&mut due, &mut ready).expect("empty wait");
        assert_eq!(outcome.park_count, 0);
        assert!(due.is_empty());
        assert!(ready.is_empty());
    }
}
