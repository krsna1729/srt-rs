//! Issue #82 A2 waiter semantics without a live bench campaign.
//!
//! Pins deadline selection, wake-all-due after one park, and the no-spin
//! contract (Immediate wait parks once; a consumed deadline is not re-armed).

use std::net::UdpSocket;
use std::time::{Duration, Instant};

use srt_transport::{HighResWaiter, MonotonicDeadline, PlannedWait, WaitBackend, plan_wait};

fn backends() -> Vec<WaitBackend> {
    let mut out = vec![WaitBackend::AbsoluteTimerFd];
    if HighResWaiter::<u32>::with_backend(WaitBackend::EpollPwait2).is_ok() {
        out.insert(0, WaitBackend::EpollPwait2);
    }
    out
}

fn bind() -> UdpSocket {
    let socket = UdpSocket::bind("127.0.0.1:0").expect("bind");
    socket.set_nonblocking(true).expect("nonblocking");
    socket
}

#[test]
fn deadline_selection_prefers_the_earliest_absolute_instant() {
    let now = MonotonicDeadline::from_nanos(1_000);
    assert_eq!(
        plan_wait(now, Some(MonotonicDeadline::from_nanos(1_000)), None),
        PlannedWait::Immediate
    );
    assert_eq!(
        plan_wait(now, Some(MonotonicDeadline::from_nanos(2_500)), None),
        PlannedWait::Until(MonotonicDeadline::from_nanos(2_500))
    );
    assert_eq!(
        plan_wait(now, None, Some(Duration::from_millis(5))),
        PlannedWait::Idle(Duration::from_millis(5))
    );
}

#[test]
fn wait_returns_every_due_connection_after_one_park() {
    for backend in backends() {
        let mut waiter = HighResWaiter::with_backend(backend).expect("waiter");
        let now = MonotonicDeadline::now();
        waiter.set_deadline(1, now);
        waiter.set_deadline(2, now);
        waiter.set_deadline(3, now.saturating_add(Duration::from_secs(30)));
        let mut due = Vec::new();
        let mut ready = Vec::new();
        let outcome = waiter.wait(&mut due, &mut ready).expect("wait");
        assert_eq!(outcome.backend, backend);
        assert_eq!(outcome.park_count, 1);
        assert!(outcome.planned.is_immediate());
        due.sort_unstable();
        assert_eq!(due, vec![1, 2], "{backend:?} must service every due key");
        assert_eq!(waiter.deadline_len(), 1);
    }
}

#[test]
fn consumed_deadline_is_not_rearmed_so_the_next_wait_does_not_spin() {
    for backend in backends() {
        let mut waiter = HighResWaiter::with_backend(backend).expect("waiter");
        waiter.set_deadline(1, MonotonicDeadline::now());
        let mut due = Vec::new();
        let mut ready = Vec::new();
        let first = waiter.wait(&mut due, &mut ready).expect("first");
        assert_eq!(first.park_count, 1);
        assert_eq!(due, vec![1]);

        // pop_due cleared the heap. A second wait with nothing registered
        // must not park (the scratch A2 busy-spin was a zero deadline that
        // stayed armed while the service block refused to run).
        let second = waiter.wait(&mut due, &mut ready).expect("second");
        assert_eq!(second.park_count, 0);
        assert!(due.is_empty());
        assert!(ready.is_empty());
    }
}

#[test]
fn immediate_waits_do_not_busy_loop_inside_the_waiter() {
    let mut waiter = HighResWaiter::<u32>::new().expect("waiter");
    let mut due = Vec::new();
    let mut ready = Vec::new();
    let start = Instant::now();
    for i in 0..64u32 {
        waiter.set_deadline(i, MonotonicDeadline::now());
        let outcome = waiter.wait(&mut due, &mut ready).expect("immediate");
        assert_eq!(outcome.park_count, 1);
        assert!(outcome.planned.is_immediate());
        assert_eq!(due, vec![i]);
    }
    assert!(
        start.elapsed() < Duration::from_millis(200),
        "Immediate waits must be a single non-blocking poll each"
    );
}

#[test]
fn future_deadline_blocks_without_a_spin_tail() {
    for backend in backends() {
        let mut waiter = HighResWaiter::with_backend(backend).expect("waiter");
        let delay = Duration::from_millis(3);
        waiter.set_deadline(1, MonotonicDeadline::after(delay));
        let mut due = Vec::new();
        let mut ready = Vec::new();
        let start = Instant::now();
        let outcome = waiter.wait(&mut due, &mut ready).expect("timed wait");
        let elapsed = start.elapsed();
        assert_eq!(outcome.park_count, 1);
        assert!(!outcome.planned.is_immediate());
        assert_eq!(due, vec![1]);
        assert!(
            elapsed >= Duration::from_millis(1),
            "{backend:?} returned in {elapsed:?}, expected a real wait"
        );
        assert!(
            elapsed < Duration::from_millis(200),
            "{backend:?} overshot to {elapsed:?}"
        );
    }
}

#[test]
fn socket_readiness_wakes_before_a_distant_deadline() {
    for backend in backends() {
        let mut waiter = HighResWaiter::with_backend(backend).expect("waiter");
        let rx = bind();
        let tx = bind();
        waiter
            .register(11, std::os::fd::AsRawFd::as_raw_fd(&rx))
            .expect("register");
        waiter.set_deadline(11, MonotonicDeadline::after(Duration::from_secs(30)));
        tx.send_to(b"wake", rx.local_addr().expect("rx addr"))
            .expect("send");

        let mut due = Vec::new();
        let mut ready = Vec::new();
        let start = Instant::now();
        let outcome = waiter.wait(&mut due, &mut ready).expect("ready wait");
        assert_eq!(outcome.park_count, 1);
        assert_eq!(
            ready,
            vec![11],
            "{backend:?} should report the ready socket"
        );
        assert!(due.is_empty(), "distant deadline must not be due");
        assert!(start.elapsed() < Duration::from_millis(200));
    }
}

#[test]
fn worker_loop_services_every_due_key_after_one_wake() {
    // A2 shape in miniature: one waiter, staggered deadlines, one wait,
    // service the whole due set. No Route B multi-admit.
    let mut waiter = HighResWaiter::<u32>::new().expect("waiter");
    let now = MonotonicDeadline::now();
    for key in 1..=5 {
        waiter.set_deadline(key, now);
    }
    let mut due = Vec::new();
    let mut ready = Vec::new();
    let outcome = waiter.wait(&mut due, &mut ready).expect("wait");
    assert_eq!(outcome.park_count, 1);
    due.sort_unstable();
    assert_eq!(due, vec![1, 2, 3, 4, 5]);
}
