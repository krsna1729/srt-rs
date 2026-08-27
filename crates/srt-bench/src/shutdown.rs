//! Cooperative shutdown, so a run ends in a defined order.
//!
//! The listener used to stop on a fixed `secs + 5` timer while the sender
//! ran to its own deadline. Under overload the sender routinely outlives
//! that budget, and then it is transmitting into a closed port: the run's
//! last seconds are measured against a listener that is already gone, and
//! the kernel books the difference as `NoPorts` rather than as anything
//! the protocol did. A prior run ended that way, and a live watcher saw a
//! large burst of `no-ports` errors.
//!
//! So the harness now decides when the listener stops: it waits for the
//! sender to finish, then signals. The timer stays as a backstop for a
//! signal that never arrives, but it is no longer the normal path.
//!
//! `SIGTERM` rather than a control socket or a pipe: the harness already
//! owns the child process, every runtime here is a different I/O model,
//! and a flag set from a signal handler needs no I/O at all -- which is
//! also what makes it safe to set from one.

use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Instant;

static REQUESTED: AtomicBool = AtomicBool::new(false);

extern "C" fn on_signal(_: libc::c_int) {
    // The only async-signal-safe thing here, and all that is needed:
    // every loop polls this between iterations.
    REQUESTED.store(true, Ordering::Relaxed);
}

/// Ask for a clean stop when the harness signals. Idempotent.
pub fn install() {
    // SAFETY: zeroed sigaction is valid; handler is an extern "C" fn with correct signature.
    unsafe {
        let mut action: libc::sigaction = std::mem::zeroed();
        action.sa_sigaction = on_signal as extern "C" fn(libc::c_int) as usize;
        action.sa_flags = 0;
        libc::sigemptyset(&raw mut action.sa_mask);
        libc::sigaction(libc::SIGTERM, &raw const action, std::ptr::null_mut());
        libc::sigaction(libc::SIGINT, &raw const action, std::ptr::null_mut());
    }
}

/// Has a clean stop been requested?
#[must_use]
pub fn requested() -> bool {
    REQUESTED.load(Ordering::Relaxed)
}

/// Should a loop holding this deadline stop now?
///
/// A requested shutdown ends the loop whether or not it ever got a
/// deadline -- a connection still mid-handshake when the run is over has
/// nothing left to wait for.
#[must_use]
pub fn past(deadline: Option<Instant>) -> bool {
    requested() || deadline.is_some_and(|d| Instant::now() >= d)
}
