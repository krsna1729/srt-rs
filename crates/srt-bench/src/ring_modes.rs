//! The io_uring setup combinations under test, in one place.
//!
//! Both floor benches drive the same flag matrix -- the UDP datagram path
//! (`udp_datapath_floor`) and the TCP stream path (`rtmp_publish_floor`). They
//! are separate binaries, and a second copy of this table would be a second
//! thing to keep in sync, so the set lives here and both benches read it.
//!
//! The names are the flag sets, not guesses about which is best: the kernel
//! rejects some combinations (`DEFER_TASKRUN` requires `SINGLE_ISSUER`;
//! `SQPOLL` is rejected with `DEFER_TASKRUN`), and a rejection is reported
//! rather than silently skipped.
//!
//! `single_issuer` is included even though the production transport already
//! sets it, so its cost is on the record next to the alternatives.

use std::time::Duration;

/// How one ring combination is applied to a Compio proactor.
pub type ApplyRing = fn(&mut compio::driver::ProactorBuilder);

/// `(name, apply)` for every combination measured here.
pub fn modes() -> Vec<(&'static str, ApplyRing)> {
    fn none(_: &mut compio::driver::ProactorBuilder) {}
    fn coop(p: &mut compio::driver::ProactorBuilder) {
        p.coop_taskrun(true);
    }
    fn coop_flag(p: &mut compio::driver::ProactorBuilder) {
        p.coop_taskrun(true);
        p.taskrun_flag(true);
    }
    fn single(p: &mut compio::driver::ProactorBuilder) {
        p.single_issuer(true);
    }
    fn single_defer(p: &mut compio::driver::ProactorBuilder) {
        p.single_issuer(true);
        p.defer_taskrun(true);
        p.taskrun_flag(true);
    }
    fn sqpoll(p: &mut compio::driver::ProactorBuilder) {
        p.sqpoll_idle(Duration::from_millis(1));
    }
    /// `SQPOLL` plus `DEFER_TASKRUN`, with `SINGLE_ISSUER` set because the
    /// kernel requires it for `DEFER_TASKRUN`. The first version of this arm
    /// omitted `SINGLE_ISSUER`, so its `EINVAL` was explained by the missing
    /// required flag and said nothing about whether the two features are
    /// compatible -- a real conclusion drawn from an invalid construction.
    fn sqpoll_defer(p: &mut compio::driver::ProactorBuilder) {
        p.sqpoll_idle(Duration::from_millis(1));
        p.single_issuer(true);
        p.defer_taskrun(true);
        p.taskrun_flag(true);
    }
    fn coop_defer(p: &mut compio::driver::ProactorBuilder) {
        p.coop_taskrun(true);
        p.single_issuer(true);
        p.defer_taskrun(true);
        p.taskrun_flag(true);
    }
    vec![
        ("none", none as ApplyRing),
        ("coop_taskrun", coop),
        ("coop_taskrun+taskrun_flag", coop_flag),
        ("single_issuer", single),
        ("single_issuer+defer_taskrun", single_defer),
        ("sqpoll_1ms", sqpoll),
        ("sqpoll_1ms+defer_taskrun", sqpoll_defer),
        ("coop+single_issuer+defer_taskrun", coop_defer),
    ]
}

/// Apply one named mode, erroring on an unknown name.
pub fn apply_named(
    name: &str,
    proactor: &mut compio::driver::ProactorBuilder,
) -> Result<(), String> {
    let (_, apply) = modes()
        .into_iter()
        .find(|(n, _)| *n == name)
        .ok_or_else(|| {
            format!(
                "unknown ring mode {name:?}; known: {}",
                modes()
                    .iter()
                    .map(|(n, _)| *n)
                    .collect::<Vec<_>>()
                    .join(", ")
            )
        })?;
    apply(proactor);
    Ok(())
}

/// A Compio runtime with the named ring mode applied, forcing io_uring.
pub fn runtime(mode: &str) -> Result<compio::runtime::Runtime, String> {
    let mut proactor = compio::driver::ProactorBuilder::new();
    proactor.driver_type(compio::driver::DriverType::IoUring);
    apply_named(mode, &mut proactor)?;
    let mut builder = compio::runtime::RuntimeBuilder::new();
    builder.with_proactor(proactor);
    builder.build().map_err(|e| format!("runtime: {e}"))
}
