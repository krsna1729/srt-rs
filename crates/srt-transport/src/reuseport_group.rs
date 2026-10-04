//! Membership of one `SO_REUSEPORT` listener group, shared by its Owners.
//!
//! Linux spreads a reuseport group's datagrams by hashing each 4-tuple over
//! the *current* member count, so any change to that count moves flows that
//! are already established to other members
//! (`tests/reuseport_rehash.rs::binding_a_new_member_reroutes_existing_flows`).
//! A member that receives another member's established session has no state
//! for it: the session's data is dropped there. A group is therefore only
//! correct when its size is fixed for as long as sessions exist. This module
//! enforces the part of that the transport controls:
//!
//! * **Barrier.** No member admits a datagram until all `count` members are
//!   bound, so no session exists while the group is still growing.
//! * **One claim per member.** Attaching the same member twice would bind a
//!   `count + 1`th socket; it is refused before the bind.
//! * **One layout per address.** A second layout on an address with a live
//!   layout would join the same kernel group; refused before the bind.
//! * **Sealed after start.** Once every member was bound, a member that left
//!   cannot rejoin: rejoining grows the group under live sessions. Rebuild
//!   the whole layout with a fresh `owner_plans` instead.
//!
//! A member leaving (an Owner stopping) still shrinks the kernel group; the
//! transport cannot prevent that, which is why `owner-contract.md` requires
//! the application to stop every member of a layout together.

use std::collections::HashMap;
use std::net::SocketAddr;

// The membership protocol is the atomics; loom explores those. Ownership
// (Arc) and the per-address registry stay std in both builds.
#[cfg(loom)]
use loom::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
#[cfg(not(loom))]
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, Weak};

use crate::{ConfigError, RuntimeBuildError};

/// Shared state of one reuseport layout.
pub(crate) struct ReusePortGroup {
    bind: SocketAddr,
    claimed: Box<[AtomicBool]>,
    /// Members currently bound.
    bound: AtomicUsize,
    /// Set once every member was bound at the same time; never cleared.
    started: AtomicBool,
}

impl std::fmt::Debug for ReusePortGroup {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ReusePortGroup")
            .field("bind", &self.bind)
            .field("count", &self.claimed.len())
            .field("bound", &self.bound.load(Ordering::Relaxed))
            .finish()
    }
}

/// Process-wide live layouts by bind address.
fn registry() -> &'static Mutex<HashMap<SocketAddr, Weak<ReusePortGroup>>> {
    static REGISTRY: std::sync::OnceLock<Mutex<HashMap<SocketAddr, Weak<ReusePortGroup>>>> =
        std::sync::OnceLock::new();
    REGISTRY.get_or_init(|| Mutex::new(HashMap::new()))
}

fn refuse(reason: &str) -> RuntimeBuildError {
    RuntimeBuildError::from(ConfigError::new("listener.reuse_port_member", reason))
}

impl ReusePortGroup {
    pub(crate) fn new(bind: SocketAddr, count: usize) -> Arc<Self> {
        Arc::new(Self {
            bind,
            claimed: (0..count).map(|_| AtomicBool::new(false)).collect(),
            bound: AtomicUsize::new(0),
            started: AtomicBool::new(false),
        })
    }

    /// Every member is bound: the kernel group has its final size.
    pub(crate) fn is_complete(&self) -> bool {
        self.bound.load(Ordering::Acquire) == self.claimed.len()
    }

    /// Reserve member `index` before its socket is bound.
    pub(crate) fn claim(self: &Arc<Self>, index: usize) -> Result<MemberClaim, RuntimeBuildError> {
        if self.started.load(Ordering::Acquire) {
            return Err(refuse(
                "this reuseport layout already ran; a member rejoining would rehash live \
                 sessions to other members; rebuild every member with a fresh owner_plans",
            ));
        }
        self.register()?;
        let slot = self
            .claimed
            .get(index)
            .ok_or_else(|| refuse("member index outside its layout"))?;
        if slot.swap(true, Ordering::AcqRel) {
            return Err(refuse(
                "member already attached; a second socket would grow the reuseport group",
            ));
        }
        Ok(MemberClaim {
            group: Arc::clone(self),
            index,
            bound: false,
        })
    }

    /// Record this layout as the live one on its address, refusing a second.
    fn register(self: &Arc<Self>) -> Result<(), RuntimeBuildError> {
        if self.bind.port() == 0 {
            // The kernel picks a distinct port per socket; no shared group.
            return Ok(());
        }
        let mut live = registry()
            .lock()
            .map_err(|_| refuse("reuseport layout registry poisoned"))?;
        match live.get(&self.bind).and_then(Weak::upgrade) {
            Some(existing) if !Arc::ptr_eq(&existing, self) => Err(refuse(
                "another reuseport layout is live on this address; its group would grow",
            )),
            Some(_) => Ok(()),
            None => {
                live.insert(self.bind, Arc::downgrade(self));
                Ok(())
            }
        }
    }
}

/// One member's reservation, held by its listener for the listener's life.
/// Dropping it releases the member.
#[derive(Debug)]
pub(crate) struct MemberClaim {
    group: Arc<ReusePortGroup>,
    index: usize,
    bound: bool,
}

impl MemberClaim {
    /// The member's socket is bound; once every member is, the layout starts.
    pub(crate) fn mark_bound(&mut self) {
        if self.bound {
            return;
        }
        self.bound = true;
        let now = self.group.bound.fetch_add(1, Ordering::AcqRel) + 1;
        if now == self.group.claimed.len() {
            self.group.started.store(true, Ordering::Release);
        }
    }

    pub(crate) fn group(&self) -> &Arc<ReusePortGroup> {
        &self.group
    }
}

impl Drop for MemberClaim {
    fn drop(&mut self) {
        if self.bound {
            self.group.bound.fetch_sub(1, Ordering::AcqRel);
        }
        self.group.claimed[self.index].store(false, Ordering::Release);
    }
}

#[cfg(all(test, not(loom)))]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn addr(port: u16) -> SocketAddr {
        SocketAddr::from(([127, 0, 0, 1], port))
    }

    #[test]
    fn group_completes_only_when_every_member_is_bound() {
        let group = ReusePortGroup::new(addr(41_001), 2);
        let mut first = group.claim(0).unwrap();
        first.mark_bound();
        assert!(!group.is_complete());
        let mut second = group.claim(1).unwrap();
        assert!(!group.is_complete(), "claimed but not yet bound");
        second.mark_bound();
        assert!(group.is_complete());
    }

    #[test]
    fn a_member_cannot_be_attached_twice() {
        let group = ReusePortGroup::new(addr(41_002), 2);
        let _held = group.claim(1).unwrap();
        assert!(group.claim(1).is_err());
        assert!(group.claim(2).is_err(), "index outside the layout");
    }

    #[test]
    fn a_released_member_rejoins_only_before_the_layout_started() {
        let group = ReusePortGroup::new(addr(41_003), 2);
        drop(group.claim(0).unwrap());
        let mut first = group.claim(0).expect("not started: rejoin is a retry");
        let mut second = group.claim(1).unwrap();
        first.mark_bound();
        second.mark_bound();
        drop(second);
        assert!(!group.is_complete());
        assert!(group.claim(1).is_err(), "started layouts are sealed");
    }

    #[test]
    fn a_second_layout_on_a_live_address_is_refused_until_the_first_is_gone() {
        let first = ReusePortGroup::new(addr(41_004), 2);
        let held = first.claim(0).unwrap();
        let second = ReusePortGroup::new(addr(41_004), 2);
        assert!(second.claim(0).is_err());
        drop(held);
        drop(first);
        assert!(second.claim(0).is_ok(), "the first layout is gone");
        // Kernel-assigned ports never share a group.
        let ephemeral = ReusePortGroup::new(addr(0), 1);
        let also = ReusePortGroup::new(addr(0), 1);
        assert!(ephemeral.claim(0).is_ok() && also.claim(0).is_ok());
    }

    proptest! {
        /// Any sequence of claims, binds and releases: the group reports
        /// complete exactly when every member is claimed and bound, and a
        /// claim succeeds exactly when the member is free and the layout has
        /// not started.
        #[test]
        fn completion_and_claims_match_a_sequential_model(
            ops in proptest::collection::vec((0usize..3, 0u8..3), 0..40),
            port in 42_000u16..43_000,
        ) {
            let count = 3;
            let group = ReusePortGroup::new(addr(port), count);
            let mut held: Vec<Option<MemberClaim>> = (0..count).map(|_| None).collect();
            let mut bound = vec![false; count];
            let mut started = false;
            for (index, op) in ops {
                match op {
                    0 => {
                        let expect_ok = held[index].is_none() && !started;
                        let claim = group.claim(index);
                        prop_assert_eq!(claim.is_ok(), expect_ok);
                        if let Ok(claim) = claim {
                            held[index] = Some(claim);
                        }
                    }
                    1 => {
                        if let Some(claim) = held[index].as_mut() {
                            claim.mark_bound();
                            bound[index] = true;
                            started |= bound.iter().all(|b| *b);
                        }
                    }
                    _ => {
                        held[index] = None;
                        bound[index] = false;
                    }
                }
                prop_assert_eq!(group.is_complete(), bound.iter().all(|b| *b));
            }
        }
    }
}

#[cfg(all(test, loom))]
mod loom_tests {
    use super::*;

    /// Two members bind on their own threads while a third admits: whenever
    /// the observer sees the layout complete, it also sees everything both
    /// members did before marking themselves bound (their sockets exist).
    /// This is the happens-before the admission barrier relies on.
    #[test]
    fn a_complete_layout_implies_every_member_finished_binding() {
        loom::model(|| {
            let group = ReusePortGroup::new(SocketAddr::from(([127, 0, 0, 1], 0)), 2);
            let sockets = Arc::new([AtomicBool::new(false), AtomicBool::new(false)]);
            let members: Vec<_> = (0..2)
                .map(|index| {
                    let (group, sockets) = (Arc::clone(&group), Arc::clone(&sockets));
                    loom::thread::spawn(move || {
                        let mut claim = group.claim(index).expect("free member");
                        sockets[index].store(true, Ordering::Relaxed);
                        claim.mark_bound();
                        claim
                    })
                })
                .collect();
            if group.is_complete() {
                assert!(sockets[0].load(Ordering::Relaxed));
                assert!(sockets[1].load(Ordering::Relaxed));
            }
            let claims: Vec<_> = members.into_iter().map(|m| m.join().unwrap()).collect();
            assert!(group.is_complete());
            drop(claims);
            assert!(!group.is_complete());
        });
    }
}
