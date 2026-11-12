//! Exact handshake-routing indexes of a listener's peer slots.
//!
//! A datagram whose Destination Socket ID does not name a slot -- an
//! INDUCTION (destination 0) or a CONCLUSION a caller sends before it knows
//! the listener's socket ID -- is routed by what its handshake carries: the
//! caller's own socket ID, the SYN cookie, or, failing both, the UDP source
//! address alone. These indexes answer each of those questions with one
//! ordered-set probe instead of a walk over the arena's slot domain, which
//! any source could otherwise force on every datagram before capacity
//! rejection. Each answers with the lowest matching slot index, which is
//! the slot an ascending arena walk would have found first.

use std::collections::BTreeSet;
use std::net::SocketAddr;

use crate::id_hash::IdHashMap;

/// The routing keys one occupied slot currently carries.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct RouteKeys {
    /// The slot's UDP source address.
    pub(crate) address: SocketAddr,
    /// The peer's own SRT socket ID, when the slot holds a connection.
    pub(crate) caller_socket_id: Option<u32>,
    /// The SYN cookie a direct (non-group) peer expects.
    pub(crate) syn_cookie: Option<u32>,
}

/// Address, address + caller-ID and address + cookie indexes over occupied
/// slots. Kept exact by [`Self::sync`] at every point a slot's keys can
/// change: insertion, removal, a change of slot kind, and handshake input.
#[derive(Debug, Default)]
pub(crate) struct RouteIndex {
    keys: IdHashMap<u32, RouteKeys>,
    by_address: BTreeSet<(Addr, u32)>,
    /// `(caller ID, address, slot)`: the ID leads, so a probe usually
    /// settles on one integer comparison per node entry.
    by_caller: BTreeSet<(u32, Addr, u32)>,
    /// `(cookie, address, slot)`, likewise.
    by_cookie: BTreeSet<(u32, Addr, u32)>,
}

/// A socket address as plain integers, so an index comparison is a few
/// integer compares rather than `SocketAddr`'s per-family ordering. Exact:
/// it keeps every field `SocketAddr` equality looks at.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct Addr {
    ip: u128,
    /// Port in the low 16 bits; bit 16 set for IPv6.
    port_family: u32,
    flowinfo: u32,
    scope_id: u32,
}

impl From<SocketAddr> for Addr {
    fn from(address: SocketAddr) -> Self {
        match address {
            SocketAddr::V4(v4) => Self {
                ip: u128::from(v4.ip().to_bits()),
                port_family: u32::from(v4.port()),
                flowinfo: 0,
                scope_id: 0,
            },
            SocketAddr::V6(v6) => Self {
                ip: v6.ip().to_bits(),
                port_family: 1 << 16 | u32::from(v6.port()),
                flowinfo: v6.flowinfo(),
                scope_id: v6.scope_id(),
            },
        }
    }
}

/// Lowest slot of `(id, address)` in an id-led index.
fn first_slot(index: &BTreeSet<(u32, Addr, u32)>, id: u32, address: SocketAddr) -> Option<u32> {
    let address = Addr::from(address);
    index
        .range((id, address, 0)..=(id, address, u32::MAX))
        .next()
        .map(|&(_, _, slot)| slot)
}

impl RouteIndex {
    /// Record `slot`'s current keys; `None` for a slot that is now empty.
    pub(crate) fn sync(&mut self, slot: u32, keys: Option<RouteKeys>) {
        let old = match keys {
            Some(keys) => self.keys.insert(slot, keys),
            None => self.keys.remove(&slot),
        };
        if old == keys {
            return;
        }
        if let Some(old) = old {
            let address = Addr::from(old.address);
            self.by_address.remove(&(address, slot));
            if let Some(id) = old.caller_socket_id {
                self.by_caller.remove(&(id, address, slot));
            }
            if let Some(cookie) = old.syn_cookie {
                self.by_cookie.remove(&(cookie, address, slot));
            }
        }
        if let Some(new) = keys {
            let address = Addr::from(new.address);
            self.by_address.insert((address, slot));
            if let Some(id) = new.caller_socket_id {
                self.by_caller.insert((id, address, slot));
            }
            if let Some(cookie) = new.syn_cookie {
                self.by_cookie.insert((cookie, address, slot));
            }
        }
    }

    /// Lowest slot at `address`.
    pub(crate) fn first_at(&self, address: SocketAddr) -> Option<u32> {
        count_work!(RouteIndexProbes);
        let address = Addr::from(address);
        self.by_address
            .range((address, 0)..=(address, u32::MAX))
            .next()
            .map(|&(_, slot)| slot)
    }

    /// Lowest slot at `address` whose peer has SRT socket ID `caller`.
    pub(crate) fn first_for_caller(&self, address: SocketAddr, caller: u32) -> Option<u32> {
        count_work!(RouteIndexProbes);
        first_slot(&self.by_caller, caller, address)
    }

    /// Lowest direct-peer slot at `address` expecting SYN cookie `cookie`.
    pub(crate) fn first_for_cookie(&self, address: SocketAddr, cookie: u32) -> Option<u32> {
        count_work!(RouteIndexProbes);
        first_slot(&self.by_cookie, cookie, address)
    }

    /// Entries in the address, caller-ID and cookie indexes.
    #[cfg(test)]
    pub(crate) fn sizes(&self) -> (usize, usize, usize) {
        (
            self.by_address.len(),
            self.by_caller.len(),
            self.by_cookie.len(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(port: u16) -> SocketAddr {
        SocketAddr::from(([10, 0, 0, 1], port))
    }

    fn keys(port: u16, caller: Option<u32>, cookie: Option<u32>) -> Option<RouteKeys> {
        Some(RouteKeys {
            address: at(port),
            caller_socket_id: caller,
            syn_cookie: cookie,
        })
    }

    #[test]
    fn lookups_answer_with_the_lowest_matching_slot() {
        let mut index = RouteIndex::default();
        index.sync(9, keys(1, Some(7), Some(70)));
        index.sync(4, keys(1, Some(7), Some(70)));
        index.sync(6, keys(1, Some(8), None));
        assert_eq!(index.first_at(at(1)), Some(4));
        assert_eq!(index.first_for_caller(at(1), 7), Some(4));
        assert_eq!(index.first_for_caller(at(1), 8), Some(6));
        assert_eq!(index.first_for_cookie(at(1), 70), Some(4));
        assert_eq!(index.first_for_caller(at(2), 7), None);
        index.sync(4, None);
        assert_eq!(index.first_for_caller(at(1), 7), Some(9));
        index.sync(9, None);
        assert_eq!(index.first_at(at(1)), Some(6));
        assert_eq!(index.first_for_cookie(at(1), 70), None);
    }

    #[test]
    fn resync_moves_every_key_of_a_slot() {
        let mut index = RouteIndex::default();
        index.sync(3, keys(1, Some(7), Some(70)));
        index.sync(3, keys(1, Some(8), Some(80)));
        assert_eq!(index.first_for_caller(at(1), 7), None);
        assert_eq!(index.first_for_cookie(at(1), 70), None);
        assert_eq!(index.first_for_caller(at(1), 8), Some(3));
        assert_eq!(index.sizes(), (1, 1, 1));
        index.sync(3, keys(2, Some(8), None));
        assert_eq!(index.first_at(at(1)), None);
        assert_eq!(index.first_for_cookie(at(2), 80), None);
        assert_eq!(index.first_at(at(2)), Some(3));
        assert_eq!(index.sizes(), (1, 1, 0));
    }

    /// The integer key keeps every field `SocketAddr` equality compares:
    /// family, port, and an IPv6 address's flow info and scope.
    #[test]
    fn addresses_equal_only_when_socket_addrs_are() {
        use std::net::{Ipv4Addr, SocketAddrV6};
        let v4 = SocketAddr::from((Ipv4Addr::new(10, 0, 0, 1), 9));
        let mapped = Ipv4Addr::new(10, 0, 0, 1).to_ipv6_mapped();
        let v6 = |flowinfo, scope| SocketAddr::V6(SocketAddrV6::new(mapped, 9, flowinfo, scope));
        let all = [
            v4,
            SocketAddr::from((Ipv4Addr::new(10, 0, 0, 1), 10)),
            v6(0, 0),
            v6(1, 0),
            v6(0, 1),
        ];
        let mut index = RouteIndex::default();
        for (slot, address) in (0..).zip(all) {
            index.sync(
                slot,
                Some(RouteKeys {
                    address,
                    caller_socket_id: Some(7),
                    syn_cookie: Some(70),
                }),
            );
        }
        for (slot, address) in (0..).zip(all) {
            assert_eq!(index.first_at(address), Some(slot), "{address}");
            assert_eq!(index.first_for_caller(address, 7), Some(slot));
            assert_eq!(index.first_for_cookie(address, 70), Some(slot));
        }
    }
}
