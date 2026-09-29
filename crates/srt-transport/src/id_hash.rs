//! Hashing for internally allocated identifiers.
//!
//! `CallerTable` looks its sessions, routes and scheduler entries up on every
//! outbound packet. Their keys are identifiers this crate allocates itself
//! (`LogicalCallerId` values and local SRT socket ids), so a peer can present
//! arbitrary ids to a lookup but never chooses which keys are stored, and hash
//! flooding is not possible. std's SipHash was ~1.5% of Owner CPU in an SRT
//! fan-out profile for no protection it could provide here; one multiply
//! spreads these keys well enough for a SwissTable (the top bits pick the
//! control byte, the low bits the bucket).

use std::hash::{BuildHasherDefault, Hasher};

/// Multiplicative hasher for integer ids. Not for keys a peer can choose.
#[derive(Default, Clone, Copy)]
pub(crate) struct IdHasher(u64);

const SEED: u64 = 0x9E37_79B9_7F4A_7C15;

impl Hasher for IdHasher {
    fn finish(&self) -> u64 {
        self.0
    }

    fn write(&mut self, bytes: &[u8]) {
        for &byte in bytes {
            self.write_u64(u64::from(byte));
        }
    }

    fn write_u32(&mut self, value: u32) {
        self.write_u64(u64::from(value));
    }

    fn write_u64(&mut self, value: u64) {
        self.0 = (self.0.rotate_left(5) ^ value).wrapping_mul(SEED);
    }

    fn write_usize(&mut self, value: usize) {
        self.write_u64(value as u64);
    }
}

pub(crate) type IdHashMap<K, V> = std::collections::HashMap<K, V, BuildHasherDefault<IdHasher>>;

#[cfg(test)]
mod tests {
    use super::*;
    use std::hash::BuildHasher;

    #[test]
    fn sequential_ids_spread_over_top_and_bottom_bits() {
        let build = BuildHasherDefault::<IdHasher>::default();
        let hashes: Vec<u64> = (0..4096u64).map(|id| build.hash_one(id)).collect();
        let top: std::collections::HashSet<u64> = hashes.iter().map(|h| h >> 57).collect();
        let low: std::collections::HashSet<u64> = hashes.iter().map(|h| h & 0xfff).collect();
        assert_eq!(top.len(), 128, "every control-byte value is used");
        assert!(low.len() > 2500, "bucket bits spread: {}", low.len());
    }

    #[test]
    fn map_behaves_like_a_map() {
        let mut map: IdHashMap<u32, u32> = IdHashMap::default();
        for id in 0..1000 {
            map.insert(id * 7, id);
        }
        assert!((0..1000).all(|id| map.get(&(id * 7)) == Some(&id)));
        assert_eq!(map.len(), 1000);
    }
}
