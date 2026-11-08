//! Fixed-capacity bitset whose range assignment, range count and next-set /
//! next-clear searches do bounded work, independent of its capacity.
//!
//! Positions live in data words of 64 bits. Every 64 data words form a block
//! with two masks -- the words that hold any set bit, and the words that are
//! entirely set -- and every block is likewise summarised in one top-level
//! pair of masks. A mask bit is authoritative: a word marked empty or full
//! reads as zero or all ones whatever its stored contents, and so does a
//! block. A range assignment therefore rewrites at most the two partial words
//! at its ends, the masks of the two partial blocks around them and the top
//! masks; the words and blocks it covers wholesale keep stale contents until a
//! point update next opens them. Each block also keeps its population so a
//! range count never reads covered words one at a time.
//!
//! With at most 1,024 data words (a 65,536-position window) there are at
//! most 16 blocks, so the top level is a single word.

const ALL: u64 = u64::MAX;

/// Bits strictly above `bit` in one word.
fn above(bit: usize) -> u64 {
    if bit >= 63 { 0 } else { ALL << (bit + 1) }
}

/// Bits `[from, to)` of one word, `from < to <= 64`.
fn span(from: usize, to: usize) -> u64 {
    (ALL >> (64 - (to - from))) << from
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    Empty,
    Mixed,
    Full,
}

/// A bitset over `0..capacity` positions, `capacity` a power of two and a
/// multiple of 64. Storage is allocated by the first set bit.
#[derive(Debug)]
pub(crate) struct RangeBitset {
    /// Data words, then per-block `nonzero`, `full` and population, then the
    /// top-level `nonzero` and `full` block masks.
    storage: Vec<u64>,
    words: u32,
    len: u32,
}

impl RangeBitset {
    pub(crate) fn new(capacity: usize) -> Self {
        debug_assert!(capacity.is_power_of_two() && capacity >= 64);
        debug_assert!(capacity / 64 <= 64 * 64, "the top level is one word");
        Self {
            storage: Vec::new(),
            words: (capacity / 64) as u32,
            len: 0,
        }
    }

    pub(crate) fn capacity(&self) -> usize {
        self.words as usize * 64
    }

    pub(crate) fn len(&self) -> u32 {
        self.len
    }

    #[cfg(test)]
    pub(crate) fn is_allocated(&self) -> bool {
        !self.storage.is_empty()
    }

    /// Heap bytes the storage occupies once allocated.
    #[cfg(test)]
    pub(crate) fn allocated_bytes(&self) -> usize {
        self.storage.capacity() * size_of::<u64>()
    }

    fn word_count(&self) -> usize {
        self.words as usize
    }

    fn blocks(&self) -> usize {
        self.word_count().div_ceil(64)
    }

    fn words_per_block(&self) -> u32 {
        self.words.min(64)
    }

    fn valid_words(&self) -> u64 {
        if self.words >= 64 {
            ALL
        } else {
            (1u64 << self.words) - 1
        }
    }

    fn nonzero_slot(&self, block: usize) -> usize {
        self.word_count() + block
    }

    fn full_slot(&self, block: usize) -> usize {
        self.word_count() + self.blocks() + block
    }

    fn population_slot(&self, block: usize) -> usize {
        self.word_count() + 2 * self.blocks() + block
    }

    fn top_nonzero_slot(&self) -> usize {
        self.word_count() + 3 * self.blocks()
    }

    fn top_full_slot(&self) -> usize {
        self.top_nonzero_slot() + 1
    }

    fn ensure_storage(&mut self) {
        if self.storage.is_empty() {
            let len = self.word_count() + 3 * self.blocks() + 2;
            self.storage.resize(len, 0);
        }
    }

    fn block_state(&self, block: usize) -> State {
        count_work!(BitmapSummaryWords);
        let bit = 1u64 << block;
        if self.storage[self.top_full_slot()] & bit != 0 {
            State::Full
        } else if self.storage[self.top_nonzero_slot()] & bit == 0 {
            State::Empty
        } else {
            State::Mixed
        }
    }

    /// Value of data word `word` whose block is `Mixed`.
    fn mixed_word(&self, word: usize) -> u64 {
        count_work!(BitmapSummaryWords);
        let block = word / 64;
        let bit = 1u64 << (word % 64);
        if self.storage[self.full_slot(block)] & bit != 0 {
            ALL
        } else if self.storage[self.nonzero_slot(block)] & bit == 0 {
            0
        } else {
            count_work!(BitmapDataWords);
            self.storage[word]
        }
    }

    /// Value of data word `word`.
    pub(crate) fn word(&self, word: usize) -> u64 {
        if self.storage.is_empty() {
            return 0;
        }
        match self.block_state(word / 64) {
            State::Empty => 0,
            State::Full => ALL,
            State::Mixed => self.mixed_word(word),
        }
    }

    pub(crate) fn get(&self, index: usize) -> bool {
        self.word(index / 64) & (1u64 << (index % 64)) != 0
    }

    /// Make `block`'s masks authoritative before changing them.
    fn open_block(&mut self, block: usize) {
        let state = self.block_state(block);
        if state == State::Mixed {
            return;
        }
        let (masks, population) = if state == State::Full {
            (self.valid_words(), u64::from(self.words_per_block()) * 64)
        } else {
            (0, 0)
        };
        let nonzero = self.nonzero_slot(block);
        let full = self.full_slot(block);
        let population_slot = self.population_slot(block);
        self.storage[nonzero] = masks;
        self.storage[full] = masks;
        self.storage[population_slot] = population;
        let top_nonzero = self.top_nonzero_slot();
        let top_full = self.top_full_slot();
        self.storage[top_nonzero] |= 1u64 << block;
        self.storage[top_full] &= !(1u64 << block);
    }

    /// Restore the top-level masks after `block`'s masks changed.
    fn close_block(&mut self, block: usize) {
        count_work!(BitmapSummaryWords);
        let bit = 1u64 << block;
        let top_nonzero = self.top_nonzero_slot();
        let top_full = self.top_full_slot();
        if self.storage[self.nonzero_slot(block)] == 0 {
            self.storage[top_nonzero] &= !bit;
        } else if self.storage[self.full_slot(block)] == self.valid_words() {
            self.storage[top_full] |= bit;
        }
    }

    fn apply_population(&mut self, block: usize, old: u32, new: u32) -> u32 {
        let slot = self.population_slot(block);
        self.storage[slot] = self.storage[slot] - u64::from(old) + u64::from(new);
        self.len = self.len - old + new;
        old.abs_diff(new)
    }

    /// Set or clear the `mask` bits of one data word; returns how many bits
    /// changed.
    fn assign_in_word(&mut self, word: usize, mask: u64, value: bool) -> u32 {
        let block = word / 64;
        self.open_block(block);
        let old = self.mixed_word(word);
        let new = if value { old | mask } else { old & !mask };
        let bit = 1u64 << (word % 64);
        count_work!(BitmapDataWords);
        self.storage[word] = new;
        let nonzero = self.nonzero_slot(block);
        let full = self.full_slot(block);
        self.storage[nonzero] = (self.storage[nonzero] & !bit) | if new != 0 { bit } else { 0 };
        self.storage[full] = (self.storage[full] & !bit) | if new == ALL { bit } else { 0 };
        let changed = self.apply_population(block, old.count_ones(), new.count_ones());
        self.close_block(block);
        changed
    }

    /// Population of the `words` of a `Mixed` block.
    fn mixed_words_population(&self, block: usize, words: u64) -> u32 {
        count_work!(BitmapSummaryWords);
        let full = self.storage[self.full_slot(block)] & words;
        let mut explicit = self.storage[self.nonzero_slot(block)] & !full & words;
        let mut population = full.count_ones() * 64;
        while explicit != 0 {
            count_work!(BitmapDataWords);
            population +=
                self.storage[block * 64 + explicit.trailing_zeros() as usize].count_ones();
            explicit &= explicit - 1;
        }
        population
    }

    /// Population of the `words` (a word mask) of `block`.
    #[cfg(test)]
    fn words_population(&self, block: usize, words: u64) -> u32 {
        match self.block_state(block) {
            State::Empty => 0,
            State::Full => words.count_ones() * 64,
            State::Mixed => self.mixed_words_population(block, words),
        }
    }

    /// Set or clear whole data words `words` (a word mask) of `block`.
    fn assign_words(&mut self, block: usize, words: u64, value: bool) -> u32 {
        self.open_block(block);
        let old = self.mixed_words_population(block, words);
        let nonzero = self.nonzero_slot(block);
        let full = self.full_slot(block);
        let new = if value {
            self.storage[nonzero] |= words;
            self.storage[full] |= words;
            words.count_ones() * 64
        } else {
            self.storage[nonzero] &= !words;
            self.storage[full] &= !words;
            0
        };
        let changed = self.apply_population(block, old, new);
        self.close_block(block);
        changed
    }

    /// Set or clear whole blocks `blocks` (a block mask).
    fn assign_blocks(&mut self, blocks: u64, value: bool) -> u32 {
        let old = self.blocks_population(blocks);
        let top_nonzero = self.top_nonzero_slot();
        let top_full = self.top_full_slot();
        let new = if value {
            self.storage[top_nonzero] |= blocks;
            self.storage[top_full] |= blocks;
            blocks.count_ones() * self.words_per_block() * 64
        } else {
            self.storage[top_nonzero] &= !blocks;
            self.storage[top_full] &= !blocks;
            0
        };
        self.len = self.len - old + new;
        old.abs_diff(new)
    }

    /// Population of whole blocks `blocks` (a block mask): full blocks by
    /// their size, only partially set ones by their kept population.
    fn blocks_population(&self, blocks: u64) -> u32 {
        count_work!(BitmapSummaryWords);
        let full = blocks & self.storage[self.top_full_slot()];
        let mut mixed = blocks & self.storage[self.top_nonzero_slot()] & !full;
        let mut population = full.count_ones() * self.words_per_block() * 64;
        while mixed != 0 {
            count_work!(BitmapSummaryWords);
            population +=
                self.storage[self.population_slot(mixed.trailing_zeros() as usize)] as u32;
            mixed &= mixed - 1;
        }
        population
    }

    /// Set or clear every position in `start..end`; returns how many changed.
    pub(crate) fn assign(&mut self, start: usize, end: usize, value: bool) -> u32 {
        debug_assert!(end <= self.capacity());
        if start >= end || (!value && self.len == 0) {
            return 0;
        }
        self.ensure_storage();
        let first_word = start / 64;
        let last_word = (end - 1) / 64;
        if first_word == last_word {
            return self.assign_in_word(first_word, span(start % 64, (end - 1) % 64 + 1), value);
        }
        let mut changed = 0;
        let mut whole_from = first_word;
        if !start.is_multiple_of(64) {
            changed += self.assign_in_word(first_word, ALL << (start % 64), value);
            whole_from += 1;
        }
        let mut whole_to = last_word + 1;
        if !end.is_multiple_of(64) {
            changed += self.assign_in_word(last_word, span(0, end % 64), value);
            whole_to -= 1;
        }
        changed + self.assign_whole_words(whole_from, whole_to, value)
    }

    fn assign_whole_words(&mut self, from: usize, to: usize, value: bool) -> u32 {
        if from >= to {
            return 0;
        }
        let first_block = from / 64;
        let last_block = (to - 1) / 64;
        if first_block == last_block {
            return self.assign_words(first_block, span(from % 64, (to - 1) % 64 + 1), value);
        }
        let mut changed = 0;
        let mut blocks_from = first_block;
        if !from.is_multiple_of(64) {
            changed += self.assign_words(first_block, ALL << (from % 64), value);
            blocks_from += 1;
        }
        let mut blocks_to = last_block + 1;
        if !to.is_multiple_of(64) {
            changed += self.assign_words(last_block, span(0, to % 64), value);
            blocks_to -= 1;
        }
        if blocks_from < blocks_to {
            changed += self.assign_blocks(span(blocks_from, blocks_to), value);
        }
        changed
    }

    /// Set or clear one position; returns whether it changed.
    pub(crate) fn set(&mut self, index: usize, value: bool) -> bool {
        if !value && self.len == 0 {
            return false;
        }
        self.ensure_storage();
        self.assign_in_word(index / 64, 1u64 << (index % 64), value) != 0
    }

    /// Number of set positions in `start..end`.
    #[cfg(test)]
    pub(crate) fn count(&self, start: usize, end: usize) -> u32 {
        if start >= end || self.len == 0 {
            return 0;
        }
        let first_word = start / 64;
        let last_word = (end - 1) / 64;
        if first_word == last_word {
            return (self.word(first_word) & span(start % 64, (end - 1) % 64 + 1)).count_ones();
        }
        let mut population = 0;
        let mut whole_from = first_word;
        if !start.is_multiple_of(64) {
            population += (self.word(first_word) & (ALL << (start % 64))).count_ones();
            whole_from += 1;
        }
        let mut whole_to = last_word + 1;
        if !end.is_multiple_of(64) {
            population += (self.word(last_word) & span(0, end % 64)).count_ones();
            whole_to -= 1;
        }
        population + self.whole_words_population(whole_from, whole_to)
    }

    #[cfg(test)]
    fn whole_words_population(&self, from: usize, to: usize) -> u32 {
        if from >= to {
            return 0;
        }
        let first_block = from / 64;
        let last_block = (to - 1) / 64;
        if first_block == last_block {
            return self.words_population(first_block, span(from % 64, (to - 1) % 64 + 1));
        }
        let mut population = 0;
        let mut blocks_from = first_block;
        if !from.is_multiple_of(64) {
            population += self.words_population(first_block, ALL << (from % 64));
            blocks_from += 1;
        }
        let mut blocks_to = last_block + 1;
        if !to.is_multiple_of(64) {
            population += self.words_population(last_block, span(0, to % 64));
            blocks_to -= 1;
        }
        if blocks_from < blocks_to {
            population += self.blocks_population(span(blocks_from, blocks_to));
        }
        population
    }

    /// Words of `block` holding at least one position equal to `value`.
    fn candidate_words(&self, block: usize, value: bool) -> u64 {
        match (self.block_state(block), value) {
            (State::Empty, false) | (State::Full, true) => self.valid_words(),
            (State::Empty, true) | (State::Full, false) => 0,
            (State::Mixed, true) => self.storage[self.nonzero_slot(block)],
            (State::Mixed, false) => self.valid_words() & !self.storage[self.full_slot(block)],
        }
    }

    /// Blocks holding at least one position equal to `value`.
    fn candidate_blocks(&self, value: bool) -> u64 {
        count_work!(BitmapSummaryWords);
        if value {
            self.storage[self.top_nonzero_slot()]
        } else {
            span(0, self.blocks()) & !self.storage[self.top_full_slot()]
        }
    }

    fn word_bits(&self, word: usize, value: bool) -> u64 {
        let bits = self.word(word);
        if value { bits } else { !bits }
    }

    /// First position at or after `from` (before `capacity`) equal to `value`.
    fn next_from(&self, from: usize, value: bool) -> Option<usize> {
        let word = from / 64;
        let bits = self.word_bits(word, value) & (ALL << (from % 64));
        if bits != 0 {
            return Some(word * 64 + bits.trailing_zeros() as usize);
        }
        let block = word / 64;
        let later_words = self.candidate_words(block, value) & above(word % 64);
        let next_word = if later_words != 0 {
            block * 64 + later_words.trailing_zeros() as usize
        } else {
            let later_blocks = self.candidate_blocks(value) & above(block);
            if later_blocks == 0 {
                return None;
            }
            let next_block = later_blocks.trailing_zeros() as usize;
            next_block * 64 + self.candidate_words(next_block, value).trailing_zeros() as usize
        };
        let bits = self.word_bits(next_word, value);
        Some(next_word * 64 + bits.trailing_zeros() as usize)
    }

    /// First set position in `from..end`.
    pub(crate) fn next_one(&self, from: usize, end: usize) -> Option<usize> {
        if from >= end || self.len == 0 {
            return None;
        }
        self.next_from(from, true).filter(|&index| index < end)
    }

    /// First clear position in `from..end`.
    pub(crate) fn next_zero(&self, from: usize, end: usize) -> Option<usize> {
        if from >= end {
            return None;
        }
        if self.storage.is_empty() {
            return Some(from);
        }
        self.next_from(from, false).filter(|&index| index < end)
    }

    /// Clear every position.
    #[cfg(test)]
    pub(crate) fn clear(&mut self) {
        if self.storage.is_empty() {
            return;
        }
        let top_nonzero = self.top_nonzero_slot();
        let top_full = self.top_full_slot();
        self.storage[top_nonzero] = 0;
        self.storage[top_full] = 0;
        self.len = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A deterministic xorshift stream; tests stay reproducible without a
    /// random-number dependency.
    fn next(state: &mut u64) -> u64 {
        *state ^= *state << 13;
        *state ^= *state >> 7;
        *state ^= *state << 17;
        *state
    }

    fn check(bits: &RangeBitset, model: &[bool], rng: &mut u64) {
        let capacity = bits.capacity();
        let ones = |start: usize, end: usize| model[start..end].iter().filter(|&&bit| bit).count();
        assert_eq!(bits.len() as usize, ones(0, capacity));
        for _ in 0..4 {
            let a = next(rng) as usize % (capacity + 1);
            let b = next(rng) as usize % (capacity + 1);
            let (start, end) = (a.min(b), a.max(b));
            assert_eq!(
                bits.count(start, end) as usize,
                ones(start, end),
                "count {start}..{end}"
            );
            let find = |value: bool| (start..end).find(|&index| model[index] == value);
            assert_eq!(
                bits.next_one(start, end),
                find(true),
                "next_one {start}..{end}"
            );
            assert_eq!(
                bits.next_zero(start, end),
                find(false),
                "next_zero {start}..{end}"
            );
            if start < capacity {
                assert_eq!(bits.get(start), model[start]);
            }
        }
    }

    #[test]
    fn matches_a_set_under_random_range_and_point_updates() {
        for (capacity, rounds) in [(64, 2_000), (128, 2_000), (4096, 1_000), (65_536, 150)] {
            let mut bits = RangeBitset::new(capacity);
            let mut model = vec![false; capacity];
            let mut rng = 0x9E37_79B9_7F4A_7C15 ^ capacity as u64;
            for _ in 0..rounds {
                let value = next(&mut rng).is_multiple_of(2);
                let start = next(&mut rng) as usize % capacity;
                let width = match next(&mut rng) % 4 {
                    0 => 1,
                    1 => next(&mut rng) as usize % 130,
                    2 => next(&mut rng) as usize % 5_000,
                    _ => capacity,
                };
                let end = (start + width).min(capacity);
                let expected = model[start..end]
                    .iter()
                    .filter(|&&bit| bit != value)
                    .count();
                model[start..end].fill(value);
                assert_eq!(bits.assign(start, end, value) as usize, expected);
                check(&bits, &model, &mut rng);
            }
            bits.clear();
            assert_eq!(bits.len(), 0);
            assert_eq!(bits.next_one(0, capacity), None);
            assert_eq!(bits.next_zero(0, capacity), Some(0));
        }
    }

    #[test]
    fn range_work_does_not_grow_with_capacity() {
        let mut worst = Vec::new();
        for capacity in [64, 8192, 65_536] {
            let mut bits = RangeBitset::new(capacity);
            // Mixed words everywhere: alternating bits.
            for index in (0..capacity).step_by(2) {
                bits.set(index, true);
            }
            let ((), work) = crate::test_support::WorkCounters::measure(|| {
                bits.assign(1, capacity - 1, true);
                let _ = bits.count(3, capacity - 3);
                let _ = bits.next_zero(0, capacity);
                bits.assign(5, capacity - 7, false);
                let _ = bits.next_one(7, capacity);
            });
            worst.push(work.bitmap_words());
        }
        // Two partial blocks of 64 words each plus a constant: never a
        // walk over the capacity.
        assert!(worst.iter().all(|&words| words <= 600), "{worst:?}");
    }
}
