//! Private receiver packet-window challenger shared by tests and benchmarks.
//!
//! This file is intentionally not part of the `shiguredo_srt` module tree.
//! It can therefore gather evidence for a direct-indexed receiver without
//! changing the published API or the production packet store.

#![allow(dead_code)] // Each source-including evidence harness exercises a subset.

use std::mem::size_of;

const SEQUENCE_MASK: u32 = 0x7fff_ffff;
const PAGE_SHIFT: usize = 6;
const PAGE_SLOTS: usize = 1 << PAGE_SHIFT;
const PAGE_MASK: usize = PAGE_SLOTS - 1;

#[derive(Debug)]
struct Slot<T> {
    sequence: u32,
    value: T,
}

#[derive(Debug)]
struct Page<T> {
    occupied: u64,
    slots: [Option<Slot<T>>; PAGE_SLOTS],
}

impl<T> Page<T> {
    fn new() -> Self {
        Self {
            occupied: 0,
            slots: std::array::from_fn(|_| None),
        }
    }
}

/// Safe, lazily paged challenger for one bounded 31-bit receive window.
///
/// The caller must keep every live sequence in one circular span whose
/// distance from a common base is strictly less than `window_size`. Full tags
/// reject physical aliases, but this live-span precondition is what makes
/// physical-order successor lookup equivalent to 31-bit circular order.
#[derive(Debug)]
pub struct ReceiverPacketWindow<T> {
    window_size: u32,
    index_mask: usize,
    pages: Box<[Option<Box<Page<T>>>]>,
    nonempty_pages: Box<[u64]>,
    nonempty_summary: u64,
    len: usize,
}

impl<T> ReceiverPacketWindow<T> {
    pub fn new(window_size: u32) -> Self {
        assert!((1..=65_536).contains(&window_size));
        let capacity = (window_size as usize).max(PAGE_SLOTS).next_power_of_two();
        let page_count = capacity / PAGE_SLOTS;
        let summary_words = page_count.div_ceil(64);
        debug_assert!(summary_words <= 64);
        Self {
            window_size,
            index_mask: capacity - 1,
            pages: std::iter::repeat_with(|| None).take(page_count).collect(),
            nonempty_pages: vec![0; summary_words].into_boxed_slice(),
            nonempty_summary: 0,
            len: 0,
        }
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub fn allocated_pages(&self) -> usize {
        self.nonempty_pages
            .iter()
            .map(|word| word.count_ones() as usize)
            .sum()
    }

    pub fn heap_bytes(&self) -> usize {
        self.pages.len() * size_of::<Option<Box<Page<T>>>>()
            + self.nonempty_pages.len() * size_of::<u64>()
            + self.allocated_pages() * size_of::<Page<T>>()
    }

    /// Insert by full sequence tag. A different live tag in the same physical
    /// slot is rejected, exposing a violated live-span invariant immediately.
    pub fn insert(&mut self, sequence: u32, value: T) -> Result<Option<T>, T> {
        let (page_index, slot_index) = self.indices(sequence);
        let page_was_empty = self.pages[page_index].is_none();
        let page = self.pages[page_index].get_or_insert_with(|| Box::new(Page::new()));
        if let Some(slot) = &mut page.slots[slot_index] {
            if slot.sequence != sequence {
                return Err(value);
            }
            return Ok(Some(std::mem::replace(&mut slot.value, value)));
        }

        page.slots[slot_index] = Some(Slot { sequence, value });
        page.occupied |= 1 << slot_index;
        self.len += 1;
        if page_was_empty {
            self.mark_page_nonempty(page_index);
        }
        Ok(None)
    }

    pub fn get(&self, sequence: u32) -> Option<&T> {
        let (page_index, slot_index) = self.indices(sequence);
        self.pages[page_index].as_ref()?.slots[slot_index]
            .as_ref()
            .filter(|slot| slot.sequence == sequence)
            .map(|slot| &slot.value)
    }

    pub fn contains_key(&self, sequence: u32) -> bool {
        self.get(sequence).is_some()
    }

    pub fn remove(&mut self, sequence: u32) -> Option<T> {
        let (page_index, slot_index) = self.indices(sequence);
        let page = self.pages[page_index].as_mut()?;
        if page.slots[slot_index].as_ref()?.sequence != sequence {
            return None;
        }
        let slot = page.slots[slot_index]
            .take()
            .expect("checked occupied slot");
        page.occupied &= !(1 << slot_index);
        self.len -= 1;
        if page.occupied == 0 {
            self.pages[page_index] = None;
            self.mark_page_empty(page_index);
        }
        Some(slot.value)
    }

    /// Nearest stored sequence strictly after `sequence` in 31-bit circular
    /// order. Full tags remain the source of truth; summaries only locate it.
    pub fn successor_after(&self, sequence: u32) -> Option<u32> {
        if self.is_empty() {
            return None;
        }
        let start = (self.physical_index(sequence) + 1) & self.index_mask;
        self.find_physical(start, self.index_mask + 1)
            .or_else(|| self.find_physical(0, start))
    }

    /// Circularly first stored sequence at or after `sequence`.
    pub fn first_from(&self, sequence: u32) -> Option<u32> {
        if self.contains_key(sequence) {
            Some(sequence)
        } else {
            self.successor_after(sequence.wrapping_sub(1) & SEQUENCE_MASK)
        }
    }

    /// Remove an inclusive circular range. Returns `None` if the request is
    /// wider than the configured logical receive window.
    pub fn remove_range(&mut self, first: u32, last: u32) -> Option<usize> {
        let count = (last.wrapping_sub(first) & SEQUENCE_MASK).saturating_add(1);
        if count > self.window_size {
            return None;
        }
        let start = self.physical_index(first);
        let end = start + count as usize;
        let removed = if end <= self.index_mask + 1 {
            self.remove_physical_range(start, end, first, count)
        } else {
            self.remove_physical_range(start, self.index_mask + 1, first, count)
                + self.remove_physical_range(0, end & self.index_mask, first, count)
        };
        Some(removed)
    }

    fn physical_index(&self, sequence: u32) -> usize {
        sequence as usize & self.index_mask
    }

    fn indices(&self, sequence: u32) -> (usize, usize) {
        let physical = self.physical_index(sequence);
        (physical >> PAGE_SHIFT, physical & PAGE_MASK)
    }

    fn mark_page_nonempty(&mut self, page_index: usize) {
        let word = page_index >> 6;
        self.nonempty_pages[word] |= 1 << (page_index & 63);
        self.nonempty_summary |= 1 << word;
    }

    fn mark_page_empty(&mut self, page_index: usize) {
        let word = page_index >> 6;
        self.nonempty_pages[word] &= !(1 << (page_index & 63));
        if self.nonempty_pages[word] == 0 {
            self.nonempty_summary &= !(1 << word);
        }
    }

    fn next_nonempty_page(&self, start: usize, end: usize) -> Option<usize> {
        if start >= end {
            return None;
        }
        let first_word = start >> 6;
        let last_word = (end - 1) >> 6;
        let mut summary = self.nonempty_summary & (!0u64 << first_word);
        if last_word < 63 {
            summary &= (1u64 << (last_word + 1)) - 1;
        }
        while summary != 0 {
            let word_index = summary.trailing_zeros() as usize;
            let mut pages = self.nonempty_pages[word_index];
            if word_index == first_word {
                pages &= !0u64 << (start & 63);
            }
            if word_index == last_word && end & 63 != 0 {
                pages &= (1u64 << (end & 63)) - 1;
            }
            if pages != 0 {
                return Some((word_index << 6) + pages.trailing_zeros() as usize);
            }
            summary &= summary - 1;
        }
        None
    }

    fn find_physical(&self, start: usize, end: usize) -> Option<u32> {
        if start >= end {
            return None;
        }
        let first_page = start >> PAGE_SHIFT;
        let last_page = (end - 1) >> PAGE_SHIFT;
        let mut page_index = self.next_nonempty_page(first_page, last_page + 1)?;
        loop {
            let page = self.pages[page_index]
                .as_ref()
                .expect("summary names a page");
            let mut occupied = page.occupied;
            if page_index == first_page {
                occupied &= !0u64 << (start & PAGE_MASK);
            }
            if page_index == last_page && end & PAGE_MASK != 0 {
                occupied &= (1u64 << (end & PAGE_MASK)) - 1;
            }
            if occupied != 0 {
                let slot = occupied.trailing_zeros() as usize;
                return Some(
                    page.slots[slot]
                        .as_ref()
                        .expect("occupancy names a slot")
                        .sequence,
                );
            }
            page_index = self.next_nonempty_page(page_index + 1, last_page + 1)?;
        }
    }

    fn remove_physical_range(
        &mut self,
        start: usize,
        end: usize,
        first_sequence: u32,
        sequence_count: u32,
    ) -> usize {
        if start >= end {
            return 0;
        }
        let first_page = start >> PAGE_SHIFT;
        let last_page = (end - 1) >> PAGE_SHIFT;
        let mut removed = 0;
        let mut search_page = first_page;
        while let Some(page_index) = self.next_nonempty_page(search_page, last_page + 1) {
            let page = self.pages[page_index]
                .as_mut()
                .expect("summary names a page");
            let mut selected = page.occupied;
            if page_index == first_page {
                selected &= !0u64 << (start & PAGE_MASK);
            }
            if page_index == last_page && end & PAGE_MASK != 0 {
                selected &= (1u64 << (end & PAGE_MASK)) - 1;
            }
            while selected != 0 {
                let slot_index = selected.trailing_zeros() as usize;
                selected &= selected - 1;
                let sequence = page.slots[slot_index]
                    .as_ref()
                    .expect("occupancy names a slot")
                    .sequence;
                if sequence.wrapping_sub(first_sequence) & SEQUENCE_MASK >= sequence_count {
                    continue;
                }
                page.slots[slot_index] = None;
                page.occupied &= !(1 << slot_index);
                removed += 1;
            }
            if page.occupied == 0 {
                self.pages[page_index] = None;
                self.mark_page_empty(page_index);
            }
            search_page = page_index + 1;
        }
        self.len -= removed;
        removed
    }
}
