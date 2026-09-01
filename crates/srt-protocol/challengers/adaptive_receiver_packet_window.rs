//! Private adaptive sparse/dense receiver packet-window challenger.
//!
//! This is evidence code only: it is source-included by tests and benchmarks,
//! never compiled into the production protocol module tree.

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
struct SparsePage<T, const N: usize> {
    occupied: u64,
    entries: [Option<Slot<T>>; N],
}

impl<T, const N: usize> SparsePage<T, N> {
    fn new(sequence: u32, value: T) -> Self {
        let mut entries = std::array::from_fn(|_| None);
        entries[0] = Some(Slot { sequence, value });
        Self {
            occupied: 1 << (sequence as usize & PAGE_MASK),
            entries,
        }
    }

    fn get(&self, sequence: u32) -> Option<&T> {
        self.entries
            .iter()
            .flatten()
            .find(|slot| slot.sequence == sequence)
            .map(|slot| &slot.value)
    }

    fn slot_at(&self, slot_index: usize) -> Option<&Slot<T>> {
        self.entries
            .iter()
            .flatten()
            .find(|slot| slot.sequence as usize & PAGE_MASK == slot_index)
    }

    fn insert(&mut self, sequence: u32, value: T) -> Result<Option<T>, T> {
        let physical_slot = sequence as usize & PAGE_MASK;
        if let Some(slot) = self
            .entries
            .iter_mut()
            .flatten()
            .find(|slot| slot.sequence as usize & PAGE_MASK == physical_slot)
        {
            if slot.sequence != sequence {
                return Err(value);
            }
            return Ok(Some(std::mem::replace(&mut slot.value, value)));
        }
        let Some(entry) = self.entries.iter_mut().find(|entry| entry.is_none()) else {
            return Err(value);
        };
        *entry = Some(Slot { sequence, value });
        self.occupied |= 1 << physical_slot;
        Ok(None)
    }

    fn remove(&mut self, sequence: u32) -> Option<T> {
        let entry = self
            .entries
            .iter_mut()
            .find(|entry| entry.as_ref().is_some_and(|slot| slot.sequence == sequence))?;
        let slot = entry.take().expect("matched occupied sparse entry");
        self.occupied &= !(1 << (sequence as usize & PAGE_MASK));
        Some(slot.value)
    }
}

#[derive(Debug)]
struct DensePage<T> {
    occupied: u64,
    slots: [Option<Slot<T>>; PAGE_SLOTS],
}

impl<T> DensePage<T> {
    fn new() -> Self {
        Self {
            occupied: 0,
            slots: std::array::from_fn(|_| None),
        }
    }

    fn insert_slot(&mut self, slot: Slot<T>) {
        let slot_index = slot.sequence as usize & PAGE_MASK;
        debug_assert!(self.slots[slot_index].is_none());
        self.slots[slot_index] = Some(slot);
        self.occupied |= 1 << slot_index;
    }
}

#[derive(Debug)]
enum Page<T, const N: usize> {
    Sparse(Box<SparsePage<T, N>>),
    Dense(Box<DensePage<T>>),
}

impl<T, const N: usize> Page<T, N> {
    fn occupied(&self) -> u64 {
        match self {
            Self::Sparse(page) => page.occupied,
            Self::Dense(page) => page.occupied,
        }
    }

    fn get(&self, sequence: u32) -> Option<&T> {
        match self {
            Self::Sparse(page) => page.get(sequence),
            Self::Dense(page) => page.slots[sequence as usize & PAGE_MASK]
                .as_ref()
                .filter(|slot| slot.sequence == sequence)
                .map(|slot| &slot.value),
        }
    }

    fn sequence_at(&self, slot_index: usize) -> Option<u32> {
        match self {
            Self::Sparse(page) => page.slot_at(slot_index).map(|slot| slot.sequence),
            Self::Dense(page) => page.slots[slot_index].as_ref().map(|slot| slot.sequence),
        }
    }

    fn insert(&mut self, sequence: u32, value: T) -> Result<Option<T>, T> {
        match self {
            Self::Dense(page) => {
                let slot_index = sequence as usize & PAGE_MASK;
                if let Some(slot) = &mut page.slots[slot_index] {
                    if slot.sequence != sequence {
                        return Err(value);
                    }
                    return Ok(Some(std::mem::replace(&mut slot.value, value)));
                }
                page.insert_slot(Slot { sequence, value });
                Ok(None)
            }
            Self::Sparse(page) => {
                let physical_slot = sequence as usize & PAGE_MASK;
                if page.occupied & (1 << physical_slot) != 0
                    || page.occupied.count_ones() < N as u32
                {
                    return page.insert(sequence, value);
                }

                let mut dense = Box::new(DensePage::new());
                for entry in &mut page.entries {
                    dense.insert_slot(entry.take().expect("full sparse page"));
                }
                dense.insert_slot(Slot { sequence, value });
                *self = Self::Dense(dense);
                Ok(None)
            }
        }
    }

    fn remove(&mut self, sequence: u32, demote_at: usize) -> Option<T> {
        let value = match self {
            Self::Sparse(page) => page.remove(sequence)?,
            Self::Dense(page) => {
                let slot_index = sequence as usize & PAGE_MASK;
                if page.slots[slot_index].as_ref()?.sequence != sequence {
                    return None;
                }
                let slot = page.slots[slot_index]
                    .take()
                    .expect("matched occupied dense slot");
                page.occupied &= !(1 << slot_index);
                slot.value
            }
        };
        if demote_at != 0
            && matches!(self, Self::Dense(page) if page.occupied.count_ones() <= demote_at as u32)
        {
            self.demote();
        }
        Some(value)
    }

    fn demote(&mut self) {
        let Self::Dense(page) = self else {
            return;
        };
        let mut sparse = Box::new(SparsePage {
            occupied: page.occupied,
            entries: std::array::from_fn(|_| None),
        });
        let mut next = 0;
        for slot in &mut page.slots {
            if let Some(slot) = slot.take() {
                sparse.entries[next] = Some(slot);
                next += 1;
            }
        }
        debug_assert!(next <= N);
        *self = Self::Sparse(sparse);
    }

    fn heap_bytes(&self) -> usize {
        match self {
            Self::Sparse(_) => size_of::<SparsePage<T, N>>(),
            Self::Dense(_) => size_of::<DensePage<T>>(),
        }
    }
}

/// Adaptive safe challenger for one bounded 31-bit receive window.
///
/// The caller must keep every live sequence in one circular span whose
/// distance from a common base is strictly less than `window_size`.
#[derive(Debug)]
pub struct AdaptiveReceiverPacketWindow<T, const N: usize = 4> {
    window_size: u32,
    index_mask: usize,
    pages: Box<[Option<Page<T, N>>]>,
    nonempty_pages: Box<[u64]>,
    nonempty_summary: u64,
    len: usize,
    demote_at: usize,
}

impl<T, const N: usize> AdaptiveReceiverPacketWindow<T, N> {
    pub fn new(window_size: u32, demote_at: usize) -> Self {
        assert!((1..=65_536).contains(&window_size));
        assert!((1..PAGE_SLOTS).contains(&N));
        assert!(demote_at <= N);
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
            demote_at,
        }
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub fn sparse_pages(&self) -> usize {
        self.pages
            .iter()
            .filter(|page| matches!(page, Some(Page::Sparse(_))))
            .count()
    }

    pub fn dense_pages(&self) -> usize {
        self.pages
            .iter()
            .filter(|page| matches!(page, Some(Page::Dense(_))))
            .count()
    }

    pub fn heap_bytes(&self) -> usize {
        self.pages.len() * size_of::<Option<Page<T, N>>>()
            + self.nonempty_pages.len() * size_of::<u64>()
            + self
                .pages
                .iter()
                .flatten()
                .map(Page::heap_bytes)
                .sum::<usize>()
    }

    pub fn insert(&mut self, sequence: u32, value: T) -> Result<Option<T>, T> {
        let (page_index, _) = self.indices(sequence);
        if let Some(page) = &mut self.pages[page_index] {
            let result = page.insert(sequence, value);
            if matches!(result, Ok(None)) {
                self.len += 1;
            }
            return result;
        }
        self.pages[page_index] = Some(Page::Sparse(Box::new(SparsePage::new(sequence, value))));
        self.len += 1;
        self.mark_page_nonempty(page_index);
        Ok(None)
    }

    pub fn get(&self, sequence: u32) -> Option<&T> {
        let (page_index, _) = self.indices(sequence);
        self.pages[page_index].as_ref()?.get(sequence)
    }

    pub fn contains_key(&self, sequence: u32) -> bool {
        self.get(sequence).is_some()
    }

    pub fn remove(&mut self, sequence: u32) -> Option<T> {
        let (page_index, _) = self.indices(sequence);
        let page = self.pages[page_index].as_mut()?;
        let value = page.remove(sequence, self.demote_at)?;
        self.len -= 1;
        if page.occupied() == 0 {
            self.pages[page_index] = None;
            self.mark_page_empty(page_index);
        }
        Some(value)
    }

    pub fn successor_after(&self, sequence: u32) -> Option<u32> {
        if self.is_empty() {
            return None;
        }
        let start = (self.physical_index(sequence) + 1) & self.index_mask;
        self.find_physical(start, self.index_mask + 1)
            .or_else(|| self.find_physical(0, start))
    }

    pub fn first_from(&self, sequence: u32) -> Option<u32> {
        if self.contains_key(sequence) {
            Some(sequence)
        } else {
            self.successor_after(sequence.wrapping_sub(1) & SEQUENCE_MASK)
        }
    }

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
            let mut occupied = page.occupied();
            if page_index == first_page {
                occupied &= !0u64 << (start & PAGE_MASK);
            }
            if page_index == last_page && end & PAGE_MASK != 0 {
                occupied &= (1u64 << (end & PAGE_MASK)) - 1;
            }
            if occupied != 0 {
                let slot_index = occupied.trailing_zeros() as usize;
                return page.sequence_at(slot_index);
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
            let mut selected = self.pages[page_index]
                .as_ref()
                .expect("summary names a page")
                .occupied();
            if page_index == first_page {
                selected &= !0u64 << (start & PAGE_MASK);
            }
            if page_index == last_page && end & PAGE_MASK != 0 {
                selected &= (1u64 << (end & PAGE_MASK)) - 1;
            }
            while selected != 0 {
                let slot_index = selected.trailing_zeros() as usize;
                selected &= selected - 1;
                let sequence = self.pages[page_index]
                    .as_ref()
                    .expect("page remains while selected bits exist")
                    .sequence_at(slot_index)
                    .expect("occupancy names a slot");
                if sequence.wrapping_sub(first_sequence) & SEQUENCE_MASK >= sequence_count {
                    continue;
                }
                let removed_value = self.pages[page_index]
                    .as_mut()
                    .expect("page remains while selected bits exist")
                    .remove(sequence, 0);
                debug_assert!(removed_value.is_some());
                removed += 1;
            }
            let occupancy = self.pages[page_index]
                .as_ref()
                .map_or(0, |page| page.occupied().count_ones() as usize);
            if occupancy == 0 {
                self.pages[page_index] = None;
                self.mark_page_empty(page_index);
            } else if self.demote_at != 0 && occupancy <= self.demote_at {
                self.pages[page_index]
                    .as_mut()
                    .expect("nonempty page remains")
                    .demote();
            }
            search_page = page_index + 1;
        }
        self.len -= removed;
        removed
    }
}
