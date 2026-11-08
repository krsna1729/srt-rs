//! Adaptive sparse/dense receiver packet-window storage.
//!
//! Stores low-occupancy 64-slot pages in compact sparse arrays and promotes
//! to direct dense representations when occupancy exceeds the configured
//! threshold. Supports explicit demotion hysteresis, circular successor
//! traversal, constant-work range retirement with budgeted release of the
//! retired values, and eager empty-page reclamation.

#![allow(dead_code)]

use std::mem::size_of;

const SEQUENCE_MASK: u32 = 0x7fff_ffff;
const PAGE_SHIFT: usize = 6;
const PAGE_SLOTS: usize = 1 << PAGE_SHIFT;
const PAGE_MASK: usize = PAGE_SLOTS - 1;

#[derive(Debug, Clone)]
struct Slot<T> {
    sequence: u32,
    value: T,
}

#[derive(Debug, Clone)]
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

    fn get_mut(&mut self, sequence: u32) -> Option<&mut T> {
        self.entries
            .iter_mut()
            .flatten()
            .find(|slot| slot.sequence == sequence)
            .map(|slot| &mut slot.value)
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

#[derive(Debug, Clone)]
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

#[derive(Debug, Clone)]
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

    fn get_mut(&mut self, sequence: u32) -> Option<&mut T> {
        match self {
            Self::Sparse(page) => page.get_mut(sequence),
            Self::Dense(page) => page.slots[sequence as usize & PAGE_MASK]
                .as_mut()
                .filter(|slot| slot.sequence == sequence)
                .map(|slot| &mut slot.value),
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

    #[inline]
    fn remove(&mut self, sequence: u32, demote_at: usize) -> Option<(T, bool)> {
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
        let mut was_demoted = false;
        if demote_at != 0
            && matches!(self, Self::Dense(page) if page.occupied.count_ones() <= demote_at as u32)
        {
            self.demote();
            was_demoted = true;
        }
        Some((value, was_demoted))
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

    fn iter(&self) -> impl Iterator<Item = (u32, &T)> {
        let (sparse_entries, dense_slots) = match self {
            Self::Sparse(sparse) => (Some(&sparse.entries[..]), None),
            Self::Dense(dense) => (None, Some(&dense.slots[..])),
        };
        sparse_entries
            .into_iter()
            .flatten()
            .chain(dense_slots.into_iter().flatten())
            .flatten()
            .map(|slot| (slot.sequence, &slot.value))
    }
}

/// Most work units -- a page inspected or a removed value released -- one
/// [`AdaptiveReceiverPacketWindow::release_retired`] call spends: four full
/// pages' worth, the unit the sender releases acknowledged pages in.
pub const MAX_RETIRED_RELEASED_PER_VISIT: usize = 4 * PAGE_SLOTS;

const ALL: u64 = u64::MAX;

/// Bits `[from, to)` of one word, `from < to <= 64`.
fn span(from: usize, to: usize) -> u64 {
    (ALL >> (64 - (to - from))) << from
}

/// Adaptive safe receiver packet window for one bounded 31-bit receive window.
///
/// The caller must keep every live sequence in one circular span whose
/// distance from a common base is strictly less than `window_size`.
///
/// A range removal retires the values it covers at once: whole pages are
/// marked retired (whole blocks of 64 pages with one bit), only the two
/// partial pages at its ends are emptied value by value. Retired values are
/// unreachable immediately and their storage is released later, at most
/// [`MAX_RETIRED_RELEASED_PER_VISIT`] work units per
/// [`Self::release_retired`] call; inserting into a retired page releases
/// that page first.
#[derive(Debug, Clone)]
pub struct AdaptiveReceiverPacketWindow<T, const N: usize = 8> {
    window_size: u32,
    /// Live values.
    len: u32,
    /// Values physically held, live or retired.
    stored: u32,
    /// The page `release_retired` inspects next.
    release_cursor: u32,
    index_mask: usize,
    pages: Box<[Option<Page<T, N>>]>,
    /// For each block of 64 pages, three adjacent words: the pages holding
    /// any value, the pages retired by a range removal, and the block's live
    /// values.
    page_masks: Box<[u64]>,
    nonempty_summary: u64,
    /// Blocks retired wholesale: every page in one counts as retired.
    retired_blocks: u64,
    demote_at: usize,
    promotions: usize,
    demotions: usize,
}

impl<T, const N: usize> AdaptiveReceiverPacketWindow<T, N> {
    pub fn new(window_size: u32, demote_at: usize) -> Self {
        assert!((1..=65_536).contains(&window_size));
        assert!((1..PAGE_SLOTS).contains(&N));
        assert!(demote_at <= N);
        let capacity = (window_size as usize).max(PAGE_SLOTS).next_power_of_two();
        let page_count = capacity / PAGE_SLOTS;
        let blocks = page_count.div_ceil(64);
        debug_assert!(blocks <= 64);
        Self {
            window_size,
            len: 0,
            stored: 0,
            release_cursor: 0,
            index_mask: capacity - 1,
            pages: std::iter::repeat_with(|| None).take(page_count).collect(),
            page_masks: vec![0; 3 * blocks].into_boxed_slice(),
            nonempty_summary: 0,
            retired_blocks: 0,
            demote_at,
            promotions: 0,
            demotions: 0,
        }
    }

    /// Live values.
    pub fn len(&self) -> usize {
        self.len as usize
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Whether removed values still await [`Self::release_retired`].
    pub fn has_retired(&self) -> bool {
        self.stored > self.len
    }

    /// Whether no value, live or retired, is held.
    pub fn is_released(&self) -> bool {
        self.stored == 0
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

    pub fn promotions(&self) -> usize {
        self.promotions
    }

    pub fn demotions(&self) -> usize {
        self.demotions
    }

    pub fn heap_bytes(&self) -> usize {
        self.pages.len() * size_of::<Option<Page<T, N>>>()
            + self.page_masks.len() * size_of::<u64>()
            + self
                .pages
                .iter()
                .flatten()
                .map(Page::heap_bytes)
                .sum::<usize>()
    }

    fn blocks(&self) -> usize {
        self.page_masks.len() / 3
    }

    fn nonempty_slot(block: usize) -> usize {
        3 * block
    }

    fn retired_slot(block: usize) -> usize {
        3 * block + 1
    }

    fn live_slot(block: usize) -> usize {
        3 * block + 2
    }

    fn nonempty_pages(&self, block: usize) -> u64 {
        self.page_masks[Self::nonempty_slot(block)]
    }

    fn retired_pages(&self, block: usize) -> u64 {
        if self.retired_blocks & (1u64 << block) != 0 {
            ALL
        } else {
            self.page_masks[Self::retired_slot(block)]
        }
    }

    /// Whether `page`'s values are reachable.
    fn page_live(&self, page: usize) -> bool {
        self.retired_pages(page >> 6) & (1u64 << (page & 63)) == 0
    }

    /// Whether a value found in `page` is reachable: always, unless some
    /// removed value still awaits release.
    fn reachable(&self, page: usize) -> bool {
        !self.has_retired() || self.page_live(page)
    }

    #[inline]
    fn add_live(&mut self, page: usize, added: u32) {
        let slot = Self::live_slot(page >> 6);
        self.page_masks[slot] += u64::from(added);
        self.len += added;
    }

    #[inline]
    fn sub_live(&mut self, block: usize, removed: u32) {
        let slot = Self::live_slot(block);
        self.page_masks[slot] -= u64::from(removed);
        self.len -= removed;
    }

    #[inline]
    pub fn insert(&mut self, sequence: u32, value: T) -> Result<Option<T>, T> {
        count_work!(PacketSlotProbes);
        let (page_index, _) = self.indices(sequence);
        // Only a retirement in progress, or a block retired wholesale while
        // empty, can leave this page retired.
        if (self.has_retired() || self.retired_blocks != 0) && !self.page_live(page_index) {
            self.revive_page(page_index);
        }
        let result = if let Some(page) = &mut self.pages[page_index] {
            let was_sparse = matches!(page, Page::Sparse(_));
            let result = page.insert(sequence, value);
            if was_sparse && matches!(page, Page::Dense(_)) {
                self.promotions += 1;
            }
            result
        } else {
            self.pages[page_index] = Some(Page::Sparse(Box::new(SparsePage::new(sequence, value))));
            self.mark_page_nonempty(page_index);
            Ok(None)
        };
        if matches!(result, Ok(None)) {
            self.stored += 1;
            self.add_live(page_index, 1);
        }
        result
    }

    /// Make a retired `page` live again by releasing what it still holds:
    /// at most one page of values.
    fn revive_page(&mut self, page: usize) {
        let block = page >> 6;
        self.split_retired_block(block);
        let retired = Self::retired_slot(block);
        let bit = 1u64 << (page & 63);
        if self.page_masks[retired] & bit != 0 {
            self.release_page(page, PAGE_SLOTS);
            self.page_masks[retired] &= !bit;
        }
    }

    /// Turn a block retired wholesale into per-page retired marks, so one
    /// of its pages can be revived alone.
    fn split_retired_block(&mut self, block: usize) {
        let bit = 1u64 << block;
        if self.retired_blocks & bit != 0 {
            self.retired_blocks &= !bit;
            let retired = Self::retired_slot(block);
            self.page_masks[retired] = self.nonempty_pages(block);
        }
    }

    #[inline]
    pub fn get(&self, sequence: u32) -> Option<&T> {
        count_work!(PacketSlotProbes);
        let (page_index, _) = self.indices(sequence);
        let value = self.pages[page_index].as_ref()?.get(sequence)?;
        self.reachable(page_index).then_some(value)
    }

    pub fn get_mut(&mut self, sequence: u32) -> Option<&mut T> {
        let (page_index, _) = self.indices(sequence);
        if !self.reachable(page_index) {
            return None;
        }
        self.pages[page_index].as_mut()?.get_mut(sequence)
    }

    pub fn contains_key(&self, sequence: u32) -> bool {
        self.get(sequence).is_some()
    }

    #[inline]
    pub fn remove(&mut self, sequence: u32) -> Option<T> {
        count_work!(PacketSlotProbes);
        let (page_index, _) = self.indices(sequence);
        if !self.reachable(page_index) {
            return None;
        }
        let page = self.pages[page_index].as_mut()?;
        let (value, was_demoted) = page.remove(sequence, self.demote_at)?;
        if was_demoted {
            self.demotions += 1;
        }
        let emptied = page.occupied() == 0;
        self.stored -= 1;
        self.sub_live(page_index >> 6, 1);
        if emptied {
            self.pages[page_index] = None;
            self.mark_page_empty(page_index);
        }
        Some(value)
    }

    #[inline]
    pub fn successor_after(&self, sequence: u32) -> Option<u32> {
        if self.is_empty() {
            return None;
        }
        let start = (self.physical_index(sequence) + 1) & self.index_mask;
        self.find_live(start, self.index_mask + 1)
            .or_else(|| self.find_live(0, start))
    }

    pub fn first_from(&self, sequence: u32) -> Option<u32> {
        if self.contains_key(sequence) {
            Some(sequence)
        } else {
            self.successor_after(sequence.wrapping_sub(1) & SEQUENCE_MASK)
        }
    }

    /// Remove every live value in `first..=last` at once and return how many
    /// there were. The range must lie inside the live span: pages are
    /// retired by position, so a value whose slot merely aliases a position
    /// in the range would go too. The retired values' storage is released by
    /// [`Self::release_retired`], which this call runs once, starting at the
    /// range unless an earlier release is still in progress.
    pub fn remove_range(&mut self, first: u32, last: u32) -> Option<usize> {
        let count = (last.wrapping_sub(first) & SEQUENCE_MASK).saturating_add(1);
        if count > self.window_size {
            return None;
        }
        let start = self.physical_index(first);
        let end = start + count as usize;
        let capacity = self.index_mask + 1;
        let in_progress = self.has_retired();
        let removed = if end <= capacity {
            self.retire_span(start, end)
        } else {
            self.retire_span(start, capacity) + self.retire_span(0, end - capacity)
        };
        if !in_progress {
            self.release_cursor = (start >> PAGE_SHIFT) as u32;
        }
        self.release_retired(MAX_RETIRED_RELEASED_PER_VISIT);
        Some(removed as usize)
    }

    /// Retire every live value in slots `start..end`: the partial pages at
    /// either end value by value, whole pages and blocks by mark.
    fn retire_span(&mut self, start: usize, end: usize) -> u32 {
        let first_page = start >> PAGE_SHIFT;
        let last_page = (end - 1) >> PAGE_SHIFT;
        if first_page == last_page {
            return self.remove_slots(first_page, span(start & PAGE_MASK, (end - 1) % 64 + 1));
        }
        let mut removed = 0;
        let mut whole_from = first_page;
        if start & PAGE_MASK != 0 {
            removed += self.remove_slots(first_page, ALL << (start & PAGE_MASK));
            whole_from += 1;
        }
        let mut whole_to = last_page + 1;
        if end & PAGE_MASK != 0 {
            removed += self.remove_slots(last_page, span(0, end & PAGE_MASK));
            whole_to -= 1;
        }
        removed + self.retire_pages(whole_from, whole_to)
    }

    /// Remove the live values in the `slots` of one page now.
    fn remove_slots(&mut self, page_index: usize, slots: u64) -> u32 {
        count_work!(PacketSlotProbes);
        if !self.page_live(page_index) {
            return 0;
        }
        let Some(page) = self.pages[page_index].as_mut() else {
            return 0;
        };
        let mut selected = page.occupied() & slots;
        let mut removed = 0;
        while selected != 0 {
            count_work!(ReleasedChunks);
            let sequence = page
                .sequence_at(selected.trailing_zeros() as usize)
                .expect("occupancy names a slot");
            drop(page.remove(sequence, 0));
            selected &= selected - 1;
            removed += 1;
        }
        self.stored -= removed;
        self.sub_live(page_index >> 6, removed);
        self.settle_page_after_removal(page_index);
        removed
    }

    /// Retire whole pages `from..to`.
    fn retire_pages(&mut self, from: usize, to: usize) -> u32 {
        if from >= to {
            return 0;
        }
        let first_block = from >> 6;
        let last_block = (to - 1) >> 6;
        if first_block == last_block {
            return self.retire_pages_in_block(first_block, span(from & 63, (to - 1) % 64 + 1));
        }
        let mut removed = 0;
        let mut blocks_from = first_block;
        if from & 63 != 0 {
            removed += self.retire_pages_in_block(first_block, ALL << (from & 63));
            blocks_from += 1;
        }
        let mut blocks_to = last_block + 1;
        if to & 63 != 0 {
            removed += self.retire_pages_in_block(last_block, span(0, to & 63));
            blocks_to -= 1;
        }
        if blocks_from < blocks_to {
            removed += self.retire_blocks(span(blocks_from, blocks_to));
        }
        removed
    }

    /// Retire the `pages` (a page mask) of one block, counting the live
    /// values they held.
    fn retire_pages_in_block(&mut self, block: usize, pages: u64) -> u32 {
        count_work!(PacketSlotProbes);
        self.split_retired_block(block);
        let retired = Self::retired_slot(block);
        let mut newly = self.nonempty_pages(block) & !self.page_masks[retired] & pages;
        self.page_masks[retired] |= newly;
        let mut removed = 0;
        while newly != 0 {
            count_work!(PacketSlotProbes);
            let page = (block << 6) | newly.trailing_zeros() as usize;
            removed += self.pages[page]
                .as_ref()
                .map_or(0, |page| page.occupied().count_ones());
            newly &= newly - 1;
        }
        self.sub_live(block, removed);
        removed
    }

    /// Retire whole blocks (a block mask) with one mark each.
    fn retire_blocks(&mut self, blocks: u64) -> u32 {
        let mut newly = blocks & !self.retired_blocks;
        self.retired_blocks |= blocks;
        let mut removed = 0;
        while newly != 0 {
            count_work!(PacketSlotProbes);
            let block = newly.trailing_zeros() as usize;
            let live = self.page_masks[Self::live_slot(block)] as u32;
            self.sub_live(block, live);
            removed += live;
            newly &= newly - 1;
        }
        removed
    }

    /// Remove every live value at once; see [`Self::remove_range`].
    pub fn clear(&mut self) {
        self.retire_all();
        self.release_retired(MAX_RETIRED_RELEASED_PER_VISIT);
    }

    fn retire_all(&mut self) {
        self.retired_blocks = span(0, self.blocks());
        for block in 0..self.blocks() {
            let slot = Self::live_slot(block);
            self.page_masks[slot] = 0;
        }
        self.len = 0;
    }

    /// Release up to `budget` work units of retired values -- each page
    /// inspected and each value released costs one -- and return how many
    /// values were released.
    pub fn release_retired(&mut self, budget: usize) -> usize {
        let mut used = 0;
        let mut released = 0;
        while self.has_retired() && used < budget {
            let cursor = self.release_cursor as usize;
            let page = self
                .next_retired_page(cursor, self.pages.len())
                .or_else(|| self.next_retired_page(0, cursor))
                .expect("retired values are held in a retired page");
            used += 1;
            count_work!(PacketSlotProbes);
            let freed = self.release_page(page, budget - used);
            used += freed;
            released += freed;
            self.release_cursor = if self.pages[page].is_none() {
                ((page + 1) % self.pages.len()) as u32
            } else {
                page as u32
            };
        }
        released
    }

    /// Release up to `budget` values of a retired `page`; an emptied page
    /// is freed and loses its retired mark.
    fn release_page(&mut self, page_index: usize, budget: usize) -> usize {
        let Some(page) = self.pages[page_index].as_mut() else {
            return 0;
        };
        let mut occupied = page.occupied();
        let mut released = 0;
        while occupied != 0 && released < budget {
            count_work!(ReleasedChunks);
            let sequence = page
                .sequence_at(occupied.trailing_zeros() as usize)
                .expect("occupancy names a slot");
            drop(page.remove(sequence, 0));
            occupied &= occupied - 1;
            released += 1;
        }
        self.stored -= released as u32;
        if occupied == 0 {
            self.pages[page_index] = None;
            self.mark_page_empty(page_index);
            let retired = Self::retired_slot(page_index >> 6);
            self.page_masks[retired] &= !(1u64 << (page_index & 63));
        }
        released
    }

    /// Terminal reclamation, including sparse/dense page transitions, with
    /// at most `max_packets` retained packet destructors.
    pub(crate) fn clear_bounded(&mut self, max_packets: usize) -> usize {
        self.retire_all();
        let mut released = 0;
        while released < max_packets && !self.is_released() {
            let page = self
                .next_nonempty_page(0, self.pages.len())
                .expect("held values have a page");
            released += self.release_page(page, max_packets - released);
        }
        released
    }

    pub fn iter(&self) -> impl Iterator<Item = (u32, &T)> {
        self.pages
            .iter()
            .enumerate()
            .filter(|&(page, _)| self.reachable(page))
            .filter_map(|(_, page)| page.as_ref())
            .flat_map(|page| page.iter())
    }

    pub fn values(&self) -> impl Iterator<Item = &T> {
        self.iter().map(|(_, value)| value)
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
        self.page_masks[Self::nonempty_slot(word)] |= 1 << (page_index & 63);
        self.nonempty_summary |= 1 << word;
    }

    fn mark_page_empty(&mut self, page_index: usize) {
        let word = page_index >> 6;
        self.page_masks[Self::nonempty_slot(word)] &= !(1 << (page_index & 63));
        if self.nonempty_pages(word) == 0 {
            self.nonempty_summary &= !(1 << word);
        }
    }

    /// First page in `start..end` holding a value and passing `select`,
    /// which picks pages from one block's nonempty-page word.
    fn next_page_where(
        &self,
        start: usize,
        end: usize,
        select: impl Fn(usize, u64) -> u64,
    ) -> Option<usize> {
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
            count_work!(PacketSlotProbes);
            let word_index = summary.trailing_zeros() as usize;
            let mut pages = select(word_index, self.nonempty_pages(word_index));
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

    fn next_nonempty_page(&self, start: usize, end: usize) -> Option<usize> {
        self.next_page_where(start, end, |_, pages| pages)
    }

    fn next_retired_page(&self, start: usize, end: usize) -> Option<usize> {
        self.next_page_where(start, end, |block, pages| pages & self.retired_pages(block))
    }

    fn next_live_page(&self, start: usize, end: usize) -> Option<usize> {
        self.next_page_where(start, end, |block, pages| {
            pages & !self.retired_pages(block)
        })
    }

    /// The sequence of the first live value in slots `start..end`.
    fn find_live(&self, start: usize, end: usize) -> Option<u32> {
        if start >= end {
            return None;
        }
        let first_page = start >> PAGE_SHIFT;
        let last_page = (end - 1) >> PAGE_SHIFT;
        let mut page_index = self.next_live_page(first_page, last_page + 1)?;
        loop {
            count_work!(PacketSlotProbes);
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
                return page.sequence_at(occupied.trailing_zeros() as usize);
            }
            page_index = self.next_live_page(page_index + 1, last_page + 1)?;
        }
    }

    fn settle_page_after_removal(&mut self, page_index: usize) {
        let occupancy = self.pages[page_index]
            .as_ref()
            .map_or(0, |page| page.occupied().count_ones() as usize);
        if occupancy == 0 {
            self.pages[page_index] = None;
            self.mark_page_empty(page_index);
        } else if self.demote_at != 0 && occupancy <= self.demote_at {
            if matches!(self.pages[page_index], Some(Page::Dense(_))) {
                self.demotions += 1;
            }
            self.pages[page_index]
                .as_mut()
                .expect("nonempty page remains")
                .demote();
        }
    }
}
