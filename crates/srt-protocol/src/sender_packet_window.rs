//! Direct paged sequence window for sender packet storage.
//!
//! Replaces the general-purpose `BTreeMap<u32, SentPacket>` and separate
//! `RetransmitQueueBitmap` with fixed 64-slot pages containing both `occupied`
//! and `retransmit_queued` bitmasks.
//!
//! Insertion is monotonic at `next_seq`, cumulative ACK retirement operates
//! page-at-a-time, and peer NAK ranges intersect occupied bitmasks directly
//! without per-sequence tree lookup.

#![allow(dead_code)]

use std::mem::size_of;

const SEQUENCE_MASK: u32 = 0x7fff_ffff;
const PAGE_SHIFT: usize = 6;
const PAGE_SLOTS: usize = 1 << PAGE_SHIFT;
const PAGE_MASK: usize = PAGE_SLOTS - 1;

/// A packet removed from the sender window, recording whether it was
/// actively queued in the retransmission list at the time of removal.
#[derive(Debug, Clone)]
pub struct RemovedPacket<T> {
    pub packet: T,
    pub was_retransmit_queued: bool,
}

#[derive(Debug, Clone)]
struct SendSlot<T> {
    sequence: u32,
    packet: T,
}

#[derive(Debug, Clone)]
struct SendPage<T> {
    occupied: u64,
    retransmit_queued: u64,
    slots: [Option<SendSlot<T>>; PAGE_SLOTS],
}

impl<T> SendPage<T> {
    fn new() -> Self {
        Self {
            occupied: 0,
            retransmit_queued: 0,
            slots: std::array::from_fn(|_| None),
        }
    }

    fn heap_bytes(&self) -> usize {
        size_of::<Self>()
    }
}

/// Direct paged sequence window for sender packet storage.
#[derive(Debug, Clone)]
pub struct SenderPacketWindow<T> {
    window_size: u32,
    index_mask: usize,
    pages: Box<[Option<Box<SendPage<T>>>]>,
    nonempty_pages: Box<[u64]>,
    nonempty_summary: u64,
    len: usize,
    retransmit_queued_count: u32,
}

impl<T> SenderPacketWindow<T> {
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
            retransmit_queued_count: 0,
        }
    }

    pub fn window_size(&self) -> u32 {
        self.window_size
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub fn retransmit_queued_count(&self) -> u32 {
        self.retransmit_queued_count
    }

    pub fn has_retransmit_queued(&self) -> bool {
        self.retransmit_queued_count > 0
    }

    pub fn retransmit_queued_contains(&self, sequence: u32) -> bool {
        let (page_index, slot_index) = self.indices(sequence);
        let Some(page) = self.pages[page_index].as_ref() else {
            return false;
        };
        let bit = 1u64 << slot_index;
        if page.occupied & bit == 0 || page.retransmit_queued & bit == 0 {
            return false;
        }
        page.slots[slot_index]
            .as_ref()
            .is_some_and(|slot| slot.sequence == sequence)
    }

    pub fn allocated_pages(&self) -> usize {
        self.pages.iter().filter(|page| page.is_some()).count()
    }

    pub fn heap_bytes(&self) -> usize {
        self.pages.len() * size_of::<Option<Box<SendPage<T>>>>()
            + self.nonempty_pages.len() * size_of::<u64>()
            + self
                .pages
                .iter()
                .flatten()
                .map(|p| p.heap_bytes())
                .sum::<usize>()
    }

    pub fn insert(&mut self, sequence: u32, packet: T) -> Result<(), T> {
        let (page_index, slot_index) = self.indices(sequence);
        let bit = 1u64 << slot_index;
        if self.pages[page_index].is_none() {
            self.pages[page_index] = Some(Box::new(SendPage::new()));
            self.mark_page_nonempty(page_index);
        }
        let page = self.pages[page_index]
            .as_mut()
            .expect("page allocated or verified");
        if page.occupied & bit != 0 {
            let slot = page.slots[slot_index]
                .as_ref()
                .expect("occupied slot is present");
            if slot.sequence != sequence {
                return Err(packet);
            }
            // Overwriting the same sequence replaces the packet without altering queued status.
            page.slots[slot_index] = Some(SendSlot { sequence, packet });
            return Ok(());
        }
        page.slots[slot_index] = Some(SendSlot { sequence, packet });
        page.occupied |= bit;
        self.len += 1;
        Ok(())
    }

    pub fn get(&self, sequence: u32) -> Option<&T> {
        let (page_index, slot_index) = self.indices(sequence);
        let page = self.pages[page_index].as_ref()?;
        if page.occupied & (1u64 << slot_index) == 0 {
            return None;
        }
        let slot = page.slots[slot_index].as_ref()?;
        if slot.sequence != sequence {
            return None;
        }
        Some(&slot.packet)
    }

    pub fn get_mut(&mut self, sequence: u32) -> Option<&mut T> {
        let (page_index, slot_index) = self.indices(sequence);
        let page = self.pages[page_index].as_mut()?;
        if page.occupied & (1u64 << slot_index) == 0 {
            return None;
        }
        let slot = page.slots[slot_index].as_mut()?;
        if slot.sequence != sequence {
            return None;
        }
        Some(&mut slot.packet)
    }

    pub fn contains_key(&self, sequence: u32) -> bool {
        self.get(sequence).is_some()
    }

    pub fn remove(&mut self, sequence: u32) -> Option<RemovedPacket<T>> {
        let (page_index, slot_index) = self.indices(sequence);
        let page = self.pages[page_index].as_mut()?;
        let bit = 1u64 << slot_index;
        if page.occupied & bit == 0 {
            return None;
        }
        if page.slots[slot_index].as_ref()?.sequence != sequence {
            return None;
        }
        let slot = page.slots[slot_index].take()?;
        page.occupied &= !bit;
        let was_retransmit_queued = page.retransmit_queued & bit != 0;
        if was_retransmit_queued {
            page.retransmit_queued &= !bit;
            self.retransmit_queued_count -= 1;
        }
        self.len -= 1;
        if page.occupied == 0 {
            self.pages[page_index] = None;
            self.mark_page_empty(page_index);
        }
        Some(RemovedPacket {
            packet: slot.packet,
            was_retransmit_queued,
        })
    }

    pub fn pop_retransmit_slot(&mut self, sequence: u32) -> Option<&mut T> {
        let (page_index, slot_index) = self.indices(sequence);
        let page = self.pages[page_index].as_mut()?;
        let bit = 1u64 << slot_index;
        if page.retransmit_queued & bit == 0 || page.occupied & bit == 0 {
            return None;
        }
        let slot = page.slots[slot_index].as_mut()?;
        if slot.sequence != sequence {
            return None;
        }
        page.retransmit_queued &= !bit;
        self.retransmit_queued_count -= 1;
        Some(&mut slot.packet)
    }

    pub fn cancel_retransmit(&mut self, sequence: u32) -> bool {
        let (page_index, slot_index) = self.indices(sequence);
        let Some(page) = self.pages[page_index].as_mut() else {
            return false;
        };
        let bit = 1u64 << slot_index;
        if page.retransmit_queued & bit == 0 {
            return false;
        }
        page.retransmit_queued &= !bit;
        self.retransmit_queued_count -= 1;
        true
    }

    pub fn queue_loss_range(
        &mut self,
        first_seq: u32,
        last_seq: u32,
        mut on_newly_queued: impl FnMut(u32),
    ) {
        let count = (last_seq.wrapping_sub(first_seq) & SEQUENCE_MASK).saturating_add(1);
        if count > self.window_size {
            return;
        }
        let start = self.physical_index(first_seq);
        let end = start + count as usize;
        if end <= self.index_mask + 1 {
            self.queue_loss_physical_range(start, end, first_seq, count, &mut on_newly_queued);
        } else {
            self.queue_loss_physical_range(
                start,
                self.index_mask + 1,
                first_seq,
                count,
                &mut on_newly_queued,
            );
            self.queue_loss_physical_range(
                0,
                end & self.index_mask,
                first_seq,
                count,
                &mut on_newly_queued,
            );
        }
    }

    pub fn discard_acked_prefix(
        &mut self,
        oldest_unacked: u32,
        ack_seq: u32,
        mut on_stale_retransmit: impl FnMut(),
    ) {
        if oldest_unacked == ack_seq {
            return;
        }
        let count = (ack_seq.wrapping_sub(oldest_unacked) & SEQUENCE_MASK) as usize;
        if count > self.window_size as usize {
            return;
        }
        let start = self.physical_index(oldest_unacked);
        let end = start + count;
        if end <= self.index_mask + 1 {
            self.discard_physical_prefix(
                start,
                end,
                oldest_unacked,
                count as u32,
                &mut on_stale_retransmit,
            );
        } else {
            self.discard_physical_prefix(
                start,
                self.index_mask + 1,
                oldest_unacked,
                count as u32,
                &mut on_stale_retransmit,
            );
            self.discard_physical_prefix(
                0,
                end & self.index_mask,
                oldest_unacked,
                count as u32,
                &mut on_stale_retransmit,
            );
        }
    }

    pub fn clear(&mut self) {
        for page in self.pages.iter_mut() {
            *page = None;
        }
        self.nonempty_pages.fill(0);
        self.nonempty_summary = 0;
        self.len = 0;
        self.retransmit_queued_count = 0;
    }

    pub fn first_occupied_from(&self, start_seq: u32) -> Option<(u32, &T)> {
        if self.is_empty() {
            return None;
        }
        let start = self.physical_index(start_seq);
        self.find_physical(start, self.index_mask + 1)
            .or_else(|| self.find_physical(0, start))
            .and_then(|seq| self.get(seq).map(|pkt| (seq, pkt)))
    }

    pub fn last_occupied_before(&self, end_seq: u32) -> Option<(u32, &T)> {
        if self.is_empty() {
            return None;
        }
        let last = self.physical_index(end_seq.wrapping_sub(1) & SEQUENCE_MASK);
        self.find_physical_rev(0, last + 1)
            .or_else(|| self.find_physical_rev(last + 1, self.index_mask + 1))
            .and_then(|seq| self.get(seq).map(|pkt| (seq, pkt)))
    }

    pub fn iter(&self) -> impl Iterator<Item = (u32, &T)> {
        self.pages.iter().flatten().flat_map(|page| {
            page.slots
                .iter()
                .flatten()
                .map(|slot| (slot.sequence, &slot.packet))
        })
    }

    pub fn values(&self) -> impl Iterator<Item = &T> {
        self.iter().map(|(_, packet)| packet)
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
                let slot_index = occupied.trailing_zeros() as usize;
                return page.slots[slot_index].as_ref().map(|s| s.sequence);
            }
            page_index = self.next_nonempty_page(page_index + 1, last_page + 1)?;
        }
    }

    fn find_physical_rev(&self, start: usize, end: usize) -> Option<u32> {
        if start >= end {
            return None;
        }
        let first_page = start >> PAGE_SHIFT;
        let last_page = (end - 1) >> PAGE_SHIFT;
        for page_index in (first_page..=last_page).rev() {
            let Some(page) = self.pages[page_index].as_ref() else {
                continue;
            };
            let mut occupied = page.occupied;
            if page_index == first_page {
                occupied &= !0u64 << (start & PAGE_MASK);
            }
            if page_index == last_page && end & PAGE_MASK != 0 {
                occupied &= (1u64 << (end & PAGE_MASK)) - 1;
            }
            if occupied != 0 {
                let slot_index = 63 - occupied.leading_zeros() as usize;
                return page.slots[slot_index].as_ref().map(|s| s.sequence);
            }
        }
        None
    }

    fn queue_loss_physical_range(
        &mut self,
        start: usize,
        end: usize,
        first_sequence: u32,
        sequence_count: u32,
        on_newly_queued: &mut impl FnMut(u32),
    ) {
        if start >= end {
            return;
        }
        let first_page = start >> PAGE_SHIFT;
        let last_page = (end - 1) >> PAGE_SHIFT;
        let mut search_page = first_page;
        while let Some(page_index) = self.next_nonempty_page(search_page, last_page + 1) {
            let page = self.pages[page_index]
                .as_mut()
                .expect("summary names an allocated page");
            let mut mask = !0u64;
            if page_index == first_page {
                mask &= !0u64 << (start & PAGE_MASK);
            }
            if page_index == last_page && end & PAGE_MASK != 0 {
                mask &= (1u64 << (end & PAGE_MASK)) - 1;
            }

            let candidates = page.occupied & mask;
            let mut newly_queued = candidates & !page.retransmit_queued;
            while newly_queued != 0 {
                let slot_index = newly_queued.trailing_zeros() as usize;
                newly_queued &= newly_queued - 1;
                let sequence = page.slots[slot_index]
                    .as_ref()
                    .expect("occupied slot exists")
                    .sequence;
                if sequence.wrapping_sub(first_sequence) & SEQUENCE_MASK < sequence_count {
                    page.retransmit_queued |= 1u64 << slot_index;
                    self.retransmit_queued_count += 1;
                    on_newly_queued(sequence);
                }
            }
            search_page = page_index + 1;
        }
    }

    fn discard_full_page(&mut self, page_index: usize, on_stale_retransmit: &mut impl FnMut()) {
        let page = self.pages[page_index].take().expect("page exists");
        let queued_count = page.retransmit_queued.count_ones();
        self.retransmit_queued_count -= queued_count;
        for _ in 0..queued_count {
            on_stale_retransmit();
        }
        self.len -= page.occupied.count_ones() as usize;
        self.mark_page_empty(page_index);
    }

    fn discard_partial_page(
        &mut self,
        page_index: usize,
        mask: u64,
        oldest_unacked: u32,
        count: u32,
        on_stale_retransmit: &mut impl FnMut(),
    ) {
        let page = self.pages[page_index].as_mut().expect("page exists");
        let mut to_remove = page.occupied & mask;
        while to_remove != 0 {
            let slot_index = to_remove.trailing_zeros() as usize;
            to_remove &= to_remove - 1;
            let bit = 1u64 << slot_index;
            let sequence = page.slots[slot_index]
                .as_ref()
                .expect("occupied slot exists")
                .sequence;
            if sequence.wrapping_sub(oldest_unacked) & SEQUENCE_MASK < count {
                page.slots[slot_index] = None;
                page.occupied &= !bit;
                if page.retransmit_queued & bit != 0 {
                    page.retransmit_queued &= !bit;
                    self.retransmit_queued_count -= 1;
                    on_stale_retransmit();
                }
                self.len -= 1;
            }
        }
        if page.occupied == 0 {
            self.pages[page_index] = None;
            self.mark_page_empty(page_index);
        }
    }

    fn discard_physical_prefix(
        &mut self,
        start: usize,
        end: usize,
        oldest_unacked: u32,
        count: u32,
        on_stale_retransmit: &mut impl FnMut(),
    ) {
        if start >= end {
            return;
        }
        let first_page = start >> PAGE_SHIFT;
        let last_page = (end - 1) >> PAGE_SHIFT;
        let mut search_page = first_page;
        while let Some(page_index) = self.next_nonempty_page(search_page, last_page + 1) {
            let is_full_page = (page_index > first_page || start & PAGE_MASK == 0)
                && (page_index < last_page || end & PAGE_MASK == 0);

            if is_full_page {
                self.discard_full_page(page_index, on_stale_retransmit);
            } else {
                let mut mask = !0u64;
                if page_index == first_page {
                    mask &= !0u64 << (start & PAGE_MASK);
                }
                if page_index == last_page && end & PAGE_MASK != 0 {
                    mask &= (1u64 << (end & PAGE_MASK)) - 1;
                }
                self.discard_partial_page(
                    page_index,
                    mask,
                    oldest_unacked,
                    count,
                    on_stale_retransmit,
                );
            }
            search_page = page_index + 1;
        }
    }
}
