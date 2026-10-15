use bytes::Bytes;
use std::fmt;
use std::sync::Arc;

/// Packet handles per independently reclaimed metadata allocation.
pub(crate) const PAYLOAD_PAGE_CHUNKS: usize = 64;
const DIRECTORY_PAGES: usize = 64;
const PAYLOAD_DIRECTORIES: usize =
    crate::srt_handshake::MAX_FLOW_WINDOW as usize / (DIRECTORY_PAGES * PAYLOAD_PAGE_CHUNKS);
type PageDirectory = [Option<Box<PayloadPage>>; DIRECTORY_PAGES];

struct PayloadPage {
    chunks: [Option<Bytes>; PAYLOAD_PAGE_CHUNKS],
}

/// One complete message, retaining its original packet chunks in wire order.
/// Single-packet messages retain the allocation-free `Bytes` representation.
/// Clones share storage; there is no implicit contiguous-message allocation.
#[derive(Clone)]
pub struct ReceivedPayload {
    storage: Storage,
}

#[derive(Clone)]
enum Storage {
    Single(Bytes),
    Paged(Arc<PayloadPages>),
}

/// The root is inline, not a growing vector allocated halfway through a large
/// message. Every heap-owned metadata page is small and independently retired.
#[derive(Default)]
pub(crate) struct PayloadPages {
    first_page: Option<Box<PayloadPage>>,
    directories: [Option<Box<PageDirectory>>; PAYLOAD_DIRECTORIES],
    bytes: usize,
    chunks: usize,
    retained_chunks: usize,
    retained_slots: usize,
}

impl PayloadPages {
    pub(crate) fn push(&mut self, chunk: Bytes) {
        let index = self.chunks;
        let page_index = index / PAYLOAD_PAGE_CHUNKS;
        if index.is_multiple_of(PAYLOAD_PAGE_CHUNKS) {
            let page = Box::new(PayloadPage {
                chunks: std::array::from_fn(|_| None),
            });
            if page_index == 0 {
                self.first_page = Some(page);
            } else {
                let directory = self.directories[page_index / DIRECTORY_PAGES]
                    .get_or_insert_with(|| Box::new(std::array::from_fn(|_| None)));
                directory[page_index % DIRECTORY_PAGES] = Some(page);
            }
        }
        self.bytes += chunk.len();
        self.page_mut(index).chunks[index % PAYLOAD_PAGE_CHUNKS] = Some(chunk);
        self.chunks += 1;
        self.retained_chunks += 1;
        self.retained_slots += 1;
    }

    fn page(&self, index: usize) -> &PayloadPage {
        if index < PAYLOAD_PAGE_CHUNKS {
            self.first_page.as_ref().expect("first payload page")
        } else {
            self.directories[index / (DIRECTORY_PAGES * PAYLOAD_PAGE_CHUNKS)]
                .as_ref()
                .expect("populated directory")[index / PAYLOAD_PAGE_CHUNKS % DIRECTORY_PAGES]
                .as_ref()
                .expect("populated payload page")
        }
    }

    fn page_mut(&mut self, index: usize) -> &mut PayloadPage {
        if index < PAYLOAD_PAGE_CHUNKS {
            self.first_page.as_mut().expect("first payload page")
        } else {
            self.directories[index / (DIRECTORY_PAGES * PAYLOAD_PAGE_CHUNKS)]
                .as_mut()
                .expect("populated directory")[index / PAYLOAD_PAGE_CHUNKS % DIRECTORY_PAGES]
                .as_mut()
                .expect("populated payload page")
        }
    }

    fn take_chunk(&mut self, index: usize) -> Bytes {
        let chunk = self.page_mut(index).chunks[index % PAYLOAD_PAGE_CHUNKS]
            .take()
            .expect("unconsumed packet chunk");
        self.retained_chunks -= 1;
        // Keep empty headers until reverse retirement. A late root metadata free
        // must not coalesce an entire message's heap span in one Owner turn.
        chunk
    }

    pub(crate) fn chunk_count(&self) -> usize {
        self.chunks
    }

    pub(crate) fn finish(self) -> ReceivedPayload {
        ReceivedPayload {
            storage: Storage::Paged(Arc::new(self)),
        }
    }

    pub(crate) fn into_retirement(self) -> PayloadRetirement {
        PayloadRetirement {
            storage: RetirementStorage::Paged(self),
        }
    }

    fn reclaim(&mut self, max_actions: usize) -> usize {
        let mut used = 0;
        while used < max_actions && self.retained_slots != 0 {
            let index = self.retained_slots - 1;
            if let Some(chunk) = self.page_mut(index).chunks[index % PAYLOAD_PAGE_CHUNKS].take() {
                drop(chunk);
                self.retained_chunks -= 1;
            }
            self.retained_slots -= 1;
            used += 1;
            if index.is_multiple_of(PAYLOAD_PAGE_CHUNKS) {
                let page_index = index / PAYLOAD_PAGE_CHUNKS;
                if page_index == 0 {
                    self.first_page = None;
                } else {
                    let directory_index = page_index / DIRECTORY_PAGES;
                    self.directories[directory_index]
                        .as_mut()
                        .expect("retained directory")[page_index % DIRECTORY_PAGES] = None;
                    if page_index == 1 || page_index.is_multiple_of(DIRECTORY_PAGES) {
                        self.directories[directory_index] = None;
                    }
                }
            }
        }
        used
    }
}

impl ReceivedPayload {
    #[must_use]
    pub fn len(&self) -> usize {
        match &self.storage {
            Storage::Single(bytes) => bytes.len(),
            Storage::Paged(pages) => pages.bytes,
        }
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    #[must_use]
    pub fn chunk_count(&self) -> usize {
        match &self.storage {
            Storage::Single(_) => 1,
            Storage::Paged(pages) => pages.chunks,
        }
    }

    pub fn chunks(&self) -> impl DoubleEndedIterator<Item = &Bytes> {
        (0..self.chunk_count()).map(|index| match &self.storage {
            Storage::Single(bytes) => bytes,
            Storage::Paged(pages) => pages.page(index).chunks[index % PAYLOAD_PAGE_CHUNKS]
                .as_ref()
                .expect("immutable message chunk"),
        })
    }

    /// Move unique packet handles; shared messages clone each existing `Bytes`
    /// reference without copying data. Always finish a cursor through `retire`,
    /// including after its last chunk: metadata or shared handles can remain.
    pub fn into_chunks(self) -> PayloadChunks {
        PayloadChunks {
            storage: match self.storage {
                Storage::Single(bytes) => ChunkStorage::Single(Some(bytes)),
                Storage::Paged(pages) => ChunkStorage::Paged { pages, next: 0 },
            },
        }
    }

    /// Transfer final owned storage into bounded owner-local reclamation.
    /// `Arc::into_inner` atomically releases a shared reference or transfers
    /// storage; a failed `try_unwrap` followed by drop would race other owners.
    pub fn retire(self) -> PayloadRetirement {
        match self.storage {
            Storage::Single(bytes) => PayloadRetirement {
                storage: RetirementStorage::Single(Some(bytes)),
            },
            Storage::Paged(pages) => match Arc::into_inner(pages) {
                Some(pages) => pages.into_retirement(),
                None => PayloadRetirement::default(),
            },
        }
    }
}

impl From<Bytes> for ReceivedPayload {
    fn from(bytes: Bytes) -> Self {
        Self {
            storage: Storage::Single(bytes),
        }
    }
}

impl fmt::Debug for ReceivedPayload {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ReceivedPayload")
            .field("bytes", &self.len())
            .field("chunks", &self.chunk_count())
            .finish()
    }
}

impl PartialEq for ReceivedPayload {
    fn eq(&self, other: &Self) -> bool {
        self.len() == other.len()
            && self
                .chunks()
                .flat_map(|chunk| chunk.iter())
                .eq(other.chunks().flat_map(|chunk| chunk.iter()))
    }
}
impl Eq for ReceivedPayload {}

impl PartialEq<[u8]> for ReceivedPayload {
    fn eq(&self, other: &[u8]) -> bool {
        self.len() == other.len()
            && self
                .chunks()
                .flat_map(|chunk| chunk.iter())
                .eq(other.iter())
    }
}

/// Owning packet cursor. `retire` relinquishes both unconsumed chunks and the
/// metadata retained during consumption, without a synchronous whole-tail drop.
pub struct PayloadChunks {
    storage: ChunkStorage,
}
enum ChunkStorage {
    Single(Option<Bytes>),
    Paged {
        pages: Arc<PayloadPages>,
        next: usize,
    },
}

impl PayloadChunks {
    pub fn retire(self) -> PayloadRetirement {
        match self.storage {
            ChunkStorage::Single(bytes) => PayloadRetirement {
                storage: RetirementStorage::Single(bytes),
            },
            ChunkStorage::Paged { pages, .. } => match Arc::into_inner(pages) {
                Some(pages) => pages.into_retirement(),
                None => PayloadRetirement::default(),
            },
        }
    }

    #[must_use]
    pub fn remaining_chunks(&self) -> usize {
        match &self.storage {
            ChunkStorage::Single(bytes) => usize::from(bytes.is_some()),
            ChunkStorage::Paged { pages, next } => pages.chunks - next,
        }
    }
}

impl Iterator for PayloadChunks {
    type Item = Bytes;
    fn next(&mut self) -> Option<Bytes> {
        match &mut self.storage {
            ChunkStorage::Single(bytes) => bytes.take(),
            ChunkStorage::Paged { pages, next } => {
                if *next == pages.chunks {
                    return None;
                }
                let chunk = if let Some(unique) = Arc::get_mut(pages) {
                    unique.take_chunk(*next)
                } else {
                    pages.page(*next).chunks[*next % PAYLOAD_PAGE_CHUNKS]
                        .as_ref()
                        .expect("shared packet chunk")
                        .clone()
                };
                *next += 1;
                Some(chunk)
            }
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let remaining = self.remaining_chunks();
        (remaining, Some(remaining))
    }
}

impl ExactSizeIterator for PayloadChunks {}
impl std::iter::FusedIterator for PayloadChunks {}

/// Physical storage serviced under a fixed action budget on its owning thread.
/// One action retires one original packet slot, including already-consumed slots.
pub struct PayloadRetirement {
    storage: RetirementStorage,
}
enum RetirementStorage {
    Single(Option<Bytes>),
    Paged(PayloadPages),
}

impl Default for PayloadRetirement {
    fn default() -> Self {
        Self {
            storage: RetirementStorage::Single(None),
        }
    }
}

impl PayloadRetirement {
    /// Release at most `max_actions` bounded storage units. Zero does no work.
    pub fn reclaim(&mut self, max_actions: usize) -> usize {
        if max_actions == 0 {
            return 0;
        }
        match &mut self.storage {
            RetirementStorage::Single(bytes) => usize::from(bytes.take().is_some()),
            RetirementStorage::Paged(pages) => pages.reclaim(max_actions),
        }
    }

    #[must_use]
    pub fn is_complete(&self) -> bool {
        match &self.storage {
            RetirementStorage::Single(bytes) => bytes.is_none(),
            RetirementStorage::Paged(pages) => pages.retained_slots == 0,
        }
    }

    #[must_use]
    pub fn remaining_chunks(&self) -> usize {
        match &self.storage {
            RetirementStorage::Single(bytes) => usize::from(bytes.is_some()),
            RetirementStorage::Paged(pages) => pages.retained_chunks,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct TrackedChunk {
        data: [u8; 1],
        freed: Arc<AtomicUsize>,
    }

    impl AsRef<[u8]> for TrackedChunk {
        fn as_ref(&self) -> &[u8] {
            &self.data
        }
    }

    impl Drop for TrackedChunk {
        fn drop(&mut self) {
            self.freed.fetch_add(1, Ordering::SeqCst);
        }
    }

    fn tracked_payload(chunks: usize, freed: &Arc<AtomicUsize>) -> ReceivedPayload {
        let mut pages = PayloadPages::default();
        for index in 0..chunks {
            pages.push(Bytes::from_owner(TrackedChunk {
                data: [index as u8],
                freed: Arc::clone(freed),
            }));
        }
        pages.finish()
    }

    #[test]
    fn retirement_preserves_page_boundaries_and_releases_only_its_budget() {
        let freed = Arc::new(AtomicUsize::new(0));
        let payload = tracked_payload(65, &freed);
        assert_eq!(payload.len(), 65);
        assert_eq!(payload.chunk_count(), 65);
        assert!(
            payload
                .chunks()
                .enumerate()
                .all(|(index, chunk)| chunk.as_ref() == &[index as u8][..])
        );
        let mut retired = payload.retire();
        assert_eq!(retired.reclaim(0), 0);
        assert_eq!(freed.load(Ordering::SeqCst), 0);
        assert_eq!(retired.reclaim(64), 64);
        assert_eq!(freed.load(Ordering::SeqCst), 64);
        assert_eq!(retired.remaining_chunks(), 1);
        assert!(!retired.is_complete());
        assert_eq!(retired.reclaim(1), 1);
        assert_eq!(freed.load(Ordering::SeqCst), 65);
        assert!(retired.is_complete());
        assert_eq!(retired.reclaim(64), 0);
    }

    #[test]
    #[expect(
        clippy::cognitive_complexity,
        reason = "One cancellation trace checks consumption, physical release and metadata retirement together"
    )]
    fn cancelling_a_partly_consumed_owned_cursor_keeps_the_tail_bounded() {
        let freed = Arc::new(AtomicUsize::new(0));
        let mut chunks = tracked_payload(130, &freed).into_chunks();
        for index in 0..67 {
            assert_eq!(chunks.next().unwrap().as_ref(), &[index as u8]);
        }
        assert_eq!(freed.load(Ordering::SeqCst), 67);
        assert_eq!(chunks.remaining_chunks(), 63);
        let mut retired = chunks.retire();
        assert_eq!(retired.reclaim(3), 3);
        assert_eq!(freed.load(Ordering::SeqCst), 70);
        assert_eq!(retired.remaining_chunks(), 60);
        assert_eq!(retired.reclaim(60), 60);
        assert_eq!(retired.remaining_chunks(), 0);
        assert!(
            !retired.is_complete(),
            "consumed page metadata still needs reclamation"
        );
        assert_eq!(retired.reclaim(64), 64);
        assert!(!retired.is_complete());
        assert_eq!(retired.reclaim(3), 3);
        assert!(retired.is_complete());
        assert_eq!(freed.load(Ordering::SeqCst), 130);
    }

    #[test]
    fn a_fully_consumed_cursor_still_retires_metadata_under_the_budget() {
        let freed = Arc::new(AtomicUsize::new(0));
        let mut chunks = tracked_payload(65, &freed).into_chunks();
        for index in 0..65 {
            assert_eq!(chunks.next().unwrap().as_ref(), &[index as u8]);
        }
        assert_eq!(freed.load(Ordering::SeqCst), 65);
        let mut retired = chunks.retire();
        assert_eq!(retired.remaining_chunks(), 0);
        assert!(!retired.is_complete());
        assert_eq!(retired.reclaim(0), 0);
        assert!(!retired.is_complete());
        assert_eq!(retired.reclaim(64), 64);
        assert!(!retired.is_complete());
        assert_eq!(retired.reclaim(1), 1);
        assert!(retired.is_complete());
    }

    #[test]
    fn cancelling_the_final_shared_cursor_reclaims_original_handles_too() {
        let freed = Arc::new(AtomicUsize::new(0));
        let payload = tracked_payload(65, &freed);
        let mut chunks = payload.clone().into_chunks();
        for index in 0..5 {
            assert_eq!(chunks.next().unwrap().as_ref(), &[index as u8]);
        }
        assert_eq!(freed.load(Ordering::SeqCst), 0);
        assert!(payload.retire().is_complete());
        let mut retired = chunks.retire();
        assert_eq!(retired.remaining_chunks(), 65);
        assert_eq!(retired.reclaim(1), 1);
        assert_eq!(freed.load(Ordering::SeqCst), 1);
        assert_eq!(retired.reclaim(64), 64);
        assert!(retired.is_complete());
        assert_eq!(freed.load(Ordering::SeqCst), 65);
    }

    #[test]
    fn simultaneous_final_owners_transfer_storage_to_exactly_one_retirement() {
        let freed = Arc::new(AtomicUsize::new(0));
        let payload = tracked_payload(65, &freed);
        let sibling = payload.clone();
        let barrier = Arc::new(std::sync::Barrier::new(2));
        let retire = |payload: ReceivedPayload, barrier: Arc<std::sync::Barrier>| {
            std::thread::spawn(move || {
                barrier.wait();
                payload.retire()
            })
        };
        let first = retire(payload, Arc::clone(&barrier));
        let second = retire(sibling, barrier);
        let mut first = first.join().unwrap();
        let mut second = second.join().unwrap();
        assert_eq!(freed.load(Ordering::SeqCst), 0);
        assert_eq!(first.remaining_chunks() + second.remaining_chunks(), 65);
        assert_eq!(first.reclaim(1) + second.reclaim(1), 1);
        assert_eq!(freed.load(Ordering::SeqCst), 1);
        assert_eq!(first.reclaim(64) + second.reclaim(64), 64);
        assert_eq!(freed.load(Ordering::SeqCst), 65);
    }
}
