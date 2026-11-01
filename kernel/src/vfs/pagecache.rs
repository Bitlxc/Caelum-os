//! Fixed-size physical page cache for the M5a VFS (agents.md §12.1, §7.4).
//!
//! Scope: this is the read/write cache that makes `read`, `write` and (later)
//! `mmap` observe the same bytes for a file. It owns *only* page frames: it does
//! not know about VNodes, dentries, paths or superblocks — the caller
//! identifies a cached file with [`CacheKey`] (file-system id + node id) and
//! passes the file's current size, because size is metadata owned by the
//! file system, not by the cache.
//!
//! # Shape
//!
//! - Exactly [`CACHE_PAGES`] (512) 4 KiB frames, i.e. 2 MiB, allocated lazily
//!   from the physical frame allocator and reached through the kernel direct
//!   map. No heap, no dynamic arrays, `no_std`.
//! - One frame is one cached file page. Slots are found by a linear scan of the
//!   slot table (512 entries at most); M5a values obvious correctness over
//!   lookup speed, and a hash index can be added later without changing the
//!   API.
//! - No eviction and no writeback in M5a: when all 512 frames are taken, new
//!   pages are refused with [`VfsError::Quota`]. Dirty bits are tracked so M5b
//!   can add writeback/eviction on top of [`dirty_count`], [`mark_clean`] and
//!   [`page_info`] without touching this file's data structures.
//!
//! # Consistency contract
//!
//! - Reads fill a missing page from the file system through the `backing`
//!   callback (a full page, pre-zeroed, so a short file's tail reads as zeros),
//!   or read zeros directly when there is no backing (a sparse hole, e.g. a
//!   ramfs file beyond its data or a gap never written).
//! - Writes are cache-only. They allocate the pages the byte range touches,
//!   update the bytes in place, mark those pages dirty and extend the file size
//!   to the end of the write. They never call `backing` and never touch disk.
//! - `truncate` shrinks by releasing the pages that lie completely beyond the
//!   new size and zeroing the tail of the page that straddles it, so a later
//!   grow-into-the-page cannot expose stale bytes.
//! - `invalidate` releases every page of one file (unlink/rename/remount).
//!
//! # Concurrency / context
//!
//! All entry points mutate one global slot table and must be called by the
//! single M5a CPU with interrupts disabled (`IF=0`); there is no lock and no
//! sleeping. The caller must also hold whatever serialisation the VFS uses for
//! its metadata, so that a `read` and a `truncate` of the same file cannot
//! interleave. The page frames belong to the cache: callers never free them,
//! they only ask the cache to release them.

use crate::vfs::VfsError;

#[cfg(not(test))]
use crate::mm::pmm;

/// Page size used by the cache (agents.md §6.2 keeps this out of ABIs; M5a's
/// x86-64 baseline is 4 KiB).
pub const FRAME_SIZE: u64 = 4096;

/// Number of cached frames. 512 x 4 KiB = 2 MiB, a fixed budget that M5b may
/// grow or make configurable.
pub const CACHE_PAGES: usize = 512;

/// Total cached capacity in bytes.
pub const CACHE_BYTES: u64 = CACHE_PAGES as u64 * FRAME_SIZE;

/// Identifies one cached file: file-system id plus that file system's node id.
///
/// Deliberately not [`crate::vfs::VNodeId`]: the cache must not depend on the
/// VFS object layer, and `(fs, node)` is the key the VFS can build from a
/// `VNodeId` without a back-pointer. The node half is 64 bits since M5b: a
/// ramfs/boot node uses its generation-packed 16-bit id, while a disk node uses
/// the mount's stable disk-node id, which survives a FAT directory-entry move
/// such as `rename` (the inode/cookie changes, the cache key must not).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct CacheKey {
    /// File-system id within the mount namespace.
    pub fs: u16,
    /// Node id within that file system.
    pub node: u64,
}

impl CacheKey {
    /// Build a cache key.
    pub const fn new(fs: u16, node: u64) -> Self {
        Self { fs, node }
    }
}

/// Slot holds a valid frame.
const FLAG_VALID: u8 = 0b0001;
/// Frame content differs from its backing store (M5b writeback work list).
const FLAG_DIRTY: u8 = 0b0010;
/// Frame was allocated by the write call that is currently running; if that
/// call fails, exactly these slots are the ones to roll back.
const FLAG_NEW: u8 = 0b0100;

#[derive(Clone, Copy)]
struct Slot {
    /// Physical address of the frame; meaningful only when `flags & VALID`.
    phys: u64,
    key: CacheKey,
    /// Page index inside the file (`offset / FRAME_SIZE`).
    page: u64,
    flags: u8,
    /// How many eager mappings currently pin this frame (M5c2).
    ///
    /// A pinned frame must not be dropped by `truncate`/`invalidate`; it may
    /// still be written through the cache, so a shared mapping observes file
    /// writes. The counter is bounded by `u16`, and the overflow answer is
    /// [`VfsError::Quota`] rather than a silently wrapped count.
    pins: u16,
}

impl Slot {
    const EMPTY: Slot = Slot {
        phys: 0,
        key: CacheKey::new(0, 0),
        page: 0,
        flags: 0,
        pins: 0,
    };
}

// A slot is bookkeeping only; the frame is the cache. Keeping this assertion
// makes an accidental field addition that doubles the table size visible.
// 8 (phys) + 16 (CacheKey: u16 + pad + u64) + 8 (page) + 1 (flags) + 2 (pins)
// fits the padding after `flags`, so the table stays 40 bytes per slot.
const _: () = assert!(core::mem::size_of::<Slot>() == 40);

/// The whole cache: one flat slot table of `CACHE_PAGES` entries.
static mut SLOTS: [Slot; CACHE_PAGES] = [Slot::EMPTY; CACHE_PAGES];

// ---------------------------------------------------------------------------
// Frame plumbing (prod: PMM + direct map, host test: page-aligned heap arena)
// ---------------------------------------------------------------------------

#[cfg(not(test))]
fn alloc_frame() -> Result<u64, VfsError> {
    pmm::alloc_frame().map_err(|_| VfsError::NoMemory)
}

#[cfg(not(test))]
fn free_frame(phys: u64) {
    // A frame the cache owns must go back to the allocator; if the allocator
    // rejects it the bookkeeping is still dropped (a double free would be a
    // cache bug, not a reason to keep a stale slot alive).
    let _ = pmm::dealloc_frame(phys);
}

#[cfg(not(test))]
fn frame_ptr(phys: u64) -> *mut u8 {
    crate::mm::vm::phys_to_virt(phys) as *mut u8
}

#[cfg(test)]
fn alloc_frame() -> Result<u64, VfsError> {
    host::alloc_frame().ok_or(VfsError::NoMemory)
}

#[cfg(test)]
fn free_frame(phys: u64) {
    host::free_frame(phys);
}

#[cfg(test)]
fn frame_ptr(phys: u64) -> *mut u8 {
    // Host "frames" are ordinary page-aligned heap buffers, so their physical
    // address is their process address.
    phys as *mut u8
}

/// Zero a frame before it becomes visible through the cache.
///
/// # Safety
/// `phys` must be a frame the cache owns and no other reference may exist.
unsafe fn zero_frame(phys: u64) {
    unsafe { core::ptr::write_bytes(frame_ptr(phys), 0, FRAME_SIZE as usize) }
}

// ---------------------------------------------------------------------------
// Slot-table helpers (all take the table explicitly; the public entry points
// pass the static one, host tests could pass their own if needed)
// ---------------------------------------------------------------------------

fn slots() -> &'static mut [Slot; CACHE_PAGES] {
    // SAFETY: M5a runs single-CPU with interrupts disabled; every entry point
    // finishes with the table before returning, so no two borrows overlap.
    unsafe { &mut *core::ptr::addr_of_mut!(SLOTS) }
}

fn find_page(slots: &[Slot; CACHE_PAGES], key: CacheKey, page: u64) -> Option<usize> {
    for (i, slot) in slots.iter().enumerate() {
        if slot.flags & FLAG_VALID != 0 && slot.key == key && slot.page == page {
            return Some(i);
        }
    }
    None
}

fn free_slot_count(slots: &[Slot; CACHE_PAGES]) -> usize {
    slots.iter().filter(|s| s.flags & FLAG_VALID == 0).count()
}

fn insert_page(
    slots: &mut [Slot; CACHE_PAGES],
    key: CacheKey,
    page: u64,
    phys: u64,
    extra_flags: u8,
) -> Result<usize, VfsError> {
    for i in 0..CACHE_PAGES {
        if slots[i].flags & FLAG_VALID == 0 {
            slots[i] = Slot {
                phys,
                key,
                page,
                flags: FLAG_VALID | extra_flags,
                pins: 0,
            };
            return Ok(i);
        }
    }
    Err(VfsError::Quota)
}

/// Release every slot of `key` whose page lies in `from..=to`.
///
/// A pinned page (an eager mapping owns its frame) refuses the release with
/// [`VfsError::Busy`]; the check runs before anything is freed, so a refused
/// call leaves the cache exactly as it was and no data is lost.
fn release_pages(
    slots: &mut [Slot; CACHE_PAGES],
    key: CacheKey,
    from: u64,
    to: u64,
) -> Result<(), VfsError> {
    let affected = |slot: &Slot| {
        slot.flags & FLAG_VALID != 0 && slot.key == key && slot.page >= from && slot.page <= to
    };
    if slots.iter().any(|slot| affected(slot) && slot.pins != 0) {
        return Err(VfsError::Busy);
    }
    for slot in slots.iter_mut() {
        if affected(slot) {
            free_frame(slot.phys);
            *slot = Slot::EMPTY;
        }
    }
    Ok(())
}

/// Undo the frames allocated by the running `write` call.
fn rollback_new(slots: &mut [Slot; CACHE_PAGES], key: CacheKey, from: u64, to: u64) {
    for slot in slots.iter_mut() {
        if slot.flags & (FLAG_VALID | FLAG_NEW) == (FLAG_VALID | FLAG_NEW)
            && slot.key == key
            && slot.page >= from
            && slot.page <= to
        {
            free_frame(slot.phys);
            *slot = Slot::EMPTY;
        }
    }
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Reset the cache. Releases every frame the cache holds and clears the slot
/// table, so a later [`read_with`] starts from an empty cache.
///
/// Called once during VFS initialisation; host tests call it between cases to
/// get a known state. Never fails: releasing a frame cannot be refused in a way
/// the cache could act on.
pub fn init() {
    for owner in owners().iter_mut() {
        *owner = PinOwner::EMPTY;
    }
    let slots = slots();
    for slot in slots.iter_mut() {
        if slot.flags & FLAG_VALID != 0 {
            free_frame(slot.phys);
        }
        *slot = Slot::EMPTY;
    }
    #[cfg(test)]
    host::reset();
}

/// Read `out.len()` bytes of `key` at `offset`, stopping at `file_size`.
///
/// Returns the number of bytes copied. `offset >= file_size`, a zero-length
/// `out`, or a zero-length file all yield `Ok(0)` without allocating a frame.
///
/// A page that is not cached is filled once:
/// - `backing == Some(f)`: allocate a frame, zero it, then call
///   `f(page_start, &mut page)` for the whole 4 KiB page. A short file's tail
///   thus reads as zeros as long as `f` only writes the bytes it has. If `f`
///   fails, the frame is released and the read fails with the same error.
/// - `backing == None`: the range is a hole; zeros are copied straight into
///   `out` and *no* frame is allocated (sparse ramfs files stay sparse).
///
/// # Errors
/// - [`VfsError::NoMemory`]: no physical frame available for a miss.
/// - [`VfsError::Quota`]: the cache is full (512 frames); M5a has no eviction.
/// - [`VfsError::Corrupt`] / whatever `backing` returns: backing read failed.
pub fn read_with(
    key: CacheKey,
    file_size: u64,
    offset: u64,
    out: &mut [u8],
    mut backing: Option<&mut dyn FnMut(u64, &mut [u8]) -> Result<(), VfsError>>,
) -> Result<usize, VfsError> {
    if out.is_empty() || offset >= file_size {
        return Ok(0);
    }
    let slots = slots();
    let want = core::cmp::min(out.len() as u64, file_size - offset);
    let mut copied = 0u64;
    while copied < want {
        // `copied < want <= file_size - offset`, so `pos < file_size` and the
        // page arithmetic cannot overflow.
        let pos = offset + copied;
        let page = pos / FRAME_SIZE;
        let in_page = (pos % FRAME_SIZE) as usize;
        let chunk = core::cmp::min(FRAME_SIZE - in_page as u64, want - copied) as usize;
        let dst = &mut out[copied as usize..copied as usize + chunk];
        let phys = match find_page(slots, key, page) {
            Some(i) => slots[i].phys,
            None => match backing.as_mut() {
                Some(f) => {
                    let phys = alloc_frame()?;
                    unsafe { zero_frame(phys) };
                    let page_start = page * FRAME_SIZE;
                    // SAFETY: freshly allocated frame owned by us, no aliasing
                    // slice survives the call.
                    let buf: &mut [u8] = unsafe {
                        core::slice::from_raw_parts_mut(frame_ptr(phys), FRAME_SIZE as usize)
                    };
                    if let Err(e) = (**f)(page_start, buf) {
                        free_frame(phys);
                        return Err(e);
                    }
                    match insert_page(slots, key, page, phys, 0) {
                        Ok(_) => phys,
                        Err(e) => {
                            free_frame(phys);
                            return Err(e);
                        }
                    }
                }
                None => {
                    // Hole: zeros, and do not allocate a frame for it.
                    for b in dst.iter_mut() {
                        *b = 0;
                    }
                    copied += chunk as u64;
                    continue;
                }
            },
        };
        // SAFETY: `phys` is a valid frame; the copy stays inside the frame
        // (`in_page + chunk <= FRAME_SIZE`) and inside `out`.
        unsafe {
            core::ptr::copy_nonoverlapping(frame_ptr(phys).add(in_page), dst.as_mut_ptr(), chunk);
        }
        copied += chunk as u64;
    }
    Ok(copied as usize)
}

/// Write `data` at `offset` into the cache for `key` (memory-only backing).
///
/// Thin wrapper around [`write_with`] with no backing store: a page that is not
/// resident is treated as a hole and starts out zeroed.
pub fn write(key: CacheKey, offset: u64, data: &[u8], file_size: u64) -> Result<u64, VfsError> {
    write_with(key, offset, data, file_size, None)
}

/// Write `data` at `offset` into the cache for `key`, filling new pages from
/// `backing` first.
///
/// Only the pages the byte range touches are allocated (already cached pages are
/// reused and never re-read from `backing`). A page that is not resident yet is
/// zeroed and then filled completely by `backing(page_start, &mut frame)` before
/// the new bytes are copied in — so a partial write to a disk file cannot zero
/// the untouched tail of that page. `backing == None` means the bytes outside
/// the written range are holes and stay zero (ramfs and `/boot` payloads).
///
/// Allocation happens before any byte is written: if capacity, the frame
/// allocator or `backing` fails, every frame this call allocated is released
/// again and the previously cached bytes are untouched, so a failed write
/// leaves the file exactly as it was.
///
/// Returns the new file size, `max(file_size, offset + data.len())`. The cache
/// does not store sizes; the caller applies the returned value to its metadata.
///
/// # Errors
/// - [`VfsError::BadOffset`]: `offset + data.len()` overflows.
/// - [`VfsError::Quota`]: the cache cannot hold the newly touched pages.
/// - [`VfsError::NoMemory`]: no physical frame available.
/// - whatever `backing` reports for a page it cannot fill.
pub fn write_with(
    key: CacheKey,
    offset: u64,
    data: &[u8],
    file_size: u64,
    mut backing: Option<&mut dyn FnMut(u64, &mut [u8]) -> Result<(), VfsError>>,
) -> Result<u64, VfsError> {
    if data.is_empty() {
        return Ok(file_size);
    }
    let end = offset
        .checked_add(data.len() as u64)
        .ok_or(VfsError::BadOffset)?;
    let new_size = core::cmp::max(file_size, end);
    let first = offset / FRAME_SIZE;
    let last = (end - 1) / FRAME_SIZE;
    let slots = slots();

    // Phase 1: capacity. Refuse before allocating anything so a full cache does
    // not disturb pages it already holds.
    let mut needed = 0usize;
    let mut page = first;
    while page <= last {
        if find_page(slots, key, page).is_none() {
            needed += 1;
        }
        page += 1;
    }
    if needed > free_slot_count(slots) {
        return Err(VfsError::Quota);
    }

    // Phase 2: allocate the missing pages (zeroed, then filled from `backing`);
    // roll back on the first failure.
    page = first;
    while page <= last {
        if find_page(slots, key, page).is_none() {
            let phys = match alloc_frame() {
                Ok(phys) => phys,
                Err(e) => {
                    if page > first {
                        rollback_new(slots, key, first, page - 1);
                    }
                    return Err(e);
                }
            };
            // SAFETY: fresh frame, exclusively ours.
            unsafe { zero_frame(phys) };
            if let Some(fill) = backing.as_mut() {
                let page_start = page * FRAME_SIZE;
                // SAFETY: `phys` is ours and the slice covers exactly its frame.
                let frame = unsafe {
                    core::slice::from_raw_parts_mut(frame_ptr(phys), FRAME_SIZE as usize)
                };
                if let Err(error) = fill(page_start, frame) {
                    free_frame(phys);
                    if page > first {
                        rollback_new(slots, key, first, page - 1);
                    }
                    return Err(error);
                }
            }
            if insert_page(slots, key, page, phys, FLAG_NEW).is_err() {
                free_frame(phys);
                if page > first {
                    rollback_new(slots, key, first, page - 1);
                }
                return Err(VfsError::Quota);
            }
        }
        page += 1;
    }

    // Phase 3: copy the bytes and mark every touched page dirty.
    let mut done = 0usize;
    while done < data.len() {
        let pos = offset + done as u64;
        let page = pos / FRAME_SIZE;
        let in_page = (pos % FRAME_SIZE) as usize;
        let chunk = core::cmp::min((FRAME_SIZE - in_page as u64) as usize, data.len() - done);
        let i = find_page(slots, key, page).ok_or(VfsError::Corrupt)?;
        let phys = slots[i].phys;
        // SAFETY: `phys` is a frame of this slot, `in_page + chunk <= FRAME_SIZE`.
        unsafe {
            core::ptr::copy_nonoverlapping(
                data.as_ptr().add(done),
                frame_ptr(phys).add(in_page),
                chunk,
            );
        }
        slots[i].flags |= FLAG_DIRTY;
        done += chunk;
    }

    // Phase 4: the pages are committed; drop the rollback markers.
    page = first;
    while page <= last {
        if let Some(i) = find_page(slots, key, page) {
            slots[i].flags &= !FLAG_NEW;
        }
        page += 1;
    }
    Ok(new_size)
}

/// Shrink `key` from `old_size` to `new_size`.
///
/// Pages that lie completely beyond `new_size` are released, and the tail of the
/// page that straddles `new_size` is zeroed (and marked dirty) so that a later
/// write/extend into that page cannot expose bytes of the old, longer file.
///
/// `new_size >= old_size` is a no-op that returns `new_size`; growing a file is
/// the writer's business (`write` returns the new size) and does not need
/// frames here. Returns the new size.
///
/// # Errors
/// The call itself cannot fail; `Result` keeps room for M5b writeback, which may
/// need to flush dirty pages before dropping them.
pub fn truncate(key: CacheKey, old_size: u64, new_size: u64) -> Result<u64, VfsError> {
    let slots = slots();
    if new_size >= old_size {
        return Ok(new_size);
    }
    // Shrinking both drops pages past the new end and zeroes the tail of the
    // page the new end falls in; neither is allowed to touch a pinned frame.
    check_shrinkable_in(slots, key, new_size)?;
    release_pages(slots, key, new_size.div_ceil(FRAME_SIZE), u64::MAX)?;
    let tail = new_size % FRAME_SIZE;
    if tail != 0 {
        if let Some(i) = find_page(slots, key, new_size / FRAME_SIZE) {
            let phys = slots[i].phys;
            // SAFETY: `tail` bytes are kept, the rest of the frame is ours.
            unsafe {
                core::ptr::write_bytes(
                    frame_ptr(phys).add(tail as usize),
                    0,
                    (FRAME_SIZE - tail) as usize,
                )
            };
            slots[i].flags |= FLAG_DIRTY;
        }
    }
    Ok(new_size)
}

/// Drop every cached page of `key`.
///
/// Used when a file is unlinked, renamed over, or a file system is unmounted.
/// Idempotent: an uncached key is `Ok(())`.
///
/// # Errors
/// Currently none; kept fallible for the M5b writeback path.
pub fn invalidate(key: CacheKey) -> Result<(), VfsError> {
    let slots = slots();
    release_pages(slots, key, 0, u64::MAX)
}

/// Clear the dirty bit of the cached pages of `key` that lie completely below
/// `upto` (the M5b writeback hook). A partially written-back page stays dirty.
pub fn mark_clean(key: CacheKey, upto: u64) {
    let slots = slots();
    for slot in slots.iter_mut() {
        if slot.flags & FLAG_VALID != 0 && slot.key == key {
            let page_end = slot.page.saturating_add(1).saturating_mul(FRAME_SIZE);
            if page_end <= upto {
                slot.flags &= !FLAG_DIRTY;
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Write-back (M5b)
// ---------------------------------------------------------------------------

/// Immutable view of the frame holding `phys`.
///
/// # Safety
/// `phys` must be a frame the cache owns; the returned slice must not outlive
/// the call (the caller immediately hands it to the backing store).
unsafe fn frame_slice(phys: u64) -> &'static [u8] {
    unsafe { core::slice::from_raw_parts(frame_ptr(phys), FRAME_SIZE as usize) }
}

/// Walk dirty resident pages selected by `key`, hand each one to `write` and
/// clear its dirty bit only after `write` succeeded.
///
/// `write` receives the full 4 KiB frame (the caller trims the tail of the last
/// page to the file size, because the cache does not know file sizes). The first
/// error stops the pass: the failing page and every following page stay dirty,
/// so a retry after the error condition clears can make progress, and a failed
/// write-back can never be mistaken for a clean cache.
fn writeback_pass<F>(key: Option<CacheKey>, mut write: F) -> Result<usize, VfsError>
where
    F: FnMut(CacheKey, u64, &[u8]) -> Result<(), VfsError>,
{
    let slots = slots();
    let mut written = 0usize;
    for index in 0..CACHE_PAGES {
        let slot = slots[index];
        if slot.flags & (FLAG_VALID | FLAG_DIRTY) != (FLAG_VALID | FLAG_DIRTY) {
            continue;
        }
        if let Some(wanted) = key {
            if slot.key != wanted {
                continue;
            }
        }
        let page_start = slot.page.saturating_mul(FRAME_SIZE);
        // SAFETY: `slot` is a valid resident cache frame owned by the cache; the
        // slice is used only for the duration of this iteration and the VFS
        // runs single-CPU with IF=0, so nothing else can free or mutate it.
        let data = unsafe { frame_slice(slot.phys) };
        write(slot.key, page_start, data)?;
        // The closure talks to the block device only and cannot touch the slot
        // table, so clearing the dirty bit afterwards is safe.
        slots[index].flags &= !FLAG_DIRTY;
        written += 1;
    }
    Ok(written)
}

/// Write back every dirty cached page of `key` through `write`.
///
/// Returns the number of pages written. Pages stay dirty on failure.
pub fn writeback_key<F>(key: CacheKey, mut write: F) -> Result<usize, VfsError>
where
    F: FnMut(u64, &[u8]) -> Result<(), VfsError>,
{
    writeback_pass(Some(key), |_, page_start, data| write(page_start, data))
}

/// Write back every dirty cached page through `write` (mount-wide flush).
///
/// Returns the number of pages written. Pages stay dirty on failure.
pub fn writeback_all<F>(mut write: F) -> Result<usize, VfsError>
where
    F: FnMut(CacheKey, u64, &[u8]) -> Result<(), VfsError>,
{
    writeback_pass(None, &mut write)
}

/// Number of cached frames.
pub fn allocated_count() -> usize {
    let slots = slots();
    slots.iter().filter(|s| s.flags & FLAG_VALID != 0).count()
}

/// Number of cached frames whose content is newer than their backing store.
pub fn dirty_count() -> usize {
    let slots = slots();
    slots
        .iter()
        .filter(|s| s.flags & (FLAG_VALID | FLAG_DIRTY) == (FLAG_VALID | FLAG_DIRTY))
        .count()
}

/// Number of frames still available.
pub fn free_count() -> usize {
    let slots = slots();
    free_slot_count(slots)
}

/// Fixed capacity in pages.
pub const fn capacity_pages() -> usize {
    CACHE_PAGES
}

/// Fixed capacity in bytes.
pub const fn capacity_bytes() -> u64 {
    CACHE_BYTES
}

/// Is page `page` of `key` currently cached?
pub fn is_resident(key: CacheKey, page: u64) -> bool {
    find_page(slots(), key, page).is_some()
}

/// Number of pages of `key` currently cached.
pub fn resident_pages(key: CacheKey) -> usize {
    let slots = slots();
    slots
        .iter()
        .filter(|s| s.flags & FLAG_VALID != 0 && s.key == key)
        .count()
}

// ---------------------------------------------------------------------------
// Eager-mapping pin ownership (M5c2 rework)
// ---------------------------------------------------------------------------

/// Upper bound on pin records: at most one record per (description, page).
///
/// The cache itself only holds `CACHE_PAGES` frames, so 512 records cover every
/// frame being pinned once. The ledger is a fixed array and never allocates; a
/// 513th record is [`VfsError::Quota`].
const MAX_PIN_OWNERS: usize = 512;

/// One page pinned by one open description.
///
/// The owner is the raw `OpenId`: a `dup`'d mapping shares the description, so it
/// also shares the ledger entry, and the final `close` can release exactly the
/// pins the description still holds without touching another description that
/// pins the same page.
#[derive(Clone, Copy)]
struct PinOwner {
    used: bool,
    open: u16,
    page: u32,
    key: CacheKey,
}

impl PinOwner {
    const EMPTY: PinOwner = PinOwner {
        used: false,
        open: 0,
        page: 0,
        key: CacheKey::new(0, 0),
    };
}

static mut PIN_OWNERS: [PinOwner; MAX_PIN_OWNERS] = [PinOwner::EMPTY; MAX_PIN_OWNERS];

fn owners() -> &'static mut [PinOwner; MAX_PIN_OWNERS] {
    // SAFETY: single-CPU, IF=0 contract; host tests serialise via `test_lock`.
    unsafe { &mut *core::ptr::addr_of_mut!(PIN_OWNERS) }
}

fn owner_of(
    owners: &[PinOwner; MAX_PIN_OWNERS],
    open: u16,
    key: CacheKey,
    page: u64,
) -> Option<usize> {
    owners.iter().position(|owner| {
        owner.used && owner.open == open && owner.key == key && u64::from(owner.page) == page
    })
}

/// Would releasing `key` drop a pinned page?
///
/// This is the dry run unlink/rename/unmount perform **before** they change any
/// file system or VNode state, so a refused call leaves both sides untouched.
pub(crate) fn check_releasable(key: CacheKey) -> Result<(), VfsError> {
    let pinned = slots()
        .iter()
        .any(|slot| slot.flags & FLAG_VALID != 0 && slot.key == key && slot.pins != 0);
    if pinned { Err(VfsError::Busy) } else { Ok(()) }
}

/// Drop every pin that belongs to `open` (the last `close` does this).
///
/// Returns how many records were released. This has no failure mode on purpose:
/// the object destroy hook has no error channel, and leaving a pin behind would
/// leak a frame forever.
pub(crate) fn release_owner(open: u16) -> usize {
    let owners = owners();
    let slots = slots();
    let mut released = 0usize;
    for owner in owners.iter_mut() {
        if !owner.used || owner.open != open {
            continue;
        }
        owner.used = false;
        if let Some(index) = find_page(slots, owner.key, u64::from(owner.page)) {
            if slots[index].pins != 0 {
                slots[index].pins -= 1;
            }
        }
        released += 1;
    }
    released
}

/// Pins currently recorded for `open` (host tests and diagnostics).
#[cfg(test)]
pub(crate) fn owner_pins(open: u16) -> usize {
    owners()
        .iter()
        .filter(|owner| owner.used && owner.open == open)
        .count()
}

/// Would shrinking `key` to `new_size` release or rewrite a pinned page?
///
/// Used by the VFS *before* it mutates a file system, because a disk truncate
/// has already touched the volume by the time the page cache is asked to shrink.
/// Leaves everything untouched on [`VfsError::Busy`].
pub(crate) fn check_shrinkable(key: CacheKey, new_size: u64) -> Result<(), VfsError> {
    check_shrinkable_in(slots(), key, new_size)
}

fn check_shrinkable_in(
    slots: &[Slot; CACHE_PAGES],
    key: CacheKey,
    new_size: u64,
) -> Result<(), VfsError> {
    let first_dropped = new_size.div_ceil(FRAME_SIZE);
    let tail = new_size % FRAME_SIZE;
    let affected = |slot: &Slot| {
        slot.flags & FLAG_VALID != 0
            && slot.key == key
            && (slot.page >= first_dropped || (tail != 0 && slot.page == new_size / FRAME_SIZE))
    };
    if slots.iter().any(|slot| affected(slot) && slot.pins != 0) {
        return Err(VfsError::Busy);
    }
    Ok(())
}

/// Make the page that holds `offset` resident and return its physical address.
///
/// Unlike [`read_with`], a hole is given a real (zeroed) frame: a sparse page
/// that is about to be mapped needs memory the mapping can point at. `backing`
/// fills the frame when the file has bytes there; it only has to write the bytes
/// it owns, because the frame was zeroed first.
pub(crate) fn materialise(
    key: CacheKey,
    file_size: u64,
    offset: u64,
    mut backing: Option<&mut dyn FnMut(u64, &mut [u8]) -> Result<(), VfsError>>,
) -> Result<u64, VfsError> {
    if offset >= file_size {
        return Err(VfsError::BadOffset);
    }
    let page = offset / FRAME_SIZE;
    let slots = slots();
    if let Some(index) = find_page(slots, key, page) {
        return Ok(slots[index].phys);
    }
    let phys = alloc_frame()?;
    // SAFETY: the frame is freshly allocated and owned by the cache.
    unsafe { zero_frame(phys) };
    if let Some(fill) = backing.as_mut() {
        // SAFETY: `frame_ptr` is a direct-map pointer to a live 4 KiB frame.
        let buf = unsafe { core::slice::from_raw_parts_mut(frame_ptr(phys), FRAME_SIZE as usize) };
        if let Err(error) = (**fill)(page * FRAME_SIZE, buf) {
            free_frame(phys);
            return Err(error);
        }
    }
    if let Err(error) = insert_page(slots, key, page, phys, 0) {
        free_frame(phys);
        return Err(error);
    }
    Ok(phys)
}

/// Pin the frame that backs (`key`, `page`) and return its physical address.
///
/// The page must already be resident; the VFS materialises it through
/// [`materialise`] (which runs the backing store and gives holes a frame) right
/// before calling this. A
/// pinned frame is never freed by [`truncate`]/[`invalidate`] — they answer
/// [`VfsError::Busy`] instead — but pinning does **not** block [`write`] or
/// [`writeback_key`]: a shared mapping is supposed to see file writes.
///
/// Every successful pin must be undone by exactly one [`unpin_page`]. The
/// counter is `u16`-bounded; overflow is [`VfsError::Quota`].
pub(crate) fn pin_page(open: u16, key: CacheKey, page: u64) -> Result<u64, VfsError> {
    let page32 = u32::try_from(page).map_err(|_| VfsError::BadOffset)?;
    // Reserve the ledger record before touching the cache, so a full ledger does
    // not leave an unowned pin behind.
    let record = owners()
        .iter()
        .position(|owner| !owner.used)
        .ok_or(VfsError::Quota)?;
    let slots = slots();
    let index = find_page(slots, key, page).ok_or(VfsError::NotFound)?;
    slots[index].pins = slots[index].pins.checked_add(1).ok_or(VfsError::Quota)?;
    let phys = slots[index].phys;
    owners()[record] = PinOwner {
        used: true,
        open,
        page: page32,
        key,
    };
    Ok(phys)
}

/// Undo one [`pin_page`]. Unpinning a page that is not resident, or whose count
/// is already zero, is a caller bug and answers [`VfsError::NotFound`].
pub(crate) fn unpin_page(open: u16, key: CacheKey, page: u64) -> Result<(), VfsError> {
    let owners = owners();
    let record = owner_of(owners, open, key, page).ok_or(VfsError::NotFound)?;
    let slots = slots();
    let index = find_page(slots, key, page).ok_or(VfsError::NotFound)?;
    if slots[index].pins == 0 {
        return Err(VfsError::NotFound);
    }
    slots[index].pins -= 1;
    owners[record].used = false;
    Ok(())
}

/// Copy the resident page (`key`, `page`) into `dst_phys`, zeroing everything
/// past `valid_len` bytes (the file's end-of-file tail inside that page).
///
/// Both ends are direct-mapped frames, so the copy runs from frame to frame and
/// never needs a 4 KiB stack buffer. Used by private `mmap`.
pub(crate) fn copy_page_to(
    key: CacheKey,
    page: u64,
    valid_len: usize,
    dst_phys: u64,
) -> Result<(), VfsError> {
    if dst_phys == 0 || dst_phys % FRAME_SIZE != 0 || valid_len > FRAME_SIZE as usize {
        return Err(VfsError::BadOffset);
    }
    let slots = slots();
    let index = find_page(slots, key, page).ok_or(VfsError::NotFound)?;
    let src = frame_ptr(slots[index].phys);
    let dst = frame_ptr(dst_phys);
    // A private mapping is supposed to hand in its own frame, but pinning can
    // legally make the two coincide (`copy_file_page(open, 0, pinned_phys)`).
    // `copy_nonoverlapping` would be UB there, so a self-copy only enforces the
    // end-of-file tail rule.
    // SAFETY: both frames are cache/caller owned, the prefix stays inside each
    // frame and the zeroed tail covers the rest of `dst`.
    unsafe {
        if !core::ptr::eq(src, dst) {
            core::ptr::copy_nonoverlapping(src, dst, valid_len);
        }
        core::ptr::write_bytes(dst.add(valid_len), 0, FRAME_SIZE as usize - valid_len);
    }
    Ok(())
}

/// Mark an already-resident page dirty without allocating or flushing it.
///
/// A shared mapping writes straight into the pinned frame, so the page cache
/// never sees those bytes; the mapping layer calls this before it lets go of the
/// page, and a later `sync` writes them back. A page that is not resident is a
/// caller bug ([`VfsError::NotFound`]) — this never reads the backing store.
pub(crate) fn mark_dirty(key: CacheKey, page: u64) -> Result<(), VfsError> {
    let slots = slots();
    let index = find_page(slots, key, page).ok_or(VfsError::NotFound)?;
    slots[index].flags |= FLAG_DIRTY;
    Ok(())
}

/// Number of pins on a frame (host tests and diagnostics).
#[cfg(test)]
pub(crate) fn pinned_count(key: CacheKey, page: u64) -> u16 {
    let slots = slots();
    find_page(slots, key, page).map_or(0, |index| slots[index].pins)
}

/// Physical address and dirty state of a cached page, for M5b writeback.
///
/// Returns `None` when the page is not cached. The physical address is stable
/// while the page stays resident.
pub fn page_info(key: CacheKey, page: u64) -> Option<(u64, bool)> {
    let slots = slots();
    find_page(slots, key, page).map(|i| (slots[i].phys, slots[i].flags & FLAG_DIRTY != 0))
}

// ---------------------------------------------------------------------------
// Host-test frame arena
//
// The kernel frame allocator needs `pmm::init`, so host tests use page-aligned
// heap buffers as "frames" and their process address as the physical address.
// `LIVE` tracks every outstanding frame: a test can assert that the cache did
// not leak a frame on an error path.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod host {
    use std::alloc::{Layout, alloc_zeroed, dealloc};
    use std::sync::Mutex;
    use std::vec::Vec;

    fn layout() -> Layout {
        Layout::from_size_align(4096, 4096).expect("static frame layout")
    }

    static LIVE: Mutex<Vec<u64>> = Mutex::new(Vec::new());

    pub fn alloc_frame() -> Option<u64> {
        // SAFETY: the layout is valid (power-of-two size, non-zero).
        let ptr = unsafe { alloc_zeroed(layout()) };
        if ptr.is_null() {
            return None;
        }
        LIVE.lock().expect("host arena mutex").push(ptr as u64);
        Some(ptr as u64)
    }

    pub fn free_frame(phys: u64) {
        let mut live = LIVE.lock().expect("host arena mutex");
        if let Some(pos) = live.iter().position(|&p| p == phys) {
            live.swap_remove(pos);
            // SAFETY: `phys` came from `alloc_frame` with the same layout and
            // is no longer tracked.
            unsafe { dealloc(phys as *mut u8, layout()) };
        }
    }

    pub fn reset() {
        let mut live = LIVE.lock().expect("host arena mutex");
        for phys in live.drain(..) {
            // SAFETY: as in `free_frame`.
            unsafe { dealloc(phys as *mut u8, layout()) };
        }
    }

    pub fn live_count() -> usize {
        LIVE.lock().expect("host arena mutex").len()
    }
}

// ---------------------------------------------------------------------------
// Host tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// All cache state is global static; `vfs::test_lock` serialises these tests
    /// against each other (and against `vfs::selftest`) so frames and slots are
    /// not shared concurrently.
    fn setup() -> std::sync::MutexGuard<'static, ()> {
        let guard = crate::vfs::test_lock();
        init();
        guard
    }

    const FS: u16 = 7;
    const KEY: CacheKey = CacheKey::new(FS, 1);

    /// Backing hook used by the tests: fills a page with a pattern derived from
    /// the page's *byte offset*, so a wrong page address shows up as wrong data.
    fn fill_backing(page_start: u64, buf: &mut [u8]) -> Result<(), VfsError> {
        for (i, b) in buf.iter_mut().enumerate() {
            *b = ((page_start as usize).wrapping_add(i) & 0xFF) as u8;
        }
        Ok(())
    }

    /// Deterministic non-zero page content whose every byte differs from zero,
    /// so a zeroed frame or a stray byte write is visible in the assertions.
    fn patterned_page(seed: u8) -> std::vec::Vec<u8> {
        let mut page = std::vec![0u8; FRAME_SIZE as usize];
        for (i, b) in page.iter_mut().enumerate() {
            *b = ((i as u8) ^ seed).wrapping_add(0x31);
        }
        page
    }

    #[test]
    fn init_resets_slots_and_frames() {
        let _g = setup();
        write(KEY, 0, &[1u8; 32], 0).unwrap();
        assert_eq!(allocated_count(), 1);
        init();
        assert_eq!(allocated_count(), 0);
        assert_eq!(dirty_count(), 0);
        assert_eq!(host::live_count(), 0);
        assert_eq!(free_count(), CACHE_PAGES);
    }

    #[test]
    fn miss_with_backing_fills_page_and_caches_it() {
        let _g = setup();
        let calls = std::cell::Cell::new(0u32);
        let mut backing = |page: u64, buf: &mut [u8]| {
            calls.set(calls.get() + 1);
            fill_backing(page, buf)
        };
        let mut out = [0u8; 16];
        let n = read_with(KEY, 8192, 0, &mut out, Some(&mut backing)).unwrap();
        assert_eq!(n, 16);
        assert_eq!(calls.get(), 1);
        assert_eq!(out[0], 0);
        assert_eq!(out[3], 3);
        assert_eq!(allocated_count(), 1);
        assert_eq!(host::live_count(), 1);

        // Second read hits the cache: no backing call.
        let mut out2 = [0u8; 16];
        let n = read_with(KEY, 8192, 0, &mut out2, Some(&mut backing)).unwrap();
        assert_eq!(n, 16);
        assert_eq!(out2, out);
        assert_eq!(calls.get(), 1);
    }

    #[test]
    fn hole_without_backing_reads_zeros_without_allocating() {
        let _g = setup();
        let mut out = [0xAAu8; 32];
        let n = read_with(KEY, 4096, 0, &mut out, None).unwrap();
        assert_eq!(n, 32);
        assert!(out.iter().all(|&b| b == 0));
        assert_eq!(allocated_count(), 0);
        assert_eq!(host::live_count(), 0);
    }

    #[test]
    fn read_crosses_pages_and_stops_at_eof() {
        let _g = setup();
        // Three-page file, all resident from backing, read across 1K -> 2K.
        let mut backing = fill_backing;
        let mut whole = [0u8; 3 * 4096];
        let n = read_with(KEY, 3 * 4096, 0, &mut whole, Some(&mut backing)).unwrap();
        assert_eq!(n, 3 * 4096);
        assert_eq!(allocated_count(), 3);

        let mut out = [0u8; 4096];
        let n = read_with(KEY, 3 * 4096, 4096 - 8, &mut out, None).unwrap();
        assert_eq!(n, 4096); // 8 bytes from page 0, 4088 from page 1
        for (i, b) in out.iter().enumerate().take(8) {
            // Page 0, offset 4088 + i: backing value = (4088 + i) & 0xFF.
            assert_eq!(*b, (4088 + i as u64) as u8);
        }
        // Page 1 starts at byte 4096: out[8 + k] is byte 4096 + k.
        for (i, b) in out.iter().enumerate().skip(8) {
            assert_eq!(*b, ((i - 8) & 0xFF) as u8);
        }
        // EOF: read past the end returns Ok(0) and allocates nothing new.
        let n = read_with(KEY, 3 * 4096, 3 * 4096, &mut out, None).unwrap();
        assert_eq!(n, 0);
        // Truncated by EOF instead of out length.
        let n = read_with(KEY, 3 * 4096, 3 * 4096 - 10, &mut out, None).unwrap();
        assert_eq!(n, 10);
    }

    #[test]
    fn read_eof_and_empty_out_allocate_nothing() {
        let _g = setup();
        let mut out = [0u8; 8];
        assert_eq!(read_with(KEY, 0, 0, &mut out, None).unwrap(), 0);
        assert_eq!(read_with(KEY, 4096, 4096, &mut out, None).unwrap(), 0);
        assert_eq!(read_with(KEY, 4096, 9000, &mut out, None).unwrap(), 0);
        assert_eq!(read_with(KEY, 4096, 0, &mut [], None).unwrap(), 0);
        assert_eq!(allocated_count(), 0);
        assert_eq!(host::live_count(), 0);
    }

    #[test]
    fn write_allocates_only_touched_pages() {
        let _g = setup();
        // Bytes 4090..4110 touch pages 0 and 1 only.
        let data = [0x5Au8; 20];
        let new_size = write(KEY, 4090, &data, 0).unwrap();
        assert_eq!(new_size, 4110);
        assert_eq!(allocated_count(), 2);
        assert_eq!(resident_pages(KEY), 2);
        assert_eq!(dirty_count(), 2);
        assert!(!is_resident(KEY, 2));

        // Read back without backing: page 0 bytes 4090..4096 and page 1 0..14.
        let mut out = [0u8; 20];
        let n = read_with(KEY, new_size, 4090, &mut out, None).unwrap();
        assert_eq!(n, 20);
        assert!(out.iter().all(|&b| b == 0x5A));
        // The untouched head of page 0 stays zero.
        let mut head = [0xAAu8; 4];
        read_with(KEY, new_size, 4086, &mut head, None).unwrap();
        assert_eq!(head, [0, 0, 0, 0]);

        // A write fully inside one cached page allocates nothing new.
        write(KEY, 4100, b"ab", new_size).unwrap();
        assert_eq!(allocated_count(), 2);
        let mut two = [0u8; 2];
        read_with(KEY, 4110, 4100, &mut two, None).unwrap();
        assert_eq!(&two, b"ab");
    }

    #[test]
    fn write_keeps_neighbour_bytes_inside_touched_page() {
        let _g = setup();
        let original = patterned_page(0x00);
        write(KEY, 0, &original, 0).unwrap();
        assert_eq!(resident_pages(KEY), 1);

        let mut back = std::vec![0u8; FRAME_SIZE as usize];
        let n = read_with(KEY, FRAME_SIZE, 0, &mut back, None).unwrap();
        assert_eq!(n as u64, FRAME_SIZE);
        assert_eq!(back, original, "initial page content must round-trip");

        // Unaligned 5-byte patch in the middle of page 0.
        let patch = [0x11u8, 0x22, 0x33, 0x44, 0x55];
        let start = 101usize;
        let end = start + patch.len();
        write(KEY, start as u64, &patch, FRAME_SIZE).unwrap();
        let mut after = std::vec![0u8; FRAME_SIZE as usize];
        read_with(KEY, FRAME_SIZE, 0, &mut after, None).unwrap();
        assert_eq!(
            &after[..start],
            &original[..start],
            "bytes before the write moved"
        );
        assert_eq!(&after[start..end], &patch, "written bytes are wrong");
        assert_eq!(
            &after[end..],
            &original[end..],
            "bytes after the write moved"
        );
        assert_eq!(allocated_count(), 1, "an in-page write must not allocate");

        // A second unaligned write in the same page must disturb neither the
        // first patch nor any byte it did not touch.
        let second = [0x77u8, 0x88, 0x99];
        let second_end = 300usize + second.len();
        write(KEY, 300, &second, FRAME_SIZE).unwrap();
        let mut after_second = std::vec![0u8; FRAME_SIZE as usize];
        read_with(KEY, FRAME_SIZE, 0, &mut after_second, None).unwrap();
        assert_eq!(&after_second[..start], &original[..start]);
        assert_eq!(&after_second[start..end], &patch);
        assert_eq!(
            &after_second[end..300],
            &original[end..300],
            "gap between the two writes moved"
        );
        assert_eq!(&after_second[300..second_end], &second);
        assert_eq!(
            &after_second[second_end..],
            &original[second_end..],
            "tail after the second write moved"
        );
        assert_eq!(
            allocated_count(),
            1,
            "the second in-page write must not allocate"
        );

        // Reading the neighbours must not disturb them either: the read path
        // never writes into a resident frame.
        let mut around = std::vec![0u8; 8];
        read_with(KEY, FRAME_SIZE, (start - 4) as u64, &mut around, None).unwrap();
        assert_eq!(&around[..4], &original[start - 4..start]);
        assert_eq!(&around[4..], &patch[..4]);
    }

    #[test]
    fn write_keeps_neighbour_bytes_across_page_boundary() {
        let _g = setup();
        let page0 = patterned_page(0x00);
        let page1 = patterned_page(0x80);
        write(KEY, 0, &page0, 0).unwrap();
        write(KEY, FRAME_SIZE, &page1, FRAME_SIZE).unwrap();
        assert_eq!(resident_pages(KEY), 2);

        // Unaligned patch straddling the 4 KiB boundary: 2 bytes at the end of
        // page 0 and 2 bytes at the start of page 1.
        let patch = [0xE1u8, 0xE2, 0xE3, 0xE4];
        let start = FRAME_SIZE as usize - 2;
        write(KEY, start as u64, &patch, 2 * FRAME_SIZE).unwrap();
        assert_eq!(
            allocated_count(),
            2,
            "both pages were already resident, so nothing new is allocated"
        );

        let mut both = std::vec![0u8; 2 * FRAME_SIZE as usize];
        read_with(KEY, 2 * FRAME_SIZE, 0, &mut both, None).unwrap();
        assert_eq!(&both[..start], &page0[..start], "page 0 head moved");
        assert_eq!(&both[start..FRAME_SIZE as usize], &patch[..2]);
        assert_eq!(
            &both[FRAME_SIZE as usize..FRAME_SIZE as usize + 2],
            &patch[2..]
        );
        assert_eq!(
            &both[FRAME_SIZE as usize + 2..],
            &page1[2..],
            "page 1 tail moved"
        );
    }

    #[test]
    fn write_extends_file_and_returns_new_size() {
        let _g = setup();
        assert_eq!(write(KEY, 100, b"", 0).unwrap(), 0);
        assert_eq!(write(KEY, 100, b"xyz", 0).unwrap(), 103);
        assert_eq!(write(KEY, 8192, b"q", 103).unwrap(), 8193);
        assert_eq!(resident_pages(KEY), 2); // page 0 (from the first write) + page 2
        let mut out = [0u8; 3];
        read_with(KEY, 8193, 100, &mut out, None).unwrap();
        assert_eq!(&out, b"xyz");
        // The hole between the two writes reads as zeros without allocating.
        let mut hole = [0xAAu8; 8];
        read_with(KEY, 8193, 5000, &mut hole, None).unwrap();
        assert!(hole.iter().all(|&b| b == 0));
        assert_eq!(resident_pages(KEY), 2);
    }

    #[test]
    fn backing_error_releases_frame_and_propagates() {
        let _g = setup();
        let mut backing =
            |_page: u64, _buf: &mut [u8]| -> Result<(), VfsError> { Err(VfsError::Corrupt) };
        let mut out = [0u8; 8];
        assert_eq!(
            read_with(KEY, 4096, 0, &mut out, Some(&mut backing)),
            Err(VfsError::Corrupt)
        );
        assert_eq!(allocated_count(), 0);
        assert_eq!(host::live_count(), 0);
    }

    #[test]
    fn write_quota_failure_leaves_old_pages_and_frames_intact() {
        let _g = setup();
        // Fill the whole cache with one page per filler key.
        for i in 0..CACHE_PAGES {
            write(CacheKey::new(9, i as u64), 0, &[i as u8], 0).unwrap();
        }
        assert_eq!(allocated_count(), CACHE_PAGES);
        assert_eq!(free_count(), 0);
        let live_before = host::live_count();
        assert_eq!(live_before, CACHE_PAGES);

        // A write needing a new page must be refused wholesale.
        assert_eq!(write(KEY, 0, b"nope", 0), Err(VfsError::Quota));
        assert_eq!(allocated_count(), CACHE_PAGES);
        assert_eq!(host::live_count(), live_before);
        assert!(!is_resident(KEY, 0));

        // Existing cached data is untouched: filler key 3 still holds 3.
        let mut one = [0u8; 1];
        read_with(CacheKey::new(9, 3), 1, 0, &mut one, None).unwrap();
        assert_eq!(one[0], 3);
    }

    #[test]
    fn write_bad_offset_is_rejected_before_allocating() {
        let _g = setup();
        assert_eq!(
            write(KEY, u64::MAX - 3, b"abcd", 0),
            Err(VfsError::BadOffset)
        );
        assert_eq!(allocated_count(), 0);
        assert_eq!(host::live_count(), 0);
        // A write crossing the last page boundary but not overflowing works.
        let new_size = write(KEY, u64::MAX - 4, b"abcd", 0).unwrap();
        assert_eq!(new_size, u64::MAX);
        assert_eq!(allocated_count(), 1);
    }

    #[test]
    fn truncate_releases_beyond_pages_and_zeroes_tail() {
        let _g = setup();
        write(KEY, 0, &[0x11u8; 3 * 4096], 0).unwrap();
        assert_eq!(resident_pages(KEY), 3);

        // Shrink to 4096 + 10: page 2 goes, page 1 keeps 10 bytes, tail zeroed.
        assert_eq!(truncate(KEY, 3 * 4096, 4096 + 10).unwrap(), 4096 + 10);
        assert_eq!(resident_pages(KEY), 2);
        assert!(!is_resident(KEY, 2));
        assert_eq!(host::live_count(), 2);
        // The tail of the straddling page is zero, so a later grow cannot
        // expose the old 0x11 bytes.
        let mut tail = [0xAAu8; 6];
        let n = read_with(KEY, 4096 + 16, 4096 + 10, &mut tail, None).unwrap();
        assert_eq!(n, 6);
        assert!(tail.iter().all(|&b| b == 0), "tail must be zeroed");

        // Growing back into the page must not resurrect 0x11.
        write(KEY, 4096 + 10, &[0x22u8; 2], 4096 + 10).unwrap();
        let mut probe = [0u8; 4];
        read_with(KEY, 4096 + 16, 4096 + 10, &mut probe, None).unwrap();
        assert_eq!(probe, [0x22, 0x22, 0x00, 0x00]);

        // Shrink to a page boundary releases that page too.
        truncate(KEY, 4096 + 12, 4096).unwrap();
        assert_eq!(resident_pages(KEY), 1);
        // No-op growth keeps state.
        assert_eq!(truncate(KEY, 100, 200).unwrap(), 200);
        assert_eq!(resident_pages(KEY), 1);
    }

    #[test]
    fn invalidate_drops_every_page_of_one_key() {
        let _g = setup();
        let other = CacheKey::new(FS, 2);
        write(KEY, 0, &[1u8; 3 * 4096], 0).unwrap();
        write(other, 0, b"keep", 0).unwrap();
        assert_eq!(allocated_count(), 4);

        invalidate(KEY).unwrap();
        assert_eq!(resident_pages(KEY), 0);
        assert_eq!(allocated_count(), 1);
        assert_eq!(host::live_count(), 1);
        // Idempotent.
        invalidate(KEY).unwrap();
        // The other file is untouched.
        let mut out = [0u8; 4];
        read_with(other, 4, 0, &mut out, None).unwrap();
        assert_eq!(&out, b"keep");
    }

    #[test]
    fn mark_clean_clears_only_fully_written_back_pages() {
        let _g = setup();
        write(KEY, 0, &[0x33u8; 3 * 4096], 0).unwrap();
        assert_eq!(dirty_count(), 3);
        // Only page 0 (end 4096) is fully below 4096.
        mark_clean(KEY, 4096);
        assert_eq!(dirty_count(), 2);
        assert_eq!(page_info(KEY, 0).map(|(_, d)| d), Some(false));
        assert_eq!(page_info(KEY, 1).map(|(_, d)| d), Some(true));
        mark_clean(KEY, u64::MAX);
        assert_eq!(dirty_count(), 0);
        assert!(page_info(KEY, 0).is_some());
        assert!(page_info(KEY, 7).is_none());
    }

    /// A partial write into a page that is not resident must not lose the rest
    /// of that page: the new frame is filled from the backing store first, so
    /// the bytes outside the written range keep their on-disk values.
    #[test]
    fn partial_write_fills_missing_pages_from_the_backing_store() {
        let _g = setup();
        let original = patterned_page(0x5C);
        let mut fills = 0usize;
        let mut fill = |page_start: u64, buf: &mut [u8]| -> Result<(), VfsError> {
            assert_eq!(page_start, 0, "only page 0 should need filling");
            assert_eq!(buf.len(), FRAME_SIZE as usize);
            fills += 1;
            buf.copy_from_slice(&original);
            Ok(())
        };
        let written = [0xAAu8; 100];
        write_with(KEY, 0, &written, 4096, Some(&mut fill)).unwrap();
        assert_eq!(fills, 1);

        let mut out = [0u8; 4096];
        read_with(KEY, 4096, 0, &mut out, None).unwrap();
        assert_eq!(&out[..written.len()], &written);
        assert_eq!(&out[written.len()..], &original[written.len()..]);

        // Without a backing store a missing page is a hole and stays zero.
        let hole = CacheKey::new(FS, 2);
        write(hole, 0, &[1, 2, 3], 4096).unwrap();
        let mut zeroed = [0xFFu8; 4096];
        read_with(hole, 4096, 0, &mut zeroed, None).unwrap();
        assert_eq!(&zeroed[..3], &[1, 2, 3]);
        assert!(zeroed[3..].iter().all(|byte| *byte == 0));
    }

    #[test]
    fn pin_counts_are_bounded_and_unpin_needs_a_pin() {
        let _guard = setup();
        let key = CacheKey::new(FS, 9);
        write(key, 0, b"x", 0).unwrap();
        // The ledger is the hard bound: one record per pin, never an allocation.
        for _ in 0..MAX_PIN_OWNERS {
            assert!(pin_page(1, key, 0).is_ok());
        }
        assert_eq!(pin_page(1, key, 0), Err(VfsError::Quota));
        assert_eq!(pinned_count(key, 0) as usize, MAX_PIN_OWNERS);
        for _ in 0..MAX_PIN_OWNERS {
            unpin_page(1, key, 0).unwrap();
        }
        assert_eq!(unpin_page(1, key, 0), Err(VfsError::NotFound));
        assert_eq!(pinned_count(key, 0), 0);
    }

    #[test]
    fn materialise_gives_a_hole_a_real_frame() {
        let _guard = setup();
        let key = CacheKey::new(FS, 10);
        let phys = materialise(key, 4096, 0, None).unwrap();
        assert!(phys != 0);
        assert!(is_resident(key, 0));
        // Materialising again returns the same frame instead of allocating one.
        assert_eq!(materialise(key, 4096, 0, None).unwrap(), phys);
        assert_eq!(allocated_count(), 1);
    }
}
