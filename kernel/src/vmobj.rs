//! Eager file mappings (`mmap`) for user processes (M5c2).
//!
//! The M5 milestone has **no demand paging**: a user `#PF` other than the
//! deliberate M2 probe halts the kernel, so a mapping must be fully
//! materialised at `map` time. This module owns the bookkeeping and the
//! teardown of those mappings; it hands the actual page-table work to
//! [`crate::mm::addrspace`] and the file-page work to [`crate::vfs`].
//!
//! ## Two mapping flavours
//!
//! * **Shared** (`shared = true`): every page is pinned in the page cache
//!   ([`vfs::pin_file_page`]) and mapped *borrowed*
//!   ([`addrspace::map_user_borrowed`]). The frame stays the page cache's
//!   property, so the mapping and the file cache see the same bytes. A write
//!   through the mapping is visible to the file only after the page is marked
//!   dirty ([`mark_shared_dirty`], called from the `sync` syscall) and synced.
//!   Releasing a shared mapping marks every page dirty before unpinning so a
//!   forgotten `sync` cannot silently drop the writes; it never flushes by
//!   itself (a flush inside the object destroy hook would put disk I/O in an
//!   interrupts-off, object-table-borrowed context).
//! * **Private** (`shared = false`): every page is copied out of the file
//!   ([`vfs::copy_file_page`]) into a fresh frame the address space then owns
//!   ([`addrspace::map_user`]). Nothing is written back, and private mappings
//!   never mark dirty.
//! * **Shared memory** (M6a2, [`map_shm`]): the pages are the frames of a
//!   `SharedMemory` object ([`crate::ipc::shm::frames`]) mapped borrowed. The
//!   mapping holds one object reference for its lifetime, so closing the user's
//!   `SharedMemory` handle cannot free frames that are still mapped. Releasing
//!   the mapping only unmaps and drops that reference; the frames themselves are
//!   freed by the object's own destroy hook once the last reference is gone.
//!   That reference is dropped through a deferred queue
//!   ([`release_pending`]), because the teardown runs inside the object table's
//!   interrupt-off section and must not re-enter it.
//!
//! * **Display** (M6c, [`map_display`]): the pages are the 64 framebuffer
//!   frames owned by a `Display` object ([`crate::ipc::display::map_pages`]),
//!   mapped borrowed. The mapping holds one `Display` object reference for its
//!   lifetime, so closing the user's `Display` handle cannot free frames that
//!   are still mapped. Releasing the mapping unmaps, decrements the display's
//!   map count ([`crate::ipc::display::unmap`]) and drops that reference through
//!   the deferred queue; the frames themselves are freed by the object's own
//!   destroy hook once the last reference is gone *and* nothing is mapped.
//!
//! ## Object integration
//!
//! A mapping is a `VmObject` capability: the syscall layer creates the object
//! with the mapping id as payload, and this module registers
//! [`destroy_from_object`] as that kind's destroy hook. Closing the last handle
//! therefore tears the mapping down exactly once. `munmap` does **not** bypass
//! the object layer: the syscall first resolves the mapping id with
//! [`mapping_payload`] and then closes the payload through
//! `object::close_payload`, so the hook performs the release.
//!
//! ## Concurrency and allocation
//!
//! Tables are fixed-size statics, there is no heap use and no 4 KiB stack
//! buffer. The destroy hook runs inside the object-table `IrqCell` (IRQs off,
//! object table borrowed) and must not re-enter the object layer; it only calls
//! the VFS and the address space. All other entry points run in syscall
//! context (`IF = 0`, no kernel preemption), so the tables need no further
//! locking.

use core::ptr::addr_of_mut;

use crate::ipc::{display, shm};
use crate::mm::addrspace::{self, AddressSpaceId, USER_MAX};
use crate::mm::pmm;
use crate::mm::vm::VmError;
use crate::object::{self, ObjectError, ObjectId, ObjectKind};
use crate::process;
use crate::sync::IrqSpinLock;
use crate::vfs::{self, NodeKind, OpenId, PAGE, VfsError};

/// Maximum number of live mappings in the system.
pub const MAX_MAPPINGS: usize = 32;
/// Maximum number of live mappings inside one address space.
pub const MAX_MAPPINGS_PER_SPACE: usize = 16;
/// Largest single mapping: 256 KiB (64 pages).
pub const MAX_MAP_BYTES: u64 = 256 * 1024;
/// First virtual address handed out for a file mapping (16 MiB). User images
/// live near 4 MiB and user stacks near 8 MiB, so 16 MiB is free; the bump
/// never reuses an address, which keeps `munmap` matching unambiguous.
pub const FIRST_MAP_BASE: u64 = 0x0100_0000;

/// Mapping is readable (mandatory).
pub const PROT_READ: u32 = 1 << 0;
/// Mapping is writable.
pub const PROT_WRITE: u32 = 1 << 1;
/// Execute permission; rejected by this slice (no executable mappings yet).
pub const PROT_EXEC: u32 = 1 << 2;

/// Union of every permission bit this ABI knows.
const PROT_VALID: u32 = PROT_READ | PROT_WRITE | PROT_EXEC;
/// Page count of the largest allowed mapping.
const MAX_PAGES: u64 = MAX_MAP_BYTES / PAGE;
/// Page count of a display mapping (M6c): the display module owns exactly this
/// many framebuffer frames, and `map_pages` fills a `[u64; DISPLAY_PAGES]`.
const DISPLAY_PAGES: usize = 64;

/// Reason a mapping operation was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MapError {
    /// The caller's arguments are malformed (alignment, permissions, range).
    BadRequest,
    /// No live mapping matches the request.
    NotFound,
    /// A fixed table, per-space limit or user-address budget is exhausted.
    Quota,
    /// The page cache refused teardown of a pinned page.
    Busy,
    /// An unexpected VFS/object failure.
    Io,
    /// Frame allocation or address-space bookkeeping failed.
    NoMemory,
    /// The requested feature is deliberately not part of M5c2.
    NotSupported,
}

impl MapError {
    /// Short, stable name for the syscall layer's status mapping and for logs.
    pub const fn as_str(self) -> &'static str {
        match self {
            MapError::BadRequest => "bad request",
            MapError::NotFound => "no such mapping",
            MapError::Quota => "mapping quota exceeded",
            MapError::Busy => "mapping is busy",
            MapError::Io => "mapping i/o error",
            MapError::NoMemory => "out of mapping memory",
            MapError::NotSupported => "mapping not supported",
        }
    }
}

/// What a mapping borrows its frames from.
#[derive(Clone, Copy)]
enum Backing {
    /// File mapping: an independent VFS description held for the mapping's
    /// lifetime. `vfs::dup` keeps the same [`OpenId`] and bumps the description
    /// reference count, so closing the user's file handle does not invalidate
    /// the mapping, and [`mark_shared_dirty`] can match mappings by id.
    File(OpenId),
    /// Shared-memory mapping: one object reference keeps the frames alive.
    Shm(ObjectId),
    /// Display mapping (M6c): the framebuffer frames belong to the `Display`
    /// object; one object reference keeps them alive for the mapping's lifetime.
    Display(ObjectId),
}

/// One live mapping.
#[derive(Clone, Copy)]
struct Mapping {
    /// Address space the mapping belongs to.
    space: AddressSpaceId,
    /// First user virtual address.
    base: u64,
    /// Length in bytes (page multiple, non-zero).
    len: u64,
    /// Offset inside the file (page aligned; zero for shared memory).
    offset: u64,
    /// Permission bits at the time of the last [`protect`].
    prot: u32,
    /// Shared (page-cache frames) or private (copied frames).
    shared: bool,
    /// Frames this mapping borrows from.
    backing: Backing,
}

/// Live mappings, indexed by `mapping_id - 1`.
static mut MAPPINGS: [Option<Mapping>; MAX_MAPPINGS] = [None; MAX_MAPPINGS];
/// Next free user virtual address per address space (0 = not started).
static mut NEXT_BASE: [u64; addrspace::MAX_SPACES] = [0; addrspace::MAX_SPACES];
/// Number of live mappings, kept for cheap assertions in the syscall layer.
static mut LIVE: usize = 0;
/// `SharedMemory` references deferred out of the object destroy hook.
///
/// The hook runs with the object table's interrupt-off section held, so it may
/// not call `object::release_object`; it queues the object here instead and the
/// syscall/teardown paths drain the queue with [`release_pending`].
///
/// The queue is shared by every CPU, so it has its own leaf lock: a destroy hook
/// on one CPU can queue while another CPU drains. The lock only protects the two
/// arrays below; every `object::release_object` happens after it is dropped,
/// because the object table takes its own interrupt-off lock (holding this one
/// there would invert the order and deadlock).
static mut PENDING_SHM: [ObjectId; MAX_MAPPINGS] = [ObjectId::MAX; MAX_MAPPINGS];
/// Number of valid entries in [`PENDING_SHM`].
static mut PENDING_LEN: usize = 0;
/// `Display` references deferred out of the object destroy hook (M6c).
///
/// Same contract as [`PENDING_SHM`]: the destroy hook may not call
/// `object::release_object`, so it queues the reference and the syscall/teardown
/// paths drain it with [`release_pending`].
static mut PENDING_DISPLAY: [ObjectId; MAX_MAPPINGS] = [ObjectId::MAX; MAX_MAPPINGS];
/// Number of valid entries in [`PENDING_DISPLAY`].
static mut PENDING_DISPLAY_LEN: usize = 0;
/// Leaf lock serialising [`PENDING_SHM`] / [`PENDING_LEN`] access.
static PENDING_LOCK: IrqSpinLock = IrqSpinLock::new();

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Map `len` bytes of `open` at file `offset` into `as_id`.
///
/// Returns `(mapping_id, base)`. `mapping_id` is non-zero and is what the
/// caller stores as the `VmObject` payload.
pub fn map(
    as_id: AddressSpaceId,
    open: OpenId,
    len: u64,
    offset: u64,
    prot: u32,
    shared: bool,
) -> Result<(u32, u64), MapError> {
    validate_shape(len, offset, prot)?;
    let stat = vfs::stat_open(open).map_err(map_vfs)?;
    if stat.kind != NodeKind::File {
        return Err(MapError::BadRequest);
    }
    if !range_fits(offset, len, stat.size) {
        return Err(MapError::BadRequest);
    }

    let slot = {
        let table = mappings();
        let slot = free_slot(table).ok_or(MapError::Quota)?;
        let space = as_id.index();
        if space >= addrspace::MAX_SPACES {
            return Err(MapError::NotFound);
        }
        if count_in_space(table, space) >= MAX_MAPPINGS_PER_SPACE {
            return Err(MapError::Quota);
        }
        slot
    };
    let base = bump_base(as_id.index(), len)?;
    // One independent description for the mapping's lifetime (same OpenId,
    // description refcount + 1).
    let held = vfs::dup(open).map_err(map_vfs)?;

    let pages = len / PAGE;
    let writable = is_writable(prot);
    let mut done = 0u64;
    let mut page = 0u64;
    while page < pages {
        let file_offset = offset + page * PAGE;
        let user_virt = base + page * PAGE;
        if shared {
            let phys = match vfs::pin_file_page(held, file_offset) {
                Ok(phys) => phys,
                Err(error) => {
                    release_shared(as_id, base, held, offset, done);
                    close_quietly(held);
                    return Err(map_vfs(error));
                }
            };
            if let Err(error) =
                addrspace::map_user_borrowed(as_id, user_virt, phys, PAGE, writable, false)
            {
                unpin_quietly(held, file_offset);
                release_shared(as_id, base, held, offset, done);
                close_quietly(held);
                return Err(map_vm(error));
            }
        } else {
            let phys = match pmm::alloc_frame() {
                Ok(phys) => phys,
                Err(_) => {
                    release_private(as_id, base, done);
                    close_quietly(held);
                    return Err(MapError::NoMemory);
                }
            };
            if let Err(error) = vfs::copy_file_page(held, file_offset, phys) {
                let _ = pmm::dealloc_frame(phys);
                release_private(as_id, base, done);
                close_quietly(held);
                return Err(map_vfs(error));
            }
            if let Err(error) = addrspace::map_user(as_id, user_virt, phys, PAGE, writable, false) {
                // The frame is not mapped yet, so the address space does not
                // own it: free it here.
                let _ = pmm::dealloc_frame(phys);
                release_private(as_id, base, done);
                close_quietly(held);
                return Err(map_vm(error));
            }
        }
        done += 1;
        page += 1;
    }

    let mapping = Mapping {
        space: as_id,
        base,
        len,
        offset,
        prot,
        shared,
        backing: Backing::File(held),
    };
    let table = mappings();
    table[slot] = Some(mapping);
    // SAFETY: single-CPU syscall context; this is the only increment site.
    unsafe {
        LIVE += 1;
    }
    Ok((slot as u32 + 1, base))
}

/// Register the `VmObject` destroy hook with the object layer.
///
/// The syscall/root initialisation calls this once, before any mapping can be
/// created. Registering the same hook twice is idempotent in the object layer.
pub fn init() -> Result<(), ObjectError> {
    object::register_destroy_hook(ObjectKind::VmObject, destroy_from_object)
}

/// Map a `SharedMemory` object into `as_id` (M6a2).
///
/// Returns `(mapping_id, base)` exactly like [`map`]; the caller stores the
/// mapping id as the new `VmObject` payload. The pages are the object's frames
/// mapped *borrowed*, so the mapping and every other mapping of the same object
/// see the same bytes.
///
/// The mapping takes one object reference for its lifetime: closing the user's
/// `SharedMemory` handle can therefore not free frames that are still mapped.
/// Releasing the mapping drops that reference through [`release_pending`]; the
/// frames are freed by the object's own destroy hook once the last reference is
/// gone. Execute permission is refused (shared memory is data, not code).
pub fn map_shm(
    as_id: AddressSpaceId,
    shm_object: ObjectId,
    prot: u32,
) -> Result<(u32, u64), MapError> {
    validate_shm_shape(prot)?;
    let pages = shm::pages(shm_object).map_err(map_shm_error)?;
    let len = pages as u64 * PAGE;
    if len == 0 || len > MAX_MAP_BYTES {
        return Err(MapError::BadRequest);
    }
    let frames = shm::frames(shm_object).map_err(map_shm_error)?;
    if frames.len() != pages {
        return Err(MapError::Io);
    }

    let slot = {
        let table = mappings();
        let slot = free_slot(table).ok_or(MapError::Quota)?;
        let space = as_id.index();
        if space >= addrspace::MAX_SPACES {
            return Err(MapError::NotFound);
        }
        if count_in_space(table, space) >= MAX_MAPPINGS_PER_SPACE {
            return Err(MapError::Quota);
        }
        slot
    };
    let base = bump_base(as_id.index(), len)?;
    // One reference for the mapping's lifetime; released by the teardown path.
    object::acquire_object(shm_object).map_err(map_object)?;

    let writable = is_writable(prot);
    let mut done = 0u64;
    for phys in frames.iter().take(pages) {
        let user_virt = base + done * PAGE;
        if let Err(error) =
            addrspace::map_user_borrowed(as_id, user_virt, *phys, PAGE, writable, false)
        {
            if done != 0 {
                let _ = addrspace::unmap_user(as_id, base, done * PAGE);
            }
            // Outside the object table here, so the reference can go directly.
            let _ = object::release_object(shm_object);
            return Err(map_vm(error));
        }
        done += 1;
    }

    let mapping = Mapping {
        space: as_id,
        base,
        len,
        offset: 0,
        prot,
        shared: true,
        backing: Backing::Shm(shm_object),
    };
    let table = mappings();
    table[slot] = Some(mapping);
    // SAFETY: single-CPU syscall context; this is the only increment site.
    unsafe {
        LIVE += 1;
    }
    Ok((slot as u32 + 1, base))
}

/// Map the framebuffer frames of a `Display` object (M6c).
///
/// The display module hands out exactly [`DISPLAY_PAGES`] page-aligned physical
/// frames ([`crate::ipc::display::map_pages`]); they are mapped *borrowed* so the
/// device and every mapping of the same display see the same bytes. The mapping
/// covers [`MAX_MAP_BYTES`] (64 pages, 256 KiB) — the display's visible bytes are
/// described by [`crate::ipc::display::info`], not by the mapping length.
///
/// The mapping takes one `Display` object reference for its lifetime (acquired
/// before `map_pages`, as that contract requires). Any failure unmaps the pages
/// already mapped, balances the display's map count with
/// [`crate::ipc::display::unmap`] and drops that reference, so a failed call
/// leaves no trace. Execute permission is refused: a framebuffer is data.
pub fn map_display(
    as_id: AddressSpaceId,
    display_object: ObjectId,
    prot: u32,
) -> Result<(u32, u64), MapError> {
    validate_display_shape(prot)?;
    let len = MAX_MAP_BYTES;

    let slot = {
        let table = mappings();
        let slot = free_slot(table).ok_or(MapError::Quota)?;
        let space = as_id.index();
        if space >= addrspace::MAX_SPACES {
            return Err(MapError::NotFound);
        }
        if count_in_space(table, space) >= MAX_MAPPINGS_PER_SPACE {
            return Err(MapError::Quota);
        }
        slot
    };
    let base = bump_base(as_id.index(), len)?;
    // One reference for the mapping's lifetime; released by the teardown path.
    object::acquire_object(display_object).map_err(map_object)?;

    let mut frames = [0u64; DISPLAY_PAGES];
    if let Err(error) = display::map_pages(display_object, &mut frames) {
        let _ = object::release_object(display_object);
        return Err(map_display_error(error));
    }

    let writable = is_writable(prot);
    let mut done = 0u64;
    for phys in frames.iter().take(DISPLAY_PAGES) {
        let user_virt = base + done * PAGE;
        if let Err(error) =
            addrspace::map_user_borrowed(as_id, user_virt, *phys, PAGE, writable, false)
        {
            if done != 0 {
                let _ = addrspace::unmap_user(as_id, base, done * PAGE);
            }
            // Undo `map_pages` before the reference goes: the display's map
            // count must not outlive the pages.
            let _ = display::unmap(display_object);
            let _ = object::release_object(display_object);
            return Err(map_vm(error));
        }
        done += 1;
    }

    let mapping = Mapping {
        space: as_id,
        base,
        len,
        offset: 0,
        prot,
        shared: true,
        backing: Backing::Display(display_object),
    };
    let table = mappings();
    table[slot] = Some(mapping);
    // SAFETY: single-CPU syscall context; this is the only increment site.
    unsafe {
        LIVE += 1;
    }
    Ok((slot as u32 + 1, base))
}

/// Release the `SharedMemory` references deferred by mapping teardown.
///
/// Must be called outside the object table's interrupt-off section: after
/// `close_handle`, after `munmap`, and once during process teardown. Repeated
/// calls are idempotent.
///
/// The queue is taken under its leaf lock and released after the guard is gone,
/// so `object::release_object` (which takes the object table lock and may run a
/// destroy hook) never nests inside [`PENDING_LOCK`].
pub fn release_pending() -> usize {
    let mut batch = [ObjectId::MAX; MAX_MAPPINGS];
    let count = PENDING_LOCK.with(|| {
        // SAFETY: `PENDING_LOCK` serialises every access to the queues; this only
        // copies and clears the arrays, touching no other state.
        unsafe {
            let mut queued = 0usize;
            let shm_len = (*core::ptr::addr_of!(PENDING_LEN)).min(MAX_MAPPINGS);
            for index in 0..shm_len {
                batch[queued] = (*core::ptr::addr_of!(PENDING_SHM))[index];
                queued += 1;
            }
            let display_len = (*core::ptr::addr_of!(PENDING_DISPLAY_LEN)).min(MAX_MAPPINGS);
            for index in 0..display_len {
                if queued < MAX_MAPPINGS {
                    batch[queued] = (*core::ptr::addr_of!(PENDING_DISPLAY))[index];
                    queued += 1;
                }
            }
            *core::ptr::addr_of_mut!(PENDING_LEN) = 0;
            *core::ptr::addr_of_mut!(PENDING_DISPLAY_LEN) = 0;
            for slot in (*core::ptr::addr_of_mut!(PENDING_SHM)).iter_mut() {
                *slot = ObjectId::MAX;
            }
            for slot in (*core::ptr::addr_of_mut!(PENDING_DISPLAY)).iter_mut() {
                *slot = ObjectId::MAX;
            }
            queued
        }
    });
    for object in batch.iter().take(count) {
        if *object != ObjectId::MAX {
            let _ = object::release_object(*object);
        }
    }
    count
}

/// Return the mapping id whose live mapping covers exactly `(base, len)`.
///
/// The `munmap` syscall uses this to find the `VmObject` payload, then closes
/// that object so [`destroy_from_object`] performs the release.
pub fn mapping_payload(as_id: AddressSpaceId, base: u64, len: u64) -> Option<u32> {
    let table = mappings_ro();
    let slot = find_exact(table, as_id.index(), base, len)?;
    Some(slot as u32 + 1)
}

/// Tear a mapping down through the object layer (helper / rollback path).
///
/// The kernel's `munmap` path resolves the payload with [`mapping_payload`] and
/// closes the `VmObject` handle instead; this helper exists for internal
/// rollback and for callers that hold no handle table. It falls back to a
/// direct release when no handle for the payload is live.
pub fn unmap(as_id: AddressSpaceId, base: u64, len: u64) -> Result<(), MapError> {
    let payload = mapping_payload(as_id, base, len).ok_or(MapError::NotFound)?;
    // Closing the `VmObject` handle runs the mapping destroy hook, which takes
    // the VFS/IPC locks, so the handle table is taken out of the process slot
    // instead of being used through `with_current_handles`.
    let through_object = match process::take_current_handles() {
        Some(mut guard) => {
            match object::close_payload(guard.table_mut(), ObjectKind::VmObject, payload) {
                Ok(closed) => closed,
                Err(error) => return Err(map_object(error)),
            }
        }
        None => false,
    };
    if !through_object {
        // No live `VmObject` handle in the current process (helper/rollback
        // path): release directly; the hook is a no-op afterwards.
        destroy_from_object(payload as u64);
    }
    Ok(())
}

/// Change the permissions of an existing exact mapping (no flush).
///
/// M5c2 only allows read-only or read/write; execute permission is refused
/// because no executable file mapping exists yet.
pub fn protect(as_id: AddressSpaceId, base: u64, len: u64, prot: u32) -> Result<(), MapError> {
    validate_shape(len, 0, prot)?;
    let payload = mapping_payload(as_id, base, len).ok_or(MapError::NotFound)?;
    addrspace::protect_user(as_id, base, len, is_writable(prot), false).map_err(map_vm)?;
    let table = mappings();
    let slot = payload as usize - 1;
    if let Some(mapping) = table[slot].as_mut() {
        mapping.prot = prot;
    }
    Ok(())
}

/// Mark every page of every live shared mapping of `open` dirty (no flush).
///
/// The `sync` syscall calls this before `vfs::sync` so bytes written through a
/// shared mapping reach the file system. Private mappings are untouched.
pub fn mark_shared_dirty(open: OpenId) -> Result<(), MapError> {
    let table = mappings_ro();
    for mapping in table.iter().flatten() {
        if !mapping.shared {
            continue;
        }
        let Backing::File(backed_by) = mapping.backing else {
            // Shared memory has no file backing to dirty.
            continue;
        };
        if backed_by != open {
            continue;
        }
        let pages = mapping.len / PAGE;
        for page in 0..pages {
            vfs::mark_file_page_dirty(backed_by, mapping.offset + page * PAGE).map_err(map_vfs)?;
        }
    }
    Ok(())
}

/// Object destroy hook for `ObjectKind::VmObject`: payload is a mapping id.
///
/// Called exactly once when the last handle to the mapping's object goes away
/// (including process teardown), while the address space is still alive.
pub fn destroy_from_object(payload: u64) {
    if payload == 0 || payload as usize > MAX_MAPPINGS {
        return;
    }
    let slot = payload as usize - 1;
    let table = mappings();
    let mapping = match table[slot].take() {
        Some(mapping) => mapping,
        // Already released (or never ours): the hook contract allows a no-op.
        None => return,
    };
    // SAFETY: see the module docs — single-CPU, IRQs off, no re-entry.
    unsafe {
        LIVE = LIVE.saturating_sub(1);
    }
    release_mapping(mapping);
}

/// Number of live mappings (used by hosts tests and by the syscall layer for
/// quota accounting).
pub fn live_mappings() -> usize {
    // SAFETY: plain read of a single-CPU counter.
    unsafe { *core::ptr::addr_of!(LIVE) }
}

// ---------------------------------------------------------------------------
// Release paths
// ---------------------------------------------------------------------------

/// Release one mapping: dirty, unmap, unpin and close its held description.
fn release_mapping(mapping: Mapping) {
    match mapping.backing {
        Backing::File(open) => release_file_mapping(mapping, open),
        Backing::Shm(shm_object) => {
            // Borrowed frames are only removed; the object still owns them.
            // The object reference cannot be dropped here (this runs inside the
            // object table's interrupt-off section), so it is queued.
            let _ = addrspace::unmap_user(mapping.space, mapping.base, mapping.len);
            queue_pending_shm(shm_object);
        }
        Backing::Display(display_object) => {
            // Same rule as shared memory: the frames stay the display's. The
            // display's map count is decremented (its state table is a leaf
            // lock, safe from a destroy hook); the object reference is queued.
            let _ = addrspace::unmap_user(mapping.space, mapping.base, mapping.len);
            let _ = display::unmap(display_object);
            queue_pending_display(display_object);
        }
    }
}

/// Release a file mapping: dirty, unmap, unpin and close its held description.
fn release_file_mapping(mapping: Mapping, open: OpenId) {
    if mapping.shared {
        // Dirty first: the user may have written through the mapping without an
        // explicit `sync`, and unpinning drops the pin that kept the page
        // resident. No flush here (destroy hooks must not perform disk I/O).
        let pages = mapping.len / PAGE;
        for page in 0..pages {
            let _ = vfs::mark_file_page_dirty(open, mapping.offset + page * PAGE);
        }
        // Borrowed frames are only removed; the page cache keeps ownership.
        let _ = addrspace::unmap_user(mapping.space, mapping.base, mapping.len);
        for page in 0..pages {
            unpin_quietly(open, mapping.offset + page * PAGE);
        }
    } else {
        // Owned frames are freed by the address space while it unmaps.
        let _ = addrspace::unmap_user(mapping.space, mapping.base, mapping.len);
    }
    close_quietly(open);
}

/// Queue one `SharedMemory` reference for [`release_pending`].
fn queue_pending_shm(object: ObjectId) {
    PENDING_LOCK.with(|| {
        // SAFETY: `PENDING_LOCK` serialises every access to the queue; the object
        // table's interrupt-off section has already been released before a
        // destroy hook runs, so taking this leaf lock cannot deadlock.
        unsafe {
            let len = *core::ptr::addr_of!(PENDING_LEN);
            if len < MAX_MAPPINGS {
                (*core::ptr::addr_of_mut!(PENDING_SHM))[len] = object;
                *core::ptr::addr_of_mut!(PENDING_LEN) = len + 1;
            }
        }
    });
}

/// Queue one `Display` reference for [`release_pending`].
fn queue_pending_display(object: ObjectId) {
    PENDING_LOCK.with(|| {
        // SAFETY: `PENDING_LOCK` serialises every access to the queues; the object
        // table's interrupt-off section has already been released before a
        // destroy hook runs, so taking this leaf lock cannot deadlock.
        unsafe {
            let len = *core::ptr::addr_of!(PENDING_DISPLAY_LEN);
            if len < MAX_MAPPINGS {
                (*core::ptr::addr_of_mut!(PENDING_DISPLAY))[len] = object;
                *core::ptr::addr_of_mut!(PENDING_DISPLAY_LEN) = len + 1;
            }
        }
    });
}

/// Roll back `done` already-mapped pages of a shared mapping.
fn release_shared(as_id: AddressSpaceId, base: u64, held: OpenId, offset: u64, done: u64) {
    if done == 0 {
        return;
    }
    let len = done * PAGE;
    let _ = addrspace::unmap_user(as_id, base, len);
    for page in 0..done {
        unpin_quietly(held, offset + page * PAGE);
    }
}

/// Roll back `done` already-mapped pages of a private mapping (owned frames are
/// freed by the address space).
fn release_private(as_id: AddressSpaceId, base: u64, done: u64) {
    if done == 0 {
        return;
    }
    let _ = addrspace::unmap_user(as_id, base, done * PAGE);
}

fn unpin_quietly(open: OpenId, offset: u64) {
    let _ = vfs::unpin_file_page(open, offset);
}

fn close_quietly(open: OpenId) {
    let _ = vfs::close(open);
}

// ---------------------------------------------------------------------------
// Tables and pure policy helpers
// ---------------------------------------------------------------------------

fn mappings() -> &'static mut [Option<Mapping>; MAX_MAPPINGS] {
    // SAFETY: callers run in syscall/destroy-hook context with interrupts off,
    // so there is a single writer. `addr_of_mut!` avoids forming a reference to
    // the bare `static mut` path.
    unsafe { &mut *addr_of_mut!(MAPPINGS) }
}

fn mappings_ro() -> &'static [Option<Mapping>; MAX_MAPPINGS] {
    // SAFETY: as above; this only reads the table.
    unsafe { &*core::ptr::addr_of!(MAPPINGS) }
}

/// Allocation bump for user mapping addresses.
fn bump_base(space: usize, len: u64) -> Result<u64, MapError> {
    let next = {
        // SAFETY: same single-writer reasoning as `mappings`.
        unsafe { (*core::ptr::addr_of_mut!(NEXT_BASE))[space] }
    };
    let base = if next == 0 { FIRST_MAP_BASE } else { next };
    let end = base.checked_add(len).ok_or(MapError::Quota)?;
    if !in_user_half(end) {
        return Err(MapError::Quota);
    }
    // SAFETY: as above.
    unsafe {
        (*core::ptr::addr_of_mut!(NEXT_BASE))[space] = end;
    }
    Ok(base)
}

/// Is `end` still inside the user half (exclusive upper bound)?
const fn in_user_half(end: u64) -> bool {
    end <= USER_MAX
}

/// Validate the caller-supplied shape of a mapping request.
fn validate_shape(len: u64, offset: u64, prot: u32) -> Result<(), MapError> {
    if len == 0 || len % PAGE != 0 || len / PAGE > MAX_PAGES {
        return Err(MapError::BadRequest);
    }
    if offset % PAGE != 0 {
        return Err(MapError::BadRequest);
    }
    if prot & !PROT_VALID != 0 {
        return Err(MapError::BadRequest);
    }
    if prot & PROT_READ == 0 {
        return Err(MapError::BadRequest);
    }
    if prot & PROT_EXEC != 0 {
        // No executable file mappings in this slice.
        return Err(MapError::NotSupported);
    }
    Ok(())
}

/// Validate the caller-supplied shape of a shared-memory mapping request.
fn validate_shm_shape(prot: u32) -> Result<(), MapError> {
    if prot & !PROT_VALID != 0 {
        return Err(MapError::BadRequest);
    }
    if prot & PROT_READ == 0 {
        return Err(MapError::BadRequest);
    }
    if prot & PROT_EXEC != 0 {
        // Shared memory is data, never code.
        return Err(MapError::NotSupported);
    }
    Ok(())
}

/// Validate the caller-supplied shape of a display mapping request (M6c).
///
/// A display mapping is always `MAX_MAP_BYTES` (64 pages), so only the
/// permission bits are checked: read is mandatory, execute is refused because a
/// framebuffer is never code, and unknown bits are rejected.
fn validate_display_shape(prot: u32) -> Result<(), MapError> {
    if prot & !PROT_VALID != 0 {
        return Err(MapError::BadRequest);
    }
    if prot & PROT_READ == 0 {
        return Err(MapError::BadRequest);
    }
    if prot & PROT_EXEC != 0 {
        return Err(MapError::NotSupported);
    }
    Ok(())
}

/// `offset + len` must stay inside the file, without wrapping.
const fn range_fits(offset: u64, len: u64, file_size: u64) -> bool {
    match offset.checked_add(len) {
        Some(end) => end <= file_size,
        None => false,
    }
}

/// Does `prot` request write access?
const fn is_writable(prot: u32) -> bool {
    prot & PROT_WRITE != 0
}

/// First free slot in `table`.
fn free_slot(table: &[Option<Mapping>]) -> Option<usize> {
    table.iter().position(Option::is_none)
}

/// Index of the live mapping that covers exactly `(space, base, len)`.
fn find_exact(table: &[Option<Mapping>], space: usize, base: u64, len: u64) -> Option<usize> {
    table.iter().position(|slot| {
        matches!(slot, Some(mapping) if mapping.space.index() == space && mapping.base == base && mapping.len == len)
    })
}

/// Number of live mappings in one address space.
fn count_in_space(table: &[Option<Mapping>], space: usize) -> usize {
    table
        .iter()
        .flatten()
        .filter(|mapping| mapping.space.index() == space)
        .count()
}

/// Next base after the requested length (pure form used by tests).
#[cfg(test)]
const fn next_base_after(current: u64, len: u64) -> Option<u64> {
    let base = if current == 0 {
        FIRST_MAP_BASE
    } else {
        current
    };
    match base.checked_add(len) {
        Some(end) if in_user_half(end) => Some(end),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Error translation
// ---------------------------------------------------------------------------

fn map_vfs(error: VfsError) -> MapError {
    match error {
        VfsError::NotFound => MapError::NotFound,
        VfsError::Busy => MapError::Busy,
        VfsError::Quota | VfsError::NoMemory => MapError::NoMemory,
        VfsError::NotSupported => MapError::NotSupported,
        _ => MapError::Io,
    }
}

fn map_vm(error: VmError) -> MapError {
    match error {
        VmError::NotFound => MapError::NotFound,
        // Every residual mapping failure is a budget/limit problem: the caller's
        // range was validated above.
        _ => MapError::Quota,
    }
}

fn map_object(error: ObjectError) -> MapError {
    match error {
        ObjectError::BadHandle | ObjectError::InvalidObject => MapError::NotFound,
        _ => MapError::Io,
    }
}

/// Translate a shared-memory table failure into a mapping error.
/// Map a display-module error onto the mapping error set (M6c).
fn map_display_error(error: display::DisplayError) -> MapError {
    match error {
        // A missing/non-display object is a bad handle: the syscall layer must
        // have resolved a live `Display` object before calling us.
        display::DisplayError::NoSuchObject | display::DisplayError::WrongKind => {
            MapError::NotFound
        }
        display::DisplayError::TableFull | display::DisplayError::NoMemory => MapError::Quota,
        // `NotMapped`/`BadBuffer` are defensive: map_pages is the only producer
        // and it returns neither on a fresh call.
        display::DisplayError::NotMapped | display::DisplayError::BadBuffer => MapError::Io,
    }
}

fn map_shm_error(error: shm::ShmError) -> MapError {
    match error {
        shm::ShmError::TableFull | shm::ShmError::NoMemory => MapError::Quota,
        shm::ShmError::BadLength | shm::ShmError::WrongKind => MapError::BadRequest,
        shm::ShmError::NoSuchObject => MapError::NotFound,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(space: AddressSpaceId, base: u64, len: u64) -> Mapping {
        Mapping {
            space,
            base,
            len,
            offset: 0,
            prot: PROT_READ,
            shared: true,
            backing: Backing::File(OpenId::from_raw(1)),
        }
    }

    #[test]
    fn permission_bits_follow_the_frozen_rules() {
        assert!(validate_shape(PAGE, 0, PROT_READ).is_ok());
        assert!(validate_shape(PAGE, 0, PROT_READ | PROT_WRITE).is_ok());
        assert_eq!(validate_shape(PAGE, 0, 0), Err(MapError::BadRequest));
        assert_eq!(
            validate_shape(PAGE, 0, PROT_WRITE),
            Err(MapError::BadRequest)
        );
        assert_eq!(
            validate_shape(PAGE, 0, PROT_READ | PROT_EXEC),
            Err(MapError::NotSupported)
        );
        assert_eq!(
            validate_shape(PAGE, 0, PROT_READ | PROT_WRITE | PROT_EXEC),
            Err(MapError::NotSupported)
        );
        assert_eq!(
            validate_shape(PAGE, 0, PROT_READ | (1 << 7)),
            Err(MapError::BadRequest)
        );
    }

    #[test]
    fn length_and_offset_must_be_page_shaped_and_bounded() {
        assert_eq!(validate_shape(0, 0, PROT_READ), Err(MapError::BadRequest));
        assert_eq!(
            validate_shape(PAGE + 1, 0, PROT_READ),
            Err(MapError::BadRequest)
        );
        assert_eq!(
            validate_shape(MAX_MAP_BYTES + PAGE, 0, PROT_READ),
            Err(MapError::BadRequest)
        );
        assert!(validate_shape(MAX_MAP_BYTES, 0, PROT_READ).is_ok());
        assert_eq!(
            validate_shape(PAGE, 1, PROT_READ),
            Err(MapError::BadRequest)
        );
        assert!(validate_shape(PAGE, PAGE, PROT_READ).is_ok());
    }

    #[test]
    fn mapping_must_stay_inside_the_file() {
        assert!(range_fits(0, PAGE, PAGE));
        assert!(range_fits(PAGE, PAGE, 2 * PAGE));
        assert!(!range_fits(0, 2 * PAGE, PAGE));
        assert!(!range_fits(PAGE, PAGE, PAGE));
        assert!(!range_fits(u64::MAX - PAGE + 1, PAGE, u64::MAX));
        assert!(range_fits(0, 0, 0));
    }

    #[test]
    fn write_permission_comes_from_the_prot_bits() {
        assert!(!is_writable(PROT_READ));
        assert!(is_writable(PROT_READ | PROT_WRITE));
    }

    #[test]
    fn bases_bump_from_the_frozen_start_and_never_wrap() {
        assert_eq!(next_base_after(0, PAGE), Some(FIRST_MAP_BASE + PAGE));
        assert_eq!(
            next_base_after(FIRST_MAP_BASE, 2 * PAGE),
            Some(FIRST_MAP_BASE + 2 * PAGE)
        );
        assert_eq!(next_base_after(u64::MAX - PAGE, PAGE), None);
        assert_eq!(next_base_after(USER_MAX - PAGE, PAGE), Some(USER_MAX));
        assert_eq!(next_base_after(USER_MAX, PAGE), None);
        assert_eq!(FIRST_MAP_BASE % PAGE, 0);
    }

    #[test]
    fn slot_lookup_requires_the_exact_range() {
        // `AddressSpaceId` has no public constructor, so a host test can only
        // use the documented placeholder. That still exercises the space filter
        // (nothing lives in index 0 here) and the exact range match.
        let placeholder = AddressSpaceId::INVALID;
        let mut table: [Option<Mapping>; 4] = [None; 4];
        table[0] = Some(sample(placeholder, FIRST_MAP_BASE, PAGE));
        table[1] = Some(sample(placeholder, FIRST_MAP_BASE + PAGE, PAGE));

        let space = placeholder.index();
        assert_eq!(find_exact(&table, space, FIRST_MAP_BASE, PAGE), Some(0));
        assert_eq!(
            find_exact(&table, space, FIRST_MAP_BASE + PAGE, PAGE),
            Some(1)
        );
        assert_eq!(find_exact(&table, space, FIRST_MAP_BASE, 2 * PAGE), None);
        assert_eq!(find_exact(&table, space, FIRST_MAP_BASE + 1, PAGE), None);
        assert_eq!(find_exact(&table, 0, FIRST_MAP_BASE, PAGE), None);
        assert_eq!(count_in_space(&table, space), 2);
        assert_eq!(count_in_space(&table, 0), 0);
    }

    #[test]
    fn fixed_tables_enforce_their_limits() {
        let placeholder = AddressSpaceId::INVALID;
        let mut table: [Option<Mapping>; 2] = [None; 2];
        assert_eq!(free_slot(&table), Some(0));
        table[0] = Some(sample(placeholder, FIRST_MAP_BASE, PAGE));
        assert_eq!(free_slot(&table), Some(1));
        table[1] = Some(sample(placeholder, FIRST_MAP_BASE + PAGE, PAGE));
        assert_eq!(free_slot(&table), None);
        assert_eq!(count_in_space(&table, placeholder.index()), 2);
        assert!(MAX_MAPPINGS_PER_SPACE < MAX_MAPPINGS);
        assert_eq!(MAX_PAGES, 64);
    }

    #[test]
    fn shared_memory_permissions_are_data_only() {
        assert!(validate_shm_shape(PROT_READ).is_ok());
        assert!(validate_shm_shape(PROT_READ | PROT_WRITE).is_ok());
        assert_eq!(validate_shm_shape(0), Err(MapError::BadRequest));
        assert_eq!(validate_shm_shape(PROT_WRITE), Err(MapError::BadRequest));
        assert_eq!(
            validate_shm_shape(PROT_READ | PROT_EXEC),
            Err(MapError::NotSupported)
        );
        assert_eq!(
            validate_shm_shape(PROT_READ | (1 << 7)),
            Err(MapError::BadRequest)
        );
    }

    #[test]
    fn display_permissions_are_data_only() {
        assert!(validate_display_shape(PROT_READ).is_ok());
        assert!(validate_display_shape(PROT_READ | PROT_WRITE).is_ok());
        assert_eq!(validate_display_shape(0), Err(MapError::BadRequest));
        assert_eq!(
            validate_display_shape(PROT_WRITE),
            Err(MapError::BadRequest)
        );
        assert_eq!(
            validate_display_shape(PROT_READ | PROT_EXEC),
            Err(MapError::NotSupported)
        );
        assert_eq!(
            validate_display_shape(PROT_READ | (1 << 7)),
            Err(MapError::BadRequest)
        );
        // A display mapping always covers the whole framebuffer: 64 frames.
        assert_eq!(DISPLAY_PAGES as u64 * PAGE, MAX_MAP_BYTES);
        assert_eq!(DISPLAY_PAGES as u64, MAX_PAGES);
    }

    #[test]
    fn display_errors_map_onto_mapping_errors() {
        assert_eq!(
            map_display_error(display::DisplayError::NoSuchObject),
            MapError::NotFound
        );
        assert_eq!(
            map_display_error(display::DisplayError::WrongKind),
            MapError::NotFound
        );
        assert_eq!(
            map_display_error(display::DisplayError::TableFull),
            MapError::Quota
        );
        assert_eq!(
            map_display_error(display::DisplayError::NoMemory),
            MapError::Quota
        );
        assert_eq!(
            map_display_error(display::DisplayError::NotMapped),
            MapError::Io
        );
        assert_eq!(
            map_display_error(display::DisplayError::BadBuffer),
            MapError::Io
        );
    }

    #[test]
    fn error_names_are_stable() {
        assert_eq!(MapError::BadRequest.as_str(), "bad request");
        assert_eq!(MapError::NotFound.as_str(), "no such mapping");
        assert_eq!(MapError::Quota.as_str(), "mapping quota exceeded");
        assert_eq!(MapError::Busy.as_str(), "mapping is busy");
        assert_eq!(MapError::Io.as_str(), "mapping i/o error");
        assert_eq!(MapError::NoMemory.as_str(), "out of mapping memory");
        assert_eq!(MapError::NotSupported.as_str(), "mapping not supported");
    }

    /// Probe hook: records how many deferred releases ran and whether the
    /// pending-queue lock was still held while they did.
    mod pending_probe {
        use super::*;
        use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

        static HOOKS: AtomicUsize = AtomicUsize::new(0);
        static LOCK_HELD: AtomicBool = AtomicBool::new(false);

        pub(super) fn reset() {
            HOOKS.store(0, Ordering::SeqCst);
            LOCK_HELD.store(false, Ordering::SeqCst);
        }

        pub(super) fn count() -> usize {
            HOOKS.load(Ordering::SeqCst)
        }

        pub(super) fn lock_was_held() -> bool {
            LOCK_HELD.load(Ordering::SeqCst)
        }

        pub(super) fn record(_kind: ObjectKind, _payload: u64, _object: ObjectId) {
            HOOKS.fetch_add(1, Ordering::SeqCst);
            // `release_object` may run a destroy hook; that side effect must
            // happen after the queue lock is gone, never under it.
            LOCK_HELD.fetch_or(PENDING_LOCK.is_locked(), Ordering::SeqCst);
        }
    }

    #[test]
    fn deferred_shared_memory_releases_run_outside_the_pending_lock() {
        let _guard = object::test_lock();
        object::reset_destroy_hooks();
        pending_probe::reset();
        object::register_destroy_hook_with_object(ObjectKind::SharedMemory, pending_probe::record)
            .expect("register probe hook");

        // `create_with_payload` hands out one reference, exactly like the
        // reference a live mapping holds; queuing it is what teardown does.
        let first = object::create_with_payload(ObjectKind::SharedMemory, 0).expect("first");
        let second = object::create_with_payload(ObjectKind::SharedMemory, 0).expect("second");
        queue_pending_shm(first);
        queue_pending_shm(second);
        assert!(
            !PENDING_LOCK.is_locked(),
            "queueing must not leave the leaf lock held"
        );

        assert_eq!(release_pending(), 2, "both queued references are drained");
        assert_eq!(pending_probe::count(), 2, "one destroy hook per reference");
        assert!(
            !pending_probe::lock_was_held(),
            "release side effects must run outside PENDING_LOCK"
        );
        assert!(object::object_kind(first).is_none());
        assert!(object::object_kind(second).is_none());
        assert_eq!(
            release_pending(),
            0,
            "the queue is empty after the first drain"
        );

        object::reset_destroy_hooks();
    }

    #[test]
    fn deferred_display_releases_run_outside_the_pending_lock() {
        let _guard = object::test_lock();
        object::reset_destroy_hooks();
        pending_probe::reset();
        object::register_destroy_hook_with_object(ObjectKind::Display, pending_probe::record)
            .expect("register probe hook");

        // Same contract as shared memory: the reference a live mapping holds is
        // queued by teardown and released after PENDING_LOCK is gone.
        let display_object = object::create_with_payload(ObjectKind::Display, 0).expect("display");
        queue_pending_display(display_object);
        assert!(
            !PENDING_LOCK.is_locked(),
            "queueing must not leave the leaf lock held"
        );

        assert_eq!(
            release_pending(),
            1,
            "the queued display reference is drained"
        );
        assert_eq!(pending_probe::count(), 1, "one destroy hook per reference");
        assert!(
            !pending_probe::lock_was_held(),
            "release side effects must run outside PENDING_LOCK"
        );
        assert!(object::object_kind(display_object).is_none());
        assert_eq!(release_pending(), 0, "the queue is empty after draining");
        object::reset_destroy_hooks();
    }

    /// Display destroy-hook adapter used by the release-ordering test below.
    fn finish_display(_kind: ObjectKind, _payload: u64, object: ObjectId) {
        display::on_destroy(object);
    }

    #[test]
    fn display_mapping_release_balances_map_count_and_defers_the_reference() {
        let _guard = object::test_lock();
        object::reset_destroy_hooks();
        display::reset();
        object::register_destroy_hook_with_object(ObjectKind::Display, finish_display)
            .expect("register display hook");

        let display_object =
            object::create_with_payload(ObjectKind::Display, 0).expect("display object");
        display::create(display_object).expect("display state");
        assert_eq!(display::live_objects(), 1);

        // The mapping's own `map_pages` registration, then the object reference
        // a real `map_display` would hold for the mapping's lifetime.
        let mut frames = [0u64; DISPLAY_PAGES];
        display::map_pages(display_object, &mut frames).expect("map pages");
        assert_eq!(display::map_count(display_object), Some(1));
        object::acquire_object(display_object).expect("mapping reference");

        // A teardown with no live address space: `unmap_user` fails softly, the
        // display count must still be balanced and the reference deferred.
        let mapping = Mapping {
            space: AddressSpaceId::INVALID,
            base: FIRST_MAP_BASE,
            len: MAX_MAP_BYTES,
            offset: 0,
            prot: PROT_READ,
            shared: true,
            backing: Backing::Display(display_object),
        };
        release_mapping(mapping);
        assert_eq!(
            display::map_count(display_object),
            Some(0),
            "release must pair the map_pages registration"
        );
        assert_eq!(
            object::object_kind(display_object),
            Some(ObjectKind::Display),
            "the mapping reference is deferred, not dropped in the hook"
        );

        assert_eq!(release_pending(), 1, "the display reference is drained");
        assert_eq!(
            display::live_frames(),
            DISPLAY_PAGES,
            "frames survive until the last object reference"
        );

        let _ = object::release_object(display_object);
        assert!(object::object_kind(display_object).is_none());
        assert_eq!(
            display::live_frames(),
            0,
            "the display hook frees the frames"
        );
        assert_eq!(release_pending(), 0, "nothing left to drain");

        object::reset_destroy_hooks();
    }
}
