//! Per-process user address spaces (M4).
//!
//! [`create`] allocates an independent PML4 from the PMM, zeroes the user half
//! and copies the kernel half (`PML4[256..512]`) out of the active kernel
//! tables, so every address space shares the kernel mappings exactly as `vm`
//! built them at takeover time (agents.md §7.1: 每进程有独立用户地址空间；内核
//! 映射在各进程间共享受控部分).
//!
//! The surface is deliberately small:
//!
//! * [`map_user`] installs 4 KiB user leaves from caller-supplied physical
//!   frames, taking ownership of them (they are freed by [`destroy`]);
//! * [`map_user_borrowed`] installs leaves over frames the address space does
//!   *not* own — page-cache pages shared into a process (M5c2). They are never
//!   freed here; only the mapping goes away;
//! * [`unmap_user`] removes a range, freeing exactly the frames it owns;
//! * [`protect_user`] rewrites leaf permissions in place, for either kind, and
//!   [`protect_user_noaccess`] turns an existing mapping into `PROT_NONE`: the
//!   frame stays owned, `PRESENT` is withdrawn and [`PTE_NOACCESS`] records a
//!   mapping that faults on every access;
//! * [`is_user_mapped`] answers whether a page is mapped at all (`PROT_NONE`
//!   included), which is what `mprotect`-style bookkeeping needs;
//! * [`copy_in`]/[`copy_out`] move bytes through a page-table walk plus the
//!   direct map — the kernel never dereferences a user virtual address
//!   (agents.md §7.2: 内核访问用户指针只能经过 copy-in/copy-out);
//! * [`activate`] switches CR3, [`destroy`] frees every tracked frame.
//!
//! Deliberately *not* here (later milestones): demand paging, `#PF` handling,
//! COW, huge user pages, and KPTI's separate user/kernel tables. M5c2 only adds
//! the eager primitives a file `mmap` needs: shared mappings borrow page-cache
//! frames, private mappings copy into owned frames elsewhere.
//!
//! ## Fixed capacity
//!
//! M4 needs at most [`MAX_SPACES`] address spaces, each with at most
//! [`MAX_USER_FRAMES`] user frames and [`MAX_TABLE_FRAMES`] page-table frames
//! (the root PML4 counts as one of them). Nothing here touches the heap, and no
//! allocation happens in interrupt context: `create`/`map_user` run on the
//! normal kernel stack.
//!
//! ## Host tests
//!
//! Page-table frames come from a [`FramePool`], the physical→kernel-address
//! translation is the single [`phys_ptr`] helper, and `invlpg`/`mov cr3` are
//! `cfg(not(test))` only. A host test therefore drives the entire walk/mapping
//! logic with frames that are ordinary page-aligned heap buffers (their
//! "physical" address is simply their host address).

use core::ptr;
use core::sync::atomic::{AtomicU8, Ordering};

#[cfg(not(test))]
use super::pmm;
use super::pmm::FRAME_SIZE;
#[cfg(not(test))]
use super::pmm::MAX_ALLOC_ADDR;
use super::vm::{self, ADDR_MASK, PTE_NX, PTE_PRESENT, PTE_USER, PTE_WRITE, PageTable, VmError};
use crate::arch;

/// Exclusive upper bound of the user half. The last canonical low-half address
/// is `0x0000_7FFF_FFFF_FFFF`, so a user mapping must stay strictly below this.
pub const USER_MAX: u64 = 0x0000_8000_0000_0000;

/// Address spaces a build may keep alive at once (must match
/// `process::MAX_PROCESSES`).
///
/// M4 needed init plus one child. M6b2 keeps the last user process alive (its
/// kernel stack and address space stay mapped until the closing fault) and adds
/// two detached workers, so three spaces were live simultaneously.
///
/// M9c runs native bootstrap, the lock-peer parent, role1 and role2 at the same
/// time, so four spaces must coexist (Lead m04884). Only the capacity grows;
/// mapping and teardown logic are unchanged.
pub const MAX_SPACES: usize = 4;
/// User page frames tracked per address space (freed by [`destroy`]).
///
/// Only *owned* frames count against this budget: frames installed by
/// [`map_user_borrowed`] belong to the page cache and are never freed here, so
/// they do not consume slots. M5c2 raised the old M4 value (64) to 256 for a
/// small mapped file plus stack and image segments.
///
/// M10a raises it to 2048 (8 MiB) so a real dynamically linked musl program
/// fits: the loader, libc, a busybox heap and its stack exceed the old cap. The
/// budget is a per-space *cap*, not a reservation -- frames are still allocated
/// on demand and freed by [`destroy`]. Worst case, with all [`MAX_SPACES`]
/// spaces filled, is 4 x 8 MiB = 32 MiB of owned user frames.
/// [`MAX_TABLE_FRAMES`] (16) still covers the page tables an 8 MiB mapping
/// needs: at most four 2 MiB windows (one PT each) plus the PML4, PDPT and PD
/// frames.
pub const MAX_USER_FRAMES: usize = 2048;
/// Page-table frames per address space, including the PML4 root.
pub const MAX_TABLE_FRAMES: usize = 16;

/// Software-only "mapped but inaccessible" leaf bit (x86-64 AVL bit 9).
///
/// `mprotect(PROT_NONE)` must keep the mapping and its frame while making every
/// access fault. Clearing `PRESENT` gives the fault, but a not-present leaf is
/// otherwise indistinguishable from an untouched hole, so the walk would forget
/// that this page still owns a frame. Bit 9 sits below the physical-address bits
/// (bit 12) and is available for software in every page-table entry, which makes
/// it the right place to record "still mapped, never accessible".
pub const PTE_NOACCESS: u64 = 1 << 9;

const PAGE_SIZE: u64 = FRAME_SIZE;
/// First PML4 index that belongs to the shared kernel half.
const PML4_KERNEL_START: usize = 256;
/// Sentinel for "no address space is active".
const NONE: u8 = u8::MAX;

/// Handle to one live user address space.
///
/// The value is a slot index, not a kernel address and not a pointer; callers
/// must not fabricate one. It stays valid until [`destroy`].
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct AddressSpaceId(u8);

impl AddressSpaceId {
    /// Placeholder for "this slot holds no live address space".
    ///
    /// `process` uses it when a process table entry has no address space yet, so
    /// a caller can store a value instead of an `Option`. It is **not** a live
    /// handle: [`activate`] refuses it (nothing is switched) and [`destroy`]
    /// returns [`VmError::NotFound`]; its [`index`](Self::index) is out of range
    /// for every slot array in this module.
    pub const INVALID: Self = Self(NONE);

    const fn from_index(index: usize) -> Self {
        AddressSpaceId(index as u8)
    }

    /// Slot index, for diagnostics and `[`MAX_SPACES`]`-bounded bookkeeping.
    pub const fn index(self) -> usize {
        self.0 as usize
    }

    /// Raw slot byte (ABI-neutral; not for persistence or user exposure).
    pub const fn raw(self) -> u8 {
        self.0
    }
}

/// Runtime state of one address space.
///
/// `pml4 == 0` means the slot is free. `tables[0]` is always the root PML4, so
/// [`destroy`] can release every page-table frame without re-walking.
#[derive(Clone, Copy)]
struct SpaceState {
    pml4: u64,
    n_user: u16,
    n_table: u8,
    user: [u64; MAX_USER_FRAMES],
    tables: [u64; MAX_TABLE_FRAMES],
}

impl SpaceState {
    const EMPTY: SpaceState = SpaceState {
        pml4: 0,
        n_user: 0,
        n_table: 0,
        user: [0; MAX_USER_FRAMES],
        tables: [0; MAX_TABLE_FRAMES],
    };

    fn is_empty(&self) -> bool {
        self.pml4 == 0
    }
}

static mut SPACES: [SpaceState; MAX_SPACES] = [SpaceState::EMPTY; MAX_SPACES];

/// Which address space each CPU is currently running on ([`AddressSpaceId::raw`],
/// or [`NONE`] when none is loaded).
///
/// One slot per CPU (M6b2a): [`activate`] writes only the calling CPU's entry and
/// [`is_active`] reads only that entry, so two CPUs can run different processes
/// at the same time. Cross-CPU queries are not part of the API: a space that is
/// active *elsewhere* is not "active" here, and [`destroy`] therefore only
/// refuses to free a space the *current* CPU is running on.
static mut ACTIVE: [AtomicU8; arch::MAX_CPUS] = [const { AtomicU8::new(NONE) }; arch::MAX_CPUS];

/// Logical index of the calling CPU, validated against [`arch::MAX_CPUS`].
fn current_cpu() -> usize {
    let cpu = arch::cpu_index();
    assert!(cpu < arch::MAX_CPUS, "cpu index out of range");
    cpu
}

/// The per-CPU active slots as a shared array (atomics need no lock).
fn active_slots() -> &'static [AtomicU8; arch::MAX_CPUS] {
    // SAFETY: `ACTIVE` is a kernel-lifetime `.bss` static and its entries are
    // atomic, so concurrent access from several CPUs is defined.
    unsafe { &*ptr::addr_of!(ACTIVE) }
}

/// Address-space slot `cpu` is running on, or [`NONE`].
fn active_on(cpu: usize) -> u8 {
    active_slots()[cpu].load(Ordering::Relaxed)
}

/// Record that `cpu` now runs slot `raw` (or [`NONE`]).
fn set_active_on(cpu: usize, raw: u8) {
    active_slots()[cpu].store(raw, Ordering::Relaxed);
}

/// Pure per-CPU core of [`is_active`]: is `id` the space loaded on `cpu`?
fn is_active_on(cpu: usize, id: AddressSpaceId) -> bool {
    id != AddressSpaceId::INVALID && usize::from(active_on(cpu)) == id.index()
}

// ---------------------------------------------------------------------------
// Frame source
// ---------------------------------------------------------------------------

/// Source of physical frames for roots and page tables.
///
/// Contract: `alloc` returns an exclusively owned, 4 KiB aligned frame that the
/// caller may freely overwrite through [`phys_ptr`]; `free` returns it to the
/// source. The kernel uses the PMM (frames below [`MAX_ALLOC_ADDR`], so the
/// direct map aliases them); host tests use a page-aligned heap arena.
trait FramePool {
    fn alloc(&mut self) -> Result<u64, VmError>;
    fn free(&mut self, phys: u64);
}

#[cfg(not(test))]
struct PmmPool;

#[cfg(not(test))]
impl FramePool for PmmPool {
    fn alloc(&mut self) -> Result<u64, VmError> {
        pmm::alloc_frame().map_err(|_| VmError::OutOfTables)
    }

    fn free(&mut self, phys: u64) {
        // A frame that the PMM already lost track of is a bug worth surfacing at
        // the allocation site, not here: `destroy` must finish freeing the rest.
        let _ = pmm::dealloc_frame(phys);
    }
}

#[cfg(not(test))]
static mut PROD_POOL: PmmPool = PmmPool;

#[cfg(not(test))]
fn global_pool() -> &'static mut dyn FramePool {
    // SAFETY: single-CPU M4 kernel; `create`/`destroy` never run concurrently
    // (no SMP) and never from an ISR.
    unsafe { &mut *ptr::addr_of_mut!(PROD_POOL) }
}

// ---------------------------------------------------------------------------
// Host-test frame source
// ---------------------------------------------------------------------------
//
// Lives at module scope (not inside `mod tests`) because the public API resolves
// `global_pool()` under both cfgs; only the *global* pool is test-only, while
// the unit tests below build explicit pools and never touch it.

#[cfg(test)]
static mut TEST_POOL: TestPool = TestPool::EMPTY;

#[cfg(test)]
fn global_pool() -> &'static mut dyn FramePool {
    // SAFETY: only the serialized public-API test reaches this pool, and it
    // holds a process-wide mutex while doing so.
    unsafe { &mut *ptr::addr_of_mut!(TEST_POOL) }
}

/// Page-aligned heap arena that lives for the rest of the test binary.
#[cfg(test)]
fn arena(frames: usize) -> *mut u8 {
    use std::alloc::{Layout, alloc_zeroed};

    let layout = Layout::from_size_align(frames * PAGE_SIZE as usize, PAGE_SIZE as usize)
        .expect("arena layout");
    // SAFETY: non-zero size with a power-of-two alignment.
    let raw = unsafe { alloc_zeroed(layout) };
    assert!(!raw.is_null(), "test frame arena");
    raw
}

/// Host frame source: "physical" addresses are the heap addresses of
/// page-aligned buffers, so [`phys_ptr`] is the identity.
#[cfg(test)]
struct TestPool {
    base: *mut u8,
    cap: usize,
    next: usize,
    freed: [u64; 512],
    n_free: usize,
}

#[cfg(test)]
impl TestPool {
    const EMPTY: TestPool = TestPool {
        base: ptr::null_mut(),
        cap: 0,
        next: 0,
        freed: [0; 512],
        n_free: 0,
    };

    fn new(frames: usize) -> TestPool {
        TestPool {
            base: arena(frames),
            cap: frames,
            next: 0,
            freed: [0; 512],
            n_free: 0,
        }
    }

    fn freed(&self) -> usize {
        self.n_free
    }

    fn ensure_arena(&mut self) {
        if self.base.is_null() {
            let frames = self.cap.max(64);
            self.base = arena(frames);
            self.cap = frames;
        }
    }
}

#[cfg(test)]
impl FramePool for TestPool {
    fn alloc(&mut self) -> Result<u64, VmError> {
        self.ensure_arena();
        if self.n_free > 0 {
            self.n_free -= 1;
            return Ok(self.freed[self.n_free]);
        }
        if self.next >= self.cap {
            return Err(VmError::OutOfTables);
        }
        let phys = self.base as u64 + (self.next as u64) * PAGE_SIZE;
        self.next += 1;
        // SAFETY: unique frame inside the leaked arena.
        unsafe { ptr::write_bytes(phys as *mut u8, 0, PAGE_SIZE as usize) };
        Ok(phys)
    }

    fn free(&mut self, phys: u64) {
        if self.n_free < self.freed.len() {
            self.freed[self.n_free] = phys;
            self.n_free += 1;
        }
    }
}

/// Kernel address aliasing one physical frame.
#[cfg(not(test))]
fn phys_ptr(phys: u64) -> *mut u8 {
    // The PMM only hands out frames below MAX_ALLOC_ADDR, which the takeover
    // tables cover with the direct map (vm::phys_to_virt).
    debug_assert!(phys < MAX_ALLOC_ADDR);
    vm::phys_to_virt(phys) as *mut u8
}

/// Test frames live in ordinary heap memory: their "physical" address is their
/// host address, so the direct map is the identity.
#[cfg(test)]
fn phys_ptr(phys: u64) -> *mut u8 {
    phys as *mut u8
}

/// Whether the bytes ending at `phys_end` are reachable through [`phys_ptr`].
#[cfg(not(test))]
fn frame_reachable(phys_end: u64) -> bool {
    phys_end <= MAX_ALLOC_ADDR
}

/// Host frames are addressed by identity, so any address is reachable.
#[cfg(test)]
fn frame_reachable(_phys_end: u64) -> bool {
    true
}

/// View a physical page-table frame.
///
/// # Safety
/// `phys` must be a page-table frame allocated by this module (or, for the
/// source root in [`init_space`], the live kernel PML4), and it must not be
/// interpreted as anything else while the returned pointer is in use.
unsafe fn table_at(phys: u64) -> *mut PageTable {
    phys_ptr(phys) as *mut PageTable
}

// ---------------------------------------------------------------------------
// Core (pool- and state-explicit, host-testable)
// ---------------------------------------------------------------------------

/// Validate a user mapping request and return its exclusive end address.
fn user_range_end(virt: u64, len: u64) -> Result<u64, VmError> {
    if len == 0 || len % PAGE_SIZE != 0 {
        return Err(VmError::BadAddress);
    }
    if virt & (PAGE_SIZE - 1) != 0 || virt >= USER_MAX {
        return Err(VmError::BadAddress);
    }
    let end = virt.checked_add(len).ok_or(VmError::BadAddress)?;
    if end > USER_MAX {
        return Err(VmError::BadAddress);
    }
    Ok(end)
}

/// Clear `state` back to the empty slot encoding, in place.
///
/// Field-wise instead of `*state = SpaceState::EMPTY`: a `SpaceState` is over
/// 16 KiB now (`user: [u64; MAX_USER_FRAMES]`, 2048 entries), and assigning a
/// whole value through the stack is what overflowed the 16 KiB boot stack in
/// QEMU when the array was still small. Do not reintroduce a by-value copy.
fn reset_state(state: &mut SpaceState) {
    state.pml4 = 0;
    state.n_user = 0;
    state.n_table = 0;
    state.user.fill(0);
    state.tables.fill(0);
}

/// Build a fresh address space directly `into` its static slot: zeroed user
/// half, kernel half copied.
///
/// On failure nothing is leaked and `into` is left untouched: the only fallible
/// step is the root allocation, which either succeeds or leaves no frame behind,
/// and it runs before any mutation.
fn init_space(
    pool: &mut dyn FramePool,
    kernel_pml4: *const PageTable,
    into: &mut SpaceState,
) -> Result<(), VmError> {
    let root_phys = pool.alloc()?;
    // SAFETY: `alloc` handed over an exclusive frame; PMM frames come back dirty
    // so clear them before installing any entries.
    unsafe { ptr::write_bytes(phys_ptr(root_phys), 0, PAGE_SIZE as usize) };

    reset_state(into);
    into.pml4 = root_phys;
    into.tables[0] = root_phys;
    into.n_table = 1;

    // SAFETY: `root_phys` is our exclusive table frame; `kernel_pml4` points at
    // the kernel's own PML4, which outlives every address space.
    unsafe {
        let root = table_at(root_phys);
        for i in PML4_KERNEL_START..512 {
            (*root).entries[i] = (*kernel_pml4).entries[i];
        }
    }
    Ok(())
}

/// Allocate and zero one page-table frame, tracking it for [`destroy`].
fn alloc_table(pool: &mut dyn FramePool, state: &mut SpaceState) -> Result<u64, VmError> {
    if usize::from(state.n_table) >= MAX_TABLE_FRAMES {
        return Err(VmError::OutOfTables);
    }
    let phys = pool.alloc()?;
    // SAFETY: exclusive fresh frame; page tables must start all-zero.
    unsafe { ptr::write_bytes(phys_ptr(phys), 0, PAGE_SIZE as usize) };
    state.tables[usize::from(state.n_table)] = phys;
    state.n_table += 1;
    Ok(phys)
}

/// Return `parent[index]`'s child table, installing a zeroed one if absent.
///
/// Intermediate entries carry `PRESENT|WRITE|USER` and no `NX`: bit 63 is only
/// meaningful on leaves, and leaving it clear keeps the tables free of
/// reserved-bit surprises.
///
/// # Safety
/// `parent` must be a page-table frame owned by `state`.
unsafe fn ensure_table(
    pool: &mut dyn FramePool,
    state: &mut SpaceState,
    parent: *mut PageTable,
    index: usize,
) -> Result<*mut PageTable, VmError> {
    // SAFETY: caller guarantees `parent` is one of our table frames.
    let entry = unsafe { (*parent).entries[index] };
    if entry & PTE_PRESENT != 0 {
        // A large leaf (PS) or a kernel-only table cannot parent a user mapping.
        if entry & vm::PTE_PS != 0 || entry & PTE_USER == 0 {
            return Err(VmError::Overlap);
        }
        // SAFETY: the entry names a table frame that `ensure_table` allocated.
        return Ok(unsafe { table_at(entry & ADDR_MASK) });
    }
    let phys = alloc_table(pool, state)?;
    // SAFETY: `parent` is ours and `phys` is a fresh zeroed table frame.
    unsafe {
        (*parent).entries[index] = (phys & ADDR_MASK) | PTE_PRESENT | PTE_WRITE | PTE_USER;
    }
    // SAFETY: `phys` is exclusively ours.
    Ok(unsafe { table_at(phys) })
}

/// Whether a leaf entry still represents a live user mapping.
///
/// A `PROT_NONE` page keeps its frame and leaf but drops `PRESENT`;
/// [`PTE_NOACCESS`] is the software record of that state. A zero entry, or one
/// with neither bit set, is a hole.
const fn leaf_is_mapped(entry: u64) -> bool {
    entry & (PTE_PRESENT | PTE_NOACCESS) != 0
}

/// Walk the user half and return the leaf entry for `virt`.
///
/// With `include_noaccess == false` only hardware-present leaves are returned:
/// that is the CPU's view and the view of every helper that must not treat a
/// `PROT_NONE` page as accessible ([`translate_user`], copy-in/out). With
/// `include_noaccess == true` a [`PTE_NOACCESS`] leaf is returned too — the view
/// of the lifetime helpers ([`unmap_user`], [`protect_user`], [`destroy`]'s
/// bookkeeping), which must still see the mapping they own.
///
/// `Ok(None)` means "no mapping"; `Err(BadAddress)` means the walk hit a
/// structure a user mapping can never live under (kernel-only table, or a large
/// page — M4 never creates user huge pages).
fn leaf_entry_matching(
    state: &SpaceState,
    virt: u64,
    include_noaccess: bool,
) -> Result<Option<u64>, VmError> {
    if virt >= USER_MAX {
        return Err(VmError::BadAddress);
    }
    // SAFETY: `state.pml4` and every table reached through a PRESENT entry were
    // allocated by this module and are not freed while `state` is live.
    unsafe {
        let pml4 = table_at(state.pml4);
        let mut entry = (*pml4).entries[vm::pml4_index(virt)];
        if entry & PTE_PRESENT == 0 {
            return Ok(None);
        }
        if entry & PTE_USER == 0 || entry & vm::PTE_PS != 0 {
            return Err(VmError::BadAddress);
        }
        let pdpt = table_at(entry & ADDR_MASK);
        entry = (*pdpt).entries[vm::pdpt_index(virt)];
        if entry & PTE_PRESENT == 0 {
            return Ok(None);
        }
        if entry & PTE_USER == 0 || entry & vm::PTE_PS != 0 {
            return Err(VmError::BadAddress);
        }
        let pd = table_at(entry & ADDR_MASK);
        entry = (*pd).entries[vm::pd_index(virt)];
        if entry & PTE_PRESENT == 0 {
            return Ok(None);
        }
        if entry & PTE_USER == 0 || entry & vm::PTE_PS != 0 {
            return Err(VmError::BadAddress);
        }
        let pt = table_at(entry & ADDR_MASK);
        entry = (*pt).entries[vm::pt_index(virt)];
        if entry & PTE_PRESENT != 0 || (include_noaccess && entry & PTE_NOACCESS != 0) {
            return Ok(Some(entry));
        }
    }
    Ok(None)
}

/// Hardware's view of a leaf: only a present entry is a mapping.
fn leaf_entry(state: &SpaceState, virt: u64) -> Result<Option<u64>, VmError> {
    leaf_entry_matching(state, virt, false)
}

/// The address space's view of a leaf: `PROT_NONE` still counts as mapped.
fn mapped_leaf_entry(state: &SpaceState, virt: u64) -> Result<Option<u64>, VmError> {
    leaf_entry_matching(state, virt, true)
}

/// Overwrite the leaf entry for `virt`.
///
/// The leaf must already carry a live mapping — `PRESENT` or [`PTE_NOACCESS`] —
/// because the walk never allocates here: this is the write side of
/// [`leaf_entry`], used by [`unmap_user_in`], [`protect_user_in`] and
/// [`protect_noaccess_in`]. `Ok(())` means the entry was replaced; a missing leaf
/// or a page-table level a user mapping can never live under keeps the old
/// value.
fn set_leaf(state: &SpaceState, virt: u64, value: u64) -> Result<(), VmError> {
    if virt >= USER_MAX {
        return Err(VmError::BadAddress);
    }
    // SAFETY: same invariants as `leaf_entry` — every table is one this module
    // allocated for `state` and stays live while the state exists.
    unsafe {
        let pml4 = table_at(state.pml4);
        let mut entry = (*pml4).entries[vm::pml4_index(virt)];
        if entry & PTE_PRESENT == 0 {
            return Err(VmError::NotFound);
        }
        if entry & PTE_USER == 0 || entry & vm::PTE_PS != 0 {
            return Err(VmError::BadAddress);
        }
        let pdpt = table_at(entry & ADDR_MASK);
        entry = (*pdpt).entries[vm::pdpt_index(virt)];
        if entry & PTE_PRESENT == 0 {
            return Err(VmError::NotFound);
        }
        if entry & PTE_USER == 0 || entry & vm::PTE_PS != 0 {
            return Err(VmError::BadAddress);
        }
        let pd = table_at(entry & ADDR_MASK);
        entry = (*pd).entries[vm::pd_index(virt)];
        if entry & PTE_PRESENT == 0 {
            return Err(VmError::NotFound);
        }
        if entry & PTE_USER == 0 || entry & vm::PTE_PS != 0 {
            return Err(VmError::BadAddress);
        }
        let pt = table_at(entry & ADDR_MASK);
        let index = vm::pt_index(virt);
        // `PROT_NONE` leaves stay writable through the software path so that
        // unmap and permission restore can find them again.
        if !leaf_is_mapped((*pt).entries[index]) {
            return Err(VmError::NotFound);
        }
        (*pt).entries[index] = value;
    }
    Ok(())
}

/// Install one 4 KiB user leaf.
fn install_leaf(
    pool: &mut dyn FramePool,
    state: &mut SpaceState,
    virt: u64,
    phys: u64,
    flags: u64,
) -> Result<(), VmError> {
    // SAFETY: `state.pml4` is ours; `ensure_table` only ever returns frames we
    // allocated, so each level below is a live table of this address space.
    unsafe {
        let root = table_at(state.pml4);
        let pdpt = ensure_table(pool, state, root, vm::pml4_index(virt))?;
        let pd = ensure_table(pool, state, pdpt, vm::pdpt_index(virt))?;
        let pt = ensure_table(pool, state, pd, vm::pd_index(virt))?;
        let index = vm::pt_index(virt);
        // A `PROT_NONE` leaf still owns its frame; installing over it would
        // strand that frame in the owned list with no mapping left to find it.
        if leaf_is_mapped((*pt).entries[index]) {
            return Err(VmError::Overlap);
        }
        (*pt).entries[index] = (phys & ADDR_MASK) | flags;
    }
    Ok(())
}

/// Map `len` bytes of caller-owned physical frames at `virt`.
///
/// The whole request is validated *before* the first leaf is installed: an
/// overlap, an oversized request or a bad argument leaves the address space
/// untouched. If a table allocation fails midway the leaves already installed
/// stay tracked, so [`destroy`] still releases every frame.
fn map_user_in(
    pool: &mut dyn FramePool,
    state: &mut SpaceState,
    virt: u64,
    phys: u64,
    len: u64,
    writable: bool,
    executable: bool,
) -> Result<(), VmError> {
    map_range_in(pool, state, virt, phys, len, writable, executable, true)
}

/// Map frames the address space does not own (page-cache pages, M5c2).
///
/// Same validation as [`map_user_in`], but nothing is added to the owned-frame
/// list: neither [`unmap_user`] nor [`destroy`] frees these frames. Page-table
/// budget is still charged for real, so a shared mapping can run out of tables
/// exactly like a private one.
fn map_borrowed_in(
    pool: &mut dyn FramePool,
    state: &mut SpaceState,
    virt: u64,
    phys: u64,
    len: u64,
    writable: bool,
    executable: bool,
) -> Result<(), VmError> {
    map_range_in(pool, state, virt, phys, len, writable, executable, false)
}

/// Shared core of [`map_user_in`] and [`map_borrowed_in`].
///
/// `owned` decides the only difference between the two: whether the frames join
/// `state.user` (and therefore whether the frame budget applies). All checks —
/// address range, alignment, direct-map reachability, W^X, owned-frame capacity
/// and overlap — happen before any leaf is touched.
fn map_range_in(
    pool: &mut dyn FramePool,
    state: &mut SpaceState,
    virt: u64,
    phys: u64,
    len: u64,
    writable: bool,
    executable: bool,
    owned: bool,
) -> Result<(), VmError> {
    let end = user_range_end(virt, len)?;
    if phys & (PAGE_SIZE - 1) != 0 {
        return Err(VmError::BadAddress);
    }
    let phys_end = phys.checked_add(len).ok_or(VmError::BadAddress)?;
    // copy_in/copy_out reach these frames through the direct map, so frames the
    // direct map does not cover are unusable. Host tests map frames by identity
    // and therefore accept any address.
    if !frame_reachable(phys_end) {
        return Err(VmError::BadAddress);
    }
    // W^X: a page is either writable or executable, never both (agents.md §7.2).
    if writable && executable {
        return Err(VmError::BadAddress);
    }
    let pages = (end - virt) / PAGE_SIZE;
    if owned && usize::from(state.n_user) + pages as usize > MAX_USER_FRAMES {
        return Err(VmError::OutOfTables);
    }
    let mut v = virt;
    while v < end {
        // `PROT_NONE` pages are still mappings: mapping over one would lose the
        // frame the address space owns (and the valid handle for `unmap_user`).
        if mapped_leaf_entry(state, v)?.is_some() {
            return Err(VmError::Overlap);
        }
        v += PAGE_SIZE;
    }

    let mut flags = PTE_PRESENT | PTE_USER;
    if writable {
        flags |= PTE_WRITE;
    }
    if !executable {
        flags |= PTE_NX;
    }
    let mut i = 0u64;
    while i < pages {
        let v = virt + i * PAGE_SIZE;
        let p = phys + i * PAGE_SIZE;
        install_leaf(pool, state, v, p, flags)?;
        if owned {
            state.user[usize::from(state.n_user)] = p;
            state.n_user += 1;
        }
        flush_user_page(v);
        i += 1;
    }
    Ok(())
}

/// Remove `len` bytes of user mappings starting at `virt`.
///
/// Owned frames are released and forgotten; borrowed frames (page cache) are
/// only unmapped, never freed. Every page is validated first, so a range that
/// touches an unmapped or kernel-only page fails with the address space
/// untouched — a caller never observes half a lifetime change (agents.md §10.1).
fn unmap_user_in(
    pool: &mut dyn FramePool,
    state: &mut SpaceState,
    virt: u64,
    len: u64,
) -> Result<(), VmError> {
    let end = user_range_end(virt, len)?;
    let pages = (end - virt) / PAGE_SIZE;

    // Validation pass: nothing is written until every page is a user leaf.
    let mut i = 0u64;
    while i < pages {
        let entry = mapped_leaf_entry(state, virt + i * PAGE_SIZE)?.ok_or(VmError::NotFound)?;
        if entry & PTE_USER == 0 {
            return Err(VmError::BadAddress);
        }
        i += 1;
    }

    // Retirement pass: the leaves were validated above and the tables do not
    // change in between, so each walk here yields the same present leaf.
    let mut i = 0u64;
    while i < pages {
        let v = virt + i * PAGE_SIZE;
        let entry = match mapped_leaf_entry(state, v) {
            Ok(Some(entry)) => entry,
            // Unreachable: validated in the pass above.
            _ => return Err(VmError::BadAddress),
        };
        let phys = entry & ADDR_MASK;
        if untrack_user_frame(state, phys) {
            pool.free(phys);
        }
        set_leaf(state, v, 0)?;
        flush_user_page(v);
        i += 1;
    }
    Ok(())
}

/// Rewrite the permissions of existing user leaves.
///
/// `PTE_USER` is always retained and W^X is enforced exactly like mapping does;
/// the physical frame is untouched, so this works the same for owned and
/// borrowed pages and never frees anything. A `PROT_NONE` leaf is accepted and
/// rewritten into a normal accessible leaf (the [`PTE_NOACCESS`] marker drops out
/// with the rebuilt flags). The whole range is validated before the first leaf
/// changes.
fn protect_user_in(
    state: &SpaceState,
    virt: u64,
    len: u64,
    writable: bool,
    executable: bool,
) -> Result<(), VmError> {
    let end = user_range_end(virt, len)?;
    if writable && executable {
        return Err(VmError::BadAddress);
    }
    let pages = (end - virt) / PAGE_SIZE;

    let mut i = 0u64;
    while i < pages {
        let entry = mapped_leaf_entry(state, virt + i * PAGE_SIZE)?.ok_or(VmError::NotFound)?;
        if entry & PTE_USER == 0 {
            return Err(VmError::BadAddress);
        }
        i += 1;
    }

    let mut flags = PTE_PRESENT | PTE_USER;
    if writable {
        flags |= PTE_WRITE;
    }
    if !executable {
        flags |= PTE_NX;
    }

    let mut i = 0u64;
    while i < pages {
        let v = virt + i * PAGE_SIZE;
        let entry = match mapped_leaf_entry(state, v) {
            Ok(Some(entry)) => entry,
            // Unreachable: validated above.
            _ => return Err(VmError::BadAddress),
        };
        if set_leaf(state, v, (entry & ADDR_MASK) | flags).is_err() {
            return Err(VmError::BadAddress);
        }
        flush_user_page(v);
        i += 1;
    }
    Ok(())
}

/// Mark existing user leaves as inaccessible (`PROT_NONE`) without freeing them.
///
/// The mapping and its frame stay owned by the address space; only the hardware
/// `PRESENT` bit is withdrawn and [`PTE_NOACCESS`] records why. Every later
/// access faults, while [`unmap_user`] and [`protect_user`] still find the page
/// and account for its frame exactly as before. The whole range is validated
/// before the first leaf changes, like [`protect_user_in`].
fn protect_noaccess_in(state: &SpaceState, virt: u64, len: u64) -> Result<(), VmError> {
    let end = user_range_end(virt, len)?;
    let pages = (end - virt) / PAGE_SIZE;

    let mut i = 0u64;
    while i < pages {
        let entry = mapped_leaf_entry(state, virt + i * PAGE_SIZE)?.ok_or(VmError::NotFound)?;
        if entry & PTE_USER == 0 {
            return Err(VmError::BadAddress);
        }
        i += 1;
    }

    let mut i = 0u64;
    while i < pages {
        let v = virt + i * PAGE_SIZE;
        let entry = match mapped_leaf_entry(state, v) {
            Ok(Some(entry)) => entry,
            // Unreachable: validated above.
            _ => return Err(VmError::BadAddress),
        };
        // Keep the frame address plus the user/NX bits; drop PRESENT and WRITE
        // (nothing about the page may look accessible to a walk) and record the
        // mapping with the software bit instead.
        let leaf = (entry & (ADDR_MASK | PTE_USER | PTE_NX)) | PTE_NOACCESS;
        if set_leaf(state, v, leaf).is_err() {
            return Err(VmError::BadAddress);
        }
        flush_user_page(v);
        i += 1;
    }
    Ok(())
}

/// Forget one owned frame; returns whether it was tracked.
fn untrack_user_frame(state: &mut SpaceState, phys: u64) -> bool {
    let n = usize::from(state.n_user);
    for i in 0..n {
        if state.user[i] == phys {
            let last = n - 1;
            state.user[i] = state.user[last];
            state.user[last] = 0;
            state.n_user -= 1;
            return true;
        }
    }
    false
}

/// Copy `len` bytes between a kernel buffer and user memory.
///
/// `to_user == true` writes into the address space; `false` reads out of it.
/// The kernel never dereferences `user` itself — the leaf's physical frame is
/// reached through [`phys_ptr`].
///
/// Every page is validated up front (present, user-accessible, and writable for
/// `to_user`), so a request that spans an unmapped or read-only page fails
/// *before* any byte is copied: the caller never observes a half-applied
/// translation of an invalid user range (agents.md §10.1 — validate first, then
/// transfer). A `PROT_NONE` page is mapped but never accessible, so it fails the
/// validation pass with [`VmError::BadAddress`] (the EFAULT-style refusal) while
/// a genuine hole fails with [`VmError::NotFound`].
fn copy_range(
    state: &SpaceState,
    user: u64,
    buf: *const u8,
    len: usize,
    to_user: bool,
) -> Result<(), VmError> {
    if len == 0 {
        return Ok(());
    }
    let end = user.checked_add(len as u64).ok_or(VmError::BadAddress)?;
    if user >= USER_MAX || end > USER_MAX {
        return Err(VmError::BadAddress);
    }

    // Validation pass: walk every page the range touches without copying.
    let mut probed = 0usize;
    while probed < len {
        let va = user + probed as u64;
        let page = va & !(PAGE_SIZE - 1);
        let offset = (va - page) as usize;
        let entry = match mapped_leaf_entry(state, page)? {
            // A `PROT_NONE` page keeps its frame but must not be dereferenced:
            // that is an inaccessible mapping, not a hole.
            Some(entry) if entry & PTE_PRESENT == 0 => return Err(VmError::BadAddress),
            Some(entry) => entry,
            None => return Err(VmError::NotFound),
        };
        if entry & PTE_USER == 0 {
            return Err(VmError::BadAddress);
        }
        if to_user && entry & PTE_WRITE == 0 {
            return Err(VmError::BadAddress);
        }
        probed += core::cmp::min(PAGE_SIZE as usize - offset, len - probed);
    }

    // Transfer pass: every page checked above, so this cannot fail.
    let mut done = 0usize;
    while done < len {
        let va = user + done as u64;
        let page = va & !(PAGE_SIZE - 1);
        let offset = (va - page) as usize;
        let chunk = core::cmp::min(PAGE_SIZE as usize - offset, len - done);
        let entry = leaf_entry(state, page)?.ok_or(VmError::NotFound)?;
        let phys = (entry & ADDR_MASK) + offset as u64;
        // SAFETY: the leaf names a frame mapped for this address space and
        // aliased by the direct map; the copy stays inside that one page.
        unsafe {
            let target = phys_ptr(phys);
            if to_user {
                ptr::copy_nonoverlapping(buf.add(done), target, chunk);
            } else {
                ptr::copy_nonoverlapping(target, buf.add(done) as *mut u8, chunk);
            }
        }
        done += chunk;
    }
    Ok(())
}

/// Release every frame tracked by `state` and clear it.
///
/// Frames are freed per category rather than by re-walking the tables, so a
/// partially constructed space (a failed `map_user` left extra tables behind)
/// is cleaned up completely. An empty state frees nothing. Borrowed mappings
/// never entered the owned list, so their frames stay with their owner.
fn destroy_in(pool: &mut dyn FramePool, state: &mut SpaceState) {
    for i in 0..usize::from(state.n_user) {
        pool.free(state.user[i]);
    }
    for i in 0..usize::from(state.n_table) {
        pool.free(state.tables[i]);
    }
    reset_state(state);
}

/// Invalidate one user page after installing a leaf.
#[cfg(not(test))]
fn flush_user_page(virt: u64) {
    // SAFETY: `invlpg` only affects TLB state for `virt`; it has no memory
    // effect and is valid in any CPL 0 context.
    unsafe {
        core::arch::asm!("invlpg [{0}]", in(reg) virt, options(nostack, preserves_flags));
    }
}

/// Host tests never run this code in a context where `invlpg` is legal.
#[cfg(test)]
fn flush_user_page(_virt: u64) {}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// The kernel's own PML4, whose high half every address space shares.
#[cfg(not(test))]
fn kernel_pml4() -> *const PageTable {
    // SAFETY: `addr_of!` yields a raw pointer to the field without creating a
    // reference to the whole static; `TABLES` lives for the kernel's lifetime.
    unsafe { ptr::addr_of!(vm::TABLES.pml4) }
}

/// Test kernels share a stand-in PML4 whose high half holds recognizable
/// entries (the low half is never mapped in a user address space).
#[cfg(test)]
fn kernel_pml4() -> *const PageTable {
    use std::alloc::{Layout, alloc_zeroed};

    static mut ROOT: *const PageTable = ptr::null();
    // SAFETY: only the serialized public-API test calls this; the allocation is
    // leaked for the rest of the test binary.
    unsafe {
        let slot = ptr::addr_of_mut!(ROOT);
        if (*slot).is_null() {
            let layout = Layout::from_size_align(PAGE_SIZE as usize, PAGE_SIZE as usize)
                .expect("page-table layout");
            let raw = alloc_zeroed(layout);
            assert!(!raw.is_null(), "test kernel PML4");
            let root = raw as *mut PageTable;
            for i in PML4_KERNEL_START..512 {
                (*root).entries[i] = 0x0000_0020_0000_0000 | i as u64 | PTE_PRESENT | PTE_WRITE;
            }
            *slot = root;
        }
        *slot
    }
}

fn spaces() -> &'static mut [SpaceState; MAX_SPACES] {
    // SAFETY: single-CPU M4 kernel; every public entry point takes this borrow
    // once and drops it before returning, and none of them run concurrently.
    unsafe { &mut *ptr::addr_of_mut!(SPACES) }
}

/// Create a new address space whose high half shares the kernel mappings.
///
/// Fails with [`VmError::OutOfTables`] when the M4 slot capacity is exhausted.
pub fn create() -> Result<AddressSpaceId, VmError> {
    let spaces = spaces();
    let index = spaces
        .iter()
        .position(SpaceState::is_empty)
        .ok_or(VmError::OutOfTables)?;
    // Initialise straight into the static slot: no `SpaceState` value ever
    // exists on the stack (see `reset_state`).
    init_space(global_pool(), kernel_pml4(), &mut spaces[index])?;
    Ok(AddressSpaceId::from_index(index))
}

/// Map caller-owned physical frames into the user half at `virt`.
///
/// Requirements: `virt` 4 KiB aligned, `len` a non-zero multiple of 4 KiB,
/// `[virt, virt + len)` inside the low canonical half, `phys` 4 KiB aligned and
/// the whole span under [`MAX_ALLOC_ADDR`] (the copy helpers reach it through
/// the direct map). Overlaps and W^X violations (`writable && executable`) are
/// rejected. Ownership of the mapped frames passes to the address space:
/// [`destroy`] frees them.
pub fn map_user(
    id: AddressSpaceId,
    virt: u64,
    phys: u64,
    len: u64,
    writable: bool,
    executable: bool,
) -> Result<(), VmError> {
    let spaces = spaces();
    let state = spaces.get_mut(id.index()).ok_or(VmError::NotFound)?;
    if state.is_empty() {
        return Err(VmError::NotFound);
    }
    map_user_in(global_pool(), state, virt, phys, len, writable, executable)
}

/// Map page-cache (or otherwise externally owned) frames into the user half.
///
/// Identical validation to [`map_user`] — alignment, user half, direct-map
/// reachability, W^X, overlap — with one crucial difference: the frames do
/// **not** become address-space property. [`unmap_user`] and [`destroy`] remove
/// the mappings without freeing them; the owner (the page cache) stays
/// responsible for the frames. This is what a shared file `mmap` needs (M5c2).
///
/// Borrowed mappings do not consume [`MAX_USER_FRAMES`], but they do allocate
/// real page tables, so [`VmError::OutOfTables`] can still come from the table
/// budget.
pub fn map_user_borrowed(
    id: AddressSpaceId,
    virt: u64,
    phys: u64,
    len: u64,
    writable: bool,
    executable: bool,
) -> Result<(), VmError> {
    let spaces = spaces();
    let state = spaces.get_mut(id.index()).ok_or(VmError::NotFound)?;
    if state.is_empty() {
        return Err(VmError::NotFound);
    }
    map_borrowed_in(global_pool(), state, virt, phys, len, writable, executable)
}

/// Remove `len` bytes of user mappings starting at `virt`.
///
/// Owned frames are freed and dropped from the tracked list exactly once;
/// borrowed mappings are only removed. A `PROT_NONE` page is retired like any
/// other mapping: the leaf and its [`PTE_NOACCESS`] marker are cleared and an
/// owned frame returns to the PMM. The range must be fully mapped (every page a
/// user leaf) — otherwise `NotFound`/`BadAddress` is returned and nothing is
/// unmapped. Page tables are left in place (M5c2 does not shrink the walk).
pub fn unmap_user(id: AddressSpaceId, virt: u64, len: u64) -> Result<(), VmError> {
    let spaces = spaces();
    let state = spaces.get_mut(id.index()).ok_or(VmError::NotFound)?;
    if state.is_empty() {
        return Err(VmError::NotFound);
    }
    unmap_user_in(global_pool(), state, virt, len)
}

/// Rewrite permissions of existing user mappings.
///
/// `PTE_USER` is preserved, `writable && executable` is refused, and the frames
/// are untouched, so owned and borrowed mappings are both supported. The whole
/// range is validated before any leaf changes, and a `PROT_NONE` page (see
/// [`protect_user_noaccess`]) is restored to a normal accessible leaf with its
/// `PTE_NOACCESS` marker cleared.
///
/// Note that `(writable = false, executable = false)` means **read-only**, not
/// Linux `PROT_NONE`: the leaf stays present. No-access mappings must go through
/// [`protect_user_noaccess`].
pub fn protect_user(
    id: AddressSpaceId,
    virt: u64,
    len: u64,
    writable: bool,
    executable: bool,
) -> Result<(), VmError> {
    let spaces = spaces();
    let state = spaces.get_mut(id.index()).ok_or(VmError::NotFound)?;
    if state.is_empty() {
        return Err(VmError::NotFound);
    }
    protect_user_in(state, virt, len, writable, executable)
}

/// Turn existing user mappings into true no-access (`PROT_NONE`) pages.
///
/// Every page in `[virt, virt + len)` must be a live user mapping (owned or
/// borrowed). The leaves lose `PRESENT` and `WRITE` and gain [`PTE_NOACCESS`],
/// but keep their frame address, `PTE_USER` and `NX`: the hardware faults on any
/// access, while [`unmap_user`] and [`protect_user`] still see a mapping and
/// account for its frame exactly as before. Nothing is freed and nothing is
/// allocated, so boot-stack use is one page walk per page.
///
/// This is the primitive Linux `mprotect(PROT_NONE)` needs; it is deliberately
/// distinct from `protect_user(.., false, false)`, which is read-only but still
/// present. The whole range is validated first: a refused request leaves every
/// leaf untouched.
pub fn protect_user_noaccess(id: AddressSpaceId, virt: u64, len: u64) -> Result<(), VmError> {
    let spaces = spaces();
    let state = spaces.get_mut(id.index()).ok_or(VmError::NotFound)?;
    if state.is_empty() {
        return Err(VmError::NotFound);
    }
    protect_noaccess_in(state, virt, len)
}

/// Switch the CPU to `id`'s page tables.
///
/// The caller must be running on a kernel stack and must not be between a user
/// trap and its `iretq`: the kernel half is shared, but the user half — including
/// the current user frame's stack — is not.
///
/// The signature is frozen at `(id) -> ()` for M4 (a `LoadedImage` carries its
/// [`AddressSpaceId`]): an id that names no live space is a caller bug, so
/// nothing is switched and the current tables stay in place. Use
/// [`is_active`] to query the result instead of matching an error.
pub fn activate(id: AddressSpaceId) {
    let _ = activate_checked(id);
}

/// Query whether `id` is the address space loaded in CR3 **on this CPU**.
///
/// The bookkeeping is per CPU (M6b2a): another CPU running the same space is
/// invisible here, and a space only this CPU has switched away from is already
/// "not active". [`AddressSpaceId::INVALID`] is never active.
pub fn is_active(id: AddressSpaceId) -> bool {
    is_active_on(current_cpu(), id)
}

/// Fallible core of [`activate`]; also the entry point host tests use.
fn activate_checked(id: AddressSpaceId) -> Result<(), VmError> {
    let spaces = spaces();
    // Borrow the slot instead of copying it: a `SpaceState` value is a little
    // over 2 KiB, and moving it through the stack overflowed the boot stack on
    // the spawn path (objdump: 2280 B frame in `activate_checked`).
    let state = spaces.get(id.index()).ok_or(VmError::NotFound)?;
    if state.is_empty() {
        return Err(VmError::NotFound);
    }
    let pml4 = state.pml4;
    #[cfg(test)]
    let _ = pml4;
    #[cfg(not(test))]
    // SAFETY: `pml4` is a table frame this module allocated, wired to the kernel
    // half; the caller guarantees it is on a kernel stack.
    unsafe {
        core::arch::asm!("mov cr3, {}", in(reg) pml4, options(nostack, preserves_flags));
    }
    // SAFETY: this CPU's slot is bookkeeping only this CPU writes.
    set_active_on(current_cpu(), id.raw());
    Ok(())
}

/// Copy `out.len()` bytes of `id`'s user memory into a kernel buffer.
///
/// Fails with [`VmError::NotFound`] on an unmapped page and
/// [`VmError::BadAddress`] when the range leaves the user half, overflows, or
/// hits a page that is not user-accessible or is mapped `PROT_NONE`.
pub fn copy_in(id: AddressSpaceId, user: u64, out: &mut [u8]) -> Result<(), VmError> {
    let spaces = spaces();
    let state = spaces.get(id.index()).ok_or(VmError::NotFound)?;
    if state.is_empty() {
        return Err(VmError::NotFound);
    }
    copy_range(state, user, out.as_mut_ptr(), out.len(), false)
}

/// Copy a kernel buffer into `id`'s user memory.
///
/// Fails with [`VmError::NotFound`] on an unmapped page and
/// [`VmError::BadAddress`] for a range outside the user half, an overflow, a
/// page that is not user-accessible or is mapped `PROT_NONE`, or a page without
/// [`PTE_WRITE`].
pub fn copy_out(id: AddressSpaceId, user: u64, input: &[u8]) -> Result<(), VmError> {
    let spaces = spaces();
    let state = spaces.get(id.index()).ok_or(VmError::NotFound)?;
    if state.is_empty() {
        return Err(VmError::NotFound);
    }
    copy_range(state, user, input.as_ptr(), input.len(), true)
}

/// Free every frame of `id` and release its slot.
///
/// Only frames the address space owns are freed (those installed by
/// [`map_user`] and not yet [`unmap_user`]ed); borrowed page-cache mappings are
/// dropped without touching their frames. The space the *calling CPU* is running
/// on cannot be destroyed (there would be no tables to run on afterwards):
/// activate another space on this CPU first. A space another CPU is still on is
/// not detected here — sched/SMP bring-up owns that protocol. Destroying a slot
/// that is not in use returns [`VmError::NotFound`]. A partially constructed
/// space is cleaned up like a complete one.
pub fn destroy(id: AddressSpaceId) -> Result<(), VmError> {
    // Validate the slot before the active check: `AddressSpaceId::INVALID` has
    // index `u8::MAX`, which is also the "nothing active" sentinel, so checking
    // liveness first would report `NotReady` for a non-handle.
    let spaces = spaces();
    let state = spaces.get_mut(id.index()).ok_or(VmError::NotFound)?;
    if state.is_empty() {
        return Err(VmError::NotFound);
    }
    if is_active(id) {
        return Err(VmError::NotReady);
    }
    destroy_in(global_pool(), state);
    Ok(())
}

/// Translate one mapped user address to the physical address it names.
///
/// Only the user half is accepted (`va < `[`USER_MAX`]) and only pages that are
/// currently present with [`PTE_USER`] in `id`'s tables translate; a hole, a
/// `PROT_NONE` page, a kernel-only leaf, a huge-page entry, a high-half address,
/// an id that names no live space and any out-of-range input all yield `None`.
/// The result is the
/// physical frame base plus `va`'s page offset, i.e. the address a device would
/// use for that byte.
///
/// This is a lookup, not a pin: M6a2 feeds it to futex word keys and to syscall
/// buffer preflight, where the value is consumed immediately and the mapping may
/// change afterwards. Nothing here reserves the frame, extends its lifetime, or
/// promises that the mapping still exists on the next instruction — the copy
/// helpers ([`copy_in`]/[`copy_out`]) remain the path that actually moves bytes.
pub fn translate_user(id: AddressSpaceId, va: u64) -> Option<u64> {
    if va >= USER_MAX {
        return None;
    }
    let spaces = spaces();
    let state = spaces.get(id.index())?;
    if state.is_empty() {
        return None;
    }
    let entry = leaf_entry(state, va).ok()??;
    if entry & PTE_PRESENT == 0 || entry & PTE_USER == 0 {
        return None;
    }
    Some((entry & ADDR_MASK) | (va & (PAGE_SIZE - 1)))
}

/// Whether `va` names a user page that is still mapped, including `PROT_NONE`.
///
/// [`translate_user`] deliberately reports `None` for a `PROT_NONE` page — the
/// kernel must never treat it as readable/writable. Mapping bookkeeping needs
/// the other question: a page that only lost access is still a mapping, and
/// restoring permissions on it must not look like mapping a fresh page
/// (`mprotect` only rewrites existing mappings, never allocates). That is what
/// this query answers.
pub fn is_user_mapped(id: AddressSpaceId, va: u64) -> bool {
    if va >= USER_MAX {
        return false;
    }
    let spaces = spaces();
    let Some(state) = spaces.get(id.index()) else {
        return false;
    };
    if state.is_empty() {
        return false;
    }
    matches!(mapped_leaf_entry(state, va), Ok(Some(entry)) if entry & PTE_USER != 0)
}

/// Check that `[va, va + len)` is memory `id` maps into the user half.
///
/// Every page the range touches must have a present leaf carrying [`PTE_USER`]
/// (`PROT_NONE` pages are mapped but inaccessible, so they are rejected); with
/// `write` the leaf must also carry [`PTE_WRITE`]. The walk is page by page,
/// so a hole or a read-only page anywhere in the middle — not just at the start
/// or end — is rejected. `va` need not be page aligned.
///
/// Empty ranges (`len == 0`) are accepted once `id` names a live space: whether a
/// zero-length buffer is legal at all is policy the syscall layer owns. Bounds
/// are otherwise strict: overflow and anything that leaves `[0, `[`USER_MAX`]`)`
/// are [`VmError::BadAddress`], as is every unmapped/hole/non-user/missing-write
/// case; an id with no live space is [`VmError::NotFound`].
///
/// Like [`translate_user`] this is preflight only: it neither pins the pages nor
/// replaces the bounds checking inside [`copy_in`]/[`copy_out`], which still
/// perform the real copy and re-validate what they touch.
pub fn validate_user_range(
    id: AddressSpaceId,
    va: u64,
    len: u64,
    write: bool,
) -> Result<(), VmError> {
    let spaces = spaces();
    let state = spaces.get(id.index()).ok_or(VmError::NotFound)?;
    if state.is_empty() {
        return Err(VmError::NotFound);
    }
    if len == 0 {
        return Ok(());
    }
    let end = va.checked_add(len).ok_or(VmError::BadAddress)?;
    if va >= USER_MAX || end > USER_MAX {
        return Err(VmError::BadAddress);
    }
    let mut page = va & !(PAGE_SIZE - 1);
    while page < end {
        match leaf_entry(state, page) {
            Ok(Some(entry))
                if entry & PTE_PRESENT != 0
                    && entry & PTE_USER != 0
                    && (!write || entry & PTE_WRITE != 0) => {}
            _ => return Err(VmError::BadAddress),
        }
        // `page < end <= USER_MAX` and both are page aligned/bounded, so this
        // cannot overflow.
        page += PAGE_SIZE;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Host tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// Kernel PML4 stand-in with distinguishable high-half entries.
    fn leaked_kernel_pml4(marker: u64) -> *const PageTable {
        let root = arena(1) as *mut PageTable;
        // SAFETY: exclusive page-aligned allocation.
        unsafe {
            for i in PML4_KERNEL_START..512 {
                (*root).entries[i] = marker | i as u64 | PTE_PRESENT | PTE_WRITE;
            }
        }
        root
    }

    fn new_space(pool: &mut TestPool) -> SpaceState {
        let mut state = SpaceState::EMPTY;
        init_space(pool, leaked_kernel_pml4(0x1122_3344_5000), &mut state).expect("address space");
        state
    }

    fn leaf(state: &SpaceState, virt: u64) -> Option<u64> {
        leaf_entry(state, virt).expect("leaf walk")
    }

    /// The address space's view: `PROT_NONE` still counts as a mapping.
    fn mapped_leaf(state: &SpaceState, virt: u64) -> Option<u64> {
        mapped_leaf_entry(state, virt).expect("mapped leaf walk")
    }

    fn read_frame_byte(phys: u64, offset: usize) -> u8 {
        // SAFETY: test frames are live heap buffers of at least one page.
        unsafe { *phys_ptr(phys).add(offset) }
    }

    fn path_flags(entry: u64) -> (bool, bool, bool) {
        (
            entry & PTE_USER != 0,
            entry & PTE_WRITE != 0,
            entry & PTE_NX != 0,
        )
    }

    #[test]
    fn create_copies_kernel_half_and_zeroes_user_half() {
        let mut pool = TestPool::new(16);
        let kernel = leaked_kernel_pml4(0x1122_3344_5000);
        let mut state = SpaceState::EMPTY;
        init_space(&mut pool, kernel, &mut state).expect("space");

        assert_eq!(state.pml4, state.tables[0]);
        assert_eq!(state.n_table, 1);
        assert_eq!(state.n_user, 0);

        // SAFETY: both pointers name live page tables.
        unsafe {
            let root = table_at(state.pml4);
            for i in 0..PML4_KERNEL_START {
                assert_eq!((*root).entries[i], 0, "user half entry {i}");
            }
            for i in PML4_KERNEL_START..512 {
                assert_eq!((*root).entries[i], (*kernel).entries[i], "kernel half {i}");
                assert_ne!((*root).entries[i], 0);
            }
        }
    }

    #[test]
    fn map_user_rejects_bad_requests() {
        let mut pool = TestPool::new(16);
        let mut state = new_space(&mut pool);
        let frame = pool.alloc().expect("frame");

        // High half (both canonical high addresses and the USER_MAX boundary).
        for virt in [USER_MAX, 0xFFFF_8000_0000_0000, 0xFFFF_FFFF_FFFF_0000] {
            assert_eq!(
                map_user_in(&mut pool, &mut state, virt, frame, PAGE_SIZE, false, false),
                Err(VmError::BadAddress)
            );
        }
        // A range that crosses USER_MAX.
        assert_eq!(
            map_user_in(
                &mut pool,
                &mut state,
                USER_MAX - PAGE_SIZE,
                frame,
                2 * PAGE_SIZE,
                false,
                false
            ),
            Err(VmError::BadAddress)
        );
        // Alignment, zero length, partial page, overflowing length.
        assert_eq!(
            map_user_in(
                &mut pool, &mut state, 0x1008, frame, PAGE_SIZE, false, false
            ),
            Err(VmError::BadAddress)
        );
        assert_eq!(
            map_user_in(&mut pool, &mut state, 0x1000, frame, 0, false, false),
            Err(VmError::BadAddress)
        );
        assert_eq!(
            map_user_in(
                &mut pool,
                &mut state,
                0x1000,
                frame,
                PAGE_SIZE - 1,
                false,
                false
            ),
            Err(VmError::BadAddress)
        );
        assert_eq!(
            map_user_in(
                &mut pool,
                &mut state,
                0x1000,
                frame + 8,
                PAGE_SIZE,
                false,
                false
            ),
            Err(VmError::BadAddress)
        );
        assert_eq!(
            map_user_in(&mut pool, &mut state, 0x1000, frame, u64::MAX, false, false),
            Err(VmError::BadAddress)
        );
        // A frame the direct map cannot reach is rejected in the kernel build;
        // host frames are addressed by identity, so that check is a no-op there.
        #[cfg(not(test))]
        assert_eq!(
            map_user_in(
                &mut pool,
                &mut state,
                0x1000,
                MAX_ALLOC_ADDR,
                PAGE_SIZE,
                false,
                false
            ),
            Err(VmError::BadAddress)
        );
        assert_eq!(leaf(&state, 0x1000), None);
        assert_eq!(state.n_user, 0);
    }

    #[test]
    fn map_user_sets_user_bit_and_enforces_wx() {
        let mut pool = TestPool::new(16);
        let mut state = new_space(&mut pool);
        let frames: [u64; 3] = [
            pool.alloc().expect("frame 0"),
            pool.alloc().expect("frame 1"),
            pool.alloc().expect("frame 2"),
        ];

        map_user_in(
            &mut pool, &mut state, 0x1000, frames[0], PAGE_SIZE, false, false,
        )
        .expect("ro nx");
        map_user_in(
            &mut pool, &mut state, 0x2000, frames[1], PAGE_SIZE, false, true,
        )
        .expect("ro exec");
        map_user_in(
            &mut pool, &mut state, 0x3000, frames[2], PAGE_SIZE, true, false,
        )
        .expect("rw nx");

        let ro_nx = leaf(&state, 0x1000).expect("ro nx leaf");
        assert_eq!(ro_nx & ADDR_MASK, frames[0]);
        assert_eq!(path_flags(ro_nx), (true, false, true));

        let ro_x = leaf(&state, 0x2000).expect("ro exec leaf");
        assert_eq!(ro_x & ADDR_MASK, frames[1]);
        assert_eq!(path_flags(ro_x), (true, false, false));

        let rw_nx = leaf(&state, 0x3000).expect("rw nx leaf");
        assert_eq!(rw_nx & ADDR_MASK, frames[2]);
        assert_eq!(path_flags(rw_nx), (true, true, true));

        // W^X: writable and executable at once is refused, nothing installed.
        let spare = pool.alloc().expect("spare frame");
        assert_eq!(
            map_user_in(&mut pool, &mut state, 0x4000, spare, PAGE_SIZE, true, true),
            Err(VmError::BadAddress)
        );
        assert_eq!(leaf(&state, 0x4000), None);
        assert_eq!(state.n_user, 3);
    }

    #[test]
    fn map_user_rejects_overlap_atomically() {
        let mut pool = TestPool::new(16);
        let mut state = new_space(&mut pool);
        let frames: [u64; 3] = [
            pool.alloc().expect("frame 0"),
            pool.alloc().expect("frame 1"),
            pool.alloc().expect("frame 2"),
        ];

        map_user_in(
            &mut pool, &mut state, 0x1000, frames[0], PAGE_SIZE, false, false,
        )
        .expect("first map");
        // Same page twice.
        assert_eq!(
            map_user_in(
                &mut pool, &mut state, 0x1000, frames[1], PAGE_SIZE, false, false
            ),
            Err(VmError::Overlap)
        );
        assert_eq!(leaf(&state, 0x1000).expect("leaf") & ADDR_MASK, frames[0]);

        // A multi-page request that collides on its second page must not install
        // the first one either.
        map_user_in(
            &mut pool, &mut state, 0x3000, frames[2], PAGE_SIZE, false, false,
        )
        .expect("second map");
        assert_eq!(
            map_user_in(
                &mut pool,
                &mut state,
                0x2000,
                frames[1],
                2 * PAGE_SIZE,
                false,
                false
            ),
            Err(VmError::Overlap)
        );
        assert_eq!(leaf(&state, 0x2000), None);
        assert_eq!(state.n_user, 2);
    }

    #[test]
    fn map_user_maps_multi_page_and_enforces_frame_budget() {
        let mut pool = TestPool::new(MAX_USER_FRAMES + 64);
        let mut state = new_space(&mut pool);

        let base = 0x10_0000;
        let frames: [u64; 4] = [
            pool.alloc().expect("0"),
            pool.alloc().expect("1"),
            pool.alloc().expect("2"),
            pool.alloc().expect("3"),
        ];
        // Non-contiguous frames in ascending physical order: each leaf must
        // carry its own frame.
        let mut sorted = frames;
        sorted.sort_unstable();
        for (i, frame) in sorted.iter().enumerate() {
            let virt = base + (i as u64) * PAGE_SIZE;
            map_user_in(&mut pool, &mut state, virt, *frame, PAGE_SIZE, true, false).expect("page");
            assert_eq!(leaf(&state, virt).expect("leaf") & ADDR_MASK, *frame);
        }
        assert_eq!(state.n_user, 4);

        // Fill up to MAX_USER_FRAMES, then one more page must be refused.
        let mut mapped = 4usize;
        let mut virt = 0x20_0000;
        while mapped < MAX_USER_FRAMES {
            let frame = pool.alloc().expect("budget frame");
            map_user_in(&mut pool, &mut state, virt, frame, PAGE_SIZE, false, false)
                .expect("budget page");
            mapped += 1;
            virt += PAGE_SIZE;
        }
        assert_eq!(usize::from(state.n_user), MAX_USER_FRAMES);
        let spill = pool.alloc().expect("spill frame");
        assert_eq!(
            map_user_in(&mut pool, &mut state, virt, spill, PAGE_SIZE, false, false),
            Err(VmError::OutOfTables)
        );
        assert_eq!(leaf(&state, virt), None);
    }

    #[test]
    fn map_user_enforces_table_budget() {
        let mut pool = TestPool::new(64);
        let mut state = new_space(&mut pool);
        let mut windows = 0usize;
        loop {
            let virt = (windows as u64) * vm::LARGE_PAGE_SIZE;
            if virt >= USER_MAX {
                break;
            }
            let frame = pool.alloc().expect("window frame");
            match map_user_in(&mut pool, &mut state, virt, frame, PAGE_SIZE, false, false) {
                Ok(()) => windows += 1,
                Err(err) => {
                    assert_eq!(err, VmError::OutOfTables);
                    break;
                }
            }
        }
        // Root + PDPT + PD plus one PT per distinct 2 MiB window: the budget
        // stops the 14th window, i.e. after 13 mapped windows.
        assert_eq!(state.n_table, MAX_TABLE_FRAMES as u8);
        assert_eq!(windows, 13);
        // A partially built space is still fully tracked.
        destroy_in(&mut pool, &mut state);
        assert!(state.is_empty());
        assert_eq!(pool.freed(), MAX_TABLE_FRAMES + windows);
    }

    #[test]
    fn copy_round_trip_across_page_boundary() {
        let mut pool = TestPool::new(32);
        let mut state = new_space(&mut pool);
        let frames: [u64; 2] = [pool.alloc().expect("a"), pool.alloc().expect("b")];
        let mut sorted = frames;
        sorted.sort_unstable();

        // Fill page A with 0xA1 and page B with 0xB2.
        // SAFETY: both are live test frames.
        unsafe {
            ptr::write_bytes(phys_ptr(sorted[0]), 0xA1, PAGE_SIZE as usize);
            ptr::write_bytes(phys_ptr(sorted[1]), 0xB2, PAGE_SIZE as usize);
        }
        map_user_in(
            &mut pool, &mut state, 0x2000, sorted[0], PAGE_SIZE, true, false,
        )
        .expect("page a");
        map_user_in(
            &mut pool, &mut state, 0x3000, sorted[1], PAGE_SIZE, true, false,
        )
        .expect("page b");

        // 8 bytes before the boundary + 8 bytes after it.
        let mut buf = [0u8; 16];
        copy_range(&state, 0x2FF8, buf.as_mut_ptr(), buf.len(), false).expect("copy_in");
        assert_eq!(&buf[..8], &[0xA1; 8]);
        assert_eq!(&buf[8..], &[0xB2; 8]);

        // Write back across the boundary and verify on the physical frames.
        let pattern: [u8; 16] = core::array::from_fn(|i| 0xC0 + i as u8);
        copy_range(&state, 0x2FF8, pattern.as_ptr(), pattern.len(), true).expect("copy_out");
        for (i, byte) in pattern.iter().enumerate() {
            if i < 8 {
                assert_eq!(read_frame_byte(sorted[0], 0xFF8 + i), *byte);
            } else {
                assert_eq!(read_frame_byte(sorted[1], i - 8), *byte);
            }
        }

        // A three-page write spanning two boundaries.
        let mut wide = [0u8; 3 * PAGE_SIZE as usize];
        for (i, byte) in wide.iter_mut().enumerate() {
            *byte = (i % 251) as u8;
        }
        // Only two pages are mapped here, so a three-page range must fail with
        // NotFound and leave the mapped bytes alone.
        assert_eq!(
            copy_range(&state, 0x2FF8, wide.as_ptr(), wide.len(), true),
            Err(VmError::NotFound)
        );
        assert_eq!(read_frame_byte(sorted[0], 0xFF8), 0xC0);
    }

    #[test]
    fn copy_rejects_unmapped_permissions_and_bounds() {
        let mut pool = TestPool::new(32);
        let mut state = new_space(&mut pool);
        let ro = pool.alloc().expect("ro frame");
        let rw = pool.alloc().expect("rw frame");
        map_user_in(&mut pool, &mut state, 0x1000, ro, PAGE_SIZE, false, false).expect("ro page");
        map_user_in(&mut pool, &mut state, 0x2000, rw, PAGE_SIZE, true, false).expect("rw page");

        let mut buf = [0u8; 8];
        // Unmapped page.
        assert_eq!(
            copy_range(&state, 0x4000, buf.as_mut_ptr(), 8, false),
            Err(VmError::NotFound)
        );
        // Outside the user half / overflowing.
        assert_eq!(
            copy_range(&state, USER_MAX, buf.as_mut_ptr(), 8, false),
            Err(VmError::BadAddress)
        );
        assert_eq!(
            copy_range(&state, 0x1000, buf.as_mut_ptr(), 8, false),
            Ok(())
        );
        assert_eq!(
            copy_range(&state, USER_MAX - 4, buf.as_mut_ptr(), 8, false),
            Err(VmError::BadAddress)
        );
        // Reading a read-only page is fine, writing it is not.
        assert_eq!(
            copy_range(&state, 0x1000, buf.as_mut_ptr(), 8, false),
            Ok(())
        );
        assert_eq!(
            copy_range(&state, 0x1000, buf.as_ptr(), 8, true),
            Err(VmError::BadAddress)
        );
        // Zero length succeeds without touching anything.
        assert_eq!(
            copy_range(&state, 0x5000, buf.as_mut_ptr(), 0, false),
            Ok(())
        );

        // A present leaf without PTE_USER must be refused in both directions.
        install_leaf(&mut pool, &mut state, 0x6000, ro, PTE_PRESENT).expect("kernel-only leaf");
        assert_eq!(
            copy_range(&state, 0x6000, buf.as_mut_ptr(), 8, false),
            Err(VmError::BadAddress)
        );
        assert_eq!(
            copy_range(&state, 0x6000, buf.as_ptr(), 8, true),
            Err(VmError::BadAddress)
        );
    }

    #[test]
    fn destroy_frees_frames_and_clears_state() {
        let mut pool = TestPool::new(32);
        let mut state = new_space(&mut pool);
        let frames: [u64; 2] = [pool.alloc().expect("a"), pool.alloc().expect("b")];
        map_user_in(
            &mut pool, &mut state, 0x1000, frames[0], PAGE_SIZE, true, false,
        )
        .expect("page a");
        map_user_in(
            &mut pool, &mut state, 0x2000, frames[1], PAGE_SIZE, true, false,
        )
        .expect("page b");
        let tables = usize::from(state.n_table);
        let users = usize::from(state.n_user);
        assert_eq!(users, 2);

        destroy_in(&mut pool, &mut state);
        assert!(state.is_empty());
        assert_eq!(pool.freed(), tables + users);

        // A second destroy of the cleared state frees nothing more.
        destroy_in(&mut pool, &mut state);
        assert_eq!(pool.freed(), tables + users);

        // The freed frames are reusable: a fresh space builds normally.
        let mut fresh = SpaceState::EMPTY;
        init_space(&mut pool, leaked_kernel_pml4(0x1122_3344_5000), &mut fresh)
            .expect("fresh space after destroy");
        assert_eq!(fresh.n_table, 1);
        assert_eq!(fresh.n_user, 0);
    }

    #[test]
    fn destroy_handles_partial_construction() {
        let mut pool = TestPool::new(32);
        let mut state = new_space(&mut pool);
        let mut mapped = 0usize;
        let mut windows = 0u64;
        loop {
            let virt = windows * vm::LARGE_PAGE_SIZE;
            let Ok(frame) = pool.alloc() else { break };
            match map_user_in(&mut pool, &mut state, virt, frame, PAGE_SIZE, false, false) {
                Ok(()) => {
                    mapped += 1;
                    windows += 1;
                }
                Err(err) => {
                    assert_eq!(err, VmError::OutOfTables);
                    break;
                }
            }
        }
        assert_eq!(state.n_table, MAX_TABLE_FRAMES as u8);
        assert_eq!(usize::from(state.n_user), mapped);
        let tables = usize::from(state.n_table);
        let users = usize::from(state.n_user);

        destroy_in(&mut pool, &mut state);
        assert!(state.is_empty());
        // Every tracked frame came back; the one frame allocated for the request
        // that failed to install a leaf was never mapped, so it is not tracked.
        assert_eq!(pool.freed(), tables + users);
    }

    #[test]
    fn failed_init_leaves_the_slot_untouched_and_leaks_nothing() {
        // A pool with no frames makes the only fallible step (the root
        // allocation) fail before any mutation happens.
        let mut pool = TestPool::new(0);

        // Sentinel contents prove `init_space` does not partially write on error.
        let mut state = SpaceState::EMPTY;
        state.pml4 = 0;
        state.n_user = 7;
        state.n_table = 3;
        state.user[0] = 0xAAAA_0000;
        state.tables[0] = 0xBBBB_0000;

        let err = init_space(&mut pool, leaked_kernel_pml4(0x1122_3344_5000), &mut state)
            .expect_err("no frames available");
        assert_eq!(err, VmError::OutOfTables);
        assert_eq!(state.n_user, 7);
        assert_eq!(state.n_table, 3);
        assert_eq!(state.user[0], 0xAAAA_0000);
        assert_eq!(state.tables[0], 0xBBBB_0000);
        assert_eq!(pool.freed(), 0);
    }

    // -----------------------------------------------------------------------
    // Public API (global state; serialized because the slots are process-wide)
    // -----------------------------------------------------------------------
    static API_LOCK: Mutex<()> = Mutex::new(());

    fn reset_globals() {
        // SAFETY: the public-API test holds API_LOCK, so no other test touches
        // the slots at the same time.
        unsafe {
            *ptr::addr_of_mut!(SPACES) = [SpaceState::EMPTY; MAX_SPACES];
            *ptr::addr_of_mut!(TEST_POOL) = TestPool::EMPTY;
        }
        for cpu in 0..arch::MAX_CPUS {
            set_active_on(cpu, NONE);
        }
    }

    fn test_alloc_frame() -> u64 {
        global_pool().alloc().expect("test frame")
    }

    #[test]
    fn create_initialises_the_static_slot_in_place() {
        let _guard = API_LOCK.lock().unwrap_or_else(|err| err.into_inner());
        reset_globals();

        // A free slot only promises `pml4 == 0`; it may still hold stale
        // bookkeeping. `create` must re-initialise in place, not trust it and
        // not build a `SpaceState` value on the stack (boot-stack overflow).
        {
            let spaces = spaces();
            spaces[0].pml4 = 0;
            spaces[0].n_user = 5;
            spaces[0].n_table = 2;
            spaces[0].user[3] = 0xDEAD_BEEF;
            spaces[0].tables[1] = 0xCAFE_F00D;
        }

        let id = create().expect("create into the reusable slot");
        assert_eq!(id.index(), 0);
        {
            let spaces = spaces();
            let state = &spaces[0];
            assert_ne!(state.pml4, 0);
            assert_eq!(state.n_table, 1);
            assert_eq!(state.n_user, 0);
            assert_eq!(state.tables[0], state.pml4);
            assert!(
                state.tables[1..].iter().all(|&p| p == 0),
                "stale table slot"
            );
            assert!(state.user.iter().all(|&p| p == 0), "stale owned frame");
        }

        destroy(id).expect("destroy");
        {
            let spaces = spaces();
            let state = &spaces[0];
            assert!(state.is_empty());
            assert_eq!(state.n_user, 0);
            assert_eq!(state.n_table, 0);
            assert!(state.user.iter().all(|&p| p == 0), "user list not cleared");
            assert!(
                state.tables.iter().all(|&p| p == 0),
                "table list not cleared"
            );
        }
    }

    #[test]
    fn invalid_id_is_not_a_live_handle() {
        let _guard = API_LOCK.lock().unwrap_or_else(|err| err.into_inner());
        reset_globals();

        let invalid = AddressSpaceId::INVALID;
        assert_eq!(invalid.raw(), u8::MAX);
        assert!(!is_active(invalid));
        // No operation accepts it: it names no slot and no live space.
        assert_eq!(activate_checked(invalid), Err(VmError::NotFound));
        activate(invalid);
        assert!(!is_active(invalid));
        assert_eq!(
            map_user(invalid, 0x1000, 0, PAGE_SIZE, false, false),
            Err(VmError::NotFound)
        );
        let mut buf = [0u8; 4];
        assert_eq!(copy_in(invalid, 0x1000, &mut buf), Err(VmError::NotFound));
        assert_eq!(copy_out(invalid, 0x1000, b"abcd"), Err(VmError::NotFound));
        assert_eq!(destroy(invalid), Err(VmError::NotFound));

        // A real space is unaffected by the placeholder.
        let live = create().expect("space");
        activate(live);
        assert!(is_active(live));
        destroy(live).expect_err("active space");
    }

    #[test]
    fn public_api_lifecycle() {
        let _guard = API_LOCK.lock().unwrap_or_else(|err| err.into_inner());
        reset_globals();

        let first = create().expect("first space");
        let second = create().expect("second space");
        assert_eq!(first.index(), 0);
        assert_eq!(second.index(), 1);
        let third = create().expect("third space");
        assert_eq!(third.index(), 2);
        // M9c raised the capacity to four so the native bootstrap, the lock-peer
        // parent and both lock peers fit at once.
        let fourth = create().expect("fourth space");
        assert_eq!(fourth.index(), 3);
        assert_eq!(create(), Err(VmError::OutOfTables));

        // A slot that was never created.
        assert_eq!(
            map_user(AddressSpaceId(9), 0x1000, 0, PAGE_SIZE, false, false),
            Err(VmError::NotFound)
        );
        assert_eq!(activate_checked(AddressSpaceId(9)), Err(VmError::NotFound));

        let frame = test_alloc_frame();
        // SAFETY: the frame came from the test pool and is aliased by phys_ptr.
        unsafe { ptr::write_bytes(phys_ptr(frame), 0x5A, PAGE_SIZE as usize) };
        map_user(first, 0x1000, frame, PAGE_SIZE, true, false).expect("map page");

        let mut buf = [0u8; 8];
        copy_in(first, 0x1000, &mut buf).expect("copy_in");
        assert_eq!(buf, [0x5A; 8]);
        copy_out(first, 0x1008, b"ABCDEFGH").expect("copy_out");
        let mut back = [0u8; 8];
        copy_in(first, 0x1008, &mut back).expect("copy_in back");
        assert_eq!(&back, b"ABCDEFGH");

        // W^X and overlap through the public entry point.
        let spare = test_alloc_frame();
        assert_eq!(
            map_user(first, 0x2000, spare, PAGE_SIZE, true, true),
            Err(VmError::BadAddress)
        );
        assert_eq!(
            map_user(first, 0x1000, spare, PAGE_SIZE, false, false),
            Err(VmError::Overlap)
        );

        // The active space cannot be destroyed; switching away releases it.
        activate(first);
        assert!(is_active(first));
        assert_eq!(destroy(first), Err(VmError::NotReady));
        activate(second);
        assert!(is_active(second));
        destroy(first).expect("destroy first");
        assert_eq!(destroy(first), Err(VmError::NotFound));
        // Activating a destroyed id is a no-op: the current tables stay.
        activate(first);
        assert!(is_active(second));
        assert_eq!(activate_checked(first), Err(VmError::NotFound));
        assert_eq!(copy_in(first, 0x1000, &mut buf), Err(VmError::NotFound));

        // Release the third slot so the reuse checks below see the free pool.
        destroy(third).expect("destroy third");

        // The active space stays awake, but its slot is not the only one: the
        // freed slot 0 is immediately reusable.
        assert_eq!(destroy(second), Err(VmError::NotReady));
        let again = create().expect("space after destroy");
        assert_eq!(again.index(), 0);
        destroy(again).expect("destroy again");
    }

    fn test_pool_freed() -> usize {
        // SAFETY: the public-API tests hold API_LOCK while the global pool is in
        // use, and no other test touches it.
        unsafe { (*ptr::addr_of!(TEST_POOL)).freed() }
    }

    #[test]
    fn public_api_borrow_unmap_protect() {
        let _guard = API_LOCK.lock().unwrap_or_else(|err| err.into_inner());
        reset_globals();

        let space = create().expect("space");
        let owned = test_alloc_frame();
        let shared = test_alloc_frame();
        map_user(space, 0x1000, owned, PAGE_SIZE, true, false).expect("owned page");
        map_user_borrowed(space, 0x2000, shared, PAGE_SIZE, false, false).expect("borrowed page");

        // A borrowed page takes the same protection path as an owned one.
        protect_user(space, 0x2000, PAGE_SIZE, true, false).expect("borrowed rw");
        copy_out(space, 0x2000, b"borrowed").expect("write borrowed");
        let mut buf = [0u8; 8];
        copy_in(space, 0x2000, &mut buf).expect("read borrowed");
        assert_eq!(&buf, b"borrowed");
        assert_eq!(
            protect_user(space, 0x2000, PAGE_SIZE, true, true),
            Err(VmError::BadAddress)
        );

        // Owned unmaps return the frame; borrowed unmaps do not.
        let freed_after_maps = test_pool_freed();
        unmap_user(space, 0x1000, PAGE_SIZE).expect("unmap owned");
        assert_eq!(test_pool_freed(), freed_after_maps + 1);
        unmap_user(space, 0x2000, PAGE_SIZE).expect("unmap borrowed");
        assert_eq!(test_pool_freed(), freed_after_maps + 1);
        assert_eq!(unmap_user(space, 0x2000, PAGE_SIZE), Err(VmError::NotFound));
        assert_eq!(
            protect_user(space, 0x2000, PAGE_SIZE, true, false),
            Err(VmError::NotFound)
        );
        assert_eq!(
            map_user_borrowed(
                AddressSpaceId::INVALID,
                0x3000,
                shared,
                PAGE_SIZE,
                false,
                false
            ),
            Err(VmError::NotFound)
        );

        // Only page tables are left: root + PDPT + PD + one PT.
        let freed_before_destroy = test_pool_freed();
        destroy(space).expect("destroy");
        assert_eq!(test_pool_freed(), freed_before_destroy + 4);
    }

    // -----------------------------------------------------------------------
    // M5c2: borrowed frames, unmap, protect
    // -----------------------------------------------------------------------

    #[test]
    fn borrowed_mapping_is_not_owned_and_not_freed() {
        let mut pool = TestPool::new(32);
        let mut state = new_space(&mut pool);
        let borrowed = pool.alloc().expect("borrowed frame");
        let spare = pool.alloc().expect("spare frame");
        map_borrowed_in(
            &mut pool, &mut state, 0x1000, borrowed, PAGE_SIZE, true, false,
        )
        .expect("borrow page");
        assert_eq!(
            state.n_user, 0,
            "borrowed frames never enter the owned list"
        );
        assert_eq!(leaf(&state, 0x1000).expect("leaf") & ADDR_MASK, borrowed);

        // The same validation as an owned mapping.
        assert_eq!(
            map_borrowed_in(&mut pool, &mut state, 0x2000, spare, PAGE_SIZE, true, true),
            Err(VmError::BadAddress)
        );
        assert_eq!(
            map_borrowed_in(
                &mut pool, &mut state, 0x1000, spare, PAGE_SIZE, false, false
            ),
            Err(VmError::Overlap)
        );
        assert_eq!(
            map_borrowed_in(
                &mut pool, &mut state, 0x2008, spare, PAGE_SIZE, false, false
            ),
            Err(VmError::BadAddress)
        );

        let tables = usize::from(state.n_table);
        destroy_in(&mut pool, &mut state);
        assert!(state.is_empty());
        // Only the page tables came back: the borrowed frame belongs to its
        // owner (the page cache), not to this address space.
        assert_eq!(pool.freed(), tables);
    }

    #[test]
    fn unmap_frees_owned_frames_exactly_once() {
        let mut pool = TestPool::new(32);
        let mut state = new_space(&mut pool);
        let a = pool.alloc().expect("a");
        let b = pool.alloc().expect("b");
        map_user_in(&mut pool, &mut state, 0x1000, a, PAGE_SIZE, true, false).expect("a");
        map_user_in(&mut pool, &mut state, 0x2000, b, PAGE_SIZE, true, false).expect("b");
        assert_eq!(state.n_user, 2);

        unmap_user_in(&mut pool, &mut state, 0x1000, PAGE_SIZE).expect("unmap a");
        assert_eq!(pool.freed(), 1);
        assert_eq!(state.n_user, 1);
        assert_eq!(leaf(&state, 0x1000), None);
        assert!(leaf(&state, 0x2000).is_some());

        // `a` was retired by unmap, `b` by destroy: each frame exactly once.
        let tables = usize::from(state.n_table);
        destroy_in(&mut pool, &mut state);
        assert_eq!(pool.freed(), 2 + tables);
    }

    #[test]
    fn unmap_is_atomic_when_range_is_partially_mapped() {
        let mut pool = TestPool::new(32);
        let mut state = new_space(&mut pool);
        let a = pool.alloc().expect("a");
        let c = pool.alloc().expect("c");
        map_user_in(&mut pool, &mut state, 0x1000, a, PAGE_SIZE, true, false).expect("a");
        map_user_in(&mut pool, &mut state, 0x3000, c, PAGE_SIZE, true, false).expect("c");

        assert_eq!(
            unmap_user_in(&mut pool, &mut state, 0x1000, 3 * PAGE_SIZE),
            Err(VmError::NotFound)
        );
        // Nothing was retired or freed by the refused request.
        assert_eq!(pool.freed(), 0);
        assert_eq!(state.n_user, 2);
        assert_eq!(leaf(&state, 0x1000).expect("a leaf") & ADDR_MASK, a);
        assert_eq!(leaf(&state, 0x3000).expect("c leaf") & ADDR_MASK, c);
    }

    #[test]
    fn unmap_rejects_bad_requests_and_kernel_leaves() {
        let mut pool = TestPool::new(32);
        let mut state = new_space(&mut pool);
        let frame = pool.alloc().expect("frame");
        map_user_in(
            &mut pool, &mut state, 0x1000, frame, PAGE_SIZE, false, false,
        )
        .expect("page");
        // A leaf that is not user-accessible must not be retired (or freed).
        install_leaf(&mut pool, &mut state, 0x2000, frame, PTE_PRESENT).expect("kernel leaf");

        assert_eq!(
            unmap_user_in(&mut pool, &mut state, 0x2000, PAGE_SIZE),
            Err(VmError::BadAddress)
        );
        assert!(
            leaf(&state, 0x2000).is_some(),
            "refused request keeps leaves"
        );
        for (virt, len) in [
            (0x1008, PAGE_SIZE),
            (0x1000, 0),
            (0x1000, PAGE_SIZE - 1),
            (USER_MAX, PAGE_SIZE),
            (USER_MAX - PAGE_SIZE, 2 * PAGE_SIZE),
        ] {
            assert_eq!(
                unmap_user_in(&mut pool, &mut state, virt, len),
                Err(VmError::BadAddress),
                "virt {virt:#x} len {len:#x}"
            );
        }
        assert_eq!(
            unmap_user_in(&mut pool, &mut state, 0x4000, PAGE_SIZE),
            Err(VmError::NotFound)
        );
        assert_eq!(pool.freed(), 0);
        assert_eq!(state.n_user, 1);
        assert!(leaf(&state, 0x1000).is_some());
    }

    #[test]
    fn protect_updates_permissions_for_owned_and_borrowed() {
        let mut pool = TestPool::new(32);
        let mut state = new_space(&mut pool);
        let owned = pool.alloc().expect("owned");
        let cached = pool.alloc().expect("cached");
        map_user_in(
            &mut pool, &mut state, 0x1000, owned, PAGE_SIZE, false, false,
        )
        .expect("owned page");
        map_borrowed_in(
            &mut pool, &mut state, 0x2000, cached, PAGE_SIZE, false, true,
        )
        .expect("borrowed page");

        protect_user_in(&state, 0x1000, PAGE_SIZE, true, false).expect("rw");
        let entry = leaf(&state, 0x1000).expect("leaf");
        assert_eq!(entry & ADDR_MASK, owned);
        assert_eq!(path_flags(entry), (true, true, true));

        protect_user_in(&state, 0x1000, PAGE_SIZE, false, true).expect("rx");
        let entry = leaf(&state, 0x1000).expect("leaf");
        assert_eq!(entry & ADDR_MASK, owned, "protect keeps the frame");
        assert_eq!(path_flags(entry), (true, false, false));

        // Borrowed pages take the same path and stay unowned.
        protect_user_in(&state, 0x2000, PAGE_SIZE, true, false).expect("borrowed rw");
        let entry = leaf(&state, 0x2000).expect("leaf");
        assert_eq!(entry & ADDR_MASK, cached);
        assert_eq!(path_flags(entry), (true, true, true));
        assert_eq!(state.n_user, 1);
        assert_eq!(pool.freed(), 0);

        // W^X is refused and the previous flags survive.
        assert_eq!(
            protect_user_in(&state, 0x1000, PAGE_SIZE, true, true),
            Err(VmError::BadAddress)
        );
        assert_eq!(
            path_flags(leaf(&state, 0x1000).expect("leaf")),
            (true, false, false)
        );
    }

    #[test]
    fn protect_is_atomic_and_rejects_unmapped_ranges() {
        let mut pool = TestPool::new(32);
        let mut state = new_space(&mut pool);
        let frame = pool.alloc().expect("frame");
        map_user_in(
            &mut pool, &mut state, 0x1000, frame, PAGE_SIZE, false, false,
        )
        .expect("page");
        let before = leaf(&state, 0x1000).expect("leaf");

        // The second page is unmapped: the first one must not change either.
        assert_eq!(
            protect_user_in(&state, 0x1000, 2 * PAGE_SIZE, true, false),
            Err(VmError::NotFound)
        );
        assert_eq!(leaf(&state, 0x1000).expect("leaf"), before);
        assert_eq!(
            protect_user_in(&state, 0x1008, PAGE_SIZE, true, false),
            Err(VmError::BadAddress)
        );
        assert_eq!(
            protect_user_in(&state, USER_MAX, PAGE_SIZE, true, false),
            Err(VmError::BadAddress)
        );
        assert_eq!(
            protect_user_in(&state, 0x1000, 0, true, false),
            Err(VmError::BadAddress)
        );
        assert_eq!(
            path_flags(leaf(&state, 0x1000).expect("leaf")),
            (true, false, true)
        );
    }

    #[test]
    fn mixed_range_unmaps_owned_and_borrowed_together() {
        let mut pool = TestPool::new(32);
        let mut state = new_space(&mut pool);
        let a = pool.alloc().expect("owned a");
        let shared = pool.alloc().expect("borrowed");
        let c = pool.alloc().expect("owned c");
        // SAFETY: live test frames, one page each.
        unsafe {
            ptr::write_bytes(phys_ptr(a), 0xA0, PAGE_SIZE as usize);
            ptr::write_bytes(phys_ptr(shared), 0x5E, PAGE_SIZE as usize);
            ptr::write_bytes(phys_ptr(c), 0xC0, PAGE_SIZE as usize);
        }
        map_user_in(&mut pool, &mut state, 0x1000, a, PAGE_SIZE, true, false).expect("a");
        map_borrowed_in(
            &mut pool, &mut state, 0x2000, shared, PAGE_SIZE, true, false,
        )
        .expect("shared");
        map_user_in(&mut pool, &mut state, 0x3000, c, PAGE_SIZE, true, false).expect("c");
        assert_eq!(state.n_user, 2);

        // Reads reach the borrowed page through the same copy path.
        let mut buf = [0u8; 4];
        copy_range(&state, 0x2000, buf.as_mut_ptr(), buf.len(), false).expect("copy_in borrowed");
        assert_eq!(buf, [0x5E; 4]);

        let tables = usize::from(state.n_table);
        unmap_user_in(&mut pool, &mut state, 0x1000, 3 * PAGE_SIZE).expect("unmap mixed");
        assert_eq!(pool.freed(), 2, "only the two owned frames return");
        assert_eq!(state.n_user, 0);
        assert_eq!(leaf(&state, 0x2000), None);
        // SAFETY: the borrowed frame is still allocated by the pool.
        assert_eq!(read_frame_byte(shared, 0), 0x5E, "borrowed data untouched");

        destroy_in(&mut pool, &mut state);
        assert_eq!(pool.freed(), 2 + tables);
    }

    // -----------------------------------------------------------------------
    // M8a: PROT_NONE (true no-access) leaves
    // -----------------------------------------------------------------------

    #[test]
    fn noaccess_keeps_the_mapping_but_hides_it_from_access() {
        let mut pool = TestPool::new(32);
        let mut state = new_space(&mut pool);
        let owned = pool.alloc().expect("owned");
        let cached = pool.alloc().expect("cached");
        map_user_in(&mut pool, &mut state, 0x1000, owned, PAGE_SIZE, true, false)
            .expect("owned page");
        map_borrowed_in(
            &mut pool, &mut state, 0x2000, cached, PAGE_SIZE, false, false,
        )
        .expect("borrowed page");

        protect_noaccess_in(&state, 0x1000, 2 * PAGE_SIZE).expect("protect none");

        // Hardware's view: neither leaf is present, so every access faults.
        assert_eq!(leaf(&state, 0x1000), None);
        assert_eq!(leaf(&state, 0x2000), None);
        // The address space's view: both are still mappings of their frames.
        let owned_leaf = mapped_leaf(&state, 0x1000).expect("owned mapping");
        let cached_leaf = mapped_leaf(&state, 0x2000).expect("borrowed mapping");
        assert_eq!(owned_leaf & ADDR_MASK, owned);
        assert_eq!(cached_leaf & ADDR_MASK, cached);
        for entry in [owned_leaf, cached_leaf] {
            assert_eq!(entry & PTE_NOACCESS, PTE_NOACCESS);
            assert_eq!(entry & PTE_PRESENT, 0, "hardware must fault");
            assert_eq!(entry & PTE_WRITE, 0, "nothing about the page is writable");
            assert_eq!(
                entry & PTE_USER,
                PTE_USER,
                "the walk must still see user memory"
            );
        }
        // No frame changed hands and no byte moved.
        assert_eq!(state.n_user, 1);
        assert_eq!(pool.freed(), 0);

        // Copy paths refuse it as inaccessible (BadAddress), not as a hole.
        let mut buf = [0u8; 8];
        assert_eq!(
            copy_range(&state, 0x1000, buf.as_mut_ptr(), 8, false),
            Err(VmError::BadAddress)
        );
        assert_eq!(
            copy_range(&state, 0x1000, buf.as_ptr(), 8, true),
            Err(VmError::BadAddress)
        );
        // A neighbouring hole keeps the "unmapped" answer.
        assert_eq!(
            copy_range(&state, 0x3000, buf.as_mut_ptr(), 8, false),
            Err(VmError::NotFound)
        );

        // Idempotent: protecting none again leaves the leaf exactly as it was.
        protect_noaccess_in(&state, 0x1000, PAGE_SIZE).expect("repeat");
        assert_eq!(mapped_leaf(&state, 0x1000).expect("leaf"), owned_leaf);
        assert_eq!(pool.freed(), 0);

        // Destroy still returns the owned frame (the no-access page owns it).
        let tables = usize::from(state.n_table);
        destroy_in(&mut pool, &mut state);
        assert_eq!(pool.freed(), 1 + tables);
    }

    #[test]
    fn restore_after_noaccess_rewrites_permissions() {
        let mut pool = TestPool::new(32);
        let mut state = new_space(&mut pool);
        let frame = pool.alloc().expect("frame");
        map_user_in(&mut pool, &mut state, 0x1000, frame, PAGE_SIZE, true, false).expect("rw");
        protect_noaccess_in(&state, 0x1000, PAGE_SIZE).expect("protect none");
        assert_eq!(leaf(&state, 0x1000), None);

        // Read-write restore: PRESENT returns, the marker is cleared.
        protect_user_in(&state, 0x1000, PAGE_SIZE, true, false).expect("rw");
        let entry = leaf(&state, 0x1000).expect("present again");
        assert_eq!(entry & ADDR_MASK, frame, "the frame is kept");
        assert_eq!(entry & PTE_NOACCESS, 0, "the marker must be cleared");
        assert_eq!(path_flags(entry), (true, true, true));
        assert_eq!(mapped_leaf(&state, 0x1000), Some(entry));
        let mut buf = [0u8; 4];
        copy_range(&state, 0x1000, buf.as_ptr(), 4, true).expect("writable again");

        // Read-only restore drops WRITE but keeps PRESENT.
        protect_noaccess_in(&state, 0x1000, PAGE_SIZE).expect("protect none again");
        protect_user_in(&state, 0x1000, PAGE_SIZE, false, false).expect("ro");
        let entry = leaf(&state, 0x1000).expect("present again");
        assert_eq!(entry & ADDR_MASK, frame);
        assert_eq!(path_flags(entry), (true, false, true));
        copy_range(&state, 0x1000, buf.as_mut_ptr(), 4, false).expect("readable");
        assert_eq!(
            copy_range(&state, 0x1000, buf.as_ptr(), 4, true),
            Err(VmError::BadAddress),
            "a read-only page still refuses writes"
        );

        // Executable restore clears NX.
        protect_noaccess_in(&state, 0x1000, PAGE_SIZE).expect("protect none a third time");
        protect_user_in(&state, 0x1000, PAGE_SIZE, false, true).expect("rx");
        assert_eq!(
            path_flags(leaf(&state, 0x1000).expect("present")),
            (true, false, false)
        );
        assert_eq!(pool.freed(), 0, "permission updates never free frames");

        let tables = usize::from(state.n_table);
        destroy_in(&mut pool, &mut state);
        assert_eq!(pool.freed(), 1 + tables);
    }

    #[test]
    fn unmap_after_noaccess_frees_owned_frames_exactly_once() {
        let mut pool = TestPool::new(32);
        let mut state = new_space(&mut pool);
        let owned = pool.alloc().expect("owned");
        let borrowed = pool.alloc().expect("borrowed");
        map_user_in(&mut pool, &mut state, 0x1000, owned, PAGE_SIZE, true, false)
            .expect("owned page");
        map_borrowed_in(
            &mut pool, &mut state, 0x2000, borrowed, PAGE_SIZE, true, false,
        )
        .expect("borrowed page");
        protect_noaccess_in(&state, 0x1000, 2 * PAGE_SIZE).expect("protect none");

        // An owned no-access page returns its frame exactly once.
        unmap_user_in(&mut pool, &mut state, 0x1000, PAGE_SIZE).expect("unmap owned");
        assert_eq!(pool.freed(), 1);
        assert_eq!(state.n_user, 0);
        assert_eq!(mapped_leaf(&state, 0x1000), None);

        // A borrowed no-access page is unmapped without freeing anything.
        unmap_user_in(&mut pool, &mut state, 0x2000, PAGE_SIZE).expect("unmap borrowed");
        assert_eq!(pool.freed(), 1, "borrowed frames stay with their owner");
        assert_eq!(mapped_leaf(&state, 0x2000), None);

        // A second unmap finds no mapping: no double free, no double count.
        assert_eq!(
            unmap_user_in(&mut pool, &mut state, 0x1000, PAGE_SIZE),
            Err(VmError::NotFound)
        );
        assert_eq!(pool.freed(), 1);

        let tables = usize::from(state.n_table);
        destroy_in(&mut pool, &mut state);
        assert_eq!(pool.freed(), 1 + tables);
    }

    #[test]
    fn noaccess_rejects_unmapped_kernel_only_and_bad_ranges() {
        let mut pool = TestPool::new(32);
        let mut state = new_space(&mut pool);
        let frame = pool.alloc().expect("frame");
        map_user_in(&mut pool, &mut state, 0x1000, frame, PAGE_SIZE, true, false).expect("page");
        let before = leaf(&state, 0x1000).expect("leaf");

        // Not mapped at all is a different answer from "mapped, no access".
        assert_eq!(
            protect_noaccess_in(&state, 0x4000, PAGE_SIZE),
            Err(VmError::NotFound)
        );
        // Bad geometry keeps the usual BadAddress contract.
        for (virt, len) in [
            (0x1008, PAGE_SIZE),
            (0x1000, 0),
            (0x1000, PAGE_SIZE - 1),
            (USER_MAX, PAGE_SIZE),
            (USER_MAX - PAGE_SIZE, 2 * PAGE_SIZE),
        ] {
            assert_eq!(
                protect_noaccess_in(&state, virt, len),
                Err(VmError::BadAddress),
                "virt {virt:#x} len {len:#x}"
            );
        }

        // A present but kernel-only leaf is not user memory.
        install_leaf(&mut pool, &mut state, 0x3000, frame, PTE_PRESENT).expect("kernel leaf");
        assert_eq!(
            protect_noaccess_in(&state, 0x3000, PAGE_SIZE),
            Err(VmError::BadAddress)
        );

        // A range with a hole in the middle is refused as a whole: the first
        // page must keep its old (present) leaf.
        assert_eq!(
            protect_noaccess_in(&state, 0x1000, 3 * PAGE_SIZE),
            Err(VmError::NotFound)
        );
        assert_eq!(leaf(&state, 0x1000).expect("leaf"), before);
        assert_eq!(pool.freed(), 0);
    }

    #[test]
    fn mapping_over_a_noaccess_page_is_an_overlap() {
        let mut pool = TestPool::new(32);
        let mut state = new_space(&mut pool);
        let owned = pool.alloc().expect("owned");
        let replacement = pool.alloc().expect("replacement");
        let shared = pool.alloc().expect("shared");
        map_user_in(&mut pool, &mut state, 0x1000, owned, PAGE_SIZE, true, false).expect("page");
        protect_noaccess_in(&state, 0x1000, PAGE_SIZE).expect("protect none");
        let noaccess = mapped_leaf(&state, 0x1000).expect("mapping");

        // Neither an owned nor a borrowed map may replace the page: the frame
        // is still owned and only `unmap_user` may retire it.
        assert_eq!(
            map_user_in(
                &mut pool,
                &mut state,
                0x1000,
                replacement,
                PAGE_SIZE,
                false,
                false
            ),
            Err(VmError::Overlap)
        );
        assert_eq!(
            map_borrowed_in(
                &mut pool, &mut state, 0x1000, shared, PAGE_SIZE, false, false
            ),
            Err(VmError::Overlap)
        );
        assert_eq!(
            mapped_leaf(&state, 0x1000),
            Some(noaccess),
            "the refused map must not replace the leaf"
        );
        assert_eq!(state.n_user, 1);
        assert_eq!(pool.freed(), 0);

        // A range overlapping a no-access page is refused as a whole.
        let extra = pool.alloc().expect("extra");
        map_user_in(
            &mut pool, &mut state, 0x2000, extra, PAGE_SIZE, false, false,
        )
        .expect("second page");
        assert_eq!(
            map_user_in(
                &mut pool,
                &mut state,
                0x1000,
                replacement,
                2 * PAGE_SIZE,
                false,
                false
            ),
            Err(VmError::Overlap)
        );
        assert_eq!(state.n_user, 2);
        assert_eq!(
            leaf(&state, 0x2000).expect("second leaf") & ADDR_MASK,
            extra
        );

        let tables = usize::from(state.n_table);
        destroy_in(&mut pool, &mut state);
        assert_eq!(pool.freed(), 2 + tables);
    }

    #[test]
    fn borrowed_mappings_do_not_consume_the_owned_frame_budget() {
        let mut pool = TestPool::new(MAX_USER_FRAMES + 64);
        let mut state = new_space(&mut pool);
        let mut virt = 0x10_0000u64;
        let mut count = 0usize;
        while count < MAX_USER_FRAMES {
            let frame = pool.alloc().expect("owned frame");
            map_user_in(&mut pool, &mut state, virt, frame, PAGE_SIZE, false, false)
                .expect("owned page");
            count += 1;
            virt += PAGE_SIZE;
        }
        assert_eq!(usize::from(state.n_user), MAX_USER_FRAMES);

        // One more owned page is refused...
        let spare = pool.alloc().expect("spare frame");
        assert_eq!(
            map_user_in(&mut pool, &mut state, virt, spare, PAGE_SIZE, false, false),
            Err(VmError::OutOfTables)
        );
        // ...but a borrowed page still maps on that same free page: it only
        // costs a page table, not an owned-frame slot.
        let cached = pool.alloc().expect("cached frame");
        let shared_virt = virt;
        map_borrowed_in(
            &mut pool,
            &mut state,
            shared_virt,
            cached,
            PAGE_SIZE,
            false,
            false,
        )
        .expect("borrowed page");
        assert_eq!(usize::from(state.n_user), MAX_USER_FRAMES);
        assert!(leaf(&state, shared_virt).is_some());
    }

    // -----------------------------------------------------------------------
    // Translation and syscall preflight (M6a2)
    // -----------------------------------------------------------------------

    #[test]
    fn translate_user_reports_owned_and_borrowed_frames() {
        let _guard = API_LOCK.lock().unwrap_or_else(|err| err.into_inner());
        reset_globals();

        let space = create().expect("space");
        let owned = test_alloc_frame();
        let shared = test_alloc_frame();
        map_user(space, 0x10_0000, owned, PAGE_SIZE, true, false).expect("owned page");
        map_user_borrowed(space, 0x20_0000, shared, PAGE_SIZE, false, false)
            .expect("borrowed page");

        assert_eq!(translate_user(space, 0x10_0000), Some(owned));
        assert_eq!(translate_user(space, 0x10_0123), Some(owned + 0x123));
        assert_eq!(
            translate_user(space, 0x20_0FFF),
            Some(shared + PAGE_SIZE - 1),
            "borrowed frames translate like owned ones"
        );

        destroy(space).expect("destroy");
        assert_eq!(translate_user(space, 0x10_0000), None, "slot is gone");
    }

    #[test]
    fn translate_user_reports_holes_high_half_and_dead_ids() {
        let _guard = API_LOCK.lock().unwrap_or_else(|err| err.into_inner());
        reset_globals();

        let space = create().expect("space");
        let frame = test_alloc_frame();
        map_user(space, 0x10_0000, frame, PAGE_SIZE, false, false).expect("page");

        assert_eq!(translate_user(space, 0x10_1000), None, "unmapped hole");
        assert_eq!(
            translate_user(space, USER_MAX),
            None,
            "outside the user half"
        );
        assert_eq!(
            translate_user(space, 0xFFFF_8000_0000_0000),
            None,
            "kernel half is not user memory"
        );
        assert_eq!(translate_user(AddressSpaceId::INVALID, 0x10_0000), None);
        assert_eq!(translate_user(AddressSpaceId(9), 0x10_0000), None);

        // A present page whose leaf lost `PTE_USER` is not user memory even
        // though the walk reaches a leaf.
        let entry = {
            let spaces = spaces();
            let state = spaces.get_mut(space.index()).expect("slot");
            let entry = leaf_entry(state, 0x10_0000).expect("walk").expect("leaf");
            set_leaf(state, 0x10_0000, entry & !PTE_USER).expect("clear user");
            entry
        };
        assert_eq!(translate_user(space, 0x10_0000), None);
        assert_eq!(
            validate_user_range(space, 0x10_0000, PAGE_SIZE, false),
            Err(VmError::BadAddress)
        );
        {
            let spaces = spaces();
            let state = spaces.get_mut(space.index()).expect("slot");
            set_leaf(state, 0x10_0000, entry).expect("restore user");
        }
        assert_eq!(translate_user(space, 0x10_0000), Some(frame));

        destroy(space).expect("destroy");
    }

    #[test]
    fn validate_user_range_checks_every_page_and_write_permission() {
        let _guard = API_LOCK.lock().unwrap_or_else(|err| err.into_inner());
        reset_globals();

        let space = create().expect("space");
        let a = test_alloc_frame();
        let b = test_alloc_frame();
        let c = test_alloc_frame();
        map_user(space, 0x10_0000, a, PAGE_SIZE, true, false).expect("rw page");
        map_user(space, 0x10_1000, b, PAGE_SIZE, false, false).expect("ro page");
        map_user(space, 0x10_2000, c, PAGE_SIZE, true, false).expect("rw page");

        // Unaligned start across three pages: readable, but the read-only middle
        // page rejects a write request.
        let span = 3 * PAGE_SIZE - 16;
        assert!(validate_user_range(space, 0x10_0008, span, false).is_ok());
        assert_eq!(
            validate_user_range(space, 0x10_0008, span, true),
            Err(VmError::BadAddress),
            "the read-only page is not the first or last one"
        );
        assert!(validate_user_range(space, 0x10_0000, PAGE_SIZE, true).is_ok());

        // A hole in the middle invalidates the range while each single page
        // still validates: the check really walks page by page.
        unmap_user(space, 0x10_1000, PAGE_SIZE).expect("unmap middle");
        assert_eq!(
            validate_user_range(space, 0x10_0000, 3 * PAGE_SIZE, false),
            Err(VmError::BadAddress)
        );
        assert!(validate_user_range(space, 0x10_0000, PAGE_SIZE, false).is_ok());
        assert!(validate_user_range(space, 0x10_2000, PAGE_SIZE, false).is_ok());

        destroy(space).expect("destroy");
    }

    #[test]
    fn validate_user_range_rejects_bad_bounds_and_dead_ids() {
        let _guard = API_LOCK.lock().unwrap_or_else(|err| err.into_inner());
        reset_globals();

        let space = create().expect("space");
        assert_eq!(
            validate_user_range(AddressSpaceId::INVALID, 0x1000, PAGE_SIZE, false),
            Err(VmError::NotFound)
        );
        assert_eq!(
            validate_user_range(AddressSpaceId(9), 0x1000, PAGE_SIZE, false),
            Err(VmError::NotFound)
        );

        // Whether a zero-length buffer is legal is the syscall layer's policy;
        // the range check itself has nothing to walk.
        assert!(validate_user_range(space, u64::MAX, 0, false).is_ok());

        assert_eq!(
            validate_user_range(space, 0x10_0000, PAGE_SIZE, false),
            Err(VmError::BadAddress),
            "nothing is mapped yet"
        );
        let last_page = USER_MAX - PAGE_SIZE;
        assert_eq!(
            validate_user_range(space, last_page, 2 * PAGE_SIZE, false),
            Err(VmError::BadAddress),
            "range crosses the user bound"
        );
        assert_eq!(
            validate_user_range(space, u64::MAX - 1, 8, false),
            Err(VmError::BadAddress),
            "va + len overflows"
        );
        assert_eq!(
            validate_user_range(space, USER_MAX, PAGE_SIZE, false),
            Err(VmError::BadAddress)
        );

        destroy(space).expect("destroy");
        assert_eq!(
            validate_user_range(space, 0x1000, PAGE_SIZE, false),
            Err(VmError::NotFound)
        );
    }

    #[test]
    fn public_api_noaccess_roundtrip() {
        let _guard = API_LOCK.lock().unwrap_or_else(|err| err.into_inner());
        reset_globals();

        let space = create().expect("space");
        let owned = test_alloc_frame();
        let shared = test_alloc_frame();
        map_user(space, 0x10_0000, owned, PAGE_SIZE, true, false).expect("owned");
        map_user_borrowed(space, 0x10_1000, shared, PAGE_SIZE, true, false).expect("borrowed");

        protect_user_noaccess(space, 0x10_0000, 2 * PAGE_SIZE).expect("protect none");

        // Mapped, but never translated or copied.
        assert_eq!(translate_user(space, 0x10_0000), None);
        assert!(is_user_mapped(space, 0x10_0000));
        assert!(is_user_mapped(space, 0x10_1000));
        assert!(!is_user_mapped(space, 0x10_2000), "a hole is not mapped");
        assert!(!is_user_mapped(space, USER_MAX));
        assert!(!is_user_mapped(AddressSpaceId::INVALID, 0x10_0000));
        assert_eq!(
            validate_user_range(space, 0x10_0000, PAGE_SIZE, false),
            Err(VmError::BadAddress)
        );
        let mut buf = [0u8; 4];
        assert_eq!(
            copy_in(space, 0x10_0000, &mut buf),
            Err(VmError::BadAddress)
        );
        assert_eq!(
            copy_out(space, 0x10_0000, b"data"),
            Err(VmError::BadAddress)
        );

        // mprotect-style restore: found by `is_user_mapped`, given its
        // permissions back, and it allocates nothing.
        let freed_before = test_pool_freed();
        protect_user(space, 0x10_0000, 2 * PAGE_SIZE, true, false).expect("restore rw");
        assert_eq!(translate_user(space, 0x10_0000), Some(owned));
        copy_out(space, 0x10_0000, b"data").expect("writable again");
        assert_eq!(test_pool_freed(), freed_before);
        protect_user(space, 0x10_1000, PAGE_SIZE, false, false).expect("restore ro");
        copy_in(space, 0x10_1000, &mut buf).expect("readable again");
        assert_eq!(copy_out(space, 0x10_1000, b"x"), Err(VmError::BadAddress));

        // Protecting none twice is idempotent; unmapping retires exactly the
        // owned frame once and leaves the borrowed one with the page cache.
        protect_user_noaccess(space, 0x10_0000, 2 * PAGE_SIZE).expect("again");
        let freed_after_maps = test_pool_freed();
        unmap_user(space, 0x10_0000, PAGE_SIZE).expect("unmap owned");
        assert_eq!(test_pool_freed(), freed_after_maps + 1);
        unmap_user(space, 0x10_1000, PAGE_SIZE).expect("unmap borrowed");
        assert_eq!(test_pool_freed(), freed_after_maps + 1);
        assert!(!is_user_mapped(space, 0x10_0000));

        // Invalid handles are refused the same way as every other primitive.
        assert_eq!(
            protect_user_noaccess(AddressSpaceId::INVALID, 0x10_0000, PAGE_SIZE),
            Err(VmError::NotFound)
        );
        assert_eq!(
            protect_user_noaccess(AddressSpaceId(9), 0x10_0000, PAGE_SIZE),
            Err(VmError::NotFound)
        );

        // Destroy releases the tables only; the no-access path leaked nothing.
        let before_destroy = test_pool_freed();
        destroy(space).expect("destroy");
        assert_eq!(test_pool_freed(), before_destroy + 4);
        reset_globals();
    }

    // -----------------------------------------------------------------------
    // Per-CPU active bookkeeping (M6b2a)
    // -----------------------------------------------------------------------

    #[test]
    fn active_slots_are_per_cpu() {
        let _guard = API_LOCK.lock().unwrap_or_else(|err| err.into_inner());
        reset_globals();

        assert!(arch::MAX_CPUS >= 2, "needs at least two CPU slots");
        assert_eq!(arch::cpu_index(), 0, "host tests run as CPU 0");
        let first = AddressSpaceId::from_index(0);
        let second = AddressSpaceId::from_index(1);

        // Each CPU records its own choice; no slot bleeds into another.
        set_active_on(0, first.raw());
        set_active_on(1, second.raw());
        assert!(is_active_on(0, first));
        assert!(is_active_on(1, second));
        assert!(!is_active_on(0, second));
        assert!(!is_active_on(1, first));
        for cpu in 2..arch::MAX_CPUS {
            assert_eq!(active_on(cpu), NONE, "CPU {cpu} was never set");
            assert!(!is_active_on(cpu, first));
            assert!(!is_active_on(cpu, second));
        }

        // INVALID is never active, whatever a slot happens to hold.
        for cpu in 0..arch::MAX_CPUS {
            assert!(!is_active_on(cpu, AddressSpaceId::INVALID));
        }

        // Clearing one CPU leaves every other slot untouched.
        set_active_on(0, NONE);
        assert!(!is_active_on(0, first));
        assert_eq!(active_on(0), NONE);
        assert!(is_active_on(1, second));
        reset_globals();
    }

    #[test]
    fn activate_claims_only_the_calling_cpu() {
        let _guard = API_LOCK.lock().unwrap_or_else(|err| err.into_inner());
        reset_globals();

        let space = create().expect("space");
        assert!(!is_active(space), "nothing is loaded yet");

        // A refused activation writes nothing.
        activate(AddressSpaceId::INVALID);
        assert_eq!(active_on(0), NONE);

        activate(space);
        assert!(is_active(space), "the calling CPU switched");
        assert!(is_active_on(0, space));
        for cpu in 1..arch::MAX_CPUS {
            assert_eq!(active_on(cpu), NONE, "CPU {cpu} must not follow");
            assert!(!is_active_on(cpu, space));
        }

        // Another CPU running the same space is invisible here; this CPU is
        // still on it, so destroy is refused for the current-CPU reason.
        set_active_on(1, space.raw());
        assert!(is_active_on(1, space));
        assert_eq!(destroy(space), Err(VmError::NotReady));

        // Once this CPU switches away, destroy consults only its own slot: the
        // stale record on the other CPU does not keep the space alive.
        set_active_on(0, NONE);
        destroy(space).expect("destroy after this CPU left it");
        assert!(!is_active_on(0, space));
        assert!(is_active_on(1, space), "bookkeeping on the other CPU");
        reset_globals();
    }
}
