//! Linux64 memory system calls (M8a): `brk`, `mmap`, `munmap`, `mprotect`.
//!
//! This module is the anonymous-memory slice of the Linux personality. It does
//! **not** build a second virtual-memory subsystem: every mapping goes through
//! the existing `mm::pmm` and `mm::addrspace` primitives, which already own the
//! frames, page tables and the user half of the address space.
//!
//! # Address ranges
//!
//! ```text
//! 0x0000_0000 .. 0x0040_0000   (unmapped below the image)
//! 0x0040_0000 .. image_end     loaded image (owned by `image`)
//! image_end   .. 0x007F_F000   program break (`brk`) window, guard below the stack
//! 0x007F_F000 .. 0x0080_8000   user stack + guard (owned by `process`)
//! 0x0090_0000 .. 0x0100_0000   `mmap` bump window (native file mapping starts at
//!                              0x0100_0000)
//! ```
//!
//! M10a adds a second, higher break window for programs loaded at the dynamic
//! main bias (`0x0200_0000`): such an image ends above [`BRK_LIMIT`], so it
//! could never grow inside the legacy window. Those images grow up to
//! [`DYNAMIC_BRK_LIMIT`] instead, which stops one page below the interpreter
//! bias (`0x0500_0000`). Low images keep the legacy window unchanged.
//!
//! The program break starts at the real end of the loaded image. That address is
//! only known to the image loader, so the compatibility layer never guesses it:
//! [`FdTable::set_program_break`](super::fd::FdTable::set_program_break) is
//! called by the process spawn path with the exact `image_end`. Until that
//! happens `brk` reports the current (zero) break and changes nothing.
//!
//! # `brk` semantics (raw Linux, not `-errno`)
//!
//! `brk` is the one memory call whose *failure* is still reported in `rax` as a
//! value: it returns the current break, and the caller compares it with its
//! request to detect failure. It never returns `-errno`. Success returns the new
//! break, which on purpose is the **requested** value (Linux keeps it exact, the
//! page rounding only affects the mapping).
//!
//! # `mmap` policy
//!
//! * anonymous private mappings (`MAP_PRIVATE | MAP_ANONYMOUS`) and, since
//!   M10a, file-backed private mappings (pages populated at map time, writes
//!   stay in the frame and are never written back);
//! * `MAP_FIXED` is honoured for file-backed mappings and for `PROT_NONE`
//!   reservations, but a *data* anonymous mapping with `MAP_FIXED` is still
//!   rejected (`EINVAL`) — the window is a bump allocator;
//! * `MAP_SHARED` is rejected (`EOPNOTSUPP`);
//! * a non-anonymous call with `fd == -1` reports `EBADF`;
//! * `PROT_NONE` on an anonymous `mmap` is a **pre-allocated frame
//!   reservation** (M10a): the frames are really allocated and mapped, then
//!   presentation is withdrawn, so a later `mprotect` can restore access and
//!   `munmap` releases the frames; `MAP_FIXED` may cover the range. This is
//!   deliberately not lazy — a future slice may replace it with a lazy VMA,
//!   but frame savings are not claimed today;
//!   **`mprotect` accepts `PROT_NONE`** on mapped pages and withdraws
//!   presentation because user programs verify protection that way;
//! * `writable && executable` is rejected (`EINVAL`, W^X).
//!
//! `munmap` succeeds for pages that are not mapped (Linux behaviour) and only
//! needs the range to be page aligned. `mprotect` requires every page of the
//! range to be mapped and reports `ENOMEM` otherwise.
//!
//! # Testability
//!
//! The syscall entry points take an [`AddressSpaceOps`] trait object. Production
//! uses [`KernelSpace`] over `mm::addrspace`; host tests use a recording fake so
//! the whole planning/rollback pipeline (address assignment, frame allocation
//! and zeroing, permission changes, unmap) is exercised without touching the
//! `addrspace` global test pool, which its own host tests serialise with a
//! private mutex.

use crate::mm::addrspace::{self, AddressSpaceId};
use crate::mm::vm;

use super::errno;

/// Page size used by the personality (matches `mm::pmm::FRAME_SIZE`).
pub const PAGE_SIZE: u64 = 4096;

/// Exclusive upper bound of the program-break window for a **low image** (the
/// stack guard sits at `0x007F_F000`). Kept for the legacy static programs.
pub const BRK_LIMIT: u64 = 0x007F_F000;

/// Exclusive upper bound of the program-break window for a **dynamically
/// loaded** image whose `image_end` already sits above [`BRK_LIMIT`].
///
/// M10a maps a generic program at the dynamic main bias (`0x0200_0000`) and the
/// musl interpreter at `0x0500_0000`. A real musl `ldso` grows its heap with
/// `brk`, so the legacy window — which ends below the image — would reject every
/// growth and `malloc` would return `NULL`. This ceiling stops one page below the
/// interpreter bias so the break can never run into the interpreter mapping.
pub const DYNAMIC_BRK_LIMIT: u64 = 0x04FF_F000;

/// Start of the `mmap` bump window. Deliberately above the stack and below the
/// native file-mapping base (`vmobj::FIRST_MAP_BASE = 0x0100_0000`).
pub const MMAP_BASE: u64 = 0x0090_0000;

/// Exclusive upper bound of the `mmap` bump window.
pub const MMAP_LIMIT: u64 = 0x0100_0000;

/// `PROT_READ`.
pub const PROT_READ: u32 = 1;
/// `PROT_WRITE`.
pub const PROT_WRITE: u32 = 2;
/// `PROT_EXEC`.
pub const PROT_EXEC: u32 = 4;
/// All `PROT_*` bits this personality understands.
const PROT_MASK: u32 = PROT_READ | PROT_WRITE | PROT_EXEC;

/// `MAP_SHARED`.
pub const MAP_SHARED: u64 = 0x01;
/// `MAP_PRIVATE`.
pub const MAP_PRIVATE: u64 = 0x02;
/// `MAP_FIXED`.
pub const MAP_FIXED: u64 = 0x10;
/// `MAP_ANONYMOUS`.
pub const MAP_ANONYMOUS: u64 = 0x20;
/// `MAP_*` bits this personality understands.
const MAP_MASK: u64 = MAP_SHARED | MAP_PRIVATE | MAP_FIXED | MAP_ANONYMOUS;

/// Per-process Linux memory bookkeeping.
///
/// Lives inside the process's `FdTable` (like the descriptor table it is part of
/// the Linux personality state), so it is created and destroyed with the
/// process and never needs a process-table entry of its own.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LinuxMemory {
    /// Real end of the loaded image, when the spawn path has told us.
    start: Option<u64>,
    /// Current program break (exact value, unaligned values are preserved).
    brk: u64,
    /// Next free byte in the `mmap` bump window.
    mmap_next: u64,
}

impl LinuxMemory {
    /// Memory bookkeeping for a process whose image end is not known yet.
    pub const fn new() -> Self {
        Self {
            start: None,
            brk: 0,
            mmap_next: MMAP_BASE,
        }
    }

    /// The program break, or `None` until [`Self::set_initial_break`] runs.
    pub const fn program_break(&self) -> Option<u64> {
        match self.start {
            Some(_) => Some(self.brk),
            None => None,
        }
    }

    /// Where the program break started (the real end of the image).
    pub const fn program_break_start(&self) -> Option<u64> {
        self.start
    }

    /// Record the real end of the loaded image and start the break there.
    ///
    /// Called by the process spawn path once the image is mapped. The value is
    /// page rounded up so the first grow maps whole pages; `brk` still reports
    /// the exact requested value to user space.
    pub fn set_initial_break(&mut self, image_end: u64) {
        let start = align_up(image_end).unwrap_or(image_end);
        self.start = Some(start);
        self.brk = start;
    }

    /// Set the current break (mapping is done by the caller).
    pub fn set_break(&mut self, new_break: u64) {
        self.brk = new_break;
    }

    /// Next `mmap` bump address.
    pub const fn mmap_next(&self) -> u64 {
        self.mmap_next
    }

    /// Commit a successful `mmap` and advance the bump pointer.
    pub fn commit_mmap(&mut self, addr: u64, len: u64) {
        self.mmap_next = addr.saturating_add(len);
    }
}

impl Default for LinuxMemory {
    fn default() -> Self {
        Self::new()
    }
}

/// Round `value` up to the next page boundary.
pub fn align_up(value: u64) -> Option<u64> {
    let page = PAGE_SIZE;
    let rem = value % page;
    if rem == 0 {
        Some(value)
    } else {
        value.checked_add(page - rem)
    }
}

/// What one `brk` call has to do to move the break.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BrkPlan {
    /// Value to report (and store) on success.
    pub new_break: u64,
    /// Pages to map when growing.
    pub grow: Option<(u64, u64)>,
    /// Pages to unmap when shrinking.
    pub shrink: Option<(u64, u64)>,
}

/// Exclusive upper bound of the break window that fits an image starting at
/// `start`.
///
/// A low image keeps the legacy guard below the user stack. A dynamically
/// loaded image already ends above that guard, so it uses
/// [`DYNAMIC_BRK_LIMIT`] instead; otherwise no growth would ever be legal.
const fn brk_ceiling(start: u64) -> u64 {
    if start > BRK_LIMIT {
        DYNAMIC_BRK_LIMIT
    } else {
        BRK_LIMIT
    }
}

/// Plan a `brk` move, or `None` when the request must fail.
///
/// Failure means "leave the break alone and report the old value" — the raw
/// Linux convention, so this is not an errno.
pub fn brk_plan(memory: &LinuxMemory, requested: u64) -> Option<BrkPlan> {
    let start = memory.start?;
    let ceiling = brk_ceiling(start);
    if requested < start || requested > ceiling {
        return None;
    }
    let from = align_up(memory.brk)?;
    let to = align_up(requested)?;
    if to > ceiling {
        return None;
    }
    let grow = if to > from {
        Some((from, to - from))
    } else {
        None
    };
    let shrink = if from > to {
        Some((to, from - to))
    } else {
        None
    };
    Some(BrkPlan {
        new_break: requested,
        grow,
        shrink,
    })
}

/// What one `mmap` call should map.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MmapPlan {
    /// User virtual address the mapping starts at.
    pub addr: u64,
    /// Page-rounded length.
    pub len: u64,
    /// `PROT_WRITE` was requested.
    pub writable: bool,
    /// `PROT_EXEC` was requested (never together with writable).
    pub executable: bool,
    /// M10a: this `mmap` is a `PROT_NONE` reservation. The caller must build
    /// it with [`reserve_pages`]: frames are really allocated and mapped, then
    /// presentation is withdrawn, so a later `mprotect` can restore access. A
    /// later `MAP_FIXED` mapping may cover it.
    pub reserve: bool,
}

/// Parse `PROT_*` bits into `(writable, executable)`.
fn protection(prot: u32) -> Result<(bool, bool), i64> {
    if prot & !PROT_MASK != 0 {
        return Err(errno::EINVAL);
    }
    let writable = prot & PROT_WRITE != 0;
    let executable = prot & PROT_EXEC != 0;
    if writable && executable {
        return Err(errno::EINVAL);
    }
    Ok((writable, executable))
}

/// Plan an anonymous private `mmap`, or return a positive Linux error number.
///
/// The bump pointer is only advanced by [`LinuxMemory::commit_mmap`] after the
/// frames really landed, so a failed map leaves the window untouched.
pub fn mmap_plan(
    memory: &LinuxMemory,
    len: u64,
    prot: u32,
    flags: u64,
    fd: u64,
    offset: u64,
) -> Result<MmapPlan, i64> {
    if len == 0 {
        return Err(errno::EINVAL);
    }
    if flags & !MAP_MASK != 0 {
        return Err(errno::EINVAL);
    }
    if flags & MAP_FIXED != 0 {
        // The M8a window is a bump allocator; honouring MAP_FIXED would need a
        // real user-space allocator, so the flag is refused instead of ignored.
        return Err(errno::EINVAL);
    }
    if flags & MAP_SHARED != 0 {
        return Err(errno::EOPNOTSUPP);
    }
    if flags & MAP_PRIVATE == 0 {
        return Err(errno::EINVAL);
    }
    if flags & MAP_ANONYMOUS == 0 {
        // The file mapping path lives in the native ABI (M5c2); a Linux
        // `mmap(fd)` is not wired to it yet.
        if fd == u64::MAX {
            return Err(errno::EBADF);
        }
        return Err(errno::EOPNOTSUPP);
    }
    // Anonymous mappings ignore the descriptor, but the personality still
    // demands the canonical -1 so a wrapper bug shows up as EINVAL.
    if fd != u64::MAX {
        return Err(errno::EINVAL);
    }
    if offset != 0 {
        return Err(errno::EINVAL);
    }
    let len = align_up(len).ok_or(errno::ENOMEM)?;
    if len == 0 {
        return Err(errno::ENOMEM);
    }
    let addr = align_up(memory.mmap_next).ok_or(errno::ENOMEM)?;
    let end = addr.checked_add(len).ok_or(errno::ENOMEM)?;
    if end > MMAP_LIMIT || end > addrspace::USER_MAX {
        return Err(errno::ENOMEM);
    }
    if prot == 0 {
        // M10a: `PROT_NONE` anonymous mmap is a pre-allocated frame
        // reservation. The bump pointer moves so later mappings cannot overlap,
        // and the caller builds a real mapping whose presentation is withdrawn
        // (see [`reserve_pages`]); `mprotect` can then restore access and
        // `munmap` releases the frames.
        return Ok(MmapPlan {
            addr,
            len,
            writable: false,
            executable: false,
            reserve: true,
        });
    }
    let (writable, executable) = protection(prot)?;
    Ok(MmapPlan {
        addr,
        len,
        writable,
        executable,
        reserve: false,
    })
}

/// M10a: validate a `MAP_FIXED` `PROT_NONE` anonymous reservation.
///
/// The range is only checked and returned here; the caller builds the real
/// reservation with [`reserve_pages`] (frames allocated, presentation
/// withdrawn). The bump pointer does not move because the caller chose the
/// address. A later `MAP_FIXED` mapping may cover the range.
pub fn mmap_reserve_fixed(addr: u64, len: u64) -> Result<(u64, u64), i64> {
    if len == 0 {
        return Err(errno::EINVAL);
    }
    if addr == 0 || addr % PAGE_SIZE != 0 {
        return Err(errno::EINVAL);
    }
    let len = align_up(len).ok_or(errno::ENOMEM)?;
    if len == 0 {
        return Err(errno::ENOMEM);
    }
    let end = addr.checked_add(len).ok_or(errno::ENOMEM)?;
    if end > MMAP_LIMIT || end > addrspace::USER_MAX {
        return Err(errno::ENOMEM);
    }
    Ok((addr, len))
}

// ---------------------------------------------------------------------------
// Address-space driver
// ---------------------------------------------------------------------------

/// The slice of `mm::addrspace` the memory personality needs.
///
/// Production uses [`KernelSpace`]; host tests use a recording fake. Keeping the
/// seam this narrow means the planning and rollback logic can be tested without
/// touching the global address-space test pool.
pub trait AddressSpaceOps {
    /// Map `virt` to the owned frame `phys`.
    fn map(&mut self, virt: u64, phys: u64, writable: bool, executable: bool) -> Result<(), i64>;
    /// Remove the mapping at `virt` (owned frames are freed by the space).
    fn unmap(&mut self, virt: u64) -> Result<(), i64>;
    /// Rewrite permissions of an existing range.
    fn protect(&mut self, virt: u64, len: u64, writable: bool, executable: bool)
    -> Result<(), i64>;
    /// Withdraw presentation of an existing range (`PROT_NONE`): every access
    /// must fault. This is *not* the same as clearing read/write on the leaf,
    /// because that would leave the page readable.
    fn protect_noaccess(&mut self, virt: u64, len: u64) -> Result<(), i64>;
    /// Whether a user page is mapped.
    fn is_mapped(&self, virt: u64) -> bool;
}

/// [`AddressSpaceOps`] over the real `mm::addrspace` implementation.
#[derive(Clone, Copy)]
pub struct KernelSpace {
    id: AddressSpaceId,
}

impl KernelSpace {
    /// Wrap a live user address space.
    pub const fn new(id: AddressSpaceId) -> Self {
        Self { id }
    }
}

impl AddressSpaceOps for KernelSpace {
    fn map(&mut self, virt: u64, phys: u64, writable: bool, executable: bool) -> Result<(), i64> {
        addrspace::map_user(self.id, virt, phys, PAGE_SIZE, writable, executable).map_err(vm_errno)
    }

    fn unmap(&mut self, virt: u64) -> Result<(), i64> {
        addrspace::unmap_user(self.id, virt, PAGE_SIZE).map_err(vm_errno)
    }

    fn protect(
        &mut self,
        virt: u64,
        len: u64,
        writable: bool,
        executable: bool,
    ) -> Result<(), i64> {
        addrspace::protect_user(self.id, virt, len, writable, executable).map_err(vm_errno)
    }

    fn protect_noaccess(&mut self, virt: u64, len: u64) -> Result<(), i64> {
        addrspace::protect_user_noaccess(self.id, virt, len).map_err(vm_errno)
    }

    fn is_mapped(&self, virt: u64) -> bool {
        // `translate_user` returns `None` for a `PROT_NONE` mapping because the
        // presentation is withdrawn; that is an access property, not a
        // lifetime one. `is_user_mapped` answers the lifetime question.
        addrspace::is_user_mapped(self.id, virt)
    }
}

/// Whether a permission request withdraws presentation entirely.
///
/// Only `PROT_NONE` (no access bits at all) does: `PROT_READ` also has
/// `writable == false && executable == false`, so the read/write pair alone
/// cannot be used to classify the request. The read bit is part of the
/// presence contract, which is why the routing must look at the full `prot`.
fn requires_no_access(prot: u32) -> bool {
    prot & PROT_MASK == 0
}

/// Translate an address-space error into a Linux error number.
fn vm_errno(error: vm::VmError) -> i64 {
    match error {
        vm::VmError::OutOfTables => errno::ENOMEM,
        vm::VmError::Overlap => errno::EINVAL,
        vm::VmError::NotFound => errno::ENOMEM,
        vm::VmError::BadAddress => errno::EINVAL,
        vm::VmError::NotReady => errno::EIO,
    }
}

/// Frame source for anonymous mappings.
///
/// Production allocates through the PMM and reaches the frame through the direct
/// map; host tests use a zeroed arena so the rollback logic can run without the
/// global PMM being wired.
mod frames {
    #[cfg(not(test))]
    mod imp {
        use super::super::PAGE_SIZE;
        use crate::mm::{pmm, vm};

        pub fn alloc() -> Option<u64> {
            pmm::alloc_frame().ok()
        }

        pub fn dealloc(phys: u64) {
            let _ = pmm::dealloc_frame(phys);
        }

        pub fn zero(phys: u64) {
            // SAFETY: `phys` is a frame just handed out by the PMM; the direct
            // map covers every allocated frame.
            let bytes = unsafe {
                core::slice::from_raw_parts_mut(
                    vm::phys_to_virt(phys) as *mut u8,
                    PAGE_SIZE as usize,
                )
            };
            bytes.fill(0);
        }

        pub fn write(phys: u64, data: &[u8]) {
            // SAFETY: `phys` is a frame just handed out by the PMM; the direct
            // map covers every allocated frame.
            let bytes = unsafe {
                core::slice::from_raw_parts_mut(
                    vm::phys_to_virt(phys) as *mut u8,
                    PAGE_SIZE as usize,
                )
            };
            bytes[..data.len()].copy_from_slice(data);
        }
    }

    #[cfg(test)]
    mod imp {
        use std::alloc::{Layout, alloc_zeroed};
        use std::sync::Mutex;
        use std::vec::Vec;

        use super::super::PAGE_SIZE;

        /// Frames handed to a test; never reused, which mirrors "owned frame"
        /// semantics and keeps the tests independent.
        static FRAMES: Mutex<Vec<usize>> = Mutex::new(Vec::new());

        pub fn alloc() -> Option<u64> {
            let layout = Layout::from_size_align(PAGE_SIZE as usize, PAGE_SIZE as usize).ok()?;
            // SAFETY: `layout` is a valid non-zero layout; `alloc_zeroed`
            // returns null on failure, which becomes `None`.
            let pointer = unsafe { alloc_zeroed(layout) };
            if pointer.is_null() {
                return None;
            }
            FRAMES.lock().unwrap().push(pointer as usize);
            Some(pointer as u64)
        }

        pub fn dealloc(_phys: u64) {
            // The mapping path frees owned frames through `unmap`; the fake
            // space does not need the memory back.
        }

        pub fn zero(phys: u64) {
            // SAFETY: `phys` points at one of our own page sized allocations.
            unsafe { (phys as *mut u8).write_bytes(0, PAGE_SIZE as usize) };
        }

        pub fn write(phys: u64, data: &[u8]) {
            // SAFETY: `phys` points at one of our own page sized allocations.
            unsafe {
                core::ptr::copy_nonoverlapping(data.as_ptr(), phys as *mut u8, data.len());
            }
        }

        /// Whether the test frame is still all zero (checks the zero-fill path).
        pub fn is_zeroed(phys: u64) -> bool {
            // SAFETY: same as `zero`.
            let bytes =
                unsafe { core::slice::from_raw_parts(phys as *const u8, PAGE_SIZE as usize) };
            bytes.iter().all(|byte| *byte == 0)
        }
    }

    #[cfg(test)]
    pub use imp::is_zeroed;
    pub use imp::{alloc, dealloc, write, zero};
}

/// Map `len` freshly allocated, zeroed frames at `virt` with the given
/// permissions, rolling the whole range back on any failure.
pub fn map_anonymous(
    space: &mut dyn AddressSpaceOps,
    virt: u64,
    len: u64,
    writable: bool,
    executable: bool,
) -> Result<(), i64> {
    let mut offset = 0;
    while offset < len {
        let Some(phys) = frames::alloc() else {
            rollback(space, virt, offset);
            return Err(errno::ENOMEM);
        };
        frames::zero(phys);
        if let Err(error) = space.map(virt + offset, phys, writable, executable) {
            // The frame never became address-space property.
            frames::dealloc(phys);
            rollback(space, virt, offset);
            return Err(error);
        }
        offset += PAGE_SIZE;
    }
    Ok(())
}

/// Plan a file-backed private `mmap` (M10a), or return a positive Linux error.
///
/// This personality populates file pages at map time (there is no page cache
/// yet). The mapping is private: writes stay in the frame and are never written
/// back, which is exactly `MAP_PRIVATE` semantics. `offset` must be page
/// aligned; `MAP_FIXED` is honoured inside the same user window as anonymous
/// mappings.
pub fn mmap_file_plan(
    memory: &LinuxMemory,
    addr: u64,
    len: u64,
    prot: u32,
    flags: u64,
    fd: u64,
    offset: u64,
) -> Result<MmapPlan, i64> {
    if len == 0 {
        return Err(errno::EINVAL);
    }
    if flags & !MAP_MASK != 0 {
        return Err(errno::EINVAL);
    }
    if flags & MAP_ANONYMOUS != 0 || flags & MAP_SHARED != 0 || flags & MAP_PRIVATE == 0 {
        return Err(errno::EINVAL);
    }
    if fd == u64::MAX {
        return Err(errno::EBADF);
    }
    if offset % PAGE_SIZE != 0 {
        return Err(errno::EINVAL);
    }
    let len = align_up(len).ok_or(errno::ENOMEM)?;
    if len == 0 {
        return Err(errno::ENOMEM);
    }
    let (writable, executable) = protection(prot)?;
    let addr = if flags & MAP_FIXED != 0 {
        if addr == 0 || addr % PAGE_SIZE != 0 {
            return Err(errno::EINVAL);
        }
        addr
    } else {
        align_up(memory.mmap_next).ok_or(errno::ENOMEM)?
    };
    let end = addr.checked_add(len).ok_or(errno::ENOMEM)?;
    if end > MMAP_LIMIT || end > addrspace::USER_MAX {
        return Err(errno::ENOMEM);
    }
    Ok(MmapPlan {
        addr,
        len,
        writable,
        executable,
        reserve: false,
    })
}

/// Map `len` file-backed pages at `virt`, calling `fill` once per page to
/// populate one page buffer (short reads leave the rest zero; a file tail
/// therefore reads as zeroes, like Linux).
///
/// Every already mapped page is rolled back on failure, mirroring
/// [`map_anonymous`].
pub fn map_file_pages<F>(
    space: &mut dyn AddressSpaceOps,
    virt: u64,
    len: u64,
    writable: bool,
    executable: bool,
    mut fill: F,
) -> Result<(), i64>
where
    F: FnMut(u64, &mut [u8]) -> Result<(), i64>,
{
    let mut offset = 0;
    let mut page = [0u8; PAGE_SIZE as usize];
    while offset < len {
        if space.is_mapped(virt + offset) {
            // M10a: a `MAP_FIXED` file mapping may cover an older reservation;
            // replace the mapping so its frames are released instead of the map
            // failing with an overlap.
            if let Err(error) = space.unmap(virt + offset) {
                rollback(space, virt, offset);
                return Err(error);
            }
        }
        let Some(phys) = frames::alloc() else {
            rollback(space, virt, offset);
            return Err(errno::ENOMEM);
        };
        page.fill(0);
        if let Err(error) = fill(offset / PAGE_SIZE, &mut page) {
            frames::dealloc(phys);
            rollback(space, virt, offset);
            return Err(error);
        }
        frames::write(phys, &page);
        if let Err(error) = space.map(virt + offset, phys, writable, executable) {
            frames::dealloc(phys);
            rollback(space, virt, offset);
            return Err(error);
        }
        offset += PAGE_SIZE;
    }
    Ok(())
}

/// Unmap the pages of a range that are mapped, ignoring the unmapped ones
/// (Linux `munmap` semantics).
pub fn unmap_pages(space: &mut dyn AddressSpaceOps, virt: u64, len: u64) -> Result<(), i64> {
    let mut offset = 0;
    while offset < len {
        let page = virt + offset;
        if space.is_mapped(page) {
            space.unmap(page)?;
        }
        offset += PAGE_SIZE;
    }
    Ok(())
}

/// Rewrite permissions of a range; every page must already be mapped.
///
/// `no_access` comes from [`requires_no_access`] on the full `prot` value:
/// `PROT_NONE` withdraws presentation, while a read-only request
/// (`PROT_READ`) must keep the page present and simply clear the write bit.
/// Passing only `writable`/`executable` cannot tell those two apart.
pub fn protect_pages(
    space: &mut dyn AddressSpaceOps,
    virt: u64,
    len: u64,
    writable: bool,
    executable: bool,
    no_access: bool,
) -> Result<(), i64> {
    let mut offset = 0;
    while offset < len {
        if !space.is_mapped(virt + offset) {
            return Err(errno::ENOMEM);
        }
        offset += PAGE_SIZE;
    }
    if no_access {
        space.protect_noaccess(virt, len)
    } else {
        space.protect(virt, len, writable, executable)
    }
}

/// Unmap the already mapped prefix after a mid-range failure.
fn rollback(space: &mut dyn AddressSpaceOps, virt: u64, mapped: u64) {
    let mut offset = 0;
    while offset < mapped {
        let _ = space.unmap(virt + offset);
        offset += PAGE_SIZE;
    }
}

/// Build a `PROT_NONE` reservation: real frames are allocated and mapped at
/// `addr`, then presentation is withdrawn.
///
/// This is the M10a semantic: musl's `reclaim_gaps` maps `PROT_NONE` and then
/// `mprotect`s the pages it wants, so a real mapping must exist when
/// `mprotect` runs. [`protect_pages`] finds it through
/// [`AddressSpaceOps::is_mapped`] and restores access; `munmap` releases the
/// frames. A previous mapping in the range is replaced first, which makes
/// `MAP_FIXED` over a reservation release the old frames instead of leaking
/// them (or reporting an overlap).
fn reserve_pages(space: &mut dyn AddressSpaceOps, addr: u64, len: u64) -> Result<(), i64> {
    unmap_pages(space, addr, len)?;
    map_anonymous(space, addr, len, false, false)?;
    if let Err(error) = space.protect_noaccess(addr, len) {
        // The frames are mapped but still present; drop the whole range rather
        // than leave a half-built reservation behind.
        rollback(space, addr, len);
        return Err(error);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// System call entry points
// ---------------------------------------------------------------------------

/// `brk(12)`: move the program break.
///
/// Returns the value for `rax` (never `-errno`): the new break on success, the
/// old break when the request cannot be satisfied.
pub fn syscall_brk(
    memory: &mut LinuxMemory,
    requested: u64,
    mut space: Option<&mut dyn AddressSpaceOps>,
) -> Result<i64, i64> {
    let current = memory.program_break().unwrap_or(0);
    if requested == 0 {
        return Ok(current as i64);
    }
    let Some(plan) = brk_plan(memory, requested) else {
        return Ok(current as i64);
    };
    if let Some((start, len)) = plan.grow {
        let Some(space) = space.as_deref_mut() else {
            return Ok(current as i64);
        };
        if map_anonymous(space, start, len, true, false).is_err() {
            return Ok(current as i64);
        }
    } else if let Some((start, len)) = plan.shrink {
        let Some(space) = space.as_deref_mut() else {
            return Ok(current as i64);
        };
        if unmap_pages(space, start, len).is_err() {
            return Ok(current as i64);
        }
    }
    memory.set_break(plan.new_break);
    Ok(plan.new_break as i64)
}

/// `mmap(9)`: map anonymous private pages.
pub fn syscall_mmap(
    memory: &mut LinuxMemory,
    args: &[u64; 6],
    mut space: Option<&mut dyn AddressSpaceOps>,
) -> Result<i64, i64> {
    let prot = u32::try_from(args[2]).map_err(|_| errno::EINVAL)?;
    if prot == 0 && args[3] & MAP_FIXED != 0 {
        // M10a: a fixed `PROT_NONE` reservation is a real mapping (frames
        // allocated, presentation withdrawn) at the caller-chosen address; the
        // bump pointer does not move.
        let (addr, len) = mmap_reserve_fixed(args[0], args[1])?;
        let Some(space) = space.as_deref_mut() else {
            return Err(errno::EINVAL);
        };
        reserve_pages(space, addr, len)?;
        return Ok(addr as i64);
    }
    let plan = mmap_plan(memory, args[1], prot, args[3], args[4], args[5])?;
    let Some(space) = space.as_deref_mut() else {
        return Err(errno::EINVAL);
    };
    if plan.reserve {
        reserve_pages(space, plan.addr, plan.len)?;
    } else {
        map_anonymous(space, plan.addr, plan.len, plan.writable, plan.executable)?;
    }
    memory.commit_mmap(plan.addr, plan.len);
    Ok(plan.addr as i64)
}

/// `munmap(11)`: drop user mappings.
pub fn syscall_munmap(
    addr: u64,
    len: u64,
    mut space: Option<&mut dyn AddressSpaceOps>,
) -> Result<i64, i64> {
    let (_addr, len) = user_range(addr, len)?;
    let Some(space) = space.as_deref_mut() else {
        return Err(errno::EINVAL);
    };
    unmap_pages(space, addr, len)?;
    Ok(0)
}

/// `mprotect(10)`: change permissions of an existing range.
///
/// `PROT_NONE` is accepted here (users verify protection that way); only the
/// W^X combination is refused.
///
/// Linux treats `len == 0` as "nothing to do" but still validates `prot` and
/// the page alignment of `addr`, so the zero-length case is handled before the
/// generic range parser (which reports `EINVAL` for an empty range because
/// `munmap` needs exactly that).
pub fn syscall_mprotect(
    addr: u64,
    len: u64,
    prot: u64,
    mut space: Option<&mut dyn AddressSpaceOps>,
) -> Result<i64, i64> {
    let prot = u32::try_from(prot).map_err(|_| errno::EINVAL)?;
    let (writable, executable) = protection(prot)?;
    let no_access = requires_no_access(prot);
    if len == 0 {
        // `mprotect` still requires a page-aligned address; with a valid
        // address and an empty range there is nothing to change.
        if addr % PAGE_SIZE != 0 {
            return Err(errno::EINVAL);
        }
        return Ok(0);
    }
    let (addr, len) = user_range(addr, len)?;
    let Some(space) = space.as_deref_mut() else {
        return Err(errno::EINVAL);
    };
    protect_pages(space, addr, len, writable, executable, no_access)?;
    Ok(0)
}

/// Validate a user memory range for `munmap`/`mprotect`.
fn user_range(addr: u64, len: u64) -> Result<(u64, u64), i64> {
    if addr % PAGE_SIZE != 0 {
        return Err(errno::EINVAL);
    }
    if len == 0 {
        return Err(errno::EINVAL);
    }
    let len = align_up(len).ok_or(errno::EINVAL)?;
    let end = addr.checked_add(len).ok_or(errno::EINVAL)?;
    if addr >= addrspace::USER_MAX || end > addrspace::USER_MAX {
        return Err(errno::EINVAL);
    }
    Ok((addr, len))
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::vec::Vec;

    use super::*;

    /// Recording stand-in for a user address space.
    #[derive(Default)]
    struct FakeSpace {
        /// Current permissions of *present* pages.
        pages: BTreeMap<u64, (bool, bool)>,
        /// Lifetime of every mapping, present or `PROT_NONE`. Mirrors
        /// `addrspace::is_user_mapped`: a withdrawn page is still mapped.
        mapped: BTreeMap<u64, ()>,
        allocs: Vec<(u64, u64)>,
        protects: Vec<(u64, u64, bool, bool)>,
        noaccess: Vec<(u64, u64)>,
        fail_map_at: Option<u64>,
    }

    impl AddressSpaceOps for FakeSpace {
        fn map(
            &mut self,
            virt: u64,
            phys: u64,
            writable: bool,
            executable: bool,
        ) -> Result<(), i64> {
            if self.fail_map_at == Some(virt) {
                return Err(errno::ENOMEM);
            }
            if self.pages.insert(virt, (writable, executable)).is_some() {
                return Err(errno::EINVAL);
            }
            self.mapped.insert(virt, ());
            self.allocs.push((virt, phys));
            Ok(())
        }

        fn unmap(&mut self, virt: u64) -> Result<(), i64> {
            self.pages.remove(&virt).ok_or(errno::ENOMEM)?;
            self.mapped.remove(&virt);
            Ok(())
        }

        fn protect(
            &mut self,
            virt: u64,
            len: u64,
            writable: bool,
            executable: bool,
        ) -> Result<(), i64> {
            self.protects.push((virt, len, writable, executable));
            let mut offset = 0;
            while offset < len {
                self.pages.insert(virt + offset, (writable, executable));
                self.mapped.insert(virt + offset, ());
                offset += PAGE_SIZE;
            }
            Ok(())
        }

        fn protect_noaccess(&mut self, virt: u64, len: u64) -> Result<(), i64> {
            // The fake models the production effect: presentation is
            // withdrawn, so the pages stop being present. Their lifetime is
            // unchanged: `is_mapped` still reports the reservation, exactly
            // like `addrspace::is_user_mapped` in production.
            self.noaccess.push((virt, len));
            let mut offset = 0;
            while offset < len {
                self.pages.remove(&(virt + offset));
                offset += PAGE_SIZE;
            }
            Ok(())
        }

        fn is_mapped(&self, virt: u64) -> bool {
            self.mapped.contains_key(&virt)
        }
    }

    fn image_end() -> u64 {
        0x0060_0000
    }

    fn memory_with_image() -> LinuxMemory {
        let mut memory = LinuxMemory::new();
        memory.set_initial_break(image_end());
        memory
    }

    fn anonymous_args(len: u64, prot: u32) -> [u64; 6] {
        [
            0,
            len,
            u64::from(prot),
            MAP_PRIVATE | MAP_ANONYMOUS,
            u64::MAX,
            0,
        ]
    }

    #[test]
    fn the_break_is_initially_unknown_and_brk_never_guesses() {
        let mut memory = LinuxMemory::new();
        let mut space = FakeSpace::default();
        assert_eq!(memory.program_break(), None);
        assert_eq!(
            syscall_brk(&mut memory, 0, Some(&mut space)),
            Ok(0),
            "brk(0) reports the current (unknown) break"
        );
        assert_eq!(
            syscall_brk(&mut memory, image_end(), Some(&mut space)),
            Ok(0),
            "an uninitialised break cannot grow"
        );
        assert_eq!(memory.program_break(), None);
        assert!(space.pages.is_empty());
    }

    #[test]
    fn brk_grows_and_shrinks_through_the_address_space() {
        let mut memory = memory_with_image();
        let mut space = FakeSpace::default();
        let grown = image_end() + 3 * PAGE_SIZE;
        assert_eq!(
            syscall_brk(&mut memory, grown, Some(&mut space)),
            Ok(grown as i64)
        );
        assert_eq!(memory.program_break(), Some(grown));
        assert_eq!(space.pages.len(), 3);
        assert!(space.pages.values().all(|(w, x)| *w && !*x));

        // Repeating the same break maps nothing new.
        assert_eq!(
            syscall_brk(&mut memory, grown, Some(&mut space)),
            Ok(grown as i64)
        );
        assert_eq!(space.pages.len(), 3);

        assert_eq!(
            syscall_brk(&mut memory, image_end(), Some(&mut space)),
            Ok(image_end() as i64)
        );
        assert_eq!(memory.program_break(), Some(image_end()));
        assert!(space.pages.is_empty());
    }

    #[test]
    fn brk_failure_reports_the_old_break_as_a_value() {
        let mut memory = memory_with_image();
        let mut space = FakeSpace::default();
        let old = memory.program_break().unwrap();
        assert_eq!(
            syscall_brk(&mut memory, old - PAGE_SIZE, Some(&mut space)),
            Ok(old as i64),
            "below the image end fails with the old break"
        );
        assert_eq!(
            syscall_brk(&mut memory, BRK_LIMIT + PAGE_SIZE, Some(&mut space)),
            Ok(old as i64),
            "above the window fails with the old break"
        );
        assert_eq!(
            syscall_brk(&mut memory, old + 9 * PAGE_SIZE, None),
            Ok(old as i64),
            "no address space cannot grow"
        );
        assert_eq!(memory.program_break(), Some(old));
        assert!(space.pages.is_empty());
    }

    #[test]
    fn dynamic_images_get_a_break_window_above_the_legacy_limit() {
        // M10a: a dynamically loaded image ends above the legacy window (for
        // the generic program loader the image ends near 0x020C_6000), so its
        // brk must use the higher dynamic ceiling; otherwise musl's malloc
        // could never grow its heap.
        let mut memory = LinuxMemory::new();
        let start = 0x020C_6000;
        memory.set_initial_break(start);
        assert_eq!(memory.program_break(), Some(start));

        let grown = start + 3 * PAGE_SIZE;
        assert_eq!(
            brk_plan(&memory, grown),
            Some(BrkPlan {
                new_break: grown,
                grow: Some((start, 3 * PAGE_SIZE)),
                shrink: None,
            })
        );

        let mut space = FakeSpace::default();
        assert_eq!(
            syscall_brk(&mut memory, grown, Some(&mut space)),
            Ok(grown as i64)
        );
        assert_eq!(memory.program_break(), Some(grown));
        assert_eq!(space.pages.len(), 3);
        assert!(space.pages.keys().all(|virt| *virt >= start));
        assert!(space.pages.keys().all(|virt| *virt < DYNAMIC_BRK_LIMIT));
    }

    #[test]
    fn the_dynamic_break_window_stops_below_the_interpreter() {
        // The M10a window must stay below the interpreter bias so the break can
        // never run into the mapped interpreter, and above the legacy window so
        // a real musl heap remains reachable.
        assert_eq!(DYNAMIC_BRK_LIMIT % PAGE_SIZE, 0);
        assert!(DYNAMIC_BRK_LIMIT > BRK_LIMIT);
        assert!(
            DYNAMIC_BRK_LIMIT < crate::image::PROGRAM_INTERPRETER_BIAS,
            "the dynamic break window must stay below the interpreter"
        );

        let mut memory = LinuxMemory::new();
        let start = 0x020C_6000;
        memory.set_initial_break(start);
        // The ceiling itself is reachable and page aligned.
        assert!(brk_plan(&memory, DYNAMIC_BRK_LIMIT).is_some());
        // One page past it is refused and keeps the old break.
        assert_eq!(brk_plan(&memory, DYNAMIC_BRK_LIMIT + PAGE_SIZE), None);
        let mut space = FakeSpace::default();
        assert_eq!(
            syscall_brk(&mut memory, DYNAMIC_BRK_LIMIT + PAGE_SIZE, Some(&mut space)),
            Ok(start as i64)
        );
        assert_eq!(memory.program_break(), Some(start));
        assert!(space.pages.is_empty());
    }

    #[test]
    fn the_legacy_break_window_is_unchanged_for_low_images() {
        let memory = memory_with_image();
        assert!(brk_plan(&memory, BRK_LIMIT).is_some());
        assert_eq!(brk_plan(&memory, BRK_LIMIT + PAGE_SIZE), None);
        // A low image cannot jump over the legacy guard: that guard defines its
        // window, and the dynamic ceiling only applies above it.
        assert_eq!(brk_plan(&memory, DYNAMIC_BRK_LIMIT), None);
    }

    #[test]
    fn a_failed_brk_mapping_rolls_back_and_keeps_the_old_break() {
        let mut memory = memory_with_image();
        let mut space = FakeSpace {
            fail_map_at: Some(image_end() + 2 * PAGE_SIZE),
            ..FakeSpace::default()
        };
        let old = memory.program_break().unwrap();
        assert_eq!(
            syscall_brk(&mut memory, old + 3 * PAGE_SIZE, Some(&mut space)),
            Ok(old as i64)
        );
        assert_eq!(memory.program_break(), Some(old));
        assert!(
            space.pages.is_empty(),
            "the two pages mapped before the failure are rolled back"
        );
    }

    #[test]
    fn anonymous_frames_come_from_the_frame_source_cleared() {
        let Some(phys) = frames::alloc() else {
            panic!("the host frame arena has room");
        };
        // The host arena allocates zeroed pages, mirroring a fresh PMM frame.
        assert!(frames::is_zeroed(phys));
        // Dirtying then zero-filling proves the fill path clears the page.
        // SAFETY: `phys` is one of the host arena's own page-sized allocations.
        unsafe { core::ptr::write_bytes(phys as *mut u8, 0xAA, PAGE_SIZE as usize) };
        assert!(!frames::is_zeroed(phys));
        frames::zero(phys);
        assert!(frames::is_zeroed(phys));
        frames::dealloc(phys);
    }

    #[test]
    fn mmap_allocates_inside_the_bump_window_and_zeroes_its_frames() {
        let mut memory = memory_with_image();
        let mut space = FakeSpace::default();
        let first = syscall_mmap(
            &mut memory,
            &anonymous_args(PAGE_SIZE + 1, PROT_READ | PROT_WRITE),
            Some(&mut space),
        );
        assert_eq!(first, Ok(MMAP_BASE as i64));
        assert_eq!(space.pages.len(), 2);
        assert!(space.pages.values().all(|(w, x)| *w && !*x));
        assert_eq!(memory.mmap_next(), MMAP_BASE + 2 * PAGE_SIZE);

        let second = syscall_mmap(
            &mut memory,
            &anonymous_args(PAGE_SIZE, PROT_READ),
            Some(&mut space),
        );
        assert_eq!(second, Ok((MMAP_BASE + 2 * PAGE_SIZE) as i64));
        let second_addr = MMAP_BASE + 2 * PAGE_SIZE;
        assert_eq!(space.pages.get(&second_addr), Some(&(false, false)));
    }

    #[test]
    fn mmap_rejects_unsupported_flags_and_protections() {
        let memory = memory_with_image();
        let cases: &[(&[u64; 6], i64)] = &[
            (
                &[0, 0, 3, MAP_PRIVATE | MAP_ANONYMOUS, u64::MAX, 0],
                errno::EINVAL,
            ),
            (
                &[
                    0,
                    1,
                    u64::from(PROT_READ | PROT_WRITE | PROT_EXEC),
                    MAP_PRIVATE | MAP_ANONYMOUS,
                    u64::MAX,
                    0,
                ],
                errno::EINVAL,
            ),
            (
                &[0, 1, 0x80, MAP_PRIVATE | MAP_ANONYMOUS, u64::MAX, 0],
                errno::EINVAL,
            ),
            (
                &[
                    0,
                    1,
                    3,
                    MAP_FIXED | MAP_PRIVATE | MAP_ANONYMOUS,
                    u64::MAX,
                    0,
                ],
                errno::EINVAL,
            ),
            (
                &[0, 1, 3, MAP_SHARED | MAP_ANONYMOUS, u64::MAX, 0],
                errno::EOPNOTSUPP,
            ),
            (&[0, 1, 3, MAP_ANONYMOUS, u64::MAX, 0], errno::EINVAL),
            (&[0, 1, 3, MAP_PRIVATE, u64::MAX, 0], errno::EBADF),
            (&[0, 1, 3, MAP_PRIVATE, 3, 0], errno::EOPNOTSUPP),
            (&[0, 1, 3, MAP_ANONYMOUS, 4, 0], errno::EINVAL),
            (
                &[
                    0,
                    1,
                    3,
                    MAP_PRIVATE | MAP_ANONYMOUS,
                    u64::MAX,
                    u64::from(PAGE_SIZE),
                ],
                errno::EINVAL,
            ),
        ];
        for (args, expected) in cases {
            let mut memory = memory;
            let mut no_space: Option<&mut dyn AddressSpaceOps> = None;
            assert_eq!(
                mmap_plan(&memory, args[1], args[2] as u32, args[3], args[4], args[5]),
                Err(*expected)
            );
            assert_eq!(
                syscall_mmap(&mut memory, args, no_space.as_deref_mut()),
                Err(*expected)
            );
        }
    }

    #[test]
    fn anonymous_prot_none_reserves_real_frames_that_mprotect_can_recover() {
        let mut memory = memory_with_image();
        let mut space = FakeSpace::default();
        let base = memory.mmap_next();
        let len = 2 * PAGE_SIZE;
        let args = [0, len, 0, MAP_PRIVATE | MAP_ANONYMOUS, u64::MAX, 0];
        assert_eq!(
            syscall_mmap(&mut memory, &args, Some(&mut space)),
            Ok(base as i64)
        );
        // The bump moved and the reservation is backed by real frames whose
        // presentation was withdrawn: this is the VMA-style reservation musl's
        // `reclaim_gaps` relies on. Frame savings are explicitly not claimed.
        assert_eq!(memory.mmap_next(), base + len);
        assert_eq!(space.mapped.len(), 2, "frames are mapped, not lazy");
        assert!(space.pages.is_empty(), "presentation withdrawn");
        assert_eq!(space.noaccess.last(), Some(&(base, len)));

        // `mprotect(RW)` restores present writable pages. This is exactly the
        // path that used to fail with ENOMEM when the reservation was lazy.
        assert_eq!(
            syscall_mprotect(base, len, (PROT_READ | PROT_WRITE) as u64, Some(&mut space)),
            Ok(0)
        );
        assert_eq!(space.pages.get(&base), Some(&(true, false)));
        assert_eq!(space.pages.get(&(base + PAGE_SIZE)), Some(&(true, false)));

        // `munmap` releases the reserved frames; it is not a no-op anymore.
        assert_eq!(syscall_munmap(base, len, Some(&mut space)), Ok(0));
        assert!(space.mapped.is_empty());
        assert!(space.pages.is_empty());

        // A following mapping starts after the reservation: they never overlap.
        let plan = mmap_plan(
            &memory,
            PAGE_SIZE,
            3,
            MAP_PRIVATE | MAP_ANONYMOUS,
            u64::MAX,
            0,
        )
        .expect("map after reservation");
        assert_eq!(plan.addr, base + len);
        assert!(!plan.reserve);
    }

    #[test]
    fn two_reservations_keep_their_windows_disjoint() {
        let mut memory = memory_with_image();
        let mut space = FakeSpace::default();
        let base = memory.mmap_next();
        assert_eq!(
            syscall_mmap(
                &mut memory,
                &[0, 0x2000, 0, MAP_PRIVATE | MAP_ANONYMOUS, u64::MAX, 0],
                Some(&mut space)
            ),
            Ok(base as i64)
        );
        assert_eq!(
            syscall_mmap(
                &mut memory,
                &[0, 0x1000, 0, MAP_PRIVATE | MAP_ANONYMOUS, u64::MAX, 0],
                Some(&mut space)
            ),
            Ok((base + 0x2000) as i64)
        );
        assert_eq!(space.mapped.len(), 3);
        assert!(space.pages.is_empty());
    }

    #[test]
    fn fixed_prot_none_reservation_validates_and_can_be_covered() {
        let mut memory = memory_with_image();
        let mut space = FakeSpace::default();
        let bump = memory.mmap_next();
        let addr = MMAP_BASE + 0x4000;
        // The fixed reservation is built through the syscall path: real frames
        // at the caller-chosen address, presentation withdrawn.
        assert_eq!(
            syscall_mmap(
                &mut memory,
                &[
                    addr,
                    0x2000,
                    0,
                    MAP_FIXED | MAP_PRIVATE | MAP_ANONYMOUS,
                    u64::MAX,
                    0
                ],
                Some(&mut space)
            ),
            Ok(addr as i64)
        );
        assert_eq!(memory.mmap_next(), bump, "fixed reservation keeps the bump");
        assert_eq!(space.mapped.len(), 2, "reservation frames exist");
        assert!(space.pages.is_empty(), "presentation withdrawn");

        // `mprotect` recovers the reservation (musl's fallback path)...
        assert_eq!(
            syscall_mprotect(
                addr,
                0x2000,
                (PROT_READ | PROT_WRITE) as u64,
                Some(&mut space)
            ),
            Ok(0)
        );
        assert_eq!(space.pages.get(&addr), Some(&(true, false)));

        // ...and a later `MAP_FIXED` file mapping covers it. The old reservation
        // frames are released (the mapping is replaced, not leaked).
        let plan = mmap_file_plan(
            &memory,
            addr,
            0x2000,
            PROT_READ,
            MAP_FIXED | MAP_PRIVATE,
            3,
            0,
        )
        .expect("cover reservation");
        assert_eq!(plan.addr, addr);
        assert!(!plan.reserve);
        let mut filled_pages = 0u32;
        map_file_pages(
            &mut space,
            plan.addr,
            plan.len,
            plan.writable,
            plan.executable,
            |_, page| {
                filled_pages += 1;
                page.fill(b'F');
                Ok(())
            },
        )
        .expect("file mapping covers the reservation");
        assert_eq!(filled_pages, 2);
        assert_eq!(space.mapped.len(), 2, "replaced, not leaked");
        assert_eq!(space.pages.get(&addr), Some(&(false, false)));
        assert_eq!(space.pages.get(&(addr + PAGE_SIZE)), Some(&(false, false)));

        // Misaligned or out-of-window fixed reservations are rejected.
        assert_eq!(mmap_reserve_fixed(addr + 1, PAGE_SIZE), Err(errno::EINVAL));
        assert_eq!(
            mmap_reserve_fixed(MMAP_LIMIT - PAGE_SIZE, PAGE_SIZE * 2),
            Err(errno::ENOMEM)
        );
    }

    #[test]
    fn mmap_window_exhaustion_reports_enomem() {
        let mut memory = memory_with_image();
        memory.mmap_next = MMAP_LIMIT - PAGE_SIZE;
        let mut space = FakeSpace::default();
        assert_eq!(
            syscall_mmap(
                &mut memory,
                &anonymous_args(3 * PAGE_SIZE, PROT_READ),
                Some(&mut space)
            ),
            Err(errno::ENOMEM)
        );
        assert!(space.pages.is_empty());
        assert_eq!(memory.mmap_next(), MMAP_LIMIT - PAGE_SIZE);
    }

    #[test]
    fn munmap_drops_mapped_pages_and_ignores_unmapped_ones() {
        let mut memory = memory_with_image();
        let mut space = FakeSpace::default();
        let addr = syscall_mmap(
            &mut memory,
            &anonymous_args(2 * PAGE_SIZE, PROT_READ | PROT_WRITE),
            Some(&mut space),
        )
        .unwrap() as u64;
        assert_eq!(syscall_munmap(addr, PAGE_SIZE, Some(&mut space)), Ok(0));
        assert_eq!(space.pages.len(), 1);
        assert_eq!(
            syscall_munmap(addr + PAGE_SIZE, PAGE_SIZE, Some(&mut space)),
            Ok(0)
        );
        assert!(space.pages.is_empty());
        // Unmapped ranges are a success, exactly like Linux.
        assert_eq!(
            syscall_munmap(MMAP_BASE, 4 * PAGE_SIZE, Some(&mut space)),
            Ok(0)
        );
        assert_eq!(
            syscall_munmap(addr + 1, PAGE_SIZE, Some(&mut space)),
            Err(errno::EINVAL),
            "unaligned address"
        );
        assert_eq!(
            syscall_munmap(addr, 0, Some(&mut space)),
            Err(errno::EINVAL)
        );
    }

    #[test]
    fn mprotect_changes_permissions_and_requires_mapped_pages() {
        let mut memory = memory_with_image();
        let mut space = FakeSpace::default();
        let addr = syscall_mmap(
            &mut memory,
            &anonymous_args(2 * PAGE_SIZE, PROT_READ | PROT_WRITE),
            Some(&mut space),
        )
        .unwrap() as u64;

        assert_eq!(
            syscall_mprotect(addr, PAGE_SIZE, PROT_READ as u64, Some(&mut space)),
            Ok(0)
        );
        assert_eq!(space.pages.get(&addr), Some(&(false, false)));
        assert_eq!(
            space.protects.last(),
            Some(&(addr, PAGE_SIZE, false, false))
        );

        // PROT_NONE is accepted and withdraws presentation instead of taking
        // the ordinary read/write rewrite path (which would leave it readable).
        assert_eq!(
            syscall_mprotect(addr, 2 * PAGE_SIZE, 0, Some(&mut space)),
            Ok(0)
        );
        assert_eq!(space.noaccess.last(), Some(&(addr, 2 * PAGE_SIZE)));
        assert_eq!(space.pages.get(&addr), None);
        assert_eq!(space.pages.get(&(addr + PAGE_SIZE)), None);

        assert_eq!(
            syscall_mprotect(addr + 1, PAGE_SIZE, PROT_READ as u64, Some(&mut space)),
            Err(errno::EINVAL),
            "unaligned address"
        );
        assert_eq!(
            syscall_mprotect(
                addr + 4 * PAGE_SIZE,
                PAGE_SIZE,
                PROT_READ as u64,
                Some(&mut space)
            ),
            Err(errno::ENOMEM),
            "unmapped page"
        );
        assert_eq!(
            syscall_mprotect(
                addr,
                PAGE_SIZE,
                PROT_READ as u64 | PROT_EXEC as u64 | PROT_WRITE as u64,
                Some(&mut space)
            ),
            Err(errno::EINVAL),
            "W^X"
        );
    }

    #[test]
    fn mprotect_accepts_a_zero_length_range_only_at_an_aligned_address() {
        let mut memory = memory_with_image();
        let mut space = FakeSpace::default();
        let addr = syscall_mmap(
            &mut memory,
            &anonymous_args(PAGE_SIZE, PROT_READ | PROT_WRITE),
            Some(&mut space),
        )
        .unwrap() as u64;

        // Linux validates `prot` and the address alignment, then does nothing.
        assert_eq!(
            syscall_mprotect(addr, 0, PROT_READ as u64, Some(&mut space)),
            Ok(0)
        );
        assert_eq!(
            syscall_mprotect(addr, 0, 0, Some(&mut space)),
            Ok(0),
            "PROT_NONE is valid with an empty range"
        );
        assert!(space.protects.is_empty(), "an empty range changes nothing");
        assert_eq!(
            syscall_mprotect(addr + 1, 0, PROT_READ as u64, Some(&mut space)),
            Err(errno::EINVAL),
            "the address must still be page aligned"
        );
        // `munmap` keeps the opposite contract: an empty range is EINVAL.
        assert_eq!(
            syscall_munmap(addr, 0, Some(&mut space)),
            Err(errno::EINVAL)
        );
    }

    #[test]
    fn a_read_only_mapping_is_recorded_without_write_permission() {
        // The real enforcement lives in `mm::addrspace` (PTE_WRITE), which the
        // fake cannot duplicate; recording the permission is the contract the
        // production driver feeds into `map_user`.
        let mut memory = memory_with_image();
        let mut space = FakeSpace::default();
        let addr = syscall_mmap(
            &mut memory,
            &anonymous_args(PAGE_SIZE, PROT_READ),
            Some(&mut space),
        )
        .unwrap() as u64;
        assert_eq!(space.pages.get(&addr), Some(&(false, false)));
    }

    #[test]
    fn executable_but_not_writable_protection_is_supported() {
        let mut memory = memory_with_image();
        let mut space = FakeSpace::default();
        assert_eq!(
            syscall_mmap(
                &mut memory,
                &anonymous_args(PAGE_SIZE, PROT_READ | PROT_EXEC),
                Some(&mut space)
            ),
            Ok(MMAP_BASE as i64)
        );
        assert_eq!(space.pages.get(&MMAP_BASE), Some(&(false, true)));
    }

    #[test]
    fn only_a_zero_prot_requests_the_no_access_transition() {
        // The classifier must look at the full `prot`: `PROT_READ` is also
        // "not writable and not executable", yet it must keep the page present.
        assert!(requires_no_access(0), "PROT_NONE withdraws presentation");
        assert!(!requires_no_access(PROT_READ as u32));
        assert!(!requires_no_access(PROT_WRITE as u32));
        assert!(!requires_no_access((PROT_READ | PROT_WRITE) as u32));
        assert!(!requires_no_access(PROT_EXEC as u32));
    }

    #[test]
    fn prot_read_keeps_the_page_present_and_only_prot_none_withdraws_it() {
        let mut memory = memory_with_image();
        let mut space = FakeSpace::default();
        let addr = syscall_mmap(
            &mut memory,
            &anonymous_args(2 * PAGE_SIZE, PROT_READ | PROT_WRITE),
            Some(&mut space),
        )
        .unwrap() as u64;

        // `mprotect(PROT_READ)` is an ordinary leaf rewrite: the page stays
        // present (and readable), only the write bit is cleared. This is the
        // regression for the user #PF on the first read after mprotect.
        assert_eq!(
            syscall_mprotect(addr, PAGE_SIZE, PROT_READ as u64, Some(&mut space)),
            Ok(0)
        );
        assert_eq!(space.pages.get(&addr), Some(&(false, false)));
        assert_eq!(
            space.protects.last(),
            Some(&(addr, PAGE_SIZE, false, false))
        );
        assert!(
            space.noaccess.is_empty(),
            "PROT_READ must not withdraw access"
        );

        // Only `PROT_NONE` takes the presence-withdrawing transition.
        assert_eq!(
            syscall_mprotect(addr, PAGE_SIZE, 0, Some(&mut space)),
            Ok(0)
        );
        assert_eq!(space.noaccess.last(), Some(&(addr, PAGE_SIZE)));
        assert_eq!(space.pages.get(&addr), None);
    }
}
