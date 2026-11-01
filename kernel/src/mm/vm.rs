//! Higher-half VM takeover (M2).
//!
//! The kernel builds its own bootstrap page tables in `.bss` and switches away
//! from the loader's initial tables:
//!
//! - Kernel image mapped at its link address from `kernel.ld` section symbols,
//!   W^X: `.text` R+X, `.rodata` R (NX), `.data`/`.bss` R+W (NX).
//! - Direct map of all conventional RAM at [`DIRECT_MAP_BASE`], 2 MiB large
//!   pages with 4 KiB fallback for non-2MiB-aligned region edges.
//! - A fresh kernel stack allocated by the PMM, mapped with a not-present
//!   guard page below it.
//!
//! The switch itself is one `asm!` sequence — `cli`, `mov cr3`, `mov rsp` —
//! with no intervening memory access; execution continues in `cont` on the
//! new stack (agents.md M2 decision). Everything the post-switch code touches
//! (kernel sections, PMM/heap statics, direct map) is mapped by these tables.
//!
//! `build` is generic over the kernel section bounds so it is host-testable;
//! only `build_kernel_tables` (which reads the linker symbols) is
//! `cfg(not(test))`.
//!
//! After the switch the kernel keeps growing its own mappings (M3): [`map_physical`]
//! adds ACPI table (read-only) and MMIO (uncached, `PWT|PCD`) windows and the
//! per-thread stacks, using the [`PtCursor`] persisted by `build_kernel_tables`
//! so those mappings reuse the PTs built at takeover time.

use crate::boot::{SavedImage, SavedMap};
use crate::mm::pmm::{FRAME_SIZE, MAX_ALLOC_ADDR};

pub const DIRECT_MAP_BASE: u64 = 0xFFFF_8000_0000_0000;
/// Fresh kernel stack virtual base (inside the kernel PDPT window, far from
/// the image). The page at `KERNEL_STACK_VIRT - 0x1000` is the guard.
pub const KERNEL_STACK_VIRT: u64 = 0xFFFF_FFFF_8100_0000;
pub const KERNEL_STACK_FRAMES: usize = 4; // 16 KiB

pub const LARGE_PAGE_SIZE: u64 = 2 * 1024 * 1024;

pub const PTE_PRESENT: u64 = 1 << 0;
pub const PTE_WRITE: u64 = 1 << 1;
/// User-accessible (CPL 3) mapping. The kernel tables built here never set it;
/// per-process user address spaces (`mm::addrspace`) do, and the copy helpers
/// there re-check it before touching a leaf (agents.md §7.2).
pub const PTE_USER: u64 = 1 << 2;
/// Page-level write-through. Set for MMIO/uncached mappings (M3: local APIC,
/// IOAPIC); meaningful only together with [`PTE_PCD`] for strong UC.
pub const PTE_PWT: u64 = 1 << 3;
/// Page-level cache disable (PCD). Set for MMIO mappings so reads reach the
/// device instead of a cache line.
pub const PTE_PCD: u64 = 1 << 4;
/// `PS` in a PD/PDPT entry (2 MiB / 1 GiB leaf). In a 4 KiB PT entry bit 7 is
/// `PAT`, so [`map_physical`] masks this bit out of caller flags.
pub const PTE_PS: u64 = 1 << 7;
pub const PTE_NX: u64 = 1 << 63;
pub const ADDR_MASK: u64 = 0x000F_FFFF_FFFF_F000;

const DIRECT_PDPT_SLOT: usize = 0; // DIRECT_MAP_BASE sits in PDPT slot 0
// Generous pool: every non-2MiB-aligned edge of every conventional region
// needs one PT (shared within the same 2 MiB window); OVMF memory maps can be
// fragmented, so keep ample headroom.
const N_DIRECT_PTS: usize = 96;
/// Kernel-window page tables, one per 2 MiB PD slot. M2 needs two (kernel
/// image at PD slot 0, kernel stack @ [`KERNEL_STACK_VIRT`]); M3 adds an ACPI
/// table window (read-only), local APIC + IOAPIC (uncached) and two per-thread
/// stacks. The pool is sized at 40 slots: 32 matched the M3/M4 budget
/// (`platform` owns the ACPI/MMIO window at `0xFFFF_FFFF_8200_0000`), and M6b1
/// adds the per-CPU AP stacks at [`AP_STACK_BASE`] plus headroom for the SMP
/// scheduler's own stacks (each 2 MiB PD slot costs one slot only when the
/// first page in it is mapped).
const N_KERN_PTS: usize = 40;

/// Highest physical address a SIPI can target. The startup IPI carries an 8-bit
/// page number, so the AP bring-up trampoline page must live below 1 MiB.
///
/// This is an architectural bound, not a memory layout: *which* page below it
/// gets used comes from the saved boot memory map
/// (`pmm::reserve_low_page`), never from a hard-coded address.
pub const SIPI_MAX_PHYS: u64 = 0x10_0000;

/// Bits a hardware page walk may set by itself (accessed/dirty) plus the
/// address: everything a table-link/leaf comparison must look at.
///
/// The CPU sets A on every level it traverses and D on a written leaf, so
/// comparing a link against its expected value without this mask makes a valid
/// live mapping look foreign (that bug showed up as a phantom `NotFound` during
/// AP teardown, where `pml4[0]` came back with bit 5 set).
const ENTRY_MASK: u64 = ADDR_MASK | PTE_PRESENT | PTE_WRITE;

/// Two entries describe the same link, ignoring hardware-owned A/D bits.
#[inline]
const fn entry_matches(entry: u64, link: u64) -> bool {
    entry & ENTRY_MASK == link & ENTRY_MASK
}

/// Base of the per-CPU AP kernel stacks inside the kernel's 1 GiB window (PD
/// slot 12). Sits above the boot stack ([`KERNEL_STACK_VIRT`], PD slot 8), the
/// M3 scheduler stacks (`0xFFFF_FFFF_8130_0000`/`.._8140_0000`, PD slots 9/10)
/// and the per-process kernel stacks (`0xFFFF_FFFF_8150_0000`/`.._8160_0000`,
/// PD slots 10/11), and below `platform`'s ACPI/MMIO window at
/// `0xFFFF_FFFF_8200_0000` (PD slot 16).
///
/// Four stacks of 64 KiB stride all share one 2 MiB PD slot, so the whole AP
/// stack pool costs exactly one page table.
pub const AP_STACK_BASE: u64 = 0xFFFF_FFFF_8180_0000;
/// Distance between two AP stack slots (guard page + 4 frames + padding).
pub const AP_STACK_STRIDE: u64 = 0x1_0000;
/// Frames per AP stack (16 KiB), matching [`KERNEL_STACK_FRAMES`].
pub const AP_STACK_FRAMES: usize = 4;
/// Number of AP stack slots. Matches `platform::acpi::MAX_CPUS - 1`; `mm` does
/// not depend on `platform`, so the value is stated here and cross-checked by a
/// host test.
pub const MAX_AP_STACKS: usize = 4;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VmError {
    /// Static page-table pool exhausted.
    OutOfTables,
    /// Overlapping mapping attempt.
    Overlap,
    /// A PD entry references a page table this build pass never allocated.
    NotFound,
    BadAddress,
    /// The kernel's own page tables are not the active ones yet: the takeover
    /// (or at least `build_kernel_tables`) has not run.
    NotReady,
}

#[derive(Clone, Copy)]
#[repr(C, align(4096))]
pub struct PageTable {
    pub entries: [u64; 512],
}

impl PageTable {
    pub const fn new() -> Self {
        PageTable { entries: [0; 512] }
    }
    pub fn clear(&mut self) {
        self.entries = [0; 512];
    }
}

pub struct BootTables {
    pub pml4: PageTable,
    pub direct_pdpt: PageTable,
    pub direct_pd: PageTable,
    pub direct_pts: [PageTable; N_DIRECT_PTS],
    pub kern_pdpt: PageTable,
    pub kern_pd: PageTable,
    pub kern_pts: [PageTable; N_KERN_PTS],
}

impl BootTables {
    pub const fn new() -> Self {
        BootTables {
            pml4: PageTable::new(),
            direct_pdpt: PageTable::new(),
            direct_pd: PageTable::new(),
            direct_pts: [PageTable::new(); N_DIRECT_PTS],
            kern_pdpt: PageTable::new(),
            kern_pd: PageTable::new(),
            kern_pts: [PageTable::new(); N_KERN_PTS],
        }
    }
    pub fn clear(&mut self) {
        self.pml4.clear();
        self.direct_pdpt.clear();
        self.direct_pd.clear();
        for t in self.direct_pts.iter_mut() {
            t.clear();
        }
        self.kern_pdpt.clear();
        self.kern_pd.clear();
        for t in self.kern_pts.iter_mut() {
            t.clear();
        }
    }
}

/// Kernel instance (physical frames are computed from the KERNEL_IMAGE TLV).
pub static mut TABLES: BootTables = BootTables::new();

/// Allocator for the static page-table pools. Every page table handed out in
/// a build pass is registered with its (physical, virtual) pair so that
/// later 4 KiB mappings in the same 2 MiB window can find the table again by
/// the physical address stored in its PD entry — without deriving virtual
/// addresses from the kernel-image placement formula (which would not be
/// meaningful for host-test buffers).
pub struct PtCursor {
    next_direct: usize,
    next_kern: usize,
    direct_phys: [u64; N_DIRECT_PTS],
    direct_virt: [*mut PageTable; N_DIRECT_PTS],
    kern_phys: [u64; N_KERN_PTS],
    kern_virt: [*mut PageTable; N_KERN_PTS],
}

impl PtCursor {
    /// `const` so the persisted takeover cursor can live in a `static`.
    pub const fn new() -> Self {
        PtCursor {
            next_direct: 0,
            next_kern: 0,
            direct_phys: [0; N_DIRECT_PTS],
            direct_virt: [core::ptr::null_mut(); N_DIRECT_PTS],
            kern_phys: [0; N_KERN_PTS],
            kern_virt: [core::ptr::null_mut(); N_KERN_PTS],
        }
    }

    pub unsafe fn take_direct(
        &mut self,
        t: *mut BootTables,
        image: &SavedImage,
    ) -> Result<*mut PageTable, VmError> {
        if self.next_direct >= N_DIRECT_PTS {
            return Err(VmError::OutOfTables);
        }
        unsafe {
            let pt = core::ptr::addr_of_mut!((*t).direct_pts[self.next_direct]);
            (*pt).clear();
            let phys = phys_of(pt as u64, image);
            let i = self.next_direct;
            self.direct_phys[i] = phys;
            self.direct_virt[i] = pt;
            self.next_direct += 1;
            Ok(pt)
        }
    }

    pub unsafe fn take_kern(
        &mut self,
        t: *mut BootTables,
        image: &SavedImage,
    ) -> Result<*mut PageTable, VmError> {
        if self.next_kern >= N_KERN_PTS {
            return Err(VmError::OutOfTables);
        }
        unsafe {
            let pt = core::ptr::addr_of_mut!((*t).kern_pts[self.next_kern]);
            (*pt).clear();
            let phys = phys_of(pt as u64, image);
            let i = self.next_kern;
            self.kern_phys[i] = phys;
            self.kern_virt[i] = pt;
            self.next_kern += 1;
            Ok(pt)
        }
    }

    /// Find a page table previously handed out in this build pass by the
    /// physical address stored in a PD entry.
    pub fn lookup(&self, phys: u64) -> Result<*mut PageTable, VmError> {
        for i in 0..self.next_direct {
            if self.direct_phys[i] == phys {
                return Ok(self.direct_virt[i]);
            }
        }
        for i in 0..self.next_kern {
            if self.kern_phys[i] == phys {
                return Ok(self.kern_virt[i]);
            }
        }
        Err(VmError::NotFound)
    }
}

// ---------------------------------------------------------------------------
// Pure helpers (host-testable)
// ---------------------------------------------------------------------------

pub const fn pml4_index(v: u64) -> usize {
    ((v >> 39) & 0x1FF) as usize
}
pub const fn pdpt_index(v: u64) -> usize {
    ((v >> 30) & 0x1FF) as usize
}
pub const fn pd_index(v: u64) -> usize {
    ((v >> 21) & 0x1FF) as usize
}
pub const fn pt_index(v: u64) -> usize {
    ((v >> 12) & 0x1FF) as usize
}

/// Direct-map translation for allocatable (<= 1 GiB) physical addresses.
pub const fn phys_to_virt(phys: u64) -> u64 {
    DIRECT_MAP_BASE + phys
}

/// Physical address of a kernel static/link address (kernel image is a
/// contiguous physical allocation covering the whole link range).
pub fn phys_of(virt: u64, image: &SavedImage) -> u64 {
    image.phys_base + (virt - image.virt_base)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SplitRegion {
    /// (base, len) 4 KiB head before the 2 MiB-aligned body.
    pub head: (u64, u64),
    /// 2 MiB-aligned (base, len) mapped with large pages.
    pub body: (u64, u64),
    /// (base, len) 4 KiB tail after the body.
    pub tail: (u64, u64),
}

/// Split `[base, base + len)` into a 2 MiB-aligned body plus 4 KiB edges.
pub fn split_large_region(base: u64, len: u64) -> SplitRegion {
    let end = base + len;
    let body_start = base.div_ceil(LARGE_PAGE_SIZE) * LARGE_PAGE_SIZE;
    let body_end = end & !(LARGE_PAGE_SIZE - 1);
    if body_end > body_start {
        SplitRegion {
            head: (base, body_start - base),
            body: (body_start, body_end - body_start),
            tail: (body_end, end - body_end),
        }
    } else {
        SplitRegion {
            head: (base, len),
            body: (base, 0),
            tail: (end, 0),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Domain {
    /// Direct map: PML4[256] → direct_pdpt → direct_pd (1 GiB window).
    Direct,
    /// Kernel window: PML4[511] → kern_pdpt → kern_pd (per-2MiB PTs).
    Kernel,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct VmSummary {
    pub pml4_phys: u64,
    pub bytes_direct_2m: u64,
    pub pages_direct_4k: u64,
    pub kernel_pages: u64,
    pub stack_pages: u64,
}

// ---------------------------------------------------------------------------
// Mapping primitives (host-testable; never dereference `phys` addresses)
// ---------------------------------------------------------------------------

unsafe fn pd_for<'a>(t: *mut BootTables, domain: Domain) -> &'a mut PageTable {
    unsafe {
        match domain {
            Domain::Direct => &mut (*t).direct_pd,
            Domain::Kernel => &mut (*t).kern_pd,
        }
    }
}

pub unsafe fn map_4k(
    t: *mut BootTables,
    cursor: &mut PtCursor,
    image: &SavedImage,
    domain: Domain,
    virt: u64,
    phys: u64,
    flags: u64,
) -> Result<(), VmError> {
    unsafe {
        let pd = pd_for(t, domain);
        let idx = pd_index(virt);
        let entry = pd.entries[idx];
        let pt: *mut PageTable = if entry & PTE_PRESENT != 0 {
            cursor.lookup(entry & ADDR_MASK)?
        } else {
            let pt = match domain {
                Domain::Direct => cursor.take_direct(t, image)?,
                Domain::Kernel => cursor.take_kern(t, image)?,
            };
            pd.entries[idx] = phys_of(pt as u64, image) | PTE_PRESENT | PTE_WRITE;
            pt
        };
        let leaf = &mut (*pt).entries[pt_index(virt)];
        if *leaf & PTE_PRESENT != 0 {
            return Err(VmError::Overlap);
        }
        *leaf = (phys & ADDR_MASK) | flags;
        Ok(())
    }
}

pub unsafe fn map_2m(
    t: *mut BootTables,
    domain: Domain,
    virt: u64,
    phys: u64,
    flags: u64,
) -> Result<(), VmError> {
    unsafe {
        let pd = pd_for(t, domain);
        let idx = pd_index(virt);
        if pd.entries[idx] & PTE_PRESENT != 0 {
            return Err(VmError::Overlap);
        }
        pd.entries[idx] = (phys & ADDR_MASK) | flags | PTE_PS;
        Ok(())
    }
}

/// Section descriptor for [`build`]: `(start_virt, end_virt, pte_flags)`.
pub type Section = (u64, u64, u64);

/// Build the complete bootstrap page table set. `image`/`map` come from the
/// pre-takeover BootInfo snapshot; `stack_frames` are freshly allocated by the
/// PMM (order: low stack page first).
///
/// Build the complete bootstrap page table set. `image`/`map` come from the
/// pre-takeover BootInfo snapshot; `stack_frames` are freshly allocated by the
/// PMM (order: low stack page first).
///
/// Always uses a stack-local [`PtCursor`]: host tests run in parallel, so this
/// path never touches the takeover statics (see [`build_inner`]).
///
/// # Safety
/// `t` must point at a zeroed-or-reusable `BootTables`; the function writes
/// the tables through kernel-virtual addresses only.
pub unsafe fn build(
    t: *mut BootTables,
    image: &SavedImage,
    map: &SavedMap,
    stack_frames: &[u64; KERNEL_STACK_FRAMES],
    sections: &[Section],
) -> Result<VmSummary, VmError> {
    unsafe {
        let mut cursor = PtCursor::new();
        build_inner(t, image, map, stack_frames, sections, &mut cursor)
    }
}

/// [`build`] with a caller-provided cursor. `build_kernel_tables` passes the
/// persistent `TAKEOVER_CURSOR` so post-takeover [`map_physical`] calls can
/// find (and extend) the PTs built here; host tests pass a local cursor.
///
/// # Safety
/// Same as [`build`]; `cursor` must not have handed out tables for `t` yet.
unsafe fn build_inner(
    t: *mut BootTables,
    image: &SavedImage,
    map: &SavedMap,
    stack_frames: &[u64; KERNEL_STACK_FRAMES],
    sections: &[Section],
    cursor: &mut PtCursor,
) -> Result<VmSummary, VmError> {
    unsafe {
        (*t).clear();
        let mut summary = VmSummary {
            pml4_phys: phys_of(core::ptr::addr_of!((*t).pml4) as u64, image),
            ..VmSummary::default()
        };

        // 1. Kernel sections, W^X at the link address.
        for &(start, end, flags) in sections {
            let mut v = start & !(FRAME_SIZE - 1);
            let end = end.div_ceil(FRAME_SIZE) * FRAME_SIZE;
            while v < end {
                let phys = phys_of(v, image);
                map_4k(t, cursor, image, Domain::Kernel, v, phys, flags)?;
                summary.kernel_pages += 1;
                v += FRAME_SIZE;
            }
        }

        // 2. Direct map of conventional RAM (clipped to the 1 GiB ceiling).
        let direct_flags = PTE_PRESENT | PTE_WRITE | PTE_NX;
        for i in 0..map.count {
            let r = map.regions[i];
            if r.ty != bootinfo::efi_desc::TYPE_CONVENTIONAL {
                continue;
            }
            let base = r.base;
            let end = r
                .base
                .saturating_add(r.pages * FRAME_SIZE)
                .min(MAX_ALLOC_ADDR);
            if base >= end {
                continue;
            }
            let split = split_large_region(base, end - base);
            for (off, len) in [split.head, split.tail] {
                let mut p = off;
                while p < off + len {
                    map_4k(
                        t,
                        cursor,
                        image,
                        Domain::Direct,
                        DIRECT_MAP_BASE + p,
                        p,
                        direct_flags,
                    )?;
                    summary.pages_direct_4k += 1;
                    p += FRAME_SIZE;
                }
            }
            let mut p = split.body.0;
            while p < split.body.0 + split.body.1 {
                map_2m(t, Domain::Direct, DIRECT_MAP_BASE + p, p, direct_flags)?;
                summary.bytes_direct_2m += LARGE_PAGE_SIZE;
                p += LARGE_PAGE_SIZE;
            }
        }

        // 3. Fresh kernel stack + not-present guard page below it.
        for (i, frame) in stack_frames.iter().enumerate() {
            map_4k(
                t,
                cursor,
                image,
                Domain::Kernel,
                KERNEL_STACK_VIRT + (i as u64 + 1) * FRAME_SIZE,
                *frame,
                PTE_PRESENT | PTE_WRITE | PTE_NX,
            )?;
            summary.stack_pages += 1;
        }

        // 4. Wire the top-level entries.
        let direct_pdpt_phys = phys_of(core::ptr::addr_of!((*t).direct_pdpt) as u64, image);
        let direct_pd_phys = phys_of(core::ptr::addr_of!((*t).direct_pd) as u64, image);
        let kern_pdpt_phys = phys_of(core::ptr::addr_of!((*t).kern_pdpt) as u64, image);
        let kern_pd_phys = phys_of(core::ptr::addr_of!((*t).kern_pd) as u64, image);
        (*t).pml4.entries[pml4_index(DIRECT_MAP_BASE)] = direct_pdpt_phys | PTE_PRESENT | PTE_WRITE;
        (*t).direct_pdpt.entries[DIRECT_PDPT_SLOT] = direct_pd_phys | PTE_PRESENT | PTE_WRITE;
        let kernel_base = image.virt_base;
        (*t).pml4.entries[pml4_index(kernel_base)] = kern_pdpt_phys | PTE_PRESENT | PTE_WRITE;
        (*t).kern_pdpt.entries[pdpt_index(kernel_base)] = kern_pd_phys | PTE_PRESENT | PTE_WRITE;

        Ok(summary)
    }
}

// ---------------------------------------------------------------------------
// Post-takeover dynamic kernel mappings (M3)
// ---------------------------------------------------------------------------

/// Cursor persisted by `build_kernel_tables` for post-takeover [`map_physical`]
/// calls. Only the non-test takeover path writes it, and only the single-CPU,
/// interrupts-disabled post-takeover path reads or mutates it, so host tests
/// (which use stack-local cursors) never touch it and cannot race on it.
static mut TAKEOVER_CURSOR: PtCursor = PtCursor::new();

/// Set when `build_kernel_tables` produced the boot tables, i.e. when
/// [`map_physical`]'s globals are meaningful. `kernel_main` switches CR3
/// immediately afterwards with interrupts disabled, so the post-switch code is
/// the first possible caller.
static mut TAKEOVER_DONE: bool = false;

/// Map `len` bytes of physical address space starting at `phys` into the kernel
/// window at the 4 KiB-aligned virtual address `virt`.
///
/// This is the M3 growth path for regions the boot snapshot does not cover:
/// ACPI tables (read-only), MMIO (uncached, `PTE_PWT | PTE_PCD`) and the
/// per-thread stacks the scheduler allocates from the PMM. `phys` may start at
/// an offset inside a page: the pages covering `[phys, phys + len)` are mapped
/// one by one, and the returned virtual address is the one that maps the
/// *given* `phys` byte, i.e. `virt + (phys & 0xFFF)`.
///
/// The whole request is validated before any PT entry is written, so a rejected
/// call (misaligned `virt`, zero `len`, address overflow, `virt` outside the
/// kernel window, or any page of the range already mapped) leaves the tables
/// unchanged.
///
/// `flags` are 4 KiB PTE attributes (`PTE_WRITE`, `PTE_PWT`, `PTE_PCD`, ...).
/// `PTE_PRESENT` and `PTE_NX` are added automatically: these are data, stack and
/// MMIO pages, never code, so the default is no-execute (W^X). Address bits and
/// `PTE_PS` are masked out (bit 7 is `PAT` in a 4 KiB leaf, not `PS`).
///
/// # Safety
/// - Only valid after `build_kernel_tables` has run *and* the CPU is running on
///   those tables (the `takeover` switch): the static tables and cursor are
///   then the active ones, `invlpg` flushes the right TLB, and `boot::state()`
///   holds the image placement used for the PT physical addresses.
/// - Callers must run with interrupts disabled (`IF=0`): the tables and the
///   cursor are global static state with no locking (M3 keeps interrupts off;
///   the scheduler re-enables them later under its own rules).
/// - `virt` must be a kernel-window address the caller owns. Overlap with an
///   existing leaf is reported as [`VmError::Overlap`], but the not-present
///   guard-page slot is not specially protected: do not map over it.
/// - `phys` must be a device or RAM region the caller owns; mapping it grants
///   exactly the permissions `flags` request.
pub unsafe fn map_physical(virt: u64, phys: u64, len: u64, flags: u64) -> Result<u64, VmError> {
    unsafe {
        if !core::ptr::read(core::ptr::addr_of!(TAKEOVER_DONE)) {
            return Err(VmError::NotReady);
        }
        let image = crate::boot::state().image;
        map_physical_in(
            core::ptr::addr_of_mut!(TABLES),
            &mut *core::ptr::addr_of_mut!(TAKEOVER_CURSOR),
            &image,
            virt,
            phys,
            len,
            flags,
        )
    }
}

/// Testable core of [`map_physical`]: explicit tables, cursor and image
/// placement instead of the static ones, so host tests can drive it with
/// stack-local state and no global race.
///
/// # Safety
/// `t`/`cursor` must be a matched pair handed out by [`build`] (or
/// `build_inner`), and `virt` must lie in the kernel window that build wired.
pub unsafe fn map_physical_in(
    t: *mut BootTables,
    cursor: &mut PtCursor,
    image: &SavedImage,
    virt: u64,
    phys: u64,
    len: u64,
    flags: u64,
) -> Result<u64, VmError> {
    unsafe {
        if virt & (FRAME_SIZE - 1) != 0 || len == 0 {
            return Err(VmError::BadAddress);
        }
        let off = phys & (FRAME_SIZE - 1);
        let first = phys - off;
        let end_phys = phys.checked_add(len).ok_or(VmError::BadAddress)?;
        // Exclusive page-aligned end of the physical span (at least one page).
        let last = end_phys
            .checked_add(FRAME_SIZE - 1)
            .ok_or(VmError::BadAddress)?
            & !(FRAME_SIZE - 1);
        let pages = (last - first) / FRAME_SIZE;
        let span = pages.checked_mul(FRAME_SIZE).ok_or(VmError::BadAddress)?;
        // `virt + span` is exclusive, so `end_virt - 1` is its last byte.
        let end_virt = virt.checked_add(span).ok_or(VmError::BadAddress)?;
        // The takeover wires exactly one PML4/PDPT slot for the kernel window
        // (`kern_pdpt[pdpt_index(image.virt_base)]`, with `kern_pd` covering
        // that 1 GiB), so every page of the request must stay inside it.
        let (win_pml4, win_pdpt) = (pml4_index(image.virt_base), pdpt_index(image.virt_base));
        if pml4_index(virt) != win_pml4
            || pdpt_index(virt) != win_pdpt
            || pml4_index(end_virt - 1) != win_pml4
            || pdpt_index(end_virt - 1) != win_pdpt
        {
            return Err(VmError::BadAddress);
        }
        // Pre-check the whole range so a rejected request never leaves a
        // partially mapped window behind.
        for i in 0..pages {
            if kernel_leaf(t, cursor, virt + i * FRAME_SIZE)?.is_some() {
                return Err(VmError::Overlap);
            }
        }
        let attrs = (flags & !ADDR_MASK & !PTE_PS) | PTE_PRESENT | PTE_NX;
        for i in 0..pages {
            let v = virt + i * FRAME_SIZE;
            let p = first + i * FRAME_SIZE;
            map_4k(t, cursor, image, Domain::Kernel, v, p, attrs)?;
            flush_tlb_page(v);
        }
        Ok(virt + off)
    }
}

/// Unmap `len` bytes of the kernel window starting at the 4 KiB-aligned `virt`.
///
/// This is the release path that mirrors [`map_physical`]: a caller that mapped
/// kernel virtual pages (scheduler thread stacks, ACPI/MMIO windows) and then
/// frees the underlying physical frames must also drop the mappings, otherwise
/// the stale leaf keeps a freed frame reachable (use-after-free) and the next
/// [`map_physical`] for the same virtual range fails with
/// [`VmError::Overlap`].
///
/// Only the 4 KiB leaf entries are cleared. The page tables themselves stay
/// allocated (they are boot-time static tables owned by `build_kernel_tables`),
/// and nothing in the direct map or the shared kernel half of a user address
/// space is touched.
///
/// The whole request is validated before the first leaf is cleared: if any page
/// of the range is not currently mapped, the call returns [`VmError::NotFound`]
/// and leaves every leaf unchanged (no partial unmapping).
///
/// # Safety
/// - Only valid after `build_kernel_tables` has run *and* the CPU is running on
///   those tables (the `takeover` switch), so the statics below are the active
///   tables and `invlpg` flushes the right TLB.
/// - Callers must run with interrupts disabled (`IF=0`): the tables are global
///   static state with no locking.
/// - `virt` must be a kernel-window range the caller mapped and owns; clearing a
///   leaf that belongs to somebody else revokes their access.
/// - The caller must keep the virtual range unused until it maps it again: after
///   this call any access through `virt` faults.
pub unsafe fn unmap_kernel(virt: u64, len: u64) -> Result<(), VmError> {
    unsafe {
        if !core::ptr::read(core::ptr::addr_of!(TAKEOVER_DONE)) {
            return Err(VmError::NotReady);
        }
        let image = crate::boot::state().image;
        unmap_kernel_in(
            core::ptr::addr_of_mut!(TABLES),
            &*core::ptr::addr_of!(TAKEOVER_CURSOR),
            &image,
            virt,
            len,
        )
    }
}

/// Testable core of [`unmap_kernel`]: explicit tables, cursor and image
/// placement instead of the static ones, so host tests can drive it with
/// stack-local state and no global race.
///
/// # Safety
/// `t` must be a table set handed out by [`build`] (or `build_inner`) and `virt`
/// must lie in the kernel window that build wired.
pub unsafe fn unmap_kernel_in(
    t: *mut BootTables,
    cursor: &PtCursor,
    image: &SavedImage,
    virt: u64,
    len: u64,
) -> Result<(), VmError> {
    unsafe {
        if virt & (FRAME_SIZE - 1) != 0 || len == 0 || len & (FRAME_SIZE - 1) != 0 {
            return Err(VmError::BadAddress);
        }
        let end_virt = virt.checked_add(len).ok_or(VmError::BadAddress)?;
        // Same window rule as `map_physical_in`: the takeover wired exactly one
        // PML4/PDPT slot, so the whole range must stay inside it.
        let (win_pml4, win_pdpt) = (pml4_index(image.virt_base), pdpt_index(image.virt_base));
        if pml4_index(virt) != win_pml4
            || pdpt_index(virt) != win_pdpt
            || pml4_index(end_virt - 1) != win_pml4
            || pdpt_index(end_virt - 1) != win_pdpt
        {
            return Err(VmError::BadAddress);
        }
        let pages = len / FRAME_SIZE;
        // Pre-check every page: an unmapped page anywhere in the range rejects
        // the request before any leaf is cleared.
        for i in 0..pages {
            if kernel_leaf(t, cursor, virt + i * FRAME_SIZE)?.is_none() {
                return Err(VmError::NotFound);
            }
        }
        for i in 0..pages {
            let v = virt + i * FRAME_SIZE;
            clear_kernel_leaf(t, cursor, v)?;
            flush_tlb_page(v);
        }
        Ok(())
    }
}

/// Resolve the 4 KiB leaf for a kernel-window address; `Ok(None)` when the PT
/// or the leaf does not exist yet.
unsafe fn kernel_leaf(
    t: *mut BootTables,
    cursor: &PtCursor,
    virt: u64,
) -> Result<Option<u64>, VmError> {
    unsafe {
        let pd_entry = (*t).kern_pd.entries[pd_index(virt)];
        if pd_entry & PTE_PRESENT == 0 {
            return Ok(None);
        }
        if pd_entry & PTE_PS != 0 {
            // The takeover never builds large pages in the kernel window; a PS
            // entry here means these are not the tables we built.
            return Err(VmError::Overlap);
        }
        let pt = cursor.lookup(pd_entry & ADDR_MASK)?;
        let leaf = (*pt).entries[pt_index(virt)];
        Ok(if leaf & PTE_PRESENT != 0 {
            Some(leaf)
        } else {
            None
        })
    }
}

/// Clear one present 4 KiB leaf in the kernel window.
///
/// The entry is zeroed rather than only having `PTE_PRESENT` removed: a
/// not-present PTE still carries the physical address bits, which would leave a
/// freed frame referenced from the tables (and confuses diagnostics).
unsafe fn clear_kernel_leaf(
    t: *mut BootTables,
    cursor: &PtCursor,
    virt: u64,
) -> Result<(), VmError> {
    unsafe {
        let pd_entry = (*t).kern_pd.entries[pd_index(virt)];
        if pd_entry & PTE_PRESENT == 0 {
            return Err(VmError::NotFound);
        }
        if pd_entry & PTE_PS != 0 {
            return Err(VmError::Overlap);
        }
        let pt = cursor.lookup(pd_entry & ADDR_MASK)?;
        (*pt).entries[pt_index(virt)] = 0;
        Ok(())
    }
}

/// Flush one TLB entry after a mapping change. The host test build runs kernel
/// code in user mode, where `invlpg` faults, so tests get a no-op (they only
/// inspect page-table memory, never the TLB).
#[cfg(not(test))]
unsafe fn flush_tlb_page(virt: u64) {
    unsafe { core::arch::asm!("invlpg [{0}]", in(reg) virt, options(nostack, preserves_flags)) }
}

#[cfg(test)]
unsafe fn flush_tlb_page(_virt: u64) {}

// ---------------------------------------------------------------------------
// AP bring-up helpers (M6b1): low-memory identity page + per-CPU stacks
// ---------------------------------------------------------------------------

/// Page tables for the single low-memory identity page the AP trampoline needs.
///
/// A SIPI can only target an address below 1 MiB, and the AP enters real mode
/// with paging off; its first long-mode instruction therefore runs on the shared
/// kernel page tables and needs an *identity* mapping (`virt == phys`) of the
/// trampoline page. The chain is three static `.bss` tables (12 KiB, no PMM
/// frames) that exist only for the bring-up window: [`identity_map_page`]
/// installs it, [`identity_unmap_page`] removes the `pml4[0]` entry again.
///
/// Exactly one 4 KiB leaf is ever present, so nothing else below 1 MiB (IVT,
/// BDA, firmware data) becomes visible, and the executable page disappears again
/// once every AP runs in long mode (agents.md §7.2 W^X is about the long-lived
/// high-half mappings; this transient page is the documented exception).
#[repr(C, align(4096))]
pub struct IdentityTables {
    pub pdpt: PageTable,
    pub pd: PageTable,
    pub pt: PageTable,
}

impl IdentityTables {
    pub const fn new() -> Self {
        IdentityTables {
            pdpt: PageTable::new(),
            pd: PageTable::new(),
            pt: PageTable::new(),
        }
    }

    pub fn clear(&mut self) {
        self.pdpt.clear();
        self.pd.clear();
        self.pt.clear();
    }
}

/// Static identity chain used by the kernel bring-up path. Only the single-CPU,
/// interrupts-disabled pre-SMP path touches it; host tests pass their own tables
/// to the `_in` cores and never observe this state.
static mut IDENT_TABLES: IdentityTables = IdentityTables::new();

/// PML4 slot of the identity window (everything below 512 GiB).
const IDENTITY_PML4_SLOT: usize = 0;

/// Physical addresses of the static identity chain (PDPT, PD, PT), derived from
/// the kernel-image placement like every other boot page-table physical address.
unsafe fn ident_table_phys(image: &SavedImage) -> [u64; 3] {
    unsafe {
        let ident = core::ptr::addr_of!(IDENT_TABLES);
        [
            phys_of(core::ptr::addr_of!((*ident).pdpt) as u64, image),
            phys_of(core::ptr::addr_of!((*ident).pd) as u64, image),
            phys_of(core::ptr::addr_of!((*ident).pt) as u64, image),
        ]
    }
}

/// The kernel PML4 while the takeover tables are active.
unsafe fn kernel_pml4() -> *mut PageTable {
    unsafe { core::ptr::addr_of_mut!((*core::ptr::addr_of_mut!(TABLES)).pml4) }
}

/// Wire the identity chain into `root` and map exactly one 4 KiB page at `phys`.
///
/// The `phys` page must lie below [`SIPI_MAX_PHYS`], and page zero is rejected
/// (it holds the real-mode IVT/BDA). Every check runs before the first entry is
/// written, so a rejected call leaves both table sets untouched. The leaf is
/// `PRESENT | WRITE` with `NX` clear: the AP jumps into it in 64-bit mode.
///
/// # Safety
/// `root`, `ident` and `ident_phys` must describe real, writable page tables (the
/// kernel image mapping in production, host-owned buffers in tests), and nothing
/// else may own `root`'s [`IDENTITY_PML4_SLOT`] entry.
pub unsafe fn identity_map_page_in(
    root: *mut PageTable,
    ident: *mut IdentityTables,
    ident_phys: [u64; 3],
    phys: u64,
) -> Result<(), VmError> {
    unsafe {
        if phys & (FRAME_SIZE - 1) != 0 || phys == 0 || phys >= SIPI_MAX_PHYS {
            return Err(VmError::BadAddress);
        }
        let root_link = ident_phys[0] | PTE_PRESENT | PTE_WRITE;
        let root_entry = (*root).entries[IDENTITY_PML4_SLOT];
        if root_entry & ENTRY_MASK != 0 && !entry_matches(root_entry, root_link) {
            // Somebody already owns the user-half PML4 slot (in the host-test
            // layout this is the fake kernel window): never clobber it.
            return Err(VmError::BadAddress);
        }
        let pdpt_link = ident_phys[1] | PTE_PRESENT | PTE_WRITE;
        let pd_link = ident_phys[2] | PTE_PRESENT | PTE_WRITE;
        let (i3, i2, i1) = (pdpt_index(phys), pd_index(phys), pt_index(phys));
        let pdpt_slot = (*ident).pdpt.entries[i3];
        if pdpt_slot & ENTRY_MASK != 0 && !entry_matches(pdpt_slot, pdpt_link) {
            return Err(VmError::BadAddress);
        }
        let pd_slot = (*ident).pd.entries[i2];
        if pd_slot & ENTRY_MASK != 0 && !entry_matches(pd_slot, pd_link) {
            return Err(VmError::BadAddress);
        }
        if (*ident).pt.entries[i1] & PTE_PRESENT != 0 {
            return Err(VmError::Overlap);
        }
        (*root).entries[IDENTITY_PML4_SLOT] = root_link;
        (*ident).pdpt.entries[i3] = pdpt_link;
        (*ident).pd.entries[i2] = pd_link;
        (*ident).pt.entries[i1] = phys | PTE_PRESENT | PTE_WRITE;
        Ok(())
    }
}

/// Remove the identity mapping of `phys`: clear the leaf, the PD/PDPT links and
/// the `root` PML4 slot, so the low half becomes unreachable again.
///
/// Answers [`VmError::NotFound`] (touching nothing) when the chain does not
/// describe exactly this page — a second unmap of the same page is therefore a
/// no-op error rather than a corruption.
///
/// # Safety
/// Same table contract as [`identity_map_page_in`]; the caller must flush the TLB
/// for the identity address (`invlpg phys`), which the production wrapper does.
pub unsafe fn identity_unmap_page_in(
    root: *mut PageTable,
    ident: *mut IdentityTables,
    ident_phys: [u64; 3],
    phys: u64,
) -> Result<(), VmError> {
    unsafe {
        if phys & (FRAME_SIZE - 1) != 0 || phys == 0 || phys >= SIPI_MAX_PHYS {
            return Err(VmError::BadAddress);
        }
        let (i3, i2, i1) = (pdpt_index(phys), pd_index(phys), pt_index(phys));
        let root_link = ident_phys[0] | PTE_PRESENT | PTE_WRITE;
        let pdpt_link = ident_phys[1] | PTE_PRESENT | PTE_WRITE;
        let pd_link = ident_phys[2] | PTE_PRESENT | PTE_WRITE;
        if !entry_matches((*root).entries[IDENTITY_PML4_SLOT], root_link)
            || !entry_matches((*ident).pdpt.entries[i3], pdpt_link)
            || !entry_matches((*ident).pd.entries[i2], pd_link)
            || !entry_matches((*ident).pt.entries[i1], phys | PTE_PRESENT | PTE_WRITE)
        {
            return Err(VmError::NotFound);
        }
        (*ident).pt.entries[i1] = 0;
        (*ident).pd.entries[i2] = 0;
        (*ident).pdpt.entries[i3] = 0;
        (*root).entries[IDENTITY_PML4_SLOT] = 0;
        Ok(())
    }
}

/// Whether `phys` is currently reachable through the identity chain, i.e. the
/// low page maps 1:1. Answers `None` for anything the chain does not map.
pub fn identity_translate_in(
    root: *const PageTable,
    ident: *const IdentityTables,
    ident_phys: [u64; 3],
    phys: u64,
) -> Option<u64> {
    unsafe {
        if phys & (FRAME_SIZE - 1) != 0 || phys >= SIPI_MAX_PHYS {
            return None;
        }
        if !entry_matches(
            (*root).entries[IDENTITY_PML4_SLOT],
            ident_phys[0] | PTE_PRESENT | PTE_WRITE,
        ) {
            return None;
        }
        let (i3, i2, i1) = (pdpt_index(phys), pd_index(phys), pt_index(phys));
        if !entry_matches(
            (*ident).pdpt.entries[i3],
            ident_phys[1] | PTE_PRESENT | PTE_WRITE,
        ) {
            return None;
        }
        if !entry_matches(
            (*ident).pd.entries[i2],
            ident_phys[2] | PTE_PRESENT | PTE_WRITE,
        ) {
            return None;
        }
        let leaf = (*ident).pt.entries[i1];
        if leaf & PTE_PRESENT == 0 || (leaf & ADDR_MASK) != phys {
            return None;
        }
        Some(phys)
    }
}

/// Map the low-memory AP trampoline page identity (kernel bring-up only).
///
/// The page must already be reserved in the PMM (`pmm::reserve_low_page`) and
/// filled through the direct map; this call only installs the mapping.
///
/// # Safety
/// - Only valid after the takeover ([`VmError::NotReady`] otherwise) and with
///   interrupts disabled: the tables and statics are unlocked global state.
/// - At most one page is supported at a time; unmap it with
///   [`identity_unmap_page`] before mapping another.
/// - The caller must keep `phys` owned (reserved) until the unmapping call, and
///   must not let another CPU execute at that physical address afterwards.
pub unsafe fn identity_map_page(phys: u64) -> Result<(), VmError> {
    unsafe {
        if !core::ptr::read(core::ptr::addr_of!(TAKEOVER_DONE)) {
            return Err(VmError::NotReady);
        }
        let image = crate::boot::state().image;
        if pml4_index(image.virt_base) == IDENTITY_PML4_SLOT {
            // The identity chain would shadow the kernel window itself; only the
            // host-test layout (image linked at 0) can produce this.
            return Err(VmError::BadAddress);
        }
        let ident = core::ptr::addr_of_mut!(IDENT_TABLES);
        (*ident).clear();
        identity_map_page_in(kernel_pml4(), ident, ident_table_phys(&image), phys)?;
        flush_tlb_page(phys);
        Ok(())
    }
}

/// Remove the identity mapping installed by [`identity_map_page`] and flush the
/// TLB entry. Answers [`VmError::NotFound`] when it is not currently mapped.
///
/// # Safety
/// Same context rules as [`identity_map_page`].
pub unsafe fn identity_unmap_page(phys: u64) -> Result<(), VmError> {
    unsafe {
        if !core::ptr::read(core::ptr::addr_of!(TAKEOVER_DONE)) {
            return Err(VmError::NotReady);
        }
        let image = crate::boot::state().image;
        if pml4_index(image.virt_base) == IDENTITY_PML4_SLOT {
            return Err(VmError::BadAddress);
        }
        identity_unmap_page_in(
            kernel_pml4(),
            core::ptr::addr_of_mut!(IDENT_TABLES),
            ident_table_phys(&image),
            phys,
        )?;
        flush_tlb_page(phys);
        Ok(())
    }
}

/// Whether `phys` is currently identity-mapped by the kernel bring-up chain.
pub fn identity_translate(phys: u64) -> Option<u64> {
    unsafe {
        if !core::ptr::read(core::ptr::addr_of!(TAKEOVER_DONE)) {
            return None;
        }
        let image = crate::boot::state().image;
        if pml4_index(image.virt_base) == IDENTITY_PML4_SLOT {
            return None;
        }
        identity_translate_in(
            kernel_pml4(),
            core::ptr::addr_of!(IDENT_TABLES),
            ident_table_phys(&image),
            phys,
        )
    }
}

/// Base of AP stack slot `cpu`: a not-present guard page, never mapped.
pub const fn ap_stack_slot(cpu: usize) -> u64 {
    AP_STACK_BASE + (cpu as u64) * AP_STACK_STRIDE
}

/// Initial RSP of AP stack slot `cpu`, i.e. the end of its last mapped frame.
///
/// Layout mirrors the boot stack ([`KERNEL_STACK_VIRT`]): guard page at the slot
/// base, frames at `+0x1000 .. +0x4000`, stack top at `+0x5000`. All
/// [`AP_STACK_FRAMES`] frames are usable below the initial RSP.
pub fn ap_stack_top(cpu: usize) -> Option<u64> {
    if cpu >= MAX_AP_STACKS {
        return None;
    }
    Some(ap_stack_slot(cpu) + (AP_STACK_FRAMES as u64 + 1) * FRAME_SIZE)
}

/// Map the frames of AP stack `cpu` into the kernel window and answer its initial
/// RSP.
///
/// Every page is checked before the first leaf is written, so a rejected call
/// (slot out of range, any page already mapped) maps nothing. Flags are
/// `PRESENT | WRITE | NX`: stacks are data, never code.
///
/// # Safety
/// `t`/`cursor` must be a matched pair handed out by [`build`] (or
/// `build_inner`) and cover [`AP_STACK_BASE`]'s PD window.
pub unsafe fn map_cpu_stack_in(
    t: *mut BootTables,
    cursor: &mut PtCursor,
    image: &SavedImage,
    cpu: usize,
    frames: &[u64; AP_STACK_FRAMES],
) -> Result<u64, VmError> {
    unsafe {
        if cpu >= MAX_AP_STACKS {
            return Err(VmError::BadAddress);
        }
        let base = ap_stack_slot(cpu);
        for i in 0..AP_STACK_FRAMES {
            let v = base + (i as u64 + 1) * FRAME_SIZE;
            if kernel_leaf(t, cursor, v)?.is_some() {
                return Err(VmError::Overlap);
            }
        }
        let attrs = PTE_PRESENT | PTE_WRITE | PTE_NX;
        for i in 0..AP_STACK_FRAMES {
            let v = base + (i as u64 + 1) * FRAME_SIZE;
            map_4k(t, cursor, image, Domain::Kernel, v, frames[i], attrs)?;
            flush_tlb_page(v);
        }
        Ok(base + (AP_STACK_FRAMES as u64 + 1) * FRAME_SIZE)
    }
}

/// Allocate the frames of AP stack `cpu` from the PMM and map them, answering the
/// initial RSP.
///
/// Failure to allocate a frame is reported as [`VmError::OutOfTables`]
/// (`VmError` has no out-of-memory variant; the caller sees a loud failure and
/// the already-allocated frames are returned to the PMM). A mapping failure also
/// releases every frame, so a failed call leaks nothing.
///
/// # Safety
/// Only valid after the takeover, with interrupts disabled (same rules as
/// [`map_physical`]).
pub unsafe fn map_cpu_stack(cpu: usize) -> Result<u64, VmError> {
    unsafe {
        if !core::ptr::read(core::ptr::addr_of!(TAKEOVER_DONE)) {
            return Err(VmError::NotReady);
        }
        if cpu >= MAX_AP_STACKS {
            return Err(VmError::BadAddress);
        }
        let mut frames = [0u64; AP_STACK_FRAMES];
        for i in 0..AP_STACK_FRAMES {
            match crate::mm::pmm::alloc_frame() {
                Ok(p) => frames[i] = p,
                Err(_) => {
                    for f in frames.iter().take(i) {
                        let _ = crate::mm::pmm::dealloc_frame(*f);
                    }
                    return Err(VmError::OutOfTables);
                }
            }
        }
        let image = crate::boot::state().image;
        let r = map_cpu_stack_in(
            core::ptr::addr_of_mut!(TABLES),
            &mut *core::ptr::addr_of_mut!(TAKEOVER_CURSOR),
            &image,
            cpu,
            &frames,
        );
        if r.is_err() {
            for f in frames.iter() {
                let _ = crate::mm::pmm::dealloc_frame(*f);
            }
        }
        r
    }
}

/// Clear the mappings of AP stack `cpu` (the frames stay owned by the caller).
///
/// # Safety
/// `t`/`cursor` must be the pair that mapped the slot; the caller must free the
/// frames itself and must not run on the stack afterwards.
pub unsafe fn unmap_cpu_stack_in(
    t: *mut BootTables,
    cursor: &PtCursor,
    cpu: usize,
) -> Result<(), VmError> {
    unsafe {
        if cpu >= MAX_AP_STACKS {
            return Err(VmError::BadAddress);
        }
        let base = ap_stack_slot(cpu);
        for i in 0..AP_STACK_FRAMES {
            let v = base + (i as u64 + 1) * FRAME_SIZE;
            if kernel_leaf(t, cursor, v)?.is_none() {
                return Err(VmError::NotFound);
            }
        }
        for i in 0..AP_STACK_FRAMES {
            let v = base + (i as u64 + 1) * FRAME_SIZE;
            clear_kernel_leaf(t, cursor, v)?;
            flush_tlb_page(v);
        }
        Ok(())
    }
}

/// Clear the mappings of AP stack `cpu`; the caller still owns the frames.
///
/// # Safety
/// Only valid after the takeover, with interrupts disabled, and never while the
/// CPU is running on that stack.
pub unsafe fn unmap_cpu_stack(cpu: usize) -> Result<(), VmError> {
    unsafe {
        if !core::ptr::read(core::ptr::addr_of!(TAKEOVER_DONE)) {
            return Err(VmError::NotReady);
        }
        unmap_cpu_stack_in(
            core::ptr::addr_of_mut!(TABLES),
            &*core::ptr::addr_of!(TAKEOVER_CURSOR),
            cpu,
        )
    }
}

// ---------------------------------------------------------------------------
// Linker-symbol section bounds (kernel build only)
// ---------------------------------------------------------------------------

#[cfg(not(test))]
unsafe extern "C" {
    static __text_start: u8;
    static __text_end: u8;
    static __rodata_start: u8;
    static __rodata_end: u8;
    static __data_start: u8;
    static __bss_end: u8;
}

/// Kernel entry point for the takeover: computes W^X section bounds from the
/// linker symbols, then delegates to [`build_inner`] with the persistent
/// takeover cursor so post-switch [`map_physical`] calls can extend the tables.
#[cfg(not(test))]
pub unsafe fn build_kernel_tables(
    t: *mut BootTables,
    image: &SavedImage,
    map: &SavedMap,
    stack_frames: &[u64; KERNEL_STACK_FRAMES],
) -> Result<VmSummary, VmError> {
    let text = (
        core::ptr::addr_of!(__text_start) as u64,
        core::ptr::addr_of!(__text_end) as u64,
    );
    let rodata = (
        core::ptr::addr_of!(__rodata_start) as u64,
        core::ptr::addr_of!(__rodata_end) as u64,
    );
    let data = (
        core::ptr::addr_of!(__data_start) as u64,
        core::ptr::addr_of!(__bss_end) as u64,
    );
    let sections: [Section; 3] = [
        (text.0, text.1, PTE_PRESENT),
        (rodata.0, rodata.1, PTE_PRESENT | PTE_NX),
        (data.0, data.1, PTE_PRESENT | PTE_WRITE | PTE_NX),
    ];
    unsafe {
        // Reset and persist the cursor, then mark the tables usable for
        // `map_physical`. All three are only reachable from the single-CPU,
        // interrupts-disabled takeover path.
        let cursor = &mut *core::ptr::addr_of_mut!(TAKEOVER_CURSOR);
        *cursor = PtCursor::new();
        let summary = build_inner(t, image, map, stack_frames, &sections, cursor)?;
        core::ptr::write(core::ptr::addr_of_mut!(TAKEOVER_DONE), true);
        Ok(summary)
    }
}

// ---------------------------------------------------------------------------
// The switch itself
// ---------------------------------------------------------------------------

/// Switch to the kernel's own page tables and stack in one instruction
/// sequence (`cli` → `mov cr3` → `mov rsp` → `jmp`), with no intermediate
/// memory access. `cont` must be a function that never returns; the jump
/// target is materialized before RSP is switched, and the surrounding code
/// is identity-free (only kernel-virtual addresses are touched afterwards).
///
/// # Safety
/// `cr3_phys` must be the physical address of fully built kernel tables that
/// map the running code and `new_rsp`'s stack; `new_rsp` must be a valid,
/// 16-byte-aligned stack top mapped by those tables.
pub unsafe fn takeover(cr3_phys: u64, new_rsp: u64, cont: extern "C" fn() -> !) -> ! {
    unsafe {
        core::arch::asm!(
            "cli",
            "mov cr3, {c}",
            "mov rsp, {s}",
            "jmp {k}",
            c = in(reg) cr3_phys,
            s = in(reg) new_rsp,
            k = in(reg) cont,
            options(noreturn),
        );
    }
}

// ---------------------------------------------------------------------------
// Tests (host)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::boot::{SavedMap, SavedRegion};
    use std::boxed::Box;

    const IMG_VIRT: u64 = 0;
    const IMG_PHYS: u64 = 0x1_0000_0000;

    fn image() -> SavedImage {
        SavedImage {
            phys_base: IMG_PHYS,
            phys_size: 0x1_0000_0000,
            virt_base: IMG_VIRT,
            virt_size: 0x1_0000_0000,
            entry: IMG_VIRT + 0x1000,
        }
    }

    fn map_one(base: u64, pages: u64, ty: u32) -> SavedMap {
        let mut m = SavedMap::empty();
        m.regions[0] = SavedRegion { base, pages, ty };
        m.count = 1;
        m
    }

    fn leaked_tables() -> *mut BootTables {
        Box::leak(Box::new(BootTables::new()))
    }

    #[test]
    fn page_table_indices() {
        assert_eq!(pml4_index(DIRECT_MAP_BASE), 256);
        assert_eq!(pdpt_index(DIRECT_MAP_BASE), 0);
        assert_eq!(pml4_index(0xFFFF_FFFF_8000_0000u64), 511);
        assert_eq!(pdpt_index(0xFFFF_FFFF_8000_0000u64), 510);
        assert_eq!(pd_index(0xFFFF_FFFF_8000_0000u64), 0);
        assert_eq!(pt_index(0xFFFF_FFFF_8000_0000u64), 0);
        assert_eq!(pd_index(0xFFFF_FFFF_8100_0000u64), 8);
    }

    #[test]
    fn phys_to_virt_direct_map() {
        assert_eq!(phys_to_virt(0), DIRECT_MAP_BASE);
        assert_eq!(phys_to_virt(0x3F8), DIRECT_MAP_BASE + 0x3F8);
    }

    #[test]
    fn split_aligned_region_is_body_only() {
        let s = split_large_region(0x20_0000, 0x40_0000);
        assert_eq!(s.head, (0x20_0000, 0));
        assert_eq!(s.body, (0x20_0000, 0x40_0000));
        assert_eq!(s.tail, (0x60_0000, 0));
    }

    #[test]
    fn split_offset_region_has_4k_edges() {
        // [0x1F0000, 0x60_0000): head [0x1F0000,0x200000), body [0x200000,0x600000)
        let s = split_large_region(0x1F_0000, 0x60_0000 - 0x1F_0000);
        assert_eq!(s.head, (0x1F_0000, 0x1_0000));
        assert_eq!(s.body, (0x20_0000, 0x40_0000));
        assert_eq!(s.tail, (0x60_0000, 0));
    }

    #[test]
    fn split_small_region_is_head_and_tail() {
        let s = split_large_region(0x1F_0000, 0x3000);
        assert_eq!(s.head.0, 0x1F_0000);
        assert_eq!(s.head.1 + s.tail.1, 0x3000);
        assert_eq!(s.body.1, 0);
    }

    #[test]
    fn build_maps_direct_map_and_kernel() {
        let t = leaked_tables();
        let img = image();
        // conventional 4 MiB starting at a 2 MiB boundary + a misaligned 1 MiB
        let mut m = SavedMap::empty();
        m.regions[0] = SavedRegion {
            base: 0x20_0000,
            pages: 1024,
            ty: 7,
        };
        m.regions[1] = SavedRegion {
            base: 0x500_0000,
            pages: 256,
            ty: 7,
        };
        m.regions[2] = SavedRegion {
            base: 0x900_0000,
            pages: 256,
            ty: 3, // boot services: must NOT be direct-mapped
        };
        m.count = 3;
        let stack = [0xA0_0000, 0xA0_1000, 0xA0_2000, 0xA0_3000];
        let sections: [Section; 1] = [(0x1000, 0x5000, PTE_PRESENT)];
        let s = unsafe { build(t, &img, &m, &stack, &sections) }.unwrap();
        assert_eq!(s.kernel_pages, 4);
        assert_eq!(s.stack_pages, 4);
        assert_eq!(s.pages_direct_4k, 256); // the 1 MiB region is below one large page
        let tt = unsafe { &*t };
        // top-level wiring
        assert_ne!(tt.pml4.entries[256], 0);
        assert_ne!(tt.pml4.entries[pml4_index(img.virt_base)], 0);
        assert_ne!(tt.direct_pdpt.entries[0], 0);
        assert_ne!(tt.kern_pdpt.entries[pdpt_index(img.virt_base)], 0);
        // kernel text: first PT entry present, executable (no NX), not writable
        let kpt = &tt.kern_pts[0];
        let e = kpt.entries[pt_index(0x1000)];
        assert!(e & PTE_PRESENT != 0);
        assert!(e & PTE_NX == 0);
        assert!(e & PTE_WRITE == 0);
        assert_eq!(e & ADDR_MASK, IMG_PHYS + 0x1000);
        // direct map 2M leaf for 0x20_0000
        let pd = &tt.direct_pd;
        let e = pd.entries[pd_index(DIRECT_MAP_BASE + 0x20_0000)];
        assert!(e & PTE_PRESENT != 0 && e & PTE_PS != 0);
        assert_eq!(e & ADDR_MASK, 0x20_0000);
        assert!(e & PTE_NX != 0);
        // boot-services region must be absent
        let e = pd.entries[pd_index(DIRECT_MAP_BASE + 0x900_0000)];
        assert_eq!(e, 0);
        // stack: kern_pts[0] serves PD window 0 (kernel text); kern_pts[1]
        // serves the stack's PD window. Guard page entry must stay zero.
        let stack_pt = &tt.kern_pts[1];
        assert_eq!(stack_pt.entries[pt_index(KERNEL_STACK_VIRT)], 0); // guard
        assert_eq!(
            stack_pt.entries[pt_index(KERNEL_STACK_VIRT + FRAME_SIZE)] & ADDR_MASK,
            0xA0_0000
        );
    }

    #[test]
    fn build_detects_overlap() {
        let t = leaked_tables();
        let img = image();
        let m = map_one(0x20_0000, 1024, 7);
        let stack = [0xA0_0000, 0xA0_1000, 0xA0_2000, 0xA0_3000];
        // Two kernel sections that overlap within a single build.
        let sections: [Section; 2] = [(0x1000, 0x5000, PTE_PRESENT), (0x4000, 0x6000, PTE_PRESENT)];
        assert_eq!(
            unsafe { build(t, &img, &m, &stack, &sections) },
            Err(VmError::Overlap)
        );
    }

    #[test]
    fn cursor_exhaustion_is_reported() {
        let t = leaked_tables();
        let img = image();
        // 100 one-page conventional regions, each in its own 2 MiB window,
        // would need 100 direct PTs; the pool holds 96.
        let mut m = SavedMap::empty();
        for i in 0..100 {
            m.regions[i] = SavedRegion {
                base: 0x1F_0000 + i as u64 * 0x30_0000,
                pages: 1,
                ty: 7,
            };
        }
        m.count = 100;
        let stack = [0xA0_0000, 0xA0_1000, 0xA0_2000, 0xA0_3000];
        let sections: [Section; 0] = [];
        let r = unsafe { build(t, &img, &m, &stack, &sections) };
        assert_eq!(r.unwrap_err(), VmError::OutOfTables);
    }

    // -----------------------------------------------------------------
    // M3: post-takeover dynamic mappings
    // -----------------------------------------------------------------

    /// Kernel-window VA for the `map_physical_in` tests. `image()` links at 0,
    /// so the wired kernel window is `pml4[0]`/`pdpt[0]` (VA < 1 GiB).
    const KVA: u64 = 0x3000_0000;

    fn map_kern(
        t: *mut BootTables,
        cursor: &mut PtCursor,
        virt: u64,
        phys: u64,
        len: u64,
        flags: u64,
    ) -> Result<u64, VmError> {
        unsafe { map_physical_in(t, cursor, &image(), virt, phys, len, flags) }
    }

    #[test]
    fn map_physical_rejects_bad_requests() {
        let t = leaked_tables();
        let mut cursor = PtCursor::new();
        // virt not 4 KiB aligned
        assert_eq!(
            map_kern(t, &mut cursor, KVA + 1, 0x1000, 0x1000, PTE_WRITE),
            Err(VmError::BadAddress)
        );
        // len == 0
        assert_eq!(
            map_kern(t, &mut cursor, KVA, 0x1000, 0, PTE_WRITE),
            Err(VmError::BadAddress)
        );
        // phys + len overflows
        assert_eq!(
            map_kern(t, &mut cursor, KVA, u64::MAX - 0x10, 0x1000, PTE_WRITE),
            Err(VmError::BadAddress)
        );
        // virt in the direct-map PML4 slot (no kernel PTs there)
        assert_eq!(
            map_kern(t, &mut cursor, DIRECT_MAP_BASE, 0x1000, 0x1000, PTE_WRITE),
            Err(VmError::BadAddress)
        );
        // virt in another PDPT slot of the same PML4 entry
        assert_eq!(
            map_kern(t, &mut cursor, 0x4000_0000, 0x1000, 0x1000, PTE_WRITE),
            Err(VmError::BadAddress)
        );
        // request straddling the end of the 1 GiB kernel PDPT window
        assert_eq!(
            map_kern(t, &mut cursor, 0x3FFF_F000, 0x1000, 0x2000, PTE_WRITE),
            Err(VmError::BadAddress)
        );
        // every rejection above happened before any PT entry was written
        assert!(unsafe { kernel_leaf(t, &cursor, KVA) }.unwrap().is_none());
    }

    #[test]
    fn map_physical_maps_mmio_with_flags() {
        let t = leaked_tables();
        let mut cursor = PtCursor::new();
        // Local-APIC style page: uncached, writable, NX. `PTE_NX` is *not*
        // requested by the caller — the mapping must still come out no-execute
        // (W^X). `PTE_PS` and a stray address bit must both be masked out.
        let flags = PTE_WRITE | PTE_PWT | PTE_PCD | PTE_PS | 0x1000;
        let ret = map_kern(t, &mut cursor, KVA, 0xFEE0_0000, 0x1000, flags).unwrap();
        assert_eq!(ret, KVA);
        let tt = unsafe { &*t };
        let pd = tt.kern_pd.entries[pd_index(KVA)];
        assert!(pd & PTE_PRESENT != 0);
        assert_eq!(pd & PTE_PS, 0, "kernel window must use 4 KiB PTs");
        let leaf = tt.kern_pts[0].entries[pt_index(KVA)];
        assert!(leaf & PTE_PRESENT != 0);
        assert!(leaf & PTE_WRITE != 0);
        assert!(leaf & PTE_PWT != 0);
        assert!(leaf & PTE_PCD != 0);
        assert!(leaf & PTE_NX != 0, "PTE_NX must be implied");
        assert_eq!(leaf & PTE_PS, 0, "PS/PAT bit must be masked out");
        assert_eq!(
            leaf & ADDR_MASK,
            0xFEE0_0000,
            "stray address bit must be masked"
        );
    }

    #[test]
    fn map_physical_handles_page_offset_and_multi_page() {
        let t = leaked_tables();
        let mut cursor = PtCursor::new();
        // 0x2000 bytes starting 0x123 into a page cover 3 physical pages.
        let ret = map_kern(t, &mut cursor, KVA, 0x1000_0123, 0x2000, PTE_WRITE | PTE_NX).unwrap();
        assert_eq!(ret, KVA + 0x123);
        let tt = unsafe { &*t };
        let pt = &tt.kern_pts[0];
        assert_eq!(pt.entries[pt_index(KVA)] & ADDR_MASK, 0x1000_0000);
        assert_eq!(pt.entries[pt_index(KVA + 0x1000)] & ADDR_MASK, 0x1000_1000);
        assert_eq!(pt.entries[pt_index(KVA + 0x2000)] & ADDR_MASK, 0x1000_2000);
        // the page after the covered span stays unmapped
        assert_eq!(pt.entries[pt_index(KVA + 0x3000)], 0);
    }

    #[test]
    fn map_physical_crosses_pd_window() {
        let t = leaked_tables();
        let mut cursor = PtCursor::new();
        // Last 4 KiB of PD slot 0x18F, then the first of slot 0x190: the second
        // page needs a second kernel PT (cursor growth).
        let virt = 0x31FF_F000;
        let ret = map_kern(
            t,
            &mut cursor,
            virt,
            0x2000_0000,
            0x2000,
            PTE_WRITE | PTE_NX,
        )
        .unwrap();
        assert_eq!(ret, virt);
        let tt = unsafe { &*t };
        assert_ne!(tt.kern_pd.entries[pd_index(virt)], 0);
        assert_ne!(tt.kern_pd.entries[pd_index(virt + 0x1000)], 0);
        assert_eq!(
            tt.kern_pts[0].entries[pt_index(virt)] & ADDR_MASK,
            0x2000_0000
        );
        assert_eq!(
            tt.kern_pts[1].entries[pt_index(virt + 0x1000)] & ADDR_MASK,
            0x2000_1000
        );
    }

    #[test]
    fn map_physical_rejects_overlap_without_partial_mapping() {
        let t = leaked_tables();
        let mut cursor = PtCursor::new();
        let flags = PTE_WRITE | PTE_NX;
        map_kern(t, &mut cursor, KVA, 0x1000, 0x2000, flags).unwrap();
        // Second page is already mapped: the request must be rejected and the
        // third page must stay unmapped (pre-check before any write).
        assert_eq!(
            map_kern(t, &mut cursor, KVA + 0x1000, 0x3000, 0x2000, flags),
            Err(VmError::Overlap)
        );
        assert!(
            unsafe { kernel_leaf(t, &cursor, KVA + 0x2000) }
                .unwrap()
                .is_none()
        );
        assert!(
            unsafe { kernel_leaf(t, &cursor, KVA + 0x1000) }
                .unwrap()
                .is_some()
        );
    }

    #[test]
    fn map_physical_requires_takeover() {
        // The public `build` path must not arm the takeover statics (host tests
        // run in parallel and share them), so the static entry point refuses.
        let t = leaked_tables();
        let m = map_one(0x20_0000, 1024, 7);
        let stack = [0xA0_0000, 0xA0_1000, 0xA0_2000, 0xA0_3000];
        let sections: [Section; 0] = [];
        unsafe { build(t, &image(), &m, &stack, &sections) }.unwrap();
        assert_eq!(
            unsafe { map_physical(KVA, 0x1000, 0x1000, PTE_WRITE) },
            Err(VmError::NotReady)
        );
    }

    // -----------------------------------------------------------------
    // M4: releasing kernel-window mappings (`unmap_kernel`)
    // -----------------------------------------------------------------

    fn unmap_kern(
        t: *mut BootTables,
        cursor: &PtCursor,
        virt: u64,
        len: u64,
    ) -> Result<(), VmError> {
        unsafe { unmap_kernel_in(t, cursor, &image(), virt, len) }
    }

    #[test]
    fn unmap_kernel_leaves_no_reachable_frame_behind() {
        let t = leaked_tables();
        let mut cursor = PtCursor::new();
        let flags = PTE_WRITE | PTE_NX;
        map_kern(t, &mut cursor, KVA, 0x2000_0000, 0x4000, flags).unwrap();

        unmap_kern(t, &cursor, KVA, 0x4000).unwrap();

        // No leaf is present any more, and the entries are fully zeroed: a
        // not-present PTE that still carried the physical address would keep the
        // (about to be freed) frame referenced from the tables.
        let tt = unsafe { &*t };
        let pt = &tt.kern_pts[0];
        for i in 0..4 {
            let v = KVA + i * 0x1000;
            assert!(
                unsafe { kernel_leaf(t, &cursor, v) }.unwrap().is_none(),
                "leaf at {v:#x} still present"
            );
            assert_eq!(pt.entries[pt_index(v)], 0, "stale bits at {v:#x}");
        }
        // The page table itself is kept (only leaves are released), so the
        // kernel window stays wired and can be reused.
        assert_ne!(tt.kern_pd.entries[pd_index(KVA)], 0);

        // Re-mapping the same virtual range is what the scheduler does when a
        // thread slot is reused after its stacks were freed; before the unmap
        // this failed with Overlap.
        let ret = map_kern(t, &mut cursor, KVA, 0x3000_0000, 0x4000, flags).unwrap();
        assert_eq!(ret, KVA);
        assert_eq!(
            unsafe { kernel_leaf(t, &cursor, KVA) }.unwrap().unwrap() & ADDR_MASK,
            0x3000_0000
        );
    }

    #[test]
    fn unmap_kernel_is_atomic_when_a_page_is_missing() {
        let t = leaked_tables();
        let mut cursor = PtCursor::new();
        let flags = PTE_WRITE | PTE_NX;
        // Pages 0 and 2 mapped, page 1 not: the request must be rejected whole.
        map_kern(t, &mut cursor, KVA, 0x2000_0000, 0x1000, flags).unwrap();
        map_kern(t, &mut cursor, KVA + 0x2000, 0x2000_2000, 0x1000, flags).unwrap();

        assert_eq!(unmap_kern(t, &cursor, KVA, 0x3000), Err(VmError::NotFound));

        assert_eq!(
            unsafe { kernel_leaf(t, &cursor, KVA) }.unwrap().unwrap() & ADDR_MASK,
            0x2000_0000,
            "page 0 must not be unmapped by a rejected request"
        );
        assert_eq!(
            unsafe { kernel_leaf(t, &cursor, KVA + 0x2000) }
                .unwrap()
                .unwrap()
                & ADDR_MASK,
            0x2000_2000,
            "page 2 must not be unmapped by a rejected request"
        );
        // Nothing at all is mapped where the hole is.
        assert!(
            unsafe { kernel_leaf(t, &cursor, KVA + 0x1000) }
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn unmap_kernel_rejects_bad_requests() {
        let t = leaked_tables();
        let mut cursor = PtCursor::new();
        let flags = PTE_WRITE | PTE_NX;
        map_kern(t, &mut cursor, KVA, 0x2000_0000, 0x1000, flags).unwrap();

        // virt not 4 KiB aligned
        assert_eq!(
            unmap_kern(t, &cursor, KVA + 1, 0x1000),
            Err(VmError::BadAddress)
        );
        // len == 0
        assert_eq!(unmap_kern(t, &cursor, KVA, 0), Err(VmError::BadAddress));
        // len not a multiple of the page size
        assert_eq!(
            unmap_kern(t, &cursor, KVA, 0x1800),
            Err(VmError::BadAddress)
        );
        // virt + len overflows
        assert_eq!(
            unmap_kern(t, &cursor, 0xFFFF_FFFF_FFFF_F000, 0x2000),
            Err(VmError::BadAddress)
        );
        // direct-map PML4 slot: not the kernel window
        assert_eq!(
            unmap_kern(t, &cursor, DIRECT_MAP_BASE, 0x1000),
            Err(VmError::BadAddress)
        );
        // another PDPT slot of the same PML4 entry
        assert_eq!(
            unmap_kern(t, &cursor, 0x4000_0000, 0x1000),
            Err(VmError::BadAddress)
        );
        // request straddling the end of the 1 GiB kernel window
        assert_eq!(
            unmap_kern(t, &cursor, 0x3FFF_F000, 0x2000),
            Err(VmError::BadAddress)
        );
        // every rejection above left the single mapping in place
        assert_eq!(
            unsafe { kernel_leaf(t, &cursor, KVA) }.unwrap().unwrap() & ADDR_MASK,
            0x2000_0000
        );
    }

    #[test]
    fn unmap_kernel_requires_takeover() {
        let t = leaked_tables();
        let m = map_one(0x20_0000, 1024, 7);
        let stack = [0xA0_0000, 0xA0_1000, 0xA0_2000, 0xA0_3000];
        let sections: [Section; 0] = [];
        unsafe { build(t, &image(), &m, &stack, &sections) }.unwrap();
        assert_eq!(unsafe { unmap_kernel(KVA, 0x1000) }, Err(VmError::NotReady));
    }

    // -----------------------------------------------------------------
    // M6b1: low-memory identity page for the AP bring-up trampoline
    // -----------------------------------------------------------------

    /// Fake identity chain: a root that is *not* the test kernel window
    /// (`image()` links at 0, so `pml4[0]` would be taken there), plus the three
    /// host-owned tables and made-up table physical addresses.
    fn identity_chain() -> (*mut PageTable, *mut IdentityTables, [u64; 3]) {
        let root: *mut PageTable = Box::leak(Box::new(PageTable::new()));
        let ident: *mut IdentityTables = Box::leak(Box::new(IdentityTables::new()));
        (root, ident, [0x1000, 0x2000, 0x3000])
    }

    #[test]
    fn identity_map_page_maps_exactly_one_page() {
        let (root, ident, phys) = identity_chain();
        unsafe { identity_map_page_in(root, ident, phys, 0x9000) }.unwrap();

        // Identity means virt == phys for exactly that page.
        assert_eq!(
            identity_translate_in(root, ident, phys, 0x9000),
            Some(0x9000)
        );
        for other in [0x1000u64, 0x8000, 0xA000, 0xFF000] {
            assert_eq!(
                identity_translate_in(root, ident, phys, other),
                None,
                "{other:#x} must not be reachable"
            );
        }
        // Chain wiring and the leaf's flags.
        let r = unsafe { (*root).entries[IDENTITY_PML4_SLOT] };
        assert_eq!(r, phys[0] | PTE_PRESENT | PTE_WRITE);
        let leaf = unsafe { (*ident).pt.entries[pt_index(0x9000)] };
        assert_eq!(leaf, 0x9000 | PTE_PRESENT | PTE_WRITE);
        assert_eq!(leaf & PTE_NX, 0, "the trampoline page must be executable");
        assert_eq!(
            unsafe { (*ident).pt.entries[pt_index(0x8000)] },
            0,
            "neighbouring low pages stay invisible"
        );
        // Only the identity PML4 slot is touched.
        for i in 1..4 {
            assert_eq!(unsafe { (*root).entries[i] }, 0);
        }
        // The real kernel window lives in PML4 slot 511; identity never touches it.
        assert_eq!(
            unsafe { (*root).entries[pml4_index(0xFFFF_FFFF_8000_0000)] },
            0,
            "identity mapping must not disturb the kernel window slot"
        );
    }

    #[test]
    fn identity_map_rejects_bad_and_duplicate_requests() {
        let (root, ident, phys) = identity_chain();
        // Unaligned, page zero (IVT/BDA) and anything above the SIPI window.
        assert_eq!(
            unsafe { identity_map_page_in(root, ident, phys, 0x9001) },
            Err(VmError::BadAddress)
        );
        assert_eq!(
            unsafe { identity_map_page_in(root, ident, phys, 0) },
            Err(VmError::BadAddress)
        );
        assert_eq!(
            unsafe { identity_map_page_in(root, ident, phys, SIPI_MAX_PHYS) },
            Err(VmError::BadAddress)
        );
        assert_eq!(
            unsafe { identity_map_page_in(root, ident, phys, SIPI_MAX_PHYS + 0x1000) },
            Err(VmError::BadAddress)
        );
        // Every rejection above happened before any entry was written.
        assert_eq!(unsafe { (*root).entries[IDENTITY_PML4_SLOT] }, 0);
        assert_eq!(unsafe { (*ident).pt.entries[pt_index(0x9000)] }, 0);

        // A present PML4 slot owned by somebody else is never clobbered: in the
        // host-test layout the fake kernel window lives exactly there.
        unsafe { identity_map_page_in(root, ident, phys, 0x9000) }.unwrap();
        assert_eq!(
            unsafe { identity_map_page_in(root, ident, phys, 0x9000) },
            Err(VmError::Overlap)
        );
        let t = leaked_tables();
        let m = map_one(0x20_0000, 1024, 7);
        let stack = [0xA0_0000, 0xA0_1000, 0xA0_2000, 0xA0_3000];
        let sections: [Section; 0] = [];
        unsafe { build(t, &image(), &m, &stack, &sections) }.unwrap();
        let root2: *mut PageTable = Box::leak(Box::new(PageTable::new()));
        let ident2: *mut IdentityTables = Box::leak(Box::new(IdentityTables::new()));
        // Steal slot 0 as if another subsystem owned the low half.
        unsafe { (*root2).entries[IDENTITY_PML4_SLOT] = 0xDEAD_0000 | PTE_PRESENT | PTE_WRITE };
        assert_eq!(
            unsafe { identity_map_page_in(root2, ident2, phys, 0x9000) },
            Err(VmError::BadAddress)
        );
        assert_eq!(unsafe { (*ident2).pt.entries[pt_index(0x9000)] }, 0);
    }

    #[test]
    fn identity_unmap_clears_the_chain_and_the_root_entry() {
        let (root, ident, phys) = identity_chain();
        unsafe { identity_map_page_in(root, ident, phys, 0x9000) }.unwrap();

        unsafe { identity_unmap_page_in(root, ident, phys, 0x9000) }.unwrap();
        assert_eq!(unsafe { (*root).entries[IDENTITY_PML4_SLOT] }, 0);
        assert_eq!(unsafe { (*ident).pt.entries[pt_index(0x9000)] }, 0);
        assert_eq!(
            unsafe { (*ident).pd.entries[pd_index(0x9000)] },
            0,
            "the PD link goes away too"
        );
        assert_eq!(identity_translate_in(root, ident, phys, 0x9000), None);
        // A second unmap is refused rather than corrupting anything.
        assert_eq!(
            unsafe { identity_unmap_page_in(root, ident, phys, 0x9000) },
            Err(VmError::NotFound)
        );
        // The chain is reusable for the next bring-up attempt.
        unsafe { identity_map_page_in(root, ident, phys, 0xA000) }.unwrap();
        assert_eq!(
            identity_translate_in(root, ident, phys, 0xA000),
            Some(0xA000)
        );
        assert_eq!(identity_translate_in(root, ident, phys, 0x9000), None);
    }

    #[test]
    fn identity_survives_hardware_accessed_and_dirty_bits() {
        let (root, ident, phys) = identity_chain();
        unsafe { identity_map_page_in(root, ident, phys, 0x9000) }.unwrap();

        // A real page walk sets A on every level it touches and D on a written
        // leaf. The CPU owns those bits, so the chain must still be recognised
        // as ours (a phantom `NotFound` here broke AP teardown in QEMU).
        const A: u64 = 1 << 5;
        const D: u64 = 1 << 6;
        unsafe {
            (*root).entries[IDENTITY_PML4_SLOT] |= A;
            (*ident).pdpt.entries[pdpt_index(0x9000)] |= A;
            (*ident).pd.entries[pd_index(0x9000)] |= A;
            (*ident).pt.entries[pt_index(0x9000)] |= A | D;
        }
        assert_eq!(
            identity_translate_in(root, ident, phys, 0x9000),
            Some(0x9000)
        );
        // Our own live chain is recognised: the failure is Overlap (the leaf is
        // taken), not BadAddress (foreign tables).
        assert_eq!(
            unsafe { identity_map_page_in(root, ident, phys, 0x9000) },
            Err(VmError::Overlap)
        );
        // Teardown succeeds and clears the hardware-owned bits with the links.
        unsafe { identity_unmap_page_in(root, ident, phys, 0x9000) }.unwrap();
        assert_eq!(unsafe { (*root).entries[IDENTITY_PML4_SLOT] }, 0);
        assert_eq!(unsafe { (*ident).pdpt.entries[pdpt_index(0x9000)] }, 0);
        assert_eq!(unsafe { (*ident).pd.entries[pd_index(0x9000)] }, 0);
        assert_eq!(unsafe { (*ident).pt.entries[pt_index(0x9000)] }, 0);
        assert_eq!(identity_translate_in(root, ident, phys, 0x9000), None);
        // A second teardown is still refused.
        assert_eq!(
            unsafe { identity_unmap_page_in(root, ident, phys, 0x9000) },
            Err(VmError::NotFound)
        );
    }

    #[test]
    fn identity_and_cpu_stacks_require_takeover() {
        let t = leaked_tables();
        let m = map_one(0x20_0000, 1024, 7);
        let stack = [0xA0_0000, 0xA0_1000, 0xA0_2000, 0xA0_3000];
        let sections: [Section; 0] = [];
        unsafe { build(t, &image(), &m, &stack, &sections) }.unwrap();
        assert_eq!(unsafe { identity_map_page(0x9000) }, Err(VmError::NotReady));
        assert_eq!(
            unsafe { identity_unmap_page(0x9000) },
            Err(VmError::NotReady)
        );
        assert_eq!(identity_translate(0x9000), None);
        assert_eq!(unsafe { map_cpu_stack(0) }, Err(VmError::NotReady));
        assert_eq!(unsafe { unmap_cpu_stack(0) }, Err(VmError::NotReady));
    }

    #[test]
    fn ap_stack_slots_are_disjoint_from_other_kernel_windows() {
        // Frozen layout: four slots of 64 KiB right below the platform window.
        assert_eq!(MAX_AP_STACKS, 4, "must match acpi::MAX_CPUS - 1");
        assert_eq!(AP_STACK_FRAMES, KERNEL_STACK_FRAMES);
        assert_eq!(ap_stack_slot(0), AP_STACK_BASE);
        assert_eq!(
            ap_stack_slot(MAX_AP_STACKS) - AP_STACK_BASE,
            4 * AP_STACK_STRIDE
        );
        // Above the per-process kernel stacks (0xFFFF_FFFF_8160_0000) ...
        assert!(AP_STACK_BASE > 0xFFFF_FFFF_8170_0000);
        // ... and clear of platform's ACPI/MMIO window at 0xFFFF_FFFF_8200_0000.
        assert!(ap_stack_slot(MAX_AP_STACKS) <= 0xFFFF_FFFF_8200_0000);
        for cpu in 0..MAX_AP_STACKS {
            let top = ap_stack_top(cpu).unwrap();
            assert_eq!(top, ap_stack_slot(cpu) + 5 * FRAME_SIZE);
            assert!(top <= ap_stack_slot(cpu) + AP_STACK_STRIDE);
            assert_eq!(ap_stack_slot(cpu) % FRAME_SIZE, 0);
            assert_eq!(top % FRAME_SIZE, 0);
        }
        assert_eq!(ap_stack_top(MAX_AP_STACKS), None);
        assert_eq!(ap_stack_top(usize::MAX), None);
        // Slots never overlap: each top stays inside its own stride.
        let mut tops: std::vec::Vec<u64> = std::vec::Vec::new();
        for cpu in 0..MAX_AP_STACKS {
            tops.push(ap_stack_top(cpu).unwrap());
        }
        tops.sort_unstable();
        for pair in tops.windows(2) {
            assert!(pair[1] - pair[0] >= AP_STACK_FRAMES as u64 * FRAME_SIZE);
        }
    }

    fn built_tables_with_cursor() -> (*mut BootTables, PtCursor) {
        let t = leaked_tables();
        let m = map_one(0x20_0000, 1024, 7);
        let stack = [0xA0_0000, 0xA0_1000, 0xA0_2000, 0xA0_3000];
        let sections: [Section; 0] = [];
        let mut cursor = PtCursor::new();
        unsafe { build_inner(t, &image(), &m, &stack, &sections, &mut cursor) }.unwrap();
        (t, cursor)
    }

    #[test]
    fn map_cpu_stack_maps_four_frames_with_a_guard() {
        let (t, mut cursor) = built_tables_with_cursor();
        let frames = [0x40_0000, 0x40_1000, 0x40_2000, 0x40_3000];
        let top = unsafe { map_cpu_stack_in(t, &mut cursor, &image(), 1, &frames) }.unwrap();

        assert_eq!(top, ap_stack_top(1).unwrap());
        let base = ap_stack_slot(1);
        // Guard page below the stack stays not-present.
        assert!(unsafe { kernel_leaf(t, &cursor, base) }.unwrap().is_none());
        // Slot 0 must be untouched by slot 1's mapping.
        assert!(
            unsafe { kernel_leaf(t, &cursor, ap_stack_slot(0) + FRAME_SIZE) }
                .unwrap()
                .is_none()
        );
        for (i, frame) in frames.iter().enumerate() {
            let v = base + (i as u64 + 1) * FRAME_SIZE;
            let leaf = unsafe { kernel_leaf(t, &cursor, v) }.unwrap().unwrap();
            assert_eq!(leaf & ADDR_MASK, *frame, "frame {i} at {v:#x}");
            assert!(leaf & PTE_PRESENT != 0 && leaf & PTE_WRITE != 0);
            assert!(leaf & PTE_NX != 0, "stacks are data, never code");
        }
        // Idempotency is not offered: remapping the same slot is an overlap.
        assert_eq!(
            unsafe { map_cpu_stack_in(t, &mut cursor, &image(), 1, &frames) },
            Err(VmError::Overlap)
        );
        // Out-of-range slots are refused before anything is written.
        assert_eq!(
            unsafe { map_cpu_stack_in(t, &mut cursor, &image(), MAX_AP_STACKS, &frames) },
            Err(VmError::BadAddress)
        );
        assert!(
            unsafe { kernel_leaf(t, &cursor, ap_stack_slot(MAX_AP_STACKS) + FRAME_SIZE) }
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn unmap_cpu_stack_clears_the_slot_and_is_atomic() {
        let (t, mut cursor) = built_tables_with_cursor();
        let base = ap_stack_slot(0);
        // Atomicity: one page missing means the whole request is refused.
        let frames = [0x50_0000, 0x50_1000, 0x50_2000, 0x50_3000];
        for i in [0usize, 2, 3] {
            let v = base + (i as u64 + 1) * FRAME_SIZE;
            unsafe {
                map_4k(
                    t,
                    &mut cursor,
                    &image(),
                    Domain::Kernel,
                    v,
                    frames[i],
                    PTE_PRESENT | PTE_WRITE,
                )
            }
            .unwrap();
        }
        assert_eq!(
            unsafe { unmap_cpu_stack_in(t, &cursor, 0) },
            Err(VmError::NotFound)
        );
        for i in [0usize, 2, 3] {
            let v = base + (i as u64 + 1) * FRAME_SIZE;
            assert!(
                unsafe { kernel_leaf(t, &cursor, v) }.unwrap().is_some(),
                "a refused unmap must not clear page {i}"
            );
        }
        // Fill the hole, then the whole slot is released.
        unsafe {
            map_4k(
                t,
                &mut cursor,
                &image(),
                Domain::Kernel,
                base + 2 * FRAME_SIZE,
                frames[1],
                PTE_PRESENT | PTE_WRITE,
            )
        }
        .unwrap();
        unsafe { unmap_cpu_stack_in(t, &cursor, 0) }.unwrap();
        for i in 0..AP_STACK_FRAMES {
            let v = base + (i as u64 + 1) * FRAME_SIZE;
            assert!(unsafe { kernel_leaf(t, &cursor, v) }.unwrap().is_none());
            // The leaf is written to zero, so no stale frame bits survive.
            let pt_phys = unsafe { (*t).kern_pd.entries[pd_index(v)] } & ADDR_MASK;
            assert!(pt_phys != 0, "the page table stays allocated");
            let pt = cursor.lookup(pt_phys).unwrap();
            assert_eq!(
                unsafe { (*pt).entries[pt_index(v)] },
                0,
                "the entry is cleared, not just made not-present"
            );
        }
        assert!(unsafe { kernel_leaf(t, &cursor, base) }.unwrap().is_none());
        // A second unmap finds nothing.
        assert_eq!(
            unsafe { unmap_cpu_stack_in(t, &cursor, 0) },
            Err(VmError::NotFound)
        );
        assert_eq!(
            unsafe { unmap_cpu_stack_in(t, &cursor, MAX_AP_STACKS) },
            Err(VmError::BadAddress)
        );
    }
}
