//! Physical memory manager (M2).
//!
//! Design (agents.md §7.3, M2 decisions):
//! - Only UEFI **conventional** (`type 7`) frames are allocatable; everything
//!   else (Loader allocations, boot services, ACPI, …) stays reserved.
//! - Hard 1 GiB ceiling: frames at or above 1 GiB physical are never handed
//!   out, which also bounds the `.bss` metadata arrays.
//! - Static state: a per-frame state byte plus a free stack of frame indices
//!   in `.bss`; no heap, no `alloc`.
//! - `alloc`/`dealloc` return `Result`. `dealloc` detects double frees and
//!   invalid frames. In debug builds `dealloc` poisons the frame with `0x5A`
//!   (through pluggable hooks, because the PMM must stay host-testable) and
//!   `alloc` of a previously-poisoned frame verifies the pattern.
//!
//! The generic `Pmm<CAP>` is the pure bookkeeping core; the kernel instantiates
//! `KERNEL_PMM` and wires the poison hooks to the direct map after the VM
//! takeover.
//!
//! # Concurrency (M6b2b)
//!
//! Every access to `KERNEL_PMM` goes through [`with_kernel_pmm`], which holds
//! `PMM_LOCK` — an [`crate::sync::IrqSpinLock`], i.e. local interrupts off *and*
//! exclusion of other CPUs. The lock is a **leaf**: the closures only touch
//! allocator bookkeeping and the (host-testable) poison hooks; they must never
//! call object/IPC/VFS code or take another kernel lock. `Pmm<CAP>` methods take
//! `&mut self` and are therefore not re-entrant, so the module-level wrappers
//! must not call each other while the lock is held.

pub const FRAME_SIZE: u64 = 4096;
/// Allocatable memory ceiling: 1 GiB.
pub const MAX_ALLOC_ADDR: u64 = 1 << 30;

const FREE: u8 = 0;
const USED: u8 = 1;
const FREE_POISONED: u8 = 2;
/// Frame handed out by [`Pmm::reserve`]: neither allocatable nor freeable until
/// [`Pmm::release`] returns it to the free stack. M6b1 keeps the low-memory AP
/// bring-up trampoline page alive this way for the duration of the SIPI window.
const RESERVED: u8 = 3;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PmmError {
    /// No free frame left.
    OutOfMemory,
    /// Address is not page aligned or outside the tracked range.
    InvalidFrame,
    /// Frame was already free (or never allocated).
    DoubleFree,
    /// Internal bookkeeping violated (bad stack entry, poison mismatch).
    Corruption,
}

pub type FrameHook = fn(u64);
pub type FrameCheck = fn(u64) -> bool;

/// Debug-only hooks (poison on free, verify on alloc). `None` in release and
/// on hosts without a direct map.
#[derive(Clone, Copy)]
pub struct PmmDebug {
    pub poison: Option<FrameHook>,
    pub check: Option<FrameCheck>,
}

impl PmmDebug {
    pub const fn none() -> Self {
        PmmDebug {
            poison: None,
            check: None,
        }
    }
}

pub struct Pmm<const CAP: usize> {
    state: [u8; CAP],
    free_stack: [u64; CAP],
    top: usize,
    free_count: u64,
    debug: PmmDebug,
}

impl<const CAP: usize> Pmm<CAP> {
    pub const fn new() -> Self {
        Pmm {
            state: [0; CAP],
            free_stack: [0; CAP],
            top: 0,
            free_count: 0,
            debug: PmmDebug::none(),
        }
    }

    pub fn set_debug(&mut self, debug: PmmDebug) {
        self.debug = debug;
    }

    /// Track every frame of `[base, base + len)` (page-aligned, clipped to the
    /// 1 GiB ceiling). Overlapping regions must not be added twice; the UEFI
    /// memory map is guaranteed non-overlapping.
    pub fn add_region(&mut self, base: u64, len: u64) -> Result<(), PmmError> {
        if len == 0 || base >= MAX_ALLOC_ADDR || base >= CAP as u64 * FRAME_SIZE {
            return Ok(());
        }
        let cap_end = (CAP as u64 * FRAME_SIZE).min(MAX_ALLOC_ADDR);
        let end = base.saturating_add(len).min(cap_end);
        let start_frame = base.div_ceil(FRAME_SIZE);
        let end_frame = end / FRAME_SIZE;
        for f in start_frame..end_frame {
            self.push_free(f)?;
        }
        Ok(())
    }

    fn push_free(&mut self, frame: u64) -> Result<(), PmmError> {
        let f = frame as usize;
        if f >= CAP || self.state[f] != FREE {
            return Err(PmmError::Corruption);
        }
        if self.top >= CAP {
            return Err(PmmError::Corruption);
        }
        self.state[f] = FREE;
        self.free_stack[self.top] = frame;
        self.top += 1;
        self.free_count += 1;
        Ok(())
    }

    pub fn alloc(&mut self) -> Result<u64, PmmError> {
        if self.top == 0 {
            return Err(PmmError::OutOfMemory);
        }
        self.top -= 1;
        let frame = self.free_stack[self.top];
        let f = frame as usize;
        if f >= CAP {
            return Err(PmmError::Corruption);
        }
        match self.state[f] {
            FREE_POISONED => {
                #[cfg(debug_assertions)]
                if let Some(check) = self.debug.check {
                    if !check(frame * FRAME_SIZE) {
                        self.top += 1; // push back
                        return Err(PmmError::Corruption);
                    }
                }
                self.state[f] = USED;
            }
            FREE => {
                self.state[f] = USED;
            }
            _ => {
                self.top += 1; // push back
                return Err(PmmError::Corruption);
            }
        }
        self.free_count -= 1;
        Ok(frame * FRAME_SIZE)
    }

    pub fn dealloc(&mut self, phys: u64) -> Result<(), PmmError> {
        if phys % FRAME_SIZE != 0 || phys >= CAP as u64 * FRAME_SIZE {
            return Err(PmmError::InvalidFrame);
        }
        let f = (phys / FRAME_SIZE) as usize;
        if self.state[f] != USED {
            return Err(PmmError::DoubleFree);
        }
        #[cfg(debug_assertions)]
        if let Some(poison) = self.debug.poison {
            poison(phys);
        }
        self.state[f] = FREE_POISONED;
        if self.top >= CAP {
            return Err(PmmError::Corruption);
        }
        self.free_stack[self.top] = phys / FRAME_SIZE;
        self.top += 1;
        self.free_count += 1;
        Ok(())
    }

    /// Whether `phys` is a frame this allocator currently holds as allocated.
    ///
    /// Only frames that were tracked by [`add_region`](Self::add_region) and are
    /// in the used state answer `true`: unaligned addresses, frames at or above
    /// the allocation ceiling, frames that were never added (early reserve,
    /// kernel image, boot services) and frames that are already free all answer
    /// `false`. Nothing is mutated.
    pub fn is_allocated(&self, phys: u64) -> bool {
        if phys % FRAME_SIZE != 0 || phys >= MAX_ALLOC_ADDR || phys >= CAP as u64 * FRAME_SIZE {
            return false;
        }
        self.state[(phys / FRAME_SIZE) as usize] == USED
    }

    /// Take a currently free frame out of the allocator entirely and mark it
    /// reserved.
    ///
    /// M6b1 needs one low conventional frame for the AP bring-up trampoline: it
    /// must survive the whole SIPI window (so no ordinary allocation may hand it
    /// out) and it must be returnable afterwards
    /// ([`release`](Self::release)). A reserved frame is neither allocatable nor
    /// freeable: it leaves the free stack, [`is_allocated`](Self::is_allocated)
    /// answers `false` for it (so a stray [`free_frame`] cannot hand it back) and
    /// [`dealloc`](Self::dealloc) rejects it.
    ///
    /// Only frames this allocator currently holds as *free* can be reserved:
    /// unaligned addresses, frames at or above the ceiling, frames that were
    /// never added, used frames and already-reserved frames all answer
    /// [`PmmError::InvalidFrame`] and change nothing. `PmmError` deliberately
    /// gains no variant for this — `mm/selftest.rs` matches it exhaustively.
    pub fn reserve(&mut self, phys: u64) -> Result<(), PmmError> {
        if phys % FRAME_SIZE != 0 || phys >= MAX_ALLOC_ADDR || phys >= CAP as u64 * FRAME_SIZE {
            return Err(PmmError::InvalidFrame);
        }
        let f = (phys / FRAME_SIZE) as usize;
        if self.state[f] != FREE {
            return Err(PmmError::InvalidFrame);
        }
        // The frame must still be on the free stack. A free-state frame that is
        // absent from it was never added to this allocator at all (a saved-map
        // region that `init` clipped to the address ceiling or dropped because
        // it overlapped the kernel image), so it is not ours to reserve — the
        // same answer as "already handed out". `reserve_low_page` relies on
        // this: it walks saved-map pages that the map calls conventional but
        // that this allocator may never have owned.
        let frame = phys / FRAME_SIZE;
        let mut slot = None;
        for i in 0..self.top {
            if self.free_stack[i] == frame {
                slot = Some(i);
                break;
            }
        }
        let Some(slot) = slot else {
            return Err(PmmError::InvalidFrame);
        };
        self.top -= 1;
        self.free_stack[slot] = self.free_stack[self.top];
        self.state[f] = RESERVED;
        self.free_count -= 1;
        Ok(())
    }

    /// Return a reserved frame to the free stack (exactly once).
    ///
    /// Anything that is not currently reserved — free, used, unaligned, out of
    /// range — is [`PmmError::InvalidFrame`] and changes nothing, so a duplicated
    /// release cannot corrupt the free stack.
    pub fn release(&mut self, phys: u64) -> Result<(), PmmError> {
        if phys % FRAME_SIZE != 0 || phys >= MAX_ALLOC_ADDR || phys >= CAP as u64 * FRAME_SIZE {
            return Err(PmmError::InvalidFrame);
        }
        let f = (phys / FRAME_SIZE) as usize;
        if self.state[f] != RESERVED {
            return Err(PmmError::InvalidFrame);
        }
        if self.top >= CAP {
            return Err(PmmError::Corruption);
        }
        self.state[f] = FREE;
        self.free_stack[self.top] = phys / FRAME_SIZE;
        self.top += 1;
        self.free_count += 1;
        Ok(())
    }

    /// Whether `phys` is a frame taken out of the allocator by
    /// [`reserve`](Self::reserve) and not yet released. Nothing is mutated.
    pub fn is_reserved(&self, phys: u64) -> bool {
        if phys % FRAME_SIZE != 0 || phys >= MAX_ALLOC_ADDR || phys >= CAP as u64 * FRAME_SIZE {
            return false;
        }
        self.state[(phys / FRAME_SIZE) as usize] == RESERVED
    }

    pub fn free_count(&self) -> u64 {
        self.free_count
    }
}

/// Number of trackable frames under the 1 GiB ceiling.
pub const KERNEL_MAX_FRAMES: usize = (MAX_ALLOC_ADDR / FRAME_SIZE) as usize;

pub static mut KERNEL_PMM: Pmm<KERNEL_MAX_FRAMES> = Pmm::new();

/// Frames the allocator took over in [`init`], frozen at the post-init baseline.
///
/// `sysinfo.totalram` asks "how much usable RAM does the machine have", not
/// "how much is free right now", so this is recorded once: loader/kernel
/// reserved regions, non-conventional descriptors and memory above the 1 GiB
/// ceiling never count (they were never allocatable), and the value does not
/// change when frames are allocated, freed or reserved afterwards.
static TOTAL_FRAMES: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

/// Leaf lock guarding every access to [`KERNEL_PMM`].
///
/// The allocator used to rely on "single CPU, interrupts off". M6b2 puts several
/// CPUs in the kernel at once, so a `cli` around the bookkeeping is no longer
/// enough: this lock also excludes the other CPUs.
static PMM_LOCK: crate::sync::IrqSpinLock = crate::sync::IrqSpinLock::new();

/// Run `f` with exclusive access to the kernel PMM.
///
/// The lock is a leaf. `f` may use the allocator and the debug hooks, but it
/// must not call back into any of this module's wrappers (the spin lock is not
/// re-entrant) and must not take another kernel lock or call into object/IPC/VFS
/// code.
fn with_kernel_pmm<R>(f: impl FnOnce(&mut Pmm<KERNEL_MAX_FRAMES>) -> R) -> R {
    PMM_LOCK.with(|| {
        // SAFETY: `with_kernel_pmm` is the only place that hands out
        // `&mut KERNEL_PMM`; it runs one closure at a time under `PMM_LOCK`, and
        // `KERNEL_PMM` lives in `.bss` for the whole kernel lifetime.
        f(unsafe { &mut *core::ptr::addr_of_mut!(KERNEL_PMM) })
    })
}

/// Install the debug poison hooks (direct-map backed). Must be called only
/// after the VM takeover, when [`crate::mm::vm::phys_to_virt`] is valid.
#[cfg(debug_assertions)]
pub fn set_kernel_debug_hooks() {
    fn poison(phys: u64) {
        unsafe {
            core::ptr::write_bytes(
                crate::mm::vm::phys_to_virt(phys) as *mut u8,
                0x5A,
                FRAME_SIZE as usize,
            )
        };
    }
    fn check(phys: u64) -> bool {
        let p = crate::mm::vm::phys_to_virt(phys) as *const u8;
        (0..FRAME_SIZE).all(|i| unsafe { *p.add(i as usize) } == 0x5A)
    }
    with_kernel_pmm(|pmm| {
        pmm.set_debug(PmmDebug {
            poison: Some(poison),
            check: Some(check),
        })
    });
}

/// Initialize the kernel PMM from the saved (pre-takeover) memory map:
/// conventional-only, 1 GiB ceiling, kernel image range excluded as
/// defense-in-depth (the loader allocates it as LoaderCode, so it should
/// never appear as conventional in the first place).
///
/// The post-init free count is frozen for [`total_frames`]: it is the same
/// baseline [`init`] reports as `added` on a fresh allocator, and it no longer
/// moves when frames are allocated or freed.
pub fn init(map: &crate::boot::SavedMap, image: &crate::boot::SavedImage) -> u64 {
    with_kernel_pmm(|pmm| {
        let mut added = 0u64;
        for i in 0..map.count {
            let r = map.regions[i];
            if r.ty != bootinfo::efi_desc::TYPE_CONVENTIONAL {
                continue;
            }
            // Exclude the kernel image physical range.
            let r_end = r.base + r.pages * FRAME_SIZE;
            let img_end = image.phys_base + image.phys_size;
            if r.base < img_end && r_end > image.phys_base {
                // Rare overlap: split is unnecessary for M2; conservatively
                // drop the whole descriptor rather than risk aliasing.
                continue;
            }
            let before = pmm.free_count();
            let _ = pmm.add_region(r.base, r.pages * FRAME_SIZE);
            added += pmm.free_count() - before;
        }
        // Freeze the post-init baseline. Recording it here instead of in
        // `add_region` keeps bare `Pmm` instances (host tests) free of global
        // state, and `free_count` is the allocator's real capacity at this
        // point — exactly the value `init` returns on a fresh PMM.
        TOTAL_FRAMES.store(pmm.free_count(), core::sync::atomic::Ordering::Release);
        added
    })
}

pub fn alloc_frame() -> Result<u64, PmmError> {
    with_kernel_pmm(|pmm| pmm.alloc())
}

pub fn dealloc_frame(phys: u64) -> Result<(), PmmError> {
    with_kernel_pmm(|pmm| pmm.dealloc(phys))
}

/// Release one frame obtained from [`alloc_frame`], answering `false` instead of
/// an error when `phys` is not a frame this PMM currently owns.
///
/// This is the idempotent form object teardown wants: M6a2 `SharedMemory` frees
/// its frames one at a time when the last handle goes away, and a bug there must
/// not panic the kernel or silently corrupt the free list. `false` means "this
/// frame was not an allocated conventional frame" — unaligned, at or above the
/// 1 GiB ceiling, never added by [`init`]/[`Pmm::add_region`] (early reserve,
/// kernel image, static pages) or already free (double free) — and **nothing is
/// mutated** in that case, so the allocator keeps its previous state.
///
/// Runs under [`PMM_LOCK`] like every other entry point, so it is safe from any
/// CPU in thread context; the lock is a leaf and must not be re-entered.
pub fn free_frame(phys: u64) -> bool {
    with_kernel_pmm(|pmm| {
        // Pre-check so a refusal cannot leave a half-updated free list behind:
        // `dealloc` validates too, but only after it starts mutating nothing at
        // all — the check makes that guarantee local and explicit.
        if !pmm.is_allocated(phys) {
            return false;
        }
        pmm.dealloc(phys).is_ok()
    })
}

/// Reserve one frame owned by the kernel PMM (see [`Pmm::reserve`]).
///
/// Runs under [`PMM_LOCK`] like every other entry point; the lock is a leaf.
pub fn reserve_frame(phys: u64) -> Result<(), PmmError> {
    with_kernel_pmm(|pmm| pmm.reserve(phys))
}

/// Return a frame reserved with [`reserve_frame`], answering `false` instead of
/// an error when `phys` is not a frame this PMM currently holds as reserved.
///
/// Like [`free_frame`], a `false` answer mutates nothing, so a duplicated or
/// bogus release cannot corrupt the free stack.
pub fn release_frame(phys: u64) -> bool {
    with_kernel_pmm(|pmm| {
        if !pmm.is_reserved(phys) {
            return false;
        }
        pmm.release(phys).is_ok()
    })
}

/// Whether the kernel PMM currently holds `phys` as reserved. Nothing is
/// mutated; the answer is taken under [`PMM_LOCK`] so it is a consistent
/// snapshot on any CPU.
pub fn is_reserved(phys: u64) -> bool {
    with_kernel_pmm(|pmm| pmm.is_reserved(phys))
}

/// Whether `page` (4 KiB aligned) lies completely inside one conventional
/// (type 7) descriptor of the saved memory map.
///
/// This mirrors what [`init`] actually tracks: a page only becomes allocatable
/// when a whole frame of it sits inside a conventional descriptor, so the
/// candidate predicate has to use the same "completely inside" rule.
fn page_is_conventional(map: &crate::boot::SavedMap, page: u64) -> bool {
    for i in 0..map.count {
        let r = map.regions[i];
        if r.ty != bootinfo::efi_desc::TYPE_CONVENTIONAL {
            continue;
        }
        let end = r.base.saturating_add(r.pages.saturating_mul(FRAME_SIZE));
        if page >= r.base && page.saturating_add(FRAME_SIZE) <= end {
            return true;
        }
    }
    false
}

/// Walk the low-memory window and let `try_reserve` claim the first page it
/// accepts, in ascending address order.
///
/// The scan starts at 4 KiB, not at 0: the real-mode IVT/BDA page is a fixed
/// architectural hazard (firmware routinely reports it as conventional), and it
/// is the only address this code assumes. Everything else comes from the saved
/// memory map, so no trampoline address is hard coded.
///
/// Split out from [`reserve_low_page`] so host tests can exercise the selection
/// rules (ordering, conventional filter, ceiling, refusals) with a plain closure
/// and no global allocator state. The closure answers `Ok(true)` to claim a
/// candidate, `Ok(false)` to skip it, or `Err(_)` to abort the scan — a
/// bookkeeping error must not be reported as "no usable page".
pub(crate) fn scan_low_page<F>(
    map: &crate::boot::SavedMap,
    ceiling: u64,
    mut try_reserve: F,
) -> Result<u64, PmmError>
where
    F: FnMut(u64) -> Result<bool, PmmError>,
{
    const FIRST_SAFE_PAGE: u64 = FRAME_SIZE;
    let limit = ceiling.min(MAX_ALLOC_ADDR);
    let mut page = FIRST_SAFE_PAGE;
    while page.saturating_add(FRAME_SIZE) <= limit {
        if page_is_conventional(map, page) && try_reserve(page)? {
            return Ok(page);
        }
        page += FRAME_SIZE;
    }
    // `InvalidFrame` is the closest existing variant ("no usable frame"); adding
    // a dedicated variant would break the exhaustive match in `mm/selftest.rs`.
    Err(PmmError::InvalidFrame)
}

/// Reserve the lowest still-free conventional frame below `ceiling` and answer
/// its physical address.
///
/// M6b1 uses this for the AP bring-up trampoline: the SIPI startup vector is an
/// 8-bit page number, so the page must be below 1 MiB
/// ([`crate::mm::vm::SIPI_MAX_PHYS`]), and it has to be a page the kernel really
/// owns — derived from the saved memory map, never a hard-coded address.
///
/// The frame comes back **reserved**: ordinary allocations cannot hand it out
/// until the caller returns it with [`release_frame`]. Failure to find any usable
/// low conventional page is [`PmmError::InvalidFrame`] and changes nothing.
pub fn reserve_low_page(map: &crate::boot::SavedMap, ceiling: u64) -> Result<u64, PmmError> {
    // One lock for the whole scan: the candidate closure only touches `pmm`, so
    // it never re-enters a wrapper (the lock is not re-entrant).
    with_kernel_pmm(|pmm| {
        scan_low_page(map, ceiling, |page| match pmm.reserve(page) {
            Ok(()) => Ok(true),
            // A page the map calls conventional but that this allocator does not
            // actually own (already handed out, or dropped by `init` because it
            // overlapped the kernel image) is simply skipped: a later candidate
            // may still work, per `scan_low_page`'s "first accepted page wins".
            Err(PmmError::InvalidFrame) => Ok(false),
            // Anything else (`Corruption`) means the free stack disagrees with
            // the frame states; surface it instead of scanning on over rot.
            Err(err) => Err(err),
        })
    })
}

pub fn free_frames() -> u64 {
    with_kernel_pmm(|pmm| pmm.free_count())
}

/// Total frames the kernel PMM took over at [`init`] (its free baseline).
///
/// This is "usable RAM" for `sysinfo.totalram`: reserved, non-conventional and
/// above-ceiling memory is not counted, and the value stays fixed afterwards
/// (only [`free_frames`] follows allocations). Returns 0 before [`init`].
pub fn total_frames() -> u64 {
    TOTAL_FRAMES.load(core::sync::atomic::Ordering::Acquire)
}

// ---------------------------------------------------------------------------
// Tests (host)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    use std::vec::Vec;

    /// Backing stores for poison hooks: one per hook-using test so parallel
    /// test threads never observe each other's patterns.
    static MEM_A: Mutex<[u8; 16 * 1024]> = Mutex::new([0u8; 16 * 1024]);
    static MEM_B: Mutex<[u8; 16 * 1024]> = Mutex::new([0u8; 16 * 1024]);

    fn poison_a(phys: u64) {
        let mut m = MEM_A.lock().unwrap();
        let len = m.len();
        for i in 0..FRAME_SIZE as usize {
            m[(phys as usize + i) % len] = 0x5A;
        }
    }
    fn check_a(phys: u64) -> bool {
        let m = MEM_A.lock().unwrap();
        let len = m.len();
        (0..FRAME_SIZE as usize).all(|i| m[(phys as usize + i) % len] == 0x5A)
    }
    fn poison_b(phys: u64) {
        let mut m = MEM_B.lock().unwrap();
        let len = m.len();
        for i in 0..FRAME_SIZE as usize {
            m[(phys as usize + i) % len] = 0x5A;
        }
    }
    fn check_b(phys: u64) -> bool {
        let m = MEM_B.lock().unwrap();
        let len = m.len();
        (0..FRAME_SIZE as usize).all(|i| m[(phys as usize + i) % len] == 0x5A)
    }

    fn pmm_with_region() -> Pmm<8> {
        let mut p = Pmm::<8>::new();
        p.add_region(0x1000, 4 * FRAME_SIZE).unwrap(); // frames 1..4
        p
    }

    #[test]
    fn add_region_clips_to_cap() {
        let mut p = Pmm::<4>::new();
        p.add_region(0, 16 * FRAME_SIZE).unwrap(); // only 4 frames fit
        assert_eq!(p.free_count(), 4);
        let mut p2 = Pmm::<8>::new();
        p2.add_region(MAX_ALLOC_ADDR, FRAME_SIZE).unwrap(); // above ceiling: ignored
        assert_eq!(p2.free_count(), 0);
    }

    #[test]
    fn alloc_dealloc_restores_free_count() {
        let mut p = pmm_with_region();
        let before = p.free_count();
        let frames: Vec<u64> = (0..4).map(|_| p.alloc().unwrap()).collect();
        assert_eq!(p.free_count(), 0);
        assert!(p.alloc().is_err()); // exhausted
        for &f in &frames {
            p.dealloc(f).unwrap();
        }
        assert_eq!(p.free_count(), before);
    }

    #[test]
    fn dealloc_detects_double_free_and_bad_frames() {
        let mut p = pmm_with_region();
        assert_eq!(p.dealloc(0x2000), Err(PmmError::DoubleFree)); // never allocated
        let f = p.alloc().unwrap();
        p.dealloc(f).unwrap();
        assert_eq!(p.dealloc(f), Err(PmmError::DoubleFree));
        assert_eq!(p.dealloc(f + 1), Err(PmmError::InvalidFrame)); // unaligned
        assert_eq!(p.dealloc(0x1000_0000), Err(PmmError::InvalidFrame)); // out of range
    }

    #[test]
    fn alloc_frames_are_distinct_and_aligned() {
        let mut p = pmm_with_region();
        let mut seen = Vec::new();
        for _ in 0..4 {
            let f = p.alloc().unwrap();
            assert_eq!(f % FRAME_SIZE, 0);
            assert!(!seen.contains(&f));
            seen.push(f);
        }
    }

    #[test]
    fn debug_poison_verified_on_realloc() {
        let mut p = pmm_with_region();
        p.set_debug(PmmDebug {
            poison: Some(poison_a),
            check: Some(check_a),
        });
        let f = p.alloc().unwrap(); // pops frame 4
        p.dealloc(f).unwrap(); // poisons frame 4 via hook
        assert!(check_a(f));
        let g = p.alloc().unwrap(); // pops frame 4 again; poison must verify
        assert_eq!(f, g, "LIFO free stack should hand back the same frame");
        p.dealloc(g).unwrap();
    }

    #[test]
    fn poison_violation_is_corruption() {
        let mut p = pmm_with_region();
        p.set_debug(PmmDebug {
            poison: Some(poison_b),
            check: Some(check_b),
        });
        let a = p.alloc().unwrap();
        let _b = p.alloc().unwrap();
        let _c = p.alloc().unwrap();
        let _d = p.alloc().unwrap();
        p.dealloc(a).unwrap(); // poison frame 4, push it back on top
        {
            let mut m = MEM_B.lock().unwrap();
            let at = (a as usize + 7) % m.len();
            m[at] = 0x00; // clobber one poison byte
        }
        assert_eq!(p.alloc(), Err(PmmError::Corruption));
        // Restore the pattern so the frame can be reused cleanly.
        {
            let mut m = MEM_B.lock().unwrap();
            let at = (a as usize + 7) % m.len();
            m[at] = 0x5A;
        }
        let fresh = p.alloc().unwrap();
        p.dealloc(fresh).unwrap();
    }

    #[test]
    fn is_allocated_tracks_the_frame_state() {
        let mut p = pmm_with_region();
        assert!(!p.is_allocated(0x1000), "free frames are not allocated");
        let f = p.alloc().unwrap();
        assert!(p.is_allocated(f));
        p.dealloc(f).unwrap();
        assert!(!p.is_allocated(f));
        assert!(!p.is_allocated(f + 1), "unaligned");
        assert!(!p.is_allocated(0x1000_0000), "out of range");
        assert!(!p.is_allocated(MAX_ALLOC_ADDR), "at the ceiling");
    }

    /// The kernel PMM is process-wide: the two tests below serialise on it.
    static GLOBAL_LOCK: Mutex<()> = Mutex::new(());

    fn kernel_pmm() -> *mut Pmm<KERNEL_MAX_FRAMES> {
        core::ptr::addr_of_mut!(KERNEL_PMM)
    }

    #[test]
    fn free_frame_round_trips_and_refuses_bad_frames() {
        let _guard = GLOBAL_LOCK.lock().unwrap_or_else(|err| err.into_inner());
        const BASE: u64 = 0x3000_0000;

        // SAFETY: GLOBAL_LOCK serialises every host-test user of the static PMM,
        // and no test dereferences the frames below 1 GiB it hands out.
        unsafe { (*kernel_pmm()).add_region(BASE, 2 * FRAME_SIZE).unwrap() };
        let free_after_region = free_frames();
        assert!(free_after_region >= 2);

        let frame = alloc_frame().expect("frame");
        assert_eq!(free_frames(), free_after_region - 1);
        // SAFETY: as above.
        assert!(unsafe { (*kernel_pmm()).is_allocated(frame) });

        // Unaligned, reserved, never-added and out-of-range frames are refused
        // and leave the bookkeeping exactly as it was.
        assert!(!free_frame(frame + 1), "unaligned");
        assert!(!free_frame(0), "frame zero was never tracked");
        assert!(
            !free_frame(BASE + 32 * FRAME_SIZE),
            "below the ceiling but never added"
        );
        assert!(!free_frame(MAX_ALLOC_ADDR), "at the ceiling");
        assert_eq!(
            free_frames(),
            free_after_region - 1,
            "refusals must not mutate the allocator"
        );

        assert!(free_frame(frame));
        assert_eq!(free_frames(), free_after_region);
        // SAFETY: as above.
        assert!(!unsafe { (*kernel_pmm()).is_allocated(frame) });

        // A double free is refused, and the frame is still reusable afterwards.
        assert!(!free_frame(frame), "double free");
        assert_eq!(free_frames(), free_after_region);
        let again = alloc_frame().expect("frame is reusable");
        assert_eq!(again, frame, "LIFO free stack hands the frame back");
        assert!(free_frame(again));
        assert_eq!(free_frames(), free_after_region);
    }

    #[test]
    fn reserve_frame_takes_the_frame_out_of_the_free_list() {
        let mut p = pmm_with_region(); // frames 0x1000..0x4000
        let before = p.free_count();
        p.reserve(0x2000).unwrap();
        assert_eq!(p.free_count(), before - 1);
        assert!(p.is_reserved(0x2000));
        assert!(!p.is_allocated(0x2000), "reserved frames are not allocated");
        let mut got = Vec::new();
        for _ in 0..before - 1 {
            got.push(p.alloc().unwrap());
        }
        assert!(
            !got.contains(&0x2000),
            "a reserved frame must never be handed out"
        );
        assert!(p.alloc().is_err(), "the free stack is otherwise drained");
    }

    #[test]
    fn reserve_refuses_bad_and_duplicate_requests() {
        let mut p = pmm_with_region();
        let before = p.free_count();
        assert_eq!(p.reserve(0x1001), Err(PmmError::InvalidFrame), "unaligned");
        assert_eq!(
            p.reserve(MAX_ALLOC_ADDR),
            Err(PmmError::InvalidFrame),
            "ceiling"
        );
        assert_eq!(
            p.reserve(0x8000),
            Err(PmmError::InvalidFrame),
            "never added"
        );
        p.reserve(0x3000).unwrap();
        assert_eq!(
            p.reserve(0x3000),
            Err(PmmError::InvalidFrame),
            "already reserved"
        );
        let used = p.alloc().unwrap();
        assert_eq!(p.reserve(used), Err(PmmError::InvalidFrame), "used frame");
        assert_eq!(
            p.free_count(),
            before - 2,
            "refusals must not mutate the allocator"
        );
    }

    #[test]
    fn reserved_frames_are_neither_allocatable_nor_freeable() {
        let mut p = pmm_with_region();
        p.reserve(0x1000).unwrap();
        assert!(!p.is_allocated(0x1000));
        assert_eq!(p.dealloc(0x1000), Err(PmmError::DoubleFree));
        assert!(p.is_reserved(0x1000), "the refusal left the state alone");
        let mut got = Vec::new();
        for _ in 0..3 {
            got.push(p.alloc().unwrap());
        }
        assert!(!got.contains(&0x1000));
        assert!(p.alloc().is_err());
        p.release(0x1000).unwrap();
        assert_eq!(
            p.alloc(),
            Ok(0x1000),
            "a released frame is allocatable again"
        );
    }

    #[test]
    fn release_returns_the_frame_exactly_once() {
        let mut p = pmm_with_region();
        let before = p.free_count();
        p.reserve(0x4000).unwrap();
        assert_eq!(p.free_count(), before - 1);
        assert_eq!(p.release(0x4000), Ok(()));
        assert_eq!(p.free_count(), before);
        assert!(!p.is_reserved(0x4000));
        assert_eq!(
            p.release(0x4000),
            Err(PmmError::InvalidFrame),
            "a second release is refused"
        );
        assert_eq!(
            p.release(0x1000),
            Err(PmmError::InvalidFrame),
            "a free frame was never reserved"
        );
        assert_eq!(p.free_count(), before, "refusals must not mutate");
        assert_eq!(
            p.alloc(),
            Ok(0x4000),
            "the released frame is back on the stack"
        );
    }

    fn low_map(regions: &[(u64, u64, u32)]) -> crate::boot::SavedMap {
        let mut map = crate::boot::SavedMap::empty();
        for (i, &(base, pages, ty)) in regions.iter().enumerate() {
            map.regions[i] = crate::boot::SavedRegion { base, pages, ty };
        }
        map.count = regions.len();
        map
    }

    const CONVENTIONAL: u32 = bootinfo::efi_desc::TYPE_CONVENTIONAL;
    const RESERVED_TYPE: u32 = 2; // EfiReservedMemoryType

    #[test]
    fn scan_low_page_picks_the_lowest_conventional_page() {
        // [0, 0x9F000) is conventional; the IVT/BDA page must still be skipped.
        let map = low_map(&[(0, 0x9F, CONVENTIONAL)]);
        let mut tried = Vec::new();
        let page = scan_low_page(&map, 0x10_0000, |p| {
            tried.push(p);
            Ok(true)
        })
        .unwrap();
        assert_eq!(page, FRAME_SIZE, "page zero is never a candidate");
        assert_eq!(tried, Vec::from([FRAME_SIZE]));

        // Refusals advance the scan, so the first *claimable* page wins.
        let mut tried = Vec::new();
        let page = scan_low_page(&map, 0x10_0000, |p| {
            tried.push(p);
            Ok(p >= 0x3000)
        })
        .unwrap();
        assert_eq!(page, 0x3000);
        assert_eq!(tried, Vec::from([0x1000, 0x2000, 0x3000]));

        // Non-conventional descriptors are filtered out before the claim runs.
        let map = low_map(&[(0x1000, 1, RESERVED_TYPE), (0x2000, 2, CONVENTIONAL)]);
        let mut tried = Vec::new();
        let page = scan_low_page(&map, 0x10_0000, |p| {
            tried.push(p);
            Ok(true)
        })
        .unwrap();
        assert_eq!(page, 0x2000);
        assert_eq!(tried, Vec::from([0x2000]));
    }

    #[test]
    fn scan_low_page_propagates_bookkeeping_errors() {
        let map = low_map(&[(0, 0x9F, CONVENTIONAL)]);
        // A closure error must abort the scan and reach the caller: swallowing it
        // would hide free-stack corruption behind a "no page" answer.
        let mut tried = Vec::new();
        assert_eq!(
            scan_low_page(&map, 0x10_0000, |p| {
                tried.push(p);
                if p == 0x2000 {
                    Err(PmmError::Corruption)
                } else {
                    Ok(false)
                }
            }),
            Err(PmmError::Corruption)
        );
        assert_eq!(tried, Vec::from([0x1000, 0x2000]));
    }

    #[test]
    fn scan_low_page_respects_the_ceiling_and_reports_no_page() {
        let map = low_map(&[(0, 0x9F, CONVENTIONAL)]);
        // A page must fit completely below the ceiling.
        assert_eq!(
            scan_low_page(&map, FRAME_SIZE, |_| Ok(true)),
            Err(PmmError::InvalidFrame)
        );
        assert_eq!(
            scan_low_page(&map, 0x1000, |_| Ok(true)),
            Err(PmmError::InvalidFrame)
        );
        // Nothing conventional at all.
        let map = low_map(&[(0x1000, 4, RESERVED_TYPE), (0x9000, 4, 9)]);
        assert_eq!(
            scan_low_page(&map, 0x10_0000, |_| Ok(true)),
            Err(PmmError::InvalidFrame)
        );
        // A conventional descriptor that lies entirely above the ceiling.
        let map = low_map(&[(0x20_0000, 4, CONVENTIONAL)]);
        assert_eq!(
            scan_low_page(&map, 0x10_0000, |_| Ok(true)),
            Err(PmmError::InvalidFrame)
        );
    }

    #[test]
    fn reserve_low_page_claims_a_real_low_frame_and_returns_it() {
        let _guard = GLOBAL_LOCK.lock().unwrap_or_else(|err| err.into_inner());
        // Only 0x4000 is tracked by the PMM, while the map claims 0x1000..0x5000
        // is conventional: the scan has to walk past the untracked pages.
        const LOW: u64 = 0x4000;
        // SAFETY: GLOBAL_LOCK serialises every host-test user of the static PMM.
        unsafe { (*kernel_pmm()).add_region(LOW, FRAME_SIZE).unwrap() };
        let map = low_map(&[(0x1000, 4, CONVENTIONAL)]);
        let before = free_frames();
        let page = reserve_low_page(&map, 0x10_0000).expect("low conventional frame");
        assert_eq!(
            page, LOW,
            "the page must come from the saved map, not a constant"
        );
        assert_eq!(free_frames(), before - 1);
        assert!(is_reserved(page));
        assert!(!free_frame(page), "reserved frames are not allocated");
        assert_eq!(free_frames(), before - 1, "a refusal must not mutate");
        assert!(release_frame(page));
        assert_eq!(free_frames(), before);
        assert!(!is_reserved(page));
        assert!(!release_frame(page), "release happens exactly once");
    }

    #[test]
    fn total_frames_is_the_post_init_baseline_and_ignores_later_allocations() {
        let _guard = GLOBAL_LOCK.lock().unwrap_or_else(|err| err.into_inner());
        // Conventional and in range: taken over. The other two descriptors must
        // not contribute (reserved), or are conventional but above the 1 GiB
        // allocatable ceiling and therefore dropped by `add_region`.
        let map = low_map(&[
            (0x2000_0000, 4, CONVENTIONAL),
            (0x1000, 1, RESERVED_TYPE),
            (MAX_ALLOC_ADDR, 1, CONVENTIONAL),
        ]);
        let image = crate::boot::SavedImage {
            phys_base: 0x1000_0000,
            phys_size: FRAME_SIZE,
            virt_base: 0xFFFF_FFFF_8000_0000,
            virt_size: FRAME_SIZE,
            entry: 0xFFFF_FFFF_8000_0000,
        };
        let before = free_frames();
        let added = init(&map, &image);
        assert_eq!(added, 4, "only the in-range conventional descriptor counts");
        assert_eq!(free_frames(), before + added);
        let baseline = total_frames();
        assert_eq!(
            baseline,
            free_frames(),
            "the total is the post-init free baseline"
        );

        // Allocation only moves the free count; the total stays put.
        let frame = alloc_frame().expect("frame");
        assert_eq!(free_frames(), baseline - 1);
        assert_eq!(total_frames(), baseline, "allocation must not change it");
        dealloc_frame(frame).expect("frame back");
        assert_eq!(free_frames(), baseline);
        assert_eq!(total_frames(), baseline);

        // Re-initialising records the new baseline rather than accumulating
        // (production calls `init` once; the test pins the "constant" contract).
        let map = low_map(&[(0x2100_0000, 2, CONVENTIONAL)]);
        let added = init(&map, &image);
        assert_eq!(added, 2);
        assert_eq!(total_frames(), free_frames());
        assert_eq!(total_frames(), baseline + 2);
    }
}
