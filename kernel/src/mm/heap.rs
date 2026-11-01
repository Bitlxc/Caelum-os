//! Kernel heap (M2): explicit API, no `GlobalAlloc`.
//!
//! - Size classes 16..=2048 (powers of two); requests above 2048 bytes are
//!   "large" and occupy whole 4 KiB frames (`frames = ceil((size+header)/4096)`).
//! - Every block carries a 16-byte header with a magic number; `dealloc`
//!   validates it (heap-corruption detection).
//! - Debug builds poison the data area with `0x5A` on `dealloc` and verify
//!   the pattern when a block is reused from a free list.
//! - Statistics: allocations, frees, current and peak bytes in use.
//! - OOM is a normal `Err(HeapError::OutOfMemory)` — never a panic.
//!
//! The heap carves a single contiguous region (kernel `.bss` in production,
//! any backing buffer in host tests), so it needs no PMM frames and no
//! third-party allocator.
//!
//! # Concurrency (M6b2b)
//!
//! The kernel instance ([`KERNEL_HEAP`]) is reached only through
//! [`with_kernel_heap`], which holds `HEAP_LOCK` — a
//! [`crate::sync::IrqSpinLock`] (local interrupts off *and* cross-CPU
//! exclusion). It is a **leaf** lock: the closure may only touch heap
//! bookkeeping. Never call back into [`alloc`]/[`dealloc`]/[`stats`] from
//! inside it, and never take another kernel lock while holding it.

pub const SIZE_CLASSES: [usize; 8] = [16, 32, 64, 128, 256, 512, 1024, 2048];
const LARGE_CLASS: u8 = 0xFF;
const HEADER_MAGIC: u32 = 0xCAEA_0001;
const HEADER_SIZE: usize = 16;
const FRAME: usize = 4096;
/// Maximum request served by the size-class path.
const MAX_SMALL: usize = SIZE_CLASSES[SIZE_CLASSES.len() - 1];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HeapError {
    /// `init` was never called.
    NotInitialized,
    /// Zero size or an alignment above 16 (the heap guarantees 16).
    BadRequest,
    /// Region and free lists are exhausted.
    OutOfMemory,
    /// Block header magic mismatch (memory corruption or bad pointer).
    Corrupted,
    /// Pointer outside the heap region.
    InvalidFree,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct HeapStats {
    pub allocs: u64,
    pub frees: u64,
    pub current_bytes: usize,
    pub peak_bytes: usize,
}

#[repr(C)]
struct BlockHeader {
    magic: u32,
    class: u8,
    reserved: u8,
    frames: u16,
    pad: [u8; 8],
}

impl BlockHeader {
    /// Free-list link storage while the block is on a free list (`pad` is
    /// otherwise unused, keeping the whole data area poisonable).
    fn next(&self) -> usize {
        usize::from_le_bytes(self.pad.try_into().unwrap())
    }
    fn set_next(&mut self, next: usize) {
        self.pad = next.to_le_bytes();
    }
}

pub struct Heap {
    start: usize,
    size: usize,
    bump: usize,
    free_lists: [usize; SIZE_CLASSES.len()],
    large_free: usize,
    stats: HeapStats,
}

impl Heap {
    pub const fn new() -> Self {
        Heap {
            start: 0,
            size: 0,
            bump: 0,
            free_lists: [0; SIZE_CLASSES.len()],
            large_free: 0,
            stats: HeapStats {
                allocs: 0,
                frees: 0,
                current_bytes: 0,
                peak_bytes: 0,
            },
        }
    }

    /// Adopt `[region, region + size)` as the heap region. Must be called
    /// once before any allocation.
    ///
    /// # Safety
    /// The region must be writable and exclusively owned by the heap for its
    /// lifetime.
    pub unsafe fn init(&mut self, region: *mut u8, size: usize) -> Result<(), HeapError> {
        if region.is_null() || size < HEADER_SIZE + SIZE_CLASSES[0] {
            return Err(HeapError::BadRequest);
        }
        if region as usize % 16 != 0 {
            return Err(HeapError::BadRequest);
        }
        self.start = region as usize;
        self.size = size;
        self.bump = 0;
        self.free_lists = [0; SIZE_CLASSES.len()];
        self.large_free = 0;
        self.stats = HeapStats::default();
        Ok(())
    }

    fn class_for(size: usize) -> Option<usize> {
        SIZE_CLASSES.iter().position(|&c| c >= size)
    }

    /// Allocate `size` bytes with 16-byte alignment.
    pub fn alloc(&mut self, size: usize, align: usize) -> Result<*mut u8, HeapError> {
        if self.start == 0 {
            return Err(HeapError::NotInitialized);
        }
        if size == 0 || size > u16::MAX as usize * FRAME {
            return Err(HeapError::BadRequest);
        }
        if align > 16 {
            return Err(HeapError::BadRequest);
        }
        if size <= MAX_SMALL {
            self.alloc_small(size)
        } else {
            self.alloc_large(size)
        }
    }

    fn alloc_small(&mut self, size: usize) -> Result<*mut u8, HeapError> {
        let class = Self::class_for(size).ok_or(HeapError::OutOfMemory)?;
        let block = self.free_lists[class];
        let (ptr, capacity) = if block != 0 {
            let header = block as *mut BlockHeader;
            unsafe {
                self.free_lists[class] = (*header).next();
            }
            #[cfg(debug_assertions)]
            self.verify_poison(block as *mut u8, SIZE_CLASSES[class])?;
            unsafe {
                (*header).magic = HEADER_MAGIC;
                (*header).class = class as u8;
                (*header).frames = 0;
                (*header).pad = [0; 8];
            }
            (block as *mut u8, SIZE_CLASSES[class])
        } else {
            let total = HEADER_SIZE + SIZE_CLASSES[class];
            let off = self.bump.checked_add(total).ok_or(HeapError::OutOfMemory)?;
            if off > self.size {
                return Err(HeapError::OutOfMemory);
            }
            self.bump = off;
            let block = (self.start + off - total) as *mut u8;
            let header = block as *mut BlockHeader;
            unsafe {
                (*header).magic = HEADER_MAGIC;
                (*header).class = class as u8;
                (*header).reserved = 0;
                (*header).frames = 0;
                (*header).pad = [0; 8];
            }
            (block, SIZE_CLASSES[class])
        };
        self.stats.allocs += 1;
        self.stats.current_bytes += capacity;
        if self.stats.current_bytes > self.stats.peak_bytes {
            self.stats.peak_bytes = self.stats.current_bytes;
        }
        Ok(unsafe { ptr.add(HEADER_SIZE) })
    }

    fn alloc_large(&mut self, size: usize) -> Result<*mut u8, HeapError> {
        let frames = (size + HEADER_SIZE + FRAME - 1) / FRAME;
        if frames > u16::MAX as usize {
            return Err(HeapError::BadRequest);
        }
        // Exact-size reuse from the large free list (free-list link lives in
        // the block header's `pad`, so the whole data area stays poisonable).
        let mut prev = 0usize;
        let mut cur = self.large_free;
        while cur != 0 {
            let header = cur as *mut BlockHeader;
            let (next, block_frames) = unsafe { ((*header).next(), (*header).frames) };
            if block_frames as usize == frames {
                if prev == 0 {
                    self.large_free = next;
                } else {
                    let prev_header = prev as *mut BlockHeader;
                    unsafe { (*prev_header).set_next(next) };
                }
                #[cfg(debug_assertions)]
                self.verify_poison(cur as *mut u8, frames * FRAME - HEADER_SIZE)?;
                unsafe {
                    (*header).magic = HEADER_MAGIC;
                    (*header).class = LARGE_CLASS;
                    (*header).frames = frames as u16;
                }
                self.stats.allocs += 1;
                self.stats.current_bytes += frames * FRAME;
                if self.stats.current_bytes > self.stats.peak_bytes {
                    self.stats.peak_bytes = self.stats.current_bytes;
                }
                return Ok(unsafe { (cur as *mut u8).add(HEADER_SIZE) });
            }
            prev = cur;
            cur = next;
        }
        let total = frames * FRAME;
        let off = self.bump.checked_add(total).ok_or(HeapError::OutOfMemory)?;
        if off > self.size {
            return Err(HeapError::OutOfMemory);
        }
        self.bump = off;
        let block = (self.start + off - total) as *mut u8;
        let header = block as *mut BlockHeader;
        unsafe {
            (*header).magic = HEADER_MAGIC;
            (*header).class = LARGE_CLASS;
            (*header).reserved = 0;
            (*header).frames = frames as u16;
            (*header).pad = [0; 8];
        }
        self.stats.allocs += 1;
        self.stats.current_bytes += total;
        if self.stats.current_bytes > self.stats.peak_bytes {
            self.stats.peak_bytes = self.stats.current_bytes;
        }
        Ok(unsafe { block.add(HEADER_SIZE) })
    }

    /// Free a block previously returned by [`Heap::alloc`].
    ///
    /// # Safety
    /// `ptr` must come from this heap and not be freed twice.
    pub unsafe fn dealloc(&mut self, ptr: *mut u8) -> Result<(), HeapError> {
        if self.start == 0 {
            return Err(HeapError::NotInitialized);
        }
        let p = ptr as usize;
        if p < self.start + HEADER_SIZE || p >= self.start + self.size {
            return Err(HeapError::InvalidFree);
        }
        let block = p - HEADER_SIZE;
        let header = block as *mut BlockHeader;
        unsafe {
            if (*header).magic != HEADER_MAGIC {
                return Err(HeapError::Corrupted);
            }
            let class = (*header).class;
            match class {
                c if (c as usize) < SIZE_CLASSES.len() => {
                    let c = c as usize;
                    #[cfg(debug_assertions)]
                    self.poison(block as *mut u8, SIZE_CLASSES[c]);
                    let head = self.free_lists[c];
                    (*header).set_next(head);
                    self.free_lists[c] = block;
                    self.stats.current_bytes -= SIZE_CLASSES[c];
                }
                LARGE_CLASS => {
                    let frames = (*header).frames as usize;
                    let total = frames * FRAME;
                    #[cfg(debug_assertions)]
                    self.poison(block as *mut u8, total - HEADER_SIZE);
                    let head = self.large_free;
                    (*header).set_next(head);
                    self.large_free = block;
                    self.stats.current_bytes -= total;
                }
                _ => return Err(HeapError::Corrupted),
            }
        }
        self.stats.frees += 1;
        Ok(())
    }

    pub fn stats(&self) -> HeapStats {
        self.stats
    }

    #[cfg(debug_assertions)]
    fn poison(&self, block: *mut u8, data_len: usize) {
        unsafe { core::ptr::write_bytes(block.add(HEADER_SIZE), 0x5A, data_len) };
    }

    #[cfg(debug_assertions)]
    fn verify_poison(&self, block: *mut u8, data_len: usize) -> Result<(), HeapError> {
        let data = unsafe { core::slice::from_raw_parts(block.add(HEADER_SIZE), data_len) };
        if data.iter().all(|&b| b == 0x5A) {
            Ok(())
        } else {
            Err(HeapError::Corrupted)
        }
    }
}

// ---------------------------------------------------------------------------
// Kernel instance
// ---------------------------------------------------------------------------

pub const KERNEL_HEAP_SIZE: usize = 512 * 1024;

#[repr(C, align(4096))]
struct HeapRegion([u8; KERNEL_HEAP_SIZE]);

static mut KERNEL_HEAP_REGION: HeapRegion = HeapRegion([0; KERNEL_HEAP_SIZE]);

pub static mut KERNEL_HEAP: Heap = Heap::new();

/// Leaf lock guarding every access to [`KERNEL_HEAP`].
static HEAP_LOCK: crate::sync::IrqSpinLock = crate::sync::IrqSpinLock::new();

/// Run `f` with exclusive access to the kernel heap.
///
/// The lock is a leaf: `f` may use the `Heap` methods, but must not call back
/// into this module's wrappers (the spin lock is not re-entrant) or take any
/// other kernel lock.
pub fn with_kernel_heap<R>(f: impl FnOnce(&mut Heap) -> R) -> R {
    HEAP_LOCK.with(|| {
        // SAFETY: `with_kernel_heap` is the only place that hands out
        // `&mut KERNEL_HEAP`; it runs one closure at a time under `HEAP_LOCK`,
        // and `KERNEL_HEAP` lives in `.bss` for the whole kernel lifetime.
        f(unsafe { &mut *core::ptr::addr_of_mut!(KERNEL_HEAP) })
    })
}

/// Allocate from the kernel heap (see [`Heap::alloc`]).
pub fn alloc(size: usize, align: usize) -> Result<*mut u8, HeapError> {
    with_kernel_heap(|heap| heap.alloc(size, align))
}

/// Free a kernel-heap block (see [`Heap::dealloc`]).
///
/// # Safety
///
/// `ptr` must be a live block previously returned by [`alloc`] (or a
/// `Heap::alloc` on the same instance) that has not been freed yet.
pub unsafe fn dealloc(ptr: *mut u8) -> Result<(), HeapError> {
    with_kernel_heap(|heap| unsafe { heap.dealloc(ptr) })
}

/// Snapshot of the kernel-heap counters (see [`Heap::stats`]).
pub fn stats() -> HeapStats {
    with_kernel_heap(|heap| heap.stats())
}

pub fn init() -> Result<(), HeapError> {
    with_kernel_heap(|heap| unsafe {
        heap.init(
            core::ptr::addr_of_mut!(KERNEL_HEAP_REGION) as *mut u8,
            KERNEL_HEAP_SIZE,
        )
    })
}

// ---------------------------------------------------------------------------
// Tests (host)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::boxed::Box;

    /// 64 KiB backing store with a 16-byte-aligned base.
    struct Backing {
        buf: Box<[u8; 64 * 1024 + 16]>,
        base: usize,
    }
    impl Backing {
        fn new() -> Self {
            let buf = Box::new([0u8; 64 * 1024 + 16]);
            let raw = buf.as_ptr() as usize;
            let base = (raw + 15) & !15;
            Backing { buf, base }
        }
        fn heap(&self) -> Heap {
            let mut h = Heap::new();
            unsafe { h.init(self.base as *mut u8, 64 * 1024).unwrap() };
            h
        }
    }

    #[test]
    fn alloc_returns_distinct_aligned_writable_blocks() {
        let b = Backing::new();
        let mut h = b.heap();
        let a = h.alloc(16, 16).unwrap();
        let c = h.alloc(16, 16).unwrap();
        assert_ne!(a, c);
        assert_eq!(a as usize % 16, 0);
        assert_eq!(c as usize % 16, 0);
        unsafe {
            core::ptr::write_bytes(a, 0xAB, 16);
            core::ptr::write_bytes(c, 0xCD, 16);
            assert_eq!(*a, 0xAB);
            assert_eq!(*c, 0xCD);
        }
    }

    #[test]
    fn sizes_map_to_expected_classes() {
        assert_eq!(Heap::class_for(1), Some(0));
        assert_eq!(Heap::class_for(16), Some(0));
        assert_eq!(Heap::class_for(17), Some(1));
        assert_eq!(Heap::class_for(2048), Some(7));
        assert_eq!(Heap::class_for(2049), None);
    }

    #[test]
    fn free_reuses_blocks_and_stats_track_usage() {
        let b = Backing::new();
        let mut h = b.heap();
        let before = h.stats();
        let mut ptrs = Vec::new();
        for _ in 0..8 {
            ptrs.push(h.alloc(100, 16).unwrap());
        }
        let mid = h.stats();
        assert_eq!(mid.allocs, before.allocs + 8);
        assert!(mid.current_bytes > 0);
        assert!(mid.peak_bytes >= mid.current_bytes);
        for &p in &ptrs {
            unsafe { h.dealloc(p).unwrap() };
        }
        let end = h.stats();
        assert_eq!(end.frees, before.frees + 8);
        assert_eq!(end.current_bytes, 0);
        assert_eq!(end.peak_bytes, mid.peak_bytes);
        // Reuse: the free list should serve the same address again.
        let again = h.alloc(100, 16).unwrap();
        assert!(ptrs.contains(&again));
    }

    #[test]
    fn exhaustion_returns_oom_error() {
        let b = Backing::new();
        let mut h = b.heap();
        let mut ptrs = Vec::new();
        let mut oom = false;
        for _ in 0..10_000 {
            match h.alloc(2048, 16) {
                Ok(p) => ptrs.push(p),
                Err(HeapError::OutOfMemory) => {
                    oom = true;
                    break;
                }
                Err(e) => panic!("unexpected error {e:?}"),
            }
        }
        assert!(oom, "expected OutOfMemory from a 64 KiB region");
        for &p in &ptrs {
            unsafe { h.dealloc(p).unwrap() };
        }
        assert_eq!(h.stats().current_bytes, 0);
    }

    #[test]
    fn large_blocks_use_whole_frames() {
        let b = Backing::new();
        let mut h = b.heap();
        let p = h.alloc(4096, 16).unwrap(); // 2 frames
        assert_eq!(p as usize % 16, 0);
        unsafe { core::ptr::write_bytes(p, 0x7E, 4096) };
        let q = h.alloc(5000, 16).unwrap(); // still 2 frames
        assert_ne!(p, q);
        let big = h.alloc(9000, 16).unwrap(); // 3 frames (9000 + header)
        assert_ne!(big, p);
        assert_ne!(big, q);
        unsafe {
            h.dealloc(p).unwrap();
            h.dealloc(q).unwrap();
            h.dealloc(big).unwrap();
        }
        assert_eq!(h.stats().current_bytes, 0);
        // Exact-frame-count reuse: the 3-frame request must get `big` back.
        let r = h.alloc(8500, 16).unwrap(); // 3 frames as well
        assert_eq!(r, big);
        // 2-frame requests are served from the two 2-frame blocks.
        let s = h.alloc(4096, 16).unwrap();
        assert!(s == p || s == q);
        unsafe {
            h.dealloc(r).unwrap();
            h.dealloc(s).unwrap();
        }
        assert_eq!(h.stats().current_bytes, 0);
    }

    #[test]
    fn corrupted_header_is_detected() {
        let b = Backing::new();
        let mut h = b.heap();
        let p = h.alloc(32, 16).unwrap();
        unsafe {
            // Trash the magic in the header (16 bytes before the data).
            *(p.sub(HEADER_SIZE) as *mut u32) = 0xDEAD_BEEF;
            assert_eq!(h.dealloc(p), Err(HeapError::Corrupted));
        }
    }

    #[test]
    fn invalid_free_is_detected() {
        let b = Backing::new();
        let mut h = b.heap();
        let _p = h.alloc(32, 16).unwrap();
        let foreign = (b.base + b.buf.len() - 1) as *mut u8;
        assert_eq!(unsafe { h.dealloc(foreign) }, Err(HeapError::InvalidFree));
    }

    #[test]
    fn debug_poison_survives_free_and_is_verified() {
        let b = Backing::new();
        let mut h = b.heap();
        let p = h.alloc(64, 16).unwrap();
        unsafe { h.dealloc(p).unwrap() };
        #[cfg(debug_assertions)]
        {
            // Data area must be 0x5A after dealloc.
            let data = unsafe { core::slice::from_raw_parts(p, 64) };
            assert!(data.iter().all(|&x| x == 0x5A));
        }
        // Reallocating the block must pass the poison verification.
        let q = h.alloc(64, 16).unwrap();
        assert_eq!(p, q);
        unsafe { h.dealloc(q).unwrap() };
    }

    /// The kernel instance is reachable only through the module wrappers, which
    /// serialise on the leaf lock; the counters must keep tracking exactly what
    /// goes in and out through them.
    #[test]
    fn kernel_heap_wrappers_round_trip_through_the_leaf_lock() {
        use std::sync::{Mutex, MutexGuard};
        static LOCK: Mutex<()> = Mutex::new(());
        let _guard: MutexGuard<'_, ()> = LOCK.lock().unwrap_or_else(|p| p.into_inner());

        init().expect("kernel heap init");
        let before = stats();
        let ptr = alloc(64, 8).expect("64-byte block");
        assert_eq!(ptr as usize % 8, 0);
        unsafe { core::ptr::write_bytes(ptr, 0xAB, 64) };
        let during = stats();
        assert_eq!(during.allocs, before.allocs + 1);
        assert!(during.current_bytes >= before.current_bytes + 64);
        assert_eq!(unsafe { core::ptr::read(ptr) }, 0xAB);

        unsafe { dealloc(ptr) }.expect("free through the wrapper");
        let after = stats();
        assert_eq!(after.frees, before.frees + 1);
        assert_eq!(after.current_bytes, before.current_bytes);
        assert_eq!(alloc(0, 8), Err(HeapError::BadRequest));
    }

    use std::vec::Vec;
}
