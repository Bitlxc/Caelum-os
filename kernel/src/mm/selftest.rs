//! M2 in-kernel self-tests for the PMM and the heap.
//!
//! These run after the VM takeover (the PMM poison hooks need the direct
//! map). Each returns `Ok(())` or an error string; the orchestrator in
//! `kernel_main` prints the acceptance marker only on success.

use crate::klog;
use crate::mm::heap::{self, HeapError};
use crate::mm::pmm::{self, PmmError};
use crate::mm::vm;

const SELFTEST_FRAMES: usize = 8;

fn pmm_err(e: PmmError) -> &'static str {
    match e {
        PmmError::OutOfMemory => "pmm: out of memory",
        PmmError::InvalidFrame => "pmm: invalid frame",
        PmmError::DoubleFree => "pmm: double free",
        PmmError::Corruption => "pmm: corruption",
    }
}

fn heap_err(e: HeapError) -> &'static str {
    match e {
        HeapError::NotInitialized => "heap: not initialized",
        HeapError::BadRequest => "heap: bad request",
        HeapError::OutOfMemory => "heap: out of memory",
        HeapError::Corrupted => "heap: corrupted block header",
        HeapError::InvalidFree => "heap: invalid free",
    }
}

/// PMM alloc/dealloc round trip with direct-map access, double-free detection
/// and (debug) poison verification. Returns the free count observed after the
/// test for logging.
pub fn pmm() -> Result<u64, &'static str> {
    let before = pmm::free_frames();
    let mut frames = [0u64; SELFTEST_FRAMES];
    for f in frames.iter_mut() {
        *f = pmm::alloc_frame().map_err(pmm_err)?;
    }
    for (i, &a) in frames.iter().enumerate().take(SELFTEST_FRAMES) {
        for &b in &frames[..i] {
            if a == b {
                return Err("pmm: duplicate frame handed out");
            }
        }
    }
    // Prove the direct map: write a pattern through it and read it back.
    let probe = frames[0];
    let v = vm::phys_to_virt(probe) as *mut u64;
    unsafe {
        v.write(0xCAEA_0000_5A5A_1234);
        if v.read() != 0xCAEA_0000_5A5A_1234 {
            return Err("pmm: direct-map readback mismatch");
        }
        v.write(0);
    }
    // Poison verification (debug builds only): after dealloc the frame holds
    // 0x5A; allocating it again must succeed (and internally re-verify).
    pmm::dealloc_frame(probe).map_err(pmm_err)?;
    let again = pmm::alloc_frame().map_err(pmm_err)?;
    if again != probe {
        return Err("pmm: LIFO stack did not return the just-freed frame");
    }
    frames[0] = again;
    for &f in &frames {
        pmm::dealloc_frame(f).map_err(pmm_err)?;
    }
    if pmm::dealloc_frame(frames[0]).map_err(pmm_err).is_ok() {
        return Err("pmm: double free not detected");
    }
    let after = pmm::free_frames();
    if after != before {
        return Err("pmm: free count not restored");
    }
    Ok(after)
}

/// Heap size-class / large-block / stats / OOM self-test.
pub fn heap() -> Result<(), &'static str> {
    heap::init().map_err(heap_err)?;
    heap::with_kernel_heap(heap_body)
}

/// Heap selftest body. It runs under `HEAP_LOCK` (via [`heap::with_kernel_heap`])
/// so it never touches the heap outside the leaf lock.
fn heap_body(h: &mut heap::Heap) -> Result<(), &'static str> {
    let small_sizes = [16usize, 24, 100, 512, 1024, 2048];
    let mut ptrs = [core::ptr::null_mut::<u8>(); 6];
    for (i, &s) in small_sizes.iter().enumerate() {
        let p = h.alloc(s, 16).map_err(heap_err)?;
        if p as usize % 16 != 0 {
            return Err("heap: misaligned block");
        }
        ptrs[i] = p;
    }
    for (i, &p) in ptrs.iter().enumerate() {
        unsafe { core::ptr::write_bytes(p, 0xA0 + i as u8, small_sizes[i]) };
    }
    // Large block: whole-frame path.
    let large = h.alloc(4096, 16).map_err(heap_err)?;
    unsafe { core::ptr::write_bytes(large, 0x5C, 4096) };
    // OOM must be a clean error, not a panic.
    let mut junk = [core::ptr::null_mut::<u8>(); 512];
    let mut oom = false;
    let mut n = 0usize;
    while n < junk.len() {
        match h.alloc(2048, 16) {
            Ok(p) => {
                junk[n] = p;
                n += 1;
            }
            Err(HeapError::OutOfMemory) => {
                oom = true;
                break;
            }
            Err(e) => return Err(heap_err(e)),
        }
    }
    if !oom {
        return Err("heap: OOM not reached with a full region");
    }
    for &p in &junk[..n] {
        unsafe { h.dealloc(p).map_err(heap_err)? };
    }
    unsafe {
        h.dealloc(large).map_err(heap_err)?;
        for &p in &ptrs {
            h.dealloc(p).map_err(heap_err)?;
        }
    }
    let stats = h.stats();
    if stats.current_bytes != 0 {
        return Err("heap: current_bytes not zero after freeing all");
    }
    if stats.allocs == 0 || stats.frees != stats.allocs {
        return Err("heap: alloc/free counters inconsistent");
    }
    if stats.peak_bytes == 0 {
        return Err("heap: peak not tracked");
    }
    klog!(
        "[CaelumKernel]   heap stats: {} allocs, {} frees, peak {} KiB",
        stats.allocs,
        stats.frees,
        stats.peak_bytes / 1024
    );
    Ok(())
}
