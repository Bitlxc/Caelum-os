//! Minimal real vDSO for the M9d2 dynamic-program closure.
//!
//! The vDSO is two things:
//!
//! 1. A read-only, non-executable **time data page** mapped at
//!    [`VDSO_DATA_BASE`] into a dynamically linked user program. The kernel owns
//!    the only writable alias (through the direct map) and publishes monotonic
//!    time into it with a sequence counter, so a user-space reader can detect a
//!    torn read:
//!
//!    ```text
//!    offset  size  field
//!    0       4     magic   = 0xCAE1_0001
//!    4       4     version = 1
//!    8       4     seq     (odd while the kernel is updating the page)
//!    12      4     hz      (monotonic ticks per second)
//!    16      8     ticks   (monotonic tick count)
//!    ```
//!
//! 2. A real ELF image (`/fat/vdso.so`, built by `services/linux-vdso`) mapped
//!    at [`VDSO_BASE`] whose entry [`VDSO_ENTRY`] implements
//!    `__vdso_clock_gettime`. The kernel only maps the ELF; the address is
//!    published to the program through the `AT_SYSINFO_EHDR` auxiliary vector.
//!
//! The data page is a single global frame: it is allocated the first time a
//! dynamic address space maps it and is never freed afterwards, because every
//! dynamic program sees the same page and a process exit must not tear it down
//! for its peers. Mapping it is read-only and non-executable, so the user cannot
//! subvert the kernel's writer.
//!
//! `on_tick` runs from the timer interrupt on the boot processor and on every
//! application processor; it never allocates and never sleeps. Before the page
//! has been mapped once, ticking is a no-op: there is no expensive lazy
//! allocation in interrupt context.

use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use crate::mm::{addrspace, pmm, vm};
use crate::sync::IrqSpinLock;

/// User virtual address the vDSO ELF image is mapped at (fixed link address).
pub const VDSO_BASE: u64 = 0x0700_0000;
/// Address of `__vdso_clock_gettime` inside the vDSO image.
pub const VDSO_ENTRY: u64 = 0x0700_1000;
/// User virtual address of the read-only time data page.
pub const VDSO_DATA_BASE: u64 = 0x0700_2000;
/// Page size of the data mapping and of the frame backing it.
pub const PAGE_SIZE: u64 = 4096;
/// Bytes in the published time data page.
pub const DATA_SIZE: usize = 24;
/// Magic value at offset 0 of the data page.
pub const DATA_MAGIC: u32 = 0xCAE1_0001;
/// Layout version at offset 4.
pub const DATA_VERSION: u32 = 1;
/// Sentinel for "no frame allocated yet" (physical frame 0 is reserved).
pub const DATA_PHYS_NONE: u64 = 0;

/// Offset of the magic field inside the data page.
const OFF_MAGIC: usize = 0;
/// Offset of the version field inside the data page.
const OFF_VERSION: usize = 4;
/// Offset of the sequence counter inside the data page.
const OFF_SEQ: usize = 8;
/// Offset of the tick rate inside the data page.
const OFF_HZ: usize = 12;
/// Offset of the monotonic tick value inside the data page.
const OFF_TICKS: usize = 16;

/// Physical frame of the shared data page, `DATA_PHYS_NONE` before first use.
static FRAME_PHYS: AtomicU64 = AtomicU64::new(DATA_PHYS_NONE);
/// Last sequence value published (even outside an update).
static SEQUENCE: AtomicU32 = AtomicU32::new(0);
/// Last monotonic tick value published.
static TICKS: AtomicU64 = AtomicU64::new(0);
/// Number of address spaces that mapped the data page (diagnostics only).
static MAPPINGS: AtomicU32 = AtomicU32::new(0);
/// Serialises frame allocation and every page update.
static LOCK: IrqSpinLock = IrqSpinLock::new();

/// The exact mapping a dynamic program receives for the data page.
///
/// Returned as a tuple so the read-only/non-executable decision is visible to
/// both `map_into` and its host tests.
pub fn mapping_request() -> (u64, u64, bool, bool) {
    (VDSO_DATA_BASE, PAGE_SIZE, false, false)
}

/// Whether a data page has been allocated and published already.
pub fn is_initialized() -> bool {
    FRAME_PHYS.load(Ordering::Acquire) != DATA_PHYS_NONE
}

/// Physical frame backing the data page (`DATA_PHYS_NONE` before first use).
pub fn data_phys() -> u64 {
    FRAME_PHYS.load(Ordering::Acquire)
}

/// Last published sequence value.
pub fn sequence() -> u32 {
    SEQUENCE.load(Ordering::Acquire)
}

/// Last published monotonic tick value.
pub fn ticks() -> u64 {
    TICKS.load(Ordering::Acquire)
}

/// Encode one complete data-page image.
///
/// This is the single source of truth for the layout: `on_tick` writes the
/// bytes it produces, and the host tests assert the offsets against it.
pub fn layout(seq: u32, hz: u32, ticks: u64) -> [u8; DATA_SIZE] {
    let mut bytes = [0u8; DATA_SIZE];
    bytes[OFF_MAGIC..OFF_MAGIC + 4].copy_from_slice(&DATA_MAGIC.to_le_bytes());
    bytes[OFF_VERSION..OFF_VERSION + 4].copy_from_slice(&DATA_VERSION.to_le_bytes());
    bytes[OFF_SEQ..OFF_SEQ + 4].copy_from_slice(&seq.to_le_bytes());
    bytes[OFF_HZ..OFF_HZ + 4].copy_from_slice(&hz.to_le_bytes());
    bytes[OFF_TICKS..OFF_TICKS + 8].copy_from_slice(&ticks.to_le_bytes());
    bytes
}

/// Convert monotonic ticks to a `(seconds, nanoseconds)` pair.
///
/// This mirrors what `__vdso_clock_gettime` computes in user space and is the
/// part that can be tested on the host. `None` means the conversion would not
/// fit into an `i64` second count (or `hz` is zero).
pub fn clock_to_timespec(ticks: u64, hz: u32) -> Option<(i64, i64)> {
    if hz == 0 {
        return None;
    }
    let hz = u128::from(hz);
    let ticks = u128::from(ticks);
    let seconds = ticks / hz;
    let remainder = ticks % hz;
    let nanos = remainder * 1_000_000_000 / hz;
    if seconds > i64::MAX as u128 {
        return None;
    }
    Some((seconds as i64, nanos as i64))
}

/// Publish `now` (monotonic ticks) into the shared data page.
///
/// Called from the timer interrupt on every online processor. A no-op until the
/// page has been allocated; the write is bracketed by an odd/even sequence so a
/// user-space reader can retry a torn read.
pub fn on_tick(now: u64) {
    if !is_initialized() {
        return;
    }
    let _guard = LOCK.lock();
    let phys = FRAME_PHYS.load(Ordering::Relaxed);
    if phys == DATA_PHYS_NONE {
        return;
    }
    let hz = crate::time::tick_hz() as u32;
    // Odd sequence: the page is being updated.
    let odd = SEQUENCE.load(Ordering::Relaxed).wrapping_add(1) | 1;
    let mut bytes = layout(odd, hz, now);
    write_bytes(phys, &bytes);
    // Even sequence: the page is consistent again.
    let even = odd.wrapping_add(1);
    bytes[OFF_SEQ..OFF_SEQ + 4].copy_from_slice(&even.to_le_bytes());
    write_bytes(phys, &bytes);
    SEQUENCE.store(even, Ordering::Release);
    TICKS.store(now, Ordering::Release);
}

/// Map the shared data page into `address_space` read-only and non-executable.
///
/// The first caller allocates and initialises the single global frame. If the
/// mapping itself fails and no other space had mapped the frame yet, the frame
/// is released again so a failed dynamic spawn leaks nothing.
pub fn map_into(address_space: addrspace::AddressSpaceId) -> Result<(), vm::VmError> {
    let mut allocated_here = false;
    let phys = if is_initialized() {
        data_phys()
    } else {
        let _guard = LOCK.lock();
        if is_initialized() {
            data_phys()
        } else {
            let phys = pmm::alloc_frame().map_err(|_| vm::VmError::OutOfTables)?;
            initialise_frame(phys);
            FRAME_PHYS.store(phys, Ordering::Release);
            allocated_here = true;
            phys
        }
    };

    let (virt, len, writable, executable) = mapping_request();
    match addrspace::map_user_borrowed(address_space, virt, phys, len, writable, executable) {
        Ok(()) => {
            MAPPINGS.fetch_add(1, Ordering::AcqRel);
            Ok(())
        }
        Err(error) => {
            if allocated_here && MAPPINGS.load(Ordering::Acquire) == 0 {
                roll_back_frame(phys);
            }
            Err(error)
        }
    }
}

/// Number of address spaces that mapped the data page.
pub fn mapped_spaces() -> u32 {
    MAPPINGS.load(Ordering::Acquire)
}

/// Zero the new frame and publish the initial (seq = 0, ticks = 0) image.
fn initialise_frame(phys: u64) {
    // SAFETY: `phys` is a frame owned by this module and reachable through the
    // direct map; the whole page is zeroed before anything is published.
    unsafe {
        core::ptr::write_bytes(vm::phys_to_virt(phys) as *mut u8, 0, PAGE_SIZE as usize);
    }
    let hz = crate::time::tick_hz() as u32;
    write_bytes(phys, &layout(0, hz, 0));
}

/// Drop a frame that was allocated for a mapping that then failed.
fn roll_back_frame(phys: u64) {
    let _guard = LOCK.lock();
    if FRAME_PHYS
        .compare_exchange(phys, DATA_PHYS_NONE, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        // Somebody else published it in the meantime; keep it.
        return;
    }
    SEQUENCE.store(0, Ordering::Release);
    TICKS.store(0, Ordering::Release);
    let _ = pmm::dealloc_frame(phys);
}

/// Copy `bytes` into the direct-map alias of `phys` with volatile writes.
fn write_bytes(phys: u64, bytes: &[u8]) {
    // SAFETY: the direct-map alias of a frame owned by this module is writable
    // and the frame is at least one page long.
    unsafe {
        let base = vm::phys_to_virt(phys) as *mut u8;
        for (offset, byte) in bytes.iter().enumerate() {
            base.add(offset).write_volatile(*byte);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_data_page_layout_is_the_frozen_twenty_four_bytes() {
        let bytes = layout(7, 100, 0x1122_3344_5566_7788);
        assert_eq!(bytes.len(), DATA_SIZE);
        assert_eq!(
            u32::from_le_bytes(bytes[0..4].try_into().unwrap()),
            DATA_MAGIC
        );
        assert_eq!(
            u32::from_le_bytes(bytes[4..8].try_into().unwrap()),
            DATA_VERSION
        );
        assert_eq!(u32::from_le_bytes(bytes[8..12].try_into().unwrap()), 7);
        assert_eq!(u32::from_le_bytes(bytes[12..16].try_into().unwrap()), 100);
        assert_eq!(
            u64::from_le_bytes(bytes[16..24].try_into().unwrap()),
            0x1122_3344_5566_7788
        );
    }

    #[test]
    fn the_mapping_request_is_read_only_and_non_executable() {
        let (virt, len, writable, executable) = mapping_request();
        assert_eq!(virt, 0x0700_2000);
        assert_eq!(len, PAGE_SIZE);
        assert!(!writable, "the user alias must be read-only");
        assert!(!executable, "the data page must be NX");
        assert_eq!(VDSO_BASE, 0x0700_0000);
        assert_eq!(VDSO_ENTRY, 0x0700_1000);
    }

    #[test]
    fn clock_conversion_matches_the_user_side_arithmetic() {
        assert_eq!(clock_to_timespec(0, 100), Some((0, 0)));
        assert_eq!(clock_to_timespec(100, 100), Some((1, 0)));
        assert_eq!(clock_to_timespec(150, 100), Some((1, 500_000_000)));
        assert_eq!(clock_to_timespec(1, 0), None, "zero hz cannot convert");
        assert_eq!(
            clock_to_timespec(u64::MAX, 1),
            None,
            "seconds must fit in i64"
        );
    }

    #[test]
    fn ticking_before_the_page_exists_is_a_no_op() {
        assert!(!is_initialized());
        assert_eq!(data_phys(), DATA_PHYS_NONE);
        on_tick(55);
        assert!(
            !is_initialized(),
            "no lazy allocation from interrupt context"
        );
        assert_eq!(sequence(), 0);
        assert_eq!(ticks(), 0);
        assert_eq!(mapped_spaces(), 0);
    }
}
