//! CaelumOS M9f shared library B (`/fat/m9f-b.so`, ET_DYN, no libc).
//!
//! The kernel maps this image into the main program's address space at the
//! frozen bias `0x0400_0000`. It has no `DT_NEEDED` entries and no relocations:
//! the interpreter only has to map it and resolve library A's `GLOB_DAT`
//! reference to [`m9f_add`]. The library is never executed directly.

#![no_std]
#![no_main]

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo<'_>) -> ! {
    loop {}
}

/// Pure addition used by library A through a `R_X86_64_GLOB_DAT` call target.
#[unsafe(no_mangle)]
pub extern "C" fn m9f_add(left: u64, right: u64) -> u64 {
    left.wrapping_add(right)
}
