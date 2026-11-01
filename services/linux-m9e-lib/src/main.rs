//! CaelumOS M9e shared library (`libm9e.so`, ET_DYN, no libc).
//!
//! The kernel maps this image into the main program's address space at the
//! frozen bias [`LIB_BIAS`] (0x0300_0000) and the self-hosted interpreter
//! resolves the main program's `GLOB_DAT` relocations against the exports
//! below. The library is never executed directly: it has no entry point and no
//! `init_array` (the interpreter does not run initializers by design).
//!
//! Exports (resolved through this image's `.dynsym`):
//! - [`m9e_value`]: frozen `u64` returned through a normal function call;
//! - [`M9E_COUNTER`]: frozen `u64` data word (`GLOB_DAT` in the main program);
//! - [`M9E_BYTES_PTR`]: pointer to 8 bytes owned by this library, proving that
//!   the main program sees a relocated library-internal pointer.

#![no_std]
#![no_main]

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo<'_>) -> ! {
    loop {}
}

/// Frozen value returned through a plain function call.
#[unsafe(no_mangle)]
pub extern "C" fn m9e_value() -> u64 {
    0x4D39_4501_0000_0001
}

/// Frozen data word: the main program reads it through a `R_X86_64_GLOB_DAT`
/// relocation, so a wrong library bias or a skipped relocation is fatal.
#[unsafe(no_mangle)]
pub static M9E_COUNTER: u64 = 0x1122_3344_5566_7788;

/// Bytes owned by this library; the main program reaches them only through the
/// exported pointer below (never through a hard-coded address).
static M9E_LIB_BYTES: [u8; 8] = *b"M9E-LIB!";

/// Exported pointer to [`M9E_LIB_BYTES`], which forces at least one
/// `R_X86_64_RELATIVE` relocation inside the library image.
#[unsafe(no_mangle)]
pub static M9E_BYTES_PTR: &[u8; 8] = &M9E_LIB_BYTES;
