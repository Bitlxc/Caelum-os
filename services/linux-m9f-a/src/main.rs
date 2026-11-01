//! CaelumOS M9f shared library A (`/fat/m9f-a.so`, ET_DYN, no libc).
//!
//! The kernel maps this image into the main program's address space at the
//! frozen bias `0x0380_0000`; the self-hosted interpreter resolves the main
//! program's `GLOB_DAT` entries against the exports below and library B's
//! `m9f_add` against library B at `0x0400_0000`.
//!
//! Exports:
//! - [`m9f_sum`]: calls B's `m9f_add` through a `R_X86_64_GLOB_DAT` call target
//!   and increments [`M9F_COUNTER`] on every call;
//! - [`M9F_COUNTER`]: mutable `u64` data word exported through `GLOB_DAT`.
//!
//! Note: even the access to A's own exported counter goes through a `GLOB_DAT`
//! relocation (default-visibility data in a shared object), so the interpreter
//! must prefer the referencing object's own definition before searching its
//! dependency chain. The library is never executed directly.

#![no_std]
#![no_main]

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo<'_>) -> ! {
    loop {}
}

unsafe extern "C" {
    /// Exported by library B (`/fat/m9f-b.so`, bias 0x0400_0000).
    fn m9f_add(left: u64, right: u64) -> u64;
}

/// Exported call counter: incremented once per [`m9f_sum`] call.
#[unsafe(no_mangle)]
pub static mut M9F_COUNTER: u64 = 0;

/// Calls [`m9f_add`] (in library B) and bumps [`M9F_COUNTER`].
#[unsafe(no_mangle)]
pub extern "C" fn m9f_sum(left: u64, right: u64) -> u64 {
    // SAFETY: `m9f_add` is provided by library B, mapped by the kernel and
    // resolved by the interpreter before the main program starts.
    let sum = unsafe { m9f_add(left, right) };
    // SAFETY: the counter is only written from this function; the single-threaded
    // M9f probe never calls it concurrently.
    unsafe {
        M9F_COUNTER = M9F_COUNTER.wrapping_add(1);
    }
    sum
}
