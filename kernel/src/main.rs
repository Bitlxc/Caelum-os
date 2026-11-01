//! CaelumOS kernel binary — a thin shim over the `caelum_kernel` library.
//!
//! Everything testable lives in the library (agents.md §21.1); this file only
//! carries the entry point ABI, the `.caelum.bootreq` metadata section the
//! loader pre-checks, and the panic handler.

#![no_std]
#![no_main]

use caelum_kernel::{arch, klog};

// ---------------------------------------------------------------------------
// .caelum.bootreq metadata (parsed by the loader before ExitBootServices)
// ---------------------------------------------------------------------------

#[used]
#[unsafe(link_section = ".caelum.bootreq")]
static BOOTREQ: [u8; 16] = [
    b'C', b'B', b'T', b'R', b'E', b'Q', b'0', b'1', // magic
    1, 0, // protocol major (LE u16)
    1, 0, // protocol minor (LE u16) — 1.1 requires boot-module TLV 0x7
    1, 0, 0, 0, // entry_abi (LE u32)
];

/// Kernel entry (Boot Protocol 1.1, entry_abi 1):
/// `rdi` = BootInfo physical address, `rsi` = BootInfo virtual address
/// (M1 identity mapping, so `rsi == rdi`; only `rdi` is passed on).
#[unsafe(no_mangle)]
pub extern "C" fn _start(bootinfo_ptr: u64) -> ! {
    caelum_kernel::kernel_main(bootinfo_ptr)
}

#[panic_handler]
fn panic(info: &core::panic::PanicInfo) -> ! {
    klog!("[CaelumKernel] PANIC: {}", info.message());
    arch::halt();
}
