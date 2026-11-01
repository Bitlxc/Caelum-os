//! CaelumOS M9d2 vDSO image.
//!
//! A **real ELF image** (`ET_EXEC`, fixed base `0x0700_0000`) that the kernel
//! maps read-only into each Linux64 process and reports through
//! `AT_SYSINFO_EHDR`. The single exported entry is
//! `__vdso_clock_gettime` at the frozen address `0x0700_1000`:
//!
//! ```text
//! __vdso_clock_gettime(clock: u64, tp: *mut Timespec) -> i64
//! ```
//!
//! * `CLOCK_MONOTONIC` (1) and `CLOCK_BOOTTIME` (7) read the kernel-maintained
//!   data page at `0x0700_2000`, compute `seconds` / `nanoseconds` from
//!   `ticks`/`hz`, return `0`;
//! * every other clock (including `CLOCK_REALTIME` = 0) returns `-38`
//!   (`-ENOSYS`) without touching `tp`.
//!
//! Data page layout (little endian, stable ABI with the kernel):
//!
//! ```text
//! 0x00 u32 magic        = 0xCAE1_0001
//! 0x04 u32 version      = 1
//! 0x08 u32 seq          (odd while the kernel updates the page)
//! 0x0C u32 hz           ticks per second
//! 0x10 u64 ticks        monotonic tick count
//! ```
//!
//! The reader below is a sequence-locked snapshot loop: it retries while
//! `seq` is odd or changed between the two reads, so a torn
//! `(ticks, hz)` pair is never turned into a wrong timestamp.
//!
//! There is no symbol table parsing: programs reach the entry through
//! `AT_SYSINFO_EHDR` + the ELF header's `e_entry`.
//!
//! M10a: the image also carries an **empty `PT_DYNAMIC`** (`.dynamic` with a
//! single `DT_NULL` pair, see `services/vdso.ld`). A real Linux vDSO is always
//! dynamically shaped, and musl's `__dls3` builds a `struct dso` for the
//! `AT_SYSINFO_EHDR` image: it takes `dso->base` from a `PT_LOAD` and
//! `dso->dynv` from `PT_DYNAMIC`, then decodes that vector (NULL `dynv` is a
//! NULL dereference). The empty dynamic section satisfies the shape contract
//! without advertising symbols; missing vDSO symbols fall back to syscalls.

#![no_std]
#![no_main]

use core::arch::global_asm;

/// Fixed vDSO link base (matches `services/vdso.ld` and the kernel contract).
pub const VDSO_BASE: u64 = 0x0700_0000;
/// Frozen `__vdso_clock_gettime` entry address.
pub const VDSO_ENTRY: u64 = 0x0700_1000;
/// Frozen data-page address.
pub const VDSO_DATA: u64 = 0x0700_2000;
/// Data-page magic.
pub const VDSO_MAGIC: u32 = 0xCAE1_0001;
/// Data-page version.
pub const VDSO_VERSION: u32 = 1;

// Module-level asm is assembled in Intel syntax by default for this target.
global_asm!(
    r#"
    .section .text._vdso, "ax", @progbits
    .global __vdso_clock_gettime
    .type __vdso_clock_gettime, @function
__vdso_clock_gettime:
    cmp rdi, 1
    je .Lvdso_compute
    cmp rdi, 7
    je .Lvdso_compute
    mov rax, -38
    ret

.Lvdso_compute:
    mov r8d, 0x07002000
.Lvdso_retry:
    mov r9d, DWORD PTR [r8+8]
    test r9d, 1
    jnz .Lvdso_retry
    mov r10d, DWORD PTR [r8+12]
    test r10d, r10d
    je .Lvdso_enosys
    mov r11, QWORD PTR [r8+16]
    mov ecx, DWORD PTR [r8+8]
    cmp ecx, r9d
    jne .Lvdso_retry

    mov rax, r11
    xor edx, edx
    div r10
    mov QWORD PTR [rsi], rax

    mov rax, rdx
    mov ecx, 1000000000
    mul rcx
    div r10
    mov QWORD PTR [rsi+8], rax

    xor eax, eax
    ret

.Lvdso_enosys:
    mov rax, -38
    ret
    .size __vdso_clock_gettime, . - __vdso_clock_gettime

    .section .data._vdso, "aw", @progbits
    .global __vdso_data
    .type __vdso_data, @object
__vdso_data:
    .long 0xCAE10001
    .long 1
    .long 0
    .long 1000
    .quad 0
    .size __vdso_data, . - __vdso_data
    "#
);

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {
        core::hint::spin_loop();
    }
}
