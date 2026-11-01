//! x86-64 architecture mechanisms (agents.md §6.1 ISA layer).
//!
//! M2 delivered GDT, TSS (+IST stacks), IDT and exception diagnostics; M3 adds
//! a returnable interrupt frame (see [`traps`]), the timer/keyboard/COM1/yield
//! IDT gates (see [`idt`]) and the privileged primitives below. M4 adds ring 3:
//! user selectors ([`gdt`]), the 22-qword frame with `user_rsp`/`user_ss`
//! ([`traps`]), and the `syscall` entry plus per-thread kernel-stack switching
//! (see [`syscall`]). M6b1 makes the GDT, TSS (+IST stacks) and the `syscall`
//! GS block **per CPU** ([`MAX_CPUS`] slots): the boot processor keeps slot 0
//! and the application processors are brought up by `crate::smp`.

use core::arch::asm;

/// Maximum number of logical CPUs this kernel supports (1 BSP + up to 3 APs).
///
/// This is the ISA layer's own bound: `arch` must not depend on the platform
/// layer's `platform::acpi::MAX_CPUS`, so the two constants are kept equal by a
/// compile-time assertion in `crate::smp` instead of an import.
pub const MAX_CPUS: usize = 4;

pub mod gdt;
pub mod idt;
pub mod syscall;
pub mod traps;
pub mod tss;

pub use gdt::{KERNEL_CS, KERNEL_DS, TSS_SELECTOR, USER_CS, USER_DS};
pub use syscall::{
    SyscallFrame, SyscallRet, cpu_index, init_percpu, init_syscall, install_dispatch,
    set_user_fs_base, set_user_kernel_stack,
};
pub use traps::{
    FRAME_QWORDS, TrapFrame, VECTOR_RESCHED, init_user_frame, resume_frame, user_frame_addr,
};

/// `RFLAGS.IF` (interrupt-enable flag).
const RFLAGS_IF: u64 = 1 << 9;

/// Execute CPUID leaf `leaf` with sub-leaf `sub`.
///
/// Returns `(eax, ebx, ecx, edx)` in that order (frozen contract: the platform
/// layer calls this signature directly for APIC/feature discovery).
pub fn cpuid(leaf: u32, sub: u32) -> (u32, u32, u32, u32) {
    // CPUID is exposed as a safe intrinsic: it only reads CPU registers.
    let r = core::arch::x86_64::__cpuid_count(leaf, sub);
    (r.eax, r.ebx, r.ecx, r.edx)
}

/// Read a model-specific register.
///
/// # Faults
///
/// Raises `#GP` if `msr` is not implemented on this CPU.
pub fn rdmsr(msr: u32) -> u64 {
    let lo: u32;
    let hi: u32;
    // SAFETY: RDMSR only reads the named MSR into EAX:EDX; no memory access.
    unsafe {
        asm!(
            "rdmsr",
            in("ecx") msr,
            out("eax") lo,
            out("edx") hi,
            options(nomem, nostack, preserves_flags),
        );
    }
    ((hi as u64) << 32) | (lo as u64)
}

/// Write a model-specific register.
///
/// # Faults
///
/// Raises `#GP` if `msr` is not implemented, read-only, or `value` has reserved
/// bits set. Callers must check `cpuid` capability bits first.
pub fn wrmsr(msr: u32, value: u64) {
    let lo = value as u32;
    let hi = (value >> 32) as u32;
    // SAFETY: WRMSR only writes the named MSR from EAX:EDX; no memory access.
    // The caller owns the privilege and validity preconditions documented above.
    unsafe {
        asm!(
            "wrmsr",
            in("ecx") msr,
            in("eax") lo,
            in("edx") hi,
            options(nomem, nostack, preserves_flags),
        );
    }
}

/// Read CR3 (current page-table root physical address).
pub fn read_cr3() -> u64 {
    let v: u64;
    // SAFETY: reading CR3 has no side effects.
    unsafe { asm!("mov {}, cr3", out(reg) v, options(nomem, nostack, preserves_flags)) };
    v
}

/// Load `cr3`: switch the active page tables on **this** CPU.
///
/// Writing CR3 flushes every non-global TLB entry (this kernel never enables
/// CR4.PCIDE), so the caller does not need to invalidate anything afterwards.
///
/// # Safety
///
/// * `cr3` must be the 4 KiB-aligned physical address of a PML4 that maps the
///   code, stack and data the caller touches immediately after the switch: a
///   wrong value faults on the very next instruction fetch.
/// * Interrupts must be off whenever CR3 is changed together with RSP0 as one
///   logical context (see `sched::ap_idle_context`).
pub unsafe fn write_cr3(cr3: u64) {
    // SAFETY: the caller promises `cr3` describes the address space it is about
    // to run in, with interrupts serialised against the switch.
    unsafe { asm!("mov cr3, {}", in(reg) cr3, options(nostack, preserves_flags)) };
}

/// Invalidate the TLB entry for one 4 KiB page.
///
/// `virt` must be a currently mapped-or-unmapped canonical address; the
/// instruction itself never faults.
pub fn invlpg(virt: u64) {
    // SAFETY: `invlpg` only discards a cached translation for `virt`.
    unsafe {
        asm!(
            "invlpg [{}]",
            in(reg) virt,
            options(nostack, preserves_flags),
        );
    }
}

/// Disable interrupts and return the previous `IF` state.
///
/// Pair with [`restore_interrupts`] so nested critical sections restore the
/// state they found instead of unconditionally re-enabling interrupts.
pub fn disable_interrupts() -> bool {
    let flags: u64;
    // SAFETY: saves RFLAGS, then clears IF; no memory is touched.
    // No `options` here on purpose: this must be a full compiler barrier.
    unsafe {
        asm!(
            "pushfq",
            "pop {}",
            "cli",
            out(reg) flags,
        );
    }
    flags & RFLAGS_IF != 0
}

/// Restore the `IF` state captured by [`disable_interrupts`].
///
/// `was_enabled == false` keeps interrupts disabled, which is what a critical
/// section nested inside another one requires.
pub fn restore_interrupts(was_enabled: bool) {
    if was_enabled {
        enable_interrupts();
    } else {
        // SAFETY: only clears IF; the caller asked for the disabled state.
        unsafe { asm!("cli") };
    }
}

/// Enable maskable interrupts (`sti`).
///
/// Interrupts stay blocked for the following instruction (architectural
/// interrupt shadow), so `sti` immediately before a `ret`/`hlt` is safe.
pub fn enable_interrupts() {
    // SAFETY: only sets IF; no memory is touched.
    unsafe { asm!("sti") };
}

/// Wait for the next interrupt: one `sti; hlt`, then return.
///
/// `sti` and `hlt` share one asm block so the architectural interrupt shadow
/// covers `hlt` (no wakeup can be lost between them). The caller must re-check
/// its condition after the return — wait loops look like
/// `while !ready() { arch::idle(); }` — which is what `time::wait_for_ticks`
/// and `input::wait_for_expected` require.
pub fn idle() {
    // SAFETY: enabling interrupts and halting for one interrupt cannot violate
    // any Rust invariant; control returns to the caller via the interrupt
    // return path.
    unsafe { asm!("sti; hlt") };
}

/// Halt forever with interrupts disabled (fatal-error path).
pub fn halt() -> ! {
    loop {
        unsafe { asm!("cli; hlt", options(nomem, nostack)) };
    }
}

/// Read CR2 (page-fault linear address).
pub fn read_cr2() -> u64 {
    let v: u64;
    unsafe { asm!("mov {}, cr2", out(reg) v) };
    v
}

// ---------------------------------------------------------------------------
// 硬件随机源（M8h）：CPUID 探测 + RDRAND/RDSEED 读取。
//
// 指令是否可用必须先经 [`has_rdrand`]/[`has_rdseed`] 探测；在不支持的 CPU 上
// 执行会触发 `#UD`。读取函数不重试：重试预算与健康检查由随机子系统
// （`crate::rng`）负责。
// ---------------------------------------------------------------------------

/// CPUID leaf 1, ECX bit 30: the RDRAND instruction is supported.
pub fn has_rdrand() -> bool {
    cpuid(1, 0).2 & (1 << 30) != 0
}

/// CPUID leaf 7 sub-leaf 0, EBX bit 18: the RDSEED instruction is supported.
pub fn has_rdseed() -> bool {
    let max_basic_leaf = cpuid(0, 0).0;
    if max_basic_leaf < 7 {
        return false;
    }
    cpuid(7, 0).1 & (1 << 18) != 0
}

#[target_feature(enable = "rdrand")]
unsafe fn rdrand64_with_feature() -> Option<u64> {
    let mut value: u64 = 0;
    // SAFETY: only reached after `has_rdrand` reported support; the intrinsic
    // writes the sampled word and reports success in the return flag. This
    // function itself is only callable with the `rdrand` target feature enabled.
    let ok = core::arch::x86_64::_rdrand64_step(&mut value);
    if ok != 0 { Some(value) } else { None }
}

/// Sample one 64-bit word from RDRAND.
///
/// Returns `None` on CPUs without RDRAND or when the hardware reports that no
/// value is currently available; the caller owns the retry budget.
pub fn rdrand64() -> Option<u64> {
    if !has_rdrand() {
        return None;
    }
    // SAFETY: CPUID reported RDRAND support above.
    unsafe { rdrand64_with_feature() }
}

#[target_feature(enable = "rdseed")]
unsafe fn rdseed64_with_feature() -> Option<u64> {
    let mut value: u64 = 0;
    // SAFETY: only reached after `has_rdseed` reported support; the intrinsic
    // writes the sampled word and reports success in the return flag. This
    // function itself is only callable with the `rdseed` target feature enabled.
    let ok = core::arch::x86_64::_rdseed64_step(&mut value);
    if ok != 0 { Some(value) } else { None }
}

/// Sample one 64-bit word from RDSEED.
///
/// Returns `None` on CPUs without RDSEED or when the entropy pool is not ready
/// yet; the caller owns the retry budget.
pub fn rdseed64() -> Option<u64> {
    if !has_rdseed() {
        return None;
    }
    // SAFETY: CPUID reported RDSEED support above.
    unsafe { rdseed64_with_feature() }
}
