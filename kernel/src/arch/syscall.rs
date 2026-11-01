//! Native syscall entry (M4): `syscall` in, `iretq` out.
//!
//! The native ABI uses the architectural `syscall` instruction because it is
//! the fast, unambiguous entry point, but the return path is `iretq` over a
//! complete [`TrapFrame`] rather than `sysretq`. `iretq` restores
//! `RFLAGS`/`CS`/`RIP`/`RSP`/`SS` from memory, so a syscall and a ring3
//! interrupt leave the CPU in exactly the same state and the scheduler can
//! resume either frame with [`crate::arch::traps::resume_frame`]. It also
//! avoids the `sysretq` selector/`RCX` canonicality hazards.
//!
//! Entry sequence (all registers saved into one 22-qword [`TrapFrame`]):
//!
//! ```text
//! user                          kernel
//! rax = syscall number    ->    frame.rax, SyscallFrame.nr
//! rdi rsi rdx r10 r8 r9   ->    SyscallFrame.args[0..6]
//! rcx = return RIP        ->    frame.rip
//! r11 = return RFLAGS     ->    frame.rflags
//! rsp                     ->    frame.user_rsp   (saved before the switch)
//! CS/SS                   ->    frame.cs = USER_CS, frame.user_ss = USER_DS
//! ```
//!
//! The kernel stack comes from a per-CPU GS block (`gs:0` = kernel stack top,
//! `gs:8` = the user stack pointer), so switching stacks costs one store and
//! one load. `swapgs` makes the kernel GS base current on entry and hands the
//! user GS base back before `iretq`.
//!
//! `SFMASK` clears `TF`/`IF`/`DF`/`AC` on entry: the handler runs with
//! interrupts disabled (a syscall never nests), traps cannot single-step kernel
//! code, the string instructions see `DF = 0`, and the alignment-check flag
//! cannot fault in kernel mode. All four are restored from `r11` by `iretq`.
//!
//! The handler is a Rust function installed with [`install_dispatch`]; the
//! assembler calls one fixed `extern "C"` shim. Keeping the dispatch behind a
//! pointer means `arch` does not depend on the root module that owns syscall
//! numbers and object semantics (it is installed once during boot, before user
//! mode exists). A `SyscallRet` is returned in `rax:rdx` and written back to
//! the frame, so the handler can also edit the frame directly (e.g. to make a
//! blocked thread return later).
//!
//! Not returning is supported: the handler may diverge (process exit hands the
//! frame to the scheduler, which switches stacks) — the stub simply never
//! reaches its own `iretq` in that case.

use core::arch::naked_asm;
use core::mem::{offset_of, size_of};

use crate::klog;

use super::MAX_CPUS;
use super::TrapFrame;
use super::gdt::{KERNEL_CS, USER_CS, USER_DS};
use super::traps::{FRAME_QWORDS, USER_STACK_TOP_RESERVED, VECTOR_SYSCALL};

// ---------------------------------------------------------------------------
// MSRs (Intel SDM vol. 4)
// ---------------------------------------------------------------------------

const IA32_EFER: u32 = 0xC000_0080;
const IA32_STAR: u32 = 0xC000_0081;
const IA32_LSTAR: u32 = 0xC000_0082;
const IA32_FMASK: u32 = 0xC000_0084;
/// FS base: user TLS lives here. The kernel keeps no pointer in it, and
/// [`init_syscall`] zeroes it so nothing kernel-side leaks into ring3.
const IA32_FS_BASE: u32 = 0xC000_0100;
/// GS base: the per-CPU block while the kernel runs here (i.e. after `swapgs`).
const IA32_GS_BASE: u32 = 0xC000_0101;
/// Kernel GS base: holds the per-CPU block while ring3 runs, which is what the
/// entry stub's `swapgs` exposes again.
///
/// M4 hit this exact trap: the three base MSRs are adjacent and were numbered
/// `0100`/`0101`/`0101`, so [`init_syscall`] wrote the per-CPU pointer into
/// *FS* and zeroed *GS*. The first `syscall` then executed `mov rsp, gs:8`
/// with `GS.base == 0` and page-faulted at CR2 = 8. The const assertions below
/// pin the three numbers so a transposition cannot compile.
const IA32_KERNEL_GS_BASE: u32 = 0xC000_0102;

const _: () = assert!(IA32_FS_BASE == 0xC000_0100);
const _: () = assert!(IA32_GS_BASE == 0xC000_0101);
const _: () = assert!(IA32_KERNEL_GS_BASE == 0xC000_0102);

/// `EFER.SCE`: enable the `syscall`/`sysret` instruction pair.
const EFER_SCE: u64 = 1 << 0;

/// `SFMASK` bits cleared on `syscall` entry: `TF` (8), `IF` (9), `DF` (10),
/// `AC` (18). Clearing `TF` keeps a user-mode single-step from trapping while
/// the kernel executes the handler; `IF`/`DF`/`AC` are cleared for the reasons
/// documented at the top of this module.
const SFMASK_TF_IF_DF_AC: u64 = (1 << 8) | (1 << 9) | (1 << 10) | (1 << 18);

const USER_CS_U64: u64 = USER_CS as u64;
const USER_DS_U64: u64 = USER_DS as u64;

/// Bytes of a [`TrapFrame`] (22 qwords); the entry stub reserves exactly this.
const TRAP_FRAME_BYTES: u64 = (FRAME_QWORDS * 8) as u64;

/// Stack bytes reserved below the `TrapFrame` for the [`SyscallFrame`] area.
///
/// The stub runs on `kernel_rsp = top - 8` (`top % 16 == 0`), so `rsp % 16` is
/// 8 on entry and stays 8 after the 176-byte `TrapFrame`. The SysV AMD64 ABI
/// requires `rsp % 16 == 0` at the `call` site (the callee then sees 8), so the
/// frame area carries one padding qword: `size_of::<SyscallFrame>() + 8 == 104`
/// puts `rsp` back on a 16-byte boundary for `call __syscall_dispatch_shim`.
/// The `SyscallFrame` itself starts at that aligned `rsp`.
const SYSCALL_STACK_BYTES: u64 = size_of::<SyscallFrame>() as u64 + 8;

const _: () = assert!(TRAP_FRAME_BYTES == 22 * 8);
const _: () = assert!(SYSCALL_STACK_BYTES == 104);
// `top - 8`, then the TrapFrame, then the SyscallFrame area => 0 mod 16.
const _: () = assert!((USER_STACK_TOP_RESERVED + TRAP_FRAME_BYTES + SYSCALL_STACK_BYTES) % 16 == 0);

// ---------------------------------------------------------------------------
// Per-CPU block
// ---------------------------------------------------------------------------

/// Per-CPU state addressed through the kernel GS base.
///
/// The syscall stub reaches the first two fields with the raw offsets
/// `gs:0`/`gs:8`, so they must stay first and in this order (checked below).
/// [`cpu_index`] is appended at 0x10 so the Rust side can find its own slot
/// without deducing it from a LAPIC id: the AP entry patches it into the
/// mailbox before the AP jumps to Rust, and [`init_percpu`] stores it here.
#[repr(C, align(8))]
pub struct PerCpu {
    /// Kernel stack top for the next ring3 → ring0 `syscall` (16-byte aligned).
    pub kernel_rsp: u64,
    /// User stack pointer saved by the entry stub for the handler.
    pub user_rsp: u64,
    /// Logical CPU index of the processor owning this block (BSP is 0).
    pub cpu_index: u64,
}

/// One block per CPU; `GS.base` of CPU `i` points at slot `i`.
static mut PER_CPU: [PerCpu; MAX_CPUS] = [const {
    PerCpu {
        kernel_rsp: 0,
        user_rsp: 0,
        cpu_index: 0,
    }
}; MAX_CPUS];

const _: () = {
    assert!(offset_of!(PerCpu, kernel_rsp) == 0);
    assert!(offset_of!(PerCpu, user_rsp) == 8);
    assert!(offset_of!(PerCpu, cpu_index) == 16);
    // `align(8)`: three qwords, no trailing padding — the block is 24 bytes so
    // the array of blocks is exactly `MAX_CPUS * 24` and `gs:[16]` stays valid.
    assert!(core::mem::size_of::<PerCpu>() == 24);
};

/// Pointer to the per-CPU block of `cpu` inside the `static mut`.
pub(crate) fn per_cpu_ptr(cpu: usize) -> *mut PerCpu {
    assert!(cpu < MAX_CPUS, "cpu index out of range");
    // SAFETY: `cpu` is in range; the array is a kernel-lifetime `.bss` static.
    unsafe { core::ptr::addr_of_mut!(PER_CPU).cast::<PerCpu>().add(cpu) }
}

/// Logical index of the CPU executing this code.
///
/// The kernel GS base points at this CPU's [`PerCpu`] block, so the index is a
/// single load. Host tests have one logical CPU, index 0.
pub fn cpu_index() -> usize {
    #[cfg(test)]
    {
        0
    }
    #[cfg(not(test))]
    {
        let index: u64;
        // SAFETY: GS.base is this CPU's PerCpu (set by `init_percpu`); the
        // offset is pinned by the assertion above. Read-only, no flags changed.
        unsafe {
            core::arch::asm!(
                "mov {}, gs:[16]",
                out(reg) index,
                options(nostack, readonly, preserves_flags),
            );
        }
        index as usize
    }
}

// ---------------------------------------------------------------------------
// Handler interface
// ---------------------------------------------------------------------------

/// Complete register state a native syscall handler receives.
///
/// The layout is frozen: it is written by the entry stub (see the module docs
/// for the register mapping) and read by the root syscall module.
#[repr(C)]
pub struct SyscallFrame {
    /// Syscall number (`rax` on entry).
    pub nr: u64,
    /// Arguments 0..6, from `rdi`, `rsi`, `rdx`, `r10`, `r8`, `r9`.
    pub args: [u64; 6],
    /// User RIP to return to (`rcx` on entry, set by the CPU).
    pub user_rip: u64,
    /// User RFLAGS to return with (`r11` on entry, set by the CPU).
    pub user_rflags: u64,
    /// User stack pointer (`rsp` before the kernel stack switch).
    pub user_rsp: u64,
    /// User stack selector (`USER_DS`; the CPU does not push it for `syscall`).
    pub user_ss: u64,
    /// The full saved [`TrapFrame`] (16-byte aligned) for handlers that need
    /// the untouched caller-saved/callee-saved registers.
    pub trap_frame: *mut TrapFrame,
}

/// Result registers a handler returns: written back to `rax` (`status`) and
/// `rdx` (`result`) before the frame is resumed.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SyscallRet {
    pub status: u64,
    pub result: u64,
}

const _: () = {
    assert!(offset_of!(SyscallFrame, nr) == 0);
    assert!(offset_of!(SyscallFrame, args) == 8);
    assert!(offset_of!(SyscallFrame, user_rip) == 56);
    assert!(offset_of!(SyscallFrame, user_rflags) == 64);
    assert!(offset_of!(SyscallFrame, user_rsp) == 72);
    assert!(offset_of!(SyscallFrame, user_ss) == 80);
    assert!(offset_of!(SyscallFrame, trap_frame) == 88);
    assert!(core::mem::size_of::<SyscallFrame>() == 96);
    assert!(offset_of!(SyscallRet, status) == 0);
    assert!(offset_of!(SyscallRet, result) == 8);
    assert!(core::mem::size_of::<SyscallRet>() == 16);
};

/// Native syscall handler signature.
pub type DispatchFn = fn(*mut SyscallFrame) -> SyscallRet;

static mut DISPATCH: Option<DispatchFn> = None;

/// Install the syscall handler. Called once during boot, before user mode.
pub fn install_dispatch(dispatch: DispatchFn) {
    // SAFETY: single CPU; the pointer is installed before any ring3 code can
    // execute a syscall, and is not mutated afterwards.
    unsafe { DISPATCH = Some(dispatch) };
}

/// Fixed `extern "C"` trampoline the entry stub calls.
#[unsafe(no_mangle)]
extern "C" fn __syscall_dispatch_shim(frame: *mut SyscallFrame) -> SyscallRet {
    // SAFETY: `frame` points at the stub's `SyscallFrame` on the kernel stack.
    match unsafe { DISPATCH } {
        Some(dispatch) => dispatch(frame),
        None => {
            klog!("[CaelumKernel] syscall entered with no handler installed, halting");
            super::halt()
        }
    }
}

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// `STAR`: `syscall` loads `CS` from bits 47:32 (`SS = CS + 8`); `sysret` would
/// derive `CS` from bits 63:48 (`+16`) — unused here, but kept consistent so
/// the selector pair is correct whichever return instruction a CPU takes.
const fn star_value() -> u64 {
    let user_base = (USER_CS - 16) as u64;
    (user_base << 48) | ((KERNEL_CS as u64) << 32)
}

/// `EFER` value with `SCE` set.
const fn efer_with_sce(efer: u64) -> u64 {
    efer | EFER_SCE
}

/// Whether the CPU advertises `syscall`/`sysret` support (CPUID.01H:EDX[11]).
fn cpu_supports_syscall() -> bool {
    super::cpuid(1, 0).3 & (1 << 11) != 0
}

/// Program the MSRs the `syscall` entry needs for CPU `cpu`, and point this
/// CPU's GS base at its own [`PerCpu`] block.
///
/// Must run in ring 0. Safe to call on the boot processor and on every
/// application processor (the MSRs and `GS.base`/`KERNEL_GS_BASE` are
/// per-CPU architectural state).
fn configure_msrs(cpu: usize) {
    let gs_base = per_cpu_ptr(cpu) as u64;
    let entry = syscall_entry as *const () as u64;
    // SAFETY: privileged MSR writes from ring 0; the values are the
    // architectural ones and every CPU runs the same kernel.
    super::wrmsr(IA32_EFER, efer_with_sce(super::rdmsr(IA32_EFER)));
    super::wrmsr(IA32_FS_BASE, 0); // user TLS stays empty; per-CPU state is GS-only
    super::wrmsr(IA32_GS_BASE, gs_base); // kernel-side per-CPU block of this CPU
    super::wrmsr(IA32_KERNEL_GS_BASE, 0); // ring3 GS base to begin with
    super::wrmsr(IA32_STAR, star_value());
    super::wrmsr(IA32_LSTAR, entry);
    super::wrmsr(IA32_FMASK, SFMASK_TF_IF_DF_AC);
}

/// Per-CPU form of [`init_syscall`] for the M6b1 application processors: store
/// the logical index in the block, then program this CPU's MSRs.
///
/// The AP entry calls this before publishing itself online, so by the time an
/// AP can execute a kernel path that uses [`cpu_index`] the block is valid.
pub fn init_percpu(cpu: usize) {
    if !cpu_supports_syscall() {
        klog!("[CaelumKernel] CPU does not support SYSCALL, halting");
        super::halt();
    }
    // SAFETY: plain field write to this CPU's block (the caller owns it until
    // the CPU publishes itself online).
    unsafe { (*per_cpu_ptr(cpu)).cpu_index = cpu as u64 };
    configure_msrs(cpu);
}

/// Program the MSRs and the per-CPU GS blocks that the `syscall` entry needs.
///
/// Run once during boot for the boot processor (interrupts disabled) after
/// [`super::gdt::init`]: user mode cannot work until `LSTAR` points at the
/// entry stub. Every other CPU calls [`init_percpu`] from its own entry path.
///
/// The three base MSRs are programmed as: `FS.base = 0` (user TLS, no kernel
/// pointer), `GS.base = &PER_CPU[cpu]` (the kernel side), `KERNEL_GS_BASE = 0`
/// (what ring3 sees as its GS). `swapgs` in the entry/return paths then just
/// swaps the last two, so no kernel address is ever visible to user mode.
pub fn init_syscall() {
    init_percpu(0);
}

/// Register the kernel stack a ring3 thread enters the kernel on.
///
/// `top` is the 16-byte-aligned **top** of the thread's kernel stack; the
/// frozen invariant (with the scheduler/root) is that the qword just below it
/// (`top - 8`) is a canary/scratch slot, so both entry paths are programmed
/// with `top - 8`:
///
/// - `TSS.RSP0` for interrupts/exceptions (the CPU pushes 40 bytes onto it),
/// - the per-CPU `kernel_rsp` for `syscall`.
///
/// A first ring3 frame lives at `align16(top - 8) - 176 == top - 192` (the
/// geometry owned by `process::first_frame_addr`): the CPU 16-byte-aligns
/// `RSP0` before pushing its 40-byte interrupt frame, and this stub adds 136
/// bytes, so a real ring3 interrupt rebuilds exactly that frame and never
/// touches the reserved qword at `top - 8`. The `syscall` path performs no stack
/// switch and no CPU alignment, so its private frame sits at `top - 184`.
/// Updates both slots of the **current** CPU at once, so the two entry paths
/// can never disagree; in M6b1 only the boot processor runs user threads, so
/// this updates slot 0 (the AP slots keep their last value).
///
/// The caller must have interrupts disabled while the thread is being made
/// current; on a single CPU no other code observes the pair mid-update.
pub fn set_user_kernel_stack(top: u64) {
    assert!(top >= size_of::<TrapFrame>() as u64 + USER_STACK_TOP_RESERVED);
    debug_assert_eq!(top % 16, 0, "user kernel stack top must be 16-byte aligned");
    let entry_rsp = top - USER_STACK_TOP_RESERVED;
    let cpu = cpu_index();
    super::tss::set_rsp0_for(cpu, entry_rsp);
    // SAFETY: interrupts are disabled by the caller while the thread is being
    // made current, and the block belongs to this CPU.
    unsafe { (*per_cpu_ptr(cpu)).kernel_rsp = entry_rsp };
}

/// Set the FS segment base (user TLS pointer) of the current context.
///
/// `arch_prctl(ARCH_SET_FS)` stores the value in the process record and asks
/// this helper to apply it immediately; `sched::activate_user_context` calls it
/// again whenever a different process is switched in, so a parent and a child
/// Linux process each resume with their own TLS base.
pub fn set_user_fs_base(value: u64) {
    super::wrmsr(IA32_FS_BASE, value);
}

/// Kernel stack currently registered for the next ring3 entry (diagnostics).
pub fn user_kernel_stack() -> u64 {
    // SAFETY: read-only access to this CPU's block.
    unsafe { (*per_cpu_ptr(cpu_index())).kernel_rsp }
}

/// User stack pointer the stub saved for the handler being executed.
pub fn saved_user_rsp() -> u64 {
    // SAFETY: read-only access to this CPU's block.
    unsafe { (*per_cpu_ptr(cpu_index())).user_rsp }
}

// ---------------------------------------------------------------------------
// Entry stub
// ---------------------------------------------------------------------------

/// `syscall` entry: save the complete frame, call the handler, `iretq` back.
///
/// Not called from Rust — `LSTAR` points here. Never returns to its caller.
#[unsafe(naked)]
pub unsafe extern "C" fn syscall_entry() -> ! {
    naked_asm!(
        "swapgs",                        // kernel GS base (per-CPU block)
        "mov qword ptr gs:[0x8], rsp",   // per-CPU user_rsp
        "mov rsp, qword ptr gs:[0x0]",   // per-CPU kernel_rsp
        "sub rsp, {trap_frame_bytes}",   // TrapFrame (22 qwords)
        "mov qword ptr [rsp + 0], r15",
        "mov qword ptr [rsp + 8], r14",
        "mov qword ptr [rsp + 16], r13",
        "mov qword ptr [rsp + 24], r12",
        "mov qword ptr [rsp + 32], rbp",
        "mov qword ptr [rsp + 40], rbx",
        "mov qword ptr [rsp + 48], r11",
        "mov qword ptr [rsp + 56], r10",
        "mov qword ptr [rsp + 64], r9",
        "mov qword ptr [rsp + 72], r8",
        "mov qword ptr [rsp + 80], rax", // syscall number
        "mov qword ptr [rsp + 88], rcx", // return RIP
        "mov qword ptr [rsp + 96], rdx",
        "mov qword ptr [rsp + 104], rsi",
        "mov qword ptr [rsp + 112], rdi",
        "mov qword ptr [rsp + 120], {vector}", // vector marker (no IDT gate)
        "mov qword ptr [rsp + 128], 0",   // error code
        "mov qword ptr [rsp + 136], rcx", // rip
        "mov qword ptr [rsp + 144], {user_cs}", // cs = USER_CS
        "mov qword ptr [rsp + 152], r11", // rflags
        "mov rax, qword ptr gs:[0x8]",
        "mov qword ptr [rsp + 160], rax", // user_rsp
        "mov qword ptr [rsp + 168], {user_ds}", // user_ss = USER_DS
        "mov rbx, rsp", // rbx = *mut TrapFrame (callee-saved)
        // SyscallFrame + one padding qword. `kernel_rsp` is `top - 8`, so
        // `rsp % 16 == 8` on entry and stays 8 after the 176-byte TrapFrame;
        // the extra 8 bytes bring it to 0 for the `call` (SysV requires a
        // 16-byte-aligned `rsp` *before* the call, the callee then sees 8).
        // The SyscallFrame itself starts at this (now aligned) `rsp`.
        "sub rsp, {syscall_stack_bytes}",
        "mov rax, qword ptr [rbx + 80]",
        "mov qword ptr [rsp + 0], rax", // nr
        "mov rax, qword ptr [rbx + 112]",
        "mov qword ptr [rsp + 8], rax", // args[0] = rdi
        "mov rax, qword ptr [rbx + 104]",
        "mov qword ptr [rsp + 16], rax", // args[1] = rsi
        "mov rax, qword ptr [rbx + 96]",
        "mov qword ptr [rsp + 24], rax", // args[2] = rdx
        "mov rax, qword ptr [rbx + 56]",
        "mov qword ptr [rsp + 32], rax", // args[3] = r10
        "mov rax, qword ptr [rbx + 72]",
        "mov qword ptr [rsp + 40], rax", // args[4] = r8
        "mov rax, qword ptr [rbx + 64]",
        "mov qword ptr [rsp + 48], rax", // args[5] = r9
        "mov rax, qword ptr [rbx + 136]",
        "mov qword ptr [rsp + 56], rax", // user_rip
        "mov rax, qword ptr [rbx + 152]",
        "mov qword ptr [rsp + 64], rax", // user_rflags
        "mov rax, qword ptr [rbx + 160]",
        "mov qword ptr [rsp + 72], rax", // user_rsp
        "mov rax, qword ptr [rbx + 168]",
        "mov qword ptr [rsp + 80], rax", // user_ss
        "mov qword ptr [rsp + 88], rbx", // trap_frame
        "mov rdi, rsp",
        "call __syscall_dispatch_shim",
        "mov qword ptr [rbx + 80], rax",  // status -> frame.rax
        "mov qword ptr [rbx + 96], rdx",  // result -> frame.rdx
        "mov rsp, rbx",
        "pop r15",
        "pop r14",
        "pop r13",
        "pop r12",
        "pop rbp",
        "pop rbx",
        "pop r11",
        "pop r10",
        "pop r9",
        "pop r8",
        "pop rax",
        "pop rcx",
        "pop rdx",
        "pop rsi",
        "pop rdi",
        "add rsp, 16", // drop vector + error
        "swapgs",      // user GS base again
        "iretq",
        vector = const VECTOR_SYSCALL,
        user_cs = const USER_CS_U64,
        user_ds = const USER_DS_U64,
        trap_frame_bytes = const TRAP_FRAME_BYTES,
        syscall_stack_bytes = const SYSCALL_STACK_BYTES,
    )
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::super::gdt::KERNEL_DS;
    use super::*;

    #[test]
    fn star_encodes_kernel_and_user_selectors() {
        let star = star_value();
        assert_eq!((star >> 32) as u16, KERNEL_CS, "syscall CS");
        assert_eq!(((star >> 32) as u16) + 8, KERNEL_DS, "syscall SS");
        assert_eq!(((star >> 48) as u16) + 16, USER_CS, "sysret CS");
        assert_eq!(((star >> 48) as u16) + 24, USER_DS, "sysret SS");
    }

    #[test]
    fn fmask_clears_tf_if_df_and_ac() {
        assert_eq!(SFMASK_TF_IF_DF_AC, 0x0004_0700);
        assert_ne!(SFMASK_TF_IF_DF_AC & (1 << 8), 0, "TF");
        assert_ne!(SFMASK_TF_IF_DF_AC & (1 << 9), 0, "IF");
        assert_ne!(SFMASK_TF_IF_DF_AC & (1 << 10), 0, "DF");
        assert_ne!(SFMASK_TF_IF_DF_AC & (1 << 18), 0, "AC");
        // No other flag (RF, VM, NT, ...) is masked: only these four.
        let others = SFMASK_TF_IF_DF_AC & !((1 << 8) | (1 << 9) | (1 << 10) | (1 << 18));
        assert_eq!(others, 0, "only TF/IF/DF/AC are masked");
    }

    #[test]
    fn syscall_stack_area_keeps_the_call_site_aligned() {
        // `set_user_kernel_stack` programs `top - 8`; the stub then subtracts the
        // TrapFrame and the SyscallFrame area before `call`.
        assert_eq!(SYSCALL_STACK_BYTES as usize, size_of::<SyscallFrame>() + 8);
        let rsp_at_call = (USER_STACK_TOP_RESERVED + TRAP_FRAME_BYTES + SYSCALL_STACK_BYTES) % 16;
        assert_eq!(rsp_at_call, 0, "rsp % 16 == 0 at the syscall call site");
        // The frame handed to the handler is 16-byte aligned in turn.
        assert_eq!(
            ((USER_STACK_TOP_RESERVED + TRAP_FRAME_BYTES) % 16) as usize,
            16 - 8,
            "SyscallFrame starts 8 mod 16 below the frame, so 104 bytes align it"
        );
    }

    #[test]
    fn msr_numbers_match_the_intel_manual() {
        // The three base MSRs are adjacent, and M4 once wrote the per-CPU
        // pointer into FS (0xC0000100) while zeroing GS: the first `syscall`
        // then loaded through `gs:8` with GS.base == 0 and faulted at CR2 = 8.
        assert_eq!(IA32_FS_BASE, 0xC000_0100, "IA32_FS_BASE");
        assert_eq!(IA32_GS_BASE, 0xC000_0101, "IA32_GS_BASE");
        assert_eq!(IA32_KERNEL_GS_BASE, 0xC000_0102, "IA32_KERNEL_GS_BASE");
        // `swapgs` moves the per-CPU block between these two, so they must
        // remain distinct and the stub's `gs:0`/`gs:8` offsets must stay
        // inside one block.
        assert_ne!(IA32_GS_BASE, IA32_FS_BASE);
        assert_ne!(IA32_KERNEL_GS_BASE, IA32_GS_BASE);
    }

    #[test]
    fn efer_sce_is_bit_zero() {
        assert_eq!(efer_with_sce(0), EFER_SCE);
        assert_eq!(efer_with_sce(0), 1);
        let efer = efer_with_sce(0x500);
        assert_eq!(efer, 0x501);
        assert_eq!(efer_with_sce(efer), efer, "idempotent");
    }

    #[test]
    fn user_selectors_are_dpl3() {
        assert_eq!(USER_CS_U64 & 3, 3);
        assert_eq!(USER_DS_U64 & 3, 3);
        // The CS/SS immediates the entry stub splices in come from these
        // constants; the architectural values are 0x1B / 0x23.
        assert_eq!(USER_CS_U64, 27);
        assert_eq!(USER_DS_U64, 35);
    }

    #[test]
    fn set_user_kernel_stack_reserves_the_top_qword() {
        let top = 0xFFFF_FFFF_8160_0000u64;
        set_user_kernel_stack(top);
        // The frozen invariant: both entry paths use `top - 8`, never `top`.
        assert_eq!(super::super::tss::rsp0(), top - 8);
        assert_eq!(user_kernel_stack(), top - 8);
        set_user_kernel_stack(0xFFFF_FFFF_8170_0000);
        assert_eq!(super::super::tss::rsp0(), 0xFFFF_FFFF_8170_0000 - 8);
        assert_eq!(user_kernel_stack(), 0xFFFF_FFFF_8170_0000 - 8);
    }

    #[test]
    fn saved_user_rsp_reads_the_per_cpu_slot() {
        // The stub writes this slot; it starts zeroed.
        assert_eq!(saved_user_rsp(), 0);
    }
}
