//! Trap frame, entry stubs and the exception/IRQ dispatcher.
//!
//! Every stub builds one uniform frame (low → high addresses):
//!
//! ```text
//! offset   0: r15 r14 r13 r12 rbp rbx r11 r10 r9 r8 rax rcx rdx rsi rdi (15 GPR)
//! offset 120: vector            (pushed by the stub)
//! offset 128: error             (hardware error code, or a dummy 0)
//! offset 136: rip               (CPU frame)
//! offset 144: cs                (CPU frame)
//! offset 152: rflags            (CPU frame)
//! offset 160: user_rsp          (CPU frame, ring3 entries only)
//! offset 168: user_ss           (CPU frame, ring3 entries only)
//! ```
//!
//! A ring0 interrupt has the CPU push only RIP/CS/RFLAGS, so the last two
//! qwords are *scratch* and simply hold whatever was at `frame + 160` on the
//! interrupted kernel stack — which is exactly the interrupted stack pointer.
//! A ring3 entry (interrupt, exception or the `syscall` stub) makes the CPU (or
//! the stub) fill them with the real user RSP/SS, and `iretq` consumes them.
//!
//! Stubs finish with `and rsp, -16` before `call`, because the error/no-error
//! variants can leave RSP differently aligned while the Rust dispatcher
//! requires the SysV entry alignment (`rsp % 16 == 8` on function entry).
//!
//! [`__trap_dispatch`] returns the frame to resume in `rax`; the stub restores
//! RSP from it, pops the 15 GPRs, drops vector/error and executes `iretq`.
//! Returning a *different* frame is how M3 switches stacks for the
//! cooperative `yield` vector. Exceptions never return: they keep the M2
//! behaviour of dumping the frame and halting.
//!
//! M4 adds ring 3: the per-CPU GS base is meaningless to user mode, so every
//! stub that may be entered from ring 3 (`swapgs` on entry) hands the kernel
//! GS base back on the way out. The check is the RPL of the frame's `CS`
//! (`cs & 3`), which is 0 for every kernel frame — so the M3 ring0 path
//! executes exactly the same instructions as before.
//!
//! The kernel is compiled with `-C no-redzone`, so a handler never has to
//! preserve an interrupted-frame red zone below RSP.

use core::arch::{global_asm, naked_asm};

use crate::klog;

use super::gdt::{KERNEL_CS, USER_CS, USER_DS};
use super::{halt, read_cr2};

/// Linear address the M2 self-test deliberately reads to force `#PF`
/// (canonical, unmapped, never touched by any mapping).
pub const DELIBERATE_PF_ADDR: u64 = 0x0000_4000_0000_0000;

/// First vector routed to the platform IRQ dispatcher instead of the
/// exception path (matches the architectural exception/IRQ split).
pub const IRQ_VECTOR_BASE: u64 = 0x20;
/// LAPIC timer vector.
pub const VECTOR_TIMER: u64 = 0x20;
/// PS/2 keyboard (IRQ1 via the 8259 remap).
pub const VECTOR_KEYBOARD: u64 = 0x21;
/// COM1 (IRQ4 via the 8259 remap).
pub const VECTOR_COM1: u64 = 0x24;
/// Software interrupt used by the scheduler for a cooperative switch.
pub const VECTOR_YIELD: u64 = 0x40;
/// Fixed-delivery inter-processor interrupt asking this CPU to re-run its
/// scheduler (M6b2).
///
/// A fixed IPI is edge-triggered, so the handler must **not** write an EOI: the
/// `irq_dispatch` arm returns the frame unchanged after updating the per-CPU
/// reschedule state.
pub const VECTOR_RESCHED: u64 = 0x41;
/// Legacy virtio-net MSI-X vector (M7c).
///
/// The device shares one vector for its configuration, RX and TX entries; the
/// handler only drains the driver rings (see [`crate::irq_dispatch`]) and the
/// boot processor acknowledges the interrupt exactly once.
pub const VECTOR_NET: u64 = 0x42;
/// Spurious-interrupt vector (no EOI expected, no frame beyond the CPU one).
pub const VECTOR_SPURIOUS: u64 = 0xFF;
/// Frame marker used by the `syscall` entry stub; it owns no IDT gate.
pub const VECTOR_SYSCALL: u64 = 0x60;

/// Number of qwords in a [`TrapFrame`]; part of the assembly contract.
pub const FRAME_QWORDS: usize = 22;
/// Qword index of [`TrapFrame::user_rsp`].
pub const Q_USER_RSP: usize = 20;
/// Qword index of [`TrapFrame::user_ss`].
pub const Q_USER_SS: usize = 21;

/// Bytes reserved at the very top of every user thread's kernel stack (a
/// canary/scratch qword). Both ring3 entry paths are programmed with
/// `top - USER_STACK_TOP_RESERVED`. On a real ring3 interrupt the CPU first
/// 16-byte-aligns that `RSP0`, then pushes its 40-byte hardware frame and this
/// stub's 136 bytes, so the frame lands at `align16(top - 8) - 176 == top - 192`
/// (the geometry owned by `process::first_frame_addr`) — 8 bytes below the ring0
/// helper [`user_frame_addr`], because a privilege change aligns the stack and a
/// ring0 trap does not.
pub const USER_STACK_TOP_RESERVED: u64 = 8;

/// Address of a ring0 (M3 kernel-thread) first [`TrapFrame`] for a kernel stack
/// whose (16-byte aligned) top is `kernel_top`: `kernel_top - 8 - 176`, so
/// `frame + 176` is the reserved qword below the top. Ring0 traps take no
/// privilege change, so the CPU does not align the stack and the frame is the
/// last thing above that reserved qword.
///
/// Ring3 frames sit 8 bytes lower (`align16(kernel_top - 8) - 176 == kernel_top -
/// 192`, see `process::first_frame_addr`); this helper keeps the ring0 geometry
/// frozen for the M3 scheduler regression.
pub const fn user_frame_addr(kernel_top: u64) -> u64 {
    kernel_top - USER_STACK_TOP_RESERVED - (FRAME_QWORDS as u64) * 8
}

/// Interrupt frame as built by the entry stubs: the 15 caller-saved/callee-saved
/// GPRs in push order, then vector/error and the interrupted ones.
#[repr(C)]
pub struct TrapFrame {
    pub r15: u64,
    pub r14: u64,
    pub r13: u64,
    pub r12: u64,
    pub rbp: u64,
    pub rbx: u64,
    pub r11: u64,
    pub r10: u64,
    pub r9: u64,
    pub r8: u64,
    pub rax: u64,
    pub rcx: u64,
    pub rdx: u64,
    pub rsi: u64,
    pub rdi: u64,
    pub vector: u64,
    pub error_code: u64,
    pub rip: u64,
    pub cs: u64,
    pub rflags: u64,
    /// Stack pointer the CPU pushed on a ring3 entry; scratch for ring0 frames.
    pub user_rsp: u64,
    /// Stack selector the CPU pushed on a ring3 entry; scratch for ring0 frames.
    pub user_ss: u64,
}

/// Frame size is part of the assembly contract; keep the two in lockstep.
const _: () = assert!(core::mem::size_of::<TrapFrame>() == FRAME_QWORDS * 8);

macro_rules! isr_no_err {
    ($vec:literal) => {
        global_asm!(concat!(
            ".balign 8\n",
            ".globl __isr_",
            $vec,
            "\n",
            "__isr_",
            $vec,
            ":\n",
            "push 0\n", // dummy error code
            "push ",
            $vec,
            "\n", // vector
            "push rdi\n",
            "push rsi\n",
            "push rdx\n",
            "push rcx\n",
            "push rax\n",
            "push r8\n",
            "push r9\n",
            "push r10\n",
            "push r11\n",
            "push rbx\n",
            "push rbp\n",
            "push r12\n",
            "push r13\n",
            "push r14\n",
            "push r15\n",
            "mov rdi, rsp\n",                 // rdi = *mut TrapFrame
            "test byte ptr [rdi + 144], 3\n", // cs RPL: entered from ring3?
            "jz .Lentry_ring0_",
            $vec,
            "\n",
            "swapgs\n", // kernel GS base back in place for kernel code
            ".Lentry_ring0_",
            $vec,
            ":\n",
            "and rsp, -16\n", // SysV stack alignment for the call
            "cld\n",          // a ring3 entry can carry DF=1; Rust must not inherit it
            "call __trap_dispatch\n",
            "mov rsp, rax\n", // resume the frame the dispatcher returned
            "test byte ptr [rsp + 144], 3\n", // resuming into ring3?
            "jz .Lreturn_ring0_",
            $vec,
            "\n",
            "swapgs\n", // hand the GS base back to user mode
            ".Lreturn_ring0_",
            $vec,
            ":\n",
            "pop r15\n",
            "pop r14\n",
            "pop r13\n",
            "pop r12\n",
            "pop rbp\n",
            "pop rbx\n",
            "pop r11\n",
            "pop r10\n",
            "pop r9\n",
            "pop r8\n",
            "pop rax\n",
            "pop rcx\n",
            "pop rdx\n",
            "pop rsi\n",
            "pop rdi\n",
            "add rsp, 16\n", // drop vector + error
            "iretq\n",
        ));
    };
}

macro_rules! isr_err {
    ($vec:literal) => {
        global_asm!(concat!(
            ".balign 8\n",
            ".globl __isr_",
            $vec,
            "\n",
            "__isr_",
            $vec,
            ":\n",
            "push ",
            $vec,
            "\n", // vector (CPU already pushed the error code)
            "push rdi\n",
            "push rsi\n",
            "push rdx\n",
            "push rcx\n",
            "push rax\n",
            "push r8\n",
            "push r9\n",
            "push r10\n",
            "push r11\n",
            "push rbx\n",
            "push rbp\n",
            "push r12\n",
            "push r13\n",
            "push r14\n",
            "push r15\n",
            "mov rdi, rsp\n",                 // rdi = *mut TrapFrame
            "test byte ptr [rdi + 144], 3\n", // cs RPL: entered from ring3?
            "jz .Lentry_ring0_",
            $vec,
            "\n",
            "swapgs\n", // kernel GS base back in place for kernel code
            ".Lentry_ring0_",
            $vec,
            ":\n",
            "and rsp, -16\n", // SysV stack alignment for the call
            "cld\n",          // a ring3 entry can carry DF=1; Rust must not inherit it
            "call __trap_dispatch\n",
            "mov rsp, rax\n", // resume the frame the dispatcher returned
            "test byte ptr [rsp + 144], 3\n", // resuming into ring3?
            "jz .Lreturn_ring0_",
            $vec,
            "\n",
            "swapgs\n", // hand the GS base back to user mode
            ".Lreturn_ring0_",
            $vec,
            ":\n",
            "pop r15\n",
            "pop r14\n",
            "pop r13\n",
            "pop r12\n",
            "pop rbp\n",
            "pop rbx\n",
            "pop r11\n",
            "pop r10\n",
            "pop r9\n",
            "pop r8\n",
            "pop rax\n",
            "pop rcx\n",
            "pop rdx\n",
            "pop rsi\n",
            "pop rdi\n",
            "add rsp, 16\n", // drop vector + error
            "iretq\n",
        ));
    };
}

isr_no_err!(0); // #DE
isr_no_err!(2); // NMI
isr_no_err!(6); // #UD
isr_err!(8); // #DF (hardware error code, always 0 in 64-bit)
isr_err!(12); // #SS
isr_err!(13); // #GP
isr_err!(14); // #PF
isr_err!(17); // #AC
isr_no_err!(32); // LAPIC timer
isr_no_err!(33); // keyboard
isr_no_err!(36); // COM1
isr_no_err!(64); // software yield
isr_no_err!(65); // reschedule IPI (M6b2)
isr_no_err!(66); // virtio-net MSI-X (M7c)
isr_no_err!(255); // spurious

/// Resume an arbitrary [`TrapFrame`]: restore all 15 GPRs and `iretq`.
///
/// Unlike the stubs this pushes nothing of its own: it takes over the caller's
/// stack completely and is the primitive the scheduler/root use to start a
/// thread from a frame that was built by hand (a ring0 synthetic frame or a
/// first ring3 frame). Ring selection follows the frame's `CS` RPL exactly like
/// the stubs, so the per-CPU GS base is swapped for ring3 and left alone for
/// ring0.
///
/// The frame is restored in place (`rsp = frame`): every caller already built it
/// on the stack the resumed context runs on. In particular a ring3 frame is
/// always the target thread's `saved_frame` — the ring3 geometry
/// `align16(kernel_top - 8) - 176 == kernel_top - 192` owned by
/// `process::first_frame_addr` — so the reserved qword at `kernel_top - 8`
/// (canary/scratch) sits immediately above `frame + 176` and is never touched.
/// The caller has already switched to the target address space (CR3) and
/// registered that thread's kernel stack, so the only extra work on the ring3
/// path is `swapgs` (user GS base) before `iretq`, which reloads
/// RIP/CS/RFLAGS/RSP/SS — including the user's own `DF` — from the frame.
///
/// Interrupts are not enabled here: the frame's `rflags` decides `IF` at
/// `iretq`, so the M3 `BOOT_FRAME` return into the root keeps its interrupt
/// policy and nothing is `sti`'d early.
///
/// # Safety
///
/// `frame` must point to a fully initialised, 16-byte-aligned [`TrapFrame`] that
/// lives on the stack this call switches to (for ring3: exactly the target
/// thread's saved frame at `align16(kernel_top - 8) - 176`, with that stack
/// mapped; for ring0: the frame of the context being resumed). For a ring3 frame
/// the caller must also have selected the target address space (CR3) and
/// registered the target kernel stack with
/// [`super::syscall::set_user_kernel_stack`], and prepared `user_rsp`/`user_ss`;
/// it must not expect to run again on the current stack.
#[unsafe(naked)]
pub unsafe extern "C" fn resume_frame(_frame: *mut TrapFrame) -> ! {
    naked_asm!(
        "mov rsp, rdi",                 // rsp = frame (built on the stack we switch to)
        "test byte ptr [rsp + 144], 3", // CS RPL: resuming into ring3?
        "jz 2f",
        "swapgs", // user GS base again for the ring3 return
        "2:",
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
        "iretq",
    )
}

/// Build a ring3 [`TrapFrame`] that enters `entry` with stack `user_rsp`.
///
/// The frame must live at the ring3 saved-frame address,
/// `align16(kernel_top - 8) - 176 == kernel_top - 192` (owned by
/// `process::first_frame_addr`), so `frame + 176 == kernel_top - 16` and the
/// reserved qword at `kernel_top - 8` stays untouched: a later real ring3
/// interrupt (the CPU aligns `RSP0`, then pushes its 40-byte hardware frame plus
/// this stub's 136 bytes) rebuilds exactly the same frame.
///
/// `rflags` is exactly `0x202` (reserved bit 1 + `IF`); `IOPL`/`NT`/`TF`/`DF`/`AC`
/// stay clear, so ring3 cannot touch I/O ports and a kernel-mode return cannot
/// take the nested-task path.
///
/// # Safety
///
/// `frame` must point to writable, 8-byte-aligned storage of at least
/// `size_of::<TrapFrame>()` bytes inside the target thread's kernel stack.
pub unsafe fn init_user_frame(frame: *mut TrapFrame, entry: u64, user_rsp: u64) {
    // SAFETY: the caller guarantees a whole writable frame.
    let f = unsafe { &mut *frame };
    f.r15 = 0;
    f.r14 = 0;
    f.r13 = 0;
    f.r12 = 0;
    f.rbp = 0;
    f.rbx = 0;
    f.r11 = 0;
    f.r10 = 0;
    f.r9 = 0;
    f.r8 = 0;
    f.rax = 0;
    f.rcx = 0;
    f.rdx = 0;
    f.rsi = 0;
    f.rdi = 0;
    f.vector = 0;
    f.error_code = 0;
    f.rip = entry;
    f.cs = USER_CS as u64;
    f.rflags = 0x202; // reserved bit 1 + IF; IOPL/NT/DF/AC clear
    f.user_rsp = user_rsp;
    f.user_ss = USER_DS as u64;
}

fn vector_name(v: u64) -> &'static str {
    match v {
        0 => "#DE",
        2 => "NMI",
        6 => "#UD",
        8 => "#DF",
        12 => "#SS",
        13 => "#GP",
        14 => "#PF",
        17 => "#AC",
        32 => "timer",
        33 => "keyboard",
        36 => "com1",
        64 => "yield",
        255 => "spurious",
        _ => "?",
    }
}

fn dump(f: &TrapFrame) {
    if f.cs != KERNEL_CS as u64 {
        klog!(
            "[CaelumKernel]   note: cs={:#06x} (expected kernel {:#06x})",
            f.cs,
            KERNEL_CS
        );
    }
    let cr2 = if f.vector == 14 { read_cr2() } else { 0 };
    if f.vector == 14 {
        let e = f.error_code;
        klog!(
            "[CaelumKernel] EXCEPTION #PF error=0x{e:04x} P={} W={} U={} RSVD={} ID={}",
            e & 1,
            (e >> 1) & 1,
            (e >> 2) & 1,
            (e >> 3) & 1,
            (e >> 4) & 1
        );
        klog!(
            "[CaelumKernel]   cr2=0x{cr2:016x} cs={:#06x} rflags=0x{:016x}",
            f.cs,
            f.rflags
        );
    } else {
        klog!(
            "[CaelumKernel] EXCEPTION {} error=0x{:04x}",
            vector_name(f.vector),
            f.error_code
        );
        klog!(
            "[CaelumKernel]   cs={:#06x} rflags=0x{:016x}",
            f.cs,
            f.rflags
        );
    }
    klog!("[CaelumKernel]   rip=0x{:016x}", f.rip);
    klog!(
        "[CaelumKernel]   rax=0x{:016x} rbx=0x{:016x} rcx=0x{:016x} rdx=0x{:016x}",
        f.rax,
        f.rbx,
        f.rcx,
        f.rdx
    );
    klog!(
        "[CaelumKernel]   rsi=0x{:016x} rdi=0x{:016x} rbp=0x{:016x} r8 =0x{:016x}",
        f.rsi,
        f.rdi,
        f.rbp,
        f.r8
    );
    klog!(
        "[CaelumKernel]   r9 =0x{:016x} r10=0x{:016x} r11=0x{:016x} r12=0x{:016x}",
        f.r9,
        f.r10,
        f.r11,
        f.r12
    );
    klog!(
        "[CaelumKernel]   r13=0x{:016x} r14=0x{:016x} r15=0x{:016x}",
        f.r13,
        f.r14,
        f.r15
    );
}

/// Trap entry, called from every stub with `rdi = frame`.
///
/// Returns the frame to resume; the stub reloads RSP from it. Exceptions
/// (vector < 0x20) keep the M2 diagnostics and never return.
#[unsafe(no_mangle)]
pub extern "C" fn __trap_dispatch(frame: *mut TrapFrame) -> *mut TrapFrame {
    // SAFETY: the stubs pass a fully built frame on the interrupted stack and
    // the trap gate keeps interrupts disabled, so the reference cannot race.
    let f = unsafe { &*frame };
    if f.vector >= IRQ_VECTOR_BASE {
        let next = crate::irq_dispatch(frame);
        if next.is_null() {
            klog!(
                "[CaelumKernel] irq_dispatch returned a null frame for vector {:#04x}, halting",
                f.vector
            );
            halt();
        }
        return next;
    }
    if f.vector == 14 && read_cr2() == DELIBERATE_PF_ADDR {
        dump(f);
        klog!("[CaelumKernel] M2 #PF caught (deliberate unmapped read)");
        klog!("[CaelumKernel] halting");
        halt();
    }
    if f.vector == 14 {
        klog!("[CaelumKernel] unexpected #PF (kernel bug?), halting");
    } else if f.vector == 8 {
        klog!("[CaelumKernel] double fault (stack overflow?), halting");
    } else {
        klog!("[CaelumKernel] unexpected exception, halting");
    }
    dump(f);
    halt();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frame_layout_is_the_asm_contract() {
        use core::mem::offset_of;
        assert_eq!(core::mem::size_of::<TrapFrame>(), FRAME_QWORDS * 8);
        assert_eq!(core::mem::align_of::<TrapFrame>(), 8);
        // 15 GPRs in push order, then vector/error, then the CPU frame.
        assert_eq!(offset_of!(TrapFrame, r15), 0);
        assert_eq!(offset_of!(TrapFrame, r14), 8);
        assert_eq!(offset_of!(TrapFrame, r13), 16);
        assert_eq!(offset_of!(TrapFrame, r12), 24);
        assert_eq!(offset_of!(TrapFrame, rbp), 32);
        assert_eq!(offset_of!(TrapFrame, rbx), 40);
        assert_eq!(offset_of!(TrapFrame, r11), 48);
        assert_eq!(offset_of!(TrapFrame, r10), 56);
        assert_eq!(offset_of!(TrapFrame, r9), 64);
        assert_eq!(offset_of!(TrapFrame, r8), 72);
        assert_eq!(offset_of!(TrapFrame, rax), 80);
        assert_eq!(offset_of!(TrapFrame, rcx), 88);
        assert_eq!(offset_of!(TrapFrame, rdx), 96);
        assert_eq!(offset_of!(TrapFrame, rsi), 104);
        assert_eq!(offset_of!(TrapFrame, rdi), 112);
        assert_eq!(offset_of!(TrapFrame, vector), 120);
        assert_eq!(offset_of!(TrapFrame, error_code), 128);
        assert_eq!(offset_of!(TrapFrame, rip), 136);
        assert_eq!(offset_of!(TrapFrame, cs), 144);
        assert_eq!(offset_of!(TrapFrame, rflags), 152);
        assert_eq!(offset_of!(TrapFrame, user_rsp), Q_USER_RSP * 8);
        assert_eq!(offset_of!(TrapFrame, user_ss), Q_USER_SS * 8);
        assert_eq!(offset_of!(TrapFrame, user_rsp), 160);
        assert_eq!(offset_of!(TrapFrame, user_ss), 168);
    }

    #[test]
    fn resume_frame_iret_tail_is_the_last_five_qwords() {
        use core::mem::offset_of;
        // `resume_frame` pops the 15 GPRs, drops vector+error with `add rsp, 16`
        // and then `iretq` consumes rip/cs/rflags (and, for a ring3 frame,
        // user_rsp/user_ss). Those 40 bytes must end exactly at the frame end.
        assert_eq!(offset_of!(TrapFrame, rip), 136);
        assert_eq!(offset_of!(TrapFrame, user_ss) + 8, FRAME_QWORDS * 8);
        assert_eq!(
            offset_of!(TrapFrame, user_ss) + 8 - offset_of!(TrapFrame, rip),
            40,
            "rip..user_ss is the iretq tail"
        );
        // `user_frame_addr` is the ring0 (M3 kernel-thread) geometry, where no
        // privilege change happens: the frame's tail ends exactly on the
        // reserved qword, so a ring0 trap's iretq tail is the last thing above it.
        let top = 0xFFFF_FFFF_8130_4000u64;
        let frame = user_frame_addr(top);
        assert_eq!(
            frame + (FRAME_QWORDS as u64) * 8,
            top - USER_STACK_TOP_RESERVED
        );
    }

    #[test]
    fn init_user_frame_builds_a_ring3_entry() {
        let mut frame = TrapFrame {
            r15: 0,
            r14: 0,
            r13: 0,
            r12: 0,
            rbp: 0,
            rbx: 0,
            r11: 0,
            r10: 0,
            r9: 0,
            r8: 0,
            rax: 0,
            rcx: 0,
            rdx: 0,
            rsi: 0,
            rdi: 0,
            vector: 0,
            error_code: 0,
            rip: 0,
            cs: 0,
            rflags: 0,
            user_rsp: 0,
            user_ss: 0,
        };
        // SAFETY: `frame` is a live, writable `TrapFrame` on this thread's stack.
        unsafe { init_user_frame(&mut frame, 0x0000_0000_0040_0000, 0x7FFF_FFFF_F000) };
        assert_eq!(frame.rip, 0x0000_0000_0040_0000);
        assert_eq!(frame.cs, USER_CS as u64);
        assert_eq!(frame.user_ss, USER_DS as u64);
        assert_eq!(frame.user_rsp, 0x7FFF_FFFF_F000);
        assert_eq!(frame.rflags, 0x202, "only reserved bit 1 and IF");
        // RPL of the code selector is ring 3, so the stubs will swapgs.
        assert_eq!(frame.cs & 3, 3);
        for gpr in [
            frame.r15, frame.r14, frame.r13, frame.r12, frame.rbp, frame.rbx, frame.r11, frame.r10,
            frame.r9, frame.r8, frame.rax, frame.rcx, frame.rdx, frame.rsi, frame.rdi,
        ] {
            assert_eq!(gpr, 0, "user entry starts with cleared GPRs");
        }
    }

    #[test]
    fn syscall_marker_vector_is_outside_the_idt_range() {
        // 0x60 is informational only: the syscall stub has no IDT gate and the
        // dispatcher is never asked to return a frame for it.
        assert_eq!(VECTOR_SYSCALL, 0x60);
        assert!(VECTOR_SYSCALL >= IRQ_VECTOR_BASE);
    }

    #[test]
    fn first_frames_sit_below_the_reserved_top_qword() {
        let top = 0xFFFF_FFFF_8160_0000u64;
        // Ring0 (M3 kernel thread): no privilege change, no CPU alignment.
        let frame = user_frame_addr(top);
        assert_eq!(frame, top - 184);
        assert_eq!(frame + (FRAME_QWORDS as u64) * 8, top - 8);
        // Ring3 (process/irq geometry, owned by `process::first_frame_addr`): the
        // CPU aligns RSP0 = top - 8 down to 16 bytes before pushing its 40-byte
        // hardware frame, and the stub adds 136 bytes.
        let ring3 = ((top - USER_STACK_TOP_RESERVED) & !0xF) - (FRAME_QWORDS as u64) * 8;
        assert_eq!(ring3, top - 192);
        assert_eq!(ring3 + (FRAME_QWORDS as u64) * 8, top - 16);
        assert_eq!(((top - 8) & !0xF) - 40 - 136, ring3);
        assert_eq!(USER_STACK_TOP_RESERVED, 8);
    }
}
