//! Thread scheduling: the M3 kernel-thread demo (A/B, cooperative yield plus
//! LAPIC-timer preemption) and the M4 user-mode round robin.
//!
//! # Frame ABI (frozen, see `arch::traps`)
//!
//! A trap frame is [`FRAME_QWORDS`] = 22 qwords: 15 GPRs, `vector`,
//! `error_code`, `rip`, `cs`, `rflags`, `user_rsp`, `user_ss`. The dispatcher
//! returns the frame the interrupted context must resume from; the IRQ stub
//! (`__isr_*`) then does `mov rsp, rax; ...; iretq`, so returning a *different*
//! frame is a context switch.
//!
//! - Ring0 (M3 kernel threads): `user_rsp` / `user_ss` are scratch slots that a
//!   same-privilege `iretq` does not pop on bare metal, but QEMU's 64-bit model
//!   does pop them, so they hold well-formed values: the post-return stack
//!   pointer (`frame + 160`, i.e. `top - 24`, 8 mod 16 for the SysV entry
//!   convention) and `KERNEL_DS`.
//! - Ring3 (M4 user threads): the two slots are real state. A
//!   privilege-changing `iretq` pops the user stack pointer and `USER_DS`, so
//!   the first frame is built by [`arch::traps::init_user_frame`] and nothing
//!   may overwrite those slots (Lead m00502).
//!
//! # Stacks
//!
//! Every thread owns a 4-page PMM stack in the kernel window with an unmapped
//! guard page below it and canaries at both ends:
//!
//! ```text
//! base - 4096  guard page (never mapped)
//! base         LO canary (16 bytes)
//! ...          stack
//! top - 192    synthetic ring3 first frame (22 qwords, user processes)
//! top - 184    synthetic ring0 first frame (22 qwords, M3 kernel threads)
//! top - 16     first byte the hardware writes on a ring3 entry
//! top - 8      TOP canary / entry scratch
//! top          end of the mapping
//! ```
//!
//! The ring3 frame sits 8 bytes lower than the naive `top - 8 - 176` layout:
//! on a privilege-changing interrupt the CPU first aligns the new stack pointer
//! (`TSS.RSP0 = top - 8`, set by `arch::set_user_kernel_stack`) **down to a
//! 16-byte boundary** and only then pushes `SS`/`RSP`/`RFLAGS`/`CS`/`RIP`
//! (40 bytes). With the stub's 136 bytes the frame therefore ends at `top - 16`
//! and starts at `top - 192` (see `process::first_frame_addr`, which owns the
//! user geometry). A real timer interrupt enters *exactly* on the synthetic
//! frame and the TOP canary at `top - 8` is never touched. Kernel threads never
//! change privilege, so their first frame stays at `top - 184` and the two
//! geometries are deliberately distinct.
//!
//! # Blocking (M6a1)
//!
//! A process that waits on event objects is `Blocked` in `process`, so the round
//! robin never selects it. [`process::block_current`] copies its private
//! `syscall` frame (`top - 184`) into a `.bss` slot, rewrites `rip` back over
//! the two-byte `syscall` instruction and calls [`block_and_switch`], which
//! switches immediately when another process is `Ready` and otherwise idles with
//! interrupts enabled on the blocked process's own kernel stack. Wakes are
//! ISR-safe and never switch: the timer ISR only records a wake reason (expired
//! deadline) or an IPC/object destroy wakes a waiter, and the idle loop performs
//! the switch. Because the copied frame lives in `.bss`, the interrupt frames
//! produced while idling (`top - 192 … top - 16`) cannot clobber it; when no
//! process is runnable at all, [`on_user_exit`] idles too instead of finishing
//! the demo underneath a blocked sibling.
//!
//! # M3 demo and its return path
//!
//! [`start`] allocates the two kernel stacks, enters thread A through the real
//! `int 0x40` gate (boot context -> A), and A yields until B has been pushed
//! forward by the timer, then prints the M3 markers. Instead of replaying the
//! M2 page fault itself, the demo *returns* to its caller: the boot context's
//! stack pointer, return address and callee-saved registers are captured in a
//! synthetic ring0 frame whose `rip` is [`boot_return_trampoline`]. Resuming it
//! restores `rsp` to the value after `call sched::start` and jumps to the
//! captured return address, which is indistinguishable from a normal return
//! with `IF=1`. The deliberate `#PF` is the final step of M4
//! (`crate::complete_m4`).
//!
//! # M4 user round robin
//!
//! [`start_user`] switches to the first process's address space, points
//! `TSS.RSP0` at its kernel stack and resumes its ring3 frame. While
//! `USER_MODE` is set, [`on_timer`] parks the running process, picks the next
//! ready one (round robin, pure policy in `process::choose_next`), switches
//! CR3 + kernel stack and returns the next frame. [`on_user_exit`] switches
//! away from an exiting process and ends the demo when nothing is runnable.
//! These paths never allocate and never log on the switch path.

use core::arch::{asm, naked_asm};
use core::mem::{offset_of, size_of};
use core::ptr;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use crate::arch::gdt::{KERNEL_CS, KERNEL_DS};
use crate::arch::traps::{FRAME_QWORDS, Q_USER_RSP, Q_USER_SS};
use crate::arch::{
    MAX_CPUS, TrapFrame, cpu_index, halt, resume_frame, set_user_fs_base, set_user_kernel_stack,
};
use crate::klog;
use crate::mm::{addrspace, pmm, vm};
use crate::platform;
use crate::process::{self, ProcessId};

// ---------------------------------------------------------------------------
// Frame ABI constants
// ---------------------------------------------------------------------------

/// Bytes of one trap frame (22 qwords).
const FRAME_BYTES: u64 = (FRAME_QWORDS as u64) * 8;

/// Offsets of the fields the synthetic first frames must fill explicitly.
const Q_VECTOR: usize = 15;
const Q_ERROR: usize = 16;
const Q_RIP: usize = 17;
const Q_CS: usize = 18;
const Q_RFLAGS: usize = 19;

/// `RFLAGS.IF` plus the reserved bit 1, i.e. the value a fresh context starts
/// with so interrupts come back exactly when the new context runs.
const RFLAGS_IF: u64 = 0x202;

const _: () = {
    assert!(size_of::<TrapFrame>() == FRAME_BYTES as usize);
    assert!(offset_of!(TrapFrame, r15) == 0);
    assert!(offset_of!(TrapFrame, vector) == Q_VECTOR * 8);
    assert!(offset_of!(TrapFrame, error_code) == Q_ERROR * 8);
    assert!(offset_of!(TrapFrame, rip) == Q_RIP * 8);
    assert!(offset_of!(TrapFrame, cs) == Q_CS * 8);
    assert!(offset_of!(TrapFrame, rflags) == Q_RFLAGS * 8);
    // The ring3 entry path depends on the CPU popping these two slots.
    assert!(offset_of!(TrapFrame, user_rsp) == Q_USER_RSP * 8);
    assert!(offset_of!(TrapFrame, user_ss) == Q_USER_SS * 8);
};

// ---------------------------------------------------------------------------
// Stack geometry (M3 kernel threads; user processes keep their ring3 geometry
// in `process::first_frame_addr`, which is 8 bytes lower — see the module docs)
// ---------------------------------------------------------------------------

const PAGE_SIZE: u64 = pmm::FRAME_SIZE;
/// Four pages per stack: deep enough for the trap frame, the ISR stub and the
/// Rust thread bodies, with room to spare for the canary checks.
const STACK_FRAMES: u64 = 4;
const STACK_BYTES: u64 = STACK_FRAMES * PAGE_SIZE;

/// Canaries at the very bottom of the mapping: a two-qword pattern catches both
/// a downward overflow and a stray write at `base`.
const LO_CANARY_BYTES: u64 = 16;

/// The top slot holds the TOP canary; the ring3 entry paths use `top - 8` as
/// their scratch (`TSS.RSP0`), so it must never become part of a frame.
const TOP_CANARY_BYTES: u64 = 8;

const CANARY_LO0: u64 = 0x0BAD_C0DE_5EED_F00D;
const CANARY_LO1: u64 = 0x0BAD_C0DE_DEAD_BEEF;
const CANARY_TOP: u64 = 0x0BAD_C0DE_CAFE_F00D;

/// Address of the synthetic **ring0** first frame for a kernel-thread stack.
///
/// `frame + FRAME_BYTES == top - TOP_CANARY_BYTES`. A ring0 entry never changes
/// privilege, so the CPU does not align the stack pointer and this stays at
/// `top - 184`; the ring3 entry (user processes) is 8 bytes lower and lives in
/// `process::first_frame_addr`.
const fn first_frame_addr(base: u64) -> u64 {
    base + STACK_BYTES - TOP_CANARY_BYTES - FRAME_BYTES
}

/// Kernel-thread stacks (M3). Fresh PD windows, clear of the image at
/// `0xffffffff80000000`, of the M2 boot stack at
/// `0xffffffff81001000..0xffffffff81005000`, of the M4 user kernel stacks at
/// `0xffffffff81500000`/`0xffffffff81600000` and of the platform window at
/// `0xffffffff82000000`. The page at `base - PAGE_SIZE` is the guard, never
/// mapped.
const STACK_A_BASE: u64 = 0xFFFF_FFFF_8130_0000;
const STACK_B_BASE: u64 = 0xFFFF_FFFF_8140_0000;

const _: () = {
    assert!((STACK_A_BASE + STACK_BYTES) <= STACK_B_BASE - PAGE_SIZE);
    assert!((STACK_B_BASE + STACK_BYTES) < 0xFFFF_FFFF_8200_0000);
    assert!(STACK_A_BASE >= 0xFFFF_FFFF_8100_0000 + 0x5000);
    assert!(STACK_BYTES >= LO_CANARY_BYTES + TOP_CANARY_BYTES + FRAME_BYTES + PAGE_SIZE);
    // Ring0 threads: the frame ends exactly at the TOP canary (no privilege
    // change, so the CPU does not realign the stack pointer).
    assert!(
        first_frame_addr(STACK_A_BASE) + FRAME_BYTES
            == STACK_A_BASE + STACK_BYTES - TOP_CANARY_BYTES
    );
    assert!(
        first_frame_addr(STACK_B_BASE) + FRAME_BYTES
            == STACK_B_BASE + STACK_BYTES - TOP_CANARY_BYTES
    );
    // Ring3 processes: the hardware aligns `RSP0 = top - 8` down to 16 bytes, so
    // their frame is exactly one qword below the ring0 geometry.
    assert!(
        crate::process::first_frame_addr(STACK_A_BASE + STACK_BYTES)
            == first_frame_addr(STACK_A_BASE) - 8
    );
    // iretq must leave the ring0 thread entry at a `%rsp % 16 == 8` boundary.
    assert!((first_frame_addr(STACK_A_BASE) + FRAME_BYTES) % 16 == 8);
};

// ---------------------------------------------------------------------------
// Threads and scheduler state
// ---------------------------------------------------------------------------

const THREAD_A: usize = 0;
const THREAD_B: usize = 1;
const NTHREADS: usize = 2;

/// Sentinel for the pre-scheduler context (M2 boot thread, abandoned at the
/// first switch; its stack is never resumed, so it needs no canaries).
const BOOT: u8 = 0xFF;

struct Thread {
    /// Virtual base of the lowest mapped stack page.
    stack_base: u64,
    /// Frame to resume when this thread is next scheduled. Never null once
    /// [`start`] has built it: it starts at the synthetic frame and is replaced
    /// by the real interrupted frame on every switch away.
    saved: *mut TrapFrame,
}

struct Sched {
    threads: [Thread; NTHREADS],
    /// `BOOT` until the first dispatch, then a thread index.
    current: u8,
}

static mut SCHED: Sched = Sched {
    threads: [
        Thread {
            stack_base: STACK_A_BASE,
            saved: ptr::null_mut(),
        },
        Thread {
            stack_base: STACK_B_BASE,
            saved: ptr::null_mut(),
        },
    ],
    current: BOOT,
};

#[inline]
fn sched_ptr() -> *mut Sched {
    ptr::addr_of_mut!(SCHED)
}

#[inline]
fn threads_ptr(st: *mut Sched) -> *mut Thread {
    // SAFETY: `st` is the address of the `SCHED` static (see `sched_ptr`); it
    // is never null and `threads` is reached through `addr_of_mut!`, so no
    // `static mut` reference is formed.
    unsafe { ptr::addr_of_mut!((*st).threads) as *mut Thread }
}

// ---------------------------------------------------------------------------
// Statistics / liveness (single CPU; atomics keep the ISR-side updates
// independent of the thread-side reads and document the shared state)
// ---------------------------------------------------------------------------

static STARTED: AtomicBool = AtomicBool::new(false);
/// Set once the M3 demo is over: kernel-context timers then pass through
/// unchanged until M4 enables user mode.
static M3_DONE: AtomicBool = AtomicBool::new(false);
/// Set by [`start_user`]; from then on timer ticks drive the user round robin.
static USER_MODE: AtomicBool = AtomicBool::new(false);

/// Every real M3 context switch, including the boot -> A one.
static SWITCHES: AtomicU64 = AtomicU64::new(0);
/// Yields issued by A through `int 0x40`.
static A_YIELDS: AtomicU64 = AtomicU64::new(0);
/// Timer preemptions of A (timer fires while A runs -> B).
static A_TIMER_PREEMPTS: AtomicU64 = AtomicU64::new(0);
/// Timer preemptions of B (timer fires while B runs -> A). This is the
/// "B was pushed forward by the timer" evidence.
static B_TIMER_PREEMPTS: AtomicU64 = AtomicU64::new(0);
/// B's progress counter (it never yields, so this only grows while it runs).
static B_ITERATIONS: AtomicU64 = AtomicU64::new(0);
/// User-mode context switches (timer + exit handovers).
static USER_SWITCHES: AtomicU64 = AtomicU64::new(0);

/// A must reach this many completed yields ...
const YIELD_TARGET: u64 = 4;
/// ... and B must have been preempted by the timer this many times.
const PREEMPT_TARGET: u64 = 4;
/// Failure bound for A: every loop iteration issues exactly one yield, and the
/// success condition needs about eight, so 256 is a generous upper bound that
/// does not assume a timer period.
const MAX_A_LOOP_ITERS: u64 = 256;
/// Failure bound for B: iterations without the timer taking the CPU away. Well
/// above any plausible interrupt period on QEMU, used only to turn "timer never
/// fired" into a loud failure instead of a silent hang.
const MAX_B_SPIN_WITHOUT_PREEMPT: u64 = 100_000_000;
/// Failure bound for the whole M3 run: success needs well under 32 switches, so
/// a run that reaches 4096 is not converging.
const MAX_SWITCHES: u64 = 4096;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Event {
    Yield,
    Timer,
}

// ---------------------------------------------------------------------------
// Boot-context return machinery (M3 demo returns to its caller)
// ---------------------------------------------------------------------------

/// Stack pointer at the `call sched::start` site (points at the return
/// address), captured by the naked entry shim.
static START_ENTRY_RSP: AtomicU64 = AtomicU64::new(0);
/// Callee-saved registers captured before any Rust code runs, so the return
/// path restores exactly the caller's values.
static START_RBX: AtomicU64 = AtomicU64::new(0);
static START_RBP: AtomicU64 = AtomicU64::new(0);
static START_R12: AtomicU64 = AtomicU64::new(0);
static START_R13: AtomicU64 = AtomicU64::new(0);
static START_R14: AtomicU64 = AtomicU64::new(0);
static START_R15: AtomicU64 = AtomicU64::new(0);

/// Synthetic ring0 frame that returns to the `sched::start` caller. A static
/// buffer rather than a stack slot: the boot stack must not be touched while
/// the demo runs, and `resume_frame` only needs readable memory.
static mut BOOT_FRAME: [u64; FRAME_QWORDS] = [0; FRAME_QWORDS];
static BOOT_RSP: AtomicU64 = AtomicU64::new(0);
static BOOT_RET: AtomicU64 = AtomicU64::new(0);

/// Enter the scheduler from the boot context.
///
/// A naked shim, so the captured stack pointer is *the caller's* (a Rust body
/// would already have its own frame): it records `rsp` and the callee-saved
/// registers, then calls [`start_inner`] with a correctly aligned stack.
///
/// Returns only through [`boot_return_trampoline`]; the C ABI is used so the
/// call/return convention is exactly the one the trampoline emulates.
#[unsafe(naked)]
pub extern "C" fn start() {
    naked_asm!(
        // rdi = caller's rsp (the slot holding the return address)
        "mov rdi, rsp",
        "mov qword ptr [rip + {entry_rsp}], rdi",
        "mov qword ptr [rip + {rbx}], rbx",
        "mov qword ptr [rip + {rbp}], rbp",
        "mov qword ptr [rip + {r12}], r12",
        "mov qword ptr [rip + {r13}], r13",
        "mov qword ptr [rip + {r14}], r14",
        "mov qword ptr [rip + {r15}], r15",
        // SysV requires rsp % 16 == 0 before the call; at entry it is 8.
        "sub rsp, 8",
        "call {inner}",
        // start_inner never returns normally; make a bug loud.
        "ud2",
        entry_rsp = sym START_ENTRY_RSP,
        rbx = sym START_RBX,
        rbp = sym START_RBP,
        r12 = sym START_R12,
        r13 = sym START_R13,
        r14 = sym START_R14,
        r15 = sym START_R15,
        inner = sym start_inner,
    );
}

/// Build the boot return frame, set up the M3 kernel threads and enter A.
fn start_inner(entry_rsp: u64) {
    // The stack build must never be preempted by a timer that would find the
    // boot context without a prepared return frame.
    unsafe { asm!("cli", options(nomem, nostack)) };

    if STARTED.load(Ordering::Acquire) {
        fail("start called twice");
    }
    if let Err(why) = unsafe { setup_threads() } {
        fail(why);
    }
    unsafe { prepare_boot_frame(entry_rsp) };
    STARTED.store(true, Ordering::Release);

    // Synthetic first yield: the dispatcher sees the boot context and resumes A
    // from its prepared frame. The boot stack is abandoned here.
    unsafe { asm!("int 0x40") };
    fail("boot context resumed without the return trampoline");
}

/// Capture the boot context's return state in a synthetic ring0 frame.
unsafe fn prepare_boot_frame(entry_rsp: u64) {
    unsafe {
        let frame = ptr::addr_of_mut!(BOOT_FRAME) as *mut TrapFrame;
        ptr::write_bytes(frame as *mut u8, 0, FRAME_BYTES as usize);

        (*frame).rbx = START_RBX.load(Ordering::Relaxed);
        (*frame).rbp = START_RBP.load(Ordering::Relaxed);
        (*frame).r12 = START_R12.load(Ordering::Relaxed);
        (*frame).r13 = START_R13.load(Ordering::Relaxed);
        (*frame).r14 = START_R14.load(Ordering::Relaxed);
        (*frame).r15 = START_R15.load(Ordering::Relaxed);

        (*frame).rip = boot_return_trampoline as *const () as usize as u64;
        (*frame).cs = KERNEL_CS as u64;
        (*frame).rflags = RFLAGS_IF;
        // Ring0 return: hardware does not pop these two, QEMU does. Give both
        // models the same well-formed values (see the module docs).
        (*frame).user_rsp = entry_rsp + 8;
        (*frame).user_ss = KERNEL_DS as u64;

        BOOT_RSP.store(entry_rsp + 8, Ordering::Release);
        // SAFETY: `entry_rsp` is the caller's `rsp` at the call site; the top
        // slot is the return address and is readable on the boot stack.
        BOOT_RET.store(ptr::read(entry_rsp as *const u64), Ordering::Release);
    }
}

/// Restore the boot context's stack and jump to its return address.
///
/// `resume_frame` has already restored the callee-saved registers from the
/// synthetic frame; only `rsp` and the instruction pointer are left.
#[unsafe(naked)]
unsafe extern "C" fn boot_return_trampoline() -> ! {
    naked_asm!(
        "mov rsp, qword ptr [rip + {rsp}]",
        "jmp qword ptr [rip + {ret}]",
        rsp = sym BOOT_RSP,
        ret = sym BOOT_RET,
    );
}

/// Leave the M3 demo: mark it done and return to the caller of [`start`].
fn finish_m3() -> ! {
    M3_DONE.store(true, Ordering::Release);
    let frame = ptr::addr_of_mut!(BOOT_FRAME) as *mut TrapFrame;
    // SAFETY: the frame is a well-formed ring0 frame built by
    // `prepare_boot_frame`; `resume_frame` never returns.
    unsafe { resume_frame(frame) }
}

// ---------------------------------------------------------------------------
// Public dispatcher entry points (called with IF=0)
// ---------------------------------------------------------------------------

/// Timer preemption entry point.
///
/// Before [`start`] nothing is touched. After the M3 demo (and before M4
/// enables user mode) the root is mutating global state in kernel context, so
/// the tick is ignored. In user mode the tick drives the round robin; a tick
/// that interrupts *kernel* mode (for example a syscall that briefly enables
/// interrupts) is also ignored: M4 has no kernel preemption, so the interrupted
/// kernel frame is simply resumed.
pub fn on_timer(frame: *mut TrapFrame) -> *mut TrapFrame {
    if !STARTED.load(Ordering::Acquire) {
        return frame;
    }
    if USER_MODE.load(Ordering::Acquire) {
        // Expire blocked deadlines first; an ISR wake only records the reason
        // and marks the waiter `Ready`, it never switches.
        process::wake_expired(crate::time::monotonic_ticks());
        if frame.is_null() || !frame_is_user(frame) {
            // Kernel-mode tick: either the blocked-idle loop or a syscall that
            // briefly enabled interrupts. M4 has no kernel preemption, so never
            // switch away from this frame.
            return frame;
        }
        return schedule_user_on(0, frame);
    }
    if M3_DONE.load(Ordering::Acquire) {
        return frame;
    }
    dispatch(frame, Event::Timer)
}

/// Cooperative yield entry point (`int 0x40`).
///
/// Only the M3 kernel threads use it; a ring3 `int 0x40` is not a yield in M4
/// and is ignored instead of killing the process.
pub fn on_yield(frame: *mut TrapFrame) -> *mut TrapFrame {
    if !STARTED.load(Ordering::Acquire) || M3_DONE.load(Ordering::Acquire) {
        return frame;
    }
    if USER_MODE.load(Ordering::Acquire) {
        return frame;
    }
    dispatch(frame, Event::Yield)
}

// ---------------------------------------------------------------------------
// M6b2: per-CPU scheduling (AP idle, AP timer preemption, reschedule IPI)
// ---------------------------------------------------------------------------
//
// M6b1 left every AP parked in `cli; hlt` with `IF = 0`. A fixed reschedule IPI
// cannot be delivered in that state, so `smp::ap_entry` now hands an online AP
// to [`ap_idle`]: `IF = 1`, no timer, and nothing else to do until the root calls
// [`enable_smp_scheduler`]. Only then does [`ap_main`] install the AP's own LAPIC
// timer and start claiming processes from the per-CPU run queue.
//
// Ownership rules that keep the four CPUs from duplicating work:
//
// * `process::claim_next_on(cpu, from)` performs *selection and the `Running`
//   transition* inside the process-table lock; `sched` never marks a process
//   running outside that lock, so two CPUs cannot pick the same `Ready` entry.
// * A process is chosen **before** the current one is parked, so a claim never
//   considers the process that is still executing on this CPU.
// * Blocking and deadline expiry stay on the boot processor: only the BSP timer
//   path calls `process::wake_expired`, `time::on_timer` and
//   `ipc::timer::on_tick`. An AP timer interrupt only accounts its own tick and
//   possibly preempts the local ring3 frame; a wake that lands on another CPU is
//   turned into vector 0x41 by [`publish_resched`].
// * An AP that has nothing to run idles with `sti; hlt`; `IF` is dropped again
//   immediately after every wake so the CR3/RSP0 pair is switched atomically
//   (`activate_user_context` requires `IF = 0`).

/// Snapshot of one CPU's scheduler counters.
#[derive(Clone, Copy, Default, PartialEq, Eq, Debug)]
pub struct CpuStats {
    /// LAPIC timer interrupts taken on this CPU.
    pub ticks: u64,
    /// Ring3 context switches performed on this CPU.
    pub switches: u64,
    /// Times this CPU resumed a process in ring3.
    pub user_entries: u64,
    /// Timer ticks that really switched away from a ring3 frame on this CPU.
    pub preempts: u64,
    /// Times this CPU idled (`sti; hlt`) waiting for work.
    pub idle_wakes: u64,
    /// Reschedule IPIs received on this CPU.
    pub remote_wakes: u64,
}

/// Aggregate view the root prints (and asserts on) after the M6b2 closeout.
///
/// The root-facing shape is frozen by Lead m00271: **seven public `u64` fields**.
/// They aggregate this module's per-CPU counters with the process layer's
/// wake/migration bookkeeping and the platform's IPI counter, so one snapshot
/// call is enough for the root to print and to decide pass/fail. Nothing here is
/// printed by the scheduler (the root owns all serial output).
///
/// Field meanings:
///
/// * `runs` — ring3 resumes that happened on application processors (BSP resumes
///   are excluded: they are the pre-M6b2 behaviour and prove nothing about SMP).
/// * `cpus` — bit mask of the application processors that resumed ring3 at least
///   once (bit `i` = CPU `i`; bit 0 is never set). This is the "different APs
///   really ran user code" evidence.
/// * `preempts` — real timer preemptions on application processors: the AP timer
///   interrupted a ring3 frame **and** another process was claimed and switched
///   to.
/// * `remote_wakes` — `process::remote_wakes()`: wakes that had to kick a remote
///   CPU (a process Ready on another CPU's queue).
/// * `ipis` — `platform::reschedule_ipi_sent()`: reschedule IPIs the platform
///   actually issued.
/// * `migrations` — `process::migration_counts().0`: migrations booked when the
///   process was resumed on its new CPU for an affinity reason.
/// * `balances` — `process::migration_counts().1`: the same for load-balancing
///   moves (`process::rebalance`).
#[derive(Clone, Copy, Default, PartialEq, Eq, Debug)]
pub struct SmpStats {
    /// Ring3 resumes on application processors.
    pub runs: u64,
    /// Bit mask of APs that resumed ring3 (bit `i` = CPU `i`, bit 0 never set).
    pub cpus: u64,
    /// Real AP timer preemptions of ring3 frames.
    pub preempts: u64,
    /// Wakes that requested a remote CPU (process layer).
    pub remote_wakes: u64,
    /// Reschedule IPIs issued by the platform.
    pub ipis: u64,
    /// Migrations booked on resume (affinity reason).
    pub migrations: u64,
    /// Migrations booked on resume (load-balancing reason).
    pub balances: u64,
}

/// Per-CPU scheduler state: control flags plus the counters of [`CpuStats`].
struct CpuSlot {
    /// The owning AP reached [`ap_main`] and its local timer is armed.
    started: AtomicBool,
    /// The root asked this AP to enter [`ap_main`] (`enable_smp_scheduler`).
    requested: AtomicBool,
    /// This AP is parked on its **private** idle stack with the kernel page
    /// tables loaded, so it no longer executes on, or reads through, any
    /// process-owned stack or address space. The boot processor must wait for
    /// this bit on every AP before reaping an exited process — otherwise it
    /// would free the very frames an idle AP is still running on.
    parked: AtomicBool,
    ticks: AtomicU64,
    switches: AtomicU64,
    user_entries: AtomicU64,
    preempts: AtomicU64,
    idle_wakes: AtomicU64,
    remote_wakes: AtomicU64,
}

impl CpuSlot {
    const fn new() -> Self {
        CpuSlot {
            started: AtomicBool::new(false),
            requested: AtomicBool::new(false),
            parked: AtomicBool::new(false),
            ticks: AtomicU64::new(0),
            switches: AtomicU64::new(0),
            user_entries: AtomicU64::new(0),
            preempts: AtomicU64::new(0),
            idle_wakes: AtomicU64::new(0),
            remote_wakes: AtomicU64::new(0),
        }
    }
}

static mut CPU_SLOTS: [CpuSlot; MAX_CPUS] = [const { CpuSlot::new() }; MAX_CPUS];

/// Set by [`enable_smp_scheduler`]: APs may enter [`ap_main`].
static SMP_SCHEDULER_ENABLED: AtomicBool = AtomicBool::new(false);

/// Physical address of the kernel PML4 an idle AP must run on.
///
/// A process-owned address space is freed by `reap` as soon as its zombie is
/// visible, so an AP must never keep using one after it stops running that
/// process: the next timer tick would take an interrupt through freed page
/// tables. [`init_smp`] seeds this from the boot processor's kernel PML4 and
/// [`set_kernel_cr3`] lets the root override it explicitly.
static KERNEL_CR3: AtomicU64 = AtomicU64::new(0);

/// Seed [`KERNEL_CR3`] from the boot processor's kernel PML4.
///
/// `init_smp` runs on the BSP in kernel context; the value is the one the root
/// also hands to `smp::init` (`VmSummary::pml4_phys`). Kept separate so a test or
/// a future boot path can set it explicitly.
fn seed_kernel_cr3() {
    let phys = crate::KERNEL_PML4_PHYS.load(Ordering::Acquire);
    if phys != 0 {
        KERNEL_CR3.store(phys, Ordering::Release);
    }
}

/// Tell the scheduler which page tables an idle AP must run on.
///
/// The root calls this once with the kernel PML4 physical address (the same
/// value it passes to `smp::init`). Without it the scheduler falls back to the
/// value seeded by [`init_smp`], which is the same address on the normal boot
/// path; setting it explicitly is what keeps the contract obvious.
pub fn set_kernel_cr3(phys: u64) {
    KERNEL_CR3.store(phys, Ordering::Release);
}

/// Test-only read-back of [`KERNEL_CR3`].
#[cfg(test)]
pub(crate) fn kernel_cr3() -> u64 {
    KERNEL_CR3.load(Ordering::Acquire)
}

/// The owning CPU's slot. Formed through `addr_of!` so no `static mut`
/// reference exists.
fn slot(cpu: usize) -> &'static CpuSlot {
    assert!(cpu < MAX_CPUS, "cpu index out of range");
    // SAFETY: `cpu` is in range and the array lives for the whole kernel.
    unsafe { &*ptr::addr_of!(CPU_SLOTS).cast::<CpuSlot>().add(cpu) }
}

/// Whether the root has enabled per-CPU scheduling on the application
/// processors.
fn smp_enabled() -> bool {
    SMP_SCHEDULER_ENABLED.load(Ordering::Acquire)
}

/// Reset every per-CPU counter and flag (M6b2 setup, called by the root with
/// interrupts disabled before any AP is enabled).
pub fn init_smp() {
    SMP_SCHEDULER_ENABLED.store(false, Ordering::Release);
    seed_kernel_cr3();
    for cpu in 0..MAX_CPUS {
        let s = slot(cpu);
        s.started.store(false, Ordering::Release);
        s.requested.store(false, Ordering::Release);
        s.ticks.store(0, Ordering::Relaxed);
        s.switches.store(0, Ordering::Relaxed);
        s.user_entries.store(0, Ordering::Relaxed);
        s.preempts.store(0, Ordering::Relaxed);
        s.idle_wakes.store(0, Ordering::Relaxed);
        s.remote_wakes.store(0, Ordering::Relaxed);
        // `parked` is deliberately not reset: the APs are already parked in
        // `ap_idle` at this point and clearing it here would make the root wait
        // for a bit that the idle loop has no reason to set again.
    }
}

/// Allow the application processors to start scheduling.
///
/// Only sets the per-CPU "requested" flags (one for every AP that `smp` reports
/// online); it does not send interrupts and does not print. The root calls this
/// once, then sends vector 0x41 to each AP to make it leave the M6b1 idle loop
/// promptly — an AP that polls the flag before the IPI arrives enters
/// [`ap_main`] by itself, so a lost IPI only costs latency, never correctness.
pub fn enable_smp_scheduler() {
    SMP_SCHEDULER_ENABLED.store(true, Ordering::Release);
    let aps = crate::smp::online_count().min(MAX_CPUS - 1);
    for cpu in 1..=aps {
        slot(cpu).requested.store(true, Ordering::Release);
    }
}

/// Snapshot of one CPU's counters.
pub fn stats(cpu: usize) -> CpuStats {
    let s = slot(cpu);
    CpuStats {
        ticks: s.ticks.load(Ordering::Relaxed),
        switches: s.switches.load(Ordering::Relaxed),
        user_entries: s.user_entries.load(Ordering::Relaxed),
        preempts: s.preempts.load(Ordering::Relaxed),
        idle_wakes: s.idle_wakes.load(Ordering::Relaxed),
        remote_wakes: s.remote_wakes.load(Ordering::Relaxed),
    }
}

/// Snapshot the frozen root-facing aggregate (see [`SmpStats`]).
///
/// The caller (always the BSP) prints it; nothing in this module writes to the
/// serial port, so an AP never produces output. Each field is aggregated exactly
/// as documented on [`SmpStats`]; the per-CPU detail stays available through
/// [`stats`] for diagnostics and host tests.
pub fn smp_stats() -> SmpStats {
    let mut out = SmpStats::default();
    for cpu in 0..MAX_CPUS {
        let snapshot = stats(cpu);
        if cpu != 0 {
            out.runs += snapshot.user_entries;
            out.preempts += snapshot.preempts;
            if snapshot.user_entries > 0 {
                out.cpus |= 1u64 << cpu;
            }
        }
    }
    out.remote_wakes = process::remote_wakes();
    out.ipis = u64::from(platform::reschedule_ipi_sent());
    let (migrations, balances) = process::migration_counts();
    out.migrations = migrations;
    out.balances = balances;
    out
}

/// Bit mask of the application processors that armed their local timer.
///
/// Diagnostics only: it is what proves "the AP really installed a timer" rather
/// than merely being awake, and the root may print it next to [`smp_stats`].
pub fn started_aps() -> u64 {
    let mut mask = 0u64;
    for cpu in 1..MAX_CPUS {
        if slot(cpu).started.load(Ordering::Acquire) {
            mask |= 1u64 << cpu;
        }
    }
    mask
}

/// Bit mask of the application processors that are parked on their private idle
/// stack with the kernel page tables loaded.
///
/// This is the handshake the boot processor must honour before it reaps an
/// exited process: `reap` frees that process's kernel stack frames and address
/// space, and an AP that were still running on them would fault on its next
/// timer tick — which, under `-no-reboot -no-shutdown`, freezes the whole VM and
/// truncates the BSP's serial output mid-line (the M6b2 post-closeout hang).
pub fn parked_aps() -> u64 {
    let mut mask = 0u64;
    for cpu in 1..MAX_CPUS {
        if slot(cpu).parked.load(Ordering::Acquire) {
            mask |= 1u64 << cpu;
        }
    }
    mask
}

/// Move this AP off every process-owned resource, then park for ever.
///
/// Entered when this CPU has run out of runnable work while it still holds a
/// process context: from the exit path ([`ap_on_user_exit`]) and from
/// [`block_and_switch`] when the last process blocked. It is the only safe way
/// for an AP to stop using a process — a `Blocked` process is not reapable yet,
/// but a zombie may be reaped by the boot processor at any moment — and it
///
/// 1. clears this CPU's current-process slot,
/// 2. switches `rsp` to the AP's own kernel stack (mapped in the kernel half, so
///    valid in every address space, and never freed by `reap`),
/// 3. loads the kernel page tables, and
/// 4. only then publishes [`CpuSlot::parked`].
///
/// Switching the stack before CR3 matters: the exiting process's kernel stack is
/// mapped in its own address space, so it is still reachable at that moment,
/// while the AP stack is reachable under both the old and the new CR3.
fn ap_idle_context(cpu: usize) -> ! {
    if cpu == 0 || cpu >= MAX_CPUS {
        halt();
    }
    let cr3 = KERNEL_CR3.load(Ordering::Acquire);
    if cr3 == 0 {
        // Without the kernel page tables the next timer tick would run through
        // the exiting process's CR3 after `reap` freed it. Fail loudly instead.
        fail("sched: kernel CR3 is not configured for AP idle");
    }
    // `smp` maps the AP stacks by **zero-based AP ordinal** (`map_cpu_stack(index)`
    // for the list of enabled APs) and starts each AP with cpu slot `index + 1`,
    // so this CPU's private stack is `ap_stack_top(cpu - 1)`, not
    // `ap_stack_top(cpu)` — the latter would hand CPU 1/2 another AP's stack and
    // send the last AP to an unmapped slot.
    let rsp = match vm::ap_stack_top(cpu - 1) {
        Some(top) => top - 8,
        None => fail("sched: AP has no private idle stack"),
    };
    unsafe { asm!("cli", options(nomem, nostack)) };
    process::set_current_index(None);
    // SAFETY: `rsp` is the top of this AP's own mapped stack and `cr3` is the
    // kernel PML4 (which maps it); interrupts are off, and the target function
    // never returns, so no frame below `rsp` is used. The jump targets an
    // `extern "C"` function, so its whole continuation state is the SysV
    // argument: `cpu` must be placed in `rdi` here, because the preceding calls
    // have already clobbered it. `rsp` is `top - 8`, i.e. `rsp % 16 == 8`, which
    // is what a normal `call` would leave for the callee.
    unsafe {
        asm!(
            "mov rsp, {rsp}",
            "mov cr3, {cr3}",
            "jmp {entry}",
            rsp = in(reg) rsp,
            cr3 = in(reg) cr3,
            // SysV first argument: the jump target is an `extern "C"` function
            // and `cpu` is its only parameter. Positional operand: explicit
            // register operands cannot carry a name.
            in("rdi") cpu,
            entry = sym ap_idle_entry,
            options(noreturn),
        );
    }
}

/// Continuation of [`ap_idle_context`] on the AP's private stack.
///
/// Runs with the kernel page tables active and this CPU's current-process slot
/// clear, which is exactly the state [`parked_aps`] advertises to the BSP.
extern "C" fn ap_idle_entry(cpu: usize) -> ! {
    slot(cpu).parked.store(true, Ordering::Release);
    idle_forever(cpu)
}

/// Send vector 0x41 to every CPU that has a process queued for it.
///
/// `process` records the target CPUs of every wake (`drain_resched_mask`); this
/// drains that mask and kicks the remote CPUs. The boot processor is skipped —
/// it is the one running this code, and it will re-check its queue on the next
/// timer tick or return to user mode. Called by the BSP timer path (after
/// deadline expiry) and by the root after a migration.
pub fn publish_resched() {
    let mask = process::drain_resched_mask();
    if mask == 0 {
        return;
    }
    let me = cpu_index();
    for cpu in 0..MAX_CPUS {
        if mask & (1u32 << cpu) == 0 || cpu == me {
            continue;
        }
        let _ = platform::send_reschedule_ipi(cpu);
    }
}

/// Reschedule-IPI handler (vector 0x41): record the kick, acknowledge it and
/// return the interrupted frame unchanged.
///
/// **The EOI is mandatory.** A fixed-delivery IPI is edge-triggered in the sense
/// that the IRR latch is not held level, but the local APIC still sets the
/// in-service bit for the vector and raises PPR to the IPI's priority class
/// (`0x41` ⇒ priority 4). Without an EOI that bit stays set, so every interrupt
/// of equal or lower priority is blocked on that CPU for ever: the LAPIC timer
/// (`0x20`, priority 2) never fires again, and later `0x41` IPIs are not
/// delivered either. That is exactly the M6b2 hang "the AP armed its timer and
/// then received no interrupt at all".
///
/// The frame is returned untouched: the interrupted context (an idle `hlt` or a
/// ring3 `iretq` target) resumes where it was and re-checks its queue.
pub fn on_reschedule(frame: *mut TrapFrame) -> *mut TrapFrame {
    let cpu = cpu_index();
    if cpu < MAX_CPUS {
        slot(cpu).remote_wakes.fetch_add(1, Ordering::Relaxed);
    }
    // Acknowledge here rather than in the IRQ dispatcher: keeping the EOI next
    // to the vector's semantics makes it impossible to add a second (erroneous)
    // EOI that would clear a timer in-service bit instead.
    platform::eoi();
    frame
}

/// Park an application processor until the root enables SMP scheduling.
///
/// Entered from `smp::ap_entry` with the AP's per-CPU structures ready and
/// `IF = 0`. It sleeps with `IF = 1` and **no timer**, so the only events are a
/// reschedule IPI from the boot processor and spurious interrupts; both simply
/// return to this loop. When [`enable_smp_scheduler`] has been called and this
/// CPU's request flag is set, control passes to [`ap_main`] for good.
pub fn ap_idle(cpu: usize) -> ! {
    if cpu == 0 || cpu >= MAX_CPUS {
        halt();
    }
    // The pre-scheduler park already runs on this AP's own kernel stack with the
    // kernel page tables, so it satisfies the same invariant the exit path
    // restores: nothing here touches a process-owned stack or address space.
    slot(cpu).parked.store(true, Ordering::Release);
    loop {
        if smp_enabled() && slot(cpu).requested.load(Ordering::Acquire) {
            ap_main(cpu);
        }
        crate::arch::idle();
        // `iretq` restored the interrupted `IF`; drop it before touching any
        // scheduler state.
        unsafe { asm!("cli", options(nomem, nostack)) };
        slot(cpu).idle_wakes.fetch_add(1, Ordering::Relaxed);
    }
}

/// AP scheduler body: install the local timer once, then schedule for ever.
///
/// The frequency is the boot processor's calibrated value — PIT calibration is
/// a global, BSP-only step — and the AP programs its own LVT through
/// `platform::start_local_timer`. All waits and switches happen with `IF = 0`
/// except inside `arch::idle`, so the CR3/TSS.RSP0 pair always changes
/// atomically with respect to interrupts.
pub fn ap_main(cpu: usize) -> ! {
    if cpu == 0 || cpu >= MAX_CPUS {
        halt();
    }
    let s = slot(cpu);
    // Publish "started" only once the timer is really armed: the root's stats
    // check treats a missing bit as a failure, and a timer that failed to arm
    // must not look healthy.
    match platform::start_local_timer(crate::time::TICK_HZ) {
        Ok(_) => s.started.store(true, Ordering::Release),
        Err(_) => {
            s.started.store(false, Ordering::Release);
            // Without a timer this CPU can still be woken by an IPI and run
            // whatever is queued for it, but it cannot preempt; stay idle so a
            // broken timer is reported by `smp_stats`, not hidden.
            idle_forever(cpu)
        }
    }
    idle_forever(cpu)
}

/// Claim-and-run loop shared by [`ap_main`] and the AP exit path.
fn idle_forever(cpu: usize) -> ! {
    loop {
        if let Some(next) = process::claim_next_on(cpu, None) {
            resume_on(cpu, next);
        }
        publish_resched();
        crate::arch::idle();
        unsafe { asm!("cli", options(nomem, nostack)) };
        slot(cpu).idle_wakes.fetch_add(1, Ordering::Relaxed);
    }
}

/// Timer entry point for a specific CPU.
///
/// * CPU 0 keeps the M4 behaviour unchanged (deadline expiry, IPC timer expiry,
///   round robin) and then publishes any remote wake.
/// * An application processor only accounts its own tick and, if the
///   interrupted frame is ring3 and another process is runnable for this CPU,
///   performs a real preemption. It never touches the global clock, the IPC
///   timer wheel or `wake_expired`: those stay single-sourced on the BSP.
///
/// The caller (the IRQ dispatcher) is responsible for the LAPIC EOI, exactly as
/// for [`on_timer`].
pub fn on_timer_cpu(cpu: usize, frame: *mut TrapFrame) -> *mut TrapFrame {
    if cpu == 0 {
        let next = on_timer(frame);
        publish_resched();
        return next;
    }
    if cpu >= MAX_CPUS {
        return frame;
    }
    let s = slot(cpu);
    s.ticks.fetch_add(1, Ordering::Relaxed);
    if !smp_enabled() || !STARTED.load(Ordering::Acquire) || !USER_MODE.load(Ordering::Acquire) {
        return frame;
    }
    if frame.is_null() || !frame_is_user(frame) {
        // Kernel-mode tick on an AP (its idle loop or a syscall): no kernel
        // preemption, the idle loop re-checks the queue when it wakes up.
        return frame;
    }
    let Some(index) = process::current_index() else {
        return frame;
    };
    if !process::frame_belongs_to(index, frame) || !process::kernel_stack_ok(index) {
        fail_corrupt_at("timer frame outside the current kernel stack", index, frame);
    }

    // Select before parking: the running process is therefore never a
    // candidate, and a failed claim leaves it running untouched.
    let Some(next) = process::claim_next_on(cpu, Some(index)) else {
        return frame;
    };
    let next_frame = process::saved_frame(next);
    if next_frame.is_null()
        || !process::frame_resumable(next, next_frame)
        || !frame_is_user(next_frame)
    {
        fail("saved frame of the next process is invalid");
    }

    process::park_to_queue(index, cpu);
    process::set_saved_frame(index, frame);
    s.preempts.fetch_add(1, Ordering::Relaxed);
    unsafe { switch_to_on(cpu, next) };
    next_frame
}

// ---------------------------------------------------------------------------
// M3 switch machinery
// ---------------------------------------------------------------------------

fn dispatch(frame: *mut TrapFrame, event: Event) -> *mut TrapFrame {
    if frame.is_null() {
        fail("null trap frame");
    }
    unsafe {
        let st = sched_ptr();
        if (*st).current == BOOT {
            // First switch: boot context -> A. The boot stack has no canaries
            // (it is abandoned, never resumed), so only the new stack is
            // checked.
            let next = threads_ptr(st).add(THREAD_A);
            if !thread_physical_ok(next) {
                fail_corrupt();
            }
            (*st).current = THREAD_A as u8;
            SWITCHES.fetch_add(1, Ordering::Relaxed);
            return (*next).saved;
        }

        let cur_i = (*st).current as usize;
        let cur = threads_ptr(st).add(cur_i);
        // The frame we are leaving must live on the current thread's stack and
        // its canaries must still be intact.
        if !frame_in_stack(cur, frame) || !canaries_ok(cur) || !frame_is_kernel(frame) {
            fail_corrupt();
        }

        let next_i = next_thread(cur_i, event);
        let next = threads_ptr(st).add(next_i);
        // Check the *destination* stack before committing to it.
        if !thread_physical_ok(next) {
            fail_corrupt();
        }

        // Account the transition that is about to happen. Doing it before the
        // switch means a resumed thread observes exactly the switches taken.
        match (event, cur_i) {
            (Event::Yield, THREAD_A) => {
                A_YIELDS.fetch_add(1, Ordering::Relaxed);
            }
            (Event::Timer, THREAD_A) => {
                A_TIMER_PREEMPTS.fetch_add(1, Ordering::Relaxed);
            }
            (Event::Timer, THREAD_B) => {
                B_TIMER_PREEMPTS.fetch_add(1, Ordering::Relaxed);
            }
            // (Event::Yield, THREAD_B): B violates its "never yield" contract;
            // switch back to A and keep going rather than deadlock.
            _ => {}
        }

        (*cur).saved = frame;
        (*st).current = next_i as u8;
        SWITCHES.fetch_add(1, Ordering::Relaxed);
        (*next).saved
    }
}

/// Two-thread round robin. A always hands the CPU to B by yielding; B never
/// yields, so only the timer can take it back. A timer tick while A runs is
/// handled the same way (A yields immediately, so this is rare but harmless).
fn next_thread(cur: usize, event: Event) -> usize {
    match (cur, event) {
        (THREAD_A, Event::Yield) => THREAD_B,
        (THREAD_A, Event::Timer) => THREAD_B,
        (THREAD_B, Event::Timer) => THREAD_A,
        (THREAD_B, Event::Yield) => THREAD_A,
        _ => THREAD_A,
    }
}

// ---------------------------------------------------------------------------
// Stack integrity
// ---------------------------------------------------------------------------

unsafe fn write_canaries(base: u64) {
    let top = base + STACK_BYTES;
    unsafe {
        *(base as *mut u64) = CANARY_LO0;
        *((base + 8) as *mut u64) = CANARY_LO1;
        *((top - TOP_CANARY_BYTES) as *mut u64) = CANARY_TOP;
    }
}

unsafe fn canaries_ok(t: *const Thread) -> bool {
    let base = unsafe { (*t).stack_base };
    let top = base + STACK_BYTES;
    unsafe {
        *(base as *const u64) == CANARY_LO0
            && *((base + 8) as *const u64) == CANARY_LO1
            && *((top - TOP_CANARY_BYTES) as *const u64) == CANARY_TOP
    }
}

/// A resumable trap frame must sit inside the mapped stack and must not overlap
/// the top canary (`frame + FRAME_BYTES <= top - 8`).
unsafe fn frame_in_stack(t: *const Thread, frame: *const TrapFrame) -> bool {
    let addr = frame as u64;
    let base = unsafe { (*t).stack_base };
    addr % 8 == 0
        && addr >= base + LO_CANARY_BYTES
        && addr + FRAME_BYTES <= base + STACK_BYTES - TOP_CANARY_BYTES
}

unsafe fn thread_physical_ok(t: *const Thread) -> bool {
    unsafe { canaries_ok(t) && frame_in_stack(t, (*t).saved) }
}

/// Both M3 stacks must still be intact (used for the `M3 stacks OK` evidence).
unsafe fn all_stacks_ok() -> bool {
    let st = sched_ptr();
    let threads = threads_ptr(st);
    (0..NTHREADS).all(|i| unsafe { thread_physical_ok(threads.add(i)) })
}

/// A frame that returns to ring0 (M3 kernel threads).
fn frame_is_kernel(frame: *const TrapFrame) -> bool {
    unsafe { (*frame).cs & 3 == 0 }
}

/// A frame that returns to ring3 (M4 user threads).
fn frame_is_user(frame: *const TrapFrame) -> bool {
    unsafe { (*frame).cs & 3 == 3 }
}

// ---------------------------------------------------------------------------
// Set up (M3 kernel threads)
// ---------------------------------------------------------------------------

unsafe fn setup_threads() -> Result<(), &'static str> {
    unsafe {
        setup_thread(THREAD_A, STACK_A_BASE, thread_a_entry)?;
        setup_thread(THREAD_B, STACK_B_BASE, thread_b_entry)?;
    }
    Ok(())
}

unsafe fn setup_thread(
    index: usize,
    base: u64,
    entry: extern "C" fn() -> !,
) -> Result<(), &'static str> {
    unsafe {
        // Independent PMM frames: never assume the four allocations are
        // physically contiguous.
        let mut frames = [0u64; STACK_FRAMES as usize];
        for frame in frames.iter_mut() {
            *frame = pmm::alloc_frame().map_err(|_| "thread stack allocation failed")?;
        }

        let flags = vm::PTE_PRESENT | vm::PTE_WRITE | vm::PTE_NX;
        for (i, &phys) in frames.iter().enumerate() {
            let virt = base + (i as u64) * PAGE_SIZE;
            vm::map_physical(virt, phys, PAGE_SIZE, flags)
                .map_err(|_| "thread stack mapping failed")?;
        }

        // Zero the stack (PMM frames may hold stale bytes), then install the
        // canaries and the synthetic first frame.
        ptr::write_bytes(base as *mut u8, 0, STACK_BYTES as usize);
        write_canaries(base);

        let frame = first_frame_addr(base) as *mut TrapFrame;
        write_initial_frame(frame, entry);

        // Boundary assertion: the frame must end exactly at the entry scratch.
        debug_assert_eq!(
            frame as u64 + FRAME_BYTES,
            base + STACK_BYTES - TOP_CANARY_BYTES
        );

        let thread = threads_ptr(sched_ptr()).add(index);
        (*thread).saved = frame;
    }
    Ok(())
}

/// Write a synthetic ring0 trap frame for an M3 kernel thread.
///
/// `user_rsp` / `user_ss` are the scratch slots described in the module docs:
/// `frame + 160` is where both a bare-metal 3-qword return and a QEMU 5-qword
/// return end up, i.e. `top - 24` (8 mod 16), and `KERNEL_DS` is a legal
/// selector for the slot. The top canary at `top - 8` is never written.
unsafe fn write_initial_frame(frame: *mut TrapFrame, entry: extern "C" fn() -> !) {
    let q = frame as *mut u64;
    unsafe {
        for i in 0..FRAME_QWORDS {
            *q.add(i) = 0;
        }
        *q.add(Q_RIP) = entry as usize as u64;
        *q.add(Q_CS) = KERNEL_CS as u64;
        *q.add(Q_RFLAGS) = RFLAGS_IF;
        *q.add(Q_USER_RSP) = frame as u64 + (Q_USER_RSP as u64) * 8;
        *q.add(Q_USER_SS) = KERNEL_DS as u64;
    }
}

// ---------------------------------------------------------------------------
// M4 user-mode scheduling
// ---------------------------------------------------------------------------

/// Switch to the first user process: activate its address space, point the
/// privilege-transition stack at its kernel stack and iretq into ring3.
///
/// Must be called by the kernel root with interrupts disabled; the ring3 frame
/// restores `IF=1` for the user thread.
pub fn start_user(init: ProcessId) -> ! {
    unsafe {
        asm!("cli", options(nomem, nostack));

        if !STARTED.load(Ordering::Acquire) {
            fail("start_user before start");
        }
        if !M3_DONE.load(Ordering::Acquire) {
            fail("start_user before the M3 demo finished");
        }
        if USER_MODE.swap(true, Ordering::AcqRel) {
            fail("start_user called twice");
        }

        let index = init.index();
        let frame = process::saved_frame(index);
        if frame.is_null() || !process::frame_belongs_to(index, frame) || !frame_is_user(frame) {
            fail("initial user frame is invalid");
        }

        // The very first entry runs before any AP can schedule, so the
        // unlocked `Running` transition here cannot race a claim; every later
        // switch goes through `claim_next_on` and never re-marks a process.
        process::mark_running(index);
        process::set_current_index(Some(index));
        activate_user_context(index);
        resume_frame(frame)
    }
}

/// Hand the CPU to the next runnable process after the current one exited.
///
/// The exiting process was already marked `Zombie` by
/// [`process::exit_current`]; its address space and kernel stack are left for
/// a later `wait` to reap (Lead m00445). When nothing is runnable, finish M4.
///
/// M6b2 splits the exit path by CPU: only the boot processor may finish the
/// demo (`complete_m4`) or idle "for the demo"; an application processor just
/// claims another process or parks. An AP therefore never reaps, never prints
/// and never completes M4 — the boot processor owns teardown and all output.
pub fn on_user_exit() -> ! {
    let cpu = cpu_index();
    if cpu != 0 {
        ap_on_user_exit(cpu)
    } else {
        bsp_on_user_exit()
    }
}

fn bsp_on_user_exit() -> ! {
    let current = process::current_index();
    if let Some(index) = current {
        if !process::kernel_stack_ok(index) {
            fail_corrupt();
        }
    }

    match process::claim_next_on(0, current) {
        Some(next) => resume_on(0, next),
        None => {
            if process::has_blocked() {
                // A sibling is only blocked, not gone: wait for its wake
                // instead of ending the demo underneath it.
                idle_blocked()
            } else {
                crate::complete_m4(process::last_exit_status())
            }
        }
    }
}

fn ap_on_user_exit(cpu: usize) -> ! {
    let current = process::current_index();
    match process::claim_next_on(cpu, current) {
        Some(next) => resume_on(cpu, next),
        // Nothing else is runnable on this AP: leave the exiting process behind
        // (the boot processor reaps the zombie) and park in a context that owns
        // no process resource — see `ap_idle_context`.
        None => ap_idle_context(cpu),
    }
}

/// Switch away from a process that just blocked.
///
/// Entered from [`process::block_current`] with interrupts off, after the caller
/// marked itself `Blocked` and stored its copied `syscall` frame as its saved
/// frame. With another `Ready` process this switches to it immediately;
/// otherwise the CPU idles with interrupts enabled until an ISR wakes someone —
/// the timer ISR only records the reason and marks the waiter `Ready`, it never
/// switches — and this loop then performs the switch.
pub fn block_and_switch() -> ! {
    let cpu = cpu_index();
    let current = process::current_index();
    if let Some(next) = process::claim_next_on(cpu, current) {
        resume_on(cpu, next)
    }
    if cpu != 0 {
        // An AP that blocked its last process must not stay on that process's
        // kernel stack and address space: the process is `Blocked`, not `Zombie`,
        // so it cannot be reaped yet, but the AP would still pin a context that
        // later may be released and `parked_aps` would never cover it. Park in
        // the process-free context instead (clear current, AP stack, kernel
        // CR3). The blocked process's saved frame lives in the process table, so
        // a later wake can still resume it through the normal claim path.
        ap_idle_context(cpu)
    } else {
        idle_blocked()
    }
}

/// Idle until a blocked process is woken, then switch to it.
///
/// Runs on the blocked process's kernel stack. Its copied `syscall` frame lives
/// in `.bss`, so the interrupt frames produced here (`top - 192 … top - 16`) can
/// never overwrite it; that is why [`process::block_current`] copies the frame
/// out before entering this loop. Interrupts are off on entry and stay off
/// except across the `sti; hlt` pair.
fn idle_blocked() -> ! {
    let cpu = cpu_index();
    loop {
        if let Some(next) = process::claim_next_on(cpu, None) {
            resume_on(cpu, next);
        }
        // A wake that landed on another CPU needs its IPI now, not on the next
        // tick: drain the pending mask before going to sleep.
        publish_resched();
        // Sleep with interrupts enabled until the next timer tick (100 Hz) or an
        // IPC wake; a wake that lands before the halt retires is simply served by
        // that tick, and the ISR only marks the waiter `Ready`.
        core::sync::atomic::compiler_fence(Ordering::SeqCst);
        unsafe { asm!("sti; hlt", options(nostack)) };
        unsafe { asm!("cli", options(nomem, nostack)) };
        core::sync::atomic::compiler_fence(Ordering::SeqCst);
        slot(cpu).idle_wakes.fetch_add(1, Ordering::Relaxed);
    }
}

/// Validate `index`'s saved frame and resume it on `cpu`; never returns.
///
/// Accepts both legal geometries (see [`process::frame_resumable`]): the ring3
/// first frame at `top - 192` after an ordinary interrupt frame was parked, and
/// the copied `syscall` frame of a process that blocked and was woken.
///
/// The CR3 / TSS.RSP0 pair is changed with interrupts off; the ring3 frame
/// itself restores `IF = 1` on the way out, so the ring3 entry is the only place
/// where an interrupt can observe the new context.
fn resume_on(cpu: usize, index: usize) -> ! {
    let frame = process::saved_frame(index);
    if frame.is_null() || !process::frame_resumable(index, frame) || !frame_is_user(frame) {
        fail("saved frame of the process to resume is invalid");
    }
    unsafe {
        asm!("cli", options(nomem, nostack));
        switch_to_on(cpu, index);
        slot(cpu).user_entries.fetch_add(1, Ordering::Relaxed);
        resume_frame(frame)
    }
}

/// Timer-driven round robin over the user processes of `cpu`.
///
/// Entered from the timer ISR with the interrupted ring3 frame. The next process
/// is claimed **before** the current one is parked: selection and the `Running`
/// transition happen together inside the process-table lock, so two CPUs can
/// never pick the same `Ready` process, and a failed claim (nothing else
/// runnable) leaves the current process running untouched.
fn schedule_user_on(cpu: usize, frame: *mut TrapFrame) -> *mut TrapFrame {
    if frame.is_null() {
        fail("null trap frame");
    }
    unsafe {
        let current = process::current_index();
        if let Some(index) = current {
            // The interrupted frame must be this process's ring3 first frame
            // (`process::first_frame_addr(top)`, i.e. top - 192 because the
            // hardware realigns RSP0) and its TOP canary must still be intact.
            if !process::frame_belongs_to(index, frame) || !frame_is_user(frame) {
                fail_corrupt_at("timer frame outside the current kernel stack", index, frame);
            }
            if !process::kernel_stack_ok(index) {
                fail_corrupt_at("kernel stack TOP canary overwritten", index, frame);
            }
        }

        let next = match process::claim_next_on(cpu, current) {
            Some(next) => next,
            None => {
                let Some(_) = current else {
                    fail("timer with no runnable process");
                };
                // Nothing else runnable: keep running the current process.
                return frame;
            }
        };

        let next_frame = process::saved_frame(next);
        if next_frame.is_null()
            || !process::frame_resumable(next, next_frame)
            || !frame_is_user(next_frame)
        {
            fail("saved frame of the next process is invalid");
        }

        if let Some(index) = current {
            process::park_to_queue(index, cpu);
            process::set_saved_frame(index, frame);
        }
        switch_to_on(cpu, next);
        next_frame
    }
}

/// Make `index` current on `cpu`: per-CPU current slot, CR3 and the kernel stack
/// used on the next ring3 entry.
///
/// The `Running` transition is **not** made here: the claim that selected
/// `index` already performed it inside the process-table lock, and a second
/// write outside the lock would re-open the double-claim window this design
/// removes (Lead m00132 item 3).
///
/// The current-process slot is per CPU: `set_current_index` writes only the slot
/// of the CPU executing the call, which is what makes it safe for an AP to run
/// against its own slot without the process table lock. This function is only
/// ever entered on the CPU it names (`resume_on`/`schedule_user_on` are called
/// from that CPU's own timer, idle or syscall path), so the debug assertion below
/// catches a future caller that got the pairing wrong.
///
/// Locking discipline: every process-table access in this module goes through a
/// `process::*` public entry point, and each of those takes the process table
/// lock itself. Nothing here may therefore be called while
/// [`crate::process`]'s table lock is held — a nested `lock()` on the same CPU
/// spins for ever because `IrqSpinLock` is not reentrant. In particular
/// `switch_to_on`/`resume_on`/`idle_blocked`/`schedule_user_on` are entered only
/// after `block_with`, `exit_current` and friends have dropped the lock.
unsafe fn switch_to_on(cpu: usize, index: usize) {
    debug_assert_eq!(cpu, cpu_index(), "switch_to_on must run on `cpu`");
    unsafe {
        // This CPU is leaving the safe idle context and will run on the
        // process's kernel stack and address space from here on, so it must not
        // be reported as parked any more.
        slot(cpu).parked.store(false, Ordering::Release);
        process::set_current_index(Some(index));
        activate_user_context(index);
        slot(cpu).switches.fetch_add(1, Ordering::Relaxed);
        if cpu == 0 {
            // Keep the historical BSP-only counter that the M3/M4 tests use.
            USER_SWITCHES.fetch_add(1, Ordering::Relaxed);
        }
    }
}

/// Activate a process's address space and its kernel-stack top.
///
/// Must run with interrupts disabled: the TSS.RSP0 / per-CPU pair is updated
/// as one logical value and a nested interrupt must never observe a half
/// updated pair.
unsafe fn activate_user_context(index: usize) {
    addrspace::activate(process::address_space(index));
    set_user_kernel_stack(process::kernel_stack_top_of(index));
    // M8f: restore the incoming process's user TLS base. The MSR is per CPU,
    // so it must be rewritten on every switch (syscall/trap returns to the
    // same process keep it unchanged).
    set_user_fs_base(process::fs_base(index));
}

// ---------------------------------------------------------------------------
// M3 thread bodies
// ---------------------------------------------------------------------------

/// Thread A: cooperative. It yields with `int 0x40` until B has been pushed
/// forward by the timer often enough, then reports and returns to the root.
extern "C" fn thread_a_entry() -> ! {
    let mut iterations = 0u64;
    loop {
        let yields = A_YIELDS.load(Ordering::Relaxed);
        let preempts = B_TIMER_PREEMPTS.load(Ordering::Relaxed);
        if yields >= YIELD_TARGET && preempts >= PREEMPT_TARGET {
            report_success(yields, preempts);
        }

        iterations += 1;
        if iterations > MAX_A_LOOP_ITERS {
            fail("A: timer did not push B forward");
        }

        // The dispatcher accounts the yield before switching away, so the
        // counter always matches the yields that actually reached the ISR.
        unsafe { asm!("int 0x40") };
    }
}

/// Thread B: never yields, never prints. It only advances an atomic counter and
/// relies on the LAPIC timer to take the CPU back. The spin counter turns
/// "timer never fires" into a bounded, loud failure.
extern "C" fn thread_b_entry() -> ! {
    let mut seen_preempts = B_TIMER_PREEMPTS.load(Ordering::Relaxed);
    let mut spin = 0u64;
    loop {
        B_ITERATIONS.fetch_add(1, Ordering::Relaxed);
        spin += 1;

        let now = B_TIMER_PREEMPTS.load(Ordering::Relaxed);
        if now != seen_preempts {
            // The timer did preempt us at least once more: new slice.
            seen_preempts = now;
            spin = 0;
        } else if spin > MAX_B_SPIN_WITHOUT_PREEMPT {
            fail("B: LAPIC timer never preempted B");
        }

        if SWITCHES.load(Ordering::Relaxed) > MAX_SWITCHES {
            fail("scheduler did not converge");
        }
    }
}

// ---------------------------------------------------------------------------
// Reporting
// ---------------------------------------------------------------------------

/// Print the M3 acceptance markers and return to the caller of [`start`].
///
/// `stacks OK` is an assertion, not a label: both stacks must still match their
/// canaries and hold a resumable frame. The deliberate page fault is no longer
/// fired here (Lead m00389): it is the last step of M4.
fn report_success(yields: u64, preempts: u64) -> ! {
    // Freeze the machine for a deterministic report; nothing can switch away
    // from A while the markers are printed.
    unsafe { asm!("cli", options(nomem, nostack)) };

    if !unsafe { all_stacks_ok() } {
        fail_corrupt();
    }

    let switches = SWITCHES.load(Ordering::Relaxed);
    klog!("[CaelumKernel] M3 stacks OK");
    klog!(
        "[CaelumKernel] M3 sched OK (switches={switches}, a_yields={yields}, a_timer_preempts={}, b_timer_preempts={preempts}, b_iterations={})",
        A_TIMER_PREEMPTS.load(Ordering::Relaxed),
        B_ITERATIONS.load(Ordering::Relaxed)
    );
    klog!("[CaelumKernel] M3 OK");

    finish_m3()
}

fn fail(message: &str) -> ! {
    let current = unsafe { (*sched_ptr()).current };
    klog!("[CaelumKernel] M3 FAIL {message}");
    klog!(
        "[CaelumKernel]   thread={}, switches={}, a_yields={}, a_timer_preempts={}, b_timer_preempts={}, b_iterations={}",
        current_name(current),
        SWITCHES.load(Ordering::Relaxed),
        A_YIELDS.load(Ordering::Relaxed),
        A_TIMER_PREEMPTS.load(Ordering::Relaxed),
        B_TIMER_PREEMPTS.load(Ordering::Relaxed),
        B_ITERATIONS.load(Ordering::Relaxed)
    );
    halt();
}

/// Canary / saved-frame mismatch. The first line is the exact required
/// diagnostic; a second line records where the check ran.
fn fail_corrupt() -> ! {
    klog!("[CaelumKernel] M3 FAIL stack corrupt");
    let current = unsafe { (*sched_ptr()).current };
    klog!(
        "[CaelumKernel]   canary/frame check failed (thread={}, switches={}, user_switches={})",
        current_name(current),
        SWITCHES.load(Ordering::Relaxed),
        USER_SWITCHES.load(Ordering::Relaxed)
    );
    halt();
}

fn current_name(current: u8) -> &'static str {
    match current {
        0 => "A",
        1 => "B",
        _ => "boot",
    }
}

/// User-frame mismatch: same required first line as [`fail_corrupt`], plus the
/// concrete reason and the numbers needed to tell a wrong frame address from a
/// clobbered canary.
fn fail_corrupt_at(reason: &str, index: usize, frame: *mut TrapFrame) -> ! {
    let top = process::kernel_stack_top_of(index);
    let expected = process::first_frame_addr(top);
    let cs = if frame.is_null() {
        0
    } else {
        // SAFETY: the caller only reaches this path with a mapped frame; `cs` is
        // inside the frame.
        unsafe { (*frame).cs }
    };
    klog!("[CaelumKernel] M3 FAIL stack corrupt");
    klog!(
        "[CaelumKernel]   {reason} (process={index}, frame=0x{:016x}, expected=0x{:016x}, top=0x{:016x}, cs=0x{cs:x})",
        frame as u64,
        expected,
        top
    );
    klog!(
        "[CaelumKernel]   canary/frame check failed (thread={}, switches={}, user_switches={})",
        current_name(unsafe { (*sched_ptr()).current }),
        SWITCHES.load(Ordering::Relaxed),
        USER_SWITCHES.load(Ordering::Relaxed)
    );
    halt();
}

// ---------------------------------------------------------------------------
// Host tests: frame layout, stack geometry and pure policy (no mapping,
// no interrupts, no process table)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::arch::traps::{self, init_user_frame};

    extern "C" fn test_entry() -> ! {
        loop {}
    }

    #[repr(C, align(16))]
    struct TestStack([u64; (STACK_BYTES / 8) as usize]);

    #[repr(C, align(16))]
    struct Mem([u64; 40]);

    fn top_of(stack: &TestStack) -> u64 {
        stack.0.as_ptr() as u64 + STACK_BYTES
    }

    #[test]
    fn synthetic_kernel_frame_matches_the_abi() {
        let mut mem = Mem([0xAAAA_AAAA_AAAA_AAAA; 40]);
        let frame = mem.0.as_mut_ptr() as *mut TrapFrame;
        // SAFETY: 40 qwords hold the 22-qword frame with room to spare.
        unsafe { write_initial_frame(frame, test_entry) };

        // SAFETY: only the frame bytes just written are read.
        let q = unsafe { core::slice::from_raw_parts(mem.0.as_ptr(), FRAME_QWORDS) };
        assert_eq!(q[Q_VECTOR], 0);
        assert_eq!(q[Q_ERROR], 0);
        assert_eq!(q[Q_RIP], test_entry as *const () as usize as u64);
        assert_eq!(q[Q_CS], KERNEL_CS as u64);
        assert_eq!(q[Q_RFLAGS], RFLAGS_IF);
        // Scratch slots: `frame + 160` is where both iret models leave rsp.
        assert_eq!(q[Q_USER_RSP], frame as u64 + (Q_USER_RSP as u64) * 8);
        assert_eq!(q[Q_USER_SS], KERNEL_DS as u64);
        // 15 GPRs are zeroed.
        for value in &q[0..15] {
            assert_eq!(*value, 0);
        }
        // SAFETY: `frame` points at the buffer just written.
        assert!(frame_is_kernel(frame));
        assert!(!frame_is_user(frame));
    }

    #[test]
    fn stack_geometry_keeps_the_top_canary_outside_the_frame() {
        let stack = TestStack([0; (STACK_BYTES / 8) as usize]);
        let base = stack.0.as_ptr() as u64;
        let frame = first_frame_addr(base);
        // Ring0 geometry: a kernel thread entry never changes privilege, so the
        // CPU does not realign RSP0 and the frame ends exactly at the TOP canary
        // (`frame + 176 == top - 8`); iretq leaves rsp = frame + 160.
        assert_eq!(frame + FRAME_BYTES + TOP_CANARY_BYTES, top_of(&stack));
        assert_eq!((frame + FRAME_BYTES) % 16, 8);
        assert_eq!(frame, traps::user_frame_addr(top_of(&stack)));
        // Ring3 processes are one qword lower: the hardware aligns
        // `RSP0 = top - 8` down to 16 bytes before pushing its 40-byte frame.
        assert_eq!(
            crate::process::first_frame_addr(STACK_A_BASE + STACK_BYTES),
            first_frame_addr(STACK_A_BASE) - 8
        );
        assert_eq!(
            crate::process::first_frame_addr(STACK_A_BASE + STACK_BYTES) + FRAME_BYTES,
            STACK_A_BASE + STACK_BYTES - 16
        );
    }

    #[test]
    fn canaries_detect_corruption_at_both_ends() {
        let stack = TestStack([0; (STACK_BYTES / 8) as usize]);
        let base = stack.0.as_ptr() as u64;
        let mut thread = Thread {
            stack_base: base,
            saved: first_frame_addr(base) as *mut TrapFrame,
        };
        unsafe { write_canaries(base) };
        assert!(unsafe { canaries_ok(&thread) });
        assert!(unsafe { thread_physical_ok(&thread) });

        // Bottom canary.
        unsafe { *(base as *mut u64) = CANARY_LO0 ^ 1 };
        assert!(!unsafe { canaries_ok(&thread) });
        unsafe { *(base as *mut u64) = CANARY_LO0 };

        // Top canary.
        let top_canary = base + STACK_BYTES - TOP_CANARY_BYTES;
        unsafe { *(top_canary as *mut u64) = CANARY_TOP ^ 1 };
        assert!(!unsafe { canaries_ok(&thread) });

        thread.saved = ptr::null_mut();
        assert!(!unsafe { thread_physical_ok(&thread) });
    }

    #[test]
    fn frame_bounds_accept_own_stack_and_reject_foreign_frames() {
        let stack = TestStack([0; (STACK_BYTES / 8) as usize]);
        let base = stack.0.as_ptr() as u64;
        let thread = Thread {
            stack_base: base,
            saved: ptr::null_mut(),
        };
        let first = first_frame_addr(base);
        unsafe {
            write_canaries(base);
            assert!(frame_in_stack(&thread, first as *const TrapFrame));
            // The exact same frame is what a real interrupt lands on.
            assert!(frame_in_stack(&thread, first as *const TrapFrame));
            // A frame that would overlap the top canary is rejected.
            assert!(!frame_in_stack(
                &thread,
                (base + STACK_BYTES - TOP_CANARY_BYTES - FRAME_BYTES + 8) as *const TrapFrame
            ));
            // A frame below the mapping, on the guard page, is rejected.
            assert!(!frame_in_stack(
                &thread,
                (base - PAGE_SIZE) as *const TrapFrame
            ));
            // An unaligned frame is rejected.
            assert!(!frame_in_stack(&thread, (first + 4) as *const TrapFrame));
        }
    }

    #[test]
    fn switch_policy_alternates_between_a_and_b() {
        assert_eq!(next_thread(THREAD_A, Event::Yield), THREAD_B);
        assert_eq!(next_thread(THREAD_A, Event::Timer), THREAD_B);
        assert_eq!(next_thread(THREAD_B, Event::Timer), THREAD_A);
        assert_eq!(next_thread(THREAD_B, Event::Yield), THREAD_A);
    }

    #[test]
    fn user_frames_are_told_apart_by_the_privilege_bits() {
        let mut mem = Mem([0; 40]);
        let frame = mem.0.as_mut_ptr() as *mut TrapFrame;
        // SAFETY: the buffer is large enough for one 22-qword frame.
        unsafe {
            write_initial_frame(frame, test_entry);
            assert!(frame_is_kernel(frame));
            init_user_frame(frame, 0x0000_0000_0040_0000, 0x0000_0000_0080_0000);
            assert!(frame_is_user(frame));
            assert_eq!((*frame).user_rsp, 0x0000_0000_0080_0000);
            assert_eq!((*frame).user_ss, crate::arch::USER_DS as u64);
        }
    }

    #[test]
    fn boot_return_frame_targets_the_trampoline() {
        let ret_slot = [0xDEAD_BEEF_1234_5678u64];
        let entry_rsp = ret_slot.as_ptr() as u64;
        // SAFETY: `entry_rsp` points at a readable qword holding the return
        // address, exactly as the naked shim passes it.
        unsafe { prepare_boot_frame(entry_rsp) };

        let frame = ptr::addr_of_mut!(BOOT_FRAME) as *mut TrapFrame;
        // SAFETY: `prepare_boot_frame` just initialised the static frame.
        unsafe {
            assert_eq!(
                (*frame).rip,
                boot_return_trampoline as *const () as usize as u64
            );
            assert_eq!((*frame).cs, KERNEL_CS as u64);
            assert_eq!((*frame).rflags, RFLAGS_IF);
            assert_eq!((*frame).user_ss, KERNEL_DS as u64);
            assert!(frame_is_kernel(frame));
        }
        assert_eq!(BOOT_RSP.load(Ordering::Relaxed), entry_rsp + 8);
        assert_eq!(BOOT_RET.load(Ordering::Relaxed), 0xDEAD_BEEF_1234_5678);
    }

    // -- M6b2 per-CPU scheduling state machine ------------------------------
    //
    // The host cannot run two CPUs in the kernel, so these tests cover the
    // bookkeeping and the bounded/early-return paths only: counter resets and
    // aggregation, the "AP tick must not touch the global clock" rule, the
    // reschedule-IPI handler contract (frame untouched, no preemption), and
    // `enable_smp_scheduler` requesting exactly the online APs. Real mutual
    // exclusion is proven by the QEMU acceptance run, not here.

    /// Serialize tests that share the global per-CPU counters.
    fn serial() -> std::sync::MutexGuard<'static, ()> {
        crate::object::test_lock()
    }

    #[test]
    fn init_smp_clears_every_per_cpu_counter_and_flag() {
        let _serial = serial();
        init_smp();
        for cpu in 0..MAX_CPUS {
            assert_eq!(stats(cpu), CpuStats::default(), "cpu {cpu} must be reset");
        }
        // The scheduler-owned part of the frozen snapshot must be zero. The
        // process/platform counters are shared globals that other tests may have
        // touched, so only their wiring is asserted in the aggregation test.
        let smp = smp_stats();
        assert_eq!(smp.runs, 0);
        assert_eq!(smp.cpus, 0);
        assert_eq!(smp.preempts, 0);
        assert!(!smp_enabled());
    }

    #[test]
    fn ap_timer_tick_is_counted_locally_and_never_preempts_an_idle_cpu() {
        let _serial = serial();
        init_smp();
        // A null frame is what the AP's idle loop interrupts: the handler must
        // count the tick and return the frame untouched.
        let returned = on_timer_cpu(1, core::ptr::null_mut());
        assert!(returned.is_null());
        let ap = stats(1);
        assert_eq!(ap.ticks, 1, "the AP must account its own tick");
        assert_eq!(ap.preempts, 0, "there is no user frame to preempt");
        // The boot processor's counters and the global `time` tick are not
        // touched: `time::TICKS` stays 0 because the host never armed a timer.
        assert_eq!(stats(0).ticks, 0);
        assert_eq!(stats(2).ticks, 0);
    }

    #[test]
    fn reschedule_ipi_is_recorded_and_hands_the_frame_back() {
        let _serial = serial();
        init_smp();
        let returned = on_reschedule(core::ptr::null_mut());
        assert!(returned.is_null(), "the frame must be returned unchanged");
        let me = stats(cpu_index());
        assert_eq!(me.remote_wakes, 1);
        assert_eq!(me.switches, 0, "an IPI never switches by itself");
        assert_eq!(me.preempts, 0);
    }

    #[test]
    fn smp_stats_aggregate_the_application_processors_only() {
        let _serial = serial();
        init_smp();
        // Pretend the BSP resumed three ring3 frames and AP 1 resumed two, with
        // one real AP timer preemption.
        slot(0).user_entries.store(3, Ordering::Relaxed);
        slot(1).user_entries.store(2, Ordering::Relaxed);
        slot(1).preempts.store(1, Ordering::Relaxed);
        let smp = smp_stats();
        assert_eq!(smp.runs, 2, "BSP ring3 resumes are not SMP evidence");
        assert_eq!(smp.cpus, 0b10, "only AP 1 resumed ring3 on an AP");
        assert_eq!(smp.preempts, 1);
        // The remaining fields are passthroughs: they must match their sources
        // exactly, which is what lets the root assert on one snapshot.
        assert_eq!(smp.remote_wakes, process::remote_wakes());
        assert_eq!(smp.ipis, u64::from(platform::reschedule_ipi_sent()));
        let (migrations, balances) = process::migration_counts();
        assert_eq!(smp.migrations, migrations);
        assert_eq!(smp.balances, balances);
        init_smp();
    }

    #[test]
    fn enable_smp_scheduler_requests_exactly_the_online_aps() {
        let _serial = serial();
        init_smp();
        // The host never brought APs online, so the flag turns on but no AP is
        // requested; the root's IPIs are what make a real AP enter `ap_main`.
        enable_smp_scheduler();
        assert!(smp_enabled());
        for cpu in 1..MAX_CPUS {
            assert!(!slot(cpu).requested.load(Ordering::Acquire));
            assert!(!slot(cpu).started.load(Ordering::Acquire));
        }
        init_smp();
        assert!(!smp_enabled(), "reset returns to the pre-enable state");
    }

    #[test]
    fn parked_aps_tracks_which_aps_left_the_process_context() {
        let _serial = serial();
        init_smp();
        assert_eq!(parked_aps(), 0, "nothing is parked before an AP runs");

        slot(1).parked.store(true, Ordering::Release);
        slot(3).parked.store(true, Ordering::Release);
        assert_eq!(parked_aps(), 0b1010, "bits are CPU indexes, BSP excluded");

        slot(1).parked.store(false, Ordering::Release);
        assert_eq!(parked_aps(), 0b1000);

        // `init_smp` must not clear `parked`: the APs are already parked when the
        // root calls it, and a reset would make the root wait for a bit that the
        // idle loop has no reason to set again.
        init_smp();
        assert_eq!(
            parked_aps(),
            0b1000,
            "init_smp must not silently unpark an AP"
        );

        slot(3).parked.store(false, Ordering::Release);
        assert_eq!(parked_aps(), 0);
    }

    #[test]
    fn kernel_cr3_is_stored_for_the_ap_idle_context() {
        let _serial = serial();
        let saved = kernel_cr3();
        set_kernel_cr3(0x0012_3000);
        assert_eq!(kernel_cr3(), 0x0012_3000);
        set_kernel_cr3(saved);
    }
}
