//! M4 process / thread-group objects and user-mode scheduling state.
//!
//! Scope (agents.md §22 M4, Lead decisions m00355/m00389/m00408/m00443/m00445):
//! a *Process* is a ThreadGroup with exactly one thread. Each process owns
//!
//! - one address space (`mm::addrspace::AddressSpaceId`),
//! - one handle table (`object::HandleTable`, created and owned here),
//! - one 8-page (32 KiB) kernel stack at a fixed high-half address with an
//!   unmapped guard page below it (M8g: 16 KiB overflowed on the
//!   TCP read/recv + one-level loopback delivery chain),
//! - a 22-qword ring-3 `TrapFrame` built at `kernel_stack_top - 192`,
//! - a Ready/Running/Blocked/Zombie state plus an exit status.
//!
//! # Blocking (M6a1)
//!
//! A running process may block on up to [`MAX_WAIT_OBJECTS`] event objects with
//! an optional monotonic deadline. The syscall entry frame (which sits at
//! `kernel_stack_top - 184`, one qword *above* the ring3 first frame) is copied
//! into a per-process slot in `.bss` and rewritten so `rip` points back at the
//! two-byte `syscall` instruction; a wake therefore just resumes the copied
//! frame and the syscall re-runs from user mode with the same number and
//! arguments. Wakes never switch: they only mark the waiter `Ready` and record
//! why (first reason wins). `sched::block_and_switch` performs the actual
//! switch, or the `sti; hlt` idle loop when nothing is runnable.
//!
//! # Stack geometry (frozen by Lead m00445, corrected by m00757)
//!
//! ```text
//! top            = base + 8 * 4096        (32 KiB, 16-byte aligned)
//! top - 8        : stack canary / scratch (TSS.rsp0 also points here)
//! top - 16       : first byte the hardware writes on a ring3 -> ring0 entry
//! top - 192      : synthetic ring-3 TrapFrame (176 bytes, occupies .. top-16)
//! frame + 160    : `user_rsp` slot  == top - 32
//! frame + 168    : `user_ss` slot   == top - 24
//! base - 4096    : guard page, never mapped
//! ```
//!
//! A hardware interrupt taken while user mode runs does **not** push at
//! `TSS.rsp0 = top - 8` directly: in 64-bit mode the CPU first aligns the new
//! stack pointer down to a 16-byte boundary (`top - 16`) and then pushes
//! `SS`/`RSP`/`RFLAGS`/`CS`/`RIP`. The entry stub adds its 17 qwords, so the
//! kernel-mode trap frame lands at `top - 192`. The synthetic first frame is
//! placed at exactly that address, so a synthetic resume and a real interrupt
//! frame coincide and the TOP canary at `top - 8` is never touched. (The
//! syscall path is private and takes no timer interrupt: it keeps its own frame
//! at `top - 184` because `syscall` performs no stack switch and no alignment.)
//!
//! # What lives where
//!
//! State machines, handle tables and the wait/exit protocol live here;
//! `sched` owns the "which process is on the CPU right now" pointer, the
//! mode flag (kernel demo vs user mode) and the actual `TrapFrame` hand-off.
//! `sched` only reads/mutates this module through the small accessors at the
//! bottom of the file.
//!
//! # Host tests
//!
//! Everything hardware dependent (PMM frames, page mapping, image loading) is
//! exercised by the QEMU run; the pure logic (frame layout, round-robin
//! selection, rights-reduction and wait/zombie decisions) is unit tested here.

use core::marker::PhantomData;
use core::sync::atomic::{AtomicU8, AtomicU32, AtomicU64, Ordering};

use crate::arch::traps::FRAME_QWORDS;
use crate::arch::{TrapFrame, halt};
use crate::compat::linux::fd::FdTable;
use crate::compat::linux::stack as linux_stack;
use crate::mm::addrspace::{self, AddressSpaceId};
use crate::mm::pmm::{self, PmmError};
use crate::mm::vm::{self, VmError};
use crate::object::{self, Handle, HandleTable, ObjectError, ObjectId, ObjectKind, Rights};
use crate::sched;
use crate::sync::IrqSpinLock;
use crate::{image, klog};

/// Maximum number of live process slots (must match `addrspace::MAX_SPACES`).
///
/// M4 needed init plus one child. M6b2 keeps the last user process (its kernel
/// stack and address space stay mapped until the closing deliberate fault) and
/// runs two detached workers at the same time, so three slots were live at once.
///
/// M9c needs four at once: init, the lock-peer parent, role1 and role2. The two
/// lock peers are direct children of the same parent (`wait4(-1)` may reap
/// either), so the parent's slot and both children's slots must coexist until
/// role1 is reaped. `addrspace::MAX_SPACES` is widened to match.
pub const MAX_PROCESSES: usize = 4;

/// Kernel stack of a process: 8 PMM frames (32 KiB), guard page below.
///
/// M8g widened this from 4 frames: the TCP read/recv path plus one level of
/// loopback synchronous delivery reached ~16,304 bytes of pure frames in the
/// frame audit (Lead m03270), just over the old 16 KiB budget. The guard page,
/// the `top - 192` first-frame geometry, the 1 MiB slot spacing and the
/// `KERNEL_STACK_TOP_RESERVED` canary slot are unchanged; 8 frames still fit
/// inside each slot and inside the PD window shared with the M3/AP stacks.
pub const KERNEL_STACK_FRAMES: u64 = 8;
/// Size of one process kernel stack in bytes.
pub const KERNEL_STACK_BYTES: u64 = KERNEL_STACK_FRAMES * pmm::FRAME_SIZE;
/// Bytes reserved at the top of the kernel stack (canary + TSS.rsp0 slack).
pub const KERNEL_STACK_TOP_RESERVED: u64 = 8;
/// Value stored at `kernel_stack_top - 8` and verified on every switch.
pub const KERNEL_STACK_CANARY: u64 = 0x4D34_0000_CAFE_5EED;
/// `size_of::<TrapFrame>()` (22 qwords) in bytes.
pub const FRAME_BYTES: u64 = core::mem::size_of::<TrapFrame>() as u64;

/// Kernel stacks of the M6b2/M9c process slots.
///
/// Lead m00408 froze 815/816; 817 is the third slot, below the per-CPU AP
/// stacks at `vm::AP_STACK_BASE`. M9c adds a fourth slot at 812, the free 1 MiB
/// window between the boot stack (810, ends at 8100_4000) and the M3 scheduler
/// stack A (813). The 812 slot keeps its guard page at 811F_F000 inside the same
/// PD window, so no new page table is needed for the guard.
pub const KERNEL_STACK_BASES: [u64; MAX_PROCESSES] = [
    0xFFFF_FFFF_8150_0000,
    0xFFFF_FFFF_8160_0000,
    0xFFFF_FFFF_8170_0000,
    0xFFFF_FFFF_8120_0000,
];

/// Sentinel for "no current process".
pub const NO_PROCESS: u8 = 0xFF;

/// Maximum number of direct children one process may have (M9c).
///
/// Two, because the fcntl hand-off runs the same ELF as two lock peers under a
/// single supervisor. The entries store raw slot indexes; `NO_PROCESS` marks an
/// empty entry. A third spawn is rejected with [`ProcessError::ChildExists`].
pub const MAX_CHILDREN: usize = 2;

/// Logical index of the boot processor (slot 0 of every per-CPU table).
///
/// New processes are published as belonging to the boot processor: M6b2a keeps
/// all scheduling on the BSP, so the recorded owner is only an observation
/// until M6b2b assigns CPUs.
pub const BSP_CPU: u8 = 0;

/// Affinity mask given to processes that do not ask for a narrower one: every
/// CPU of the M6b2 machine (four slots, `arch::MAX_CPUS`).
pub const DEFAULT_AFFINITY: u8 = 0x0F;

/// Every CPU bit the affinity mask can name.
pub const CPU_MASK_ALL: u8 = (1u8 << crate::arch::MAX_CPUS) - 1;

/// Why a process was moved to another CPU (M6b2).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum MigrationReason {
    /// Explicit affinity change ([`migrate`]).
    Affinity,
    /// Load balancing ([`rebalance`]).
    Balance,
}

/// A migration that has been decided but not yet observed on the target CPU.
///
/// Statistics are only bumped when the process is actually resumed in ring 3 on
/// `target` (see [`mark_running`]): counting at request time would report moves
/// that never happened (the process can still be woken on its source CPU).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
struct PendingMigration {
    source_cpu: u8,
    target_cpu: u8,
    reason: MigrationReason,
}

/// Index of a process inside the process table.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct ProcessId(u8);

impl ProcessId {
    /// Table index of this process.
    pub const fn index(self) -> usize {
        self.0 as usize
    }

    /// Raw encoded id.
    pub const fn raw(self) -> u8 {
        self.0
    }

    const fn from_index(index: usize) -> ProcessId {
        ProcessId(index as u8)
    }
}

/// Scheduler-visible state of a process.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ProcessState {
    /// Runnable, waiting on the CPU.
    Ready = 0,
    /// Currently on the CPU.
    Running = 1,
    /// Waiting for one of its wait objects or its deadline; never selected by
    /// the round robin until a wake marks it `Ready` again.
    Blocked = 2,
    /// Exited; status is available until the parent reaps it.
    Zombie = 3,
}

impl ProcessState {
    const fn as_u8(self) -> u8 {
        self as u8
    }
}

/// Maximum number of event objects one blocking wait may observe.
///
/// The wake path scans the (at most two) process slots, never the object table,
/// so this bound is what keeps a wake ISR-safe and O(1).
pub const MAX_WAIT_OBJECTS: usize = 4;

/// Key that matches every [`wake_object_key`] of its object.
///
/// Non-keyed waits ([`block_current`]) use this for every item; a keyed wait
/// ([`block_current_keyed`]) passes the caller's key verbatim (0 for Event and
/// Timer, the endpoint for an EventPair).
pub const WAIT_ANY_KEY: u32 = u32::MAX;

/// Bytes of the native `syscall` instruction the blocked frame replays.
const NATIVE_SYSCALL_BYTES: u64 = 2;

/// Offset from a kernel stack top to the private `syscall` trap frame.
///
/// The `syscall` stub enters on `top - 8` and subtracts one 176-byte
/// [`TrapFrame`] without any CPU stack realignment (no privilege change), so
/// its frame sits one qword above the ring3 first frame at `top - 192`.
pub const SYSCALL_FRAME_OFFSET: u64 = KERNEL_STACK_TOP_RESERVED + FRAME_BYTES;

/// Address of the private `syscall` trap frame for a kernel stack top.
pub const fn syscall_frame_addr(top: u64) -> u64 {
    top - SYSCALL_FRAME_OFFSET
}

/// Why a blocked process was made runnable again.
///
/// Values are frozen by the Lead (M6a1 interface): `None` is the "no reason
/// recorded" state returned by [`take_wake_reason`] after a process has already
/// consumed its wake.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum WakeReason {
    /// No wake recorded.
    None = 0,
    /// One of the wait objects became ready.
    Ready = 1,
    /// The deadline passed.
    Timeout = 2,
    /// A wait object was destroyed.
    Destroyed = 3,
    /// An armed wait was cancelled by its owner.
    Cancelled = 4,
    /// A peer closed (Channel/Port close in later M6a slices).
    PeerClosed = 5,
}

impl WakeReason {
    /// True when a wake reason has been recorded.
    pub const fn is_some(self) -> bool {
        !matches!(self, WakeReason::None)
    }
}

// ---------------------------------------------------------------------------
// Linux64 signal state (M8c).
//
// The compat personality owns the Linux ABI surface: `rt_sigaction`,
// `rt_sigprocmask`, `kill`/`tgkill` argument checking, `rt_sigreturn`, the
// user-memory `rt_sigframe` and the choice of default actions. This module
// owns only the per-thread-group state and the small state machine:
//
// - the action table (`actions[signo]`, slot 0 unused),
// - the pending and blocked masks (standard signals 1..=31 only; RT signals
//   32..=64 are rejected by the personality layer),
// - one in-flight handler delivery record (M8c does not support nesting).
//
// Every entry point takes `PROCESS_LOCK` through `with_table` and only touches
// the current process slot: it never runs object/handle code, never touches
// user memory and never allocates. The compat layer is responsible for writing
// the user stack frame and for rewriting the ring-3 `TrapFrame` after
// [`signal_take_pending`] returns `Handler`.
// ---------------------------------------------------------------------------

/// `SIG_DFL`: perform the signal's default action.
pub const SIG_DFL: u64 = 0;
/// `SIG_IGN`: ignore the signal.
pub const SIG_IGN: u64 = 1;
/// `SIGKILL`: cannot be caught, blocked or ignored.
pub const SIGKILL: u32 = 9;
/// `SIGSTOP`: cannot be caught, blocked or ignored.
pub const SIGSTOP: u32 = 19;
/// Highest standard signal number supported by this slice.
pub const SIGNAL_MAX: u32 = 31;
/// `SA_NODEFER`: do not add the delivered signal to the blocked mask.
pub const SA_NODEFER: u64 = 0x4000_0000;

/// Number of slots in [`SignalState::actions`] (index 0 unused).
const SIGNAL_TABLE: usize = 32;
/// Bits of the supported standard signals (`signo n` <-> bit `n - 1`).
const SIGNAL_BITS: u64 = (1u64 << SIGNAL_MAX) - 1;
/// `SIGKILL`/`SIGSTOP` can never be blocked.
const UNCATCHABLE_BITS: u64 = signal_bit(SIGKILL) | signal_bit(SIGSTOP);

/// ABI-visible `struct sigaction` (32 bytes on Linux64).
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
#[repr(C)]
pub struct SigAction {
    /// Handler address, [`SIG_DFL`] or [`SIG_IGN`].
    pub handler: u64,
    /// `SA_*` flags.
    pub flags: u64,
    /// `SA_RESTORER` trampoline; preserved verbatim by this slice.
    pub restorer: u64,
    /// Signals additionally blocked while the handler runs.
    pub mask: u64,
}

const _: () = assert!(core::mem::size_of::<SigAction>() == 32);

/// Signal state machine errors; the personality layer maps them to Linux
/// `errno` values.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SignalError {
    /// Signal number 0 or above [`SIGNAL_MAX`].
    InvalidSignal,
    /// `rt_sigaction` for [`SIGKILL`]/[`SIGSTOP`].
    Uncatchable,
    /// No process is current on this CPU.
    NoCurrentProcess,
    /// `signal_restore_context` without an in-flight handler.
    NotDelivering,
}

/// `rt_sigprocmask` operation.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SignalMaskHow {
    /// Add the signals in the set.
    Block,
    /// Remove the signals in the set.
    Unblock,
    /// Replace the mask with the set.
    SetMask,
}

/// Registers and user stack pointer captured when a handler is entered.
///
/// `regs` mirrors the first 15 `TrapFrame` words exactly:
/// `[r15, r14, r13, r12, rbp, rbx, r11, r10, r9, r8, rax, rcx, rdx, rsi, rdi]`,
/// so `regs[10]` is `rax` and `regs[12]` is `rdx`.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct UserContext {
    pub regs: [u64; 15],
    pub rip: u64,
    pub rflags: u64,
    pub rsp: u64,
    pub ss: u64,
}

const _: () = assert!(core::mem::size_of::<UserContext>() == 19 * 8);

impl UserContext {
    /// Capture the ring-3 state from `frame`.
    pub fn capture(frame: &TrapFrame) -> Self {
        Self {
            regs: [
                frame.r15, frame.r14, frame.r13, frame.r12, frame.rbp, frame.rbx, frame.r11,
                frame.r10, frame.r9, frame.r8, frame.rax, frame.rcx, frame.rdx, frame.rsi,
                frame.rdi,
            ],
            rip: frame.rip,
            rflags: frame.rflags,
            rsp: frame.user_rsp,
            ss: frame.user_ss,
        }
    }

    /// Restore the captured ring-3 state into `frame`.
    ///
    /// Does **not** touch `cs`: the ring-3 code selector stays `USER_CS`.
    pub fn apply(self, frame: &mut TrapFrame) {
        frame.r15 = self.regs[0];
        frame.r14 = self.regs[1];
        frame.r13 = self.regs[2];
        frame.r12 = self.regs[3];
        frame.rbp = self.regs[4];
        frame.rbx = self.regs[5];
        frame.r11 = self.regs[6];
        frame.r10 = self.regs[7];
        frame.r9 = self.regs[8];
        frame.r8 = self.regs[9];
        frame.rax = self.regs[10];
        frame.rcx = self.regs[11];
        frame.rdx = self.regs[12];
        frame.rsi = self.regs[13];
        frame.rdi = self.regs[14];
        frame.rip = self.rip;
        frame.rflags = self.rflags;
        frame.user_rsp = self.rsp;
        frame.user_ss = self.ss;
    }
}

/// Result of [`signal_take_pending`].
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum PendingSignal {
    /// The signal is ignored (`SIG_IGN`, or ignored by default): pending was
    /// consumed and no handler runs.
    Ignored(u32),
    /// The default action applies; the personality performs termination (or
    /// rejects unsupported stop) after releasing its own guards.
    Default(u32),
    /// A user handler runs: the personality builds the `rt_sigframe` from
    /// `saved`, rewrites the ring-3 `TrapFrame` and later calls
    /// [`signal_restore_context`].
    Handler {
        signo: u32,
        action: SigAction,
        saved: UserContext,
        /// Blocked mask **before** delivery; write it into the `rt_sigframe`.
        saved_mask: u64,
    },
}

/// Single in-flight delivery record.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
struct SavedDelivery {
    saved: UserContext,
    saved_mask: u64,
}

/// Empty action slot used to build [`SignalState::new`] in const context.
const EMPTY_SIGACTION: SigAction = SigAction {
    handler: SIG_DFL,
    flags: 0,
    restorer: 0,
    mask: 0,
};

/// Per-thread-group Linux signal state.
///
/// Opaque to the compat personality: access goes through
/// [`with_current_signals`] and the `signal_*` entry points so the process
/// table lock is taken in exactly one place.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct SignalState {
    /// `actions[signo]`; slot 0 is unused, entries default to [`SIG_DFL`].
    pub(crate) actions: [SigAction; SIGNAL_TABLE],
    /// Pending standard signals (`signo n` <-> bit `n - 1`).
    pub(crate) pending: u64,
    /// Blocked standard signals (`signo n` <-> bit `n - 1`).
    pub(crate) blocked: u64,
    /// In-flight handler delivery (`None` when no handler runs).
    saved: Option<SavedDelivery>,
}

impl SignalState {
    /// Fresh state: default actions, nothing blocked or pending and no handler
    /// in flight.
    pub const fn new() -> Self {
        Self {
            actions: [EMPTY_SIGACTION; SIGNAL_TABLE],
            pending: 0,
            blocked: 0,
            saved: None,
        }
    }
}

/// Map a signal number to its pending/blocked mask bit.
const fn signal_bit(signo: u32) -> u64 {
    1u64 << (signo - 1)
}

/// Validate a user-provided signal number.
fn valid_signal(signo: u32) -> Result<u32, SignalError> {
    if signo == 0 || signo > SIGNAL_MAX {
        return Err(SignalError::InvalidSignal);
    }
    Ok(signo)
}

/// True when the signal's default action is "ignore" on Linux.
const fn default_ignores(signo: u32) -> bool {
    matches!(signo, 17 | 18 | 23 | 28) // SIGCHLD, SIGCONT, SIGURG, SIGWINCH
}

/// Lowest pending signal that may be delivered now; `None` when every pending
/// signal is blocked and not uncatchable.
fn select_pending(state: &SignalState) -> Option<u32> {
    let pending = state.pending & SIGNAL_BITS;
    for signo in 1..=SIGNAL_MAX {
        if pending & signal_bit(signo) == 0 {
            continue;
        }
        if signo != SIGKILL && signo != SIGSTOP && state.blocked & signal_bit(signo) != 0 {
            continue;
        }
        return Some(signo);
    }
    None
}

/// True when `signo` would interrupt a blocked process rather than stay
/// pending: not blocked, not ignored and not ignored by default.
fn signal_interrupts(state: &SignalState, signo: u32) -> bool {
    if signo != SIGKILL && signo != SIGSTOP && state.blocked & signal_bit(signo) != 0 {
        return false;
    }
    let action = state.actions[signo as usize];
    if action.handler == SIG_IGN {
        return false;
    }
    !(action.handler == SIG_DFL && default_ignores(signo))
}

/// Run `f` on the current process's signal state with [`PROCESS_LOCK`] held.
///
/// **Context rules**: `f` may only read/write the state. It must not touch user
/// memory, the object/handle table or any path that can run a destroy hook.
/// Returns `None` when no process is current on this CPU.
pub fn with_current_signals<R>(f: impl FnOnce(&mut SignalState) -> R) -> Option<R> {
    with_table(|| {
        let index = current_index_unlocked()?;
        let process = unsafe { process_ref(index) }?;
        Some(f(&mut process.signals))
    })
}

/// `rt_sigaction` read: the current action of `signo`.
pub fn signal_action(signo: u32) -> Result<SigAction, SignalError> {
    let signo = valid_signal(signo)?;
    with_current_signals(|state| state.actions[signo as usize]).ok_or(SignalError::NoCurrentProcess)
}

/// `rt_sigaction` write: install `action`, returning the previous one.
pub fn signal_set_action(signo: u32, action: SigAction) -> Result<SigAction, SignalError> {
    let signo = valid_signal(signo)?;
    if matches!(signo, SIGKILL | SIGSTOP) {
        return Err(SignalError::Uncatchable);
    }
    with_current_signals(|state| core::mem::replace(&mut state.actions[signo as usize], action))
        .ok_or(SignalError::NoCurrentProcess)
}

/// Current blocked mask (`rt_sigprocmask` read); bits are `signo - 1`.
pub fn signal_mask() -> Result<u64, SignalError> {
    with_current_signals(|state| state.blocked & SIGNAL_BITS).ok_or(SignalError::NoCurrentProcess)
}

/// `rt_sigprocmask`: update the blocked mask, returning the previous one.
///
/// `SIGKILL`/`SIGSTOP` bits are silently dropped: they can never be blocked.
pub fn signal_set_mask(how: SignalMaskHow, set: u64) -> Result<u64, SignalError> {
    let set = set & SIGNAL_BITS & !UNCATCHABLE_BITS;
    with_current_signals(|state| {
        let old = state.blocked & SIGNAL_BITS;
        let next = match how {
            SignalMaskHow::Block => old | set,
            SignalMaskHow::Unblock => old & !set,
            SignalMaskHow::SetMask => set,
        };
        state.blocked = next & !UNCATCHABLE_BITS;
        old
    })
    .ok_or(SignalError::NoCurrentProcess)
}

/// Pending signals of `owner` that `mask` selects while they stay blocked.
///
/// Returns a bitmap (`signo n` maps to bit `n - 1`): `pending & mask & blocked`.
/// Only blocked signals can be consumed through a signalfd — a deliverable
/// pending signal must keep its normal delivery/interrupt path. `SIGKILL` and
/// `SIGSTOP` are never reported. An unknown or dead `owner` yields `0`.
pub fn signal_pending_for(owner: ProcessId, mask: u64) -> u64 {
    let mask = mask & SIGNAL_BITS & !UNCATCHABLE_BITS;
    if mask == 0 {
        return 0;
    }
    with_table(|| {
        let Some(process) = (unsafe { process_ref(owner.index()) }) else {
            return 0;
        };
        process.signals.pending & process.signals.blocked & mask
    })
}

/// Consume the lowest pending signal of `owner` selected by `mask`.
///
/// The signal must be blocked (signalfd semantics); its pending bit is cleared
/// without running the action. `SIGKILL`/`SIGSTOP` are skipped and other
/// pending signals are left untouched. Returns the signal number (1..=31).
pub fn signal_take_pending_for(owner: ProcessId, mask: u64) -> Option<u32> {
    let mask = mask & SIGNAL_BITS & !UNCATCHABLE_BITS;
    if mask == 0 {
        return None;
    }
    with_table(|| {
        let process = unsafe { process_ref(owner.index()) }?;
        let state = &mut process.signals;
        let pending = state.pending & state.blocked & mask;
        let signo = (1..=SIGNAL_MAX).find(|&signo| pending & signal_bit(signo) != 0)?;
        state.pending &= !signal_bit(signo);
        Some(signo)
    })
}

/// `kill(2)`/`tgkill(2)` addressed at the current process.
///
/// `pid`/`tid` validation stays in the personality layer. Standard signals do
/// not queue: sending one while its pending bit is set is a no-op. When the
/// current process is `Blocked` and the signal is deliverable, it is woken with
/// [`WakeReason::Cancelled`] so its syscall replays with `EINTR`.
pub fn signal_send_current(signo: u32) -> Result<(), SignalError> {
    let signo = valid_signal(signo)?;
    let index = with_table(|| {
        let index = current_index_unlocked().ok_or(SignalError::NoCurrentProcess)?;
        let process = unsafe { process_ref(index) }.ok_or(SignalError::NoCurrentProcess)?;
        process.signals.pending |= signal_bit(signo);
        if process.state == ProcessState::Blocked && signal_interrupts(&process.signals, signo) {
            wake_process_unlocked(index, WakeReason::Cancelled);
        }
        Ok(index)
    })?;
    notify_signalfd(ProcessId::from_index(index));
    Ok(())
}

/// Deliver the lowest deliverable pending signal.
///
/// Clears the pending bit, applies the action and, for a user handler, saves
/// the ring-3 state and the pre-delivery blocked mask. While a handler is in
/// flight (`saved.is_some()`) this returns `Ok(None)`: M8c does not nest
/// deliveries, remaining pending signals wait for `rt_sigreturn`.
pub fn signal_take_pending(frame: &TrapFrame) -> Result<Option<PendingSignal>, SignalError> {
    with_table(|| -> Result<Option<PendingSignal>, SignalError> {
        let index = current_index_unlocked().ok_or(SignalError::NoCurrentProcess)?;
        let process = unsafe { process_ref(index) }.ok_or(SignalError::NoCurrentProcess)?;
        let state = &mut process.signals;
        if state.saved.is_some() {
            return Ok(None);
        }
        let Some(signo) = select_pending(state) else {
            return Ok(None);
        };
        state.pending &= !signal_bit(signo);
        let action = state.actions[signo as usize];
        if signo == SIGKILL || signo == SIGSTOP {
            return Ok(Some(PendingSignal::Default(signo)));
        }
        if action.handler == SIG_IGN {
            return Ok(Some(PendingSignal::Ignored(signo)));
        }
        if action.handler == SIG_DFL {
            return Ok(Some(if default_ignores(signo) {
                PendingSignal::Ignored(signo)
            } else {
                PendingSignal::Default(signo)
            }));
        }
        let saved = UserContext::capture(frame);
        let saved_mask = state.blocked & SIGNAL_BITS;
        let mut added = action.mask & SIGNAL_BITS & !UNCATCHABLE_BITS;
        if action.flags & SA_NODEFER == 0 {
            added |= signal_bit(signo);
        }
        state.blocked = (state.blocked | added) & !UNCATCHABLE_BITS;
        state.saved = Some(SavedDelivery { saved, saved_mask });
        Ok(Some(PendingSignal::Handler {
            signo,
            action,
            saved,
            saved_mask,
        }))
    })
}

/// `rt_sigreturn`: restore the state saved by [`signal_take_pending`].
///
/// Restores every [`UserContext`] field into `frame` (including `regs[10]` /
/// `regs[12]`, i.e. `rax`/`rdx`) and the pre-delivery blocked mask, then clears
/// the in-flight record. The caller then reads `frame.rax`/`frame.rdx` for its
/// `SyscallRet` status/result pair.
pub fn signal_restore_context(frame: &mut TrapFrame) -> Result<(), SignalError> {
    with_table(|| -> Result<(), SignalError> {
        let index = current_index_unlocked().ok_or(SignalError::NoCurrentProcess)?;
        let process = unsafe { process_ref(index) }.ok_or(SignalError::NoCurrentProcess)?;
        let Some(saved) = process.signals.saved.take() else {
            return Err(SignalError::NotDelivering);
        };
        process.signals.blocked = saved.saved_mask & SIGNAL_BITS & !UNCATCHABLE_BITS;
        saved.saved.apply(frame);
        Ok(())
    })
}

/// Wake exactly one blocked process slot on its owner CPU, recording `reason`;
/// same routing rules as [`wake_matching`] (first reason wins).
fn wake_process_unlocked(index: usize, reason: WakeReason) {
    let Some(process) = (unsafe { process_ref(index) }) else {
        return;
    };
    if process.wake_reason.is_some() {
        return;
    }
    process.wake_reason = reason;
    let affinity = process.affinity.load(Ordering::Acquire);
    let recorded = process.cpu.load(Ordering::Acquire) as usize;
    let target = if recorded < crate::arch::MAX_CPUS
        && recorded < online_cpu_count()
        && affinity_allows(affinity, recorded as u8)
    {
        recorded
    } else {
        first_online_affinity_cpu(affinity)
            .map(|cpu| cpu as usize)
            .unwrap_or(BSP_CPU as usize)
    };
    queue_remove_unlocked(index);
    process.state = ProcessState::Ready;
    process.cpu.store(target as u8, Ordering::Release);
    queue_push_unlocked(index, target);
    if target != current_cpu() {
        REMOTE_WAKES.fetch_add(1, Ordering::AcqRel);
        request_resched_unlocked(target);
    }
}

/// Kind of a blocking wait (M6a2 added the futex kind).
///
/// The two kinds never match each other's triggers: an object wake
/// ([`wake_object`]/[`wake_object_key`]) cannot release a futex waiter, and
/// [`wake_futex`] cannot release an object waiter. Only a deadline expires both.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum WaitKind {
    /// Event/EventPair/Timer objects watched through [`WaitSpec::objects`].
    Objects,
    /// A user futex word, identified by its **exact physical address** (the
    /// syscall layer translates the user VA and compares the value; the kernel
    /// never dereferences the address).
    Futex(u64),
}

/// What a blocked process is waiting for.
#[derive(Clone, Copy, Debug)]
struct WaitSpec {
    /// Which family of trigger may release this wait.
    kind: WaitKind,
    /// Objects watched for readiness/destruction; entries beyond `count` are
    /// `ObjectId::MAX` padding and never match.
    objects: [ObjectId; MAX_WAIT_OBJECTS],
    /// Kind-specific key per object (`u32::MAX` = matches any key). Parallel to
    /// `objects`; for an EventPair this is the endpoint (0/1), for Event/Timer 0.
    keys: [u32; MAX_WAIT_OBJECTS],
    /// Number of meaningful entries in `objects`/`keys`.
    count: usize,
    /// Absolute deadline on the [`crate::time::monotonic_ticks`] clock.
    deadline: Option<u64>,
}

impl WaitSpec {
    /// A wait for nothing: only the timer tick could ever release it.
    const EMPTY: WaitSpec = WaitSpec {
        kind: WaitKind::Objects,
        objects: [ObjectId::MAX; MAX_WAIT_OBJECTS],
        keys: [WAIT_ANY_KEY; MAX_WAIT_OBJECTS],
        count: 0,
        deadline: None,
    };

    /// Build an object wait spec from the caller's arrays and count.
    const fn new(
        objects: [ObjectId; MAX_WAIT_OBJECTS],
        keys: [u32; MAX_WAIT_OBJECTS],
        count: usize,
        deadline: Option<u64>,
    ) -> Self {
        WaitSpec {
            kind: WaitKind::Objects,
            objects,
            keys,
            count,
            deadline,
        }
    }

    /// Build a futex wait spec for the exact physical word `physical_word`.
    const fn futex(physical_word: u64, deadline: Option<u64>) -> Self {
        WaitSpec {
            kind: WaitKind::Futex(physical_word),
            objects: [ObjectId::MAX; MAX_WAIT_OBJECTS],
            keys: [WAIT_ANY_KEY; MAX_WAIT_OBJECTS],
            count: 0,
            deadline,
        }
    }

    /// Clamped number of meaningful entries.
    fn len(&self) -> usize {
        if self.count < MAX_WAIT_OBJECTS {
            self.count
        } else {
            MAX_WAIT_OBJECTS
        }
    }

    /// The futex word this wait observes, if it is a futex wait.
    const fn futex_word(&self) -> Option<u64> {
        match self.kind {
            WaitKind::Futex(word) => Some(word),
            WaitKind::Objects => None,
        }
    }

    /// True when the wait observes `object`, regardless of its key.
    fn watches(&self, object: ObjectId) -> bool {
        matches!(self.kind, WaitKind::Objects) && self.objects[..self.len()].contains(&object)
    }

    /// True when the wait observes `object` with `key` (or a wildcard key).
    fn watches_key(&self, object: ObjectId, key: u32) -> bool {
        matches!(self.kind, WaitKind::Objects)
            && self.objects[..self.len()]
                .iter()
                .zip(&self.keys[..self.len()])
                .any(|(watched, watched_key)| {
                    *watched == object && (*watched_key == key || *watched_key == WAIT_ANY_KEY)
                })
    }
}

/// Fixed storage for the copied `syscall` [`TrapFrame`] of a blocked process.
///
/// 16-byte aligned so the copy is a plain qword copy and the frame can later be
/// handed straight to `resume_frame`/an IRQ stub. It lives in `.bss`, **not** on
/// the process's kernel stack: while the process is blocked, the idle loop runs
/// on that stack with interrupts enabled and its timer frames would overwrite
/// the private `top - 184` frame.
#[repr(C, align(16))]
struct FrameSlot([u64; FRAME_QWORDS]);

impl FrameSlot {
    const fn new() -> Self {
        FrameSlot([0; FRAME_QWORDS])
    }

    fn as_frame(&mut self) -> *mut TrapFrame {
        self.0.as_mut_ptr().cast::<TrapFrame>()
    }
}

const _: () = assert!(core::mem::size_of::<FrameSlot>() == FRAME_BYTES as usize);

/// What should wake a blocked process, as a pure decision input.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum WakeTrigger {
    /// An event object became observable, ignoring the wait key.
    Object(ObjectId, WakeReason),
    /// One keyed facet of an event object became observable (EventPair endpoint).
    ObjectKey(ObjectId, u32, WakeReason),
    /// A futex word at this exact physical address was woken.
    Futex(u64),
    /// The clock reached `now`; every deadline `<= now` expires.
    Deadline(u64),
}

impl WakeTrigger {
    /// Reason recorded for a successful wake.
    const fn reason(self) -> WakeReason {
        match self {
            WakeTrigger::Object(_, reason) | WakeTrigger::ObjectKey(_, _, reason) => reason,
            // A futex wake publishes the word to user space; the waiter replays
            // the syscall and reports a normal success.
            WakeTrigger::Futex(_) => WakeReason::Ready,
            WakeTrigger::Deadline(_) => WakeReason::Timeout,
        }
    }

    /// True when `wait` is satisfied by this trigger.
    fn matches(self, wait: &WaitSpec) -> bool {
        match self {
            WakeTrigger::Object(object, _) => wait.watches(object),
            WakeTrigger::ObjectKey(object, key, _) => wait.watches_key(object, key),
            WakeTrigger::Futex(word) => wait.futex_word() == Some(word),
            WakeTrigger::Deadline(now) => {
                matches!(wait.deadline, Some(deadline) if now >= deadline)
            }
        }
    }
}

/// One handle the parent explicitly passes to a child on creation.
///
/// Only the listed handles are copied (a copy, never a move: the parent keeps
/// its handle); rights are narrowed, never widened.
#[derive(Clone, Copy, Debug)]
pub struct HandleTransfer {
    /// Handle in the parent's table.
    pub handle: Handle,
    /// Rights requested for the child's copy (must be a subset).
    pub rights: Rights,
}

impl HandleTransfer {
    /// Build a transfer request.
    pub const fn new(handle: Handle, rights: Rights) -> Self {
        HandleTransfer { handle, rights }
    }
}

/// Failures of the process layer.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ProcessError {
    /// Both process slots are taken.
    NoFreeSlot,
    /// Parent id does not name a live process.
    NoSuchProcess,
    /// The parent already has [`MAX_CHILDREN`] direct children (M9c).
    ChildExists,
    /// The requested pid does not name a live child of the caller (M8d).
    ///
    /// The compat personality maps this to `ECHILD`; a zombie is *not* an
    /// error for `wait4` — the caller first tries [`take_child_exit`] and this
    /// variant only reports "there is no such child to wait for".
    NoChild,
    /// Boot module / ELF loading failed (details are logged by `image`).
    Image,
    /// Address-space creation failed.
    AddressSpace(VmError),
    /// Page mapping failed.
    Map(VmError),
    /// Kernel stack frame allocation failed.
    Stack(PmmError),
    /// Handle table operation failed.
    Objects(ObjectError),
    /// A transfer asked for rights the parent does not have.
    RightsEscalation,
    /// The request reused one source handle twice (or is otherwise malformed).
    ///
    /// Two `duplicate` calls on the same source would create two handles that
    /// guard the *same* reference released twice, so M4 rejects the whole
    /// request instead of tracking per-duplicate reference counts.
    BadRequest,
}

/// Result of a wait attempt.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum WaitError {
    /// The child exists but has not exited yet.
    WouldBlock,
    /// The handle is not a valid Process+WAIT handle of this process.
    InvalidHandle,
    /// The handle names a process that is not a child of the caller.
    NotChild,
    /// Reaping the child failed.
    Reap(ProcessError),
}

/// What a wait attempt decided, as a pure function of the child's state.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum WaitDecision {
    /// The child is a zombie: report its status (and reap it).
    Exited(u64),
    /// The child is still running.
    Blocked,
}

/// Execution personality bound to a thread group (M7d).
///
/// The personality is a thread-group resource: every thread of the group shares
/// it and `exec` replaces it for the whole group. The syscall entry reads the
/// **current process's** personality to pick its dispatch table; the value is
/// never a global variable, so two processes of different personalities can run
/// on two CPUs at the same time.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum Personality {
    /// Native CaelumOS ABI (every M4-M6 process).
    #[default]
    Native,
    /// x86-64 Linux personality: Linux syscall table plus the Linux fd table
    /// and network namespace carried by [`ProcessExtras`].
    Linux64,
}

impl Personality {
    /// Stable short name for diagnostics and `/proc`-style views.
    pub const fn name(self) -> &'static str {
        match self {
            Personality::Native => "native",
            Personality::Linux64 => "linux64",
        }
    }
}

/// Thread-group state a creator hands to [`register_with`] (M7d).
///
/// Native processes use [`ProcessExtras::native`] (empty fd table, no network
/// namespace). `spawn_detached_linux` fills a `Linux64` group with the console
/// fds, the inherited channel endpoint and the network namespace object.
struct ProcessExtras {
    personality: Personality,
    /// Linux fd table. Empty for native processes; `install_console` fills
    /// fds 0/1/2 before registration for a Linux process.
    fds: FdTable,
    /// Network namespace object of a Linux process, also exposed through the
    /// initial stack's `AT_CAELUM_NETNS` entry.
    linux_netns: Option<Handle>,
}

impl ProcessExtras {
    /// Extras of a native process: native personality and an empty fd table.
    const fn native() -> Self {
        Self {
            personality: Personality::Native,
            fds: FdTable::new(),
            linux_netns: None,
        }
    }
}

/// One process (a single-threaded thread group).
struct Process {
    state: ProcessState,
    address_space: AddressSpaceId,
    handles: HandleTable,
    /// Execution personality of this thread group (M7d).
    personality: Personality,
    /// Linux fd table (M7d). Empty for native processes.
    fds: FdTable,
    /// True while a [`CurrentFdsGuard`] owns the table and left an empty
    /// placeholder in the slot. Mirrors [`Process::handles_taken`].
    fds_taken: bool,
    /// Network namespace handle bound to a Linux process (auxv
    /// `AT_CAELUM_NETNS`); `None` for native processes and for the Linux
    /// `/proc/self/ns/net`-less case.
    linux_netns: Option<Handle>,
    /// True while a [`CurrentHandlesGuard`] owns this table and left an empty
    /// placeholder in the slot.
    ///
    /// The table is moved out under [`PROCESS_LOCK`] so the caller can run
    /// object destroy hooks, VFS closes and similar work **outside** the lock.
    /// Every reader must check this flag before treating `handles` as the real
    /// table; only the guard clears it, in its `Drop`, and only for the slot it
    /// took the table from.
    handles_taken: bool,
    kernel_stack_top: u64,
    stack_frames: [u64; KERNEL_STACK_FRAMES as usize],
    saved: *mut TrapFrame,
    exit_status: u64,
    /// Signal that terminated the process (M8d `wait4`).
    ///
    /// `None` for a normal exit. The compat layer must not infer this from the
    /// exit code: a signal-terminated process records the signal here and the
    /// status encoding (`code << 8` vs. the low 7 bits) is decided by that
    /// personality, not by a `128 + signo` convention.
    exit_signal: Option<u32>,
    process_object: ObjectId,
    parent: Option<ProcessId>,
    /// Direct children, by process slot index; [`NO_PROCESS`] marks an empty
    /// entry.
    ///
    /// M9c replaced the single M4 `child` link with two bounded entries so one
    /// parent can supervise both lock peers of the fcntl hand-off. Keeping raw
    /// `u8` entries (instead of `Option<ProcessId>`) preserves the frozen
    /// `Process` layout: the field still occupies exactly two bytes.
    children: [u8; MAX_CHILDREN],
    wait_handle: Handle,
    /// What this process is waiting on; meaningful while `state` is `Blocked`.
    wait: WaitSpec,
    /// Why the last wake happened; consumed by [`take_wake_reason`].
    wake_reason: WakeReason,
    /// Copy of the `syscall` frame a blocked process resumes from.
    blocked_frame: FrameSlot,
    /// Logical index of the CPU that last made this process current.
    ///
    /// M6b2 publishes it as [`BSP_CPU`], [`claim_next_on`] records the CPU that
    /// picked the process off its ready queue, and [`mark_running`] records the
    /// CPU that actually resumed it. [`wake_object`] enqueues the process on this
    /// CPU and raises its reschedule bit when the waking CPU differs.
    cpu: AtomicU8,
    /// CPUs this process may run on ([`DEFAULT_AFFINITY`] unless narrowed).
    affinity: AtomicU8,
    /// A decided migration whose statistics the target CPU still has to book.
    migration: Option<PendingMigration>,
    /// Linux64 signal state (M8c). The core never interprets it; the compat
    /// personality reads and writes it through [`with_current_signals`] and the
    /// `signal_*` entry points. Native processes carry a default state and
    /// never look at it.
    signals: SignalState,
    /// User TLS base (FS segment base) of this process, M8f.
    ///
    /// Stored here so context switches can restore it; the actual MSR is
    /// written by [`set_current_fs_base`] (arch_prctl SET_FS) and by
    /// `sched::activate_user_context` whenever this process is resumed.
    fs_base: u64,
    /// Userspace address that `set_tid_address` registered, M8f.
    ///
    /// On exit the kernel writes a zero `u32` there and wakes one futex
    /// waiter (Linux clear_child_tid semantics). `0` means "not set".
    clear_child_tid: u64,
}

impl Process {
    /// Number of occupied direct-child slots (M9c).
    fn child_count(&self) -> usize {
        self.children
            .iter()
            .filter(|raw| **raw != NO_PROCESS)
            .count()
    }

    /// First free direct-child slot, if the process can take another child.
    fn free_child_slot(&self) -> Option<usize> {
        if self.child_count() >= MAX_CHILDREN {
            return None;
        }
        self.children.iter().position(|raw| *raw == NO_PROCESS)
    }

    /// Slot index of `child` inside this process's child list.
    fn child_slot(&self, child: ProcessId) -> Option<usize> {
        let index = child.index() as u8;
        self.children.iter().position(|raw| *raw == index)
    }

    /// Publish `child` in the first free child slot.
    ///
    /// Callers validate `child_count() < MAX_CHILDREN` under the process lock
    /// first; the `debug_assert` keeps that contract explicit.
    fn add_child(&mut self, child: ProcessId) {
        let slot = self
            .free_child_slot()
            .expect("spawn validated a free child slot");
        debug_assert!(slot < MAX_CHILDREN);
        self.children[slot] = child.index() as u8;
    }

    /// Drop the link to `child` (no-op if it was already gone).
    fn remove_child(&mut self, child: ProcessId) {
        if let Some(slot) = self.child_slot(child) {
            self.children[slot] = NO_PROCESS;
        }
    }
}

// The process table is only ever touched by the kernel, either with interrupts
// disabled during a syscall or from the timer/exit paths. "Which process is on
// the CPU" is per-CPU (M6b2a): every CPU owns one slot of `CURRENTS` and only
// ever reads or writes its own, so those atomics need no lock. Everything else
// in the table is shared between CPUs and is protected by `PROCESS_LOCK`
// (M6b2b): whoever touches `PROCESSES` (states, saved frames, wait specs, the
// CPU a process last ran on, handle-table moves) must hold it.
//
// Lock order (M6b2b): process → object → vfs → pagecache → pmm. A holder of
// `PROCESS_LOCK` must never take a VFS/ipc lock, run an object destroy hook,
// allocate, print or switch stacks: those steps run after the guard is dropped.
static mut PROCESSES: [Option<Process>; MAX_PROCESSES] = [const { None }; MAX_PROCESSES];
static CURRENTS: [AtomicU8; crate::arch::MAX_CPUS] =
    [const { AtomicU8::new(NO_PROCESS) }; crate::arch::MAX_CPUS];

/// Per-CPU ready queues, one bit per process slot.
///
/// Bit `i` is set exactly while process `i` is `Ready` and waiting for that CPU
/// to pick it up. Every transition to `Ready` adds the bit, every claim/removal
/// clears it, and all of it happens under [`PROCESS_LOCK`] so two CPUs can never
/// claim the same process.
static mut READY_QUEUES: [u32; crate::arch::MAX_CPUS] = [0; crate::arch::MAX_CPUS];

/// CPUs with a pending reschedule request, one bit per CPU.
///
/// A wake that happens on another CPU sets the target CPU's bit; that CPU's
/// scheduler drains the mask and sends itself (or asks for) a reschedule IPI.
/// `sched` owns the IPI, this module only records the need.
static RESCHED_PENDING: AtomicU32 = AtomicU32::new(0);

/// Wakes that had to run on a different CPU than the waiter's owner (M6b2).
static REMOTE_WAKES: AtomicU64 = AtomicU64::new(0);
/// Migrations actually resumed on their target CPU (affinity reasons).
static MIGRATIONS: AtomicU64 = AtomicU64::new(0);
/// Rebalances actually resumed on their target CPU (load-balancing reasons).
static BALANCES: AtomicU64 = AtomicU64::new(0);

/// Host-test override for the number of online CPUs (0 = use `smp`).
#[cfg(test)]
static TEST_ONLINE_CPUS: AtomicU32 = AtomicU32::new(0);

/// CPUs available for scheduling right now.
///
/// The boot processor plus the APs `smp` brought online. Host tests have no AP,
/// so they override the value through [`test_set_online_cpus`].
fn online_cpu_count() -> usize {
    #[cfg(test)]
    {
        let forced = TEST_ONLINE_CPUS.load(Ordering::Relaxed) as usize;
        if forced != 0 {
            return forced.min(crate::arch::MAX_CPUS);
        }
    }
    (1 + crate::smp::online_count()).min(crate::arch::MAX_CPUS)
}

/// Override the online-CPU count in host tests (`0` restores the real value).
#[cfg(test)]
pub(crate) fn test_set_online_cpus(count: usize) {
    TEST_ONLINE_CPUS.store(count as u32, Ordering::Relaxed);
}

/// Whether `cpu` is a valid CPU index whose bit is set in `affinity`.
const fn affinity_allows(affinity: u8, cpu: u8) -> bool {
    (cpu as usize) < crate::arch::MAX_CPUS && affinity & (1u8 << cpu) != 0
}

/// First CPU allowed by `affinity` that is currently online.
fn first_online_affinity_cpu(affinity: u8) -> Option<u8> {
    let online = online_cpu_count();
    (0..online)
        .find(|cpu| affinity_allows(affinity, *cpu as u8))
        .map(|cpu| cpu as u8)
}

/// Initial CPU for a process created by [`spawn`].
///
/// `spawn` runs in the calling parent, so the child starts on the CPU that
/// issued the call — an AP-resident parent therefore gets a child that the same
/// AP can claim. Only when the creating CPU cannot host the child (an offline
/// CPU in a reduced `-smp` boot, or an affinity that excludes it) does the
/// placement fall back to the first online CPU the default affinity allows.
/// The boot processor therefore keeps landing on slot 0, exactly like the
/// [`register`] default.
fn initial_placement_cpu(creator: usize) -> u8 {
    let creator = creator.min(crate::arch::MAX_CPUS - 1);
    if creator < online_cpu_count() && affinity_allows(DEFAULT_AFFINITY, creator as u8) {
        creator as u8
    } else {
        first_online_affinity_cpu(DEFAULT_AFFINITY).unwrap_or(BSP_CPU)
    }
}

/// Move a freshly published `Ready` child to `target` as its initial placement.
///
/// Caller must hold [`PROCESS_LOCK`]. This is placement, not a migration: the
/// migration/balance counters stay untouched, and the move is a plain queue-bit
/// transfer (`register` publishes on the boot queue first). A target different
/// from the creating CPU gets a reschedule request; a same-CPU placement does
/// not send an IPI to itself.
fn place_initial_unlocked(index: usize, target: u8, creator: usize) {
    debug_assert!(
        PROCESS_LOCK.is_locked(),
        "place_initial_unlocked requires PROCESS_LOCK"
    );
    // A boot-processor spawn only moves the bit off and back onto the same
    // queue, leaving exactly the state `register` produced.
    let _ = queue_remove_unlocked(index);
    if let Some(process) = unsafe { process_ref(index) } {
        process.cpu.store(target, Ordering::Release);
    }
    queue_push_unlocked(index, target as usize);
    if target as usize != creator {
        request_resched_unlocked(target as usize);
    }
}

/// Pointer to one CPU's ready-queue bitmask (caller holds [`PROCESS_LOCK`]).
fn ready_queue_ptr(cpu: usize) -> *mut u32 {
    debug_assert!(cpu < crate::arch::MAX_CPUS);
    // SAFETY: `cpu` is in range and the caller holds the table lock.
    unsafe { core::ptr::addr_of_mut!(READY_QUEUES).cast::<u32>().add(cpu) }
}

/// Add `index` to the ready queue of `cpu` (caller holds [`PROCESS_LOCK`]).
fn queue_push_unlocked(index: usize, cpu: usize) {
    if cpu < crate::arch::MAX_CPUS {
        unsafe { *ready_queue_ptr(cpu) |= 1u32 << index };
    }
}

/// Remove `index` from every ready queue (caller holds [`PROCESS_LOCK`]).
fn queue_remove_unlocked(index: usize) -> Option<usize> {
    let bit = 1u32 << index;
    for cpu in 0..crate::arch::MAX_CPUS {
        let queue = ready_queue_ptr(cpu);
        if unsafe { *queue } & bit != 0 {
            unsafe { *queue &= !bit };
            return Some(cpu);
        }
    }
    None
}

/// Position of `index` in the ready queue of `cpu` (caller holds the lock).
fn queue_contains_unlocked(index: usize, cpu: usize) -> bool {
    cpu < crate::arch::MAX_CPUS && unsafe { *ready_queue_ptr(cpu) } & (1u32 << index) != 0
}

/// Number of processes queued on `cpu` (caller holds the lock).
fn queue_len_unlocked(cpu: usize) -> usize {
    if cpu < crate::arch::MAX_CPUS {
        (unsafe { *ready_queue_ptr(cpu) }).count_ones() as usize
    } else {
        0
    }
}

/// Mark `cpu` as needing a reschedule (caller holds the lock or accepts the
/// atomic store; the mask only grows, so a plain fetch_or is enough).
fn request_resched_unlocked(cpu: usize) {
    if cpu < crate::arch::MAX_CPUS {
        RESCHED_PENDING.fetch_or(1u32 << cpu, Ordering::Release);
    }
}

/// Protects [`PROCESSES`] and every read-modify-write of a process record.
///
/// `IrqSpinLock` keeps a same-CPU interrupt from re-entering a held section and
/// spins on another CPU. It is **not** reentrant: the internal `*_locked`
/// helpers document that they must only be called with the guard held, and
/// [`with_table`] asserts that the caller is not already inside one.
static PROCESS_LOCK: IrqSpinLock = IrqSpinLock::new();

// Test-only: set while this host thread is currently inside `with_table`.
//
// `IrqSpinLock` is not reentrant, so a nested acquisition on one thread would
// deadlock. `IrqSpinLock::is_locked` reports the *global* lock word, which a
// parallel host-test thread holding the same table also sets, so it cannot
// tell same-thread nesting from ordinary cross-thread contention. This
// thread-local marker distinguishes the two: only the owning thread sets it,
// so genuine nesting still fails loudly while another thread's legitimate
// hold is left to the real spin lock (SMP semantics, as on the target).
#[cfg(test)]
std::thread_local! {
    static TABLE_REENTRY: core::cell::Cell<bool> = const { core::cell::Cell::new(false) };
}

/// Test-only RAII marker cleared when [`with_table`] returns or unwinds.
#[cfg(test)]
struct TableReentryGuard;

#[cfg(test)]
impl Drop for TableReentryGuard {
    fn drop(&mut self) {
        TABLE_REENTRY.with(|marker| marker.set(false));
    }
}

/// Run `f` with the process table locked.
///
/// A nested acquisition on one thread would deadlock; in host tests the
/// thread-local marker turns that into an immediate, attributable failure.
/// A different thread holding the table (parallel host tests, or another CPU
/// on the target) is ordinary SMP contention and is not a failure: it spins on
/// [`PROCESS_LOCK`] exactly like production code does.
#[inline]
fn with_table<R>(f: impl FnOnce() -> R) -> R {
    #[cfg(test)]
    {
        TABLE_REENTRY.with(|marker| {
            debug_assert!(!marker.get(), "process table lock taken twice on one CPU");
            marker.set(true);
        });
        let _reentry = TableReentryGuard;
        PROCESS_LOCK.with(f)
    }
    #[cfg(not(test))]
    {
        PROCESS_LOCK.with(f)
    }
}

/// Whether the process table lock is currently held (diagnostics and tests).
pub fn process_lock_is_held() -> bool {
    PROCESS_LOCK.is_locked()
}

// Compile-time geometry checks (Lead m00445 asked for boundary assertions).
const _: () = {
    assert!(KERNEL_STACK_BYTES == 32768);
    assert!(FRAME_BYTES == 176);
    assert!(KERNEL_STACK_TOP_RESERVED == 8);
    assert!(KERNEL_STACK_BASES[0] % 16 == 0);
    assert!(KERNEL_STACK_BASES[1] % 16 == 0);
    assert!(KERNEL_STACK_BASES[2] % 16 == 0);
    assert!(KERNEL_STACK_BASES[1] > KERNEL_STACK_BASES[0] + KERNEL_STACK_BYTES);
    assert!(KERNEL_STACK_BASES[2] > KERNEL_STACK_BASES[1] + KERNEL_STACK_BYTES);
    // Guard page of process 1 sits below its base and must stay unmapped.
    assert!(KERNEL_STACK_BASES[1] - pmm::FRAME_SIZE >= KERNEL_STACK_BASES[0] + KERNEL_STACK_BYTES);
    // Same for the third slot: its guard page must not overlap slot 1's frames.
    assert!(KERNEL_STACK_BASES[2] - pmm::FRAME_SIZE >= KERNEL_STACK_BASES[1] + KERNEL_STACK_BYTES);
    // All stacks stay below the 0xffffffff82000000 platform window.
    assert!(KERNEL_STACK_BASES[2] + KERNEL_STACK_BYTES <= 0xFFFF_FFFF_8200_0000);
    // The third slot must stay below the per-CPU AP stacks (`vm::AP_STACK_BASE`,
    // 0xffffffff81800000): both share PD slot 11's page table, so the PT the AP
    // stacks would need stays untouched.
    assert!(KERNEL_STACK_BASES[2] + KERNEL_STACK_BYTES <= 0xFFFF_FFFF_8180_0000);
    // The stacks must be exactly the frozen 815/816 windows plus the new 817 slot.
    assert!(KERNEL_STACK_BASES[0] == 0xFFFF_FFFF_8150_0000);
    assert!(KERNEL_STACK_BASES[1] == 0xFFFF_FFFF_8160_0000);
    assert!(KERNEL_STACK_BASES[2] == 0xFFFF_FFFF_8170_0000);
    // The fourth (M9c) slot reuses the free 812 window between the boot stack
    // (frames end at 8100_4000) and the M3 scheduler stack A (8130_0000); its
    // guard page sits at 811F_F000, inside the same PD window and still free.
    assert!(KERNEL_STACK_BASES[3] % 16 == 0);
    assert!(KERNEL_STACK_BASES[3] == 0xFFFF_FFFF_8120_0000);
    assert!(KERNEL_STACK_BASES[3] + KERNEL_STACK_BYTES <= 0xFFFF_FFFF_8130_0000);
    assert!(KERNEL_STACK_BASES[3] - pmm::FRAME_SIZE >= 0xFFFF_FFFF_8100_4000);
};

/// Kernel stack top of process `index`.
pub const fn kernel_stack_top(index: usize) -> u64 {
    KERNEL_STACK_BASES[index] + KERNEL_STACK_BYTES
}

/// Address of the synthetic ring-3 `TrapFrame` for a kernel stack top.
///
/// Leaves `KERNEL_STACK_TOP_RESERVED` bytes at the top for the canary and for
/// `TSS.rsp0`, then keeps the 16-byte alignment the hardware imposes.
///
/// A ring3 -> ring0 interrupt does **not** start pushing at `RSP0` itself: in
/// 64-bit mode the CPU first aligns the new stack pointer down to a 16-byte
/// boundary and only then pushes `SS`/`RSP`/`RFLAGS`/`CS`/`RIP` (40 bytes). The
/// stub adds 136 more, so the hardware frame ends at `align16(RSP0)` and starts
/// `40 + 136` bytes below it. With `RSP0 = top - 8` and a 16-byte aligned top
/// that is `top - 16 - 176 = top - 192`.
///
/// M4 hardware evidence (first user tick): `TSS.RSP0` read back as `top - 8`,
/// yet the pushed `SS` sat at `top - 16` and the trap frame at `top - 192`.
/// The first synthetic frame is placed at exactly that address, so the first
/// real timer interrupt lands on the same frame the process was resumed from.
pub const fn first_frame_addr(top: u64) -> u64 {
    ((top - KERNEL_STACK_TOP_RESERVED) & !0xF) - FRAME_BYTES
}

// ---------------------------------------------------------------------------
// Pure policy helpers (host tested; no hardware access)
// ---------------------------------------------------------------------------

/// Round-robin selection over a snapshot of process states.
///
/// `states[i]` is a [`ProcessState`] discriminant; `from` is the process that
/// just left the CPU. Zombie and Running processes are never selected.
fn choose_next_state(states: &[u8], from: Option<usize>) -> Option<usize> {
    let count = states.len();
    if count == 0 {
        return None;
    }
    let start = match from {
        Some(index) => (index + 1) % count,
        None => 0,
    };
    for step in 0..count {
        let index = (start + step) % count;
        if states[index] == ProcessState::Ready.as_u8() {
            return Some(index);
        }
    }
    None
}

/// Decide what a `wait` on a child in `state` must do.
fn wait_decision(state: u8, status: u64) -> WaitDecision {
    if state == ProcessState::Zombie.as_u8() {
        WaitDecision::Exited(status)
    } else {
        WaitDecision::Blocked
    }
}

/// Rights may only be narrowed when a handle is copied into a child.
fn rights_fit_in(requested: Rights, available: Rights) -> bool {
    available.contains(requested)
}

/// Decide whether a blocked process must be made runnable by `trigger`.
///
/// Pure state transition input: only `Blocked` waiters qualify, a recorded
/// reason wins over any later wake (first reason is sticky until consumed), and
/// the trigger must match the wait spec. Returns the reason to record.
fn wake_decision(
    state: u8,
    reason: WakeReason,
    wait: &WaitSpec,
    trigger: WakeTrigger,
) -> Option<WakeReason> {
    if state != ProcessState::Blocked.as_u8() {
        return None;
    }
    if reason.is_some() {
        // Duplicate/racing wake: never overwrite the first recorded reason.
        return None;
    }
    if trigger.matches(wait) {
        Some(trigger.reason())
    } else {
        None
    }
}

/// Copy a process's private `syscall` frame out of its kernel stack and rewrite
/// it to replay the two-byte `syscall` instruction on resume.
///
/// The woken process re-executes the syscall from user mode with the same
/// number and arguments (all GPRs, `rip`, `rflags`, `user_rsp` and `user_ss` are
/// preserved; only `rip` moves back by two bytes), so the syscall handler can
/// re-evaluate its condition instead of resuming a half-finished kernel call.
///
/// # Safety
///
/// `src` must be the process's `syscall_frame_addr(top)` frame and `slot` must
/// point at 22 writable qwords (8-byte aligned).
unsafe fn copy_blocked_frame(src: *mut TrapFrame, slot: *mut TrapFrame) {
    unsafe {
        core::ptr::copy_nonoverlapping(src as *const u64, slot as *mut u64, FRAME_QWORDS);
        (*slot).rip = (*slot).rip.wrapping_sub(NATIVE_SYSCALL_BYTES);
    }
}

// ---------------------------------------------------------------------------
// Process table accessors
// ---------------------------------------------------------------------------

unsafe fn slot_ptr(index: usize) -> *mut Option<Process> {
    debug_assert!(index < MAX_PROCESSES);
    debug_assert!(
        PROCESS_LOCK.is_locked(),
        "process table accessed without PROCESS_LOCK"
    );
    // SAFETY: caller guarantees `index < MAX_PROCESSES`; `addr_of_mut!` avoids
    // creating a reference to the whole static.
    unsafe {
        core::ptr::addr_of_mut!(PROCESSES)
            .cast::<Option<Process>>()
            .add(index)
    }
}

/// Raw pointer to a live process record. Caller must hold [`PROCESS_LOCK`].
unsafe fn process_ptr(index: usize) -> *mut Process {
    let slot = unsafe { slot_ptr(index) };
    match unsafe { &mut *slot } {
        Some(process) => process as *mut Process,
        None => core::ptr::null_mut(),
    }
}

/// Borrow a live process record. Caller must hold [`PROCESS_LOCK`].
///
/// # Safety
///
/// The returned reference is tied to the table lock discipline, not to the
/// borrow checker: the caller must not keep it past the guard (no await/yield,
/// no context switch) and must not hold another one for the same index.
unsafe fn process_ref(index: usize) -> Option<&'static mut Process> {
    let pointer = unsafe { process_ptr(index) };
    if pointer.is_null() {
        None
    } else {
        // SAFETY: every caller holds `PROCESS_LOCK`, so no other CPU can mutate
        // the record concurrently; a reaped slot is checked through the pointer.
        Some(unsafe { &mut *pointer })
    }
}

/// Slot index if it holds a live process. Caller must hold [`PROCESS_LOCK`].
fn live_index(index: usize) -> Option<usize> {
    if index < MAX_PROCESSES && unsafe { !process_ptr(index).is_null() } {
        Some(index)
    } else {
        None
    }
}

/// Iterate over live process slots. Caller must hold [`PROCESS_LOCK`].
fn for_each_live(mut f: impl FnMut(usize, &'static mut Process)) {
    for index in 0..MAX_PROCESSES {
        if let Some(process) = unsafe { process_ref(index) } {
            f(index, process);
        }
    }
}

// ---------------------------------------------------------------------------
// Public API: creation
// ---------------------------------------------------------------------------

/// Create the first user process (`init`) from the `init` boot module.
///
/// The process starts with two handles, in this order (frozen by w6):
/// Console (`READ|WRITE`, raw `0x0001_0001`) and Random (`READ`, raw
/// `0x0001_0002`). The first ring-3 frame receives those two raw handle values
/// in `rdi` / `rsi`; `rdx` is the third entry argument (frozen by native ABI)
/// and is zero here because init has no third initial handle.
///
/// Failure contract: an error returned after `image::load_module` succeeded
/// releases the loaded address space and every handle acquired so far, so no
/// mapping, frame or object survives a failed spawn.
pub fn spawn_init() -> Result<ProcessId, ProcessError> {
    let loaded = image::load_module(b"init").map_err(|_| ProcessError::Image)?;
    let mut handles = HandleTable::new();
    let args = match init_entry_args(&mut handles) {
        Ok(args) => args,
        Err(error) => {
            // Nothing has been published: undo the handles and the image.
            if let Err(vm_error) = unsafe {
                discard_unregistered(
                    0,
                    loaded.address_space,
                    &mut handles,
                    &[0; KERNEL_STACK_FRAMES as usize],
                    0,
                    None,
                )
            } {
                return Err(ProcessError::AddressSpace(vm_error));
            }
            return Err(error);
        }
    };
    // `register` takes ownership of both the address space and the table; its
    // own failure paths release them, so nothing is released twice here.
    unsafe {
        register(
            None,
            loaded.address_space,
            loaded.entry,
            loaded.user_stack,
            handles,
            args,
            None,
        )
    }
}

/// Insert the two initial handles and return their raw values as entry args.
///
/// The third entry argument (`rdx`) is always zero for init: init owns exactly
/// these two handles, while a child's third slot arrives from `transfers`.
fn init_entry_args(handles: &mut HandleTable) -> Result<[u64; 3], ProcessError> {
    let console = object::insert_new(handles, ObjectKind::Console, Rights::READ | Rights::WRITE)
        .map_err(ProcessError::Objects)?;
    let random = object::insert_new(handles, ObjectKind::Random, Rights::READ)
        .map_err(ProcessError::Objects)?;
    Ok([console.raw() as u64, random.raw() as u64, 0])
}

/// Create the M4 child process of `parent`.
///
/// Only the handles listed in `transfers` are copied into the child, in the
/// listed order (child slot 0 first, generation 1), with narrowed rights. The
/// parent keeps its own handles. Returns the child id plus the parent-side
/// `Process` handle with `WAIT` rights, which is what `wait` consumes.
///
/// The child is initially placed on the **creating CPU** ([`current_cpu`]) so a
/// child of an AP-resident parent can be claimed by that AP; the boot processor
/// keeps publishing onto its own queue exactly as [`register`] does.
pub fn spawn(
    parent: ProcessId,
    name: &[u8],
    transfers: &[HandleTransfer],
) -> Result<(ProcessId, u32), ProcessError> {
    let parent_index = parent.index();
    // Validate the parent and its remaining child capacity under the table lock;
    // the (long) image load below runs outside it.
    with_table(|| {
        let parent_process =
            unsafe { process_ref(parent_index) }.ok_or(ProcessError::NoSuchProcess)?;
        if parent_process.state == ProcessState::Zombie {
            return Err(ProcessError::NoSuchProcess);
        }
        // M9c allows up to two direct children; a third spawn is rejected
        // instead of silently overwriting a link.
        // M9c allows up to two direct children; a third spawn is rejected
        // instead of silently overwriting a link.
        let child_count = (0..MAX_PROCESSES)
            .filter(|index| {
                unsafe { process_ref(*index) }
                    .map(|process| process.parent == Some(parent))
                    .unwrap_or(false)
            })
            .count();
        if child_count >= MAX_CHILDREN {
            return Err(ProcessError::ChildExists);
        }
        Ok(())
    })?;

    let loaded = image::load_module(name).map_err(|_| ProcessError::Image)?;

    // Copy the explicitly listed handles. Rights are pre-validated so a bad
    // transfer cannot leave a half-populated child table behind; any error in
    // this phase releases the image address space and the partial table.
    //
    // The copy runs under the table lock but only touches object-table metadata
    // (resolve/duplicate acquire references; nothing runs a destroy hook), which
    // is the documented `process -> object` order.
    let mut child_handles = HandleTable::new();
    let args = match with_table(|| {
        let parent_process = match unsafe { process_ref(parent_index) } {
            Some(process) => process,
            None => return Err(ProcessError::NoSuchProcess),
        };
        // The transfer reads and grows the parent table; refuse while a
        // `CurrentHandlesGuard` owns the real one (the slot then only holds an
        // empty placeholder, which must never be used for a transfer).
        if parent_process.handles_taken {
            return Err(ProcessError::BadRequest);
        }
        build_child_handles(&mut parent_process.handles, transfers, &mut child_handles)
    }) {
        Ok(args) => args,
        Err(error) => {
            if let Err(vm_error) = unsafe {
                discard_unregistered(
                    0,
                    loaded.address_space,
                    &mut child_handles,
                    &[0; KERNEL_STACK_FRAMES as usize],
                    0,
                    None,
                )
            } {
                return Err(ProcessError::AddressSpace(vm_error));
            }
            return Err(error);
        }
    };

    // `register` owns the address space and the child table from here on: when
    // it fails it releases both, so the error path below must not free them.
    let child = match unsafe {
        register(
            Some(parent),
            loaded.address_space,
            loaded.entry,
            loaded.user_stack,
            child_handles,
            args,
            None,
        )
    } {
        Ok(child) => child,
        Err(error) => return Err(error),
    };

    // The child is registered but not yet reachable: it is `Ready` and cannot be
    // scheduled, so every failure below must take the slot back and release
    // everything it owns before returning.
    let process_object = match object::create_process_object() {
        Ok(object) => object,
        Err(error) => {
            unsafe { rollback_registration(child.index()) };
            return Err(ProcessError::Objects(error));
        }
    };

    // Initial placement target: the CPU running this `spawn` call. The child has
    // to be claimable there — an AP parent's child left on the boot queue would
    // never run while the boot processor only idles in a monitor loop (M7b).
    let creator = current_cpu();

    // Link phase: insert the parent WAIT handle and publish the child fields
    // under one short table lock. On failure the lock is released before the
    // object is destroyed and the registration rolled back, so no object-table
    // or cleanup work runs while the process lock is held.
    let linked = with_table(|| -> Result<Handle, Option<object::ObjectError>> {
        let parent_process = match unsafe { process_ref(parent_index) } {
            Some(process) => process,
            None => return Err(None),
        };
        // Inserting the WAIT handle needs the real parent table; a guard owning
        // it would make the insert land in an empty placeholder.
        debug_assert!(
            !parent_process.handles_taken,
            "spawn while the parent handle table is owned by a guard"
        );
        let wait_handle =
            object::insert_handle(&mut parent_process.handles, process_object, Rights::WAIT)
                .map_err(Some)?;
        // Cannot fail while this call owns the slot; keep the contract total.
        let child_process = match unsafe { process_ref(child.index()) } {
            Some(process) => process,
            None => return Err(None),
        };
        child_process.process_object = process_object;
        child_process.wait_handle = wait_handle;
        parent_process.add_child(child);
        // Last step of the link phase: queue the child where the caller runs.
        // Everything fallible is done above, so a failed link never leaves a
        // placed child behind.
        let target = initial_placement_cpu(creator);
        place_initial_unlocked(child.index(), target, creator);
        Ok(wait_handle)
    });
    match linked {
        Ok(wait_handle) => Ok((child, wait_handle.raw())),
        Err(reason) => {
            // The object exists but has no reference yet: `close` would be the
            // wrong primitive, so destroy the zero-reference entry directly.
            let _ = object::destroy_object(process_object);
            unsafe { rollback_registration(child.index()) };
            match reason {
                Some(error) => Err(ProcessError::Objects(error)),
                None => Err(ProcessError::NoSuchProcess),
            }
        }
    }
}

/// Copy the requested handles from `parent` into `child` and return the child
/// entry arguments (the first three child handle values, for `rdi` / `rsi` /
/// `rdx`; slots the request does not fill are zero).
///
/// The pre-validation pass rejects a request that lists the same source handle
/// more than once: two `duplicate` calls on one source produce two handles whose
/// closes would both release the single reference that was acquired, so closing
/// either could free an object the other still names. M4 keeps the minimal safe
/// rule and refuses such a request before any address space or duplicate exists.
///
/// The same pass refuses handle kinds a child must not own: `VmObject` and
/// `Watch`, both reported as [`ProcessError::BadRequest`]. A `VmObject` payload
/// names its creator's address space and mapping, so after the creator is reaped
/// or its slot is reused a child closing that handle could unmap somebody else's
/// mapping; a `Watch` payload names its owner the same way. Both are rejected
/// before any reference is acquired, so a refused request leaves the parent
/// table exactly as it was.
///
/// On error `child` may be partially populated; the caller owns the cleanup
/// (see [`discard_unregistered`]).
fn build_child_handles(
    parent: &mut HandleTable,
    transfers: &[HandleTransfer],
    child: &mut HandleTable,
) -> Result<[u64; 3], ProcessError> {
    for (position, transfer) in transfers.iter().enumerate() {
        if transfers[..position]
            .iter()
            .any(|earlier| earlier.handle.raw() == transfer.handle.raw())
        {
            return Err(ProcessError::BadRequest);
        }
        let resolved = object::resolve_handle(&*parent, transfer.handle, Rights::NONE)
            .map_err(ProcessError::Objects)?;
        // Handles whose payload names a creator-owned resource (a VmObject's
        // address space/mapping, a Watch's owner) must not cross the process
        // boundary. Refuse before `duplicate_handle` so no reference is taken.
        if matches!(resolved.kind, ObjectKind::VmObject | ObjectKind::Watch) {
            return Err(ProcessError::BadRequest);
        }
        if !rights_fit_in(transfer.rights, resolved.rights) {
            return Err(ProcessError::RightsEscalation);
        }
    }
    for transfer in transfers {
        object::duplicate_handle(&mut *parent, &mut *child, transfer.handle, transfer.rights)
            .map_err(ProcessError::Objects)?;
    }
    Ok(child_entry_args(child))
}

/// Create the child of the currently running process (syscall entry point).
pub fn spawn_from_current(
    name: &[u8],
    transfers: &[HandleTransfer],
) -> Result<Handle, ProcessError> {
    let parent = current().ok_or(ProcessError::NoSuchProcess)?;
    spawn(parent, name, transfers).map(|(_child, raw)| Handle::from_raw(raw))
}

/// Number of initial handles a detached process can receive (M6c `gfx`).
///
/// Three is the frozen native entry ABI: the raw handle values travel in
/// `rdi` / `rsi` / `rdx`, exactly like a child spawned through
/// [`spawn`] with three transfers.
pub const DETACHED_HANDLE_SLOTS: usize = 3;

/// Validate and materialise the initial handle table of a detached process.
///
/// `objects[..count]` are inserted as slots `0..count`, in order, with exactly
/// the requested rights: the raw values returned are the real generation-encoded
/// handles the user entry receives in `rdi` / `rsi` / `rdx`, and they are slots
/// 0, 1 and 2 of a fresh table.
///
/// Every entry is validated **before** a single reference is taken:
///
/// - the object must be live ([`object::object_kind`]);
/// - `VmObject` and `Watch` are refused like child transfers
///   ([`build_child_handles`]): their payload names a creator-owned mapping or
///   watch owner, so they cannot cross into a process without handle provenance;
/// - rights must be non-empty and a subset of the object kind's creation bound
///   ([`object::check_initial_rights`]), so this path can never widen the rights
///   the object was created with. `insert_handle` itself does not enforce that
///   bound, which is why it is checked here.
///
/// A failure while inserting (table full, object concurrently gone) clears the
/// table so every reference taken so far is released before returning.
fn prepare_detached_handles(
    table: &mut HandleTable,
    objects: &[(ObjectId, Rights); DETACHED_HANDLE_SLOTS],
    count: usize,
) -> Result<[u64; DETACHED_HANDLE_SLOTS], ProcessError> {
    debug_assert!(count <= DETACHED_HANDLE_SLOTS);
    for (object, rights) in &objects[..count] {
        let kind = object::object_kind(*object)
            .ok_or(ProcessError::Objects(ObjectError::InvalidObject))?;
        if matches!(kind, ObjectKind::VmObject | ObjectKind::Watch) {
            return Err(ProcessError::BadRequest);
        }
        object::check_initial_rights(kind, *rights).map_err(ProcessError::Objects)?;
    }
    let mut args = [0u64; DETACHED_HANDLE_SLOTS];
    for (slot, (object, rights)) in objects[..count].iter().enumerate() {
        match object::insert_handle(table, *object, *rights) {
            Ok(handle) => args[slot] = u64::from(handle.raw()),
            Err(error) => {
                let _ = object::clear_handle_table(table);
                return Err(ProcessError::Objects(error));
            }
        }
    }
    Ok(args)
}

/// Shared loader behind [`spawn_detached`] and [`spawn_detached_with_handles`].
///
/// `initial[..count]` become the process's initial handles (see
/// [`prepare_detached_handles`]); `spawn_detached` passes `count == 0`.
fn spawn_detached_inner(
    name: &str,
    affinity: u8,
    initial: &[(ObjectId, Rights); DETACHED_HANDLE_SLOTS],
    count: usize,
) -> Result<(ProcessId, [u32; DETACHED_HANDLE_SLOTS]), ProcessError> {
    if affinity == 0 || affinity & !CPU_MASK_ALL != 0 {
        return Err(ProcessError::BadRequest);
    }
    let mut handles = HandleTable::new();
    let args = prepare_detached_handles(&mut handles, initial, count)?;
    let loaded = match image::load_module(name.as_bytes()) {
        Ok(loaded) => loaded,
        Err(_) => {
            // The image never loaded: release the references the table holds.
            let _ = object::clear_handle_table(&mut handles);
            return Err(ProcessError::Image);
        }
    };
    // `register` owns the address space/table from here on; on failure it has
    // already released both. The image never loaded: release the references the
    // table holds.
    let child = unsafe {
        register(
            None,
            loaded.address_space,
            loaded.entry,
            loaded.user_stack,
            handles,
            args,
            None,
        )
    }?;

    // Record the affinity and move the freshly published `Ready` process from
    // the boot queue to the CPU it should start on (initial placement is not a
    // migration and is never counted in `migration_stats`).
    link_detached(child, affinity)?;
    Ok((child, [args[0] as u32, args[1] as u32, args[2] as u32]))
}

/// Link a freshly registered detached child (M6b2/M7d).
///
/// Creates the child's own `Process` object, records the requested affinity and
/// moves the `Ready` process from the boot queue to the first CPU it may run on
/// (raising a reschedule IPI when that is not the current CPU). On failure the
/// object is destroyed and the registration is rolled back, so the caller's
/// process slot is free again.
fn link_detached(child: ProcessId, affinity: u8) -> Result<(), ProcessError> {
    let process_object = match object::create_process_object() {
        Ok(object) => object,
        Err(error) => {
            unsafe { rollback_registration(child.index()) };
            return Err(ProcessError::Objects(error));
        }
    };

    let linked = with_table(|| {
        let Some(process) = (unsafe { process_ref(child.index()) }) else {
            return Err(());
        };
        process.process_object = process_object;
        process.affinity.store(affinity, Ordering::Release);
        let target = first_online_affinity_cpu(affinity).unwrap_or(BSP_CPU);
        queue_remove_unlocked(child.index());
        process.cpu.store(target, Ordering::Release);
        queue_push_unlocked(child.index(), target as usize);
        if target as usize != current_cpu() {
            request_resched_unlocked(target as usize);
        }
        Ok(())
    });
    match linked {
        Ok(()) => Ok(()),
        Err(()) => {
            // The object still has no reference: destroy it directly, then take
            // the registration back.
            let _ = object::destroy_object(process_object);
            unsafe { rollback_registration(child.index()) };
            Err(ProcessError::NoSuchProcess)
        }
    }
}

/// Spawn a detached (parentless) process for the M6b2 SMP self-test.
///
/// Shares the unified image/address-space/kernel-stack loading with
/// [`spawn`], but has **no** parent link, **no** initial handles and **no** wait
/// handle: nobody can `wait` for it, and its zombie is reclaimed by
/// [`reap_orphans`]. `affinity` must be a non-zero subset of [`CPU_MASK_ALL`];
/// the process is queued on the first online CPU it is allowed to run on, so a
/// worker can be started directly on an AP.
pub fn spawn_detached(name: &str, affinity: u8) -> Result<ProcessId, ProcessError> {
    spawn_detached_inner(
        name,
        affinity,
        &[(ObjectId::MAX, Rights::NONE); DETACHED_HANDLE_SLOTS],
        0,
    )
    .map(|(child, _args)| child)
}

/// Spawn a detached process that starts with three initial handles (M6c `gfx`).
///
/// Same loader, address space, kernel stack and orphan reaping as
/// [`spawn_detached`], but `handles` are inserted as slots 0, 1 and 2 with
/// exactly the requested (reduced) rights, and the raw handle values are
/// returned in the same order *and* written into the entry registers
/// `rdi` / `rsi` / `rdx`. A failure at any step (bad object, rejected rights,
/// image load, slot/stack allocation, process object) releases every reference
/// taken, the address space, the kernel stack and the process slot.
pub fn spawn_detached_with_handles(
    name: &str,
    affinity: u8,
    handles: [(ObjectId, Rights); DETACHED_HANDLE_SLOTS],
) -> Result<(ProcessId, [u32; DETACHED_HANDLE_SLOTS]), ProcessError> {
    spawn_detached_inner(name, affinity, &handles, DETACHED_HANDLE_SLOTS)
}

/// Spawn a detached process with a `Linux64` personality (M7d).
///
/// The child starts from `name` (the same boot-module ELF loader as the native
/// paths), owns fds 0/1/2 pointing at `console`, and receives the optional
/// `channel` and `netns` handles as native slots 0 and 1. Their raw values are
/// written into the initial stack auxv entries `AT_CAELUM_CHANNEL` and
/// `AT_CAELUM_NETNS` (0 means `HANDLE_NONE`); `netns` is also recorded so
/// [`current_linux_netns`] can answer for Linux syscalls. The initial user `rsp`
/// points at the encoded auxiliary vector / argument block.
///
/// `affinity` must be a non-zero subset of [`CPU_MASK_ALL`]. Every failure path
/// releases the fds, native handles, image, address space, kernel stack and
/// process slot; on success the caller owns none of them.
pub fn spawn_detached_linux(
    name: &str,
    affinity: u8,
    console: ObjectId,
    channel: Option<(ObjectId, Rights)>,
    netns: Option<(ObjectId, Rights)>,
) -> Result<ProcessId, ProcessError> {
    if affinity == 0 || affinity & !CPU_MASK_ALL != 0 {
        return Err(ProcessError::BadRequest);
    }
    if object::object_kind(console) != Some(ObjectKind::Console) {
        return Err(ProcessError::Objects(ObjectError::InvalidObject));
    }
    if let Some((object, _)) = netns {
        if object::object_kind(object) != Some(ObjectKind::NetNamespace) {
            return Err(ProcessError::Objects(ObjectError::InvalidObject));
        }
    }

    // Native handle table of the child: channel first (slot 0), then the network
    // namespace (slot 1), matching the raw values written into the auxv.
    let mut handles = HandleTable::new();
    let mut channel_raw = 0u32;
    let mut netns_raw = 0u32;
    let mut netns_handle = None;
    if let Some((object, rights)) = channel {
        match object::insert_handle(&mut handles, object, rights) {
            Ok(handle) => channel_raw = u32::from(handle.raw()),
            Err(error) => {
                let _ = object::clear_handle_table(&mut handles);
                return Err(ProcessError::Objects(error));
            }
        }
    }
    if let Some((object, rights)) = netns {
        match object::insert_handle(&mut handles, object, rights) {
            Ok(handle) => {
                netns_raw = u32::from(handle.raw());
                netns_handle = Some(handle);
            }
            Err(error) => {
                let _ = object::clear_handle_table(&mut handles);
                return Err(ProcessError::Objects(error));
            }
        }
    }

    // Install the console into fds 0/1/2 before registration; on any failure the
    // table is cleared and the fd references released.
    let mut fds = FdTable::new();
    if fds.install_console(console).is_err() {
        let _ = object::clear_handle_table(&mut handles);
        let _ = release_all_fds(&mut fds);
        return Err(ProcessError::Objects(ObjectError::InvalidObject));
    }

    let loaded = match image::load_module(name.as_bytes()) {
        Ok(loaded) => loaded,
        Err(_) => {
            let _ = object::clear_handle_table(&mut handles);
            let _ = release_all_fds(&mut fds);
            return Err(ProcessError::Image);
        }
    };

    // M8a: the Linux personality's initial `brk` is the real end of the loaded
    // image (`image_end`, page-aligned and including bss). The image loader is
    // the only source of this address; the compat layer never guesses it. The
    // native personality has no program break, so only this path records one.
    fds.set_program_break(loaded.image_end);

    let mut stack_image = [0u8; linux_stack::INITIAL_STACK_BYTES];
    let written = match linux_stack::encode_initial_stack(&mut stack_image, channel_raw, netns_raw)
    {
        Ok(written) => written,
        Err(_) => {
            let _ = object::clear_handle_table(&mut handles);
            let _ = release_all_fds(&mut fds);
            return Err(ProcessError::BadRequest);
        }
    };
    let rsp = (loaded.user_stack - written as u64) & !0xF;
    if let Err(error) = addrspace::copy_out(loaded.address_space, rsp, &stack_image[..written]) {
        let _ = object::clear_handle_table(&mut handles);
        let _ = release_all_fds(&mut fds);
        return Err(ProcessError::Map(error));
    }

    let extras = ProcessExtras {
        personality: Personality::Linux64,
        fds,
        linux_netns: netns_handle,
    };
    // `register_with` owns the address space, the handle table and the extras;
    // on failure it has already released all three.
    let child = unsafe {
        register_with(
            None,
            loaded.address_space,
            loaded.entry,
            rsp,
            handles,
            [0, 0, 0],
            None,
            extras,
        )
    }?;

    link_detached(child, affinity)?;
    Ok(child)
}

/// Spawn the M9d1 dynamic-linker closure as a detached `Linux64` process.
///
/// `main_path` must be [`image::DYNAMIC_MAIN_PATH`]. The image loader stages the
/// main `ET_DYN` image and the interpreter named by its `PT_INTERP`, maps both
/// into one new address space and returns the **interpreter** entry as the ring-3
/// entry point. The initial stack carries the main image's real
/// `AT_PHDR`/`AT_PHENT`/`AT_PHNUM`/`AT_ENTRY` values so the interpreter can
/// relocate the main program and hand over to it.
///
/// No native handles are installed and no program break is recorded: this is a
/// startup verification process, not a socket service.
pub fn spawn_detached_linux_dynamic(
    main_path: &[u8],
    affinity: u8,
    console: ObjectId,
) -> Result<ProcessId, ProcessError> {
    if affinity == 0 || affinity & !CPU_MASK_ALL != 0 {
        return Err(ProcessError::BadRequest);
    }
    if object::object_kind(console) != Some(ObjectKind::Console) {
        return Err(ProcessError::Objects(ObjectError::InvalidObject));
    }

    let mut handles = HandleTable::new();
    let mut fds = FdTable::new();
    if fds.install_console(console).is_err() {
        let _ = object::clear_handle_table(&mut handles);
        let _ = release_all_fds(&mut fds);
        return Err(ProcessError::Objects(ObjectError::InvalidObject));
    }

    let loaded = match image::load_dynamic(main_path) {
        Ok(loaded) => loaded,
        Err(_) => {
            let _ = object::clear_handle_table(&mut handles);
            let _ = release_all_fds(&mut fds);
            return Err(ProcessError::Image);
        }
    };

    // M9d1/M9d2: the interpreter reads these from `rsp`; `AT_ENTRY` is the
    // *main* program's biased entry, `loaded.entry` is the interpreter's entry
    // and `AT_SYSINFO_EHDR` points at the mapped vDSO image.
    let mut stack_image = [0u8; linux_stack::DYNAMIC_STACK_BYTES];
    let written = match linux_stack::encode_dynamic_stack(
        &mut stack_image,
        loaded.phdr,
        loaded.phent,
        loaded.phnum,
        loaded.main_entry,
        crate::vdso::VDSO_BASE,
    ) {
        Ok(written) => written,
        Err(_) => {
            let _ = object::clear_handle_table(&mut handles);
            let _ = release_all_fds(&mut fds);
            return Err(ProcessError::BadRequest);
        }
    };
    let rsp = (loaded.user_stack - written as u64) & !0xF;
    if let Err(error) = addrspace::copy_out(loaded.address_space, rsp, &stack_image[..written]) {
        let _ = object::clear_handle_table(&mut handles);
        let _ = release_all_fds(&mut fds);
        return Err(ProcessError::Map(error));
    }

    let extras = ProcessExtras {
        personality: Personality::Linux64,
        fds,
        linux_netns: None,
    };
    let child = unsafe {
        register_with(
            None,
            loaded.address_space,
            loaded.entry,
            rsp,
            handles,
            [0, 0, 0],
            None,
            extras,
        )
    }?;

    link_detached(child, affinity)?;
    Ok(child)
}
/// M10a: spawn a real dynamically linked Linux program by VFS path.
///
/// The main image and the interpreter named by its `PT_INTERP` are loaded by
/// [`image::load_program`]; the initial stack carries argv, the full auxv
/// (including `AT_RANDOM` from the secure RNG and a non-zero `AT_BASE`), and
/// the program path (`AT_EXECFN`). The child is detached so the caller can wait
/// on its exit state exactly like the other detached Linux workers.
pub fn spawn_detached_linux_program(
    main_path: &[u8],
    interpreter_path: &[u8],
    argv: &[&[u8]],
    affinity: u8,
    console: ObjectId,
) -> Result<ProcessId, ProcessError> {
    if affinity == 0 || affinity & !CPU_MASK_ALL != 0 {
        return Err(ProcessError::BadRequest);
    }
    if object::object_kind(console) != Some(ObjectKind::Console) {
        return Err(ProcessError::Objects(ObjectError::InvalidObject));
    }

    let mut handles = HandleTable::new();
    let mut fds = FdTable::new();
    if fds.install_console(console).is_err() {
        let _ = object::clear_handle_table(&mut handles);
        let _ = release_all_fds(&mut fds);
        return Err(ProcessError::Objects(ObjectError::InvalidObject));
    }

    let loaded = match image::load_program(main_path, interpreter_path) {
        Ok(loaded) => loaded,
        Err(_) => {
            let _ = object::clear_handle_table(&mut handles);
            let _ = release_all_fds(&mut fds);
            return Err(ProcessError::Image);
        }
    };

    // The program image ends here; without this initialisation `brk` reports
    // zero (the "unknown break" contract, see `compat::linux::memory`) and musl
    // falls back to its mmap+mprotect path for heap metadata. Initialise the
    // break exactly like the dynamic and init spawn paths do.
    fds.set_program_break(loaded.image_end);

    // `AT_RANDOM` and `getrandom(2)` are security-relevant: a missing secure
    // source must fail the spawn loudly instead of handing out fake bytes.
    let mut random = [0u8; 16];
    if crate::rng::read_secure(&mut random).is_err() {
        let _ = addrspace::destroy(loaded.address_space);
        let _ = object::clear_handle_table(&mut handles);
        let _ = release_all_fds(&mut fds);
        return Err(ProcessError::BadRequest);
    }

    let execfn = argv.first().copied().unwrap_or(main_path);
    let mut stack_image = [0u8; linux_stack::PROGRAM_STACK_BYTES];
    let (rsp, written) = match linux_stack::encode_program_stack(
        &mut stack_image,
        loaded.user_stack,
        loaded.phdr,
        loaded.phent,
        loaded.phnum,
        loaded.main_entry,
        image::PROGRAM_INTERPRETER_BIAS,
        crate::vdso::VDSO_BASE,
        &random,
        execfn,
        argv,
    ) {
        Ok(encoded) => encoded,
        Err(_) => {
            let _ = addrspace::destroy(loaded.address_space);
            let _ = object::clear_handle_table(&mut handles);
            let _ = release_all_fds(&mut fds);
            return Err(ProcessError::BadRequest);
        }
    };
    if let Err(error) = addrspace::copy_out(loaded.address_space, rsp, &stack_image[..written]) {
        let _ = addrspace::destroy(loaded.address_space);
        let _ = object::clear_handle_table(&mut handles);
        let _ = release_all_fds(&mut fds);
        return Err(ProcessError::Map(error));
    }

    let extras = ProcessExtras {
        personality: Personality::Linux64,
        fds,
        linux_netns: None,
    };
    let child = unsafe {
        register_with(
            None,
            loaded.address_space,
            loaded.entry,
            rsp,
            handles,
            [0, 0, 0],
            None,
            extras,
        )
    }?;

    link_detached(child, affinity)?;
    Ok(child)
}
/// Reap every `Zombie` process that has no parent (detached M6b2 workers).
///
/// Only collects the slots under [`PROCESS_LOCK`]; the actual reaping (handle
/// clear, drain, VFS ownership, stack/address-space release, object destroy
/// hooks) runs outside the lock through [`reap`]. A reap that fails is left for
/// the next call instead of being retried here.
pub fn reap_orphans() -> usize {
    let mut orphans = [0usize; MAX_PROCESSES];
    let mut count = 0;
    with_table(|| {
        for index in 0..MAX_PROCESSES {
            if let Some(process) = unsafe { process_ref(index) } {
                if process.state == ProcessState::Zombie && process.parent.is_none() {
                    orphans[count] = index;
                    count += 1;
                }
            }
        }
    });
    let mut reaped = 0;
    for &index in &orphans[..count] {
        if unsafe { reap(index) }.is_ok() {
            reaped += 1;
        }
    }
    reaped
}

/// Register a fully loaded process: allocate its kernel stack, build the first
/// ring-3 frame and publish it as `Ready`.
///
/// Ownership: this function takes the address space and the handle table over.
/// Either the process is published (and then owns both) or every failure path
/// releases the address space, the handle table and each stack frame already
/// allocated/mapped. The caller must not free anything when this returns `Err`.
unsafe fn register(
    parent: Option<ProcessId>,
    address_space: AddressSpaceId,
    entry: u64,
    user_stack: u64,
    handles: HandleTable,
    args: [u64; 3],
    wait_handle: Option<Handle>,
) -> Result<ProcessId, ProcessError> {
    // SAFETY: same ownership contract as `register_with`; native extras carry an
    // empty fd table and no network namespace.
    unsafe {
        register_with(
            parent,
            address_space,
            entry,
            user_stack,
            handles,
            args,
            wait_handle,
            ProcessExtras::native(),
        )
    }
}

/// [`register`] with explicit thread-group extras (M7d).
///
/// Ownership: this function takes the address space, the handle table and the
/// extras over. Either the process is published (and then owns all three) or
/// every failure path releases the address space, the handle table, each stack
/// frame already allocated/mapped **and** the fd-table references still held by
/// `extras`. The caller must not free anything when this returns `Err`.
unsafe fn register_with(
    parent: Option<ProcessId>,
    address_space: AddressSpaceId,
    entry: u64,
    user_stack: u64,
    handles: HandleTable,
    args: [u64; 3],
    wait_handle: Option<Handle>,
    extras: ProcessExtras,
) -> Result<ProcessId, ProcessError> {
    let mut extras = extras;
    let mut handles = handles;
    let mut stack_frames = [0u64; KERNEL_STACK_FRAMES as usize];
    // Reserve a free slot under the table lock; the stack allocation and frame
    // setup below run without it (PMM/mapping are lower layers and the APs do
    // not schedule in M6b2a, so the reservation cannot be raced).
    let index = match with_table(|| {
        (0..MAX_PROCESSES).find(|index| unsafe { process_ptr(*index).is_null() })
    }) {
        Some(index) => index,
        None => {
            // No stack page was mapped yet, so only the image, handles and fds go.
            let _ = release_all_fds(&mut extras.fds);
            if let Err(vm_error) = unsafe {
                discard_unregistered(0, address_space, &mut handles, &stack_frames, 0, None)
            } {
                return Err(ProcessError::AddressSpace(vm_error));
            }
            return Err(ProcessError::NoFreeSlot);
        }
    };

    let base = KERNEL_STACK_BASES[index];
    let top = kernel_stack_top(index);
    if top % 16 != 0 {
        // Frozen by Lead: the top must be 16-byte aligned so that
        // `set_user_kernel_stack` can reserve exactly one qword for rsp0.
        unsafe { fail("kernel stack top is not 16-byte aligned") };
    }
    if first_frame_addr(top) + FRAME_BYTES != (top - KERNEL_STACK_TOP_RESERVED) & !0xF {
        unsafe { fail("first frame does not end at the 16-byte aligned RSP0") };
    }

    // 1. Allocate and map the 8 stack frames, leaving the guard page below the
    //    base unmapped. Both the PMM and the mapping can fail, so each step
    //    unwinds the frames and resources acquired so far.
    for page in 0..KERNEL_STACK_FRAMES as usize {
        let physical = match pmm::alloc_frame() {
            Ok(physical) => physical,
            Err(error) => {
                let _ = release_all_fds(&mut extras.fds);
                if let Err(vm_error) = unsafe {
                    discard_unregistered(
                        base,
                        address_space,
                        &mut handles,
                        &stack_frames,
                        page,
                        None,
                    )
                } {
                    return Err(ProcessError::Map(vm_error));
                }
                return Err(ProcessError::Stack(error));
            }
        };
        let virt = base + page as u64 * pmm::FRAME_SIZE;
        if let Err(error) = unsafe {
            vm::map_physical(
                virt,
                physical,
                pmm::FRAME_SIZE,
                vm::PTE_PRESENT | vm::PTE_WRITE | vm::PTE_NX,
            )
        } {
            // The failing page never got a PTE, so only the frame goes back.
            let _ = pmm::dealloc_frame(physical);
            let _ = release_all_fds(&mut extras.fds);
            if let Err(vm_error) = unsafe {
                discard_unregistered(base, address_space, &mut handles, &stack_frames, page, None)
            } {
                return Err(ProcessError::Map(vm_error));
            }
            return Err(ProcessError::Map(error));
        }
        stack_frames[page] = physical;
        // SAFETY: the page was just mapped writable, non-executable.
        unsafe { core::ptr::write_bytes(virt as *mut u8, 0, pmm::FRAME_SIZE as usize) };
    }
    // Canary/scratch at the very top; `TSS.rsp0` will point here while this
    // process runs.
    unsafe { ((top - KERNEL_STACK_TOP_RESERVED) as *mut u64).write_volatile(KERNEL_STACK_CANARY) };

    // 2. Synthetic ring-3 frame at `align16(top - 8) - 176` (= `top - 192`).
    //    The three entry arguments travel in `rdi` / `rsi` / `rdx` (frozen by
    //    the native entry ABI); init passes 0 as the third one.
    let frame_addr = first_frame_addr(top);
    let frame = frame_addr as *mut TrapFrame;
    unsafe { write_first_frame(frame, entry, user_stack, args[0], args[1], args[2]) };

    // 3. Publish the process under the table lock. The slot was reserved above;
    //    a collision is treated as a clean failure instead of overwriting a
    //    live record (only reachable if M6b2b starts scheduling other CPUs).
    //
    //    The record is built once, in this frame, and published inline: the M7d
    //    `#DF` and the 2048-byte M8c record proved the 16 KiB boot stack cannot
    //    afford debug-build staging copies (`Option<Process>` plus a second
    //    `Process` in the failure arm), so none are created here. Cleanup uses
    //    `&mut process` too: no field is copied out on the failure path.
    let mut process = Process {
        state: ProcessState::Ready,
        address_space,
        handles,
        handles_taken: false,
        personality: extras.personality,
        signals: SignalState::new(),
        fs_base: 0,
        clear_child_tid: 0,
        fds: core::mem::take(&mut extras.fds),
        fds_taken: false,
        linux_netns: extras.linux_netns,
        kernel_stack_top: top,
        stack_frames,
        saved: frame,
        exit_status: 0,
        exit_signal: None,
        process_object: object::ObjectId::MAX,
        parent,
        children: [NO_PROCESS; MAX_CHILDREN],
        wait_handle: wait_handle.unwrap_or(Handle::INVALID),
        wait: WaitSpec::EMPTY,
        wake_reason: WakeReason::None,
        blocked_frame: FrameSlot::new(),
        cpu: AtomicU8::new(BSP_CPU),
        affinity: AtomicU8::new(DEFAULT_AFFINITY),
        migration: None,
    };
    #[cfg(test)]
    debug_assert!(
        !PROCESS_LOCK.is_locked(),
        "process table lock taken twice on one CPU"
    );
    let guard = PROCESS_LOCK.lock();
    if unsafe { !process_ptr(index).is_null() } {
        drop(guard);
        // Release the stack frames, the image/table and the fd references with
        // the lock dropped, exactly like a late registration failure.
        let _ = release_all_fds(&mut process.fds);
        let mapped = mapped_stack_pages(&process.stack_frames);
        if let Err(vm_error) = unsafe {
            discard_unregistered(
                base,
                address_space,
                &mut process.handles,
                &process.stack_frames,
                mapped,
                None,
            )
        } {
            return Err(ProcessError::AddressSpace(vm_error));
        }
        return Err(ProcessError::NoFreeSlot);
    }
    // SAFETY: `index` is a free slot and the table lock is held.
    unsafe { *slot_ptr(index) = Some(process) };
    // A published process is `Ready`: put it on the boot processor's queue so
    // the first `claim_next_on` finds it.
    queue_push_unlocked(index, BSP_CPU as usize);
    drop(guard);
    Ok(ProcessId::from_index(index))
}

/// Fill the synthetic first ring-3 frame.
///
/// `entry` is the user entry point and `user_stack` the 16-byte aligned user
/// stack top, which becomes the first `rsp` seen in user mode (m00443). The
/// `user_rsp` / `user_ss` slots are *real* user state here, not the scratch
/// slots the ring0 M3 frame had: a privilege-changing `iretq` pops them, so
/// they must hold the user stack pointer and `USER_DS` (Lead m00502). No
/// overwrite after `init_user_frame` is allowed.
///
/// The three initial handle values are the entry arguments frozen by the
/// native ABI: `arg0` → `rdi`, `arg1` → `rsi`, `arg2` → `rdx`. Without the
/// `rdx` slot a child that received a third handle (the M6a2 `ChannelB`
/// endpoint) would call `ipc_recv(0)` and get `BAD_HANDLE`.
unsafe fn write_first_frame(
    frame: *mut TrapFrame,
    entry: u64,
    user_stack: u64,
    arg0: u64,
    arg1: u64,
    arg2: u64,
) {
    unsafe {
        crate::arch::traps::init_user_frame(frame, entry, user_stack);
        (*frame).rdi = arg0;
        (*frame).rsi = arg1;
        (*frame).rdx = arg2;
    }
}

/// First three handle values of a child table, passed in `rdi` / `rsi` / `rdx`.
///
/// Handle `raw()` values are generation-encoded (`(generation << 16) | slot + 1`)
/// and `duplicate_handle` never bumps the destination generation, so the values
/// are the frozen layout the user runtime decodes, not an internal detail.
fn child_entry_args(handles: &HandleTable) -> [u64; 3] {
    let mut args = [0u64; 3];
    for slot in 0..handles.len().min(3) {
        let raw = (1u32 << 16) | (slot as u32 + 1);
        args[slot] = raw as u64;
    }
    args
}

// ---------------------------------------------------------------------------
// Public API: wait / exit
// ---------------------------------------------------------------------------

/// Wait for a child process to exit.
///
/// The handle must be a `Process` handle with `WAIT` rights in the *current*
/// process's table. A zombie child is reaped (address space destroyed, kernel
/// stack frames returned, handle table cleared, parent's WAIT handle closed)
/// and its status returned. A running child yields [`WaitError::WouldBlock`]:
/// M4 does not block in the syscall, the caller retries.
pub fn wait(child: Handle) -> Result<u64, WaitError> {
    let (child_index, decision) = with_table(|| {
        let current = current_unlocked().ok_or(WaitError::InvalidHandle)?;
        let parent = unsafe { process_ref(current.index()) }.ok_or(WaitError::InvalidHandle)?;
        // Resolving needs the real table: while a `CurrentHandlesGuard` owns it
        // the slot only holds an empty placeholder, so every handle would look
        // invalid. Reject explicitly instead of reporting a bad handle.
        if parent.handles_taken {
            return Err(WaitError::InvalidHandle);
        }
        let resolved =
            object::resolve_as_handle(&parent.handles, child, ObjectKind::Process, Rights::WAIT)
                .map_err(|_| WaitError::InvalidHandle)?;

        let child_index = (0..MAX_PROCESSES)
            .find(|index| {
                unsafe { process_ref(*index) }
                    .map(|process| process.process_object == resolved.object)
                    .unwrap_or(false)
            })
            .ok_or(WaitError::InvalidHandle)?;
        let child_process = unsafe { process_ref(child_index) }.ok_or(WaitError::InvalidHandle)?;
        if child_process.parent != Some(current) {
            return Err(WaitError::NotChild);
        }
        Ok((
            child_index,
            wait_decision(child_process.state.as_u8(), child_process.exit_status),
        ))
    })?;

    // `reap` takes the table lock itself and then releases the process's
    // resources after dropping it, so it must run outside this critical section.
    match decision {
        WaitDecision::Blocked => Err(WaitError::WouldBlock),
        WaitDecision::Exited(status) => {
            unsafe { reap(child_index) }.map_err(WaitError::Reap)?;
            Ok(status)
        }
    }
}

/// Clear the exiting process's `clear_child_tid` word and wake one futex
/// waiter (M8f).
///
/// Must run while the exiting process's address space is still active (it is
/// only released later, at reap); every fault is ignored, matching Linux's
/// "only clear the word if it is writable" behaviour.
fn clear_child_tid_on_exit(address_space: AddressSpaceId, address: u64) {
    if address == 0 {
        return;
    }
    let word = 0u32;
    if addrspace::copy_out(address_space, address, &word.to_le_bytes()).is_err() {
        return;
    }
    if let Some(physical) = addrspace::translate_user(address_space, address) {
        let _ = wake_futex(physical, 1);
    }
}

/// Mark the current process as a zombie and switch to the next runnable one.
///
/// The address space and kernel stack of the exiting process are deliberately
/// *not* released here (Lead m00445): the current address space is still on the
/// CPU and the current kernel stack is still in use. Reaping happens later, in
/// the context of the parent's `wait`, or never if the machine ends the demo.
///
/// **M7d:** the Linux fd table is released here, not at reap time, so a Linux
/// process that exits without anybody waiting on it does not keep its console
/// and socket references alive. The table is taken under the process lock and
/// closed outside it (closing a fd may run object destroy hooks and VFS/IPC
/// locks, which must not run while `PROCESS_LOCK` is held).
pub fn exit_current(status: u64) -> ! {
    exit_current_inner(status, None)
}

/// [`exit_current`] for a process terminated by signal `signo` (M8d).
///
/// The compat layer calls this for the M8c delayed default action
/// (`SIG_DFL` termination). The signal is stored in `Process::exit_signal`, so
/// the parent's `wait4` can encode the Linux status without the kernel ever
/// reverse-engineering it from a `128 + signo` exit code.
pub fn exit_current_with_signal(status: u64, signo: u32) -> ! {
    exit_current_inner(status, Some(signo))
}

/// Shared exit path: mark `Zombie`, release the fds and wake a waiting parent.
///
/// The wake is new in M8d: before, `wait` was polling-only (`WouldBlock` and the
/// caller retried), so an exiting child never touched the process object. A
/// blocking `wait4` waits on that object, therefore the exit path must publish
/// the readiness **after** dropping [`PROCESS_LOCK`] (both because the wake
/// takes the lock again and because a wake may switch stacks).
fn exit_current_inner(status: u64, signal: Option<u32>) -> ! {
    let mut released_fds = None;
    let mut process_object = ObjectId::MAX;
    let mut address_space = AddressSpaceId::INVALID;
    let mut clear_child_tid = 0u64;
    with_table(|| {
        if let Some(index) = current_index_unlocked() {
            if let Some(process) = unsafe { process_ref(index) } {
                process.state = ProcessState::Zombie;
                process.exit_status = status;
                process.exit_signal = signal;
                process_object = process.process_object;
                address_space = process.address_space;
                clear_child_tid = process.clear_child_tid;
                if !process.fds_taken {
                    released_fds = Some(core::mem::take(&mut process.fds));
                }
            }
        }
    });
    if let Some(mut fds) = released_fds {
        let _ = release_all_fds(&mut fds);
    }
    // M8f: the address space is still active here (it is released at reap), so
    // the userspace `clear_child_tid` word can be zeroed and one futex waiter
    // woken through the exiting process's own mappings.
    clear_child_tid_on_exit(address_space, clear_child_tid);
    if process_object != ObjectId::MAX {
        // Wakes a parent blocked in `wait4` on the child's process object. The
        // object is kept alive by the parent's `WAIT` handle until `reap`, so
        // this cannot race the object table into destroying it.
        let _ = wake_object(process_object, WakeReason::Ready);
    }
    // The switch happens outside the process table lock: `sched` runs other
    // processes and may call back into this module.
    sched::on_user_exit()
}

// ---------------------------------------------------------------------------
// M8d: second Linux process (path B), Linux pid mapping, cross-process signals
// and the process half of a blocking `wait4`
//
// The M8d design is deliberately *not* `clone`/`fork`: the root phase loads the
// same `linux` boot module once for a detached parent (`role = 0`) and once for
// a parented child (`role = 1`, from an auxv entry). Both are ordinary fresh
// image loads; only the parent link and the explicit channel/netns handles are
// inherited. Capacity stays at `MAX_PROCESSES`/`MAX_SPACES`.
// ---------------------------------------------------------------------------

/// Linux pid of a process record: table index plus one (Linux pids start at 1).
pub const fn linux_pid(process: ProcessId) -> u32 {
    process.index() as u32 + 1
}

/// Resolve a Linux pid to a live process record (caller holds [`PROCESS_LOCK`]).
fn process_from_linux_pid_unlocked(pid: u32) -> Option<ProcessId> {
    let index = (pid as usize).checked_sub(1)?;
    if index >= MAX_PROCESSES {
        return None;
    }
    unsafe { process_ref(index) }.map(|_| ProcessId::from_index(index))
}

/// Resolve a Linux pid to a live process record.
pub fn process_from_linux_pid(pid: u32) -> Option<ProcessId> {
    with_table(|| process_from_linux_pid_unlocked(pid))
}

/// Linux pid of the current process, if any.
pub fn current_linux_pid() -> Option<u32> {
    with_table(|| current_index_unlocked().map(|index| index as u32 + 1))
}

/// Parent of the current process, if it has a real parent link (M8d).
///
/// Detached processes (spawned with [`spawn_detached`]/[`spawn_detached_linux`])
/// have no parent and report `None`, which the compat `getppid` turns into 0.
pub fn current_parent_id() -> Option<ProcessId> {
    with_table(|| {
        let current = current_index_unlocked()?;
        let process = unsafe { process_ref(current) }?;
        process.parent
    })
}

/// Linux pid of the current process's parent, if any.
pub fn parent_linux_pid() -> Option<u32> {
    current_parent_id().map(linux_pid)
}

/// Exit information of a reaped child (M8d `wait4`).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct ChildExit {
    /// Linux pid of the reaped child; this is the `wait4` return value.
    pub pid: u32,
    /// Exit code of a normal exit; meaningless when `signal` is `Some`.
    pub code: u64,
    /// Signal that terminated the child, if the delayed M8c default action ran.
    pub signal: Option<u32>,
}

/// What a non-blocking wait attempt found (M8d `wait4`).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ChildWait {
    /// The child was a zombie: it has been reaped and its status returned.
    Exited(ChildExit),
    /// The child is still running; block on this process object until it exits.
    Running(ObjectId),
}

/// Result of a cross-process `kill`/`tgkill` (M8d).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct SignalDecision {
    /// Linux pid of the process the signal was queued for.
    pub target_pid: u32,
}

impl SignalDecision {
    /// Build a decision for `target_pid`.
    pub const fn new(target_pid: u32) -> Self {
        Self { target_pid }
    }
}

/// Failures of [`signal_send_process`] / [`signal_send_children`].
///
/// Kept separate from [`SignalError`] so the frozen M8c entry points
/// (`rt_sigaction`/`rt_sigprocmask`/`rt_sigreturn`) keep their exact error set;
/// the compat layer maps `NoSuchProcess` to `ESRCH` and an unknown relation to
/// the same, as the M8d contract requires.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SignalSendError {
    /// The target does not exist, or the sender is neither the target itself,
    /// its parent nor its child (M8d allows only parent<->child and self).
    NoSuchProcess,
    /// Signal number outside `1..=SIGNAL_MAX` (0 is accepted as a probe).
    InvalidSignal,
}

/// Resolve the child named by `pid` for the caller `current` (lock held).
///
/// `None` means "any child of the caller" (`wait4(-1)`). M9c prefers a zombie
/// child over a live one, so a supervisor that already reaped one peer gets the
/// exited child back instead of blocking on the other one; among live children
/// the first occupied slot wins. A positive pid must name a direct child of
/// `current`.
fn child_index_unlocked(current: usize, pid: Option<u32>) -> Option<usize> {
    match pid {
        None => {
            let parent = unsafe { process_ref(current) }?;
            let mut first_live: Option<usize> = None;
            for raw in parent.children {
                if raw == NO_PROCESS {
                    continue;
                }
                let index = raw as usize;
                let Some(child) = (unsafe { process_ref(index) }) else {
                    continue;
                };
                if child.state == ProcessState::Zombie {
                    return Some(index);
                }
                if first_live.is_none() {
                    first_live = Some(index);
                }
            }
            first_live
        }
        Some(pid) => {
            if pid == 0 {
                return None;
            }
            let child = process_from_linux_pid_unlocked(pid)?;
            let child_process = unsafe { process_ref(child.index()) }?;
            if child_process.parent != Some(ProcessId::from_index(current)) {
                return None;
            }
            Some(child.index())
        }
    }
}

/// Spawn a parented Linux64 child from the same boot module image (M8d).
///
/// `parent` must be a live, non-zombie process with fewer than
/// [`MAX_CHILDREN`] direct children. The child is a fresh image load (own
/// address space, kernel stack and fds); the console becomes fds 0/1/2, and only
/// the explicit `channel`/`netns` handles are inherited. `role` is written into
/// the initial-stack auxv (`AT_CAELUM_ROLE`): the boot module contains both the
/// parent (role 0) and the child (role 1) paths, and M9c runs the same image a
/// second time as the role 2 lock peer.
///
/// On success the parent owns a hidden `Wait` handle for the child (the pid-based
/// `wait4` never exposes it to user mode) and the child is immediately queued on
/// the first CPU allowed by `affinity`.
pub fn spawn_linux_child(
    parent: ProcessId,
    name: &str,
    affinity: u8,
    console: ObjectId,
    channel: Option<(ObjectId, Rights)>,
    netns: Option<(ObjectId, Rights)>,
    role: u64,
) -> Result<(ProcessId, u32), ProcessError> {
    let parent_index = parent.index();
    if affinity == 0 || affinity & !CPU_MASK_ALL != 0 {
        return Err(ProcessError::BadRequest);
    }

    // Validate the parent and the one-child rule before the (long) image load.
    with_table(|| {
        let parent_process =
            unsafe { process_ref(parent_index) }.ok_or(ProcessError::NoSuchProcess)?;
        if parent_process.state == ProcessState::Zombie {
            return Err(ProcessError::NoSuchProcess);
        }
        if parent_process.handles_taken {
            return Err(ProcessError::BadRequest);
        }
        // M9c allows up to two direct children; a third spawn is rejected
        // instead of silently overwriting a link.
        let child_count = (0..MAX_PROCESSES)
            .filter(|index| {
                unsafe { process_ref(*index) }
                    .map(|process| process.parent == Some(parent))
                    .unwrap_or(false)
            })
            .count();
        if child_count >= MAX_CHILDREN {
            return Err(ProcessError::ChildExists);
        }
        Ok(())
    })?;

    if object::object_kind(console) != Some(ObjectKind::Console) {
        return Err(ProcessError::Objects(ObjectError::InvalidObject));
    }
    if let Some((object, _)) = netns {
        if object::object_kind(object) != Some(ObjectKind::NetNamespace) {
            return Err(ProcessError::Objects(ObjectError::InvalidObject));
        }
    }

    // The child's native handle table: channel first (slot 0), then netns
    // (slot 1), matching the raw values written into the auxv. The compat
    // roles do not use the native entry arguments, so those stay zero.
    let mut handles = HandleTable::new();
    let mut channel_raw = 0u32;
    let mut netns_raw = 0u32;
    let mut netns_handle = None;
    if let Some((object, rights)) = channel {
        match object::insert_handle(&mut handles, object, rights) {
            Ok(handle) => channel_raw = u32::from(handle.raw()),
            Err(error) => {
                let _ = object::clear_handle_table(&mut handles);
                return Err(ProcessError::Objects(error));
            }
        }
    }
    if let Some((object, rights)) = netns {
        match object::insert_handle(&mut handles, object, rights) {
            Ok(handle) => {
                netns_raw = u32::from(handle.raw());
                netns_handle = Some(handle);
            }
            Err(error) => {
                let _ = object::clear_handle_table(&mut handles);
                return Err(ProcessError::Objects(error));
            }
        }
    }

    let mut fds = FdTable::new();
    if fds.install_console(console).is_err() {
        let _ = object::clear_handle_table(&mut handles);
        let _ = release_all_fds(&mut fds);
        return Err(ProcessError::Objects(ObjectError::InvalidObject));
    }

    let loaded = match image::load_module(name.as_bytes()) {
        Ok(loaded) => loaded,
        Err(_) => {
            let _ = object::clear_handle_table(&mut handles);
            let _ = release_all_fds(&mut fds);
            return Err(ProcessError::Image);
        }
    };

    // The image address space now exists: every failure from here until
    // `register_with` takes ownership releases it through the same single
    // cleanup point the spawn path uses (`discard_unregistered`), so a failed
    // child creation never leaks an address space or stack frames.
    let release_after_load = |handles: &mut HandleTable, address_space: AddressSpaceId| {
        let frames = [0u64; KERNEL_STACK_FRAMES as usize];
        // SAFETY: no stack frame was mapped yet, the table holds only copied
        // handle references and the address space is not active.
        let _ = unsafe { discard_unregistered(0, address_space, handles, &frames, 0, None) };
    };

    fds.set_program_break(loaded.image_end);

    let mut stack_image = [0u8; linux_stack::INITIAL_STACK_BYTES];
    let written = match linux_stack::encode_initial_stack_with_role(
        &mut stack_image,
        channel_raw,
        netns_raw,
        role,
    ) {
        Ok(written) => written,
        Err(_) => {
            let _ = release_all_fds(&mut fds);
            release_after_load(&mut handles, loaded.address_space);
            return Err(ProcessError::BadRequest);
        }
    };
    let rsp = (loaded.user_stack - written as u64) & !0xF;
    if let Err(error) = addrspace::copy_out(loaded.address_space, rsp, &stack_image[..written]) {
        let _ = release_all_fds(&mut fds);
        release_after_load(&mut handles, loaded.address_space);
        return Err(ProcessError::Map(error));
    }

    let extras = ProcessExtras {
        personality: Personality::Linux64,
        fds,
        linux_netns: netns_handle,
    };
    // `register_with` owns the address space, the handle table and the extras;
    // on failure it has already released all three.
    let child = unsafe {
        register_with(
            Some(parent),
            loaded.address_space,
            loaded.entry,
            rsp,
            handles,
            [0, 0, 0],
            None,
            extras,
        )
    }?;

    // Link phase: the child is registered but unreachable (`Ready`, not yet
    // claimable as the parent's child). Insert the hidden WAIT handle and queue
    // the child on its affinity CPU under one short table lock; every cleanup
    // step runs after it.
    let process_object = match object::create_process_object() {
        Ok(object) => object,
        Err(error) => {
            unsafe { rollback_registration(child.index()) };
            return Err(ProcessError::Objects(error));
        }
    };
    let linked = with_table(|| -> Result<Handle, Option<object::ObjectError>> {
        let parent_process = match unsafe { process_ref(parent_index) } {
            Some(process) => process,
            None => return Err(None),
        };
        if parent_process.handles_taken || parent_process.state == ProcessState::Zombie {
            return Err(None);
        }
        let wait_handle =
            object::insert_handle(&mut parent_process.handles, process_object, Rights::WAIT)
                .map_err(Some)?;
        let child_process = match unsafe { process_ref(child.index()) } {
            Some(process) => process,
            None => return Err(None),
        };
        child_process.process_object = process_object;
        child_process.wait_handle = wait_handle;
        child_process.affinity.store(affinity, Ordering::Release);
        parent_process.add_child(child);
        // Same initial placement rules as `link_detached`: move the Ready bit
        // off the boot queue onto the first CPU the affinity allows.
        let target = first_online_affinity_cpu(affinity).unwrap_or(BSP_CPU);
        queue_remove_unlocked(child.index());
        child_process.cpu.store(target, Ordering::Release);
        queue_push_unlocked(child.index(), target as usize);
        if target as usize != current_cpu() {
            request_resched_unlocked(target as usize);
        }
        Ok(wait_handle)
    });
    match linked {
        Ok(wait_handle) => Ok((child, wait_handle.raw())),
        Err(reason) => {
            let _ = object::destroy_object(process_object);
            unsafe { rollback_registration(child.index()) };
            match reason {
                Some(error) => Err(ProcessError::Objects(error)),
                None => Err(ProcessError::NoSuchProcess),
            }
        }
    }
}

/// Try to reap the child named by `pid` and return its exit information.
///
/// `pid == None` means `wait4(-1)`: M9c prefers a zombie direct child, then the
/// first live one; a positive pid must name a direct child. Returns `Ok(None)`
/// while the child is still running; returns `Err(ProcessError::NoChild)` when
/// `pid` does not name a child at all. A zombie is reaped here.
pub fn take_child_exit(pid: Option<u32>) -> Result<Option<ChildExit>, ProcessError> {
    let (child_index, snapshot) = with_table(
        || -> Result<(usize, Option<(u64, Option<u32>)>), ProcessError> {
            let current = current_index_unlocked().ok_or(ProcessError::NoSuchProcess)?;
            let child_index = child_index_unlocked(current, pid).ok_or(ProcessError::NoChild)?;
            let child = unsafe { process_ref(child_index) }.ok_or(ProcessError::NoSuchProcess)?;
            let snapshot = (child.state == ProcessState::Zombie)
                .then_some((child.exit_status, child.exit_signal));
            Ok((child_index, snapshot))
        },
    )?;
    match snapshot {
        Some((code, signal)) => {
            let pid = child_index as u32 + 1;
            // `reap` takes the table lock itself and releases the child's
            // resources (address space, stack, handles, process object) after
            // dropping it, so it must run outside this critical section.
            unsafe { reap(child_index) }?;
            Ok(Some(ChildExit { pid, code, signal }))
        }
        None => Ok(None),
    }
}

/// Linux pid of the child named by `pid`, without reaping or changing state.
///
/// `pid == None` means `wait4(-1)`: M9c reports the zombie child first, else the
/// first live direct child (see [`child_index_unlocked`]). `wait4` needs the pid
/// for its return value; the handler resolves it *before* calling [`wait_child`],
/// so an exited child can still be reported with its pid even though
/// [`take_child_exit`] reaps it.
pub fn child_linux_pid(pid: Option<u32>) -> Result<u32, ProcessError> {
    with_table(|| {
        let current = current_index_unlocked().ok_or(ProcessError::NoSuchProcess)?;
        let child_index = child_index_unlocked(current, pid).ok_or(ProcessError::NoChild)?;
        Ok(child_index as u32 + 1)
    })
}

/// Process object to block on for a still-running child (M8d `wait4`).
///
/// The caller first calls [`take_child_exit`]; a `None` there means the child is
/// running (or exited between the two calls). This helper only hands out the
/// blockable object and **never reaps**: if the child has meanwhile become a
/// zombie it returns [`ProcessError::NoChild`], telling the caller to replay
/// `wait4` (whose first `take_child_exit` then reaps and reports the status).
pub fn child_wait_object(pid: Option<u32>) -> Result<ObjectId, ProcessError> {
    with_table(|| {
        let current = current_index_unlocked().ok_or(ProcessError::NoSuchProcess)?;
        let child_index = child_index_unlocked(current, pid).ok_or(ProcessError::NoChild)?;
        let child = unsafe { process_ref(child_index) }.ok_or(ProcessError::NoSuchProcess)?;
        if child.state == ProcessState::Zombie {
            return Err(ProcessError::NoChild);
        }
        if child.process_object == ObjectId::MAX {
            return Err(ProcessError::NoSuchProcess);
        }
        Ok(child.process_object)
    })
}

/// One-shot wait attempt: reap a zombie child or return the object to block on.
///
/// This is the preferred entry point for `wait4` handlers: unlike two separate
/// calls it takes the table lock once, so the "child exited between the check
/// and the block" case is narrowed to the return-to-block window (the caller
/// then blocks on an object whose exit wake may already have fired — the M8d
/// phase keeps parent and child on the same single AP, so they cannot run
/// simultaneously and the wake cannot be missed).
pub fn wait_child(pid: Option<u32>) -> Result<ChildWait, ProcessError> {
    if let Some(exit) = take_child_exit(pid)? {
        return Ok(ChildWait::Exited(exit));
    }
    Ok(ChildWait::Running(child_wait_object(pid)?))
}

/// `wait4`-friendly pid form: `u32::MAX` is `-1` (wait for any direct child).
pub fn wait_child_pid(pid: u32) -> Result<ChildWait, ProcessError> {
    if pid == 0 {
        return Err(ProcessError::NoChild);
    }
    wait_child(if pid == u32::MAX { None } else { Some(pid) })
}

/// Linux `kill`/`tgkill` addressed at another process (M8d).
///
/// The sender must be the target itself, its parent or its child (path B only
/// creates parent<->child pairs). `signo == 0` is a pure existence/permission
/// probe and queues nothing. A queued signal follows the M8c delayed semantics:
/// it sets the target's pending bit and, when the target is `Blocked` and the
/// signal is deliverable, wakes it with [`WakeReason::Cancelled`] so its syscall
/// replays with `EINTR`; the default action runs when the target returns to
/// user mode — nothing is terminated across CPUs by force.
pub fn signal_send_process(target_pid: u32, signo: u32) -> Result<SignalDecision, SignalSendError> {
    let (target_index, queued) = with_table(|| {
        let sender = current_index_unlocked().ok_or(SignalSendError::NoSuchProcess)?;
        let target =
            process_from_linux_pid_unlocked(target_pid).ok_or(SignalSendError::NoSuchProcess)?;
        let target_index = target.index();
        if !siblings_or_self(sender, target_index) {
            return Err(SignalSendError::NoSuchProcess);
        }
        if signo != 0 {
            let signo = valid_signal(signo).map_err(|_| SignalSendError::InvalidSignal)?;
            queue_signal_unlocked(target_index, signo);
        }
        Ok((target_index, signo != 0))
    })?;
    if queued {
        notify_signalfd(ProcessId::from_index(target_index));
    }
    Ok(SignalDecision::new(target_pid))
}

/// Broadcast `signo` to every live child of the current process (`kill(-1)`).
///
/// `signo == 0` only counts the children (existence probe). Returns the number
/// of children the signal was queued for; the compat layer maps 0 to `ESRCH`.
pub fn signal_send_children(signo: u32) -> usize {
    let mut queued: [ProcessId; MAX_PROCESSES] = [ProcessId::from_index(0); MAX_PROCESSES];
    let mut queued_count: usize = 0;
    let count = with_table(|| {
        let Some(current) = current_index_unlocked() else {
            return 0;
        };
        let signo = if signo == 0 {
            0
        } else {
            match valid_signal(signo) {
                Ok(signo) => signo,
                Err(_) => return 0,
            }
        };
        let mut count = 0;
        for index in 0..MAX_PROCESSES {
            let Some(process) = (unsafe { process_ref(index) }) else {
                continue;
            };
            if process.parent != Some(ProcessId::from_index(current))
                || process.state == ProcessState::Zombie
            {
                continue;
            }
            count += 1;
            if signo != 0 {
                queue_signal_unlocked(index, signo);
                if queued_count < MAX_PROCESSES {
                    queued[queued_count] = ProcessId::from_index(index);
                    queued_count += 1;
                }
            }
        }
        count
    });
    for owner in queued.iter().take(queued_count) {
        notify_signalfd(*owner);
    }
    count
}

/// True when `from` may signal `to` under the M8d parent<->child rule.
fn siblings_or_self(from: usize, to: usize) -> bool {
    if from == to {
        return true;
    }
    let from_parent = unsafe { process_ref(from) }.and_then(|process| process.parent);
    let to_parent = unsafe { process_ref(to) }.and_then(|process| process.parent);
    from_parent.map(|parent| parent.index()) == Some(to)
        || to_parent.map(|parent| parent.index()) == Some(from)
}

/// Set `signo` pending on `index` and wake it when the signal can interrupt.
fn queue_signal_unlocked(index: usize, signo: u32) {
    let Some(process) = (unsafe { process_ref(index) }) else {
        return;
    };
    process.signals.pending |= signal_bit(signo);
    if process.state == ProcessState::Blocked && signal_interrupts(&process.signals, signo) {
        wake_process_unlocked(index, WakeReason::Cancelled);
    }
}

/// Ask the signalfd layer to re-check `owner` after its pending flags changed.
///
/// Runs after [`with_table`] has returned, i.e. outside [`PROCESS_LOCK`]: the
/// signalfd layer calls back into [`signal_pending_for`] and wakes the objects
/// its descriptors wait on, both of which take the process table again.
fn notify_signalfd(owner: ProcessId) {
    let _ = crate::ipc::signalfd::on_signal_pending(owner);
}

// ---------------------------------------------------------------------------
// Blocking / wakeup (M6a1)
// ---------------------------------------------------------------------------

/// Block the current user process until one of its wait objects fires or its
/// deadline expires.
///
/// Only callable from the running process's own syscall entry: `frame` must be
/// that entry's private `TrapFrame` at [`syscall_frame_addr`] (`top - 184`).
/// The frame is copied into the process's `.bss` slot and `rip` is moved back
/// by the two-byte `syscall` length, so the woken process replays the syscall
/// from user mode with the same number and arguments; this function never
/// returns to the syscall handler.
///
/// `objects[..count]` are the watched object ids (`count <= MAX_WAIT_OBJECTS`);
/// `count == 0` means only the deadline can release the wait. `deadline` is an
/// absolute value on the [`crate::time::monotonic_ticks`] clock and is expired
/// by the timer ISR through [`wake_expired`].
pub fn block_current(
    frame: *mut TrapFrame,
    objects: [ObjectId; MAX_WAIT_OBJECTS],
    count: usize,
    deadline: Option<u64>,
) -> ! {
    block_current_keyed(
        frame,
        objects,
        [WAIT_ANY_KEY; MAX_WAIT_OBJECTS],
        count,
        deadline,
    )
}

/// Keyed form of [`block_current`]: `keys[..count]` runs parallel to
/// `objects[..count]` and is matched by [`wake_object_key`].
///
/// A key of [`WAIT_ANY_KEY`] matches every key of that object; an EventPair
/// waiter passes the endpoint (0/1), while Event and Timer waiters pass 0.
/// Everything else (frame identity, replay, state transition) is identical to
/// [`block_current`].
pub fn block_current_keyed(
    frame: *mut TrapFrame,
    objects: [ObjectId; MAX_WAIT_OBJECTS],
    keys: [u32; MAX_WAIT_OBJECTS],
    count: usize,
    deadline: Option<u64>,
) -> ! {
    block_with(
        frame,
        WaitSpec::new(objects, keys, count.min(MAX_WAIT_OBJECTS), deadline),
    )
}

/// Block the current process on the futex word at `physical_word` (M6a2).
///
/// Same entry contract and frame handling as [`block_current`]: only callable
/// from the running process's own syscall entry, the frame is copied to the
/// `.bss` slot and `rip` moves back so the syscall replays on wake. The wait is
/// identified by the **exact physical address** the syscall layer already
/// translated and compared; [`wake_futex`] releases it, [`wake_expired`]
/// expires its deadline, and no object wake may touch it.
pub fn block_on_futex(frame: *mut TrapFrame, physical_word: u64, deadline: Option<u64>) -> ! {
    block_with(frame, WaitSpec::futex(physical_word, deadline))
}

/// Shared blocking path: validate the caller, save the frame, mark `Blocked`
/// and switch away. Never returns.
fn block_with(frame: *mut TrapFrame, wait: WaitSpec) -> ! {
    with_table(|| {
        let index = match current_index_unlocked() {
            Some(index) => index,
            None => unsafe { fail("block_current without a current process") },
        };
        let top = kernel_stack_top_of_unlocked(index);
        if frame.is_null() || frame as u64 != syscall_frame_addr(top) {
            unsafe { fail("block_current frame is not the private syscall frame") };
        }
        if !kernel_stack_ok_unlocked(index) {
            unsafe { fail("kernel stack TOP canary overwritten before blocking") };
        }
        let process = match unsafe { process_ref(index) } {
            Some(process) => process,
            None => unsafe { fail("block_current on a dead process slot") },
        };
        if process.state != ProcessState::Running {
            unsafe { fail("block_current while not running") };
        }

        // Copy the frame out of the kernel stack *before* idling: while this
        // process is blocked, `sched` runs the idle loop on the same kernel
        // stack and its timer frames overwrite the private `top - 184` slot.
        let slot = process.blocked_frame.as_frame();
        unsafe { copy_blocked_frame(frame, slot) };
        process.wait = wait;
        process.wake_reason = WakeReason::None;
        process.saved = slot;
        process.state = ProcessState::Blocked;
    });
    // The switch happens with the table lock released: the idle loop and the
    // next process both come back through this module.
    sched::block_and_switch()
}

/// Make every process blocked on `object` runnable and record `reason`.
///
/// Safe to call from interrupt context (timer / IPC destroy paths): it only
/// reads and writes the process table — no object-table access, no allocation,
/// no printing and no context switch (the switch happens at the waiter's next
/// scheduling point or in `sched`'s idle loop). Returns the number of processes
/// woken. A wake is idempotent: once a reason is recorded, later wakes are
/// ignored until [`take_wake_reason`] consumes it. Futex waiters are never
/// matched here.
pub fn wake_object(object: ObjectId, reason: WakeReason) -> usize {
    if !reason.is_some() {
        return 0;
    }
    with_table(|| wake_matching(WakeTrigger::Object(object, reason), usize::MAX))
}

/// Make every process blocked on `object` **with `key`** runnable and record
/// `reason`, for endpoint-exact EventPair signalling.
///
/// A waiter only matches when `object` equals a watched id *and* the watched
/// key equals `key` or is [`WAIT_ANY_KEY`]. Context rules are the same as
/// [`wake_object`]; destroying an object must keep using the key-agnostic
/// [`wake_object`] so both EventPair endpoints are released.
pub fn wake_object_key(object: ObjectId, key: u32, reason: WakeReason) -> usize {
    if !reason.is_some() {
        return 0;
    }
    with_table(|| wake_matching(WakeTrigger::ObjectKey(object, key, reason), usize::MAX))
}

/// Wake at most `max` processes blocked on the futex word at `physical_word`
/// (M6a2), recording [`WakeReason::Ready`].
///
/// Matching is by exact physical address; two processes that reached the same
/// word through different user virtual addresses (or even different address
/// spaces) match, and any other word does not. `max == 0` returns 0. Safe from
/// interrupt context under the same rules as [`wake_object`]; object wakes never
/// release these waiters.
pub fn wake_futex(physical_word: u64, max: usize) -> usize {
    if max == 0 {
        return 0;
    }
    with_table(|| wake_matching(WakeTrigger::Futex(physical_word), max))
}

/// Number of live processes currently blocked on a futex word.
pub fn futex_waiters() -> usize {
    with_table(futex_waiters_unlocked)
}

fn futex_waiters_unlocked() -> usize {
    let mut count = 0;
    for_each_live(|_, process| {
        if process.state == ProcessState::Blocked && process.wait.futex_word().is_some() {
            count += 1;
        }
    });
    count
}

/// Absolute deadline of the current process's most recent wait, if it had one.
///
/// Still readable after [`take_wake_reason`] until the next blocking wait
/// overwrites the spec, so a replayed syscall can reuse the original absolute
/// deadline instead of computing `now + timeout_ticks` again (which would keep
/// postponing the timeout). `None` means the wait was unbounded, the process
/// never blocked, or there is no current process.
pub fn wait_deadline() -> Option<u64> {
    with_table(wait_deadline_unlocked)
}

fn wait_deadline_unlocked() -> Option<u64> {
    let index = current_index_unlocked()?;
    let process = unsafe { process_ref(index) }?;
    process.wait.deadline
}

/// Expire every blocked deadline at or before `now` on the
/// [`crate::time::monotonic_ticks`] clock.
///
/// Same context rules as [`wake_object`]; driven by the timer ISR. Applies to
/// object and futex waiters alike: only the deadline is shared.
pub fn wake_expired(now: u64) -> usize {
    with_table(|| wake_matching(WakeTrigger::Deadline(now), usize::MAX))
}

/// Shared bounded scan behind the wake entry points: wake at most `max` of the
/// waiters matched by `trigger`. Caller must hold [`PROCESS_LOCK`].
fn wake_matching(trigger: WakeTrigger, max: usize) -> usize {
    debug_assert!(
        PROCESS_LOCK.is_locked(),
        "wake_matching requires PROCESS_LOCK"
    );
    let mut woken = 0;
    for index in 0..MAX_PROCESSES {
        if woken >= max {
            break;
        }
        // SAFETY: the caller holds the table lock and `index` is in range; the
        // borrow is released before the next iteration.
        let Some(process) = (unsafe { process_ref(index) }) else {
            continue;
        };
        if let Some(reason) = wake_decision(
            process.state.as_u8(),
            process.wake_reason,
            &process.wait,
            trigger,
        ) {
            process.wake_reason = reason;
            // Put the process back on the ready queue of its owner CPU and,
            // when this CPU differs, raise that CPU's reschedule bit. The IPI
            // itself belongs to `sched`/root: this path stays a short table
            // update with no platform, ipc or object-table access.
            let affinity = process.affinity.load(Ordering::Acquire);
            let recorded = process.cpu.load(Ordering::Acquire) as usize;
            let target = if recorded < crate::arch::MAX_CPUS
                && recorded < online_cpu_count()
                && affinity_allows(affinity, recorded as u8)
            {
                recorded
            } else {
                first_online_affinity_cpu(affinity)
                    .map(|cpu| cpu as usize)
                    .unwrap_or(BSP_CPU as usize)
            };
            queue_remove_unlocked(index);
            process.state = ProcessState::Ready;
            process.cpu.store(target as u8, Ordering::Release);
            queue_push_unlocked(index, target);
            if target != current_cpu() {
                REMOTE_WAKES.fetch_add(1, Ordering::AcqRel);
                request_resched_unlocked(target);
            }
            woken += 1;
        }
    }
    woken
}

/// Consume the current process's recorded wake reason.
///
/// Returns [`WakeReason::None`] when there is no current process or nothing was
/// recorded.
pub fn take_wake_reason() -> WakeReason {
    with_table(take_wake_reason_unlocked)
}

fn take_wake_reason_unlocked() -> WakeReason {
    let Some(index) = current_index_unlocked() else {
        return WakeReason::None;
    };
    let Some(process) = (unsafe { process_ref(index) }) else {
        return WakeReason::None;
    };
    let reason = process.wake_reason;
    process.wake_reason = WakeReason::None;
    reason
}

/// True when at least one live process is `Blocked` (idle-policy input).
pub fn has_blocked() -> bool {
    with_table(has_blocked_unlocked)
}

fn has_blocked_unlocked() -> bool {
    let mut any = false;
    for_each_live(|_, process| {
        if process.state == ProcessState::Blocked {
            any = true;
        }
    });
    any
}

/// Run the four teardown steps of [`reap`] in their mandatory order.
///
/// Kept as a tiny generic so a host test can pin the order: clearing the handle
/// table must come first (VmObject destroy hooks unmap user pages, and that
/// needs a live address space; File hooks close their descriptions in the same
/// step), then the per-owner VFS leftovers, then the kernel stack, and only
/// afterwards the address space. A failure aborts the remaining steps so a
/// retried reap never observes a half-released address space.
fn release_in_order<F, L, S, A, E>(
    mut handles: F,
    mut locks: L,
    mut stack: S,
    mut space: A,
) -> Result<(), E>
where
    F: FnMut(),
    L: FnMut(),
    S: FnMut() -> Result<(), E>,
    A: FnMut() -> Result<(), E>,
{
    handles();
    locks();
    stack()?;
    space()
}

/// Release everything a zombie process still owns and free its slot.
///
/// The handle table is cleared **before** the address space is destroyed: a
/// `VmObject` destroy hook has to unmap the user pages of its mapping, which
/// needs a live address space. `File` hooks close their VFS description in the
/// same step, and the parent's held `WAIT` handle is closed afterwards.
///
/// Between the handles and the address space, the per-owner VFS leftovers are
/// released with [`close_vfs_ownership`], keyed by **this** process's id (never
/// the current one): the destroy hooks cleared what had a description, and this
/// is the backstop for POSIX locks and watches without one.
///
/// Any object left with no reference at all (including one whose creation never
/// got a handle) is destroyed instead of lingering in the object table.
/// Console/Random handles are only *released* here through the child table, so
/// their references shared with the parent stay correct.
unsafe fn reap(index: usize) -> Result<(), ProcessError> {
    // Phase 1 (table lock held): validate the zombie and take its owned
    // resources out of the slot. Nothing heavy runs here: the handle table is
    // moved out, so the clear/drain/unmap/free work below happens with the
    // process table lock released and can take the object and VFS locks in the
    // documented process -> object -> vfs -> pagecache -> pmm order.
    //
    // The parent's WAIT handle is closed by moving the *parent's* table out too
    // (same convention as `take_current_handles`): closing a handle can run a
    // destroy hook, and hooks may take the object, VFS and IPC locks, so they
    // must never run while PROCESS_LOCK is held.
    let mut parent_wait: Option<(ProcessId, HandleTable)> = None;
    let (
        mut handles,
        mut fds,
        stack_frames,
        address_space,
        process_object,
        pid,
        children,
        wait_handle,
    ) = with_table(|| {
        let process = unsafe { process_ref(index) }.ok_or(ProcessError::NoSuchProcess)?;
        if process.state != ProcessState::Zombie {
            return Err(ProcessError::NoSuchProcess);
        }
        if current_index_unlocked() == Some(index) {
            // Never reap the process that is on the CPU.
            return Err(ProcessError::NoSuchProcess);
        }
        // A guard only ever owns the *current* process's table, and the
        // current process is never reaped, so this is a defensive check.
        debug_assert!(
            !process.handles_taken,
            "reaping a process whose handle table is owned by a guard"
        );
        process.handles_taken = false;
        // Same rule for the Linux fd table (M7d): a guard only owns the
        // current process's table, and the current process is never reaped.
        debug_assert!(
            !process.fds_taken,
            "reaping a process whose fd table is owned by a guard"
        );
        process.fds_taken = false;
        if let Some(parent) = process.parent {
            if !process.wait_handle.is_invalid() {
                if let Some(parent_process) = unsafe { process_ref(parent.index()) } {
                    debug_assert!(
                        !parent_process.handles_taken,
                        "reaping while the parent's handle table is owned by a guard"
                    );
                    let table = core::mem::take(&mut parent_process.handles);
                    parent_process.handles_taken = true;
                    parent_wait = Some((parent, table));
                }
            }
        }
        Ok((
            core::mem::take(&mut process.handles),
            core::mem::take(&mut process.fds),
            process.stack_frames,
            process.address_space,
            process.process_object,
            teardown_pid(index),
            process.children,
            process.wait_handle,
        ))
    })?;

    // Phase 2 (no process lock): handles first, because the VmObject destroy
    // hooks still need this address space to exist so they can unmap their user
    // pages. Clearing an already empty table is a no-op, so a retried reap stays
    // safe on this step. Then the pending queues the hooks parked their deferred
    // references in, the VFS ownership leftovers of *this* id, the kernel stack
    // (each PTE is cleared before its frame goes back to the PMM), and only
    // afterwards the address space itself: the current process is never reaped
    // (checked above), so it cannot be the active one.
    let release_result = release_in_order(
        || {
            let _ = object::clear_handle_table(&mut handles);
            // The destroy hooks park the references they cannot release inside
            // the object table; drain them while the address space is still
            // alive, exactly like the hooks themselves would have released them.
            let _ = drain_pending_object_refs();
            // Linux fds still hold console/socket references (M7d); close them
            // outside the process lock so their destroy hooks may run. Doing it
            // here also covers a process that exited without a parent `wait`.
            let _ = release_all_fds(&mut fds);
        },
        || {
            let _ = close_vfs_ownership(pid);
        },
        || {
            let mapped = mapped_stack_pages(&stack_frames);
            unsafe { release_stack_frames(KERNEL_STACK_BASES[index], &stack_frames, mapped) }
                .map(|_released| ())
                .map_err(ProcessError::Map)
        },
        || release_address_space(address_space).map_err(ProcessError::AddressSpace),
    );

    // Close the parent's WAIT handle with the process table lock released: the
    // destroy hook a closing handle can run must not observe PROCESS_LOCK. This
    // is skipped when a resource step above failed so a retried reap still owns
    // the handle and the slot stays intact.
    let release_failure = release_result.err();
    if release_failure.is_none() {
        if let Some((_, parent_handles)) = parent_wait.as_mut() {
            let _ = object::close_handle(parent_handles, wait_handle);
        }
    }

    // Phase 3 (short critical section): put the parent's table back, and only
    // when nothing failed drop the links and the slot. No object store call
    // happens here, so no destroy hook can run inside this section. Putting the
    // table back is unconditional: the parent must never be left with an empty
    // placeholder even when the release above failed.
    let mut orphan: Option<HandleTable> = None;
    with_table(|| {
        if let Some((parent, table)) = parent_wait.take() {
            if let Some(parent_process) = unsafe { process_ref(parent.index()) } {
                parent_process.handles = table;
                parent_process.handles_taken = false;
                if release_failure.is_none() {
                    parent_process.remove_child(ProcessId::from_index(index));
                }
            } else {
                // The parent slot vanished while its table was out; release the
                // references outside the lock instead of leaking them.
                orphan = Some(table);
            }
        }
        if release_failure.is_none() {
            for raw in children {
                if raw == NO_PROCESS {
                    continue;
                }
                // Defensive: a child of a reaped process is not reachable any more.
                if let Some(link) = unsafe { process_ref(raw as usize) } {
                    link.parent = None;
                }
            }
            // SAFETY: the slot was live and no borrow of it escapes this section.
            unsafe { *slot_ptr(index) = None };
        }
    });
    if let Some(mut table) = orphan {
        let _ = object::clear_handle_table(&mut table);
    }
    if release_failure.is_some() {
        // The process was partially released: keep its slot so a later reap can
        // retry, and leave the object alive (it is still reachable through the
        // slot). Report the first failure instead of pretending success.
        return Err(release_failure.unwrap_or(ProcessError::NoSuchProcess));
    }
    // The WAIT handle above is normally the last reference; if no handle ever
    // existed (or the parent is gone) the object would otherwise leak. Done
    // outside the process lock because destroying an object is a lower-layer
    // operation.
    destroy_unreferenced_object(process_object);
    Ok(())
}

// ---------------------------------------------------------------------------
// Resource cleanup (failure paths and reaping)
// ---------------------------------------------------------------------------

/// Destroy an address space, treating `INVALID` (never created) as "nothing to
/// do" so failure paths that never got past image loading stay total.
fn release_address_space(address_space: AddressSpaceId) -> Result<(), VmError> {
    if address_space == AddressSpaceId::INVALID {
        return Ok(());
    }
    addrspace::destroy(address_space)
}

/// Number of kernel-stack pages actually mapped, derived from the frame list.
///
/// A real process has [`KERNEL_STACK_FRAMES`] frames. Synthetic processes in
/// host tests have none, which keeps the release path from touching kernel
/// addresses under test.
const fn mapped_stack_pages(frames: &[u64; KERNEL_STACK_FRAMES as usize]) -> usize {
    let mut mapped = 0;
    while mapped < frames.len() && frames[mapped] != 0 {
        mapped += 1;
    }
    mapped
}

/// Unmap the first `mapped` kernel-stack pages and then return their frames.
///
/// Every page is unmapped **before** its frame goes back to the PMM, so the
/// kernel half can never keep a PTE pointing at a free frame (which would be a
/// use-after-free and would make the next spawn in the same slot fail with
/// `Overlap`). On an unmap failure the loop stops and the error is propagated:
/// the pages not released yet stay mapped and allocated, so the process is left
/// in a consistent state instead of half-freed.
unsafe fn release_stack_frames(
    base: u64,
    frames: &[u64; KERNEL_STACK_FRAMES as usize],
    mapped: usize,
) -> Result<usize, VmError> {
    let mapped = mapped.min(KERNEL_STACK_FRAMES as usize);
    let mut released = 0;
    for page in 0..mapped {
        let virt = base + page as u64 * pmm::FRAME_SIZE;
        // SAFETY: the page belongs to the kernel-stack window of this process.
        unsafe { vm::unmap_kernel(virt, pmm::FRAME_SIZE) }?;
        if pmm::dealloc_frame(frames[page]).is_ok() {
            released += 1;
        }
    }
    Ok(released)
}

/// Release everything a process that never became visible in a slot still owns:
/// its address space, its already-mapped stack frames and its handle table.
///
/// This is the single cleanup point for `register` failures, so the caller does
/// not have to reason about which step failed and never frees anything twice.
/// The handle table is always cleared (pure memory, never a PTE); when `owner`
/// is given (a registered slot being rolled back) the per-owner VFS leftovers
/// of that id are released right after it, mirroring [`reap`]. A failure to
/// unmap or destroy is propagated so a broken cleanup is never reported done.
unsafe fn discard_unregistered(
    base: u64,
    address_space: AddressSpaceId,
    handles: &mut HandleTable,
    frames: &[u64; KERNEL_STACK_FRAMES as usize],
    mapped: usize,
    owner: Option<u32>,
) -> Result<usize, VmError> {
    let frames_result = unsafe { release_stack_frames(base, frames, mapped) };
    object::clear_handle_table(handles);
    // Same drain as [`reap`]: the pending queues are the only place a deferred
    // `EventSubscription`/`SharedMemory` reference can sit, and this path never
    // reaches the parent's `reap`.
    let _ = drain_pending_object_refs();
    if let Some(pid) = owner {
        let _ = close_vfs_ownership(pid);
    }
    let address_space_result = release_address_space(address_space);
    // Report the first failure, but only after every best-effort step ran.
    let released = frames_result?;
    address_space_result?;
    Ok(released)
}

/// Take a registered-but-unreachable child back out of its slot and release
/// everything it owns (the post-register failure paths of `spawn`).
///
/// The child is `Ready` and was never scheduled, so its address space is not
/// active and its handle table only holds copied handles. Returns whether a
/// slot was actually released, so callers cannot double free.
unsafe fn rollback_registration(index: usize) -> bool {
    if index >= MAX_PROCESSES {
        return false;
    }
    // Phase 1: take the record out of its slot under the table lock. Only the
    // slot is touched here; every resource it owns is released below with the
    // lock dropped, so no object hook or VFS call runs under the process lock.
    let Some(process) = with_table(|| unsafe { (*slot_ptr(index)).take() }) else {
        return false;
    };
    let frames = process.stack_frames;
    let mut handles = process.handles;
    let mapped = mapped_stack_pages(&frames);
    // The slot was published, so this child has a real id: its per-owner VFS
    // leftovers (if any) must go with the rest of its state.
    let pid = teardown_pid(index);
    unsafe {
        discard_unregistered(
            KERNEL_STACK_BASES[index],
            process.address_space,
            &mut handles,
            &frames,
            mapped,
            Some(pid),
        )
        .is_ok()
    }
}

/// Destroy `object` when it has no reference left.
///
/// The child `Process` object is created before the parent's `WAIT` handle
/// exists. When that handle is never created, or when it was the last reference
/// and got closed, the object must not stay in the table. `close` is the wrong
/// primitive for a zero-reference entry, so this destroys it directly.
fn destroy_unreferenced_object(object: ObjectId) {
    if object == ObjectId::MAX {
        return;
    }
    if object::object_refs(object) == Some(0) {
        let _ = object::destroy_object(object);
    }
}

// ---------------------------------------------------------------------------
// Accessors used by `sched`
//
// The process table itself still needs the single-CPU discipline M6b2a keeps
// (everything runs on the boot processor), but "which process is current" is
// per-CPU: every CPU reads and writes only its own `CURRENTS` slot.
// ---------------------------------------------------------------------------

/// Logical index of the CPU executing this code, clamped to the table size.
///
/// `arch::syscall::cpu_index()` reads the GS block, which every CPU programs
/// before it is allowed to run kernel code. The clamp keeps a hypothetical
/// out-of-range index from indexing `CURRENTS` out of bounds; it is a
/// defensive `min`, not a correction, and cannot happen with `MAX_CPUS` slots
/// because the SMP layer refuses to start a CPU beyond them.
fn current_cpu() -> usize {
    let cpu = crate::arch::syscall::cpu_index();
    debug_assert!(cpu < crate::arch::MAX_CPUS, "CPU index outside the table");
    cpu.min(crate::arch::MAX_CPUS - 1)
}

/// Current-process slot of `cpu` (pure table read, no hardware access).
///
/// Host tests call this directly with every CPU index to pin the per-CPU
/// isolation without needing more than one real processor. Caller must hold
/// [`PROCESS_LOCK`] because it resolves the slot to a live index.
fn current_on(cpu: usize) -> Option<usize> {
    let raw = CURRENTS[cpu].load(Ordering::Acquire);
    if raw == NO_PROCESS {
        None
    } else {
        live_index(raw as usize)
    }
}

/// Set the current-process slot of `cpu` (pure table write, no hardware access).
///
/// Only the atomic slot is written; the caller is responsible for the fact that
/// only this CPU may name itself as current.
fn set_current_on(cpu: usize, index: Option<usize>) {
    let slot = match index {
        Some(index) if index < MAX_PROCESSES => index as u8,
        _ => NO_PROCESS,
    };
    CURRENTS[cpu].store(slot, Ordering::Release);
}

/// Index of the process currently running on this CPU. Caller must hold the
/// table lock (the slot is resolved through the process table).
fn current_index_unlocked() -> Option<usize> {
    current_on(current_cpu())
}

/// Currently running process on this CPU (caller holds [`PROCESS_LOCK`]).
fn current_unlocked() -> Option<ProcessId> {
    current_index_unlocked().map(ProcessId::from_index)
}

/// Currently running process on this CPU, if any.
pub fn current() -> Option<ProcessId> {
    with_table(current_unlocked)
}

/// Index of the process currently running on this CPU, if any.
pub fn current_index() -> Option<usize> {
    with_table(current_index_unlocked)
}

/// Run a closure on the current process handle table.
///
/// Returns `None` when there is no current process (kernel context) or while a
/// [`CurrentHandlesGuard`] owns the table (the slot then holds an empty
/// placeholder that must never be mistaken for the real table). Used by the
/// syscall layer for handle resolve/close without exposing the table itself
/// (Lead m00515). The process table lock is held for the duration of the
/// closure, so the closure must not take the VFS/ipc locks or run an object
/// destroy hook; work that needs hooks, VFS or page-cache calls must go through
/// [`take_current_handles`] instead.
pub fn with_current_handles<R>(f: impl FnOnce(&mut HandleTable) -> R) -> Option<R> {
    with_table(|| {
        let index = current_index_unlocked()?;
        // SAFETY: the table lock is held and current_index_unlocked only
        // returns live slots; the reference does not outlive this call.
        let process = unsafe { process_ref(index) }?;
        if process.handles_taken {
            // The real table is owned by a [`CurrentHandlesGuard`]; the slot
            // only holds an empty placeholder, which must never be handed to a
            // caller as if it were the process table.
            return None;
        }
        Some(f(&mut process.handles))
    })
}

/// RAII ownership of the current process's handle table (M6b2b).
///
/// [`take_current_handles`] moves the table out of the process slot **while
/// holding [`PROCESS_LOCK`]** and hands the ownership to the caller. The caller
/// then runs work that was previously forbidden inside the process lock —
/// `object::clear_handle_table`, `close_handle`/`close_payload`, `insert_new*`
/// (their destroy hooks), VFS closes, and any `wake_object` call — with the
/// process table lock **released**. Dropping the guard takes one short critical
/// section and puts the *same* table back into the *same* slot; handle
/// generations and numbers are therefore unchanged.
///
/// While the guard is alive the slot keeps an empty placeholder and
/// `handles_taken` is set:
/// * [`with_current_handles`] returns `None` instead of the placeholder,
/// * `wait`/`spawn` refuse to use the placeholder,
/// * a second [`take_current_handles`] is a loud API misuse (debug assertion)
///   and returns `None` instead of a second, silently empty table.
///
/// The guard is deliberately `!Send`/`!Sync`: it may only be used on the CPU
/// that is running the process whose table it owns. It must not be dropped
/// inside another `with_table` closure — `Drop` takes the process lock itself
/// and `IrqSpinLock` is not reentrant.
pub struct CurrentHandlesGuard {
    index: usize,
    /// `Some` until `Drop` moves it back into the process slot.
    table: Option<HandleTable>,
    /// Keeps the guard `!Send`/`!Sync` without tying it to a lifetime.
    _not_send: PhantomData<*const ()>,
}

impl CurrentHandlesGuard {
    /// Index of the process whose handle table this guard owns.
    pub fn process_index(&self) -> usize {
        self.index
    }

    /// Borrow the owned table (metadata reads).
    pub fn table(&self) -> &HandleTable {
        self.table
            .as_ref()
            .expect("the handle table is present until the guard is dropped")
    }

    /// Mutably borrow the owned table for `close`/`clear`/`insert` paths.
    pub fn table_mut(&mut self) -> &mut HandleTable {
        self.table
            .as_mut()
            .expect("the handle table is present until the guard is dropped")
    }
}

impl core::ops::Deref for CurrentHandlesGuard {
    type Target = HandleTable;

    fn deref(&self) -> &HandleTable {
        self.table()
    }
}

impl core::ops::DerefMut for CurrentHandlesGuard {
    fn deref_mut(&mut self) -> &mut HandleTable {
        self.table_mut()
    }
}

/// Take the current process's handle table out of its slot (see
/// [`CurrentHandlesGuard`] for the contract).
///
/// Returns `None` when there is no current process (kernel context) or when the
/// table is already owned by another guard. Once the guard is dropped the table
/// is back in the slot it came from, even on early `?`/error returns.
///
/// Reaping the current process is not possible in M6b2 (`reap` rejects it), so
/// the guard always wins against a concurrent reap: if the slot somehow
/// disappears, `Drop` releases the leftover table's references outside the lock
/// and trips a debug assertion instead of leaking or double-returning it.
pub fn take_current_handles() -> Option<CurrentHandlesGuard> {
    with_table(|| {
        let index = current_index_unlocked()?;
        // SAFETY: the table lock is held and `current_index_unlocked` only
        // returns live slots; the reference does not outlive this call.
        let process = unsafe { process_ref(index) }?;
        if process.handles_taken {
            // Misuse: the caller already holds a guard for this process. Never
            // hand out the empty placeholder as a second table — refuse instead.
            // Debug builds of the kernel trip loudly; host tests assert the
            // documented `None` so the refusal itself is covered.
            #[cfg(not(test))]
            debug_assert!(
                false,
                "current handle table taken twice on one CPU (nested guard)"
            );
            return None;
        }
        process.handles_taken = true;
        Some(CurrentHandlesGuard {
            index,
            table: Some(core::mem::take(&mut process.handles)),
            _not_send: PhantomData,
        })
    })
}

impl Drop for CurrentHandlesGuard {
    fn drop(&mut self) {
        let Some(table) = self.table.take() else {
            return;
        };
        // Short critical section: return the same table to the same slot. No
        // object/VFS work runs here, which keeps the lock order intact.
        let orphaned = with_table(|| match unsafe { process_ref(self.index) } {
            Some(process) if process.handles_taken => {
                process.handles = table;
                process.handles_taken = false;
                None
            }
            _ => Some(table),
        });
        if let Some(mut leftover) = orphaned {
            // The slot disappeared while the guard was alive. That is a caller
            // lifetime bug (the current process must not be reaped), but it
            // must not leak object references: clear the table outside the
            // lock, where the destroy hooks are allowed to run.
            debug_assert!(
                false,
                "a current-handle guard outlived the process whose table it owned"
            );
            let _ = object::clear_handle_table(&mut leftover);
        }
    }
}

// ---------------------------------------------------------------------------
// M7d: Linux personality, fd-table ownership and network namespace accessors
// ---------------------------------------------------------------------------

/// Release every fd in `table` (Linux exit/reap teardown).
///
/// `FdTable` has no bulk-close API on purpose: closing a fd drops its object
/// reference and may therefore run an object destroy hook. The caller must be
/// **outside** the process lock and outside every IPC/VFS lock; `reap` runs this
/// from its handle-release closure and `exit_current` after dropping the lock.
/// Returns the number of fds that were actually closed (holes are skipped).
fn release_all_fds(table: &mut FdTable) -> usize {
    let mut closed = 0;
    for fd in 0..crate::compat::linux::fd::MAX_FDS as u32 {
        if table.close(fd).is_ok() {
            closed += 1;
        }
    }
    closed
}

/// RAII ownership of the current process's Linux fd table (M7d).
///
/// Exactly the [`CurrentHandlesGuard`] contract, one table over: the table is
/// moved out of the process slot under [`PROCESS_LOCK`] so the Linux syscall
/// dispatcher can close/insert/dup fds **outside** the process lock (closing a
/// fd may run object destroy hooks and the VFS/IPC locks). The guard keeps the
/// slot marked `fds_taken`; every reader of `process.fds` must check the flag.
///
/// The guard is deliberately `!Send`/`!Sync` and must not be dropped inside a
/// `with_table` closure (`Drop` takes the process lock itself).
pub struct CurrentFdsGuard {
    index: usize,
    /// `Some` until `Drop` moves it back into the process slot.
    table: Option<FdTable>,
    /// Keeps the guard `!Send`/`!Sync` without tying it to a lifetime.
    _not_send: PhantomData<*const ()>,
}

impl CurrentFdsGuard {
    /// Index of the process whose fd table this guard owns.
    pub fn process_index(&self) -> usize {
        self.index
    }

    /// Borrow the owned fd table (read-only lookups).
    pub fn table(&self) -> &FdTable {
        self.table
            .as_ref()
            .expect("the fd table is present until the guard is dropped")
    }

    /// Mutably borrow the owned fd table for syscall dispatch.
    pub fn table_mut(&mut self) -> &mut FdTable {
        self.table
            .as_mut()
            .expect("the fd table is present until the guard is dropped")
    }
}

impl core::ops::Deref for CurrentFdsGuard {
    type Target = FdTable;

    fn deref(&self) -> &FdTable {
        self.table()
    }
}

impl core::ops::DerefMut for CurrentFdsGuard {
    fn deref_mut(&mut self) -> &mut FdTable {
        self.table_mut()
    }
}

/// Take the current process's Linux fd table out of its slot (M7d).
///
/// Returns `None` when there is no current process (kernel context), when the
/// current process is not a `Linux64` personality, or when the table is already
/// owned by another guard. Once the guard is dropped the table is back in the
/// slot it came from, even on early `?`/error returns.
///
/// **Exit contract:** the Linux `exit`/`exit_group` path must not run while the
/// entry layer holds this guard (`exit_current` never returns, so the guard
/// would never be dropped and its fd references would leak). The syscall entry
/// must special-case the exit numbers *before* taking the guard — or compat must
/// return a distinguishable outcome so the guard is dropped first.
pub fn take_current_fds() -> Option<CurrentFdsGuard> {
    with_table(|| {
        let index = current_index_unlocked()?;
        // SAFETY: the table lock is held and `current_index_unlocked` only
        // returns live slots; the reference does not outlive this call.
        let process = unsafe { process_ref(index) }?;
        if process.personality != Personality::Linux64 {
            return None;
        }
        if process.fds_taken {
            // Misuse: the caller already holds a guard for this process. Never
            // hand out the placeholder as a second table — refuse instead.
            #[cfg(not(test))]
            debug_assert!(
                false,
                "current fd table taken twice on one CPU (nested guard)"
            );
            return None;
        }
        process.fds_taken = true;
        Some(CurrentFdsGuard {
            index,
            table: Some(core::mem::take(&mut process.fds)),
            _not_send: PhantomData,
        })
    })
}

impl Drop for CurrentFdsGuard {
    fn drop(&mut self) {
        let Some(table) = self.table.take() else {
            return;
        };
        // Short critical section: return the same table to the same slot. No
        // object/VFS work runs here, which keeps the lock order intact.
        let orphaned = with_table(|| match unsafe { process_ref(self.index) } {
            Some(process) if process.fds_taken => {
                process.fds = table;
                process.fds_taken = false;
                None
            }
            _ => Some(table),
        });
        if let Some(mut leftover) = orphaned {
            // The slot disappeared while the guard was alive. The current
            // process must not be reaped, but if it happens the fd references
            // must not leak: close them outside the lock, where hooks may run.
            debug_assert!(
                false,
                "a current-fd guard outlived the process whose table it owned"
            );
            let _ = release_all_fds(&mut leftover);
        }
    }
}

/// Execution personality of the current process (M7d).
///
/// Kernel context (no current process) reports [`Personality::Native`], the
/// same behaviour the syscall entry had before personalities existed.
pub fn current_personality() -> Personality {
    with_table(|| unsafe {
        current_index_unlocked()
            .and_then(|index| process_ref(index))
            .map(|process| process.personality)
            .unwrap_or(Personality::Native)
    })
}

/// Network namespace handle of the current Linux process, if any (M7d).
///
/// Returns `None` for native processes, for a Linux process spawned without a
/// network namespace, and in kernel context.
pub fn current_linux_netns() -> Option<Handle> {
    with_table(|| unsafe {
        let index = current_index_unlocked()?;
        let process = process_ref(index)?;
        if process.personality != Personality::Linux64 {
            return None;
        }
        process.linux_netns
    })
}

/// Install a minimal "current process" that owns `table`, run `f`, then put the
/// slot back the way it was (normally empty).
///
/// Test-only: host tests have no running user process, so
/// [`take_current_handles`] would always return `None` and the guard path would
/// stay unexercised from other modules' tests. Callers must **not** hold the
/// object test lock themselves; this helper serialises itself and panics on a
/// nested install. After `f` returns (or unwinds) the helper releases any handle
/// still in the table, so destroy hooks run outside every lock.
#[cfg(test)]
pub(crate) fn test_with_current_handles<R>(table: HandleTable, f: impl FnOnce() -> R) -> R {
    use core::sync::atomic::{AtomicBool, Ordering};

    // Take the object test lock *before* touching the "already installed" flag:
    // two host test threads may call this helper concurrently, and the second
    // one must wait for the first (the flag then reads false again) instead of
    // panicking on a transient overlap.
    let _serial = crate::object::test_lock();
    static INSTALLED: AtomicBool = AtomicBool::new(false);
    if INSTALLED.swap(true, Ordering::SeqCst) {
        // Do not poison every later test: fail this one loudly and clean up.
        INSTALLED.store(false, Ordering::SeqCst);
        panic!("test_with_current_handles installed twice on one CPU");
    }

    // CPU 0, slot 0: the host has exactly one CPU and no user process of its own.
    const INDEX: usize = 0;
    debug_assert!(INDEX < MAX_PROCESSES);
    let previous = with_table(|| unsafe { (*slot_ptr(INDEX)).take() });
    let previous_current = current_on(0);
    let process = Process {
        state: ProcessState::Running,
        address_space: AddressSpaceId::INVALID,
        handles: table,
        handles_taken: false,
        personality: Personality::Native,
        signals: SignalState::new(),
        fs_base: 0,
        clear_child_tid: 0,
        fds: crate::compat::linux::fd::FdTable::new(),
        fds_taken: false,
        linux_netns: None,
        kernel_stack_top: 0,
        stack_frames: [0; KERNEL_STACK_FRAMES as usize],
        saved: core::ptr::null_mut(),
        exit_status: 0,
        exit_signal: None,
        process_object: object::ObjectId::MAX,
        parent: None,
        children: [NO_PROCESS; MAX_CHILDREN],
        wait_handle: Handle::INVALID,
        wait: WaitSpec::EMPTY,
        wake_reason: WakeReason::None,
        blocked_frame: FrameSlot::new(),
        cpu: AtomicU8::new(BSP_CPU),
        affinity: AtomicU8::new(DEFAULT_AFFINITY),
        migration: None,
    };
    with_table(|| unsafe { *slot_ptr(INDEX) = Some(process) });
    set_current_on(0, Some(INDEX));

    struct Restore {
        previous: Option<Process>,
        previous_current: Option<usize>,
    }
    impl Drop for Restore {
        fn drop(&mut self) {
            let leftover = with_table(|| {
                let slot = unsafe { &mut *slot_ptr(INDEX) };
                let leftover = slot.take().map(|mut process| {
                    if process.handles_taken {
                        // A guard escaped `f`; its table is the only real one.
                        debug_assert!(
                            false,
                            "a CurrentHandlesGuard outlived test_with_current_handles"
                        );
                        core::mem::take(&mut process.handles)
                    } else {
                        process.handles
                    }
                });
                *slot = self.previous.take();
                leftover
            });
            set_current_on(0, self.previous_current);
            if let Some(mut table) = leftover {
                // Release references (and run their hooks) outside the lock.
                let _ = object::clear_handle_table(&mut table);
            }
            INSTALLED.store(false, Ordering::SeqCst);
        }
    }
    let _restore = Restore {
        previous,
        previous_current,
    };
    f()
}

// ---------------------------------------------------------------------------
// VFS ownership
// ---------------------------------------------------------------------------

/// Owner id the VFS records for the process in `index`.
///
/// This is the slot id, which stays valid while the slot is being reaped:
/// unlike [`current_process_id`] it never refers to whichever process happens
/// to be on the CPU.
const fn teardown_pid(index: usize) -> u32 {
    ProcessId::from_index(index).raw() as u32
}

/// Release the VFS state a dead process still owns: POSIX file locks and
/// directory watches.
///
/// The `object` destroy hooks already closed each description before this runs
/// (which releases OFD locks, flocks and the per-description watch cleanup);
/// the per-owner tables are the backstop for state that never had a live
/// description left, e.g. a POSIX lock whose file was already unlinked.
///
/// Must not be called while holding the object table or the VFS lock: both
/// tables take their own paths and the ownership rules forbid nesting them.
fn close_vfs_ownership(pid: u32) -> usize {
    crate::vfs::close_process(pid)
}

/// Release the object references [`object::clear_handle_table`] parks in the
/// per-subsystem pending queues instead of releasing them inline.
///
/// `clear_handle_table` runs every last reference it owns through its destroy
/// hooks while it still holds the object-table cell, but the two subsystems
/// that would have to re-enter the table cannot do their work there: `ipc`
/// defers the `EventSubscription` references it observes and `vmobj` defers the
/// `SharedMemory` reference a released mapping holds, each into a small fixed
/// queue that a later drain empties. Nothing else drains those queues on the
/// process-exit paths, so a parked reference would keep its object (and, for
/// `SharedMemory`, its physical frames) alive past the process that owned it.
///
/// Both drains are idempotent and release through the normal handle path, so
/// calling this after every `clear_handle_table` is safe. It must run *outside*
/// the handle-table lock and after `clear_handle_table` has returned, because
/// the drains take the object table again.
///
/// Returns how many references the two subsystems released.
pub(crate) fn drain_pending_object_refs() -> usize {
    crate::ipc::release_subscription_pending() + crate::vmobj::release_pending()
}

/// ABI-facing id of the currently running process, if any.
///
/// The VFS records lock/watch ownership by this id, so the syscall layer needs
/// it when a user process names itself as an owner. Reaping uses the reaped
/// slot own id instead (see [`teardown_pid`]), never this one.
pub fn current_process_id() -> Option<u32> {
    with_table(|| current_index_unlocked().map(teardown_pid))
}

/// Record which process is running on **this** CPU. `sched` owns the call
/// order; the state field is updated by [`mark_running`].
///
/// Only the per-CPU atomic slot is written, so this needs no table lock: a CPU
/// may always name its own current process.
pub fn set_current_index(index: Option<usize>) {
    set_current_on(current_cpu(), index);
}

/// Address space of a live process. Caller must hold [`PROCESS_LOCK`].
fn address_space_unlocked(index: usize) -> AddressSpaceId {
    unsafe { process_ref(index) }
        .map(|process| process.address_space)
        .unwrap_or(AddressSpaceId::INVALID)
}

/// Address space of a live process.
pub fn address_space(index: usize) -> AddressSpaceId {
    with_table(|| address_space_unlocked(index))
}

/// Kernel stack top of a live process (16-byte aligned). Caller must hold
/// [`PROCESS_LOCK`].
fn kernel_stack_top_of_unlocked(index: usize) -> u64 {
    unsafe { process_ref(index) }
        .map(|process| process.kernel_stack_top)
        .unwrap_or(0)
}

/// Kernel stack top of a live process (16-byte aligned).
pub fn kernel_stack_top_of(index: usize) -> u64 {
    with_table(|| kernel_stack_top_of_unlocked(index))
}

/// User TLS base of a live process (0 for a dead slot). Caller must hold the
/// process table lock.
fn fs_base_unlocked(index: usize) -> u64 {
    unsafe { process_ref(index) }
        .map(|process| process.fs_base)
        .unwrap_or(0)
}

/// User TLS base of a live process.
pub fn fs_base(index: usize) -> u64 {
    with_table(|| fs_base_unlocked(index))
}

/// User TLS base of the current process (0 when there is none).
///
/// The compat `arch_prctl(ARCH_GET_FS)` handler reads this instead of the MSR
/// so it observes the value the process actually registered even between
/// context switches.
pub fn current_fs_base() -> u64 {
    with_table(|| current_index_unlocked().map(fs_base_unlocked).unwrap_or(0))
}

/// Store `base` as the current process's user TLS base and apply it to the
/// live MSR immediately.
///
/// `arch_prctl(ARCH_SET_FS)` calls this; the stored value is what
/// `sched::activate_user_context` restores when the process is switched in
/// again. Returns [`ProcessError::NoSuchProcess`] in kernel context (there is
/// no user TLS to set).
pub fn set_current_fs_base(base: u64) -> Result<(), ProcessError> {
    with_table(|| {
        let index = current_index_unlocked().ok_or(ProcessError::NoSuchProcess)?;
        let process = unsafe { process_ref(index) }.ok_or(ProcessError::NoSuchProcess)?;
        process.fs_base = base;
        Ok(())
    })?;
    // Host tests cannot execute WRMSR; they assert the stored field.
    #[cfg(not(test))]
    crate::arch::set_user_fs_base(base);
    Ok(())
}

/// Record the current process's `clear_child_tid` address and return its Linux
/// pid, which is what `set_tid_address` must return (0 in kernel context).
///
/// `address == 0` is a valid request: it clears a previously registered
/// address (the kernel then has nothing to clear on exit).
pub fn set_current_clear_child_tid(address: u64) -> u64 {
    with_table(|| {
        let Some(index) = current_index_unlocked() else {
            return 0;
        };
        let Some(process) = (unsafe { process_ref(index) }) else {
            return 0;
        };
        process.clear_child_tid = address;
        u64::from(linux_pid(ProcessId::from_index(index)))
    })
}

/// Address registered by [`set_current_clear_child_tid`] for a live process
/// (0 when unset or dead). Used by the exit path and by host tests.
pub fn clear_child_tid(index: usize) -> u64 {
    with_table(|| {
        unsafe { process_ref(index) }
            .map(|process| process.clear_child_tid)
            .unwrap_or(0)
    })
}

/// Saved resume frame (ring-3 or first ring-3 frame) of a live process.
pub fn saved_frame(index: usize) -> *mut TrapFrame {
    with_table(|| {
        unsafe { process_ref(index) }
            .map(|process| process.saved)
            .unwrap_or(core::ptr::null_mut())
    })
}

/// Record the frame a process must resume from.
pub fn set_saved_frame(index: usize, frame: *mut TrapFrame) {
    with_table(|| {
        if let Some(process) = unsafe { process_ref(index) } {
            process.saved = frame;
        }
    });
}

/// True when `frame` is exactly the trap frame of the kernel stack of `index`.
///
/// The entry stub plus the 5 qwords the CPU pushes place every ring-3 trap
/// frame at [`first_frame_addr`], so this is an equality check, not a range
/// check. Caller must hold [`PROCESS_LOCK`].
fn frame_belongs_to_unlocked(index: usize, frame: *mut TrapFrame) -> bool {
    let top = kernel_stack_top_of_unlocked(index);
    top != 0 && !frame.is_null() && frame as u64 == first_frame_addr(top)
}

/// True when `frame` is exactly the trap frame of the kernel stack of `index`.
pub fn frame_belongs_to(index: usize, frame: *mut TrapFrame) -> bool {
    with_table(|| frame_belongs_to_unlocked(index, frame))
}

/// Address of the copied `syscall` frame slot of a live process (0 if none).
/// Caller must hold [`PROCESS_LOCK`].
fn blocked_frame_addr_unlocked(index: usize) -> u64 {
    unsafe { process_ref(index) }
        .map(|process| process.blocked_frame.as_frame() as u64)
        .unwrap_or(0)
}

/// Address of the copied `syscall` frame slot of a live process (0 if none).
pub fn blocked_frame_addr(index: usize) -> u64 {
    with_table(|| blocked_frame_addr_unlocked(index))
}

/// True when `frame` is a frame this process may be resumed from.
///
/// Two geometries are legal: the ring3 first frame at [`first_frame_addr`] (an
/// ordinary interrupt frame, or a never-blocked process) and the copied
/// `syscall` frame of a process that blocked and was woken. The check stays
/// exact (equality, never a range) so a corrupted `saved` pointer is still
/// caught. Caller must hold [`PROCESS_LOCK`].
fn frame_resumable_unlocked(index: usize, frame: *mut TrapFrame) -> bool {
    if frame.is_null() {
        return false;
    }
    if frame_belongs_to_unlocked(index, frame) {
        return true;
    }
    let slot = blocked_frame_addr_unlocked(index);
    slot != 0 && frame as u64 == slot
}

/// True when `frame` is a frame this process may be resumed from.
pub fn frame_resumable(index: usize, frame: *mut TrapFrame) -> bool {
    with_table(|| frame_resumable_unlocked(index, frame))
}

/// Verify the canary at `top - 8` is intact. Caller must hold [`PROCESS_LOCK`].
fn kernel_stack_ok_unlocked(index: usize) -> bool {
    let top = kernel_stack_top_of_unlocked(index);
    if top == 0 {
        return false;
    }
    let value = unsafe { ((top - KERNEL_STACK_TOP_RESERVED) as *const u64).read_volatile() };
    value == KERNEL_STACK_CANARY
}

/// Verify the canary at `top - 8` is intact.
pub fn kernel_stack_ok(index: usize) -> bool {
    with_table(|| kernel_stack_ok_unlocked(index))
}

/// Mark a process Running on `cpu` and book a pending migration that has now
/// really happened. Caller must hold [`PROCESS_LOCK`].
///
/// The recorded CPU is what a wake compares against. A pending migration is
/// only counted when the process is resumed on its **target** CPU, and exactly
/// once: resuming it on the source instead cancels the pending record, so a
/// request that never took effect is never reported as a migration.
fn mark_running_on_unlocked(index: usize, cpu: usize) {
    if let Some(process) = unsafe { process_ref(index) } {
        process.state = ProcessState::Running;
        process.cpu.store(cpu as u8, Ordering::Release);
        if let Some(pending) = process.migration {
            if cpu == pending.target_cpu as usize && cpu != pending.source_cpu as usize {
                match pending.reason {
                    MigrationReason::Affinity => {
                        MIGRATIONS.fetch_add(1, Ordering::AcqRel);
                    }
                    MigrationReason::Balance => {
                        BALANCES.fetch_add(1, Ordering::AcqRel);
                    }
                }
                process.migration = None;
            } else if cpu == pending.source_cpu as usize {
                // Resumed where it already was: the migration never happened.
                process.migration = None;
            }
        }
    }
}

fn mark_running_unlocked(index: usize) {
    mark_running_on_unlocked(index, current_cpu());
}

/// Mark a process Running and record the CPU that owns it.
pub fn mark_running(index: usize) {
    with_table(|| mark_running_unlocked(index));
}

/// Host-tests only: resume `index` on an explicit CPU without switching.
#[cfg(test)]
pub(crate) fn test_mark_running_on(index: usize, cpu: usize) {
    with_table(|| mark_running_on_unlocked(index, cpu));
}

/// CPU that owns `pid` (the CPU that last resumed it or that its ready queue
/// belongs to), or `None` when the process is not live.
pub fn process_cpu(pid: ProcessId) -> Option<usize> {
    with_table(|| {
        unsafe { process_ref(pid.index()) }
            .map(|process| process.cpu.load(Ordering::Acquire) as usize)
    })
}

/// Mark a process Ready (it is being descheduled) and queue it on its CPU.
pub fn park(index: usize) {
    with_table(|| {
        if let Some(process) = unsafe { process_ref(index) } {
            if process.state == ProcessState::Running {
                let cpu = process.cpu.load(Ordering::Acquire) as usize;
                let cpu = if cpu < crate::arch::MAX_CPUS {
                    cpu
                } else {
                    BSP_CPU as usize
                };
                queue_remove_unlocked(index);
                process.state = ProcessState::Ready;
                queue_push_unlocked(index, cpu);
            }
        }
    });
}

/// Round-robin pick of the next `Ready` process after `from`. Caller must hold
/// [`PROCESS_LOCK`].
///
/// This is the single-CPU legacy view: it only reads states, so two CPUs calling
/// it could both run the same process. SMP schedulers use [`claim_next_on`].
fn choose_next_unlocked(from: Option<usize>) -> Option<usize> {
    let mut states = [0u8; MAX_PROCESSES];
    for (index, state) in states.iter_mut().enumerate() {
        *state = unsafe { process_ref(index) }
            .map(|process| process.state.as_u8())
            .unwrap_or(NO_PROCESS);
    }
    choose_next_state(&states, from)
}

/// Round-robin pick of the next `Ready` process after `from`.
///
/// Kept for the single-CPU paths; SMP schedulers must use [`claim_next_on`].
pub fn choose_next(from: Option<usize>) -> Option<usize> {
    with_table(|| choose_next_unlocked(from))
}

// ---------------------------------------------------------------------------
// M6b2: per-CPU ready queues, claims, affinity and migration
// ---------------------------------------------------------------------------

/// Claim the next runnable process for `cpu`, transitioning it to `Running`.
///
/// Selection and the `Ready -> Running` transition happen inside **one**
/// [`PROCESS_LOCK`] critical section, so two CPUs cannot claim the same process:
/// the queue bit is consumed by whoever gets there first. `from` is the process
/// that just left this CPU (round-robin start), or `None` to start at slot 0.
/// A queued process whose affinity no longer allows `cpu` is moved to its first
/// online CPU (and that CPU gets a reschedule request) instead of running here.
pub fn claim_next_on(cpu: usize, from: Option<usize>) -> Option<usize> {
    with_table(|| claim_next_on_unlocked(cpu, from))
}

fn claim_next_on_unlocked(cpu: usize, from: Option<usize>) -> Option<usize> {
    debug_assert!(
        PROCESS_LOCK.is_locked(),
        "claim_next_on requires PROCESS_LOCK"
    );
    if cpu >= crate::arch::MAX_CPUS {
        return None;
    }
    if queue_len_unlocked(cpu) == 0 {
        // Nothing queued here: a claim would scan every slot for stale bits only.
        return None;
    }
    let start = from.map(|last| (last + 1) % MAX_PROCESSES).unwrap_or(0);
    for step in 0..MAX_PROCESSES {
        let index = (start + step) % MAX_PROCESSES;
        if unsafe { *ready_queue_ptr(cpu) } & (1u32 << index) == 0 {
            continue;
        }
        let Some(process) = (unsafe { process_ref(index) }) else {
            // Stale bit for a slot that no longer holds a process.
            unsafe { *ready_queue_ptr(cpu) &= !(1u32 << index) };
            continue;
        };
        if process.state != ProcessState::Ready {
            // Kept queued only while Ready; clean up a stale bit defensively.
            unsafe { *ready_queue_ptr(cpu) &= !(1u32 << index) };
            continue;
        }
        let affinity = process.affinity.load(Ordering::Acquire);
        if !affinity_allows(affinity, cpu as u8) {
            // Enqueued here before the affinity was narrowed: move it rather
            // than starve it. The move keeps the queue invariant "one bit".
            unsafe { *ready_queue_ptr(cpu) &= !(1u32 << index) };
            if let Some(target) = first_online_affinity_cpu(affinity) {
                process.cpu.store(target, Ordering::Release);
                queue_push_unlocked(index, target as usize);
                if target as usize != current_cpu() {
                    request_resched_unlocked(target as usize);
                }
            }
            continue;
        }
        // SAFETY: `index` is in range, the process is live and the lock is held.
        unsafe { *ready_queue_ptr(cpu) &= !(1u32 << index) };
        // The claim *is* the target CPU resuming the process, so this is where a
        // pending migration is booked (never in `migrate`/`rebalance`).
        mark_running_on_unlocked(index, cpu);
        return Some(index);
    }
    None
}

/// Make `index` `Ready` and put it on the ready queue of `cpu`.
///
/// If `cpu` is out of range or no longer allowed by the process's affinity the
/// first online allowed CPU is used instead. Returns nothing; a dead slot is a
/// no-op so scheduling loops stay total.
pub fn enqueue_ready(index: usize, cpu: usize) {
    with_table(|| enqueue_ready_unlocked(index, cpu));
}

fn enqueue_ready_unlocked(index: usize, cpu: usize) {
    let Some(process) = (unsafe { process_ref(index) }) else {
        return;
    };
    if process.state == ProcessState::Zombie {
        return;
    }
    let affinity = process.affinity.load(Ordering::Acquire);
    let target = if cpu < crate::arch::MAX_CPUS && affinity_allows(affinity, cpu as u8) {
        cpu
    } else {
        first_online_affinity_cpu(affinity)
            .map(|c| c as usize)
            .unwrap_or(cpu.min(crate::arch::MAX_CPUS - 1))
    };
    queue_remove_unlocked(index);
    process.state = ProcessState::Ready;
    process.cpu.store(target as u8, Ordering::Release);
    debug_assert!(
        !queue_contains_unlocked(index, target),
        "enqueue_ready queued a process on a CPU that already had its bit"
    );
    queue_push_unlocked(index, target);
    if target != current_cpu() {
        request_resched_unlocked(target);
    }
}

/// Park a running process and queue it on `cpu` (its new owner).
pub fn park_to_queue(index: usize, cpu: usize) {
    with_table(|| {
        if unsafe { process_ref(index) }.map(|process| process.state) == Some(ProcessState::Running)
        {
            enqueue_ready_unlocked(index, cpu);
        }
    });
}

/// Narrow the CPUs a process may run on.
///
/// `mask` must be a non-zero subset of [`CPU_MASK_ALL`]. A `Ready` process that
/// was queued on a now-disallowed CPU is moved to its first online CPU, which is
/// asked to reschedule. A running process keeps running until it is parked.
/// Takes a slot index, matching the root/sched call sites already wired.
pub fn set_affinity(index: usize, mask: u8) -> Result<(), ProcessError> {
    with_table(|| set_affinity_unlocked(index, mask))
}

fn set_affinity_unlocked(index: usize, mask: u8) -> Result<(), ProcessError> {
    let Some(process) = (unsafe { process_ref(index) }) else {
        return Err(ProcessError::NoSuchProcess);
    };
    if process.state == ProcessState::Zombie {
        return Err(ProcessError::NoSuchProcess);
    }
    if mask == 0 || mask & !CPU_MASK_ALL != 0 {
        return Err(ProcessError::BadRequest);
    }
    process.affinity.store(mask, Ordering::Release);
    if process.state == ProcessState::Ready {
        if let Some(queued_on) = queue_remove_unlocked(index) {
            let target = if affinity_allows(mask, queued_on as u8) {
                queued_on
            } else {
                match first_online_affinity_cpu(mask) {
                    Some(cpu) => cpu as usize,
                    None => queued_on,
                }
            };
            process.cpu.store(target as u8, Ordering::Release);
            queue_push_unlocked(index, target);
            if target != current_cpu() {
                request_resched_unlocked(target);
            }
        }
    }
    Ok(())
}

/// Take the pending-reschedule mask, clearing it: bit `c` was set by a remote
/// wake (or migration) that needs CPU `c` to reschedule. The caller
/// (`sched`/root) owns turning the bits into IPIs; this module never does.
pub fn drain_resched_mask() -> u32 {
    with_table(|| RESCHED_PENDING.swap(0, Ordering::AcqRel))
}

/// Whether `cpu` has a pending reschedule request (without draining it).
pub fn resched_pending(cpu: usize) -> bool {
    cpu < crate::arch::MAX_CPUS && RESCHED_PENDING.load(Ordering::Acquire) & (1u32 << cpu) != 0
}

/// Current state of `pid`, or `None` when the slot is not live.
pub fn process_state(pid: ProcessId) -> Option<ProcessState> {
    with_table(|| unsafe { process_ref(pid.index()) }.map(|process| process.state))
}

/// Affinity mask of `index`, or `None` when the slot is not live.
pub fn affinity(index: usize) -> Option<u8> {
    with_table(|| {
        unsafe { process_ref(index) }.map(|process| process.affinity.load(Ordering::Acquire))
    })
}

/// Number of wakes that had to enqueue a process on a different CPU than the one
/// that woke it (each one raised that CPU's reschedule bit).
pub fn remote_wakes() -> u64 {
    REMOTE_WAKES.load(Ordering::Acquire)
}

/// `(migrations, balances)` counted when the target CPU actually resumed the
/// process. A migration requested on an already-remote CPU but resumed back on
/// its source is not counted. `w3` aggregates these into `SmpStats`.
pub fn migration_counts() -> (u64, u64) {
    (
        MIGRATIONS.load(Ordering::Acquire),
        BALANCES.load(Ordering::Acquire),
    )
}

/// Compatibility alias for [`migration_counts`], kept while `sched` (w3) moves
/// to the root-facing name. New callers use [`migration_counts`].
pub fn migration_stats() -> (u64, u64) {
    migration_counts()
}

/// Assigned load of one CPU: every non-zombie process whose recorded owner is
/// that CPU, regardless of whether it is `Running`, `Ready` or `Blocked`.
///
/// A `Blocked` process cannot be claimed right now, but it still represents work
/// the CPU owns: its wake enqueues it on that CPU again. Counting it keeps
/// [`rebalance`] from treating an idle-looking CPU that owns two sleeping workers
/// as empty (Lead m00710). Caller holds [`PROCESS_LOCK`].
fn load_on_cpu_unlocked(cpu: usize) -> usize {
    if cpu >= crate::arch::MAX_CPUS {
        return usize::MAX;
    }
    let mut load = 0;
    for_each_live(|_, process| {
        if process.state != ProcessState::Zombie
            && process.cpu.load(Ordering::Acquire) as usize == cpu
        {
            load += 1;
        }
    });
    load
}

/// Move `index` to `target` for `reason` (caller holds [`PROCESS_LOCK`]).
///
/// `Ready` processes are moved between ready queues; `Blocked` processes only
/// record the new owner, so their wake enqueues them on the target directly.
/// Running processes are refused: they must be parked (or migrate themselves on
/// their next scheduling point) before they can change CPU.
fn migrate_to_unlocked(
    index: usize,
    target: usize,
    reason: MigrationReason,
) -> Result<(), ProcessError> {
    let Some(process) = (unsafe { process_ref(index) }) else {
        return Err(ProcessError::NoSuchProcess);
    };
    if process.state == ProcessState::Zombie {
        return Err(ProcessError::NoSuchProcess);
    }
    if target >= crate::arch::MAX_CPUS || target >= online_cpu_count() {
        return Err(ProcessError::BadRequest);
    }
    let affinity = process.affinity.load(Ordering::Acquire);
    if !affinity_allows(affinity, target as u8) {
        return Err(ProcessError::BadRequest);
    }
    let source = process.cpu.load(Ordering::Acquire);
    if source == target as u8 {
        return Ok(());
    }
    match process.state {
        ProcessState::Running => return Err(ProcessError::BadRequest),
        ProcessState::Ready => {
            queue_remove_unlocked(index);
            queue_push_unlocked(index, target);
        }
        ProcessState::Blocked | ProcessState::Zombie => {}
    }
    process.cpu.store(target as u8, Ordering::Release);
    process.migration = Some(PendingMigration {
        source_cpu: source,
        target_cpu: target as u8,
        reason,
    });
    request_resched_unlocked(target);
    Ok(())
}

/// Move `index` to `target` for an explicit affinity reason.
///
/// The matching `migrations` counter is only bumped when the target CPU really
/// resumes the process in ring 3 (see [`mark_running`]); asking twice before
/// that just refreshes the pending record.
pub fn migrate(pid: ProcessId, target: usize) -> Result<(), ProcessError> {
    with_table(|| migrate_to_unlocked(pid.index(), target, MigrationReason::Affinity))
}

/// Move `index` to the least loaded online CPU allowed by its affinity.
///
/// Load is the *assigned* load of that CPU — every non-zombie process owned by
/// it, counting `Running`, `Ready` and `Blocked` alike (see
/// [`load_on_cpu_unlocked`]) — so a CPU owning two sleeping workers is not
/// mistaken for an idle one. Candidates are the online APs only: CPU 0 (BSP) is
/// reserved for root/monitor work and never receives an automatic balance
/// migration. Only `Ready`/`Blocked` processes can be rebalanced.
/// Returns the CPU the process was assigned to; the source CPU is returned
/// unchanged when no other CPU is both allowed and strictly less loaded. The
/// `balances` counter is booked when the target actually resumes the process,
/// never here.
pub fn rebalance(pid: ProcessId) -> Result<usize, ProcessError> {
    let index = pid.index();
    with_table(|| {
        let Some(process) = (unsafe { process_ref(index) }) else {
            return Err(ProcessError::NoSuchProcess);
        };
        if process.state == ProcessState::Zombie {
            return Err(ProcessError::NoSuchProcess);
        }
        if process.state == ProcessState::Running {
            return Err(ProcessError::BadRequest);
        }
        let affinity = process.affinity.load(Ordering::Acquire);
        let source = process.cpu.load(Ordering::Acquire) as usize;
        let online = online_cpu_count();
        let mut best: Option<(usize, usize)> = None;
        // CPU 0 (BSP) is reserved for root/monitor work and never receives an
        // automatic balance migration (Lead m00783): only online APs (cpu >= 1)
        // are candidates. Otherwise an idle BSP would always win the tie and
        // starve the APs the closeout script wants the workers spread over.
        for cpu in 1..online {
            if cpu == source || !affinity_allows(affinity, cpu as u8) {
                continue;
            }
            let load = load_on_cpu_unlocked(cpu);
            if best.map(|(best_load, _)| load < best_load).unwrap_or(true) {
                best = Some((load, cpu));
            }
        }
        let Some((best_load, target)) = best else {
            return Ok(source);
        };
        if best_load >= load_on_cpu_unlocked(source) {
            return Ok(source);
        }
        migrate_to_unlocked(index, target, MigrationReason::Balance)?;
        Ok(target)
    })
}

/// Number of occupied process slots.
///
/// Zombies count as occupied: their slot, kernel stack and address space are
/// still there until [`reap`] / [`reap_orphans`] releases them. In particular
/// the last user process of a boot (the one `complete_m4` keeps mapped for the
/// closing deliberate fault) keeps counting after it exits, so a caller that
/// only cares about runnable processes must look at [`process_state`] instead.
pub fn live_count() -> usize {
    with_table(live_count_unlocked)
}

fn live_count_unlocked() -> usize {
    let mut count = 0;
    for_each_live(|_, _| count += 1);
    count
}

/// True when no process can ever run again (all live ones are zombies).
pub fn all_zombie() -> bool {
    with_table(all_zombie_unlocked)
}

fn all_zombie_unlocked() -> bool {
    let mut any = false;
    for index in 0..MAX_PROCESSES {
        if let Some(process) = unsafe { process_ref(index) } {
            any = true;
            if process.state != ProcessState::Zombie {
                return false;
            }
        }
    }
    any
}

/// Exit status of the most recently exited process (for `complete_m4`).
pub fn last_exit_status() -> u64 {
    with_table(last_exit_status_unlocked)
}

fn last_exit_status_unlocked() -> u64 {
    if let Some(current) = current_index_unlocked() {
        if let Some(process) = unsafe { process_ref(current) } {
            if process.state == ProcessState::Zombie {
                return process.exit_status;
            }
        }
    }
    for index in (0..MAX_PROCESSES).rev() {
        if let Some(process) = unsafe { process_ref(index) } {
            return process.exit_status;
        }
    }
    0
}

/// Exit status of one specific process, once it has exited.
///
/// Read-only and lock-protected. Returns `Some(status)` only while the slot is
/// still occupied by `pid` **and** the process is a `Zombie` (exited but not
/// reaped yet); `None` means the slot is empty, holds another process, or `pid`
/// has not exited. This is the per-pid counterpart of [`last_exit_status`],
/// which answers for the *current* boot processor's process and therefore
/// cannot observe a detached process that exited on an AP.
pub fn exit_status(pid: ProcessId) -> Option<u64> {
    with_table(|| {
        let process = unsafe { process_ref(pid.index()) }?;
        if process.state == ProcessState::Zombie {
            Some(process.exit_status)
        } else {
            None
        }
    })
}

/// Reap one detached (`parent == None`) zombie by pid (M6c closeout).
///
/// Returns `false` when the slot is empty, still running, has a parent (that
/// path goes through [`wait`]), or belongs to the process the *calling* CPU is
/// executing: the last user process of a boot stays mapped for the closing
/// deliberate fault and must not be reaped. The heavy release (handles, drain,
/// VFS ownership, kernel stack, address space) runs outside [`PROCESS_LOCK`]
/// through [`reap`], so a successful call implies the slot is gone.
pub fn reap_orphan(pid: ProcessId) -> bool {
    let index = pid.index();
    if index >= MAX_PROCESSES {
        return false;
    }
    let orphan = with_table(|| match unsafe { process_ref(index) } {
        Some(process) => process.state == ProcessState::Zombie && process.parent.is_none(),
        None => false,
    });
    if !orphan {
        return false;
    }
    unsafe { reap(index) }.is_ok()
}

// ---------------------------------------------------------------------------
// Failure handling (never returns)
// ---------------------------------------------------------------------------

/// Print a loud M4 failure and halt.
unsafe fn fail(message: &str) -> ! {
    klog!("[CaelumKernel] M4 FAIL {message}");
    halt()
}

#[cfg(test)]
mod tests {

    // Test-side table accessors: each one takes the process table lock for the
    // duration of the access. Host tests are single-threaded (serialized by
    // `global_lock`), so the returned pointer/reference is used immediately and
    // never escapes the test body.
    fn test_process_ptr(index: usize) -> *mut Process {
        with_table(|| unsafe { process_ptr(index) })
    }

    fn test_slot_ptr(index: usize) -> *mut Option<Process> {
        with_table(|| unsafe { slot_ptr(index) })
    }

    fn test_process_ref(index: usize) -> Option<&'static mut Process> {
        with_table(|| unsafe { process_ref(index) })
    }

    fn test_current_on(cpu: usize) -> Option<usize> {
        with_table(|| current_on(cpu))
    }
    use super::*;

    /// A 16-byte aligned scratch buffer big enough for one TrapFrame.
    #[repr(C, align(16))]
    struct FrameBuffer([u64; 24]);

    impl FrameBuffer {
        fn new() -> Self {
            FrameBuffer([0; 24])
        }

        fn as_frame(&mut self) -> *mut TrapFrame {
            self.0.as_mut_ptr().cast::<TrapFrame>()
        }
    }

    #[test]
    fn stack_geometry_matches_the_frozen_layout() {
        for index in 0..MAX_PROCESSES {
            let base = KERNEL_STACK_BASES[index];
            let top = kernel_stack_top(index);
            assert_eq!(top, base + KERNEL_STACK_BYTES);
            assert_eq!(top % 16, 0);
            // guard page directly below the base, unmapped
            assert_eq!(base % 4096, 0);
            let frame = first_frame_addr(top);
            // RSP0 is top - 8, but the CPU aligns it down to top - 16 before it
            // pushes the 40-byte hardware frame; 40 + 136 puts the frame here.
            assert_eq!(frame, top - 192);
            assert_eq!(frame + FRAME_BYTES, top - 16);
            assert_eq!(top - KERNEL_STACK_TOP_RESERVED & !0xF, frame + FRAME_BYTES);
            // The top canary/scratch qword must stay outside the frame.
            assert!(frame + FRAME_BYTES <= top - KERNEL_STACK_TOP_RESERVED);
            // The aligned frame itself is 16-byte aligned (the naive top - 184
            // placement was 8 mod 16); the ring3 entry `rsp` comes from the
            // `user_rsp` slot, which `init_user_frame` fills with the aligned
            // user stack top.
            assert_eq!(frame % 16, 0);
            assert_eq!(frame + crate::arch::traps::Q_USER_RSP as u64 * 8, top - 32);
            assert_eq!(frame + crate::arch::traps::Q_USER_SS as u64 * 8, top - 24);
        }
        assert_eq!(KERNEL_STACK_BASES[0], 0xFFFF_FFFF_8150_0000);
        assert_eq!(KERNEL_STACK_BASES[1], 0xFFFF_FFFF_8160_0000);
        assert_eq!(KERNEL_STACK_BASES[2], 0xFFFF_FFFF_8170_0000);
        assert_eq!(KERNEL_STACK_BASES[3], 0xFFFF_FFFF_8120_0000);
    }

    #[test]
    fn the_first_frame_sits_where_the_hardware_will_push() {
        // Regression for the first-user-tick `M3 FAIL stack corrupt`: the
        // hardware aligns RSP0 (top - 8) down to 16 bytes before pushing, so
        // the interrupt frame is 8 bytes *below* the naive top - 184 layout.
        let top = kernel_stack_top(0);
        let frame = first_frame_addr(top);
        let hardware_frame = ((top - KERNEL_STACK_TOP_RESERVED) & !0xF) - FRAME_BYTES;
        assert_eq!(frame, hardware_frame);
        assert_eq!(frame, top - 192, "the naive top - 184 placement is wrong");
        // The canary qword at the very top is never part of the frame.
        assert!(frame + FRAME_BYTES < top - KERNEL_STACK_TOP_RESERVED);
    }

    #[test]
    fn first_frame_is_a_valid_ring3_frame() {
        let mut buffer = FrameBuffer::new();
        let frame = buffer.as_frame();
        unsafe {
            write_first_frame(
                frame,
                0x0000_0000_0040_1000,
                0x0000_0000_0080_0000,
                7,
                9,
                11,
            )
        };
        let frame_ref = unsafe { &*frame };
        assert_eq!(frame_ref.rip, 0x0000_0000_0040_1000);
        assert_eq!(frame_ref.cs, crate::arch::gdt::USER_CS as u64);
        assert_eq!(frame_ref.user_ss, crate::arch::gdt::USER_DS as u64);
        assert_eq!(frame_ref.user_rsp, 0x0000_0000_0080_0000);
        assert_eq!(frame_ref.user_ss, 0x23);
        assert_eq!(frame_ref.rflags & 0x2, 0x2);
        // The three entry arguments are the frozen native entry ABI.
        assert_eq!(frame_ref.rdi, 7);
        assert_eq!(frame_ref.rsi, 9);
        assert_eq!(frame_ref.rdx, 11);
        assert_eq!(frame_ref.vector, 0);
        assert_eq!(frame_ref.error_code, 0);
        // 22 qwords: the last two hold the ring-3 rsp/ss.
        assert_eq!(core::mem::size_of::<TrapFrame>(), 22 * 8);
    }

    #[test]
    fn round_robin_selection_skips_zombies_and_the_current_process() {
        let ready = ProcessState::Ready.as_u8();
        let running = ProcessState::Running.as_u8();
        let zombie = ProcessState::Zombie.as_u8();

        // Both ready: alternate.
        assert_eq!(choose_next_state(&[ready, ready], Some(0)), Some(1));
        assert_eq!(choose_next_state(&[ready, ready], Some(1)), Some(0));
        // First pick starts at slot 0.
        assert_eq!(choose_next_state(&[ready, ready], None), Some(0));
        // Running current is never re-picked while another is ready.
        assert_eq!(choose_next_state(&[running, ready], Some(0)), Some(1));
        // Zombie is skipped.
        assert_eq!(choose_next_state(&[zombie, ready], Some(0)), Some(1));
        assert_eq!(choose_next_state(&[ready, zombie], Some(1)), Some(0));
        // Nothing runnable.
        assert_eq!(choose_next_state(&[running, zombie], Some(0)), None);
        assert_eq!(choose_next_state(&[zombie, zombie], None), None);
        assert_eq!(choose_next_state(&[], None), None);
    }

    #[test]
    fn wait_decides_on_zombie_only() {
        assert_eq!(
            wait_decision(ProcessState::Zombie.as_u8(), 42),
            WaitDecision::Exited(42)
        );
        assert_eq!(
            wait_decision(ProcessState::Ready.as_u8(), 0),
            WaitDecision::Blocked
        );
        assert_eq!(
            wait_decision(ProcessState::Running.as_u8(), 0),
            WaitDecision::Blocked
        );
    }

    #[test]
    fn handle_transfer_rights_can_only_shrink() {
        assert!(rights_fit_in(Rights::READ, Rights::READ | Rights::WRITE));
        assert!(rights_fit_in(Rights::NONE, Rights::WAIT));
        assert!(!rights_fit_in(Rights::WRITE, Rights::READ));
        assert!(!rights_fit_in(Rights::ALL, Rights::WAIT));
    }

    #[test]
    fn child_entry_args_are_the_first_three_handle_slots() {
        // Creating Console/Random objects touches the global object table, so
        // this test shares `object::test_lock()` with the object tests.
        let _guard = global_lock();
        // Build the expected frozen values for slot 0 / 1 / 2, generation 1.
        // In production slot 2 is the transferred `ChannelB` endpoint (the
        // M6a2 `ipc_recv(channel_b)` argument); the mapping is kind-agnostic,
        // so a third Console handle exercises exactly the same path without
        // reaching into the ipc destroy-hook state from a process test.
        let mut table = HandleTable::new();
        let console = object::insert_new(&mut table, ObjectKind::Console, Rights::READ)
            .expect("console object");
        let random = object::insert_new(&mut table, ObjectKind::Random, Rights::READ)
            .expect("random object");
        let channel_b = object::insert_new(&mut table, ObjectKind::Console, Rights::READ)
            .expect("third handle");
        assert_eq!(console.raw(), 0x0001_0001);
        assert_eq!(random.raw(), 0x0001_0002);
        assert_eq!(channel_b.raw(), 0x0001_0003);
        let args = child_entry_args(&table);
        assert_eq!(args, [0x0001_0001, 0x0001_0002, 0x0001_0003]);
        object::clear_handle_table(&mut table);
    }

    #[test]
    fn child_entry_args_zero_fill_the_slots_the_request_did_not_use() {
        let _guard = global_lock();
        // Two transfers fill `rdi` / `rsi` only: `rdx` must be 0, exactly like
        // init's third argument, instead of a stale or fabricated handle value.
        let mut table = HandleTable::new();
        object::insert_new(&mut table, ObjectKind::Console, Rights::READ).expect("console object");
        object::insert_new(&mut table, ObjectKind::Random, Rights::READ).expect("random object");
        assert_eq!(child_entry_args(&table), [0x0001_0001, 0x0001_0002, 0]);
        object::clear_handle_table(&mut table);
    }

    #[test]
    fn init_entry_args_keep_the_two_documented_handles_and_a_zero_third() {
        let _guard = global_lock();
        // Init owns exactly Console + Random (frozen by w6); its third entry
        // argument is 0 so `rdx` never names an object init does not hold.
        let mut table = HandleTable::new();
        let args = init_entry_args(&mut table).expect("init entry args");
        assert_eq!(args, [0x0001_0001, 0x0001_0002, 0]);
        assert_eq!(table.len(), 2);
        let console = object::resolve_handle(&table, Handle::from_raw(0x0001_0001), Rights::WRITE)
            .expect("console handle with WRITE");
        assert_eq!(console.kind, ObjectKind::Console);
        let random = object::resolve_handle(&table, Handle::from_raw(0x0001_0002), Rights::READ)
            .expect("random handle with READ");
        assert_eq!(random.kind, ObjectKind::Random);
        object::clear_handle_table(&mut table);
    }

    // -----------------------------------------------------------------------
    // Failure-path and reaping regressions
    // -----------------------------------------------------------------------
    //
    // These tests touch the process table and the global object table, so they
    // are serialized with a mutex (the tables are single-instance statics).

    /// Serialize tests that mutate the global process/object state.
    ///
    /// This deliberately shares `object`'s crate-level test lock: process tests
    /// create and release objects (including the child `Process` object), so
    /// `object`'s own tests must not run concurrently with them. VFS tests keep
    /// their separate `vfs::test_lock` because the object table is not involved.
    fn global_lock() -> std::sync::MutexGuard<'static, ()> {
        crate::object::test_lock()
    }

    /// Reset every process slot and every CPU's current index.
    ///
    /// Clearing all per-CPU slots (not just the host CPU's) keeps the isolation
    /// tests independent of which CPU the test harness would report.
    fn reset_process_state() {
        for index in 0..MAX_PROCESSES {
            // SAFETY: every caller holds `global_lock`.
            unsafe { *test_slot_ptr(index) = None };
        }
        for cpu in 0..crate::arch::MAX_CPUS {
            set_current_on(cpu, None);
        }
        // Drop every queue bit and every M6b2 counter so tests are independent.
        with_table(|| {
            for cpu in 0..crate::arch::MAX_CPUS {
                unsafe { *ready_queue_ptr(cpu) = 0 };
            }
            RESCHED_PENDING.store(0, Ordering::Relaxed);
            REMOTE_WAKES.store(0, Ordering::Relaxed);
            MIGRATIONS.store(0, Ordering::Relaxed);
            BALANCES.store(0, Ordering::Relaxed);
        });
        test_set_online_cpus(0);
    }

    /// Publish a synthetic process record with no real stack frames.
    ///
    /// `saved` is null and `stack_frames` are zero: the cleanup helpers only
    /// hand zero frames to the PMM, which rejects them without side effects.
    fn publish(
        index: usize,
        state: ProcessState,
        parent: Option<usize>,
        handles: HandleTable,
        address_space: AddressSpaceId,
        process_object: ObjectId,
        wait_handle: Handle,
    ) -> ProcessId {
        let process = Process {
            state,
            address_space,
            handles,
            handles_taken: false,
            personality: Personality::Native,
            signals: SignalState::new(),
            fs_base: 0,
            clear_child_tid: 0,
            fds: crate::compat::linux::fd::FdTable::new(),
            fds_taken: false,
            linux_netns: None,
            kernel_stack_top: kernel_stack_top(index),
            stack_frames: [0; KERNEL_STACK_FRAMES as usize],
            saved: core::ptr::null_mut(),
            exit_status: 0,
            exit_signal: None,
            process_object,
            parent: parent.map(ProcessId::from_index),
            children: [NO_PROCESS; MAX_CHILDREN],
            wait_handle,
            wait: WaitSpec::EMPTY,
            wake_reason: WakeReason::None,
            blocked_frame: FrameSlot::new(),
            cpu: AtomicU8::new(BSP_CPU),
            affinity: AtomicU8::new(DEFAULT_AFFINITY),
            migration: None,
        };
        // SAFETY: the slot is free and the caller holds `global_lock`.
        unsafe { *test_slot_ptr(index) = Some(process) };
        if state == ProcessState::Ready {
            with_table(|| queue_push_unlocked(index, BSP_CPU as usize));
        }
        ProcessId::from_index(index)
    }

    #[test]
    fn failed_spawn_releases_the_address_space_and_the_handles() {
        let _guard = global_lock();
        let mut table = HandleTable::new();
        let console = object::insert_new(&mut table, ObjectKind::Console, Rights::READ)
            .expect("console object");
        let object_id = object::resolve_handle(&table, console, Rights::NONE)
            .expect("console handle")
            .object;
        // A failed spawn owns this table and an address space it never
        // published: both must be released exactly once.
        let released = unsafe {
            discard_unregistered(
                0,
                AddressSpaceId::INVALID,
                &mut table,
                &[0; KERNEL_STACK_FRAMES as usize],
                0,
                None,
            )
        }
        .expect("pre-register cleanup must not fail");
        assert_eq!(released, 0, "no stack frame had been mapped yet");
        assert!(table.is_empty(), "the child handle table must be cleared");
        assert_eq!(
            object::object_refs(object_id),
            None,
            "the last handle release destroys the copied object"
        );
    }

    #[test]
    fn invalid_address_space_and_unmapped_frames_are_no_ops() {
        // A spawn that failed before mapping its stack must stay total: the
        // release helpers report nothing to free and do not panic.
        assert_eq!(release_address_space(AddressSpaceId::INVALID), Ok(()));
        let frames = [0; KERNEL_STACK_FRAMES as usize];
        assert_eq!(mapped_stack_pages(&frames), 0, "no page was ever mapped");
        assert_eq!(
            unsafe { release_stack_frames(0, &frames, mapped_stack_pages(&frames)) },
            Ok(0)
        );
        // Every real stack frame is exactly one page.
        let mut filled = [0u64; KERNEL_STACK_FRAMES as usize];
        for (index, frame) in filled.iter_mut().enumerate() {
            *frame = index as u64 + 1;
        }
        assert_eq!(mapped_stack_pages(&filled), KERNEL_STACK_FRAMES as usize);
    }

    #[test]
    fn stack_release_does_not_return_frames_it_could_not_unmap() {
        // Unmapping must happen first: in the host test environment there is no
        // page table takeover, so the unmap fails and the release has to report
        // that instead of quietly handing the frames back to the PMM (which
        // would leave a PTE pointing at a freed frame).
        let frames = [1u64, 2, 3, 4, 5, 6, 7, 8];
        let result = unsafe {
            release_stack_frames(KERNEL_STACK_BASES[1], &frames, mapped_stack_pages(&frames))
        };
        assert!(
            result.is_err(),
            "an unmap failure must be propagated, not hidden"
        );
        assert_eq!(
            frames,
            [1u64, 2, 3, 4, 5, 6, 7, 8],
            "no frame may be dropped before unmap"
        );
    }

    #[test]
    fn duplicate_source_handle_in_one_request_is_rejected() {
        let _guard = global_lock();
        let mut parent = HandleTable::new();
        let console = object::insert_new(&mut parent, ObjectKind::Console, Rights::READ)
            .expect("console object");
        let console_object = object::resolve_handle(&parent, console, Rights::NONE)
            .expect("console handle")
            .object;
        assert_eq!(object::object_refs(console_object), Some(1));

        // The same source handle twice would create two handles guarding one
        // reference, so closing either could free the object the other names.
        let request = [
            HandleTransfer::new(console, Rights::READ),
            HandleTransfer::new(console, Rights::READ),
        ];
        let mut child = HandleTable::new();
        assert_eq!(
            build_child_handles(&mut parent, &request, &mut child),
            Err(ProcessError::BadRequest),
            "a duplicate source handle must be refused outright"
        );
        assert!(child.is_empty(), "nothing may be duplicated on rejection");
        assert_eq!(
            object::object_refs(console_object),
            Some(1),
            "a rejected request must not change any reference count"
        );
        let _ = object::close_handle(&mut parent, console);
        assert_eq!(object::object_refs(console_object), None);
    }

    #[test]
    fn single_console_transfer_still_copies_one_handle() {
        let _guard = global_lock();
        let mut parent = HandleTable::new();
        let console = object::insert_new(&mut parent, ObjectKind::Console, Rights::READ)
            .expect("console object");
        let console_object = object::resolve_handle(&parent, console, Rights::NONE)
            .expect("console handle")
            .object;

        let mut child = HandleTable::new();
        let request = [HandleTransfer::new(console, Rights::READ)];
        let args = build_child_handles(&mut parent, &request, &mut child)
            .expect("a single transfer is valid");
        assert_eq!(
            args,
            [console.raw() as u64, 0, 0],
            "the child gets the copied handle in rdi, zero in rsi and zero in rdx"
        );
        assert_eq!(child.len(), 1, "one request copies one handle");
        assert_eq!(object::object_refs(console_object), Some(2));

        object::clear_handle_table(&mut child);
        assert_eq!(object::object_refs(console_object), Some(1));
        let _ = object::close_handle(&mut parent, console);
        assert_eq!(object::object_refs(console_object), None);
    }

    #[test]
    fn rollback_clears_the_slot_and_releases_the_child_table() {
        let _guard = global_lock();
        reset_process_state();
        let mut handles = HandleTable::new();
        let console = object::insert_new(&mut handles, ObjectKind::Console, Rights::READ)
            .expect("console object");
        let object_id = object::resolve_handle(&handles, console, Rights::NONE)
            .expect("console handle")
            .object;
        publish(
            1,
            ProcessState::Ready,
            None,
            handles,
            AddressSpaceId::INVALID,
            ObjectId::MAX,
            Handle::INVALID,
        );

        assert!(unsafe { rollback_registration(1) }, "the slot was released");
        assert!(
            test_process_ptr(1).is_null(),
            "a rolled-back child must not stay schedulable"
        );
        assert!(unsafe { rollback_registration(1) } == false);
        assert_eq!(object::object_refs(object_id), None);
        reset_process_state();
    }

    #[test]
    fn reap_closes_the_wait_handle_and_destroys_the_process_object() {
        let _guard = global_lock();
        reset_process_state();
        let process_object = object::create_process_object().expect("process object");
        let mut parent_handles = HandleTable::new();
        let wait_handle = object::insert_handle(&mut parent_handles, process_object, Rights::WAIT)
            .expect("parent wait handle");
        let _parent = publish(
            0,
            ProcessState::Ready,
            None,
            parent_handles,
            AddressSpaceId::INVALID,
            ObjectId::MAX,
            Handle::INVALID,
        );
        let child = publish(
            1,
            ProcessState::Zombie,
            Some(0),
            HandleTable::new(),
            AddressSpaceId::INVALID,
            process_object,
            wait_handle,
        );
        {
            let parent_process = test_process_ref(0).expect("parent slot");
            parent_process.add_child(child);
        }
        assert_eq!(object::object_refs(process_object), Some(1));

        assert_eq!(unsafe { reap(1) }, Ok(()));
        assert!(test_process_ptr(1).is_null(), "the child slot is freed");
        let parent_process = test_process_ref(0).expect("parent slot");
        assert_eq!(
            parent_process.child_count(),
            0,
            "the parent link is cleared"
        );
        assert_eq!(parent_process.handles.len(), 0, "the wait handle is closed");
        assert_eq!(
            object::object_refs(process_object),
            None,
            "closing the last handle destroys the child process object"
        );
        reset_process_state();
    }

    #[test]
    fn reap_destroys_a_process_object_that_never_got_a_handle() {
        let _guard = global_lock();
        reset_process_state();
        // `create_process_object` leaves the object with zero references; the
        // success path normally adds the parent's WAIT handle, but if that handle
        // is never created the reaper must destroy the object itself.
        let process_object = object::create_process_object().expect("process object");
        assert_eq!(object::object_refs(process_object), Some(0));
        publish(
            1,
            ProcessState::Zombie,
            None,
            HandleTable::new(),
            AddressSpaceId::INVALID,
            process_object,
            Handle::INVALID,
        );

        assert_eq!(unsafe { reap(1) }, Ok(()));
        assert_eq!(
            object::object_refs(process_object),
            None,
            "a zero-reference process object must not leak"
        );
        reset_process_state();
    }

    #[test]
    fn reap_keeps_a_shared_console_object_alive() {
        let _guard = global_lock();
        reset_process_state();
        let mut parent_handles = HandleTable::new();
        let console_handle = object::insert_new(
            &mut parent_handles,
            ObjectKind::Console,
            Rights::READ | Rights::WRITE,
        )
        .expect("console object");
        let console_object = object::resolve_handle(&parent_handles, console_handle, Rights::NONE)
            .expect("console handle")
            .object;
        let mut child_handles = HandleTable::new();
        object::duplicate_handle(
            &mut parent_handles,
            &mut child_handles,
            console_handle,
            Rights::READ,
        )
        .expect("copied console handle");
        assert_eq!(object::object_refs(console_object), Some(2));

        let parent = publish(
            0,
            ProcessState::Ready,
            None,
            parent_handles,
            AddressSpaceId::INVALID,
            ObjectId::MAX,
            Handle::INVALID,
        );
        publish(
            1,
            ProcessState::Zombie,
            Some(0),
            child_handles,
            AddressSpaceId::INVALID,
            ObjectId::MAX,
            Handle::INVALID,
        );

        assert_eq!(unsafe { reap(1) }, Ok(()));
        assert_eq!(
            object::object_refs(console_object),
            Some(1),
            "reaping only drops the child's reference, the parent still holds one"
        );
        // Clean the parent reference up so the object table stays empty.
        let parent_process = test_process_ref(parent.index()).expect("parent slot");
        let _ = object::close_handle(&mut parent_process.handles, console_handle);
        assert_eq!(object::object_refs(console_object), None);
        reset_process_state();
    }

    #[test]
    fn reap_releases_handles_before_the_stack_and_the_address_space() {
        // The order is load-bearing for M5c2/M5c3: a VmObject destroy hook
        // unmaps user pages, so the AddressSpace must still be alive while the
        // handle table is cleared; the per-owner VFS leftovers go right after
        // the handles and before the stack. A failing step must abort the later
        // ones, leaving the address space for a retried reap.
        let log = std::cell::RefCell::new(std::vec::Vec::new());
        let outcome = release_in_order(
            || log.borrow_mut().push(1u8),
            || log.borrow_mut().push(2),
            || {
                log.borrow_mut().push(3);
                Ok::<(), u8>(())
            },
            || {
                log.borrow_mut().push(4);
                Ok(())
            },
        );
        assert_eq!(outcome, Ok(()));
        assert_eq!(*log.borrow(), std::vec![1, 2, 3, 4]);

        let log = std::cell::RefCell::new(std::vec::Vec::new());
        let failed = release_in_order(
            || log.borrow_mut().push(1u8),
            || log.borrow_mut().push(2),
            || {
                log.borrow_mut().push(3);
                Err::<(), u8>(7)
            },
            || {
                log.borrow_mut().push(4);
                Ok(())
            },
        );
        assert_eq!(failed, Err(7));
        assert_eq!(
            *log.borrow(),
            std::vec![1, 2, 3],
            "a failed stack release must leave the address space alone"
        );
    }

    #[test]
    fn teardown_uses_the_reaped_slot_id_not_the_current_process() {
        let _guard = global_lock();
        reset_process_state();
        // Slot ids are stable per slot and never depend on which process is on
        // the CPU: that is what lets reap clear the right owner's VFS state.
        assert_eq!(teardown_pid(0), 0);
        assert_eq!(teardown_pid(1), 1);
        assert_ne!(teardown_pid(0), teardown_pid(1));
        assert_eq!(current_process_id(), None, "kernel context has no pid");

        let first = publish(
            0,
            ProcessState::Running,
            None,
            HandleTable::new(),
            AddressSpaceId::INVALID,
            object::ObjectId::MAX,
            Handle::INVALID,
        );
        assert_eq!(first.raw(), 0);
        set_current_index(Some(first.index()));
        assert_eq!(current_process_id(), Some(0));

        // Slot 1 is published but *not* current: reaping it must still clear
        // owner 1, so the pid is taken from the slot, not from CURRENT.
        let second = publish(
            1,
            ProcessState::Zombie,
            None,
            HandleTable::new(),
            AddressSpaceId::INVALID,
            object::ObjectId::MAX,
            Handle::INVALID,
        );
        assert_eq!(second.raw(), 1);
        assert_eq!(current_process_id(), Some(0));
        assert_eq!(teardown_pid(second.index()), 1);

        set_current_index(Some(second.index()));
        assert_eq!(current_process_id(), Some(1));
        assert_eq!(teardown_pid(first.index()), 0);
        reset_process_state();
    }

    #[test]
    fn per_cpu_current_slots_are_independent() {
        let _guard = global_lock();
        reset_process_state();
        // The pure slot helpers are what the public API delegates to on the
        // calling CPU; driving them for every CPU index proves the isolation
        // without needing more than one real processor.
        let first = publish(
            0,
            ProcessState::Running,
            None,
            HandleTable::new(),
            AddressSpaceId::INVALID,
            object::ObjectId::MAX,
            Handle::INVALID,
        );
        let second = publish(
            1,
            ProcessState::Running,
            None,
            HandleTable::new(),
            AddressSpaceId::INVALID,
            object::ObjectId::MAX,
            Handle::INVALID,
        );
        for cpu in 0..crate::arch::MAX_CPUS {
            assert_eq!(test_current_on(cpu), None, "cpu {cpu} starts empty");
        }

        set_current_on(0, Some(first.index()));
        assert_eq!(test_current_on(0), Some(first.index()));
        for cpu in 1..crate::arch::MAX_CPUS {
            assert_eq!(
                test_current_on(cpu),
                None,
                "cpu {cpu} must not observe cpu 0"
            );
        }

        if crate::arch::MAX_CPUS > 1 {
            set_current_on(1, Some(second.index()));
            assert_eq!(
                test_current_on(0),
                Some(first.index()),
                "cpu 0 keeps its slot"
            );
            assert_eq!(test_current_on(1), Some(second.index()));
            set_current_on(1, None);
            assert_eq!(
                test_current_on(0),
                Some(first.index()),
                "clearing cpu 1 leaves cpu 0 alone"
            );
        }

        set_current_on(0, None);
        for cpu in 0..crate::arch::MAX_CPUS {
            assert_eq!(test_current_on(cpu), None);
        }
        reset_process_state();
    }

    #[test]
    fn current_index_reads_the_calling_cpus_slot() {
        let _guard = global_lock();
        reset_process_state();
        let process = publish(
            1,
            ProcessState::Running,
            None,
            HandleTable::new(),
            AddressSpaceId::INVALID,
            object::ObjectId::MAX,
            Handle::INVALID,
        );

        // Host tests execute on the boot CPU index; other slots must not leak
        // into what `current()`/`current_index()` report.
        set_current_on(0, Some(process.index()));
        for cpu in 1..crate::arch::MAX_CPUS {
            set_current_on(cpu, Some(0));
        }
        assert_eq!(current_index(), Some(process.index()));
        assert_eq!(current(), Some(process));
        assert_eq!(current_process_id(), Some(1));
        reset_process_state();
    }

    #[test]
    fn mark_running_records_the_executing_cpu() {
        let _guard = global_lock();
        reset_process_state();
        let process = publish(
            0,
            ProcessState::Ready,
            None,
            HandleTable::new(),
            AddressSpaceId::INVALID,
            object::ObjectId::MAX,
            Handle::INVALID,
        );
        assert_eq!(
            process_cpu(process),
            Some(BSP_CPU as usize),
            "a published process starts on the boot processor"
        );

        set_current_on(current_cpu(), Some(process.index()));
        mark_running(process.index());
        assert_eq!(
            process_cpu(process),
            Some(current_cpu()),
            "resuming a process records the CPU that ran it"
        );
        // SAFETY: `publish` just installed this slot and `global_lock` is held.
        let state = unsafe { &*test_slot_ptr(process.index()) }
            .as_ref()
            .unwrap()
            .state;
        assert_eq!(state, ProcessState::Running);
        reset_process_state();
    }

    #[test]
    fn setting_current_on_a_dead_slot_reads_back_as_none() {
        let _guard = global_lock();
        reset_process_state();
        // `set_current_on` accepts any in-range index; the read side filters
        // slots that are not live so a stale index can never be reported.
        set_current_on(0, Some(0));
        assert_eq!(test_current_on(0), None);
        set_current_on(0, Some(MAX_PROCESSES));
        assert_eq!(test_current_on(0), None, "out-of-range clears the slot");
        reset_process_state();
    }

    #[test]
    fn forbidden_handle_kinds_are_rejected_before_any_reference_is_taken() {
        let _guard = global_lock();
        let mut parent = HandleTable::new();
        let console = object::insert_new(&mut parent, ObjectKind::Console, Rights::READ)
            .expect("console object");
        let console_object = object::resolve_handle(&parent, console, Rights::NONE)
            .expect("console handle")
            .object;
        // Payloads that no live mapping/watch backs: even if a destroy hook is
        // registered in this test binary, releasing these is a no-op.
        let vm_object_handle = object::insert_new_with_payload(
            &mut parent,
            ObjectKind::VmObject,
            0x1234,
            Rights::READ,
        )
        .expect("mapping object");
        let vm_object = object::resolve_handle(&parent, vm_object_handle, Rights::NONE)
            .expect("mapping handle")
            .object;
        let watch_handle =
            object::insert_new_with_payload(&mut parent, ObjectKind::Watch, 0, Rights::READ)
                .expect("watch object");
        let watch_object = object::resolve_handle(&parent, watch_handle, Rights::NONE)
            .expect("watch handle")
            .object;

        // Both creator-owned kinds are refused, and the rejection happens in the
        // pre-validation pass: no child handle exists and no reference is taken.
        for (source, object_id) in [(vm_object_handle, vm_object), (watch_handle, watch_object)] {
            let mut child = HandleTable::new();
            let request = [HandleTransfer::new(source, Rights::READ)];
            assert_eq!(
                build_child_handles(&mut parent, &request, &mut child),
                Err(ProcessError::BadRequest)
            );
            assert!(
                child.is_empty(),
                "a refused transfer must not reach the child table"
            );
            assert_eq!(
                object::object_refs(object_id),
                Some(1),
                "the source reference must be untouched"
            );
        }

        // A mixed request fails as a whole: the legal part is not copied either.
        let mut child = HandleTable::new();
        let mixed = [
            HandleTransfer::new(console, Rights::READ),
            HandleTransfer::new(vm_object_handle, Rights::READ),
        ];
        assert_eq!(
            build_child_handles(&mut parent, &mixed, &mut child),
            Err(ProcessError::BadRequest)
        );
        assert!(child.is_empty());
        assert_eq!(object::object_refs(console_object), Some(1));

        // Console, a kind a child may own, still transfers under the old rules.
        let mut child = HandleTable::new();
        let args = build_child_handles(
            &mut parent,
            &[HandleTransfer::new(console, Rights::READ)],
            &mut child,
        )
        .expect("console transfer");
        assert_eq!(child.len(), 1);
        assert_eq!(object::object_refs(console_object), Some(2));
        assert_eq!(args, [(1u64 << 16) | 1, 0, 0]);

        let _ = object::clear_handle_table(&mut child);
        let _ = object::clear_handle_table(&mut parent);
    }

    // -----------------------------------------------------------------------
    // Blocking / wakeup (M6a1)
    // -----------------------------------------------------------------------

    /// Publish a `Blocked` record waiting on `objects[..count]` with any key.
    fn publish_blocked(
        index: usize,
        objects: [ObjectId; MAX_WAIT_OBJECTS],
        count: usize,
        deadline: Option<u64>,
    ) -> ProcessId {
        publish_blocked_keyed(
            index,
            objects,
            [WAIT_ANY_KEY; MAX_WAIT_OBJECTS],
            count,
            deadline,
        )
    }

    /// Publish a `Blocked` record waiting on keyed `objects[..count]`.
    fn publish_blocked_keyed(
        index: usize,
        objects: [ObjectId; MAX_WAIT_OBJECTS],
        keys: [u32; MAX_WAIT_OBJECTS],
        count: usize,
        deadline: Option<u64>,
    ) -> ProcessId {
        let pid = publish(
            index,
            ProcessState::Blocked,
            None,
            HandleTable::new(),
            AddressSpaceId::INVALID,
            ObjectId::MAX,
            Handle::INVALID,
        );
        // SAFETY: the caller holds `global_lock` and just published the slot.
        unsafe {
            (*test_process_ptr(index)).wait = WaitSpec::new(objects, keys, count, deadline);
        }
        pid
    }

    /// Publish a `Blocked` record waiting on the futex word at `physical_word`.
    fn publish_futex_waiter(index: usize, physical_word: u64, deadline: Option<u64>) -> ProcessId {
        let pid = publish(
            index,
            ProcessState::Blocked,
            None,
            HandleTable::new(),
            AddressSpaceId::INVALID,
            ObjectId::MAX,
            Handle::INVALID,
        );
        // SAFETY: the caller holds `global_lock` and just published the slot.
        unsafe {
            (*test_process_ptr(index)).wait = WaitSpec::futex(physical_word, deadline);
        }
        pid
    }

    /// State of a published record.
    fn state_of(index: usize) -> ProcessState {
        // SAFETY: the caller holds `global_lock`.
        unsafe { (*test_process_ptr(index)).state }
    }

    /// Recorded wake reason of a published record.
    fn reason_of(index: usize) -> WakeReason {
        // SAFETY: the caller holds `global_lock`.
        unsafe { (*test_process_ptr(index)).wake_reason }
    }

    #[test]
    fn blocked_processes_are_never_selected_until_woken() {
        let _guard = global_lock();
        reset_process_state();
        publish_blocked(0, [7, u16::MAX, u16::MAX, u16::MAX], 1, None);

        // A blocked record is skipped exactly like a zombie, and when nothing is
        // runnable the scheduler must idle instead of picking it.
        assert_eq!(
            choose_next_state(&[ProcessState::Blocked.as_u8()], None),
            None
        );
        assert_eq!(
            choose_next_state(
                &[ProcessState::Blocked.as_u8(), ProcessState::Ready.as_u8()],
                Some(0)
            ),
            Some(1)
        );
        assert_eq!(choose_next(None), None);
        assert_eq!(choose_next(Some(0)), None);
        assert!(has_blocked());

        // Waking it makes it runnable again.
        assert_eq!(wake_object(7, WakeReason::Ready), 1);
        assert_eq!(state_of(0), ProcessState::Ready);
        assert_eq!(choose_next(None), Some(0));
        assert!(!has_blocked());

        reset_process_state();
    }

    #[test]
    fn wake_matches_only_the_objects_in_the_wait_spec() {
        let _guard = global_lock();
        reset_process_state();
        publish_blocked(0, [5, 7, u16::MAX, u16::MAX], 2, None);

        // An unrelated object, and a reason of `None`, are not wakes.
        assert_eq!(wake_object(6, WakeReason::Ready), 0);
        assert_eq!(wake_object(5, WakeReason::None), 0);
        assert_eq!(state_of(0), ProcessState::Blocked);
        assert_eq!(reason_of(0), WakeReason::None);

        // An object inside the spec wakes it with the given reason.
        assert_eq!(wake_object(7, WakeReason::Destroyed), 1);
        assert_eq!(state_of(0), ProcessState::Ready);
        assert_eq!(reason_of(0), WakeReason::Destroyed);

        reset_process_state();
    }

    #[test]
    fn a_second_wake_does_not_overwrite_the_first_reason() {
        let _guard = global_lock();
        reset_process_state();
        publish_blocked(0, [9, u16::MAX, u16::MAX, u16::MAX], 1, Some(0));

        assert_eq!(wake_object(9, WakeReason::Ready), 1);
        // Duplicate wake: already `Ready` with a recorded reason.
        assert_eq!(wake_object(9, WakeReason::Destroyed), 0);
        assert_eq!(wake_expired(100), 0, "deadline must not overwrite either");
        assert_eq!(reason_of(0), WakeReason::Ready);

        reset_process_state();
    }

    #[test]
    fn take_wake_reason_consumes_the_recorded_reason() {
        let _guard = global_lock();
        reset_process_state();
        publish_blocked(0, [11, u16::MAX, u16::MAX, u16::MAX], 1, None);
        assert_eq!(take_wake_reason(), WakeReason::None, "no current process");

        set_current_index(Some(0));
        assert_eq!(wake_object(11, WakeReason::Timeout), 1);
        assert_eq!(take_wake_reason(), WakeReason::Timeout);
        assert_eq!(
            take_wake_reason(),
            WakeReason::None,
            "reason is consumed once"
        );
        assert_eq!(reason_of(0), WakeReason::None);

        reset_process_state();
    }

    #[test]
    fn deadlines_expire_only_when_they_are_due() {
        let _guard = global_lock();
        reset_process_state();

        // Nothing to wake when the record has no deadline.
        publish_blocked(0, [u16::MAX; MAX_WAIT_OBJECTS], 0, None);
        assert_eq!(wake_expired(u64::MAX), 0);
        assert_eq!(state_of(0), ProcessState::Blocked);
        reset_process_state();

        // Deadline 0 is due immediately, deadline 1 only from tick 1 onwards.
        publish_blocked(0, [u16::MAX; MAX_WAIT_OBJECTS], 0, Some(1));
        assert_eq!(wake_expired(0), 0);
        assert_eq!(state_of(0), ProcessState::Blocked);
        assert_eq!(wake_expired(1), 1);
        assert_eq!(reason_of(0), WakeReason::Timeout);
        reset_process_state();

        // A deadline at the top of the range must not overflow the comparison.
        publish_blocked(0, [u16::MAX; MAX_WAIT_OBJECTS], 0, Some(u64::MAX));
        assert_eq!(wake_expired(u64::MAX - 1), 0);
        assert_eq!(wake_expired(u64::MAX), 1);

        reset_process_state();
    }

    #[test]
    fn the_copied_syscall_frame_replays_the_two_byte_syscall() {
        let mut source = FrameBuffer::new();
        let source_frame = source.as_frame();
        unsafe {
            write_first_frame(
                source_frame,
                0x0000_0000_0040_1234,
                0x0000_0000_0080_0000,
                3,
                4,
                5,
            );
            (*source_frame).rip = 0x0000_0000_0040_2000;
        }
        let mut slot = FrameSlot::new();
        let slot_frame = slot.as_frame();
        unsafe { copy_blocked_frame(source_frame, slot_frame) };

        let copied = unsafe { &*slot_frame };
        assert_eq!(
            copied.rip, 0x0000_0000_0040_1FFE,
            "rip must move back over the two-byte syscall"
        );
        // Everything else is the user-visible register state and must survive.
        assert_eq!(copied.rdi, 3);
        assert_eq!(copied.rsi, 4);
        assert_eq!(copied.rdx, 5);
        assert_eq!(copied.user_rsp, 0x0000_0000_0080_0000);
        assert_eq!(copied.cs, crate::arch::gdt::USER_CS as u64);
        assert_eq!(copied.user_ss, crate::arch::gdt::USER_DS as u64);
        assert_eq!(
            core::mem::size_of_val(&slot),
            22 * 8,
            "the slot holds exactly one frame"
        );
    }

    #[test]
    fn both_frame_geometries_are_resumable() {
        let _guard = global_lock();
        reset_process_state();
        publish(
            0,
            ProcessState::Blocked,
            None,
            HandleTable::new(),
            AddressSpaceId::INVALID,
            ObjectId::MAX,
            Handle::INVALID,
        );

        let top = kernel_stack_top_of(0);
        // The private syscall frame sits one qword above the ring3 first frame.
        assert_eq!(syscall_frame_addr(top), top - 184);
        assert_eq!(first_frame_addr(top), top - 192);
        assert_eq!(syscall_frame_addr(top) % 8, 0);
        let blocked = blocked_frame_addr(0);
        assert_ne!(blocked, 0);
        assert_eq!(
            blocked % 16,
            0,
            "the .bss frame slot must be 16-byte aligned"
        );

        // SAFETY: `frame_resumable` only compares addresses, it never dereferences.
        assert!(frame_resumable(0, first_frame_addr(top) as *mut TrapFrame));
        assert!(frame_resumable(0, blocked as *mut TrapFrame));
        assert!(!frame_resumable(0, core::ptr::null_mut()));
        assert!(!frame_resumable(0, (top - 176) as *mut TrapFrame));
        assert!(!frame_resumable(
            0,
            blocked.wrapping_add(8) as *mut TrapFrame
        ));

        reset_process_state();
    }

    #[test]
    fn a_dead_sibling_does_not_strand_a_blocked_process() {
        let _guard = global_lock();
        reset_process_state();
        // The exiting process leaves one blocked sibling behind: the scheduler
        // must idle (has_blocked) rather than finish the demo, and a later wake
        // still resumes the sibling.
        publish(
            0,
            ProcessState::Ready,
            None,
            HandleTable::new(),
            AddressSpaceId::INVALID,
            ObjectId::MAX,
            Handle::INVALID,
        );
        publish_blocked(1, [3, u16::MAX, u16::MAX, u16::MAX], 1, Some(5));
        unsafe { *test_slot_ptr(0) = None };

        assert_eq!(choose_next(None), None);
        assert!(has_blocked());
        assert_eq!(wake_expired(5), 1);
        assert_eq!(choose_next(None), Some(1));

        reset_process_state();
    }

    #[test]
    fn keyed_wakes_match_only_the_requested_endpoint() {
        let _guard = global_lock();
        reset_process_state();
        // Waiting on endpoint 1 of pair 21 only (a real EventPair endpoint 0/1).
        publish_blocked_keyed(
            0,
            [21, u16::MAX, u16::MAX, u16::MAX],
            [1, WAIT_ANY_KEY, WAIT_ANY_KEY, WAIT_ANY_KEY],
            1,
            None,
        );

        // The other endpoint of the same pair is not our wake.
        assert_eq!(wake_object_key(21, 0, WakeReason::Ready), 0);
        assert_eq!(state_of(0), ProcessState::Blocked);
        // A different object with the right key is not our wake either.
        assert_eq!(wake_object_key(22, 1, WakeReason::Ready), 0);
        assert_eq!(state_of(0), ProcessState::Blocked);
        assert_eq!(reason_of(0), WakeReason::None);

        // Object and key both match: wake with the first reason, and a second
        // keyed wake must not overwrite it.
        assert_eq!(wake_object_key(21, 1, WakeReason::Ready), 1);
        assert_eq!(state_of(0), ProcessState::Ready);
        assert_eq!(reason_of(0), WakeReason::Ready);
        assert_eq!(wake_object_key(21, 1, WakeReason::Destroyed), 0);
        assert_eq!(reason_of(0), WakeReason::Ready);

        reset_process_state();
    }

    #[test]
    fn key_agnostic_wake_releases_a_keyed_waiter() {
        let _guard = global_lock();
        reset_process_state();
        // Destroy must release both endpoints: the old event-object wake path
        // ignores keys, so a keyed waiter is still woken by it.
        publish_blocked_keyed(
            0,
            [31, u16::MAX, u16::MAX, u16::MAX],
            [0, WAIT_ANY_KEY, WAIT_ANY_KEY, WAIT_ANY_KEY],
            1,
            None,
        );
        assert_eq!(wake_object(31, WakeReason::Destroyed), 1);
        assert_eq!(reason_of(0), WakeReason::Destroyed);
        reset_process_state();

        // A wildcard watcher matches any keyed wake.
        publish_blocked_keyed(
            0,
            [32, u16::MAX, u16::MAX, u16::MAX],
            [WAIT_ANY_KEY, WAIT_ANY_KEY, WAIT_ANY_KEY, WAIT_ANY_KEY],
            1,
            None,
        );
        assert_eq!(wake_object_key(32, 7, WakeReason::Ready), 1);
        assert_eq!(reason_of(0), WakeReason::Ready);
        reset_process_state();
    }

    #[test]
    fn wait_deadline_survives_the_wake_for_the_replayed_syscall() {
        let _guard = global_lock();
        reset_process_state();

        // No current process: no deadline.
        assert_eq!(wait_deadline(), None);

        publish_blocked(0, [41, u16::MAX, u16::MAX, u16::MAX], 1, Some(42));
        set_current_index(Some(0));
        assert_eq!(wait_deadline(), Some(42));

        // The wake and the take must both leave the original absolute deadline
        // readable, so the replay re-uses it instead of computing it afresh.
        assert_eq!(wake_object(41, WakeReason::Ready), 1);
        assert_eq!(take_wake_reason(), WakeReason::Ready);
        assert_eq!(wait_deadline(), Some(42));

        // Only a new wait may replace it; an unbounded wait clears it.
        unsafe {
            (*test_process_ptr(0)).wait = WaitSpec::new(
                [ObjectId::MAX; MAX_WAIT_OBJECTS],
                [WAIT_ANY_KEY; MAX_WAIT_OBJECTS],
                0,
                None,
            )
        };
        assert_eq!(wait_deadline(), None);

        set_current_index(None);
        assert_eq!(wait_deadline(), None, "no current process again");

        reset_process_state();
    }

    // -----------------------------------------------------------------------
    // Futex words (M6a2)
    // -----------------------------------------------------------------------

    #[test]
    fn a_futex_wait_is_released_only_by_its_own_physical_word() {
        let _guard = global_lock();
        reset_process_state();
        publish_futex_waiter(0, 0x0000_0000_1234_5000, None);

        // A neighbouring word, and an object wake, are unrelated triggers.
        assert_eq!(wake_futex(0x0000_0000_1234_5004, usize::MAX), 0);
        assert_eq!(wake_object(1, WakeReason::Ready), 0);
        assert_eq!(state_of(0), ProcessState::Blocked);
        assert_eq!(reason_of(0), WakeReason::None);

        // The exact physical word releases it with a normal success reason.
        assert_eq!(wake_futex(0x0000_0000_1234_5000, usize::MAX), 1);
        assert_eq!(state_of(0), ProcessState::Ready);
        assert_eq!(reason_of(0), WakeReason::Ready);

        reset_process_state();
    }

    #[test]
    fn object_wakes_never_release_a_futex_waiter() {
        let _guard = global_lock();
        reset_process_state();
        publish_futex_waiter(0, 0xABC0, Some(9));

        // Neither the key-agnostic nor the keyed object path may match a futex
        // wait, regardless of the object id or key used.
        assert_eq!(wake_object(u16::MAX, WakeReason::Destroyed), 0);
        assert_eq!(
            wake_object_key(u16::MAX, WAIT_ANY_KEY, WakeReason::Ready),
            0
        );
        assert_eq!(wake_object(0, WakeReason::Ready), 0);
        assert_eq!(state_of(0), ProcessState::Blocked);
        assert_eq!(reason_of(0), WakeReason::None);

        // Only the deadline expires it, with the timeout reason.
        assert_eq!(wake_expired(8), 0);
        assert_eq!(wake_expired(9), 1);
        assert_eq!(reason_of(0), WakeReason::Timeout);

        reset_process_state();
    }

    #[test]
    fn futex_wake_respects_max_and_reports_the_number_woken() {
        let _guard = global_lock();
        reset_process_state();
        publish_futex_waiter(0, 0x2000, None);
        publish_futex_waiter(1, 0x2000, None);
        assert_eq!(futex_waiters(), 2);

        // One at a time: the two waiters share the physical word.
        assert_eq!(wake_futex(0x2000, 1), 1);
        assert_eq!(state_of(0), ProcessState::Ready);
        assert_eq!(state_of(1), ProcessState::Blocked);
        assert_eq!(wake_futex(0x2000, 1), 1);
        assert_eq!(state_of(1), ProcessState::Ready);
        assert_eq!(wake_futex(0x2000, 0), 0, "max 0 must not wake anyone");
        assert_eq!(wake_futex(0x2000, usize::MAX), 0, "nobody is blocked now");
        assert_eq!(futex_waiters(), 0);

        reset_process_state();
    }

    #[test]
    fn one_wake_reaches_the_same_word_from_different_places() {
        let _guard = global_lock();
        reset_process_state();
        // Matching is by physical address only: the wait spec carries neither a
        // virtual address nor an address-space id, so two processes that reached
        // the same word share one wake.
        publish_futex_waiter(0, 0x9000, None);
        publish_futex_waiter(1, 0x9000, None);
        assert_eq!(wake_futex(0x9000, usize::MAX), 2);
        assert_eq!(state_of(0), ProcessState::Ready);
        assert_eq!(state_of(1), ProcessState::Ready);
        assert_eq!(reason_of(0), WakeReason::Ready);
        assert_eq!(reason_of(1), WakeReason::Ready);

        reset_process_state();
    }

    #[test]
    fn futex_waiter_count_covers_only_futex_waits() {
        let _guard = global_lock();
        reset_process_state();
        assert_eq!(futex_waiters(), 0);

        // An object waiter is blocked but not a futex waiter.
        publish_blocked(0, [61, u16::MAX, u16::MAX, u16::MAX], 1, None);
        assert_eq!(futex_waiters(), 0);
        reset_process_state();

        publish_futex_waiter(0, 0x3000, None);
        assert_eq!(futex_waiters(), 1);
        assert_eq!(wake_futex(0x3000, usize::MAX), 1);
        assert_eq!(futex_waiters(), 0, "a woken waiter stops counting");

        // A vanished (reaped) waiter cannot linger in the count either.
        publish_futex_waiter(0, 0x3000, None);
        assert_eq!(futex_waiters(), 1);
        unsafe { *test_slot_ptr(0) = None };
        assert_eq!(futex_waiters(), 0);

        reset_process_state();
    }

    #[test]
    fn futex_waits_and_keyed_object_waits_coexist() {
        let _guard = global_lock();
        reset_process_state();
        // Both process slots in use: slot 0 waits on a futex word, slot 1 on
        // endpoint 1 of EventPair 71. Each wake path must leave the other alone.
        publish_futex_waiter(0, 0x4000, None);
        publish_blocked_keyed(
            1,
            [71, u16::MAX, u16::MAX, u16::MAX],
            [1, WAIT_ANY_KEY, WAIT_ANY_KEY, WAIT_ANY_KEY],
            1,
            None,
        );

        assert_eq!(wake_object_key(71, 1, WakeReason::Ready), 1);
        assert_eq!(state_of(1), ProcessState::Ready);
        assert_eq!(state_of(0), ProcessState::Blocked);

        assert_eq!(wake_futex(0x4000, usize::MAX), 1);
        assert_eq!(state_of(0), ProcessState::Ready);
        assert_eq!(reason_of(0), WakeReason::Ready);

        reset_process_state();
    }

    #[test]
    fn a_futex_waits_deadline_is_reported_for_the_replay() {
        let _guard = global_lock();
        reset_process_state();
        publish_futex_waiter(0, 0x5000, Some(21));
        set_current_index(Some(0));

        assert_eq!(wait_deadline(), Some(21));
        assert_eq!(wake_expired(21), 1);
        assert_eq!(take_wake_reason(), WakeReason::Timeout);
        assert_eq!(
            wait_deadline(),
            Some(21),
            "the absolute deadline survives the wake for the replay"
        );

        reset_process_state();
    }

    #[test]
    fn a_destroy_hook_never_observes_the_table_lock_held() {
        use core::sync::atomic::AtomicBool;

        // Probe registered for a kind the process module never uses itself: the
        // reap path clears the handle table with the process lock already
        // released, so the probe must see a free table lock.
        static HOOK_RAN: AtomicBool = AtomicBool::new(false);
        static LOCK_FREE: AtomicBool = AtomicBool::new(false);

        fn probe(_payload: u64) {
            HOOK_RAN.store(true, Ordering::SeqCst);
            LOCK_FREE.store(!process_lock_is_held(), Ordering::SeqCst);
        }

        let _guard = global_lock();
        reset_process_state();
        // Other modules' tests also register hooks; take a clean table so this
        // test never races on a `HookConflict`.
        object::reset_destroy_hooks();
        object::register_destroy_hook(ObjectKind::VmObject, probe).expect("probe hook");

        // A zombie whose table still owns a VmObject: reap has to clear that
        // table in its unlocked phase, which fires the destroy hook.
        let mut table = HandleTable::new();
        object::insert_new_with_payload(
            &mut table,
            ObjectKind::VmObject,
            0xDEAD_BEEF,
            Rights::READ | Rights::WRITE | Rights::MAP | Rights::DUPLICATE,
        )
        .expect("probe handle");
        let _zombie = publish(
            0,
            ProcessState::Zombie,
            None,
            table,
            AddressSpaceId::INVALID,
            object::ObjectId::MAX,
            Handle::INVALID,
        );

        unsafe { reap(0) }.expect("reap succeeds with the probe object");
        assert!(
            HOOK_RAN.load(Ordering::SeqCst),
            "the destroy hook never ran"
        );
        assert!(
            LOCK_FREE.load(Ordering::SeqCst),
            "reap ran an object destroy hook while holding PROCESS_LOCK"
        );
        assert!(!process_lock_is_held(), "reap leaked PROCESS_LOCK");
        assert_eq!(live_count(), 0);

        reset_process_state();
    }

    #[test]
    fn public_entry_points_do_not_leak_the_table_lock() {
        let _guard = global_lock();
        reset_process_state();
        let first = publish(
            0,
            ProcessState::Ready,
            None,
            HandleTable::new(),
            AddressSpaceId::INVALID,
            object::ObjectId::MAX,
            Handle::INVALID,
        );
        set_current_index(Some(first.index()));

        // Every read-only entry point used by sched and the syscall layer.
        assert_eq!(current(), Some(first));
        assert_eq!(current_index(), Some(first.index()));
        let _ = current_process_id();
        let _ = address_space(first.index());
        let _ = kernel_stack_top_of(first.index());
        let _ = saved_frame(first.index());
        set_saved_frame(first.index(), core::ptr::null_mut());
        assert!(!frame_belongs_to(first.index(), core::ptr::null_mut()));
        assert!(!frame_resumable(first.index(), core::ptr::null_mut()));
        let _ = blocked_frame_addr(first.index());
        let _ = process_cpu(first);
        mark_running(first.index());
        park(first.index());
        let _ = choose_next(None);
        assert_eq!(live_count(), 1);
        assert!(!all_zombie());
        let _ = last_exit_status();
        assert!(with_current_handles(|table| table.len()).is_some());
        assert_eq!(futex_waiters(), 0);
        let _ = wait_deadline();
        let _ = take_wake_reason();
        assert!(!has_blocked());

        // Wake entry points take the lock themselves and must release it.
        assert_eq!(wake_object(object::ObjectId::MAX, WakeReason::Ready), 0);
        assert_eq!(
            wake_object_key(object::ObjectId::MAX, 0, WakeReason::Ready),
            0
        );
        assert_eq!(wake_futex(0x1000, 1), 0);
        assert_eq!(wake_expired(u64::MAX), 0);
        assert!(
            !process_lock_is_held(),
            "a public entry point leaked PROCESS_LOCK"
        );

        reset_process_state();
    }

    /// Take the current process's table out and leave it empty again, so every
    /// guard test starts and ends with a clean object table.
    fn clear_taken_handles() {
        if let Some(mut taken) = take_current_handles() {
            let _ = object::clear_handle_table(taken.table_mut());
        }
    }

    #[test]
    fn taking_the_current_handles_releases_the_table_lock_and_restores_it() {
        let _guard = global_lock();
        reset_process_state();
        let mut table = HandleTable::new();
        object::insert_new(&mut table, ObjectKind::Console, Rights::READ).expect("console");
        let id = publish(
            0,
            ProcessState::Running,
            None,
            table,
            AddressSpaceId::INVALID,
            object::ObjectId::MAX,
            Handle::INVALID,
        );
        set_current_index(Some(id.index()));

        let mut taken = take_current_handles().expect("the current process owns a table");
        assert!(
            !process_lock_is_held(),
            "the guard must not keep PROCESS_LOCK while it owns the table"
        );
        assert_eq!(taken.table().len(), 1);
        assert_eq!(taken.table_mut().len(), 1);
        assert_eq!(taken.process_index(), id.index());
        assert!(
            with_current_handles(|table| table.len()).is_none(),
            "the empty placeholder must not be exposed through with_current_handles"
        );
        drop(taken);
        assert!(!process_lock_is_held(), "Drop must release PROCESS_LOCK");
        assert_eq!(
            with_current_handles(|table| table.len()),
            Some(1),
            "the very same table must be back in the slot"
        );

        clear_taken_handles();
        reset_process_state();
    }

    #[test]
    fn an_early_return_still_restores_the_handle_table() {
        let _guard = global_lock();
        reset_process_state();
        let mut table = HandleTable::new();
        object::insert_new(&mut table, ObjectKind::Console, Rights::READ).expect("console");
        let id = publish(
            0,
            ProcessState::Running,
            None,
            table,
            AddressSpaceId::INVALID,
            object::ObjectId::MAX,
            Handle::INVALID,
        );
        set_current_index(Some(id.index()));

        fn with_early_return() -> Option<()> {
            let _taken = take_current_handles()?;
            // A `?`/early return drops the guard on the way out.
            None::<()>
        }
        assert_eq!(with_early_return(), None);
        assert!(
            !process_lock_is_held(),
            "the early return must release the lock"
        );
        assert_eq!(
            with_current_handles(|table| table.len()),
            Some(1),
            "the table must be restored even on an early return"
        );

        clear_taken_handles();
        reset_process_state();
    }

    #[test]
    fn taking_handles_without_a_current_process_returns_none() {
        let _guard = global_lock();
        reset_process_state();
        assert!(take_current_handles().is_none());
        assert!(!process_lock_is_held());
    }

    #[test]
    fn a_second_take_never_hands_out_an_empty_table() {
        let _guard = global_lock();
        reset_process_state();
        let mut table = HandleTable::new();
        object::insert_new(&mut table, ObjectKind::Console, Rights::READ).expect("console");
        let id = publish(
            0,
            ProcessState::Running,
            None,
            table,
            AddressSpaceId::INVALID,
            object::ObjectId::MAX,
            Handle::INVALID,
        );
        set_current_index(Some(id.index()));

        let first = take_current_handles().expect("first take succeeds");
        assert!(
            take_current_handles().is_none(),
            "a nested take must be refused, not handed an empty table"
        );
        assert_eq!(
            first.table().len(),
            1,
            "the first guard still owns the real table"
        );
        drop(first);
        let again = take_current_handles().expect("the table is back after Drop");
        assert_eq!(again.table().len(), 1);
        drop(again);

        clear_taken_handles();
        reset_process_state();
    }

    #[test]
    fn the_guard_lets_a_destroy_hook_run_without_the_table_lock() {
        use core::sync::atomic::AtomicBool;

        static HOOK_RAN: AtomicBool = AtomicBool::new(false);
        static HOOK_LOCK_FREE: AtomicBool = AtomicBool::new(false);

        fn probe(_payload: u64) {
            HOOK_RAN.store(true, Ordering::SeqCst);
            HOOK_LOCK_FREE.store(!process_lock_is_held(), Ordering::SeqCst);
        }

        let _guard = global_lock();
        reset_process_state();
        object::reset_destroy_hooks();
        object::register_destroy_hook(ObjectKind::File, probe).expect("probe hook");
        let mut table = HandleTable::new();
        object::insert_new(&mut table, ObjectKind::File, Rights::READ).expect("file handle");
        let id = publish(
            0,
            ProcessState::Running,
            None,
            table,
            AddressSpaceId::INVALID,
            object::ObjectId::MAX,
            Handle::INVALID,
        );
        set_current_index(Some(id.index()));

        let mut taken = take_current_handles().expect("guard");
        // This is exactly the call that used to run inside PROCESS_LOCK.
        let cleared = object::clear_handle_table(taken.table_mut());
        assert_eq!(cleared, 1);
        drop(taken);

        assert!(
            HOOK_RAN.load(Ordering::SeqCst),
            "the destroy hook never ran"
        );
        assert!(
            HOOK_LOCK_FREE.load(Ordering::SeqCst),
            "the destroy hook ran while PROCESS_LOCK was held"
        );
        assert!(!process_lock_is_held());
        assert_eq!(with_current_handles(|table| table.len()), Some(0));

        reset_process_state();
    }

    #[test]
    fn reap_closes_the_parent_wait_handle_without_the_table_lock() {
        use core::sync::atomic::AtomicBool;

        static HOOK_RAN: AtomicBool = AtomicBool::new(false);
        static HOOK_LOCK_FREE: AtomicBool = AtomicBool::new(false);

        fn probe(_payload: u64) {
            HOOK_RAN.store(true, Ordering::SeqCst);
            HOOK_LOCK_FREE.store(!process_lock_is_held(), Ordering::SeqCst);
        }

        let _guard = global_lock();
        reset_process_state();
        object::reset_destroy_hooks();
        object::register_destroy_hook(ObjectKind::Process, probe).expect("process probe hook");

        // The parent holds the child's WAIT handle; the child owns the object.
        let process_object = object::create_process_object().expect("process object");
        let mut parent_table = HandleTable::new();
        let wait_handle = object::insert_handle(&mut parent_table, process_object, Rights::WAIT)
            .expect("parent wait handle");
        let parent = publish(
            0,
            ProcessState::Running,
            None,
            parent_table,
            AddressSpaceId::INVALID,
            object::ObjectId::MAX,
            Handle::INVALID,
        );
        let child = publish(
            1,
            ProcessState::Zombie,
            Some(parent.index()),
            HandleTable::new(),
            AddressSpaceId::INVALID,
            process_object,
            wait_handle,
        );
        set_current_index(Some(parent.index()));

        unsafe { reap(child.index()) }.expect("reap the zombie child");

        assert!(!process_lock_is_held(), "reap must release PROCESS_LOCK");
        assert!(
            HOOK_RAN.load(Ordering::SeqCst),
            "closing the WAIT handle did not destroy the Process object"
        );
        assert!(
            HOOK_LOCK_FREE.load(Ordering::SeqCst),
            "the WAIT-handle destroy hook ran while PROCESS_LOCK was held"
        );
        // The parent's table is back in its slot (and empty), its child link gone.
        assert_eq!(with_current_handles(|table| table.len()), Some(0));
        assert_eq!(
            test_process_ref(parent.index())
                .expect("parent slot")
                .child_count(),
            0
        );

        reset_process_state();
    }

    #[test]
    fn test_current_handles_helper_installs_a_guardable_process() {
        // The helper takes the object test lock itself, so this test must not
        // hold `global_lock`.
        let mut table = HandleTable::new();
        object::insert_new(&mut table, ObjectKind::Console, Rights::READ).expect("console");
        let inside = test_with_current_handles(table, || {
            assert!(
                current_index().is_some(),
                "helper must install a current process"
            );
            let mut taken = take_current_handles().expect("the guard must take the helper table");
            assert!(!process_lock_is_held());
            let len = taken.table().len();
            let cleared = object::clear_handle_table(taken.table_mut());
            assert_eq!(cleared, 1);
            drop(taken);
            // The table is back and empty, and the lock is free again.
            assert_eq!(with_current_handles(|table| table.len()), Some(0));
            assert!(!process_lock_is_held());
            len
        });
        assert_eq!(inside, 1);
    }

    // -----------------------------------------------------------------------
    // M6b2: per-CPU ready queues, affinity, migration and balancing
    // -----------------------------------------------------------------------

    #[test]
    fn two_cpus_cannot_claim_the_same_ready_process() {
        let _guard = global_lock();
        reset_process_state();
        test_set_online_cpus(2);
        let pid = publish(
            0,
            ProcessState::Ready,
            None,
            HandleTable::new(),
            AddressSpaceId::INVALID,
            object::ObjectId::MAX,
            Handle::INVALID,
        );

        // Queued on the BSP only: another CPU cannot see or steal it.
        assert_eq!(claim_next_on(1, None), None);
        // The first claim consumes the queue bit and resumes it on that CPU.
        assert_eq!(claim_next_on(0, None), Some(pid.index()));
        assert_eq!(state_of(pid.index()), ProcessState::Running);
        assert_eq!(process_cpu(pid), Some(BSP_CPU as usize));
        // A second claim from either CPU finds nothing: no double scheduling.
        assert_eq!(claim_next_on(0, None), None);
        assert_eq!(claim_next_on(1, None), None);
        reset_process_state();
    }

    #[test]
    fn affinity_moves_a_ready_process_off_a_disallowed_cpu() {
        let _guard = global_lock();
        reset_process_state();
        test_set_online_cpus(2);
        let pid = publish(
            0,
            ProcessState::Ready,
            None,
            HandleTable::new(),
            AddressSpaceId::INVALID,
            object::ObjectId::MAX,
            Handle::INVALID,
        );
        set_affinity(pid.index(), 1 << 1).expect("narrow to AP1");

        // The queue bit moved with the affinity, so the BSP claim must not run it.
        assert_eq!(claim_next_on(0, None), None);
        assert_eq!(claim_next_on(1, None), Some(pid.index()));
        assert_eq!(process_cpu(pid), Some(1));
        reset_process_state();
    }

    #[test]
    fn a_blocked_process_wakes_on_the_cpu_it_was_migrated_to() {
        let _guard = global_lock();
        reset_process_state();
        test_set_online_cpus(2);
        let pid = publish_blocked(0, [42, u16::MAX, u16::MAX, u16::MAX], 1, None);
        migrate(pid, 1).expect("migrating a blocked process is allowed");
        assert_eq!(process_cpu(pid), Some(1));

        assert_eq!(wake_object(42, WakeReason::Ready), 1);
        assert_eq!(state_of(pid.index()), ProcessState::Ready);
        assert_eq!(
            process_cpu(pid),
            Some(1),
            "the wake must enqueue on the CPU that owns the wait"
        );
        assert_eq!(remote_wakes(), 1, "a cross-CPU wake is counted once");
        assert!(
            resched_pending(1),
            "the target CPU must be asked to reschedule"
        );

        // Claiming on the target CPU books the pending affinity migration, and
        // claiming it elsewhere is impossible because only CPU1 has the bit.
        assert_eq!(claim_next_on(0, None), None);
        assert_eq!(claim_next_on(1, None), Some(pid.index()));
        assert_eq!(migration_counts(), (1, 0));
        reset_process_state();
    }

    #[test]
    fn rebalance_moves_a_sleeping_worker_to_the_idle_ap() {
        let _guard = global_lock();
        reset_process_state();
        test_set_online_cpus(4);
        let a = publish_blocked(0, [0, u16::MAX, u16::MAX, u16::MAX], 0, None);
        let b = publish_blocked(1, [0, u16::MAX, u16::MAX, u16::MAX], 0, None);

        // Root flow: A is narrowed to AP2 and migrated there; B is placed on AP1
        // and then allowed on every CPU (0x0F) before being rebalanced.
        set_affinity(a.index(), 1 << 2).expect("narrow A to AP2");
        migrate(a, 2).expect("migrate A");
        migrate(b, 1).expect("place B on AP1");
        set_affinity(b.index(), CPU_MASK_ALL).expect("allow every CPU for B");

        // Loads: AP1 = 1 (B), AP2 = 1 (A), AP3 = 0, and the BSP also has 0 in
        // this synthetic setup. CPU 0 must still not be chosen: a balance
        // migration only targets online APs, so B ends up on AP3.
        assert_eq!(rebalance(b), Ok(3));
        assert_eq!(process_cpu(b), Some(3));
        // Nothing is booked until the target CPU really resumes the process.
        assert_eq!(migration_counts(), (0, 0));
        test_mark_running_on(b.index(), 3);
        assert_eq!(
            migration_counts(),
            (0, 1),
            "the balance is booked once, when AP3 resumes B"
        );
        reset_process_state();
    }

    #[test]
    fn initial_placement_prefers_the_creating_cpu() {
        let _guard = global_lock();
        reset_process_state();
        test_set_online_cpus(4);
        assert_eq!(initial_placement_cpu(0), BSP_CPU);
        assert_eq!(initial_placement_cpu(1), 1);
        assert_eq!(initial_placement_cpu(3), 3);

        // A creator outside the online set (reduced `-smp` boot) cannot host
        // the child: fall back to the first online CPU the default affinity
        // allows.
        test_set_online_cpus(1);
        assert_eq!(initial_placement_cpu(3), BSP_CPU);
        reset_process_state();
    }

    #[test]
    fn ap_spawn_places_the_child_on_the_creating_cpu() {
        let _guard = global_lock();
        reset_process_state();
        test_set_online_cpus(4);
        // `register` publishes every new process on the boot processor's queue
        // first; the link phase then moves it (M7b: the parent runs on AP1).
        let child = publish(
            0,
            ProcessState::Ready,
            None,
            HandleTable::new(),
            AddressSpaceId::INVALID,
            object::ObjectId::MAX,
            Handle::INVALID,
        );
        assert_eq!(process_cpu(child), Some(BSP_CPU as usize));

        let creator = 1;
        let target = initial_placement_cpu(creator);
        assert_eq!(target, 1);
        with_table(|| place_initial_unlocked(child.index(), target, creator));

        assert_eq!(process_cpu(child), Some(1));
        assert!(
            with_table(|| queue_contains_unlocked(child.index(), 1)),
            "the child must be queued on the AP that created it"
        );
        assert!(
            !with_table(|| queue_contains_unlocked(child.index(), 0)),
            "the child must not stay on the boot queue"
        );
        // The boot processor's monitor loop only idles; a child left there is
        // never claimed, so the AP has to be the one that finds it.
        assert_eq!(claim_next_on(0, None), None);
        assert_eq!(claim_next_on(1, None), Some(child.index()));
        reset_process_state();
    }

    #[test]
    fn bsp_spawn_keeps_the_register_placement() {
        let _guard = global_lock();
        reset_process_state();
        test_set_online_cpus(4);
        let child = publish(
            0,
            ProcessState::Ready,
            None,
            HandleTable::new(),
            AddressSpaceId::INVALID,
            object::ObjectId::MAX,
            Handle::INVALID,
        );
        let creator = BSP_CPU as usize;
        let target = initial_placement_cpu(creator);
        assert_eq!(target, BSP_CPU);
        with_table(|| place_initial_unlocked(child.index(), target, creator));

        assert_eq!(process_cpu(child), Some(BSP_CPU as usize));
        assert!(with_table(|| queue_contains_unlocked(child.index(), 0)));
        assert!(
            !resched_pending(BSP_CPU as usize),
            "a same-CPU placement must not request an IPI"
        );
        assert_eq!(claim_next_on(BSP_CPU as usize, None), Some(child.index()));
        reset_process_state();
    }

    #[test]
    fn reap_orphans_releases_only_parentless_zombies() {
        let _guard = global_lock();
        reset_process_state();
        let orphan = publish(
            0,
            ProcessState::Zombie,
            None,
            HandleTable::new(),
            AddressSpaceId::INVALID,
            object::ObjectId::MAX,
            Handle::INVALID,
        );
        let childbearing = publish(
            1,
            ProcessState::Zombie,
            Some(0),
            HandleTable::new(),
            AddressSpaceId::INVALID,
            object::ObjectId::MAX,
            Handle::INVALID,
        );
        // Publish the forward link too, so reaping the parent can clear the back
        // link of the child it leaves behind.
        unsafe { (*test_process_ptr(orphan.index())).add_child(childbearing) };

        assert_eq!(reap_orphans(), 1);
        assert!(
            unsafe { (*test_slot_ptr(orphan.index())).is_none() },
            "the orphan slot must be freed"
        );
        assert!(
            unsafe { (*test_slot_ptr(childbearing.index())).is_some() },
            "a zombie with a parent is reaped by wait, not by the orphan sweep"
        );
        assert_eq!(
            test_process_ref(childbearing.index()).expect("slot").parent,
            None,
            "reaping the parent drops the back link"
        );
        reset_process_state();
    }

    #[test]
    fn a_failed_reap_keeps_the_slot_and_the_parent_link() {
        let _guard = global_lock();
        reset_process_state();
        let process_object = object::create_process_object().expect("process object");
        let mut parent_table = HandleTable::new();
        let wait_handle = object::insert_handle(&mut parent_table, process_object, Rights::WAIT)
            .expect("parent wait handle");
        let parent = publish(
            1,
            ProcessState::Running,
            None,
            parent_table,
            AddressSpaceId::INVALID,
            object::ObjectId::MAX,
            Handle::INVALID,
        );
        let child = publish(
            0,
            ProcessState::Zombie,
            Some(parent.index()),
            HandleTable::new(),
            AddressSpaceId::INVALID,
            process_object,
            wait_handle,
        );
        // A non-zero stack frame makes the host-side unmap fail, so the release
        // phase reports an error after Phase 1 already took the resources out.
        unsafe { (*test_process_ptr(child.index())).stack_frames[0] = 0x1234 };
        unsafe { (*test_process_ptr(parent.index())).add_child(child) };

        let result = unsafe { reap(child.index()) };
        assert!(
            matches!(result, Err(ProcessError::Map(_))),
            "a release failure must propagate instead of pretending success"
        );
        assert!(
            unsafe { (*test_slot_ptr(child.index())).is_some() },
            "a failed reap must keep the slot so a later reap can retry"
        );
        let parent_process = test_process_ref(parent.index()).expect("parent slot");
        assert!(
            !parent_process.handles_taken,
            "the parent table must be put back even when the release failed"
        );
        assert!(
            object::resolve_handle(&parent_process.handles, wait_handle, Rights::WAIT).is_ok(),
            "the WAIT handle must not be closed on a failed reap"
        );
        assert!(
            parent_process.child_slot(child).is_some(),
            "the child link must survive a failed reap"
        );

        // Clean up: take both slots and release the handle table plus the object.
        unsafe { *test_slot_ptr(child.index()) = None };
        let mut leftover = unsafe { (*test_slot_ptr(parent.index())).take() }
            .map(|process| process.handles)
            .unwrap_or_else(HandleTable::new);
        let _ = object::clear_handle_table(&mut leftover);
        reset_process_state();
    }

    /// Three live objects a detached `gfx` process could receive, held by the
    /// returned source table so the caller can clean them up.
    ///
    /// Console has the historical `Rights::ALL` creation bound, EventPair the
    /// M6a `READ | WRITE | WAIT | DUPLICATE` bound and SharedMemory the M6a2
    /// `READ | WRITE | MAP | DUPLICATE` bound: all three bound shapes are
    /// exercised by the detached-handle tests.
    fn detached_fixture() -> (HandleTable, [ObjectId; 3]) {
        let mut source = HandleTable::new();
        let console = object::insert_new(
            &mut source,
            ObjectKind::Console,
            Rights::READ | Rights::WRITE,
        )
        .expect("console");
        let pair = object::insert_new(
            &mut source,
            ObjectKind::EventPair,
            Rights::READ
                .union(Rights::WRITE)
                .union(Rights::WAIT)
                .union(Rights::DUPLICATE),
        )
        .expect("event pair");
        let shm = object::insert_new(
            &mut source,
            ObjectKind::SharedMemory,
            Rights::READ
                .union(Rights::WRITE)
                .union(Rights::MAP)
                .union(Rights::DUPLICATE),
        )
        .expect("shared memory");
        let ids = [console, pair, shm].map(|handle| {
            object::resolve_handle(&source, handle, Rights::NONE)
                .expect("fresh handle")
                .object
        });
        (source, ids)
    }

    #[test]
    fn detached_handles_take_slots_zero_to_two_with_the_requested_rights() {
        let _guard = global_lock();
        reset_process_state();
        object::reset_destroy_hooks();
        let (mut source, ids) = detached_fixture();
        let objects = [
            (ids[0], Rights::WRITE),
            (ids[1], Rights::WAIT),
            (ids[2], Rights::READ),
        ];
        let mut table = HandleTable::new();
        let args = prepare_detached_handles(&mut table, &objects, DETACHED_HANDLE_SLOTS)
            .expect("three valid handles");

        assert_eq!(table.len(), 3, "exactly three handles are installed");
        assert!(
            args.iter().all(|raw| *raw != 0),
            "every slot got a real handle"
        );
        for (slot, raw) in args.iter().enumerate() {
            let handle = Handle::from_raw(*raw as u32);
            assert_eq!(handle.slot_index(), Some(slot), "slot order is preserved");
            let resolved = object::resolve_handle(&table, handle, Rights::NONE)
                .expect("installed handle resolves");
            assert_eq!(
                resolved.object, ids[slot],
                "handle points at the requested object"
            );
        }
        // Rights are exactly the requested reduction, never the source rights.
        let console = Handle::from_raw(args[0] as u32);
        assert!(object::resolve_handle(&table, console, Rights::WRITE).is_ok());
        assert!(object::resolve_handle(&table, console, Rights::READ).is_err());
        let pair = Handle::from_raw(args[1] as u32);
        assert!(object::resolve_handle(&table, pair, Rights::WAIT).is_ok());
        assert!(object::resolve_handle(&table, pair, Rights::WRITE).is_err());
        let shm = Handle::from_raw(args[2] as u32);
        assert!(object::resolve_handle(&table, shm, Rights::READ).is_ok());
        assert!(object::resolve_handle(&table, shm, Rights::MAP).is_err());

        let _ = object::clear_handle_table(&mut table);
        let _ = object::clear_handle_table(&mut source);
        reset_process_state();
    }

    #[test]
    fn detached_handle_validation_refuses_over_bound_rights_and_creator_owned_objects() {
        let _guard = global_lock();
        reset_process_state();
        object::reset_destroy_hooks();
        let (mut source, ids) = detached_fixture();

        // An EventPair was created without MAP: granting MAP would widen the
        // object's creation bound and must be rejected before any reference.
        let mut table = HandleTable::new();
        let over_bound = [
            (ids[0], Rights::WRITE),
            (ids[1], Rights::MAP),
            (ids[2], Rights::READ),
        ];
        assert!(matches!(
            prepare_detached_handles(&mut table, &over_bound, DETACHED_HANDLE_SLOTS),
            Err(ProcessError::Objects(ObjectError::InvalidRights))
        ));
        assert!(table.is_empty(), "a rejected request installs nothing");

        // Empty rights are not a valid reduction either.
        let empty = [
            (ids[0], Rights::NONE),
            (ids[1], Rights::WAIT),
            (ids[2], Rights::READ),
        ];
        assert!(matches!(
            prepare_detached_handles(&mut table, &empty, DETACHED_HANDLE_SLOTS),
            Err(ProcessError::Objects(ObjectError::InvalidRights))
        ));
        assert!(table.is_empty());

        // A VmObject payload names the creator's mapping and a Watch payload its
        // owner: neither may cross into a process with no handle provenance.
        let vm =
            object::insert_new_with_payload(&mut source, ObjectKind::VmObject, 0x1234, Rights::ALL)
                .expect("vm object");
        let vm_id = object::resolve_handle(&source, vm, Rights::NONE)
            .expect("vm handle")
            .object;
        let creator_owned = [
            (vm_id, Rights::READ),
            (ids[1], Rights::WAIT),
            (ids[2], Rights::READ),
        ];
        assert!(matches!(
            prepare_detached_handles(&mut table, &creator_owned, DETACHED_HANDLE_SLOTS),
            Err(ProcessError::BadRequest)
        ));
        assert!(table.is_empty());

        // An already destroyed / never allocated id is an invalid object, not a
        // silently skipped slot.
        let missing = [
            (ids[0], Rights::WRITE),
            (ids[1], Rights::WAIT),
            (ObjectId::MAX, Rights::READ),
        ];
        assert!(matches!(
            prepare_detached_handles(&mut table, &missing, DETACHED_HANDLE_SLOTS),
            Err(ProcessError::Objects(ObjectError::InvalidObject))
        ));
        assert!(table.is_empty());

        let _ = object::clear_handle_table(&mut source);
        reset_process_state();
    }

    #[test]
    fn a_failed_detached_handle_insertion_releases_every_reference() {
        let _guard = global_lock();
        reset_process_state();
        object::reset_destroy_hooks();
        let (mut source, ids) = detached_fixture();
        let console_refs = object::object_refs(ids[0]).expect("live console");
        let pair_refs = object::object_refs(ids[1]).expect("live pair");

        // The first two entries insert fine, the third one cannot: the table
        // must be cleared so the two references taken are released again.
        let mut table = HandleTable::new();
        let partial = [
            (ids[0], Rights::WRITE),
            (ids[1], Rights::WAIT),
            (ObjectId::MAX, Rights::READ),
        ];
        assert!(matches!(
            prepare_detached_handles(&mut table, &partial, DETACHED_HANDLE_SLOTS),
            Err(ProcessError::Objects(ObjectError::InvalidObject))
        ));
        assert!(table.is_empty(), "the partially built table is cleared");
        assert_eq!(
            object::object_refs(ids[0]),
            Some(console_refs),
            "the first taken reference was released"
        );
        assert_eq!(
            object::object_refs(ids[1]),
            Some(pair_refs),
            "the second taken reference was released"
        );

        let _ = object::clear_handle_table(&mut source);
        reset_process_state();
    }

    #[test]
    fn detached_entry_handles_reach_rdi_rsi_and_rdx() {
        let _guard = global_lock();
        reset_process_state();
        let args = [0x0001_0001u64, 0x0001_0002, 0x0001_0003];
        let mut buffer = FrameBuffer::new();
        let frame = buffer.as_frame();
        unsafe {
            write_first_frame(
                frame,
                0x0000_0000_0040_1000,
                0x0000_0000_0080_0000,
                args[0],
                args[1],
                args[2],
            );
        }
        let frame = unsafe { &*frame };
        assert_eq!(frame.rdi, args[0], "the first handle arrives in rdi");
        assert_eq!(frame.rsi, args[1], "the second handle arrives in rsi");
        assert_eq!(frame.rdx, args[2], "the third handle arrives in rdx");
        reset_process_state();
    }

    #[test]
    fn the_m6c_gfx_rights_sets_are_valid_subsets_of_their_creation_bounds() {
        let _guard = global_lock();
        // The frozen M6c call: Console WRITE, Display READ|WRITE|MAP, Input
        // READ|WAIT. The detached-handle path validates through
        // `check_initial_rights`, so these must pass (and an over-wide Input
        // request such as MAP must not).
        object::check_initial_rights(ObjectKind::Console, Rights::WRITE).expect("console write");
        object::check_initial_rights(
            ObjectKind::Display,
            Rights::READ.union(Rights::WRITE).union(Rights::MAP),
        )
        .expect("display map");
        object::check_initial_rights(ObjectKind::Input, Rights::READ.union(Rights::WAIT))
            .expect("input wait");
        assert!(
            object::check_initial_rights(ObjectKind::Input, Rights::READ.union(Rights::MAP))
                .is_err(),
            "input never gets MAP"
        );
        assert!(
            object::check_initial_rights(ObjectKind::Input, Rights::NONE).is_err(),
            "empty rights are always refused"
        );
    }

    #[test]
    fn the_plain_detached_spawn_passes_no_handles() {
        let _guard = global_lock();
        reset_process_state();
        let mut table = HandleTable::new();
        let args = prepare_detached_handles(
            &mut table,
            &[(ObjectId::MAX, Rights::NONE); DETACHED_HANDLE_SLOTS],
            0,
        )
        .expect("an empty handle list is valid");
        assert_eq!(args, [0, 0, 0], "worker entries still see rdi=rsi=rdx=0");
        assert!(table.is_empty(), "no handles are installed for a worker");
        reset_process_state();
    }

    #[test]
    fn exit_status_reports_only_the_exited_slot() {
        let _guard = global_lock();
        reset_process_state();
        let ready = publish(
            0,
            ProcessState::Ready,
            None,
            HandleTable::new(),
            AddressSpaceId::INVALID,
            ObjectId::MAX,
            Handle::INVALID,
        );
        assert_eq!(exit_status(ready), None, "a live process has no status yet");

        let zombie = publish(
            1,
            ProcessState::Zombie,
            None,
            HandleTable::new(),
            AddressSpaceId::INVALID,
            ObjectId::MAX,
            Handle::INVALID,
        );
        with_table(|| unsafe { process_ref(1) }.expect("zombie").exit_status = 7);
        assert_eq!(exit_status(zombie), Some(7), "a zombie reports its status");
        assert_eq!(
            last_exit_status(),
            7,
            "the current-process helper sees the same zombie"
        );

        assert!(reap_orphan(zombie), "the parentless zombie is reaped");
        assert_eq!(exit_status(zombie), None, "a reaped slot has no status");
        assert_eq!(exit_status(ready), None, "an empty slot has no status");
        reset_process_state();
    }

    #[test]
    fn reap_orphan_only_removes_a_parentless_exited_process() {
        let _guard = global_lock();
        reset_process_state();
        let parent = publish(
            0,
            ProcessState::Zombie,
            None,
            HandleTable::new(),
            AddressSpaceId::INVALID,
            ObjectId::MAX,
            Handle::INVALID,
        );
        let child = publish(
            1,
            ProcessState::Zombie,
            Some(0),
            HandleTable::new(),
            AddressSpaceId::INVALID,
            ObjectId::MAX,
            Handle::INVALID,
        );
        assert!(!reap_orphan(child), "a parented zombie belongs to wait");
        assert!(
            test_process_ref(child.index()).is_some(),
            "the parented slot survives"
        );

        let running = publish(
            1,
            ProcessState::Running,
            None,
            HandleTable::new(),
            AddressSpaceId::INVALID,
            ObjectId::MAX,
            Handle::INVALID,
        );
        // The parented zombie slot was replaced by `running` above (the old
        // record is dropped without reaping, which is what a test wants).
        assert!(!reap_orphan(running), "a running process is not reaped");

        // The process on this CPU is never reaped, even when it is a zombie.
        set_current_index(Some(parent.index()));
        assert!(
            !reap_orphan(parent),
            "the CPU's current process stays mapped for the closing fault"
        );
        assert!(
            test_process_ref(parent.index()).is_some(),
            "the current zombie slot survives"
        );
        set_current_index(None);
        assert!(
            reap_orphan(parent),
            "after clearing current it can be reaped"
        );
        assert!(test_process_ref(parent.index()).is_none(), "slot released");
        reset_process_state();
    }

    /// M7d: the Linux fd table lives in the process slot and can only be taken
    /// by a `Linux64` process; `CurrentFdsGuard` moves it out and returns it.
    #[test]
    fn fd_guard_owns_the_table_only_for_linux_processes() {
        let _guard = global_lock();
        reset_process_state();
        object::reset_destroy_hooks();

        // Kernel context (no current process) is the native default.
        assert_eq!(current_personality(), Personality::Native);
        assert!(take_current_fds().is_none());

        let console = object::create_console().expect("console object");
        let mut fds = FdTable::new();
        fds.install_console(console).expect("console fds");
        // `create_console` starts at refs 0 (M4 compatibility path); the three
        // console fds are the only owners here.
        assert_eq!(object::object_refs(console), Some(3));

        let id = publish(
            0,
            ProcessState::Running,
            None,
            HandleTable::new(),
            AddressSpaceId::INVALID,
            ObjectId::MAX,
            Handle::INVALID,
        );
        set_current_index(Some(id.index()));

        // A native process has no Linux fd table to hand out.
        assert_eq!(current_personality(), Personality::Native);
        assert!(take_current_fds().is_none());

        // A Linux process gets here through `spawn_detached_linux`; the test
        // flips the slot directly so no boot module is needed.
        with_table(|| unsafe {
            let process = process_ref(id.index()).expect("test process");
            process.personality = Personality::Linux64;
            process.fds = fds;
        });
        assert_eq!(current_personality(), Personality::Linux64);
        assert_eq!(current_linux_netns(), None);

        {
            let mut guard = take_current_fds().expect("linux current owns an fd table");
            assert_eq!(guard.process_index(), id.index());
            assert_eq!(guard.len(), 3);
            assert_eq!(guard.get(0).map(|entry| entry.object), Ok(console));
            // A nested take is refused instead of handing out an empty table.
            assert!(take_current_fds().is_none());
            let fd = guard
                .insert(crate::compat::linux::fd::FdEntry::new(console, false))
                .expect("extra fd");
            assert_eq!(fd, 3);
        }
        // Drop returned the table to the slot: a second guard owns it again.
        let guard = take_current_fds().expect("table returned to the slot");
        assert_eq!(guard.len(), 4);
        assert_eq!(guard.get(3).map(|entry| entry.object), Ok(console));
        drop(guard);

        // The slot still owns the table, so release it explicitly before reset.
        set_current_index(None);
        let leftover = with_table(|| unsafe { (*slot_ptr(id.index())).take() });
        let mut leftover = leftover.expect("slot still mapped");
        let _ = object::clear_handle_table(&mut leftover.handles);
        let _ = release_all_fds(&mut leftover.fds);
        let _ = object::release_object(console);
        assert_eq!(object::object_refs(console), None);
        reset_process_state();
    }

    /// M7d: reaping a Linux process closes its fd table outside the process
    /// lock, releasing console and fd-object references through destroy hooks.
    #[test]
    fn reaping_a_linux_process_releases_its_fd_references() {
        use core::sync::atomic::AtomicBool;

        static HOOK_RAN: AtomicBool = AtomicBool::new(false);
        static LOCK_FREE: AtomicBool = AtomicBool::new(false);

        fn probe(_payload: u64) {
            HOOK_RAN.store(true, Ordering::SeqCst);
            LOCK_FREE.store(!process_lock_is_held(), Ordering::SeqCst);
        }

        let _guard = global_lock();
        reset_process_state();
        object::reset_destroy_hooks();
        object::register_destroy_hook(ObjectKind::Event, probe).expect("probe hook");

        let console = object::create_console().expect("console object");
        let event = object::create_with_payload(ObjectKind::Event, 0).expect("event object");
        let mut fds = FdTable::new();
        fds.install_console(console).expect("console fds");
        fds.insert(crate::compat::linux::fd::FdEntry::new(event, false))
            .expect("event fd");
        assert_eq!(object::object_refs(event), Some(2));
        // Drop the creation reference: the fd table becomes the only owner, so
        // closing it during reap must run the destroy hook.
        object::release_object(event).expect("release creation reference");
        assert_eq!(object::object_refs(event), Some(1));
        // Three console fds; `create_console` itself starts at refs 0.
        assert_eq!(object::object_refs(console), Some(3));

        let zombie = publish(
            0,
            ProcessState::Zombie,
            None,
            HandleTable::new(),
            AddressSpaceId::INVALID,
            ObjectId::MAX,
            Handle::INVALID,
        );
        with_table(|| unsafe {
            let process = process_ref(zombie.index()).expect("zombie slot");
            process.personality = Personality::Linux64;
            process.fds = fds;
        });

        unsafe { reap(zombie.index()) }.expect("reap succeeds");
        assert!(!process_lock_is_held(), "reap leaked PROCESS_LOCK");
        assert!(
            HOOK_RAN.load(Ordering::SeqCst),
            "event destroy hook never ran"
        );
        assert!(
            LOCK_FREE.load(Ordering::SeqCst),
            "fd close ran with PROCESS_LOCK held"
        );
        // The fd table owned the event's last reference and the console's only
        // owners: both were destroyed by the unlocked teardown.
        assert_eq!(object::object_refs(event), None);
        assert_eq!(object::object_refs(console), None);
        assert_eq!(live_count(), 0);
        reset_process_state();
    }

    /// M7d: `spawn_detached_linux` validates its initial state before loading an
    /// image (host tests have no boot modules, so a valid request ends at
    /// `Image`).
    #[test]
    fn spawn_detached_linux_rejects_bad_initial_state() {
        let _guard = global_lock();
        reset_process_state();
        object::reset_destroy_hooks();

        let console = object::create_console().expect("console object");
        let event = object::create_with_payload(ObjectKind::Event, 0).expect("event object");
        let netns = object::create_with_payload(ObjectKind::NetNamespace, 0).expect("netns");

        // Zero / out-of-mask affinity.
        assert_eq!(
            spawn_detached_linux("worker", 0, console, None, None),
            Err(ProcessError::BadRequest)
        );
        assert_eq!(
            spawn_detached_linux("worker", 0x80, console, None, None),
            Err(ProcessError::BadRequest)
        );
        // The console argument must be a Console object.
        assert_eq!(
            spawn_detached_linux("worker", 0x01, event, None, None),
            Err(ProcessError::Objects(ObjectError::InvalidObject))
        );
        // The network namespace argument must be a NetNamespace object.
        assert_eq!(
            spawn_detached_linux("worker", 0x01, console, None, Some((event, Rights::READ))),
            Err(ProcessError::Objects(ObjectError::InvalidObject))
        );
        // A dead channel object is rejected by the handle insert.
        assert!(
            spawn_detached_linux(
                "worker",
                0x01,
                console,
                Some((ObjectId::MAX, Rights::READ)),
                None
            )
            .is_err()
        );
        // A valid request reaches the (host-empty) image loader and cleans up
        // every reference it acquired on the way.
        assert_eq!(
            spawn_detached_linux("worker", 0x01, console, None, Some((netns, Rights::READ))),
            Err(ProcessError::Image)
        );

        let _ = object::release_object(console);
        let _ = object::release_object(event);
        let _ = object::release_object(netns);
        assert_eq!(live_count(), 0);
        reset_process_state();
    }

    // -- M8c: Linux64 signal state machine ---------------------------------

    fn handler(address: u64) -> SigAction {
        SigAction {
            handler: address,
            ..SigAction::default()
        }
    }

    /// True when `mask` carries the pending/blocked bit of `signo`.
    fn has_bit(mask: u64, signo: u32) -> bool {
        mask & (1u64 << (signo - 1)) != 0
    }

    #[test]
    fn pending_signals_are_deduplicated_and_delivered_lowest_first() {
        test_with_current_handles(HandleTable::new(), || {
            signal_set_action(10, handler(0x1000)).unwrap();
            signal_set_action(12, handler(0x2000)).unwrap();
            signal_send_current(10).unwrap();
            signal_send_current(10).unwrap();
            signal_send_current(12).unwrap();

            let mut buffer = FrameBuffer::new();
            let frame = buffer.as_frame();
            match signal_take_pending(unsafe { &*frame }).unwrap() {
                Some(PendingSignal::Handler { signo, action, .. }) => {
                    assert_eq!(signo, 10);
                    assert_eq!(action.handler, 0x1000);
                }
                other => panic!("expected the first handler, got {:?}", other),
            }
            // Single-slot delivery: no nesting while a handler is in flight.
            assert_eq!(signal_take_pending(unsafe { &*frame }).unwrap(), None);
            signal_restore_context(unsafe { &mut *frame }).unwrap();
            match signal_take_pending(unsafe { &*frame }).unwrap() {
                Some(PendingSignal::Handler { signo, action, .. }) => {
                    assert_eq!(signo, 12);
                    assert_eq!(action.handler, 0x2000);
                }
                other => panic!("expected the second handler, got {:?}", other),
            }
            signal_restore_context(unsafe { &mut *frame }).unwrap();
            assert_eq!(signal_take_pending(unsafe { &*frame }).unwrap(), None);
        });
    }

    #[test]
    fn blocked_signals_wait_until_the_mask_is_cleared() {
        test_with_current_handles(HandleTable::new(), || {
            signal_set_action(10, handler(0x1000)).unwrap();
            let usr1 = 1u64 << (10 - 1);
            assert_eq!(signal_set_mask(SignalMaskHow::Block, usr1).unwrap(), 0);
            assert_eq!(signal_mask().unwrap(), usr1);
            signal_send_current(10).unwrap();

            let mut buffer = FrameBuffer::new();
            let frame = buffer.as_frame();
            assert_eq!(signal_take_pending(unsafe { &*frame }).unwrap(), None);
            assert_eq!(signal_set_mask(SignalMaskHow::Unblock, usr1).unwrap(), usr1);
            assert!(matches!(
                signal_take_pending(unsafe { &*frame }).unwrap(),
                Some(PendingSignal::Handler { signo: 10, .. })
            ));
            signal_restore_context(unsafe { &mut *frame }).unwrap();
            // `rt_sigreturn` restores the pre-delivery mask.
            assert_eq!(signal_mask().unwrap(), 0);
        });
    }

    #[test]
    fn ignored_and_default_actions_are_reported_to_the_personality() {
        test_with_current_handles(HandleTable::new(), || {
            signal_set_action(
                10,
                SigAction {
                    handler: SIG_IGN,
                    ..SigAction::default()
                },
            )
            .unwrap();
            signal_send_current(10).unwrap();
            let mut buffer = FrameBuffer::new();
            let frame = buffer.as_frame();
            assert_eq!(
                signal_take_pending(unsafe { &*frame }).unwrap(),
                Some(PendingSignal::Ignored(10))
            );
            assert_eq!(signal_take_pending(unsafe { &*frame }).unwrap(), None);
            // SIGCHLD is ignored by default, SIGTERM terminates by default.
            signal_send_current(17).unwrap();
            assert_eq!(
                signal_take_pending(unsafe { &*frame }).unwrap(),
                Some(PendingSignal::Ignored(17))
            );
            signal_send_current(15).unwrap();
            assert_eq!(
                signal_take_pending(unsafe { &*frame }).unwrap(),
                Some(PendingSignal::Default(15))
            );
        });
    }

    #[test]
    fn handler_delivery_saves_the_mask_and_round_trips_the_trap_frame() {
        test_with_current_handles(HandleTable::new(), || {
            let action = SigAction {
                handler: 0xDEAD_B000,
                flags: 0,
                restorer: 0x5000,
                mask: 1u64 << (12 - 1),
            };
            signal_set_action(10, action).unwrap();

            let mut buffer = FrameBuffer::new();
            let frame = buffer.as_frame();
            unsafe {
                (*frame).r15 = 0xA1;
                (*frame).r14 = 0xA2;
                (*frame).r13 = 0xA3;
                (*frame).r12 = 0xA4;
                (*frame).rbp = 0xA5;
                (*frame).rbx = 0xA6;
                (*frame).r11 = 0xA7;
                (*frame).r10 = 0xA8;
                (*frame).r9 = 0xA9;
                (*frame).r8 = 0xAA;
                (*frame).rax = 0xAB;
                (*frame).rcx = 0xAC;
                (*frame).rdx = 0xAD;
                (*frame).rsi = 0xAE;
                (*frame).rdi = 0xAF;
                (*frame).rip = 0x4000_0000;
                (*frame).rflags = 0x202;
                (*frame).user_rsp = 0x7000_0000;
                (*frame).user_ss = 0x2B;
            }
            signal_send_current(10).unwrap();
            let (saved, saved_mask) = match signal_take_pending(unsafe { &*frame }).unwrap() {
                Some(PendingSignal::Handler {
                    saved, saved_mask, ..
                }) => (saved, saved_mask),
                other => panic!("expected a handler, got {:?}", other),
            };
            assert_eq!(saved_mask, 0);
            assert_eq!(
                saved.regs,
                [
                    0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD,
                    0xAE, 0xAF
                ]
            );
            assert_eq!(saved.rip, 0x4000_0000);
            assert_eq!(saved.rflags, 0x202);
            assert_eq!(saved.rsp, 0x7000_0000);
            assert_eq!(saved.ss, 0x2B);
            // Auto-block the delivered signal plus the action's mask.
            let mask = signal_mask().unwrap();
            assert!(has_bit(mask, 10));
            assert!(has_bit(mask, 12));

            signal_restore_context(unsafe { &mut *frame }).unwrap();
            assert_eq!(signal_mask().unwrap(), 0);
            unsafe {
                assert_eq!((*frame).r15, 0xA1);
                assert_eq!((*frame).rax, 0xAB);
                assert_eq!((*frame).rdx, 0xAD);
                assert_eq!((*frame).rip, 0x4000_0000);
                assert_eq!((*frame).rflags, 0x202);
                assert_eq!((*frame).user_rsp, 0x7000_0000);
                assert_eq!((*frame).user_ss, 0x2B);
            }
        });
    }

    #[test]
    fn uncatchable_signals_are_rejected_and_never_blocked() {
        test_with_current_handles(HandleTable::new(), || {
            assert_eq!(
                signal_set_action(SIGKILL, SigAction::default()),
                Err(SignalError::Uncatchable)
            );
            assert_eq!(
                signal_set_action(SIGSTOP, SigAction::default()),
                Err(SignalError::Uncatchable)
            );
            // KILL/STOP bits are silently dropped from the blocked mask.
            assert_eq!(signal_set_mask(SignalMaskHow::SetMask, !0).unwrap(), 0);
            let mask = signal_mask().unwrap();
            assert!(!has_bit(mask, SIGKILL));
            assert!(!has_bit(mask, SIGSTOP));
            assert!(has_bit(mask, 10));
            // An uncatchable signal is delivered even with a non-empty mask.
            signal_send_current(SIGKILL).unwrap();
            let mut buffer = FrameBuffer::new();
            let frame = buffer.as_frame();
            assert_eq!(
                signal_take_pending(unsafe { &*frame }).unwrap(),
                Some(PendingSignal::Default(SIGKILL))
            );
        });
    }

    #[test]
    fn signal_numbers_are_validated() {
        test_with_current_handles(HandleTable::new(), || {
            assert_eq!(signal_action(0), Err(SignalError::InvalidSignal));
            assert_eq!(signal_action(32), Err(SignalError::InvalidSignal));
            assert_eq!(signal_send_current(0), Err(SignalError::InvalidSignal));
            assert_eq!(signal_send_current(64), Err(SignalError::InvalidSignal));
            assert_eq!(
                signal_restore_context(unsafe { &mut *FrameBuffer::new().as_frame() }),
                Err(SignalError::NotDelivering)
            );
        });
    }

    #[test]
    fn a_deliverable_signal_wakes_a_blocked_process() {
        test_with_current_handles(HandleTable::new(), || {
            {
                let process = test_process_ref(0).expect("installed process");
                process.state = ProcessState::Blocked;
                process.wake_reason = WakeReason::None;
            }
            signal_send_current(10).unwrap();
            {
                let process = test_process_ref(0).expect("installed process");
                assert_eq!(process.state, ProcessState::Ready);
                assert_eq!(process.wake_reason, WakeReason::Cancelled);
                // Leave the slot the way the fixture expects it.
                process.state = ProcessState::Running;
                process.wake_reason = WakeReason::None;
            }
            with_table(|| queue_remove_unlocked(0));
        });
    }

    #[test]
    fn signal_state_types_have_the_expected_layout() {
        assert_eq!(core::mem::size_of::<SigAction>(), 32);
        assert_eq!(core::mem::size_of::<UserContext>(), 19 * 8);
        // The boot stack is 16 KiB; surface the Process footprint here so any
        // further growth is a deliberate, reviewed change (M8c added the
        // 32-slot signal table: 816 -> 2048 bytes; M8d added `exit_signal`:
        // 2064 bytes; M8f added `fs_base` + `clear_child_tid`: 2080 bytes;
        // M8g added the `ppoll` temporary-mask state to `FdTable`: 2112 bytes;
        // M8g widened the process kernel stack from 4 to 8 frames, so the
        // `stack_frames` array grew 32 -> 64 bytes: 2144 bytes).
        assert_eq!(core::mem::size_of::<Process>(), 2144);
        let state = SignalState::new();
        assert_eq!(state.pending, 0);
        assert_eq!(state.blocked, 0);
        assert!(state.saved.is_none());
        assert!(state.actions.iter().all(|action| action.handler == SIG_DFL));
    }

    #[test]
    fn fs_base_and_clear_child_tid_round_trip_and_default_to_zero() {
        let _guard = global_lock();
        reset_process_state();
        assert_eq!(current_fs_base(), 0, "no current process -> TLS base 0");
        let process = publish(
            0,
            ProcessState::Running,
            None,
            HandleTable::new(),
            AddressSpaceId::INVALID,
            object::ObjectId::MAX,
            Handle::INVALID,
        );
        set_current_index(Some(process.index()));
        assert_eq!(current_fs_base(), 0, "fresh process starts without TLS");
        // `set_current_fs_base` stores the field; the MSR write is skipped on
        // the host because WRMSR is privileged (asserted through the field).
        set_current_fs_base(0x8000_1000).expect("current process stores the TLS base");
        assert_eq!(current_fs_base(), 0x8000_1000);
        assert_eq!(fs_base(process.index()), 0x8000_1000);
        set_current_fs_base(0x8000_2000).expect("updates the TLS base");
        assert_eq!(current_fs_base(), 0x8000_2000);
        // Zero is a valid value for both setters: it restores "no user TLS"
        // and clears a previously registered clear_child_tid.
        set_current_fs_base(0).expect("clearing the TLS base is allowed");
        assert_eq!(current_fs_base(), 0);
        // `set_tid_address`: stores clear_child_tid, returns the Linux pid.
        assert_eq!(set_current_clear_child_tid(0x4000), 1);
        assert_eq!(clear_child_tid(process.index()), 0x4000);
        assert_eq!(
            set_current_clear_child_tid(0),
            1,
            "clearing still returns the Linux pid"
        );
        assert_eq!(clear_child_tid(process.index()), 0);
        // The exit helper ignores address 0 and an invalid address space
        // instead of faulting while the process is being torn down.
        clear_child_tid_on_exit(AddressSpaceId::INVALID, 0);
        clear_child_tid_on_exit(AddressSpaceId::INVALID, 0x4000);
        set_current_index(None);
        reset_process_state();
    }

    /// M8c follow-up: only same-thread nesting is a bug.
    ///
    /// The marker is thread-local, so a nested `with_table` on this thread must
    /// still panic; a parallel host-test thread holding the table is ordinary
    /// SMP contention and must not. This pins the distinction the host-test
    /// assertion relies on (see `with_table`).
    #[test]
    #[should_panic(expected = "process table lock taken twice on one CPU")]
    fn nested_process_table_access_still_panics_on_one_thread() {
        with_table(|| {
            with_table(|| {});
        });
    }

    // -- M8d: path B, pid mapping, cross-process signals and wait4 helpers ---

    #[test]
    fn linux_pids_are_one_based_and_map_back_to_process_slots() {
        let _guard = global_lock();
        reset_process_state();
        let first = publish(
            0,
            ProcessState::Running,
            None,
            HandleTable::new(),
            AddressSpaceId::INVALID,
            ObjectId::MAX,
            Handle::INVALID,
        );
        let second = publish(
            1,
            ProcessState::Running,
            Some(0),
            HandleTable::new(),
            AddressSpaceId::INVALID,
            ObjectId::MAX,
            Handle::INVALID,
        );
        assert_eq!(linux_pid(first), 1);
        assert_eq!(linux_pid(second), 2);
        assert_eq!(process_from_linux_pid(1), Some(first));
        assert_eq!(process_from_linux_pid(2), Some(second));
        assert_eq!(process_from_linux_pid(0), None);
        assert_eq!(process_from_linux_pid(3), None);

        set_current_on(0, Some(0));
        assert_eq!(current_linux_pid(), Some(1));
        assert_eq!(current_parent_id(), None);
        assert_eq!(parent_linux_pid(), None);

        set_current_on(0, Some(1));
        assert_eq!(current_linux_pid(), Some(2));
        assert_eq!(current_parent_id(), Some(first));
        assert_eq!(parent_linux_pid(), Some(1));

        set_current_on(0, None);
        reset_process_state();
    }

    #[test]
    fn signal_send_process_checks_the_parent_child_relationship() {
        let _guard = global_lock();
        reset_process_state();
        let parent = publish(
            0,
            ProcessState::Running,
            None,
            HandleTable::new(),
            AddressSpaceId::INVALID,
            ObjectId::MAX,
            Handle::INVALID,
        );
        let _child = publish(
            1,
            ProcessState::Running,
            Some(0),
            HandleTable::new(),
            AddressSpaceId::INVALID,
            ObjectId::MAX,
            Handle::INVALID,
        );
        let _stranger = publish(
            2,
            ProcessState::Running,
            None,
            HandleTable::new(),
            AddressSpaceId::INVALID,
            ObjectId::MAX,
            Handle::INVALID,
        );

        // parent (pid 1) -> child (pid 2): allowed, queued and deduplicated.
        set_current_on(0, Some(parent.index()));
        assert_eq!(signal_send_process(2, 15), Ok(SignalDecision::new(2)));
        {
            let child = test_process_ref(1).expect("child slot");
            assert_ne!(child.signals.pending & signal_bit(15), 0);
        }
        assert_eq!(signal_send_process(2, 15), Ok(SignalDecision::new(2)));
        // signo == 0 only probes the relationship; garbage signo is rejected.
        assert_eq!(signal_send_process(2, 0), Ok(SignalDecision::new(2)));
        assert_eq!(
            signal_send_process(2, 64),
            Err(SignalSendError::InvalidSignal)
        );
        // Unknown pid and unrelated third process are both ESRCH material.
        assert_eq!(
            signal_send_process(4, 10),
            Err(SignalSendError::NoSuchProcess)
        );
        assert_eq!(
            signal_send_process(3, 10),
            Err(SignalSendError::NoSuchProcess)
        );

        // child -> parent is allowed; self signalling is allowed.
        set_current_on(0, Some(1));
        assert_eq!(signal_send_process(1, 10), Ok(SignalDecision::new(1)));
        assert_eq!(signal_send_process(2, 10), Ok(SignalDecision::new(2)));
        // A stranger may not signal the parent.
        set_current_on(0, Some(2));
        assert_eq!(
            signal_send_process(1, 10),
            Err(SignalSendError::NoSuchProcess)
        );

        set_current_on(0, None);
        reset_process_state();
    }

    #[test]
    fn a_cross_process_signal_wakes_a_blocked_target() {
        let _guard = global_lock();
        reset_process_state();
        let parent = publish(
            0,
            ProcessState::Running,
            None,
            HandleTable::new(),
            AddressSpaceId::INVALID,
            ObjectId::MAX,
            Handle::INVALID,
        );
        let _child = publish(
            1,
            ProcessState::Blocked,
            Some(0),
            HandleTable::new(),
            AddressSpaceId::INVALID,
            ObjectId::MAX,
            Handle::INVALID,
        );
        set_current_on(0, Some(parent.index()));
        assert_eq!(signal_send_process(2, 10), Ok(SignalDecision::new(2)));
        {
            let child = test_process_ref(1).expect("child slot");
            assert_eq!(child.state, ProcessState::Ready);
            assert_eq!(child.wake_reason, WakeReason::Cancelled);
        }
        with_table(|| {
            queue_remove_unlocked(1);
        });
        set_current_on(0, None);
        reset_process_state();
    }

    #[test]
    fn signal_send_children_only_reaches_direct_children() {
        let _guard = global_lock();
        reset_process_state();
        let _parent = publish(
            0,
            ProcessState::Running,
            None,
            HandleTable::new(),
            AddressSpaceId::INVALID,
            ObjectId::MAX,
            Handle::INVALID,
        );
        let _first_child = publish(
            1,
            ProcessState::Running,
            Some(0),
            HandleTable::new(),
            AddressSpaceId::INVALID,
            ObjectId::MAX,
            Handle::INVALID,
        );
        let _second_child = publish(
            2,
            ProcessState::Running,
            Some(0),
            HandleTable::new(),
            AddressSpaceId::INVALID,
            ObjectId::MAX,
            Handle::INVALID,
        );

        set_current_on(0, Some(0));
        assert_eq!(signal_send_children(0), 2);
        assert_eq!(signal_send_children(15), 2);
        for index in 1..=2 {
            let child = test_process_ref(index).expect("child slot");
            assert_ne!(child.signals.pending & signal_bit(15), 0);
        }

        // A child has no children of its own, so the broadcast queue is empty.
        set_current_on(0, Some(1));
        assert_eq!(signal_send_children(15), 0);

        set_current_on(0, None);
        reset_process_state();
    }

    #[test]
    fn signal_pending_for_reports_only_blocked_masked_bits() {
        let _guard = global_lock();
        reset_process_state();
        let current = publish(
            0,
            ProcessState::Running,
            None,
            HandleTable::new(),
            AddressSpaceId::INVALID,
            ObjectId::MAX,
            Handle::INVALID,
        );
        set_current_on(0, Some(current.index()));
        with_table(|| {
            let process = (unsafe { process_ref(current.index()) }).expect("current slot");
            process.signals.pending = signal_bit(SIGKILL)
                | signal_bit(SIGSTOP)
                | signal_bit(10)
                | signal_bit(12)
                | signal_bit(15);
            process.signals.blocked = signal_bit(10) | signal_bit(12);
        });

        let all = SIGNAL_BITS;
        // Only pending signals that are both selected and blocked are reported.
        assert_eq!(
            signal_pending_for(current, all),
            signal_bit(10) | signal_bit(12)
        );
        // Unblocked pending signals stay deliverable and are not reported.
        assert_eq!(signal_pending_for(current, signal_bit(15)), 0);
        // Uncatchable signals are never reported.
        assert_eq!(
            signal_pending_for(current, signal_bit(SIGKILL) | signal_bit(SIGSTOP)),
            0
        );
        // Empty masks and unknown owners are empty.
        assert_eq!(signal_pending_for(current, 0), 0);
        assert_eq!(signal_pending_for(ProcessId::from_index(2), all), 0);

        set_current_on(0, None);
        reset_process_state();
    }

    #[test]
    fn signal_take_pending_for_consumes_lowest_and_skips_uncatchable() {
        let _guard = global_lock();
        reset_process_state();
        let current = publish(
            0,
            ProcessState::Running,
            None,
            HandleTable::new(),
            AddressSpaceId::INVALID,
            ObjectId::MAX,
            Handle::INVALID,
        );
        set_current_on(0, Some(current.index()));
        with_table(|| {
            let process = (unsafe { process_ref(current.index()) }).expect("current slot");
            process.signals.pending =
                signal_bit(SIGKILL) | signal_bit(SIGSTOP) | signal_bit(15) | signal_bit(10);
            process.signals.blocked = signal_bit(10) | signal_bit(15);
        });

        let all = SIGNAL_BITS;
        assert_eq!(signal_take_pending_for(current, all), Some(10));
        assert_eq!(signal_take_pending_for(current, all), Some(15));
        assert_eq!(signal_take_pending_for(current, all), None);
        // Only the consumed signals were cleared; uncatchable pending bits stay.
        with_table(|| {
            let process = (unsafe { process_ref(current.index()) }).expect("current slot");
            assert_eq!(
                process.signals.pending,
                signal_bit(SIGKILL) | signal_bit(SIGSTOP)
            );
        });
        assert_eq!(signal_take_pending_for(ProcessId::from_index(2), all), None);

        set_current_on(0, None);
        reset_process_state();
    }

    #[test]
    fn a_pending_signal_wakes_the_process_waiting_on_its_signalfd() {
        let _guard = global_lock();
        reset_process_state();
        crate::ipc::signalfd::reset_for_test();

        // The process is blocked on the object a signalfd will be bound to.
        let signalfd_object = 0x0B01;
        let process = publish_blocked(0, [signalfd_object, u16::MAX, u16::MAX, u16::MAX], 1, None);
        set_current_on(0, Some(process.index()));
        with_table(|| {
            let slot = (unsafe { process_ref(process.index()) }).expect("current slot");
            slot.signals.blocked = signal_bit(10);
        });
        let payload =
            crate::ipc::signalfd::create(process, signal_bit(10), 0).expect("signalfd table slot");
        crate::ipc::signalfd::bind(payload, signalfd_object).expect("bind signalfd object");
        assert_eq!(crate::ipc::signalfd::readable(signalfd_object), Ok(false));

        // Signal 10 is blocked, so the ordinary interrupt path stays quiet; the
        // waiter must be released by the signalfd notification instead.
        signal_send_current(10).expect("queue signal");
        assert_eq!(state_of(0), ProcessState::Ready);
        assert_eq!(reason_of(0), WakeReason::Ready);
        assert_eq!(crate::ipc::signalfd::readable(signalfd_object), Ok(true));
        assert_eq!(signal_pending_for(process, signal_bit(10)), signal_bit(10));

        with_table(|| {
            queue_remove_unlocked(0);
        });
        crate::ipc::signalfd::on_destroy(signalfd_object);
        crate::ipc::signalfd::reset_for_test();
        set_current_on(0, None);
        reset_process_state();
    }

    #[test]
    fn spawn_linux_child_rejects_bad_preconditions() {
        let _guard = global_lock();
        reset_process_state();
        let parent = publish(
            0,
            ProcessState::Running,
            None,
            HandleTable::new(),
            AddressSpaceId::INVALID,
            ObjectId::MAX,
            Handle::INVALID,
        );
        set_current_on(0, Some(parent.index()));

        // Empty / out-of-range affinity is rejected before any allocation.
        assert_eq!(
            spawn_linux_child(parent, "linux", 0, ObjectId::MAX, None, None, 1),
            Err(ProcessError::BadRequest)
        );
        assert_eq!(
            spawn_linux_child(parent, "linux", 0x10, ObjectId::MAX, None, None, 1),
            Err(ProcessError::BadRequest)
        );
        // Missing parent.
        assert_eq!(
            spawn_linux_child(
                ProcessId::from_index(2),
                "linux",
                0x01,
                ObjectId::MAX,
                None,
                None,
                1
            ),
            Err(ProcessError::NoSuchProcess)
        );

        // Ordering guard: with one child the capacity check passes, so the
        // invalid console (object kind) is what rejects this spawn.
        publish(
            1,
            ProcessState::Running,
            Some(0),
            HandleTable::new(),
            AddressSpaceId::INVALID,
            ObjectId::MAX,
            Handle::INVALID,
        );
        assert_eq!(
            spawn_linux_child(parent, "linux", 0x01, ObjectId::MAX, None, None, 1),
            Err(ProcessError::Objects(ObjectError::InvalidObject))
        );

        // Filling the second slot makes a third spawn a capacity error, reported
        // before any console/object work.
        publish(
            2,
            ProcessState::Running,
            Some(0),
            HandleTable::new(),
            AddressSpaceId::INVALID,
            ObjectId::MAX,
            Handle::INVALID,
        );
        assert_eq!(
            spawn_linux_child(parent, "linux", 0x01, ObjectId::MAX, None, None, 1),
            Err(ProcessError::ChildExists)
        );

        // A zombie parent cannot create another child (capacity aside).
        {
            let process = test_process_ref(0).expect("parent slot");
            process.state = ProcessState::Zombie;
        }
        assert_eq!(
            spawn_linux_child(parent, "linux", 0x01, ObjectId::MAX, None, None, 1),
            Err(ProcessError::NoSuchProcess)
        );

        set_current_on(0, None);
        reset_process_state();
    }

    #[test]
    fn spawn_linux_child_releases_everything_when_the_image_is_missing() {
        let _guard = global_lock();
        reset_process_state();
        let console = object::create_with_payload(ObjectKind::Console, 0).expect("console object");
        let netns = object::create_with_payload(ObjectKind::NetNamespace, 0).expect("netns object");
        let parent = publish(
            0,
            ProcessState::Running,
            None,
            HandleTable::new(),
            AddressSpaceId::INVALID,
            ObjectId::MAX,
            Handle::INVALID,
        );
        set_current_on(0, Some(parent.index()));

        // Host tests have no boot modules: the load must fail cleanly *after*
        // the console/netns handles and the fds were prepared.
        assert_eq!(
            spawn_linux_child(
                parent,
                "linux",
                0x01,
                console,
                None,
                Some((netns, Rights::READ)),
                1
            ),
            Err(ProcessError::Image)
        );
        {
            let parent_process = test_process_ref(0).expect("parent slot");
            assert_eq!(parent_process.child_count(), 0, "no child link on failure");
            assert_eq!(parent_process.handles.len(), 0, "no hidden WAIT handle");
        }
        assert_eq!(live_count(), 1, "no child slot was published");
        // The copied handle references were released; the creation references
        // are the only ones left, so the test must release those explicitly.
        assert_eq!(object::object_refs(console), Some(1));
        assert_eq!(object::object_refs(netns), Some(1));

        object::release_object(netns).expect("release netns");
        object::release_object(console).expect("release console");
        set_current_on(0, None);
        reset_process_state();
    }

    #[test]
    fn wait_helpers_reap_a_zombie_child_and_report_the_signal() {
        let _guard = global_lock();
        reset_process_state();
        let process_object = object::create_process_object().expect("process object");
        let mut parent_handles = HandleTable::new();
        let wait_handle = object::insert_handle(&mut parent_handles, process_object, Rights::WAIT)
            .expect("parent wait handle");
        let _parent = publish(
            0,
            ProcessState::Running,
            None,
            parent_handles,
            AddressSpaceId::INVALID,
            ObjectId::MAX,
            Handle::INVALID,
        );
        let child = publish(
            1,
            ProcessState::Zombie,
            Some(0),
            HandleTable::new(),
            AddressSpaceId::INVALID,
            process_object,
            wait_handle,
        );
        {
            let parent_process = test_process_ref(0).expect("parent slot");
            parent_process.add_child(child);
        }
        {
            let child_process = test_process_ref(1).expect("child slot");
            child_process.exit_status = 7;
            child_process.exit_signal = Some(9);
        }
        assert_eq!(object::object_refs(process_object), Some(1));

        set_current_on(0, Some(0));
        assert_eq!(
            take_child_exit(None),
            Ok(Some(ChildExit {
                pid: 2,
                code: 7,
                signal: Some(9)
            }))
        );
        assert!(test_process_ref(1).is_none(), "the zombie is reaped");
        assert_eq!(
            test_process_ref(0).expect("parent slot").child_count(),
            0,
            "reap clears the parent link"
        );
        assert_eq!(
            object::object_refs(process_object),
            None,
            "reap closes the parent WAIT handle and destroys the object"
        );
        assert_eq!(take_child_exit(None), Err(ProcessError::NoChild));
        assert_eq!(wait_child_pid(2), Err(ProcessError::NoChild));

        set_current_on(0, None);
        reset_process_state();
    }

    #[test]
    fn wait_any_prefers_the_zombie_child_and_keeps_the_other_link() {
        let _guard = global_lock();
        reset_process_state();
        // M9c: two direct children, each with its own Process object and hidden
        // WAIT handle in the parent's table.
        let object_a = object::create_process_object().expect("child a object");
        let object_b = object::create_process_object().expect("child b object");
        let mut parent_handles = HandleTable::new();
        let handle_a = object::insert_handle(&mut parent_handles, object_a, Rights::WAIT)
            .expect("parent wait handle a");
        let handle_b = object::insert_handle(&mut parent_handles, object_b, Rights::WAIT)
            .expect("parent wait handle b");
        let _parent = publish(
            0,
            ProcessState::Running,
            None,
            parent_handles,
            AddressSpaceId::INVALID,
            ObjectId::MAX,
            Handle::INVALID,
        );
        let child_a = publish(
            1,
            ProcessState::Zombie,
            Some(0),
            HandleTable::new(),
            AddressSpaceId::INVALID,
            object_a,
            handle_a,
        );
        let child_b = publish(
            2,
            ProcessState::Running,
            Some(0),
            HandleTable::new(),
            AddressSpaceId::INVALID,
            object_b,
            handle_b,
        );
        {
            let parent_process = test_process_ref(0).expect("parent slot");
            parent_process.add_child(child_a);
            parent_process.add_child(child_b);
        }
        {
            let child_process = test_process_ref(1).expect("child a slot");
            child_process.exit_status = 5;
            child_process.exit_signal = Some(11);
        }

        set_current_on(0, Some(0));
        // wait4(-1) reports/reaps the zombie child first even though a live
        // child is linked after it.
        assert_eq!(child_linux_pid(None), Ok(2));
        assert_eq!(
            take_child_exit(None),
            Ok(Some(ChildExit {
                pid: 2,
                code: 5,
                signal: Some(11)
            }))
        );
        assert!(test_process_ref(1).is_none(), "the zombie child is reaped");
        {
            let parent_process = test_process_ref(0).expect("parent slot");
            assert_eq!(parent_process.child_count(), 1);
            assert!(
                parent_process.child_slot(child_b).is_some(),
                "only the reaped child's link is cleared"
            );
        }
        assert_eq!(object::object_refs(object_a), None);

        // The remaining child is still running: wait4(-1) reports "no exit"
        // instead of reaping it, and an exact wait behaves the same.
        assert_eq!(child_linux_pid(None), Ok(3));
        assert_eq!(take_child_exit(None), Ok(None));
        assert_eq!(child_linux_pid(Some(3)), Ok(3));
        assert_eq!(take_child_exit(Some(3)), Ok(None));

        // Exact wait reaps the second child by pid.
        {
            let child_process = test_process_ref(2).expect("child b slot");
            child_process.state = ProcessState::Zombie;
            child_process.exit_status = 0;
        }
        assert_eq!(
            take_child_exit(Some(3)),
            Ok(Some(ChildExit {
                pid: 3,
                code: 0,
                signal: None
            }))
        );
        assert!(test_process_ref(2).is_none());
        assert_eq!(
            test_process_ref(0).expect("parent slot").child_count(),
            0,
            "both links are gone"
        );
        assert_eq!(object::object_refs(object_b), None);
        assert_eq!(take_child_exit(Some(3)), Err(ProcessError::NoChild));

        set_current_on(0, None);
        reset_process_state();
    }

    #[test]
    fn wait_helpers_hand_the_parent_the_child_object_while_it_runs() {
        let _guard = global_lock();
        reset_process_state();
        let process_object = object::create_process_object().expect("process object");
        let mut parent_handles = HandleTable::new();
        let wait_handle = object::insert_handle(&mut parent_handles, process_object, Rights::WAIT)
            .expect("parent wait handle");
        let _parent = publish(
            0,
            ProcessState::Running,
            None,
            parent_handles,
            AddressSpaceId::INVALID,
            ObjectId::MAX,
            Handle::INVALID,
        );
        let child = publish(
            1,
            ProcessState::Running,
            Some(0),
            HandleTable::new(),
            AddressSpaceId::INVALID,
            process_object,
            wait_handle,
        );
        {
            let parent_process = test_process_ref(0).expect("parent slot");
            parent_process.add_child(child);
        }

        set_current_on(0, Some(0));
        assert_eq!(wait_child_pid(2), Ok(ChildWait::Running(process_object)));
        assert_eq!(child_linux_pid(None), Ok(2));
        assert_eq!(child_linux_pid(Some(2)), Ok(2));
        assert_eq!(child_linux_pid(Some(3)), Err(ProcessError::NoChild));
        assert_eq!(take_child_exit(None), Ok(None));
        assert_eq!(child_wait_object(None), Ok(process_object));
        assert_eq!(wait_child_pid(3), Err(ProcessError::NoChild));

        // A zombie is never handed out as a blockable object: `take_child_exit`
        // owns the reap, while `child_wait_object` tells the caller to replay.
        {
            let child_process = test_process_ref(1).expect("child slot");
            child_process.state = ProcessState::Zombie;
            child_process.exit_status = 3;
        }
        assert_eq!(
            child_wait_object(None),
            Err(ProcessError::NoChild),
            "zombie must be reaped by take_child_exit, not returned as an object"
        );
        assert_eq!(
            take_child_exit(None),
            Ok(Some(ChildExit {
                pid: 2,
                code: 3,
                signal: None
            }))
        );
        assert!(test_process_ref(1).is_none());

        set_current_on(0, None);
        reset_process_state();
    }
}
