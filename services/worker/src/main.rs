//! CaelumOS `worker`: the M6b2 SMP scheduling workload.
//!
//! init spawns **two** instances of this program and gives them **no initial
//! handles** (`rdi`/`rsi`/`rdx` are 0). Because the worker has no Console it
//! prints nothing: the M6b2 acceptance signal is the kernel-side marker plus
//! the two exit statuses, so the whole user program is deliberately tiny and
//! only touches the syscalls this slice allows.
//!
//! Sequence:
//!
//! 1. Spin on [`native_rt::abi_query`] for [`SPIN_ROUNDS`] iterations. Every
//!    iteration issues a real `syscall` instruction (the runtime keeps the
//!    result in a `static mut`, so `-O` cannot delete the loop), which leaves
//!    the AP timer a long uninterrupted window to preempt this thread and to
//!    let the kernel migrate it to another CPU.
//! 2. Create a one-shot [`IPC_KIND_TIMER`], arm it for [`WORKER_TICKS`]
//!    scheduling ticks, and block on it with an infinite timeout. It is while
//!    blocked here that the two instances are expected to sit on different APs;
//!    the BSP timer expiry is then responsible for waking them across CPUs.
//! 3. Verify the wake reason and exit through `process_exit(0)` immediately.
//!    Nothing long runs after the wake, so the post-wake path is only the exit
//!    syscall.
//!
//! Deliberately unused: Console (there is no handle), VFS, Channel, Port,
//! SharedMemory, EventSubscription, futex and every other syscall. The `Timer`
//! handle is intentionally not closed: closing it would add a syscall after the
//! wake, and the kernel's process-exit path reaps it.

#![no_std]
#![no_main]

use native_abi::{ABI_VERSION, IPC_KIND_TIMER, WAIT_TIMEOUT_INFINITE, WAKE_READY};
use native_rt as rt;

/// Number of `abi_query` round trips before the timer phase.
///
/// Large enough that the timer interrupt (and the AP's own timer) has a real
/// chance to preempt and migrate this thread several times, small enough to keep
/// the acceptance boot short.
const SPIN_ROUNDS: u32 = 100_000;

/// Timer deadline in scheduling ticks (the same unit as `timer_arm`/`wait`).
const WORKER_TICKS: u32 = 20;

/// Exit codes (0 is success). They exist for the kernel's exit diagnostics: the
/// worker has no Console, so a failure can only be reported this way.
const EXIT_ABI_VERSION: u64 = 0x60;
const EXIT_ABI_STATUS: u64 = 0x61;
const EXIT_TIMER_CREATE: u64 = 0x62;
const EXIT_TIMER_ARM: u64 = 0x63;
const EXIT_WAIT: u64 = 0x64;
const EXIT_WAKE_REASON: u64 = 0x65;

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    // Phase 1: bounded syscall loop. The result is consumed every iteration, so
    // the call cannot be hoisted out of the loop, and a build against the wrong
    // ABI is reported instead of silently "working".
    let mut round = 0;
    while round < SPIN_ROUNDS {
        // `ABI_VERSION` comes from the shared crate, so an ABI bump can never
        // leave this freestanding binary hard-coding a stale version word.
        match rt::abi_query() {
            Ok(version) if version == ABI_VERSION => {}
            Ok(_) => rt::process_exit(EXIT_ABI_VERSION),
            Err(_) => rt::process_exit(EXIT_ABI_STATUS),
        }
        round += 1;
    }

    // Phase 2: arm the one-shot timer and block with no timeout. Both worker
    // instances are expected to be on different APs while blocked here.
    let timer = match rt::ipc_create_kind(IPC_KIND_TIMER, 0, 0, 0) {
        Ok(handle) => handle,
        Err(_) => rt::process_exit(EXIT_TIMER_CREATE),
    };
    if rt::timer_arm(timer, WORKER_TICKS, 0).is_err() {
        rt::process_exit(EXIT_TIMER_ARM);
    }
    let out = match rt::wait_one(timer, 0, WAIT_TIMEOUT_INFINITE) {
        Ok(out) => out,
        Err(_) => rt::process_exit(EXIT_WAIT),
    };

    // Phase 3: the one-shot timer must have fired; exit immediately after the
    // wake without running any further loop.
    if out.wake_reason != WAKE_READY || !out.is_ready(0) {
        rt::process_exit(EXIT_WAKE_REASON);
    }
    rt::process_exit(0)
}
