//! Futex word waiting (M6a2).
//!
//! A futex wait is deliberately *not* an object: no object-table entry is
//! created, nothing is allocated, and no handle is involved. The syscall layer
//! translates the user address, compares the 32-bit value, and only then calls
//! [`wait`], identifying the word by its **exact physical address**. Matching is
//! therefore value-agnostic and address-space-agnostic: two threads that
//! reached the same physical word through different virtual addresses (or even
//! different address spaces) are woken together, while any other word is not.
//!
//! The blocking machinery itself lives in [`crate::process`] and is shared with
//! object waits: the caller's private `syscall` [`TrapFrame`] is saved, `rip`
//! moves back two bytes so the syscall replays in user space after the wake, and
//! the process slot is marked `Blocked`. That means a woken futex waiter always
//! re-checks the word itself; the kernel never writes user memory here.
//!
//! Wakes may come from a syscall (another thread's `FUTEX_WAKE`) or from the
//! timer ISR (deadline expiry), so both paths are interrupt-safe: no allocation,
//! no object-table access, no printing, and no context switch — only the two
//! process-table slots are touched.
//!
//! This module is the futex-facing surface plus statistics; w8 wires
//! `kernel/src/lib.rs` (`pub mod futex;`) and the syscall side.

use core::sync::atomic::{AtomicU64, Ordering};

use crate::arch::TrapFrame;

/// Number of futex waits that actually blocked since boot.
static BLOCKED_TOTAL: AtomicU64 = AtomicU64::new(0);

/// Number of futex waiters woken through [`wake`] since boot.
static WOKEN_TOTAL: AtomicU64 = AtomicU64::new(0);

/// Block the current process on the futex word at `physical_word`.
///
/// Only callable from the running process's own syscall entry, with the private
/// `top - 184` syscall frame; the contract is the same as
/// [`crate::process::block_current`]. Never returns: the process resumes by
/// replaying the syscall after [`wake`] or a deadline expiry in
/// [`crate::process::wake_expired`].
pub fn wait(frame: *mut TrapFrame, physical_word: u64, deadline: Option<u64>) -> ! {
    BLOCKED_TOTAL.fetch_add(1, Ordering::Relaxed);
    crate::process::block_on_futex(frame, physical_word, deadline)
}

/// Wake at most `max` waiters of the futex word at `physical_word`.
///
/// Returns the number of processes transitioned `Blocked` -> `Ready` (`0..=max`,
/// and `0` when `max == 0`). Safe from interrupt context. The wake records
/// `WakeReason::Ready`; object wakes (`wake_object`/`wake_object_key`) never
/// release futex waiters.
pub fn wake(physical_word: u64, max: usize) -> usize {
    let woken = crate::process::wake_futex(physical_word, max);
    if woken != 0 {
        WOKEN_TOTAL.fetch_add(woken as u64, Ordering::Relaxed);
    }
    woken
}

/// `(waits_that_blocked, waiters_woken)` since boot.
pub fn stats() -> (u64, u64) {
    (
        BLOCKED_TOTAL.load(Ordering::Relaxed),
        WOKEN_TOTAL.load(Ordering::Relaxed),
    )
}

/// Number of live processes currently blocked on some futex word.
pub fn waiter_count() -> usize {
    crate::process::futex_waiters()
}

#[cfg(test)]
mod tests {
    use super::*;

    // The process table is global state: every test that scans or wakes it must
    // hold the same lock the process tests use, otherwise a parallel test could
    // observe (or wake) a waiter another test just published.
    fn table_lock() -> std::sync::MutexGuard<'static, ()> {
        crate::object::test_lock()
    }

    #[test]
    fn fresh_stats_start_at_zero() {
        let _guard = table_lock();
        assert_eq!(stats(), (0, 0));
        assert_eq!(waiter_count(), 0);
    }

    #[test]
    fn waking_an_unobserved_word_wakes_nothing() {
        let _guard = table_lock();
        assert_eq!(wake(0x1234_5000, 1), 0);
        assert_eq!(wake(0x1234_5000, usize::MAX), 0);
        assert_eq!(stats().1, 0);
        assert_eq!(waiter_count(), 0);
    }

    #[test]
    fn zero_max_never_wakes() {
        let _guard = table_lock();
        assert_eq!(wake(0x1234_5000, 0), 0);
        assert_eq!(stats().1, 0);
    }

    #[test]
    fn waiter_count_tracks_process_table_state() {
        let _guard = table_lock();
        // Nothing is published, so no process can be a futex waiter. The count is
        // derived from the process table on every call, not cached here.
        assert_eq!(waiter_count(), 0);
    }
}
