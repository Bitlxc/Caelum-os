//! Interrupt-aware spin locks (M6b2a).
//!
//! M6b1 brought the application processors online with `IF = 0` and left them
//! idle; nothing in the kernel was actually concurrent yet. M6b2a starts
//! replacing the "one CPU, so `cli` is enough" assumption with a lock that is
//! correct when several CPUs are in the kernel at the same time.
//!
//! # Why a spin lock also has to touch `IF`
//!
//! A plain `AtomicBool` spin lock alone is not enough in a kernel: the boot
//! processor acquires the lock with interrupts enabled, an interrupt handler
//! runs on the *same* CPU and tries to take the same lock, and the CPU spins on
//! a lock it is itself holding — a self-deadlock that no other CPU can resolve.
//! So [`IrqSpinLock`] pins the local interrupt flag down *before* it starts
//! spinning:
//!
//! 1. save `RFLAGS.IF` and clear it (`cli`) — from now on no interrupt handler
//!    can run on this CPU;
//! 2. spin on the lock word with `Acquire` until the compare-and-swap wins;
//! 3. on `Drop`: store `false` with `Release`, *then* restore the saved `IF`.
//!
//! Restoring `IF` after the release is deliberate: an interrupt taken the
//! moment the lock is free must never observe the lock as still held.
//!
//! # Contract
//!
//! * **Not reentrant.** Taking the same lock twice on one CPU spins forever;
//!   that is a programming error, not a recoverable condition.
//! * **A guard must not leave the CPU that took it.** It is `!Send` (and
//!   `!Sync`) by construction: the saved `IF` value only means anything on the
//!   CPU that executed the `cli`, and a guard restored on another CPU would
//!   re-enable interrupts in the wrong place.
//! * **Do not take locks with interrupts already disabled unless the lock
//!   order is fixed.** Nesting works (`cli` is idempotent and each acquisition
//!   remembers its own entry state), but a lock-then-lock chain must use the
//!   same order everywhere to stay deadlock-free.
//!
//! # Relationship to `IrqCell`
//!
//! `ipc::IrqCell` is the existing single-CPU table wrapper: on the real target
//! it just disables interrupts while a closure runs. Wrapping that same closure
//! body in [`IrqSpinLock::with`] is what turns it into a real lock on a
//! multi-CPU kernel without changing the call sites, which is the planned
//! M6b2b direction. This module deliberately ships only the primitive.

use core::hint::spin_loop;
use core::marker::PhantomData;
use core::sync::atomic::{AtomicBool, Ordering};

/// Local interrupt state, abstracted so host tests can exercise the save /
/// restore logic without executing privileged `cli`/`sti` instructions.
mod interrupts {
    #[cfg(not(test))]
    mod imp {
        /// Save `RFLAGS.IF` and clear it; returns whether it was enabled.
        pub fn disable() -> bool {
            crate::arch::disable_interrupts()
        }

        /// Restore the state returned by [`disable`].
        pub fn restore(was_enabled: bool) {
            crate::arch::restore_interrupts(was_enabled);
        }
    }

    #[cfg(test)]
    mod imp {
        use core::sync::atomic::{AtomicBool, Ordering};

        /// Emulated `RFLAGS.IF`, so tests can observe the save/restore pair.
        pub(super) static TEST_IF: AtomicBool = AtomicBool::new(false);

        /// Save `RFLAGS.IF` and clear it; returns whether it was enabled.
        pub fn disable() -> bool {
            TEST_IF.swap(false, Ordering::AcqRel)
        }

        /// Restore the state returned by [`disable`].
        pub fn restore(was_enabled: bool) {
            TEST_IF.store(was_enabled, Ordering::Release);
        }
    }

    pub use imp::{disable, restore};

    /// Test-only probe: is the emulated `RFLAGS.IF` set?
    #[cfg(test)]
    pub fn test_flag() -> bool {
        imp::TEST_IF.load(core::sync::atomic::Ordering::Acquire)
    }

    /// Test-only setter for the emulated `RFLAGS.IF`.
    #[cfg(test)]
    pub fn set_test_flag(enabled: bool) {
        imp::TEST_IF.store(enabled, core::sync::atomic::Ordering::Release);
    }
}

/// Test-only probe for the emulated interrupt flag.
#[cfg(test)]
pub(crate) fn test_interrupts_enabled() -> bool {
    interrupts::test_flag()
}

/// Test-only setter for the emulated interrupt flag.
#[cfg(test)]
pub(crate) fn set_test_interrupts(enabled: bool) {
    interrupts::set_test_flag(enabled);
}

/// A spin lock that disables local interrupts while it is held.
///
/// See the module documentation for the contract. The lock owns no data; pair it
/// with a `static mut` payload (or wrap an existing `IrqCell` body) and do all
/// payload access inside [`IrqSpinLock::with`].
#[derive(Debug)]
pub struct IrqSpinLock {
    locked: AtomicBool,
}

impl IrqSpinLock {
    /// Create an unlocked spin lock (usable in a `static`).
    pub const fn new() -> Self {
        IrqSpinLock {
            locked: AtomicBool::new(false),
        }
    }

    /// Acquire the lock, disabling local interrupts first.
    ///
    /// Spins until the lock word can be taken with an `Acquire` compare-and-swap.
    /// The returned guard releases the lock and restores the interrupt flag.
    pub fn lock(&self) -> IrqGuard<'_> {
        let if_was_enabled = interrupts::disable();
        while self
            .locked
            .compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            // Keep the read-only spin cheap; the CAS above is the slow path.
            while self.locked.load(Ordering::Relaxed) {
                spin_loop();
            }
        }
        IrqGuard {
            lock: self,
            if_was_enabled,
            _not_send: PhantomData,
        }
    }

    /// Run `f` while holding the lock.
    ///
    /// Equivalent to [`IrqSpinLock::lock`] plus `Drop`, without the guard
    /// leaving the call site. This is the intended form for replacing the body
    /// of an `IrqCell::with` closure.
    pub fn with<R>(&self, f: impl FnOnce() -> R) -> R {
        let guard = self.lock();
        let result = f();
        drop(guard);
        result
    }

    /// Try to take the lock without spinning.
    ///
    /// Returns `None` when another CPU holds it; local interrupts are restored
    /// immediately in that case.
    pub fn try_lock(&self) -> Option<IrqGuard<'_>> {
        let if_was_enabled = interrupts::disable();
        if self
            .locked
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_ok()
        {
            Some(IrqGuard {
                lock: self,
                if_was_enabled,
                _not_send: PhantomData,
            })
        } else {
            interrupts::restore(if_was_enabled);
            None
        }
    }

    /// Whether the lock is currently held by anyone (diagnostics/tests only).
    pub fn is_locked(&self) -> bool {
        self.locked.load(Ordering::Acquire)
    }
}

impl Default for IrqSpinLock {
    fn default() -> Self {
        IrqSpinLock::new()
    }
}

/// RAII handle returned by [`IrqSpinLock::lock`].
///
/// Releases the lock with `Release` ordering and then restores the caller's
/// interrupt flag. `!Send`/`!Sync`: it must be dropped on the CPU that took it.
#[derive(Debug)]
pub struct IrqGuard<'a> {
    lock: &'a IrqSpinLock,
    if_was_enabled: bool,
    /// `*mut ()` is neither `Send` nor `Sync`, which makes the guard CPU-bound.
    _not_send: PhantomData<*mut ()>,
}

impl Drop for IrqGuard<'_> {
    fn drop(&mut self) {
        // Release first, restore `IF` second: see the module documentation.
        self.lock.locked.store(false, Ordering::Release);
        interrupts::restore(self.if_was_enabled);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Serialize tests that share the emulated interrupt flag and start every
    /// test from a known `IF = 0`. Without the reset a test that deliberately
    /// enables interrupts and leaves them enabled would make the "entry state
    /// is remembered" assertions depend on execution order.
    fn serial() -> std::sync::MutexGuard<'static, ()> {
        let guard = crate::object::test_lock();
        set_test_interrupts(false);
        guard
    }

    #[test]
    fn lock_reports_held_state_until_dropped() {
        let _serial = serial();
        let spin = IrqSpinLock::new();
        assert!(!spin.is_locked());
        {
            let guard = spin.lock();
            assert!(spin.is_locked());
            assert!(!guard.if_was_enabled);
        }
        assert!(!spin.is_locked());
    }

    #[test]
    fn with_returns_the_closure_result_and_releases() {
        let _serial = serial();
        let spin = IrqSpinLock::new();
        let value = spin.with(|| 21 * 2);
        assert_eq!(value, 42);
        assert!(!spin.is_locked());
    }

    #[test]
    fn guard_saves_and_restores_the_interrupt_flag() {
        let _serial = serial();
        let spin = IrqSpinLock::new();

        set_test_interrupts(true);
        {
            let guard = spin.lock();
            assert!(guard.if_was_enabled, "entry state must be remembered");
            assert!(
                !test_interrupts_enabled(),
                "interrupts must be disabled while held"
            );
        }
        assert!(test_interrupts_enabled(), "entry state must be restored");

        set_test_interrupts(false);
        {
            let guard = spin.lock();
            assert!(!guard.if_was_enabled);
        }
        assert!(
            !test_interrupts_enabled(),
            "an IF=0 entry must stay IF=0 after the guard"
        );
    }

    #[test]
    fn nested_locks_restore_the_entry_state_of_each_acquisition() {
        let _serial = serial();
        let outer = IrqSpinLock::new();
        let inner = IrqSpinLock::new();

        set_test_interrupts(true);
        {
            let first = outer.lock();
            assert!(first.if_was_enabled);
            {
                let second = inner.lock();
                // The inner acquisition saw IF=0 and must leave it that way.
                assert!(!second.if_was_enabled);
            }
            assert!(
                !test_interrupts_enabled(),
                "inner lock must not re-enable IF"
            );
        }
        assert!(
            test_interrupts_enabled(),
            "outer lock restores the entry state"
        );
    }

    #[test]
    fn try_lock_reports_contention_and_restores_its_entry_flag() {
        let _serial = serial();
        let spin = IrqSpinLock::new();

        // Uncontended: the guard is handed out and IF is restored on drop.
        set_test_interrupts(true);
        {
            let guard = spin.try_lock().expect("unlocked lock must be taken");
            assert!(spin.is_locked());
            assert!(guard.if_was_enabled);
            assert!(!test_interrupts_enabled());
        }
        assert!(!spin.is_locked());
        assert!(test_interrupts_enabled());

        // Contended (emulated by the guard this test already holds): `None`
        // and the flag returns to what it was on entry.
        set_test_interrupts(true);
        let held = spin.lock();
        set_test_interrupts(true);
        assert!(spin.try_lock().is_none());
        assert!(
            test_interrupts_enabled(),
            "a failed try_lock must restore its own entry state"
        );
        drop(held);
    }
}
