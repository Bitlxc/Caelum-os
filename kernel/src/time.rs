//! Minimal monotonic time (M3).
//!
//! Hardware programming lives in `crate::platform`; this module owns the *clock
//! semantics*: one 64-bit tick counter advanced by the periodic timer interrupt
//! and the tick ↔ millisecond conversion. Nothing here prints, allocates or
//! locks, so [`on_timer`] is safe to call from the interrupt path.
//!
//! Scope is deliberately M3-sized: a single monotonic domain. Realtime,
//! clocksource switching and tickless operation are later milestones.

use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};

use crate::arch;
use crate::platform::{self, calc};

/// Periodic timer rate requested by M3: 100 Hz, i.e. a 10 ms tick.
pub const TICK_HZ: u32 = 100;

/// Set once the periodic timer runs; published with release ordering.
static READY: AtomicBool = AtomicBool::new(false);
/// Monotonic tick counter; written only by the timer interrupt.
static TICKS: AtomicU64 = AtomicU64::new(0);
/// Rate actually delivered by the hardware (integer calibration division).
static TICK_RATE: AtomicU32 = AtomicU32::new(TICK_HZ);

/// Calibrate and start the monotonic clock.
///
/// Must be called with interrupts disabled: the PIT-based calibration
/// busy-waits ~10 ms and must not take a timer interrupt mid-measurement.
pub fn init() -> Result<(), &'static str> {
    if is_ready() {
        return Err("time-already-initialised");
    }
    let rate = platform::start_periodic_timer(TICK_HZ)?;
    if rate == 0 {
        return Err("time-zero-tick-rate");
    }
    TICK_RATE.store(rate, Ordering::Relaxed);
    TICKS.store(0, Ordering::Relaxed);
    READY.store(true, Ordering::Release);
    Ok(())
}

/// Advance the monotonic clock; called from the timer interrupt handler.
pub fn on_timer() {
    // Interrupt context: one atomic increment, nothing that can block.
    TICKS.fetch_add(1, Ordering::Relaxed);
}

/// Whether the clock is running.
pub fn is_ready() -> bool {
    READY.load(Ordering::Acquire)
}

/// Monotonic tick count since [`init`].
pub fn monotonic_ticks() -> u64 {
    TICKS.load(Ordering::Relaxed)
}

/// Monotonic milliseconds since [`init`].
pub fn monotonic_millis() -> u64 {
    calc::ticks_to_millis(monotonic_ticks(), tick_hz())
}

/// Tick rate currently driving [`on_timer`].
pub fn tick_hz() -> u32 {
    TICK_RATE.load(Ordering::Relaxed)
}

/// Busy-wait for `delta` timer ticks.
///
/// Requires interrupts enabled: the wait is satisfied by `arch::idle`, which
/// halts until the next interrupt. The tick comparison uses wrapping arithmetic
/// so the wait remains correct across counter wrap. Returns immediately when the
/// clock is not running, because no tick would ever arrive.
pub fn wait_for_ticks(delta: u64) {
    if delta == 0 || !is_ready() {
        return;
    }
    let start = monotonic_ticks();
    while monotonic_ticks().wrapping_sub(start) < delta {
        arch::idle();
    }
}
