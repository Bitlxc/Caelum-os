//! LAPIC timer calibration and periodic programming (M3).
//!
//! The LAPIC timer frequency is measured against the PIT: the LAPIC timer runs
//! in one-shot mode with the largest reload, the PIT channel 0 provides a
//! known real-time window (~10 ms), and the observed difference yields LAPIC
//! counts per second. The whole procedure runs with interrupts disabled and
//! never enables the PIT interrupt, so no vector has to exist yet.
//!
//! `time` owns the tick semantics; this module only programs hardware and
//! reports the rate it actually achieved.

use super::{apic, calc, pit};

/// LAPIC counts per second from the last calibration; 0 means "not calibrated".
static mut CALIBRATED_HZ: u32 = 0;

/// Calibrate the LAPIC timer against the PIT and remember the result.
///
/// `vector` is stored in the (masked) LVT entry for later reuse; passing it here
/// keeps the timer configuration in one place.
pub fn calibrate(lapic: &apic::Lapic, vector: u8) -> Result<u32, &'static str> {
    // Divide-by-1 keeps the measured resolution as fine as possible.
    lapic.write(apic::REG_TIMER_DIV, apic::TIMER_DIVIDE_BY_1);
    // One-shot mode, masked: calibration only observes the counter, it must not
    // deliver an interrupt before the IDT has a timer gate.
    lapic.write(
        apic::REG_LVT_TIMER,
        apic::LVT_MASK | (u32::from(vector) & 0xFF),
    );
    lapic.write(apic::REG_TIMER_INIT, u32::MAX);

    pit::program_rate_generator(pit::CALIBRATION_DIVISOR);
    let first = pit::latch_and_read();
    let start = lapic.read(apic::REG_TIMER_CUR);

    // Poll the latched PIT count until half a calibration window has passed.
    let window = u32::from(pit::CALIBRATION_DIVISOR) / 2;
    let mut elapsed = 0u32;
    let mut attempts = 0u32;
    while attempts < 1_000_000 {
        let current = pit::latch_and_read();
        match pit::counts_since(first, current) {
            Some(counts) if counts >= window => {
                elapsed = counts;
                break;
            }
            Some(_) => {}
            // A sample outside the programmed divisor means the channel was
            // reprogrammed from under us: do not derive a frequency from it.
            None => return Err("pit-sample-invalid"),
        }
        attempts += 1;
    }
    if elapsed == 0 {
        return Err("pit-sampling-timeout");
    }

    let end = lapic.read(apic::REG_TIMER_CUR);
    // Stop the down-counter before switching modes.
    lapic.write(apic::REG_TIMER_INIT, 0);

    // `end <= start` because the counter counts down; a larger value means it
    // already wrapped, which the 32-bit reload over a 10 ms window cannot do on
    // sane hardware, so treat it as a failed measurement.
    let lapic_delta = start.checked_sub(end).ok_or("lapic-count-wrapped")?;
    let hz = calc::lapic_hz_from_pit(lapic_delta, elapsed).ok_or("lapic-calibration-failed")?;

    // SAFETY: written once from the single-CPU init path before the periodic
    // timer starts; afterwards it is read-only.
    unsafe { core::ptr::addr_of_mut!(CALIBRATED_HZ).write(hz) }
    Ok(hz)
}

/// Start the periodic LAPIC timer on the CPU executing this call at `target_hz`.
///
/// This is the per-CPU entry point (M6b2) shared by the boot processor and APs:
/// every CPU programs its own LAPIC timer with the frequency the boot processor
/// measured, so nobody re-runs the PIT calibration and the global tick
/// bookkeeping in `time` is untouched. The caller must have enabled this CPU's
/// local APIC and installed the gate for `vector` first.
///
/// Returns the rate the hardware will actually deliver (integer division means
/// it can be slightly above `target_hz`). Requires [`calibrate`] to have run.
pub fn start_local(lapic: &apic::Lapic, vector: u8, target_hz: u32) -> Result<u32, &'static str> {
    let hz = calibrated_hz();
    if hz == 0 {
        return Err("timer-not-calibrated");
    }
    let count = calc::periodic_initial_count(hz, target_hz).ok_or("timer-rate-out-of-range")?;

    lapic.write(apic::REG_TIMER_DIV, apic::TIMER_DIVIDE_BY_1);
    lapic.write(
        apic::REG_LVT_TIMER,
        (u32::from(vector) & 0xFF) | apic::TIMER_MODE_PERIODIC,
    );
    lapic.write(apic::REG_TIMER_INIT, count);

    // `count` is non-zero, so the division is safe.
    Ok(hz / count)
}

/// Start the periodic LAPIC timer at `target_hz` (boot-processor entry point).
///
/// Same hardware programming as [`start_local`]; this is the M3 name kept for the
/// boot path that `platform::start_periodic_timer` already drives.
pub fn start_periodic(
    lapic: &apic::Lapic,
    vector: u8,
    target_hz: u32,
) -> Result<u32, &'static str> {
    start_local(lapic, vector, target_hz)
}

/// LAPIC timer frequency measured by the last calibration, 0 if not calibrated.
pub fn calibrated_hz() -> u32 {
    // SAFETY: written once during init before any reader can observe it; a
    // plain 32-bit load is atomic on x86-64.
    unsafe { *core::ptr::addr_of!(CALIBRATED_HZ) }
}
