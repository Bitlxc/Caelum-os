//! Pure calibration and clock arithmetic for the M3 platform layer.
//!
//! No kernel dependencies, no `unsafe`, no `alloc`: the port/MMIO register
//! access lives in `pit.rs`/`apic.rs`/`timer.rs`, and the tick counters live in
//! `crate::time`. Everything here is integer math, so it is host-testable.
//!
//! Units are explicit in every name: PIT counts (1.193182 MHz input clock),
//! LAPIC timer counts (bus-clock derived, calibrated), and ticks of the
//! periodic kernel timer (100 Hz in M3).

/// PIT input clock; every 8254-compatible PIT is driven at 1.193182 MHz.
pub const PIT_HZ: u32 = 1_193_182;
/// Largest PIT divisor representable in the 16-bit count register.
pub const PIT_MAX_DIVISOR: u32 = 0xFFFF;
/// Counts elapsed between two latched PIT samples of a down-counter.
///
/// The channel counts `divisor ... 1`, then reloads `divisor`. A sample that
/// grew therefore wrapped once; anything else is a plain decrease. Returns
/// `None` when the inputs cannot come from the same programmed channel.
pub fn elapsed_pit_counts(divisor: u32, previous: u32, current: u32) -> Option<u32> {
    if divisor == 0 || divisor > PIT_MAX_DIVISOR {
        return None;
    }
    if previous > divisor || current > divisor {
        return None;
    }
    Some(if current <= previous {
        previous - current
    } else {
        // Wrapped: `previous` counts down to 0, then reload to `divisor`.
        previous + (divisor - current)
    })
}

/// LAPIC timer frequency (Hz) from a calibration measurement.
///
/// `lapic_delta` counts were observed to elapse while `pit_counts` PIT counts
/// elapsed, so `hz = lapic_delta * PIT_HZ / pit_counts`. The LAPIC timer is a
/// down-counter, so callers pass `initial - current` as the delta.
pub fn lapic_hz_from_pit(lapic_delta: u32, pit_counts: u32) -> Option<u32> {
    if lapic_delta == 0 || pit_counts == 0 {
        return None;
    }
    let hz = (u64::from(lapic_delta) * u64::from(PIT_HZ)) / u64::from(pit_counts);
    if hz == 0 || hz > u64::from(u32::MAX) {
        None
    } else {
        Some(hz as u32)
    }
}

/// Initial LAPIC timer count for a periodic timer at `target_hz`.
///
/// Returns `None` when the target rate is zero or finer than the calibrated
/// LAPIC frequency can express (a zero reload count would stop the timer).
pub fn periodic_initial_count(lapic_hz: u32, target_hz: u32) -> Option<u32> {
    if lapic_hz == 0 || target_hz == 0 {
        return None;
    }
    let count = lapic_hz / target_hz;
    if count == 0 { None } else { Some(count) }
}

/// Convert timer ticks to milliseconds, saturating at `u64::MAX`.
pub fn ticks_to_millis(ticks: u64, tick_hz: u32) -> u64 {
    if tick_hz == 0 {
        return 0;
    }
    let millis = (u128::from(ticks) * 1_000) / u128::from(tick_hz);
    if millis > u128::from(u64::MAX) {
        u64::MAX
    } else {
        millis as u64
    }
}

// ---------------------------------------------------------------------------
// Host tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// PIT counts covered by the ~42 ms measurement window used in these tests.
    const PIT_MEASURE_COUNTS: u32 = 50_000;

    #[test]
    fn elapsed_counts_handles_plain_decrease() {
        // Channel counting down 8000 -> 7900: 100 counts elapsed.
        assert_eq!(elapsed_pit_counts(11932, 8000, 7900), Some(100));
        assert_eq!(elapsed_pit_counts(11932, 7900, 7900), Some(0));
    }

    #[test]
    fn elapsed_counts_handles_reload() {
        // 10 down to 1 (9 counts), the reload step 1 -> 11932 (1 count), then
        // 11932 down to 11930 (2 counts): 12 counts elapsed in total.
        assert_eq!(elapsed_pit_counts(11932, 10, 11930), Some(12));
        // The sample straddling the reload is exactly one count.
        assert_eq!(elapsed_pit_counts(11932, 1, 11932), Some(1));
        assert_eq!(elapsed_pit_counts(0xFFFF, 1, 0xFFFF), Some(1));
    }

    #[test]
    fn elapsed_counts_rejects_bad_input() {
        // Divisor must be a programmed 16-bit count.
        assert_eq!(elapsed_pit_counts(0, 10, 5), None);
        assert_eq!(elapsed_pit_counts(0x1_0000, 10, 5), None);
        // Samples cannot exceed the divisor.
        assert_eq!(elapsed_pit_counts(100, 101, 50), None);
        assert_eq!(elapsed_pit_counts(100, 50, 101), None);
    }

    #[test]
    fn lapic_hz_roundtrip() {
        // 100_000 LAPIC counts over 100_000 PIT counts is exactly PIT_HZ.
        assert_eq!(lapic_hz_from_pit(100_000, 100_000), Some(PIT_HZ));
        // A 100 MHz LAPIC over the ~42 ms window used at boot.
        let delta = 4_194_304u32; // 100 MHz * 41.94304 ms
        let hz = lapic_hz_from_pit(delta, PIT_MEASURE_COUNTS).unwrap();
        let expected =
            (u64::from(delta) * u64::from(PIT_HZ) / u64::from(PIT_MEASURE_COUNTS)) as u32;
        assert_eq!(hz, expected);
        assert!(hz > 99_000_000 && hz < 101_000_000, "hz = {hz}");
    }

    #[test]
    fn lapic_hz_rejects_degenerate_measurements() {
        assert_eq!(lapic_hz_from_pit(0, 50_000), None);
        assert_eq!(lapic_hz_from_pit(1234, 0), None);
        // A full 32-bit delta would imply a clock above u32::MAX Hz.
        assert_eq!(lapic_hz_from_pit(u32::MAX, PIT_MEASURE_COUNTS), None);
        // A one-count delta still yields the low-but-non-zero result; the
        // caller's "calibration must be plausible" check is the boot path's.
        assert_eq!(lapic_hz_from_pit(1, PIT_MEASURE_COUNTS), Some(23));
    }

    #[test]
    fn periodic_count_for_100hz() {
        assert_eq!(periodic_initial_count(100_000_000, 100), Some(1_000_000));
        assert_eq!(periodic_initial_count(PIT_HZ, 100), Some(11_931));
        assert_eq!(periodic_initial_count(100, 100), Some(1));
        assert_eq!(periodic_initial_count(100, 0), None);
        assert_eq!(periodic_initial_count(0, 100), None);
        // Target faster than the timer can count: refuse rather than reload 0.
        assert_eq!(periodic_initial_count(99, 100), None);
    }

    #[test]
    fn tick_conversions_are_wrap_safe() {
        assert_eq!(ticks_to_millis(0, 100), 0);
        assert_eq!(ticks_to_millis(1, 100), 10);
        assert_eq!(ticks_to_millis(1234, 100), 12_340);
        // 100 Hz to 1 kHz scaling stays exact.
        assert_eq!(ticks_to_millis(1, 1000), 1);
        // No division by zero and no overflow on absurd inputs.
        assert_eq!(ticks_to_millis(1, 0), 0);
        assert_eq!(ticks_to_millis(u64::MAX, 100), u64::MAX); // saturates
    }
}
