//! 8254 PIT used as the calibration reference for the LAPIC timer (M3).
//!
//! Channel 0 is programmed as a rate generator and then *sampled* through the
//! counter-latch command; the elapsed PIT counts give a real-time window for
//! measuring the LAPIC timer frequency. M3 deliberately never enables the PIT
//! interrupt: IRQ0 stays masked in the 8259 and unrouted in the IO APIC, so
//! calibration works with interrupts disabled (as required by `time::init`).

use super::calc;
use super::io::{inb, outb};

/// PIT channel-0 data port.
const PIT_CH0: u16 = 0x40;
/// PIT mode/command port.
const PIT_CMD: u16 = 0x43;

/// Divisor giving the ~100 Hz sampling window used during calibration.
///
/// 1_193_182 Hz / 11_932 = 100.0 Hz, i.e. a 10 ms measurement window.
pub const CALIBRATION_DIVISOR: u16 = 11_932;

/// Program channel 0 as a rate generator (mode 2, binary, lo/hi access).
pub fn program_rate_generator(divisor: u16) {
    // A zero reload means 65536 in mode 2; clamp to the largest explicit value.
    let divisor = if divisor == 0 {
        calc::PIT_MAX_DIVISOR as u16
    } else {
        divisor
    };
    // Channel 0 (bits 7:6 = 00), lo/hi access (bits 5:4 = 11),
    // mode 2 rate generator (bits 3:1 = 010), binary (bit 0 = 0).
    outb(PIT_CMD, 0x34);
    outb(PIT_CH0, (divisor & 0x00FF) as u8);
    outb(PIT_CH0, (divisor >> 8) as u8);
}

/// Latch and read the current channel-0 count.
pub fn latch_and_read() -> u16 {
    outb(PIT_CMD, 0x00); // counter-latch command for channel 0
    let lo = u16::from(inb(PIT_CH0));
    let hi = u16::from(inb(PIT_CH0));
    lo | (hi << 8)
}

/// PIT counts that elapsed between two samples of the programmed channel.
///
/// Returns `None` when the two samples cannot describe a valid window (a reset
/// in between, or a sample outside the programmed divisor).
pub fn counts_since(previous: u16, current: u16) -> Option<u32> {
    calc::elapsed_pit_counts(
        u32::from(CALIBRATION_DIVISOR),
        u32::from(previous),
        u32::from(current),
    )
}
