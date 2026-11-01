//! Early 16550 serial output (COM1-class I/O-port UART) and `klog!`.
//!
//! M1 baseline: a single I/O-port 16550, initialized from the BootInfo
//! EARLY_SERIAL TLV when available (agents.md §5.3 rule 9 allows reading the
//! TLV address parameters before checksum validation, with minimal bounds
//! checks). Port access is inlined I/O; the writer is `fmt::Write`-based and
//! allocation-free.
//!
//! M3 additions (agents.md §22):
//! - One `klog!` line is emitted inside an irqsave critical section: `cli`,
//!   then restore the `IF` state that was found. On the single-CPU M3 target no
//!   lock is needed, so a panic or exception path that logs cannot deadlock,
//!   and an IRQ cannot interleave its own output into the middle of a line.
//! - Once [`crate::time`] reports the monotonic clock is ready, each line ends
//!   with ` [t=N ms]`. Before that the timestamp is omitted instead of being
//!   faked (agents.md §8.4: no invented precision before a clock exists), and
//!   every pre-M3 marker substring is emitted unchanged.
//! - RX-side register helpers are exposed for `input::init` and the COM1 IRQ
//!   handler. The polled TX path below keeps its original behavior.

use core::arch::asm;
use core::fmt;
use core::sync::atomic::{AtomicU16, Ordering};

static SERIAL_PORT: AtomicU16 = AtomicU16::new(0x3F8);

/// 16550 register offsets from the UART base I/O port.
pub const REG_RBR: u16 = 0; // receive buffer (read) / transmit holding (write)
pub const REG_IER: u16 = 1; // interrupt enable
pub const REG_LSR: u16 = 5; // line status

/// `IER` bit 0: interrupt when a received byte is available.
pub const IER_RX_AVAILABLE: u8 = 0x01;
/// `LSR` bit 0: received data available (RBR/FIFO not empty).
pub const LSR_RX_AVAILABLE: u8 = 0x01;

#[inline]
fn outb(port: u16, val: u8) {
    unsafe { asm!("out dx, al", in("dx") port, in("al") val) }
}

#[inline]
fn inb(port: u16) -> u8 {
    let val: u8;
    unsafe { asm!("in al, dx", out("al") val, in("dx") port) };
    val
}

pub fn serial_init(port: u16, baud: u32) {
    if baud == 0 {
        return;
    }
    let divisor = (115200 / baud).max(1) as u16;
    SERIAL_PORT.store(port, Ordering::Relaxed);
    outb(port + REG_IER, 0x00); // IER: no interrupts
    outb(port + 3, 0x80); // LCR: DLAB
    outb(port, (divisor & 0xFF) as u8);
    outb(port + 1, (divisor >> 8) as u8);
    outb(port + 3, 0x03); // LCR: 8N1
    outb(port + 2, 0xC7); // FCR: FIFO on, cleared, 14-byte trigger
    outb(port + 4, 0x0B); // MCR: DTR/RTS/OUT2
}

/// UART base I/O port currently in use (0x3F8 unless the BootInfo TLV says
/// otherwise).
pub fn serial_port() -> u16 {
    SERIAL_PORT.load(Ordering::Relaxed)
}

/// Read one UART register by offset from the base port. Used by
/// `input::init` and the COM1 RX interrupt handler; TX state is untouched.
pub fn serial_read_reg(offset: u16) -> u8 {
    inb(serial_port().wrapping_add(offset))
}

/// Write one UART register by offset from the base port.
pub fn serial_write_reg(offset: u16, value: u8) {
    outb(serial_port().wrapping_add(offset), value)
}

/// `true` when the UART reports a received byte available (LSR bit 0).
pub fn serial_rx_ready() -> bool {
    serial_read_reg(REG_LSR) & LSR_RX_AVAILABLE != 0
}

/// Read the received byte (RBR). Call only after [`serial_rx_ready`].
pub fn serial_read_rx() -> u8 {
    serial_read_reg(REG_RBR)
}

fn serial_putc(c: u8) {
    let port = SERIAL_PORT.load(Ordering::Relaxed);
    let mut spins = 0u32;
    while inb(port + 5) & 0x20 == 0 {
        spins += 1;
        if spins > 1_000_000 {
            return;
        }
    }
    outb(port, c);
}

struct SerialWriter;

impl fmt::Write for SerialWriter {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        for &b in s.as_bytes() {
            serial_putc(b);
        }
        Ok(())
    }
}

/// irqsave guard for one whole log line.
///
/// This is not a lock: it only disables maskable interrupts and restores the
/// previous `IF` state on drop, so it is safe in panic/exception context (where
/// interrupts are already off) and cannot deadlock.
struct IrqGuard {
    /// `IF` state found on entry, restored on drop. Host tests have no `IF`, so
    /// the field is only read on the target build.
    #[cfg_attr(test, allow(dead_code))]
    was_enabled: bool,
}

impl IrqGuard {
    fn acquire() -> Self {
        #[cfg(not(test))]
        let was_enabled = crate::arch::disable_interrupts();
        // Host tests never touch the serial port and have no `IF` to save.
        #[cfg(test)]
        let was_enabled = false;
        Self { was_enabled }
    }
}

impl Drop for IrqGuard {
    fn drop(&mut self) {
        #[cfg(not(test))]
        crate::arch::restore_interrupts(self.was_enabled);
    }
}

/// Write `n` in decimal without allocating: at most 20 digits.
fn write_dec<W: fmt::Write + ?Sized>(w: &mut W, mut n: u64) -> fmt::Result {
    let mut buf = [0u8; 20];
    let mut i = buf.len();
    loop {
        i -= 1;
        buf[i] = b'0' + (n % 10) as u8;
        n /= 10;
        if n == 0 {
            break;
        }
    }
    // Digits are ASCII by construction, so this cannot fail.
    let digits = core::str::from_utf8(&buf[i..]).unwrap_or("0");
    w.write_str(digits)
}

/// Write the message followed by the optional M3 timestamp.
///
/// Kept separate from the port writer so the formatting rule is host-testable:
/// `stamp_millis == None` must leave the line exactly as it was before M3.
fn write_line<W: fmt::Write + ?Sized>(
    w: &mut W,
    args: fmt::Arguments<'_>,
    stamp_millis: Option<u64>,
) -> fmt::Result {
    w.write_fmt(args)?;
    if let Some(ms) = stamp_millis {
        w.write_str(" [t=")?;
        write_dec(w, ms)?;
        w.write_str(" ms]")?;
    }
    Ok(())
}

/// Monotonic milliseconds once the M3 clock is ready; `None` before that.
#[cfg(not(test))]
fn timestamp_millis() -> Option<u64> {
    if crate::time::is_ready() {
        Some(crate::time::monotonic_millis())
    } else {
        None
    }
}

/// Host test builds have no clock, so no timestamp is ever fabricated.
#[cfg(test)]
fn timestamp_millis() -> Option<u64> {
    None
}

/// Emit one fully formatted line (called by the [`klog!`] macro).
///
/// The whole line (message, optional ` [t=N ms]`, CRLF) is written inside one
/// irqsave section so an IRQ handler logging from another path cannot split
/// it; handlers themselves must not log (agents.md §22).
pub fn klog(args: fmt::Arguments<'_>) {
    let guard = IrqGuard::acquire();
    let mut w = SerialWriter;
    let _ = write_line(&mut w, args, timestamp_millis());
    serial_putc(b'\r');
    serial_putc(b'\n');
    drop(guard);
}

/// Write raw bytes to the serial port exactly as given.
///
/// This is the M4 console path: the native `write` syscall hands over bytes the
/// user program already framed, so adding a `[t=...]` suffix or a CRLF here
/// would corrupt the message. Interrupts are masked for the whole call so a
/// console write can never interleave with a [`klog`] line (both share the same
/// 16550 transmitter).
pub fn serial_write_bytes(bytes: &[u8]) {
    let guard = IrqGuard::acquire();
    for &b in bytes {
        serial_putc(b);
    }
    drop(guard);
}

/// Log one `[CaelumKernel]` line to the early serial port.
#[macro_export]
macro_rules! klog {
    ($($arg:tt)*) => { $crate::log::klog(format_args!($($arg)*)) };
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::string::String;

    fn render(args: fmt::Arguments<'_>, stamp_millis: Option<u64>) -> String {
        let mut s = String::new();
        write_line(&mut s, args, stamp_millis).expect("write_line into String");
        s
    }

    fn dec(n: u64) -> String {
        let mut s = String::new();
        write_dec(&mut s, n).expect("write_dec into String");
        s
    }

    #[test]
    fn decimal_rendering_is_exact() {
        assert_eq!(dec(0), "0");
        assert_eq!(dec(7), "7");
        assert_eq!(dec(10), "10");
        assert_eq!(dec(1234), "1234");
        assert_eq!(dec(u64::MAX), "18446744073709551615");
    }

    #[test]
    fn no_timestamp_before_clock_is_ready() {
        // `time::is_ready() == false` must not invent a time.
        assert_eq!(
            render(format_args!("[CaelumKernel] M2 OK"), None),
            "[CaelumKernel] M2 OK"
        );
        assert_eq!(render(format_args!("plain"), None), "plain");
    }

    #[test]
    fn timestamp_is_appended_at_line_end_once_ready() {
        assert_eq!(
            render(format_args!("[CaelumKernel] M3 clock OK"), Some(0)),
            "[CaelumKernel] M3 clock OK [t=0 ms]"
        );
        assert_eq!(
            render(format_args!("[CaelumKernel] M3 input OK"), Some(1234)),
            "[CaelumKernel] M3 input OK [t=1234 ms]"
        );
    }

    #[test]
    fn original_marker_substrings_are_preserved() {
        let line = render(format_args!("[CaelumKernel] M3 serial OK"), Some(42));
        assert!(line.starts_with("[CaelumKernel] M3 serial OK"));
        assert!(line.ends_with("[t=42 ms]"));
        // The timestamp goes after the whole message, never inside a marker.
        assert!(line.contains("[CaelumKernel] M3 serial OK"));
    }

    #[test]
    fn formatting_arguments_still_work_before_and_after_clock() {
        assert_eq!(
            render(format_args!("v{} {} of {}", 3, "abc", 7), None),
            "v3 abc of 7"
        );
        assert_eq!(
            render(format_args!("0x{:04x}", 0x21), Some(5)),
            "0x0021 [t=5 ms]"
        );
    }
}
