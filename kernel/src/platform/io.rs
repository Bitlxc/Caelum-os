//! Raw port I/O used by the M3 platform layer.
//!
//! Kept in one place so the PIT (channel-0 sampling), the 8259 masking and the
//! legacy delay sink share a single, reviewed set of instructions. Only the
//! fixed legacy devices the platform layer owns are touched here.

use core::arch::asm;

/// Write `value` to the 8-bit I/O port `port`.
#[inline]
pub fn outb(port: u16, value: u8) {
    // SAFETY: plain port output to a device the platform layer owns; no memory
    // is read or written by this instruction.
    unsafe {
        asm!(
            "out dx, al",
            in("dx") port,
            in("al") value,
            options(nomem, nostack, preserves_flags)
        )
    }
}

/// Read the 8-bit I/O port `port`.
#[inline]
pub fn inb(port: u16) -> u8 {
    let value: u8;
    // SAFETY: see `outb`.
    unsafe {
        asm!(
            "in al, dx",
            out("al") value,
            in("dx") port,
            options(nomem, nostack, preserves_flags)
        )
    };
    value
}

/// Short settling delay for chips that need time between command bytes.
#[inline]
pub fn io_delay() {
    // Port 0x80 is the POST diagnostic port and is the conventional delay sink;
    // writing to it has no side effect on QEMU or real PCs.
    outb(0x80, 0);
}

// --- crate-internal port I/O DDI ---------------------------------------------
//
// Device drivers (M5b `io` module and later) must not carry inline assembly of
// their own: the instructions live here, the driver only names a port and a
// width. These are pure port accesses with no device policy — no reset, no
// probing, no sequencing, no error path.

/// Read one byte from I/O `port`.
#[inline]
#[allow(dead_code)] // crate-internal port I/O DDI; consumed by the io/block drivers
pub(crate) fn io_read8(port: u16) -> u8 {
    inb(port)
}

/// Read one 16-bit word from I/O `port`.
#[inline]
#[allow(dead_code)] // crate-internal port I/O DDI; consumed by the io/block drivers
pub(crate) fn io_read16(port: u16) -> u16 {
    let value: u16;
    // SAFETY: see `outb`; `dx` holds the port, `ax` receives the word.
    unsafe {
        asm!(
            "in ax, dx",
            out("ax") value,
            in("dx") port,
            options(nomem, nostack, preserves_flags)
        )
    };
    value
}

/// Read one 32-bit dword from I/O `port`.
#[inline]
#[allow(dead_code)] // crate-internal port I/O DDI; consumed by the io/block drivers
pub(crate) fn io_read32(port: u16) -> u32 {
    let value: u32;
    // SAFETY: see `outb`; `dx` holds the port, `eax` receives the dword.
    unsafe {
        asm!(
            "in eax, dx",
            out("eax") value,
            in("dx") port,
            options(nomem, nostack, preserves_flags)
        )
    };
    value
}

/// Write one byte to I/O `port`.
#[inline]
#[allow(dead_code)] // crate-internal port I/O DDI; consumed by the io/block drivers
pub(crate) fn io_write8(port: u16, value: u8) {
    outb(port, value);
}

/// Write one 16-bit word to I/O `port`.
#[inline]
#[allow(dead_code)] // crate-internal port I/O DDI; consumed by the io/block drivers
pub(crate) fn io_write16(port: u16, value: u16) {
    // SAFETY: see `outb`; `dx` holds the port, `ax` the word to write.
    unsafe {
        asm!(
            "out dx, ax",
            in("dx") port,
            in("ax") value,
            options(nomem, nostack, preserves_flags)
        )
    }
}

/// Write one 32-bit dword to I/O `port`.
#[inline]
#[allow(dead_code)] // crate-internal port I/O DDI; consumed by the io/block drivers
pub(crate) fn io_write32(port: u16, value: u32) {
    // SAFETY: see `outb`; `dx` holds the port, `eax` the dword to write.
    unsafe {
        asm!(
            "out dx, eax",
            in("dx") port,
            in("eax") value,
            options(nomem, nostack, preserves_flags)
        )
    }
}
