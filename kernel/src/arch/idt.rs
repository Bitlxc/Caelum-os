//! Interrupt Descriptor Table (M2 exceptions + M3 IRQ gates).
//!
//! Gates are present 64-bit interrupt gates, DPL 0, CS = kernel code.
//! Exception coverage (agents.md §22 M2): `#UD`(6), `#GP`(13), `#DF`(8, IST1),
//! `#PF`(14), plus `#DE`(0), NMI(2, IST2), `#SS`(12) and `#AC`(17) so an
//! unexpected condition yields a readable dump instead of a triple fault.
//! Any other exception vector arrives as `#GP` (error code identifies the slot).
//!
//! M3 adds the returnable handlers (agents.md §22 M3): LAPIC timer(0x20),
//! keyboard(0x21), COM1(0x24), software yield(0x40) and spurious(0xFF). They
//! share the M2 stub shape and are dispatched through `crate::irq_dispatch`.
//! M7c adds the legacy virtio-net MSI-X vector (0x42); the driver installs the
//! MSI-X table, so the gate only has to exist and return through the same path.

use core::arch::asm;
use core::ptr::addr_of;

use super::gdt::KERNEL_CS;
use super::traps::{
    VECTOR_COM1, VECTOR_KEYBOARD, VECTOR_NET, VECTOR_RESCHED, VECTOR_SPURIOUS, VECTOR_TIMER,
    VECTOR_YIELD,
};
use super::tss::{IST_DF, IST_NMI};

/// Present, 64-bit interrupt gate (type 0xE), DPL 0.
const GATE_INTERRUPT: u8 = 0x8E;

#[derive(Clone, Copy)]
#[repr(C, align(16))]
pub struct IdtEntry {
    words: [u64; 2],
}

impl IdtEntry {
    pub const fn null() -> Self {
        IdtEntry { words: [0; 2] }
    }

    /// `ist` is the 1-based IST index (0 = use the current stack).
    pub const fn interrupt_gate(handler: u64, ist: u8) -> Self {
        let lo = (handler & 0xFFFF)
            | ((KERNEL_CS as u64) << 16)
            | (((ist as u64) & 0x7) << 32)
            | ((GATE_INTERRUPT as u64) << 40)
            | ((handler >> 16) & 0xFFFF) << 48;
        let hi = handler >> 32;
        IdtEntry {
            words: [lo, hi as u64],
        }
    }
}

pub const IDT_ENTRIES: usize = 256;

pub static mut IDT: [IdtEntry; IDT_ENTRIES] = [IdtEntry::null(); IDT_ENTRIES];

#[repr(C, packed)]
struct Idtr {
    limit: u16,
    base: u64,
}

unsafe extern "C" {
    fn __isr_0();
    fn __isr_2();
    fn __isr_6();
    fn __isr_8();
    fn __isr_12();
    fn __isr_13();
    fn __isr_14();
    fn __isr_17();
    fn __isr_32();
    fn __isr_33();
    fn __isr_36();
    fn __isr_64();
    fn __isr_65();
    fn __isr_66();
    fn __isr_255();
}

fn set(vector: usize, handler: usize, ist: u8) {
    unsafe {
        let idt = core::ptr::addr_of_mut!(IDT);
        (*idt)[vector] = IdtEntry::interrupt_gate(handler as u64, ist);
    }
}

/// Fill the shared IDT with the exception and IRQ gates.
///
/// The table is identical for every CPU (the exception entry points and the
/// timer/keyboard/serial vectors are the same), so M6b1 builds it once on the
/// boot processor and each application processor only re-loads it with
/// [`load`] — `lidt` is architecturally per-CPU state even though the table
/// contents are shared.
pub fn build() {
    unsafe {
        let idt = core::ptr::addr_of_mut!(IDT);
        for e in (*idt).iter_mut() {
            *e = IdtEntry::null();
        }
    }
    set(0, __isr_0 as *const () as usize, 0); // #DE divide error
    set(2, __isr_2 as *const () as usize, (IST_NMI + 1) as u8); // NMI -> IST2
    set(6, __isr_6 as *const () as usize, 0); // #UD invalid opcode
    set(8, __isr_8 as *const () as usize, (IST_DF + 1) as u8); // #DF -> IST1
    set(12, __isr_12 as *const () as usize, 0); // #SS stack segment
    set(13, __isr_13 as *const () as usize, 0); // #GP general protection
    set(14, __isr_14 as *const () as usize, 0); // #PF page fault
    set(17, __isr_17 as *const () as usize, 0); // #AC alignment check
    set(VECTOR_TIMER as usize, __isr_32 as *const () as usize, 0); // LAPIC timer, returnable
    set(VECTOR_KEYBOARD as usize, __isr_33 as *const () as usize, 0); // keyboard, returnable
    set(VECTOR_COM1 as usize, __isr_36 as *const () as usize, 0); // COM1, returnable
    set(VECTOR_YIELD as usize, __isr_64 as *const () as usize, 0); // scheduler yield
    set(VECTOR_RESCHED as usize, __isr_65 as *const () as usize, 0); // reschedule IPI
    set(VECTOR_NET as usize, __isr_66 as *const () as usize, 0); // virtio-net MSI-X (M7c)
    set(VECTOR_SPURIOUS as usize, __isr_255 as *const () as usize, 0); // spurious interrupt
}

/// Load the (already built) IDT into this CPU's `IDTR`.
pub fn load() {
    unsafe {
        let idtr = Idtr {
            limit: (IDT_ENTRIES * 16 - 1) as u16,
            base: addr_of!(IDT) as u64,
        };
        asm!("lidt [{}]", in(reg) &idtr, options(readonly, nostack, preserves_flags));
    }
}

/// Boot-processor form: build the table and load it.
pub fn init() {
    build();
    load();
}
