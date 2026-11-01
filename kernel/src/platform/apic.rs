//! xAPIC bring-up for M3: local APIC, IO APIC routing and 8259 masking.
//!
//! Scope is intentionally narrow:
//! * xAPIC (memory-mapped) only - M3 does not enable x2APIC. If firmware left
//!   x2APIC enabled, `detect_local_apic` switches the base MSR back to xAPIC
//!   explicitly instead of silently depending on the firmware state.
//! * The local APIC MMIO base comes from `IA32_APIC_BASE` and is cross-checked
//!   against MADT, never hard-coded.
//! * Only the legacy ISA lines the M3 devices need (IRQ1 keyboard, IRQ4 COM1)
//!   are routed; every other redirection entry stays masked.
//!
//! All MMIO windows are mapped by `platform::init` with device attributes
//! (uncached); this module only performs register access.

use core::ptr::{read_volatile, write_volatile};
use core::sync::atomic::{AtomicU32, Ordering};

use super::acpi::Route;
use super::io::outb;
use crate::arch;

/// `IA32_APIC_BASE` model-specific register.
pub const MSR_APIC_BASE: u32 = 0x1B;
/// `IA32_APIC_BASE` bit 11: global APIC enable.
const APIC_BASE_ENABLE: u64 = 1 << 11;
/// `IA32_APIC_BASE` bit 10: x2APIC mode enable.
const APIC_BASE_X2APIC: u64 = 1 << 10;
/// `IA32_APIC_BASE` bits 12..=35: local APIC MMIO base address.
const APIC_BASE_ADDR_MASK: u64 = 0x0000_000F_FFFF_F000;

/// CPUID.01H:EDX bit 9: local APIC present.
const CPUID_EDX_APIC: u32 = 1 << 9;

/// Local APIC ID register.
pub const REG_ID: u32 = 0x020;
/// Local APIC version register.
pub const REG_VERSION: u32 = 0x030;
/// Task priority register (0 accepts every priority class).
pub const REG_TPR: u32 = 0x080;
/// End-of-interrupt register.
pub const REG_EOI: u32 = 0x0B0;
/// Spurious interrupt vector register.
pub const REG_SVR: u32 = 0x0F0;
/// LVT timer register.
pub const REG_LVT_TIMER: u32 = 0x320;
/// LVT LINT0 register.
pub const REG_LVT_LINT0: u32 = 0x350;
/// LVT LINT1 register.
pub const REG_LVT_LINT1: u32 = 0x360;
/// LVT error register.
pub const REG_LVT_ERROR: u32 = 0x370;
/// Timer initial-count register.
pub const REG_TIMER_INIT: u32 = 0x380;
/// Timer current-count register.
pub const REG_TIMER_CUR: u32 = 0x390;
/// Timer divide-configuration register.
pub const REG_TIMER_DIV: u32 = 0x3E0;

/// "Masked" bit shared by every LVT entry.
pub const LVT_MASK: u32 = 1 << 16;
/// Timer mode bit: periodic when set, one-shot when clear.
pub const TIMER_MODE_PERIODIC: u32 = 1 << 17;
/// Divide-configuration value selecting divide-by-1 (0b1011).
pub const TIMER_DIVIDE_BY_1: u32 = 0b1011;
/// Spurious-vector register bit 8: software APIC enable.
const SVR_ENABLE: u32 = 1 << 8;

/// 8259 master data port (interrupt mask register).
const PIC1_DATA: u16 = 0x21;
/// 8259 slave data port (interrupt mask register).
const PIC2_DATA: u16 = 0xA1;

/// Vector the local APIC raises for a spurious interrupt.
///
/// The stub for this vector must return without an EOI (PROJECT_PROGRESS.md:507);
/// `platform` only owns the vector number, the IDT/routing side lives with the
/// arch/sched integration.
pub const SPURIOUS_VECTOR: u8 = 0xFF;

/// Memory-mapped local APIC.
#[derive(Clone, Copy, Debug)]
pub struct Lapic {
    base: u64,
}

impl Lapic {
    /// Create a handle for a local APIC already mapped at `base`.
    pub const fn new(base: u64) -> Self {
        Lapic { base }
    }

    /// Read a local APIC register.
    pub fn read(&self, reg: u32) -> u32 {
        // SAFETY: `base` is the mapped, permanently valid local APIC window.
        unsafe { read_volatile((self.base + u64::from(reg)) as *const u32) }
    }

    /// Write a local APIC register.
    pub fn write(&self, reg: u32, value: u32) {
        // SAFETY: see `read`; these registers are memory-mapped device state.
        unsafe { write_volatile((self.base + u64::from(reg)) as *mut u32, value) }
    }

    /// Physical local APIC ID of this CPU (xAPIC bits 24..=31).
    pub fn id(&self) -> u8 {
        (self.read(REG_ID) >> 24) as u8
    }

    /// Local APIC version register value.
    pub fn version(&self) -> u32 {
        self.read(REG_VERSION)
    }
}

// ---------------------------------------------------------------------------
// MSI / MSI-X message encoding (M7c prerequisites)
// ---------------------------------------------------------------------------

/// Physical base of the local APIC MMIO page an x86 MSI/MSI-X message targets.
pub const MSI_ADDRESS_BASE: u32 = 0xFEE0_0000;
/// Shift of the destination APIC id inside the MSI message address.
///
/// x86 routes the message to `0xFEE0_0000 | (apic_id << 12)`: one 4 KiB page per
/// destination, which is why the address is an encoded physical address rather
/// than a register offset.
const MSI_DESTINATION_SHIFT: u32 = 12;

/// Low 32 bits of the MSI/MSI-X message address routed to `dest_apic`.
///
/// The high dword is zero for the 8-bit xAPIC ids this kernel owns. Callers must
/// pass a destination whose APIC page exists (an enabled MADT entry): the
/// platform layer refuses to encode an id it has no CPU behind.
pub const fn msi_message_address(dest_apic: u8) -> u32 {
    MSI_ADDRESS_BASE | ((dest_apic as u32) << MSI_DESTINATION_SHIFT)
}

/// MSI/MSI-X message data word for a fixed-delivery interrupt `vector`.
///
/// MSI-X carries the bare vector in the low byte. The legacy MSI capability
/// encodes delivery mode/level/trigger in its own data register and must not
/// reuse this value unchanged.
pub const fn msi_message_data(vector: u8) -> u32 {
    vector as u32
}

/// Configure the local APIC for interrupt reception.
///
/// `spurious_vector` becomes the SPIV vector; vector 0xFF is the x86 convention
/// for a spurious interrupt. The returned value is the spurious vector actually
/// programmed, so callers can log/report it without this module printing.
pub fn enable(lapic: &Lapic, spurious_vector: u8) -> u8 {
    // TPR = 0: accept every priority class.
    lapic.write(REG_TPR, 0);

    // Leave both LINT inputs masked: M3 uses the IO APIC exclusively and does
    // not rely on any ExtINT/NMI delivery path.
    lapic.write(REG_LVT_LINT0, LVT_MASK);
    lapic.write(REG_LVT_LINT1, LVT_MASK);
    lapic.write(REG_LVT_ERROR, LVT_MASK);
    lapic.write(REG_LVT_TIMER, LVT_MASK);

    // Software-enable the APIC and install the spurious vector.
    lapic.write(REG_SVR, (u32::from(spurious_vector) & 0xFF) | SVR_ENABLE);

    // Publish the vector the hardware will report for a spurious interrupt.
    (lapic.read(REG_SVR) & 0xFF) as u8
}

/// Whether the CPU advertises a local APIC (CPUID.01H:EDX bit 9).
pub fn cpuid_reports_apic() -> bool {
    let (_, _, _, edx) = arch::cpuid(1, 0);
    edx & CPUID_EDX_APIC != 0
}

/// Resolve the local APIC MMIO base and make sure the APIC is in xAPIC mode.
///
/// `madt_base` is the base reported by MADT (entry type 4 may legitimately
/// override entry type 0); a mismatch with `IA32_APIC_BASE` is a firmware
/// inconsistency and is reported instead of being papered over.
pub fn detect_local_apic(madt_base: u64) -> Result<u64, &'static str> {
    if !cpuid_reports_apic() {
        return Err("apic-not-present");
    }

    let mut value = arch::rdmsr(MSR_APIC_BASE);

    if value & APIC_BASE_X2APIC != 0 {
        // Firmware handed us x2APIC; drop back to the memory-mapped interface
        // that M3 implements.
        value &= !APIC_BASE_X2APIC;
        arch::wrmsr(MSR_APIC_BASE, value);
        value = arch::rdmsr(MSR_APIC_BASE);
        if value & APIC_BASE_X2APIC != 0 {
            return Err("apic-x2apic-stuck");
        }
    }

    if value & APIC_BASE_ENABLE == 0 {
        arch::wrmsr(MSR_APIC_BASE, value | APIC_BASE_ENABLE);
        value = arch::rdmsr(MSR_APIC_BASE);
        if value & APIC_BASE_ENABLE == 0 {
            return Err("apic-cannot-enable");
        }
    }

    let base = value & APIC_BASE_ADDR_MASK;
    if base != madt_base {
        return Err("apic-base-mismatch");
    }
    if base < 0x000F_0000 {
        return Err("apic-base-implausible");
    }
    Ok(base)
}

/// Signal end-of-interrupt for the given local APIC.
pub fn eoi(lapic: &Lapic) {
    lapic.write(REG_EOI, 0);
}

/// Interrupt command register, low half (destination and command bits).
pub const REG_ICR: u32 = 0x300;
/// Interrupt command register, high half (destination APIC id in 24..=31).
pub const REG_ICR_HIGH: u32 = 0x310;
/// ICR bit 12: delivery status (set while a previous IPI is still pending).
pub const ICR_DELIVERY_PENDING: u32 = 1 << 12;
/// ICR bit 14: level assertion, mandatory for INIT delivery.
pub const ICR_LEVEL_ASSERT: u32 = 1 << 14;
/// ICR bits 8..=10: INIT delivery mode.
pub const ICR_DELIVERY_INIT: u32 = 0b101 << 8;
/// ICR bits 8..=10: startup (SIPI) delivery mode.
pub const ICR_DELIVERY_STARTUP: u32 = 0b110 << 8;
/// Upper bound on the "delivery status clear" wait; an APIC that never clears
/// this bit is broken, and spinning forever would hide that.
const ICR_WAIT_BOUND: u32 = 1_000_000;

/// Delivery mode of an inter-processor interrupt.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IcrDelivery {
    /// INIT: resets the target CPU into real mode and waits for a SIPI.
    Init,
    /// Startup: hands the target CPU a real-mode entry page via `vector`.
    Startup,
    /// Fixed: normal IDT-vector delivery, edge triggered. `vector` is a real
    /// interrupt vector (an IDT gate must exist), unlike the SIPI page number.
    Fixed,
}

/// Encode the low half of an ICR write (pure: host-testable).
///
/// `dest` is the physical xAPIC id (0..=255). For `Startup` the `vector`
/// argument is a **SIPI page number** (entry physical address = `vector << 12`),
/// not an IDT vector; INIT ignores it and carries the level-assert bit instead,
/// which the architecture requires for INIT delivery. For `Fixed` the `vector`
/// is a real IDT vector: delivery mode 0b000, edge triggered and no
/// level-assert bit.
pub const fn icr_command(delivery: IcrDelivery, dest: u8, vector: u8) -> u32 {
    let destination = (dest as u32) << 24;
    match delivery {
        IcrDelivery::Init => destination | ICR_DELIVERY_INIT | ICR_LEVEL_ASSERT,
        IcrDelivery::Startup => destination | ICR_DELIVERY_STARTUP | vector as u32,
        // Fixed delivery mode is 0b000, so only the vector byte is added.
        IcrDelivery::Fixed => destination | vector as u32,
    }
}

/// Wait until the local APIC reports no delivery in flight.
fn wait_icr_idle(lapic: &Lapic) -> Result<(), &'static str> {
    let mut spins = 0;
    while spins < ICR_WAIT_BOUND {
        if lapic.read(REG_ICR) & ICR_DELIVERY_PENDING == 0 {
            return Ok(());
        }
        spins += 1;
    }
    Err("icr-delivery-stuck")
}

/// Send an INIT IPI to `dest` and wait for the local APIC to accept it.
///
/// The caller still owns the follow-up delay and the SIPI retries: the
/// architecture requires INIT, a wait, then (at most) two STARTUP IPIs.
pub fn send_init(lapic: &Lapic, dest: u8) -> Result<(), &'static str> {
    wait_icr_idle(lapic)?;
    lapic.write(REG_ICR_HIGH, u32::from(dest) << 24);
    lapic.write(REG_ICR, icr_command(IcrDelivery::Init, dest, 0));
    wait_icr_idle(lapic)
}

/// Whether `page` is a legal SIPI entry page.
///
/// The SIPI "vector" byte is **not** an IDT vector: the hardware shifts it left
/// by 12 and starts the core there, so the only constraint is physical memory.
/// Page 0 (the real-mode IVT/BDA area) is reserved by the physical allocator and
/// therefore refused here; every other page number fits below 1 MiB simply
/// because the field is 8 bits wide (`0xFF << 12` = 0xF_F000).
pub const fn sipi_page_is_valid(page: u8) -> bool {
    page != 0
}

/// Send a STARTUP IPI handing `dest` the real-mode entry page `page`.
///
/// `page` is the SIPI page number (physical entry = `page << 12`), not an IDT
/// vector, so there is no `>= 0x20` requirement. INIT and normal IDT-vector
/// checks are intentionally unaffected by this rule.
pub fn send_startup(lapic: &Lapic, dest: u8, page: u8) -> Result<(), &'static str> {
    if !sipi_page_is_valid(page) {
        return Err("invalid-sipi-vector");
    }
    wait_icr_idle(lapic)?;
    lapic.write(REG_ICR_HIGH, u32::from(dest) << 24);
    lapic.write(REG_ICR, icr_command(IcrDelivery::Startup, dest, page));
    wait_icr_idle(lapic)
}

/// Send a fixed IPI delivering `vector` to `dest`.
///
/// `vector` is a real IDT vector (an IDT gate must exist for it); this is not the
/// SIPI page-number rule. Reuses the same bounded delivery-status wait as INIT
/// and SIPI so a wedged APIC surfaces as `Err("icr-delivery-stuck")` instead of
/// spinning forever. The caller owns any "skip self" / affinity policy.
pub fn send_fixed_ipi(lapic: &Lapic, dest: u8, vector: u8) -> Result<(), &'static str> {
    wait_icr_idle(lapic)?;
    lapic.write(REG_ICR_HIGH, u32::from(dest) << 24);
    lapic.write(REG_ICR, icr_command(IcrDelivery::Fixed, dest, vector));
    wait_icr_idle(lapic)
}

/// Number of reschedule IPIs this CPU actually wrote into the ICR.
///
/// Diagnostics/counters only: a wake that decided to IPI still counts only once
/// the ICR write was accepted (see [`send_reschedule_ipi`]).
static RESCHEDULE_IPIS_SENT: AtomicU32 = AtomicU32::new(0);

/// Reschedule IPIs this CPU sent since boot.
pub fn reschedule_ipi_sent() -> u32 {
    RESCHEDULE_IPIS_SENT.load(Ordering::Relaxed)
}

/// Send the M6b2 reschedule IPI to the processor with local APIC id `target`.
///
/// The caller resolves the logical CPU index to an APIC id and is responsible
/// for skipping its own CPU; unlike the INIT/SIPI path, the boot processor is a
/// legal target. The counter is bumped only after the ICR write completed.
pub fn send_reschedule_ipi(lapic: &Lapic, target: u8) -> Result<(), &'static str> {
    send_fixed_ipi(lapic, target, super::RESCHEDULE_VECTOR)?;
    RESCHEDULE_IPIS_SENT.fetch_add(1, Ordering::Relaxed);
    Ok(())
}

/// Mask every 8259 line.
///
/// The PICs are never unmasked again in M3; the IO APIC owns the legacy IRQs
/// from here on. Masking is explicit because firmware may leave the PICs
/// delivering ExtINT/IRQ0 into the CPU.
pub fn mask_legacy_pics() {
    // OCW1 masks all eight lines on each chip.
    outb(PIC1_DATA, 0xFF);
    outb(PIC2_DATA, 0xFF);
    // Real 8259s need settling time after a mask write.
    super::io::io_delay();
}

/// Single IO APIC instance.
#[derive(Clone, Copy, Debug)]
pub struct IoApic {
    base: u64,
}

/// Registers of the IO APIC are reached through an index/data pair.
const IOAPIC_INDEX: u32 = 0x00;
const IOAPIC_DATA: u32 = 0x10;
/// IO APIC identification register.
const IOAPIC_REG_ID: u32 = 0x00;
/// IO APIC version register.
const IOAPIC_REG_VERSION: u32 = 0x01;
/// First redirection-table register (each entry spans two 32-bit registers).
const IOAPIC_REG_REDIRECT: u32 = 0x10;

impl IoApic {
    /// Create a handle for an IO APIC already mapped at `base`.
    pub const fn new(base: u64) -> Self {
        IoApic { base }
    }

    fn read(&self, reg: u32) -> u32 {
        // SAFETY: the 4 KiB IO APIC window is mapped permanently by platform::init.
        unsafe {
            write_volatile((self.base + u64::from(IOAPIC_INDEX)) as *mut u32, reg);
            read_volatile((self.base + u64::from(IOAPIC_DATA)) as *const u32)
        }
    }

    fn write(&self, reg: u32, value: u32) {
        // SAFETY: see `read`.
        unsafe {
            write_volatile((self.base + u64::from(IOAPIC_INDEX)) as *mut u32, reg);
            write_volatile((self.base + u64::from(IOAPIC_DATA)) as *mut u32, value);
        }
    }

    /// IO APIC identification register value.
    pub fn id(&self) -> u8 {
        (self.read(IOAPIC_REG_ID) >> 24) as u8
    }

    /// Number of redirection entries minus one.
    pub fn max_redirection(&self) -> u32 {
        (self.read(IOAPIC_REG_VERSION) >> 16) & 0xFF
    }
}

/// Mask every IO APIC redirection entry.
pub fn mask_all_redirections(io: &IoApic) -> Result<(), &'static str> {
    let max = io.max_redirection();
    // A single-entry IO APIC reports 0; anything beyond 0x7F is not a real
    // device and would mean the register read is bogus.
    if max > 0x7F {
        return Err("ioapic-implausible-entry-count");
    }
    let mut index = 0;
    while index <= max {
        let reg = IOAPIC_REG_REDIRECT + 2 * index;
        let low = io.read(reg);
        io.write(reg, low | LVT_MASK);
        index += 1;
    }
    Ok(())
}

/// Route one GSI to a local-APIC vector on `dest` and unmask it.
///
/// `route` carries the MADT interrupt-source-override translation (GSI, polarity
/// and trigger mode). Delivery is fixed, physical-destination, edge or level as
/// the override says.
pub fn route_gsi(
    io: &IoApic,
    gsi_base: u32,
    route: Route,
    vector: u8,
    dest: u8,
) -> Result<(), &'static str> {
    if vector < 0x20 {
        return Err("ioapic-vector-reserved");
    }
    let index = route
        .gsi
        .checked_sub(gsi_base)
        .ok_or("ioapic-gsi-below-base")?;
    if index > io.max_redirection() {
        return Err("ioapic-gsi-out-of-range");
    }

    let mut low = u32::from(vector);
    if route.active_low {
        low |= 1 << 13;
    }
    if route.level_triggered {
        low |= 1 << 15;
    }
    let high = u32::from(dest) << 24;

    let reg = IOAPIC_REG_REDIRECT + 2 * index;
    // Write the destination half first: the entry stays masked until the low
    // half is written, so no interrupt can arrive with a half-written entry.
    io.write(reg + 1, high);
    io.write(reg, low);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn init_ipi_asserts_level_and_encodes_the_destination() {
        let low = icr_command(IcrDelivery::Init, 0x03, 0);
        assert_eq!(low & 0xFF, 0, "INIT carries no vector");
        assert_eq!(low & 0b111 << 8, ICR_DELIVERY_INIT);
        assert_ne!(low & ICR_LEVEL_ASSERT, 0, "INIT needs level assert");
        assert_eq!(low >> 24, 0x03);
    }

    #[test]
    fn startup_ipi_encodes_the_entry_page_and_edge_semantics() {
        // Page 1 is the lowest page the dynamic low-page reservation can hand
        // out; it must encode fine (the SIPI byte is a page number, not an IDT
        // vector, so the 0x20 threshold does not apply).
        let low = icr_command(IcrDelivery::Startup, 0x07, 0x01);
        assert_eq!(low & 0xFF, 0x01, "SIPI page lives in bits 0..=7");
        assert_eq!(low & 0b111 << 8, ICR_DELIVERY_STARTUP);
        assert_eq!(low & ICR_LEVEL_ASSERT, 0, "SIPI is edge triggered");
        assert_eq!(low >> 24, 0x07);
    }

    #[test]
    fn sipi_pages_one_through_255_are_legal_and_page_zero_is_not() {
        assert!(!sipi_page_is_valid(0), "page 0 is the real-mode IVT/BDA");
        for page in 1..=u8::MAX {
            assert!(
                sipi_page_is_valid(page),
                "SIPI page {page} must be accepted: u8 already keeps it below 1 MiB"
            );
        }
    }

    #[test]
    fn page_zero_is_refused_before_the_local_apic_is_touched() {
        // The check runs before `wait_icr_idle`, so this must not touch the
        // fabricated window at address 0.
        let lapic = Lapic::new(0);
        assert_eq!(
            send_startup(&lapic, 1, 0),
            Err("invalid-sipi-vector"),
            "page 0 stays reserved"
        );
    }

    #[test]
    fn destinations_above_255_do_not_bleed_into_the_command_bits() {
        for dest in [0u8, 1, 0x7F, 0xFF] {
            let low = icr_command(IcrDelivery::Startup, dest, 0x20);
            assert_eq!(low >> 24, u32::from(dest));
            assert_eq!(low & 0x00FF_FFFF & !(0b111 << 8) & !0xFF, 0);
        }
    }

    #[test]
    fn fixed_ipi_encodes_an_idt_vector_with_edge_semantics() {
        let vector = crate::platform::RESCHEDULE_VECTOR;
        let low = icr_command(IcrDelivery::Fixed, 0x05, vector);
        assert_eq!(low & 0xFF, u32::from(vector), "vector lives in bits 0..=7");
        assert_eq!(low & 0b111 << 8, 0, "fixed delivery is mode 0b000");
        assert_eq!(low & ICR_LEVEL_ASSERT, 0, "fixed IPIs are edge triggered");
        assert_eq!(low >> 24, 0x05, "destination lives in bits 24..=31");
    }

    #[test]
    fn reschedule_ipi_encodes_the_target_and_counts_only_completed_writes() {
        // A zeroed page stands in for the local APIC window: the delivery-status
        // bit reads back clear, so the bounded idle wait succeeds immediately and
        // the ICR writes land in host memory this test can inspect.
        #[repr(C, align(4096))]
        struct FakeLapic([u8; 4096]);
        let mut fake = FakeLapic([0u8; 4096]);
        let lapic = Lapic::new(&mut fake as *mut FakeLapic as u64);

        let before = reschedule_ipi_sent();
        send_reschedule_ipi(&lapic, 0x07).expect("fake window accepts the write");
        assert_eq!(reschedule_ipi_sent(), before + 1, "one send, one count");
        assert_eq!(lapic.read(REG_ICR_HIGH), 0x07 << 24, "target in ICR high");
        assert_eq!(
            lapic.read(REG_ICR),
            icr_command(IcrDelivery::Fixed, 0x07, crate::platform::RESCHEDULE_VECTOR),
            "ICR low half carries the fixed-delivery command"
        );
    }

    #[test]
    fn msi_messages_encode_the_destination_apic_page_and_bare_vector() {
        // Destination page encoding: `0xFEE0_0000 | apic_id << 12`, high dword 0.
        assert_eq!(msi_message_address(0), 0xFEE0_0000);
        assert_eq!(msi_message_address(1), 0xFEE0_1000);
        assert_eq!(msi_message_address(0x0F), 0xFEE0_F000);
        assert_eq!(msi_message_address(0xFF), 0xFEEF_F000);
        // The address never leaves the 4 KiB-granular APIC window.
        let mut id = 0u8;
        loop {
            let addr = msi_message_address(id);
            assert_eq!(addr & 0xFFF, 0, "destination sits on a page boundary");
            assert_eq!(
                addr & !0x000F_F000,
                MSI_ADDRESS_BASE & !0x000F_F000,
                "only the destination field changes"
            );
            if id == 0xFF {
                break;
            }
            id += 1;
        }
        // MSI-X data is the bare vector; MSI-X has no trigger/level bits.
        assert_eq!(msi_message_data(0), 0);
        assert_eq!(msi_message_data(0x20), 0x20);
        assert_eq!(msi_message_data(0xFF), 0xFF);
    }
}
