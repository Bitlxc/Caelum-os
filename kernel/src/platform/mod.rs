//! M3 platform layer: ACPI discovery, xAPIC bring-up and the LAPIC timer.
//!
//! Responsibilities split (see the architecture baseline, 鎼?):
//! * `acpi` 閳?pure table parsing/validation (host-tested, no `unsafe`).
//! * `apic` 閳?local APIC / IO APIC / 8259 register access.
//! * `pit`  閳?PIT channel 0 as the calibration time reference.
//! * `timer`閳?LAPIC timer calibration and periodic programming.
//! * this module 閳?the boot-time orchestration: take the RSDP physical address
//!   from BootInfo, map the ACPI tables read-only and the APIC windows uncached
//!   into the permanent platform window, route the two legacy lines M3 owns and
//!   publish the `eoi` primitive used by the interrupt path.
//!
//! Boundaries this module deliberately keeps:
//! * no printing and no allocation 閳?every failure is a `&'static str` the
//!   caller reports;
//! * no IDT/ISR work 閳?the vector numbers are exported, the root input handler
//!   calls `time::on_timer`/`platform::eoi` in the agreed order;
//! * no firmware fallback: a missing/illegal ACPI description is an error, not
//!   a q35-specific guess.
//!
//! Mappings are permanent (the M2 VM has no unmap), so each range is mapped
//! exactly once at its final virtual address. The window bump pointer only moves
//! during the single-CPU `init` path.

mod acpi;
mod apic;
pub(crate) mod calc;
mod io;
mod pci;
mod pit;
mod timer;

use core::sync::atomic::{AtomicU32, Ordering};

use crate::arch;
use crate::boot;
use crate::mm::vm;

#[allow(unused_imports)] // Frozen crate-internal port I/O DDI for the io/block drivers.
pub(crate) use io::{io_delay, io_read8, io_read16, io_read32, io_write8, io_write16, io_write32};
pub use pci::{
    CAP_ID_MSI, CAP_ID_MSIX, CapabilityWalk, MSIX_ENTRY_BYTES, MSIX_MAX_VECTORS, MSIX_VECTOR_MASK,
    MsixCapability, PciFunction, bar_mmio_base, capabilities, configure_msix_vector,
    decode_msix_location, find_pci, init_pci, is_pci_ready, map_bar_mmio, map_msix_table,
    msix_capability, msix_table_phys, pci_ecam_pages, pci_function_count, read_config16,
    read_config32, set_msix_enabled, set_msix_function_mask, write_config16, write_config32,
};

/// LAPIC timer vector (PROJECT_PROGRESS M3 IRQ table).
pub const TIMER_VECTOR: u8 = 0x20;
/// Keyboard (ISA IRQ1) vector.
pub const KEYBOARD_VECTOR: u8 = 0x21;
/// COM1 receive (ISA IRQ4) vector.
pub const SERIAL_VECTOR: u8 = 0x24;
/// IDT vector reserved for the M6b2 cross-CPU reschedule IPI.
///
/// Mirrors [`arch::VECTOR_RESCHED`] (the `0x41` the arch layer installs an IDT
/// gate and the `sched::on_reschedule` handler for), so the platform sender and
/// the IDT wiring cannot drift; the `u8` narrowing is what the ICR vector byte
/// carries. `0x40` is the scheduler's self-yield marker and `0x60` the syscall
/// marker, so this is the next free IRQ-range slot.
pub const RESCHEDULE_VECTOR: u8 = arch::VECTOR_RESCHED as u8;

/// Base of the permanent device/ACPI mapping window (bump-allocated, page-sized).
///
/// ACPI tables live in firmware-reserved memory and the APIC registers are MMIO,
/// so neither is reachable through the M2 direct map (conventional RAM only).
/// They also cannot get a fresh top-level region: the takeover page tables only
/// wire the kernel-image high-half PDPT (the 1 GiB from `0xFFFF_FFFF_8000_0000`),
/// so the platform window stays inside it. It starts above the boot stack
/// (`...8100_0000`) and the scheduler stacks (`...8110_0000`/`...8120_0000`) and
/// is capped at [`WINDOW_LIMIT`] so it cannot grow into anything else.
pub const WINDOW_BASE: u64 = 0xFFFF_FFFF_8200_0000;
/// Upper bound of the platform window; the bump allocator refuses to grow past
/// it so a runaway ACPI walk cannot silently collide with other mappings.
const WINDOW_LIMIT: u64 = 16 * 1024 * 1024;

/// Base of the PCI ECAM mapping window.
///
/// Sits above the boot-module window (`0xFFFF_FFFF_8300_0000` + 16 MiB) so the
/// three permanent bump windows cannot meet; like the platform window it stays
/// inside the kernel-image 1 GiB PDPT the takeover page tables wire.
pub(crate) const PCI_WINDOW_BASE: u64 = 0xFFFF_FFFF_8400_0000;
/// Upper bound of the PCI window: at most 16 MiB of ECAM pages.
pub(crate) const PCI_WINDOW_LIMIT: u64 = 16 * 1024 * 1024;

/// Base of the M6c GOP framebuffer window.
///
/// Sits directly above the PCI ECAM window (`0xFFFF_FFFF_8400_0000` + 16 MiB)
/// so the permanent windows stay disjoint, and — like the others — stays
/// inside the kernel-image 1 GiB PDPT that the takeover page tables wire.
/// Only `crate::display` maps here (M6c); the window is sized for the largest
/// plausible 32 bpp GOP mode rather than for a specific QEMU resolution.
pub(crate) const FB_WINDOW_BASE: u64 = 0xFFFF_FFFF_8500_0000;
/// Upper bound of the framebuffer window: 64 MiB covers e.g. 4096x2160x32.
pub(crate) const FB_WINDOW_LIMIT: u64 = 64 * 1024 * 1024;

/// Base of the M7 device-MMIO window (MSI-X tables and network BAR slices).
///
/// Sits above the framebuffer window base so the permanent windows stay
/// disjoint, and — like the others — stays inside the kernel-image 1 GiB PDPT
/// the takeover page tables wire. Only [`map_net_mmio`] hands out pages here.
pub(crate) const NET_WINDOW_BASE: u64 = 0xFFFF_FFFF_8600_0000;
/// Upper bound on the device-MMIO window: 16 MiB is far more than the 32 KiB an
/// MSI-X table can occupy plus the BAR slices a driver actually maps.
const NET_WINDOW_LIMIT: u64 = 16 * 1024 * 1024;

/// Bump pointer inside the device-MMIO window; advanced only by [`map_net_mmio`].
static mut NET_WINDOW_NEXT: u64 = NET_WINDOW_BASE;

/// Page size used for platform mappings.
const PAGE: u64 = 4096;

const PTE_PRESENT: u64 = 1 << 0;
const PTE_WRITE: u64 = 1 << 1;
const PTE_PWT: u64 = 1 << 3;
const PTE_PCD: u64 = 1 << 4;
const PTE_NX: u64 = 1 << 63;

/// ACPI tables: readable, cacheable, never executable.
const TABLE_FLAGS: u64 = PTE_PRESENT | PTE_NX;
/// Device MMIO: uncached (PWT + PCD) and never executable. M2 has no PAT
/// support, so PWT|PCD is the strong-uncached encoding available.
const DEVICE_FLAGS: u64 = PTE_PRESENT | PTE_WRITE | PTE_PWT | PTE_PCD | PTE_NX;

/// Hardware state discovered by [`init`].
struct State {
    lapic: apic::Lapic,
    io_apic: apic::IoApic,
    lapic_id: u8,
    io_apic_id: u8,
    spurious_vector: u8,
    /// Enabled processors reported by MADT, in table order (the boot processor
    /// is not necessary the first entry).
    cpus: [acpi::CpuEntry; acpi::MAX_CPUS],
    cpu_count: usize,
}

/// Published once, after every fallible step of `init` succeeded.
static mut STATE: Option<State> = None;

/// Bump pointer inside the platform window; only advanced by `init`.
static mut WINDOW_NEXT: u64 = WINDOW_BASE;

/// Spurious interrupts observed by the ISR path (diagnostics only).
static SPURIOUS_COUNT: AtomicU32 = AtomicU32::new(0);

/// Bring up the M3 platform layer.
///
/// Order: RSDP 閳?RSDT/XSDT 閳?MADT, then local APIC, 8259 masking, IO APIC and
/// the ISA line routing. Interrupts are forced off for the duration; the
/// previous state is restored before returning so the caller controls when the
/// CPU starts accepting interrupts.
pub fn init() -> Result<(), &'static str> {
    let flags = arch::disable_interrupts();
    let result = init_locked();
    arch::restore_interrupts(flags);
    result
}

/// Signal end-of-interrupt on the local APIC.
///
/// Called by the root interrupt handler after the device-specific work. The
/// spurious-interrupt stub must *not* call this (PROJECT_PROGRESS.md:507).
pub fn eoi() {
    if let Some(state) = platform_state() {
        apic::eoi(&state.lapic);
    }
}

/// Start the periodic LAPIC timer and return the rate it actually delivers.
///
/// Must be called with interrupts disabled (PIT-based calibration busy-waits);
/// `time::init` is the intended caller.
pub fn start_periodic_timer(target_hz: u32) -> Result<u32, &'static str> {
    let state = platform_state().ok_or("platform-not-initialised")?;
    timer::calibrate(&state.lapic, TIMER_VECTOR)?;
    timer::start_periodic(&state.lapic, TIMER_VECTOR, target_hz)
}

/// Start the periodic LAPIC timer on the CPU executing this call.
///
/// APs call this during per-CPU bring-up. It reuses the frequency the boot
/// processor measured (`timer::calibrated_hz`): no PIT recalibration, and no
/// change to the `time` subsystem's global tick counters. The caller must have
/// enabled this CPU's local APIC and installed the [`TIMER_VECTOR`] gate first.
/// Returns the rate the hardware will actually deliver.
pub fn start_local_timer(target_hz: u32) -> Result<u32, &'static str> {
    let state = platform_state().ok_or("platform-not-initialised")?;
    timer::start_local(&state.lapic, TIMER_VECTOR, target_hz)
}

/// LAPIC timer frequency measured during the last calibration (0 = unknown).
pub fn timer_hz() -> u32 {
    timer::calibrated_hz()
}

/// Local APIC id of the boot processor, once `init` has run.
pub fn lapic_id() -> Option<u8> {
    platform_state().map(|state| state.lapic_id)
}

/// Enabled processors MADT reported, once `init` has run.
///
/// The boot processor is included: `bsp_apic_id` tells which entry it is. The
/// slice is empty before `init`, so SMP bring-up can tell "single CPU machine"
/// from "platform not initialised" by `cpu_count()` returning `Some(1)`.
pub fn cpus() -> &'static [acpi::CpuEntry] {
    match platform_state() {
        Some(state) => &state.cpus[..state.cpu_count],
        None => &[],
    }
}

/// Number of enabled processors, once `init` has run.
pub fn cpu_count() -> Option<usize> {
    platform_state().map(|state| state.cpu_count)
}

/// Local APIC id of the boot processor, once `init` has run.
///
/// Same value as `lapic_id`; the separate name marks the SMP role explicitly.
pub fn bsp_apic_id() -> Option<u8> {
    platform_state().map(|state| state.lapic_id)
}

/// Send an INIT IPI to another processor and wait for the local APIC to take it.
///
/// `apic_id` must be one of the enabled MADT entries and must not be the boot
/// processor: INIT to self would reset the CPU running this code. The caller
/// owns the follow-up delay and the SIPI retries.
pub fn send_init_ipi(apic_id: u8) -> Result<(), &'static str> {
    let state = platform_state().ok_or("platform-not-initialised")?;
    check_ap_target(state, apic_id)?;
    apic::send_init(&state.lapic, apic_id)
}

/// Send a STARTUP IPI handing `apic_id` the real-mode entry page `page`.
///
/// `page` is a SIPI page number (physical entry = `page << 12`), not an IDT
/// vector; see `apic::sipi_page_is_valid` for the legal range.
pub fn send_startup_ipi(apic_id: u8, page: u8) -> Result<(), &'static str> {
    let state = platform_state().ok_or("platform-not-initialised")?;
    check_ap_target(state, apic_id)?;
    apic::send_startup(&state.lapic, apic_id, page)
}

/// Software-enable the local APIC of the CPU executing this call.
///
/// Built for application processors: it reuses the local APIC window the boot
/// processor mapped (the xAPIC MMIO page is per CPU at the same physical
/// address, so the same virtual mapping reaches whichever CPU runs this), sets
/// TPR to 0 and puts the spurious vector into SVR. It deliberately does **not**
/// start a timer or route any LINT line: M6b1 APs only need to accept IPIs, and
/// timer ownership stays with the boot processor.
pub fn enable_local_apic() -> Result<(), &'static str> {
    let state = platform_state().ok_or("platform-not-initialised")?;
    let programmed = apic::enable(&state.lapic, state.spurious_vector);
    if programmed != state.spurious_vector {
        return Err("apic-spurious-vector-mismatch");
    }
    Ok(())
}

/// Reject IPI targets that are not enabled application processors.
fn check_ap_target(state: &State, apic_id: u8) -> Result<(), &'static str> {
    if apic_id == state.lapic_id {
        return Err("ipi-target-is-boot-processor");
    }
    if !state.cpus[..state.cpu_count]
        .iter()
        .any(|cpu| cpu.enabled && cpu.apic_id == apic_id)
    {
        return Err("ipi-target-not-an-enabled-cpu");
    }
    Ok(())
}

/// Resolve a logical CPU index (index into [`cpus`]) to a local APIC id.
///
/// Unlike [`check_ap_target`], the boot processor is a **legal** target: a wake
/// may need to kick whichever CPU owns a runnable process, and that can be the
/// BSP. Skipping the CPU that is running the caller is the caller's job. MADT
/// entries flagged disabled are refused because no CPU exists behind them.
fn reschedule_target(cpus: &[acpi::CpuEntry], cpu: usize) -> Result<u8, &'static str> {
    let entry = cpus.get(cpu).ok_or("ipi-target-not-an-enabled-cpu")?;
    if !entry.enabled {
        return Err("ipi-target-not-an-enabled-cpu");
    }
    Ok(entry.apic_id)
}

/// Send the M6b2 reschedule IPI to the processor at logical index `cpu`.
///
/// `cpu` indexes [`cpus`] (MADT order, boot processor included). The caller must
/// not target the CPU it is running on; the vector is [`RESCHEDULE_VECTOR`].
pub fn send_reschedule_ipi(cpu: usize) -> Result<(), &'static str> {
    let state = platform_state().ok_or("platform-not-initialised")?;
    let target = reschedule_target(&state.cpus[..state.cpu_count], cpu)?;
    apic::send_reschedule_ipi(&state.lapic, target)
}

/// Reschedule IPIs this CPU has actually issued since boot.
pub fn reschedule_ipi_sent() -> u32 {
    apic::reschedule_ipi_sent()
}

/// Hardware id of the IO APIC M3 routed, once `init` has run.
pub fn io_apic_id() -> Option<u8> {
    platform_state().map(|state| state.io_apic_id)
}

/// Highest redirection-entry index of the routed IO APIC (entries = index + 1).
///
/// Exposed for diagnostics only: the M3 routing itself is fixed (IRQ1/IRQ4).
pub fn io_apic_entries() -> Option<u32> {
    platform_state().map(|state| state.io_apic.max_redirection() + 1)
}

/// Vector the local APIC reports for a spurious interrupt.
pub fn spurious_vector() -> u8 {
    match platform_state() {
        Some(state) => state.spurious_vector,
        None => apic::SPURIOUS_VECTOR,
    }
}

/// Record one spurious interrupt (called from the 0xFF stub).
pub fn note_spurious() {
    SPURIOUS_COUNT.fetch_add(1, Ordering::Relaxed);
}

/// Number of spurious interrupts observed so far.
pub fn spurious_count() -> u32 {
    SPURIOUS_COUNT.load(Ordering::Relaxed)
}

fn platform_state() -> Option<&'static State> {
    // SAFETY: `STATE` is written once at the very end of the single-CPU init
    // path and is read-only afterwards.
    unsafe { (*core::ptr::addr_of!(STATE)).as_ref() }
}

fn init_locked() -> Result<(), &'static str> {
    if platform_state().is_some() {
        return Err("platform-already-initialised");
    }

    let root = root_table()?;
    let madt_phys = locate_table(&root, acpi::MADT_SIG)?.ok_or("acpi-madt-missing")?;
    let (madt_bytes, _) = read_table(madt_phys, acpi::MADT_SIG)?;
    let madt = acpi::parse_madt(madt_bytes).map_err(acpi::AcpiError::as_str)?;
    if madt.enabled_cpus == 0 {
        return Err("acpi-no-enabled-cpu");
    }

    // --- Local APIC ------------------------------------------------------
    let lapic_base = apic::detect_local_apic(madt.local_apic_phys)?;
    let lapic_va = map_pages(lapic_base, 1, DEVICE_FLAGS)?;
    let lapic = apic::Lapic::new(lapic_va);
    let lapic_id = lapic.id();
    let version = lapic.version();
    // A silent MMIO window reads back as all-ones/all-zeroes; both are refused
    // instead of programming a device that is not there.
    if lapic_id == 0xFF || version == 0 || version & 0xFF == 0xFF {
        return Err("apic-window-invalid");
    }
    // CPUID.01H:EBX[31:24] is the initial APIC id; the register must agree,
    // otherwise the window maps a different local APIC than this CPU owns.
    let (_, ebx, _, _) = arch::cpuid(1, 0);
    if (ebx >> 24) as u8 != lapic_id {
        return Err("apic-id-mismatch");
    }
    let spurious_vector = apic::enable(&lapic, apic::SPURIOUS_VECTOR);

    // The boot processor must be one of the enabled MADT entries; otherwise the
    // firmware table and the CPU executing this code disagree and any AP
    // id assignment derived from that table would be wrong too.
    if !madt
        .cpus()
        .iter()
        .any(|cpu| cpu.enabled && cpu.apic_id == lapic_id)
    {
        return Err("acpi-bsp-not-in-madt");
    }
    let cpus = madt.cpus;
    let cpu_count = madt.cpu_count;

    // The PICs must be muted explicitly: firmware may still route legacy IRQs
    // through them, and M3 uses the IO APIC for IRQ1/IRQ4.
    apic::mask_legacy_pics();

    // --- IO APIC ---------------------------------------------------------
    let io_apic_va = map_pages(madt.io_apic_phys, 1, DEVICE_FLAGS)?;
    let io_apic = apic::IoApic::new(io_apic_va);
    let io_apic_id = io_apic.id();
    if io_apic_id != madt.io_apic_id {
        return Err("ioapic-id-mismatch");
    }
    apic::mask_all_redirections(&io_apic)?;

    // Only the two legacy lines M3 owns are routed; everything else stays
    // masked. MADT interrupt-source overrides are honoured when present.
    let keyboard = acpi::route_isa_irq(&madt, 1);
    apic::route_gsi(
        &io_apic,
        madt.io_apic_gsi_base,
        keyboard,
        KEYBOARD_VECTOR,
        lapic_id,
    )?;
    let serial = acpi::route_isa_irq(&madt, 4);
    apic::route_gsi(
        &io_apic,
        madt.io_apic_gsi_base,
        serial,
        SERIAL_VECTOR,
        lapic_id,
    )?;

    // SAFETY: single-CPU init path; nothing can observe `STATE` before this
    // write, and it is read-only from here on.
    unsafe {
        core::ptr::addr_of_mut!(STATE).write(Some(State {
            lapic,
            io_apic,
            lapic_id,
            io_apic_id,
            spurious_vector,
            cpus,
            cpu_count,
        }));
    }
    Ok(())
}

/// Copy-and-validate the RSDP at `phys`.
fn read_rsdp(phys: u64) -> Result<acpi::Rsdp, &'static str> {
    let bytes = read_bytes(phys, acpi::RSDP_V2_LEN)?;
    acpi::parse_rsdp(bytes).map_err(acpi::AcpiError::as_str)
}

/// ACPI root description table resolved from the BootInfo RSDP.
struct RootTable {
    phys: u64,
    signature: [u8; 4],
    entry_size: usize,
}

/// Resolve the ACPI root table (XSDT when present, RSDT otherwise).
fn root_table() -> Result<RootTable, &'static str> {
    let rsdp_phys = boot::state().acpi_rsdp.ok_or("acpi-rsdp-missing")?;
    acpi::check_rsdp_phys(rsdp_phys).map_err(acpi::AcpiError::as_str)?;
    let rsdp = read_rsdp(rsdp_phys)?;
    // ACPI 2.0+ prefers the 64-bit XSDT; a 1.0-only firmware has no XSDT.
    if rsdp.xsdt_phys != 0 {
        Ok(RootTable {
            phys: rsdp.xsdt_phys,
            signature: acpi::XSDT_SIG,
            entry_size: 8,
        })
    } else {
        Ok(RootTable {
            phys: rsdp.rsdt_phys,
            signature: acpi::RSDT_SIG,
            entry_size: 4,
        })
    }
}

/// Find the description table `wanted` among the root table's entries.
///
/// Only each candidate's 36-byte header is mapped to compare signatures; the
/// caller maps the winning table at its declared length. A missing table is
/// `Ok(None)` so each subsystem can report its own reason string.
fn locate_table(root: &RootTable, wanted: [u8; 4]) -> Result<Option<u64>, &'static str> {
    let (bytes, info) = read_table(root.phys, root.signature)?;
    let count = acpi::entry_count(&info, root.entry_size).map_err(acpi::AcpiError::as_str)?;
    let mut index = 0;
    while index < count {
        let phys = acpi::entry_at(bytes, &info, index, root.entry_size)
            .map_err(acpi::AcpiError::as_str)?;
        // Only the 36-byte header is needed to identify the candidate table.
        let header = read_bytes(phys, acpi::SDT_HEADER_LEN)?;
        if header[..4] == wanted {
            return Ok(Some(phys));
        }
        index += 1;
    }
    Ok(None)
}

/// Physical address of the first ACPI table carrying `wanted` signature.
///
/// Used by subsystems that need an additional table (M5b: MCFG). The RSDP and
/// root table are resolved fresh, so this can be called after [`init`] without
/// sharing its cached state.
pub(crate) fn find_acpi_table(wanted: [u8; 4]) -> Result<u64, &'static str> {
    let root = root_table()?;
    locate_table(&root, wanted)?.ok_or("acpi-table-missing")
}

/// Map a system description table and validate it.
///
/// The declared length is only known after mapping the header, and mappings are
/// permanent, so the header is mapped once and the full table right after it.
pub(crate) fn read_table(
    phys: u64,
    signature: [u8; 4],
) -> Result<(&'static [u8], acpi::TableInfo), &'static str> {
    let header = read_bytes(phys, acpi::SDT_HEADER_LEN)?;
    let declared =
        acpi::declared_table_length(header, signature).map_err(acpi::AcpiError::as_str)?;
    let bytes = read_bytes(phys, declared as usize)?;
    let info = acpi::validate_table(bytes, signature).map_err(acpi::AcpiError::as_str)?;
    Ok((bytes, info))
}

/// Reserve `pages` of the platform window and map them over `phys`.
fn map_pages(phys: u64, pages: u64, flags: u64) -> Result<u64, &'static str> {
    let bytes = pages.checked_mul(PAGE).ok_or("platform-map-overflow")?;
    let len = usize::try_from(bytes).map_err(|_| "platform-map-overflow")?;
    map_bytes(phys, len, flags)
}

/// Name the concrete page-table constraint that refused a platform mapping.
///
/// `kernel/src/mm/vm.rs` folds several distinct conditions into `VmError`, and
/// an early-boot "mapping failed" is only diagnosable if the message says which
/// one fired, so every variant keeps its own string here.
fn map_error(err: vm::VmError) -> &'static str {
    match err {
        vm::VmError::OutOfTables => "platform-map-out-of-tables",
        vm::VmError::Overlap => "platform-map-overlap",
        vm::VmError::NotFound => "platform-map-not-found",
        vm::VmError::BadAddress => "platform-map-bad-address",
        vm::VmError::NotReady => "platform-map-not-ready",
    }
}

/// Pages a [`vm::map_physical`] request consumes for `len` bytes at `phys`.
///
/// The VM maps the page-aligned physical span covering `[phys, phys + len)`,
/// starting at `phys & !(PAGE - 1)`, so an unaligned start can consume one page
/// more than `len` alone accounts for. The window reservation below has to
/// match that span exactly: reserving fewer pages than the request maps makes
/// the *next* reservation land on pages the previous request just mapped (the
/// VM reports that as `VmError::Overlap`), and reserving more strands window.
fn span_pages(phys: u64, len: u64) -> Option<u64> {
    let offset = phys & (PAGE - 1);
    offset
        .checked_add(len)?
        .checked_add(PAGE - 1)
        .map(|n| n / PAGE)
}

/// Reserve window space for `len` bytes over `phys` and map them.
///
/// Exactly [`span_pages`] pages are reserved, so every reservation is used up
/// by the mapping it was made for and consecutive reservations never collide.
fn map_bytes(phys: u64, len: usize, flags: u64) -> Result<u64, &'static str> {
    // SAFETY: only the single-CPU `init` path touches this pointer.
    unsafe {
        map_bytes_in(
            phys,
            len,
            flags,
            &mut *core::ptr::addr_of_mut!(WINDOW_NEXT),
            WINDOW_BASE,
            WINDOW_LIMIT,
        )
    }
}

/// Map `len` bytes at `phys` into the bump window described by `next`.
fn map_bytes_in(
    phys: u64,
    len: usize,
    flags: u64,
    next: &mut u64,
    base: u64,
    limit: u64,
) -> Result<u64, &'static str> {
    if len == 0 {
        return Err("platform-empty-mapping");
    }
    let len = len as u64;
    let pages = span_pages(phys, len).ok_or("platform-map-overflow")?;
    let virt = reserve_in(next, base, limit, pages)?;
    // SAFETY: `virt` is page aligned and freshly reserved inside the window
    // (never handed out twice), and the whole span stays inside the
    // kernel-image 1 GiB window that the takeover page tables wired.
    let mapped = unsafe { vm::map_physical(virt, phys, len, flags) }.map_err(map_error)?;
    // The VM returns the address of `phys` itself inside the mapped span.
    if mapped != virt + (phys & (PAGE - 1)) {
        return Err("platform-map-inconsistent");
    }
    Ok(mapped)
}

/// Reserve `pages` at `*next`, refusing to grow past `base + limit`.
fn reserve_in(next: &mut u64, base: u64, limit: u64, pages: u64) -> Result<u64, &'static str> {
    if pages == 0 {
        return Err("platform-window-empty");
    }
    let bytes = pages.checked_mul(PAGE).ok_or("platform-window-overflow")?;
    let virt = *next;
    let end = virt.checked_add(bytes).ok_or("platform-window-overflow")?;
    let window_end = base.checked_add(limit).ok_or("platform-window-overflow")?;
    if end > window_end {
        return Err("platform-window-exhausted");
    }
    *next = end;
    Ok(virt)
}

/// Map `len` bytes of device MMIO at `phys` into the device-MMIO window.
///
/// Callers pass only the slice they actually touch — one MSI-X table entry, or
/// the register block of a virtio BAR — never a whole BAR. Returns the virtual
/// address of `phys` itself. The mapping is uncached (`PWT|PCD`), writable,
/// non-executable and permanent, like every other platform mapping.  Errors are
/// loud: `net-window-empty`, `net-window-overflow`, `platform-map-*`,
/// `net-window-inconsistent`.
pub(crate) fn map_net_mmio(phys: u64, len: usize) -> Result<u64, &'static str> {
    if len == 0 {
        return Err("net-window-empty");
    }
    let len = len as u64;
    let pages = span_pages(phys, len).ok_or("net-window-overflow")?;
    // SAFETY: PCI bring-up runs with interrupts off on a single CPU, and only
    // this function advances the device-MMIO bump pointer.
    unsafe {
        let virt = reserve_in(
            &mut *core::ptr::addr_of_mut!(NET_WINDOW_NEXT),
            NET_WINDOW_BASE,
            NET_WINDOW_LIMIT,
            pages,
        )?;
        // SAFETY: `virt` is page aligned, freshly reserved and never handed out
        // twice; the mapped span stays inside the kernel-image 1 GiB window.
        let mapped = vm::map_physical(virt, phys, len, DEVICE_FLAGS).map_err(map_error)?;
        if mapped != virt + (phys & (PAGE - 1)) {
            return Err("net-window-inconsistent");
        }
        Ok(mapped)
    }
}

/// Pages handed out by [`map_net_mmio`] so far (diagnostics/budget check).
pub fn net_window_pages() -> u64 {
    // SAFETY: single-CPU read of a bump pointer that only `map_net_mmio` writes.
    unsafe { (*core::ptr::addr_of!(NET_WINDOW_NEXT) - NET_WINDOW_BASE) / PAGE }
}

/// Borrow `len` bytes of firmware memory at `phys` through the read-only window.
fn read_bytes(phys: u64, len: usize) -> Result<&'static [u8], &'static str> {
    let va = map_bytes(phys, len, TABLE_FLAGS)?;
    // SAFETY: the range was just mapped read-only into the permanent window and
    // covers at least `len` bytes; it is never unmapped.
    Ok(unsafe { core::slice::from_raw_parts(va as *const u8, len) })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `vm::map_physical` maps this span: `[phys & !(PAGE-1), ceil(phys + len))`.
    fn vm_span_pages(phys: u64, len: u64) -> Option<u64> {
        let first = phys & !(PAGE - 1);
        let last = phys.checked_add(len)?.checked_add(PAGE - 1)? & !(PAGE - 1);
        Some((last - first) / PAGE)
    }

    #[test]
    fn span_pages_counts_the_aligned_physical_span() {
        // Page-aligned table start: one page covers a 36-byte header.
        assert_eq!(span_pages(0x0f77e000, 36), Some(1));
        // OVMF's rev2 RSDP sits at page offset 0x14, still one page for itself.
        assert_eq!(span_pages(0x0f77e014, 36), Some(1));
        // A request that starts unaligned and crosses a page boundary needs two.
        assert_eq!(span_pages(0x0f77eff0, 32), Some(2));
        // The regression that broke the first QEMU bring-up: 8 KiB at offset
        // 0x14 covers the tail of the first page, so it consumes three pages,
        // and a two-page reservation then collided with the next request.
        assert_eq!(span_pages(0x0f77e014, 8192), Some(3));
        assert_eq!(span_pages(0, 4096), Some(1));
    }

    #[test]
    fn span_pages_agrees_with_the_vm_span_rule() {
        let cases = [
            (0x0f77e000u64, 36u64),
            (0x0f77e014, 36),
            (0x0f77e014, 8192),
            (0x0f77eff0, 32),
            (0x0f778000, 120),
            (0x0f77d0e8, 84),
            (0xfee00000, 4096),
            (0xfec00000, 4096),
            (0x1000, 0x2000),
            (0, 1),
        ];
        for (phys, len) in cases {
            assert_eq!(
                span_pages(phys, len),
                vm_span_pages(phys, len),
                "span mismatch for phys={phys:#x} len={len}"
            );
        }
    }

    #[test]
    fn span_pages_rejects_overflow() {
        // `offset + len` itself is fine but rounding cannot represent the span.
        assert_eq!(span_pages(0, u64::MAX), None);
        assert_eq!(span_pages(0x100, u64::MAX), None);
    }

    /// Fabricated platform state: boot processor 0, one fallback AP, one
    /// disabled MADT entry. No MMIO is touched by the constructors.
    fn smp_test_state() -> State {
        let mut cpus = [acpi::CpuEntry::NONE; acpi::MAX_CPUS];
        cpus[0] = acpi::CpuEntry {
            acpi_processor_id: 0,
            apic_id: 0,
            enabled: true,
        };
        cpus[1] = acpi::CpuEntry {
            acpi_processor_id: 1,
            apic_id: 1,
            enabled: true,
        };
        cpus[2] = acpi::CpuEntry {
            acpi_processor_id: 2,
            apic_id: 2,
            enabled: false,
        };
        State {
            lapic: apic::Lapic::new(0),
            io_apic: apic::IoApic::new(0),
            lapic_id: 0,
            io_apic_id: 0,
            spurious_vector: apic::SPURIOUS_VECTOR,
            cpus,
            cpu_count: 3,
        }
    }

    #[test]
    fn ipi_targets_must_be_enabled_application_processors() {
        let state = smp_test_state();
        assert_eq!(
            check_ap_target(&state, 0),
            Err("ipi-target-is-boot-processor")
        );
        assert_eq!(check_ap_target(&state, 1), Ok(()));
        // Disabled MADT entries exist in the table but have no CPU behind them.
        assert_eq!(
            check_ap_target(&state, 2),
            Err("ipi-target-not-an-enabled-cpu")
        );
        assert_eq!(
            check_ap_target(&state, 9),
            Err("ipi-target-not-an-enabled-cpu")
        );
    }

    #[test]
    fn the_cpu_list_excludes_table_tail_entries() {
        let state = smp_test_state();
        assert_eq!(&state.cpus[..state.cpu_count].len(), &3);
        assert_eq!(
            state.cpus[..state.cpu_count]
                .iter()
                .filter(|cpu| cpu.enabled)
                .count(),
            2
        );
    }

    #[test]
    fn enabling_the_local_apic_requires_a_published_platform_state() {
        // Host tests never publish `STATE`; the AP helper must refuse instead of
        // programming a fabricated local APIC window.
        assert_eq!(enable_local_apic(), Err("platform-not-initialised"));
    }

    #[test]
    fn reschedule_targets_include_the_boot_processor_and_enabled_aps() {
        let state = smp_test_state();
        let cpus = &state.cpus[..state.cpu_count];
        // Indexes follow MADT order and the BSP is entry 0 here: unlike the
        // INIT/SIPI rule, the boot processor stays a legal reschedule target.
        assert_eq!(reschedule_target(cpus, 0), Ok(0));
        assert_eq!(reschedule_target(cpus, 1), Ok(1));
        // A disabled MADT entry has no CPU behind it.
        assert_eq!(
            reschedule_target(cpus, 2),
            Err("ipi-target-not-an-enabled-cpu")
        );
        assert_eq!(
            reschedule_target(cpus, 3),
            Err("ipi-target-not-an-enabled-cpu")
        );
        assert_eq!(
            reschedule_target(cpus, usize::MAX),
            Err("ipi-target-not-an-enabled-cpu")
        );
    }

    #[test]
    fn reschedule_ipi_and_local_timer_need_a_published_platform_state() {
        // Without `init` there is no local APIC handle to program, so both M6b2
        // entry points must refuse rather than touch a fabricated window.
        assert_eq!(send_reschedule_ipi(0), Err("platform-not-initialised"));
        assert_eq!(start_local_timer(100), Err("platform-not-initialised"));
        // The counter accessor is a plain read and stays callable.
        assert_eq!(reschedule_ipi_sent(), apic::reschedule_ipi_sent());
    }

    #[test]
    fn the_net_window_is_disjoint_and_inside_the_kernel_window() {
        // M7c freezes `0xFFFF_FFFF_8600_0000` for device MMIO; it must not meet
        // the PCI ECAM window, must sit above the pages display actually maps
        // today (64 frames = 256 KiB at the framebuffer base), and must stay in
        // the kernel-image 1 GiB PDPT the takeover page tables wire.
        assert_eq!(NET_WINDOW_BASE, 0xFFFF_FFFF_8600_0000);
        assert!(NET_WINDOW_BASE >= PCI_WINDOW_BASE + PCI_WINDOW_LIMIT);
        assert!(NET_WINDOW_BASE >= FB_WINDOW_BASE + 64 * PAGE);
        assert!(NET_WINDOW_BASE + NET_WINDOW_LIMIT <= 0xFFFF_FFFF_C000_0000);
        // A fresh process has handed out nothing yet.
        assert_eq!(net_window_pages(), 0);
    }

    #[test]
    fn bump_reservations_respect_the_window_limit() {
        let mut next = NET_WINDOW_BASE;
        assert_eq!(
            reserve_in(&mut next, NET_WINDOW_BASE, NET_WINDOW_LIMIT, 1),
            Ok(NET_WINDOW_BASE)
        );
        assert_eq!(next, NET_WINDOW_BASE + PAGE);

        // The last page of the window is still available, the one past it is not.
        let mut last = NET_WINDOW_BASE + NET_WINDOW_LIMIT - PAGE;
        assert_eq!(
            reserve_in(&mut last, NET_WINDOW_BASE, NET_WINDOW_LIMIT, 1),
            Ok(NET_WINDOW_BASE + NET_WINDOW_LIMIT - PAGE)
        );
        assert_eq!(
            reserve_in(&mut last, NET_WINDOW_BASE, NET_WINDOW_LIMIT, 1),
            Err("platform-window-exhausted")
        );

        // Zero pages and pointer overflow are refused before touching `*next`.
        let mut untouched = NET_WINDOW_BASE;
        assert_eq!(
            reserve_in(&mut untouched, NET_WINDOW_BASE, NET_WINDOW_LIMIT, 0),
            Err("platform-window-empty")
        );
        assert_eq!(untouched, NET_WINDOW_BASE);
        let mut huge = u64::MAX - PAGE;
        assert_eq!(
            reserve_in(&mut huge, NET_WINDOW_BASE, NET_WINDOW_LIMIT, 2),
            Err("platform-window-overflow")
        );
    }
}
