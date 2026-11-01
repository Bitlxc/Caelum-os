//! PCI configuration space access through ACPI MCFG / ECAM (M5b platform layer).
//!
//! Responsibility split (see the architecture baseline, section 6.1):
//! * `acpi::parse_mcfg` - pure validation of the MCFG table (host-tested).
//! * this module - ECAM page mapping, bus/device/function enumeration and the
//!   raw configuration-space read/write primitives a device driver needs.
//!
//! Boundaries this module deliberately keeps:
//! * no firmware fallback: the ECAM base comes from the ACPI MCFG table, never
//!   from a hard-coded q35 address (`0xB000_0000` or otherwise);
//! * no device policy: BARs are reported as raw `u32` values, nothing is
//!   probed, reset, enabled or claimed as an interrupt;
//! * no printing and no allocation; failures are `&'static str` reason strings.
//!
//! # Mapping budget
//!
//! The M2 VM has no unmap, so every ECAM page mapped here stays mapped. A whole
//! MCFG allocation may describe the full 256-bus space (the vendored OVMF does:
//! `base=0xE000_0000, segment=0, buses 0..=255`, i.e. 256 MiB), which does not
//! fit - and must not be stuffed into - the kernel's 16 MiB PCI window.
//! Therefore exactly one 4 KiB page is mapped per *function actually probed*:
//! function 0 of every device, then functions 1..7 only when the device reports
//! the multifunction bit. Enumeration starts at each MCFG allocation's root bus
//! and follows PCI-to-PCI bridges (secondary bus), so every reachable device is
//! found while bogus bus numbers cost no mappings. Two hard caps keep the budget
//! bounded and are reported loudly instead of silently dropping devices:
//! [`MAX_ECAM_PAGES`] pages and [`MAX_BUSES`] visited buses.

use core::ptr::{addr_of_mut, read_volatile, write_volatile};

use crate::arch;
use crate::mm::vm;

use super::{
    DEVICE_FLAGS, PAGE, PCI_WINDOW_BASE, PCI_WINDOW_LIMIT, acpi, apic, find_acpi_table, map_error,
    map_net_mmio, read_table,
};

/// Upper bound on functions cached for drivers.
pub const MAX_FUNCTIONS: usize = 64;
/// Upper bound on mapped ECAM pages (4 MiB of the 16 MiB PCI window).
pub const MAX_ECAM_PAGES: u64 = 1024;
/// Upper bound on visited buses (root buses plus bridge secondaries).
pub const MAX_BUSES: usize = 64;

/// Devices per bus / functions per device, per the PCI specification.
const DEVICES_PER_BUS: u8 = 32;
const FUNCTIONS_PER_DEVICE: u8 = 8;
/// `vendor_id` of a function that is not present.
const VENDOR_NONE: u16 = 0xFFFF;
/// Configuration space space per function (ECAM architectural page).
const FUNCTION_SPACE: u64 = acpi::ECAM_FUNCTION_LEN;
/// Configuration header offsets used while enumerating.
const REG_VENDOR_DEVICE: u8 = 0x00;
const REG_REVISION_CLASS: u8 = 0x08;
const REG_HEADER_TYPE: u8 = 0x0E;
const REG_BARS: u8 = 0x10;
/// Number of dwords covering the standard 64-byte configuration header.
const HEADER_DWORDS: usize = 16;
/// Header-type bit 7: the device has multiple functions.
const HEADER_TYPE_MULTIFUNCTION: u8 = 0x80;
/// Header-type low bits of a PCI-to-PCI bridge.
const HEADER_TYPE_BRIDGE: u8 = 0x01;
/// Offset of `secondary_bus` inside a bridge header.
const REG_SECONDARY_BUS: u8 = 0x19;

/// One enumerated PCI function.
///
/// BARs are the raw configuration-space values: the platform layer does not
/// interpret them (the driver decides I/O vs MMIO and merges 64-bit BARs).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PciFunction {
    /// PCI segment group.
    pub segment: u16,
    /// Bus number.
    pub bus: u8,
    /// Device number (0..=31).
    pub device: u8,
    /// Function number (0..=7).
    pub function: u8,
    /// Vendor id (`0xFFFF` means "no function").
    pub vendor_id: u16,
    /// Device id.
    pub device_id: u16,
    /// Base class code (config offset `0x0B`).
    pub class: u8,
    /// Sub-class code (config offset `0x0A`).
    pub subclass: u8,
    /// Programming interface (config offset `0x09`).
    pub prog_if: u8,
    /// Revision id (config offset `0x08`).
    pub revision: u8,
    /// Raw BAR0..BAR5 values.
    pub bars: [u32; 6],
}

impl PciFunction {
    /// Zero value used to pre-fill the static table.
    const NONE: Self = Self {
        segment: 0,
        bus: 0,
        device: 0,
        function: 0,
        vendor_id: 0,
        device_id: 0,
        class: 0,
        subclass: 0,
        prog_if: 0,
        revision: 0,
        bars: [0; 6],
    };

    /// True when this descriptor refers to the same function as `other`.
    pub fn same_function(&self, other: &Self) -> bool {
        self.segment == other.segment
            && self.bus == other.bus
            && self.device == other.device
            && self.function == other.function
    }
}

/// One decoded configuration header (plus the page it came from).
struct Header {
    function: PciFunction,
    multifunction: bool,
    bridge: bool,
    secondary_bus: u8,
    ecam: u64,
}

/// Enumeration state: cached functions, their ECAM pages and the walk work list.
struct State {
    ready: bool,
    count: usize,
    functions: [PciFunction; MAX_FUNCTIONS],
    /// Virtual address of each cached function's 4 KiB ECAM page.
    ecam: [u64; MAX_FUNCTIONS],
    /// Buses already scanned, to stop bridge cycles.
    visited: [(u16, u8); MAX_BUSES],
    visited_count: usize,
    /// Buses still to scan.
    queue: [(u16, u8); MAX_BUSES],
    queue_head: usize,
    queue_tail: usize,
    /// Bump pointer inside the PCI window and pages consumed from it.
    next_virt: u64,
    pages: u64,
}

impl State {
    /// Zeroed state; the single production instance lives in `.bss`.
    const EMPTY: Self = Self {
        ready: false,
        count: 0,
        functions: [PciFunction::NONE; MAX_FUNCTIONS],
        ecam: [0; MAX_FUNCTIONS],
        visited: [(0, 0); MAX_BUSES],
        visited_count: 0,
        queue: [(0, 0); MAX_BUSES],
        queue_head: 0,
        queue_tail: 0,
        next_virt: PCI_WINDOW_BASE,
        pages: 0,
    };
}

static mut STATE: State = State::EMPTY;

/// Enumerate PCI functions and cache the descriptors drivers match on.
///
/// Interrupts are forced off for the duration (mapping and MMIO probing are
/// single-CPU bring-up work). Returns the number of cached functions. Calling it
/// again after success returns the same count without mapping anything new.
///
/// Errors (all loud, no fallback): `pci-mcfg-missing`, `acpi-*`/`mcfg-*`,
/// `pci-map-*`, `pci-window-quota`, `pci-function-quota`, `pci-bus-quota`,
/// `pci-bus-outside-mcfg`, `pci-bridge-outside-mcfg`, `pci-no-devices`.
pub fn init_pci() -> Result<usize, &'static str> {
    let flags = arch::disable_interrupts();
    let result = init_locked();
    arch::restore_interrupts(flags);
    result
}

/// True once [`init_pci`] completed successfully.
pub fn is_pci_ready() -> bool {
    state().ready
}

/// Number of functions cached by [`init_pci`] (0 before it runs).
pub fn pci_function_count() -> usize {
    state().count
}

/// Number of ECAM pages mapped into the PCI window (diagnostics/budget check).
pub fn pci_ecam_pages() -> u64 {
    state().pages
}

/// Find the `instance`-th cached function with this vendor/device id.
///
/// Functions are matched in enumeration order (bus, device, function ascending),
/// so `instance = 0` is the first one found and `instance = 1` the second.
pub fn find_pci(vendor: u16, device: u16, instance: usize) -> Option<PciFunction> {
    let st = state();
    select_instance(&st.functions[..st.count], vendor, device, instance)
}

/// Pick the `instance`-th matching function from an enumeration-ordered slice.
fn select_instance(
    functions: &[PciFunction],
    vendor: u16,
    device: u16,
    instance: usize,
) -> Option<PciFunction> {
    let mut seen = 0;
    for function in functions {
        if function.vendor_id == vendor && function.device_id == device {
            if seen == instance {
                return Some(*function);
            }
            seen += 1;
        }
    }
    None
}

/// Read the 16-bit configuration word at byte `offset` of `function`.
///
/// `offset` must be 2-byte aligned and inside the function's 4 KiB ECAM page;
/// the function must have been returned by [`find_pci`].
pub fn read_config16(function: &PciFunction, offset: u8) -> Result<u16, &'static str> {
    let ecam = ecam_of(function)?;
    check_access(offset, 2)?;
    // SAFETY: `ecam` is the base of a mapped 4 KiB uncached ECAM page and the
    // checked offset keeps the access inside it; reads have no side effects.
    Ok(unsafe { read_volatile((ecam + u64::from(offset)) as *const u16) })
}

/// Read the 32-bit configuration dword at byte `offset` of `function`.
pub fn read_config32(function: &PciFunction, offset: u8) -> Result<u32, &'static str> {
    let ecam = ecam_of(function)?;
    check_access(offset, 4)?;
    // SAFETY: see `read_config16`.
    Ok(unsafe { read_volatile((ecam + u64::from(offset)) as *const u32) })
}

/// Write the 16-bit configuration word at byte `offset` of `function`.
///
/// Used by drivers to set the command register (`offset 0x04`: I/O space, bus
/// master) once they own the device.
pub fn write_config16(function: &PciFunction, offset: u8, value: u16) -> Result<(), &'static str> {
    let ecam = ecam_of(function)?;
    check_access(offset, 2)?;
    // SAFETY: see `read_config16`; volatile keeps the MMIO write.
    unsafe { write_volatile((ecam + u64::from(offset)) as *mut u16, value) };
    Ok(())
}

/// Write the 32-bit configuration dword at byte `offset` of `function`.
pub fn write_config32(function: &PciFunction, offset: u8, value: u32) -> Result<(), &'static str> {
    let ecam = ecam_of(function)?;
    check_access(offset, 4)?;
    // SAFETY: see `read_config16`; volatile keeps the MMIO write.
    unsafe { write_volatile((ecam + u64::from(offset)) as *mut u32, value) };
    Ok(())
}

// ---------------------------------------------------------------------------
// MSI / MSI-X (M7c prerequisites)
// ---------------------------------------------------------------------------
//
// The path is fixed and loud: walk the capability list with truncation and
// cycle checks, decode the MSI-X table location (BIR + offset), and program one
// vector with the mask -> address/data -> unmask sequence. A function without
// MSI-X is reported, never demoted to the q35 INTx routing this kernel only
// owns for the two legacy ISA lines.

/// PCI capability id of the legacy MSI capability.
pub const CAP_ID_MSI: u8 = 0x05;
/// PCI capability id of MSI-X.
pub const CAP_ID_MSIX: u8 = 0x11;
/// Config-space offset of the status word (`status` is its high half).
const CONFIG_STATUS: u8 = 0x06;
/// `status` bit 4: the function has a capability list.
const STATUS_CAP_LIST: u16 = 1 << 4;
/// Config-space offset of the capability-list head pointer.
const CAP_POINTER_OFFSET: u8 = 0x34;
/// First offset a capability record may occupy (the fixed header is 64 bytes).
const FIRST_CAPABILITY: u8 = 0x40;
/// Capability pointers are dword aligned; the low two bits are reserved.
const CAP_POINTER_MASK: u8 = 0xFC;
/// A capability record plus its MSI-X table/PBA dwords must fit in config space.
const CONFIG_SPACE_END: u16 = 0x100;
/// Guard against firmware loops: real lists hold a handful of records.
const MAX_CAPABILITIES: usize = 48;

/// Largest MSI-X table the specification allows (bits 10:0 of `msgctl`).
pub const MSIX_MAX_VECTORS: u16 = 2048;
/// One MSI-X table entry: 64-bit address, 32-bit data, 32-bit vector control.
pub const MSIX_ENTRY_BYTES: u64 = 16;
/// Vector-control bit 0: mask this vector.
pub const MSIX_VECTOR_MASK: u32 = 1;
/// Bit 14 of `msgctl`: mask the whole function.
const MSIX_CONTROL_FUNCTION_MASK: u16 = 1 << 14;
/// Bit 15 of `msgctl`: enable MSI-X for the function.
const MSIX_CONTROL_ENABLE: u16 = 1 << 15;
/// Bits 10:0 of `msgctl`: table size minus one.
const MSIX_CONTROL_TABLE_SIZE: u16 = 0x07FF;
/// Upper bound on a single BAR slice a driver may map; whole BARs stay unmapped.
pub const MAX_BAR_SLICE: usize = 64 * 1024;

/// Decoded MSI-X capability (configuration-space values, no MMIO touched).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct MsixCapability {
    /// Offset of the capability record in configuration space.
    pub cap_offset: u8,
    /// Number of table entries (1..=2048).
    pub vectors: u16,
    /// BAR index (`BIR`) backing the MSI-X table.
    pub table_bir: u8,
    /// Byte offset of the table inside that BAR.
    pub table_offset: u32,
    /// Bytes the whole table occupies.
    pub table_bytes: u64,
    /// BAR index backing the pending-bit array.
    pub pba_bir: u8,
    /// Byte offset of the pending-bit array inside that BAR.
    pub pba_offset: u32,
    /// `msgctl` function-mask bit as read.
    pub function_mask: bool,
    /// `msgctl` enable bit as read.
    pub enabled: bool,
}

impl MsixCapability {
    /// Config-space offset of the MSI-X message control word (`cap + 2`).
    fn control_offset(&self) -> Result<u8, &'static str> {
        self.cap_offset.checked_add(2).ok_or("pci-msix-truncated")
    }
}

/// Result of walking a function's capability list.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct CapabilityWalk {
    /// Offset of the legacy MSI capability, when the function has one.
    pub msi_offset: Option<u8>,
    /// Decoded MSI-X capability, when the function has one.
    pub msix: Option<MsixCapability>,
}

/// Decode an MSI-X table/PBA "BIR | offset" dword into `(bar index, offset)`.
///
/// Bits 2:0 select the BAR, bits 31:3 carry an 8-byte aligned byte offset.
pub const fn decode_msix_location(word: u32) -> (u8, u32) {
    ((word & 0x7) as u8, word & !0x7)
}

/// Decode the MSI-X `msgctl` word.
fn decode_msix(control: u16, table: u32, pba: u32, cap_offset: u8) -> MsixCapability {
    let vectors = (control & MSIX_CONTROL_TABLE_SIZE) + 1;
    let (table_bir, table_offset) = decode_msix_location(table);
    let (pba_bir, pba_offset) = decode_msix_location(pba);
    MsixCapability {
        cap_offset,
        vectors,
        table_bir,
        table_offset,
        table_bytes: u64::from(vectors) * MSIX_ENTRY_BYTES,
        pba_bir,
        pba_offset,
        function_mask: control & MSIX_CONTROL_FUNCTION_MASK != 0,
        enabled: control & MSIX_CONTROL_ENABLE != 0,
    }
}

/// Walk a capability list safely.
///
/// `status` and `cap_pointer` come from configuration space; `read_dword`
/// supplies the dword at a given config offset (the host tests pass a closure
/// over a fake config space, production passes [`read_config32`]).
///
/// Refused loudly instead of looping or guessing:
/// * a pointer into the fixed header (`< 0x40`) or a non-dword-aligned one →
///   `pci-bad-cap-pointer`;
/// * a record (plus the MSI-X table/PBA dwords) crossing the 256-byte config
///   space → `pci-cap-truncated`;
/// * a non-increasing `next` pointer, i.e. a cycle → `pci-cap-cycle`;
/// * more than [`MAX_CAPABILITIES`] records → `pci-cap-list-too-long`.
///
/// A function without the status bit has no capabilities at all: that is a
/// successful empty walk, not an error (the MSI-X caller reports the absence).
pub fn walk_capabilities<F>(
    status: u16,
    cap_pointer: u8,
    mut read_dword: F,
) -> Result<CapabilityWalk, &'static str>
where
    F: FnMut(u8) -> Result<u32, &'static str>,
{
    let mut walk = CapabilityWalk::default();
    if status & STATUS_CAP_LIST == 0 {
        return Ok(walk);
    }
    let mut next = cap_pointer & CAP_POINTER_MASK;
    let mut records = 0usize;
    while next != 0 {
        records += 1;
        if records > MAX_CAPABILITIES {
            return Err("pci-cap-list-too-long");
        }
        if next < FIRST_CAPABILITY || next & 3 != 0 {
            return Err("pci-bad-cap-pointer");
        }
        // Header dword plus the two MSI-X dwords must stay in config space.
        if u16::from(next) + 12 > CONFIG_SPACE_END {
            return Err("pci-cap-truncated");
        }
        let header = read_dword(next)?;
        let id = (header & 0xFF) as u8;
        let following = ((header >> 8) & 0xFF) as u8;
        match id {
            CAP_ID_MSI => {
                if walk.msi_offset.is_none() {
                    walk.msi_offset = Some(next);
                }
            }
            CAP_ID_MSIX => {
                if walk.msix.is_none() {
                    let control = (header >> 16) as u16;
                    let table = read_dword(next + 4)?;
                    let pba = read_dword(next + 8)?;
                    walk.msix = Some(decode_msix(control, table, pba, next));
                }
            }
            _ => {}
        }
        if following == 0 {
            break;
        }
        if following & 3 != 0 || following < FIRST_CAPABILITY {
            return Err("pci-bad-cap-pointer");
        }
        if following <= next {
            return Err("pci-cap-cycle");
        }
        next = following;
    }
    Ok(walk)
}

/// Walk the capability list of `function` through its mapped config page.
pub fn capabilities(function: &PciFunction) -> Result<CapabilityWalk, &'static str> {
    let status = read_config16(function, CONFIG_STATUS)?;
    let pointer = (read_config32(function, CAP_POINTER_OFFSET)? & 0xFF) as u8;
    walk_capabilities(status, pointer, |offset| read_config32(function, offset))
}

/// MSI-X capability of `function`, or a loud error when it has none.
pub fn msix_capability(function: &PciFunction) -> Result<MsixCapability, &'static str> {
    capabilities(function)?.msix.ok_or("pci-msix-not-present")
}

/// Memory base address of BAR `index` from raw configuration values (pure).
///
/// 64-bit memory BARs occupy two entries: the low dword's type bits are `0b10`
/// and the next entry holds the high 32 bits. I/O BARs and the reserved memory
/// type are refused: the MSI-X table and a virtio registers BAR are both memory.
pub fn bar_mmio_base(bars: &[u32; 6], index: u8) -> Result<u64, &'static str> {
    let index = usize::from(index);
    let bar = *bars.get(index).ok_or("pci-bar-index")?;
    if bar & 1 != 0 {
        return Err("pci-bar-io");
    }
    match (bar >> 1) & 0b11 {
        0b00 => Ok(u64::from(bar & !0xF)),
        0b10 => {
            let high = *bars.get(index + 1).ok_or("pci-bar-truncated")?;
            Ok((u64::from(high) << 32) | u64::from(bar & !0xF))
        }
        _ => Err("pci-bar-reserved-type"),
    }
}

/// Physical address of the MSI-X table of `function`.
pub fn msix_table_phys(function: &PciFunction, cap: &MsixCapability) -> Result<u64, &'static str> {
    let base = bar_mmio_base(&function.bars, cap.table_bir)?;
    base.checked_add(u64::from(cap.table_offset))
        .ok_or("pci-msix-table-overflow")
}

/// Map the whole MSI-X table of `function` into the device-MMIO window.
///
/// The table is at most 32 KiB (2048 entries), so mapping it whole is one slice,
/// not a BAR: the surrounding BAR bytes stay unmapped.
pub fn map_msix_table(function: &PciFunction, cap: &MsixCapability) -> Result<u64, &'static str> {
    let phys = msix_table_phys(function, cap)?;
    let bytes = usize::try_from(cap.table_bytes).map_err(|_| "pci-msix-table-overflow")?;
    if bytes == 0 || cap.vectors > MSIX_MAX_VECTORS {
        return Err("pci-msix-bad-vector-count");
    }
    map_net_mmio(phys, bytes)
}

/// Program one MSI-X table entry to deliver `vector` to `dest_apic`.
///
/// Sequence required by the MSI-X rules: mask the vector, write address and
/// data, then unmask. The address is the x86 encoded APIC page from
/// [`apic::msi_message_address`]; the data word is the bare vector.
pub fn configure_msix_vector(
    function: &PciFunction,
    cap: &MsixCapability,
    entry: u16,
    vector: u8,
    dest_apic: u8,
) -> Result<(), &'static str> {
    if vector == 0 {
        return Err("pci-msix-bad-vector");
    }
    if entry >= cap.vectors {
        return Err("pci-msix-bad-entry");
    }
    let table = msix_table_phys(function, cap)?;
    let entry_phys = table
        .checked_add(u64::from(entry) * MSIX_ENTRY_BYTES)
        .ok_or("pci-msix-table-overflow")?;
    let bytes = usize::try_from(MSIX_ENTRY_BYTES).map_err(|_| "pci-msix-table-overflow")?;
    let virt = map_net_mmio(entry_phys, bytes)?;
    // SAFETY: `virt` is the mapped, uncached 16-byte table entry the mapping was
    // made for; all four dword stores stay inside that entry.
    unsafe {
        let slots = virt as *mut u32;
        let control = read_volatile(slots.add(3));
        write_volatile(slots.add(3), control | MSIX_VECTOR_MASK);
        write_volatile(slots, apic::msi_message_address(dest_apic));
        write_volatile(slots.add(1), 0);
        write_volatile(slots.add(2), apic::msi_message_data(vector));
        write_volatile(slots.add(3), control & !MSIX_VECTOR_MASK);
    }
    Ok(())
}

/// Mask or unmask every vector of the function (MSI-X `msgctl` bit 14).
pub fn set_msix_function_mask(
    function: &PciFunction,
    cap: &MsixCapability,
    masked: bool,
) -> Result<(), &'static str> {
    let offset = cap.control_offset()?;
    let mut control = read_config16(function, offset)?;
    if masked {
        control |= MSIX_CONTROL_FUNCTION_MASK;
    } else {
        control &= !MSIX_CONTROL_FUNCTION_MASK;
    }
    write_config16(function, offset, control)
}

/// Enable or disable MSI-X for the function (MSI-X `msgctl` bit 15).
///
/// Only `msgctl` is touched; the table must already be programmed. This is a
/// config-space write, so it needs the function's ECAM page (enumeration done).
pub fn set_msix_enabled(
    function: &PciFunction,
    cap: &MsixCapability,
    enabled: bool,
) -> Result<(), &'static str> {
    let offset = cap.control_offset()?;
    let mut control = read_config16(function, offset)?;
    if enabled {
        control |= MSIX_CONTROL_ENABLE;
    } else {
        control &= !MSIX_CONTROL_ENABLE;
    }
    write_config16(function, offset, control)
}

/// Physical address of a BAR slice `[offset, offset + len)` (pure checks only).
fn bar_slice_phys(
    function: &PciFunction,
    bar_index: u8,
    offset: u32,
    len: usize,
) -> Result<u64, &'static str> {
    if len == 0 {
        return Err("pci-bar-empty-slice");
    }
    if len > MAX_BAR_SLICE {
        return Err("pci-bar-slice-too-large");
    }
    let base = bar_mmio_base(&function.bars, bar_index)?;
    base.checked_add(u64::from(offset))
        .ok_or("pci-bar-overflow")
}

/// Map `[offset, offset + len)` of memory BAR `bar_index` into the device window.
///
/// Drivers map the register block they drive, not the whole BAR: the unmapped
/// remainder stays outside the kernel address space, and each slice is capped at
/// [`MAX_BAR_SLICE`]. Returns the virtual address of the slice start.
pub fn map_bar_mmio(
    function: &PciFunction,
    bar_index: u8,
    offset: u32,
    len: usize,
) -> Result<u64, &'static str> {
    let phys = bar_slice_phys(function, bar_index, offset, len)?;
    map_net_mmio(phys, len)
}

fn init_locked() -> Result<usize, &'static str> {
    if is_pci_ready() {
        return Ok(pci_function_count());
    }

    let mcfg_phys = find_acpi_table(acpi::MCFG_SIG).map_err(|_| "pci-mcfg-missing")?;
    let (bytes, _info) = read_table(mcfg_phys, acpi::MCFG_SIG)?;
    let mcfg = acpi::parse_mcfg(bytes).map_err(acpi::AcpiError::as_str)?;

    // Seed the walk with every allocation's root bus. The advertised bus range
    // itself is *not* expanded: it may be the full 256 buses (OVMF/QEMU), and
    // unreachable bus numbers would only burn window pages. Bridges lead to the
    // buses that actually exist.
    let mut index = 0;
    while index < mcfg.count() {
        let entry = mcfg.entries()[index];
        push_bus(state(), (entry.segment, entry.start_bus))?;
        index += 1;
    }

    while let Some((segment, bus)) = pop_bus(state()) {
        if mark_visited(state(), (segment, bus))? {
            continue;
        }
        let entry = entry_for(&mcfg, segment, bus).ok_or("pci-bus-outside-mcfg")?;
        scan_bus(state(), &mcfg, bus, &entry)?;
    }

    let st = state();
    if st.count == 0 {
        return Err("pci-no-devices");
    }
    st.ready = true;
    Ok(st.count)
}

/// Visit every device on one bus; call `function` 0 first, then any other
/// function the header advertises, and enqueue bridge secondaries.
fn scan_bus(
    st: &mut State,
    mcfg: &acpi::Mcfg,
    bus: u8,
    entry: &acpi::McfgEntry,
) -> Result<(), &'static str> {
    let mut device = 0u8;
    while device < DEVICES_PER_BUS {
        if let Some(header) = probe(st, entry, bus, device, 0)? {
            let multifunction = header.multifunction;
            let bridge = header.bridge;
            let secondary_bus = header.secondary_bus;
            cache(st, header)?;
            if multifunction {
                let mut function = 1u8;
                while function < FUNCTIONS_PER_DEVICE {
                    if let Some(header) = probe(st, entry, bus, device, function)? {
                        cache(st, header)?;
                    }
                    function += 1;
                }
            }
            if bridge {
                let (segment, next) = bridge_bus(mcfg, entry.segment, secondary_bus)?;
                push_bus(st, (segment, next))?;
            }
        }
        device += 1;
    }
    Ok(())
}

/// Resolve the bus a bridge's secondary side lives on.
fn bridge_bus(
    mcfg: &acpi::Mcfg,
    segment: u16,
    secondary_bus: u8,
) -> Result<(u16, u8), &'static str> {
    // A bridge must point at a bus described by some MCFG allocation; a bridge
    // to nowhere is a firmware/table inconsistency, not something to skip.
    match entry_for(mcfg, segment, secondary_bus) {
        Some(entry) => {
            if entry.function_phys(secondary_bus, 0, 0).is_some() {
                Ok((segment, secondary_bus))
            } else {
                Err("pci-bridge-outside-mcfg")
            }
        }
        None => {
            // Some firmwares put the bridge's downstream bus in a different
            // allocation; accept it when any allocation covers that bus.
            let mut index = 0;
            while index < mcfg.count() {
                let candidate = mcfg.entries()[index];
                if candidate.function_phys(secondary_bus, 0, 0).is_some() {
                    return Ok((candidate.segment, secondary_bus));
                }
                index += 1;
            }
            Err("pci-bridge-outside-mcfg")
        }
    }
}

/// Find the allocation describing `segment`/`bus`.
fn entry_for(mcfg: &acpi::Mcfg, segment: u16, bus: u8) -> Option<acpi::McfgEntry> {
    let mut index = 0;
    while index < mcfg.count() {
        let entry = mcfg.entries()[index];
        if entry.segment == segment && bus >= entry.start_bus && bus <= entry.end_bus {
            return Some(entry);
        }
        index += 1;
    }
    None
}

/// Map one function's ECAM page, decode its header, and report absence as `None`.
fn probe(
    st: &mut State,
    entry: &acpi::McfgEntry,
    bus: u8,
    device: u8,
    function: u8,
) -> Result<Option<Header>, &'static str> {
    let phys = entry
        .function_phys(bus, device, function)
        .ok_or("pci-bad-function")?;
    if st.pages >= MAX_ECAM_PAGES {
        return Err("pci-window-quota");
    }
    let virt = reserve_page(st)?;
    // SAFETY: `virt` is page aligned and freshly reserved inside the PCI
    // window; the physical range is one architectural ECAM function page.
    let mapped =
        unsafe { vm::map_physical(virt, phys, FUNCTION_SPACE, DEVICE_FLAGS) }.map_err(map_error)?;
    if mapped != virt {
        return Err("pci-map-inconsistent");
    }
    st.pages += 1;

    let mut dwords = [0u32; HEADER_DWORDS];
    let mut offset = 0u8;
    for slot in dwords.iter_mut() {
        // SAFETY: each offset is 4-byte aligned and inside the mapped page.
        *slot = unsafe { read_volatile((virt + u64::from(offset)) as *const u32) };
        offset += 4;
    }
    if (dwords[0] as u16) == VENDOR_NONE {
        return Ok(None);
    }
    let mut header = decode_header(entry.segment, bus, device, function, &dwords);
    header.ecam = virt;
    Ok(Some(header))
}

/// Decode a 64-byte configuration header (pure; host-tested).
fn decode_header(
    segment: u16,
    bus: u8,
    device: u8,
    function: u8,
    dwords: &[u32; HEADER_DWORDS],
) -> Header {
    let vendor_device = dwords[(REG_VENDOR_DEVICE / 4) as usize];
    let revision_class = dwords[(REG_REVISION_CLASS / 4) as usize];
    let header_type = (dwords[(REG_HEADER_TYPE / 4) as usize] >> 16) as u8;
    let mut bars = [0u32; 6];
    let first_bar = (REG_BARS / 4) as usize;
    let mut index = 0;
    while index < bars.len() {
        bars[index] = dwords[first_bar + index];
        index += 1;
    }
    let secondary_bus = (dwords[(REG_SECONDARY_BUS / 4) as usize] >> 8) as u8;
    Header {
        function: PciFunction {
            segment,
            bus,
            device,
            function,
            vendor_id: vendor_device as u16,
            device_id: (vendor_device >> 16) as u16,
            class: (revision_class >> 24) as u8,
            subclass: (revision_class >> 16) as u8,
            prog_if: (revision_class >> 8) as u8,
            revision: revision_class as u8,
            bars,
        },
        multifunction: header_type & HEADER_TYPE_MULTIFUNCTION != 0,
        bridge: header_type & 0x7F == HEADER_TYPE_BRIDGE,
        secondary_bus,
        ecam: 0,
    }
}

/// Cache one enumerated function, refusing to silently drop the overflow.
fn cache(st: &mut State, header: Header) -> Result<(), &'static str> {
    if st.count >= MAX_FUNCTIONS {
        return Err("pci-function-quota");
    }
    st.functions[st.count] = header.function;
    st.ecam[st.count] = header.ecam;
    st.count += 1;
    Ok(())
}

/// Resolve the ECAM page of a function descriptor handed back by this module.
fn ecam_of(function: &PciFunction) -> Result<u64, &'static str> {
    resolve_ecam(state(), function)
}

/// Pure lookup rule: only descriptors produced by enumeration own a page.
fn resolve_ecam(st: &State, function: &PciFunction) -> Result<u64, &'static str> {
    if !st.ready {
        return Err("pci-not-initialised");
    }
    let mut index = 0;
    while index < st.count {
        if st.functions[index].same_function(function) {
            return Ok(st.ecam[index]);
        }
        index += 1;
    }
    Err("pci-not-enumerated")
}

/// Validate a configuration-space access: natural alignment and page bounds.
fn check_access(offset: u8, width: usize) -> Result<(), &'static str> {
    let start = offset as usize;
    if start % width != 0 {
        return Err("pci-bad-alignment");
    }
    if start + width > FUNCTION_SPACE as usize {
        return Err("pci-bad-offset");
    }
    Ok(())
}

/// Reserve the next page of the PCI window.
fn reserve_page(st: &mut State) -> Result<u64, &'static str> {
    let virt = st.next_virt;
    let next = virt.checked_add(PAGE).ok_or("pci-window-overflow")?;
    if next > PCI_WINDOW_BASE + PCI_WINDOW_LIMIT {
        return Err("pci-window-quota");
    }
    st.next_virt = next;
    Ok(virt)
}

fn push_bus(st: &mut State, bus: (u16, u8)) -> Result<(), &'static str> {
    if st.queue_tail >= MAX_BUSES {
        return Err("pci-bus-quota");
    }
    st.queue[st.queue_tail] = bus;
    st.queue_tail += 1;
    Ok(())
}

fn pop_bus(st: &mut State) -> Option<(u16, u8)> {
    if st.queue_head >= st.queue_tail {
        return None;
    }
    let bus = st.queue[st.queue_head];
    st.queue_head += 1;
    Some(bus)
}

/// Mark `bus` visited; returns `true` when it already was (bridge cycle).
fn mark_visited(st: &mut State, bus: (u16, u8)) -> Result<bool, &'static str> {
    let mut index = 0;
    while index < st.visited_count {
        if st.visited[index] == bus {
            return Ok(true);
        }
        index += 1;
    }
    if st.visited_count >= MAX_BUSES {
        return Err("pci-bus-quota");
    }
    st.visited[st.visited_count] = bus;
    st.visited_count += 1;
    Ok(false)
}

fn state() -> &'static mut State {
    // SAFETY: enumeration and every accessor run on the single CPU with
    // interrupts disabled during `init_pci`; afterwards the state is read-only
    // apart from the per-call `&mut` that is never held across a yield point.
    unsafe { &mut *addr_of_mut!(STATE) }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dwords_for(
        vendor: u16,
        device: u16,
        revision: u8,
        prog_if: u8,
        subclass: u8,
        class: u8,
        header_type: u8,
        secondary_bus: u8,
        bars: [u32; 6],
    ) -> [u32; HEADER_DWORDS] {
        let mut d = [0u32; HEADER_DWORDS];
        d[0] = u32::from(vendor) | (u32::from(device) << 16);
        d[2] = u32::from(revision)
            | (u32::from(prog_if) << 8)
            | (u32::from(subclass) << 16)
            | (u32::from(class) << 24);
        d[3] = u32::from(header_type) << 16;
        let mut index = 0;
        while index < 6 {
            d[4 + index] = bars[index];
            index += 1;
        }
        // For a bridge the dword at offset 0x18 holds the bus-number triplet
        // instead of BAR2, so the secondary bus is written after the BAR loop.
        d[6] = u32::from(secondary_bus) << 8;
        d
    }

    #[test]
    fn decodes_a_legacy_virtio_function() {
        // virtio-blk legacy id 0x1AF4:0x1001, class 0x010000 (storage/other),
        // I/O BAR0 and MMIO BAR1, single function, not a bridge.
        let d = dwords_for(
            0x1AF4,
            0x1001,
            0x00,
            0x00,
            0x00,
            0x01,
            0x00,
            0,
            [0xC001, 0xFEBD0000, 0, 0, 0, 0],
        );
        let header = decode_header(0, 0, 4, 0, &d);
        assert_eq!(header.function.vendor_id, 0x1AF4);
        assert_eq!(header.function.device_id, 0x1001);
        assert_eq!(header.function.class, 0x01);
        assert_eq!(header.function.subclass, 0x00);
        assert_eq!(header.function.prog_if, 0x00);
        assert_eq!(header.function.revision, 0x00);
        assert_eq!(header.function.bus, 0);
        assert_eq!(header.function.device, 4);
        assert_eq!(header.function.function, 0);
        assert_eq!(header.function.bars, [0xC001, 0xFEBD0000, 0, 0, 0, 0]);
        assert!(!header.multifunction);
        assert!(!header.bridge);
    }

    #[test]
    fn decodes_multifunction_and_bridge_headers() {
        // Multifunction bit is header-type bit 7, independent of the low bits.
        let d = dwords_for(0x8086, 0x1234, 1, 2, 3, 4, 0x80, 0, [0; 6]);
        let header = decode_header(2, 7, 31, 5, &d);
        assert!(header.multifunction);
        assert!(!header.bridge);
        assert_eq!(header.function.segment, 2);
        assert_eq!(header.function.bus, 7);
        assert_eq!(header.function.function, 5);

        // A PCI-to-PCI bridge advertises its secondary bus at offset 0x19.
        let d = dwords_for(0x1B36, 0x0002, 0, 0, 0, 0x06, 0x01, 9, [0; 6]);
        let header = decode_header(0, 0, 2, 0, &d);
        assert!(header.bridge);
        assert!(!header.multifunction);
        assert_eq!(header.function.class, 0x06);
        assert_eq!(header.secondary_bus, 9);
    }

    #[test]
    fn access_checks_require_natural_alignment() {
        // The registers a virtio driver needs: command (0x04), BAR0 (0x10),
        // subsystem ids (0x2E) - all naturally aligned at their width.
        assert_eq!(check_access(0x04, 2), Ok(()));
        assert_eq!(check_access(0x10, 4), Ok(()));
        assert_eq!(check_access(0x2E, 2), Ok(()));
        assert_eq!(check_access(0x2C, 4), Ok(()));

        // Unaligned offsets are refused rather than silently split.
        assert_eq!(check_access(0x05, 2), Err("pci-bad-alignment"));
        assert_eq!(check_access(0x12, 4), Err("pci-bad-alignment"));
        assert_eq!(check_access(0xFF, 4), Err("pci-bad-alignment"));
    }

    #[test]
    fn only_enumerated_functions_resolve_to_an_ecam_page() {
        // A descriptor that enumeration never produced is refused instead of
        // dereferencing a guessed address, and accessors refuse to run before
        // enumeration has happened at all.
        let forged = PciFunction {
            segment: 0,
            bus: 0,
            device: 9,
            function: 0,
            ..PciFunction::NONE
        };
        let mut st = State::EMPTY;
        assert_eq!(resolve_ecam(&st, &forged), Err("pci-not-initialised"));

        st.ready = true;
        assert_eq!(resolve_ecam(&st, &forged), Err("pci-not-enumerated"));

        // Once a function is cached its page is returned verbatim; vendor/device
        // and BARs are payload, not part of the lookup identity.
        let cached = PciFunction {
            segment: 0,
            bus: 0,
            device: 4,
            function: 0,
            vendor_id: 0x1AF4,
            ..PciFunction::NONE
        };
        st.functions[0] = cached;
        st.ecam[0] = PCI_WINDOW_BASE;
        st.count = 1;
        assert_eq!(resolve_ecam(&st, &cached), Ok(PCI_WINDOW_BASE));
        assert_eq!(resolve_ecam(&st, &forged), Err("pci-not-enumerated"));

        // The public accessors refuse unknown descriptors (the static state is
        // not initialised on the host).
        assert!(read_config16(&forged, 0x04).is_err());
        assert!(write_config32(&forged, 0x10, 0).is_err());
    }

    #[test]
    fn window_budget_stays_inside_the_pci_window() {
        // A fresh state starts at the window base and every reservation is one
        // page; the cap matches the window size so the reservation can never
        // leave the window even if the counter were bypassed.
        assert_eq!(State::EMPTY.next_virt, PCI_WINDOW_BASE);
        assert_eq!(State::EMPTY.pages, 0);
        assert!(MAX_ECAM_PAGES * PAGE <= PCI_WINDOW_LIMIT);
        assert_eq!(MAX_ECAM_PAGES * PAGE, 4 * 1024 * 1024);
        // The PCI window sits above the boot-module window and inside the
        // kernel-image 1 GiB PDPT.
        assert_eq!(PCI_WINDOW_BASE, 0xFFFF_FFFF_8400_0000);
        assert!(PCI_WINDOW_BASE + PCI_WINDOW_LIMIT <= 0xFFFF_FFFF_C000_0000);
    }

    #[test]
    fn find_pci_selects_by_instance_in_enumeration_order() {
        // Enumeration order is kept verbatim: two identical virtio disks first,
        // then an unrelated device. `instance` selects among the matches only.
        let mut functions = [PciFunction::NONE; 3];
        functions[0] = PciFunction {
            vendor_id: 0x1AF4,
            device_id: 0x1001,
            device: 4,
            ..PciFunction::NONE
        };
        functions[1] = PciFunction {
            vendor_id: 0x1AF4,
            device_id: 0x1001,
            device: 5,
            ..PciFunction::NONE
        };
        functions[2] = PciFunction {
            vendor_id: 0x8086,
            device_id: 0x1234,
            device: 6,
            ..PciFunction::NONE
        };
        assert_eq!(
            select_instance(&functions, 0x1AF4, 0x1001, 0).map(|f| f.device),
            Some(4)
        );
        assert_eq!(
            select_instance(&functions, 0x1AF4, 0x1001, 1).map(|f| f.device),
            Some(5)
        );
        assert!(select_instance(&functions, 0x1AF4, 0x1001, 2).is_none());
        assert!(select_instance(&functions, 0x1AF4, 0x1002, 0).is_none());
        assert_eq!(
            select_instance(&functions, 0x8086, 0x1234, 0).map(|f| f.device),
            Some(6)
        );
    }

    // --- MSI / MSI-X (M7c prerequisites) ---------------------------------

    /// One dword of a fake 256-byte configuration space.
    fn put(config: &mut [u32; 64], offset: u8, value: u32) {
        config[(offset / 4) as usize] = value;
    }

    fn read_fake(config: &[u32; 64], offset: u8) -> Result<u32, &'static str> {
        config
            .get((offset / 4) as usize)
            .copied()
            .ok_or("pci-bad-offset")
    }

    fn walk(config: &[u32; 64], status: u16, pointer: u8) -> Result<CapabilityWalk, &'static str> {
        walk_capabilities(status, pointer, |offset| read_fake(config, offset))
    }

    #[test]
    fn walks_a_multi_capability_list_and_decodes_msix() {
        // Capability list: MSI at 0x40 -> MSI-X at 0x60 -> end.
        let mut config = [0u32; 64];
        put(&mut config, 0x40, 0x05 | (0x60 << 8));
        put(&mut config, 0x60, 0x11 | (3u32 << 16));
        put(&mut config, 0x64, 0x3 | 0x1000);
        put(&mut config, 0x68, 0x3 | 0x2000);

        let walk = walk(&config, STATUS_CAP_LIST, 0x40).expect("well-formed list");
        assert_eq!(walk.msi_offset, Some(0x40));
        let msix = walk.msix.expect("MSI-X record decoded");
        assert_eq!(msix.cap_offset, 0x60);
        assert_eq!(msix.vectors, 4);
        assert_eq!(msix.table_bir, 3);
        assert_eq!(msix.table_offset, 0x1000);
        assert_eq!(msix.table_bytes, 4 * MSIX_ENTRY_BYTES);
        assert_eq!(msix.pba_bir, 3);
        assert_eq!(msix.pba_offset, 0x2000);
        assert!(!msix.function_mask);
        assert!(!msix.enabled);
    }

    #[test]
    fn decodes_the_msix_message_control_bits() {
        let mut config = [0u32; 64];
        let control = MSIX_CONTROL_ENABLE | MSIX_CONTROL_FUNCTION_MASK | 0x7FF;
        put(&mut config, 0x40, 0x11 | (u32::from(control) << 16));
        put(&mut config, 0x44, 0x1);
        put(&mut config, 0x48, 0x2);
        let walk = walk(&config, STATUS_CAP_LIST, 0x40).expect("well-formed list");
        let msix = walk.msix.expect("MSI-X record decoded");
        assert!(msix.enabled);
        assert!(msix.function_mask);
        assert_eq!(msix.vectors, MSIX_MAX_VECTORS);
        assert_eq!(
            msix.table_bytes,
            u64::from(MSIX_MAX_VECTORS) * MSIX_ENTRY_BYTES
        );
        assert_eq!(decode_msix_location(0x0000_1003), (3, 0x1000));
        assert_eq!(decode_msix_location(u32::MAX), (7, u32::MAX & !0x7));
    }

    #[test]
    fn a_function_without_the_capability_bit_has_an_empty_walk() {
        let config = [0u32; 64];
        // No status bit: no capabilities, and the pointer is irrelevant.
        assert_eq!(walk(&config, 0, 0x40), Ok(CapabilityWalk::default()));
        // Status bit set but the list holds only MSI: no MSI-X, not silence.
        let mut config = [0u32; 64];
        put(&mut config, 0x40, 0x05);
        let walk = walk(&config, STATUS_CAP_LIST, 0x40).expect("well-formed list");
        assert_eq!(walk.msi_offset, Some(0x40));
        assert_eq!(walk.msix, None);
    }

    #[test]
    fn refuses_capability_cycles_and_unaligned_or_header_pointers() {
        // 0x40 -> 0x60 -> 0x40 is a cycle, not a list to spin on.
        let mut config = [0u32; 64];
        put(&mut config, 0x40, 0x05 | (0x60 << 8));
        put(&mut config, 0x60, 0x11 | (0x40 << 8));
        assert_eq!(walk(&config, STATUS_CAP_LIST, 0x40), Err("pci-cap-cycle"));

        // A next pointer into the fixed 64-byte header is not a capability.
        let mut config = [0u32; 64];
        put(&mut config, 0x40, 0x05 | (0x20 << 8));
        assert_eq!(
            walk(&config, STATUS_CAP_LIST, 0x40),
            Err("pci-bad-cap-pointer")
        );

        // Non-dword-aligned next pointers are refused instead of rounded.
        let mut config = [0u32; 64];
        put(&mut config, 0x40, 0x05 | (0x62 << 8));
        assert_eq!(
            walk(&config, STATUS_CAP_LIST, 0x40),
            Err("pci-bad-cap-pointer")
        );

        // The head pointer itself may not point into the header either.
        let config = [0u32; 64];
        assert_eq!(
            walk(&config, STATUS_CAP_LIST, 0x3C),
            Err("pci-bad-cap-pointer")
        );
    }

    #[test]
    fn refuses_records_that_would_read_past_configuration_space() {
        // MSI-X at 0xF8 needs dwords at +4/+8, i.e. bytes up to 0x104.
        let mut config = [0u32; 64];
        put(&mut config, 0x40, 0x05 | (0xF8 << 8));
        assert_eq!(
            walk(&config, STATUS_CAP_LIST, 0x40),
            Err("pci-cap-truncated")
        );

        // 0xF4 is the last record that still fits all three dwords.
        let mut config = [0u32; 64];
        put(&mut config, 0x40, 0x05 | (0xF4 << 8));
        put(&mut config, 0xF4, 0x11 | (1u32 << 16));
        put(&mut config, 0xF8, 0x2);
        put(&mut config, 0xFC, 0x3);
        let walk = walk(&config, STATUS_CAP_LIST, 0x40).expect("last fitting record");
        assert_eq!(walk.msix.expect("decoded").vectors, 2);
    }

    #[test]
    fn bar_bases_merge_64_bit_bars_and_refuse_io_or_reserved_ones() {
        let mut bars = [0u32; 6];
        bars[0] = 0xFEBD_0000; // 32-bit memory BAR
        bars[1] = 0x1004; // 64-bit memory BAR: type 0b10, base low 0x1000
        bars[2] = 0x0000_0001; // its high dword
        assert_eq!(bar_mmio_base(&bars, 0), Ok(0xFEBD_0000));
        assert_eq!(bar_mmio_base(&bars, 1), Ok(0x1_0000_1000));
        // Index 2 is the high half of BAR1, not a BAR of its own: it reads back
        // as I/O space, which is exactly why the 64-bit merge must be tracked.
        assert_eq!(bar_mmio_base(&bars, 2), Err("pci-bar-io"));

        bars[3] = 0xC001; // I/O space
        assert_eq!(bar_mmio_base(&bars, 3), Err("pci-bar-io"));
        bars[4] = 0x0000_0002; // reserved memory type 0b01
        assert_eq!(bar_mmio_base(&bars, 4), Err("pci-bar-reserved-type"));
        bars[5] = 0x1004; // 64-bit BAR without its high dword
        assert_eq!(bar_mmio_base(&bars, 5), Err("pci-bar-truncated"));
        assert_eq!(bar_mmio_base(&bars, 6), Err("pci-bar-index"));
    }

    #[test]
    fn msix_table_address_follows_the_bar_and_the_slice_checks_are_loud() {
        let function = PciFunction {
            bars: [0, 0x1004, 0x0000_0001, 0, 0, 0],
            ..PciFunction::NONE
        };
        let cap = MsixCapability {
            cap_offset: 0x60,
            vectors: 8,
            table_bir: 1,
            table_offset: 0x2000,
            table_bytes: 8 * MSIX_ENTRY_BYTES,
            pba_bir: 2,
            pba_offset: 0x3000,
            function_mask: false,
            enabled: false,
        };
        assert_eq!(msix_table_phys(&function, &cap), Ok(0x1_0000_3000));

        // An I/O BAR cannot back the table.
        let mut io_bars = function;
        io_bars.bars[1] = 0xC001;
        assert_eq!(msix_table_phys(&io_bars, &cap), Err("pci-bar-io"));

        // A slice must be non-empty, bounded, and overflow-checked before any
        // mapping happens (so these run safely on the host).
        assert_eq!(
            bar_slice_phys(&function, 1, 0, 0),
            Err("pci-bar-empty-slice")
        );
        assert_eq!(
            bar_slice_phys(&function, 1, 0, MAX_BAR_SLICE + 1),
            Err("pci-bar-slice-too-large")
        );
        let mut high = function;
        high.bars[1] = 0xFFFF_FFF4;
        high.bars[2] = 0xFFFF_FFFF;
        assert_eq!(
            bar_slice_phys(&high, 1, 0x2000, 16),
            Err("pci-bar-overflow")
        );
        // Validated arguments pass the pure stage; the mapping itself needs the
        // takeover page tables and is not exercised on the host.
        assert_eq!(bar_slice_phys(&function, 1, 0x10, 16), Ok(0x1_0000_1010));
    }

    #[test]
    fn msix_vector_programming_validates_before_touching_mmio() {
        let function = PciFunction {
            bars: [0, 0x1004, 0x0000_0001, 0, 0, 0],
            ..PciFunction::NONE
        };
        let cap = MsixCapability {
            cap_offset: 0x60,
            vectors: 2,
            table_bir: 1,
            table_offset: 0,
            table_bytes: 2 * MSIX_ENTRY_BYTES,
            pba_bir: 1,
            pba_offset: 0x1000,
            function_mask: false,
            enabled: false,
        };
        // Vector 0 is the "no interrupt" encoding: refuse it.
        assert_eq!(
            configure_msix_vector(&function, &cap, 0, 0, 0),
            Err("pci-msix-bad-vector")
        );
        // Only entries inside the decoded table size are legal.
        assert_eq!(
            configure_msix_vector(&function, &cap, 2, 0x20, 0),
            Err("pci-msix-bad-entry")
        );
        // `map_msix_table` refuses a zero-sized table before mapping.
        let empty = MsixCapability {
            table_bytes: 0,
            vectors: 0,
            ..cap
        };
        assert_eq!(
            map_msix_table(&function, &empty),
            Err("pci-msix-bad-vector-count")
        );
        // An overflowing message-control offset is refused, not wrapped.
        let bad_offset = MsixCapability {
            cap_offset: 0xFF,
            ..cap
        };
        assert_eq!(
            set_msix_enabled(&function, &bad_offset, true),
            Err("pci-msix-truncated")
        );
        assert_eq!(
            set_msix_function_mask(&function, &bad_offset, true),
            Err("pci-msix-truncated")
        );
    }

    #[test]
    fn capability_and_config_accessors_are_loud_before_enumeration() {
        // The production state is not initialised on the host: the walk must
        // refuse instead of dereferencing a guessed ECAM address.
        let forged = PciFunction::NONE;
        assert!(capabilities(&forged).is_err());
        assert!(msix_capability(&forged).is_err());
    }
}
