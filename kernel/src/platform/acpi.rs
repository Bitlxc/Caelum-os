//! ACPI table discovery and validation (M3 platform layer).
//!
//! Deliberately free of kernel dependencies — no MMIO, no page mapping, no
//! logging, no `alloc`, no `unsafe` — so that every rule here is host-testable.
//! The caller maps the tables read-only and hands the bytes in.
//!
//! Scope: RSDP (v0/v1/v2) -> XSDT (preferred) or RSDT -> MADT. Every other
//! entry in the table set is skipped by length. There is no "assume q35"
//! fallback: a missing or inconsistent table is a hard error that the boot
//! path must report loudly (agents.md §6.1, PROJECT_PROGRESS M3 decision).
//!
//! All multi-byte fields are little-endian per the ACPI specification.

#![allow(dead_code)] // accessors used by later M3 stages (sched, input)

/// RSDP signature, including the trailing NUL byte.
pub const RSDP_SIG: [u8; 8] = *b"RSD PTR ";
/// Extended System Description Table signature.
pub const XSDT_SIG: [u8; 4] = *b"XSDT";
/// Root System Description Table signature (ACPI 1.0 only).
pub const RSDT_SIG: [u8; 4] = *b"RSDT";
/// Multiple APIC Description Table signature.
pub const MADT_SIG: [u8; 4] = *b"APIC";

/// ACPI 1.0 RSDP payload length (no extended fields).
pub const RSDP_V1_LEN: usize = 20;
/// ACPI 2.0+ RSDP payload length (adds XSDT address + extended checksum).
pub const RSDP_V2_LEN: usize = 36;
/// Common system description table header length.
pub const SDT_HEADER_LEN: usize = 36;
/// Upper bound on any single table we are willing to map and parse.
pub const MAX_TABLE_LEN: u32 = 64 * 1024;
/// Upper bound on MADT interrupt source overrides we retain.
pub const MAX_ISO: usize = 16;

/// Maximum number of processors the kernel tracks from the MADT.
///
/// Alias of [`crate::arch::MAX_CPUS`]: the ISA layer owns the number because it
/// sizes the per-CPU GDT/TSS/IST/GS slots; `platform` only carries it into the
/// MADT list. `platform` may depend on `arch`, the reverse direction is
/// forbidden. The table is also the hard bound on how many CPUs the SMP bring-up
/// may start: an enabled processor entry that would overflow it is rejected
/// loudly rather than silently dropped.
pub const MAX_CPUS: usize = crate::arch::MAX_CPUS;
/// PCI Express memory-mapped configuration space table signature.
pub const MCFG_SIG: [u8; 4] = *b"MCFG";
/// Bytes between the common table header and the first MCFG allocation entry.
pub const MCFG_RESERVED_LEN: usize = 8;
/// Size of one MCFG configuration-space allocation entry.
pub const MCFG_ENTRY_LEN: usize = 16;
/// Upper bound on MCFG allocation entries we retain.
pub const MAX_MCFG_ENTRIES: usize = 8;
/// Size of one PCI function's ECAM configuration space (architectural 4 KiB).
pub const ECAM_FUNCTION_LEN: u64 = 4096;
/// ECAM offset of one PCI function (a device holds eight functions).
pub const ECAM_FUNCTION_STRIDE: u64 = 1 << 12;
/// ECAM offset of one PCI device (a bus holds 32 devices).
pub const ECAM_DEVICE_STRIDE: u64 = 1 << 15;
/// ECAM offset of one PCI bus.
pub const ECAM_BUS_STRIDE: u64 = 1 << 20;

/// ACPI discovery/validation failure.
///
/// The variants are the *reason class* reported to the boot path; they are
/// stable enough to appear in `M3 apic FAIL: <reason>` diagnostics.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AcpiError {
    /// Buffer shorter than the structure it claims to hold.
    TooShort,
    /// Signature mismatch (RSDP/XSDT/RSDT/MADT).
    BadSignature,
    /// Wrapping byte sum is non-zero.
    BadChecksum,
    /// RSDP revision not understood.
    BadRevision,
    /// Length field inconsistent with the buffer or the protocol.
    BadLength,
    /// Physical address not aligned strongly enough for our access rules.
    BadAlignment,
    /// MADT sub-entry length/flag field inconsistent.
    BadMadtEntry,
    /// MADT advertised no usable local APIC.
    BadLapicAddr,
    /// MADT advertised no usable IO APIC (missing table is *not* assumed).
    BadIoApic,
    /// More interrupt source overrides than [`MAX_ISO`].
    TooManyIsos,
    /// More enabled processors than [`MAX_CPUS`].
    TooManyCpus,
    /// Index past the end of an entry array.
    OutOfRange,
    /// MCFG allocation entry is inconsistent (bus range, body length).
    BadMcfgEntry,
    /// MCFG ECAM base address is unusable (zero, misaligned, overflowing).
    BadMcfgAddress,
    /// More MCFG allocation entries than [`MAX_MCFG_ENTRIES`].
    TooManyMcfgEntries,
}

impl AcpiError {
    /// Short stable reason string for serial diagnostics.
    pub const fn as_str(self) -> &'static str {
        match self {
            AcpiError::TooShort => "acpi-too-short",
            AcpiError::BadSignature => "acpi-bad-signature",
            AcpiError::BadChecksum => "acpi-bad-checksum",
            AcpiError::BadRevision => "acpi-bad-revision",
            AcpiError::BadLength => "acpi-bad-length",
            AcpiError::BadAlignment => "acpi-bad-alignment",
            AcpiError::BadMadtEntry => "madt-bad-entry",
            AcpiError::BadLapicAddr => "madt-bad-lapic-address",
            AcpiError::BadIoApic => "madt-bad-ioapic",
            AcpiError::TooManyIsos => "madt-too-many-isos",
            AcpiError::TooManyCpus => "madt-too-many-cpus",
            AcpiError::OutOfRange => "acpi-out-of-range",
            AcpiError::BadMcfgEntry => "mcfg-bad-entry",
            AcpiError::BadMcfgAddress => "mcfg-bad-address",
            AcpiError::TooManyMcfgEntries => "mcfg-too-many-entries",
        }
    }
}

#[inline]
fn le_u16(b: &[u8], at: usize) -> u16 {
    u16::from_le_bytes([b[at], b[at + 1]])
}

#[inline]
fn le_u32(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]])
}

#[inline]
fn le_u64(b: &[u8], at: usize) -> u64 {
    u64::from_le_bytes([
        b[at],
        b[at + 1],
        b[at + 2],
        b[at + 3],
        b[at + 4],
        b[at + 5],
        b[at + 6],
        b[at + 7],
    ])
}

/// ACPI checksum rule: the byte sum over the covered range must be zero.
#[inline]
pub fn checksum_ok(bytes: &[u8]) -> bool {
    bytes.iter().fold(0u8, |acc, &b| acc.wrapping_add(b)) == 0
}

/// Validate the RSDP *physical* placement rule.
///
/// The 16-byte alignment in the ACPI specification is a *producer* obligation
/// that firmware does not always honour, and we cannot enforce it without
/// refusing to boot real firmware. The vendored OVMF (QEMU 11.1, `q35`) is one
/// such producer: it publishes a contiguous 56-byte (rev 1, rev 2) RSDP block
/// starting at a page boundary, and the ACPI 2.0 configuration-table entry
/// points at the rev-2 half, i.e. `0x0F77E014` (`% 16 == 4`). Both halves have
/// valid signatures and checksums; only the placement rule is violated. This
/// function is called exactly once, with the address the UEFI configuration
/// table (which is authoritative, not a scan candidate) provided, so the
/// relaxed rule below is scoped to that input rather than applied to ACPI
/// structures in general.
///
/// A dword-aligned base is the strongest property our byte-wise readers need,
/// and it still rejects NULL as well as odd / 2-byte-offset nonsense before any
/// page gets mapped. Signature, length and both checksums are validated
/// afterwards by [`parse_rsdp`] and are *not* relaxed.
pub fn check_rsdp_phys(phys: u64) -> Result<(), AcpiError> {
    if phys == 0 || phys % 4 != 0 {
        return Err(AcpiError::BadAlignment);
    }
    Ok(())
}

/// Parsed root pointer: the ACPI entry table the caller must follow next.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Rsdp {
    /// RSDP revision (0 = ACPI 1.0, 2 = ACPI 2.0+ with XSDT).
    pub revision: u8,
    /// RSDT physical address (valid for every revision).
    pub rsdt_phys: u64,
    /// XSDT physical address; 0 when the RSDP predates ACPI 2.0.
    pub xsdt_phys: u64,
}

/// Parse and fully validate an RSDP copied out of firmware memory.
///
/// `bytes` may be longer than the RSDP; only the declared range is covered by
/// the extended checksum.
pub fn parse_rsdp(bytes: &[u8]) -> Result<Rsdp, AcpiError> {
    if bytes.len() < RSDP_V1_LEN {
        return Err(AcpiError::TooShort);
    }
    if bytes[..8] != RSDP_SIG {
        return Err(AcpiError::BadSignature);
    }
    if !checksum_ok(&bytes[..RSDP_V1_LEN]) {
        return Err(AcpiError::BadChecksum);
    }
    let revision = bytes[15];
    let rsdt_phys = u64::from(le_u32(bytes, 16));
    if rsdt_phys == 0 {
        return Err(AcpiError::BadLength);
    }
    // Description tables live on a dword boundary; every read below is
    // byte-wise, so that is the alignment this parser needs. The vendored OVMF
    // is a live example of why an 8-byte rule would be wrong: its rev-2 RSDP
    // points at the RSDT at `0x0F77D074` (4-byte but not 8-byte aligned) and at
    // the XSDT at `0x0F77D0E8`; both tables are otherwise valid.
    if rsdt_phys % 4 != 0 {
        return Err(AcpiError::BadAlignment);
    }
    if revision == 0 {
        // ACPI 1.0: no extended fields, only the RSDT exists.
        return Ok(Rsdp {
            revision,
            rsdt_phys,
            xsdt_phys: 0,
        });
    }
    if revision != 2 {
        return Err(AcpiError::BadRevision);
    }
    if bytes.len() < RSDP_V2_LEN {
        return Err(AcpiError::TooShort);
    }
    let length = le_u32(bytes, 20) as usize;
    if length < RSDP_V2_LEN || length > bytes.len() || length > 1024 {
        return Err(AcpiError::BadLength);
    }
    if !checksum_ok(&bytes[..length]) {
        return Err(AcpiError::BadChecksum);
    }
    let xsdt_phys = le_u64(bytes, 24);
    if xsdt_phys == 0 {
        return Err(AcpiError::BadLength);
    }
    // Same dword rule as the RSDT pointer above (see the OVMF note there); the
    // firmware here happens to hand out an 8-byte aligned XSDT, but the parser
    // must not depend on that.
    if xsdt_phys % 4 != 0 {
        return Err(AcpiError::BadAlignment);
    }
    Ok(Rsdp {
        revision,
        rsdt_phys,
        xsdt_phys,
    })
}

/// Validated description-table header.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TableInfo {
    pub signature: [u8; 4],
    /// Declared table length including this header.
    pub length: u32,
    pub revision: u8,
}

/// Validate one system description table (signature, length, checksum).
pub fn validate_table(bytes: &[u8], expected: [u8; 4]) -> Result<TableInfo, AcpiError> {
    if bytes.len() < SDT_HEADER_LEN {
        return Err(AcpiError::TooShort);
    }
    if bytes[..4] != expected {
        return Err(AcpiError::BadSignature);
    }
    let length = le_u32(bytes, 4);
    if length < SDT_HEADER_LEN as u32 || length as usize > bytes.len() || length > MAX_TABLE_LEN {
        return Err(AcpiError::BadLength);
    }
    if !checksum_ok(&bytes[..length as usize]) {
        return Err(AcpiError::BadChecksum);
    }
    Ok(TableInfo {
        signature: expected,
        length,
        revision: bytes[8],
    })
}

/// Read the declared length of a description table from its header only.
///
/// The caller needs this *before* it can map the whole table (mapping is
/// permanent, so a table is mapped exactly once at its real size). Only the
/// signature and the length bounds are checked here; [`validate_table`] then
/// verifies the checksum over the complete table.
pub fn declared_table_length(bytes: &[u8], expected: [u8; 4]) -> Result<u32, AcpiError> {
    if bytes.len() < SDT_HEADER_LEN {
        return Err(AcpiError::TooShort);
    }
    if bytes[..4] != expected {
        return Err(AcpiError::BadSignature);
    }
    let length = le_u32(bytes, 4);
    if length < SDT_HEADER_LEN as u32 || length > MAX_TABLE_LEN {
        return Err(AcpiError::BadLength);
    }
    Ok(length)
}

/// Number of fixed-size entry slots in an XSDT/RSDT body.
pub fn entry_count(table: &TableInfo, entry_size: usize) -> Result<usize, AcpiError> {
    if entry_size == 0 || entry_size > 8 {
        return Err(AcpiError::BadLength);
    }
    let body = table.length as usize - SDT_HEADER_LEN;
    if body % entry_size != 0 {
        return Err(AcpiError::BadLength);
    }
    Ok(body / entry_size)
}

/// Read entry `index` of an XSDT (8-byte) or RSDT (4-byte) body as a physical
/// address. Rejects slots that are zero or not naturally aligned.
pub fn entry_at(
    bytes: &[u8],
    table: &TableInfo,
    index: usize,
    entry_size: usize,
) -> Result<u64, AcpiError> {
    let count = entry_count(table, entry_size)?;
    if index >= count {
        return Err(AcpiError::OutOfRange);
    }
    let at = SDT_HEADER_LEN + index * entry_size;
    if at + entry_size > bytes.len() {
        return Err(AcpiError::TooShort);
    }
    let value = match entry_size {
        4 => u64::from(le_u32(bytes, at)),
        8 => le_u64(bytes, at),
        _ => return Err(AcpiError::BadLength),
    };
    if value == 0 || value % entry_size as u64 != 0 {
        return Err(AcpiError::BadAlignment);
    }
    Ok(value)
}

/// One MCFG configuration-space allocation: the ECAM region of a PCI segment.
///
/// `base` is the physical address of bus `start_bus`' configuration space; the
/// region is contiguous, `(end_bus - start_bus + 1) * 1 MiB` bytes long, and
/// laid out bus -> device (32 KiB) -> function (4 KiB) per the PCI Express
/// specification.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct McfgEntry {
    /// Physical base of the ECAM region.
    pub base: u64,
    /// PCI segment group the region describes.
    pub segment: u16,
    /// First bus number covered by the region.
    pub start_bus: u8,
    /// Last bus number covered by the region.
    pub end_bus: u8,
}

impl McfgEntry {
    /// Number of buses covered by the allocation.
    pub const fn bus_count(&self) -> u32 {
        (self.end_bus - self.start_bus) as u32 + 1
    }

    /// Bytes the ECAM region spans.
    pub fn region_len(&self) -> Option<u64> {
        u64::from(self.bus_count()).checked_mul(ECAM_BUS_STRIDE)
    }

    /// Physical address of one function's 4 KiB configuration space.
    ///
    /// Returns `None` for a bus/device/function outside the allocation or for
    /// an address that would overflow, so callers never compute an address the
    /// table did not describe.
    pub fn function_phys(&self, bus: u8, device: u8, function: u8) -> Option<u64> {
        if bus < self.start_bus || bus > self.end_bus || device >= 32 || function >= 8 {
            return None;
        }
        let bus_offset = u64::from(bus - self.start_bus).checked_mul(ECAM_BUS_STRIDE)?;
        let device_offset = u64::from(device).checked_mul(ECAM_DEVICE_STRIDE)?;
        let function_offset = u64::from(function).checked_mul(ECAM_FUNCTION_STRIDE)?;
        self.base
            .checked_add(bus_offset)?
            .checked_add(device_offset)?
            .checked_add(function_offset)
    }
}

/// Validated MCFG body: the ECAM allocations of one or more segments.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Mcfg {
    entries: [McfgEntry; MAX_MCFG_ENTRIES],
    count: usize,
}

impl Mcfg {
    /// Allocations in table order.
    pub fn entries(&self) -> &[McfgEntry] {
        &self.entries[..self.count]
    }

    /// Number of allocations.
    pub const fn count(&self) -> usize {
        self.count
    }
}

/// Parse and validate a PCI Express MCFG table.
///
/// Rules enforced here (no firmware assumptions, no q35 fallback):
/// * signature, declared length, checksum ([`validate_table`]);
/// * the 8-byte reserved field after the header must be present;
/// * the allocation body must be a non-zero whole number of 16-byte entries,
///   and no more than [`MAX_MCFG_ENTRIES`];
/// * every ECAM base must be non-zero, 4 KiB aligned, describe a plausible
///   (`start_bus <= end_bus`) bus range, and the whole region must stay inside
///   the 64-bit physical address space.
pub fn parse_mcfg(bytes: &[u8]) -> Result<Mcfg, AcpiError> {
    let table = validate_table(bytes, MCFG_SIG)?;
    let body_start = SDT_HEADER_LEN + MCFG_RESERVED_LEN;
    let length = table.length as usize;
    if length < body_start {
        return Err(AcpiError::TooShort);
    }
    let body = length - body_start;
    if body % MCFG_ENTRY_LEN != 0 {
        return Err(AcpiError::BadMcfgEntry);
    }
    let count = body / MCFG_ENTRY_LEN;
    if count == 0 {
        return Err(AcpiError::BadMcfgEntry);
    }
    if count > MAX_MCFG_ENTRIES {
        return Err(AcpiError::TooManyMcfgEntries);
    }
    let empty = McfgEntry {
        base: 0,
        segment: 0,
        start_bus: 0,
        end_bus: 0,
    };
    let mut entries = [empty; MAX_MCFG_ENTRIES];
    for (index, slot) in entries.iter_mut().enumerate().take(count) {
        let at = body_start + index * MCFG_ENTRY_LEN;
        let base = le_u64(bytes, at);
        let segment = le_u16(bytes, at + 8);
        let start_bus = bytes[at + 10];
        let end_bus = bytes[at + 11];
        let entry = McfgEntry {
            base,
            segment,
            start_bus,
            end_bus,
        };
        if base == 0 || base % ECAM_FUNCTION_LEN != 0 {
            return Err(AcpiError::BadMcfgAddress);
        }
        if start_bus > end_bus {
            return Err(AcpiError::BadMcfgEntry);
        }
        // The whole described region must be representable; a table that
        // describes a truncated ECAM range is refused instead of being used
        // partially.
        if entry
            .region_len()
            .and_then(|len| base.checked_add(len))
            .is_none()
        {
            return Err(AcpiError::BadMcfgAddress);
        }
        *slot = entry;
    }
    Ok(Mcfg { entries, count })
}

/// One MADT interrupt source override (ISA IRQ -> GSI re-mapping).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IsoOverride {
    /// Source bus; 0 = ISA.
    pub bus: u8,
    /// Legacy IRQ being overridden.
    pub source_irq: u8,
    /// Global system interrupt it maps to.
    pub gsi: u32,
    /// `None` = "conforms to the bus default" (active high).
    pub active_low: Option<bool>,
    /// `None` = "conforms to the bus default" (edge triggered).
    pub level_triggered: Option<bool>,
}

/// One processor entry from the MADT (the fields the SMP bring-up needs).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CpuEntry {
    /// ACPI processor id (the identity the firmware/tables use).
    pub acpi_processor_id: u8,
    /// Local APIC id of this processor; used for INIT-SIPI-SIPI targeting.
    pub apic_id: u8,
    /// Whether the entry's "enabled" flag is set.
    pub enabled: bool,
}

impl CpuEntry {
    /// An empty, disabled placeholder (used for unused table slots).
    pub const NONE: CpuEntry = CpuEntry {
        acpi_processor_id: 0,
        apic_id: 0,
        enabled: false,
    };
}

/// The subset of MADT that M3 needs to bring up xAPIC, plus the processor list
/// M6b1 needs to start the application processors.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Madt {
    /// Local APIC MMIO base (physical); may be overridden by a type-4 entry.
    pub local_apic_phys: u64,
    /// `PCAT_COMPAT` flag: a dual-8259 setup is described.
    pub pcat_compat: bool,
    /// First IO APIC's hardware id.
    pub io_apic_id: u8,
    /// First IO APIC MMIO base (physical).
    pub io_apic_phys: u64,
    /// GSI number of the first IO APIC redirection entry.
    pub io_apic_gsi_base: u32,
    /// Number of processor local APIC entries (all, including disabled).
    pub lapic_count: u16,
    /// Number of local APICs whose "enabled" flag is set.
    pub enabled_cpus: u16,
    /// Processors described by type-0 entries, in table order (includes
    /// disabled processors; `cpu_count` is the number of valid slots).
    pub cpus: [CpuEntry; MAX_CPUS],
    /// Number of valid entries in [`Madt::cpus`].
    pub cpu_count: usize,
    pub isos: [IsoOverride; MAX_ISO],
    pub iso_count: usize,
}

impl Madt {
    /// The processor entries described by the table.
    pub fn cpus(&self) -> &[CpuEntry] {
        &self.cpus[..self.cpu_count]
    }

    /// Number of processors whose enabled flag is set.
    pub fn enabled_cpu_count(&self) -> usize {
        self.cpus().iter().filter(|cpu| cpu.enabled).count()
    }
}

/// Parse and validate a MADT (`APIC`) table.
///
/// Fails loudly when no usable local/IO APIC is described, or when any entry
/// overruns the table or uses reserved flag encodings.
pub fn parse_madt(bytes: &[u8]) -> Result<Madt, AcpiError> {
    let table = validate_table(bytes, MADT_SIG)?;
    let len = table.length as usize;
    if len < SDT_HEADER_LEN + 8 {
        return Err(AcpiError::BadLength);
    }
    let local_apic_phys = u64::from(le_u32(bytes, SDT_HEADER_LEN));
    if local_apic_phys == 0 || local_apic_phys % 4096 != 0 {
        return Err(AcpiError::BadLapicAddr);
    }
    let flags = le_u32(bytes, SDT_HEADER_LEN + 4);

    let mut madt = Madt {
        local_apic_phys,
        pcat_compat: flags & 1 != 0,
        io_apic_id: 0,
        io_apic_phys: 0,
        io_apic_gsi_base: 0,
        lapic_count: 0,
        enabled_cpus: 0,
        cpus: [CpuEntry::NONE; MAX_CPUS],
        cpu_count: 0,
        isos: [IsoOverride {
            bus: 0,
            source_irq: 0,
            gsi: 0,
            active_low: None,
            level_triggered: None,
        }; MAX_ISO],
        iso_count: 0,
    };
    let mut io_apic_found = false;

    // MADT entries start right after the header + local APIC address + flags.
    let mut off = SDT_HEADER_LEN + 8;
    while off < len {
        if off + 2 > len {
            return Err(AcpiError::BadMadtEntry);
        }
        let entry_type = bytes[off];
        let entry_len = bytes[off + 1] as usize;
        if entry_len < 2 || off + entry_len > len {
            return Err(AcpiError::BadMadtEntry);
        }
        match entry_type {
            // 0: Processor Local APIC.
            0 => {
                if entry_len < 8 {
                    return Err(AcpiError::BadMadtEntry);
                }
                madt.lapic_count = madt.lapic_count.saturating_add(1);
                let acpi_processor_id = bytes[off + 2];
                let apic_id = bytes[off + 3];
                let cpu_flags = le_u32(bytes, off + 4);
                let enabled = cpu_flags & 1 != 0;
                if madt.cpu_count >= MAX_CPUS {
                    // Only an enabled processor that would be dropped matters:
                    // disabled entries are irrelevant to the bring-up.
                    if enabled {
                        return Err(AcpiError::TooManyCpus);
                    }
                } else {
                    madt.cpus[madt.cpu_count] = CpuEntry {
                        acpi_processor_id,
                        apic_id,
                        enabled,
                    };
                    madt.cpu_count += 1;
                }
                if enabled {
                    madt.enabled_cpus = madt.enabled_cpus.saturating_add(1);
                }
            }
            // 1: IO APIC. M3 is single-IOAPIC; the first entry wins.
            1 => {
                if entry_len < 12 {
                    return Err(AcpiError::BadMadtEntry);
                }
                if !io_apic_found {
                    let id = bytes[off + 2];
                    let addr = u64::from(le_u32(bytes, off + 4));
                    let gsi_base = le_u32(bytes, off + 8);
                    if addr == 0 || addr % 4096 != 0 {
                        return Err(AcpiError::BadIoApic);
                    }
                    madt.io_apic_id = id;
                    madt.io_apic_phys = addr;
                    madt.io_apic_gsi_base = gsi_base;
                    io_apic_found = true;
                }
            }
            // 2: Interrupt Source Override.
            2 => {
                if entry_len < 10 {
                    return Err(AcpiError::BadMadtEntry);
                }
                if madt.iso_count >= MAX_ISO {
                    return Err(AcpiError::TooManyIsos);
                }
                let override_flags = le_u16(bytes, off + 8) & 0x0F;
                let active_low = match override_flags & 0b11 {
                    0 => None,
                    1 => Some(false), // active high
                    3 => Some(true),  // active low
                    _ => return Err(AcpiError::BadMadtEntry),
                };
                let level_triggered = match (override_flags >> 2) & 0b11 {
                    0 => None,
                    1 => Some(false), // edge
                    3 => Some(true),  // level
                    _ => return Err(AcpiError::BadMadtEntry),
                };
                madt.isos[madt.iso_count] = IsoOverride {
                    bus: bytes[off + 2],
                    source_irq: bytes[off + 3],
                    gsi: le_u32(bytes, off + 4),
                    active_low,
                    level_triggered,
                };
                madt.iso_count += 1;
            }
            // 4: Local APIC NMI. Irrelevant to the M3 xAPIC bring-up, and it
            // is the entry QEMU/OVMF ends its MADT with, so it has to be
            // skipped rather than treated as an error.
            4 => {}
            // 5: Local APIC address override (64-bit). Note the numbering:
            // ACPI puts the NMI structure at type 4 and the override at 5.
            5 => {
                if entry_len < 12 {
                    return Err(AcpiError::BadMadtEntry);
                }
                let addr = le_u64(bytes, off + 4);
                if addr == 0 || addr % 4096 != 0 {
                    return Err(AcpiError::BadLapicAddr);
                }
                madt.local_apic_phys = addr;
            }
            // Everything else (NMI sources, x2APIC, GICC, ...) is skipped by
            // length on purpose: M3 brings up xAPIC only.
            _ => {}
        }
        off += entry_len;
    }
    if off != len {
        return Err(AcpiError::BadMadtEntry);
    }
    if !io_apic_found {
        // No q35/legacy fallback: without the MADT IO APIC entry we cannot
        // route the keyboard/serial GSIs, so M3 must refuse to start.
        return Err(AcpiError::BadIoApic);
    }
    if madt.enabled_cpus == 0 {
        return Err(AcpiError::BadLapicAddr);
    }
    Ok(madt)
}

/// Resolved routing for one legacy ISA IRQ.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Route {
    pub gsi: u32,
    pub active_low: bool,
    pub level_triggered: bool,
}

/// Bus default for an ISA IRQ: identity GSI, active high, edge triggered.
pub const fn isa_default_route(irq: u8) -> Route {
    Route {
        gsi: irq as u32,
        active_low: false,
        level_triggered: false,
    }
}

/// Resolve an ISA IRQ to its GSI and electrical properties, applying the
/// first matching MADT interrupt source override on bus 0.
pub fn route_isa_irq(madt: &Madt, irq: u8) -> Route {
    let mut route = isa_default_route(irq);
    let mut i = 0;
    while i < madt.iso_count {
        let iso = madt.isos[i];
        if iso.bus == 0 && iso.source_irq == irq {
            route.gsi = iso.gsi;
            if let Some(v) = iso.active_low {
                route.active_low = v;
            }
            if let Some(v) = iso.level_triggered {
                route.level_triggered = v;
            }
            break;
        }
        i += 1;
    }
    route
}

// ---------------------------------------------------------------------------
// Host tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Zero-fill a buffer and fix up a table checksum in place.
    fn fix_checksum(buf: &mut [u8], len: usize) {
        buf[9] = 0;
        let sum = buf[..len].iter().fold(0u8, |acc, &b| acc.wrapping_add(b));
        buf[9] = 0u8.wrapping_sub(sum);
        assert!(checksum_ok(&buf[..len]));
    }

    fn build_rsdp_v2(buf: &mut [u8], rsdt: u32, xsdt: u64) -> usize {
        buf[..8].copy_from_slice(&RSDP_SIG);
        buf[8..15].copy_from_slice(b"CAELUM ");
        buf[15] = 2;
        buf[16..20].copy_from_slice(&rsdt.to_le_bytes());
        buf[20..24].copy_from_slice(&(RSDP_V2_LEN as u32).to_le_bytes());
        buf[24..32].copy_from_slice(&xsdt.to_le_bytes());
        buf[32] = 0; // extended checksum
        buf[33..36].copy_from_slice(&[0, 0, 0]);
        // Legacy checksum covers the first 20 bytes.
        buf[8] = 0;
        let sum = buf[..RSDP_V1_LEN]
            .iter()
            .fold(0u8, |acc, &b| acc.wrapping_add(b));
        buf[8] = 0u8.wrapping_sub(sum);
        // Extended checksum covers the declared length.
        buf[32] = 0;
        let sum = buf[..RSDP_V2_LEN]
            .iter()
            .fold(0u8, |acc, &b| acc.wrapping_add(b));
        buf[32] = 0u8.wrapping_sub(sum);
        RSDP_V2_LEN
    }

    fn build_sdt(buf: &mut [u8], sig: [u8; 4], len: usize) -> usize {
        buf[..4].copy_from_slice(&sig);
        buf[4..8].copy_from_slice(&(len as u32).to_le_bytes());
        buf[8] = 2;
        fix_checksum(buf, len);
        len
    }

    fn build_madt(buf: &mut [u8]) -> usize {
        // Header + local APIC address + flags.
        let mut off = SDT_HEADER_LEN + 8;
        // Type 0: BSP, enabled.
        buf[off] = 0;
        buf[off + 1] = 8;
        buf[off + 2] = 0;
        buf[off + 3] = 0;
        buf[off + 4..off + 8].copy_from_slice(&1u32.to_le_bytes());
        off += 8;
        // Type 0: AP, disabled.
        buf[off] = 0;
        buf[off + 1] = 8;
        buf[off + 2] = 1;
        buf[off + 3] = 0;
        buf[off + 4..off + 8].copy_from_slice(&0u32.to_le_bytes());
        off += 8;
        // Type 1: IO APIC @ 0xFEC00000, GSI base 0, id 0.
        buf[off] = 1;
        buf[off + 1] = 12;
        buf[off + 2] = 0;
        buf[off + 4..off + 8].copy_from_slice(&0xFEC0_0000u32.to_le_bytes());
        buf[off + 8..off + 12].copy_from_slice(&0u32.to_le_bytes());
        off += 12;
        let len = off;
        buf[SDT_HEADER_LEN..SDT_HEADER_LEN + 4].copy_from_slice(&0xFEE0_0000u32.to_le_bytes());
        buf[SDT_HEADER_LEN + 4..SDT_HEADER_LEN + 8].copy_from_slice(&1u32.to_le_bytes());
        build_sdt(buf, MADT_SIG, len)
    }

    #[test]
    fn rsdp_v2_roundtrip() {
        let mut buf = [0u8; 64];
        build_rsdp_v2(&mut buf, 0x1234_5000, 0x1234_6000);
        let rsdp = parse_rsdp(&buf).unwrap();
        assert_eq!(rsdp.revision, 2);
        assert_eq!(rsdp.rsdt_phys, 0x1234_5000);
        assert_eq!(rsdp.xsdt_phys, 0x1234_6000);
    }

    #[test]
    fn rsdp_v1_has_no_xsdt() {
        let mut buf = [0u8; 64];
        build_rsdp_v2(&mut buf, 0x1234_5000, 0x1234_6000);
        // Rewrite as ACPI 1.0: revision 0, legacy checksum only.
        buf[15] = 0;
        buf[8] = 0;
        let sum = buf[..RSDP_V1_LEN]
            .iter()
            .fold(0u8, |acc, &b| acc.wrapping_add(b));
        buf[8] = 0u8.wrapping_sub(sum);
        let rsdp = parse_rsdp(&buf).unwrap();
        assert_eq!(rsdp.revision, 0);
        assert_eq!(rsdp.xsdt_phys, 0);
    }

    #[test]
    fn rsdp_rejects_corruption() {
        let mut buf = [0u8; 64];
        build_rsdp_v2(&mut buf, 0x1234_5000, 0x1234_6000);
        let mut bad = buf;
        bad[9] ^= 0xFF; // OEMID byte: breaks the legacy checksum
        assert_eq!(parse_rsdp(&bad), Err(AcpiError::BadChecksum));

        let mut bad = buf;
        bad[..8].copy_from_slice(b"RSD PTRX");
        assert_eq!(parse_rsdp(&bad), Err(AcpiError::BadSignature));
        assert_eq!(parse_rsdp(&buf[..8]), Err(AcpiError::TooShort));
    }

    #[test]
    fn table_entry_bounds_are_checked() {
        let mut buf = [0u8; 128];
        let len = 36 + 8 + 4; // two 8-byte slots would need 52; make it 48
        let len = len; // 48: body 12 -> not a multiple of 8
        let len = build_sdt(&mut buf, XSDT_SIG, len);
        let table = validate_table(&buf, XSDT_SIG).unwrap();
        assert_eq!(table.length as usize, len);
        assert_eq!(entry_count(&table, 8), Err(AcpiError::BadLength));

        // Now a well-formed XSDT with two aligned entries.
        let mut buf = [0u8; 128];
        let len = 36 + 16;
        buf[36..44].copy_from_slice(&0x1000_0000u64.to_le_bytes());
        buf[44..52].copy_from_slice(&0x2000_0000u64.to_le_bytes());
        build_sdt(&mut buf, XSDT_SIG, len);
        let table = validate_table(&buf, XSDT_SIG).unwrap();
        assert_eq!(entry_count(&table, 8), Ok(2));
        assert_eq!(entry_at(&buf, &table, 0, 8), Ok(0x1000_0000));
        assert_eq!(entry_at(&buf, &table, 1, 8), Ok(0x2000_0000));
        assert_eq!(entry_at(&buf, &table, 2, 8), Err(AcpiError::OutOfRange));
        // Zero / misaligned slots are rejected rather than followed.
        buf[36..44].copy_from_slice(&0u64.to_le_bytes());
        assert_eq!(entry_at(&buf, &table, 0, 8), Err(AcpiError::BadAlignment));
        buf[36..44].copy_from_slice(&0x1000_0004u64.to_le_bytes());
        assert_eq!(entry_at(&buf, &table, 0, 8), Err(AcpiError::BadAlignment));
    }

    #[test]
    fn rsdp_phys_accepts_firmware_dword_placement() {
        // The vendored OVMF publishes its ACPI 2.0 RSDP at 0x0F77E014, i.e. at a
        // dword but *not* 16-byte boundary. That must be accepted; the content
        // checks in parse_rsdp are what actually validate it.
        assert_eq!(check_rsdp_phys(0x0F77_E014), Ok(()));
        assert_eq!(check_rsdp_phys(0x0F77_E000), Ok(()));
        // NULL and non-dword bases are still rejected before anything is mapped.
        assert_eq!(check_rsdp_phys(0), Err(AcpiError::BadAlignment));
        assert_eq!(check_rsdp_phys(0x0F77_E001), Err(AcpiError::BadAlignment));
        assert_eq!(check_rsdp_phys(0x0F77_E002), Err(AcpiError::BadAlignment));
        assert_eq!(check_rsdp_phys(0x0F77_E006), Err(AcpiError::BadAlignment));
    }

    #[test]
    fn root_pointers_must_be_dword_aligned() {
        // Real OVMF values: RSDT is only 4-byte aligned; XSDT is 8-byte aligned.
        let mut buf = [0u8; 64];
        build_rsdp_v2(&mut buf, 0x0F77_D074, 0x0F77_D0E8);
        let rsdp = parse_rsdp(&buf).unwrap();
        assert_eq!(rsdp.rsdt_phys, 0x0F77_D074);
        assert_eq!(rsdp.xsdt_phys, 0x0F77_D0E8);
        assert_eq!(rsdp.revision, 2);

        // 2-byte offsets are rejected: the check is kept, just at dword width.
        let mut bad = [0u8; 64];
        build_rsdp_v2(&mut bad, 0x0F77_D076, 0x0F77_D0E8);
        assert_eq!(parse_rsdp(&bad), Err(AcpiError::BadAlignment));

        let mut bad = [0u8; 64];
        build_rsdp_v2(&mut bad, 0x0F77_D074, 0x0F77_D0EA);
        assert_eq!(parse_rsdp(&bad), Err(AcpiError::BadAlignment));

        // A zero root pointer stays a length error, as before.
        let mut bad = [0u8; 64];
        build_rsdp_v2(&mut bad, 0, 0x0F77_D0E8);
        assert_eq!(parse_rsdp(&bad), Err(AcpiError::BadLength));
    }

    /// Regression for the first real-hardware (vendored OVMF) boot failure.
    ///
    /// Reproduces the exact blob OVMF builds below 4 GiB: a rev-1 and a rev-2
    /// RSDP back to back starting at a page boundary, the ACPI 2.0 pointer at
    /// `+0x14` (16-byte rule violated, dword rule honoured), a dword-only
    /// aligned RSDT at `+0x74`, an 8-byte aligned XSDT at `+0xE8`, and
    /// page-aligned description tables. Before the alignment fix this failed at
    /// the very first `check_rsdp_phys` call with `acpi-bad-alignment`.
    #[test]
    fn ovmf_rsdp_blob_layout_parses_end_to_end() {
        const BASE: u64 = 0x0F76_0000;
        const RSDP_V2_OFF: usize = 0x14;
        const RSDT_OFF: usize = 0x74;
        const XSDT_OFF: usize = 0xE8;
        const FACP_OFF: usize = 0x1000;
        const MADT_OFF: usize = 0x2000;

        let mut blob = [0u8; 0x2200];

        // rev-1 RSDP at 0x0F760000 pointing at the 16-byte aligned RSDT copy.
        blob[..8].copy_from_slice(&RSDP_SIG);
        blob[9..15].copy_from_slice(b"Bochs ");
        blob[15] = 0;
        blob[16..20].copy_from_slice(&((BASE + 0xD000) as u32).to_le_bytes());
        blob[8] = 0;
        let sum = blob[..RSDP_V1_LEN]
            .iter()
            .fold(0u8, |acc, &b| acc.wrapping_add(b));
        blob[8] = 0u8.wrapping_sub(sum);

        // rev-2 RSDP at +0x14 pointing at the dword-only aligned RSDT.
        build_rsdp_v2(
            &mut blob[RSDP_V2_OFF..RSDP_V2_OFF + RSDP_V2_LEN],
            (BASE + RSDT_OFF as u64) as u32,
            BASE + XSDT_OFF as u64,
        );

        // RSDT (4-byte entries) and XSDT (8-byte entries) reach the same tables.
        let rsdt_off = RSDT_OFF;
        blob[rsdt_off + 36..rsdt_off + 40]
            .copy_from_slice(&((BASE + FACP_OFF as u64) as u32).to_le_bytes());
        blob[rsdt_off + 40..rsdt_off + 44]
            .copy_from_slice(&((BASE + MADT_OFF as u64) as u32).to_le_bytes());
        build_sdt(&mut blob[rsdt_off..], RSDT_SIG, 36 + 8);

        let xsdt_off = XSDT_OFF;
        blob[xsdt_off + 36..xsdt_off + 44].copy_from_slice(&(BASE + FACP_OFF as u64).to_le_bytes());
        blob[xsdt_off + 44..xsdt_off + 52].copy_from_slice(&(BASE + MADT_OFF as u64).to_le_bytes());
        build_sdt(&mut blob[xsdt_off..], XSDT_SIG, 36 + 16);

        // Minimal FACP (never parsed, only walked past by signature).
        build_sdt(&mut blob[FACP_OFF..], *b"FACP", SDT_HEADER_LEN);
        // Real MADT shape: one enabled BSP + one IO APIC.
        let madt_len = build_madt(&mut blob[MADT_OFF..]);

        // 1) The firmware-provided RSDP address must pass the placement rule.
        let rsdp_phys = BASE + RSDP_V2_OFF as u64;
        assert_eq!(rsdp_phys % 16, 4, "regression fixture must mirror OVMF");
        check_rsdp_phys(rsdp_phys).unwrap();

        // 2) Root pointer: dword-aligned RSDT is accepted.
        let rsdp = parse_rsdp(&blob[RSDP_V2_OFF..]).unwrap();
        assert_eq!(rsdp.revision, 2);
        assert_eq!(rsdp.rsdt_phys, BASE + RSDT_OFF as u64);
        assert_eq!(rsdp.xsdt_phys, BASE + XSDT_OFF as u64);

        // 3) XSDT entries lead to the page-aligned tables.
        let xsdt = validate_table(&blob[XSDT_OFF..], XSDT_SIG).unwrap();
        assert_eq!(entry_count(&xsdt, 8).unwrap(), 2);
        assert_eq!(
            entry_at(&blob[XSDT_OFF..], &xsdt, 0, 8),
            Ok(BASE + FACP_OFF as u64)
        );
        assert_eq!(
            entry_at(&blob[XSDT_OFF..], &xsdt, 1, 8),
            Ok(BASE + MADT_OFF as u64)
        );

        // 4) RSDT (the dword-only aligned copy) is equally walkable.
        let rsdt = validate_table(&blob[RSDT_OFF..], RSDT_SIG).unwrap();
        assert_eq!(entry_count(&rsdt, 4).unwrap(), 2);
        assert_eq!(
            entry_at(&blob[RSDT_OFF..], &rsdt, 1, 4),
            Ok(BASE + MADT_OFF as u64)
        );

        // 5) Walking each XSDT entry by signature header finds the MADT, and the
        //    MADT parses down to the xAPIC base the M3 bring-up needs.
        let madt_bytes = &blob[MADT_OFF..];
        assert_eq!(
            declared_table_length(madt_bytes, MADT_SIG),
            Ok(madt_len as u32)
        );
        let madt = parse_madt(madt_bytes).unwrap();
        assert_eq!(madt.local_apic_phys, 0xFEE0_0000);
        assert_eq!(madt.io_apic_phys, 0xFEC0_0000);
        assert_eq!(madt.enabled_cpus, 1);
    }

    #[test]
    fn declared_length_is_available_from_header_only() {
        let mut buf = [0u8; 256];
        let len = build_madt(&mut buf) as u32;
        // Only the 36-byte header is available at this point.
        assert_eq!(
            declared_table_length(&buf[..SDT_HEADER_LEN], MADT_SIG),
            Ok(len)
        );
        assert_eq!(
            declared_table_length(&buf[..SDT_HEADER_LEN], XSDT_SIG),
            Err(AcpiError::BadSignature)
        );
        assert_eq!(
            declared_table_length(&buf[..8], MADT_SIG),
            Err(AcpiError::TooShort)
        );
    }

    #[test]
    fn madt_core_tables() {
        let mut buf = [0u8; 256];
        let len = build_madt(&mut buf);
        let madt = parse_madt(&buf).unwrap();
        assert_eq!(madt.local_apic_phys, 0xFEE0_0000);
        assert_eq!(madt.io_apic_phys, 0xFEC0_0000);
        assert_eq!(madt.io_apic_gsi_base, 0);
        assert_eq!(madt.lapic_count, 2);
        assert_eq!(madt.enabled_cpus, 1);
        // The processor list keeps both type-0 entries, in table order.
        assert_eq!(madt.cpu_count, 2);
        assert_eq!(
            madt.cpus(),
            &[
                CpuEntry {
                    acpi_processor_id: 0,
                    apic_id: 0,
                    enabled: true,
                },
                CpuEntry {
                    acpi_processor_id: 1,
                    apic_id: 0,
                    enabled: false,
                },
            ]
        );
        assert_eq!(madt.enabled_cpu_count(), 1);
        assert!(madt.pcat_compat);
        assert_eq!(madt.iso_count, 0);
        // No overrides: ISA identity routing.
        assert_eq!(route_isa_irq(&madt, 1), isa_default_route(1));
        assert_eq!(route_isa_irq(&madt, 4).gsi, 4);
        assert_eq!(len, madt_len_for_check(&buf));
    }

    /// Sanity: the table length we built is what `validate_table` reports.
    fn madt_len_for_check(buf: &[u8]) -> usize {
        validate_table(buf, MADT_SIG).unwrap().length as usize
    }

    #[test]
    fn madt_rejects_more_enabled_cpus_than_the_table_holds() {
        let mut buf = [0u8; 256];
        let mut off = SDT_HEADER_LEN + 8;
        // One enabled processor too many: the table can hold MAX_CPUS, so the
        // (MAX_CPUS + 1)-th enabled entry must be a loud error, not a silent
        // truncation that would leave a CPU permanently offline.
        for cpu in 0..MAX_CPUS + 1 {
            buf[off] = 0;
            buf[off + 1] = 8;
            buf[off + 2] = cpu as u8;
            buf[off + 3] = cpu as u8;
            buf[off + 4..off + 8].copy_from_slice(&1u32.to_le_bytes());
            off += 8;
        }
        // The IO APIC entry keeps the "usable IO APIC" requirement satisfied.
        buf[off] = 1;
        buf[off + 1] = 12;
        buf[off + 4..off + 8].copy_from_slice(&0xFEC0_0000u32.to_le_bytes());
        off += 12;
        let len = off;
        buf[SDT_HEADER_LEN..SDT_HEADER_LEN + 4].copy_from_slice(&0xFEE0_0000u32.to_le_bytes());
        buf[SDT_HEADER_LEN + 4..SDT_HEADER_LEN + 8].copy_from_slice(&1u32.to_le_bytes());
        build_sdt(&mut buf, MADT_SIG, len);
        assert_eq!(parse_madt(&buf), Err(AcpiError::TooManyCpus));
    }

    #[test]
    fn madt_iso_overrides_irq1_and_irq4() {
        let mut buf = [0u8; 256];
        let mut len = build_madt(&mut buf);
        // Two ISOs: IRQ1 -> GSI1 active-low level (flags 0x000F),
        //           IRQ4 -> GSI4 active-high edge (flags 0x0001).
        buf[len] = 2;
        buf[len + 1] = 10;
        buf[len + 2] = 0; // bus 0
        buf[len + 3] = 1; // source IRQ 1
        buf[len + 4..len + 8].copy_from_slice(&1u32.to_le_bytes()); // GSI 1
        buf[len + 8..len + 10].copy_from_slice(&0x000Fu16.to_le_bytes());
        len += 10;
        buf[len] = 2;
        buf[len + 1] = 10;
        buf[len + 2] = 0;
        buf[len + 3] = 4;
        buf[len + 4..len + 8].copy_from_slice(&4u32.to_le_bytes());
        buf[len + 8..len + 10].copy_from_slice(&0x0001u16.to_le_bytes());
        len += 10;
        build_sdt(&mut buf, MADT_SIG, len);

        let madt = parse_madt(&buf).unwrap();
        assert_eq!(madt.iso_count, 2);
        assert_eq!(
            route_isa_irq(&madt, 1),
            Route {
                gsi: 1,
                active_low: true,
                level_triggered: true
            }
        );
        assert_eq!(
            route_isa_irq(&madt, 4),
            Route {
                gsi: 4,
                active_low: false,
                level_triggered: false
            }
        );
        // A non-overridden IRQ keeps the bus default.
        assert_eq!(route_isa_irq(&madt, 12), isa_default_route(12));
    }

    #[test]
    fn madt_lapic_address_override() {
        let mut buf = [0u8; 256];
        let mut len = build_madt(&mut buf);
        // Type 5: local APIC address override to 0xFEE0_1000 (12-byte entry).
        buf[len] = 5;
        buf[len + 1] = 12;
        buf[len + 2] = 0;
        buf[len + 3] = 0;
        buf[len + 4..len + 12].copy_from_slice(&0xFEE0_1000u64.to_le_bytes());
        len += 12;
        build_sdt(&mut buf, MADT_SIG, len);
        let madt = parse_madt(&buf).unwrap();
        assert_eq!(madt.local_apic_phys, 0xFEE0_1000);
    }

    #[test]
    fn madt_skips_the_local_apic_nmi_tail_qemu_emits() {
        // Real QEMU/OVMF MADTs end with `04 06 ff 00 00 01`: type 4 is the
        // Local APIC NMI structure (6 bytes), not the address override, so it
        // must be skipped by length instead of failing the whole bring-up.
        let mut buf = [0u8; 256];
        let mut len = build_madt(&mut buf);
        buf[len] = 4;
        buf[len + 1] = 6;
        buf[len + 2] = 0xFF; // ACPI processor UID: all processors
        buf[len + 3] = 0;
        buf[len + 4] = 0;
        buf[len + 5] = 1; // LINT1
        len += 6;
        build_sdt(&mut buf, MADT_SIG, len);
        let madt = parse_madt(&buf).unwrap();
        assert_eq!(madt.local_apic_phys, 0xFEE0_0000);
        assert_eq!(madt.io_apic_phys, 0xFEC0_0000);
        assert_eq!(madt.enabled_cpus, 1);
    }

    #[test]
    fn madt_requires_io_apic_and_valid_entries() {
        // Build a MADT with the IO APIC entry removed entirely.
        let mut buf = [0u8; 256];
        let mut len = SDT_HEADER_LEN + 8;
        buf[len] = 0;
        buf[len + 1] = 8;
        buf[len + 4..len + 8].copy_from_slice(&1u32.to_le_bytes());
        len += 8;
        buf[SDT_HEADER_LEN..SDT_HEADER_LEN + 4].copy_from_slice(&0xFEE0_0000u32.to_le_bytes());
        build_sdt(&mut buf, MADT_SIG, len);
        assert_eq!(parse_madt(&buf), Err(AcpiError::BadIoApic));

        // An entry that overruns the table must be rejected, not truncated.
        let mut buf = [0u8; 256];
        let mut len = build_madt(&mut buf);
        buf[len] = 2;
        buf[len + 1] = 200; // claims far more than remains
        len += 2;
        build_sdt(&mut buf, MADT_SIG, len);
        assert_eq!(parse_madt(&buf), Err(AcpiError::BadMadtEntry));

        // Reserved polarity/trigger encodings are an error, not "conform".
        let mut buf = [0u8; 256];
        let mut len = build_madt(&mut buf);
        buf[len] = 2;
        buf[len + 1] = 10;
        buf[len + 2] = 0;
        buf[len + 3] = 1;
        buf[len + 4..len + 8].copy_from_slice(&1u32.to_le_bytes());
        buf[len + 8..len + 10].copy_from_slice(&0x0002u16.to_le_bytes()); // reserved polarity
        len += 10;
        build_sdt(&mut buf, MADT_SIG, len);
        assert_eq!(parse_madt(&buf), Err(AcpiError::BadMadtEntry));
    }

    #[test]
    fn madt_rejects_bad_signature_and_checksum() {
        let mut buf = [0u8; 256];
        let len = build_madt(&mut buf);
        assert_eq!(
            validate_table(&buf[..len], XSDT_SIG),
            Err(AcpiError::BadSignature)
        );
        let mut bad = buf;
        bad[9] = bad[9].wrapping_add(1);
        assert_eq!(parse_madt(&bad[..len]), Err(AcpiError::BadChecksum));
    }

    /// Lay out an MCFG table with the given `(base, segment, start, end)` rows.
    fn build_mcfg(buf: &mut [u8], rows: &[(u64, u16, u8, u8)]) -> usize {
        let mut len = SDT_HEADER_LEN + MCFG_RESERVED_LEN;
        for (index, &(base, segment, start_bus, end_bus)) in rows.iter().enumerate() {
            let at = SDT_HEADER_LEN + MCFG_RESERVED_LEN + index * MCFG_ENTRY_LEN;
            buf[at..at + 8].copy_from_slice(&base.to_le_bytes());
            buf[at + 8..at + 10].copy_from_slice(&segment.to_le_bytes());
            buf[at + 10] = start_bus;
            buf[at + 11] = end_bus;
            len += MCFG_ENTRY_LEN;
        }
        build_sdt(buf, MCFG_SIG, len)
    }

    #[test]
    fn mcfg_matches_the_qemu_q35_table() {
        // Real vendored OVMF / QEMU 11.1 q35 table (parsed out of a live boot):
        // one allocation, base 0xE000_0000, segment 0, all 256 buses.
        let mut buf = [0u8; 128];
        let len = build_mcfg(&mut buf, &[(0xE000_0000, 0, 0, 255)]);
        let mcfg = parse_mcfg(&buf[..len]).unwrap();
        assert_eq!(mcfg.count(), 1);
        let entry = mcfg.entries()[0];
        assert_eq!(entry.base, 0xE000_0000);
        assert_eq!(entry.segment, 0);
        assert_eq!(entry.start_bus, 0);
        assert_eq!(entry.end_bus, 255);
        assert_eq!(entry.bus_count(), 256);
        assert_eq!(entry.region_len(), Some(256 * ECAM_BUS_STRIDE));

        // Function/device/bus strides: bus 1 MiB, device 32 KiB, function 4 KiB.
        assert_eq!(entry.function_phys(0, 0, 0), Some(0xE000_0000));
        assert_eq!(entry.function_phys(0, 0, 1), Some(0xE000_1000));
        assert_eq!(entry.function_phys(0, 1, 0), Some(0xE000_8000));
        assert_eq!(entry.function_phys(1, 0, 0), Some(0xE010_0000));
        assert_eq!(
            entry.function_phys(255, 31, 7),
            Some(
                0xE000_0000
                    + 255 * ECAM_BUS_STRIDE
                    + 31 * ECAM_DEVICE_STRIDE
                    + 7 * ECAM_FUNCTION_STRIDE
            )
        );
        // Out-of-range device/function numbers never produce an address.
        assert_eq!(entry.function_phys(0, 32, 0), None);
        assert_eq!(entry.function_phys(0, 0, 8), None);
    }

    #[test]
    fn mcfg_rejects_bad_body_length() {
        // Header + reserved + half an entry: the body must be whole entries.
        let mut buf = [0u8; 128];
        let len = build_sdt(&mut buf, MCFG_SIG, SDT_HEADER_LEN + MCFG_RESERVED_LEN + 8);
        assert_eq!(parse_mcfg(&buf[..len]), Err(AcpiError::BadMcfgEntry));

        // No allocations at all is not a usable configuration.
        let mut buf = [0u8; 128];
        let len = build_sdt(&mut buf, MCFG_SIG, SDT_HEADER_LEN + MCFG_RESERVED_LEN);
        assert_eq!(parse_mcfg(&buf[..len]), Err(AcpiError::BadMcfgEntry));

        // Truncated header.
        let mut buf = [0u8; 128];
        let len = build_sdt(&mut buf, MCFG_SIG, SDT_HEADER_LEN + 2);
        assert_eq!(parse_mcfg(&buf[..len]), Err(AcpiError::TooShort));
    }

    #[test]
    fn mcfg_rejects_corrupt_checksum_and_signature() {
        let mut buf = [0u8; 128];
        let len = build_mcfg(&mut buf, &[(0xE000_0000, 0, 0, 0)]);
        let mut bad = buf;
        bad[9] = bad[9].wrapping_add(1);
        assert_eq!(parse_mcfg(&bad[..len]), Err(AcpiError::BadChecksum));

        let mut bad = buf;
        bad[..4].copy_from_slice(b"MCFX");
        assert_eq!(parse_mcfg(&bad[..len]), Err(AcpiError::BadSignature));
    }

    #[test]
    fn mcfg_rejects_unusable_ecam_addresses() {
        // Zero base.
        let mut buf = [0u8; 128];
        let len = build_mcfg(&mut buf, &[(0, 0, 0, 0)]);
        assert_eq!(parse_mcfg(&buf[..len]), Err(AcpiError::BadMcfgAddress));

        // Not 4 KiB aligned.
        let mut buf = [0u8; 128];
        let len = build_mcfg(&mut buf, &[(0xE000_0001, 0, 0, 0)]);
        assert_eq!(parse_mcfg(&buf[..len]), Err(AcpiError::BadMcfgAddress));

        // The described region must not wrap the 64-bit address space.
        let mut buf = [0u8; 128];
        let len = build_mcfg(&mut buf, &[(0xFFFF_FFFF_FFFF_F000, 0, 0, 0)]);
        assert_eq!(parse_mcfg(&buf[..len]), Err(AcpiError::BadMcfgAddress));
    }

    #[test]
    fn mcfg_rejects_inverted_bus_range_and_excess_allocations() {
        let mut buf = [0u8; 128];
        let len = build_mcfg(&mut buf, &[(0xE000_0000, 0, 2, 1)]);
        assert_eq!(parse_mcfg(&buf[..len]), Err(AcpiError::BadMcfgEntry));

        // Nine allocations exceed the bounded table this kernel retains.
        let rows = [(0xE000_0000u64, 0u16, 0u8, 0u8); 9];
        let mut buf = [0u8; 256];
        let len = build_mcfg(&mut buf, &rows);
        assert_eq!(parse_mcfg(&buf[..len]), Err(AcpiError::TooManyMcfgEntries));
    }

    #[test]
    fn mcfg_multiple_segments_keep_their_own_bus_window() {
        let mut buf = [0u8; 128];
        let len = build_mcfg(
            &mut buf,
            &[(0xE000_0000, 0, 0, 3), (0xE100_0000, 7, 16, 19)],
        );
        let mcfg = parse_mcfg(&buf[..len]).unwrap();
        assert_eq!(mcfg.count(), 2);
        let low = mcfg.entries()[0];
        let high = mcfg.entries()[1];
        assert_eq!(low.segment, 0);
        assert_eq!(high.segment, 7);
        // Bus numbers are relative to each allocation's own start bus.
        assert_eq!(high.function_phys(16, 0, 0), Some(0xE100_0000));
        assert_eq!(
            high.function_phys(19, 0, 0),
            Some(0xE100_0000 + 3 * ECAM_BUS_STRIDE)
        );
        assert_eq!(high.function_phys(15, 0, 0), None);
        assert_eq!(high.function_phys(20, 0, 0), None);
        assert_eq!(low.function_phys(4, 0, 0), None);
    }
}
