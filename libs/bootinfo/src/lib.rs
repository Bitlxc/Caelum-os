//! CaelumOS Boot Protocol 1.0 — shared BootInfo structures, TLV codec and CRC32C.
//!
//! This crate is `no_std` and has zero dependencies. It is used by:
//! - the UEFI loader (`x86_64-unknown-uefi`) to *construct* a BootInfo,
//! - the kernel (`x86_64-unknown-none`) to *validate and parse* it,
//! - host unit tests to verify both directions.
//!
//! See `docs/abi/boot-protocol.md` for the normative specification. All
//! multi-byte integers are little-endian on the wire; encoding/decoding is
//! done explicitly so the layout is identical on every host.

#![no_std]
#![forbid(unsafe_code)]

#[cfg(test)]
extern crate std;

// ---------------------------------------------------------------------------
// Protocol constants
// ---------------------------------------------------------------------------

/// BootInfo magic: the ASCII bytes `CAELUM01`.
pub const MAGIC: u64 = u64::from_le_bytes(*b"CAELUM01");

/// Boot Protocol major version implemented by this build.
pub const PROTOCOL_MAJOR: u16 = 1;
/// Boot Protocol minor version implemented by this build.
///
/// 1.1 (M4) adds the optional [`tlv_type::BOOT_MODULES`] TLV; it is a
/// backward-compatible addition (rule: new optional TLVs only in `minor`).
pub const PROTOCOL_MINOR: u16 = 1;

/// Entry ABI version: `rdi` = BootInfo physical address, `rsi` = BootInfo
/// virtual address (M1: identity-mapped, so `rsi == rdi`).
pub const ENTRY_ABI: u32 = 1;

/// Fixed header size in bytes.
pub const HEADER_SIZE: u32 = 64;

/// Sanity bound for `total_size` (validation fails above this).
pub const MAX_TOTAL_SIZE: u32 = 1 << 20;

/// `flags` bit 0: loader/kernel emit verbose debug logging.
pub const FLAG_DEBUG: u64 = 1 << 0;

/// TLV record types.
pub mod tlv_type {
    /// Final UEFI memory map. Required in M1. Value: [`MemoryMapTlv`].
    pub const MEMORY_MAP: u32 = 0x1;
    /// Kernel image placement, stack and initial page table. Required in M1. Value: [`crate::KernelImageTlv`].
    pub const KERNEL_IMAGE: u32 = 0x2;
    /// Early diagnostic serial port. Required in M1 unless [`FB_GOP`] is present. Value: [`crate::EarlySerialTlv`].
    pub const EARLY_SERIAL: u32 = 0x3;
    /// GOP framebuffer. Optional in M1. Value: [`crate::FbGopTlv`].
    pub const FB_GOP: u32 = 0x4;
    /// Physical address of the ACPI RSDP. Optional. Value: `u64` LE.
    pub const ACPI_RSDP: u32 = 0x5;
    /// Loader version string (UTF-8, no NUL). Optional. Value: raw bytes.
    pub const LOADER_INFO: u32 = 0x6;
    /// M4 boot modules (protocol 1.1, optional). Value: [`crate::validate_boot_modules`]
    /// payload — `count u32`, `reserved u32`, then `count` × 40-byte records
    /// (`phys u64`, `size u64`, `kind u32`, `name_len u32`, `name[16]`).
    pub const BOOT_MODULES: u32 = 0x7;
}

// ---------------------------------------------------------------------------
// CRC32C (Castagnoli), reflected, poly 0x1EDC6F41, init/xorout 0xFFFFFFFF
// ---------------------------------------------------------------------------

const fn make_crc_table() -> [u32; 256] {
    let mut table = [0u32; 256];
    let mut i = 0;
    while i < 256 {
        let mut crc = i as u32;
        let mut bit = 0;
        while bit < 8 {
            crc = if crc & 1 != 0 {
                (crc >> 1) ^ 0x82F6_3B78
            } else {
                crc >> 1
            };
            bit += 1;
        }
        table[i] = crc;
        i += 1;
    }
    table
}

static CRC_TABLE: [u32; 256] = make_crc_table();

#[inline]
fn crc_update(mut crc: u32, data: &[u8]) -> u32 {
    for &b in data {
        crc = CRC_TABLE[((crc ^ u32::from(b)) & 0xFF) as usize] ^ (crc >> 8);
    }
    crc
}

/// CRC32C of `data`.
pub fn crc32c(data: &[u8]) -> u32 {
    !crc_update(!0, data)
}

/// BootInfo checksum: CRC32C over the whole image with the checksum field
/// (bytes `[20..24]`) treated as zero. `image.len()` must be `>= 24`.
pub fn compute_checksum(image: &[u8]) -> u32 {
    debug_assert!(image.len() >= 24);
    let mut crc = crc_update(!0, &image[0..20]);
    crc = crc_update(crc, &image[24..]);
    !crc
}

// ---------------------------------------------------------------------------
// Fixed 64-byte header
// ---------------------------------------------------------------------------

/// Decoded BootInfo fixed header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header {
    pub major: u16,
    pub minor: u16,
    /// `header_size` field as stored (must equal [`HEADER_SIZE`]).
    pub header_size: u32,
    pub total_size: u32,
    pub checksum: u32,
    pub flags: u64,
    pub entry_abi: u32,
    pub tlv_offset: u32,
    pub tlv_count: u32,
}

// Field offsets within the 64-byte header.
pub mod off {
    pub const MAGIC: usize = 0;
    pub const MAJOR: usize = 8;
    pub const MINOR: usize = 10;
    pub const HEADER_SIZE: usize = 12;
    pub const TOTAL_SIZE: usize = 16;
    pub const CHECKSUM: usize = 20;
    pub const FLAGS: usize = 24;
    pub const ENTRY_ABI: usize = 32;
    pub const TLV_OFFSET: usize = 36;
    pub const TLV_COUNT: usize = 40;
}

impl Header {
    /// Decode a header from the first 64 bytes. Returns `None` if the buffer
    /// is too short or the magic does not match.
    pub fn decode(buf: &[u8]) -> Option<Header> {
        if buf.len() < HEADER_SIZE as usize {
            return None;
        }
        let magic = u64::from_le_bytes(buf[off::MAGIC..][..8].try_into().ok()?);
        if magic != MAGIC {
            return None;
        }
        Some(Header {
            major: u16::from_le_bytes(buf[off::MAJOR..][..2].try_into().ok()?),
            minor: u16::from_le_bytes(buf[off::MINOR..][..2].try_into().ok()?),
            header_size: u32::from_le_bytes(buf[off::HEADER_SIZE..][..4].try_into().ok()?),
            total_size: u32::from_le_bytes(buf[off::TOTAL_SIZE..][..4].try_into().ok()?),
            checksum: u32::from_le_bytes(buf[off::CHECKSUM..][..4].try_into().ok()?),
            flags: u64::from_le_bytes(buf[off::FLAGS..][..8].try_into().ok()?),
            entry_abi: u32::from_le_bytes(buf[off::ENTRY_ABI..][..4].try_into().ok()?),
            tlv_offset: u32::from_le_bytes(buf[off::TLV_OFFSET..][..4].try_into().ok()?),
            tlv_count: u32::from_le_bytes(buf[off::TLV_COUNT..][..4].try_into().ok()?),
        })
    }
}

fn encode_header(buf: &mut [u8], h: &Header) {
    buf[off::MAGIC..][..8].copy_from_slice(&MAGIC.to_le_bytes());
    buf[off::MAJOR..][..2].copy_from_slice(&h.major.to_le_bytes());
    buf[off::MINOR..][..2].copy_from_slice(&h.minor.to_le_bytes());
    buf[off::HEADER_SIZE..][..4].copy_from_slice(&h.header_size.to_le_bytes());
    buf[off::TOTAL_SIZE..][..4].copy_from_slice(&h.total_size.to_le_bytes());
    buf[off::CHECKSUM..][..4].copy_from_slice(&h.checksum.to_le_bytes());
    buf[off::FLAGS..][..8].copy_from_slice(&h.flags.to_le_bytes());
    buf[off::ENTRY_ABI..][..4].copy_from_slice(&h.entry_abi.to_le_bytes());
    buf[off::TLV_OFFSET..][..4].copy_from_slice(&h.tlv_offset.to_le_bytes());
    buf[off::TLV_COUNT..][..4].copy_from_slice(&h.tlv_count.to_le_bytes());
    buf[44..HEADER_SIZE as usize].fill(0);
}

// ---------------------------------------------------------------------------
// TLV codec
// ---------------------------------------------------------------------------

fn align8(n: usize) -> usize {
    (n + 7) & !7
}

/// Error returned while *constructing* a BootInfo.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BuildError {
    /// TLV types must be strictly ascending.
    UnsortedTlv,
    /// The backing buffer is too small.
    OutOfSpace,
}

/// Sequential BootInfo builder. TLVs must be added in strictly ascending
/// type order; every record is 8-byte aligned and zero-padded.
pub struct Writer<'a> {
    buf: &'a mut [u8],
    cursor: usize,
    count: u32,
    last: u32,
    major: u16,
    minor: u16,
    flags: u64,
    entry_abi: u32,
}

impl<'a> Writer<'a> {
    /// Create a writer over `buf` (which must hold the whole BootInfo,
    /// starting at the fixed header). TLV records start at [`HEADER_SIZE`].
    pub fn new(buf: &'a mut [u8], major: u16, minor: u16, flags: u64, entry_abi: u32) -> Self {
        buf.fill(0);
        Writer {
            buf,
            cursor: HEADER_SIZE as usize,
            count: 0,
            last: 0,
            major,
            minor,
            flags,
            entry_abi,
        }
    }

    pub fn add_tlv(&mut self, ty: u32, value: &[u8]) -> Result<(), BuildError> {
        if self.count > 0 && ty <= self.last {
            return Err(BuildError::UnsortedTlv);
        }
        let need = align8(8 + value.len());
        if self.cursor + need > self.buf.len() {
            return Err(BuildError::OutOfSpace);
        }
        let at = self.cursor;
        self.buf[at..][..4].copy_from_slice(&ty.to_le_bytes());
        self.buf[at + 4..][..4].copy_from_slice(&(value.len() as u32).to_le_bytes());
        self.buf[at + 8..at + 8 + value.len()].copy_from_slice(value);
        let end = at + 8 + value.len();
        self.buf[end..at + need].fill(0);
        self.cursor = at + need;
        self.count += 1;
        self.last = ty;
        Ok(())
    }

    /// Finalize the header, compute the checksum and return `total_size`.
    pub fn finish(self) -> Result<u32, BuildError> {
        let total_size = u32::try_from(self.cursor).map_err(|_| BuildError::OutOfSpace)?;
        let header = Header {
            major: self.major,
            minor: self.minor,
            header_size: HEADER_SIZE,
            total_size,
            checksum: 0,
            flags: self.flags,
            entry_abi: self.entry_abi,
            tlv_offset: HEADER_SIZE,
            tlv_count: self.count,
        };
        encode_header(self.buf, &header);
        let checksum = compute_checksum(&self.buf[..self.cursor]);
        self.buf[off::CHECKSUM..][..4].copy_from_slice(&checksum.to_le_bytes());
        Ok(total_size)
    }
}

/// Iterate TLV records of an already-validated image.
pub struct Tlvs<'a> {
    image: &'a [u8],
    cursor: usize,
    end: usize,
}

impl<'a> Tlvs<'a> {
    /// `image` must start at the BootInfo base and be at least `tlv_offset`
    /// bytes long; iteration stops at `end` (normally `total_size`).
    pub fn new(image: &'a [u8], tlv_offset: u32, end: u32) -> Tlvs<'a> {
        Tlvs {
            image,
            cursor: tlv_offset as usize,
            end: end as usize,
        }
    }

    /// Next record as `(type, value)`. Returns `None` at the end; a malformed
    /// record also yields `None` (callers must have run `validate` first).
    pub fn next(&mut self) -> Option<(u32, &'a [u8])> {
        if self.cursor + 8 > self.end {
            return None;
        }
        let ty = u32::from_le_bytes(self.image[self.cursor..][..4].try_into().ok()?);
        let len = u32::from_le_bytes(self.image[self.cursor + 4..][..4].try_into().ok()?) as usize;
        let val_start = self.cursor + 8;
        let val_end = val_start.checked_add(len)?;
        if val_end > self.end {
            return None;
        }
        self.cursor = align8(val_end);
        Some((ty, &self.image[val_start..val_end]))
    }
}

impl<'a> Iterator for Tlvs<'a> {
    type Item = (u32, &'a [u8]);

    fn next(&mut self) -> Option<Self::Item> {
        Tlvs::next(self)
    }
}

/// Find the first TLV of type `ty`.
pub fn find_tlv<'a>(
    image: &'a [u8],
    tlv_offset: u32,
    total_size: u32,
    ty: u32,
) -> Option<&'a [u8]> {
    Tlvs::new(image, tlv_offset, total_size)
        .find(|(t, _)| *t == ty)
        .map(|(_, v)| v)
}

// ---------------------------------------------------------------------------
// Validation (kernel side)
// ---------------------------------------------------------------------------

/// BootInfo validation failure category. The kernel prints the category in
/// its minimal failure output.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// Buffer shorter than the fixed header.
    TooSmall,
    BadMagic,
    /// Unsupported protocol `major`.
    Version,
    /// Unsupported `entry_abi`.
    Abi,
    /// `header_size`/`total_size`/TLV layout problems or arithmetic overflow.
    Layout,
    Checksum,
    /// A required TLV is missing (M1: MEMORY_MAP, KERNEL_IMAGE, and
    /// EARLY_SERIAL or FB_GOP).
    MissingRequiredTlv,
}

/// Validate a BootInfo image of exactly `header.total_size` bytes.
pub fn validate(image: &[u8]) -> Result<Header, Error> {
    let header = Header::decode(image).ok_or(Error::TooSmall)?;
    if header.major != PROTOCOL_MAJOR {
        return Err(Error::Version);
    }
    if header.entry_abi != ENTRY_ABI {
        return Err(Error::Abi);
    }
    if header.header_size != HEADER_SIZE {
        return Err(Error::Layout);
    }
    if header.total_size < HEADER_SIZE || header.total_size > MAX_TOTAL_SIZE {
        return Err(Error::Layout);
    }
    if (image.len() as u32) < header.total_size {
        return Err(Error::Layout);
    }
    let image = &image[..header.total_size as usize];
    if header.tlv_offset < HEADER_SIZE || header.tlv_offset > header.total_size {
        return Err(Error::Layout);
    }
    // Structural walk: 8-byte aligned records, strictly ascending types,
    // all bounds checked.
    let mut prev: Option<u32> = None;
    let mut seen = 0u32;
    let mut tlvs = Tlvs::new(image, header.tlv_offset, header.total_size);
    while let Some((ty, _)) = tlvs.next() {
        if prev.is_some_and(|p| ty <= p) {
            return Err(Error::Layout);
        }
        prev = Some(ty);
        seen += 1;
    }
    // `next()` returning None early means a malformed record ended the walk;
    // verify the walk consumed the whole TLV area.
    let consumed = tlvs.cursor == header.total_size as usize;
    if !consumed {
        return Err(Error::Layout);
    }
    if seen != header.tlv_count {
        return Err(Error::Layout);
    }
    // Required TLV set for M1.
    let has = |ty: u32| find_tlv(image, header.tlv_offset, header.total_size, ty).is_some();
    if !has(tlv_type::MEMORY_MAP) || !has(tlv_type::KERNEL_IMAGE) {
        return Err(Error::MissingRequiredTlv);
    }
    if !has(tlv_type::EARLY_SERIAL) && !has(tlv_type::FB_GOP) {
        return Err(Error::MissingRequiredTlv);
    }
    if compute_checksum(image) != header.checksum {
        return Err(Error::Checksum);
    }
    Ok(header)
}

// ---------------------------------------------------------------------------
// Typed TLV payloads (fixed-size, little-endian)
// ---------------------------------------------------------------------------

/// TLV 0x1 MEMORY_MAP payload prefix (followed by `count` raw 48-byte UEFI
/// memory descriptors).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MemoryMapTlv {
    pub desc_size: u32,
    pub desc_version: u32,
}

impl MemoryMapTlv {
    pub const PREFIX_LEN: usize = 8;

    pub fn encode(&self) -> [u8; 8] {
        let mut b = [0u8; 8];
        b[0..4].copy_from_slice(&self.desc_size.to_le_bytes());
        b[4..8].copy_from_slice(&self.desc_version.to_le_bytes());
        b
    }

    pub fn decode(value: &[u8]) -> Option<MemoryMapTlv> {
        if value.len() < 8 {
            return None;
        }
        Some(MemoryMapTlv {
            desc_size: u32::from_le_bytes(value[0..4].try_into().ok()?),
            desc_version: u32::from_le_bytes(value[4..8].try_into().ok()?),
        })
    }

    /// Number of complete descriptors in a TLV value.
    pub fn descriptor_count(&self, value_len: usize) -> Option<usize> {
        if self.desc_size < 48 {
            return None;
        }
        let rest = value_len.checked_sub(Self::PREFIX_LEN)?;
        Some(rest / self.desc_size as usize)
    }
}

/// Offsets inside a raw 48-byte UEFI memory descriptor.
pub mod efi_desc {
    pub const TYPE: usize = 0; // u32
    pub const PHYS_START: usize = 8; // u64
    pub const PAGE_COUNT: usize = 24; // u64
    pub const ATTRIBUTE: usize = 32; // u64
    pub const LEN: usize = 48;
    /// `EFI_MEMORY_CONVENTIONAL_MEMORY`
    pub const TYPE_CONVENTIONAL: u32 = 7;
}

/// Read the `PhysicalStart` field of a raw descriptor.
pub fn efi_desc_phys(desc: &[u8]) -> Option<u64> {
    Some(u64::from_le_bytes(
        desc.get(efi_desc::PHYS_START..)?
            .get(..8)?
            .try_into()
            .ok()?,
    ))
}

/// Read the `NumberOfPages` field of a raw descriptor.
pub fn efi_desc_pages(desc: &[u8]) -> Option<u64> {
    Some(u64::from_le_bytes(
        desc.get(efi_desc::PAGE_COUNT..)?
            .get(..8)?
            .try_into()
            .ok()?,
    ))
}

/// Read the `Type` field of a raw descriptor.
pub fn efi_desc_type(desc: &[u8]) -> Option<u32> {
    Some(u32::from_le_bytes(
        desc.get(efi_desc::TYPE..)?.get(..4)?.try_into().ok()?,
    ))
}

/// TLV 0x2 KERNEL_IMAGE payload (64 bytes).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KernelImageTlv {
    pub image_phys_base: u64,
    pub image_phys_size: u64,
    pub image_virt_base: u64,
    pub image_virt_size: u64,
    pub entry_virt: u64,
    /// Initial stack base (identity-mapped; M1: `rsp` is already switched by
    /// the loader, this is informational).
    pub stack_base: u64,
    pub stack_size: u64,
    /// Physical address of the top-level (PML4) initial page table.
    pub page_table_phys: u64,
}

impl KernelImageTlv {
    pub const LEN: usize = 64;

    pub fn encode(&self) -> [u8; 64] {
        let mut b = [0u8; 64];
        let f = [
            self.image_phys_base,
            self.image_phys_size,
            self.image_virt_base,
            self.image_virt_size,
            self.entry_virt,
            self.stack_base,
            self.stack_size,
            self.page_table_phys,
        ];
        for (i, v) in f.iter().enumerate() {
            b[i * 8..i * 8 + 8].copy_from_slice(&v.to_le_bytes());
        }
        b
    }

    pub fn decode(value: &[u8]) -> Option<KernelImageTlv> {
        if value.len() < 64 {
            return None;
        }
        let g = |i: usize| -> Option<u64> {
            Some(u64::from_le_bytes(
                value.get(i * 8..)?.get(..8)?.try_into().ok()?,
            ))
        };
        Some(KernelImageTlv {
            image_phys_base: g(0)?,
            image_phys_size: g(1)?,
            image_virt_base: g(2)?,
            image_virt_size: g(3)?,
            entry_virt: g(4)?,
            stack_base: g(5)?,
            stack_size: g(6)?,
            page_table_phys: g(7)?,
        })
    }
}

/// TLV 0x3 EARLY_SERIAL payload (24 bytes).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EarlySerialTlv {
    /// 1 = 16550-compatible at an I/O port (x86-64 M1 baseline).
    pub kind: u32,
    /// I/O port base (e.g. 0x3F8) or MMIO base depending on `kind`.
    pub base: u64,
    pub baud: u32,
    pub reserved: u32,
}

impl EarlySerialTlv {
    pub const KIND_IOPORT_16550: u32 = 1;
    pub const LEN: usize = 24;

    pub fn encode(&self) -> [u8; 24] {
        let mut b = [0u8; 24];
        b[0..4].copy_from_slice(&self.kind.to_le_bytes());
        b[4..12].copy_from_slice(&self.base.to_le_bytes());
        b[12..16].copy_from_slice(&self.baud.to_le_bytes());
        b[16..20].copy_from_slice(&self.reserved.to_le_bytes());
        b
    }

    pub fn decode(value: &[u8]) -> Option<EarlySerialTlv> {
        if value.len() < 24 {
            return None;
        }
        Some(EarlySerialTlv {
            kind: u32::from_le_bytes(value[0..4].try_into().ok()?),
            base: u64::from_le_bytes(value[4..12].try_into().ok()?),
            baud: u32::from_le_bytes(value[12..16].try_into().ok()?),
            reserved: u32::from_le_bytes(value[16..20].try_into().ok()?),
        })
    }
}

/// TLV 0x4 FB_GOP payload (32 bytes).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FbGopTlv {
    pub base: u64,
    pub size: u64,
    pub width: u32,
    pub height: u32,
    pub stride: u32,
    pub pixel_format: u32,
}

impl FbGopTlv {
    pub const LEN: usize = 32;

    pub fn encode(&self) -> [u8; 32] {
        let mut b = [0u8; 32];
        b[0..8].copy_from_slice(&self.base.to_le_bytes());
        b[8..16].copy_from_slice(&self.size.to_le_bytes());
        b[16..20].copy_from_slice(&self.width.to_le_bytes());
        b[20..24].copy_from_slice(&self.height.to_le_bytes());
        b[24..28].copy_from_slice(&self.stride.to_le_bytes());
        b[28..32].copy_from_slice(&self.pixel_format.to_le_bytes());
        b
    }

    pub fn decode(value: &[u8]) -> Option<FbGopTlv> {
        if value.len() < 32 {
            return None;
        }
        Some(FbGopTlv {
            base: u64::from_le_bytes(value[0..8].try_into().ok()?),
            size: u64::from_le_bytes(value[8..16].try_into().ok()?),
            width: u32::from_le_bytes(value[16..20].try_into().ok()?),
            height: u32::from_le_bytes(value[20..24].try_into().ok()?),
            stride: u32::from_le_bytes(value[24..28].try_into().ok()?),
            pixel_format: u32::from_le_bytes(value[28..32].try_into().ok()?),
        })
    }
}

// ---------------------------------------------------------------------------
// Boot modules (Boot Protocol 1.1): TLV 0x7 payload + INITFS.IMG container
// ---------------------------------------------------------------------------
//
// Two distinct wire formats share the same 40-byte module-record size:
//
// * BootInfo TLV 0x7 (kernel-facing): `phys u64`, `size u64`, `kind u32`,
//   `name_len u32`, `name[16]` — the loader resolves the module bytes to a
//   physical address the kernel can map after page-table takeover.
// * INITFS.IMG (loader-facing, read from the ESP): `name[16]`, `kind u32`,
//   `reserved u32`, `offset u64`, `size u64` — no natural padding, the
//   `reserved` word is explicit so the layout is unambiguous.

/// Module kind: loadable ELF64 image (`ET_EXEC`, x86-64).
pub const MODULE_KIND_ELF: u32 = 1;

/// Module name field width in bytes, in both wire formats.
pub const MODULE_NAME_LEN: usize = 16;

/// Wire size of one module record in both wire formats.
pub const MODULE_RECORD_LEN: usize = 40;

/// Upper bound on the number of modules in one container / BootInfo TLV.
pub const MAX_BOOT_MODULES: usize = 8;

/// TLV 0x7 payload prefix: `count u32`, `reserved u32`.
pub const BOOT_MODULES_PREFIX_LEN: usize = 8;

/// `INITFS.IMG` header magic: the ASCII bytes `CAELUMFS`.
pub const INITFS_MAGIC: u64 = u64::from_le_bytes(*b"CAELUMFS");
/// `INITFS.IMG` container format version.
pub const INITFS_VERSION: u32 = 1;
/// `INITFS.IMG` fixed header size (magic + version + count).
pub const INITFS_HEADER_LEN: usize = 16;
/// Module payload offsets inside `INITFS.IMG` must be multiples of this.
pub const MODULE_ALIGN: u64 = 16;

/// Failure categories for boot-module payloads and `INITFS.IMG` containers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ModuleError {
    Truncated,
    BadMagic,
    BadVersion,
    BadCount,
    /// Module record malformed (zero kind/size, non-zero reserved word, ...).
    BadRecord,
    /// Module name empty, too long, non-graphic or not NUL-padded.
    BadName,
    /// Module payload offset not aligned to [`MODULE_ALIGN`].
    BadAlign,
    /// Module payload not fully inside the container / file.
    OutOfRange,
    /// Two modules claim overlapping payload ranges (or the header).
    Overlap,
}

/// Module names are short ASCII identifiers (`init`, `child`, ...).
fn module_name_ok(bytes: &[u8]) -> bool {
    !bytes.is_empty()
        && bytes
            .iter()
            .all(|&b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

/// Validate a fixed-width `name[16]` field against an explicit `name_len`.
fn module_name_field(name: &[u8; MODULE_NAME_LEN], name_len: u32) -> Option<usize> {
    let n = name_len as usize;
    if n == 0 || n > MODULE_NAME_LEN || !module_name_ok(&name[..n]) {
        return None;
    }
    if name[n..].iter().any(|&b| b != 0) {
        return None;
    }
    Some(n)
}

/// One boot module as delivered in the TLV 0x7 payload.
///
/// Wire layout (40 bytes, little-endian): `phys u64 @0`, `size u64 @8`,
/// `kind u32 @16`, `name_len u32 @20`, `name[16] @24`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BootModule {
    pub phys: u64,
    pub size: u64,
    pub kind: u32,
    pub name: [u8; MODULE_NAME_LEN],
    pub name_len: u32,
}

impl BootModule {
    pub const LEN: usize = MODULE_RECORD_LEN;

    /// Build a record. Returns `None` on an invalid name, zero kind/size, or
    /// an overflowing `phys + size`.
    pub fn new(name: &[u8], kind: u32, phys: u64, size: u64) -> Option<BootModule> {
        if name.len() > MODULE_NAME_LEN || !module_name_ok(name) || kind == 0 || size == 0 {
            return None;
        }
        phys.checked_add(size)?;
        let mut padded = [0u8; MODULE_NAME_LEN];
        padded[..name.len()].copy_from_slice(name);
        Some(BootModule {
            phys,
            size,
            kind,
            name: padded,
            name_len: name.len() as u32,
        })
    }

    pub fn name_bytes(&self) -> Option<&[u8]> {
        let n = module_name_field(&self.name, self.name_len)?;
        Some(&self.name[..n])
    }

    pub fn matches(&self, name: &[u8]) -> bool {
        self.name_bytes() == Some(name)
    }

    pub fn encode(&self) -> [u8; MODULE_RECORD_LEN] {
        let mut b = [0u8; MODULE_RECORD_LEN];
        b[0..8].copy_from_slice(&self.phys.to_le_bytes());
        b[8..16].copy_from_slice(&self.size.to_le_bytes());
        b[16..20].copy_from_slice(&self.kind.to_le_bytes());
        b[20..24].copy_from_slice(&self.name_len.to_le_bytes());
        b[24..40].copy_from_slice(&self.name);
        b
    }

    pub fn decode(value: &[u8]) -> Option<BootModule> {
        if value.len() < MODULE_RECORD_LEN {
            return None;
        }
        let phys = u64::from_le_bytes(value[0..8].try_into().ok()?);
        let size = u64::from_le_bytes(value[8..16].try_into().ok()?);
        let kind = u32::from_le_bytes(value[16..20].try_into().ok()?);
        let name_len = u32::from_le_bytes(value[20..24].try_into().ok()?);
        if kind == 0 || size == 0 || phys.checked_add(size).is_none() {
            return None;
        }
        let mut name = [0u8; MODULE_NAME_LEN];
        name.copy_from_slice(&value[24..40]);
        module_name_field(&name, name_len)?;
        Some(BootModule {
            phys,
            size,
            kind,
            name,
            name_len,
        })
    }
}

/// Validated view over a TLV 0x7 payload (the kernel-facing module list).
#[derive(Debug, Clone, Copy)]
pub struct BootModules<'a> {
    value: &'a [u8],
    count: u32,
}

impl<'a> BootModules<'a> {
    pub fn new(value: &'a [u8]) -> Option<BootModules<'a>> {
        let count = validate_boot_modules(value).ok()?;
        Some(BootModules { value, count })
    }

    pub fn count(&self) -> u32 {
        self.count
    }

    pub fn get(&self, index: u32) -> Option<BootModule> {
        if index >= self.count {
            return None;
        }
        let start = BOOT_MODULES_PREFIX_LEN + index as usize * MODULE_RECORD_LEN;
        BootModule::decode(self.value.get(start..start + MODULE_RECORD_LEN)?)
    }

    pub fn iter(&self) -> impl Iterator<Item = BootModule> + '_ {
        (0..self.count).filter_map(|i| self.get(i))
    }

    pub fn find(&self, name: &[u8]) -> Option<BootModule> {
        self.iter().find(|m| m.matches(name))
    }
}

/// Validate a TLV 0x7 payload and return its module count.
pub fn validate_boot_modules(value: &[u8]) -> Result<u32, ModuleError> {
    if value.len() < BOOT_MODULES_PREFIX_LEN {
        return Err(ModuleError::Truncated);
    }
    let count = u32::from_le_bytes(value[0..4].try_into().map_err(|_| ModuleError::Truncated)?);
    let reserved = u32::from_le_bytes(value[4..8].try_into().map_err(|_| ModuleError::Truncated)?);
    if count == 0 || count as usize > MAX_BOOT_MODULES {
        return Err(ModuleError::BadCount);
    }
    if reserved != 0 {
        return Err(ModuleError::BadRecord);
    }
    let want = BOOT_MODULES_PREFIX_LEN + count as usize * MODULE_RECORD_LEN;
    if value.len() != want {
        return Err(ModuleError::Truncated);
    }
    let modules = BootModules { value, count };
    for i in 0..count {
        let m = modules.get(i).ok_or(ModuleError::BadRecord)?;
        if m.phys % MODULE_ALIGN != 0 {
            return Err(ModuleError::BadAlign);
        }
        for j in 0..i {
            let prev = modules.get(j).ok_or(ModuleError::BadRecord)?;
            if prev.name_bytes() == m.name_bytes() {
                return Err(ModuleError::BadName);
            }
        }
    }
    Ok(count)
}

/// One module record of an `INITFS.IMG` container.
///
/// Wire layout (40 bytes, little-endian): `name[16] @0`, `kind u32 @16`,
/// `reserved u32 @20` (must be 0), `offset u64 @24`, `size u64 @32`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InitfsModule {
    pub name: [u8; MODULE_NAME_LEN],
    pub kind: u32,
    pub offset: u64,
    pub size: u64,
}

impl InitfsModule {
    pub const LEN: usize = MODULE_RECORD_LEN;

    pub fn new(name: &[u8], kind: u32, offset: u64, size: u64) -> Option<InitfsModule> {
        if name.len() > MODULE_NAME_LEN || !module_name_ok(name) || kind == 0 || size == 0 {
            return None;
        }
        if offset % MODULE_ALIGN != 0 {
            return None;
        }
        offset.checked_add(size)?;
        let mut padded = [0u8; MODULE_NAME_LEN];
        padded[..name.len()].copy_from_slice(name);
        Some(InitfsModule {
            name: padded,
            kind,
            offset,
            size,
        })
    }

    /// Container names are NUL-padded; the length is implicit.
    pub fn name_bytes(&self) -> Option<&[u8]> {
        let mut n = 0usize;
        while n < MODULE_NAME_LEN && self.name[n] != 0 {
            n += 1;
        }
        if !module_name_ok(&self.name[..n]) {
            return None;
        }
        if self.name[n..].iter().any(|&b| b != 0) {
            return None;
        }
        Some(&self.name[..n])
    }

    pub fn matches(&self, name: &[u8]) -> bool {
        self.name_bytes() == Some(name)
    }

    pub fn encode(&self) -> [u8; MODULE_RECORD_LEN] {
        let mut b = [0u8; MODULE_RECORD_LEN];
        b[0..16].copy_from_slice(&self.name);
        b[16..20].copy_from_slice(&self.kind.to_le_bytes());
        // b[20..24]: explicit `reserved u32` = 0.
        b[24..32].copy_from_slice(&self.offset.to_le_bytes());
        b[32..40].copy_from_slice(&self.size.to_le_bytes());
        b
    }

    pub fn decode(value: &[u8]) -> Option<InitfsModule> {
        if value.len() < MODULE_RECORD_LEN {
            return None;
        }
        let kind = u32::from_le_bytes(value[16..20].try_into().ok()?);
        let reserved = u32::from_le_bytes(value[20..24].try_into().ok()?);
        if kind == 0 || reserved != 0 {
            return None;
        }
        let offset = u64::from_le_bytes(value[24..32].try_into().ok()?);
        let size = u64::from_le_bytes(value[32..40].try_into().ok()?);
        if size == 0 || offset % MODULE_ALIGN != 0 {
            return None;
        }
        offset.checked_add(size)?;
        let mut name = [0u8; MODULE_NAME_LEN];
        name.copy_from_slice(&value[0..MODULE_NAME_LEN]);
        let m = InitfsModule {
            name,
            kind,
            offset,
            size,
        };
        m.name_bytes()?;
        Some(m)
    }
}

/// Validated view over an `INITFS.IMG` container held in memory.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Initfs<'a> {
    data: &'a [u8],
    count: u32,
}

impl<'a> Initfs<'a> {
    /// Parse and fully validate the container: magic, version, count, record
    /// geometry, 16-byte payload alignment, in-file bounds, no overlaps.
    pub fn parse(data: &'a [u8]) -> Result<Initfs<'a>, ModuleError> {
        if data.len() < INITFS_HEADER_LEN {
            return Err(ModuleError::Truncated);
        }
        let magic = u64::from_le_bytes(data[0..8].try_into().map_err(|_| ModuleError::Truncated)?);
        if magic != INITFS_MAGIC {
            return Err(ModuleError::BadMagic);
        }
        let version =
            u32::from_le_bytes(data[8..12].try_into().map_err(|_| ModuleError::Truncated)?);
        if version != INITFS_VERSION {
            return Err(ModuleError::BadVersion);
        }
        let count = u32::from_le_bytes(
            data[12..16]
                .try_into()
                .map_err(|_| ModuleError::Truncated)?,
        );
        if count == 0 || count as usize > MAX_BOOT_MODULES {
            return Err(ModuleError::BadCount);
        }
        let table_end = INITFS_HEADER_LEN + count as usize * MODULE_RECORD_LEN;
        if data.len() < table_end {
            return Err(ModuleError::Truncated);
        }
        let initfs = Initfs { data, count };
        for i in 0..count {
            let m = initfs.module(i).ok_or(ModuleError::BadRecord)?;
            let end = m
                .offset
                .checked_add(m.size)
                .ok_or(ModuleError::OutOfRange)?;
            if end > data.len() as u64 || m.offset < table_end as u64 {
                return Err(ModuleError::OutOfRange);
            }
            for j in 0..i {
                let prev = initfs.module(j).ok_or(ModuleError::BadRecord)?;
                let prev_end = prev.offset + prev.size;
                if m.offset < prev_end && prev.offset < end {
                    return Err(ModuleError::Overlap);
                }
                if prev.name_bytes() == m.name_bytes() {
                    return Err(ModuleError::BadName);
                }
            }
        }
        Ok(initfs)
    }

    pub fn count(&self) -> u32 {
        self.count
    }

    pub fn module(&self, index: u32) -> Option<InitfsModule> {
        if index >= self.count {
            return None;
        }
        let start = INITFS_HEADER_LEN + index as usize * MODULE_RECORD_LEN;
        InitfsModule::decode(self.data.get(start..start + MODULE_RECORD_LEN)?)
    }

    pub fn iter(&self) -> impl Iterator<Item = InitfsModule> + '_ {
        (0..self.count).filter_map(|i| self.module(i))
    }

    pub fn find(&self, name: &[u8]) -> Option<InitfsModule> {
        self.iter().find(|m| m.matches(name))
    }

    /// Borrow the bytes of one module payload.
    pub fn data_of(&self, module: &InitfsModule) -> Option<&'a [u8]> {
        let start = usize::try_from(module.offset).ok()?;
        let size = usize::try_from(module.size).ok()?;
        self.data.get(start..start.checked_add(size)?)
    }

    /// Encode the TLV 0x7 payload for modules mapped at physical `base`.
    ///
    /// Returns the payload length written into `out`. `out` must be at least
    /// `BOOT_MODULES_PREFIX_LEN + count * MODULE_RECORD_LEN` bytes.
    pub fn to_boot_modules(&self, base: u64, out: &mut [u8]) -> Option<usize> {
        let need = BOOT_MODULES_PREFIX_LEN + self.count as usize * MODULE_RECORD_LEN;
        if out.len() < need {
            return None;
        }
        out[..4].copy_from_slice(&self.count.to_le_bytes());
        out[4..8].fill(0);
        for i in 0..self.count {
            let m = self.module(i)?;
            let phys = base.checked_add(m.offset)?;
            let bm = BootModule::new(m.name_bytes()?, m.kind, phys, m.size)?;
            let at = BOOT_MODULES_PREFIX_LEN + i as usize * MODULE_RECORD_LEN;
            out[at..at + MODULE_RECORD_LEN].copy_from_slice(&bm.encode());
        }
        Some(need)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::vec::Vec;

    #[test]
    fn crc32c_known_vectors() {
        assert_eq!(crc32c(b""), 0);
        assert_eq!(crc32c(b"123456789"), 0xE306_9283);
        assert_eq!(
            crc32c(b"The quick brown fox jumps over the lazy dog"),
            0x2262_0404
        );
    }

    #[test]
    fn header_roundtrip() {
        let mut buf = [0u8; 64];
        let h = Header {
            major: 1,
            minor: 0,
            header_size: HEADER_SIZE,
            total_size: 64,
            checksum: 0,
            flags: FLAG_DEBUG,
            entry_abi: ENTRY_ABI,
            tlv_offset: HEADER_SIZE,
            tlv_count: 0,
        };
        encode_header(&mut buf, &h);
        let d = Header::decode(&buf).expect("decode");
        assert_eq!(d.major, 1);
        assert_eq!(d.flags, FLAG_DEBUG);
        assert_eq!(d.tlv_offset, HEADER_SIZE);
        // reserved zeroed
        assert!(buf[44..].iter().all(|&b| b == 0));
    }

    #[test]
    fn header_decode_rejects_bad_magic() {
        let buf = [0u8; 64];
        assert!(Header::decode(&buf).is_none());
    }

    /// Build a valid minimal M1 image.
    fn build_image(buf: &mut [u8]) -> u32 {
        let mut w = Writer::new(buf, PROTOCOL_MAJOR, PROTOCOL_MINOR, 0, ENTRY_ABI);
        let mm = MemoryMapTlv {
            desc_size: 48,
            desc_version: 1,
        };
        let mut mm_val = Vec::new();
        mm_val.extend_from_slice(&mm.encode());
        mm_val.extend_from_slice(&[0xAA; 48]); // one fake descriptor
        w.add_tlv(tlv_type::MEMORY_MAP, &mm_val).unwrap();
        w.add_tlv(
            tlv_type::KERNEL_IMAGE,
            &KernelImageTlv {
                image_phys_base: 0x10_0000,
                image_phys_size: 0x2_0000,
                image_virt_base: 0xFFFF_FFFF_8000_0000,
                image_virt_size: 0x2_0000,
                entry_virt: 0xFFFF_FFFF_8000_0000,
                stack_base: 0x20_0000,
                stack_size: 0x1_0000,
                page_table_phys: 0x30_0000,
            }
            .encode(),
        )
        .unwrap();
        w.add_tlv(
            tlv_type::EARLY_SERIAL,
            &EarlySerialTlv {
                kind: EarlySerialTlv::KIND_IOPORT_16550,
                base: 0x3F8,
                baud: 115200,
                reserved: 0,
            }
            .encode(),
        )
        .unwrap();
        w.add_tlv(tlv_type::LOADER_INFO, b"0.1.0-test").unwrap();
        w.finish().unwrap()
    }

    #[test]
    fn writer_validate_roundtrip() {
        let mut buf = [0u8; 1024];
        let total = build_image(&mut buf);
        let image = &buf[..total as usize];
        let h = validate(image).expect("validate");
        assert_eq!(h.tlv_count, 4);
        // memory map descriptor count
        let mm = find_tlv(image, h.tlv_offset, h.total_size, tlv_type::MEMORY_MAP).unwrap();
        let mm = MemoryMapTlv::decode(mm).unwrap();
        assert_eq!(
            mm.descriptor_count(
                find_tlv(image, h.tlv_offset, h.total_size, tlv_type::MEMORY_MAP)
                    .unwrap()
                    .len()
            ),
            Some(1)
        );
        // serial decode
        let s = find_tlv(image, h.tlv_offset, h.total_size, tlv_type::EARLY_SERIAL).unwrap();
        let s = EarlySerialTlv::decode(s).unwrap();
        assert_eq!(s.base, 0x3F8);
        // loader info string
        let li = find_tlv(image, h.tlv_offset, h.total_size, tlv_type::LOADER_INFO).unwrap();
        assert_eq!(li, b"0.1.0-test");
    }

    #[test]
    fn validate_rejects_bad_checksum() {
        let mut buf = [0u8; 1024];
        let total = build_image(&mut buf);
        buf[100] ^= 0xFF; // corrupt a TLV byte
        assert_eq!(validate(&buf[..total as usize]), Err(Error::Checksum));
    }

    #[test]
    fn validate_rejects_bad_magic() {
        let mut buf = [0u8; 1024];
        let total = build_image(&mut buf);
        buf[0] ^= 0xFF;
        assert_eq!(validate(&buf[..total as usize]), Err(Error::TooSmall));
    }

    #[test]
    fn validate_rejects_unsupported_major() {
        let mut buf = [0u8; 1024];
        let mut w = Writer::new(&mut buf, 2, 0, 0, ENTRY_ABI);
        w.add_tlv(tlv_type::EARLY_SERIAL, &[0u8; 24]).unwrap();
        let _ = w.finish().unwrap();
        // decode works (magic ok) but major mismatch
        let h = Header::decode(&buf).unwrap();
        assert_eq!(h.major, 2);
        // rebuild minimal valid-major image then flip major byte
        let mut buf2 = [0u8; 1024];
        let total = build_image(&mut buf2);
        buf2[8] = 9;
        assert_eq!(validate(&buf2[..total as usize]), Err(Error::Version));
    }

    #[test]
    fn validate_rejects_missing_required() {
        let mut buf = [0u8; 1024];
        let mut w = Writer::new(&mut buf, 1, 0, 0, ENTRY_ABI);
        w.add_tlv(tlv_type::EARLY_SERIAL, &[0u8; 24]).unwrap();
        let total = w.finish().unwrap();
        assert_eq!(
            validate(&buf[..total as usize]),
            Err(Error::MissingRequiredTlv)
        );
    }

    #[test]
    fn validate_rejects_bad_entry_abi() {
        let mut buf = [0u8; 1024];
        let mut w = Writer::new(&mut buf, 1, 0, 0, 99);
        w.add_tlv(tlv_type::EARLY_SERIAL, &[0u8; 24]).unwrap();
        let total = w.finish().unwrap();
        assert_eq!(validate(&buf[..total as usize]), Err(Error::Abi));
    }

    #[test]
    fn writer_rejects_unsorted() {
        let mut buf = [0u8; 1024];
        let mut w = Writer::new(&mut buf, 1, 0, 0, ENTRY_ABI);
        w.add_tlv(0x5, &[0u8; 8]).unwrap();
        assert_eq!(w.add_tlv(0x5, &[0u8; 8]), Err(BuildError::UnsortedTlv));
        assert_eq!(w.add_tlv(0x2, &[0u8; 8]), Err(BuildError::UnsortedTlv));
    }

    #[test]
    fn writer_rejects_overflow() {
        let mut buf = [0u8; 80]; // no room for any TLV
        let mut w = Writer::new(&mut buf, 1, 0, 0, ENTRY_ABI);
        assert_eq!(w.add_tlv(0x1, &[0u8; 16]), Err(BuildError::OutOfSpace));
    }

    #[test]
    fn tlv_alignment_pads_to_8() {
        let mut buf = [0u8; 256];
        let mut w = Writer::new(&mut buf, 1, 0, 0, ENTRY_ABI);
        w.add_tlv(0x1, &[1, 2, 3]).unwrap(); // len 3 -> padded record 16 bytes
        w.add_tlv(0x2, &[4, 5, 6, 7]).unwrap(); // len 4 -> padded record 16 bytes
        let total = w.finish().unwrap();
        let h = Header::decode(&buf).unwrap();
        assert_eq!(total, 64 + 16 + 16);
        let mut tlvs = Tlvs::new(&buf, h.tlv_offset, h.total_size);
        assert_eq!(tlvs.next().unwrap().1, &[1, 2, 3]);
        assert_eq!(tlvs.next().unwrap().1, &[4, 5, 6, 7]);
        assert!(tlvs.next().is_none());
    }

    #[test]
    fn checksum_ignores_checksum_field() {
        let mut buf = [0u8; 1024];
        let total = build_image(&mut buf);
        let a = compute_checksum(&buf[..total as usize]);
        buf[20] ^= 0x5A;
        buf[22] ^= 0xA5;
        let b = compute_checksum(&buf[..total as usize]);
        assert_eq!(a, b, "checksum must not depend on the checksum field bytes");
    }

    #[test]
    fn kernel_image_tlv_roundtrip() {
        let k = KernelImageTlv {
            image_phys_base: 1,
            image_phys_size: 2,
            image_virt_base: 3,
            image_virt_size: 4,
            entry_virt: 5,
            stack_base: 6,
            stack_size: 7,
            page_table_phys: 8,
        };
        assert_eq!(KernelImageTlv::decode(&k.encode()), Some(k));
    }

    /// Lock the on-the-wire field offsets so the loader cannot silently write
    /// a value into the wrong slot (regression guard for the M2 fix that
    /// stopped reporting `image_phys_size` from the *virtual* size).
    #[test]
    fn kernel_image_tlv_wire_layout() {
        let fields = [0x11u64, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];
        let mut raw = [0u8; 64];
        for (i, v) in fields.iter().enumerate() {
            raw[i * 8..i * 8 + 8].copy_from_slice(&v.to_le_bytes());
        }
        let k = KernelImageTlv::decode(&raw).expect("decode");
        assert_eq!(k.image_phys_base, 0x11);
        assert_eq!(k.image_phys_size, 0x22);
        assert_eq!(k.image_virt_base, 0x33);
        assert_eq!(k.image_virt_size, 0x44);
        assert_eq!(k.entry_virt, 0x55);
        assert_eq!(k.stack_base, 0x66);
        assert_eq!(k.stack_size, 0x77);
        assert_eq!(k.page_table_phys, 0x88);
        // phys and virt sizes are independent slots; distinct values must
        // survive a round trip (catches cross-wiring of the two size fields).
        let k2 = KernelImageTlv {
            image_phys_size: 0x1000,
            image_virt_size: 0x4000,
            ..k
        };
        assert_eq!(
            KernelImageTlv::decode(&k2.encode()),
            Some(k2),
            "phys/virt sizes must not be aliased"
        );
    }

    // -----------------------------------------------------------------------
    // Boot Protocol 1.1: boot modules (TLV 0x7) and INITFS.IMG
    // -----------------------------------------------------------------------

    #[test]
    fn protocol_minor_is_1() {
        assert_eq!(PROTOCOL_MAJOR, 1);
        assert_eq!(PROTOCOL_MINOR, 1);
        assert_eq!(tlv_type::BOOT_MODULES, 0x7);
    }

    fn align16(x: u64) -> u64 {
        (x + MODULE_ALIGN - 1) & !(MODULE_ALIGN - 1)
    }

    /// Two-module container: `init` then `child`, payloads arbitrary bytes.
    fn build_initfs(init: &[u8], child: &[u8]) -> Vec<u8> {
        let count = 2usize;
        let table_end = (INITFS_HEADER_LEN + count * MODULE_RECORD_LEN) as u64;
        let init_off = table_end;
        let child_off = align16(init_off + init.len() as u64);
        let mut data = Vec::new();
        data.extend_from_slice(b"CAELUMFS");
        data.extend_from_slice(&INITFS_VERSION.to_le_bytes());
        data.extend_from_slice(&(count as u32).to_le_bytes());
        for (name, off, payload) in [
            (&b"init"[..], init_off, init),
            (&b"child"[..], child_off, child),
        ] {
            let m = InitfsModule::new(name, MODULE_KIND_ELF, off, payload.len() as u64).unwrap();
            data.extend_from_slice(&m.encode());
        }
        while (data.len() as u64) < init_off {
            data.push(0);
        }
        data.extend_from_slice(init);
        while (data.len() as u64) < child_off {
            data.push(0);
        }
        data.extend_from_slice(child);
        data
    }

    #[test]
    fn boot_module_tlv_wire_layout() {
        let m = BootModule::new(b"child", MODULE_KIND_ELF, 0x1234_5678, 0x9abc).unwrap();
        let raw = m.encode();
        assert_eq!(&raw[0..8], &0x1234_5678u64.to_le_bytes());
        assert_eq!(&raw[8..16], &0x9abcu64.to_le_bytes());
        assert_eq!(&raw[16..20], &MODULE_KIND_ELF.to_le_bytes());
        assert_eq!(&raw[20..24], &5u32.to_le_bytes()); // name_len
        assert_eq!(&raw[24..29], b"child");
        assert_eq!(&raw[29..40], &[0u8; 11]);
        assert_eq!(BootModule::decode(&raw), Some(m));
    }

    #[test]
    fn boot_modules_payload_roundtrip() {
        let initfs = build_initfs(&[0xAA; 64], &[0xBB; 32]);
        let initfs = Initfs::parse(&initfs).expect("initfs");
        let base = 0x10_0000u64;
        let mut payload = [0u8; BOOT_MODULES_PREFIX_LEN + MAX_BOOT_MODULES * MODULE_RECORD_LEN];
        let len = initfs.to_boot_modules(base, &mut payload).unwrap();
        assert_eq!(len, BOOT_MODULES_PREFIX_LEN + 2 * MODULE_RECORD_LEN);
        assert_eq!(validate_boot_modules(&payload[..len]), Ok(2));
        let modules = BootModules::new(&payload[..len]).expect("modules");
        assert_eq!(modules.count(), 2);
        assert_eq!(modules.get(0).unwrap().name_bytes(), Some(&b"init"[..]));
        assert_eq!(
            modules.get(0).unwrap().phys,
            base + INITFS_HEADER_LEN as u64 + 2 * MODULE_RECORD_LEN as u64
        );
        assert_eq!(modules.get(0).unwrap().phys % MODULE_ALIGN, 0);
        assert_eq!(modules.get(0).unwrap().size, 64);
        assert_eq!(modules.get(1).unwrap().name_bytes(), Some(&b"child"[..]));
        assert_eq!(modules.find(b"child").unwrap().size, 32);
        assert!(modules.find(b"missing").is_none());
        assert_eq!(modules.get(2), None);
    }

    #[test]
    fn boot_modules_reject_malformed() {
        let mut payload = [0u8; BOOT_MODULES_PREFIX_LEN + MAX_BOOT_MODULES * MODULE_RECORD_LEN];
        let container = build_initfs(&[0u8; 16], &[0u8; 16]);
        let initfs = Initfs::parse(&container).unwrap();
        let len = initfs.to_boot_modules(0x10_0000, &mut payload).unwrap();

        // count 0
        let mut zero = payload;
        zero[0..4].copy_from_slice(&0u32.to_le_bytes());
        assert_eq!(
            validate_boot_modules(&zero[..len]),
            Err(ModuleError::BadCount)
        );
        // reserved word non-zero
        let mut res = payload;
        res[4] = 1;
        assert_eq!(
            validate_boot_modules(&res[..len]),
            Err(ModuleError::BadRecord)
        );
        // trailing bytes beyond the declared count
        assert_eq!(
            validate_boot_modules(&payload[..len + 8]),
            Err(ModuleError::Truncated)
        );
        assert_eq!(
            validate_boot_modules(&payload[..len - 1]),
            Err(ModuleError::Truncated)
        );
        // zero kind in the second record
        let mut kind = payload;
        kind[BOOT_MODULES_PREFIX_LEN + MODULE_RECORD_LEN + 16..][..4]
            .copy_from_slice(&0u32.to_le_bytes());
        assert_eq!(
            validate_boot_modules(&kind[..len]),
            Err(ModuleError::BadRecord)
        );
        // unaligned phys in the first record
        let mut phys = payload;
        phys[BOOT_MODULES_PREFIX_LEN] ^= 0x1;
        assert_eq!(
            validate_boot_modules(&phys[..len]),
            Err(ModuleError::BadAlign)
        );
        // duplicate module names
        let mut dup = payload;
        let second = BOOT_MODULES_PREFIX_LEN + MODULE_RECORD_LEN;
        let first_name: [u8; MODULE_NAME_LEN] = payload[BOOT_MODULES_PREFIX_LEN + 24..]
            [..MODULE_NAME_LEN]
            .try_into()
            .unwrap();
        dup[second + 24..second + 24 + MODULE_NAME_LEN].copy_from_slice(&first_name);
        let first_len = u32::from_le_bytes(
            payload[BOOT_MODULES_PREFIX_LEN + 20..][..4]
                .try_into()
                .unwrap(),
        );
        dup[second + 20..second + 24].copy_from_slice(&first_len.to_le_bytes());
        assert_eq!(
            validate_boot_modules(&dup[..len]),
            Err(ModuleError::BadName)
        );
    }

    #[test]
    fn initfs_container_roundtrip() {
        let data = build_initfs(&[0xAA; 37], &[0xBB; 21]);
        let initfs = Initfs::parse(&data).expect("parse");
        assert_eq!(initfs.count(), 2);
        let init = initfs.find(b"init").expect("init");
        let child = initfs.find(b"child").expect("child");
        assert_eq!(init.kind, MODULE_KIND_ELF);
        assert_eq!(init.size, 37);
        assert_eq!(init.offset % MODULE_ALIGN, 0);
        assert_eq!(initfs.data_of(&init).unwrap(), &[0xAA; 37]);
        assert_eq!(initfs.data_of(&child).unwrap(), &[0xBB; 21]);
    }

    #[test]
    fn initfs_record_wire_layout() {
        let m = InitfsModule::new(b"init", MODULE_KIND_ELF, 0x60, 0x30).unwrap();
        let raw = m.encode();
        assert_eq!(&raw[0..4], b"init");
        assert_eq!(&raw[4..16], &[0u8; 12]);
        assert_eq!(&raw[16..20], &MODULE_KIND_ELF.to_le_bytes());
        assert_eq!(&raw[20..24], &0u32.to_le_bytes()); // explicit reserved
        assert_eq!(&raw[24..32], &0x60u64.to_le_bytes());
        assert_eq!(&raw[32..40], &0x30u64.to_le_bytes());
        assert_eq!(InitfsModule::decode(&raw), Some(m));
    }

    #[test]
    fn initfs_rejects_bad_containers() {
        let good = build_initfs(&[0xAA; 16], &[0xBB; 16]);
        // magic
        let mut bad = good.clone();
        bad[0] ^= 0xFF;
        assert_eq!(Initfs::parse(&bad), Err(ModuleError::BadMagic));
        // version
        let mut bad = good.clone();
        bad[8..12].copy_from_slice(&2u32.to_le_bytes());
        assert_eq!(Initfs::parse(&bad), Err(ModuleError::BadVersion));
        // count 0 / too many
        let mut bad = good.clone();
        bad[12..16].copy_from_slice(&0u32.to_le_bytes());
        assert_eq!(Initfs::parse(&bad), Err(ModuleError::BadCount));
        let mut bad = good.clone();
        bad[12..16].copy_from_slice(&(MAX_BOOT_MODULES as u32 + 1).to_le_bytes());
        assert_eq!(Initfs::parse(&bad), Err(ModuleError::BadCount));
        // truncated header / table
        assert_eq!(
            Initfs::parse(&good[..INITFS_HEADER_LEN]),
            Err(ModuleError::Truncated)
        );
        // record reserved word non-zero
        let mut bad = good.clone();
        bad[INITFS_HEADER_LEN + 20] = 1;
        assert_eq!(Initfs::parse(&bad), Err(ModuleError::BadRecord));
        // unaligned offset
        let mut bad = good.clone();
        let off = INITFS_HEADER_LEN + 24;
        bad[off] = (u64::from_le_bytes(bad[off..off + 8].try_into().unwrap()) | 1).to_le_bytes()[0];
        assert_eq!(Initfs::parse(&bad), Err(ModuleError::BadRecord));
        // payload out of range
        let mut bad = good.clone();
        let size_at = INITFS_HEADER_LEN + 32;
        bad[size_at..size_at + 8].copy_from_slice(&0x1_0000u64.to_le_bytes());
        assert_eq!(Initfs::parse(&bad), Err(ModuleError::OutOfRange));
        // overlapping payloads (second module points at the first)
        let mut bad = good.clone();
        let first_off = u64::from_le_bytes(
            bad[INITFS_HEADER_LEN + 24..INITFS_HEADER_LEN + 32]
                .try_into()
                .unwrap(),
        );
        let second = INITFS_HEADER_LEN + MODULE_RECORD_LEN;
        bad[second + 24..second + 32].copy_from_slice(&first_off.to_le_bytes());
        assert_eq!(Initfs::parse(&bad), Err(ModuleError::Overlap));
    }

    #[test]
    fn validate_accepts_old_minor_loaders() {
        // A 1.0 loader image (minor 0) must still be accepted by a 1.1 kernel:
        // `validate` compares `major` only.
        let mut buf = [0u8; 1024];
        let mut w = Writer::new(&mut buf, PROTOCOL_MAJOR, 0, 0, ENTRY_ABI);
        let mm = MemoryMapTlv {
            desc_size: 48,
            desc_version: 1,
        };
        let mut mm_val = Vec::new();
        mm_val.extend_from_slice(&mm.encode());
        mm_val.extend_from_slice(&[0xAA; 48]);
        w.add_tlv(tlv_type::MEMORY_MAP, &mm_val).unwrap();
        w.add_tlv(
            tlv_type::KERNEL_IMAGE,
            &KernelImageTlv {
                image_phys_base: 0x10_0000,
                image_phys_size: 0x2_0000,
                image_virt_base: 0xFFFF_FFFF_8000_0000,
                image_virt_size: 0x2_0000,
                entry_virt: 0xFFFF_FFFF_8000_0000,
                stack_base: 0x20_0000,
                stack_size: 0x1_0000,
                page_table_phys: 0x30_0000,
            }
            .encode(),
        )
        .unwrap();
        w.add_tlv(tlv_type::EARLY_SERIAL, &[0u8; 24]).unwrap();
        let total = w.finish().unwrap();
        let h = validate(&buf[..total as usize]).expect("1.0 image must validate");
        assert_eq!(h.minor, 0);
        assert_eq!(h.tlv_count, 3);
    }

    #[test]
    fn validate_accepts_boot_modules_tlv() {
        let mut buf = [0u8; 2048];
        let mut w = Writer::new(&mut buf, PROTOCOL_MAJOR, PROTOCOL_MINOR, 0, ENTRY_ABI);
        let mm = MemoryMapTlv {
            desc_size: 48,
            desc_version: 1,
        };
        let mut mm_val = Vec::new();
        mm_val.extend_from_slice(&mm.encode());
        mm_val.extend_from_slice(&[0xAA; 48]);
        w.add_tlv(tlv_type::MEMORY_MAP, &mm_val).unwrap();
        w.add_tlv(
            tlv_type::KERNEL_IMAGE,
            &KernelImageTlv {
                image_phys_base: 0x10_0000,
                image_phys_size: 0x2_0000,
                image_virt_base: 0xFFFF_FFFF_8000_0000,
                image_virt_size: 0x2_0000,
                entry_virt: 0xFFFF_FFFF_8000_0000,
                stack_base: 0x20_0000,
                stack_size: 0x1_0000,
                page_table_phys: 0x30_0000,
            }
            .encode(),
        )
        .unwrap();
        w.add_tlv(tlv_type::EARLY_SERIAL, &[0u8; 24]).unwrap();
        w.add_tlv(tlv_type::LOADER_INFO, b"0.2.0").unwrap();
        let container = build_initfs(&[0xAA; 64], &[0xBB; 32]);
        let initfs = Initfs::parse(&container).unwrap();
        let mut payload = [0u8; BOOT_MODULES_PREFIX_LEN + MAX_BOOT_MODULES * MODULE_RECORD_LEN];
        let len = initfs.to_boot_modules(0x20_0000, &mut payload).unwrap();
        w.add_tlv(tlv_type::BOOT_MODULES, &payload[..len]).unwrap();
        let total = w.finish().unwrap();

        let image = &buf[..total as usize];
        let h = validate(image).expect("1.1 image must validate");
        assert_eq!(h.minor, 1);
        assert_eq!(h.tlv_count, 5);
        let raw = find_tlv(image, h.tlv_offset, h.total_size, tlv_type::BOOT_MODULES)
            .expect("boot modules TLV");
        let modules = BootModules::new(raw).expect("modules");
        assert_eq!(modules.count(), 2);
        assert_eq!(modules.find(b"init").unwrap().phys, 0x20_0000 + 96);
    }
}
