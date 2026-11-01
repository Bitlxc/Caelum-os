//! Minimal ELF64 parsing and boot-time validation for the CaelumOS UEFI
//! loader. `no_std`, zero dependencies, host-testable.
//!
//! Only what the M1 loader needs is implemented: ELF header + program header
//! validation, PT_LOAD iteration, and named-section lookup (used to find the
//! `.caelum.bootreq` boot-requirement metadata section).

#![no_std]
#![forbid(unsafe_code)]

#[cfg(test)]
extern crate std;

pub const ET_EXEC: u16 = 2;
/// Position-independent executable (M9d1 dynamic main program).
pub const ET_DYN: u16 = 3;
pub const EM_X86_64: u16 = 0x3E;
pub const PT_LOAD: u32 = 1;
/// Program interpreter path string (`PT_INTERP`).
pub const PT_INTERP: u32 = 3;
/// Dynamic linking information (`PT_DYNAMIC`, M9e shared-library closure).
pub const PT_DYNAMIC: u32 = 2;

/// Dynamic table tags needed by the kernel (M9e). Only `DT_NEEDED` is
/// interpreted; the kernel never applies relocations.
pub const DT_NULL: i64 = 0;
pub const DT_NEEDED: i64 = 1;
pub const DT_STRTAB: i64 = 5;
pub const DT_STRSZ: i64 = 10;

/// Upper bound on `DT_NEEDED` entries the kernel will accept.
pub const MAX_DYNAMIC_NEEDED: usize = 4;

pub const PF_X: u32 = 1;
pub const PF_W: u32 = 2;
pub const PF_R: u32 = 4;

/// Upper bound on PT_LOAD segments the loader will accept.
pub const MAX_LOAD_SEGMENTS: usize = 8;

/// Exclusive upper bound of the user-space (low canonical half) virtual
/// address range. Images mapped for ring 3 must lie entirely below this.
pub const USER_ADDR_LIMIT: u64 = 0x0000_8000_0000_0000;

/// `.caelum.bootreq` metadata: magic + protocol major/minor + entry ABI.
pub const BOOTREQ_MAGIC: &[u8; 8] = b"CBTREQ01";
pub const BOOTREQ_LEN: usize = 16;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BootReq {
    pub major: u16,
    pub minor: u16,
    pub entry_abi: u32,
}

/// Parse a `.caelum.bootreq` section payload.
pub fn parse_bootreq(sec: &[u8]) -> Option<BootReq> {
    if sec.len() < BOOTREQ_LEN || &sec[0..8] != BOOTREQ_MAGIC {
        return None;
    }
    Some(BootReq {
        major: u16::from_le_bytes(sec[8..10].try_into().ok()?),
        minor: u16::from_le_bytes(sec[10..12].try_into().ok()?),
        entry_abi: u32::from_le_bytes(sec[12..16].try_into().ok()?),
    })
}

impl BootReq {
    /// Boot Protocol compatibility rule (agents.md §5.3 rule 6): the loader
    /// must implement the same `major` and `entry_abi`, and its `minor` must
    /// be **at least** the kernel's requirement (never an equality check).
    pub fn is_compatible(
        &self,
        loader_major: u16,
        loader_minor: u16,
        loader_entry_abi: u32,
    ) -> bool {
        self.major == loader_major
            && self.entry_abi == loader_entry_abi
            && self.minor <= loader_minor
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    BadMagic,
    /// EI_CLASS != ELFCLASS64.
    BadClass,
    /// EI_DATA != little-endian.
    BadEndian,
    BadVersion,
    /// e_type is not ET_EXEC.
    BadType,
    /// e_machine is not x86-64.
    BadMachine,
    Truncated,
    /// Program/section header table out of bounds.
    BadTable,
    /// No PT_LOAD segment at all.
    NoLoadSegments,
    /// A PT_LOAD segment is malformed.
    BadLoadSegment,
    /// Entry point is not covered by any PT_LOAD virtual range.
    BadEntry,
    /// Segment virtual range exceeds the user (low canonical half) limit.
    HighAddress,
    /// Segment is both writable and executable (W^X violation).
    WritableExecutable,
    /// Two PT_LOAD segments claim overlapping page-aligned ranges.
    OverlappingSegments,
    /// `PT_DYNAMIC`/`DT_STRTAB`/`DT_NEEDED` is malformed (M9e).
    BadDynamic,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProgramHeader {
    pub p_type: u32,
    pub flags: u32,
    pub offset: u64,
    pub vaddr: u64,
    pub paddr: u64,
    pub filesz: u64,
    pub memsz: u64,
    pub align: u64,
}

#[derive(Debug, Clone, Copy)]
struct SectionHeader {
    name_off: u32,
    sh_offset: u64,
    sh_size: u64,
}

/// Page-aligned virtual span covered by all PT_LOAD segments.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LoadSpan {
    /// Lowest page-aligned `p_vaddr` over all PT_LOAD segments.
    pub min_vaddr: u64,
    /// Page-aligned span size (`max_end - min_vaddr`), a multiple of 4096.
    pub span_size: u64,
}

/// Up to [`MAX_DYNAMIC_NEEDED`] `DT_NEEDED` library names from an ELF image,
/// in dynamic-table order, without their trailing NULs (M9e).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DynamicLibraryList<'a> {
    names: [&'a [u8]; MAX_DYNAMIC_NEEDED],
    count: usize,
}

impl<'a> DynamicLibraryList<'a> {
    fn empty() -> Self {
        Self {
            names: [&[][..]; MAX_DYNAMIC_NEEDED],
            count: 0,
        }
    }

    pub const fn len(&self) -> usize {
        self.count
    }

    pub const fn is_empty(&self) -> bool {
        self.count == 0
    }

    pub fn get(&self, index: usize) -> Option<&'a [u8]> {
        if index < self.count {
            Some(self.names[index])
        } else {
            None
        }
    }
}

/// A parsed ELF64 image borrowed from `data`.
#[derive(Debug, Clone, Copy)]
pub struct Elf64<'a> {
    data: &'a [u8],
    etype: u16,
    pub entry: u64,
    phoff: u64,
    phentsize: u16,
    phnum: u16,
    shoff: u64,
    shentsize: u16,
    shnum: u16,
    shstrndx: u16,
}

fn get<const N: usize>(data: &[u8], at: usize) -> Option<[u8; N]> {
    data.get(at..)?.get(..N)?.try_into().ok()
}

fn parse_phdr(data: &[u8], at: usize) -> Option<ProgramHeader> {
    Some(ProgramHeader {
        p_type: u32::from_le_bytes(get::<4>(data, at)?),
        flags: u32::from_le_bytes(get::<4>(data, at + 4)?),
        offset: u64::from_le_bytes(get::<8>(data, at + 8)?),
        vaddr: u64::from_le_bytes(get::<8>(data, at + 16)?),
        paddr: u64::from_le_bytes(get::<8>(data, at + 24)?),
        filesz: u64::from_le_bytes(get::<8>(data, at + 32)?),
        memsz: u64::from_le_bytes(get::<8>(data, at + 40)?),
        align: u64::from_le_bytes(get::<8>(data, at + 48)?),
    })
}

fn parse_shdr(data: &[u8], at: usize) -> Option<SectionHeader> {
    Some(SectionHeader {
        name_off: u32::from_le_bytes(get::<4>(data, at)?),
        sh_offset: u64::from_le_bytes(get::<8>(data, at + 24)?),
        sh_size: u64::from_le_bytes(get::<8>(data, at + 32)?),
    })
}

impl<'a> Elf64<'a> {
    /// Parse and minimally validate the ELF header (magic, class, endianness,
    /// version, and table bounds).
    pub fn parse(data: &'a [u8]) -> Result<Elf64<'a>, Error> {
        if data.len() < 64 {
            return Err(Error::Truncated);
        }
        if data[0..4] != [0x7F, b'E', b'L', b'F'] {
            return Err(Error::BadMagic);
        }
        if data[4] != 2 {
            return Err(Error::BadClass);
        }
        if data[5] != 1 {
            return Err(Error::BadEndian);
        }
        if data[6] != 1 {
            return Err(Error::BadVersion);
        }
        let e_type = u16::from_le_bytes(get::<2>(data, 16).ok_or(Error::Truncated)?);
        let machine = u16::from_le_bytes(get::<2>(data, 18).ok_or(Error::Truncated)?);
        let version = u32::from_le_bytes(get::<4>(data, 20).ok_or(Error::Truncated)?);
        if e_type != ET_EXEC && e_type != ET_DYN {
            return Err(Error::BadType);
        }
        if machine != EM_X86_64 {
            return Err(Error::BadMachine);
        }
        if version != 1 {
            return Err(Error::BadVersion);
        }
        let entry = u64::from_le_bytes(get::<8>(data, 24).ok_or(Error::Truncated)?);
        let phoff = u64::from_le_bytes(get::<8>(data, 32).ok_or(Error::Truncated)?);
        let shoff = u64::from_le_bytes(get::<8>(data, 40).ok_or(Error::Truncated)?);
        let phentsize = u16::from_le_bytes(get::<2>(data, 54).ok_or(Error::Truncated)?);
        let phnum = u16::from_le_bytes(get::<2>(data, 56).ok_or(Error::Truncated)?);
        let shentsize = u16::from_le_bytes(get::<2>(data, 58).ok_or(Error::Truncated)?);
        let shnum = u16::from_le_bytes(get::<2>(data, 60).ok_or(Error::Truncated)?);
        let shstrndx = u16::from_le_bytes(get::<2>(data, 62).ok_or(Error::Truncated)?);
        if u16::from_le_bytes(get::<2>(data, 52).ok_or(Error::Truncated)?) < 64 {
            return Err(Error::Truncated);
        }
        // Table bounds (checked arithmetic; phnum==0 means "no program
        // headers", which the boot validation rejects).
        let ph_end = phoff
            .checked_add(u64::from(phnum) * u64::from(phentsize))
            .ok_or(Error::BadTable)?;
        if phnum > 0 && (phentsize < 56 || ph_end > data.len() as u64) {
            return Err(Error::BadTable);
        }
        let sh_end = shoff
            .checked_add(u64::from(shnum) * u64::from(shentsize))
            .ok_or(Error::BadTable)?;
        if shnum > 0 && (shentsize < 64 || sh_end > data.len() as u64) {
            return Err(Error::BadTable);
        }
        if shnum > 0 && u32::from(shstrndx) >= u32::from(shnum) {
            return Err(Error::BadTable);
        }
        Ok(Elf64 {
            data,
            etype: e_type,
            entry,
            phoff,
            phentsize,
            phnum,
            shoff,
            shentsize,
            shnum,
            shstrndx,
        })
    }

    pub fn phnum(&self) -> usize {
        usize::from(self.phnum)
    }

    pub fn phdr(&self, index: usize) -> Option<ProgramHeader> {
        if index >= usize::from(self.phnum) {
            return None;
        }
        let at = self.phoff as usize + index * usize::from(self.phentsize);
        parse_phdr(self.data, at)
    }

    /// Call `f` for every PT_LOAD segment, in file order.
    pub fn for_each_load(
        &self,
        mut f: impl FnMut(ProgramHeader) -> Result<(), Error>,
    ) -> Result<(), Error> {
        for i in 0..self.phnum() {
            let ph = self.phdr(i).ok_or(Error::BadTable)?;
            if ph.p_type == PT_LOAD {
                f(ph)?;
            }
        }
        Ok(())
    }

    /// Full boot-time validation required by the Boot Protocol: entry covered
    /// by a PT_LOAD, sane segment geometry, file bounds, page alignment rule
    /// `(vaddr % 4096) == (offset % 4096)`.
    pub fn validate_for_boot(&self) -> Result<(), Error> {
        let mut loads = 0usize;
        let mut entry_ok = false;
        self.for_each_load(|ph| {
            loads += 1;
            if loads > MAX_LOAD_SEGMENTS {
                return Err(Error::BadLoadSegment);
            }
            if ph.memsz == 0 || ph.filesz > ph.memsz {
                return Err(Error::BadLoadSegment);
            }
            if ph
                .offset
                .checked_add(ph.filesz)
                .filter(|&end| end <= self.data.len() as u64)
                .is_none()
            {
                return Err(Error::BadLoadSegment);
            }
            ph.vaddr
                .checked_add(ph.memsz)
                .ok_or(Error::BadLoadSegment)?;
            if ph.vaddr == 0 || (ph.vaddr & 0xFFF) != (ph.offset & 0xFFF) {
                return Err(Error::BadLoadSegment);
            }
            if self.entry >= ph.vaddr && self.entry < ph.vaddr + ph.memsz {
                entry_ok = true;
            }
            Ok(())
        })?;
        if loads == 0 {
            return Err(Error::NoLoadSegments);
        }
        if !entry_ok {
            return Err(Error::BadEntry);
        }
        Ok(())
    }

    /// Validation required before mapping an image into a *user* address
    /// space (M4: boot modules and process images share this one path).
    ///
    /// Strictly stricter than [`Elf64::validate_for_boot`]: every check of that
    /// function is repeated here (never relaxed), plus:
    /// low-half address limit, W^X, entry inside an **executable** segment, and
    /// no overlapping page-aligned segment ranges.
    pub fn validate_for_user(&self) -> Result<(), Error> {
        let mut loads = 0usize;
        let mut entry_ok = false;
        let mut ranges = [(0u64, 0u64); MAX_LOAD_SEGMENTS];
        self.for_each_load(|ph| {
            loads += 1;
            if loads > MAX_LOAD_SEGMENTS {
                return Err(Error::BadLoadSegment);
            }
            if ph.memsz == 0 || ph.filesz > ph.memsz {
                return Err(Error::BadLoadSegment);
            }
            if ph
                .offset
                .checked_add(ph.filesz)
                .filter(|&end| end <= self.data.len() as u64)
                .is_none()
            {
                return Err(Error::BadLoadSegment);
            }
            let end = ph
                .vaddr
                .checked_add(ph.memsz)
                .ok_or(Error::BadLoadSegment)?;
            if ph.vaddr == 0 || (ph.vaddr & 0xFFF) != (ph.offset & 0xFFF) {
                return Err(Error::BadLoadSegment);
            }
            if end > USER_ADDR_LIMIT {
                return Err(Error::HighAddress);
            }
            if ph.flags & PF_W != 0 && ph.flags & PF_X != 0 {
                return Err(Error::WritableExecutable);
            }
            if ph.flags & PF_X != 0 && self.entry >= ph.vaddr && self.entry < end {
                entry_ok = true;
            }
            let page_start = ph.vaddr & !0xFFF;
            let page_end = end.checked_add(0xFFF).ok_or(Error::BadLoadSegment)? & !0xFFF;
            ranges[loads - 1] = (page_start, page_end);
            Ok(())
        })?;
        if loads == 0 {
            return Err(Error::NoLoadSegments);
        }
        if !entry_ok {
            return Err(Error::BadEntry);
        }
        for i in 0..loads {
            for j in (i + 1)..loads {
                let (a_start, a_end) = ranges[i];
                let (b_start, b_end) = ranges[j];
                if a_start < b_end && b_start < a_end {
                    return Err(Error::OverlappingSegments);
                }
            }
        }
        Ok(())
    }

    /// ELF file type (`ET_EXEC` or `ET_DYN`).
    pub const fn elf_type(&self) -> u16 {
        self.etype
    }

    /// Whether this image is a position-independent executable (M9d1).
    pub const fn is_dynamic(&self) -> bool {
        self.etype == ET_DYN
    }

    /// Program-header table file offset (`e_phoff`).
    pub const fn phoff(&self) -> u64 {
        self.phoff
    }

    /// Program-header entry size (`e_phentsize`).
    pub const fn phentsize(&self) -> u16 {
        self.phentsize
    }

    /// Program interpreter path from `PT_INTERP`, without its trailing NUL.
    ///
    /// The CaelumOS kernel treats the string as the interpreter's VFS path, so
    /// it must be NUL-terminated inside the file image and non-empty.
    pub fn interpreter(&self) -> Option<&'a [u8]> {
        for index in 0..self.phnum() {
            let ph = self.phdr(index)?;
            if ph.p_type != PT_INTERP || ph.filesz == 0 {
                continue;
            }
            let start = usize::try_from(ph.offset).ok()?;
            let len = usize::try_from(ph.filesz).ok()?;
            let end = start.checked_add(len)?;
            let bytes = self.data.get(start..end)?;
            let nul = bytes.iter().position(|byte| *byte == 0)?;
            if nul == 0 {
                return None;
            }
            return Some(&bytes[..nul]);
        }
        None
    }

    /// Shared segment validation for biased (`ET_DYN`) images.
    ///
    /// When `require_entry` is true the image behaves as an executable and the
    /// biased `e_entry` must fall inside a `PF_X` segment. Shared objects have
    /// no process entry point (`e_entry == 0`), so the library path passes
    /// `false`; every other rule stays identical.
    fn validate_user_segments(&self, bias: u64, require_entry: bool) -> Result<(), Error> {
        if bias == 0 || (bias & 0xFFF) != 0 {
            return Err(Error::BadLoadSegment);
        }
        let entry = if require_entry {
            bias.checked_add(self.entry).ok_or(Error::BadEntry)?
        } else {
            0
        };
        let mut loads = 0usize;
        let mut entry_ok = !require_entry;
        let mut ranges = [(0u64, 0u64); MAX_LOAD_SEGMENTS];
        self.for_each_load(|ph| {
            loads += 1;
            if loads > MAX_LOAD_SEGMENTS {
                return Err(Error::BadLoadSegment);
            }
            if ph.memsz == 0 || ph.filesz > ph.memsz {
                return Err(Error::BadLoadSegment);
            }
            if ph
                .offset
                .checked_add(ph.filesz)
                .filter(|&end| end <= self.data.len() as u64)
                .is_none()
            {
                return Err(Error::BadLoadSegment);
            }
            let start = bias.checked_add(ph.vaddr).ok_or(Error::BadLoadSegment)?;
            let end = start.checked_add(ph.memsz).ok_or(Error::BadLoadSegment)?;
            if (start & 0xFFF) != (ph.offset & 0xFFF) {
                return Err(Error::BadLoadSegment);
            }
            if end > USER_ADDR_LIMIT {
                return Err(Error::HighAddress);
            }
            if ph.flags & PF_W != 0 && ph.flags & PF_X != 0 {
                return Err(Error::WritableExecutable);
            }
            if require_entry && ph.flags & PF_X != 0 && entry >= start && entry < end {
                entry_ok = true;
            }
            let page_start = start & !0xFFF;
            let page_end = end.checked_add(0xFFF).ok_or(Error::BadLoadSegment)? & !0xFFF;
            ranges[loads - 1] = (page_start, page_end);
            Ok(())
        })?;
        if loads == 0 {
            return Err(Error::NoLoadSegments);
        }
        if !entry_ok {
            return Err(Error::BadEntry);
        }
        for i in 0..loads {
            for j in (i + 1)..loads {
                let (a_start, a_end) = ranges[i];
                let (b_start, b_end) = ranges[j];
                if a_start < b_end && b_start < a_end {
                    return Err(Error::OverlappingSegments);
                }
            }
        }
        Ok(())
    }

    /// Validation required before mapping an **ET_DYN** image at `bias`.
    ///
    /// Every check of [`Elf64::validate_for_user`] is repeated with the load
    /// bias applied to `p_vaddr` and `e_entry`, except that `p_vaddr == 0` is
    /// legal: on x86-64 a PIE may place its first segment at virtual address
    /// `bias`. The bias itself must be page-aligned and non-zero, because the
    /// kernel never maps a PIE at address zero.
    pub fn validate_for_user_dynamic(&self, bias: u64) -> Result<(), Error> {
        if self.etype != ET_DYN {
            return Err(Error::BadType);
        }
        self.validate_user_segments(bias, true)
    }

    /// Validation required before mapping an **ET_DYN shared object** at `bias`.
    ///
    /// A shared object has no process entry point, so `e_entry` is not required
    /// to lie in an executable segment. Every segment, address-limit,
    /// permission, offset-congruence and overlap rule of
    /// [`Elf64::validate_for_user_dynamic`] still applies.
    pub fn validate_for_shared_object(&self, bias: u64) -> Result<(), Error> {
        if self.etype != ET_DYN {
            return Err(Error::BadType);
        }
        self.validate_user_segments(bias, false)
    }

    /// Page-aligned `[min_vaddr, min_vaddr + span_size)` span that physically
    /// holds the whole image: every PT_LOAD segment is placed at
    /// `kernel_phys + (align_down(p_vaddr) - min_vaddr)`, so the physical
    /// allocation must be exactly `span_size` bytes. `validate_for_boot` must
    /// have passed (nonempty, in-bounds, non-overflowing segments).
    pub fn load_span(&self) -> Result<LoadSpan, Error> {
        let mut min_vaddr = u64::MAX;
        let mut max_end = 0u64;
        let mut loads = 0usize;
        self.for_each_load(|ph| {
            loads += 1;
            if loads > MAX_LOAD_SEGMENTS {
                return Err(Error::BadLoadSegment);
            }
            if ph.memsz == 0 || ph.filesz > ph.memsz {
                return Err(Error::BadLoadSegment);
            }
            let vaddr_page = ph.vaddr & !0xFFF;
            let end = ph
                .vaddr
                .checked_add(ph.memsz)
                .ok_or(Error::BadLoadSegment)?
                .checked_add(0xFFF)
                .ok_or(Error::BadLoadSegment)?
                & !0xFFF;
            min_vaddr = min_vaddr.min(vaddr_page);
            max_end = max_end.max(end);
            Ok(())
        })?;
        if loads == 0 {
            return Err(Error::NoLoadSegments);
        }
        Ok(LoadSpan {
            min_vaddr,
            span_size: max_end - min_vaddr,
        })
    }

    /// The `PT_DYNAMIC` program header, when the image has one (M9e).
    pub fn pt_dynamic(&self) -> Option<ProgramHeader> {
        for index in 0..self.phnum() {
            let ph = self.phdr(index)?;
            if ph.p_type == PT_DYNAMIC {
                return Some(ph);
            }
        }
        None
    }

    /// Translate a virtual address that lives in a file-backed `PT_LOAD`
    /// segment into its offset in the ELF image bytes (M9e: `DT_STRTAB` points
    /// into a load segment, and the kernel has the whole image file staged).
    pub fn vaddr_to_file(&self, vaddr: u64) -> Result<usize, Error> {
        let mut found = None;
        self.for_each_load(|ph| {
            if found.is_none() && vaddr >= ph.vaddr && vaddr - ph.vaddr < ph.filesz {
                let delta = vaddr - ph.vaddr;
                let offset = ph.offset.checked_add(delta).ok_or(Error::BadTable)?;
                found = Some(usize::try_from(offset).map_err(|_| Error::BadTable)?);
            }
            Ok(())
        })?;
        found.ok_or(Error::BadTable)
    }

    /// `DT_NEEDED` library names, in table order, without trailing NULs.
    ///
    /// An image with no `PT_DYNAMIC` (the M9d1 static-interpreter closure) or
    /// an empty dynamic table has no needed libraries and returns an empty
    /// list. Malformed tables — missing `DT_STRTAB`/`DT_STRSZ`, a needed name
    /// outside the string table, a missing NUL, or more than
    /// [`MAX_DYNAMIC_NEEDED`] entries — are rejected with [`Error::BadDynamic`].
    pub fn needed_libraries(&self) -> Result<DynamicLibraryList<'a>, Error> {
        let mut list = DynamicLibraryList::empty();
        let Some(dynamic) = self.pt_dynamic() else {
            return Ok(list);
        };
        if dynamic.filesz == 0 || dynamic.filesz % 16 != 0 {
            return Err(Error::BadDynamic);
        }
        let start = usize::try_from(dynamic.offset).map_err(|_| Error::BadDynamic)?;
        let len = usize::try_from(dynamic.filesz).map_err(|_| Error::BadDynamic)?;
        let end = start.checked_add(len).ok_or(Error::BadDynamic)?;
        let table = self.data.get(start..end).ok_or(Error::BadDynamic)?;
        let mut needed = [0u64; MAX_DYNAMIC_NEEDED];
        let mut needed_count = 0usize;
        let mut strtab = None;
        let mut strsz = None;
        for entry in table.chunks_exact(16) {
            let bytes: [u8; 8] = entry[0..8].try_into().map_err(|_| Error::BadDynamic)?;
            let tag = i64::from_le_bytes(bytes);
            let bytes: [u8; 8] = entry[8..16].try_into().map_err(|_| Error::BadDynamic)?;
            let value = u64::from_le_bytes(bytes);
            match tag {
                DT_NULL => break,
                DT_NEEDED => {
                    if needed_count >= MAX_DYNAMIC_NEEDED {
                        return Err(Error::BadDynamic);
                    }
                    needed[needed_count] = value;
                    needed_count += 1;
                }
                DT_STRTAB => strtab = Some(value),
                DT_STRSZ => strsz = Some(value),
                _ => {}
            }
        }
        if needed_count == 0 {
            return Ok(list);
        }
        let strtab_vaddr = strtab.ok_or(Error::BadDynamic)?;
        let strsz =
            usize::try_from(strsz.ok_or(Error::BadDynamic)?).map_err(|_| Error::BadDynamic)?;
        let strtab_offset = self
            .vaddr_to_file(strtab_vaddr)
            .map_err(|_| Error::BadDynamic)?;
        let strtab_end = strtab_offset.checked_add(strsz).ok_or(Error::BadDynamic)?;
        let strtab_bytes = self
            .data
            .get(strtab_offset..strtab_end)
            .ok_or(Error::BadDynamic)?;
        for (index, offset) in needed[..needed_count].iter().enumerate() {
            let offset = usize::try_from(*offset).map_err(|_| Error::BadDynamic)?;
            if offset >= strsz {
                return Err(Error::BadDynamic);
            }
            let tail = &strtab_bytes[offset..];
            let nul = tail
                .iter()
                .position(|byte| *byte == 0)
                .ok_or(Error::BadDynamic)?;
            if nul == 0 {
                return Err(Error::BadDynamic);
            }
            list.names[index] = &tail[..nul];
            list.count += 1;
        }
        Ok(list)
    }

    fn section_content(&self, index: usize) -> Option<&'a [u8]> {
        if index >= usize::from(self.shnum) {
            return None;
        }
        let at = self.shoff as usize + index * usize::from(self.shentsize);
        let sh = parse_shdr(self.data, at)?;
        let start = usize::try_from(sh.sh_offset).ok()?;
        let size = usize::try_from(sh.sh_size).ok()?;
        self.data.get(start..start.checked_add(size)?)
    }

    /// Look up a section by name (via the section-header string table).
    pub fn section(&self, name: &str) -> Option<&'a [u8]> {
        if self.shnum == 0 {
            return None;
        }
        let strtab = self.section_content(usize::from(self.shstrndx))?;
        for i in 0..usize::from(self.shnum) {
            let at = self.shoff as usize + i * usize::from(self.shentsize);
            let sh = parse_shdr(self.data, at)?;
            let no = sh.name_off as usize;
            if no >= strtab.len() {
                continue;
            }
            let end = strtab[no..]
                .iter()
                .position(|&b| b == 0)
                .map(|p| no + p)
                .unwrap_or(strtab.len());
            if strtab.get(no..end) == Some(name.as_bytes()) {
                return self.section_content(i);
            }
        }
        None
    }

    /// Find and parse the `.caelum.bootreq` section.
    pub fn boot_requirements(&self) -> Result<BootReq, Error> {
        let sec = self.section(".caelum.bootreq").ok_or(Error::BadTable)?;
        parse_bootreq(sec).ok_or(Error::BadTable)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::vec;
    use std::vec::Vec;

    const VBASE: u64 = 0xFFFF_FFFF_8000_0000;
    /// Low-half link address used by the user-space validation tests.
    const UBASE: u64 = 0x0040_0000;

    /// Build a small but valid ET_EXEC x86-64 ELF with two PT_LOAD segments
    /// and a `.caelum.bootreq` section.
    fn make_test_elf() -> Vec<u8> {
        make_test_elf_at(VBASE)
    }

    /// Same synthetic image, linkable at an arbitrary base address.
    fn make_test_elf_at(vbase: u64) -> Vec<u8> {
        let mut b = vec![0u8; 0x3200];
        // ELF header
        b[0..4].copy_from_slice(&[0x7F, b'E', b'L', b'F']);
        b[4] = 2; // class 64
        b[5] = 1; // little-endian
        b[6] = 1; // version
        b[16..18].copy_from_slice(&ET_EXEC.to_le_bytes());
        b[18..20].copy_from_slice(&EM_X86_64.to_le_bytes());
        b[20..24].copy_from_slice(&1u32.to_le_bytes());
        b[24..32].copy_from_slice(&(vbase + 0x40).to_le_bytes()); // entry
        let phoff = 64u64;
        let shoff = 64 + 2 * 56u64;
        b[32..40].copy_from_slice(&phoff.to_le_bytes());
        b[40..48].copy_from_slice(&shoff.to_le_bytes());
        b[52..54].copy_from_slice(&64u16.to_le_bytes()); // ehsize
        b[54..56].copy_from_slice(&56u16.to_le_bytes()); // phentsize
        b[56..58].copy_from_slice(&2u16.to_le_bytes()); // phnum
        b[58..60].copy_from_slice(&64u16.to_le_bytes()); // shentsize
        b[60..62].copy_from_slice(&3u16.to_le_bytes()); // shnum
        b[62..64].copy_from_slice(&2u16.to_le_bytes()); // shstrndx
        // Program header 0: text (R+X)
        let ph0 = phoff as usize;
        b[ph0..ph0 + 4].copy_from_slice(&PT_LOAD.to_le_bytes());
        b[ph0 + 4..ph0 + 8].copy_from_slice(&(PF_R | PF_X).to_le_bytes());
        b[ph0 + 8..ph0 + 16].copy_from_slice(&0x1000u64.to_le_bytes()); // offset
        b[ph0 + 16..ph0 + 24].copy_from_slice(&vbase.to_le_bytes()); // vaddr
        b[ph0 + 24..ph0 + 32].copy_from_slice(&vbase.to_le_bytes()); // paddr
        b[ph0 + 32..ph0 + 40].copy_from_slice(&0x100u64.to_le_bytes()); // filesz
        b[ph0 + 40..ph0 + 48].copy_from_slice(&0x100u64.to_le_bytes()); // memsz
        b[ph0 + 48..ph0 + 56].copy_from_slice(&0x1000u64.to_le_bytes()); // align
        // Program header 1: data (R+W) with bss
        let ph1 = ph0 + 56;
        b[ph1..ph1 + 4].copy_from_slice(&PT_LOAD.to_le_bytes());
        b[ph1 + 4..ph1 + 8].copy_from_slice(&(PF_R | PF_W).to_le_bytes());
        b[ph1 + 8..ph1 + 16].copy_from_slice(&0x2000u64.to_le_bytes());
        b[ph1 + 16..ph1 + 24].copy_from_slice(&(vbase + 0x1000).to_le_bytes());
        b[ph1 + 24..ph1 + 32].copy_from_slice(&(vbase + 0x1000).to_le_bytes());
        b[ph1 + 32..ph1 + 40].copy_from_slice(&0x80u64.to_le_bytes());
        b[ph1 + 40..ph1 + 48].copy_from_slice(&0x100u64.to_le_bytes());
        b[ph1 + 48..ph1 + 56].copy_from_slice(&0x1000u64.to_le_bytes());
        // Section header 1: .caelum.bootreq
        let s1 = shoff as usize + 64;
        b[s1 + 4..s1 + 8].copy_from_slice(&1u32.to_le_bytes()); // SHT_PROGBITS
        b[s1 + 24..s1 + 32].copy_from_slice(&0x3000u64.to_le_bytes()); // offset
        b[s1 + 32..s1 + 40].copy_from_slice(&16u64.to_le_bytes()); // size
        // Section header 2: .shstrtab
        let s2 = s1 + 64;
        b[s2 + 4..s2 + 8].copy_from_slice(&3u32.to_le_bytes()); // SHT_STRTAB
        b[s2 + 24..s2 + 32].copy_from_slice(&0x3100u64.to_le_bytes());
        b[s2 + 32..s2 + 40].copy_from_slice(&26u64.to_le_bytes());
        // .caelum.bootreq content: magic, major 1, minor 0, entry_abi 1
        let req = 0x3000usize;
        b[req..req + 8].copy_from_slice(BOOTREQ_MAGIC);
        b[req + 8..req + 10].copy_from_slice(&1u16.to_le_bytes());
        b[req + 10..req + 12].copy_from_slice(&0u16.to_le_bytes());
        b[req + 12..req + 16].copy_from_slice(&1u32.to_le_bytes());
        // shstrtab content
        let strs: &[u8] = b"\0.caelum.bootreq\0.shstrtab\0";
        b[0x3100..0x3100 + strs.len()].copy_from_slice(strs);
        // section 1 name offset = 1 (".caelum.bootreq")
        b[s1..s1 + 4].copy_from_slice(&1u32.to_le_bytes());
        // section 2 name offset = 17 (".shstrtab")
        b[s2..s2 + 4].copy_from_slice(&17u32.to_le_bytes());
        b
    }

    #[test]
    fn parses_valid_elf() {
        let b = make_test_elf();
        let elf = Elf64::parse(&b).expect("parse");
        assert_eq!(elf.entry, VBASE + 0x40);
        assert_eq!(elf.phnum(), 2);
        elf.validate_for_boot().expect("validate_for_boot");
        let req = elf.boot_requirements().expect("bootreq");
        assert_eq!(req.major, 1);
        assert_eq!(req.minor, 0);
        assert_eq!(req.entry_abi, 1);
    }

    #[test]
    fn iterates_load_segments() {
        let b = make_test_elf();
        let elf = Elf64::parse(&b).unwrap();
        let mut n = 0;
        elf.for_each_load(|ph| {
            assert_eq!(ph.p_type, PT_LOAD);
            n += 1;
            Ok(())
        })
        .unwrap();
        assert_eq!(n, 2);
    }

    #[test]
    fn rejects_bad_magic() {
        let mut b = make_test_elf();
        b[0] = 0;
        assert_eq!(Elf64::parse(&b).unwrap_err(), Error::BadMagic);
    }

    #[test]
    fn rejects_bad_class() {
        let mut b = make_test_elf();
        b[4] = 1;
        assert_eq!(Elf64::parse(&b).unwrap_err(), Error::BadClass);
    }

    #[test]
    fn rejects_bad_machine() {
        let mut b = make_test_elf();
        b[18] = 0x28; // EM_AARCH64
        assert_eq!(Elf64::parse(&b).unwrap_err(), Error::BadMachine);
    }

    #[test]
    fn rejects_bad_type() {
        let mut b = make_test_elf();
        b[16] = 1; // ET_REL: neither a loadable executable nor a PIE
        assert_eq!(Elf64::parse(&b).unwrap_err(), Error::BadType);
    }

    #[test]
    fn rejects_entry_not_covered() {
        let mut b = make_test_elf();
        b[24..32].copy_from_slice(&0xFFFF_FFFF_9000_0000u64.to_le_bytes());
        let elf = Elf64::parse(&b).unwrap();
        assert_eq!(elf.validate_for_boot().unwrap_err(), Error::BadEntry);
    }

    #[test]
    fn rejects_filesz_beyond_file() {
        let mut b = make_test_elf();
        let ph0 = 64;
        b[ph0 + 32..ph0 + 40].copy_from_slice(&0x100_0000u64.to_le_bytes()); // filesz
        let elf = Elf64::parse(&b).unwrap();
        assert_eq!(elf.validate_for_boot().unwrap_err(), Error::BadLoadSegment);
    }

    #[test]
    fn rejects_filesz_gt_memsz() {
        let mut b = make_test_elf();
        let ph1 = 64 + 56;
        b[ph1 + 32..ph1 + 40].copy_from_slice(&0x200u64.to_le_bytes()); // filesz > memsz
        let elf = Elf64::parse(&b).unwrap();
        assert_eq!(elf.validate_for_boot().unwrap_err(), Error::BadLoadSegment);
    }

    #[test]
    fn rejects_misaligned_vaddr() {
        let mut b = make_test_elf();
        let ph0 = 64;
        b[ph0 + 16..ph0 + 24].copy_from_slice(&(VBASE + 0x800).to_le_bytes());
        let elf = Elf64::parse(&b).unwrap();
        assert_eq!(elf.validate_for_boot().unwrap_err(), Error::BadLoadSegment);
    }

    #[test]
    fn rejects_truncated() {
        let b = make_test_elf();
        assert_eq!(Elf64::parse(&b[..32]).unwrap_err(), Error::Truncated);
    }

    #[test]
    fn parse_bootreq_validates_magic() {
        let mut b = make_test_elf();
        b[0x3000] ^= 0xFF;
        let elf = Elf64::parse(&b).unwrap();
        assert!(elf.boot_requirements().is_err());
    }

    #[test]
    fn load_span_covers_all_segments_page_aligned() {
        let b = make_test_elf();
        let elf = Elf64::parse(&b).unwrap();
        elf.validate_for_boot().unwrap();
        let span = elf.load_span().unwrap();
        // text at VBASE (filesz 0x100), data at VBASE+0x1000 (memsz 0x100)
        assert_eq!(span.min_vaddr, VBASE);
        assert_eq!(span.span_size, 0x2000);
        // span is page aligned and at least as large as any segment end
        assert_eq!(span.span_size % 0x1000, 0);
    }

    #[test]
    fn load_span_accounts_for_unaligned_vaddr() {
        let mut b = make_test_elf();
        let ph0 = 64;
        // vaddr 0x...800 (not page aligned but congruent to offset per rule)
        b[ph0 + 8..ph0 + 16].copy_from_slice(&0x1800u64.to_le_bytes()); // offset
        b[ph0 + 16..ph0 + 24].copy_from_slice(&(VBASE + 0x800).to_le_bytes()); // vaddr
        // keep the entry covered by the shifted text segment
        b[24..32].copy_from_slice(&(VBASE + 0x840).to_le_bytes());
        let elf = Elf64::parse(&b).unwrap();
        elf.validate_for_boot().unwrap();
        let span = elf.load_span().unwrap();
        assert_eq!(span.min_vaddr, VBASE);
        // segment ends at VBASE+0x900 -> page end VBASE+0x1000
        assert_eq!(span.span_size, 0x2000);
    }

    #[test]
    fn load_span_rejects_empty() {
        let mut b = make_test_elf();
        b[56..58].copy_from_slice(&0u16.to_le_bytes()); // phnum = 0
        let elf = Elf64::parse(&b).unwrap();
        assert_eq!(elf.load_span().unwrap_err(), Error::NoLoadSegments);
    }

    // -----------------------------------------------------------------------
    // Boot Protocol 1.1 / M4: bootreq rule and user-space image validation
    // -----------------------------------------------------------------------

    #[test]
    fn bootreq_minor_is_a_floor_not_equality() {
        let req = BootReq {
            major: 1,
            minor: 1,
            entry_abi: 1,
        };
        // Loader implementing 1.1 or newer satisfies a 1.1 kernel.
        assert!(req.is_compatible(1, 1, 1));
        assert!(req.is_compatible(1, 2, 1));
        // An older loader minor must be rejected.
        assert!(!req.is_compatible(1, 0, 1));
        // Different major or entry ABI must be rejected.
        assert!(!req.is_compatible(2, 1, 1));
        assert!(!req.is_compatible(1, 1, 2));
        // A 1.0 kernel image is still bootable by a 1.1 loader.
        let old = BootReq {
            major: 1,
            minor: 0,
            entry_abi: 1,
        };
        assert!(old.is_compatible(1, 1, 1));
        assert!(old.is_compatible(1, 0, 1));
    }

    #[test]
    fn validate_for_user_accepts_low_half_image() {
        let b = make_test_elf_at(UBASE);
        let elf = Elf64::parse(&b).expect("parse");
        elf.validate_for_user().expect("low-half user image");
        // Boot validation keeps accepting the same image.
        elf.validate_for_boot().expect("boot validation");
    }

    #[test]
    fn validate_for_user_rejects_high_half_image() {
        let b = make_test_elf();
        let elf = Elf64::parse(&b).expect("parse");
        assert_eq!(elf.validate_for_user().unwrap_err(), Error::HighAddress);
    }

    #[test]
    fn validate_for_user_rejects_writable_executable_segment() {
        let mut b = make_test_elf_at(UBASE);
        let ph1 = 64 + 56;
        b[ph1 + 4..ph1 + 8].copy_from_slice(&(PF_R | PF_W | PF_X).to_le_bytes());
        let elf = Elf64::parse(&b).expect("parse");
        assert_eq!(
            elf.validate_for_user().unwrap_err(),
            Error::WritableExecutable
        );
    }

    #[test]
    fn validate_for_user_rejects_overlapping_segments() {
        let mut b = make_test_elf_at(UBASE);
        let ph1 = 64 + 56;
        // Move the data segment onto the text segment's page.
        b[ph1 + 8..ph1 + 16].copy_from_slice(&0x1000u64.to_le_bytes()); // offset
        b[ph1 + 16..ph1 + 24].copy_from_slice(&UBASE.to_le_bytes()); // vaddr
        b[ph1 + 24..ph1 + 32].copy_from_slice(&UBASE.to_le_bytes()); // paddr
        let elf = Elf64::parse(&b).expect("parse");
        assert_eq!(
            elf.validate_for_user().unwrap_err(),
            Error::OverlappingSegments
        );
        // The boot validator does not care about overlaps.
        elf.validate_for_boot().expect("boot validation");
    }

    #[test]
    fn validate_for_user_requires_executable_entry_segment() {
        let mut b = make_test_elf_at(UBASE);
        let ph0 = 64;
        b[ph0 + 4..ph0 + 8].copy_from_slice(&PF_R.to_le_bytes()); // text: R only
        let elf = Elf64::parse(&b).expect("parse");
        assert_eq!(elf.validate_for_user().unwrap_err(), Error::BadEntry);
        // …but `validate_for_boot` only requires entry coverage.
        elf.validate_for_boot().expect("boot validation");
    }

    #[test]
    fn validate_for_user_rejects_address_limit_overrun() {
        let mut b = make_test_elf_at(UBASE);
        let ph1 = 64 + 56;
        // Segment starts below the limit but its memsz crosses it.
        let near_limit = USER_ADDR_LIMIT - 0x800;
        // offset must stay congruent to vaddr modulo the page size.
        b[ph1 + 8..ph1 + 16].copy_from_slice(&0x1800u64.to_le_bytes());
        b[ph1 + 16..ph1 + 24].copy_from_slice(&near_limit.to_le_bytes());
        b[ph1 + 24..ph1 + 32].copy_from_slice(&near_limit.to_le_bytes());
        b[ph1 + 40..ph1 + 48].copy_from_slice(&0x1000u64.to_le_bytes()); // memsz
        let elf = Elf64::parse(&b).expect("parse");
        assert_eq!(elf.validate_for_user().unwrap_err(), Error::HighAddress);
    }
}

/// M9d1: PIE / `PT_INTERP` support added for the dynamic-ELF closure.
#[cfg(test)]
mod m9d_tests {
    use super::*;

    const PIE_BIAS: u64 = 0x0200_0000;
    const INTERPRETER: &[u8] = b"/fat/ldcaelum.so";

    fn put16(data: &mut [u8], at: usize, value: u16) {
        data[at..at + 2].copy_from_slice(&value.to_le_bytes());
    }

    fn put32(data: &mut [u8], at: usize, value: u32) {
        data[at..at + 4].copy_from_slice(&value.to_le_bytes());
    }

    fn put64(data: &mut [u8], at: usize, value: u64) {
        data[at..at + 8].copy_from_slice(&value.to_le_bytes());
    }

    fn phdr(
        data: &mut [u8],
        index: usize,
        p_type: u32,
        flags: u32,
        offset: u64,
        vaddr: u64,
        filesz: u64,
        memsz: u64,
        align: u64,
    ) {
        let at = 64 + index * 56;
        put32(data, at, p_type);
        put32(data, at + 4, flags);
        put64(data, at + 8, offset);
        put64(data, at + 16, vaddr);
        put64(data, at + 24, vaddr);
        put64(data, at + 32, filesz);
        put64(data, at + 40, memsz);
        put64(data, at + 48, align);
    }

    /// Minimal ET_DYN image: text at vaddr 0 (bias only), data congruent at
    /// 0x1200/offset 0x200, and a `PT_INTERP` record naming the frozen path.
    fn pie() -> [u8; 0x400] {
        let mut data = [0u8; 0x400];
        data[0..4].copy_from_slice(&[0x7F, b'E', b'L', b'F']);
        data[4] = 2; // ELFCLASS64
        data[5] = 1; // little endian
        data[6] = 1; // version
        put16(&mut data, 16, ET_DYN);
        put16(&mut data, 18, EM_X86_64);
        put32(&mut data, 20, 1);
        put64(&mut data, 24, 0x100); // e_entry
        put64(&mut data, 32, 64); // e_phoff
        put64(&mut data, 40, 0); // e_shoff
        put16(&mut data, 52, 64); // e_ehsize
        put16(&mut data, 54, 56); // e_phentsize
        put16(&mut data, 56, 3); // e_phnum
        phdr(
            &mut data,
            0,
            PT_LOAD,
            PF_R | PF_X,
            0,
            0,
            0x200,
            0x200,
            0x1000,
        );
        phdr(
            &mut data,
            1,
            PT_LOAD,
            PF_R | PF_W,
            0x200,
            0x1200,
            0x10,
            0x20,
            0x1000,
        );
        phdr(
            &mut data,
            2,
            PT_INTERP,
            PF_R,
            0x300,
            0,
            INTERPRETER.len() as u64 + 1,
            INTERPRETER.len() as u64 + 1,
            1,
        );
        data[0x300..0x300 + INTERPRETER.len()].copy_from_slice(INTERPRETER);
        data[0x300 + INTERPRETER.len()] = 0;
        data
    }

    #[test]
    fn pie_headers_expose_the_interpreter_and_geometry() {
        let data = pie();
        let elf = Elf64::parse(&data).expect("ET_DYN parses");
        assert_eq!(elf.elf_type(), ET_DYN);
        assert!(elf.is_dynamic());
        assert_eq!(elf.entry, 0x100);
        assert_eq!(elf.phoff(), 64);
        assert_eq!(elf.phentsize(), 56);
        assert_eq!(elf.phnum(), 3);
        assert_eq!(elf.interpreter(), Some(INTERPRETER));
    }

    #[test]
    fn pie_validation_applies_the_page_aligned_bias() {
        let data = pie();
        let elf = Elf64::parse(&data).expect("parse");
        elf.validate_for_user_dynamic(PIE_BIAS)
            .expect("a page-aligned non-zero bias is valid");
        assert_eq!(
            elf.validate_for_user_dynamic(0).unwrap_err(),
            Error::BadLoadSegment
        );
        assert_eq!(
            elf.validate_for_user_dynamic(PIE_BIAS + 1).unwrap_err(),
            Error::BadLoadSegment
        );
        // The legacy path still rejects a `p_vaddr == 0` ET_EXEC-style image.
        assert!(elf.validate_for_user().is_err());
    }

    #[test]
    fn pie_validation_keeps_the_congruence_and_entry_rules() {
        let mut data = pie();
        // `p_offset` 0x300 is no longer congruent with `p_vaddr` 0x1200.
        put64(&mut data, 64 + 56 + 8, 0x300);
        let elf = Elf64::parse(&data).expect("parse");
        assert_eq!(
            elf.validate_for_user_dynamic(PIE_BIAS).unwrap_err(),
            Error::BadLoadSegment
        );

        let mut data = pie();
        // Entry 0x100 is outside the (now read-only) text segment.
        put32(&mut data, 64 + 4, PF_R);
        let elf = Elf64::parse(&data).expect("parse");
        assert_eq!(
            elf.validate_for_user_dynamic(PIE_BIAS).unwrap_err(),
            Error::BadEntry
        );
    }

    #[test]
    fn et_exec_images_keep_the_legacy_type() {
        let mut data = pie();
        put16(&mut data, 16, ET_EXEC);
        let elf = Elf64::parse(&data).expect("ET_EXEC parses");
        assert_eq!(elf.elf_type(), ET_EXEC);
        assert!(!elf.is_dynamic());
        assert_eq!(
            elf.validate_for_user_dynamic(PIE_BIAS).unwrap_err(),
            Error::BadType
        );
    }
}

// ---------------------------------------------------------------------------
// M9e: dynamic table / DT_NEEDED parsing
// ---------------------------------------------------------------------------

#[cfg(test)]
mod dynamic_tests {
    use super::*;
    use std::vec;
    use std::vec::Vec;

    const BASE: u64 = 0x0040_0000;
    const DATA_OFF: u64 = 0x2000;
    const DATA_VADDR: u64 = BASE + 0x1000;
    const DYNAMIC_OFF: u64 = 0x2200;

    fn put16(b: &mut [u8], at: usize, value: u16) {
        b[at..at + 2].copy_from_slice(&value.to_le_bytes());
    }

    fn put32(b: &mut [u8], at: usize, value: u32) {
        b[at..at + 4].copy_from_slice(&value.to_le_bytes());
    }

    fn put64(b: &mut [u8], at: usize, value: u64) {
        b[at..at + 8].copy_from_slice(&value.to_le_bytes());
    }

    fn put_dynamic(b: &mut [u8], index: usize, tag: i64, value: u64) {
        let at = DYNAMIC_OFF as usize + index * 16;
        b[at..at + 8].copy_from_slice(&tag.to_le_bytes());
        b[at + 8..at + 16].copy_from_slice(&value.to_le_bytes());
    }

    /// Synthetic ET_DYN image with two PT_LOAD segments and, when
    /// `with_dynamic` is set, a `PT_DYNAMIC` table listing `needed`. The
    /// dynamic string table lives at the start of the RW LOAD's file range.
    fn image(needed: &[&[u8]], with_dynamic: bool) -> Vec<u8> {
        let mut b = vec![0u8; 0x3200];
        b[0..4].copy_from_slice(&[0x7F, b'E', b'L', b'F']);
        b[4] = 2;
        b[5] = 1;
        b[6] = 1;
        put16(&mut b, 16, ET_DYN);
        put16(&mut b, 18, EM_X86_64);
        put32(&mut b, 20, 1);
        put64(&mut b, 24, BASE + 0x40);
        put64(&mut b, 32, 64);
        put64(&mut b, 40, 0);
        put16(&mut b, 52, 64);
        put16(&mut b, 54, 56);
        put16(&mut b, 56, if with_dynamic { 3 } else { 2 });
        put16(&mut b, 58, 0);
        put16(&mut b, 60, 0);
        put16(&mut b, 62, 0);
        // Program header 0: text (R+X), file 0x1000.
        put32(&mut b, 64, PT_LOAD);
        put32(&mut b, 68, PF_R | PF_X);
        put64(&mut b, 72, 0x1000);
        put64(&mut b, 80, BASE);
        put64(&mut b, 88, BASE);
        put64(&mut b, 96, 0x100);
        put64(&mut b, 104, 0x100);
        put64(&mut b, 112, 0x1000);
        // Program header 1: data (R+W), file 0x2000.
        put32(&mut b, 120, PT_LOAD);
        put32(&mut b, 124, PF_R | PF_W);
        put64(&mut b, 128, DATA_OFF);
        put64(&mut b, 136, DATA_VADDR);
        put64(&mut b, 144, DATA_VADDR);
        put64(&mut b, 152, 0x80);
        put64(&mut b, 160, 0x100);
        put64(&mut b, 168, 0x1000);
        // Dynamic string table: leading NUL, then each name + NUL.
        let mut cursor = 1u64;
        for name in needed {
            let at = DATA_OFF as usize + cursor as usize;
            b[at..at + name.len()].copy_from_slice(name);
            cursor += name.len() as u64 + 1;
        }
        let strsz = cursor;
        if with_dynamic {
            let entries = needed.len() as u64 + 3;
            put32(&mut b, 176, PT_DYNAMIC);
            put32(&mut b, 180, PF_R | PF_W);
            put64(&mut b, 184, DYNAMIC_OFF);
            put64(&mut b, 192, BASE + 0x3000);
            put64(&mut b, 200, BASE + 0x3000);
            put64(&mut b, 208, entries * 16);
            put64(&mut b, 216, entries * 16);
            put64(&mut b, 224, 8);
            let mut offset = 1u64;
            for (index, name) in needed.iter().enumerate() {
                put_dynamic(&mut b, index, DT_NEEDED, offset);
                offset += name.len() as u64 + 1;
            }
            let mut index = needed.len();
            put_dynamic(&mut b, index, DT_STRTAB, DATA_VADDR);
            index += 1;
            put_dynamic(&mut b, index, DT_STRSZ, strsz);
            index += 1;
            put_dynamic(&mut b, index, DT_NULL, 0);
        }
        b
    }

    #[test]
    fn dynamic_needed_lists_a_single_library() {
        let b = image(&[b"/fat/m9e.so"], true);
        let elf = Elf64::parse(&b).expect("parse");
        let needed = elf.needed_libraries().expect("needed");
        assert_eq!(needed.len(), 1);
        assert_eq!(needed.get(0), Some(&b"/fat/m9e.so"[..]));
        assert_eq!(needed.get(1), None);
    }

    #[test]
    fn dynamic_needed_keeps_table_order() {
        let b = image(&[b"/fat/a.so", b"/fat/b.so"], true);
        let elf = Elf64::parse(&b).expect("parse");
        let needed = elf.needed_libraries().expect("needed");
        assert_eq!(needed.len(), 2);
        assert_eq!(needed.get(0), Some(&b"/fat/a.so"[..]));
        assert_eq!(needed.get(1), Some(&b"/fat/b.so"[..]));
    }

    #[test]
    fn image_without_pt_dynamic_has_no_needed_libraries() {
        let b = image(&[], false);
        let elf = Elf64::parse(&b).expect("parse");
        assert_eq!(elf.pt_dynamic(), None);
        assert!(elf.needed_libraries().expect("needed").is_empty());
    }

    #[test]
    fn needed_without_a_string_table_is_rejected() {
        let mut b = image(&[b"/fat/m9e.so"], true);
        put_dynamic(&mut b, 1, DT_NULL, 0);
        let elf = Elf64::parse(&b).expect("parse");
        assert_eq!(elf.needed_libraries().unwrap_err(), Error::BadDynamic);
    }

    #[test]
    fn needed_name_outside_the_string_table_is_rejected() {
        let mut b = image(&[b"/fat/m9e.so"], true);
        put_dynamic(&mut b, 0, DT_NEEDED, 1000);
        let elf = Elf64::parse(&b).expect("parse");
        assert_eq!(elf.needed_libraries().unwrap_err(), Error::BadDynamic);
    }

    #[test]
    fn truncated_dynamic_table_is_rejected() {
        let mut b = image(&[b"/fat/m9e.so"], true);
        put64(&mut b, 208, 0xFFFF_FFFF);
        put64(&mut b, 216, 0xFFFF_FFFF);
        let elf = Elf64::parse(&b).expect("parse");
        assert_eq!(elf.needed_libraries().unwrap_err(), Error::BadDynamic);
    }

    #[test]
    fn vaddr_to_file_maps_file_backed_load_segments() {
        let b = image(&[b"/fat/m9e.so"], true);
        let elf = Elf64::parse(&b).expect("parse");
        assert_eq!(elf.vaddr_to_file(BASE + 0x40).expect("text"), 0x1040);
        assert_eq!(elf.vaddr_to_file(DATA_VADDR + 1).expect("data"), 0x2001);
        assert!(elf.vaddr_to_file(DATA_VADDR + 0x100).is_err());
    }

    /// Synthetic shared-object-shaped ET_DYN image: caller-provided entry and
    /// PT_LOAD segments, no interpreter and no dynamic table.
    fn shared_object(entry: u64, segments: &[(u64, u64, u64, u64, u32)]) -> Vec<u8> {
        let mut b = vec![0u8; 0x4000];
        b[0..4].copy_from_slice(&[0x7F, b'E', b'L', b'F']);
        b[4] = 2;
        b[5] = 1;
        b[6] = 1;
        put16(&mut b, 16, ET_DYN);
        put16(&mut b, 18, EM_X86_64);
        put32(&mut b, 20, 1);
        put64(&mut b, 24, entry);
        put64(&mut b, 32, 64);
        put64(&mut b, 40, 0);
        put16(&mut b, 52, 64);
        put16(&mut b, 54, 56);
        put16(&mut b, 56, segments.len() as u16);
        put16(&mut b, 58, 0);
        put16(&mut b, 60, 0);
        put16(&mut b, 62, 0);
        for (index, &(offset, vaddr, filesz, memsz, flags)) in segments.iter().enumerate() {
            let at = 64 + index * 56;
            put32(&mut b, at, PT_LOAD);
            put32(&mut b, at + 4, flags);
            put64(&mut b, at + 8, offset);
            put64(&mut b, at + 16, vaddr);
            put64(&mut b, at + 24, vaddr);
            put64(&mut b, at + 32, filesz);
            put64(&mut b, at + 40, memsz);
            put64(&mut b, at + 48, 0x1000);
        }
        b
    }

    const LIB_BIAS: u64 = 0x0300_0000;

    #[test]
    fn shared_object_accepts_entry_zero_with_rx_and_rw_segments() {
        // Shaped like the real `/fat/m9e.so`: `e_entry == 0`, separate RX and RW
        // segments, and the executable segment does not contain the biased
        // entry. A shared object has no process entry point, so this is legal.
        let b = shared_object(
            0,
            &[
                (0x1000, 0x1000, 0x100, 0x100, PF_R | PF_X),
                (0x2000, 0x2000, 0x80, 0x80, PF_R | PF_W),
            ],
        );
        let elf = Elf64::parse(&b).expect("parse");
        elf.validate_for_shared_object(LIB_BIAS)
            .expect("shared object");
        // The executable path still demands a covered entry: same image fails.
        assert_eq!(
            elf.validate_for_user_dynamic(LIB_BIAS).unwrap_err(),
            Error::BadEntry
        );
    }

    #[test]
    fn shared_object_still_rejects_bad_segments() {
        // W^X violation.
        let b = shared_object(0, &[(0x1000, 0x1000, 0x100, 0x100, PF_R | PF_W | PF_X)]);
        let elf = Elf64::parse(&b).expect("parse");
        assert_eq!(
            elf.validate_for_shared_object(LIB_BIAS).unwrap_err(),
            Error::WritableExecutable
        );

        // Offset/vaddr congruence violation.
        let b = shared_object(0, &[(0x3f0, 0x1000, 0x100, 0x100, PF_R | PF_X)]);
        let elf = Elf64::parse(&b).expect("parse");
        assert_eq!(
            elf.validate_for_shared_object(LIB_BIAS).unwrap_err(),
            Error::BadLoadSegment
        );

        // Address outside the low canonical half once biased. The file bytes
        // stay in bounds; only the biased `p_vaddr` overruns the limit.
        let high = USER_ADDR_LIMIT - LIB_BIAS;
        let b = shared_object(0, &[(0x1000, high, 0x100, 0x200, PF_R)]);
        let elf = Elf64::parse(&b).expect("parse");
        assert_eq!(
            elf.validate_for_shared_object(LIB_BIAS).unwrap_err(),
            Error::HighAddress
        );

        // Overlapping page ranges.
        let b = shared_object(
            0,
            &[
                (0x1000, 0x1000, 0x100, 0x100, PF_R),
                (0x1080, 0x1080, 0x100, 0x100, PF_R | PF_X),
            ],
        );
        let elf = Elf64::parse(&b).expect("parse");
        assert_eq!(
            elf.validate_for_shared_object(LIB_BIAS).unwrap_err(),
            Error::OverlappingSegments
        );

        // A non-ET_DYN image is still rejected on the shared-object path.
        let mut b = shared_object(0, &[(0x1000, 0x1000, 0x100, 0x100, PF_R | PF_X)]);
        put16(&mut b, 16, ET_EXEC);
        let elf = Elf64::parse(&b).expect("parse");
        assert_eq!(
            elf.validate_for_shared_object(LIB_BIAS).unwrap_err(),
            Error::BadType
        );
    }
}
