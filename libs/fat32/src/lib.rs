//! FAT32 read/write filesystem for CaelumOS (M5b).
//!
//! Scope is deliberately the M5b contract:
//!
//! * FAT32 only (BPB with 32-bit FAT, no FAT12/FAT16, no exFAT).
//! * 512-byte logical sectors only; any other (or non-512-block) device is
//!   rejected with [`Fat32Error::Unsupported`] instead of being guessed at.
//! * Short 8.3 names only. Long-file-name (LFN) entries are *skipped* when
//!   reading a directory, never interpreted and never created. A name that
//!   cannot be represented in 8.3 is rejected with [`Fat32Error::BadName`]; it
//!   is never silently truncated.
//! * Mirrored FATs: every FAT metadata update is written to all FAT copies.
//!   `BPB_ExtFlags` with "no mirroring / one active FAT" is unsupported.
//! * Read/write/truncate operate byte-granularity on files, allocate and free
//!   cluster chains, zero freshly allocated clusters and explicitly zero the
//!   gap left by a sparse (`offset > size`) write.
//!
//! Buffer and code-size discipline: the filesystem owns only small control
//! fields ([`Fat32::layout`] plus allocator hints) — no in-structure arrays
//! sized by the volume, and the FAT is never materialised on the stack.
//!
//! Everything in the crate is synchronous and allocation-free; the device is
//! borrowed through the [`block::BlockDevice`] trait so the kernel, the loader
//! and host image tools share one code path.

#![no_std]
#![forbid(unsafe_code)]

#[cfg(test)]
extern crate std;

mod bpb;
mod dir;
mod fat;
mod file;
mod format;
mod name83;
#[cfg(test)]
mod tests;

pub use block::{BlockDevice, BlockError};
pub use format::format;

/// Logical sector size supported by this implementation.
pub const SECTOR_SIZE: u32 = 512;

/// One on-disk sector buffer.
///
/// The whole crate reuses a single caller-owned buffer instead of allocating a
/// 512-byte array per layer: the boot path runs on a 16 KiB stack, so a chain of
/// `read_sector`-returns-an-array calls (each level keeping its own copy) used to
/// cost more than the stack had. Internal helpers all take `&mut Sector`; the
/// public methods allocate exactly one per call and thread it down.
pub(crate) type Sector = [u8; SECTOR_SIZE as usize];

/// `cookie` value that identifies the root directory node.
pub const ROOT_COOKIE: u64 = u64::MAX;

/// Maximum bytes a directory entry name can occupy in [`DirEntry::name`].
pub const MAX_NAME_LEN: usize = 32;

/// Directory entry size in bytes.
pub const DIR_ENTRY_SIZE: usize = 32;

/// Directory entries per sector.
pub(crate) const ENTRIES_PER_SECTOR: usize = (SECTOR_SIZE as usize) / DIR_ENTRY_SIZE;

/// FAT entry value at which a chain ends (`0x0FFFFFF8..=0x0FFFFFFF`).
pub(crate) const FAT_EOC_MIN: u32 = 0x0FFF_FFF8;

/// FAT entry marking a bad cluster.
pub(crate) const FAT_BAD: u32 = 0x0FFF_FFF7;

/// The 28 bits of a FAT32 entry that carry a cluster number.
pub(crate) const FAT_MASK: u32 = 0x0FFF_FFFF;

pub(crate) const FSINFO_LEAD: u32 = 0x4161_5252;
pub(crate) const FSINFO_STRUCT: u32 = 0x6141_7272;
pub(crate) const FSINFO_TRAIL: u32 = 0xAA55_0000;

pub(crate) const ATTR_VOLUME_ID: u8 = 0x08;
pub(crate) const ATTR_DIRECTORY: u8 = 0x10;
pub(crate) const ATTR_ARCHIVE: u8 = 0x20;
pub(crate) const ATTR_LFN: u8 = 0x0F;
pub(crate) const ENTRY_END: u8 = 0x00;
pub(crate) const ENTRY_DELETED: u8 = 0xE5;

/// FAT date encoding used for deterministic timestamps (2024-01-01).
pub(crate) const DEFAULT_DATE: u16 = (((2024u16 - 1980) << 9) | (1u16 << 5)) | 1u16;
/// FAT time encoding used for deterministic timestamps (00:00:00).
pub(crate) const DEFAULT_TIME: u16 = 0;

/// Everything a FAT32 operation can fail with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Fat32Error {
    /// The block layer failed; see the wrapped [`BlockError`].
    Block(BlockError),
    /// The boot sector / BPB is structurally invalid.
    BadBpb,
    /// The operation cannot be represented (e.g. 4096-byte devices, exFAT,
    /// non-mirrored FATs, FAT12/16).
    Unsupported,
    /// The name is not a valid 8.3 short name.
    BadName,
    /// A cluster number is outside `2..=cluster_count+1`.
    BadCluster,
    /// On-disk structures are inconsistent (bad chain, loop, lost cluster).
    Corrupt,
    /// No such file or directory.
    NotFound,
    /// A non-directory was used where a directory was required.
    NotADirectory,
    /// A directory was used where a file was required.
    IsADirectory,
    /// A directory that still has entries cannot be removed.
    NotEmpty,
    /// The name already exists in the target directory.
    AlreadyExists,
    /// The volume has no free clusters left.
    NoSpace,
    /// Offset/size exceeds the FAT32 32-bit limit or the volume.
    TooLarge,
    /// The arguments make no sense (e.g. unlink the root, move a directory
    /// into its own subtree).
    InvalidArgument,
}

impl From<BlockError> for Fat32Error {
    fn from(error: BlockError) -> Self {
        Self::Block(error)
    }
}

impl core::fmt::Display for Fat32Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Block(e) => write!(f, "block layer: {e}"),
            Self::BadBpb => f.write_str("invalid FAT32 boot sector"),
            Self::Unsupported => f.write_str("unsupported filesystem feature"),
            Self::BadName => f.write_str("not a valid 8.3 name"),
            Self::BadCluster => f.write_str("cluster number out of range"),
            Self::Corrupt => f.write_str("FAT32 metadata is corrupt"),
            Self::NotFound => f.write_str("not found"),
            Self::NotADirectory => f.write_str("not a directory"),
            Self::IsADirectory => f.write_str("is a directory"),
            Self::NotEmpty => f.write_str("directory is not empty"),
            Self::AlreadyExists => f.write_str("name already exists"),
            Self::NoSpace => f.write_str("volume is full"),
            Self::TooLarge => f.write_str("size/offset exceeds FAT32 limits"),
            Self::InvalidArgument => f.write_str("invalid argument"),
        }
    }
}

/// Whether a node is a regular file or a directory.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeKind {
    File,
    Directory,
}

/// Stable handle to a directory entry.
///
/// `cookie` encodes the physical location of the short directory entry
/// (`sector << 8 | index`); it stays valid until the entry is deleted or the
/// directory is modified by another writer. The root directory has
/// [`ROOT_COOKIE`]. Path walkers keep `FatNode`s instead of file descriptors;
/// file contents are always re-read from the directory entry, so renaming via
/// [`Fat32::rename`] only needs to update this handle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FatNode {
    /// Physical location of the short directory entry, or [`ROOT_COOKIE`].
    pub cookie: u64,
    /// First cluster of the containing directory.
    pub parent: u32,
    /// File or directory.
    pub kind: NodeKind,
    /// Size in bytes (0 for directories).
    pub size: u64,
}

impl FatNode {
    /// True for the root directory node.
    pub fn is_root(&self) -> bool {
        self.cookie == ROOT_COOKIE
    }
}

/// One directory entry as returned by [`Fat32::readdir`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DirEntry {
    /// Uppercase 8.3 name, space padding removed (`NAME.EXT`).
    pub name: [u8; MAX_NAME_LEN],
    /// Number of valid bytes in [`DirEntry::name`].
    pub name_len: u8,
    /// The entry itself.
    pub node: FatNode,
}

impl DirEntry {
    /// The directory entry name as bytes.
    pub fn name(&self) -> &[u8] {
        &self.name[..self.name_len as usize]
    }
}

/// On-disk geometry derived from the BPB.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Layout {
    pub bytes_per_sector: u16,
    pub sectors_per_cluster: u8,
    pub reserved_sectors: u16,
    pub num_fats: u8,
    pub fat_sectors: u32,
    pub total_sectors: u32,
    pub root_cluster: u32,
    pub fsinfo_sector: u16,
    pub backup_boot_sector: u16,
    /// Number of data clusters (`2..=cluster_count+1` are valid numbers).
    pub cluster_count: u32,
    /// First sector of cluster 2.
    pub data_start_sector: u32,
}

impl Layout {
    /// Bytes in one cluster.
    pub fn cluster_bytes(&self) -> u32 {
        self.sectors_per_cluster as u32 * self.bytes_per_sector as u32
    }

    /// Largest valid cluster number.
    pub fn max_cluster(&self) -> u32 {
        self.cluster_count + 1
    }

    /// True when `cluster` is a valid data cluster number.
    pub fn valid_cluster(&self, cluster: u32) -> bool {
        cluster >= 2 && cluster <= self.max_cluster()
    }
}

/// Options for [`Fat32::format`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FormatOptions {
    /// Sectors per cluster. `0` picks a size derived from the volume, which is
    /// what tests and `xtask` use.
    pub sectors_per_cluster: u8,
    /// Volume label, exactly 11 bytes, space padded.
    pub label: [u8; 11],
}

impl Default for FormatOptions {
    fn default() -> Self {
        Self {
            sectors_per_cluster: 0,
            label: *b"CAELUM     ",
        }
    }
}

/// Mounted FAT32 volume.
///
/// The device is owned by the filesystem; use [`Fat32::unmount`] to get it back
/// (which flushes first).
#[derive(Debug)]
pub struct Fat32<D: BlockDevice> {
    pub(crate) device: D,
    pub(crate) layout: Layout,
    /// Free cluster count from FSInfo, or [`UNKNOWN_FREE`] when not trustworthy.
    pub(crate) free_count: u32,
    /// Allocator hint: first cluster worth probing.
    pub(crate) next_free: u32,
    pub(crate) fsinfo_dirty: bool,
}

/// Sentinel in [`Fat32::free_count`] meaning "unknown, rescan on demand".
pub(crate) const UNKNOWN_FREE: u32 = u32::MAX;

impl<D: BlockDevice> Fat32<D> {
    /// Mount an existing FAT32 volume.
    ///
    /// Validates the boot sector, geometry, FAT entry 0 media descriptor, the
    /// root directory cluster and the FSInfo signature. FSInfo that does not
    /// validate is tolerated (counts become unknown); everything structural
    /// fails loudly.
    pub fn mount(mut device: D) -> Result<Self, Fat32Error> {
        if device.block_size() != SECTOR_SIZE {
            return Err(Fat32Error::Unsupported);
        }
        let blocks = device.block_count();
        if blocks == 0 {
            return Err(Fat32Error::BadBpb);
        }
        let mut scratch: Sector = [0u8; SECTOR_SIZE as usize];
        device.read_exact(0, &mut scratch)?;
        let layout = bpb::parse(&scratch)?;
        if layout.total_sectors as u64 > blocks {
            return Err(Fat32Error::BadBpb);
        }
        let needed_end = layout.data_start_sector as u64
            + layout.cluster_count as u64 * layout.sectors_per_cluster as u64;
        if needed_end > blocks {
            return Err(Fat32Error::BadBpb);
        }

        let mut fs = Self {
            device,
            layout,
            free_count: UNKNOWN_FREE,
            next_free: 2,
            fsinfo_dirty: false,
        };

        // Media descriptor lives in the low byte of FAT[0]; reject a wiped FAT
        // instead of mounting a volume whose allocator state is meaningless.
        let fat0 = fs.fat_raw_read(0, &mut scratch)?;
        if fat0 & 0xFF < 0xF0 {
            return Err(Fat32Error::Corrupt);
        }
        // The root directory must be allocated (its FAT entry is a chain head).
        if fs.read_fat(layout.root_cluster, &mut scratch)? == 0 {
            return Err(Fat32Error::Corrupt);
        }
        // The first root sector must be readable, otherwise the geometry is lie.
        fs.cluster_lba(layout.root_cluster)?;
        fs.load_fsinfo(&mut scratch)?;
        Ok(fs)
    }

    /// Geometry of the mounted volume.
    pub fn layout(&self) -> &Layout {
        &self.layout
    }

    /// The underlying device.
    pub fn device(&self) -> &D {
        &self.device
    }

    /// The underlying device, mutably (drivers/diagnostics only).
    pub fn device_mut(&mut self) -> &mut D {
        &mut self.device
    }

    /// Stable handle for the root directory.
    pub fn root(&self) -> FatNode {
        FatNode {
            cookie: ROOT_COOKIE,
            parent: 0,
            kind: NodeKind::Directory,
            size: 0,
        }
    }

    /// Free clusters, or `None` when FSInfo could not be trusted and no rescan
    /// has happened yet.
    pub fn free_clusters(&self) -> Option<u32> {
        if self.free_count == UNKNOWN_FREE {
            None
        } else {
            Some(self.free_count)
        }
    }

    /// Sector of a data cluster. Public for diagnostics and tests.
    pub fn cluster_to_sector(&self, cluster: u32) -> Result<u32, Fat32Error> {
        self.cluster_lba(cluster)
    }

    /// Flush the filesystem: persist FSInfo (when changed) and then the device.
    ///
    /// Errors are propagated, never swallowed.
    pub fn sync(&mut self) -> Result<(), Fat32Error> {
        if self.fsinfo_dirty {
            let mut scratch: Sector = [0u8; SECTOR_SIZE as usize];
            self.write_fsinfo(&mut scratch)?;
            self.fsinfo_dirty = false;
        }
        self.device.flush()?;
        Ok(())
    }

    /// Flush and hand the device back.
    pub fn unmount(mut self) -> Result<D, Fat32Error> {
        self.sync()?;
        Ok(self.device)
    }

    // ---- low-level sector helpers -----------------------------------------

    /// Read one sector into the caller's scratch buffer (never allocates).
    pub(crate) fn read_sector_into(
        &mut self,
        lba: u32,
        out: &mut Sector,
    ) -> Result<(), Fat32Error> {
        self.device.read_exact(lba as u64, out)?;
        Ok(())
    }

    pub(crate) fn write_sector(&mut self, lba: u32, data: &Sector) -> Result<(), Fat32Error> {
        self.device.write_exact(lba as u64, data)?;
        Ok(())
    }

    pub(crate) fn cluster_lba(&self, cluster: u32) -> Result<u32, Fat32Error> {
        if !self.layout.valid_cluster(cluster) {
            return Err(Fat32Error::BadCluster);
        }
        let offset = (cluster - 2) as u64 * self.layout.sectors_per_cluster as u64;
        let lba = self.layout.data_start_sector as u64 + offset;
        if lba > u32::MAX as u64 {
            return Err(Fat32Error::Corrupt);
        }
        Ok(lba as u32)
    }

    // ---- directory entry access ------------------------------------------

    /// Read the short directory entry behind `cookie`.
    pub(crate) fn entry_at(
        &mut self,
        cookie: u64,
        scratch: &mut Sector,
    ) -> Result<[u8; DIR_ENTRY_SIZE], Fat32Error> {
        let lba = (cookie >> 8) as u32;
        let index = (cookie & 0xFF) as usize;
        if index >= ENTRIES_PER_SECTOR {
            return Err(Fat32Error::Corrupt);
        }
        self.read_sector_into(lba, scratch)?;
        let at = index * DIR_ENTRY_SIZE;
        let mut raw = [0u8; DIR_ENTRY_SIZE];
        raw.copy_from_slice(&scratch[at..at + DIR_ENTRY_SIZE]);
        Ok(raw)
    }

    /// Write one short directory entry.
    pub(crate) fn write_entry_at(
        &mut self,
        lba: u32,
        index: usize,
        raw: &[u8; DIR_ENTRY_SIZE],
        scratch: &mut Sector,
    ) -> Result<(), Fat32Error> {
        if index >= ENTRIES_PER_SECTOR {
            return Err(Fat32Error::Corrupt);
        }
        self.read_sector_into(lba, scratch)?;
        let at = index * DIR_ENTRY_SIZE;
        scratch[at..at + DIR_ENTRY_SIZE].copy_from_slice(raw);
        self.write_sector(lba, scratch)
    }

    /// Update the cluster/size fields of an existing entry in place.
    pub(crate) fn update_entry(
        &mut self,
        cookie: u64,
        first_cluster: u32,
        size: u64,
        scratch: &mut Sector,
    ) -> Result<(), Fat32Error> {
        if size > u32::MAX as u64 {
            return Err(Fat32Error::TooLarge);
        }
        let lba = (cookie >> 8) as u32;
        let index = (cookie & 0xFF) as usize;
        let mut raw = self.entry_at(cookie, scratch)?;
        set_cluster(&mut raw, first_cluster);
        set_size(&mut raw, size as u32);
        raw[22..24].copy_from_slice(&DEFAULT_TIME.to_le_bytes());
        raw[24..26].copy_from_slice(&DEFAULT_DATE.to_le_bytes());
        self.write_entry_at(lba, index, &raw, scratch)
    }

    /// First cluster referenced by a node's directory entry (0 for empty files).
    pub(crate) fn node_first_cluster(
        &mut self,
        node: &FatNode,
        scratch: &mut Sector,
    ) -> Result<u32, Fat32Error> {
        if node.cookie == ROOT_COOKIE {
            return Ok(self.layout.root_cluster);
        }
        let raw = self.entry_at(node.cookie, scratch)?;
        Ok(entry_cluster(&raw))
    }

    /// First cluster of a directory node (the cluster its entries live in).
    pub(crate) fn dir_cluster_of(
        &mut self,
        node: &FatNode,
        scratch: &mut Sector,
    ) -> Result<u32, Fat32Error> {
        if node.cookie == ROOT_COOKIE {
            return Ok(self.layout.root_cluster);
        }
        if node.kind != NodeKind::Directory {
            return Err(Fat32Error::NotADirectory);
        }
        let cluster = self.node_first_cluster(node, scratch)?;
        if cluster == 0 {
            return Err(Fat32Error::Corrupt);
        }
        Ok(cluster)
    }
}

// ---- raw entry field codecs ---------------------------------------------

pub(crate) fn entry_attr(raw: &[u8; DIR_ENTRY_SIZE]) -> u8 {
    raw[11]
}

pub(crate) fn entry_cluster(raw: &[u8; DIR_ENTRY_SIZE]) -> u32 {
    let hi = u16::from_le_bytes([raw[20], raw[21]]) as u32;
    let lo = u16::from_le_bytes([raw[26], raw[27]]) as u32;
    (hi << 16) | lo
}

pub(crate) fn entry_size(raw: &[u8; DIR_ENTRY_SIZE]) -> u32 {
    u32::from_le_bytes([raw[28], raw[29], raw[30], raw[31]])
}

pub(crate) fn entry_name83(raw: &[u8; DIR_ENTRY_SIZE]) -> [u8; 11] {
    let mut name = [0u8; 11];
    name.copy_from_slice(&raw[0..11]);
    name
}

pub(crate) fn set_cluster(raw: &mut [u8; DIR_ENTRY_SIZE], cluster: u32) {
    let hi = ((cluster >> 16) & 0xFFFF) as u16;
    let lo = (cluster & 0xFFFF) as u16;
    raw[20..22].copy_from_slice(&hi.to_le_bytes());
    raw[26..28].copy_from_slice(&lo.to_le_bytes());
}

pub(crate) fn set_size(raw: &mut [u8; DIR_ENTRY_SIZE], size: u32) {
    raw[28..32].copy_from_slice(&size.to_le_bytes());
}

pub(crate) fn is_dir_entry(raw: &[u8; DIR_ENTRY_SIZE]) -> bool {
    entry_attr(raw) & ATTR_DIRECTORY != 0
}

/// True for entries that are not real children: LFN chunks, volume labels and
/// the `.`/`..` links.
pub(crate) fn is_special_entry(raw: &[u8; DIR_ENTRY_SIZE]) -> bool {
    let attr = entry_attr(raw);
    if attr == ATTR_LFN || attr & ATTR_VOLUME_ID != 0 {
        return true;
    }
    let name = entry_name83(raw);
    name[0] == b'.' && (name[1] == b' ' || name[1] == b'.')
}

pub(crate) fn node_kind(raw: &[u8; DIR_ENTRY_SIZE]) -> NodeKind {
    if is_dir_entry(raw) {
        NodeKind::Directory
    } else {
        NodeKind::File
    }
}
