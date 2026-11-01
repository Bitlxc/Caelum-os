//! Minimal ext2 filesystem for CaelumOS.
//!
//! Scope is deliberately narrow and fully documented, because this filesystem
//! exists to prove the persistence *path* end to end (VFS → page cache → block
//! layer → device), not to be a general ext2 implementation:
//!
//! * rev-1 volumes, **1 KiB blocks**, **256-byte inodes**;
//! * `s_feature_incompat` limited to `FILETYPE` (journal, extents, 64-bit,
//!   meta_bg, … are rejected with [`Error::Unsupported`]);
//! * files use the 12 direct pointers plus the single indirect block only, i.e.
//!   a hard maximum of [`MAX_FILE_SIZE`]; anything larger fails loudly with
//!   [`Error::Quota`] instead of silently corrupting the volume;
//! * regular files and directories (no symlinks, hard links, xattrs, ACLs).
//!
//! Design constraints that matter for the kernel:
//!
//! * `no_std`, zero dependencies besides [`block`], no heap, no `unsafe`;
//! * [`Ext2`] owns the device but keeps no bitmaps or inode tables in memory:
//!   every operation reads at most one 1 KiB block at a time;
//! * no internal helper owns a block-sized array: the public entry points own at
//!   most **two** `[u8; BLOCK_SIZE]` scratch buffers and thread them down as
//!   `&mut` parameters, so deep call chains keep boot stacks small;
//! * all metadata writes are eager — `drop` followed by a fresh
//!   [`Ext2::mount`] always observes the previous operations, and
//!   [`Ext2::sync`] surfaces device flush errors to the caller.

#![no_std]
#![forbid(unsafe_code)]

#[cfg(test)]
extern crate std;

mod alloc;
mod dir;
mod file;
mod format;
mod inode;
mod le;
mod sb;

#[cfg(test)]
mod tests;

use block::{BlockDevice, BlockError};

pub use crate::format::format;

use inode::Inode;
use sb::Superblock;

/// Size of an ext2 block, in bytes. This driver only supports 1 KiB blocks.
pub const BLOCK_SIZE: usize = 1024;

/// Largest file this driver can represent: 12 direct blocks, one single-indirect
/// block, and one double-indirect tree (no triple indirection).
pub const MAX_FILE_SIZE: u64 = inode::MAX_BLOCKS as u64 * BLOCK_SIZE as u64;

/// Maximum directory-entry name length accepted (and reported) by this driver.
pub const MAX_NAME_LEN: usize = dir::MAX_NAME_LEN;

/// Inode number of the root directory.
pub const ROOT_INODE: u32 = sb::ROOT_INODE;

/// How deep [`Ext2::rename`] follows `..` while checking for cycles.
const MAX_DIR_DEPTH: usize = 64;

/// A pair of caller-owned 1 KiB block buffers.
///
/// Internal helpers take the two buffers they need as separate `&mut`
/// parameters instead of owning block-sized arrays, which keeps every frame on
/// the `create`/`write` path small (the kernel boots on a 16 KiB stack).
pub(crate) type BlockBuf = [u8; BLOCK_SIZE];

/// Everything that can go wrong in this filesystem.
///
/// The set is intentionally small and stable; device errors collapse into
/// [`Error::Io`] because every caller treats them the same way (fail the
/// operation, keep the volume usable).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// The block device reported a failure (I/O error, timeout, …).
    Io,
    /// The device rejected a write because it is read-only.
    ReadOnly,
    /// The volume uses a feature or geometry this driver does not implement.
    Unsupported,
    /// `s_magic` is not the ext2 magic.
    BadMagic,
    /// The superblock is self-inconsistent or outside sane bounds.
    BadSuperblock,
    /// The requested inode / directory entry does not exist.
    NotFound,
    /// A path component that must be a directory is not one.
    NotDirectory,
    /// A directory was used where a regular file was required.
    IsDirectory,
    /// The target name already exists.
    Exists,
    /// A name is empty, `.`/`..`, or contains NUL / `/`.
    NameInvalid,
    /// A name is longer than [`MAX_NAME_LEN`] bytes.
    NameTooLong,
    /// `unlink` on a directory that still has entries.
    NotEmpty,
    /// The volume ran out of free blocks or inodes.
    NoSpace,
    /// The request exceeds this driver's limits (file size, block indices).
    Quota,
    /// On-disk structure is inconsistent (bad pointer, bad `rec_len`, …).
    Corrupt,
    /// An offset/length argument is invalid for the target inode.
    BadOffset,
    /// A directory move would create a cycle.
    Cycle,
}

impl Error {
    /// Stable, human-readable description (used by logs and tests).
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Io => "block device i/o error",
            Self::ReadOnly => "filesystem is read-only",
            Self::Unsupported => "unsupported feature or geometry",
            Self::BadMagic => "bad ext2 magic",
            Self::BadSuperblock => "inconsistent superblock",
            Self::NotFound => "not found",
            Self::NotDirectory => "not a directory",
            Self::IsDirectory => "is a directory",
            Self::Exists => "already exists",
            Self::NameInvalid => "invalid name",
            Self::NameTooLong => "name too long",
            Self::NotEmpty => "directory not empty",
            Self::NoSpace => "no space left",
            Self::Quota => "exceeds filesystem limits",
            Self::Corrupt => "corrupt filesystem metadata",
            Self::BadOffset => "invalid offset or length",
            Self::Cycle => "rename would create a directory cycle",
        }
    }
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Collapse a device error into a filesystem error.
pub(crate) fn map_block_error(err: BlockError) -> Error {
    match err {
        BlockError::ReadOnly => Error::ReadOnly,
        BlockError::Unsupported => Error::Unsupported,
        BlockError::Corrupt => Error::Corrupt,
        // Out-of-bounds or a misaligned buffer here means the filesystem asked
        // the device for something outside its own geometry: our bug, and the
        // volume can no longer be trusted for this operation.
        BlockError::OutOfBounds | BlockError::BadBuffer => Error::Corrupt,
        BlockError::Io | BlockError::Timeout => Error::Io,
    }
}

/// Kind of a filesystem object.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeKind {
    /// Regular file.
    File,
    /// Directory.
    Directory,
}

/// A resolved node (inode number plus the metadata VFS needs first).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExtNode {
    /// Inode number.
    pub inode: u32,
    /// Object kind.
    pub kind: NodeKind,
    /// Size in bytes (directory size for [`NodeKind::Directory`]).
    pub size: u32,
}

/// One directory entry, shaped so it can be handed to VFS without allocating.
///
/// `name` is NUL-padded, so `&entry.name[..entry.len as usize]` is the name and
/// the whole array can also be treated as a C string.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExtDirEntry {
    /// NUL-padded name bytes.
    pub name: [u8; 32],
    /// Number of valid bytes in [`Self::name`].
    pub len: u8,
    /// Inode number the entry points at.
    pub inode: u32,
    /// Kind of the target, resolved from `file_type` or the inode.
    pub kind: NodeKind,
    /// Size of the target inode in bytes.
    pub size: u32,
}

impl ExtDirEntry {
    /// The entry name as bytes.
    pub fn name(&self) -> &[u8] {
        &self.name[..self.len as usize]
    }
}

/// A mounted ext2 volume.
pub struct Ext2<D: BlockDevice> {
    dev: D,
    sb: Superblock,
    now: u32,
}

/// A directory entry located on disk (internal).
struct FoundEntry {
    /// Physical block number holding the entry.
    phys: u32,
    /// Parsed slot.
    slot: dir::Slot,
}

impl<D: BlockDevice> Ext2<D> {
    // ------------------------------------------------------------- mounting

    /// Mount the volume on `device`, validating its superblock and metadata.
    ///
    /// Rejects geometries this driver does not implement (see the module docs)
    /// instead of mounting a volume it would then corrupt.
    pub fn mount(mut device: D) -> Result<Self, Error> {
        let dev_block_size = device.block_size();
        if dev_block_size != 512 && dev_block_size as usize != BLOCK_SIZE {
            return Err(Error::Unsupported);
        }
        let mut buf = [0u8; BLOCK_SIZE];
        let mut aux = [0u8; BLOCK_SIZE];
        Self::read_raw_superblock(&mut device, &mut buf)?;
        let sb = Superblock::parse(&buf)?;
        let volume_bytes = sb.blocks_count as u64 * BLOCK_SIZE as u64;
        if volume_bytes > device.byte_capacity() {
            return Err(Error::BadSuperblock);
        }
        let mut fs = Self {
            dev: device,
            sb,
            now: 0,
        };
        fs.validate_descriptors(&mut aux)?;
        let root = fs.read_inode(ROOT_INODE, &mut buf, &mut aux)?;
        if root.kind() != Some(NodeKind::Directory) {
            return Err(Error::Corrupt);
        }
        Ok(fs)
    }

    /// Read the superblock without an [`Ext2`] instance (device may be 512-byte).
    fn read_raw_superblock(dev: &mut D, out: &mut BlockBuf) -> Result<(), Error> {
        let bs = dev.block_size() as u64;
        if bs as usize == BLOCK_SIZE {
            dev.read_blocks(1, &mut out[..]).map_err(map_block_error)
        } else {
            dev.read_blocks(2, &mut out[..512])
                .map_err(map_block_error)?;
            dev.read_blocks(3, &mut out[512..]).map_err(map_block_error)
        }
    }

    /// Every group descriptor must describe metadata inside its own group.
    ///
    /// This is the only place that decides whether the descriptor pointers may be
    /// trusted for writes, so it runs once per mount and cheaply re-runs before
    /// each allocation (see `alloc`).
    fn validate_descriptors(&mut self, aux: &mut BlockBuf) -> Result<(), Error> {
        for group in 0..self.sb.group_count() {
            let desc = self.read_group_desc(group, aux)?;
            desc.validate(&self.sb, group)?;
        }
        Ok(())
    }

    // ----------------------------------------------------------------- device

    /// Size of one device block in bytes.
    fn dev_block_size(&self) -> u64 {
        self.dev.block_size() as u64
    }

    /// Read the 1 KiB ext2 block `block` into `out`.
    ///
    /// The device may use 512-byte or 1 KiB blocks; anything else is rejected
    /// during [`Ext2::mount`] because a larger device block would need a
    /// read-modify-write buffer of that size, which we deliberately avoid.
    pub(crate) fn read_block(&mut self, block: u32, out: &mut BlockBuf) -> Result<(), Error> {
        if block >= self.sb.blocks_count {
            return Err(Error::Corrupt);
        }
        if self.dev_block_size() as usize == BLOCK_SIZE {
            self.dev
                .read_blocks(block as u64, &mut out[..])
                .map_err(map_block_error)
        } else {
            let first = block as u64 * 2;
            self.dev
                .read_blocks(first, &mut out[..512])
                .map_err(map_block_error)?;
            self.dev
                .read_blocks(first + 1, &mut out[512..])
                .map_err(map_block_error)
        }
    }

    /// Write a 1 KiB ext2 block.
    pub(crate) fn write_block(&mut self, block: u32, buf: &BlockBuf) -> Result<(), Error> {
        if block >= self.sb.blocks_count {
            return Err(Error::Corrupt);
        }
        if self.dev_block_size() as usize == BLOCK_SIZE {
            self.dev
                .write_blocks(block as u64, &buf[..])
                .map_err(map_block_error)
        } else {
            let first = block as u64 * 2;
            self.dev
                .write_blocks(first, &buf[..512])
                .map_err(map_block_error)?;
            self.dev
                .write_blocks(first + 1, &buf[512..])
                .map_err(map_block_error)
        }
    }

    // ---------------------------------------------------------------- inodes

    /// Read an inode, validating its number and the inode-table pointer.
    ///
    /// `buf` holds the inode-table block, `aux` is scratch for the group
    /// descriptor.
    pub(crate) fn read_inode(
        &mut self,
        ino: u32,
        buf: &mut BlockBuf,
        aux: &mut BlockBuf,
    ) -> Result<Inode, Error> {
        let (block, offset) = self.inode_location(ino, aux)?;
        self.read_block(block, buf)?;
        let mut raw = [0u8; inode::INODE_SIZE];
        raw.copy_from_slice(&buf[offset..offset + inode::INODE_SIZE]);
        Ok(Inode { raw })
    }

    /// Write an inode back to its table slot.
    pub(crate) fn write_inode(
        &mut self,
        ino: u32,
        node: &Inode,
        buf: &mut BlockBuf,
        aux: &mut BlockBuf,
    ) -> Result<(), Error> {
        let (block, offset) = self.inode_location(ino, aux)?;
        self.read_block(block, buf)?;
        buf[offset..offset + inode::INODE_SIZE].copy_from_slice(&node.raw);
        self.write_block(block, buf)
    }

    /// Locate an inode: `(table block, byte offset within that block)`.
    fn inode_location(&mut self, ino: u32, aux: &mut BlockBuf) -> Result<(u32, usize), Error> {
        if ino == 0 || ino > self.sb.inodes_count {
            return Err(Error::NotFound);
        }
        let group = (ino - 1) / self.sb.inodes_per_group;
        if group >= self.sb.group_count() {
            return Err(Error::Corrupt);
        }
        let local = (ino - 1) % self.sb.inodes_per_group;
        let desc = self.read_group_desc(group, aux)?;
        let table = desc.inode_table;
        if table == 0 || table >= self.sb.blocks_count {
            return Err(Error::Corrupt);
        }
        let byte = local as usize * inode::INODE_SIZE;
        let table_block = (byte / BLOCK_SIZE) as u32;
        if table_block >= self.sb.inode_table_blocks() {
            return Err(Error::Corrupt);
        }
        let block = table.checked_add(table_block).ok_or(Error::Corrupt)?;
        Ok((block, byte % BLOCK_SIZE))
    }

    // -------------------------------------------------------------- metadata

    /// Fetch the metadata VFS needs for `inode`.
    pub fn stat(&mut self, inode: u32) -> Result<ExtNode, Error> {
        let mut buf = [0u8; BLOCK_SIZE];
        let mut aux = [0u8; BLOCK_SIZE];
        self.stat_in(inode, &mut buf, &mut aux)
    }

    /// [`Ext2::stat`] with caller-owned buffers.
    fn stat_in(
        &mut self,
        inode: u32,
        buf: &mut BlockBuf,
        aux: &mut BlockBuf,
    ) -> Result<ExtNode, Error> {
        let node = self.read_inode(inode, buf, aux)?;
        let kind = node.kind().ok_or(Error::Corrupt)?;
        Ok(ExtNode {
            inode,
            kind,
            size: node.size(),
        })
    }

    /// Root directory of the volume.
    pub fn root(&mut self) -> Result<ExtNode, Error> {
        self.stat(ROOT_INODE)
    }

    /// Last modification time recorded for `inode` (seconds since epoch).
    pub fn mtime(&mut self, inode: u32) -> Result<u32, Error> {
        let mut buf = [0u8; BLOCK_SIZE];
        let mut aux = [0u8; BLOCK_SIZE];
        Ok(self.read_inode(inode, &mut buf, &mut aux)?.mtime())
    }

    /// Set the timestamp stamped into metadata updates (0 by default).
    pub fn set_time(&mut self, seconds_since_epoch: u32) {
        self.now = seconds_since_epoch;
    }

    /// Total blocks on the volume.
    pub fn block_count(&self) -> u32 {
        self.sb.blocks_count
    }

    /// Block size used by this filesystem (always [`BLOCK_SIZE`]).
    pub const fn block_size(&self) -> u32 {
        BLOCK_SIZE as u32
    }

    /// Free blocks reported by the superblock.
    pub fn free_blocks(&self) -> u32 {
        self.sb.free_blocks_count
    }

    /// Total inodes on the volume.
    pub fn inode_count(&self) -> u32 {
        self.sb.inodes_count
    }

    /// Free inodes reported by the superblock.
    pub fn free_inodes(&self) -> u32 {
        self.sb.free_inodes_count
    }

    /// Borrow the underlying device.
    pub fn device(&self) -> &D {
        &self.dev
    }

    /// Mutably borrow the underlying device (fault injection in tests, and
    /// `xtask` tooling that wants to poke the medium directly).
    pub fn device_mut(&mut self) -> &mut D {
        &mut self.dev
    }

    /// Consume the filesystem and return the device.
    pub fn into_device(self) -> D {
        self.dev
    }

    /// Push pending writes to the device and report flush failures.
    pub fn sync(&mut self) -> Result<(), Error> {
        self.dev.flush().map_err(map_block_error)
    }

    // ----------------------------------------------------------- directories

    /// Byte limit of the directory's valid data inside block `index`.
    fn dir_block_limit(dir_size: u32, index: u32) -> usize {
        let start = index as usize * BLOCK_SIZE;
        let end = (dir_size as usize).min(start + BLOCK_SIZE);
        // A directory whose recorded size does not reach this block (corrupt or
        // freshly truncated) has no valid bytes here; do not underflow.
        end.saturating_sub(start)
    }

    /// Find `name` in directory `dir`.
    fn find_entry(
        &mut self,
        dir: u32,
        name: &[u8],
        buf: &mut BlockBuf,
        aux: &mut BlockBuf,
    ) -> Result<Option<FoundEntry>, Error> {
        let node = self.read_inode(dir, buf, aux)?;
        if node.kind() != Some(NodeKind::Directory) {
            return Err(Error::NotDirectory);
        }
        let size = node.size();
        let blocks = size.div_ceil(BLOCK_SIZE as u32);
        for block_index in 0..blocks {
            let phys = match self.map_block(&node, block_index, aux)? {
                Some(phys) => phys,
                None => continue,
            };
            self.read_block(phys, buf)?;
            let limit = Self::dir_block_limit(size, block_index);
            let mut off = 0usize;
            while off + dir::DIRENT_HEADER <= limit {
                let slot = dir::parse_slot(buf, off, limit)?;
                if slot.inode != 0 && dir::slot_name(buf, &slot) == name {
                    return Ok(Some(FoundEntry { phys, slot }));
                }
                off += slot.rec_len as usize;
            }
        }
        Ok(None)
    }

    /// Resolve `name` inside directory `parent`.
    pub fn lookup(&mut self, parent: u32, name: &[u8]) -> Result<ExtNode, Error> {
        let mut buf = [0u8; BLOCK_SIZE];
        let mut aux = [0u8; BLOCK_SIZE];
        let found = self
            .find_entry(parent, name, &mut buf, &mut aux)?
            .ok_or(Error::NotFound)?;
        self.stat_in(found.slot.inode, &mut buf, &mut aux)
    }

    /// Read the directory entry at byte `offset`, returning it and the offset of
    /// the next entry.
    ///
    /// Entries come back in on-disk order and include `"."` and `".."`; the
    /// caller decides whether to surface them. `offset == 0` starts at the
    /// beginning, and `Ok(None)` marks the end of the directory.
    pub fn readdir(&mut self, dir: u32, offset: u64) -> Result<Option<(ExtDirEntry, u64)>, Error> {
        let mut buf = [0u8; BLOCK_SIZE];
        let mut aux = [0u8; BLOCK_SIZE];
        let node = self.read_inode(dir, &mut buf, &mut aux)?;
        if node.kind() != Some(NodeKind::Directory) {
            return Err(Error::NotDirectory);
        }
        let size = node.size() as u64;
        let mut cursor = offset;
        while cursor < size {
            let block_index = (cursor / BLOCK_SIZE as u64) as u32;
            let block_start = block_index as u64 * BLOCK_SIZE as u64;
            let limit = Self::dir_block_limit(node.size(), block_index);
            let phys = match self.map_block(&node, block_index, &mut aux)? {
                Some(phys) => phys,
                None => {
                    // A hole inside a directory carries no entries: skip it.
                    cursor = block_start + BLOCK_SIZE as u64;
                    continue;
                }
            };
            self.read_block(phys, &mut buf)?;
            let mut off = (cursor - block_start) as usize;
            while off + dir::DIRENT_HEADER <= limit {
                let slot = dir::parse_slot(&buf, off, limit)?;
                if slot.inode != 0 {
                    // Capture the entry before reading the target inode, which
                    // reuses both buffers.
                    let mut name = [0u8; 32];
                    let name_len;
                    {
                        let name_bytes = dir::slot_name(&buf, &slot);
                        name_len = name_bytes.len();
                        name[..name_len].copy_from_slice(name_bytes);
                    }
                    let target = self.read_inode(slot.inode, &mut buf, &mut aux)?;
                    let kind = dir::kind_from_file_type(slot.file_type)
                        .or_else(|| target.kind())
                        .ok_or(Error::Corrupt)?;
                    let entry = ExtDirEntry {
                        name,
                        len: name_len as u8,
                        inode: slot.inode,
                        kind,
                        size: target.size(),
                    };
                    let next = block_start + (off + slot.rec_len as usize) as u64;
                    return Ok(Some((entry, next)));
                }
                off += slot.rec_len as usize;
            }
            cursor = block_start + BLOCK_SIZE as u64;
        }
        Ok(None)
    }

    /// Write an entry into `dir`, extending the directory if necessary.
    fn insert_dir_entry(
        &mut self,
        dir: u32,
        name: &[u8],
        ino: u32,
        kind: NodeKind,
        buf: &mut BlockBuf,
        aux: &mut BlockBuf,
    ) -> Result<(), Error> {
        let mut node = self.read_inode(dir, buf, aux)?;
        if node.kind() != Some(NodeKind::Directory) {
            return Err(Error::NotDirectory);
        }
        let need = dir::min_rec_len(name.len()) as usize;
        let size = node.size();
        let blocks = size.div_ceil(BLOCK_SIZE as u32);
        // Pass 1: reuse a deleted slot, or split a live entry's slack.
        for block_index in 0..blocks {
            let phys = match self.map_block(&node, block_index, aux)? {
                Some(phys) => phys,
                None => continue,
            };
            self.read_block(phys, buf)?;
            let limit = Self::dir_block_limit(size, block_index);
            let mut off = 0usize;
            while off + dir::DIRENT_HEADER <= limit {
                let slot = dir::parse_slot(buf, off, limit)?;
                if slot.inode == 0 {
                    if slot.rec_len as usize >= need {
                        dir::write_slot(buf, off, ino, slot.rec_len, name, kind)?;
                        return self.write_block(phys, buf);
                    }
                } else if slot.slack() >= need {
                    let used = slot.used_len();
                    let name_len = slot.name_len;
                    let mut existing = [0u8; dir::MAX_NAME_LEN];
                    existing[..name_len as usize].copy_from_slice(dir::slot_name(buf, &slot));
                    let existing_kind =
                        dir::kind_from_file_type(slot.file_type).unwrap_or(NodeKind::File);
                    dir::write_slot(
                        buf,
                        off,
                        slot.inode,
                        used as u16,
                        &existing[..name_len as usize],
                        existing_kind,
                    )?;
                    dir::write_slot(
                        buf,
                        off + used,
                        ino,
                        (slot.rec_len as usize - used) as u16,
                        name,
                        kind,
                    )?;
                    return self.write_block(phys, buf);
                }
                off += slot.rec_len as usize;
            }
        }
        // Pass 2: append a fresh block.
        let new_index = blocks;
        if new_index as usize >= inode::MAX_BLOCKS {
            return Err(Error::Quota);
        }
        let block = self.ensure_block(&mut node, new_index, buf, aux)?;
        buf.fill(0);
        dir::write_slot(buf, 0, ino, BLOCK_SIZE as u16, name, kind)?;
        self.write_block(block, buf)?;
        node.set_size((new_index + 1) * BLOCK_SIZE as u32);
        node.set_mtime(self.now);
        self.write_inode(dir, &node, buf, aux)
    }

    /// Clear the entry described by `found`, merging free space.
    fn remove_dir_entry(
        &mut self,
        parent: u32,
        found: &FoundEntry,
        buf: &mut BlockBuf,
        aux: &mut BlockBuf,
    ) -> Result<(), Error> {
        self.read_block(found.phys, buf)?;
        crate::le::put_u32le(buf, found.slot.off, 0);
        let mut rec_len = found.slot.rec_len as usize;
        // Merge the freed slot with a following free slot so space does not
        // fragment into unusable holes.
        let next_off = found.slot.off + rec_len;
        if next_off + dir::DIRENT_HEADER <= BLOCK_SIZE {
            let next = dir::parse_slot(buf, next_off, BLOCK_SIZE)?;
            if next.inode == 0 {
                rec_len += next.rec_len as usize;
            }
        }
        // Merge into the previous slot when it is already free.
        let mut prev_off: Option<usize> = None;
        let mut off = 0usize;
        while off + dir::DIRENT_HEADER <= found.slot.off {
            let slot = dir::parse_slot(buf, off, BLOCK_SIZE)?;
            if off + slot.rec_len as usize == found.slot.off {
                if slot.inode == 0 {
                    prev_off = Some(off);
                }
                break;
            }
            off += slot.rec_len as usize;
        }
        if let Some(prev) = prev_off {
            let prev_rec = crate::le::u16le(buf, prev + 4) as usize;
            crate::le::put_u16le(buf, prev + 4, (prev_rec + rec_len) as u16);
        } else {
            crate::le::put_u16le(buf, found.slot.off + 4, rec_len as u16);
        }
        self.write_block(found.phys, buf)?;
        let mut parent_node = self.read_inode(parent, buf, aux)?;
        parent_node.set_mtime(self.now);
        self.write_inode(parent, &parent_node, buf, aux)
    }

    /// True when `node` (a directory) contains only `.` and `..`.
    fn is_empty_dir(
        &mut self,
        node: &Inode,
        buf: &mut BlockBuf,
        aux: &mut BlockBuf,
    ) -> Result<bool, Error> {
        let size = node.size();
        let blocks = size.div_ceil(BLOCK_SIZE as u32);
        for block_index in 0..blocks {
            let phys = match self.map_block(node, block_index, aux)? {
                Some(phys) => phys,
                None => continue,
            };
            self.read_block(phys, buf)?;
            let limit = Self::dir_block_limit(size, block_index);
            let mut off = 0usize;
            while off + dir::DIRENT_HEADER <= limit {
                let slot = dir::parse_slot(buf, off, limit)?;
                if slot.inode != 0 {
                    let name = dir::slot_name(buf, &slot);
                    if name != b"." && name != b".." {
                        return Ok(false);
                    }
                }
                off += slot.rec_len as usize;
            }
        }
        Ok(true)
    }

    /// Point the `..` entry of directory `dir` at `new_parent`.
    fn rewrite_dotdot(
        &mut self,
        dir: u32,
        node: &Inode,
        new_parent: u32,
        buf: &mut BlockBuf,
        aux: &mut BlockBuf,
    ) -> Result<(), Error> {
        let size = node.size();
        let blocks = size.div_ceil(BLOCK_SIZE as u32);
        for block_index in 0..blocks {
            let phys = match self.map_block(node, block_index, aux)? {
                Some(phys) => phys,
                None => continue,
            };
            self.read_block(phys, buf)?;
            let limit = Self::dir_block_limit(size, block_index);
            let mut off = 0usize;
            while off + dir::DIRENT_HEADER <= limit {
                let slot = dir::parse_slot(buf, off, limit)?;
                if slot.inode != 0 && dir::slot_name(buf, &slot) == b".." {
                    crate::le::put_u32le(buf, off, new_parent);
                    return self.write_block(phys, buf);
                }
                off += slot.rec_len as usize;
            }
            let _ = dir;
        }
        Err(Error::Corrupt)
    }

    /// Reject moving a directory into itself or one of its descendants.
    fn reject_descendant_move(
        &mut self,
        new_parent: u32,
        target: u32,
        buf: &mut BlockBuf,
        aux: &mut BlockBuf,
    ) -> Result<(), Error> {
        let mut cur = new_parent;
        for _ in 0..MAX_DIR_DEPTH {
            if cur == target {
                return Err(Error::Cycle);
            }
            // The root's `..` points at itself; stop there instead of walking in
            // circles until the depth budget runs out.
            if cur == ROOT_INODE {
                return Ok(());
            }
            cur = match self.find_entry(cur, b"..", buf, aux)? {
                Some(found) => found.slot.inode,
                // A directory without ".." cannot be walked further; treat the
                // chain as exhausted rather than corrupting the namespace.
                None => return Ok(()),
            };
        }
        Err(Error::Cycle)
    }

    // -------------------------------------------------------------- mutation

    /// Create a file or directory named `name` inside `parent`.
    pub fn create(&mut self, parent: u32, name: &[u8], kind: NodeKind) -> Result<ExtNode, Error> {
        dir::validate_name(name)?;
        if name == b"." || name == b".." {
            return Err(Error::NameInvalid);
        }
        let mut buf = [0u8; BLOCK_SIZE];
        let mut aux = [0u8; BLOCK_SIZE];
        let parent_node = self.read_inode(parent, &mut buf, &mut aux)?;
        if parent_node.kind() != Some(NodeKind::Directory) {
            return Err(Error::NotDirectory);
        }
        if parent_node.links() == 0 {
            return Err(Error::Corrupt);
        }
        if self.find_entry(parent, name, &mut buf, &mut aux)?.is_some() {
            return Err(Error::Exists);
        }

        let ino = self.alloc_inode(&mut buf, &mut aux)?;
        let mut node = Inode::create(kind, self.now);
        if kind == NodeKind::Directory {
            let block = match self.alloc_clear_block(&mut buf, &mut aux) {
                Ok(block) => block,
                Err(err) => {
                    let _ = self.free_inode(ino, &mut buf, &mut aux);
                    return Err(err);
                }
            };
            dir::init_directory_block(&mut buf, ino, parent)?;
            if let Err(err) = self.write_block(block, &buf) {
                let _ = self.free_block(block, &mut buf, &mut aux);
                let _ = self.free_inode(ino, &mut buf, &mut aux);
                return Err(err);
            }
            node.set_block(0, block);
            node.set_size(BLOCK_SIZE as u32);
            node.add_blocks_1k(1);
        }
        if let Err(err) = self.write_inode(ino, &node, &mut buf, &mut aux) {
            let _ = self.discard_new_inode(ino, &node, &mut buf, &mut aux);
            return Err(err);
        }
        if let Err(err) = self.insert_dir_entry(parent, name, ino, kind, &mut buf, &mut aux) {
            let _ = self.discard_new_inode(ino, &node, &mut buf, &mut aux);
            return Err(err);
        }
        if kind == NodeKind::Directory {
            let mut p = self.read_inode(parent, &mut buf, &mut aux)?;
            p.set_links(p.links().saturating_add(1));
            p.set_mtime(self.now);
            self.write_inode(parent, &p, &mut buf, &mut aux)?;
            let group = self.group_of_inode(ino)?;
            self.adjust_used_dirs(group, 1, &mut aux)?;
        }
        Ok(ExtNode {
            inode: ino,
            kind,
            size: node.size(),
        })
    }

    /// Remove `name` from `parent`.
    ///
    /// Directories must be empty ([`Error::NotEmpty`] otherwise), matching ext2
    /// semantics; removing a directory also drops the parent's link count.
    pub fn unlink(&mut self, parent: u32, name: &[u8]) -> Result<(), Error> {
        dir::validate_name(name)?;
        if name == b"." || name == b".." {
            return Err(Error::NameInvalid);
        }
        let mut buf = [0u8; BLOCK_SIZE];
        let mut aux = [0u8; BLOCK_SIZE];
        let found = self
            .find_entry(parent, name, &mut buf, &mut aux)?
            .ok_or(Error::NotFound)?;
        let target_ino = found.slot.inode;
        let mut target = self.read_inode(target_ino, &mut buf, &mut aux)?;
        let kind = target.kind().ok_or(Error::Corrupt)?;
        if kind == NodeKind::Directory && !self.is_empty_dir(&target, &mut buf, &mut aux)? {
            return Err(Error::NotEmpty);
        }
        self.remove_dir_entry(parent, &found, &mut buf, &mut aux)?;
        target.set_ctime(self.now);
        target.set_dtime(self.now);
        if kind == NodeKind::Directory {
            self.free_inode_blocks(&mut target, &mut buf, &mut aux)?;
            self.free_inode(target_ino, &mut buf, &mut aux)?;
            let mut p = self.read_inode(parent, &mut buf, &mut aux)?;
            p.set_links(p.links().saturating_sub(1));
            p.set_mtime(self.now);
            self.write_inode(parent, &p, &mut buf, &mut aux)?;
            let group = self.group_of_inode(target_ino)?;
            self.adjust_used_dirs(group, -1, &mut aux)?;
        } else {
            let links = target.links().saturating_sub(1);
            target.set_links(links);
            if links == 0 {
                self.free_inode_blocks(&mut target, &mut buf, &mut aux)?;
                self.free_inode(target_ino, &mut buf, &mut aux)?;
            } else {
                self.write_inode(target_ino, &target, &mut buf, &mut aux)?;
            }
        }
        Ok(())
    }

    /// Rename `old_name` in `old_parent` to `new_name` in `new_parent`.
    ///
    /// Only the same volume is supported (there is only one volume); moving a
    /// directory into itself or a descendant fails with [`Error::Cycle`].
    pub fn rename(
        &mut self,
        old_parent: u32,
        old_name: &[u8],
        new_parent: u32,
        new_name: &[u8],
    ) -> Result<(), Error> {
        dir::validate_name(old_name)?;
        dir::validate_name(new_name)?;
        if old_name == b"." || old_name == b".." || new_name == b"." || new_name == b".." {
            return Err(Error::NameInvalid);
        }
        if old_parent == new_parent && old_name == new_name {
            return Ok(());
        }
        let mut buf = [0u8; BLOCK_SIZE];
        let mut aux = [0u8; BLOCK_SIZE];
        let target_ino = self
            .find_entry(old_parent, old_name, &mut buf, &mut aux)?
            .ok_or(Error::NotFound)?
            .slot
            .inode;
        if self
            .find_entry(new_parent, new_name, &mut buf, &mut aux)?
            .is_some()
        {
            return Err(Error::Exists);
        }
        let kind = self.rename_resolve_target(target_ino, new_parent, &mut buf, &mut aux)?;
        // Add the destination name first: if that fails nothing has changed.
        self.insert_dir_entry(new_parent, new_name, target_ino, kind, &mut buf, &mut aux)?;
        self.rename_apply(
            old_parent, old_name, new_parent, new_name, target_ino, kind, &mut buf, &mut aux,
        )
    }

    /// Resolve the kind of a rename target and reject cyclic directory moves.
    ///
    /// Split out of [`Ext2::rename`] (and kept out of line) so the 256-byte
    /// `Inode` temporaries and the `..` walk live in this frame rather than in
    /// the caller's: the kernel boots on a 16 KiB stack.
    #[inline(never)]
    fn rename_resolve_target(
        &mut self,
        target_ino: u32,
        new_parent: u32,
        buf: &mut BlockBuf,
        aux: &mut BlockBuf,
    ) -> Result<NodeKind, Error> {
        let target = self.read_inode(target_ino, buf, aux)?;
        let kind = target.kind().ok_or(Error::Corrupt)?;
        if kind == NodeKind::Directory {
            self.reject_descendant_move(new_parent, target_ino, buf, aux)?;
        }
        Ok(kind)
    }

    /// Apply the namespace update of a validated rename.
    ///
    /// The destination entry has already been added by the caller, so this only
    /// removes the source name (rolling the destination back on failure), then
    /// repoints `..` and the parent link counts. Also `#[inline(never)]`: this is
    /// the part that touches directory blocks, and keeping it in one small frame
    /// (one inode temporary plus the caller-owned buffers) is what lets the
    /// rename chain fit the 16 KiB boot stack.
    #[inline(never)]
    fn rename_apply(
        &mut self,
        old_parent: u32,
        old_name: &[u8],
        new_parent: u32,
        new_name: &[u8],
        target_ino: u32,
        kind: NodeKind,
        buf: &mut BlockBuf,
        aux: &mut BlockBuf,
    ) -> Result<(), Error> {
        // Inserting may have split slots in `old_parent` (when both names live in
        // the same directory and block), so re-resolve the source entry instead
        // of trusting the offsets captured before the insert.
        let found = match self.find_entry(old_parent, old_name, buf, aux) {
            Ok(Some(found)) => found,
            Ok(None) => return Err(Error::NotFound),
            Err(err) => return Err(err),
        };
        if let Err(err) = self.remove_dir_entry(old_parent, &found, buf, aux) {
            // Roll the destination entry back so the namespace stays consistent.
            if let Ok(Some(added)) = self.find_entry(new_parent, new_name, buf, aux) {
                let _ = self.remove_dir_entry(new_parent, &added, buf, aux);
            }
            return Err(err);
        }
        let mut target = self.read_inode(target_ino, buf, aux)?;
        target.set_ctime(self.now);
        if kind == NodeKind::Directory {
            self.rewrite_dotdot(target_ino, &target, new_parent, buf, aux)?;
            self.rename_relink_parents(old_parent, new_parent, buf, aux)?;
        }
        self.write_inode(target_ino, &target, buf, aux)
    }

    /// Update `nlink`/`mtime` on both directories of a cross-directory rename.
    #[inline(never)]
    fn rename_relink_parents(
        &mut self,
        old_parent: u32,
        new_parent: u32,
        buf: &mut BlockBuf,
        aux: &mut BlockBuf,
    ) -> Result<(), Error> {
        self.rename_relink_one(old_parent, -1, buf, aux)?;
        self.rename_relink_one(new_parent, 1, buf, aux)
    }

    /// Add `delta` to a directory's `nlink` and refresh its `mtime`.
    ///
    /// Called twice in sequence rather than once per parent with two locals, so
    /// the rename chain never holds two 256-byte `Inode`s at the same time.
    #[inline(never)]
    fn rename_relink_one(
        &mut self,
        dir: u32,
        delta: i16,
        buf: &mut BlockBuf,
        aux: &mut BlockBuf,
    ) -> Result<(), Error> {
        let mut node = self.read_inode(dir, buf, aux)?;
        let links = if delta < 0 {
            node.links().saturating_sub(delta.unsigned_abs())
        } else {
            node.links().saturating_add(delta as u16)
        };
        node.set_links(links);
        node.set_mtime(self.now);
        self.write_inode(dir, &node, buf, aux)
    }

    /// Free the data blocks and the inode of a freshly created node.
    fn discard_new_inode(
        &mut self,
        ino: u32,
        node: &Inode,
        buf: &mut BlockBuf,
        aux: &mut BlockBuf,
    ) -> Result<(), Error> {
        let mut copy = node.clone();
        self.free_inode_blocks(&mut copy, buf, aux)?;
        self.free_inode(ino, buf, aux)
    }
}
