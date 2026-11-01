//! ext2 superblock and block-group descriptor decoding/encoding.
//!
//! Only the subset this filesystem supports is modelled: rev-1 volumes with
//! 1 KiB blocks and 256-byte inodes. Reads validate every field that affects
//! address arithmetic; anything outside the support envelope is rejected with
//! [`Error::Unsupported`] instead of being half-honoured.

use crate::le::{u16le, u32le};
use crate::{BLOCK_SIZE, Error};

/// ext2 superblock magic (`s_magic`).
pub(crate) const MAGIC: u16 = 0xEF53;

/// Superblock lives at byte offset 1024, i.e. block 1 for 1 KiB blocks.
pub(crate) const SUPERBLOCK_BLOCK: u32 = 1;

/// On-disk size of a block group descriptor.
pub(crate) const DESC_SIZE: usize = 32;

/// `s_feature_incompat`: directory entries carry an explicit file type.
pub(crate) const INCOMPAT_FILETYPE: u32 = 0x2;

/// `s_feature_ro_compat`: backup superblocks only at sparse offsets.
pub(crate) const RO_COMPAT_SPARSE_SUPER: u32 = 0x1;

/// `s_feature_ro_compat`: files may exceed 2 GiB (we never create such files,
/// but reading such a volume is fine).
pub(crate) const RO_COMPAT_LARGE_FILE: u32 = 0x2;

/// First inode available to users (1 is bad-blocks, 2 is the root, 3..10 are
/// reserved by the original ext2 specification).
pub(crate) const FIRST_NON_RESERVED_INODE: u32 = 11;

/// Root directory inode number.
pub(crate) const ROOT_INODE: u32 = 2;

// Superblock field offsets (bytes from the start of the 1 KiB superblock).
const OFF_INODES_COUNT: usize = 0x00;
const OFF_BLOCKS_COUNT: usize = 0x04;
const OFF_R_BLOCKS_COUNT: usize = 0x08;
const OFF_FREE_BLOCKS_COUNT: usize = 0x0C;
const OFF_FREE_INODES_COUNT: usize = 0x10;
const OFF_FIRST_DATA_BLOCK: usize = 0x14;
const OFF_LOG_BLOCK_SIZE: usize = 0x18;
const OFF_LOG_FRAG_SIZE: usize = 0x1C;
const OFF_BLOCKS_PER_GROUP: usize = 0x20;
const OFF_FRAGS_PER_GROUP: usize = 0x24;
const OFF_INODES_PER_GROUP: usize = 0x28;
const OFF_MTIME: usize = 0x2C;
const OFF_WTIME: usize = 0x30;
const OFF_MNT_COUNT: usize = 0x34;
const OFF_MAGIC: usize = 0x38;
const OFF_STATE: usize = 0x3A;
const OFF_ERRORS: usize = 0x3C;
const OFF_MINOR_REV_LEVEL: usize = 0x3E;
const OFF_LASTCHECK: usize = 0x40;
const OFF_CHECKINTERVAL: usize = 0x44;
const OFF_REV_LEVEL: usize = 0x4C;
const OFF_FIRST_INO: usize = 0x54;
const OFF_INODE_SIZE: usize = 0x58;
const OFF_FEATURE_COMPAT: usize = 0x5C;
const OFF_FEATURE_INCOMPAT: usize = 0x60;
const OFF_FEATURE_RO_COMPAT: usize = 0x64;
const OFF_UUID: usize = 0x68;
const OFF_VOLUME_NAME: usize = 0x78;
const OFF_PREALLOC_BLOCKS: usize = 0xCC;
const OFF_PREALLOC_DIR_BLOCKS: usize = 0xCD;
const OFF_MAX_MNT_COUNT: usize = 0x36;
const OFF_DEF_RESUID: usize = 0x50;
const OFF_DEF_RESGID: usize = 0x52;
const OFF_BLOCK_GROUP_NR: usize = 0x5A;
const OFF_ALGORITHM_USAGE: usize = 0xC8;
const OFF_RESERVED_GDT: usize = 0xCE;
const OFF_JOURNAL_UUID: usize = 0xD0;
const OFF_JOURNAL_INUM: usize = 0xE0;
const OFF_JOURNAL_DEV: usize = 0xE4;
const OFF_LAST_ORPHAN: usize = 0xE8;

/// Parsed ext2 superblock: only the fields the driver actually uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Superblock {
    pub inodes_count: u32,
    pub blocks_count: u32,
    pub r_blocks_count: u32,
    pub free_blocks_count: u32,
    pub free_inodes_count: u32,
    pub first_data_block: u32,
    pub blocks_per_group: u32,
    pub inodes_per_group: u32,
    pub mtime: u32,
    pub wtime: u32,
    pub mnt_count: u16,
    pub state: u16,
    pub errors: u16,
    pub minor_rev_level: u16,
    pub lastcheck: u32,
    pub checkinterval: u32,
    pub rev_level: u32,
    pub first_ino: u32,
    pub inode_size: u16,
    pub feature_compat: u32,
    pub feature_incompat: u32,
    pub feature_ro_compat: u32,
    pub uuid: [u8; 16],
    pub volume_name: [u8; 16],
    pub prealloc_blocks: u8,
    pub prealloc_dir_blocks: u8,
}

impl Superblock {
    /// Parse and validate a raw 1 KiB superblock block.
    pub(crate) fn parse(block: &[u8; BLOCK_SIZE]) -> Result<Self, Error> {
        let magic = u16le(block, OFF_MAGIC);
        if magic != MAGIC {
            return Err(Error::BadMagic);
        }

        let sb = Self {
            inodes_count: u32le(block, OFF_INODES_COUNT),
            blocks_count: u32le(block, OFF_BLOCKS_COUNT),
            r_blocks_count: u32le(block, OFF_R_BLOCKS_COUNT),
            free_blocks_count: u32le(block, OFF_FREE_BLOCKS_COUNT),
            free_inodes_count: u32le(block, OFF_FREE_INODES_COUNT),
            first_data_block: u32le(block, OFF_FIRST_DATA_BLOCK),
            blocks_per_group: u32le(block, OFF_BLOCKS_PER_GROUP),
            inodes_per_group: u32le(block, OFF_INODES_PER_GROUP),
            mtime: u32le(block, OFF_MTIME),
            wtime: u32le(block, OFF_WTIME),
            mnt_count: u16le(block, OFF_MNT_COUNT),
            state: u16le(block, OFF_STATE),
            errors: u16le(block, OFF_ERRORS),
            minor_rev_level: u16le(block, OFF_MINOR_REV_LEVEL),
            lastcheck: u32le(block, OFF_LASTCHECK),
            checkinterval: u32le(block, OFF_CHECKINTERVAL),
            rev_level: u32le(block, OFF_REV_LEVEL),
            first_ino: u32le(block, OFF_FIRST_INO),
            inode_size: u16le(block, OFF_INODE_SIZE),
            feature_compat: u32le(block, OFF_FEATURE_COMPAT),
            feature_incompat: u32le(block, OFF_FEATURE_INCOMPAT),
            feature_ro_compat: u32le(block, OFF_FEATURE_RO_COMPAT),
            uuid: {
                let mut uuid = [0u8; 16];
                uuid.copy_from_slice(&block[OFF_UUID..OFF_UUID + 16]);
                uuid
            },
            volume_name: {
                let mut name = [0u8; 16];
                name.copy_from_slice(&block[OFF_VOLUME_NAME..OFF_VOLUME_NAME + 16]);
                name
            },
            prealloc_blocks: block[OFF_PREALLOC_BLOCKS],
            prealloc_dir_blocks: block[OFF_PREALLOC_DIR_BLOCKS],
        };

        sb.validate()?;
        Ok(sb)
    }

    /// Geometry and feature validation.
    fn validate(&self) -> Result<(), Error> {
        // Support envelope: rev 1, 1 KiB blocks, 1 KiB fragments, 256-byte inodes.
        if self.rev_level != 1 {
            return Err(Error::Unsupported);
        }
        if self.inode_size as usize != crate::inode::INODE_SIZE {
            return Err(Error::Unsupported);
        }
        if self.first_data_block != SUPERBLOCK_BLOCK {
            return Err(Error::Unsupported);
        }
        if self.blocks_per_group == 0
            || self.blocks_per_group > BLOCK_SIZE as u32 * 8
            || self.inodes_per_group == 0
            || self.inodes_per_group > BLOCK_SIZE as u32 * 8
        {
            return Err(Error::BadSuperblock);
        }
        // Anything beyond FILETYPE changes the on-disk layout we must understand.
        if self.feature_incompat & !INCOMPAT_FILETYPE != 0 {
            return Err(Error::Unsupported);
        }
        let ro_known = RO_COMPAT_SPARSE_SUPER | RO_COMPAT_LARGE_FILE;
        if self.feature_ro_compat & !ro_known != 0 {
            return Err(Error::Unsupported);
        }
        if self.blocks_count <= self.first_data_block || self.inodes_count == 0 {
            return Err(Error::BadSuperblock);
        }
        if self.free_blocks_count > self.blocks_count {
            return Err(Error::BadSuperblock);
        }
        if self.free_inodes_count > self.inodes_count {
            return Err(Error::BadSuperblock);
        }
        // The inode table of one group must fit inside that group.
        let table_blocks = self.inode_table_blocks();
        if table_blocks == 0 || table_blocks >= self.blocks_per_group {
            return Err(Error::BadSuperblock);
        }
        // Descriptor table must fit in the first group.
        if self.gdt_blocks() == 0 || self.gdt_blocks() >= self.blocks_per_group {
            return Err(Error::BadSuperblock);
        }
        // The descriptor table must also fit inside the volume; otherwise every
        // group-descriptor read would land outside the device.
        if self
            .gdt_start_block()
            .checked_add(self.gdt_blocks())
            .ok_or(Error::BadSuperblock)?
            > self.blocks_count
        {
            return Err(Error::BadSuperblock);
        }
        // Inode numbering must be fully described by the group count.
        if self
            .group_count()
            .checked_mul(self.inodes_per_group)
            .ok_or(Error::BadSuperblock)?
            != self.inodes_count
        {
            return Err(Error::BadSuperblock);
        }
        if self.inode_table_blocks() as u64 * self.group_count() as u64 > self.blocks_count as u64 {
            return Err(Error::BadSuperblock);
        }
        Ok(())
    }

    /// Number of block groups in the volume.
    pub(crate) fn group_count(&self) -> u32 {
        // blocks_count > first_data_block and blocks_per_group > 0 (validated).
        let data_blocks = self.blocks_count - self.first_data_block;
        data_blocks.div_ceil(self.blocks_per_group)
    }

    /// First block (inclusive) belonging to group `group`.
    pub(crate) fn group_first_block(&self, group: u32) -> u32 {
        // Callers must pass a validated group index; the multiply is bounded by
        // blocks_count <= u32::MAX because the volume fits a 32-bit block count.
        self.first_data_block + group * self.blocks_per_group
    }

    /// Number of blocks in group `group` (the last group may be partial).
    pub(crate) fn group_block_count(&self, group: u32) -> u32 {
        let first = self.group_first_block(group);
        if first >= self.blocks_count {
            0
        } else {
            let remaining = self.blocks_count - first;
            remaining.min(self.blocks_per_group)
        }
    }

    /// First inode number belonging to group `group`.
    pub(crate) fn group_first_inode(&self, group: u32) -> u32 {
        group * self.inodes_per_group + 1
    }

    /// Block holding the first block-group descriptor.
    pub(crate) fn gdt_start_block(&self) -> u32 {
        self.first_data_block + 1
    }

    /// Number of blocks the block-group descriptor table occupies.
    pub(crate) fn gdt_blocks(&self) -> u32 {
        let bytes = self.group_count() as usize * DESC_SIZE;
        (bytes.div_ceil(BLOCK_SIZE)) as u32
    }

    /// First block of `group` that may hold that group's own metadata
    /// (bitmaps and inode table).
    ///
    /// Group 0 additionally holds the boot block, the superblock and the group
    /// descriptor table, so its metadata starts after them. Every other group
    /// starts at its first block.
    ///
    /// This is the boundary allocation must never cross: a descriptor (or a
    /// bitmap) that points below it would let a bitmap write land on the
    /// superblock or on the descriptor table itself.
    pub(crate) fn group_meta_start(&self, group: u32) -> u32 {
        if group == 0 {
            self.gdt_start_block().saturating_add(self.gdt_blocks())
        } else {
            self.group_first_block(group)
        }
    }

    /// Blocks occupied by one group's inode table.
    pub(crate) fn inode_table_blocks(&self) -> u32 {
        let bytes = self.inodes_per_group as usize * crate::inode::INODE_SIZE;
        (bytes.div_ceil(BLOCK_SIZE)) as u32
    }

    /// Patch the mutable counters into a raw superblock block (preserving every
    /// field this driver does not understand).
    pub(crate) fn write_into(&self, block: &mut [u8; BLOCK_SIZE]) {
        crate::le::put_u32le(block, OFF_FREE_BLOCKS_COUNT, self.free_blocks_count);
        crate::le::put_u32le(block, OFF_FREE_INODES_COUNT, self.free_inodes_count);
        crate::le::put_u32le(block, OFF_MTIME, self.mtime);
        crate::le::put_u32le(block, OFF_WTIME, self.wtime);
        crate::le::put_u16le(block, OFF_MNT_COUNT, self.mnt_count);
        crate::le::put_u16le(block, OFF_STATE, self.state);
    }

    /// Encode a fresh rev-1 superblock matching the layout [`crate::format`]
    /// lays down. Fields this driver never changes are written once, explicitly,
    /// so a formatted volume is complete even on virgin media.
    pub(crate) fn encode_fresh_into(
        block: &mut [u8; BLOCK_SIZE],
        blocks_count: u32,
        inodes_count: u32,
        blocks_per_group: u32,
        inodes_per_group: u32,
        free_blocks_count: u32,
        free_inodes_count: u32,
    ) {
        block.fill(0);
        let put32 = crate::le::put_u32le;
        let put16 = crate::le::put_u16le;
        put32(block, OFF_INODES_COUNT, inodes_count);
        put32(block, OFF_BLOCKS_COUNT, blocks_count);
        // Keep a 5% superuser reserve, like mke2fs; the driver never allocates
        // from it, it is only reported.
        put32(block, OFF_R_BLOCKS_COUNT, blocks_count / 20);
        put32(block, OFF_FREE_BLOCKS_COUNT, free_blocks_count);
        put32(block, OFF_FREE_INODES_COUNT, free_inodes_count);
        put32(block, OFF_FIRST_DATA_BLOCK, SUPERBLOCK_BLOCK);
        put32(block, OFF_LOG_BLOCK_SIZE, 0);
        put32(block, OFF_LOG_FRAG_SIZE, 0);
        put32(block, OFF_BLOCKS_PER_GROUP, blocks_per_group);
        put32(block, OFF_FRAGS_PER_GROUP, blocks_per_group);
        put32(block, OFF_INODES_PER_GROUP, inodes_per_group);
        put16(block, OFF_MNT_COUNT, 0);
        put16(block, OFF_MAX_MNT_COUNT, u16::MAX);
        put16(block, OFF_MAGIC, MAGIC);
        // s_state: cleanly unmounted (VALID_FS).
        put16(block, OFF_STATE, 1);
        // s_errors: continue on errors (no panic remount semantics needed).
        put16(block, OFF_ERRORS, 1);
        put16(block, OFF_MINOR_REV_LEVEL, 0);
        put32(block, OFF_REV_LEVEL, 1);
        put16(block, OFF_DEF_RESUID, 0);
        put16(block, OFF_DEF_RESGID, 0);
        put32(block, OFF_FIRST_INO, FIRST_NON_RESERVED_INODE);
        put16(block, OFF_INODE_SIZE, crate::inode::INODE_SIZE as u16);
        put16(block, OFF_BLOCK_GROUP_NR, 0);
        put32(block, OFF_FEATURE_COMPAT, 0);
        put32(block, OFF_FEATURE_INCOMPAT, INCOMPAT_FILETYPE);
        put32(
            block,
            OFF_FEATURE_RO_COMPAT,
            RO_COMPAT_SPARSE_SUPER | RO_COMPAT_LARGE_FILE,
        );
        block[OFF_UUID..OFF_UUID + 16].copy_from_slice(b"caelum-ext2-0001");
        block[OFF_VOLUME_NAME..OFF_VOLUME_NAME + 16].copy_from_slice(b"caelum-root\0\0\0\0\0");
        put32(block, OFF_ALGORITHM_USAGE, 0);
        block[OFF_PREALLOC_BLOCKS] = 0;
        block[OFF_PREALLOC_DIR_BLOCKS] = 0;
        put16(block, OFF_RESERVED_GDT, 0);
        block[OFF_JOURNAL_UUID..OFF_JOURNAL_UUID + 16].fill(0);
        put32(block, OFF_JOURNAL_INUM, 0);
        put32(block, OFF_JOURNAL_DEV, 0);
        put32(block, OFF_LAST_ORPHAN, 0);
    }
}

/// Parsed block-group descriptor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct GroupDesc {
    pub block_bitmap: u32,
    pub inode_bitmap: u32,
    pub inode_table: u32,
    pub free_blocks: u16,
    pub free_inodes: u16,
    pub used_dirs: u16,
}

impl GroupDesc {
    /// Parse one 32-byte descriptor.
    pub(crate) fn parse(raw: &[u8]) -> Result<Self, Error> {
        if raw.len() < DESC_SIZE {
            return Err(Error::Corrupt);
        }
        Ok(Self {
            block_bitmap: u32le(raw, 0),
            inode_bitmap: u32le(raw, 4),
            inode_table: u32le(raw, 8),
            free_blocks: u16le(raw, 12),
            free_inodes: u16le(raw, 14),
            used_dirs: u16le(raw, 16),
        })
    }

    /// Encode into the first 32 bytes of `raw`.
    pub(crate) fn write_into(&self, raw: &mut [u8]) -> Result<(), Error> {
        if raw.len() < DESC_SIZE {
            return Err(Error::Corrupt);
        }
        crate::le::put_u32le(raw, 0, self.block_bitmap);
        crate::le::put_u32le(raw, 4, self.inode_bitmap);
        crate::le::put_u32le(raw, 8, self.inode_table);
        crate::le::put_u16le(raw, 12, self.free_blocks);
        crate::le::put_u16le(raw, 14, self.free_inodes);
        crate::le::put_u16le(raw, 16, self.used_dirs);
        Ok(())
    }

    /// Sanity-check the pointers against the volume geometry.
    ///
    /// A descriptor is trusted by every later operation — bitmap scans write
    /// through `block_bitmap`, inode-table access reads and writes through
    /// `inode_table` — so a bad pointer must be rejected while mounting, not
    /// discovered after a write already landed on somebody else's block. The
    /// checks are pure arithmetic on the superblock geometry: no I/O, no full
    /// bitmap scan.
    pub(crate) fn validate(&self, sb: &Superblock, group: u32) -> Result<(), Error> {
        if group >= sb.group_count() {
            return Err(Error::Corrupt);
        }
        let start = sb.group_meta_start(group);
        let end = sb
            .group_first_block(group)
            .checked_add(sb.group_block_count(group))
            .ok_or(Error::Corrupt)?;
        if start >= end {
            return Err(Error::Corrupt);
        }
        // Every metadata pointer must live in this group, below the superblock /
        // descriptor-table area for group 0.
        for block in [self.block_bitmap, self.inode_bitmap, self.inode_table] {
            if block < start || block >= end {
                return Err(Error::Corrupt);
            }
        }
        if self.block_bitmap == self.inode_bitmap {
            return Err(Error::Corrupt);
        }
        // The inode table must fit in the group, and neither bitmap may alias
        // part of it (that would make an inode write scribble over a bitmap).
        let table_end = self
            .inode_table
            .checked_add(sb.inode_table_blocks())
            .ok_or(Error::Corrupt)?;
        if table_end > end {
            return Err(Error::Corrupt);
        }
        for block in [self.block_bitmap, self.inode_bitmap] {
            if block >= self.inode_table && block < table_end {
                return Err(Error::Corrupt);
            }
        }
        if self.free_blocks as u32 > sb.group_block_count(group)
            || self.free_inodes as u32 > sb.inodes_per_group
        {
            return Err(Error::Corrupt);
        }
        Ok(())
    }
}
