//! Block and inode allocation: bitmap scans plus group-descriptor/superblock
//! counter updates.
//!
//! Allocation is first-fit over block groups, always re-reading the bitmap from
//! disk. That costs one block read per group probe but keeps the working set at
//! two caller-owned 1 KiB buffers, which matters on the boot stack, and it means
//! a volume edited behind our back is never trusted from a stale cached bitmap.
//!
//! Every successful allocation/deallocation updates three places in lockstep —
//! the bitmap block, the group descriptor, and the superblock counters — so a
//! crash between any two writes leaves a detectable, not silently corrupt,
//! volume.
//!
//! The metadata itself is never a candidate for allocation: before the first
//! bitmap write of an allocation, the block is checked against the group's
//! boot/superblock/descriptor area, both bitmap blocks and the inode-table
//! span. A volume whose bitmap marks one of those free is reported as
//! [`Error::Corrupt`] with no bytes written, instead of being "repaired" by
//! scribbling over metadata.

use block::BlockDevice;

use crate::sb::{self, DESC_SIZE, GroupDesc};
use crate::{BLOCK_SIZE, BlockBuf, Error, Ext2};

impl<D: BlockDevice> Ext2<D> {
    // ------------------------------------------------------------- descriptors

    /// Read block-group descriptor `group` into `aux`.
    pub(crate) fn read_group_desc(
        &mut self,
        group: u32,
        aux: &mut BlockBuf,
    ) -> Result<GroupDesc, Error> {
        if group >= self.sb.group_count() {
            return Err(Error::Corrupt);
        }
        let byte = group as usize * DESC_SIZE;
        let block = self.sb.gdt_start_block() + (byte / BLOCK_SIZE) as u32;
        let off = byte % BLOCK_SIZE;
        self.read_block(block, aux)?;
        GroupDesc::parse(&aux[off..off + DESC_SIZE])
    }

    /// Write block-group descriptor `group` back, preserving unknown fields.
    pub(crate) fn write_group_desc(
        &mut self,
        group: u32,
        desc: &GroupDesc,
        aux: &mut BlockBuf,
    ) -> Result<(), Error> {
        if group >= self.sb.group_count() {
            return Err(Error::Corrupt);
        }
        let byte = group as usize * DESC_SIZE;
        let block = self.sb.gdt_start_block() + (byte / BLOCK_SIZE) as u32;
        let off = byte % BLOCK_SIZE;
        self.read_block(block, aux)?;
        desc.write_into(&mut aux[off..off + DESC_SIZE])?;
        self.write_block(block, aux)
    }

    /// Persist the superblock counters (via `aux`).
    pub(crate) fn write_superblock(&mut self, aux: &mut BlockBuf) -> Result<(), Error> {
        self.read_block(sb::SUPERBLOCK_BLOCK, aux)?;
        self.sb.write_into(aux);
        self.write_block(sb::SUPERBLOCK_BLOCK, aux)
    }

    /// Block group owning `block`.
    pub(crate) fn group_of_block(&self, block: u32) -> Result<u32, Error> {
        if block < self.sb.first_data_block || block >= self.sb.blocks_count {
            return Err(Error::Corrupt);
        }
        Ok((block - self.sb.first_data_block) / self.sb.blocks_per_group)
    }

    /// Block group owning inode `ino`.
    pub(crate) fn group_of_inode(&self, ino: u32) -> Result<u32, Error> {
        if ino == 0 || ino > self.sb.inodes_count {
            return Err(Error::NotFound);
        }
        Ok((ino - 1) / self.sb.inodes_per_group)
    }

    // ---------------------------------------------------------------- bitmaps

    /// Bit index inside a bitmap block.
    fn bit_get(bitmap: &BlockBuf, index: u32) -> bool {
        (bitmap[index as usize / 8] >> (index % 8)) & 1 != 0
    }

    fn bit_set(bitmap: &mut BlockBuf, index: u32) {
        bitmap[index as usize / 8] |= 1 << (index % 8);
    }

    fn bit_clear(bitmap: &mut BlockBuf, index: u32) {
        bitmap[index as usize / 8] &= !(1 << (index % 8));
    }

    /// Read bitmap block `block` into the caller's buffer.
    fn load_bitmap(&mut self, block: u32, out: &mut BlockBuf) -> Result<(), Error> {
        self.read_block(block, out)
    }

    /// Is `block` reserved by `group`'s metadata instead of being data?
    ///
    /// Covers the boot block / superblock / descriptor-table area (everything
    /// below the group's metadata start), both bitmap blocks and the inode-table
    /// span. Allocation and release both refuse to touch such a block even when
    /// the on-disk bitmap claims it is free: the bitmap is the thing that may be
    /// lying, and metadata must never be handed out or marked free.
    fn is_metadata_block(&self, group: u32, desc: &GroupDesc, block: u32) -> bool {
        if block < self.sb.group_meta_start(group) {
            return true;
        }
        let table_end = desc
            .inode_table
            .saturating_add(self.sb.inode_table_blocks());
        block == desc.block_bitmap
            || block == desc.inode_bitmap
            || (block >= desc.inode_table && block < table_end)
    }

    // ------------------------------------------------------------ allocation

    /// Allocate one block and zero it, so new file/directory data never exposes
    /// a previously freed block's contents.
    pub(crate) fn alloc_clear_block(
        &mut self,
        buf: &mut BlockBuf,
        aux: &mut BlockBuf,
    ) -> Result<u32, Error> {
        let block = self.alloc_block(buf, aux)?;
        buf.fill(0);
        self.write_block(block, buf)?;
        Ok(block)
    }

    /// Allocate one block, returning its number (contents are undefined).
    ///
    /// `buf` holds the bitmap block being scanned, `aux` is reused for the group
    /// descriptor and the superblock: both are touched one after the other, so
    /// two buffers are enough.
    ///
    /// Every check that can fail runs before the first write: a corrupt
    /// descriptor or a bitmap that marks metadata free leaves the volume exactly
    /// as it was found.
    pub(crate) fn alloc_block(
        &mut self,
        buf: &mut BlockBuf,
        aux: &mut BlockBuf,
    ) -> Result<u32, Error> {
        for group in 0..self.sb.group_count() {
            let mut desc = self.read_group_desc(group, aux)?;
            desc.validate(&self.sb, group)?;
            if desc.free_blocks == 0 {
                continue;
            }
            let count = self.sb.group_block_count(group);
            self.load_bitmap(desc.block_bitmap, buf)?;
            for index in 0..count {
                if Self::bit_get(buf, index) {
                    continue;
                }
                let block = self.sb.group_first_block(group) + index;
                if block < self.sb.first_data_block || block >= self.sb.blocks_count {
                    return Err(Error::Corrupt);
                }
                if self.is_metadata_block(group, &desc, block) {
                    return Err(Error::Corrupt);
                }
                Self::bit_set(buf, index);
                self.write_block(desc.block_bitmap, buf)?;
                desc.free_blocks -= 1;
                self.write_group_desc(group, &desc, aux)?;
                self.sb.free_blocks_count = self.sb.free_blocks_count.saturating_sub(1);
                self.write_superblock(aux)?;
                return Ok(block);
            }
            // The descriptor claimed free blocks but no bit in the group is
            // free: the volume is inconsistent. Report it instead of writing a
            // "repaired" counter over metadata we do not understand.
            return Err(Error::Corrupt);
        }
        Err(Error::NoSpace)
    }

    /// Release one block back to its group.
    pub(crate) fn free_block(
        &mut self,
        block: u32,
        buf: &mut BlockBuf,
        aux: &mut BlockBuf,
    ) -> Result<(), Error> {
        let group = self.group_of_block(block)?;
        let index = block - self.sb.group_first_block(group);
        if index >= self.sb.group_block_count(group) {
            return Err(Error::Corrupt);
        }
        let mut desc = self.read_group_desc(group, aux)?;
        desc.validate(&self.sb, group)?;
        // Freeing metadata would hand it to the next allocation: refuse before
        // the bitmap is touched.
        if self.is_metadata_block(group, &desc, block) {
            return Err(Error::Corrupt);
        }
        self.load_bitmap(desc.block_bitmap, buf)?;
        if !Self::bit_get(buf, index) {
            // Freeing an already-free block means our metadata is inconsistent;
            // report it instead of silently double-counting free space.
            return Err(Error::Corrupt);
        }
        Self::bit_clear(buf, index);
        self.write_block(desc.block_bitmap, buf)?;
        desc.free_blocks = desc.free_blocks.saturating_add(1);
        self.write_group_desc(group, &desc, aux)?;
        self.sb.free_blocks_count = self.sb.free_blocks_count.saturating_add(1);
        self.write_superblock(aux)
    }

    /// Allocate one inode number (never one of the reserved first inodes).
    pub(crate) fn alloc_inode(
        &mut self,
        buf: &mut BlockBuf,
        aux: &mut BlockBuf,
    ) -> Result<u32, Error> {
        for group in 0..self.sb.group_count() {
            let mut desc = self.read_group_desc(group, aux)?;
            desc.validate(&self.sb, group)?;
            if desc.free_inodes == 0 {
                continue;
            }
            self.load_bitmap(desc.inode_bitmap, buf)?;
            for index in 0..self.sb.inodes_per_group {
                let ino = self.sb.group_first_inode(group) + index;
                if ino < sb::FIRST_NON_RESERVED_INODE {
                    continue;
                }
                if Self::bit_get(buf, index) {
                    continue;
                }
                Self::bit_set(buf, index);
                self.write_block(desc.inode_bitmap, buf)?;
                desc.free_inodes -= 1;
                self.write_group_desc(group, &desc, aux)?;
                self.sb.free_inodes_count = self.sb.free_inodes_count.saturating_sub(1);
                self.write_superblock(aux)?;
                return Ok(ino);
            }
            // Descriptor says free inodes exist but the bitmap disagrees: report
            // the inconsistency instead of overwriting the counter.
            return Err(Error::Corrupt);
        }
        Err(Error::NoSpace)
    }

    /// Release one inode number.
    pub(crate) fn free_inode(
        &mut self,
        ino: u32,
        buf: &mut BlockBuf,
        aux: &mut BlockBuf,
    ) -> Result<(), Error> {
        // The reserved inodes (root, bad-blocks, the first ten numbers) are not
        // ours to release; doing so would let a later allocation reuse root.
        if ino < sb::FIRST_NON_RESERVED_INODE {
            return Err(Error::Corrupt);
        }
        let group = self.group_of_inode(ino)?;
        let index = ino - self.sb.group_first_inode(group);
        if index >= self.sb.inodes_per_group {
            return Err(Error::Corrupt);
        }
        let mut desc = self.read_group_desc(group, aux)?;
        desc.validate(&self.sb, group)?;
        self.load_bitmap(desc.inode_bitmap, buf)?;
        if !Self::bit_get(buf, index) {
            return Err(Error::Corrupt);
        }
        Self::bit_clear(buf, index);
        self.write_block(desc.inode_bitmap, buf)?;
        desc.free_inodes = desc.free_inodes.saturating_add(1);
        self.write_group_desc(group, &desc, aux)?;
        self.sb.free_inodes_count = self.sb.free_inodes_count.saturating_add(1);
        self.write_superblock(aux)
    }

    /// Adjust the per-group directory counter (`used_dirs`).
    pub(crate) fn adjust_used_dirs(
        &mut self,
        group: u32,
        delta: i32,
        aux: &mut BlockBuf,
    ) -> Result<(), Error> {
        let mut desc = self.read_group_desc(group, aux)?;
        if delta >= 0 {
            desc.used_dirs = desc.used_dirs.saturating_add(delta as u16);
        } else {
            desc.used_dirs = desc.used_dirs.saturating_sub(delta.unsigned_abs() as u16);
        }
        self.write_group_desc(group, &desc, aux)
    }
}
