//! Creating a fresh ext2 volume ([`format`]).
//!
//! The layout is fixed and simple so `xtask` (host) and the kernel agree on the
//! same on-disk facts, and so tests use whatever device size they like instead
//! of a hand-carved fixture:
//!
//! ```text
//! block 0                 boot block (zeroed, unused)
//! block 1                 superblock
//! blocks 2 .. 2+G        block-group descriptor table
//! per group:              block bitmap, inode bitmap, inode table (256 blocks)
//! remaining blocks        data area (first data block of group 0 = root dir)
//! ```
//!
//! Groups hold [`BLOCKS_PER_GROUP`] blocks; inodes are [`INODES_PER_GROUP`] per
//! group, so a 2 MiB image has one group and a 32 MiB image has four.

use block::BlockDevice;

use crate::inode::{self, INODE_SIZE};
use crate::sb::{self, DESC_SIZE, GroupDesc};
use crate::{BLOCK_SIZE, BlockBuf, Error, NodeKind, dir, map_block_error};

/// Blocks covered by one block bitmap (8 bits per byte).
pub(crate) const BLOCKS_PER_GROUP: u32 = BLOCK_SIZE as u32 * 8;

/// Inodes per group. Deliberately smaller than the bitmap allows: 1024 inodes
/// per group costs 256 KiB of inode table instead of 2 MiB, which keeps small
/// volumes (2 MiB test images) usable.
pub(crate) const INODES_PER_GROUP: u32 = 1024;

/// Blocks one group's inode table occupies.
pub(crate) const INODE_TABLE_BLOCKS: u32 =
    (INODES_PER_GROUP as usize * INODE_SIZE).div_ceil(BLOCK_SIZE) as u32;

/// Inodes reserved by the specification (1 = bad blocks, 2 = root, 3..10 reserved).
const RESERVED_INODES: u32 = sb::FIRST_NON_RESERVED_INODE - 1;

/// First data block on a 1 KiB-block volume.
const FIRST_DATA_BLOCK: u32 = sb::SUPERBLOCK_BLOCK;

/// Per-group metadata layout.
struct GroupLayout {
    first_block: u32,
    block_bitmap: u32,
    inode_bitmap: u32,
    inode_table: u32,
    data_start: u32,
    block_count: u32,
    free_blocks: u16,
}

/// Compute the metadata layout of `group`.
fn layout(group: u32, blocks_count: u32, gdt_blocks: u32) -> Result<GroupLayout, Error> {
    let first_block = FIRST_DATA_BLOCK
        .checked_add(group.checked_mul(BLOCKS_PER_GROUP).ok_or(Error::NoSpace)?)
        .ok_or(Error::NoSpace)?;
    if first_block >= blocks_count {
        return Err(Error::NoSpace);
    }
    let block_count = (blocks_count - first_block).min(BLOCKS_PER_GROUP);
    let prefix = if group == 0 { 1 + gdt_blocks } else { 0 };
    let block_bitmap = first_block + prefix;
    let inode_bitmap = block_bitmap + 1;
    let inode_table = inode_bitmap + 1;
    let data_start = inode_table + INODE_TABLE_BLOCKS;
    let metadata = data_start - first_block;
    // Every group needs at least one data block; group 0 additionally loses its
    // first data block to the root directory.
    let reserve = if group == 0 { 1 } else { 0 };
    if block_count <= metadata + reserve {
        return Err(Error::NoSpace);
    }
    let free_blocks = (block_count - metadata - reserve) as u16;
    Ok(GroupLayout {
        first_block,
        block_bitmap,
        inode_bitmap,
        inode_table,
        data_start,
        block_count,
        free_blocks,
    })
}

/// Write one 1 KiB ext2 block to `device`, splitting for 512-byte devices.
fn write_dev_block<D: BlockDevice>(
    device: &mut D,
    block: u32,
    buf: &BlockBuf,
) -> Result<(), Error> {
    if device.block_size() as usize == BLOCK_SIZE {
        device
            .write_blocks(block as u64, &buf[..])
            .map_err(map_block_error)
    } else {
        let first = block as u64 * 2;
        device
            .write_blocks(first, &buf[..512])
            .map_err(map_block_error)?;
        device
            .write_blocks(first + 1, &buf[512..])
            .map_err(map_block_error)
    }
}

/// Create a fresh ext2 volume covering the whole device.
///
/// The device must report 512-byte or 1 KiB blocks; larger device blocks are
/// rejected because this driver deliberately holds only two 1 KiB buffers.
pub fn format<D: BlockDevice>(device: &mut D) -> Result<(), Error> {
    let dev_block = device.block_size();
    if dev_block != 512 && dev_block as usize != BLOCK_SIZE {
        return Err(Error::Unsupported);
    }
    let capacity = device.byte_capacity();
    let blocks_count = (capacity / BLOCK_SIZE as u64).min(u32::MAX as u64) as u32;
    if blocks_count <= FIRST_DATA_BLOCK + 4 {
        return Err(Error::NoSpace);
    }
    let data_blocks = blocks_count - FIRST_DATA_BLOCK;
    let groups = data_blocks.div_ceil(BLOCKS_PER_GROUP);
    let gdt_blocks = ((groups as usize * DESC_SIZE).div_ceil(BLOCK_SIZE)) as u32;

    // Pass 1: validate the geometry fits and total the free-block counter.
    let mut free_blocks = 0u32;
    for group in 0..groups {
        let group_layout = layout(group, blocks_count, gdt_blocks)?;
        free_blocks += group_layout.free_blocks as u32;
    }
    let inodes_count = groups * INODES_PER_GROUP;
    let free_inodes = inodes_count - RESERVED_INODES;

    // The whole writer runs on these two caller-owned buffers: `buf` for the
    // block being produced, `aux` for the descriptor block it shares with others.
    let mut buf = [0u8; BLOCK_SIZE];
    let mut aux = [0u8; BLOCK_SIZE];

    // Pass 2: wipe the fixed metadata area so no stale filesystem survives.
    buf.fill(0);
    write_dev_block(device, 0, &buf)?;
    write_dev_block(device, FIRST_DATA_BLOCK, &buf)?;
    for index in 0..gdt_blocks {
        write_dev_block(device, FIRST_DATA_BLOCK + 1 + index, &buf)?;
    }

    // Superblock.
    buf.fill(0);
    sb::Superblock::encode_fresh_into(
        &mut buf,
        blocks_count,
        inodes_count,
        BLOCKS_PER_GROUP,
        INODES_PER_GROUP,
        free_blocks,
        free_inodes,
    );
    write_dev_block(device, FIRST_DATA_BLOCK, &buf)?;

    // Block-group descriptors.
    let root_data = layout(0, blocks_count, gdt_blocks)?.data_start;
    for group in 0..groups {
        let group_layout = layout(group, blocks_count, gdt_blocks)?;
        let desc = GroupDesc {
            block_bitmap: group_layout.block_bitmap,
            inode_bitmap: group_layout.inode_bitmap,
            inode_table: group_layout.inode_table,
            free_blocks: group_layout.free_blocks,
            // The reserved inodes live in group 0 only, so its free-inode
            // counter must not claim them: the bitmaps and the counters have to
            // agree, otherwise allocation fails the consistency check below
            // instead of walking on into the next group.
            free_inodes: INODES_PER_GROUP as u16
                - if group == 0 {
                    RESERVED_INODES as u16
                } else {
                    0
                },
            used_dirs: if group == 0 { 1 } else { 0 },
        };
        let byte = group as usize * DESC_SIZE;
        let block = FIRST_DATA_BLOCK + 1 + (byte / BLOCK_SIZE) as u32;
        let off = byte % BLOCK_SIZE;
        // Only the first descriptor block is non-zero, but read-modify-write
        // keeps this correct for any group count.
        aux.fill(0);
        if off != 0 {
            // Descriptor shares a block with previously written entries.
            read_dev_block(device, block, &mut aux)?;
        }
        desc.write_into(&mut aux[off..off + DESC_SIZE])?;
        write_dev_block(device, block, &aux)?;
    }

    // Per-group bitmaps and inode tables.
    for group in 0..groups {
        let group_layout = layout(group, blocks_count, gdt_blocks)?;

        // Block bitmap: mark metadata (and the root data block) used, and every
        // bit past the end of the group used so allocation never leaves the
        // device.
        buf.fill(0);
        let used_prefix = group_layout.data_start - group_layout.first_block;
        let used = if group == 0 {
            used_prefix + 1
        } else {
            used_prefix
        };
        for index in 0..used {
            set_bit(&mut buf, index);
        }
        for index in group_layout.block_count..BLOCKS_PER_GROUP {
            set_bit(&mut buf, index);
        }
        write_dev_block(device, group_layout.block_bitmap, &buf)?;

        // Inode bitmap: only fixed metadata blocks are non-zero; mark the
        // reserved inodes used in group 0 and no tail (inodes per group is exact).
        aux.fill(0);
        if group == 0 {
            for index in 0..RESERVED_INODES {
                set_bit(&mut aux, index);
            }
        }
        write_dev_block(device, group_layout.inode_bitmap, &aux)?;

        // Inode table: zero every block, then place the root inode in group 0.
        buf.fill(0);
        for index in 0..INODE_TABLE_BLOCKS {
            write_dev_block(device, group_layout.inode_table + index, &buf)?;
        }
        if group == 0 {
            let mut root = inode::Inode::create(NodeKind::Directory, 0);
            root.set_links(2);
            root.set_size(BLOCK_SIZE as u32);
            root.set_block(0, root_data);
            root.add_blocks_1k(1);
            let offset = (sb::ROOT_INODE as usize - 1) * INODE_SIZE;
            buf[offset..offset + INODE_SIZE].copy_from_slice(&root.raw);
            write_dev_block(device, group_layout.inode_table, &buf)?;
        }
    }

    // Root directory contents: "." and ".." both point at inode 2.
    aux.fill(0);
    dir::init_directory_block(&mut aux, sb::ROOT_INODE, sb::ROOT_INODE)?;
    write_dev_block(device, root_data, &aux)?;

    // The volume is consistent; make sure the counters reached the platter.
    device.flush().map_err(map_block_error)?;
    Ok(())
}

/// Read one 1 KiB ext2 block from `device` (512-byte devices split in two).
fn read_dev_block<D: BlockDevice>(
    device: &mut D,
    block: u32,
    out: &mut BlockBuf,
) -> Result<(), Error> {
    if device.block_size() as usize == BLOCK_SIZE {
        device
            .read_blocks(block as u64, &mut out[..])
            .map_err(map_block_error)
    } else {
        let first = block as u64 * 2;
        device
            .read_blocks(first, &mut out[..512])
            .map_err(map_block_error)?;
        device
            .read_blocks(first + 1, &mut out[512..])
            .map_err(map_block_error)
    }
}

/// Mark bit `index` in a bitmap block.
fn set_bit(bitmap: &mut BlockBuf, index: u32) {
    bitmap[index as usize / 8] |= 1 << (index % 8);
}

const _: () = {
    // Guard the layout assumptions documented above.
    assert!(BLOCKS_PER_GROUP == 8192);
    assert!(INODE_TABLE_BLOCKS as usize * BLOCK_SIZE >= INODES_PER_GROUP as usize * INODE_SIZE);
};
