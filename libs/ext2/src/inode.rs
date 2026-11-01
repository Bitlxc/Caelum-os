//! The 256-byte ext2 inode: field accessors over the raw on-disk bytes.
//!
//! Keeping the raw array (instead of a lossy struct) means unknown/reserved
//! fields survive a read-modify-write cycle untouched, and nothing about the
//! layout has to be re-derived at write time.

use crate::NodeKind;
use crate::le::{u16le, u32le};

/// On-disk inode size for every volume this driver accepts.
pub(crate) const INODE_SIZE: usize = 256;

/// Direct block pointers in `i_block`.
pub(crate) const DIRECT_BLOCKS: usize = 12;

/// 32-bit block pointers per 1 KiB index block.
pub(crate) const PTRS_PER_BLOCK: usize = crate::BLOCK_SIZE / 4;

/// Index of the single-indirect pointer in `i_block`.
pub(crate) const SINGLE_INDIRECT_INDEX: usize = DIRECT_BLOCKS;

/// Index of the double-indirect pointer in `i_block`.
///
/// The triple-indirect pointer (`i_block[14]`) is deliberately left unused.
pub(crate) const DOUBLE_INDIRECT_INDEX: usize = DIRECT_BLOCKS + 1;

/// Logical blocks addressable by the double-indirect level (two pointer levels).
pub(crate) const DOUBLE_BLOCKS: usize = PTRS_PER_BLOCK * PTRS_PER_BLOCK;

/// Highest number of logical blocks this driver can address: the 12 direct
/// pointers, one single-indirect block, and one double-indirect tree (each
/// pointer block also covers the index block itself, hence the `+ 1` terms).
pub(crate) const MAX_BLOCKS: usize = DIRECT_BLOCKS + PTRS_PER_BLOCK + DOUBLE_BLOCKS;

/// Offset of `i_block[0]` inside the inode.
const OFF_MODE: usize = 0x00;
const OFF_SIZE: usize = 0x04;
const OFF_ATIME: usize = 0x08;
const OFF_CTIME: usize = 0x0C;
const OFF_MTIME: usize = 0x10;
const OFF_DTIME: usize = 0x14;
const OFF_LINKS: usize = 0x1A;
const OFF_BLOCKS_512: usize = 0x1C;
const OFF_BLOCK: usize = 0x28;

/// `i_mode` for a regular file, `rmw-r--r--`.
pub(crate) const MODE_FILE: u16 = 0o100_644;

/// `i_mode` for a directory, `rwxr-xr-x`.
pub(crate) const MODE_DIR: u16 = 0o040_755;

/// `i_mode` type mask.
const S_IFMT: u16 = 0o170_000;
const S_IFDIR: u16 = 0o040_000;

/// A raw inode.
#[derive(Clone)]
pub(crate) struct Inode {
    pub raw: [u8; INODE_SIZE],
}

impl Inode {
    /// A zeroed inode (all block pointers point at "no block").
    pub(crate) fn zeroed() -> Self {
        Self {
            raw: [0u8; INODE_SIZE],
        }
    }

    /// Build a fresh inode for a new file or directory.
    pub(crate) fn create(kind: NodeKind, now: u32) -> Self {
        let mut inode = Self::zeroed();
        inode.set_mode(match kind {
            NodeKind::File => MODE_FILE,
            NodeKind::Directory => MODE_DIR,
        });
        inode.set_links(match kind {
            NodeKind::File => 1,
            // A directory starts with the implicit "." link plus its "." entry;
            // every child directory adds one more.
            NodeKind::Directory => 2,
        });
        inode.set_atime(now);
        inode.set_ctime(now);
        inode.set_mtime(now);
        inode
    }

    pub(crate) fn mode(&self) -> u16 {
        u16le(&self.raw, OFF_MODE)
    }

    pub(crate) fn set_mode(&mut self, mode: u16) {
        crate::le::put_u16le(&mut self.raw, OFF_MODE, mode);
    }

    pub(crate) fn kind(&self) -> Option<NodeKind> {
        match self.mode() & S_IFMT {
            S_IFDIR => Some(NodeKind::Directory),
            0o100_000 => Some(NodeKind::File),
            _ => None,
        }
    }

    pub(crate) fn size(&self) -> u32 {
        u32le(&self.raw, OFF_SIZE)
    }

    pub(crate) fn set_size(&mut self, size: u32) {
        crate::le::put_u32le(&mut self.raw, OFF_SIZE, size);
    }

    pub(crate) fn links(&self) -> u16 {
        u16le(&self.raw, OFF_LINKS)
    }

    pub(crate) fn set_links(&mut self, links: u16) {
        crate::le::put_u16le(&mut self.raw, OFF_LINKS, links);
    }

    /// `i_blocks` in 512-byte units.
    pub(crate) fn blocks_512(&self) -> u32 {
        u32le(&self.raw, OFF_BLOCKS_512)
    }

    pub(crate) fn set_blocks_512(&mut self, blocks: u32) {
        crate::le::put_u32le(&mut self.raw, OFF_BLOCKS_512, blocks);
    }

    /// Account for `count` 1 KiB blocks (data or index) in `i_blocks`.
    pub(crate) fn add_blocks_1k(&mut self, count: u32) {
        self.set_blocks_512(self.blocks_512().saturating_add(count * 2));
    }

    /// Remove `count` 1 KiB blocks from `i_blocks` (saturating at zero).
    pub(crate) fn sub_blocks_1k(&mut self, count: u32) {
        self.set_blocks_512(self.blocks_512().saturating_sub(count * 2));
    }

    pub(crate) fn set_dtime(&mut self, dtime: u32) {
        crate::le::put_u32le(&mut self.raw, OFF_DTIME, dtime);
    }

    pub(crate) fn mtime(&self) -> u32 {
        u32le(&self.raw, OFF_MTIME)
    }

    pub(crate) fn set_atime(&mut self, atime: u32) {
        crate::le::put_u32le(&mut self.raw, OFF_ATIME, atime);
    }

    pub(crate) fn set_ctime(&mut self, ctime: u32) {
        crate::le::put_u32le(&mut self.raw, OFF_CTIME, ctime);
    }

    pub(crate) fn set_mtime(&mut self, mtime: u32) {
        crate::le::put_u32le(&mut self.raw, OFF_MTIME, mtime);
    }

    /// Raw value of `i_block[index]` (0 means the index does not exist / hole).
    pub(crate) fn block(&self, index: usize) -> u32 {
        u32le(&self.raw, OFF_BLOCK + index * 4)
    }

    pub(crate) fn set_block(&mut self, index: usize, block: u32) {
        crate::le::put_u32le(&mut self.raw, OFF_BLOCK + index * 4, block);
    }
}
