//! ext2 directory entries: decoding, name validation, and slot bookkeeping.
//!
//! A directory is a sequence of 1 KiB blocks, each holding variable-length
//! entries that never straddle a block boundary. Every entry's `rec_len` covers
//! the rest of its slot, so a block is fully described by walking `rec_len`.

use crate::le::{put_u16le, put_u32le, u16le, u32le};
use crate::{BLOCK_SIZE, Error, NodeKind};

/// Fixed part of a directory entry.
pub(crate) const DIRENT_HEADER: usize = 8;

/// Maximum name length accepted by this driver (`name[32]` minus the trailing
/// NUL used by [`crate::ExtDirEntry`]).
pub(crate) const MAX_NAME_LEN: usize = 31;

/// `file_type` value for a regular file.
pub(crate) const FILE_TYPE_REGULAR: u8 = 1;

/// `file_type` value for a directory.
pub(crate) const FILE_TYPE_DIRECTORY: u8 = 2;

/// A parsed directory entry inside one block.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Slot {
    /// Byte offset of the entry inside its block.
    pub off: usize,
    pub inode: u32,
    pub rec_len: u16,
    pub name_len: u8,
    pub file_type: u8,
}

impl Slot {
    /// Bytes this slot actually uses (header + name rounded up to 4).
    pub(crate) fn used_len(&self) -> usize {
        (DIRENT_HEADER + self.name_len as usize).div_ceil(4) * 4
    }

    /// Free bytes in this slot when it holds a live entry.
    pub(crate) fn slack(&self) -> usize {
        (self.rec_len as usize).saturating_sub(self.used_len())
    }
}

/// Reject names that are not representable in an ext2 directory.
pub(crate) fn validate_name(name: &[u8]) -> Result<(), Error> {
    if name.is_empty() {
        return Err(Error::NameInvalid);
    }
    if name.len() > MAX_NAME_LEN {
        return Err(Error::NameTooLong);
    }
    for &byte in name {
        if byte == 0 || byte == b'/' {
            return Err(Error::NameInvalid);
        }
    }
    Ok(())
}

/// Smallest `rec_len` that can hold a name of `name_len` bytes (4-byte aligned).
pub(crate) fn min_rec_len(name_len: usize) -> u16 {
    ((DIRENT_HEADER + name_len).div_ceil(4) * 4) as u16
}

/// Parse the entry starting at `off` inside `block`, bounded by `block_limit`
/// (the directory's valid bytes in this block, normally [`BLOCK_SIZE`]).
pub(crate) fn parse_slot(
    block: &[u8; BLOCK_SIZE],
    off: usize,
    block_limit: usize,
) -> Result<Slot, Error> {
    if off + DIRENT_HEADER > block_limit {
        return Err(Error::Corrupt);
    }
    let slot = Slot {
        off,
        inode: u32le(block, off),
        rec_len: u16le(block, off + 4),
        name_len: block[off + 6],
        file_type: block[off + 7],
    };
    let rec_len = slot.rec_len as usize;
    // `rec_len` must be 4-byte aligned and keep the entry inside the block.
    if rec_len < DIRENT_HEADER
        || !rec_len.is_multiple_of(4)
        || off + rec_len > block_limit
        || DIRENT_HEADER + slot.name_len as usize > rec_len
    {
        return Err(Error::Corrupt);
    }
    Ok(slot)
}

/// Entry name bytes.
pub(crate) fn slot_name<'a>(block: &'a [u8; BLOCK_SIZE], slot: &Slot) -> &'a [u8] {
    let start = slot.off + DIRENT_HEADER;
    &block[start..start + slot.name_len as usize]
}

/// Map an on-disk `file_type` to a [`NodeKind`]; unknown values are resolved by
/// the caller from the target inode.
pub(crate) fn kind_from_file_type(file_type: u8) -> Option<NodeKind> {
    match file_type {
        FILE_TYPE_REGULAR => Some(NodeKind::File),
        FILE_TYPE_DIRECTORY => Some(NodeKind::Directory),
        _ => None,
    }
}

/// `file_type` for a [`NodeKind`].
pub(crate) fn file_type_from_kind(kind: NodeKind) -> u8 {
    match kind {
        NodeKind::File => FILE_TYPE_REGULAR,
        NodeKind::Directory => FILE_TYPE_DIRECTORY,
    }
}

/// Write a complete entry occupying `rec_len` bytes at `off`.
pub(crate) fn write_slot(
    block: &mut [u8; BLOCK_SIZE],
    off: usize,
    inode: u32,
    rec_len: u16,
    name: &[u8],
    kind: NodeKind,
) -> Result<(), Error> {
    let name_len = name.len();
    if name_len > MAX_NAME_LEN || (rec_len as usize) < min_rec_len(name_len) as usize {
        return Err(Error::NameTooLong);
    }
    if off + rec_len as usize > BLOCK_SIZE {
        return Err(Error::Corrupt);
    }
    put_u32le(block, off, inode);
    put_u16le(block, off + 4, rec_len);
    block[off + 6] = name_len as u8;
    block[off + 7] = file_type_from_kind(kind);
    // Clear the slot first so stale bytes never leak into the name area.
    for byte in block[off + DIRENT_HEADER..off + rec_len as usize].iter_mut() {
        *byte = 0;
    }
    block[off + DIRENT_HEADER..off + DIRENT_HEADER + name_len].copy_from_slice(name);
    Ok(())
}

/// Initialise an empty directory block with "." and ".." entries.
pub(crate) fn init_directory_block(
    block: &mut [u8; BLOCK_SIZE],
    self_inode: u32,
    parent_inode: u32,
) -> Result<(), Error> {
    for byte in block.iter_mut() {
        *byte = 0;
    }
    // "." occupies the minimum slot; ".." takes the remainder of the block.
    let dot_len = min_rec_len(1);
    write_slot(block, 0, self_inode, dot_len, b".", NodeKind::Directory)?;
    write_slot(
        block,
        dot_len as usize,
        parent_inode,
        (BLOCK_SIZE as u16) - dot_len,
        b"..",
        NodeKind::Directory,
    )?;
    Ok(())
}
