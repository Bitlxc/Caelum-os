//! Block mapping and file data I/O.
//!
//! Mapping is the classic ext2 scheme: 12 direct pointers, one single-indirect
//! block and one double-indirect tree. That is [`crate::MAX_FILE_SIZE`] bytes,
//! which is what the VFS bridge needs to host real Linux dynamic binaries.
//! The triple-indirect pointer is not implemented; logical block indices beyond
//! the double-indirect range fail with [`Error::Quota`] instead of wrapping into
//! a wrong pointer.
//!
//! Sparse files are first class: a zero pointer reads as zeros, and writes fill
//! holes by allocating zeroed blocks. No block is ever left with stale data from
//! a previously deleted file.
//!
//! Every helper takes caller-owned scratch buffers instead of owning a
//! block-sized array: `buf` carries the data/indirect block that is being worked
//! on, `aux` is spare for the indirect block when `buf` is already in use.

use block::BlockDevice;

use crate::inode::{
    DIRECT_BLOCKS, DOUBLE_INDIRECT_INDEX, Inode, MAX_BLOCKS, PTRS_PER_BLOCK, SINGLE_INDIRECT_INDEX,
};
use crate::le::{put_u32le, u32le};
use crate::{BLOCK_SIZE, BlockBuf, Error, Ext2, NodeKind};

/// First logical block that lives behind the double-indirect tree.
const DOUBLE_FIRST: usize = DIRECT_BLOCKS + PTRS_PER_BLOCK;

/// Split a double-indirect logical block into `(first-level slot, second-level
/// slot)`. The caller guarantees `index` is inside the double-indirect range.
fn double_slots(index: usize) -> (usize, usize) {
    let relative = index - DOUBLE_FIRST;
    (relative / PTRS_PER_BLOCK, relative % PTRS_PER_BLOCK)
}

impl<D: BlockDevice> Ext2<D> {
    /// Reject block numbers outside the data area of the volume.
    fn check_block(&self, block: u32) -> Result<(), Error> {
        if block < self.sb.first_data_block || block >= self.sb.blocks_count {
            return Err(Error::Corrupt);
        }
        Ok(())
    }

    /// Map logical block `index` of `inode`, or `None` for a hole.
    pub(crate) fn map_block(
        &mut self,
        inode: &Inode,
        index: u32,
        aux: &mut BlockBuf,
    ) -> Result<Option<u32>, Error> {
        if index as usize >= MAX_BLOCKS {
            return Err(Error::Quota);
        }
        if (index as usize) < DIRECT_BLOCKS {
            let block = inode.block(index as usize);
            if block == 0 {
                return Ok(None);
            }
            self.check_block(block)?;
            return Ok(Some(block));
        }
        if (index as usize) < DOUBLE_FIRST {
            let indirect = inode.block(SINGLE_INDIRECT_INDEX);
            if indirect == 0 {
                return Ok(None);
            }
            self.check_block(indirect)?;
            self.read_block(indirect, aux)?;
            let slot = (index as usize - DIRECT_BLOCKS) * 4;
            let block = u32le(aux, slot);
            if block == 0 {
                return Ok(None);
            }
            self.check_block(block)?;
            return Ok(Some(block));
        }
        let (first, second) = double_slots(index as usize);
        let root = inode.block(DOUBLE_INDIRECT_INDEX);
        if root == 0 {
            return Ok(None);
        }
        self.check_block(root)?;
        self.read_block(root, aux)?;
        let indirect = u32le(aux, first * 4);
        if indirect == 0 {
            return Ok(None);
        }
        self.check_block(indirect)?;
        self.read_block(indirect, aux)?;
        let block = u32le(aux, second * 4);
        if block == 0 {
            return Ok(None);
        }
        self.check_block(block)?;
        Ok(Some(block))
    }

    /// Return the physical block for `index`, allocating (and zeroing) it when
    /// the index is a hole. Newly allocated blocks are always zero-filled so a
    /// file never exposes another file's old contents.
    pub(crate) fn ensure_block(
        &mut self,
        inode: &mut Inode,
        index: u32,
        buf: &mut BlockBuf,
        aux: &mut BlockBuf,
    ) -> Result<u32, Error> {
        if index as usize >= MAX_BLOCKS {
            return Err(Error::Quota);
        }
        if (index as usize) < DIRECT_BLOCKS {
            let current = inode.block(index as usize);
            if current != 0 {
                self.check_block(current)?;
                return Ok(current);
            }
            let block = self.alloc_clear_block(buf, aux)?;
            inode.set_block(index as usize, block);
            inode.add_blocks_1k(1);
            return Ok(block);
        }
        if (index as usize) < DOUBLE_FIRST {
            let slot = (index as usize - DIRECT_BLOCKS) * 4;
            let mut indirect = inode.block(SINGLE_INDIRECT_INDEX);
            if indirect != 0 {
                self.check_block(indirect)?;
                self.read_block(indirect, aux)?;
                let current = u32le(aux, slot);
                if current != 0 {
                    self.check_block(current)?;
                    return Ok(current);
                }
            }
            // Allocation uses both buffers, so it happens before the indirect block
            // is (re-)read; the extra read only costs one block I/O on the cold path.
            let block = self.alloc_clear_block(buf, aux)?;
            if indirect == 0 {
                indirect = self.alloc_clear_block(buf, aux)?;
                inode.set_block(SINGLE_INDIRECT_INDEX, indirect);
                inode.add_blocks_1k(1);
                aux.fill(0);
            } else {
                self.read_block(indirect, aux)?;
            }
            put_u32le(aux, slot, block);
            self.write_block(indirect, aux)?;
            inode.add_blocks_1k(1);
            return Ok(block);
        }

        // Double indirect: `i_block[13]` points at a first-level index block whose
        // entries point at second-level index blocks; the data block is indexed
        // by the lower 8 bits of the relative logical block.
        let (first, second) = double_slots(index as usize);
        let mut indirect = 0u32;
        let root = inode.block(DOUBLE_INDIRECT_INDEX);
        let mut root_is_new = false;
        if root != 0 {
            self.check_block(root)?;
            self.read_block(root, aux)?;
            indirect = u32le(aux, first * 4);
            if indirect != 0 {
                self.check_block(indirect)?;
                self.read_block(indirect, aux)?;
                let current = u32le(aux, second * 4);
                if current != 0 {
                    self.check_block(current)?;
                    return Ok(current);
                }
            }
        }
        // Allocate the data block first: every later failure can free it again,
        // and it is not reachable from the inode until both index levels exist.
        let block = self.alloc_clear_block(buf, aux)?;
        if indirect == 0 {
            // A second-level index block is needed. Allocate it before touching
            // the inode so a failure leaves the tree unchanged.
            indirect = match self.alloc_clear_block(buf, aux) {
                Ok(block) => block,
                Err(error) => {
                    self.free_block(block, buf, aux)?;
                    return Err(error);
                }
            };
            let mut root_block = root;
            if root_block == 0 {
                root_block = match self.alloc_clear_block(buf, aux) {
                    Ok(block) => block,
                    Err(error) => {
                        self.free_block(indirect, buf, aux)?;
                        self.free_block(block, buf, aux)?;
                        return Err(error);
                    }
                };
                root_is_new = true;
            }
            // Link the new second-level block into the first level.
            self.read_block(root_block, aux)?;
            put_u32le(aux, first * 4, indirect);
            self.write_block(root_block, aux)?;
            if root_is_new {
                inode.set_block(DOUBLE_INDIRECT_INDEX, root_block);
                inode.add_blocks_1k(1);
            }
            inode.add_blocks_1k(1);
        }
        // Link the data block into the second level and account for it.
        self.read_block(indirect, aux)?;
        put_u32le(aux, second * 4, block);
        self.write_block(indirect, aux)?;
        inode.add_blocks_1k(1);
        Ok(block)
    }

    /// Free logical block `index` of `inode`, releasing index blocks that become
    /// empty (single-indirect block and both double-indirect levels).
    fn free_logical_block(
        &mut self,
        inode: &mut Inode,
        index: u32,
        buf: &mut BlockBuf,
        aux: &mut BlockBuf,
    ) -> Result<(), Error> {
        if (index as usize) < DIRECT_BLOCKS {
            let block = inode.block(index as usize);
            if block != 0 {
                inode.set_block(index as usize, 0);
                inode.sub_blocks_1k(1);
                self.free_block(block, buf, aux)?;
            }
            return Ok(());
        }
        if (index as usize) < DOUBLE_FIRST {
            let indirect = inode.block(SINGLE_INDIRECT_INDEX);
            if indirect == 0 {
                return Ok(());
            }
            self.check_block(indirect)?;
            let slot = (index as usize - DIRECT_BLOCKS) * 4;
            self.read_block(indirect, aux)?;
            let block = u32le(aux, slot);
            if block == 0 {
                return Ok(());
            }
            put_u32le(aux, slot, 0);
            // Decide about the indirect block before the buffers are reused for the
            // allocation counters.
            let indirect_is_empty = aux.iter().all(|&byte| byte == 0);
            self.write_block(indirect, aux)?;
            inode.sub_blocks_1k(1);
            self.free_block(block, buf, aux)?;
            if indirect_is_empty {
                inode.set_block(SINGLE_INDIRECT_INDEX, 0);
                inode.sub_blocks_1k(1);
                self.free_block(indirect, buf, aux)?;
            }
            return Ok(());
        }

        let (first, second) = double_slots(index as usize);
        let root = inode.block(DOUBLE_INDIRECT_INDEX);
        if root == 0 {
            return Ok(());
        }
        self.check_block(root)?;
        self.read_block(root, aux)?;
        let indirect = u32le(aux, first * 4);
        if indirect == 0 {
            return Ok(());
        }
        self.check_block(indirect)?;
        self.read_block(indirect, aux)?;
        let block = u32le(aux, second * 4);
        if block == 0 {
            return Ok(());
        }
        put_u32le(aux, second * 4, 0);
        let indirect_is_empty = aux.iter().all(|&byte| byte == 0);
        self.write_block(indirect, aux)?;
        inode.sub_blocks_1k(1);
        self.free_block(block, buf, aux)?;
        if indirect_is_empty {
            // `free_block` reused the scratch buffers, so re-read the first level
            // before clearing its slot.
            self.read_block(root, aux)?;
            put_u32le(aux, first * 4, 0);
            let root_is_empty = aux.iter().all(|&byte| byte == 0);
            self.write_block(root, aux)?;
            inode.sub_blocks_1k(1);
            self.free_block(indirect, buf, aux)?;
            if root_is_empty {
                inode.set_block(DOUBLE_INDIRECT_INDEX, 0);
                inode.sub_blocks_1k(1);
                self.free_block(root, buf, aux)?;
            }
        }
        Ok(())
    }

    /// Free every block owned by `inode` (used by unlink and truncate-to-zero).
    pub(crate) fn free_inode_blocks(
        &mut self,
        inode: &mut Inode,
        buf: &mut BlockBuf,
        aux: &mut BlockBuf,
    ) -> Result<(), Error> {
        for index in 0..MAX_BLOCKS {
            self.free_logical_block(inode, index as u32, buf, aux)?;
        }
        for index in 0..=DOUBLE_INDIRECT_INDEX {
            inode.set_block(index, 0);
        }
        inode.set_blocks_512(0);
        Ok(())
    }

    /// Read up to `out.len()` bytes at `offset`. Returns the number copied,
    /// clamped at end of file; holes read as zeros.
    pub fn read(&mut self, inode: u32, offset: u64, out: &mut [u8]) -> Result<usize, Error> {
        let mut buf = [0u8; BLOCK_SIZE];
        let mut aux = [0u8; BLOCK_SIZE];
        let node = self.read_inode(inode, &mut buf, &mut aux)?;
        if node.kind() != Some(NodeKind::File) {
            return Err(Error::IsDirectory);
        }
        let size = node.size() as u64;
        if offset > size {
            return Err(Error::BadOffset);
        }
        let available = (size - offset).min(out.len() as u64) as usize;
        let mut done = 0usize;
        while done < available {
            let pos = offset + done as u64;
            let block_index = (pos / BLOCK_SIZE as u64) as u32;
            let intra = (pos % BLOCK_SIZE as u64) as usize;
            let take = (BLOCK_SIZE - intra).min(available - done);
            match self.map_block(&node, block_index, &mut aux)? {
                Some(phys) => {
                    self.read_block(phys, &mut buf)?;
                    out[done..done + take].copy_from_slice(&buf[intra..intra + take]);
                }
                None => out[done..done + take].fill(0),
            }
            done += take;
        }
        Ok(done)
    }

    /// Write `data` at `offset`, extending the file as needed. Returns the
    /// number of bytes written (always `data.len()` on success).
    pub fn write(&mut self, inode: u32, offset: u64, data: &[u8]) -> Result<usize, Error> {
        let mut buf = [0u8; BLOCK_SIZE];
        let mut aux = [0u8; BLOCK_SIZE];
        let mut node = self.read_inode(inode, &mut buf, &mut aux)?;
        if node.kind() != Some(NodeKind::File) {
            return Err(Error::IsDirectory);
        }
        let end = offset
            .checked_add(data.len() as u64)
            .ok_or(Error::BadOffset)?;
        if end > crate::MAX_FILE_SIZE {
            return Err(Error::Quota);
        }
        let old_size = node.size() as u64;
        let mut done = 0usize;
        while done < data.len() {
            let pos = offset + done as u64;
            let block_index = (pos / BLOCK_SIZE as u64) as u32;
            let intra = (pos % BLOCK_SIZE as u64) as usize;
            let take = (BLOCK_SIZE - intra).min(data.len() - done);
            let phys = self.ensure_block(&mut node, block_index, &mut buf, &mut aux)?;
            // Only a whole-block overwrite can skip the read; every other case
            // must preserve the neighbouring bytes.
            if intra == 0 && take == BLOCK_SIZE {
                buf.fill(0);
            } else {
                self.read_block(phys, &mut buf)?;
            }
            buf[intra..intra + take].copy_from_slice(&data[done..done + take]);
            self.write_block(phys, &buf)?;
            done += take;
        }
        if end > old_size {
            node.set_size(end as u32);
        }
        node.set_mtime(self.now);
        self.write_inode(inode, &node, &mut buf, &mut aux)?;
        Ok(done)
    }

    /// Truncate (or extend with a hole) a regular file to `size` bytes.
    pub fn truncate(&mut self, inode: u32, size: u64) -> Result<(), Error> {
        let mut buf = [0u8; BLOCK_SIZE];
        let mut aux = [0u8; BLOCK_SIZE];
        let mut node = self.read_inode(inode, &mut buf, &mut aux)?;
        if node.kind() != Some(NodeKind::File) {
            return Err(Error::IsDirectory);
        }
        if size > crate::MAX_FILE_SIZE {
            return Err(Error::Quota);
        }
        let old_size = node.size() as u64;
        if size == old_size {
            return Ok(());
        }
        if size < old_size {
            let keep = (size as usize).div_ceil(BLOCK_SIZE);
            for index in keep..MAX_BLOCKS {
                self.free_logical_block(&mut node, index as u32, &mut buf, &mut aux)?;
            }
            // Zero the tail of the last kept block so a later extension cannot
            // resurrect truncated bytes.
            if size % BLOCK_SIZE as u64 != 0 {
                let last = (size / BLOCK_SIZE as u64) as u32;
                if let Some(phys) = self.map_block(&node, last, &mut aux)? {
                    self.read_block(phys, &mut buf)?;
                    let intra = (size % BLOCK_SIZE as u64) as usize;
                    buf[intra..].fill(0);
                    self.write_block(phys, &buf)?;
                }
            }
        }
        node.set_size(size as u32);
        node.set_mtime(self.now);
        self.write_inode(inode, &node, &mut buf, &mut aux)
    }

    /// Bytes addressable by this driver: 12 direct blocks, one single-indirect
    /// block, and one double-indirect tree (no triple indirection).
    pub const fn max_file_size(&self) -> u64 {
        crate::MAX_FILE_SIZE
    }

    /// Number of logical blocks currently mapped by `inode` (sparse-aware).
    pub fn mapped_blocks(&mut self, inode: u32) -> Result<u32, Error> {
        let mut buf = [0u8; BLOCK_SIZE];
        let mut aux = [0u8; BLOCK_SIZE];
        let node = self.read_inode(inode, &mut buf, &mut aux)?;
        let mut count = 0u32;
        for index in 0..MAX_BLOCKS {
            if self.map_block(&node, index as u32, &mut aux)?.is_some() {
                count += 1;
            }
        }
        Ok(count)
    }
}
