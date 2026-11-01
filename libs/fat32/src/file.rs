//! File data access: byte-granular reads and writes, sparse gaps, truncation.
//!
//! Writes allocate clusters on demand, link them into the chain (all FAT copies)
//! and update the directory entry's first cluster and size. A write at an
//! offset beyond the current end of file explicitly zero-fills the gap, so the
//! volume never exposes stale cluster contents — FAT32 has no real sparse-file
//! representation.
//!
//! The public entry points allocate exactly one [`Sector`] buffer and thread it
//! through the private `*_with` implementations, so a full write/read/truncate
//! costs one 512-byte scratch slot on the stack instead of one per helper.

use crate::{
    BlockDevice, FAT_EOC_MIN, Fat32, Fat32Error, FatNode, NodeKind, SECTOR_SIZE, Sector, entry_size,
};

impl<D: BlockDevice> Fat32<D> {
    /// Current size from the node's directory entry (truth, not the snapshot).
    fn size_of(&mut self, node: &FatNode, scratch: &mut Sector) -> Result<u64, Fat32Error> {
        if node.cookie == crate::ROOT_COOKIE {
            return Ok(0);
        }
        Ok(entry_size(&self.entry_at(node.cookie, scratch)?) as u64)
    }

    /// Read up to `buf.len()` bytes at `offset`.
    ///
    /// Returns the number of bytes copied. Reads past end-of-file return 0 or a
    /// short count; they never error and never read stale cluster data.
    pub fn read(
        &mut self,
        node: &FatNode,
        offset: u64,
        buf: &mut [u8],
    ) -> Result<usize, Fat32Error> {
        let mut scratch: Sector = [0u8; SECTOR_SIZE as usize];
        self.read_with(node, offset, buf, &mut scratch)
    }

    fn read_with(
        &mut self,
        node: &FatNode,
        offset: u64,
        buf: &mut [u8],
        scratch: &mut Sector,
    ) -> Result<usize, Fat32Error> {
        if node.is_root() || node.kind != NodeKind::File {
            return Err(Fat32Error::IsADirectory);
        }
        let size = self.size_of(node, scratch)?;
        if buf.is_empty() || offset >= size {
            return Ok(0);
        }
        let want = core::cmp::min(buf.len() as u64, size - offset) as usize;
        let first = self.node_first_cluster(node, scratch)?;
        if first == 0 {
            return Ok(0);
        }
        let cluster_bytes = self.layout.cluster_bytes() as u64;
        let mut done = 0usize;
        while done < want {
            let pos = offset + done as u64;
            let cluster = self
                .cluster_at(first, (pos / cluster_bytes) as u32, scratch)?
                .ok_or(Fat32Error::Corrupt)?;
            let in_cluster = (pos % cluster_bytes) as u32;
            let lba = self.cluster_lba(cluster)? + in_cluster / SECTOR_SIZE;
            let at = (in_cluster % SECTOR_SIZE) as usize;
            self.read_sector_into(lba, scratch)?;
            let n = core::cmp::min(SECTOR_SIZE as usize - at, want - done);
            buf[done..done + n].copy_from_slice(&scratch[at..at + n]);
            done += n;
        }
        Ok(done)
    }

    /// Write `buf` at `offset`, extending the file as needed.
    ///
    /// Returns the number of bytes written (all of them on success). A gap left
    /// by a write beyond the old end of file is zero-filled.
    pub fn write(
        &mut self,
        node: &mut FatNode,
        offset: u64,
        buf: &[u8],
    ) -> Result<usize, Fat32Error> {
        let mut scratch: Sector = [0u8; SECTOR_SIZE as usize];
        self.write_with(node, offset, buf, &mut scratch)
    }

    fn write_with(
        &mut self,
        node: &mut FatNode,
        offset: u64,
        buf: &[u8],
        scratch: &mut Sector,
    ) -> Result<usize, Fat32Error> {
        if node.is_root() || node.kind != NodeKind::File {
            return Err(Fat32Error::IsADirectory);
        }
        if buf.is_empty() {
            return Ok(0);
        }
        let end = offset
            .checked_add(buf.len() as u64)
            .ok_or(Fat32Error::TooLarge)?;
        if end > u32::MAX as u64 {
            return Err(Fat32Error::TooLarge);
        }
        let cluster_bytes = self.layout.cluster_bytes() as u64;
        let mut first = self.node_first_cluster(node, scratch)?;
        let existing = if first == 0 {
            0
        } else {
            self.chain_len(first, scratch)?
        };
        let needed64 = end.div_ceil(cluster_bytes);
        if needed64 > self.layout.cluster_count as u64 {
            return Err(Fat32Error::TooLarge);
        }
        let needed = needed64 as u32;
        first = self.extend_chain(first, existing, needed, scratch)?;

        let old_size = self.size_of(node, scratch)?;
        if offset > old_size {
            self.zero_file_range(first, old_size, offset, scratch)?;
        }

        let mut done = 0usize;
        while done < buf.len() {
            let pos = offset + done as u64;
            let cluster = self
                .cluster_at(first, (pos / cluster_bytes) as u32, scratch)?
                .ok_or(Fat32Error::Corrupt)?;
            let in_cluster = (pos % cluster_bytes) as u32;
            let lba = self.cluster_lba(cluster)? + in_cluster / SECTOR_SIZE;
            let at = (in_cluster % SECTOR_SIZE) as usize;
            let n = core::cmp::min(SECTOR_SIZE as usize - at, buf.len() - done);
            if at == 0 && n == SECTOR_SIZE as usize {
                scratch.copy_from_slice(&buf[done..done + n]);
                self.write_sector(lba, scratch)?;
            } else {
                self.read_sector_into(lba, scratch)?;
                scratch[at..at + n].copy_from_slice(&buf[done..done + n]);
                self.write_sector(lba, scratch)?;
            }
            done += n;
        }

        let new_size = core::cmp::max(old_size, end);
        node.size = new_size;
        self.update_entry(node.cookie, first, new_size, scratch)?;
        Ok(buf.len())
    }

    /// Truncate or extend a file to exactly `size` bytes.
    ///
    /// Growing zero-fills; shrinking frees whole clusters that fall beyond the
    /// new end and rewrites the chain terminator.
    pub fn truncate(&mut self, node: &mut FatNode, size: u64) -> Result<(), Fat32Error> {
        let mut scratch: Sector = [0u8; SECTOR_SIZE as usize];
        self.truncate_with(node, size, &mut scratch)
    }

    fn truncate_with(
        &mut self,
        node: &mut FatNode,
        size: u64,
        scratch: &mut Sector,
    ) -> Result<(), Fat32Error> {
        if node.is_root() || node.kind != NodeKind::File {
            return Err(Fat32Error::IsADirectory);
        }
        if size > u32::MAX as u64 {
            return Err(Fat32Error::TooLarge);
        }
        let cluster_bytes = self.layout.cluster_bytes() as u64;
        let old_size = self.size_of(node, scratch)?;
        let mut first = self.node_first_cluster(node, scratch)?;
        if size == old_size {
            node.size = size;
            return Ok(());
        }
        let needed64 = size.div_ceil(cluster_bytes);
        if needed64 > self.layout.cluster_count as u64 {
            return Err(Fat32Error::TooLarge);
        }
        let needed = needed64 as u32;
        let existing = if first == 0 {
            0
        } else {
            self.chain_len(first, scratch)?
        };
        let grew = size > old_size;
        if existing < needed {
            first = self.extend_chain(first, existing, needed, scratch)?;
        }
        if grew {
            // Freshly reachable bytes must read as zeros, whether the range lies
            // in a new cluster or in the tail of an already allocated one.
            self.zero_file_range(first, old_size, size, scratch)?;
        }
        if existing > needed {
            if needed == 0 {
                self.free_chain(first, scratch)?;
                first = 0;
            } else {
                let last = self
                    .cluster_at(first, needed - 1, scratch)?
                    .ok_or(Fat32Error::Corrupt)?;
                let rest = self.next_cluster(last, scratch)?;
                self.write_fat(last, FAT_EOC_MIN, scratch)?;
                if let Some(rest) = rest {
                    self.free_chain(rest, scratch)?;
                }
            }
        }
        node.size = size;
        self.update_entry(node.cookie, first, size, scratch)?;
        Ok(())
    }

    /// Zero the byte range `from..to` of a file whose first cluster is `first`.
    fn zero_file_range(
        &mut self,
        first: u32,
        from: u64,
        to: u64,
        scratch: &mut Sector,
    ) -> Result<(), Fat32Error> {
        if from >= to || first == 0 {
            return Ok(());
        }
        let cluster_bytes = self.layout.cluster_bytes() as u64;
        let mut pos = from;
        while pos < to {
            let cluster = self
                .cluster_at(first, (pos / cluster_bytes) as u32, scratch)?
                .ok_or(Fat32Error::Corrupt)?;
            let in_cluster = (pos % cluster_bytes) as u32;
            let lba = self.cluster_lba(cluster)? + in_cluster / SECTOR_SIZE;
            let at = (in_cluster % SECTOR_SIZE) as usize;
            let n = core::cmp::min(SECTOR_SIZE as usize - at, (to - pos) as usize);
            if at == 0 && n == SECTOR_SIZE as usize {
                scratch.fill(0);
                self.write_sector(lba, scratch)?;
            } else {
                self.read_sector_into(lba, scratch)?;
                scratch[at..at + n].fill(0);
                self.write_sector(lba, scratch)?;
            }
            pos += n as u64;
        }
        Ok(())
    }
}
