//! FAT table access, cluster-chain walking and the cluster allocator.
//!
//! All metadata writes go to *every* FAT copy (mirrored FATs). Chains are
//! walked with a step limit bounded by the cluster count, so a corrupt FAT that
//! loops back on itself fails with [`Fat32Error::Corrupt`] instead of hanging.
//!
//! Every helper takes the caller's [`Sector`] scratch buffer: one 512-byte
//! buffer is reused from the public entry point down to the block device, so the
//! FAT32 call chain costs one sector of stack instead of one per layer.

use crate::{
    BlockDevice, FAT_BAD, FAT_EOC_MIN, FAT_MASK, Fat32, Fat32Error, SECTOR_SIZE, Sector,
    UNKNOWN_FREE, bpb,
};

const ENTRIES_PER_SECTOR: u32 = SECTOR_SIZE / 4;

impl<D: BlockDevice> Fat32<D> {
    /// Read a FAT entry by raw index (0 and 1 included); no range check beyond
    /// the FAT table itself.
    pub(crate) fn fat_raw_read(
        &mut self,
        index: u32,
        scratch: &mut Sector,
    ) -> Result<u32, Fat32Error> {
        let lba = self.layout.reserved_sectors as u32 + index / ENTRIES_PER_SECTOR;
        let at = (index % ENTRIES_PER_SECTOR) as usize * 4;
        self.read_sector_into(lba, scratch)?;
        let raw = u32::from_le_bytes([
            scratch[at],
            scratch[at + 1],
            scratch[at + 2],
            scratch[at + 3],
        ]);
        Ok(raw & FAT_MASK)
    }

    /// Read the FAT entry of a data cluster.
    pub(crate) fn read_fat(
        &mut self,
        cluster: u32,
        scratch: &mut Sector,
    ) -> Result<u32, Fat32Error> {
        if !self.layout.valid_cluster(cluster) {
            return Err(Fat32Error::BadCluster);
        }
        self.fat_raw_read(cluster, scratch)
    }

    /// Write the FAT entry of a data cluster to all FAT copies.
    pub(crate) fn write_fat(
        &mut self,
        cluster: u32,
        value: u32,
        scratch: &mut Sector,
    ) -> Result<(), Fat32Error> {
        if !self.layout.valid_cluster(cluster) {
            return Err(Fat32Error::BadCluster);
        }
        self.fat_raw_write(cluster, value, scratch)
    }

    fn fat_raw_write(
        &mut self,
        index: u32,
        value: u32,
        scratch: &mut Sector,
    ) -> Result<(), Fat32Error> {
        let fat_sector = index / ENTRIES_PER_SECTOR;
        let at = (index % ENTRIES_PER_SECTOR) as usize * 4;

        // Remember the entry stored in the first copy so a failure while
        // updating the mirrored copies can be undone; otherwise the copies
        // would disagree and a later mount would see a different volume.
        let first_lba = self.layout.reserved_sectors as u32 + fat_sector;
        self.read_sector_into(first_lba, scratch)?;
        let previous = u32::from_le_bytes([
            scratch[at],
            scratch[at + 1],
            scratch[at + 2],
            scratch[at + 3],
        ]) & FAT_MASK;

        for copy in 0..self.layout.num_fats as u32 {
            if let Err(error) = self.write_fat_copy(copy, fat_sector, at, value, scratch) {
                let mut restore_failed = false;
                for done in 0..copy {
                    if self
                        .write_fat_copy(done, fat_sector, at, previous, scratch)
                        .is_err()
                    {
                        restore_failed = true;
                    }
                }
                return Err(if restore_failed {
                    Fat32Error::Corrupt
                } else {
                    error
                });
            }
        }
        Ok(())
    }

    /// Write one FAT copy's entry, preserving the reserved high bits.
    fn write_fat_copy(
        &mut self,
        copy: u32,
        fat_sector: u32,
        at: usize,
        value: u32,
        scratch: &mut Sector,
    ) -> Result<(), Fat32Error> {
        let lba = self.layout.reserved_sectors as u32 + copy * self.layout.fat_sectors + fat_sector;
        self.read_sector_into(lba, scratch)?;
        let old = u32::from_le_bytes([
            scratch[at],
            scratch[at + 1],
            scratch[at + 2],
            scratch[at + 3],
        ]);
        let new = (old & !FAT_MASK) | (value & FAT_MASK);
        scratch[at..at + 4].copy_from_slice(&new.to_le_bytes());
        self.write_sector(lba, scratch)
    }

    /// Next cluster in a chain, `None` at end-of-chain.
    pub(crate) fn next_cluster(
        &mut self,
        cluster: u32,
        scratch: &mut Sector,
    ) -> Result<Option<u32>, Fat32Error> {
        let value = self.read_fat(cluster, scratch)?;
        if value == FAT_BAD {
            return Err(Fat32Error::Corrupt);
        }
        if value >= FAT_EOC_MIN {
            return Ok(None);
        }
        if !self.layout.valid_cluster(value) {
            // 0 (free) or an out-of-range number inside a used chain is corrupt.
            return Err(Fat32Error::Corrupt);
        }
        Ok(Some(value))
    }

    /// Cluster `index` (0-based) of the chain starting at `first`.
    pub(crate) fn cluster_at(
        &mut self,
        first: u32,
        index: u32,
        scratch: &mut Sector,
    ) -> Result<Option<u32>, Fat32Error> {
        if first == 0 {
            return Ok(None);
        }
        if !self.layout.valid_cluster(first) {
            return Err(Fat32Error::Corrupt);
        }
        let mut cluster = first;
        let mut at = 0u32;
        loop {
            if at == index {
                return Ok(Some(cluster));
            }
            match self.next_cluster(cluster, scratch)? {
                Some(next) => {
                    cluster = next;
                    at += 1;
                    if at > self.layout.cluster_count {
                        return Err(Fat32Error::Corrupt);
                    }
                }
                None => return Ok(None),
            }
        }
    }

    /// Number of clusters in a chain.
    pub(crate) fn chain_len(
        &mut self,
        first: u32,
        scratch: &mut Sector,
    ) -> Result<u32, Fat32Error> {
        if first == 0 {
            return Ok(0);
        }
        if !self.layout.valid_cluster(first) {
            return Err(Fat32Error::Corrupt);
        }
        let mut cluster = first;
        let mut len = 1u32;
        while let Some(next) = self.next_cluster(cluster, scratch)? {
            cluster = next;
            len += 1;
            if len > self.layout.cluster_count {
                return Err(Fat32Error::Corrupt);
            }
        }
        Ok(len)
    }

    /// Allocate one cluster, zero it and return its number.
    ///
    /// The zeroing happens before the FAT entry is claimed: the cluster is
    /// still marked free, so an I/O failure at any step leaves the volume
    /// exactly as it was found (the mirror write rolls itself back too).
    pub(crate) fn alloc_cluster(&mut self, scratch: &mut Sector) -> Result<u32, Fat32Error> {
        if self.free_count != UNKNOWN_FREE && self.free_count == 0 {
            return Err(Fat32Error::NoSpace);
        }
        let max = self.layout.max_cluster();
        let start = if self.layout.valid_cluster(self.next_free) {
            self.next_free
        } else {
            2
        };
        let mut candidate = start;
        let mut scanned = 0u32;
        loop {
            if self.read_fat(candidate, scratch)? == 0 {
                self.zero_cluster(candidate, scratch)?;
                self.write_fat(candidate, FAT_EOC_MIN, scratch)?;
                if self.free_count != UNKNOWN_FREE {
                    self.free_count = self.free_count.saturating_sub(1);
                    self.fsinfo_dirty = true;
                }
                self.next_free = if candidate < max { candidate + 1 } else { 2 };
                return Ok(candidate);
            }
            scanned += 1;
            if scanned > self.layout.cluster_count {
                return Err(Fat32Error::NoSpace);
            }
            candidate = if candidate >= max { 2 } else { candidate + 1 };
        }
    }

    /// Free an entire chain (no-op for cluster 0).
    pub(crate) fn free_chain(
        &mut self,
        first: u32,
        scratch: &mut Sector,
    ) -> Result<(), Fat32Error> {
        if first == 0 {
            return Ok(());
        }
        if !self.layout.valid_cluster(first) {
            return Err(Fat32Error::Corrupt);
        }
        let mut cluster = first;
        let mut steps = 0u32;
        loop {
            let next = self.next_cluster(cluster, scratch)?;
            self.write_fat(cluster, 0, scratch)?;
            if self.free_count != UNKNOWN_FREE {
                self.free_count = self.free_count.saturating_add(1);
                self.fsinfo_dirty = true;
            }
            if self.next_free == 0 || cluster < self.next_free {
                self.next_free = cluster;
                self.fsinfo_dirty = true;
            }
            steps += 1;
            if steps > self.layout.cluster_count {
                return Err(Fat32Error::Corrupt);
            }
            match next {
                Some(next) => cluster = next,
                None => return Ok(()),
            }
        }
    }

    /// Write zeros over a whole cluster.
    pub(crate) fn zero_cluster(
        &mut self,
        cluster: u32,
        scratch: &mut Sector,
    ) -> Result<(), Fat32Error> {
        let base = self.cluster_lba(cluster)?;
        scratch.fill(0);
        for sector in 0..self.layout.sectors_per_cluster as u32 {
            self.write_sector(base + sector, scratch)?;
        }
        Ok(())
    }

    /// Grow a chain from `existing` to `needed` clusters; returns the (possibly
    /// new) first cluster. New clusters are zeroed by [`Self::alloc_cluster`].
    pub(crate) fn extend_chain(
        &mut self,
        first: u32,
        existing: u32,
        needed: u32,
        scratch: &mut Sector,
    ) -> Result<u32, Fat32Error> {
        if existing >= needed {
            return Ok(first);
        }
        if existing == 0 {
            if first != 0 {
                return Err(Fat32Error::Corrupt);
            }
        } else if first == 0 {
            return Err(Fat32Error::Corrupt);
        }
        let mut tail = if existing == 0 {
            0
        } else {
            self.cluster_at(first, existing - 1, scratch)?
                .ok_or(Fat32Error::Corrupt)?
        };
        let mut first_out = first;
        for _ in existing..needed {
            let new = self.alloc_cluster(scratch)?;
            if tail == 0 {
                first_out = new;
            } else {
                self.write_fat(tail, new, scratch)?;
            }
            tail = new;
        }
        Ok(first_out)
    }

    /// Load allocator hints from FSInfo; a damaged FSInfo is not fatal.
    pub(crate) fn load_fsinfo(&mut self, scratch: &mut Sector) -> Result<(), Fat32Error> {
        self.next_free = 2;
        if self.layout.fsinfo_sector == 0 {
            self.free_count = UNKNOWN_FREE;
            return Ok(());
        }
        self.read_sector_into(self.layout.fsinfo_sector as u32, scratch)?;
        match bpb::parse_fsinfo(scratch) {
            Some(fs) => {
                self.free_count =
                    if fs.free_count == UNKNOWN_FREE || fs.free_count > self.layout.cluster_count {
                        UNKNOWN_FREE
                    } else {
                        fs.free_count
                    };
                if self.layout.valid_cluster(fs.next_free) {
                    self.next_free = fs.next_free;
                }
            }
            None => self.free_count = UNKNOWN_FREE,
        }
        Ok(())
    }

    /// Persist FSInfo (and its backup, when in range).
    pub(crate) fn write_fsinfo(&mut self, scratch: &mut Sector) -> Result<(), Fat32Error> {
        if self.layout.fsinfo_sector == 0 || self.free_count == UNKNOWN_FREE {
            return Ok(());
        }
        *scratch = bpb::build_fsinfo(self.free_count, self.next_free);
        self.write_sector(self.layout.fsinfo_sector as u32, scratch)?;
        let backup = self.layout.fsinfo_sector + 1;
        if backup < self.layout.reserved_sectors {
            self.write_sector(backup as u32, scratch)?;
        }
        Ok(())
    }
}
