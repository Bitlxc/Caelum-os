//! Directory scanning and mutation: lookup, readdir, create, unlink, rename.
//!
//! Directory iteration always walks the cluster chain in order and stops at the
//! first `0x00` name byte (end of directory). LFN chunks, volume labels and
//! `.`/`..` are never reported as children. Deletion removes the whole LFN run
//! that belongs to the short entry, so images produced by other tools stay
//! consistent.
//!
//! Every internal helper takes the caller's [`Sector`] scratch buffer, and the
//! scan visitor is I/O-free by construction: visitors only inspect the 32-byte
//! entry they are handed, so one buffer is enough at every depth (the `&mut self`
//! borrow rules make a filesystem call from inside a visitor impossible).

use crate::name83;
use crate::{
    ATTR_ARCHIVE, ATTR_DIRECTORY, ATTR_LFN, BlockDevice, DEFAULT_DATE, DEFAULT_TIME,
    DIR_ENTRY_SIZE, DirEntry, ENTRIES_PER_SECTOR, ENTRY_DELETED, ENTRY_END, Fat32, Fat32Error,
    FatNode, NodeKind, ROOT_COOKIE, Sector, entry_cluster, entry_name83, entry_size,
    is_special_entry, node_kind, set_cluster,
};

/// Longest LFN run we are willing to track back from a short entry
/// (255 UTF-16 characters = 20 chunks, plus the short entry itself).
const MAX_LFN_CHUNKS: usize = 20;

impl<D: BlockDevice> Fat32<D> {
    /// Walk a directory in on-disk order.
    ///
    /// `visit(cookie, raw_entry)` returns `true` to stop early. The walk stops
    /// at the end-of-directory marker and at the end of the cluster chain.
    pub(crate) fn scan_dir<F>(
        &mut self,
        dir_cluster: u32,
        scratch: &mut Sector,
        mut visit: F,
    ) -> Result<(), Fat32Error>
    where
        F: FnMut(u64, &[u8; DIR_ENTRY_SIZE]) -> Result<bool, Fat32Error>,
    {
        if !self.layout.valid_cluster(dir_cluster) {
            return Err(Fat32Error::Corrupt);
        }
        let sectors_per_cluster = self.layout.sectors_per_cluster as u32;
        let mut cluster = dir_cluster;
        let mut steps = 0u32;
        loop {
            let base = self.cluster_lba(cluster)?;
            for sector_index in 0..sectors_per_cluster {
                let lba = base + sector_index;
                self.read_sector_into(lba, scratch)?;
                for index in 0..ENTRIES_PER_SECTOR {
                    let at = index * DIR_ENTRY_SIZE;
                    let mut raw = [0u8; DIR_ENTRY_SIZE];
                    raw.copy_from_slice(&scratch[at..at + DIR_ENTRY_SIZE]);
                    if raw[0] == ENTRY_END {
                        return Ok(());
                    }
                    let cookie = ((lba as u64) << 8) | index as u64;
                    if visit(cookie, &raw)? {
                        return Ok(());
                    }
                }
            }
            steps += 1;
            if steps > self.layout.cluster_count {
                return Err(Fat32Error::Corrupt);
            }
            match self.next_cluster(cluster, scratch)? {
                Some(next) => cluster = next,
                None => return Ok(()),
            }
        }
    }

    /// Find a short entry by its eleven encoded name bytes.
    pub(crate) fn find_entry(
        &mut self,
        dir_cluster: u32,
        key: &[u8; 11],
        scratch: &mut Sector,
    ) -> Result<Option<FatNode>, Fat32Error> {
        let mut found: Option<FatNode> = None;
        let parent = dir_cluster;
        self.scan_dir(dir_cluster, scratch, |cookie, raw| {
            if raw[0] == ENTRY_DELETED || is_special_entry(raw) {
                return Ok(false);
            }
            if &entry_name83(raw) == key {
                found = Some(FatNode {
                    cookie,
                    parent,
                    kind: node_kind(raw),
                    size: entry_size(raw) as u64,
                });
                return Ok(true);
            }
            Ok(false)
        })?;
        Ok(found)
    }

    /// Look up `name` in `parent` (exact 8.3 semantics, case-insensitive).
    pub fn lookup(&mut self, parent: &FatNode, name: &str) -> Result<FatNode, Fat32Error> {
        let mut scratch: Sector = [0u8; crate::SECTOR_SIZE as usize];
        let key = name83::encode(name)?;
        let dir_cluster = self.dir_cluster_of(parent, &mut scratch)?;
        self.find_entry(dir_cluster, &key, &mut scratch)?
            .ok_or(Fat32Error::NotFound)
    }

    /// Report the children of `dir` (`.`, `..`, LFN chunks and volume labels are
    /// skipped). Returns the first error from `visit`.
    pub fn readdir(
        &mut self,
        dir: &FatNode,
        visit: impl FnMut(&DirEntry) -> Result<(), Fat32Error>,
    ) -> Result<(), Fat32Error> {
        let mut scratch: Sector = [0u8; crate::SECTOR_SIZE as usize];
        self.readdir_with(dir, &mut scratch, visit)
    }

    fn readdir_with(
        &mut self,
        dir: &FatNode,
        scratch: &mut Sector,
        mut visit: impl FnMut(&DirEntry) -> Result<(), Fat32Error>,
    ) -> Result<(), Fat32Error> {
        let dir_cluster = self.dir_cluster_of(dir, scratch)?;
        let parent = dir_cluster;
        self.scan_dir(dir_cluster, scratch, |cookie, raw| {
            if raw[0] == ENTRY_DELETED || is_special_entry(raw) {
                return Ok(false);
            }
            let (name, name_len) = name83::decode(&entry_name83(raw));
            let entry = DirEntry {
                name,
                name_len,
                node: FatNode {
                    cookie,
                    parent,
                    kind: node_kind(raw),
                    size: entry_size(raw) as u64,
                },
            };
            visit(&entry)?;
            Ok(false)
        })
    }

    /// Find a free directory slot, extending the directory by one cluster when
    /// it is full.
    ///
    /// On success the caller also receives the cluster that was appended (as
    /// `(tail, appended)`), so a later failure in the same operation can undo
    /// the extension with [`Fat32::undo_dir_extension`] instead of leaking a
    /// cluster that no entry will ever use.
    pub(crate) fn alloc_dir_slot(
        &mut self,
        dir_cluster: u32,
        scratch: &mut Sector,
    ) -> Result<(u32, usize, Option<(u32, u32)>), Fat32Error> {
        if !self.layout.valid_cluster(dir_cluster) {
            return Err(Fat32Error::Corrupt);
        }
        let sectors_per_cluster = self.layout.sectors_per_cluster as u32;
        let mut cluster = dir_cluster;
        let mut steps = 0u32;
        let mut tail;
        loop {
            tail = cluster;
            let base = self.cluster_lba(cluster)?;
            for sector_index in 0..sectors_per_cluster {
                let lba = base + sector_index;
                self.read_sector_into(lba, scratch)?;
                for index in 0..ENTRIES_PER_SECTOR {
                    let first = scratch[index * DIR_ENTRY_SIZE];
                    if first == ENTRY_END || first == ENTRY_DELETED {
                        return Ok((lba, index, None));
                    }
                }
            }
            steps += 1;
            if steps > self.layout.cluster_count {
                return Err(Fat32Error::Corrupt);
            }
            match self.next_cluster(cluster, scratch)? {
                Some(next) => cluster = next,
                None => break,
            }
        }
        let new = self.alloc_cluster(scratch)?;
        if let Err(error) = self.write_fat(tail, new, scratch) {
            // The cluster is allocated but not linked: release it before the
            // error escapes, otherwise the operation leaks one cluster.
            let _ = self.free_chain(new, scratch);
            return Err(error);
        }
        match self.cluster_lba(new) {
            Ok(lba) => Ok((lba, 0, Some((tail, new)))),
            Err(error) => {
                // Linking succeeded but the new sector is unusable: unlink and
                // free it so the directory chain stays exactly as it was.
                let _ = self.write_fat(tail, crate::FAT_EOC_MIN, scratch);
                let _ = self.free_chain(new, scratch);
                Err(error)
            }
        }
    }

    /// Undo a directory extension made by [`Self::alloc_dir_slot`]: terminate
    /// the previous tail again and release the appended cluster.
    fn undo_dir_extension(
        &mut self,
        extension: (u32, u32),
        scratch: &mut Sector,
    ) -> Result<(), Fat32Error> {
        let (tail, appended) = extension;
        self.write_fat(tail, crate::FAT_EOC_MIN, scratch)?;
        self.free_chain(appended, scratch)
    }

    /// Mark one directory entry as deleted (used to undo an insertion).
    fn delete_entry_at(
        &mut self,
        lba: u32,
        index: usize,
        scratch: &mut Sector,
    ) -> Result<(), Fat32Error> {
        if index >= ENTRIES_PER_SECTOR {
            return Err(Fat32Error::Corrupt);
        }
        self.read_sector_into(lba, scratch)?;
        scratch[index * DIR_ENTRY_SIZE] = ENTRY_DELETED;
        self.write_sector(lba, scratch)
    }

    /// Create a file or directory.
    pub fn create(
        &mut self,
        parent: &FatNode,
        name: &str,
        kind: NodeKind,
    ) -> Result<FatNode, Fat32Error> {
        let mut scratch: Sector = [0u8; crate::SECTOR_SIZE as usize];
        self.create_with(parent, name, kind, &mut scratch)
    }

    fn create_with(
        &mut self,
        parent: &FatNode,
        name: &str,
        kind: NodeKind,
        scratch: &mut Sector,
    ) -> Result<FatNode, Fat32Error> {
        let key = name83::encode(name)?;
        let dir_cluster = self.dir_cluster_of(parent, scratch)?;
        if self.find_entry(dir_cluster, &key, scratch)?.is_some() {
            return Err(Fat32Error::AlreadyExists);
        }
        let first_cluster = match kind {
            NodeKind::File => 0,
            NodeKind::Directory => {
                let cluster = self.alloc_cluster(scratch)?;
                self.write_dot_entries(cluster, dir_cluster, scratch)?;
                cluster
            }
        };
        let (lba, index, extension) = self.alloc_dir_slot(dir_cluster, scratch)?;
        let mut raw = [0u8; DIR_ENTRY_SIZE];
        raw[0..11].copy_from_slice(&key);
        raw[11] = match kind {
            NodeKind::File => ATTR_ARCHIVE,
            NodeKind::Directory => ATTR_DIRECTORY,
        };
        raw[13] = 0; // creation tenths
        raw[14..16].copy_from_slice(&DEFAULT_TIME.to_le_bytes());
        raw[16..18].copy_from_slice(&DEFAULT_DATE.to_le_bytes());
        raw[18..20].copy_from_slice(&DEFAULT_DATE.to_le_bytes());
        raw[22..24].copy_from_slice(&DEFAULT_TIME.to_le_bytes());
        raw[24..26].copy_from_slice(&DEFAULT_DATE.to_le_bytes());
        set_cluster(&mut raw, first_cluster);
        raw[28..32].copy_from_slice(&0u32.to_le_bytes());
        if let Err(error) = self.write_entry_at(lba, index, &raw, scratch) {
            // The entry write is the first mutation here: a failed write leaves
            // the free slot untouched, so only an already-linked directory
            // extension and (for a new directory) its reserved cluster need to
            // be released. Escalate when that release itself fails.
            let mut rollback_failed = false;
            if let Some(extension) = extension {
                rollback_failed |= self.undo_dir_extension(extension, scratch).is_err();
            }
            if kind == NodeKind::Directory {
                rollback_failed |= self.free_chain(first_cluster, scratch).is_err();
            }
            return Err(if rollback_failed {
                Fat32Error::Corrupt
            } else {
                error
            });
        }
        Ok(FatNode {
            cookie: ((lba as u64) << 8) | index as u64,
            parent: dir_cluster,
            kind,
            size: 0,
        })
    }

    /// Write the `.` and `..` entries of a freshly allocated directory cluster.
    fn write_dot_entries(
        &mut self,
        cluster: u32,
        parent_cluster: u32,
        scratch: &mut Sector,
    ) -> Result<(), Fat32Error> {
        let lba = self.cluster_lba(cluster)?;
        self.read_sector_into(lba, scratch)?;
        let mut dot = [0u8; DIR_ENTRY_SIZE];
        dot[0..11].copy_from_slice(b".          ");
        dot[11] = ATTR_DIRECTORY;
        dot[22..24].copy_from_slice(&DEFAULT_TIME.to_le_bytes());
        dot[24..26].copy_from_slice(&DEFAULT_DATE.to_le_bytes());
        set_cluster(&mut dot, cluster);
        let mut dot_dot = [0u8; DIR_ENTRY_SIZE];
        dot_dot[0..11].copy_from_slice(b"..         ");
        dot_dot[11] = ATTR_DIRECTORY;
        dot_dot[22..24].copy_from_slice(&DEFAULT_TIME.to_le_bytes());
        dot_dot[24..26].copy_from_slice(&DEFAULT_DATE.to_le_bytes());
        let parent_link = if parent_cluster == self.layout.root_cluster {
            0
        } else {
            parent_cluster
        };
        set_cluster(&mut dot_dot, parent_link);
        scratch[0..DIR_ENTRY_SIZE].copy_from_slice(&dot);
        scratch[DIR_ENTRY_SIZE..2 * DIR_ENTRY_SIZE].copy_from_slice(&dot_dot);
        self.write_sector(lba, scratch)
    }

    /// Read the `..` link of a directory cluster (0 means "the root directory").
    fn read_dot_dot(&mut self, cluster: u32, scratch: &mut Sector) -> Result<u32, Fat32Error> {
        let lba = self.cluster_lba(cluster)?;
        self.read_sector_into(lba, scratch)?;
        let mut raw = [0u8; DIR_ENTRY_SIZE];
        raw.copy_from_slice(&scratch[DIR_ENTRY_SIZE..2 * DIR_ENTRY_SIZE]);
        if !name83::is_dot_dot(&entry_name83(&raw)) {
            return Err(Fat32Error::Corrupt);
        }
        Ok(entry_cluster(&raw))
    }

    /// Point a directory's `..` entry at `parent_cluster` (0 for root).
    fn set_dot_dot(
        &mut self,
        cluster: u32,
        parent_cluster: u32,
        scratch: &mut Sector,
    ) -> Result<(), Fat32Error> {
        let lba = self.cluster_lba(cluster)?;
        self.read_sector_into(lba, scratch)?;
        let mut raw = [0u8; DIR_ENTRY_SIZE];
        raw.copy_from_slice(&scratch[DIR_ENTRY_SIZE..2 * DIR_ENTRY_SIZE]);
        let link = if parent_cluster == self.layout.root_cluster {
            0
        } else {
            parent_cluster
        };
        set_cluster(&mut raw, link);
        scratch[DIR_ENTRY_SIZE..2 * DIR_ENTRY_SIZE].copy_from_slice(&raw);
        self.write_sector(lba, scratch)
    }

    /// True when a directory has no children other than `.` and `..`.
    pub(crate) fn dir_is_empty(
        &mut self,
        cluster: u32,
        scratch: &mut Sector,
    ) -> Result<bool, Fat32Error> {
        let mut empty = true;
        self.scan_dir(cluster, scratch, |_cookie, raw| {
            if raw[0] == ENTRY_DELETED || is_special_entry(raw) {
                return Ok(false);
            }
            empty = false;
            Ok(true)
        })?;
        Ok(empty)
    }

    /// Delete a node and its cluster chain.
    pub fn unlink(&mut self, node: &FatNode) -> Result<(), Fat32Error> {
        let mut scratch: Sector = [0u8; crate::SECTOR_SIZE as usize];
        self.unlink_with(node, &mut scratch)
    }

    fn unlink_with(&mut self, node: &FatNode, scratch: &mut Sector) -> Result<(), Fat32Error> {
        if node.cookie == ROOT_COOKIE {
            return Err(Fat32Error::InvalidArgument);
        }
        let cluster = self.node_first_cluster(node, scratch)?;
        if node.kind == NodeKind::Directory {
            if cluster == 0 {
                return Err(Fat32Error::Corrupt);
            }
            if !self.dir_is_empty(cluster, scratch)? {
                return Err(Fat32Error::NotEmpty);
            }
        }
        self.delete_entry_with_lfn(node.parent, node.cookie, scratch)?;
        if cluster != 0 {
            self.free_chain(cluster, scratch)?;
        }
        Ok(())
    }

    /// Delete a short entry plus the LFN run immediately before it.
    fn delete_entry_with_lfn(
        &mut self,
        parent_cluster: u32,
        target: u64,
        scratch: &mut Sector,
    ) -> Result<(), Fat32Error> {
        let mut ring = [0u64; MAX_LFN_CHUNKS];
        let mut ring_len = 0usize;
        let mut run = [0u64; MAX_LFN_CHUNKS + 1];
        let mut run_len = 0usize;
        let mut found = false;
        self.scan_dir(parent_cluster, scratch, |cookie, raw| {
            let attr = raw[11];
            if raw[0] == ENTRY_DELETED {
                // A deleted slot ends any LFN run and can never be the target.
                ring_len = 0;
                return Ok(false);
            }
            if attr == ATTR_LFN {
                if ring_len < MAX_LFN_CHUNKS {
                    ring[ring_len] = cookie;
                    ring_len += 1;
                }
                return Ok(false);
            }
            if cookie == target {
                run[..ring_len].copy_from_slice(&ring[..ring_len]);
                run[ring_len] = cookie;
                run_len = ring_len + 1;
                found = true;
                return Ok(true);
            }
            ring_len = 0;
            Ok(false)
        })?;
        if !found {
            return Err(Fat32Error::NotFound);
        }
        for &cookie in &run[..run_len] {
            let lba = (cookie >> 8) as u32;
            let index = (cookie & 0xFF) as usize;
            if index >= ENTRIES_PER_SECTOR {
                return Err(Fat32Error::Corrupt);
            }
            self.read_sector_into(lba, scratch)?;
            scratch[index * DIR_ENTRY_SIZE] = ENTRY_DELETED;
            self.write_sector(lba, scratch)?;
        }
        Ok(())
    }

    /// Rename or move a node.
    ///
    /// Cross-directory moves are supported. Renaming a directory into its own
    /// subtree is rejected. An existing target name is rejected rather than
    /// overwritten.
    pub fn rename(
        &mut self,
        node: &mut FatNode,
        new_parent: &FatNode,
        new_name: &str,
    ) -> Result<(), Fat32Error> {
        let mut scratch: Sector = [0u8; crate::SECTOR_SIZE as usize];
        self.rename_with(node, new_parent, new_name, &mut scratch)
    }

    fn rename_with(
        &mut self,
        node: &mut FatNode,
        new_parent: &FatNode,
        new_name: &str,
        scratch: &mut Sector,
    ) -> Result<(), Fat32Error> {
        if node.cookie == ROOT_COOKIE {
            return Err(Fat32Error::InvalidArgument);
        }
        let key = name83::encode(new_name)?;
        let new_dir = self.dir_cluster_of(new_parent, scratch)?;
        let cluster = self.node_first_cluster(node, scratch)?;
        if node.kind == NodeKind::Directory {
            if cluster == 0 {
                return Err(Fat32Error::Corrupt);
            }
            self.check_move_into_subtree(cluster, new_dir, scratch)?;
        }
        let old_raw = self.entry_at(node.cookie, scratch)?;
        let old_key = entry_name83(&old_raw);
        if new_dir == node.parent && old_key == key {
            return Ok(());
        }
        if self.find_entry(new_dir, &key, scratch)?.is_some() {
            // The current contract never replaces an occupied name (the VFS
            // relies on `AlreadyExists`), and rejecting here happens before
            // any allocation or write, so this path has no side effects.
            return Err(Fat32Error::AlreadyExists);
        }
        let (lba, index, extension) = self.alloc_dir_slot(new_dir, scratch)?;
        let mut raw = old_raw;
        raw[0..11].copy_from_slice(&key);
        raw[22..24].copy_from_slice(&DEFAULT_TIME.to_le_bytes());
        raw[24..26].copy_from_slice(&DEFAULT_DATE.to_le_bytes());
        // The new entry is inserted first, then `..` is retargeted, and the
        // source entry is removed last. Every failure below therefore leaves
        // the source reachable and is undone by `undo_rename`: delete the new
        // entry, restore `..`, and release a directory extension.
        let mut inserted = false;
        let mut dot_dot = None;
        let applied = (|| -> Result<(), Fat32Error> {
            self.write_entry_at(lba, index, &raw, scratch)?;
            inserted = true;
            if node.kind == NodeKind::Directory && new_dir != node.parent {
                // Remember the old `..` link before touching it so a later
                // failure (including the source deletion) can restore it.
                let previous = self.read_dot_dot(cluster, scratch)?;
                self.set_dot_dot(cluster, new_dir, scratch)?;
                dot_dot = Some((cluster, previous));
            }
            self.delete_entry_with_lfn(node.parent, node.cookie, scratch)?;
            Ok(())
        })();
        if let Err(error) = applied {
            self.undo_rename(
                if inserted { Some((lba, index)) } else { None },
                extension,
                dot_dot,
                scratch,
            )?;
            return Err(error);
        }
        node.cookie = ((lba as u64) << 8) | index as u64;
        node.parent = new_dir;
        Ok(())
    }

    /// Undo a partially applied [`Self::rename`].
    ///
    /// Steps are attempted from newest to oldest: restore `..`, delete the
    /// inserted entry, then release a directory extension. Any failure here
    /// means the volume is no longer self-consistent, so the caller receives
    /// `Corrupt` (an explicit error) instead of a silent success.
    fn undo_rename(
        &mut self,
        inserted: Option<(u32, usize)>,
        extension: Option<(u32, u32)>,
        dot_dot: Option<(u32, u32)>,
        scratch: &mut Sector,
    ) -> Result<(), Fat32Error> {
        let mut failed = false;
        if let Some((cluster, previous)) = dot_dot {
            let parent = if previous == 0 {
                self.layout.root_cluster
            } else {
                previous
            };
            failed |= self.set_dot_dot(cluster, parent, scratch).is_err();
        }
        if let Some(inserted) = inserted {
            failed |= self
                .delete_entry_at(inserted.0, inserted.1, scratch)
                .is_err();
        }
        if let Some(extension) = extension {
            failed |= self.undo_dir_extension(extension, scratch).is_err();
        }
        if failed {
            Err(Fat32Error::Corrupt)
        } else {
            Ok(())
        }
    }

    /// Reject moving a directory into itself or one of its descendants.
    fn check_move_into_subtree(
        &mut self,
        node_cluster: u32,
        target_dir: u32,
        scratch: &mut Sector,
    ) -> Result<(), Fat32Error> {
        let mut cluster = target_dir;
        let mut steps = 0u32;
        loop {
            if cluster == node_cluster {
                return Err(Fat32Error::InvalidArgument);
            }
            if cluster == self.layout.root_cluster {
                return Ok(());
            }
            let parent = self.read_dot_dot(cluster, scratch)?;
            if parent == 0 {
                return Ok(());
            }
            cluster = parent;
            steps += 1;
            if steps > self.layout.cluster_count {
                return Err(Fat32Error::Corrupt);
            }
        }
    }
}
