//! The fixed VNode table.
//!
//! The VFS stores metadata only: a ramfs file's bytes live in the page cache and
//! an initramfs file's bytes stay in the boot module window that `bootmod`
//! mapped. Directories are linked children of a parent VNode through a
//! singly-linked sibling list, which fits the fixed 64-slot budget and keeps
//! lookups allocation-free.
//!
//! Ids carry a generation byte ([`VNodeId`]), bumped when a slot is released, so
//! a stale id is rejected instead of resolving to a recycled node, and the cache
//! key derived from it can never alias another file.

use super::pagecache::CacheKey;
use super::types::{
    DirEntry, MAX_NAME, MAX_VNODES, MAX_XATTR_NAME, MAX_XATTR_VALUE, MAX_XATTRS, NodeKind, VNodeId,
    VfsError,
};

/// File system id used in cache keys for ramfs nodes.
pub const FS_RAM: u16 = 1;
/// File system id used in cache keys for read-only boot-module nodes.
pub const FS_BOOT: u16 = 2;
/// First file-system id of the disk mounts: mount `n` uses `FS_DISK_BASE + n`,
/// so the page cache can route a write-back to the right mount from the key
/// alone (and reject ramfs/boot keys it must never flush).
pub const FS_DISK_BASE: u16 = 3;

/// Where a node's bytes come from.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Backing {
    /// Ramfs file: the page cache owns every byte (uncached pages read zero).
    Ram,
    /// Immutable boot module payload; `name` is the module name.
    Boot {
        /// Module name bytes.
        name: [u8; MAX_NAME],
        /// Meaningful bytes of `name`.
        name_len: u8,
    },
    /// File on a mounted on-disk file system (M5b).
    ///
    /// `node` is the mount's stable disk-node id, which is the cache key half:
    /// a FAT directory-entry move (rename) changes the underlying cookie but not
    /// this id, so cached pages and open descriptions stay valid.
    Disk {
        /// Index into the VFS mount table.
        mount: u8,
        /// Stable disk-node id inside that mount.
        node: u16,
    },
    /// VFS-generated node (M8h): the bytes are produced by `vfs::pseudo`
    /// instead of being stored in the page cache.
    ///
    /// `node` is the pseudo node id (`vfs::pseudo::STATUS` and friends); it is
    /// deliberately not a VNode id so the generator can never be confused with
    /// a table slot.
    Generated {
        /// Pseudo node id understood by `vfs::pseudo`.
        node: u16,
    },
}

impl Backing {
    const EMPTY: Backing = Backing::Ram;

    /// Module name, when this is a boot payload.
    ///
    /// Only the host tests inspect it: the read path uses [`ReadSource`] instead
    /// of matching on the backing again, so production code never needs it.
    #[cfg(test)]
    pub fn boot_name(&self) -> Option<&[u8]> {
        match self {
            Backing::Ram => None,
            Backing::Boot { name, name_len } => Some(&name[..(*name_len as usize).min(name.len())]),
            Backing::Disk { .. } => None,
            Backing::Generated { .. } => None,
        }
    }

    /// Mount index and disk-node id, when this is a disk file.
    pub fn disk_node(&self) -> Option<(u8, u16)> {
        match *self {
            Backing::Disk { mount, node } => Some((mount, node)),
            Backing::Ram | Backing::Boot { .. } | Backing::Generated { .. } => None,
        }
    }
}

/// One `user.*` extension attribute.
#[derive(Clone, Copy)]
pub enum Xattr {
    /// No attribute in this slot.
    Empty,
    /// Attribute with a short name and value.
    Set {
        /// Meaningful bytes of `name`.
        name_len: u8,
        /// Attribute name (the `user.` prefix is implicit).
        name: [u8; MAX_XATTR_NAME],
        /// Meaningful bytes of `value`.
        value_len: u8,
        /// Attribute value.
        value: [u8; MAX_XATTR_VALUE],
    },
}

impl Xattr {
    const EMPTY: Xattr = Xattr::Empty;

    /// Attribute name bytes, when set.
    pub fn name(&self) -> Option<&[u8]> {
        match self {
            Xattr::Empty => None,
            Xattr::Set { name_len, name, .. } => {
                Some(&name[..(*name_len as usize).min(name.len())])
            }
        }
    }

    /// Attribute value bytes, when set.
    pub fn value(&self) -> Option<&[u8]> {
        match self {
            Xattr::Empty => None,
            Xattr::Set {
                value_len, value, ..
            } => Some(&value[..(*value_len as usize).min(value.len())]),
        }
    }
}

/// One VNode.
#[derive(Clone, Copy)]
pub struct VNode {
    /// Whether the slot currently holds a node.
    pub used: bool,
    /// File or directory.
    pub kind: NodeKind,
    /// Rejects writes (boot payloads).
    pub read_only: bool,
    /// Major device number (non-zero for character devices, M8h).
    pub dev_major: u16,
    /// Minor device number (non-zero for character devices, M8h).
    pub dev_minor: u16,
    /// Size in bytes (0 for directories).
    pub size: u64,
    /// Parent directory, or [`VNodeId::NONE`] for the root.
    pub parent: VNodeId,
    /// First child of this directory.
    pub first_child: VNodeId,
    /// Next sibling within the parent directory.
    pub next_sibling: VNodeId,
    /// Entry name; only `name_len` bytes are meaningful.
    pub name: [u8; MAX_NAME],
    /// Meaningful bytes of `name`.
    pub name_len: u8,
    /// Where the bytes come from.
    pub backing: Backing,
    /// Extension attributes.
    pub xattrs: [Xattr; MAX_XATTRS],
}

impl VNode {
    /// Empty slot.
    pub const EMPTY: VNode = VNode {
        used: false,
        kind: NodeKind::File,
        read_only: false,
        dev_major: 0,
        dev_minor: 0,
        size: 0,
        parent: VNodeId::NONE,
        first_child: VNodeId::NONE,
        next_sibling: VNodeId::NONE,
        name: [0u8; MAX_NAME],
        name_len: 0,
        backing: Backing::EMPTY,
        xattrs: [Xattr::EMPTY; MAX_XATTRS],
    };

    /// Entry name bytes.
    pub fn name(&self) -> &[u8] {
        &self.name[..(self.name_len as usize).min(self.name.len())]
    }

    /// Whether this node is named `name`.
    pub fn matches(&self, name: &[u8]) -> bool {
        self.name() == name
    }

    /// Cache key of this node's data pages.
    ///
    /// The key combines the backing store id with the node's generation-packed
    /// id, so a recycled slot cannot inherit another file's cached pages and the
    /// two boot payloads (`init` and `child`) stay distinct.
    ///
    /// A disk node uses its stable mount-local disk-node id instead of the VNode
    /// id: the VNode for a materialised disk entry can be released and rebuilt,
    /// but the disk node id survives a FAT rename, so the cached pages must stay
    /// attached to it.
    pub fn cache_key(&self, id: VNodeId) -> CacheKey {
        match self.backing.disk_node() {
            Some((mount, node)) => CacheKey::new(FS_DISK_BASE + mount as u16, node as u64),
            None => CacheKey::new(self.fs_id(), id.raw() as u64),
        }
    }

    /// Data backing store id used in cache keys.
    pub fn fs_id(&self) -> u16 {
        match self.backing {
            Backing::Ram => FS_RAM,
            Backing::Boot { .. } => FS_BOOT,
            Backing::Disk { mount, .. } => FS_DISK_BASE + mount as u16,
            // Generated nodes never use the page cache, so their cache-key file
            // system id is the reserved 0 and no page can ever be attached.
            Backing::Generated { .. } => 0,
        }
    }
}

/// The VNode table plus its generation counters.
pub struct Table {
    nodes: [VNode; MAX_VNODES],
    generations: [u8; MAX_VNODES],
}

impl Table {
    /// Empty table.
    pub const fn new() -> Table {
        Table {
            nodes: [VNode::EMPTY; MAX_VNODES],
            generations: [0u8; MAX_VNODES],
        }
    }

    /// Reset every slot in place; never materialises a table-sized temporary.
    pub fn clear(&mut self) {
        for node in self.nodes.iter_mut() {
            *node = VNode::EMPTY;
        }
        for generation in self.generations.iter_mut() {
            *generation = 0;
        }
    }

    /// Live id for a table index.
    pub fn id_of(&self, index: usize) -> VNodeId {
        let generation = self.generations[index.min(MAX_VNODES - 1)] as u16;
        VNodeId::from_raw((generation << 8) | (index as u16 & 0xFF))
    }

    fn index_of(&self, id: VNodeId) -> Result<usize, VfsError> {
        if id == VNodeId::NONE {
            return Err(VfsError::NotFound);
        }
        let index = id.index();
        if index >= MAX_VNODES {
            return Err(VfsError::NotFound);
        }
        if !self.nodes[index].used || self.generations[index] != id.generation() {
            return Err(VfsError::NotFound);
        }
        Ok(index)
    }

    /// Look up a live node.
    pub fn get(&self, id: VNodeId) -> Result<&VNode, VfsError> {
        Ok(&self.nodes[self.index_of(id)?])
    }

    /// Look up a live node mutably.
    pub fn get_mut(&mut self, id: VNodeId) -> Result<&mut VNode, VfsError> {
        let index = self.index_of(id)?;
        Ok(&mut self.nodes[index])
    }

    /// Id of the entry `name` in `directory`, if any.
    pub fn child(&self, directory: VNodeId, name: &[u8]) -> Result<Option<VNodeId>, VfsError> {
        let dir = self.get(directory)?;
        if dir.kind != NodeKind::Directory {
            return Err(VfsError::NotDirectory);
        }
        let mut cursor = dir.first_child;
        while cursor != VNodeId::NONE {
            let node = self.get(cursor)?;
            if node.matches(name) {
                return Ok(Some(cursor));
            }
            cursor = node.next_sibling;
        }
        Ok(None)
    }

    /// The live node whose backing is exactly `backing`, if any.
    ///
    /// Used by the M5b disk mounts to reuse the VNode of a disk entry that has
    /// already been materialised, so a second lookup of the same file does not
    /// split its identity (and therefore its page-cache key) in two.
    pub fn find_backing(&self, backing: Backing) -> Option<VNodeId> {
        for index in 0..MAX_VNODES {
            let node = &self.nodes[index];
            if node.used && node.backing == backing {
                return Some(self.id_of(index));
            }
        }
        None
    }

    /// Whether at least one node slot is free.
    ///
    /// Creation paths ask first: the disk layer writes a directory entry and then
    /// needs a VNode to name it, so a full table must be refused *before* the
    /// volume changes (M5c never evicts cached nodes to make room).
    pub fn has_free_slot(&self) -> bool {
        self.nodes.iter().any(|node| !node.used)
    }

    /// Allocate a node below `parent`.
    /// Every live node with its id.
    ///
    /// Whole-namespace passes (M5b write-back) need to know which nodes exist
    /// without walking the parent/child links, which only cover directories.
    pub fn used(&self) -> impl Iterator<Item = (VNodeId, &VNode)> {
        self.nodes
            .iter()
            .enumerate()
            .filter(|(_, node)| node.used)
            .map(|(index, node)| (self.id_of(index), node))
    }

    pub fn alloc(
        &mut self,
        kind: NodeKind,
        parent: VNodeId,
        name: &[u8],
        backing: Backing,
    ) -> Result<VNodeId, VfsError> {
        if name.is_empty() && parent != VNodeId::NONE {
            return Err(VfsError::BadPath);
        }
        if name.len() > MAX_NAME {
            return Err(VfsError::NameTooLong);
        }
        if name.contains(&0) {
            return Err(VfsError::BadPath);
        }
        if parent != VNodeId::NONE {
            self.get(parent)?;
        }
        for index in 0..MAX_VNODES {
            if self.nodes[index].used {
                continue;
            }
            let id = self.id_of(index);
            let mut node = VNode::EMPTY;
            node.used = true;
            node.kind = kind;
            node.parent = parent;
            node.name[..name.len()].copy_from_slice(name);
            node.name_len = name.len() as u8;
            node.backing = backing;
            node.read_only = matches!(backing, Backing::Boot { .. });
            self.nodes[index] = node;
            if parent != VNodeId::NONE {
                self.link_child(parent, id);
            }
            return Ok(id);
        }
        Err(VfsError::Quota)
    }

    /// Release a node slot, bumping its generation.
    pub fn release(&mut self, id: VNodeId) -> Result<(), VfsError> {
        let index = self.index_of(id)?;
        self.unlink_from_parent(id)?;
        self.nodes[index] = VNode::EMPTY;
        self.generations[index] = self.generations[index].wrapping_add(1);
        Ok(())
    }

    /// Whether `directory` has no children.
    pub fn is_empty_directory(&self, directory: VNodeId) -> Result<bool, VfsError> {
        let dir = self.get(directory)?;
        if dir.kind != NodeKind::Directory {
            return Err(VfsError::NotDirectory);
        }
        Ok(dir.first_child == VNodeId::NONE)
    }

    /// Push the children of `directory` into `out`, starting at index `start`.
    ///
    /// Returns the number of entries written. `start` lets a caller walk a
    /// directory in pages without holding an iterator across table mutations.
    pub fn readdir(
        &self,
        directory: VNodeId,
        start: usize,
        out: &mut [DirEntry],
    ) -> Result<usize, VfsError> {
        let dir = self.get(directory)?;
        if dir.kind != NodeKind::Directory {
            return Err(VfsError::NotDirectory);
        }
        let mut written = 0;
        let mut seen = 0;
        let mut cursor = dir.first_child;
        while cursor != VNodeId::NONE && written < out.len() {
            let node = self.get(cursor)?;
            if seen >= start {
                let mut entry = DirEntry::empty();
                let len = node.name().len().min(entry.name.len());
                entry.name[..len].copy_from_slice(&node.name()[..len]);
                entry.name_len = len as u8;
                entry.kind = node.kind;
                entry.size = node.size;
                entry.dev_major = node.dev_major;
                entry.dev_minor = node.dev_minor;
                out[written] = entry;
                written += 1;
            }
            seen += 1;
            cursor = node.next_sibling;
        }
        Ok(written)
    }

    /// Move `id` to `parent` and rename it (used by `rename`).
    pub fn reparent(&mut self, id: VNodeId, parent: VNodeId, name: &[u8]) -> Result<(), VfsError> {
        self.get(id)?;
        self.get(parent)?;
        if name.is_empty() || name.len() > MAX_NAME || name.contains(&0) {
            return Err(VfsError::BadPath);
        }
        self.unlink_from_parent(id)?;
        {
            let node = &mut self.nodes[id.index()];
            node.name = [0u8; MAX_NAME];
            node.name[..name.len()].copy_from_slice(name);
            node.name_len = name.len() as u8;
        }
        self.link_child(parent, id);
        Ok(())
    }

    fn link_child(&mut self, parent: VNodeId, child: VNodeId) {
        let previous = {
            let dir = &self.nodes[parent.index()];
            dir.first_child
        };
        {
            let node = &mut self.nodes[child.index()];
            node.next_sibling = previous;
            node.parent = parent;
        }
        self.nodes[parent.index()].first_child = child;
    }

    fn unlink_from_parent(&mut self, id: VNodeId) -> Result<(), VfsError> {
        let parent = self.nodes[id.index()].parent;
        if parent == VNodeId::NONE {
            return Ok(());
        }
        let mut previous = VNodeId::NONE;
        let mut cursor = self.nodes[parent.index()].first_child;
        while cursor != VNodeId::NONE {
            if cursor == id {
                let next = self.nodes[cursor.index()].next_sibling;
                if previous == VNodeId::NONE {
                    self.nodes[parent.index()].first_child = next;
                } else {
                    self.nodes[previous.index()].next_sibling = next;
                }
                let node = &mut self.nodes[id.index()];
                node.next_sibling = VNodeId::NONE;
                node.parent = VNodeId::NONE;
                return Ok(());
            }
            previous = cursor;
            cursor = self.nodes[cursor.index()].next_sibling;
        }
        Err(VfsError::Corrupt)
    }
}
