//! M5b disk-backed mounts: FAT32 and ext2 in one static mount table.
//!
//! # What this module is
//!
//! The M5a VFS is an in-memory namespace (`ramfs` plus read-only `/boot`). M5b
//! adds two *real* file systems on top of the legacy virtio-blk devices that
//! [`crate::io`] brings up, without introducing a generic mount API yet: exactly
//! two mounts, `/fat` (FAT32) and `/ext2` (ext2), both at the root of the RAM
//! namespace. Mounting is therefore a fixed operation, not a table walk.
//!
//! # Stable disk-node identity
//!
//! A `VNode` is metadata that can be released and rebuilt; a page-cache key and
//! an open description must survive that. Every file opened through a mount
//! therefore gets a **small fixed-size disk-node id** in this table. For FAT the
//! underlying identity is the short directory-entry cookie, which `rename`
//! *changes* — so the id is allocated once per cookie, and [`rename`] updates the
//! stored cookie instead of moving the id. For ext2 the identity is the inode
//! number, which is stable by construction.
//!
//! The id is also the low half of the page-cache key ([`CacheKey::node`]), and
//! the mount index is the key's file-system half (`FS_DISK_BASE + mount`), so a
//! cache flush can find its way back to this table from a key alone.
//!
//! # Write-back, not write-through
//!
//! Writes go through the page cache first (the VFS marks pages dirty and updates
//! the VNode size). [`writeback`] is the only path that pushes bytes to the file
//! system, and [`sync`] is the only path that flushes the device. An error from
//! either is recorded as a **sticky** mount error: every later operation on that
//! mount fails with the first error instead of pretending the data reached the
//! disk. A failed write-back leaves the page dirty.
//!
//! # Concurrency and stack
//!
//! M5b is single-CPU: the VFS runs with interrupts disabled, and the block
//! driver's own `IrqGuard` nests inside that. No lock is needed and none is
//! taken. The mount table and node table are `static mut` (the VFS is the only
//! accessor), never copied by value, and every buffer used here lives on the
//! caller's stack and is bounded by one 4 KiB cache frame that is not copied.

use core::mem::MaybeUninit;
use core::str;

use super::pagecache::CacheKey;
use super::types::DirEntry;
use super::types::MAX_NAME;
use super::types::NodeKind;
use super::types::VfsError;
use super::vnode::FS_DISK_BASE;

/// How many disk mounts M5b supports (`/fat` and `/ext2`).
pub const MAX_MOUNTS: usize = 2;

/// Fixed table of disk nodes per mount.
///
/// M5c1 raises this from 16 to 64 so a real directory tree fits. The table stays
/// fixed capacity by design (M5c does not evict cached nodes to make room), and an
/// exhausted table is reported as [`VfsError::Quota`] *before* the file system is
/// mutated, so no unreachable entry is left on the volume.
pub const MAX_DISK_NODES: usize = 64;

/// Longest FAT 8.3 name accepted from the VFS (`XXXXXXXX.XXX`).
const FAT_NAME_MAX: usize = 12;

/// Longest ext2 name accepted; the library limit is 31.
const EXT2_NAME_MAX: usize = 31;

/// The block device a mounted file system borrows.
///
/// In the kernel this is the index handle of a legacy virtio-blk device; host
/// regressions use the in-memory `MemDisk` so the real FAT32/ext2 code runs
/// against a real block device implementation.
#[cfg(not(test))]
pub type Device = crate::io::VirtioBlk;
#[cfg(test)]
pub type Device = block::test_support::MemDisk;

/// Which on-disk file system a mount holds.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Kind {
    /// FAT32 (`/fat`, 64 MiB data disk).
    Fat32,
    /// ext2 (`/ext2`, 32 MiB data disk).
    Ext2,
}

impl Kind {
    /// Name of the mount point below `/`.
    pub const fn mount_name(self) -> &'static [u8] {
        match self {
            Kind::Fat32 => b"fat",
            Kind::Ext2 => b"ext2",
        }
    }
}

/// One mounted file system and its node table.
enum Fs {
    /// FAT32 volume.
    Fat(fat32::Fat32<Device>),
    /// ext2 volume.
    Ext2(ext2::Ext2<Device>),
}

/// One materialised disk file (mount-root children only in M5b).
#[derive(Clone, Copy)]
struct Entry {
    /// Slot is live.
    used: bool,
    /// File or directory.
    kind: NodeKind,
    /// Last known size in bytes.
    size: u64,
    /// FAT: cookie of the short directory entry (`ROOT_COOKIE` for the root).
    fat_cookie: u64,
    /// FAT: first cluster of the containing directory.
    fat_parent: u32,
    /// ext2: inode number.
    ino: u32,
}

/// Empty node slot.
const ENTRY_EMPTY: Entry = Entry {
    used: false,
    kind: NodeKind::File,
    size: 0,
    fat_cookie: 0,
    fat_parent: 0,
    ino: 0,
};

/// One mount: the file-system object, the node table and the sticky error.
struct Mount {
    kind: Kind,
    fs: Fs,
    entries: [Entry; MAX_DISK_NODES],
    sticky: Option<VfsError>,
}

impl Mount {
    /// Record the first *media* error; later calls keep reporting it.
    ///
    /// Negative lookup results (`NotFound`, `AlreadyExists`, ... ) are ordinary
    /// answers, not device failures, so they must never poison the mount: a
    /// `stat` of a missing name would otherwise make every later operation on
    /// the volume fail with the same error.
    fn fail(&mut self, error: VfsError) -> VfsError {
        let media = matches!(error, VfsError::Io | VfsError::Timeout | VfsError::Corrupt);
        if media && self.sticky.is_none() {
            self.sticky = Some(error);
        }
        error
    }

    /// Reject work once the mount is in the sticky-error state.
    fn check(&self) -> Result<(), VfsError> {
        match self.sticky {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }
}

/// One mount slot: whether it holds a live [`Mount`], plus that mount's storage.
///
/// A [`Mount`] is large (a 64-entry node table plus the file-system object) and
/// the boot stack is only 16 KiB, so the mount is written **in place** into this
/// static slot instead of being built as a local and then copied in. `used` is
/// the only flag readers consult, and it is set last, so a half-built mount is
/// never observable.
struct Slot {
    used: bool,
    mount: MaybeUninit<Mount>,
}

impl Slot {
    const EMPTY: Slot = Slot {
        used: false,
        mount: MaybeUninit::uninit(),
    };
}

/// The static mount table. `used == false` slots are free.
static mut MOUNTS: [Slot; MAX_MOUNTS] = [Slot::EMPTY, Slot::EMPTY];

fn mounts() -> &'static mut [Slot; MAX_MOUNTS] {
    // SAFETY: single-CPU, IF=0 contract (see the module docs); the VFS owns this
    // table and every accessor finishes before returning. It is never copied.
    unsafe { &mut *core::ptr::addr_of_mut!(MOUNTS) }
}

fn mount_ref(index: u8) -> Result<&'static mut Mount, VfsError> {
    if (index as usize) >= MAX_MOUNTS {
        return Err(VfsError::NotSupported);
    }
    let slot = &mut mounts()[index as usize];
    if !slot.used {
        return Err(VfsError::NotSupported);
    }
    // SAFETY: `used` is set only after the whole mount is initialised, and it is
    // cleared only after the mount has been dropped.
    Ok(unsafe { &mut *slot.mount.as_mut_ptr() })
}

/// Is the mount slot live?
pub fn is_mounted(index: u8) -> bool {
    (index as usize) < MAX_MOUNTS && mounts()[index as usize].used
}

/// Clear the sticky media error of a mounted volume and return the old value.
///
/// Negative answers never poison a mount, but a media failure (`Io`, `Timeout`,
/// `Corrupt`) is sticky on purpose: a volume that failed must keep failing rather
/// than quietly hand back stale data. This entry point is the one deliberate way
/// out of that state, for callers that know they just consumed a one-shot device
/// fault (the M5c3 fault self-test). It only rewrites `sticky`: nothing is
/// flushed, no node table is reset and no cached page is invalidated.
pub fn clear_sticky(kind: Kind) -> Option<VfsError> {
    for index in 0..MAX_MOUNTS {
        let Ok(mounted) = mount_ref(index as u8) else {
            continue;
        };
        if mounted.kind == kind {
            return mounted.sticky.take();
        }
    }
    None
}

/// Page-cache key of a disk node.
pub fn cache_key(index: u8, node: u16) -> CacheKey {
    CacheKey::new(FS_DISK_BASE + index as u16, node as u64)
}

// ---------------------------------------------------------------------------
// Mount / unmount
// ---------------------------------------------------------------------------

/// Mount a formatted volume in the first free slot.
///
/// The kernel never formats: the volume layout is produced by xtask. A mount
/// that cannot be read is reported to the caller, which owns the boot marker.
///
/// The mount is built **in place** in the static table. A `Mount` local would be
/// a multi-kilobyte stack frame, which the 16 KiB boot stack cannot afford next
/// to the file-system library's own frame (this function used to reserve 4 KiB).
pub fn mount(kind: Kind, device: Device) -> Result<u8, VfsError> {
    let index = {
        let slots = mounts();
        let mut free = None;
        for (index, slot) in slots.iter().enumerate() {
            if !slot.used {
                free = Some(index);
                break;
            }
        }
        free.ok_or(VfsError::Busy)?
    };
    let slot = &mut mounts()[index];
    // SAFETY: the slot is free, so nothing reads this storage; interrupts are off
    // (module contract) and `used` stays false until every field has been written.
    let place = slot.mount.as_mut_ptr();
    let entries = unsafe { core::ptr::addr_of_mut!((*place).entries).cast::<Entry>() };
    for node in 0..MAX_DISK_NODES {
        // SAFETY: `entries` points at `MAX_DISK_NODES` uninitialised `Entry`s.
        unsafe { core::ptr::write(entries.add(node), ENTRY_EMPTY) };
    }
    // SAFETY: same free slot; these two fields are plain data.
    unsafe {
        core::ptr::addr_of_mut!((*place).kind).write(kind);
        core::ptr::addr_of_mut!((*place).sticky).write(None);
    }
    // The file-system object is the one value the libraries hand back by value;
    // it is written straight into the slot instead of through a `Mount` local.
    match kind {
        Kind::Fat32 => {
            let fat = fat32::Fat32::mount(device).map_err(map_fat)?;
            // SAFETY: as above; a failed mount never publishes the slot.
            unsafe { core::ptr::addr_of_mut!((*place).fs).write(Fs::Fat(fat)) };
        }
        Kind::Ext2 => {
            let ext = ext2::Ext2::mount(device).map_err(map_ext2)?;
            // SAFETY: as above.
            unsafe { core::ptr::addr_of_mut!((*place).fs).write(Fs::Ext2(ext)) };
        }
    }
    slot.used = true;
    Ok(index as u8)
}

/// Drop every mount (host test reset, and a failed boot path).
pub fn reset() {
    for slot in mounts().iter_mut() {
        if slot.used {
            // SAFETY: a used slot holds an initialised mount; drop it in place
            // instead of moving a multi-kilobyte value onto the stack.
            unsafe { core::ptr::drop_in_place(slot.mount.as_mut_ptr()) };
            slot.used = false;
        }
    }
}

/// Take the device back out of a mount (host tests remount the same disk).
#[cfg(test)]
pub fn unmount(index: u8) -> Option<Device> {
    if (index as usize) >= MAX_MOUNTS {
        return None;
    }
    let slot = &mut mounts()[index as usize];
    if !slot.used {
        return None;
    }
    // SAFETY: the slot is initialised; the file-system object is the only field
    // with a destructor, so reading it out and forgetting the slot is enough.
    let fs = unsafe { core::ptr::read(core::ptr::addr_of!((*slot.mount.as_mut_ptr()).fs)) };
    slot.used = false;
    match fs {
        Fs::Fat(fat) => fat.unmount().ok(),
        Fs::Ext2(ext2) => Some(ext2.into_device()),
    }
}

// ---------------------------------------------------------------------------
// Names
// ---------------------------------------------------------------------------

/// Validate a FAT 8.3 name and borrow it as `&str`.
///
/// The VFS speaks raw path bytes; FAT only speaks ASCII 8.3 short names. The
/// conversion is explicit and refuses anything else — it never truncates.
fn fat_name(name: &[u8]) -> Result<&str, VfsError> {
    if name.is_empty() || name.len() > FAT_NAME_MAX {
        return Err(VfsError::NameTooLong);
    }
    for &byte in name {
        let allowed = byte.is_ascii_alphanumeric()
            || matches!(
                byte,
                b'.' | b'_'
                    | b'-'
                    | b'~'
                    | b'$'
                    | b'%'
                    | b'\''
                    | b'!'
                    | b'#'
                    | b'&'
                    | b'('
                    | b')'
                    | b'@'
                    | b'^'
                    | b'{'
                    | b'}'
                    | b'`'
            );
        if !allowed {
            return Err(VfsError::NotSupported);
        }
    }
    // `for` above only accepted ASCII, so this cannot fail.
    str::from_utf8(name).map_err(|_| VfsError::NotSupported)
}

/// Validate an ext2 name.
fn ext2_name(name: &[u8]) -> Result<&[u8], VfsError> {
    if name.is_empty() {
        return Err(VfsError::NameTooLong);
    }
    if name.len() > EXT2_NAME_MAX {
        return Err(VfsError::NameTooLong);
    }
    if name.contains(&b'/') || name.contains(&0) {
        return Err(VfsError::BadPath);
    }
    Ok(name)
}

fn from_fat_kind(kind: fat32::NodeKind) -> NodeKind {
    match kind {
        fat32::NodeKind::File => NodeKind::File,
        fat32::NodeKind::Directory => NodeKind::Directory,
    }
}

fn to_fat_kind(kind: NodeKind) -> fat32::NodeKind {
    match kind {
        NodeKind::File => fat32::NodeKind::File,
        NodeKind::Directory => fat32::NodeKind::Directory,
        // Disk file systems never store character devices (M8h): the only
        // character devices live in the generated /dev namespace.
        NodeKind::CharDevice => unreachable!("disk mounts never store character devices"),
    }
}

fn from_ext2_kind(kind: ext2::NodeKind) -> NodeKind {
    match kind {
        ext2::NodeKind::File => NodeKind::File,
        ext2::NodeKind::Directory => NodeKind::Directory,
    }
}

fn to_ext2_kind(kind: NodeKind) -> ext2::NodeKind {
    match kind {
        NodeKind::File => ext2::NodeKind::File,
        NodeKind::Directory => ext2::NodeKind::Directory,
        NodeKind::CharDevice => unreachable!("disk mounts never store character devices"),
    }
}

/// FAT root directory node of a mount.
fn fat_root() -> fat32::FatNode {
    fat32::FatNode {
        cookie: fat32::ROOT_COOKIE,
        parent: 0,
        kind: fat32::NodeKind::Directory,
        size: 0,
    }
}

// ---------------------------------------------------------------------------
// Error mapping
// ---------------------------------------------------------------------------

/// Map a FAT32 error onto the VFS error set.
///
/// Block-level timeouts and read-only devices keep their identity; every other
/// block failure is [`VfsError::Io`] because the VFS has no richer vocabulary
/// yet and must not invent success.
pub fn map_fat(error: fat32::Fat32Error) -> VfsError {
    use fat32::Fat32Error as E;
    match error {
        E::Block(fat32::BlockError::Timeout) => VfsError::Timeout,
        E::Block(fat32::BlockError::ReadOnly) => VfsError::ReadOnly,
        E::Block(fat32::BlockError::Unsupported) => VfsError::NotSupported,
        E::Block(_) => VfsError::Io,
        E::NotFound => VfsError::NotFound,
        E::NotADirectory => VfsError::NotDirectory,
        E::IsADirectory => VfsError::IsDirectory,
        E::AlreadyExists => VfsError::AlreadyExists,
        E::NotEmpty => VfsError::NotEmpty,
        E::NoSpace => VfsError::NoMemory,
        E::BadName | E::InvalidArgument => VfsError::NotSupported,
        E::TooLarge => VfsError::Quota,
        E::BadBpb | E::BadCluster | E::Corrupt => VfsError::Corrupt,
        E::Unsupported => VfsError::NotSupported,
    }
}

/// Map an ext2 error onto the VFS error set.
pub fn map_ext2(error: ext2::Error) -> VfsError {
    use ext2::Error as E;
    match error {
        E::Io => VfsError::Io,
        E::ReadOnly => VfsError::ReadOnly,
        E::Unsupported => VfsError::NotSupported,
        E::BadMagic | E::BadSuperblock | E::Corrupt | E::Cycle => VfsError::Corrupt,
        E::NotFound => VfsError::NotFound,
        E::NotDirectory => VfsError::NotDirectory,
        E::IsDirectory => VfsError::IsDirectory,
        E::Exists => VfsError::AlreadyExists,
        E::NameInvalid => VfsError::NotSupported,
        E::NameTooLong => VfsError::NameTooLong,
        E::NotEmpty => VfsError::NotEmpty,
        E::NoSpace => VfsError::NoMemory,
        E::Quota => VfsError::Quota,
        E::BadOffset => VfsError::BadOffset,
    }
}

// ---------------------------------------------------------------------------
// Node table
// ---------------------------------------------------------------------------

/// Whether the node table still has a slot for one more entry.
fn entry_slot_free(entries: &[Entry; MAX_DISK_NODES]) -> bool {
    entries.iter().any(|entry| !entry.used)
}

/// Node id for an already materialised FAT file, or a fresh one.
fn ensure_fat_node(
    entries: &mut [Entry; MAX_DISK_NODES],
    node: &fat32::FatNode,
) -> Result<u16, VfsError> {
    let kind = from_fat_kind(node.kind);
    for (index, entry) in entries.iter().enumerate() {
        if entry.used && entry.fat_cookie == node.cookie {
            entries[index].kind = kind;
            entries[index].size = node.size;
            entries[index].fat_parent = node.parent;
            return Ok(index as u16);
        }
    }
    for (index, entry) in entries.iter_mut().enumerate() {
        if !entry.used {
            *entry = Entry {
                used: true,
                kind,
                size: node.size,
                fat_cookie: node.cookie,
                fat_parent: node.parent,
                ino: 0,
            };
            return Ok(index as u16);
        }
    }
    Err(VfsError::Quota)
}

/// Node id for an already materialised ext2 inode, or a fresh one.
fn ensure_ext2_node(
    entries: &mut [Entry; MAX_DISK_NODES],
    node: &ext2::ExtNode,
) -> Result<u16, VfsError> {
    let kind = from_ext2_kind(node.kind);
    for (index, entry) in entries.iter().enumerate() {
        if entry.used && entry.ino == node.inode {
            entries[index].kind = kind;
            entries[index].size = node.size as u64;
            return Ok(index as u16);
        }
    }
    for (index, entry) in entries.iter_mut().enumerate() {
        if !entry.used {
            *entry = Entry {
                used: true,
                kind,
                size: node.size as u64,
                fat_cookie: 0,
                fat_parent: 0,
                ino: node.inode,
            };
            return Ok(index as u16);
        }
    }
    Err(VfsError::Quota)
}

// ---------------------------------------------------------------------------
// Operations (directory aware: M5c1 walks real subdirectories)
// ---------------------------------------------------------------------------

/// Node id naming the root directory of a mount in [`lookup`], [`create`],
/// [`unlink`], [`rename`] and [`readdir`].
///
/// Disk-node ids are 16-bit table indices with at most [`MAX_DISK_NODES`] live
/// slots, so `u16::MAX` can never collide with a real node.
pub const ROOT_NODE: u16 = u16::MAX;

/// How many entries one `readdir` walk may examine before giving up.
///
/// The VFS is fixed capacity by design; a directory that cannot be walked within
/// this budget is reported as [`VfsError::Quota`] instead of spinning on a
/// malformed file system.
pub const MAX_DIR_ENTRIES: usize = 512;

/// Copy a live entry out of the node table.
fn entry_of(mount: &Mount, node: u16) -> Result<Entry, VfsError> {
    let entry = *mount.entries.get(node as usize).ok_or(VfsError::NotFound)?;
    if !entry.used {
        return Err(VfsError::NotFound);
    }
    Ok(entry)
}

/// FAT node of a materialised directory id (or of the mount root).
fn fat_directory(mount: &Mount, dir: u16) -> Result<fat32::FatNode, VfsError> {
    if dir == ROOT_NODE {
        return Ok(fat_root());
    }
    let entry = entry_of(mount, dir)?;
    if entry.kind != NodeKind::Directory {
        return Err(VfsError::NotDirectory);
    }
    Ok(fat32::FatNode {
        cookie: entry.fat_cookie,
        parent: entry.fat_parent,
        kind: fat32::NodeKind::Directory,
        size: 0,
    })
}

/// ext2 inode number of a materialised directory id (or of the mount root).
fn ext2_directory(mount: &Mount, dir: u16) -> Result<u32, VfsError> {
    if dir == ROOT_NODE {
        return Ok(ext2::ROOT_INODE);
    }
    let entry = entry_of(mount, dir)?;
    if entry.kind != NodeKind::Directory {
        return Err(VfsError::NotDirectory);
    }
    Ok(entry.ino)
}

/// Fill `entry` with the directory entry at index `start`.
///
/// Returns `Ok(true)` when an entry was produced and `Ok(false)` at the end of
/// the directory. Both file systems are walked in on-disk order and `.`/`..`
/// are skipped, so the index is stable across calls as long as the directory is
/// not modified in between.
pub fn readdir(index: u8, dir: u16, start: usize, entry: &mut DirEntry) -> Result<bool, VfsError> {
    let mount = mount_ref(index)?;
    mount.check()?;
    match mount.kind {
        Kind::Fat32 => {
            let parent = fat_directory(mount, dir)?;
            let mut seen = 0usize;
            let mut filled = false;
            let mut over_budget = false;
            let mut pending = DirEntry::empty();
            let result = match &mut mount.fs {
                Fs::Fat(fat) => fat.readdir(&parent, |entry| {
                    if filled {
                        return Ok(());
                    }
                    if seen < start {
                        seen += 1;
                        return Ok(());
                    }
                    if seen - start >= MAX_DIR_ENTRIES {
                        // Too many entries to walk in one call: a capacity limit
                        // (reported as `Quota` below), not an unsupported option.
                        over_budget = true;
                        return Err(fat32::Fat32Error::Unsupported);
                    }
                    let name = entry.name();
                    if name.len() > MAX_NAME {
                        seen += 1;
                        return Ok(());
                    }
                    pending = DirEntry {
                        name: [0u8; MAX_NAME],
                        name_len: name.len() as u8,
                        kind: from_fat_kind(entry.node.kind),
                        size: entry.node.size,
                        dev_major: 0,
                        dev_minor: 0,
                    };
                    pending.name[..name.len()].copy_from_slice(name);
                    filled = true;
                    // The visitor only has fat32 errors, so a private sentinel
                    // unwinds the walk once the wanted entry has been copied.
                    Err(fat32::Fat32Error::Unsupported)
                }),
                Fs::Ext2(_) => unreachable!("mount kind and file system disagree"),
            };
            match result {
                Ok(()) => {}
                Err(fat32::Fat32Error::Unsupported) if filled => {}
                Err(fat32::Fat32Error::Unsupported) if over_budget => {
                    return Err(VfsError::Quota);
                }
                Err(error) => return Err(mount.fail(map_fat(error))),
            }
            if filled {
                *entry = pending;
            }
            Ok(filled)
        }
        Kind::Ext2 => {
            let parent = ext2_directory(mount, dir)?;
            let mut offset = 0u64;
            let mut seen = 0usize;
            let mut examined = 0usize;
            loop {
                let next = match &mut mount.fs {
                    Fs::Ext2(ext2) => ext2.readdir(parent, offset),
                    Fs::Fat(_) => unreachable!("mount kind and file system disagree"),
                };
                match next {
                    Ok(Some((found, next_offset))) => {
                        examined += 1;
                        if examined > MAX_DIR_ENTRIES {
                            return Err(VfsError::Quota);
                        }
                        offset = next_offset;
                        let name = found.name();
                        if name == b"." || name == b".." || name.len() > MAX_NAME {
                            continue;
                        }
                        if seen < start {
                            seen += 1;
                            continue;
                        }
                        let mut built = DirEntry {
                            name: [0u8; MAX_NAME],
                            name_len: name.len() as u8,
                            kind: from_ext2_kind(found.kind),
                            size: found.size as u64,
                            dev_major: 0,
                            dev_minor: 0,
                        };
                        built.name[..name.len()].copy_from_slice(name);
                        *entry = built;
                        return Ok(true);
                    }
                    Ok(None) => return Ok(false),
                    Err(error) => return Err(mount.fail(map_ext2(error))),
                }
            }
        }
    }
}

/// Look up `name` in directory `dir` (`ROOT_NODE` for the mount root).
pub fn lookup(index: u8, dir: u16, name: &[u8]) -> Result<(u16, NodeKind, u64), VfsError> {
    let mount = mount_ref(index)?;
    mount.check()?;
    match mount.kind {
        Kind::Fat32 => {
            let parent = fat_directory(mount, dir)?;
            let name = fat_name(name)?;
            let result = match &mut mount.fs {
                Fs::Fat(fat) => fat.lookup(&parent, name),
                Fs::Ext2(_) => unreachable!("mount kind and file system disagree"),
            };
            match result {
                Ok(node) => Ok((
                    ensure_fat_node(&mut mount.entries, &node)?,
                    from_fat_kind(node.kind),
                    node.size,
                )),
                Err(error) => Err(mount.fail(map_fat(error))),
            }
        }
        Kind::Ext2 => {
            let parent = ext2_directory(mount, dir)?;
            let name = ext2_name(name)?;
            let result = match &mut mount.fs {
                Fs::Ext2(ext2) => ext2.lookup(parent, name),
                Fs::Fat(_) => unreachable!("mount kind and file system disagree"),
            };
            match result {
                Ok(node) => Ok((
                    ensure_ext2_node(&mut mount.entries, &node)?,
                    from_ext2_kind(node.kind),
                    node.size as u64,
                )),
                Err(error) => Err(mount.fail(map_ext2(error))),
            }
        }
    }
}

/// Create `name` (file or directory) in directory `dir`.
///
/// The node table is checked first: a fresh directory entry that cannot be named
/// here would be an unreachable orphan on the volume, so capacity is a `Quota`
/// *before* any mutation. Should the entry still fail to register afterwards, the
/// file system create is rolled back for the same reason.
pub fn create(
    index: u8,
    dir: u16,
    name: &[u8],
    kind: NodeKind,
) -> Result<(u16, NodeKind, u64), VfsError> {
    let mount = mount_ref(index)?;
    mount.check()?;
    if !entry_slot_free(&mount.entries) {
        return Err(VfsError::Quota);
    }
    match mount.kind {
        Kind::Fat32 => {
            let parent = fat_directory(mount, dir)?;
            let name = fat_name(name)?;
            let created = match &mut mount.fs {
                Fs::Fat(fat) => fat.create(&parent, name, to_fat_kind(kind)),
                Fs::Ext2(_) => unreachable!("mount kind and file system disagree"),
            };
            let node = match created {
                Ok(node) => node,
                Err(error) => return Err(mount.fail(map_fat(error))),
            };
            match ensure_fat_node(&mut mount.entries, &node) {
                Ok(id) => Ok((id, from_fat_kind(node.kind), node.size)),
                Err(error) => {
                    let undone = match &mut mount.fs {
                        Fs::Fat(fat) => fat.unlink(&node).map_err(map_fat),
                        Fs::Ext2(_) => unreachable!("mount kind and file system disagree"),
                    };
                    match undone {
                        Ok(()) => Err(error),
                        Err(_) => Err(mount.fail(VfsError::Corrupt)),
                    }
                }
            }
        }
        Kind::Ext2 => {
            let parent = ext2_directory(mount, dir)?;
            let name = ext2_name(name)?;
            let created = match &mut mount.fs {
                Fs::Ext2(ext2) => ext2.create(parent, name, to_ext2_kind(kind)),
                Fs::Fat(_) => unreachable!("mount kind and file system disagree"),
            };
            let node = match created {
                Ok(node) => node,
                Err(error) => return Err(mount.fail(map_ext2(error))),
            };
            match ensure_ext2_node(&mut mount.entries, &node) {
                Ok(id) => Ok((id, from_ext2_kind(node.kind), node.size as u64)),
                Err(error) => {
                    let undone = match &mut mount.fs {
                        Fs::Ext2(ext2) => ext2.unlink(parent, name).map_err(map_ext2),
                        Fs::Fat(_) => unreachable!("mount kind and file system disagree"),
                    };
                    match undone {
                        Ok(()) => Err(error),
                        Err(_) => Err(mount.fail(VfsError::Corrupt)),
                    }
                }
            }
        }
    }
}

/// Remove entry `name` of node `node` from directory `dir`.
///
/// `node` identifies the VNode being removed, which is what keeps the cache key
/// valid until the caller invalidates it. Directories may be removed only while
/// empty: the file systems report that themselves and it maps to
/// [`VfsError::NotEmpty`].
pub fn unlink(index: u8, dir: u16, node: u16, name: &[u8]) -> Result<CacheKey, VfsError> {
    let mount = mount_ref(index)?;
    mount.check()?;
    let entry = entry_of(mount, node)?;
    match mount.kind {
        Kind::Fat32 => {
            let _parent = fat_directory(mount, dir)?;
            let _ = fat_name(name)?;
            let fat_node = fat32::FatNode {
                cookie: entry.fat_cookie,
                parent: entry.fat_parent,
                kind: to_fat_kind(entry.kind),
                size: entry.size,
            };
            let result = match &mut mount.fs {
                Fs::Fat(fat) => fat.unlink(&fat_node),
                Fs::Ext2(_) => unreachable!("mount kind and file system disagree"),
            };
            if let Err(error) = result {
                return Err(mount.fail(map_fat(error)));
            }
        }
        Kind::Ext2 => {
            let parent = ext2_directory(mount, dir)?;
            let name = ext2_name(name)?;
            let result = match &mut mount.fs {
                Fs::Ext2(ext2) => ext2.unlink(parent, name),
                Fs::Fat(_) => unreachable!("mount kind and file system disagree"),
            };
            if let Err(error) = result {
                return Err(mount.fail(map_ext2(error)));
            }
        }
    }
    mount.entries[node as usize] = ENTRY_EMPTY;
    Ok(cache_key(index, node))
}

/// Move node `node` from directory `dir`/`old_name` to
/// `new_dir`/`new_name`.
///
/// The stable disk-node id (and therefore the page-cache key) survives; for FAT
/// only the short-entry cookie is updated. Neither file system overwrites an
/// existing target: FAT answers `AlreadyExists`, ext2 `Exists`.
pub fn rename(
    index: u8,
    dir: u16,
    node: u16,
    old_name: &[u8],
    new_dir: u16,
    new_name: &[u8],
) -> Result<(), VfsError> {
    let mount = mount_ref(index)?;
    mount.check()?;
    let entry = entry_of(mount, node)?;
    match mount.kind {
        Kind::Fat32 => {
            let old_dir = fat_directory(mount, dir)?;
            let new_dir = fat_directory(mount, new_dir)?;
            let _ = fat_name(old_name)?;
            let new_name = fat_name(new_name)?;
            let mut fat_node = fat32::FatNode {
                cookie: entry.fat_cookie,
                parent: entry.fat_parent,
                kind: to_fat_kind(entry.kind),
                size: entry.size,
            };
            let result = match &mut mount.fs {
                Fs::Fat(fat) => fat.rename(&mut fat_node, &new_dir, new_name),
                Fs::Ext2(_) => unreachable!("mount kind and file system disagree"),
            };
            let _ = old_dir;
            if let Err(error) = result {
                return Err(mount.fail(map_fat(error)));
            }
            // The directory-entry cookie moved; the stable disk-node id did not.
            let stored = &mut mount.entries[node as usize];
            stored.fat_cookie = fat_node.cookie;
            stored.fat_parent = fat_node.parent;
            stored.size = fat_node.size;
            Ok(())
        }
        Kind::Ext2 => {
            let old_dir = ext2_directory(mount, dir)?;
            let new_dir = ext2_directory(mount, new_dir)?;
            let old_name = ext2_name(old_name)?;
            let new_name = ext2_name(new_name)?;
            let result = match &mut mount.fs {
                Fs::Ext2(ext2) => ext2.rename(old_dir, old_name, new_dir, new_name),
                Fs::Fat(_) => unreachable!("mount kind and file system disagree"),
            };
            if let Err(error) = result {
                return Err(mount.fail(map_ext2(error)));
            }
            Ok(())
        }
    }
}
/// Change the size of a disk file.
pub fn truncate(index: u8, node: u16, size: u64) -> Result<(), VfsError> {
    let mount = mount_ref(index)?;
    mount.check()?;
    let entry = *mount.entries.get(node as usize).ok_or(VfsError::NotFound)?;
    if !entry.used {
        return Err(VfsError::NotFound);
    }
    match mount.kind {
        Kind::Fat32 => {
            let mut fat_node = fat32::FatNode {
                cookie: entry.fat_cookie,
                parent: entry.fat_parent,
                kind: to_fat_kind(entry.kind),
                size: entry.size,
            };
            let result = match &mut mount.fs {
                Fs::Fat(fat) => fat.truncate(&mut fat_node, size),
                Fs::Ext2(_) => unreachable!("mount kind and file system disagree"),
            };
            if let Err(error) = result {
                let mapped = map_fat(error);
                return Err(mount.fail(mapped));
            }
            mount.entries[node as usize].size = fat_node.size;
            Ok(())
        }
        Kind::Ext2 => {
            let result = match &mut mount.fs {
                Fs::Ext2(ext2) => ext2.truncate(entry.ino, size),
                Fs::Fat(_) => unreachable!("mount kind and file system disagree"),
            };
            if let Err(error) = result {
                let mapped = map_ext2(error);
                return Err(mount.fail(mapped));
            }
            mount.entries[node as usize].size = size;
            Ok(())
        }
    }
}

/// Fill `out` with the cache page at `page_start` of a disk file.
///
/// The page cache zeroes the frame first, so this only has to copy the bytes
/// that exist; the tail past end-of-file stays zero.
pub fn read_page(index: u8, node: u16, page_start: u64, out: &mut [u8]) -> Result<(), VfsError> {
    let mount = mount_ref(index)?;
    mount.check()?;
    let entry = *mount.entries.get(node as usize).ok_or(VfsError::NotFound)?;
    if !entry.used {
        return Err(VfsError::NotFound);
    }
    let count = remaining(entry.size, page_start, out.len() as u64) as usize;
    if count == 0 {
        return Ok(());
    }
    let target = &mut out[..count];
    match mount.kind {
        Kind::Fat32 => {
            let fat_node = fat32::FatNode {
                cookie: entry.fat_cookie,
                parent: entry.fat_parent,
                kind: to_fat_kind(entry.kind),
                size: entry.size,
            };
            let result = match &mut mount.fs {
                Fs::Fat(fat) => fat.read(&fat_node, page_start, target),
                Fs::Ext2(_) => unreachable!("mount kind and file system disagree"),
            };
            match result {
                Ok(read) if read == count => Ok(()),
                Ok(_) => Err(VfsError::Corrupt),
                Err(error) => {
                    let mapped = map_fat(error);
                    Err(mount.fail(mapped))
                }
            }
        }
        Kind::Ext2 => {
            let result = match &mut mount.fs {
                Fs::Ext2(ext2) => ext2.read(entry.ino, page_start, target),
                Fs::Fat(_) => unreachable!("mount kind and file system disagree"),
            };
            match result {
                Ok(read) if read == count => Ok(()),
                Ok(_) => Err(VfsError::Corrupt),
                Err(error) => {
                    let mapped = map_ext2(error);
                    Err(mount.fail(mapped))
                }
            }
        }
    }
}

/// Push one dirty cache page (the full 4 KiB frame, trimmed to the file size)
/// into the file system. Does not flush the device; see [`sync`].
pub fn writeback(
    index: u8,
    node: u16,
    page_start: u64,
    data: &[u8],
    size: u64,
) -> Result<(), VfsError> {
    let mount = mount_ref(index)?;
    mount.check()?;
    let entry = *mount.entries.get(node as usize).ok_or(VfsError::NotFound)?;
    if !entry.used {
        return Err(VfsError::NotFound);
    }
    // `size` is the VFS's authoritative in-memory size (it may be ahead of the
    // on-disk entry until this very write lands); the file system itself must
    // still be driven from its own recorded size, hence `entry.size` below.
    let count = remaining(size, page_start, data.len() as u64) as usize;
    if count == 0 {
        // A dirty page wholly beyond end-of-file cannot be flushed without
        // extending the file; treat it as nothing to write.
        return Ok(());
    }
    let source = &data[..count];
    match mount.kind {
        Kind::Fat32 => {
            let mut fat_node = fat32::FatNode {
                cookie: entry.fat_cookie,
                parent: entry.fat_parent,
                kind: to_fat_kind(entry.kind),
                size: entry.size,
            };
            let result = match &mut mount.fs {
                Fs::Fat(fat) => fat.write(&mut fat_node, page_start, source),
                Fs::Ext2(_) => unreachable!("mount kind and file system disagree"),
            };
            match result {
                Ok(written) if written == count => {
                    let stored = &mut mount.entries[node as usize];
                    stored.size = fat_node.size;
                    stored.fat_cookie = fat_node.cookie;
                    stored.fat_parent = fat_node.parent;
                    Ok(())
                }
                Ok(_) => Err(VfsError::Corrupt),
                Err(error) => {
                    let mapped = map_fat(error);
                    Err(mount.fail(mapped))
                }
            }
        }
        Kind::Ext2 => {
            let result = match &mut mount.fs {
                Fs::Ext2(ext2) => ext2.write(entry.ino, page_start, source),
                Fs::Fat(_) => unreachable!("mount kind and file system disagree"),
            };
            match result {
                Ok(written) if written == count => {
                    mount.entries[node as usize].size = mount.entries[node as usize]
                        .size
                        .max(page_start + count as u64);
                    Ok(())
                }
                Ok(_) => Err(VfsError::Corrupt),
                Err(error) => {
                    let mapped = map_ext2(error);
                    Err(mount.fail(mapped))
                }
            }
        }
    }
}

/// Flush the mount's file-system metadata and the block device.
pub fn sync(index: u8) -> Result<(), VfsError> {
    let mount = mount_ref(index)?;
    mount.check()?;
    let result = match &mut mount.fs {
        Fs::Fat(fat) => fat.sync().map_err(map_fat),
        Fs::Ext2(ext2) => ext2.sync().map_err(map_ext2),
    };
    match result {
        Ok(()) => Ok(()),
        Err(mapped) => Err(mount.fail(mapped)),
    }
}

/// Update the cached size after the VFS extended the file in the cache.
pub fn set_size(index: u8, node: u16, size: u64) -> Result<(), VfsError> {
    let mount = mount_ref(index)?;
    mount.check()?;
    let slot = mount
        .entries
        .get_mut(node as usize)
        .ok_or(VfsError::NotFound)?;
    if !slot.used {
        return Err(VfsError::NotFound);
    }
    slot.size = size;
    Ok(())
}

/// Bytes of the page starting at `page_start` that lie inside the file.
fn remaining(size: u64, page_start: u64, wanted: u64) -> u64 {
    if page_start >= size {
        return 0;
    }
    (size - page_start).min(wanted)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fat_83_names_are_validated_explicitly() {
        assert_eq!(fat_name(b"M5STATE.BIN").unwrap(), "M5STATE.BIN");
        assert_eq!(fat_name(b""), Err(VfsError::NameTooLong));
        assert_eq!(fat_name(b"a/b"), Err(VfsError::NotSupported));
        // Case is not rejected here: the FS layer upper-cases 8.3 names itself.
        assert_eq!(fat_name(b"m5state.bin"), Ok("m5state.bin"));
        assert_eq!(fat_name(b"ABCDEFGH.1234"), Err(VfsError::NameTooLong));
        assert_eq!(fat_name(&[0xFF, 0xFE]), Err(VfsError::NotSupported));
    }

    #[test]
    fn ext2_names_are_validated_explicitly() {
        assert_eq!(ext2_name(b"m5state").unwrap(), b"m5state");
        assert_eq!(ext2_name(b""), Err(VfsError::NameTooLong));
        assert_eq!(ext2_name(b"a/b"), Err(VfsError::BadPath));
        let long = [b'a'; 32];
        assert_eq!(ext2_name(&long), Err(VfsError::NameTooLong));
    }

    #[test]
    fn remaining_trims_to_the_file_size() {
        assert_eq!(remaining(0, 0, 4096), 0);
        assert_eq!(remaining(100, 0, 4096), 100);
        assert_eq!(remaining(100, 96, 4096), 4);
        assert_eq!(remaining(8192, 8192, 4096), 0);
    }

    #[test]
    fn kind_names_match_the_mount_points() {
        assert_eq!(Kind::Fat32.mount_name(), b"fat");
        assert_eq!(Kind::Ext2.mount_name(), b"ext2");
    }

    #[test]
    fn cache_keys_separate_the_mounts() {
        assert_eq!(cache_key(0, 3), CacheKey::new(FS_DISK_BASE, 3));
        assert_eq!(cache_key(1, 3), CacheKey::new(FS_DISK_BASE + 1, 3));
        assert_ne!(cache_key(0, 3), cache_key(1, 3));
    }

    fn formatted_device(kind: Kind) -> Device {
        match kind {
            Kind::Fat32 => {
                let mut device = block::test_support::MemDisk::new(131_072, 512);
                {
                    let formatted = fat32::format(&mut device, &fat32::FormatOptions::default())
                        .expect("format FAT32 volume");
                    drop(formatted);
                }
                device
            }
            Kind::Ext2 => {
                let mut device = block::test_support::MemDisk::new(65_536, 512);
                ext2::format(&mut device).expect("format ext2 volume");
                device
            }
        }
    }

    #[test]
    fn mounting_initialises_the_static_slot_in_place() {
        let _guard = crate::vfs::test_lock();
        reset();
        let index = mount(Kind::Fat32, formatted_device(Kind::Fat32)).expect("mount FAT32");
        assert!(is_mounted(index));
        {
            let mounted = mount_ref(index).expect("live mount");
            assert_eq!(mounted.kind, Kind::Fat32);
            assert!(mounted.sticky.is_none());
            assert_eq!(mounted.entries.iter().filter(|entry| entry.used).count(), 0);
        }
        let second = mount(Kind::Ext2, formatted_device(Kind::Ext2)).expect("mount ext2");
        assert!(is_mounted(second));
        assert_ne!(index, second);
        reset();
        assert!(!is_mounted(index));
        assert!(!is_mounted(second));
        // Remounting after a reset proves the freed slot is initialised from a
        // clean state instead of reusing stale node entries.
        let again = mount(Kind::Fat32, formatted_device(Kind::Fat32)).expect("remount FAT32");
        assert!(is_mounted(again));
        let entries = mount_ref(again).expect("remount live");
        assert_eq!(entries.entries.iter().filter(|entry| entry.used).count(), 0);
        reset();
    }

    #[test]
    fn unmount_hands_the_device_back_and_frees_the_slot() {
        let _guard = crate::vfs::test_lock();
        reset();
        let index = mount(Kind::Ext2, formatted_device(Kind::Ext2)).expect("mount ext2");
        let device = unmount(index).expect("device back");
        assert!(!is_mounted(index));
        drop(device);
        let again = mount(Kind::Ext2, formatted_device(Kind::Ext2)).expect("remount ext2");
        assert_eq!(again, index);
        reset();
    }

    #[test]
    fn clear_sticky_returns_and_forgets_the_media_error() {
        let _guard = crate::vfs::test_lock();
        reset();
        let index = mount(Kind::Fat32, formatted_device(Kind::Fat32)).expect("mount FAT32");
        assert_eq!(clear_sticky(Kind::Fat32), None);
        mount_ref(index).expect("live mount").fail(VfsError::Io);
        assert_eq!(
            mount_ref(index).expect("live mount").check(),
            Err(VfsError::Io)
        );
        assert_eq!(clear_sticky(Kind::Ext2), None);
        assert_eq!(clear_sticky(Kind::Fat32), Some(VfsError::Io));
        assert_eq!(mount_ref(index).expect("live mount").check(), Ok(()));
        assert_eq!(clear_sticky(Kind::Fat32), None);
        reset();
    }
}
