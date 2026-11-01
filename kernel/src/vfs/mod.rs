//! M5a virtual file system: ramfs, the read-only initramfs view and the open-file
//! and node tables.
//!
//! Scope of this stage is deliberately small and entirely in-memory: a fixed
//! 64-node table, 16 open file descriptions, one ramfs mount at `/` and one
//! read-only boot mount at `/boot` holding the boot payloads (`init`, `child`,
//! `worker`, `gfx`, `net`, `linux`) that `bootmod` mapped. There is no disk, no
//! journal, no symbolic links, no path cache and no snapshotting; VFS 1.0
//! semantics that need those arrive later.
//!
//! Concurrency contract: every entry point below runs on a single CPU with
//! interrupts disabled (the same contract `pagecache` documents). Nothing here
//! sleeps, spins or allocates from the heap, so the VFS can be called from the
//! syscall path without a lock; host tests serialise themselves with
//! [`test_lock`] because they share the module's `static` tables.
//!
//! The data plane belongs to `pagecache`: ramfs files keep their bytes there and
//! read holes as zero, while boot payloads are streamed page by page out of the
//! boot module window by `initramfs`. Locking (`lock`) and directory
//! notifications (`notify`) are separate modules that reuse the ids defined here.

pub mod lock;
pub mod notify;
pub mod pagecache;
pub mod types;

pub(crate) mod disk;
pub(crate) mod initramfs;
pub(crate) mod open;
pub(crate) mod path;
pub(crate) mod pseudo;
pub(crate) mod ramfs;
pub(crate) mod vnode;

pub use types::{
    DirEntry, MAX_COMPONENTS, MAX_NAME, MAX_OPEN, MAX_PATH, MAX_VNODES, MAX_XATTR_NAME,
    MAX_XATTR_VALUE, MAX_XATTRS, NodeKind, NodeStat, OpenId, OpenOptions, PAGE, SeekFrom, VNodeId,
    VfsError,
};
// Lock-domain names and the `F_GETLK` result are part of the public lock API, so
// callers name `LockDomain`/`LockKind`/`LockConflict` without reaching into the
// module path (the module itself stays public for the lower-level helpers).
pub use lock::{LockConflict, LockDomain, LockKind};

// Short aliases for the bodies below; the public re-export above already brings
// the capacity constants and `VfsError` into scope.
use pagecache::CacheKey;
use path::Path;
use types::{NodeKind as Kind, NodeStat as Stat, OpenId as Open, VNodeId as Id};
use vnode::{Backing, Table};

/// One disk mount registered in the namespace (M5b): its kind and the VNode of
/// its mount point (a plain ramfs directory holding the disk's children).
#[derive(Clone, Copy)]
struct MountSlot {
    used: bool,
    kind: disk::Kind,
    root: Id,
}

impl MountSlot {
    const EMPTY: MountSlot = MountSlot {
        used: false,
        // Only read while `used`; the concrete kind of a free slot is irrelevant.
        kind: disk::Kind::Fat32,
        root: Id::NONE,
    };
}

/// The one mount table: root ramfs, the read-only boot mount and (M5b) up to two
/// disk mounts at `/fat` and `/ext2`.
struct State {
    ready: bool,
    root: Id,
    boot: Id,
    table: Table,
    opens: open::Table,
    mounts: [MountSlot; disk::MAX_MOUNTS],
}

impl State {
    /// All-zero value for the static; `ready` stays false until `init` runs.
    const EMPTY: State = State {
        ready: false,
        root: Id::NONE,
        boot: Id::NONE,
        table: Table::new(),
        opens: open::Table::new(),
        mounts: [MountSlot::EMPTY; disk::MAX_MOUNTS],
    };

    /// Index of the disk mount whose mount point is called `name`, if any.
    fn mount_index(&self, name: &[u8]) -> Option<u8> {
        for (index, slot) in self.mounts.iter().enumerate() {
            if !slot.used {
                continue;
            }
            if let Ok(node) = self.table.get(slot.root) {
                if node.matches(name) {
                    return Some(index as u8);
                }
            }
        }
        None
    }

    /// Disk mount whose mount-point VNode is `id`.
    fn mount_of(&self, id: Id) -> Option<(u8, disk::Kind)> {
        for (index, slot) in self.mounts.iter().enumerate() {
            if slot.used && slot.root == id {
                return Some((index as u8, slot.kind));
            }
        }
        None
    }

    /// True while a mount of `kind` is registered.
    fn has_mount(&self, kind: disk::Kind) -> bool {
        self.mounts
            .iter()
            .any(|slot| slot.used && slot.kind == kind)
    }
}

static mut STATE: State = State::EMPTY;

/// Single static mutex that serialises host tests touching [`STATE`] and the
/// page-cache/lock/notify statics. Not compiled for the bare-metal target.
#[cfg(test)]
pub(crate) fn test_lock() -> std::sync::MutexGuard<'static, ()> {
    static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    match LOCK.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

#[cfg(test)]
pub(crate) fn test_reset() {
    // Tests hold `test_lock`, so nothing else touches the tables concurrently.
    neutral_reset();
}

fn state() -> &'static mut State {
    // SAFETY: single-CPU, IF=0 contract. `STATE` is a `static mut` and every
    // caller runs on the boot path (or under the host test lock), never with
    // interrupts enabled.
    unsafe { &mut *core::ptr::addr_of_mut!(STATE) }
}

fn require_ready() -> Result<&'static mut State, VfsError> {
    let state = state();
    if !state.ready {
        return Err(VfsError::NotSupported);
    }
    Ok(state)
}

/// Initialise the VFS on top of `bootmod` and the page cache.
///
/// Must be called once, after `bootmod::init` succeeded and before any other VFS
/// entry point. It builds `/`, `/boot` and the six boot payloads (`/boot/init`,
/// `/boot/child`, `/boot/worker`, `/boot/gfx`, `/boot/net`, `/boot/linux`),
/// wires the
/// initramfs reader to the boot module window, and runs the real closure
/// self-check (ramfs + page cache + boot payload + locks + notifications). Any
/// failure is returned to the caller, which owns the stage marker; nothing is
/// printed here.
pub fn init() -> Result<(), VfsError> {
    if !crate::bootmod::is_ready() {
        return Err(VfsError::NotSupported);
    }
    if state().ready {
        return Err(VfsError::Busy);
    }
    let init_size = crate::bootmod::find(crate::bootmod::INIT_MODULE)
        .ok_or(VfsError::NotFound)?
        .size();
    let child_size = crate::bootmod::find(crate::bootmod::CHILD_MODULE)
        .ok_or(VfsError::NotFound)?
        .size();
    let worker_size = crate::bootmod::find(crate::bootmod::WORKER_MODULE)
        .ok_or(VfsError::NotFound)?
        .size();
    let gfx_size = crate::bootmod::find(crate::bootmod::GFX_MODULE)
        .ok_or(VfsError::NotFound)?
        .size();
    let net_size = crate::bootmod::find(crate::bootmod::NET_MODULE)
        .ok_or(VfsError::NotFound)?
        .size();
    let linux_size = crate::bootmod::find(crate::bootmod::LINUX_MODULE)
        .ok_or(VfsError::NotFound)?
        .size();
    // Build straight into the static: `State` carries the 64-node table and the
    // open table, which must never be copied through the 16 KiB boot stack.
    build(
        state(),
        init_size,
        child_size,
        worker_size,
        gfx_size,
        net_size,
        linux_size,
    )?;
    state().ready = true;
    initramfs::install_reader(initramfs::bootmod_reader);
    match selftest() {
        Ok(()) => Ok(()),
        Err(error) => {
            neutral_reset();
            Err(error)
        }
    }
}

/// Clear the published state in place (failed `init`, and host test helpers).
fn neutral_reset() {
    let state = state();
    state.ready = false;
    state.root = Id::NONE;
    state.boot = Id::NONE;
    state.table.clear();
    state.opens.clear();
    for slot in state.mounts.iter_mut() {
        *slot = MountSlot::EMPTY;
    }
    disk::reset();
}

/// Populate the one static in place; never returns or copies a [`State`].
fn build(
    state: &mut State,
    init_size: u64,
    child_size: u64,
    worker_size: u64,
    gfx_size: u64,
    net_size: u64,
    linux_size: u64,
) -> Result<(), VfsError> {
    pagecache::init();
    lock::clear();
    notify::clear();
    state.ready = false;
    state.root = Id::NONE;
    state.boot = Id::NONE;
    state.table.clear();
    state.opens.clear();
    for slot in state.mounts.iter_mut() {
        *slot = MountSlot::EMPTY;
    }
    disk::reset();
    let root = state
        .table
        .alloc(Kind::Directory, Id::NONE, b"", Backing::Ram)?;
    let boot = state
        .table
        .alloc(Kind::Directory, root, b"boot", Backing::Ram)?;
    ramfs::create_boot_node(
        &mut state.table,
        boot,
        crate::bootmod::INIT_MODULE,
        init_size,
    )?;
    ramfs::create_boot_node(
        &mut state.table,
        boot,
        crate::bootmod::CHILD_MODULE,
        child_size,
    )?;
    ramfs::create_boot_node(
        &mut state.table,
        boot,
        crate::bootmod::WORKER_MODULE,
        worker_size,
    )?;
    ramfs::create_boot_node(&mut state.table, boot, crate::bootmod::GFX_MODULE, gfx_size)?;
    ramfs::create_boot_node(&mut state.table, boot, crate::bootmod::NET_MODULE, net_size)?;
    ramfs::create_boot_node(
        &mut state.table,
        boot,
        crate::bootmod::LINUX_MODULE,
        linux_size,
    )?;
    // M8h: the generated /proc and /dev namespace is part of every boot.
    pseudo::install(&mut state.table, root)?;
    state.root = root;
    state.boot = boot;
    Ok(())
}

/// Whether [`init`] completed.
pub fn is_ready() -> bool {
    state().ready
}

/// Root VNode id (valid after [`init`]).
pub fn root() -> Result<Id, VfsError> {
    Ok(require_ready()?.root)
}

/// Boot mount point VNode id (valid after [`init`]).
pub fn boot_mount() -> Result<Id, VfsError> {
    Ok(require_ready()?.boot)
}

/// Drop the cached pages of an immutable boot payload (M6a2).
///
/// A boot payload lives in the loader's read-only window and never changes, so
/// its cached frames are pure cache: once `image` has staged the file it needs
/// (read/ELF load done), the pages can be handed back instead of pinning the
/// page cache for the rest of the boot. `init` + `child` together are larger
/// than the 512-page cache, which is why the staging path must be able to
/// release them at all.
///
/// Only a file that is a **direct child of the boot mount** and backed by the
/// immutable boot payload is accepted: a ramfs or disk file is writable, so its
/// cached pages may hold the only copy of unsynced data and are refused with
/// [`VfsError::NotSupported`]. A page still pinned by an eager mapping is
/// reported as [`VfsError::Busy`], exactly like every other invalidation path,
/// and must be unpinned by its owner first.
///
/// Returns the number of frames the call actually released. No resident page is
/// not a failure (`Ok(0)`), which makes repeated calls and the best-effort
/// "release whatever the previous staging left behind" call safe; a `/boot`
/// name that is not in the namespace at all is equally `Ok(0)` because no frame
/// can be cached under a key that no node owns.
pub fn release_boot_pages(raw_path: &[u8]) -> Result<usize, VfsError> {
    let state = require_ready()?;
    let boot = state.boot;
    let id = match resolve(state, raw_path) {
        Ok(id) => id,
        Err(error) => {
            // Only a missing boot payload is a no-op: every other resolution
            // failure stays visible to the caller (a path outside `/boot` must
            // not silently look released).
            if error == VfsError::NotFound && is_boot_payload_path(state, raw_path) {
                return Ok(0);
            }
            return Err(error);
        }
    };
    let key = {
        let node = state.table.get(id)?;
        if node.kind != Kind::File {
            return Err(VfsError::IsDirectory);
        }
        // The boot mount is a fixed ramfs directory whose only children are the
        // loader-provided payloads; checking the parent rejects a `Backing::Boot`
        // node that some future code might attach elsewhere, and `read_only` is
        // the invariant that makes its pages safe to drop.
        let immutable_payload =
            node.read_only && node.parent == boot && matches!(node.backing, Backing::Boot { .. });
        if !immutable_payload {
            return Err(VfsError::NotSupported);
        }
        node.cache_key(id)
    };
    let resident = pagecache::resident_pages(key);
    pagecache::invalidate(key)?;
    Ok(resident)
}

/// Whether `raw_path` names exactly one entry of the boot mount (`/boot/<name>`).
fn is_boot_payload_path(state: &State, raw_path: &[u8]) -> bool {
    let parsed = scratch_path();
    if path::parse_into(raw_path, parsed).is_err() || parsed.len() != 2 {
        return false;
    }
    let Some(first) = parsed.name(0) else {
        return false;
    };
    match state.table.get(state.boot) {
        Ok(boot) => boot.matches(first),
        Err(_) => false,
    }
}

/// Scratch buffer holding the parsed path of the current VFS call.
///
/// A [`Path`] is ~1 KiB. The M5b disk chain already runs through the file-system
/// library, virtqueue and `submit_inner` frames on the 16 KiB boot stack, so an
/// entry point must not hand a `Path` (or a second one) to its callees: it parses
/// once here and passes `&Path` down.
///
/// Ownership: there is one CPU; the VFS is only entered from kernel context and
/// never from an interrupt handler; kernel code is not preempted; and no public
/// entry point calls another one (each parses once and forwards `&Path`), so this
/// buffer is never aliased by a nested parse. Host tests serialise on
/// [`test_lock`].
static mut PATH_SCRATCH: Path = Path::root();

/// Borrow the parsed-path scratch described on [`PATH_SCRATCH`].
fn scratch_path() -> &'static mut Path {
    // SAFETY: see the ownership note on PATH_SCRATCH. `Path::root` is a const
    // value, so the static starts empty and every use parses before it reads.
    unsafe { &mut *core::ptr::addr_of_mut!(PATH_SCRATCH) }
}

fn resolve(state: &mut State, raw_path: &[u8]) -> Result<Id, VfsError> {
    let parsed = scratch_path();
    path::parse_into(raw_path, parsed)?;
    resolve_parsed(state, parsed)
}

/// Top-level directories that are a read-only view of the ext2 volume (M10a).
///
/// The dynamic Linux root keeps the musl loader and busybox on the ext2 volume
/// (`/ext2/lib/ld-musl-x86_64.so.1`, `/ext2/bin/busybox`), while a Linux program
/// opens them at the absolute paths it was built for. Resolving those two names
/// through the mount keeps every path-based entry point (open, read, readdir,
/// stat, ...) consistent without a symlink, a second mount, or per-syscall path
/// rewriting. Only resolution is aliased: `/ext2/...` keeps working unchanged.
const ALIAS_DIRS: [&[u8]; 2] = [b"bin", b"lib"];
/// Mount point whose root directory backs [`ALIAS_DIRS`].
const ALIAS_MOUNT: &[u8] = b"ext2";

/// True when `raw_path` names `/bin` or `/lib`, or a child of one.
///
/// The alias is read-only: it is a second name for data that lives on the ext2
/// volume, so creating, renaming, removing or truncating through it is refused
/// instead of mutating the mounted volume under a name the program did not use.
fn alias_top_level(raw_path: &[u8]) -> bool {
    let rest = match raw_path.split_first() {
        Some((b'/', rest)) => rest,
        _ => return false,
    };
    let name_len = rest
        .iter()
        .position(|byte| *byte == b'/')
        .unwrap_or(rest.len());
    let name = &rest[..name_len];
    ALIAS_DIRS.iter().any(|alias| *alias == name)
}

/// Mount index backing `first` when it names an alias directory.
///
/// Returns `None` for every other name, and also when the ext2 volume is not
/// mounted: the alias must never invent a directory.
fn alias_mount(state: &State, first: &[u8]) -> Option<u8> {
    if !ALIAS_DIRS.iter().any(|alias| *alias == first) {
        return None;
    }
    state.mount_index(ALIAS_MOUNT)
}

/// Resolve an already parsed path, materialising disk nodes on first sight.
///
/// Disk paths (`/fat/...`, `/ext2/...`) are walked one component at a time on
/// the mounted file system and every directory on the way is materialised as a
/// VNode, so the child can name it as `parent`. A missing component fails with
/// [`VfsError::NotFound`]; there is no cross-mount traversal.
///
/// `/bin/...` and `/lib/...` are a read-only namespace alias of the ext2
/// volume's same-named directories (M10a); see [`ALIAS_DIRS`]. The alias starts
/// the disk walk at component 0, so `/bin` itself resolves to the ext2 `/bin`
/// directory.
fn resolve_parsed(state: &mut State, parsed: &Path) -> Result<Id, VfsError> {
    if parsed.name(0).is_none() {
        return Ok(state.root);
    }
    let first = parsed.name(0).ok_or(VfsError::BadPath)?;
    if let Some(index) = state.mount_index(first) {
        return resolve_disk(state, index, parsed, 1);
    }
    if let Some(index) = alias_mount(state, first) {
        return resolve_disk(state, index, parsed, 0);
    }
    ramfs::lookup(&state.table, state.root, parsed)
}

/// Walk `parsed[from..]` on the mounted file system of `index`.
///
/// Every component is looked up on the volume and materialised as a VNode, so
/// each one can name the next as its parent. The mount root itself is
/// [`disk::ROOT_NODE`]; `from` skips the mount-point component (1) or starts at
/// the alias directory itself (0).
fn resolve_disk(state: &mut State, index: u8, parsed: &Path, from: usize) -> Result<Id, VfsError> {
    let mut parent = state.mounts[index as usize].root;
    let mut token = disk::ROOT_NODE;
    for position in from..parsed.len() {
        let name = parsed.name(position).ok_or(VfsError::BadPath)?;
        let (node, kind, size) = disk::lookup(index, token, name)?;
        parent = materialise_disk(state, index, node, kind, size, name, parent)?;
        token = node;
    }
    Ok(parent)
}

/// VNode of a disk entry, reusing the existing one when it is already
/// materialised (so the page-cache key and open descriptions stay stable).
fn materialise_disk(
    state: &mut State,
    mount: u8,
    node: u16,
    kind: Kind,
    size: u64,
    name: &[u8],
    parent: Id,
) -> Result<Id, VfsError> {
    let backing = Backing::Disk { mount, node };
    if let Some(id) = state.table.find_backing(backing) {
        // Keep the node's size: dirty pages may be newer than the on-disk
        // directory entry, which is only updated when the write is flushed.
        let stored = state.table.get_mut(id)?;
        stored.kind = kind;
        stored.read_only = false;
        return Ok(id);
    }
    let id = state.table.alloc(kind, parent, name, backing)?;
    let stored = state.table.get_mut(id)?;
    stored.size = size;
    stored.read_only = false;
    Ok(id)
}

/// Operations that name a child entry (create, mkdir, unlink, rmdir, rename and
/// `open` with `create`) reject a trailing slash: `/x/` names the directory `x`,
/// not the entry `x`. Reads keep collapsing it, as before.
fn reject_trailing_slash(raw: &[u8]) -> Result<(), VfsError> {
    if raw.len() > 1 && raw[raw.len() - 1] == b'/' {
        return Err(VfsError::BadPath);
    }
    Ok(())
}

/// Refuse a creation that could not be materialised.
///
/// The disk layer writes the directory entry and only then needs a VNode; with a
/// fixed VNode table the only safe order is to check capacity before the file
/// system mutates anything (M5c1).
fn require_vnode_slot(state: &State) -> Result<(), VfsError> {
    if state.table.has_free_slot() {
        Ok(())
    } else {
        Err(VfsError::Quota)
    }
}

/// Create a regular file, routing the request to the disk mount when the parent
/// lives on one and to ramfs otherwise.
fn create_file_child(state: &mut State, raw_path: &[u8]) -> Result<Id, VfsError> {
    let parsed = scratch_path();
    path::parse_into(raw_path, parsed)?;
    create_file_from_parsed(state, parsed)
}

/// Create a regular file from an already parsed path.
///
/// `parsed` is split in place: on return it holds the parent path, so the caller
/// must not reuse it. Taking the parsed path (instead of raw bytes) keeps a second
/// ~1 KiB `Path` out of the create chain.
fn create_file_from_parsed(state: &mut State, parsed: &mut Path) -> Result<Id, VfsError> {
    let mut buffer = [0u8; MAX_NAME];
    let name_len = parsed.split_last(&mut buffer)?;
    let name = &buffer[..name_len];
    let parent = resolve_parsed(state, parsed)?;
    reject_read_only_parent(state, parent)?;
    if let Some((mount, dir)) = disk_parent(state, parent)? {
        require_vnode_slot(state)?;
        let (node, kind, size) = disk::create(mount, dir, name, Kind::File)?;
        let id = match materialise_disk(state, mount, node, kind, size, name, parent) {
            Ok(id) => id,
            Err(error) => {
                // Undo the fresh entry: a file system name with no VNode would be
                // unreachable, and M5c does not leave orphans behind.
                let _ = disk::unlink(mount, dir, node, name);
                return Err(error);
            }
        };
        notify::publish(parent, notify::NotifyKind::Created, name)?;
        return Ok(id);
    }
    let id = ramfs::create_file_at(&mut state.table, parent, name)?;
    notify::publish(parent, notify::NotifyKind::Created, name)?;
    Ok(id)
}

fn node_size(state: &State, id: Id) -> Result<u64, VfsError> {
    Ok(state.table.get(id)?.size)
}

/// Where the bytes of a file live while it is being read.
#[derive(Clone, Copy)]
enum ReadSource {
    /// ramfs: the page cache is the only copy (holes read zero).
    Ram,
    /// Read-only boot payload streamed through the initramfs reader.
    Boot { name: [u8; MAX_NAME], len: usize },
    /// M5b disk file, read page by page from its mounted file system.
    Disk { mount: u8, node: u16 },
}

fn read_node(
    state: &mut State,
    id: Id,
    owner: u32,
    offset: u64,
    out: &mut [u8],
) -> Result<usize, VfsError> {
    let (kind, backing, size, key) = {
        let node = state.table.get(id)?;
        (node.kind, node.backing, node.size, node.cache_key(id))
    };
    if kind == Kind::Directory {
        return Err(VfsError::IsDirectory);
    }
    // Generated (M8h) nodes never touch the page cache: their bytes are produced
    // on every read, so a proc file always reflects the current process state and
    // `/dev/zero` is not a zero-filled page cached for later readers.
    if let Backing::Generated { node } = backing {
        return pseudo::read(node, kind, owner, offset, out);
    }
    let source = match backing {
        Backing::Ram => ReadSource::Ram,
        Backing::Boot { name, name_len } => ReadSource::Boot {
            name,
            len: (name_len as usize).min(MAX_NAME),
        },
        Backing::Disk { mount, node: entry } => ReadSource::Disk { mount, node: entry },
        Backing::Generated { .. } => return Err(VfsError::NotSupported),
    };
    if out.is_empty() || offset >= size {
        return Ok(0);
    }
    match source {
        ReadSource::Ram => pagecache::read_with(key, size, offset, out, None),
        ReadSource::Boot { name, len } => {
            let mut backing =
                |page_start: u64, page: &mut [u8]| initramfs::fill(&name[..len], page_start, page);
            pagecache::read_with(key, size, offset, out, Some(&mut backing))
        }
        ReadSource::Disk { mount, node } => {
            let mut backing =
                |page_start: u64, page: &mut [u8]| disk::read_page(mount, node, page_start, page);
            pagecache::read_with(key, size, offset, out, Some(&mut backing))
        }
    }
}

/// Cache key and size of an open description's file, with the page-alignment
/// check every eager-mapping entry point shares.
///
/// The description must exist and point at a file: rights (`read`/`write`) are
/// enforced by the caller (the syscall layer) but the VFS never pins a directory.
/// `unpin` also uses this path, which is why the file size is returned instead of
/// being checked here: an unmapping must be able to release a page even after the
/// file shrank below that offset.
fn file_page_identity(
    state: &State,
    open: Open,
    offset: u64,
) -> Result<(CacheKey, Id, u64), VfsError> {
    let description = state.opens.get(open)?;
    let id = description.vnode;
    let node = state.table.get(id)?;
    if node.kind != Kind::File {
        return if node.kind == Kind::Directory {
            Err(VfsError::IsDirectory)
        } else {
            Err(VfsError::NotSupported)
        };
    }
    if matches!(node.backing, Backing::Generated { .. }) {
        return Err(VfsError::NotSupported);
    }
    if offset % PAGE != 0 {
        return Err(VfsError::BadOffset);
    }
    Ok((node.cache_key(id), id, node.size))
}

/// Everything one page of an open file needs: cache key, file size, page index
/// and where the bytes come from. Only offsets inside the current file are
/// accepted, so a mapping never asks the backing store for an impossible page.
fn file_page_target(
    state: &State,
    open: Open,
    offset: u64,
) -> Result<(CacheKey, u64, u64, ReadSource), VfsError> {
    let (key, id, size) = file_page_identity(state, open, offset)?;
    if offset >= size {
        return Err(VfsError::BadOffset);
    }
    let source = match state.table.get(id)?.backing {
        Backing::Ram => ReadSource::Ram,
        Backing::Boot { name, name_len } => ReadSource::Boot {
            name,
            len: (name_len as usize).min(MAX_NAME),
        },
        Backing::Disk { mount, node } => ReadSource::Disk { mount, node },
        Backing::Generated { .. } => return Err(VfsError::NotSupported),
    };
    Ok((key, size, offset / PAGE, source))
}

/// Make the page that holds `offset` resident, running the backing store on a
/// miss. Sparse pages get a real zeroed frame from the cache, so a mapping never
/// points at a hole without memory behind it.
fn materialise_page(
    key: CacheKey,
    size: u64,
    offset: u64,
    source: ReadSource,
) -> Result<(), VfsError> {
    match source {
        ReadSource::Ram => {
            pagecache::materialise(key, size, offset, None)?;
        }
        ReadSource::Boot { name, len } => {
            let mut backing =
                |page_start: u64, page: &mut [u8]| initramfs::fill(&name[..len], page_start, page);
            pagecache::materialise(key, size, offset, Some(&mut backing))?;
        }
        ReadSource::Disk { mount, node } => {
            let mut backing =
                |page_start: u64, page: &mut [u8]| disk::read_page(mount, node, page_start, page);
            pagecache::materialise(key, size, offset, Some(&mut backing))?;
        }
    }
    Ok(())
}

fn write_node(state: &mut State, id: Id, offset: u64, data: &[u8]) -> Result<usize, VfsError> {
    let (kind, backing, size, key, read_only, disk_node) = {
        let node = state.table.get(id)?;
        if node.kind == Kind::Directory {
            return Err(VfsError::IsDirectory);
        }
        (
            node.kind,
            node.backing,
            node.size,
            node.cache_key(id),
            node.read_only,
            node.backing.disk_node(),
        )
    };
    if read_only {
        return Err(VfsError::ReadOnly);
    }
    // Generated nodes (M8h): character devices discard the bytes, proc files are
    // read-only and were rejected above.
    if matches!(backing, Backing::Generated { .. }) {
        return pseudo::write(kind, data);
    }
    if kind == Kind::CharDevice {
        return Err(VfsError::NotSupported);
    }
    // Write-back, not write-through: the cache takes the bytes now, the dirty
    // page reaches the file system on `sync_path`/`sync_all`. The VNode's size is
    // authoritative for the cache; the on-disk directory entry is only updated
    // when the page actually lands (see `disk::writeback`).
    //
    // A page that is not resident yet must first be filled from the file system:
    // a partial write into a fresh page would otherwise zero the rest of that
    // page in the cache and write those zeros back to the disk file.
    let new_size = match disk_node {
        Some((mount, node)) => {
            let mut fill =
                |page_start: u64, frame: &mut [u8]| disk::read_page(mount, node, page_start, frame);
            pagecache::write_with(key, offset, data, size, Some(&mut fill))?
        }
        None => pagecache::write(key, offset, data, size)?,
    };
    state.table.get_mut(id)?.size = new_size;
    Ok(data.len())
}

fn truncate_node(state: &mut State, id: Id, new_size: u64) -> Result<u64, VfsError> {
    let (kind, backing, size, key, read_only, disk_node) = {
        let node = state.table.get(id)?;
        if node.kind == Kind::Directory {
            return Err(VfsError::IsDirectory);
        }
        (
            node.kind,
            node.backing,
            node.size,
            node.cache_key(id),
            node.read_only,
            node.backing.disk_node(),
        )
    };
    if read_only {
        return Err(VfsError::ReadOnly);
    }
    // Character devices and generated files have no persistent size: O_TRUNC is a
    // no-op and reports the current (always zero) size.
    if kind == Kind::CharDevice || matches!(backing, Backing::Generated { .. }) {
        return Ok(size);
    }
    if new_size < size {
        // A disk truncate frees blocks before the cache is asked to shrink, so a
        // pinned page must be rejected here — not after the volume changed.
        pagecache::check_shrinkable(key, new_size)?;
    }
    if let Some((mount, node)) = disk_node {
        // The file system is the authority on allocated blocks: flush what is
        // still dirty before shrinking, so the cache cannot resurrect bytes the
        // file system just freed, then truncate on disk and in the cache.
        let mut write =
            |page_start: u64, data: &[u8]| disk::writeback(mount, node, page_start, data, size);
        pagecache::writeback_key(key, &mut write)?;
        disk::truncate(mount, node, new_size)?;
        let size = pagecache::truncate(key, size, new_size)?;
        state.table.get_mut(id)?.size = size;
        disk::set_size(mount, node, size)?;
        return Ok(size);
    }
    let size = pagecache::truncate(key, size, new_size)?;
    state.table.get_mut(id)?.size = size;
    Ok(size)
}

/// Flush every dirty page of one file to its disk mount, then the device.
fn sync_node(state: &mut State, id: Id) -> Result<(), VfsError> {
    let (key, disk_node, size) = {
        let node = state.table.get(id)?;
        (node.cache_key(id), node.backing.disk_node(), node.size)
    };
    let Some((mount, node)) = disk_node else {
        // ramfs and boot payloads are memory-only; there is nothing to flush.
        return Ok(());
    };
    let mut write =
        |page_start: u64, data: &[u8]| disk::writeback(mount, node, page_start, data, size);
    pagecache::writeback_key(key, &mut write)?;
    disk::sync(mount)
}

/// Flush `path`'s dirty pages and the device they live on.
pub fn sync_path(raw_path: &[u8]) -> Result<(), VfsError> {
    let state = require_ready()?;
    let id = resolve(state, raw_path)?;
    sync_node(state, id)
}

/// Flush every dirty page of both disk mounts and their devices.
///
/// ramfs and `/boot` pages are skipped: they have no stable storage, and
/// pretending they were flushed would hide that fact.
pub fn sync_all() -> Result<(), VfsError> {
    let state = require_ready()?;
    // Collect first, then flush: `sync_node` needs `&mut State` while the table
    // itself is borrowed for iteration.
    let mut ids = [Id::NONE; MAX_VNODES];
    let mut count = 0usize;
    for (id, node) in state.table.used() {
        if node.backing.disk_node().is_some() {
            ids[count] = id;
            count += 1;
        }
    }
    for id in ids[..count].iter().copied() {
        sync_node(state, id)?;
    }
    for index in 0..disk::MAX_MOUNTS as u8 {
        if disk::is_mounted(index) {
            disk::sync(index)?;
        }
    }
    Ok(())
}

/// Clear the sticky media error of a mounted volume and return the old value.
///
/// The fault self-test in the boot path injects one device failure, checks that a
/// dirty write plus `sync` reports it, then confirms the one-shot fault has been
/// consumed and retries: without this entry point the volume would stay poisoned
/// and the retry could never succeed. Only the sticky flag is cleared.
pub fn clear_disk_sticky(kind: disk::Kind) -> Option<VfsError> {
    disk::clear_sticky(kind)
}

/// Mount the FAT32 volume at `/fat` (M5b).
///
/// The VFS takes ownership of the file system object and therefore of the block
/// device behind it. The mount point is an ordinary ramfs directory; its children
/// are materialised from the file system on first lookup.
pub fn mount_fat32(device: disk::Device) -> Result<(), VfsError> {
    mount_disk(disk::Kind::Fat32, device)
}

/// Mount the ext2 volume at `/ext2` (M5b).
pub fn mount_ext2(device: disk::Device) -> Result<(), VfsError> {
    mount_disk(disk::Kind::Ext2, device)
}

/// Register one disk mount and its mount point.
fn mount_disk(kind: disk::Kind, device: disk::Device) -> Result<(), VfsError> {
    let state = require_ready()?;
    if state.has_mount(kind) {
        return Err(VfsError::Busy);
    }
    let root = state.root;
    if state.table.child(root, kind.mount_name())?.is_some() {
        // A stale `/fat` (or a user-made directory with that name) would make the
        // mount point ambiguous: refuse instead of attaching a second child with
        // the same name below the root.
        return Err(VfsError::Busy);
    }
    let point = state
        .table
        .alloc(Kind::Directory, root, kind.mount_name(), Backing::Ram)?;
    match disk::mount(kind, device) {
        Ok(index) => {
            state.mounts[index as usize] = MountSlot {
                used: true,
                kind,
                root: point,
            };
            Ok(())
        }
        Err(error) => {
            // Never leave a mount point behind for a mount that failed: a path
            // that exists but lists nothing is worse than a clear error.
            state.table.release(point)?;
            Err(error)
        }
    }
}

/// Flush one mount and hand its device back (host tests remount the same disk to
/// prove the bytes reached the medium instead of staying in the page cache).
#[cfg(test)]
pub fn unmount_for_test(kind: disk::Kind) -> Result<disk::Device, VfsError> {
    let index = {
        let state = require_ready()?;
        state
            .mounts
            .iter()
            .position(|slot| slot.used && slot.kind == kind)
            .ok_or(VfsError::NotFound)? as u8
    };
    // Collect the VNodes that name entries of this mount before anything moves:
    // their cache keys are where the volume's pages live, and the same keys are
    // reused by a later mount of the same medium.
    let mut stale = [Id::NONE; types::MAX_VNODES];
    let mut keys = [pagecache::CacheKey::new(0, 0); types::MAX_VNODES];
    let mut stale_len = 0;
    {
        let state = require_ready()?;
        for (id, node) in state.table.used() {
            if matches!(node.backing, Backing::Disk { mount, .. } if mount == index)
                && stale_len < stale.len()
            {
                stale[stale_len] = id;
                keys[stale_len] = node.cache_key(id);
                stale_len += 1;
            }
        }
    }
    // A pinned page would outlive both the mount and the inode its key names, so
    // the dry run happens while the volume and the namespace are still intact.
    for key in &keys[..stale_len] {
        pagecache::check_releasable(*key)?;
    }
    // Flush every dirty page of every node first: the medium is about to change
    // hands, so nothing may still be sitting in the cache.
    sync_all()?;
    // Drop the mount's cached pages before the volume is released: a remount
    // reuses these keys and must not inherit a stale frame.
    for key in &keys[..stale_len] {
        pagecache::invalidate(*key)?;
    }
    let device = disk::unmount(index).ok_or(VfsError::Corrupt)?;
    let state = require_ready()?;
    let point = state.mounts[index as usize].root;
    state.mounts[index as usize] = MountSlot::EMPTY;
    // Drop the mount point and every VNode that named an entry of this mount: the
    // disk node table they refer to was just reset, and a later mount of the same
    // volume must start from a clean namespace instead of tripping the
    // duplicate-name guard in `mount_disk`.
    for id in &stale[..stale_len] {
        let _ = state.table.release(*id);
    }
    let _ = state.table.release(point);
    Ok(device)
}

/// Read `out.len()` bytes of `path` at `offset`.
///
/// At or past end-of-file this returns `Ok(0)` (never an error), which is what a
/// caller looping until a short read expects. Only offset arithmetic overflow is
/// [`VfsError::BadOffset`].
pub fn read_path(raw_path: &[u8], offset: u64, out: &mut [u8]) -> Result<usize, VfsError> {
    let state = require_ready()?;
    let id = resolve(state, raw_path)?;
    read_node(state, id, 0, offset, out)
}

/// Read an entire file into `out`.
///
/// `out.len()` must be at least the file size, otherwise [`VfsError::BadOffset`]
/// is returned (the caller can ask [`stat_path`] first). Returns the file size.
pub fn read_all_path(raw_path: &[u8], out: &mut [u8]) -> Result<usize, VfsError> {
    let state = require_ready()?;
    let id = resolve(state, raw_path)?;
    let size = node_size(state, id)?;
    if out.len() < size as usize {
        return Err(VfsError::BadOffset);
    }
    let read = read_node(state, id, 0, 0, &mut out[..size as usize])?;
    if read as u64 != size {
        return Err(VfsError::Corrupt);
    }
    Ok(read)
}

/// Metadata of `path`.
pub fn stat_path(raw_path: &[u8]) -> Result<Stat, VfsError> {
    let state = require_ready()?;
    let id = resolve(state, raw_path)?;
    let node = state.table.get(id)?;
    Ok(Stat {
        kind: node.kind,
        size: node.size,
        read_only: node.read_only,
        dev_major: node.dev_major,
        dev_minor: node.dev_minor,
    })
}

/// Open `path`, creating it when `options.create` is set.
///
/// Directories may be opened as well (read-only): M5c1 needs a description to
/// hang `readdir`/`stat` on, mirroring how the syscall layer will hand out a
/// directory fd. Writing or truncating a directory is refused here, before any
/// offset or cache state changes.
pub fn open_path(raw_path: &[u8], options: OpenOptions) -> Result<Open, VfsError> {
    open_path_as(raw_path, options, 0)
}

/// Open `raw_path` on behalf of `owner` (M5c3).
///
/// `owner` is the process id used for POSIX lock bookkeeping: descriptors of one
/// owner never conflict on POSIX locks, and both [`close`] and [`close_process`]
/// use it to release exactly that owner's locks. Kernel and test opens go through
/// [`open_path`] with owner 0; [`dup`] keeps the owner.
pub fn open_path_as(raw_path: &[u8], options: OpenOptions, owner: u32) -> Result<Open, VfsError> {
    // Reject impossible requests before touching any state: `validate` is what
    // keeps `truncate` from reaching a read-only description.
    options.validate()?;
    let state = require_ready()?;
    if (options.write || options.truncate || options.create) && alias_top_level(raw_path) {
        return Err(VfsError::ReadOnly);
    }
    if options.create {
        reject_trailing_slash(raw_path)?;
    }
    // Parse once: the scratch path is forwarded to create-through as-is, so the
    // create chain does not have to re-parse the same bytes (and keep another
    // ~1 KiB `Path` live on the boot stack).
    let parsed = scratch_path();
    path::parse_into(raw_path, parsed)?;
    let id = match resolve_parsed(state, parsed) {
        Ok(id) => id,
        // Create-through is routed by parent: a disk directory creates on the
        // file system, everything else creates a ramfs node.
        Err(VfsError::NotFound) if options.create => create_file_from_parsed(state, parsed)?,
        Err(error) => return Err(error),
    };
    let (kind, read_only) = {
        let node = state.table.get(id)?;
        (node.kind, node.read_only)
    };
    if kind == Kind::Directory {
        if options.write || options.truncate || options.create {
            return Err(VfsError::IsDirectory);
        }
    } else if options.write && read_only {
        return Err(VfsError::ReadOnly);
    }
    if options.truncate {
        truncate_node(state, id, 0)?;
    }
    state.opens.alloc(id, options, owner)
}

/// Read from an open description, advancing its offset.
pub fn read(open: Open, out: &mut [u8]) -> Result<usize, VfsError> {
    let state = require_ready()?;
    let (id, offset, allowed, owner) = {
        let description = state.opens.get(open)?;
        (
            description.vnode,
            description.offset,
            description.read,
            description.owner,
        )
    };
    if !allowed {
        return Err(VfsError::PermissionDenied);
    }
    let read = read_node(state, id, owner, offset, out)?;
    let description = state.opens.get_mut(open)?;
    description.offset = description.offset.saturating_add(read as u64);
    Ok(read)
}

/// Write through an open description, advancing its offset.
pub fn write(open: Open, data: &[u8]) -> Result<usize, VfsError> {
    let state = require_ready()?;
    let (id, offset, allowed) = {
        let description = state.opens.get(open)?;
        (description.vnode, description.offset, description.write)
    };
    if !allowed {
        return Err(VfsError::PermissionDenied);
    }
    let written = write_node(state, id, offset, data)?;
    state.opens.get_mut(open)?.offset = offset.saturating_add(written as u64);
    Ok(written)
}

/// Current offset of an open description.
pub fn offset(open: Open) -> Result<u64, VfsError> {
    Ok(require_ready()?.opens.get(open)?.offset)
}

/// Access mode of an open description as `(read, write)`.
///
/// Read-only query for `fcntl(F_GETFL)` (and `F_SETFL` validation). It performs
/// no permission check: a caller holding the description may always ask.
pub fn open_modes(open: Open) -> Result<(bool, bool), VfsError> {
    let state = require_ready()?;
    let description = state.opens.get(open)?;
    Ok((description.read, description.write))
}

/// Reposition an open description to an absolute byte offset.
///
/// Same semantics as [`seek_from`] with [`SeekFrom::Start`], including the
/// refusal to seek a directory ([`VfsError::IsDirectory`]).
pub fn seek(open: Open, offset: u64) -> Result<u64, VfsError> {
    seek_from(open, SeekFrom::Start(offset))
}

/// Reposition an open description relative to the start, the current position or
/// the end of the file.
///
/// Directories are refused ([`VfsError::IsDirectory`]): their position is an
/// entry index maintained by `readdir`, not a byte offset. A seek past
/// end-of-file is allowed; the following write extends the file, which is how a
/// sparse file becomes expressible through the public API.
pub fn seek_from(open: Open, from: SeekFrom) -> Result<u64, VfsError> {
    let state = require_ready()?;
    let (id, current, kind) = {
        let description = state.opens.get(open)?;
        let node = state.table.get(description.vnode)?;
        (description.vnode, description.offset, node.kind)
    };
    if !matches!(kind, Kind::File | Kind::CharDevice) {
        return Err(VfsError::IsDirectory);
    }
    let base: i128 = match from {
        SeekFrom::Start(value) => {
            state.opens.get_mut(open)?.offset = value;
            return Ok(value);
        }
        SeekFrom::Current(delta) => current as i128 + delta as i128,
        SeekFrom::End(delta) => node_size(state, id)? as i128 + delta as i128,
    };
    if base < 0 || base > u64::MAX as i128 {
        return Err(VfsError::BadOffset);
    }
    let offset = base as u64;
    state.opens.get_mut(open)?.offset = offset;
    Ok(offset)
}

/// Take another reference to the same description (`dup`), sharing the offset.
pub fn dup(open: Open) -> Result<Open, VfsError> {
    let state = require_ready()?;
    state.opens.retain(open)?;
    Ok(open)
}

/// Drop one reference to an open description.
///
/// Closing *any* descriptor that refers to a `VNode` releases every POSIX lock
/// its owner holds on that `VNode` (Linux `fcntl` close rule), including a `dup`
/// that leaves the description alive; that is [`note_close_locks`], repeated
/// here so the VFS stays correct even when a caller closes through [`close`]
/// directly. The last reference additionally releases the description-bound OFD
/// and `flock` locks ([`lock::close_description`]).
pub fn close(open: Open) -> Result<(), VfsError> {
    let state = require_ready()?;
    let (vnode, owner) = {
        let description = state.opens.get(open)?;
        (description.vnode, description.owner)
    };
    // POSIX locks die with *any* descriptor of the vnode, not only the last one.
    lock::posix_close(vnode, owner);
    if state.opens.release(open)? {
        // The description is gone: release the pins it still holds. This path has
        // no error channel on purpose (the object destroy hook has none), and a
        // leftover pin would leak a frame forever. Pages stay resident and dirty,
        // so a mapping that unpinned first still syncs normally.
        pagecache::release_owner(open.raw());
        lock::close_description(vnode, owner, open);
    }
    Ok(())
}

/// Apply a lock on an open description; non-blocking (M5c3).
///
/// `Posix` locks belong to the opening process (`description.owner`), while
/// `OpenDescription` and `Flock` locks belong to the description itself: two
/// `dup`-ed handles share them and two independent opens do not. A shared request
/// needs a readable description and an exclusive one a writable description;
/// directories are refused. `flock` is whole-file only (`offset == 0 && length ==
/// 0`), while for POSIX and OFD locks `length == 0` means "to end of file". A
/// conflict answers [`VfsError::WouldBlock`] instead of blocking.
pub fn lock_open(
    open: Open,
    domain: lock::LockDomain,
    kind: lock::LockKind,
    offset: u64,
    length: u64,
) -> Result<(), VfsError> {
    let state = require_ready()?;
    let (vnode, read, write, owner) = {
        let description = state.opens.get(open)?;
        (
            description.vnode,
            description.read,
            description.write,
            description.owner,
        )
    };
    if state.table.get(vnode)?.kind != Kind::File {
        return Err(VfsError::IsDirectory);
    }
    match kind {
        lock::LockKind::Shared if !read => return Err(VfsError::PermissionDenied),
        lock::LockKind::Exclusive if !write => return Err(VfsError::PermissionDenied),
        _ => {}
    }
    match domain {
        lock::LockDomain::Posix => lock::posix_lock(vnode, offset, length, kind, owner),
        lock::LockDomain::OpenDescription => lock::ofd_lock(vnode, open, offset, length, kind),
        lock::LockDomain::Flock => {
            if offset != 0 || length != 0 {
                return Err(VfsError::BadOffset);
            }
            lock::flock(vnode, open, kind == lock::LockKind::Exclusive)
        }
    }
}

/// Release a lock range requested through [`lock_open`].
///
/// POSIX unlocks use the description's owner and OFD unlocks its `OpenId`;
/// `flock` is whole-file and ignores the (still validated) range.
pub fn unlock_open(
    open: Open,
    domain: lock::LockDomain,
    offset: u64,
    length: u64,
) -> Result<(), VfsError> {
    let state = require_ready()?;
    let (vnode, owner) = {
        let description = state.opens.get(open)?;
        (description.vnode, description.owner)
    };
    match domain {
        lock::LockDomain::Posix => lock::posix_unlock(vnode, offset, length, owner),
        lock::LockDomain::OpenDescription => lock::ofd_unlock(vnode, open, offset, length),
        lock::LockDomain::Flock => {
            if offset != 0 || length != 0 {
                return Err(VfsError::BadOffset);
            }
            lock::funlock(vnode, open);
            Ok(())
        }
    }
}

/// Probe for a conflicting lock without inserting anything (`fcntl(F_GETLK)`).
///
/// Unlike [`lock_open`] this is a pure query: it needs no read/write access to
/// the description, never changes the lock table, and reports the first lock
/// that would block the request instead of [`VfsError::WouldBlock`].
///
/// The description's owner identifies a POSIX caller and the [`Open`] id an
/// OFD/`flock` caller, so locks held by the same holder never conflict. The
/// returned [`lock::LockConflict::owner`] is `0` for a description-bound lock
/// (no process owns it; Linux reports `l_pid == -1`). `flock` requests are
/// whole-file only, matching [`lock_open`]; directories are refused.
pub fn lock_probe(
    open: Open,
    domain: lock::LockDomain,
    kind: lock::LockKind,
    offset: u64,
    length: u64,
) -> Result<Option<lock::LockConflict>, VfsError> {
    let state = require_ready()?;
    let (vnode, owner) = {
        let description = state.opens.get(open)?;
        (description.vnode, description.owner)
    };
    if state.table.get(vnode)?.kind != Kind::File {
        return Err(VfsError::IsDirectory);
    }
    if domain == lock::LockDomain::Flock && (offset != 0 || length != 0) {
        return Err(VfsError::BadOffset);
    }
    Ok(lock::first_conflict(
        vnode, domain, kind, offset, length, owner, open,
    ))
}

/// Release the POSIX locks `open`'s owner holds on the description's `VNode`.
///
/// Linux releases a process's POSIX locks on a file when *any* descriptor that
/// refers to it is closed, so a close hook calls this for every close, including
/// one that only drops a `dup` reference and leaves the description alive. OFD
/// and `flock` locks belong to the description and are released by
/// [`lock::close_description`] on the last close instead. Idempotent;
/// [`VfsError::NotFound`] is only returned for a stale id.
pub fn note_close_locks(open: Open) -> Result<(), VfsError> {
    let state = require_ready()?;
    let (vnode, owner) = {
        let description = state.opens.get(open)?;
        (description.vnode, description.owner)
    };
    lock::posix_close(vnode, owner);
    Ok(())
}

/// Process-exit hook: release every POSIX lock and directory watch owned by
/// `owner`. OFD and `flock` locks belong to their `OpenId` and are released when
/// the object layer closes the description, not here.
pub fn close_process(owner: u32) -> usize {
    let locks = lock::close_process(owner);
    notify::close_process(owner);
    locks
}

/// Number of live lock entries (acceptance hook).
pub fn lock_count() -> usize {
    lock::count()
}

/// Number of live directory watches (acceptance hook).
pub fn watch_count() -> usize {
    notify::count()
}

/// Watch `raw_path` on behalf of `owner`; only directories can be watched.
pub fn watch_directory_as(raw_path: &[u8], owner: u32) -> Result<notify::WatchId, VfsError> {
    let state = require_ready()?;
    let id = resolve(state, raw_path)?;
    if state.table.get(id)?.kind != Kind::Directory {
        return Err(VfsError::NotDirectory);
    }
    notify::watch_owned(id, owner)
}

/// Drain pending events of a watch owned by `owner`.
pub fn watch_drain_owned(
    id: notify::WatchId,
    owner: u32,
    out: &mut [notify::NotifyEvent],
) -> Result<usize, VfsError> {
    notify::drain_owned(id, owner, out)
}

/// Stop a watch owned by `owner`.
pub fn watch_unwatch_owned(id: notify::WatchId, owner: u32) -> Result<(), VfsError> {
    notify::unwatch_owned(id, owner)
}

/// Create an empty file at `raw_path`.
pub fn create_path(raw_path: &[u8]) -> Result<Id, VfsError> {
    let state = require_ready()?;
    reject_trailing_slash(raw_path)?;
    if alias_top_level(raw_path) {
        return Err(VfsError::ReadOnly);
    }
    create_file_child(state, raw_path)
}

/// Byte token naming a directory inside its disk mount.
///
/// The mount root itself is [`disk::ROOT_NODE`]; every other directory is a
/// materialised VNode whose backing already carries the disk-node id.
fn disk_dir_token(state: &State, id: Id) -> Result<u16, VfsError> {
    if state.mount_of(id).is_some() {
        return Ok(disk::ROOT_NODE);
    }
    let node = state.table.get(id)?;
    if node.kind != Kind::Directory {
        return Err(VfsError::NotDirectory);
    }
    match node.backing.disk_node() {
        Some((_, token)) => Ok(token),
        None => Err(VfsError::NotSupported),
    }
}

/// Disk directory that owns the children of `parent`.
///
/// The mount root maps to [`disk::ROOT_NODE`]; a materialised directory VNode
/// maps to its disk node. `Ok(None)` means the parent is a ramfs directory, so
/// the caller stays on the in-memory path; a non-directory parent is refused here
/// so both paths reject it the same way.
fn disk_parent(state: &State, parent: Id) -> Result<Option<(u8, u16)>, VfsError> {
    if let Some((mount, _)) = state.mount_of(parent) {
        return Ok(Some((mount, disk::ROOT_NODE)));
    }
    let node = state.table.get(parent)?;
    if node.kind != Kind::Directory {
        return Err(VfsError::NotDirectory);
    }
    Ok(node.backing.disk_node())
}

/// Read one directory entry (by index) from a directory VNode or a mount root.
fn readdir_node(
    state: &mut State,
    id: Id,
    start: usize,
    out: &mut [DirEntry],
) -> Result<usize, VfsError> {
    if out.is_empty() {
        return Ok(0);
    }
    let (kind, disk_node) = {
        let node = state.table.get(id)?;
        (node.kind, node.backing.disk_node())
    };
    if kind != Kind::Directory {
        return Err(VfsError::NotDirectory);
    }
    if let Some((mount, _)) = state.mount_of(id) {
        let mut entry = DirEntry::empty();
        if disk::readdir(mount, disk::ROOT_NODE, start, &mut entry)? {
            out[0] = entry;
            return Ok(1);
        }
        return Ok(0);
    }
    if let Some((mount, token)) = disk_node {
        let mut entry = DirEntry::empty();
        if disk::readdir(mount, token, start, &mut entry)? {
            out[0] = entry;
            return Ok(1);
        }
        return Ok(0);
    }
    state.table.readdir(id, start, out)
}

/// Create a directory at `raw_path`, on the disk mount when the parent lives on
/// one and in ramfs otherwise.
pub fn mkdir_path(raw_path: &[u8]) -> Result<Id, VfsError> {
    let state = require_ready()?;
    reject_trailing_slash(raw_path)?;
    if alias_top_level(raw_path) {
        return Err(VfsError::ReadOnly);
    }
    let parsed = scratch_path();
    path::parse_into(raw_path, parsed)?;
    let mut name = [0u8; MAX_NAME];
    let name_len = parsed.split_last(&mut name)?;
    let name = &name[..name_len];
    let parent = resolve_parsed(state, parsed)?;
    reject_read_only_parent(state, parent)?;
    if let Some((mount, dir)) = disk_parent(state, parent)? {
        require_vnode_slot(state)?;
        let (node, kind, size) = disk::create(mount, dir, name, Kind::Directory)?;
        let id = match materialise_disk(state, mount, node, kind, size, name, parent) {
            Ok(id) => id,
            Err(error) => {
                // Undo the fresh directory entry rather than leak an orphan.
                let _ = disk::unlink(mount, dir, node, name);
                return Err(error);
            }
        };
        notify::publish(parent, notify::NotifyKind::Created, name)?;
        return Ok(id);
    }
    let id = ramfs::create_directory_at(&mut state.table, parent, name)?;
    notify::publish(parent, notify::NotifyKind::Created, name)?;
    Ok(id)
}

/// Remove a file (directories are refused; see [`rmdir_path`]).
pub fn unlink_path(raw_path: &[u8]) -> Result<(), VfsError> {
    let state = require_ready()?;
    reject_trailing_slash(raw_path)?;
    if alias_top_level(raw_path) {
        return Err(VfsError::ReadOnly);
    }
    let parsed = scratch_path();
    path::parse_into(raw_path, parsed)?;
    // Resolve the file before splitting, then reuse the same buffer for its
    // parent path: one parse, one `Path`.
    let id = resolve_parsed(state, parsed)?;
    reject_generated_node(state, id)?;
    // M5c1 pins open descriptions: the `OpenId` carried by a `File` object must
    // never outlive its VNode, so a path with live descriptions cannot be
    // unlinked. POSIX would defer the reclaim until the last close; that
    // machinery is explicitly out of scope for M5c1 instead of being faked here.
    if state.opens.has_description(id) {
        return Err(VfsError::Busy);
    }
    let mut name = [0u8; MAX_NAME];
    let name_len = parsed.split_last(&mut name)?;
    let name = &name[..name_len];
    let parent = resolve_parsed(state, parsed)?;
    reject_read_only_parent(state, parent)?;
    if let Some((mount, dir)) = disk_parent(state, parent)? {
        let (disk_node, key, kind) = {
            let node = state.table.get(id)?;
            (
                node.backing.disk_node().ok_or(VfsError::NotSupported)?.1,
                node.cache_key(id),
                node.kind,
            )
        };
        if kind == Kind::Directory {
            return Err(VfsError::IsDirectory);
        }
        // A pinned page cannot be dropped, and dropping it after the entry is gone
        // would lose the only name for those bytes: refuse before the mutation.
        pagecache::check_releasable(key)?;
        disk::unlink(mount, dir, disk_node, name)?;
        // Drop the cached pages now: they belong to an inode the file system has
        // just freed.
        pagecache::invalidate(key)?;
        state.table.release(id)?;
        notify::publish(parent, notify::NotifyKind::Deleted, name)?;
        return Ok(());
    }
    let key = { state.table.get(id)?.cache_key(id) };
    pagecache::check_releasable(key)?;
    let removed = ramfs::unlink_at(&mut state.table, parent, name)?;
    pagecache::invalidate(removed.key)?;
    notify::publish(parent, notify::NotifyKind::Deleted, name)?;
    Ok(())
}

/// True when `id` is the VNode of a registered disk mount point.
///
/// Mount points are structural: `rmdir` on one would leave its mount slot `used`
/// while the root becomes unreachable, and a later mount of the same kind would
/// report `Busy`. Renaming one (as source or as replacement target) has the same
/// effect, so all three checks happen before any file system or VNode mutation.
fn is_mount_root(state: &State, id: Id) -> bool {
    state.mount_of(id).is_some()
}

/// Refuse structural changes inside a read-only directory (M8h: /proc and /dev).
///
/// The generated namespace is fixed at boot: creating, unlinking, renaming or
/// rmdir-ing inside it would either corrupt the tree or silently disappear on the
/// next boot, so those mutations report `PermissionDenied` instead.
fn reject_read_only_parent(state: &State, parent: Id) -> Result<(), VfsError> {
    let node = state.table.get(parent)?;
    if node.kind == Kind::Directory && node.read_only {
        return Err(VfsError::PermissionDenied);
    }
    Ok(())
}

/// Refuse mutating a generated node itself (M8h): its contents are produced on
/// demand and it has no persistent name to move or remove.
fn reject_generated_node(state: &State, id: Id) -> Result<(), VfsError> {
    if matches!(state.table.get(id)?.backing, Backing::Generated { .. }) {
        return Err(VfsError::PermissionDenied);
    }
    Ok(())
}

/// Remove an empty directory (on ramfs or on a mounted file system).
pub fn rmdir_path(raw_path: &[u8]) -> Result<(), VfsError> {
    let state = require_ready()?;
    reject_trailing_slash(raw_path)?;
    if alias_top_level(raw_path) {
        return Err(VfsError::ReadOnly);
    }
    let parsed = scratch_path();
    path::parse_into(raw_path, parsed)?;
    // A mount point may not be removed: check the target before mutating anything.
    let id = resolve_parsed(state, parsed)?;
    reject_generated_node(state, id)?;
    reject_read_only_parent(state, id)?;
    if is_mount_root(state, id) {
        return Err(VfsError::Busy);
    }
    // Same M5c1 limitation as `unlink_path`: an open directory description keeps
    // its VNode alive, so the directory cannot be removed yet.
    if state.opens.has_description(id) {
        return Err(VfsError::Busy);
    }
    let mut name = [0u8; MAX_NAME];
    let name_len = parsed.split_last(&mut name)?;
    let name = &name[..name_len];
    let parent = resolve_parsed(state, parsed)?;
    reject_read_only_parent(state, parent)?;
    if let Some((mount, dir)) = disk_parent(state, parent)? {
        let (disk_node, key, kind) = {
            let node = state.table.get(id)?;
            (
                node.backing.disk_node().ok_or(VfsError::NotSupported)?.1,
                node.cache_key(id),
                node.kind,
            )
        };
        if kind != Kind::Directory {
            return Err(VfsError::NotDirectory);
        }
        pagecache::check_releasable(key)?;
        // The file system decides emptiness and answers `NotEmpty`, which the
        // error mapping keeps distinct from `Busy`.
        disk::unlink(mount, dir, disk_node, name)?;
        pagecache::invalidate(key)?;
        state.table.release(id)?;
        notify::publish(parent, notify::NotifyKind::Deleted, name)?;
        notify::invalidate_directory(id);
        return Ok(());
    }
    let key = { state.table.get(id)?.cache_key(id) };
    pagecache::check_releasable(key)?;
    ramfs::rmdir_at(&mut state.table, parent, name)?;
    notify::publish(parent, notify::NotifyKind::Deleted, name)?;
    notify::invalidate_directory(id);
    Ok(())
}

/// Publish the rename notification(s) for the affected parent directories.
///
/// A rename inside one directory is a single event carrying the **new** name: the
/// directory itself did not change, and also reporting the old name would make a
/// watcher observe two `Renamed` events for one rename (the init's watch fixture
/// expects exactly `Created -> Renamed(new) -> Deleted`). Moving between
/// directories keeps the two events, one per parent, because each directory lost
/// or gained an entry under the old or the new name.
fn publish_rename(
    old_parent: Id,
    new_parent: Id,
    old_name: &[u8],
    new_name: &[u8],
) -> Result<(), VfsError> {
    if old_parent == new_parent {
        notify::publish(old_parent, notify::NotifyKind::Renamed, new_name)?;
        return Ok(());
    }
    notify::publish(old_parent, notify::NotifyKind::Renamed, old_name)?;
    notify::publish(new_parent, notify::NotifyKind::Renamed, new_name)?;
    Ok(())
}

/// Rename `old_path` to `new_path`, moving between directories of one mount.
///
/// Both names must live in the same mount. Cross-mount renames (and moves
/// between ramfs and a disk mount) are refused explicitly rather than copied
/// behind the caller's back: there is no cross-mount copy machinery.
///
/// Replacement follows the underlying store, and the two differ on purpose:
/// ramfs follows POSIX - a regular file target is replaced and its cached pages
/// are invalidated - while the FAT32 and ext2 back ends refuse an existing target
/// name (reported as [`VfsError::AlreadyExists`]) because neither library
/// overwrites an entry. Callers must not assume the POSIX replace rule on a disk
/// mount.
pub fn rename_path(old_path: &[u8], new_path: &[u8]) -> Result<(), VfsError> {
    let state = require_ready()?;
    reject_trailing_slash(old_path)?;
    reject_trailing_slash(new_path)?;
    if alias_top_level(old_path) || alias_top_level(new_path) {
        return Err(VfsError::ReadOnly);
    }
    // One `Path` buffer is reused for both names, and the old file is resolved
    // before the buffer is overwritten: no second `Path` is kept live.
    let parsed = scratch_path();
    let mut old_name = [0u8; MAX_NAME];
    let mut new_name = [0u8; MAX_NAME];
    path::parse_into(old_path, parsed)?;
    let old_id = resolve_parsed(state, parsed)?;
    reject_generated_node(state, old_id)?;
    // A mount point may not be moved away: refuse before touching either side.
    if is_mount_root(state, old_id) {
        return Err(VfsError::Busy);
    }
    let old_len = parsed.split_last(&mut old_name)?;
    let old_parent = resolve_parsed(state, parsed)?;
    reject_read_only_parent(state, old_parent)?;
    let old_mount = disk_parent(state, old_parent)?.map(|(mount, _)| mount);
    path::parse_into(new_path, parsed)?;
    // Nor may one be replaced: resolve the destination (missing is fine) and
    // reject a mount root before any file system or VNode mutation.
    let replaced = match resolve_parsed(state, parsed) {
        Ok(id) => Some(id),
        Err(VfsError::NotFound) => None,
        Err(error) => return Err(error),
    };
    if let Some(target) = replaced {
        if is_mount_root(state, target) {
            return Err(VfsError::Busy);
        }
        reject_generated_node(state, target)?;
    }
    let new_len = parsed.split_last(&mut new_name)?;
    let new_parent = resolve_parsed(state, parsed)?;
    reject_read_only_parent(state, new_parent)?;
    let new_mount = disk_parent(state, new_parent)?.map(|(mount, _)| mount);
    match (old_mount, new_mount) {
        (Some(source), Some(target)) => {
            if source != target {
                return Err(VfsError::NotSupported);
            }
            let disk_node = state
                .table
                .get(old_id)?
                .backing
                .disk_node()
                .ok_or(VfsError::NotSupported)?
                .1;
            let old_dir = disk_dir_token(state, old_parent)?;
            let new_dir = disk_dir_token(state, new_parent)?;
            // The file system entry moves; the VNode (and its page-cache key)
            // stays, so open descriptions and cached pages survive the rename.
            disk::rename(
                source,
                old_dir,
                disk_node,
                &old_name[..old_len],
                new_dir,
                &new_name[..new_len],
            )?;
            state
                .table
                .reparent(old_id, new_parent, &new_name[..new_len])?;
            publish_rename(
                old_parent,
                new_parent,
                &old_name[..old_len],
                &new_name[..new_len],
            )?;
            Ok(())
        }
        (None, None) => {
            // POSIX replaces a regular-file target here, but never at the cost of a
            // live description or a pinned page. Both checks run before any VNode
            // or page-cache mutation, so a refusal leaves the tree untouched
            // instead of releasing the target first and failing afterwards.
            if let Some(target) = replaced {
                if state.opens.has_description(target) {
                    return Err(VfsError::Busy);
                }
                let key = state.table.get(target)?.cache_key(target);
                pagecache::check_releasable(key)?;
            }
            let replaced = ramfs::rename_at(
                &mut state.table,
                old_parent,
                &old_name[..old_len],
                new_parent,
                &new_name[..new_len],
            )?;
            if let Some(removed) = replaced {
                pagecache::invalidate(removed.key)?;
            }
            publish_rename(
                old_parent,
                new_parent,
                &old_name[..old_len],
                &new_name[..new_len],
            )?;
            Ok(())
        }
        _ => Err(VfsError::NotSupported),
    }
}

/// Change the size of a file.
pub fn truncate_path(raw_path: &[u8], new_size: u64) -> Result<u64, VfsError> {
    let state = require_ready()?;
    if alias_top_level(raw_path) {
        return Err(VfsError::ReadOnly);
    }
    let id = resolve(state, raw_path)?;
    truncate_node(state, id, new_size)
}

/// List directory entries starting at index `start`.
pub fn readdir_path(
    raw_path: &[u8],
    start: usize,
    out: &mut [DirEntry],
) -> Result<usize, VfsError> {
    let state = require_ready()?;
    let id = resolve(state, raw_path)?;
    readdir_node(state, id, start, out)
}

/// Metadata of an open description.
pub fn stat_open(open: Open) -> Result<Stat, VfsError> {
    let state = require_ready()?;
    let id = state.opens.get(open)?.vnode;
    let node = state.table.get(id)?;
    Ok(Stat {
        kind: node.kind,
        size: node.size,
        read_only: node.read_only,
        dev_major: node.dev_major,
        dev_minor: node.dev_minor,
    })
}

/// Flush an open description's dirty pages and the device they live on.
pub fn sync_open(open: Open) -> Result<(), VfsError> {
    let state = require_ready()?;
    let id = state.opens.get(open)?.vnode;
    sync_node(state, id)
}

/// Change the size of an open file (a write-mode description is required).
pub fn truncate_open(open: Open, new_size: u64) -> Result<u64, VfsError> {
    let state = require_ready()?;
    let (id, writable) = {
        let description = state.opens.get(open)?;
        (description.vnode, description.write)
    };
    if !writable {
        return Err(VfsError::PermissionDenied);
    }
    truncate_node(state, id, new_size)
}

/// List entries of an open directory description.
pub fn readdir_open(open: Open, start: usize, out: &mut [DirEntry]) -> Result<usize, VfsError> {
    let state = require_ready()?;
    let (id, readable) = {
        let description = state.opens.get(open)?;
        (description.vnode, description.read)
    };
    if !readable {
        return Err(VfsError::PermissionDenied);
    }
    readdir_node(state, id, start, out)
}

/// Read the next directory entries of an open directory description.
///
/// The description's `offset` is used as a directory cursor - an entry index,
/// not a byte offset. Entry 0 is `.` and entry 1 is `..`; both are synthesised
/// here because the VFS never stores them, and real entries start at index 2.
/// Each call writes as many entries as fit in `out` and advances the cursor
/// only by the number actually written, so a short buffer never skips an
/// entry and the end of the directory leaves the cursor where it is. `dup`
/// shares the same description and therefore the same cursor; an independent
/// open starts at 0. This is not a byte offset: `seek` on a directory keeps
/// answering [`VfsError::IsDirectory`].
pub fn readdir_open_next(open: Open, out: &mut [DirEntry]) -> Result<usize, VfsError> {
    if out.is_empty() {
        return Ok(0);
    }
    let (id, readable, mut cursor) = {
        let state = require_ready()?;
        let description = state.opens.get(open)?;
        (description.vnode, description.read, description.offset)
    };
    if !readable {
        return Err(VfsError::PermissionDenied);
    }
    {
        let state = require_ready()?;
        if state.table.get(id)?.kind != Kind::Directory {
            return Err(VfsError::NotDirectory);
        }
    }
    let mut written = 0;
    while written < out.len() && cursor < 2 {
        out[written] = readdir_dot(cursor == 1);
        written += 1;
        cursor += 1;
    }
    // Real entries start after the two synthetic ones.
    if written < out.len() && cursor >= 2 {
        let start = usize::try_from(cursor - 2).map_err(|_| VfsError::BadOffset)?;
        let read = readdir_open(open, start, &mut out[written..])?;
        written += read;
        cursor += read as u64;
    }
    if written > 0 {
        require_ready()?.opens.get_mut(open)?.offset = cursor;
    }
    Ok(written)
}

/// Synthetic `.` (index 0) or `..` (index 1) directory entry.
fn readdir_dot(parent: bool) -> DirEntry {
    let mut entry = DirEntry::empty();
    entry.name[0] = b'.';
    if parent {
        entry.name[1] = b'.';
        entry.name_len = 2;
    } else {
        entry.name_len = 1;
    }
    entry.kind = Kind::Directory;
    entry.size = 0;
    entry
}

/// Pin the page that holds `offset` of an open file and return its physical
/// frame (eager `mmap`, M5c2).
///
/// `offset` must be page aligned and inside the file's current size. The page is
/// materialised from ramfs/initramfs/the disk on the first pin, so the returned
/// frame is stable while the pin is held: `truncate`/`unlink` answer
/// [`VfsError::Busy`] instead of freeing it. Writes and `sync` are **not**
/// blocked - a shared mapping is expected to see file writes through the cache.
///
/// Every successful pin needs exactly one [`unpin_file_page`]; the final `close`
/// of the description releases whatever pins the description still holds, so a
/// mapping that outlives the file handle is legal. Callers pass the `dup`'d
/// description used for the mapping.
pub fn pin_file_page(open: Open, offset: u64) -> Result<u64, VfsError> {
    let state = require_ready()?;
    let (key, size, page, source) = file_page_target(state, open, offset)?;
    materialise_page(key, size, offset, source)?;
    pagecache::pin_page(open.raw(), key, page)
}

/// Release one pin taken by [`pin_file_page`] (exactly once per pin).
pub fn unpin_file_page(open: Open, offset: u64) -> Result<(), VfsError> {
    let state = require_ready()?;
    let (key, _id, _size) = file_page_identity(state, open, offset)?;
    pagecache::unpin_page(open.raw(), key, offset / PAGE)
}

/// Mark the page that holds `offset` dirty after a shared mapping wrote into its
/// frame directly (M5c2).
///
/// The page must already be pinned or resident; this never reads the backing
/// store and never flushes, so a later [`sync_path`]/[`sync_all`] writes the
/// mapping's bytes back to the file system.
pub fn mark_file_page_dirty(open: Open, offset: u64) -> Result<(), VfsError> {
    let state = require_ready()?;
    let (key, id, _size) = file_page_identity(state, open, offset)?;
    // The mark never materialises a page: a page that is neither pinned nor
    // resident has no frame to make dirty, and reporting that beats a rights
    // error because nothing in the cache changed either way.
    if !pagecache::is_resident(key, offset / PAGE) {
        return Err(VfsError::NotFound);
    }
    // A shared mapping only publishes bytes its handle could have written: a
    // read-only description or a read-only payload must not leave a permanently
    // dirty page that the next sync would push into a read-only store.
    let (writable, read_only) = {
        let description = state.opens.get(open)?;
        let node = state.table.get(id)?;
        (description.write, node.read_only)
    };
    if !writable {
        return Err(VfsError::PermissionDenied);
    }
    if read_only {
        return Err(VfsError::ReadOnly);
    }
    pagecache::mark_dirty(key, offset / PAGE)
}

/// Copy the whole page that holds `offset` into `dst_phys` and zero the
/// end-of-file tail past the file's end (private `mmap`, M5c2).
///
/// `dst_phys` must be a 4 KiB aligned frame the caller already allocated; the
/// copy runs frame to frame through the direct map, so no stack buffer is used.
pub fn copy_file_page(open: Open, offset: u64, dst_phys: u64) -> Result<(), VfsError> {
    if dst_phys == 0 || dst_phys % PAGE != 0 {
        return Err(VfsError::BadOffset);
    }
    let state = require_ready()?;
    let (key, size, page, source) = file_page_target(state, open, offset)?;
    materialise_page(key, size, offset, source)?;
    let valid = core::cmp::min(size - offset, PAGE) as usize;
    pagecache::copy_page_to(key, page, valid, dst_phys)
}

/// Set a `user.*` extension attribute (name is the suffix after `user.`).
pub fn xattr_set(raw_path: &[u8], name: &[u8], value: &[u8]) -> Result<(), VfsError> {
    let state = require_ready()?;
    let id = resolve(state, raw_path)?;
    xattr_set_node(state, id, name, value)
}

/// Set an extension attribute through an open description (M5c3); requires WRITE.
/// Directories carry no attributes here. Only the VNode table stores the value,
/// so a disk mount loses it on unmount by design (no fake persistence).
pub fn xattr_set_open(open: Open, name: &[u8], value: &[u8]) -> Result<(), VfsError> {
    let state = require_ready()?;
    let (id, write) = {
        let description = state.opens.get(open)?;
        (description.vnode, description.write)
    };
    if !write {
        return Err(VfsError::PermissionDenied);
    }
    xattr_set_node(state, id, name, value)
}

fn xattr_set_node(state: &mut State, id: Id, name: &[u8], value: &[u8]) -> Result<(), VfsError> {
    if name.is_empty() || name.len() > MAX_XATTR_NAME || value.len() > MAX_XATTR_VALUE {
        return Err(VfsError::Quota);
    }
    let node = state.table.get_mut(id)?;
    if node.kind != Kind::File {
        return Err(VfsError::IsDirectory);
    }
    if node.read_only {
        return Err(VfsError::ReadOnly);
    }
    let mut existing = None;
    let mut free = None;
    for index in 0..MAX_XATTRS {
        match &node.xattrs[index] {
            vnode::Xattr::Empty => {
                if free.is_none() {
                    free = Some(index);
                }
            }
            vnode::Xattr::Set {
                name_len,
                name: stored,
                ..
            } => {
                if &stored[..*name_len as usize] == name {
                    existing = Some(index);
                }
            }
        }
    }
    let target = existing.or(free).ok_or(VfsError::Quota)?;
    node.xattrs[target] = make_xattr(name, value)?;
    Ok(())
}

fn make_xattr(name: &[u8], value: &[u8]) -> Result<vnode::Xattr, VfsError> {
    if name.is_empty() || name.len() > MAX_XATTR_NAME || value.len() > MAX_XATTR_VALUE {
        return Err(VfsError::Quota);
    }
    let mut xattr = vnode::Xattr::Set {
        name_len: name.len() as u8,
        name: [0u8; MAX_XATTR_NAME],
        value_len: value.len() as u8,
        value: [0u8; MAX_XATTR_VALUE],
    };
    if let vnode::Xattr::Set {
        name: stored,
        value: stored_value,
        ..
    } = &mut xattr
    {
        stored[..name.len()].copy_from_slice(name);
        stored_value[..value.len()].copy_from_slice(value);
    }
    Ok(xattr)
}

/// Read a `user.*` extension attribute into `out`; returns its length.
pub fn xattr_get(raw_path: &[u8], name: &[u8], out: &mut [u8]) -> Result<usize, VfsError> {
    let state = require_ready()?;
    let id = resolve(state, raw_path)?;
    xattr_get_node(state, id, name, out)
}

/// Read an extension attribute through an open description (M5c3); requires READ.
pub fn xattr_get_open(open: Open, name: &[u8], out: &mut [u8]) -> Result<usize, VfsError> {
    let state = require_ready()?;
    let (id, read) = {
        let description = state.opens.get(open)?;
        (description.vnode, description.read)
    };
    if !read {
        return Err(VfsError::PermissionDenied);
    }
    xattr_get_node(state, id, name, out)
}

fn xattr_get_node(state: &State, id: Id, name: &[u8], out: &mut [u8]) -> Result<usize, VfsError> {
    let node = state.table.get(id)?;
    if node.kind != Kind::File {
        return Err(VfsError::IsDirectory);
    }
    for slot in node.xattrs.iter() {
        if let Some(stored_name) = slot.name() {
            if stored_name == name {
                let value = slot.value().ok_or(VfsError::Corrupt)?;
                if out.len() < value.len() {
                    return Err(VfsError::BadOffset);
                }
                out[..value.len()].copy_from_slice(value);
                return Ok(value.len());
            }
        }
    }
    Err(VfsError::NotFound)
}

/// Remove a `user.*` extension attribute.
pub fn xattr_remove(raw_path: &[u8], name: &[u8]) -> Result<(), VfsError> {
    let state = require_ready()?;
    let id = resolve(state, raw_path)?;
    let node = state.table.get_mut(id)?;
    if node.read_only {
        return Err(VfsError::ReadOnly);
    }
    for index in 0..MAX_XATTRS {
        if node.xattrs[index].name() == Some(name) {
            node.xattrs[index] = vnode::Xattr::Empty;
            return Ok(());
        }
    }
    Err(VfsError::NotFound)
}

/// Real runtime self-check: ramfs + page cache + boot payload + locks + notify.
///
/// Runs the exact wiring the kernel depends on (`create` → `write` → `read` →
/// `read` → `unlink` → `read`), checks sparse holes, truncation, rename, dup
/// offsets and the read-only boot mount, then hands over to the lock and notify
/// self-tests. Temporary nodes are removed again; nothing is printed.
pub fn selftest() -> Result<(), VfsError> {
    const TEMP: &[u8] = b"/selftest.tmp";
    const TEMP2: &[u8] = b"/selftest.renamed";

    // Boot payloads first: the fixed bytes the loader handed us must be readable
    // through the VNode + page cache path, not through a side channel.
    let boot_stat = stat_path(b"/boot/init")?;
    if boot_stat.kind != Kind::File || !boot_stat.read_only || boot_stat.size == 0 {
        return Err(VfsError::Corrupt);
    }
    let expected = crate::bootmod::find(crate::bootmod::INIT_MODULE)
        .map(|module| module.data())
        .ok_or(VfsError::NotFound)?;
    let mut head = [0u8; 8];
    let probe_len = head.len().min(expected.len());
    let copied = read_path(b"/boot/init", 0, &mut head[..probe_len])?;
    if copied != probe_len || head[..copied] != expected[..probe_len] {
        return Err(VfsError::Corrupt);
    }
    if write_path_for_test(b"/boot/init", b"x") != Err(VfsError::ReadOnly) {
        return Err(VfsError::Corrupt);
    }

    // Ramfs closure.
    let _ = unlink_path(TEMP);
    create_path(TEMP)?;
    let open = open_path(TEMP, OpenOptions::create_write())?;
    if write(open, b"hello")? != 5 {
        return Err(VfsError::Corrupt);
    }
    if seek(open, 0)? != 0 {
        return Err(VfsError::Corrupt);
    }
    let mut buffer = [0u8; 8];
    if read(open, &mut buffer[..5])? != 5 || &buffer[..5] != b"hello" {
        return Err(VfsError::Corrupt);
    }
    if offset(open)? != 5 {
        return Err(VfsError::Corrupt);
    }
    // Sparse hole inside the file reads zero: extend to 8193 bytes and read the
    // unwritten page below the new end.
    let extender = open_path(TEMP, OpenOptions::read_write())?;
    if seek(extender, 8192)? != 8192 {
        return Err(VfsError::Corrupt);
    }
    if write(extender, b"z")? != 1 {
        return Err(VfsError::Corrupt);
    }
    close(extender)?;
    let mut hole = [0xFFu8; 4];
    if read_path(TEMP, 4096, &mut hole)? != 4 || hole != [0; 4] {
        return Err(VfsError::Corrupt);
    }
    // dup shares the offset.
    let duped = dup(open)?;
    if offset(duped)? != 5 {
        return Err(VfsError::Corrupt);
    }
    close(duped)?;
    close(open)?;
    if truncate_path(TEMP, 2)? != 2 {
        return Err(VfsError::Corrupt);
    }
    if stat_path(TEMP)?.size != 2 {
        return Err(VfsError::Corrupt);
    }
    // Extension attributes.
    xattr_set(TEMP, b"tag", b"m5a")?;
    let mut value = [0u8; MAX_XATTR_VALUE];
    if xattr_get(TEMP, b"tag", &mut value)? != 3 || &value[..3] != b"m5a" {
        return Err(VfsError::Corrupt);
    }
    xattr_remove(TEMP, b"tag")?;
    if xattr_get(TEMP, b"tag", &mut value) != Err(VfsError::NotFound) {
        return Err(VfsError::Corrupt);
    }
    // Rename then unlink, and the cache must forget the pages.
    let _ = unlink_path(TEMP2);
    rename_path(TEMP, TEMP2)?;
    if stat_path(TEMP) != Err(VfsError::NotFound) {
        return Err(VfsError::Corrupt);
    }
    unlink_path(TEMP2)?;
    if read_path(TEMP2, 0, &mut buffer) != Err(VfsError::NotFound) {
        return Err(VfsError::Corrupt);
    }
    // Directory listing sees the six boot modules the loader handed us. The
    // table iterates children newest-first, so the order is not part of the
    // contract: only the set and the count are.
    let mut entries = [DirEntry::empty(); 6];
    let boot_entries = readdir_path(b"/boot", 0, &mut entries)?;
    let mut found = [false; 6];
    for entry in &entries[..boot_entries.min(entries.len())] {
        let name = entry.name();
        if name == crate::bootmod::INIT_MODULE {
            found[0] = true;
        } else if name == crate::bootmod::CHILD_MODULE {
            found[1] = true;
        } else if name == crate::bootmod::WORKER_MODULE {
            found[2] = true;
        } else if name == crate::bootmod::GFX_MODULE {
            found[3] = true;
        } else if name == crate::bootmod::NET_MODULE {
            found[4] = true;
        } else if name == crate::bootmod::LINUX_MODULE {
            found[5] = true;
        } else {
            return Err(VfsError::Corrupt);
        }
    }
    if boot_entries != 6 || !found.iter().all(|seen| *seen) {
        return Err(VfsError::Corrupt);
    }
    // Path grammar is enforced at this boundary too.
    if stat_path(b"boot/init") != Err(VfsError::BadPath) {
        return Err(VfsError::Corrupt);
    }
    // Notification wiring: the VFS itself must publish to a live watch, not just
    // the notify table's own self-test.
    let watched_dir = mkdir_path(b"/selftest.dir")?;
    let watch = notify::watch(watched_dir)?;
    let mut events = [notify::NotifyEvent::empty(); 4];
    create_path(b"/selftest.dir/a")?;
    if notify::drain(watch, &mut events)? != 1
        || events[0].kind != notify::NotifyKind::Created
        || events[0].child.as_bytes() != b"a"
    {
        return Err(VfsError::Corrupt);
    }
    // A rename inside one directory is a single `Renamed` carrying the new name
    // (the ABI and the init's watch fixture agree on that); only a move between
    // different directories publishes a second event to the new parent.
    rename_path(b"/selftest.dir/a", b"/selftest.dir/b")?;
    if notify::drain(watch, &mut events)? != 1
        || events[0].kind != notify::NotifyKind::Renamed
        || events[0].child.as_bytes() != b"b"
    {
        return Err(VfsError::Corrupt);
    }
    unlink_path(b"/selftest.dir/b")?;
    if notify::drain(watch, &mut events)? != 1
        || events[0].kind != notify::NotifyKind::Deleted
        || events[0].child.as_bytes() != b"b"
    {
        return Err(VfsError::Corrupt);
    }
    notify::unwatch(watch)?;
    rmdir_path(b"/selftest.dir")?;
    lock::selftest()?;
    notify::selftest()?;
    Ok(())
}

/// Internal helper used by `selftest` to prove the boot mount refuses writes
/// through the ordinary path API without opening a description.
fn write_path_for_test(raw_path: &[u8], data: &[u8]) -> Result<(), VfsError> {
    let state = require_ready()?;
    let id = resolve(state, raw_path)?;
    write_node(state, id, 0, data)?;
    Ok(())
}

/// Read-only helper for the root integration: path of the init payload.
pub const INIT_PATH: &[u8] = b"/boot/init";
/// Read-only helper for the root integration: path of the child payload.
pub const CHILD_PATH: &[u8] = b"/boot/child";

#[cfg(test)]
mod tests {
    use super::*;

    fn fresh() -> std::sync::MutexGuard<'static, ()> {
        let guard = test_lock();
        rebuild();
        guard
    }

    /// Reset the VFS static and build the minimal M4 namespace without taking the
    /// test lock again (callers already hold it).
    fn rebuild() {
        test_reset();
        pagecache::init();
        lock::clear();
        notify::clear();
        disk::reset();
        let mut table = Table::new();
        let root = table
            .alloc(Kind::Directory, Id::NONE, b"", Backing::Ram)
            .unwrap();
        let boot = table
            .alloc(Kind::Directory, root, b"boot", Backing::Ram)
            .unwrap();
        ramfs::create_boot_node(&mut table, boot, b"init", 24).unwrap();
        ramfs::create_boot_node(&mut table, boot, b"child", 8).unwrap();
        pseudo::install(&mut table, root).unwrap();
        {
            let published = state();
            published.ready = true;
            published.root = root;
            published.boot = boot;
            published.table = table;
            published.opens = open::Table::new();
        }
    }

    #[test]
    fn ramfs_round_trip_and_holes() {
        let _guard = fresh();
        create_path(b"/file").unwrap();
        let open = open_path(b"/file", OpenOptions::create_write()).unwrap();
        assert_eq!(write(open, b"abc").unwrap(), 3);
        assert_eq!(seek(open, 0).unwrap(), 0);
        let mut buffer = [0u8; 3];
        assert_eq!(read(open, &mut buffer).unwrap(), 3);
        assert_eq!(&buffer, b"abc");
        close(open).unwrap();

        let mut hole = [0xFFu8; 2];
        assert_eq!(read_path(b"/file", 3, &mut hole).unwrap(), 0);
        // Extend past a whole page: the untouched page in between reads zero.
        let extender = open_path(b"/file", OpenOptions::read_write()).unwrap();
        seek(extender, 4096).unwrap();
        assert_eq!(write(extender, b"z").unwrap(), 1);
        close(extender).unwrap();
        // Bytes 3..4096 were never written: they must read as zeros, not as EOF.
        assert_eq!(read_path(b"/file", 3, &mut hole).unwrap(), 2);
        assert_eq!(hole, [0, 0]);
        assert_eq!(stat_path(b"/file").unwrap().size, 4097);
    }

    #[test]
    fn independent_opens_do_not_share_offsets_but_dup_does() {
        let _guard = fresh();
        create_path(b"/f").unwrap();
        let a = open_path(b"/f", OpenOptions::create_write()).unwrap();
        write(a, b"0123456789").unwrap();
        seek(a, 3).unwrap();
        let b = open_path(b"/f", OpenOptions::read_only()).unwrap();
        assert_eq!(offset(b).unwrap(), 0);
        let duped = dup(a).unwrap();
        assert_eq!(offset(duped).unwrap(), 3);
        close(a).unwrap();
        assert_eq!(offset(duped).unwrap(), 3);
        close(duped).unwrap();
        close(b).unwrap();
    }

    #[test]
    fn boot_mount_is_read_only_and_sized() {
        let _guard = fresh();
        let stat = stat_path(b"/boot/init").unwrap();
        assert_eq!(stat.kind, Kind::File);
        assert_eq!(stat.size, 24);
        assert!(stat.read_only);
        assert_eq!(
            open_path(b"/boot/init", OpenOptions::read_write()).unwrap_err(),
            VfsError::ReadOnly
        );
        assert_eq!(unlink_path(b"/boot/init").unwrap_err(), VfsError::ReadOnly);
        assert_eq!(
            read_path(b"/boot/init", 0, &mut [0u8; 4]).unwrap_err(),
            VfsError::NotSupported
        );
    }

    #[test]
    fn rename_replaces_and_invalidates_the_old_pages() {
        let _guard = fresh();
        create_path(b"/a").unwrap();
        let open = open_path(b"/a", OpenOptions::create_write()).unwrap();
        write(open, b"aaaa").unwrap();
        close(open).unwrap();
        create_path(b"/b").unwrap();
        let open = open_path(b"/b", OpenOptions::create_write()).unwrap();
        write(open, b"bb").unwrap();
        close(open).unwrap();
        rename_path(b"/a", b"/b").unwrap();
        assert_eq!(stat_path(b"/b").unwrap().size, 4);
        let mut buffer = [0u8; 4];
        assert_eq!(read_path(b"/b", 0, &mut buffer).unwrap(), 4);
        assert_eq!(&buffer, b"aaaa");
        assert_eq!(stat_path(b"/a").unwrap_err(), VfsError::NotFound);
    }

    #[test]
    fn read_all_requires_a_large_enough_buffer() {
        let _guard = fresh();
        create_path(b"/x").unwrap();
        let mut buffer = [0u8; 16];
        assert_eq!(read_all_path(b"/x", &mut buffer).unwrap(), 0);
        let open = open_path(b"/x", OpenOptions::create_write()).unwrap();
        write(open, b"0123456789ab").unwrap();
        close(open).unwrap();
        assert_eq!(read_all_path(b"/x", &mut buffer).unwrap(), 12);
        assert_eq!(&buffer[..12], b"0123456789ab");
        assert_eq!(
            read_all_path(b"/x", &mut buffer[..4]).unwrap_err(),
            VfsError::BadOffset
        );
    }

    #[test]
    fn directory_operations_and_quota() {
        let _guard = fresh();
        mkdir_path(b"/dir").unwrap();
        create_path(b"/dir/file").unwrap();
        let mut entries = [DirEntry::empty(); 4];
        assert_eq!(readdir_path(b"/dir", 0, &mut entries).unwrap(), 1);
        assert_eq!(entries[0].name(), b"file");
        assert_eq!(unlink_path(b"/dir").unwrap_err(), VfsError::Busy);
        unlink_path(b"/dir/file").unwrap();
        rmdir_path(b"/dir").unwrap();
        assert_eq!(stat_path(b"/dir").unwrap_err(), VfsError::NotFound);
    }

    #[test]
    fn xattr_budget_is_enforced() {
        let _guard = fresh();
        create_path(b"/x").unwrap();
        xattr_set(b"/x", b"a", b"1").unwrap();
        xattr_set(b"/x", b"b", b"2").unwrap();
        assert_eq!(xattr_set(b"/x", b"c", b"3").unwrap_err(), VfsError::Quota);
        xattr_set(b"/x", b"a", b"11").unwrap();
        let mut value = [0u8; MAX_XATTR_VALUE];
        assert_eq!(xattr_get(b"/x", b"a", &mut value).unwrap(), 2);
        assert_eq!(&value[..2], b"11");
        xattr_remove(b"/x", b"a").unwrap();
        assert_eq!(
            xattr_get(b"/x", b"a", &mut value).unwrap_err(),
            VfsError::NotFound
        );
    }

    #[test]
    fn bad_paths_and_missing_nodes_are_reported() {
        let _guard = fresh();
        assert_eq!(stat_path(b"relative").unwrap_err(), VfsError::BadPath);
        assert_eq!(stat_path(b"/nope").unwrap_err(), VfsError::NotFound);
        assert_eq!(
            read_path(b"/nope", 0, &mut [0u8; 1]).unwrap_err(),
            VfsError::NotFound
        );
        create_path(b"/f").unwrap();
        assert_eq!(read_path(b"/f", 0, &mut []).unwrap(), 0);
    }

    #[test]
    fn child_operations_reject_trailing_slashes() {
        // Path parsing collapses trailing slashes for reads, but operations that
        // name a child entry (create/mkdir/unlink/rmdir/rename, and `open` with
        // `create`) must reject them: `/x/` does not name the entry `x`.
        let _guard = fresh();
        assert_eq!(create_path(b"/a/").unwrap_err(), VfsError::BadPath);
        assert_eq!(mkdir_path(b"/d/").unwrap_err(), VfsError::BadPath);
        assert_eq!(
            open_path(b"/o/", OpenOptions::create_write()).unwrap_err(),
            VfsError::BadPath
        );
        create_path(b"/f").unwrap();
        assert_eq!(unlink_path(b"/f/").unwrap_err(), VfsError::BadPath);
        assert_eq!(rmdir_path(b"/d/").unwrap_err(), VfsError::BadPath);
        assert_eq!(rename_path(b"/f/", b"/g").unwrap_err(), VfsError::BadPath);
        assert_eq!(rename_path(b"/f", b"/g/").unwrap_err(), VfsError::BadPath);
        // The entry itself is untouched by the rejected calls.
        assert_eq!(stat_path(b"/f").unwrap().size, 0);
        // A plain open still tolerates a trailing slash, as before.
        assert!(open_path(b"/f/", OpenOptions::read_only()).is_ok());
    }

    #[test]
    fn init_refuses_to_run_on_the_host() {
        let _guard = fresh();
        // `bootmod` is never initialised in a host test, so the real entry point
        // must refuse instead of building a half-populated mount table.
        assert_eq!(init().unwrap_err(), VfsError::NotSupported);
    }

    #[test]
    fn directory_watches_see_create_rename_and_unlink() {
        let _guard = fresh();
        let dir = mkdir_path(b"/dir").unwrap();
        let watch = notify::watch(dir).unwrap();
        let mut events = [notify::NotifyEvent::empty(); 8];

        create_path(b"/dir/a").unwrap();
        assert_eq!(notify::drain(watch, &mut events).unwrap(), 1);
        assert_eq!(events[0].directory, dir);
        assert_eq!(events[0].kind, notify::NotifyKind::Created);
        assert_eq!(events[0].child.as_bytes(), b"a");

        // A rename inside one directory is a single event carrying the new name:
        // the ABI and the init fixture count exactly one `Renamed` per rename.
        rename_path(b"/dir/a", b"/dir/b").unwrap();
        assert_eq!(notify::drain(watch, &mut events).unwrap(), 1);
        assert_eq!(events[0].kind, notify::NotifyKind::Renamed);
        assert_eq!(events[0].child.as_bytes(), b"b");

        unlink_path(b"/dir/b").unwrap();
        assert_eq!(notify::drain(watch, &mut events).unwrap(), 1);
        assert_eq!(events[0].kind, notify::NotifyKind::Deleted);
        assert_eq!(events[0].child.as_bytes(), b"b");
    }

    #[test]
    fn neutral_reset_clears_the_published_state_in_place() {
        let _guard = fresh();
        assert!(is_ready());
        neutral_reset();
        assert!(!is_ready());
        assert_eq!(root().unwrap_err(), VfsError::NotSupported);
        assert_eq!(
            read_path(b"/boot/init", 0, &mut [0u8; 1]).unwrap_err(),
            VfsError::NotSupported
        );
    }

    #[test]
    fn open_path_rejects_truncate_without_write() {
        let _guard = fresh();
        create_path(b"/t").unwrap();
        let bad = OpenOptions {
            read: true,
            write: false,
            create: false,
            truncate: true,
        };
        assert_eq!(
            open_path(b"/t", bad).unwrap_err(),
            VfsError::PermissionDenied
        );
        assert_eq!(stat_path(b"/t").unwrap().size, 0);
    }

    /// Format a host memory disk with a real FAT32 (64 MiB) or ext2 (32 MiB)
    /// volume, exactly the geometry the M5b acceptance disks use.
    fn disk_device(kind: disk::Kind) -> disk::Device {
        match kind {
            disk::Kind::Fat32 => {
                let mut device = block::test_support::MemDisk::new(131_072, 512);
                {
                    let mounted = fat32::format(&mut device, &fat32::FormatOptions::default())
                        .expect("format FAT32 volume");
                    drop(mounted);
                }
                device
            }
            disk::Kind::Ext2 => {
                let mut device = block::test_support::MemDisk::new(65_536, 512);
                ext2::format(&mut device).expect("format ext2 volume");
                device
            }
        }
    }

    fn mount_kind(kind: disk::Kind) {
        let device = disk_device(kind);
        match kind {
            disk::Kind::Fat32 => mount_fat32(device).unwrap(),
            disk::Kind::Ext2 => mount_ext2(device).unwrap(),
        }
    }

    /// Join a mount point (`/fat/` or `/ext2/`) and a file name into `buffer`.
    fn disk_path<'a>(dir: &[u8], name: &[u8], buffer: &'a mut [u8]) -> &'a [u8] {
        let len = dir.len() + name.len();
        buffer[..dir.len()].copy_from_slice(dir);
        buffer[dir.len()..len].copy_from_slice(name);
        &buffer[..len]
    }

    fn disk_volume_round_trip(kind: disk::Kind, dir: &[u8], name: &[u8]) {
        let _guard = fresh();
        mount_kind(kind);
        let mut buffer = [0u8; 64];
        let path = disk_path(dir, name, &mut buffer);
        create_path(path).unwrap();
        assert_eq!(stat_path(path).unwrap().size, 0);
        let open = open_path(path, OpenOptions::read_write()).unwrap();
        assert_eq!(write(open, b"CAELUM-M5B-V1").unwrap(), 13);
        assert_eq!(seek(open, 0).unwrap(), 0);
        let mut read_back = [0u8; 13];
        assert_eq!(read(open, &mut read_back).unwrap(), 13);
        assert_eq!(&read_back, b"CAELUM-M5B-V1");
        close(open).unwrap();
        assert_eq!(stat_path(path).unwrap().size, 13);
        // Write back, then read through a fresh description: the bytes must be
        // the same whether they come from the cache or from the medium.
        sync_path(path).unwrap();
        let mut verify = [0u8; 13];
        assert_eq!(read_path(path, 0, &mut verify).unwrap(), 13);
        assert_eq!(&verify, b"CAELUM-M5B-V1");
        // Grow past a whole page (filesystem must allocate across the page), then
        // shrink: the FS and the cache must agree on the resulting size.
        assert_eq!(truncate_path(path, 8192).unwrap(), 8192);
        assert_eq!(stat_path(path).unwrap().size, 8192);
        assert_eq!(truncate_path(path, 4608).unwrap(), 4608);
        assert_eq!(stat_path(path).unwrap().size, 4608);
        sync_all().unwrap();
    }

    #[test]
    fn fat32_volume_round_trip() {
        disk_volume_round_trip(disk::Kind::Fat32, b"/fat/", b"M5STATE.BIN");
    }

    #[test]
    fn ext2_volume_round_trip() {
        disk_volume_round_trip(disk::Kind::Ext2, b"/ext2/", b"m5state");
    }

    #[test]
    fn disk_bytes_survive_a_remount_of_the_same_device() {
        let _guard = fresh();
        mount_kind(disk::Kind::Fat32);
        create_path(b"/fat/M5DATA.BIN").unwrap();
        let open = open_path(b"/fat/M5DATA.BIN", OpenOptions::read_write()).unwrap();
        let mut chunk = [0u8; 256];
        for (index, slot) in chunk.iter_mut().enumerate() {
            *slot = ((index * 13 + 7) % 251) as u8;
        }
        assert_eq!(write(open, &chunk).unwrap(), 256);
        close(open).unwrap();
        sync_path(b"/fat/M5DATA.BIN").unwrap();
        let device = unmount_for_test(disk::Kind::Fat32).unwrap();
        // Drop every cached page and rebuild the namespace, then remount the very
        // same medium: a successful read now proves the bytes were written.
        rebuild();
        mount_fat32(device).unwrap();
        let mut verify = [0u8; 256];
        assert_eq!(read_path(b"/fat/M5DATA.BIN", 0, &mut verify).unwrap(), 256);
        assert_eq!(verify, chunk);
        assert_eq!(stat_path(b"/fat/M5DATA.BIN").unwrap().size, 256);
    }

    #[test]
    fn disk_rename_keeps_identity_and_content() {
        let _guard = fresh();
        mount_kind(disk::Kind::Fat32);
        create_path(b"/fat/M5DATA.BIN").unwrap();
        let open = open_path(b"/fat/M5DATA.BIN", OpenOptions::read_write()).unwrap();
        write(open, b"pattern").unwrap();
        close(open).unwrap();
        sync_path(b"/fat/M5DATA.BIN").unwrap();
        rename_path(b"/fat/M5DATA.BIN", b"/fat/M5DONE.BIN").unwrap();
        assert_eq!(stat_path(b"/fat/M5DATA.BIN"), Err(VfsError::NotFound));
        assert_eq!(stat_path(b"/fat/M5DONE.BIN").unwrap().size, 7);
        let mut verify = [0u8; 7];
        assert_eq!(read_path(b"/fat/M5DONE.BIN", 0, &mut verify).unwrap(), 7);
        assert_eq!(&verify, b"pattern");
        // The rename must not detach the page-cache identity from the file: a
        // truncate after the rename still reaches the same inode.
        assert_eq!(truncate_path(b"/fat/M5DONE.BIN", 3).unwrap(), 3);
        assert_eq!(stat_path(b"/fat/M5DONE.BIN").unwrap().size, 3);
        sync_all().unwrap();
    }

    #[test]
    fn cross_mount_rename_is_refused() {
        let _guard = fresh();
        mount_kind(disk::Kind::Fat32);
        mount_kind(disk::Kind::Ext2);
        create_path(b"/fat/A.BIN").unwrap();
        assert_eq!(
            rename_path(b"/fat/A.BIN", b"/ext2/a"),
            Err(VfsError::NotSupported)
        );
        assert_eq!(
            rename_path(b"/fat/A.BIN", b"/ram-a"),
            Err(VfsError::NotSupported)
        );
        assert_eq!(stat_path(b"/fat/A.BIN").unwrap().size, 0);
    }

    #[test]
    fn mount_points_cannot_be_removed_or_moved() {
        let _guard = fresh();
        mount_kind(disk::Kind::Fat32);
        // The mount point is structural: removing it would leave a `used` mount
        // slot whose root is unreachable, and a re-mount would then report Busy.
        assert_eq!(rmdir_path(b"/fat").unwrap_err(), VfsError::Busy);
        assert_eq!(stat_path(b"/fat").unwrap().kind, NodeKind::Directory);
        assert_eq!(
            rename_path(b"/fat", b"/x").unwrap_err(),
            VfsError::Busy,
            "a mount point may not be renamed away"
        );
        mkdir_path(b"/x").unwrap();
        assert_eq!(
            rename_path(b"/x", b"/fat").unwrap_err(),
            VfsError::Busy,
            "a mount point may not be replaced by a rename target"
        );
        // Nothing was mutated by the rejected calls.
        assert_eq!(stat_path(b"/x").unwrap().kind, NodeKind::Directory);
        assert_eq!(stat_path(b"/fat").unwrap().kind, NodeKind::Directory);
        // Ordinary directories and entries inside a mount keep working.
        rmdir_path(b"/x").unwrap();
        assert_eq!(stat_path(b"/x"), Err(VfsError::NotFound));
        create_path(b"/fat/ENTRY.BIN").unwrap();
        rename_path(b"/fat/ENTRY.BIN", b"/fat/MOVED.BIN").unwrap();
        assert_eq!(stat_path(b"/fat/MOVED.BIN").unwrap().size, 0);
        unlink_path(b"/fat/MOVED.BIN").unwrap();
        assert_eq!(stat_path(b"/fat/MOVED.BIN"), Err(VfsError::NotFound));
        // The mount is still reachable through its mount point.
        assert_eq!(stat_path(b"/fat").unwrap().kind, NodeKind::Directory);
    }

    #[test]
    fn clear_disk_sticky_reports_no_error_for_unmounted_volumes() {
        let _guard = fresh();
        assert_eq!(clear_disk_sticky(disk::Kind::Fat32), None);
        assert_eq!(clear_disk_sticky(disk::Kind::Ext2), None);
    }

    #[test]
    fn disk_mounts_are_not_implicitly_available() {
        let _guard = fresh();
        assert_eq!(stat_path(b"/fat"), Err(VfsError::NotFound));
        assert_eq!(stat_path(b"/ext2"), Err(VfsError::NotFound));
        assert_eq!(
            read_path(b"/fat/M5STATE.BIN", 0, &mut [0u8; 1]).unwrap_err(),
            VfsError::NotFound
        );
    }

    /// M5c1: one directory inside a real on-disk file system must support the
    /// whole create/enumerate/remove cycle, not just the mount root.
    fn disk_directory_closure(
        kind: disk::Kind,
        root: &[u8],
        dir_path: &[u8],
        dir_name: &[u8],
        child_path: &[u8],
        child_name: &[u8],
    ) {
        let _guard = fresh();
        mount_kind(kind);

        mkdir_path(dir_path).unwrap();
        assert_eq!(stat_path(dir_path).unwrap().kind, NodeKind::Directory);

        let mut entries = [DirEntry::empty(); 8];
        let count = readdir_path(root, 0, &mut entries).unwrap();
        assert!(count >= 1);
        assert!(
            entries[..count]
                .iter()
                .any(|entry| entry.name() == dir_name && entry.kind == NodeKind::Directory),
            "the new directory must appear in the mount root listing"
        );

        assert_eq!(stat_path(child_path), Err(VfsError::NotFound));
        create_path(child_path).unwrap();
        let open = open_path(child_path, OpenOptions::read_write()).unwrap();
        assert_eq!(write(open, b"nested").unwrap(), 6);
        assert_eq!(seek(open, 0).unwrap(), 0);
        let mut bytes = [0u8; 6];
        assert_eq!(read(open, &mut bytes).unwrap(), 6);
        assert_eq!(&bytes, b"nested");
        close(open).unwrap();
        // Writes are write-back: the on-disk directory entry only learns the new
        // size once the dirty page has been flushed.
        sync_all().unwrap();

        let count = readdir_path(dir_path, 0, &mut entries).unwrap();
        let child = entries[..count]
            .iter()
            .find(|entry| entry.name() == child_name)
            .expect("the child must appear in the subdirectory listing");
        assert_eq!(child.kind, NodeKind::File);
        assert_eq!(child.size, 6);

        assert_eq!(rmdir_path(dir_path).unwrap_err(), VfsError::NotEmpty);
        unlink_path(child_path).unwrap();
        rmdir_path(dir_path).unwrap();
        assert_eq!(stat_path(dir_path), Err(VfsError::NotFound));
        assert_eq!(rmdir_path(root).unwrap_err(), VfsError::Busy);
    }

    #[test]
    fn fat32_directories_create_enumerate_and_remove() {
        disk_directory_closure(
            disk::Kind::Fat32,
            b"/fat",
            b"/fat/M5CDIR",
            b"M5CDIR",
            b"/fat/M5CDIR/X.TXT",
            b"X.TXT",
        );
    }

    #[test]
    fn ext2_directories_create_enumerate_and_remove() {
        disk_directory_closure(
            disk::Kind::Ext2,
            b"/ext2",
            b"/ext2/m5cdir",
            b"m5cdir",
            b"/ext2/m5cdir/child",
            b"child",
        );
    }

    #[test]
    fn fat32_rename_moves_files_between_subdirectories() {
        let _guard = fresh();
        mount_kind(disk::Kind::Fat32);
        mkdir_path(b"/fat/M5CDIR").unwrap();
        mkdir_path(b"/fat/M5CDIR2").unwrap();
        create_path(b"/fat/M5CDIR/A.TXT").unwrap();
        write_path_for_test(b"/fat/M5CDIR/A.TXT", b"moved").unwrap();
        rename_path(b"/fat/M5CDIR/A.TXT", b"/fat/M5CDIR2/B.TXT").unwrap();
        assert_eq!(stat_path(b"/fat/M5CDIR/A.TXT"), Err(VfsError::NotFound));
        assert_eq!(stat_path(b"/fat/M5CDIR2/B.TXT").unwrap().size, 5);
        let mut bytes = [0u8; 5];
        assert_eq!(read_path(b"/fat/M5CDIR2/B.TXT", 0, &mut bytes).unwrap(), 5);
        assert_eq!(&bytes, b"moved");
        create_path(b"/fat/M5CDIR2/C.TXT").unwrap();
        assert_eq!(
            rename_path(b"/fat/M5CDIR2/C.TXT", b"/fat/M5CDIR2/B.TXT").unwrap_err(),
            VfsError::AlreadyExists,
            "a rename must not replace an existing on-disk target"
        );
        assert_eq!(stat_path(b"/fat/M5CDIR2/C.TXT").unwrap().size, 0);
    }

    #[test]
    fn ext2_rename_moves_files_between_subdirectories() {
        let _guard = fresh();
        mount_kind(disk::Kind::Ext2);
        mkdir_path(b"/ext2/m5cdir").unwrap();
        mkdir_path(b"/ext2/m5cdir2").unwrap();
        create_path(b"/ext2/m5cdir/a.txt").unwrap();
        write_path_for_test(b"/ext2/m5cdir/a.txt", b"moved").unwrap();
        rename_path(b"/ext2/m5cdir/a.txt", b"/ext2/m5cdir2/b.txt").unwrap();
        assert_eq!(stat_path(b"/ext2/m5cdir/a.txt"), Err(VfsError::NotFound));
        assert_eq!(stat_path(b"/ext2/m5cdir2/b.txt").unwrap().size, 5);
        let mut bytes = [0u8; 5];
        assert_eq!(read_path(b"/ext2/m5cdir2/b.txt", 0, &mut bytes).unwrap(), 5);
        assert_eq!(&bytes, b"moved");
        create_path(b"/ext2/m5cdir2/c.txt").unwrap();
        assert_eq!(
            rename_path(b"/ext2/m5cdir2/c.txt", b"/ext2/m5cdir2/b.txt").unwrap_err(),
            VfsError::AlreadyExists,
            "ext2 must report Exists for an occupied rename target"
        );
        assert_eq!(stat_path(b"/ext2/m5cdir2/c.txt").unwrap().size, 0);
    }

    /// M10a: `/bin` and `/lib` are a read-only namespace alias of the real
    /// directories on the ext2 volume, so a dynamically linked musl program can
    /// open the paths it was built for (and the kernel can load it) while the
    /// volume keeps its own mount point unchanged.
    #[test]
    fn bin_and_lib_alias_the_ext2_volume_read_only() {
        let _guard = fresh();
        mount_kind(disk::Kind::Ext2);
        mkdir_path(b"/ext2/bin").unwrap();
        mkdir_path(b"/ext2/lib").unwrap();
        create_path(b"/ext2/bin/busybox").unwrap();
        write_path_for_test(b"/ext2/bin/busybox", b"#!/bin/sh\n").unwrap();
        create_path(b"/ext2/lib/ld-musl-x86_64.so.1").unwrap();
        write_path_for_test(b"/ext2/lib/ld-musl-x86_64.so.1", b"\x7fELF\x02\x01").unwrap();
        sync_all().unwrap();

        // The alias directory itself is a directory, not a mounting point.
        assert_eq!(stat_path(b"/bin").unwrap().kind, NodeKind::Directory);
        assert_eq!(stat_path(b"/lib").unwrap().kind, NodeKind::Directory);

        // Children resolve to the very same on-disk files.
        assert_eq!(stat_path(b"/bin/busybox").unwrap().size, 10);
        assert_eq!(stat_path(b"/lib/ld-musl-x86_64.so.1").unwrap().size, 6);
        let mut script = [0u8; 10];
        assert_eq!(read_path(b"/bin/busybox", 0, &mut script).unwrap(), 10);
        assert_eq!(&script, b"#!/bin/sh\n");

        // `open` (openat) on an aliased path, then `read`, then `close`.
        let open = open_path(
            b"/lib/ld-musl-x86_64.so.1",
            OpenOptions {
                read: true,
                write: false,
                create: false,
                truncate: false,
            },
        )
        .unwrap();
        let mut magic = [0u8; 6];
        assert_eq!(read(open, &mut magic).unwrap(), 6);
        assert_eq!(&magic, b"\x7fELF\x02\x01");
        close(open).unwrap();

        // `readdir` lists the real ext2 entries, including the exact `/bin` form.
        let mut entries = [DirEntry::empty(); 8];
        let count = readdir_path(b"/bin", 0, &mut entries).unwrap();
        assert!(
            entries[..count]
                .iter()
                .any(|entry| entry.name() == b"busybox" && entry.kind == NodeKind::File),
            "the alias must list the real ext2 directory"
        );

        // `/ext2/...` is untouched by the alias, and a missing child is still
        // reported as such.
        assert_eq!(stat_path(b"/ext2/bin/busybox").unwrap().size, 10);
        assert_eq!(stat_path(b"/bin/missing"), Err(VfsError::NotFound));

        // The alias is read-only: no operation may mutate the ext2 volume
        // through a name the caller did not spell.
        assert_eq!(create_path(b"/bin/extra"), Err(VfsError::ReadOnly));
        assert_eq!(mkdir_path(b"/lib/private"), Err(VfsError::ReadOnly));
        assert_eq!(unlink_path(b"/bin/busybox"), Err(VfsError::ReadOnly));
        assert_eq!(truncate_path(b"/bin/busybox", 0), Err(VfsError::ReadOnly));
        assert_eq!(
            rename_path(b"/bin/busybox", b"/ext2/elsewhere"),
            Err(VfsError::ReadOnly)
        );
        assert_eq!(
            open_path(b"/bin/busybox", OpenOptions::read_write()).unwrap_err(),
            VfsError::ReadOnly
        );
        assert_eq!(stat_path(b"/bin/extra"), Err(VfsError::NotFound));
        assert_eq!(stat_path(b"/bin/busybox").unwrap().size, 10);
    }

    #[test]
    fn open_description_seek_truncate_sync_and_close() {
        let _guard = fresh();
        create_path(b"/seek.bin").unwrap();
        let open = open_path(b"/seek.bin", OpenOptions::read_write()).unwrap();
        assert_eq!(write(open, b"0123456789").unwrap(), 10);

        assert_eq!(seek_from(open, SeekFrom::Start(2)).unwrap(), 2);
        let mut two = [0u8; 2];
        assert_eq!(read(open, &mut two).unwrap(), 2);
        assert_eq!(&two, b"23");
        assert_eq!(seek_from(open, SeekFrom::Current(-1)).unwrap(), 3);
        assert_eq!(seek_from(open, SeekFrom::End(-5)).unwrap(), 5);
        assert_eq!(seek_from(open, SeekFrom::Start(0)).unwrap(), 0);
        assert_eq!(
            seek_from(open, SeekFrom::Current(-1)).unwrap_err(),
            VfsError::BadOffset,
            "a negative resulting offset is rejected"
        );
        assert_eq!(seek_from(open, SeekFrom::End(2)).unwrap(), 12);
        assert_eq!(write(open, b"!").unwrap(), 1);
        assert_eq!(stat_open(open).unwrap().size, 13);
        assert_eq!(truncate_open(open, 4).unwrap(), 4);
        assert_eq!(stat_path(b"/seek.bin").unwrap().size, 4);
        assert_eq!(sync_open(open), Ok(()));

        // Writing past EOF keeps the gap as a hole.
        assert_eq!(seek_from(open, SeekFrom::End(4)).unwrap(), 8);
        assert_eq!(write(open, b"Z").unwrap(), 1);
        assert_eq!(stat_path(b"/seek.bin").unwrap().size, 9);
        let mut zeros = [0u8; 4];
        assert_eq!(read_path(b"/seek.bin", 4, &mut zeros).unwrap(), 4);
        assert_eq!(zeros, [0u8; 4]);

        let id = open;
        close(id).unwrap();
        assert_eq!(offset(id).unwrap_err(), VfsError::NotFound);
        let mut dead = [0u8; 1];
        assert_eq!(read(id, &mut dead).unwrap_err(), VfsError::NotFound);
    }

    #[test]
    fn directories_open_read_only_and_serve_readdir() {
        let _guard = fresh();
        mkdir_path(b"/dir").unwrap();
        create_path(b"/dir/a").unwrap();

        let dir = open_path(b"/dir", OpenOptions::read_only()).unwrap();
        let mut entries = [DirEntry::empty(); 4];
        assert_eq!(readdir_open(dir, 0, &mut entries).unwrap(), 1);
        assert_eq!(entries[0].name(), b"a");
        assert_eq!(stat_open(dir).unwrap().kind, NodeKind::Directory);
        assert_eq!(stat_open(dir).unwrap().size, 0);

        let mut sink = [0u8; 4];
        assert_eq!(read(dir, &mut sink).unwrap_err(), VfsError::IsDirectory);
        assert_eq!(
            seek_from(dir, SeekFrom::Start(0)).unwrap_err(),
            VfsError::IsDirectory
        );
        close(dir).unwrap();

        assert_eq!(
            open_path(b"/dir", OpenOptions::write_only()).unwrap_err(),
            VfsError::IsDirectory,
            "a directory cannot be opened for writing"
        );
        assert_eq!(
            readdir_path(b"/dir/a", 0, &mut entries).unwrap_err(),
            VfsError::NotDirectory,
            "a regular file is not a directory"
        );
    }

    #[test]
    fn boot_payload_write_open_is_read_only() {
        let _guard = fresh();
        assert_eq!(
            open_path(INIT_PATH, OpenOptions::write_only()).unwrap_err(),
            VfsError::ReadOnly
        );
        let init = open_path(INIT_PATH, OpenOptions::read_only()).unwrap();
        assert!(stat_open(init).unwrap().read_only);
        close(init).unwrap();
    }

    #[test]
    fn dup_shares_the_seek_position() {
        let _guard = fresh();
        create_path(b"/dup.bin").unwrap();
        let one = open_path(b"/dup.bin", OpenOptions::read_write()).unwrap();
        assert_eq!(write(one, b"abcdef").unwrap(), 6);

        let two = dup(one).unwrap();
        assert_eq!(seek_from(one, SeekFrom::End(-2)).unwrap(), 4);
        assert_eq!(offset(two).unwrap(), 4);
        assert_eq!(seek_from(two, SeekFrom::Start(1)).unwrap(), 1);
        assert_eq!(offset(one).unwrap(), 1);

        close(two).unwrap();
        assert_eq!(offset(one).unwrap(), 1);
        close(one).unwrap();
    }

    #[test]
    fn unlinking_a_node_with_live_descriptions_is_busy() {
        let _guard = fresh();
        create_path(b"/pinned").unwrap();
        let open = open_path(b"/pinned", OpenOptions::read_write()).unwrap();
        assert_eq!(
            unlink_path(b"/pinned").unwrap_err(),
            VfsError::Busy,
            "M5c1 pins descriptions: an OpenId must never dangle"
        );
        assert!(stat_path(b"/pinned").is_ok(), "the file is still there");
        close(open).unwrap();
        unlink_path(b"/pinned").unwrap();
        assert_eq!(stat_path(b"/pinned").unwrap_err(), VfsError::NotFound);

        mkdir_path(b"/pinned.dir").unwrap();
        let dir = open_path(b"/pinned.dir", OpenOptions::read_only()).unwrap();
        assert_eq!(
            rmdir_path(b"/pinned.dir").unwrap_err(),
            VfsError::Busy,
            "an open directory description keeps the directory alive"
        );
        close(dir).unwrap();
        rmdir_path(b"/pinned.dir").unwrap();
    }

    #[test]
    fn mount_point_conflicts_with_an_existing_child() {
        let _guard = fresh();
        mkdir_path(b"/fat").unwrap();
        let stale = disk_device(disk::Kind::Fat32);
        assert_eq!(
            mount_fat32(stale).unwrap_err(),
            VfsError::Busy,
            "two children named `fat` would make the mount point ambiguous"
        );
        rmdir_path(b"/fat").unwrap();
        mount_kind(disk::Kind::Fat32);
        assert!(stat_path(b"/fat").is_ok());
    }

    #[test]
    fn create_quota_leaves_no_orphan_on_the_volume() {
        let _guard = fresh();
        mount_kind(disk::Kind::Fat32);
        let mut index = 0u32;
        let failure = loop {
            let text = std::format!("Q{index}.TXT");
            let mut buffer = [0u8; 64];
            let path = disk_path(b"/fat/", text.as_bytes(), &mut buffer);
            match create_path(path) {
                Ok(_) => index += 1,
                Err(error) => break (index, error),
            }
            assert!(index < 128, "the fixed tables must stop the loop");
        };
        assert_eq!(
            failure.1,
            VfsError::Quota,
            "a full table is a capacity limit"
        );
        // The refused name was never written: capacity is checked before mutation.
        let text = std::format!("Q{}.TXT", failure.0);
        let mut buffer = [0u8; 64];
        let path = disk_path(b"/fat/", text.as_bytes(), &mut buffer);
        assert_eq!(stat_path(path).unwrap_err(), VfsError::NotFound);

        // Prove it on the medium too: remount and look again.
        let device = unmount_for_test(disk::Kind::Fat32).unwrap();
        mount_fat32(device).unwrap();
        assert_eq!(stat_path(path).unwrap_err(), VfsError::NotFound);
    }

    #[test]
    fn directory_descriptions_refuse_seek_and_unreadable_readdir() {
        let _guard = fresh();
        create_path(b"/plain").unwrap();
        mkdir_path(b"/plain.dir").unwrap();
        let dir = open_path(b"/plain.dir", OpenOptions::read_only()).unwrap();
        assert_eq!(seek(dir, 0).unwrap_err(), VfsError::IsDirectory);
        assert_eq!(
            seek_from(dir, SeekFrom::Current(1)).unwrap_err(),
            VfsError::IsDirectory
        );
        close(dir).unwrap();

        let write_only = open_path(b"/plain", OpenOptions::write_only()).unwrap();
        let mut entries = [DirEntry::empty(); 2];
        assert_eq!(
            readdir_open(write_only, 0, &mut entries).unwrap_err(),
            VfsError::PermissionDenied,
            "readdir needs a readable description"
        );
        close(write_only).unwrap();
    }

    // -----------------------------------------------------------------------
    // M5c2: eager-mapping pins
    // -----------------------------------------------------------------------

    /// Cache key of a path, for tests that need to look inside the page cache.
    fn cache_key_of(raw_path: &[u8]) -> pagecache::CacheKey {
        let state = super::state();
        let id = super::resolve(state, raw_path).expect("resolve for cache key");
        state
            .table
            .get(id)
            .expect("node for cache key")
            .cache_key(id)
    }

    #[test]
    fn pinning_a_page_materialises_it_once_and_keeps_the_frame_stable() {
        let _guard = fresh();
        let path = b"/pinned.bin";
        create_path(path).unwrap();
        write_path_for_test(path, b"0123456789").unwrap();
        let reader = open_path(path, OpenOptions::read_only()).unwrap();

        let first = pin_file_page(reader, 0).unwrap();
        let second = pin_file_page(reader, 0).unwrap();
        assert_eq!(first, second, "the cached frame is stable while pinned");
        let key = cache_key_of(path);
        assert!(pagecache::is_resident(key, 0));
        assert_eq!(pagecache::pinned_count(key, 0), 2);

        unpin_file_page(reader, 0).unwrap();
        unpin_file_page(reader, 0).unwrap();
        assert_eq!(pagecache::pinned_count(key, 0), 0);
        assert_eq!(
            unpin_file_page(reader, 0).unwrap_err(),
            VfsError::NotFound,
            "an unpin without a matching pin is rejected"
        );
        close(reader).unwrap();
    }

    #[test]
    fn pinned_pages_survive_truncate_until_unpinned() {
        let _guard = fresh();
        let path = b"/pinned-trunc.bin";
        create_path(path).unwrap();
        write_path_for_test(path, b"abcdef").unwrap();
        let writer = open_path(path, OpenOptions::read_write()).unwrap();
        let key = cache_key_of(path);

        pin_file_page(writer, 0).unwrap();
        assert_eq!(truncate_open(writer, 0).unwrap_err(), VfsError::Busy);
        assert!(
            pagecache::is_resident(key, 0),
            "a refused truncate keeps the page"
        );
        let mut bytes = [0u8; 3];
        assert_eq!(seek(writer, 0).unwrap(), 0);
        assert_eq!(read(writer, &mut bytes).unwrap(), 3);
        assert_eq!(&bytes, b"abc");

        unpin_file_page(writer, 0).unwrap();
        assert_eq!(truncate_open(writer, 0).unwrap(), 0);
        assert!(!pagecache::is_resident(key, 0));
        close(writer).unwrap();
    }

    #[test]
    fn invalidate_refuses_pinned_pages() {
        let _guard = fresh();
        let path = b"/pinned-inv.bin";
        create_path(path).unwrap();
        write_path_for_test(path, b"abc").unwrap();
        let reader = open_path(path, OpenOptions::read_only()).unwrap();
        let key = cache_key_of(path);

        pin_file_page(reader, 0).unwrap();
        assert_eq!(pagecache::invalidate(key), Err(VfsError::Busy));
        assert!(pagecache::is_resident(key, 0));
        unpin_file_page(reader, 0).unwrap();
        assert_eq!(pagecache::invalidate(key), Ok(()));
        assert!(!pagecache::is_resident(key, 0));
        close(reader).unwrap();
    }

    // -----------------------------------------------------------------------
    // M6a2: releasing immutable boot payload pages
    // -----------------------------------------------------------------------

    /// Fake initramfs backing: every page of every module reads as `0xA5`.
    fn boot_payload_reader(
        _name: &[u8],
        _page_start: u64,
        page: &mut [u8],
    ) -> Result<(), VfsError> {
        page.fill(0xA5);
        Ok(())
    }

    fn install_boot_payload_reader() {
        initramfs::install_reader(boot_payload_reader);
    }

    #[test]
    fn release_boot_pages_drops_resident_payload_frames() {
        let _guard = fresh();
        install_boot_payload_reader();
        let key = cache_key_of(INIT_PATH);
        // `fresh` builds `/boot/init` with a 24-byte payload: one cache frame.
        let mut buffer = [0u8; 24];
        assert_eq!(read_path(INIT_PATH, 0, &mut buffer).unwrap(), 24);
        assert!(pagecache::is_resident(key, 0));

        assert_eq!(release_boot_pages(INIT_PATH), Ok(1));
        assert!(!pagecache::is_resident(key, 0), "the frame is handed back");
        assert_eq!(pagecache::resident_pages(key), 0);
        // Idempotent: having nothing left to release is not an error.
        assert_eq!(release_boot_pages(INIT_PATH), Ok(0));
        // The payload is immutable, so a later read simply re-fills the cache.
        assert_eq!(read_path(INIT_PATH, 0, &mut buffer).unwrap(), 24);
        assert_eq!(buffer, [0xA5; 24]);
        // A payload that was never staged holds no frame at all.
        assert_eq!(release_boot_pages(CHILD_PATH), Ok(0));

        initramfs::clear_reader();
    }

    #[test]
    fn release_boot_pages_refuses_pinned_and_writable_pages() {
        let _guard = fresh();
        install_boot_payload_reader();
        let key = cache_key_of(INIT_PATH);
        let reader = open_path(INIT_PATH, OpenOptions::read_only()).unwrap();
        pin_file_page(reader, 0).unwrap();
        assert_eq!(release_boot_pages(INIT_PATH), Err(VfsError::Busy));
        assert!(
            pagecache::is_resident(key, 0),
            "a refused release keeps the pinned frame"
        );
        unpin_file_page(reader, 0).unwrap();
        assert_eq!(release_boot_pages(INIT_PATH), Ok(1));
        close(reader).unwrap();

        // A ramfs file is writable: its cached page may be the only copy.
        create_path(b"/ram.bin").unwrap();
        write_path_for_test(b"/ram.bin", b"abcdef").unwrap();
        let ram_key = cache_key_of(b"/ram.bin");
        assert!(pagecache::is_resident(ram_key, 0));
        assert_eq!(release_boot_pages(b"/ram.bin"), Err(VfsError::NotSupported));
        assert!(
            pagecache::is_resident(ram_key, 0),
            "a refused release changes nothing"
        );

        // Directories are not payloads, and a path outside `/boot` must not look
        // like it was released.
        assert_eq!(release_boot_pages(b"/boot"), Err(VfsError::IsDirectory));
        assert_eq!(release_boot_pages(b"/elsewhere"), Err(VfsError::NotFound));
        // A missing `/boot` name can have no cached frame: no-op.
        assert_eq!(release_boot_pages(b"/boot/absent"), Ok(0));

        initramfs::clear_reader();
    }

    #[test]
    fn a_pinned_frame_observes_writes_through_the_cache() {
        let _guard = fresh();
        let path = b"/shared-view.bin";
        create_path(path).unwrap();
        write_path_for_test(path, b"ABCD").unwrap();
        let reader = open_path(path, OpenOptions::read_only()).unwrap();
        let writer = open_path(path, OpenOptions::read_write()).unwrap();

        let phys = pin_file_page(reader, 0).unwrap();
        assert_eq!(write(writer, b"xy").unwrap(), 2);
        // The mapping holds the very frame the cache writes into.
        let bytes = unsafe { core::slice::from_raw_parts(phys as *const u8, 4) };
        assert_eq!(bytes, b"xyCD");
        unpin_file_page(reader, 0).unwrap();
        close(reader).unwrap();
        close(writer).unwrap();
    }

    #[test]
    fn copy_page_zeroes_the_eof_tail() {
        let _guard = fresh();
        create_path(b"/tail.bin").unwrap();
        write_path_for_test(b"/tail.bin", b"abcde").unwrap();
        create_path(b"/scratch.bin").unwrap();
        write_path_for_test(b"/scratch.bin", b"x").unwrap();

        let source = open_path(b"/tail.bin", OpenOptions::read_only()).unwrap();
        let scratch = open_path(b"/scratch.bin", OpenOptions::read_only()).unwrap();
        let dst = pin_file_page(scratch, 0).unwrap();
        copy_file_page(source, 0, dst).unwrap();
        // Host frames are heap allocations addressed by their physical address.
        let frame = unsafe { core::slice::from_raw_parts(dst as *const u8, PAGE as usize) };
        assert_eq!(&frame[..5], b"abcde");
        assert!(
            frame[5..].iter().all(|byte| *byte == 0),
            "the end-of-file tail must be zeroed"
        );
        unpin_file_page(scratch, 0).unwrap();
        close(source).unwrap();
        close(scratch).unwrap();
    }

    #[test]
    fn copy_page_handles_a_later_page_and_rejects_bad_inputs() {
        let _guard = fresh();
        create_path(b"/multi.bin").unwrap();
        let mut data = [0u8; 5000];
        for (index, byte) in data.iter_mut().enumerate() {
            *byte = (index % 251) as u8;
        }
        write_path_for_test(b"/multi.bin", &data).unwrap();
        create_path(b"/dst.bin").unwrap();
        write_path_for_test(b"/dst.bin", b"x").unwrap();

        let source = open_path(b"/multi.bin", OpenOptions::read_only()).unwrap();
        let scratch = open_path(b"/dst.bin", OpenOptions::read_only()).unwrap();
        let dst = pin_file_page(scratch, 0).unwrap();
        copy_file_page(source, PAGE, dst).unwrap();
        let tail = 5000 - PAGE as usize;
        let frame = unsafe { core::slice::from_raw_parts(dst as *const u8, PAGE as usize) };
        assert_eq!(&frame[..tail], &data[PAGE as usize..]);
        assert!(frame[tail..].iter().all(|byte| *byte == 0));

        assert_eq!(
            copy_file_page(source, 1, dst).unwrap_err(),
            VfsError::BadOffset
        );
        assert_eq!(
            copy_file_page(source, PAGE * 2, dst).unwrap_err(),
            VfsError::BadOffset,
            "a page past the end of the file is rejected"
        );
        assert_eq!(
            copy_file_page(source, 0, 0).unwrap_err(),
            VfsError::BadOffset
        );
        unpin_file_page(scratch, 0).unwrap();
        close(source).unwrap();
        close(scratch).unwrap();
    }

    #[test]
    fn mark_file_page_dirty_does_not_flush_and_survives_unpin() {
        let _guard = fresh();
        mount_kind(disk::Kind::Fat32);
        let path = b"/fat/DIRTY.TXT";
        create_path(path).unwrap();
        write_path_for_test(path, b"AAAAAAAA").unwrap();
        sync_path(path).unwrap();
        let key = cache_key_of(path);
        assert_eq!(
            pagecache::page_info(key, 0).map(|(_, dirty)| dirty),
            Some(false)
        );

        let shared = open_path(path, OpenOptions::read_write()).unwrap();
        let phys = pin_file_page(shared, 0).unwrap();
        // A shared mapping writes straight into the frame; only the explicit
        // mark tells the cache about it.
        unsafe {
            core::ptr::copy_nonoverlapping(b"ZZZZ".as_ptr(), phys as *mut u8, 4);
        }
        mark_file_page_dirty(shared, 0).unwrap();
        assert_eq!(pagecache::page_info(key, 0), Some((phys, true)));

        unpin_file_page(shared, 0).unwrap();
        assert_eq!(
            pagecache::page_info(key, 0),
            Some((phys, true)),
            "unpin must not flush the page"
        );
        sync_path(path).unwrap();
        assert_eq!(
            pagecache::page_info(key, 0).map(|(_, dirty)| dirty),
            Some(false)
        );
        close(shared).unwrap();
    }

    #[test]
    fn marking_a_never_materialised_page_is_not_found() {
        let _guard = fresh();
        create_path(b"/sparse.bin").unwrap();
        truncate_path(b"/sparse.bin", 8192).unwrap();
        let reader = open_path(b"/sparse.bin", OpenOptions::read_write()).unwrap();
        assert_eq!(
            mark_file_page_dirty(reader, 0).unwrap_err(),
            VfsError::NotFound,
            "the mark never reads the backing store"
        );
        pin_file_page(reader, 0).unwrap();
        mark_file_page_dirty(reader, 0).unwrap();
        unpin_file_page(reader, 0).unwrap();
        close(reader).unwrap();
    }

    #[test]
    fn pinning_rejects_directories_and_bad_offsets() {
        let _guard = fresh();
        mkdir_path(b"/pin.dir").unwrap();
        let dir = open_path(b"/pin.dir", OpenOptions::read_only()).unwrap();
        assert_eq!(pin_file_page(dir, 0).unwrap_err(), VfsError::IsDirectory);
        assert_eq!(
            mark_file_page_dirty(dir, 0).unwrap_err(),
            VfsError::IsDirectory
        );
        close(dir).unwrap();

        create_path(b"/pin.bin").unwrap();
        write_path_for_test(b"/pin.bin", b"x").unwrap();
        let reader = open_path(b"/pin.bin", OpenOptions::read_only()).unwrap();
        assert_eq!(pin_file_page(reader, 1).unwrap_err(), VfsError::BadOffset);
        assert_eq!(
            pin_file_page(reader, PAGE).unwrap_err(),
            VfsError::BadOffset
        );
        close(reader).unwrap();
    }

    #[test]
    fn a_duplicated_description_keeps_pinning_after_the_original_close() {
        let _guard = fresh();
        let path = b"/mapped.bin";
        create_path(path).unwrap();
        write_path_for_test(path, b"hello").unwrap();
        let original = open_path(path, OpenOptions::read_only()).unwrap();
        // The mapping owns its own description, so closing the file handle does
        // not invalidate future pin/unpin/copy calls.
        let mapping = dup(original).unwrap();
        close(original).unwrap();
        let phys = pin_file_page(mapping, 0).unwrap();
        unpin_file_page(mapping, 0).unwrap();
        assert_eq!(unpin_file_page(mapping, 0).unwrap_err(), VfsError::NotFound);
        let _ = phys;
        close(mapping).unwrap();
    }

    #[test]
    fn unlink_refuses_a_pinned_page_without_touching_the_file_system() {
        let _guard = fresh();
        mount_kind(disk::Kind::Fat32);
        let path = b"/fat/PINNED.TXT";
        create_path(path).unwrap();
        write_path_for_test(path, b"payload").unwrap();
        sync_path(path).unwrap();
        let key = cache_key_of(path);
        // A pin whose description is already gone must still stop the unlink: the
        // dry run looks at the cache, not at the open table.
        pagecache::materialise(key, 7, 0, None).unwrap();
        pagecache::pin_page(9, key, 0).unwrap();
        assert_eq!(unlink_path(path), Err(VfsError::Busy));
        assert!(stat_path(path).is_ok(), "the entry must still exist");
        assert!(
            pagecache::is_resident(key, 0),
            "the cache must keep the page"
        );
        pagecache::unpin_page(9, key, 0).unwrap();
        unlink_path(path).unwrap();
        assert!(!pagecache::is_resident(key, 0));
    }

    #[test]
    fn rename_replacement_refuses_live_descriptions_and_pins() {
        let _guard = fresh();
        create_path(b"/src.txt").unwrap();
        write_path_for_test(b"/src.txt", b"src").unwrap();
        create_path(b"/dst.txt").unwrap();
        write_path_for_test(b"/dst.txt", b"dst").unwrap();
        let reader = open_path(b"/dst.txt", OpenOptions::read_only()).unwrap();
        assert_eq!(rename_path(b"/src.txt", b"/dst.txt"), Err(VfsError::Busy));
        assert!(stat_path(b"/src.txt").is_ok(), "the source must not move");
        assert!(stat_path(b"/dst.txt").is_ok(), "the target must survive");
        close(reader).unwrap();

        // A pin with no live description is still a refusal, and it happens before
        // the target VNode is released.
        let key = cache_key_of(b"/dst.txt");
        pagecache::materialise(key, 3, 0, None).unwrap();
        pagecache::pin_page(11, key, 0).unwrap();
        assert_eq!(rename_path(b"/src.txt", b"/dst.txt"), Err(VfsError::Busy));
        assert!(stat_path(b"/src.txt").is_ok());
        assert!(stat_path(b"/dst.txt").is_ok());
        pagecache::unpin_page(11, key, 0).unwrap();
        rename_path(b"/src.txt", b"/dst.txt").unwrap();
        assert_eq!(read_all_path(b"/dst.txt", &mut [0u8; 8]).unwrap(), 3);
    }

    #[test]
    fn close_releases_only_the_pins_of_its_own_description() {
        let _guard = fresh();
        let path = b"/two-opens.bin";
        create_path(path).unwrap();
        write_path_for_test(path, b"abcdef").unwrap();
        let first = open_path(path, OpenOptions::read_only()).unwrap();
        let second = open_path(path, OpenOptions::read_only()).unwrap();
        assert_ne!(first, second);
        let key = cache_key_of(path);
        let phys = pin_file_page(first, 0).unwrap();
        assert_eq!(pin_file_page(second, 0).unwrap(), phys);
        assert_eq!(pagecache::pinned_count(key, 0), 2);

        close(first).unwrap();
        assert_eq!(
            pagecache::pinned_count(key, 0),
            1,
            "closing one description must not release the other one's pin"
        );
        assert!(pagecache::is_resident(key, 0));
        assert_eq!(truncate_path(path, 0), Err(VfsError::Busy));

        close(second).unwrap();
        assert_eq!(pagecache::pinned_count(key, 0), 0);
        truncate_path(path, 0).unwrap();
    }

    #[test]
    fn close_with_a_pin_releases_it_instead_of_leaking() {
        let _guard = fresh();
        let path = b"/close-pin.bin";
        create_path(path).unwrap();
        write_path_for_test(path, b"data").unwrap();
        let only = open_path(path, OpenOptions::read_only()).unwrap();
        let key = cache_key_of(path);
        pin_file_page(only, 0).unwrap();
        assert_eq!(pagecache::pinned_count(key, 0), 1);
        // The object destroy hook cannot report errors, so the final close must
        // clean up the pins itself rather than leaving an unreachable frame.
        close(only).unwrap();
        assert_eq!(pagecache::pinned_count(key, 0), 0);
        assert_eq!(pagecache::owner_pins(only.raw()), 0);
        assert_eq!(unpin_file_page(only, 0).unwrap_err(), VfsError::NotFound);
        truncate_path(path, 0).unwrap();
    }

    #[test]
    fn copy_page_into_the_same_frame_only_clears_the_tail() {
        let _guard = fresh();
        let path = b"/self-copy.bin";
        create_path(path).unwrap();
        write_path_for_test(path, b"abcde").unwrap();
        let open = open_path(path, OpenOptions::read_only()).unwrap();
        let phys = pin_file_page(open, 0).unwrap();
        // Copying the page onto itself must not be UB and must not corrupt the
        // prefix; only the end-of-file tail is ruled by this function.
        copy_file_page(open, 0, phys).unwrap();
        let frame = unsafe { core::slice::from_raw_parts(phys as *const u8, PAGE as usize) };
        assert_eq!(&frame[..5], b"abcde");
        assert!(frame[5..].iter().all(|byte| *byte == 0));
        unpin_file_page(open, 0).unwrap();
        close(open).unwrap();
    }

    #[test]
    fn mark_file_page_dirty_requires_a_writable_description() {
        let _guard = fresh();
        mount_kind(disk::Kind::Fat32);
        let path = b"/fat/RIGHTS.TXT";
        create_path(path).unwrap();
        write_path_for_test(path, b"abcd").unwrap();
        sync_path(path).unwrap();
        let key = cache_key_of(path);

        let reader = open_path(path, OpenOptions::read_only()).unwrap();
        pin_file_page(reader, 0).unwrap();
        assert_eq!(
            mark_file_page_dirty(reader, 0).unwrap_err(),
            VfsError::PermissionDenied
        );
        assert_eq!(
            pagecache::page_info(key, 0).map(|(_, dirty)| dirty),
            Some(false),
            "a refused mark must not leave a permanent dirty page"
        );
        unpin_file_page(reader, 0).unwrap();

        let writer = open_path(path, OpenOptions::read_write()).unwrap();
        pin_file_page(writer, 0).unwrap();
        mark_file_page_dirty(writer, 0).unwrap();
        assert_eq!(
            pagecache::page_info(key, 0).map(|(_, dirty)| dirty),
            Some(true)
        );
        unpin_file_page(writer, 0).unwrap();
        close(reader).unwrap();
        close(writer).unwrap();

        // A read-only payload can never become dirty either. Host tests do not
        // install an initramfs reader, so its page cannot even be materialised:
        // the answer is `NotFound` and, critically, the page stays clean instead
        // of being marked and flushed into a read-only store.
        let boot = open_path(INIT_PATH, OpenOptions::read_only()).unwrap();
        assert_eq!(
            mark_file_page_dirty(boot, 0).unwrap_err(),
            VfsError::NotFound
        );
        assert_eq!(
            pagecache::page_info(cache_key_of(INIT_PATH), 0),
            None,
            "a read-only payload must not gain a dirty frame"
        );
        close(boot).unwrap();
    }

    #[test]
    fn unmount_refuses_pinned_cache_and_clears_it_on_success() {
        let _guard = fresh();
        mount_kind(disk::Kind::Fat32);
        let path = b"/fat/UMOUNT.TXT";
        create_path(path).unwrap();
        write_path_for_test(path, b"payload").unwrap();
        sync_path(path).unwrap();
        let key = cache_key_of(path);
        assert!(pagecache::is_resident(key, 0));

        pagecache::pin_page(13, key, 0).unwrap();
        assert!(matches!(
            unmount_for_test(disk::Kind::Fat32),
            Err(VfsError::Busy)
        ));
        assert!(stat_path(path).is_ok(), "the mount must still be usable");
        pagecache::unpin_page(13, key, 0).unwrap();

        unmount_for_test(disk::Kind::Fat32).unwrap();
        assert!(
            !pagecache::is_resident(key, 0),
            "a remount reuses the keys; a stale frame would alias the new volume"
        );
        assert_eq!(stat_path(path), Err(VfsError::NotFound));
    }

    #[test]
    fn open_path_as_owner_keeps_posix_locks_per_process() {
        let _guard = fresh();
        mount_kind(disk::Kind::Fat32);
        let file = open_path_as(b"/fat/LOCK.TXT", OpenOptions::create_write(), 0x21).unwrap();
        write(file, b"payload").unwrap();
        lock_open(
            file,
            lock::LockDomain::Posix,
            lock::LockKind::Exclusive,
            0,
            1,
        )
        .unwrap();
        // One owner never conflicts with itself, even through a new descriptor.
        let same_owner = open_path_as(b"/fat/LOCK.TXT", OpenOptions::read_write(), 0x21).unwrap();
        lock_open(
            same_owner,
            lock::LockDomain::Posix,
            lock::LockKind::Shared,
            0,
            1,
        )
        .unwrap();
        let stranger = open_path_as(b"/fat/LOCK.TXT", OpenOptions::read_write(), 0x22).unwrap();
        assert_eq!(
            lock_open(
                stranger,
                lock::LockDomain::Posix,
                lock::LockKind::Exclusive,
                0,
                1
            )
            .unwrap_err(),
            VfsError::WouldBlock
        );
        // Directories are not lockable.
        mkdir_path(b"/lockdir").unwrap();
        let dir = open_path(b"/lockdir", OpenOptions::read_only()).unwrap();
        assert_eq!(
            lock_open(dir, lock::LockDomain::Posix, lock::LockKind::Shared, 0, 0).unwrap_err(),
            VfsError::IsDirectory
        );
        close(dir).unwrap();
        close(stranger).unwrap();
        close(same_owner).unwrap();
        close(file).unwrap();
        assert_eq!(lock_count(), 0);
    }

    #[test]
    fn ofd_locks_belong_to_the_description_and_flock_is_separate() {
        let _guard = fresh();
        mount_kind(disk::Kind::Ext2);
        let first = open_path_as(b"/ext2/ofd", OpenOptions::create_write(), 0x31).unwrap();
        write(first, b"x").unwrap();
        let shared = dup(first).unwrap();
        let other = open_path_as(b"/ext2/ofd", OpenOptions::read_write(), 0x31).unwrap();
        lock_open(
            first,
            lock::LockDomain::OpenDescription,
            lock::LockKind::Exclusive,
            0,
            1,
        )
        .unwrap();
        lock_open(
            shared,
            lock::LockDomain::OpenDescription,
            lock::LockKind::Shared,
            0,
            1,
        )
        .unwrap();
        assert_eq!(
            lock_open(
                other,
                lock::LockDomain::OpenDescription,
                lock::LockKind::Exclusive,
                0,
                1
            )
            .unwrap_err(),
            VfsError::WouldBlock
        );
        // flock is its own domain and whole-file only.
        lock_open(
            first,
            lock::LockDomain::Flock,
            lock::LockKind::Exclusive,
            0,
            0,
        )
        .unwrap();
        assert_eq!(
            lock_open(first, lock::LockDomain::Flock, lock::LockKind::Shared, 1, 0).unwrap_err(),
            VfsError::BadOffset
        );
        assert_eq!(
            lock_open(first, lock::LockDomain::Flock, lock::LockKind::Shared, 0, 4).unwrap_err(),
            VfsError::BadOffset
        );
        // Dropping one handle of the shared description keeps its OFD lock.
        close(shared).unwrap();
        assert!(lock_count() > 0);
        unlock_open(other, lock::LockDomain::OpenDescription, 0, 1).unwrap();
        close(other).unwrap();
        close(first).unwrap();
        assert_eq!(lock_count(), 0);
    }

    #[test]
    fn closing_any_descriptor_drops_the_owners_posix_locks() {
        let _guard = fresh();
        mount_kind(disk::Kind::Fat32);
        let first = open_path_as(b"/fat/POSIX.TXT", OpenOptions::create_write(), 0x41).unwrap();
        write(first, b"x").unwrap();
        let second = open_path_as(b"/fat/POSIX.TXT", OpenOptions::read_write(), 0x41).unwrap();
        lock_open(
            first,
            lock::LockDomain::Posix,
            lock::LockKind::Exclusive,
            0,
            0,
        )
        .unwrap();
        assert_eq!(lock_count(), 1);
        close(second).unwrap();
        assert_eq!(
            lock_count(),
            0,
            "closing any descriptor drops that owner's POSIX locks"
        );
        close(first).unwrap();
    }

    #[test]
    fn closing_a_dup_releases_posix_locks_but_keeps_description_locks() {
        let _guard = fresh();
        mount_kind(disk::Kind::Fat32);
        let first = open_path_as(b"/fat/DUP.TXT", OpenOptions::create_write(), 0x81).unwrap();
        write(first, b"x").unwrap();
        let second = dup(first).unwrap();
        lock_open(
            first,
            lock::LockDomain::Posix,
            lock::LockKind::Exclusive,
            0,
            0,
        )
        .unwrap();
        lock_open(
            first,
            lock::LockDomain::OpenDescription,
            lock::LockKind::Exclusive,
            0,
            0,
        )
        .unwrap();
        lock_open(
            first,
            lock::LockDomain::Flock,
            lock::LockKind::Exclusive,
            0,
            0,
        )
        .unwrap();
        assert_eq!(lock_count(), 3);
        // Closing only the dup reference keeps the description alive, so its
        // OFD/flock locks survive while the owner's POSIX locks die (Linux).
        close(second).unwrap();
        assert_eq!(lock_count(), 2);
        assert!(
            lock_probe(
                first,
                lock::LockDomain::Posix,
                lock::LockKind::Exclusive,
                0,
                0
            )
            .unwrap()
            .is_none()
        );
        close(first).unwrap();
        assert_eq!(lock_count(), 0);
    }

    #[test]
    fn note_close_locks_releases_posix_locks_without_dropping_the_description() {
        let _guard = fresh();
        mount_kind(disk::Kind::Ext2);
        let first = open_path_as(b"/ext2/NOTE.TXT", OpenOptions::create_write(), 0x82).unwrap();
        write(first, b"x").unwrap();
        let second = dup(first).unwrap();
        lock_open(
            first,
            lock::LockDomain::Posix,
            lock::LockKind::Exclusive,
            0,
            0,
        )
        .unwrap();
        assert_eq!(lock_count(), 1);
        note_close_locks(second).unwrap();
        assert_eq!(lock_count(), 0);
        // The description itself is still usable through the remaining reference.
        assert_eq!(offset(second).unwrap(), offset(first).unwrap());
        // A stale id is reported instead of silently succeeding.
        let stale = open_path_as(b"/ext2/STALE.TXT", OpenOptions::create_write(), 0x82).unwrap();
        close(stale).unwrap();
        assert_eq!(note_close_locks(stale), Err(VfsError::NotFound));
        close(second).unwrap();
        close(first).unwrap();
    }

    #[test]
    fn lock_probe_reports_conflicts_without_requiring_access() {
        let _guard = fresh();
        mount_kind(disk::Kind::Fat32);
        // A write-only description may still query the POSIX lock state.
        let writer = open_path_as(b"/fat/PROBE.TXT", OpenOptions::create_write(), 0x91).unwrap();
        write(writer, b"x").unwrap();
        lock_open(
            writer,
            lock::LockDomain::Posix,
            lock::LockKind::Exclusive,
            10,
            10,
        )
        .unwrap();
        let read_only = open_path_as(b"/fat/PROBE.TXT", OpenOptions::read_only(), 0x92).unwrap();
        // A shared probe on a read-only description must not need write access.
        let conflict = lock_probe(
            read_only,
            lock::LockDomain::Posix,
            lock::LockKind::Shared,
            15,
            1,
        )
        .unwrap()
        .expect("an overlapping exclusive lock conflicts");
        assert_eq!(
            conflict,
            lock::LockConflict {
                owner: 0x91,
                start: 10,
                len: 10,
                kind: lock::LockKind::Exclusive,
            }
        );
        // Probing is read-only: the table did not change.
        assert_eq!(lock_count(), 1);
        // The same owner never conflicts with itself; a disjoint range is free.
        assert!(
            lock_probe(
                writer,
                lock::LockDomain::Posix,
                lock::LockKind::Shared,
                15,
                1
            )
            .unwrap()
            .is_none()
        );
        assert!(
            lock_probe(
                read_only,
                lock::LockDomain::Posix,
                lock::LockKind::Exclusive,
                20,
                5
            )
            .unwrap()
            .is_none()
        );
        // OFD probes use the description as the holder and report no process owner.
        lock_open(
            writer,
            lock::LockDomain::OpenDescription,
            lock::LockKind::Exclusive,
            0,
            4,
        )
        .unwrap();
        let ofd = lock_probe(
            read_only,
            lock::LockDomain::OpenDescription,
            lock::LockKind::Shared,
            1,
            1,
        )
        .unwrap()
        .expect("another description conflicts");
        assert_eq!(ofd.owner, 0);
        // Directories are not lockable and flock probes are whole-file only.
        mkdir_path(b"/probedir").unwrap();
        let dir = open_path(b"/probedir", OpenOptions::read_only()).unwrap();
        assert_eq!(
            lock_probe(dir, lock::LockDomain::Posix, lock::LockKind::Shared, 0, 0).unwrap_err(),
            VfsError::IsDirectory
        );
        assert_eq!(
            lock_probe(
                writer,
                lock::LockDomain::Flock,
                lock::LockKind::Shared,
                1,
                0
            )
            .unwrap_err(),
            VfsError::BadOffset
        );
        close(dir).unwrap();
        close(read_only).unwrap();
        close(writer).unwrap();
        assert_eq!(lock_count(), 0);
    }

    #[test]
    fn open_modes_reports_the_description_access_mode() {
        let _guard = fresh();
        create_path(b"/modes").unwrap();
        let read_only = open_path(b"/modes", OpenOptions::read_only()).unwrap();
        assert_eq!(open_modes(read_only).unwrap(), (true, false));
        close(read_only).unwrap();
        let write_only = open_path(b"/modes", OpenOptions::write_only()).unwrap();
        assert_eq!(open_modes(write_only).unwrap(), (false, true));
        let duped = dup(write_only).unwrap();
        assert_eq!(open_modes(duped).unwrap(), (false, true));
        close(duped).unwrap();
        close(write_only).unwrap();
        let read_write = open_path(b"/modes", OpenOptions::read_write()).unwrap();
        assert_eq!(open_modes(read_write).unwrap(), (true, true));
        close(read_write).unwrap();
        let stale = open_path(b"/modes", OpenOptions::read_only()).unwrap();
        close(stale).unwrap();
        assert_eq!(open_modes(stale), Err(VfsError::NotFound));
    }

    #[test]
    fn close_process_only_releases_its_own_locks_and_watches() {
        let _guard = fresh();
        mount_kind(disk::Kind::Fat32);
        create_path(b"/fat/A.TXT").unwrap();
        create_path(b"/fat/B.TXT").unwrap();
        let own = open_path_as(b"/fat/A.TXT", OpenOptions::read_write(), 0x51).unwrap();
        let other = open_path_as(b"/fat/B.TXT", OpenOptions::read_write(), 0x52).unwrap();
        lock_open(
            own,
            lock::LockDomain::Posix,
            lock::LockKind::Exclusive,
            0,
            0,
        )
        .unwrap();
        lock_open(
            other,
            lock::LockDomain::Posix,
            lock::LockKind::Exclusive,
            0,
            0,
        )
        .unwrap();
        mkdir_path(b"/watchdir").unwrap();
        let watch = watch_directory_as(b"/watchdir", 0x51).unwrap();
        assert_eq!(lock_count(), 2);
        assert_eq!(watch_count(), 1);
        assert_eq!(close_process(0x51), 1);
        assert_eq!(lock_count(), 1);
        assert_eq!(watch_count(), 0);
        close(own).unwrap();
        assert_eq!(close_process(0x52), 1);
        assert_eq!(lock_count(), 0);
        close(other).unwrap();
        let _ = watch;
    }

    #[test]
    fn watches_follow_the_directory_identity_and_die_with_it() {
        let _guard = fresh();
        mkdir_path(b"/watched").unwrap();
        let watch = watch_directory_as(b"/watched", 0x61).unwrap();
        assert_eq!(watch_count(), 1);
        let mut events = [notify::NotifyEvent::empty(); 4];
        assert!(watch_drain_owned(watch, 0x62, &mut events).is_err());
        // A rename keeps the watch: it is keyed by the directory's VNode id.
        rename_path(b"/watched", b"/moved").unwrap();
        assert_eq!(watch_count(), 1);
        create_path(b"/moved/child.txt").unwrap();
        assert_eq!(watch_drain_owned(watch, 0x61, &mut events).unwrap(), 1);
        unlink_path(b"/moved/child.txt").unwrap();
        rmdir_path(b"/moved").unwrap();
        assert_eq!(
            watch_count(),
            0,
            "removing the directory invalidates its watches"
        );
        assert!(watch_drain_owned(watch, 0x61, &mut events).is_err());
        assert_eq!(
            watch_unwatch_owned(watch, 0x61).unwrap_err(),
            VfsError::NotFound
        );
    }

    #[test]
    fn same_directory_rename_publishes_one_event_with_the_new_name() {
        let _guard = fresh();
        mkdir_path(b"/wd").unwrap();
        let watch = watch_directory_as(b"/wd", 0x71).unwrap();
        let mut events = [notify::NotifyEvent::empty(); 4];

        create_path(b"/wd/A.BIN").unwrap();
        assert_eq!(watch_drain_owned(watch, 0x71, &mut events).unwrap(), 1);
        assert_eq!(events[0].kind, notify::NotifyKind::Created);
        assert_eq!(events[0].child.as_bytes(), b"A.BIN");

        // One rename inside the same directory must be one event, with the new
        // name: the init counts exactly three events for create/rename/unlink.
        rename_path(b"/wd/A.BIN", b"/wd/B.BIN").unwrap();
        assert_eq!(watch_drain_owned(watch, 0x71, &mut events).unwrap(), 1);
        assert_eq!(events[0].kind, notify::NotifyKind::Renamed);
        assert_eq!(events[0].child.as_bytes(), b"B.BIN");

        unlink_path(b"/wd/B.BIN").unwrap();
        assert_eq!(watch_drain_owned(watch, 0x71, &mut events).unwrap(), 1);
        assert_eq!(events[0].kind, notify::NotifyKind::Deleted);
        assert_eq!(events[0].child.as_bytes(), b"B.BIN");

        watch_unwatch_owned(watch, 0x71).unwrap();
        assert_eq!(watch_count(), 0);
    }

    #[test]
    fn xattr_through_a_description_checks_rights_and_is_volatile() {
        let _guard = fresh();
        mount_kind(disk::Kind::Fat32);
        let writer = open_path(b"/fat/XATTR.TXT", OpenOptions::create_write()).unwrap();
        write(writer, b"x").unwrap();
        xattr_set_open(writer, b"user.tag", b"volatile").unwrap();
        let reader = open_path(b"/fat/XATTR.TXT", OpenOptions::read_only()).unwrap();
        let mut value = [0u8; MAX_XATTR_VALUE];
        let len = xattr_get_open(reader, b"user.tag", &mut value).unwrap();
        assert_eq!(&value[..len], b"volatile");
        assert_eq!(
            xattr_set_open(reader, b"user.tag", b"nope").unwrap_err(),
            VfsError::PermissionDenied
        );
        let write_only = open_path_as(b"/fat/XATTR.TXT", OpenOptions::write_only(), 0x71).unwrap();
        assert_eq!(
            xattr_get_open(write_only, b"user.tag", &mut value).unwrap_err(),
            VfsError::PermissionDenied
        );
        mkdir_path(b"/fat/D1").unwrap();
        let dir = open_path(b"/fat/D1", OpenOptions::read_only()).unwrap();
        assert_eq!(
            xattr_set_open(dir, b"user.dir", b"v").unwrap_err(),
            VfsError::PermissionDenied
        );
        close(dir).unwrap();
        assert_eq!(
            xattr_set(b"/fat/D1", b"user.dir", b"v").unwrap_err(),
            VfsError::IsDirectory
        );
        close(write_only).unwrap();
        close(reader).unwrap();
        close(writer).unwrap();
        // Attributes live only in the VNode table: a remount loses them.
        sync_all().unwrap();
        let device = unmount_for_test(disk::Kind::Fat32).unwrap();
        mount_fat32(device).unwrap();
        assert_eq!(
            xattr_get(b"/fat/XATTR.TXT", b"user.tag", &mut value).unwrap_err(),
            VfsError::NotFound
        );
    }

    // -- M8e: directory cursor held in the open description -----------------

    #[test]
    fn readdir_open_next_starts_with_dot_and_dotdot() {
        let _guard = fresh();
        mkdir_path(b"/next").unwrap();
        create_path(b"/next/only").unwrap();
        let open = open_path(b"/next", OpenOptions::read_only()).unwrap();
        let mut entries = [DirEntry::empty(); 3];
        assert_eq!(readdir_open_next(open, &mut entries).unwrap(), 3);
        assert_eq!(entries[0].name(), &b"."[..]);
        assert_eq!(entries[0].kind, Kind::Directory);
        assert_eq!(entries[1].name(), &b".."[..]);
        assert_eq!(entries[1].kind, Kind::Directory);
        assert_eq!(entries[2].name(), &b"only"[..]);
        assert_eq!(entries[2].kind, Kind::File);
        assert_eq!(offset(open).unwrap(), 3);
        close(open).unwrap();
    }

    #[test]
    fn readdir_open_next_continues_after_the_first_call() {
        let _guard = fresh();
        mkdir_path(b"/next").unwrap();
        create_path(b"/next/aaa").unwrap();
        create_path(b"/next/bbb").unwrap();
        let open = open_path(b"/next", OpenOptions::read_only()).unwrap();
        let mut entries = [DirEntry::empty(); 8];
        assert_eq!(readdir_open_next(open, &mut entries).unwrap(), 4);
        assert_eq!(entries[0].name(), &b"."[..]);
        assert_eq!(entries[1].name(), &b".."[..]);
        let third = entries[2].name();
        let fourth = entries[3].name();
        assert!(
            (third == &b"aaa"[..] && fourth == &b"bbb"[..])
                || (third == &b"bbb"[..] && fourth == &b"aaa"[..])
        );
        let mut extra = [DirEntry::empty(); 2];
        assert_eq!(readdir_open_next(open, &mut extra).unwrap(), 0);
        assert_eq!(offset(open).unwrap(), 4);
        close(open).unwrap();
    }

    #[test]
    fn readdir_open_next_leaves_the_cursor_at_end_of_directory() {
        let _guard = fresh();
        mkdir_path(b"/next").unwrap();
        let open = open_path(b"/next", OpenOptions::read_only()).unwrap();
        let mut two = [DirEntry::empty(); 2];
        assert_eq!(readdir_open_next(open, &mut two).unwrap(), 2);
        assert_eq!(offset(open).unwrap(), 2);
        assert_eq!(readdir_open_next(open, &mut two).unwrap(), 0);
        assert_eq!(offset(open).unwrap(), 2);
        close(open).unwrap();
    }

    #[test]
    fn independent_opens_restart_at_the_first_entry() {
        let _guard = fresh();
        mkdir_path(b"/next").unwrap();
        let first = open_path(b"/next", OpenOptions::read_only()).unwrap();
        let second = open_path(b"/next", OpenOptions::read_only()).unwrap();
        let mut one = [DirEntry::empty(); 1];
        assert_eq!(readdir_open_next(first, &mut one).unwrap(), 1);
        assert_eq!(one[0].name(), &b"."[..]);
        assert_eq!(readdir_open_next(second, &mut one).unwrap(), 1);
        assert_eq!(one[0].name(), &b"."[..]);
        assert_eq!(offset(first).unwrap(), 1);
        assert_eq!(offset(second).unwrap(), 1);
        assert_eq!(readdir_open_next(first, &mut one).unwrap(), 1);
        assert_eq!(one[0].name(), &b".."[..]);
        close(second).unwrap();
        close(first).unwrap();
    }

    #[test]
    fn dup_shares_the_directory_cursor() {
        let _guard = fresh();
        mkdir_path(b"/next").unwrap();
        let open = open_path(b"/next", OpenOptions::read_only()).unwrap();
        let duped = dup(open).unwrap();
        let mut one = [DirEntry::empty(); 1];
        assert_eq!(readdir_open_next(open, &mut one).unwrap(), 1);
        assert_eq!(one[0].name(), &b"."[..]);
        assert_eq!(readdir_open_next(duped, &mut one).unwrap(), 1);
        assert_eq!(one[0].name(), &b".."[..]);
        assert_eq!(offset(open).unwrap(), 2);
        assert_eq!(offset(duped).unwrap(), 2);
        close(duped).unwrap();
        close(open).unwrap();
    }

    #[test]
    fn short_buffers_return_one_entry_at_a_time_without_skipping() {
        let _guard = fresh();
        mkdir_path(b"/next").unwrap();
        create_path(b"/next/aaa").unwrap();
        create_path(b"/next/bbb").unwrap();
        let open = open_path(b"/next", OpenOptions::read_only()).unwrap();
        let mut one = [DirEntry::empty(); 1];
        let mut total = 0u64;
        let mut real = 0u32;
        loop {
            let count = readdir_open_next(open, &mut one).unwrap();
            if count == 0 {
                break;
            }
            assert_eq!(count, 1);
            match total {
                0 => assert_eq!(one[0].name(), &b"."[..]),
                1 => assert_eq!(one[0].name(), &b".."[..]),
                _ => {
                    assert!(
                        one[0].name() == &b"aaa"[..] || one[0].name() == &b"bbb"[..],
                        "unexpected entry"
                    );
                    real += 1;
                }
            }
            total += 1;
            assert_eq!(offset(open).unwrap(), total);
        }
        assert_eq!(total, 4);
        assert_eq!(real, 2);
        assert_eq!(offset(open).unwrap(), 4);
        close(open).unwrap();
    }

    #[test]
    fn readdir_open_next_reports_non_directories_and_empty_buffers() {
        let _guard = fresh();
        mkdir_path(b"/next").unwrap();
        create_path(b"/next/only").unwrap();
        let file = open_path(b"/next/only", OpenOptions::read_only()).unwrap();
        let mut one = [DirEntry::empty(); 1];
        assert_eq!(
            readdir_open_next(file, &mut one).unwrap_err(),
            VfsError::NotDirectory
        );
        close(file).unwrap();
        let dir = open_path(b"/next", OpenOptions::read_only()).unwrap();
        let mut none: [DirEntry; 0] = [];
        assert_eq!(readdir_open_next(dir, &mut none).unwrap(), 0);
        assert_eq!(offset(dir).unwrap(), 0);
        close(dir).unwrap();
    }

    // -- M8h: generated /proc and /dev namespace ------------------------------

    fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
        haystack
            .windows(needle.len())
            .any(|window| window == needle)
    }

    #[test]
    fn generated_proc_files_are_read_fresh_and_ignore_their_zero_size() {
        let _guard = fresh();
        let stat = stat_path(b"/proc/uptime").unwrap();
        assert_eq!(stat.kind, Kind::File);
        assert_eq!(stat.size, 0);
        assert!(stat.read_only);

        let mut first_buffer = [0u8; 192];
        let first_len = read_path(b"/proc/uptime", 0, &mut first_buffer).unwrap();
        let first = &first_buffer[..first_len];
        assert!(first.ends_with(b"\n"));
        assert!(contains_bytes(first, b"."));
        assert!(contains_bytes(first, b" "));

        // Nothing is cached: the second read generates the same text again.
        let mut second_buffer = [0u8; 192];
        let second_len = read_path(b"/proc/uptime", 0, &mut second_buffer).unwrap();
        assert_eq!(first_len, second_len);
        assert_eq!(first, &second_buffer[..second_len]);

        // The size-0 file still supports byte-offset reads into its generated
        // text (the size check must not cut it off at zero).
        let tail_start = (first_len - 2) as u64;
        let mut tail = [0u8; 2];
        assert_eq!(
            read_path(b"/proc/uptime", tail_start, &mut tail).unwrap(),
            2
        );
        assert_eq!(&tail, &first[first_len - 2..]);
        assert_eq!(
            read_path(b"/proc", 0, &mut tail).unwrap_err(),
            VfsError::IsDirectory
        );
    }

    #[test]
    fn proc_status_reports_the_expected_identity_lines() {
        let _guard = fresh();
        let mut buffer = [0u8; 192];
        let len = read_path(b"/proc/self/status", 0, &mut buffer).unwrap();
        let text = &buffer[..len];
        for line in [
            &b"Name:\tlinux\n"[..],
            &b"State:\t"[..],
            &b"Pid:\t"[..],
            &b"PPid:\t"[..],
            &b"Uid:\t0\t0\t0\t0\n"[..],
            &b"Gid:\t0\t0\t0\t0\n"[..],
            &b"Threads:\t1\n"[..],
        ] {
            assert!(contains_bytes(text, line));
        }
    }

    #[test]
    fn character_devices_report_their_numbers_and_have_linux_semantics() {
        let _guard = fresh();
        let null = stat_path(b"/dev/null").unwrap();
        assert_eq!(null.kind, Kind::CharDevice);
        assert_eq!((null.dev_major, null.dev_minor), (1, 3));
        assert_eq!(null.size, 0);
        assert!(!null.read_only);

        let zero = stat_path(b"/dev/zero").unwrap();
        assert_eq!(zero.kind, Kind::CharDevice);
        assert_eq!((zero.dev_major, zero.dev_minor), (1, 5));

        let mut buffer = [0xAAu8; 8];
        assert_eq!(read_path(b"/dev/null", 0, &mut buffer).unwrap(), 0);
        assert_eq!(buffer, [0xAAu8; 8]);
        assert_eq!(read_path(b"/dev/zero", 0, &mut buffer).unwrap(), 8);
        assert_eq!(buffer, [0u8; 8]);
        // A byte offset does not matter for character devices.
        assert_eq!(read_path(b"/dev/zero", 1234, &mut buffer).unwrap(), 8);
        assert_eq!(buffer, [0u8; 8]);

        let writer = open_path(b"/dev/null", OpenOptions::write_only()).unwrap();
        assert_eq!(write(writer, b"discard").unwrap(), 7);
        assert_eq!(offset(writer).unwrap(), 7);
        assert_eq!(seek(writer, 0).unwrap(), 0);
        close(writer).unwrap();

        // O_TRUNC on a character device is a no-op, not an error.
        assert_eq!(truncate_path(b"/dev/null", 4).unwrap(), 0);
        assert_eq!(truncate_path(b"/dev/zero", 4096).unwrap(), 0);

        // Character devices are not page-cache backed and cannot be mapped.
        let reader = open_path(b"/dev/zero", OpenOptions::read_only()).unwrap();
        assert_eq!(
            pin_file_page(reader, 0).unwrap_err(),
            VfsError::NotSupported
        );
        close(reader).unwrap();
    }

    #[test]
    fn generated_namespace_is_enumerable_and_refuses_structural_changes() {
        let _guard = fresh();
        let mut entries = [DirEntry::empty(); 8];
        let count = readdir_path(b"/", 0, &mut entries).unwrap();
        let root = &entries[..count];
        assert!(root.iter().any(|entry| entry.name() == &b"boot"[..]));
        assert!(root.iter().any(|entry| entry.name() == &b"proc"[..]));
        assert!(root.iter().any(|entry| entry.name() == &b"dev"[..]));

        let proc = open_path(b"/proc", OpenOptions::read_only()).unwrap();
        let mut names = [DirEntry::empty(); 8];
        let mut listed = 0;
        loop {
            let read = readdir_open_next(proc, &mut names[listed..listed + 1]).unwrap();
            if read == 0 {
                break;
            }
            listed += read;
        }
        assert_eq!(listed, 4);
        let proc_entries = &names[..listed];
        assert!(
            proc_entries
                .iter()
                .any(|entry| entry.name() == &b"self"[..] && entry.kind == Kind::Directory)
        );
        assert!(
            proc_entries
                .iter()
                .any(|entry| entry.name() == &b"uptime"[..] && entry.kind == Kind::File)
        );
        close(proc).unwrap();

        let dev = open_path(b"/dev", OpenOptions::read_only()).unwrap();
        let mut names = [DirEntry::empty(); 8];
        let mut listed = 0;
        loop {
            let read = readdir_open_next(dev, &mut names[listed..listed + 1]).unwrap();
            if read == 0 {
                break;
            }
            listed += read;
        }
        assert_eq!(listed, 4);
        let dev_entries = &names[..listed];
        let null = dev_entries
            .iter()
            .find(|entry| entry.name() == &b"null"[..])
            .expect("null entry");
        assert_eq!(null.kind, Kind::CharDevice);
        assert_eq!((null.dev_major, null.dev_minor), (1, 3));
        let zero = dev_entries
            .iter()
            .find(|entry| entry.name() == &b"zero"[..])
            .expect("zero entry");
        assert_eq!(zero.kind, Kind::CharDevice);
        assert_eq!((zero.dev_major, zero.dev_minor), (1, 5));
        close(dev).unwrap();

        assert_eq!(
            mkdir_path(b"/proc/x").unwrap_err(),
            VfsError::PermissionDenied
        );
        assert_eq!(
            create_path(b"/dev/x").unwrap_err(),
            VfsError::PermissionDenied
        );
        assert_eq!(
            unlink_path(b"/dev/null").unwrap_err(),
            VfsError::PermissionDenied
        );
        assert_eq!(
            rename_path(b"/dev/null", b"/dev/x").unwrap_err(),
            VfsError::PermissionDenied
        );
        assert_eq!(
            rename_path(b"/boot/init", b"/proc/moved").unwrap_err(),
            VfsError::PermissionDenied
        );
        assert_eq!(
            rmdir_path(b"/proc/self").unwrap_err(),
            VfsError::PermissionDenied
        );
        assert_eq!(rmdir_path(b"/dev").unwrap_err(), VfsError::PermissionDenied);
        assert_eq!(
            open_path(b"/proc/uptime", OpenOptions::write_only()).unwrap_err(),
            VfsError::ReadOnly
        );
        assert_eq!(
            truncate_path(b"/proc/uptime", 5).unwrap_err(),
            VfsError::ReadOnly
        );
    }

    #[test]
    fn m8e_seek_then_short_read_keeps_file_semantics() {
        let _guard = fresh();
        const TEXT: &[u8] = b"abcdef";
        let writer = open_path(b"/m8e-files.bin", OpenOptions::create_write()).unwrap();
        assert_eq!(write(writer, TEXT).unwrap(), 6);
        close(writer).unwrap();

        let reader = open_path(b"/m8e-files.bin", OpenOptions::read_only()).unwrap();
        assert_eq!(seek(reader, 2).unwrap(), 2);
        let mut buffer = [0u8; 4];
        assert_eq!(read(reader, &mut buffer).unwrap(), 4);
        assert_eq!(&buffer, b"cdef");
        close(reader).unwrap();

        let mut all = [0u8; 16];
        assert_eq!(read_path(b"/m8e-files.bin", 0, &mut all).unwrap(), 6);
        assert_eq!(&all[..6], TEXT);
        assert_eq!(read_path(b"/m8e-files.bin", 6, &mut all).unwrap(), 0);
    }
}
