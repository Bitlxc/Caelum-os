//! Public VFS types and the fixed capacities the M5a file system lives within.
//!
//! Everything the rest of the kernel (and the parallel M5a work on the page
//! cache, locks and notifications) is allowed to name lives here; `vfs::mod`
//! re-exports it, so callers write `crate::vfs::VNodeId` and never reach into
//! this file. The types are plain integers and enums: no Rust layout, reference
//! or trait object crosses the boundary, in line with the ABI rules.

/// Fixed number of VNodes (files, directories and boot-backed payloads).
pub const MAX_VNODES: usize = 64;
/// Fixed number of open file descriptions ("open files") the VFS tracks.
pub const MAX_OPEN: usize = 16;
/// Longest accepted path in bytes, including the leading `/`.
pub const MAX_PATH: usize = 255;
/// Maximum number of path components (the root `/` counts as zero).
pub const MAX_COMPONENTS: usize = 32;
/// Longest accepted single component (file or directory name).
pub const MAX_NAME: usize = 31;
/// Extension attributes per VNode (M5a keeps a deliberately tiny hook).
pub const MAX_XATTRS: usize = 2;
/// Longest accepted extension-attribute name (`user.*` prefix excluded).
pub const MAX_XATTR_NAME: usize = 16;
/// Largest accepted extension-attribute value.
pub const MAX_XATTR_VALUE: usize = 64;
/// Page size used by the VFS / page cache boundary.
pub const PAGE: u64 = 4096;

/// A VNode slot plus a generation counter.
///
/// The low byte is the table index and the high byte a generation: a freed slot
/// bumps its generation, so a stale id can never resolve to a different file and
/// cache keys built from it cannot alias. `pub u16` keeps the type transparent
/// for the page cache, whose `CacheKey.node` is a `u16`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct VNodeId(pub u16);

impl VNodeId {
    /// Id that never refers to a live node.
    pub const NONE: VNodeId = VNodeId(u16::MAX);

    /// Underlying integer (index and generation packed).
    pub const fn raw(self) -> u16 {
        self.0
    }

    /// Rebuild an id from [`VNodeId::raw`].
    pub const fn from_raw(raw: u16) -> VNodeId {
        VNodeId(raw)
    }

    /// Table index this id maps to.
    pub const fn index(self) -> usize {
        (self.0 & 0xFF) as usize
    }

    /// Generation counter of this id.
    pub const fn generation(self) -> u8 {
        (self.0 >> 8) as u8
    }
}

/// Handle to an open file description.
///
/// The description carries the offset; [`dup`] hands back the same description,
/// so two handles share their offset while two independent opens do not.
///
/// # Contract (M5c1)
///
/// This is a fixed-table slot index, **not** a durable identifier: M5c1 adds no
/// generation counter. In production it is only carried as the payload of a
/// `File` object, and the user-visible handle is an object-table handle with its
/// own generation (that is where ABA protection lives). Once the last reference
/// is closed the id becomes stale and must not be used again; host tests must not
/// treat it as a stable, persistable number.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct OpenId(pub u16);

impl OpenId {
    /// Id that never refers to a live description.
    pub const NONE: OpenId = OpenId(u16::MAX);

    /// Underlying integer.
    pub const fn raw(self) -> u16 {
        self.0
    }

    /// Rebuild an id from [`OpenId::raw`].
    pub const fn from_raw(raw: u16) -> OpenId {
        OpenId(raw)
    }
}

/// What a VNode is.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum NodeKind {
    /// Regular file (byte-addressable, sparse reads read zero).
    File,
    /// Directory (its children are VNodes with this node as parent).
    Directory,
    /// Character device node (M8h).
    ///
    /// Only the VFS-generated nodes use this kind today: `/dev/null` and
    /// `/dev/zero`. Their bytes are produced or discarded by `vfs::pseudo`, so
    /// reads and writes never reach the page cache and the size stays zero.
    CharDevice,
}

/// Why a VFS operation failed.
///
/// The set is closed for M5a: the page cache, lock and notification modules
/// reuse these variants instead of inventing their own, and the root maps them
/// to stage markers without the VFS printing anything.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VfsError {
    /// No node / open description for that name or id.
    NotFound,
    /// A path component that must be a directory is not one.
    NotDirectory,
    /// An operation requiring a file was given a directory.
    IsDirectory,
    /// Creating a name that already exists.
    AlreadyExists,
    /// The mount (or the boot payload) is read-only.
    ReadOnly,
    /// Path is not absolute, too long, or escapes the root.
    BadPath,
    /// A single component (or a requested name) is longer than [`MAX_NAME`].
    NameTooLong,
    /// A fixed-capacity table (VNodes, open files, attributes) is full.
    Quota,
    /// Offset arithmetic overflowed or is past the end of the file.
    BadOffset,
    /// Access would violate the handle's mode.
    PermissionDenied,
    /// The operation would block (lock conflicts; no blocking path in M5a).
    WouldBlock,
    /// Feature not implemented at this stage.
    NotSupported,
    /// On-disk / backing data is malformed.
    Corrupt,
    /// Backing store allocation failed.
    NoMemory,
    /// The resource is busy (for example a mount point that may not be removed).
    Busy,
    /// A directory removal found entries other than `.` and `..`.
    ///
    /// M5a reported this as [`VfsError::Busy`]; M5c1 gives `rmdir` of a non-empty
    /// directory its own answer so the syscall layer can return `ENOTEMPTY`
    /// instead of `EBUSY`.
    NotEmpty,
    /// The backing store refused a request (block device or on-disk file
    /// system I/O). M5b raises this from a real `BlockError`/`Error::Io`;
    /// once a write-back fails the mount keeps reporting it (sticky error).
    Io,
    /// The block device did not complete a request in time (bounded polling).
    Timeout,
}

impl VfsError {
    /// Stable short string, used by the root's failure markers only.
    pub const fn as_str(self) -> &'static str {
        match self {
            VfsError::NotFound => "vfs-not-found",
            VfsError::NotDirectory => "vfs-not-directory",
            VfsError::IsDirectory => "vfs-is-directory",
            VfsError::AlreadyExists => "vfs-already-exists",
            VfsError::ReadOnly => "vfs-read-only",
            VfsError::BadPath => "vfs-bad-path",
            VfsError::NameTooLong => "vfs-name-too-long",
            VfsError::Quota => "vfs-quota",
            VfsError::BadOffset => "vfs-bad-offset",
            VfsError::PermissionDenied => "vfs-permission-denied",
            VfsError::WouldBlock => "vfs-would-block",
            VfsError::NotSupported => "vfs-not-supported",
            VfsError::Corrupt => "vfs-corrupt",
            VfsError::NoMemory => "vfs-no-memory",
            VfsError::Busy => "vfs-busy",
            VfsError::NotEmpty => "vfs-not-empty",
            VfsError::Io => "vfs-io",
            VfsError::Timeout => "vfs-timeout",
        }
    }
}

/// Metadata for one VNode (the M5a subset of a stat result).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NodeStat {
    /// File or directory.
    pub kind: NodeKind,
    /// Size in bytes (0 for directories).
    pub size: u64,
    /// Whether this node rejects writes (boot payloads are always read-only).
    pub read_only: bool,
    /// Major device number (`0` for non-device nodes, M8h).
    pub dev_major: u16,
    /// Minor device number (`0` for non-device nodes, M8h).
    pub dev_minor: u16,
}

/// One directory entry produced by [`crate::vfs::readdir`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DirEntry {
    /// Entry name; only `name_len` bytes are meaningful.
    pub name: [u8; MAX_NAME],
    /// Length of the name in bytes.
    pub name_len: u8,
    /// File, directory or character device.
    pub kind: NodeKind,
    /// Size in bytes.
    pub size: u64,
    /// Major device number (`0` for non-device nodes, M8h).
    pub dev_major: u16,
    /// Minor device number (`0` for non-device nodes, M8h).
    pub dev_minor: u16,
}

impl DirEntry {
    /// Empty placeholder.
    pub const fn empty() -> DirEntry {
        DirEntry {
            name: [0u8; MAX_NAME],
            name_len: 0,
            kind: NodeKind::File,
            size: 0,
            dev_major: 0,
            dev_minor: 0,
        }
    }

    /// Name bytes.
    pub fn name(&self) -> &[u8] {
        let len = (self.name_len as usize).min(self.name.len());
        &self.name[..len]
    }
}

/// How a file is opened.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OpenOptions {
    /// Reads allowed.
    pub read: bool,
    /// Writes allowed (rejected on read-only mounts).
    pub write: bool,
    /// Create the file if it does not exist (parent must exist).
    pub create: bool,
    /// Truncate to zero length on open.
    pub truncate: bool,
}

impl OpenOptions {
    /// Read-only open of an existing file.
    pub const fn read_only() -> OpenOptions {
        OpenOptions {
            read: true,
            write: false,
            create: false,
            truncate: false,
        }
    }

    /// Write-only open of an existing file.
    pub const fn write_only() -> OpenOptions {
        OpenOptions {
            read: false,
            write: true,
            create: false,
            truncate: false,
        }
    }

    /// Read-write open of an existing file.
    pub const fn read_write() -> OpenOptions {
        OpenOptions {
            read: true,
            write: true,
            create: false,
            truncate: false,
        }
    }

    /// Create-or-open for writing.
    pub const fn create_write() -> OpenOptions {
        OpenOptions {
            read: true,
            write: true,
            create: true,
            truncate: false,
        }
    }

    /// `truncate` on open (implies writing is allowed).
    pub const fn truncate(mut self) -> OpenOptions {
        self.truncate = true;
        self.write = true;
        self
    }

    /// Returns an error if the request can never succeed on this kind of node.
    pub(crate) fn validate(self) -> Result<(), VfsError> {
        if self.truncate && !self.write {
            return Err(VfsError::PermissionDenied);
        }
        Ok(())
    }
}

/// Where [`crate::vfs::seek_from`] starts counting from.
///
/// `Current` and `End` carry a signed delta because `lseek` allows moving
/// backwards; [`crate::vfs::seek_from`] converts a negative result or an
/// arithmetic overflow into [`VfsError::BadOffset`]. A seek past end-of-file is
/// allowed (the following write extends the file, which is what makes sparse
/// files expressible through the public API).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SeekFrom {
    /// Absolute byte offset from the start of the file.
    Start(u64),
    /// Offset relative to the current file position.
    Current(i64),
    /// Offset relative to the file size.
    End(i64),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn node_ids_pack_index_and_generation() {
        let id = VNodeId::from_raw(0x0205);
        assert_eq!(id.index(), 5);
        assert_eq!(id.generation(), 2);
        assert_eq!(id.raw(), 0x0205);
        assert_eq!(VNodeId::NONE.index(), 0xFF);
    }

    #[test]
    fn error_strings_are_stable_and_unique() {
        let all = [
            VfsError::NotFound,
            VfsError::NotDirectory,
            VfsError::IsDirectory,
            VfsError::AlreadyExists,
            VfsError::ReadOnly,
            VfsError::BadPath,
            VfsError::NameTooLong,
            VfsError::Quota,
            VfsError::BadOffset,
            VfsError::PermissionDenied,
            VfsError::WouldBlock,
            VfsError::NotSupported,
            VfsError::Corrupt,
            VfsError::NoMemory,
            VfsError::Busy,
            VfsError::NotEmpty,
            VfsError::Io,
            VfsError::Timeout,
        ];
        assert_eq!(all.len(), 18);
        assert_eq!(VfsError::NotFound.as_str(), "vfs-not-found");
        assert_eq!(VfsError::NameTooLong.as_str(), "vfs-name-too-long");
        for (index, error) in all.iter().enumerate() {
            for other in &all[index + 1..] {
                assert_ne!(error.as_str(), other.as_str());
            }
        }
    }

    #[test]
    fn open_options_validate() {
        assert_eq!(OpenOptions::read_only().validate(), Ok(()));
        assert_eq!(OpenOptions::create_write().truncate().validate(), Ok(()));
        assert_eq!(
            OpenOptions {
                read: true,
                write: false,
                create: false,
                truncate: true,
            }
            .validate(),
            Err(VfsError::PermissionDenied)
        );
    }

    #[test]
    fn dir_entry_exposes_only_its_name_bytes() {
        let entry = DirEntry {
            name: *b"init\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0",
            name_len: 4,
            kind: NodeKind::File,
            size: 12,
            dev_major: 0,
            dev_minor: 0,
        };
        assert_eq!(entry.name(), b"init");
        assert_eq!(DirEntry::empty().name(), b"");
    }
}
