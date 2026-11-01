//! CaelumOS native syscall ABI, version 0.6 (M7b).
//!
//! This crate is the single source of truth for the native syscall surface
//! shared by the kernel's native syscall entry and user-mode programs:
//! syscall numbers, status codes, capability handles, rights bits and the
//! `repr(C)` request layouts. It is `no_std` with no dependencies and also
//! builds on the host toolchain, so the ABI can be unit tested without
//! booting a kernel.
//!
//! The normative description (register convention, per-syscall semantics,
//! non-blocking wait rules) lives in `docs/abi/native-syscall.md`.
#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]

/// A capability handle: a process-local, opaque, 32-bit value.
///
/// The kernel encodes a handle as `(generation << 16) | (slot + 1)`, where
/// `slot` is the 0-based index in the owning process' handle table and
/// `generation` starts at 1. Consequences that are part of the ABI:
///
/// - handle `0` is always invalid ([`HANDLE_NONE`]);
/// - a handle from a reused slot has a different generation, so stale values
///   are rejected instead of silently referring to a new object;
/// - user code must treat the value as opaque. Only [`handle`] may construct
///   one, and only for tests / diagnostics; a program receives its handles
///   from the kernel at startup or from `process_create`.
pub type Handle = u32;

/// The invalid handle. Also passed for an absent entry argument.
pub const HANDLE_NONE: Handle = 0;

/// Encodes a handle from its generation (starting at 1) and 0-based slot.
///
/// Writing `handle(1, 0)` yields `0x0001_0001`, `handle(1, 1)` yields
/// `0x0001_0002`. User programs normally never need this: they receive
/// already-encoded handles.
pub const fn handle(generation: u16, slot: u16) -> Handle {
    ((generation as u32) << 16) | ((slot as u32) + 1)
}

/// Native ABI major version. Pre-1.0 the major stays `0`; incompatible
/// changes are still documented in the ABI document's change log.
pub const ABI_MAJOR: u16 = 0;
/// Native ABI minor version (0.6 at M7b).
pub const ABI_MINOR: u16 = 6;
/// Version word returned by `abi_query`: `(ABI_MAJOR << 16) | ABI_MINOR`.
pub const ABI_VERSION: u32 = ((ABI_MAJOR as u32) << 16) | ABI_MINOR as u32;

/// Layout version carried by every `repr(C)` request/response structure.
///
/// This is deliberately *not* the ABI version: it versions the shape of one
/// structure, so a structure may only be extended by bumping its own layout
/// version. ABI 0.3 keeps every structure at layout version 1 (which is also
/// the value M4 kernels already validated for `process_create`).
pub const REQUEST_VERSION: u32 = 1;

/// Syscall numbers. Frozen per ABI version; new calls get new numbers and an
/// existing number never changes meaning.
pub const NR_ABI_QUERY: u64 = 0;
pub const NR_WRITE: u64 = 1;
pub const NR_PROCESS_CREATE: u64 = 2;
pub const NR_PROCESS_WAIT: u64 = 3;
pub const NR_PROCESS_EXIT: u64 = 4;
pub const NR_RANDOM_READ: u64 = 5;
pub const NR_HANDLE_CLOSE: u64 = 6;
/// Opens a path (argument: pointer to [`OpenRequest`]); returns a handle.
pub const NR_OPEN: u64 = 7;
/// Reads from a file handle: `(handle, buffer, length)`; returns bytes read.
pub const NR_READ: u64 = 8;
/// Stats a handle: `(handle, out: *mut StatOut)`.
pub const NR_STAT: u64 = 9;
/// Enumerates a directory: `(handle, index, out: *mut DirEntryOut)`.
pub const NR_READDIR: u64 = 10;
/// Creates a directory: `(path, path_len)`.
pub const NR_MKDIR: u64 = 11;
/// Removes an empty directory: `(path, path_len)`.
pub const NR_RMDIR: u64 = 12;
/// Removes a file or empty directory: `(path, path_len)`.
pub const NR_UNLINK: u64 = 13;
/// Renames a node: pointer to [`RenameRequest`].
pub const NR_RENAME: u64 = 14;
/// Flushes a file handle to stable storage: `(handle)`.
pub const NR_SYNC: u64 = 15;
/// Repositions a file handle: `(handle, offset: i64, whence)`; returns offset.
pub const NR_SEEK: u64 = 16;
/// Duplicates a handle with narrowed rights: `(handle, rights)`.
pub const NR_DUP: u64 = 17;
/// Maps file or anonymous memory (M5c2): pointer to [`MmapRequest`].
pub const NR_MMAP: u64 = 18;
/// Unmaps a mapping (M5c2): `(address, length)`.
pub const NR_MUNMAP: u64 = 19;
/// Changes mapping protection (M5c2): `(address, length, prot)`.
pub const NR_MPROTECT: u64 = 20;
/// Takes a file lock (M5c3): pointer to [`LockRequest`].
pub const NR_LOCK: u64 = 21;
/// Sets an extended attribute (M5c3): pointer to [`XattrRequest`].
pub const NR_XATTR_SET: u64 = 22;
/// Gets an extended attribute (M5c3): pointer to [`XattrRequest`].
pub const NR_XATTR_GET: u64 = 23;
/// Subscribes to directory-change notifications (M5c3): `(path, path_len)`.
pub const NR_WATCH: u64 = 24;
/// Drains pending directory-change notifications (M5c3): pointer to
/// [`WatchDrainRequest`].
pub const NR_WATCH_DRAIN: u64 = 25;
/// Truncates a file handle: `(handle, length)`.
pub const NR_TRUNCATE: u64 = 26;
/// Creates one IPC object (M6a1): pointer to [`IpcCreateRequest`]; the new
/// handle is returned in `rdx`.
pub const NR_IPC_CREATE: u64 = 27;
/// Resets or signals a waitable object (M6a1): `(handle, operation, endpoint)`.
///
/// `operation` is [`SIGNAL_OP_RESET`] or [`SIGNAL_OP_SIGNAL`]; `endpoint` is
/// only meaningful for an `EventPair` ([`EVENT_PAIR_ENDPOINT_A`]/
/// [`EVENT_PAIR_ENDPOINT_B`]) and must be 0 otherwise.
pub const NR_IPC_SIGNAL: u64 = 28;
/// Waits on up to [`WAIT_MAX_ITEMS`] handles (M6a1): pointer to
/// [`WaitRequest`]; the number of ready items is returned in `rdx`.
pub const NR_WAIT: u64 = 29;
/// Sends one message (M6a2): `(handle, *const IpcSendRequest)`.
///
/// A channel or port handle may be used; the data and up to
/// [`IPC_HANDLES_MAX`] handles are queued on the peer/receiver side. Handles
/// travel with narrowed rights and the receive side gets new handle numbers.
pub const NR_IPC_SEND: u64 = 30;
/// Receives one message (M6a2): `(handle, *const IpcReceiveRequest)`; the
/// received data length is returned in `rdx`, metadata is copied to
/// [`IpcReceiveRequest::out_meta_ptr`].
pub const NR_IPC_RECV: u64 = 31;
/// Maps a shared-memory object into the caller (M6a2): `(handle, *const
/// ShmMapRequest)`; the mapping handle is returned in `rdx`.
pub const NR_SHM_MAP: u64 = 32;
/// Arms a one-shot timer (M6a1): `(handle, ticks, flags)`; `flags` must be 0.
pub const NR_TIMER_ARM: u64 = 33;
/// Subscribes to readiness events (M6a2): pointer to [`SubscribeRequest`]; the
/// subscription handle is returned in `rdx`.
pub const NR_SUBSCRIBE: u64 = 34;
/// Removes every interest of a subscription (M6a2): `(subscription handle)`.
pub const NR_UNSUBSCRIBE: u64 = 35;
/// Reserved for M6 handle hand-off; superseded by [`NR_IPC_SEND`], which
/// carries handles with messages. Unimplemented in ABI 0.4.
pub const NR_IPC_TRANSFER: u64 = 36;
/// Waits on a user `u32` futex (M6a2): `(address, expected, timeout_ticks)`.
pub const NR_FUTEX_WAIT: u64 = 37;
/// Wakes up to `max` waiters of a user `u32` futex (M6a2): `(address, max)`;
/// the number of woken waiters is returned in `rdx`.
pub const NR_FUTEX_WAKE: u64 = 38;
/// Drains readiness events of a subscription (M6a2): `(subscription handle,
/// *const SubscriptionReadRequest)`; the event count is returned in `rdx`.
pub const NR_SUBSCRIPTION_READ: u64 = 39;
/// Fills one [`DisplayInfoWire`] (M6c): `(display handle,
/// *const DisplayInfoRequest)`.
pub const NR_DISPLAY_INFO: u64 = 40;
/// Maps the display RAM shadow into the caller (M6c): `(display handle,
/// *const ShmMapRequest)`; the mapping handle is returned in `rdx`. The shadow
/// is plain RAM: writing it never touches the framebuffer until
/// [`NR_DISPLAY_PRESENT`].
pub const NR_DISPLAY_MAP: u64 = 41;
/// Copies the display RAM shadow to the framebuffer (M6c): `(display handle,
/// *const DisplayPresentRequest)`; ABI 0.5 only accepts a full 320x200 present.
pub const NR_DISPLAY_PRESENT: u64 = 42;
/// Drains input events (M6c): `(input handle, *const InputReadRequest)`; the
/// number of events written is returned in `rdx` (`0` when none are queued
/// yet, this call never blocks; wait with [`NR_WAIT`] first).
pub const NR_INPUT_READ: u64 = 43;
/// Creates a socket (M7b): `(*const SocketCreateRequest)`. This call has no
/// input handle, so the request pointer travels in `rdi` (same convention as
/// `process_create` and `ipc_create`); the new socket handle is returned in
/// `rdx`. UNIX-domain named sockets must name a network namespace handle in the
/// request; anonymous `socketpair` does not.
pub const NR_SOCKET: u64 = 44;
/// Binds a socket to an address (M7b): `(socket handle,
/// *const SocketAddrRequest)`; result 0.
pub const NR_BIND: u64 = 45;
/// Marks a stream socket as accepting connections (M7b): `(socket handle,
/// backlog)` passed in `rsi`; result 0.
pub const NR_LISTEN: u64 = 46;
/// Accepts one pending connection (M7b): `(socket handle,
/// *const SocketAcceptRequest)`; the new handle is returned in `rdx` and also
/// written to `out_handle_ptr`. Non-blocking: returns [`ERR_WOULD_BLOCK`] when
/// no connection is pending, so wait on the listening socket first.
pub const NR_ACCEPT: u64 = 47;
/// Starts a connection (M7b): `(socket handle, *const SocketAddrRequest)`;
/// result 0. Non-blocking: returns [`ERR_WOULD_BLOCK`] while in progress or
/// when it cannot complete immediately.
pub const NR_CONNECT: u64 = 48;
/// Sends bytes (M7b): `(socket handle, *const SocketSendRequest)`; the number
/// of bytes accepted is returned in `rdx`. A full queue returns
/// [`ERR_WOULD_BLOCK`] without consuming data.
pub const NR_SEND: u64 = 49;
/// Receives bytes (M7b): `(socket handle, *const SocketRecvRequest)`; the
/// number of bytes received is returned in `rdx`. Never blocks: returns
/// [`ERR_WOULD_BLOCK`] when nothing is queued (`0` would mean "zero-length
/// datagram"), so wait on the socket first.
pub const NR_RECV: u64 = 50;
/// Shuts down part of a socket (M7b): `(socket handle, how)` with `how` in
/// `rsi` ([`SOCKET_SHUTDOWN_READ`] / [`SOCKET_SHUTDOWN_WRITE`] /
/// [`SOCKET_SHUTDOWN_BOTH`]); result 0.
pub const NR_SHUTDOWN: u64 = 51;
/// Creates an anonymous, already-connected socket pair (M7b):
/// `(*const SocketPairRequest)` — no input handle, so the request pointer is in
/// `rdi` (`rsi` unused, 0); result 0, and the two raw handles are written to
/// `out_handles_ptr` as two `u32` values. On any failure neither handle is
/// created.
pub const NR_SOCKETPAIR: u64 = 52;
/// Queries a socket's local or peer address (M7b): `(socket handle,
/// *const SocketAddressRequest)`; a [`SocketAddrWire`] is written to
/// `out_addr_ptr`; result 0.
pub const NR_SOCKET_ADDRESS: u64 = 53;

/// Status code for success. Non-zero status values are error codes.
pub const STATUS_OK: u64 = 0;

/// Error codes returned in the status register (`rax`). Values are frozen per
/// ABI version; user code compares them by constant, never by numeric literal.
pub const ERR_BAD_HANDLE: u64 = 1;
pub const ERR_BAD_RIGHT: u64 = 2;
pub const ERR_BAD_POINTER: u64 = 3;
pub const ERR_BAD_REQUEST: u64 = 4;
pub const ERR_NO_ENTROPY: u64 = 5;
pub const ERR_WOULD_BLOCK: u64 = 6;
pub const ERR_NOT_FOUND: u64 = 7;
pub const ERR_QUOTA: u64 = 8;
pub const ERR_NOT_SUPPORTED: u64 = 9;
pub const ERR_EXISTS: u64 = 10;
pub const ERR_NOT_DIR: u64 = 11;
pub const ERR_IS_DIR: u64 = 12;
pub const ERR_READ_ONLY: u64 = 13;
pub const ERR_NO_SPACE: u64 = 14;
pub const ERR_TOO_LARGE: u64 = 15;
pub const ERR_BUSY: u64 = 16;
pub const ERR_IO: u64 = 17;
pub const ERR_TIMEOUT: u64 = 18;
pub const ERR_CORRUPT: u64 = 19;
pub const ERR_NOT_EMPTY: u64 = 20;
pub const ERR_CROSS_DEVICE: u64 = 21;
/// A wait was cancelled (M6a1): the caller or a signal aborted it.
pub const ERR_CANCELLED: u64 = 22;
/// The peer end of a waitable object is closed or gone (M6a1).
pub const ERR_PEER_CLOSED: u64 = 23;
/// A connection attempt was refused by the peer (M7b).
///
/// This is a *native* status, not Linux `ECONNREFUSED`: the Linux personality
/// maps this value to its own errno (`111`) instead of the kernel reusing the
/// Linux number here.
pub const ERR_CONNECTION_REFUSED: u64 = 24;
/// The connection was reset by the peer (M7b); a native status like
/// [`ERR_CONNECTION_REFUSED`].
pub const ERR_CONNECTION_RESET: u64 = 25;
/// The socket is not connected, or the requested operation needs a connected
/// socket (M7b); a native status.
pub const ERR_NOT_CONNECTED: u64 = 26;

/// Stable diagnostic name of a status/error code (`"OK"` for 0).
pub fn status_name(status: u64) -> &'static str {
    match status {
        STATUS_OK => "OK",
        ERR_BAD_HANDLE => "BAD_HANDLE",
        ERR_BAD_RIGHT => "BAD_RIGHT",
        ERR_BAD_POINTER => "BAD_POINTER",
        ERR_BAD_REQUEST => "BAD_REQUEST",
        ERR_NO_ENTROPY => "NO_ENTROPY",
        ERR_WOULD_BLOCK => "WOULD_BLOCK",
        ERR_NOT_FOUND => "NOT_FOUND",
        ERR_QUOTA => "QUOTA",
        ERR_NOT_SUPPORTED => "NOT_SUPPORTED",
        ERR_EXISTS => "EXISTS",
        ERR_NOT_DIR => "NOT_DIR",
        ERR_IS_DIR => "IS_DIR",
        ERR_READ_ONLY => "READ_ONLY",
        ERR_NO_SPACE => "NO_SPACE",
        ERR_TOO_LARGE => "TOO_LARGE",
        ERR_BUSY => "BUSY",
        ERR_IO => "IO",
        ERR_TIMEOUT => "TIMEOUT",
        ERR_CORRUPT => "CORRUPT",
        ERR_NOT_EMPTY => "NOT_EMPTY",
        ERR_CROSS_DEVICE => "CROSS_DEVICE",
        ERR_CANCELLED => "CANCELLED",
        ERR_PEER_CLOSED => "PEER_CLOSED",
        ERR_CONNECTION_REFUSED => "CONNECTION_REFUSED",
        ERR_CONNECTION_RESET => "CONNECTION_RESET",
        ERR_NOT_CONNECTED => "NOT_CONNECTED",
        _ => "UNKNOWN",
    }
}

/// Rights bits carried by a [`HandleTransfer`] (and by every handle table
/// entry in the kernel). A transfer may only narrow the sender's rights.
pub const RIGHT_READ: u32 = 1 << 0;
pub const RIGHT_WRITE: u32 = 1 << 1;
pub const RIGHT_WAIT: u32 = 1 << 2;
pub const RIGHT_DUPLICATE: u32 = 1 << 3;
/// Maps a shared-memory object into the caller's address space (M6a2).
pub const RIGHT_MAP: u32 = 1 << 4;

/// Fixed length of [`ProcessCreateRequest::module_name`], including the
/// implicit zero padding / terminator.
pub const MODULE_NAME_LEN: usize = 16;
/// Maximum number of handles a single `process_create` may transfer.
pub const MAX_HANDLES: usize = 4;

/// One capability handed to a newly created process.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HandleTransfer {
    /// Handle in the *caller's* handle table.
    pub source: Handle,
    /// Rights granted for the child's new handle; must be a non-empty subset
    /// of the caller's rights on `source`.
    pub rights: u32,
}

impl HandleTransfer {
    pub const fn new(source: Handle, rights: u32) -> Self {
        Self { source, rights }
    }
}

/// Request passed (by pointer) to `process_create`.
///
/// Layout (little endian, `repr(C)`, 64 bytes):
///
/// | offset | size | field |
/// |-------:|-----:|-------|
/// | 0  | 4 | `size` = 64, must equal [`ProcessCreateRequest::SIZE`] |
/// | 4  | 4 | `version` = [`REQUEST_VERSION`] |
/// | 8  | 16 | `module_name`, NUL padded |
/// | 24 | 4 | `handle_count` (0..=[`MAX_HANDLES`]) |
/// | 28 | 4 | `reserved`, must be 0 |
/// | 32 | 32 | `handles[4]` |
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProcessCreateRequest {
    pub size: u32,
    pub version: u32,
    pub module_name: [u8; MODULE_NAME_LEN],
    pub handle_count: u32,
    pub reserved: u32,
    pub handles: [HandleTransfer; MAX_HANDLES],
}

impl ProcessCreateRequest {
    /// `size_of::<ProcessCreateRequest>()`; the value the kernel validates
    /// `size` against.
    pub const SIZE: u32 = core::mem::size_of::<Self>() as u32;

    /// A request with no module name and no handles.
    pub const fn empty() -> Self {
        Self {
            size: Self::SIZE,
            version: REQUEST_VERSION,
            module_name: [0; MODULE_NAME_LEN],
            handle_count: 0,
            reserved: 0,
            handles: [HandleTransfer {
                source: 0,
                rights: 0,
            }; MAX_HANDLES],
        }
    }

    /// A request naming `name`, zero padded. Longer names are truncated to
    /// [`MODULE_NAME_LEN`]; the kernel additionally stops at the first NUL.
    pub fn with_module_name(name: &[u8]) -> Self {
        let mut request = Self::empty();
        let len = if name.len() < MODULE_NAME_LEN {
            name.len()
        } else {
            MODULE_NAME_LEN
        };
        let mut i = 0;
        while i < len {
            request.module_name[i] = name[i];
            i += 1;
        }
        request
    }

    /// Appends one handle transfer; returns `false` when the request is full.
    pub fn push_handle(&mut self, source: Handle, rights: u32) -> bool {
        if self.handle_count as usize >= MAX_HANDLES {
            return false;
        }
        self.handles[self.handle_count as usize] = HandleTransfer::new(source, rights);
        self.handle_count += 1;
        true
    }

    /// The module name as the kernel reads it: bytes up to the first NUL.
    pub fn module_name(&self) -> &[u8] {
        let mut len = 0;
        while len < MODULE_NAME_LEN && self.module_name[len] != 0 {
            len += 1;
        }
        &self.module_name[..len]
    }
}

/// Node kind reported by [`StatOut`] and [`DirEntryOut`].
pub const NODE_FILE: u32 = 1;
/// Node kind reported by [`StatOut`] and [`DirEntryOut`].
pub const NODE_DIRECTORY: u32 = 2;

/// `StatOut::flags` bit: the node cannot be opened for writing. Advisory for
/// user space; the authoritative answer is the `open` status.
pub const STAT_FLAG_READ_ONLY: u32 = 1 << 0;

/// `open` flag: request read access.
pub const OPEN_READ: u32 = 1 << 0;
/// `open` flag: request write access (never truncates on its own).
pub const OPEN_WRITE: u32 = 1 << 1;
/// `open` flag: create the file when missing (requires `OPEN_WRITE`).
pub const OPEN_CREATE: u32 = 1 << 2;
/// `open` flag: truncate an existing file to zero length.
pub const OPEN_TRUNC: u32 = 1 << 3;
/// `open` flag: the caller expects a directory and does not read file data.
pub const OPEN_DIRECTORY: u32 = 1 << 4;
/// All bits defined for `open` flags in ABI 0.2.
pub const OPEN_VALID: u32 = OPEN_READ | OPEN_WRITE | OPEN_CREATE | OPEN_TRUNC | OPEN_DIRECTORY;

/// `seek` whence: `offset` is absolute.
pub const SEEK_SET: u32 = 0;
/// `seek` whence: `offset` is relative to the current position.
pub const SEEK_CUR: u32 = 1;
/// `seek` whence: `offset` is relative to the end of the file.
pub const SEEK_END: u32 = 2;

/// `mmap` protection bit: the mapping is readable.
pub const PROT_READ: u32 = 1 << 0;
/// `mmap` protection bit: the mapping is writable.
pub const PROT_WRITE: u32 = 1 << 1;
/// `mmap` protection bit: the mapping is executable.
///
/// The number is frozen for later stages; the M5c2 kernel reports
/// [`ERR_NOT_SUPPORTED`] for executable mappings.
pub const PROT_EXEC: u32 = 1 << 2;
/// All protection bits defined by ABI 0.2.
pub const PROT_VALID: u32 = PROT_READ | PROT_WRITE | PROT_EXEC;

/// `mmap` flag: shared mapping. Writes become visible to other mappings and are
/// written back to the file by `sync`/`munmap`.
pub const MMAP_SHARED: u32 = 1;
/// `mmap` flag: private mapping. Writes are process-private and never reach the
/// file.
pub const MMAP_PRIVATE: u32 = 2;
/// All mapping flags defined by ABI 0.2.
pub const MMAP_VALID: u32 = MMAP_SHARED | MMAP_PRIVATE;

/// Largest byte length one `mmap` request may map (256 KiB).
pub const MMAP_MAX_LEN: u64 = 256 * 1024;

// ---------------------------------------------------------------------------
// M5c3: file locks, extended attributes and directory watching.
// ---------------------------------------------------------------------------

/// POSIX (process-owned) byte-range locks.
pub const LOCK_DOMAIN_POSIX: u32 = 1;
/// Open-file-description locks: shared between `dup`ed handles.
pub const LOCK_DOMAIN_OFD: u32 = 2;
/// `flock`-style whole-file locks in their own, independent domain.
pub const LOCK_DOMAIN_FLOCK: u32 = 3;
/// Highest defined lock domain.
pub const LOCK_DOMAIN_MAX: u32 = LOCK_DOMAIN_FLOCK;

/// Shared (read) lock.
pub const LOCK_OP_SHARED: u32 = 1;
/// Exclusive (write) lock.
pub const LOCK_OP_EXCLUSIVE: u32 = 2;
/// Release the lock covering the request range.
pub const LOCK_OP_UNLOCK: u32 = 3;
/// Highest defined lock operation.
pub const LOCK_OP_MAX: u32 = LOCK_OP_UNLOCK;

/// Maximum extended-attribute name length in bytes (including `user.`).
pub const XATTR_NAME_MAX: u32 = 16;
/// Maximum extended-attribute value length in bytes.
pub const XATTR_VALUE_MAX: u32 = 64;
/// The only attribute namespace exposed to user mode in ABI 0.2.
pub const XATTR_USER_PREFIX: &[u8] = b"user.";

/// A directory entry was created in the watched directory.
pub const WATCH_EVENT_CREATED: u32 = 1;
/// A directory entry was removed from the watched directory.
pub const WATCH_EVENT_DELETED: u32 = 2;
/// A directory entry was renamed (the event carries the new name).
pub const WATCH_EVENT_RENAMED: u32 = 3;
/// Highest defined watch event kind.
pub const WATCH_EVENT_KIND_MAX: u32 = WATCH_EVENT_RENAMED;
/// Bytes available for the event name, NUL padded.
pub const WATCH_EVENT_NAME_LEN: usize = 32;
/// Largest `max_events` value a single drain may ask for.
pub const WATCH_MAX_BATCH: u64 = 16;

/// Common header contract of every `repr(C)` request/response structure.
///
/// The kernel validates `size` and `version` before reading any other field,
/// so a structure can never be reinterpreted across layout versions.
pub trait RequestHeader {
    /// Exact wire size in bytes of the structure that implements this trait.
    const WIRE_SIZE: u32;

    /// The value of the leading `size` field.
    fn size(&self) -> u32;

    /// The value of the leading `version` field.
    fn version(&self) -> u32;

    /// `true` when `size` and `version` match this layout version.
    fn header_valid(&self) -> bool {
        self.size() == Self::WIRE_SIZE && self.version() == REQUEST_VERSION
    }
}

/// Request passed (by pointer) to `open`.
///
/// Layout (little endian, `repr(C)`, 32 bytes):
///
/// | offset | size | field |
/// |-------:|-----:|-------|
/// | 0  | 4  | `size` = 32 |
/// | 4  | 4  | `version` = [`REQUEST_VERSION`] |
/// | 8  | 8  | `path_ptr` = user pointer to the UTF-8 path bytes |
/// | 16 | 4  | `path_len` = number of path bytes |
/// | 20 | 4  | `flags` = `OPEN_*` bits |
/// | 24 | 8  | `reserved` = 0 |
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OpenRequest {
    pub size: u32,
    pub version: u32,
    pub path_ptr: u64,
    pub path_len: u32,
    pub flags: u32,
    pub reserved: u64,
}

impl OpenRequest {
    pub const SIZE: u32 = 32;

    /// A request naming the `path_len` bytes at `path_ptr`.
    pub const fn new(path_ptr: u64, path_len: u32, flags: u32) -> Self {
        Self {
            size: Self::SIZE,
            version: REQUEST_VERSION,
            path_ptr,
            path_len,
            flags,
            reserved: 0,
        }
    }
}

impl RequestHeader for OpenRequest {
    const WIRE_SIZE: u32 = Self::SIZE;

    fn size(&self) -> u32 {
        self.size
    }

    fn version(&self) -> u32 {
        self.version
    }
}

/// Result structure written by `stat`.
///
/// Layout (little endian, `repr(C)`, 32 bytes):
///
/// | offset | size | field |
/// |-------:|-----:|-------|
/// | 0  | 4  | `size` = 32 |
/// | 4  | 4  | `version` = [`REQUEST_VERSION`] |
/// | 8  | 4  | `kind` = [`NODE_FILE`] or [`NODE_DIRECTORY`] |
/// | 12 | 4  | `flags` = `STAT_FLAG_*` bits |
/// | 16 | 8  | `file_size` in bytes (0 for directories in ABI 0.2) |
/// | 24 | 8  | `reserved` = 0 |
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StatOut {
    pub size: u32,
    pub version: u32,
    pub kind: u32,
    pub flags: u32,
    pub file_size: u64,
    pub reserved: u64,
}

impl StatOut {
    pub const SIZE: u32 = 32;

    /// A zeroed result the kernel overwrites in place.
    pub const fn empty() -> Self {
        Self {
            size: Self::SIZE,
            version: REQUEST_VERSION,
            kind: 0,
            flags: 0,
            file_size: 0,
            reserved: 0,
        }
    }

    pub const fn is_file(&self) -> bool {
        self.kind == NODE_FILE
    }

    pub const fn is_directory(&self) -> bool {
        self.kind == NODE_DIRECTORY
    }

    pub const fn is_read_only(&self) -> bool {
        self.flags & STAT_FLAG_READ_ONLY != 0
    }
}

impl RequestHeader for StatOut {
    const WIRE_SIZE: u32 = Self::SIZE;

    fn size(&self) -> u32 {
        self.size
    }

    fn version(&self) -> u32 {
        self.version
    }
}

/// Maximum name length carried by one [`DirEntryOut`].
pub const DIR_ENTRY_NAME_LEN: usize = 32;

/// One directory entry written by `readdir`.
///
/// Layout (little endian, `repr(C)`, 56 bytes):
///
/// | offset | size | field |
/// |-------:|-----:|-------|
/// | 0  | 4  | `size` = 56 |
/// | 4  | 4  | `version` = [`REQUEST_VERSION`] |
/// | 8  | 4  | `kind` = [`NODE_FILE`] or [`NODE_DIRECTORY`] |
/// | 12 | 4  | `name_len` = number of valid bytes in `name` |
/// | 16 | 32 | `name`, NUL padded, never NUL terminated inside `name_len` |
/// | 48 | 8  | `file_size` in bytes |
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DirEntryOut {
    pub size: u32,
    pub version: u32,
    pub kind: u32,
    pub name_len: u32,
    pub name: [u8; DIR_ENTRY_NAME_LEN],
    pub file_size: u64,
}

impl DirEntryOut {
    /// Maximum name length carried by one entry.
    pub const NAME_LEN: usize = DIR_ENTRY_NAME_LEN;
    pub const SIZE: u32 = 56;

    /// A zeroed entry the kernel overwrites in place.
    pub const fn empty() -> Self {
        Self {
            size: Self::SIZE,
            version: REQUEST_VERSION,
            kind: 0,
            name_len: 0,
            name: [0; Self::NAME_LEN],
            file_size: 0,
        }
    }

    /// The entry name as the kernel wrote it (bytes up to `name_len`).
    ///
    /// Returns an empty slice when the kernel reported an inconsistent value,
    /// so user code never reads past the array.
    pub fn name(&self) -> &[u8] {
        let len = self.name_len as usize;
        if len > Self::NAME_LEN {
            return &[];
        }
        &self.name[..len]
    }
}

impl RequestHeader for DirEntryOut {
    const WIRE_SIZE: u32 = Self::SIZE;

    fn size(&self) -> u32 {
        self.size
    }

    fn version(&self) -> u32 {
        self.version
    }
}

/// Request passed (by pointer) to `rename`.
///
/// Layout (little endian, `repr(C)`, 40 bytes):
///
/// | offset | size | field |
/// |-------:|-----:|-------|
/// | 0  | 4  | `size` = 40 |
/// | 4  | 4  | `version` = [`REQUEST_VERSION`] |
/// | 8  | 8  | `old_ptr` = user pointer to the current path |
/// | 16 | 4  | `old_len` = number of current-path bytes |
/// | 20 | 4  | `new_len` = number of new-path bytes |
/// | 24 | 8  | `new_ptr` = user pointer to the new path |
/// | 32 | 8  | `reserved` = 0 |
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RenameRequest {
    pub size: u32,
    pub version: u32,
    pub old_ptr: u64,
    pub old_len: u32,
    pub new_len: u32,
    pub new_ptr: u64,
    pub reserved: u64,
}

impl RenameRequest {
    pub const SIZE: u32 = 40;

    /// A request moving the `old_len` bytes at `old_ptr` to `new_ptr`.
    pub const fn new(old_ptr: u64, old_len: u32, new_ptr: u64, new_len: u32) -> Self {
        Self {
            size: Self::SIZE,
            version: REQUEST_VERSION,
            old_ptr,
            old_len,
            new_len,
            new_ptr,
            reserved: 0,
        }
    }
}

impl RequestHeader for RenameRequest {
    const WIRE_SIZE: u32 = Self::SIZE;

    fn size(&self) -> u32 {
        self.size
    }

    fn version(&self) -> u32 {
        self.version
    }
}

/// Request passed (by pointer) to `mmap`.
///
/// Layout (little endian, `repr(C)`, 48 bytes):
///
/// | offset | size | field |
/// |-------:|-----:|-------|
/// | 0  | 4  | `size` = 48 |
/// | 4  | 4  | `version` = [`REQUEST_VERSION`] |
/// | 8  | 8  | `len` = mapped byte length, page aligned |
/// | 16 | 8  | `offset` = file offset, page aligned |
/// | 24 | 4  | `prot` = `PROT_*` bits |
/// | 28 | 4  | `flags` = `MMAP_*` bits |
/// | 32 | 8  | `out_address` = user pointer to a writable `u64` |
/// | 40 | 8  | `reserved` = 0 |
///
/// On success the kernel copies the mapping base address out through
/// `out_address` and returns the mapping handle in the second result register
/// (`rdx`). Closing that handle unmaps the range.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MmapRequest {
    pub size: u32,
    pub version: u32,
    pub len: u64,
    pub offset: u64,
    pub prot: u32,
    pub flags: u32,
    pub out_address: u64,
    pub reserved: u64,
}

impl MmapRequest {
    pub const SIZE: u32 = 48;

    /// A request mapping `len` bytes at `offset` with `prot`/`flags`.
    ///
    /// `out_address` must point at a writable `u64` owned by the caller; the
    /// kernel writes the mapping base address there.
    pub const fn new(len: u64, offset: u64, prot: u32, flags: u32, out_address: u64) -> Self {
        Self {
            size: Self::SIZE,
            version: REQUEST_VERSION,
            len,
            offset,
            prot,
            flags,
            out_address,
            reserved: 0,
        }
    }
}

impl RequestHeader for MmapRequest {
    const WIRE_SIZE: u32 = Self::SIZE;

    fn size(&self) -> u32 {
        self.size
    }

    fn version(&self) -> u32 {
        self.version
    }
}

/// Request passed (by pointer) to `lock`.
///
/// Layout (little endian, `repr(C)`, 32 bytes):
///
/// | offset | size | field |
/// |-------:|-----:|-------|
/// | 0  | 4  | `size` = 32 |
/// | 4  | 4  | `version` = [`REQUEST_VERSION`] |
/// | 8  | 4  | `domain` = [`LOCK_DOMAIN_POSIX`] / [`LOCK_DOMAIN_OFD`] / [`LOCK_DOMAIN_FLOCK`] |
/// | 12 | 4  | `operation` = [`LOCK_OP_SHARED`] / [`LOCK_OP_EXCLUSIVE`] / [`LOCK_OP_UNLOCK`] |
/// | 16 | 8  | `offset` = first locked byte |
/// | 24 | 8  | `len` = locked byte count, `0` = to EOF (POSIX/OFD) |
///
/// Locks are non-blocking in ABI 0.2: a conflicting request fails with
/// [`ERR_WOULD_BLOCK`] instead of sleeping. `flock` locks only accept
/// `offset = 0, len = 0`.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LockRequest {
    pub size: u32,
    pub version: u32,
    pub domain: u32,
    pub operation: u32,
    pub offset: u64,
    pub len: u64,
}

impl LockRequest {
    pub const SIZE: u32 = 32;

    /// A request for the `len` bytes at `offset` in `domain`.
    pub const fn new(domain: u32, operation: u32, offset: u64, len: u64) -> Self {
        Self {
            size: Self::SIZE,
            version: REQUEST_VERSION,
            domain,
            operation,
            offset,
            len,
        }
    }
}

impl RequestHeader for LockRequest {
    const WIRE_SIZE: u32 = Self::SIZE;

    fn size(&self) -> u32 {
        self.size
    }

    fn version(&self) -> u32 {
        self.version
    }
}

/// Request passed (by pointer) to `xattr_set` and `xattr_get`.
///
/// Layout (little endian, `repr(C)`, 40 bytes):
///
/// | offset | size | field |
/// |-------:|-----:|-------|
/// | 0  | 4  | `size` = 40 |
/// | 4  | 4  | `version` = [`REQUEST_VERSION`] |
/// | 8  | 8  | `name_ptr` = user pointer to the attribute name |
/// | 16 | 8  | `name_len` = name length in bytes (1..=[`XATTR_NAME_MAX`]) |
/// | 24 | 8  | `value_ptr` = user pointer to the value buffer |
/// | 32 | 8  | `value_len` = value length (`set`) or buffer size (`get`) |
///
/// `set` copies the value in; `get` writes at most `value_len` bytes out and
/// reports the real length in the second result register (`rdx`). A buffer
/// that is too small fails with [`ERR_TOO_LARGE`] without a partial write.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct XattrRequest {
    pub size: u32,
    pub version: u32,
    pub name_ptr: u64,
    pub name_len: u64,
    pub value_ptr: u64,
    pub value_len: u64,
}

impl XattrRequest {
    pub const SIZE: u32 = 40;

    /// A request naming the attribute and value buffers.
    pub const fn new(name_ptr: u64, name_len: u64, value_ptr: u64, value_len: u64) -> Self {
        Self {
            size: Self::SIZE,
            version: REQUEST_VERSION,
            name_ptr,
            name_len,
            value_ptr,
            value_len,
        }
    }
}

impl RequestHeader for XattrRequest {
    const WIRE_SIZE: u32 = Self::SIZE;

    fn size(&self) -> u32 {
        self.size
    }

    fn version(&self) -> u32 {
        self.version
    }
}

/// Request passed (by pointer) to `watch_drain`.
///
/// Layout (little endian, `repr(C)`, 24 bytes):
///
/// | offset | size | field |
/// |-------:|-----:|-------|
/// | 0  | 4  | `size` = 24 |
/// | 4  | 4  | `version` = [`REQUEST_VERSION`] |
/// | 8  | 8  | `events_ptr` = user pointer to `max_events` [`WatchEventOut`] slots |
/// | 16 | 8  | `max_events` = slots to fill, 1..=[`WATCH_MAX_BATCH`] |
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WatchDrainRequest {
    pub size: u32,
    pub version: u32,
    pub events_ptr: u64,
    pub max_events: u64,
}

impl WatchDrainRequest {
    pub const SIZE: u32 = 24;

    /// A request draining at most `max_events` events into `events_ptr`.
    pub const fn new(events_ptr: u64, max_events: u64) -> Self {
        Self {
            size: Self::SIZE,
            version: REQUEST_VERSION,
            events_ptr,
            max_events,
        }
    }
}

impl RequestHeader for WatchDrainRequest {
    const WIRE_SIZE: u32 = Self::SIZE;

    fn size(&self) -> u32 {
        self.size
    }

    fn version(&self) -> u32 {
        self.version
    }
}

/// One event written by `watch_drain`.
///
/// Layout (little endian, `repr(C)`, 48 bytes):
///
/// | offset | size | field |
/// |-------:|-----:|-------|
/// | 0  | 4  | `kind` = `WATCH_EVENT_*` |
/// | 4  | 4  | `name_len` = significant bytes of `name` |
/// | 8  | 32 | `name` = entry name, NUL padded |
/// | 40 | 8  | `dropped` = events this watch lost to overflow so far |
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WatchEventOut {
    pub kind: u32,
    pub name_len: u32,
    pub name: [u8; WATCH_EVENT_NAME_LEN],
    pub dropped: u64,
}

impl WatchEventOut {
    /// Bytes available for the name in one event record.
    pub const NAME_LEN: usize = WATCH_EVENT_NAME_LEN;
    pub const SIZE: u32 = 48;

    /// A zeroed record the kernel overwrites in place.
    pub const fn empty() -> Self {
        Self {
            kind: 0,
            name_len: 0,
            name: [0u8; Self::NAME_LEN],
            dropped: 0,
        }
    }

    /// The significant name bytes; a bogus `name_len` yields an empty slice.
    pub fn name(&self) -> &[u8] {
        let len = self.name_len as usize;
        if len > Self::NAME_LEN {
            &[]
        } else {
            &self.name[..len]
        }
    }
}

/// IPC object kinds accepted by [`NR_IPC_CREATE`].
///
/// M6a1 only creates `Event`, `EventPair` and `Timer`; the remaining kinds are
/// frozen here but answer [`ERR_NOT_SUPPORTED`] until a later M6 slice.
pub const IPC_KIND_EVENT: u32 = 1;
pub const IPC_KIND_EVENT_PAIR: u32 = 2;
pub const IPC_KIND_CHANNEL: u32 = 3;
pub const IPC_KIND_PORT: u32 = 4;
pub const IPC_KIND_SHARED_MEMORY: u32 = 5;
pub const IPC_KIND_TIMER: u32 = 6;
pub const IPC_KIND_SUBSCRIPTION: u32 = 7;
/// Highest defined IPC object kind.
pub const IPC_KIND_MAX: u32 = IPC_KIND_SUBSCRIPTION;

/// `Event` creation flag: manual reset (0 = auto reset on consume).
pub const EVENT_FLAG_MANUAL_RESET: u32 = 1;

/// `EventPair` endpoints: signal/observe one end, wake the other.
pub const EVENT_PAIR_ENDPOINT_A: u32 = 0;
pub const EVENT_PAIR_ENDPOINT_B: u32 = 1;

/// `ipc_signal` operations.
pub const SIGNAL_OP_RESET: u32 = 0;
pub const SIGNAL_OP_SIGNAL: u32 = 1;

/// `wait` timeout in ticks: fail immediately with [`ERR_WOULD_BLOCK`].
pub const WAIT_TIMEOUT_IMMEDIATE: u32 = 0;
/// `wait` timeout in ticks: block until an item is ready.
pub const WAIT_TIMEOUT_INFINITE: u32 = 0xFFFF_FFFF;

/// Largest number of items one `wait` may observe.
pub const WAIT_MAX_ITEMS: usize = 4;
/// Wire size of one [`WaitItem`].
pub const WAIT_ITEM_SIZE: u32 = 16;

/// `WaitOut::wake_reason` values.
pub const WAKE_NONE: u32 = 0;
pub const WAKE_READY: u32 = 1;
pub const WAKE_TIMEOUT: u32 = 2;
pub const WAKE_DESTROYED: u32 = 3;
pub const WAKE_CANCELLED: u32 = 4;
pub const WAKE_PEER_CLOSED: u32 = 5;

/// Request passed (by pointer) to `ipc_create` (40 bytes).
///
/// `kind`/`flags` follow the [`IPC_KIND_*`] and creation-flag constants;
/// `arg0`/`arg1` are kind specific and must be 0 when unused. `arg0` is the
/// shared-memory length in bytes for [`IPC_KIND_SHARED_MEMORY`], 0 otherwise.
/// For [`IPC_KIND_CHANNEL`] and [`IPC_KIND_PORT`] the kernel writes the second
/// (peer) handle to `out_second_ptr`; the first handle is returned in `rdx`.
/// Every other kind returns a single handle and must leave `out_second_ptr` 0.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct IpcCreateRequest {
    pub size: u32,
    pub version: u32,
    pub kind: u32,
    pub flags: u32,
    pub arg0: u64,
    pub arg1: u64,
    /// User pointer receiving the second handle (Channel/Port) or 0.
    pub out_second_ptr: u64,
}

impl IpcCreateRequest {
    /// Exact wire size in bytes.
    pub const SIZE: u32 = 40;

    /// Builds a request for `kind` with creation `flags` and kind arguments.
    pub const fn new(kind: u32, flags: u32, arg0: u64, arg1: u64) -> Self {
        Self {
            size: Self::SIZE,
            version: REQUEST_VERSION,
            kind,
            flags,
            arg0,
            arg1,
            out_second_ptr: 0,
        }
    }

    /// Builds a request that also captures a second handle at `out_second_ptr`.
    pub const fn new_pair(
        kind: u32,
        flags: u32,
        arg0: u64,
        arg1: u64,
        out_second_ptr: u64,
    ) -> Self {
        Self {
            size: Self::SIZE,
            version: REQUEST_VERSION,
            kind,
            flags,
            arg0,
            arg1,
            out_second_ptr,
        }
    }
}

impl RequestHeader for IpcCreateRequest {
    const WIRE_SIZE: u32 = Self::SIZE;

    fn size(&self) -> u32 {
        self.size
    }

    fn version(&self) -> u32 {
        self.version
    }
}

/// One item of a [`WaitRequest`] (16 bytes).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct WaitItem {
    /// Handle of a waitable object.
    pub handle: u64,
    /// Item flags; reserved and must be 0 in ABI 0.3.
    pub flags: u32,
    /// Kind-specific key: the `EventPair` endpoint, 0 otherwise.
    pub key: u32,
}

impl WaitItem {
    /// Exact wire size in bytes.
    pub const SIZE: u32 = 16;

    /// Builds an item that observes `handle` with the default flags.
    pub const fn new(handle: Handle, key: u32) -> Self {
        Self {
            handle: handle as u64,
            flags: 0,
            key,
        }
    }
}

/// Request passed (by pointer) to `wait` (96 bytes).
///
/// The caller points `out_ptr` at a [`WaitOut`]; on success the kernel writes
/// it once and reports the number of ready items in `rdx`.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct WaitRequest {
    pub size: u32,
    pub version: u32,
    /// Wait flags; reserved and must be 0 in ABI 0.3.
    pub flags: u32,
    /// Timeout in scheduling ticks ([`WAIT_TIMEOUT_IMMEDIATE`] /
    /// [`WAIT_TIMEOUT_INFINITE`] have special meanings).
    pub timeout_ticks: u32,
    /// Number of valid [`items`](Self::items) entries, 1..=[`WAIT_MAX_ITEMS`].
    pub count: u32,
    /// Must be 0.
    pub reserved: u32,
    /// Address of the caller's [`WaitOut`].
    pub out_ptr: u64,
    /// Observed items; only the first `count` entries are meaningful.
    pub items: [WaitItem; WAIT_MAX_ITEMS],
}

impl WaitRequest {
    /// Exact wire size in bytes: 24-byte header + `out_ptr` + 4 * 16-byte items.
    pub const SIZE: u32 = 96;

    /// Builds an empty request that writes its result to `out_ptr`.
    pub const fn new(out_ptr: u64, timeout_ticks: u32) -> Self {
        Self {
            size: Self::SIZE,
            version: REQUEST_VERSION,
            flags: 0,
            timeout_ticks,
            count: 0,
            reserved: 0,
            out_ptr,
            items: [WaitItem {
                handle: 0,
                flags: 0,
                key: 0,
            }; WAIT_MAX_ITEMS],
        }
    }

    /// Appends one item; returns `false` when the four slots are full.
    pub fn push(&mut self, item: WaitItem) -> bool {
        let index = self.count as usize;
        if index >= WAIT_MAX_ITEMS {
            return false;
        }
        self.items[index] = item;
        self.count = index as u32 + 1;
        true
    }
}

impl RequestHeader for WaitRequest {
    const WIRE_SIZE: u32 = Self::SIZE;

    fn size(&self) -> u32 {
        self.size
    }

    fn version(&self) -> u32 {
        self.version
    }
}

/// Result written by `wait` (16 bytes).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct WaitOut {
    /// Bit `i` set when `items[i]` became ready.
    pub ready_mask: u32,
    /// One of the [`WAKE_*`] reasons.
    pub wake_reason: u32,
    /// Key of the first ready item.
    pub ready_key: u32,
    /// Must be 0.
    pub reserved: u32,
}

impl WaitOut {
    /// Exact wire size in bytes.
    pub const SIZE: u32 = 16;

    /// The all-zero output of a wait that has not run yet.
    pub const fn empty() -> Self {
        Self {
            ready_mask: 0,
            wake_reason: 0,
            ready_key: 0,
            reserved: 0,
        }
    }

    /// `true` when the item at `index` is marked ready.
    pub const fn is_ready(&self, index: usize) -> bool {
        index < WAIT_MAX_ITEMS && (self.ready_mask & (1 << index)) != 0
    }
}

// ---------------------------------------------------------------------------
// M6a2: channels, ports, shared memory and event subscriptions
// ---------------------------------------------------------------------------

/// Maximum inline data bytes carried by one IPC message.
pub const IPC_DATA_MAX: usize = 64;
/// Maximum number of handles transferred with one IPC message.
pub const IPC_HANDLES_MAX: usize = 2;
/// Maximum number of entries in one [`SubscribeRequest`].
pub const SUBSCRIBE_MAX_ENTRIES: usize = 4;
/// Maximum number of events one [`SubscriptionReadRequest`] returns.
pub const SUBSCRIPTION_EVENTS_MAX: usize = 16;

/// Level-triggered subscription mode: every read reports an object as ready
/// while the underlying condition still holds.
pub const SUBSCRIPTION_MODE_LEVEL: u32 = 1;
/// Edge-triggered subscription mode: every ready transition is reported once.
pub const SUBSCRIPTION_MODE_EDGE: u32 = 2;

/// Encodes a [`SubscriptionEvent::object_key`]: the target object's raw id in
/// the high 32 bits and the interest key (EventPair endpoint, 0 otherwise) in
/// the low 32 bits.
pub const fn subscription_object_key(object_raw: u32, key: u32) -> u64 {
    ((object_raw as u64) << 32) | key as u64
}

/// Raw target object id of a [`SubscriptionEvent::object_key`].
pub const fn subscription_object_raw(object_key: u64) -> u32 {
    (object_key >> 32) as u32
}

/// Interest key part of a [`SubscriptionEvent::object_key`].
pub const fn subscription_key(object_key: u64) -> u32 {
    object_key as u32
}

/// Message passed (by pointer) to `ipc_send` (64 bytes).
///
/// `protocol`/`msg_version`/`transaction` are opaque to the kernel and echoed
/// back through [`IpcMessageMeta`]. `data_ptr` points at `data_len` bytes
/// ([`IPC_DATA_MAX`] at most); `handles_ptr` points at `handle_count`
/// consecutive little-endian `u32` handle values and `rights_ptr` at
/// `handle_count` consecutive `u32` right masks ([`IPC_HANDLES_MAX`] at most).
/// Every transferred right must be a subset of the sender's rights.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct IpcSendRequest {
    pub size: u32,
    pub version: u32,
    pub protocol: u32,
    pub msg_version: u32,
    pub transaction: u64,
    pub data_ptr: u64,
    pub data_len: u32,
    pub handle_count: u32,
    pub handles_ptr: u64,
    pub rights_ptr: u64,
    pub reserved: u64,
}

impl IpcSendRequest {
    /// Exact wire size in bytes.
    pub const SIZE: u32 = 64;

    /// Builds an empty-data request with the given routing metadata.
    pub const fn new(protocol: u32, msg_version: u32, transaction: u64) -> Self {
        Self {
            size: Self::SIZE,
            version: REQUEST_VERSION,
            protocol,
            msg_version,
            transaction,
            data_ptr: 0,
            data_len: 0,
            handle_count: 0,
            handles_ptr: 0,
            rights_ptr: 0,
            reserved: 0,
        }
    }
}

impl RequestHeader for IpcSendRequest {
    const WIRE_SIZE: u32 = Self::SIZE;

    fn size(&self) -> u32 {
        self.size
    }

    fn version(&self) -> u32 {
        self.version
    }
}

/// Request passed (by pointer) to `ipc_recv` (64 bytes).
///
/// The kernel copies the message payload into `data_ptr` (up to
/// `data_capacity` bytes), the transferred handles into `out_handles_ptr`
/// (each a `u32`) and their rights into `out_rights_ptr` (each a `u32`), and
/// the [`IpcMessageMeta`] into `out_meta_ptr`. A payload larger than
/// `data_capacity` fails with [`ERR_TOO_LARGE`] and leaves the message
/// queued, so no data is lost.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct IpcReceiveRequest {
    pub size: u32,
    pub version: u32,
    pub data_ptr: u64,
    pub data_capacity: u32,
    pub handle_capacity: u32,
    pub out_handles_ptr: u64,
    pub out_rights_ptr: u64,
    pub out_meta_ptr: u64,
    pub timeout_ticks: u64,
    pub reserved: u64,
}

impl IpcReceiveRequest {
    /// Exact wire size in bytes.
    pub const SIZE: u32 = 64;

    /// Builds a receive request for the given output buffers.
    pub const fn new(
        data_ptr: u64,
        data_capacity: u32,
        out_meta_ptr: u64,
        timeout_ticks: u64,
    ) -> Self {
        Self {
            size: Self::SIZE,
            version: REQUEST_VERSION,
            data_ptr,
            data_capacity,
            handle_capacity: 0,
            out_handles_ptr: 0,
            out_rights_ptr: 0,
            out_meta_ptr,
            timeout_ticks,
            reserved: 0,
        }
    }
}

impl RequestHeader for IpcReceiveRequest {
    const WIRE_SIZE: u32 = Self::SIZE;

    fn size(&self) -> u32 {
        self.size
    }

    fn version(&self) -> u32 {
        self.version
    }
}

/// Metadata written by `ipc_recv` (32 bytes).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct IpcMessageMeta {
    /// Routing metadata echoed from the send request.
    pub protocol: u32,
    pub version: u32,
    pub transaction: u64,
    /// Actual payload and handle counts of the received message.
    pub data_len: u32,
    pub handle_count: u32,
    /// Process id of the sender (diagnostics only).
    pub sender_pid: u32,
    /// Must be 0.
    pub reserved: u32,
}

impl IpcMessageMeta {
    /// Exact wire size in bytes.
    pub const SIZE: u32 = 32;

    /// The all-zero metadata of a receive that has not run yet.
    pub const fn empty() -> Self {
        Self {
            protocol: 0,
            version: 0,
            transaction: 0,
            data_len: 0,
            handle_count: 0,
            sender_pid: 0,
            reserved: 0,
        }
    }
}

/// Request passed (by pointer) to `shm_map` and `display_map` (32 bytes).
///
/// `prot` is a [`PROT_*`] mask; `out_address` is a user `u64` the kernel
/// writes the mapped base address into. The returned handle is the mapping
/// object and must be closed (or the range unmapped) before exit. For
/// `display_map` the mapped object is the whole display RAM shadow (see
/// [`DisplayInfoWire::shadow_bytes`]).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ShmMapRequest {
    pub size: u32,
    pub version: u32,
    pub prot: u32,
    pub reserved: u32,
    pub out_address: u64,
    pub reserved_high: u64,
}

impl ShmMapRequest {
    /// Exact wire size in bytes.
    pub const SIZE: u32 = 32;

    /// Builds a map request with the given protection and output pointer.
    pub const fn new(prot: u32, out_address: u64) -> Self {
        Self {
            size: Self::SIZE,
            version: REQUEST_VERSION,
            prot,
            reserved: 0,
            out_address,
            reserved_high: 0,
        }
    }
}

impl RequestHeader for ShmMapRequest {
    const WIRE_SIZE: u32 = Self::SIZE;

    fn size(&self) -> u32 {
        self.size
    }

    fn version(&self) -> u32 {
        self.version
    }
}

/// One interest of a [`SubscribeRequest`] (16 bytes).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SubscriptionEntry {
    /// Handle of the observed object.
    pub handle: Handle,
    /// [`SUBSCRIPTION_MODE_LEVEL`] or [`SUBSCRIPTION_MODE_EDGE`].
    pub mode: u32,
    /// Kind-specific key (channel endpoint etc.); 0 when unused.
    pub key: u64,
}

impl SubscriptionEntry {
    /// Exact wire size in bytes.
    pub const SIZE: u32 = 16;

    /// Builds one interest entry.
    pub const fn new(handle: Handle, mode: u32, key: u64) -> Self {
        Self { handle, mode, key }
    }
}

/// Request passed (by pointer) to `subscribe` (24 bytes).
///
/// `rdi` is the subscription handle and `rsi` points at this request: the
/// entries are interests added to an existing subscription. A subscription
/// has one handle and survives the handles it observes: after
/// [`NR_UNSUBSCRIBE`] or a close of the subscription it no longer reports
/// events, while the observed objects stay usable.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SubscribeRequest {
    pub size: u32,
    pub version: u32,
    /// Number of entries at `entries_ptr` ([`SUBSCRIBE_MAX_ENTRIES`] at most).
    pub count: u32,
    pub reserved: u32,
    pub entries_ptr: u64,
}

impl SubscribeRequest {
    /// Exact wire size in bytes.
    pub const SIZE: u32 = 24;

    /// Builds a subscribe request for `count` entries at `entries_ptr`.
    pub const fn new(entries_ptr: u64, count: u32) -> Self {
        Self {
            size: Self::SIZE,
            version: REQUEST_VERSION,
            count,
            reserved: 0,
            entries_ptr,
        }
    }
}

impl RequestHeader for SubscribeRequest {
    const WIRE_SIZE: u32 = Self::SIZE;

    fn size(&self) -> u32 {
        self.size
    }

    fn version(&self) -> u32 {
        self.version
    }
}

/// Request passed (by pointer) to `subscription_read` (24 bytes).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SubscriptionReadRequest {
    pub size: u32,
    pub version: u32,
    /// Requested event count (1..=[`SUBSCRIPTION_EVENTS_MAX`]).
    pub max_events: u32,
    pub reserved: u32,
    /// Pointer to `max_events` [`SubscriptionEvent`] outputs.
    pub out_events_ptr: u64,
}

impl SubscriptionReadRequest {
    /// Exact wire size in bytes.
    pub const SIZE: u32 = 24;

    /// Builds a read request for `max_events` outputs at `out_events_ptr`.
    pub const fn new(max_events: u32, out_events_ptr: u64) -> Self {
        Self {
            size: Self::SIZE,
            version: REQUEST_VERSION,
            max_events,
            reserved: 0,
            out_events_ptr,
        }
    }
}

impl RequestHeader for SubscriptionReadRequest {
    const WIRE_SIZE: u32 = Self::SIZE;

    fn size(&self) -> u32 {
        self.size
    }

    fn version(&self) -> u32 {
        self.version
    }
}

/// One readiness event written by `subscription_read` (16 bytes).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SubscriptionEvent {
    /// The `key` of the matched [`SubscriptionEntry`].
    pub object_key: u64,
    /// The mode the event was reported under.
    pub mode: u32,
    /// Must be 0.
    pub reserved: u32,
}

impl SubscriptionEvent {
    /// Exact wire size in bytes.
    pub const SIZE: u32 = 16;

    /// The all-zero event placeholder.
    pub const fn empty() -> Self {
        Self {
            object_key: 0,
            mode: 0,
            reserved: 0,
        }
    }
}

// ---------------------------------------------------------------------------
// M6c: display RAM shadow and input events
// ---------------------------------------------------------------------------

/// Logical display width of the M6c RAM shadow frame, in pixels.
pub const DISPLAY_WIDTH: u32 = 320;
/// Logical display height of the M6c RAM shadow frame, in pixels.
pub const DISPLAY_HEIGHT: u32 = 200;
/// Bytes of one 32-bit-per-pixel display frame
/// (`DISPLAY_WIDTH * DISPLAY_HEIGHT * 4`).
pub const DISPLAY_FRAME_BYTES: u64 = (DISPLAY_WIDTH as u64) * (DISPLAY_HEIGHT as u64) * 4;
/// Maximum number of events one [`InputReadRequest`] returns.
pub const INPUT_EVENTS_MAX: u32 = 16;
/// Keyboard input event kind (`InputEventWire::kind`).
pub const INPUT_EVENT_KIND_KEYBOARD: u32 = 1;
/// Serial input event kind (`InputEventWire::kind`).
pub const INPUT_EVENT_KIND_SERIAL: u32 = 2;

/// Request passed (by pointer) to `display_info` (24 bytes).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct DisplayInfoRequest {
    pub size: u32,
    pub version: u32,
    /// Pointer to one [`DisplayInfoWire`] output.
    pub out_info_ptr: u64,
    /// Must be 0.
    pub reserved: u64,
}

impl DisplayInfoRequest {
    /// Exact wire size in bytes.
    pub const SIZE: u32 = 24;

    /// Builds an info request writing to `out_info_ptr`.
    pub const fn new(out_info_ptr: u64) -> Self {
        Self {
            size: Self::SIZE,
            version: REQUEST_VERSION,
            out_info_ptr,
            reserved: 0,
        }
    }
}

impl RequestHeader for DisplayInfoRequest {
    const WIRE_SIZE: u32 = Self::SIZE;

    fn size(&self) -> u32 {
        self.size
    }

    fn version(&self) -> u32 {
        self.version
    }
}

/// Display description written by `display_info` (32 bytes).
///
/// The kernel exposes a RAM shadow through `display_map`; nothing written to
/// the shadow reaches the framebuffer until `display_present`. `pixel_format`
/// uses the UEFI GOP enum (`0` = RGBX, `1` = BGRX, `2` = bit mask, `3` = blt
/// only), `stride` is the shadow row pitch in pixels, and `shadow_bytes` is the
/// byte length of the mapping (M6c: [`DISPLAY_FRAME_BYTES`]). No MMIO is
/// exposed to user space.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct DisplayInfoWire {
    pub width: u32,
    pub height: u32,
    pub stride: u32,
    pub pixel_format: u32,
    /// Byte length of the shadow mapping; M6c always reports
    /// [`DISPLAY_FRAME_BYTES`].
    pub shadow_bytes: u64,
    /// Must be 0.
    pub reserved: u64,
}

impl DisplayInfoWire {
    /// Exact wire size in bytes.
    pub const SIZE: u32 = 32;

    /// The all-zero description of a unit that has not been queried yet.
    pub const fn empty() -> Self {
        Self {
            width: 0,
            height: 0,
            stride: 0,
            pixel_format: 0,
            shadow_bytes: 0,
            reserved: 0,
        }
    }
}

/// Request passed (by pointer) to `display_present` (24 bytes).
///
/// ABI 0.5 accepts exactly one rectangle: [`DisplayPresentRequest::new`] builds
/// the full-frame `(0, 0, 320, 200)` present.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct DisplayPresentRequest {
    pub size: u32,
    pub version: u32,
    /// Left edge in pixels; `0` in ABI 0.5.
    pub x: u32,
    /// Top edge in pixels; `0` in ABI 0.5.
    pub y: u32,
    /// Width in pixels; [`DISPLAY_WIDTH`] in ABI 0.5.
    pub w: u32,
    /// Height in pixels; [`DISPLAY_HEIGHT`] in ABI 0.5.
    pub h: u32,
}

impl DisplayPresentRequest {
    /// Exact wire size in bytes.
    pub const SIZE: u32 = 24;

    /// Builds the full-frame present accepted by ABI 0.5.
    pub const fn new() -> Self {
        Self {
            size: Self::SIZE,
            version: REQUEST_VERSION,
            x: 0,
            y: 0,
            w: DISPLAY_WIDTH,
            h: DISPLAY_HEIGHT,
        }
    }
}

impl RequestHeader for DisplayPresentRequest {
    const WIRE_SIZE: u32 = Self::SIZE;

    fn size(&self) -> u32 {
        self.size
    }

    fn version(&self) -> u32 {
        self.version
    }
}

/// Request passed (by pointer) to `input_read` (24 bytes).
///
/// `max_events` must be `1..=INPUT_EVENTS_MAX`; events are written in arrival
/// order (input queue semantics) with a per-queue `sequence` and a monotonic
/// `timestamp_ms`. The call never blocks: with an empty queue it returns `0`.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct InputReadRequest {
    pub size: u32,
    pub version: u32,
    /// Number of [`InputEventWire`] outputs requested.
    pub max_events: u32,
    /// Must be 0.
    pub reserved: u32,
    /// Pointer to `max_events` [`InputEventWire`] outputs.
    pub out_events_ptr: u64,
}

impl InputReadRequest {
    /// Exact wire size in bytes.
    pub const SIZE: u32 = 24;

    /// Builds a read request for `max_events` outputs at `out_events_ptr`.
    pub const fn new(max_events: u32, out_events_ptr: u64) -> Self {
        Self {
            size: Self::SIZE,
            version: REQUEST_VERSION,
            max_events,
            reserved: 0,
            out_events_ptr,
        }
    }
}

impl RequestHeader for InputReadRequest {
    const WIRE_SIZE: u32 = Self::SIZE;

    fn size(&self) -> u32 {
        self.size
    }

    fn version(&self) -> u32 {
        self.version
    }
}

/// One input event written by `input_read` (24 bytes).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct InputEventWire {
    /// [`INPUT_EVENT_KIND_KEYBOARD`] or [`INPUT_EVENT_KIND_SERIAL`].
    pub kind: u32,
    /// Keyboard: PS/2 set-1 scan code (make code, with bit 7 set on break — the
    /// `d` key is make `0x20` / break `0xA0`); serial: the byte value.
    pub code: u32,
    /// Per-queue arrival number starting at 1.
    pub sequence: u32,
    /// Must be 0.
    pub reserved: u32,
    /// Monotonic arrival timestamp in milliseconds.
    pub timestamp_ms: u64,
}

impl InputEventWire {
    /// Exact wire size in bytes.
    pub const SIZE: u32 = 24;

    /// The all-zero event placeholder.
    pub const fn empty() -> Self {
        Self {
            kind: 0,
            code: 0,
            sequence: 0,
            reserved: 0,
            timestamp_ms: 0,
        }
    }
}

// ---------------------------------------------------------------------------
// M7b: socket wire formats (ABI 0.6)
//
// The kernel engine is delivered separately; this crate freezes only the
// shared wire contract: address representation, request layouts and the
// domain/kind/shutdown constants. Every call is non-blocking and integrates
// with the unified wait/deadline mechanism (`NR_WAIT`), never with an embedded
// socket timeout option.
// ---------------------------------------------------------------------------

/// UNIX-domain socket (filesystem path or, from M9, abstract namespace).
pub const SOCKET_DOMAIN_UNIX: u32 = 1;
/// IPv4 socket.
pub const SOCKET_DOMAIN_INET: u32 = 2;
/// IPv6 socket.
pub const SOCKET_DOMAIN_INET6: u32 = 10;

/// [`SocketAddrWire::family`] for UNIX-domain addresses; same numbering as
/// [`SOCKET_DOMAIN_UNIX`].
pub const SOCKET_FAMILY_UNIX: u32 = 1;
/// [`SocketAddrWire::family`] for IPv4 addresses.
pub const SOCKET_FAMILY_INET: u32 = 2;
/// [`SocketAddrWire::family`] for IPv6 addresses.
pub const SOCKET_FAMILY_INET6: u32 = 10;

/// Reliable, ordered byte-stream socket.
pub const SOCKET_KIND_STREAM: u32 = 1;
/// Independent datagram socket.
pub const SOCKET_KIND_DGRAM: u32 = 2;

/// `shutdown` how: stop receiving; the peer observes its send side closing.
pub const SOCKET_SHUTDOWN_READ: u32 = 0;
/// `shutdown` how: stop sending; the peer observes end-of-stream.
pub const SOCKET_SHUTDOWN_WRITE: u32 = 1;
/// `shutdown` how: both directions.
pub const SOCKET_SHUTDOWN_BOTH: u32 = 2;

/// `socket_address` selector: the socket's local address.
pub const SOCKET_ADDR_LOCAL: u32 = 0;
/// `socket_address` selector: the connected peer's address.
pub const SOCKET_ADDR_PEER: u32 = 1;

/// Maximum valid [`SocketAddrWire::path_len`] (one byte is kept free so a
/// path can always be NUL-terminated by a consumer without growing the wire).
pub const SOCKET_PATH_MAX: u32 = 107;
/// Size of [`SocketAddrWire::path`] in bytes.
pub const SOCKET_PATH_BYTES: usize = 108;
/// Wire size of [`SocketAddrWire`]; `bind`/`connect` require `addr_len` to
/// equal this value.
pub const SOCKET_ADDR_WIRE: u32 = 144;

/// One socket address, shared by `bind`, `connect`, `accept` (peer address)
/// and `socket_address` (144 bytes, ABI 0.6).
///
/// Layout (little endian, `repr(C)`):
///
/// | offset | size | field |
/// |-------:|-----:|-------|
/// | 0   | 4   | `family` ([`SOCKET_FAMILY_UNIX`] / `_INET` / `_INET6`) |
/// | 4   | 4   | `port`, an ABI integer; the kernel converts to network order |
/// | 8   | 4   | `flags`, must be 0 in ABI 0.6 |
/// | 12  | 16  | `addr`: IPv4 in `[0..4]`, IPv6 in `[0..16]`, network order |
/// | 28  | 4   | `scope`, IPv6 scope id (0 for IPv4/UNIX) |
/// | 32  | 4   | `path_len`, `0` for IP families, `1..=`[`SOCKET_PATH_MAX`] for UNIX |
/// | 36  | 108 | `path`, UNIX path bytes (not required to be UTF-8) |
///
/// ABI rules: `path_len <= SOCKET_PATH_MAX`; IP addresses carry
/// `path_len == 0` and use `addr`; UNIX addresses carry `addr == [0; 16]`,
/// `port == 0` and use `path[..path_len]` as a filesystem path (the abstract
/// namespace starts at M9 and is not part of ABI 0.6).
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SocketAddrWire {
    /// Address family: [`SOCKET_FAMILY_UNIX`], [`SOCKET_FAMILY_INET`] or
    /// [`SOCKET_FAMILY_INET6`].
    pub family: u32,
    /// Port number as an ABI integer (the kernel does the byte-order work).
    pub port: u32,
    /// Reserved flag word, must be 0 in ABI 0.6.
    pub flags: u32,
    /// IPv4 (first 4 bytes) or IPv6 address bytes, network order.
    pub addr: [u8; 16],
    /// IPv6 scope id; 0 for IPv4 and UNIX addresses.
    pub scope: u32,
    /// Use only the first `path_len` bytes of [`Self::path`].
    pub path_len: u32,
    /// UNIX-domain path bytes; meaningful only up to `path_len`.
    pub path: [u8; SOCKET_PATH_BYTES],
}

impl SocketAddrWire {
    /// Exact wire size in bytes.
    pub const SIZE: u32 = SOCKET_ADDR_WIRE;

    /// The all-zero (invalid) address placeholder.
    pub const fn empty() -> Self {
        Self {
            family: 0,
            port: 0,
            flags: 0,
            addr: [0; 16],
            scope: 0,
            path_len: 0,
            path: [0; SOCKET_PATH_BYTES],
        }
    }

    /// Whether `path_len` stays inside the frozen bound.
    pub const fn path_len_valid(&self) -> bool {
        self.path_len <= SOCKET_PATH_MAX
    }
}

/// Request passed (by pointer) to `socket` (32 bytes, ABI 0.6).
///
/// `namespace_handle` must name the network namespace the socket is created
/// in when `domain == SOCKET_DOMAIN_UNIX` and the address is a named
/// filesystem path; anonymous `socketpair` needs no namespace. `protocol` and
/// `flags` must be 0 in ABI 0.6.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SocketCreateRequest {
    pub size: u32,
    pub version: u32,
    /// [`SOCKET_DOMAIN_UNIX`], [`SOCKET_DOMAIN_INET`] or
    /// [`SOCKET_DOMAIN_INET6`].
    pub domain: u32,
    /// [`SOCKET_KIND_STREAM`] or [`SOCKET_KIND_DGRAM`].
    pub kind: u32,
    /// Reserved for a transport selector; must be 0 in ABI 0.6.
    pub protocol: u32,
    /// Reserved flag word; must be 0 in ABI 0.6.
    pub flags: u32,
    /// Network namespace handle, or [`HANDLE_NONE`] when not required.
    pub namespace_handle: Handle,
    /// Must be 0.
    pub reserved: u32,
}

impl SocketCreateRequest {
    /// Exact wire size in bytes.
    pub const SIZE: u32 = 32;

    /// Creates a request with zeroed optional fields.
    pub const fn new(domain: u32, kind: u32, namespace_handle: Handle) -> Self {
        Self {
            size: Self::SIZE,
            version: REQUEST_VERSION,
            domain,
            kind,
            protocol: 0,
            flags: 0,
            namespace_handle,
            reserved: 0,
        }
    }
}

/// Request passed (by pointer) to `bind` and to `connect` (24 bytes, ABI 0.6).
///
/// `addr_ptr` points at exactly one [`SocketAddrWire`]; `addr_len` must be
/// [`SOCKET_ADDR_WIRE`] so an implementation cannot read a short address.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SocketAddrRequest {
    pub size: u32,
    pub version: u32,
    /// Must equal [`SOCKET_ADDR_WIRE`].
    pub addr_len: u32,
    /// Must be 0.
    pub reserved: u32,
    /// User pointer to one [`SocketAddrWire`].
    pub addr_ptr: u64,
}

impl SocketAddrRequest {
    /// Exact wire size in bytes.
    pub const SIZE: u32 = 24;

    /// Wraps a pointer to one [`SocketAddrWire`].
    pub const fn new(addr_ptr: u64) -> Self {
        Self {
            size: Self::SIZE,
            version: REQUEST_VERSION,
            addr_len: SOCKET_ADDR_WIRE,
            reserved: 0,
            addr_ptr,
        }
    }
}

/// Alias so a call site can spell the syscall it uses; `bind` and `connect`
/// share the same request.
pub type BindConnectRequest = SocketAddrRequest;

/// Request passed (by pointer) to `accept` (16 bytes, ABI 0.6).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SocketAcceptRequest {
    pub size: u32,
    pub version: u32,
    /// User pointer that receives the new raw [`Handle`] (a `u32`).
    pub out_handle_ptr: u64,
}

impl SocketAcceptRequest {
    /// Exact wire size in bytes.
    pub const SIZE: u32 = 16;

    /// Wraps the output handle pointer.
    pub const fn new(out_handle_ptr: u64) -> Self {
        Self {
            size: Self::SIZE,
            version: REQUEST_VERSION,
            out_handle_ptr,
        }
    }
}

/// Request passed (by pointer) to `send` (24 bytes, ABI 0.6).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SocketSendRequest {
    pub size: u32,
    pub version: u32,
    /// Reserved flag word; must be 0 in ABI 0.6.
    pub flags: u32,
    /// Number of bytes at `data_ptr`.
    pub data_len: u32,
    /// User pointer to the bytes to send.
    pub data_ptr: u64,
}

impl SocketSendRequest {
    /// Exact wire size in bytes.
    pub const SIZE: u32 = 24;

    /// Wraps a data pointer and length.
    pub const fn new(data_ptr: u64, data_len: u32) -> Self {
        Self {
            size: Self::SIZE,
            version: REQUEST_VERSION,
            flags: 0,
            data_len,
            data_ptr,
        }
    }
}

/// Request passed (by pointer) to `recv` (32 bytes, ABI 0.6).
///
/// `out_source_ptr` may be 0; when nonzero the kernel writes one
/// [`SocketAddrWire`] describing the datagram source (or the stream peer)
/// there. `recv` never blocks: an empty queue returns `ERR_WOULD_BLOCK`.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SocketRecvRequest {
    pub size: u32,
    pub version: u32,
    /// Reserved flag word; must be 0 in ABI 0.6.
    pub flags: u32,
    /// Capacity of the buffer at `data_ptr` in bytes.
    pub data_capacity: u32,
    /// User pointer to the receive buffer.
    pub data_ptr: u64,
    /// Optional user pointer to one [`SocketAddrWire`] for the source address.
    pub out_source_ptr: u64,
}

impl SocketRecvRequest {
    /// Exact wire size in bytes.
    pub const SIZE: u32 = 32;

    /// Wraps a receive buffer; the source address output starts disabled.
    pub const fn new(data_ptr: u64, data_capacity: u32) -> Self {
        Self {
            size: Self::SIZE,
            version: REQUEST_VERSION,
            flags: 0,
            data_capacity,
            data_ptr,
            out_source_ptr: 0,
        }
    }
}

/// Request passed (by pointer) to `socketpair` (24 bytes, ABI 0.6).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SocketPairRequest {
    pub size: u32,
    pub version: u32,
    /// [`SOCKET_DOMAIN_UNIX`] (`socketpair` is local-only in ABI 0.6).
    pub domain: u32,
    /// [`SOCKET_KIND_STREAM`] or [`SOCKET_KIND_DGRAM`].
    pub kind: u32,
    /// User pointer that receives two consecutive raw [`Handle`] (`u32`) values.
    pub out_handles_ptr: u64,
}

impl SocketPairRequest {
    /// Exact wire size in bytes.
    pub const SIZE: u32 = 24;

    /// Wraps the two-handle output pointer.
    pub const fn new(domain: u32, kind: u32, out_handles_ptr: u64) -> Self {
        Self {
            size: Self::SIZE,
            version: REQUEST_VERSION,
            domain,
            kind,
            out_handles_ptr,
        }
    }
}

/// Request passed (by pointer) to `socket_address` (24 bytes, ABI 0.6).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SocketAddressRequest {
    pub size: u32,
    pub version: u32,
    /// [`SOCKET_ADDR_LOCAL`] or [`SOCKET_ADDR_PEER`].
    pub which: u32,
    /// Must be 0.
    pub reserved: u32,
    /// User pointer that receives one [`SocketAddrWire`].
    pub out_addr_ptr: u64,
}

impl SocketAddressRequest {
    /// Exact wire size in bytes.
    pub const SIZE: u32 = 24;

    /// Wraps the selector and output address pointer.
    pub const fn new(which: u32, out_addr_ptr: u64) -> Self {
        Self {
            size: Self::SIZE,
            version: REQUEST_VERSION,
            which,
            reserved: 0,
            out_addr_ptr,
        }
    }
}

impl RequestHeader for SocketCreateRequest {
    const WIRE_SIZE: u32 = Self::SIZE;

    fn size(&self) -> u32 {
        self.size
    }

    fn version(&self) -> u32 {
        self.version
    }
}

impl RequestHeader for SocketAddrRequest {
    const WIRE_SIZE: u32 = Self::SIZE;

    fn size(&self) -> u32 {
        self.size
    }

    fn version(&self) -> u32 {
        self.version
    }
}

impl RequestHeader for SocketAcceptRequest {
    const WIRE_SIZE: u32 = Self::SIZE;

    fn size(&self) -> u32 {
        self.size
    }

    fn version(&self) -> u32 {
        self.version
    }
}

impl RequestHeader for SocketSendRequest {
    const WIRE_SIZE: u32 = Self::SIZE;

    fn size(&self) -> u32 {
        self.size
    }

    fn version(&self) -> u32 {
        self.version
    }
}

impl RequestHeader for SocketRecvRequest {
    const WIRE_SIZE: u32 = Self::SIZE;

    fn size(&self) -> u32 {
        self.size
    }

    fn version(&self) -> u32 {
        self.version
    }
}

impl RequestHeader for SocketPairRequest {
    const WIRE_SIZE: u32 = Self::SIZE;

    fn size(&self) -> u32 {
        self.size
    }

    fn version(&self) -> u32 {
        self.version
    }
}

impl RequestHeader for SocketAddressRequest {
    const WIRE_SIZE: u32 = Self::SIZE;

    fn size(&self) -> u32 {
        self.size
    }

    fn version(&self) -> u32 {
        self.version
    }
}

impl RequestHeader for ProcessCreateRequest {
    const WIRE_SIZE: u32 = Self::SIZE;

    fn size(&self) -> u32 {
        self.size
    }

    fn version(&self) -> u32 {
        self.version
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::mem::{align_of, offset_of, size_of};

    #[test]
    fn abi_version_word_is_major_shl_16_or_minor() {
        assert_eq!(ABI_VERSION, (0 << 16) | 6);
        assert_eq!((ABI_MAJOR as u32) << 16 | ABI_MINOR as u32, ABI_VERSION);
        assert_eq!(ABI_VERSION, 6);
        // Layout version is independent of the ABI version and stays at 1.
        assert_eq!(REQUEST_VERSION, 1);
    }

    #[test]
    fn syscall_numbers_are_frozen_and_unique() {
        let numbers = [
            NR_ABI_QUERY,
            NR_WRITE,
            NR_PROCESS_CREATE,
            NR_PROCESS_WAIT,
            NR_PROCESS_EXIT,
            NR_RANDOM_READ,
            NR_HANDLE_CLOSE,
            NR_OPEN,
            NR_READ,
            NR_STAT,
            NR_READDIR,
            NR_MKDIR,
            NR_RMDIR,
            NR_UNLINK,
            NR_RENAME,
            NR_SYNC,
            NR_SEEK,
            NR_DUP,
            NR_MMAP,
            NR_MUNMAP,
            NR_MPROTECT,
            NR_LOCK,
            NR_XATTR_SET,
            NR_XATTR_GET,
            NR_WATCH,
            NR_WATCH_DRAIN,
            NR_TRUNCATE,
            NR_IPC_CREATE,
            NR_IPC_SIGNAL,
            NR_WAIT,
            NR_IPC_SEND,
            NR_IPC_RECV,
            NR_SHM_MAP,
            NR_TIMER_ARM,
            NR_SUBSCRIBE,
            NR_UNSUBSCRIBE,
            NR_IPC_TRANSFER,
            NR_FUTEX_WAIT,
            NR_FUTEX_WAKE,
            NR_SUBSCRIPTION_READ,
            NR_DISPLAY_INFO,
            NR_DISPLAY_MAP,
            NR_DISPLAY_PRESENT,
            NR_INPUT_READ,
            NR_SOCKET,
            NR_BIND,
            NR_LISTEN,
            NR_ACCEPT,
            NR_CONNECT,
            NR_SEND,
            NR_RECV,
            NR_SHUTDOWN,
            NR_SOCKETPAIR,
            NR_SOCKET_ADDRESS,
        ];
        assert_eq!(
            numbers,
            [
                0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22,
                23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43,
                44, 45, 46, 47, 48, 49, 50, 51, 52, 53
            ]
        );
        for (i, nr) in numbers.iter().enumerate() {
            assert_eq!(*nr, i as u64, "syscall numbers must stay dense and stable");
        }
    }

    #[test]
    fn error_codes_are_frozen_and_named() {
        let errors = [
            ERR_BAD_HANDLE,
            ERR_BAD_RIGHT,
            ERR_BAD_POINTER,
            ERR_BAD_REQUEST,
            ERR_NO_ENTROPY,
            ERR_WOULD_BLOCK,
            ERR_NOT_FOUND,
            ERR_QUOTA,
            ERR_NOT_SUPPORTED,
            ERR_EXISTS,
            ERR_NOT_DIR,
            ERR_IS_DIR,
            ERR_READ_ONLY,
            ERR_NO_SPACE,
            ERR_TOO_LARGE,
            ERR_BUSY,
            ERR_IO,
            ERR_TIMEOUT,
            ERR_CORRUPT,
            ERR_NOT_EMPTY,
            ERR_CROSS_DEVICE,
            ERR_CANCELLED,
            ERR_PEER_CLOSED,
            ERR_CONNECTION_REFUSED,
            ERR_CONNECTION_RESET,
            ERR_NOT_CONNECTED,
        ];
        assert_eq!(
            errors,
            [
                1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
                24, 25, 26
            ]
        );
        assert_eq!(STATUS_OK, 0);
        assert_eq!(status_name(STATUS_OK), "OK");
        for (i, code) in errors.iter().enumerate() {
            assert_ne!(status_name(*code), "UNKNOWN");
            assert_ne!(status_name(*code), "OK");
            assert_eq!(*code, i as u64 + 1);
        }
        assert_eq!(status_name(ERR_READ_ONLY), "READ_ONLY");
        assert_eq!(status_name(ERR_CROSS_DEVICE), "CROSS_DEVICE");
        assert_eq!(status_name(ERR_NOT_EMPTY), "NOT_EMPTY");
        assert_eq!(status_name(0xdead), "UNKNOWN");
    }

    #[test]
    fn rights_bits_are_distinct_single_bits() {
        assert_eq!(RIGHT_READ, 1);
        assert_eq!(RIGHT_WRITE, 2);
        assert_eq!(RIGHT_WAIT, 4);
        assert_eq!(RIGHT_DUPLICATE, 8);
        assert_eq!(RIGHT_READ.count_ones(), 1);
        assert_eq!(RIGHT_WRITE.count_ones(), 1);
        assert_eq!(RIGHT_WAIT.count_ones(), 1);
        assert_eq!(RIGHT_DUPLICATE.count_ones(), 1);
    }

    #[test]
    fn handle_encoding_is_generation_and_slot_plus_one() {
        assert_eq!(HANDLE_NONE, 0);
        assert_eq!(handle(1, 0), 0x0001_0001);
        // init's Random handle in the reference M4 boot: generation 1, slot 1.
        assert_eq!(handle(1, 1), 0x0001_0002);
        assert_eq!(handle(2, 0), 0x0002_0001);
        // Generation 0 is not used in practice, but the encoding stays
        // non-zero so slot 0 never collides with the invalid handle.
        assert_ne!(handle(0, 0), HANDLE_NONE);
    }

    #[test]
    fn process_create_request_layout_is_stable() {
        assert_eq!(size_of::<HandleTransfer>(), 8);
        assert_eq!(align_of::<HandleTransfer>(), 4);
        assert_eq!(size_of::<ProcessCreateRequest>(), 64);
        assert_eq!(align_of::<ProcessCreateRequest>(), 4);
        assert_eq!(ProcessCreateRequest::SIZE, 64);
        assert_eq!(offset_of!(ProcessCreateRequest, size), 0);
        assert_eq!(offset_of!(ProcessCreateRequest, version), 4);
        assert_eq!(offset_of!(ProcessCreateRequest, module_name), 8);
        assert_eq!(offset_of!(ProcessCreateRequest, handle_count), 24);
        assert_eq!(offset_of!(ProcessCreateRequest, reserved), 28);
        assert_eq!(offset_of!(ProcessCreateRequest, handles), 32);
    }

    #[test]
    fn empty_request_is_zeroed_and_valid() {
        let request = ProcessCreateRequest::empty();
        assert_eq!(request.size, ProcessCreateRequest::SIZE);
        assert_eq!(request.version, REQUEST_VERSION);
        assert_eq!(request.module_name, [0u8; MODULE_NAME_LEN]);
        assert_eq!(request.handle_count, 0);
        assert_eq!(request.reserved, 0);
        for transfer in request.handles {
            assert_eq!(transfer, HandleTransfer::new(HANDLE_NONE, 0));
        }
        assert_eq!(request.module_name(), b"");
    }

    #[test]
    fn module_name_is_nul_padded_and_truncated() {
        let request = ProcessCreateRequest::with_module_name(b"child");
        assert_eq!(request.module_name(), b"child");
        assert_eq!(&request.module_name[..5], b"child");
        assert!(request.module_name[5..].iter().all(|b| *b == 0));

        let long = b"abcdefghijklmnopqrstuvwxyz";
        let request = ProcessCreateRequest::with_module_name(long);
        assert_eq!(request.module_name(), &long[..MODULE_NAME_LEN]);
        assert_eq!(request.module_name().len(), MODULE_NAME_LEN);

        let empty = ProcessCreateRequest::with_module_name(b"");
        assert_eq!(empty.module_name(), b"");
    }

    #[test]
    fn handle_transfers_are_capped_at_max_handles() {
        let mut request = ProcessCreateRequest::with_module_name(b"child");
        for slot in 0..MAX_HANDLES {
            assert!(request.push_handle(handle(1, slot as u16), RIGHT_WRITE));
        }
        assert_eq!(request.handle_count as usize, MAX_HANDLES);
        assert!(!request.push_handle(handle(1, 9), RIGHT_READ));
        assert_eq!(request.handle_count as usize, MAX_HANDLES);
        assert_eq!(
            request.handles[0],
            HandleTransfer::new(handle(1, 0), RIGHT_WRITE)
        );
    }

    #[test]
    fn m5c1_request_layouts_are_pinned() {
        assert_eq!(size_of::<OpenRequest>(), 32);
        assert_eq!(align_of::<OpenRequest>(), 8);
        assert_eq!(OpenRequest::SIZE, 32);
        assert_eq!(offset_of!(OpenRequest, size), 0);
        assert_eq!(offset_of!(OpenRequest, version), 4);
        assert_eq!(offset_of!(OpenRequest, path_ptr), 8);
        assert_eq!(offset_of!(OpenRequest, path_len), 16);
        assert_eq!(offset_of!(OpenRequest, flags), 20);
        assert_eq!(offset_of!(OpenRequest, reserved), 24);

        assert_eq!(size_of::<StatOut>(), 32);
        assert_eq!(align_of::<StatOut>(), 8);
        assert_eq!(StatOut::SIZE, 32);
        assert_eq!(offset_of!(StatOut, kind), 8);
        assert_eq!(offset_of!(StatOut, flags), 12);
        assert_eq!(offset_of!(StatOut, file_size), 16);
        assert_eq!(offset_of!(StatOut, reserved), 24);

        assert_eq!(size_of::<DirEntryOut>(), 56);
        assert_eq!(align_of::<DirEntryOut>(), 8);
        assert_eq!(DirEntryOut::SIZE, 56);
        assert_eq!(offset_of!(DirEntryOut, kind), 8);
        assert_eq!(offset_of!(DirEntryOut, name_len), 12);
        assert_eq!(offset_of!(DirEntryOut, name), 16);
        assert_eq!(offset_of!(DirEntryOut, file_size), 48);

        assert_eq!(size_of::<RenameRequest>(), 40);
        assert_eq!(align_of::<RenameRequest>(), 8);
        assert_eq!(RenameRequest::SIZE, 40);
        assert_eq!(offset_of!(RenameRequest, old_ptr), 8);
        assert_eq!(offset_of!(RenameRequest, old_len), 16);
        assert_eq!(offset_of!(RenameRequest, new_len), 20);
        assert_eq!(offset_of!(RenameRequest, new_ptr), 24);
        assert_eq!(offset_of!(RenameRequest, reserved), 32);
    }

    #[test]
    fn request_headers_carry_layout_version_one() {
        let open = OpenRequest::new(0x1234, 7, OPEN_READ);
        assert_eq!(open.version, REQUEST_VERSION);
        assert!(open.header_valid());

        let stat = StatOut::empty();
        assert!(stat.header_valid());

        let entry = DirEntryOut::empty();
        assert!(entry.header_valid());

        let rename = RenameRequest::new(0x10, 3, 0x20, 5);
        assert_eq!(rename.version, REQUEST_VERSION);
        assert!(rename.header_valid());

        assert!(ProcessCreateRequest::empty().header_valid());

        let create = IpcCreateRequest::new(IPC_KIND_TIMER, 0, 0, 0);
        assert_eq!(create.version, REQUEST_VERSION);
        assert!(create.header_valid());

        let wait = WaitRequest::new(0, WAIT_TIMEOUT_IMMEDIATE);
        assert_eq!(wait.version, REQUEST_VERSION);
        assert!(wait.header_valid());

        let send = IpcSendRequest::new(0x4D36_4132, 1, 7);
        assert_eq!(send.version, REQUEST_VERSION);
        assert!(send.header_valid());

        let recv = IpcReceiveRequest::new(0x1000, IPC_DATA_MAX as u32, 0x2000, 0);
        assert_eq!(recv.version, REQUEST_VERSION);
        assert!(recv.header_valid());

        let shm = ShmMapRequest::new(PROT_READ | PROT_WRITE, 0x3000);
        assert_eq!(shm.version, REQUEST_VERSION);
        assert!(shm.header_valid());

        let subscribe = SubscribeRequest::new(0x4000, 1);
        assert_eq!(subscribe.version, REQUEST_VERSION);
        assert!(subscribe.header_valid());

        let read = SubscriptionReadRequest::new(SUBSCRIPTION_EVENTS_MAX as u32, 0x5000);
        assert_eq!(read.version, REQUEST_VERSION);
        assert!(read.header_valid());

        // A mismatched size or version is rejected by the same predicate the
        // kernel uses before it reads any other field.
        let mut wrong_size = open;
        wrong_size.size = 31;
        assert!(!wrong_size.header_valid());
        let mut wrong_version = open;
        wrong_version.version = 2;
        assert!(!wrong_version.header_valid());
    }

    #[test]
    fn open_flags_seek_whence_and_kinds_are_frozen() {
        assert_eq!(OPEN_READ, 1);
        assert_eq!(OPEN_WRITE, 2);
        assert_eq!(OPEN_CREATE, 4);
        assert_eq!(OPEN_TRUNC, 8);
        assert_eq!(OPEN_DIRECTORY, 16);
        assert_eq!(OPEN_VALID, 31);
        for bit in [
            OPEN_READ,
            OPEN_WRITE,
            OPEN_CREATE,
            OPEN_TRUNC,
            OPEN_DIRECTORY,
        ] {
            assert_eq!(bit.count_ones(), 1);
            assert_eq!(OPEN_VALID & bit, bit);
        }
        assert_eq!(SEEK_SET, 0);
        assert_eq!(SEEK_CUR, 1);
        assert_eq!(SEEK_END, 2);
        assert_eq!(NODE_FILE, 1);
        assert_eq!(NODE_DIRECTORY, 2);
        assert_eq!(STAT_FLAG_READ_ONLY, 1);
    }

    #[test]
    fn stat_out_reports_kind_flags_and_size() {
        let mut stat = StatOut::empty();
        assert!(!stat.is_file());
        assert!(!stat.is_directory());
        assert!(!stat.is_read_only());

        stat.kind = NODE_FILE;
        stat.file_size = 14;
        stat.flags = STAT_FLAG_READ_ONLY;
        assert!(stat.is_file());
        assert!(!stat.is_directory());
        assert!(stat.is_read_only());
        assert_eq!(stat.file_size, 14);

        stat.kind = NODE_DIRECTORY;
        stat.flags = 0;
        assert!(!stat.is_file());
        assert!(stat.is_directory());
        assert!(!stat.is_read_only());
    }

    #[test]
    fn dir_entry_name_reader_never_reads_out_of_bounds() {
        let mut entry = DirEntryOut::empty();
        assert_eq!(entry.name(), b"");

        entry.name_len = 5;
        entry.name[..5].copy_from_slice(b"inner");
        assert_eq!(entry.name(), b"inner");

        // A bogus length from a broken kernel yields an empty name rather than
        // a slice past the array.
        entry.name_len = (DirEntryOut::NAME_LEN + 1) as u32;
        assert_eq!(entry.name(), b"");

        entry.name_len = DirEntryOut::NAME_LEN as u32;
        assert_eq!(entry.name().len(), DirEntryOut::NAME_LEN);
    }

    #[test]
    fn rename_request_keeps_old_and_new_paths_distinct() {
        let request = RenameRequest::new(0x1000, 11, 0x2000, 9);
        assert_eq!(request.old_ptr, 0x1000);
        assert_eq!(request.old_len, 11);
        assert_eq!(request.new_ptr, 0x2000);
        assert_eq!(request.new_len, 9);
        assert_eq!(request.reserved, 0);
    }

    #[test]
    fn mmap_request_wire_layout_is_frozen() {
        assert_eq!(size_of::<MmapRequest>(), 48);
        assert_eq!(align_of::<MmapRequest>(), 8);
        assert_eq!(MmapRequest::SIZE, 48);
        assert_eq!(offset_of!(MmapRequest, size), 0);
        assert_eq!(offset_of!(MmapRequest, version), 4);
        assert_eq!(offset_of!(MmapRequest, len), 8);
        assert_eq!(offset_of!(MmapRequest, offset), 16);
        assert_eq!(offset_of!(MmapRequest, prot), 24);
        assert_eq!(offset_of!(MmapRequest, flags), 28);
        assert_eq!(offset_of!(MmapRequest, out_address), 32);
        assert_eq!(offset_of!(MmapRequest, reserved), 40);
    }

    #[test]
    fn mmap_request_round_trips_and_validates_its_header() {
        let request = MmapRequest::new(8192, 4096, PROT_READ | PROT_WRITE, MMAP_SHARED, 0x7000);
        assert_eq!(request.len, 8192);
        assert_eq!(request.offset, 4096);
        assert_eq!(request.prot, PROT_READ | PROT_WRITE);
        assert_eq!(request.flags, MMAP_SHARED);
        assert_eq!(request.out_address, 0x7000);
        assert_eq!(request.reserved, 0);
        assert!(request.header_valid());
        assert_eq!(request.size(), 48);
        assert_eq!(request.version(), REQUEST_VERSION);

        // A stale size or layout version must be rejected before the kernel
        // looks at any other field.
        let mut stale = request;
        stale.size = 40;
        assert!(!stale.header_valid());
        stale.size = MmapRequest::SIZE;
        stale.version = 2;
        assert!(!stale.header_valid());
    }

    #[test]
    fn mmap_protection_and_flag_bits_are_frozen() {
        assert_eq!(PROT_READ, 1);
        assert_eq!(PROT_WRITE, 2);
        assert_eq!(PROT_EXEC, 4);
        assert_eq!(PROT_VALID, PROT_READ | PROT_WRITE | PROT_EXEC);
        assert_eq!(MMAP_SHARED, 1);
        assert_eq!(MMAP_PRIVATE, 2);
        assert_eq!(MMAP_VALID, MMAP_SHARED | MMAP_PRIVATE);
        // Exactly one mapping kind must be selected.
        assert_eq!(MMAP_SHARED & MMAP_PRIVATE, 0);
        assert_eq!(MMAP_MAX_LEN, 256 * 1024);
    }

    #[test]
    fn lock_request_wire_layout_is_frozen() {
        assert_eq!(size_of::<LockRequest>(), 32);
        assert_eq!(align_of::<LockRequest>(), 8);
        assert_eq!(LockRequest::SIZE, 32);
        assert_eq!(offset_of!(LockRequest, size), 0);
        assert_eq!(offset_of!(LockRequest, version), 4);
        assert_eq!(offset_of!(LockRequest, domain), 8);
        assert_eq!(offset_of!(LockRequest, operation), 12);
        assert_eq!(offset_of!(LockRequest, offset), 16);
        assert_eq!(offset_of!(LockRequest, len), 24);

        // Domains and operations are enumerated values, not bit sets.
        assert_eq!(LOCK_DOMAIN_POSIX, 1);
        assert_eq!(LOCK_DOMAIN_OFD, 2);
        assert_eq!(LOCK_DOMAIN_FLOCK, 3);
        assert_eq!(LOCK_DOMAIN_MAX, 3);
        assert_eq!(LOCK_OP_SHARED, 1);
        assert_eq!(LOCK_OP_EXCLUSIVE, 2);
        assert_eq!(LOCK_OP_UNLOCK, 3);
        assert_eq!(LOCK_OP_MAX, 3);
    }

    #[test]
    fn xattr_request_wire_layout_and_limits_are_frozen() {
        assert_eq!(size_of::<XattrRequest>(), 40);
        assert_eq!(align_of::<XattrRequest>(), 8);
        assert_eq!(XattrRequest::SIZE, 40);
        assert_eq!(offset_of!(XattrRequest, size), 0);
        assert_eq!(offset_of!(XattrRequest, version), 4);
        assert_eq!(offset_of!(XattrRequest, name_ptr), 8);
        assert_eq!(offset_of!(XattrRequest, name_len), 16);
        assert_eq!(offset_of!(XattrRequest, value_ptr), 24);
        assert_eq!(offset_of!(XattrRequest, value_len), 32);
        assert_eq!(XATTR_NAME_MAX, 16);
        assert_eq!(XATTR_VALUE_MAX, 64);
        assert_eq!(XATTR_USER_PREFIX, b"user.");
    }

    #[test]
    fn watch_requests_and_events_wire_layouts_are_frozen() {
        assert_eq!(size_of::<WatchDrainRequest>(), 24);
        assert_eq!(align_of::<WatchDrainRequest>(), 8);
        assert_eq!(WatchDrainRequest::SIZE, 24);
        assert_eq!(offset_of!(WatchDrainRequest, size), 0);
        assert_eq!(offset_of!(WatchDrainRequest, version), 4);
        assert_eq!(offset_of!(WatchDrainRequest, events_ptr), 8);
        assert_eq!(offset_of!(WatchDrainRequest, max_events), 16);

        assert_eq!(size_of::<WatchEventOut>(), 48);
        assert_eq!(align_of::<WatchEventOut>(), 8);
        assert_eq!(WatchEventOut::SIZE, 48);
        assert_eq!(offset_of!(WatchEventOut, kind), 0);
        assert_eq!(offset_of!(WatchEventOut, name_len), 4);
        assert_eq!(offset_of!(WatchEventOut, name), 8);
        assert_eq!(offset_of!(WatchEventOut, dropped), 40);

        assert_eq!(WATCH_EVENT_CREATED, 1);
        assert_eq!(WATCH_EVENT_DELETED, 2);
        assert_eq!(WATCH_EVENT_RENAMED, 3);
        assert_eq!(WATCH_EVENT_KIND_MAX, 3);
        assert_eq!(WATCH_EVENT_NAME_LEN, 32);
        assert_eq!(WatchEventOut::NAME_LEN, 32);
        assert_eq!(WATCH_MAX_BATCH, 16);
    }

    #[test]
    fn watch_event_name_reader_never_reads_out_of_bounds() {
        let mut event = WatchEventOut::empty();
        assert_eq!(event.name(), b"");
        event.name_len = 3;
        event.name[..3].copy_from_slice(b"A.B");
        assert_eq!(event.name(), b"A.B");
        event.name_len = (WatchEventOut::NAME_LEN + 1) as u32;
        assert_eq!(event.name(), b"");
        event.name_len = WatchEventOut::NAME_LEN as u32;
        assert_eq!(event.name().len(), WatchEventOut::NAME_LEN);
    }

    #[test]
    fn m5c3_requests_round_trip_and_validate_their_headers() {
        let lock = LockRequest::new(LOCK_DOMAIN_OFD, LOCK_OP_EXCLUSIVE, 0, 0);
        assert_eq!(lock.domain, LOCK_DOMAIN_OFD);
        assert_eq!(lock.operation, LOCK_OP_EXCLUSIVE);
        assert!(lock.header_valid());

        let xattr = XattrRequest::new(0x1000, 10, 0x2000, 5);
        assert_eq!(xattr.name_ptr, 0x1000);
        assert_eq!(xattr.name_len, 10);
        assert_eq!(xattr.value_ptr, 0x2000);
        assert_eq!(xattr.value_len, 5);
        assert!(xattr.header_valid());

        let drain = WatchDrainRequest::new(0x3000, WATCH_MAX_BATCH);
        assert_eq!(drain.events_ptr, 0x3000);
        assert_eq!(drain.max_events, 16);
        assert!(drain.header_valid());

        // Stale sizes and layout versions must be rejected before the kernel
        // looks at any other field.
        let mut stale = lock;
        stale.size = 24;
        assert!(!stale.header_valid());
        stale.size = LockRequest::SIZE;
        stale.version = 2;
        assert!(!stale.header_valid());
    }

    #[test]
    fn ipc_create_request_wire_layout_is_frozen() {
        assert_eq!(
            size_of::<IpcCreateRequest>(),
            IpcCreateRequest::SIZE as usize
        );
        assert_eq!(align_of::<IpcCreateRequest>(), 8);
        assert_eq!(offset_of!(IpcCreateRequest, size), 0);
        assert_eq!(offset_of!(IpcCreateRequest, version), 4);
        assert_eq!(offset_of!(IpcCreateRequest, kind), 8);
        assert_eq!(offset_of!(IpcCreateRequest, flags), 12);
        assert_eq!(offset_of!(IpcCreateRequest, arg0), 16);
        assert_eq!(offset_of!(IpcCreateRequest, arg1), 24);
        assert_eq!(offset_of!(IpcCreateRequest, out_second_ptr), 32);
        assert_eq!(IpcCreateRequest::SIZE, 40);

        assert_eq!(IPC_KIND_EVENT, 1);
        assert_eq!(IPC_KIND_EVENT_PAIR, 2);
        assert_eq!(IPC_KIND_CHANNEL, 3);
        assert_eq!(IPC_KIND_PORT, 4);
        assert_eq!(IPC_KIND_SHARED_MEMORY, 5);
        assert_eq!(IPC_KIND_TIMER, 6);
        assert_eq!(IPC_KIND_SUBSCRIPTION, 7);
        assert_eq!(IPC_KIND_MAX, 7);
        assert_eq!(EVENT_FLAG_MANUAL_RESET, 1);
        assert_eq!(EVENT_PAIR_ENDPOINT_A, 0);
        assert_eq!(EVENT_PAIR_ENDPOINT_B, 1);
        assert_eq!(SIGNAL_OP_RESET, 0);
        assert_eq!(SIGNAL_OP_SIGNAL, 1);
    }

    #[test]
    fn wait_request_wire_layout_is_frozen_at_ninety_six_bytes() {
        assert_eq!(size_of::<WaitItem>(), WaitItem::SIZE as usize);
        assert_eq!(size_of::<WaitRequest>(), WaitRequest::SIZE as usize);
        assert_eq!(size_of::<WaitOut>(), WaitOut::SIZE as usize);
        assert_eq!(align_of::<WaitRequest>(), 8);

        assert_eq!(offset_of!(WaitRequest, size), 0);
        assert_eq!(offset_of!(WaitRequest, version), 4);
        assert_eq!(offset_of!(WaitRequest, flags), 8);
        assert_eq!(offset_of!(WaitRequest, timeout_ticks), 12);
        assert_eq!(offset_of!(WaitRequest, count), 16);
        assert_eq!(offset_of!(WaitRequest, reserved), 20);
        assert_eq!(offset_of!(WaitRequest, out_ptr), 24);
        assert_eq!(offset_of!(WaitRequest, items), 32);
        assert_eq!(WaitRequest::SIZE, 96);
        assert_eq!(WAIT_MAX_ITEMS, 4);
        assert_eq!(WAIT_ITEM_SIZE, 16);
        assert_eq!(WAIT_TIMEOUT_IMMEDIATE, 0);
        assert_eq!(WAIT_TIMEOUT_INFINITE, 0xFFFF_FFFF);

        // Item: handle at 0, flags at 8, key at 12.
        assert_eq!(offset_of!(WaitItem, handle), 0);
        assert_eq!(offset_of!(WaitItem, flags), 8);
        assert_eq!(offset_of!(WaitItem, key), 12);
        let item = WaitItem::new(handle(1, 2), EVENT_PAIR_ENDPOINT_B);
        assert_eq!(item.handle, handle(1, 2) as u64);
        assert_eq!(item.flags, 0);
        assert_eq!(item.key, EVENT_PAIR_ENDPOINT_B);

        // Output: mask/reason/key/reserved.
        let out = WaitOut {
            ready_mask: 0b0011,
            wake_reason: WAKE_READY,
            ready_key: EVENT_PAIR_ENDPOINT_B,
            reserved: 0,
        };
        assert!(out.is_ready(0));
        assert!(out.is_ready(1));
        assert!(!out.is_ready(2));
        assert!(!out.is_ready(WAIT_MAX_ITEMS));
        assert_eq!(WAKE_NONE, 0);
        assert_eq!(WAKE_READY, 1);
        assert_eq!(WAKE_TIMEOUT, 2);
        assert_eq!(WAKE_DESTROYED, 3);
        assert_eq!(WAKE_CANCELLED, 4);
        assert_eq!(WAKE_PEER_CLOSED, 5);
    }

    #[test]
    fn m6a1_requests_round_trip_and_validate_their_headers() {
        let create = IpcCreateRequest::new(IPC_KIND_EVENT, 0, 0, 0);
        assert_eq!(create.kind, IPC_KIND_EVENT);
        assert_eq!(create.size, IpcCreateRequest::SIZE);
        assert!(create.header_valid());

        let mut wait = WaitRequest::new(0x5000, WAIT_TIMEOUT_INFINITE);
        assert_eq!(wait.out_ptr, 0x5000);
        assert_eq!(wait.timeout_ticks, WAIT_TIMEOUT_INFINITE);
        assert_eq!(wait.count, 0);
        assert!(wait.header_valid());
        assert!(wait.push(WaitItem::new(handle(1, 1), EVENT_PAIR_ENDPOINT_B)));
        assert_eq!(wait.count, 1);
        assert!(wait.push(WaitItem::new(handle(1, 2), 0)));
        assert!(wait.push(WaitItem::new(handle(1, 3), 0)));
        assert!(wait.push(WaitItem::new(handle(1, 4), 0)));
        assert!(!wait.push(WaitItem::new(handle(1, 5), 0)));
        assert_eq!(wait.count, WAIT_MAX_ITEMS as u32);

        let mut stale = wait;
        stale.size = 88;
        assert!(!stale.header_valid());
        stale.size = WaitRequest::SIZE;
        stale.version = 2;
        assert!(!stale.header_valid());
    }

    #[test]
    fn m6a1_error_codes_are_named() {
        assert_eq!(ERR_CANCELLED, 22);
        assert_eq!(ERR_PEER_CLOSED, 23);
        assert_eq!(status_name(ERR_CANCELLED), "CANCELLED");
        assert_eq!(status_name(ERR_PEER_CLOSED), "PEER_CLOSED");
    }

    #[test]
    fn ipc_send_and_receive_request_wire_layouts_are_frozen() {
        assert_eq!(size_of::<IpcSendRequest>(), IpcSendRequest::SIZE as usize);
        assert_eq!(align_of::<IpcSendRequest>(), 8);
        assert_eq!(IpcSendRequest::SIZE, 64);
        assert_eq!(offset_of!(IpcSendRequest, size), 0);
        assert_eq!(offset_of!(IpcSendRequest, version), 4);
        assert_eq!(offset_of!(IpcSendRequest, protocol), 8);
        assert_eq!(offset_of!(IpcSendRequest, msg_version), 12);
        assert_eq!(offset_of!(IpcSendRequest, transaction), 16);
        assert_eq!(offset_of!(IpcSendRequest, data_ptr), 24);
        assert_eq!(offset_of!(IpcSendRequest, data_len), 32);
        assert_eq!(offset_of!(IpcSendRequest, handle_count), 36);
        assert_eq!(offset_of!(IpcSendRequest, handles_ptr), 40);
        assert_eq!(offset_of!(IpcSendRequest, rights_ptr), 48);
        assert_eq!(offset_of!(IpcSendRequest, reserved), 56);

        assert_eq!(
            size_of::<IpcReceiveRequest>(),
            IpcReceiveRequest::SIZE as usize
        );
        assert_eq!(align_of::<IpcReceiveRequest>(), 8);
        assert_eq!(IpcReceiveRequest::SIZE, 64);
        assert_eq!(offset_of!(IpcReceiveRequest, size), 0);
        assert_eq!(offset_of!(IpcReceiveRequest, version), 4);
        assert_eq!(offset_of!(IpcReceiveRequest, data_ptr), 8);
        assert_eq!(offset_of!(IpcReceiveRequest, data_capacity), 16);
        assert_eq!(offset_of!(IpcReceiveRequest, handle_capacity), 20);
        assert_eq!(offset_of!(IpcReceiveRequest, out_handles_ptr), 24);
        assert_eq!(offset_of!(IpcReceiveRequest, out_rights_ptr), 32);
        assert_eq!(offset_of!(IpcReceiveRequest, out_meta_ptr), 40);
        assert_eq!(offset_of!(IpcReceiveRequest, timeout_ticks), 48);
        assert_eq!(offset_of!(IpcReceiveRequest, reserved), 56);

        assert_eq!(size_of::<IpcMessageMeta>(), IpcMessageMeta::SIZE as usize);
        assert_eq!(align_of::<IpcMessageMeta>(), 8);
        assert_eq!(IpcMessageMeta::SIZE, 32);
        assert_eq!(offset_of!(IpcMessageMeta, protocol), 0);
        assert_eq!(offset_of!(IpcMessageMeta, version), 4);
        assert_eq!(offset_of!(IpcMessageMeta, transaction), 8);
        assert_eq!(offset_of!(IpcMessageMeta, data_len), 16);
        assert_eq!(offset_of!(IpcMessageMeta, handle_count), 20);
        assert_eq!(offset_of!(IpcMessageMeta, sender_pid), 24);
        assert_eq!(offset_of!(IpcMessageMeta, reserved), 28);

        assert_eq!(IPC_DATA_MAX, 64);
        assert_eq!(IPC_HANDLES_MAX, 2);
    }

    #[test]
    fn m6a2_shm_and_subscription_layouts_are_frozen() {
        assert_eq!(size_of::<ShmMapRequest>(), ShmMapRequest::SIZE as usize);
        assert_eq!(align_of::<ShmMapRequest>(), 8);
        assert_eq!(ShmMapRequest::SIZE, 32);
        assert_eq!(offset_of!(ShmMapRequest, size), 0);
        assert_eq!(offset_of!(ShmMapRequest, version), 4);
        assert_eq!(offset_of!(ShmMapRequest, prot), 8);
        assert_eq!(offset_of!(ShmMapRequest, reserved), 12);
        assert_eq!(offset_of!(ShmMapRequest, out_address), 16);
        assert_eq!(offset_of!(ShmMapRequest, reserved_high), 24);

        assert_eq!(
            size_of::<SubscribeRequest>(),
            SubscribeRequest::SIZE as usize
        );
        assert_eq!(SubscribeRequest::SIZE, 24);
        assert_eq!(offset_of!(SubscribeRequest, size), 0);
        assert_eq!(offset_of!(SubscribeRequest, version), 4);
        assert_eq!(offset_of!(SubscribeRequest, count), 8);
        assert_eq!(offset_of!(SubscribeRequest, reserved), 12);
        assert_eq!(offset_of!(SubscribeRequest, entries_ptr), 16);

        assert_eq!(
            size_of::<SubscriptionEntry>(),
            SubscriptionEntry::SIZE as usize
        );
        assert_eq!(SubscriptionEntry::SIZE, 16);
        assert_eq!(offset_of!(SubscriptionEntry, handle), 0);
        assert_eq!(offset_of!(SubscriptionEntry, mode), 4);
        assert_eq!(offset_of!(SubscriptionEntry, key), 8);

        assert_eq!(
            size_of::<SubscriptionReadRequest>(),
            SubscriptionReadRequest::SIZE as usize
        );
        assert_eq!(SubscriptionReadRequest::SIZE, 24);
        assert_eq!(offset_of!(SubscriptionReadRequest, size), 0);
        assert_eq!(offset_of!(SubscriptionReadRequest, version), 4);
        assert_eq!(offset_of!(SubscriptionReadRequest, max_events), 8);
        assert_eq!(offset_of!(SubscriptionReadRequest, reserved), 12);
        assert_eq!(offset_of!(SubscriptionReadRequest, out_events_ptr), 16);

        assert_eq!(
            size_of::<SubscriptionEvent>(),
            SubscriptionEvent::SIZE as usize
        );
        assert_eq!(SubscriptionEvent::SIZE, 16);
        assert_eq!(offset_of!(SubscriptionEvent, object_key), 0);
        assert_eq!(offset_of!(SubscriptionEvent, mode), 8);
        assert_eq!(offset_of!(SubscriptionEvent, reserved), 12);
    }

    #[test]
    fn m6a2_requests_round_trip_and_validate_their_headers() {
        let mut send = IpcSendRequest::new(0x4D36_4132, 1, 0x1122_3344);
        send.data_ptr = 0x1000;
        send.data_len = 3;
        send.handle_count = 1;
        send.handles_ptr = 0x2000;
        send.rights_ptr = 0x2008;
        assert_eq!(send.protocol, 0x4D36_4132);
        assert!(send.header_valid());

        let mut recv = IpcReceiveRequest::new(0x3000, IPC_DATA_MAX as u32, 0x4000, 5);
        recv.handle_capacity = IPC_HANDLES_MAX as u32;
        recv.out_handles_ptr = 0x5000;
        recv.out_rights_ptr = 0x5008;
        assert_eq!(recv.timeout_ticks, 5);
        assert!(recv.header_valid());

        let shm = ShmMapRequest::new(PROT_READ | PROT_WRITE, 0x6000);
        assert_eq!(shm.prot, PROT_READ | PROT_WRITE);
        assert_eq!(shm.reserved_high, 0);
        assert!(shm.header_valid());

        let entry = SubscriptionEntry::new(handle(1, 3), SUBSCRIPTION_MODE_EDGE, 0);
        assert_eq!(entry.handle, handle(1, 3));
        assert_eq!(entry.mode, SUBSCRIPTION_MODE_EDGE);

        let subscribe = SubscribeRequest::new(0x7000, 1);
        assert_eq!(subscribe.count, 1);
        assert!(subscribe.header_valid());

        let read = SubscriptionReadRequest::new(2, 0x8000);
        assert_eq!(read.max_events, 2);
        assert!(read.header_valid());

        assert_eq!(IpcMessageMeta::empty(), IpcMessageMeta::default());
        assert_eq!(SubscriptionEvent::empty(), SubscriptionEvent::default());

        // Stale sizes and layout versions are rejected before any other field.
        let mut stale = send;
        stale.size = 32;
        assert!(!stale.header_valid());
        stale.size = IpcSendRequest::SIZE;
        stale.version = 2;
        assert!(!stale.header_valid());
    }

    #[test]
    fn m6a2_constants_and_rights_are_frozen() {
        assert_eq!(RIGHT_READ, 1);
        assert_eq!(RIGHT_WRITE, 2);
        assert_eq!(RIGHT_WAIT, 4);
        assert_eq!(RIGHT_DUPLICATE, 8);
        assert_eq!(RIGHT_MAP, 16);
        assert_eq!(SUBSCRIPTION_MODE_LEVEL, 1);
        assert_eq!(SUBSCRIPTION_MODE_EDGE, 2);
        assert_eq!(SUBSCRIBE_MAX_ENTRIES, 4);
        assert_eq!(SUBSCRIPTION_EVENTS_MAX, 16);
        assert_eq!(NR_IPC_SEND, 30);
        assert_eq!(NR_IPC_RECV, 31);
        assert_eq!(NR_SHM_MAP, 32);
        assert_eq!(NR_SUBSCRIBE, 34);
        assert_eq!(NR_UNSUBSCRIBE, 35);
        assert_eq!(NR_FUTEX_WAIT, 37);
        assert_eq!(NR_FUTEX_WAKE, 38);
        assert_eq!(NR_SUBSCRIPTION_READ, 39);

        // object_key = (object_raw << 32) | key.
        let key = subscription_object_key(0xABCD_1234, 1);
        assert_eq!(key, 0xABCD_1234_0000_0001);
        assert_eq!(subscription_object_raw(key), 0xABCD_1234);
        assert_eq!(subscription_key(key), 1);
    }

    #[test]
    fn m6c_display_and_input_layouts_are_frozen() {
        assert_eq!(
            size_of::<DisplayInfoRequest>(),
            DisplayInfoRequest::SIZE as usize
        );
        assert_eq!(align_of::<DisplayInfoRequest>(), 8);
        assert_eq!(DisplayInfoRequest::SIZE, 24);
        assert_eq!(offset_of!(DisplayInfoRequest, size), 0);
        assert_eq!(offset_of!(DisplayInfoRequest, version), 4);
        assert_eq!(offset_of!(DisplayInfoRequest, out_info_ptr), 8);
        assert_eq!(offset_of!(DisplayInfoRequest, reserved), 16);

        assert_eq!(size_of::<DisplayInfoWire>(), DisplayInfoWire::SIZE as usize);
        assert_eq!(align_of::<DisplayInfoWire>(), 8);
        assert_eq!(DisplayInfoWire::SIZE, 32);
        assert_eq!(offset_of!(DisplayInfoWire, width), 0);
        assert_eq!(offset_of!(DisplayInfoWire, height), 4);
        assert_eq!(offset_of!(DisplayInfoWire, stride), 8);
        assert_eq!(offset_of!(DisplayInfoWire, pixel_format), 12);
        assert_eq!(offset_of!(DisplayInfoWire, shadow_bytes), 16);
        assert_eq!(offset_of!(DisplayInfoWire, reserved), 24);

        assert_eq!(
            size_of::<DisplayPresentRequest>(),
            DisplayPresentRequest::SIZE as usize
        );
        assert_eq!(align_of::<DisplayPresentRequest>(), 4);
        assert_eq!(DisplayPresentRequest::SIZE, 24);
        assert_eq!(offset_of!(DisplayPresentRequest, size), 0);
        assert_eq!(offset_of!(DisplayPresentRequest, version), 4);
        assert_eq!(offset_of!(DisplayPresentRequest, x), 8);
        assert_eq!(offset_of!(DisplayPresentRequest, y), 12);
        assert_eq!(offset_of!(DisplayPresentRequest, w), 16);
        assert_eq!(offset_of!(DisplayPresentRequest, h), 20);

        assert_eq!(
            size_of::<InputReadRequest>(),
            InputReadRequest::SIZE as usize
        );
        assert_eq!(align_of::<InputReadRequest>(), 8);
        assert_eq!(InputReadRequest::SIZE, 24);
        assert_eq!(offset_of!(InputReadRequest, size), 0);
        assert_eq!(offset_of!(InputReadRequest, version), 4);
        assert_eq!(offset_of!(InputReadRequest, max_events), 8);
        assert_eq!(offset_of!(InputReadRequest, reserved), 12);
        assert_eq!(offset_of!(InputReadRequest, out_events_ptr), 16);

        assert_eq!(size_of::<InputEventWire>(), InputEventWire::SIZE as usize);
        assert_eq!(align_of::<InputEventWire>(), 8);
        assert_eq!(InputEventWire::SIZE, 24);
        assert_eq!(offset_of!(InputEventWire, kind), 0);
        assert_eq!(offset_of!(InputEventWire, code), 4);
        assert_eq!(offset_of!(InputEventWire, sequence), 8);
        assert_eq!(offset_of!(InputEventWire, reserved), 12);
        assert_eq!(offset_of!(InputEventWire, timestamp_ms), 16);

        // `display_map` reuses the shared-memory map request unchanged.
        assert_eq!(size_of::<ShmMapRequest>(), 32);
    }

    #[test]
    fn m6c_requests_round_trip_and_constants_are_frozen() {
        assert_eq!(DISPLAY_WIDTH, 320);
        assert_eq!(DISPLAY_HEIGHT, 200);
        assert_eq!(DISPLAY_FRAME_BYTES, 256_000);
        assert_eq!(INPUT_EVENTS_MAX, 16);
        assert_eq!(INPUT_EVENT_KIND_KEYBOARD, 1);
        assert_eq!(INPUT_EVENT_KIND_SERIAL, 2);
        assert_eq!(NR_DISPLAY_INFO, 40);
        assert_eq!(NR_DISPLAY_MAP, 41);
        assert_eq!(NR_DISPLAY_PRESENT, 42);
        assert_eq!(NR_INPUT_READ, 43);

        assert_eq!(DisplayInfoWire::empty(), DisplayInfoWire::default());
        assert_eq!(InputEventWire::empty(), InputEventWire::default());

        let mut info = DisplayInfoRequest::new(0x1000);
        assert!(info.header_valid());
        assert_eq!(info.out_info_ptr, 0x1000);

        let present = DisplayPresentRequest::new();
        assert!(present.header_valid());
        assert_eq!(
            (present.x, present.y, present.w, present.h),
            (0, 0, 320, 200)
        );

        let read = InputReadRequest::new(INPUT_EVENTS_MAX, 0x3000);
        assert!(read.header_valid());
        assert_eq!(read.max_events, INPUT_EVENTS_MAX);
        assert_eq!(read.out_events_ptr, 0x3000);

        // Stale sizes and layout versions are rejected before any other field.
        let mut stale = info;
        stale.size = 16;
        assert!(!stale.header_valid());
        stale.size = DisplayInfoRequest::SIZE;
        stale.version = 2;
        assert!(!stale.header_valid());

        let mut event = InputEventWire::empty();
        event.kind = INPUT_EVENT_KIND_KEYBOARD;
        event.code = 0x20;
        event.sequence = 1;
        event.timestamp_ms = 7;
        assert_eq!((event.kind, event.code, event.sequence), (1, 0x20, 1));
        assert_eq!(event.timestamp_ms, 7);
    }

    #[test]
    fn m7b_socket_address_and_request_layouts_are_frozen() {
        // SocketAddrWire: 4+4+4+16+4+4+108 = 144 bytes, align 4.
        assert_eq!(SocketAddrWire::SIZE, SOCKET_ADDR_WIRE);
        assert_eq!(SOCKET_ADDR_WIRE, 144);
        assert_eq!(size_of::<SocketAddrWire>(), 144);
        assert_eq!(align_of::<SocketAddrWire>(), 4);
        assert_eq!(offset_of!(SocketAddrWire, family), 0);
        assert_eq!(offset_of!(SocketAddrWire, port), 4);
        assert_eq!(offset_of!(SocketAddrWire, flags), 8);
        assert_eq!(offset_of!(SocketAddrWire, addr), 12);
        assert_eq!(offset_of!(SocketAddrWire, scope), 28);
        assert_eq!(offset_of!(SocketAddrWire, path_len), 32);
        assert_eq!(offset_of!(SocketAddrWire, path), 36);
        assert_eq!(SOCKET_PATH_BYTES, 108);
        assert_eq!(SOCKET_PATH_MAX, 107);

        let mut address = SocketAddrWire::empty();
        assert!(address.path_len_valid());
        address.path_len = SOCKET_PATH_MAX;
        assert!(address.path_len_valid());
        address.path_len = SOCKET_PATH_MAX + 1;
        assert!(!address.path_len_valid());

        // Requests: 8-byte size/version header plus their frozen payloads.
        assert_eq!(
            size_of::<SocketCreateRequest>(),
            SocketCreateRequest::SIZE as usize
        );
        assert_eq!(SocketCreateRequest::SIZE, 32);
        assert_eq!(align_of::<SocketCreateRequest>(), 4);
        assert_eq!(offset_of!(SocketCreateRequest, domain), 8);
        assert_eq!(offset_of!(SocketCreateRequest, kind), 12);
        assert_eq!(offset_of!(SocketCreateRequest, protocol), 16);
        assert_eq!(offset_of!(SocketCreateRequest, flags), 20);
        assert_eq!(offset_of!(SocketCreateRequest, namespace_handle), 24);
        assert_eq!(offset_of!(SocketCreateRequest, reserved), 28);

        assert_eq!(
            size_of::<SocketAddrRequest>(),
            SocketAddrRequest::SIZE as usize
        );
        assert_eq!(SocketAddrRequest::SIZE, 24);
        assert_eq!(align_of::<SocketAddrRequest>(), 8);
        assert_eq!(offset_of!(SocketAddrRequest, addr_len), 8);
        assert_eq!(offset_of!(SocketAddrRequest, reserved), 12);
        assert_eq!(offset_of!(SocketAddrRequest, addr_ptr), 16);

        assert_eq!(
            size_of::<SocketAcceptRequest>(),
            SocketAcceptRequest::SIZE as usize
        );
        assert_eq!(SocketAcceptRequest::SIZE, 16);
        assert_eq!(offset_of!(SocketAcceptRequest, out_handle_ptr), 8);

        assert_eq!(
            size_of::<SocketSendRequest>(),
            SocketSendRequest::SIZE as usize
        );
        assert_eq!(SocketSendRequest::SIZE, 24);
        assert_eq!(offset_of!(SocketSendRequest, flags), 8);
        assert_eq!(offset_of!(SocketSendRequest, data_len), 12);
        assert_eq!(offset_of!(SocketSendRequest, data_ptr), 16);

        assert_eq!(
            size_of::<SocketRecvRequest>(),
            SocketRecvRequest::SIZE as usize
        );
        assert_eq!(SocketRecvRequest::SIZE, 32);
        assert_eq!(offset_of!(SocketRecvRequest, flags), 8);
        assert_eq!(offset_of!(SocketRecvRequest, data_capacity), 12);
        assert_eq!(offset_of!(SocketRecvRequest, data_ptr), 16);
        assert_eq!(offset_of!(SocketRecvRequest, out_source_ptr), 24);

        assert_eq!(
            size_of::<SocketPairRequest>(),
            SocketPairRequest::SIZE as usize
        );
        assert_eq!(SocketPairRequest::SIZE, 24);
        assert_eq!(offset_of!(SocketPairRequest, domain), 8);
        assert_eq!(offset_of!(SocketPairRequest, kind), 12);
        assert_eq!(offset_of!(SocketPairRequest, out_handles_ptr), 16);

        assert_eq!(
            size_of::<SocketAddressRequest>(),
            SocketAddressRequest::SIZE as usize
        );
        assert_eq!(SocketAddressRequest::SIZE, 24);
        assert_eq!(offset_of!(SocketAddressRequest, which), 8);
        assert_eq!(offset_of!(SocketAddressRequest, reserved), 12);
        assert_eq!(offset_of!(SocketAddressRequest, out_addr_ptr), 16);

        // The bind/connect alias must stay the same wire type.
        assert_eq!(
            size_of::<BindConnectRequest>(),
            SocketAddrRequest::SIZE as usize
        );
    }

    #[test]
    fn m7b_requests_round_trip_and_constants_are_frozen() {
        assert_eq!(SOCKET_DOMAIN_UNIX, 1);
        assert_eq!(SOCKET_DOMAIN_INET, 2);
        assert_eq!(SOCKET_DOMAIN_INET6, 10);
        assert_eq!(SOCKET_FAMILY_UNIX, 1);
        assert_eq!(SOCKET_FAMILY_INET, SOCKET_DOMAIN_INET);
        assert_eq!(SOCKET_FAMILY_INET6, SOCKET_DOMAIN_INET6);
        assert_eq!(SOCKET_KIND_STREAM, 1);
        assert_eq!(SOCKET_KIND_DGRAM, 2);
        assert_eq!(
            (
                SOCKET_SHUTDOWN_READ,
                SOCKET_SHUTDOWN_WRITE,
                SOCKET_SHUTDOWN_BOTH
            ),
            (0, 1, 2)
        );
        assert_eq!((SOCKET_ADDR_LOCAL, SOCKET_ADDR_PEER), (0, 1));
        assert_eq!(ERR_PEER_CLOSED, 23);
        assert_eq!(ERR_CONNECTION_REFUSED, 24);
        assert_eq!(ERR_CONNECTION_RESET, 25);
        assert_eq!(ERR_NOT_CONNECTED, 26);
        assert_eq!(status_name(ERR_CONNECTION_REFUSED), "CONNECTION_REFUSED");
        assert_eq!(status_name(ERR_CONNECTION_RESET), "CONNECTION_RESET");
        assert_eq!(status_name(ERR_NOT_CONNECTED), "NOT_CONNECTED");

        let create = SocketCreateRequest::new(SOCKET_DOMAIN_UNIX, SOCKET_KIND_STREAM, 0x0001_0005);
        assert!(create.header_valid());
        assert_eq!(create.domain, SOCKET_DOMAIN_UNIX);
        assert_eq!(create.namespace_handle, 0x0001_0005);
        assert_eq!(create.protocol, 0);
        assert_eq!(create.flags, 0);
        assert_eq!(create.reserved, 0);

        let bind = SocketAddrRequest::new(0x4000);
        assert!(bind.header_valid());
        assert_eq!(bind.addr_len, SOCKET_ADDR_WIRE);
        assert_eq!(bind.addr_ptr, 0x4000);
        let connect: BindConnectRequest = SocketAddrRequest::new(0x5000);
        assert_eq!(connect.addr_ptr, 0x5000);

        let accept = SocketAcceptRequest::new(0x6000);
        assert!(accept.header_valid());
        assert_eq!(accept.out_handle_ptr, 0x6000);

        let send = SocketSendRequest::new(0x7000, 5);
        assert!(send.header_valid());
        assert_eq!((send.data_ptr, send.data_len, send.flags), (0x7000, 5, 0));

        let recv = SocketRecvRequest::new(0x8000, 64);
        assert!(recv.header_valid());
        assert_eq!((recv.data_ptr, recv.data_capacity), (0x8000, 64));
        assert_eq!(recv.out_source_ptr, 0);

        let pair = SocketPairRequest::new(SOCKET_DOMAIN_UNIX, SOCKET_KIND_DGRAM, 0x9000);
        assert!(pair.header_valid());
        assert_eq!(
            (pair.domain, pair.kind),
            (SOCKET_DOMAIN_UNIX, SOCKET_KIND_DGRAM)
        );
        assert_eq!(pair.out_handles_ptr, 0x9000);

        let address = SocketAddressRequest::new(SOCKET_ADDR_PEER, 0xa000);
        assert!(address.header_valid());
        assert_eq!(
            (address.which, address.out_addr_ptr),
            (SOCKET_ADDR_PEER, 0xa000)
        );

        // Stale sizes and layout versions are rejected before any other field.
        let mut stale = create;
        stale.size = 24;
        assert!(!stale.header_valid());
        stale.size = SocketCreateRequest::SIZE;
        stale.version = REQUEST_VERSION + 1;
        assert!(!stale.header_valid());
        let mut stale_recv = recv;
        stale_recv.size = SocketRecvRequest::SIZE - 8;
        assert!(!stale_recv.header_valid());
    }
}
