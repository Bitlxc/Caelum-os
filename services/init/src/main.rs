//! CaelumOS `init`: the first native user process.
//!
//! Boot protocol for native user programs (ABI 0.2): the kernel enters
//! `_start` with `rdi` = first transferred handle (Console) and `rsi` = second
//! transferred handle (Random), both zero-extended 64-bit values. An absent
//! second handle is passed as 0 (`HANDLE_NONE`).
//!
//! init only talks to the kernel through the native syscall ABI; it never
//! touches the serial port or any hardware directly.
//!
//! M4 sequence (markers unchanged, they are the regression contract):
//!
//! 1. `abi_query` must report [`ABI_VERSION`], then `[CaelumInit] M4 init OK`.
//! 2. Spawn `child`, transferring only the Console handle with WRITE rights,
//!    then `[CaelumInit] M4 spawn OK`.
//! 3. Wait (non-blocking syscall wrapped in a `pause` loop) for the child to
//!    exit with status 0, then `[CaelumInit] M4 wait OK`.
//! 4. `random_read` on init's own Random handle must report `NO_ENTROPY` at
//!    early boot, then `[CaelumInit] M4 rng OK`.
//! 5. `process_exit(0)`.
//!
//! M5c1 addition, performed *before* the child is spawned so the child can
//! verify the same bytes: a real file and directory round-trip on the FAT32
//! (`/fat`) and ext2 (`/ext2`) roots. On the first boot each file is created
//! with exactly 14 bytes; on the second boot six more bytes are appended
//! (20 total). Directory tests are self-cleaning so a second boot can rerun
//! them. On success init prints `[CaelumInit] M5c files OK`.
//!
//! M5c2 addition, also before the child is spawned: eager `mmap` round trips on
//! both roots (`/fat/M5MAP.BIN`, `/ext2/m5cmap`) covering shared mappings with
//! write-back through `sync`, private mappings that never reach the file,
//! `mprotect` and `munmap`, the close-hook (closing a mapping handle unmaps) and
//! the rejecting negative paths. On success init prints
//! `[CaelumInit] M5c mmap OK`.
//!
//! M5c3 additions, still before the spawn: extended attributes on the M5c1 files
//! (quota, `user.*` namespace and handle-right checks), a sparse file with a
//! zero-filled hole, a watched FAT32 directory (create/rename/unlink events,
//! drained and validated, with the watch handle deliberately left open), and the
//! lock contract (OFD conflicts, `dup` sharing a description, `flock` as an
//! independent domain, POSIX locks being process-owned). init keeps a POSIX
//! exclusive lock held across the spawn so the child must observe a conflict, and
//! releases it after the child exits. Markers: `[CaelumInit] M5c xattr OK`,
//! `[CaelumInit] M5c sparse OK`, `[CaelumInit] M5c watch OK`,
//! `[CaelumInit] M5c locks OK` (the last one after `M4 wait OK`).

#![no_std]
#![no_main]

use native_abi::{
    ABI_VERSION, DirEntryOut, ERR_BAD_HANDLE, ERR_BAD_REQUEST, ERR_BAD_RIGHT, ERR_BUSY,
    ERR_CROSS_DEVICE, ERR_EXISTS, ERR_NOT_EMPTY, ERR_NOT_FOUND, ERR_NOT_SUPPORTED, ERR_QUOTA,
    ERR_READ_ONLY, ERR_TIMEOUT, ERR_TOO_LARGE, ERR_WOULD_BLOCK, EVENT_PAIR_ENDPOINT_A, Handle,
    IPC_KIND_CHANNEL, IPC_KIND_EVENT, IPC_KIND_EVENT_PAIR, IPC_KIND_PORT, IPC_KIND_TIMER,
    IpcMessageMeta, IpcReceiveRequest, IpcSendRequest, LOCK_DOMAIN_FLOCK, LOCK_DOMAIN_OFD,
    LOCK_DOMAIN_POSIX, LOCK_OP_EXCLUSIVE, LOCK_OP_UNLOCK, LockRequest, MMAP_PRIVATE, MMAP_SHARED,
    MmapRequest, NODE_FILE, NR_IPC_RECV, OPEN_CREATE, OPEN_DIRECTORY, OPEN_READ, OPEN_TRUNC,
    OPEN_WRITE, PROT_EXEC, PROT_READ, PROT_WRITE, ProcessCreateRequest, RIGHT_MAP, RIGHT_READ,
    RIGHT_WAIT, RIGHT_WRITE, SEEK_END, SEEK_SET, SIGNAL_OP_SIGNAL, SUBSCRIPTION_MODE_EDGE,
    SUBSCRIPTION_MODE_LEVEL, ShmMapRequest, StatOut, SubscriptionEntry, SubscriptionEvent,
    WAIT_TIMEOUT_IMMEDIATE, WAIT_TIMEOUT_INFINITE, WAKE_READY, WATCH_EVENT_CREATED,
    WATCH_EVENT_DELETED, WATCH_EVENT_RENAMED, WaitItem, WaitOut, WaitRequest, WatchEventOut,
    XATTR_VALUE_MAX, XattrRequest, handle,
};
use native_rt as rt;

/// Fixed output lines. They are the serial acceptance markers and must match
/// `xtask`'s observation list exactly.
const INIT_OK: &[u8] = b"[CaelumInit] M4 init OK\n";
const SPAWN_OK: &[u8] = b"[CaelumInit] M4 spawn OK\n";
const WAIT_OK: &[u8] = b"[CaelumInit] M4 wait OK\n";
const RNG_OK: &[u8] = b"[CaelumInit] M4 rng OK\n";
const M5C_FILES_OK: &[u8] = b"[CaelumInit] M5c files OK\n";
const M5C_MMAP_OK: &[u8] = b"[CaelumInit] M5c mmap OK\n";
const M5C_XATTR_OK: &[u8] = b"[CaelumInit] M5c xattr OK\n";
const M5C_SPARSE_OK: &[u8] = b"[CaelumInit] M5c sparse OK\n";
const M5C_WATCH_OK: &[u8] = b"[CaelumInit] M5c watch OK\n";
const M5C_LOCKS_OK: &[u8] = b"[CaelumInit] M5c locks OK\n";
const M6A_TIMER_OK: &[u8] = b"[CaelumInit] M6a timer OK\n";
const M6A_EVENT_OK: &[u8] = b"[CaelumInit] M6a event OK\n";

/// Module name resolved by `process_create` against the boot module set.
const CHILD_MODULE: &[u8] = b"child";

/// The exact first-boot payload (14 bytes) and the appended suffix (6 bytes).
const FILE_FIRST: &[u8] = b"CAELUM-M5C1-V1";
const FILE_APPEND: &[u8] = b"\nBOOT2";
/// First boot payload plus suffix (20 bytes).
const FILE_SECOND: &[u8] = b"CAELUM-M5C1-V1\nBOOT2";

/// Absolute paths used by the M5c1 user file/directory test.
const FAT_FILE: &[u8] = b"/fat/M5CUSER.BIN";
const EXT2_FILE: &[u8] = b"/ext2/m5cuser";
const FAT_DIR: &[u8] = b"/fat/M5CDIR";
const FAT_DIR_RENAMED: &[u8] = b"/fat/M5CDIR2";
const EXT2_DIR: &[u8] = b"/ext2/m5cdir";
const EXT2_DIR_RENAMED: &[u8] = b"/ext2/m5cdir2";
const FAT_INNER: &[u8] = b"/fat/M5CDIR/INNER.TXT";
const EXT2_INNER: &[u8] = b"/ext2/m5cdir/inner.txt";
const FAT_INNER_RENAMED: &[u8] = b"/fat/M5CDIR2/INNER.TXT";
const EXT2_INNER_RENAMED: &[u8] = b"/ext2/m5cdir2/inner.txt";
const FAT_TMP: &[u8] = b"/fat/M5CTMP.BIN";
/// A read-only startup module (the M4 boot module migration target) on the VFS
/// boot mount: opening it for writing must fail with `READ_ONLY`, not
/// `NOT_FOUND`.
const STARTUP_FILE: &[u8] = b"/boot/init";

/// Files used by the M5c2 user `mmap` round trip (one per persistent root).
const FAT_MAP: &[u8] = b"/fat/M5MAP.BIN";
const EXT2_MAP: &[u8] = b"/ext2/m5cmap";

/// Payload of the directory inner file.
const INNER_BYTES: &[u8] = b"inner";
/// Payload of the temporary dup/seek file.
const TMP_BYTES: &[u8] = b"ABCDEFGH";

/// Size in bytes of the M5c2 mapping and of its backing file (eight pages).
const MAP_LEN: usize = 8192;
/// One page, used by the close-hook and negative `mmap` cases.
const MAP_PAGE: usize = 4096;
/// Bytes init writes through the shared mapping at [`MAP_POS_A`]/[`MAP_POS_B`].
const MAP_A: u8 = 0xA5;
const MAP_B: u8 = 0x5A;
const MAP_POS_A: usize = 0;
const MAP_POS_B: usize = 4103;

/// Files used by the M5c3 extended-attribute, sparse-file and lock round trips.
const FAT_HOLE: &[u8] = b"/fat/M5HOLE.BIN";
const EXT2_HOLE: &[u8] = b"/ext2/m5chole";
const FAT_LOCK: &[u8] = b"/fat/M5LOCK.BIN";

/// The directory init watches while creating, renaming and removing entries.
const FAT_WATCH: &[u8] = b"/fat/M5WATCH";
const FAT_WATCH_A: &[u8] = b"/fat/M5WATCH/A.BIN";
const FAT_WATCH_B: &[u8] = b"/fat/M5WATCH/B.BIN";
const WATCH_NAME_A: &[u8] = b"A.BIN";
const WATCH_NAME_B: &[u8] = b"B.BIN";

/// Attribute names and values used by [`xattr_step`].
const XATTR_MARK: &[u8] = b"user.caelum";
const XATTR_MARK_VALUE: &[u8] = b"m5c3";
const XATTR_BOOT: &[u8] = b"user.boot";
const XATTR_BOOT_FIRST: &[u8] = b"one";
const XATTR_BOOT_SECOND: &[u8] = b"two";
const XATTR_EXTRA: &[u8] = b"user.extra";
const XATTR_FOREIGN: &[u8] = b"other.name";

/// Geometric constants for the sparse-file round trip: a four-byte payload far
/// past the start of the file, with a zero-filled gap in front of it.
const SPARSE_HOLE_START: u64 = 32768;
const SPARSE_MARK: &[u8] = b"HOLE";
const SPARSE_FILE_SIZE: u64 = SPARSE_HOLE_START + SPARSE_MARK.len() as u64;

/// Non-zero exit codes identify the failing step for the kernel/diagnostic
/// output; 0 is success.
const EXIT_WRITE: u64 = 0x01;
const EXIT_ABI: u64 = 0x10;
const EXIT_ABI_VERSION: u64 = 0x11;
const EXIT_SPAWN: u64 = 0x12;
const EXIT_WAIT: u64 = 0x13;
const EXIT_WAIT_STATUS: u64 = 0x14;
const EXIT_RNG: u64 = 0x15;

const EXIT_FILE_OPEN: u64 = 0x30;
const EXIT_FILE_CONTENT: u64 = 0x31;
const EXIT_FILE_WRITE: u64 = 0x32;
const EXIT_FILE_SIZE: u64 = 0x33;
const EXIT_FILE_PAIR: u64 = 0x34;
const EXIT_DIR_CREATE: u64 = 0x35;
const EXIT_DIR_READDIR: u64 = 0x36;
const EXIT_DIR_INNER: u64 = 0x37;
const EXIT_DIR_STAT: u64 = 0x38;
const EXIT_DIR_RENAME: u64 = 0x39;
const EXIT_DIR_NOT_EMPTY: u64 = 0x3a;
const EXIT_DIR_CLEANUP: u64 = 0x3b;
const EXIT_READONLY: u64 = 0x3c;
const EXIT_CROSS_DEVICE: u64 = 0x3d;
const EXIT_STALE_HANDLE: u64 = 0x3e;
const EXIT_DUP: u64 = 0x3f;
const EXIT_SEEK: u64 = 0x40;
const EXIT_TRUNC: u64 = 0x41;

const EXIT_MAP_OPEN: u64 = 0x50;
const EXIT_MAP_SIZE: u64 = 0x51;
const EXIT_MAP_WRITE: u64 = 0x52;
const EXIT_MAP_MMAP: u64 = 0x53;
const EXIT_MAP_PATTERN: u64 = 0x54;
const EXIT_MAP_SHARED_SEEN: u64 = 0x55;
const EXIT_MAP_PRIVATE: u64 = 0x56;
const EXIT_MAP_ISOLATION: u64 = 0x57;
const EXIT_MAP_MPROTECT: u64 = 0x58;
const EXIT_MAP_UNMAP: u64 = 0x59;
const EXIT_MAP_STALE: u64 = 0x5a;
const EXIT_MAP_RIGHTS: u64 = 0x5b;
const EXIT_MAP_BAD_REQUEST: u64 = 0x5c;

const EXIT_XATTR_OPEN: u64 = 0x60;
const EXIT_XATTR_SET: u64 = 0x61;
const EXIT_XATTR_GET: u64 = 0x62;
const EXIT_XATTR_QUOTA: u64 = 0x63;
const EXIT_XATTR_NAMESPACE: u64 = 0x64;
const EXIT_XATTR_TOO_LARGE: u64 = 0x65;
const EXIT_XATTR_RIGHTS: u64 = 0x66;

const EXIT_SPARSE_OPEN: u64 = 0x70;
const EXIT_SPARSE_SEEK: u64 = 0x71;
const EXIT_SPARSE_WRITE: u64 = 0x72;
const EXIT_SPARSE_SIZE: u64 = 0x73;
const EXIT_SPARSE_HOLE: u64 = 0x74;
const EXIT_SPARSE_SYNC: u64 = 0x75;

const EXIT_WATCH_MKDIR: u64 = 0x80;
const EXIT_WATCH_WATCH: u64 = 0x81;
const EXIT_WATCH_CREATE: u64 = 0x82;
const EXIT_WATCH_RENAME: u64 = 0x83;
const EXIT_WATCH_UNLINK: u64 = 0x84;
const EXIT_WATCH_DRAIN: u64 = 0x85;
const EXIT_WATCH_COUNT: u64 = 0x86;
const EXIT_WATCH_EVENTS: u64 = 0x87;
const EXIT_WATCH_BAD_HANDLE: u64 = 0x88;

const EXIT_LOCK_OPEN: u64 = 0x90;
const EXIT_LOCK_OFD: u64 = 0x91;
const EXIT_LOCK_DUP: u64 = 0x92;
const EXIT_LOCK_FLOCK: u64 = 0x93;
const EXIT_LOCK_POSIX: u64 = 0x94;
const EXIT_LOCK_RELEASE: u64 = 0x95;

/// M6a1: timer armed by `m6a_timer_step`, in scheduler ticks (100 Hz).
const M6A_TIMER_TICKS: u32 = 5;
/// M6a1: an unsignalled Event must time out after this many ticks.
const M6A_TIMEOUT_TICKS: u32 = 2;
const EXIT_M6A_CREATE: u64 = 0xa0;
const EXIT_M6A_EVENT: u64 = 0xa1;
const EXIT_M6A_TIMEOUT: u64 = 0xa2;
const EXIT_M6A_TIMER: u64 = 0xa3;
const EXIT_M6A_PAIR: u64 = 0xa4;

/// M6a2: markers for the IPC slices this program exercises.
const M6A_CHANNEL_OK: &[u8] = b"[CaelumInit] M6a channel OK\n";
const M6A_PORT_OK: &[u8] = b"[CaelumInit] M6a port OK\n";
const M6A_SHM_OK: &[u8] = b"[CaelumInit] M6a shm OK\n";
const M6A_FUTEX_OK: &[u8] = b"[CaelumInit] M6a futex OK\n";
const M6A_SUBSCRIPTION_OK: &[u8] = b"[CaelumInit] M6a subscription OK\n";

/// Routing ids and payloads of the M6a2 messages (opaque to the kernel).
const PROTO_CHANNEL: u32 = 0x4D36_4132;
const PROTO_PORT: u32 = 0x504F_5254;
const MSG_VERSION: u32 = 1;
const CHANNEL_FIRST: &[u8] = b"M6A2-CHANNEL-1";
const CHANNEL_SECOND: &[u8] = b"M6A2-CHANNEL-2";
/// Exactly [`native_abi::IPC_DATA_MAX`] bytes: the inline data boundary.
const CHANNEL_BOUNDARY: [u8; native_abi::IPC_DATA_MAX] =
    *b"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const CHANNEL_GO_SUB: &[u8] = b"M6A2-GO-SUB";
const CHANNEL_GO_SUB2: &[u8] = b"M6A2-GO-SUB2";
const PORT_HELLO: &[u8] = b"m6a2-port-hello";
const SHM_RESPONSE_MARK: &[u8] = b"M6A2-SHM-RESPONSE";
const SUB_FIRST: &[u8] = b"M6A2-SUB-1";
const SUB_SECOND: &[u8] = b"M6A2-SUB-2";
/// Transactions that order the channel handshake.
const TX_CHANNEL_FIRST: u64 = 1;
const TX_CHANNEL_SECOND: u64 = 2;
const TX_CHANNEL_GO_SUB: u64 = 3;
const TX_CHANNEL_GO_SUB2: u64 = 4;
const TX_PORT: u64 = 5;
/// The inline-data boundary message, kept after the two handle transfers.
const TX_CHANNEL_BOUNDARY: u64 = 6;
const TX_SHM_MAPPED: u64 = 10;
const TX_FUTEX_READY: u64 = 11;
const TX_FUTEX_OK: u64 = 12;
const TX_PORT_SENT: u64 = 13;
const TX_SUB_FIRST: u64 = 20;
const TX_SUB_SECOND: u64 = 21;
const TX_LAST: u64 = 30;

/// Two-page shared-memory object and the offsets the M6a2 test uses.
const SHM_LEN: usize = 8192;
const SHM_RESPONSE_OFFSET: usize = 4096;
const SHM_FUTEX_OFFSET: usize = 64;
/// After the child claims it is about to block on the futex, init waits this
/// many ticks so the child is actually asleep before the wake arrives.
const SHM_WAKE_TICKS: u32 = 20;

const EXIT_M6A2_CREATE: u64 = 0xb0;
const EXIT_M6A2_SEND: u64 = 0xb1;
const EXIT_M6A2_RECV: u64 = 0xb2;
const EXIT_M6A2_PAYLOAD: u64 = 0xb3;
const EXIT_M6A2_HANDLES: u64 = 0xb4;
const EXIT_M6A2_QUEUE: u64 = 0xb5;
const EXIT_M6A2_SHM: u64 = 0xb6;
const EXIT_M6A2_FUTEX: u64 = 0xb7;
const EXIT_M6A2_PORT: u64 = 0xb8;
const EXIT_M6A2_SUB: u64 = 0xb9;
const EXIT_M6A2_HANDLE_BACK: u64 = 0xba;
const EXIT_M6A2_CLOSE: u64 = 0xbb;

/// Handles and addresses that make up the M6a2 channel/port/shm test rig.
struct M6a2State {
    channel_a: Handle,
    channel_b: Handle,
    port_receiver: Handle,
    port_sender: Handle,
    shm: Handle,
    shm_map_a: Handle,
    shm_map_b: Handle,
    shm_alias_a: usize,
    shm_alias_b: usize,
    sub_channel_a: Handle,
    sub_channel_b: Handle,
    sub_level: Handle,
    sub_edge: Handle,
}

/// Writes one output line through the Console handle.
fn write_line(console: Handle, line: &[u8]) {
    if rt::write_all(console, line).is_err() {
        // The console capability is broken; there is nothing left to report on.
        rt::process_exit(EXIT_WRITE);
    }
}

/// Reports a failed M5c1 step and terminates with `code`.
fn fail(console: Handle, what: &[u8], code: u64) -> ! {
    let _ = rt::write_all(console, b"init FAIL ");
    let _ = rt::write_all(console, what);
    let _ = rt::write_all(console, b"\n");
    rt::process_exit(code)
}

/// Reads the whole file behind `handle` into `buffer` and closes it.
fn read_and_close(handle: Handle, buffer: &mut [u8]) -> Result<usize, u64> {
    let filled = rt::read_all(handle, buffer)?;
    rt::handle_close(handle)?;
    Ok(filled)
}

/// The byte the M5c2 backing file starts with at `index`.
const fn map_pattern(index: usize) -> u8 {
    ((index * 7 + 3) % 251) as u8
}

/// `true` when `value` is acceptable at `index`: either the untouched pattern
/// byte or the byte init wrote there on an earlier boot (A5 / 5A).
fn map_byte_ok(index: usize, value: u8) -> bool {
    value == map_pattern(index)
        || (index == MAP_POS_A && value == MAP_A)
        || (index == MAP_POS_B && value == MAP_B)
}

/// Reads one byte out of a live mapping.
fn map_read(base: usize, index: usize) -> u8 {
    debug_assert!(index < MAP_LEN);
    // SAFETY: `base` is the start of a live `MAP_LEN`-byte mapping of this
    // process and every caller keeps `index < MAP_LEN`.
    unsafe { *((base + index) as *const u8) }
}

/// Writes one byte into a live mapping that was requested writable.
fn map_write(base: usize, index: usize, value: u8) {
    debug_assert!(index < MAP_LEN);
    // SAFETY: same contract as `map_read`; the caller requested `PROT_WRITE`.
    unsafe { *((base + index) as *mut u8) = value }
}

/// Reads the byte at `offset` of the file behind `file` and checks it.
fn file_byte(file: Handle, offset: u64, expected: u8) -> Result<(), u64> {
    let mut byte = [0u8; 1];
    rt::seek(file, offset as i64, SEEK_SET).map_err(|_| EXIT_MAP_SHARED_SEEN)?;
    if rt::read(file, &mut byte).map_err(|_| EXIT_MAP_SHARED_SEEN)? != 1 || byte[0] != expected {
        return Err(EXIT_MAP_SHARED_SEEN);
    }
    Ok(())
}

/// Asserts that `mmap` rejects `request` with `ERR_BAD_REQUEST`.
fn expect_bad_request(file: Handle, request: &mut MmapRequest) -> Result<(), u64> {
    match rt::mmap(file, request) {
        Err(ERR_BAD_REQUEST) => Ok(()),
        Ok((mapping, _base)) => {
            let _ = rt::handle_close(mapping);
            Err(EXIT_MAP_BAD_REQUEST)
        }
        Err(_) => Err(EXIT_MAP_BAD_REQUEST),
    }
}

/// Asserts that `mmap` rejects `request` with `ERR_NOT_SUPPORTED`.
///
/// Executable mappings are refused by the ABI (see the M5c2 `mmap` contract:
/// `PROT_EXEC`, including W^X combinations, must answer `ERR_NOT_SUPPORTED`,
/// not `ERR_BAD_REQUEST`).
fn expect_not_supported(file: Handle, request: &mut MmapRequest) -> Result<(), u64> {
    match rt::mmap(file, request) {
        Err(ERR_NOT_SUPPORTED) => Ok(()),
        Ok((mapping, _base)) => {
            let _ = rt::handle_close(mapping);
            Err(EXIT_MAP_BAD_REQUEST)
        }
        Err(_) => Err(EXIT_MAP_BAD_REQUEST),
    }
}

/// First-boot creates the file with [`FILE_FIRST`]; a later boot appends
/// [`FILE_APPEND`] once. Returns `true` when the file was already at its
/// 14-byte first-boot state and this call appended the suffix.
fn file_step(console: Handle, path: &[u8]) -> Result<bool, u64> {
    match rt::open(path, OPEN_READ) {
        Ok(handle) => {
            let mut buffer = [0u8; 32];
            let filled = read_and_close(handle, &mut buffer).map_err(|_| EXIT_FILE_OPEN)?;

            if filled == FILE_FIRST.len() && buffer[..filled] == FILE_FIRST[..] {
                // Second boot: append exactly six bytes at the current end.
                let handle = rt::open(path, OPEN_WRITE).map_err(|_| EXIT_FILE_OPEN)?;
                if rt::seek(handle, 0, SEEK_END).map_err(|_| EXIT_SEEK)? != FILE_FIRST.len() as u64
                {
                    fail(console, b"file seek", EXIT_SEEK);
                }
                if rt::write_all(handle, FILE_APPEND).is_err() {
                    fail(console, b"file append", EXIT_FILE_WRITE);
                }
                if rt::sync(handle).is_err() {
                    fail(console, b"file sync", EXIT_FILE_WRITE);
                }
                let mut stat = StatOut::empty();
                let stat_result = rt::stat(handle, &mut stat);
                let _ = rt::handle_close(handle);
                stat_result.map_err(|_| EXIT_FILE_SIZE)?;
                if stat.file_size != FILE_SECOND.len() as u64 {
                    fail(console, b"file size after append", EXIT_FILE_SIZE);
                }

                // Verify the exact 20 bytes from a fresh open.
                let handle = rt::open(path, OPEN_READ).map_err(|_| EXIT_FILE_OPEN)?;
                let mut verify = [0u8; 32];
                let filled = read_and_close(handle, &mut verify).map_err(|_| EXIT_FILE_OPEN)?;
                if filled != FILE_SECOND.len() || verify[..filled] != FILE_SECOND[..] {
                    fail(console, b"file content after append", EXIT_FILE_CONTENT);
                }
                return Ok(true);
            }

            if filled == FILE_SECOND.len() && buffer[..filled] == FILE_SECOND[..] {
                // A third boot: already in the final state, nothing to append.
                return Ok(true);
            }

            fail(console, b"file content", EXIT_FILE_CONTENT);
        }
        Err(ERR_NOT_FOUND) => {
            let handle = rt::open(path, OPEN_WRITE | OPEN_CREATE).map_err(|_| EXIT_FILE_OPEN)?;
            if rt::write_all(handle, FILE_FIRST).is_err() {
                fail(console, b"file create write", EXIT_FILE_WRITE);
            }
            if rt::sync(handle).is_err() {
                fail(console, b"file create sync", EXIT_FILE_WRITE);
            }
            let mut stat = StatOut::empty();
            let stat_result = rt::stat(handle, &mut stat);
            let _ = rt::handle_close(handle);
            stat_result.map_err(|_| EXIT_FILE_SIZE)?;
            if stat.file_size != FILE_FIRST.len() as u64 {
                fail(console, b"file size after create", EXIT_FILE_SIZE);
            }

            let handle = rt::open(path, OPEN_READ).map_err(|_| EXIT_FILE_OPEN)?;
            let mut verify = [0u8; 32];
            let filled = read_and_close(handle, &mut verify).map_err(|_| EXIT_FILE_OPEN)?;
            if filled != FILE_FIRST.len() || verify[..filled] != FILE_FIRST[..] {
                fail(console, b"file content after create", EXIT_FILE_CONTENT);
            }
            Ok(false)
        }
        Err(_) => Err(EXIT_FILE_OPEN),
    }
}

/// Case-insensitive ASCII comparison, because FAT32 exposes 8.3 names in
/// upper case while ext2 preserves the created case.
fn eq_name(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    let mut i = 0;
    while i < left.len() {
        if left[i].to_ascii_lowercase() != right[i].to_ascii_lowercase() {
            return false;
        }
        i += 1;
    }
    true
}

/// The file name component of `path`.
fn base_name(path: &[u8]) -> &[u8] {
    let mut start = 0;
    let mut i = 0;
    while i < path.len() {
        if path[i] == b'/' {
            start = i + 1;
        }
        i += 1;
    }
    &path[start..]
}

/// One self-cleaning directory round-trip: mkdir, enumerate, create an inner
/// file, stat it, rename the directory, fail a non-empty rmdir, then remove
/// everything again.
fn dir_step(
    console: Handle,
    dir: &[u8],
    renamed: &[u8],
    inner: &[u8],
    inner_renamed: &[u8],
) -> Result<(), u64> {
    // Best-effort cleanup of a previously interrupted run.
    let _ = rt::unlink(inner);
    let _ = rt::unlink(inner_renamed);
    let _ = rt::rmdir(dir);
    let _ = rt::rmdir(renamed);

    rt::mkdir(dir).map_err(|_| EXIT_DIR_CREATE)?;

    let dir_handle = rt::open(dir, OPEN_READ | OPEN_DIRECTORY).map_err(|_| EXIT_DIR_CREATE)?;
    let mut entry = DirEntryOut::empty();
    if rt::readdir(dir_handle, 0, &mut entry).is_ok() {
        let _ = rt::handle_close(dir_handle);
        fail(console, b"dir not empty after mkdir", EXIT_DIR_READDIR);
    }

    let file_handle = rt::open(inner, OPEN_WRITE | OPEN_CREATE).map_err(|_| EXIT_DIR_INNER)?;
    if rt::write_all(file_handle, INNER_BYTES).is_err() {
        fail(console, b"dir inner write", EXIT_DIR_INNER);
    }
    if rt::sync(file_handle).is_err() {
        fail(console, b"dir inner sync", EXIT_DIR_INNER);
    }
    let mut stat = StatOut::empty();
    let stat_result = rt::stat(file_handle, &mut stat);
    let _ = rt::handle_close(file_handle);
    stat_result.map_err(|_| EXIT_DIR_STAT)?;
    if !stat.is_file() || stat.file_size != INNER_BYTES.len() as u64 {
        fail(console, b"dir inner stat", EXIT_DIR_STAT);
    }

    let mut entry = DirEntryOut::empty();
    rt::readdir(dir_handle, 0, &mut entry).map_err(|_| EXIT_DIR_READDIR)?;
    if entry.kind != NODE_FILE || entry.file_size != INNER_BYTES.len() as u64 {
        fail(console, b"dir readdir entry", EXIT_DIR_READDIR);
    }
    if !eq_name(entry.name(), base_name(inner)) {
        fail(console, b"dir readdir name", EXIT_DIR_READDIR);
    }
    let mut second = DirEntryOut::empty();
    if rt::readdir(dir_handle, 1, &mut second).is_ok() {
        fail(console, b"dir readdir count", EXIT_DIR_READDIR);
    }
    let _ = rt::handle_close(dir_handle);

    rt::rename(dir, renamed).map_err(|_| EXIT_DIR_RENAME)?;

    // The old name is gone, the new name resolves, and the inner file moved
    // with its parent directory.
    match rt::open(dir, OPEN_READ) {
        Err(ERR_NOT_FOUND) => {}
        Ok(handle) => {
            let _ = rt::handle_close(handle);
            fail(console, b"dir rename left old name", EXIT_DIR_RENAME);
        }
        Err(_) => fail(console, b"dir rename lookup", EXIT_DIR_RENAME),
    }
    let handle = rt::open(inner_renamed, OPEN_READ).map_err(|_| EXIT_DIR_RENAME)?;
    let mut verify = [0u8; 16];
    let filled = read_and_close(handle, &mut verify).map_err(|_| EXIT_DIR_RENAME)?;
    if filled != INNER_BYTES.len() || verify[..filled] != INNER_BYTES[..] {
        fail(console, b"dir inner after rename", EXIT_DIR_RENAME);
    }

    // A non-empty directory cannot be removed.
    match rt::rmdir(renamed) {
        Err(ERR_NOT_EMPTY) | Err(ERR_BUSY) => {}
        _ => fail(console, b"dir non-empty rmdir", EXIT_DIR_NOT_EMPTY),
    }

    rt::unlink(inner_renamed).map_err(|_| EXIT_DIR_CLEANUP)?;
    rt::rmdir(renamed).map_err(|_| EXIT_DIR_CLEANUP)?;
    match rt::open(renamed, OPEN_READ) {
        Err(ERR_NOT_FOUND) => Ok(()),
        Ok(handle) => {
            let _ = rt::handle_close(handle);
            fail(console, b"dir cleanup left name", EXIT_DIR_CLEANUP);
        }
        Err(_) => fail(console, b"dir cleanup lookup", EXIT_DIR_CLEANUP),
    }
}

/// Failures that are about API semantics rather than on-disk state.
fn misc_steps(console: Handle) -> Result<(), u64> {
    // 1. The read-only startup module rejects a write open with READ_ONLY.
    match rt::open(STARTUP_FILE, OPEN_WRITE) {
        Err(ERR_READ_ONLY) => {}
        Ok(handle) => {
            let _ = rt::handle_close(handle);
            fail(console, b"read-only open succeeded", EXIT_READONLY);
        }
        Err(_) => fail(console, b"read-only open error", EXIT_READONLY),
    }

    // 2. Renaming across mounts is refused, and the source stays put.
    match rt::rename(FAT_FILE, EXT2_FILE) {
        Err(ERR_CROSS_DEVICE) => {}
        _ => fail(console, b"cross-mount rename", EXIT_CROSS_DEVICE),
    }

    // 3. A closed handle is stale, not silently reused.
    let handle = rt::open(FAT_FILE, OPEN_READ).map_err(|_| EXIT_STALE_HANDLE)?;
    rt::handle_close(handle).map_err(|_| EXIT_STALE_HANDLE)?;
    let mut probe = [0u8; 4];
    if rt::read(handle, &mut probe) != Err(ERR_BAD_HANDLE) {
        fail(console, b"stale handle read", EXIT_STALE_HANDLE);
    }
    if rt::stat(handle, &mut StatOut::empty()) != Err(ERR_BAD_HANDLE) {
        fail(console, b"stale handle stat", EXIT_STALE_HANDLE);
    }

    // 4. dup shares the file offset, seek reports END, TRUNC empties a file.
    // This handle is written, then read back and duplicated with RIGHT_READ, so
    // it must request OPEN_READ explicitly: WRITE never implies READ.
    let _ = rt::unlink(FAT_TMP);
    let handle = rt::open(FAT_TMP, OPEN_READ | OPEN_WRITE | OPEN_CREATE | OPEN_TRUNC)
        .map_err(|_| EXIT_DUP)?;
    if rt::write_all(handle, TMP_BYTES).is_err() {
        fail(console, b"tmp write", EXIT_DUP);
    }
    if rt::seek(handle, 0, SEEK_END).map_err(|_| EXIT_SEEK)? != TMP_BYTES.len() as u64 {
        fail(console, b"seek end", EXIT_SEEK);
    }
    if rt::seek(handle, 0, SEEK_SET).map_err(|_| EXIT_SEEK)? != 0 {
        fail(console, b"seek set", EXIT_SEEK);
    }
    let duplicate = rt::dup(handle, RIGHT_READ | RIGHT_WRITE).map_err(|_| EXIT_DUP)?;

    let mut first = [0u8; 3];
    if rt::read_all(handle, &mut first).map_err(|_| EXIT_DUP)? != 3 || &first != b"ABC" {
        fail(console, b"dup first read", EXIT_DUP);
    }
    let mut second = [0u8; 3];
    if rt::read_all(duplicate, &mut second).map_err(|_| EXIT_DUP)? != 3 || &second != b"DEF" {
        fail(console, b"dup shared offset", EXIT_DUP);
    }
    if rt::seek(duplicate, 0, SEEK_SET).map_err(|_| EXIT_SEEK)? != 0 {
        fail(console, b"dup seek", EXIT_SEEK);
    }
    let mut again = [0u8; 3];
    if rt::read_all(handle, &mut again).map_err(|_| EXIT_DUP)? != 3 || &again != b"ABC" {
        fail(console, b"dup shared seek", EXIT_DUP);
    }

    rt::truncate(handle, 4).map_err(|_| EXIT_TRUNC)?;
    let mut stat = StatOut::empty();
    rt::stat(duplicate, &mut stat).map_err(|_| EXIT_TRUNC)?;
    if stat.file_size != 4 {
        fail(console, b"truncate size", EXIT_TRUNC);
    }
    rt::handle_close(duplicate).map_err(|_| EXIT_DUP)?;
    rt::handle_close(handle).map_err(|_| EXIT_DUP)?;

    // 5. OPEN_TRUNC empties the existing file on open.
    let handle = rt::open(FAT_TMP, OPEN_WRITE | OPEN_TRUNC).map_err(|_| EXIT_TRUNC)?;
    let mut stat = StatOut::empty();
    let stat_result = rt::stat(handle, &mut stat);
    let _ = rt::handle_close(handle);
    stat_result.map_err(|_| EXIT_TRUNC)?;
    if stat.file_size != 0 {
        fail(console, b"open trunc size", EXIT_TRUNC);
    }
    rt::unlink(FAT_TMP).map_err(|_| EXIT_TRUNC)?;
    Ok(())
}

/// M5c2: shared/private `mmap`, `mprotect`, `munmap` and the rejecting paths on
/// one file. Opens and closes the backing file; the body keeps every buffer
/// bounded because no allocator is available.
fn mmap_step(path: &[u8]) -> Result<(), u64> {
    let file = rt::open(path, OPEN_READ | OPEN_WRITE | OPEN_CREATE).map_err(|_| EXIT_MAP_OPEN)?;
    let result = mmap_step_body(file);
    let closed = rt::handle_close(file);
    match (result, closed) {
        (Err(code), _) => Err(code),
        (Ok(()), Ok(())) => Ok(()),
        (Ok(()), Err(_)) => Err(EXIT_MAP_UNMAP),
    }
}

fn mmap_step_body(file: Handle) -> Result<(), u64> {
    // 1. `MAP_LEN` bytes of pattern on the first boot; later boots accept the
    //    file as-is (it already holds the A5/5A final state).
    let mut stat = StatOut::empty();
    rt::stat(file, &mut stat).map_err(|_| EXIT_MAP_SIZE)?;
    if stat.file_size == 0 {
        let mut chunk = [0u8; 512];
        let mut offset = 0usize;
        while offset < MAP_LEN {
            let count = chunk.len().min(MAP_LEN - offset);
            for (index, byte) in chunk[..count].iter_mut().enumerate() {
                *byte = map_pattern(offset + index);
            }
            rt::write_all(file, &chunk[..count]).map_err(|_| EXIT_MAP_WRITE)?;
            offset += count;
        }
        rt::sync(file).map_err(|_| EXIT_MAP_WRITE)?;
    } else if stat.file_size != MAP_LEN as u64 {
        return Err(EXIT_MAP_SIZE);
    }

    // 2. Shared mapping of the whole file: the pattern is visible and writes
    //    become file contents at the next `sync`.
    let mut request = MmapRequest::new(MAP_LEN as u64, 0, PROT_READ | PROT_WRITE, MMAP_SHARED, 0);
    let (_shared_mapping, shared) = rt::mmap(file, &mut request).map_err(|_| EXIT_MAP_MMAP)?;
    let mut index = 0usize;
    while index < MAP_LEN {
        if !map_byte_ok(index, map_read(shared, index)) {
            return Err(EXIT_MAP_PATTERN);
        }
        index += 1;
    }
    map_write(shared, MAP_POS_A, MAP_A);
    map_write(shared, MAP_POS_B, MAP_B);
    rt::sync(file).map_err(|_| EXIT_MAP_SHARED_SEEN)?;
    file_byte(file, MAP_POS_A as u64, MAP_A)?;
    file_byte(file, MAP_POS_B as u64, MAP_B)?;

    // 3. Private mapping created after the shared writes: it sees them, but its
    //    own writes stay in memory and never reach the file.
    let mut request = MmapRequest::new(MAP_LEN as u64, 0, PROT_READ | PROT_WRITE, MMAP_PRIVATE, 0);
    let (_private_mapping, private) = rt::mmap(file, &mut request).map_err(|_| EXIT_MAP_MMAP)?;
    index = 0;
    while index < MAP_LEN {
        if !map_byte_ok(index, map_read(private, index)) {
            return Err(EXIT_MAP_PRIVATE);
        }
        index += 1;
    }
    map_write(private, MAP_POS_A, 0xFF);
    if map_read(shared, MAP_POS_A) != MAP_A {
        return Err(EXIT_MAP_ISOLATION);
    }
    rt::sync(file).map_err(|_| EXIT_MAP_ISOLATION)?;
    file_byte(file, MAP_POS_A as u64, MAP_A)?;

    // 4. `mprotect` down to read-only and back; the private page content must
    //    survive the round trip.
    rt::mprotect(private, MAP_LEN, PROT_READ).map_err(|_| EXIT_MAP_MPROTECT)?;
    rt::mprotect(private, MAP_LEN, PROT_READ | PROT_WRITE).map_err(|_| EXIT_MAP_MPROTECT)?;
    if map_read(private, MAP_POS_A) != 0xFF || map_read(private, MAP_POS_B) != MAP_B {
        return Err(EXIT_MAP_MPROTECT);
    }

    // 5. `munmap` removes both mappings and closes their handles.
    rt::munmap(private, MAP_LEN).map_err(|_| EXIT_MAP_UNMAP)?;
    rt::munmap(shared, MAP_LEN).map_err(|_| EXIT_MAP_UNMAP)?;

    // 6. Close-hook: closing a mapping handle unmaps, so a later `munmap` of the
    //    same range finds nothing.
    let mut request = MmapRequest::new(MAP_PAGE as u64, 0, PROT_READ, MMAP_SHARED, 0);
    let (page_mapping, page_base) = rt::mmap(file, &mut request).map_err(|_| EXIT_MAP_MMAP)?;
    rt::handle_close(page_mapping).map_err(|_| EXIT_MAP_STALE)?;
    match rt::munmap(page_base, MAP_PAGE) {
        Err(ERR_NOT_FOUND) | Err(ERR_BAD_REQUEST) => {}
        _ => return Err(EXIT_MAP_STALE),
    }

    // 7. A read-only file cannot give a writable shared mapping.
    let readonly = rt::open(STARTUP_FILE, OPEN_READ).map_err(|_| EXIT_MAP_RIGHTS)?;
    let mut request = MmapRequest::new(MAP_PAGE as u64, 0, PROT_READ | PROT_WRITE, MMAP_SHARED, 0);
    let rights = rt::mmap(readonly, &mut request);
    let _ = rt::handle_close(readonly);
    match rights {
        Err(ERR_BAD_RIGHT) => {}
        Ok((mapping, _base)) => {
            let _ = rt::handle_close(mapping);
            return Err(EXIT_MAP_RIGHTS);
        }
        Err(_) => return Err(EXIT_MAP_RIGHTS),
    }

    // 8. Zero length and an unaligned offset are bad requests; an executable
    //    (W^X) request is a valid shape the kernel must refuse as unsupported.
    let mut request = MmapRequest::new(0, 0, PROT_READ, MMAP_SHARED, 0);
    expect_bad_request(file, &mut request)?;
    let mut request = MmapRequest::new(MAP_PAGE as u64, 0x100, PROT_READ, MMAP_SHARED, 0);
    expect_bad_request(file, &mut request)?;
    let mut request = MmapRequest::new(MAP_PAGE as u64, 0, PROT_WRITE | PROT_EXEC, MMAP_SHARED, 0);
    expect_not_supported(file, &mut request)?;

    Ok(())
}

/// Builds an `xattr_set`/`xattr_get` request naming `name` and `value`.
fn xattr_request(name: &[u8], value: &[u8]) -> XattrRequest {
    XattrRequest::new(
        name.as_ptr() as u64,
        name.len() as u64,
        value.as_ptr() as u64,
        value.len() as u64,
    )
}

/// Stores one extended attribute on `handle`.
fn set_xattr(handle: Handle, name: &[u8], value: &[u8]) -> Result<(), u64> {
    let mut request = xattr_request(name, value);
    rt::xattr_set(handle, &mut request)
}

/// Reads one extended attribute into `buffer` and returns its real length.
fn get_xattr(handle: Handle, name: &[u8], buffer: &mut [u8]) -> Result<usize, u64> {
    let mut request = xattr_request(name, buffer);
    rt::xattr_get(handle, &mut request)
}

/// M5c3: extended attributes on one persistent-root file.
///
/// Proves that attributes round trip, that the per-file quota and the `user.*`
/// namespace are enforced, that a short output buffer is refused without a
/// partial write, and that `READ`/`WRITE` handle capabilities also gate
/// attribute access. Attributes are explicitly volatile: nothing here expects
/// them to survive a reboot.
fn xattr_step(path: &[u8], appended: bool) -> Result<(), u64> {
    let file = rt::open(path, OPEN_READ | OPEN_WRITE).map_err(|_| EXIT_XATTR_OPEN)?;

    // 1. Store the marker attribute and read it back byte for byte.
    set_xattr(file, XATTR_MARK, XATTR_MARK_VALUE).map_err(|_| EXIT_XATTR_SET)?;
    let mut value = [0u8; XATTR_VALUE_MAX as usize];
    let len = get_xattr(file, XATTR_MARK, &mut value).map_err(|_| EXIT_XATTR_GET)?;
    if len != XATTR_MARK_VALUE.len() || value[..len] != XATTR_MARK_VALUE[..] {
        return Err(EXIT_XATTR_GET);
    }

    // 2. The boot-generation attribute must follow the same 14->20 byte file
    //    protocol as the file itself.
    let generation = if appended {
        XATTR_BOOT_SECOND
    } else {
        XATTR_BOOT_FIRST
    };
    set_xattr(file, XATTR_BOOT, generation).map_err(|_| EXIT_XATTR_SET)?;
    let mut value = [0u8; XATTR_VALUE_MAX as usize];
    let len = get_xattr(file, XATTR_BOOT, &mut value).map_err(|_| EXIT_XATTR_GET)?;
    if len != generation.len() || value[..len] != generation[..] {
        return Err(EXIT_XATTR_GET);
    }

    // 3. A third attribute exceeds the per-file quota.
    if !matches!(set_xattr(file, XATTR_EXTRA, b"x"), Err(ERR_QUOTA)) {
        return Err(EXIT_XATTR_QUOTA);
    }

    // 4. Only the `user.*` namespace is exposed to user mode.
    if !matches!(set_xattr(file, XATTR_FOREIGN, b"x"), Err(ERR_NOT_SUPPORTED)) {
        return Err(EXIT_XATTR_NAMESPACE);
    }

    // 5. A short output buffer reports `TOO_LARGE` and stays untouched. The
    //    buffer is one byte shorter than the stored value (`m5c3`); a buffer of
    //    exactly the value length is a successful read, not a short one.
    const SHORT: usize = XATTR_MARK_VALUE.len() - 1;
    let mut small = [0xEEu8; SHORT];
    if !matches!(get_xattr(file, XATTR_MARK, &mut small), Err(ERR_TOO_LARGE)) {
        return Err(EXIT_XATTR_TOO_LARGE);
    }
    if small != [0xEEu8; SHORT] {
        return Err(EXIT_XATTR_TOO_LARGE);
    }

    // 6. A write-only handle may not read attributes...
    let write_only = rt::open(path, OPEN_WRITE).map_err(|_| EXIT_XATTR_RIGHTS)?;
    let mut value = [0u8; XATTR_VALUE_MAX as usize];
    let refused = matches!(
        get_xattr(write_only, XATTR_MARK, &mut value),
        Err(ERR_BAD_RIGHT)
    );
    let _ = rt::handle_close(write_only);
    if !refused {
        return Err(EXIT_XATTR_RIGHTS);
    }

    // ...and a read-only handle may not change them, though it may read them.
    let read_only = rt::open(path, OPEN_READ).map_err(|_| EXIT_XATTR_RIGHTS)?;
    let refused = matches!(set_xattr(read_only, XATTR_MARK, b"x"), Err(ERR_BAD_RIGHT));
    if !refused {
        let _ = rt::handle_close(read_only);
        return Err(EXIT_XATTR_RIGHTS);
    }
    let mut value = [0u8; XATTR_VALUE_MAX as usize];
    let len = get_xattr(read_only, XATTR_MARK, &mut value).map_err(|_| EXIT_XATTR_RIGHTS)?;
    let _ = rt::handle_close(read_only);
    if len != XATTR_MARK_VALUE.len() || value[..len] != XATTR_MARK_VALUE[..] {
        return Err(EXIT_XATTR_RIGHTS);
    }

    rt::handle_close(file).map_err(|_| EXIT_XATTR_OPEN)
}

/// M5c3: a sparse write on one persistent root.
///
/// Seeks far past the start, writes four bytes and proves that the file has the
/// expected size, that the untouched gap reads back as zeroes, that the payload
/// survives a `sync`, and that a fresh handle sees the same image.
fn sparse_step(path: &[u8]) -> Result<(), u64> {
    let file = rt::open(path, OPEN_CREATE | OPEN_TRUNC | OPEN_READ | OPEN_WRITE)
        .map_err(|_| EXIT_SPARSE_OPEN)?;

    // 1. Write four bytes far past the start of the file.
    let position =
        rt::seek(file, SPARSE_HOLE_START as i64, SEEK_SET).map_err(|_| EXIT_SPARSE_SEEK)?;
    if position != SPARSE_HOLE_START {
        return Err(EXIT_SPARSE_SEEK);
    }
    rt::write_all(file, SPARSE_MARK).map_err(|_| EXIT_SPARSE_WRITE)?;

    // 2. The size covers the gap plus the payload.
    let mut stat = StatOut::empty();
    rt::stat(file, &mut stat).map_err(|_| EXIT_SPARSE_SIZE)?;
    if stat.file_size != SPARSE_FILE_SIZE {
        return Err(EXIT_SPARSE_SIZE);
    }

    // 3. The gap reads back as zeroes and the payload as itself.
    for offset in [0u64, 4096, SPARSE_HOLE_START - 1] {
        if rt::seek(file, offset as i64, SEEK_SET).map_err(|_| EXIT_SPARSE_SEEK)? != offset {
            return Err(EXIT_SPARSE_SEEK);
        }
        let mut byte = [0xFFu8; 1];
        if rt::read(file, &mut byte).map_err(|_| EXIT_SPARSE_HOLE)? != 1 || byte[0] != 0 {
            return Err(EXIT_SPARSE_HOLE);
        }
    }
    if rt::seek(file, SPARSE_HOLE_START as i64, SEEK_SET).map_err(|_| EXIT_SPARSE_SEEK)?
        != SPARSE_HOLE_START
    {
        return Err(EXIT_SPARSE_SEEK);
    }
    let mut mark = [0u8; 4];
    if rt::read(file, &mut mark).map_err(|_| EXIT_SPARSE_HOLE)? != SPARSE_MARK.len() as u64
        || mark[..] != SPARSE_MARK[..]
    {
        return Err(EXIT_SPARSE_HOLE);
    }

    // 4. `sync` must make the same bytes readable through a fresh handle and
    //    keep the gap zeroed.
    rt::sync(file).map_err(|_| EXIT_SPARSE_SYNC)?;
    rt::handle_close(file).map_err(|_| EXIT_SPARSE_OPEN)?;

    let file = rt::open(path, OPEN_READ).map_err(|_| EXIT_SPARSE_OPEN)?;
    let mut byte = [0xFFu8; 1];
    if rt::read(file, &mut byte).map_err(|_| EXIT_SPARSE_HOLE)? != 1 || byte[0] != 0 {
        return Err(EXIT_SPARSE_HOLE);
    }
    if rt::seek(file, SPARSE_HOLE_START as i64, SEEK_SET).map_err(|_| EXIT_SPARSE_SEEK)?
        != SPARSE_HOLE_START
    {
        return Err(EXIT_SPARSE_SEEK);
    }
    let mut mark = [0u8; 4];
    if rt::read(file, &mut mark).map_err(|_| EXIT_SPARSE_HOLE)? != SPARSE_MARK.len() as u64
        || mark[..] != SPARSE_MARK[..]
    {
        return Err(EXIT_SPARSE_HOLE);
    }
    let mut stat = StatOut::empty();
    rt::stat(file, &mut stat).map_err(|_| EXIT_SPARSE_SIZE)?;
    let size_ok = stat.file_size == SPARSE_FILE_SIZE;
    let _ = rt::handle_close(file);
    if !size_ok {
        return Err(EXIT_SPARSE_SIZE);
    }

    Ok(())
}

/// M5c3: watches one FAT32 directory while creating, renaming and removing an
/// entry, then drains and validates the queued events.
///
/// The watch handle is intentionally left open: the process exits with it held
/// so the kernel's reaping path has to drop the watch and the root check can
/// observe `watch_count == 0`.
fn watch_step() -> Result<(), u64> {
    match rt::mkdir(FAT_WATCH) {
        Ok(()) => {}
        Err(ERR_EXISTS) => {
            // A previous boot left the directory behind: clear the two test
            // entries so the event sequence starts from a known state.
            let _ = rt::unlink(FAT_WATCH_A);
            let _ = rt::unlink(FAT_WATCH_B);
        }
        Err(_) => return Err(EXIT_WATCH_MKDIR),
    }

    let watch = rt::watch(FAT_WATCH).map_err(|_| EXIT_WATCH_WATCH)?;

    // Create, rename to a second name, then remove the entry.
    let created = rt::open(FAT_WATCH_A, OPEN_CREATE | OPEN_WRITE).map_err(|_| EXIT_WATCH_CREATE)?;
    rt::handle_close(created).map_err(|_| EXIT_WATCH_CREATE)?;
    rt::rename(FAT_WATCH_A, FAT_WATCH_B).map_err(|_| EXIT_WATCH_RENAME)?;
    rt::unlink(FAT_WATCH_B).map_err(|_| EXIT_WATCH_UNLINK)?;

    // Drain and check kind/name/order of the three events.
    let mut events = [WatchEventOut::empty(); 4];
    let count = rt::watch_drain(watch, &mut events).map_err(|_| EXIT_WATCH_DRAIN)?;
    if count != 3 {
        return Err(EXIT_WATCH_COUNT);
    }
    let expected: [(u32, &[u8]); 3] = [
        (WATCH_EVENT_CREATED, WATCH_NAME_A),
        (WATCH_EVENT_RENAMED, WATCH_NAME_B),
        (WATCH_EVENT_DELETED, WATCH_NAME_B),
    ];
    for (index, (kind, name)) in expected.iter().enumerate() {
        let event = &events[index];
        if event.kind != *kind || event.name() != *name || event.dropped != 0 {
            return Err(EXIT_WATCH_EVENTS);
        }
    }

    // A handle that was never issued must be rejected, not silently accepted.
    let bogus = handle(0x7FFF, 0);
    if !matches!(rt::watch_drain(bogus, &mut events), Err(ERR_BAD_HANDLE)) {
        return Err(EXIT_WATCH_BAD_HANDLE);
    }

    Ok(())
}

/// Handles init keeps open (with a POSIX exclusive lock held) across the child
/// spawn, so the child can observe a real cross-process conflict.
struct HeldLocks {
    file: Handle,
    other: Handle,
    duplicated: Handle,
}

/// M5c3: lock semantics inside one process, before the child is spawned.
///
/// Covers OFD conflicts between distinct open file descriptions, `dup` sharing
/// one description, `flock` living in its own domain, and POSIX locks being
/// process-owned. The POSIX exclusive lock is left held across the spawn.
fn lock_step_prepare() -> Result<HeldLocks, u64> {
    let file = rt::open(FAT_LOCK, OPEN_CREATE | OPEN_READ | OPEN_WRITE | OPEN_TRUNC)
        .map_err(|_| EXIT_LOCK_OPEN)?;
    let other = rt::open(FAT_LOCK, OPEN_READ | OPEN_WRITE).map_err(|_| EXIT_LOCK_OPEN)?;

    // 1. Two distinct open file descriptions conflict in the OFD domain.
    rt::lock(
        other,
        &mut LockRequest::new(LOCK_DOMAIN_OFD, LOCK_OP_EXCLUSIVE, 0, 0),
    )
    .map_err(|_| EXIT_LOCK_OFD)?;
    let third = rt::open(FAT_LOCK, OPEN_READ | OPEN_WRITE).map_err(|_| EXIT_LOCK_OPEN)?;
    let conflicted = matches!(
        rt::lock(
            third,
            &mut LockRequest::new(LOCK_DOMAIN_OFD, LOCK_OP_EXCLUSIVE, 0, 0)
        ),
        Err(ERR_WOULD_BLOCK)
    );
    let _ = rt::handle_close(third);
    if !conflicted {
        return Err(EXIT_LOCK_OFD);
    }
    rt::lock(
        other,
        &mut LockRequest::new(LOCK_DOMAIN_OFD, LOCK_OP_UNLOCK, 0, 0),
    )
    .map_err(|_| EXIT_LOCK_OFD)?;

    // 2. A `dup` shares its open file description: the lock can be re-taken
    //    through the duplicate, and releasing it there releases the shared lock.
    rt::lock(
        file,
        &mut LockRequest::new(LOCK_DOMAIN_OFD, LOCK_OP_EXCLUSIVE, 0, 0),
    )
    .map_err(|_| EXIT_LOCK_DUP)?;
    let duplicated = rt::dup(file, RIGHT_READ | RIGHT_WRITE).map_err(|_| EXIT_LOCK_DUP)?;
    rt::lock(
        duplicated,
        &mut LockRequest::new(LOCK_DOMAIN_OFD, LOCK_OP_EXCLUSIVE, 0, 0),
    )
    .map_err(|_| EXIT_LOCK_DUP)?;
    rt::lock(
        duplicated,
        &mut LockRequest::new(LOCK_DOMAIN_OFD, LOCK_OP_UNLOCK, 0, 0),
    )
    .map_err(|_| EXIT_LOCK_DUP)?;

    // 3. `flock` is an independent domain: it ignores OFD locks.
    rt::lock(
        other,
        &mut LockRequest::new(LOCK_DOMAIN_FLOCK, LOCK_OP_EXCLUSIVE, 0, 0),
    )
    .map_err(|_| EXIT_LOCK_FLOCK)?;
    rt::lock(
        other,
        &mut LockRequest::new(LOCK_DOMAIN_FLOCK, LOCK_OP_UNLOCK, 0, 0),
    )
    .map_err(|_| EXIT_LOCK_FLOCK)?;

    // 4. POSIX locks belong to the process: a second handle never conflicts,
    //    and the lock is still held for the child to trip over.
    rt::lock(
        file,
        &mut LockRequest::new(LOCK_DOMAIN_POSIX, LOCK_OP_EXCLUSIVE, 0, 0),
    )
    .map_err(|_| EXIT_LOCK_POSIX)?;
    rt::lock(
        other,
        &mut LockRequest::new(LOCK_DOMAIN_POSIX, LOCK_OP_EXCLUSIVE, 0, 0),
    )
    .map_err(|_| EXIT_LOCK_POSIX)?;

    // 5. POSIX and flock must not conflict with each other either: take the
    //    flock while the POSIX lock is held.
    rt::lock(
        other,
        &mut LockRequest::new(LOCK_DOMAIN_FLOCK, LOCK_OP_EXCLUSIVE, 0, 0),
    )
    .map_err(|_| EXIT_LOCK_FLOCK)?;
    rt::lock(
        other,
        &mut LockRequest::new(LOCK_DOMAIN_FLOCK, LOCK_OP_UNLOCK, 0, 0),
    )
    .map_err(|_| EXIT_LOCK_FLOCK)?;

    Ok(HeldLocks {
        file,
        other,
        duplicated,
    })
}

/// M5c3: releases the process lock the child had to observe and closes handles.
fn lock_step_finish(held: HeldLocks) -> Result<(), u64> {
    rt::lock(
        held.file,
        &mut LockRequest::new(LOCK_DOMAIN_POSIX, LOCK_OP_UNLOCK, 0, 0),
    )
    .map_err(|_| EXIT_LOCK_RELEASE)?;
    rt::handle_close(held.duplicated).map_err(|_| EXIT_LOCK_RELEASE)?;
    rt::handle_close(held.other).map_err(|_| EXIT_LOCK_RELEASE)?;
    rt::handle_close(held.file).map_err(|_| EXIT_LOCK_RELEASE)?;
    Ok(())
}

/// M6a1: creates the EventPair whose second end is handed to the child.
fn m6a_create_pair() -> Result<Handle, u64> {
    rt::ipc_create_kind(IPC_KIND_EVENT_PAIR, 0, 0, 0).map_err(|_| EXIT_M6A_CREATE)
}

/// M6a1: auto-reset Event semantics and the "never signalled" timeout path.
///
/// A fresh auto-reset Event must not be ready; signalling makes it ready exactly
/// once (the successful wait consumes it), so the next immediate wait blocks
/// again. A second Event that is never signalled must report `ERR_TIMEOUT`
/// after [`M6A_TIMEOUT_TICKS`] rather than blocking forever.
fn m6a_event_step() -> Result<(), u64> {
    let event = rt::ipc_create_kind(IPC_KIND_EVENT, 0, 0, 0).map_err(|_| EXIT_M6A_CREATE)?;
    if !matches!(
        rt::wait_one(event, 0, WAIT_TIMEOUT_IMMEDIATE),
        Err(ERR_WOULD_BLOCK)
    ) {
        return Err(EXIT_M6A_EVENT);
    }
    rt::ipc_signal(event, SIGNAL_OP_SIGNAL, 0).map_err(|_| EXIT_M6A_EVENT)?;
    let out = rt::wait_one(event, 0, WAIT_TIMEOUT_INFINITE).map_err(|_| EXIT_M6A_EVENT)?;
    if out.wake_reason != WAKE_READY || !out.is_ready(0) {
        return Err(EXIT_M6A_EVENT);
    }
    // Auto reset: the successful wait consumed the signal.
    if !matches!(
        rt::wait_one(event, 0, WAIT_TIMEOUT_IMMEDIATE),
        Err(ERR_WOULD_BLOCK)
    ) {
        return Err(EXIT_M6A_EVENT);
    }
    rt::handle_close(event).map_err(|_| EXIT_M6A_EVENT)?;

    let idle = rt::ipc_create_kind(IPC_KIND_EVENT, 0, 0, 0).map_err(|_| EXIT_M6A_CREATE)?;
    if !matches!(rt::wait_one(idle, 0, M6A_TIMEOUT_TICKS), Err(ERR_TIMEOUT)) {
        return Err(EXIT_M6A_TIMEOUT);
    }
    rt::handle_close(idle).map_err(|_| EXIT_M6A_TIMEOUT)?;
    Ok(())
}

/// M6a1: arms a one-shot timer and blocks until it fires.
///
/// While init sleeps here the child is blocked on the EventPair, so this also
/// covers the "every user thread blocked, kernel goes idle" path.
fn m6a_timer_step() -> Result<(), u64> {
    let timer = rt::ipc_create_kind(IPC_KIND_TIMER, 0, 0, 0).map_err(|_| EXIT_M6A_CREATE)?;
    rt::timer_arm(timer, M6A_TIMER_TICKS, 0).map_err(|_| EXIT_M6A_TIMER)?;
    let out = rt::wait_one(timer, 0, WAIT_TIMEOUT_INFINITE).map_err(|_| EXIT_M6A_TIMER)?;
    if out.wake_reason != WAKE_READY || !out.is_ready(0) {
        return Err(EXIT_M6A_TIMER);
    }
    rt::handle_close(timer).map_err(|_| EXIT_M6A_TIMER)?;
    Ok(())
}

/// M6a1: signals the EventPair end the child waits on.
///
/// EventPair readiness is cross-endpoint (final contract): signalling endpoint A
/// makes a waiter on endpoint B ready, which is the end the child blocks on.
fn m6a_signal_pair(pair: Handle) -> Result<(), u64> {
    rt::ipc_signal(pair, SIGNAL_OP_SIGNAL, EVENT_PAIR_ENDPOINT_A).map_err(|_| EXIT_M6A_PAIR)
}

// ---------------------------------------------------------------------------
// M6a2: channels, ports, shared memory, futexes and event subscriptions
// ---------------------------------------------------------------------------

/// Sends one message, transferring `handles` with `rights` when non-empty.
fn ipc_send_message(
    channel: Handle,
    protocol: u32,
    transaction: u64,
    data: &[u8],
    handles: &[Handle],
    rights: &[u32],
) -> Result<usize, u64> {
    let mut request = IpcSendRequest::new(protocol, MSG_VERSION, transaction);
    request.data_ptr = data.as_ptr() as u64;
    request.data_len = data.len() as u32;
    request.handle_count = handles.len() as u32;
    request.handles_ptr = handles.as_ptr() as u64;
    request.rights_ptr = rights.as_ptr() as u64;
    rt::ipc_send(channel, &mut request).map_err(|_| EXIT_M6A2_SEND)
}

/// Receives one message into the caller's buffers.
fn ipc_recv_message(
    channel: Handle,
    data: &mut [u8],
    handles: &mut [Handle],
    rights: &mut [u32],
    meta: &mut IpcMessageMeta,
    timeout_ticks: u32,
) -> Result<usize, u64> {
    rt::ipc_recv(channel, data, handles, rights, meta, timeout_ticks as u64)
        .map_err(|_| EXIT_M6A2_RECV)
}

/// Checks the routing metadata and payload of a received message.
fn expect_message(
    data_len: usize,
    meta: &IpcMessageMeta,
    protocol: u32,
    transaction: u64,
    expected: &[u8],
) -> Result<usize, u64> {
    if meta.protocol != protocol || meta.transaction != transaction {
        return Err(EXIT_M6A2_PAYLOAD);
    }
    if data_len != expected.len() || meta.data_len as usize != expected.len() {
        return Err(EXIT_M6A2_PAYLOAD);
    }
    Ok(data_len)
}

/// Reads one byte of the shared-memory mapping at `base + index`.
fn shm_read(base: usize, index: usize) -> u8 {
    unsafe { core::ptr::read_volatile((base + index) as *const u8) }
}

/// Writes one byte of the shared-memory mapping at `base + index`.
fn shm_write(base: usize, index: usize, value: u8) {
    unsafe { core::ptr::write_volatile((base + index) as *mut u8, value) }
}

/// Reads the `u32` at `base + offset`.
fn shm_read_u32(base: usize, offset: usize) -> u32 {
    unsafe { core::ptr::read_volatile((base + offset) as *const u32) }
}

/// Writes the `u32` at `base + offset`.
fn shm_write_u32(base: usize, offset: usize, value: u32) {
    unsafe { core::ptr::write_volatile((base + offset) as *mut u32, value) }
}

/// Self-contained channel test with both ends owned by init.
///
/// Covers FIFO ordering, the [`native_abi::IPC_DATA_MAX`] inline-data boundary,
/// an empty message, and the bounded queue reporting `WOULD_BLOCK` instead of
/// growing without limit.
fn m6a2_channel_self_test() -> Result<(), u64> {
    let (sender, receiver) =
        rt::ipc_create_pair(IPC_KIND_CHANNEL, 0).map_err(|_| EXIT_M6A2_CREATE)?;
    let payloads: [&[u8]; 3] = [b"ONE", b"TWO", b"THREE"];
    for (i, payload) in payloads.iter().enumerate() {
        ipc_send_message(sender, PROTO_CHANNEL, 100 + i as u64, payload, &[], &[])?;
    }
    let mut data = [0u8; native_abi::IPC_DATA_MAX];
    let mut meta = IpcMessageMeta::empty();
    for (i, payload) in payloads.iter().enumerate() {
        let len = ipc_recv_message(
            receiver,
            &mut data,
            &mut [],
            &mut [],
            &mut meta,
            WAIT_TIMEOUT_IMMEDIATE,
        )?;
        expect_message(len, &meta, PROTO_CHANNEL, 100 + i as u64, payload)?;
        if data[..len] != payload[..] {
            return Err(EXIT_M6A2_PAYLOAD);
        }
    }

    // Inline-data boundary: exactly IPC_DATA_MAX bytes, then an empty message.
    ipc_send_message(sender, PROTO_CHANNEL, 200, &CHANNEL_BOUNDARY, &[], &[])?;
    let len = ipc_recv_message(
        receiver,
        &mut data,
        &mut [],
        &mut [],
        &mut meta,
        WAIT_TIMEOUT_IMMEDIATE,
    )?;
    if len != CHANNEL_BOUNDARY.len() || data[..len] != CHANNEL_BOUNDARY[..] {
        return Err(EXIT_M6A2_PAYLOAD);
    }
    ipc_send_message(sender, PROTO_CHANNEL, 201, b"", &[], &[])?;
    let len = ipc_recv_message(
        receiver,
        &mut data,
        &mut [],
        &mut [],
        &mut meta,
        WAIT_TIMEOUT_IMMEDIATE,
    )?;
    if len != 0 {
        return Err(EXIT_M6A2_PAYLOAD);
    }

    // Queue full: keep sending until the channel refuses, then drain it.
    let mut queued = 0usize;
    let mut full = false;
    for _ in 0..64 {
        let mut request = IpcSendRequest::new(PROTO_CHANNEL, MSG_VERSION, 300);
        let payload = b"Q";
        request.data_ptr = payload.as_ptr() as u64;
        request.data_len = payload.len() as u32;
        match rt::ipc_send(sender, &mut request) {
            Ok(_) => queued += 1,
            Err(ERR_WOULD_BLOCK) => {
                full = true;
                break;
            }
            Err(_) => return Err(EXIT_M6A2_QUEUE),
        }
    }
    if !full || queued == 0 {
        return Err(EXIT_M6A2_QUEUE);
    }
    for _ in 0..queued {
        ipc_recv_message(
            receiver,
            &mut data,
            &mut [],
            &mut [],
            &mut meta,
            WAIT_TIMEOUT_IMMEDIATE,
        )?;
    }
    // The empty receive must surface the *raw* `WOULD_BLOCK`: `ipc_recv_message`
    // flattens every error into `EXIT_M6A2_RECV`, so build the request here and
    // issue the syscall directly. The other paths keep the helper's exit codes.
    let mut empty = IpcReceiveRequest::new(
        data.as_mut_ptr() as u64,
        data.len() as u32,
        &mut meta as *mut IpcMessageMeta as u64,
        WAIT_TIMEOUT_IMMEDIATE as u64,
    );
    empty.handle_capacity = 0;
    empty.out_handles_ptr = 0;
    empty.out_rights_ptr = 0;
    let status = unsafe {
        rt::syscall(
            NR_IPC_RECV,
            receiver as u64,
            &mut empty as *mut IpcReceiveRequest as u64,
            0,
            0,
            0,
            0,
        )
    };
    if status.into_result() != Err(ERR_WOULD_BLOCK) {
        return Err(EXIT_M6A2_QUEUE);
    }

    rt::handle_close(sender).map_err(|_| EXIT_M6A2_CLOSE)?;
    rt::handle_close(receiver).map_err(|_| EXIT_M6A2_CLOSE)?;
    Ok(())
}

/// Builds the channel/port/shm/subscription rig and fills the shm pattern.
fn m6a2_prepare() -> Result<M6a2State, u64> {
    let (channel_a, channel_b) =
        rt::ipc_create_pair(IPC_KIND_CHANNEL, 0).map_err(|_| EXIT_M6A2_CREATE)?;
    let (port_receiver, port_sender) =
        rt::ipc_create_pair(IPC_KIND_PORT, 0).map_err(|_| EXIT_M6A2_CREATE)?;
    let (sub_channel_a, sub_channel_b) =
        rt::ipc_create_pair(IPC_KIND_CHANNEL, 0).map_err(|_| EXIT_M6A2_CREATE)?;
    let shm = rt::ipc_create_shm(SHM_LEN).map_err(|_| EXIT_M6A2_CREATE)?;
    let (shm_map_a, shm_alias_a) =
        rt::shm_map(shm, &mut ShmMapRequest::new(PROT_READ | PROT_WRITE, 0))
            .map_err(|_| EXIT_M6A2_SHM)?;
    let (shm_map_b, shm_alias_b) =
        rt::shm_map(shm, &mut ShmMapRequest::new(PROT_READ | PROT_WRITE, 0))
            .map_err(|_| EXIT_M6A2_SHM)?;
    if shm_alias_a == shm_alias_b {
        return Err(EXIT_M6A2_SHM);
    }
    for index in 0..SHM_LEN {
        shm_write(shm_alias_a, index, map_pattern(index));
    }
    shm_write_u32(shm_alias_a, SHM_FUTEX_OFFSET, 0);

    let sub_level = rt::ipc_create_subscription().map_err(|_| EXIT_M6A2_CREATE)?;
    rt::subscribe(
        sub_level,
        &[SubscriptionEntry::new(
            sub_channel_a,
            SUBSCRIPTION_MODE_LEVEL,
            0,
        )],
    )
    .map_err(|_| EXIT_M6A2_SUB)?;
    let sub_edge = rt::ipc_create_subscription().map_err(|_| EXIT_M6A2_CREATE)?;
    rt::subscribe(
        sub_edge,
        &[SubscriptionEntry::new(
            sub_channel_a,
            SUBSCRIPTION_MODE_EDGE,
            0,
        )],
    )
    .map_err(|_| EXIT_M6A2_SUB)?;

    Ok(M6a2State {
        channel_a,
        channel_b,
        port_receiver,
        port_sender,
        shm,
        shm_map_a,
        shm_map_b,
        shm_alias_a,
        shm_alias_b,
        sub_channel_a,
        sub_channel_b,
        sub_level,
        sub_edge,
    })
}

/// Queues the messages the child consumes right after the spawn.
fn m6a2_handshake(state: &M6a2State) -> Result<(), u64> {
    // Message 1 carries the port sender (write-only) and the shm object.
    let handles = [state.port_sender, state.shm];
    let rights = [RIGHT_WRITE, RIGHT_MAP | RIGHT_READ | RIGHT_WRITE];
    ipc_send_message(
        state.channel_a,
        PROTO_CHANNEL,
        TX_CHANNEL_FIRST,
        CHANNEL_FIRST,
        &handles,
        &rights,
    )?;
    // Message 2 hands over the child's subscription channel end (write-only).
    let sub_handles = [state.sub_channel_b];
    let sub_rights = [RIGHT_WRITE];
    ipc_send_message(
        state.channel_a,
        PROTO_CHANNEL,
        TX_CHANNEL_SECOND,
        CHANNEL_SECOND,
        &sub_handles,
        &sub_rights,
    )?;
    // Message 3 exercises the inline-data boundary and FIFO ordering.
    ipc_send_message(
        state.channel_a,
        PROTO_CHANNEL,
        TX_CHANNEL_BOUNDARY,
        &CHANNEL_BOUNDARY,
        &[],
        &[],
    )?;
    Ok(())
}

/// Verifies the child's channel/shared-memory/futex/port handshakes.
fn m6a2_after_spawn(console: Handle, state: &M6a2State) -> Result<(), u64> {
    let mut data = [0u8; native_abi::IPC_DATA_MAX];
    let mut handles = [0u32; native_abi::IPC_HANDLES_MAX];
    let mut rights = [0u32; native_abi::IPC_HANDLES_MAX];
    let mut meta = IpcMessageMeta::empty();

    // The child mapped the shm, verified our pattern and wrote its response.
    let len = ipc_recv_message(
        state.channel_a,
        &mut data,
        &mut handles,
        &mut rights,
        &mut meta,
        WAIT_TIMEOUT_INFINITE,
    )?;
    expect_message(len, &meta, PROTO_CHANNEL, TX_SHM_MAPPED, b"shm-mapped")?;
    for (index, byte) in SHM_RESPONSE_MARK.iter().enumerate() {
        if shm_read(state.shm_alias_b, SHM_RESPONSE_OFFSET + index) != *byte {
            return Err(EXIT_M6A2_SHM);
        }
    }
    write_line(console, M6A_SHM_OK);

    // The child is about to block on the futex; give it time to sleep, then
    // publish the new value through alias A and wake it.
    let len = ipc_recv_message(
        state.channel_a,
        &mut data,
        &mut handles,
        &mut rights,
        &mut meta,
        WAIT_TIMEOUT_INFINITE,
    )?;
    expect_message(len, &meta, PROTO_CHANNEL, TX_FUTEX_READY, b"futex-ready")?;
    let timer = rt::ipc_create_kind(IPC_KIND_TIMER, 0, 0, 0).map_err(|_| EXIT_M6A2_FUTEX)?;
    rt::timer_arm(timer, SHM_WAKE_TICKS, 0).map_err(|_| EXIT_M6A2_FUTEX)?;
    rt::wait_one(timer, 0, WAIT_TIMEOUT_INFINITE).map_err(|_| EXIT_M6A2_FUTEX)?;
    rt::handle_close(timer).map_err(|_| EXIT_M6A2_FUTEX)?;
    shm_write_u32(state.shm_alias_a, SHM_FUTEX_OFFSET, 1);
    let woken =
        rt::futex_wake(state.shm_alias_a + SHM_FUTEX_OFFSET, 1).map_err(|_| EXIT_M6A2_FUTEX)?;
    if woken != 1 {
        return Err(EXIT_M6A2_FUTEX);
    }
    let len = ipc_recv_message(
        state.channel_a,
        &mut data,
        &mut handles,
        &mut rights,
        &mut meta,
        WAIT_TIMEOUT_INFINITE,
    )?;
    expect_message(len, &meta, PROTO_CHANNEL, TX_FUTEX_OK, b"futex-ok")?;
    if shm_read_u32(state.shm_alias_b, SHM_FUTEX_OFFSET) != 1 {
        return Err(EXIT_M6A2_FUTEX);
    }
    write_line(console, M6A_FUTEX_OK);

    // Port: the child sends one message through the write-only sender it got.
    let len = ipc_recv_message(
        state.port_receiver,
        &mut data,
        &mut handles,
        &mut rights,
        &mut meta,
        WAIT_TIMEOUT_INFINITE,
    )
    .map_err(|_| EXIT_M6A2_PORT)?;
    expect_message(len, &meta, PROTO_PORT, TX_PORT, PORT_HELLO)?;
    let len = ipc_recv_message(
        state.channel_a,
        &mut data,
        &mut handles,
        &mut rights,
        &mut meta,
        WAIT_TIMEOUT_INFINITE,
    )?;
    expect_message(len, &meta, PROTO_CHANNEL, TX_PORT_SENT, b"port-sent")?;
    write_line(console, M6A_PORT_OK);
    write_line(console, M6A_CHANNEL_OK);
    Ok(())
}

/// Drives the level/edge subscription checks on the dedicated channel.
fn m6a2_subscription(console: Handle, state: &M6a2State) -> Result<(), u64> {
    ipc_send_message(
        state.channel_a,
        PROTO_CHANNEL,
        TX_CHANNEL_GO_SUB,
        CHANNEL_GO_SUB,
        &[],
        &[],
    )?;

    let mut request = WaitRequest::new(0, WAIT_TIMEOUT_INFINITE);
    if !request.push(WaitItem::new(state.sub_level, 0))
        || !request.push(WaitItem::new(state.sub_edge, 0))
    {
        return Err(EXIT_M6A2_SUB);
    }
    let mut out = WaitOut::empty();
    if rt::wait_objects(&mut request, &mut out).map_err(|_| EXIT_M6A2_SUB)? != 2
        || !out.is_ready(0)
        || !out.is_ready(1)
    {
        return Err(EXIT_M6A2_SUB);
    }

    let mut level_events = [SubscriptionEvent::empty(); 1];
    let mut edge_events = [SubscriptionEvent::empty(); 1];
    if rt::subscription_read(state.sub_level, &mut level_events).map_err(|_| EXIT_M6A2_SUB)? != 1
        || level_events[0].mode != SUBSCRIPTION_MODE_LEVEL
    {
        return Err(EXIT_M6A2_SUB);
    }
    if rt::subscription_read(state.sub_edge, &mut edge_events).map_err(|_| EXIT_M6A2_SUB)? != 1
        || edge_events[0].mode != SUBSCRIPTION_MODE_EDGE
    {
        return Err(EXIT_M6A2_SUB);
    }
    // Both interests observe the same object at key 0: the frozen encoding is
    // `(object_raw << 32) | key`.
    let object_key = level_events[0].object_key;
    if object_key != edge_events[0].object_key
        || native_abi::subscription_object_raw(object_key) == 0
        || native_abi::subscription_key(object_key) != 0
    {
        return Err(EXIT_M6A2_SUB);
    }

    // Level-triggered re-read still reports ready while the message is queued.
    if rt::subscription_read(state.sub_level, &mut level_events).map_err(|_| EXIT_M6A2_SUB)? != 1 {
        return Err(EXIT_M6A2_SUB);
    }
    // Edge-triggered re-read reports nothing new.
    if rt::subscription_read(state.sub_edge, &mut edge_events).map_err(|_| EXIT_M6A2_SUB)? != 0 {
        return Err(EXIT_M6A2_SUB);
    }

    // Drain the observed channel; level-triggered readiness must fall back.
    let mut data = [0u8; native_abi::IPC_DATA_MAX];
    let mut meta = IpcMessageMeta::empty();
    let len = ipc_recv_message(
        state.sub_channel_a,
        &mut data,
        &mut [],
        &mut [],
        &mut meta,
        WAIT_TIMEOUT_INFINITE,
    )?;
    expect_message(len, &meta, PROTO_CHANNEL, TX_SUB_FIRST, SUB_FIRST)?;
    if rt::subscription_read(state.sub_level, &mut level_events).map_err(|_| EXIT_M6A2_SUB)? != 0 {
        return Err(EXIT_M6A2_SUB);
    }

    // Drop both interests; the observed channel must stay fully usable.
    if rt::unsubscribe(state.sub_level, state.sub_channel_a).map_err(|_| EXIT_M6A2_SUB)? != 1 {
        return Err(EXIT_M6A2_SUB);
    }
    rt::handle_close(state.sub_edge).map_err(|_| EXIT_M6A2_SUB)?;
    ipc_send_message(
        state.channel_a,
        PROTO_CHANNEL,
        TX_CHANNEL_GO_SUB2,
        CHANNEL_GO_SUB2,
        &[],
        &[],
    )?;
    let len = ipc_recv_message(
        state.sub_channel_a,
        &mut data,
        &mut [],
        &mut [],
        &mut meta,
        WAIT_TIMEOUT_INFINITE,
    )?;
    expect_message(len, &meta, PROTO_CHANNEL, TX_SUB_SECOND, SUB_SECOND)?;
    write_line(console, M6A_SUBSCRIPTION_OK);
    Ok(())
}

/// Receives the message the child queued just before exiting.
fn m6a2_take_last(state: &M6a2State) -> Result<(), u64> {
    let mut data = [0u8; native_abi::IPC_DATA_MAX];
    let mut handles = [0u32; native_abi::IPC_HANDLES_MAX];
    let mut rights = [0u32; native_abi::IPC_HANDLES_MAX];
    let mut meta = IpcMessageMeta::empty();
    let len = ipc_recv_message(
        state.channel_a,
        &mut data,
        &mut handles,
        &mut rights,
        &mut meta,
        WAIT_TIMEOUT_INFINITE,
    )?;
    expect_message(len, &meta, PROTO_CHANNEL, TX_LAST, b"last")?;
    if meta.handle_count != 1 || rights[0] != RIGHT_WRITE || handles[0] == 0 {
        return Err(EXIT_M6A2_HANDLES);
    }
    // The transferred Console handle must be a real, closeable capability.
    rt::handle_close(handles[0]).map_err(|_| EXIT_M6A2_HANDLE_BACK)?;
    Ok(())
}

/// Closes every object the M6a2 rig created.
fn m6a2_release(state: M6a2State) -> Result<(), u64> {
    for handle in [
        state.shm_map_a,
        state.shm_map_b,
        state.sub_level,
        state.sub_channel_a,
        state.sub_channel_b,
        state.port_sender,
        state.port_receiver,
        state.shm,
        state.channel_b,
        state.channel_a,
    ] {
        rt::handle_close(handle).map_err(|_| EXIT_M6A2_CLOSE)?;
    }
    Ok(())
}

#[unsafe(no_mangle)]
pub extern "C" fn _start(console: u64, random: u64) -> ! {
    // Entry handles are ABI-level 64-bit values; the low 32 bits are the
    // opaque handle, upper bits are zero.
    let console = console as Handle;
    let random = random as Handle;

    match rt::abi_query() {
        Ok(version) if version == ABI_VERSION => {}
        Ok(_) => {
            write_line(console, b"init FAIL abi version\n");
            rt::process_exit(EXIT_ABI_VERSION);
        }
        Err(_) => {
            write_line(console, b"init FAIL abi\n");
            rt::process_exit(EXIT_ABI);
        }
    }
    write_line(console, INIT_OK);

    // M5c1: real file and directory semantics on both persistent roots, before
    // the child is spawned so the child can verify the same bytes.
    let fat_appended = match file_step(console, FAT_FILE) {
        Ok(appended) => appended,
        Err(code) => fail(console, b"fat file step", code),
    };
    let ext2_appended = match file_step(console, EXT2_FILE) {
        Ok(appended) => appended,
        Err(code) => fail(console, b"ext2 file step", code),
    };
    if fat_appended != ext2_appended {
        fail(
            console,
            b"files disagree on boot generation",
            EXIT_FILE_PAIR,
        );
    }

    if let Err(code) = misc_steps(console) {
        fail(console, b"misc step", code);
    }
    if let Err(code) = dir_step(
        console,
        FAT_DIR,
        FAT_DIR_RENAMED,
        FAT_INNER,
        FAT_INNER_RENAMED,
    ) {
        fail(console, b"fat dir step", code);
    }
    if let Err(code) = dir_step(
        console,
        EXT2_DIR,
        EXT2_DIR_RENAMED,
        EXT2_INNER,
        EXT2_INNER_RENAMED,
    ) {
        fail(console, b"ext2 dir step", code);
    }
    write_line(console, M5C_FILES_OK);

    // M5c2: eager mappings on both persistent roots, still before the child is
    // spawned so the child can verify the shared/private result.
    if let Err(code) = mmap_step(FAT_MAP) {
        fail(console, b"fat mmap step", code);
    }
    if let Err(code) = mmap_step(EXT2_MAP) {
        fail(console, b"ext2 mmap step", code);
    }
    write_line(console, M5C_MMAP_OK);

    // M5c3: extended attributes, a sparse file, a directory watch and the locks
    // the child will probe. All of it runs before the spawn so the child sees
    // the final state and can observe a held POSIX lock.
    if let Err(code) = xattr_step(FAT_FILE, fat_appended) {
        fail(console, b"fat xattr step", code);
    }
    if let Err(code) = xattr_step(EXT2_FILE, ext2_appended) {
        fail(console, b"ext2 xattr step", code);
    }
    write_line(console, M5C_XATTR_OK);

    if let Err(code) = sparse_step(FAT_HOLE) {
        fail(console, b"fat sparse step", code);
    }
    if let Err(code) = sparse_step(EXT2_HOLE) {
        fail(console, b"ext2 sparse step", code);
    }
    write_line(console, M5C_SPARSE_OK);

    if let Err(code) = watch_step() {
        fail(console, b"watch step", code);
    }
    write_line(console, M5C_WATCH_OK);

    // M6a2: a self-contained channel test (both ends owned by init), then the
    // rig whose ends and objects are handed to the child.
    if let Err(code) = m6a2_channel_self_test() {
        fail(console, b"channel self test", code);
    }
    let m6a2 = match m6a2_prepare() {
        Ok(state) => state,
        Err(code) => fail(console, b"m6a2 prepare", code),
    };

    let held = match lock_step_prepare() {
        Ok(held) => held,
        Err(code) => fail(console, b"locks step", code),
    };

    // M6a1/M6a2: the child receives three initial handles - the console, the
    // second end of an EventPair init signals after arming a timer, and its end
    // of the channel used for the M6a2 handshake.
    let pair = match m6a_create_pair() {
        Ok(pair) => pair,
        Err(code) => fail(console, b"m6a pair", code),
    };
    let mut request = ProcessCreateRequest::with_module_name(CHILD_MODULE);
    if !request.push_handle(console, RIGHT_WRITE)
        || !request.push_handle(pair, RIGHT_WAIT | RIGHT_WRITE)
        || !request.push_handle(m6a2.channel_b, RIGHT_READ | RIGHT_WRITE)
    {
        write_line(console, b"init FAIL request\n");
        rt::process_exit(EXIT_SPAWN);
    }
    let child = match rt::process_create(&request) {
        Ok(child) => child,
        Err(_) => {
            write_line(console, b"init FAIL spawn\n");
            rt::process_exit(EXIT_SPAWN);
        }
    };
    write_line(console, SPAWN_OK);

    // M6a1: local Event semantics, then a one-shot timer wait (the child is
    // blocked on the EventPair, so the kernel must idle until the timer fires).
    if let Err(code) = m6a_event_step() {
        fail(console, b"m6a event step", code);
    }
    if let Err(code) = m6a_timer_step() {
        fail(console, b"m6a timer step", code);
    }
    write_line(console, M6A_TIMER_OK);
    if let Err(code) = m6a_signal_pair(pair) {
        fail(console, b"m6a pair signal", code);
    }
    write_line(console, M6A_EVENT_OK);

    // M6a2: queue the handshake messages, then verify the child's replies (shm
    // alias visibility, futex wake, port delivery) and the subscriptions.
    if let Err(code) = m6a2_handshake(&m6a2) {
        fail(console, b"m6a2 handshake", code);
    }
    if let Err(code) = m6a2_after_spawn(console, &m6a2) {
        fail(console, b"m6a2 after spawn", code);
    }
    if let Err(code) = m6a2_subscription(console, &m6a2) {
        fail(console, b"m6a2 subscription", code);
    }

    match rt::wait(child) {
        Ok(0) => {}
        Ok(_) => {
            write_line(console, b"init FAIL child status\n");
            rt::process_exit(EXIT_WAIT_STATUS);
        }
        Err(_) => {
            write_line(console, b"init FAIL wait\n");
            rt::process_exit(EXIT_WAIT);
        }
    }
    write_line(console, WAIT_OK);

    // M6a2: the child queued one last message (with a transferred Console
    // handle) right before exiting; it must be readable after the process died.
    if let Err(code) = m6a2_take_last(&m6a2) {
        fail(console, b"m6a2 handle back", code);
    }

    // M6a1: the child has consumed the EventPair signal; drop our end.
    if rt::handle_close(pair).is_err() {
        write_line(console, b"init FAIL m6a pair close\n");
        rt::process_exit(EXIT_M6A_PAIR);
    }

    // M5c3: with the child gone there are no cross-process conflicts left, so
    // release the held POSIX lock and close the handles.
    if let Err(code) = lock_step_finish(held) {
        fail(console, b"locks finish", code);
    }
    write_line(console, M5C_LOCKS_OK);

    // M6a2: release every object of the rig now that nothing observes them.
    if let Err(code) = m6a2_release(m6a2) {
        fail(console, b"m6a2 release", code);
    }

    let mut probe = [0u8; 8];
    match rt::random_read(random, &mut probe) {
        Err(native_abi::ERR_NO_ENTROPY) => {}
        _ => {
            write_line(console, b"init FAIL rng\n");
            rt::process_exit(EXIT_RNG);
        }
    }
    write_line(console, RNG_OK);

    rt::process_exit(0)
}
