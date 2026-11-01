//! CaelumOS `child`: a native user process spawned by init.
//!
//! The kernel enters `_start` with `rdi` = the Console handle that init
//! explicitly transferred and `rsi` = 0 (no second handle for this program).
//! The child is deliberately *not* given init's Random capability: handles are
//! only inherited when listed in the `process_create` request.
//!
//! Sequence:
//!
//! 1. `[CaelumChild] M4 child OK` via `write` on the Console handle.
//! 2. M5c1: read the two files init created before spawning this process and
//!    verify their exact bytes (14 on the first boot, 20 on the second boot).
//!    The child never writes, so a broken child cannot mask an init bug; on
//!    success it prints `[CaelumChild] M5c files OK`.
//! 3. M5c2: read the two files init mapped with a shared read-only mapping,
//!    verify that init's `A5`/`5A` bytes reached the files while its private
//!    `0xFF` write did not, reject a writable mapping of a read-only file, then
//!    print `[CaelumChild] M5c mmap OK`.
//! 4. M5c3: a cross-process POSIX lock request on init's held lock must report a
//!    conflict, OFD and `flock` must stay independent domains, and this process
//!    exits while holding its own POSIX lock on the ext2 root so the kernel's
//!    exit path has to reap it, then `[CaelumChild] M5c locks OK`.
//! 5. M6a1: block on the EventPair end init signals after arming a timer, then
//!    print `[CaelumChild] M6a event OK`.
//! 6. M6a2: receive the channel handshake (port sender, shm object and the
//!    write-only subscription channel end), verify the capability downgrades,
//!    exercise the channel/port boundary, map the shared memory through the
//!    transferred handle, wait on a futex init has to wake, publish the one
//!    event each subscription mode expects, hand the Console capability back,
//!    then print the four `[CaelumChild] M6a ... OK` markers.
//! 7. `random_read` on the fixed probe handle of init's Random capability must
//!    fail with `BAD_HANDLE` (not `BAD_RIGHT`, not success), proving there is no
//!    implicit handle inheritance, then `[CaelumChild] M4 handles OK`.
//! 8. `process_exit(0)`.

#![no_std]
#![no_main]

use native_abi::{
    ERR_BAD_HANDLE, ERR_BAD_RIGHT, ERR_WOULD_BLOCK, EVENT_PAIR_ENDPOINT_B, Handle, IpcMessageMeta,
    IpcSendRequest, LOCK_DOMAIN_FLOCK, LOCK_DOMAIN_OFD, LOCK_DOMAIN_POSIX, LOCK_OP_EXCLUSIVE,
    LOCK_OP_UNLOCK, LockRequest, MMAP_SHARED, MmapRequest, OPEN_CREATE, OPEN_READ, OPEN_WRITE,
    PROT_READ, PROT_WRITE, RIGHT_MAP, RIGHT_READ, RIGHT_WRITE, ShmMapRequest, StatOut,
    WAIT_TIMEOUT_IMMEDIATE, WAIT_TIMEOUT_INFINITE, WAKE_READY, handle,
};
use native_rt as rt;

/// Fixed output lines. They are the serial acceptance markers and must match
/// `xtask`'s observation list exactly.
const CHILD_OK: &[u8] = b"[CaelumChild] M4 child OK\n";
const M5C_FILES_OK: &[u8] = b"[CaelumChild] M5c files OK\n";
const M5C_MMAP_OK: &[u8] = b"[CaelumChild] M5c mmap OK\n";
const M5C_LOCKS_OK: &[u8] = b"[CaelumChild] M5c locks OK\n";
const M6A_EVENT_OK: &[u8] = b"[CaelumChild] M6a event OK\n";
const M6A_CHANNEL_OK: &[u8] = b"[CaelumChild] M6a channel OK\n";
const M6A_PORT_OK: &[u8] = b"[CaelumChild] M6a port OK\n";
const M6A_SHM_OK: &[u8] = b"[CaelumChild] M6a shm OK\n";
const M6A_FUTEX_OK: &[u8] = b"[CaelumChild] M6a futex OK\n";
const HANDLES_OK: &[u8] = b"[CaelumChild] M4 handles OK\n";

/// The exact bytes init must have left behind (see `services/init`).
const FILE_FIRST: &[u8] = b"CAELUM-M5C1-V1";
const FILE_SECOND: &[u8] = b"CAELUM-M5C1-V1\nBOOT2";

/// The two files created by init on the FAT32 and ext2 roots.
const FAT_FILE: &[u8] = b"/fat/M5CUSER.BIN";
const EXT2_FILE: &[u8] = b"/ext2/m5cuser";

/// The two files init mapped in the M5c2 round trip.
const FAT_MAP: &[u8] = b"/fat/M5MAP.BIN";
const EXT2_MAP: &[u8] = b"/ext2/m5cmap";

/// The read-only VFS boot module used for the rejecting `mmap` case.
const STARTUP_FILE: &[u8] = b"/boot/init";

/// The files init locks in the M5c3 round trip: on the first root it holds a
/// POSIX exclusive lock across the spawn; on the second root *this* process
/// leaves a POSIX lock held when it exits, so the reaping path is exercised.
const FAT_LOCK: &[u8] = b"/fat/M5LOCK.BIN";
const EXT2_LOCK: &[u8] = b"/ext2/m5clock";

/// Mapping geometry and the bytes init left in the files.
const MAP_LEN: usize = 8192;
const MAP_PAGE: usize = 4096;
const MAP_A: u8 = 0xA5;
const MAP_B: u8 = 0x5A;
const MAP_POS_A: usize = 0;
const MAP_POS_B: usize = 4103;

/// The handle of init's Random capability in the reference boot:
/// generation 1, slot 1 (ABI encoding `(generation << 16) | (slot + 1)`), so
/// `0x0001_0002`. init never transfers this handle to the child, so the child
/// must see it as an unknown handle.
const INIT_RANDOM_PROBE: Handle = handle(1, 1);

const EXIT_WRITE: u64 = 0x01;
const EXIT_HANDLES: u64 = 0x20;
const EXIT_HANDLES_INHERITED: u64 = 0x21;
const EXIT_FILES: u64 = 0x22;
const EXIT_FILES_GENERATION: u64 = 0x23;
const EXIT_MMAP: u64 = 0x24;
const EXIT_MMAP_PATTERN: u64 = 0x25;
const EXIT_MMAP_UNMAP: u64 = 0x26;
const EXIT_MMAP_RIGHTS: u64 = 0x27;
const EXIT_LOCKS_OPEN: u64 = 0x30;
const EXIT_LOCKS_POSIX: u64 = 0x31;
const EXIT_LOCKS_OFD: u64 = 0x32;
const EXIT_LOCKS_FLOCK: u64 = 0x33;
const EXIT_LOCKS_REAP: u64 = 0x34;
const EXIT_M6A_EVENT: u64 = 0x40;
const EXIT_M6A_EVENT_STATE: u64 = 0x41;
const EXIT_M6A2_RECV: u64 = 0x42;
const EXIT_M6A2_PAYLOAD: u64 = 0x43;
const EXIT_M6A2_HANDLES: u64 = 0x44;
const EXIT_M6A2_RIGHTS: u64 = 0x45;
const EXIT_M6A2_PORT: u64 = 0x46;
const EXIT_M6A2_SHM: u64 = 0x47;
const EXIT_M6A2_FUTEX: u64 = 0x48;
const EXIT_M6A2_SEND: u64 = 0x49;
const EXIT_M6A2_CLOSE: u64 = 0x4a;

/// M6a2 wire constants shared with `services/init`.
const PROTO_CHANNEL: u32 = 0x4D36_4132;
const PROTO_PORT: u32 = 0x504F_5254;
const MSG_VERSION: u32 = 1;
const CHANNEL_FIRST: &[u8] = b"M6A2-CHANNEL-1";
const CHANNEL_SECOND: &[u8] = b"M6A2-CHANNEL-2";
/// Exactly [`native_abi::IPC_DATA_MAX`] bytes: the inline data boundary.
const CHANNEL_BOUNDARY: [u8; native_abi::IPC_DATA_MAX] =
    *b"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const PORT_HELLO: &[u8] = b"m6a2-port-hello";
const SHM_RESPONSE_MARK: &[u8] = b"M6A2-SHM-RESPONSE";
const SUB_FIRST: &[u8] = b"M6A2-SUB-1";
const SUB_SECOND: &[u8] = b"M6A2-SUB-2";
const TX_CHANNEL_FIRST: u64 = 1;
const TX_CHANNEL_SECOND: u64 = 2;
const TX_CHANNEL_BOUNDARY: u64 = 6;
const TX_SHM_MAPPED: u64 = 10;
const TX_FUTEX_READY: u64 = 11;
const TX_FUTEX_OK: u64 = 12;
const TX_PORT_SENT: u64 = 13;
const TX_PORT: u64 = 5;
const TX_SUB_FIRST: u64 = 20;
const TX_SUB_SECOND: u64 = 21;
const TX_LAST: u64 = 30;
const TX_CHANNEL_GO_SUB: u64 = 3;
const TX_CHANNEL_GO_SUB2: u64 = 4;

/// Shared-memory geometry, matching `services/init`.
const SHM_LEN: usize = 8192;
const SHM_RESPONSE_OFFSET: usize = 4096;
const SHM_FUTEX_OFFSET: usize = 64;

/// Writes one output line through the Console handle.
fn write_line(console: Handle, line: &[u8]) {
    if rt::write_all(console, line).is_err() {
        rt::process_exit(EXIT_WRITE);
    }
}

/// Appends `bytes` to `line` at `len`.
fn push_bytes(line: &mut [u8; 96], len: &mut usize, bytes: &[u8]) {
    let mut index = 0;
    while index < bytes.len() {
        line[*len] = bytes[index];
        *len += 1;
        index += 1;
    }
}

/// Appends `value` as lowercase hex without leading zeros.
fn push_hex(line: &mut [u8; 96], len: &mut usize, value: u64) {
    let mut shift = 60u32;
    while shift > 0 && (value >> shift) == 0 {
        shift -= 4;
    }
    loop {
        let nibble = ((value >> shift) & 0xf) as u8;
        line[*len] = if nibble < 10 {
            b'0' + nibble
        } else {
            b'a' + (nibble - 10)
        };
        *len += 1;
        if shift == 0 {
            break;
        }
        shift -= 4;
    }
}

/// Names the M6a2 step behind one exit code, so a serial log is self-locating.
fn m6a2_reason(code: u64) -> &'static [u8] {
    match code {
        EXIT_M6A2_RECV => b"recv",
        EXIT_M6A2_PAYLOAD => b"payload",
        EXIT_M6A2_HANDLES => b"handles",
        EXIT_M6A2_RIGHTS => b"rights",
        EXIT_M6A2_PORT => b"port",
        EXIT_M6A2_SHM => b"shm",
        EXIT_M6A2_FUTEX => b"futex",
        EXIT_M6A2_SEND => b"send",
        EXIT_M6A2_CLOSE => b"close",
        _ => b"unknown",
    }
}

/// Prints `child FAIL m6a2 <reason> 0x<code>` plus the kernel status behind a
/// failed receive; the exit path itself is unchanged.
fn write_m6a2_failure(console: Handle, code: u64) {
    // Read the kernel status before the Console write overwrites it.
    let status = rt::last_status();
    let mut line = [0u8; 96];
    let mut len = 0;
    push_bytes(&mut line, &mut len, b"child FAIL m6a2 ");
    push_bytes(&mut line, &mut len, m6a2_reason(code));
    push_bytes(&mut line, &mut len, b" 0x");
    push_hex(&mut line, &mut len, code);
    if code == EXIT_M6A2_RECV {
        push_bytes(&mut line, &mut len, b" (kernel status 0x");
        push_hex(&mut line, &mut len, status);
        push_bytes(&mut line, &mut len, b")");
    }
    push_bytes(&mut line, &mut len, b"\n");
    write_line(console, &line[..len]);
}

/// Prints the first SHM pattern mismatch so a serial log says which byte
/// differed and what the mapping actually held; the failure path is unchanged.
fn write_shm_mismatch(console: Handle, index: usize, expected: u8, actual: u8) {
    let mut line = [0u8; 96];
    let mut len = 0;
    push_bytes(&mut line, &mut len, b"[dbg] child shm mismatch index 0x");
    push_hex(&mut line, &mut len, index as u64);
    push_bytes(&mut line, &mut len, b" expected 0x");
    push_hex(&mut line, &mut len, expected as u64);
    push_bytes(&mut line, &mut len, b" actual 0x");
    push_hex(&mut line, &mut len, actual as u64);
    push_bytes(&mut line, &mut len, b"\n");
    write_line(console, &line[..len]);
}

/// Verifies one init-created file: reads it, stats it through the same handle
/// and returns `true` when it holds the 14-byte first-boot payload, `false`
/// when it holds the 20-byte second-boot payload.
fn verify_file(path: &[u8]) -> Result<bool, u64> {
    let handle = rt::open(path, OPEN_READ).map_err(|_| EXIT_FILES)?;
    let mut buffer = [0u8; 32];
    let filled = rt::read_all(handle, &mut buffer).map_err(|_| EXIT_FILES)?;
    let mut stat = StatOut::empty();
    let stat_result = rt::stat(handle, &mut stat);
    let _ = rt::handle_close(handle);
    stat_result.map_err(|_| EXIT_FILES)?;

    if filled == FILE_FIRST.len()
        && buffer[..filled] == FILE_FIRST[..]
        && stat.file_size == FILE_FIRST.len() as u64
    {
        return Ok(true);
    }
    if filled == FILE_SECOND.len()
        && buffer[..filled] == FILE_SECOND[..]
        && stat.file_size == FILE_SECOND.len() as u64
    {
        return Ok(false);
    }
    Err(EXIT_FILES)
}

/// The byte init's M5c2 backing file starts with at `index`.
const fn map_pattern(index: usize) -> u8 {
    ((index * 7 + 3) % 251) as u8
}

/// Reads one byte out of a live read-only mapping.
fn map_read(base: usize, index: usize) -> u8 {
    debug_assert!(index < MAP_LEN);
    // SAFETY: `base` is the start of a live `MAP_LEN`-byte mapping of this
    // process and every caller keeps `index < MAP_LEN`.
    unsafe { *((base + index) as *const u8) }
}

/// Verifies one file through a shared read-only mapping: init's `A5`/`5A`
/// writes reached the file, the untouched pattern is intact elsewhere, and
/// init's private `0xFF` never persisted.
fn verify_mapping(path: &[u8]) -> Result<(), u64> {
    let file = rt::open(path, OPEN_READ).map_err(|_| EXIT_MMAP)?;
    let mut request = MmapRequest::new(MAP_LEN as u64, 0, PROT_READ, MMAP_SHARED, 0);
    let (_mapping, base) = match rt::mmap(file, &mut request) {
        Ok(pair) => pair,
        Err(_) => {
            let _ = rt::handle_close(file);
            return Err(EXIT_MMAP);
        }
    };

    let mut result = Ok(());
    let mut index = 0usize;
    while index < MAP_LEN {
        let value = map_read(base, index);
        let expected = match index {
            MAP_POS_A => MAP_A,
            MAP_POS_B => MAP_B,
            _ => map_pattern(index),
        };
        if value != expected || value == 0xFF {
            result = Err(EXIT_MMAP_PATTERN);
            break;
        }
        index += 1;
    }

    let unmapped = rt::munmap(base, MAP_LEN);
    let closed = rt::handle_close(file);
    result?;
    unmapped.map_err(|_| EXIT_MMAP_UNMAP)?;
    closed.map_err(|_| EXIT_MMAP_UNMAP)
}

/// A read-only file must reject a writable shared mapping with `BAD_RIGHT`.
fn expect_writable_mapping_rights_error() -> Result<(), u64> {
    let file = rt::open(STARTUP_FILE, OPEN_READ).map_err(|_| EXIT_MMAP_RIGHTS)?;
    let mut request = MmapRequest::new(MAP_PAGE as u64, 0, PROT_READ | PROT_WRITE, MMAP_SHARED, 0);
    let result = rt::mmap(file, &mut request);
    let _ = rt::handle_close(file);
    match result {
        Err(ERR_BAD_RIGHT) => Ok(()),
        Ok((mapping, _base)) => {
            let _ = rt::handle_close(mapping);
            Err(EXIT_MMAP_RIGHTS)
        }
        Err(_) => Err(EXIT_MMAP_RIGHTS),
    }
}

/// M5c3: proves the lock contract across processes, then leaves a lock held on
/// the second root so the kernel's exit path has to reap it.
fn lock_step() -> Result<(), u64> {
    // init holds a POSIX exclusive lock on this file across the spawn: a
    // cross-process POSIX request must report a conflict, never sleep or win.
    let file = rt::open(FAT_LOCK, OPEN_READ | OPEN_WRITE).map_err(|_| EXIT_LOCKS_OPEN)?;
    if !matches!(
        rt::lock(
            file,
            &mut LockRequest::new(LOCK_DOMAIN_POSIX, LOCK_OP_EXCLUSIVE, 0, 0)
        ),
        Err(ERR_WOULD_BLOCK)
    ) {
        let _ = rt::handle_close(file);
        return Err(EXIT_LOCKS_POSIX);
    }

    // OFD and flock are independent domains: init's POSIX lock must not leak
    // into them, so both can be taken and released here.
    rt::lock(
        file,
        &mut LockRequest::new(LOCK_DOMAIN_OFD, LOCK_OP_EXCLUSIVE, 0, 0),
    )
    .map_err(|_| EXIT_LOCKS_OFD)?;
    rt::lock(
        file,
        &mut LockRequest::new(LOCK_DOMAIN_OFD, LOCK_OP_UNLOCK, 0, 0),
    )
    .map_err(|_| EXIT_LOCKS_OFD)?;
    rt::lock(
        file,
        &mut LockRequest::new(LOCK_DOMAIN_FLOCK, LOCK_OP_EXCLUSIVE, 0, 0),
    )
    .map_err(|_| EXIT_LOCKS_FLOCK)?;
    rt::lock(
        file,
        &mut LockRequest::new(LOCK_DOMAIN_FLOCK, LOCK_OP_UNLOCK, 0, 0),
    )
    .map_err(|_| EXIT_LOCKS_FLOCK)?;
    rt::handle_close(file).map_err(|_| EXIT_LOCKS_OPEN)?;

    // Hold a POSIX exclusive lock on the second root and exit without releasing
    // it: the kernel must release both the lock and the handle on exit.
    let ext2 =
        rt::open(EXT2_LOCK, OPEN_CREATE | OPEN_READ | OPEN_WRITE).map_err(|_| EXIT_LOCKS_OPEN)?;
    rt::lock(
        ext2,
        &mut LockRequest::new(LOCK_DOMAIN_POSIX, LOCK_OP_EXCLUSIVE, 0, 0),
    )
    .map_err(|_| EXIT_LOCKS_REAP)?;

    Ok(())
}

/// Sends one message, transferring `handles` with `rights` when non-empty.
fn ipc_send_message(
    channel: Handle,
    protocol: u32,
    transaction: u64,
    data: &[u8],
    handles: &[Handle],
    rights: &[u32],
) -> Result<(), u64> {
    let mut request = IpcSendRequest::new(protocol, MSG_VERSION, transaction);
    request.data_ptr = data.as_ptr() as u64;
    request.data_len = data.len() as u32;
    request.handle_count = handles.len() as u32;
    request.handles_ptr = handles.as_ptr() as u64;
    request.rights_ptr = rights.as_ptr() as u64;
    rt::ipc_send(channel, &mut request)
        .map(|_| ())
        .map_err(|_| EXIT_M6A2_SEND)
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

/// Drives the M6a2 channel/port/shm/futex/subscription handshake.
///
/// Everything this process owns is closed before returning; the last channel
/// message hands the Console capability back to init so the receiving side can
/// prove handle transfer still works after the sender exits.
fn m6a2_step(console: Handle, channel: Handle) -> Result<(), u64> {
    let mut data = [0u8; native_abi::IPC_DATA_MAX];
    let mut handles = [0u32; native_abi::IPC_HANDLES_MAX];
    let mut rights = [0u32; native_abi::IPC_HANDLES_MAX];
    let mut meta = IpcMessageMeta::empty();

    // A1: the port sender (write-only) and the shm object (map/read/write).
    let len = ipc_recv_message(
        channel,
        &mut data,
        &mut handles,
        &mut rights,
        &mut meta,
        WAIT_TIMEOUT_INFINITE,
    )?;
    if meta.protocol != PROTO_CHANNEL
        || meta.transaction != TX_CHANNEL_FIRST
        || len != CHANNEL_FIRST.len()
        || data[..len] != CHANNEL_FIRST[..]
    {
        return Err(EXIT_M6A2_PAYLOAD);
    }
    if meta.handle_count != 2 {
        return Err(EXIT_M6A2_HANDLES);
    }
    let port_sender = handles[0];
    let shm = handles[1];
    if rights[0] != RIGHT_WRITE || rights[1] != (RIGHT_MAP | RIGHT_READ | RIGHT_WRITE) {
        return Err(EXIT_M6A2_RIGHTS);
    }

    // A2: the write-only end of the subscription channel.
    let len = ipc_recv_message(
        channel,
        &mut data,
        &mut handles,
        &mut rights,
        &mut meta,
        WAIT_TIMEOUT_INFINITE,
    )?;
    if meta.transaction != TX_CHANNEL_SECOND
        || len != CHANNEL_SECOND.len()
        || data[..len] != CHANNEL_SECOND[..]
    {
        return Err(EXIT_M6A2_PAYLOAD);
    }
    if meta.handle_count != 1 {
        return Err(EXIT_M6A2_HANDLES);
    }
    let sub_channel = handles[0];
    if rights[0] != RIGHT_WRITE {
        return Err(EXIT_M6A2_RIGHTS);
    }

    // Receiving from a write-only end must be refused, not silently upgraded.
    if !matches!(
        rt::ipc_recv(
            port_sender,
            &mut data,
            &mut [],
            &mut [],
            &mut meta,
            WAIT_TIMEOUT_IMMEDIATE as u64,
        ),
        Err(ERR_BAD_RIGHT)
    ) {
        return Err(EXIT_M6A2_RIGHTS);
    }

    // A3: the inline-data boundary message arrives intact and in order.
    let len = ipc_recv_message(
        channel,
        &mut data,
        &mut handles,
        &mut rights,
        &mut meta,
        WAIT_TIMEOUT_INFINITE,
    )?;
    if meta.transaction != TX_CHANNEL_BOUNDARY
        || len != CHANNEL_BOUNDARY.len()
        || data[..len] != CHANNEL_BOUNDARY[..]
    {
        return Err(EXIT_M6A2_PAYLOAD);
    }
    write_line(console, M6A_CHANNEL_OK);

    // Port: one message through the write-only sender.
    ipc_send_message(port_sender, PROTO_PORT, TX_PORT, PORT_HELLO, &[], &[])
        .map_err(|_| EXIT_M6A2_PORT)?;
    rt::handle_close(port_sender).map_err(|_| EXIT_M6A2_CLOSE)?;

    // Shm: map through the transferred object, verify init's pattern, answer.
    let (shm_map, alias) = rt::shm_map(shm, &mut ShmMapRequest::new(PROT_READ | PROT_WRITE, 0))
        .map_err(|_| EXIT_M6A2_SHM)?;
    // The futex word at `SHM_FUTEX_OFFSET` is init's zeroed control word, not
    // part of the pattern; every other byte of the 8192-byte object must match.
    for index in 0..SHM_LEN {
        if index >= SHM_FUTEX_OFFSET && index < SHM_FUTEX_OFFSET + 4 {
            continue;
        }
        let expected = map_pattern(index);
        let actual = shm_read(alias, index);
        if actual != expected {
            write_shm_mismatch(console, index, expected, actual);
            return Err(EXIT_M6A2_SHM);
        }
    }
    for (index, byte) in SHM_RESPONSE_MARK.iter().enumerate() {
        shm_write(alias, SHM_RESPONSE_OFFSET + index, *byte);
    }
    ipc_send_message(
        channel,
        PROTO_CHANNEL,
        TX_SHM_MAPPED,
        b"shm-mapped",
        &[],
        &[],
    )?;
    write_line(console, M6A_SHM_OK);

    // Futex: report readiness, then block while the word is still zero. init
    // writes one through its own alias and wakes us; a spurious wake is fine.
    ipc_send_message(
        channel,
        PROTO_CHANNEL,
        TX_FUTEX_READY,
        b"futex-ready",
        &[],
        &[],
    )?;
    rt::futex_wait(alias + SHM_FUTEX_OFFSET, 0, WAIT_TIMEOUT_INFINITE)
        .map_err(|_| EXIT_M6A2_FUTEX)?;
    if shm_read_u32(alias, SHM_FUTEX_OFFSET) != 1 {
        return Err(EXIT_M6A2_FUTEX);
    }
    ipc_send_message(channel, PROTO_CHANNEL, TX_FUTEX_OK, b"futex-ok", &[], &[])?;
    write_line(console, M6A_FUTEX_OK);

    // The port message is delivered before the channel acknowledgement.
    ipc_send_message(channel, PROTO_CHANNEL, TX_PORT_SENT, b"port-sent", &[], &[])?;
    write_line(console, M6A_PORT_OK);

    // Subscriptions: publish exactly one message per go command.
    let _ = ipc_recv_message(
        channel,
        &mut data,
        &mut [],
        &mut [],
        &mut meta,
        WAIT_TIMEOUT_INFINITE,
    )?;
    if meta.transaction != TX_CHANNEL_GO_SUB {
        return Err(EXIT_M6A2_PAYLOAD);
    }
    ipc_send_message(
        sub_channel,
        PROTO_CHANNEL,
        TX_SUB_FIRST,
        SUB_FIRST,
        &[],
        &[],
    )?;
    let _ = ipc_recv_message(
        channel,
        &mut data,
        &mut [],
        &mut [],
        &mut meta,
        WAIT_TIMEOUT_INFINITE,
    )?;
    if meta.transaction != TX_CHANNEL_GO_SUB2 {
        return Err(EXIT_M6A2_PAYLOAD);
    }
    ipc_send_message(
        sub_channel,
        PROTO_CHANNEL,
        TX_SUB_SECOND,
        SUB_SECOND,
        &[],
        &[],
    )?;

    // Hand the Console capability back so init can prove handle transfer works
    // even after the sending process is gone.
    ipc_send_message(
        channel,
        PROTO_CHANNEL,
        TX_LAST,
        b"last",
        &[console],
        &[RIGHT_WRITE],
    )?;

    rt::handle_close(shm_map).map_err(|_| EXIT_M6A2_CLOSE)?;
    rt::handle_close(sub_channel).map_err(|_| EXIT_M6A2_CLOSE)?;
    rt::handle_close(channel).map_err(|_| EXIT_M6A2_CLOSE)?;
    rt::handle_close(shm).map_err(|_| EXIT_M6A2_CLOSE)?;
    Ok(())
}

#[unsafe(no_mangle)]
pub extern "C" fn _start(console: u64, pair: u64, channel: u64) -> ! {
    let console = console as Handle;
    let pair = pair as Handle;
    let channel = channel as Handle;

    write_line(console, CHILD_OK);

    // M5c1: both roots must expose exactly the bytes init wrote, and both must
    // agree on the boot generation (a one-sided file is a failure).
    let fat_first = match verify_file(FAT_FILE) {
        Ok(first) => first,
        Err(code) => rt::process_exit(code),
    };
    let ext2_first = match verify_file(EXT2_FILE) {
        Ok(first) => first,
        Err(code) => rt::process_exit(code),
    };
    if fat_first != ext2_first {
        write_line(console, b"child FAIL files disagree\n");
        rt::process_exit(EXIT_FILES_GENERATION);
    }
    write_line(console, M5C_FILES_OK);

    // M5c2: both roots must expose init's shared writes and must not have
    // persisted init's private write; a writable mapping of a read-only file is
    // refused rather than silently downgraded.
    if let Err(code) = verify_mapping(FAT_MAP) {
        write_line(console, b"child FAIL fat mmap\n");
        rt::process_exit(code);
    }
    if let Err(code) = verify_mapping(EXT2_MAP) {
        write_line(console, b"child FAIL ext2 mmap\n");
        rt::process_exit(code);
    }
    if let Err(code) = expect_writable_mapping_rights_error() {
        write_line(console, b"child FAIL mmap rights\n");
        rt::process_exit(code);
    }
    write_line(console, M5C_MMAP_OK);

    // M5c3: conflict with init's held POSIX lock, confirm OFD/flock are separate
    // domains, and exit with our own POSIX lock held for the reaping path.
    if let Err(code) = lock_step() {
        write_line(console, b"child FAIL locks\n");
        rt::process_exit(code);
    }
    write_line(console, M5C_LOCKS_OK);

    // M6a2: channel/port/shm/futex/subscription handshake with init. This runs
    // before the EventPair wait so init can queue the messages while we are
    // already blocked on the channel.
    if let Err(code) = m6a2_step(console, channel) {
        write_m6a2_failure(console, code);
        rt::process_exit(code);
    }

    // M6a1: init arms a timer and signals this EventPair end afterwards. Blocking
    // here with no timeout is what forces the kernel through its idle path.
    let out = match rt::wait_one(pair, EVENT_PAIR_ENDPOINT_B, WAIT_TIMEOUT_INFINITE) {
        Ok(out) => out,
        Err(_) => {
            write_line(console, b"child FAIL event\n");
            rt::process_exit(EXIT_M6A_EVENT);
        }
    };
    if out.wake_reason != WAKE_READY || !out.is_ready(0) {
        write_line(console, b"child FAIL event state\n");
        rt::process_exit(EXIT_M6A_EVENT_STATE);
    }
    if rt::handle_close(pair).is_err() {
        write_line(console, b"child FAIL event close\n");
        rt::process_exit(EXIT_M6A_EVENT);
    }
    write_line(console, M6A_EVENT_OK);

    let mut probe = [0u8; 8];
    match rt::random_read(INIT_RANDOM_PROBE, &mut probe) {
        Err(ERR_BAD_HANDLE) => write_line(console, HANDLES_OK),
        Err(_) => {
            write_line(console, b"child FAIL handles wrong error\n");
            rt::process_exit(EXIT_HANDLES);
        }
        Ok(_) => {
            write_line(console, b"child FAIL handles inherited\n");
            rt::process_exit(EXIT_HANDLES_INHERITED);
        }
    }

    rt::process_exit(0)
}
