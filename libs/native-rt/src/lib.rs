//! CaelumOS user-mode runtime for the native ABI (0.6, M7b).
//!
//! This crate is the only place in user space that executes the `syscall`
//! instruction. It wraps the raw register convention documented in
//! `docs/abi/native-syscall.md` into typed functions returning
//! `Result<result, status>`:
//!
//! - `rax` = syscall number, `rdi`/`rsi`/`rdx`/`r10`/`r8`/`r9` = arguments;
//! - on return `rax` = status (`0` = OK, non-zero = error code) and
//!   `rdx` = result;
//! - `rcx` and `r11` are clobbered by the hardware and never used as inputs.
//!
//! All wrappers are thin and do not allocate; the runtime defines the panic
//! handler as a `pause` loop because there is nothing sensible to unwind to.
#![no_std]

use native_abi::{
    DirEntryOut, DisplayInfoRequest, DisplayInfoWire, DisplayPresentRequest, ERR_WOULD_BLOCK,
    Handle, IPC_KIND_SHARED_MEMORY, IPC_KIND_SUBSCRIPTION, InputEventWire, InputReadRequest,
    IpcCreateRequest, IpcMessageMeta, IpcReceiveRequest, IpcSendRequest, LockRequest, MmapRequest,
    NR_ABI_QUERY, NR_ACCEPT, NR_BIND, NR_CONNECT, NR_DISPLAY_INFO, NR_DISPLAY_MAP,
    NR_DISPLAY_PRESENT, NR_DUP, NR_FUTEX_WAIT, NR_FUTEX_WAKE, NR_HANDLE_CLOSE, NR_INPUT_READ,
    NR_IPC_CREATE, NR_IPC_RECV, NR_IPC_SEND, NR_IPC_SIGNAL, NR_LISTEN, NR_LOCK, NR_MKDIR, NR_MMAP,
    NR_MPROTECT, NR_MUNMAP, NR_OPEN, NR_PROCESS_CREATE, NR_PROCESS_EXIT, NR_PROCESS_WAIT,
    NR_RANDOM_READ, NR_READ, NR_READDIR, NR_RECV, NR_RENAME, NR_RMDIR, NR_SEEK, NR_SEND,
    NR_SHM_MAP, NR_SHUTDOWN, NR_SOCKET, NR_SOCKET_ADDRESS, NR_SOCKETPAIR, NR_STAT, NR_SUBSCRIBE,
    NR_SUBSCRIPTION_READ, NR_SYNC, NR_TIMER_ARM, NR_TRUNCATE, NR_UNLINK, NR_UNSUBSCRIBE, NR_WAIT,
    NR_WATCH, NR_WATCH_DRAIN, NR_WRITE, NR_XATTR_GET, NR_XATTR_SET, OpenRequest,
    ProcessCreateRequest, RenameRequest, ShmMapRequest, SocketAcceptRequest, SocketAddrRequest,
    SocketAddrWire, SocketAddressRequest, SocketCreateRequest, SocketPairRequest,
    SocketRecvRequest, SocketSendRequest, StatOut, SubscribeRequest, SubscriptionEntry,
    SubscriptionEvent, SubscriptionReadRequest, WaitItem, WaitOut, WaitRequest, WatchDrainRequest,
    WatchEventOut, XattrRequest,
};

/// The raw `(status, result)` pair returned by the syscall instruction.
///
/// Both registers are 64-bit; the ABI never reuses them for sign-extension of
/// small values.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SyscallResult {
    pub status: u64,
    pub result: u64,
}

impl SyscallResult {
    /// `Ok(result)` when the kernel reported success, `Err(status)` otherwise.
    pub const fn into_result(self) -> Result<u64, u64> {
        if self.status == native_abi::STATUS_OK {
            Ok(self.result)
        } else {
            Err(self.status)
        }
    }
}

/// Status of the most recent syscall, kept as a diagnostics breadcrumb.
///
/// This is the only writable state in the runtime: it also guarantees that
/// every user image has a writable section and therefore a writable PT_LOAD
/// segment, so a loader can map each segment strictly by its permissions.
static mut LAST_STATUS: u64 = 0;

/// Status of the most recent syscall (`0` = OK). Useful when a caller only
/// keeps the `Err` case minimally and wants the exact code later.
pub fn last_status() -> u64 {
    unsafe { LAST_STATUS }
}

/// Issues one native syscall.
///
/// # Safety
///
/// The caller must uphold the ABI contract of the selected syscall: pointers
/// must reference memory the calling process may access for the duration of
/// the call, and `nr` must be a defined syscall number.
#[inline(always)]
pub unsafe fn syscall(
    nr: u64,
    a0: u64,
    a1: u64,
    a2: u64,
    a3: u64,
    a4: u64,
    a5: u64,
) -> SyscallResult {
    let status: u64;
    let result: u64;
    // `rdx` is the third argument *and* the result register, hence `inlateout`.
    // `rcx`/`r11` hold the return RIP/RFLAGS after `syscall` and are clobbered.
    // No `nomem`: the call may read and write the caller's buffers.
    unsafe {
        core::arch::asm!(
            "syscall",
            inlateout("rax") nr => status,
            in("rdi") a0,
            in("rsi") a1,
            inlateout("rdx") a2 => result,
            in("r10") a3,
            in("r8") a4,
            in("r9") a5,
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack),
        );
        LAST_STATUS = status;
    }
    SyscallResult { status, result }
}

/// Queries the native ABI version word: `(major << 16) | minor`.
pub fn abi_query() -> Result<u32, u64> {
    let raw = unsafe { syscall(NR_ABI_QUERY, 0, 0, 0, 0, 0, 0) };
    raw.into_result().map(|version| version as u32)
}

/// Writes `buffer` to the stream-like object behind `handle`.
///
/// The kernel copies the bytes before returning; a short write is reported
/// through `result` (bytes written) rather than as an error.
pub fn write(handle: Handle, buffer: &[u8]) -> Result<u64, u64> {
    let raw = unsafe {
        syscall(
            NR_WRITE,
            handle as u64,
            buffer.as_ptr() as u64,
            buffer.len() as u64,
            0,
            0,
            0,
        )
    };
    raw.into_result()
}

/// Creates a child process from the startup module named in `request`,
/// transferring the listed handles. Returns the child's process handle.
pub fn process_create(request: &ProcessCreateRequest) -> Result<Handle, u64> {
    let raw = unsafe {
        syscall(
            NR_PROCESS_CREATE,
            request as *const ProcessCreateRequest as u64,
            0,
            0,
            0,
            0,
            0,
        )
    };
    raw.into_result().map(|handle| handle as Handle)
}

/// Non-blocking wait on a child process.
///
/// `Ok(exit_status)` means the child has exited; `Err(ERR_WOULD_BLOCK)` means
/// it is still running and the caller must retry (see [`wait`]).
pub fn process_wait(child: Handle) -> Result<u64, u64> {
    let raw = unsafe { syscall(NR_PROCESS_WAIT, child as u64, 0, 0, 0, 0, 0) };
    raw.into_result()
}

/// Terminates the calling process with `status`. Never returns.
pub fn process_exit(status: u64) -> ! {
    unsafe {
        syscall(NR_PROCESS_EXIT, status, 0, 0, 0, 0, 0);
    }
    // The kernel must never return from process_exit. If it does, trap instead
    // of running off the end of the entry point.
    unsafe { core::arch::asm!("ud2", options(noreturn)) }
}

/// Fills `buffer` with cryptographically secure random bytes.
///
/// `Err(ERR_NO_ENTROPY)` means the CRNG is not ready; the caller decides
/// whether that is fatal (M4 init treats it as a successful, expected answer).
pub fn random_read(handle: Handle, buffer: &mut [u8]) -> Result<u64, u64> {
    let raw = unsafe {
        syscall(
            NR_RANDOM_READ,
            handle as u64,
            buffer.as_mut_ptr() as u64,
            buffer.len() as u64,
            0,
            0,
            0,
        )
    };
    raw.into_result()
}

/// Closes a handle in the caller's handle table.
pub fn handle_close(handle: Handle) -> Result<(), u64> {
    let raw = unsafe { syscall(NR_HANDLE_CLOSE, handle as u64, 0, 0, 0, 0, 0) };
    raw.into_result().map(|_| ())
}

// ---------------------------------------------------------------------------
// ABI 0.2 file and directory calls (M5c1).
//
// Every path and every result structure is a caller-owned buffer: the kernel
// copies the request in and the result out, so no pointer is retained after
// the syscall returns.
// ---------------------------------------------------------------------------

/// Opens `path` with `flags` (`OPEN_*` bits) and returns a file handle.
pub fn open(path: &[u8], flags: u32) -> Result<Handle, u64> {
    let request = OpenRequest::new(path.as_ptr() as u64, path.len() as u32, flags);
    let raw = unsafe {
        syscall(
            NR_OPEN,
            &request as *const OpenRequest as u64,
            0,
            0,
            0,
            0,
            0,
        )
    };
    raw.into_result().map(|handle| handle as Handle)
}

/// Reads at most `buffer.len()` bytes from `handle`; returns bytes read.
///
/// A short read is not an error: `0` means end of file.
pub fn read(handle: Handle, buffer: &mut [u8]) -> Result<u64, u64> {
    let raw = unsafe {
        syscall(
            NR_READ,
            handle as u64,
            buffer.as_mut_ptr() as u64,
            buffer.len() as u64,
            0,
            0,
            0,
        )
    };
    raw.into_result()
}

/// Stats `handle` into `out`.
pub fn stat(handle: Handle, out: &mut StatOut) -> Result<(), u64> {
    let raw = unsafe {
        syscall(
            NR_STAT,
            handle as u64,
            out as *mut StatOut as u64,
            0,
            0,
            0,
            0,
        )
    };
    raw.into_result().map(|_| ())
}

/// Reads directory entry `index` of the directory behind `handle` into `out`.
///
/// `Err(ERR_NOT_FOUND)` means the index is past the last entry.
pub fn readdir(handle: Handle, index: u64, out: &mut DirEntryOut) -> Result<(), u64> {
    let raw = unsafe {
        syscall(
            NR_READDIR,
            handle as u64,
            index,
            out as *mut DirEntryOut as u64,
            0,
            0,
            0,
        )
    };
    raw.into_result().map(|_| ())
}

/// Creates the directory at `path`.
pub fn mkdir(path: &[u8]) -> Result<(), u64> {
    let raw = unsafe {
        syscall(
            NR_MKDIR,
            path.as_ptr() as u64,
            path.len() as u64,
            0,
            0,
            0,
            0,
        )
    };
    raw.into_result().map(|_| ())
}

/// Removes the empty directory at `path`.
pub fn rmdir(path: &[u8]) -> Result<(), u64> {
    let raw = unsafe {
        syscall(
            NR_RMDIR,
            path.as_ptr() as u64,
            path.len() as u64,
            0,
            0,
            0,
            0,
        )
    };
    raw.into_result().map(|_| ())
}

/// Removes the file (or empty directory) at `path`.
pub fn unlink(path: &[u8]) -> Result<(), u64> {
    let raw = unsafe {
        syscall(
            NR_UNLINK,
            path.as_ptr() as u64,
            path.len() as u64,
            0,
            0,
            0,
            0,
        )
    };
    raw.into_result().map(|_| ())
}

/// Renames `old` to `new` within the same mount.
pub fn rename(old: &[u8], new: &[u8]) -> Result<(), u64> {
    let request = RenameRequest::new(
        old.as_ptr() as u64,
        old.len() as u32,
        new.as_ptr() as u64,
        new.len() as u32,
    );
    let raw = unsafe {
        syscall(
            NR_RENAME,
            &request as *const RenameRequest as u64,
            0,
            0,
            0,
            0,
            0,
        )
    };
    raw.into_result().map(|_| ())
}

/// Flushes the file behind `handle` to stable storage.
pub fn sync(handle: Handle) -> Result<(), u64> {
    let raw = unsafe { syscall(NR_SYNC, handle as u64, 0, 0, 0, 0, 0) };
    raw.into_result().map(|_| ())
}

/// Moves the offset of `handle` to `offset` relative to `whence`
/// ([`native_abi::SEEK_SET`], [`native_abi::SEEK_CUR`], [`native_abi::SEEK_END`]).
///
/// Returns the resulting absolute offset.
pub fn seek(handle: Handle, offset: i64, whence: u32) -> Result<u64, u64> {
    let raw = unsafe {
        syscall(
            NR_SEEK,
            handle as u64,
            offset as u64,
            whence as u64,
            0,
            0,
            0,
        )
    };
    raw.into_result()
}

/// Duplicates `handle`, keeping at most `rights` (`RIGHT_*` bits).
pub fn dup(handle: Handle, rights: u32) -> Result<Handle, u64> {
    let raw = unsafe { syscall(NR_DUP, handle as u64, rights as u64, 0, 0, 0, 0) };
    raw.into_result().map(|handle| handle as Handle)
}

/// Truncates the file behind `handle` to `length` bytes.
pub fn truncate(handle: Handle, length: u64) -> Result<(), u64> {
    let raw = unsafe { syscall(NR_TRUNCATE, handle as u64, length, 0, 0, 0, 0) };
    raw.into_result().map(|_| ())
}

/// Maps part of the file behind `handle` into the caller's address space.
///
/// `request` carries `len`, `offset`, `prot` ([`native_abi::PROT_READ`] /
/// [`native_abi::PROT_WRITE`]) and `flags` ([`native_abi::MMAP_SHARED`] /
/// [`native_abi::MMAP_PRIVATE`]). This wrapper fills in `size`/`version` and
/// points `out_address` at a local `u64`, then returns the mapping handle and
/// the base address the kernel copied out.
///
/// The mapping lives until `munmap`, until the returned handle is closed, or
/// until the process exits. Closing the handle unmaps the range; `munmap` also
/// closes the handle.
pub fn mmap(file: Handle, request: &mut MmapRequest) -> Result<(Handle, usize), u64> {
    let mut base = 0u64;
    request.size = MmapRequest::SIZE;
    request.version = native_abi::REQUEST_VERSION;
    request.out_address = core::ptr::addr_of_mut!(base) as u64;
    let raw = unsafe {
        syscall(
            NR_MMAP,
            file as u64,
            request as *mut MmapRequest as u64,
            0,
            0,
            0,
            0,
        )
    };
    let handle = raw.into_result()?;
    Ok((handle as Handle, base as usize))
}

/// Removes the mapping that starts at `address` and spans `length` bytes,
/// closing the mapping handle the kernel kept for it.
pub fn munmap(address: usize, length: usize) -> Result<(), u64> {
    let raw = unsafe { syscall(NR_MUNMAP, address as u64, length as u64, 0, 0, 0, 0) };
    raw.into_result().map(|_| ())
}

/// Changes the protection of the mapping at `address` to `prot` (`PROT_*`).
pub fn mprotect(address: usize, length: usize, prot: u32) -> Result<(), u64> {
    let raw = unsafe {
        syscall(
            NR_MPROTECT,
            address as u64,
            length as u64,
            prot as u64,
            0,
            0,
            0,
        )
    };
    raw.into_result().map(|_| ())
}

/// Acquires, converts or releases the file lock described by `request`.
///
/// Locks are non-blocking in ABI 0.2: a conflicting request fails with
/// [`native_abi::ERR_WOULD_BLOCK`] instead of sleeping. This wrapper fills in
/// `size`/`version`; callers set `domain` ([`native_abi::LOCK_DOMAIN_POSIX`] /
/// [`native_abi::LOCK_DOMAIN_OFD`] / [`native_abi::LOCK_DOMAIN_FLOCK`]),
/// `operation` and the byte range. `flock` locks only accept `offset = 0,
/// len = 0`; POSIX/OFD accept `len = 0` as "to end of file".
pub fn lock(handle: Handle, request: &mut LockRequest) -> Result<(), u64> {
    request.size = LockRequest::SIZE;
    request.version = native_abi::REQUEST_VERSION;
    let raw = unsafe {
        syscall(
            NR_LOCK,
            handle as u64,
            request as *mut LockRequest as u64,
            0,
            0,
            0,
            0,
        )
    };
    raw.into_result().map(|_| ())
}

/// Sets the extended attribute described by `request` on `handle`.
///
/// Only names in the `user.` namespace are accepted; the value is copied in
/// from user memory. File systems that do not store attributes answer
/// `ERR_NOT_SUPPORTED`, and exceeding a per-file attribute quota answers
/// `ERR_QUOTA`.
pub fn xattr_set(handle: Handle, request: &mut XattrRequest) -> Result<(), u64> {
    request.size = XattrRequest::SIZE;
    request.version = native_abi::REQUEST_VERSION;
    let raw = unsafe {
        syscall(
            NR_XATTR_SET,
            handle as u64,
            request as *mut XattrRequest as u64,
            0,
            0,
            0,
            0,
        )
    };
    raw.into_result().map(|_| ())
}

/// Reads the extended attribute described by `request` from `handle`.
///
/// The kernel writes at most `request.value_len` bytes to the value buffer and
/// returns the real attribute length. A buffer that is too small fails with
/// `ERR_TOO_LARGE` and is left untouched.
pub fn xattr_get(handle: Handle, request: &mut XattrRequest) -> Result<usize, u64> {
    request.size = XattrRequest::SIZE;
    request.version = native_abi::REQUEST_VERSION;
    let raw = unsafe {
        syscall(
            NR_XATTR_GET,
            handle as u64,
            request as *mut XattrRequest as u64,
            0,
            0,
            0,
            0,
        )
    };
    Ok(raw.into_result()? as usize)
}

/// Starts watching the directory at `path` and returns the watch handle.
///
/// The watch keeps the directory's identity, not its path. Events are queued
/// per watch; `watch_drain` empties the queue. Dropping the handle stops the
/// watch at the next reap point.
pub fn watch(path: &[u8]) -> Result<Handle, u64> {
    let raw = unsafe {
        syscall(
            NR_WATCH,
            path.as_ptr() as u64,
            path.len() as u64,
            0,
            0,
            0,
            0,
        )
    };
    let handle = raw.into_result()?;
    Ok(handle as Handle)
}

/// Drains up to `out.len()` pending events from `watch` into `out`.
///
/// Returns how many records the kernel wrote. Each record carries that watch's
/// cumulative overflow count in `dropped`, so a caller can notice lost events
/// even when the queue is drained in batches.
pub fn watch_drain(watch: Handle, out: &mut [WatchEventOut]) -> Result<usize, u64> {
    let request = WatchDrainRequest::new(out.as_mut_ptr() as u64, out.len() as u64);
    let raw = unsafe {
        syscall(
            NR_WATCH_DRAIN,
            watch as u64,
            &request as *const WatchDrainRequest as u64,
            0,
            0,
            0,
            0,
        )
    };
    Ok(raw.into_result()? as usize)
}

/// Creates one IPC object and returns its handle.
///
/// `request.kind` selects the object (`Event`, `EventPair` or `Timer` in ABI
/// 0.3); the other kinds are frozen but answer `NOT_SUPPORTED` until a later
/// M6 slice. The kernel returns the new handle in `rdx`.
pub fn ipc_create(request: &IpcCreateRequest) -> Result<Handle, u64> {
    let raw = unsafe {
        syscall(
            NR_IPC_CREATE,
            request as *const IpcCreateRequest as u64,
            0,
            0,
            0,
            0,
            0,
        )
    };
    Ok(raw.into_result()? as Handle)
}

/// Creates one IPC object of `kind` with `flags` and `arg0`/`arg1`.
pub fn ipc_create_kind(kind: u32, flags: u32, arg0: u64, arg1: u64) -> Result<Handle, u64> {
    let request = IpcCreateRequest::new(kind, flags, arg0, arg1);
    ipc_create(&request)
}

/// Resets (`SIGNAL_OP_RESET`) or signals (`SIGNAL_OP_SIGNAL`) a waitable object.
///
/// `endpoint` selects the `EventPair` end and must be 0 for every other object
/// kind. The endpoint travels in `rdx` as an input, so this call has no result
/// value besides its status.
pub fn ipc_signal(object: Handle, operation: u32, endpoint: u32) -> Result<(), u64> {
    let raw = unsafe {
        syscall(
            NR_IPC_SIGNAL,
            object as u64,
            operation as u64,
            endpoint as u64,
            0,
            0,
            0,
        )
    };
    raw.into_result().map(|_| ())
}

/// Waits on the items of `request` and writes the outcome to `out`.
///
/// The wrapper fills `size`, `version` and `out_ptr`, so callers only add items
/// and a timeout. Returns the number of ready items (the kernel's `rdx`).
///
/// Named `wait_objects` to stay distinct from the legacy [`wait`] alias of
/// [`process_wait`], which keeps its M4 meaning.
pub fn wait_objects(request: &mut WaitRequest, out: &mut WaitOut) -> Result<usize, u64> {
    request.size = WaitRequest::SIZE;
    request.version = native_abi::REQUEST_VERSION;
    request.out_ptr = out as *mut WaitOut as u64;
    let raw = unsafe { syscall(NR_WAIT, request as *const WaitRequest as u64, 0, 0, 0, 0, 0) };
    Ok(raw.into_result()? as usize)
}

/// Waits on exactly one object with `key` and `timeout_ticks`.
///
/// Returns the output record; the caller inspects `wake_reason`/`ready_mask`
/// to tell a real wakeup from a timeout.
pub fn wait_one(object: Handle, key: u32, timeout_ticks: u32) -> Result<WaitOut, u64> {
    let mut out = WaitOut::empty();
    let mut request = WaitRequest::new(0, timeout_ticks);
    if !request.push(WaitItem::new(object, key)) {
        return Err(native_abi::ERR_BAD_REQUEST);
    }
    wait_objects(&mut request, &mut out)?;
    Ok(out)
}

/// Arms a one-shot timer for `ticks` scheduling ticks; `flags` must be 0.
pub fn timer_arm(timer: Handle, ticks: u32, flags: u32) -> Result<(), u64> {
    let raw = unsafe {
        syscall(
            NR_TIMER_ARM,
            timer as u64,
            ticks as u64,
            flags as u64,
            0,
            0,
            0,
        )
    };
    raw.into_result().map(|_| ())
}

// ---------------------------------------------------------------------------
// M6a2: channels, ports, shared memory, futexes and subscriptions
// ---------------------------------------------------------------------------

/// Creates a `Channel` or `Port` pair and returns `(first, second)`.
///
/// For a `Channel` the first handle is endpoint A and the second endpoint B;
/// for a `Port` the first handle is the receiver and the second the sender.
/// The second handle is captured through
/// [`IpcCreateRequest::out_second_ptr`], never through a bare register.
pub fn ipc_create_pair(kind: u32, flags: u32) -> Result<(Handle, Handle), u64> {
    let mut second: u64 = 0;
    let request =
        IpcCreateRequest::new_pair(kind, flags, 0, 0, core::ptr::addr_of_mut!(second) as u64);
    let first = ipc_create(&request)?;
    if second == 0 {
        return Err(native_abi::ERR_IO);
    }
    Ok((first, second as Handle))
}

/// Creates a shared-memory object of `length` bytes and returns its handle.
pub fn ipc_create_shm(length: usize) -> Result<Handle, u64> {
    ipc_create_kind(IPC_KIND_SHARED_MEMORY, 0, length as u64, 0)
}

/// Creates an empty event subscription; add interests with [`subscribe`].
pub fn ipc_create_subscription() -> Result<Handle, u64> {
    ipc_create_kind(IPC_KIND_SUBSCRIPTION, 0, 0, 0)
}

/// Queues one message on `handle` (a channel end or a port sender).
///
/// The wrapper fills `size`/`version`; the caller sets `data_ptr`/`data_len`
/// and, when transferring handles, `handles_ptr`/`rights_ptr`/`handle_count`.
/// Returns the payload length the kernel accepted (equal to `data_len`).
pub fn ipc_send(handle: Handle, request: &mut IpcSendRequest) -> Result<usize, u64> {
    request.size = IpcSendRequest::SIZE;
    request.version = native_abi::REQUEST_VERSION;
    let raw = unsafe {
        syscall(
            NR_IPC_SEND,
            handle as u64,
            request as *mut IpcSendRequest as u64,
            0,
            0,
            0,
            0,
        )
    };
    Ok(raw.into_result()? as usize)
}

/// Receives one message from `handle` into the caller's buffers.
///
/// Returns the received payload length. Transferred handles are written as new
/// `u32` handle numbers into `handles` and their rights into `rights`; the
/// message routing metadata is written to `meta`. A payload that does not fit
/// `data.len()` fails with `ERR_TOO_LARGE` and keeps the message queued.
pub fn ipc_recv(
    handle: Handle,
    data: &mut [u8],
    handles: &mut [Handle],
    rights: &mut [u32],
    meta: &mut IpcMessageMeta,
    timeout_ticks: u64,
) -> Result<usize, u64> {
    let capacity = handles.len().min(rights.len());
    let mut request = IpcReceiveRequest::new(
        data.as_mut_ptr() as u64,
        data.len() as u32,
        meta as *mut IpcMessageMeta as u64,
        timeout_ticks,
    );
    request.handle_capacity = capacity as u32;
    request.out_handles_ptr = handles.as_mut_ptr() as u64;
    request.out_rights_ptr = rights.as_mut_ptr() as u64;
    let raw = unsafe {
        syscall(
            NR_IPC_RECV,
            handle as u64,
            &mut request as *mut IpcReceiveRequest as u64,
            0,
            0,
            0,
            0,
        )
    };
    Ok(raw.into_result()? as usize)
}

/// Maps the whole shared-memory object `shm` and returns `(mapping, address)`.
///
/// The returned handle is the mapping object; closing it unmaps the range.
/// `request.prot` is a [`native_abi::PROT_*`] mask the object's rights allow.
pub fn shm_map(shm: Handle, request: &mut ShmMapRequest) -> Result<(Handle, usize), u64> {
    let mut base: u64 = 0;
    request.size = ShmMapRequest::SIZE;
    request.version = native_abi::REQUEST_VERSION;
    request.out_address = core::ptr::addr_of_mut!(base) as u64;
    let raw = unsafe {
        syscall(
            NR_SHM_MAP,
            shm as u64,
            request as *mut ShmMapRequest as u64,
            0,
            0,
            0,
            0,
        )
    };
    let mapping = raw.into_result()? as Handle;
    Ok((mapping, base as usize))
}

/// Fills `out` with the display description (M6c).
///
/// `shadow_bytes` is the length of the RAM shadow that [`display_map`] maps;
/// nothing written there reaches the framebuffer until [`display_present`].
pub fn display_info(display: Handle, out: &mut DisplayInfoWire) -> Result<(), u64> {
    let mut request = DisplayInfoRequest::new(core::ptr::addr_of_mut!(*out) as u64);
    request.size = DisplayInfoRequest::SIZE;
    request.version = native_abi::REQUEST_VERSION;
    let raw = unsafe {
        syscall(
            NR_DISPLAY_INFO,
            display as u64,
            &mut request as *mut DisplayInfoRequest as u64,
            0,
            0,
            0,
            0,
        )
    };
    raw.into_result().map(|_| ())
}

/// Maps the display RAM shadow and returns `(mapping, address)` (M6c).
///
/// The returned handle is the mapping object; closing it unmaps the range.
/// `request.prot` is a [`native_abi::PROT_*`] mask the display handle's rights
/// allow; the mapping is plain RAM and never the framebuffer.
pub fn display_map(display: Handle, request: &mut ShmMapRequest) -> Result<(Handle, usize), u64> {
    let mut base: u64 = 0;
    request.size = ShmMapRequest::SIZE;
    request.version = native_abi::REQUEST_VERSION;
    request.out_address = core::ptr::addr_of_mut!(base) as u64;
    let raw = unsafe {
        syscall(
            NR_DISPLAY_MAP,
            display as u64,
            request as *mut ShmMapRequest as u64,
            0,
            0,
            0,
            0,
        )
    };
    let mapping = raw.into_result()? as Handle;
    Ok((mapping, base as usize))
}

/// Copies the whole display RAM shadow to the framebuffer (M6c).
///
/// ABI 0.5 accepts only the full-frame `(0, 0, 320, 200)` present, so this
/// wrapper takes no rectangle arguments and cannot express a partial present.
pub fn display_present(display: Handle) -> Result<(), u64> {
    let mut request = DisplayPresentRequest::new();
    request.size = DisplayPresentRequest::SIZE;
    request.version = native_abi::REQUEST_VERSION;
    let raw = unsafe {
        syscall(
            NR_DISPLAY_PRESENT,
            display as u64,
            &mut request as *mut DisplayPresentRequest as u64,
            0,
            0,
            0,
            0,
        )
    };
    raw.into_result().map(|_| ())
}

/// Drains up to `out.len()` queued input events (M6c); returns the count.
///
/// This is a non-blocking read: with no queued event it returns `Ok(0)`. To
/// block, wait on the input handle with [`wait_one`] first and read afterwards.
pub fn input_read(input: Handle, out: &mut [InputEventWire]) -> Result<usize, u64> {
    let mut request = InputReadRequest::new(out.len() as u32, out.as_mut_ptr() as u64);
    request.size = InputReadRequest::SIZE;
    request.version = native_abi::REQUEST_VERSION;
    let raw = unsafe {
        syscall(
            NR_INPUT_READ,
            input as u64,
            &mut request as *mut InputReadRequest as u64,
            0,
            0,
            0,
            0,
        )
    };
    Ok(raw.into_result()? as usize)
}

/// Adds the interests in `entries` to an existing subscription.
///
/// Returns how many interests were added (the kernel's `rdx`).
pub fn subscribe(subscription: Handle, entries: &[SubscriptionEntry]) -> Result<usize, u64> {
    let mut request = SubscribeRequest::new(entries.as_ptr() as u64, entries.len() as u32);
    request.size = SubscribeRequest::SIZE;
    request.version = native_abi::REQUEST_VERSION;
    let raw = unsafe {
        syscall(
            NR_SUBSCRIBE,
            subscription as u64,
            &mut request as *mut SubscribeRequest as u64,
            0,
            0,
            0,
            0,
        )
    };
    Ok(raw.into_result()? as usize)
}

/// Removes every interest in `target` from `subscription`; returns how many
/// interests were removed.
pub fn unsubscribe(subscription: Handle, target: Handle) -> Result<usize, u64> {
    let raw = unsafe {
        syscall(
            NR_UNSUBSCRIBE,
            subscription as u64,
            target as u64,
            0,
            0,
            0,
            0,
        )
    };
    Ok(raw.into_result()? as usize)
}

/// Drains up to `out.len()` readiness events from `subscription`.
pub fn subscription_read(
    subscription: Handle,
    out: &mut [SubscriptionEvent],
) -> Result<usize, u64> {
    let mut request = SubscriptionReadRequest::new(out.len() as u32, out.as_mut_ptr() as u64);
    request.size = SubscriptionReadRequest::SIZE;
    request.version = native_abi::REQUEST_VERSION;
    let raw = unsafe {
        syscall(
            NR_SUBSCRIPTION_READ,
            subscription as u64,
            &mut request as *mut SubscriptionReadRequest as u64,
            0,
            0,
            0,
            0,
        )
    };
    Ok(raw.into_result()? as usize)
}

// ---------------------------------------------------------------------------
// M7b: sockets (ABI 0.6)
//
// The wrappers freeze the request layouts and the register convention only;
// the kernel network engine is delivered separately. Every call is
// non-blocking and reports `ERR_WOULD_BLOCK` instead of sleeping, so callers
// wait with [`wait_one`] / [`wait_objects`] between attempts.
// ---------------------------------------------------------------------------

/// Creates a socket (M7b); returns its handle.
///
/// `namespace_handle` names the network namespace for a UNIX-domain named
/// socket; pass [`native_abi::HANDLE_NONE`] when none is required.
pub fn socket_create(domain: u32, kind: u32, namespace_handle: Handle) -> Result<Handle, u64> {
    let mut request = SocketCreateRequest::new(domain, kind, namespace_handle);
    request.size = SocketCreateRequest::SIZE;
    request.version = native_abi::REQUEST_VERSION;
    // No input handle: like `process_create`/`ipc_create`, a request-only call
    // passes its request pointer in `rdi` and leaves the remaining registers 0.
    let raw = unsafe {
        syscall(
            NR_SOCKET,
            &mut request as *mut SocketCreateRequest as u64,
            0,
            0,
            0,
            0,
            0,
        )
    };
    Ok(raw.into_result()? as Handle)
}

/// Shared body of `bind`/`connect`: both pass one [`SocketAddrWire`] by
/// pointer and return no result.
fn socket_addr_call(nr: u64, socket: Handle, address: &SocketAddrWire) -> Result<(), u64> {
    let mut request = SocketAddrRequest::new(address as *const SocketAddrWire as u64);
    request.size = SocketAddrRequest::SIZE;
    request.version = native_abi::REQUEST_VERSION;
    let raw = unsafe {
        syscall(
            nr,
            socket as u64,
            &mut request as *mut SocketAddrRequest as u64,
            0,
            0,
            0,
            0,
        )
    };
    raw.into_result().map(|_| ())
}

/// Binds a socket to `address` (M7b).
pub fn socket_bind(socket: Handle, address: &SocketAddrWire) -> Result<(), u64> {
    socket_addr_call(NR_BIND, socket, address)
}

/// Starts connecting `socket` to `address` (M7b).
///
/// Non-blocking: `ERR_WOULD_BLOCK` means the connection is still in progress;
/// wait on the socket and retry, or query the peer with [`socket_address`].
pub fn socket_connect(socket: Handle, address: &SocketAddrWire) -> Result<(), u64> {
    socket_addr_call(NR_CONNECT, socket, address)
}

/// Marks a stream socket as accepting connections (M7b); `backlog` is passed
/// in `rsi` and is not part of a request structure.
pub fn socket_listen(socket: Handle, backlog: u32) -> Result<(), u64> {
    let raw = unsafe { syscall(NR_LISTEN, socket as u64, backlog as u64, 0, 0, 0, 0) };
    raw.into_result().map(|_| ())
}

/// Accepts one pending connection (M7b); returns the new peer handle.
///
/// Non-blocking: `ERR_WOULD_BLOCK` when nothing is pending, so wait on the
/// listening socket first. The kernel writes the handle to `out_handle_ptr`
/// and returns it in `rdx`; the wrapper returns `rdx`.
pub fn socket_accept(socket: Handle) -> Result<Handle, u64> {
    let mut out: u32 = native_abi::HANDLE_NONE;
    let mut request = SocketAcceptRequest::new(&mut out as *mut u32 as u64);
    request.size = SocketAcceptRequest::SIZE;
    request.version = native_abi::REQUEST_VERSION;
    let raw = unsafe {
        syscall(
            NR_ACCEPT,
            socket as u64,
            &mut request as *mut SocketAcceptRequest as u64,
            0,
            0,
            0,
            0,
        )
    };
    Ok(raw.into_result()? as Handle)
}

/// Sends `data` (M7b); returns how many bytes were accepted.
///
/// A full queue reports `ERR_WOULD_BLOCK` without consuming data.
pub fn socket_send(socket: Handle, data: &[u8]) -> Result<usize, u64> {
    let mut request = SocketSendRequest::new(data.as_ptr() as u64, data.len() as u32);
    request.size = SocketSendRequest::SIZE;
    request.version = native_abi::REQUEST_VERSION;
    let raw = unsafe {
        syscall(
            NR_SEND,
            socket as u64,
            &mut request as *mut SocketSendRequest as u64,
            0,
            0,
            0,
            0,
        )
    };
    Ok(raw.into_result()? as usize)
}

/// Receives into `buffer` (M7b); returns how many bytes were received.
///
/// Never blocks: `ERR_WOULD_BLOCK` means nothing is queued (a `0` byte count
/// would mean a zero-length datagram), so wait on the socket first. When
/// `source` is `Some`, the kernel writes the datagram source (or stream peer)
/// address into it.
pub fn socket_recv(
    socket: Handle,
    buffer: &mut [u8],
    source: Option<&mut SocketAddrWire>,
) -> Result<usize, u64> {
    let mut request = SocketRecvRequest::new(buffer.as_mut_ptr() as u64, buffer.len() as u32);
    request.size = SocketRecvRequest::SIZE;
    request.version = native_abi::REQUEST_VERSION;
    request.out_source_ptr = match source {
        Some(address) => address as *mut SocketAddrWire as u64,
        None => 0,
    };
    let raw = unsafe {
        syscall(
            NR_RECV,
            socket as u64,
            &mut request as *mut SocketRecvRequest as u64,
            0,
            0,
            0,
            0,
        )
    };
    Ok(raw.into_result()? as usize)
}

/// Shuts down part of `socket` (M7b); `how` is
/// [`native_abi::SOCKET_SHUTDOWN_READ`], `_WRITE` or `_BOTH`, passed in `rsi`.
pub fn socket_shutdown(socket: Handle, how: u32) -> Result<(), u64> {
    let raw = unsafe { syscall(NR_SHUTDOWN, socket as u64, how as u64, 0, 0, 0, 0) };
    raw.into_result().map(|_| ())
}

/// Creates an anonymous, already-connected socket pair (M7b).
///
/// `domain` must be [`native_abi::SOCKET_DOMAIN_UNIX`] in ABI 0.6. On success
/// both handles are valid; a failure creates neither.
pub fn socketpair(domain: u32, kind: u32) -> Result<(Handle, Handle), u64> {
    let mut handles = [native_abi::HANDLE_NONE; 2];
    let mut request = SocketPairRequest::new(domain, kind, handles.as_mut_ptr() as u64);
    request.size = SocketPairRequest::SIZE;
    request.version = native_abi::REQUEST_VERSION;
    // No input handle: the request pointer travels in `rdi`, like the other
    // request-only syscalls (`process_create`, `ipc_create`).
    let raw = unsafe {
        syscall(
            NR_SOCKETPAIR,
            &mut request as *mut SocketPairRequest as u64,
            0,
            0,
            0,
            0,
            0,
        )
    };
    raw.into_result()?;
    Ok((handles[0], handles[1]))
}

/// Writes the socket's local or peer address into `out` (M7b); `which` is
/// [`native_abi::SOCKET_ADDR_LOCAL`] or `_PEER`.
pub fn socket_address(socket: Handle, which: u32, out: &mut SocketAddrWire) -> Result<(), u64> {
    let mut request = SocketAddressRequest::new(which, out as *mut SocketAddrWire as u64);
    request.size = SocketAddressRequest::SIZE;
    request.version = native_abi::REQUEST_VERSION;
    let raw = unsafe {
        syscall(
            NR_SOCKET_ADDRESS,
            socket as u64,
            &mut request as *mut SocketAddressRequest as u64,
            0,
            0,
            0,
            0,
        )
    };
    raw.into_result().map(|_| ())
}

/// Atomically checks `*address == expected` and, when equal, sleeps until a
/// matching [`futex_wake`].
///
/// `timeout_ticks` uses [`native_abi::WAIT_TIMEOUT_IMMEDIATE`] (return
/// `WOULD_BLOCK` at once when the value differs) and
/// [`native_abi::WAIT_TIMEOUT_INFINITE`]. A wakeup returns `Ok(())` even when
/// the value changed meanwhile (spurious wakeups are allowed); only a timeout
/// reports `ERR_TIMEOUT`.
pub fn futex_wait(address: usize, expected: u32, timeout_ticks: u32) -> Result<(), u64> {
    let raw = unsafe {
        syscall(
            NR_FUTEX_WAIT,
            address as u64,
            expected as u64,
            timeout_ticks as u64,
            0,
            0,
            0,
        )
    };
    raw.into_result().map(|_| ())
}

/// Wakes up to `max` waiters of the futex at `address`; returns the count.
pub fn futex_wake(address: usize, max: u32) -> Result<usize, u64> {
    let raw = unsafe { syscall(NR_FUTEX_WAKE, address as u64, max as u64, 0, 0, 0, 0) };
    Ok(raw.into_result()? as usize)
}

/// Writes all of `bytes` with `write`, retrying on short writes.
pub fn write_all(handle: Handle, bytes: &[u8]) -> Result<(), u64> {
    let mut written = 0usize;
    while written < bytes.len() {
        let n = write(handle, &bytes[written..])? as usize;
        if n == 0 {
            return Err(native_abi::ERR_IO);
        }
        written += n;
    }
    Ok(())
}

/// Reads until `buffer` is full or the file ends; returns the bytes read.
pub fn read_all(handle: Handle, buffer: &mut [u8]) -> Result<usize, u64> {
    let mut filled = 0usize;
    while filled < buffer.len() {
        let n = read(handle, &mut buffer[filled..])? as usize;
        if n == 0 {
            break;
        }
        filled += n;
    }
    Ok(filled)
}

/// CPU hint for a short wait: lets the core (and a timer interrupt) make
/// progress instead of hammering the pipeline.
#[inline(always)]
pub fn pause() {
    unsafe { core::arch::asm!("pause", options(nomem, nostack)) }
}

/// Blocks the calling thread until `child` exits, returning its exit status.
///
/// `process_wait` is deliberately non-blocking in the kernel (it never sleeps
/// inside the syscall), so the runtime retries with [`pause`]: this keeps the
/// user program cooperative while still allowing the timer interrupt to
/// preempt it. Any error other than `WOULD_BLOCK` is returned to the caller.
pub fn wait(child: Handle) -> Result<u64, u64> {
    loop {
        match process_wait(child) {
            Ok(status) => return Ok(status),
            Err(ERR_WOULD_BLOCK) => pause(),
            Err(other) => return Err(other),
        }
    }
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo<'_>) -> ! {
    loop {
        pause();
    }
}
