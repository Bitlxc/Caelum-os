//! Native syscall dispatch (ABI 0.2, M5c2).
//!
//! The architecture entry ([`crate::arch::syscall`]) has already saved the user
//! context and handed us a [`SyscallFrame`]; this module implements the ABI
//! documented in `libs/native-abi` and `docs/abi/native-syscall.md`:
//!
//! | nr | call | semantics |
//! |----|------|-----------|
//! | 0 | `abi_query` | `result` = [`native_abi::ABI_VERSION`] |
//! | 1 | `write` | Console + `RIGHT_WRITE`, or a `File` handle: copy-in, write |
//! | 2 | `process_create` | copy-in 64-byte request, explicit handle transfers |
//! | 3 | `process_wait` | Zombie -> status, Running -> `ERR_WOULD_BLOCK` |
//! | 4 | `process_exit` | never returns |
//! | 5 | `random_read` | Random handle + `RIGHT_READ`, no entropy -> no bytes |
//! | 6 | `handle_close` | close one handle of the calling process |
//! | 7 | `open` | `OpenRequest` -> `File` handle owning a VFS description |
//! | 8 | `read` | File + `RIGHT_READ`, from the description's offset |
//! | 9 | `stat` | File handle -> `StatOut` |
//! | 10 | `readdir` | directory description -> `DirEntryOut` |
//! | 11–13 | `mkdir` / `rmdir` / `unlink` | path -> VFS mutation |
//! | 14 | `rename` | `RenameRequest`, one backing store only |
//! | 15 | `sync` | File + `RIGHT_WRITE`, flush dirty pages and the device |
//! | 16 | `seek` | File handle -> new offset |
//! | 17 | `dup` | duplicate a handle, sharing the same open description |
//! | 18 | `mmap` | `MmapRequest` + `File` handle -> `VmObject` mapping handle |
//! | 19 | `munmap` | close the mapping handle that owns an exact range |
//! | 20 | `mprotect` | change an existing mapping's permissions |
//! | 26 | `truncate` | File + `RIGHT_WRITE`, resize (grow is zero-filled) |
//! | 27 | `ipc_create` | `IpcCreateRequest` -> `Event`/`EventPair`/`Timer`/Channel/Port handle |
//! | 28 | `ipc_signal` | Event/EventPair + `RIGHT_WRITE`, reset or signal one endpoint |
//! | 29 | `wait` | `WaitRequest` over 1..=4 waitable handles, optional deadline |
//! | 30 | `ipc_send` | `IpcSendRequest` -> Channel/Port queue, never blocks |
//! | 31 | `ipc_recv` | `IpcReceiveRequest` -> one message, optional deadline |
//! | 32 | `shm_map` | `ShmMapRequest` + `SharedMemory` handle -> `VmObject` mapping |
//! | 33 | `timer_arm` | Timer + `RIGHT_WRITE`, one-shot deadline on the tick clock |
//! | 34 | `subscribe` | `SubscribeRequest` -> interests added to a subscription |
//! | 35 | `unsubscribe` | subscription handle + target handle -> interest removed |
//! | 37 | `futex_wait` | user `u32` word, block while it still equals `expected` |
//! | 38 | `futex_wake` | wake up to `max` waiters of one physical word |
//! | 39 | `subscription_read` | `SubscriptionReadRequest` -> drained readiness events |
//! | 40 | `display_info` | `DisplayInfoRequest` -> `DisplayInfoWire` geometry |
//! | 41 | `display_map` | `ShmMapRequest` + `Display` handle -> `VmObject` shadow mapping |
//! | 42 | `display_present` | `DisplayPresentRequest` -> shadow copied to the framebuffer |
//! | 43 | `input_read` | `InputReadRequest` -> queued console events, never blocks |
//! | 44 | `socket` | `SocketCreateRequest` -> Socket handle, optionally in a namespace |
//! | 45 | `bind` | `SocketAddrRequest` -> Socket, local address (named inside a namespace) |
//! | 46 | `listen` | Socket + backlog in `rsi`; a TCP listener is allocated here |
//! | 47 | `accept` | `SocketAcceptRequest` -> new Socket handle, never blocks |
//! | 48 | `connect` | `SocketAddrRequest` -> Socket, non-blocking start |
//! | 49 | `send` | `SocketSendRequest` -> bytes accepted, never blocks |
//! | 50 | `recv` | `SocketRecvRequest` -> bytes received plus optional source address |
//! | 51 | `shutdown` | Socket + how in `rsi` (`SOCKET_SHUTDOWN_*`) |
//! | 52 | `socketpair` | `SocketPairRequest` -> two connected Socket handles |
//! | 53 | `socket_address` | `SocketAddressRequest` -> `SocketAddrWire` (local or peer) |
//!
//! Number 36 (`ipc_transfer`) is frozen for a later stage: it returns
//! [`ERR_NOT_SUPPORTED`] and is never given another meaning.
//!
//! Three invariants matter more than the individual calls:
//!
//! * **User memory is never dereferenced here.** Every user pointer goes
//!   through [`addrspace::copy_in`] / [`addrspace::copy_out`], which walk the
//!   calling process's page tables, so a bad pointer is an error and not a
//!   kernel fault.
//! * **Capabilities are explicit.** A syscall may only act on handles the
//!   caller already holds with the required right; nothing is inherited
//!   implicitly (the M4 contract: `init` hands `child` exactly its Console).
//! * **A `File` handle owns a VFS open description.** The object payload is the
//!   raw [`vfs::OpenId`]; `object` deliberately knows nothing about the VFS, so
//!   [`init`] registers a destroy hook that closes the description when the
//!   last handle goes away. `dup` copies the handle (same payload), and the
//!   object refcount keeps the description alive exactly once.

use native_abi::{
    ABI_VERSION,
    DISPLAY_HEIGHT,
    DISPLAY_WIDTH,
    DirEntryOut,
    DisplayInfoRequest,
    DisplayInfoWire,
    DisplayPresentRequest,
    ERR_BAD_HANDLE,
    ERR_BAD_POINTER,
    ERR_BAD_REQUEST,
    ERR_BAD_RIGHT,
    ERR_BUSY,
    ERR_CANCELLED,
    // ABI 0.6: native sockets (M7b).
    ERR_CONNECTION_REFUSED,
    ERR_CONNECTION_RESET,
    ERR_CORRUPT,
    ERR_CROSS_DEVICE,
    ERR_EXISTS,
    ERR_IO,
    ERR_IS_DIR,
    ERR_NO_ENTROPY,
    ERR_NO_SPACE,
    ERR_NOT_CONNECTED,
    ERR_NOT_DIR,
    ERR_NOT_EMPTY,
    ERR_NOT_FOUND,
    ERR_NOT_SUPPORTED,
    ERR_PEER_CLOSED,
    ERR_QUOTA,
    ERR_READ_ONLY,
    ERR_TIMEOUT,
    ERR_TOO_LARGE,
    ERR_WOULD_BLOCK,
    EVENT_FLAG_MANUAL_RESET,
    EVENT_PAIR_ENDPOINT_B,
    HANDLE_NONE,
    INPUT_EVENTS_MAX,
    IPC_DATA_MAX,
    IPC_HANDLES_MAX,
    IPC_KIND_CHANNEL,
    IPC_KIND_EVENT,
    IPC_KIND_EVENT_PAIR,
    IPC_KIND_PORT,
    IPC_KIND_SHARED_MEMORY,
    IPC_KIND_SUBSCRIPTION,
    IPC_KIND_TIMER,
    InputReadRequest,
    IpcCreateRequest,
    IpcMessageMeta,
    IpcReceiveRequest,
    IpcSendRequest,
    LOCK_DOMAIN_FLOCK,
    LOCK_DOMAIN_MAX,
    LOCK_DOMAIN_OFD,
    LOCK_DOMAIN_POSIX,
    LOCK_OP_EXCLUSIVE,
    LOCK_OP_MAX,
    LOCK_OP_SHARED,
    LOCK_OP_UNLOCK,
    LockRequest,
    MAX_HANDLES,
    NR_ABI_QUERY,
    NR_ACCEPT,
    NR_BIND,
    NR_CONNECT,
    NR_DISPLAY_INFO,
    NR_DISPLAY_MAP,
    NR_DISPLAY_PRESENT,
    NR_DUP,
    NR_FUTEX_WAIT,
    NR_FUTEX_WAKE,
    NR_HANDLE_CLOSE,
    NR_INPUT_READ,
    NR_IPC_CREATE,
    NR_IPC_RECV,
    NR_IPC_SEND,
    NR_IPC_SIGNAL,
    NR_LISTEN,
    NR_LOCK,
    NR_MKDIR,
    NR_MMAP,
    NR_MPROTECT,
    NR_MUNMAP,
    NR_OPEN,
    NR_PROCESS_CREATE,
    NR_PROCESS_EXIT,
    NR_PROCESS_WAIT,
    NR_RANDOM_READ,
    NR_READ,
    NR_READDIR,
    NR_RECV,
    NR_RENAME,
    NR_RMDIR,
    NR_SEEK,
    NR_SEND,
    NR_SHM_MAP,
    NR_SHUTDOWN,
    NR_SOCKET,
    NR_SOCKET_ADDRESS,
    NR_SOCKETPAIR,
    NR_STAT,
    NR_SUBSCRIBE,
    NR_SUBSCRIPTION_READ,
    NR_SYNC,
    NR_TIMER_ARM,
    NR_TRUNCATE,
    NR_UNLINK,
    NR_UNSUBSCRIBE,
    NR_WAIT,
    NR_WATCH,
    NR_WATCH_DRAIN,
    NR_WRITE,
    NR_XATTR_GET,
    NR_XATTR_SET,
    OPEN_CREATE,
    OPEN_DIRECTORY,
    OPEN_READ,
    OPEN_TRUNC,
    OPEN_VALID,
    OPEN_WRITE,
    REQUEST_VERSION,
    SEEK_CUR,
    SEEK_END,
    SEEK_SET,
    SIGNAL_OP_RESET,
    SIGNAL_OP_SIGNAL,
    SOCKET_ADDR_LOCAL,
    SOCKET_ADDR_PEER,
    SOCKET_ADDR_WIRE,
    SOCKET_DOMAIN_INET,
    SOCKET_DOMAIN_INET6,
    SOCKET_DOMAIN_UNIX,
    SOCKET_FAMILY_INET,
    SOCKET_FAMILY_INET6,
    SOCKET_FAMILY_UNIX,
    SOCKET_KIND_DGRAM,
    SOCKET_KIND_STREAM,
    SOCKET_PATH_BYTES,
    SOCKET_SHUTDOWN_BOTH,
    SOCKET_SHUTDOWN_READ,
    SOCKET_SHUTDOWN_WRITE,
    STATUS_OK,
    SUBSCRIBE_MAX_ENTRIES,
    SUBSCRIPTION_EVENTS_MAX,
    SUBSCRIPTION_MODE_EDGE,
    SUBSCRIPTION_MODE_LEVEL,
    SocketAcceptRequest,
    SocketAddrRequest,
    SocketAddrWire,
    SocketAddressRequest,
    SocketCreateRequest,
    SocketPairRequest,
    SocketRecvRequest,
    SocketSendRequest,
    StatOut,
    SubscribeRequest,
    SubscriptionReadRequest,
    WAIT_MAX_ITEMS,
    WAIT_TIMEOUT_IMMEDIATE,
    WAIT_TIMEOUT_INFINITE,
    WAKE_READY,
    WATCH_EVENT_CREATED,
    WATCH_EVENT_DELETED,
    WATCH_EVENT_RENAMED,
    WATCH_MAX_BATCH,
    WaitOut,
    WaitRequest,
    WatchDrainRequest,
    WatchEventOut,
    XATTR_NAME_MAX,
    XATTR_USER_PREFIX,
    XATTR_VALUE_MAX,
    XattrRequest,
};

use crate::arch::syscall::{self, SyscallFrame, SyscallRet};
use crate::ipc::{self, IpcError, Message, OutMessage};
use crate::mm::addrspace::{self, AddressSpaceId};
use crate::net;
use crate::object::{self, Handle, ObjectError, ObjectId, ObjectKind, ResolvedHandle, Rights};
use crate::process::{self, HandleTransfer, ProcessError, WakeReason};
use crate::vfs::{self, DirEntry, NodeKind, OpenId, OpenOptions, SeekFrom, VfsError};
use crate::vmobj;

/// Largest `read`/`write` payload accepted in one call (keeps the syscall
/// bounded; user libraries loop over larger buffers).
const MAX_IO_BYTES: u64 = 4096;
/// Copy chunk for `read`/`write`; no allocation is used on this path.
const IO_CHUNK: usize = 128;
/// Largest `random_read` request accepted in one call.
const MAX_RANDOM_BYTES: u64 = 256;
/// Largest `xattr` name accepted in one call (ABI 0.2 [`XATTR_NAME_MAX`]).
const MAX_XATTR_NAME: usize = XATTR_NAME_MAX as usize;
/// Largest `xattr` value accepted in one call (ABI 0.2 [`XATTR_VALUE_MAX`]).
const MAX_XATTR_VALUE: usize = XATTR_VALUE_MAX as usize;
/// Largest `watch_drain` batch (ABI 0.2 [`WATCH_MAX_BATCH`]).
const MAX_WATCH_EVENTS: usize = WATCH_MAX_BATCH as usize;

/// Install the dispatch table, the destroy hook and the `syscall` MSRs.
///
/// Called once by the kernel root after the M3 demo returns and before the
/// first user process is started.
pub fn init() {
    // A `File` object's payload is a VFS open description; the object layer
    // releases it through this hook when the last handle is closed (or when a
    // handle-table insertion fails after the description was opened). The
    // registration is idempotent for the same function.
    if object::register_destroy_hook(ObjectKind::File, release_open_description).is_err() {
        // Only a second, *different* `File` hook can fail this. That would leave
        // every description opened afterwards leaked, so it is a boot-time
        // invariant rather than a warning: refuse to start user mode.
        crate::fail_m5c("a second File destroy hook is already registered");
    }
    // A `VmObject`'s payload is a live mapping id; the hook unmaps the range when
    // the last handle is closed, which is also the only release path `munmap`
    // and process teardown use.
    if object::register_destroy_hook(ObjectKind::VmObject, vmobj::destroy_from_object).is_err() {
        crate::fail_m5c("a second VmObject destroy hook is already registered");
    }
    // A `Watch` object's payload is `(owner << 32) | watch id`; the hook stops the
    // watch through the owner recorded at creation time. The kind-aware variant
    // keeps this signature distinct from the two `fn(u64)` hooks above.
    if object::register_destroy_hook_with_kind(ObjectKind::Watch, release_watch).is_err() {
        crate::fail_m5c("a second Watch destroy hook is already registered");
    }
    // The IPC layer owns the Event / EventPair / Timer tables; its hook releases
    // the table slot and wakes anyone blocked on the object. Registration is
    // idempotent, but a conflict would leak every IPC table slot from then on.
    if ipc::install_destroy_hooks().is_err() {
        crate::fail_m6a("a second IPC destroy hook is already registered");
    }
    // M7b: a `Socket`'s payload is the raw net socket id. The hook closes the
    // socket (and wakes its peer) when the last handle goes away; a repeated
    // close is expected during rollback and the engine reports it as an invalid
    // id, which is ignored. A `NetNamespace` owns the path bindings, so its hook
    // tears the namespace down once the last handle is gone.
    if object::register_destroy_hook(ObjectKind::Socket, release_socket).is_err() {
        crate::fail_m7b("socket-hook");
    }
    if object::register_destroy_hook_with_object(ObjectKind::NetNamespace, release_net_namespace)
        .is_err()
    {
        crate::fail_m7b("netns-hook");
    }
    syscall::install_dispatch(dispatch);
    syscall::init_syscall();
}

/// Close the VFS open description owned by a `File` object.
///
/// Runs from the object layer with interrupts already disabled; `vfs::close`
/// takes its own interrupt-safe lock and does not re-enter the object table.
fn release_open_description(payload: u64) {
    let _ = vfs::close(OpenId::from_raw(payload as u16));
}

fn ok(result: u64) -> SyscallRet {
    SyscallRet {
        status: STATUS_OK,
        result,
    }
}

fn err(status: u64) -> SyscallRet {
    SyscallRet { status, result: 0 }
}

/// Address space of the process that issued the current syscall.
fn current_address_space() -> Option<AddressSpaceId> {
    process::current_index().map(process::address_space)
}

/// The only syscalls an application processor may issue.
///
/// Three user programs run on APs: the M6b2 `worker` (event/timer round trip),
/// the M6c `gfx` client (display shadow, presentation, input), and the M7b `net`
/// parent (its socket suite plus the process/channel calls it needs to run a
/// child). The list is their exact union and nothing else: widening it would let
/// a scheduler bug expose the rest of the BSP ABI on a secondary CPU.
const AP_SYSCALL_WHITELIST: [u64; 25] = [
    NR_ABI_QUERY,
    NR_WRITE,
    NR_PROCESS_CREATE,
    NR_PROCESS_WAIT,
    NR_PROCESS_EXIT,
    NR_HANDLE_CLOSE,
    NR_IPC_CREATE,
    NR_WAIT,
    NR_IPC_SEND,
    NR_IPC_RECV,
    NR_TIMER_ARM,
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

/// Whether `nr` may run on an application processor.
fn ap_syscall_allowed(nr: u64) -> bool {
    AP_SYSCALL_WHITELIST.contains(&nr)
}

/// Network-namespace object the current Linux process was spawned with.
///
/// The spawn contract stores the namespace as a native handle in the child's
/// table; the personality needs the object id (or `0` when there is none) to
/// authorise named UNIX addresses. A handle that no longer resolves, or that
/// points at the wrong kind, degrades to `0`: UNIX path calls then fail with
/// `BAD_RIGHT`, which is exactly the "no namespace capability" answer.
fn current_linux_netns_object() -> crate::object::ObjectId {
    use crate::object::{ObjectKind, Rights};
    let Some(handle) = process::current_linux_netns() else {
        return 0;
    };
    process::with_current_handles(|table| {
        match crate::object::resolve_handle(table, handle, Rights::READ) {
            Ok(resolved) if resolved.kind == ObjectKind::NetNamespace => resolved.object,
            _ => 0,
        }
    })
    .unwrap_or(0)
}

/// Build the native return frame for a Linux `rax` value.
///
/// The Linux personality returns a single `rax`: a non-negative result or
/// `-errno`. The native `status`/`result` pair is not used, so the value goes in
/// `status` and `result` stays zero.
fn linux_status(value: i64) -> SyscallRet {
    SyscallRet {
        status: value as u64,
        result: 0,
    }
}

/// What the pending-signal loop did.
enum SignalDelivery {
    /// No handler ran (nothing was pending, or every pending signal was
    /// ignored/consumed).
    None,
    /// A user handler was installed; the trap frame now returns into it.
    Handler,
}

/// Deliver every pending Linux signal before returning to ring 3.
///
/// `Done` calls run this after the fd guard is dropped. A `Wait` call runs it
/// **before** blocking: a signal that arrives while the call is about to sleep
/// must interrupt it instead of being swallowed by the wait, which is what
/// makes `kill` reach a handler when the process is already blocked.
///
/// A handler frame that cannot be written is never reported as delivered: the
/// process terminates loudly instead of returning to the interrupted
/// instruction with a half-built user stack.
fn deliver_pending_signals(
    trap_frame: *mut crate::arch::TrapFrame,
    address_space: Option<AddressSpaceId>,
) -> SignalDelivery {
    use crate::compat::linux::signal;
    use crate::compat::linux::syscall as linux;

    let mut delivered = SignalDelivery::None;
    loop {
        // SAFETY: the entry stub built this trap frame for the current system
        // call and keeps it alive until dispatch returns.
        let trap = unsafe { &*trap_frame };
        match process::signal_take_pending(trap) {
            Ok(Some(process::PendingSignal::Ignored(_))) => continue,
            Ok(Some(process::PendingSignal::Default(signo))) => {
                // Record the signal so a parent's `wait4` reports
                // `WIFSIGNALED` (a bare exit status would lose it).
                process::exit_current_with_signal(128 + u64::from(signo), signo);
            }
            Ok(Some(process::PendingSignal::Handler {
                signo,
                action,
                saved,
                saved_mask,
            })) => {
                let Some(space) = address_space else {
                    crate::klog!(
                        "[CaelumLinux] signal delivery without an address space; terminating"
                    );
                    process::exit_current_with_signal(128 + u64::from(signo), signo);
                };
                let mut memory = linux::KernelSignalMemory::new(space);
                // SAFETY: same frame pointer as above; the signal delivery only
                // rewrites the ring-3 return values of this one system call.
                let trap = unsafe { &mut *trap_frame };
                if signal::deliver_handler(trap, &action, signo, &saved, saved_mask, &mut memory)
                    .is_err()
                {
                    crate::klog!("[CaelumLinux] signal frame write failed; terminating");
                    process::exit_current_with_signal(128 + u64::from(signo), signo);
                }
                delivered = SignalDelivery::Handler;
                // The process keeps one in-flight delivery slot, so the next
                // `take_pending` reports `None` and the loop ends here.
            }
            Ok(None) => return delivered,
            Err(_) => {
                crate::klog!("[CaelumLinux] signal state unavailable; terminating");
                process::exit_current_with_signal(
                    128 + u64::from(process::SIGKILL),
                    process::SIGKILL,
                );
            }
        }
    }
}

/// Drop the wake reason recorded by an interrupted `ppoll` replay.
///
/// [`linux_sigmask_enter`] returns before [`linux_dispatch`]'s generic
/// stale-reason drain and before the compat layer can consume the reason, so an
/// interruption that delivered a signal handler must clear the recorded
/// `Cancelled` reason here. Otherwise the next owns-wake call
/// (`futex`/`clock_nanosleep`/`poll`/`ppoll`) would map the stale reason to a
/// spurious `-EINTR`.
fn clear_interrupted_ppoll_reason() {
    let _ = process::take_wake_reason();
}

/// Install or replay a temporary signal mask before dispatching a masked wait.
///
/// Shared by `ppoll` (M8p) and `epoll_pwait` (M9a): both replace the blocked
/// mask for the duration of the call and must be interrupted by a pending
/// signal the temporary mask lets through. `request` is the already-validated
/// mask pointer of the calling ABI (`Ok(None)` = no mask argument).
///
/// Returns `Some` when the call was completed here (invalid fixed arguments or a
/// pending signal interrupted it); `None` means the normal dispatch continues
/// with the temporary mask installed (and, for a blocking wait, still active
/// across the replay).
fn linux_sigmask_enter(
    frame: &SyscallFrame,
    trap_frame: *mut crate::arch::TrapFrame,
    address_space: Option<AddressSpaceId>,
    request: Result<Option<u64>, i64>,
) -> Option<SyscallRet> {
    use crate::compat::linux::errno;
    use crate::compat::linux::signal;
    use crate::compat::linux::syscall as linux;

    let mask_pointer = match request {
        Ok(None) => return None,
        Ok(Some(pointer)) => pointer,
        Err(error) => return Some(linux_status(error)),
    };
    let Some(space) = address_space else {
        return Some(linux_status(-errno::EFAULT));
    };
    let mut raw_mask = [0u8; signal::SIGSET_BYTES];
    if addrspace::copy_in(space, mask_pointer, &mut raw_mask).is_err() {
        return Some(linux_status(-errno::EFAULT));
    }
    let temporary = signal::decode_sigset(&raw_mask);

    // A replay already installed the mask before it slept. The original value
    // lives in the process fd table, so a replay never re-saves the temporary
    // mask as the "original".
    let active = process::take_current_fds().and_then(|guard| guard.table().ppoll_mask());
    let original = match active {
        Some(original) => original,
        None => {
            let Ok(original) = process::signal_mask() else {
                return Some(linux_status(-errno::EINVAL));
            };
            if process::signal_set_mask(process::SignalMaskHow::SetMask, temporary).is_err() {
                return Some(linux_status(-errno::EINVAL));
            }
            let Some(mut guard) = process::take_current_fds() else {
                let _ = process::signal_set_mask(process::SignalMaskHow::SetMask, original);
                return Some(linux_status(-errno::EBADF));
            };
            guard.table_mut().begin_ppoll_mask(original);
            original
        }
    };

    // A signal that the temporary mask lets through must interrupt the call
    // instead of being consumed by the wait.
    let deliverable = process::with_current_signals(|state| {
        linux::pending_is_deliverable(state.pending, state.blocked)
    })
    .unwrap_or(false);
    if !deliverable {
        return None;
    }
    // SAFETY: the entry stub built this trap frame for the current system call
    // and keeps it alive until dispatch returns; a handler's saved context must
    // observe `-EINTR` as this call's return value.
    unsafe {
        (*trap_frame).rax = (-errno::EINTR) as u64;
        (*trap_frame).rdx = 0;
    }
    if matches!(
        deliver_pending_signals(trap_frame, address_space),
        SignalDelivery::Handler
    ) {
        if let Some(mut guard) = process::take_current_fds() {
            let _ = guard.table_mut().end_ppoll_mask();
            guard.table_mut().set_pending_mask_restore(original);
        }
        // This path returns before the compat layer and before the generic
        // stale-reason drain can run, so the reason recorded by the interrupted
        // wait must be dropped here (see `clear_interrupted_ppoll_reason`).
        clear_interrupted_ppoll_reason();
        return Some(linux_status(-errno::EINTR));
    }
    // Nothing was delivered (every candidate was ignored or consumed): the
    // call must run, so restore the syscall number the replay reads.
    // SAFETY: same frame pointer; `rax` holds the system call number again.
    unsafe {
        (*trap_frame).rax = frame.nr;
        (*trap_frame).rdx = 0;
    }
    None
}

/// Linux64 system call entry (M7d).
///
/// Dispatches through [`crate::compat::linux::syscall`] with the process' own
/// fd table and network namespace. This runs **before** the native AP whitelist:
/// Linux numbers (`dup` = 32, …) are not native numbers and must not be filtered
/// by that table.
///
/// # Exit contract
///
/// `exit`/`exit_group` are handled before the fd guard exists. The Linux call
/// never returns, so a guard taken first would never be dropped and its table
/// (plus every fd reference) would leak.
///
/// # Blocking
///
/// A call that reports [`crate::compat::linux::syscall::Outcome::Wait`] drops the
/// fd guard first and then blocks through the scheduler; the architecture entry
/// stub replays the whole system call after the wake, so `rax` ends up with the
/// Linux result.
fn linux_dispatch(raw: *mut SyscallFrame, frame: &SyscallFrame) -> SyscallRet {
    use crate::compat::linux::errno;
    use crate::compat::linux::syscall as linux;

    if frame.nr == linux::NR_EXIT || frame.nr == linux::NR_EXIT_GROUP {
        process::exit_current(frame.args[0]);
    }
    // A completed wait leaves the recorded wake reason behind; clear it here so
    // the first personality call after a wake does not mistake a stale `Ready`
    // for an interruption. `clock_nanosleep` keeps its own reason because
    // `Timeout` is its success signal.
    //
    // `Cancelled` means a signal interrupted a blocking call. The syscall is
    // replayed by the entry stub, so the interruption has to be handled here
    // instead of leaking into the call: deliver the pending handler and, if one
    // was installed, return `-EINTR` for the interrupted call. If nothing was
    // delivered (the signal is ignored/blocked), restore the replay registers
    // and let the syscall run again — an ignored signal must not interrupt it.
    // SAFETY: the entry stub stored its own `TrapFrame` pointer in the frame;
    // the scheduler re-checks that it belongs to the current stack before
    // switching away, and the pointer stays valid until dispatch returns.
    let trap_frame = unsafe { (*raw).trap_frame };
    let address_space = current_address_space();
    // M8p: `ppoll` replaces the blocked mask for the duration of the call. The
    // temporary mask has to exist before the wait so a pending handler
    // interrupts the call; the original mask is kept in the process fd table
    // because the call replays across the blocking wait.
    if frame.nr == linux::NR_PPOLL || frame.nr == linux::NR_EPOLL_PWAIT {
        // Both calls take a signal mask at a different argument slot: `ppoll`
        // uses args[3]/args[4], `epoll_pwait` uses args[4]/args[5].
        let request = if frame.nr == linux::NR_PPOLL {
            linux::ppoll_mask_request(&frame.args)
        } else {
            linux::epoll_pwait_mask_request(&frame.args)
        };
        if let Some(result) = linux_sigmask_enter(frame, trap_frame, address_space, request) {
            return result;
        }
    }
    if !linux::owns_wake_reason(frame.nr) {
        let reason = process::take_wake_reason();
        if reason == process::WakeReason::Cancelled {
            // The saved handler context must observe the interrupted syscall's
            // return value, exactly as an `EINTR` return would.
            // SAFETY: same frame pointer as above; only the ring-3 return
            // registers of the current system call are written.
            unsafe {
                (*trap_frame).rax = (-errno::EINTR) as u64;
                (*trap_frame).rdx = 0;
            }
            if matches!(
                deliver_pending_signals(trap_frame, address_space),
                SignalDelivery::Handler
            ) {
                return SyscallRet {
                    status: (-errno::EINTR) as u64,
                    result: 0,
                };
            }
            // Nothing was delivered: replay the same call with `rax` restored.
            // SAFETY: same frame pointer; `rax` is the Linux system call number
            // the replay reads, never a return value before the call runs.
            unsafe {
                (*trap_frame).rax = frame.nr;
                (*trap_frame).rdx = 0;
            }
        }
    }
    let Some(mut guard) = process::take_current_fds() else {
        // Linux64 personality without an fd table: report a bad descriptor
        // rather than fabricating a successful call.
        return linux_status(-errno::EBADF);
    };
    let namespace = current_linux_netns_object();
    let outcome = {
        let mut context = linux::LinuxContext::new(guard.table_mut(), namespace, address_space)
            .with_trap_frame(trap_frame);
        linux::dispatch(frame.nr, &frame.args, &mut context)
    };
    match outcome {
        linux::Outcome::Done(value) => {
            // A normal `ppoll` return (ready descriptors, timeout or error)
            // puts the process' original blocked mask back before any handler
            // delivery decides what stays pending.
            let restored_ppoll = guard.table_mut().end_ppoll_mask();
            // The guard must be gone before the delivery loop: a handler frame
            // must not keep the process' descriptor table borrowed.
            drop(guard);
            if let Some(original) = restored_ppoll {
                let _ = process::signal_set_mask(process::SignalMaskHow::SetMask, original);
            }
            let status = value as u64;
            // The delivery saves the interrupted context from this frame, so
            // record the system call's return value first: once the handler
            // returns through `rt_sigreturn`, the interrupted instruction must
            // observe it in `rax`.
            // SAFETY: same frame pointer as above; this only writes the ring-3
            // return values of the current system call.
            unsafe {
                (*trap_frame).rax = status;
                (*trap_frame).rdx = 0;
            }
            let _ = deliver_pending_signals(trap_frame, address_space);
            SyscallRet { status, result: 0 }
        }
        linux::Outcome::Restore { rax, rdx } => {
            drop(guard);
            let status = rax as u64;
            // The delivery loop below may install a *new* handler (a signal
            // that arrived while the old handler ran). Its saved context must
            // see the restored return value, so record it in the frame first;
            // the architecture stub writes the same values after dispatch in
            // either case.
            // SAFETY: the same current-syscall frame pointer used above.
            unsafe {
                (*trap_frame).rax = status;
                (*trap_frame).rdx = rdx;
            }
            let _ = deliver_pending_signals(trap_frame, address_space);
            SyscallRet {
                status,
                result: rdx,
            }
        }
        linux::Outcome::Wait { object, .. } => {
            // The guard must be gone before sleeping: `block_current_keyed`
            // does not return and another thread may need the table slot.
            drop(guard);
            // Do **not** touch `rax`/`rdx` here: the architecture entry stub
            // replays the `syscall` instruction after the wake, so `rax` still
            // has to hold the Linux system call number. Writing an `EINTR`
            // result into the frame before blocking made the replay read the
            // error value as the call number and answer `ENOSYS`.
            //
            // A signal that arrives while blocked wakes the process with
            // `WakeReason::Cancelled`; the replay then takes the `Done` arm
            // (e.g. `clock_nanosleep` turns it into `EINTR`) and the delivery
            // loop there captures the interrupted frame with the right value.
            linux::block_until_ready(trap_frame, object)
        }
        linux::Outcome::FutexWait { word, deadline } => {
            // `futex::wait` saves the frame (with the user `rip` rewound over
            // the `syscall` instruction) and never returns: the replay
            // re-enters this dispatch with the recorded wake reason.
            //
            // As in the `Wait` arm the FdTable guard must be gone first, and
            // `rax` still holds the Linux system call number because the entry
            // stub replays the instruction.
            drop(guard);
            crate::futex::wait(trap_frame, word, deadline)
        }
        linux::Outcome::PollWait {
            objects,
            keys,
            count,
            deadline,
        } => {
            // `poll`/`ppoll` waits on up to four objects with the deadline the
            // compat layer computed; the same syscall replays when it wakes, so
            // `revents` always reflects the state at wake time and `rax` still
            // holds the call number.
            drop(guard);
            process::block_current_keyed(trap_frame, objects, keys, count, deadline)
        }
    }
}

/// Root dispatcher: decode the syscall number and run one call.
fn dispatch(frame: *mut SyscallFrame) -> SyscallRet {
    // SAFETY: the architecture entry stub builds this frame in kernel memory and
    // passes it only for the duration of the call. `raw` is kept because `wait`
    // hands the frame to the scheduler when it has to block.
    let raw = frame;
    let frame = unsafe { &*frame };
    // M7d: the Linux64 personality has its own numbers and its own fd table, and
    // must be dispatched before the native AP whitelist and the native match.
    if process::current_personality() == process::Personality::Linux64 {
        return linux_dispatch(raw, frame);
    }
    // M6b2: secondary CPUs run only the worker workload (see the whitelist).
    if crate::arch::cpu_index() != 0 && !ap_syscall_allowed(frame.nr) {
        return err(ERR_NOT_SUPPORTED);
    }
    match frame.nr {
        NR_ABI_QUERY => abi_query(),
        NR_WRITE => write(frame.args[0], frame.args[1], frame.args[2]),
        NR_PROCESS_CREATE => process_create(frame.args[0]),
        NR_PROCESS_WAIT => process_wait(frame.args[0]),
        NR_PROCESS_EXIT => process_exit(frame.args[0]),
        NR_RANDOM_READ => random_read(frame.args[0], frame.args[1], frame.args[2]),
        NR_HANDLE_CLOSE => handle_close(frame.args[0]),
        NR_OPEN => open(frame.args[0]),
        NR_READ => read(frame.args[0], frame.args[1], frame.args[2]),
        NR_STAT => stat(frame.args[0], frame.args[1]),
        NR_READDIR => readdir(frame.args[0], frame.args[1], frame.args[2]),
        NR_MKDIR => mkdir(frame.args[0], frame.args[1]),
        NR_RMDIR => rmdir(frame.args[0], frame.args[1]),
        NR_UNLINK => unlink(frame.args[0], frame.args[1]),
        NR_RENAME => rename(frame.args[0]),
        NR_SYNC => sync(frame.args[0]),
        NR_SEEK => seek(frame.args[0], frame.args[1], frame.args[2]),
        NR_DUP => dup(frame.args[0], frame.args[1]),
        NR_TRUNCATE => truncate(frame.args[0], frame.args[1]),
        NR_MMAP => mmap(frame.args[0], frame.args[1]),
        NR_MUNMAP => munmap(frame.args[0], frame.args[1]),
        NR_MPROTECT => mprotect(frame.args[0], frame.args[1], frame.args[2]),
        NR_LOCK => lock(frame.args[0], frame.args[1]),
        NR_XATTR_SET => xattr_set(frame.args[0], frame.args[1]),
        NR_XATTR_GET => xattr_get(frame.args[0], frame.args[1]),
        NR_WATCH => watch(frame.args[0], frame.args[1]),
        NR_WATCH_DRAIN => watch_drain(frame.args[0], frame.args[1]),
        NR_IPC_CREATE => ipc_create(frame.args[0]),
        NR_IPC_SEND => ipc_send(frame.args[0], frame.args[1]),
        NR_IPC_RECV => ipc_receive(raw, frame.args[0], frame.args[1]),
        NR_SHM_MAP => shm_map(frame.args[0], frame.args[1]),
        NR_SUBSCRIBE => subscribe(frame.args[0], frame.args[1]),
        NR_UNSUBSCRIBE => unsubscribe(frame.args[0], frame.args[1]),
        NR_SUBSCRIPTION_READ => subscription_read(frame.args[0], frame.args[1]),
        NR_INPUT_READ => input_read(frame.args[0], frame.args[1]),
        NR_DISPLAY_INFO => display_info(frame.args[0], frame.args[1]),
        NR_DISPLAY_MAP => display_map(frame.args[0], frame.args[1]),
        NR_DISPLAY_PRESENT => display_present(frame.args[0], frame.args[1]),
        NR_IPC_SIGNAL => ipc_signal(frame.args[0], frame.args[1], frame.args[2]),
        NR_WAIT => wait(raw, frame.args[0]),
        NR_TIMER_ARM => timer_arm(frame.args[0], frame.args[1], frame.args[2]),
        NR_FUTEX_WAIT => futex_wait(raw, frame.args[0], frame.args[1], frame.args[2]),
        NR_FUTEX_WAKE => futex_wake(frame.args[0], frame.args[1]),
        NR_SOCKET => socket_create(frame.args[0]),
        NR_BIND => socket_bind(frame.args[0], frame.args[1]),
        NR_LISTEN => socket_listen(frame.args[0], frame.args[1]),
        NR_ACCEPT => socket_accept(frame.args[0], frame.args[1]),
        NR_CONNECT => socket_connect(frame.args[0], frame.args[1]),
        NR_SEND => socket_send(frame.args[0], frame.args[1]),
        NR_RECV => socket_recv(frame.args[0], frame.args[1]),
        NR_SHUTDOWN => socket_shutdown(frame.args[0], frame.args[1]),
        NR_SOCKETPAIR => socket_pair(frame.args[0]),
        NR_SOCKET_ADDRESS => socket_address(frame.args[0], frame.args[1]),
        // Unknown numbers must never look like success.
        _ => err(ERR_NOT_SUPPORTED),
    }
}

/// `abi_query`: report the ABI version the kernel implements.
fn abi_query() -> SyscallRet {
    ok(ABI_VERSION as u64)
}

// ---------------------------------------------------------------------------
// User-memory helpers
// ---------------------------------------------------------------------------

/// Copy one `repr(C)` request structure in from user memory.
fn copy_in_struct<T>(address_space: AddressSpaceId, user: u64, value: &mut T) -> Result<(), u64> {
    // SAFETY: `value` is a live local of exactly `size_of::<T>()` bytes and the
    // slice never outlives this call.
    let bytes = unsafe {
        core::slice::from_raw_parts_mut(value as *mut T as *mut u8, core::mem::size_of::<T>())
    };
    addrspace::copy_in(address_space, user, bytes).map_err(|_| ERR_BAD_POINTER)
}

/// Copy one `repr(C)` response structure out to user memory.
fn copy_out_struct<T>(address_space: AddressSpaceId, user: u64, value: &T) -> Result<(), u64> {
    // SAFETY: `value` is a live, fully initialised `repr(C)` value and the slice
    // covers exactly its bytes.
    let bytes = unsafe {
        core::slice::from_raw_parts(value as *const T as *const u8, core::mem::size_of::<T>())
    };
    addrspace::copy_out(address_space, user, bytes).map_err(|_| ERR_BAD_POINTER)
}

/// Validate a user path length before copying it.
///
/// An empty path is a malformed request; a path longer than the VFS can hold is
/// reported as a bad pointer (the ABI's name for "the bytes you pointed at are
/// not a usable path").
fn path_length(len: u64) -> Result<usize, u64> {
    if len == 0 {
        return Err(ERR_BAD_REQUEST);
    }
    if len > vfs::MAX_PATH as u64 {
        return Err(ERR_BAD_POINTER);
    }
    Ok(len as usize)
}

/// Copy a user path into `buffer` and return it.
fn copy_path<'a>(
    address_space: AddressSpaceId,
    user: u64,
    len: u64,
    buffer: &'a mut [u8; vfs::MAX_PATH],
) -> Result<&'a [u8], u64> {
    let len = path_length(len)?;
    addrspace::copy_in(address_space, user, &mut buffer[..len]).map_err(|_| ERR_BAD_POINTER)?;
    let path = &buffer[..len];
    // Every path in ABI 0.2 is absolute; a relative one is a malformed request.
    if path[0] != b'/' {
        return Err(ERR_BAD_REQUEST);
    }
    Ok(path)
}

// ---------------------------------------------------------------------------
// Handle helpers
// ---------------------------------------------------------------------------

/// Resolve a handle of the calling process, requiring only a right.
fn resolve_handle_any(raw_handle: u64, required: Rights) -> Result<ResolvedHandle, u64> {
    if raw_handle > u32::MAX as u64 {
        return Err(ERR_BAD_HANDLE);
    }
    let handle = Handle::from_raw(raw_handle as u32);
    process::with_current_handles(|table| object::resolve_handle(table, handle, required))
        .ok_or(ERR_BAD_HANDLE)?
        .map_err(object_status)
}

/// Payload of a live object (the raw [`vfs::OpenId`] for `File` objects).
fn object_payload(object: ObjectId) -> Option<u64> {
    object::with_object_table(|objects| objects.payload(object))
}

/// The VFS open description behind a `File` handle.
fn file_open(raw_handle: u64, required: Rights) -> Result<OpenId, u64> {
    let resolved = resolve_handle_any(raw_handle, required)?;
    if resolved.kind != ObjectKind::File {
        return Err(ERR_BAD_HANDLE);
    }
    object_payload(resolved.object)
        .map(|payload| OpenId::from_raw(payload as u16))
        .ok_or(ERR_BAD_HANDLE)
}

// ---------------------------------------------------------------------------
// Memory mapping request validation (M5c2)
// ---------------------------------------------------------------------------

/// Largest `mmap` length accepted in one call: 256 KiB.
const MAX_MAP_BYTES: u64 = 256 * 1024;

/// A validated `mmap` request.
///
/// Everything is checked before any VM or object state is touched, so a
/// malformed request can never leave a half-built mapping behind.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct MapPlan {
    len: u64,
    offset: u64,
    prot: u32,
    shared: bool,
    out_address: u64,
}

/// Validate one protection mask.
///
/// Execution permission belongs to a later stage and is reported as
/// `NOT_SUPPORTED` rather than as a malformed request, so user space can tell
/// "not yet" apart from "never". A mapping must be readable: a write-only file
/// mapping has no meaning here.
fn protect_bits(prot: u32) -> Result<u32, u64> {
    if prot & native_abi::PROT_EXEC != 0 {
        return Err(ERR_NOT_SUPPORTED);
    }
    if prot & !native_abi::PROT_VALID != 0 {
        return Err(ERR_BAD_REQUEST);
    }
    if prot & native_abi::PROT_READ == 0 {
        return Err(ERR_BAD_REQUEST);
    }
    Ok(prot)
}

/// Validate a user range for `munmap`/`mprotect`: page aligned, non-empty and
/// free of wrap-around.
fn map_range(addr: u64, len: u64) -> Result<(), u64> {
    let page = vfs::PAGE;
    if addr % page != 0 || len == 0 || len % page != 0 {
        return Err(ERR_BAD_REQUEST);
    }
    if addr.checked_add(len).is_none() {
        return Err(ERR_BAD_REQUEST);
    }
    Ok(())
}

/// Validate one `mmap` request and turn it into a plan.
fn map_request(request: &native_abi::MmapRequest) -> Result<MapPlan, u64> {
    if request.size != native_abi::MmapRequest::SIZE
        || request.version != REQUEST_VERSION
        || request.reserved != 0
    {
        return Err(ERR_BAD_REQUEST);
    }
    let prot = protect_bits(request.prot)?;
    // Exactly one sharing mode: `SHARED` and `PRIVATE` together (or neither)
    // is a malformed request, not a default.
    let shared = match request.flags {
        native_abi::MMAP_SHARED => true,
        native_abi::MMAP_PRIVATE => false,
        _ => return Err(ERR_BAD_REQUEST),
    };
    let page = vfs::PAGE;
    if request.len == 0 || request.len % page != 0 || request.len > MAX_MAP_BYTES {
        return Err(ERR_BAD_REQUEST);
    }
    if request.offset % page != 0 || request.offset.checked_add(request.len).is_none() {
        return Err(ERR_BAD_REQUEST);
    }
    if request.out_address == 0 {
        return Err(ERR_BAD_POINTER);
    }
    Ok(MapPlan {
        len: request.len,
        offset: request.offset,
        prot,
        shared,
        out_address: request.out_address,
    })
}

// ---------------------------------------------------------------------------
// 0.1/0.2 calls
// ---------------------------------------------------------------------------

/// `write`: console bytes, or bytes into a file description.
fn write(raw_handle: u64, ptr: u64, len: u64) -> SyscallRet {
    if len > MAX_IO_BYTES {
        return err(ERR_BAD_REQUEST);
    }
    let Some(address_space) = current_address_space() else {
        return err(ERR_BAD_REQUEST);
    };
    let resolved = match resolve_handle_any(raw_handle, Rights::WRITE) {
        Ok(resolved) => resolved,
        Err(status) => return err(status),
    };
    match resolved.kind {
        ObjectKind::Console => write_console(address_space, ptr, len),
        ObjectKind::File => write_file(address_space, resolved.object, ptr, len),
        // A live handle of another kind is not writable; the ABI does not say
        // what it points at, so it is reported as a bad handle.
        _ => err(ERR_BAD_HANDLE),
    }
}

/// Append the caller's bytes to the console (raw 16550 byte stream).
fn write_console(address_space: AddressSpaceId, ptr: u64, len: u64) -> SyscallRet {
    let mut buffer = [0u8; IO_CHUNK];
    let mut done = 0u64;
    while done < len {
        let chunk = core::cmp::min(IO_CHUNK as u64, len - done) as usize;
        let Some(address) = ptr.checked_add(done) else {
            return err(ERR_BAD_POINTER);
        };
        if addrspace::copy_in(address_space, address, &mut buffer[..chunk]).is_err() {
            return err(ERR_BAD_POINTER);
        }
        // The console object is a raw 16550 byte stream: no timestamp, no CRLF.
        crate::log::serial_write_bytes(&buffer[..chunk]);
        done += chunk as u64;
    }
    ok(len)
}

/// Write the caller's bytes at the file description's current offset.
fn write_file(address_space: AddressSpaceId, object: ObjectId, ptr: u64, len: u64) -> SyscallRet {
    let Some(payload) = object_payload(object) else {
        return err(ERR_BAD_HANDLE);
    };
    let open = OpenId::from_raw(payload as u16);
    let mut buffer = [0u8; IO_CHUNK];
    let mut done = 0u64;
    while done < len {
        let chunk = core::cmp::min(IO_CHUNK as u64, len - done) as usize;
        let Some(address) = ptr.checked_add(done) else {
            return err(ERR_BAD_POINTER);
        };
        if addrspace::copy_in(address_space, address, &mut buffer[..chunk]).is_err() {
            return err(ERR_BAD_POINTER);
        }
        let written = match vfs::write(open, &buffer[..chunk]) {
            Ok(written) => written,
            Err(error) => return err(vfs_status(error)),
        };
        done += written as u64;
        if written < chunk {
            // A short write only happens when the file refuses more bytes; the
            // ABI reports the bytes actually written.
            break;
        }
    }
    ok(done)
}

/// `process_create`: spawn the named boot module with explicitly transferred
/// handles (copy semantics: the parent keeps its own handles).
fn process_create(request_ptr: u64) -> SyscallRet {
    let Some(address_space) = current_address_space() else {
        return err(ERR_BAD_REQUEST);
    };
    let mut request = native_abi::ProcessCreateRequest::empty();
    if let Err(status) = copy_in_struct(address_space, request_ptr, &mut request) {
        return err(status);
    }
    let (name, count, transfers) = match validate_request(&request) {
        Ok(valid) => valid,
        Err(status) => return err(status),
    };
    match process::spawn_from_current(name, &transfers[..count]) {
        Ok(handle) => ok(handle.raw() as u64),
        Err(error) => {
            // The precise reason goes to the kernel log; the ABI status stays
            // coarse (see `process_status`).
            crate::klog!(
                "[CaelumKernel] M4 FAIL process_create: \"{}\" was rejected",
                core::str::from_utf8(name).unwrap_or("<non-utf8>")
            );
            err(process_status(error))
        }
    }
}

/// Validate a copied-in create request and resolve its handle transfers.
///
/// Returns the module name, the transfer count and the (fixed-size) transfer
/// array so the caller can pass a slice without allocating.
fn validate_request(
    request: &native_abi::ProcessCreateRequest,
) -> Result<(&[u8], usize, [HandleTransfer; MAX_HANDLES]), u64> {
    // `size`/`version` guard the *layout* of this structure, not the ABI as a
    // whole: ABI 0.2 keeps every request at `REQUEST_VERSION` 1.
    if request.size != native_abi::ProcessCreateRequest::SIZE || request.version != REQUEST_VERSION
    {
        return Err(ERR_BAD_REQUEST);
    }
    if request.reserved != 0 {
        return Err(ERR_BAD_REQUEST);
    }
    let count = request.handle_count as usize;
    if count > MAX_HANDLES {
        return Err(ERR_BAD_REQUEST);
    }
    let name = request.module_name();
    if name.is_empty() {
        return Err(ERR_BAD_REQUEST);
    }
    let mut transfers = [HandleTransfer::new(Handle::INVALID, Rights::NONE); MAX_HANDLES];
    for index in 0..count {
        let entry = &request.handles[index];
        // Rights must be a non-empty subset of the ABI's right bits; the
        // process layer re-checks that the transfer never escalates.
        let rights = Rights::from_bits(entry.rights).ok_or(ERR_BAD_REQUEST)?;
        if rights.is_empty() {
            return Err(ERR_BAD_REQUEST);
        }
        // The same source handle may appear at most once per request. Two
        // entries for one object would give the child two handles that share a
        // single transferred reference, and closing both would release that
        // reference twice — a premature free guarded only by the object's
        // refcount, which M4 keeps minimal. `HANDLE_NONE` is exempt so an
        // invalid source is still reported as `BAD_HANDLE` by the process
        // layer instead of being misreported as a malformed request.
        if entry.source != HANDLE_NONE
            && transfers[..index]
                .iter()
                .any(|prior| prior.handle.raw() == entry.source)
        {
            return Err(ERR_BAD_REQUEST);
        }
        transfers[index] = HandleTransfer::new(Handle::from_raw(entry.source), rights);
    }
    Ok((name, count, transfers))
}

/// `process_wait`: reap a zombie child, or report that it is still running.
fn process_wait(raw_handle: u64) -> SyscallRet {
    if raw_handle > u32::MAX as u64 {
        return err(ERR_BAD_HANDLE);
    }
    match process::wait(Handle::from_raw(raw_handle as u32)) {
        Ok(status) => ok(status),
        Err(process::WaitError::WouldBlock) => err(ERR_WOULD_BLOCK),
        Err(process::WaitError::InvalidHandle) => err(ERR_BAD_HANDLE),
        Err(process::WaitError::NotChild) => err(ERR_NOT_FOUND),
        // Reaping failed after the child was known to be a zombie; the process
        // layer logs the reason. There is no finer ABI status for it.
        Err(process::WaitError::Reap(_)) => err(ERR_BAD_REQUEST),
    }
}

/// `process_exit`: mark the caller a zombie and switch away for good.
fn process_exit(status: u64) -> SyscallRet {
    process::exit_current(status)
}

/// `random_read`: read from a Random handle.
///
/// While the CRNG has no entropy this returns `ERR_NO_ENTROPY` and writes
/// **nothing** to the caller's buffer: the ABI never fabricates randomness.
fn random_read(raw_handle: u64, ptr: u64, len: u64) -> SyscallRet {
    if len > MAX_RANDOM_BYTES {
        return err(ERR_BAD_REQUEST);
    }
    let Some(address_space) = current_address_space() else {
        return err(ERR_BAD_REQUEST);
    };
    if let Err(status) = check_handle(raw_handle, ObjectKind::Random, Rights::READ) {
        return err(status);
    }
    let mut buffer = [0u8; MAX_RANDOM_BYTES as usize];
    let count = len as usize;
    match crate::rng::read_secure(&mut buffer[..count]) {
        Ok(()) => {
            if addrspace::copy_out(address_space, ptr, &buffer[..count]).is_err() {
                return err(ERR_BAD_POINTER);
            }
            ok(len)
        }
        Err(error) => err(rng_status(error)),
    }
}

/// `handle_close`: close one handle of the calling process.
fn handle_close(raw_handle: u64) -> SyscallRet {
    if raw_handle > u32::MAX as u64 {
        return err(ERR_BAD_HANDLE);
    }
    let handle = Handle::from_raw(raw_handle as u32);
    // The table is taken out of the process slot so the `File`/`VmObject`/
    // `Watch`/IPC destroy hooks run with the process lock released, and it goes
    // back untouched on every early return in `Drop`.
    let closed = process::take_current_handles()
        .map(|mut guard| object::close_handle(guard.table_mut(), handle));
    match closed {
        None => err(ERR_BAD_HANDLE),
        Some(Ok(_)) => {
            // Closing a handle can destroy the last reference to a subscription
            // or to a shared-memory mapping. Both keep their object references in
            // a deferred queue that may only be drained outside the object table
            // lock, so drain it here, after the close completed.
            let _ = ipc::release_subscription_pending();
            let _ = vmobj::release_pending();
            ok(0)
        }
        Some(Err(error)) => err(object_status(error)),
    }
}

// ---------------------------------------------------------------------------
// ABI 0.2 file calls (7–17, 26)
// ---------------------------------------------------------------------------

/// Translate `open` flags into VFS options and the rights of the new handle.
///
/// Rights follow the flags exactly, as in POSIX: `OPEN_READ` grants
/// `RIGHT_READ`, `OPEN_WRITE` grants `RIGHT_WRITE`, and a caller that wants both
/// must ask for both (`OPEN_READ | OPEN_WRITE`). Nothing is implied, so a
/// write-only description cannot be read back through its own handle. Bits
/// outside `OPEN_VALID` are reserved and rejected, as are `TRUNC` without
/// `WRITE` and a request that asks for neither reading nor writing.
fn open_options(flags: u32) -> Result<(OpenOptions, Rights), u64> {
    if flags & !OPEN_VALID != 0 {
        return Err(ERR_BAD_REQUEST);
    }
    let read = flags & OPEN_READ != 0;
    let write = flags & OPEN_WRITE != 0;
    if !read && !write {
        return Err(ERR_BAD_REQUEST);
    }
    if flags & OPEN_TRUNC != 0 && !write {
        return Err(ERR_BAD_REQUEST);
    }
    let mut rights = Rights::NONE;
    if read {
        rights = rights.union(Rights::READ);
    }
    if write {
        rights = rights.union(Rights::WRITE);
    }
    Ok((
        OpenOptions {
            read,
            write,
            create: flags & OPEN_CREATE != 0,
            truncate: flags & OPEN_TRUNC != 0,
        },
        rights,
    ))
}

/// `open`: resolve a path into a `File` handle that owns the description.
fn open(request_ptr: u64) -> SyscallRet {
    let Some(address_space) = current_address_space() else {
        return err(ERR_BAD_REQUEST);
    };
    // The description must belong to the calling process: POSIX byte-range locks
    // are process-owned, so a description opened with a hard-coded owner would
    // make every process the same lock owner and no cross-process conflict could
    // ever be observed.
    let Some(owner) = process::current_process_id() else {
        return err(ERR_BAD_HANDLE);
    };
    let mut request = native_abi::OpenRequest::new(0, 0, 0);
    if let Err(status) = copy_in_struct(address_space, request_ptr, &mut request) {
        return err(status);
    }
    if request.size != native_abi::OpenRequest::SIZE || request.version != REQUEST_VERSION {
        return err(ERR_BAD_REQUEST);
    }
    if request.reserved != 0 {
        return err(ERR_BAD_REQUEST);
    }
    let (options, rights) = match open_options(request.flags) {
        Ok(translated) => translated,
        Err(status) => return err(status),
    };
    let mut path_buffer = [0u8; vfs::MAX_PATH];
    let path = match copy_path(
        address_space,
        request.path_ptr,
        request.path_len as u64,
        &mut path_buffer,
    ) {
        Ok(path) => path,
        Err(status) => return err(status),
    };
    let open = match vfs::open_path_as(path, options, owner) {
        Ok(open) => open,
        Err(error) => return err(vfs_status(error)),
    };
    // The description carries the node kind; the `OPEN_DIRECTORY` expectation
    // is enforced here so the ABI reports `NOT_DIR`/`IS_DIR` precisely.
    let kind = match vfs::stat_open(open) {
        Ok(stat) => stat.kind,
        Err(error) => {
            let _ = vfs::close(open);
            return err(vfs_status(error));
        }
    };
    let wants_directory = request.flags & OPEN_DIRECTORY != 0;
    if wants_directory && kind != NodeKind::Directory {
        let _ = vfs::close(open);
        return err(ERR_NOT_DIR);
    }
    if !wants_directory && kind == NodeKind::Directory {
        let _ = vfs::close(open);
        return err(ERR_IS_DIR);
    }
    // A failed insertion releases the initial reference, which fires the `File`
    // destroy hook; the guard makes that hook run with the process lock released.
    let inserted = process::take_current_handles().map(|mut guard| {
        object::insert_new_with_payload(
            guard.table_mut(),
            ObjectKind::File,
            open.raw() as u64,
            rights,
        )
    });
    match inserted {
        None => {
            let _ = vfs::close(open);
            err(ERR_BAD_HANDLE)
        }
        Some(Ok(handle)) => ok(handle.raw() as u64),
        // On insertion failure `insert_new_with_payload` has already released
        // the initial reference, which fired the destroy hook and closed the
        // description: nothing leaks and nothing is closed twice.
        Some(Err(error)) => err(object_status(error)),
    }
}

/// `read`: copy bytes from the file description's current offset.
///
/// The read is all-or-nothing per chunk: the description's offset is recorded
/// before the bytes are taken and put back if they cannot be delivered to user
/// memory, so a `BAD_POINTER` never consumes data the caller did not receive.
/// A directory is rejected by the VFS before any byte is taken, so it never
/// reaches the rewind path.
fn read(raw_handle: u64, ptr: u64, len: u64) -> SyscallRet {
    if len > MAX_IO_BYTES {
        return err(ERR_BAD_REQUEST);
    }
    let Some(address_space) = current_address_space() else {
        return err(ERR_BAD_REQUEST);
    };
    let open = match file_open(raw_handle, Rights::READ) {
        Ok(open) => open,
        Err(status) => return err(status),
    };
    if len == 0 {
        return ok(0);
    }
    let mut buffer = [0u8; IO_CHUNK];
    let mut done = 0u64;
    while done < len {
        let chunk = core::cmp::min(IO_CHUNK as u64, len - done) as usize;
        let before = match vfs::offset(open) {
            Ok(offset) => offset,
            Err(error) => return err(vfs_status(error)),
        };
        let filled = match vfs::read(open, &mut buffer[..chunk]) {
            Ok(filled) => filled,
            Err(error) => return err(vfs_status(error)),
        };
        if filled == 0 {
            // End of file: a short (possibly zero-length) read is success.
            break;
        }
        // The bytes are already out of the file; if they cannot reach the
        // caller's buffer, undo the read instead of silently dropping them.
        let delivered = ptr.checked_add(done).is_some_and(|address| {
            addrspace::copy_out(address_space, address, &buffer[..filled]).is_ok()
        });
        if !delivered {
            return err(rewind(open, before));
        }
        done += filled as u64;
        if filled < chunk {
            break;
        }
    }
    ok(done)
}

/// Put a description back to `offset` after a read whose bytes were never
/// delivered, and return the status to report.
///
/// The rewind itself can only fail on a corrupt description table; that is not
/// a bad pointer any more, so it is reported loudly as an I/O failure.
fn rewind(open: OpenId, offset: u64) -> u64 {
    match vfs::seek_from(open, SeekFrom::Start(offset)) {
        Ok(_) => ERR_BAD_POINTER,
        Err(error) => {
            crate::klog!(
                "[CaelumKernel] M5c1 FAIL read offset rewind after a failed copy-out: {}",
                error.as_str()
            );
            ERR_IO
        }
    }
}

/// `stat`: fill the caller's `StatOut` from the description's node.
fn stat(raw_handle: u64, out_ptr: u64) -> SyscallRet {
    let Some(address_space) = current_address_space() else {
        return err(ERR_BAD_REQUEST);
    };
    let mut out = StatOut::empty();
    if let Err(status) = copy_in_struct(address_space, out_ptr, &mut out) {
        return err(status);
    }
    if out.size != StatOut::SIZE || out.version != REQUEST_VERSION {
        return err(ERR_BAD_REQUEST);
    }
    let open = match file_open(raw_handle, Rights::NONE) {
        Ok(open) => open,
        Err(status) => return err(status),
    };
    let stat = match vfs::stat_open(open) {
        Ok(stat) => stat,
        Err(error) => return err(vfs_status(error)),
    };
    let filled = StatOut {
        size: StatOut::SIZE,
        version: REQUEST_VERSION,
        kind: node_kind(stat.kind),
        flags: if stat.read_only {
            native_abi::STAT_FLAG_READ_ONLY
        } else {
            0
        },
        file_size: if stat.kind == NodeKind::File {
            stat.size
        } else {
            0
        },
        reserved: 0,
    };
    if let Err(status) = copy_out_struct(address_space, out_ptr, &filled) {
        return err(status);
    }
    ok(0)
}

/// `readdir`: write the directory entry at `index` into the caller's buffer.
fn readdir(raw_handle: u64, index: u64, out_ptr: u64) -> SyscallRet {
    let Some(address_space) = current_address_space() else {
        return err(ERR_BAD_REQUEST);
    };
    let mut out = DirEntryOut::empty();
    if let Err(status) = copy_in_struct(address_space, out_ptr, &mut out) {
        return err(status);
    }
    if out.size != DirEntryOut::SIZE || out.version != REQUEST_VERSION {
        return err(ERR_BAD_REQUEST);
    }
    let open = match file_open(raw_handle, Rights::READ) {
        Ok(open) => open,
        Err(status) => return err(status),
    };
    // Only a directory description can be enumerated; the kind is checked
    // before the index so a bad index never hides a wrong node kind.
    match vfs::stat_open(open) {
        Ok(stat) if stat.kind == NodeKind::Directory => {}
        Ok(_) => return err(ERR_NOT_DIR),
        Err(error) => return err(vfs_status(error)),
    }
    if index > u32::MAX as u64 {
        // No directory has that many entries; treat it as the end of the list.
        return err(ERR_NOT_FOUND);
    }
    let mut entries = [DirEntry::empty(); 1];
    let count = match vfs::readdir_open(open, index as usize, &mut entries) {
        Ok(count) => count,
        Err(error) => return err(vfs_status(error)),
    };
    if count == 0 {
        return err(ERR_NOT_FOUND);
    }
    let entry = entries[0];
    let mut name = [0u8; DirEntryOut::NAME_LEN];
    let name_len = (entry.name_len as usize).min(name.len());
    name[..name_len].copy_from_slice(&entry.name()[..name_len]);
    let filled = DirEntryOut {
        size: DirEntryOut::SIZE,
        version: REQUEST_VERSION,
        kind: node_kind(entry.kind),
        name_len: name_len as u32,
        name,
        file_size: if entry.kind == NodeKind::File {
            entry.size
        } else {
            0
        },
    };
    if let Err(status) = copy_out_struct(address_space, out_ptr, &filled) {
        return err(status);
    }
    ok(0)
}

/// `mkdir`: create one directory (no intermediate components).
fn mkdir(ptr: u64, len: u64) -> SyscallRet {
    path_mutation(ptr, len, |path| vfs::mkdir_path(path).map(|_| ()))
}

/// `rmdir`: remove an empty directory.
fn rmdir(ptr: u64, len: u64) -> SyscallRet {
    path_mutation(ptr, len, vfs::rmdir_path)
}

/// `unlink`: remove a regular file.
fn unlink(ptr: u64, len: u64) -> SyscallRet {
    path_mutation(ptr, len, vfs::unlink_path)
}

/// Copy a user path and run one VFS mutation on it.
fn path_mutation(
    ptr: u64,
    len: u64,
    operation: impl FnOnce(&[u8]) -> Result<(), VfsError>,
) -> SyscallRet {
    let Some(address_space) = current_address_space() else {
        return err(ERR_BAD_REQUEST);
    };
    let mut path_buffer = [0u8; vfs::MAX_PATH];
    let path = match copy_path(address_space, ptr, len, &mut path_buffer) {
        Ok(path) => path,
        Err(status) => return err(status),
    };
    match operation(path) {
        Ok(()) => ok(0),
        Err(error) => err(vfs_status(error)),
    }
}

/// `rename`: move one name to another inside a single backing store.
fn rename(request_ptr: u64) -> SyscallRet {
    let Some(address_space) = current_address_space() else {
        return err(ERR_BAD_REQUEST);
    };
    let mut request = native_abi::RenameRequest::new(0, 0, 0, 0);
    if let Err(status) = copy_in_struct(address_space, request_ptr, &mut request) {
        return err(status);
    }
    if request.size != native_abi::RenameRequest::SIZE || request.version != REQUEST_VERSION {
        return err(ERR_BAD_REQUEST);
    }
    if request.reserved != 0 {
        return err(ERR_BAD_REQUEST);
    }
    let mut old_buffer = [0u8; vfs::MAX_PATH];
    let old_path = match copy_path(
        address_space,
        request.old_ptr,
        request.old_len as u64,
        &mut old_buffer,
    ) {
        Ok(path) => path,
        Err(status) => return err(status),
    };
    let mut new_buffer = [0u8; vfs::MAX_PATH];
    let new_path = match copy_path(
        address_space,
        request.new_ptr,
        request.new_len as u64,
        &mut new_buffer,
    ) {
        Ok(path) => path,
        Err(status) => return err(status),
    };
    match vfs::rename_path(old_path, new_path) {
        Ok(()) => ok(0),
        // The VFS refuses any move that spans two backing stores (different
        // mounts, or a disk node to a ramfs node) with `NotSupported`; the ABI
        // names exactly that situation `CROSS_DEVICE`.
        Err(VfsError::NotSupported) => err(ERR_CROSS_DEVICE),
        Err(error) => err(vfs_status(error)),
    }
}

/// `sync`: flush the description's dirty pages and the device they live on.
fn sync(raw_handle: u64) -> SyscallRet {
    let open = match file_open(raw_handle, Rights::WRITE) {
        Ok(open) => open,
        Err(status) => return err(status),
    };
    // Writes through a shared mapping touch page-cache frames without going
    // through `write`, so the page cache does not know they are dirty. Mark
    // every page of every shared mapping of this description dirty first, so
    // `sync` really flushes them. Private mappings are copies and are skipped.
    if let Err(error) = vmobj::mark_shared_dirty(open) {
        return err(map_status(error));
    }
    match vfs::sync_open(open) {
        Ok(()) => ok(0),
        Err(error) => err(vfs_status(error)),
    }
}

/// Translate `seek` arguments into a VFS request.
fn seek_request(whence: u64, raw_offset: u64) -> Result<SeekFrom, u64> {
    if whence == SEEK_SET as u64 {
        Ok(SeekFrom::Start(raw_offset))
    } else if whence == SEEK_CUR as u64 {
        Ok(SeekFrom::Current(raw_offset as i64))
    } else if whence == SEEK_END as u64 {
        Ok(SeekFrom::End(raw_offset as i64))
    } else {
        Err(ERR_BAD_REQUEST)
    }
}

/// `seek`: reposition the description and report the new offset.
fn seek(raw_handle: u64, raw_offset: u64, raw_whence: u64) -> SyscallRet {
    let from = match seek_request(raw_whence, raw_offset) {
        Ok(from) => from,
        Err(status) => return err(status),
    };
    let open = match file_open(raw_handle, Rights::NONE) {
        Ok(open) => open,
        Err(status) => return err(status),
    };
    match vfs::seek_from(open, from) {
        Ok(offset) => ok(offset),
        // A negative result or an arithmetic overflow leaves the offset
        // unchanged; the ABI accepts `BAD_REQUEST` for both.
        Err(VfsError::BadOffset) => err(ERR_BAD_REQUEST),
        Err(error) => err(vfs_status(error)),
    }
}

/// Validate the rights requested by `dup`.
fn dup_rights(raw_rights: u64) -> Result<Rights, u64> {
    if raw_rights == 0 || raw_rights > u32::MAX as u64 {
        return Err(ERR_BAD_RIGHT);
    }
    let rights = Rights::from_bits(raw_rights as u32).ok_or(ERR_BAD_RIGHT)?;
    if rights.is_empty() {
        return Err(ERR_BAD_RIGHT);
    }
    Ok(rights)
}

/// `dup`: duplicate a handle inside the calling process's table.
///
/// Both handles carry the same object (and therefore the same `OpenId`
/// payload), so they share the description's offset and truncate state while
/// each has its own rights. No `vfs::dup` is needed: the object refcount is
/// what keeps the single description alive.
fn dup(raw_handle: u64, raw_rights: u64) -> SyscallRet {
    let rights = match dup_rights(raw_rights) {
        Ok(rights) => rights,
        Err(status) => return err(status),
    };
    if raw_handle > u32::MAX as u64 {
        return err(ERR_BAD_HANDLE);
    }
    let handle = Handle::from_raw(raw_handle as u32);
    let duplicated = process::with_current_handles(|table| {
        object::with_object_table(|objects| table.duplicate(objects, handle, rights))
    });
    match duplicated {
        None => err(ERR_BAD_HANDLE),
        Some(Ok(new_handle)) => ok(new_handle.raw() as u64),
        Some(Err(error)) => err(object_status(error)),
    }
}

/// `truncate`: resize the description's file (growing zero-fills).
fn truncate(raw_handle: u64, len: u64) -> SyscallRet {
    let open = match file_open(raw_handle, Rights::WRITE) {
        Ok(open) => open,
        Err(status) => return err(status),
    };
    match vfs::truncate_open(open, len) {
        Ok(_) => ok(0),
        Err(VfsError::IsDirectory) => err(ERR_IS_DIR),
        // A length the file system cannot represent is "too large", not a
        // malformed request.
        Err(VfsError::BadOffset) => err(ERR_TOO_LARGE),
        Err(VfsError::Quota) | Err(VfsError::NoMemory) => err(ERR_NO_SPACE),
        Err(error) => err(vfs_status(error)),
    }
}

// ---------------------------------------------------------------------------
// Memory mapping (M5c2)
// ---------------------------------------------------------------------------

/// Rights a mapping needs on the underlying `File` handle.
///
/// Every mapping reads file pages once, so `READ` is mandatory. A *shared*
/// writable mapping writes through to the file, so it additionally needs
/// `WRITE`; a private writable mapping only ever writes to its own copy.
fn map_rights(plan: &MapPlan) -> Rights {
    if plan.shared && plan.prot & native_abi::PROT_WRITE != 0 {
        Rights::READ.union(Rights::WRITE)
    } else {
        Rights::READ
    }
}

/// Close a `VmObject` handle, letting its destroy hook tear the mapping down.
///
/// Returns `true` when the handle was closed. A failure here would leak the
/// mapping, so the caller falls back to a direct release.
fn close_mapping_handle(handle: Handle) -> bool {
    process::take_current_handles()
        .is_some_and(|mut guard| object::close_handle(guard.table_mut(), handle).is_ok())
}

/// `mmap`: map part of the file behind `raw_handle` into the caller's space.
///
/// Arguments: `rdi` = `File` handle, `rsi` = user pointer to a 48-byte
/// [`native_abi::MmapRequest`]. On success `rdx` (the `result` register) holds
/// the new `VmObject` handle and the base address was copied out to
/// `request.out_address`.
///
/// The mapping is owned by a capability: closing the returned handle (or the
/// process exiting) runs the `VmObject` destroy hook, which unmaps the range.
fn mmap(raw_handle: u64, request_ptr: u64) -> SyscallRet {
    let address_space = match current_address_space() {
        Some(id) => id,
        None => return err(ERR_BAD_HANDLE),
    };
    let mut request = native_abi::MmapRequest::new(0, 0, 0, 0, 0);
    if let Err(status) = copy_in_struct(address_space, request_ptr, &mut request) {
        return err(status);
    }
    let plan = match map_request(&request) {
        Ok(plan) => plan,
        Err(status) => return err(status),
    };
    let open = match file_open(raw_handle, map_rights(&plan)) {
        Ok(open) => open,
        Err(status) => return err(status),
    };
    let (mapping_id, base) = match vmobj::map(
        address_space,
        open,
        plan.len,
        plan.offset,
        plan.prot,
        plan.shared,
    ) {
        Ok(mapping) => mapping,
        Err(error) => return err(map_status(error)),
    };
    // Publish the mapping as a `VmObject` capability. If the insertion fails the
    // object layer has already dropped the initial reference, which runs the
    // destroy hook and rolls the mapping back; `unmap` below is then a no-op.
    // The guard keeps that hook out of the process-lock window.
    let inserted = process::take_current_handles().map(|mut guard| {
        object::insert_new_with_payload(
            guard.table_mut(),
            ObjectKind::VmObject,
            u64::from(mapping_id),
            Rights::MAP,
        )
    });
    let handle = match inserted {
        Some(Ok(handle)) => handle,
        Some(Err(error)) => {
            let _ = vmobj::unmap(address_space, base, plan.len);
            return err(object_status(error));
        }
        None => {
            let _ = vmobj::unmap(address_space, base, plan.len);
            return err(ERR_BAD_HANDLE);
        }
    };
    // The base address is the only thing the caller needs to use the mapping, so
    // it is copied out *after* the handle exists: a bad out pointer rolls the
    // whole mapping back through the hook instead of leaving it half-visible.
    if copy_out_struct(address_space, plan.out_address, &base).is_err() {
        if !close_mapping_handle(handle) {
            let _ = vmobj::unmap(address_space, base, plan.len);
        }
        return err(ERR_BAD_POINTER);
    }
    ok(handle.raw() as u64)
}

/// `munmap`: remove the mapping that covers exactly `(addr, len)`.
///
/// The mapping is released by closing its `VmObject` handle, so the destroy hook
/// runs the same teardown path as a plain `handle_close`. A range with no live
/// mapping is `NOT_FOUND`.
fn munmap(addr: u64, len: u64) -> SyscallRet {
    if let Err(status) = map_range(addr, len) {
        return err(status);
    }
    let address_space = match current_address_space() {
        Some(id) => id,
        None => return err(ERR_BAD_HANDLE),
    };
    let payload = match vmobj::mapping_payload(address_space, addr, len) {
        Some(payload) => payload,
        None => return err(ERR_NOT_FOUND),
    };
    // `close_payload` runs the `VmObject` destroy hook; the guard releases the
    // process lock first so the hook may take the VFS/IPC locks.
    let closed = process::take_current_handles()
        .map(|mut guard| object::close_payload(guard.table_mut(), ObjectKind::VmObject, payload));
    match closed {
        Some(Ok(true)) => {
            // The destroy hook only queued the shared-memory object reference;
            // releasing it must happen outside the handle-table lock.
            let _ = vmobj::release_pending();
            ok(0)
        }
        // No handle is live for this mapping: it was already torn down, so the
        // range is not mapped any more.
        Some(Ok(false)) => err(ERR_NOT_FOUND),
        Some(Err(error)) => err(object_status(error)),
        None => err(ERR_BAD_HANDLE),
    }
}

/// `mprotect`: change the permissions of the mapping covering `(addr, len)`.
///
/// Only permissions change; the frames, offset and sharing mode stay as they
/// are, and nothing is flushed.
fn mprotect(addr: u64, len: u64, raw_prot: u64) -> SyscallRet {
    if raw_prot > u32::MAX as u64 {
        return err(ERR_BAD_REQUEST);
    }
    if let Err(status) = map_range(addr, len) {
        return err(status);
    }
    let prot = match protect_bits(raw_prot as u32) {
        Ok(prot) => prot,
        Err(status) => return err(status),
    };
    let address_space = match current_address_space() {
        Some(id) => id,
        None => return err(ERR_BAD_HANDLE),
    };
    match vmobj::protect(address_space, addr, len, prot) {
        Ok(()) => ok(0),
        Err(error) => err(map_status(error)),
    }
}

// ---------------------------------------------------------------------------
// File locks (M5c3)
// ---------------------------------------------------------------------------

/// Translate an ABI lock domain; `0` and out-of-range values are malformed.
fn lock_domain(raw: u32) -> Result<vfs::lock::LockDomain, u64> {
    if raw == 0 || raw > LOCK_DOMAIN_MAX {
        return Err(ERR_BAD_REQUEST);
    }
    match raw {
        LOCK_DOMAIN_POSIX => Ok(vfs::lock::LockDomain::Posix),
        LOCK_DOMAIN_OFD => Ok(vfs::lock::LockDomain::OpenDescription),
        LOCK_DOMAIN_FLOCK => Ok(vfs::lock::LockDomain::Flock),
        _ => Err(ERR_BAD_REQUEST),
    }
}

/// A validated `lock` request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct LockPlan {
    domain: vfs::lock::LockDomain,
    /// `None` means "unlock"; the VFS needs no kind to release a range.
    kind: Option<vfs::lock::LockKind>,
    offset: u64,
    len: u64,
    /// Right the file handle must carry for this operation.
    required: Rights,
}

/// Validate one `lock` request before any handle or VFS state is touched.
fn lock_plan(request: &LockRequest) -> Result<LockPlan, u64> {
    if request.size != LockRequest::SIZE || request.version != REQUEST_VERSION {
        return Err(ERR_BAD_REQUEST);
    }
    let domain = lock_domain(request.domain)?;
    if request.operation == 0 || request.operation > LOCK_OP_MAX {
        return Err(ERR_BAD_REQUEST);
    }
    let (kind, required) = match request.operation {
        LOCK_OP_SHARED => (Some(vfs::lock::LockKind::Shared), Rights::READ),
        LOCK_OP_EXCLUSIVE => (Some(vfs::lock::LockKind::Exclusive), Rights::WRITE),
        LOCK_OP_UNLOCK => (None, Rights::NONE),
        _ => return Err(ERR_BAD_REQUEST),
    };
    Ok(LockPlan {
        domain,
        kind,
        offset: request.offset,
        len: request.len,
        required,
    })
}

/// `lock`: apply or release a byte-range lock on an open file.
///
/// A shared lock needs a readable handle and an exclusive one a writable
/// handle; the VFS independently checks the description's own mode. Unlocking
/// names a range the caller is expected to own, so it needs no extra right.
fn lock(raw_handle: u64, request_ptr: u64) -> SyscallRet {
    let Some(address_space) = current_address_space() else {
        return err(ERR_BAD_HANDLE);
    };
    let mut request = LockRequest::new(0, 0, 0, 0);
    if let Err(status) = copy_in_struct(address_space, request_ptr, &mut request) {
        return err(status);
    }
    let plan = match lock_plan(&request) {
        Ok(plan) => plan,
        Err(status) => return err(status),
    };
    let open = match file_open(raw_handle, plan.required) {
        Ok(open) => open,
        Err(status) => return err(status),
    };
    let result = match plan.kind {
        Some(kind) => vfs::lock_open(open, plan.domain, kind, plan.offset, plan.len),
        None => vfs::unlock_open(open, plan.domain, plan.offset, plan.len),
    };
    match result {
        Ok(()) => ok(0),
        Err(error) => err(vfs_status(error)),
    }
}

// ---------------------------------------------------------------------------
// Extended attributes (M5c3)
// ---------------------------------------------------------------------------

/// A validated `xattr` request: the name copied in plus the value buffers.
struct XattrPlan {
    name: [u8; MAX_XATTR_NAME],
    name_len: usize,
    value_ptr: u64,
    value_len: usize,
}

/// Validate the fixed part of an `xattr` request; returns the name length.
fn xattr_header(request: &XattrRequest) -> Result<usize, u64> {
    if request.size != XattrRequest::SIZE || request.version != REQUEST_VERSION {
        return Err(ERR_BAD_REQUEST);
    }
    if request.name_len == 0 || request.name_len > MAX_XATTR_NAME as u64 {
        return Err(ERR_BAD_REQUEST);
    }
    Ok(request.name_len as usize)
}

/// Only the `user.` namespace is exposed in ABI 0.2. A foreign namespace is a
/// well-formed request for something this version does not support, so it is
/// `NOT_SUPPORTED` rather than a malformed request.
fn xattr_name(name: &[u8]) -> Result<(), u64> {
    if name.contains(&0) {
        return Err(ERR_BAD_REQUEST);
    }
    if !name.starts_with(XATTR_USER_PREFIX) {
        return Err(ERR_NOT_SUPPORTED);
    }
    Ok(())
}

/// Validate an `xattr` request and copy the attribute name into the kernel.
///
/// The value buffer is *not* copied here: `set` copies it in afterwards and
/// `get` treats `value_len` as the caller's capacity, so the two directions
/// interpret the same field differently.
fn xattr_plan(address_space: AddressSpaceId, request_ptr: u64) -> Result<XattrPlan, u64> {
    let mut request = XattrRequest::new(0, 0, 0, 0);
    copy_in_struct(address_space, request_ptr, &mut request)?;
    let name_len = xattr_header(&request)?;
    let mut name = [0u8; MAX_XATTR_NAME];
    addrspace::copy_in(address_space, request.name_ptr, &mut name[..name_len])
        .map_err(|_| ERR_BAD_POINTER)?;
    xattr_name(&name[..name_len])?;
    Ok(XattrPlan {
        name,
        name_len,
        value_ptr: request.value_ptr,
        value_len: request.value_len as usize,
    })
}

/// `xattr_set`: store one attribute on the file behind `handle`.
fn xattr_set(raw_handle: u64, request_ptr: u64) -> SyscallRet {
    let Some(address_space) = current_address_space() else {
        return err(ERR_BAD_HANDLE);
    };
    let plan = match xattr_plan(address_space, request_ptr) {
        Ok(plan) => plan,
        Err(status) => return err(status),
    };
    if plan.value_len > MAX_XATTR_VALUE {
        return err(ERR_TOO_LARGE);
    }
    let mut value = [0u8; MAX_XATTR_VALUE];
    if plan.value_len > 0 {
        if addrspace::copy_in(address_space, plan.value_ptr, &mut value[..plan.value_len]).is_err()
        {
            return err(ERR_BAD_POINTER);
        }
    }
    let open = match file_open(raw_handle, Rights::WRITE) {
        Ok(open) => open,
        Err(status) => return err(status),
    };
    match vfs::xattr_set_open(open, &plan.name[..plan.name_len], &value[..plan.value_len]) {
        Ok(()) => ok(0),
        Err(error) => err(vfs_status(error)),
    }
}

/// `xattr_get`: read one attribute into the caller's buffer.
///
/// The value is assembled in a kernel buffer first, so a buffer that is too
/// small fails with `TOO_LARGE` and leaves user memory untouched.
fn xattr_get(raw_handle: u64, request_ptr: u64) -> SyscallRet {
    let Some(address_space) = current_address_space() else {
        return err(ERR_BAD_HANDLE);
    };
    let plan = match xattr_plan(address_space, request_ptr) {
        Ok(plan) => plan,
        Err(status) => return err(status),
    };
    let open = match file_open(raw_handle, Rights::READ) {
        Ok(open) => open,
        Err(status) => return err(status),
    };
    let mut value = [0u8; MAX_XATTR_VALUE];
    let len = match vfs::xattr_get_open(open, &plan.name[..plan.name_len], &mut value) {
        Ok(len) => len,
        Err(error) => return err(vfs_status(error)),
    };
    if len > plan.value_len {
        return err(ERR_TOO_LARGE);
    }
    if len > 0 && addrspace::copy_out(address_space, plan.value_ptr, &value[..len]).is_err() {
        return err(ERR_BAD_POINTER);
    }
    ok(len as u64)
}

// ---------------------------------------------------------------------------
// Directory watches (M5c3)
// ---------------------------------------------------------------------------

/// Event kind as the ABI numbers it.
fn notify_kind(kind: vfs::notify::NotifyKind) -> u32 {
    match kind {
        vfs::notify::NotifyKind::Created => WATCH_EVENT_CREATED,
        vfs::notify::NotifyKind::Deleted => WATCH_EVENT_DELETED,
        vfs::notify::NotifyKind::Renamed => WATCH_EVENT_RENAMED,
    }
}

/// `watch`: start watching a directory on behalf of the calling process.
///
/// The watch id lives inside a `Watch` object, so closing the last handle (or
/// the process dying) stops the watch through the destroy hook.
fn watch(path_ptr: u64, path_len: u64) -> SyscallRet {
    let Some(address_space) = current_address_space() else {
        return err(ERR_BAD_HANDLE);
    };
    let mut buffer = [0u8; vfs::MAX_PATH];
    let path = match copy_path(address_space, path_ptr, path_len, &mut buffer) {
        Ok(path) => path,
        Err(status) => return err(status),
    };
    let Some(owner) = process::current_process_id() else {
        return err(ERR_BAD_HANDLE);
    };
    let id = match vfs::watch_directory_as(path, owner) {
        Ok(id) => id,
        Err(error) => return err(vfs_status(error)),
    };
    let payload = object::watch_payload(owner, u32::from(id.raw()));
    // The insertion can fail after the watch object exists; that releases the
    // initial reference and runs the `Watch` destroy hook, so it must not happen
    // under the process lock.
    let inserted = process::take_current_handles().map(|mut guard| {
        object::insert_new_with_payload(guard.table_mut(), ObjectKind::Watch, payload, Rights::READ)
    });
    match inserted {
        Some(Ok(handle)) => ok(handle.raw() as u64),
        Some(Err(error)) => {
            // The watch exists but no handle owns it: roll it back so a failed
            // call never leaves a live watch behind.
            let _ = vfs::watch_unwatch_owned(id, owner);
            err(object_status(error))
        }
        None => {
            let _ = vfs::watch_unwatch_owned(id, owner);
            err(ERR_BAD_HANDLE)
        }
    }
}

/// Validate a `watch_drain` request; returns the batch size.
fn watch_drain_count(request: &WatchDrainRequest) -> Result<usize, u64> {
    if request.size != WatchDrainRequest::SIZE || request.version != REQUEST_VERSION {
        return Err(ERR_BAD_REQUEST);
    }
    if request.max_events == 0 || request.max_events > WATCH_MAX_BATCH {
        return Err(ERR_BAD_REQUEST);
    }
    Ok(request.max_events as usize)
}

/// `watch_drain`: copy pending events of a watch into the caller's buffer.
fn watch_drain(raw_handle: u64, request_ptr: u64) -> SyscallRet {
    let Some(address_space) = current_address_space() else {
        return err(ERR_BAD_HANDLE);
    };
    let mut request = WatchDrainRequest::new(0, 0);
    if let Err(status) = copy_in_struct(address_space, request_ptr, &mut request) {
        return err(status);
    }
    let wanted = match watch_drain_count(&request) {
        Ok(wanted) => wanted,
        Err(status) => return err(status),
    };
    let resolved = match resolve_handle_any(raw_handle, Rights::READ) {
        Ok(resolved) => resolved,
        Err(status) => return err(status),
    };
    if resolved.kind != ObjectKind::Watch {
        return err(ERR_BAD_HANDLE);
    }
    let Some(payload) = object_payload(resolved.object) else {
        return err(ERR_BAD_HANDLE);
    };
    let owner = object::watch_payload_owner(payload);
    // A watch may only be drained by the process that created it, which is also
    // the owner the VFS recorded; a mismatch is a rights failure.
    let Some(current) = process::current_process_id() else {
        return err(ERR_BAD_HANDLE);
    };
    if owner != current {
        return err(ERR_BAD_RIGHT);
    }
    let id = vfs::notify::WatchId(object::watch_payload_id(payload) as u8);
    let mut out = [WatchEventOut::empty(); MAX_WATCH_EVENTS];
    // The ABI requires `events_ptr` to cover `max_events` records. Validate the
    // whole range *before* draining, so a bad pointer can never consume events
    // that then fail to reach the caller.
    if addrspace::copy_out(
        address_space,
        request.events_ptr,
        record_bytes(&out[..wanted]),
    )
    .is_err()
    {
        return err(ERR_BAD_POINTER);
    }
    let mut events = [vfs::notify::NotifyEvent::empty(); MAX_WATCH_EVENTS];
    let count = match vfs::watch_drain_owned(id, owner, &mut events[..wanted]) {
        Ok(count) => count,
        Err(error) => return err(vfs_status(error)),
    };
    let dropped = vfs::notify::dropped_owned(id, owner).unwrap_or(0);
    for (slot, event) in out.iter_mut().zip(events[..count].iter()) {
        let name = event.child.as_bytes();
        slot.kind = notify_kind(event.kind);
        slot.name_len = name.len() as u32;
        slot.name[..name.len()].copy_from_slice(name);
        slot.dropped = dropped;
    }
    if count > 0
        && addrspace::copy_out(
            address_space,
            request.events_ptr,
            record_bytes(&out[..count]),
        )
        .is_err()
    {
        return err(ERR_BAD_POINTER);
    }
    ok(count as u64)
}

/// A slice of ABI records viewed as bytes.
fn record_bytes(records: &[WatchEventOut]) -> &[u8] {
    // SAFETY: `WatchEventOut` is `repr(C)` and every field is plain data, so its
    // bytes may be read; the length is derived from the slice itself.
    unsafe {
        core::slice::from_raw_parts(
            records.as_ptr().cast::<u8>(),
            records.len() * core::mem::size_of::<WatchEventOut>(),
        )
    }
}

/// Stop the watch owned by a dying `Watch` object.
///
/// Runs from the object layer with interrupts disabled; the payload records the
/// original owner, so a watch created by another (already dead) process is still
/// released against the right owner.
fn release_watch(_kind: ObjectKind, payload: u64) {
    let owner = object::watch_payload_owner(payload);
    let id = vfs::notify::WatchId(object::watch_payload_id(payload) as u8);
    let _ = vfs::watch_unwatch_owned(id, owner);
}

// ---------------------------------------------------------------------------
// Status mapping
// ---------------------------------------------------------------------------

/// Node kind as the ABI numbers it.
fn node_kind(kind: NodeKind) -> u32 {
    match kind {
        NodeKind::File => native_abi::NODE_FILE,
        NodeKind::Directory => native_abi::NODE_DIRECTORY,
        // M8h: the native ABI has no device class. Character devices behave
        // like byte files for native callers (`/dev/null` and `/dev/zero` are
        // openable, reads produce zero bytes or EOF and writes succeed), so
        // they are reported as files. A dedicated `NODE_DEVICE` value would be
        // an ABI addition and is not introduced here.
        NodeKind::CharDevice => native_abi::NODE_FILE,
    }
}

/// Resolve a handle of the calling process, requiring a kind and a right.
fn check_handle(raw_handle: u64, kind: ObjectKind, required: Rights) -> Result<(), u64> {
    if raw_handle > u32::MAX as u64 {
        return Err(ERR_BAD_HANDLE);
    }
    let handle = Handle::from_raw(raw_handle as u32);
    let resolved = process::with_current_handles(|table| {
        object::resolve_as_handle(table, handle, kind, required)
    })
    .ok_or(ERR_BAD_HANDLE)?;
    match resolved {
        Ok(_) => Ok(()),
        Err(error) => Err(object_status(error)),
    }
}

/// Map a process-layer error onto the native ABI status codes.
///
/// M4 keeps this deliberately coarse: the ABI distinguishes a malformed
/// request, a rights escalation and quota exhaustion; every other failure
/// collapses to `BAD_REQUEST` and the process layer logs the precise reason.
fn process_status(error: ProcessError) -> u64 {
    match error {
        ProcessError::BadRequest => ERR_BAD_REQUEST,
        ProcessError::RightsEscalation => ERR_BAD_RIGHT,
        ProcessError::NoFreeSlot => ERR_QUOTA,
        ProcessError::Objects(error) => object_status(error),
        _ => ERR_BAD_REQUEST,
    }
}

/// Map an object-layer error onto the native ABI status codes.
fn object_status(error: ObjectError) -> u64 {
    match error {
        ObjectError::BadHandle => ERR_BAD_HANDLE,
        // A rights set the caller asked for is wrong — empty, unknown bits, or
        // above the type's initial bound — the same answer `dup` gives for a
        // non-subset request.
        ObjectError::MissingRights | ObjectError::RightsEscalation | ObjectError::InvalidRights => {
            ERR_BAD_RIGHT
        }
        // A live handle of the wrong kind is reported as a bad handle: the ABI
        // does not tell a caller what an unusable handle points at.
        ObjectError::WrongObjectKind => ERR_BAD_HANDLE,
        ObjectError::ObjectTableFull | ObjectError::HandleTableFull => ERR_QUOTA,
        _ => ERR_BAD_REQUEST,
    }
}

/// Map a VFS error onto the native ABI status codes.
fn vfs_status(error: VfsError) -> u64 {
    match error {
        VfsError::NotFound => ERR_NOT_FOUND,
        VfsError::NotDirectory => ERR_NOT_DIR,
        VfsError::IsDirectory => ERR_IS_DIR,
        VfsError::AlreadyExists => ERR_EXISTS,
        VfsError::ReadOnly => ERR_READ_ONLY,
        // A path the VFS cannot parse (relative, escaping the root, too long)
        // is a malformed request, not a missing file.
        VfsError::BadPath | VfsError::NameTooLong => ERR_BAD_REQUEST,
        VfsError::Quota => ERR_QUOTA,
        VfsError::BadOffset => ERR_BAD_REQUEST,
        VfsError::PermissionDenied => ERR_BAD_RIGHT,
        VfsError::WouldBlock => ERR_WOULD_BLOCK,
        VfsError::NotSupported => ERR_NOT_SUPPORTED,
        VfsError::Corrupt => ERR_CORRUPT,
        VfsError::NoMemory => ERR_NO_SPACE,
        VfsError::Busy => ERR_BUSY,
        VfsError::NotEmpty => ERR_NOT_EMPTY,
        VfsError::Io => ERR_IO,
        VfsError::Timeout => ERR_TIMEOUT,
    }
}

/// Map an RNG error onto the native ABI status codes.
fn rng_status(error: crate::rng::RngError) -> u64 {
    match error {
        crate::rng::RngError::NoEntropy | crate::rng::RngError::NotCryptographic => ERR_NO_ENTROPY,
        crate::rng::RngError::BackendUnavailable => ERR_NOT_SUPPORTED,
    }
}

/// Map a VM mapping error onto the native ABI status codes.
fn map_status(error: vmobj::MapError) -> u64 {
    match error {
        vmobj::MapError::BadRequest => ERR_BAD_REQUEST,
        vmobj::MapError::NotFound => ERR_NOT_FOUND,
        vmobj::MapError::Quota => ERR_QUOTA,
        vmobj::MapError::Busy => ERR_BUSY,
        vmobj::MapError::Io => ERR_IO,
        // The ABI has no `ENOMEM`; an exhausted frame/address budget is closest
        // to "no space".
        vmobj::MapError::NoMemory => ERR_NO_SPACE,
        vmobj::MapError::NotSupported => ERR_NOT_SUPPORTED,
    }
}

// ---------------------------------------------------------------------------
// IPC syscalls (M6a1)
// ---------------------------------------------------------------------------

/// Rights a freshly created IPC handle carries.
///
/// One handle is the only way user space reaches the object in this stage, so it
/// must be signalable (`WRITE`), waitable (`WAIT`) and transferable
/// (`DUPLICATE`); `READ` is what a state query uses.
const IPC_HANDLE_RIGHTS: Rights = Rights::READ
    .union(Rights::WRITE)
    .union(Rights::WAIT)
    .union(Rights::DUPLICATE);

/// Map an [`IpcError`] onto the stable ABI status codes.
fn ipc_status(error: IpcError) -> u64 {
    match error {
        IpcError::TableFull => ERR_QUOTA,
        // A payload is decoded from a handle we just resolved, so a bad payload
        // means the object behind the handle is gone or not what we expected.
        IpcError::InvalidPayload | IpcError::WrongKind => ERR_BAD_HANDLE,
        IpcError::Object(error) => object_status(error),
        // A full queue is a retryable condition, not a malformed request: the
        // sender may wait for the peer to drain and try again.
        IpcError::WouldBlock => ERR_WOULD_BLOCK,
        // The peer went away while the message was in flight; the caller must
        // observe it instead of retrying a send that can never succeed.
        IpcError::PeerClosed => ERR_PEER_CLOSED,
        // Oversized payloads and over-full handle lists are reported as
        // `TOO_LARGE` so user space can tell "shrink it" from "malformed".
        IpcError::MessageTooLarge | IpcError::TooManyHandles => ERR_TOO_LARGE,
        IpcError::NotSupported => ERR_NOT_SUPPORTED,
        IpcError::InvalidEndpoint
        | IpcError::AlreadyBound
        | IpcError::NotBound
        | IpcError::NotArmed
        | IpcError::Overflow
        | IpcError::NotReceiver
        | IpcError::NotSender
        | IpcError::AlreadyLinked
        | IpcError::InvalidSequence => ERR_BAD_REQUEST,
    }
}

/// A validated `ipc_create` request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum IpcCreatePlan {
    /// One waitable object, returned as a single handle.
    Single {
        kind: ObjectKind,
        manual_reset: bool,
    },
    /// Two linked Channel endpoints, returned as two handles.
    Channel,
    /// A Port receiver/sender pair, returned as two handles.
    Port,
    /// A SharedMemory object with `length` bytes of frames behind it.
    SharedMemory { length: u64 },
    /// An EventSubscription object; interests are added by `subscribe`.
    Subscription,
}

/// Validate one `ipc_create` request without touching any IPC or object state.
fn ipc_create_plan(request: &IpcCreateRequest) -> Result<IpcCreatePlan, u64> {
    if request.size != IpcCreateRequest::SIZE || request.version != REQUEST_VERSION {
        return Err(ERR_BAD_REQUEST);
    }
    let plan = match request.kind {
        IPC_KIND_EVENT => {
            if request.flags & !EVENT_FLAG_MANUAL_RESET != 0 {
                return Err(ERR_BAD_REQUEST);
            }
            if request.arg0 != 0 || request.arg1 != 0 {
                return Err(ERR_BAD_REQUEST);
            }
            IpcCreatePlan::Single {
                kind: ObjectKind::Event,
                manual_reset: request.flags & EVENT_FLAG_MANUAL_RESET != 0,
            }
        }
        IPC_KIND_EVENT_PAIR => {
            if request.flags != 0 || request.arg0 != 0 || request.arg1 != 0 {
                return Err(ERR_BAD_REQUEST);
            }
            IpcCreatePlan::Single {
                kind: ObjectKind::EventPair,
                manual_reset: false,
            }
        }
        IPC_KIND_TIMER => {
            if request.flags != 0 || request.arg0 != 0 || request.arg1 != 0 {
                return Err(ERR_BAD_REQUEST);
            }
            IpcCreatePlan::Single {
                kind: ObjectKind::Timer,
                manual_reset: false,
            }
        }
        // A Channel/Port is a *pair* of endpoints: without a place to put the
        // second handle the request could only leak it, so it is malformed.
        IPC_KIND_CHANNEL | IPC_KIND_PORT => {
            if request.flags != 0 || request.arg0 != 0 || request.arg1 != 0 {
                return Err(ERR_BAD_REQUEST);
            }
            if request.out_second_ptr == 0 {
                return Err(ERR_BAD_REQUEST);
            }
            if request.kind == IPC_KIND_CHANNEL {
                IpcCreatePlan::Channel
            } else {
                IpcCreatePlan::Port
            }
        }
        // A SharedMemory object takes its byte length in `arg0`; its frames are
        // created here and released when the last object reference goes away.
        IPC_KIND_SHARED_MEMORY => {
            if request.flags != 0 || request.arg1 != 0 || request.out_second_ptr != 0 {
                return Err(ERR_BAD_REQUEST);
            }
            IpcCreatePlan::SharedMemory {
                length: request.arg0,
            }
        }
        // An EventSubscription starts empty: every interest is added later by
        // `subscribe`, so the create request carries no arguments.
        IPC_KIND_SUBSCRIPTION => {
            if request.flags != 0
                || request.arg0 != 0
                || request.arg1 != 0
                || request.out_second_ptr != 0
            {
                return Err(ERR_BAD_REQUEST);
            }
            IpcCreatePlan::Subscription
        }
        _ => return Err(ERR_BAD_REQUEST),
    };
    Ok(plan)
}

/// Create one Channel or Port pair and return both handles to the caller.
///
/// Both endpoints start in the caller's table; handing the second one out is the
/// caller's decision (initial handles today, IPC transfer later). A failed
/// `copy_out` closes both handles again so a rejected create never leaves a
/// linked pair behind.
fn create_endpoint_pair(
    address_space: AddressSpaceId,
    request: &IpcCreateRequest,
    plan: IpcCreatePlan,
) -> SyscallRet {
    // Creating a pair registers two endpoint objects and a channel/port entry;
    // a failure part-way releases them and runs their destroy hooks, so the
    // process lock is dropped before this call and restored afterwards.
    let created = process::take_current_handles().map(|mut guard| match plan {
        IpcCreatePlan::Channel => {
            ipc::insert_channel(guard.table_mut(), IPC_HANDLE_RIGHTS, IPC_HANDLE_RIGHTS)
        }
        _ => ipc::insert_port(guard.table_mut(), PORT_RECEIVER_RIGHTS, PORT_SENDER_RIGHTS),
    });
    let (first, second) = match created {
        None => return err(ERR_BAD_HANDLE),
        Some(Ok(pair)) => pair,
        Some(Err(error)) => return err(ipc_status(error)),
    };
    if let Err(status) = copy_out_struct(address_space, request.out_second_ptr, &second.raw()) {
        let rollback = process::take_current_handles();
        if let Some(mut guard) = rollback {
            let _ = object::close_handle(guard.table_mut(), second);
            let _ = object::close_handle(guard.table_mut(), first);
        }
        return err(status);
    }
    ok(u64::from(first.raw()))
}

/// `ipc_create`: build one waitable object and return its handle.
fn ipc_create(request_ptr: u64) -> SyscallRet {
    let Some(address_space) = current_address_space() else {
        return err(ERR_BAD_HANDLE);
    };
    let mut request = IpcCreateRequest::default();
    if let Err(status) = copy_in_struct(address_space, request_ptr, &mut request) {
        return err(status);
    }
    let plan = match ipc_create_plan(&request) {
        Ok(plan) => plan,
        Err(status) => return err(status),
    };
    let (kind, manual_reset) = match plan {
        IpcCreatePlan::Single { kind, manual_reset } => (kind, manual_reset),
        IpcCreatePlan::Channel | IpcCreatePlan::Port => {
            return create_endpoint_pair(address_space, &request, plan);
        }
        IpcCreatePlan::SharedMemory { length } => {
            return create_bound_object(ObjectKind::SharedMemory, SHM_HANDLE_RIGHTS, |object| {
                ipc::shm::create(object, length)
                    .map(|_| ())
                    .map_err(shm_status)
            });
        }
        IpcCreatePlan::Subscription => {
            return create_bound_object(
                ObjectKind::EventSubscription,
                SUBSCRIPTION_HANDLE_RIGHTS,
                |object| ipc::subscription::create(object).map_err(subscription_status),
            );
        }
    };
    let created = process::take_current_handles().map(|mut guard| match kind {
        ObjectKind::Event => ipc::insert_event(guard.table_mut(), manual_reset, IPC_HANDLE_RIGHTS),
        ObjectKind::EventPair => ipc::insert_event_pair(guard.table_mut(), IPC_HANDLE_RIGHTS),
        _ => ipc::insert_timer(guard.table_mut(), IPC_HANDLE_RIGHTS),
    });
    match created {
        None => err(ERR_BAD_HANDLE),
        Some(Ok(handle)) => ok(u64::from(handle.raw())),
        Some(Err(error)) => err(ipc_status(error)),
    }
}

/// `ipc_signal`: reset or signal one endpoint of an `Event` / `EventPair`.
///
/// Only a signal wakes waiters; a reset just clears the state (a manual-reset
/// event stays signalled until it is reset here).
fn ipc_signal(raw_handle: u64, operation: u64, endpoint: u64) -> SyscallRet {
    let operation = if operation == u64::from(SIGNAL_OP_RESET) {
        SIGNAL_OP_RESET
    } else if operation == u64::from(SIGNAL_OP_SIGNAL) {
        SIGNAL_OP_SIGNAL
    } else {
        return err(ERR_BAD_REQUEST);
    };
    if endpoint > u64::from(EVENT_PAIR_ENDPOINT_B) {
        return err(ERR_BAD_REQUEST);
    }
    let resolved = match resolve_handle_any(raw_handle, Rights::WRITE) {
        Ok(resolved) => resolved,
        Err(status) => return err(status),
    };
    let Some(payload) = object_payload(resolved.object) else {
        return err(ERR_BAD_HANDLE);
    };
    let endpoint = endpoint as u8;
    let outcome = match resolved.kind {
        ObjectKind::Event => {
            if endpoint != 0 {
                return err(ERR_BAD_REQUEST);
            }
            if operation == SIGNAL_OP_SIGNAL {
                ipc::event::signal(payload)
            } else {
                ipc::event::reset(payload)
            }
        }
        ObjectKind::EventPair => {
            if operation == SIGNAL_OP_SIGNAL {
                ipc::event::signal_pair(payload, endpoint)
            } else {
                ipc::event::reset_pair(payload, endpoint)
            }
        }
        // A live handle of a non-signalable kind is not a signal target.
        _ => return err(ERR_BAD_HANDLE),
    };
    if let Err(error) = outcome {
        return err(ipc_status(error));
    }
    if operation == SIGNAL_OP_SIGNAL {
        // An `EventPair` wake is endpoint specific, and the peer semantics apply:
        // signalling endpoint X makes endpoint X^1 ready, so the waiter to wake is
        // the one blocked on X^1 — never the signaller's own endpoint. `Event` and
        // `Timer` have a single readiness state, so they wake every waiter of the
        // object regardless of key.
        match signal_wake_key(resolved.kind, endpoint) {
            Some(key) => process::wake_object_key(resolved.object, key, WakeReason::Ready),
            None => process::wake_object(resolved.object, WakeReason::Ready),
        };
    }
    ok(0)
}

/// Which key a successful signal wakes, if the wake is keyed.
///
/// `EventPair` is the only keyed kind: its two endpoints are peers, so signalling
/// endpoint `X` makes `X ^ 1` ready and the peer's waiters are the ones to wake.
/// The other IPC kinds have one state per object and use the unkeyed wake.
fn signal_wake_key(kind: ObjectKind, endpoint: u8) -> Option<u32> {
    match kind {
        ObjectKind::EventPair => Some(u32::from(endpoint ^ 1)),
        _ => None,
    }
}

/// One resolved wait item.
#[derive(Clone, Copy)]
struct WaitSlot {
    object: ObjectId,
    kind: ObjectKind,
    payload: u64,
    key: u8,
}

impl WaitSlot {
    const EMPTY: WaitSlot = WaitSlot {
        object: 0,
        kind: ObjectKind::Event,
        payload: 0,
        key: 0,
    };
}

/// A validated `wait` request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct WaitPlan {
    out_ptr: u64,
    timeout_ticks: u32,
    count: usize,
}

/// Validate the fixed part of one `wait` request.
fn wait_plan(request: &WaitRequest) -> Result<WaitPlan, u64> {
    if request.size != WaitRequest::SIZE || request.version != REQUEST_VERSION {
        return Err(ERR_BAD_REQUEST);
    }
    if request.flags != 0 || request.reserved != 0 {
        return Err(ERR_BAD_REQUEST);
    }
    let count = request.count as usize;
    if count == 0 || count > WAIT_MAX_ITEMS {
        return Err(ERR_BAD_REQUEST);
    }
    if request.out_ptr == 0 {
        return Err(ERR_BAD_POINTER);
    }
    for item in &request.items[..count] {
        if item.flags != 0 {
            return Err(ERR_BAD_REQUEST);
        }
    }
    Ok(WaitPlan {
        out_ptr: request.out_ptr,
        timeout_ticks: request.timeout_ticks,
        count,
    })
}

/// Decode the per-object `key` a `wait` item may carry, rejecting kinds that
/// cannot be waited on and keys those kinds do not define.
///
/// Event, Timer, Channel, Port, Input and EventSubscription are object-wide
/// (key must be 0); only `EventPair` selects an endpoint. SharedMemory and the
/// syscall-only handles are not waitable at all.
fn wait_item_key(kind: ObjectKind, key: u32) -> Result<u8, u64> {
    match kind {
        ObjectKind::Event | ObjectKind::Timer => {
            if key != 0 {
                return Err(ERR_BAD_REQUEST);
            }
            Ok(0)
        }
        ObjectKind::EventPair => {
            if key > u32::from(EVENT_PAIR_ENDPOINT_B) {
                return Err(ERR_BAD_REQUEST);
            }
            Ok(key as u8)
        }
        // Channel, Port, Input, EventSubscription and Socket report readiness per
        // object; their waiters are woken by the unkeyed `wake_object`.
        ObjectKind::Channel
        | ObjectKind::Port
        | ObjectKind::Input
        | ObjectKind::EventSubscription
        | ObjectKind::Socket => {
            if key != 0 {
                return Err(ERR_BAD_REQUEST);
            }
            Ok(0)
        }
        _ => Err(ERR_BAD_HANDLE),
    }
}

/// `wait`: wait for one of up to four waitable handles to become ready.
///
/// When nothing is ready and the timeout is not immediate, the process blocks and
/// this call is replayed from the start on wake-up (`block_current` rewinds the
/// saved user `rip` over the two-byte `syscall`), so every check below runs again
/// against fresh state.
fn wait(frame: *mut SyscallFrame, request_ptr: u64) -> SyscallRet {
    // Consume any recorded wake reason first: a non-`None` value means this is a
    // replay of the call that blocked, and leaving it in place would mis-attribute
    // it to the next wait. The items are still inspected before the reason is
    // acted on (below), so a same-tick ready object is never reported as timeout.
    let reason = process::take_wake_reason();
    let Some(address_space) = current_address_space() else {
        return err(ERR_BAD_HANDLE);
    };
    let mut request = WaitRequest::default();
    if let Err(status) = copy_in_struct(address_space, request_ptr, &mut request) {
        return err(status);
    }
    let plan = match wait_plan(&request) {
        Ok(plan) => plan,
        Err(status) => return err(status),
    };
    let mut slots = [WaitSlot::EMPTY; WAIT_MAX_ITEMS];
    for (index, slot) in slots.iter_mut().enumerate().take(plan.count) {
        let item = request.items[index];
        let resolved = match resolve_handle_any(item.handle, Rights::WAIT) {
            Ok(resolved) => resolved,
            Err(status) => return err(status),
        };
        let key = match wait_item_key(resolved.kind, item.key) {
            Ok(key) => key,
            Err(status) => return err(status),
        };
        let Some(payload) = object_payload(resolved.object) else {
            return err(ERR_BAD_HANDLE);
        };
        *slot = WaitSlot {
            object: resolved.object,
            kind: resolved.kind,
            payload,
            key,
        };
    }

    // The items were already inspected above, so the recorded reason only decides
    // what to report once nothing is ready.
    let mut ready_mask = 0u32;
    let mut ready_key = 0u32;
    let mut first_ready = true;
    for (index, slot) in slots.iter().enumerate().take(plan.count) {
        let ready = match slot.kind {
            // Event/EventPair/Timer keep their per-object readiness check; the
            // signal is only cleared when the wait actually reports it.
            ObjectKind::Event | ObjectKind::EventPair | ObjectKind::Timer => {
                match ipc::is_ready(slot.kind, slot.payload, slot.key) {
                    Ok(ready) => ready,
                    Err(error) => return err(ipc_status(error)),
                }
            }
            // Channel, Port and EventSubscription are polled without consuming:
            // messages leave the queue only through `ipc_recv`, and subscription
            // events only through `subscription_read`. A socket is the same: the
            // net stack is asked for readiness and the data stays queued until
            // `recv`. Write readiness is only decisive after a `Ready` wake (see
            // `socket_wait_ready`): the engine wakes a blocked sender once its
            // peer's accept frees the socket, and that replay must report ready.
            ObjectKind::Socket => match net::poll(socket_from_payload(slot.payload)) {
                Ok(mask) => socket_wait_ready(mask, reason),
                Err(error) => return err(socket_status(error)),
            },
            _ => match ipc::poll_waitable_keyed(slot.object, slot.key, false) {
                Ok(ready) => ready,
                Err(error) => return err(ipc_status(error)),
            },
        };
        if ready {
            ready_mask |= 1 << index;
            if first_ready {
                ready_key = u32::from(slot.key);
                first_ready = false;
            }
        }
    }
    if ready_mask != 0 {
        // Consume only what was reported ready, and only for the signal-like
        // kinds: auto-reset events and timers clear their signal here, manual-reset
        // events stay set until reset. Channel/Port/Subscription are never drained
        // by a wait.
        for (index, slot) in slots.iter().enumerate().take(plan.count) {
            if ready_mask & (1 << index) == 0 {
                continue;
            }
            if !matches!(
                slot.kind,
                ObjectKind::Event | ObjectKind::EventPair | ObjectKind::Timer
            ) {
                continue;
            }
            if let Err(error) = ipc::consume(slot.kind, slot.payload, slot.key) {
                return err(ipc_status(error));
            }
        }
        let out = WaitOut {
            ready_mask,
            wake_reason: WAKE_READY,
            ready_key,
            reserved: 0,
        };
        if let Err(status) = copy_out_struct(address_space, plan.out_ptr, &out) {
            return err(status);
        }
        return ok(u64::from(ready_mask.count_ones()));
    }

    match reason {
        WakeReason::Timeout => return err(ERR_TIMEOUT),
        WakeReason::Destroyed => return err(ERR_BAD_HANDLE),
        WakeReason::PeerClosed => return err(ERR_PEER_CLOSED),
        WakeReason::Cancelled => return err(ERR_CANCELLED),
        // `Ready` with nothing ready any more (an auto-reset event consumed
        // elsewhere) falls through and waits again instead of spinning.
        WakeReason::None | WakeReason::Ready => {}
    }

    if plan.timeout_ticks == WAIT_TIMEOUT_IMMEDIATE {
        return err(ERR_WOULD_BLOCK);
    }
    // A replay must reuse the absolute deadline recorded when this call first
    // blocked: recomputing `now + ticks` on every wake-up would let a spurious
    // wake (an auto-reset event consumed elsewhere, a signal for another endpoint)
    // push the timeout further into the future for ever.
    let deadline = if reason.is_some() {
        process::wait_deadline()
    } else {
        first_wait_deadline(plan.timeout_ticks, crate::time::monotonic_ticks())
    };
    let mut objects = [0u16; crate::process::MAX_WAIT_OBJECTS];
    let mut keys = [crate::process::WAIT_ANY_KEY; crate::process::MAX_WAIT_OBJECTS];
    for (index, slot) in slots.iter().enumerate().take(plan.count) {
        objects[index] = slot.object;
        // Only `EventPair` is keyed (the endpoint being waited on). `Event` and
        // `Timer` have one state per object, so their waiters use the wildcard key
        // and are woken by the unkeyed `wake_object`.
        if slot.kind == ObjectKind::EventPair {
            keys[index] = u32::from(slot.key);
        }
    }
    // SAFETY: the entry stub stored its own private `TrapFrame` pointer in the
    // frame we were handed; `block_current_keyed` re-checks that it is this
    // process's syscall frame before switching away.
    let trap_frame = unsafe { (*frame).trap_frame };
    process::block_current_keyed(trap_frame, objects, keys, plan.count, deadline)
}

/// Absolute deadline for a `wait` that is blocking for the first time.
///
/// `None` means "wait for ever"; otherwise the deadline is `now + ticks`, saturating
/// so a huge timeout can never wrap into an immediate one. A replayed call must not
/// use this: it reuses the deadline recorded by [`process::wait_deadline`].
fn first_wait_deadline(timeout_ticks: u32, now: u64) -> Option<u64> {
    if timeout_ticks == WAIT_TIMEOUT_INFINITE {
        None
    } else {
        Some(now.saturating_add(u64::from(timeout_ticks)))
    }
}

/// `timer_arm`: arm a one-shot `Timer` for `ticks` from now.
///
/// `ticks == 0` fires immediately: the timer is armed for the current tick and
/// expired through the same path the timer ISR uses, so the waiter sees a normal
/// ready signal rather than a special case.
fn timer_arm(raw_handle: u64, ticks: u64, flags: u64) -> SyscallRet {
    if flags != 0 {
        return err(ERR_BAD_REQUEST);
    }
    let resolved = match resolve_handle_any(raw_handle, Rights::WRITE) {
        Ok(resolved) => resolved,
        Err(status) => return err(status),
    };
    if resolved.kind != ObjectKind::Timer {
        return err(ERR_BAD_HANDLE);
    }
    let Some(payload) = object_payload(resolved.object) else {
        return err(ERR_BAD_HANDLE);
    };
    let now = crate::time::monotonic_ticks();
    let deadline = now.saturating_add(ticks);
    // Re-arming clears any previous signal, so a stale "ready" can never be
    // observed after a new deadline was requested.
    if let Err(error) = ipc::timer::arm(payload, Some(deadline)) {
        return err(ipc_status(error));
    }
    if ticks == 0 {
        ipc::timer::on_tick(now);
    }
    ok(0)
}

// ---------------------------------------------------------------------------
// M6a2: Channel / Port messaging
// ---------------------------------------------------------------------------

/// Rights granted to the receiving endpoint of a `Port`.
const PORT_RECEIVER_RIGHTS: Rights = Rights::READ.union(Rights::WAIT).union(Rights::DUPLICATE);

/// Rights granted to the sending endpoint of a `Port`.
const PORT_SENDER_RIGHTS: Rights = Rights::WRITE.union(Rights::DUPLICATE);

/// Resolve one handle to a Channel/Port endpoint that carries `required`.
fn resolve_ipc_endpoint(raw_handle: u64, required: Rights) -> Result<ObjectId, u64> {
    let resolved = resolve_handle_any(raw_handle, required)?;
    match resolved.kind {
        ObjectKind::Channel | ObjectKind::Port => Ok(resolved.object),
        // The caller pointed at an object that is not a message endpoint: a bad
        // handle, not a malformed request.
        _ => Err(ERR_BAD_HANDLE),
    }
}

/// Peek at the queue of `receiver` without consuming anything.
fn ipc_endpoint_peek(receiver: ObjectId) -> Result<Message, IpcError> {
    match object::object_kind(receiver) {
        Some(ObjectKind::Channel) => ipc::channel::peek(receiver),
        Some(ObjectKind::Port) => ipc::port::peek(receiver),
        _ => Err(IpcError::WrongKind),
    }
}

/// Commit (consume) the message `sequence` on `receiver`.
fn ipc_endpoint_commit(receiver: ObjectId, sequence: u64) -> Result<(), IpcError> {
    match object::object_kind(receiver) {
        Some(ObjectKind::Channel) => ipc::channel::commit(receiver, sequence),
        Some(ObjectKind::Port) => ipc::port::commit(receiver, sequence),
        _ => Err(IpcError::WrongKind),
    }
}

/// Release every object acquired so far, then report `status`.
fn send_failure(status: u64, objects: &[ObjectId]) -> u64 {
    for object in objects {
        let _ = object::release_object(*object);
    }
    status
}

/// Build the [`OutMessage`] for one `ipc_send` request.
///
/// Every transferred handle is validated **before** any reference is acquired,
/// so a rejected request changes neither the object table nor the queue. Rights
/// may only be narrowed: each requested mask must be a non-empty subset of the
/// rights the sender's own handle carries.
fn build_out_message(
    address_space: AddressSpaceId,
    request: &IpcSendRequest,
    destination: ObjectId,
) -> Result<OutMessage, u64> {
    if request.data_len > IPC_DATA_MAX as u32 || request.handle_count > IPC_HANDLES_MAX as u32 {
        return Err(ERR_TOO_LARGE);
    }
    let data_len = request.data_len as usize;
    let mut data = [0u8; IPC_DATA_MAX];
    if data_len != 0 {
        if request.data_ptr == 0 {
            return Err(ERR_BAD_POINTER);
        }
        addrspace::copy_in(address_space, request.data_ptr, &mut data[..data_len])
            .map_err(|_| ERR_BAD_POINTER)?;
    }
    let mut message = OutMessage::with_data(&data[..data_len]).map_err(ipc_status)?;
    message.protocol = request.protocol;
    message.version = request.msg_version;
    message.transaction = request.transaction;
    message.sender_pid = process::current_process_id().unwrap_or(0);

    let handle_count = request.handle_count as usize;
    if handle_count == 0 {
        return Ok(message);
    }
    if request.handles_ptr == 0 || request.rights_ptr == 0 {
        return Err(ERR_BAD_POINTER);
    }
    let mut handles = [0u8; 4 * IPC_HANDLES_MAX];
    let mut rights = [0u8; 4 * IPC_HANDLES_MAX];
    addrspace::copy_in(
        address_space,
        request.handles_ptr,
        &mut handles[..4 * handle_count],
    )
    .map_err(|_| ERR_BAD_POINTER)?;
    addrspace::copy_in(
        address_space,
        request.rights_ptr,
        &mut rights[..4 * handle_count],
    )
    .map_err(|_| ERR_BAD_POINTER)?;

    let mut objects = [ObjectId::MAX; IPC_HANDLES_MAX];
    let mut count = 0usize;
    for index in 0..handle_count {
        let base = index * 4;
        let raw = u32::from_le_bytes([
            handles[base],
            handles[base + 1],
            handles[base + 2],
            handles[base + 3],
        ]);
        let mask = u32::from_le_bytes([
            rights[base],
            rights[base + 1],
            rights[base + 2],
            rights[base + 3],
        ]);
        let Some(requested) = Rights::from_bits(mask) else {
            return Err(send_failure(ERR_BAD_REQUEST, &objects[..count]));
        };
        if requested.is_empty() {
            return Err(send_failure(ERR_BAD_REQUEST, &objects[..count]));
        }
        let resolved = match resolve_handle_any(u64::from(raw), Rights::NONE) {
            Ok(resolved) => resolved,
            Err(status) => return Err(send_failure(status, &objects[..count])),
        };
        if !resolved.rights.contains(requested) {
            // Transfer may only narrow the sender's rights.
            return Err(send_failure(ERR_BAD_REQUEST, &objects[..count]));
        }
        if resolved.object == destination {
            // Sending the endpoint's own handle inside a message addressed to it
            // would hand the receiver a duplicate of the queue it is reading.
            return Err(send_failure(ERR_BAD_REQUEST, &objects[..count]));
        }
        if let Err(error) = object::acquire_object(resolved.object) {
            return Err(send_failure(object_status(error), &objects[..count]));
        }
        objects[count] = resolved.object;
        count += 1;
        message = match message.with_handle(resolved.object, requested) {
            Ok(message) => message,
            Err(error) => {
                let _ = object::release_object(resolved.object);
                return Err(send_failure(ipc_status(error), &objects[..count - 1]));
            }
        };
    }
    Ok(message)
}

/// `ipc_send`: enqueue one message on a Channel/Port endpoint (never blocks).
///
/// `raw_handle` names the caller's **sending** end: a Channel message lands in
/// the *peer* endpoint's inbound queue (so the other side receives it), and a
/// Port handle must be the sender endpoint (the module resolves the single
/// receiver queue from it). A full queue reports `WOULD_BLOCK`; the caller
/// retries. On success `rdx` (the result register) holds the accepted payload
/// length in bytes, exactly as frozen in the 0.4 ABI: the internal queue
/// sequence number is never exposed to user space.
fn ipc_send(raw_handle: u64, request_ptr: u64) -> SyscallRet {
    let Some(address_space) = current_address_space() else {
        return err(ERR_BAD_HANDLE);
    };
    let destination = match resolve_ipc_endpoint(raw_handle, Rights::WRITE) {
        Ok(object) => object,
        Err(status) => return err(status),
    };
    let mut request = IpcSendRequest::default();
    if let Err(status) = copy_in_struct(address_space, request_ptr, &mut request) {
        return err(status);
    }
    if request.size != IpcSendRequest::SIZE
        || request.version != REQUEST_VERSION
        || request.reserved != 0
    {
        return err(ERR_BAD_REQUEST);
    }
    let message = match build_out_message(address_space, &request, destination) {
        Ok(message) => message,
        Err(status) => return err(status),
    };
    let sent = match object::object_kind(destination) {
        Some(ObjectKind::Channel) => ipc::channel::send(destination, message),
        Some(ObjectKind::Port) => ipc::port::send(destination, message),
        _ => Err(IpcError::WrongKind),
    };
    // The queue already released the object references it was handed when it
    // refused the message (see `ipc::channel::send`), so the message must not be
    // released again here: that would double-release and could hit a recycled
    // object slot.
    match sent {
        // The whole payload was accepted; the sequence number stays internal.
        Ok(_sequence) => ok(u64::from(request.data_len)),
        Err(error) => err(ipc_status(error)),
    }
}

/// Close the handles a failed receive had already inserted.
fn close_inserted(handles: &[Handle]) {
    if handles.is_empty() {
        return;
    }
    // Each close may release the last reference to a message handle and run its
    // destroy hook, so the table is taken out of the process slot first.
    let closed = process::take_current_handles();
    if let Some(mut guard) = closed {
        for handle in handles {
            let _ = object::close_handle(guard.table_mut(), *handle);
        }
    }
}

/// Copy a received message out and insert its handles into the caller's table.
///
/// Runs in the frozen transaction order: insert every transferred object first,
/// then copy data/meta/handles out. Nothing is committed here, so a failure
/// leaves the message queued and closes the handles inserted so far.
fn write_received(
    address_space: AddressSpaceId,
    request: &IpcReceiveRequest,
    message: &Message,
    inserted: &[Handle],
) -> Result<(), u64> {
    let data_len = usize::from(message.data_len);
    if data_len != 0 {
        addrspace::copy_out(address_space, request.data_ptr, &message.data[..data_len])
            .map_err(|_| ERR_BAD_POINTER)?;
    }
    let meta = IpcMessageMeta {
        protocol: message.protocol,
        version: message.version,
        transaction: message.transaction,
        data_len: u32::from(message.data_len),
        handle_count: u32::from(message.handle_count),
        sender_pid: message.sender_pid,
        reserved: 0,
    };
    copy_out_struct(address_space, request.out_meta_ptr, &meta)?;
    if inserted.is_empty() {
        return Ok(());
    }
    let mut handles = [0u8; 4 * IPC_HANDLES_MAX];
    let mut rights = [0u8; 4 * IPC_HANDLES_MAX];
    for (index, handle) in inserted.iter().enumerate() {
        let base = index * 4;
        handles[base..base + 4].copy_from_slice(&handle.raw().to_le_bytes());
        rights[base..base + 4].copy_from_slice(&message.rights[index].to_le_bytes());
    }
    addrspace::copy_out(
        address_space,
        request.out_handles_ptr,
        &handles[..4 * inserted.len()],
    )
    .map_err(|_| ERR_BAD_POINTER)?;
    addrspace::copy_out(
        address_space,
        request.out_rights_ptr,
        &rights[..4 * inserted.len()],
    )
    .map_err(|_| ERR_BAD_POINTER)
}

/// Deliver one peeked `message` to the caller.
fn deliver_message(
    address_space: AddressSpaceId,
    request: &IpcReceiveRequest,
    receiver: ObjectId,
    message: Message,
) -> SyscallRet {
    // A message that does not fit the caller's buffers stays queued: user space
    // retries with bigger buffers and no data is lost.
    if u32::from(message.data_len) > request.data_capacity
        || u32::from(message.handle_count) > request.handle_capacity
    {
        return err(ERR_TOO_LARGE);
    }
    let mut inserted = [Handle::from_raw(HANDLE_NONE); IPC_HANDLES_MAX];
    let mut count = 0usize;
    let transferred = process::with_current_handles(|table| -> Result<(), u64> {
        for index in 0..usize::from(message.handle_count) {
            let Some(rights) = Rights::from_bits(message.rights[index]) else {
                return Err(ERR_BAD_REQUEST);
            };
            let handle = object::insert_handle(table, message.objects[index], rights)
                .map_err(object_status)?;
            inserted[count] = handle;
            count += 1;
        }
        Ok(())
    });
    match transferred {
        None => return err(ERR_BAD_HANDLE),
        Some(Ok(())) => {}
        Some(Err(status)) => {
            close_inserted(&inserted[..count]);
            return err(status);
        }
    }
    if let Err(status) = write_received(address_space, request, &message, &inserted[..count]) {
        close_inserted(&inserted[..count]);
        return err(status);
    }
    match ipc_endpoint_commit(receiver, message.sequence) {
        Ok(()) => ok(u64::from(message.data_len)),
        Err(error) => {
            // The handles are already visible and the data was copied out, so a
            // commit failure here is an internal inconsistency rather than a
            // caller error; report it instead of pretending the receive failed.
            close_inserted(&inserted[..count]);
            err(ipc_status(error))
        }
    }
}

/// `ipc_receive`: take one message from a Channel/Port endpoint.
///
/// Blocks on the endpoint object until a message arrives, the timeout expires or
/// the peer closes; the saved user `rip` is rewound so the call is replayed and
/// every check runs again. A recorded wake reason is only consulted after a
/// fresh peek, so a message that arrived together with a timeout still wins.
fn ipc_receive(frame: *mut SyscallFrame, raw_handle: u64, request_ptr: u64) -> SyscallRet {
    let Some(address_space) = current_address_space() else {
        return err(ERR_BAD_HANDLE);
    };
    let receiver = match resolve_ipc_endpoint(raw_handle, Rights::READ) {
        Ok(object) => object,
        Err(status) => return err(status),
    };
    let mut request = IpcReceiveRequest::default();
    if let Err(status) = copy_in_struct(address_space, request_ptr, &mut request) {
        return err(status);
    }
    if request.size != IpcReceiveRequest::SIZE
        || request.version != REQUEST_VERSION
        || request.reserved != 0
    {
        return err(ERR_BAD_REQUEST);
    }
    if request.data_capacity > IPC_DATA_MAX as u32
        || request.handle_capacity > IPC_HANDLES_MAX as u32
    {
        return err(ERR_TOO_LARGE);
    }
    if request.out_meta_ptr == 0 {
        return err(ERR_BAD_POINTER);
    }
    if request.data_capacity != 0 && request.data_ptr == 0 {
        return err(ERR_BAD_POINTER);
    }
    if request.handle_capacity != 0 && (request.out_handles_ptr == 0 || request.out_rights_ptr == 0)
    {
        return err(ERR_BAD_POINTER);
    }
    let Some(timeout_ticks) = u32::try_from(request.timeout_ticks).ok() else {
        return err(ERR_BAD_REQUEST);
    };
    // Consume the reason first so it can never be mis-attributed to a later wait,
    // but do not act on it until the queue has been inspected.
    let reason = process::take_wake_reason();
    match ipc_endpoint_peek(receiver) {
        Ok(message) => return deliver_message(address_space, &request, receiver, message),
        Err(IpcError::WouldBlock) => {}
        Err(error) => return err(ipc_status(error)),
    }
    match reason {
        WakeReason::None | WakeReason::Ready => {}
        WakeReason::Timeout => return err(ERR_TIMEOUT),
        WakeReason::Destroyed => return err(ERR_BAD_HANDLE),
        WakeReason::Cancelled => return err(ERR_CANCELLED),
        WakeReason::PeerClosed => return err(ERR_PEER_CLOSED),
    }
    if timeout_ticks == WAIT_TIMEOUT_IMMEDIATE {
        return err(ERR_WOULD_BLOCK);
    }
    // A replay reuses the absolute deadline recorded by the first entry, so a
    // spurious wake can never push the timeout further into the future.
    let deadline = match reason {
        WakeReason::None => first_wait_deadline(timeout_ticks, crate::time::monotonic_ticks()),
        _ => process::wait_deadline(),
    };
    let objects = [receiver; WAIT_MAX_ITEMS];
    let keys = [process::WAIT_ANY_KEY; WAIT_MAX_ITEMS];
    // SAFETY: the entry stub stored its own private `TrapFrame` pointer in the
    // frame we were handed; `block_current_keyed` re-checks that it is this
    // process's syscall frame before switching away.
    let trap_frame = unsafe { (*frame).trap_frame };
    process::block_current_keyed(trap_frame, objects, keys, 1, deadline)
}

// ---------------------------------------------------------------------------
// M6a2: shared memory mapping
// ---------------------------------------------------------------------------

/// Validate one `shm_map` request and return the requested protection mask.
///
/// The permission bits themselves are validated by [`vmobj::map_shm`] (which
/// refuses execute); this only checks the wire header and the out pointer.
fn shm_map_request(request: &native_abi::ShmMapRequest) -> Result<u32, u64> {
    if request.size != native_abi::ShmMapRequest::SIZE
        || request.version != REQUEST_VERSION
        || request.reserved != 0
        || request.reserved_high != 0
    {
        return Err(ERR_BAD_REQUEST);
    }
    if request.out_address == 0 {
        return Err(ERR_BAD_POINTER);
    }
    Ok(request.prot)
}

/// `shm_map`: map a `SharedMemory` object into the caller's address space.
///
/// Arguments: `rdi` = `SharedMemory` handle (needs `Rights::MAP`), `rsi` = user
/// pointer to a 32-byte [`native_abi::ShmMapRequest`]. On success `rdx` (the
/// `result` register) holds the new `VmObject` handle and the base address was
/// copied out to `request.out_address`.
///
/// The frames stay the object's property: the mapping only borrows them and
/// holds one object reference, so closing the `SharedMemory` handle does not
/// invalidate a live mapping. Closing the returned mapping handle unmaps the
/// range and drops that reference.
fn shm_map(raw_handle: u64, request_ptr: u64) -> SyscallRet {
    let Some(address_space) = current_address_space() else {
        return err(ERR_BAD_HANDLE);
    };
    let mut request = native_abi::ShmMapRequest::new(0, 0);
    if let Err(status) = copy_in_struct(address_space, request_ptr, &mut request) {
        return err(status);
    }
    let prot = match shm_map_request(&request) {
        Ok(prot) => prot,
        Err(status) => return err(status),
    };
    let resolved = match resolve_handle_any(raw_handle, Rights::MAP) {
        Ok(resolved) => resolved,
        Err(status) => return err(status),
    };
    if resolved.kind != ObjectKind::SharedMemory {
        return err(ERR_BAD_HANDLE);
    }
    let pages = match crate::ipc::shm::pages(resolved.object) {
        Ok(pages) => pages,
        Err(_) => return err(ERR_BAD_HANDLE),
    };
    let len = pages as u64 * vfs::PAGE;
    let (mapping_id, base) = match vmobj::map_shm(address_space, resolved.object, prot) {
        Ok(mapping) => mapping,
        Err(error) => return err(map_status(error)),
    };
    // Publish the mapping as a `VmObject` capability, exactly like `mmap`. If
    // the insertion fails the object layer drops the initial reference, which
    // runs the destroy hook and rolls the mapping back.
    let inserted = process::take_current_handles().map(|mut guard| {
        object::insert_new_with_payload(
            guard.table_mut(),
            ObjectKind::VmObject,
            u64::from(mapping_id),
            Rights::MAP,
        )
    });
    let handle = match inserted {
        Some(Ok(handle)) => handle,
        Some(Err(error)) => {
            let _ = vmobj::unmap(address_space, base, len);
            vmobj::release_pending();
            return err(object_status(error));
        }
        None => {
            let _ = vmobj::unmap(address_space, base, len);
            vmobj::release_pending();
            return err(ERR_BAD_HANDLE);
        }
    };
    if copy_out_struct(address_space, request.out_address, &base).is_err() {
        if !close_mapping_handle(handle) {
            let _ = vmobj::unmap(address_space, base, len);
        }
        vmobj::release_pending();
        return err(ERR_BAD_POINTER);
    }
    ok(handle.raw() as u64)
}

// ---------------------------------------------------------------------------
// M6a2: SharedMemory / EventSubscription
// ---------------------------------------------------------------------------

/// Rights `ipc_create` grants on a `SharedMemory` handle.
///
/// `MAP` is what `shm_map` checks; `READ`/`WRITE` describe the data access the
/// mapping may request, and `DUPLICATE` lets the owner hand the object on.
const SHM_HANDLE_RIGHTS: Rights = Rights::READ
    .union(Rights::WRITE)
    .union(Rights::MAP)
    .union(Rights::DUPLICATE);

/// Rights `ipc_create` grants on an `EventSubscription` handle.
///
/// `WAIT` observes readiness, `READ` drains events through `subscription_read`,
/// `DUPLICATE` lets the subscription be shared.
const SUBSCRIPTION_HANDLE_RIGHTS: Rights =
    Rights::READ.union(Rights::WAIT).union(Rights::DUPLICATE);

/// Map one [`ipc::shm::ShmError`] onto the ABI status codes.
fn shm_status(error: ipc::shm::ShmError) -> u64 {
    match error {
        ipc::shm::ShmError::TableFull | ipc::shm::ShmError::NoMemory => ERR_QUOTA,
        ipc::shm::ShmError::BadLength | ipc::shm::ShmError::WrongKind => ERR_BAD_REQUEST,
        ipc::shm::ShmError::NoSuchObject => ERR_NOT_FOUND,
    }
}

/// Map one [`ipc::subscription::SubscriptionError`] onto the ABI status codes.
fn subscription_status(error: ipc::subscription::SubscriptionError) -> u64 {
    use ipc::subscription::SubscriptionError;
    match error {
        SubscriptionError::TableFull => ERR_QUOTA,
        SubscriptionError::NotFound => ERR_NOT_FOUND,
        SubscriptionError::BadRequest | SubscriptionError::WrongKind => ERR_BAD_REQUEST,
        SubscriptionError::Object(error) => object_status(error),
    }
}

/// Create one object of `kind`, bind it through `bind`, and insert its handle.
///
/// The object is created first so `bind` can see its [`ObjectId`] (the shared
/// memory and subscription tables key on it). [`object::create_object`] returns
/// an object with **zero** references: the inserted handle acquires the first
/// and only reference, so the success path must not release anything.
///
/// Every failure path destroys the not-yet-inserted object instead: at zero
/// references `destroy_object` is the entry point that runs the kind's destroy
/// hook, which frees whatever `bind` had already allocated (frames, table
/// slots). Releasing instead would target a zero count and leave the slot
/// behind.
fn create_bound_object(
    kind: ObjectKind,
    rights: Rights,
    bind: impl FnOnce(ObjectId) -> Result<(), u64>,
) -> SyscallRet {
    let object = match object::create_object(kind) {
        Ok(object) => object,
        Err(error) => return err(object_status(error)),
    };
    if let Err(status) = bind(object) {
        let _ = object::destroy_object(object);
        return err(status);
    }
    let inserted =
        process::with_current_handles(|table| object::insert_handle(table, object, rights));
    match inserted {
        None => {
            let _ = object::destroy_object(object);
            err(ERR_BAD_HANDLE)
        }
        Some(Ok(handle)) => ok(u64::from(handle.raw())),
        Some(Err(error)) => {
            let _ = object::destroy_object(object);
            err(object_status(error))
        }
    }
}

/// Resolve a handle that names an `EventSubscription`.
fn resolve_subscription(raw_handle: u64) -> Result<ObjectId, u64> {
    let resolved = resolve_handle_any(raw_handle, Rights::READ)?;
    if resolved.kind != ObjectKind::EventSubscription {
        return Err(ERR_BAD_HANDLE);
    }
    Ok(resolved.object)
}

/// Decode one wire [`native_abi::SubscriptionEntry`] (16 bytes).
///
/// The wire layout is `handle: u32, mode: u32, key: u64`; it is decoded by hand
/// so a short user buffer can never be over-read.
fn decode_subscription_entry(raw: &[u8; 16]) -> (u32, u32, u64) {
    let handle = u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]);
    let mode = u32::from_le_bytes([raw[4], raw[5], raw[6], raw[7]]);
    let key = u64::from_le_bytes([
        raw[8], raw[9], raw[10], raw[11], raw[12], raw[13], raw[14], raw[15],
    ]);
    (handle, mode, key)
}

/// Validate one interest: the target kind, its key and the mode.
///
/// Only objects whose readiness a subscription can report are accepted, and only
/// their *read* side: a Channel/Port interest observes the receive queue, so a
/// sender endpoint (no `READ` right) is rejected by [`resolve_handle_any`].
fn subscription_interest(handle: u32, mode: u32, key: u64) -> Result<(ObjectId, u32, u64), u64> {
    if mode != SUBSCRIPTION_MODE_LEVEL && mode != SUBSCRIPTION_MODE_EDGE {
        return Err(ERR_BAD_REQUEST);
    }
    if key > u64::from(u32::MAX) {
        return Err(ERR_BAD_REQUEST);
    }
    let resolved = resolve_handle_any(u64::from(handle), Rights::READ)?;
    let expected_key = match resolved.kind {
        ObjectKind::EventPair => {
            if key > u64::from(EVENT_PAIR_ENDPOINT_B) {
                return Err(ERR_BAD_REQUEST);
            }
            key
        }
        ObjectKind::Event | ObjectKind::Timer | ObjectKind::Channel | ObjectKind::Port => {
            if key != 0 {
                return Err(ERR_BAD_REQUEST);
            }
            0
        }
        // SharedMemory is not waitable and a subscription cannot observe itself.
        _ => return Err(ERR_BAD_HANDLE),
    };
    Ok((resolved.object, mode, expected_key))
}

/// `subscribe`: append interests to an existing `EventSubscription`.
///
/// Every entry is validated before any of them is registered, so a malformed
/// request changes nothing. Registration itself can still hit the table limit
/// half-way through; the interests added before that point stay registered and
/// the count of registered interests is reported.
fn subscribe(raw_handle: u64, request_ptr: u64) -> SyscallRet {
    let Some(address_space) = current_address_space() else {
        return err(ERR_BAD_HANDLE);
    };
    let subscription = match resolve_subscription(raw_handle) {
        Ok(object) => object,
        Err(status) => return err(status),
    };
    let mut request = SubscribeRequest::default();
    if let Err(status) = copy_in_struct(address_space, request_ptr, &mut request) {
        return err(status);
    }
    if request.size != SubscribeRequest::SIZE
        || request.version != REQUEST_VERSION
        || request.reserved != 0
    {
        return err(ERR_BAD_REQUEST);
    }
    let count = request.count as usize;
    if count == 0 || count > SUBSCRIBE_MAX_ENTRIES {
        return err(ERR_BAD_REQUEST);
    }
    if request.entries_ptr == 0 {
        return err(ERR_BAD_POINTER);
    }
    let mut raw = [0u8; 16 * SUBSCRIBE_MAX_ENTRIES];
    let bytes = 16 * count;
    if let Err(_status) = addrspace::copy_in(address_space, request.entries_ptr, &mut raw[..bytes])
    {
        return err(ERR_BAD_POINTER);
    }
    let mut interests = [(ObjectId::MAX, 0u32, 0u64); SUBSCRIBE_MAX_ENTRIES];
    for index in 0..count {
        let base = index * 16;
        let entry: [u8; 16] = match raw[base..base + 16].try_into() {
            Ok(entry) => entry,
            Err(_) => return err(ERR_BAD_REQUEST),
        };
        let (handle, mode, key) = decode_subscription_entry(&entry);
        interests[index] = match subscription_interest(handle, mode, key) {
            Ok(interest) => interest,
            Err(status) => return err(status),
        };
    }
    let mut registered = 0usize;
    for (target, mode, key) in interests.iter().copied().take(count) {
        if let Err(error) = ipc::subscription::register(subscription, target, mode, key) {
            return err(subscription_status(error));
        }
        registered += 1;
    }
    ok(registered as u64)
}

/// `unsubscribe`: remove one interest from an `EventSubscription`.
///
/// On success `rdx` reports the number of removed interests, which is always one:
/// the interest table rejects duplicate targets, so a matching entry can only
/// appear once. A missing interest is `NOT_FOUND`, never a zero count.
fn unsubscribe(raw_handle: u64, target_handle: u64) -> SyscallRet {
    let subscription = match resolve_subscription(raw_handle) {
        Ok(object) => object,
        Err(status) => return err(status),
    };
    // The target may already be gone; resolve it as a plain object id so a
    // missing interest reports NOT_FOUND rather than a bad handle.
    let target = match resolve_handle_any(target_handle, Rights::READ) {
        Ok(resolved) => resolved.object,
        Err(status) => return err(status),
    };
    unsubscribe_status(ipc::subscription::unsubscribe(subscription, target))
}

/// Maps one `unsubscribe` result to the ABI.
///
/// A successful removal always reports **one** interest: registration rejects
/// duplicate targets, so a matching entry exists at most once. Reporting zero
/// here would tell user space "nothing was removed" while the interest is gone.
fn unsubscribe_status(result: Result<(), ipc::subscription::SubscriptionError>) -> SyscallRet {
    match result {
        Ok(()) => ok(1),
        Err(error) => err(subscription_status(error)),
    }
}

/// `subscription_read`: drain up to `max_events` readiness events.
///
/// This is the only call that consumes edge-triggered notifications; `wait` on a
/// subscription merely reports that something is ready.
fn subscription_read(raw_handle: u64, request_ptr: u64) -> SyscallRet {
    let Some(address_space) = current_address_space() else {
        return err(ERR_BAD_HANDLE);
    };
    let subscription = match resolve_subscription(raw_handle) {
        Ok(object) => object,
        Err(status) => return err(status),
    };
    let mut request = SubscriptionReadRequest::default();
    if let Err(status) = copy_in_struct(address_space, request_ptr, &mut request) {
        return err(status);
    }
    if request.size != SubscriptionReadRequest::SIZE
        || request.version != REQUEST_VERSION
        || request.reserved != 0
    {
        return err(ERR_BAD_REQUEST);
    }
    let max_events = request.max_events as usize;
    if max_events == 0 || max_events > SUBSCRIPTION_EVENTS_MAX {
        return err(ERR_BAD_REQUEST);
    }
    if request.out_events_ptr == 0 {
        return err(ERR_BAD_POINTER);
    }
    let mut events = [ipc::subscription::SubscriptionEvent {
        object_key: 0,
        mode: 0,
    }; SUBSCRIPTION_EVENTS_MAX];
    let read = match ipc::subscription::read(subscription, &mut events[..max_events]) {
        Ok(count) => count,
        Err(error) => return err(subscription_status(error)),
    };
    if read != 0 {
        let mut raw = [0u8; 16 * SUBSCRIPTION_EVENTS_MAX];
        for (index, event) in events.iter().enumerate().take(read) {
            let base = index * 16;
            raw[base..base + 8].copy_from_slice(&event.object_key.to_le_bytes());
            raw[base + 8..base + 12].copy_from_slice(&event.mode.to_le_bytes());
            // The last four bytes stay zero: `SubscriptionEvent::reserved`.
        }
        let bytes = 16 * read;
        if let Err(_status) =
            addrspace::copy_out(address_space, request.out_events_ptr, &raw[..bytes])
        {
            return err(ERR_BAD_POINTER);
        }
    }
    ok(read as u64)
}

// ---------------------------------------------------------------------------
// M6c: input
// ---------------------------------------------------------------------------

/// `input_read`: drain up to `max_events` events from the console seat queue.
///
/// Never blocks: an empty queue is a successful zero-event read, which is what
/// lets the `gfx` client poll for keystrokes without a timer. The batch is
/// translated into the ABI layout completely before the single `copy_out`, so a
/// bad user pointer cannot leave a partially written batch behind; when the
/// pointer is bad the events have already been consumed, exactly like `read`
/// on a file description that advanced its offset.
fn input_read(raw_handle: u64, request_ptr: u64) -> SyscallRet {
    let Some(address_space) = current_address_space() else {
        return err(ERR_BAD_HANDLE);
    };
    let resolved = match resolve_handle_any(raw_handle, Rights::READ) {
        Ok(resolved) => resolved,
        Err(status) => return err(status),
    };
    if resolved.kind != ObjectKind::Input {
        return err(ERR_BAD_HANDLE);
    }
    let mut request = InputReadRequest::default();
    if let Err(status) = copy_in_struct(address_space, request_ptr, &mut request) {
        return err(status);
    }
    if request.size != InputReadRequest::SIZE
        || request.version != REQUEST_VERSION
        || request.reserved != 0
    {
        return err(ERR_BAD_REQUEST);
    }
    if request.max_events == 0 || request.max_events > INPUT_EVENTS_MAX {
        return err(ERR_BAD_REQUEST);
    }
    if request.out_events_ptr == 0 {
        return err(ERR_BAD_POINTER);
    }
    let max_events = request.max_events as usize;
    let mut events = [ipc::input::InputEventWire::EMPTY; INPUT_EVENTS_MAX as usize];
    let read = ipc::input::read(resolved.object, &mut events[..max_events]);
    if read == 0 {
        return ok(0);
    }
    // Marshal into the frozen 24-byte ABI layout: `kind:u32, code:u32,
    // sequence:u32, reserved:u32, timestamp_ms:u64` (little endian).
    let mut raw = [0u8; 24 * INPUT_EVENTS_MAX as usize];
    for (index, event) in events.iter().enumerate().take(read) {
        let base = index * 24;
        raw[base..base + 4].copy_from_slice(&u32::from(event.kind).to_le_bytes());
        raw[base + 4..base + 8].copy_from_slice(&u32::from(event.code).to_le_bytes());
        raw[base + 8..base + 12].copy_from_slice(&event.sequence.to_le_bytes());
        // `base + 12 .. base + 16` stays zero: `InputEventWire::reserved`.
        raw[base + 16..base + 24].copy_from_slice(&event.timestamp_ms.to_le_bytes());
    }
    let bytes = 24 * read;
    if addrspace::copy_out(address_space, request.out_events_ptr, &raw[..bytes]).is_err() {
        return err(ERR_BAD_POINTER);
    }
    ok(read as u64)
}

// ---------------------------------------------------------------------------
// M6c: display
// ---------------------------------------------------------------------------

/// Map one [`ipc::display::DisplayError`] onto the ABI status codes.
fn display_status(error: ipc::display::DisplayError) -> u64 {
    match error {
        ipc::display::DisplayError::TableFull => ERR_QUOTA,
        ipc::display::DisplayError::NoMemory => ERR_QUOTA,
        ipc::display::DisplayError::NoSuchObject | ipc::display::DisplayError::WrongKind => {
            ERR_BAD_HANDLE
        }
        ipc::display::DisplayError::NotMapped | ipc::display::DisplayError::BadBuffer => {
            ERR_BAD_REQUEST
        }
    }
}

/// Resolve a `Display` handle that must carry `rights`.
fn resolve_display(raw_handle: u64, rights: Rights) -> Result<ObjectId, u64> {
    let resolved = resolve_handle_any(raw_handle, rights)?;
    if resolved.kind != ObjectKind::Display {
        return Err(ERR_BAD_HANDLE);
    }
    Ok(resolved.object)
}

/// `display_info`: report the geometry of the shadow surface the handle maps.
///
/// The wire reply is 32 bytes (`DisplayInfoWire`): the 320x200 shadow geometry
/// (`crate::display::SURFACE_*`), the live GOP pixel order and `shadow_bytes`
/// (`crate::display::SURFACE_BYTES`). The physical framebuffer mode is not part
/// of the ABI; the root prints it separately in its probe line. Nothing here
/// touches the framebuffer.
fn display_info(raw_handle: u64, request_ptr: u64) -> SyscallRet {
    let Some(address_space) = current_address_space() else {
        return err(ERR_BAD_HANDLE);
    };
    let display = match resolve_display(raw_handle, Rights::READ) {
        Ok(object) => object,
        Err(status) => return err(status),
    };
    let mut request = DisplayInfoRequest::default();
    if let Err(status) = copy_in_struct(address_space, request_ptr, &mut request) {
        return err(status);
    }
    if request.size != DisplayInfoRequest::SIZE
        || request.version != REQUEST_VERSION
        || request.reserved != 0
    {
        return err(ERR_BAD_REQUEST);
    }
    if request.out_info_ptr == 0 {
        return err(ERR_BAD_POINTER);
    }
    let info = match ipc::display::info(display) {
        Ok(info) => info,
        Err(error) => return err(display_status(error)),
    };
    // The ABI describes the 320x200 RAM shadow that `display_map` hands out, not
    // the physical framebuffer: `gfx` indexes the shadow with exactly these
    // numbers. `pixel_format` keeps the live GOP order because that is the
    // conversion `present` applies to the shadow (and the root's probe line
    // prints the physical mode separately).
    let wire = DisplayInfoWire {
        width: crate::display::SURFACE_WIDTH,
        height: crate::display::SURFACE_HEIGHT,
        stride: crate::display::SURFACE_WIDTH,
        pixel_format: info.pixel_format,
        shadow_bytes: crate::display::SURFACE_BYTES,
        reserved: 0,
    };
    if copy_out_struct(address_space, request.out_info_ptr, &wire).is_err() {
        return err(ERR_BAD_POINTER);
    }
    ok(0)
}

/// Rights a `display_map` request needs on top of `MAP`, derived from `prot`.
fn display_map_rights(prot: u32) -> Rights {
    let mut rights = Rights::MAP;
    if prot & vmobj::PROT_READ != 0 {
        rights = rights.union(Rights::READ);
    }
    if prot & vmobj::PROT_WRITE != 0 {
        rights = rights.union(Rights::WRITE);
    }
    rights
}

/// `display_map`: map the RAM shadow into the caller as one `VmObject`.
///
/// Arguments: `rdi` = `Display` handle, `rsi` = user pointer to a 32-byte
/// [`native_abi::ShmMapRequest`] (the same request `shm_map` uses). On success
/// the result register holds the new mapping handle and the base address was
/// copied out to `request.out_address`.
///
/// Execute permission is refused by [`vmobj::map_display`]: a framebuffer is
/// data. The mapping borrows the shadow frames for its lifetime and holds one
/// `Display` reference, so closing the display handle does not invalidate it.
fn display_map(raw_handle: u64, request_ptr: u64) -> SyscallRet {
    let Some(address_space) = current_address_space() else {
        return err(ERR_BAD_HANDLE);
    };
    let mut request = native_abi::ShmMapRequest::new(0, 0);
    if let Err(status) = copy_in_struct(address_space, request_ptr, &mut request) {
        return err(status);
    }
    let prot = match shm_map_request(&request) {
        Ok(prot) => prot,
        Err(status) => return err(status),
    };
    let display = match resolve_display(raw_handle, display_map_rights(prot)) {
        Ok(object) => object,
        Err(status) => return err(status),
    };
    let len = vmobj::MAX_MAP_BYTES;
    let (mapping_id, base) = match vmobj::map_display(address_space, display, prot) {
        Ok(mapping) => mapping,
        Err(error) => return err(map_status(error)),
    };
    let inserted = process::take_current_handles().map(|mut guard| {
        object::insert_new_with_payload(
            guard.table_mut(),
            ObjectKind::VmObject,
            u64::from(mapping_id),
            Rights::MAP,
        )
    });
    let handle = match inserted {
        Some(Ok(handle)) => handle,
        Some(Err(error)) => {
            let _ = vmobj::unmap(address_space, base, len);
            vmobj::release_pending();
            return err(object_status(error));
        }
        None => {
            let _ = vmobj::unmap(address_space, base, len);
            vmobj::release_pending();
            return err(ERR_BAD_HANDLE);
        }
    };
    if copy_out_struct(address_space, request.out_address, &base).is_err() {
        if !close_mapping_handle(handle) {
            let _ = vmobj::unmap(address_space, base, len);
        }
        vmobj::release_pending();
        return err(ERR_BAD_POINTER);
    }
    ok(handle.raw() as u64)
}

/// `display_present`: copy the shadow to the framebuffer.
///
/// ABI 0.5 accepts exactly one rectangle — the full `320x200` frame — and
/// requires at least one live mapping, so a client cannot present a shadow it
/// never mapped. The copy itself happens in [`crate::display::present`].
fn display_present(raw_handle: u64, request_ptr: u64) -> SyscallRet {
    let Some(address_space) = current_address_space() else {
        return err(ERR_BAD_HANDLE);
    };
    let display = match resolve_display(raw_handle, Rights::WRITE) {
        Ok(object) => object,
        Err(status) => return err(status),
    };
    let mut request = DisplayPresentRequest::default();
    if let Err(status) = copy_in_struct(address_space, request_ptr, &mut request) {
        return err(status);
    }
    if request.size != DisplayPresentRequest::SIZE || request.version != REQUEST_VERSION {
        return err(ERR_BAD_REQUEST);
    }
    if request.x != 0 || request.y != 0 || request.w != DISPLAY_WIDTH || request.h != DISPLAY_HEIGHT
    {
        return err(ERR_BAD_REQUEST);
    }
    match ipc::display::map_count(display) {
        Some(count) if count > 0 => {}
        _ => return err(ERR_BAD_REQUEST),
    }
    match ipc::display::present(display) {
        Ok(()) => ok(0),
        Err(error) => err(display_status(error)),
    }
}

// ---------------------------------------------------------------------------
// M6a2: futex
// ---------------------------------------------------------------------------

/// `futex_wait`: block while the user `u32` at `address` still equals `expected`.
///
/// The comparison runs here, on a copy taken through the checked user-memory
/// path, and the **physical** address of the word becomes the wait key: two
/// processes that reach the same word through different virtual addresses (or
/// different address spaces) wait on the same futex, and no other word does.
/// [`crate::futex::wait`] rewinds the saved user `rip`, so the call is replayed
/// from the start on wake-up and every check below runs again.
///
/// Replay rules: a recorded [`WakeReason::Ready`] reports success even if the
/// word changed meanwhile — a futex wake is allowed to be spurious and must not
/// be reported as a failure; a recorded [`WakeReason::Timeout`] reports the
/// timeout; only a call with no recorded reason re-reads the word and answers
/// `WOULD_BLOCK` when it no longer holds `expected`.
fn futex_wait(
    frame: *mut SyscallFrame,
    address: u64,
    expected: u64,
    timeout_ticks: u64,
) -> SyscallRet {
    // Consume the reason first so it is never mis-attributed to a later wait.
    let reason = process::take_wake_reason();
    match reason {
        WakeReason::Ready => return ok(0),
        WakeReason::Timeout => return err(ERR_TIMEOUT),
        WakeReason::Destroyed => return err(ERR_BAD_HANDLE),
        WakeReason::Cancelled => return err(ERR_CANCELLED),
        WakeReason::PeerClosed => return err(ERR_PEER_CLOSED),
        WakeReason::None => {}
    }
    let Some(expected) = futex_expected(expected) else {
        return err(ERR_BAD_REQUEST);
    };
    let Some(timeout_ticks) = futex_timeout_ticks(timeout_ticks) else {
        return err(ERR_BAD_REQUEST);
    };
    let Some(address_space) = current_address_space() else {
        return err(ERR_BAD_HANDLE);
    };
    let Some(physical_word) = futex_word_address(address_space, address) else {
        return err(ERR_BAD_POINTER);
    };
    let mut word = [0u8; 4];
    if addrspace::copy_in(address_space, address, &mut word).is_err() {
        return err(ERR_BAD_POINTER);
    }
    if u32::from_le_bytes(word) != expected {
        return err(ERR_WOULD_BLOCK);
    }
    if timeout_ticks == WAIT_TIMEOUT_IMMEDIATE {
        // The word matches but the caller asked not to wait: report the timeout
        // instead of blocking for a tick that would expire immediately.
        return err(ERR_TIMEOUT);
    }
    // Reaching the block means no reason was recorded, i.e. this is the first
    // entry of the call: the deadline is derived once from `now + ticks`. A
    // replay that ends in a wake returns above and never re-derives it, so a
    // spurious wake can never push the timeout further into the future.
    let deadline = first_wait_deadline(timeout_ticks, crate::time::monotonic_ticks());
    // SAFETY: the entry stub stored its own private `TrapFrame` pointer in the
    // frame we were handed; `futex::wait` re-checks that it is this process's
    // syscall frame before switching away.
    let trap_frame = unsafe { (*frame).trap_frame };
    crate::futex::wait(trap_frame, physical_word, deadline)
}

/// Validate the `expected` argument: a user `u32` widened into a register.
///
/// A wider value is a malformed request, not a value that can never match: user
/// space that passes a 64-bit number is wrong about the ABI, and silently
/// answering `WOULD_BLOCK` would hide that.
fn futex_expected(expected: u64) -> Option<u32> {
    u32::try_from(expected).ok()
}

/// Validate the `timeout_ticks` argument against the frozen `WAIT_TIMEOUT_*` range.
fn futex_timeout_ticks(ticks: u64) -> Option<u32> {
    u32::try_from(ticks).ok()
}

/// Physical address of the four-byte futex word at `address`.
///
/// `None` when the address is unmapped, outside the user half, or the word
/// straddles a page boundary: such a word occupies two frames, has no single
/// physical address and therefore no futex key.
fn futex_word_address(address_space: AddressSpaceId, address: u64) -> Option<u64> {
    let start = addrspace::translate_user(address_space, address)?;
    let end = addrspace::translate_user(address_space, address.checked_add(3)?)?;
    if end != start.checked_add(3)? {
        return None;
    }
    Some(start)
}

/// `futex_wake`: wake at most `max` waiters of the word at `address`.
///
/// The wake is unconditional (the value is not inspected) and returns the number
/// of processes actually woken, so user space can tell "nobody was waiting" from
/// "somebody was". `max == 0` wakes nobody.
fn futex_wake(address: u64, max: u64) -> SyscallRet {
    let Some(address_space) = current_address_space() else {
        return err(ERR_BAD_HANDLE);
    };
    let Some(physical_word) = futex_word_address(address_space, address) else {
        return err(ERR_BAD_POINTER);
    };
    let max = usize::try_from(max).unwrap_or(usize::MAX);
    ok(crate::futex::wake(physical_word, max) as u64)
}

// ---------------------------------------------------------------------------
// M7b: native sockets
// ---------------------------------------------------------------------------

/// Rights carried by every `Socket` handle the kernel publishes.
///
/// `WAIT` lets a socket join the unified `wait`; `MAP` is absent because a
/// socket is not memory, and `DUPLICATE` keeps `dup` available to user space.
const SOCKET_HANDLE_RIGHTS: Rights = Rights::READ
    .union(Rights::WRITE)
    .union(Rights::WAIT)
    .union(Rights::DUPLICATE);

/// Largest payload moved through `send`/`recv` in one call.
///
/// It matches the net engine's TCP segment bound (1024 B), which is also the
/// widest single message the M7b contract allows. The bounce buffer below is a
/// `.bss` array, never a stack frame, so `send`/`recv` keep the syscall stack
/// flat no matter how much user space streams.
const SOCKET_IO_MAX: usize = 1024;

/// Per-CPU bounce buffer for one `send`/`recv` payload.
///
/// User memory is never handed to the net engine: `send` copies into this
/// buffer first and `recv` copies out of it afterwards. Indexing by CPU keeps
/// two processors that enter a socket call at the same time apart.
static mut SOCKET_IO_BUFFER: [[u8; SOCKET_IO_MAX]; crate::arch::MAX_CPUS] =
    [[0u8; SOCKET_IO_MAX]; crate::arch::MAX_CPUS];

/// Number of sockets whose network namespace is remembered.
///
/// One entry per socket the engine can hold (`MAX_SOCKETS` is 16), so the table
/// can never be the reason a legal socket cannot bind.
const MAX_TRACKED_SOCKET_NAMESPACES: usize = 16;

/// `(raw socket id, namespace object)` associations recorded at `socket`.
///
/// A socket remembers the namespace it was created in: `bind`/`connect` take an
/// address but no namespace handle, so the namespace has to come from here. A
/// reference to the namespace is held while the entry exists, which keeps the
/// path-binding tables alive exactly as long as a socket can still use them.
static SOCKET_NAMESPACE_LOCK: crate::sync::IrqSpinLock = crate::sync::IrqSpinLock::new();
static mut SOCKET_NAMESPACES: [(u32, ObjectId); MAX_TRACKED_SOCKET_NAMESPACES] =
    [(0, 0); MAX_TRACKED_SOCKET_NAMESPACES];

fn socket_io_buffer() -> &'static mut [u8] {
    let cpu = crate::arch::cpu_index().min(crate::arch::MAX_CPUS - 1);
    // SAFETY: each CPU owns its row, and kernel-mode execution is never migrated
    // to another CPU in the middle of a syscall, so two users of one row cannot
    // overlap. The pointer is derived from the static's address (not a `&mut`
    // to the static), which is what edition-2024 `static_mut_refs` wants.
    unsafe {
        &mut *core::ptr::addr_of_mut!(SOCKET_IO_BUFFER)
            .cast::<[u8; SOCKET_IO_MAX]>()
            .add(cpu)
    }
}

/// The engine id behind a `Socket` object payload (raw in the low 32 bits).
fn socket_from_payload(payload: u64) -> net::SocketId {
    let raw = payload as u32;
    net::SocketId::new(usize::from((raw >> 16) as u8), raw as u16)
}

/// Map one net-engine error onto the frozen ABI 0.6 status code.
///
/// `AddressInUse` becomes `ERR_EXISTS` (a second `bind` of one path) and
/// `BadAddress` becomes `ERR_BAD_POINTER`: both are what user space is told to
/// expect in the M7b contract, which is deliberately *not* the Linux errno set.
fn socket_status(error: net::NetError) -> u64 {
    match error {
        net::NetError::Quota => ERR_QUOTA,
        net::NetError::WouldBlock => ERR_WOULD_BLOCK,
        net::NetError::InvalidSocket => ERR_BAD_HANDLE,
        net::NetError::NotConnected => ERR_NOT_CONNECTED,
        net::NetError::PeerClosed => ERR_PEER_CLOSED,
        net::NetError::Reset => ERR_CONNECTION_RESET,
        net::NetError::Refused => ERR_CONNECTION_REFUSED,
        net::NetError::Timeout => ERR_TIMEOUT,
        net::NetError::Malformed => ERR_BAD_REQUEST,
        net::NetError::Unsupported => ERR_NOT_SUPPORTED,
        net::NetError::AddressInUse => ERR_EXISTS,
        net::NetError::NotFound => ERR_NOT_FOUND,
        net::NetError::BadAddress => ERR_BAD_POINTER,
        net::NetError::TooLarge => ERR_TOO_LARGE,
    }
}

/// Whether a `Socket` counts as ready for one `wait` item.
///
/// A plain poll only promotes readable/error states: the engine reports `WRITE`
/// for every UDP socket and for almost every connected TCP socket, so accepting
/// `WRITE` on the first entry would make a receive-side wait return immediately
/// and spin. After a `Ready` wake, however, write readiness is exactly what the
/// engine is reporting: `send` returns `WouldBlock` while the peer has not been
/// accepted (or the window is full), and the engine wakes the writer with
/// `ReadyEvent::Write` once that clears. Promoting `WRITE` only on that replay
/// is what lets the caller retry the send it could not complete.
fn socket_wait_ready(mask: net::PollMask, wake_reason: WakeReason) -> bool {
    mask.contains(net::PollMask::READ)
        || mask.contains(net::PollMask::ERROR)
        || (wake_reason == WakeReason::Ready && mask.contains(net::PollMask::WRITE))
}

/// Resolve a socket handle and return the engine id it names.
fn socket_handle(raw_handle: u64, required: Rights) -> Result<net::SocketId, u64> {
    let resolved = resolve_handle_any(raw_handle, required)?;
    if resolved.kind != ObjectKind::Socket {
        return Err(ERR_BAD_HANDLE);
    }
    let payload = object_payload(resolved.object).ok_or(ERR_BAD_HANDLE)?;
    Ok(socket_from_payload(payload))
}

/// Resolve a `NetNamespace` handle.
///
/// `HANDLE_NONE` is rejected with `ERR_BAD_RIGHT` on purpose: a named UNIX bind
/// without a namespace is a rights problem in the M7b contract (the caller
/// forgot the capability), not a missing object.
fn resolve_namespace(raw_handle: u64, required: Rights) -> Result<ObjectId, u64> {
    if raw_handle == u64::from(HANDLE_NONE) {
        return Err(ERR_BAD_RIGHT);
    }
    let resolved = resolve_handle_any(raw_handle, required)?;
    if resolved.kind != ObjectKind::NetNamespace {
        return Err(ERR_BAD_HANDLE);
    }
    Ok(resolved.object)
}

/// Resolve an optional namespace handle: `HANDLE_NONE` means "no namespace".
fn optional_namespace(raw_handle: u64, required: Rights) -> Result<ObjectId, u64> {
    if raw_handle == u64::from(HANDLE_NONE) {
        return Ok(0);
    }
    resolve_namespace(raw_handle, required)
}

/// Remember the namespace a socket was created in (acquires one reference).
fn record_socket_namespace(id: net::SocketId, namespace: ObjectId) -> Result<(), u64> {
    if namespace == 0 {
        return Ok(());
    }
    object::acquire_object(namespace).map_err(object_status)?;
    // SAFETY: the table is only touched under `SOCKET_NAMESPACE_LOCK`, and the
    // pointer comes from the static's address rather than a static reference.
    let stored = SOCKET_NAMESPACE_LOCK.with(|| unsafe {
        let table = &mut *core::ptr::addr_of_mut!(SOCKET_NAMESPACES);
        if let Some(slot) = table.iter_mut().find(|(raw, _)| *raw == id.raw()) {
            slot.1 = namespace;
            return true;
        }
        if let Some(slot) = table.iter_mut().find(|(raw, _)| *raw == 0) {
            *slot = (id.raw(), namespace);
            return true;
        }
        false
    });
    if !stored {
        // The table cannot hold this socket; give the reference straight back.
        let _ = object::release_object(namespace);
        return Err(ERR_QUOTA);
    }
    Ok(())
}

/// The namespace recorded for `id`, if any.
fn socket_namespace_of(id: net::SocketId) -> Option<ObjectId> {
    // SAFETY: read-only under the same lock; see `record_socket_namespace`.
    SOCKET_NAMESPACE_LOCK.with(|| unsafe {
        let table = &*core::ptr::addr_of!(SOCKET_NAMESPACES);
        table
            .iter()
            .find(|(raw, _)| *raw == id.raw())
            .map(|(_, namespace)| *namespace)
    })
}

/// Drop the namespace association (the caller releases the reference outside
/// every lock, because that release can run the namespace destroy hook).
fn forget_socket_namespace(id: net::SocketId) -> Option<ObjectId> {
    // SAFETY: the table is only touched under `SOCKET_NAMESPACE_LOCK`.
    SOCKET_NAMESPACE_LOCK.with(|| unsafe {
        let table = &mut *core::ptr::addr_of_mut!(SOCKET_NAMESPACES);
        let slot = table.iter_mut().find(|(raw, _)| *raw == id.raw())?;
        let namespace = slot.1;
        *slot = (0, 0);
        Some(namespace)
    })
}

/// Convert one frozen `SocketAddrWire` into the engine's address type.
///
/// Validation is done here, once, so the engine never sees a half-valid
/// address: flags and path length are bounded, UNIX addresses carry no port or
/// IP bytes and a NUL-free path, and IP addresses must be loopback (M7b has no
/// route to anything else, and a request for a wider scope is `NOT_SUPPORTED`
/// rather than silently local).
///
/// `allow_ephemeral_port` admits `port == 0` for INET/INET6: `bind` uses it to
/// ask the engine for a temporary local port. `connect` passes `false`, because
/// a zero remote port is not a request for a temporary port; it is a malformed
/// address.
fn socket_address_from_wire(
    wire: &SocketAddrWire,
    allow_ephemeral_port: bool,
) -> Result<net::SocketAddress, u64> {
    if wire.flags != 0 || !wire.path_len_valid() {
        return Err(ERR_BAD_REQUEST);
    }
    if wire.family == SOCKET_FAMILY_UNIX {
        if wire.port != 0 || wire.scope != 0 || wire.addr != [0u8; 16] {
            return Err(ERR_BAD_REQUEST);
        }
        let path_len = wire.path_len as usize;
        if path_len == 0 || path_len > SOCKET_PATH_BYTES {
            return Err(ERR_BAD_REQUEST);
        }
        if wire.path[..path_len].contains(&0) {
            return Err(ERR_BAD_REQUEST);
        }
        return Ok(net::SocketAddress {
            family: wire.family,
            port: 0,
            flags: 0,
            addr: [0; 16],
            scope: 0,
            path_len: wire.path_len,
            path: wire.path,
        });
    }
    if wire.family == SOCKET_FAMILY_INET || wire.family == SOCKET_FAMILY_INET6 {
        // A zero port is only a request for a temporary local port when the
        // caller is `bind`; `connect` must name the remote endpoint.
        if wire.path_len != 0 || (wire.port == 0 && !allow_ephemeral_port) {
            return Err(ERR_BAD_REQUEST);
        }
        // ABI 0.6 reaches only the loopback interface.
        let loopback = if wire.family == SOCKET_FAMILY_INET {
            wire.addr[..4] == [127, 0, 0, 1] && wire.addr[4..] == [0u8; 12]
        } else {
            let mut expected = [0u8; 16];
            expected[15] = 1;
            wire.addr == expected && wire.scope == 0
        };
        if !loopback {
            return Err(ERR_NOT_SUPPORTED);
        }
        return Ok(net::SocketAddress {
            family: wire.family,
            port: wire.port,
            flags: 0,
            addr: wire.addr,
            scope: wire.scope,
            path_len: 0,
            path: [0; SOCKET_PATH_BYTES],
        });
    }
    Err(ERR_BAD_REQUEST)
}

/// Convert an engine address into the frozen wire layout.
fn socket_address_to_wire(address: &net::SocketAddress) -> SocketAddrWire {
    let mut wire = SocketAddrWire::empty();
    wire.family = address.family;
    wire.port = address.port;
    wire.flags = address.flags;
    wire.addr = address.addr;
    wire.scope = address.scope;
    wire.path_len = address.path_len;
    wire.path = address.path;
    wire
}

/// Create the kernel object and handle for one engine socket.
///
/// `create_with_payload` hands back an object with **one** reference (see
/// `object.rs`: only the payload-free `create` starts at zero). Inserting the
/// handle takes a second reference, so the creation reference is dropped after
/// the insert and the handle owns the only one. Dropping it is also what runs the
/// socket hook on the failure paths: `release_object` executes the queued
/// destroy outside the object lock, which closes the engine socket and releases
/// the recorded namespace reference exactly once.
fn publish_socket(id: net::SocketId) -> Result<Handle, u64> {
    let object = match object::create_with_payload(ObjectKind::Socket, u64::from(id.raw())) {
        Ok(object) => object,
        Err(error) => {
            // No object exists, so no destroy hook can run: close the engine
            // socket and drop the namespace reference here instead.
            let _ = net::destroy(id);
            if let Some(namespace) = forget_socket_namespace(id) {
                let _ = object::release_object(namespace);
            }
            return Err(object_status(error));
        }
    };
    let inserted = process::take_current_handles()
        .map(|mut guard| object::insert_handle(guard.table_mut(), object, SOCKET_HANDLE_RIGHTS));
    let handle = match inserted {
        Some(Ok(handle)) => handle,
        Some(Err(error)) => {
            let _ = object::release_object(object);
            return Err(object_status(error));
        }
        None => {
            let _ = object::release_object(object);
            return Err(ERR_BAD_HANDLE);
        }
    };
    let _ = object::release_object(object);
    if let Err(error) = net::attach_object(id, object) {
        // The handle owns the last reference; closing it queues the hook, which
        // has to run outside the process lock.
        close_socket_handle(handle);
        process::drain_pending_object_refs();
        return Err(socket_status(error));
    }
    Ok(handle)
}

/// Close one socket handle (used to roll a half-finished call back).
fn close_socket_handle(handle: Handle) -> bool {
    process::take_current_handles()
        .is_some_and(|mut guard| object::close_handle(guard.table_mut(), handle).is_ok())
}

/// Object destroy hook for `Socket`: close the engine socket.
///
/// A repeated close (rollback after a failed publish) reports an invalid id and
/// is ignored. The namespace reference, if one was recorded, is released after
/// every lock of this hook is dropped, because that release can run the
/// namespace hook and take the net stack again.
fn release_socket(payload: u64) {
    let id = socket_from_payload(payload);
    let _ = net::destroy(id);
    if let Some(namespace) = forget_socket_namespace(id) {
        let _ = object::release_object(namespace);
    }
}

/// Object destroy hook for `NetNamespace`: tear down its path bindings.
fn release_net_namespace(_kind: ObjectKind, _payload: u64, object: ObjectId) {
    let _ = net::destroy_namespace(object);
}

/// `socket`: create one socket, optionally inside a namespace.
fn socket_create(request_ptr: u64) -> SyscallRet {
    let Some(address_space) = current_address_space() else {
        return err(ERR_BAD_HANDLE);
    };
    let mut request = SocketCreateRequest::default();
    if copy_in_struct(address_space, request_ptr, &mut request).is_err() {
        return err(ERR_BAD_POINTER);
    }
    if request.size != SocketCreateRequest::SIZE || request.version != REQUEST_VERSION {
        return err(ERR_BAD_REQUEST);
    }
    if request.protocol != 0 || request.flags != 0 || request.reserved != 0 {
        return err(ERR_BAD_REQUEST);
    }
    let domain = match request.domain {
        SOCKET_DOMAIN_UNIX | SOCKET_DOMAIN_INET | SOCKET_DOMAIN_INET6 => request.domain,
        _ => return err(ERR_BAD_REQUEST),
    };
    if request.kind != SOCKET_KIND_STREAM && request.kind != SOCKET_KIND_DGRAM {
        return err(ERR_BAD_REQUEST);
    }
    let namespace = match optional_namespace(u64::from(request.namespace_handle), Rights::READ) {
        Ok(namespace) => namespace,
        Err(status) => return err(status),
    };
    // IP sockets are not namespaced in ABI 0.6: a namespace handle there is a
    // malformed request rather than something to ignore.
    if domain != SOCKET_DOMAIN_UNIX && namespace != 0 {
        return err(ERR_BAD_REQUEST);
    }
    let id = match net::create(domain, request.kind) {
        Ok(id) => id,
        Err(error) => return err(socket_status(error)),
    };
    if let Err(status) = record_socket_namespace(id, namespace) {
        let _ = net::destroy(id);
        return err(status);
    }
    match publish_socket(id) {
        Ok(handle) => ok(u64::from(handle.raw())),
        // `publish_socket` has already closed the engine socket exactly once on
        // every failure path; closing it again here would be a double close.
        Err(status) => err(status),
    }
}

/// Shared body of `bind` and `connect`: the request carries one address.
fn socket_bind_or_connect(raw_handle: u64, request_ptr: u64, connect: bool) -> SyscallRet {
    let Some(address_space) = current_address_space() else {
        return err(ERR_BAD_HANDLE);
    };
    let mut request = SocketAddrRequest::default();
    if copy_in_struct(address_space, request_ptr, &mut request).is_err() {
        return err(ERR_BAD_POINTER);
    }
    if request.size != SocketAddrRequest::SIZE
        || request.version != REQUEST_VERSION
        || request.addr_len != SOCKET_ADDR_WIRE
        || request.reserved != 0
    {
        return err(ERR_BAD_REQUEST);
    }
    if request.addr_ptr == 0 {
        return err(ERR_BAD_POINTER);
    }
    let mut wire = SocketAddrWire::empty();
    if copy_in_struct(address_space, request.addr_ptr, &mut wire).is_err() {
        return err(ERR_BAD_POINTER);
    }
    // `bind` may ask the engine for a temporary local port (`port == 0`);
    // `connect` must name a concrete remote port, so zero stays a bad request.
    let address = match socket_address_from_wire(&wire, !connect) {
        Ok(address) => address,
        Err(status) => return err(status),
    };
    let id = match socket_handle(raw_handle, Rights::READ.union(Rights::WRITE)) {
        Ok(id) => id,
        Err(status) => return err(status),
    };
    // A named local address only exists inside a namespace; an unnamed one
    // (`socketpair`, and any IP socket) uses the engine's local namespace 0.
    let namespace = if address.family == SOCKET_DOMAIN_UNIX {
        match socket_namespace_of(id) {
            Some(namespace) if namespace != 0 => namespace,
            _ => return err(ERR_BAD_RIGHT),
        }
    } else {
        0
    };
    let result = if connect {
        net::connect(id, namespace, address)
    } else {
        net::bind(id, namespace, address)
    };
    match result {
        Ok(()) => ok(0),
        // A taken local address means different things by family: a UNIX path
        // collides with a namespace binding (`EXISTS`), an INET port is a busy
        // resource (`BUSY`).
        Err(error) => err(bind_connect_status(error, address.family)),
    }
}

/// Map a `bind`/`connect` failure, splitting `AddressInUse` by address family.
///
/// The net engine reports one `AddressInUse` for both cases, but a UNIX path
/// conflict and an INET port conflict are different ABI outcomes: the former is
/// "that name already exists", the latter "that port is busy".
fn bind_connect_status(error: net::NetError, family: u32) -> u64 {
    match error {
        net::NetError::AddressInUse if family == SOCKET_DOMAIN_UNIX => ERR_EXISTS,
        net::NetError::AddressInUse => ERR_BUSY,
        other => socket_status(other),
    }
}

/// `bind`: attach a local address.
fn socket_bind(raw_handle: u64, request_ptr: u64) -> SyscallRet {
    socket_bind_or_connect(raw_handle, request_ptr, false)
}

/// `connect`: attach a remote address and start the connection.
fn socket_connect(raw_handle: u64, request_ptr: u64) -> SyscallRet {
    socket_bind_or_connect(raw_handle, request_ptr, true)
}

/// `listen`: put one stream socket into the listening state.
fn socket_listen(raw_handle: u64, backlog: u64) -> SyscallRet {
    let id = match socket_handle(raw_handle, Rights::READ.union(Rights::WRITE)) {
        Ok(id) => id,
        Err(status) => return err(status),
    };
    let Ok(backlog) = u32::try_from(backlog) else {
        return err(ERR_BAD_REQUEST);
    };
    if backlog == 0 {
        return err(ERR_BAD_REQUEST);
    }
    match net::listen(id, backlog) {
        Ok(()) => ok(0),
        Err(error) => err(socket_status(error)),
    }
}

/// `accept`: take one pending connection and publish it as a new handle.
///
/// The new handle is written to `out_handle_ptr` and returned in `rdx`; if the
/// copy-out fails the fresh socket is closed again, so a failed accept never
/// leaks a connection.
fn socket_accept(raw_handle: u64, request_ptr: u64) -> SyscallRet {
    let Some(address_space) = current_address_space() else {
        return err(ERR_BAD_HANDLE);
    };
    let mut request = SocketAcceptRequest::default();
    if copy_in_struct(address_space, request_ptr, &mut request).is_err() {
        return err(ERR_BAD_POINTER);
    }
    if request.size != SocketAcceptRequest::SIZE || request.version != REQUEST_VERSION {
        return err(ERR_BAD_REQUEST);
    }
    if request.out_handle_ptr == 0 {
        return err(ERR_BAD_POINTER);
    }
    let id = match socket_handle(raw_handle, Rights::READ.union(Rights::WAIT)) {
        Ok(id) => id,
        Err(status) => return err(status),
    };
    let new_id = match net::accept(id) {
        Ok(new_id) => new_id,
        Err(error) => return err(socket_status(error)),
    };
    let namespace = socket_namespace_of(id).unwrap_or(0);
    if let Err(status) = record_socket_namespace(new_id, namespace) {
        let _ = net::destroy(new_id);
        return err(status);
    }
    let handle = match publish_socket(new_id) {
        Ok(handle) => handle,
        // `publish_socket` already closed the accepted connection on failure.
        Err(status) => return err(status),
    };
    let raw = handle.raw();
    if copy_out_struct(address_space, request.out_handle_ptr, &raw).is_err() {
        close_socket_handle(handle);
        process::drain_pending_object_refs();
        return err(ERR_BAD_POINTER);
    }
    ok(u64::from(raw))
}

/// Bytes copied into the per-CPU bounce buffer for one `send`.
///
/// Stream sends may be arbitrarily large; the call copies one chunk and reports
/// the accepted count so the user loop continues. Datagram sizes are still
/// bounded by the engine, which reports `TOO_LARGE` before taking the message.
fn socket_send_copy_len(data_len: usize) -> usize {
    data_len.min(SOCKET_IO_MAX)
}

/// `send`: copy the payload in, hand it to the engine, report the byte count.
fn socket_send(raw_handle: u64, request_ptr: u64) -> SyscallRet {
    let Some(address_space) = current_address_space() else {
        return err(ERR_BAD_HANDLE);
    };
    let mut request = SocketSendRequest::default();
    if copy_in_struct(address_space, request_ptr, &mut request).is_err() {
        return err(ERR_BAD_POINTER);
    }
    if request.size != SocketSendRequest::SIZE || request.version != REQUEST_VERSION {
        return err(ERR_BAD_REQUEST);
    }
    if request.flags != 0 {
        return err(ERR_BAD_REQUEST);
    }
    let Ok(data_len) = usize::try_from(request.data_len) else {
        return err(ERR_TOO_LARGE);
    };
    let id = match socket_handle(raw_handle, Rights::WRITE) {
        Ok(id) => id,
        Err(status) => return err(status),
    };
    // A stream send may be larger than the per-CPU bounce buffer: copy one
    // chunk, hand it to the engine and report what it accepted, so the caller
    // loops instead of getting `TOO_LARGE` for a legal stream write. A datagram
    // still reports its own `TOO_LARGE` from the engine (peek before take).
    let copy_len = socket_send_copy_len(data_len);
    let buffer = socket_io_buffer();
    if copy_len != 0 {
        if request.data_ptr == 0 {
            return err(ERR_BAD_POINTER);
        }
        if addrspace::copy_in(address_space, request.data_ptr, &mut buffer[..copy_len]).is_err() {
            return err(ERR_BAD_POINTER);
        }
    }
    match net::send(id, &buffer[..copy_len]) {
        Ok(written) => ok(written as u64),
        Err(error) => err(socket_status(error)),
    }
}

/// `recv`: preflight the user range, receive into the bounce buffer, copy out.
///
/// A datagram that does not fit the caller's buffer is `ERR_TOO_LARGE` **and
/// stays queued**: the engine peeks before it takes. Stream data is allowed to
/// come back short, which is the normal read contract.
fn socket_recv(raw_handle: u64, request_ptr: u64) -> SyscallRet {
    let Some(address_space) = current_address_space() else {
        return err(ERR_BAD_HANDLE);
    };
    let mut request = SocketRecvRequest::default();
    if copy_in_struct(address_space, request_ptr, &mut request).is_err() {
        return err(ERR_BAD_POINTER);
    }
    if request.size != SocketRecvRequest::SIZE || request.version != REQUEST_VERSION {
        return err(ERR_BAD_REQUEST);
    }
    if request.flags != 0 {
        return err(ERR_BAD_REQUEST);
    }
    if request.data_ptr == 0 || request.data_capacity == 0 {
        return err(ERR_BAD_POINTER);
    }
    // The whole advertised range has to be writable before any data leaves the
    // engine, so a bad pointer cannot consume a message.
    if addrspace::validate_user_range(
        address_space,
        request.data_ptr,
        u64::from(request.data_capacity),
        true,
    )
    .is_err()
    {
        return err(ERR_BAD_POINTER);
    }
    let id = match socket_handle(raw_handle, Rights::READ) {
        Ok(id) => id,
        Err(status) => return err(status),
    };
    let capacity = usize::try_from(request.data_capacity)
        .unwrap_or(SOCKET_IO_MAX)
        .min(SOCKET_IO_MAX);
    let buffer = socket_io_buffer();
    let received = match net::recv(id, &mut buffer[..capacity]) {
        Ok(received) => received,
        Err(error) => return err(socket_status(error)),
    };
    if received.len > capacity {
        return err(ERR_CORRUPT);
    }
    if received.len != 0
        && addrspace::copy_out(address_space, request.data_ptr, &buffer[..received.len]).is_err()
    {
        return err(ERR_BAD_POINTER);
    }
    if request.out_source_ptr != 0 {
        let wire = match &received.source {
            Some(source) => socket_address_to_wire(source),
            None => SocketAddrWire::empty(),
        };
        if copy_out_struct(address_space, request.out_source_ptr, &wire).is_err() {
            return err(ERR_BAD_POINTER);
        }
    }
    ok(received.len as u64)
}

/// `shutdown`: close one or both directions of a connected socket.
fn socket_shutdown(raw_handle: u64, how: u64) -> SyscallRet {
    let how = match u32::try_from(how).ok() {
        Some(SOCKET_SHUTDOWN_READ) => net::ShutdownHow::Read,
        Some(SOCKET_SHUTDOWN_WRITE) => net::ShutdownHow::Write,
        Some(SOCKET_SHUTDOWN_BOTH) => net::ShutdownHow::Both,
        _ => return err(ERR_BAD_REQUEST),
    };
    let required = match how {
        net::ShutdownHow::Read => Rights::READ,
        net::ShutdownHow::Write => Rights::WRITE,
        net::ShutdownHow::Both => Rights::READ.union(Rights::WRITE),
    };
    let id = match socket_handle(raw_handle, required) {
        Ok(id) => id,
        Err(status) => return err(status),
    };
    match net::shutdown(id, how) {
        Ok(()) => ok(0),
        Err(error) => err(socket_status(error)),
    }
}

/// `socketpair`: two connected local sockets, both published atomically.
fn socket_pair(request_ptr: u64) -> SyscallRet {
    let Some(address_space) = current_address_space() else {
        return err(ERR_BAD_HANDLE);
    };
    let mut request = SocketPairRequest::default();
    if copy_in_struct(address_space, request_ptr, &mut request).is_err() {
        return err(ERR_BAD_POINTER);
    }
    if request.size != SocketPairRequest::SIZE || request.version != REQUEST_VERSION {
        return err(ERR_BAD_REQUEST);
    }
    if request.out_handles_ptr == 0 {
        return err(ERR_BAD_POINTER);
    }
    if request.domain != SOCKET_DOMAIN_UNIX
        || (request.kind != SOCKET_KIND_STREAM && request.kind != SOCKET_KIND_DGRAM)
    {
        return err(ERR_BAD_REQUEST);
    }
    let (first, second) = match net::socket_pair(request.domain, request.kind) {
        Ok(pair) => pair,
        Err(error) => return err(socket_status(error)),
    };
    let first_handle = match publish_socket(first) {
        Ok(handle) => handle,
        Err(status) => {
            // `publish_socket` closed `first`; `second` has no object yet, so it
            // still needs the explicit engine close.
            let _ = net::destroy(second);
            return err(status);
        }
    };
    let second_handle = match publish_socket(second) {
        Ok(handle) => handle,
        Err(status) => {
            // `publish_socket` closed `second`; closing the first handle queues
            // its hook, which must run outside the process lock.
            close_socket_handle(first_handle);
            process::drain_pending_object_refs();
            return err(status);
        }
    };
    let mut out = [0u8; 8];
    out[..4].copy_from_slice(&first_handle.raw().to_le_bytes());
    out[4..].copy_from_slice(&second_handle.raw().to_le_bytes());
    if addrspace::copy_out(address_space, request.out_handles_ptr, &out).is_err() {
        close_socket_handle(first_handle);
        close_socket_handle(second_handle);
        process::drain_pending_object_refs();
        return err(ERR_BAD_POINTER);
    }
    ok(0)
}

/// `socket_address`: report the local or peer address of one socket.
fn socket_address(raw_handle: u64, request_ptr: u64) -> SyscallRet {
    let Some(address_space) = current_address_space() else {
        return err(ERR_BAD_HANDLE);
    };
    let mut request = SocketAddressRequest::default();
    if copy_in_struct(address_space, request_ptr, &mut request).is_err() {
        return err(ERR_BAD_POINTER);
    }
    if request.size != SocketAddressRequest::SIZE
        || request.version != REQUEST_VERSION
        || request.reserved != 0
    {
        return err(ERR_BAD_REQUEST);
    }
    let peer = match request.which {
        SOCKET_ADDR_LOCAL => false,
        SOCKET_ADDR_PEER => true,
        _ => return err(ERR_BAD_REQUEST),
    };
    if request.out_addr_ptr == 0 {
        return err(ERR_BAD_POINTER);
    }
    let id = match socket_handle(raw_handle, Rights::READ) {
        Ok(id) => id,
        Err(status) => return err(status),
    };
    let address = match net::address(id, peer) {
        Ok(address) => address,
        Err(error) => return err(socket_status(error)),
    };
    let wire = socket_address_to_wire(&address);
    if copy_out_struct(address_space, request.out_addr_ptr, &wire).is_err() {
        return err(ERR_BAD_POINTER);
    }
    ok(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use native_abi::RIGHT_WRITE;

    #[test]
    fn an_interrupted_ppoll_replay_clears_its_wake_reason() {
        // A host test has no current process, so this exercises the "nothing to
        // clear" path; the replay path itself needs a real interrupted wait and
        // is covered by the QEMU ppoll case. What matters here: the cleanup is
        // safe to call and leaves no reason behind for the next owns-wake call.
        clear_interrupted_ppoll_reason();
        clear_interrupted_ppoll_reason();
        assert!(matches!(
            crate::process::take_wake_reason(),
            crate::process::WakeReason::None
        ));
    }

    fn valid_request() -> native_abi::ProcessCreateRequest {
        let mut request = native_abi::ProcessCreateRequest::with_module_name(b"child");
        assert!(request.push_handle(0x0001_0001, RIGHT_WRITE));
        request
    }

    #[test]
    fn abi_query_reports_the_frozen_version() {
        // Derived from the ABI crate so a version bump cannot leave this test
        // asserting a stale number; the word itself is still checked by shape.
        let expected = ((native_abi::ABI_MAJOR as u32) << 16) | native_abi::ABI_MINOR as u32;
        assert_eq!(ABI_VERSION, expected);
        assert_eq!(native_abi::ABI_MAJOR, 0);
        assert_eq!(abi_query(), ok(expected as u64));
    }

    #[test]
    fn application_processors_only_run_the_worker_whitelist() {
        // Three user programs run on APs: the M6b2 worker, the M6c gfx client and
        // the M7b net parent. The whitelist must be exactly their union and
        // nothing else: widening it would let a scheduler bug expose the BSP ABI
        // on a secondary CPU.
        for nr in [
            NR_ABI_QUERY,
            NR_WRITE,
            NR_PROCESS_CREATE,
            NR_PROCESS_WAIT,
            NR_PROCESS_EXIT,
            NR_HANDLE_CLOSE,
            NR_IPC_CREATE,
            NR_WAIT,
            NR_IPC_SEND,
            NR_IPC_RECV,
            NR_TIMER_ARM,
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
        ] {
            assert!(ap_syscall_allowed(nr), "AP syscall {nr} must be allowed");
        }
        for nr in [
            NR_RANDOM_READ,
            NR_OPEN,
            NR_READ,
            NR_MMAP,
            NR_IPC_SIGNAL,
            NR_SHM_MAP,
            NR_SUBSCRIBE,
            NR_FUTEX_WAIT,
        ] {
            assert!(
                !ap_syscall_allowed(nr),
                "syscall {nr} must stay off the AP whitelist"
            );
        }
        assert_eq!(AP_SYSCALL_WHITELIST.len(), 25);
    }

    #[test]
    fn valid_request_resolves_name_and_transfers() {
        let request = valid_request();
        let (name, count, transfers) = validate_request(&request).unwrap();
        assert_eq!(name, b"child");
        assert_eq!(count, 1);
        assert_eq!(transfers[0].handle.raw(), 0x0001_0001);
        assert_eq!(transfers[0].rights, Rights::WRITE);
    }

    /// The error code of a rejected request (the Ok type is not `PartialEq`).
    fn rejection(request: &native_abi::ProcessCreateRequest) -> u64 {
        validate_request(request).unwrap_err()
    }

    #[test]
    fn request_validation_rejects_each_bad_field() {
        let mut request = valid_request();
        request.size = 32;
        assert_eq!(rejection(&request), ERR_BAD_REQUEST, "bad size");

        let mut request = valid_request();
        request.version = REQUEST_VERSION + 1;
        assert_eq!(rejection(&request), ERR_BAD_REQUEST, "bad version");

        let mut request = valid_request();
        request.reserved = 1;
        assert_eq!(rejection(&request), ERR_BAD_REQUEST, "reserved not zero");

        let mut request = valid_request();
        request.handle_count = MAX_HANDLES as u32 + 1;
        assert_eq!(rejection(&request), ERR_BAD_REQUEST, "too many transfers");

        let mut request = native_abi::ProcessCreateRequest::empty();
        request.size = native_abi::ProcessCreateRequest::SIZE;
        request.version = REQUEST_VERSION;
        assert_eq!(rejection(&request), ERR_BAD_REQUEST, "empty name");

        let mut request = valid_request();
        request.handles[0].rights = 0;
        assert_eq!(rejection(&request), ERR_BAD_REQUEST, "empty rights");

        let mut request = valid_request();
        request.handles[0].rights = 0x8000_0000;
        assert_eq!(rejection(&request), ERR_BAD_REQUEST, "unknown right bit");
    }

    #[test]
    fn duplicate_source_handles_are_rejected() {
        // Two entries for one object would share a single transferred reference
        // in the child's table, so closing both could release that reference
        // twice. The request is malformed; the kernel refuses it up front.
        let mut request = native_abi::ProcessCreateRequest::with_module_name(b"child");
        assert!(request.push_handle(0x0001_0001, RIGHT_WRITE));
        assert!(request.push_handle(0x0001_0001, native_abi::RIGHT_READ));
        assert_eq!(rejection(&request), ERR_BAD_REQUEST, "duplicate source");
    }

    #[test]
    fn distinct_sources_and_invalid_duplicates_stay_valid() {
        // Distinct sources are the normal case.
        let mut request = native_abi::ProcessCreateRequest::with_module_name(b"child");
        assert!(request.push_handle(0x0001_0001, RIGHT_WRITE));
        assert!(request.push_handle(0x0001_0002, native_abi::RIGHT_READ));
        let (_, count, transfers) = validate_request(&request).unwrap();
        assert_eq!(count, 2);
        assert_eq!(transfers[1].handle.raw(), 0x0001_0002);

        // A repeated invalid source is not a duplicate-handle problem: it is
        // left to the process layer, which reports BAD_HANDLE for it.
        let mut request = native_abi::ProcessCreateRequest::with_module_name(b"child");
        assert!(request.push_handle(HANDLE_NONE, RIGHT_WRITE));
        assert!(request.push_handle(HANDLE_NONE, RIGHT_WRITE));
        assert!(validate_request(&request).is_ok());
    }

    #[test]
    fn process_errors_map_to_abi_status() {
        assert_eq!(process_status(ProcessError::BadRequest), ERR_BAD_REQUEST);
        assert_eq!(
            process_status(ProcessError::RightsEscalation),
            ERR_BAD_RIGHT
        );
        assert_eq!(process_status(ProcessError::NoFreeSlot), ERR_QUOTA);
        assert_eq!(
            process_status(ProcessError::Objects(ObjectError::BadHandle)),
            ERR_BAD_HANDLE
        );
        assert_eq!(process_status(ProcessError::Image), ERR_BAD_REQUEST);
    }

    #[test]
    fn object_errors_map_to_abi_status() {
        assert_eq!(object_status(ObjectError::BadHandle), ERR_BAD_HANDLE);
        assert_eq!(object_status(ObjectError::MissingRights), ERR_BAD_RIGHT);
        assert_eq!(object_status(ObjectError::RightsEscalation), ERR_BAD_RIGHT);
        assert_eq!(object_status(ObjectError::InvalidRights), ERR_BAD_RIGHT);
        assert_eq!(object_status(ObjectError::WrongObjectKind), ERR_BAD_HANDLE);
        assert_eq!(object_status(ObjectError::ObjectTableFull), ERR_QUOTA);
        assert_eq!(object_status(ObjectError::HandleTableFull), ERR_QUOTA);
    }

    #[test]
    fn rng_errors_never_look_like_success() {
        assert_eq!(rng_status(crate::rng::RngError::NoEntropy), ERR_NO_ENTROPY);
        assert_eq!(
            rng_status(crate::rng::RngError::NotCryptographic),
            ERR_NO_ENTROPY
        );
        assert_eq!(
            rng_status(crate::rng::RngError::BackendUnavailable),
            ERR_NOT_SUPPORTED
        );
    }

    #[test]
    fn oversized_requests_are_bounded() {
        // Bounds are checked before any user-memory access, so these return
        // without touching a process table.
        assert_eq!(write(0, 0, MAX_IO_BYTES + 1).status, ERR_BAD_REQUEST);
        assert_eq!(read(0, 0, MAX_IO_BYTES + 1).status, ERR_BAD_REQUEST);
        assert_eq!(
            random_read(0, 0, MAX_RANDOM_BYTES + 1).status,
            ERR_BAD_REQUEST
        );
    }

    #[test]
    fn handles_that_do_not_fit_in_32_bits_are_rejected() {
        assert_eq!(process_wait(u64::MAX).status, ERR_BAD_HANDLE);
        assert_eq!(handle_close(u64::MAX).status, ERR_BAD_HANDLE);
        assert_eq!(dup(u64::MAX, RIGHT_WRITE as u64).status, ERR_BAD_HANDLE);
        assert_eq!(sync(u64::MAX).status, ERR_BAD_HANDLE);
        assert_eq!(truncate(u64::MAX, 0).status, ERR_BAD_HANDLE);
        assert_eq!(seek(u64::MAX, 0, SEEK_SET as u64).status, ERR_BAD_HANDLE);
    }

    #[test]
    fn open_flags_translate_to_options_and_rights() {
        // A read open is read-only and grants only RIGHT_READ.
        let (options, rights) = open_options(OPEN_READ).unwrap();
        assert!(options.read && !options.write);
        assert_eq!(rights, Rights::READ);

        // A write open is write-only: nothing is implied, so it grants only
        // RIGHT_WRITE and the description cannot be read back through it.
        let (options, rights) = open_options(OPEN_WRITE).unwrap();
        assert!(!options.read && options.write);
        assert_eq!(rights, Rights::WRITE);

        // Both at once is the only way to get a read-write description.
        let (options, rights) = open_options(OPEN_READ | OPEN_WRITE).unwrap();
        assert!(options.read && options.write);
        assert_eq!(rights, Rights::READ.union(Rights::WRITE));

        // Create/truncate only modify how the open is performed.
        let (options, _) = open_options(OPEN_WRITE | OPEN_CREATE | OPEN_TRUNC).unwrap();
        assert!(options.create && options.truncate && options.write);
    }

    #[test]
    fn open_flags_reject_reserved_and_contradictory_requests() {
        assert_eq!(open_options(0).unwrap_err(), ERR_BAD_REQUEST, "no access");
        assert_eq!(
            open_options(0x0001_0000).unwrap_err(),
            ERR_BAD_REQUEST,
            "reserved bit"
        );
        assert_eq!(
            open_options(OPEN_TRUNC).unwrap_err(),
            ERR_BAD_REQUEST,
            "truncate without write"
        );
        assert_eq!(
            open_options(OPEN_READ | OPEN_TRUNC).unwrap_err(),
            ERR_BAD_REQUEST,
            "truncate without write"
        );
        assert!(open_options(OPEN_READ | OPEN_DIRECTORY).is_ok());
    }

    #[test]
    fn path_lengths_are_bounded() {
        assert_eq!(path_length(0).unwrap_err(), ERR_BAD_REQUEST);
        assert_eq!(
            path_length(vfs::MAX_PATH as u64 + 1).unwrap_err(),
            ERR_BAD_POINTER
        );
        assert_eq!(path_length(1).unwrap(), 1);
        assert_eq!(path_length(vfs::MAX_PATH as u64).unwrap(), vfs::MAX_PATH);
    }

    #[test]
    fn seek_arguments_are_translated_and_validated() {
        assert_eq!(
            seek_request(SEEK_SET as u64, 7).unwrap(),
            SeekFrom::Start(7)
        );
        assert_eq!(
            seek_request(SEEK_CUR as u64, (-3i64) as u64).unwrap(),
            SeekFrom::Current(-3)
        );
        assert_eq!(seek_request(SEEK_END as u64, 0).unwrap(), SeekFrom::End(0));
        assert_eq!(seek_request(3, 0).unwrap_err(), ERR_BAD_REQUEST);
        assert_eq!(seek_request(u64::MAX, 0).unwrap_err(), ERR_BAD_REQUEST);
    }

    #[test]
    fn dup_rights_must_be_non_empty_and_known() {
        assert_eq!(dup_rights(0).unwrap_err(), ERR_BAD_RIGHT);
        assert_eq!(dup_rights(0x8000_0000).unwrap_err(), ERR_BAD_RIGHT);
        assert_eq!(dup_rights(u64::from(RIGHT_WRITE)).unwrap(), Rights::WRITE);
        assert_eq!(
            dup_rights(u64::from(native_abi::RIGHT_READ | RIGHT_WRITE)).unwrap(),
            Rights::READ.union(Rights::WRITE)
        );
    }

    #[test]
    fn vfs_errors_map_to_abi_status() {
        assert_eq!(vfs_status(VfsError::NotFound), ERR_NOT_FOUND);
        assert_eq!(vfs_status(VfsError::NotDirectory), ERR_NOT_DIR);
        assert_eq!(vfs_status(VfsError::IsDirectory), ERR_IS_DIR);
        assert_eq!(vfs_status(VfsError::AlreadyExists), ERR_EXISTS);
        assert_eq!(vfs_status(VfsError::ReadOnly), ERR_READ_ONLY);
        assert_eq!(vfs_status(VfsError::BadPath), ERR_BAD_REQUEST);
        assert_eq!(vfs_status(VfsError::NameTooLong), ERR_BAD_REQUEST);
        assert_eq!(vfs_status(VfsError::Quota), ERR_QUOTA);
        assert_eq!(vfs_status(VfsError::PermissionDenied), ERR_BAD_RIGHT);
        assert_eq!(vfs_status(VfsError::WouldBlock), ERR_WOULD_BLOCK);
        assert_eq!(vfs_status(VfsError::NotSupported), ERR_NOT_SUPPORTED);
        assert_eq!(vfs_status(VfsError::Corrupt), ERR_CORRUPT);
        assert_eq!(vfs_status(VfsError::NoMemory), ERR_NO_SPACE);
        assert_eq!(vfs_status(VfsError::Busy), ERR_BUSY);
        assert_eq!(vfs_status(VfsError::NotEmpty), ERR_NOT_EMPTY);
        assert_eq!(vfs_status(VfsError::Io), ERR_IO);
        assert_eq!(vfs_status(VfsError::Timeout), ERR_TIMEOUT);
    }

    #[test]
    fn reserved_calls_are_not_supported() {
        // 0.6 numbers 0–53. The ones this slice does not implement are frozen for
        // later stages and must answer `NOT_SUPPORTED`, never a silent success.
        for nr in [native_abi::NR_IPC_TRANSFER] {
            let mut frame = zero_frame(nr);
            assert_eq!(dispatch(&mut frame).status, ERR_NOT_SUPPORTED, "nr {nr}");
        }
        // Everything past the frozen range is unknown as well.
        for nr in 54u64..=64 {
            let mut frame = zero_frame(nr);
            assert_eq!(dispatch(&mut frame).status, ERR_NOT_SUPPORTED, "nr {nr}");
        }
        let mut frame = zero_frame(u64::MAX);
        assert_eq!(dispatch(&mut frame).status, ERR_NOT_SUPPORTED);
    }

    /// A zeroed frame with `nr` set and no arguments.
    fn zero_frame(nr: u64) -> SyscallFrame {
        SyscallFrame {
            nr,
            args: [0; 6],
            user_rip: 0,
            user_rflags: 0,
            user_rsp: 0,
            user_ss: 0,
            trap_frame: core::ptr::null_mut(),
        }
    }

    fn valid_mmap() -> native_abi::MmapRequest {
        native_abi::MmapRequest::new(
            8192,
            4096,
            native_abi::PROT_READ | native_abi::PROT_WRITE,
            native_abi::MMAP_SHARED,
            0x0080_0000,
        )
    }

    #[test]
    fn mmap_request_accepts_a_well_formed_request() {
        let plan = map_request(&valid_mmap()).unwrap();
        assert_eq!(plan.len, 8192);
        assert_eq!(plan.offset, 4096);
        assert_eq!(
            plan.prot,
            native_abi::PROT_READ | native_abi::PROT_WRITE,
            "read/write is accepted"
        );
        assert!(plan.shared);
        assert_eq!(plan.out_address, 0x0080_0000);

        let private = native_abi::MmapRequest::new(
            4096,
            0,
            native_abi::PROT_READ,
            native_abi::MMAP_PRIVATE,
            0x0080_0000,
        );
        assert!(!map_request(&private).unwrap().shared);
    }

    #[test]
    fn mmap_request_rejects_a_bad_header() {
        let mut request = valid_mmap();
        request.size = native_abi::MmapRequest::SIZE - 8;
        assert_eq!(map_request(&request).unwrap_err(), ERR_BAD_REQUEST);

        let mut request = valid_mmap();
        request.version = REQUEST_VERSION + 1;
        assert_eq!(map_request(&request).unwrap_err(), ERR_BAD_REQUEST);

        let mut request = valid_mmap();
        request.reserved = 1;
        assert_eq!(map_request(&request).unwrap_err(), ERR_BAD_REQUEST);
    }

    #[test]
    fn mmap_request_maps_protection_to_errors() {
        // Execution permission is a later stage, not a malformed request.
        let mut request = valid_mmap();
        request.prot = native_abi::PROT_READ | native_abi::PROT_EXEC;
        assert_eq!(map_request(&request).unwrap_err(), ERR_NOT_SUPPORTED);

        // Write plus execute is rejected for the same reason, not as W+X.
        let mut request = valid_mmap();
        request.prot = native_abi::PROT_READ | native_abi::PROT_WRITE | native_abi::PROT_EXEC;
        assert_eq!(map_request(&request).unwrap_err(), ERR_NOT_SUPPORTED);

        // Unknown bits are malformed.
        let mut request = valid_mmap();
        request.prot = native_abi::PROT_READ | (1 << 7);
        assert_eq!(map_request(&request).unwrap_err(), ERR_BAD_REQUEST);

        // A mapping must be readable.
        let mut request = valid_mmap();
        request.prot = native_abi::PROT_WRITE;
        assert_eq!(map_request(&request).unwrap_err(), ERR_BAD_REQUEST);
    }

    #[test]
    fn mmap_request_requires_exactly_one_sharing_mode() {
        for flags in [
            0,
            native_abi::MMAP_SHARED | native_abi::MMAP_PRIVATE,
            1 << 5,
        ] {
            let mut request = valid_mmap();
            request.flags = flags;
            assert_eq!(
                map_request(&request).unwrap_err(),
                ERR_BAD_REQUEST,
                "flags {flags:#x}"
            );
        }
    }

    #[test]
    fn mmap_request_rejects_bad_length_and_offset() {
        for len in [0, 1, 4095, MAX_MAP_BYTES + vfs::PAGE] {
            let mut request = valid_mmap();
            request.len = len;
            assert_eq!(
                map_request(&request).unwrap_err(),
                ERR_BAD_REQUEST,
                "len {len}"
            );
        }
        // Exactly the maximum is fine.
        let mut request = valid_mmap();
        request.len = MAX_MAP_BYTES;
        assert!(map_request(&request).is_ok());

        let mut request = valid_mmap();
        request.offset = 1;
        assert_eq!(map_request(&request).unwrap_err(), ERR_BAD_REQUEST);

        // `offset + len` must not wrap.
        let mut request = valid_mmap();
        request.offset = u64::MAX & !(vfs::PAGE - 1);
        assert_eq!(map_request(&request).unwrap_err(), ERR_BAD_REQUEST);
    }

    #[test]
    fn mmap_request_rejects_a_null_out_address() {
        let mut request = valid_mmap();
        request.out_address = 0;
        assert_eq!(map_request(&request).unwrap_err(), ERR_BAD_POINTER);
    }

    #[test]
    fn map_range_requires_an_aligned_nonempty_range() {
        assert!(map_range(0x0080_0000, 4096).is_ok());
        assert_eq!(map_range(1, 4096).unwrap_err(), ERR_BAD_REQUEST);
        assert_eq!(map_range(0x0080_0000, 0).unwrap_err(), ERR_BAD_REQUEST);
        assert_eq!(map_range(0x0080_0000, 1).unwrap_err(), ERR_BAD_REQUEST);
        assert_eq!(
            map_range(u64::MAX & !(vfs::PAGE - 1), 4096).unwrap_err(),
            ERR_BAD_REQUEST
        );
    }

    #[test]
    fn map_rights_requires_write_only_for_shared_writable_mappings() {
        let writable = MapPlan {
            len: 4096,
            offset: 0,
            prot: native_abi::PROT_READ | native_abi::PROT_WRITE,
            shared: true,
            out_address: 0x0080_0000,
        };
        assert_eq!(map_rights(&writable), Rights::READ.union(Rights::WRITE));

        let read_only = MapPlan {
            prot: native_abi::PROT_READ,
            ..writable
        };
        assert_eq!(map_rights(&read_only), Rights::READ);

        // A private writable mapping never writes through, so READ suffices.
        let private = MapPlan {
            shared: false,
            ..writable
        };
        assert_eq!(map_rights(&private), Rights::READ);
    }

    #[test]
    fn map_errors_map_to_abi_status() {
        assert_eq!(map_status(vmobj::MapError::BadRequest), ERR_BAD_REQUEST);
        assert_eq!(map_status(vmobj::MapError::NotFound), ERR_NOT_FOUND);
        assert_eq!(map_status(vmobj::MapError::Quota), ERR_QUOTA);
        assert_eq!(map_status(vmobj::MapError::Busy), ERR_BUSY);
        assert_eq!(map_status(vmobj::MapError::Io), ERR_IO);
        assert_eq!(map_status(vmobj::MapError::NoMemory), ERR_NO_SPACE);
        assert_eq!(map_status(vmobj::MapError::NotSupported), ERR_NOT_SUPPORTED);
    }

    #[test]
    fn munmap_and_mprotect_reject_bad_arguments_before_any_lookup() {
        // Argument validation happens before the address space is consulted, so
        // these are deterministic even without a current process.
        let mut frame = zero_frame(NR_MUNMAP);
        frame.args[0] = 1;
        frame.args[1] = 4096;
        assert_eq!(
            dispatch(&mut frame).status,
            ERR_BAD_REQUEST,
            "unaligned base"
        );

        let mut frame = zero_frame(NR_MUNMAP);
        frame.args[0] = 0x0080_0000;
        frame.args[1] = 0;
        assert_eq!(dispatch(&mut frame).status, ERR_BAD_REQUEST, "empty range");

        let mut frame = zero_frame(NR_MPROTECT);
        frame.args[0] = 0x0080_0000;
        frame.args[1] = 4096;
        frame.args[2] = native_abi::PROT_READ as u64 | native_abi::PROT_EXEC as u64;
        assert_eq!(dispatch(&mut frame).status, ERR_NOT_SUPPORTED);

        let mut frame = zero_frame(NR_MPROTECT);
        frame.args[0] = 1;
        frame.args[1] = 4096;
        frame.args[2] = native_abi::PROT_READ as u64;
        assert_eq!(dispatch(&mut frame).status, ERR_BAD_REQUEST);

        let mut frame = zero_frame(NR_MPROTECT);
        frame.args[0] = 0x0080_0000;
        frame.args[1] = 4096;
        frame.args[2] = 0x1_0000_0000;
        assert_eq!(
            dispatch(&mut frame).status,
            ERR_BAD_REQUEST,
            "prot wider than u32"
        );
    }

    // -- M5c3: locks, extended attributes, directory watches -----------------

    fn valid_lock() -> LockRequest {
        LockRequest::new(
            native_abi::LOCK_DOMAIN_POSIX,
            native_abi::LOCK_OP_SHARED,
            0,
            4096,
        )
    }

    #[test]
    fn lock_request_accepts_a_well_formed_request() {
        let plan = lock_plan(&valid_lock()).unwrap();
        assert_eq!(plan.domain, vfs::lock::LockDomain::Posix);
        assert_eq!(plan.kind, Some(vfs::lock::LockKind::Shared));
        assert_eq!(plan.required, Rights::READ);
        assert_eq!(plan.offset, 0);
        assert_eq!(plan.len, 4096);
    }

    #[test]
    fn lock_request_maps_operations_to_rights() {
        let mut request = valid_lock();
        request.operation = native_abi::LOCK_OP_EXCLUSIVE;
        let plan = lock_plan(&request).unwrap();
        assert_eq!(plan.kind, Some(vfs::lock::LockKind::Exclusive));
        assert_eq!(plan.required, Rights::WRITE);

        let mut request = valid_lock();
        request.operation = native_abi::LOCK_OP_UNLOCK;
        let plan = lock_plan(&request).unwrap();
        assert_eq!(plan.kind, None, "unlocking names no lock kind");
        assert_eq!(plan.required, Rights::NONE);
    }

    #[test]
    fn lock_request_accepts_every_domain() {
        let cases = [
            (native_abi::LOCK_DOMAIN_POSIX, vfs::lock::LockDomain::Posix),
            (
                native_abi::LOCK_DOMAIN_OFD,
                vfs::lock::LockDomain::OpenDescription,
            ),
            (native_abi::LOCK_DOMAIN_FLOCK, vfs::lock::LockDomain::Flock),
        ];
        for (raw, expected) in cases {
            let mut request = valid_lock();
            request.domain = raw;
            assert_eq!(
                lock_plan(&request).unwrap().domain,
                expected,
                "domain {raw}"
            );
        }
    }

    #[test]
    fn lock_request_rejects_a_bad_header_or_field() {
        let mut request = valid_lock();
        request.size = LockRequest::SIZE - 8;
        assert_eq!(lock_plan(&request).unwrap_err(), ERR_BAD_REQUEST);

        let mut request = valid_lock();
        request.version = REQUEST_VERSION + 1;
        assert_eq!(lock_plan(&request).unwrap_err(), ERR_BAD_REQUEST);

        let mut request = valid_lock();
        request.domain = 0;
        assert_eq!(lock_plan(&request).unwrap_err(), ERR_BAD_REQUEST);

        let mut request = valid_lock();
        request.domain = native_abi::LOCK_DOMAIN_FLOCK + 1;
        assert_eq!(lock_plan(&request).unwrap_err(), ERR_BAD_REQUEST);

        let mut request = valid_lock();
        request.operation = 0;
        assert_eq!(lock_plan(&request).unwrap_err(), ERR_BAD_REQUEST);

        let mut request = valid_lock();
        request.operation = native_abi::LOCK_OP_UNLOCK + 1;
        assert_eq!(lock_plan(&request).unwrap_err(), ERR_BAD_REQUEST);
    }

    fn xattr_request(name_len: u64) -> XattrRequest {
        XattrRequest::new(0, name_len, 0, 0)
    }

    #[test]
    fn xattr_header_checks_the_fixed_part() {
        assert_eq!(xattr_header(&xattr_request(9)).unwrap(), 9);

        assert_eq!(
            xattr_header(&xattr_request(0)).unwrap_err(),
            ERR_BAD_REQUEST,
            "an empty name is malformed"
        );
        assert_eq!(
            xattr_header(&xattr_request(MAX_XATTR_NAME as u64 + 1)).unwrap_err(),
            ERR_BAD_REQUEST
        );

        let mut request = xattr_request(9);
        request.size = XattrRequest::SIZE - 8;
        assert_eq!(xattr_header(&request).unwrap_err(), ERR_BAD_REQUEST);

        let mut request = xattr_request(9);
        request.version = REQUEST_VERSION + 1;
        assert_eq!(xattr_header(&request).unwrap_err(), ERR_BAD_REQUEST);
    }

    #[test]
    fn xattr_names_must_use_the_user_namespace() {
        assert!(xattr_name(b"user.flag").is_ok());
        assert!(
            xattr_name(b"user.").is_ok(),
            "a bare prefix is still a name"
        );
        // A foreign namespace is well formed but unsupported in 0.2.
        assert_eq!(
            xattr_name(b"system.posix_acl").unwrap_err(),
            ERR_NOT_SUPPORTED
        );
        assert_eq!(xattr_name(b"User.flag").unwrap_err(), ERR_NOT_SUPPORTED);
        assert_eq!(xattr_name(b"userx").unwrap_err(), ERR_NOT_SUPPORTED);
        // A NUL byte inside the name is malformed, not a namespace question.
        assert_eq!(xattr_name(b"user.a\0b").unwrap_err(), ERR_BAD_REQUEST);
        assert_eq!(xattr_name(b"\0user.a").unwrap_err(), ERR_BAD_REQUEST);
    }

    fn watch_drain_request(max_events: u64) -> WatchDrainRequest {
        WatchDrainRequest::new(0, max_events)
    }

    #[test]
    fn watch_drain_batch_is_bounded() {
        assert_eq!(watch_drain_count(&watch_drain_request(1)).unwrap(), 1);
        assert_eq!(
            watch_drain_count(&watch_drain_request(WATCH_MAX_BATCH)).unwrap(),
            WATCH_MAX_BATCH as usize
        );
        assert_eq!(
            watch_drain_count(&watch_drain_request(0)).unwrap_err(),
            ERR_BAD_REQUEST
        );
        assert_eq!(
            watch_drain_count(&watch_drain_request(WATCH_MAX_BATCH + 1)).unwrap_err(),
            ERR_BAD_REQUEST
        );

        let mut request = watch_drain_request(1);
        request.size = WatchDrainRequest::SIZE - 8;
        assert_eq!(watch_drain_count(&request).unwrap_err(), ERR_BAD_REQUEST);

        let mut request = watch_drain_request(1);
        request.version = REQUEST_VERSION + 1;
        assert_eq!(watch_drain_count(&request).unwrap_err(), ERR_BAD_REQUEST);
    }

    #[test]
    fn watch_event_kinds_match_the_abi() {
        assert_eq!(
            notify_kind(vfs::notify::NotifyKind::Created),
            native_abi::WATCH_EVENT_CREATED
        );
        assert_eq!(
            notify_kind(vfs::notify::NotifyKind::Deleted),
            native_abi::WATCH_EVENT_DELETED
        );
        assert_eq!(
            notify_kind(vfs::notify::NotifyKind::Renamed),
            native_abi::WATCH_EVENT_RENAMED
        );
    }

    /// The M5c3 calls exist as real dispatch arms, not as reserved numbers: with
    /// no current process they fail on the process check rather than reporting
    /// `NOT_SUPPORTED`.
    #[test]
    fn m5c3_calls_are_dispatched() {
        for nr in [
            native_abi::NR_LOCK,
            native_abi::NR_XATTR_SET,
            native_abi::NR_XATTR_GET,
            native_abi::NR_WATCH,
            native_abi::NR_WATCH_DRAIN,
        ] {
            let mut frame = zero_frame(nr);
            assert_eq!(
                dispatch(&mut frame).status,
                ERR_BAD_HANDLE,
                "nr {nr} must reach its implementation"
            );
        }
    }

    /// The `open` syscall must stamp the calling process onto the description.
    ///
    /// `vfs::open_path` hard-codes owner 0; two processes opening through it
    /// share one POSIX-lock owner, so a cross-process lock conflict is invisible.
    /// Only the owner-aware entry may be used here, and the check is static so a
    /// future edit cannot quietly reintroduce the owner-less call.
    #[test]
    fn open_uses_the_owner_aware_vfs_entry() {
        let source = include_str!("syscall.rs");
        let owner_aware = concat!("vfs::open_path", "_as(");
        let owner_less = concat!("vfs::open_path", "(");
        assert!(
            source.contains(owner_aware),
            "the open syscall must pass the calling process as the description owner"
        );
        assert!(
            !source.contains(owner_less),
            "vfs::open_path hard-codes owner 0 and must not be used by the syscall layer"
        );
    }

    // -----------------------------------------------------------------------
    // M6a1: IPC syscalls
    // -----------------------------------------------------------------------

    #[test]
    fn ipc_create_accepts_the_supported_kinds() {
        let event = ipc_create_plan(&IpcCreateRequest::new(IPC_KIND_EVENT, 0, 0, 0)).unwrap();
        assert_eq!(
            event,
            IpcCreatePlan::Single {
                kind: ObjectKind::Event,
                manual_reset: false,
            }
        );

        let manual = ipc_create_plan(&IpcCreateRequest::new(
            IPC_KIND_EVENT,
            EVENT_FLAG_MANUAL_RESET,
            0,
            0,
        ))
        .unwrap();
        assert_eq!(
            manual,
            IpcCreatePlan::Single {
                kind: ObjectKind::Event,
                manual_reset: true,
            }
        );

        assert_eq!(
            ipc_create_plan(&IpcCreateRequest::new(IPC_KIND_EVENT_PAIR, 0, 0, 0)).unwrap(),
            IpcCreatePlan::Single {
                kind: ObjectKind::EventPair,
                manual_reset: false,
            }
        );
        assert_eq!(
            ipc_create_plan(&IpcCreateRequest::new(IPC_KIND_TIMER, 0, 0, 0)).unwrap(),
            IpcCreatePlan::Single {
                kind: ObjectKind::Timer,
                manual_reset: false,
            }
        );

        // Channel and Port are pairs: they need the second handle's destination.
        let channel = IpcCreateRequest::new_pair(IPC_KIND_CHANNEL, 0, 0, 0, 0x2000);
        assert_eq!(ipc_create_plan(&channel).unwrap(), IpcCreatePlan::Channel);
        let port = IpcCreateRequest::new_pair(IPC_KIND_PORT, 0, 0, 0, 0x2000);
        assert_eq!(ipc_create_plan(&port).unwrap(), IpcCreatePlan::Port);
    }

    #[test]
    fn ipc_create_rejects_bad_headers_and_unused_arguments() {
        let mut request = IpcCreateRequest::new(IPC_KIND_EVENT, 0, 0, 0);
        request.size = 16;
        assert_eq!(ipc_create_plan(&request), Err(ERR_BAD_REQUEST), "bad size");

        let mut request = IpcCreateRequest::new(IPC_KIND_EVENT, 0, 0, 0);
        request.version = REQUEST_VERSION + 1;
        assert_eq!(
            ipc_create_plan(&request),
            Err(ERR_BAD_REQUEST),
            "bad version"
        );

        // Unknown creation-flag bits are a malformed request, not a new feature.
        let request = IpcCreateRequest::new(IPC_KIND_EVENT, 1 << 8, 0, 0);
        assert_eq!(ipc_create_plan(&request), Err(ERR_BAD_REQUEST));

        // `arg0`/`arg1` must be zero for every kind this stage supports.
        let request = IpcCreateRequest::new(IPC_KIND_EVENT_PAIR, 0, 1, 0);
        assert_eq!(ipc_create_plan(&request), Err(ERR_BAD_REQUEST));
        let request = IpcCreateRequest::new(IPC_KIND_TIMER, 0, 0, 1);
        assert_eq!(ipc_create_plan(&request), Err(ERR_BAD_REQUEST));

        // A pair without a place to put the second handle would leak it.
        let request = IpcCreateRequest::new(IPC_KIND_CHANNEL, 0, 0, 0);
        assert_eq!(ipc_create_plan(&request), Err(ERR_BAD_REQUEST));
        let request = IpcCreateRequest::new_pair(IPC_KIND_PORT, 0, 1, 0, 0x2000);
        assert_eq!(ipc_create_plan(&request), Err(ERR_BAD_REQUEST));
        let request = IpcCreateRequest::new_pair(IPC_KIND_CHANNEL, 1, 0, 0, 0x2000);
        assert_eq!(ipc_create_plan(&request), Err(ERR_BAD_REQUEST));

        // Kind 0 and kinds past the frozen range are malformed.
        let request = IpcCreateRequest::new(0, 0, 0, 0);
        assert_eq!(ipc_create_plan(&request), Err(ERR_BAD_REQUEST));
        let request = IpcCreateRequest::new(native_abi::IPC_KIND_MAX + 1, 0, 0, 0);
        assert_eq!(ipc_create_plan(&request), Err(ERR_BAD_REQUEST));
    }

    #[test]
    fn ipc_create_builds_shared_memory_and_subscriptions() {
        // A SharedMemory object takes its byte length in `arg0` and returns one
        // handle, so a second-handle pointer is malformed.
        let request = IpcCreateRequest::new(IPC_KIND_SHARED_MEMORY, 0, 4096, 0);
        assert_eq!(
            ipc_create_plan(&request),
            Ok(IpcCreatePlan::SharedMemory { length: 4096 })
        );
        let request = IpcCreateRequest::new_pair(IPC_KIND_SHARED_MEMORY, 0, 4096, 0, 0x2000);
        assert_eq!(
            ipc_create_plan(&request),
            Err(ERR_BAD_REQUEST),
            "second handle"
        );
        let request = IpcCreateRequest::new(IPC_KIND_SHARED_MEMORY, 1, 4096, 0);
        assert_eq!(ipc_create_plan(&request), Err(ERR_BAD_REQUEST), "flags");

        // A subscription starts empty: every argument must be zero.
        let request = IpcCreateRequest::new(IPC_KIND_SUBSCRIPTION, 0, 0, 0);
        assert_eq!(ipc_create_plan(&request), Ok(IpcCreatePlan::Subscription));
        let request = IpcCreateRequest::new(IPC_KIND_SUBSCRIPTION, 0, 1, 0);
        assert_eq!(ipc_create_plan(&request), Err(ERR_BAD_REQUEST), "arg0");
        let request = IpcCreateRequest::new_pair(IPC_KIND_SUBSCRIPTION, 0, 0, 0, 0x2000);
        assert_eq!(
            ipc_create_plan(&request),
            Err(ERR_BAD_REQUEST),
            "second handle"
        );
    }

    /// `create_bound_object` relies on `create_object` handing out **zero**
    /// references: the inserted handle acquires the first and only one, so the
    /// success path must not release anything. Releasing here used to drop the
    /// count to zero, run the destroy hook and free the shm slot, which made the
    /// very next `shm_map` fail with `NoSuchObject`.
    #[test]
    fn bound_objects_keep_their_table_slot_while_a_handle_exists() {
        let _guard = object::test_lock();
        object::reset_destroy_hooks();
        crate::ipc::shm::reset();
        assert!(crate::ipc::install_destroy_hooks().is_ok());

        let object = object::create_object(ObjectKind::SharedMemory).expect("create");
        assert_eq!(
            object::object_refs(object),
            Some(0),
            "create gives no reference"
        );
        assert_eq!(crate::ipc::shm::create(object, 8192), Ok(2));

        let mut table = object::HandleTable::new();
        let handle = object::insert_handle(&mut table, object, SHM_HANDLE_RIGHTS).expect("insert");
        assert_eq!(object::object_refs(object), Some(1));
        // The bind result must survive the handle insertion.
        assert_eq!(crate::ipc::shm::pages(object), Ok(2));
        assert_eq!(crate::ipc::shm::live_objects(), 1);

        // Closing the only handle drops the last reference, which frees the frames.
        assert!(object::close_handle(&mut table, handle).is_ok());
        assert_eq!(object::object_kind(object), None);
        assert_eq!(
            crate::ipc::shm::pages(object),
            Err(crate::ipc::shm::ShmError::NoSuchObject)
        );
        assert_eq!(crate::ipc::shm::live_frames(), 0);
        object::reset_destroy_hooks();
        crate::ipc::shm::reset();
    }

    /// A failed bind never inserted the object, so it still has zero references:
    /// `destroy_object` is the entry point that runs the destroy hook and frees
    /// whatever `bind` allocated. Releasing would target a zero count instead.
    #[test]
    fn a_failed_bind_frees_the_table_slot() {
        let _guard = object::test_lock();
        object::reset_destroy_hooks();
        crate::ipc::shm::reset();
        assert!(crate::ipc::install_destroy_hooks().is_ok());

        let object = object::create_object(ObjectKind::SharedMemory).expect("create");
        assert_eq!(crate::ipc::shm::create(object, 4096), Ok(1));
        assert_eq!(crate::ipc::shm::live_frames(), 1);

        assert!(object::destroy_object(object).is_ok());
        assert_eq!(object::object_kind(object), None);
        assert_eq!(
            crate::ipc::shm::pages(object),
            Err(crate::ipc::shm::ShmError::NoSuchObject)
        );
        assert_eq!(crate::ipc::shm::live_frames(), 0);
        object::reset_destroy_hooks();
        crate::ipc::shm::reset();
    }

    /// Probe hook for the guard tests: records whether the process lock was held
    /// while the destroy hook (the side effect that needs the VFS/IPC locks) ran.
    mod lock_probe {
        use super::*;
        use core::sync::atomic::{AtomicBool, AtomicU16, AtomicUsize, Ordering};

        /// Objects this probe test created itself; other tests destroy
        /// `VmObject`s concurrently and must not inflate the count.
        const MAX_EXPECTED: usize = 2;
        static HOOKS: AtomicUsize = AtomicUsize::new(0);
        static LOCK_HELD: AtomicBool = AtomicBool::new(false);
        static EXPECTED: [AtomicU16; MAX_EXPECTED] = [const { AtomicU16::new(0) }; MAX_EXPECTED];
        static EXPECTED_COUNT: AtomicUsize = AtomicUsize::new(0);

        std::thread_local! {
            /// Whether the current thread is the probe test that installed the
            /// hook. Object ids are recycled, so another test on another thread
            /// can destroy a `VmObject` with the same id after this test's
            /// object died; only the probe thread's own destroys count.
            static ON_PROBE_THREAD: core::cell::Cell<bool> = const { core::cell::Cell::new(false) };
        }

        pub(super) fn reset() {
            ON_PROBE_THREAD.with(|flag| flag.set(true));
            HOOKS.store(0, Ordering::SeqCst);
            LOCK_HELD.store(false, Ordering::SeqCst);
            for slot in EXPECTED.iter() {
                slot.store(0, Ordering::SeqCst);
            }
            EXPECTED_COUNT.store(0, Ordering::SeqCst);
        }

        /// Only count the object this test creates.
        pub(super) fn expect(object: object::ObjectId) {
            let index = EXPECTED_COUNT.load(Ordering::SeqCst);
            if index < MAX_EXPECTED {
                EXPECTED[index].store(object, Ordering::SeqCst);
                EXPECTED_COUNT.store(index + 1, Ordering::SeqCst);
            }
        }

        pub(super) fn hooks() -> usize {
            HOOKS.load(Ordering::SeqCst)
        }

        pub(super) fn lock_was_held() -> bool {
            LOCK_HELD.load(Ordering::SeqCst)
        }

        pub(super) fn record(_kind: ObjectKind, _payload: u64, object: object::ObjectId) {
            if !ON_PROBE_THREAD.with(|flag| flag.get()) {
                return;
            }
            let count = EXPECTED_COUNT.load(Ordering::SeqCst);
            if !EXPECTED[..count]
                .iter()
                .any(|slot| slot.load(Ordering::SeqCst) == object)
            {
                return;
            }
            HOOKS.fetch_add(1, Ordering::SeqCst);
            // The whole point of the `CurrentHandlesGuard` migration: this runs
            // after the process lock is released.
            LOCK_HELD.fetch_or(process::process_lock_is_held(), Ordering::SeqCst);
        }
    }

    /// `handle_close` must take the table out of the process slot before closing:
    /// the `VmObject` destroy hook runs under the object/VFS locks, so it cannot
    /// run while `PROCESS_LOCK` is held.
    #[test]
    fn closing_a_handle_runs_its_destroy_hook_outside_the_process_lock() {
        // `test_with_current_handles` serialises on the object test lock itself,
        // so the probe state, hooks and objects are all created inside the
        // closure: resetting the shared probe before taking the lock would let
        // the sibling probe test pollute the expected-id table.
        process::test_with_current_handles(object::HandleTable::new(), || {
            lock_probe::reset();
            object::reset_destroy_hooks();
            object::register_destroy_hook_with_object(ObjectKind::VmObject, lock_probe::record)
                .expect("register probe hook");

            let object =
                object::create_with_payload(ObjectKind::VmObject, 0).expect("create object");
            lock_probe::expect(object);
            // Put one handle into the current table and drop the creation
            // reference, so the guarded close below really destroys the object.
            let handle = {
                let mut guard = process::take_current_handles().expect("current handles");
                let handle = object::insert_handle(guard.table_mut(), object, Rights::MAP)
                    .expect("insert handle");
                let _ = object::release_object(object);
                handle
            };

            assert!(
                close_mapping_handle(handle),
                "the guarded close recognises the handle"
            );
            assert_eq!(lock_probe::hooks(), 1, "the destroy hook ran exactly once");
            assert!(
                !lock_probe::lock_was_held(),
                "the hook must run with the process lock released"
            );
            object::reset_destroy_hooks();
        });
    }

    /// The same property for the process-teardown path: the two lines of
    /// `release_last_process_resources` (take the guard, clear the table) must let
    /// every destroy hook run with `PROCESS_LOCK` released.
    #[test]
    fn clearing_the_handle_table_runs_destroy_hooks_outside_the_process_lock() {
        process::test_with_current_handles(object::HandleTable::new(), || {
            lock_probe::reset();
            object::reset_destroy_hooks();
            object::register_destroy_hook_with_object(ObjectKind::VmObject, lock_probe::record)
                .expect("register probe hook");

            {
                let mut guard = process::take_current_handles().expect("current handles");
                for _ in 0..2 {
                    let object = object::create_with_payload(ObjectKind::VmObject, 0)
                        .expect("create object");
                    lock_probe::expect(object);
                    object::insert_handle(guard.table_mut(), object, Rights::MAP)
                        .expect("insert handle");
                    let _ = object::release_object(object);
                }
            }

            // Exactly what `release_last_process_resources` does.
            if let Some(mut guard) = process::take_current_handles() {
                let _ = object::clear_handle_table(guard.table_mut());
            }

            assert_eq!(lock_probe::hooks(), 2, "one destroy hook per handle");
            assert!(
                !lock_probe::lock_was_held(),
                "hooks must run with the process lock released"
            );
            object::reset_destroy_hooks();
        });
    }

    /// M6c: `gfx` waits on its `Input` seat with an empty queue and must get
    /// `WOULD_BLOCK` (not `BAD_HANDLE`), so the seat has to be a legal wait item
    /// with key 0. SharedMemory and the syscall-only handles stay unwaitable.
    #[test]
    fn wait_items_accept_input_seats_without_a_key() {
        assert_eq!(wait_item_key(ObjectKind::Input, 0), Ok(0));
        assert_eq!(
            wait_item_key(ObjectKind::Input, 1),
            Err(ERR_BAD_REQUEST),
            "an Input seat is object-wide; keys are EventPair-only"
        );
        assert_eq!(wait_item_key(ObjectKind::Event, 0), Ok(0));
        assert_eq!(wait_item_key(ObjectKind::Timer, 1), Err(ERR_BAD_REQUEST));
        assert_eq!(wait_item_key(ObjectKind::EventPair, 1), Ok(1));
        assert_eq!(
            wait_item_key(ObjectKind::EventPair, 2),
            Err(ERR_BAD_REQUEST)
        );
        assert_eq!(wait_item_key(ObjectKind::Channel, 0), Ok(0));
        assert_eq!(wait_item_key(ObjectKind::Channel, 7), Err(ERR_BAD_REQUEST));
        assert_eq!(
            wait_item_key(ObjectKind::File, 0),
            Err(ERR_BAD_HANDLE),
            "files are not waitable"
        );
        assert_eq!(
            wait_item_key(ObjectKind::SharedMemory, 0),
            Err(ERR_BAD_HANDLE),
            "shared memory has no readiness"
        );
    }

    #[test]
    fn wait_plan_checks_the_fixed_part() {
        let mut request = WaitRequest::new(0x1000, 10);
        request.push(native_abi::WaitItem::new(0x0001_0001, 0));
        assert_eq!(
            wait_plan(&request),
            Ok(WaitPlan {
                out_ptr: 0x1000,
                timeout_ticks: 10,
                count: 1,
            })
        );

        let mut bad = request;
        bad.size = 88;
        assert_eq!(wait_plan(&bad), Err(ERR_BAD_REQUEST), "bad size");

        let mut bad = request;
        bad.version = REQUEST_VERSION + 1;
        assert_eq!(wait_plan(&bad), Err(ERR_BAD_REQUEST), "bad version");

        let mut bad = request;
        bad.reserved = 1;
        assert_eq!(wait_plan(&bad), Err(ERR_BAD_REQUEST), "reserved must be 0");

        let mut bad = request;
        bad.flags = 1;
        assert_eq!(wait_plan(&bad), Err(ERR_BAD_REQUEST), "flags must be 0");

        let mut bad = request;
        bad.count = 0;
        assert_eq!(
            wait_plan(&bad),
            Err(ERR_BAD_REQUEST),
            "a wait with no item and no deadline would block forever"
        );

        let mut bad = request;
        bad.count = WAIT_MAX_ITEMS as u32 + 1;
        assert_eq!(wait_plan(&bad), Err(ERR_BAD_REQUEST), "too many items");

        let mut bad = request;
        bad.items[0].flags = 1;
        assert_eq!(wait_plan(&bad), Err(ERR_BAD_REQUEST), "item flags");

        let mut bad = request;
        bad.out_ptr = 0;
        assert_eq!(
            wait_plan(&bad),
            Err(ERR_BAD_POINTER),
            "the result must have somewhere to go"
        );
    }

    #[test]
    fn ipc_status_maps_table_pressure_and_object_errors() {
        assert_eq!(ipc_status(IpcError::TableFull), ERR_QUOTA);
        assert_eq!(ipc_status(IpcError::InvalidPayload), ERR_BAD_HANDLE);
        assert_eq!(ipc_status(IpcError::WrongKind), ERR_BAD_HANDLE);
        assert_eq!(
            ipc_status(IpcError::Object(ObjectError::WrongObjectKind)),
            ERR_BAD_HANDLE
        );
        assert_eq!(ipc_status(IpcError::InvalidEndpoint), ERR_BAD_REQUEST);
        assert_eq!(ipc_status(IpcError::NotBound), ERR_BAD_REQUEST);
    }

    /// M4 regression: the child's second initial handle is an `EventPair`.
    ///
    /// `random_read` resolves the handle as `Random`; a live handle of the wrong
    /// kind must read as `BAD_HANDLE` — not `NO_ENTROPY` (a valid Random handle
    /// without entropy) and not `BAD_RIGHT` (a rights problem). The kind check
    /// runs before the rights check, so this is the mapping that decides it.
    #[test]
    fn random_read_rejects_a_wrong_kind_handle_with_bad_handle() {
        let mut objects = object::ObjectTable::new();
        let mut table = object::HandleTable::new();
        let object = objects.create(ObjectKind::EventPair).unwrap();
        let handle = table.insert(&mut objects, object, Rights::READ).unwrap();
        let error = object::resolve_as_handle(&table, handle, ObjectKind::Random, Rights::READ)
            .expect_err("an EventPair handle is not a Random handle");
        assert_eq!(object_status(error), ERR_BAD_HANDLE);
    }

    /// The five M6a1 numbers must reach their implementations rather than fall
    /// through to the unknown-number arm (which returns `NOT_SUPPORTED`).
    #[test]
    fn m6a1_calls_are_dispatched() {
        for nr in [
            native_abi::NR_IPC_CREATE,
            native_abi::NR_IPC_SIGNAL,
            native_abi::NR_WAIT,
            native_abi::NR_TIMER_ARM,
        ] {
            let mut frame = zero_frame(nr);
            assert_eq!(
                dispatch(&mut frame).status,
                ERR_BAD_HANDLE,
                "nr {nr} must reach its implementation"
            );
        }
    }

    /// `ipc_signal` and `timer_arm` take plain registers, so the operation and
    /// flag words are validated before any handle is touched.
    #[test]
    fn ipc_signal_and_timer_arm_reject_bad_register_words() {
        // An unknown signal operation is a malformed request.
        assert_eq!(ipc_signal(HANDLE_NONE as u64, 7, 0).status, ERR_BAD_REQUEST);
        // An endpoint outside the two EventPair endpoints is malformed.
        assert_eq!(
            ipc_signal(HANDLE_NONE as u64, SIGNAL_OP_SIGNAL as u64, 2).status,
            ERR_BAD_REQUEST
        );
        // Timer flags are reserved and must be zero.
        assert_eq!(timer_arm(HANDLE_NONE as u64, 10, 1).status, ERR_BAD_REQUEST);
    }

    /// An `EventPair` signal wakes the *peer* endpoint's waiter, not its own.
    #[test]
    fn event_pair_signal_wakes_the_peer_endpoint() {
        // Endpoint A is 0; it is only referenced from tests, so it is spelled out
        // through the ABI crate rather than imported at module scope (where the
        // non-test build would see an unused import).
        let endpoint_a = native_abi::EVENT_PAIR_ENDPOINT_A;
        assert_eq!(endpoint_a, 0);
        assert_eq!(
            signal_wake_key(ObjectKind::EventPair, endpoint_a as u8),
            Some(u32::from(EVENT_PAIR_ENDPOINT_B))
        );
        assert_eq!(
            signal_wake_key(ObjectKind::EventPair, EVENT_PAIR_ENDPOINT_B as u8),
            Some(endpoint_a)
        );
        // One state per object: no key, so the unkeyed wake is used.
        assert_eq!(signal_wake_key(ObjectKind::Event, 0), None);
        assert_eq!(signal_wake_key(ObjectKind::Timer, 0), None);
    }

    /// A first wait derives `now + ticks`; a replay must reuse the recorded one.
    #[test]
    fn first_wait_deadline_is_derived_once() {
        assert_eq!(first_wait_deadline(WAIT_TIMEOUT_INFINITE, 1_000), None);
        assert_eq!(first_wait_deadline(5, 1_000), Some(1_005));
        // A huge finite timeout saturates instead of wrapping into an immediate
        // deadline. `u32::MAX` itself is the "wait for ever" sentinel, so the
        // largest finite value is one below it.
        assert_eq!(
            first_wait_deadline(WAIT_TIMEOUT_INFINITE - 1, u64::MAX - 2),
            Some(u64::MAX)
        );
    }

    /// A plain poll must not treat writability as readiness; a write wake must.
    #[test]
    fn socket_wait_readiness_accepts_write_only_after_a_ready_wake() {
        // First entry (no wake recorded): only readable/error states are ready.
        assert!(socket_wait_ready(net::PollMask::READ, WakeReason::None));
        assert!(socket_wait_ready(net::PollMask::ERROR, WakeReason::None));
        assert!(!socket_wait_ready(net::PollMask::WRITE, WakeReason::None));
        assert!(!socket_wait_ready(net::PollMask::EMPTY, WakeReason::None));

        // The engine wakes a blocked sender once its peer accepts the
        // connection (or the window opens); that replay may report write
        // readiness, which is what makes the caller retry the send.
        assert!(socket_wait_ready(net::PollMask::WRITE, WakeReason::Ready));
        assert!(socket_wait_ready(
            net::PollMask::READ.union(net::PollMask::WRITE),
            WakeReason::Ready
        ));
        assert!(!socket_wait_ready(net::PollMask::EMPTY, WakeReason::Ready));

        // Another wake reason never promotes writability.
        assert!(!socket_wait_ready(
            net::PollMask::WRITE,
            WakeReason::Timeout
        ));
        assert!(!socket_wait_ready(
            net::PollMask::WRITE,
            WakeReason::PeerClosed
        ));
        assert!(socket_wait_ready(net::PollMask::ERROR, WakeReason::Timeout));
    }

    #[test]
    fn futex_arguments_are_validated() {
        // The word is a user `u32`: a wider `expected` is a malformed request,
        // not a value that can never match.
        assert_eq!(futex_expected(0), Some(0));
        assert_eq!(futex_expected(u64::from(u32::MAX)), Some(u32::MAX));
        assert_eq!(futex_expected(u64::from(u32::MAX) + 1), None);
        // Timeouts share the frozen `WAIT_TIMEOUT_*` encoding.
        assert_eq!(
            futex_timeout_ticks(u64::from(WAIT_TIMEOUT_IMMEDIATE)),
            Some(WAIT_TIMEOUT_IMMEDIATE)
        );
        assert_eq!(
            futex_timeout_ticks(u64::from(WAIT_TIMEOUT_INFINITE)),
            Some(WAIT_TIMEOUT_INFINITE)
        );
        assert_eq!(futex_timeout_ticks(u64::from(u32::MAX) + 1), None);
    }

    #[test]
    fn futex_calls_fail_loudly_without_a_current_process() {
        // Host tests have no running process, so the address-space lookup is the
        // first check that fails: a futex call must never look like it blocked.
        for nr in [native_abi::NR_FUTEX_WAIT, native_abi::NR_FUTEX_WAKE] {
            let mut frame = zero_frame(nr);
            frame.args[0] = 0x1000;
            assert_eq!(dispatch(&mut frame).status, ERR_BAD_HANDLE, "nr {nr}");
        }
    }

    #[test]
    fn unsubscribe_reports_the_single_removed_interest() {
        let _guard = object::test_lock();
        object::reset_destroy_hooks();
        ipc::subscription::reset();

        let subscription =
            object::create_with_payload(ObjectKind::EventSubscription, 0).expect("subscription");
        ipc::subscription::create(subscription).expect("subscription table entry");
        let event = object::create_with_payload(ObjectKind::Event, 0).expect("event");
        ipc::subscription::register(subscription, event, ipc::subscription::MODE_LEVEL, 0)
            .expect("register interest");
        assert_eq!(ipc::subscription::interest_count(subscription), Ok(1));

        let removed = unsubscribe_status(ipc::subscription::unsubscribe(subscription, event));
        assert_eq!(removed.status, STATUS_OK);
        assert_eq!(removed.result, 1);
        assert_eq!(ipc::subscription::interest_count(subscription), Ok(0));

        // The interest is really gone: removing it again is NOT_FOUND, not a
        // second successful removal and not a zero count.
        let again = unsubscribe_status(ipc::subscription::unsubscribe(subscription, event));
        assert_eq!(again.status, ERR_NOT_FOUND);
        assert_eq!(again.result, 0);

        ipc::subscription::destroy(subscription).expect("destroy subscription");
        ipc::subscription::release_pending();
        let _ = object::release_object(event);
        let _ = object::release_object(subscription);
    }

    #[test]
    fn subscription_calls_fail_loudly_without_a_current_process() {
        for nr in [
            native_abi::NR_SUBSCRIBE,
            native_abi::NR_UNSUBSCRIBE,
            native_abi::NR_SUBSCRIPTION_READ,
        ] {
            let mut frame = zero_frame(nr);
            frame.args[0] = 0x0001_0001;
            assert_eq!(dispatch(&mut frame).status, ERR_BAD_HANDLE, "nr {nr}");
        }
    }

    #[test]
    fn subscription_entries_are_decoded_from_the_wire_layout() {
        let mut raw = [0u8; 16];
        raw[0..4].copy_from_slice(&0x0001_0001u32.to_le_bytes());
        raw[4..8].copy_from_slice(&SUBSCRIPTION_MODE_EDGE.to_le_bytes());
        raw[8..16].copy_from_slice(&1u64.to_le_bytes());
        assert_eq!(
            decode_subscription_entry(&raw),
            (0x0001_0001, SUBSCRIPTION_MODE_EDGE, 1)
        );

        // Malformed mode and an oversized key are rejected before any lookup.
        assert_eq!(
            subscription_interest(0x0001_0001, 3, 0),
            Err(ERR_BAD_REQUEST)
        );
        assert_eq!(
            subscription_interest(
                0x0001_0001,
                SUBSCRIPTION_MODE_LEVEL,
                u64::from(u32::MAX) + 1
            ),
            Err(ERR_BAD_REQUEST)
        );
    }

    mod socket_probe {
        use super::*;
        use core::sync::atomic::{AtomicUsize, Ordering};

        static SOCKETS: AtomicUsize = AtomicUsize::new(0);
        static NAMESPACES: AtomicUsize = AtomicUsize::new(0);

        pub(super) fn reset() {
            SOCKETS.store(0, Ordering::SeqCst);
            NAMESPACES.store(0, Ordering::SeqCst);
        }

        pub(super) fn sockets() -> usize {
            SOCKETS.load(Ordering::SeqCst)
        }

        pub(super) fn namespaces() -> usize {
            NAMESPACES.load(Ordering::SeqCst)
        }

        pub(super) fn record_socket(_payload: u64) {
            SOCKETS.fetch_add(1, Ordering::SeqCst);
        }

        pub(super) fn record_namespace(
            _kind: ObjectKind,
            _payload: u64,
            _object: object::ObjectId,
        ) {
            NAMESPACES.fetch_add(1, Ordering::SeqCst);
        }
    }

    /// Mirrors `publish_socket`: `create_with_payload` starts at one reference, the
    /// handle takes a second, dropping the creation reference leaves the object
    /// alive, and closing the handle destroys it exactly once.
    #[test]
    fn socket_publish_keeps_the_object_alive_until_the_handle_closes() {
        let _guard = object::test_lock();
        object::reset_destroy_hooks();
        socket_probe::reset();
        object::register_destroy_hook(ObjectKind::Socket, socket_probe::record_socket).unwrap();

        let object = object::create_with_payload(ObjectKind::Socket, 0x0000_0001).unwrap();
        assert_eq!(object::object_refs(object), Some(1));
        let mut table = object::HandleTable::new();
        let handle = object::insert_handle(&mut table, object, SOCKET_HANDLE_RIGHTS).unwrap();
        assert_eq!(object::object_refs(object), Some(2));
        assert_eq!(object::release_object(object), Ok(1));
        assert!(
            object::object_kind(object).is_some(),
            "dropping the creation reference must not destroy the object"
        );
        assert!(object::close_handle(&mut table, handle).is_ok());
        assert!(object::object_kind(object).is_none());
        assert_eq!(
            socket_probe::sockets(),
            1,
            "the socket hook runs exactly once"
        );

        object::reset_destroy_hooks();
    }

    /// The namespace reference recorded for a socket is released exactly once, and
    /// the namespace object only dies after that last reference is dropped.
    #[test]
    fn socket_namespace_reference_is_recorded_and_released_once() {
        let _guard = object::test_lock();
        object::reset_destroy_hooks();
        socket_probe::reset();
        object::register_destroy_hook_with_object(
            ObjectKind::NetNamespace,
            socket_probe::record_namespace,
        )
        .unwrap();

        let namespace = object::create_object(ObjectKind::NetNamespace).unwrap();
        let id = net::SocketId::new(3, 7);
        record_socket_namespace(id, namespace).unwrap();
        assert_eq!(object::object_refs(namespace), Some(1));
        assert_eq!(socket_namespace_of(id), Some(namespace));
        assert_eq!(forget_socket_namespace(id), Some(namespace));
        assert_eq!(forget_socket_namespace(id), None);
        assert_eq!(object::release_object(namespace), Ok(0));
        assert!(object::object_kind(namespace).is_none());
        assert_eq!(socket_probe::namespaces(), 1);

        object::reset_destroy_hooks();
    }

    /// Loopback address wire for the address-parsing tests.
    fn loopback_wire(family: u32, port: u32) -> SocketAddrWire {
        let mut wire = SocketAddrWire::empty();
        wire.family = family;
        wire.port = port;
        if family == SOCKET_FAMILY_INET {
            wire.addr[..4].copy_from_slice(&[127, 0, 0, 1]);
        } else {
            wire.addr[15] = 1;
        }
        wire
    }

    /// `bind` may hand the engine port 0 so it can allocate a temporary local
    /// port; every other address rule (loopback, no path on IP, clean flags)
    /// still applies.
    #[test]
    fn bind_accepts_an_ephemeral_loopback_port() {
        for family in [SOCKET_FAMILY_INET, SOCKET_FAMILY_INET6] {
            let parsed = socket_address_from_wire(&loopback_wire(family, 0), true)
                .expect("bind may request a temporary port");
            assert_eq!(parsed.family, family);
            assert_eq!(parsed.port, 0);
            assert_eq!(parsed.path_len, 0);
        }
        // A concrete port keeps parsing exactly as before.
        let parsed = socket_address_from_wire(&loopback_wire(SOCKET_FAMILY_INET, 7), true).unwrap();
        assert_eq!(parsed.port, 7);
    }

    /// `connect` must never reinterpret a zero remote port as a temporary port.
    #[test]
    fn connect_rejects_an_ephemeral_remote_port() {
        for family in [SOCKET_FAMILY_INET, SOCKET_FAMILY_INET6] {
            assert_eq!(
                socket_address_from_wire(&loopback_wire(family, 0), false),
                Err(ERR_BAD_REQUEST)
            );
            // The same address with a concrete remote port is still accepted.
            assert!(socket_address_from_wire(&loopback_wire(family, 7), false).is_ok());
        }
    }

    /// The ephemeral-port relaxation changes nothing else: UNIX semantics and
    /// the loopback-only / path-length / flags rules stay as they were.
    #[test]
    fn ephemeral_port_relaxation_keeps_the_other_address_rules() {
        let mut unix = SocketAddrWire::empty();
        unix.family = SOCKET_FAMILY_UNIX;
        unix.path_len = 4;
        unix.path[..4].copy_from_slice(b"/tmp");
        assert!(
            socket_address_from_wire(&unix, false).is_ok(),
            "a UNIX address has port 0 by definition and must stay valid"
        );
        assert!(socket_address_from_wire(&unix, true).is_ok());

        let mut routed = loopback_wire(SOCKET_FAMILY_INET, 0);
        routed.addr[..4].copy_from_slice(&[10, 0, 0, 1]);
        assert_eq!(
            socket_address_from_wire(&routed, true),
            Err(ERR_NOT_SUPPORTED),
            "a non-loopback address is still refused"
        );

        let mut with_path = loopback_wire(SOCKET_FAMILY_INET, 0);
        with_path.path_len = 1;
        assert_eq!(
            socket_address_from_wire(&with_path, true),
            Err(ERR_BAD_REQUEST),
            "an IP address must not carry a path"
        );

        let mut bad_flags = loopback_wire(SOCKET_FAMILY_INET, 0);
        bad_flags.flags = 1;
        assert_eq!(
            socket_address_from_wire(&bad_flags, true),
            Err(ERR_BAD_REQUEST)
        );
    }

    /// A stream send longer than the bounce buffer copies one chunk instead of
    /// failing: the engine reports how much it accepted and the user loops.
    #[test]
    fn a_stream_send_is_chunked_to_the_bounce_buffer() {
        assert_eq!(socket_send_copy_len(0), 0);
        assert_eq!(socket_send_copy_len(7), 7);
        assert_eq!(socket_send_copy_len(SOCKET_IO_MAX), SOCKET_IO_MAX);
        assert_eq!(socket_send_copy_len(SOCKET_IO_MAX + 1), SOCKET_IO_MAX);
        assert_eq!(socket_send_copy_len(64 * 1024), SOCKET_IO_MAX);
    }

    /// `AddressInUse` splits by family: a UNIX path conflict is `EXISTS`, an INET
    /// port conflict is `BUSY`, and unrelated errors keep their normal mapping.
    #[test]
    fn address_in_use_is_split_between_unix_paths_and_inet_ports() {
        assert_eq!(
            bind_connect_status(net::NetError::AddressInUse, SOCKET_DOMAIN_UNIX),
            ERR_EXISTS
        );
        assert_eq!(
            bind_connect_status(net::NetError::AddressInUse, SOCKET_DOMAIN_INET),
            ERR_BUSY
        );
        assert_eq!(
            bind_connect_status(net::NetError::AddressInUse, SOCKET_DOMAIN_INET6),
            ERR_BUSY
        );
        // Everything else still goes through the shared error mapping.
        assert_eq!(
            bind_connect_status(net::NetError::NotFound, SOCKET_DOMAIN_UNIX),
            ERR_NOT_FOUND
        );
        assert_eq!(
            bind_connect_status(net::NetError::WouldBlock, SOCKET_DOMAIN_INET),
            ERR_WOULD_BLOCK
        );
    }

    #[test]
    fn linux_results_are_reported_in_rax() {
        // A successful Linux call puts its non-negative result in `rax`...
        let success = linux_status(37);
        assert_eq!(success.status, 37);
        assert_eq!(success.result, 0);
        // ...and a failure puts the two's-complement `-errno` there instead.
        let failure = linux_status(-crate::compat::linux::errno::EINVAL);
        assert_eq!(
            failure.status,
            (-crate::compat::linux::errno::EINVAL) as u64
        );
        assert_eq!(failure.result, 0);
    }
}
