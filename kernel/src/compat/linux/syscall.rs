//! Linux64 system call dispatch.
//!
//! # Calling convention
//!
//! The Linux x86-64 ABI keeps the native register assignment (`rax` = system
//! call number, `rdi`/`rsi`/`rdx`/`r10`/`r8`/`r9` = arguments), but the return
//! value is a single `rax`: either a non-negative result or `-errno`. This
//! module therefore never builds a native `status`/`result` pair.
//!
//! # Blocking
//!
//! A system call that cannot complete without sleeping does not block inside
//! the dispatch: it returns [`Outcome::Wait`] naming the object whose readiness
//! ends the wait. This holds for `accept`, `recvfrom`/`read` **and** for the
//! send direction (`write`/`sendto`): this stage has no `O_NONBLOCK` model, so
//! a send that cannot make progress blocks just like Linux does instead of
//! reporting `EAGAIN`. The entry layer performs `process::block_current_keyed`
//! with the same object and then **replays the same system call**, so the
//! Linux caller observes a normal blocking call whose final `rax` still carries
//! the Linux value. [`block_until_ready`] is that entry hook.
//!
//! Implemented: `read`, `write`, `close`, `openat`, `dup`, `dup2`, `mmap`,
//! `mprotect`, `munmap`, `brk`, `socket`, `connect`, `accept`, `accept4`,
//! `sendto`, `recvfrom`, `bind`, `listen`, `getsockname`, `getpeername`,
//! `socketpair`, `setsockopt`, `getsockopt`, `shutdown`, `getpid`, `getuid`,
//! `getgid`, `geteuid`, `getegid`, `exit`, `exit_group`.
//! Everything else reports `-ENOSYS` and is counted (a Linux program must not
//! see a fabricated success).
//!
//! # File descriptors
//!
//! Socket descriptors point at `ObjectKind::Socket` objects whose payload is the
//! engine socket id; file descriptors point at `ObjectKind::File` objects whose
//! payload is the VFS `OpenId` (the same convention the native syscall layer
//! uses). `read`/`write`/`close` dispatch on that object kind, so the VFS owns
//! the file offset: `dup` copies the object reference and therefore shares the
//! offset, while a new `openat` obtains a fresh `OpenId` with its own offset.
//! Closing the last reference runs the registered `File` destroy hook, which is
//! what actually calls [`vfs::close`].

use core::sync::atomic::{AtomicU64, Ordering};

use netcore::{Ipv4Addr, Ipv6Addr};

use crate::arch::TrapFrame;
use crate::ipc::{epoll, eventfd, signalfd, timerfd};
use crate::mm::addrspace::{self, AddressSpaceId};
use crate::net::{self, NetError, SocketId};
use crate::object::{self, ObjectId, ObjectKind};
use crate::process;
use crate::vfs::{self, OpenId, OpenOptions, VfsError};

use super::address;
use super::errno;
use super::fd::{FdEntry, FdError, FdTable};
use super::lock as file_lock;
use super::memory::{self, KernelSpace};
use super::msg;
use super::signal;

// ---------------------------------------------------------------------------
// System call numbers
// ---------------------------------------------------------------------------

/// `read`.
pub const NR_READ: u64 = 0;
/// `write`.
pub const NR_WRITE: u64 = 1;
/// `close`.
pub const NR_CLOSE: u64 = 3;
/// `poll`.
pub const NR_POLL: u64 = 7;
/// `ppoll`.
pub const NR_PPOLL: u64 = 271;
/// `eventfd` (legacy entry: only the initial value is passed).
pub const NR_EVENTFD: u64 = 284;
/// `eventfd2`.
pub const NR_EVENTFD2: u64 = 290;
/// `fstat`.
pub const NR_FSTAT: u64 = 5;
/// `lseek`.
pub const NR_LSEEK: u64 = 8;
/// `mmap`.
pub const NR_MMAP: u64 = 9;
/// `mprotect`.
pub const NR_MPROTECT: u64 = 10;
/// `munmap`.
pub const NR_MUNMAP: u64 = 11;
/// `brk`.
pub const NR_BRK: u64 = 12;
/// `dup`.
pub const NR_DUP: u64 = 32;
/// `dup2`.
pub const NR_DUP2: u64 = 33;
/// `getpid`.
pub const NR_GETPID: u64 = 39;
/// `socket`.
pub const NR_SOCKET: u64 = 41;
/// `connect`.
pub const NR_CONNECT: u64 = 42;
/// `accept`.
pub const NR_ACCEPT: u64 = 43;
/// `sendto`.
pub const NR_SENDTO: u64 = 44;
/// `recvfrom`.
pub const NR_RECVFROM: u64 = 45;
/// `sendmsg`.
pub const NR_SENDMSG: u64 = 46;
/// `recvmsg`.
pub const NR_RECVMSG: u64 = 47;
/// `bind`.
pub const NR_BIND: u64 = 49;
/// `listen`.
pub const NR_LISTEN: u64 = 50;
/// `getsockname`.
pub const NR_GETSOCKNAME: u64 = 51;
/// `getpeername`.
pub const NR_GETPEERNAME: u64 = 52;
/// `socketpair`.
pub const NR_SOCKETPAIR: u64 = 53;
/// `setsockopt`.
pub const NR_SETSOCKOPT: u64 = 54;
/// `getsockopt`.
pub const NR_GETSOCKOPT: u64 = 55;
/// `shutdown`.
///
/// The x86-64 Linux number is 48; 56 is `clone`, which this stage does not
/// implement and which therefore stays `ENOSYS`.
pub const NR_SHUTDOWN: u64 = 48;
/// `exit`.
pub const NR_EXIT: u64 = 60;
/// `fcntl`.
pub const NR_FCNTL: u64 = 72;
/// `flock`.
pub const NR_FLOCK: u64 = 73;
/// `getdents64`.
pub const NR_GETDENTS64: u64 = 217;
/// `getuid`.
pub const NR_GETUID: u64 = 102;
/// `geteuid`.
pub const NR_GETEUID: u64 = 104;
/// `getgid`.
pub const NR_GETGID: u64 = 107;
/// `getegid`.
pub const NR_GETEGID: u64 = 108;
/// `exit_group`.
pub const NR_EXIT_GROUP: u64 = 231;
/// `accept4`.
pub const NR_ACCEPT4: u64 = 288;
/// `statx`.
pub const NR_STATX: u64 = 332;
/// `openat`.
pub const NR_OPENAT: u64 = 257;
/// `uname`.
pub const NR_UNAME: u64 = 63;
/// `sysinfo`.
pub const NR_SYSINFO: u64 = 99;
/// `getppid`.
pub const NR_GETPPID: u64 = 110;
/// `clock_gettime`.
pub const NR_CLOCK_GETTIME: u64 = 228;
/// `clock_nanosleep`.
pub const NR_CLOCK_NANOSLEEP: u64 = 230;
/// `rt_sigaction`.
pub const NR_RT_SIGACTION: u64 = 13;
/// `rt_sigprocmask`.
pub const NR_RT_SIGPROCMASK: u64 = 14;
/// `rt_sigreturn`.
pub const NR_RT_SIGRETURN: u64 = 15;
/// `kill`.
pub const NR_KILL: u64 = 62;
/// `tgkill`.
pub const NR_TGKILL: u64 = 234;
/// `wait4`.
pub const NR_WAIT4: u64 = 61;
/// `WNOHANG`: return immediately when no child has exited.
pub const WNOHANG: u64 = 1;
/// Every `wait4` option this stage understands; everything else is `EINVAL`.
const WAIT_OPTION_MASK: u64 = WNOHANG;

/// `arch_prctl` (x86-64).
pub const NR_ARCH_PRCTL: u64 = 158;
/// `futex`.
pub const NR_FUTEX: u64 = 202;
/// `set_tid_address`.
pub const NR_SET_TID_ADDRESS: u64 = 218;

// M9a: timerfd / signalfd / epoll numbers (x86-64).

/// `epoll_create`.
pub const NR_EPOLL_CREATE: u64 = 213;
/// `epoll_ctl`.
pub const NR_EPOLL_CTL: u64 = 233;
/// `epoll_wait`.
pub const NR_EPOLL_WAIT: u64 = 232;
/// `epoll_pwait`.
pub const NR_EPOLL_PWAIT: u64 = 281;
/// `epoll_create1`.
pub const NR_EPOLL_CREATE1: u64 = 291;
/// `timerfd_create`.
pub const NR_TIMERFD_CREATE: u64 = 283;
/// `timerfd_settime`.
pub const NR_TIMERFD_SETTIME: u64 = 286;
/// `timerfd_gettime`.
pub const NR_TIMERFD_GETTIME: u64 = 287;
/// `signalfd`.
pub const NR_SIGNALFD: u64 = 282;
/// `signalfd4`.
pub const NR_SIGNALFD4: u64 = 289;

// Stop-family signals that this slice refuses: a personality cannot stop a
// process without a job-control model, so reporting `ENOSYS` is honest.
const SIGSTOP: u32 = 19;
const SIGTSTP: u32 = 20;
const SIGTTIN: u32 = 21;
const SIGTTOU: u32 = 22;

// Linux file flags used by the M8a file slice.

/// `AT_FDCWD`: the only directory descriptor this stage accepts.
pub const AT_FDCWD: i64 = -100;
/// Access-mode bits of `O_*`.
const O_ACCMODE: u64 = 0o3;
/// `O_RDONLY`.
pub const O_RDONLY: u64 = 0o0;
/// `O_WRONLY`.
pub const O_WRONLY: u64 = 0o1;
/// `O_RDWR`.
pub const O_RDWR: u64 = 0o2;
/// `O_CREAT`.
pub const O_CREAT: u64 = 0o100;
/// `O_EXCL`.
pub const O_EXCL: u64 = 0o200;
/// `O_TRUNC`.
pub const O_TRUNC: u64 = 0o1000;
/// `O_CLOEXEC`.
pub const O_CLOEXEC: u64 = 0o2_000_000;
/// `O_DIRECTORY`: only open if the target is a directory (M8e `getdents64`).
pub const O_DIRECTORY: u64 = 0o200_000;
/// Every `O_*` bit this stage understands.
const FILE_FLAG_MASK: u64 = O_ACCMODE | O_CREAT | O_EXCL | O_TRUNC | O_CLOEXEC | O_DIRECTORY;

/// Largest pathname accepted by [`NR_OPENAT`], matching the VFS limit.
pub const FILE_PATH_MAX: usize = crate::vfs::MAX_PATH;

// Linux clocks and the fixed ABI layouts used by the M8b time/system slice.

/// `CLOCK_REALTIME`: there is no trusted RTC baseline yet, so it stays
/// `ENOSYS` rather than fabricating wall-clock time.
pub const CLOCK_REALTIME: u32 = 0;
/// `CLOCK_MONOTONIC`.
pub const CLOCK_MONOTONIC: u32 = 1;
/// `CLOCK_BOOTTIME`.
pub const CLOCK_BOOTTIME: u32 = 7;
/// `TIMER_ABSTIME`: the request is an absolute deadline on its clock.
pub const TIMER_ABSTIME: u32 = 1;
/// `sizeof(struct timespec)` on Linux64: `tv_sec` then `tv_nsec`, both `i64`.
pub const TIMESPEC_SIZE: usize = 16;
/// One `utsname` field (`char[65]`).
pub const UTSNAME_FIELD: usize = 65;
/// Number of `utsname` fields.
pub const UTSNAME_FIELDS: usize = 6;
/// `sizeof(struct utsname)` on Linux64.
pub const UTSNAME_SIZE: usize = UTSNAME_FIELD * UTSNAME_FIELDS;
/// `sizeof(struct sysinfo)` on Linux64.
pub const SYSINFO_SIZE: usize = 112;
/// Nanoseconds in a second.
const NANOS_PER_SECOND: u128 = 1_000_000_000;

/// Sentinels for [`Outcome::Wait`].
///
/// A real object id is never [`ObjectId::MAX`], so the entry layer can use it
/// to distinguish a pure deadline sleep from an object wait. The deadline that
/// accompanies it is kept in [`SLEEP_DEADLINES`] because the entry glue only
/// forwards the object id to [`block_until_ready`].
pub const SLEEP_OBJECT: ObjectId = ObjectId::MAX;

/// Deadline of a pure-deadline sleep, one slot per CPU: the slot is written by
/// the dispatch and read by [`block_until_ready`] on the same CPU, so a second
/// CPU sleeping at the same time cannot overwrite it in between.
static SLEEP_DEADLINES: [AtomicU64; crate::arch::MAX_CPUS] =
    [const { AtomicU64::new(u64::MAX) }; crate::arch::MAX_CPUS];

/// Per-CPU slot for [`SLEEP_DEADLINES`]; the host build reports CPU 0.
fn sleep_slot() -> usize {
    crate::arch::cpu_index().min(crate::arch::MAX_CPUS - 1)
}

// Linux socket type flags and option names used by the personality.

/// `SOCK_STREAM`.
pub const SOCK_STREAM: u32 = 1;
/// `SOCK_DGRAM`.
pub const SOCK_DGRAM: u32 = 2;
/// `SOCK_NONBLOCK`.
pub const SOCK_NONBLOCK: u32 = 0o4000;
/// `SOCK_CLOEXEC`.
pub const SOCK_CLOEXEC: u32 = 0o2_000_000;
/// `SOL_SOCKET`.
pub const SOL_SOCKET: u64 = 1;
/// `SO_REUSEADDR`.
pub const SO_REUSEADDR: u64 = 2;
/// `SO_ERROR`.
pub const SO_ERROR: u64 = 4;

/// Largest payload copied through the per-call bounce buffer.
pub const MAX_IO: usize = 1024;

/// Count of calls that returned `-ENOSYS` (diagnostics, never a success).
static ENOSYS_COUNT: AtomicU64 = AtomicU64::new(0);

/// Number of unimplemented Linux system calls seen so far.
pub fn enosys_count() -> u64 {
    ENOSYS_COUNT.load(Ordering::Relaxed)
}

/// Execution context handed to the dispatch by the (future) entry layer.
pub struct LinuxContext<'a> {
    /// The process' Linux descriptor table.
    pub fds: &'a mut FdTable,
    /// Network namespace object of the process (`0` = none).
    pub netns: ObjectId,
    /// Address space used for `copy_in`/`copy_out`; `None` in host tests.
    pub address_space: Option<AddressSpaceId>,
    /// The interrupted ring-3 frame of the current syscall.
    ///
    /// The entry passes its frame pointer so signal delivery (`rt_sigreturn`
    /// validation and the handler-entry rewrite) can act on the frame that the
    /// architecture stub will return through. Host tests leave it `None`.
    pub trap_frame: Option<*mut TrapFrame>,
}

impl<'a> LinuxContext<'a> {
    /// Build a context for tests and for the entry shim.
    pub fn new(fds: &'a mut FdTable, netns: ObjectId, space: Option<AddressSpaceId>) -> Self {
        Self {
            fds,
            netns,
            address_space: space,
            trap_frame: None,
        }
    }

    /// Attach the syscall's ring-3 frame (used by signal delivery).
    pub fn with_trap_frame(mut self, trap_frame: *mut TrapFrame) -> Self {
        self.trap_frame = Some(trap_frame);
        self
    }

    fn space(&self) -> Result<AddressSpaceId, i64> {
        self.address_space.ok_or(errno::EFAULT)
    }
}

/// Result of one Linux system call.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// The call completed; `0` carries the Linux `rax` value (negative errno on
    /// failure).
    Done(i64),
    /// The call must sleep until `object` becomes ready, then be replayed.
    Wait {
        /// Waitable object, or [`SLEEP_OBJECT`] for a pure deadline sleep.
        object: ObjectId,
        /// Absolute deadline in monotonic ticks, `None` = no timeout.
        deadline: Option<u64>,
    },
    /// `futex(FUTEX_WAIT)`: sleep on a user futex word and replay the call.
    FutexWait {
        /// Physical address of the futex word (page translation done by the
        /// compat layer, so the kernel wake path needs no user mapping).
        word: u64,
        /// Absolute deadline in monotonic ticks, `None` = wait forever.
        deadline: Option<u64>,
    },
    /// `poll`/`ppoll`: sleep on up to [`MAX_POLL_WAIT`] distinct objects, then
    /// replay the call so the returned `revents` reflect the *current* state.
    ///
    /// Waits use the kernel's direct multi-object wait: no `EventSubscription`
    /// object is created, because a subscription has a persistent table slot
    /// (capacity 2) and a transient poll would leak or contend on it.
    PollWait {
        /// Objects whose readiness ends the wait.
        objects: [ObjectId; MAX_POLL_WAIT],
        /// Wake keys (all `WAIT_ANY_KEY`: poll has no per-object key).
        keys: [u32; MAX_POLL_WAIT],
        /// Used entries in `objects`/`keys`.
        count: usize,
        /// Absolute deadline in monotonic ticks, `None` = no timeout.
        deadline: Option<u64>,
    },
    /// `rt_sigreturn`: restore the interrupted frame and return these values in
    /// `rax`/`rdx`.
    ///
    /// The architecture entry stub overwrites `rax`/`rdx` from the native
    /// status/result pair *after* dispatch, so the restored user values have to
    /// travel back through those two registers; every other register is already
    /// written into the trap frame by the restore.
    Restore {
        /// Restored `rax`.
        rax: i64,
        /// Restored `rdx`.
        rdx: u64,
    },
}

/// Whether the call consumes its own wake reason.
///
/// The entry layer uses this to decide which calls keep the recorded wake
/// reason: `clock_nanosleep` treats `Timeout` as its success signal, every
/// other call must start from a clean slate.
pub fn owns_wake_reason(nr: u64) -> bool {
    // `clock_nanosleep` turns `Timeout` into success; `futex` distinguishes
    // `Ready` (woken), `Timeout` (ETIMEDOUT) and `Cancelled` (EINTR) itself;
    // `poll`/`ppoll` turn `Timeout` into a zero-ready return and `Cancelled`
    // into `EINTR`, and must keep the original deadline across a replay.
    nr == NR_CLOCK_NANOSLEEP
        || nr == NR_FUTEX
        || nr == NR_POLL
        || nr == NR_PPOLL
        || nr == NR_EPOLL_WAIT
        || nr == NR_EPOLL_PWAIT
}

/// Dispatch one Linux64 system call.
///
/// The entry layer drains a stale wake reason before calling this (except for
/// [`owns_wake_reason`] calls); keeping that out of `dispatch` means a unit
/// test can exercise the personality without touching the process table.
pub fn dispatch(nr: u64, args: &[u64; 6], context: &mut LinuxContext<'_>) -> Outcome {
    match handle(nr, args, context) {
        Ok(outcome) => outcome,
        Err(error) => Outcome::Done(-error),
    }
}

/// Sleep until `object` is ready, then let the entry replay the system call.
///
/// This is the only place the personality touches the scheduler; the replay
/// itself happens in the entry layer, which keeps `rax` as a Linux value.
///
/// [`SLEEP_OBJECT`] is the pure-deadline form used by `clock_nanosleep`:
/// `process::block_current` with `count == 0` is documented as "only the
/// deadline can release the wait", which is exactly the semantics needed and
/// needs no entry-layer change. The deadline is read from the per-CPU slot the
/// dispatch filled on this same CPU.
pub fn block_until_ready(frame: *mut TrapFrame, object: ObjectId) -> ! {
    if object == SLEEP_OBJECT {
        let deadline = SLEEP_DEADLINES[sleep_slot()].load(Ordering::Relaxed);
        let deadline = if deadline == u64::MAX {
            None
        } else {
            Some(deadline)
        };
        let objects = [0; process::MAX_WAIT_OBJECTS];
        process::block_current(frame, objects, 0, deadline)
    } else {
        let objects = [object; process::MAX_WAIT_OBJECTS];
        let keys = [process::WAIT_ANY_KEY; process::MAX_WAIT_OBJECTS];
        process::block_current_keyed(frame, objects, keys, 1, None)
    }
}

// ---------------------------------------------------------------------------
// M8g: eventfd and poll/ppoll
// ---------------------------------------------------------------------------

/// `EFD_SEMAPHORE`: a read decrements by one and returns 1.
pub const EFD_SEMAPHORE: u32 = 0x0_0001;
/// `EFD_NONBLOCK`: reads/writes return `EAGAIN` instead of blocking.
pub const EFD_NONBLOCK: u32 = 0o0_0004_000;
/// `EFD_CLOEXEC`: close the descriptor on `exec`.
pub const EFD_CLOEXEC: u32 = 0o2_000_000;

/// Flags `eventfd2` recognises.
const EFD_FLAG_MASK: u32 = EFD_SEMAPHORE | EFD_NONBLOCK | EFD_CLOEXEC;

/// `POLLIN`.
pub const POLLIN: i16 = 0x0001;
/// `POLLPRI`.
pub const POLLPRI: i16 = 0x0002;
/// `POLLOUT`.
pub const POLLOUT: i16 = 0x0004;
/// `POLLERR`.
pub const POLLERR: i16 = 0x0008;
/// `POLLHUP`.
pub const POLLHUP: i16 = 0x0010;
/// `POLLNVAL`.
pub const POLLNVAL: i16 = 0x0020;
/// `POLLRDNORM`.
pub const POLLRDNORM: i16 = 0x0040;
/// `POLLRDBAND`.
pub const POLLRDBAND: i16 = 0x0080;
/// `POLLWRNORM`.
pub const POLLWRNORM: i16 = 0x0100;
/// `POLLWRBAND`.
pub const POLLWRBAND: i16 = 0x0200;

/// Requested bits that map to "readable".
const POLL_READABLE: i16 = POLLIN | POLLPRI | POLLRDNORM | POLLRDBAND;
/// Requested bits that map to "writable".
const POLL_WRITABLE: i16 = POLLOUT | POLLWRNORM | POLLWRBAND;

/// Largest `pollfd` array accepted in one call (agents.md: bounded, no dynamic
/// kernel allocation for user input).
pub const MAX_POLL_FDS: usize = 16;
/// Largest number of distinct objects one `poll` may block on. This is the
/// kernel's own multi-object wait budget (`process::block_current_keyed`).
pub const MAX_POLL_WAIT: usize = process::MAX_WAIT_OBJECTS;
/// Wire size of one `struct pollfd`.
pub const POLLFD_SIZE: usize = 8;

/// One `struct pollfd` decoded from the user array.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PollFd {
    /// File descriptor (`< 0` entries are ignored by `poll`).
    pub fd: i32,
    /// Requested events.
    pub events: i16,
    /// Returned events.
    pub revents: i16,
}

impl PollFd {
    /// Decode one 8-byte little-endian `pollfd`.
    pub fn decode(raw: &[u8]) -> Self {
        // The caller passes exactly `POLLFD_SIZE` bytes (checked by the poll
        // loop), so the fixed-index reads stay in bounds.
        let fd = i32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]);
        let events = i16::from_le_bytes([raw[4], raw[5]]);
        let revents = i16::from_le_bytes([raw[6], raw[7]]);
        Self {
            fd,
            events,
            revents,
        }
    }

    /// Encode this entry back into its wire image.
    pub fn encode(&self) -> [u8; POLLFD_SIZE] {
        let mut raw = [0u8; POLLFD_SIZE];
        raw[..4].copy_from_slice(&self.fd.to_le_bytes());
        raw[4..6].copy_from_slice(&self.events.to_le_bytes());
        raw[6..8].copy_from_slice(&self.revents.to_le_bytes());
        raw
    }
}

// ---------------------------------------------------------------------------
// Dispatch
// ---------------------------------------------------------------------------

/// M10a: `readlink(2)`. The minimal personality has no symbolic links to
/// resolve yet; the dynamic loader tolerates `ENOENT` when resolving `$ORIGIN`.
pub const NR_READLINK: u64 = 89;
/// M10a: `pread64(2)` (dynamic loader header/segment reads).
pub const NR_PREAD64: u64 = 17;
/// M10a: `ioctl(2)` (minimal: report `ENOTTY`; stdio probes with `TCGETS`).
pub const NR_IOCTL: u64 = 16;
/// M10a: `getrandom(2)`; the personality only serves the secure CRNG.
pub const NR_GETRANDOM: u64 = 318;

/// `ENOTTY`: the control operation is not supported by this descriptor.
const ENOTTY: i64 = 25;

/// M10a: `getrandom` — fill a user buffer from the secure CRNG.
///
/// No flags are supported (`0` only, like musl's start-up call). A CRNG that is
/// not ready must fail instead of returning fake bytes; the error is `EAGAIN`
/// (a blocking retry is a future slicing of the RNG policy).
fn getrandom(args: &[u64; 6], context: &mut LinuxContext<'_>) -> Result<Outcome, i64> {
    if args[2] != 0 {
        return Err(errno::EINVAL);
    }
    let length = args[1];
    if length == 0 {
        return Ok(Outcome::Done(0));
    }
    let mut done = 0u64;
    let mut chunk = [0u8; MAX_IO];
    while done < length {
        let take = (length - done).min(MAX_IO as u64) as usize;
        crate::rng::read_secure(&mut chunk[..take]).map_err(|_| errno::EAGAIN)?;
        copy_out(context, args[0] + done, &chunk[..take])?;
        done += take as u64;
    }
    Ok(Outcome::Done(done as i64))
}

/// M10a: `pread64` — read at an absolute offset without moving the shared
/// open-description offset (the dynamic loader depends on it).
fn pread64(args: &[u64; 6], context: &mut LinuxContext<'_>) -> Result<Outcome, i64> {
    let fd = linux_fd(args[0])?;
    let entry = entry(context, fd)?;
    if object::object_kind(entry.object) != Some(ObjectKind::File) {
        return Err(errno::EBADF);
    }
    let open = file_open_of(entry.object)?;
    let length = args[2];
    if length == 0 {
        return Ok(Outcome::Done(0));
    }
    let offset = args[3];
    let saved = crate::vfs::offset(open).map_err(vfs_errno)?;
    let mut done = 0u64;
    let mut chunk = [0u8; MAX_IO];
    while done < length {
        let take = (length - done).min(MAX_IO as u64) as usize;
        crate::vfs::seek(open, offset.saturating_add(done)).map_err(vfs_errno)?;
        match crate::vfs::read(open, &mut chunk[..take]) {
            Ok(0) => break,
            Ok(read) => {
                if let Err(error) = copy_out(context, args[1] + done, &chunk[..read]) {
                    let _ = crate::vfs::seek(open, saved);
                    return Err(error);
                }
                done += read as u64;
            }
            Err(error) => {
                let _ = crate::vfs::seek(open, saved);
                return Err(vfs_errno(error));
            }
        }
    }
    let _ = crate::vfs::seek(open, saved);
    Ok(Outcome::Done(done as i64))
}

/// M10a: `ioctl` — the minimal personality has no control operations; a valid
/// descriptor reports `ENOTTY` so stdio's terminal probes fall back cleanly.
fn ioctl(args: &[u64; 6], context: &mut LinuxContext<'_>) -> Result<Outcome, i64> {
    let fd = linux_fd(args[0])?;
    let _ = context.fds.get(fd).map_err(|_| errno::EBADF)?;
    Err(ENOTTY)
}

/// M10a: `readlink` — no symbolic links are exposed yet (`ENOENT`).
fn readlink(args: &[u64; 6], _context: &mut LinuxContext<'_>) -> Result<Outcome, i64> {
    let _ = (args[0], args[1], args[2]);
    Err(errno::ENOENT)
}

fn handle(nr: u64, args: &[u64; 6], context: &mut LinuxContext<'_>) -> Result<Outcome, i64> {
    match nr {
        NR_READ => read(args, context),
        NR_WRITE => write(args, context),
        NR_CLOSE => close(args, context),
        NR_FSTAT => fstat(args, context),
        NR_LSEEK => lseek(args, context),
        NR_FCNTL => fcntl(args, context),
        NR_FLOCK => flock(args, context),
        NR_GETDENTS64 => getdents64(args, context),
        NR_STATX => statx(args, context),
        NR_OPENAT => openat(args, context),
        NR_MMAP => memory_mmap(args, context),
        NR_MPROTECT => memory_mprotect(args, context),
        NR_MUNMAP => memory_munmap(args, context),
        NR_BRK => memory_brk(args, context),
        NR_DUP => dup(args, context),
        NR_DUP2 => dup2(args, context),
        NR_POLL => poll(args, context, false),
        NR_PPOLL => poll(args, context, true),
        NR_EVENTFD => eventfd_create(args, context, false),
        NR_EVENTFD2 => eventfd_create(args, context, true),
        NR_SOCKET => socket(args, context),
        NR_CONNECT => connect(args, context),
        NR_ACCEPT => accept(args, context, 0),
        NR_ACCEPT4 => accept(args, context, args[3]),
        NR_SENDTO => sendto(args, context),
        NR_RECVFROM => recvfrom(args, context),
        NR_SENDMSG => sendmsg(args, context),
        NR_RECVMSG => recvmsg(args, context),
        NR_BIND => bind(args, context),
        NR_LISTEN => listen(args, context),
        NR_GETSOCKNAME => socket_name(args, context, false),
        NR_GETPEERNAME => socket_name(args, context, true),
        NR_SOCKETPAIR => socketpair(args, context),
        NR_SETSOCKOPT => setsockopt(args, context),
        NR_GETSOCKOPT => getsockopt(args, context),
        NR_SHUTDOWN => shutdown(args, context),
        NR_GETPID => getpid(),
        NR_GETPPID => getppid(),
        NR_UNAME => uname(args, context),
        NR_CLOCK_GETTIME => clock_gettime(args, context),
        NR_CLOCK_NANOSLEEP => clock_nanosleep(args, context),
        NR_RT_SIGACTION => rt_sigaction(args, context),
        NR_RT_SIGPROCMASK => rt_sigprocmask(args, context),
        NR_RT_SIGRETURN => rt_sigreturn(context),
        NR_KILL => kill(args, context),
        NR_TGKILL => tgkill(args, context),
        NR_WAIT4 => wait4(args, context),
        NR_SYSINFO => sysinfo(args, context),
        NR_FUTEX => futex_op(args, context),
        NR_ARCH_PRCTL => arch_prctl(args, context),
        NR_SET_TID_ADDRESS => set_tid_address(args),
        NR_EPOLL_CREATE => epoll_create(args, context, true),
        NR_EPOLL_CREATE1 => epoll_create(args, context, false),
        NR_EPOLL_CTL => epoll_ctl(args, context),
        NR_EPOLL_WAIT => epoll_wait(args, context, false),
        NR_EPOLL_PWAIT => epoll_wait(args, context, true),
        NR_TIMERFD_CREATE => timerfd_create(args, context),
        NR_TIMERFD_SETTIME => timerfd_settime(args, context),
        NR_TIMERFD_GETTIME => timerfd_gettime(args, context),
        NR_SIGNALFD => signalfd_create(args, context, false),
        NR_SIGNALFD4 => signalfd_create(args, context, true),
        NR_GETUID | NR_GETEUID | NR_GETGID | NR_GETEGID => Ok(Outcome::Done(0)),
        NR_EXIT | NR_EXIT_GROUP => process::exit_current(args[0]),
        NR_GETRANDOM => getrandom(args, context),
        NR_PREAD64 => pread64(args, context),
        NR_IOCTL => ioctl(args, context),
        NR_READLINK => readlink(args, context),
        _ => {
            ENOSYS_COUNT.fetch_add(1, Ordering::Relaxed);
            Err(errno::ENOSYS)
        }
    }
}

// ---------------------------------------------------------------------------
// Descriptor helpers
// ---------------------------------------------------------------------------

fn linux_fd(raw: u64) -> Result<u32, i64> {
    u32::try_from(raw).map_err(|_| errno::EBADF)
}

fn entry(context: &LinuxContext<'_>, fd: u32) -> Result<FdEntry, i64> {
    context.fds.get(fd).map_err(|_| errno::EBADF)
}

/// Translate a descriptor-table failure that is not a plain missing descriptor.
fn fd_errno(error: FdError) -> i64 {
    match error {
        FdError::BadFd => errno::EBADF,
        FdError::Full => errno::EMFILE,
        FdError::Object => errno::EIO,
    }
}

/// `dup`: copy a descriptor onto the lowest free slot.
///
/// The new descriptor shares the same object (the table takes its own
/// reference) and, as on Linux, does not inherit `FD_CLOEXEC`. `dup` of a
/// missing descriptor is `EBADF`; a full table is `EMFILE`.
fn dup(args: &[u64; 6], context: &mut LinuxContext<'_>) -> Result<Outcome, i64> {
    let fd = linux_fd(args[0])?;
    let entry = entry(context, fd)?;
    let new = context
        .fds
        .insert(FdEntry::new_socket(entry.object, false, entry.domain))
        .map_err(fd_errno)?;
    Ok(Outcome::Done(i64::from(new)))
}

/// `dup2`: put a copy of `oldfd` at `newfd`.
///
/// `newfd == oldfd` is a successful no-op (`FD_CLOEXEC` is unchanged). For a
/// different `newfd`, an occupied target is closed first (its reference is
/// dropped) and the new descriptor never inherits `FD_CLOEXEC`. Both descriptors
/// are validated before the target is touched, so a bad `oldfd` or an
/// out-of-range `newfd` leaves the table unchanged and reports `EBADF`.
fn dup2(args: &[u64; 6], context: &mut LinuxContext<'_>) -> Result<Outcome, i64> {
    let old = linux_fd(args[0])?;
    let new = linux_fd(args[1])?;
    let entry = entry(context, old)?;
    if new == old {
        return Ok(Outcome::Done(i64::from(new)));
    }
    context
        .fds
        .install_at(new, FdEntry::new_socket(entry.object, false, entry.domain))
        .map_err(fd_errno)?;
    Ok(Outcome::Done(i64::from(new)))
}

/// The socket behind a descriptor, or `ENOTSOCK` for a non-socket object.
fn socket_of(context: &LinuxContext<'_>, fd: u32) -> Result<SocketId, i64> {
    let entry = entry(context, fd)?;
    match object::object_kind(entry.object) {
        Some(ObjectKind::Socket) => {
            let payload = object::payload(entry.object).ok_or(errno::EBADF)?;
            let raw = payload as u32;
            Ok(SocketId::new((raw >> 16) as usize, raw as u16))
        }
        Some(_) => Err(errno::ENOTSOCK),
        None => Err(errno::EBADF),
    }
}

/// The waitable object of a socket.
fn socket_object(id: SocketId) -> Result<ObjectId, i64> {
    net::object_of(id).ok_or(errno::EBADF)
}

/// Record the creating process identity on a fresh socket.
///
/// The network slot stores the `Credential`; the personality only decides when
/// to fill it. Linux stamps every socket with its creator so that
/// `SO_PASSCRED`/`SCM_CREDENTIALS` can report the real sender later.
fn stamp_credential(id: SocketId) -> Result<(), i64> {
    let pid = process::current_linux_pid().unwrap_or(0);
    if pid == 0 {
        return Ok(());
    }
    net::set_cred(id, net::Credential::new(pid, 0, 0)).map_err(net_errno)
}

/// Linux `AF_*` family of a socket descriptor.
///
/// The descriptor table records the family at `socket()`/`socketpair()` time
/// (and `dup`/`dup2` copy it), so `getsockname` can report a zeroed address of
/// the right layout even before the engine has bound the socket. The engine
/// lookup is only a fallback for descriptors that predate the record.
fn socket_family(context: &LinuxContext<'_>, fd: u32) -> Result<u16, i64> {
    let entry = entry(context, fd)?;
    if entry.domain != 0 {
        return Ok(entry.domain);
    }
    let id = socket_of(context, fd)?;
    let address = net::local_address(id).map_err(net_errno)?;
    address::family_for_domain(address.family).ok_or(errno::EINVAL)
}

/// The zeroed address `getsockname` reports for an unbound socket.
fn unnamed_address(family: u16) -> net::SocketAddress {
    match family {
        address::AF_INET => net::SocketAddress::inet_v4(Ipv4Addr::new(0, 0, 0, 0), 0),
        address::AF_INET6 => net::SocketAddress::inet_v6(Ipv6Addr::new([0u8; 16]), 0),
        _ => net::SocketAddress {
            family: net::DOMAIN_UNIX,
            ..net::SocketAddress::INVALID
        },
    }
}

/// Publish a freshly created engine socket as an attached object and install it
/// in the descriptor table. On failure the engine socket is destroyed.
fn install_socket(
    context: &mut LinuxContext<'_>,
    id: SocketId,
    cloexec: bool,
    family: u16,
) -> Result<u32, i64> {
    let object = object::create_with_payload(ObjectKind::Socket, u64::from(id.raw()))
        .map_err(object_errno)?;
    if net::attach_object(id, object).is_err() {
        let _ = object::release_object(object);
        let _ = net::destroy(id);
        return Err(errno::EIO);
    }
    let installed = context
        .fds
        .insert(FdEntry::new_socket(object, cloexec, family));
    // The descriptor table took its own reference; drop the creation reference.
    let _ = object::release_object(object);
    match installed {
        Ok(fd) => Ok(fd),
        Err(_) => {
            let _ = net::destroy(id);
            Err(errno::EMFILE)
        }
    }
}

/// Run a post-install step and, when it fails, close the descriptor it was
/// going to complete.
///
/// `accept` publishes the accepted socket first and then writes the peer
/// address back into user memory. Every failure between the two (a bad
/// `socklen_t`, an unmapped buffer, an unsupported address layout) must undo the
/// descriptor: returning with it installed would leak both the fd entry and the
/// engine socket, which a Linux program can never close because it never learns
/// the descriptor number.
fn close_on_failure(
    context: &mut LinuxContext<'_>,
    installed: u32,
    result: Result<(), i64>,
) -> Result<(), i64> {
    match result {
        Ok(()) => Ok(()),
        Err(error) => {
            context.fds.close(installed).ok();
            Err(error)
        }
    }
}

/// Write an engine address into the user `sockaddr` buffer.
fn write_socket_address(
    context: &LinuxContext<'_>,
    source: &net::SocketAddress,
    pointer: u64,
    length_pointer: u64,
) -> Result<(), i64> {
    write_sockaddr(context, source, pointer, length_pointer).map(|_| ())
}

/// Write the peer address of `id` into the user buffer (`accept`).
fn write_peer_address(
    context: &LinuxContext<'_>,
    id: SocketId,
    pointer: u64,
    length_pointer: u64,
) -> Result<(), i64> {
    let peer = net::remote_address(id).map_err(net_errno)?;
    write_socket_address(context, &peer, pointer, length_pointer)
}

// ---------------------------------------------------------------------------
// Error mapping
// ---------------------------------------------------------------------------

fn net_errno(error: NetError) -> i64 {
    match error {
        NetError::Quota => errno::ENOMEM,
        NetError::WouldBlock => errno::EAGAIN,
        NetError::InvalidSocket => errno::EBADF,
        NetError::NotConnected => errno::ENOTCONN,
        NetError::PeerClosed => errno::ENOTCONN,
        NetError::Reset => errno::ECONNRESET,
        NetError::Refused => errno::ECONNREFUSED,
        NetError::Timeout => errno::ETIMEDOUT,
        NetError::Malformed => errno::EINVAL,
        NetError::Unsupported => errno::EOPNOTSUPP,
        NetError::AddressInUse => errno::EADDRINUSE,
        NetError::NotFound => errno::ENOENT,
        NetError::BadAddress => errno::EINVAL,
        NetError::TooLarge => errno::EMSGSIZE,
    }
}

fn object_errno(error: object::ObjectError) -> i64 {
    use object::ObjectError;
    match error {
        ObjectError::ObjectTableFull => errno::ENOMEM,
        ObjectError::HandleTableFull => errno::EMFILE,
        ObjectError::InvalidObject | ObjectError::BadHandle => errno::EBADF,
        ObjectError::WrongObjectKind => errno::ENOTSOCK,
        ObjectError::MissingRights | ObjectError::InvalidRights => errno::EACCES,
        ObjectError::RightsEscalation => errno::EACCES,
        _ => errno::EIO,
    }
}

// ---------------------------------------------------------------------------
// User-memory helpers
// ---------------------------------------------------------------------------

fn copy_in(context: &LinuxContext<'_>, pointer: u64, out: &mut [u8]) -> Result<(), i64> {
    if pointer == 0 {
        return Err(errno::EFAULT);
    }
    let space = context.space()?;
    addrspace::copy_in(space, pointer, out).map_err(|_| errno::EFAULT)
}

fn copy_out(context: &LinuxContext<'_>, pointer: u64, bytes: &[u8]) -> Result<(), i64> {
    if pointer == 0 {
        return Err(errno::EFAULT);
    }
    let space = context.space()?;
    addrspace::copy_out(space, pointer, bytes).map_err(|_| errno::EFAULT)
}

fn read_u32(context: &LinuxContext<'_>, pointer: u64) -> Result<u32, i64> {
    let mut raw = [0u8; 4];
    copy_in(context, pointer, &mut raw)?;
    Ok(u32::from_le_bytes(raw))
}

fn write_u32(context: &LinuxContext<'_>, pointer: u64, value: u32) -> Result<(), i64> {
    copy_out(context, pointer, &value.to_le_bytes())
}

/// Clamp a user-supplied address length before copying it in.
///
/// Linux programs routinely pass `sizeof(struct sockaddr_storage)` (128) even
/// when the concrete layout is 16/28 bytes; reading 110 bytes worth of the
/// family-specific layout is correct and must not fail. A length below the
/// smallest layout (the family tag alone) is still `EINVAL`.
fn clamped_wire_length(length: u64) -> Result<usize, i64> {
    let length = usize::try_from(length).map_err(|_| errno::EINVAL)?;
    if length < 2 {
        return Err(errno::EINVAL);
    }
    Ok(length.min(address::SOCKADDR_MAX))
}

/// Clamp a user-supplied `socklen_t` capacity before writing an address back.
///
/// The kernel writes at most [`address::SOCKADDR_MAX`] bytes (and reports the
/// real length through the `socklen_t` pointer), so a `sockaddr_storage`
/// capacity is a superset, not an error. A zero/near-zero capacity cannot hold
/// even the family tag and stays `EINVAL`.
fn clamped_wire_capacity(capacity: u32) -> Result<usize, i64> {
    let capacity = capacity as usize;
    if capacity < 2 {
        return Err(errno::EINVAL);
    }
    Ok(capacity.min(address::SOCKADDR_MAX))
}

fn read_sockaddr(
    context: &LinuxContext<'_>,
    pointer: u64,
    length: u64,
) -> Result<net::SocketAddress, i64> {
    if pointer == 0 {
        return Err(errno::EFAULT);
    }
    let length = clamped_wire_length(length)?;
    let mut raw = [0u8; address::SOCKADDR_MAX];
    copy_in(context, pointer, &mut raw[..length])?;
    address::parse(&raw[..length])
}

/// Install a socket name (`getsockname`/`getpeername`) into a user buffer.
fn write_sockaddr(
    context: &LinuxContext<'_>,
    address: &net::SocketAddress,
    pointer: u64,
    length_pointer: u64,
) -> Result<i64, i64> {
    if pointer == 0 || length_pointer == 0 {
        return Err(errno::EFAULT);
    }
    let capacity = clamped_wire_capacity(read_u32(context, length_pointer)?)?;
    let mut raw = [0u8; address::SOCKADDR_MAX];
    let real = address::write(address, &mut raw[..capacity])?;
    copy_out(context, pointer, &raw[..real])?;
    write_u32(context, length_pointer, real as u32)?;
    Ok(i64::from(real as u32))
}

// ---------------------------------------------------------------------------
// read / write / close
// ---------------------------------------------------------------------------

fn read(args: &[u64; 6], context: &mut LinuxContext<'_>) -> Result<Outcome, i64> {
    let fd = linux_fd(args[0])?;
    let buffer = args[1];
    let length = usize::try_from(args[2]).map_err(|_| errno::EINVAL)?;
    let entry = entry(context, fd)?;
    match object::object_kind(entry.object) {
        Some(ObjectKind::Socket) => {
            let id = socket_of(context, fd)?;
            receive_into(context, id, buffer, length, 0, 0)
        }
        Some(ObjectKind::File) => {
            let open = file_open_of(entry.object)?;
            reject_directory_io(open)?;
            file_read(context, &mut VfsIo, open, buffer, length)
        }
        Some(ObjectKind::EventFd) => eventfd_read(context, &entry, buffer, length),
        // M9a: timerfd and signalfd carry their own blocking semantics; the
        // epoll instance itself is only waitable through `epoll_wait`.
        Some(ObjectKind::TimerFd) => timerfd_read(context, &entry, buffer, length),
        Some(ObjectKind::SignalFd) => signalfd_read(context, &entry, buffer, length),
        Some(ObjectKind::Epoll) => Err(errno::EINVAL),
        Some(ObjectKind::Console) => {
            // The kernel has no Linux input path yet; claiming data would be a
            // lie, so a non-blocking read reports EAGAIN.
            Err(errno::EAGAIN)
        }
        Some(_) => Err(errno::ENOTSOCK),
        None => Err(errno::EBADF),
    }
}

fn write(args: &[u64; 6], context: &mut LinuxContext<'_>) -> Result<Outcome, i64> {
    let fd = linux_fd(args[0])?;
    let buffer = args[1];
    let length = usize::try_from(args[2]).map_err(|_| errno::EINVAL)?;
    let entry = entry(context, fd)?;
    match object::object_kind(entry.object) {
        Some(ObjectKind::Socket) => {
            let id = socket_of(context, fd)?;
            let sent = send_from_user(context, id, buffer, length)?;
            send_outcome(sent, socket_object(id).ok())
        }
        Some(ObjectKind::File) => {
            let open = file_open_of(entry.object)?;
            reject_directory_io(open)?;
            file_write(context, &mut VfsIo, open, buffer, length)
        }
        Some(ObjectKind::EventFd) => eventfd_write(context, &entry, buffer, length),
        // M9a descriptors are read-only or control objects: writing them is an
        // invalid operation, not a socket mismatch.
        Some(ObjectKind::TimerFd) | Some(ObjectKind::SignalFd) | Some(ObjectKind::Epoll) => {
            Err(errno::EINVAL)
        }
        Some(ObjectKind::Console) => {
            if fd > 2 {
                return Err(errno::EBADF);
            }
            let chunk = length.min(MAX_IO);
            let mut data = [0u8; MAX_IO];
            copy_in(context, buffer, &mut data[..chunk])?;
            crate::log::serial_write_bytes(&data[..chunk]);
            Ok(Outcome::Done(chunk as i64))
        }
        Some(_) => Err(errno::ENOTSOCK),
        None => Err(errno::EBADF),
    }
}

fn close(args: &[u64; 6], context: &mut LinuxContext<'_>) -> Result<Outcome, i64> {
    let fd = linux_fd(args[0])?;
    // POSIX locks belong to the opening process: closing *any* descriptor of the
    // same open description releases every POSIX lock this process holds on the
    // file (Linux semantics, agents.md §12.1). The VFS keeps the same invariant
    // on its own close path; the explicit hook also covers duplicated fds whose
    // last reference is only dropped here.
    if let Ok(entry) = context.fds.get(fd)
        && object::object_kind(entry.object) == Some(ObjectKind::File)
        && let Ok(open) = file_open_of(entry.object)
    {
        let _ = vfs::note_close_locks(open);
    }
    context.fds.close(fd).map_err(|_| errno::EBADF)?;
    Ok(Outcome::Done(0))
}

// ---------------------------------------------------------------------------
// M8g: eventfd
// ---------------------------------------------------------------------------

fn eventfd_errno(error: eventfd::EventFdError) -> i64 {
    use eventfd::EventFdError;
    match error {
        EventFdError::TableFull => errno::EMFILE,
        EventFdError::NoSuchObject => errno::EBADF,
        EventFdError::WrongKind | EventFdError::BadValue | EventFdError::InvalidPayload => {
            errno::EINVAL
        }
        EventFdError::WouldBlock => errno::EAGAIN,
    }
}

/// `eventfd(284)` / `eventfd2(290)`.
///
/// The compat descriptor table stores `ObjectId`s, so the personality builds
/// the kernel eventfd slot, the object and the binding itself instead of using
/// the native `HandleTable` helper `ipc::insert_eventfd`.
fn eventfd_create(
    args: &[u64; 6],
    context: &mut LinuxContext<'_>,
    version_two: bool,
) -> Result<Outcome, i64> {
    // Both entries take an `unsigned int` initial value.
    let initval = u64::from(args[0] as u32);
    // The legacy `eventfd` entry has no flags argument.
    let flags = if version_two {
        u32::try_from(args[1]).map_err(|_| errno::EINVAL)?
    } else {
        0
    };
    if flags & !EFD_FLAG_MASK != 0 {
        return Err(errno::EINVAL);
    }
    let cloexec = flags & EFD_CLOEXEC != 0;

    let payload = eventfd::create(initval, flags).map_err(eventfd_errno)?;
    let object = match object::create_with_payload(ObjectKind::EventFd, payload) {
        Ok(object) => object,
        Err(error) => {
            let _ = eventfd::discard(payload);
            return Err(object_errno(error));
        }
    };
    if let Err(error) = eventfd::bind(payload, object) {
        let _ = eventfd::discard(payload);
        let _ = object::release_object(object);
        return Err(eventfd_errno(error));
    }
    let installed = context.fds.insert(FdEntry::new(object, cloexec));
    // Drop the creation reference: the descriptor now owns the object, and a
    // failed install drops the last reference, which runs the kernel destroy
    // hook and releases the eventfd slot.
    let _ = object::release_object(object);
    match installed {
        Ok(fd) => Ok(Outcome::Done(i64::from(fd))),
        Err(_) => Err(errno::EMFILE),
    }
}

/// Outcome of an eventfd read/write that cannot complete now.
fn eventfd_would_block(object: ObjectId) -> Result<Outcome, i64> {
    if eventfd::nonblocking(object).unwrap_or(false) {
        Err(errno::EAGAIN)
    } else {
        Ok(Outcome::Wait {
            object,
            deadline: None,
        })
    }
}

/// `read` on an eventfd descriptor.
///
/// The eight-byte result must be writable **before** the counter is consumed,
/// so a bad user pointer cannot silently lose the value (`EFAULT`).
fn eventfd_read(
    context: &LinuxContext<'_>,
    entry: &FdEntry,
    buffer: u64,
    length: usize,
) -> Result<Outcome, i64> {
    if length < 8 {
        return Err(errno::EINVAL);
    }
    let space = context.space()?;
    addrspace::validate_user_range(space, buffer, 8, true).map_err(|_| errno::EFAULT)?;
    match eventfd::read(entry.object) {
        Ok(value) => {
            copy_out(context, buffer, &value.to_le_bytes())?;
            Ok(Outcome::Done(8))
        }
        Err(error) if error.is_would_block() => eventfd_would_block(entry.object),
        Err(error) => Err(eventfd_errno(error)),
    }
}

/// `write` on an eventfd descriptor: exactly one eight-byte counter value.
fn eventfd_write(
    context: &LinuxContext<'_>,
    entry: &FdEntry,
    buffer: u64,
    length: usize,
) -> Result<Outcome, i64> {
    if length != 8 {
        return Err(errno::EINVAL);
    }
    let mut raw = [0u8; 8];
    copy_in(context, buffer, &mut raw)?;
    match eventfd::write(entry.object, u64::from_le_bytes(raw)) {
        Ok(()) => Ok(Outcome::Done(8)),
        Err(error) if error.is_would_block() => eventfd_would_block(entry.object),
        Err(error) => Err(eventfd_errno(error)),
    }
}

// ---------------------------------------------------------------------------
// M8g: poll / ppoll
// ---------------------------------------------------------------------------

/// Readiness snapshot of one descriptor.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct Readiness {
    readable: bool,
    writable: bool,
    error: bool,
    invalid: bool,
}

impl Readiness {
    /// Project the snapshot onto the caller's requested `events` bits.
    ///
    /// As on Linux only requested readiness bits are reported; `POLLERR`,
    /// `POLLNVAL` (and `POLLHUP`, which this personality never raises) are
    /// unconditional.
    fn revents(self, requested: i16) -> i16 {
        if self.invalid {
            return POLLNVAL;
        }
        let mut revents = 0;
        if self.readable {
            revents |= requested & POLL_READABLE;
        }
        if self.writable {
            revents |= requested & POLL_WRITABLE;
        }
        if self.error {
            revents |= POLLERR;
        }
        revents
    }
}

/// Current readiness of `fd` for `poll`.
fn descriptor_readiness(context: &LinuxContext<'_>, fd: u32) -> Readiness {
    let Ok(entry) = context.fds.get(fd) else {
        return Readiness {
            invalid: true,
            ..Readiness::default()
        };
    };
    let mut readiness = Readiness::default();
    match object::object_kind(entry.object) {
        Some(ObjectKind::Socket) => match socket_of(context, fd) {
            Ok(id) => match net::poll(id) {
                Ok(mask) => {
                    readiness.readable = mask.contains(net::PollMask::READ);
                    readiness.writable = mask.contains(net::PollMask::WRITE);
                    readiness.error = mask.contains(net::PollMask::ERROR);
                }
                Err(NetError::InvalidSocket) => readiness.invalid = true,
                Err(_) => readiness.error = true,
            },
            Err(_) => readiness.invalid = true,
        },
        Some(ObjectKind::EventFd) => {
            readiness.readable = eventfd::readable(entry.object).unwrap_or(false);
            readiness.writable = eventfd::writable(entry.object).unwrap_or(false);
        }
        // M9a descriptors: readable when their kernel object reports readiness.
        Some(ObjectKind::TimerFd) => {
            readiness.readable = timerfd::readable(entry.object).unwrap_or(false);
        }
        Some(ObjectKind::SignalFd) => {
            readiness.readable = signalfd::readable(entry.object).unwrap_or(false);
        }
        Some(ObjectKind::Epoll) => {
            readiness.readable = epoll::any_ready(entry.object).unwrap_or(false);
        }
        // Regular files, and any personality object that behaves like one, are
        // always ready in both directions.
        Some(ObjectKind::File) => {
            readiness.readable = true;
            readiness.writable = true;
        }
        // The console has no Linux input path yet; only writing is truthful.
        Some(ObjectKind::Console) => readiness.writable = true,
        Some(_) => {
            readiness.readable = true;
            readiness.writable = true;
        }
        None => readiness.invalid = true,
    }
    readiness
}

/// Whether readiness changes can wake a `poll` wait.
fn descriptor_is_waitable(context: &LinuxContext<'_>, fd: u32) -> bool {
    let Ok(entry) = context.fds.get(fd) else {
        return false;
    };
    matches!(
        object::object_kind(entry.object),
        Some(ObjectKind::Socket)
            | Some(ObjectKind::EventFd)
            | Some(ObjectKind::TimerFd)
            | Some(ObjectKind::SignalFd)
            | Some(ObjectKind::Epoll)
    )
}

/// `poll` timeout in milliseconds → absolute monotonic deadline.
///
/// `timeout < 0` means no deadline, `0` is "check only" (already due).
fn poll_ms_deadline(now: u64, hz: u32, timeout: i32) -> Result<Option<u64>, i64> {
    if timeout < 0 {
        return Ok(None);
    }
    if timeout == 0 {
        return Ok(Some(now));
    }
    let nanos = u128::from(timeout as u32) * 1_000_000;
    Ok(Some(now.saturating_add(nanos_to_ticks_ceil(nanos, hz)?)))
}

/// `ppoll` timeout (`struct timespec`, relative) → absolute monotonic deadline.
fn poll_timespec_deadline(
    context: &LinuxContext<'_>,
    pointer: u64,
    now: u64,
    hz: u32,
) -> Result<Option<u64>, i64> {
    let (seconds, nanos) = read_timespec(context, pointer)?;
    let nanos = u128::try_from(seconds)
        .map_err(|_| errno::EINVAL)?
        .checked_mul(NANOS_PER_SECOND)
        .ok_or(errno::EOVERFLOW)?
        .checked_add(u128::try_from(nanos).map_err(|_| errno::EINVAL)?)
        .ok_or(errno::EOVERFLOW)?;
    if nanos == 0 {
        return Ok(Some(now));
    }
    Ok(Some(now.saturating_add(nanos_to_ticks_ceil(nanos, hz)?)))
}

/// Wait for the remaining `poll` timeout when there is no waitable descriptor.
fn poll_sleep(now: u64, deadline: Option<u64>) -> Result<Outcome, i64> {
    match deadline {
        Some(target) if target > now => {
            SLEEP_DEADLINES[sleep_slot()].store(target, Ordering::Relaxed);
            Ok(Outcome::Wait {
                object: SLEEP_OBJECT,
                deadline: Some(target),
            })
        }
        Some(_) => Ok(Outcome::Done(0)),
        None => {
            SLEEP_DEADLINES[sleep_slot()].store(u64::MAX, Ordering::Relaxed);
            Ok(Outcome::Wait {
                object: SLEEP_OBJECT,
                deadline: None,
            })
        }
    }
}

/// Validate the `ppoll` signal-mask argument without touching user memory.
///
/// Returns the user pointer when a mask was requested. The entry layer copies
/// the sigset and installs the temporary mask; the compat layer only validates
/// the fixed part so a direct dispatch also rejects a wrong `sigsetsize`.
pub fn ppoll_mask_request(args: &[u64; 6]) -> Result<Option<u64>, i64> {
    if args[3] == 0 {
        return Ok(None);
    }
    if args[4] != signal::SIGSET_SIZE {
        return Err(errno::EINVAL);
    }
    Ok(Some(args[3]))
}

/// Same contract as [`ppoll_mask_request`] for `epoll_pwait`.
///
/// `epoll_pwait(epfd, events, maxevents, timeout, sigmask, sigsetsize)`: the
/// signal mask pointer is `args[4]` and its size is `args[5]`. A `NULL` mask
/// keeps the process mask untouched (`None`); a non-`NULL` one must carry the
/// frozen 8-byte sigset size like `ppoll`.
pub fn epoll_pwait_mask_request(args: &[u64; 6]) -> Result<Option<u64>, i64> {
    if args[4] == 0 {
        return Ok(None);
    }
    if args[5] != signal::SIGSET_SIZE {
        return Err(errno::EINVAL);
    }
    Ok(Some(args[4]))
}

/// Lowest pending signal that the given blocked mask lets through.
///
/// Standard signals only (1..=31); `SIGKILL`/`SIGSTOP` can never be blocked.
/// The decision deliberately ignores the action table: an ignored pending
/// signal is consumed by delivery and does not interrupt the call, and the
/// delivery loop reports that case by delivering nothing.
pub fn pending_is_deliverable(pending: u64, blocked: u64) -> bool {
    const SIGNAL_MAX: u32 = 31;
    const SIGKILL: u32 = 9;
    const SIGSTOP: u32 = 19;
    for signo in 1..=SIGNAL_MAX {
        let bit = 1u64 << (signo - 1);
        if pending & bit == 0 {
            continue;
        }
        if signo != SIGKILL && signo != SIGSTOP && blocked & bit != 0 {
            continue;
        }
        return true;
    }
    false
}

/// `poll(7)` / `ppoll(271)`.
///
/// The call stays non-blocking: when no descriptor is ready it reports the
/// objects to wait on ([`Outcome::PollWait`]) and the entry replay computes the
/// returned `revents` against the state at wake time.
fn poll(args: &[u64; 6], context: &mut LinuxContext<'_>, ppoll: bool) -> Result<Outcome, i64> {
    let fd_pointer = args[0];
    let nfds = usize::try_from(args[1]).map_err(|_| errno::EINVAL)?;
    if nfds > MAX_POLL_FDS {
        return Err(errno::EINVAL);
    }
    if ppoll {
        // The entry layer copies the sigset and installs the temporary mask;
        // here only the fixed `sigsetsize` is validated so a direct dispatch
        // behaves the same as a real call.
        let _ = ppoll_mask_request(args)?;
    }

    let hz = crate::time::tick_hz();
    let now = crate::time::monotonic_ticks();
    let requested_deadline = if ppoll {
        if args[2] == 0 {
            None
        } else {
            poll_timespec_deadline(context, args[2], now, hz)?
        }
    } else {
        poll_ms_deadline(now, hz, args[2] as u32 as i32)?
    };

    // `poll` owns its wake reason: a timeout ends the call with zero ready
    // descriptors, a signal interruption reports `EINTR`.
    let reason = process::take_wake_reason();
    match reason {
        process::WakeReason::Timeout => return Ok(Outcome::Done(0)),
        process::WakeReason::Cancelled => return Ok(Outcome::Done(-errno::EINTR)),
        _ => {}
    }
    // On replay keep the absolute deadline computed by the first pass.
    let deadline = if reason.is_some() {
        process::wait_deadline().or(requested_deadline)
    } else {
        requested_deadline
    };

    // Preflight and copy the whole descriptor array before using any pointer.
    let mut fds = [PollFd {
        fd: 0,
        events: 0,
        revents: 0,
    }; MAX_POLL_FDS];
    let mut space = None;
    if nfds > 0 {
        if fd_pointer == 0 {
            return Err(errno::EFAULT);
        }
        let id = context.space()?;
        let bytes = nfds * POLLFD_SIZE;
        addrspace::validate_user_range(id, fd_pointer, bytes as u64, true)
            .map_err(|_| errno::EFAULT)?;
        let mut raw = [0u8; MAX_POLL_FDS * POLLFD_SIZE];
        addrspace::copy_in(id, fd_pointer, &mut raw[..bytes]).map_err(|_| errno::EFAULT)?;
        for (index, descriptor) in fds[..nfds].iter_mut().enumerate() {
            let start = index * POLLFD_SIZE;
            *descriptor = PollFd::decode(&raw[start..start + POLLFD_SIZE]);
        }
        space = Some(id);
    }

    let mut objects: [ObjectId; MAX_POLL_WAIT] = [0; MAX_POLL_WAIT];
    let mut wait_count = 0usize;
    let mut ready = 0i64;
    for descriptor in fds[..nfds].iter_mut() {
        if descriptor.fd < 0 {
            // Linux ignores negative descriptors.
            descriptor.revents = 0;
            continue;
        }
        let fd = descriptor.fd as u32;
        descriptor.revents = descriptor_readiness(context, fd).revents(descriptor.events);
        if descriptor.revents != 0 {
            ready += 1;
            continue;
        }
        let wants_wait = descriptor.events & (POLL_READABLE | POLL_WRITABLE) != 0;
        if !wants_wait || !descriptor_is_waitable(context, fd) {
            continue;
        }
        let Ok(entry) = context.fds.get(fd) else {
            continue;
        };
        if objects[..wait_count].contains(&entry.object) {
            continue;
        }
        // The kernel wait budget is four objects; refusing more is honest.
        if wait_count == MAX_POLL_WAIT {
            return Err(errno::EINVAL);
        }
        objects[wait_count] = entry.object;
        wait_count += 1;
    }

    if ready > 0 {
        let space = space.ok_or(errno::EFAULT)?;
        let mut raw = [0u8; MAX_POLL_FDS * POLLFD_SIZE];
        for (index, descriptor) in fds[..nfds].iter().enumerate() {
            let start = index * POLLFD_SIZE;
            raw[start..start + POLLFD_SIZE].copy_from_slice(&descriptor.encode());
        }
        addrspace::copy_out(space, fd_pointer, &raw[..nfds * POLLFD_SIZE])
            .map_err(|_| errno::EFAULT)?;
        return Ok(Outcome::Done(ready));
    }
    if nfds == 0 {
        // `poll` with no descriptors is a pure timeout sleep.
        return poll_sleep(now, deadline);
    }
    if wait_count == 0 {
        // Nothing can become ready: return instead of sleeping on nothing.
        return Ok(Outcome::Done(0));
    }
    if deadline.map(|target| target <= now).unwrap_or(false) {
        return Ok(Outcome::Done(0));
    }
    let keys = [process::WAIT_ANY_KEY; MAX_POLL_WAIT];
    Ok(Outcome::PollWait {
        objects,
        keys,
        count: wait_count,
        deadline,
    })
}

// ---------------------------------------------------------------------------
// M9a: timerfd / signalfd / epoll
// ---------------------------------------------------------------------------

/// `TFD_NONBLOCK`.
pub const TFD_NONBLOCK: u32 = 0o0_0004_000;
/// `TFD_CLOEXEC`.
pub const TFD_CLOEXEC: u32 = 0o2_000_000;
const TFD_FLAG_MASK: u32 = TFD_NONBLOCK | TFD_CLOEXEC;
/// `TFD_TIMER_ABSTIME`.
pub const TFD_TIMER_ABSTIME: u64 = 1;
const ITIMERSPEC_SIZE: usize = 2 * TIMESPEC_SIZE;
/// `SFD_NONBLOCK`.
pub const SFD_NONBLOCK: u32 = 0o0_0004_000;
/// `SFD_CLOEXEC`.
pub const SFD_CLOEXEC: u32 = 0o2_000_000;
const SFD_FLAG_MASK: u32 = SFD_NONBLOCK | SFD_CLOEXEC;
/// `sizeof(struct signalfd_siginfo)`.
pub const SIGNALFD_SIGINFO_SIZE: usize = 128;
/// `EPOLL_CTL_ADD`.
pub const EPOLL_CTL_ADD: u64 = 1;
/// `EPOLL_CTL_DEL`.
pub const EPOLL_CTL_DEL: u64 = 2;
/// `EPOLL_CTL_MOD`.
pub const EPOLL_CTL_MOD: u64 = 3;
/// `EPOLL_CLOEXEC` (the only flag `epoll_create1` accepts).
pub const EPOLL_CLOEXEC: u32 = 0o2_000_000;
/// `sizeof(struct epoll_event)` on x86-64 (packed `events` + `data`).
pub const EPOLL_EVENT_SIZE: usize = 12;
/// Upper bound on `maxevents`.
pub const MAX_EPOLL_EVENTS: usize = 16;
const EPOLLIN: u32 = 0x001;
const EPOLLOUT: u32 = 0x004;
const EPOLLERR: u32 = 0x008;
const EPOLLHUP: u32 = 0x010;
/// `EPOLLET`: edge-triggered interest. The edge state is kept by the kernel
/// epoll table, so this is a plain flag from the front-end's point of view.
const EPOLLET: u32 = 1 << 31;
/// `EPOLLONESHOT`: not wired yet (needs the post-delivery disarm step).
const EPOLLONESHOT: u32 = 1 << 30;
/// Bits an interest may request. `EPOLLERR`/`EPOLLHUP` are always reported by
/// Linux even when not requested, so they are accepted here too. `EPOLLET` is
/// a semantic modifier, not an extra readiness bit.
const EPOLL_INTEREST_BITS: u32 = EPOLLIN | EPOLLOUT | EPOLLERR | EPOLLHUP | EPOLLET;

fn timerfd_errno(error: timerfd::TimerFdError) -> i64 {
    match error {
        timerfd::TimerFdError::TableFull => errno::EMFILE,
        timerfd::TimerFdError::NoSuchObject => errno::EBADF,
        timerfd::TimerFdError::WrongKind | timerfd::TimerFdError::BadValue => errno::EINVAL,
        timerfd::TimerFdError::WouldBlock => errno::EAGAIN,
    }
}

fn signalfd_errno(error: signalfd::SignalFdError) -> i64 {
    match error {
        signalfd::SignalFdError::TableFull => errno::EMFILE,
        signalfd::SignalFdError::NoSuchObject => errno::EBADF,
        signalfd::SignalFdError::WrongKind | signalfd::SignalFdError::BadValue => errno::EINVAL,
        signalfd::SignalFdError::WouldBlock => errno::EAGAIN,
    }
}

fn epoll_errno(error: epoll::EpollError) -> i64 {
    match error {
        epoll::EpollError::TableFull => errno::EMFILE,
        epoll::EpollError::NoSuchObject => errno::EBADF,
        epoll::EpollError::WrongKind | epoll::EpollError::BadValue => errno::EINVAL,
        epoll::EpollError::AlreadyExists => errno::EEXIST,
        epoll::EpollError::NotFound => errno::ENOENT,
        epoll::EpollError::NoSpace => errno::ENOSPC,
    }
}

fn nanoseconds_to_ticks(nanos: u128) -> Result<u64, i64> {
    nanos_to_ticks_ceil(nanos, crate::time::tick_hz())
}

fn decode_timespec_slice(raw: &[u8]) -> Result<(i64, i64), i64> {
    let sec = i64::from_le_bytes(raw[0..8].try_into().unwrap());
    let nsec = i64::from_le_bytes(raw[8..16].try_into().unwrap());
    if sec < 0 || nsec < 0 || nsec >= 1_000_000_000 {
        return Err(errno::EINVAL);
    }
    Ok((sec, nsec))
}

fn timespec_nanos(sec: i64, nsec: i64) -> u128 {
    u128::try_from(sec)
        .unwrap_or(0)
        .saturating_mul(1_000_000_000)
        .saturating_add(u128::try_from(nsec).unwrap_or(0))
}

fn encode_timespec_ticks(ticks: Option<u64>) -> [u8; TIMESPEC_SIZE] {
    let mut raw = [0u8; TIMESPEC_SIZE];
    let ticks = ticks.unwrap_or(0);
    let hz = u64::from(crate::time::tick_hz());
    let (sec, remainder) = if hz == 0 {
        (0, 0)
    } else {
        (ticks / hz, ticks % hz)
    };
    let nsec = if hz == 0 {
        0
    } else {
        ((u128::from(remainder) * 1_000_000_000) / u128::from(hz)) as u64
    };
    raw[0..8].copy_from_slice(&(sec as i64).to_le_bytes());
    raw[8..16].copy_from_slice(&(nsec as i64).to_le_bytes());
    raw
}

/// `timerfd_create(283)`.
fn timerfd_create(args: &[u64; 6], context: &mut LinuxContext<'_>) -> Result<Outcome, i64> {
    let clock = match u32::try_from(args[0]).map_err(|_| errno::EINVAL)? {
        CLOCK_MONOTONIC => timerfd::TimerFdClock::Monotonic,
        CLOCK_BOOTTIME => timerfd::TimerFdClock::Boottime,
        CLOCK_REALTIME => return Err(errno::ENOSYS),
        _ => return Err(errno::EINVAL),
    };
    let flags = u32::try_from(args[1]).map_err(|_| errno::EINVAL)?;
    if flags & !TFD_FLAG_MASK != 0 {
        return Err(errno::EINVAL);
    }
    let cloexec = flags & TFD_CLOEXEC != 0;
    let payload = timerfd::create(clock, flags).map_err(timerfd_errno)?;
    install_kind_object(
        context,
        ObjectKind::TimerFd,
        payload,
        cloexec,
        |payload, object| timerfd::bind(payload, object).is_ok(),
    )
}

/// Shared `create -> object -> bind -> descriptor` tail.
///
/// `payload` must come from the module's `create`; `bind` attaches the module
/// slot to the new object. The descriptor owns the surviving object reference,
/// the creation reference is released right after the handle is installed. A
/// failure before installation tears the payload and the object down again.
fn install_kind_object(
    context: &mut LinuxContext<'_>,
    kind: ObjectKind,
    payload: u64,
    cloexec: bool,
    bind: fn(u64, ObjectId) -> bool,
) -> Result<Outcome, i64> {
    let object = match object::create_with_payload(kind, payload) {
        Ok(object) => object,
        Err(error) => {
            discard_kind_payload(kind, payload);
            return Err(object_errno(error));
        }
    };
    if !bind(payload, object) {
        discard_kind_payload(kind, payload);
        let _ = object::release_object(object);
        return Err(errno::EIO);
    }
    let installed = context.fds.insert(FdEntry::new(object, cloexec));
    // The descriptor table took its own reference; dropping the creation
    // reference leaves exactly one.
    let _ = object::release_object(object);
    match installed {
        Ok(fd) => Ok(Outcome::Done(i64::from(fd))),
        Err(_) => Err(errno::EMFILE),
    }
}

/// Drop an unbound payload created for an object that never came to life.
///
/// The timerfd/signalfd tables only expose their `discard` helpers to unit
/// tests, so the production path binds the payload to a sentinel object id and
/// lets the regular destroy hooks return the table slot.
fn discard_kind_payload(kind: ObjectKind, payload: u64) {
    let sentinel = ObjectId::MAX;
    match kind {
        ObjectKind::TimerFd => {
            if timerfd::bind(payload, sentinel).is_ok() {
                timerfd::on_destroy(sentinel);
            }
        }
        ObjectKind::SignalFd => {
            if signalfd::bind(payload, sentinel).is_ok() {
                signalfd::on_destroy(sentinel);
            }
        }
        ObjectKind::Epoll => {
            if epoll::bind(payload, sentinel).is_ok() {
                epoll::on_destroy(sentinel);
            }
        }
        _ => {}
    }
}

/// `timerfd_settime(286)`.
fn timerfd_settime(args: &[u64; 6], context: &mut LinuxContext<'_>) -> Result<Outcome, i64> {
    let fd = linux_fd(args[0])?;
    let entry = entry(context, fd)?;
    if object::object_kind(entry.object) != Some(ObjectKind::TimerFd) {
        return Err(errno::EINVAL);
    }
    let flags = args[1];
    if flags & !TFD_TIMER_ABSTIME != 0 {
        return Err(errno::EINVAL);
    }
    let space = context.space()?;
    let new_value = args[2];
    if new_value == 0 {
        return Err(errno::EFAULT);
    }
    addrspace::validate_user_range(space, new_value, ITIMERSPEC_SIZE as u64, false)
        .map_err(|_| errno::EFAULT)?;
    let mut raw = [0u8; ITIMERSPEC_SIZE];
    addrspace::copy_in(space, new_value, &mut raw).map_err(|_| errno::EFAULT)?;
    let (interval_sec, interval_nsec) = decode_timespec_slice(&raw[0..TIMESPEC_SIZE])?;
    let (value_sec, value_nsec) = decode_timespec_slice(&raw[TIMESPEC_SIZE..ITIMERSPEC_SIZE])?;
    let interval_nanos = timespec_nanos(interval_sec, interval_nsec);
    let value_nanos = timespec_nanos(value_sec, value_nsec);
    let interval = if interval_nanos == 0 {
        None
    } else {
        Some(nanoseconds_to_ticks(interval_nanos)?)
    };
    let now = crate::time::monotonic_ticks();
    let deadline = if value_nanos == 0 {
        None
    } else {
        let ticks = nanoseconds_to_ticks(value_nanos)?;
        if flags & TFD_TIMER_ABSTIME != 0 {
            Some(ticks)
        } else {
            Some(now.saturating_add(ticks))
        }
    };
    let old_value = args[3];
    if old_value != 0 {
        addrspace::validate_user_range(space, old_value, ITIMERSPEC_SIZE as u64, true)
            .map_err(|_| errno::EFAULT)?;
        let (remaining, period) = timerfd::gettime(entry.object).map_err(timerfd_errno)?;
        let mut previous = [0u8; ITIMERSPEC_SIZE];
        previous[0..TIMESPEC_SIZE].copy_from_slice(&encode_timespec_ticks(period));
        previous[TIMESPEC_SIZE..ITIMERSPEC_SIZE].copy_from_slice(&encode_timespec_ticks(remaining));
        addrspace::copy_out(space, old_value, &previous).map_err(|_| errno::EFAULT)?;
    }
    timerfd::settime(entry.object, deadline, interval).map_err(timerfd_errno)?;
    Ok(Outcome::Done(0))
}

/// `timerfd_gettime(287)`.
fn timerfd_gettime(args: &[u64; 6], context: &mut LinuxContext<'_>) -> Result<Outcome, i64> {
    let fd = linux_fd(args[0])?;
    let entry = entry(context, fd)?;
    if object::object_kind(entry.object) != Some(ObjectKind::TimerFd) {
        return Err(errno::EINVAL);
    }
    let out = args[1];
    if out == 0 {
        return Err(errno::EFAULT);
    }
    let space = context.space()?;
    addrspace::validate_user_range(space, out, ITIMERSPEC_SIZE as u64, true)
        .map_err(|_| errno::EFAULT)?;
    let (remaining, period) = timerfd::gettime(entry.object).map_err(timerfd_errno)?;
    let mut raw = [0u8; ITIMERSPEC_SIZE];
    raw[0..TIMESPEC_SIZE].copy_from_slice(&encode_timespec_ticks(period));
    raw[TIMESPEC_SIZE..ITIMERSPEC_SIZE].copy_from_slice(&encode_timespec_ticks(remaining));
    addrspace::copy_out(space, out, &raw).map_err(|_| errno::EFAULT)?;
    Ok(Outcome::Done(0))
}

/// `timerfd` read: eight-byte expiration count.
fn timerfd_read(
    context: &LinuxContext<'_>,
    entry: &FdEntry,
    buffer: u64,
    length: usize,
) -> Result<Outcome, i64> {
    if length < 8 {
        return Err(errno::EINVAL);
    }
    let space = context.space()?;
    addrspace::validate_user_range(space, buffer, 8, true).map_err(|_| errno::EFAULT)?;
    match timerfd::read(entry.object) {
        Ok(count) => {
            addrspace::copy_out(space, buffer, &count.to_le_bytes()).map_err(|_| errno::EFAULT)?;
            Ok(Outcome::Done(8))
        }
        Err(timerfd::TimerFdError::WouldBlock) => {
            if timerfd::nonblocking(entry.object).unwrap_or(false) {
                Err(errno::EAGAIN)
            } else {
                Ok(Outcome::Wait {
                    object: entry.object,
                    deadline: None,
                })
            }
        }
        Err(error) => Err(timerfd_errno(error)),
    }
}

/// `signalfd(282)` / `signalfd4(289)`.
fn signalfd_create(
    args: &[u64; 6],
    context: &mut LinuxContext<'_>,
    version_four: bool,
) -> Result<Outcome, i64> {
    let raw_fd = args[0] as u32 as i32;
    let flags = if version_four {
        u32::try_from(args[3]).map_err(|_| errno::EINVAL)?
    } else {
        0
    };
    if flags & !SFD_FLAG_MASK != 0 {
        return Err(errno::EINVAL);
    }
    if args[2] != signal::SIGSET_SIZE {
        return Err(errno::EINVAL);
    }
    if args[1] == 0 {
        return Err(errno::EFAULT);
    }
    let space = context.space()?;
    addrspace::validate_user_range(space, args[1], 8, false).map_err(|_| errno::EFAULT)?;
    let mut mask_raw = [0u8; 8];
    addrspace::copy_in(space, args[1], &mut mask_raw).map_err(|_| errno::EFAULT)?;
    let mask = u64::from_le_bytes(mask_raw);

    if raw_fd >= 0 {
        let entry = entry(context, raw_fd as u32)?;
        if object::object_kind(entry.object) != Some(ObjectKind::SignalFd) {
            return Err(errno::EINVAL);
        }
        signalfd::update_mask(entry.object, mask).map_err(signalfd_errno)?;
        return Ok(Outcome::Done(i64::from(raw_fd)));
    }
    if raw_fd != -1 {
        return Err(errno::EINVAL);
    }
    let owner = process::current().ok_or(errno::ESRCH)?;
    let cloexec = flags & SFD_CLOEXEC != 0;
    let payload = signalfd::create(owner, mask, flags).map_err(signalfd_errno)?;
    install_kind_object(
        context,
        ObjectKind::SignalFd,
        payload,
        cloexec,
        |payload, object| signalfd::bind(payload, object).is_ok(),
    )
}

/// `signalfd` read: one 128-byte `signalfd_siginfo`.
fn signalfd_read(
    context: &LinuxContext<'_>,
    entry: &FdEntry,
    buffer: u64,
    length: usize,
) -> Result<Outcome, i64> {
    if length < SIGNALFD_SIGINFO_SIZE {
        return Err(errno::EINVAL);
    }
    let space = context.space()?;
    addrspace::validate_user_range(space, buffer, SIGNALFD_SIGINFO_SIZE as u64, true)
        .map_err(|_| errno::EFAULT)?;
    match signalfd::read(entry.object) {
        Ok(record) => {
            let mut raw = [0u8; SIGNALFD_SIGINFO_SIZE];
            raw[0..4].copy_from_slice(&record.signo.to_le_bytes());
            // ssi_errno (offset 4) and ssi_code (offset 8) stay zero: the
            // kernel pending bitmap carries no code information.
            raw[12..16].copy_from_slice(&record.sender_pid.to_le_bytes());
            addrspace::copy_out(space, buffer, &raw).map_err(|_| errno::EFAULT)?;
            Ok(Outcome::Done(SIGNALFD_SIGINFO_SIZE as i64))
        }
        Err(signalfd::SignalFdError::WouldBlock) => {
            if signalfd::nonblocking(entry.object).unwrap_or(false) {
                Err(errno::EAGAIN)
            } else {
                Ok(Outcome::Wait {
                    object: entry.object,
                    deadline: None,
                })
            }
        }
        Err(error) => Err(signalfd_errno(error)),
    }
}

/// `epoll_create(213)` / `epoll_create1(291)`.
fn epoll_create(
    args: &[u64; 6],
    context: &mut LinuxContext<'_>,
    version_one: bool,
) -> Result<Outcome, i64> {
    let flags = u32::try_from(args[0]).map_err(|_| errno::EINVAL)?;
    if version_one {
        // The legacy entry takes a positive `size` hint and ignores it.
        if (args[0] as i64) <= 0 {
            return Err(errno::EINVAL);
        }
    } else if flags & !EPOLL_CLOEXEC != 0 {
        return Err(errno::EINVAL);
    }
    let cloexec = !version_one && flags & EPOLL_CLOEXEC != 0;
    let payload = epoll::create().map_err(epoll_errno)?;
    install_kind_object(
        context,
        ObjectKind::Epoll,
        payload,
        cloexec,
        |payload, object| epoll::bind(payload, object).is_ok(),
    )
}

/// `epoll_ctl(233)`.
fn epoll_ctl(args: &[u64; 6], context: &mut LinuxContext<'_>) -> Result<Outcome, i64> {
    let epfd = linux_fd(args[0])?;
    let ep_entry = entry(context, epfd)?;
    if object::object_kind(ep_entry.object) != Some(ObjectKind::Epoll) {
        return Err(errno::EINVAL);
    }
    let operation = args[1];
    if !matches!(operation, EPOLL_CTL_ADD | EPOLL_CTL_DEL | EPOLL_CTL_MOD) {
        return Err(errno::EINVAL);
    }
    let target_fd = linux_fd(args[2])?;
    let target_entry = entry(context, target_fd)?;
    if target_entry.object == ep_entry.object {
        return Err(errno::EINVAL);
    }
    if !matches!(
        object::object_kind(target_entry.object),
        Some(ObjectKind::Socket)
            | Some(ObjectKind::EventFd)
            | Some(ObjectKind::TimerFd)
            | Some(ObjectKind::SignalFd)
    ) {
        return Err(errno::EINVAL);
    }
    if operation == EPOLL_CTL_DEL {
        epoll::ctl_del(ep_entry.object, target_entry.object).map_err(epoll_errno)?;
        return Ok(Outcome::Done(0));
    }
    if args[3] == 0 {
        return Err(errno::EFAULT);
    }
    let space = context.space()?;
    addrspace::validate_user_range(space, args[3], EPOLL_EVENT_SIZE as u64, false)
        .map_err(|_| errno::EFAULT)?;
    let mut raw = [0u8; EPOLL_EVENT_SIZE];
    addrspace::copy_in(space, args[3], &mut raw).map_err(|_| errno::EFAULT)?;
    let events = u32::from_le_bytes(raw[0..4].try_into().unwrap());
    let data = u64::from_le_bytes(raw[4..12].try_into().unwrap());
    let events = epoll_interest_events(events)?;
    match operation {
        EPOLL_CTL_ADD => epoll::ctl_add(ep_entry.object, target_entry.object, events, data),
        EPOLL_CTL_MOD => epoll::ctl_mod(ep_entry.object, target_entry.object, events, data),
        _ => Err(epoll::EpollError::BadValue),
    }
    .map_err(epoll_errno)?;
    Ok(Outcome::Done(0))
}

/// Validate the interest mask of one `epoll` registration.
///
/// M9b accepts both level-triggered and edge-triggered interests: the edge
/// state lives in the kernel epoll table (`EpollInterest::observed`), so
/// `EPOLLET` is just a flag here. `EPOLLONESHOT` is still refused (its disarm
/// step is not wired yet), as are bits the front-end does not understand.
/// `EPOLLERR`/`EPOLLHUP` are accepted because Linux reports them whether or not
/// they were requested.
fn epoll_interest_events(events: u32) -> Result<u32, i64> {
    if events & !EPOLL_INTEREST_BITS != 0 || events & EPOLLONESHOT != 0 {
        return Err(errno::EINVAL);
    }
    Ok(events)
}

/// Readiness probe for [`epoll::scan_with`]: raw `epoll` bits for one target.
///
/// Sockets are the only kind whose readiness lives in the network engine, so
/// they are mapped through `net::poll`; everything else uses the IPC layer's
/// own readiness helper.
fn epoll_probe(target: ObjectId) -> u32 {
    match object::object_kind(target) {
        Some(ObjectKind::Socket) => {
            let payload = match object::payload(target) {
                Some(payload) => payload,
                None => return EPOLLERR,
            };
            let raw = payload as u32;
            let id = SocketId::new((raw >> 16) as usize, raw as u16);
            match net::poll(id) {
                Ok(mask) => {
                    let mut ready = 0u32;
                    if mask.contains(net::PollMask::READ) {
                        ready |= EPOLLIN;
                    }
                    if mask.contains(net::PollMask::WRITE) {
                        ready |= EPOLLOUT;
                    }
                    if mask.contains(net::PollMask::ERROR) {
                        ready |= EPOLLERR;
                    }
                    ready
                }
                Err(_) => EPOLLERR,
            }
        }
        Some(_) => epoll::target_readiness(target),
        None => EPOLLERR,
    }
}

/// `epoll_wait(232)` / `epoll_pwait(281)`.
fn epoll_wait(
    args: &[u64; 6],
    context: &mut LinuxContext<'_>,
    pwait: bool,
) -> Result<Outcome, i64> {
    let epfd = linux_fd(args[0])?;
    let entry = entry(context, epfd)?;
    if object::object_kind(entry.object) != Some(ObjectKind::Epoll) {
        return Err(errno::EINVAL);
    }
    let maxevents = usize::try_from(args[2]).map_err(|_| errno::EINVAL)?;
    if maxevents == 0 || maxevents > MAX_EPOLL_EVENTS {
        return Err(errno::EINVAL);
    }
    if args[1] == 0 {
        return Err(errno::EFAULT);
    }
    let space = context.space()?;
    addrspace::validate_user_range(space, args[1], (maxevents * EPOLL_EVENT_SIZE) as u64, true)
        .map_err(|_| errno::EFAULT)?;
    if pwait && args[4] != 0 && args[5] != signal::SIGSET_SIZE {
        return Err(errno::EINVAL);
    }
    let timeout = args[3] as u32 as i32;
    let hz = crate::time::tick_hz();
    let now = crate::time::monotonic_ticks();
    let requested_deadline = poll_ms_deadline(now, hz, timeout)?;

    // A replay consumes the wake reason; a timeout is a normal empty return.
    let reason = process::take_wake_reason();
    match reason {
        process::WakeReason::Timeout => return Ok(Outcome::Done(0)),
        process::WakeReason::Cancelled => return Ok(Outcome::Done(-errno::EINTR)),
        process::WakeReason::Destroyed => return Err(errno::EBADF),
        _ => {}
    }
    let deadline = if reason.is_some() {
        process::wait_deadline().or(requested_deadline)
    } else {
        requested_deadline
    };

    let empty = epoll::ReadyEvent {
        target: 0,
        data: 0,
        events: 0,
    };
    let mut ready_events = [empty; MAX_EPOLL_EVENTS];
    let count = epoll::scan_with(entry.object, &mut ready_events[..maxevents], epoll_probe)
        .map_err(epoll_errno)?;
    let mut raw = [0u8; MAX_EPOLL_EVENTS * EPOLL_EVENT_SIZE];
    for (index, event) in ready_events[..count].iter().enumerate() {
        let start = index * EPOLL_EVENT_SIZE;
        raw[start..start + 4].copy_from_slice(&event.events.to_le_bytes());
        raw[start + 4..start + EPOLL_EVENT_SIZE].copy_from_slice(&event.data.to_le_bytes());
    }
    if count > 0 {
        addrspace::copy_out(space, args[1], &raw[..count * EPOLL_EVENT_SIZE])
            .map_err(|_| errno::EFAULT)?;
        return Ok(Outcome::Done(count as i64));
    }
    if deadline.map(|target| target <= now).unwrap_or(false) {
        return Ok(Outcome::Done(0));
    }
    let objects = [entry.object; MAX_POLL_WAIT];
    let keys = [process::WAIT_ANY_KEY; MAX_POLL_WAIT];
    Ok(Outcome::PollWait {
        objects,
        keys,
        count: 1,
        deadline,
    })
}

// ---------------------------------------------------------------------------
// memory: brk / mmap / munmap / mprotect
// ---------------------------------------------------------------------------

/// The live user address space of the caller.
///
/// Host tests dispatch without an address space; the planners then reject every
/// request that would need real mappings instead of pretending to map.
fn kernel_space(context: &LinuxContext<'_>) -> Option<KernelSpace> {
    context.address_space.map(KernelSpace::new)
}

fn memory_brk(args: &[u64; 6], context: &mut LinuxContext<'_>) -> Result<Outcome, i64> {
    let mut space = kernel_space(context);
    let result = memory::syscall_brk(
        &mut context.fds.memory,
        args[0],
        space
            .as_mut()
            .map(|space| space as &mut dyn memory::AddressSpaceOps),
    )?;
    Ok(Outcome::Done(result))
}

fn memory_mmap(args: &[u64; 6], context: &mut LinuxContext<'_>) -> Result<Outcome, i64> {
    if args[3] & memory::MAP_ANONYMOUS == 0 {
        return memory_mmap_file(args, context);
    }
    let mut space = kernel_space(context);
    let result = memory::syscall_mmap(
        &mut context.fds.memory,
        args,
        space
            .as_mut()
            .map(|space| space as &mut dyn memory::AddressSpaceOps),
    )?;
    Ok(Outcome::Done(result))
}

/// M10a: `mmap(fd, ...)` — private pages populated from the file at map time
/// (no page cache yet); writes stay in the frame, which is `MAP_PRIVATE`
/// semantics. `MAP_FIXED` is honoured for the dynamic loader's segment
/// placement.
fn memory_mmap_file(args: &[u64; 6], context: &mut LinuxContext<'_>) -> Result<Outcome, i64> {
    let prot = u32::try_from(args[2]).map_err(|_| errno::EINVAL)?;
    let plan = memory::mmap_file_plan(
        &context.fds.memory,
        args[0],
        args[1],
        prot,
        args[3],
        args[4],
        args[5],
    )?;
    let fd = linux_fd(args[4])?;
    let entry = entry(context, fd)?;
    if object::object_kind(entry.object) != Some(ObjectKind::File) {
        return Err(errno::EBADF);
    }
    let open = file_open_of(entry.object)?;
    let mut space = kernel_space(context);
    let Some(space) = space.as_mut() else {
        return Err(errno::EINVAL);
    };
    let base = args[5];
    memory::map_file_pages(
        space,
        plan.addr,
        plan.len,
        plan.writable,
        plan.executable,
        |index, page| {
            crate::vfs::seek(open, base.saturating_add(index * memory::PAGE_SIZE))
                .map_err(vfs_errno)?;
            let mut filled = 0;
            while filled < page.len() {
                match crate::vfs::read(open, &mut page[filled..]) {
                    Ok(0) => break,
                    Ok(read) => filled += read,
                    Err(_) => break,
                }
            }
            Ok(())
        },
    )?;
    context.fds.memory.commit_mmap(plan.addr, plan.len);
    Ok(Outcome::Done(plan.addr as i64))
}

fn memory_munmap(args: &[u64; 6], context: &mut LinuxContext<'_>) -> Result<Outcome, i64> {
    let mut space = kernel_space(context);
    let result = memory::syscall_munmap(
        args[0],
        args[1],
        space
            .as_mut()
            .map(|space| space as &mut dyn memory::AddressSpaceOps),
    )?;
    Ok(Outcome::Done(result))
}

fn memory_mprotect(args: &[u64; 6], context: &mut LinuxContext<'_>) -> Result<Outcome, i64> {
    let mut space = kernel_space(context);
    let result = memory::syscall_mprotect(
        args[0],
        args[1],
        args[2],
        space
            .as_mut()
            .map(|space| space as &mut dyn memory::AddressSpaceOps),
    )?;
    Ok(Outcome::Done(result))
}

// ---------------------------------------------------------------------------
// socket / bind / connect / listen / accept / socketpair
// ---------------------------------------------------------------------------

fn domain_kind(domain: u64, kinds: u64) -> Result<(u32, u16, u32, bool), i64> {
    let domain = u32::try_from(domain).map_err(|_| errno::EAFNOSUPPORT)?;
    let family = u16::try_from(domain).map_err(|_| errno::EAFNOSUPPORT)?;
    let mapped = address::domain_for_family(family).ok_or(errno::EAFNOSUPPORT)?;
    let raw = u32::try_from(kinds).map_err(|_| errno::EINVAL)?;
    let cloexec = raw & SOCK_CLOEXEC != 0;
    let nonblock = raw & SOCK_NONBLOCK != 0;
    // The personality has no non-blocking descriptor flag yet; refusing is
    // honest, silently accepting would break every later read.
    if nonblock {
        return Err(errno::EINVAL);
    }
    let kind = raw & !(SOCK_CLOEXEC | SOCK_NONBLOCK);
    let kind = match kind {
        SOCK_STREAM => net::SOCK_STREAM,
        SOCK_DGRAM => net::SOCK_DGRAM,
        _ => return Err(errno::EPROTONOSUPPORT),
    };
    Ok((mapped, family, kind, cloexec))
}

fn socket(args: &[u64; 6], context: &mut LinuxContext<'_>) -> Result<Outcome, i64> {
    let (domain, family, kind, cloexec) = domain_kind(args[0], args[1])?;
    let protocol = args[2];
    if protocol != 0 {
        return Err(errno::EPROTONOSUPPORT);
    }
    let id = net::create(domain, kind).map_err(net_errno)?;
    if let Err(error) = stamp_credential(id) {
        let _ = net::destroy(id);
        return Err(error);
    }
    let fd = install_socket(context, id, cloexec, family)?;
    Ok(Outcome::Done(i64::from(fd)))
}

fn bind(args: &[u64; 6], context: &mut LinuxContext<'_>) -> Result<Outcome, i64> {
    let fd = linux_fd(args[0])?;
    let id = socket_of(context, fd)?;
    let address = read_sockaddr(context, args[1], args[2])?;
    let namespace = namespace_for(context, address.family)?;
    net::bind(id, namespace, address).map_err(net_errno)?;
    Ok(Outcome::Done(0))
}

fn connect(args: &[u64; 6], context: &mut LinuxContext<'_>) -> Result<Outcome, i64> {
    let fd = linux_fd(args[0])?;
    let id = socket_of(context, fd)?;
    let address = read_sockaddr(context, args[1], args[2])?;
    let namespace = namespace_for(context, address.family)?;
    net::connect(id, namespace, address).map_err(net_errno)?;
    Ok(Outcome::Done(0))
}

/// UNIX named addresses need the process network namespace; INET does not.
///
/// The native M7b layer passes a namespace object only for UNIX addresses and
/// `0` for INET/INET6, and the engine relies on that split: an INET socket must
/// not be associated with a path-namespace object.
fn namespace_for(context: &LinuxContext<'_>, family: u32) -> Result<ObjectId, i64> {
    if family == net::DOMAIN_UNIX {
        if context.netns == 0 {
            return Err(errno::EAFNOSUPPORT);
        }
        Ok(context.netns)
    } else {
        Ok(0)
    }
}

fn listen(args: &[u64; 6], context: &mut LinuxContext<'_>) -> Result<Outcome, i64> {
    let fd = linux_fd(args[0])?;
    let id = socket_of(context, fd)?;
    let backlog = u32::try_from(args[1]).unwrap_or(u32::MAX);
    net::listen(id, backlog).map_err(net_errno)?;
    Ok(Outcome::Done(0))
}

fn accept(args: &[u64; 6], context: &mut LinuxContext<'_>, flags: u64) -> Result<Outcome, i64> {
    let fd = linux_fd(args[0])?;
    let listener = socket_of(context, fd)?;
    let raw_flags = u32::try_from(flags).map_err(|_| errno::EINVAL)?;
    if raw_flags & !SOCK_CLOEXEC != 0 {
        return Err(errno::EINVAL);
    }
    let cloexec = raw_flags & SOCK_CLOEXEC != 0;
    let family = socket_family(context, fd)?;
    match net::accept(listener) {
        Ok(accepted) => {
            if let Err(error) = stamp_credential(accepted) {
                let _ = net::destroy(accepted);
                return Err(error);
            }
            let installed = install_socket(context, accepted, cloexec, family)?;
            if args[1] != 0 {
                // The caller supplied a peer-address buffer; a failure here must
                // not leave the accepted descriptor installed (it would leak the
                // fd entry and the engine socket).
                close_on_failure(
                    context,
                    installed,
                    write_peer_address(context, accepted, args[1], args[2]),
                )?;
            }
            Ok(Outcome::Done(i64::from(installed)))
        }
        Err(NetError::WouldBlock) => Ok(Outcome::Wait {
            object: socket_object(listener)?,
            deadline: None,
        }),
        Err(error) => Err(net_errno(error)),
    }
}

fn socketpair(args: &[u64; 6], context: &mut LinuxContext<'_>) -> Result<Outcome, i64> {
    let (domain, family, kind, cloexec) = domain_kind(args[0], args[1])?;
    if args[2] != 0 {
        return Err(errno::EPROTONOSUPPORT);
    }
    if args[3] == 0 {
        return Err(errno::EFAULT);
    }
    let (first, second) = net::socket_pair(domain, kind).map_err(net_errno)?;
    if let Err(error) = stamp_credential(first).and_then(|()| stamp_credential(second)) {
        let _ = net::destroy(first);
        let _ = net::destroy(second);
        return Err(error);
    }
    let first_fd = match install_socket(context, first, cloexec, family) {
        Ok(fd) => fd,
        Err(error) => {
            let _ = net::destroy(second);
            return Err(error);
        }
    };
    let second_fd = match install_socket(context, second, cloexec, family) {
        Ok(fd) => fd,
        Err(error) => {
            context.fds.close(first_fd).ok();
            return Err(error);
        }
    };
    let mut pair = [0u8; 8];
    pair[..4].copy_from_slice(&first_fd.to_le_bytes());
    pair[4..].copy_from_slice(&second_fd.to_le_bytes());
    if copy_out(context, args[3], &pair).is_err() {
        context.fds.close(first_fd).ok();
        context.fds.close(second_fd).ok();
        return Err(errno::EFAULT);
    }
    Ok(Outcome::Done(0))
}

// ---------------------------------------------------------------------------
// send / recv
// ---------------------------------------------------------------------------

/// Copy the payload out of user memory and run the engine send.
///
/// The copy-out error stays a Linux errno; the engine result is returned as-is
/// so the caller can turn `WouldBlock` into a blocking wait.
fn send_from_user(
    context: &LinuxContext<'_>,
    id: SocketId,
    pointer: u64,
    length: usize,
) -> Result<Result<usize, NetError>, i64> {
    let chunk = length.min(MAX_IO);
    let mut data = [0u8; MAX_IO];
    copy_in(context, pointer, &mut data[..chunk])?;
    Ok(net::send(id, &data[..chunk]))
}

/// Turn an engine send result into the Linux outcome.
///
/// This stage has no `O_NONBLOCK` descriptor state, so `WouldBlock` must block
/// until the socket becomes writable again — exactly like `recv`/`accept`, the
/// call reports the waitable object and the entry replays it after the wake.
/// The object is resolved by the caller so the mapping stays testable without
/// the network engine.
fn send_outcome(
    sent: Result<usize, NetError>,
    wait_object: Option<ObjectId>,
) -> Result<Outcome, i64> {
    match sent {
        Ok(count) => Ok(Outcome::Done(count as i64)),
        Err(NetError::WouldBlock) => match wait_object {
            Some(object) => Ok(Outcome::Wait {
                object,
                deadline: None,
            }),
            None => Err(errno::EBADF),
        },
        Err(error) => Err(net_errno(error)),
    }
}

fn sendto(args: &[u64; 6], context: &mut LinuxContext<'_>) -> Result<Outcome, i64> {
    let fd = linux_fd(args[0])?;
    let id = socket_of(context, fd)?;
    let length = usize::try_from(args[2]).map_err(|_| errno::EINVAL)?;
    if args[3] != 0 {
        // `sendto` flags are not implemented; accepting them would change
        // semantics silently.
        return Err(errno::EOPNOTSUPP);
    }
    if args[4] != 0 {
        // Only connected sockets are bridged to the engine today. Reporting
        // that honestly beats pretending the datagram was addressed.
        return Err(errno::EOPNOTSUPP);
    }
    let sent = send_from_user(context, id, args[1], length)?;
    send_outcome(sent, socket_object(id).ok())
}

/// Counts engine receives in host tests so the userspace pre-check can be shown
/// to run **before** the engine consumes a message.
#[cfg(test)]
pub(crate) mod net_recv_probe {
    use core::sync::atomic::{AtomicUsize, Ordering};

    static CALLS: AtomicUsize = AtomicUsize::new(0);

    /// Record one engine receive.
    pub fn record() {
        CALLS.fetch_add(1, Ordering::Relaxed);
    }

    /// Number of engine receives since the last [`reset`].
    pub fn count() -> usize {
        CALLS.load(Ordering::Relaxed)
    }

    /// Reset the counter. Tests that use it run under the object-table lock.
    pub fn reset() {
        CALLS.store(0, Ordering::Relaxed);
    }
}

/// Engine receive wrapper: the probe is recorded here so the pre-check ordering
/// stays observable without the network engine in host tests.
fn receive_from_engine(id: SocketId, out: &mut [u8]) -> Result<net::Received, NetError> {
    #[cfg(test)]
    net_recv_probe::record();
    net::recv(id, out)
}

/// Validate every userspace range a receive will write **before** the engine
/// consumes anything.
///
/// Linux `read`/`recvfrom` must leave the message queued when the destination
/// is invalid: an `EFAULT` after `net::recv` would silently drop stream bytes or
/// a whole datagram. The destination buffer, the optional source address and
/// its `socklen_t` are therefore all checked first; `Ok(0)` means a zero-length
/// receive, which Linux completes without touching any pointer.
fn receive_precheck(
    context: &LinuxContext<'_>,
    buffer: u64,
    length: usize,
    source_pointer: u64,
    source_length_pointer: u64,
) -> Result<usize, i64> {
    if length == 0 {
        return Ok(0);
    }
    let space = context.space()?;
    let chunk = length.min(MAX_IO);
    if buffer == 0 {
        return Err(errno::EFAULT);
    }
    addrspace::validate_user_range(space, buffer, chunk as u64, true).map_err(|_| errno::EFAULT)?;
    if source_pointer != 0 {
        if source_length_pointer == 0 {
            return Err(errno::EFAULT);
        }
        let capacity = read_u32(context, source_length_pointer)? as usize;
        let wire = capacity.min(address::SOCKADDR_MAX);
        if wire > 0 {
            addrspace::validate_user_range(space, source_pointer, wire as u64, true)
                .map_err(|_| errno::EFAULT)?;
        }
        addrspace::validate_user_range(space, source_length_pointer, 4, true)
            .map_err(|_| errno::EFAULT)?;
    }
    Ok(chunk)
}

fn receive_into(
    context: &mut LinuxContext<'_>,
    id: SocketId,
    buffer: u64,
    length: usize,
    source_pointer: u64,
    source_length_pointer: u64,
) -> Result<Outcome, i64> {
    let chunk = receive_precheck(
        context,
        buffer,
        length,
        source_pointer,
        source_length_pointer,
    )?;
    if chunk == 0 {
        return Ok(Outcome::Done(0));
    }
    let mut data = [0u8; MAX_IO];
    match receive_from_engine(id, &mut data[..chunk]) {
        Ok(received) => {
            copy_out(context, buffer, &data[..received.len])?;
            if source_pointer != 0 {
                let capacity = read_u32(context, source_length_pointer)? as usize;
                if let Some(source) = received.source {
                    let mut raw = [0u8; address::SOCKADDR_MAX];
                    let real =
                        address::write(&source, &mut raw[..capacity.min(address::SOCKADDR_MAX)])?;
                    copy_out(context, source_pointer, &raw[..real])?;
                    write_u32(context, source_length_pointer, real as u32)?;
                } else {
                    write_u32(context, source_length_pointer, 0)?;
                }
            }
            Ok(Outcome::Done(received.len as i64))
        }
        Err(NetError::WouldBlock) => Ok(Outcome::Wait {
            object: socket_object(id)?,
            deadline: None,
        }),
        // `recv` reports end-of-stream as zero bytes, not as a connection
        // error, so a closed peer is mapped to the Linux EOF convention.
        Err(NetError::PeerClosed) => Ok(Outcome::Done(0)),
        Err(error) => Err(net_errno(error)),
    }
}

fn recvfrom(args: &[u64; 6], context: &mut LinuxContext<'_>) -> Result<Outcome, i64> {
    let fd = linux_fd(args[0])?;
    let id = socket_of(context, fd)?;
    let length = usize::try_from(args[2]).map_err(|_| errno::EINVAL)?;
    if args[3] != 0 {
        return Err(errno::EOPNOTSUPP);
    }
    receive_into(context, id, args[1], length, args[4], args[5])
}

// ---------------------------------------------------------------------------
// sendmsg / recvmsg (M9b)
// ---------------------------------------------------------------------------

/// Release the object references a failed `send_msg` leaves with the caller.
///
/// The engine's `send_msg` contract is: `Ok` transfers every reference to the
/// queue, `Err` consumes nothing, so this helper is only called on failure.
fn release_objects(objects: &[ObjectId]) {
    for object in objects {
        let _ = object::release_object(*object);
    }
}

/// Copy the iovec payload of a `sendmsg` request into the bounce buffer.
fn gather_send_payload(
    context: &LinuxContext<'_>,
    header: &msg::MsgHdr,
) -> Result<([u8; msg::MSG_IO_MAX], usize), i64> {
    let count = msg::check_iovlen(header.iovlen)?;
    let mut buffer = [0u8; msg::MSG_IO_MAX];
    if count == 0 {
        return Ok((buffer, 0));
    }
    if header.iov == 0 {
        return Err(errno::EFAULT);
    }
    let space = context.space()?;
    let mut total = 0u64;
    let mut cursor = 0usize;
    let mut index = 0usize;
    while index < count {
        let pointer = header.iov + (index * msg::IOVEC_SIZE) as u64;
        let mut raw = [0u8; msg::IOVEC_SIZE];
        addrspace::copy_in(space, pointer, &mut raw).map_err(|_| errno::EFAULT)?;
        let (base, length) = msg::decode_iovec(&raw)?;
        msg::accumulate_iov(&mut total, length)?;
        if total > msg::MSG_IO_MAX as u64 {
            // The personality bridges at most one bounce buffer per call.
            return Err(errno::EMSGSIZE);
        }
        let chunk = length as usize;
        if chunk > 0 {
            if base == 0 {
                return Err(errno::EFAULT);
            }
            addrspace::validate_user_range(space, base, length, false)
                .map_err(|_| errno::EFAULT)?;
            addrspace::copy_in(space, base, &mut buffer[cursor..cursor + chunk])
                .map_err(|_| errno::EFAULT)?;
            cursor += chunk;
        }
        index += 1;
    }
    Ok((buffer, cursor))
}

/// Parse the send-side control buffer: `SCM_RIGHTS` descriptors and
/// `SCM_CREDENTIALS`.
///
/// Every transferred descriptor is acquired here (the engine needs a held
/// reference); on any error the references taken so far are released before
/// returning, because the engine was never called.
fn parse_send_control(
    context: &LinuxContext<'_>,
    header: &msg::MsgHdr,
    objects: &mut [ObjectId; msg::SCM_MAX_FD],
    object_count: &mut usize,
) -> Result<Option<net::Credential>, i64> {
    if header.control == 0 || header.controllen == 0 {
        return Ok(None);
    }
    let capacity = usize::try_from(header.controllen).map_err(|_| errno::EINVAL)?;
    let capacity = capacity.min(msg::MSG_CONTROL_MAX);
    let mut control = [0u8; msg::MSG_CONTROL_MAX];
    copy_in(context, header.control, &mut control[..capacity])?;
    let mut iterator = msg::CmsgIter::new(&control[..capacity]);
    let mut credential = None;
    loop {
        match iterator.next() {
            Ok(None) => break,
            Ok(Some(cmsg)) => match (cmsg.level, cmsg.kind) {
                (msg::SOL_SOCKET, msg::SCM_RIGHTS) => {
                    let mut fds = [0i32; msg::SCM_MAX_FD];
                    let count = match msg::parse_scm_rights(cmsg.data, &mut fds) {
                        Ok(count) => count,
                        Err(error) => {
                            release_objects(&objects[..*object_count]);
                            return Err(error);
                        }
                    };
                    if *object_count + count > msg::SCM_MAX_FD {
                        release_objects(&objects[..*object_count]);
                        return Err(errno::EMSGSIZE);
                    }
                    for raw_fd in &fds[..count] {
                        if *raw_fd < 0 {
                            release_objects(&objects[..*object_count]);
                            return Err(errno::EBADF);
                        }
                        let source = match entry(context, *raw_fd as u32) {
                            Ok(entry) => entry.object,
                            Err(_) => {
                                release_objects(&objects[..*object_count]);
                                return Err(errno::EBADF);
                            }
                        };
                        if object::acquire_object(source).is_err() {
                            release_objects(&objects[..*object_count]);
                            return Err(errno::EBADF);
                        }
                        objects[*object_count] = source;
                        *object_count += 1;
                    }
                }
                (msg::SOL_SOCKET, msg::SCM_CREDENTIALS) => {
                    let sender = match msg::parse_ucred(cmsg.data) {
                        Ok(sender) => sender,
                        Err(error) => {
                            release_objects(&objects[..*object_count]);
                            return Err(error);
                        }
                    };
                    let pid = process::current_linux_pid().unwrap_or(0) as i32;
                    if (sender.pid != 0 && sender.pid != pid) || sender.uid != 0 || sender.gid != 0
                    {
                        release_objects(&objects[..*object_count]);
                        return Err(errno::EPERM);
                    }
                    credential = Some(net::Credential::new(sender.pid.max(0) as u32, 0, 0));
                }
                // Unknown control messages are ignored, as Linux does.
                _ => {}
            },
            Err(error) => {
                release_objects(&objects[..*object_count]);
                return Err(error);
            }
        }
    }
    Ok(credential)
}

/// Credential the engine must attach to a sent message.
///
/// Linux attaches the **sending process' real credentials** to every message
/// travelling over an `AF_UNIX` socket, whether or not the program supplied an
/// `SCM_CREDENTIALS` control message; the receiving side decides through
/// `SO_PASSCRED` whether those credentials become a control message. INET and
/// INET6 sockets carry no credential at all.
///
/// An explicit `SCM_CREDENTIALS` whose pid is `0` means "the sending process";
/// `parse_send_control` already rejected a forged pid, so filling in `pid` here
/// keeps the Linux convention without widening what a sender may claim.
fn send_credential(
    domain: u16,
    explicit: Option<net::Credential>,
    pid: u32,
) -> Option<net::Credential> {
    match (domain, explicit) {
        (address::AF_UNIX, None) => Some(net::Credential::new(pid, 0, 0)),
        (_, Some(credential)) => {
            let pid = if credential.pid == 0 {
                pid
            } else {
                credential.pid
            };
            Some(net::Credential::new(pid, credential.uid, credential.gid))
        }
        (_, None) => None,
    }
}

/// `sendmsg(46)`.
fn sendmsg(args: &[u64; 6], context: &mut LinuxContext<'_>) -> Result<Outcome, i64> {
    let fd = linux_fd(args[0])?;
    let id = socket_of(context, fd)?;
    if args[1] == 0 {
        return Err(errno::EFAULT);
    }
    let mut raw = [0u8; msg::MSGHDR_SIZE];
    copy_in(context, args[1], &mut raw)?;
    let header = msg::decode_msghdr(&raw)?;
    msg::check_send_flags(header.flags)?;
    if header.name != 0 && header.namelen != 0 {
        // A datagram destination address is not bridged to the engine yet;
        // reporting it honestly beats sending to the connected peer instead.
        return Err(errno::EOPNOTSUPP);
    }
    let (payload, payload_len) = gather_send_payload(context, &header)?;
    let mut objects = [0u16; msg::SCM_MAX_FD];
    let mut object_count = 0usize;
    let mut credential = parse_send_control(context, &header, &mut objects, &mut object_count)?;
    // Fill in the sender credential the engine has to carry for UNIX sockets
    // even when the program sent no control data at all.
    let domain = entry(context, fd)?.domain;
    let pid = process::current_linux_pid().unwrap_or(0) as u32;
    credential = send_credential(domain, credential, pid);
    match net::send_msg(
        id,
        &payload[..payload_len],
        &objects[..object_count],
        credential,
    ) {
        Ok(sent) => Ok(Outcome::Done(sent as i64)),
        Err(NetError::WouldBlock) => {
            release_objects(&objects[..object_count]);
            Ok(Outcome::Wait {
                object: socket_object(id)?,
                deadline: None,
            })
        }
        Err(error) => {
            release_objects(&objects[..object_count]);
            Err(net_errno(error))
        }
    }
}

/// The iovec list and total writable capacity of one `recvmsg` request.
struct RecvIovecs {
    entries: [(u64, u64); msg::IOV_MAX_MINI],
    count: usize,
    capacity: usize,
}

/// Validate every userspace range a `recvmsg` will write **before** the engine
/// consumes a message.
fn preflight_recvmsg(context: &LinuxContext<'_>, header: &msg::MsgHdr) -> Result<RecvIovecs, i64> {
    let space = context.space()?;
    let count = msg::check_iovlen(header.iovlen)?;
    let mut entries = [(0u64, 0u64); msg::IOV_MAX_MINI];
    let mut total = 0u64;
    if count > 0 {
        if header.iov == 0 {
            return Err(errno::EFAULT);
        }
        let mut index = 0usize;
        while index < count {
            let pointer = header.iov + (index * msg::IOVEC_SIZE) as u64;
            let mut raw = [0u8; msg::IOVEC_SIZE];
            addrspace::copy_in(space, pointer, &mut raw).map_err(|_| errno::EFAULT)?;
            let (base, length) = msg::decode_iovec(&raw)?;
            msg::accumulate_iov(&mut total, length)?;
            entries[index] = (base, length);
            if length > 0 {
                if base == 0 {
                    return Err(errno::EFAULT);
                }
                let chunk = length.min(msg::MSG_IO_MAX as u64);
                addrspace::validate_user_range(space, base, chunk, true)
                    .map_err(|_| errno::EFAULT)?;
            }
            index += 1;
        }
    }
    if header.name != 0 && header.namelen >= 2 {
        let capacity = u64::from(header.namelen).min(address::SOCKADDR_MAX as u64);
        addrspace::validate_user_range(space, header.name, capacity, true)
            .map_err(|_| errno::EFAULT)?;
    }
    if header.control != 0 && header.controllen != 0 {
        let capacity = header.controllen.min(msg::MSG_CONTROL_MAX as u64);
        addrspace::validate_user_range(space, header.control, capacity, true)
            .map_err(|_| errno::EFAULT)?;
    }
    let capacity = total.min(msg::MSG_IO_MAX as u64) as usize;
    Ok(RecvIovecs {
        entries,
        count,
        capacity,
    })
}

/// Scatter received payload bytes into the iovec list.
fn scatter_payload(
    context: &LinuxContext<'_>,
    iovecs: &RecvIovecs,
    data: &[u8],
) -> Result<usize, i64> {
    let mut written = 0usize;
    let mut index = 0usize;
    while index < iovecs.count && written < data.len() {
        let (base, length) = iovecs.entries[index];
        let room = (length as usize).min(data.len() - written);
        if room > 0 {
            copy_out(context, base, &data[written..written + room])?;
            written += room;
        }
        index += 1;
    }
    Ok(written)
}

/// Install the descriptors transferred by a message.
///
/// The net contract hands one reference per object to the caller. The fd table
/// takes its own reference on insert, so the transferred reference is released
/// right after a successful insert. A failure closes the descriptors already
/// installed and releases every reference that was not installed (including
/// the one that failed).
fn install_received_fds(
    context: &mut LinuxContext<'_>,
    received: &net::ReceivedMessage,
) -> Result<([u32; msg::SCM_MAX_FD], usize), i64> {
    let mut installed = [0u32; msg::SCM_MAX_FD];
    let mut count = 0usize;
    let objects = received.objects;
    let total = received.object_count as usize;
    while count < total {
        match context.fds.insert(FdEntry::new(objects[count], false)) {
            Ok(fd) => {
                installed[count] = fd;
                let _ = object::release_object(objects[count]);
                count += 1;
            }
            Err(_) => {
                let mut index = 0usize;
                while index < count {
                    context.fds.close(installed[index]).ok();
                    index += 1;
                }
                let mut index = count;
                while index < total {
                    let _ = object::release_object(objects[index]);
                    index += 1;
                }
                return Err(errno::EMFILE);
            }
        }
    }
    Ok((installed, count))
}

/// Encode and write the receive-side control buffer.
fn write_recv_control(
    context: &LinuxContext<'_>,
    header: &mut msg::MsgHdr,
    id: SocketId,
    installed: &[u32],
    credential: Option<net::Credential>,
) -> Result<(), i64> {
    let wanted = installed.len()
        + credential
            .filter(|cred| net::passcred(id).unwrap_or(false) && cred.is_set())
            .map(|_| 1)
            .unwrap_or(0);
    if header.control == 0 || header.controllen == 0 {
        if wanted > 0 {
            header.flags |= msg::MSG_CTRUNC;
        }
        return Ok(());
    }
    let capacity = usize::try_from(header.controllen)
        .map_err(|_| errno::EINVAL)?
        .min(msg::MSG_CONTROL_MAX);
    let mut control = [0u8; msg::MSG_CONTROL_MAX];
    let mut cursor = 0usize;
    let mut truncated = false;
    if !installed.is_empty() {
        let mut bytes = [0u8; msg::SCM_MAX_FD * 4];
        let mut index = 0usize;
        while index < installed.len() {
            let start = index * 4;
            bytes[start..start + 4].copy_from_slice(&(installed[index] as i32).to_le_bytes());
            index += 1;
        }
        if !msg::push_cmsg(
            &mut control[..capacity],
            &mut cursor,
            msg::SOL_SOCKET,
            msg::SCM_RIGHTS,
            &bytes[..installed.len() * 4],
        ) {
            truncated = true;
        }
    }
    if let Some(cred) =
        credential.filter(|cred| net::passcred(id).unwrap_or(false) && cred.is_set())
    {
        let ucred = msg::Ucred {
            pid: cred.pid as i32,
            uid: cred.uid,
            gid: cred.gid,
        };
        if !msg::push_cmsg(
            &mut control[..capacity],
            &mut cursor,
            msg::SOL_SOCKET,
            msg::SCM_CREDENTIALS,
            &msg::encode_ucred(&ucred),
        ) {
            truncated = true;
        }
    }
    if cursor > 0 {
        copy_out(context, header.control, &control[..cursor])?;
    }
    header.controllen = cursor as u64;
    if truncated {
        header.flags |= msg::MSG_CTRUNC;
    }
    Ok(())
}

/// Write the received source address back into `msg_name`.
fn write_recv_name(
    context: &LinuxContext<'_>,
    header: &mut msg::MsgHdr,
    source: Option<net::SocketAddress>,
) -> Result<(), i64> {
    if header.name == 0 {
        return Ok(());
    }
    let Some(source) = source else {
        header.namelen = 0;
        return Ok(());
    };
    let capacity = (header.namelen as usize).min(address::SOCKADDR_MAX);
    if capacity < 2 {
        header.namelen = 0;
        return Ok(());
    }
    let mut raw = [0u8; address::SOCKADDR_MAX];
    let real = address::write(&source, &mut raw[..capacity])?;
    copy_out(context, header.name, &raw[..real])?;
    header.namelen = real as u32;
    Ok(())
}

/// Finish a successful `recv_msg`: scatter the payload, install descriptors,
/// encode the control buffer, and write the updated msghdr back.
fn finish_recvmsg(
    context: &mut LinuxContext<'_>,
    id: SocketId,
    header_pointer: u64,
    header: &mut msg::MsgHdr,
    iovecs: &RecvIovecs,
    data: &[u8],
    received: &net::ReceivedMessage,
) -> Result<Outcome, i64> {
    let copied = scatter_payload(context, iovecs, &data[..received.len.min(data.len())])?;
    write_recv_name(context, header, received.source)?;
    let count = received.object_count as usize;
    let (installed, installed_count) = if header.control != 0 && header.controllen != 0 {
        install_received_fds(context, received)?
    } else {
        // No control buffer: Linux discards ancillary data (and closes the
        // transferred descriptors) while reporting `MSG_CTRUNC`.
        let mut index = 0usize;
        while index < count {
            let _ = object::release_object(received.objects[index]);
            index += 1;
        }
        header.flags |= msg::MSG_CTRUNC;
        ([0u32; msg::SCM_MAX_FD], 0usize)
    };
    write_recv_control(
        context,
        header,
        id,
        &installed[..installed_count],
        received.cred,
    )?;
    let raw = msg::encode_msghdr(header);
    copy_out(context, header_pointer, &raw)?;
    Ok(Outcome::Done(copied as i64))
}

/// `recvmsg(47)`.
fn recvmsg(args: &[u64; 6], context: &mut LinuxContext<'_>) -> Result<Outcome, i64> {
    let fd = linux_fd(args[0])?;
    let id = socket_of(context, fd)?;
    if args[1] == 0 {
        return Err(errno::EFAULT);
    }
    let header_pointer = args[1];
    let mut raw = [0u8; msg::MSGHDR_SIZE];
    copy_in(context, header_pointer, &mut raw)?;
    let mut header = msg::decode_msghdr(&raw)?;
    msg::check_recv_flags(header.flags)?;
    let iovecs = preflight_recvmsg(context, &header)?;
    if context.fds.lowest_free().is_none() {
        // No descriptor slot for a possible `SCM_RIGHTS` transfer: reject
        // before the engine consumes the message.
        return Err(errno::EMFILE);
    }
    let mut data = [0u8; msg::MSG_IO_MAX];
    let mut objects = [0u16; net::MAX_SCM_FDS];
    match net::recv_msg(id, &mut data[..iovecs.capacity], &mut objects) {
        Ok(received) => finish_recvmsg(
            context,
            id,
            header_pointer,
            &mut header,
            &iovecs,
            &data,
            &received,
        ),
        Err(NetError::WouldBlock) => Ok(Outcome::Wait {
            object: socket_object(id)?,
            deadline: None,
        }),
        Err(NetError::PeerClosed) => Ok(Outcome::Done(0)),
        Err(error) => Err(net_errno(error)),
    }
}

// ---------------------------------------------------------------------------
// getsockname / getpeername / shutdown / options
// ---------------------------------------------------------------------------

/// `getsockname` / `getpeername`.
///
/// `getpeername` keeps Linux's `ENOTCONN` when the socket has no peer: the
/// engine reports a family-less address for an unconnected socket, and turning
/// that into a zeroed address would claim a peer that does not exist.
/// `getsockname` on an unbound socket, on the other hand, must **succeed** and
/// report a zeroed address whose layout matches the socket's creation family
/// (16 bytes for `AF_INET`, 28 for `AF_INET6`, the family tag alone for an
/// anonymous `AF_UNIX`).
fn socket_name(
    args: &[u64; 6],
    context: &mut LinuxContext<'_>,
    peer: bool,
) -> Result<Outcome, i64> {
    let fd = linux_fd(args[0])?;
    let id = socket_of(context, fd)?;
    if args[1] == 0 {
        // Linux allows a NULL address buffer; nothing is written in that case.
        return Ok(Outcome::Done(0));
    }
    let address = if peer {
        match net::remote_address(id) {
            Ok(address) if address::family_for_domain(address.family).is_some() => address,
            Ok(_) => return Err(errno::ENOTCONN),
            Err(NetError::NotConnected) => return Err(errno::ENOTCONN),
            Err(error) => return Err(net_errno(error)),
        }
    } else {
        match net::local_address(id) {
            Ok(address) if address::family_for_domain(address.family).is_some() => address,
            _ => unnamed_address(socket_family(context, fd)?),
        }
    };
    write_socket_address(context, &address, args[1], args[2])?;
    // Linux `getsockname`/`getpeername` return 0; the real length goes back
    // through the `socklen_t` pointer, not through `rax`.
    Ok(Outcome::Done(0))
}

fn shutdown(args: &[u64; 6], context: &mut LinuxContext<'_>) -> Result<Outcome, i64> {
    let fd = linux_fd(args[0])?;
    let id = socket_of(context, fd)?;
    let how = match args[1] {
        0 => net::ShutdownHow::Read,
        1 => net::ShutdownHow::Write,
        2 => net::ShutdownHow::Both,
        _ => return Err(errno::EINVAL),
    };
    net::shutdown(id, how).map_err(net_errno)?;
    Ok(Outcome::Done(0))
}

/// The personality supports `SO_REUSEADDR` (accepted as a no-op hint: the
/// engine's bind is already safe) and `SO_ERROR` (always clear, reported by the
/// engine through call results rather than a stored error). Everything else is
/// reported as unsupported.
fn setsockopt(args: &[u64; 6], context: &mut LinuxContext<'_>) -> Result<Outcome, i64> {
    let fd = linux_fd(args[0])?;
    let id = socket_of(context, fd)?;
    let length = usize::try_from(args[4]).map_err(|_| errno::EINVAL)?;
    if length < 4 {
        return Err(errno::EINVAL);
    }
    let value = read_u32(context, args[3])?;
    match (args[1], args[2]) {
        (SOL_SOCKET, SO_REUSEADDR) => {
            if value > 1 {
                return Err(errno::EINVAL);
            }
            Ok(Outcome::Done(0))
        }
        (SOL_SOCKET, msg::SO_PASSCRED) => {
            if value > 1 {
                return Err(errno::EINVAL);
            }
            net::set_passcred(id, value != 0).map_err(net_errno)?;
            Ok(Outcome::Done(0))
        }
        _ => Err(errno::EOPNOTSUPP),
    }
}

fn getsockopt(args: &[u64; 6], context: &mut LinuxContext<'_>) -> Result<Outcome, i64> {
    let fd = linux_fd(args[0])?;
    let id = socket_of(context, fd)?;
    if args[3] == 0 || args[4] == 0 {
        return Err(errno::EFAULT);
    }
    match (args[1], args[2]) {
        (SOL_SOCKET, SO_ERROR) | (SOL_SOCKET, SO_REUSEADDR) => {
            write_u32(context, args[3], 0)?;
            write_u32(context, args[4], 4)?;
            Ok(Outcome::Done(0))
        }
        (SOL_SOCKET, msg::SO_PASSCRED) => {
            let enabled = net::passcred(id).map_err(net_errno)?;
            write_u32(context, args[3], u32::from(enabled))?;
            write_u32(context, args[4], 4)?;
            Ok(Outcome::Done(0))
        }
        (SOL_SOCKET, msg::SO_PEERCRED) => match net::peer_cred(id).map_err(net_errno)? {
            Some(credential) => {
                let ucred = msg::Ucred {
                    pid: credential.pid as i32,
                    uid: credential.uid,
                    gid: credential.gid,
                };
                let bytes = msg::encode_ucred(&ucred);
                copy_out(context, args[3], &bytes)?;
                write_u32(context, args[4], bytes.len() as u32)?;
                Ok(Outcome::Done(0))
            }
            None => Err(errno::EINVAL),
        },
        _ => Err(errno::EOPNOTSUPP),
    }
}

// ---------------------------------------------------------------------------
// files: openat / read / write / close
// ---------------------------------------------------------------------------

/// Parsed `openat` flags for the M8a file slice.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct FileFlags {
    read: bool,
    write: bool,
    create: bool,
    exclusive: bool,
    truncate: bool,
    cloexec: bool,
    /// `O_DIRECTORY`: the target must be a directory.
    directory: bool,
}

impl FileFlags {
    fn open_options(self) -> OpenOptions {
        OpenOptions {
            read: self.read,
            write: self.write,
            create: self.create,
            truncate: self.truncate,
        }
    }
}

/// Split `O_*` into the directions and actions this stage supports.
fn parse_file_flags(flags: u64) -> Result<FileFlags, i64> {
    if flags & !FILE_FLAG_MASK != 0 {
        return Err(errno::EINVAL);
    }
    let (read, write) = match flags & O_ACCMODE {
        O_RDONLY => (true, false),
        O_WRONLY => (false, true),
        O_RDWR => (true, true),
        _ => return Err(errno::EINVAL),
    };
    Ok(FileFlags {
        read,
        write,
        create: flags & O_CREAT != 0,
        exclusive: flags & O_EXCL != 0,
        // Linux ignores `O_TRUNC` on a descriptor that cannot write.
        truncate: flags & O_TRUNC != 0 && write,
        cloexec: flags & O_CLOEXEC != 0,
        directory: flags & O_DIRECTORY != 0,
    })
}

/// Only the two permission modes the frozen contract allows when creating.
fn file_mode_is_supported(flags: u64, mode: u64) -> Result<(), i64> {
    if flags & O_CREAT == 0 {
        return Ok(());
    }
    match mode {
        0o644 | 0o600 => Ok(()),
        _ => Err(errno::EINVAL),
    }
}

/// The M8a file slice only resolves absolute paths; relative ones would need a
/// working directory this stage does not model.
fn check_absolute_path(path: &[u8]) -> Result<(), i64> {
    if path.is_empty() || path[0] != b'/' {
        return Err(errno::ENOENT);
    }
    if path.contains(&0) {
        return Err(errno::EINVAL);
    }
    Ok(())
}

fn vfs_errno(error: VfsError) -> i64 {
    match error {
        VfsError::NotFound => errno::ENOENT,
        VfsError::NotDirectory => errno::ENOTDIR,
        VfsError::IsDirectory => errno::EISDIR,
        VfsError::AlreadyExists => errno::EEXIST,
        VfsError::ReadOnly => errno::EROFS,
        VfsError::BadPath => errno::ENOENT,
        VfsError::NameTooLong => errno::ENAMETOOLONG,
        VfsError::Quota => errno::ENOSPC,
        VfsError::BadOffset => errno::EINVAL,
        VfsError::PermissionDenied => errno::EACCES,
        VfsError::WouldBlock => errno::EAGAIN,
        VfsError::NotSupported => errno::EOPNOTSUPP,
        VfsError::Corrupt | VfsError::Io | VfsError::Timeout => errno::EIO,
        VfsError::NoMemory => errno::ENOMEM,
        VfsError::Busy => errno::EBUSY,
        VfsError::NotEmpty => errno::ENOTEMPTY,
    }
}

/// A sticky media error keeps the VFS in a failed state; clear it once and
/// retry, exactly like the native file layer does.
fn vfs_retry<T>(mut operation: impl FnMut() -> Result<T, VfsError>) -> Result<T, VfsError> {
    match operation() {
        Err(VfsError::Io) | Err(VfsError::Timeout) => {
            let _ = vfs::clear_disk_sticky(crate::vfs::disk::Kind::Fat32);
            let _ = vfs::clear_disk_sticky(crate::vfs::disk::Kind::Ext2);
            operation()
        }
        other => other,
    }
}

/// Read a NUL-terminated pathname from user memory, bounded by `out`.
///
/// The caller sizes `out` to `vfs::MAX_PATH + 1`, so a missing NUL is reported
/// as `ENAMETOOLONG` instead of reading past the VFS limit.
fn read_path(context: &LinuxContext<'_>, pointer: u64, out: &mut [u8]) -> Result<usize, i64> {
    for (index, slot) in out.iter_mut().enumerate() {
        let address = pointer.checked_add(index as u64).ok_or(errno::EFAULT)?;
        copy_in(context, address, core::slice::from_mut(slot))?;
        if *slot == 0 {
            return Ok(index);
        }
    }
    Err(errno::ENAMETOOLONG)
}

/// File operations the personality needs from the file system.
///
/// The production implementation is [`VfsIo`]; host tests use a fake so the
/// personality's buffer/offset rules are tested without a mounted file system.
trait FileIo {
    fn read(&mut self, open: OpenId, out: &mut [u8]) -> Result<usize, VfsError>;
    fn write(&mut self, open: OpenId, data: &[u8]) -> Result<usize, VfsError>;
}

struct VfsIo;

impl FileIo for VfsIo {
    fn read(&mut self, open: OpenId, out: &mut [u8]) -> Result<usize, VfsError> {
        vfs::read(open, out)
    }

    fn write(&mut self, open: OpenId, data: &[u8]) -> Result<usize, VfsError> {
        vfs::write(open, data)
    }
}

/// A descriptor without the requested direction is a bad descriptor, not an
/// I/O failure (Linux `EBADF`).
fn file_io_errno(error: VfsError) -> i64 {
    if error == VfsError::PermissionDenied {
        errno::EBADF
    } else {
        vfs_errno(error)
    }
}

/// The VFS `OpenId` behind a `File` object.
fn file_open_of(object: ObjectId) -> Result<OpenId, i64> {
    let payload = object::payload(object).ok_or(errno::EBADF)?;
    Ok(OpenId::from_raw(payload as u16))
}

/// Copy `length` bytes from a file into user memory.
///
/// The whole user range is validated **before** the first read so a bad pointer
/// cannot advance the file offset. The VFS owns the offset through the open
/// description, which is what makes `dup` share it and a new `openat` not.
fn file_read(
    context: &LinuxContext<'_>,
    io: &mut dyn FileIo,
    open: OpenId,
    buffer: u64,
    length: usize,
) -> Result<Outcome, i64> {
    if length == 0 {
        return Ok(Outcome::Done(0));
    }
    let space = context.space()?;
    addrspace::validate_user_range(space, buffer, length as u64, true)
        .map_err(|_| errno::EFAULT)?;
    let mut data = [0u8; MAX_IO];
    let mut done = 0usize;
    while done < length {
        let chunk = (length - done).min(MAX_IO);
        let read = vfs_retry(|| io.read(open, &mut data[..chunk])).map_err(file_io_errno)?;
        if read == 0 {
            break;
        }
        let address = buffer.checked_add(done as u64).ok_or(errno::EFAULT)?;
        addrspace::copy_out(space, address, &data[..read]).map_err(|_| errno::EFAULT)?;
        done += read;
        if read < chunk {
            break;
        }
    }
    Ok(Outcome::Done(done as i64))
}

/// Copy `length` bytes from user memory into a file.
///
/// The user range is checked with `write = false` (the kernel only reads it) and
/// validated before the first write, so `EFAULT` leaves the offset untouched.
fn file_write(
    context: &LinuxContext<'_>,
    io: &mut dyn FileIo,
    open: OpenId,
    buffer: u64,
    length: usize,
) -> Result<Outcome, i64> {
    if length == 0 {
        return Ok(Outcome::Done(0));
    }
    let space = context.space()?;
    addrspace::validate_user_range(space, buffer, length as u64, false)
        .map_err(|_| errno::EFAULT)?;
    let mut data = [0u8; MAX_IO];
    let mut done = 0usize;
    while done < length {
        let chunk = (length - done).min(MAX_IO);
        let address = buffer.checked_add(done as u64).ok_or(errno::EFAULT)?;
        addrspace::copy_in(space, address, &mut data[..chunk]).map_err(|_| errno::EFAULT)?;
        let written = vfs_retry(|| io.write(open, &data[..chunk])).map_err(file_io_errno)?;
        if written == 0 {
            break;
        }
        done += written;
        if written < chunk {
            break;
        }
    }
    Ok(Outcome::Done(done as i64))
}

/// Publish a freshly opened VFS description as a `File` object and install it
/// in the descriptor table. On any failure the description is closed again, so
/// neither the fd nor the `OpenId` can leak.
fn install_file(context: &mut LinuxContext<'_>, open: OpenId, cloexec: bool) -> Result<u32, i64> {
    let object = match object::create_with_payload(ObjectKind::File, u64::from(open.raw())) {
        Ok(object) => object,
        Err(error) => {
            let _ = vfs::close(open);
            return Err(object_errno(error));
        }
    };
    let installed = context.fds.insert(FdEntry::new(object, cloexec));
    // The descriptor table holds its own reference; drop the creation one.
    let _ = object::release_object(object);
    match installed {
        Ok(fd) => Ok(fd),
        Err(_) => {
            let _ = vfs::close(open);
            Err(errno::EMFILE)
        }
    }
}

/// Resolve the `openat` directory descriptor.
///
/// This slice resolves only absolute paths against `AT_FDCWD`. A descriptor
/// number that is not installed in the Linux table is still reported as
/// `EBADF` (that is what a real program observes for a bad descriptor), while a
/// valid descriptor is `EOPNOTSUPP` because relative directory resolution is
/// not implemented yet.
fn openat_dirfd(context: &LinuxContext<'_>, raw: u64) -> Result<(), i64> {
    if (raw as i64) == AT_FDCWD {
        return Ok(());
    }
    let fd = linux_fd(raw)?;
    context.fds.get(fd).map_err(|_| errno::EBADF)?;
    Err(errno::EOPNOTSUPP)
}

/// `openat(2)`.
///
/// The M8a slice accepts only `AT_FDCWD`, absolute paths, and the frozen flag
/// set; everything else is reported honestly instead of being approximated.
fn openat(args: &[u64; 6], context: &mut LinuxContext<'_>) -> Result<Outcome, i64> {
    openat_dirfd(context, args[0])?;
    let flags = parse_file_flags(args[2])?;
    file_mode_is_supported(args[2], args[3])?;
    if flags.directory && flags.create {
        // `O_DIRECTORY | O_CREAT` is meaningless on Linux.
        return Err(errno::EINVAL);
    }

    let mut raw_path = [0u8; FILE_PATH_MAX + 1];
    let length = read_path(context, args[1], &mut raw_path)?;
    let path = &raw_path[..length];
    check_absolute_path(path)?;

    let options = flags.open_options();
    match vfs_retry(|| vfs::stat_path(path)) {
        Ok(stat) => {
            if stat.kind == vfs::NodeKind::Directory {
                // M8e: a read-only directory open is the ticket for
                // `getdents64`; anything that would write, create or truncate
                // through the descriptor is still a directory I/O error.
                if flags.write || flags.create || flags.truncate {
                    return Err(errno::EISDIR);
                }
            } else {
                if flags.directory {
                    // `O_DIRECTORY` on a non-directory is `ENOTDIR`.
                    return Err(errno::ENOTDIR);
                }
                if flags.create && flags.exclusive {
                    return Err(errno::EEXIST);
                }
            }
        }
        Err(VfsError::NotFound) => {
            if !flags.create {
                return Err(errno::ENOENT);
            }
        }
        Err(error) => return Err(vfs_errno(error)),
    }

    let owner = process::current_process_id().unwrap_or(0);
    let open = vfs_retry(|| vfs::open_path_as(path, options, owner)).map_err(vfs_errno)?;
    let fd = install_file(context, open, flags.cloexec)?;
    Ok(Outcome::Done(i64::from(fd)))
}

// ---------------------------------------------------------------------------
// M8e: file offsets, metadata and directory streams
// ---------------------------------------------------------------------------

/// `SEEK_SET`.
pub const SEEK_SET: u64 = 0;
/// `SEEK_CUR`.
pub const SEEK_CUR: u64 = 1;
/// `SEEK_END`.
pub const SEEK_END: u64 = 2;

/// Size of the Linux64 `struct stat` image.
pub const STAT_SIZE: usize = 144;
/// Size of the Linux64 `struct statx` image.
pub const STATX_SIZE: usize = 256;

/// `AT_SYMLINK_NOFOLLOW`: the only extra `statx` flag this stage accepts.
pub const AT_SYMLINK_NOFOLLOW: u64 = 0x100;
/// `STATX_BASIC_STATS`: the fields this stage fills.
pub const STATX_BASIC_STATS: u32 = 0x7ff;

/// `S_IFREG`.
const S_IFREG: u32 = 0o100_000;
/// `S_IFDIR`.
const S_IFDIR: u32 = 0o040_000;
/// `S_IFCHR`.
const S_IFCHR: u32 = 0o020_000;
/// Permission bits for a character device (`/dev/null`, `/dev/zero`).
const CHAR_DEVICE_MODE: u32 = 0o666;
/// Permission bits for a writable file.
const FILE_MODE: u32 = 0o644;
/// Permission bits for a read-only file.
const FILE_MODE_READ_ONLY: u32 = 0o444;
/// Permission bits for a directory.
const DIRECTORY_MODE: u32 = 0o755;

/// `FD_CLOEXEC`.
const FD_CLOEXEC: u64 = 1;
/// `F_DUPFD`.
const F_DUPFD: u64 = 0;
/// `F_GETFD`.
const F_GETFD: u64 = 1;
/// `F_SETFD`.
const F_SETFD: u64 = 2;
/// `F_DUPFD_CLOEXEC`.
const F_DUPFD_CLOEXEC: u64 = 1030;
/// `F_GETFL` (recognised; not implemented in M8e).
const F_GETFL: u64 = 3;
/// `F_SETFL` (recognised; not implemented in M8e).
const F_SETFL: u64 = 4;
/// `F_GETLK` (recognised; not implemented in M8e).
const F_GETLK: u64 = 5;
/// `F_SETLK` (recognised; not implemented in M8e).
const F_SETLK: u64 = 6;
/// `F_SETLKW` (recognised; not implemented in M8e).
const F_SETLKW: u64 = 7;
/// `F_SETOWN` (recognised; not implemented in M8e).
const F_SETOWN: u64 = 8;
/// `F_GETOWN` (recognised; not implemented in M8e).
const F_GETOWN: u64 = 9;

/// `DT_REG`.
const DT_REG: u8 = 8;
/// `DT_DIR`.
const DT_DIR: u8 = 4;
/// `DT_CHR` (character device, M8h).
const DT_CHR: u8 = 2;

/// Fixed part of a Linux `dirent64` record.
#[cfg_attr(not(test), allow(dead_code))]
const DIRENT64_HEADER: usize = 19;
/// Smallest `dirent64` record: header plus a one-character name, aligned to
/// eight bytes. A `getdents64` buffer that cannot hold a single record is
/// rejected; larger buffers are filled with as many whole records as fit, so a
/// record is never split across calls.
const DIRENT64_MIN: usize = (DIRENT64_HEADER + 1 + 7) / 8 * 8;
/// Entries requested from the VFS per `getdents64` call.
const DIRENT_BATCH: usize = 8;

/// Translate a Linux `(offset, whence)` pair into a VFS seek request.
fn seek_request(offset: i64, whence: u64) -> Result<vfs::SeekFrom, i64> {
    match whence {
        SEEK_SET => {
            let offset = u64::try_from(offset).map_err(|_| errno::EINVAL)?;
            Ok(vfs::SeekFrom::Start(offset))
        }
        SEEK_CUR => Ok(vfs::SeekFrom::Current(offset)),
        SEEK_END => Ok(vfs::SeekFrom::End(offset)),
        _ => Err(errno::EINVAL),
    }
}

/// Ordinary `read`/`write` on a directory descriptor is an error; directory
/// access is only available through `getdents64`.
fn reject_directory_io(open: OpenId) -> Result<(), i64> {
    let stat = vfs_retry(|| vfs::stat_open(open)).map_err(vfs_errno)?;
    if stat.kind == vfs::NodeKind::Directory {
        return Err(errno::EISDIR);
    }
    Ok(())
}

/// Capture the Linux64 `struct stat` image for a VFS node.
///
/// `device` is `Some(dev_t)` for a character device (`/dev/null`, `/dev/zero`):
/// such a node reports `S_IFCHR | 0666`, size 0, no blocks, and the device
/// number in `st_rdev`. This stage still has no inode model, so `st_dev`,
/// `st_ino` and the timestamps stay zero and `st_nlink` is the minimal POSIX
/// value. That is a documented restricted contract, not a fabricated inode
/// number.
fn encode_stat(
    kind: vfs::NodeKind,
    size: u64,
    read_only: bool,
    device: Option<u64>,
) -> [u8; STAT_SIZE] {
    let mut image = [0u8; STAT_SIZE];
    let directory = kind == vfs::NodeKind::Directory;
    let mode = if device.is_some() {
        S_IFCHR | CHAR_DEVICE_MODE
    } else if directory {
        S_IFDIR | DIRECTORY_MODE
    } else if read_only {
        S_IFREG | FILE_MODE_READ_ONLY
    } else {
        S_IFREG | FILE_MODE
    };
    // A character device has no byte size and no block count.
    let (size, blocks) = match device {
        Some(_) => (0i64, 0i64),
        None => {
            let size = u64::min(size, i64::MAX as u64) as i64;
            (size, (size as u64).div_ceil(512) as i64)
        }
    };
    image[16..24].copy_from_slice(&(if directory { 2u64 } else { 1u64 }).to_le_bytes());
    image[24..28].copy_from_slice(&mode.to_le_bytes());
    if let Some(device) = device {
        image[40..48].copy_from_slice(&device.to_le_bytes());
    }
    image[48..56].copy_from_slice(&size.to_le_bytes());
    image[56..64].copy_from_slice(&4096i64.to_le_bytes());
    image[64..72].copy_from_slice(&blocks.to_le_bytes());
    image
}

/// Split a Linux `dev_t` (the `stat` encoding where the minor's high bits live
/// in bits 12..31) into the raw major/minor pair `struct statx` carries.
fn device_numbers(device: u64) -> (u32, u32) {
    let major = ((device >> 8) & 0xfff) | ((device >> 32) & 0xffff_f000);
    let minor = (device & 0xff) | ((device >> 12) & 0xffff_ff00);
    (major as u32, minor as u32)
}

/// Join a `(major, minor)` pair into the Linux `dev_t` encoding used by
/// `struct stat` (the inverse of [`device_numbers`], `new_encode_dev`).
fn device_from_numbers(major: u16, minor: u16) -> u64 {
    ((u64::from(major) & 0xfff) << 8)
        | (u64::from(minor) & 0xff)
        | ((u64::from(minor) & 0xffff_ff00) << 12)
}

/// The `st_rdev` value for a VFS node: `Some(dev_t)` only for character
/// devices, `None` for files and directories (their `st_rdev` stays zero).
fn node_device(stat: &vfs::NodeStat) -> Option<u64> {
    if stat.kind == vfs::NodeKind::CharDevice {
        Some(device_from_numbers(stat.dev_major, stat.dev_minor))
    } else {
        None
    }
}

/// Encode the Linux64 `struct statx` image (basic statistics only).
///
/// Character devices follow the same restricted contract as [`encode_stat`]:
/// `S_IFCHR | 0666`, size 0, no blocks, and the raw major/minor pair in
/// `stx_rdev_major`/`stx_rdev_minor`.
fn encode_statx(
    kind: vfs::NodeKind,
    size: u64,
    read_only: bool,
    device: Option<u64>,
) -> [u8; STATX_SIZE] {
    let mut image = [0u8; STATX_SIZE];
    let directory = kind == vfs::NodeKind::Directory;
    let mode = if device.is_some() {
        S_IFCHR | CHAR_DEVICE_MODE
    } else if directory {
        S_IFDIR | DIRECTORY_MODE
    } else if read_only {
        S_IFREG | FILE_MODE_READ_ONLY
    } else {
        S_IFREG | FILE_MODE
    };
    let (size, blocks) = match device {
        Some(_) => (0i64, 0i64),
        None => {
            let size = u64::min(size, i64::MAX as u64) as i64;
            (size, (size as u64).div_ceil(512) as i64)
        }
    };
    image[0..4].copy_from_slice(&STATX_BASIC_STATS.to_le_bytes());
    image[4..8].copy_from_slice(&4096u32.to_le_bytes());
    image[16..20].copy_from_slice(&(if directory { 2u32 } else { 1u32 }).to_le_bytes());
    image[28..30].copy_from_slice(&(mode as u16).to_le_bytes());
    if let Some(device) = device {
        let (major, minor) = device_numbers(device);
        image[128..132].copy_from_slice(&major.to_le_bytes());
        image[132..136].copy_from_slice(&minor.to_le_bytes());
    }
    image[40..48].copy_from_slice(&size.to_le_bytes());
    image[48..56].copy_from_slice(&blocks.to_le_bytes());
    image
}

/// Encode up to `out.len()` Linux `dirent64` records from `entries`.
///
/// `next_index` is the index of `entries[0]` in the directory, so `d_off` can
/// carry the index of the entry after the record. Returns `(bytes_written,
/// entries_consumed)`; a record is never split or partially written.
fn encode_dir_entries(
    entries: &[vfs::DirEntry],
    next_index: u32,
    out: &mut [u8],
) -> (usize, usize) {
    let mut used = 0usize;
    let mut consumed = 0usize;
    for entry in entries {
        let name = entry.name();
        let record = (DIRENT64_HEADER + name.len() + 1).div_ceil(8) * 8;
        if used + record > out.len() {
            break;
        }
        let start = used;
        let after = next_index + consumed as u32 + 1;
        out[start..start + 8].copy_from_slice(&0u64.to_le_bytes());
        out[start + 8..start + 16].copy_from_slice(&i64::from(after).to_le_bytes());
        out[start + 16..start + 18].copy_from_slice(&(record as u16).to_le_bytes());
        out[start + 18] = match entry.kind {
            vfs::NodeKind::Directory => DT_DIR,
            vfs::NodeKind::CharDevice => DT_CHR,
            vfs::NodeKind::File => DT_REG,
        };
        out[start + DIRENT64_HEADER..start + DIRENT64_HEADER + name.len()].copy_from_slice(name);
        out[start + DIRENT64_HEADER + name.len()] = 0;
        out[start + DIRENT64_HEADER + name.len() + 1..start + record].fill(0);
        used += record;
        consumed += 1;
    }
    (used, consumed)
}

fn lseek(args: &[u64; 6], context: &mut LinuxContext<'_>) -> Result<Outcome, i64> {
    let fd = linux_fd(args[0])?;
    let entry = context.fds.get(fd).map_err(|_| errno::EBADF)?;
    if object::object_kind(entry.object) != Some(ObjectKind::File) {
        return Err(errno::ESPIPE);
    }
    let open = file_open_of(entry.object)?;
    let request = seek_request(args[1] as i64, args[2])?;
    let offset = vfs_retry(|| vfs::seek_from(open, request)).map_err(|error| match error {
        VfsError::BadOffset | VfsError::IsDirectory => errno::EINVAL,
        other => vfs_errno(other),
    })?;
    if offset > i64::MAX as u64 {
        return Err(errno::EOVERFLOW);
    }
    Ok(Outcome::Done(offset as i64))
}

fn fstat(args: &[u64; 6], context: &mut LinuxContext<'_>) -> Result<Outcome, i64> {
    let fd = linux_fd(args[0])?;
    let entry = context.fds.get(fd).map_err(|_| errno::EBADF)?;
    if object::object_kind(entry.object) != Some(ObjectKind::File) {
        return Err(errno::EOPNOTSUPP);
    }
    let open = file_open_of(entry.object)?;
    let stat = vfs_retry(|| vfs::stat_open(open)).map_err(vfs_errno)?;
    // M8h: character devices carry their `(major, minor)` pair; files and
    // directories report a zero `st_rdev`.
    let device = node_device(&stat);
    let image = encode_stat(stat.kind, stat.size, stat.read_only, device);
    copy_out(context, args[1], &image)?;
    Ok(Outcome::Done(0))
}

fn statx(args: &[u64; 6], context: &mut LinuxContext<'_>) -> Result<Outcome, i64> {
    openat_dirfd(context, args[0])?;
    let flags = args[2];
    if flags & !AT_SYMLINK_NOFOLLOW != 0 {
        return Err(errno::EINVAL);
    }
    let mut raw_path = [0u8; FILE_PATH_MAX];
    let length = read_path(context, args[1], &mut raw_path)?;
    check_absolute_path(&raw_path[..length])?;
    let stat = vfs_retry(|| vfs::stat_path(&raw_path[..length])).map_err(vfs_errno)?;
    // M8h: a generated node's device number is owner independent, so `statx`
    // can fill it from the path statistics once the VFS exposes it.
    let device = node_device(&stat);
    let image = encode_statx(stat.kind, stat.size, stat.read_only, device);
    copy_out(context, args[4], &image)?;
    Ok(Outcome::Done(0))
}

fn getdents64(args: &[u64; 6], context: &mut LinuxContext<'_>) -> Result<Outcome, i64> {
    let fd = linux_fd(args[0])?;
    let entry = context.fds.get(fd).map_err(|_| errno::EBADF)?;
    if object::object_kind(entry.object) != Some(ObjectKind::File) {
        return Err(errno::EBADF);
    }
    let open = file_open_of(entry.object)?;
    let stat = vfs_retry(|| vfs::stat_open(open)).map_err(vfs_errno)?;
    if stat.kind != vfs::NodeKind::Directory {
        return Err(errno::ENOTDIR);
    }
    let capacity = usize::try_from(args[2]).map_err(|_| errno::EINVAL)?;
    if capacity < DIRENT64_MIN {
        return Err(errno::EINVAL);
    }
    let space = context.space()?;
    addrspace::validate_user_range(space, args[1], capacity as u64, true)
        .map_err(|_| errno::EFAULT)?;

    // The VFS cursor lives on the open description (so `dup` shares it). Probe
    // entries *without* advancing through `readdir_open`, encode as many
    // records as fit into the user buffer, and only then advance the cursor by
    // exactly the number of records written: a record that does not fit must
    // not be lost.
    let base = vfs_retry(|| vfs::offset(open)).map_err(vfs_errno)?;
    let base_index = u32::try_from(base).map_err(|_| errno::EOVERFLOW)?;
    let mut buffer = [0u8; MAX_IO];
    let limit = usize::min(capacity, MAX_IO);
    let mut used = 0usize;
    let mut produced = 0usize;
    while produced < DIRENT_BATCH {
        let index = u64::from(base_index) + produced as u64;
        let mut candidate = vfs::DirEntry::empty();
        if index < 2 {
            candidate = directory_dot(index == 1);
        } else {
            let start = usize::try_from(index - 2).map_err(|_| errno::EOVERFLOW)?;
            let read =
                vfs_retry(|| vfs::readdir_open(open, start, core::slice::from_mut(&mut candidate)))
                    .map_err(vfs_errno)?;
            if read == 0 {
                break;
            }
        }
        let (written, consumed) = encode_dir_entries(
            core::slice::from_ref(&candidate),
            base_index + produced as u32,
            &mut buffer[used..limit],
        );
        if consumed == 0 {
            break;
        }
        used += written;
        produced += 1;
    }
    if produced > 0 {
        // Advance the description cursor by exactly the entries we emitted.
        let mut drain = [vfs::DirEntry::empty(); DIRENT_BATCH];
        let advanced = vfs_retry(|| vfs::readdir_open_next(open, &mut drain[..produced]))
            .map_err(vfs_errno)?;
        if advanced != produced {
            return Err(errno::EIO);
        }
        copy_out(context, args[1], &buffer[..used]).map_err(|_| errno::EFAULT)?;
    }
    Ok(Outcome::Done(used as i64))
}

/// The synthetic `.`/`..` entries listed at the head of every directory.
fn directory_dot(parent: bool) -> vfs::DirEntry {
    let mut entry = vfs::DirEntry::empty();
    entry.name[0] = b'.';
    if parent {
        entry.name[1] = b'.';
        entry.name_len = 2;
    } else {
        entry.name_len = 1;
    }
    entry.kind = vfs::NodeKind::Directory;
    entry.size = 0;
    entry
}

fn fcntl(args: &[u64; 6], context: &mut LinuxContext<'_>) -> Result<Outcome, i64> {
    let fd = linux_fd(args[0])?;
    let entry = context.fds.get(fd).map_err(|_| errno::EBADF)?;
    match args[1] {
        F_DUPFD => fcntl_duplicate(context, fd, args[2], false),
        F_DUPFD_CLOEXEC => fcntl_duplicate(context, fd, args[2], true),
        F_GETFD => Ok(Outcome::Done(if entry.cloexec {
            FD_CLOEXEC as i64
        } else {
            0
        })),
        F_SETFD => {
            let flags = args[2];
            if flags & !FD_CLOEXEC != 0 {
                return Err(errno::EINVAL);
            }
            context
                .fds
                .set_cloexec(fd, flags & FD_CLOEXEC != 0)
                .map_err(|_| errno::EBADF)?;
            Ok(Outcome::Done(0))
        }
        // M9c: record locks and status flags.
        F_GETLK => fcntl_getlk(args, context),
        F_SETLK => fcntl_lock(args, context, false),
        F_SETLKW => fcntl_lock(args, context, true),
        F_GETFL => fcntl_getfl(args, context),
        F_SETFL => fcntl_setfl(args, context),
        // Ownership signals are not modelled yet.
        F_SETOWN | F_GETOWN => Err(errno::EOPNOTSUPP),
        _ => Err(errno::EINVAL),
    }
}

fn fcntl_duplicate(
    context: &mut LinuxContext<'_>,
    fd: u32,
    minimum_raw: u64,
    cloexec: bool,
) -> Result<Outcome, i64> {
    let minimum = u32::try_from(minimum_raw).map_err(|_| errno::EINVAL)?;
    // `F_DUPFD` requires the argument to be a descriptor number the table can
    // actually reach; a minimum at or beyond the table size is EINVAL, not
    // "table full".
    if u64::from(minimum) >= super::fd::MAX_FDS as u64 {
        return Err(errno::EINVAL);
    }
    let new_fd = context
        .fds
        .duplicate_at_least(fd, minimum, cloexec)
        .map_err(|error| match error {
            super::fd::FdError::BadFd => errno::EBADF,
            super::fd::FdError::Full => errno::EMFILE,
            super::fd::FdError::Object => errno::EBADF,
        })?;
    Ok(Outcome::Done(i64::from(new_fd)))
}

// ---------------------------------------------------------------------------
// M9c: record locks (`fcntl` F_GETLK/F_SETLK/F_SETLKW) and `flock(2)`
// ---------------------------------------------------------------------------

/// Map a lock-path VFS error onto Linux errno.
fn lock_errno(error: VfsError) -> i64 {
    match error {
        // A held lock that the caller asked to take without waiting.
        VfsError::WouldBlock => errno::EAGAIN,
        // Linux reports an unusable access mode on a lock request as EBADF.
        VfsError::PermissionDenied => errno::EBADF,
        // The global lock table is full.
        VfsError::Quota => errno::ENOLCK,
        other => vfs_errno(other),
    }
}

/// The open description behind a file descriptor; non-`File` descriptors are
/// `EBADF` for every lock command.
fn file_description(context: &LinuxContext<'_>, fd: u32) -> Result<OpenId, i64> {
    let entry = context.fds.get(fd).map_err(|_| errno::EBADF)?;
    if object::object_kind(entry.object) != Some(ObjectKind::File) {
        return Err(errno::EBADF);
    }
    file_open_of(entry.object)
}

/// Resolve a `struct flock` into an absolute `(start, length)` byte range.
fn flock_range(open: OpenId, request: &file_lock::Flock) -> Result<(u64, u64), i64> {
    let current = if request.whence == file_lock::SEEK_CUR {
        vfs::offset(open).map_err(vfs_errno)?
    } else {
        0
    };
    let size = if request.whence == file_lock::SEEK_END {
        vfs::stat_open(open).map_err(vfs_errno)?.size
    } else {
        0
    };
    file_lock::resolve_range(request.whence, request.start, request.len, current, size)
}

/// Turn a wake reason into the one-tick lock sleep (or `EINTR`).
///
/// `F_SETLKW` and blocking `flock` have no wake source of their own: they arm a
/// one-tick deadline and let the entry replay the same call, which re-checks the
/// lock table. A cancelled wait means a signal is deliverable, so the replay
/// reports `EINTR` instead of retrying.
fn lock_wait_after(reason: process::WakeReason) -> Result<Outcome, i64> {
    if reason == process::WakeReason::Cancelled {
        return Err(errno::EINTR);
    }
    let deadline = crate::time::monotonic_ticks().saturating_add(1);
    SLEEP_DEADLINES[sleep_slot()].store(deadline, Ordering::Relaxed);
    Ok(Outcome::Wait {
        object: SLEEP_OBJECT,
        deadline: Some(deadline),
    })
}

/// Sleep one tick and let the entry replay the lock call.
fn lock_wait() -> Result<Outcome, i64> {
    lock_wait_after(process::take_wake_reason())
}

/// Copy in and decode a `struct flock` request image.
fn read_flock(context: &LinuxContext<'_>, pointer: u64) -> Result<file_lock::Flock, i64> {
    let mut image = [0u8; file_lock::FLOCK_SIZE];
    copy_in(context, pointer, &mut image)?;
    file_lock::decode_flock(&image)
}

/// Linux pid of a lock owner (`process::linux_pid`: table index plus one).
fn owner_linux_pid(owner: u32) -> i32 {
    if owner == 0 {
        return -1;
    }
    match i32::try_from(owner) {
        Ok(index) => index.saturating_add(1),
        Err(_) => -1,
    }
}

/// `fcntl(F_SETLK)` (non-blocking) and `fcntl(F_SETLKW)` (one-tick retry).
fn fcntl_lock(
    args: &[u64; 6],
    context: &mut LinuxContext<'_>,
    blocking: bool,
) -> Result<Outcome, i64> {
    let fd = linux_fd(args[0])?;
    let open = file_description(context, fd)?;
    // The userspace image is validated before any lock table change.
    let request = read_flock(context, args[2])?;
    let (start, length) = flock_range(open, &request)?;
    if request.kind == file_lock::FlockType::Unlock {
        vfs::unlock_open(open, vfs::lock::LockDomain::Posix, start, length).map_err(lock_errno)?;
        return Ok(Outcome::Done(0));
    }
    let kind = match request.kind {
        file_lock::FlockType::Read => vfs::lock::LockKind::Shared,
        _ => vfs::lock::LockKind::Exclusive,
    };
    match vfs::lock_open(open, vfs::lock::LockDomain::Posix, kind, start, length) {
        Ok(()) => Ok(Outcome::Done(0)),
        Err(VfsError::WouldBlock) if blocking => lock_wait(),
        Err(error) => Err(lock_errno(error)),
    }
}

/// `fcntl(F_GETLK)`.
fn fcntl_getlk(args: &[u64; 6], context: &mut LinuxContext<'_>) -> Result<Outcome, i64> {
    let fd = linux_fd(args[0])?;
    let open = file_description(context, fd)?;
    let request = read_flock(context, args[2])?;
    // POSIX only lets the query carry a read or write request; F_UNLCK is EINVAL.
    if !request.kind.is_query_type() {
        return Err(errno::EINVAL);
    }
    let (start, length) = flock_range(open, &request)?;
    let kind = if request.kind == file_lock::FlockType::Read {
        vfs::lock::LockKind::Shared
    } else {
        vfs::lock::LockKind::Exclusive
    };
    let answer = match vfs::lock_probe(open, vfs::lock::LockDomain::Posix, kind, start, length) {
        Ok(None) => file_lock::Flock {
            kind: file_lock::FlockType::Unlock,
            whence: file_lock::SEEK_SET,
            start: 0,
            len: 0,
            pid: 0,
        },
        Ok(Some(conflict)) => file_lock::Flock {
            kind: match conflict.kind {
                vfs::lock::LockKind::Shared => file_lock::FlockType::Read,
                vfs::lock::LockKind::Exclusive => file_lock::FlockType::Write,
            },
            whence: file_lock::SEEK_SET,
            start: i64::try_from(conflict.start).map_err(|_| errno::EOVERFLOW)?,
            len: i64::try_from(conflict.len).map_err(|_| errno::EOVERFLOW)?,
            pid: owner_linux_pid(conflict.owner),
        },
        Err(error) => return Err(lock_errno(error)),
    };
    copy_out(context, args[2], &file_lock::encode_flock(&answer))?;
    Ok(Outcome::Done(0))
}

/// `fcntl(F_GETFL)`.
fn fcntl_getfl(args: &[u64; 6], context: &mut LinuxContext<'_>) -> Result<Outcome, i64> {
    let fd = linux_fd(args[0])?;
    let open = file_description(context, fd)?;
    let (read, write) = vfs::open_modes(open).map_err(vfs_errno)?;
    let flags = match (read, write) {
        (true, true) => O_RDWR,
        (false, true) => O_WRONLY,
        _ => O_RDONLY,
    };
    Ok(Outcome::Done(flags as i64))
}

/// `fcntl(F_SETFL)`.
///
/// The access mode cannot be changed here and no status flag (`O_APPEND`,
/// `O_NONBLOCK`, ...) is modelled by this personality yet, so only the empty
/// flag set is a supported no-op; every other flag is reported as unsupported
/// rather than silently dropped.
fn fcntl_setfl(args: &[u64; 6], context: &mut LinuxContext<'_>) -> Result<Outcome, i64> {
    let fd = linux_fd(args[0])?;
    context.fds.get(fd).map_err(|_| errno::EBADF)?;
    if args[2] == 0 {
        return Ok(Outcome::Done(0));
    }
    Err(errno::EOPNOTSUPP)
}

/// `flock(2)` (NR 73).
fn flock(args: &[u64; 6], context: &mut LinuxContext<'_>) -> Result<Outcome, i64> {
    // Validate the operation word before touching the descriptor table.
    let operation = file_lock::decode_flock_operation(args[1])?;
    let fd = linux_fd(args[0])?;
    let open = file_description(context, fd)?;
    if operation.unlock {
        vfs::unlock_open(open, vfs::lock::LockDomain::Flock, 0, 0).map_err(lock_errno)?;
        return Ok(Outcome::Done(0));
    }
    let kind = if operation.exclusive {
        vfs::lock::LockKind::Exclusive
    } else {
        vfs::lock::LockKind::Shared
    };
    match vfs::lock_open(open, vfs::lock::LockDomain::Flock, kind, 0, 0) {
        Ok(()) => Ok(Outcome::Done(0)),
        Err(VfsError::WouldBlock) if operation.nonblocking => Err(errno::EAGAIN),
        Err(VfsError::WouldBlock) => lock_wait(),
        Err(error) => Err(lock_errno(error)),
    }
}

// ---------------------------------------------------------------------------
// M8b: clocks, uname and system information
// ---------------------------------------------------------------------------

/// Convert monotonic `ticks` into `(seconds, nanoseconds)` on the same clock.
fn timespec_from_ticks(ticks: u64, hz: u32) -> Result<(i64, i64), i64> {
    if hz == 0 {
        return Err(errno::EIO);
    }
    let seconds = ticks / u64::from(hz);
    let remainder = ticks % u64::from(hz);
    let nanos = u128::from(remainder) * NANOS_PER_SECOND / u128::from(hz);
    Ok((
        i64::try_from(seconds).map_err(|_| errno::EOVERFLOW)?,
        i64::try_from(nanos).map_err(|_| errno::EOVERFLOW)?,
    ))
}

/// Encode a Linux64 `timespec` image.
fn encode_timespec(seconds: i64, nanos: i64) -> [u8; TIMESPEC_SIZE] {
    let mut image = [0u8; TIMESPEC_SIZE];
    image[..8].copy_from_slice(&seconds.to_le_bytes());
    image[8..].copy_from_slice(&nanos.to_le_bytes());
    image
}

/// Decode and validate a Linux64 `timespec` image.
fn decode_timespec(image: &[u8; TIMESPEC_SIZE]) -> Result<(i64, i64), i64> {
    let mut seconds = [0u8; 8];
    seconds.copy_from_slice(&image[..8]);
    let mut nanos = [0u8; 8];
    nanos.copy_from_slice(&image[8..]);
    let seconds = i64::from_le_bytes(seconds);
    let nanos = i64::from_le_bytes(nanos);
    if seconds < 0 || !(0..1_000_000_000i64).contains(&nanos) {
        return Err(errno::EINVAL);
    }
    Ok((seconds, nanos))
}

/// Copy a `timespec` out of user memory and validate it.
fn read_timespec(context: &LinuxContext<'_>, pointer: u64) -> Result<(i64, i64), i64> {
    let mut image = [0u8; TIMESPEC_SIZE];
    copy_in(context, pointer, &mut image)?;
    decode_timespec(&image)
}

/// Nanoseconds → clock ticks, rounded up so a sleep never ends early.
fn nanos_to_ticks_ceil(nanos: u128, hz: u32) -> Result<u64, i64> {
    if hz == 0 {
        return Err(errno::EIO);
    }
    let scaled = nanos.checked_mul(u128::from(hz)).ok_or(errno::EOVERFLOW)?;
    let mut ticks = scaled / NANOS_PER_SECOND;
    if scaled % NANOS_PER_SECOND != 0 {
        ticks += 1;
    }
    u64::try_from(ticks).map_err(|_| errno::EOVERFLOW)
}

/// Resolve a `clock_nanosleep` request into an absolute monotonic deadline.
///
/// `Ok(None)` means the deadline is already due (the call returns immediately);
/// `Ok(Some(ticks))` is the absolute tick to sleep until. A relative request is
/// `now + duration`; `TIMER_ABSTIME` treats the request as ticks since boot.
fn sleep_deadline(
    now: u64,
    hz: u32,
    flags: u32,
    seconds: i64,
    nanos: i64,
) -> Result<Option<u64>, i64> {
    let nanos = u128::try_from(seconds)
        .map_err(|_| errno::EINVAL)?
        .checked_mul(NANOS_PER_SECOND)
        .ok_or(errno::EOVERFLOW)?
        .checked_add(u128::try_from(nanos).map_err(|_| errno::EINVAL)?)
        .ok_or(errno::EOVERFLOW)?;
    let ticks = nanos_to_ticks_ceil(nanos, hz)?;
    let target = if flags & TIMER_ABSTIME != 0 {
        ticks
    } else {
        now.saturating_add(ticks)
    };
    Ok((target > now).then_some(target))
}

/// Map a Linux clock id onto the kernel's monotonic clock.
///
/// `CLOCK_REALTIME` has no trusted RTC baseline, so it reports `ENOSYS`
/// instead of inventing wall-clock time; unknown ids are `EINVAL`.
fn clock_supported(clockid: u32) -> Result<(), i64> {
    match clockid {
        CLOCK_MONOTONIC | CLOCK_BOOTTIME => Ok(()),
        CLOCK_REALTIME => Err(errno::ENOSYS),
        _ => Err(errno::EINVAL),
    }
}

/// True when a resumed sleep finished normally.
///
/// A pure deadline wait (`count == 0`) has no object triggers, so the only wake
/// it can receive is the timer reporting that its deadline passed.
fn sleep_wake_completed(reason: process::WakeReason) -> bool {
    matches!(reason, process::WakeReason::Timeout)
}

/// `clock_gettime(228)`.
fn clock_gettime(args: &[u64; 6], context: &LinuxContext<'_>) -> Result<Outcome, i64> {
    let clockid = u32::try_from(args[0]).map_err(|_| errno::EINVAL)?;
    clock_supported(clockid)?;
    let (seconds, nanos) =
        timespec_from_ticks(crate::time::monotonic_ticks(), crate::time::tick_hz())?;
    copy_out(context, args[1], &encode_timespec(seconds, nanos))?;
    Ok(Outcome::Done(0))
}

/// `clock_nanosleep(230)`.
///
/// The wait is a pure deadline wait (`count == 0`), so the timer ISR is the
/// only wake source and reports `Timeout` on expiry: that is a completed sleep
/// (Linux returns 0). Any other wake reason is treated as an interruption and
/// returns `EINTR`, with the caller's request copied back as the remaining
/// time (no signal delivery exists yet, so this is defensive).
fn clock_nanosleep(args: &[u64; 6], context: &LinuxContext<'_>) -> Result<Outcome, i64> {
    let clockid = u32::try_from(args[0]).map_err(|_| errno::EINVAL)?;
    clock_supported(clockid)?;
    let flags = u32::try_from(args[1]).map_err(|_| errno::EINVAL)?;
    if flags & !TIMER_ABSTIME != 0 {
        return Err(errno::EINVAL);
    }
    let hz = crate::time::tick_hz();

    let reason = process::take_wake_reason();
    if reason.is_some() {
        // The only wake a pure deadline wait can receive is its own expiry, so
        // that is a completed sleep and must not touch user memory.
        if sleep_wake_completed(reason) {
            return Ok(Outcome::Done(0));
        }
        // Defensive interruption path: hand the original request back as the
        // remaining time (no signal delivery exists yet).
        if args[3] != 0
            && let Ok(request) = read_timespec(context, args[2])
        {
            let _ = copy_out(context, args[3], &encode_timespec(request.0, request.1));
        }
        return Err(errno::EINTR);
    }

    let request = read_timespec(context, args[2])?;
    let now = crate::time::monotonic_ticks();
    let Some(deadline) = sleep_deadline(now, hz, flags, request.0, request.1)? else {
        return Ok(Outcome::Done(0));
    };
    SLEEP_DEADLINES[sleep_slot()].store(deadline, Ordering::Relaxed);
    Ok(Outcome::Wait {
        object: SLEEP_OBJECT,
        deadline: Some(deadline),
    })
}

/// The fixed `utsname` image reported by `uname`.
fn uname_image() -> [u8; UTSNAME_SIZE] {
    let fields = [
        "CaelumOS",
        "caelum",
        crate::KERNEL_VERSION,
        "CaelumOS kernel",
        "x86_64",
        "(none)",
    ];
    let mut image = [0u8; UTSNAME_SIZE];
    for (index, text) in fields.iter().enumerate() {
        let start = index * UTSNAME_FIELD;
        let bytes = text.as_bytes();
        let length = bytes.len().min(UTSNAME_FIELD - 1);
        image[start..start + length].copy_from_slice(&bytes[..length]);
    }
    image
}

/// `uname(63)`.
fn uname(args: &[u64; 6], context: &LinuxContext<'_>) -> Result<Outcome, i64> {
    copy_out(context, args[0], &uname_image())?;
    Ok(Outcome::Done(0))
}

/// `getppid(110)`.
///
/// M8d gives the parented Linux child a real parent link; detached processes
/// still report 0, which is what Linux reports for a parentless process.
fn getppid() -> Result<Outcome, i64> {
    let parent = process::parent_linux_pid().unwrap_or(0);
    Ok(Outcome::Done(i64::from(parent)))
}

/// Linux pid number for a kernel process id.
///
/// `process::current_process_id` is the 0-based process-table index, while
/// Linux pid numbers start at 1. The host negative path (no current process)
/// keeps the established 0 convention.
fn linux_pid(current: Option<u32>) -> i64 {
    match current {
        Some(index) => i64::from(index) + 1,
        None => 0,
    }
}

/// `getpid(39)`.
fn getpid() -> Result<Outcome, i64> {
    Ok(Outcome::Done(linux_pid(process::current_process_id())))
}

// Linux64 `struct sysinfo` byte offsets (all members 8-byte except `procs`,
// `pad` and `mem_unit`).
const SYSINFO_UPTIME: usize = 0;
const SYSINFO_TOTALRAM: usize = 32;
const SYSINFO_FREERAM: usize = 40;
const SYSINFO_PROCS: usize = 80;
const SYSINFO_MEM_UNIT: usize = 104;

/// The real values the personality feeds into `struct sysinfo`.
struct SysinfoValues {
    uptime: i64,
    totalram: u64,
    freeram: u64,
    procs: u16,
}

fn put_u64(image: &mut [u8; SYSINFO_SIZE], offset: usize, value: u64) {
    image[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

fn put_i64(image: &mut [u8; SYSINFO_SIZE], offset: usize, value: i64) {
    image[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

fn put_u32(image: &mut [u8; SYSINFO_SIZE], offset: usize, value: u32) {
    image[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn put_u16(image: &mut [u8; SYSINFO_SIZE], offset: usize, value: u16) {
    image[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

/// Encode Linux64 `struct sysinfo`; every field not reported by this stage is
/// left zero, as Linux does, and `mem_unit` is 1 so all sizes are bytes.
fn encode_sysinfo(values: &SysinfoValues) -> [u8; SYSINFO_SIZE] {
    let mut image = [0u8; SYSINFO_SIZE];
    put_i64(&mut image, SYSINFO_UPTIME, values.uptime);
    put_u64(&mut image, SYSINFO_TOTALRAM, values.totalram);
    put_u64(&mut image, SYSINFO_FREERAM, values.freeram);
    put_u16(&mut image, SYSINFO_PROCS, values.procs);
    put_u32(&mut image, SYSINFO_MEM_UNIT, 1);
    image
}

const FRAME_BYTES: u64 = 4096;

/// `sysinfo(99)`.
fn sysinfo(args: &[u64; 6], context: &LinuxContext<'_>) -> Result<Outcome, i64> {
    let uptime =
        i64::try_from(crate::time::monotonic_millis() / 1000).map_err(|_| errno::EOVERFLOW)?;
    let totalram = crate::mm::pmm::total_frames()
        .checked_mul(FRAME_BYTES)
        .ok_or(errno::EOVERFLOW)?;
    let freeram = crate::mm::pmm::free_frames()
        .checked_mul(FRAME_BYTES)
        .ok_or(errno::EOVERFLOW)?;
    let values = SysinfoValues {
        uptime,
        totalram,
        freeram,
        procs: u16::try_from(process::live_count()).unwrap_or(u16::MAX),
    };
    copy_out(context, args[0], &encode_sysinfo(&values))?;
    Ok(Outcome::Done(0))
}

// ---------------------------------------------------------------------------
// Signals (M8c)
// ---------------------------------------------------------------------------

/// Linux error number for a [`process::SignalError`].
fn signal_errno(error: process::SignalError) -> i64 {
    match error {
        process::SignalError::InvalidSignal => errno::EINVAL,
        process::SignalError::Uncatchable => errno::EINVAL,
        process::SignalError::NoCurrentProcess => errno::ESRCH,
        process::SignalError::NotDelivering => errno::EINVAL,
    }
}

/// Whether `signo` belongs to the stop family this slice refuses.
fn is_stop_family(signo: u32) -> bool {
    matches!(signo, SIGSTOP | SIGTSTP | SIGTTIN | SIGTTOU)
}

/// Read a 32-byte `struct sigaction` from user memory.
fn read_sigaction(context: &LinuxContext<'_>, pointer: u64) -> Result<process::SigAction, i64> {
    let mut wire = [0u8; signal::SIGACTION_BYTES];
    copy_in(context, pointer, &mut wire)?;
    Ok(signal::decode_action(&wire))
}

/// Write a 32-byte `struct sigaction` to user memory.
fn write_sigaction(
    context: &LinuxContext<'_>,
    pointer: u64,
    action: &process::SigAction,
) -> Result<(), i64> {
    copy_out(context, pointer, &signal::encode_action(action))
}

/// `rt_sigaction(13)`.
fn rt_sigaction(args: &[u64; 6], context: &LinuxContext<'_>) -> Result<Outcome, i64> {
    let signum = signal::validate_signal(args[0])?;
    if args[3] != signal::SIGSET_SIZE {
        return Err(errno::EINVAL);
    }
    if args[1] != 0 {
        let action = read_sigaction(context, args[1])?;
        signal::validate_action(signum, &action)?;
        let old = process::signal_set_action(signum, action).map_err(signal_errno)?;
        if args[2] != 0 {
            write_sigaction(context, args[2], &old)?;
        }
    } else if args[2] != 0 {
        let old = process::signal_action(signum).map_err(signal_errno)?;
        write_sigaction(context, args[2], &old)?;
    }
    Ok(Outcome::Done(0))
}

fn mask_how(how: u64) -> Result<process::SignalMaskHow, i64> {
    match signal::validate_mask_how(how)? {
        signal::SIG_BLOCK => Ok(process::SignalMaskHow::Block),
        signal::SIG_UNBLOCK => Ok(process::SignalMaskHow::Unblock),
        signal::SIG_SETMASK => Ok(process::SignalMaskHow::SetMask),
        _ => Err(errno::EINVAL),
    }
}

/// `rt_sigprocmask(14)`.
fn rt_sigprocmask(args: &[u64; 6], context: &LinuxContext<'_>) -> Result<Outcome, i64> {
    if args[3] != signal::SIGSET_SIZE {
        return Err(errno::EINVAL);
    }
    let how = mask_how(args[0])?;
    let old = if args[1] != 0 {
        let mut wire = [0u8; signal::SIGSET_BYTES];
        copy_in(context, args[1], &mut wire)?;
        let set = signal::decode_sigset(&wire);
        process::signal_set_mask(how, set).map_err(signal_errno)?
    } else {
        process::signal_mask().map_err(signal_errno)?
    };
    if args[2] != 0 {
        let mut wire = [0u8; signal::SIGSET_BYTES];
        wire.copy_from_slice(&signal::encode_sigset(old));
        copy_out(context, args[2], &wire)?;
    }
    Ok(Outcome::Done(0))
}

/// Production [`signal::SignalMemory`] over the current address space.
pub struct KernelSignalMemory {
    space: AddressSpaceId,
}

impl KernelSignalMemory {
    /// Build the accessor for `space`.
    pub const fn new(space: AddressSpaceId) -> Self {
        Self { space }
    }
}

impl signal::SignalMemory for KernelSignalMemory {
    fn validate_write(&self, user: u64, len: u64) -> Result<(), i64> {
        addrspace::validate_user_range(self.space, user, len, true).map_err(|_| errno::EFAULT)
    }

    fn write(&mut self, user: u64, bytes: &[u8]) -> Result<(), i64> {
        addrspace::copy_out(self.space, user, bytes).map_err(|_| errno::EFAULT)
    }

    fn read(&mut self, user: u64, out: &mut [u8]) -> Result<(), i64> {
        addrspace::copy_in(self.space, user, out).map_err(|_| errno::EFAULT)
    }
}

/// `rt_sigreturn(15)`.
///
/// The handler ran and the user `sa_restorer` invoked `rt_sigreturn`; the frame
/// it left on the user stack is validated (magic) and the trusted context saved
/// at delivery is restored into the trap frame.
fn rt_sigreturn(context: &mut LinuxContext<'_>) -> Result<Outcome, i64> {
    let Some(trap_frame) = context.trap_frame else {
        return Err(errno::EFAULT);
    };
    let space = context.space()?;
    let mut memory = KernelSignalMemory::new(space);
    // SAFETY: the entry passes the frame of the current syscall, valid for the
    // duration of dispatch; this is the same pointer every other handler uses
    // through `copy_in`/`copy_out` and the scheduler's replay path.
    let trap = unsafe { &mut *trap_frame };
    signal::validate_user_frame(trap, &mut memory)?;
    process::signal_restore_context(trap).map_err(signal_errno)?;
    // A `ppoll` interrupted by a handler installed the temporary mask before
    // delivery, so the mask saved in the signal frame is the temporary one.
    // The interrupted call restores the original mask once the handler has
    // returned, exactly like Linux' `TIF_RESTORE_SIGMASK`.
    if let Some(original) = context.fds.take_pending_mask_restore() {
        let _ = process::signal_set_mask(process::SignalMaskHow::SetMask, original);
    }
    Ok(Outcome::Restore {
        rax: trap.rax as i64,
        rdx: trap.rdx,
    })
}

/// Linux error number for a cross-process signal failure (M8d).
fn signal_send_errno(error: process::SignalSendError) -> i64 {
    match error {
        process::SignalSendError::NoSuchProcess => errno::ESRCH,
        process::SignalSendError::InvalidSignal => errno::EINVAL,
    }
}

/// Validate a signal number for `kill`/`tgkill`.
///
/// `signo == 0` is the existence/permission probe; the stop family is refused
/// with `ENOSYS` (no job-control model in this slice) and must not enter the
/// pending queue of any process.
fn validate_send_signal(signo: u64) -> Result<u32, i64> {
    let signo = u32::try_from(signo).map_err(|_| errno::EINVAL)?;
    if signo == 0 {
        return Ok(0);
    }
    let signum = signal::validate_signal(u64::from(signo))?;
    if is_stop_family(signum) {
        return Err(errno::ENOSYS);
    }
    Ok(signo)
}

/// `kill(62)`.
///
/// M8d only allows signalling the target itself, its parent or its child (plus
/// the `kill(-1)` broadcast to the children); a pid that cannot be resolved or
/// reached reports `ESRCH` instead of pretending to deliver. `pid == 0` targets
/// the caller, and the stop family never enters the pending queue.
fn kill(args: &[u64; 6], _context: &LinuxContext<'_>) -> Result<Outcome, i64> {
    let signo = validate_send_signal(args[1])?;
    let target = args[0] as i64;
    if target == -1 {
        if process::signal_send_children(signo) == 0 {
            return Err(errno::ESRCH);
        }
        return Ok(Outcome::Done(0));
    }
    if target < 0 {
        return Err(errno::EINVAL);
    }
    let pid = if target == 0 {
        process::current_linux_pid().ok_or(errno::ESRCH)?
    } else {
        u32::try_from(target).map_err(|_| errno::ESRCH)?
    };
    process::signal_send_process(pid, signo).map_err(signal_send_errno)?;
    Ok(Outcome::Done(0))
}

/// `tgkill(234)`.
///
/// A single-threaded Linux process only has `tgid == tid`; Linux refuses a
/// mismatched pair with `EINVAL`. Delivery then follows the same parent/child
/// rule as `kill`.
fn tgkill(args: &[u64; 6], _context: &LinuxContext<'_>) -> Result<Outcome, i64> {
    let tgid = i64::try_from(args[0]).map_err(|_| errno::EINVAL)?;
    let tid = i64::try_from(args[1]).map_err(|_| errno::EINVAL)?;
    if tgid <= 0 || tid <= 0 || tgid != tid {
        return Err(errno::EINVAL);
    }
    let signo = validate_send_signal(args[2])?;
    process::signal_send_process(tid as u32, signo).map_err(signal_send_errno)?;
    Ok(Outcome::Done(0))
}

// ---------------------------------------------------------------------------
// M8d: cross-process signalling and `wait4`
// ---------------------------------------------------------------------------

/// Validate `wait4` options.
///
/// Only `WNOHANG` is supported. `WUNTRACED`/`WCONTINUED`/`__WNOTHREAD` would
/// change the reported state machine, so they are refused with `EINVAL`
/// instead of being silently ignored.
fn wait4_nohang(options: u64) -> Result<bool, i64> {
    if options & !WAIT_OPTION_MASK != 0 {
        return Err(errno::EINVAL);
    }
    Ok(options & WNOHANG != 0)
}

/// Encode a normal child exit for `wait4` (`WIFEXITED`; `WEXITSTATUS` = code).
pub const fn wait_status_exit(code: u32) -> i32 {
    ((code & 0xff) << 8) as i32
}

/// Encode a signal death for `wait4` (`WIFSIGNALED`; the low 7 bits hold it).
pub const fn wait_status_signal(signo: u32) -> i32 {
    (signo & 0x7f) as i32
}

/// Resolve the `wait4` pid argument to a concrete child or "any child".
///
/// `pid == -1` waits for any child; a positive pid names one child. `0`
/// (process group) and the other negative forms are refused until job control
/// exists, which is honest rather than wrong.
fn wait4_target(pid: i64) -> Result<Option<u32>, i64> {
    if pid == -1 {
        return Ok(None);
    }
    if pid <= 0 {
        return Err(errno::EINVAL);
    }
    Ok(Some(pid as u32))
}

/// `rusage` must be a null pointer: there is no accounting yet, and writing
/// invented numbers would be worse than refusing the request.
fn wait4_rusage_is_null(rusage: u64) -> Result<(), i64> {
    if rusage != 0 {
        return Err(errno::EINVAL);
    }
    Ok(())
}

/// Linux error number for a `wait4` process-table failure.
///
/// A pid that names no child is `ECHILD`; the other failures possible in this
/// slice are treated the same way, because the wait4 contract has no richer
/// error the user can act on.
fn wait_child_errno(error: process::ProcessError) -> i64 {
    match error {
        process::ProcessError::NoChild | process::ProcessError::NoSuchProcess => errno::ECHILD,
        _ => errno::EINVAL,
    }
}

/// `wait4(61)`.
///
/// `WNOHANG` never blocks; otherwise a running child reports [`Outcome::Wait`]
/// on its process object and the syscall is replayed after the child's exit
/// wake (the replay keeps `rax` as the Linux call number, so the blocking path
/// needs no special entry change). `rusage` must be NULL because no accounting
/// exists yet.
fn wait4(args: &[u64; 6], context: &LinuxContext<'_>) -> Result<Outcome, i64> {
    let pid = wait4_target(args[0] as i64)?;
    let nohang = wait4_nohang(args[2])?;
    wait4_rusage_is_null(args[3])?;
    match process::wait_child(pid).map_err(wait_child_errno)? {
        process::ChildWait::Exited(exit) => {
            let status = match exit.signal {
                Some(signo) => wait_status_signal(signo),
                None => wait_status_exit(exit.code as u32),
            };
            if args[1] != 0 {
                copy_out(context, args[1], &status.to_le_bytes())?;
            }
            Ok(Outcome::Done(i64::from(exit.pid)))
        }
        process::ChildWait::Running(object) => {
            if nohang {
                Ok(Outcome::Done(0))
            } else {
                Ok(Outcome::Wait {
                    object,
                    deadline: None,
                })
            }
        }
    }
}

#[cfg(test)]
mod wait4_helpers {
    use super::*;

    #[test]
    fn wait4_only_accepts_wnohang() {
        assert_eq!(wait4_nohang(0), Ok(false));
        assert_eq!(wait4_nohang(WNOHANG), Ok(true));
        assert_eq!(wait4_nohang(2), Err(errno::EINVAL), "WUNTRACED");
        assert_eq!(wait4_nohang(0x0100_0000), Err(errno::EINVAL), "__WNOTHREAD");
        assert_eq!(wait4_nohang(WNOHANG | 2), Err(errno::EINVAL));
    }

    #[test]
    fn wait4_status_encoding_matches_the_linux_layout() {
        assert_eq!(wait_status_exit(0), 0);
        assert_eq!(wait_status_exit(7), 7 << 8);
        assert_eq!(wait_status_exit(255), 0xFF00);
        assert_eq!(wait_status_signal(15), 15);
        assert_eq!(wait_status_signal(11), 11);
        // The kernel marks the low seven bits and leaves the exit code zero.
        assert_eq!(wait_status_exit(0) | wait_status_signal(9), 9);
        assert_eq!(wait_status_signal(128), 0);
    }

    #[test]
    fn wait4_pid_forms_and_rusage_pointer_are_validated() {
        assert_eq!(wait4_target(7), Ok(Some(7)));
        assert_eq!(wait4_target(i64::from(u32::MAX)), Ok(Some(u32::MAX)));
        assert_eq!(wait4_target(-1), Ok(None));
        assert_eq!(wait4_target(0), Err(errno::EINVAL));
        assert_eq!(wait4_target(-2), Err(errno::EINVAL));
        assert_eq!(wait4_rusage_is_null(0), Ok(()));
        assert_eq!(wait4_rusage_is_null(0x1000), Err(errno::EINVAL));
    }
}

// ---------------------------------------------------------------------------
// M8f: futex, TLS base and thread-id address
// ---------------------------------------------------------------------------

/// `FUTEX_WAIT`.
pub const FUTEX_WAIT: u64 = 0;
/// `FUTEX_WAKE`.
pub const FUTEX_WAKE: u64 = 1;
/// `FUTEX_PRIVATE_FLAG`: the wait is private to the process.
pub const FUTEX_PRIVATE_FLAG: u64 = 128;
/// `FUTEX_WAIT | FUTEX_PRIVATE_FLAG`.
const FUTEX_WAIT_PRIVATE: u64 = FUTEX_WAIT | FUTEX_PRIVATE_FLAG;
/// `FUTEX_WAKE | FUTEX_PRIVATE_FLAG`.
const FUTEX_WAKE_PRIVATE: u64 = FUTEX_WAKE | FUTEX_PRIVATE_FLAG;
/// `ARCH_SET_FS`.
pub const ARCH_SET_FS: u64 = 0x1002;
/// `ARCH_GET_FS`.
pub const ARCH_GET_FS: u64 = 0x1003;

/// Split a futex operation into its command and flags.
///
/// Only `FUTEX_WAIT`/`FUTEX_WAKE` with the optional private flag are
/// understood; every other operation word is reported as unsupported
/// (`ENOSYS`) instead of being silently truncated into a known command.
fn futex_command(operation: u64) -> Result<(u64, u64), i64> {
    match operation {
        FUTEX_WAIT => Ok((FUTEX_WAIT, 0)),
        FUTEX_WAKE => Ok((FUTEX_WAKE, 0)),
        FUTEX_WAIT_PRIVATE => Ok((FUTEX_WAIT, FUTEX_PRIVATE_FLAG)),
        FUTEX_WAKE_PRIVATE => Ok((FUTEX_WAKE, FUTEX_PRIVATE_FLAG)),
        _ => Err(errno::ENOSYS),
    }
}

/// Physical address of a user futex word, rejecting a word that straddles a page.
fn futex_word(context: &LinuxContext<'_>, address: u64) -> Result<u64, i64> {
    let space = context.space()?;
    let start = addrspace::translate_user(space, address).ok_or(errno::EFAULT)?;
    let end = addrspace::translate_user(space, address + 3).ok_or(errno::EFAULT)?;
    if end != start + 3 {
        return Err(errno::EFAULT);
    }
    Ok(start)
}

/// `futex` (NR 202).
fn futex_op(args: &[u64; 6], context: &mut LinuxContext<'_>) -> Result<Outcome, i64> {
    let (command, _flags) = futex_command(args[1])?;
    match command {
        FUTEX_WAIT => futex_wait(args, context),
        FUTEX_WAKE => futex_wake(args, context),
        _ => Err(errno::ENOSYS),
    }
}

fn futex_wait(args: &[u64; 6], context: &mut LinuxContext<'_>) -> Result<Outcome, i64> {
    let expected = u32::try_from(args[2]).map_err(|_| errno::EINVAL)?;
    let word = futex_word(context, args[0])?;
    // Replay path: only a wake/timeout can make the call return. A fresh call
    // starts with `None` because the entry layer leaves the reason to us.
    match process::take_wake_reason() {
        process::WakeReason::None => {}
        process::WakeReason::Ready => return Ok(Outcome::Done(0)),
        process::WakeReason::Timeout => return Ok(Outcome::Done(-errno::ETIMEDOUT)),
        process::WakeReason::Cancelled => return Ok(Outcome::Done(-errno::EINTR)),
        process::WakeReason::Destroyed => return Ok(Outcome::Done(-errno::EBADF)),
        process::WakeReason::PeerClosed => return Ok(Outcome::Done(-errno::ENOTCONN)),
    }
    let mut current = [0u8; 4];
    copy_in(context, args[0], &mut current)?;
    if u32::from_le_bytes(current) != expected {
        // The value changed before we slept: Linux reports `EAGAIN`.
        return Ok(Outcome::Done(-errno::EAGAIN));
    }
    let deadline = if args[3] == 0 {
        None
    } else {
        let (seconds, nanos) = read_timespec(context, args[3])?;
        let total = (seconds as u128)
            .checked_mul(NANOS_PER_SECOND)
            .and_then(|value| value.checked_add(nanos as u128))
            .ok_or(errno::EOVERFLOW)?;
        let ticks = nanos_to_ticks_ceil(total, crate::time::tick_hz())?;
        if ticks == 0 {
            // A zero (or sub-tick) relative timeout expires immediately.
            return Ok(Outcome::Done(-errno::ETIMEDOUT));
        }
        Some(crate::time::monotonic_ticks().saturating_add(ticks))
    };
    Ok(Outcome::FutexWait { word, deadline })
}

fn futex_wake(args: &[u64; 6], context: &mut LinuxContext<'_>) -> Result<Outcome, i64> {
    let word = futex_word(context, args[0])?;
    let count = usize::try_from(args[2]).unwrap_or(usize::MAX);
    let woken = crate::futex::wake(word, count);
    Ok(Outcome::Done(woken as i64))
}

/// `arch_prctl` (NR 158): only the FS base is meaningful for the personality.
fn arch_prctl(args: &[u64; 6], context: &mut LinuxContext<'_>) -> Result<Outcome, i64> {
    match args[0] {
        ARCH_SET_FS => {
            process::set_current_fs_base(args[1]).map_err(|_| errno::ESRCH)?;
            Ok(Outcome::Done(0))
        }
        ARCH_GET_FS => {
            let base = process::current_fs_base();
            copy_out(context, args[1], &base.to_le_bytes())?;
            Ok(Outcome::Done(0))
        }
        _ => Err(errno::EINVAL),
    }
}

/// `set_tid_address` (NR 218).
///
/// Records the clear-child-tid address on the current process and returns the
/// calling tid. The tid is written to user memory when the thread exits (the
/// process layer owns that), not here.
fn set_tid_address(args: &[u64; 6]) -> Result<Outcome, i64> {
    let pid = process::set_current_clear_child_tid(args[0]);
    if pid == 0 {
        // No current user process: report ESRCH instead of fabricating a tid.
        return Err(errno::ESRCH);
    }
    Ok(Outcome::Done(pid as i64))
}

#[cfg(test)]
mod m8f_tests {
    use super::*;

    #[test]
    fn futex_operations_accept_only_wait_and_wake_with_the_private_flag() {
        assert_eq!(futex_command(FUTEX_WAIT), Ok((FUTEX_WAIT, 0)));
        assert_eq!(futex_command(FUTEX_WAKE), Ok((FUTEX_WAKE, 0)));
        assert_eq!(
            futex_command(FUTEX_WAIT | FUTEX_PRIVATE_FLAG),
            Ok((FUTEX_WAIT, FUTEX_PRIVATE_FLAG))
        );
        assert_eq!(
            futex_command(FUTEX_WAKE | FUTEX_PRIVATE_FLAG),
            Ok((FUTEX_WAKE, FUTEX_PRIVATE_FLAG))
        );
        // Unknown commands and unknown flag bits are unsupported.
        assert_eq!(futex_command(2), Err(errno::ENOSYS));
        assert_eq!(futex_command(FUTEX_WAIT | 64), Err(errno::ENOSYS));
        assert_eq!(
            futex_command(FUTEX_WAIT | FUTEX_PRIVATE_FLAG | 64),
            Err(errno::ENOSYS)
        );
    }

    #[test]
    fn unsupported_futex_commands_and_bad_arguments_are_rejected() {
        let mut table = FdTable::new();
        let mut context = LinuxContext::new(&mut table, 0, None);
        assert_eq!(
            dispatch(NR_FUTEX, &[0, 2, 0, 0, 0, 0], &mut context),
            Outcome::Done(-errno::ENOSYS)
        );
        // A wait without an address space cannot translate its word.
        assert_eq!(
            dispatch(NR_FUTEX, &[0x1000, FUTEX_WAIT, 0, 0, 0, 0], &mut context),
            Outcome::Done(-errno::EFAULT)
        );
        // The expected value must fit in the Linux 32-bit futex word.
        assert_eq!(
            dispatch(
                NR_FUTEX,
                &[0x1000, FUTEX_WAIT, u64::from(u32::MAX) + 1, 0, 0, 0],
                &mut context
            ),
            Outcome::Done(-errno::EINVAL)
        );
        // A wake with no translatable word is EFAULT as well.
        assert_eq!(
            dispatch(NR_FUTEX, &[0x1000, FUTEX_WAKE, 1, 0, 0, 0], &mut context),
            Outcome::Done(-errno::EFAULT)
        );
    }

    #[test]
    fn arch_prctl_rejects_unknown_codes() {
        let mut table = FdTable::new();
        let mut context = LinuxContext::new(&mut table, 0, None);
        assert_eq!(
            dispatch(NR_ARCH_PRCTL, &[0xDEAD, 0, 0, 0, 0, 0], &mut context),
            Outcome::Done(-errno::EINVAL)
        );
    }

    #[test]
    fn set_tid_address_needs_a_current_process() {
        let _guard = crate::object::test_lock();
        let mut table = FdTable::new();
        let mut context = LinuxContext::new(&mut table, 0, None);
        // The host build has no current process; the call must report ESRCH
        // rather than fabricate a tid.
        assert_eq!(
            dispatch(NR_SET_TID_ADDRESS, &[0, 0, 0, 0, 0, 0], &mut context),
            Outcome::Done(-errno::ESRCH)
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signal_syscall_numbers_match_linux_x86_64() {
        assert_eq!(NR_RT_SIGACTION, 13);
        assert_eq!(NR_RT_SIGPROCMASK, 14);
        assert_eq!(NR_RT_SIGRETURN, 15);
        assert_eq!(NR_KILL, 62);
        assert_eq!(NR_TGKILL, 234);
    }

    #[test]
    fn rt_sigaction_and_procmask_validate_their_fixed_arguments() {
        // `dispatch` drains the stale wake reason through the process table;
        // the process tests hold the crate test lock while they do the same.
        let _guard = crate::object::test_lock();
        let mut table = FdTable::new();
        let mut context = LinuxContext::new(&mut table, 0, None);
        // sigsetsize must be sizeof(sigset_t).
        assert_eq!(
            dispatch(NR_RT_SIGACTION, &[10, 0, 0, 4, 0, 0], &mut context),
            Outcome::Done(-errno::EINVAL)
        );
        // Signal numbers are the standard 1..=31 range.
        assert_eq!(
            dispatch(NR_RT_SIGACTION, &[0, 0, 0, 8, 0, 0], &mut context),
            Outcome::Done(-errno::EINVAL)
        );
        assert_eq!(
            dispatch(NR_RT_SIGACTION, &[32, 0, 0, 8, 0, 0], &mut context),
            Outcome::Done(-errno::EINVAL)
        );
        assert_eq!(
            dispatch(NR_RT_SIGPROCMASK, &[0, 0, 0, 16, 0, 0], &mut context),
            Outcome::Done(-errno::EINVAL)
        );
        // Only SIG_BLOCK/SIG_UNBLOCK/SIG_SETMASK exist.
        assert_eq!(
            dispatch(NR_RT_SIGPROCMASK, &[9, 0, 0, 8, 0, 0], &mut context),
            Outcome::Done(-errno::EINVAL)
        );
    }

    #[test]
    fn kill_and_tgkill_only_accept_the_current_process() {
        // `dispatch` reads the process table, so serialise with the process
        // and object tests through the shared crate test lock.
        let _guard = crate::object::test_lock();
        let mut table = FdTable::new();
        let mut context = LinuxContext::new(&mut table, 0, None);
        // A different pid/tid is `ESRCH`, never a fabricated delivery.
        assert_eq!(
            dispatch(NR_KILL, &[1234, 10, 0, 0, 0, 0], &mut context),
            Outcome::Done(-errno::ESRCH)
        );
        assert_eq!(
            dispatch(NR_KILL, &[99, 10, 0, 0, 0, 0], &mut context),
            Outcome::Done(-errno::ESRCH)
        );
        assert_eq!(
            dispatch(NR_TGKILL, &[1234, 1234, 10, 0, 0, 0], &mut context),
            Outcome::Done(-errno::ESRCH)
        );
        // A mismatched tgid/tid pair is EINVAL, as Linux refuses it outright.
        assert_eq!(
            dispatch(NR_TGKILL, &[1, 2, 10, 0, 0, 0], &mut context),
            Outcome::Done(-errno::EINVAL)
        );
        // Bad signal numbers never reach the process table.
        assert_eq!(
            dispatch(NR_KILL, &[1234, 99, 0, 0, 0, 0], &mut context),
            Outcome::Done(-errno::EINVAL)
        );
        // The stop family is refused with ENOSYS before the pid is resolved.
        assert_eq!(
            dispatch(NR_KILL, &[1234, 19, 0, 0, 0, 0], &mut context),
            Outcome::Done(-errno::ENOSYS)
        );
        // kill(-1) with no children is ESRCH, not a silent success.
        assert_eq!(
            dispatch(NR_KILL, &[u64::MAX, 10, 0, 0, 0, 0], &mut context),
            Outcome::Done(-errno::ESRCH)
        );
        // Negative pids other than -1 are refused.
        assert_eq!(
            dispatch(
                NR_KILL,
                &[2u64.wrapping_neg(), 10, 0, 0, 0, 0],
                &mut context
            ),
            Outcome::Done(-errno::EINVAL)
        );
        // The stop family is routed to `ENOSYS` before any state is touched.
        assert!(is_stop_family(19));
        assert!(is_stop_family(20));
        assert!(is_stop_family(21));
        assert!(is_stop_family(22));
        assert!(!is_stop_family(1));
        assert!(!is_stop_family(9));
        assert!(!is_stop_family(31));
    }

    #[test]
    fn wait4_validates_its_arguments_before_touching_the_process_table() {
        // `wait4` walks the process table, so serialise like the process tests.
        let _guard = crate::object::test_lock();
        let mut table = FdTable::new();
        let mut context = LinuxContext::new(&mut table, 0, None);
        // options other than WNOHANG are refused.
        assert_eq!(
            dispatch(NR_WAIT4, &[u64::MAX, 0, 2, 0, 0, 0], &mut context),
            Outcome::Done(-errno::EINVAL)
        );
        // rusage must be NULL.
        assert_eq!(
            dispatch(NR_WAIT4, &[u64::MAX, 0, 0, 0x2000, 0, 0], &mut context),
            Outcome::Done(-errno::EINVAL)
        );
        // pid 0 (process group) is unsupported.
        assert_eq!(
            dispatch(NR_WAIT4, &[0, 0, 0, 0, 0, 0], &mut context),
            Outcome::Done(-errno::EINVAL)
        );
        // No current process / no such child: ECHILD, never a fabricated pid.
        assert_eq!(
            dispatch(NR_WAIT4, &[u64::MAX, 0, 0, 0, 0, 0], &mut context),
            Outcome::Done(-errno::ECHILD)
        );
        assert_eq!(
            dispatch(NR_WAIT4, &[7, 0, u64::from(WNOHANG), 0, 0, 0], &mut context),
            Outcome::Done(-errno::ECHILD)
        );
    }

    #[test]
    fn rt_sigreturn_needs_a_current_ring3_frame() {
        // `dispatch` reads the process table, so serialise with the process
        // and object tests through the shared crate test lock.
        let _guard = crate::object::test_lock();
        let mut table = FdTable::new();
        let mut context = LinuxContext::new(&mut table, 0, None);
        assert_eq!(
            dispatch(NR_RT_SIGRETURN, &[0; 6], &mut context),
            Outcome::Done(-errno::EFAULT)
        );
    }

    #[test]
    fn unimplemented_calls_return_enosys_and_are_counted() {
        let mut table = FdTable::new();
        let mut context = LinuxContext::new(&mut table, 0, None);
        let before = enosys_count();
        let outcome = dispatch(999, &[0; 6], &mut context);
        assert_eq!(outcome, Outcome::Done(-errno::ENOSYS));
        assert_eq!(enosys_count(), before + 1);
    }

    #[test]
    fn descriptor_calls_reject_missing_descriptors() {
        let mut table = FdTable::new();
        let mut context = LinuxContext::new(&mut table, 0, None);
        assert_eq!(
            dispatch(NR_CLOSE, &[3, 0, 0, 0, 0, 0], &mut context),
            Outcome::Done(-errno::EBADF)
        );
        assert_eq!(
            dispatch(NR_READ, &[3, 0x1000, 8, 0, 0, 0], &mut context),
            Outcome::Done(-errno::EBADF)
        );
        assert_eq!(
            dispatch(NR_SHUTDOWN, &[3, 1, 0, 0, 0, 0], &mut context),
            Outcome::Done(-errno::EBADF)
        );
        assert_eq!(
            dispatch(NR_GETSOCKNAME, &[3, 0x1000, 0x1004, 0, 0, 0], &mut context),
            Outcome::Done(-errno::EBADF)
        );
    }

    #[test]
    fn unsupported_families_and_types_are_reported_honestly() {
        let mut table = FdTable::new();
        let mut context = LinuxContext::new(&mut table, 0, None);
        assert_eq!(
            dispatch(
                NR_SOCKET,
                &[99, SOCK_STREAM as u64, 0, 0, 0, 0],
                &mut context
            ),
            Outcome::Done(-errno::EAFNOSUPPORT)
        );
        assert_eq!(
            dispatch(
                NR_SOCKET,
                &[address::AF_INET as u64, 3, 0, 0, 0, 0],
                &mut context
            ),
            Outcome::Done(-errno::EPROTONOSUPPORT)
        );
        assert_eq!(
            dispatch(
                NR_SOCKET,
                &[
                    address::AF_INET as u64,
                    u64::from(SOCK_STREAM | SOCK_NONBLOCK),
                    0,
                    0,
                    0,
                    0
                ],
                &mut context
            ),
            Outcome::Done(-errno::EINVAL)
        );
        assert_eq!(
            dispatch(
                NR_SOCKET,
                &[address::AF_INET as u64, SOCK_STREAM as u64, 6, 0, 0, 0],
                &mut context
            ),
            Outcome::Done(-errno::EPROTONOSUPPORT)
        );
    }

    #[test]
    fn socketpair_checks_its_output_pointer_before_creating_sockets() {
        let mut table = FdTable::new();
        let mut context = LinuxContext::new(&mut table, 0, None);
        assert_eq!(
            dispatch(
                NR_SOCKETPAIR,
                &[address::AF_UNIX as u64, SOCK_STREAM as u64, 0, 0, 0, 0],
                &mut context
            ),
            Outcome::Done(-errno::EFAULT)
        );
    }

    #[test]
    fn shutdown_rejects_an_invalid_how() {
        let mut table = FdTable::new();
        let mut context = LinuxContext::new(&mut table, 0, None);
        assert_eq!(
            dispatch(NR_SHUTDOWN, &[3, 3, 0, 0, 0, 0], &mut context),
            Outcome::Done(-errno::EBADF)
        );
    }

    #[test]
    fn getpid_and_identity_calls_are_available_without_descriptors() {
        // `getpid` reads the process table; serialise with the process tests.
        let _guard = crate::object::test_lock();
        let mut table = FdTable::new();
        let mut context = LinuxContext::new(&mut table, 0, None);
        assert!(matches!(
            dispatch(NR_GETPID, &[0; 6], &mut context),
            Outcome::Done(value) if value >= 0
        ));
        assert_eq!(dispatch(NR_GETUID, &[0; 6], &mut context), Outcome::Done(0));
        assert_eq!(dispatch(NR_GETGID, &[0; 6], &mut context), Outcome::Done(0));
        assert_eq!(
            dispatch(NR_GETEUID, &[0; 6], &mut context),
            Outcome::Done(0)
        );
        assert_eq!(
            dispatch(NR_GETEGID, &[0; 6], &mut context),
            Outcome::Done(0)
        );
    }

    #[test]
    fn the_address_layer_is_used_by_the_dispatch() {
        let console = crate::object::create_with_payload(ObjectKind::Console, 0).unwrap();
        let mut table = FdTable::new();
        table.install_console(console).unwrap();
        {
            let mut context = LinuxContext::new(&mut table, 0, None);
            // A missing socket descriptor is reported before any address is
            // touched, so the error is EBADF and not EFAULT.
            assert_eq!(
                dispatch(NR_BIND, &[3, 0x1000, 16, 0, 0, 0], &mut context),
                Outcome::Done(-errno::EBADF)
            );
            // The console descriptor is a real object, but not a socket.
            assert_eq!(
                dispatch(NR_BIND, &[0, 0x1000, 16, 0, 0, 0], &mut context),
                Outcome::Done(-errno::ENOTSOCK)
            );
        }
        table.close(0).ok();
        table.close(1).ok();
        table.close(2).ok();
    }

    #[test]
    fn linux_syscall_numbers_match_the_x86_64_abi() {
        assert_eq!(NR_READ, 0);
        assert_eq!(NR_WRITE, 1);
        assert_eq!(NR_CLOSE, 3);
        assert_eq!(NR_MMAP, 9);
        assert_eq!(NR_MPROTECT, 10);
        assert_eq!(NR_MUNMAP, 11);
        assert_eq!(NR_BRK, 12);
        assert_eq!(NR_DUP, 32);
        assert_eq!(NR_DUP2, 33);
        assert_eq!(NR_GETPID, 39);
        assert_eq!(NR_SOCKET, 41);
        assert_eq!(NR_CONNECT, 42);
        assert_eq!(NR_ACCEPT, 43);
        assert_eq!(NR_SENDTO, 44);
        assert_eq!(NR_RECVFROM, 45);
        // `shutdown` is 48; 56 is `clone` and is deliberately not implemented.
        assert_eq!(NR_SHUTDOWN, 48);
        assert_eq!(NR_BIND, 49);
        assert_eq!(NR_LISTEN, 50);
        assert_eq!(NR_GETSOCKNAME, 51);
        assert_eq!(NR_GETPEERNAME, 52);
        assert_eq!(NR_SOCKETPAIR, 53);
        assert_eq!(NR_SETSOCKOPT, 54);
        assert_eq!(NR_GETSOCKOPT, 55);
        assert_eq!(NR_EXIT, 60);
        assert_eq!(NR_GETUID, 102);
        assert_eq!(NR_GETEUID, 104);
        assert_eq!(NR_GETGID, 107);
        assert_eq!(NR_GETEGID, 108);
        assert_eq!(NR_EXIT_GROUP, 231);
        assert_eq!(NR_OPENAT, 257);
        assert_eq!(NR_ACCEPT4, 288);
    }

    #[test]
    fn shutdown_is_routed_through_48_and_clone_stays_unimplemented() {
        let mut table = FdTable::new();
        let mut context = LinuxContext::new(&mut table, 0, None);
        // Number 48 reaches `shutdown`; a missing descriptor reports EBADF.
        assert_eq!(
            dispatch(NR_SHUTDOWN, &[3, 1, 0, 0, 0, 0], &mut context),
            Outcome::Done(-errno::EBADF)
        );
        // 56 is `clone`, outside this stage: it must be counted and refused.
        let before = enosys_count();
        assert_eq!(
            dispatch(56, &[3, 1, 0, 0, 0, 0], &mut context),
            Outcome::Done(-errno::ENOSYS)
        );
        assert_eq!(enosys_count(), before + 1);
    }

    #[test]
    fn dup_returns_the_lowest_free_descriptor_and_shares_the_object() {
        let _guard = crate::object::test_lock();
        let console = crate::object::create_with_payload(ObjectKind::Console, 0).unwrap();
        let max_fds = crate::compat::linux::fd::MAX_FDS;
        let mut table = FdTable::new();
        table.install_console(console).unwrap();
        table.set_cloexec(1, true).unwrap();
        {
            let mut context = LinuxContext::new(&mut table, 0, None);
            // fd 3 is the lowest free descriptor, and `dup` clears FD_CLOEXEC.
            assert_eq!(
                dispatch(NR_DUP, &[0, 0, 0, 0, 0, 0], &mut context),
                Outcome::Done(3)
            );
            assert_eq!(
                dispatch(NR_DUP, &[0, 0, 0, 0, 0, 0], &mut context),
                Outcome::Done(4)
            );
            // A missing source descriptor is EBADF.
            assert_eq!(
                dispatch(NR_DUP, &[99, 0, 0, 0, 0, 0], &mut context),
                Outcome::Done(-errno::EBADF)
            );
        }
        let first_copy = table.get(3).expect("fd 3 is installed");
        assert_eq!(first_copy.object, console);
        assert!(!first_copy.cloexec, "dup must clear FD_CLOEXEC");
        assert_eq!(table.get(4).expect("fd 4 is installed").object, console);
        // Fill every remaining slot; the next `dup` reports EMFILE.
        {
            let mut context = LinuxContext::new(&mut table, 0, None);
            for _ in 5..max_fds {
                assert!(matches!(
                    dispatch(NR_DUP, &[0, 0, 0, 0, 0, 0], &mut context),
                    Outcome::Done(fd) if fd >= 5
                ));
            }
            assert_eq!(
                dispatch(NR_DUP, &[0, 0, 0, 0, 0, 0], &mut context),
                Outcome::Done(-errno::EMFILE)
            );
        }
        for fd in 0..max_fds {
            table.close(fd as u32).ok();
        }
        let _ = crate::object::release_object(console);
    }

    #[test]
    fn dup2_replaces_the_target_and_rejects_bad_descriptors() {
        let _guard = crate::object::test_lock();
        let first = crate::object::create_with_payload(ObjectKind::Console, 0).unwrap();
        let second = crate::object::create_with_payload(ObjectKind::Console, 0).unwrap();
        let max_fds = crate::compat::linux::fd::MAX_FDS;
        let mut table = FdTable::new();
        table.install_console(first).unwrap();
        // Occupy fd 3 with a different object so `dup2` has something to close.
        table.insert(FdEntry::new(second, false)).unwrap();
        table.set_cloexec(1, true).unwrap();
        {
            let mut context = LinuxContext::new(&mut table, 0, None);
            // Replacing fd 3 returns 3 and closes the previous object.
            assert_eq!(
                dispatch(NR_DUP2, &[0, 3, 0, 0, 0, 0], &mut context),
                Outcome::Done(3)
            );
            // `dup2(fd, fd)` is a successful no-op.
            assert_eq!(
                dispatch(NR_DUP2, &[0, 0, 0, 0, 0, 0], &mut context),
                Outcome::Done(0)
            );
            // A copy at an explicit descriptor clears FD_CLOEXEC.
            assert_eq!(
                dispatch(NR_DUP2, &[1, 5, 0, 0, 0, 0], &mut context),
                Outcome::Done(5)
            );
            // Bad `oldfd`, and an out-of-range `newfd`, both report EBADF...
            assert_eq!(
                dispatch(NR_DUP2, &[99, 3, 0, 0, 0, 0], &mut context),
                Outcome::Done(-errno::EBADF)
            );
            assert_eq!(
                dispatch(NR_DUP2, &[0, max_fds as u64, 0, 0, 0, 0], &mut context),
                Outcome::Done(-errno::EBADF)
            );
        }
        // ...and neither touched the table.
        assert_eq!(table.get(3).expect("fd 3").object, first);
        let copy = table.get(5).expect("fd 5 is installed");
        assert_eq!(copy.object, first);
        assert!(!copy.cloexec, "dup2 must clear FD_CLOEXEC");
        for fd in [0u32, 1, 2, 3, 5] {
            table.close(fd).ok();
        }
        let _ = crate::object::release_object(first);
        let _ = crate::object::release_object(second);
    }

    #[test]
    fn send_would_block_reports_a_wait_instead_of_eagain() {
        // No O_NONBLOCK model in this stage: a full socket must block, exactly
        // like recv/accept, and never fabricate EAGAIN.
        assert_eq!(
            send_outcome(Err(NetError::WouldBlock), Some(7)),
            Ok(Outcome::Wait {
                object: 7,
                deadline: None
            })
        );
        assert_eq!(
            send_outcome(Err(NetError::WouldBlock), None),
            Err(errno::EBADF)
        );
        assert_eq!(send_outcome(Ok(5), None), Ok(Outcome::Done(5)));
        assert_eq!(
            send_outcome(Err(NetError::NotConnected), Some(7)),
            Err(errno::ENOTCONN)
        );
    }

    #[test]
    fn a_failed_accept_address_writeback_closes_the_installed_descriptor() {
        let _guard = crate::object::test_lock();
        let object = crate::object::create_with_payload(ObjectKind::Event, 0).unwrap();
        let mut table = FdTable::new();
        let fd = table.insert(FdEntry::new(object, false)).unwrap();
        let mut context = LinuxContext::new(&mut table, 0, None);
        // Simulate the write-back failure the accept path can hit after the
        // descriptor is already installed (EFAULT here).
        assert_eq!(
            close_on_failure(&mut context, fd, Err(errno::EFAULT)),
            Err(errno::EFAULT)
        );
        assert!(
            context.fds.get(fd).is_err(),
            "the accepted descriptor must be closed again"
        );
        assert_eq!(crate::object::object_refs(object), Some(1));
        drop(context);
        let _ = crate::object::release_object(object);
    }

    #[test]
    fn address_lengths_are_clamped_instead_of_rejected() {
        assert_eq!(clamped_wire_length(16), Ok(16));
        assert_eq!(clamped_wire_length(2), Ok(2));
        assert_eq!(clamped_wire_length(128), Ok(address::SOCKADDR_MAX));
        assert_eq!(clamped_wire_length(1), Err(errno::EINVAL));
        assert_eq!(clamped_wire_capacity(28), Ok(28));
        assert_eq!(clamped_wire_capacity(128), Ok(address::SOCKADDR_MAX));
        assert_eq!(clamped_wire_capacity(0), Err(errno::EINVAL));
    }

    #[test]
    fn an_unbound_socket_reports_a_zeroed_address_of_its_family() {
        let mut buffer = [0xAAu8; address::SOCKADDR_MAX];
        let inet = unnamed_address(address::AF_INET);
        assert_eq!(address::write(&inet, &mut buffer[..16]), Ok(16));
        assert_eq!(&buffer[..2], &address::AF_INET.to_ne_bytes());
        assert_eq!(&buffer[4..8], &[0, 0, 0, 0]);

        let inet6 = unnamed_address(address::AF_INET6);
        assert_eq!(address::write(&inet6, &mut buffer[..28]), Ok(28));
        assert_eq!(&buffer[..2], &address::AF_INET6.to_ne_bytes());
        assert_eq!(&buffer[8..24], &[0u8; 16]);

        let unix = unnamed_address(address::AF_UNIX);
        assert_eq!(address::write(&unix, &mut buffer[..2]), Ok(2));
        assert_eq!(&buffer[..2], &address::AF_UNIX.to_ne_bytes());
    }

    #[test]
    fn the_descriptor_table_remembers_the_socket_family() {
        let _guard = crate::object::test_lock();
        let object = crate::object::create_with_payload(ObjectKind::Event, 0).unwrap();
        let mut table = FdTable::new();
        let fd = table
            .insert(FdEntry::new_socket(object, false, address::AF_INET6))
            .unwrap();
        let context = LinuxContext::new(&mut table, 0, None);
        assert_eq!(socket_family(&context, fd), Ok(address::AF_INET6));
        assert_eq!(socket_family(&context, fd + 1), Err(errno::EBADF));
        drop(context);
        table.close(fd).ok();
        let _ = crate::object::release_object(object);
    }

    /// `brk`/`mmap`/`munmap`/`mprotect` are routed and validate their arguments
    /// before they need a real address space.
    #[test]
    fn memory_calls_are_routed_and_validate_their_arguments() {
        let mut table = FdTable::new();
        let mut context = LinuxContext::new(&mut table, 0, None);

        // `brk(0)` reports the current break; an uninitialised table has none.
        assert_eq!(
            dispatch(NR_BRK, &[0, 0, 0, 0, 0, 0], &mut context),
            Outcome::Done(0)
        );

        // A zero-length mapping is rejected before the space is consulted.
        assert_eq!(
            dispatch(
                NR_MMAP,
                &[
                    0,
                    0,
                    u64::from(memory::PROT_READ),
                    memory::MAP_PRIVATE | memory::MAP_ANONYMOUS,
                    u64::MAX,
                    0
                ],
                &mut context
            ),
            Outcome::Done(-errno::EINVAL)
        );

        // A non-anonymous mapping without a valid descriptor reports EBADF.
        assert_eq!(
            dispatch(
                NR_MMAP,
                &[
                    0,
                    memory::PAGE_SIZE,
                    u64::from(memory::PROT_READ),
                    memory::MAP_PRIVATE,
                    u64::MAX,
                    0
                ],
                &mut context
            ),
            Outcome::Done(-errno::EBADF)
        );

        // Both range calls reject unaligned addresses.
        assert_eq!(
            dispatch(
                NR_MUNMAP,
                &[memory::MMAP_BASE + 1, memory::PAGE_SIZE, 0, 0, 0, 0],
                &mut context
            ),
            Outcome::Done(-errno::EINVAL)
        );
        assert_eq!(
            dispatch(
                NR_MPROTECT,
                &[
                    memory::MMAP_BASE + 1,
                    memory::PAGE_SIZE,
                    u64::from(memory::PROT_READ),
                    0,
                    0,
                    0
                ],
                &mut context
            ),
            Outcome::Done(-errno::EINVAL)
        );
    }

    // -----------------------------------------------------------------------
    // files: openat / read / write
    // -----------------------------------------------------------------------

    #[test]
    fn file_flags_are_split_into_the_supported_directions() {
        let read = parse_file_flags(O_RDONLY).expect("read-only");
        assert!(read.read && !read.write && !read.create && !read.cloexec);
        let write = parse_file_flags(O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC).expect("write");
        assert!(!write.read && write.write && write.create && write.truncate && write.cloexec);
        let both = parse_file_flags(O_RDWR | O_EXCL).expect("read-write");
        assert!(both.read && both.write && both.exclusive);
        // `O_TRUNC` on a read-only descriptor is ignored, like Linux.
        let read_trunc = parse_file_flags(O_RDONLY | O_TRUNC).expect("read-only truncate");
        assert!(read_trunc.read && !read_trunc.truncate);
        assert_eq!(parse_file_flags(0o4000), Err(errno::EINVAL));
        assert_eq!(parse_file_flags(0o3), Err(errno::EINVAL));
    }

    #[test]
    fn only_the_frozen_creation_modes_are_accepted() {
        assert_eq!(file_mode_is_supported(O_RDONLY, 0), Ok(()));
        assert_eq!(file_mode_is_supported(O_CREAT, 0o644), Ok(()));
        assert_eq!(file_mode_is_supported(O_CREAT, 0o600), Ok(()));
        assert_eq!(file_mode_is_supported(O_CREAT, 0o755), Err(errno::EINVAL));
        assert_eq!(file_mode_is_supported(O_CREAT, 0o777), Err(errno::EINVAL));
    }

    #[test]
    fn the_m8a_file_slice_only_resolves_absolute_paths() {
        assert_eq!(check_absolute_path(b"/m8a-files.bin"), Ok(()));
        assert_eq!(check_absolute_path(b""), Err(errno::ENOENT));
        assert_eq!(check_absolute_path(b"m8a-files.bin"), Err(errno::ENOENT));
        assert_eq!(check_absolute_path(b"/bad\0name"), Err(errno::EINVAL));
    }

    #[test]
    fn vfs_errors_map_onto_linux_errno_values() {
        use crate::vfs::VfsError;
        let cases = [
            (VfsError::NotFound, errno::ENOENT),
            (VfsError::NotDirectory, errno::ENOTDIR),
            (VfsError::IsDirectory, errno::EISDIR),
            (VfsError::AlreadyExists, errno::EEXIST),
            (VfsError::ReadOnly, errno::EROFS),
            (VfsError::BadPath, errno::ENOENT),
            (VfsError::NameTooLong, errno::ENAMETOOLONG),
            (VfsError::Quota, errno::ENOSPC),
            (VfsError::BadOffset, errno::EINVAL),
            (VfsError::PermissionDenied, errno::EACCES),
            (VfsError::WouldBlock, errno::EAGAIN),
            (VfsError::NotSupported, errno::EOPNOTSUPP),
            (VfsError::Corrupt, errno::EIO),
            (VfsError::Io, errno::EIO),
            (VfsError::Timeout, errno::EIO),
            (VfsError::NoMemory, errno::ENOMEM),
            (VfsError::Busy, errno::EBUSY),
            (VfsError::NotEmpty, errno::ENOTEMPTY),
        ];
        for (error, expected) in cases {
            assert_eq!(vfs_errno(error), expected, "{error:?}");
        }
        // A descriptor without the requested direction is EBADF, not EACCES.
        assert_eq!(file_io_errno(VfsError::PermissionDenied), errno::EBADF);
    }

    #[test]
    fn openat_checks_relative_dirfds_before_any_path_work() {
        let _guard = object::test_lock();
        let mut table = FdTable::new();
        {
            let mut context = LinuxContext::new(&mut table, 0, None);
            // No descriptors installed: 0, 999 and an out-of-range value are all
            // invalid Linux descriptors, so `openat` reports EBADF for them.
            for dirfd in [0u64, 999, u64::MAX] {
                assert_eq!(
                    dispatch(NR_OPENAT, &[dirfd, 0x1000, O_RDONLY, 0, 0, 0], &mut context),
                    Outcome::Done(-errno::EBADF),
                    "dirfd {dirfd}"
                );
            }
        }

        // A valid descriptor that is not AT_FDCWD cannot be used for relative
        // resolution yet, so the call reports that honestly.
        let console = object::create_with_payload(ObjectKind::Console, 0).expect("console object");
        table.install_console(console).expect("console descriptors");
        let mut context = LinuxContext::new(&mut table, 0, None);
        assert_eq!(
            dispatch(NR_OPENAT, &[0, 0x1000, O_RDONLY, 0, 0, 0], &mut context),
            Outcome::Done(-errno::EOPNOTSUPP)
        );
        drop(context);
        table.close(0).ok();
        table.close(1).ok();
        table.close(2).ok();
        object::release_object(console).ok();
    }

    #[test]
    fn openat_needs_an_address_space_to_read_its_path() {
        let mut table = FdTable::new();
        let mut context = LinuxContext::new(&mut table, 0, None);
        assert_eq!(
            dispatch(
                NR_OPENAT,
                &[AT_FDCWD as u64, 0x1000, O_RDONLY, 0, 0, 0],
                &mut context
            ),
            Outcome::Done(-errno::EFAULT)
        );
    }

    struct FakeFileIo {
        reads: usize,
        writes: usize,
    }

    impl FileIo for FakeFileIo {
        fn read(&mut self, _open: OpenId, out: &mut [u8]) -> Result<usize, VfsError> {
            self.reads += 1;
            Ok(out.len())
        }

        fn write(&mut self, _open: OpenId, _data: &[u8]) -> Result<usize, VfsError> {
            self.writes += 1;
            Ok(0)
        }
    }

    #[test]
    fn file_io_without_an_address_space_fails_before_any_io() {
        let mut table = FdTable::new();
        let context = LinuxContext::new(&mut table, 0, None);
        let mut io = FakeFileIo {
            reads: 0,
            writes: 0,
        };
        assert_eq!(
            file_read(&context, &mut io, OpenId::from_raw(3), 0x1000, 8),
            Err(errno::EFAULT)
        );
        assert_eq!(
            file_write(&context, &mut io, OpenId::from_raw(3), 0x1000, 8),
            Err(errno::EFAULT)
        );
        assert_eq!((io.reads, io.writes), (0, 0), "no I/O before validation");
    }

    #[test]
    fn zero_length_file_ios_complete_without_io() {
        let mut table = FdTable::new();
        let context = LinuxContext::new(&mut table, 0, None);
        let mut io = FakeFileIo {
            reads: 0,
            writes: 0,
        };
        assert_eq!(
            file_read(&context, &mut io, OpenId::from_raw(3), 0, 0),
            Ok(Outcome::Done(0))
        );
        assert_eq!(
            file_write(&context, &mut io, OpenId::from_raw(3), 0, 0),
            Ok(Outcome::Done(0))
        );
        assert_eq!((io.reads, io.writes), (0, 0));
    }

    #[test]
    fn dup_shares_a_file_description_while_a_new_open_gets_its_own() {
        let _guard = object::test_lock();
        let first = object::create_with_payload(ObjectKind::File, 7).expect("file object");
        let second = object::create_with_payload(ObjectKind::File, 8).expect("file object");
        let mut table = FdTable::new();
        let fd = table
            .insert(FdEntry::new(first, false))
            .expect("descriptor");
        let copy = table.dup(fd).expect("dup");
        assert_eq!(
            table.get(fd).expect("fd").object,
            table.get(copy).expect("copy").object,
            "dup shares the description object"
        );
        assert_eq!(
            file_open_of(table.get(copy).expect("copy").object),
            Ok(OpenId::from_raw(7))
        );
        let other = table
            .insert(FdEntry::new(second, false))
            .expect("descriptor");
        assert_eq!(
            file_open_of(table.get(other).expect("other").object),
            Ok(OpenId::from_raw(8))
        );
        table.close(fd).ok();
        table.close(copy).ok();
        table.close(other).ok();
        object::release_object(first).ok();
        object::release_object(second).ok();
    }

    /// Install a socket descriptor (the engine is never reached by these tests).
    fn socket_descriptor(table: &mut FdTable, raw: u32, family: u16) -> u32 {
        let socket =
            object::create_with_payload(ObjectKind::Socket, u64::from(raw)).expect("socket object");
        let fd = table
            .insert(FdEntry::new_socket(socket, false, family))
            .expect("socket descriptor");
        // The descriptor holds its own reference; drop the creation reference.
        let _ = object::release_object(socket);
        fd
    }

    #[test]
    fn a_receive_checks_the_user_buffer_before_touching_the_engine() {
        let _guard = object::test_lock();
        net_recv_probe::reset();

        let mut table = FdTable::new();
        let fd = socket_descriptor(&mut table, SocketId::new(0, 1).raw(), address::AF_INET);
        let mut context = LinuxContext::new(&mut table, 0, None);

        // An invalid/absent destination buffer is EFAULT, and the engine must
        // not have consumed a message: `read`/`recvfrom` have to keep the data
        // queued when the copy-out would fail.
        assert_eq!(
            dispatch(NR_READ, &[u64::from(fd), 0x1000, 8, 0, 0, 0], &mut context),
            Outcome::Done(-errno::EFAULT)
        );
        assert_eq!(
            dispatch(
                NR_RECVFROM,
                &[u64::from(fd), 0x1000, 8, 0, 0, 0],
                &mut context
            ),
            Outcome::Done(-errno::EFAULT)
        );
        assert_eq!(
            net_recv_probe::count(),
            0,
            "the engine must not run before the userspace pre-check"
        );

        // A zero-length receive completes without touching any buffer (Linux
        // reads/writes of length zero succeed), and still reaches no engine.
        assert_eq!(
            dispatch(NR_READ, &[u64::from(fd), 0x1000, 0, 0, 0, 0], &mut context),
            Outcome::Done(0)
        );
        assert_eq!(
            dispatch(
                NR_RECVFROM,
                &[u64::from(fd), 0x1000, 0, 0, 0, 0],
                &mut context
            ),
            Outcome::Done(0)
        );
        assert_eq!(net_recv_probe::count(), 0);

        context.fds.close(fd).ok();
    }

    // -----------------------------------------------------------------------
    // M8b: clocks, uname and system information
    // -----------------------------------------------------------------------

    #[test]
    fn timespec_conversion_uses_the_kernel_tick_rate() {
        assert_eq!(timespec_from_ticks(0, 100), Ok((0, 0)));
        assert_eq!(timespec_from_ticks(1, 100), Ok((0, 10_000_000)));
        assert_eq!(timespec_from_ticks(100, 100), Ok((1, 0)));
        assert_eq!(timespec_from_ticks(1234, 100), Ok((12, 340_000_000)));
        // 1/3 s at 3 Hz rounds the sub-tick remainder in nanoseconds.
        assert_eq!(timespec_from_ticks(1, 3), Ok((0, 333_333_333)));
        assert_eq!(timespec_from_ticks(7, 0), Err(errno::EIO));
    }

    #[test]
    fn timespec_images_round_trip_and_validate_the_nanosecond_range() {
        assert_eq!(
            decode_timespec(&encode_timespec(12, 345_000_000)),
            Ok((12, 345_000_000))
        );
        assert_eq!(
            decode_timespec(&encode_timespec(1, 999_999_999)),
            Ok((1, 999_999_999))
        );
        assert_eq!(decode_timespec(&encode_timespec(-1, 0)), Err(errno::EINVAL));
        assert_eq!(
            decode_timespec(&encode_timespec(1, 1_000_000_000)),
            Err(errno::EINVAL)
        );
        assert_eq!(decode_timespec(&encode_timespec(1, -1)), Err(errno::EINVAL));
    }

    #[test]
    fn sleep_deadlines_are_relative_absolute_or_immediate() {
        // 10 ms = 1 tick at 100 Hz; a relative request from tick 50 ends at 51.
        assert_eq!(sleep_deadline(50, 100, 0, 0, 10_000_000), Ok(Some(51)));
        // Absolute deadline 80 ticks with now 50 stays 80.
        assert_eq!(
            sleep_deadline(50, 100, TIMER_ABSTIME, 0, 800_000_000),
            Ok(Some(80))
        );
        // An absolute deadline in the past (or now) completes immediately.
        assert_eq!(sleep_deadline(50, 100, TIMER_ABSTIME, 0, 0), Ok(None));
        assert_eq!(sleep_deadline(0, 100, TIMER_ABSTIME, 0, 0), Ok(None));
        // A 1 ns relative sleep still needs one tick (rounded up).
        assert_eq!(sleep_deadline(50, 100, 0, 0, 1), Ok(Some(51)));
        // A zero duration is immediate.
        assert_eq!(sleep_deadline(50, 100, 0, 0, 0), Ok(None));
        // Negative durations are invalid.
        assert_eq!(sleep_deadline(50, 100, 0, -1, 0), Err(errno::EINVAL));
    }

    #[test]
    fn clocks_are_mapped_honestly() {
        assert_eq!(clock_supported(CLOCK_MONOTONIC), Ok(()));
        assert_eq!(clock_supported(CLOCK_BOOTTIME), Ok(()));
        // No trusted RTC baseline exists, so realtime must stay ENOSYS.
        assert_eq!(clock_supported(CLOCK_REALTIME), Err(errno::ENOSYS));
        assert_eq!(clock_supported(42), Err(errno::EINVAL));
    }

    #[test]
    fn clock_syscalls_require_an_address_space_for_their_result() {
        // `clock_nanosleep` consumes the process wake reason, so serialise with
        // the process tests through the shared crate test lock.
        let _guard = crate::object::test_lock();
        let mut table = FdTable::new();
        let mut context = LinuxContext::new(&mut table, 0, None);
        // No user address space: the result copy must fail, never fabricate.
        assert_eq!(
            dispatch(
                NR_CLOCK_GETTIME,
                &[u64::from(CLOCK_MONOTONIC), 0x2000, 0, 0, 0, 0],
                &mut context
            ),
            Outcome::Done(-errno::EFAULT)
        );
        // Realtime has no source yet.
        assert_eq!(
            dispatch(
                NR_CLOCK_GETTIME,
                &[u64::from(CLOCK_REALTIME), 0x2000, 0, 0, 0, 0],
                &mut context
            ),
            Outcome::Done(-errno::ENOSYS)
        );
        // Unknown clock id.
        assert_eq!(
            dispatch(NR_CLOCK_GETTIME, &[42, 0x2000, 0, 0, 0, 0], &mut context),
            Outcome::Done(-errno::EINVAL)
        );
        // Unknown sleep flags.
        assert_eq!(
            dispatch(
                NR_CLOCK_NANOSLEEP,
                &[u64::from(CLOCK_MONOTONIC), 2, 0x2000, 0, 0, 0],
                &mut context
            ),
            Outcome::Done(-errno::EINVAL)
        );
        // A valid request still has to read the timespec from user memory.
        assert_eq!(
            dispatch(
                NR_CLOCK_NANOSLEEP,
                &[u64::from(CLOCK_MONOTONIC), 0, 0x2000, 0, 0, 0],
                &mut context
            ),
            Outcome::Done(-errno::EFAULT)
        );
    }

    #[test]
    fn uname_reports_the_fixed_system_identity() {
        let image = uname_image();
        assert_eq!(image.len(), UTSNAME_SIZE);
        let field = |index: usize| -> &[u8] {
            let start = index * UTSNAME_FIELD;
            let bytes = &image[start..start + UTSNAME_FIELD];
            let end = bytes
                .iter()
                .position(|byte| *byte == 0)
                .unwrap_or(UTSNAME_FIELD);
            &bytes[..end]
        };
        assert_eq!(field(0), b"CaelumOS");
        assert_eq!(field(1), b"caelum");
        assert_eq!(field(2), crate::KERNEL_VERSION.as_bytes());
        assert_eq!(field(3), b"CaelumOS kernel");
        assert_eq!(field(4), b"x86_64");
        assert_eq!(field(5), b"(none)");
        for index in 0..UTSNAME_FIELDS {
            assert_eq!(
                image[index * UTSNAME_FIELD + UTSNAME_FIELD - 1],
                0,
                "field {index} must end with NUL"
            );
        }
    }

    #[test]
    fn sysinfo_layout_matches_the_linux64_structure() {
        let values = SysinfoValues {
            uptime: 7,
            totalram: 0x11,
            freeram: 0x22,
            procs: 3,
        };
        let image = encode_sysinfo(&values);
        assert_eq!(image.len(), SYSINFO_SIZE);
        let u64_at = |offset: usize| -> u64 {
            u64::from_le_bytes(image[offset..offset + 8].try_into().unwrap())
        };
        assert_eq!(
            i64::from_le_bytes(
                image[SYSINFO_UPTIME..SYSINFO_UPTIME + 8]
                    .try_into()
                    .unwrap()
            ),
            7
        );
        assert_eq!(u64_at(SYSINFO_TOTALRAM), 0x11);
        assert_eq!(u64_at(SYSINFO_FREERAM), 0x22);
        assert_eq!(
            u16::from_le_bytes(image[SYSINFO_PROCS..SYSINFO_PROCS + 2].try_into().unwrap()),
            3
        );
        assert_eq!(
            u32::from_le_bytes(
                image[SYSINFO_MEM_UNIT..SYSINFO_MEM_UNIT + 4]
                    .try_into()
                    .unwrap()
            ),
            1
        );
        // Unreported members (loads, sharedram, buffers, swap, high) stay zero.
        for offset in [8usize, 16, 24, 48, 56, 64, 72, 88, 96, 108] {
            assert!(
                image[offset..offset + 4].iter().all(|byte| *byte == 0),
                "offset {offset} must stay zero"
            );
        }
    }

    #[test]
    fn identity_and_system_calls_are_real_not_fabricated() {
        // `sysinfo` reads the live process count, so this test touches the
        // process table just like the signal tests; take the same host-test
        // serialisation lock the process tests use (see process.rs tests).
        let _guard = crate::object::test_lock();
        let mut table = FdTable::new();
        let mut context = LinuxContext::new(&mut table, 0, None);
        assert_eq!(
            dispatch(NR_GETPPID, &[0; 6], &mut context),
            Outcome::Done(0)
        );
        // Without an address space the data must not be claimed as written.
        assert_eq!(
            dispatch(NR_UNAME, &[0x2000, 0, 0, 0, 0, 0], &mut context),
            Outcome::Done(-errno::EFAULT)
        );
        assert_eq!(
            dispatch(NR_SYSINFO, &[0x2000, 0, 0, 0, 0, 0], &mut context),
            Outcome::Done(-errno::EFAULT)
        );
    }

    // -----------------------------------------------------------------------
    // M8b rework: stale wake reasons and Linux pid numbering
    // -----------------------------------------------------------------------

    #[test]
    fn only_clock_nanosleep_owns_its_wake_reason() {
        // The entry layer drains a stale wake reason before every call except
        // `clock_nanosleep`, whose `Timeout` is its success signal. Exercising
        // the drain itself needs a live process record, so this test pins the
        // ownership rule the entry keys off.
        assert!(owns_wake_reason(NR_CLOCK_NANOSLEEP));
        for nr in [NR_CLOSE, NR_ACCEPT, NR_READ, NR_SOCKET, NR_CLOCK_GETTIME] {
            assert!(!owns_wake_reason(nr), "call {nr} must not own the reason");
        }
    }

    #[test]
    fn a_completed_deadline_sleep_reports_success_and_never_einr() {
        assert!(sleep_wake_completed(process::WakeReason::Timeout));
        assert!(!sleep_wake_completed(process::WakeReason::Ready));
        assert!(!sleep_wake_completed(process::WakeReason::Destroyed));
        assert!(!sleep_wake_completed(process::WakeReason::Cancelled));
        assert!(!sleep_wake_completed(process::WakeReason::PeerClosed));
        assert!(!sleep_wake_completed(process::WakeReason::None));
    }

    #[test]
    fn linux_pids_are_one_based() {
        // No current process keeps the established host convention.
        assert_eq!(linux_pid(None), 0);
        // The kernel's 0-based table index maps to Linux' 1-based pid.
        assert_eq!(linux_pid(Some(0)), 1);
        assert_eq!(linux_pid(Some(4)), 5);
        assert_eq!(linux_pid(Some(u32::MAX)), i64::from(u32::MAX) + 1);
    }
}

/// M8e: file offsets, metadata and directory enumeration helpers.
#[cfg(test)]
mod m8e_tests {
    use super::*;

    fn console_table() -> FdTable {
        let mut table = FdTable::new();
        let console = object::create_with_payload(ObjectKind::Console, 0).expect("console object");
        table.install_console(console).expect("console descriptors");
        table
    }

    fn call(nr: u64, args: &[u64; 6], table: &mut FdTable) -> Outcome {
        let mut context = LinuxContext::new(table, 0, None);
        dispatch(nr, args, &mut context)
    }

    fn word(bytes: &[u8], at: usize) -> u64 {
        u64::from_le_bytes(bytes[at..at + 8].try_into().unwrap())
    }

    #[test]
    fn stat_images_carry_the_linux64_offsets_and_restricted_values() {
        let regular = encode_stat(vfs::NodeKind::File, 5000, false, None);
        assert_eq!(regular.len(), STAT_SIZE);
        assert_eq!(word(&regular, 0), 0, "st_dev");
        assert_eq!(word(&regular, 8), 0, "st_ino");
        assert_eq!(word(&regular, 16), 1, "st_nlink");
        let mode = u32::from_le_bytes(regular[24..28].try_into().unwrap());
        assert_eq!(mode, S_IFREG | FILE_MODE);
        assert_eq!(word(&regular, 48), 5000, "st_size");
        assert_eq!(word(&regular, 56), 4096, "st_blksize");
        assert_eq!(word(&regular, 64), 10, "st_blocks (ceil(5000/512))");

        let read_only = encode_stat(vfs::NodeKind::File, 1, true, None);
        assert_eq!(
            u32::from_le_bytes(read_only[24..28].try_into().unwrap()),
            S_IFREG | FILE_MODE_READ_ONLY
        );
        let directory = encode_stat(vfs::NodeKind::Directory, 8192, false, None);
        assert_eq!(word(&directory, 16), 2, "directory st_nlink");
        assert_eq!(
            u32::from_le_bytes(directory[24..28].try_into().unwrap()),
            S_IFDIR | DIRECTORY_MODE
        );
    }

    #[test]
    fn character_device_images_report_chr_mode_and_no_size() {
        // `/dev/null`: major 1, minor 3; `/dev/zero`: major 1, minor 5. A
        // Linux `dev_t` keeps the minor's high bits in bits 12..31.
        let null = 0x103u64;
        let image = encode_stat(vfs::NodeKind::CharDevice, 0, false, Some(null));
        assert_eq!(image.len(), STAT_SIZE);
        assert_eq!(
            u32::from_le_bytes(image[24..28].try_into().unwrap()),
            S_IFCHR | CHAR_DEVICE_MODE
        );
        assert_eq!(word(&image, 16), 1, "character device st_nlink");
        assert_eq!(word(&image, 40), null, "st_rdev");
        assert_eq!(word(&image, 48), 0, "a character device has no size");
        assert_eq!(word(&image, 64), 0, "a character device has no blocks");

        let statx = encode_statx(vfs::NodeKind::CharDevice, 0, false, Some(null));
        assert_eq!(statx.len(), STATX_SIZE);
        assert_eq!(
            u16::from_le_bytes(statx[28..30].try_into().unwrap()),
            (S_IFCHR | CHAR_DEVICE_MODE) as u16
        );
        assert_eq!(u32::from_le_bytes(statx[128..132].try_into().unwrap()), 1);
        assert_eq!(u32::from_le_bytes(statx[132..136].try_into().unwrap()), 3);
        assert_eq!(word(&statx, 40), 0);
        assert_eq!(word(&statx, 48), 0);

        let zero = encode_statx(vfs::NodeKind::CharDevice, 0, false, Some(0x105));
        assert_eq!(u32::from_le_bytes(zero[128..132].try_into().unwrap()), 1);
        assert_eq!(u32::from_le_bytes(zero[132..136].try_into().unwrap()), 5);
    }

    #[test]
    fn character_device_numbers_round_trip_through_the_stat_encoding() {
        // The Linux `stat` form is `new_encode_dev`: the low 12 major bits sit
        // in bits 8..19, the low 8 minor bits in bits 0..7, the minor's high
        // bits in 12..31 and the major's high bits in 32..63.
        fn encoded(major: u32, minor: u32) -> u64 {
            ((u64::from(major) & 0xfff) << 8)
                | (u64::from(minor) & 0xff)
                | ((u64::from(major) & 0xffff_f000) << 32)
                | ((u64::from(minor) & 0xffff_ff00) << 12)
        }
        for (major, minor) in [(1, 3), (1, 5), (4660, 0x56789), (0, 0)] {
            assert_eq!(
                device_numbers(encoded(major, minor)),
                (major, minor),
                "dev_t {major}:{minor} must decode back"
            );
        }
        // The production pair is the inverse used on `NodeStat`/`DirEntry`.
        for (major, minor) in [(1u16, 3u16), (1, 5), (259, 0x1234), (0, 0)] {
            assert_eq!(
                device_numbers(device_from_numbers(major, minor)),
                (u32::from(major), u32::from(minor))
            );
        }
    }

    #[test]
    fn character_device_nodes_report_their_device_pair() {
        let null = vfs::NodeStat {
            kind: vfs::NodeKind::CharDevice,
            size: 0,
            read_only: false,
            dev_major: 1,
            dev_minor: 3,
        };
        let zero = vfs::NodeStat {
            kind: vfs::NodeKind::CharDevice,
            size: 0,
            read_only: false,
            dev_major: 1,
            dev_minor: 5,
        };
        let file = vfs::NodeStat {
            kind: vfs::NodeKind::File,
            size: 4096,
            read_only: true,
            dev_major: 0,
            dev_minor: 0,
        };
        assert_eq!(node_device(&null), Some(0x103));
        assert_eq!(node_device(&zero), Some(0x105));
        assert_eq!(node_device(&file), None);

        // The directory record for a character device is `DT_CHR`, not
        // `DT_REG`; `/proc` files and ordinary files stay `DT_REG`.
        let mut entries = [vfs::DirEntry::empty(); 2];
        entries[0].name[..4].copy_from_slice(b"null");
        entries[0].name_len = 4;
        entries[0].kind = vfs::NodeKind::CharDevice;
        entries[1].name[..2].copy_from_slice(b"ok");
        entries[1].name_len = 2;
        entries[1].kind = vfs::NodeKind::File;
        let mut out = [0u8; 64];
        let (used, consumed) = encode_dir_entries(&entries, 0, &mut out);
        assert_eq!((used, consumed), (48, 2));
        assert_eq!(out[18], DT_CHR);
        assert_eq!(out[24 + 18], DT_REG);
    }

    #[test]
    fn statx_images_report_only_the_basic_statistics_mask() {
        let image = encode_statx(vfs::NodeKind::Directory, 8192, false, None);
        assert_eq!(image.len(), STATX_SIZE);
        assert_eq!(
            u32::from_le_bytes(image[0..4].try_into().unwrap()),
            STATX_BASIC_STATS
        );
        assert_eq!(u32::from_le_bytes(image[4..8].try_into().unwrap()), 4096);
        assert_eq!(u32::from_le_bytes(image[16..20].try_into().unwrap()), 2);
        assert_eq!(
            u16::from_le_bytes(image[28..30].try_into().unwrap()),
            (S_IFDIR | DIRECTORY_MODE) as u16
        );
        assert_eq!(word(&image, 40), 8192);
        assert_eq!(word(&image, 48), 16, "blocks = ceil(8192/512)");
        // Everything the ABI does not provide stays zero.
        assert_eq!(word(&image, 8), 0, "mask beyond BASIC_STATS");
        assert_eq!(u32::from_le_bytes(image[20..24].try_into().unwrap()), 0);
        assert_eq!(u32::from_le_bytes(image[24..28].try_into().unwrap()), 0);
    }

    #[test]
    fn seek_requests_cover_every_linux_whence() {
        assert_eq!(seek_request(0, SEEK_SET), Ok(vfs::SeekFrom::Start(0)));
        assert_eq!(seek_request(512, SEEK_SET), Ok(vfs::SeekFrom::Start(512)));
        assert_eq!(seek_request(7, SEEK_CUR), Ok(vfs::SeekFrom::Current(7)));
        assert_eq!(seek_request(-7, SEEK_CUR), Ok(vfs::SeekFrom::Current(-7)));
        assert_eq!(seek_request(-1, SEEK_END), Ok(vfs::SeekFrom::End(-1)));
        assert_eq!(seek_request(-1, SEEK_SET), Err(errno::EINVAL));
        assert_eq!(seek_request(0, 3), Err(errno::EINVAL));
    }

    #[test]
    fn directory_records_are_aligned_and_never_split() {
        let mut entries = [vfs::DirEntry::empty(); 2];
        entries[0].name[..1].copy_from_slice(b"a");
        entries[0].name_len = 1;
        entries[0].kind = vfs::NodeKind::File;
        entries[1].name[..3].copy_from_slice(b"dir");
        entries[1].name_len = 3;
        entries[1].kind = vfs::NodeKind::Directory;

        let mut out = [0u8; 64];
        let (used, consumed) = encode_dir_entries(&entries, 5, &mut out);
        assert_eq!(consumed, 2);
        assert_eq!(used, 48);
        // First record: d_ino 0, d_off = index after the entry, d_type DT_REG.
        assert_eq!(word(&out, 0), 0);
        assert_eq!(word(&out, 8), 6);
        let record = u16::from_le_bytes(out[16..18].try_into().unwrap()) as usize;
        assert_eq!(record, 24);
        assert_eq!(out[18], DT_REG);
        assert_eq!(&out[DIRENT64_HEADER..DIRENT64_HEADER + 2], b"a\0");
        // Second record starts on the aligned boundary.
        assert_eq!(word(&out, 24 + 8), 7);
        assert_eq!(out[24 + 18], DT_DIR);
        assert_eq!(
            &out[24 + DIRENT64_HEADER..24 + DIRENT64_HEADER + 4],
            b"dir\0"
        );

        // A buffer that cannot hold one record consumes nothing.
        let mut tiny = [0u8; 8];
        assert_eq!(encode_dir_entries(&entries, 0, &mut tiny), (0, 0));
    }

    #[test]
    fn synthetic_dot_entries_report_a_directory_kind() {
        let dot = directory_dot(false);
        assert_eq!(dot.name(), b".");
        assert_eq!(dot.kind, vfs::NodeKind::Directory);
        assert_eq!(dot.size, 0);
        let parent = directory_dot(true);
        assert_eq!(parent.name(), b"..");
        assert_eq!(parent.kind, vfs::NodeKind::Directory);
    }

    #[test]
    fn fcntl_duplicates_and_tracks_cloexec() {
        let mut table = console_table();
        assert_eq!(
            call(NR_FCNTL, &[0, F_GETFD, 0, 0, 0, 0], &mut table),
            Outcome::Done(0)
        );
        assert_eq!(
            call(NR_FCNTL, &[0, F_SETFD, FD_CLOEXEC, 0, 0, 0], &mut table),
            Outcome::Done(0)
        );
        assert_eq!(table.get(0).expect("console fd").cloexec, true);
        assert_eq!(
            call(NR_FCNTL, &[0, F_GETFD, 0, 0, 0, 0], &mut table),
            Outcome::Done(FD_CLOEXEC as i64)
        );
        // F_DUPFD takes the lowest free descriptor at or above the argument.
        assert_eq!(
            call(NR_FCNTL, &[0, F_DUPFD, 3, 0, 0, 0], &mut table),
            Outcome::Done(3)
        );
        assert_eq!(table.get(3).expect("duplicate").cloexec, false);
        let duplicated = call(NR_FCNTL, &[0, F_DUPFD_CLOEXEC, 9, 0, 0, 0], &mut table);
        assert_eq!(duplicated, Outcome::Done(9));
        assert_eq!(table.get(9).expect("duplicate").cloexec, true);
    }

    #[test]
    fn fcntl_rejects_unknown_commands_and_bad_descriptors() {
        let mut table = console_table();
        assert_eq!(
            call(NR_FCNTL, &[0, F_SETFD, 2, 0, 0, 0], &mut table),
            Outcome::Done(-errno::EINVAL)
        );
        assert_eq!(
            call(NR_FCNTL, &[0, 99, 0, 0, 0, 0], &mut table),
            Outcome::Done(-errno::EINVAL)
        );
        assert_eq!(
            call(NR_FCNTL, &[0, F_GETLK, 0, 0, 0, 0], &mut table),
            Outcome::Done(-errno::EBADF)
        );
        assert_eq!(
            call(NR_FCNTL, &[12, F_GETFD, 0, 0, 0, 0], &mut table),
            Outcome::Done(-errno::EBADF)
        );
        assert_eq!(
            call(NR_FCNTL, &[0, F_DUPFD, 0x1_0000_0000, 0, 0, 0], &mut table),
            Outcome::Done(-errno::EINVAL)
        );
    }

    #[test]
    fn offset_and_metadata_calls_reject_non_file_descriptors() {
        let mut table = console_table();
        assert_eq!(
            call(NR_LSEEK, &[0, 0, SEEK_SET, 0, 0, 0], &mut table),
            Outcome::Done(-errno::ESPIPE)
        );
        assert_eq!(
            call(NR_FSTAT, &[0, 0x1000, 0, 0, 0, 0], &mut table),
            Outcome::Done(-errno::EOPNOTSUPP)
        );
        assert_eq!(
            call(NR_GETDENTS64, &[0, 0x1000, 64, 0, 0, 0], &mut table),
            Outcome::Done(-errno::EBADF)
        );
        assert_eq!(
            call(NR_LSEEK, &[12, 0, SEEK_SET, 0, 0, 0], &mut table),
            Outcome::Done(-errno::EBADF)
        );
        assert_eq!(
            call(NR_FSTAT, &[12, 0x1000, 0, 0, 0, 0], &mut table),
            Outcome::Done(-errno::EBADF)
        );
    }
}

/// M8g: eventfd and poll/ppoll helpers and dispatch paths.
#[cfg(test)]
mod m8g_tests {
    use super::*;

    fn console_table() -> FdTable {
        let mut table = FdTable::new();
        let console = object::create_with_payload(ObjectKind::Console, 0).expect("console object");
        table.install_console(console).expect("console descriptors");
        table
    }

    fn call(nr: u64, args: &[u64; 6], table: &mut FdTable) -> Outcome {
        let mut context = LinuxContext::new(table, 0, None);
        dispatch(nr, args, &mut context)
    }

    /// Close a console table without leaking the console object.
    ///
    /// `install_console` takes one reference per descriptor and the creation
    /// reference is still held, so dropping the table alone leaves the object
    /// alive. The unit tests run in one process against the fixed global object
    /// table, so every test must return its objects.
    fn dispose_console_table(mut table: FdTable) {
        let console = table.get(0).ok().map(|entry| entry.object);
        table.close(0).ok();
        table.close(1).ok();
        table.close(2).ok();
        if let Some(console) = console {
            let _ = object::release_object(console);
        }
    }

    fn install_eventfd_hooks() {
        let _ = crate::ipc::install_destroy_hooks();
        crate::ipc::eventfd::reset_for_test();
    }

    fn reset_eventfd_hooks() {
        crate::object::reset_destroy_hooks();
        crate::ipc::eventfd::reset_for_test();
    }

    #[test]
    fn poll_and_eventfd_numbers_match_linux_x86_64() {
        assert_eq!(NR_POLL, 7);
        assert_eq!(NR_PPOLL, 271);
        assert_eq!(NR_EVENTFD, 284);
        assert_eq!(NR_EVENTFD2, 290);
        assert_eq!(POLLIN, 0x0001);
        assert_eq!(POLLPRI, 0x0002);
        assert_eq!(POLLOUT, 0x0004);
        assert_eq!(POLLERR, 0x0008);
        assert_eq!(POLLHUP, 0x0010);
        assert_eq!(POLLNVAL, 0x0020);
        assert_eq!(POLLRDNORM, 0x0040);
        assert_eq!(POLLRDBAND, 0x0080);
        assert_eq!(POLLWRNORM, 0x0100);
        assert_eq!(POLLWRBAND, 0x0200);
        assert_eq!(EFD_SEMAPHORE, 0x1);
        assert_eq!(EFD_NONBLOCK, 0o4000);
        assert_eq!(EFD_CLOEXEC, 0o2_000_000);
        assert_eq!(POLLFD_SIZE, 8);
        assert_eq!(MAX_POLL_FDS, 16);
        assert_eq!(MAX_POLL_WAIT, process::MAX_WAIT_OBJECTS);
        assert!(owns_wake_reason(NR_POLL) && owns_wake_reason(NR_PPOLL));
        assert!(!owns_wake_reason(NR_EVENTFD2));
    }

    #[test]
    fn pollfd_wire_layout_round_trips() {
        let descriptor = PollFd {
            fd: 7,
            events: POLLIN | POLLOUT,
            revents: POLLERR,
        };
        let raw = descriptor.encode();
        assert_eq!(raw, [7, 0, 0, 0, 0x05, 0x00, 0x08, 0x00]);
        assert_eq!(PollFd::decode(&raw), descriptor);
    }

    #[test]
    fn readiness_projections_only_echo_requested_bits() {
        let readable = Readiness {
            readable: true,
            ..Readiness::default()
        };
        assert_eq!(readable.revents(POLLIN), POLLIN);
        assert_eq!(readable.revents(POLLOUT), 0);
        assert_eq!(readable.revents(POLLIN | POLLOUT), POLLIN);
        let writable = Readiness {
            writable: true,
            ..Readiness::default()
        };
        assert_eq!(writable.revents(POLLOUT | POLLWRNORM), POLLOUT | POLLWRNORM);
        assert_eq!(writable.revents(POLLIN), 0);
        let failed = Readiness {
            error: true,
            ..Readiness::default()
        };
        assert_eq!(failed.revents(0), POLLERR);
        let invalid = Readiness {
            invalid: true,
            ..Readiness::default()
        };
        assert_eq!(invalid.revents(POLLIN), POLLNVAL);
    }

    #[test]
    fn poll_timeouts_convert_to_absolute_deadlines() {
        assert_eq!(poll_ms_deadline(100, 100, -1), Ok(None));
        assert_eq!(poll_ms_deadline(100, 100, 0), Ok(Some(100)));
        assert_eq!(poll_ms_deadline(100, 100, 1), Ok(Some(101)));
        assert_eq!(poll_ms_deadline(100, 100, 10), Ok(Some(101)));
        assert_eq!(poll_ms_deadline(100, 100, 11), Ok(Some(102)));
        assert_eq!(poll_ms_deadline(100, 100, 100), Ok(Some(110)));
        assert_eq!(poll_ms_deadline(0, 0, 1), Err(errno::EIO));
    }

    #[test]
    fn poll_rejects_bad_fixed_arguments() {
        let _guard = crate::object::test_lock();
        let mut table = console_table();
        assert_eq!(
            call(
                NR_POLL,
                &[0, (MAX_POLL_FDS + 1) as u64, 0, 0, 0, 0],
                &mut table
            ),
            Outcome::Done(-errno::EINVAL)
        );
        // `nfds > 0` needs a descriptor array pointer.
        assert_eq!(
            call(NR_POLL, &[0, 1, 0, 0, 0, 0], &mut table),
            Outcome::Done(-errno::EFAULT)
        );
        // A non-NULL ppoll signal mask must carry the Linux sigsetsize.
        assert_eq!(
            call(NR_PPOLL, &[0, 0, 0, 1, 0, 0], &mut table),
            Outcome::Done(-errno::EINVAL)
        );
        assert_eq!(
            call(NR_PPOLL, &[0, 0, 0, 1, 9, 0], &mut table),
            Outcome::Done(-errno::EINVAL)
        );
        // With `sigsetsize == 8` the mask is accepted (the entry installs it);
        // this mask pointer is not read by the compat layer, and the timespec
        // copy-in still fails without an address space.
        assert_eq!(
            call(NR_PPOLL, &[0, 0, 0x1000, 1, 8, 0], &mut table),
            Outcome::Done(-errno::EFAULT)
        );
        // A timespec pointer without an address space fails at copy-in.
        assert_eq!(
            call(NR_PPOLL, &[0, 0, 0x1000, 0, 0, 0], &mut table),
            Outcome::Done(-errno::EFAULT)
        );
        dispose_console_table(table);
    }

    #[test]
    fn poll_without_descriptors_behaves_like_a_timeout_sleep() {
        let _guard = crate::object::test_lock();
        let mut table = FdTable::new();
        // A zero timeout is an immediate "check".
        assert_eq!(
            call(NR_POLL, &[0, 0, 0, 0, 0, 0], &mut table),
            Outcome::Done(0)
        );
        // A negative timeout with no descriptors is a pure unlimited sleep.
        match call(NR_POLL, &[0, 0, u64::from(u32::MAX), 0, 0, 0], &mut table) {
            Outcome::Wait { object, deadline } => {
                assert_eq!(object, SLEEP_OBJECT);
                assert_eq!(deadline, None);
            }
            other => panic!("expected a pure sleep, got {other:?}"),
        }
    }

    #[test]
    fn eventfd_creation_and_close_round_trip() {
        let _guard = crate::object::test_lock();
        install_eventfd_hooks();
        let mut table = FdTable::new();
        // Unknown flag bits are rejected before any object exists.
        assert_eq!(
            call(NR_EVENTFD2, &[0, 1 << 30, 0, 0, 0, 0], &mut table),
            Outcome::Done(-errno::EINVAL)
        );
        // The legacy `eventfd` entry takes only the initial value.
        assert_eq!(
            call(NR_EVENTFD, &[5, 0xDEAD_BEEF, 0, 0, 0, 0], &mut table),
            Outcome::Done(3)
        );
        let object = table.get(3).expect("eventfd descriptor").object;
        assert!(object::payload(object).expect("eventfd payload") > 0);
        assert_eq!(crate::ipc::eventfd::readable(object), Ok(true));
        assert_eq!(crate::ipc::eventfd::read(object), Ok(5));
        assert_eq!(crate::ipc::eventfd::readable(object), Ok(false));
        assert_eq!(crate::ipc::eventfd::writable(object), Ok(true));
        assert_eq!(crate::ipc::eventfd::nonblocking(object), Ok(false));
        assert_eq!(crate::ipc::eventfd::live_count(), 1);
        assert_eq!(
            call(NR_CLOSE, &[3, 0, 0, 0, 0, 0], &mut table),
            Outcome::Done(0)
        );
        assert_eq!(crate::ipc::eventfd::live_count(), 0);
        reset_eventfd_hooks();
    }

    #[test]
    fn eventfd_read_and_write_preflight_the_wire_value() {
        let _guard = crate::object::test_lock();
        install_eventfd_hooks();
        let mut table = FdTable::new();
        assert_eq!(
            call(NR_EVENTFD2, &[0, 0, 0, 0, 0, 0], &mut table),
            Outcome::Done(3)
        );
        // read: fewer than eight bytes is EINVAL before any pointer is touched.
        assert_eq!(
            call(NR_READ, &[3, 0x1000, 4, 0, 0, 0], &mut table),
            Outcome::Done(-errno::EINVAL)
        );
        // Without an address space the eight-byte target cannot be preflighted.
        assert_eq!(
            call(NR_READ, &[3, 0x1000, 8, 0, 0, 0], &mut table),
            Outcome::Done(-errno::EFAULT)
        );
        // write: exactly eight bytes, and the value is copied in before use.
        assert_eq!(
            call(NR_WRITE, &[3, 0x1000, 4, 0, 0, 0], &mut table),
            Outcome::Done(-errno::EINVAL)
        );
        assert_eq!(
            call(NR_WRITE, &[3, 0x1000, 8, 0, 0, 0], &mut table),
            Outcome::Done(-errno::EFAULT)
        );
        assert_eq!(
            call(NR_CLOSE, &[3, 0, 0, 0, 0, 0], &mut table),
            Outcome::Done(0)
        );
        reset_eventfd_hooks();
    }

    #[test]
    fn poll_readiness_covers_console_eventfd_and_invalid_descriptors() {
        let _guard = crate::object::test_lock();
        install_eventfd_hooks();
        let mut table = console_table();
        let console = table.get(0).expect("console fd");
        let context = LinuxContext::new(&mut table, 0, None);
        let readiness = descriptor_readiness(&context, 0);
        assert_eq!(readiness.revents(POLLOUT), POLLOUT);
        assert_eq!(readiness.revents(POLLIN), 0);
        assert_eq!(descriptor_readiness(&context, 12).revents(POLLIN), POLLNVAL);
        assert!(descriptor_is_waitable(&context, 0) == false);
        drop(context);
        let _ = console;
        dispose_console_table(table);

        let mut table = FdTable::new();
        assert_eq!(
            call(NR_EVENTFD2, &[0, 0, 0, 0, 0, 0], &mut table),
            Outcome::Done(3)
        );
        let object = table.get(3).expect("eventfd descriptor").object;
        let context = LinuxContext::new(&mut table, 0, None);
        let empty = descriptor_readiness(&context, 3);
        assert_eq!(empty.revents(POLLIN | POLLOUT), POLLOUT);
        assert!(descriptor_is_waitable(&context, 3));
        drop(context);
        assert_eq!(crate::ipc::eventfd::write(object, 7), Ok(()));
        let context = LinuxContext::new(&mut table, 0, None);
        assert_eq!(
            descriptor_readiness(&context, 3).revents(POLLIN | POLLOUT),
            POLLIN | POLLOUT
        );
        drop(context);
        assert_eq!(
            call(NR_CLOSE, &[3, 0, 0, 0, 0, 0], &mut table),
            Outcome::Done(0)
        );
        reset_eventfd_hooks();
    }

    #[test]
    fn ppoll_signal_mask_arguments_are_validated() {
        // A NULL mask is always fine; with a mask the sigsetsize must match.
        assert_eq!(ppoll_mask_request(&[0, 0, 0, 0, 0, 0]), Ok(None));
        assert_eq!(
            ppoll_mask_request(&[0, 0, 0, 0x1000, 0, 0]),
            Err(errno::EINVAL)
        );
        assert_eq!(
            ppoll_mask_request(&[0, 0, 0, 0x1000, signal::SIGSET_SIZE + 1, 0]),
            Err(errno::EINVAL)
        );
        assert_eq!(
            ppoll_mask_request(&[0, 0, 0, 0x1000, signal::SIGSET_SIZE, 0]),
            Ok(Some(0x1000))
        );
    }

    #[test]
    fn pending_signals_are_deliverable_only_when_the_mask_allows_them() {
        // Bit `n-1` is signal `n`: SIGKILL=9, SIGUSR1=10, SIGSTOP=19.
        let sigkill = 1u64 << 8;
        let sigusr1 = 1u64 << 9;
        let sigstop = 1u64 << 18;
        assert!(!pending_is_deliverable(0, 0));
        assert!(pending_is_deliverable(sigusr1, 0));
        assert!(!pending_is_deliverable(sigusr1, sigusr1));
        // SIGKILL/SIGSTOP cannot be blocked, so their pending bit always wins.
        assert!(pending_is_deliverable(sigkill, sigkill));
        assert!(pending_is_deliverable(sigstop, sigstop));
        // Only signals 1..=31 participate; higher bits are ignored.
        assert!(!pending_is_deliverable(1u64 << 40, 0));
        assert!(pending_is_deliverable(sigusr1 | (1u64 << 40), 0));
    }

    #[test]
    fn ppoll_mask_state_round_trips_through_the_descriptor_table() {
        let mut table = FdTable::new();
        assert_eq!(table.ppoll_mask(), None);
        table.begin_ppoll_mask(0b1010);
        assert_eq!(table.ppoll_mask(), Some(0b1010));
        // A replay must keep the original mask instead of overwriting it.
        table.begin_ppoll_mask(0b1111);
        assert_eq!(table.ppoll_mask(), Some(0b1010));
        assert_eq!(table.end_ppoll_mask(), Some(0b1010));
        assert_eq!(table.ppoll_mask(), None);
        assert_eq!(table.take_pending_mask_restore(), None);
        table.set_pending_mask_restore(0b1010);
        assert_eq!(table.take_pending_mask_restore(), Some(0b1010));
        assert_eq!(table.take_pending_mask_restore(), None);
    }
}

/// Host coverage for the M9a surface: `timerfd`, `signalfd` and `epoll`.
///
/// The handlers that copy user structures cannot run in a host test (there is
/// no address space), so every case pins one of the two layers it can reach:
/// the dispatch-level validation that runs before any user access, or the real
/// `ipc` API the handler drives. Both directions matter: a validation test that
/// only exercises an early `return` would not notice a broken create/bind or a
/// leaked slot, so the creation paths are always paired with a close/release
/// and a live-count check.
#[cfg(test)]
mod m9a_tests {
    use super::*;
    use crate::ipc::{epoll, eventfd, signalfd, timerfd};

    fn call(nr: u64, args: &[u64; 6], table: &mut FdTable) -> Outcome {
        let mut context = LinuxContext::new(table, 0, None);
        dispatch(nr, args, &mut context)
    }

    fn done(outcome: Outcome) -> i64 {
        match outcome {
            Outcome::Done(code) => code,
            other => panic!("expected a completed call, got {other:?}"),
        }
    }

    fn install_m9a_hooks() {
        let _ = crate::ipc::install_destroy_hooks();
        timerfd::reset_for_test();
        signalfd::reset_for_test();
        epoll::reset_for_test();
        eventfd::reset_for_test();
    }

    fn reset_m9a_hooks() {
        crate::object::reset_destroy_hooks();
        timerfd::reset_for_test();
        signalfd::reset_for_test();
        epoll::reset_for_test();
        eventfd::reset_for_test();
    }

    fn create_timerfd(table: &mut FdTable, clock: u64, flags: u64) -> u32 {
        let fd = done(call(NR_TIMERFD_CREATE, &[clock, flags, 0, 0, 0, 0], table));
        u32::try_from(fd).expect("timerfd descriptor")
    }

    fn create_eventfd(table: &mut FdTable) -> u32 {
        let fd = done(call(NR_EVENTFD2, &[0, 0, 0, 0, 0, 0], table));
        u32::try_from(fd).expect("eventfd descriptor")
    }

    fn create_epoll(table: &mut FdTable) -> u32 {
        let fd = done(call(NR_EPOLL_CREATE1, &[0, 0, 0, 0, 0, 0], table));
        u32::try_from(fd).expect("epoll descriptor")
    }

    fn object_of(table: &FdTable, fd: u32) -> ObjectId {
        table.get(fd).expect("installed descriptor").object
    }

    #[test]
    fn timerfd_creation_validates_clock_and_flags() {
        let _guard = crate::object::test_lock();
        install_m9a_hooks();
        let mut table = FdTable::new();

        assert_eq!(
            done(call(NR_TIMERFD_CREATE, &[0, 0, 0, 0, 0, 0], &mut table)),
            -errno::ENOSYS,
            "CLOCK_REALTIME has no kernel clock source yet"
        );
        assert_eq!(
            done(call(NR_TIMERFD_CREATE, &[3, 0, 0, 0, 0, 0], &mut table)),
            -errno::EINVAL,
            "unknown clocks are refused"
        );
        assert_eq!(
            done(call(NR_TIMERFD_CREATE, &[1, 0x100, 0, 0, 0, 0], &mut table)),
            -errno::EINVAL,
            "unknown timerfd flags are refused"
        );

        let mono = create_timerfd(&mut table, 1, 0);
        let boot = create_timerfd(&mut table, 7, u64::from(TFD_CLOEXEC));
        assert!(mono >= 3 && boot >= 3 && mono != boot);
        let mono_object = object_of(&table, mono);
        assert_eq!(object::object_kind(mono_object), Some(ObjectKind::TimerFd));
        assert_eq!(timerfd::live_count(), 2);

        assert_eq!(
            done(call(
                NR_CLOSE,
                &[u64::from(mono), 0, 0, 0, 0, 0],
                &mut table
            )),
            0
        );
        assert_eq!(
            timerfd::live_count(),
            1,
            "closing one timerfd frees exactly one slot"
        );
        assert_eq!(
            done(call(
                NR_CLOSE,
                &[u64::from(boot), 0, 0, 0, 0, 0],
                &mut table
            )),
            0
        );
        assert_eq!(timerfd::live_count(), 0);
        assert_eq!(object::object_kind(mono_object), None);
        reset_m9a_hooks();
    }

    #[test]
    fn timerfd_time_helpers_convert_and_encode_ticks() {
        let hz = u64::from(crate::time::tick_hz());
        assert!(hz > 0, "the timer tick rate is published");
        assert_eq!(nanoseconds_to_ticks(1_000_000_000), Ok(hz));
        assert_eq!(nanoseconds_to_ticks(1), Ok(1), "sub-tick delays round up");
        assert_eq!(nanoseconds_to_ticks(0), Ok(0));

        let armed = encode_timespec_ticks(Some(2 * hz + 5));
        let nanos_of_five_ticks = ((5 * 1_000_000_000) / hz) as i64;
        assert_eq!(decode_timespec_slice(&armed), Ok((2, nanos_of_five_ticks)));
        let stopped = encode_timespec_ticks(None);
        assert_eq!(decode_timespec_slice(&stopped), Ok((0, 0)));
        assert_eq!(timespec_nanos(1, 500_000_000), 1_500_000_000u128);
    }

    #[test]
    fn timerfd_rearm_and_gettime_track_the_armed_timer() {
        let _guard = crate::object::test_lock();
        install_m9a_hooks();

        let payload =
            timerfd::create(timerfd::TimerFdClock::Monotonic, 0).expect("timerfd payload");
        let object =
            object::create_with_payload(ObjectKind::TimerFd, payload).expect("timerfd object");
        timerfd::bind(payload, object).expect("bind the timerfd slot");
        assert_eq!(timerfd::readable(object), Ok(false));
        assert!(matches!(
            timerfd::read(object),
            Err(timerfd::TimerFdError::WouldBlock)
        ));

        let deadline = crate::time::monotonic_ticks() + 40;
        timerfd::settime(object, Some(deadline), Some(7)).expect("arm the timer");
        let (remaining, period) = timerfd::gettime(object).expect("query the armed timer");
        assert_eq!(period, Some(7));
        assert!(remaining.is_some_and(|ticks| ticks <= 40));

        timerfd::settime(object, None, None).expect("disarm the timer");
        assert!(matches!(timerfd::gettime(object), Ok((None, None))));
        assert!(
            matches!(
                timerfd::read(object),
                Err(timerfd::TimerFdError::WouldBlock)
            ),
            "a disarmed timer keeps its unread count but does not become readable"
        );

        let nonblocking_payload = timerfd::create(timerfd::TimerFdClock::Boottime, TFD_NONBLOCK)
            .expect("timerfd payload");
        let nonblocking_object =
            object::create_with_payload(ObjectKind::TimerFd, nonblocking_payload)
                .expect("timerfd object");
        timerfd::bind(nonblocking_payload, nonblocking_object).expect("bind the timerfd slot");
        assert_eq!(timerfd::nonblocking(nonblocking_object), Ok(true));
        assert_eq!(timerfd::nonblocking(object), Ok(false));

        object::release_object(nonblocking_object).expect("destroy the timerfd");
        object::release_object(object).expect("destroy the timerfd");
        assert_eq!(timerfd::live_count(), 0);
        reset_m9a_hooks();
    }

    #[test]
    fn timerfd_read_rejects_short_and_unmapped_buffers() {
        let _guard = crate::object::test_lock();
        install_m9a_hooks();
        let mut table = FdTable::new();
        let fd = create_timerfd(&mut table, 1, 0);

        assert_eq!(
            done(call(
                NR_READ,
                &[u64::from(fd), 0x1_0000, 4, 0, 0, 0],
                &mut table
            )),
            -errno::EINVAL,
            "the eight-byte counter needs an eight-byte buffer"
        );
        assert_eq!(
            done(call(
                NR_READ,
                &[u64::from(fd), 0x1_0000, 8, 0, 0, 0],
                &mut table
            )),
            -errno::EFAULT,
            "the destination is validated before the counter is consumed"
        );
        assert_eq!(
            done(call(NR_CLOSE, &[u64::from(fd), 0, 0, 0, 0, 0], &mut table)),
            0
        );
        assert_eq!(timerfd::live_count(), 0);
        reset_m9a_hooks();
    }

    #[test]
    fn signalfd_validates_sizemask_and_rejects_short_reads() {
        let _guard = crate::object::test_lock();
        install_m9a_hooks();
        let mut table = FdTable::new();

        assert_eq!(
            done(call(
                NR_SIGNALFD4,
                &[u64::MAX, 0x1_0000, 4, 0, 0, 0],
                &mut table
            )),
            -errno::EINVAL,
            "sigsetsize must be the frozen eight bytes"
        );
        assert_eq!(
            done(call(NR_SIGNALFD4, &[u64::MAX, 0, 8, 0, 0, 0], &mut table)),
            -errno::EFAULT,
            "a null mask pointer is refused"
        );
        assert_eq!(
            done(call(
                NR_SIGNALFD4,
                &[u64::MAX, 0x1_0000, 8, 0, 0, 0],
                &mut table
            )),
            -errno::EFAULT,
            "without an address space the mask cannot be read"
        );

        // The generic `read` routes on the object kind, so a SignalFd object is
        // enough to exercise the size check; it runs before the object is used.
        let object = object::create_with_payload(ObjectKind::SignalFd, 0).expect("signalfd object");
        let fd = table
            .insert(FdEntry::new(object, false))
            .expect("signalfd descriptor");
        assert_eq!(
            done(call(
                NR_READ,
                &[u64::from(fd), 0x1_0000, 127, 0, 0, 0],
                &mut table
            )),
            -errno::EINVAL,
            "a signalfd read produces a full 128-byte siginfo"
        );
        assert_eq!(
            done(call(
                NR_READ,
                &[u64::from(fd), 0x1_0000, 128, 0, 0, 0],
                &mut table
            )),
            -errno::EFAULT
        );
        table.close(fd).expect("drop the descriptor reference");
        object::release_object(object).expect("destroy the signalfd object");
        reset_m9a_hooks();
    }

    #[test]
    fn epoll_create_and_ctl_validate_descriptors_and_interests() {
        let _guard = crate::object::test_lock();
        install_m9a_hooks();
        let mut table = FdTable::new();

        assert_eq!(
            done(call(NR_EPOLL_CREATE, &[0, 0, 0, 0, 0, 0], &mut table)),
            -errno::EINVAL,
            "the legacy epoll_create needs a positive size hint"
        );
        assert_eq!(
            done(call(NR_EPOLL_CREATE1, &[0x1, 0, 0, 0, 0, 0], &mut table)),
            -errno::EINVAL,
            "unknown epoll_create1 flags are refused"
        );
        let epfd = create_epoll(&mut table);
        let ep_object = object_of(&table, epfd);
        assert_eq!(object::object_kind(ep_object), Some(ObjectKind::Epoll));
        let event_fd = create_eventfd(&mut table);
        let timer_fd = create_timerfd(&mut table, 1, 0);
        let console = object::create_with_payload(ObjectKind::Console, 0).expect("console object");
        let console_fd = table
            .insert(FdEntry::new(console, false))
            .expect("console descriptor");

        assert_eq!(
            done(call(
                NR_EPOLL_CTL,
                &[u64::from(event_fd), EPOLL_CTL_ADD, u64::from(epfd), 0, 0, 0],
                &mut table
            )),
            -errno::EINVAL,
            "the epoll descriptor must refer to an epoll object"
        );
        assert_eq!(
            done(call(
                NR_EPOLL_CTL,
                &[u64::from(epfd), 7, u64::from(event_fd), 0, 0, 0],
                &mut table
            )),
            -errno::EINVAL,
            "unknown epoll_ctl operations are refused"
        );
        assert_eq!(
            done(call(
                NR_EPOLL_CTL,
                &[
                    u64::from(epfd),
                    EPOLL_CTL_ADD,
                    u64::from(console_fd),
                    0,
                    0,
                    0
                ],
                &mut table
            )),
            -errno::EINVAL,
            "a console is not an epoll target"
        );
        assert_eq!(
            done(call(
                NR_EPOLL_CTL,
                &[u64::from(epfd), EPOLL_CTL_ADD, u64::from(event_fd), 0, 0, 0],
                &mut table
            )),
            -errno::EFAULT,
            "a null event pointer is refused"
        );
        assert_eq!(
            done(call(
                NR_EPOLL_CTL,
                &[u64::from(epfd), EPOLL_CTL_DEL, u64::from(timer_fd), 0, 0, 0],
                &mut table
            )),
            -errno::ENOENT,
            "deleting an unregistered interest is ENOENT"
        );

        // The mask validator accepts EPOLLET (the kernel tracks the edge) but
        // still refuses EPOLLONESHOT, which needs the post-delivery disarm step.
        assert_eq!(epoll_interest_events(EPOLLIN), Ok(EPOLLIN));
        assert_eq!(
            epoll_interest_events(EPOLLIN | EPOLLOUT | EPOLLERR | EPOLLHUP),
            Ok(EPOLLIN | EPOLLOUT | EPOLLERR | EPOLLHUP)
        );
        assert_eq!(
            epoll_interest_events(EPOLLIN | EPOLLET),
            Ok(EPOLLIN | EPOLLET),
            "M9b accepts edge-triggered interests"
        );
        assert_eq!(epoll_interest_events(EPOLLONESHOT), Err(errno::EINVAL));
        assert_eq!(epoll_interest_events(0x8000), Err(errno::EINVAL));

        // Real bookkeeping on a second instance: EEXIST and missing MOD/DEL.
        let payload = epoll::create().expect("epoll payload");
        let object = object::create_with_payload(ObjectKind::Epoll, payload).expect("epoll object");
        epoll::bind(payload, object).expect("bind the epoll slot");
        let event_object = object_of(&table, event_fd);
        let timer_object = object_of(&table, timer_fd);
        epoll::ctl_add(object, event_object, EPOLLIN, 0x11).expect("add one interest");
        assert!(matches!(
            epoll::ctl_add(object, event_object, EPOLLIN, 0x22),
            Err(epoll::EpollError::AlreadyExists)
        ));
        assert!(matches!(
            epoll::ctl_mod(object, timer_object, EPOLLOUT, 0),
            Err(epoll::EpollError::NotFound)
        ));
        assert!(matches!(
            epoll::ctl_del(object, timer_object),
            Err(epoll::EpollError::NotFound)
        ));
        epoll::ctl_del(object, event_object).expect("delete the interest");
        object::release_object(object).expect("destroy the epoll object");
        assert_eq!(
            epoll::live_count(),
            1,
            "the instance behind the epoll descriptor is still open"
        );

        table.close(console_fd).ok();
        object::release_object(console).expect("destroy the console object");
        table.close(event_fd).ok();
        table.close(timer_fd).ok();
        table.close(epfd).ok();
        assert_eq!(eventfd::live_count(), 0);
        assert_eq!(epoll::live_count(), 0);
        reset_m9a_hooks();
    }

    #[test]
    fn epoll_wait_validates_maxevents_and_keeps_lt_readiness() {
        let _guard = crate::object::test_lock();
        install_m9a_hooks();
        let mut table = FdTable::new();
        let epfd = create_epoll(&mut table);
        let event_fd = create_eventfd(&mut table);
        let event_object = object_of(&table, event_fd);

        assert_eq!(
            done(call(
                NR_EPOLL_WAIT,
                &[u64::from(event_fd), 0x1_0000, 1, 0, 0, 0],
                &mut table
            )),
            -errno::EINVAL,
            "the descriptor must be an epoll instance"
        );
        assert_eq!(
            done(call(
                NR_EPOLL_WAIT,
                &[u64::from(epfd), 0x1_0000, 0, 0, 0, 0],
                &mut table
            )),
            -errno::EINVAL
        );
        assert_eq!(
            done(call(
                NR_EPOLL_WAIT,
                &[u64::from(epfd), 0x1_0000, 17, 0, 0, 0],
                &mut table
            )),
            -errno::EINVAL
        );
        assert_eq!(
            done(call(
                NR_EPOLL_WAIT,
                &[u64::from(epfd), 0, 1, 0, 0, 0],
                &mut table
            )),
            -errno::EFAULT
        );
        assert_eq!(
            done(call(
                NR_EPOLL_WAIT,
                &[u64::from(epfd), 0x1_0000, 1, 0, 0, 0],
                &mut table
            )),
            -errno::EFAULT,
            "the result array is validated before waiting"
        );

        // Level-triggered readiness survives repeated snapshots; MOD replaces
        // the user data carried by the interest.
        let payload = epoll::create().expect("epoll payload");
        let object = object::create_with_payload(ObjectKind::Epoll, payload).expect("epoll object");
        epoll::bind(payload, object).expect("bind the epoll slot");
        epoll::ctl_add(object, event_object, EPOLLIN, 0x1111).expect("register the eventfd");
        eventfd::write(event_object, 1).expect("make the eventfd readable");
        assert!(matches!(epoll::any_ready(object), Ok(true)));
        let empty = epoll::ReadyEvent {
            target: 0,
            data: 0,
            events: 0,
        };
        let mut events = [empty; 4];
        assert!(matches!(epoll::snapshot(object, &mut events), Ok(1)));
        assert_eq!(events[0].target, event_object);
        assert_eq!(events[0].data, 0x1111);
        assert!(
            matches!(epoll::snapshot(object, &mut events), Ok(1)),
            "observing a level-triggered interest does not consume its readiness"
        );
        epoll::ctl_mod(object, event_object, EPOLLIN, 0x2222).expect("update the interest data");
        assert!(matches!(epoll::snapshot(object, &mut events), Ok(1)));
        assert_eq!(events[0].data, 0x2222);
        epoll::ctl_del(object, event_object).expect("remove the interest");
        object::release_object(object).expect("destroy the epoll object");

        table.close(event_fd).ok();
        table.close(epfd).ok();
        assert_eq!(epoll::live_count(), 0);
        assert_eq!(eventfd::live_count(), 0);
        reset_m9a_hooks();
    }

    #[test]
    fn epoll_pwait_mask_request_and_restore_state_round_trip() {
        assert_eq!(epoll_pwait_mask_request(&[0, 0, 0, 0, 0, 0]), Ok(None));
        assert_eq!(
            epoll_pwait_mask_request(&[0, 0, 0, 0, 0x1_0000, 4]),
            Err(errno::EINVAL),
            "sigsetsize must be the frozen eight bytes"
        );
        assert_eq!(
            epoll_pwait_mask_request(&[0, 0, 0, 0, 0x1_0000, u64::from(signal::SIGSET_SIZE)]),
            Ok(Some(0x1_0000))
        );
        assert_eq!(
            ppoll_mask_request(&[0, 0, 0, 0x1_0000, 4, 0]),
            Err(errno::EINVAL)
        );

        let mut table = FdTable::new();
        table.begin_ppoll_mask(0b1010);
        table.begin_ppoll_mask(0b1111);
        assert_eq!(
            table.ppoll_mask(),
            Some(0b1010),
            "a replay keeps the original mask instead of overwriting it"
        );
        assert_eq!(table.end_ppoll_mask(), Some(0b1010));
        assert_eq!(table.ppoll_mask(), None);
        assert_eq!(table.take_pending_mask_restore(), None);
        table.set_pending_mask_restore(0b1010);
        assert_eq!(table.take_pending_mask_restore(), Some(0b1010));
        assert_eq!(table.take_pending_mask_restore(), None);
    }
}

#[cfg(test)]
mod m9b_tests {
    use super::*;
    use crate::compat::linux::{address, msg};
    use crate::net::{self, SocketId};

    /// Create a real UNIX datagram socket through `socket(2)`.
    fn unix_dgram_socket(context: &mut LinuxContext<'_>) -> u32 {
        match dispatch(
            NR_SOCKET,
            &[
                u64::from(address::AF_UNIX),
                u64::from(SOCK_DGRAM),
                0,
                0,
                0,
                0,
            ],
            context,
        ) {
            Outcome::Done(fd) if fd >= 3 => fd as u32,
            other => panic!("socket(AF_UNIX, SOCK_DGRAM) failed: {other:?}"),
        }
    }

    /// The engine socket behind a descriptor.
    fn socket_id_of(context: &LinuxContext<'_>, fd: u32) -> SocketId {
        let entry = context.fds.get(fd).expect("descriptor is installed");
        let payload = object::payload(entry.object).expect("socket object has a payload");
        let raw = payload as u32;
        SocketId::new((raw >> 16) as usize, raw as u16)
    }

    /// Close the descriptor and destroy the engine socket it points at.
    fn destroy_socket(context: &mut LinuxContext<'_>, fd: u32) {
        if let Ok(entry) = context.fds.get(fd) {
            if let Some(payload) = object::payload(entry.object) {
                let raw = payload as u32;
                let id = SocketId::new((raw >> 16) as usize, raw as u16);
                let _ = net::destroy(id);
            }
        }
        context.fds.close(fd).ok();
    }

    #[test]
    fn sendmsg_and_recvmsg_validate_descriptors_before_any_userspace_copy() {
        let _guard = crate::object::test_lock();
        let console = object::create_with_payload(ObjectKind::Console, 0).expect("console object");
        let mut table = FdTable::new();
        table.install_console(console).expect("install console");
        {
            let mut context = LinuxContext::new(&mut table, 0, None);
            // Empty descriptor: EBADF regardless of the header pointer.
            assert_eq!(
                dispatch(NR_SENDMSG, &[3, 0x1000, 0, 0, 0, 0], &mut context),
                Outcome::Done(-errno::EBADF)
            );
            assert_eq!(
                dispatch(NR_RECVMSG, &[3, 0x1000, 0, 0, 0, 0], &mut context),
                Outcome::Done(-errno::EBADF)
            );
            // Console descriptor is not a socket.
            assert_eq!(
                dispatch(NR_SENDMSG, &[0, 0x1000, 0, 0, 0, 0], &mut context),
                Outcome::Done(-errno::ENOTSOCK)
            );
            assert_eq!(
                dispatch(NR_RECVMSG, &[0, 0x1000, 0, 0, 0, 0], &mut context),
                Outcome::Done(-errno::ENOTSOCK)
            );
        }
        table.close(0).ok();
        table.close(1).ok();
        table.close(2).ok();
        let _ = object::release_object(console);
    }

    #[test]
    fn a_null_msghdr_pointer_is_efault_and_a_real_socket_reaches_the_engine() {
        let _guard = crate::object::test_lock();
        let mut table = FdTable::new();
        let mut context = LinuxContext::new(&mut table, 0, None);
        let fd = unix_dgram_socket(&mut context);
        let id = socket_id_of(&context, fd);
        let raw_fd = u64::from(fd);
        // A null msghdr is rejected before copying anything.
        assert_eq!(
            dispatch(NR_SENDMSG, &[raw_fd, 0, 0, 0, 0, 0], &mut context),
            Outcome::Done(-errno::EFAULT)
        );
        assert_eq!(
            dispatch(NR_RECVMSG, &[raw_fd, 0, 0, 0, 0, 0], &mut context),
            Outcome::Done(-errno::EFAULT)
        );
        // A non-null header cannot be copied without an address space; the
        // error comes from the copy, not from a fabricated success.
        assert_eq!(
            dispatch(NR_SENDMSG, &[raw_fd, 0x1000, 0, 0, 0, 0], &mut context),
            Outcome::Done(-errno::EFAULT)
        );
        assert_eq!(
            dispatch(NR_RECVMSG, &[raw_fd, 0x1000, 0, 0, 0, 0], &mut context),
            Outcome::Done(-errno::EFAULT)
        );
        destroy_socket(&mut context, fd);
        assert!(
            net::object_of(id).is_none(),
            "closing the descriptor destroys the engine socket"
        );
    }

    #[test]
    fn socket_options_reach_the_engine_through_a_real_descriptor() {
        let _guard = crate::object::test_lock();
        let mut table = FdTable::new();
        let mut context = LinuxContext::new(&mut table, 0, None);
        let fd = unix_dgram_socket(&mut context);
        let id = socket_id_of(&context, fd);
        let raw_fd = u64::from(fd);

        // SO_PEERCRED on an unconnected socket is EINVAL: the engine answered
        // before any userspace copy happened (the buffers are unmapped).
        assert_eq!(
            dispatch(
                NR_GETSOCKOPT,
                &[raw_fd, SOL_SOCKET, msg::SO_PEERCRED, 0x1000, 0x1004, 0],
                &mut context
            ),
            Outcome::Done(-errno::EINVAL)
        );
        // SO_ERROR has a value to write but no address space: EFAULT, never a
        // fake zero that would claim the socket is clean.
        assert_eq!(
            dispatch(
                NR_GETSOCKOPT,
                &[raw_fd, SOL_SOCKET, SO_ERROR, 0x1000, 0x1004, 0],
                &mut context
            ),
            Outcome::Done(-errno::EFAULT)
        );
        // SO_PASSCRED needs a user value to read; without an address space the
        // copy fails before the engine is touched.
        assert_eq!(
            dispatch(
                NR_SETSOCKOPT,
                &[raw_fd, SOL_SOCKET, msg::SO_PASSCRED, 0x1000, 4, 0],
                &mut context
            ),
            Outcome::Done(-errno::EFAULT)
        );
        destroy_socket(&mut context, fd);
        assert!(net::object_of(id).is_none());
    }

    #[test]
    fn control_message_helpers_compose_a_rights_and_credentials_buffer() {
        // The wire helpers used by `sendmsg`/`recvmsg` share one layout: build
        // both control messages, walk them back and verify the payloads.
        let mut control = [0u8; msg::MSG_CONTROL_MAX];
        let mut cursor = 0usize;
        let mut rights = [0u8; 8];
        rights[0..4].copy_from_slice(&4i32.to_le_bytes());
        rights[4..8].copy_from_slice(&7i32.to_le_bytes());
        assert!(msg::push_cmsg(
            &mut control,
            &mut cursor,
            msg::SOL_SOCKET,
            msg::SCM_RIGHTS,
            &rights
        ));
        let ucred = msg::Ucred::current(12);
        assert!(msg::push_cmsg(
            &mut control,
            &mut cursor,
            msg::SOL_SOCKET,
            msg::SCM_CREDENTIALS,
            &msg::encode_ucred(&ucred)
        ));

        let mut iterator = msg::CmsgIter::new(&control[..cursor]);
        let first = iterator.next().unwrap().unwrap();
        assert_eq!(
            (first.level, first.kind),
            (msg::SOL_SOCKET, msg::SCM_RIGHTS)
        );
        let mut decoded = [0i32; msg::SCM_MAX_FD];
        assert_eq!(msg::parse_scm_rights(first.data, &mut decoded), Ok(2));
        assert_eq!(&decoded[..2], &[4, 7]);
        let second = iterator.next().unwrap().unwrap();
        assert_eq!(
            (second.level, second.kind),
            (msg::SOL_SOCKET, msg::SCM_CREDENTIALS)
        );
        assert_eq!(msg::parse_ucred(second.data), Ok(ucred));
        assert!(iterator.next().unwrap().is_none());
    }

    #[test]
    fn unix_messages_carry_the_sender_credential_by_default() {
        let _guard = crate::object::test_lock();
        // Helper semantics: UNIX gets the sender credential, INET does not, and
        // an explicit pid 0 means "the sending process".
        assert_eq!(
            send_credential(address::AF_UNIX, None, 42).map(|cred| (cred.pid, cred.uid, cred.gid)),
            Some((42, 0, 0))
        );
        assert_eq!(send_credential(address::AF_INET, None, 42), None);
        assert_eq!(
            send_credential(address::AF_UNIX, Some(net::Credential::new(0, 0, 0)), 42)
                .map(|cred| cred.pid),
            Some(42)
        );

        // Real engine round trip: a message sent without any control data must
        // still reach the receiver with the sender credential attached.
        let (sender, receiver) =
            net::socket_pair(net::DOMAIN_UNIX, net::SOCK_DGRAM).expect("UNIX datagram pair");
        let credential = send_credential(address::AF_UNIX, None, 42);
        net::send_msg(sender, b"cred", &[], credential).expect("send without control data");
        let mut buffer = [0u8; 16];
        let mut objects = [0u16; net::MAX_SCM_FDS];
        let received = net::recv_msg(receiver, &mut buffer, &mut objects).expect("receive");
        assert_eq!(received.len, 4);
        assert_eq!(&buffer[..4], b"cred");
        let carried = received.cred.expect("UNIX messages carry credentials");
        assert_eq!((carried.pid, carried.uid, carried.gid), (42, 0, 0));
        let _ = net::destroy(sender);
        let _ = net::destroy(receiver);
    }
}

#[cfg(test)]
mod m9c_tests {
    use super::*;

    fn console_table() -> (ObjectId, FdTable) {
        let console = object::create_with_payload(ObjectKind::Console, 0).expect("console object");
        let mut table = FdTable::new();
        table.install_console(console).expect("install console");
        (console, table)
    }

    fn dispose_console(table: &mut FdTable, console: ObjectId) {
        for fd in 0..3 {
            table.close(fd).ok();
        }
        let _ = object::release_object(console);
    }

    fn unix_dgram(context: &mut LinuxContext<'_>) -> u32 {
        match dispatch(
            NR_SOCKET,
            &[
                u64::from(crate::compat::linux::address::AF_UNIX),
                u64::from(SOCK_DGRAM),
                0,
                0,
                0,
                0,
            ],
            context,
        ) {
            Outcome::Done(fd) if fd >= 3 => fd as u32,
            other => panic!("socket(AF_UNIX, SOCK_DGRAM) failed: {other:?}"),
        }
    }

    fn destroy_socket(context: &mut LinuxContext<'_>, fd: u32) {
        if let Ok(entry) = context.fds.get(fd)
            && let Some(payload) = object::payload(entry.object)
        {
            let raw = payload as u32;
            let _ = net::destroy(SocketId::new((raw >> 16) as usize, raw as u16));
        }
        context.fds.close(fd).ok();
    }

    #[test]
    fn lock_commands_reject_missing_and_non_file_descriptors() {
        let _guard = crate::object::test_lock();
        let (console, mut table) = console_table();
        {
            let mut context = LinuxContext::new(&mut table, 0, None);
            // Empty descriptor: EBADF for every lock entry point.
            assert_eq!(
                dispatch(
                    NR_FLOCK,
                    &[3, u64::from(file_lock::LOCK_SH), 0, 0, 0, 0],
                    &mut context
                ),
                Outcome::Done(-errno::EBADF)
            );
            assert_eq!(
                dispatch(NR_FCNTL, &[3, F_SETLK, 0x1000, 0, 0, 0], &mut context),
                Outcome::Done(-errno::EBADF)
            );
            // The console is not a file description.
            assert_eq!(
                dispatch(
                    NR_FLOCK,
                    &[0, u64::from(file_lock::LOCK_EX), 0, 0, 0, 0],
                    &mut context
                ),
                Outcome::Done(-errno::EBADF)
            );
            assert_eq!(
                dispatch(NR_FCNTL, &[0, F_GETLK, 0x1000, 0, 0, 0], &mut context),
                Outcome::Done(-errno::EBADF)
            );
        }
        dispose_console(&mut table, console);
    }

    #[test]
    fn flock_operation_words_are_validated_before_the_descriptor() {
        let _guard = crate::object::test_lock();
        let mut table = FdTable::new();
        let mut context = LinuxContext::new(&mut table, 0, None);
        // Invalid operation words fail with EINVAL even when the fd is empty.
        for operation in [
            u64::from(file_lock::LOCK_SH | file_lock::LOCK_EX),
            u64::from(file_lock::LOCK_SH | file_lock::LOCK_UN),
            0u64,
            0x10u64,
        ] {
            assert_eq!(
                dispatch(NR_FLOCK, &[3, operation, 0, 0, 0, 0], &mut context),
                Outcome::Done(-errno::EINVAL),
                "operation {operation:#x}"
            );
        }
    }

    #[test]
    fn setfl_zero_is_a_noop_and_other_flags_are_unsupported() {
        let _guard = crate::object::test_lock();
        let (console, mut table) = console_table();
        {
            let mut context = LinuxContext::new(&mut table, 0, None);
            assert_eq!(
                dispatch(NR_FCNTL, &[0, F_SETFL, 0, 0, 0, 0], &mut context),
                Outcome::Done(0)
            );
            assert_eq!(
                dispatch(NR_FCNTL, &[0, F_SETFL, 0o2000, 0, 0, 0], &mut context),
                Outcome::Done(-errno::EOPNOTSUPP)
            );
            assert_eq!(
                dispatch(NR_FCNTL, &[3, F_SETFL, 0, 0, 0, 0], &mut context),
                Outcome::Done(-errno::EBADF)
            );
        }
        dispose_console(&mut table, console);
    }

    #[test]
    fn dupfd_keeps_the_socket_family_and_rejects_an_unreachable_minimum() {
        let _guard = crate::object::test_lock();
        let (console, mut table) = console_table();
        {
            let mut context = LinuxContext::new(&mut table, 0, None);
            let socket = unix_dgram(&mut context);
            match dispatch(
                NR_FCNTL,
                &[u64::from(socket), F_DUPFD, 3, 0, 0, 0],
                &mut context,
            ) {
                Outcome::Done(duplicate) if duplicate >= 3 => {
                    let original = context.fds.get(socket).expect("socket fd");
                    let copied = context.fds.get(duplicate as u32).expect("duplicate fd");
                    assert_eq!(copied.domain, original.domain);
                    assert_eq!(copied.domain, crate::compat::linux::address::AF_UNIX);
                    destroy_socket(&mut context, duplicate as u32);
                }
                other => panic!("F_DUPFD failed: {other:?}"),
            }
            // A minimum at or beyond the table size cannot be satisfied.
            assert_eq!(
                dispatch(
                    NR_FCNTL,
                    &[
                        u64::from(socket),
                        F_DUPFD,
                        u64::from(super::super::fd::MAX_FDS as u32),
                        0,
                        0,
                        0
                    ],
                    &mut context
                ),
                Outcome::Done(-errno::EINVAL)
            );
            destroy_socket(&mut context, socket);
        }
        dispose_console(&mut table, console);
    }

    #[test]
    fn lock_wait_arms_one_tick_and_cancellation_is_eintr() {
        let _guard = crate::object::test_lock();
        use crate::process::WakeReason;
        assert_eq!(lock_wait_after(WakeReason::Cancelled), Err(errno::EINTR));
        for reason in [WakeReason::None, WakeReason::Ready, WakeReason::Timeout] {
            match lock_wait_after(reason) {
                Ok(Outcome::Wait {
                    object,
                    deadline: Some(deadline),
                }) => {
                    assert_eq!(object, SLEEP_OBJECT);
                    assert!(deadline > 0);
                }
                other => panic!("unexpected lock wait: {other:?}"),
            }
        }
    }
}
