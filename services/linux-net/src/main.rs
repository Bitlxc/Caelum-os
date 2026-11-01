//! CaelumOS M7d Linux64 personality self-test (single process).
//!
//! This program is deliberately **not** a native-ABI program: it is built for
//! the Linux x86-64 personality and talks to the kernel only through the Linux
//! system call instruction and the Linux process-startup stack.
//!
//! # Entry contract
//!
//! As on Linux, `_start` receives no arguments in registers. The kernel builds
//! the System V initial stack image and sets `rsp` to its first word:
//!
//! ```text
//! rsp + 0x00  argc (= 0)
//! rsp + 0x08  argv[0] = NULL
//! rsp + 0x10  envp[0] = NULL
//! rsp + 0x18  auxv[0].a_type, auxv[0].a_val
//! ...
//!             AT_NULL, 0
//! ```
//!
//! The Caelum-specific auxv entries carry the initial native handles the
//! personality needs ([`AT_CAELUM_CHANNEL`], [`AT_CAELUM_NETNS`]); the standard
//! descriptors 0/1/2 are the console. `_start` here is a small assembly shim
//! that moves the initial `rsp` into `rdi` and calls the Rust body; the Rust
//! body must never take handles from `rdi`/`rsi`/`rdx` as if it were a native
//! program.
//!
//! # Coverage
//!
//! Startup: argc/argv/envp image, `AT_PAGESZ`, both Caelum auxv entries,
//! `getpid`/`getuid`. Sockets: IPv4 and IPv6 UDP (ephemeral `bind`, local
//! address read-back, payload), IPv4 and IPv6 TCP (listener/client/accept,
//! bidirectional data, `shutdown` half-close and EOF), UNIX stream/datagram
//! `socketpair` and a netns-authorised named datagram socket. Descriptors: the
//! lowest-free allocation rule, `dup` sharing and `close` reference release.
//! Negative paths: `ENOSYS` for an unknown call, `EBADF`, `ENOTSOCK` for the
//! console descriptor and `EMSGSIZE` for a datagram that does not fit (and is
//! not consumed).
//!
//! Every wait in this program is a normal blocking Linux system call; the
//! suites never depend on wall-clock timeouts.

#![no_std]
#![no_main]

use core::arch::{asm, global_asm};
use core::panic::PanicInfo;
use core::ptr::addr_of_mut;

// ---------------------------------------------------------------------------
// ELF entry: preserve the initial Linux stack pointer and call the Rust body.
// ---------------------------------------------------------------------------

global_asm!(
    r#"
    .section .text._start, "ax", @progbits
    .global _start
    .type _start, @function
_start:
    mov rdi, rsp
    and rsp, -16
    call {entry}
    ud2
    .size _start, . - _start
    "#,
    entry = sym linux_entry,
);

// `sa_restorer` target: after the Rust handler returns, the kernel resumes
// this stub, whose `rt_sigreturn` restores the interrupted context (including
// every general-purpose register) from the signal frame.
global_asm!(
    r#"
    .section .text.rt_sigreturn_restorer, "ax", @progbits
    .global rt_sigreturn_restorer
    .type rt_sigreturn_restorer, @function
rt_sigreturn_restorer:
    mov eax, 15
    syscall
    ud2
    .size rt_sigreturn_restorer, . - rt_sigreturn_restorer
    "#
);

/// Linux x86-64 system call numbers (System V ABI / Linux kernel).
const NR_READ: u64 = 0;
const NR_WRITE: u64 = 1;
const NR_CLOSE: u64 = 3;
const NR_DUP: u64 = 32;
const NR_GETPID: u64 = 39;
const NR_SOCKET: u64 = 41;
const NR_CONNECT: u64 = 42;
const NR_ACCEPT: u64 = 43;
const NR_SENDTO: u64 = 44;
const NR_RECVFROM: u64 = 45;
/// M9b: `sendmsg` / `recvmsg` (control messages carry `SCM_RIGHTS` fds).
const NR_SENDMSG: u64 = 46;
const NR_RECVMSG: u64 = 47;
const NR_BIND: u64 = 49;
const NR_LISTEN: u64 = 50;
const NR_GETSOCKNAME: u64 = 51;
const NR_GETPEERNAME: u64 = 52;
const NR_SOCKETPAIR: u64 = 53;
const NR_SETSOCKOPT: u64 = 54;
const NR_GETSOCKOPT: u64 = 55;
/// `shutdown` in the Linux x86-64 table.
const NR_SHUTDOWN: u64 = 48;
/// Current `kernel/src/compat/linux/syscall.rs` value (deviation); the wrapper
/// retries this number only when the Linux one reports `ENOSYS`.
const NR_SHUTDOWN_COMPAT: u64 = 56;
/// M8a: memory-management calls (Linux x86-64 numbers).
const NR_MMAP: u64 = 9;
const NR_MPROTECT: u64 = 10;
const NR_MUNMAP: u64 = 11;
const NR_BRK: u64 = 12;
/// M8a: `openat` (the only path-based open used by this program).
const NR_OPENAT: u64 = 257;
const NR_GETUID: u64 = 102;
/// M9b: `getgid` (credential assertions).
const NR_GETGID: u64 = 104;
const NR_EXIT_GROUP: u64 = 231;

/// M8b: information and time calls (Linux x86-64 numbers).
const NR_UNAME: u64 = 63;
const NR_CLOCK_GETTIME: u64 = 228;
const NR_CLOCK_NANOSLEEP: u64 = 230;
const NR_SYSINFO: u64 = 99;
const NR_GETPPID: u64 = 110;

/// M8c: Linux64 signal ABI numbers (`rt_sigreturn` = 15 is only used by the
/// restorer assembly installed as `sa_restorer`).
const NR_RT_SIGACTION: u64 = 13;
const NR_RT_SIGPROCMASK: u64 = 14;
const NR_KILL: u64 = 62;
const NR_TGKILL: u64 = 234;
/// M8d: `wait4` (blocking child reaping and the `WNOHANG` poll).
const NR_WAIT4: u64 = 61;
/// `wait4` option: do not block (`WNOHANG`).
const WNOHANG: u64 = 1;
/// M8e: `lseek`.
const NR_LSEEK: u64 = 8;
/// M8e: `fstat`.
const NR_FSTAT: u64 = 5;
/// M8e: `fcntl`.
const NR_FCNTL: u64 = 72;
/// M8e: `getdents64`.
const NR_GETDENTS64: u64 = 217;
/// M8e: `statx`.
const NR_STATX: u64 = 332;
/// M8f: `futex` (wait/wake closure).
const NR_FUTEX: u64 = 202;
/// M8f: `arch_prctl` (`ARCH_SET_FS` / `ARCH_GET_FS`).
const NR_ARCH_PRCTL: u64 = 158;
/// M8f: `set_tid_address`.
const NR_SET_TID_ADDRESS: u64 = 218;
/// M8g: `eventfd2` (two-argument form: initial count + flags).
const NR_EVENTFD2: u64 = 290;
/// M8g: `poll`.
const NR_POLL: u64 = 7;
/// M8g: `ppoll` (relative `timespec`; NULL means infinite).
const NR_PPOLL: u64 = 271;
/// M9a: `epoll_wait` (level-triggered readiness, milliseconds timeout).
const NR_EPOLL_WAIT: u64 = 232;
/// M9a: `epoll_ctl` (`ADD` / `MOD` / `DEL`).
const NR_EPOLL_CTL: u64 = 233;
/// M9a: `epoll_pwait` (temporary signal mask variant of `epoll_wait`).
const NR_EPOLL_PWAIT: u64 = 281;
/// M9a: `signalfd4` (signalfd creation carrying an explicit flags argument).
const NR_SIGNALFD4: u64 = 289;
/// M9a: `timerfd_create`.
const NR_TIMERFD_CREATE: u64 = 283;
/// M9a: `timerfd_settime` (arm / rearm / disarm).
const NR_TIMERFD_SETTIME: u64 = 286;
/// M9a: `timerfd_gettime` (query interval and remaining value).
const NR_TIMERFD_GETTIME: u64 = 287;
/// M9a: `epoll_create1`.
const NR_EPOLL_CREATE1: u64 = 291;
/// M9c: `flock` (the BSD whole-file lock domain).
const NR_FLOCK: u64 = 73;

/// User signals and the `SIG_IGN` handler value.
const SIGUSR1: u64 = 10;
const SIGUSR2: u64 = 12;
/// M8d handshake ping: `SIGWINCH` defaults to ignore, so a lost ping cannot
/// terminate either process before its handler is installed.
const SIGWINCH: u64 = 28;
const SIG_IGN: u64 = 1;
/// `rt_sigprocmask` `how` values used by the signal closure.
const SIG_BLOCK: u64 = 0;
const SIG_UNBLOCK: u64 = 1;
/// Kernel 64-bit sigset size (`_NSIG / 8`).
const SIGSET_BYTES: u64 = 8;
/// x86-64 `SA_RESTORER`: the action carries an explicit restorer address.
const SA_RESTORER: u64 = 0x0400_0000;
/// Sentinel held in `r8`/`r9` across signal delivery: `rt_sigreturn` must
/// restore both to this value when it restores the interrupted context.

/// M9a: timerfd / signalfd / epoll constants.
const TFD_NONBLOCK: u64 = 0x800;
const SFD_NONBLOCK: u64 = 0x800;
/// `epoll_event.events` bits used by the level-triggered closure.
const EPOLLIN: u32 = 0x1;
const EPOLLOUT: u32 = 0x4;
/// `epoll_ctl` operations.
const EPOLL_CTL_ADD: u64 = 1;
const EPOLL_CTL_DEL: u64 = 2;
const EPOLL_CTL_MOD: u64 = 3;
/// `rt_sigprocmask` restore value (M8d only ever unblocked; M9a restores).
const SIG_SETMASK: u64 = 2;
/// Bytes in one `signalfd_siginfo` record.
const SIGINFO_BYTES: u64 = 128;
/// Maximum events requested per `epoll_wait`.
const EPOLL_MAX_EVENTS: u64 = 16;
/// M9a relative timer periods (nanoseconds; the scheduler tick is 10 ms).
const M9A_TIMER_FIRST_NS: i64 = 30_000_000;
const M9A_TIMER_SLEEP_NS: i64 = 60_000_000;
const M9A_TIMER_PERIOD_NS: i64 = 30_000_000;
const M9A_TIMER_PERIOD_SLEEP_NS: i64 = 90_000_000;
/// M9a epoll wait bounds.
const M9A_WAIT_MS: i64 = 200;
const M9A_SHORT_TIMEOUT_MS: i64 = 50;
const M9A_MIN_SHORT_ELAPSED_NS: i64 = 10_000_000;
const M9A_PWAIT_MS: i64 = 1000;

/// M9c: POSIX record-lock and `flock` ABI constants (frozen with the kernel).
const F_GETFL: u64 = 3;
const F_GETLK: u64 = 5;
const F_SETLK: u64 = 6;
const F_SETLKW: u64 = 7;
/// `O_ACCMODE`: the access-mode mask of the open file status flags.
const O_ACCMODE: u64 = 3;
/// `struct flock.l_type` values.
const F_RDLCK: u16 = 0;
const F_WRLCK: u16 = 1;
const F_UNLCK: u16 = 2;
/// `flock` operations.
const LOCK_EX: u64 = 2;
const LOCK_NB: u64 = 4;
const LOCK_UN: u64 = 8;
/// Frozen x86-64 `struct flock` image: 32 bytes, 8-byte aligned, with
/// `l_type@0`, `l_whence@2`, `l_start@8`, `l_len@16` and `l_pid@24`.
const FLOCK_BYTES: usize = 32;
const FLOCK_WHENCE_SET: u16 = 0;
/// M9c: the ramfs file whose lock domain is exercised.
const M9C_FILE_PATH: &[u8] = b"/m9c-locks.bin\0";
/// M9c handshake commands: the parent broadcasts them with `SIGUSR2`; after
/// each action the peer acknowledges with a broadcast `SIGUSR1`.
const M9C_CMD_VALIDATE: u64 = 1;
const M9C_CMD_BLOCK: u64 = 2;
const M9C_CMD_UNLOCK: u64 = 3;
const M9C_CMD_EXPECT_HELD: u64 = 4;
const M9C_CMD_EXPECT_RELEASED: u64 = 5;
const M9C_CMD_FLOCK_CONFLICT: u64 = 6;
const M9C_CMD_FLOCK_AVAILABLE: u64 = 7;
const M9C_CMD_EXIT: u64 = 8;
/// One 10 ms poll step and its handshake bound (300 steps = 3 s).
const M9C_POLL_NS: i64 = 10_000_000;
const M9C_ACK_TICKS: u64 = 300;
/// The parent releases its write lock 100 ms after issuing the blocking
/// command; the peer asserts it stayed blocked for at least half of that.
const M9C_BLOCK_RELEASE_NS: i64 = 100_000_000;
const M9C_MIN_BLOCKED_NS: i64 = 50_000_000;
/// Duplicate-descriptor floors well above the stdio descriptors.
/// `F_DUPFD` floor for the descriptor-flags steps.
///
/// The Linux fd table is frozen at 16 descriptors (`fd::MAX_FDS` in the kernel),
/// and `F_DUPFD` rejects a minimum at or beyond the table size with `EINVAL`
/// instead of faking an unreachable number. The floors therefore stay small
/// enough to be satisfiable (6/8/10 are above the console fds and the file fd,
/// so the duplicate is a fresh descriptor) while still proving `>= floor`.
const M9C_DUP_FLOOR: u64 = 6;
/// `F_DUPFD_CLOEXEC` floor (see [`M9C_DUP_FLOOR`]).
const M9C_DUP_FLOOR_CLOEXEC: u64 = 8;
/// Duplicate floor used by the close-releases-POSIX-locks step.
const M9C_DUP_FLOOR_CLOSE: u64 = 10;

/// Clock identifiers used by the M8b time closure.
const CLOCK_REALTIME: u64 = 0;
const CLOCK_MONOTONIC: u64 = 1;
const CLOCK_BOOTTIME: u64 = 7;
/// `clock_nanosleep` flag: the request is an absolute time.
const TIMER_ABSTIME: u64 = 1;
/// One second in nanoseconds.
const NSEC_PER_SEC: i64 = 1_000_000_000;
/// Scheduler tick: 100 Hz (10 ms), the period the M7b net self-test assumes.
const TICK_NS: i64 = 10_000_000;
/// Relative sleep request: 3 ticks.
const M8B_SLEEP_NS: i64 = 3 * TICK_NS;
/// Minimum acceptable monotonic progress for a sleep of `M8B_SLEEP_NS`.
const M8B_MIN_ELAPSED_NS: i64 = 2 * TICK_NS;

/// `ENOSYS`.
const ENOSYS: i64 = 38;
/// `EBADF`.
const EBADF: i64 = 9;
/// `EAGAIN`.
const EAGAIN: i64 = 11;
/// `EINTR`: a blocking `wait4` was restarted after signal delivery.
const EINTR: i64 = 4;
/// `ECHILD`: no waitable child remains.
const ECHILD: i64 = 10;
/// `EISDIR`: a directory was read as a byte stream.
const EISDIR: i64 = 21;
/// `ETIMEDOUT`: a `futex` wait timed out.
const ETIMEDOUT: i64 = 110;
/// `EINVAL` (also used as the failure marker of an internal assertion).
const EINVAL: i64 = 22;
/// `ENOTSOCK`.
const ENOTSOCK: i64 = 88;
/// `EMSGSIZE`.
const EMSGSIZE: i64 = 90;
/// `EOPNOTSUPP`.
const EOPNOTSUPP: i64 = 95;
/// `ENOTCONN`.
const ENOTCONN: i64 = 107;
/// `ENOENT`.
const ENOENT: i64 = 2;
/// `EEXIST`.
const EEXIST: i64 = 17;
/// `EADDRINUSE`: an abstract UNIX name is already bound.
const EADDRINUSE: i64 = 98;
/// `ENOMEM`.
const ENOMEM: i64 = 12;
/// `EFAULT` (also proves user-copy write protection).
const EFAULT: i64 = 14;

/// `AF_UNIX`.
const AF_UNIX: u64 = 1;
/// `AF_INET`.
const AF_INET: u64 = 2;
/// `AF_INET6`.
const AF_INET6: u64 = 10;
/// `SOCK_STREAM`.
const SOCK_STREAM: u64 = 1;
/// `SOCK_DGRAM`.
const SOCK_DGRAM: u64 = 2;
/// `SOL_SOCKET`.
const SOL_SOCKET: u64 = 1;
/// `SO_REUSEADDR`.
const SO_REUSEADDR: u64 = 2;
/// `SO_ERROR`.
const SO_ERROR: u64 = 4;
/// `SHUT_WR`.
const SHUT_WR: u64 = 1;

// M9b: UNIX abstract addresses, fd-passing control messages and epoll ET.
/// `SO_PASSCRED`: ask the kernel to attach `SCM_CREDENTIALS` to datagrams.
const SO_PASSCRED: u64 = 16;
/// `SO_PEERCRED`: read the peer's `struct ucred`.
const SO_PEERCRED: u64 = 17;
/// `SCM_RIGHTS`: control message carrying file descriptors.
const SCM_RIGHTS: u32 = 1;
/// `SCM_CREDENTIALS`: control message carrying `struct ucred`.
const SCM_CREDENTIALS: u32 = 2;
/// `MSG_CTRUNC`: control data was truncated.
const MSG_CTRUNC: u32 = 0x08;
/// `MSG_CMSG_CLOEXEC`: received fds are close-on-exec.
const MSG_CMSG_CLOEXEC: u64 = 0x4000_0000;
/// `EPOLLET`: edge-triggered interest flag.
const EPOLLET: u32 = 0x8000_0000;

/// `AT_PAGESZ`: page size.
const AT_PAGESZ: u64 = 6;
/// `AT_NULL`: the auxiliary vector terminator.
const AT_NULL: u64 = 0;
/// Caelum: native handle of the initial IPC channel endpoint.
const AT_CAELUM_CHANNEL: u64 = 0xCAE1_0001;
/// Caelum: native handle of the process network namespace.
const AT_CAELUM_NETNS: u64 = 0xCAE1_0002;
/// Caelum: M8d Linux process role (0 = parent, 1 = child).
const AT_CAELUM_ROLE: u64 = 0xCAE1_0003;
/// `AT_CAELUM_ROLE` values.
const ROLE_PARENT: u64 = 0;
const ROLE_CHILD: u64 = 1;
/// M9c: a second, long-lived child that only participates in the file-lock
/// protocol (POSIX record locks are process-scoped, so the conflict and
/// blocking cases need a real second process).
const ROLE_PEER: u64 = 2;
/// Page size carried by `AT_PAGESZ`.
const PAGE_SIZE: u64 = 4096;

// M8a memory/file constants (Linux ABI values frozen with the personality).
/// `AT_FDCWD`: resolve `openat` paths against the working directory.
const AT_FDCWD: i64 = -100;
/// `PROT_READ`.
const PROT_READ: u64 = 1;
/// `PROT_WRITE`.
const PROT_WRITE: u64 = 2;
/// `PROT_NONE`.
const PROT_NONE: u64 = 0;
/// `MAP_PRIVATE`.
const MAP_PRIVATE: u64 = 0x02;
/// `MAP_ANONYMOUS`.
const MAP_ANONYMOUS: u64 = 0x20;
/// `O_RDONLY`.
const O_RDONLY: u64 = 0;
/// `O_WRONLY`.
const O_WRONLY: u64 = 1;
/// `O_RDWR`.
const O_RDWR: u64 = 2;
/// `O_CREAT`.
const O_CREAT: u64 = 0x40;
/// `O_EXCL`.
const O_EXCL: u64 = 0x80;
/// `O_TRUNC`.
const O_TRUNC: u64 = 0x200;
/// Mode used when creating the M8a file.
const O_FILE_MODE: u64 = 0o644;
/// M8a file on the writable ramfs root.
const M8A_FILE_PATH: &[u8] = b"/m8a-files.bin\0";
/// A path the files suite expects to be absent.
const M8A_MISSING_PATH: &[u8] = b"/m8a-missing.bin\0";
/// An address expected to be unmapped for the `mprotect` negative path.
const UNMAPPED_PROBE: u64 = 0x1000_0000;

// M8e extended-file constants (Linux ABI values frozen with the personality).
/// M8e file created and inspected on the writable ramfs root.
const M8E_FILE_PATH: &[u8] = b"/m8e-files.bin\0";
/// A path the M8e suite expects to be absent.
const M8E_MISSING_PATH: &[u8] = b"/m8e-missing.bin\0";
/// Relative name resolved against an explicit directory descriptor.
const M8E_RELATIVE_NAME: &[u8] = b"m8e-files.bin\0";
/// The ramfs root directory.
const M8E_ROOT_PATH: &[u8] = b"/\0";
/// `SEEK_SET` / `SEEK_CUR` / `SEEK_END`.
const SEEK_SET: u64 = 0;
const SEEK_CUR: u64 = 1;
const SEEK_END: u64 = 2;
/// `O_DIRECTORY`.
const O_DIRECTORY: u64 = 0x10000;
/// `F_DUPFD` / `F_GETFD` / `F_SETFD` / `F_DUPFD_CLOEXEC`.
const F_DUPFD: u64 = 0;
const F_GETFD: u64 = 1;
const F_SETFD: u64 = 2;
const F_DUPFD_CLOEXEC: u64 = 1030;
/// `FD_CLOEXEC`.
const FD_CLOEXEC: u64 = 1;
/// `S_IFMT` / `S_IFREG` / `S_IFDIR` / `S_IFCHR` for the `stat`/`statx` mode word.
const S_IFMT: u32 = 0o170000;
const S_IFREG: u32 = 0o100000;
const S_IFDIR: u32 = 0o040000;
const S_IFCHR: u32 = 0o020000;
/// `statx` request mask and result bits used by the suite.
const STATX_BASIC_STATS: u64 = 0x7ff;
const STATX_TYPE: u32 = 0x1;
const STATX_SIZE: u32 = 0x200;
/// An unknown `statx` flag bit that must be rejected with `EINVAL`.
const STATX_UNKNOWN_FLAG: u64 = 0x8000_0000;
/// `getdents64` record geometry: `d_type` offset 18, name at offset 19.
const DIRENT_NAME_OFFSET: usize = 19;
/// `dirent64` file type: regular file / character device / unknown (filesystems
/// may omit the type, which the listing checks accept).
const DT_REG: u8 = 8;
const DT_CHR: u8 = 2;
const DT_UNKNOWN: u8 = 0;

// M8f futex / TLS constants (Linux ABI values frozen with the personality).
/// `futex` operations used by the wait/wake closure.
const FUTEX_WAIT: u64 = 0;
const FUTEX_WAKE: u64 = 1;
/// `FUTEX_PRIVATE_FLAG`: the wait/wake operates on this process' own mapping.
const FUTEX_PRIVATE_FLAG: u64 = 128;
/// `arch_prctl` commands for the TLS (FS segment) base.
const ARCH_SET_FS: u64 = 0x1002;
const ARCH_GET_FS: u64 = 0x1003;

// M8g eventfd / poll constants (Linux ABI values).
/// `eventfd2` flags: non-blocking fd and close-on-exec.
const EFD_NONBLOCK: u64 = 0x800;
const EFD_CLOEXEC: u64 = 0x80000;
/// `poll` event bits (`struct pollfd.events` / `.revents`).
const POLLIN: u16 = 0x001;
const POLLOUT: u16 = 0x004;
/// Relative timeout of the short-timeout poll/ppoll steps (50 ms).
const M8G_TIMEOUT_MS: i64 = 50;

// M8h procfs / devfs constants (frozen with the Linux personality views).
/// Paths exercised by the procfs and devfs suites.
const M8H_PROC_PATH: &[u8] = b"/proc\0";
const M8H_PROC_SELF_PATH: &[u8] = b"/proc/self\0";
const M8H_PROC_STATUS_PATH: &[u8] = b"/proc/self/status\0";
const M8H_PROC_UPTIME_PATH: &[u8] = b"/proc/uptime\0";
const M8H_DEV_PATH: &[u8] = b"/dev\0";
const M8H_DEV_NULL_PATH: &[u8] = b"/dev/null\0";
const M8H_DEV_ZERO_PATH: &[u8] = b"/dev/zero\0";
/// Directory entries the listings must expose.
const M8H_SELF_NAME: &[u8] = b"self";
const M8H_UPTIME_NAME: &[u8] = b"uptime";
const M8H_STATUS_NAME: &[u8] = b"status";
const M8H_NULL_NAME: &[u8] = b"null";
const M8H_ZERO_NAME: &[u8] = b"zero";
/// Character device numbers: `/dev/null` is (1,3) and `/dev/zero` is (1,5).
const M8H_NULL_MAJOR: u32 = 1;
const M8H_NULL_MINOR: u32 = 3;
const M8H_ZERO_MAJOR: u32 = 1;
const M8H_ZERO_MINOR: u32 = 5;
/// `/proc/uptime` is sampled twice, this many nanoseconds apart (50 ms).
const M8H_UPTIME_GAP_NS: u64 = 50_000_000;

/// `sizeof(struct sockaddr_in)`.
const SOCKADDR_IN: u64 = 16;
/// `sizeof(struct sockaddr_in6)`.
const SOCKADDR_IN6: u64 = 28;
/// `sizeof(struct sockaddr_un)`.
const SOCKADDR_UN: u64 = 110;

const MARK_STARTUP: &[u8] = b"[CaelumLinux] M7d startup OK\n";
const MARK_UDP: &[u8] = b"[CaelumLinux] M7d udp OK\n";
const MARK_TCP: &[u8] = b"[CaelumLinux] M7d tcp OK\n";
const MARK_UNIX: &[u8] = b"[CaelumLinux] M7d unix OK\n";
const MARK_FD: &[u8] = b"[CaelumLinux] M7d fd OK\n";
const MARK_ERRORS: &[u8] = b"[CaelumLinux] M7d errors OK\n";
const MARK_DONE: &[u8] = b"[CaelumLinux] M7d OK\n";
/// M8a: memory closure passed.
const MARK_M8A_MEMORY: &[u8] = b"[CaelumLinux] M8a memory OK\n";
/// M8a: file closure passed.
const MARK_M8A_FILES: &[u8] = b"[CaelumLinux] M8a files OK\n";
/// M8b: Linux time closure passed.
const MARK_M8B_TIME: &[u8] = b"[CaelumLinux] M8b time OK\n";
/// M8b: system information closure passed.
const MARK_M8B_INFO: &[u8] = b"[CaelumLinux] M8b info OK\n";
/// M8c: Linux64 signal ABI closure passed.
const MARK_M8C_SIGNALS: &[u8] = b"[CaelumLinux] M8c signals OK\n";
/// M8d: two-process signal/kill/wait4 closure passed (printed by the parent).
const MARK_M8D_PROCESS: &[u8] = b"[CaelumLinux] M8d process OK\n";
/// M8e: extended file ABI closure passed (printed by the parent).
const MARK_M8E_FILES: &[u8] = b"[CaelumLinux] M8e files OK\n";
/// M8f: futex wait/wake closure passed (printed by the parent).
const MARK_M8F_FUTEX: &[u8] = b"[CaelumLinux] M8f futex OK\n";
/// M8f: TLS base and tid-address closure passed (printed by the parent).
const MARK_M8F_TLS: &[u8] = b"[CaelumLinux] M8f tls OK\n";
/// M8g: eventfd counter closure passed (printed by the parent).
const MARK_M8G_EVENTFD: &[u8] = b"[CaelumLinux] M8g eventfd OK\n";
/// M8g: poll / ppoll readiness closure passed (printed by the parent).
const MARK_M8G_POLL: &[u8] = b"[CaelumLinux] M8g poll OK\n";
/// M8h: procfs listing, `/proc/self/status` and `/proc/uptime` closure passed.
const MARK_M8H_PROCFS: &[u8] = b"[CaelumLinux] M8h procfs OK\n";
/// M8h: devfs listing and `/dev/null` / `/dev/zero` closure passed.
const MARK_M8H_DEVFILES: &[u8] = b"[CaelumLinux] M8h devfs OK\n";
/// M9a: timerfd relative / periodic / disarm closure passed.
const MARK_M9A_TIMERFD: &[u8] = b"[CaelumLinux] M9a timerfd OK\n";
/// M9a: signalfd wakeup / read / drain closure passed.
const MARK_M9A_SIGNALFD: &[u8] = b"[CaelumLinux] M9a signalfd OK\n";
/// M9a: epoll level-triggered readiness closure passed.
const MARK_M9A_EPOLL: &[u8] = b"[CaelumLinux] M9a epoll OK\n";
const MARK_M9B_ABSTRACT: &[u8] = b"[CaelumLinux] M9b abstract OK\n";
const MARK_M9B_RIGHTS: &[u8] = b"[CaelumLinux] M9b rights OK\n";
const MARK_M9B_CREDENTIALS: &[u8] = b"[CaelumLinux] M9b credentials OK\n";
const MARK_M9B_EPOLL_ET: &[u8] = b"[CaelumLinux] M9b epoll-et OK\n";
/// M9c: POSIX record locks (conflict, blocking, close release) and `flock`
/// domain independence passed (printed once by the parent after reaping the
/// protocol peer).
const MARK_M9C_LOCKS: &[u8] = b"[CaelumLinux] M9c locks OK\n";

/// Failure stages (the process exits with `0x70 + stage`).
const STAGE_STARTUP: u32 = 1;
const STAGE_UDP: u32 = 2;
const STAGE_TCP: u32 = 3;
const STAGE_UNIX: u32 = 4;
const STAGE_FD: u32 = 5;
const STAGE_ERRORS: u32 = 6;
/// M8a: brk / anonymous mmap / mprotect / munmap closure.
const STAGE_MEMORY: u32 = 7;
/// M8a: openat / read / write / close and dup offset closure.
const STAGE_FILES: u32 = 8;
/// M8b: clock_gettime / clock_nanosleep closure.
const STAGE_TIME: u32 = 9;
/// M8b: uname / getpid / getppid / sysinfo closure.
const STAGE_INFO: u32 = 10;
/// M8c: rt_sigaction / rt_sigprocmask / rt_sigreturn / kill / tgkill closure.
const STAGE_SIGNALS: u32 = 11;
/// M8d: two-process role handshake, cross-process signals and child reaping.
const STAGE_PROCESS: u32 = 12;
/// M8e: lseek / fstat / statx / getdents64 / fcntl closure.
const STAGE_FILES_EXTRA: u32 = 13;
/// M8f: futex wait/wake closure.
const STAGE_FUTEX: u32 = 14;
/// M8f: TLS base / tid-address closure.
const STAGE_TLS: u32 = 15;
/// M8g: eventfd counter closure.
const STAGE_EVENTFD: u32 = 16;
/// M8g: poll / ppoll readiness closure.
const STAGE_POLL: u32 = 17;
/// M8h: procfs listing / `/proc/self/status` / `/proc/uptime` closure.
const STAGE_PROCFS: u32 = 18;
/// M8h: devfs listing / `/dev/null` / `/dev/zero` closure.
const STAGE_DEVFILES: u32 = 19;
/// M9a: timerfd relative / periodic / disarm closure.
const STAGE_M9A_TIMERFD: u32 = 20;
/// M9a: signalfd wakeup / read / drain closure.
const STAGE_M9A_SIGNALFD: u32 = 21;
/// M9a: epoll level-triggered readiness closure.
const STAGE_M9A_EPOLL: u32 = 22;
const STAGE_M9B_ABSTRACT: u32 = 23;
const STAGE_M9B_RIGHTS: u32 = 24;
const STAGE_M9B_CREDENTIALS: u32 = 25;
const STAGE_M9B_EPOLL_ET: u32 = 26;
/// M9c: POSIX record locks, blocking wakeup, close release and the independent
/// `flock` domain.
const STAGE_M9C_LOCKS: u32 = 27;

// ---------------------------------------------------------------------------
// Scratch memory (no heap: one fixed writable arena in `.bss`).
// ---------------------------------------------------------------------------

const ARENA_BYTES: usize = 8192;
const OFF_ADDR_A: usize = 0; // 128 bytes: sockaddr / stored address
const OFF_ADDR_B: usize = 128; // 128 bytes: peer or reply address
const OFF_LEN_A: usize = 256; // u32 socklen_t in/out
const OFF_LEN_B: usize = 260; // u32 socklen_t in/out / option value
const OFF_RX: usize = 1328; // received bytes (<= 1024 bytes)
const OFF_TX: usize = 2384; // bytes to send / reply (<= 1024 bytes)
const OFF_FUTEX: usize = 3408; // u32 futex word for the M8f closure
const OFF_TID: usize = 3416; // u32 tid written by `set_tid_address`
const OFF_ARCH_OUT: usize = 3424; // u64 FS base in/out
const OFF_ARCH_SAVED: usize = 3432; // u64 saved FS base
const OFF_TS_ZERO: usize = 3440; // timespec: zero relative timeout
const OFF_TS_SHORT: usize = 3456; // timespec: short relative timeout
const OFF_POLLFD: usize = 3472; // 2 x struct pollfd (8 bytes each)
const OFF_EVENT_VALUE: usize = 3536; // u64 eventfd counter in/out
const OFF_POLL_TS: usize = 3552; // timespec: relative ppoll timeout
const OFF_SIGSET_BLOCK: usize = 3568; // sigset: SIGUSR1 blocked
const OFF_SIGSET_EMPTY: usize = 3576; // sigset: empty (temporary ppoll mask)
// M8h: text and directory buffers for the procfs/devfs suites.
const OFF_PROC_TEXT: usize = 3584; // 2048 bytes: /proc/self/status text
const OFF_PROC_TEXT_SIZE: usize = 2048;
const OFF_UPTIME_TEXT: usize = 5632; // 64 bytes: /proc/uptime samples
const OFF_UPTIME_TEXT_SIZE: usize = 64;
const OFF_DIR_BUF: usize = 5696; // 1024 bytes: getdents64 buffer
const OFF_DIR_BUF_SIZE: usize = 1024;
const OFF_DEV_BUF: usize = 6720; // 128 bytes: /dev/null and /dev/zero data
// M9a: timerfd, signalfd and epoll scratch space.
const OFF_TIMER_SPEC: usize = 6848; // 32 bytes: itimerspec written before settime
const OFF_TIMER_NOW: usize = 6880; // 32 bytes: itimerspec read back by gettime
const OFF_SFD_INFO: usize = 6912; // 128 bytes: signalfd_siginfo
const OFF_EPOLL_EVENTS: usize = 7040; // 16 x packed 12-byte epoll_event
const OFF_EPOLL_EVENT: usize = 7232; // 12 bytes: one packed epoll_event
const OFF_SIGSET_FD: usize = 7248; // 8 bytes: sigset for signalfd / block
const OFF_SIGSET_OLD: usize = 7256; // 8 bytes: previous mask saved for restore
const OFF_TIMER_READ: usize = 7264; // 8 bytes: timerfd expiration counter
// M9b: UNIX addresses, msghdr/iovec/control buffers and received fds.
const OFF_M9B_UN: usize = 7296; // 128 bytes: sockaddr_un (bind/connect)
const OFF_M9B_UN2: usize = 7424; // 128 bytes: sockaddr_un (source/peer)
const OFF_M9B_LEN: usize = 7552; // 4 bytes: socklen_t in/out
const OFF_M9B_MSG: usize = 7560; // 56 bytes: struct msghdr
const OFF_M9B_IOV: usize = 7616; // 16 bytes: struct iovec
const OFF_M9B_CTRL: usize = 7632; // 128 bytes: control-message buffer
const OFF_M9B_CRED: usize = 7760; // 24 bytes: struct ucred / option value
const OFF_M9B_BUF: usize = 7784; // 64 bytes: payload/pattern scratch
// M9c: POSIX record-lock requests/results (`struct flock`) and payload scratch.
const OFF_M9C_FLOCK: usize = 7808; // 32 bytes: struct flock request/result
const OFF_M9C_FLOCK2: usize = 7840; // 32 bytes: second struct flock
const OFF_M9C_BUF: usize = 7872; // 16 bytes: shared-offset payload

static mut ARENA: [u8; ARENA_BYTES] = [0; ARENA_BYTES];

// ---------------------------------------------------------------------------
// Raw Linux system calls.
// ---------------------------------------------------------------------------

/// Issue one Linux x86-64 system call: `rax` = number, arguments in
/// `rdi`/`rsi`/`rdx`/`r10`/`r8`/`r9`, result in `rax` (negative = `-errno`).
fn syscall6(nr: u64, arg1: u64, arg2: u64, arg3: u64, arg4: u64, arg5: u64, arg6: u64) -> i64 {
    let result: i64;
    unsafe {
        asm!(
            "syscall",
            inlateout("rax") nr => result,
            in("rdi") arg1,
            in("rsi") arg2,
            in("rdx") arg3,
            in("r10") arg4,
            in("r8") arg5,
            in("r9") arg6,
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack),
        );
    }
    result
}

fn socket(domain: u64, kind: u64, protocol: u64) -> i64 {
    syscall6(NR_SOCKET, domain, kind, protocol, 0, 0, 0)
}

fn bind(fd: i64, address: u64, length: u64) -> i64 {
    syscall6(NR_BIND, fd as u64, address, length, 0, 0, 0)
}

fn getsockname(fd: i64, address: u64, length_pointer: u64) -> i64 {
    syscall6(NR_GETSOCKNAME, fd as u64, address, length_pointer, 0, 0, 0)
}

fn getpeername(fd: i64, address: u64, length_pointer: u64) -> i64 {
    syscall6(NR_GETPEERNAME, fd as u64, address, length_pointer, 0, 0, 0)
}

fn listen(fd: i64, backlog: u64) -> i64 {
    syscall6(NR_LISTEN, fd as u64, backlog, 0, 0, 0, 0)
}

fn connect(fd: i64, address: u64, length: u64) -> i64 {
    syscall6(NR_CONNECT, fd as u64, address, length, 0, 0, 0)
}

fn accept(fd: i64) -> i64 {
    syscall6(NR_ACCEPT, fd as u64, 0, 0, 0, 0, 0)
}

fn sendto(fd: i64, buffer: u64, length: u64) -> i64 {
    syscall6(NR_SENDTO, fd as u64, buffer, length, 0, 0, 0)
}

fn recvfrom(fd: i64, buffer: u64, capacity: u64, source: u64, source_length: u64) -> i64 {
    syscall6(
        NR_RECVFROM,
        fd as u64,
        buffer,
        capacity,
        0,
        source,
        source_length,
    )
}

/// `sendmsg`: `message` points at a `struct msghdr` we filled in `ARENA`.
fn sendmsg(fd: i64, message: u64, flags: u64) -> i64 {
    syscall6(NR_SENDMSG, fd as u64, message, flags, 0, 0, 0)
}

/// `recvmsg`: the kernel rewrites `msg_controllen`/`msg_flags` before returning.
fn recvmsg(fd: i64, message: u64, flags: u64) -> i64 {
    syscall6(NR_RECVMSG, fd as u64, message, flags, 0, 0, 0)
}

fn read_fd(fd: i64, buffer: u64, length: u64) -> i64 {
    syscall6(NR_READ, fd as u64, buffer, length, 0, 0, 0)
}

fn write_fd(fd: i64, buffer: u64, length: u64) -> i64 {
    syscall6(NR_WRITE, fd as u64, buffer, length, 0, 0, 0)
}

fn close(fd: i64) -> i64 {
    syscall6(NR_CLOSE, fd as u64, 0, 0, 0, 0, 0)
}

fn socketpair_raw(domain: u64, kind: u64, out_pointer: u64) -> i64 {
    syscall6(NR_SOCKETPAIR, domain, kind, 0, out_pointer, 0, 0)
}

fn setsockopt(fd: i64, level: u64, name: u64, value: u64, length: u64) -> i64 {
    syscall6(NR_SETSOCKOPT, fd as u64, level, name, value, length, 0)
}

fn getsockopt(fd: i64, level: u64, name: u64, value: u64, length: u64) -> i64 {
    syscall6(NR_GETSOCKOPT, fd as u64, level, name, value, length, 0)
}

fn dup(fd: i64) -> i64 {
    syscall6(NR_DUP, fd as u64, 0, 0, 0, 0, 0)
}

fn getpid() -> i64 {
    syscall6(NR_GETPID, 0, 0, 0, 0, 0, 0)
}

fn getuid() -> i64 {
    syscall6(NR_GETUID, 0, 0, 0, 0, 0, 0)
}

fn getgid() -> i64 {
    syscall6(NR_GETGID, 0, 0, 0, 0, 0, 0)
}

/// `wait4`: `pid = -1` waits for any child, `options = WNOHANG` polls, and
/// `rusage = 0` (`NULL`) means no `struct rusage` is written.
fn wait4(pid: i64, status: &mut i32, options: u64, rusage: u64) -> i64 {
    syscall6(
        NR_WAIT4,
        pid as u64,
        status as *mut i32 as u64,
        options,
        rusage,
        0,
        0,
    )
}

/// `shutdown`: the Linux number first, then the compat table's current value.
fn shutdown(fd: i64, how: u64) -> i64 {
    let result = syscall6(NR_SHUTDOWN, fd as u64, how, 0, 0, 0, 0);
    if result == -ENOSYS {
        return syscall6(NR_SHUTDOWN_COMPAT, fd as u64, how, 0, 0, 0, 0);
    }
    result
}

/// `brk`: returns the new program break (or the old one when it fails).
fn brk(address: u64) -> i64 {
    syscall6(NR_BRK, address, 0, 0, 0, 0, 0)
}

/// Anonymous private `mmap`; the wrapper takes all Linux arguments so the
/// negative `len = 0` and non-anonymous `fd = -1` shapes stay reachable.
fn mmap(address: u64, length: u64, protection: u64, flags: u64, fd: i64, offset: u64) -> i64 {
    syscall6(
        NR_MMAP, address, length, protection, flags, fd as u64, offset,
    )
}

/// `munmap`.
fn munmap(address: u64, length: u64) -> i64 {
    syscall6(NR_MUNMAP, address, length, 0, 0, 0, 0)
}

/// `mprotect`.
fn mprotect(address: u64, length: u64, protection: u64) -> i64 {
    syscall6(NR_MPROTECT, address, length, protection, 0, 0, 0)
}

/// `openat` against an explicit directory descriptor (`AT_FDCWD` for the cwd).
fn openat_at(directory_fd: i64, path: &[u8], flags: u64, mode: u64) -> i64 {
    syscall6(
        NR_OPENAT,
        directory_fd as u64,
        path.as_ptr() as u64,
        flags,
        mode,
        0,
        0,
    )
}

/// `lseek`: `offset` is a signed byte offset and `whence` is `SEEK_*`.
fn lseek(fd: i64, offset: i64, whence: u64) -> i64 {
    syscall6(NR_LSEEK, fd as u64, offset as u64, whence, 0, 0, 0)
}

/// `fstat`: fills the frozen x86-64 `struct stat` image.
fn fstat(fd: i64, status: &mut Stat) -> i64 {
    syscall6(NR_FSTAT, fd as u64, status as *mut Stat as u64, 0, 0, 0, 0)
}

/// `fcntl`: `request` is a `F_*` command and `argument` its command-specific
/// value.
fn fcntl(fd: i64, request: u64, argument: u64) -> i64 {
    syscall6(NR_FCNTL, fd as u64, request, argument, 0, 0, 0)
}

/// `flock`: the BSD whole-file lock, a lock domain independent from POSIX
/// record locks (`fcntl`).
fn flock(fd: i64, operation: u64) -> i64 {
    syscall6(NR_FLOCK, fd as u64, operation, 0, 0, 0, 0)
}

/// Fill a frozen x86-64 `struct flock` image at `offset`: lock `kind`,
/// `l_whence = SEEK_SET`, `l_start`/`l_len` (0 = to EOF) and `l_pid`.
fn put_flock(offset: usize, kind: u16, start: i64, length: i64, pid: i32) {
    put_bytes(offset, &[0u8; FLOCK_BYTES]);
    put_u16_ne(offset, kind);
    put_u16_ne(offset + 2, FLOCK_WHENCE_SET);
    put_u64_ne(offset + 8, start as u64);
    put_u64_ne(offset + 16, length as u64);
    put_u32_le(offset + 24, pid as u32);
}

fn flock_type(offset: usize) -> u16 {
    get_u16_ne(offset)
}

fn flock_start(offset: usize) -> i64 {
    get_u64_ne(offset + 8) as i64
}

fn flock_length(offset: usize) -> i64 {
    get_u64_ne(offset + 16) as i64
}

fn flock_pid(offset: usize) -> i32 {
    get_u32_le(offset + 24) as i32
}

/// `getdents64`: fills `count` bytes of `dirent64` records at `buffer`.
fn getdents64(fd: i64, buffer: u64, count: u64) -> i64 {
    syscall6(NR_GETDENTS64, fd as u64, buffer, count, 0, 0, 0)
}

/// `statx`: extended stat. An absolute `path` ignores `directory_fd`.
fn statx(directory_fd: i64, path: &[u8], flags: u64, mask: u64, status: &mut Statx) -> i64 {
    syscall6(
        NR_STATX,
        directory_fd as u64,
        path.as_ptr() as u64,
        flags,
        mask,
        status as *mut Statx as u64,
        0,
    )
}

/// `futex`: `operation` combines a futex op with `FUTEX_PRIVATE_FLAG`.
fn futex(word: u64, operation: u64, value: u64, timeout: u64, word2: u64, value3: u64) -> i64 {
    syscall6(NR_FUTEX, word, operation, value, timeout, word2, value3)
}

/// `arch_prctl`: the `FS` segment commands set/get the TLS base.
fn arch_prctl(code: u64, address: u64) -> i64 {
    syscall6(NR_ARCH_PRCTL, code, address, 0, 0, 0, 0)
}

/// `set_tid_address`: returns the calling tid and records it at `address`.
fn set_tid_address(address: u64) -> i64 {
    syscall6(NR_SET_TID_ADDRESS, address, 0, 0, 0, 0, 0)
}

/// `eventfd2`: create an eventfd counter (single `u64`, 8-byte read/write).
fn eventfd2(initial: u64, flags: u64) -> i64 {
    syscall6(NR_EVENTFD2, initial, flags, 0, 0, 0, 0)
}

/// `poll`: wait for readiness on `count` entries of the `pollfd` array at `fds`.
/// A negative timeout blocks until readiness or a signal.
fn poll(fds: u64, count: u64, timeout_ms: i64) -> i64 {
    syscall6(NR_POLL, fds, count, timeout_ms as u64, 0, 0, 0)
}

/// `ppoll`: like [`poll`] with a relative `timespec`; a NULL timeout means
/// infinite. A non-NULL `signal_mask` applies a temporary mask for the wait;
/// its sigset size is validated as 8 bytes (0 only when the mask is NULL).
fn ppoll(fds: u64, count: u64, timeout: u64, signal_mask: u64) -> i64 {
    let signal_mask_bytes = if signal_mask == 0 { 0 } else { SIGSET_BYTES };
    syscall6(
        NR_PPOLL,
        fds,
        count,
        timeout,
        signal_mask,
        signal_mask_bytes,
        0,
    )
}

/// M9a: `timerfd_create` (monotonic clock, non-blocking timer).
fn timerfd_create(clock: u64, flags: u64) -> i64 {
    syscall6(NR_TIMERFD_CREATE, clock, flags, 0, 0, 0, 0)
}

/// M9a: `timerfd_settime`; `new_value` points at an `itimerspec` (32 bytes).
fn timerfd_settime(fd: i64, flags: u64, new_value: u64, old_value: u64) -> i64 {
    syscall6(
        NR_TIMERFD_SETTIME,
        fd as u64,
        flags,
        new_value,
        old_value,
        0,
        0,
    )
}

/// M9a: `timerfd_gettime`; `current_value` points at an `itimerspec` (32 bytes).
fn timerfd_gettime(fd: i64, current_value: u64) -> i64 {
    syscall6(NR_TIMERFD_GETTIME, fd as u64, current_value, 0, 0, 0, 0)
}

/// M9a: `signalfd4`; `fd = -1` creates a new descriptor, `mask` points at a
/// sigset of `mask_bytes` (8) bytes and `flags` may carry `SFD_NONBLOCK`.
fn signalfd4(fd: i64, mask: u64, mask_bytes: u64, flags: u64) -> i64 {
    syscall6(NR_SIGNALFD4, fd as u64, mask, mask_bytes, flags, 0, 0)
}

/// M9a: `epoll_create1`.
fn epoll_create1(flags: u64) -> i64 {
    syscall6(NR_EPOLL_CREATE1, flags, 0, 0, 0, 0, 0)
}

/// M9a: `epoll_ctl`; `event` points at one packed 12-byte `epoll_event`.
fn epoll_ctl(epfd: i64, operation: u64, fd: i64, event: u64) -> i64 {
    syscall6(NR_EPOLL_CTL, epfd as u64, operation, fd as u64, event, 0, 0)
}

/// M9a: `epoll_wait`; a negative `timeout_ms` blocks indefinitely.
fn epoll_wait(epfd: i64, events: u64, max_events: u64, timeout_ms: i64) -> i64 {
    syscall6(
        NR_EPOLL_WAIT,
        epfd as u64,
        events,
        max_events,
        timeout_ms as u64,
        0,
        0,
    )
}

/// M9a: `epoll_pwait`; a NULL `mask` passes sigsetsize 0, otherwise 8.
fn epoll_pwait(
    epfd: i64,
    events: u64,
    max_events: u64,
    timeout_ms: i64,
    mask: u64,
    mask_bytes: u64,
) -> i64 {
    let mask_bytes = if mask == 0 { 0 } else { mask_bytes };
    syscall6(
        NR_EPOLL_PWAIT,
        epfd as u64,
        events,
        max_events,
        timeout_ms as u64,
        mask,
        mask_bytes,
    )
}

fn exit_group(status: i64) -> ! {
    syscall6(NR_EXIT_GROUP, status as u64, 0, 0, 0, 0, 0);
    loop {
        core::hint::spin_loop();
    }
}

// ---------------------------------------------------------------------------
// Console output and failure reporting.
// ---------------------------------------------------------------------------

fn write_raw(bytes: &[u8]) {
    let mut offset = 0usize;
    while offset < bytes.len() {
        let result = write_fd(
            1,
            bytes[offset..].as_ptr() as u64,
            (bytes.len() - offset) as u64,
        );
        if result <= 0 {
            exit_group(0x7e);
        }
        offset += result as usize;
    }
}

fn push_bytes(line: &mut [u8; 96], length: &mut usize, bytes: &[u8]) {
    for byte in bytes {
        if *length < line.len() {
            line[*length] = *byte;
            *length += 1;
        }
    }
}

fn push_decimal(line: &mut [u8; 96], length: &mut usize, value: i64) {
    let mut digits = [0u8; 20];
    let mut count = 0usize;
    let negative = value < 0;
    let mut remaining = if negative {
        value.wrapping_neg() as u64
    } else {
        value as u64
    };
    loop {
        digits[count] = b'0' + (remaining % 10) as u8;
        count += 1;
        remaining /= 10;
        if remaining == 0 {
            break;
        }
    }
    if negative {
        push_bytes(line, length, b"-");
    }
    while count > 0 {
        count -= 1;
        push_bytes(line, length, &[digits[count]]);
    }
}

/// Print a failure diagnostic that never contains `OK`, then exit non-zero.
fn fail(stage: u32, step: u32, rc: i64) -> ! {
    let mut line = [0u8; 96];
    let mut length = 0usize;
    push_bytes(&mut line, &mut length, b"[CaelumLinux] FAIL stage=");
    push_decimal(&mut line, &mut length, i64::from(stage));
    push_bytes(&mut line, &mut length, b" step=");
    push_decimal(&mut line, &mut length, i64::from(step));
    push_bytes(&mut line, &mut length, b" rc=");
    push_decimal(&mut line, &mut length, rc);
    push_bytes(&mut line, &mut length, b"\n");
    write_raw(&line[..length]);
    exit_group(0x70 + i64::from(stage))
}

// ---------------------------------------------------------------------------
// Arena helpers.
// ---------------------------------------------------------------------------

fn arena(offset: usize) -> *mut u8 {
    unsafe { addr_of_mut!(ARENA).cast::<u8>().add(offset) }
}

fn put_bytes(offset: usize, bytes: &[u8]) {
    let pointer = arena(offset);
    unsafe {
        for (index, byte) in bytes.iter().enumerate() {
            pointer.add(index).write(*byte);
        }
    }
}

fn put_u8(offset: usize, value: u8) {
    unsafe {
        arena(offset).write(value);
    }
}

fn get_u8(offset: usize) -> u8 {
    unsafe { arena(offset).read() }
}

fn put_u16_ne(offset: usize, value: u16) {
    put_bytes(offset, &value.to_ne_bytes());
}

fn get_u16_ne(offset: usize) -> u16 {
    let bytes = [get_u8(offset), get_u8(offset + 1)];
    u16::from_ne_bytes(bytes)
}

fn get_u16_be(offset: usize) -> u16 {
    let bytes = [get_u8(offset), get_u8(offset + 1)];
    u16::from_be_bytes(bytes)
}

fn put_u32_le(offset: usize, value: u32) {
    put_bytes(offset, &value.to_le_bytes());
}

fn get_u32_le(offset: usize) -> u32 {
    let bytes = [
        get_u8(offset),
        get_u8(offset + 1),
        get_u8(offset + 2),
        get_u8(offset + 3),
    ];
    u32::from_le_bytes(bytes)
}

fn put_u64_ne(offset: usize, value: u64) {
    put_bytes(offset, &value.to_ne_bytes());
}

fn get_u64_ne(offset: usize) -> u64 {
    let mut bytes = [0u8; 8];
    for (index, byte) in bytes.iter_mut().enumerate() {
        *byte = get_u8(offset + index);
    }
    u64::from_ne_bytes(bytes)
}

fn pattern_byte(index: usize, seed: u8) -> u8 {
    ((index * 37 + usize::from(seed)) & 0xff) as u8
}

fn fill_pattern(offset: usize, length: usize, seed: u8) {
    for index in 0..length {
        put_u8(offset + index, pattern_byte(index, seed));
    }
}

fn check_pattern(offset: usize, length: usize, seed: u8) -> bool {
    (0..length).all(|index| get_u8(offset + index) == pattern_byte(index, seed))
}

/// True when the arena bytes at `offset` equal `expected`.
fn arena_eq(offset: usize, expected: &[u8]) -> bool {
    expected
        .iter()
        .enumerate()
        .all(|(index, byte)| get_u8(offset + index) == *byte)
}

// ---------------------------------------------------------------------------
// Address helpers (Linux sockaddr layouts, native syscall layer).
// ---------------------------------------------------------------------------

fn put_sockaddr_in(port: u16, address: [u8; 4]) -> (u64, u64) {
    put_bytes(OFF_ADDR_A, &[0u8; SOCKADDR_IN as usize]);
    put_u16_ne(OFF_ADDR_A, AF_INET as u16);
    put_bytes(OFF_ADDR_A + 2, &port.to_be_bytes());
    put_bytes(OFF_ADDR_A + 4, &address);
    (arena(OFF_ADDR_A) as u64, SOCKADDR_IN)
}

fn put_sockaddr_in6(port: u16) -> (u64, u64) {
    put_bytes(OFF_ADDR_A, &[0u8; SOCKADDR_IN6 as usize]);
    put_u16_ne(OFF_ADDR_A, AF_INET6 as u16);
    put_bytes(OFF_ADDR_A + 2, &port.to_be_bytes());
    // sin6_flowinfo stays zero; sin6_addr = ::1; sin6_scope_id stays zero.
    put_u8(OFF_ADDR_A + 8 + 15, 1);
    (arena(OFF_ADDR_A) as u64, SOCKADDR_IN6)
}

fn put_sockaddr_un(offset: usize, path: &[u8]) -> (u64, u64) {
    put_bytes(offset, &[0u8; SOCKADDR_UN as usize]);
    put_u16_ne(offset, AF_UNIX as u16);
    put_bytes(offset + 2, path);
    (arena(offset) as u64, 2 + path.len() as u64 + 1)
}

/// Loopback address of the given family, bound to `port`.
fn put_loopback(port: u16, family: u64) -> (u64, u64) {
    if family == AF_INET6 {
        put_sockaddr_in6(port)
    } else {
        put_sockaddr_in(port, [127, 0, 0, 1])
    }
}

/// `getsockname`/`getpeername` into `OFF_ADDR_A`; returns `(family, port)`.
fn read_socket_name(
    stage: u32,
    step: u32,
    function: fn(i64, u64, u64) -> i64,
    fd: i64,
    capacity: u64,
) -> (u16, u16) {
    put_u32_le(OFF_LEN_A, capacity as u32);
    let result = function(fd, arena(OFF_ADDR_A) as u64, arena(OFF_LEN_A) as u64);
    if result < 0 {
        fail(stage, step, result);
    }
    (get_u16_ne(OFF_ADDR_A), get_u16_be(OFF_ADDR_A + 2))
}

fn local_family_and_port(stage: u32, step: u32, fd: i64, capacity: u64) -> (u16, u16) {
    read_socket_name(stage, step, getsockname, fd, capacity)
}

fn peer_family_and_port(stage: u32, step: u32, fd: i64, capacity: u64) -> (u16, u16) {
    read_socket_name(stage, step, getpeername, fd, capacity)
}

fn check(stage: u32, step: u32, condition: bool) {
    if !condition {
        fail(stage, step, -EINVAL);
    }
}

fn expect_ok(stage: u32, step: u32, result: i64) -> i64 {
    if result < 0 {
        fail(stage, step, result);
    }
    result
}

fn expect_value(stage: u32, step: u32, result: i64, expected: i64) {
    if result != expected {
        fail(stage, step, result);
    }
}

fn expect_errno(stage: u32, step: u32, result: i64, errno: i64) {
    if result != -errno {
        fail(stage, step, result);
    }
}

fn check_loopback_address(stage: u32, step: u32, family: u64) {
    if family == AF_INET6 {
        let mut ok = get_u16_ne(OFF_ADDR_A) == AF_INET6 as u16;
        for index in 0..15 {
            ok = ok && get_u8(OFF_ADDR_A + 8 + index) == 0;
        }
        ok = ok && get_u8(OFF_ADDR_A + 8 + 15) == 1;
        check(stage, step, ok);
    } else {
        let mut ok = get_u16_ne(OFF_ADDR_A) == AF_INET as u16;
        for (index, expected) in [127u8, 0, 0, 1].iter().enumerate() {
            ok = ok && get_u8(OFF_ADDR_A + 4 + index) == *expected;
        }
        check(stage, step, ok);
    }
}

/// Round `value` up to the next multiple of `alignment`.
fn align_up(value: u64, alignment: u64) -> u64 {
    let remainder = value % alignment;
    if remainder == 0 {
        value
    } else {
        value + (alignment - remainder)
    }
}

/// Volatile byte read, so a protection/`munmap` test really touches memory.
fn read_byte(address: u64) -> u8 {
    unsafe { (address as *const u8).read_volatile() }
}

/// Volatile byte write (see [`read_byte`]).
fn write_byte(address: u64, value: u8) {
    unsafe {
        (address as *mut u8).write_volatile(value);
    }
}

/// Fill one page with the standard byte pattern starting at index 0.
fn fill_page(address: u64, seed: u8) {
    let mut index = 0usize;
    while index < PAGE_SIZE as usize {
        write_byte(address + index as u64, pattern_byte(index, seed));
        index += 1;
    }
}

/// Verify one page against the standard byte pattern.
fn check_page(address: u64, seed: u8) -> bool {
    let mut index = 0usize;
    while index < PAGE_SIZE as usize {
        if read_byte(address + index as u64) != pattern_byte(index, seed) {
            return false;
        }
        index += 1;
    }
    true
}

// ---------------------------------------------------------------------------
// Startup: the System V initial stack image and the Caelum auxv entries.
// ---------------------------------------------------------------------------

fn auxv_word(stack: *const u64, index: usize) -> u64 {
    unsafe { stack.add(index).read() }
}

/// System V initial-stack image pointer (was `rsp` at the ELF entry) → the
/// Linux personality test body. The register is only used for the stack, never
/// as a native initial handle.
extern "C" fn linux_entry(initial_rsp: usize) -> ! {
    let stack = initial_rsp as *mut u64;
    let argc = auxv_word(stack, 0);
    let argv0 = auxv_word(stack, 1);
    let envp0 = auxv_word(stack, 2);

    let mut pagesz = 0u64;
    let mut channel = 0u64;
    let mut netns = 0u64;
    let mut role = ROLE_PARENT;
    let mut saw_terminator = false;
    let mut index = 3usize;
    while index < 3 + 64 {
        let kind = auxv_word(stack, index);
        let value = auxv_word(stack, index + 1);
        if kind == AT_NULL {
            saw_terminator = true;
            break;
        }
        match kind {
            AT_PAGESZ => pagesz = value,
            AT_CAELUM_CHANNEL => channel = value,
            AT_CAELUM_NETNS => netns = value,
            AT_CAELUM_ROLE => role = value,
            _ => {}
        }
        index += 2;
    }

    // M8d role 1 is the second Linux process: it runs only the two-process
    // handshake and never prints the single-process markers.
    if role == ROLE_CHILD {
        m8d_child_main()
    }

    // M9c role 2 is the long-lived lock-protocol peer: it runs only the file
    // lock handshake and never prints a marker.
    if role == ROLE_PEER {
        m9c_peer_main()
    }

    check(STAGE_STARTUP, 1, argc == 0);
    check(STAGE_STARTUP, 2, argv0 == 0);
    check(STAGE_STARTUP, 3, envp0 == 0);
    check(STAGE_STARTUP, 4, saw_terminator);
    check(STAGE_STARTUP, 5, pagesz == PAGE_SIZE);
    check(STAGE_STARTUP, 6, channel != 0);
    check(STAGE_STARTUP, 7, netns != 0);
    check(STAGE_STARTUP, 8, getpid() >= 0);
    check(STAGE_STARTUP, 9, getuid() == 0);

    write_raw(MARK_STARTUP);

    suite_udp();
    write_raw(MARK_UDP);

    suite_tcp();
    write_raw(MARK_TCP);

    suite_unix();
    write_raw(MARK_UNIX);

    suite_fd();
    write_raw(MARK_FD);

    suite_errors();
    write_raw(MARK_ERRORS);

    write_raw(MARK_DONE);

    suite_memory();
    write_raw(MARK_M8A_MEMORY);

    suite_files();
    write_raw(MARK_M8A_FILES);

    suite_time();
    write_raw(MARK_M8B_TIME);

    suite_info();
    write_raw(MARK_M8B_INFO);

    suite_signals(initial_rsp);
    write_raw(MARK_M8C_SIGNALS);

    suite_process();
    write_raw(MARK_M8D_PROCESS);

    suite_m8e_files();
    write_raw(MARK_M8E_FILES);

    suite_m8f_futex();
    write_raw(MARK_M8F_FUTEX);

    suite_m8f_tls();
    write_raw(MARK_M8F_TLS);

    suite_m8g_eventfd();
    write_raw(MARK_M8G_EVENTFD);

    suite_m8g_poll();
    write_raw(MARK_M8G_POLL);

    suite_m8h_procfs();
    write_raw(MARK_M8H_PROCFS);

    suite_m8h_devfs();
    write_raw(MARK_M8H_DEVFILES);

    suite_m9a_timerfd();
    write_raw(MARK_M9A_TIMERFD);

    suite_m9a_signalfd();
    write_raw(MARK_M9A_SIGNALFD);

    suite_m9a_epoll();
    write_raw(MARK_M9A_EPOLL);

    suite_m9b_abstract();
    write_raw(MARK_M9B_ABSTRACT);

    suite_m9b_rights();
    write_raw(MARK_M9B_RIGHTS);

    suite_m9b_credentials();
    write_raw(MARK_M9B_CREDENTIALS);

    suite_m9b_epoll_et();
    write_raw(MARK_M9B_EPOLL_ET);

    // M9c prints its own marker after the protocol peer has been reaped.
    suite_m9c_locks();

    exit_group(0)
}

// ---------------------------------------------------------------------------
// UDP over IPv4 and IPv6.
// ---------------------------------------------------------------------------

fn suite_udp() {
    udp_family(1, AF_INET, 0x11, 0x12);
    udp_family(2, AF_INET6, 0x13, 0x14);
}

fn udp_family(family_step: u32, family: u64, seed_up: u8, seed_down: u8) {
    let stage = STAGE_UDP;
    let step = |offset: u32| family_step * 100 + offset;

    let server = expect_ok(stage, step(1), socket(family, SOCK_DGRAM, 0));
    let (address, length) = put_loopback(0, family);
    expect_ok(stage, step(2), bind(server, address, length));
    let (bound_family, port) = local_family_and_port(stage, step(3), server, length);
    check(stage, step(4), bound_family == family as u16);
    check(stage, step(5), port != 0);
    check_loopback_address(stage, step(6), family);

    let client = expect_ok(stage, step(7), socket(family, SOCK_DGRAM, 0));
    let (remote, remote_length) = put_loopback(port, family);
    expect_ok(stage, step(8), connect(client, remote, remote_length));
    let (client_family, client_port) = local_family_and_port(stage, step(9), client, remote_length);
    check(stage, step(10), client_family == family as u16);
    check(stage, step(11), client_port != 0);

    fill_pattern(OFF_TX, 7, seed_up);
    expect_value(stage, step(12), sendto(client, arena(OFF_TX) as u64, 7), 7);

    put_u32_le(OFF_LEN_A, remote_length as u32);
    expect_value(
        stage,
        step(13),
        recvfrom(
            server,
            arena(OFF_RX) as u64,
            7,
            arena(OFF_ADDR_B) as u64,
            arena(OFF_LEN_A) as u64,
        ),
        7,
    );
    check(stage, step(14), check_pattern(OFF_RX, 7, seed_up));
    check(stage, step(15), get_u16_ne(OFF_ADDR_B) == family as u16);
    check(stage, step(16), get_u16_be(OFF_ADDR_B + 2) == client_port);

    // Reply on the connected server socket towards the recorded source address.
    expect_ok(
        stage,
        step(17),
        connect(server, arena(OFF_ADDR_B) as u64, remote_length),
    );
    fill_pattern(OFF_TX, 7, seed_down);
    expect_value(stage, step(18), sendto(server, arena(OFF_TX) as u64, 7), 7);
    expect_value(
        stage,
        step(19),
        recvfrom(client, arena(OFF_RX) as u64, 7, 0, 0),
        7,
    );
    check(stage, step(20), check_pattern(OFF_RX, 7, seed_down));

    expect_ok(stage, step(21), close(client));
    expect_ok(stage, step(22), close(server));
}

// ---------------------------------------------------------------------------
// TCP over IPv4 and IPv6.
// ---------------------------------------------------------------------------

fn suite_tcp() {
    tcp_family(1, AF_INET, 0x21, 0x22);
    tcp_family(2, AF_INET6, 0x23, 0x24);
}

fn tcp_family(family_step: u32, family: u64, seed_up: u8, seed_down: u8) {
    let stage = STAGE_TCP;
    let step = |offset: u32| family_step * 100 + offset;

    let listener = expect_ok(stage, step(1), socket(family, SOCK_STREAM, 0));
    put_u32_le(OFF_LEN_B, 1);
    expect_ok(
        stage,
        step(2),
        setsockopt(
            listener,
            SOL_SOCKET,
            SO_REUSEADDR,
            arena(OFF_LEN_B) as u64,
            4,
        ),
    );
    let (address, length) = put_loopback(0, family);
    expect_ok(stage, step(3), bind(listener, address, length));
    let (bound_family, port) = local_family_and_port(stage, step(4), listener, length);
    check(stage, step(5), bound_family == family as u16 && port != 0);
    check_loopback_address(stage, step(6), family);
    expect_ok(stage, step(7), listen(listener, 2));

    let client = expect_ok(stage, step(8), socket(family, SOCK_STREAM, 0));
    // SO_ERROR is clear on a fresh socket.
    put_u32_le(OFF_LEN_B, 0);
    let option_length = OFF_LEN_A;
    put_u32_le(option_length, 4);
    expect_ok(
        stage,
        step(9),
        getsockopt(
            client,
            SOL_SOCKET,
            SO_ERROR,
            arena(OFF_LEN_B) as u64,
            arena(option_length) as u64,
        ),
    );
    check(stage, step(10), get_u32_le(OFF_LEN_B) == 0);

    let (remote, remote_length) = put_loopback(port, family);
    let accepted = tcp_handshake(stage, step(11), listener, client, remote, remote_length);

    // The client's peer must be the listener address, and vice versa.
    let (peer_family, peer_port) = peer_family_and_port(stage, step(12), client, remote_length);
    check(
        stage,
        step(13),
        peer_family == family as u16 && peer_port == port,
    );
    let (accepted_family, _) = local_family_and_port(stage, step(14), accepted, remote_length);
    check(stage, step(15), accepted_family == family as u16);

    fill_pattern(OFF_TX, 14, seed_up);
    expect_value(
        stage,
        step(16),
        sendto(client, arena(OFF_TX) as u64, 14),
        14,
    );
    expect_value(
        stage,
        step(17),
        recvfrom(accepted, arena(OFF_RX) as u64, 14, 0, 0),
        14,
    );
    check(stage, step(18), check_pattern(OFF_RX, 14, seed_up));

    fill_pattern(OFF_TX, 14, seed_down);
    expect_value(
        stage,
        step(19),
        sendto(accepted, arena(OFF_TX) as u64, 14),
        14,
    );
    expect_value(
        stage,
        step(20),
        recvfrom(client, arena(OFF_RX) as u64, 14, 0, 0),
        14,
    );
    check(stage, step(21), check_pattern(OFF_RX, 14, seed_down));

    // Half-close: the peer observes EOF (0), and the closed direction refuses
    // to send.
    expect_ok(stage, step(22), shutdown(client, SHUT_WR));
    expect_value(
        stage,
        step(23),
        recvfrom(accepted, arena(OFF_RX) as u64, 8, 0, 0),
        0,
    );
    expect_errno(
        stage,
        step(24),
        sendto(client, arena(OFF_TX) as u64, 4),
        ENOTCONN,
    );
    expect_ok(stage, step(25), close(client));
    expect_value(
        stage,
        step(26),
        recvfrom(accepted, arena(OFF_RX) as u64, 8, 0, 0),
        0,
    );
    expect_ok(stage, step(27), close(accepted));
    expect_ok(stage, step(28), close(listener));
}

/// Establish one TCP connection entirely inside this process.
///
/// The Linux personality may report `EAGAIN` for an in-progress `connect` (the
/// compat layer maps `WouldBlock` to `EAGAIN` rather than sleeping). The loop
/// therefore alternates `connect` attempts with a blocking `accept`: the
/// blocking call lets the engine run the loopback handshake, so this remains
/// deterministic without wall-clock timeouts.
fn tcp_handshake(
    stage: u32,
    step: u32,
    listener: i64,
    client: i64,
    remote: u64,
    remote_length: u64,
) -> i64 {
    let mut connected = false;
    let mut rounds = 0u32;
    loop {
        if !connected {
            let result = connect(client, remote, remote_length);
            if result == 0 {
                connected = true;
            } else if result != -EAGAIN {
                fail(stage, step, result);
            }
        }
        let accepted = accept(listener);
        if accepted >= 0 {
            if connected {
                return accepted;
            }
            // The listener accepted while the client side is still finishing;
            // retry the connect until it reports success (bounded, no sleeps).
            let mut attempts = 0u32;
            loop {
                let result = connect(client, remote, remote_length);
                if result == 0 {
                    return accepted;
                }
                if result == -EAGAIN && attempts < 256 {
                    attempts += 1;
                    continue;
                }
                // Some engines report an already-established socket as an
                // error; let the following send confirm the state.
                return accepted;
            }
        }
        if accepted == -EAGAIN && rounds < 4096 {
            rounds += 1;
            continue;
        }
        fail(stage, step, accepted);
    }
}

// ---------------------------------------------------------------------------
// UNIX sockets: stream/datagram socketpair and a named datagram socket.
// ---------------------------------------------------------------------------

fn socket_pair(stage: u32, step: u32, family: u64, kind: u64) -> (i64, i64) {
    let result = socketpair_raw(family, kind, arena(OFF_LEN_A) as u64);
    if result < 0 {
        fail(stage, step, result);
    }
    let first = get_u32_le(OFF_LEN_A) as i64;
    let second = get_u32_le(OFF_LEN_A + 4) as i64;
    check(
        stage,
        step + 1,
        first >= 0 && second >= 0 && first != second,
    );
    (first, second)
}

fn suite_unix() {
    let stage = STAGE_UNIX;

    // Stream socketpair: 512 bytes one way.
    let (first, second) = socket_pair(stage, 1, AF_UNIX, SOCK_STREAM);
    fill_pattern(OFF_TX, 512, 0x31);
    expect_value(stage, 3, write_fd(first, arena(OFF_TX) as u64, 512), 512);
    expect_value(stage, 4, read_fd(second, arena(OFF_RX) as u64, 512), 512);
    check(stage, 5, check_pattern(OFF_RX, 512, 0x31));
    expect_ok(stage, 6, close(first));
    expect_ok(stage, 7, close(second));

    // Datagram socketpair: one message boundary of 512 bytes each way.
    let (first, second) = socket_pair(stage, 8, AF_UNIX, SOCK_DGRAM);
    fill_pattern(OFF_TX, 512, 0x32);
    expect_value(stage, 10, write_fd(first, arena(OFF_TX) as u64, 512), 512);
    expect_value(
        stage,
        11,
        recvfrom(second, arena(OFF_RX) as u64, 512, 0, 0),
        512,
    );
    check(stage, 12, check_pattern(OFF_RX, 512, 0x32));
    fill_pattern(OFF_TX, 128, 0x33);
    expect_value(stage, 13, write_fd(second, arena(OFF_TX) as u64, 128), 128);
    expect_value(
        stage,
        14,
        recvfrom(first, arena(OFF_RX) as u64, 512, 0, 0),
        128,
    );
    check(stage, 15, check_pattern(OFF_RX, 128, 0x33));
    expect_ok(stage, 16, close(first));
    expect_ok(stage, 17, close(second));

    // Named datagram socket inside the process network namespace.
    let path = b"/linux-m7d-dgram";
    let server = expect_ok(stage, 18, socket(AF_UNIX, SOCK_DGRAM, 0));
    let (address, length) = put_sockaddr_un(OFF_ADDR_A, path);
    expect_ok(stage, 19, bind(server, address, length));
    let client = expect_ok(stage, 20, socket(AF_UNIX, SOCK_DGRAM, 0));
    let (remote, remote_length) = put_sockaddr_un(OFF_ADDR_B, path);
    expect_ok(stage, 21, connect(client, remote, remote_length));
    fill_pattern(OFF_TX, 512, 0x41);
    expect_value(stage, 22, write_fd(client, arena(OFF_TX) as u64, 512), 512);
    expect_value(
        stage,
        23,
        recvfrom(server, arena(OFF_RX) as u64, 512, 0, 0),
        512,
    );
    check(stage, 24, check_pattern(OFF_RX, 512, 0x41));
    expect_ok(stage, 25, close(client));
    expect_ok(stage, 26, close(server));
}

// ---------------------------------------------------------------------------
// Descriptors: lowest-free allocation, dup sharing and close reference rules.
// ---------------------------------------------------------------------------

fn suite_fd() {
    let stage = STAGE_FD;

    // 0/1/2 are the console, so the first two sockets land on 3 and 4.
    let (first, second) = socket_pair(stage, 1, AF_UNIX, SOCK_STREAM);
    check(stage, 3, first == 3 && second == 4);

    // dup() takes the next lowest free descriptor and refers to the same
    // socket object.
    let duplicate = dup(first);
    if duplicate < 0 {
        fail(stage, 4, duplicate);
    }
    check(stage, 5, duplicate == 5);
    fill_pattern(OFF_TX, 3, 0x61);
    expect_value(stage, 6, write_fd(second, arena(OFF_TX) as u64, 3), 3);
    expect_value(stage, 7, read_fd(duplicate, arena(OFF_RX) as u64, 3), 3);
    check(stage, 8, check_pattern(OFF_RX, 3, 0x61));

    // Closing the original descriptor must not destroy the shared object: the
    // duplicate keeps working.
    expect_ok(stage, 9, close(first));
    fill_pattern(OFF_TX, 3, 0x62);
    expect_value(stage, 10, write_fd(second, arena(OFF_TX) as u64, 3), 3);
    expect_value(stage, 11, read_fd(duplicate, arena(OFF_RX) as u64, 3), 3);
    check(stage, 12, check_pattern(OFF_RX, 3, 0x62));

    // Closing the peer yields end-of-stream on the remaining descriptor.
    expect_ok(stage, 13, close(second));
    expect_value(stage, 14, read_fd(duplicate, arena(OFF_RX) as u64, 3), 0);
    expect_ok(stage, 15, close(duplicate));

    // Lowest-free allocation is reused after a close: (3, 4) again, then 3 is
    // handed back to the next socket after closing it.
    let (again_first, again_second) = socket_pair(stage, 16, AF_UNIX, SOCK_DGRAM);
    check(stage, 18, again_first == 3 && again_second == 4);
    expect_ok(stage, 19, close(again_first));
    let reused = expect_ok(stage, 20, socket(AF_INET, SOCK_DGRAM, 0));
    check(stage, 21, reused == 3);
    expect_ok(stage, 22, close(reused));
    expect_ok(stage, 23, close(again_second));
}

// ---------------------------------------------------------------------------
// Negative paths.
// ---------------------------------------------------------------------------

fn suite_errors() {
    let stage = STAGE_ERRORS;

    // Unknown system call: -ENOSYS, counted by the personality.
    expect_errno(stage, 1, syscall6(999, 0, 0, 0, 0, 0, 0), ENOSYS);

    // Bad descriptors.
    expect_errno(stage, 2, close(999), EBADF);
    expect_errno(
        stage,
        3,
        recvfrom(999, arena(OFF_RX) as u64, 8, 0, 0),
        EBADF,
    );

    // The console descriptor is a real descriptor but not a socket.
    put_u32_le(OFF_LEN_A, SOCKADDR_IN as u32);
    expect_errno(
        stage,
        4,
        getsockname(1, arena(OFF_ADDR_A) as u64, arena(OFF_LEN_A) as u64),
        ENOTSOCK,
    );
    expect_errno(
        stage,
        5,
        bind(0, arena(OFF_ADDR_A) as u64, SOCKADDR_IN),
        ENOTSOCK,
    );

    // A datagram that does not fit is EMSGSIZE and is not consumed; the retry
    // with a full-size buffer then returns the same message.
    let server = expect_ok(stage, 6, socket(AF_INET, SOCK_DGRAM, 0));
    let (address, length) = put_loopback(0, AF_INET);
    expect_ok(stage, 7, bind(server, address, length));
    let (_, port) = local_family_and_port(stage, 8, server, SOCKADDR_IN);
    check(stage, 9, port != 0);
    let client = expect_ok(stage, 10, socket(AF_INET, SOCK_DGRAM, 0));
    let (remote, remote_length) = put_loopback(port, AF_INET);
    expect_ok(stage, 11, connect(client, remote, remote_length));
    fill_pattern(OFF_TX, 16, 0x51);
    expect_value(stage, 12, sendto(client, arena(OFF_TX) as u64, 16), 16);
    expect_errno(
        stage,
        13,
        recvfrom(server, arena(OFF_RX) as u64, 8, 0, 0),
        EMSGSIZE,
    );
    expect_value(
        stage,
        14,
        recvfrom(server, arena(OFF_RX) as u64, 16, 0, 0),
        16,
    );
    check(stage, 15, check_pattern(OFF_RX, 16, 0x51));
    expect_ok(stage, 16, close(client));
    expect_ok(stage, 17, close(server));

    // Unsupported socket option and unsupported sendto address are reported
    // honestly instead of silently succeeding.
    let socket_fd = expect_ok(stage, 18, socket(AF_INET, SOCK_DGRAM, 0));
    put_u32_le(OFF_LEN_B, 1);
    expect_errno(
        stage,
        19,
        setsockopt(socket_fd, SOL_SOCKET, SO_ERROR, arena(OFF_LEN_B) as u64, 4),
        EOPNOTSUPP,
    );
    expect_ok(stage, 20, close(socket_fd));
}

// ---------------------------------------------------------------------------
// M8a memory closure: brk, anonymous mmap, mprotect and munmap.
// ---------------------------------------------------------------------------

fn suite_memory() {
    let stage = STAGE_MEMORY;

    // 1-2: read the initial break, then grow it by one page past the current
    // end.
    let initial = expect_ok(stage, 1, brk(0));
    if initial <= 0 {
        fail(stage, 1, initial);
    }
    let page_start = align_up(initial as u64, PAGE_SIZE);
    let grown = page_start + PAGE_SIZE;
    let after_grow = brk(grown);
    if after_grow < grown as i64 {
        fail(stage, 2, after_grow);
    }

    // 3: the new break region is writable and keeps a byte pattern.
    fill_page(page_start, 0xE1);
    check(stage, 3, check_page(page_start, 0xE1));

    // 4-5: brk(0) reports the grown break; shrinking restores the initial one.
    expect_value(stage, 4, brk(0), after_grow);
    expect_value(stage, 5, brk(initial as u64), initial);

    // 6: grow again. Pages freed by the shrink may legitimately come back
    // zeroed, so only writability is asserted (no stale-content check).
    let regrown = brk(grown);
    if regrown < grown as i64 {
        fail(stage, 6, regrown);
    }
    fill_page(page_start, 0xE2);
    check(stage, 6, check_page(page_start, 0xE2));

    // 7: an impossible break request fails by returning the current break
    // (Linux reports the old break, it does not return -ENOMEM).
    expect_value(stage, 7, brk(0x0000_7fff_ffff_f000), regrown);

    // 8-9: anonymous private mapping is page aligned, writable and readable.
    let mapped = expect_ok(
        stage,
        8,
        mmap(
            0,
            PAGE_SIZE,
            PROT_READ | PROT_WRITE,
            MAP_PRIVATE | MAP_ANONYMOUS,
            -1,
            0,
        ),
    );
    let mapped = mapped as u64;
    if mapped == 0 || mapped % PAGE_SIZE != 0 {
        fail(stage, 8, mapped as i64);
    }
    fill_page(mapped, 0xE3);
    check(stage, 9, check_page(mapped, 0xE3));

    // 10-11: rejected mmap shapes.
    expect_errno(
        stage,
        10,
        mmap(
            0,
            0,
            PROT_READ | PROT_WRITE,
            MAP_PRIVATE | MAP_ANONYMOUS,
            -1,
            0,
        ),
        EINVAL,
    );
    expect_errno(
        stage,
        11,
        mmap(0, PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE, -1, 0),
        EBADF,
    );

    // 12: read-only protection keeps the mapping readable.
    expect_ok(stage, 12, mprotect(mapped, PAGE_SIZE, PROT_READ));
    check(stage, 12, read_byte(mapped) == pattern_byte(0, 0xE3));

    // 13: write protection is observable through the kernel user-copy path:
    // a receive into a read-only page must fail with EFAULT, not write it.
    let (first, second) = socket_pair(stage, 13, AF_UNIX, SOCK_STREAM);
    put_u8(OFF_TX, b'X');
    expect_value(stage, 13, write_fd(second, arena(OFF_TX) as u64, 1), 1);
    expect_errno(stage, 13, read_fd(first, mapped, 1), EFAULT);
    expect_ok(stage, 13, close(first));
    expect_ok(stage, 13, close(second));

    // 14: the same proof for PROT_NONE.
    expect_ok(stage, 14, mprotect(mapped, PAGE_SIZE, PROT_NONE));
    let (first, second) = socket_pair(stage, 14, AF_UNIX, SOCK_STREAM);
    put_u8(OFF_TX, b'Y');
    expect_value(stage, 14, write_fd(second, arena(OFF_TX) as u64, 1), 1);
    expect_errno(stage, 14, read_fd(first, mapped, 1), EFAULT);
    expect_ok(stage, 14, close(first));
    expect_ok(stage, 14, close(second));

    // 15: restoring write access makes the page usable again.
    expect_ok(
        stage,
        15,
        mprotect(mapped, PAGE_SIZE, PROT_READ | PROT_WRITE),
    );
    fill_page(mapped, 0xE4);
    check(stage, 15, check_page(mapped, 0xE4));

    // 16-17: protection errors (unaligned address, unmapped range).
    expect_errno(
        stage,
        16,
        mprotect(mapped + 1, PAGE_SIZE, PROT_READ | PROT_WRITE),
        EINVAL,
    );
    expect_errno(
        stage,
        17,
        mprotect(UNMAPPED_PROBE, PAGE_SIZE, PROT_READ | PROT_WRITE),
        ENOMEM,
    );

    // 18-19: unmapping reports success, and repeating it is a Linux no-op.
    expect_ok(stage, 18, munmap(mapped, PAGE_SIZE));
    expect_ok(stage, 19, munmap(mapped, PAGE_SIZE));

    // 20-22: a fresh mapping works again, and len = 0 is rejected.
    let remapped = expect_ok(
        stage,
        20,
        mmap(
            0,
            PAGE_SIZE,
            PROT_READ | PROT_WRITE,
            MAP_PRIVATE | MAP_ANONYMOUS,
            -1,
            0,
        ),
    );
    let remapped = remapped as u64;
    if remapped == 0 || remapped % PAGE_SIZE != 0 {
        fail(stage, 20, remapped as i64);
    }
    fill_page(remapped, 0xE5);
    check(stage, 20, check_page(remapped, 0xE5));
    expect_ok(stage, 21, munmap(remapped, PAGE_SIZE));
    expect_errno(stage, 22, munmap(remapped, 0), EINVAL);

    // 23 (M10a): a `PROT_NONE` anonymous mmap is a pure address reservation.
    // 批准的语义：非 FIXED 调用只推进 bump、不建立任何映射；之后一个
    // MAP_FIXED 映射可以覆盖该范围。因此本步断言 (a) 调用成功且返回页对齐
    // 地址、(b) 保留页对内核 user-copy 不可访问（read 得到 EFAULT）、
    // (c) munmap 成功（对保留范围是 no-op）。
    let reserved = expect_ok(
        stage,
        23,
        mmap(0, PAGE_SIZE, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0),
    );
    let reserved = reserved as u64;
    if reserved == 0 || reserved % PAGE_SIZE != 0 {
        fail(stage, 23, reserved as i64);
    }
    let (first, second) = socket_pair(stage, 23, AF_UNIX, SOCK_STREAM);
    put_u8(OFF_TX, b'Z');
    expect_value(stage, 23, write_fd(second, arena(OFF_TX) as u64, 1), 1);
    expect_errno(stage, 23, read_fd(first, reserved, 1), EFAULT);
    expect_ok(stage, 23, close(first));
    expect_ok(stage, 23, close(second));
    // 批准语义的另一半：保留也推进 bump，后续匿名映射不得与保留区重叠。
    let after = expect_ok(
        stage,
        23,
        mmap(
            0,
            PAGE_SIZE,
            PROT_READ | PROT_WRITE,
            MAP_PRIVATE | MAP_ANONYMOUS,
            -1,
            0,
        ),
    ) as u64;
    check(stage, 23, after >= reserved + PAGE_SIZE);
    expect_ok(stage, 23, munmap(after, PAGE_SIZE));
    expect_ok(stage, 23, munmap(reserved, PAGE_SIZE));
}

// ---------------------------------------------------------------------------
// M8a file closure: openat / write / read / close, plus dup offset sharing.
// ---------------------------------------------------------------------------

fn suite_files() {
    let stage = STAGE_FILES;

    // 1: create the file on the writable ramfs root; descriptors start at 3.
    let file = expect_ok(
        stage,
        1,
        openat_at(
            AT_FDCWD,
            M8A_FILE_PATH,
            O_CREAT | O_RDWR | O_TRUNC,
            O_FILE_MODE,
        ),
    );
    check(stage, 1, file == 3);

    // 2-4: write 8 bytes, duplicate the descriptor, write 8 more through the
    // duplicate.
    fill_pattern(OFF_TX, 8, 0xA1);
    expect_value(stage, 2, write_fd(file, arena(OFF_TX) as u64, 8), 8);
    let duplicate = expect_ok(stage, 3, dup(file));
    check(stage, 3, duplicate == 4);
    fill_pattern(OFF_TX + 64, 8, 0xA2);
    expect_value(
        stage,
        4,
        write_fd(duplicate, arena(OFF_TX + 64) as u64, 8),
        8,
    );

    // 5: dup shares the open description's offset, so both are at end-of-file
    // and reading through the original returns zero (no lseek needed).
    expect_value(stage, 5, read_fd(file, arena(OFF_RX) as u64, 8), 0);

    // 6-7: a fresh open starts at offset zero and sees both halves.
    let fresh = expect_ok(stage, 6, openat_at(AT_FDCWD, M8A_FILE_PATH, O_RDONLY, 0));
    check(stage, 6, fresh == 5);
    expect_value(stage, 6, read_fd(fresh, arena(OFF_RX) as u64, 8), 8);
    check(stage, 6, check_pattern(OFF_RX, 8, 0xA1));
    expect_value(stage, 7, read_fd(fresh, arena(OFF_RX + 64) as u64, 8), 8);
    check(stage, 7, check_pattern(OFF_RX + 64, 8, 0xA2));

    // 8: end-of-file at 16 bytes.
    expect_value(stage, 8, read_fd(fresh, arena(OFF_RX) as u64, 1), 0);

    // 9: close every descriptor (the duplicate shares the open description).
    expect_ok(stage, 9, close(duplicate));
    expect_ok(stage, 9, close(file));
    expect_ok(stage, 9, close(fresh));

    // 10-11: reopening from the root sees the persisted bytes.
    let reopened = expect_ok(stage, 10, openat_at(AT_FDCWD, M8A_FILE_PATH, O_RDONLY, 0));
    check(stage, 10, reopened == 3);
    expect_value(stage, 10, read_fd(reopened, arena(OFF_RX) as u64, 8), 8);
    check(stage, 10, check_pattern(OFF_RX, 8, 0xA1));
    expect_ok(stage, 11, close(reopened));

    // 12-16: negative paths (missing file, create-exclusive collision, bad
    // descriptors for read/write and for openat's directory argument).
    expect_errno(
        stage,
        12,
        openat_at(AT_FDCWD, M8A_MISSING_PATH, O_RDONLY, 0),
        ENOENT,
    );
    expect_errno(
        stage,
        13,
        openat_at(
            AT_FDCWD,
            M8A_FILE_PATH,
            O_CREAT | O_EXCL | O_WRONLY,
            O_FILE_MODE,
        ),
        EEXIST,
    );
    expect_errno(stage, 14, read_fd(999, arena(OFF_RX) as u64, 1), EBADF);
    expect_errno(stage, 15, write_fd(999, arena(OFF_TX) as u64, 1), EBADF);
    expect_errno(stage, 16, openat_at(999, M8A_FILE_PATH, O_RDONLY, 0), EBADF);
}

// ---------------------------------------------------------------------------
// M8b: Linux time and system information.
// ---------------------------------------------------------------------------

/// Linux `struct timespec` (x86-64): 16 bytes.
#[repr(C)]
struct Timespec {
    seconds: i64,
    nanoseconds: i64,
}

impl Timespec {
    const fn zeroed() -> Self {
        Self {
            seconds: 0,
            nanoseconds: 0,
        }
    }
}

/// Linux `_UTSNAME_LENGTH`: every `utsname` field is a 65-byte NUL-terminated
/// string (the field is NUL padded, never necessarily filled).
const UTS_FIELD: usize = 65;

/// Linux `struct utsname` (x86-64): six 65-byte fields.
#[repr(C)]
struct Utsname {
    sysname: [u8; UTS_FIELD],
    nodename: [u8; UTS_FIELD],
    release: [u8; UTS_FIELD],
    version: [u8; UTS_FIELD],
    machine: [u8; UTS_FIELD],
    domainname: [u8; UTS_FIELD],
}

impl Utsname {
    const fn zeroed() -> Self {
        Self {
            sysname: [0; UTS_FIELD],
            nodename: [0; UTS_FIELD],
            release: [0; UTS_FIELD],
            version: [0; UTS_FIELD],
            machine: [0; UTS_FIELD],
            domainname: [0; UTS_FIELD],
        }
    }
}

/// Linux `struct sysinfo` (x86-64): 112 bytes. The fields end at offset 108
/// (`mem_unit` is a `u32` at offset 104) and 8-byte alignment rounds the
/// struct up to 112, matching the kernel's own `#[repr(C)]` layout. Every field
/// is part of the wire layout the kernel fills; only the fields the closure
/// inspects are read, hence the `dead_code` allowance.
#[repr(C)]
#[allow(dead_code)]
struct SysInfo {
    uptime: i64,
    loads: [u64; 3],
    totalram: u64,
    freeram: u64,
    sharedram: u64,
    bufferram: u64,
    totalswap: u64,
    freeswap: u64,
    procs: u16,
    pad: u16,
    totalhigh: u64,
    freehigh: u64,
    mem_unit: u32,
}

// Freeze the ABI layout: 112 bytes with `mem_unit` at offset 104. A mismatch
// here would mean the kernel and this program disagree about `sysinfo`, so it
// is worth failing the build rather than misreading the structure at runtime.
const _: () = assert!(core::mem::size_of::<SysInfo>() == 112);
const _: () = assert!(core::mem::offset_of!(SysInfo, mem_unit) == 104);

impl SysInfo {
    const fn zeroed() -> Self {
        Self {
            uptime: 0,
            loads: [0; 3],
            totalram: 0,
            freeram: 0,
            sharedram: 0,
            bufferram: 0,
            totalswap: 0,
            freeswap: 0,
            procs: 0,
            pad: 0,
            totalhigh: 0,
            freehigh: 0,
            mem_unit: 0,
        }
    }
}

fn clock_gettime(clock: u64, value: &mut Timespec) -> i64 {
    syscall6(
        NR_CLOCK_GETTIME,
        clock,
        value as *mut Timespec as u64,
        0,
        0,
        0,
        0,
    )
}

fn clock_nanosleep(clock: u64, flags: u64, request: &Timespec, remaining: &mut Timespec) -> i64 {
    syscall6(
        NR_CLOCK_NANOSLEEP,
        clock,
        flags,
        request as *const Timespec as u64,
        remaining as *mut Timespec as u64,
        0,
        0,
    )
}

fn uname(name: &mut Utsname) -> i64 {
    syscall6(NR_UNAME, name as *mut Utsname as u64, 0, 0, 0, 0, 0)
}

fn sysinfo(info: &mut SysInfo) -> i64 {
    syscall6(NR_SYSINFO, info as *mut SysInfo as u64, 0, 0, 0, 0, 0)
}

fn getppid() -> i64 {
    syscall6(NR_GETPPID, 0, 0, 0, 0, 0, 0)
}

/// `tv_nsec` must be in `[0, NSEC_PER_SEC)` for every `timespec` the kernel
/// writes.
fn timespec_valid(value: &Timespec) -> bool {
    value.nanoseconds >= 0 && value.nanoseconds < NSEC_PER_SEC
}

/// Total nanoseconds. The monotonic/boottime clocks start at boot, so their
/// seconds are small and the multiply cannot overflow here.
fn timespec_total_ns(value: &Timespec) -> i64 {
    value.seconds * NSEC_PER_SEC + value.nanoseconds
}

/// Split a non-negative total into a normalized `timespec`.
fn timespec_from_ns(total: i64) -> Timespec {
    Timespec {
        seconds: total / NSEC_PER_SEC,
        nanoseconds: total % NSEC_PER_SEC,
    }
}

/// Read one clock, assert the result shape, and return total nanoseconds.
fn read_clock_ns(stage: u32, step: u32, clock: u64) -> i64 {
    let mut value = Timespec::zeroed();
    expect_ok(stage, step, clock_gettime(clock, &mut value));
    check(stage, step, timespec_valid(&value));
    timespec_total_ns(&value)
}

/// Fail unless the clock progressed or stayed equal between two samples.
fn expect_monotonic_progress(stage: u32, step: u32, previous: i64, current: i64) {
    if current < previous {
        fail(stage, step, current - previous);
    }
}

/// True when `field` holds a terminating NUL inside its 65 bytes.
fn uts_field_terminated(field: &[u8; UTS_FIELD]) -> bool {
    field.iter().any(|byte| *byte == 0)
}

/// The field text before the first NUL byte.
fn uts_field_text(field: &[u8; UTS_FIELD]) -> &[u8] {
    let end = field
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(UTS_FIELD);
    &field[..end]
}

/// M8b step 1: `clock_gettime` / `clock_nanosleep` on the Linux clocks.
fn suite_time() {
    let stage = STAGE_TIME;

    // step 1: CLOCK_MONOTONIC advances and never runs backwards.
    let monotonic_first = read_clock_ns(stage, 1, CLOCK_MONOTONIC);
    let monotonic_second = read_clock_ns(stage, 1, CLOCK_MONOTONIC);
    check(stage, 1, monotonic_second >= monotonic_first);

    // step 2: CLOCK_BOOTTIME is monotonic and covers at least CLOCK_MONOTONIC
    // (boottime additionally counts suspend time).
    let boottime_first = read_clock_ns(stage, 2, CLOCK_BOOTTIME);
    let boottime_second = read_clock_ns(stage, 2, CLOCK_BOOTTIME);
    check(stage, 2, boottime_second >= boottime_first);
    check(stage, 2, boottime_second >= monotonic_second);

    // step 3: CLOCK_REALTIME is optional (ENOSYS is accepted), but a value the
    // kernel does claim to have must look like a real wall clock: a normalized
    // timespec, non-decreasing across two samples, an epoch far past 0, and not
    // a copy of CLOCK_MONOTONIC. Zero/constant/aliased answers are fabricated
    // and fail here.
    let mut realtime_first = Timespec::zeroed();
    let realtime_result = clock_gettime(CLOCK_REALTIME, &mut realtime_first);
    if realtime_result != -ENOSYS {
        expect_ok(stage, 3, realtime_result);
        check(stage, 3, timespec_valid(&realtime_first));
        let mut realtime_second = Timespec::zeroed();
        expect_ok(
            stage,
            3,
            clock_gettime(CLOCK_REALTIME, &mut realtime_second),
        );
        check(stage, 3, timespec_valid(&realtime_second));
        let realtime_first_ns = timespec_total_ns(&realtime_first);
        let realtime_second_ns = timespec_total_ns(&realtime_second);
        expect_monotonic_progress(stage, 3, realtime_first_ns, realtime_second_ns);
        // A plausible wall clock is at least 1e8 seconds (1973-03); zero, a
        // fixed constant, or a monotonic alias all fall below this.
        check(stage, 3, realtime_first_ns >= 100_000_000 * NSEC_PER_SEC);
        check(stage, 3, realtime_first_ns != monotonic_second);
    }

    // step 4: a relative CLOCK_MONOTONIC sleep of M8B_SLEEP_NS (3 ticks) must
    // actually elapse at least M8B_MIN_ELAPSED_NS (2 ticks).
    let sleep_request = timespec_from_ns(M8B_SLEEP_NS);
    let mut remaining = Timespec::zeroed();
    let before_relative = read_clock_ns(stage, 4, CLOCK_MONOTONIC);
    expect_ok(
        stage,
        4,
        clock_nanosleep(CLOCK_MONOTONIC, 0, &sleep_request, &mut remaining),
    );
    let after_relative = read_clock_ns(stage, 4, CLOCK_MONOTONIC);
    expect_monotonic_progress(stage, 4, before_relative, after_relative);
    check(
        stage,
        4,
        after_relative - before_relative >= M8B_MIN_ELAPSED_NS,
    );

    // step 5: TIMER_ABSTIME with an instant in the past returns immediately
    // (well under one tick) instead of sleeping.
    let now = read_clock_ns(stage, 5, CLOCK_MONOTONIC);
    let past_total = if now > NSEC_PER_SEC {
        now - NSEC_PER_SEC
    } else {
        0
    };
    let past_request = timespec_from_ns(past_total);
    let before_past = read_clock_ns(stage, 5, CLOCK_MONOTONIC);
    expect_ok(
        stage,
        5,
        clock_nanosleep(
            CLOCK_MONOTONIC,
            TIMER_ABSTIME,
            &past_request,
            &mut remaining,
        ),
    );
    let after_past = read_clock_ns(stage, 5, CLOCK_MONOTONIC);
    expect_monotonic_progress(stage, 5, before_past, after_past);
    check(stage, 5, after_past - before_past < TICK_NS);

    // step 6: TIMER_ABSTIME with a future instant must wait for it.
    let future_request = timespec_from_ns(now + M8B_SLEEP_NS);
    let before_absolute = read_clock_ns(stage, 6, CLOCK_MONOTONIC);
    expect_ok(
        stage,
        6,
        clock_nanosleep(
            CLOCK_MONOTONIC,
            TIMER_ABSTIME,
            &future_request,
            &mut remaining,
        ),
    );
    let after_absolute = read_clock_ns(stage, 6, CLOCK_MONOTONIC);
    expect_monotonic_progress(stage, 6, before_absolute, after_absolute);
    check(
        stage,
        6,
        after_absolute - before_absolute >= M8B_MIN_ELAPSED_NS,
    );

    // step 7: the clock observed across all sleeps is still non-decreasing.
    let final_monotonic = read_clock_ns(stage, 7, CLOCK_MONOTONIC);
    check(stage, 7, final_monotonic >= after_absolute);
}

/// M8b step 2: `uname` / `getpid` / `getppid` / `sysinfo`.
fn suite_info() {
    let stage = STAGE_INFO;

    // step 1: uname describes the Linux personality; six fields terminate and
    // the machine type is x86-64 with a non-empty release string.
    let mut name = Utsname::zeroed();
    expect_ok(stage, 1, uname(&mut name));
    check(
        stage,
        1,
        uts_field_terminated(&name.sysname)
            && uts_field_terminated(&name.nodename)
            && uts_field_terminated(&name.release)
            && uts_field_terminated(&name.version)
            && uts_field_terminated(&name.machine)
            && uts_field_terminated(&name.domainname),
    );
    check(
        stage,
        1,
        uts_field_text(&name.machine) == b"x86_64".as_slice(),
    );
    check(stage, 1, !uts_field_text(&name.sysname).is_empty());
    check(stage, 1, !uts_field_text(&name.release).is_empty());

    // step 2: the test process has a real pid.
    let pid = expect_ok(stage, 2, getpid());
    check(stage, 2, pid > 0);

    // step 3: the Linux personality root is spawned by the kernel rather than
    // by another user process, so its parent pid is 0.
    let parent = expect_ok(stage, 3, getppid());
    expect_value(stage, 3, parent, 0);

    // step 4: sysinfo reflects a sane machine layout.
    let mut info = SysInfo::zeroed();
    expect_ok(stage, 4, sysinfo(&mut info));
    check(stage, 4, info.uptime >= 0);
    check(stage, 4, info.totalram > 0);
    check(stage, 4, info.freeram <= info.totalram);
    check(stage, 4, info.procs > 0);
    expect_value(stage, 4, i64::from(info.mem_unit), 1);
}

// ---------------------------------------------------------------------------
// M8c: Linux64 signal ABI (rt_sigaction / rt_sigprocmask / rt_sigreturn /
// kill / tgkill).
// ---------------------------------------------------------------------------

/// x86-64 kernel `struct kernel_sigaction`: 32 bytes, `mask` is the 8-byte
/// 64-bit kernel sigset (`_NSIG / 8`).
#[repr(C)]
#[derive(Clone, Copy)]
struct KernelSigaction {
    handler: u64,
    flags: u64,
    restorer: u64,
    mask: u64,
}

impl KernelSigaction {
    const fn empty() -> Self {
        Self {
            handler: 0,
            flags: 0,
            restorer: 0,
            mask: 0,
        }
    }

    /// `SIG_IGN`: the kernel compares the handler against this value.
    const fn ignored() -> Self {
        Self {
            handler: SIG_IGN,
            flags: 0,
            restorer: 0,
            mask: 0,
        }
    }
}

const _: () = assert!(core::mem::size_of::<KernelSigaction>() == 32);

unsafe extern "C" {
    /// Assembly restorer installed through `sa_restorer`: after the Rust
    /// handler returns, it runs `rt_sigreturn` so the interrupted context
    /// (registers included) is restored from the signal frame.
    fn rt_sigreturn_restorer();
}

/// Delivered `SIGUSR1` handler invocations (read/written volatile).
static mut SIGNAL_COUNT: u64 = 0;
/// Last `signum` passed to the handler; `-1` means "never called".
static mut SIGNAL_LAST: i32 = -1;
/// User stack pointer observed inside the handler.
static mut SIGNAL_HANDLER_STACK: u64 = 0;

extern "C" fn signal_handler(signum: i32) {
    // Async-signal-safe: only statics and the stack are touched. The kernel
    // restores every register from the signal frame after `rt_sigreturn`, which
    // the register probe in step 3 verifies separately.
    unsafe {
        let count = core::ptr::read_volatile(core::ptr::addr_of!(SIGNAL_COUNT));
        core::ptr::write_volatile(addr_of_mut!(SIGNAL_COUNT), count + 1);
        core::ptr::write_volatile(addr_of_mut!(SIGNAL_LAST), signum);
        let stack_pointer: u64;
        asm!("lea {}, [rsp]", out(reg) stack_pointer, options(nomem, nostack));
        core::ptr::write_volatile(addr_of_mut!(SIGNAL_HANDLER_STACK), stack_pointer);
        // Touch a local so a broken handler stack shows up in the record.
        let probe = [0x5Au8; 16];
        if probe[3] != 0x5A || probe[15] != 0x5A {
            core::ptr::write_volatile(addr_of_mut!(SIGNAL_LAST), -signum);
        }
    }
}

fn signal_count() -> u64 {
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(SIGNAL_COUNT)) }
}

fn signal_last() -> i32 {
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(SIGNAL_LAST)) }
}

fn signal_handler_stack() -> u64 {
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(SIGNAL_HANDLER_STACK)) }
}

fn reset_signal_probe() {
    unsafe {
        core::ptr::write_volatile(addr_of_mut!(SIGNAL_COUNT), 0);
        core::ptr::write_volatile(addr_of_mut!(SIGNAL_LAST), -1);
        core::ptr::write_volatile(addr_of_mut!(SIGNAL_HANDLER_STACK), 0);
    }
}

/// Single-bit 64-bit kernel signal set for `signum`.
const fn signal_bit(signum: u64) -> u64 {
    1u64 << (signum - 1)
}

fn rt_sigaction(signum: u64, action: u64, old_action: u64) -> i64 {
    syscall6(
        NR_RT_SIGACTION,
        signum,
        action,
        old_action,
        SIGSET_BYTES,
        0,
        0,
    )
}

fn rt_sigprocmask(how: u64, set: u64, old_set: u64) -> i64 {
    syscall6(NR_RT_SIGPROCMASK, how, set, old_set, SIGSET_BYTES, 0, 0)
}

fn kill(pid: i64, signal: u64) -> i64 {
    syscall6(NR_KILL, pid as u64, signal, 0, 0, 0, 0)
}

fn tgkill(tgid: i64, tid: i64, signal: u64) -> i64 {
    syscall6(NR_TGKILL, tgid as u64, tid as u64, signal, 0, 0, 0)
}

/// Unblock `SIGUSR1` while holding a sentinel in `r8`/`r9`. A pending signal is
/// delivered on the return to user mode, so its handler runs and `rt_sigreturn`
/// restores the interrupted context; both registers must still hold the
/// sentinel afterwards. Returns `(syscall result, 1 if a register mismatched)`.
fn unblock_with_register_probe(set_pointer: u64) -> (i64, u64) {
    const SENTINEL: u32 = 0x1234_5678;
    let mut raw_result: u64;
    let mut corrupted: u64;
    unsafe {
        asm!(
            "mov r8d, {sentinel}",
            "mov r9d, {sentinel}",
            "syscall",
            "mov {corrupted}, 0",
            "cmp r8d, {sentinel}",
            "jne 2f",
            "cmp r9d, {sentinel}",
            "jne 2f",
            "jmp 3f",
            "2:",
            "mov {corrupted}, 1",
            "3:",
            inlateout("rax") NR_RT_SIGPROCMASK => raw_result,
            in("rdi") SIG_UNBLOCK,
            in("rsi") set_pointer,
            in("rdx") 0u64,
            in("r10") SIGSET_BYTES,
            sentinel = const SENTINEL,
            corrupted = lateout(reg) corrupted,
            lateout("r8") _,
            lateout("r9") _,
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack),
        );
    }
    (raw_result as i64, corrupted)
}

/// M8c: minimal Linux64 signal ABI closure.
fn suite_signals(initial_rsp: usize) {
    let stage = STAGE_SIGNALS;

    // step 1: install the SIGUSR1 handler with SA_RESTORER, then read the
    // stored action back and compare handler/restorer/flags/mask.
    reset_signal_probe();
    let handler_pointer: extern "C" fn(i32) = signal_handler;
    let handler_address = handler_pointer as usize as u64;
    let restorer_pointer: unsafe extern "C" fn() = rt_sigreturn_restorer;
    let restorer_address = restorer_pointer as usize as u64;
    let action = KernelSigaction {
        handler: handler_address,
        flags: SA_RESTORER,
        restorer: restorer_address,
        mask: 0,
    };
    expect_ok(
        stage,
        1,
        rt_sigaction(SIGUSR1, &action as *const KernelSigaction as u64, 0),
    );
    let mut stored = KernelSigaction::empty();
    expect_ok(
        stage,
        1,
        rt_sigaction(SIGUSR1, 0, &mut stored as *mut KernelSigaction as u64),
    );
    check(stage, 1, stored.handler == handler_address);
    check(stage, 1, stored.restorer == restorer_address);
    check(stage, 1, stored.flags & SA_RESTORER != 0);
    expect_value(stage, 1, stored.mask as i64, 0);

    // step 2: block SIGUSR1; the signal must become pending without running the
    // handler, and the block must be visible in the exported mask.
    let mask = signal_bit(SIGUSR1);
    let mut previous = 0u64;
    expect_ok(
        stage,
        2,
        rt_sigprocmask(
            SIG_BLOCK,
            &mask as *const u64 as u64,
            &mut previous as *mut u64 as u64,
        ),
    );
    check(stage, 2, previous & mask == 0);
    let mut blocked = 0u64;
    expect_ok(
        stage,
        2,
        rt_sigprocmask(0, 0, &mut blocked as *mut u64 as u64),
    );
    check(stage, 2, blocked & mask != 0);
    let pid = expect_ok(stage, 2, getpid());
    expect_value(stage, 2, kill(pid, SIGUSR1), 0);
    check(stage, 2, signal_count() == 0);
    expect_value(stage, 2, i64::from(signal_last()), -1);

    // step 3: unblock while holding register sentinels; the pending signal is
    // delivered exactly once, the handler records signum, and `rt_sigreturn`
    // must restore r8/r9 plus a sane handler stack.
    let (unblock_result, corrupted) = unblock_with_register_probe(&mask as *const u64 as u64);
    expect_value(stage, 3, unblock_result, 0);
    expect_value(stage, 3, corrupted as i64, 0);
    check(stage, 3, signal_count() == 1);
    expect_value(stage, 3, i64::from(signal_last()), SIGUSR1 as i64);
    let handler_stack = signal_handler_stack();
    check(stage, 3, handler_stack != 0);
    check(stage, 3, handler_stack < 0x0000_8000_0000_0000);
    check(stage, 3, handler_stack <= initial_rsp as u64);
    check(stage, 3, handler_stack + 0x1_0000 >= initial_rsp as u64);

    // step 4: thread-directed delivery via tgkill triggers the handler again.
    expect_value(stage, 4, tgkill(pid, pid, SIGUSR1), 0);
    check(stage, 4, signal_count() == 2);
    expect_value(stage, 4, i64::from(signal_last()), SIGUSR1 as i64);

    // step 5: SIGUSR2 set to SIG_IGN: kill succeeds, the handler is not called
    // and the process keeps running.
    let ignored = KernelSigaction::ignored();
    expect_ok(
        stage,
        5,
        rt_sigaction(SIGUSR2, &ignored as *const KernelSigaction as u64, 0),
    );
    let mut stored_ignored = KernelSigaction::empty();
    expect_ok(
        stage,
        5,
        rt_sigaction(
            SIGUSR2,
            0,
            &mut stored_ignored as *mut KernelSigaction as u64,
        ),
    );
    expect_value(stage, 5, stored_ignored.handler as i64, SIG_IGN as i64);
    expect_value(stage, 5, kill(pid, SIGUSR2), 0);
    check(stage, 5, signal_count() == 2);
    expect_value(stage, 5, i64::from(signal_last()), SIGUSR1 as i64);
}

// ---------------------------------------------------------------------------
// M8d: two Linux64 processes (role 0 = parent, role 1 = child) and the
// cross-process kill / tgkill / wait4 closure.
// ---------------------------------------------------------------------------

/// Bound for one handshake poll: one iteration is one tick (5 s at 100 Hz).
const M8D_POLL_TICKS: u64 = 500;
/// Bound for the initial hello ping; it covers the child being scheduled while
/// the parent is still inside the earlier single-process suites.
const M8D_PING_TICKS: u64 = 6000;
/// Bound for the child waiting for its terminating signal.
const M8D_TERM_TICKS: u64 = 1000;
/// Bound on blocking `wait4` retries after `EINTR`.
const M8D_REAP_TRIES: u64 = 500;

/// `SIGWINCH` deliveries observed by the handshake (volatile in the handler).
static mut WINCH_COUNT: u64 = 0;

/// `SIGWINCH` handler: count deliveries only. The default action of `SIGWINCH`
/// is "ignore", so a ping that arrives before installation cannot kill either
/// process.
extern "C" fn winch_handler(_signum: i32) {
    unsafe {
        let count = core::ptr::read_volatile(core::ptr::addr_of!(WINCH_COUNT));
        core::ptr::write_volatile(addr_of_mut!(WINCH_COUNT), count + 1);
    }
}

fn winch_count() -> u64 {
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(WINCH_COUNT)) }
}

fn reset_winch_probe() {
    unsafe { core::ptr::write_volatile(addr_of_mut!(WINCH_COUNT), 0) }
}

/// Kernel action carrying the M8c assembly restorer.
fn signal_action(handler: usize) -> KernelSigaction {
    let restorer_pointer: unsafe extern "C" fn() = rt_sigreturn_restorer;
    KernelSigaction {
        handler: handler as u64,
        flags: SA_RESTORER,
        restorer: restorer_pointer as usize as u64,
        mask: 0,
    }
}

/// One tick of relative `CLOCK_MONOTONIC` sleep. The return to user mode is the
/// point where a pending cross-process signal is delivered.
fn sleep_ticks(ticks: u64) {
    let mut remaining = Timespec::zeroed();
    let request = Timespec {
        seconds: 0,
        nanoseconds: ticks as i64 * TICK_NS,
    };
    let _ = clock_nanosleep(CLOCK_MONOTONIC, 0, &request, &mut remaining);
}

/// Bounded poll for `SIGNAL_COUNT >= target`.
fn poll_signal_count(target: u64, ticks: u64) -> bool {
    let mut spent = 0u64;
    while spent < ticks {
        if signal_count() >= target {
            return true;
        }
        sleep_ticks(1);
        spent += 1;
    }
    signal_count() >= target
}

/// Bounded poll for `WINCH_COUNT >= target`.
fn poll_winch_count(target: u64, ticks: u64) -> bool {
    let mut spent = 0u64;
    while spent < ticks {
        if winch_count() >= target {
            return true;
        }
        sleep_ticks(1);
        spent += 1;
    }
    winch_count() >= target
}

/// M8d parent: handshake with the child, cross-process signals in both
/// directions, then a real blocking `wait4` that reaps the child.
fn suite_process() {
    let stage = STAGE_PROCESS;

    // step 1: the parent is the detached test root: its pid is a valid positive
    // index and it has no parent (getppid() == 0). No absolute pid value is
    // asserted; only this parent relation is contractual.
    check(stage, 1, getpid() > 0);
    expect_value(stage, 1, getppid(), 0);

    reset_signal_probe();
    reset_winch_probe();
    let winch: extern "C" fn(i32) = winch_handler;
    let usr1: extern "C" fn(i32) = signal_handler;
    let winch_action = signal_action(winch as usize);
    expect_ok(
        stage,
        3,
        rt_sigaction(SIGWINCH, &winch_action as *const KernelSigaction as u64, 0),
    );
    let usr1_action = signal_action(usr1 as usize);
    expect_ok(
        stage,
        4,
        rt_sigaction(SIGUSR1, &usr1_action as *const KernelSigaction as u64, 0),
    );

    // step 5: ping the child until it acknowledges with SIGWINCH. kill(-1)
    // broadcasts to the test's children; before the child exists it returns
    // -ESRCH, which this bounded retry tolerates.
    let mut pinged = 0u64;
    while winch_count() == 0 && pinged < M8D_PING_TICKS {
        let _ = kill(-1, SIGWINCH);
        sleep_ticks(1);
        pinged += 1;
    }
    check(stage, 6, winch_count() >= 1);

    // step 7: the child sends SIGUSR1 through tgkill(getppid(), getppid(), ...):
    // the custom handler must run exactly once with the expected signum.
    check(stage, 7, poll_signal_count(1, M8D_POLL_TICKS));
    expect_value(stage, 8, signal_count() as i64, 1);
    expect_value(stage, 9, i64::from(signal_last()), SIGUSR1 as i64);

    // step 10: the child is alive, so a non-blocking wait4 reports nothing yet.
    let mut status = 0i32;
    expect_value(stage, 10, wait4(-1, &mut status, WNOHANG, 0), 0);

    // step 11: the first SIGUSR1 reaches the child's custom handler; the child
    // then restores SIG_DFL and acknowledges with SIGWINCH.
    expect_value(stage, 11, kill(-1, SIGUSR1), 0);
    check(stage, 12, poll_winch_count(2, M8D_POLL_TICKS));

    // step 13: the second SIGUSR1 terminates the child by its default action.
    expect_value(stage, 13, kill(-1, SIGUSR1), 0);

    // step 14: a blocking wait4 reaps the child. Linux encodes a signal death as
    // the signum in the low 7 bits (WIFSIGNALED + WTERMSIG).
    let mut reaped = 0i64;
    let mut attempts = 0u64;
    while attempts < M8D_REAP_TRIES {
        let result = wait4(-1, &mut status, 0, 0);
        if result > 0 {
            reaped = result;
            break;
        }
        check(stage, 15, result == -EINTR);
        attempts += 1;
    }
    check(stage, 16, reaped > 0);
    expect_value(stage, 17, (status & 0x7f) as i64, SIGUSR1 as i64);
    check(stage, 18, (status & 0x7f) != 0 && (status & 0x7f) != 0x7f);
    // The child pid is our own pid + 1 (index + 1); a controlled regression
    // assertion that also keeps the reaped pid self-consistent.
    expect_value(stage, 19, reaped, getpid() + 1);

    // step 20: role 2 (the M9c lock peer) is still alive, so a non-blocking
    // wait4 over all children reports no state change; a pid that is not a
    // child keeps the ECHILD negative path observable.
    expect_value(stage, 20, wait4(-1, &mut status, WNOHANG, 0), 0);
    expect_errno(stage, 20, wait4(getpid(), &mut status, WNOHANG, 0), ECHILD);
}

/// M8d child: acknowledges the parent handshake, delivers one `tgkill` to the
/// parent, arms `SIG_DFL`, and waits for the terminating signal. Never returns:
/// the parent reaps the default-action death through `wait4`.
fn m8d_child_main() -> ! {
    let stage = STAGE_PROCESS;

    // step 21: the child's pid is a valid positive index and its parent link
    // points at a different process. The relation is proven by the handshake
    // below: the pid from getppid() receives this child's tgkill and its handler
    // runs exactly once. No absolute pid value is asserted.
    check(stage, 21, getpid() > 0);
    check(stage, 21, getppid() > 0);
    check(stage, 21, getppid() != getpid());

    reset_signal_probe();
    reset_winch_probe();
    let winch: extern "C" fn(i32) = winch_handler;
    let usr1: extern "C" fn(i32) = signal_handler;
    let winch_action = signal_action(winch as usize);
    expect_ok(
        stage,
        23,
        rt_sigaction(SIGWINCH, &winch_action as *const KernelSigaction as u64, 0),
    );
    let usr1_action = signal_action(usr1 as usize);
    expect_ok(
        stage,
        24,
        rt_sigaction(SIGUSR1, &usr1_action as *const KernelSigaction as u64, 0),
    );

    // step 25: wait for the parent's hello ping, then acknowledge it.
    check(stage, 25, poll_winch_count(1, M8D_PING_TICKS));
    let parent_pid = getppid();
    expect_value(stage, 26, kill(parent_pid, SIGWINCH), 0);

    // step 27: thread-directed cross-process delivery to the parent through the
    // pid relation (tgid == tid == getppid()).
    expect_value(stage, 27, tgkill(parent_pid, parent_pid, SIGUSR1), 0);

    // step 28: the parent's first SIGUSR1 reaches this process' custom handler.
    check(stage, 28, poll_signal_count(1, M8D_POLL_TICKS));
    expect_value(stage, 29, signal_count() as i64, 1);
    expect_value(stage, 30, i64::from(signal_last()), SIGUSR1 as i64);

    // step 31: restore SIG_DFL for SIGUSR1 and prove the stored action is the
    // default one.
    let default_action = KernelSigaction::empty();
    expect_ok(
        stage,
        31,
        rt_sigaction(SIGUSR1, &default_action as *const KernelSigaction as u64, 0),
    );
    let mut stored = KernelSigaction::empty();
    expect_ok(
        stage,
        31,
        rt_sigaction(SIGUSR1, 0, &mut stored as *mut KernelSigaction as u64),
    );
    expect_value(stage, 31, stored.handler as i64, 0);

    // step 32: tell the parent the default action is armed.
    expect_value(stage, 32, kill(parent_pid, SIGWINCH), 0);

    // step 33: bounded wait for the terminating SIGUSR1. The default action must
    // kill this process before the bound; reaching the end is a failure.
    let mut waited = 0u64;
    while waited < M8D_TERM_TICKS {
        sleep_ticks(1);
        waited += 1;
    }
    fail(stage, 33, -EINTR);
}

// ---------------------------------------------------------------------------
// M8e: extended file ABI (lseek / fstat / statx / getdents64 / fcntl).
// ---------------------------------------------------------------------------

/// Frozen x86-64 `struct stat` (144 bytes). Only the fields the suite inspects
/// are read; the rest keeps the kernel padding/offsets unchanged.
#[repr(C)]
#[derive(Clone, Copy)]
#[allow(dead_code)]
struct Stat {
    device: u64,
    inode: u64,
    links: u64,
    mode: u32,
    uid: u32,
    gid: u32,
    reserved0: u32,
    rdevice: u64,
    size: i64,
    block_size: i64,
    blocks: i64,
    atime: [i64; 2],
    mtime: [i64; 2],
    ctime: [i64; 2],
    reserved: [i64; 3],
}

impl Stat {
    const fn zeroed() -> Self {
        Self {
            device: 0,
            inode: 0,
            links: 0,
            mode: 0,
            uid: 0,
            gid: 0,
            reserved0: 0,
            rdevice: 0,
            size: 0,
            block_size: 0,
            blocks: 0,
            atime: [0; 2],
            mtime: [0; 2],
            ctime: [0; 2],
            reserved: [0; 3],
        }
    }
}

const _: () = assert!(core::mem::size_of::<Stat>() == 144);

/// Frozen x86-64 `struct statx_timestamp` (16 bytes).
#[repr(C)]
#[derive(Clone, Copy)]
#[allow(dead_code)]
struct StatxTimestamp {
    seconds: i64,
    nanoseconds: u32,
    reserved: i32,
}

impl StatxTimestamp {
    const fn zeroed() -> Self {
        Self {
            seconds: 0,
            nanoseconds: 0,
            reserved: 0,
        }
    }
}

/// Frozen x86-64 `struct statx` (256 bytes). Only `mask`, `block_size`, `mode`
/// and `size` are inspected; the remaining fields pin the ABI layout.
#[repr(C)]
#[derive(Clone, Copy)]
#[allow(dead_code)]
struct Statx {
    mask: u32,
    block_size: u32,
    attributes: u64,
    links: u32,
    uid: u32,
    gid: u32,
    mode: u16,
    spare0: u16,
    inode: u64,
    size: u64,
    blocks: u64,
    attributes_mask: u64,
    atime: StatxTimestamp,
    btime: StatxTimestamp,
    ctime: StatxTimestamp,
    mtime: StatxTimestamp,
    rdevice_major: u32,
    rdevice_minor: u32,
    device_major: u32,
    device_minor: u32,
    mount_id: u64,
    direct_io_memory_alignment: u32,
    direct_io_offset_alignment: u32,
    spare: [u64; 12],
}

impl Statx {
    const fn zeroed() -> Self {
        Self {
            mask: 0,
            block_size: 0,
            attributes: 0,
            links: 0,
            uid: 0,
            gid: 0,
            mode: 0,
            spare0: 0,
            inode: 0,
            size: 0,
            blocks: 0,
            attributes_mask: 0,
            atime: StatxTimestamp::zeroed(),
            btime: StatxTimestamp::zeroed(),
            ctime: StatxTimestamp::zeroed(),
            mtime: StatxTimestamp::zeroed(),
            rdevice_major: 0,
            rdevice_minor: 0,
            device_major: 0,
            device_minor: 0,
            mount_id: 0,
            direct_io_memory_alignment: 0,
            direct_io_offset_alignment: 0,
            spare: [0; 12],
        }
    }
}

const _: () = assert!(core::mem::size_of::<Statx>() == 256);

/// Walk one `getdents64` buffer: assert every record is 8-byte aligned and in
/// bounds, and report whether `wanted` (a regular file) is present.
fn scan_dirents(
    offset: usize,
    count: usize,
    wanted: &[u8],
    wanted_type: u8,
    stage: u32,
    step: u32,
) -> bool {
    let mut cursor = 0usize;
    let mut found = false;
    while cursor < count {
        check(stage, step, count - cursor >= DIRENT_NAME_OFFSET + 1);
        let record = usize::from(get_u16_ne(offset + cursor + 16));
        check(stage, step, record >= DIRENT_NAME_OFFSET + 1);
        check(stage, step, record % 8 == 0);
        check(stage, step, cursor + record <= count);
        let name_bytes = record - DIRENT_NAME_OFFSET;
        if name_bytes >= wanted.len() + 1
            && arena_eq(offset + cursor + DIRENT_NAME_OFFSET, wanted)
            && get_u8(offset + cursor + DIRENT_NAME_OFFSET + wanted.len()) == 0
        {
            let entry_type = get_u8(offset + cursor + 18);
            // An unknown (or all-zero) wanted type accepts any reported type;
            // otherwise the reported `d_type` must match exactly.
            check(
                stage,
                step,
                wanted_type == DT_UNKNOWN || entry_type == wanted_type,
            );
            found = true;
        }
        cursor += record;
    }
    found
}

/// M8e: extended file ABI closure.
fn suite_m8e_files() {
    let stage = STAGE_FILES_EXTRA;

    // step 1: create `/m8e-files.bin` with the six-byte payload "abcdef".
    let file = expect_ok(
        stage,
        1,
        openat_at(
            AT_FDCWD,
            M8E_FILE_PATH,
            O_CREAT | O_RDWR | O_TRUNC,
            O_FILE_MODE,
        ),
    );
    check(stage, 1, file >= 3);
    expect_value(stage, 1, write_fd(file, b"abcdef".as_ptr() as u64, 6), 6);
    expect_value(stage, 1, close(file), 0);

    // step 2: SEEK_SET relocates inside the file; the read reports the tail.
    let file = expect_ok(stage, 2, openat_at(AT_FDCWD, M8E_FILE_PATH, O_RDONLY, 0));
    check(stage, 2, file >= 3);
    expect_value(stage, 2, lseek(file, 2, SEEK_SET), 2);
    expect_value(stage, 2, read_fd(file, arena(OFF_RX) as u64, 4), 4);
    check(stage, 2, arena_eq(OFF_RX, b"cdef"));

    // step 3: negative SEEK_CUR and both SEEK_END shapes.
    expect_value(stage, 3, lseek(file, -6, SEEK_CUR), 0);
    expect_value(stage, 3, read_fd(file, arena(OFF_RX) as u64, 2), 2);
    check(stage, 3, arena_eq(OFF_RX, b"ab"));
    expect_value(stage, 3, lseek(file, 0, SEEK_END), 6);
    expect_value(stage, 3, lseek(file, -2, SEEK_END), 4);
    expect_value(stage, 3, read_fd(file, arena(OFF_RX) as u64, 2), 2);
    check(stage, 3, arena_eq(OFF_RX, b"ef"));

    // step 4: a negative resulting position and an unknown whence are EINVAL.
    expect_value(stage, 4, lseek(file, -1, SEEK_SET), -EINVAL);
    expect_value(stage, 4, lseek(file, 0, 99), -EINVAL);

    // step 5: `dup` shares the open file description, so the offset is shared.
    expect_value(stage, 5, lseek(file, 0, SEEK_SET), 0);
    let duplicate = expect_ok(stage, 5, dup(file));
    check(stage, 5, duplicate > file);
    expect_value(stage, 5, read_fd(file, arena(OFF_RX) as u64, 1), 1);
    check(stage, 5, get_u8(OFF_RX) == b'a');
    expect_value(stage, 5, read_fd(duplicate, arena(OFF_RX) as u64, 1), 1);
    check(stage, 5, get_u8(OFF_RX) == b'b');
    expect_value(stage, 5, close(duplicate), 0);

    // step 6: fstat reports a regular file of the written size with a sane
    // block geometry.
    let mut metadata = Stat::zeroed();
    expect_ok(stage, 6, fstat(file, &mut metadata));
    check(stage, 6, metadata.mode & S_IFMT == S_IFREG);
    expect_value(stage, 6, metadata.size, 6);
    check(
        stage,
        6,
        metadata.block_size > 0 && metadata.block_size <= 65536,
    );
    check(
        stage,
        6,
        metadata.block_size & (metadata.block_size - 1) == 0,
    );
    check(stage, 6, metadata.blocks >= 0);
    expect_value(stage, 6, close(file), 0);

    // step 7: statx(AT_FDCWD, absolute path) reports the same values.
    let mut extended = Statx::zeroed();
    expect_ok(
        stage,
        7,
        statx(AT_FDCWD, M8E_FILE_PATH, 0, STATX_BASIC_STATS, &mut extended),
    );
    check(stage, 7, u32::from(extended.mode) & S_IFMT == S_IFREG);
    expect_value(stage, 7, extended.size as i64, 6);
    expect_value(
        stage,
        7,
        i64::from(extended.block_size),
        metadata.block_size,
    );
    check(stage, 7, extended.mask & STATX_TYPE != 0);
    check(stage, 7, extended.mask & STATX_SIZE != 0);

    // step 8: invalid statx inputs fail explicitly: missing path, unknown flag,
    // and an invalid directory descriptor for a relative path.
    expect_errno(
        stage,
        8,
        statx(
            AT_FDCWD,
            M8E_MISSING_PATH,
            0,
            STATX_BASIC_STATS,
            &mut extended,
        ),
        ENOENT,
    );
    expect_errno(
        stage,
        8,
        statx(
            AT_FDCWD,
            M8E_FILE_PATH,
            STATX_UNKNOWN_FLAG,
            STATX_BASIC_STATS,
            &mut extended,
        ),
        EINVAL,
    );
    expect_errno(
        stage,
        8,
        statx(
            424242,
            M8E_RELATIVE_NAME,
            0,
            STATX_BASIC_STATS,
            &mut extended,
        ),
        EBADF,
    );

    // step 9: getdents64 over the root directory with a 64-byte buffer: records
    // are 8-byte aligned and successive calls continue from the directory offset.
    let directory = expect_ok(
        stage,
        9,
        openat_at(AT_FDCWD, M8E_ROOT_PATH, O_RDONLY | O_DIRECTORY, 0),
    );
    check(stage, 9, directory >= 3);
    let mut listed = false;
    let mut calls = 0u64;
    while calls < 16 {
        calls += 1;
        let count = expect_ok(stage, 9, getdents64(directory, arena(OFF_RX) as u64, 64));
        if count == 0 {
            break;
        }
        check(stage, 9, count as usize % 8 == 0);
        listed = scan_dirents(OFF_RX, count as usize, b"m8e-files.bin", DT_REG, stage, 9) || listed;
    }
    check(stage, 9, listed);
    check(stage, 9, calls >= 2);

    // step 10: a directory descriptor cannot be read as a byte stream.
    expect_errno(
        stage,
        10,
        read_fd(directory, arena(OFF_TX) as u64, 1),
        EISDIR,
    );
    expect_value(stage, 10, close(directory), 0);

    // step 11: reopening the directory starts a fresh traversal from the start.
    let directory = expect_ok(
        stage,
        11,
        openat_at(AT_FDCWD, M8E_ROOT_PATH, O_RDONLY | O_DIRECTORY, 0),
    );
    let count = expect_ok(stage, 11, getdents64(directory, arena(OFF_RX) as u64, 256));
    check(stage, 11, count > 0);
    check(
        stage,
        11,
        scan_dirents(OFF_RX, count as usize, b"m8e-files.bin", DT_REG, stage, 11),
    );
    expect_value(stage, 11, close(directory), 0);

    // step 12: FD_CLOEXEC default, set and clear through F_GETFD/F_SETFD.
    let file = expect_ok(stage, 12, openat_at(AT_FDCWD, M8E_FILE_PATH, O_RDWR, 0));
    expect_value(stage, 12, fcntl(file, F_GETFD, 0), 0);
    expect_value(stage, 12, fcntl(file, F_SETFD, FD_CLOEXEC), 0);
    expect_value(stage, 12, fcntl(file, F_GETFD, 0), FD_CLOEXEC as i64);
    expect_value(stage, 12, fcntl(file, F_SETFD, 0), 0);
    expect_value(stage, 12, fcntl(file, F_GETFD, 0), 0);

    // step 13: F_DUPFD returns the lowest free descriptor >= the argument and
    // shares the open file description (hence the offset).
    let duplicated = expect_ok(stage, 13, fcntl(file, F_DUPFD, 7));
    check(stage, 13, duplicated >= 7);
    expect_value(stage, 13, lseek(file, 3, SEEK_SET), 3);
    expect_value(stage, 13, read_fd(duplicated, arena(OFF_RX) as u64, 1), 1);
    check(stage, 13, get_u8(OFF_RX) == b'd');

    // step 14: F_DUPFD_CLOEXEC sets FD_CLOEXEC on the new descriptor.
    let cloexec_copy = expect_ok(stage, 14, fcntl(file, F_DUPFD_CLOEXEC, 9));
    check(stage, 14, cloexec_copy >= 9);
    expect_value(
        stage,
        14,
        fcntl(cloexec_copy, F_GETFD, 0),
        FD_CLOEXEC as i64,
    );

    // step 15: an unknown fcntl request fails explicitly with EINVAL.
    expect_errno(stage, 15, fcntl(file, 999, 0), EINVAL);

    // step 16: release every descriptor.
    expect_value(stage, 16, close(cloexec_copy), 0);
    expect_value(stage, 16, close(duplicated), 0);
    expect_value(stage, 16, close(file), 0);
}

// ---------------------------------------------------------------------------
// M8f: futex wait/wake and the TLS base / tid-address closure.
// ---------------------------------------------------------------------------

/// TLS words stored through plain memory and read through the FS base.
const TLS_WORD_A: u64 = 0x0102_0304_0506_0708;
const TLS_WORD_B: u64 = 0x1112_1314_1516_1718;
const TLS_WORD_A_NEW: u64 = 0x2122_2324_2526_2728;
const TLS_WORD_B_NEW: u64 = 0x3132_3334_3536_3738;
/// Sentinel placed where `set_tid_address` stores its `clear_child_tid` pointer:
/// the kernel must leave the memory untouched until the thread exits.
const TID_SENTINEL: i64 = 0x0BAD_F00D;

/// 64-bit word at `FS:0`, read as the kernel's TLS base register (FS) demands.
fn read_fs_0() -> u64 {
    let value: u64;
    unsafe {
        asm!(
            "mov {value}, qword ptr fs:[0]",
            value = out(reg) value,
            options(nostack, preserves_flags),
        );
    }
    value
}

/// 64-bit word at `FS:8`.
fn read_fs_8() -> u64 {
    let value: u64;
    unsafe {
        asm!(
            "mov {value}, qword ptr fs:[8]",
            value = out(reg) value,
            options(nostack, preserves_flags),
        );
    }
    value
}

/// Store the 64-bit word at `FS:0`.
fn write_fs_0(value: u64) {
    unsafe {
        asm!(
            "mov qword ptr fs:[0], {value}",
            value = in(reg) value,
            options(nostack, preserves_flags),
        );
    }
}

/// Volatile 64-bit read of user memory (the mapping itself, not the FS view).
fn read_user_word(address: u64) -> u64 {
    unsafe { core::ptr::read_volatile(address as *const u64) }
}

/// Volatile 64-bit write of user memory.
fn write_user_word(address: u64, value: u64) {
    unsafe { core::ptr::write_volatile(address as *mut u64, value) }
}

/// M8f: futex wait/wake closure.
fn suite_m8f_futex() {
    let stage = STAGE_FUTEX;

    // Zero and short relative timeouts for `futex` waits.
    put_u64_ne(OFF_TS_ZERO, 0);
    put_u64_ne(OFF_TS_ZERO + 8, 0);
    put_u64_ne(OFF_TS_SHORT, 0);
    put_u64_ne(OFF_TS_SHORT + 8, 10_000_000); // 10 ms relative.

    let word = arena(OFF_FUTEX) as u64;

    // step 1: a matching value with a zero relative timeout times out at once.
    put_u32_le(OFF_FUTEX, 0);
    expect_errno(
        stage,
        1,
        futex(word, FUTEX_WAIT, 0, arena(OFF_TS_ZERO) as u64, 0, 0),
        ETIMEDOUT,
    );

    // step 2: a mismatched expected value fails with EAGAIN before waiting.
    put_u32_le(OFF_FUTEX, 1);
    expect_errno(stage, 2, futex(word, FUTEX_WAIT, 0, 0, 0, 0), EAGAIN);

    // step 3: a matching value with a short relative timeout times out.
    put_u32_le(OFF_FUTEX, 5);
    expect_errno(
        stage,
        3,
        futex(word, FUTEX_WAIT, 5, arena(OFF_TS_SHORT) as u64, 0, 0),
        ETIMEDOUT,
    );

    // step 4: waking with no waiters reports zero wakeups.
    expect_value(stage, 4, futex(word, FUTEX_WAKE, 1, 0, 0, 0), 0);

    // step 5: FUTEX_WAIT_PRIVATE keeps the same timeout contract.
    put_u32_le(OFF_FUTEX, 7);
    expect_errno(
        stage,
        5,
        futex(
            word,
            FUTEX_WAIT | FUTEX_PRIVATE_FLAG,
            7,
            arena(OFF_TS_ZERO) as u64,
            0,
            0,
        ),
        ETIMEDOUT,
    );

    // step 6: FUTEX_WAKE_PRIVATE with no waiters reports zero wakeups too.
    expect_value(
        stage,
        6,
        futex(word, FUTEX_WAKE | FUTEX_PRIVATE_FLAG, 1, 0, 0, 0),
        0,
    );
}

/// M8f: FS-based TLS word access plus `set_tid_address`.
fn suite_m8f_tls() {
    let stage = STAGE_TLS;

    // step 1: an anonymous writable low-half page becomes the TLS base.
    let tls_page = expect_ok(
        stage,
        1,
        mmap(
            0,
            PAGE_SIZE,
            PROT_READ | PROT_WRITE,
            MAP_PRIVATE | MAP_ANONYMOUS,
            -1,
            0,
        ),
    );
    check(stage, 1, tls_page > 0);
    check(stage, 1, tls_page < 0x0000_8000_0000_0000);
    check(stage, 1, tls_page as u64 % PAGE_SIZE == 0);

    // step 2: remember the current FS base so the test leaves it as it found it.
    put_u64_ne(OFF_ARCH_SAVED, 0);
    expect_ok(
        stage,
        2,
        arch_prctl(ARCH_GET_FS, arena(OFF_ARCH_SAVED) as u64),
    );
    let previous = get_u64_ne(OFF_ARCH_SAVED);

    // step 3: install the page as FS base and read the base back.
    expect_ok(stage, 3, arch_prctl(ARCH_SET_FS, tls_page as u64));
    expect_ok(
        stage,
        3,
        arch_prctl(ARCH_GET_FS, arena(OFF_ARCH_OUT) as u64),
    );
    expect_value(stage, 3, get_u64_ne(OFF_ARCH_OUT) as i64, tls_page);

    // step 4: the fresh anonymous page reads as zero through FS, and plain
    // stores at TLS offsets are visible through FS:0/FS:8.
    check(stage, 4, read_fs_0() == 0);
    check(stage, 4, read_fs_8() == 0);
    write_user_word(tls_page as u64, TLS_WORD_A);
    write_user_word(tls_page as u64 + 8, TLS_WORD_B);
    expect_value(stage, 4, read_fs_0() as i64, TLS_WORD_A as i64);
    expect_value(stage, 4, read_fs_8() as i64, TLS_WORD_B as i64);

    // step 5: stores through FS are visible through plain loads, and the two
    // TLS words stay independent.
    write_fs_0(TLS_WORD_A_NEW);
    write_user_word(tls_page as u64 + 8, TLS_WORD_B_NEW);
    expect_value(
        stage,
        5,
        read_user_word(tls_page as u64) as i64,
        TLS_WORD_A_NEW as i64,
    );
    expect_value(
        stage,
        5,
        read_user_word(tls_page as u64 + 8) as i64,
        TLS_WORD_B_NEW as i64,
    );
    expect_value(stage, 5, read_fs_0() as i64, TLS_WORD_A_NEW as i64);
    expect_value(stage, 5, read_fs_8() as i64, TLS_WORD_B_NEW as i64);

    // step 6: restoring the previous FS base reads back the same value.
    expect_ok(stage, 6, arch_prctl(ARCH_SET_FS, previous));
    expect_ok(
        stage,
        6,
        arch_prctl(ARCH_GET_FS, arena(OFF_ARCH_OUT) as u64),
    );
    expect_value(stage, 6, get_u64_ne(OFF_ARCH_OUT) as i64, previous as i64);

    // step 7: `set_tid_address` stores the `clear_child_tid` pointer and returns
    // the calling tid; it does not write the tid at the address until the thread
    // exits, so the sentinel must stay untouched. The single-threaded tid equals
    // the pid, and a second registration (NULL pointer) returns the same tid.
    put_u32_le(OFF_TID, TID_SENTINEL as u32);
    let tid = expect_ok(stage, 7, set_tid_address(arena(OFF_TID) as u64));
    check(stage, 7, tid > 0);
    expect_value(stage, 7, tid, getpid());
    expect_value(stage, 7, i64::from(get_u32_le(OFF_TID)), TID_SENTINEL);
    let second = expect_ok(stage, 7, set_tid_address(0));
    expect_value(stage, 7, second, tid);
    expect_value(stage, 7, i64::from(get_u32_le(OFF_TID)), TID_SENTINEL);
}

// ---------------------------------------------------------------------------
// M8g: eventfd counters and poll/ppoll readiness (+ the signal wake closure).
// ---------------------------------------------------------------------------

/// `sizeof(struct pollfd)` (`i32 fd`, `i16 events`, `i16 revents`).
const POLLFD_BYTES: usize = 8;

/// Socket used by [`wake_handler`]: the peer end of the polled socketpair.
static mut WAKE_FD: u64 = 0;

/// Fixed byte written by [`wake_handler`]; immutable so the handler only reads
/// static storage besides the write itself.
static WAKE_BYTE: u8 = b'w';

/// Number of [`wake_handler`] deliveries; the blocked-signal step asserts the
/// handler does not run before the temporary mask is lifted.
static mut WAKE_WRITES: u64 = 0;

/// SIGUSR1 handler for the M8g wake closure: count the delivery and write one
/// byte to [`WAKE_FD`], making the retried `poll` observe `POLLIN`.
extern "C" fn wake_handler(_signum: i32) {
    // SAFETY: single-threaded test process; the statics outlive the handler.
    unsafe {
        let counter = core::ptr::addr_of!(WAKE_WRITES);
        core::ptr::addr_of_mut!(WAKE_WRITES).write_volatile(counter.read_volatile() + 1);
        let fd = core::ptr::addr_of!(WAKE_FD).read_volatile();
        let _ = write_fd(fd as i64, core::ptr::addr_of!(WAKE_BYTE) as u64, 1);
    }
}

/// Number of wake-handler deliveries so far (test-only static).
fn wake_writes() -> u64 {
    // SAFETY: single-threaded test process; no concurrent writer.
    unsafe { core::ptr::addr_of!(WAKE_WRITES).read_volatile() }
}

/// Reset the wake-handler delivery counter before a deterministic step.
fn reset_wake_writes() {
    // SAFETY: single-threaded test process; the handler has not run yet.
    unsafe { core::ptr::addr_of_mut!(WAKE_WRITES).write_volatile(0) }
}

/// Fill one `struct pollfd` entry at `offset`.
fn pollfd_set(offset: usize, fd: i64, events: u16) {
    put_u32_le(offset, fd as u32);
    put_u16_ne(offset + 4, events);
    put_u16_ne(offset + 6, 0);
}

/// `revents` of the `struct pollfd` entry at `offset`.
fn pollfd_revents(offset: usize) -> u16 {
    get_u16_ne(offset + 6)
}

/// Whole milliseconds between two monotonic samples (must not go backwards).
fn elapsed_ms(stage: u32, step: u32, start_ns: i64, end_ns: i64) -> i64 {
    check(stage, step, end_ns >= start_ns);
    (end_ns - start_ns) / 1_000_000
}

/// M8g eventfd closure: 8-byte counter semantics (write adds, read resets),
/// `EFD_NONBLOCK`/`EFD_CLOEXEC`, `dup` sharing and close/`EBADF`.
fn suite_m8g_eventfd() {
    let stage = STAGE_EVENTFD;

    // step 1: a non-blocking eventfd starts with a zero counter.
    let event = expect_ok(stage, 1, eventfd2(0, EFD_NONBLOCK));
    check(stage, 1, event >= 3);

    // step 2: reading an empty non-blocking eventfd is EAGAIN, not a block.
    expect_errno(
        stage,
        2,
        read_fd(event, arena(OFF_EVENT_VALUE) as u64, 8),
        EAGAIN,
    );

    // step 3: writing 5 writes exactly 8 bytes and the read consumes that
    // counter (a read resets it to zero).
    put_u64_ne(OFF_EVENT_VALUE, 5);
    expect_value(
        stage,
        3,
        write_fd(event, arena(OFF_EVENT_VALUE) as u64, 8),
        8,
    );
    expect_value(
        stage,
        3,
        read_fd(event, arena(OFF_EVENT_VALUE) as u64, 8),
        8,
    );
    expect_value(stage, 3, get_u64_ne(OFF_EVENT_VALUE) as i64, 5);

    // step 4: the counter is zero again, so a non-blocking read is EAGAIN.
    expect_errno(
        stage,
        4,
        read_fd(event, arena(OFF_EVENT_VALUE) as u64, 8),
        EAGAIN,
    );

    // step 5: consecutive writes accumulate (3 + 4 reads back as 7).
    put_u64_ne(OFF_EVENT_VALUE, 3);
    expect_value(
        stage,
        5,
        write_fd(event, arena(OFF_EVENT_VALUE) as u64, 8),
        8,
    );
    put_u64_ne(OFF_EVENT_VALUE, 4);
    expect_value(
        stage,
        5,
        write_fd(event, arena(OFF_EVENT_VALUE) as u64, 8),
        8,
    );
    expect_value(
        stage,
        5,
        read_fd(event, arena(OFF_EVENT_VALUE) as u64, 8),
        8,
    );
    expect_value(stage, 5, get_u64_ne(OFF_EVENT_VALUE) as i64, 7);

    // step 6: `dup` shares the counter object, so a write through the original
    // fd is readable through the duplicate.
    let duplicate = expect_ok(stage, 6, dup(event));
    check(stage, 6, duplicate > event);
    put_u64_ne(OFF_EVENT_VALUE, 2);
    expect_value(
        stage,
        6,
        write_fd(event, arena(OFF_EVENT_VALUE) as u64, 8),
        8,
    );
    expect_value(
        stage,
        6,
        read_fd(duplicate, arena(OFF_EVENT_VALUE) as u64, 8),
        8,
    );
    expect_value(stage, 6, get_u64_ne(OFF_EVENT_VALUE) as i64, 2);

    // step 7: closing the duplicate leaves the original usable, and closing the
    // original makes further reads fail with EBADF.
    expect_ok(stage, 7, close(duplicate));
    put_u64_ne(OFF_EVENT_VALUE, 1);
    expect_value(
        stage,
        7,
        write_fd(event, arena(OFF_EVENT_VALUE) as u64, 8),
        8,
    );
    expect_value(
        stage,
        7,
        read_fd(event, arena(OFF_EVENT_VALUE) as u64, 8),
        8,
    );
    expect_value(stage, 7, get_u64_ne(OFF_EVENT_VALUE) as i64, 1);
    expect_ok(stage, 7, close(event));
    expect_errno(
        stage,
        7,
        read_fd(event, arena(OFF_EVENT_VALUE) as u64, 8),
        EBADF,
    );

    // step 8: `EFD_CLOEXEC` is visible through `F_GETFD`.
    let cloexec = expect_ok(stage, 8, eventfd2(0, EFD_NONBLOCK | EFD_CLOEXEC));
    check(stage, 8, cloexec >= 3);
    expect_value(stage, 8, fcntl(cloexec, F_GETFD, 0), FD_CLOEXEC as i64);
    expect_ok(stage, 8, close(cloexec));
}

/// M8g poll closure: readiness/timeout/array semantics, `ppoll` relative
/// `timespec`, and a signal wake-up of an infinite `poll` (pending SIGUSR1 ->
/// EINTR; the handler writes the peer end so the retried poll is ready).
fn suite_m8g_poll() {
    let stage = STAGE_POLL;

    // steps 1-2: one UNIX stream socketpair; both endpoints are pollable.
    let (polled, peer) = socket_pair(stage, 1, AF_UNIX, SOCK_STREAM);

    // step 3: timeout 0 with nothing queued reports no events.
    pollfd_set(OFF_POLLFD, polled, POLLIN);
    expect_value(stage, 3, poll(arena(OFF_POLLFD) as u64, 1, 0), 0);
    expect_value(stage, 3, pollfd_revents(OFF_POLLFD) as i64, 0);

    // step 4: a queued byte makes the read end readable.
    put_u8(OFF_TX, b'w');
    expect_value(stage, 4, write_fd(peer, arena(OFF_TX) as u64, 1), 1);
    expect_value(stage, 4, poll(arena(OFF_POLLFD) as u64, 1, 0), 1);
    check(stage, 4, pollfd_revents(OFF_POLLFD) & POLLIN != 0);

    // step 5: consuming the byte clears readiness.
    expect_value(stage, 5, read_fd(polled, arena(OFF_RX) as u64, 1), 1);
    expect_value(stage, 5, poll(arena(OFF_POLLFD) as u64, 1, 0), 0);

    // step 6: the same fd is writable while the peer stays open.
    pollfd_set(OFF_POLLFD, polled, POLLOUT);
    expect_value(stage, 6, poll(arena(OFF_POLLFD) as u64, 1, 0), 1);
    check(stage, 6, pollfd_revents(OFF_POLLFD) & POLLOUT != 0);

    // step 7: two entries are reported independently: only the fd with queued
    // data is ready, the peer end has nothing to read.
    pollfd_set(OFF_POLLFD, polled, POLLIN);
    pollfd_set(OFF_POLLFD + POLLFD_BYTES, peer, POLLIN);
    expect_value(stage, 7, write_fd(peer, arena(OFF_TX) as u64, 1), 1);
    expect_value(stage, 7, poll(arena(OFF_POLLFD) as u64, 2, 0), 1);
    check(stage, 7, pollfd_revents(OFF_POLLFD) & POLLIN != 0);
    expect_value(
        stage,
        7,
        pollfd_revents(OFF_POLLFD + POLLFD_BYTES) as i64,
        0,
    );
    expect_value(stage, 8, read_fd(polled, arena(OFF_RX) as u64, 1), 1);

    // step 9: the short relative timeout expires without events.
    pollfd_set(OFF_POLLFD, polled, POLLIN);
    let start = read_clock_ns(stage, 9, CLOCK_MONOTONIC);
    expect_value(
        stage,
        9,
        poll(arena(OFF_POLLFD) as u64, 1, M8G_TIMEOUT_MS),
        0,
    );
    let elapsed = elapsed_ms(stage, 9, start, read_clock_ns(stage, 9, CLOCK_MONOTONIC));
    check(stage, 9, elapsed >= 10);

    // step 10: an infinite timeout returns immediately when data is ready.
    expect_value(stage, 10, write_fd(peer, arena(OFF_TX) as u64, 1), 1);
    expect_value(stage, 10, poll(arena(OFF_POLLFD) as u64, 1, -1), 1);
    check(stage, 10, pollfd_revents(OFF_POLLFD) & POLLIN != 0);
    expect_value(stage, 11, read_fd(polled, arena(OFF_RX) as u64, 1), 1);

    // step 12: block SIGUSR1 and raise it: the signal stays pending (the handler
    // has not run, the peer end stays empty). A blocking `ppoll` with a temporary
    // empty mask (SIGUSR1 unblocked for the wait) then receives that pending
    // signal: the syscall returns -EINTR and the handler writes the peer end.
    let wake: extern "C" fn(i32) = wake_handler;
    let wake_action = signal_action(wake as usize);
    expect_ok(
        stage,
        12,
        rt_sigaction(SIGUSR1, &wake_action as *const KernelSigaction as u64, 0),
    );
    // SAFETY: single-threaded test process; the handler runs on this process.
    unsafe {
        core::ptr::addr_of_mut!(WAKE_FD).write_volatile(peer as u64);
    }
    reset_wake_writes();
    put_u64_ne(OFF_SIGSET_BLOCK, signal_bit(SIGUSR1));
    expect_ok(
        stage,
        12,
        rt_sigprocmask(SIG_BLOCK, arena(OFF_SIGSET_BLOCK) as u64, 0),
    );
    expect_value(stage, 12, kill(getpid(), SIGUSR1), 0);
    expect_value(stage, 12, wake_writes() as i64, 0);
    pollfd_set(OFF_POLLFD, polled, POLLIN);
    expect_value(stage, 12, poll(arena(OFF_POLLFD) as u64, 1, 0), 0);
    // A one-second relative timeout bounds the wait if the kernel fails to
    // deliver the pending signal; the expected result is an immediate EINTR.
    put_u64_ne(OFF_SIGSET_EMPTY, 0);
    put_u64_ne(OFF_POLL_TS, 1);
    put_u64_ne(OFF_POLL_TS + 8, 0);
    expect_errno(
        stage,
        12,
        ppoll(
            arena(OFF_POLLFD) as u64,
            1,
            arena(OFF_POLL_TS) as u64,
            arena(OFF_SIGSET_EMPTY) as u64,
        ),
        EINTR,
    );
    expect_value(stage, 12, wake_writes() as i64, 1);

    // step 13: the handler wrote `WAKE_BYTE` to the peer end, so the retried
    // infinite poll observes POLLIN and the byte read back is 'w'.
    expect_value(stage, 13, poll(arena(OFF_POLLFD) as u64, 1, -1), 1);
    check(stage, 13, pollfd_revents(OFF_POLLFD) & POLLIN != 0);
    expect_value(stage, 13, read_fd(polled, arena(OFF_RX) as u64, 1), 1);
    expect_value(stage, 13, get_u8(OFF_RX) as i64, i64::from(b'w'));

    // step 14: `ppoll` with a relative timespec expires without events.
    put_u64_ne(OFF_POLL_TS, 0);
    put_u64_ne(OFF_POLL_TS + 8, (M8G_TIMEOUT_MS as u64) * 1_000_000);
    let start = read_clock_ns(stage, 14, CLOCK_MONOTONIC);
    expect_value(
        stage,
        14,
        ppoll(arena(OFF_POLLFD) as u64, 1, arena(OFF_POLL_TS) as u64, 0),
        0,
    );
    let elapsed = elapsed_ms(stage, 14, start, read_clock_ns(stage, 14, CLOCK_MONOTONIC));
    check(stage, 14, elapsed >= 10);

    // step 15: a NULL timespec means infinite; readiness returns immediately.
    expect_value(stage, 15, write_fd(peer, arena(OFF_TX) as u64, 1), 1);
    expect_value(stage, 15, ppoll(arena(OFF_POLLFD) as u64, 1, 0, 0), 1);
    check(stage, 15, pollfd_revents(OFF_POLLFD) & POLLIN != 0);
    expect_value(stage, 16, read_fd(polled, arena(OFF_RX) as u64, 1), 1);

    // step 16: close both endpoints.
    expect_ok(stage, 16, close(polled));
    expect_ok(stage, 16, close(peer));
}

// ---------------------------------------------------------------------------
// M8h: procfs and devfs views.
// ---------------------------------------------------------------------------

/// Read a whole small text file into the arena and return its length.
fn read_text_file(path: &[u8], offset: usize, capacity: usize, stage: u32, step: u32) -> usize {
    let fd = expect_ok(stage, step, openat_at(AT_FDCWD, path, O_RDONLY, 0));
    let length = expect_ok(
        stage,
        step,
        read_fd(fd, arena(offset) as u64, capacity as u64),
    );
    expect_ok(stage, step, close(fd));
    length as usize
}

/// `statx` an absolute path with `STATX_BASIC_STATS`.
fn statx_path(path: &[u8], stage: u32, step: u32) -> Statx {
    let mut result = Statx::zeroed();
    expect_ok(
        stage,
        step,
        statx(AT_FDCWD, path, 0, STATX_BASIC_STATS, &mut result),
    );
    result
}

/// Walk a directory and report whether `wanted` is among its entries.
fn dir_entries_contain(
    directory: &[u8],
    wanted: &[u8],
    wanted_type: u8,
    stage: u32,
    step: u32,
) -> bool {
    let fd = expect_ok(stage, step, openat_at(AT_FDCWD, directory, O_DIRECTORY, 0));
    let mut found = false;
    let mut calls = 0usize;
    loop {
        let count = expect_ok(
            stage,
            step,
            getdents64(fd, arena(OFF_DIR_BUF) as u64, OFF_DIR_BUF_SIZE as u64),
        );
        calls += 1;
        check(stage, step, calls <= 16);
        check(stage, step, count >= 0);
        if count == 0 {
            break;
        }
        if scan_dirents(
            OFF_DIR_BUF,
            count as usize,
            wanted,
            wanted_type,
            stage,
            step,
        ) {
            found = true;
        }
    }
    expect_ok(stage, step, close(fd));
    found
}

/// Whether the text window contains a line starting with `prefix`.
fn text_has_line_prefix(offset: usize, length: usize, prefix: &[u8]) -> bool {
    let mut cursor = 0usize;
    while cursor + prefix.len() <= length {
        if arena_eq(offset + cursor, prefix) {
            return true;
        }
        let mut next = cursor;
        while next < length && get_u8(offset + next) != b'\n' {
            next += 1;
        }
        cursor = next + 1;
    }
    false
}

/// Parse the first decimal number on the line starting with `prefix`.
fn line_value_u64(offset: usize, length: usize, prefix: &[u8]) -> Option<u64> {
    let mut cursor = 0usize;
    while cursor + prefix.len() <= length {
        if arena_eq(offset + cursor, prefix) {
            let mut index = cursor + prefix.len();
            while index < length && matches!(get_u8(offset + index), b' ' | b'\t') {
                index += 1;
            }
            let mut value = 0u64;
            let mut digits = 0usize;
            while index < length {
                let byte = get_u8(offset + index);
                if !byte.is_ascii_digit() {
                    break;
                }
                value = value * 10 + u64::from(byte - b'0');
                digits += 1;
                index += 1;
                if digits > 18 {
                    return None;
                }
            }
            return if digits == 0 { None } else { Some(value) };
        }
        let mut next = cursor;
        while next < length && get_u8(offset + next) != b'\n' {
            next += 1;
        }
        cursor = next + 1;
    }
    None
}

/// Whether the `Uid:` status line lists four zero ids.
fn status_uid_all_zero(offset: usize, length: usize) -> bool {
    const PREFIX: &[u8] = b"Uid:";
    let mut cursor = 0usize;
    while cursor + PREFIX.len() <= length {
        if arena_eq(offset + cursor, PREFIX) {
            let mut index = cursor + PREFIX.len();
            let mut fields = 0usize;
            while fields < 4 {
                while index < length && matches!(get_u8(offset + index), b' ' | b'\t') {
                    index += 1;
                }
                let start = index;
                let mut value = 0u64;
                while index < length {
                    let byte = get_u8(offset + index);
                    if !byte.is_ascii_digit() {
                        break;
                    }
                    value = value * 10 + u64::from(byte - b'0');
                    index += 1;
                }
                if index == start || value != 0 {
                    return false;
                }
                fields += 1;
            }
            return true;
        }
        let mut next = cursor;
        while next < length && get_u8(offset + next) != b'\n' {
            next += 1;
        }
        cursor = next + 1;
    }
    false
}

/// Parse the `<sec>.<cc>` first field of `/proc/uptime` as centiseconds.
fn uptime_centis(offset: usize, length: usize) -> Option<u64> {
    let mut index = 0usize;
    let mut seconds = 0u64;
    let mut digits = 0usize;
    while index < length {
        let byte = get_u8(offset + index);
        if !byte.is_ascii_digit() {
            break;
        }
        seconds = seconds * 10 + u64::from(byte - b'0');
        digits += 1;
        index += 1;
        if digits > 12 {
            return None;
        }
    }
    if digits == 0 || index + 3 > length || get_u8(offset + index) != b'.' {
        return None;
    }
    let high = get_u8(offset + index + 1);
    let low = get_u8(offset + index + 2);
    if !high.is_ascii_digit() || !low.is_ascii_digit() {
        return None;
    }
    let hundredths = u64::from(high - b'0') * 10 + u64::from(low - b'0');
    Some(seconds * 100 + hundredths)
}

/// Whether every byte in the window is zero.
fn all_zero(offset: usize, length: usize) -> bool {
    let mut index = 0usize;
    while index < length {
        if get_u8(offset + index) != 0 {
            return false;
        }
        index += 1;
    }
    true
}

/// M8h procfs closure: listings, `/proc/self/status` and `/proc/uptime`.
fn suite_m8h_procfs() {
    let stage = STAGE_PROCFS;

    // step 1: `/proc` itself is a directory.
    let proc_entry = statx_path(M8H_PROC_PATH, stage, 1);
    check(stage, 1, u32::from(proc_entry.mode) & S_IFMT == S_IFDIR);

    // step 2: `/proc/self` follows the magic link and is a directory.
    let self_entry = statx_path(M8H_PROC_SELF_PATH, stage, 2);
    check(stage, 2, u32::from(self_entry.mode) & S_IFMT == S_IFDIR);

    // step 3: `/proc` lists `self`.
    check(
        stage,
        3,
        dir_entries_contain(M8H_PROC_PATH, M8H_SELF_NAME, DT_UNKNOWN, stage, 3),
    );

    // step 4: `/proc` lists `uptime`.
    check(
        stage,
        4,
        dir_entries_contain(M8H_PROC_PATH, M8H_UPTIME_NAME, DT_UNKNOWN, stage, 4),
    );

    // step 5: `/proc/self` lists `status`.
    check(
        stage,
        5,
        dir_entries_contain(M8H_PROC_SELF_PATH, M8H_STATUS_NAME, DT_UNKNOWN, stage, 5),
    );

    // step 6: `/proc/self/status` is a size-zero regular file.
    let status = statx_path(M8H_PROC_STATUS_PATH, stage, 6);
    check(stage, 6, u32::from(status.mode) & S_IFMT == S_IFREG);
    expect_value(stage, 6, status.size as i64, 0);
    check(stage, 6, status.links >= 1);

    // step 7: the status text carries the four anchor lines.
    let length = read_text_file(
        M8H_PROC_STATUS_PATH,
        OFF_PROC_TEXT,
        OFF_PROC_TEXT_SIZE,
        stage,
        7,
    );
    check(stage, 7, length > 0);
    check(
        stage,
        7,
        text_has_line_prefix(OFF_PROC_TEXT, length, b"Name:"),
    );
    check(
        stage,
        7,
        text_has_line_prefix(OFF_PROC_TEXT, length, b"Pid:"),
    );
    check(
        stage,
        7,
        text_has_line_prefix(OFF_PROC_TEXT, length, b"PPid:"),
    );
    check(
        stage,
        7,
        text_has_line_prefix(OFF_PROC_TEXT, length, b"Uid:"),
    );

    // step 8: Pid / PPid / Uid report this process' real identity.
    check(
        stage,
        8,
        line_value_u64(OFF_PROC_TEXT, length, b"Pid:") == Some(getpid() as u64),
    );
    check(
        stage,
        8,
        line_value_u64(OFF_PROC_TEXT, length, b"PPid:") == Some(getppid() as u64),
    );
    check(stage, 8, status_uid_all_zero(OFF_PROC_TEXT, length));

    // step 9: `/proc/uptime` is a size-zero regular file.
    let uptime = statx_path(M8H_PROC_UPTIME_PATH, stage, 9);
    check(stage, 9, u32::from(uptime.mode) & S_IFMT == S_IFREG);
    expect_value(stage, 9, uptime.size as i64, 0);

    // step 10: two samples 50 ms apart never go backwards.
    let first_length = read_text_file(
        M8H_PROC_UPTIME_PATH,
        OFF_UPTIME_TEXT,
        OFF_UPTIME_TEXT_SIZE,
        stage,
        10,
    );
    let first = uptime_centis(OFF_UPTIME_TEXT, first_length);
    check(stage, 10, first.is_some());
    let mut remaining = Timespec::zeroed();
    let request = Timespec {
        seconds: 0,
        nanoseconds: M8H_UPTIME_GAP_NS as i64,
    };
    expect_ok(
        stage,
        10,
        clock_nanosleep(CLOCK_MONOTONIC, 0, &request, &mut remaining),
    );
    let second_length = read_text_file(
        M8H_PROC_UPTIME_PATH,
        OFF_UPTIME_TEXT,
        OFF_UPTIME_TEXT_SIZE,
        stage,
        10,
    );
    let second = uptime_centis(OFF_UPTIME_TEXT, second_length);
    check(stage, 10, second.is_some());
    check(
        stage,
        10,
        matches!((first, second), (Some(earlier), Some(later)) if later >= earlier),
    );
}

/// M8h devfs closure: listings, `/dev/null` and `/dev/zero`.
fn suite_m8h_devfs() {
    let stage = STAGE_DEVFILES;

    // step 1: `/dev` is a directory.
    let dev = statx_path(M8H_DEV_PATH, stage, 1);
    check(stage, 1, u32::from(dev.mode) & S_IFMT == S_IFDIR);

    // step 2: the listing contains `/dev/null`.
    check(
        stage,
        2,
        dir_entries_contain(M8H_DEV_PATH, M8H_NULL_NAME, DT_CHR, stage, 2),
    );

    // step 3: the listing contains `/dev/zero`.
    check(
        stage,
        3,
        dir_entries_contain(M8H_DEV_PATH, M8H_ZERO_NAME, DT_CHR, stage, 3),
    );

    // step 4: `/dev/null` is the (1,3) character device.
    let null = statx_path(M8H_DEV_NULL_PATH, stage, 4);
    check(stage, 4, u32::from(null.mode) & S_IFMT == S_IFCHR);
    expect_value(
        stage,
        4,
        null.rdevice_major as i64,
        i64::from(M8H_NULL_MAJOR),
    );
    expect_value(
        stage,
        4,
        null.rdevice_minor as i64,
        i64::from(M8H_NULL_MINOR),
    );

    // step 5: `/dev/null` accepts every byte (including an empty write).
    let null_fd = expect_ok(stage, 5, openat_at(AT_FDCWD, M8H_DEV_NULL_PATH, O_RDWR, 0));
    fill_pattern(OFF_DEV_BUF, 8, 0x71);
    expect_value(stage, 5, write_fd(null_fd, arena(OFF_DEV_BUF) as u64, 8), 8);
    expect_value(stage, 5, write_fd(null_fd, arena(OFF_DEV_BUF) as u64, 0), 0);

    // step 6: `/dev/null` reads back nothing.
    expect_value(stage, 6, read_fd(null_fd, arena(OFF_DEV_BUF) as u64, 8), 0);
    expect_ok(stage, 6, close(null_fd));

    // step 7: `/dev/zero` is the (1,5) character device.
    let zero = statx_path(M8H_DEV_ZERO_PATH, stage, 7);
    check(stage, 7, u32::from(zero.mode) & S_IFMT == S_IFCHR);
    expect_value(
        stage,
        7,
        zero.rdevice_major as i64,
        i64::from(M8H_ZERO_MAJOR),
    );
    expect_value(
        stage,
        7,
        zero.rdevice_minor as i64,
        i64::from(M8H_ZERO_MINOR),
    );

    // step 8: every `/dev/zero` read yields zeroed bytes.
    let zero_fd = expect_ok(
        stage,
        8,
        openat_at(AT_FDCWD, M8H_DEV_ZERO_PATH, O_RDONLY, 0),
    );
    fill_pattern(OFF_DEV_BUF, 64, 0x5a);
    expect_value(
        stage,
        8,
        read_fd(zero_fd, arena(OFF_DEV_BUF) as u64, 64),
        64,
    );
    check(stage, 8, all_zero(OFF_DEV_BUF, 64));
    fill_pattern(OFF_DEV_BUF, 64, 0x5b);
    expect_value(
        stage,
        8,
        read_fd(zero_fd, arena(OFF_DEV_BUF) as u64, 64),
        64,
    );
    check(stage, 8, all_zero(OFF_DEV_BUF, 64));
    expect_ok(stage, 8, close(zero_fd));
}

// ---------------------------------------------------------------------------
// M9a: timerfd, signalfd and epoll level-triggered readiness.
// ---------------------------------------------------------------------------

/// Linux `struct itimerspec` (x86-64): two 16-byte `timespec` fields, 32 bytes.
#[repr(C)]
struct Itimerspec {
    interval_seconds: i64,
    interval_nanoseconds: i64,
    value_seconds: i64,
    value_nanoseconds: i64,
}

impl Itimerspec {
    const fn zeroed() -> Self {
        Self {
            interval_seconds: 0,
            interval_nanoseconds: 0,
            value_seconds: 0,
            value_nanoseconds: 0,
        }
    }

    const fn relative(nanoseconds: i64) -> Self {
        Self {
            interval_seconds: 0,
            interval_nanoseconds: 0,
            value_seconds: 0,
            value_nanoseconds: nanoseconds,
        }
    }

    const fn periodic(first_nanoseconds: i64, period_nanoseconds: i64) -> Self {
        Self {
            interval_seconds: 0,
            interval_nanoseconds: period_nanoseconds,
            value_seconds: 0,
            value_nanoseconds: first_nanoseconds,
        }
    }
}

const _: () = assert!(core::mem::size_of::<Itimerspec>() == 32);

fn put_itimerspec(offset: usize, value: &Itimerspec) {
    put_u64_ne(offset, value.interval_seconds as u64);
    put_u64_ne(offset + 8, value.interval_nanoseconds as u64);
    put_u64_ne(offset + 16, value.value_seconds as u64);
    put_u64_ne(offset + 24, value.value_nanoseconds as u64);
}

fn itimerspec_interval_ns(offset: usize) -> i64 {
    get_u64_ne(offset) as i64 * NSEC_PER_SEC + get_u64_ne(offset + 8) as i64
}

fn itimerspec_value_ns(offset: usize) -> i64 {
    get_u64_ne(offset + 16) as i64 * NSEC_PER_SEC + get_u64_ne(offset + 24) as i64
}

/// Relative `clock_nanosleep` on the monotonic clock; the remaining time is
/// not used by the M9a suites.
fn sleep_ns(nanoseconds: i64) {
    let mut remaining = Timespec::zeroed();
    let request = Timespec {
        seconds: 0,
        nanoseconds,
    };
    let _ = clock_nanosleep(CLOCK_MONOTONIC, 0, &request, &mut remaining);
}

/// Write one packed 12-byte `epoll_event`: `events` at +0, `data` at +4.
fn epoll_event_write(offset: usize, events: u32, data: u64) {
    put_u32_le(offset, events);
    put_u64_ne(offset + 4, data);
}

fn epoll_event_events(offset: usize) -> u32 {
    get_u32_le(offset)
}

fn epoll_event_data(offset: usize) -> u64 {
    get_u64_ne(offset + 4)
}

fn suite_m9a_timerfd() {
    let stage = STAGE_M9A_TIMERFD;

    // step 1: a non-blocking monotonic timer starts disarmed.
    let timer = expect_ok(stage, 1, timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK));
    check(stage, 1, timer > 0);
    expect_ok(
        stage,
        1,
        timerfd_gettime(timer, arena(OFF_TIMER_NOW) as u64),
    );
    expect_value(stage, 1, itimerspec_value_ns(OFF_TIMER_NOW), 0);
    expect_value(stage, 1, itimerspec_interval_ns(OFF_TIMER_NOW), 0);

    // step 2: one relative expiry after 30 ms; the counter reads >= 1.
    let first = Itimerspec::relative(M9A_TIMER_FIRST_NS);
    put_itimerspec(OFF_TIMER_SPEC, &first);
    expect_ok(
        stage,
        2,
        timerfd_settime(timer, 0, arena(OFF_TIMER_SPEC) as u64, 0),
    );
    sleep_ns(M9A_TIMER_SLEEP_NS);
    expect_value(stage, 2, read_fd(timer, arena(OFF_TIMER_READ) as u64, 8), 8);
    check(stage, 2, get_u64_ne(OFF_TIMER_READ) >= 1);

    // step 3: a 30 ms periodic timer delivers at least two expirations in 90 ms.
    let periodic = Itimerspec::periodic(M9A_TIMER_PERIOD_NS, M9A_TIMER_PERIOD_NS);
    put_itimerspec(OFF_TIMER_SPEC, &periodic);
    expect_ok(
        stage,
        3,
        timerfd_settime(timer, 0, arena(OFF_TIMER_SPEC) as u64, 0),
    );
    sleep_ns(M9A_TIMER_PERIOD_SLEEP_NS);
    expect_value(stage, 3, read_fd(timer, arena(OFF_TIMER_READ) as u64, 8), 8);
    check(stage, 3, get_u64_ne(OFF_TIMER_READ) >= 2);
    expect_ok(
        stage,
        3,
        timerfd_gettime(timer, arena(OFF_TIMER_NOW) as u64),
    );
    expect_value(
        stage,
        3,
        itimerspec_interval_ns(OFF_TIMER_NOW),
        M9A_TIMER_PERIOD_NS,
    );
    let remaining = itimerspec_value_ns(OFF_TIMER_NOW);
    check(stage, 3, (0..=M9A_TIMER_PERIOD_NS).contains(&remaining));

    // step 4: a zero spec disarms; the next non-blocking read reports EAGAIN.
    let zero = Itimerspec::zeroed();
    put_itimerspec(OFF_TIMER_SPEC, &zero);
    expect_ok(
        stage,
        4,
        timerfd_settime(timer, 0, arena(OFF_TIMER_SPEC) as u64, 0),
    );
    expect_ok(
        stage,
        4,
        timerfd_gettime(timer, arena(OFF_TIMER_NOW) as u64),
    );
    expect_value(stage, 4, itimerspec_value_ns(OFF_TIMER_NOW), 0);
    expect_value(stage, 4, itimerspec_interval_ns(OFF_TIMER_NOW), 0);
    expect_errno(
        stage,
        4,
        read_fd(timer, arena(OFF_TIMER_READ) as u64, 8),
        EAGAIN,
    );

    // step 5: close.
    expect_ok(stage, 5, close(timer));
}

fn suite_m9a_signalfd() {
    let stage = STAGE_M9A_SIGNALFD;

    // step 1: block SIGWINCH and remember the previous mask.
    put_u64_ne(OFF_SIGSET_FD, 1u64 << (SIGWINCH - 1));
    expect_ok(
        stage,
        1,
        rt_sigprocmask(
            SIG_BLOCK,
            arena(OFF_SIGSET_FD) as u64,
            arena(OFF_SIGSET_OLD) as u64,
        ),
    );

    // step 2: create a non-blocking signalfd for that set.
    let sfd = expect_ok(
        stage,
        2,
        signalfd4(-1, arena(OFF_SIGSET_FD) as u64, SIGSET_BYTES, SFD_NONBLOCK),
    );
    check(stage, 2, sfd > 0);

    // step 3: a blocked self-signal becomes readable and reports its signo.
    expect_ok(stage, 3, kill(getpid(), SIGWINCH));
    expect_value(
        stage,
        3,
        read_fd(sfd, arena(OFF_SFD_INFO) as u64, SIGINFO_BYTES),
        SIGINFO_BYTES as i64,
    );
    expect_value(
        stage,
        3,
        u64::from(get_u32_le(OFF_SFD_INFO)) as i64,
        SIGWINCH as i64,
    );

    // step 4: the pending queue is empty again.
    expect_errno(
        stage,
        4,
        read_fd(sfd, arena(OFF_SFD_INFO) as u64, SIGINFO_BYTES),
        EAGAIN,
    );

    // step 5: close and restore the previous mask.
    expect_ok(stage, 5, close(sfd));
    expect_ok(
        stage,
        5,
        rt_sigprocmask(SIG_SETMASK, arena(OFF_SIGSET_OLD) as u64, 0),
    );
}

fn suite_m9a_epoll() {
    let stage = STAGE_M9A_EPOLL;

    // step 1: create an epoll instance.
    let epfd = expect_ok(stage, 1, epoll_create1(0));
    check(stage, 1, epfd > 0);

    // step 2: an eventfd registered for EPOLLIN is idle while its counter is 0.
    let efd = expect_ok(stage, 2, eventfd2(0, EFD_NONBLOCK));
    check(stage, 2, efd > 0);
    epoll_event_write(OFF_EPOLL_EVENT, EPOLLIN, 0xE1);
    expect_ok(
        stage,
        2,
        epoll_ctl(epfd, EPOLL_CTL_ADD, efd, arena(OFF_EPOLL_EVENT) as u64),
    );
    expect_value(
        stage,
        2,
        epoll_wait(epfd, arena(OFF_EPOLL_EVENTS) as u64, EPOLL_MAX_EVENTS, 0),
        0,
    );

    // step 3: writing makes it readable; draining silences level-triggered mode.
    put_u64_ne(OFF_EVENT_VALUE, 4);
    expect_value(stage, 3, write_fd(efd, arena(OFF_EVENT_VALUE) as u64, 8), 8);
    expect_value(
        stage,
        3,
        epoll_wait(epfd, arena(OFF_EPOLL_EVENTS) as u64, EPOLL_MAX_EVENTS, 0),
        1,
    );
    check(
        stage,
        3,
        epoll_event_events(OFF_EPOLL_EVENTS) & EPOLLIN != 0,
    );
    expect_value(stage, 3, epoll_event_data(OFF_EPOLL_EVENTS) as i64, 0xE1);
    expect_value(stage, 3, read_fd(efd, arena(OFF_EVENT_VALUE) as u64, 8), 8);
    expect_value(
        stage,
        3,
        epoll_wait(epfd, arena(OFF_EPOLL_EVENTS) as u64, EPOLL_MAX_EVENTS, 0),
        0,
    );

    // step 4: MOD changes the interest; the event carries the new data token.
    epoll_event_write(OFF_EPOLL_EVENT, EPOLLOUT, 0xE4);
    expect_ok(
        stage,
        4,
        epoll_ctl(epfd, EPOLL_CTL_MOD, efd, arena(OFF_EPOLL_EVENT) as u64),
    );
    expect_value(
        stage,
        4,
        epoll_wait(epfd, arena(OFF_EPOLL_EVENTS) as u64, EPOLL_MAX_EVENTS, 0),
        1,
    );
    check(
        stage,
        4,
        epoll_event_events(OFF_EPOLL_EVENTS) & EPOLLOUT != 0,
    );
    expect_value(stage, 4, epoll_event_data(OFF_EPOLL_EVENTS) as i64, 0xE4);
    epoll_event_write(OFF_EPOLL_EVENT, EPOLLIN, 0xE1);
    expect_ok(
        stage,
        4,
        epoll_ctl(epfd, EPOLL_CTL_MOD, efd, arena(OFF_EPOLL_EVENT) as u64),
    );

    // step 5: a socketpair endpoint becomes readable when the peer writes.
    expect_ok(
        stage,
        5,
        socketpair_raw(AF_UNIX, SOCK_STREAM, arena(OFF_ADDR_A) as u64),
    );
    let socket_a = get_u32_le(OFF_ADDR_A) as i64;
    let socket_b = get_u32_le(OFF_ADDR_A + 4) as i64;
    epoll_event_write(OFF_EPOLL_EVENT, EPOLLIN, 0xE2);
    expect_ok(
        stage,
        5,
        epoll_ctl(epfd, EPOLL_CTL_ADD, socket_a, arena(OFF_EPOLL_EVENT) as u64),
    );
    expect_value(
        stage,
        5,
        epoll_wait(epfd, arena(OFF_EPOLL_EVENTS) as u64, EPOLL_MAX_EVENTS, 0),
        0,
    );
    fill_pattern(OFF_TX, 4, 0x21);
    expect_value(stage, 5, write_fd(socket_b, arena(OFF_TX) as u64, 4), 4);
    expect_value(
        stage,
        5,
        epoll_wait(epfd, arena(OFF_EPOLL_EVENTS) as u64, EPOLL_MAX_EVENTS, 0),
        1,
    );
    expect_value(stage, 5, epoll_event_data(OFF_EPOLL_EVENTS) as i64, 0xE2);
    expect_value(stage, 5, read_fd(socket_a, arena(OFF_RX) as u64, 4), 4);
    expect_value(
        stage,
        5,
        epoll_wait(epfd, arena(OFF_EPOLL_EVENTS) as u64, EPOLL_MAX_EVENTS, 0),
        0,
    );

    // step 6: an armed timerfd becomes readable within the bounded wait.
    let tfd = expect_ok(stage, 6, timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK));
    let one = Itimerspec::relative(M9A_TIMER_FIRST_NS);
    put_itimerspec(OFF_TIMER_SPEC, &one);
    expect_ok(
        stage,
        6,
        timerfd_settime(tfd, 0, arena(OFF_TIMER_SPEC) as u64, 0),
    );
    epoll_event_write(OFF_EPOLL_EVENT, EPOLLIN, 0xE3);
    expect_ok(
        stage,
        6,
        epoll_ctl(epfd, EPOLL_CTL_ADD, tfd, arena(OFF_EPOLL_EVENT) as u64),
    );
    expect_value(
        stage,
        6,
        epoll_wait(epfd, arena(OFF_EPOLL_EVENTS) as u64, EPOLL_MAX_EVENTS, 0),
        0,
    );
    expect_value(
        stage,
        6,
        epoll_wait(
            epfd,
            arena(OFF_EPOLL_EVENTS) as u64,
            EPOLL_MAX_EVENTS,
            M9A_WAIT_MS,
        ),
        1,
    );
    expect_value(stage, 6, epoll_event_data(OFF_EPOLL_EVENTS) as i64, 0xE3);
    expect_value(stage, 6, read_fd(tfd, arena(OFF_TIMER_READ) as u64, 8), 8);
    check(stage, 6, get_u64_ne(OFF_TIMER_READ) >= 1);
    expect_value(
        stage,
        6,
        epoll_wait(epfd, arena(OFF_EPOLL_EVENTS) as u64, EPOLL_MAX_EVENTS, 0),
        0,
    );

    // step 7: a blocked self-signal becomes readable through a signalfd.
    put_u64_ne(OFF_SIGSET_FD, 1u64 << (SIGUSR1 - 1));
    expect_ok(
        stage,
        7,
        rt_sigprocmask(
            SIG_BLOCK,
            arena(OFF_SIGSET_FD) as u64,
            arena(OFF_SIGSET_OLD) as u64,
        ),
    );
    let sfd = expect_ok(
        stage,
        7,
        signalfd4(-1, arena(OFF_SIGSET_FD) as u64, SIGSET_BYTES, SFD_NONBLOCK),
    );
    epoll_event_write(OFF_EPOLL_EVENT, EPOLLIN, 0xE5);
    expect_ok(
        stage,
        7,
        epoll_ctl(epfd, EPOLL_CTL_ADD, sfd, arena(OFF_EPOLL_EVENT) as u64),
    );
    expect_ok(stage, 7, kill(getpid(), SIGUSR1));
    expect_value(
        stage,
        7,
        epoll_wait(epfd, arena(OFF_EPOLL_EVENTS) as u64, EPOLL_MAX_EVENTS, 0),
        1,
    );
    expect_value(stage, 7, epoll_event_data(OFF_EPOLL_EVENTS) as i64, 0xE5);
    expect_value(
        stage,
        7,
        read_fd(sfd, arena(OFF_SFD_INFO) as u64, SIGINFO_BYTES),
        SIGINFO_BYTES as i64,
    );
    expect_value(
        stage,
        7,
        u64::from(get_u32_le(OFF_SFD_INFO)) as i64,
        SIGUSR1 as i64,
    );
    expect_value(
        stage,
        7,
        epoll_wait(epfd, arena(OFF_EPOLL_EVENTS) as u64, EPOLL_MAX_EVENTS, 0),
        0,
    );

    // step 8: a pending signal interrupts epoll_pwait with a temporary empty
    // mask; the handler consumes it, so a fresh blocked kill is queued for the
    // signalfd before the blocking wait.
    expect_ok(stage, 8, kill(getpid(), SIGUSR1));
    put_u64_ne(OFF_SIGSET_EMPTY, 0);
    put_u64_ne(OFF_POLL_TS, 1);
    put_u64_ne(OFF_POLL_TS + 8, 0);
    expect_errno(
        stage,
        8,
        epoll_pwait(
            epfd,
            arena(OFF_EPOLL_EVENTS) as u64,
            EPOLL_MAX_EVENTS,
            M9A_PWAIT_MS,
            arena(OFF_SIGSET_EMPTY) as u64,
            SIGSET_BYTES,
        ),
        EINTR,
    );
    expect_ok(stage, 8, kill(getpid(), SIGUSR1));
    expect_value(
        stage,
        8,
        epoll_wait(epfd, arena(OFF_EPOLL_EVENTS) as u64, EPOLL_MAX_EVENTS, -1),
        1,
    );
    expect_value(stage, 8, epoll_event_data(OFF_EPOLL_EVENTS) as i64, 0xE5);
    expect_value(
        stage,
        8,
        read_fd(sfd, arena(OFF_SFD_INFO) as u64, SIGINFO_BYTES),
        SIGINFO_BYTES as i64,
    );
    expect_value(
        stage,
        8,
        u64::from(get_u32_le(OFF_SFD_INFO)) as i64,
        SIGUSR1 as i64,
    );
    expect_value(
        stage,
        8,
        epoll_wait(epfd, arena(OFF_EPOLL_EVENTS) as u64, EPOLL_MAX_EVENTS, 0),
        0,
    );

    // step 9: DEL each source; the instance reports no events and honours a
    // short timeout without spinning.
    expect_ok(stage, 9, epoll_ctl(epfd, EPOLL_CTL_DEL, tfd, 0));
    expect_ok(stage, 9, epoll_ctl(epfd, EPOLL_CTL_DEL, socket_a, 0));
    expect_ok(stage, 9, epoll_ctl(epfd, EPOLL_CTL_DEL, efd, 0));
    expect_ok(stage, 9, epoll_ctl(epfd, EPOLL_CTL_DEL, sfd, 0));
    expect_value(
        stage,
        9,
        epoll_wait(epfd, arena(OFF_EPOLL_EVENTS) as u64, EPOLL_MAX_EVENTS, 0),
        0,
    );
    let started = read_clock_ns(stage, 9, CLOCK_MONOTONIC);
    expect_value(
        stage,
        9,
        epoll_wait(
            epfd,
            arena(OFF_EPOLL_EVENTS) as u64,
            EPOLL_MAX_EVENTS,
            M9A_SHORT_TIMEOUT_MS,
        ),
        0,
    );
    let elapsed = read_clock_ns(stage, 9, CLOCK_MONOTONIC) - started;
    check(stage, 9, elapsed >= M9A_MIN_SHORT_ELAPSED_NS);

    // step 10: cleanup (close every source and restore the mask).
    expect_ok(stage, 10, close(tfd));
    expect_ok(stage, 10, close(socket_a));
    expect_ok(stage, 10, close(socket_b));
    expect_ok(stage, 10, close(efd));
    expect_ok(stage, 10, close(sfd));
    expect_ok(stage, 10, close(epfd));
    expect_ok(
        stage,
        10,
        rt_sigprocmask(SIG_SETMASK, arena(OFF_SIGSET_OLD) as u64, 0),
    );
}

// ---------------------------------------------------------------------------
// M9b: UNIX abstract names, fd passing and edge-triggered epoll.
// ---------------------------------------------------------------------------

/// Writes a `struct msghdr` (Linux x86-64 layout, 56 bytes) at `offset`.
fn put_msghdr(
    offset: usize,
    name: u64,
    namelen: u64,
    iov: u64,
    iovlen: u64,
    control: u64,
    controllen: u64,
) {
    put_u64_ne(offset, name);
    put_u32_le(offset + 8, namelen as u32);
    put_u32_le(offset + 12, 0);
    put_u64_ne(offset + 16, iov);
    put_u64_ne(offset + 24, iovlen);
    put_u64_ne(offset + 32, control);
    put_u64_ne(offset + 40, controllen);
    put_u32_le(offset + 48, 0);
    put_u32_le(offset + 52, 0);
}

fn put_iovec(offset: usize, base: u64, length: u64) {
    put_u64_ne(offset, base);
    put_u64_ne(offset + 8, length);
}

fn msghdr_flags(offset: usize) -> u32 {
    get_u32_le(offset + 48)
}

fn msghdr_controllen(offset: usize) -> u64 {
    get_u64_ne(offset + 40)
}

/// `CMSG_SPACE(payload)` for a control record whose data is `payload` bytes.
fn cmsg_space(payload: usize) -> u64 {
    (((16 + payload) + 7) & !7) as u64
}

fn put_cmsg_header(offset: usize, payload: usize, level: u32, kind: u32) {
    put_u64_ne(offset, (16 + payload) as u64);
    put_u32_le(offset + 8, level);
    put_u32_le(offset + 12, kind);
}

/// Finds the payload of the first `(level, kind)` control record and returns
/// its **ARENA OFFSET** (not a buffer-relative index), so callers can feed it
/// straight to the `get_*`/`put_*` helpers.
fn find_cmsg_payload(level: u32, kind: u32) -> Option<usize> {
    let total = msghdr_controllen(OFF_M9B_MSG) as usize;
    let mut offset = 0usize;
    while offset + 16 <= total {
        let length = get_u64_ne(OFF_M9B_CTRL + offset) as usize;
        if length < 16 {
            return None;
        }
        if get_u32_le(OFF_M9B_CTRL + offset + 8) == level
            && get_u32_le(OFF_M9B_CTRL + offset + 12) == kind
        {
            return Some(OFF_M9B_CTRL + offset + 16);
        }
        offset += (length + 7) & !7;
    }
    None
}

/// Writes an abstract `sockaddr_un` (leading NUL in `sun_path`) and returns
/// its `socklen_t`: family (2) + NUL (1) + name bytes.
fn put_un_abstract(offset: usize, name: &[u8]) -> u64 {
    put_u16_ne(offset, AF_UNIX as u16);
    put_u8(offset + 2, 0);
    let mut index = 0usize;
    while index < name.len() {
        put_u8(offset + 3 + index, name[index]);
        index += 1;
    }
    (3 + name.len()) as u64
}

/// Verifies the abstract `sockaddr_un` at `offset` against `name` and the
/// length the kernel wrote back into `OFF_M9B_LEN`.
fn check_un_abstract(stage: u32, step: u32, offset: usize, name: &[u8]) {
    check(stage, step, get_u16_ne(offset) == AF_UNIX as u16);
    check(
        stage,
        step,
        get_u32_le(OFF_M9B_LEN) as usize == 3 + name.len(),
    );
    check(stage, step, read_byte(arena(offset + 2) as u64) == 0);
    let mut index = 0usize;
    while index < name.len() {
        check(
            stage,
            step,
            read_byte(arena(offset + 3 + index) as u64) == name[index],
        );
        index += 1;
    }
}

/// Non-blocking `connect` retry: `EAGAIN` means "still connecting".
fn retry_connect(stage: u32, step: u32, fd: i64, address: u64, length: u64) {
    let mut attempt = 0u32;
    loop {
        let result = connect(fd, address, length);
        if result == 0 {
            return;
        }
        if result == -EAGAIN && attempt < 128 {
            attempt += 1;
            continue;
        }
        fail(stage, step, result);
    }
}

/// Non-blocking `accept` retry: `EAGAIN` means "no pending connection yet".
fn retry_accept(stage: u32, step: u32, fd: i64) -> i64 {
    let mut attempt = 0u32;
    loop {
        let result = accept(fd);
        if result >= 0 {
            return result;
        }
        if result == -EAGAIN && attempt < 128 {
            attempt += 1;
            continue;
        }
        fail(stage, step, result);
    }
}

/// M9b abstract UNIX sockets: bind/getsockname readback for stream and
/// datagram, connect/accept across two abstract names, and the negative
/// paths (duplicate bind, missing name).
fn suite_m9b_abstract() {
    let stage = STAGE_M9B_ABSTRACT;
    let stream_name = b"m9b-abs-stream";
    let dgram_name = b"m9b-abs-dgram";
    let client_name = b"m9b-abs-client";

    // step 1: stream listener bound to an abstract name; read it back.
    let server = expect_ok(stage, 1, socket(AF_UNIX, SOCK_STREAM, 0));
    let server_length = put_un_abstract(OFF_M9B_UN, stream_name);
    expect_ok(
        stage,
        1,
        bind(server, arena(OFF_M9B_UN) as u64, server_length),
    );
    put_u32_le(OFF_M9B_LEN, 110);
    expect_ok(
        stage,
        1,
        getsockname(server, arena(OFF_M9B_UN2) as u64, arena(OFF_M9B_LEN) as u64),
    );
    check_un_abstract(stage, 1, OFF_M9B_UN2, stream_name);
    expect_ok(stage, 1, listen(server, 1));

    // step 2: binding the same abstract name twice is EADDRINUSE.
    let duplicate = expect_ok(stage, 2, socket(AF_UNIX, SOCK_STREAM, 0));
    let duplicate_length = put_un_abstract(OFF_M9B_UN2, stream_name);
    expect_errno(
        stage,
        2,
        bind(duplicate, arena(OFF_M9B_UN2) as u64, duplicate_length),
        EADDRINUSE,
    );
    expect_ok(stage, 2, close(duplicate));

    // step 3: connect from a client that names itself abstractly.
    let client = expect_ok(stage, 3, socket(AF_UNIX, SOCK_STREAM, 0));
    let client_length = put_un_abstract(OFF_M9B_UN2, client_name);
    expect_ok(
        stage,
        3,
        bind(client, arena(OFF_M9B_UN2) as u64, client_length),
    );
    retry_connect(stage, 3, client, arena(OFF_M9B_UN) as u64, server_length);
    let accepted = retry_accept(stage, 3, server);

    // step 4: the accepted stream has no pathname (family only, namelen 2).
    put_u32_le(OFF_M9B_LEN, 110);
    expect_ok(
        stage,
        4,
        getsockname(
            accepted,
            arena(OFF_M9B_UN2) as u64,
            arena(OFF_M9B_LEN) as u64,
        ),
    );
    check(stage, 4, get_u16_ne(OFF_M9B_UN2) == AF_UNIX as u16);
    check(stage, 4, get_u32_le(OFF_M9B_LEN) == 2);
    expect_ok(stage, 4, close(accepted));
    expect_ok(stage, 4, close(client));

    // step 5: connecting to an unbound abstract name is ENOENT.
    let missing = expect_ok(stage, 5, socket(AF_UNIX, SOCK_STREAM, 0));
    let missing_length = put_un_abstract(OFF_M9B_UN2, b"m9b-abs-missing");
    expect_errno(
        stage,
        5,
        connect(missing, arena(OFF_M9B_UN2) as u64, missing_length),
        ENOENT,
    );
    expect_ok(stage, 5, close(missing));
    expect_ok(stage, 5, close(server));

    // step 6: datagram sockets bound to abstract names with source readback.
    let receiver = expect_ok(stage, 6, socket(AF_UNIX, SOCK_DGRAM, 0));
    let receiver_length = put_un_abstract(OFF_M9B_UN, dgram_name);
    expect_ok(
        stage,
        6,
        bind(receiver, arena(OFF_M9B_UN) as u64, receiver_length),
    );
    put_u32_le(OFF_M9B_LEN, 110);
    expect_ok(
        stage,
        6,
        getsockname(
            receiver,
            arena(OFF_M9B_UN2) as u64,
            arena(OFF_M9B_LEN) as u64,
        ),
    );
    check_un_abstract(stage, 6, OFF_M9B_UN2, dgram_name);
    let sender = expect_ok(stage, 6, socket(AF_UNIX, SOCK_DGRAM, 0));
    let sender_length = put_un_abstract(OFF_M9B_UN2, client_name);
    expect_ok(
        stage,
        6,
        bind(sender, arena(OFF_M9B_UN2) as u64, sender_length),
    );
    // The sender must be connected before a destination-less `send`; the
    // receiver's abstract name is still in `OFF_M9B_UN`.
    retry_connect(stage, 6, sender, arena(OFF_M9B_UN) as u64, receiver_length);
    fill_pattern(OFF_M9B_BUF, 16, 0xA1);
    expect_value(stage, 6, sendto(sender, arena(OFF_M9B_BUF) as u64, 16), 16);
    put_u32_le(OFF_M9B_LEN, 110);
    expect_value(
        stage,
        6,
        recvfrom(
            receiver,
            arena(OFF_M9B_BUF) as u64,
            64,
            arena(OFF_M9B_UN) as u64,
            arena(OFF_M9B_LEN) as u64,
        ),
        16,
    );
    check(stage, 6, check_pattern(OFF_M9B_BUF, 16, 0xA1));
    check_un_abstract(stage, 6, OFF_M9B_UN, client_name);
    expect_ok(stage, 6, close(sender));
    expect_ok(stage, 6, close(receiver));
}

/// M9b `SCM_RIGHTS`: pass both endpoints of a fresh socketpair across a
/// carrier pair, close the originals, then use/shutdown the received fds.
fn suite_m9b_rights() {
    let stage = STAGE_M9B_RIGHTS;

    // step 1: the carrier pair that transports the descriptors.
    let mut carrier_pair = [0i32; 2];
    expect_ok(
        stage,
        1,
        socketpair_raw(AF_UNIX, SOCK_STREAM, carrier_pair.as_mut_ptr() as u64),
    );
    let carrier = carrier_pair[0] as i64;
    let carrier_peer = carrier_pair[1] as i64;

    // step 2: the pair whose endpoints the message will carry.
    let mut endpoint_pair = [0i32; 2];
    expect_ok(
        stage,
        2,
        socketpair_raw(AF_UNIX, SOCK_STREAM, endpoint_pair.as_mut_ptr() as u64),
    );
    let endpoint_a = endpoint_pair[0] as i64;
    let endpoint_b = endpoint_pair[1] as i64;

    // step 3: send one payload byte plus both fds as SCM_RIGHTS.
    fill_pattern(OFF_M9B_BUF, 16, 0x71);
    put_iovec(OFF_M9B_IOV, arena(OFF_M9B_BUF) as u64, 16);
    put_cmsg_header(OFF_M9B_CTRL, 8, SOL_SOCKET as u32, SCM_RIGHTS);
    put_u32_le(OFF_M9B_CTRL + 16, endpoint_a as u32);
    put_u32_le(OFF_M9B_CTRL + 20, endpoint_b as u32);
    put_msghdr(
        OFF_M9B_MSG,
        0,
        0,
        arena(OFF_M9B_IOV) as u64,
        1,
        arena(OFF_M9B_CTRL) as u64,
        cmsg_space(8),
    );
    expect_value(stage, 3, sendmsg(carrier, arena(OFF_M9B_MSG) as u64, 0), 16);

    // step 4: the received copies must own the objects; drop the originals.
    expect_ok(stage, 4, close(endpoint_a));
    expect_ok(stage, 4, close(endpoint_b));

    // step 5: receive the payload and both descriptors.
    put_bytes(OFF_M9B_BUF, &[0u8; 16]);
    put_iovec(OFF_M9B_IOV, arena(OFF_M9B_BUF) as u64, 16);
    put_msghdr(
        OFF_M9B_MSG,
        0,
        0,
        arena(OFF_M9B_IOV) as u64,
        1,
        arena(OFF_M9B_CTRL) as u64,
        128,
    );
    expect_value(
        stage,
        5,
        recvmsg(carrier_peer, arena(OFF_M9B_MSG) as u64, MSG_CMSG_CLOEXEC),
        16,
    );
    check(stage, 5, (msghdr_flags(OFF_M9B_MSG) & MSG_CTRUNC) == 0);
    check(stage, 5, msghdr_controllen(OFF_M9B_MSG) >= cmsg_space(8));
    check(stage, 5, get_u64_ne(OFF_M9B_CTRL) >= 24);
    check(stage, 5, get_u32_le(OFF_M9B_CTRL + 8) == SOL_SOCKET as u32);
    check(stage, 5, get_u32_le(OFF_M9B_CTRL + 12) == SCM_RIGHTS);
    check(stage, 5, check_pattern(OFF_M9B_BUF, 16, 0x71));
    let received_a = get_u32_le(OFF_M9B_CTRL + 16) as i64;
    let received_b = get_u32_le(OFF_M9B_CTRL + 20) as i64;
    check(stage, 5, received_a > 2);
    check(stage, 5, received_b > 2);
    check(stage, 5, received_a != received_b);

    // step 6: the two received fds still form the original connected pair.
    fill_pattern(OFF_M9B_CRED, 4, 0x81);
    expect_value(
        stage,
        6,
        write_fd(received_a, arena(OFF_M9B_CRED) as u64, 4),
        4,
    );
    put_bytes(OFF_M9B_BUF, &[0u8; 4]);
    expect_value(
        stage,
        6,
        read_fd(received_b, arena(OFF_M9B_BUF) as u64, 4),
        4,
    );
    check(stage, 6, check_pattern(OFF_M9B_BUF, 4, 0x81));

    // step 7: shutdown on one received fd is visible as EOF on the other.
    expect_ok(stage, 7, shutdown(received_a, SHUT_WR));
    put_bytes(OFF_M9B_BUF, &[0u8; 8]);
    expect_value(
        stage,
        7,
        read_fd(received_b, arena(OFF_M9B_BUF) as u64, 8),
        0,
    );

    // step 8: cleanup.
    expect_ok(stage, 8, close(received_a));
    expect_ok(stage, 8, close(received_b));
    expect_ok(stage, 8, close(carrier));
    expect_ok(stage, 8, close(carrier_peer));
}

/// M9b credentials: `SO_PASSCRED`-attached `SCM_CREDENTIALS`, an explicit
/// record, and `SO_PEERCRED` — pid == getpid(), uid/gid == 0.
fn suite_m9b_credentials() {
    let stage = STAGE_M9B_CREDENTIALS;

    // step 1: datagram socketpair; the receiver will request credentials.
    let mut pair = [0i32; 2];
    expect_ok(
        stage,
        1,
        socketpair_raw(AF_UNIX, SOCK_DGRAM, pair.as_mut_ptr() as u64),
    );
    let sender = pair[0] as i64;
    let receiver = pair[1] as i64;
    put_u32_le(OFF_M9B_CRED, 1);
    expect_ok(
        stage,
        2,
        setsockopt(
            receiver,
            SOL_SOCKET,
            SO_PASSCRED,
            arena(OFF_M9B_CRED) as u64,
            4,
        ),
    );

    // step 3: kernel-attached credentials (no explicit control record).
    fill_pattern(OFF_M9B_BUF, 8, 0x91);
    put_iovec(OFF_M9B_IOV, arena(OFF_M9B_BUF) as u64, 8);
    put_msghdr(OFF_M9B_MSG, 0, 0, arena(OFF_M9B_IOV) as u64, 1, 0, 0);
    expect_value(stage, 3, sendmsg(sender, arena(OFF_M9B_MSG) as u64, 0), 8);
    put_bytes(OFF_M9B_BUF, &[0u8; 8]);
    put_iovec(OFF_M9B_IOV, arena(OFF_M9B_BUF) as u64, 8);
    put_msghdr(
        OFF_M9B_MSG,
        0,
        0,
        arena(OFF_M9B_IOV) as u64,
        1,
        arena(OFF_M9B_CTRL) as u64,
        128,
    );
    expect_value(stage, 3, recvmsg(receiver, arena(OFF_M9B_MSG) as u64, 0), 8);
    check(stage, 3, check_pattern(OFF_M9B_BUF, 8, 0x91));
    let credentials = match find_cmsg_payload(SOL_SOCKET as u32, SCM_CREDENTIALS) {
        Some(payload) => payload,
        None => fail(stage, 3, -EBADF),
    };
    check(stage, 3, get_u32_le(credentials) == getpid() as u32);
    check(stage, 3, get_u32_le(credentials + 4) == getuid() as u32);
    check(stage, 3, get_u32_le(credentials + 8) == getgid() as u32);

    // step 4: an explicit SCM_CREDENTIALS record must pass the same checks.
    fill_pattern(OFF_M9B_BUF, 8, 0x92);
    put_iovec(OFF_M9B_IOV, arena(OFF_M9B_BUF) as u64, 8);
    put_cmsg_header(OFF_M9B_CTRL, 12, SOL_SOCKET as u32, SCM_CREDENTIALS);
    put_u32_le(OFF_M9B_CTRL + 16, getpid() as u32);
    put_u32_le(OFF_M9B_CTRL + 20, getuid() as u32);
    put_u32_le(OFF_M9B_CTRL + 24, getgid() as u32);
    put_msghdr(
        OFF_M9B_MSG,
        0,
        0,
        arena(OFF_M9B_IOV) as u64,
        1,
        arena(OFF_M9B_CTRL) as u64,
        cmsg_space(12),
    );
    expect_value(stage, 4, sendmsg(sender, arena(OFF_M9B_MSG) as u64, 0), 8);
    put_bytes(OFF_M9B_BUF, &[0u8; 8]);
    put_iovec(OFF_M9B_IOV, arena(OFF_M9B_BUF) as u64, 8);
    put_msghdr(
        OFF_M9B_MSG,
        0,
        0,
        arena(OFF_M9B_IOV) as u64,
        1,
        arena(OFF_M9B_CTRL) as u64,
        128,
    );
    expect_value(stage, 4, recvmsg(receiver, arena(OFF_M9B_MSG) as u64, 0), 8);
    check(stage, 4, check_pattern(OFF_M9B_BUF, 8, 0x92));
    let explicit = match find_cmsg_payload(SOL_SOCKET as u32, SCM_CREDENTIALS) {
        Some(payload) => payload,
        None => fail(stage, 4, -EBADF),
    };
    check(stage, 4, get_u32_le(explicit) == getpid() as u32);
    check(stage, 4, get_u32_le(explicit + 4) == getuid() as u32);
    check(stage, 4, get_u32_le(explicit + 8) == getgid() as u32);

    // step 5: SO_PEERCRED reports the peer's real pid with uid/gid 0.
    put_u32_le(OFF_M9B_LEN, 12);
    expect_ok(
        stage,
        5,
        getsockopt(
            receiver,
            SOL_SOCKET,
            SO_PEERCRED,
            arena(OFF_M9B_CRED) as u64,
            arena(OFF_M9B_LEN) as u64,
        ),
    );
    check(stage, 5, get_u32_le(OFF_M9B_LEN) >= 12);
    check(stage, 5, get_u32_le(OFF_M9B_CRED) == getpid() as u32);
    check(stage, 5, get_u32_le(OFF_M9B_CRED + 4) == getuid() as u32);
    check(stage, 5, get_u32_le(OFF_M9B_CRED + 8) == getgid() as u32);

    // step 6: cleanup.
    expect_ok(stage, 6, close(sender));
    expect_ok(stage, 6, close(receiver));
}

/// M9b edge-triggered epoll: one eventfd watched by an ET and an LT
/// instance; ET reports only new edges while LT keeps reporting while
/// readable, and `EPOLL_CTL_MOD` switches the interest back to LT.
fn suite_m9b_epoll_et() {
    let stage = STAGE_M9B_EPOLL_ET;
    let et_epoll = expect_ok(stage, 1, epoll_create1(0));
    let lt_epoll = expect_ok(stage, 1, epoll_create1(0));
    let efd = expect_ok(stage, 1, eventfd2(0, SFD_NONBLOCK));
    epoll_event_write(OFF_EPOLL_EVENT, EPOLLIN | EPOLLET, 0xE1);
    expect_ok(
        stage,
        1,
        epoll_ctl(et_epoll, EPOLL_CTL_ADD, efd, arena(OFF_EPOLL_EVENT) as u64),
    );
    epoll_event_write(OFF_EPOLL_EVENT, EPOLLIN, 0xE6);
    expect_ok(
        stage,
        1,
        epoll_ctl(lt_epoll, EPOLL_CTL_ADD, efd, arena(OFF_EPOLL_EVENT) as u64),
    );

    // step 2: a write wakes both interests exactly once.
    put_u64_ne(OFF_M9B_BUF, 1);
    expect_value(stage, 2, write_fd(efd, arena(OFF_M9B_BUF) as u64, 8), 8);
    expect_value(
        stage,
        2,
        epoll_wait(et_epoll, arena(OFF_EPOLL_EVENTS) as u64, 1, 0),
        1,
    );
    check(stage, 2, epoll_event_data(OFF_EPOLL_EVENTS) == 0xE1);
    expect_value(
        stage,
        2,
        epoll_wait(lt_epoll, arena(OFF_EPOLL_EVENTS) as u64, 1, 0),
        1,
    );
    check(stage, 2, epoll_event_data(OFF_EPOLL_EVENTS) == 0xE6);

    // step 3: ET stays silent (no new edge) while LT keeps reporting.
    expect_value(
        stage,
        3,
        epoll_wait(et_epoll, arena(OFF_EPOLL_EVENTS) as u64, 1, 0),
        0,
    );
    expect_value(
        stage,
        3,
        epoll_wait(lt_epoll, arena(OFF_EPOLL_EVENTS) as u64, 1, 0),
        1,
    );

    // step 4: another write is a new edge for the ET interest.
    put_u64_ne(OFF_M9B_BUF, 2);
    expect_value(stage, 4, write_fd(efd, arena(OFF_M9B_BUF) as u64, 8), 8);
    expect_value(
        stage,
        4,
        epoll_wait(et_epoll, arena(OFF_EPOLL_EVENTS) as u64, 1, 0),
        1,
    );
    check(stage, 4, epoll_event_data(OFF_EPOLL_EVENTS) == 0xE1);

    // step 5: draining clears both interests.
    expect_value(stage, 5, read_fd(efd, arena(OFF_M9B_BUF) as u64, 8), 8);
    expect_value(
        stage,
        5,
        epoll_wait(et_epoll, arena(OFF_EPOLL_EVENTS) as u64, 1, 0),
        0,
    );
    expect_value(
        stage,
        5,
        epoll_wait(lt_epoll, arena(OFF_EPOLL_EVENTS) as u64, 1, 0),
        0,
    );

    // step 6: MOD switches the ET instance to level-triggered.
    epoll_event_write(OFF_EPOLL_EVENT, EPOLLIN, 0xE1);
    expect_ok(
        stage,
        6,
        epoll_ctl(et_epoll, EPOLL_CTL_MOD, efd, arena(OFF_EPOLL_EVENT) as u64),
    );
    put_u64_ne(OFF_M9B_BUF, 3);
    expect_value(stage, 6, write_fd(efd, arena(OFF_M9B_BUF) as u64, 8), 8);
    expect_value(
        stage,
        6,
        epoll_wait(et_epoll, arena(OFF_EPOLL_EVENTS) as u64, 1, 0),
        1,
    );
    expect_value(
        stage,
        6,
        epoll_wait(et_epoll, arena(OFF_EPOLL_EVENTS) as u64, 1, 0),
        1,
    );
    expect_value(stage, 6, read_fd(efd, arena(OFF_M9B_BUF) as u64, 8), 8);
    expect_value(
        stage,
        6,
        epoll_wait(et_epoll, arena(OFF_EPOLL_EVENTS) as u64, 1, 0),
        0,
    );

    // step 7: DEL both interests and clean up.
    expect_ok(stage, 7, epoll_ctl(et_epoll, EPOLL_CTL_DEL, efd, 0));
    expect_ok(stage, 7, epoll_ctl(lt_epoll, EPOLL_CTL_DEL, efd, 0));
    expect_ok(stage, 7, close(efd));
    expect_ok(stage, 7, close(lt_epoll));
    expect_ok(stage, 7, close(et_epoll));
}

// ---------------------------------------------------------------------------
// M9c: POSIX record locks, blocking wakeup, close release and `flock`.
// ---------------------------------------------------------------------------

/// Command counter incremented by the peer's `SIGUSR2` handler.
static mut PEER_COMMAND_COUNT: u64 = 0;

extern "C" fn peer_command_handler(_signum: i32) {
    unsafe {
        let count = core::ptr::read_volatile(core::ptr::addr_of!(PEER_COMMAND_COUNT));
        core::ptr::write_volatile(addr_of_mut!(PEER_COMMAND_COUNT), count + 1);
    }
}

fn peer_command_count() -> u64 {
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(PEER_COMMAND_COUNT)) }
}

/// Bounded wait until `signal_count()` grows past `baseline`: one peer ack.
fn wait_m9c_ack(baseline: u64, ticks: u64) -> bool {
    let mut spent = 0u64;
    while spent < ticks {
        if signal_count() > baseline {
            return true;
        }
        sleep_ticks(1);
        spent += 1;
    }
    signal_count() > baseline
}

/// Parent side: broadcast the next `SIGUSR2` command and wait for the peer's
/// `SIGUSR1` ack. Commands are issued sequentially, so the peer counts them in
/// the same order.
fn m9c_command(stage: u32, step: u32) {
    let baseline = signal_count();
    expect_value(stage, step, kill(-1, SIGUSR2), 0);
    let acked = wait_m9c_ack(baseline, M9C_ACK_TICKS);
    check(stage, step, acked);
}

/// M9c peer: a long-lived second Linux process that only participates in the
/// file-lock protocol. It never prints a marker. During M8d the parent
/// broadcasts `SIGWINCH` pings and `SIGUSR1` (including its terminating
/// signal) to every child, so both are set to `SIG_IGN` before anything else.
fn m9c_peer_main() -> ! {
    let stage = STAGE_M9C_LOCKS;

    let ignored = KernelSigaction::ignored();
    expect_ok(
        stage,
        1,
        rt_sigaction(SIGWINCH, &ignored as *const KernelSigaction as u64, 0),
    );
    expect_ok(
        stage,
        1,
        rt_sigaction(SIGUSR1, &ignored as *const KernelSigaction as u64, 0),
    );

    // `SIGUSR2` is only ever sent by the parent once the lock suite starts, so
    // installing the command handler here arms the peer exactly for M9c.
    let command: extern "C" fn(i32) = peer_command_handler;
    let command_action = signal_action(command as usize);
    expect_ok(
        stage,
        2,
        rt_sigaction(SIGUSR2, &command_action as *const KernelSigaction as u64, 0),
    );
    let parent_pid = getppid();
    let mut file = -1i64;
    let mut served = 0u64;
    loop {
        while peer_command_count() <= served {
            sleep_ns(M9C_POLL_NS);
        }
        served = peer_command_count();
        match served {
            M9C_CMD_VALIDATE => {
                file = expect_ok(stage, 21, openat_at(AT_FDCWD, M9C_FILE_PATH, O_RDWR, 0));
                // The parent's write lock is visible to the peer: type, owner
                // pid and the whole-file range.
                put_flock(OFF_M9C_FLOCK2, F_WRLCK, 0, 0, 0);
                expect_ok(
                    stage,
                    22,
                    fcntl(file, F_GETLK, arena(OFF_M9C_FLOCK2) as u64),
                );
                check(stage, 22, flock_type(OFF_M9C_FLOCK2) == F_WRLCK);
                check(stage, 22, flock_pid(OFF_M9C_FLOCK2) == parent_pid as i32);
                check(stage, 22, flock_start(OFF_M9C_FLOCK2) == 0);
                check(stage, 22, flock_length(OFF_M9C_FLOCK2) == 0);
                // A non-blocking conflicting request still fails with EAGAIN.
                put_flock(OFF_M9C_FLOCK2, F_WRLCK, 0, 0, 0);
                expect_errno(
                    stage,
                    23,
                    fcntl(file, F_SETLK, arena(OFF_M9C_FLOCK2) as u64),
                    EAGAIN,
                );
            }
            M9C_CMD_BLOCK => {
                // A blocking write request stays blocked until the parent
                // releases its lock 100 ms after issuing this command.
                put_flock(OFF_M9C_FLOCK2, F_WRLCK, 0, 0, 0);
                let started = read_clock_ns(stage, 24, CLOCK_MONOTONIC);
                expect_ok(
                    stage,
                    24,
                    fcntl(file, F_SETLKW, arena(OFF_M9C_FLOCK2) as u64),
                );
                let waited = read_clock_ns(stage, 24, CLOCK_MONOTONIC) - started;
                check(stage, 24, waited >= M9C_MIN_BLOCKED_NS);
                // The peer now owns the write lock; its own GETLK reports
                // UNLCK because an owner never conflicts with itself.
                put_flock(OFF_M9C_FLOCK2, F_WRLCK, 0, 0, 0);
                expect_ok(
                    stage,
                    25,
                    fcntl(file, F_GETLK, arena(OFF_M9C_FLOCK2) as u64),
                );
                check(stage, 25, flock_type(OFF_M9C_FLOCK2) == F_UNLCK);
            }
            M9C_CMD_UNLOCK => {
                put_flock(OFF_M9C_FLOCK2, F_UNLCK, 0, 0, 0);
                expect_ok(
                    stage,
                    26,
                    fcntl(file, F_SETLK, arena(OFF_M9C_FLOCK2) as u64),
                );
                // A shared lock is acquirable here, and a write query does not
                // conflict with the owner's own lock.
                put_flock(OFF_M9C_FLOCK2, F_RDLCK, 0, 0, 0);
                expect_ok(
                    stage,
                    26,
                    fcntl(file, F_SETLK, arena(OFF_M9C_FLOCK2) as u64),
                );
                put_flock(OFF_M9C_FLOCK2, F_WRLCK, 0, 0, 0);
                expect_ok(
                    stage,
                    26,
                    fcntl(file, F_GETLK, arena(OFF_M9C_FLOCK2) as u64),
                );
                check(stage, 26, flock_type(OFF_M9C_FLOCK2) == F_UNLCK);
                put_flock(OFF_M9C_FLOCK2, F_UNLCK, 0, 0, 0);
                expect_ok(
                    stage,
                    26,
                    fcntl(file, F_SETLK, arena(OFF_M9C_FLOCK2) as u64),
                );
            }
            M9C_CMD_EXPECT_HELD => {
                put_flock(OFF_M9C_FLOCK2, F_WRLCK, 0, 0, 0);
                expect_ok(
                    stage,
                    27,
                    fcntl(file, F_GETLK, arena(OFF_M9C_FLOCK2) as u64),
                );
                check(stage, 27, flock_type(OFF_M9C_FLOCK2) == F_WRLCK);
                check(stage, 27, flock_pid(OFF_M9C_FLOCK2) == parent_pid as i32);
            }
            M9C_CMD_EXPECT_RELEASED => {
                put_flock(OFF_M9C_FLOCK2, F_WRLCK, 0, 0, 0);
                expect_ok(
                    stage,
                    28,
                    fcntl(file, F_GETLK, arena(OFF_M9C_FLOCK2) as u64),
                );
                check(stage, 28, flock_type(OFF_M9C_FLOCK2) == F_UNLCK);
            }
            M9C_CMD_FLOCK_CONFLICT => {
                // The parent's `LOCK_EX` really conflicts inside the flock
                // domain, while the independent POSIX domain stays available.
                expect_errno(stage, 29, flock(file, LOCK_EX | LOCK_NB), EAGAIN);
                put_flock(OFF_M9C_FLOCK2, F_WRLCK, 0, 0, 0);
                expect_ok(
                    stage,
                    29,
                    fcntl(file, F_SETLK, arena(OFF_M9C_FLOCK2) as u64),
                );
                put_flock(OFF_M9C_FLOCK2, F_UNLCK, 0, 0, 0);
                expect_ok(
                    stage,
                    29,
                    fcntl(file, F_SETLK, arena(OFF_M9C_FLOCK2) as u64),
                );
            }
            M9C_CMD_FLOCK_AVAILABLE => {
                // The parent released its flock: the peer takes it, and the
                // parent then proves a POSIX lock can coexist with it.
                expect_ok(stage, 30, flock(file, LOCK_EX | LOCK_NB));
            }
            M9C_CMD_EXIT => {
                expect_ok(stage, 31, flock(file, LOCK_UN));
                expect_ok(stage, 31, close(file));
                exit_group(0)
            }
            _ => fail(stage, 32, served as i64),
        }
        // Acknowledge directly to the parent: `kill(-1, ...)` broadcasts only
        // to the caller's own children, and the peer has none (ESRCH). The
        // parent keeps broadcasting its commands with `kill(-1, SIGUSR2)`.
        let ack = kill(parent_pid, SIGUSR1);
        expect_value(stage, 33, ack, 0);
    }
}

/// M9c parent: exercises the POSIX record-lock and `flock` domains against the
/// role-2 peer, then reaps it through the protocol and prints the single
/// `M9c locks OK` marker.
fn suite_m9c_locks() {
    let stage = STAGE_M9C_LOCKS;

    // M8g step 12 temporarily unblocked SIGUSR1 for `ppoll`; the kernel then
    // restored the *original* mask, which still had SIGUSR1 blocked. M9c uses
    // SIGUSR1 for the peer ack, so clear the whole blocked mask before any
    // lock step — otherwise every ack stays pending and step 4 times out.
    put_u64_ne(OFF_SIGSET_EMPTY, 0);
    expect_ok(
        stage,
        0,
        rt_sigprocmask(SIG_SETMASK, arena(OFF_SIGSET_EMPTY) as u64, 0),
    );

    // M8g step 12 also replaced the SIGUSR1 disposition with its own
    // `wake_handler`, which only bumps `WAKE_WRITES`. M9c counts acks through
    // the generic `signal_handler` (`SIGNAL_COUNT`), so restore it before any
    // command (the blocked mask is already cleared above).
    let ack_handler: extern "C" fn(i32) = signal_handler;
    let ack_action = signal_action(ack_handler as usize);
    expect_ok(
        stage,
        0,
        rt_sigaction(SIGUSR1, &ack_action as *const KernelSigaction as u64, 0),
    );

    // step 1: bad descriptors, a bad user pointer and an unknown command keep
    // the syscall-level negative paths observable.
    put_flock(OFF_M9C_FLOCK, F_WRLCK, 0, 0, 0);
    expect_errno(
        stage,
        1,
        fcntl(-1, F_GETLK, arena(OFF_M9C_FLOCK) as u64),
        EBADF,
    );
    let file = expect_ok(
        stage,
        1,
        openat_at(
            AT_FDCWD,
            M9C_FILE_PATH,
            O_CREAT | O_RDWR | O_TRUNC,
            O_FILE_MODE,
        ),
    );
    expect_errno(stage, 1, fcntl(file, F_GETLK, 1), EFAULT);
    expect_errno(
        stage,
        1,
        fcntl(file, 0x7fff, arena(OFF_M9C_FLOCK) as u64),
        EINVAL,
    );
    expect_errno(stage, 1, flock(-1, LOCK_EX), EBADF);
    // The fd table is frozen at 16 entries: a minimum at or beyond it is
    // `EINVAL`, never a fabricated descriptor number.
    expect_errno(stage, 1, fcntl(file, F_DUPFD, 16), EINVAL);

    // step 2: an owner's own write lock is not reported back to itself.
    put_flock(OFF_M9C_FLOCK, F_WRLCK, 0, 0, 0);
    expect_ok(stage, 2, fcntl(file, F_SETLK, arena(OFF_M9C_FLOCK) as u64));
    put_flock(OFF_M9C_FLOCK, F_WRLCK, 0, 0, 0);
    expect_ok(stage, 2, fcntl(file, F_GETLK, arena(OFF_M9C_FLOCK) as u64));
    check(stage, 2, flock_type(OFF_M9C_FLOCK) == F_UNLCK);

    // step 3: descriptor flags and one shared open description.
    let duplicate = expect_ok(stage, 3, fcntl(file, F_DUPFD, M9C_DUP_FLOOR));
    check(stage, 3, duplicate >= M9C_DUP_FLOOR as i64);
    expect_value(stage, 3, fcntl(duplicate, F_GETFD, 0), 0);
    expect_ok(stage, 3, fcntl(duplicate, F_SETFD, FD_CLOEXEC));
    expect_value(stage, 3, fcntl(duplicate, F_GETFD, 0), FD_CLOEXEC as i64);
    expect_ok(stage, 3, fcntl(duplicate, F_SETFD, 0));
    expect_value(stage, 3, fcntl(duplicate, F_GETFD, 0), 0);
    let cloexec = expect_ok(
        stage,
        3,
        fcntl(file, F_DUPFD_CLOEXEC, M9C_DUP_FLOOR_CLOEXEC),
    );
    check(stage, 3, cloexec >= M9C_DUP_FLOOR_CLOEXEC as i64);
    expect_value(stage, 3, fcntl(cloexec, F_GETFD, 0), FD_CLOEXEC as i64);
    expect_value(
        stage,
        3,
        fcntl(file, F_GETFL, 0) & O_ACCMODE as i64,
        O_RDWR as i64,
    );
    // Write through the duplicate, then read at the shared offset: the write
    // moved the single open-description offset, so the read reports EOF.
    expect_value(stage, 3, lseek(file, 0, SEEK_SET), 0);
    fill_pattern(OFF_M9C_BUF, 4, 0xC1);
    expect_value(
        stage,
        3,
        write_fd(duplicate, arena(OFF_M9C_BUF) as u64, 4),
        4,
    );
    put_bytes(OFF_M9C_BUF, &[0u8; 4]);
    expect_value(stage, 3, read_fd(file, arena(OFF_M9C_BUF) as u64, 4), 0);
    expect_value(stage, 3, lseek(file, 0, SEEK_SET), 0);
    expect_value(stage, 3, read_fd(file, arena(OFF_M9C_BUF) as u64, 4), 4);
    check(stage, 3, check_pattern(OFF_M9C_BUF, 4, 0xC1));
    expect_value(stage, 3, lseek(file, 0, SEEK_SET), 0);

    // step 4: the peer observes the parent's write lock (type, owner pid and
    // range) and its own non-blocking conflicting request fails with EAGAIN.
    m9c_command(stage, 4);

    // step 5: the peer's blocking request is woken by the parent's unlock; the
    // peer then owns the lock, which the parent observes as a foreign lock.
    let baseline = signal_count();
    let sent = kill(-1, SIGUSR2);
    expect_value(stage, 5, sent, 0);
    sleep_ns(M9C_BLOCK_RELEASE_NS);
    put_flock(OFF_M9C_FLOCK, F_UNLCK, 0, 0, 0);
    expect_ok(stage, 5, fcntl(file, F_SETLK, arena(OFF_M9C_FLOCK) as u64));
    check(stage, 5, wait_m9c_ack(baseline, M9C_ACK_TICKS));
    put_flock(OFF_M9C_FLOCK, F_WRLCK, 0, 0, 0);
    expect_ok(stage, 5, fcntl(file, F_GETLK, arena(OFF_M9C_FLOCK) as u64));
    check(stage, 5, flock_type(OFF_M9C_FLOCK) == F_WRLCK);
    check(stage, 5, flock_pid(OFF_M9C_FLOCK) > 0);
    check(stage, 5, flock_pid(OFF_M9C_FLOCK) != getpid() as i32);
    check(stage, 5, flock_start(OFF_M9C_FLOCK) == 0);
    check(stage, 5, flock_length(OFF_M9C_FLOCK) == 0);

    // step 6: the peer releases its lock.
    m9c_command(stage, 6);
    put_flock(OFF_M9C_FLOCK, F_WRLCK, 0, 0, 0);
    expect_ok(stage, 6, fcntl(file, F_GETLK, arena(OFF_M9C_FLOCK) as u64));
    check(stage, 6, flock_type(OFF_M9C_FLOCK) == F_UNLCK);

    // step 7: the peer sees the parent's lock, then closing a duplicate of the
    // open description drops every POSIX lock of the process on that file,
    // even on the surviving descriptor.
    put_flock(OFF_M9C_FLOCK, F_WRLCK, 0, 0, 0);
    expect_ok(stage, 7, fcntl(file, F_SETLK, arena(OFF_M9C_FLOCK) as u64));
    let closing = expect_ok(stage, 7, fcntl(file, F_DUPFD, M9C_DUP_FLOOR_CLOSE));
    check(stage, 7, closing >= M9C_DUP_FLOOR_CLOSE as i64);
    m9c_command(stage, 7);
    expect_ok(stage, 7, close(closing));
    put_flock(OFF_M9C_FLOCK, F_WRLCK, 0, 0, 0);
    expect_ok(stage, 7, fcntl(file, F_GETLK, arena(OFF_M9C_FLOCK) as u64));
    check(stage, 7, flock_type(OFF_M9C_FLOCK) == F_UNLCK);
    m9c_command(stage, 8);

    // step 8: flock conflicts with flock, but the POSIX domain is independent
    // in both directions.
    expect_ok(stage, 8, flock(file, LOCK_EX));
    m9c_command(stage, 9);
    expect_ok(stage, 8, flock(file, LOCK_UN));
    m9c_command(stage, 10);
    put_flock(OFF_M9C_FLOCK, F_WRLCK, 0, 0, 0);
    expect_ok(stage, 8, fcntl(file, F_SETLK, arena(OFF_M9C_FLOCK) as u64));
    put_flock(OFF_M9C_FLOCK, F_UNLCK, 0, 0, 0);
    expect_ok(stage, 8, fcntl(file, F_SETLK, arena(OFF_M9C_FLOCK) as u64));

    // step 9: the peer exits through the protocol; the parent reaps it, checks
    // the zero exit status and prints the marker exactly once.
    // The exit command is its own synchronization point: the peer reports
    // `exit_group(0)` and never acknowledges it, so broadcast it without
    // waiting for an ack and let the blocking `wait4(-1)` below be the sync.
    expect_value(stage, 11, kill(-1, SIGUSR2), 0);
    let mut status = 0i32;
    let mut reaped = 0i64;
    let mut attempts = 0u64;
    while attempts < M9C_ACK_TICKS {
        let result = wait4(-1, &mut status, 0, 0);
        if result > 0 {
            reaped = result;
            break;
        }
        check(stage, 12, result == -EINTR);
        attempts += 1;
    }
    check(stage, 12, reaped > 0);
    expect_value(stage, 12, status as i64, 0);
    expect_ok(stage, 12, close(file));
    expect_ok(stage, 12, close(duplicate));
    expect_ok(stage, 12, close(cloexec));
    write_raw(MARK_M9C_LOCKS);
}

// ---------------------------------------------------------------------------
// Panic.
// ---------------------------------------------------------------------------

#[panic_handler]
fn panic(_info: &PanicInfo<'_>) -> ! {
    write_raw(b"[CaelumLinux] FAIL panic\n");
    exit_group(0x7f)
}
