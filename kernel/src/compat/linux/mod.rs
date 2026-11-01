//! Linux x86-64 personality core (M7d).
//!
//! This tree implements the Linux personality that a process carries once it is
//! spawned with [`crate::process::Personality::Linux64`]:
//!
//! - [`fd`]: the Linux file-descriptor table (`FdTable`/`FdEntry`). It owns its
//!   own numbering space, its own reference counts and the recorded socket
//!   family; it never shares native handle numbers or generations.
//! - [`address`]: `sockaddr_in`/`sockaddr_in6`/`sockaddr_un` parsing and
//!   serialisation plus conversion to and from `net::SocketAddress`.
//! - [`errno`]: the Linux error numbers plus the native-status translation.
//! - [`stack`]: the initial Linux process stack encoder (`argc`/`argv`/`envp`/
//!   `auxv`), including the Caelum auxv entries that carry the initial channel
//!   and network-namespace handles.
//! - [`syscall`]: the Linux64 system call dispatch table for the socket
//!   personality. It returns Linux `-errno` directly in `rax` (`Outcome::Done`);
//!   a call that cannot complete without sleeping reports the object to wait on
//!   (`Outcome::Wait`) instead of blocking inside the dispatch.
//!
//! - [`memory`]: the Linux64 memory slice (M8a): per-process program break and
//!   `mmap` bump pointer, `brk`/`mmap`/`munmap`/`mprotect` over the existing
//!   `mm::pmm` + `mm::addrspace` primitives (no second VM subsystem).
//!
//! - [`lock`]: the Linux file-lock wire formats (M9c): `struct flock` and the
//!   `flock(2)` operation word, plus the POSIX range normalisation. The lock
//!   table itself stays in the VFS; this module never records a lock.
//!
//! # Entry
//!
//! `kernel/src/syscall.rs` checks the current thread's personality **before** the
//! native AP whitelist and the native number match: a `Linux64` thread enters
//! [`syscall::dispatch`] with its own `FdTable`, the net-namespace object and
//! the current address space. `NR_EXIT`/`NR_EXIT_GROUP` are handled before the
//! fd guard is taken, and a blocking call drops the guard before sleeping; the
//! architecture entry stub then replays the same system call, so `rax` ends up
//! with the Linux result.
//!
//! [`stack::encode_initial_stack`] is called by `process::spawn_detached_linux`,
//! which owns placing the image on the user stack and the 16-byte alignment of
//! the initial `rsp`.

pub mod address;
pub mod errno;
pub mod fd;
pub mod lock;
pub mod memory;
pub mod msg;
pub mod signal;
pub mod stack;
pub mod syscall;

pub use fd::{FdEntry, FdTable};
