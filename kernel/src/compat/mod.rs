//! ABI compatibility personalities (M7d).
//!
//! A personality translates one foreign system-call ABI onto the native kernel
//! objects and services. The tree is mounted and wired into the syscall entry
//! since M7d: when the current thread's personality is
//! [`crate::process::Personality::Linux64`], `kernel/src/syscall.rs` dispatches
//! through [`linux::syscall`] before the native AP whitelist and the native
//! number match.
//!
//! - [`linux`]: the Linux x86-64 personality core (descriptor table, socket
//!   address layouts, errno mapping, initial stack and the socket system call
//!   dispatch). Its process-side interfaces (`Personality`, the embedded
//!   `FdTable`, the current Linux network namespace and the blocking replay)
//!   are provided by the process layer; see [`linux::syscall`] for the exact
//!   integration points.

pub mod linux;
