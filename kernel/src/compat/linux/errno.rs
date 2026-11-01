//! Linux error numbers and the native-status translation.
//!
//! The Linux personality returns `-errno` in `rax` directly; it never uses the
//! native `status`/`result` register pair. Every syscall handler in
//! [`super::syscall`] therefore returns either a non-negative Linux result or
//! `Err(errno)` with a positive error number taken from this module.

/// Operation not permitted.
pub const EPERM: i64 = 1;
/// No such file or directory.
pub const ENOENT: i64 = 2;
/// No such process.
pub const ESRCH: i64 = 3;
/// Interrupted system call.
pub const EINTR: i64 = 4;
/// I/O error.
pub const EIO: i64 = 5;
/// Bad file descriptor.
pub const EBADF: i64 = 9;
/// No child processes.
pub const ECHILD: i64 = 10;
/// Try again (non-blocking operation would block).
pub const EAGAIN: i64 = 11;
/// Cannot allocate memory.
pub const ENOMEM: i64 = 12;
/// Permission denied.
pub const EACCES: i64 = 13;
/// Bad address.
pub const EFAULT: i64 = 14;
/// Device or resource busy.
pub const EBUSY: i64 = 16;
/// File exists.
pub const EEXIST: i64 = 17;
/// Not a directory.
pub const ENOTDIR: i64 = 20;
/// Is a directory.
pub const EISDIR: i64 = 21;
/// Invalid argument.
pub const EINVAL: i64 = 22;
/// Too many open files in system.
pub const ENFILE: i64 = 23;
/// Too many open files (per process table full).
pub const EMFILE: i64 = 24;
/// No space left on device.
pub const ENOSPC: i64 = 28;
/// Illegal seek (the descriptor is not seekable).
pub const ESPIPE: i64 = 29;
/// Function not implemented.
pub const ENOSYS: i64 = 38;
/// Directory not empty.
pub const ENOTEMPTY: i64 = 39;
/// Socket operation on non-socket.
pub const ENOTSOCK: i64 = 88;
/// Protocol wrong type for socket.
pub const EPROTOTYPE: i64 = 91;
/// Protocol not supported.
pub const EPROTONOSUPPORT: i64 = 93;
/// Operation not supported.
pub const EOPNOTSUPP: i64 = 95;
/// Address family not supported by protocol.
pub const EAFNOSUPPORT: i64 = 97;
/// Address already in use.
pub const EADDRINUSE: i64 = 98;
/// Address not available.
pub const EADDRNOTAVAIL: i64 = 99;
/// Connection reset by peer.
pub const ECONNRESET: i64 = 104;
/// Transport endpoint is not connected.
pub const ENOTCONN: i64 = 107;
/// Connection timed out.
pub const ETIMEDOUT: i64 = 110;
/// Connection refused.
pub const ECONNREFUSED: i64 = 111;
/// Message too long.
pub const EMSGSIZE: i64 = 90;
/// Value too large for the defined data type.
pub const EOVERFLOW: i64 = 75;
/// Read-only file system.
pub const EROFS: i64 = 30;
/// File name too long.
pub const ENAMETOOLONG: i64 = 36;
/// No locks available (the global lock table is full).
pub const ENOLCK: i64 = 37;

/// Translate a native ABI status word into a positive Linux error number.
///
/// The Linux personality maps the native status codes onto the closest Linux
/// error rather than forwarding native numbers, so a Linux program never sees
/// a Caelum-specific code by accident. Unknown codes become [`EIO`].
pub fn from_native(status: u64) -> i64 {
    use native_abi::*;
    if status == 0 {
        return 0;
    }
    match status {
        ERR_BAD_HANDLE => EBADF,
        ERR_BAD_RIGHT => EACCES,
        ERR_BAD_POINTER => EFAULT,
        ERR_WOULD_BLOCK => EAGAIN,
        ERR_TIMEOUT => ETIMEDOUT,
        ERR_QUOTA => ENOMEM,
        ERR_NOT_FOUND => ENOENT,
        ERR_NOT_SUPPORTED => EOPNOTSUPP,
        ERR_EXISTS => EEXIST,
        ERR_BUSY => EBUSY,
        ERR_IO => EIO,
        ERR_CORRUPT => EIO,
        ERR_PEER_CLOSED => ENOTCONN,
        ERR_NOT_CONNECTED => ENOTCONN,
        ERR_CANCELLED => EINTR,
        ERR_CONNECTION_REFUSED => ECONNREFUSED,
        ERR_CONNECTION_RESET => ECONNRESET,
        ERR_IS_DIR => EISDIR,
        ERR_NOT_DIR => ENOTDIR,
        ERR_NO_SPACE => ENOSPC,
        ERR_NOT_EMPTY => ENOTEMPTY,
        ERR_TOO_LARGE => EMSGSIZE,
        _ => EIO,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn linux_error_numbers_match_the_abi() {
        assert_eq!(EBADF, 9);
        assert_eq!(EAGAIN, 11);
        assert_eq!(EFAULT, 14);
        assert_eq!(EINVAL, 22);
        assert_eq!(ENOSYS, 38);
        assert_eq!(ENOTSOCK, 88);
        assert_eq!(EMSGSIZE, 90);
        assert_eq!(EPROTONOSUPPORT, 93);
        assert_eq!(EOPNOTSUPP, 95);
        assert_eq!(EAFNOSUPPORT, 97);
        assert_eq!(EADDRINUSE, 98);
        assert_eq!(ECONNRESET, 104);
        assert_eq!(ENOTCONN, 107);
        assert_eq!(ETIMEDOUT, 110);
        assert_eq!(ECONNREFUSED, 111);
    }

    #[test]
    fn native_statuses_become_linux_errors() {
        assert_eq!(from_native(0), 0);
        assert_eq!(from_native(native_abi::ERR_BAD_HANDLE), EBADF);
        assert_eq!(from_native(native_abi::ERR_BAD_POINTER), EFAULT);
        assert_eq!(from_native(native_abi::ERR_WOULD_BLOCK), EAGAIN);
        assert_eq!(from_native(native_abi::ERR_QUOTA), ENOMEM);
        assert_eq!(from_native(native_abi::ERR_PEER_CLOSED), ENOTCONN);
        assert_eq!(
            from_native(native_abi::ERR_CONNECTION_REFUSED),
            ECONNREFUSED
        );
        assert_eq!(from_native(native_abi::ERR_CORRUPT), EIO);
        assert_eq!(from_native(0xDEAD_BEEF), EIO);
    }
}
