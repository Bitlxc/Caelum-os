//! Wire layouts for Linux `sendmsg`/`recvmsg` (M9b).
//!
//! The personality parses the x86-64 System V socket message layouts byte by
//! byte; the kernel never maps a user `struct msghdr` directly. Everything in
//! this module is pure: it takes `&[u8]` copies that the caller obtained
//! through `addrspace::copy_in`, so the parser can be host-tested without an
//! address space.
//!
//! ```text
//! struct msghdr {           // 56 bytes on x86-64
//!     void         *msg_name;        // +0
//!     socklen_t     msg_namelen;     // +8  (u32, 4 bytes hole after it)
//!     struct iovec *msg_iov;         // +16
//!     size_t        msg_iovlen;      // +24
//!     void         *msg_control;     // +32
//!     size_t        msg_controllen;  // +40
//!     int           msg_flags;       // +48
//! };
//! struct iovec { void *iov_base; size_t iov_len; };          // 16 bytes
//! struct cmsghdr { size_t cmsg_len; int cmsg_level; int cmsg_type; }; // 16
//! struct ucred { pid_t pid; uid_t uid; gid_t gid; };          // 12 bytes
//! ```
//!
//! Control messages are walked with the [`CmsgIter`]; the parser enforces the
//! alignment rules (`CMSG_ALIGN`) so a malformed buffer can never make the
//! kernel read outside the copy the caller validated.

use super::errno;

/// `sizeof(struct msghdr)` on x86-64.
pub const MSGHDR_SIZE: usize = 56;
/// `sizeof(struct iovec)`.
pub const IOVEC_SIZE: usize = 16;
/// `sizeof(struct cmsghdr)`.
pub const CMSG_HDR_SIZE: usize = 16;
/// `sizeof(struct ucred)`.
pub const UCRED_SIZE: usize = 12;

/// Offset of `msg_namelen` inside `struct msghdr`.
pub const MSGHDR_NAMELEN_OFFSET: usize = 8;
/// Offset of `msg_flags` inside `struct msghdr`.
pub const MSGHDR_FLAGS_OFFSET: usize = 48;

/// Largest scatter/gather vector the personality walks in one call.
///
/// Linux allows `IOV_MAX` (1024) entries; the personality keeps a much smaller
/// bounded copy so one call cannot pin unbounded user memory, and reports
/// `EINVAL` above the limit instead of silently truncating.
pub const IOV_MAX_MINI: usize = 8;
/// Largest payload moved through the per-call bounce buffer.
pub const MSG_IO_MAX: usize = 1024;
/// Largest control buffer the personality accepts or produces.
pub const MSG_CONTROL_MAX: usize = 64;
/// Largest `SCM_RIGHTS` fd array accepted in one message.
pub const SCM_MAX_FD: usize = 4;

/// `MSG_OOB` (not supported, rejected).
pub const MSG_OOB: i32 = 0x1;
/// `MSG_PEEK` (not supported, rejected).
pub const MSG_PEEK: i32 = 0x2;
/// `MSG_CTRUNC`: control data was truncated on receive.
pub const MSG_CTRUNC: i32 = 0x8;
/// `MSG_TRUNC`: payload was truncated on receive.
pub const MSG_TRUNC: i32 = 0x20;
/// `MSG_DONTWAIT`: one-shot non-blocking operation.
pub const MSG_DONTWAIT: i32 = 0x40;
/// `MSG_WAITALL` (not supported, rejected).
pub const MSG_WAITALL: i32 = 0x100;
/// `MSG_NOSIGNAL`: accepted as a no-op hint; the kernel never raises SIGPIPE.
pub const MSG_NOSIGNAL: i32 = 0x4000;

/// `SOL_SOCKET` option level.
pub const SOL_SOCKET: i32 = 1;
/// `SCM_RIGHTS` control message type.
pub const SCM_RIGHTS: i32 = 1;
/// `SCM_CREDENTIALS` control message type.
pub const SCM_CREDENTIALS: i32 = 2;
/// `SO_PASSCRED` option number.
pub const SO_PASSCRED: u64 = 16;
/// `SO_PEERCRED` option number.
pub const SO_PEERCRED: u64 = 17;

/// Flags a `sendmsg` call may pass; everything else is reported as unsupported.
pub const SENDMSG_ALLOWED_FLAGS: i32 = MSG_DONTWAIT | MSG_NOSIGNAL;
/// Flags a `recvmsg` call may pass.
pub const RECVMSG_ALLOWED_FLAGS: i32 = MSG_DONTWAIT;

/// A decoded `struct msghdr`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MsgHdr {
    /// User pointer to the optional address buffer.
    pub name: u64,
    /// Capacity of the address buffer.
    pub namelen: u32,
    /// User pointer to the iovec array.
    pub iov: u64,
    /// Number of iovec entries.
    pub iovlen: u64,
    /// User pointer to the control buffer.
    pub control: u64,
    /// Capacity of the control buffer.
    pub controllen: u64,
    /// `msg_flags` field (input only; output is written back separately).
    pub flags: i32,
}

/// One control message.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Cmsg<'a> {
    /// `cmsg_level`.
    pub level: i32,
    /// `cmsg_type`.
    pub kind: i32,
    /// Payload bytes (without the header, without alignment padding).
    pub data: &'a [u8],
}

/// One `SCM_CREDENTIALS` payload.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ucred {
    /// Sender process id.
    pub pid: i32,
    /// Sender user id (always 0: the personality has no uid model yet).
    pub uid: u32,
    /// Sender group id (always 0).
    pub gid: u32,
}

impl Ucred {
    /// The credential the current process presents.
    pub const fn current(pid: i32) -> Self {
        Self {
            pid,
            uid: 0,
            gid: 0,
        }
    }
}

/// Decode a copied `struct msghdr`.
pub fn decode_msghdr(raw: &[u8]) -> Result<MsgHdr, i64> {
    if raw.len() < MSGHDR_SIZE {
        return Err(errno::EINVAL);
    }
    let qword = |offset: usize| {
        u64::from_le_bytes([
            raw[offset],
            raw[offset + 1],
            raw[offset + 2],
            raw[offset + 3],
            raw[offset + 4],
            raw[offset + 5],
            raw[offset + 6],
            raw[offset + 7],
        ])
    };
    Ok(MsgHdr {
        name: qword(0),
        namelen: u32::from_le_bytes([raw[8], raw[9], raw[10], raw[11]]),
        iov: qword(16),
        iovlen: qword(24),
        control: qword(32),
        controllen: qword(40),
        flags: i32::from_le_bytes([raw[48], raw[49], raw[50], raw[51]]),
    })
}

/// Encode a `struct msghdr` (used by tests and by the receive-side name write).
pub fn encode_msghdr(header: &MsgHdr) -> [u8; MSGHDR_SIZE] {
    let mut raw = [0u8; MSGHDR_SIZE];
    raw[0..8].copy_from_slice(&header.name.to_le_bytes());
    raw[8..12].copy_from_slice(&header.namelen.to_le_bytes());
    raw[16..24].copy_from_slice(&header.iov.to_le_bytes());
    raw[24..32].copy_from_slice(&header.iovlen.to_le_bytes());
    raw[32..40].copy_from_slice(&header.control.to_le_bytes());
    raw[40..48].copy_from_slice(&header.controllen.to_le_bytes());
    raw[48..52].copy_from_slice(&header.flags.to_le_bytes());
    raw
}

/// Decode one `struct iovec` from a copied array.
pub fn decode_iovec(raw: &[u8]) -> Result<(u64, u64), i64> {
    if raw.len() < IOVEC_SIZE {
        return Err(errno::EINVAL);
    }
    let base = u64::from_le_bytes([
        raw[0], raw[1], raw[2], raw[3], raw[4], raw[5], raw[6], raw[7],
    ]);
    let len = u64::from_le_bytes([
        raw[8], raw[9], raw[10], raw[11], raw[12], raw[13], raw[14], raw[15],
    ]);
    Ok((base, len))
}

/// Accumulate one iovec length into the running total, rejecting overflow.
pub fn accumulate_iov(total: &mut u64, len: u64) -> Result<(), i64> {
    *total = total.checked_add(len).ok_or(errno::EINVAL)?;
    Ok(())
}

/// Validate the `msg_iovlen` field against the bounded copy.
pub fn check_iovlen(iovlen: u64) -> Result<usize, i64> {
    let count = usize::try_from(iovlen).map_err(|_| errno::EINVAL)?;
    if count > IOV_MAX_MINI {
        return Err(errno::EINVAL);
    }
    Ok(count)
}

/// Validate `sendmsg` flags: only `MSG_DONTWAIT`/`MSG_NOSIGNAL` are supported.
pub fn check_send_flags(flags: i32) -> Result<i32, i64> {
    if flags & !SENDMSG_ALLOWED_FLAGS != 0 {
        return Err(errno::EOPNOTSUPP);
    }
    Ok(flags)
}

/// Validate `recvmsg` flags: only `MSG_DONTWAIT` is supported.
pub fn check_recv_flags(flags: i32) -> Result<i32, i64> {
    if flags & !RECVMSG_ALLOWED_FLAGS != 0 {
        return Err(errno::EOPNOTSUPP);
    }
    Ok(flags)
}

/// `CMSG_ALIGN`: round a control-message length up to the ABI boundary.
pub const fn cmsg_align(length: usize) -> usize {
    (length + 7) & !7
}

/// Bytes of control buffer needed for a payload.
pub const fn cmsg_space(payload: usize) -> usize {
    cmsg_align(CMSG_HDR_SIZE + payload)
}

/// Iterator over a copied control buffer.
///
/// A malformed buffer (short header, `cmsg_len` below the header size, a length
/// beyond the buffer, or a padded length beyond the buffer) fails with
/// `EINVAL`; it never reads memory the caller did not validate.
pub struct CmsgIter<'a> {
    control: &'a [u8],
    offset: usize,
}

impl<'a> CmsgIter<'a> {
    /// Start walking a control buffer.
    pub const fn new(control: &'a [u8]) -> Self {
        Self { control, offset: 0 }
    }

    /// The next control message, if any.
    pub fn next(&mut self) -> Result<Option<Cmsg<'a>>, i64> {
        let remaining = &self.control[self.offset..];
        if remaining.is_empty() {
            return Ok(None);
        }
        if remaining.len() < CMSG_HDR_SIZE {
            return Err(errno::EINVAL);
        }
        let length = u64::from_le_bytes([
            remaining[0],
            remaining[1],
            remaining[2],
            remaining[3],
            remaining[4],
            remaining[5],
            remaining[6],
            remaining[7],
        ]);
        let length = usize::try_from(length).map_err(|_| errno::EINVAL)?;
        if length < CMSG_HDR_SIZE || length > remaining.len() {
            return Err(errno::EINVAL);
        }
        let aligned = cmsg_align(length);
        if aligned > remaining.len() {
            return Err(errno::EINVAL);
        }
        let level = i32::from_le_bytes([remaining[8], remaining[9], remaining[10], remaining[11]]);
        let kind = i32::from_le_bytes([remaining[12], remaining[13], remaining[14], remaining[15]]);
        let data = &remaining[CMSG_HDR_SIZE..length];
        self.offset += aligned;
        Ok(Some(Cmsg { level, kind, data }))
    }
}

/// Decode an `SCM_RIGHTS` payload into up to [`SCM_MAX_FD`] fds.
///
/// Returns the number of descriptors. A payload that is not a whole number of
/// `int`s is `EINVAL`; more than [`SCM_MAX_FD`] descriptors is `EMSGSIZE`
/// (Linux would accept more, the bounded personality does not).
pub fn parse_scm_rights(data: &[u8], out: &mut [i32; SCM_MAX_FD]) -> Result<usize, i64> {
    if data.len() % 4 != 0 {
        return Err(errno::EINVAL);
    }
    let count = data.len() / 4;
    if count > SCM_MAX_FD {
        return Err(errno::EMSGSIZE);
    }
    for (index, chunk) in data.chunks_exact(4).enumerate() {
        out[index] = i32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
    }
    Ok(count)
}

/// Decode an `SCM_CREDENTIALS` payload.
pub fn parse_ucred(data: &[u8]) -> Result<Ucred, i64> {
    if data.len() != UCRED_SIZE {
        return Err(errno::EINVAL);
    }
    Ok(Ucred {
        pid: i32::from_le_bytes([data[0], data[1], data[2], data[3]]),
        uid: u32::from_le_bytes([data[4], data[5], data[6], data[7]]),
        gid: u32::from_le_bytes([data[8], data[9], data[10], data[11]]),
    })
}

/// Encode an `SCM_CREDENTIALS` payload.
pub fn encode_ucred(credential: &Ucred) -> [u8; UCRED_SIZE] {
    let mut raw = [0u8; UCRED_SIZE];
    raw[0..4].copy_from_slice(&credential.pid.to_le_bytes());
    raw[4..8].copy_from_slice(&credential.uid.to_le_bytes());
    raw[8..12].copy_from_slice(&credential.gid.to_le_bytes());
    raw
}

/// Append one control message to `out` starting at `cursor`.
///
/// Returns `false` when the aligned message does not fit; the caller then sets
/// `MSG_CTRUNC` and must not install any descriptors that belong to the
/// message it could not deliver.
pub fn push_cmsg(
    out: &mut [u8],
    cursor: &mut usize,
    level: i32,
    kind: i32,
    payload: &[u8],
) -> bool {
    let length = CMSG_HDR_SIZE + payload.len();
    let space = cmsg_align(length);
    if *cursor + space > out.len() {
        return false;
    }
    out[*cursor..*cursor + 8].copy_from_slice(&(length as u64).to_le_bytes());
    out[*cursor + 8..*cursor + 12].copy_from_slice(&level.to_le_bytes());
    out[*cursor + 12..*cursor + 16].copy_from_slice(&kind.to_le_bytes());
    out[*cursor + 16..*cursor + length].copy_from_slice(payload);
    out[*cursor + length..*cursor + space].fill(0);
    *cursor += space;
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_msghdr() -> MsgHdr {
        MsgHdr {
            name: 0x1000,
            namelen: 16,
            iov: 0x2000,
            iovlen: 2,
            control: 0x3000,
            controllen: 32,
            flags: 0,
        }
    }

    #[test]
    fn msghdr_round_trips_and_rejects_short_copies() {
        let mut raw = encode_msghdr(&sample_msghdr());
        assert_eq!(raw.len(), MSGHDR_SIZE);
        assert_eq!(decode_msghdr(&raw), Ok(sample_msghdr()));
        raw[8..12].copy_from_slice(&110u32.to_le_bytes());
        assert_eq!(decode_msghdr(&raw).unwrap().namelen, 110);
        assert_eq!(decode_msghdr(&raw[..MSGHDR_SIZE - 1]), Err(errno::EINVAL));
    }

    #[test]
    fn iovec_decoding_checks_length_and_overflow() {
        let mut raw = [0u8; IOVEC_SIZE];
        raw[0..8].copy_from_slice(&0x4000u64.to_le_bytes());
        raw[8..16].copy_from_slice(&64u64.to_le_bytes());
        assert_eq!(decode_iovec(&raw), Ok((0x4000, 64)));
        let mut total = 0u64;
        assert_eq!(accumulate_iov(&mut total, 64), Ok(()));
        assert_eq!(total, 64);
        assert_eq!(accumulate_iov(&mut total, u64::MAX), Err(errno::EINVAL));
        assert_eq!(check_iovlen(0), Ok(0));
        assert_eq!(check_iovlen(IOV_MAX_MINI as u64), Ok(IOV_MAX_MINI));
        assert_eq!(check_iovlen(IOV_MAX_MINI as u64 + 1), Err(errno::EINVAL));
        assert_eq!(decode_iovec(&raw[..8]), Err(errno::EINVAL));
    }

    #[test]
    fn cmsg_iteration_skips_alignment_padding() {
        let mut control = [0u8; 64];
        let mut cursor = 0usize;
        assert!(push_cmsg(
            &mut control,
            &mut cursor,
            SOL_SOCKET,
            SCM_RIGHTS,
            &[3, 0, 0, 0]
        ));
        assert!(push_cmsg(
            &mut control,
            &mut cursor,
            SOL_SOCKET,
            SCM_CREDENTIALS,
            &encode_ucred(&Ucred::current(7)),
        ));
        assert_eq!(cursor, cmsg_space(4) + cmsg_space(UCRED_SIZE));

        let mut iter = CmsgIter::new(&control[..cursor]);
        let first = iter.next().unwrap().unwrap();
        assert_eq!((first.level, first.kind), (SOL_SOCKET, SCM_RIGHTS));
        let mut fds = [0i32; SCM_MAX_FD];
        assert_eq!(parse_scm_rights(first.data, &mut fds), Ok(1));
        assert_eq!(fds[0], 3);

        let second = iter.next().unwrap().unwrap();
        assert_eq!((second.level, second.kind), (SOL_SOCKET, SCM_CREDENTIALS));
        assert_eq!(parse_ucred(second.data), Ok(Ucred::current(7)));
        assert!(iter.next().unwrap().is_none());
    }

    #[test]
    fn malformed_control_buffers_are_rejected() {
        // Header shorter than the buffer but length below the header.
        let mut control = [0u8; 32];
        control[0..8].copy_from_slice(&15u64.to_le_bytes());
        assert_eq!(CmsgIter::new(&control).next(), Err(errno::EINVAL));

        // Length beyond the buffer.
        control[0..8].copy_from_slice(&25u64.to_le_bytes());
        assert_eq!(CmsgIter::new(&control[..24]).next(), Err(errno::EINVAL));

        // Trailing bytes that are too short to be a header.
        assert_eq!(CmsgIter::new(&[0u8; 8]).next(), Err(errno::EINVAL));

        // Empty control buffer is valid (no messages).
        assert_eq!(CmsgIter::new(&[]).next(), Ok(None));
    }

    #[test]
    fn scm_rights_and_ucred_lengths_are_validated() {
        let mut fds = [0i32; SCM_MAX_FD];
        assert_eq!(parse_scm_rights(&[], &mut fds), Ok(0));
        assert_eq!(parse_scm_rights(&[1, 0, 0, 0], &mut fds), Ok(1));
        assert_eq!(parse_scm_rights(&[1, 0], &mut fds), Err(errno::EINVAL));
        assert_eq!(
            parse_scm_rights(&[0u8; 4 * (SCM_MAX_FD + 1)], &mut fds),
            Err(errno::EMSGSIZE)
        );
        assert_eq!(parse_ucred(&[0u8; UCRED_SIZE - 1]), Err(errno::EINVAL));
        assert_eq!(parse_ucred(&[0u8; UCRED_SIZE + 1]), Err(errno::EINVAL));
    }

    #[test]
    fn control_space_and_cursor_rejection_are_exact() {
        assert_eq!(cmsg_space(0), 16);
        assert_eq!(cmsg_space(4), 24);
        assert_eq!(cmsg_space(12), 32);
        assert_eq!(cmsg_align(17), 24);
        let mut small = [0u8; 16];
        let mut cursor = 0usize;
        assert!(!push_cmsg(
            &mut small,
            &mut cursor,
            SOL_SOCKET,
            SCM_RIGHTS,
            &[1, 0, 0, 0]
        ));
        assert_eq!(cursor, 0);
    }

    #[test]
    fn flags_are_validated_against_the_supported_set() {
        assert_eq!(check_send_flags(0), Ok(0));
        assert_eq!(check_send_flags(MSG_DONTWAIT), Ok(MSG_DONTWAIT));
        assert_eq!(check_send_flags(MSG_PEEK), Err(errno::EOPNOTSUPP));
        assert_eq!(check_send_flags(MSG_WAITALL), Err(errno::EOPNOTSUPP));
        assert_eq!(check_send_flags(MSG_OOB), Err(errno::EOPNOTSUPP));
        assert_eq!(check_recv_flags(MSG_DONTWAIT), Ok(MSG_DONTWAIT));
        assert_eq!(check_recv_flags(MSG_TRUNC), Err(errno::EOPNOTSUPP));
    }
}
