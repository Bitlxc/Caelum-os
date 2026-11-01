//! Linux file-lock wire formats and range normalisation (M9c).
//!
//! The Linux lock ABI is split into two users:
//!
//! - `fcntl(F_SETLK/F_SETLKW/F_GETLK)` uses a 32-byte `struct flock`:
//!   `l_type` (2 bytes, 0 = read lock / 1 = write lock / 2 = unlock),
//!   `l_whence` (2 bytes, `SEEK_SET/CUR/END`), 4 bytes of padding, then
//!   `l_start`, `l_len`, `l_pid`. This module only parses/encodes the image and
//!   normalises it into a `(start, length)` byte range; the actual lock table is
//!   the VFS (`vfs::lock_open`/`vfs::lock_probe`/`vfs::unlock_open`).
//! - `flock(2)` uses an operation word: `LOCK_SH`/`LOCK_EX`/`LOCK_UN` plus the
//!   optional `LOCK_NB` flag.
//!
//! Range rules follow POSIX:
//!
//! - `l_len == 0` means "from `l_start` to end of file" (encoded as length `0`
//!   and interpreted by the VFS).
//! - `l_len < 0` locks the range `[l_start + l_len, l_start)`, i.e. the start is
//!   moved forward and the length made positive.
//! - the absolute start must not be negative; a negative range therefore fails
//!   with `EINVAL` rather than wrapping.

use super::errno;

/// `sizeof(struct flock)` on Linux64.
pub const FLOCK_SIZE: usize = 32;
/// Offset of `l_type` in `struct flock`.
pub const FLOCK_TYPE_OFFSET: usize = 0;
/// Offset of `l_start`.
pub const FLOCK_START_OFFSET: usize = 8;
/// Offset of `l_len`.
pub const FLOCK_LEN_OFFSET: usize = 16;
/// Offset of `l_pid`.
pub const FLOCK_PID_OFFSET: usize = 24;

/// `F_RDLCK`.
pub const F_RDLCK: u16 = 0;
/// `F_WRLCK`.
pub const F_WRLCK: u16 = 1;
/// `F_UNLCK`.
pub const F_UNLCK: u16 = 2;

/// `SEEK_SET`.
pub const SEEK_SET: u16 = 0;
/// `SEEK_CUR`.
pub const SEEK_CUR: u16 = 1;
/// `SEEK_END`.
pub const SEEK_END: u16 = 2;

/// `LOCK_SH`.
pub const LOCK_SH: u32 = 1;
/// `LOCK_EX`.
pub const LOCK_EX: u32 = 2;
/// `LOCK_NB`.
pub const LOCK_NB: u32 = 4;
/// `LOCK_UN`.
pub const LOCK_UN: u32 = 8;

/// Lock type understood by `fcntl`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FlockType {
    /// `F_RDLCK`.
    Read,
    /// `F_WRLCK`.
    Write,
    /// `F_UNLCK`.
    Unlock,
}

impl FlockType {
    /// Whether `fcntl(F_GETLK)` accepts this type in the request image.
    pub const fn is_query_type(self) -> bool {
        matches!(self, FlockType::Read | FlockType::Write)
    }

    /// Wire value for this lock type.
    pub const fn wire(self) -> u16 {
        match self {
            FlockType::Read => F_RDLCK,
            FlockType::Write => F_WRLCK,
            FlockType::Unlock => F_UNLCK,
        }
    }
}

/// A decoded `struct flock`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Flock {
    /// `l_type`.
    pub kind: FlockType,
    /// `l_whence` (already validated to `SEEK_SET/CUR/END`).
    pub whence: u16,
    /// `l_start`.
    pub start: i64,
    /// `l_len`.
    pub len: i64,
    /// `l_pid` (ignored on input, filled by the kernel for `F_GETLK`).
    pub pid: i32,
}

impl Flock {
    /// Build a neutral request with no pid.
    pub const fn new(kind: FlockType, whence: u16, start: i64, len: i64) -> Self {
        Self {
            kind,
            whence,
            start,
            len,
            pid: 0,
        }
    }
}

/// Decode a Linux64 `struct flock` image.
pub fn decode_flock(image: &[u8]) -> Result<Flock, i64> {
    if image.len() < FLOCK_SIZE {
        return Err(errno::EINVAL);
    }
    let kind = match u16::from_le_bytes([image[FLOCK_TYPE_OFFSET], image[FLOCK_TYPE_OFFSET + 1]]) {
        F_RDLCK => FlockType::Read,
        F_WRLCK => FlockType::Write,
        F_UNLCK => FlockType::Unlock,
        _ => return Err(errno::EINVAL),
    };
    let whence = u16::from_le_bytes([image[FLOCK_TYPE_OFFSET + 2], image[FLOCK_TYPE_OFFSET + 3]]);
    if whence > SEEK_END {
        return Err(errno::EINVAL);
    }
    let start = i64::from_le_bytes(slice8(image, FLOCK_START_OFFSET));
    let len = i64::from_le_bytes(slice8(image, FLOCK_LEN_OFFSET));
    let pid = i32::from_le_bytes(slice4(image, FLOCK_PID_OFFSET));
    Ok(Flock {
        kind,
        whence,
        start,
        len,
        pid,
    })
}

/// Encode a `struct flock` image (used to answer `F_GETLK`).
pub fn encode_flock(flock: &Flock) -> [u8; FLOCK_SIZE] {
    let mut image = [0u8; FLOCK_SIZE];
    image[FLOCK_TYPE_OFFSET..FLOCK_TYPE_OFFSET + 2]
        .copy_from_slice(&flock.kind.wire().to_le_bytes());
    image[FLOCK_TYPE_OFFSET + 2..FLOCK_TYPE_OFFSET + 4]
        .copy_from_slice(&flock.whence.to_le_bytes());
    image[FLOCK_START_OFFSET..FLOCK_START_OFFSET + 8].copy_from_slice(&flock.start.to_le_bytes());
    image[FLOCK_LEN_OFFSET..FLOCK_LEN_OFFSET + 8].copy_from_slice(&flock.len.to_le_bytes());
    image[FLOCK_PID_OFFSET..FLOCK_PID_OFFSET + 4].copy_from_slice(&flock.pid.to_le_bytes());
    image
}

fn slice8(image: &[u8], offset: usize) -> [u8; 8] {
    let mut out = [0u8; 8];
    out.copy_from_slice(&image[offset..offset + 8]);
    out
}

fn slice4(image: &[u8], offset: usize) -> [u8; 4] {
    let mut out = [0u8; 4];
    out.copy_from_slice(&image[offset..offset + 4]);
    out
}

/// Normalise a `(whence, start, len)` triple into an absolute `(start, length)`.
///
/// `current` is the description's current byte offset (`SEEK_CUR` base) and
/// `size` the file size (`SEEK_END` base). A zero length means "to end of file"
/// and is passed through as `0`; a negative length selects the range that ends
/// at `start` (POSIX semantics).
pub fn resolve_range(
    whence: u16,
    start: i64,
    len: i64,
    current: u64,
    size: u64,
) -> Result<(u64, u64), i64> {
    let base = match whence {
        SEEK_SET => 0i64,
        SEEK_CUR => i64::try_from(current).map_err(|_| errno::EOVERFLOW)?,
        SEEK_END => i64::try_from(size).map_err(|_| errno::EOVERFLOW)?,
        _ => return Err(errno::EINVAL),
    };
    let absolute = base.checked_add(start).ok_or(errno::EOVERFLOW)?;
    if absolute < 0 {
        return Err(errno::EINVAL);
    }
    let absolute = absolute as u64;
    if len > 0 {
        let length = u64::try_from(len).map_err(|_| errno::EOVERFLOW)?;
        Ok((absolute, length))
    } else if len == 0 {
        Ok((absolute, 0))
    } else {
        let length = len.checked_neg().ok_or(errno::EOVERFLOW)?;
        let length = u64::try_from(length).map_err(|_| errno::EOVERFLOW)?;
        let start = absolute.checked_sub(length).ok_or(errno::EINVAL)?;
        Ok((start, length))
    }
}

/// A decoded `flock(2)` operation word.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FlockOperation {
    /// `LOCK_EX` (otherwise a shared lock is requested).
    pub exclusive: bool,
    /// `LOCK_UN`.
    pub unlock: bool,
    /// `LOCK_NB` (report `EAGAIN` instead of sleeping).
    pub nonblocking: bool,
}

/// Decode and validate a `flock(2)` operation word.
pub fn decode_flock_operation(raw: u64) -> Result<FlockOperation, i64> {
    let raw = u32::try_from(raw).map_err(|_| errno::EINVAL)?;
    if raw & !(LOCK_SH | LOCK_EX | LOCK_NB | LOCK_UN) != 0 {
        return Err(errno::EINVAL);
    }
    let shared = raw & LOCK_SH != 0;
    let exclusive = raw & LOCK_EX != 0;
    let unlock = raw & LOCK_UN != 0;
    // Exactly one of LOCK_SH/LOCK_EX/LOCK_UN selects the operation.
    if u8::from(shared) + u8::from(exclusive) + u8::from(unlock) != 1 {
        return Err(errno::EINVAL);
    }
    if shared && exclusive {
        return Err(errno::EINVAL);
    }
    Ok(FlockOperation {
        exclusive,
        unlock,
        nonblocking: raw & LOCK_NB != 0,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flock_images_decode_and_encode_byte_exactly() {
        let mut image = [0u8; FLOCK_SIZE];
        image[..2].copy_from_slice(&F_WRLCK.to_le_bytes());
        image[2..4].copy_from_slice(&SEEK_CUR.to_le_bytes());
        image[8..16].copy_from_slice(&16i64.to_le_bytes());
        image[16..24].copy_from_slice(&64i64.to_le_bytes());
        image[24..28].copy_from_slice(&42i32.to_le_bytes());
        let decoded = decode_flock(&image).expect("decode");
        assert_eq!(
            decoded,
            Flock {
                kind: FlockType::Write,
                whence: SEEK_CUR,
                start: 16,
                len: 64,
                pid: 42,
            }
        );
        assert_eq!(encode_flock(&decoded), image);
    }

    #[test]
    fn unknown_lock_types_and_whence_values_are_rejected() {
        let mut image = [0u8; FLOCK_SIZE];
        image[..2].copy_from_slice(&7u16.to_le_bytes());
        assert_eq!(decode_flock(&image), Err(errno::EINVAL));
        image[..2].copy_from_slice(&F_RDLCK.to_le_bytes());
        image[2..4].copy_from_slice(&9u16.to_le_bytes());
        assert_eq!(decode_flock(&image), Err(errno::EINVAL));
        assert_eq!(decode_flock(&[0u8; 8]), Err(errno::EINVAL));
    }

    #[test]
    fn ranges_normalise_from_set_cur_and_end() {
        assert_eq!(resolve_range(SEEK_SET, 8, 16, 0, 100), Ok((8, 16)));
        assert_eq!(resolve_range(SEEK_CUR, 8, 16, 33, 100), Ok((41, 16)));
        assert_eq!(resolve_range(SEEK_END, -8, 8, 0, 100), Ok((92, 8)));
        // Zero length keeps "to end of file" semantics for the VFS.
        assert_eq!(resolve_range(SEEK_SET, 8, 0, 0, 100), Ok((8, 0)));
        // A negative length selects the range ending at start.
        assert_eq!(resolve_range(SEEK_SET, 32, -8, 0, 100), Ok((24, 8)));
        // The range must not start before offset zero.
        assert_eq!(resolve_range(SEEK_CUR, -10, 4, 5, 100), Err(errno::EINVAL));
        assert_eq!(resolve_range(SEEK_SET, 0, -1, 0, 100), Err(errno::EINVAL));
    }

    #[test]
    fn flock_operation_words_are_validated() {
        assert_eq!(
            decode_flock_operation(u64::from(LOCK_SH)),
            Ok(FlockOperation {
                exclusive: false,
                unlock: false,
                nonblocking: false
            })
        );
        assert_eq!(
            decode_flock_operation(u64::from(LOCK_EX | LOCK_NB)),
            Ok(FlockOperation {
                exclusive: true,
                unlock: false,
                nonblocking: true
            })
        );
        assert_eq!(
            decode_flock_operation(u64::from(LOCK_UN)),
            Ok(FlockOperation {
                exclusive: false,
                unlock: true,
                nonblocking: false
            })
        );
        for bad in [
            u64::from(LOCK_SH | LOCK_EX),
            u64::from(LOCK_SH | LOCK_UN),
            0u64,
            0x10u64,
            u64::from(u32::MAX),
        ] {
            assert_eq!(decode_flock_operation(bad), Err(errno::EINVAL), "{bad:#x}");
        }
    }

    #[test]
    fn query_types_exclude_unlock() {
        assert!(FlockType::Read.is_query_type());
        assert!(FlockType::Write.is_query_type());
        assert!(!FlockType::Unlock.is_query_type());
    }
}
