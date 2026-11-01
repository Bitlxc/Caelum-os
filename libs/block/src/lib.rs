//! CaelumOS block-device abstraction.
//!
//! This crate is `no_std` and has zero dependencies. It is the single contract
//! between block drivers (`virtio-blk`, mem disk), filesystems (`fat32`,
//! `ext2`) and the M5b storage stack, so it is deliberately tiny:
//!
//! * [`BlockDevice`] — a synchronous, sector-addressed device.
//! * [`BlockError`] — the only error vocabulary a device may return.
//! * Range/buffer validation helpers so every implementation agrees on the
//!   edge cases.
//!
//! # Contract
//!
//! * A *block* is `block_size()` bytes. This crate does not assume 512; the
//!   sector size is whatever the device reports.
//! * Buffers passed to [`BlockDevice::read_blocks`] /
//!   [`BlockDevice::write_blocks`] **must be a whole, non-zero multiple of
//!   `block_size()`**; an implementation must return [`BlockError::BadBuffer`]
//!   otherwise (the [`BlockDevice::read_exact`] / `write_exact` provided
//!   methods do this check for the implementation).
//! * The transferred range is `block_count()` blocks starting at `first`.
//!   `first + count` must not overflow and must not exceed `block_count()`;
//!   an implementation must return [`BlockError::OutOfBounds`] otherwise.
//! * [`BlockError::ReadOnly`] means the device (or its backing image) rejects
//!   writes; [`BlockError::Io`] is "the device reported a failure",
//!   [`BlockError::Timeout`] means the driver gave up waiting,
//!   [`BlockError::Corrupt`] means the device/data is inconsistent and
//!   [`BlockError::Unsupported`] means the requested operation cannot be
//!   represented (e.g. a 4096-byte block device used where 512 is required).
//! * `flush()` must push every previously accepted write to stable storage;
//!   callers propagate its error, they never ignore it.
//!
//! `&mut D` implements [`BlockDevice`] for every `D: BlockDevice`, so
//! filesystems can borrow a device instead of taking ownership.

#![no_std]
#![forbid(unsafe_code)]

#[cfg(any(test, feature = "test-support"))]
extern crate std;

use core::fmt;

/// Everything that can go wrong at the block layer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlockError {
    /// The requested block range leaves the device.
    OutOfBounds,
    /// The buffer is empty or not a whole multiple of the block size.
    BadBuffer,
    /// The device reported a transfer failure.
    Io,
    /// The driver gave up waiting for the device.
    Timeout,
    /// The device is (currently) not writable.
    ReadOnly,
    /// The device or on-disk data is inconsistent.
    Corrupt,
    /// The operation cannot be represented on this device.
    Unsupported,
}

impl fmt::Display for BlockError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::OutOfBounds => "block range out of bounds",
            Self::BadBuffer => "buffer is not a whole number of blocks",
            Self::Io => "block device I/O error",
            Self::Timeout => "block device timeout",
            Self::ReadOnly => "block device is read-only",
            Self::Corrupt => "block device reported corrupt data",
            Self::Unsupported => "operation unsupported by the block device",
        };
        f.write_str(s)
    }
}

/// A synchronous, sector-addressed block device.
///
/// See the crate documentation for the exact validation rules; implementations
/// should use [`check_buffer`] and [`check_range`] (or the provided
/// [`BlockDevice::read_exact`] / [`BlockDevice::write_exact`]) instead of
/// re-deriving them.
pub trait BlockDevice {
    /// Size of one block (sector) in bytes. Must be a power of two and > 0.
    fn block_size(&self) -> u32;

    /// Total number of addressable blocks.
    fn block_count(&self) -> u64;

    /// Read `buf.len() / block_size()` blocks starting at block `first`.
    fn read_blocks(&mut self, first: u64, buf: &mut [u8]) -> Result<(), BlockError>;

    /// Write `buf.len() / block_size()` blocks starting at block `first`.
    fn write_blocks(&mut self, first: u64, buf: &[u8]) -> Result<(), BlockError>;

    /// Push all previously accepted writes to stable storage.
    fn flush(&mut self) -> Result<(), BlockError>;

    /// Device capacity in bytes (saturating, never overflows).
    fn byte_capacity(&self) -> u64 {
        self.block_count().saturating_mul(self.block_size() as u64)
    }

    /// Validated [`BlockDevice::read_blocks`].
    fn read_exact(&mut self, first: u64, buf: &mut [u8]) -> Result<(), BlockError> {
        let count = check_buffer(buf.len(), self.block_size())?;
        check_range(first, count, self.block_count())?;
        self.read_blocks(first, buf)
    }

    /// Validated [`BlockDevice::write_blocks`].
    fn write_exact(&mut self, first: u64, buf: &[u8]) -> Result<(), BlockError> {
        let count = check_buffer(buf.len(), self.block_size())?;
        check_range(first, count, self.block_count())?;
        self.write_blocks(first, buf)
    }
}

impl<D: BlockDevice + ?Sized> BlockDevice for &mut D {
    fn block_size(&self) -> u32 {
        (**self).block_size()
    }

    fn block_count(&self) -> u64 {
        (**self).block_count()
    }

    fn read_blocks(&mut self, first: u64, buf: &mut [u8]) -> Result<(), BlockError> {
        (**self).read_blocks(first, buf)
    }

    fn write_blocks(&mut self, first: u64, buf: &[u8]) -> Result<(), BlockError> {
        (**self).write_blocks(first, buf)
    }

    fn flush(&mut self) -> Result<(), BlockError> {
        (**self).flush()
    }
}

/// Validate a transfer buffer and return its length in blocks.
///
/// Fails with [`BlockError::BadBuffer`] when `buf_len` is zero, `block_size`
/// is zero, or `buf_len` is not a multiple of `block_size`.
pub fn check_buffer(buf_len: usize, block_size: u32) -> Result<u64, BlockError> {
    if block_size == 0 || buf_len == 0 {
        return Err(BlockError::BadBuffer);
    }
    let block_size = block_size as usize;
    if !buf_len.is_multiple_of(block_size) {
        return Err(BlockError::BadBuffer);
    }
    Ok((buf_len / block_size) as u64)
}

/// Validate `first..first + count` against `block_count`.
///
/// Fails with [`BlockError::OutOfBounds`] when the range is empty, overflows
/// or leaves the device.
pub fn check_range(first: u64, count: u64, block_count: u64) -> Result<(), BlockError> {
    let end = first.checked_add(count).ok_or(BlockError::OutOfBounds)?;
    if count == 0 || end > block_count {
        return Err(BlockError::OutOfBounds);
    }
    Ok(())
}

/// In-memory [`BlockDevice`] with fault injection, for host tests and xtask.
///
/// Enabled by the `test-support` feature (or `cfg(test)`). Backed by `std::vec`,
/// so it must never be enabled for kernel builds.
#[cfg(any(test, feature = "test-support"))]
pub mod test_support {
    use super::{BlockDevice, BlockError, check_buffer, check_range};
    use std::vec;
    use std::vec::Vec;

    /// How the next N operations behave.
    #[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
    pub struct Faults {
        /// Fail this many upcoming reads with `failure` and decrement.
        pub fail_reads: u32,
        /// Fail this many upcoming writes with `failure` and decrement.
        pub fail_writes: u32,
        /// Fail this many upcoming flushes with `failure` and decrement.
        pub fail_flushes: u32,
    }

    /// A RAM-backed block device plus counters and fault injection.
    #[derive(Debug, Clone)]
    pub struct MemDisk {
        data: Vec<u8>,
        block_size: u32,
        /// Error returned by injected failures.
        pub failure: BlockError,
        pub faults: Faults,
        pub read_only: bool,
        pub reads: u64,
        pub writes: u64,
        pub flushes: u64,
    }

    impl MemDisk {
        /// Create a zeroed device of `blocks * block_size` bytes.
        pub fn new(blocks: u64, block_size: u32) -> Self {
            assert!(block_size > 0);
            let len =
                usize::try_from(blocks).expect("disk too large for host") * block_size as usize;
            Self {
                data: vec![0u8; len],
                block_size,
                failure: BlockError::Io,
                faults: Faults::default(),
                read_only: false,
                reads: 0,
                writes: 0,
                flushes: 0,
            }
        }

        /// Create a device over an existing image (must be block-aligned).
        pub fn from_bytes(bytes: Vec<u8>, block_size: u32) -> Self {
            assert!(!bytes.is_empty() && bytes.len().is_multiple_of(block_size as usize));
            Self {
                data: bytes,
                block_size,
                failure: BlockError::Io,
                faults: Faults::default(),
                read_only: false,
                reads: 0,
                writes: 0,
                flushes: 0,
            }
        }

        /// The raw backing bytes.
        pub fn data(&self) -> &[u8] {
            &self.data
        }

        /// The raw backing bytes, mutably (test setup only).
        pub fn data_mut(&mut self) -> &mut [u8] {
            &mut self.data
        }

        /// Fail the next `n` reads/flushes with the current [`Self::failure`].
        pub fn fail_next_reads(&mut self, n: u32) {
            self.faults.fail_reads = n;
        }

        /// Fail the next `n` writes with the current [`Self::failure`].
        pub fn fail_next_writes(&mut self, n: u32) {
            self.faults.fail_writes = n;
        }

        /// Fail the next `n` flushes with the current [`Self::failure`].
        pub fn fail_next_flushes(&mut self, n: u32) {
            self.faults.fail_flushes = n;
        }
    }

    impl BlockDevice for MemDisk {
        fn block_size(&self) -> u32 {
            self.block_size
        }

        fn block_count(&self) -> u64 {
            self.data.len() as u64 / self.block_size as u64
        }

        fn read_blocks(&mut self, first: u64, buf: &mut [u8]) -> Result<(), BlockError> {
            let count = check_buffer(buf.len(), self.block_size)?;
            check_range(first, count, self.block_count())?;
            if self.faults.fail_reads > 0 {
                self.faults.fail_reads -= 1;
                return Err(self.failure);
            }
            let at = first as usize * self.block_size as usize;
            buf.copy_from_slice(&self.data[at..at + buf.len()]);
            self.reads += 1;
            Ok(())
        }

        fn write_blocks(&mut self, first: u64, buf: &[u8]) -> Result<(), BlockError> {
            let count = check_buffer(buf.len(), self.block_size)?;
            check_range(first, count, self.block_count())?;
            if self.faults.fail_writes > 0 {
                self.faults.fail_writes -= 1;
                return Err(self.failure);
            }
            if self.read_only {
                return Err(BlockError::ReadOnly);
            }
            let at = first as usize * self.block_size as usize;
            self.data[at..at + buf.len()].copy_from_slice(buf);
            self.writes += 1;
            Ok(())
        }

        fn flush(&mut self) -> Result<(), BlockError> {
            if self.faults.fail_flushes > 0 {
                self.faults.fail_flushes -= 1;
                return Err(self.failure);
            }
            self.flushes += 1;
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::{Faults, MemDisk};
    use super::*;

    /// Minimal device that records calls and never validates: used to prove the
    /// provided `read_exact`/`write_exact` wrappers enforce the contract even
    /// when an implementation is sloppy.
    struct Raw {
        blocks: u64,
        reads: u32,
        writes: u32,
    }

    impl BlockDevice for Raw {
        fn block_size(&self) -> u32 {
            512
        }

        fn block_count(&self) -> u64 {
            self.blocks
        }

        fn read_blocks(&mut self, _first: u64, _buf: &mut [u8]) -> Result<(), BlockError> {
            self.reads += 1;
            Ok(())
        }

        fn write_blocks(&mut self, _first: u64, _buf: &[u8]) -> Result<(), BlockError> {
            self.writes += 1;
            Ok(())
        }

        fn flush(&mut self) -> Result<(), BlockError> {
            Ok(())
        }
    }

    #[test]
    fn memdisk_roundtrip_and_accounting() {
        let mut disk = MemDisk::new(8, 512);
        assert_eq!(disk.byte_capacity(), 4096);
        let buf = [0xAB; 1024];
        disk.write_exact(2, &buf).unwrap();
        assert_eq!(disk.writes, 1);
        let mut back = [0u8; 1024];
        disk.read_exact(2, &mut back).unwrap();
        assert_eq!(back, buf);
        assert_eq!(disk.reads, 1);
        disk.flush().unwrap();
        assert_eq!(disk.flushes, 1);
        // The bytes really landed at offset 2 blocks, not 0.
        assert_eq!(&disk.data()[0..1024], &[0u8; 1024]);
        assert_eq!(&disk.data()[1024..2048], &buf);
    }

    #[test]
    fn memdisk_rejects_bad_requests() {
        let mut disk = MemDisk::new(4, 512);
        let mut short = [0u8; 100];
        assert_eq!(disk.read_blocks(0, &mut short), Err(BlockError::BadBuffer));
        let mut empty: [u8; 0] = [];
        assert_eq!(disk.read_blocks(0, &mut empty), Err(BlockError::BadBuffer));
        let mut block = [0u8; 512];
        assert_eq!(
            disk.read_blocks(4, &mut block),
            Err(BlockError::OutOfBounds)
        );
        assert_eq!(
            disk.write_blocks(u64::MAX, &mut block),
            Err(BlockError::OutOfBounds)
        );
        assert_eq!(disk.read_exact(3, &mut block), Ok(()));
    }

    #[test]
    fn fault_injection_is_counted() {
        let mut disk = MemDisk::new(4, 512);
        disk.failure = BlockError::Timeout;
        disk.fail_next_reads(1);
        disk.fail_next_writes(2);
        disk.fail_next_flushes(1);
        let mut block = [0u8; 512];
        assert_eq!(disk.read_blocks(0, &mut block), Err(BlockError::Timeout));
        assert_eq!(disk.read_blocks(0, &mut block), Ok(()));
        assert_eq!(disk.write_blocks(0, &block), Err(BlockError::Timeout));
        assert_eq!(disk.write_blocks(0, &block), Err(BlockError::Timeout));
        assert_eq!(disk.write_blocks(0, &block), Ok(()));
        assert_eq!(disk.flush(), Err(BlockError::Timeout));
        assert_eq!(disk.flush(), Ok(()));
        assert_eq!(disk.faults, Faults::default());
    }

    #[test]
    fn read_only_device_reports_read_only() {
        let mut disk = MemDisk::new(4, 512);
        disk.read_only = true;
        let block = [0u8; 512];
        assert_eq!(disk.write_blocks(0, &block), Err(BlockError::ReadOnly));
        assert_eq!(disk.write_exact(0, &block), Err(BlockError::ReadOnly));
        let mut buf = [0u8; 512];
        assert_eq!(disk.read_blocks(0, &mut buf), Ok(()));
    }

    #[test]
    fn mutable_reference_is_a_block_device() {
        let mut disk = MemDisk::new(4, 512);
        let mut buf = [1u8; 512];
        {
            let by_ref: &mut MemDisk = &mut disk;
            by_ref.write_exact(1, &buf).unwrap();
            assert_eq!(by_ref.read_exact(1, &mut [0u8; 512]), Ok(()));
        }
        assert_eq!(&disk.data()[512..1024], &buf[..]);
        buf[0] = 2;
        disk.write_exact(1, &buf).unwrap();
        assert_eq!(disk.data()[512], 2);
    }

    #[test]
    fn helpers_reject_empty_and_overflowing_ranges() {
        assert_eq!(check_buffer(0, 512), Err(BlockError::BadBuffer));
        assert_eq!(check_buffer(512, 0), Err(BlockError::BadBuffer));
        assert_eq!(check_buffer(513, 512), Err(BlockError::BadBuffer));
        assert_eq!(check_buffer(1024, 512), Ok(2));
        assert_eq!(check_range(0, 0, 10), Err(BlockError::OutOfBounds));
        assert_eq!(check_range(10, 1, 10), Err(BlockError::OutOfBounds));
        assert_eq!(check_range(9, 1, 10), Ok(()));
        assert_eq!(check_range(u64::MAX, 1, 10), Err(BlockError::OutOfBounds));
    }

    #[test]
    fn provided_wrappers_validate_before_calling_the_device() {
        let mut raw = Raw {
            blocks: 2,
            reads: 0,
            writes: 0,
        };
        let mut block = [0u8; 512];
        assert_eq!(raw.read_exact(0, &mut block), Ok(()));
        assert_eq!(raw.reads, 1);
        assert_eq!(raw.read_exact(2, &mut block), Err(BlockError::OutOfBounds));
        assert_eq!(raw.reads, 1, "device must not be touched on bad range");
        let short = [0u8; 511];
        assert_eq!(raw.write_exact(0, &short), Err(BlockError::BadBuffer));
        assert_eq!(raw.writes, 0);
    }

    #[test]
    fn errors_display_and_derive() {
        assert_eq!(BlockError::Io, BlockError::Io);
        assert_ne!(BlockError::Io, BlockError::Timeout);
        let mut text = std::string::String::new();
        for e in [
            BlockError::OutOfBounds,
            BlockError::BadBuffer,
            BlockError::Io,
            BlockError::Timeout,
            BlockError::ReadOnly,
            BlockError::Corrupt,
            BlockError::Unsupported,
        ] {
            use std::fmt::Write as _;
            write!(text, "{e};").unwrap();
        }
        assert!(text.starts_with("block range out of bounds;"));
        assert!(text.contains("read-only"));
    }
}
