//! Explicit little-endian field access for on-disk ext2 structures.
//!
//! Everything on an ext2 volume is little-endian regardless of the host, so
//! every multi-byte access goes through these helpers. Offsets are compile-time
//! constants of fixed-size structures, hence the direct indexing: a bounds
//! failure here is a programming error, not malformed input (all input-driven
//! bounds are checked by the callers before reading).
//!
//! This module is also the only place that assumes the 1 KiB block format, so
//! the byte-level facts stay in one spot.

/// Little-endian `u16` at `off`.
#[inline]
pub const fn u16le(buf: &[u8], off: usize) -> u16 {
    u16::from_le_bytes([buf[off], buf[off + 1]])
}

/// Little-endian `u32` at `off`.
#[inline]
pub const fn u32le(buf: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([buf[off], buf[off + 1], buf[off + 2], buf[off + 3]])
}

/// Store `value` as a little-endian `u16` at `off`.
#[inline]
pub fn put_u16le(buf: &mut [u8], off: usize, value: u16) {
    buf[off..off + 2].copy_from_slice(&value.to_le_bytes());
}

/// Store `value` as a little-endian `u32` at `off`.
#[inline]
pub fn put_u32le(buf: &mut [u8], off: usize, value: u32) {
    buf[off..off + 4].copy_from_slice(&value.to_le_bytes());
}
