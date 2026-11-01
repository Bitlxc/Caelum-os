//! 8.3 short-name encoding and decoding.
//!
//! FAT stores names as eleven bytes: eight for the base name and three for the
//! extension, space padded and uppercase. This module is strict on purpose: a
//! name either maps exactly onto eleven valid bytes or it is rejected. Nothing
//! is truncated, no long-file-name entries are synthesised.

use crate::{Fat32Error, MAX_NAME_LEN};

/// Length of the on-disk 8.3 name field.
pub(crate) const NAME83_LEN: usize = 11;
/// Maximum base-name length.
pub(crate) const BASE_LEN: usize = 8;
/// Maximum extension length.
pub(crate) const EXT_LEN: usize = 3;

/// Encode an 8.3 short name into its eleven on-disk bytes.
///
/// Accepts `NAME`, `NAME.EXT`, `name.ext` (converted to uppercase). Rejects
/// empty names, names without a base, longer-than-8.3 parts, more than one dot,
/// trailing dot, `.`/`..`, spaces and every character outside the FAT 8.3
/// uppercase set.
pub(crate) fn encode(name: &str) -> Result<[u8; NAME83_LEN], Fat32Error> {
    let bytes = name.as_bytes();
    if bytes.is_empty() || bytes.len() > BASE_LEN + 1 + EXT_LEN {
        return Err(Fat32Error::BadName);
    }
    if name == "." || name == ".." {
        return Err(Fat32Error::BadName);
    }

    let (base, ext) = match bytes.iter().position(|&b| b == b'.') {
        Some(dot) => {
            if bytes[dot + 1..].contains(&b'.') {
                return Err(Fat32Error::BadName);
            }
            let ext = &bytes[dot + 1..];
            if ext.is_empty() {
                // A trailing dot is rejected rather than silently dropped.
                return Err(Fat32Error::BadName);
            }
            (&bytes[..dot], ext)
        }
        None => (bytes, &[][..]),
    };
    if base.is_empty() || base.len() > BASE_LEN || ext.len() > EXT_LEN {
        return Err(Fat32Error::BadName);
    }

    let mut out = [b' '; NAME83_LEN];
    for (i, &b) in base.iter().enumerate() {
        out[i] = upper(b).ok_or(Fat32Error::BadName)?;
    }
    for (i, &b) in ext.iter().enumerate() {
        out[BASE_LEN + i] = upper(b).ok_or(Fat32Error::BadName)?;
    }
    // A name whose first byte would look like the 0x00 end marker cannot be
    // represented; the allowed character set already excludes it.
    Ok(out)
}

/// Map one character to the uppercase 8.3 on-disk set, or `None`.
///
/// The accepted punctuation is exactly the set FAT permits in short names
/// besides `A-Z` and `0-9`.
fn upper(b: u8) -> Option<u8> {
    match b {
        b'a'..=b'z' => Some(b - b'a' + b'A'),
        b'A'..=b'Z' | b'0'..=b'9' => Some(b),
        b'!' | b'#' | b'$' | b'%' | b'&' | b'\'' | b'(' | b')' | b'-' | b'@' | b'^' | b'_'
        | b'`' | b'{' | b'}' | b'~' => Some(b),
        _ => None,
    }
}

/// Decode eleven on-disk bytes into a displayable `NAME.EXT` byte string.
///
/// The returned buffer is zero padded beyond `len`. Trailing component padding
/// is removed; both parts are already uppercase on disk.
pub(crate) fn decode(raw: &[u8; NAME83_LEN]) -> ([u8; MAX_NAME_LEN], u8) {
    let mut out = [0u8; MAX_NAME_LEN];
    let base_end = trim_end(&raw[0..BASE_LEN]);
    let ext_end = trim_end(&raw[BASE_LEN..]);
    let mut len = 0usize;
    for &b in &raw[0..base_end] {
        out[len] = b;
        len += 1;
    }
    if ext_end > 0 {
        out[len] = b'.';
        len += 1;
        for &b in &raw[BASE_LEN..BASE_LEN + ext_end] {
            out[len] = b;
            len += 1;
        }
    }
    (out, len as u8)
}

fn trim_end(bytes: &[u8]) -> usize {
    let mut end = bytes.len();
    while end > 0 && bytes[end - 1] == b' ' {
        end -= 1;
    }
    end
}

/// True when `name` is the `..` entry.
pub(crate) fn is_dot_dot(name: &[u8; NAME83_LEN]) -> bool {
    name[0] == b'.' && name[1] == b'.' && name[2..].iter().all(|&b| b == b' ')
}
