//! Path parsing for the M5a VFS.
//!
//! Paths are absolute byte strings (agents.md §12.1: names are not required to be
//! UTF-8). This module is pure: it never touches the node table, so the whole
//! grammar is exercised by host tests. Rules:
//!
//! - one leading `/`; a relative path is [`VfsError::BadPath`];
//! - repeated slashes are collapsed (`/a//b` == `/a/b`);
//! - `.` components are dropped and `..` pops the previous component (`..` at
//!   the root stays at the root, like Linux);
//! - at most [`MAX_PATH`] bytes and [`MAX_COMPONENTS`] components;
//! - each component is at most [`MAX_NAME`] bytes, and no NUL bytes are accepted
//!   (an embedded NUL would truncate the name in the boot protocol's fixed-size
//!   name slot);
//! - no symbolic links exist in M5a, so nothing is resolved recursively.
//!
//! # Stack budget
//!
//! A [`Path`] is a fixed ~1 KiB value and the kernel boot stack is 16 KiB, so the
//! production entry points parse **into** a caller-owned buffer ([`parse_into`],
//! [`parse_parent_into`]) instead of returning a fresh `Path` (or a
//! `Path`-carrying tuple) by value. Each production frame therefore holds at
//! most one `Path` plus a small name buffer, and callers that need two paths
//! reuse the same buffer. The owning forms ([`parse`], [`parse_parent`]) are
//! test-only conveniences kept so the grammar stays easy to assert on.

use super::types::{MAX_COMPONENTS, MAX_NAME, MAX_PATH, VfsError};

/// One parsed absolute path: a fixed sequence of components.
#[derive(Clone, Copy, Debug)]
pub struct Path {
    names: [[u8; MAX_NAME]; MAX_COMPONENTS],
    lens: [u8; MAX_COMPONENTS],
    count: usize,
}

impl Path {
    /// The root path `/`.
    ///
    /// `inline(always)` (not just `inline`): this is built in every caller, and a
    /// debug build would otherwise emit a helper frame holding a whole 1 KiB
    /// `Path` plus a copy-out. Forcing the inline keeps the value in the caller's
    /// own slot, which is what the boot stack budget counts.
    #[inline(always)]
    pub const fn root() -> Path {
        Path {
            names: [[0u8; MAX_NAME]; MAX_COMPONENTS],
            lens: [0u8; MAX_COMPONENTS],
            count: 0,
        }
    }

    /// Number of components (0 for the root).
    #[inline(always)]
    pub const fn len(&self) -> usize {
        self.count
    }

    /// Whether this is the root path.
    #[cfg(test)]
    pub const fn is_root(&self) -> bool {
        self.count == 0
    }

    /// Component at `index`.
    pub fn name(&self, index: usize) -> Option<&[u8]> {
        if index >= self.count {
            return None;
        }
        Some(&self.names[index][..self.lens[index] as usize])
    }

    /// Iterate the components in order.
    pub fn iter(&self) -> impl Iterator<Item = &[u8]> + '_ {
        (0..self.count).filter_map(|index| self.name(index))
    }

    /// Forget every component so the buffer can be parsed into again.
    ///
    /// Only the component count is reset: stale name bytes past `count` are
    /// never read (`name`/`iter` slice by `lens`), so re-parsing does not have to
    /// clear the ~1 KiB array.
    fn reset(&mut self) {
        self.count = 0;
    }

    /// Append one component, keeping the fixed bound.
    fn push(&mut self, name: &[u8]) -> Result<(), VfsError> {
        if name.len() > MAX_NAME {
            return Err(VfsError::NameTooLong);
        }
        if self.count >= MAX_COMPONENTS {
            return Err(VfsError::BadPath);
        }
        if name.is_empty() || name.contains(&0) {
            return Err(VfsError::BadPath);
        }
        let slot = &mut self.names[self.count];
        slot[..name.len()].copy_from_slice(name);
        self.lens[self.count] = name.len() as u8;
        self.count += 1;
        Ok(())
    }

    /// Drop the last component (`..`).
    fn pop(&mut self) {
        if self.count > 0 {
            self.count -= 1;
        }
    }

    /// Split off the final component: copy it to `name`, drop it from the path,
    /// and return its length.
    ///
    /// This is the parse-once form used by create/unlink/rename: a caller parses
    /// a path once, then splits it into parent components plus child name without
    /// re-parsing. The root has no final component.
    pub fn split_last(&mut self, name: &mut [u8; MAX_NAME]) -> Result<usize, VfsError> {
        let count = self.len();
        if count == 0 {
            return Err(VfsError::BadPath);
        }
        let last = self.name(count - 1).ok_or(VfsError::BadPath)?;
        let len = last.len();
        name[..len].copy_from_slice(last);
        self.pop();
        Ok(len)
    }
}

/// Parse an absolute path into `out`, replacing its previous contents.
///
/// `out` is left empty when parsing fails part-way through, so a failed call
/// never exposes a half-built path.
pub fn parse_into(raw: &[u8], out: &mut Path) -> Result<(), VfsError> {
    match parse_components(raw, out) {
        Ok(()) => Ok(()),
        Err(error) => {
            // Never leave a half-built path behind: a caller that ignores the
            // error still sees an empty buffer rather than a partial path.
            out.reset();
            Err(error)
        }
    }
}

fn parse_components(raw: &[u8], out: &mut Path) -> Result<(), VfsError> {
    if raw.is_empty() || raw[0] != b'/' {
        return Err(VfsError::BadPath);
    }
    if raw.len() > MAX_PATH {
        return Err(VfsError::BadPath);
    }
    if raw.contains(&0) {
        return Err(VfsError::BadPath);
    }
    out.reset();
    for component in raw[1..].split(|&byte| byte == b'/') {
        match component {
            b"" | b"." => continue,
            b".." => out.pop(),
            name => out.push(name)?,
        }
    }
    Ok(())
}

/// Parse a path that names a child entry: absolute, **no trailing slash**, then
/// split off the final component.
///
/// The VFS entry points now parse once into the shared scratch `Path` and split
/// with [`Path::split_last`], so this helper is only exercised by host tests and
/// the ramfs test helpers; it is kept because it documents the trailing-slash
/// rule those call sites rely on.
#[cfg_attr(not(test), allow(dead_code))]
pub fn parse_child_into(
    raw: &[u8],
    out: &mut Path,
    name: &mut [u8; MAX_NAME],
) -> Result<usize, VfsError> {
    if raw.len() > 1 && raw[raw.len() - 1] == b'/' {
        return Err(VfsError::BadPath);
    }
    parse_into(raw, out)?;
    out.split_last(name)
}

/// Split a path into its parent directory (written to `out`) plus the final
/// component name (copied to `name`).
///
/// Test-only alias of [`parse_child_into`], kept so the grammar stays easy to
/// assert on from the host tests.
#[cfg(test)]
pub fn parse_parent_into(
    raw: &[u8],
    out: &mut Path,
    name: &mut [u8; MAX_NAME],
) -> Result<usize, VfsError> {
    parse_child_into(raw, out, name)
}

/// Parse an absolute path into its components (test-only owning form).
#[cfg(test)]
pub fn parse(raw: &[u8]) -> Result<Path, VfsError> {
    let mut parsed = Path::root();
    parse_into(raw, &mut parsed)?;
    Ok(parsed)
}

/// Split a path into parent plus final name (test-only owning form).
#[cfg(test)]
pub fn parse_parent(raw: &[u8]) -> Result<(Path, [u8; MAX_NAME], usize), VfsError> {
    let mut parent = Path::root();
    let mut name = [0u8; MAX_NAME];
    let len = parse_parent_into(raw, &mut parent, &mut name)?;
    Ok((parent, name, len))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::vec;
    use std::vec::Vec;

    fn names(path: &[u8]) -> Vec<Vec<u8>> {
        parse(path)
            .unwrap()
            .iter()
            .map(|name| name.to_vec())
            .collect()
    }

    #[test]
    fn root_and_trailing_slashes_collapse() {
        assert!(parse(b"/").unwrap().is_root());
        assert_eq!(names(b"//"), Vec::<Vec<u8>>::new());
        assert_eq!(
            names(b"/boot/init"),
            vec![b"boot".to_vec(), b"init".to_vec()]
        );
        assert_eq!(
            names(b"//boot///init/"),
            vec![b"boot".to_vec(), b"init".to_vec()]
        );
    }

    #[test]
    fn dot_and_dotdot_are_normalised() {
        assert_eq!(
            names(b"/./boot/./init"),
            vec![b"boot".to_vec(), b"init".to_vec()]
        );
        assert_eq!(names(b"/boot/../init"), vec![b"init".to_vec()]);
        assert_eq!(names(b"/../../../boot"), vec![b"boot".to_vec()]);
        assert_eq!(names(b"/boot/.."), Vec::<Vec<u8>>::new());
        assert_eq!(names(b"/boot/../.."), Vec::<Vec<u8>>::new());
    }

    #[test]
    fn relative_and_empty_paths_are_rejected() {
        assert_eq!(parse(b"").unwrap_err(), VfsError::BadPath);
        assert_eq!(parse(b"boot/init").unwrap_err(), VfsError::BadPath);
        assert_eq!(parse(b"./boot").unwrap_err(), VfsError::BadPath);
    }

    #[test]
    fn lengths_are_bounded() {
        let long_name = [b'a'; MAX_NAME + 1];
        assert_eq!(parse(long_name.as_slice()).unwrap_err(), VfsError::BadPath);
        let mut path = [0u8; MAX_NAME + 1];
        path[0] = b'/';
        path[1..].copy_from_slice(&long_name[..MAX_NAME]);
        // `/aaaa...` with MAX_NAME bytes is fine, one more is not.
        assert!(parse(&path).is_ok());
        assert_eq!(parse(&[b'/'][..]).unwrap().len(), 0);

        let mut too_long = [b'a'; MAX_PATH + 1];
        too_long[0] = b'/';
        assert_eq!(parse(&too_long).unwrap_err(), VfsError::BadPath);

        let mut too_many = Vec::new();
        too_many.push(b'/');
        for _ in 0..MAX_COMPONENTS + 1 {
            too_many.extend_from_slice(b"a/");
        }
        assert_eq!(parse(&too_many).unwrap_err(), VfsError::BadPath);
    }

    #[test]
    fn nested_nul_is_rejected() {
        assert_eq!(parse(b"/a\0b").unwrap_err(), VfsError::BadPath);
    }

    #[test]
    fn parent_split_returns_the_child_name() {
        let (parent, name, len) = parse_parent(b"/boot/init").unwrap();
        assert_eq!(
            parent.iter().map(|n| n.to_vec()).collect::<Vec<_>>(),
            vec![b"boot".to_vec()]
        );
        assert_eq!(&name[..len], b"init");

        let (parent, name, len) = parse_parent(b"/top").unwrap();
        assert!(parent.is_root());
        assert_eq!(&name[..len], b"top");

        assert_eq!(parse_parent(b"/").unwrap_err(), VfsError::BadPath);
        assert_eq!(parse_parent(b"/boot/").unwrap_err(), VfsError::BadPath);
    }

    #[test]
    fn parse_into_reuses_one_buffer() {
        let mut parsed = Path::root();
        parse_into(b"/boot/init", &mut parsed).unwrap();
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed.name(0), Some(b"boot".as_slice()));
        assert_eq!(parsed.name(1), Some(b"init".as_slice()));

        // Re-parsing a shorter path must not leave stale components behind.
        parse_into(b"/x", &mut parsed).unwrap();
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed.name(0), Some(b"x".as_slice()));
        assert_eq!(parsed.name(1), None);

        // A failed parse leaves the buffer empty (no half-built path).
        assert_eq!(
            parse_into(b"relative", &mut parsed).unwrap_err(),
            VfsError::BadPath
        );
        assert_eq!(parsed.len(), 0);

        // `/..` normalises to the root without touching any byte.
        parse_into(b"/a/b/../..", &mut parsed).unwrap();
        assert_eq!(parsed.len(), 0);
    }

    #[test]
    fn parse_parent_into_matches_the_owned_form() {
        let cases: [&[u8]; 6] = [
            b"/boot/init",
            b"/top",
            b"//boot///init",
            b"/a/./b/../c",
            b"/boot/init/",
            b"/",
        ];
        for raw in cases {
            let mut parent = Path::root();
            let mut name = [0u8; MAX_NAME];
            let inplace = parse_parent_into(raw, &mut parent, &mut name);
            let owned = parse_parent(raw);
            match (inplace, owned) {
                (Ok(len), Ok((owned_parent, owned_name, owned_len))) => {
                    assert_eq!(len, owned_len, "name length for {raw:?}");
                    assert_eq!(&name[..len], &owned_name[..owned_len]);
                    assert_eq!(parent.len(), owned_parent.len());
                    for index in 0..parent.len() {
                        assert_eq!(parent.name(index), owned_parent.name(index));
                    }
                }
                (Err(left), Err(right)) => assert_eq!(left, right, "error for {raw:?}"),
                (left, right) => panic!("mismatch for {raw:?}: {left:?} vs {right:?}"),
            }
        }
    }
}
