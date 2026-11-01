//! Ramfs directory operations on top of the VNode table.
//!
//! This layer owns names and the directory tree; it never touches file bytes.
//! Callers (the module-level API in `vfs`) pair the returned [`CacheKey`] values
//! with `pagecache::write`, `pagecache::truncate` and `pagecache::invalidate`, so
//! all data-cache bookkeeping stays in one place.

use super::pagecache::CacheKey;
use super::path::Path;
use super::types::{MAX_NAME, NodeKind, VNodeId, VfsError};
use super::vnode::{Backing, Table};

/// What a mutating operation removed, so the caller can drop cached pages.
///
/// The cache key is captured before the slot is released: releasing bumps the
/// generation, which would otherwise produce a key that no longer matches the
/// pages written for the old file.
#[derive(Clone, Copy, Debug)]
pub struct Removed {
    /// Cache key of the removed node's data.
    pub key: CacheKey,
}

/// Resolve an absolute path to its node.
pub fn lookup(table: &Table, root: VNodeId, path: &Path) -> Result<VNodeId, VfsError> {
    let mut current = root;
    for name in path.iter() {
        let node = table.get(current)?;
        if node.kind != NodeKind::Directory {
            return Err(VfsError::NotDirectory);
        }
        current = table.child(current, name)?.ok_or(VfsError::NotFound)?;
    }
    Ok(current)
}

/// Resolve an already-parsed parent path to its directory VNode.
///
/// The caller parses the path with [`super::path::parse_child_into`] (which also
/// copies out the child name), so create/unlink/rename parse exactly once and
/// never build a `Path` by value.
#[cfg(test)]
pub fn lookup_parent_dir(table: &Table, root: VNodeId, parent: &Path) -> Result<VNodeId, VfsError> {
    let parent_id = lookup(table, root, parent)?;
    let node = table.get(parent_id)?;
    if node.kind != NodeKind::Directory {
        return Err(VfsError::NotDirectory);
    }
    Ok(parent_id)
}

/// Parse `raw_path` and resolve its parent directory (host-test convenience).
#[cfg(test)]
pub fn lookup_parent_into(
    table: &Table,
    root: VNodeId,
    raw_path: &[u8],
    parent: &mut Path,
    name: &mut [u8; MAX_NAME],
) -> Result<(VNodeId, usize), VfsError> {
    let name_len = super::path::parse_child_into(raw_path, parent, name)?;
    Ok((lookup_parent_dir(table, root, parent)?, name_len))
}

/// Create a child node below `parent`, refusing duplicates.
fn create_child(
    table: &mut Table,
    parent: VNodeId,
    name: &[u8],
    kind: NodeKind,
    backing: Backing,
) -> Result<VNodeId, VfsError> {
    if table.child(parent, name)?.is_some() {
        return Err(VfsError::AlreadyExists);
    }
    table.alloc(kind, parent, name, backing)
}

/// Create an empty ramfs file named `name` below `parent`.
pub fn create_file_at(
    table: &mut Table,
    parent: VNodeId,
    name: &[u8],
) -> Result<VNodeId, VfsError> {
    create_child(table, parent, name, NodeKind::File, Backing::Ram)
}

/// Create a ramfs directory named `name` below `parent`.
pub fn create_directory_at(
    table: &mut Table,
    parent: VNodeId,
    name: &[u8],
) -> Result<VNodeId, VfsError> {
    create_child(table, parent, name, NodeKind::Directory, Backing::Ram)
}

/// Create an empty ramfs file at `raw_path` (host-test convenience form).
///
/// Production callers resolve the parent once and call [`create_file_at`]; this
/// owning form exists so the tests can keep asserting on raw paths.
#[cfg(test)]
pub fn create_file(table: &mut Table, root: VNodeId, raw_path: &[u8]) -> Result<VNodeId, VfsError> {
    let mut parent = Path::root();
    let mut name = [0u8; MAX_NAME];
    let (parent_id, name_len) = lookup_parent_into(table, root, raw_path, &mut parent, &mut name)?;
    create_file_at(table, parent_id, &name[..name_len])
}

/// Create a ramfs directory at `raw_path` (host-test convenience form).
#[cfg(test)]
pub fn create_directory(
    table: &mut Table,
    root: VNodeId,
    raw_path: &[u8],
) -> Result<VNodeId, VfsError> {
    let mut parent = Path::root();
    let mut name = [0u8; MAX_NAME];
    let (parent_id, name_len) = lookup_parent_into(table, root, raw_path, &mut parent, &mut name)?;
    create_directory_at(table, parent_id, &name[..name_len])
}

/// Attach an immutable boot payload as a read-only file named `name`.
pub fn create_boot_node(
    table: &mut Table,
    parent: VNodeId,
    name: &[u8],
    size: u64,
) -> Result<VNodeId, VfsError> {
    if name.is_empty() || name.len() > MAX_NAME {
        return Err(VfsError::NameTooLong);
    }
    let mut backing_name = [0u8; MAX_NAME];
    backing_name[..name.len()].copy_from_slice(name);
    let id = create_child(
        table,
        parent,
        name,
        NodeKind::File,
        Backing::Boot {
            name: backing_name,
            name_len: name.len() as u8,
        },
    )?;
    table.get_mut(id)?.size = size;
    Ok(id)
}

/// Unlink the file named `name` below `parent`.
///
/// Directories are refused (`Busy`), never removed recursively.
pub fn unlink_at(table: &mut Table, parent: VNodeId, name: &[u8]) -> Result<Removed, VfsError> {
    let id = table.child(parent, name)?.ok_or(VfsError::NotFound)?;
    let node = table.get(id)?;
    if node.kind == NodeKind::Directory {
        return Err(VfsError::Busy);
    }
    if node.read_only {
        return Err(VfsError::ReadOnly);
    }
    let key = node.cache_key(id);
    table.release(id)?;
    Ok(Removed { key })
}

/// Unlink a file at `raw_path` (host-test convenience form).
#[cfg(test)]
pub fn unlink(table: &mut Table, root: VNodeId, raw_path: &[u8]) -> Result<Removed, VfsError> {
    let mut parent = Path::root();
    let mut name = [0u8; MAX_NAME];
    let (parent_id, name_len) = lookup_parent_into(table, root, raw_path, &mut parent, &mut name)?;
    unlink_at(table, parent_id, &name[..name_len])
}

/// Remove the empty directory named `name` below `parent`.
pub fn rmdir_at(table: &mut Table, parent: VNodeId, name: &[u8]) -> Result<(), VfsError> {
    let id = table.child(parent, name)?.ok_or(VfsError::NotFound)?;
    let node = table.get(id)?;
    if node.kind != NodeKind::Directory {
        return Err(VfsError::NotDirectory);
    }
    if !table.is_empty_directory(id)? {
        return Err(VfsError::Busy);
    }
    table.release(id)
}

/// Remove an empty directory at `raw_path` (host-test convenience form).
#[cfg(test)]
pub fn rmdir(table: &mut Table, root: VNodeId, raw_path: &[u8]) -> Result<(), VfsError> {
    let mut parent = Path::root();
    let mut name = [0u8; MAX_NAME];
    let (parent_id, name_len) = lookup_parent_into(table, root, raw_path, &mut parent, &mut name)?;
    rmdir_at(table, parent_id, &name[..name_len])
}

/// Rename (and possibly replace) the entry `old_name` below `old_parent`.
///
/// A regular file may be replaced; replacing a directory, or moving a directory
/// into itself, is rejected. The caller publishes notifications and invalidates
/// the returned cache key when a file was replaced.
pub fn rename_at(
    table: &mut Table,
    old_parent: VNodeId,
    old_name: &[u8],
    new_parent: VNodeId,
    new_name: &[u8],
) -> Result<Option<Removed>, VfsError> {
    let id = table
        .child(old_parent, old_name)?
        .ok_or(VfsError::NotFound)?;
    if new_parent == id {
        return Err(VfsError::BadPath);
    }
    let mut replaced = None;
    if let Some(existing) = table.child(new_parent, new_name)? {
        if existing == id {
            return Ok(None);
        }
        let node = table.get(existing)?;
        if node.kind == NodeKind::Directory {
            return Err(VfsError::AlreadyExists);
        }
        if node.read_only {
            return Err(VfsError::ReadOnly);
        }
        let key = node.cache_key(existing);
        table.release(existing)?;
        replaced = Some(Removed { key });
    }
    table.reparent(id, new_parent, new_name)?;
    Ok(replaced)
}

/// Rename between raw paths (host-test convenience form).
///
/// Production callers reuse one `Path` buffer for both paths and call
/// [`rename_at`]; this owning form exists for the tests.
#[cfg(test)]
pub fn rename(
    table: &mut Table,
    root: VNodeId,
    old_path: &[u8],
    new_path: &[u8],
) -> Result<Option<Removed>, VfsError> {
    let mut parent = Path::root();
    let mut old_name = [0u8; MAX_NAME];
    let (old_parent, old_len) =
        lookup_parent_into(table, root, old_path, &mut parent, &mut old_name)?;
    let mut new_name = [0u8; MAX_NAME];
    let (new_parent, new_len) =
        lookup_parent_into(table, root, new_path, &mut parent, &mut new_name)?;
    rename_at(
        table,
        old_parent,
        &old_name[..old_len],
        new_parent,
        &new_name[..new_len],
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vfs::path;

    fn table_with_root() -> (Table, VNodeId) {
        let mut table = Table::new();
        let root = table
            .alloc(NodeKind::Directory, VNodeId::NONE, b"", Backing::Ram)
            .unwrap();
        (table, root)
    }

    #[test]
    fn create_and_lookup_round_trip() {
        let (mut table, root) = table_with_root();
        let id = create_file(&mut table, root, b"/notes").unwrap();
        assert_eq!(
            lookup(&table, root, &path::parse(b"/notes").unwrap()).unwrap(),
            id
        );
        assert_eq!(
            create_file(&mut table, root, b"/notes").unwrap_err(),
            VfsError::AlreadyExists
        );
        assert_eq!(
            lookup(&table, root, &path::parse(b"/missing").unwrap()).unwrap_err(),
            VfsError::NotFound
        );
    }

    #[test]
    fn missing_parent_is_reported() {
        let (mut table, root) = table_with_root();
        assert_eq!(
            create_file(&mut table, root, b"/dir/file").unwrap_err(),
            VfsError::NotFound
        );
        create_directory(&mut table, root, b"/dir").unwrap();
        assert!(create_file(&mut table, root, b"/dir/file").is_ok());
    }

    #[test]
    fn unlink_drops_the_entry_and_returns_its_cache_key() {
        let (mut table, root) = table_with_root();
        let id = create_file(&mut table, root, b"/gone").unwrap();
        let node = table.get(id).unwrap();
        let expected = node.cache_key(id);
        let removed = unlink(&mut table, root, b"/gone").unwrap();
        assert_eq!(removed.key, expected);
        assert_eq!(
            lookup(&table, root, &path::parse(b"/gone").unwrap()).unwrap_err(),
            VfsError::NotFound
        );
    }

    #[test]
    fn directories_are_not_unlinked_as_files() {
        let (mut table, root) = table_with_root();
        create_directory(&mut table, root, b"/dir").unwrap();
        assert_eq!(
            unlink(&mut table, root, b"/dir").unwrap_err(),
            VfsError::Busy
        );
        create_file(&mut table, root, b"/dir/child").unwrap();
        assert_eq!(
            rmdir(&mut table, root, b"/dir").unwrap_err(),
            VfsError::Busy
        );
        unlink(&mut table, root, b"/dir/child").unwrap();
        rmdir(&mut table, root, b"/dir").unwrap();
    }

    #[test]
    fn rename_moves_and_replaces_files() {
        let (mut table, root) = table_with_root();
        let id = create_file(&mut table, root, b"/a").unwrap();
        rename(&mut table, root, b"/a", b"/b").unwrap();
        assert_eq!(
            lookup(&table, root, &path::parse(b"/b").unwrap()).unwrap(),
            id
        );

        let other = create_file(&mut table, root, b"/c").unwrap();
        let replaced = rename(&mut table, root, b"/c", b"/b").unwrap();
        assert!(replaced.is_some());
        assert_eq!(
            lookup(&table, root, &path::parse(b"/b").unwrap()).unwrap(),
            other
        );
        assert_eq!(
            lookup(&table, root, &path::parse(b"/a").unwrap()).unwrap_err(),
            VfsError::NotFound
        );
    }

    #[test]
    fn readdir_walks_children_in_slices() {
        let (mut table, root) = table_with_root();
        for name in [&b"/one"[..], &b"/two"[..], &b"/three"[..]] {
            create_file(&mut table, root, name).unwrap();
        }
        let mut entries = [crate::vfs::DirEntry::empty(); 2];
        assert_eq!(table.readdir(root, 0, &mut entries).unwrap(), 2);
        assert_eq!(table.readdir(root, 2, &mut entries).unwrap(), 1);
        assert_eq!(table.readdir(root, 3, &mut entries).unwrap(), 0);
    }

    #[test]
    fn boot_nodes_are_read_only_and_sized() {
        let (mut table, root) = table_with_root();
        let boot = create_directory(&mut table, root, b"/boot").unwrap();
        let id = create_boot_node(&mut table, boot, b"init", 4096).unwrap();
        let node = table.get(id).unwrap();
        assert!(node.read_only);
        assert_eq!(node.size, 4096);
        assert_eq!(node.backing.boot_name(), Some(b"init".as_slice()));
        assert_eq!(
            unlink(&mut table, root, b"/boot/init").unwrap_err(),
            VfsError::ReadOnly
        );
    }
}
