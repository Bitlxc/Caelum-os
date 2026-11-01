//! Open file descriptions.
//!
//! A description is the thing that carries a file offset: two independent opens
//! of the same file get two descriptions with independent offsets, while [`dup`]
//! hands back the same description (an extra reference) so both handles read from
//! the same position. That is the POSIX/Linux distinction the M5b ABI needs, and
//! it is why the table is separate from the VNode table.
//!
//! # `OpenId` contract
//!
//! An [`OpenId`] is a slot index into this fixed 16-entry table, not a durable
//! identifier: M5c1 deliberately adds no generation counter. In production it is
//! only carried as the payload of a `File` object; the handle a process can name
//! is an object-table handle with its own generation, which is what protects user
//! space against ABA (M4). A closed `OpenId` must therefore never be used
//! again: every accessor answers [`VfsError::NotFound`] once its slot is
//! free, and host tests must not treat it as a stable, persistable number.
//! tests must not treat it as a stable, persistable number.

use super::types::{MAX_OPEN, OpenId, OpenOptions, VNodeId, VfsError};

/// One open file description.
#[derive(Clone, Copy, Debug)]
pub struct Description {
    /// Whether the slot is in use.
    pub used: bool,
    /// Node this description refers to.
    pub vnode: VNodeId,
    /// Process that opened this description (M5c3).
    ///
    /// POSIX locks are tracked per owner, so two descriptors opened by the
    /// same owner never conflict. Kernel and test opens use owner 0 through
    /// [`super::open_path`]; [`super::dup`] keeps the owner.
    pub owner: u32,
    /// Reads allowed by the mode passed to `open`.
    pub read: bool,
    /// Writes allowed by the mode passed to `open`.
    pub write: bool,
    /// Current file offset.
    pub offset: u64,
    /// Extra references created by [`dup`]; `close` releases one at a time.
    pub refs: u8,
}

impl Description {
    /// Empty slot.
    pub const EMPTY: Description = Description {
        used: false,
        vnode: VNodeId::NONE,
        owner: 0,
        read: false,
        write: false,
        offset: 0,
        refs: 0,
    };
}

/// The fixed description table.
pub struct Table {
    descriptions: [Description; MAX_OPEN],
}

impl Table {
    /// Empty table.
    pub const fn new() -> Table {
        Table {
            descriptions: [Description::EMPTY; MAX_OPEN],
        }
    }

    /// Reset every slot in place.
    pub fn clear(&mut self) {
        for description in self.descriptions.iter_mut() {
            *description = Description::EMPTY;
        }
    }

    fn index_of(&self, id: OpenId) -> Result<usize, VfsError> {
        if id == OpenId::NONE {
            return Err(VfsError::NotFound);
        }
        let index = id.raw() as usize;
        if index >= MAX_OPEN || !self.descriptions[index].used {
            return Err(VfsError::NotFound);
        }
        Ok(index)
    }

    /// Look up a live description.
    pub fn get(&self, id: OpenId) -> Result<&Description, VfsError> {
        Ok(&self.descriptions[self.index_of(id)?])
    }

    /// Look up a live description mutably.
    pub fn get_mut(&mut self, id: OpenId) -> Result<&mut Description, VfsError> {
        let index = self.index_of(id)?;
        Ok(&mut self.descriptions[index])
    }

    /// Allocate a description for `vnode`.
    pub fn alloc(
        &mut self,
        vnode: VNodeId,
        options: OpenOptions,
        owner: u32,
    ) -> Result<OpenId, VfsError> {
        for index in 0..MAX_OPEN {
            if self.descriptions[index].used {
                continue;
            }
            self.descriptions[index] = Description {
                used: true,
                vnode,
                owner,
                read: options.read,
                write: options.write,
                offset: 0,
                refs: 1,
            };
            return Ok(OpenId::from_raw(index as u16));
        }
        Err(VfsError::Quota)
    }

    /// Take one reference; returns `true` when the description is now unused.
    pub fn release(&mut self, id: OpenId) -> Result<bool, VfsError> {
        let index = self.index_of(id)?;
        let description = &mut self.descriptions[index];
        description.refs = description.refs.saturating_sub(1);
        if description.refs == 0 {
            self.descriptions[index] = Description::EMPTY;
            return Ok(true);
        }
        Ok(false)
    }

    /// Take one more reference (`dup`); `Quota` instead of wrapping the count.
    pub fn retain(&mut self, id: OpenId) -> Result<(), VfsError> {
        let description = self.get_mut(id)?;
        description.refs = description.refs.checked_add(1).ok_or(VfsError::Quota)?;
        Ok(())
    }

    /// Whether a live description still refers to `vnode`.
    ///
    /// Unlink/rmdir use this to keep descriptions pinned in M5c1: an `OpenId`
    /// stored in a `File` must never outlive the VNode it names.
    pub fn has_description(&self, vnode: VNodeId) -> bool {
        self.descriptions
            .iter()
            .any(|description| description.used && description.vnode == vnode)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn independent_opens_have_independent_offsets() {
        let mut table = Table::new();
        let node = VNodeId::from_raw(0x0102);
        let first = table.alloc(node, OpenOptions::read_only(), 0).unwrap();
        let second = table.alloc(node, OpenOptions::read_only(), 0).unwrap();
        assert_ne!(first, second);
        table.get_mut(first).unwrap().offset = 5;
        assert_eq!(table.get(second).unwrap().offset, 0);
    }

    #[test]
    fn dup_shares_one_description() {
        let mut table = Table::new();
        let node = VNodeId::from_raw(0x0102);
        let id = table.alloc(node, OpenOptions::read_write(), 0).unwrap();
        table.get_mut(id).unwrap().refs = 2;
        table.get_mut(id).unwrap().offset = 9;
        assert!(!table.release(id).unwrap());
        assert_eq!(table.get(id).unwrap().offset, 9);
        assert!(table.release(id).unwrap());
        assert_eq!(table.get(id).unwrap_err(), VfsError::NotFound);
    }

    #[test]
    fn table_is_bounded_and_rejects_stale_ids() {
        let mut table = Table::new();
        let node = VNodeId::from_raw(0x0102);
        let mut ids = [OpenId::NONE; MAX_OPEN];
        for slot in ids.iter_mut() {
            *slot = table.alloc(node, OpenOptions::read_only(), 0).unwrap();
        }
        assert_eq!(
            table.alloc(node, OpenOptions::read_only(), 0).unwrap_err(),
            VfsError::Quota
        );
        assert!(table.release(ids[0]).unwrap());
        assert_eq!(table.get(ids[0]).unwrap_err(), VfsError::NotFound);
        assert!(table.alloc(node, OpenOptions::read_only(), 0).is_ok());
    }

    #[test]
    fn retain_refuses_to_overflow_the_reference_count() {
        let mut table = Table::new();
        let node = VNodeId::from_raw(0x0102);
        let id = table.alloc(node, OpenOptions::read_only(), 0).unwrap();
        table.get_mut(id).unwrap().refs = u8::MAX;
        assert_eq!(table.retain(id).unwrap_err(), VfsError::Quota);
        assert_eq!(table.get(id).unwrap().refs, u8::MAX, "count is unchanged");
    }

    #[test]
    fn has_description_tracks_live_descriptions_only() {
        let mut table = Table::new();
        let node = VNodeId::from_raw(0x0102);
        assert!(!table.has_description(node));
        let id = table.alloc(node, OpenOptions::read_only(), 0).unwrap();
        assert!(table.has_description(node));
        assert!(table.release(id).unwrap());
        assert!(!table.has_description(node));
    }

    #[test]
    fn alloc_records_the_owner_and_dup_keeps_it() {
        let mut table = Table::new();
        let node = VNodeId::from_raw(0x0102);
        let owner = 0x4D5C_3301;
        let id = table.alloc(node, OpenOptions::read_only(), owner).unwrap();
        assert_eq!(table.get(id).unwrap().owner, owner);
        table.retain(id).unwrap();
        assert_eq!(table.get(id).unwrap().owner, owner, "dup keeps the owner");
        assert!(!table.release(id).unwrap());
        assert!(table.release(id).unwrap());
    }
}
