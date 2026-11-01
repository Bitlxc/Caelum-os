//! VFS advisory file locks (agents.md §12.1).
//!
//! Three independent lock domains share one fixed-capacity table
//! ([`MAX_LOCKS`] entries, no heap):
//!
//! * [`LockDomain::Posix`] — `fcntl` locks, owned by the thread group
//!   (`owner`), so any thread of the same process may re-lock or unlock.
//!   Linux semantics: closing *any* file descriptor that refers to the vnode
//!   releases all POSIX locks the process holds on that vnode. [`posix_close`]
//!   implements that rule for a close that is not the last reference;
//!   [`close_description`] repeats it (idempotently) on the last reference
//!   together with the description-bound OFD/`flock` locks.
//! * [`LockDomain::OpenDescription`] — OFD locks keyed by the open file
//!   description (`open`): `dup`-ed descriptors mean the same description and
//!   therefore never conflict with each other, while two independent opens do.
//! * [`LockDomain::Flock`] — `flock` whole-file locks. `flock` has its own
//!   domain and never conflicts with the two `fcntl` families above.
//!
//! Ranges are `[start, start + len)`; `len == 0` means "to the end of file"
//! (POSIX `l_len == 0`). Only the *smallest* coherent range bookkeeping is
//! implemented: locks of the same owner/description are merged, unlock carves
//! the requested range out of existing entries (splitting when necessary).
//!
//! Conflict rules: two entries conflict when they are in the same domain, on
//! the same vnode, overlap, are not owned by the same owner/description, and
//! at least one of them is exclusive. All conflict checks are non-blocking:
//! a conflict is reported as [`VfsError::WouldBlock`].
//!
//! No allocation, no printing, never call from interrupt context.

use crate::vfs::{OpenId, VNodeId, VfsError};

/// Maximum number of lock entries across all three domains.
pub const MAX_LOCKS: usize = 32;

/// Read (shared) or write (exclusive) lock.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum LockKind {
    Shared,
    Exclusive,
}

/// Lock domain; domains never conflict with each other.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum LockDomain {
    Posix,
    OpenDescription,
    Flock,
}

/// One entry in the global lock table.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
struct LockEntry {
    live: bool,
    domain: LockDomain,
    vnode: VNodeId,
    /// POSIX owner (thread group id); unused for the description domains.
    owner: u32,
    /// Open file description; unused for the POSIX domain.
    open: OpenId,
    start: u64,
    /// `0` means "to the end of file".
    len: u64,
    kind: LockKind,
}

/// The first lock that would block a request (Linux `F_GETLK` result).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct LockConflict {
    /// Owner of the conflicting lock; `0` when the lock belongs to an open file
    /// description, which has no owning process (`F_GETLK` reports `l_pid == -1`
    /// for those).
    pub owner: u32,
    /// Start of the conflicting range.
    pub start: u64,
    /// Length of the conflicting range; `0` means "to the end of file".
    pub len: u64,
    /// Whether the conflicting lock is shared or exclusive.
    pub kind: LockKind,
}

const EMPTY_ENTRY: LockEntry = LockEntry {
    live: false,
    domain: LockDomain::Posix,
    vnode: VNodeId(0),
    owner: 0,
    open: OpenId(0),
    start: 0,
    len: 0,
    kind: LockKind::Shared,
};

/// Exclusive end of a range; `len == 0` is unbounded (end of file).
const fn range_end(start: u64, len: u64) -> u64 {
    if len == 0 {
        u64::MAX
    } else {
        start.saturating_add(len)
    }
}

/// Do two half-open ranges overlap?
const fn ranges_overlap(a_start: u64, a_len: u64, b_start: u64, b_len: u64) -> bool {
    a_start < range_end(b_start, b_len) && b_start < range_end(a_start, a_len)
}

/// Do two half-open ranges overlap or touch (so they can be merged)?
const fn ranges_touch(a_start: u64, a_len: u64, b_start: u64, b_len: u64) -> bool {
    a_start <= range_end(b_start, b_len) && b_start <= range_end(a_start, a_len)
}

/// Smallest range covering both inputs.
const fn merge_ranges(a_start: u64, a_len: u64, b_start: u64, b_len: u64) -> (u64, u64) {
    let start = if a_start < b_start { a_start } else { b_start };
    let a_end = range_end(a_start, a_len);
    let b_end = range_end(b_start, b_len);
    let end = if a_end > b_end { a_end } else { b_end };
    if end == u64::MAX {
        (start, 0)
    } else {
        (start, end - start)
    }
}

/// Is `entry` a live lock of the same domain on the same vnode as `query`?
fn same_scope(entry: &LockEntry, query: &LockEntry) -> bool {
    entry.live && entry.domain == query.domain && entry.vnode == query.vnode
}

/// Does `entry` belong to the same holder (process or open description) as
/// `query`? Only meaningful after [`same_scope`].
fn same_holder(entry: &LockEntry, query: &LockEntry) -> bool {
    match query.domain {
        LockDomain::Posix => entry.owner == query.owner,
        LockDomain::OpenDescription | LockDomain::Flock => entry.open == query.open,
    }
}

/// Would `existing` block a request described by `query`?
fn conflicts(existing: &LockEntry, query: &LockEntry) -> bool {
    if !same_scope(existing, query) {
        return false;
    }
    if !ranges_overlap(existing.start, existing.len, query.start, query.len) {
        return false;
    }
    if same_holder(existing, query) {
        return false;
    }
    !(existing.kind == LockKind::Shared && query.kind == LockKind::Shared)
}

/// Does `entry` belong to the given domain key?
fn matches_key(
    entry: &LockEntry,
    domain: LockDomain,
    vnode: VNodeId,
    owner: u32,
    open: OpenId,
) -> bool {
    if !entry.live || entry.domain != domain || entry.vnode != vnode {
        return false;
    }
    match domain {
        LockDomain::Posix => entry.owner == owner,
        LockDomain::OpenDescription | LockDomain::Flock => entry.open == open,
    }
}

/// Split `entry` around the unlocked range: 0 pieces (fully removed), 1 piece
/// (trimmed or untouched) or 2 pieces (range carved out of the middle).
fn carve(entry: &LockEntry, start: u64, len: u64) -> ([LockEntry; 2], usize) {
    if !ranges_overlap(entry.start, entry.len, start, len) {
        return ([*entry, EMPTY_ENTRY], 1);
    }
    let entry_end = range_end(entry.start, entry.len);
    let unlocked_start = if entry.start > start {
        entry.start
    } else {
        start
    };
    let unlocked_end = if entry_end < range_end(start, len) {
        entry_end
    } else {
        range_end(start, len)
    };

    let mut pieces = [EMPTY_ENTRY; 2];
    let mut count = 0usize;
    if unlocked_start > entry.start {
        pieces[count] = LockEntry {
            start: entry.start,
            len: unlocked_start - entry.start,
            ..*entry
        };
        count += 1;
    }
    if unlocked_end < entry_end {
        let tail_len = if entry_end == u64::MAX {
            0
        } else {
            entry_end - unlocked_end
        };
        pieces[count] = LockEntry {
            start: unlocked_end,
            len: tail_len,
            ..*entry
        };
        count += 1;
    }
    (pieces, count)
}

/// The global lock table.
struct LockTable {
    entries: [LockEntry; MAX_LOCKS],
}

impl LockTable {
    const fn new() -> Self {
        Self {
            entries: [EMPTY_ENTRY; MAX_LOCKS],
        }
    }

    fn live_count(&self) -> usize {
        self.entries.iter().filter(|entry| entry.live).count()
    }

    fn free_slot(&self) -> Option<usize> {
        self.entries.iter().position(|entry| !entry.live)
    }

    fn push(&mut self, entry: LockEntry) -> Result<(), VfsError> {
        match self.free_slot() {
            Some(slot) => {
                self.entries[slot] = entry;
                Ok(())
            }
            None => Err(VfsError::Quota),
        }
    }

    fn clear(&mut self) {
        self.entries = [EMPTY_ENTRY; MAX_LOCKS];
    }

    /// Check for conflicts, then absorb same-holder *same-kind* touching entries
    /// and insert the request.
    ///
    /// Only entries with the same kind may be merged: merging a different kind
    /// would silently change the lock type of a range the caller never
    /// re-checked against other holders. Instead, a same-holder entry of another
    /// kind that overlaps the request is converted — the request's range is
    /// carved out of it (keeping the existing kind outside) and the request is
    /// inserted with its own kind. Adjacent entries of another kind are left
    /// untouched.
    fn insert(&mut self, query: LockEntry) -> Result<(), VfsError> {
        for existing in self.entries.iter() {
            if conflicts(existing, &query) {
                return Err(VfsError::WouldBlock);
            }
        }

        // Absorb same-holder, same-kind entries that touch the request range.
        let mut merged_start = query.start;
        let mut merged_len = query.len;
        let mut absorbed = [false; MAX_LOCKS];
        let mut changed = true;
        while changed {
            changed = false;
            for (index, existing) in self.entries.iter().enumerate() {
                if absorbed[index]
                    || !same_scope(existing, &query)
                    || !same_holder(existing, &query)
                    || existing.kind != query.kind
                {
                    continue;
                }
                if !ranges_touch(existing.start, existing.len, merged_start, merged_len) {
                    continue;
                }
                let (start, len) =
                    merge_ranges(existing.start, existing.len, merged_start, merged_len);
                merged_start = start;
                merged_len = len;
                absorbed[index] = true;
                changed = true;
            }
        }

        // Rebuild so a failed insert (Quota) leaves the table untouched.
        let mut next = LockTable::new();
        for (index, existing) in self.entries.iter().enumerate() {
            if !existing.live || absorbed[index] {
                continue;
            }
            if same_scope(existing, &query) && same_holder(existing, &query) {
                // Different kind: keep only the part outside the request range.
                let (pieces, count) = carve(existing, query.start, query.len);
                for piece in pieces[..count].iter() {
                    next.push(*piece)?;
                }
            } else {
                next.push(*existing)?;
            }
        }
        next.push(LockEntry {
            live: true,
            start: merged_start,
            len: merged_len,
            ..query
        })?;
        *self = next;
        Ok(())
    }

    /// Remove `[start, start + len)` from every entry of the given holder.
    fn unlock(
        &mut self,
        domain: LockDomain,
        vnode: VNodeId,
        owner: u32,
        open: OpenId,
        start: u64,
        len: u64,
    ) -> Result<(), VfsError> {
        let mut needed = 0usize;
        for entry in self.entries.iter() {
            if matches_key(entry, domain, vnode, owner, open) {
                needed += carve(entry, start, len).1;
            } else if entry.live {
                needed += 1;
            }
        }
        if needed > MAX_LOCKS {
            // Carving would split more locks than the table can hold.
            return Err(VfsError::Quota);
        }

        let mut next = LockTable::new();
        for entry in self.entries.iter() {
            if !entry.live {
                continue;
            }
            if matches_key(entry, domain, vnode, owner, open) {
                let (pieces, count) = carve(entry, start, len);
                for piece in pieces[..count].iter() {
                    next.push(*piece)?;
                }
            } else {
                next.push(*entry)?;
            }
        }
        *self = next;
        Ok(())
    }

    /// Drop every lock of the given open file description (OFD + `flock`), and
    /// — Linux POSIX semantics — every POSIX lock `owner` holds on `vnode`.
    fn close_description(&mut self, vnode: VNodeId, owner: u32, open: OpenId) -> usize {
        let mut next = LockTable::new();
        let mut removed = 0usize;
        for entry in self.entries.iter() {
            if !entry.live {
                continue;
            }
            let drop_entry = entry.vnode == vnode
                && match entry.domain {
                    LockDomain::Posix => entry.owner == owner,
                    LockDomain::OpenDescription | LockDomain::Flock => entry.open == open,
                };
            if drop_entry {
                removed += 1;
            } else {
                // Invariant: at most MAX_LOCKS live entries, so this cannot fail.
                let _ = next.push(*entry);
            }
        }
        *self = next;
        removed
    }

    /// Drop every POSIX lock `owner` holds on `vnode` without touching the
    /// description domains: Linux releases the process's POSIX locks when *any*
    /// descriptor of the file is closed, even when `dup`-ed handles keep the
    /// description alive ([`crate::vfs::note_close_locks`]).
    fn close_posix(&mut self, vnode: VNodeId, owner: u32) -> usize {
        let mut removed = 0usize;
        for entry in self.entries.iter_mut() {
            if entry.live
                && entry.domain == LockDomain::Posix
                && entry.vnode == vnode
                && entry.owner == owner
            {
                *entry = EMPTY_ENTRY;
                removed += 1;
            }
        }
        removed
    }

    /// First entry that would block `query`; the query is never inserted.
    fn first_conflict(&self, query: &LockEntry) -> Option<LockConflict> {
        self.entries
            .iter()
            .find(|entry| conflicts(entry, query))
            .map(|entry| LockConflict {
                owner: entry.owner,
                start: entry.start,
                len: entry.len,
                kind: entry.kind,
            })
    }

    /// Drop every POSIX lock held by `owner` on any vnode. OFD/`flock` locks
    /// are bound to their open description and are released by
    /// [`close_description`] instead.
    fn close_process(&mut self, owner: u32) -> usize {
        let mut next = LockTable::new();
        let mut removed = 0usize;
        for entry in self.entries.iter() {
            if !entry.live {
                continue;
            }
            if entry.domain == LockDomain::Posix && entry.owner == owner {
                removed += 1;
            } else {
                let _ = next.push(*entry);
            }
        }
        *self = next;
        removed
    }
}

/// Global lock table. Interrupts are masked for the short table update so a
/// future interrupt-context path cannot observe a half-updated entry; the
/// table itself is only mutated from process context.
struct IrqCell<T> {
    value: core::cell::UnsafeCell<T>,
}

// SAFETY: all access goes through `with`, which masks interrupts on a single
// CPU and never re-enters itself (no allocation, no printing, no locking).
unsafe impl<T> Sync for IrqCell<T> {}

impl<T> IrqCell<T> {
    const fn new(value: T) -> Self {
        Self {
            value: core::cell::UnsafeCell::new(value),
        }
    }

    fn with<R>(&self, f: impl FnOnce(&mut T) -> R) -> R {
        #[cfg(not(test))]
        let was_enabled = crate::arch::disable_interrupts();
        // SAFETY: interrupts are masked (single CPU) and `with` never re-enters.
        let outcome = f(unsafe { &mut *self.value.get() });
        #[cfg(not(test))]
        crate::arch::restore_interrupts(was_enabled);
        outcome
    }
}

static LOCKS: IrqCell<LockTable> = IrqCell::new(LockTable::new());

fn posix_entry(vnode: VNodeId, owner: u32, start: u64, len: u64, kind: LockKind) -> LockEntry {
    LockEntry {
        live: true,
        domain: LockDomain::Posix,
        vnode,
        owner,
        open: OpenId(0),
        start,
        len,
        kind,
    }
}

fn description_entry(
    domain: LockDomain,
    vnode: VNodeId,
    open: OpenId,
    start: u64,
    len: u64,
    kind: LockKind,
) -> LockEntry {
    LockEntry {
        live: true,
        domain,
        vnode,
        owner: 0,
        open,
        start,
        len,
        kind,
    }
}

/// Apply a POSIX (`fcntl`) lock request. Non-blocking: a conflict with another
/// process returns [`VfsError::WouldBlock`]. Re-locking a range already held by
/// the same process merges/replaces it (upgrade/downgrade alike).
pub fn posix_lock(
    vnode: VNodeId,
    start: u64,
    len: u64,
    kind: LockKind,
    owner: u32,
) -> Result<(), VfsError> {
    LOCKS.with(|table| table.insert(posix_entry(vnode, owner, start, len, kind)))
}

/// Release the POSIX-locked part of `[start, start + len)` held by `owner`.
/// Ranges not covered by a lock are ignored (POSIX `F_UNLCK` semantics).
pub fn posix_unlock(vnode: VNodeId, start: u64, len: u64, owner: u32) -> Result<(), VfsError> {
    LOCKS.with(|table| table.unlock(LockDomain::Posix, vnode, owner, OpenId(0), start, len))
}

/// Apply an OFD (`fcntl(F_OFD_SETLK)`) lock request on an open file
/// description. Descriptions never conflict with themselves, so `dup`-ed
/// descriptors share the lock.
pub fn ofd_lock(
    vnode: VNodeId,
    open: OpenId,
    start: u64,
    len: u64,
    kind: LockKind,
) -> Result<(), VfsError> {
    LOCKS.with(|table| {
        table.insert(description_entry(
            LockDomain::OpenDescription,
            vnode,
            open,
            start,
            len,
            kind,
        ))
    })
}

/// Release the OFD-locked part of the range on an open file description.
pub fn ofd_unlock(vnode: VNodeId, open: OpenId, start: u64, len: u64) -> Result<(), VfsError> {
    LOCKS.with(|table| table.unlock(LockDomain::OpenDescription, vnode, 0, open, start, len))
}

/// Apply a whole-file `flock` on an open file description. `flock` lives in its
/// own domain and never conflicts with POSIX or OFD locks.
pub fn flock(vnode: VNodeId, open: OpenId, exclusive: bool) -> Result<(), VfsError> {
    let kind = if exclusive {
        LockKind::Exclusive
    } else {
        LockKind::Shared
    };
    LOCKS.with(|table| {
        table.insert(description_entry(
            LockDomain::Flock,
            vnode,
            open,
            0,
            0,
            kind,
        ))
    })
}

/// Release every `flock` held by an open file description. Returns the number
/// of entries removed.
pub fn funlock(vnode: VNodeId, open: OpenId) -> usize {
    LOCKS.with(|table| {
        let before = table.live_count();
        if table
            .unlock(LockDomain::Flock, vnode, 0, open, 0, 0)
            .is_ok()
        {
            before - table.live_count()
        } else {
            0
        }
    })
}

/// Close path hook: release the locks owned by an open file description
/// (OFD + `flock`) and, per Linux POSIX semantics, every POSIX lock `owner`
/// holds on `vnode` (closing any descriptor of that vnode does this).
/// Returns the number of entries removed.
pub fn close_description(vnode: VNodeId, owner: u32, open: OpenId) -> usize {
    LOCKS.with(|table| table.close_description(vnode, owner, open))
}

/// Close path hook for a descriptor that is not the last reference: Linux
/// releases every POSIX lock `owner` holds on `vnode` when *any* descriptor of
/// that file is closed. OFD and `flock` locks stay bound to the description and
/// are released by [`close_description`] on the final close. Idempotent.
/// Returns the number of POSIX entries removed.
pub fn posix_close(vnode: VNodeId, owner: u32) -> usize {
    LOCKS.with(|table| table.close_posix(vnode, owner))
}

/// Process-exit hook: release every POSIX lock held by `owner` on every vnode.
/// Returns the number of entries removed.
pub fn close_process(owner: u32) -> usize {
    LOCKS.with(|table| table.close_process(owner))
}

/// Build the probe/lock query entry for `domain`. POSIX requests are matched by
/// `owner` and ignore `open`; the description domains are matched by `open`.
fn query_entry(
    vnode: VNodeId,
    domain: LockDomain,
    kind: LockKind,
    start: u64,
    len: u64,
    owner: u32,
    open: OpenId,
) -> LockEntry {
    match domain {
        LockDomain::Posix => posix_entry(vnode, owner, start, len, kind),
        LockDomain::OpenDescription | LockDomain::Flock => {
            description_entry(domain, vnode, open, start, len, kind)
        }
    }
}

/// Non-blocking conflict query; `true` means the request would block.
pub fn has_conflict(
    vnode: VNodeId,
    start: u64,
    len: u64,
    kind: LockKind,
    owner: u32,
    domain: LockDomain,
    open: Option<OpenId>,
) -> bool {
    let query = query_entry(
        vnode,
        domain,
        kind,
        start,
        len,
        owner,
        open.unwrap_or(OpenId(0)),
    );
    LOCKS.with(|table| table.entries.iter().any(|entry| conflicts(entry, &query)))
}

/// First lock that would block the request, without inserting anything
/// (Linux `F_GETLK`). No table entry changes, so a caller that only queries does
/// not need read/write access to the file.
///
/// `owner` identifies a POSIX caller and `open` an OFD/`flock` caller; the
/// caller's own entries never conflict with it.
pub fn first_conflict(
    vnode: VNodeId,
    domain: LockDomain,
    kind: LockKind,
    start: u64,
    len: u64,
    owner: u32,
    open: OpenId,
) -> Option<LockConflict> {
    let query = query_entry(vnode, domain, kind, start, len, owner, open);
    LOCKS.with(|table| table.first_conflict(&query))
}

/// Number of live lock entries across all domains.
pub fn count() -> usize {
    LOCKS.with(|table| table.live_count())
}

/// Drop every lock entry (used by self-checks and tests).
pub fn clear() {
    LOCKS.with(|table| table.clear());
}

fn expect(condition: bool) -> Result<(), VfsError> {
    if condition {
        Ok(())
    } else {
        Err(VfsError::Corrupt)
    }
}

/// In-kernel self-check: exercises the three domains, the POSIX close semantics
/// and the conflict paths against reserved ids ([`VNodeId::NONE`]) that never
/// refer to a live node. Prints nothing, allocates nothing; returns
/// [`VfsError::Corrupt`] on an unexpected result. The table is cleared before
/// and after the check.
pub fn selftest() -> Result<(), VfsError> {
    let file = VNodeId::NONE;
    let owner = 0x4D35_5F4C; // "M5_L"
    let other = owner + 1;
    let open_a = OpenId(0x4D35);
    let open_b = OpenId(0x4D36);

    LOCKS.with(|table| {
        table.clear();
        let outcome = (|| -> Result<(), VfsError> {
            // POSIX: the same owner re-locks in place; another process blocks.
            table.insert(posix_entry(file, owner, 0, 0, LockKind::Shared))?;
            table.insert(posix_entry(file, owner, 0, 0, LockKind::Exclusive))?;
            expect(table.live_count() == 1)?;
            expect(
                table
                    .insert(posix_entry(file, other, 0, 0, LockKind::Shared))
                    .is_err(),
            )?;
            // OFD: the same description re-locks in place, another description blocks.
            table.insert(description_entry(
                LockDomain::OpenDescription,
                file,
                open_a,
                0,
                0,
                LockKind::Exclusive,
            ))?;
            table.insert(description_entry(
                LockDomain::OpenDescription,
                file,
                open_a,
                0,
                0,
                LockKind::Exclusive,
            ))?;
            expect(table.live_count() == 2)?;
            expect(
                table
                    .insert(description_entry(
                        LockDomain::OpenDescription,
                        file,
                        open_b,
                        0,
                        0,
                        LockKind::Shared,
                    ))
                    .is_err(),
            )?;
            // Closing open_a drops its OFD entry and the owner's POSIX lock; the
            // now-free description key admits open_b.
            expect(table.close_description(file, owner, open_a) == 2)?;
            table.insert(description_entry(
                LockDomain::OpenDescription,
                file,
                open_b,
                0,
                0,
                LockKind::Shared,
            ))?;
            // flock is independent from both fcntl domains and conflicts only with
            // other flock entries on a different description.
            table.insert(description_entry(
                LockDomain::Flock,
                file,
                open_a,
                0,
                0,
                LockKind::Exclusive,
            ))?;
            expect(
                table
                    .insert(description_entry(
                        LockDomain::Flock,
                        file,
                        open_b,
                        0,
                        0,
                        LockKind::Shared,
                    ))
                    .is_err(),
            )?;
            table.insert(description_entry(
                LockDomain::Flock,
                file,
                open_a,
                0,
                0,
                LockKind::Shared,
            ))?;
            table.insert(description_entry(
                LockDomain::Flock,
                file,
                open_b,
                0,
                0,
                LockKind::Shared,
            ))?;
            expect(table.live_count() == 3)?; // OFD open_b + flock open_a + flock open_b
            // close_description removes the description's flock entry; POSIX locks
            // are released by close_process.
            expect(table.close_description(file, owner, open_a) == 1)?;
            table.insert(posix_entry(file, owner, 0, 10, LockKind::Exclusive))?;
            expect(table.close_process(owner) == 1)?;
            expect(table.live_count() == 2)?; // open_b OFD + open_b flock
            Ok(())
        })();
        table.clear();
        outcome
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn file(raw: u16) -> VNodeId {
        VNodeId(raw)
    }

    #[test]
    fn posix_same_owner_does_not_conflict_and_upgrades() {
        let _guard = crate::vfs::test_lock();
        clear();
        let vnode = file(1);
        posix_lock(vnode, 0, 0, LockKind::Shared, 1).expect("shared");
        posix_lock(vnode, 0, 0, LockKind::Exclusive, 1).expect("same owner upgrade");
        assert_eq!(count(), 1);
        // A different process sees the exclusive lock.
        assert_eq!(
            posix_lock(vnode, 0, 0, LockKind::Shared, 2),
            Err(VfsError::WouldBlock)
        );
        assert!(has_conflict(
            vnode,
            0,
            0,
            LockKind::Shared,
            2,
            LockDomain::Posix,
            None
        ));
        assert!(!has_conflict(
            vnode,
            0,
            0,
            LockKind::Shared,
            1,
            LockDomain::Posix,
            None
        ));
        clear();
    }

    #[test]
    fn posix_shared_locks_coexist_but_exclusive_blocks() {
        let _guard = crate::vfs::test_lock();
        clear();
        let vnode = file(2);
        posix_lock(vnode, 0, 10, LockKind::Shared, 1).expect("first shared");
        posix_lock(vnode, 0, 10, LockKind::Shared, 2).expect("second shared");
        assert_eq!(count(), 2);
        assert_eq!(
            posix_lock(vnode, 5, 1, LockKind::Exclusive, 3),
            Err(VfsError::WouldBlock)
        );
        // Non-overlapping range is fine.
        posix_lock(vnode, 10, 10, LockKind::Exclusive, 3).expect("disjoint range");
        assert_eq!(count(), 3);
        clear();
    }

    #[test]
    fn posix_unlock_releases_and_splits() {
        let _guard = crate::vfs::test_lock();
        clear();
        let vnode = file(3);
        posix_lock(vnode, 0, 100, LockKind::Exclusive, 1).expect("whole range");
        posix_unlock(vnode, 40, 20, 1).expect("carve");
        assert_eq!(count(), 2);
        assert!(!has_conflict(
            vnode,
            45,
            10,
            LockKind::Exclusive,
            2,
            LockDomain::Posix,
            None
        ));
        assert!(has_conflict(
            vnode,
            0,
            10,
            LockKind::Exclusive,
            2,
            LockDomain::Posix,
            None
        ));
        assert!(has_conflict(
            vnode,
            80,
            10,
            LockKind::Exclusive,
            2,
            LockDomain::Posix,
            None
        ));
        // Unlock only affects the given process.
        posix_unlock(vnode, 0, 0, 2).expect("wrong owner is a no-op");
        assert_eq!(count(), 2);
        posix_unlock(vnode, 0, 0, 1).expect("release all");
        assert_eq!(count(), 0);
        clear();
    }

    #[test]
    fn ofd_dup_does_not_conflict_but_independent_open_does() {
        let _guard = crate::vfs::test_lock();
        clear();
        let vnode = file(4);
        ofd_lock(vnode, OpenId(1), 0, 0, LockKind::Exclusive).expect("first open");
        ofd_lock(vnode, OpenId(1), 0, 0, LockKind::Exclusive).expect("same description");
        assert_eq!(count(), 1);
        assert_eq!(
            ofd_lock(vnode, OpenId(2), 0, 0, LockKind::Shared),
            Err(VfsError::WouldBlock)
        );
        ofd_unlock(vnode, OpenId(1), 0, 0).expect("release description");
        ofd_lock(vnode, OpenId(2), 0, 0, LockKind::Shared).expect("independent open now free");
        clear();
    }

    #[test]
    fn adjacent_different_kind_does_not_absorb_other_owners_shared_lock() {
        let _guard = crate::vfs::test_lock();
        clear();
        let vnode = file(20);
        posix_lock(vnode, 0, 10, LockKind::Shared, 1).expect("owner 1 shared");
        posix_lock(vnode, 0, 10, LockKind::Shared, 2).expect("owner 2 shared");
        // Adjacent exclusive of owner 1 must stay [10,20), not become [0,20):
        // merging it into the shared range would silently upgrade it.
        posix_lock(vnode, 10, 10, LockKind::Exclusive, 1).expect("adjacent exclusive");
        assert_eq!(count(), 3);
        // Owner 1's [0,10) is still shared, so a third shared lock is allowed.
        posix_lock(vnode, 0, 10, LockKind::Shared, 3).expect("shared survives");
        assert_eq!(count(), 4);
        assert!(!has_conflict(
            vnode,
            5,
            1,
            LockKind::Shared,
            5,
            LockDomain::Posix,
            None
        ));
        // ...and an exclusive over the whole range is still blocked.
        assert_eq!(
            posix_lock(vnode, 0, 20, LockKind::Exclusive, 4),
            Err(VfsError::WouldBlock)
        );
        // Same-kind adjacency still merges: [10,20) + [20,10) -> [10,30).
        posix_lock(vnode, 20, 10, LockKind::Exclusive, 1).expect("same kind merge");
        assert_eq!(count(), 4);
        assert!(has_conflict(
            vnode,
            25,
            1,
            LockKind::Exclusive,
            5,
            LockDomain::Posix,
            None
        ));
        assert!(!has_conflict(
            vnode,
            5,
            1,
            LockKind::Shared,
            5,
            LockDomain::Posix,
            None
        ));
        clear();
    }

    #[test]
    fn conversion_rechecks_conflicts_and_keeps_single_entry() {
        let _guard = crate::vfs::test_lock();
        clear();
        let vnode = file(21);
        posix_lock(vnode, 0, 10, LockKind::Exclusive, 1).expect("exclusive");
        assert_eq!(count(), 1);
        posix_lock(vnode, 0, 10, LockKind::Shared, 1).expect("downgrade");
        assert_eq!(count(), 1);
        posix_lock(vnode, 0, 10, LockKind::Shared, 2).expect("other shared");
        assert_eq!(count(), 2);
        // Upgrading back must re-check and observe owner 2's shared lock.
        assert_eq!(
            posix_lock(vnode, 0, 10, LockKind::Exclusive, 1),
            Err(VfsError::WouldBlock)
        );
        assert_eq!(count(), 2);
        posix_unlock(vnode, 0, 10, 2).expect("unlock other");
        posix_lock(vnode, 0, 10, LockKind::Exclusive, 1).expect("upgrade now");
        assert_eq!(count(), 1);
        clear();
    }

    #[test]
    fn partial_kind_change_preserves_outside_ranges() {
        let _guard = crate::vfs::test_lock();
        clear();
        let vnode = file(22);
        posix_lock(vnode, 0, 20, LockKind::Exclusive, 1).expect("whole range");
        posix_lock(vnode, 10, 10, LockKind::Shared, 1).expect("convert tail");
        assert_eq!(count(), 2);
        // [0,10) stays exclusive, [10,20) became shared.
        assert_eq!(
            posix_lock(vnode, 0, 10, LockKind::Shared, 2),
            Err(VfsError::WouldBlock)
        );
        posix_lock(vnode, 10, 10, LockKind::Shared, 2).expect("shared tail");
        assert!(!has_conflict(
            vnode,
            15,
            1,
            LockKind::Shared,
            9,
            LockDomain::Posix,
            None
        ));
        clear();
    }

    #[test]
    fn flock_is_independent_domain() {
        let _guard = crate::vfs::test_lock();
        clear();
        let vnode = file(5);
        posix_lock(vnode, 0, 0, LockKind::Exclusive, 1).expect("posix");
        ofd_lock(vnode, OpenId(1), 0, 0, LockKind::Exclusive).expect("ofd");
        flock(vnode, OpenId(2), true).expect("flock ignores fcntl domains");
        assert_eq!(count(), 3);
        // flock conflicts only inside its own domain.
        assert_eq!(flock(vnode, OpenId(3), false), Err(VfsError::WouldBlock));
        flock(vnode, OpenId(2), false).expect("same description upgrade/downgrade");
        assert_eq!(count(), 3);
        assert_eq!(funlock(vnode, OpenId(2)), 1);
        flock(vnode, OpenId(3), false).expect("other description now free");
        clear();
    }

    #[test]
    fn close_description_releases_posix_and_description_locks() {
        let _guard = crate::vfs::test_lock();
        clear();
        let vnode = file(6);
        posix_lock(vnode, 0, 0, LockKind::Exclusive, 7).expect("posix");
        ofd_lock(vnode, OpenId(1), 0, 0, LockKind::Shared).expect("ofd");
        flock(vnode, OpenId(1), true).expect("flock");
        ofd_lock(vnode, OpenId(2), 0, 0, LockKind::Shared).expect("other description");
        assert_eq!(count(), 4);
        assert_eq!(close_description(vnode, 7, OpenId(1)), 3);
        assert_eq!(count(), 1);
        assert!(!has_conflict(
            vnode,
            0,
            0,
            LockKind::Exclusive,
            8,
            LockDomain::Posix,
            None
        ));
        clear();
    }

    #[test]
    fn close_process_releases_only_posix_locks() {
        let _guard = crate::vfs::test_lock();
        clear();
        let vnode = file(7);
        posix_lock(vnode, 0, 0, LockKind::Exclusive, 9).expect("posix a");
        posix_lock(file(8), 0, 10, LockKind::Shared, 9).expect("posix b other vnode");
        flock(vnode, OpenId(5), true).expect("flock");
        assert_eq!(count(), 3);
        assert_eq!(close_process(9), 2);
        assert_eq!(count(), 1);
        posix_lock(vnode, 0, 0, LockKind::Exclusive, 10).expect("posix domain is free");
        clear();
    }

    #[test]
    fn table_quota_is_reported() {
        let _guard = crate::vfs::test_lock();
        clear();
        for index in 0..MAX_LOCKS as u16 {
            posix_lock(file(index + 100), 0, 0, LockKind::Exclusive, 1).expect("fill");
        }
        assert_eq!(count(), MAX_LOCKS);
        assert_eq!(
            posix_lock(file(500), 0, 0, LockKind::Exclusive, 1),
            Err(VfsError::Quota)
        );
        // Re-locking an existing entry still succeeds (merge, no new slot).
        posix_lock(file(100), 0, 0, LockKind::Exclusive, 1).expect("merge");
        clear();
    }

    #[test]
    fn len_zero_means_to_end_of_file() {
        let _guard = crate::vfs::test_lock();
        clear();
        let vnode = file(9);
        posix_lock(vnode, 100, 0, LockKind::Exclusive, 1).expect("to eof");
        assert!(has_conflict(
            vnode,
            100,
            1,
            LockKind::Exclusive,
            2,
            LockDomain::Posix,
            None
        ));
        assert!(has_conflict(
            vnode,
            10_000,
            0,
            LockKind::Exclusive,
            2,
            LockDomain::Posix,
            None
        ));
        assert!(!has_conflict(
            vnode,
            99,
            1,
            LockKind::Exclusive,
            2,
            LockDomain::Posix,
            None
        ));
        clear();
    }

    #[test]
    fn first_conflict_reports_a_blocking_posix_lock_without_inserting() {
        let _guard = crate::vfs::test_lock();
        clear();
        let vnode = file(11);
        posix_lock(vnode, 10, 10, LockKind::Exclusive, 1).expect("exclusive");
        assert_eq!(count(), 1);
        let conflict = first_conflict(
            vnode,
            LockDomain::Posix,
            LockKind::Shared,
            15,
            1,
            2,
            OpenId(0),
        )
        .expect("an overlapping exclusive lock blocks");
        assert_eq!(
            conflict,
            LockConflict {
                owner: 1,
                start: 10,
                len: 10,
                kind: LockKind::Exclusive,
            }
        );
        // A probe never inserts a lock entry.
        assert_eq!(count(), 1);
        // The same owner and a disjoint range are not conflicts.
        assert!(
            first_conflict(
                vnode,
                LockDomain::Posix,
                LockKind::Shared,
                15,
                1,
                1,
                OpenId(0)
            )
            .is_none()
        );
        assert!(
            first_conflict(
                vnode,
                LockDomain::Posix,
                LockKind::Exclusive,
                20,
                5,
                2,
                OpenId(0),
            )
            .is_none()
        );
        clear();
    }

    #[test]
    fn first_conflict_separates_the_domains_and_description_holders() {
        let _guard = crate::vfs::test_lock();
        clear();
        let vnode = file(12);
        ofd_lock(vnode, OpenId(1), 0, 4, LockKind::Exclusive).expect("ofd");
        // The same description never conflicts with itself.
        assert!(
            first_conflict(
                vnode,
                LockDomain::OpenDescription,
                LockKind::Shared,
                1,
                1,
                0,
                OpenId(1),
            )
            .is_none()
        );
        // Another description sees it; description locks have no process owner.
        let conflict = first_conflict(
            vnode,
            LockDomain::OpenDescription,
            LockKind::Shared,
            1,
            1,
            0,
            OpenId(2),
        )
        .expect("another description conflicts");
        assert_eq!(
            conflict,
            LockConflict {
                owner: 0,
                start: 0,
                len: 4,
                kind: LockKind::Exclusive,
            }
        );
        // POSIX queries never see OFD entries and flock is yet another domain.
        assert!(
            first_conflict(
                vnode,
                LockDomain::Posix,
                LockKind::Exclusive,
                0,
                4,
                3,
                OpenId(0)
            )
            .is_none()
        );
        assert!(
            first_conflict(
                vnode,
                LockDomain::Flock,
                LockKind::Exclusive,
                0,
                0,
                0,
                OpenId(2)
            )
            .is_none()
        );
        posix_lock(vnode, 0, 4, LockKind::Exclusive, 3).expect("posix");
        assert!(
            first_conflict(
                vnode,
                LockDomain::OpenDescription,
                LockKind::Shared,
                0,
                4,
                0,
                OpenId(2),
            )
            .is_some()
        );
        clear();
    }

    #[test]
    fn posix_close_releases_only_that_owner_on_that_vnode() {
        let _guard = crate::vfs::test_lock();
        clear();
        let vnode = file(13);
        let other_vnode = file(14);
        posix_lock(vnode, 0, 10, LockKind::Exclusive, 1).expect("owner 1");
        posix_lock(vnode, 20, 10, LockKind::Exclusive, 2).expect("owner 2");
        posix_lock(other_vnode, 0, 10, LockKind::Exclusive, 1).expect("owner 1 other vnode");
        ofd_lock(vnode, OpenId(1), 0, 10, LockKind::Exclusive).expect("ofd survives");
        flock(vnode, OpenId(1), true).expect("flock survives");
        assert_eq!(count(), 5);
        assert_eq!(posix_close(vnode, 1), 1);
        assert_eq!(count(), 4);
        assert!(has_conflict(
            vnode,
            20,
            10,
            LockKind::Exclusive,
            1,
            LockDomain::Posix,
            None
        ));
        assert!(has_conflict(
            other_vnode,
            0,
            10,
            LockKind::Exclusive,
            2,
            LockDomain::Posix,
            None
        ));
        assert!(has_conflict(
            vnode,
            0,
            10,
            LockKind::Shared,
            0,
            LockDomain::OpenDescription,
            Some(OpenId(2))
        ));
        assert!(has_conflict(
            vnode,
            0,
            0,
            LockKind::Shared,
            0,
            LockDomain::Flock,
            Some(OpenId(2))
        ));
        // Idempotent: a second close releases nothing.
        assert_eq!(posix_close(vnode, 1), 0);
        clear();
    }

    #[test]
    fn selftest_passes_and_leaves_table_empty() {
        let _guard = crate::vfs::test_lock();
        assert_eq!(selftest(), Ok(()));
        assert_eq!(count(), 0);
    }
}
