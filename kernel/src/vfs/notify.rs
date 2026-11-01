//! VFS directory-change notifications (agents.md §12.1).
//!
//! M5a keeps one fixed-capacity watch table ([`MAX_WATCHES`] watches, no heap).
//! A watch is bound to one directory VNode and receives depth-1 events: creates,
//! unlinks and renames of its *direct* children, each carrying the parent vnode,
//! the event kind and the child name. Renames are published twice by the VFS —
//! once to the old parent and once to the new parent — so a watcher sees the
//! name on the side of the rename it watches.
//!
//! Every watch owns a fixed FIFO of [`WATCH_QUEUE`] events. When the FIFO is
//! full the *new* event is dropped and the watch's overflow counter is
//! incremented: overflow is reported via [`dropped`], never silently hidden.
//! Events stay queued until the owner drains them; there is no implicit wakeup
//! object in M5a (EventSubscription arrives with M6).
//!
//! Every watch records an owning process id (`0` is the in-kernel self-check /
//! host-test owner, user processes pass their real `ProcessId`). Ownership is
//! checked on every drain / unwatch / pending / dropped query, so one process
//! can neither read nor drop another process's events
//! ([`VfsError::PermissionDenied`]). Two lifecycle primitives keep the fixed
//! table leak-free: [`close_process`] releases everything a dead process owned,
//! and [`invalidate_directory`] releases watches when the watched directory
//! itself is removed. Renaming the watched directory must NOT invalidate: the
//! watch follows the same VNode.
//!
//! No allocation, no printing, never call from interrupt context.

use crate::vfs::{VNodeId, VfsError};

/// Maximum number of registered watches.
pub const MAX_WATCHES: usize = 8;
/// Events queued per watch before new events are counted as dropped.
pub const WATCH_QUEUE: usize = 16;
/// Longest child name carried by an event (matches `vfs::MAX_NAME`).
pub const MAX_CHILD_NAME: usize = 31;

/// What happened to a child of a watched directory.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum NotifyKind {
    /// A new child was created.
    Created,
    /// A child was unlinked.
    Deleted,
    /// A child changed name (published to the old and the new parent).
    Renamed,
}

/// Child name copied into an event.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct ChildName {
    bytes: [u8; MAX_CHILD_NAME],
    len: u8,
}

impl ChildName {
    /// Placeholder used by `const` event values.
    pub const fn empty() -> ChildName {
        ChildName {
            bytes: [0u8; MAX_CHILD_NAME],
            len: 0,
        }
    }

    /// Copy `name` into an event; empty names and names longer than
    /// [`MAX_CHILD_NAME`] are rejected with [`VfsError::NameTooLong`].
    pub fn new(name: &[u8]) -> Result<ChildName, VfsError> {
        if name.is_empty() || name.len() > MAX_CHILD_NAME {
            return Err(VfsError::NameTooLong);
        }
        let mut child = ChildName::empty();
        child.len = name.len() as u8;
        child.bytes[..name.len()].copy_from_slice(name);
        Ok(child)
    }

    /// Meaningful name bytes.
    pub fn as_bytes(&self) -> &[u8] {
        let len = (self.len as usize).min(self.bytes.len());
        &self.bytes[..len]
    }

    /// Length in bytes.
    pub const fn len(&self) -> usize {
        self.len as usize
    }

    /// Whether this name is empty (only placeholders are).
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }
}

/// One directory-change event.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct NotifyEvent {
    /// Directory whose direct child changed.
    pub directory: VNodeId,
    /// What happened.
    pub kind: NotifyKind,
    /// Name of the child the event refers to.
    pub child: ChildName,
}

impl NotifyEvent {
    /// Placeholder used for unused FIFO slots.
    pub const fn empty() -> NotifyEvent {
        NotifyEvent {
            directory: VNodeId::NONE,
            kind: NotifyKind::Created,
            child: ChildName::empty(),
        }
    }
}

/// Handle to a registered watch.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct WatchId(pub u8);

impl WatchId {
    /// Id that never refers to a live watch.
    pub const NONE: WatchId = WatchId(u8::MAX);

    /// Underlying index.
    pub const fn raw(self) -> u8 {
        self.0
    }
}

#[derive(Clone, Copy)]
struct Watch {
    live: bool,
    /// Owning process id: `0` is the in-kernel self-check/test owner, user
    /// processes use their real `ProcessId` (> 0). Ownership gates every
    /// drain/unwatch operation so one process cannot read or drop another's
    /// events.
    owner: u32,
    directory: VNodeId,
    events: [NotifyEvent; WATCH_QUEUE],
    head: u8,
    len: u8,
    dropped: u64,
}

const EMPTY_WATCH: Watch = Watch {
    live: false,
    owner: 0,
    directory: VNodeId::NONE,
    events: [NotifyEvent::empty(); WATCH_QUEUE],
    head: 0,
    len: 0,
    dropped: 0,
};

struct NotifyTable {
    watches: [Watch; MAX_WATCHES],
}

impl NotifyTable {
    const fn new() -> Self {
        Self {
            watches: [EMPTY_WATCH; MAX_WATCHES],
        }
    }

    fn live_count(&self) -> usize {
        self.watches.iter().filter(|watch| watch.live).count()
    }

    fn watch(&mut self, directory: VNodeId) -> Result<WatchId, VfsError> {
        self.watch_owned(directory, 0)
    }

    fn watch_owned(&mut self, directory: VNodeId, owner: u32) -> Result<WatchId, VfsError> {
        let Some(index) = self.watches.iter().position(|watch| !watch.live) else {
            return Err(VfsError::Quota);
        };
        self.watches[index] = Watch {
            live: true,
            owner,
            directory,
            ..EMPTY_WATCH
        };
        Ok(WatchId(index as u8))
    }

    fn unwatch(&mut self, id: WatchId) -> Result<(), VfsError> {
        self.unwatch_owned(id, 0)
    }

    fn unwatch_owned(&mut self, id: WatchId, owner: u32) -> Result<(), VfsError> {
        let watch = self.owned_mut(id, owner)?;
        *watch = EMPTY_WATCH;
        Ok(())
    }

    /// Resolve a live watch owned by `owner`: a missing/stale slot is
    /// [`VfsError::NotFound`], a live watch owned by somebody else is
    /// [`VfsError::PermissionDenied`] (never readable or removable).
    fn owned_mut(&mut self, id: WatchId, owner: u32) -> Result<&mut Watch, VfsError> {
        let Some(watch) = self
            .watches
            .get_mut(id.0 as usize)
            .filter(|watch| watch.live)
        else {
            return Err(VfsError::NotFound);
        };
        if watch.owner != owner {
            return Err(VfsError::PermissionDenied);
        }
        Ok(watch)
    }

    fn owned(&self, id: WatchId, owner: u32) -> Result<&Watch, VfsError> {
        let watch = self
            .watches
            .get(id.0 as usize)
            .filter(|watch| watch.live)
            .ok_or(VfsError::NotFound)?;
        if watch.owner != owner {
            return Err(VfsError::PermissionDenied);
        }
        Ok(watch)
    }

    fn publish(&mut self, directory: VNodeId, kind: NotifyKind, name: &[u8]) -> usize {
        // Validate the name once; an invalid name is a programming error in the
        // caller and must not be silently truncated into a wrong event.
        let Ok(child) = ChildName::new(name) else {
            return 0;
        };
        let mut delivered = 0usize;
        for watch in self.watches.iter_mut() {
            if !watch.live || watch.directory != directory {
                continue;
            }
            if watch.len as usize >= WATCH_QUEUE {
                watch.dropped = watch.dropped.saturating_add(1);
                continue;
            }
            let tail = watch.head.wrapping_add(watch.len) % (WATCH_QUEUE as u8);
            watch.events[tail as usize] = NotifyEvent {
                directory,
                kind,
                child,
            };
            watch.len += 1;
            delivered += 1;
        }
        delivered
    }

    fn drain(&mut self, id: WatchId, out: &mut [NotifyEvent]) -> Result<usize, VfsError> {
        self.drain_owned(id, 0, out)
    }

    fn drain_owned(
        &mut self,
        id: WatchId,
        owner: u32,
        out: &mut [NotifyEvent],
    ) -> Result<usize, VfsError> {
        let watch = self.owned_mut(id, owner)?;
        let mut count = 0usize;
        while count < out.len() && watch.len > 0 {
            out[count] = watch.events[watch.head as usize];
            watch.head = (watch.head + 1) % (WATCH_QUEUE as u8);
            watch.len -= 1;
            count += 1;
        }
        if watch.len == 0 {
            watch.head = 0;
        }
        Ok(count)
    }

    fn pending(&self, id: WatchId) -> Result<usize, VfsError> {
        self.pending_owned(id, 0)
    }

    fn pending_owned(&self, id: WatchId, owner: u32) -> Result<usize, VfsError> {
        Ok(self.owned(id, owner)?.len as usize)
    }

    fn dropped(&self, id: WatchId) -> Result<u64, VfsError> {
        self.dropped_owned(id, 0)
    }

    fn dropped_owned(&self, id: WatchId, owner: u32) -> Result<u64, VfsError> {
        Ok(self.owned(id, owner)?.dropped)
    }

    /// Release every watch (and queued events) owned by `owner`; returns how
    /// many watch slots were freed. Called from the process reap path so a dead
    /// process cannot leak watch slots or strand events.
    fn close_process(&mut self, owner: u32) -> usize {
        let mut released = 0usize;
        for watch in self.watches.iter_mut() {
            if watch.live && watch.owner == owner {
                *watch = EMPTY_WATCH;
                released += 1;
            }
        }
        released
    }

    /// Release every watch registered on a directory that is being removed;
    /// returns how many watch slots were freed. A rename of the directory
    /// itself does NOT invalidate anything: the watch follows the same VNode.
    fn invalidate_directory(&mut self, directory: VNodeId) -> usize {
        let mut released = 0usize;
        for watch in self.watches.iter_mut() {
            if watch.live && watch.directory == directory {
                *watch = EMPTY_WATCH;
                released += 1;
            }
        }
        released
    }

    fn clear(&mut self) {
        self.watches = [EMPTY_WATCH; MAX_WATCHES];
    }
}

/// Global watch table. Interrupts are masked around each update so interrupts
/// cannot observe a half-written FIFO; the table is only mutated from process
/// context and never re-enters itself.
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

static WATCHES: IrqCell<NotifyTable> = IrqCell::new(NotifyTable::new());

/// Register a watch on a directory vnode for the in-kernel owner (`0`).
/// Returns [`VfsError::Quota`] when all [`MAX_WATCHES`] watch slots are taken.
pub fn watch(directory: VNodeId) -> Result<WatchId, VfsError> {
    WATCHES.with(|table| table.watch(directory))
}

/// Register a watch owned by `owner`.
///
/// `owner` is a process id: `0` is reserved for the in-kernel self-check and
/// host tests, user processes pass their real `ProcessId` (> 0). Every later
/// drain/unwatch of this watch must come from the same owner.
pub fn watch_owned(directory: VNodeId, owner: u32) -> Result<WatchId, VfsError> {
    WATCHES.with(|table| table.watch_owned(directory, owner))
}

/// Unregister an in-kernel (`owner == 0`) watch and drop its queued events.
/// A stale or invalid id returns [`VfsError::NotFound`].
pub fn unwatch(id: WatchId) -> Result<(), VfsError> {
    WATCHES.with(|table| table.unwatch(id))
}

/// Unregister a watch owned by `owner` and drop its queued events.
///
/// A stale/invalid id returns [`VfsError::NotFound`]; a live watch owned by a
/// different process returns [`VfsError::PermissionDenied`] and stays intact.
pub fn unwatch_owned(id: WatchId, owner: u32) -> Result<(), VfsError> {
    WATCHES.with(|table| table.unwatch_owned(id, owner))
}

/// Publish a depth-1 change to every watch registered on `directory`. Returns
/// the number of watches the event was queued into; watchers whose queue is full
/// see their [`dropped`] counter increase instead.
///
/// `name` must be 1..=[`MAX_CHILD_NAME`] bytes. The VFS calls this from its
/// `create`, `unlink` and `rename` paths; a rename is published twice, once to
/// the old parent and once to the new parent.
pub fn publish(directory: VNodeId, kind: NotifyKind, name: &[u8]) -> Result<usize, VfsError> {
    ChildName::new(name)?;
    Ok(WATCHES.with(|table| table.publish(directory, kind, name)))
}

/// Drain up to `out.len()` queued events for an in-kernel (`owner == 0`) watch,
/// oldest first. Returns how many events were written.
pub fn drain(id: WatchId, out: &mut [NotifyEvent]) -> Result<usize, VfsError> {
    WATCHES.with(|table| table.drain(id, out))
}

/// Drain up to `out.len()` queued events for a watch owned by `owner`, oldest
/// first. Returns how many events were written.
///
/// A live watch owned by a different process returns
/// [`VfsError::PermissionDenied`]: one process can never read another's events.
pub fn drain_owned(id: WatchId, owner: u32, out: &mut [NotifyEvent]) -> Result<usize, VfsError> {
    WATCHES.with(|table| table.drain_owned(id, owner, out))
}

/// Number of events currently queued for an in-kernel (`owner == 0`) watch.
pub fn pending(id: WatchId) -> Result<usize, VfsError> {
    WATCHES.with(|table| table.pending(id))
}

/// Number of events currently queued for a watch owned by `owner`.
pub fn pending_owned(id: WatchId, owner: u32) -> Result<usize, VfsError> {
    WATCHES.with(|table| table.pending_owned(id, owner))
}

/// Number of events dropped because an in-kernel watch's queue was full.
/// Overflow is always observable here, never silent.
pub fn dropped(id: WatchId) -> Result<u64, VfsError> {
    WATCHES.with(|table| table.dropped(id))
}

/// Number of events dropped because a watch owned by `owner` overflowed.
pub fn dropped_owned(id: WatchId, owner: u32) -> Result<u64, VfsError> {
    WATCHES.with(|table| table.dropped_owned(id, owner))
}

/// Release every watch (and queued events) owned by `owner`; returns how many
/// watch slots were freed.
///
/// The process reap path calls this so a dead process cannot leak watch slots
/// or strand events for somebody else to see. Other owners are untouched.
pub fn close_process(owner: u32) -> usize {
    WATCHES.with(|table| table.close_process(owner))
}

/// Release every watch registered on a directory that is being removed;
/// returns how many watch slots were freed.
///
/// Watches on other directories are untouched, and a **rename** of the watched
/// directory itself must NOT call this: the watch follows the same VNode.
pub fn invalidate_directory(directory: VNodeId) -> usize {
    WATCHES.with(|table| table.invalidate_directory(directory))
}

/// Number of live watches.
pub fn count() -> usize {
    WATCHES.with(|table| table.live_count())
}

/// Drop every watch and queued event (used by self-checks and tests).
pub fn clear() {
    WATCHES.with(|table| table.clear());
}

fn expect(condition: bool) -> Result<(), VfsError> {
    if condition {
        Ok(())
    } else {
        Err(VfsError::Corrupt)
    }
}

/// In-kernel self-check against reserved vnode ids (index `0xFF` never maps to a
/// live node, so no real watcher is disturbed): exercises watch registration,
/// delivery, FIFO drain, overflow accounting and rename-to-two-parents.
/// Prints nothing, allocates nothing; clears the table before and after the
/// check and returns [`VfsError::Corrupt`] on an unexpected result.
pub fn selftest() -> Result<(), VfsError> {
    // `VNodeId::NONE.index()` is 0xFF (>= MAX_VNODES), so it can never be live.
    let old_parent = VNodeId::NONE;
    let new_parent = VNodeId(0xFFFE);

    WATCHES.with(|table| {
        table.clear();
        let outcome = (|| -> Result<(), VfsError> {
            let old_watch = table.watch(old_parent)?;
            let new_watch = table.watch(new_parent)?;
            expect(table.live_count() == 2)?;

            // A rename is published to both parents with their own names.
            expect(table.publish(old_parent, NotifyKind::Renamed, b"before") == 1)?;
            expect(table.publish(new_parent, NotifyKind::Renamed, b"after") == 1)?;

            let mut events = [NotifyEvent::empty(); 4];
            let count = table.drain(old_watch, &mut events)?;
            expect(count == 1)?;
            expect(events[0].kind == NotifyKind::Renamed)?;
            expect(events[0].directory == old_parent)?;
            expect(events[0].child.as_bytes() == b"before")?;

            let count = table.drain(new_watch, &mut events)?;
            expect(count == 1)?;
            expect(events[0].child.as_bytes() == b"after")?;

            // Queue overflow is counted, not silently swallowed.
            let mut index = 0usize;
            while index < WATCH_QUEUE + 2 {
                table.publish(old_parent, NotifyKind::Created, b"child");
                index += 1;
            }
            expect(table.pending(old_watch)? == WATCH_QUEUE)?;
            expect(table.dropped(old_watch)? == 2)?;

            // Unwatched slots stop receiving; stale ids are NotFound.
            table.unwatch(old_watch)?;
            expect(table.live_count() == 1)?;
            expect(table.drain(old_watch, &mut events) == Err(VfsError::NotFound))?;
            expect(table.unwatch(old_watch) == Err(VfsError::NotFound))?;
            expect(table.unwatch(new_watch)? == ())?;
            expect(table.live_count() == 0)?;
            Ok(())
        })();
        table.clear();
        outcome
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn directory(raw: u16) -> VNodeId {
        VNodeId(raw)
    }

    #[test]
    fn watch_and_drain_events_in_order() {
        let _guard = crate::vfs::test_lock();
        clear();
        let dir = directory(1);
        let id = watch(dir).expect("watch");
        assert_eq!(count(), 1);
        assert_eq!(
            publish(dir, NotifyKind::Created, b"init").expect("create"),
            1
        );
        assert_eq!(
            publish(dir, NotifyKind::Deleted, b"tmp").expect("delete"),
            1
        );
        assert_eq!(pending(id), Ok(2));

        let mut events = [NotifyEvent::empty(); 4];
        assert_eq!(drain(id, &mut events), Ok(2));
        assert_eq!(events[0].directory, dir);
        assert_eq!(events[0].kind, NotifyKind::Created);
        assert_eq!(events[0].child.as_bytes(), b"init");
        assert_eq!(events[1].kind, NotifyKind::Deleted);
        assert_eq!(events[1].child.as_bytes(), b"tmp");
        assert_eq!(pending(id), Ok(0));
        assert_eq!(drain(id, &mut events), Ok(0));
        clear();
    }

    #[test]
    fn publish_without_watchers_is_ok_and_delivers_nothing() {
        let _guard = crate::vfs::test_lock();
        clear();
        assert_eq!(publish(directory(2), NotifyKind::Created, b"x"), Ok(0));
        assert_eq!(count(), 0);
        clear();
    }

    #[test]
    fn queue_overflow_is_counted_and_keeps_oldest() {
        let _guard = crate::vfs::test_lock();
        clear();
        let dir = directory(3);
        let id = watch(dir).expect("watch");
        for index in 0..(WATCH_QUEUE + 3) {
            let name = [b'c', (b'0' + (index % 10) as u8)];
            publish(dir, NotifyKind::Created, &name).expect("publish");
        }
        assert_eq!(pending(id), Ok(WATCH_QUEUE));
        assert_eq!(dropped(id), Ok(3));
        let mut events = [NotifyEvent::empty(); WATCH_QUEUE];
        assert_eq!(drain(id, &mut events), Ok(WATCH_QUEUE));
        // The oldest event is still first: overflow drops new events only.
        assert_eq!(events[0].child.as_bytes(), b"c0");
        assert_eq!(events[WATCH_QUEUE - 1].child.as_bytes(), b"c5");
        assert_eq!(dropped(id), Ok(3));
        clear();
    }

    #[test]
    fn watch_table_quota() {
        let _guard = crate::vfs::test_lock();
        clear();
        let mut ids = [WatchId::NONE; MAX_WATCHES];
        for (index, slot) in ids.iter_mut().enumerate() {
            *slot = watch(directory(index as u16 + 10)).expect("watch");
        }
        assert_eq!(count(), MAX_WATCHES);
        assert_eq!(watch(directory(99)), Err(VfsError::Quota));
        unwatch(ids[0]).expect("unwatch");
        watch(directory(99)).expect("slot reused");
        clear();
    }

    #[test]
    fn unwatch_stops_delivery_and_rejects_stale_ids() {
        let _guard = crate::vfs::test_lock();
        clear();
        let dir = directory(4);
        let id = watch(dir).expect("watch");
        unwatch(id).expect("unwatch");
        assert_eq!(publish(dir, NotifyKind::Created, b"a"), Ok(0));
        let mut events = [NotifyEvent::empty(); 2];
        assert_eq!(drain(id, &mut events), Err(VfsError::NotFound));
        assert_eq!(pending(id), Err(VfsError::NotFound));
        assert_eq!(dropped(id), Err(VfsError::NotFound));
        assert_eq!(unwatch(WatchId::NONE), Err(VfsError::NotFound));
        assert_eq!(unwatch(id), Err(VfsError::NotFound));
        clear();
    }

    #[test]
    fn rename_publishes_old_and_new_parent() {
        let _guard = crate::vfs::test_lock();
        clear();
        let old_parent = directory(5);
        let new_parent = directory(6);
        let old_id = watch(old_parent).expect("old watch");
        let new_id = watch(new_parent).expect("new watch");
        publish(old_parent, NotifyKind::Renamed, b"before").expect("publish old");
        publish(new_parent, NotifyKind::Renamed, b"after").expect("publish new");
        let mut events = [NotifyEvent::empty(); 2];
        assert_eq!(drain(old_id, &mut events), Ok(1));
        assert_eq!(events[0].kind, NotifyKind::Renamed);
        assert_eq!(events[0].directory, old_parent);
        assert_eq!(events[0].child.as_bytes(), b"before");
        assert_eq!(drain(new_id, &mut events), Ok(1));
        assert_eq!(events[0].directory, new_parent);
        assert_eq!(events[0].child.as_bytes(), b"after");
        clear();
    }

    #[test]
    fn child_name_validation() {
        let _guard = crate::vfs::test_lock();
        clear();
        assert_eq!(ChildName::new(b""), Err(VfsError::NameTooLong));
        let too_long = [b'a'; MAX_CHILD_NAME + 1];
        assert_eq!(ChildName::new(&too_long), Err(VfsError::NameTooLong));
        let exact = [b'b'; MAX_CHILD_NAME];
        let name = ChildName::new(&exact).expect("max length accepted");
        assert_eq!(name.len(), MAX_CHILD_NAME);
        assert_eq!(name.as_bytes(), &exact[..]);
        let dir = directory(7);
        watch(dir).expect("watch");
        assert_eq!(
            publish(dir, NotifyKind::Created, &too_long),
            Err(VfsError::NameTooLong)
        );
        clear();
    }

    #[test]
    fn selftest_passes_and_leaves_table_empty() {
        let _guard = crate::vfs::test_lock();
        assert_eq!(selftest(), Ok(()));
        assert_eq!(count(), 0);
    }

    // -- M5c3：owner 隔离与生命周期原语 -------------------------------------

    #[test]
    fn owner_isolation_gates_drain_unwatch_and_counters() {
        let _guard = crate::vfs::test_lock();
        clear();
        let dir = directory(20);
        let id = watch_owned(dir, 42).expect("owned watch");
        assert_eq!(publish(dir, NotifyKind::Created, b"a"), Ok(1));

        let mut events = [NotifyEvent::empty(); 2];
        // 其他 owner 既不能读、也不能删、也看不到计数。
        assert_eq!(
            drain_owned(id, 43, &mut events),
            Err(VfsError::PermissionDenied)
        );
        assert_eq!(pending_owned(id, 43), Err(VfsError::PermissionDenied));
        assert_eq!(dropped_owned(id, 43), Err(VfsError::PermissionDenied));
        assert_eq!(unwatch_owned(id, 43), Err(VfsError::PermissionDenied));

        // 所有者的事件与队列完好无损。
        assert_eq!(pending_owned(id, 42), Ok(1));
        assert_eq!(drain_owned(id, 42, &mut events), Ok(1));
        assert_eq!(events[0].child.as_bytes(), b"a");
        assert_eq!(unwatch_owned(id, 42), Ok(()));
        assert_eq!(count(), 0);
        clear();
    }

    #[test]
    fn kernel_owner_zero_keeps_the_legacy_api() {
        let _guard = crate::vfs::test_lock();
        clear();
        let dir = directory(21);
        // 旧 API 全部等价于 owner = 0。
        let id = watch(dir).expect("kernel watch");
        assert_eq!(publish(dir, NotifyKind::Created, b"init"), Ok(1));
        assert_eq!(pending(id), Ok(1));
        let mut events = [NotifyEvent::empty(); 2];
        assert_eq!(drain(id, &mut events), Ok(1));
        assert_eq!(events[0].child.as_bytes(), b"init");
        // 用户 owner 不能动内核自测 watch。
        assert_eq!(unwatch_owned(id, 42), Err(VfsError::PermissionDenied));
        assert_eq!(pending_owned(id, 42), Err(VfsError::PermissionDenied));
        assert_eq!(unwatch(id), Ok(()));
        // watch_owned(.., 0) 与 watch(..) 完全等价。
        let kernel_id = watch_owned(directory(22), 0).expect("owner zero watch");
        assert_eq!(unwatch(kernel_id), Ok(()));
        assert_eq!(count(), 0);
        clear();
    }

    #[test]
    fn close_process_releases_only_its_own_watches() {
        let _guard = crate::vfs::test_lock();
        clear();
        let mine = watch_owned(directory(30), 42).expect("watch 42");
        let other = watch_owned(directory(31), 43).expect("watch 43");
        let kernel = watch(directory(32)).expect("kernel watch");
        assert_eq!(count(), 3);

        assert_eq!(close_process(42), 1);
        assert_eq!(count(), 2);
        // 已释放的 watch 对任何 owner 都是 NotFound。
        let mut events = [NotifyEvent::empty(); 2];
        assert_eq!(unwatch_owned(mine, 42), Err(VfsError::NotFound));
        assert_eq!(drain_owned(mine, 42, &mut events), Err(VfsError::NotFound));

        // 其他 owner 与内核 watch 不受影响，仍能正常收事件。
        assert_eq!(publish(directory(31), NotifyKind::Created, b"x"), Ok(1));
        assert_eq!(pending_owned(other, 43), Ok(1));
        assert_eq!(publish(directory(32), NotifyKind::Created, b"k"), Ok(1));
        assert_eq!(pending(kernel), Ok(1));

        assert_eq!(close_process(43), 1);
        assert_eq!(close_process(0), 1);
        assert_eq!(count(), 0);
        clear();
    }

    #[test]
    fn invalidate_directory_frees_only_that_directory() {
        let _guard = crate::vfs::test_lock();
        clear();
        let removed = directory(40);
        let kept = directory(41);
        let first = watch_owned(removed, 42).expect("watch a");
        let second = watch_owned(removed, 43).expect("watch b");
        let survivor = watch_owned(kept, 42).expect("watch c");

        // 目录被删除：该目录上的所有 watch 都释放，其他目录不受影响。
        assert_eq!(invalidate_directory(removed), 2);
        assert_eq!(count(), 1);
        let mut events = [NotifyEvent::empty(); 2];
        assert_eq!(drain_owned(first, 42, &mut events), Err(VfsError::NotFound));
        assert_eq!(unwatch_owned(second, 43), Err(VfsError::NotFound));
        assert_eq!(invalidate_directory(removed), 0);

        assert_eq!(publish(kept, NotifyKind::Created, b"y"), Ok(1));
        assert_eq!(pending_owned(survivor, 42), Ok(1));
        assert_eq!(close_process(42), 1);
        assert_eq!(count(), 0);
        clear();
    }

    #[test]
    fn rename_of_the_watched_directory_keeps_the_watch() {
        let _guard = crate::vfs::test_lock();
        clear();
        let dir = directory(50);
        let parent = directory(51);
        let dir_watch = watch_owned(dir, 42).expect("dir watch");
        let parent_watch = watch_owned(parent, 43).expect("parent watch");

        // 目录本身被 rename：VFS 只向父目录 publish(Renamed)，不 invalidate 目录自身。
        assert_eq!(publish(parent, NotifyKind::Renamed, b"dir"), Ok(1));
        assert_eq!(pending_owned(parent_watch, 43), Ok(1));
        assert_eq!(pending_owned(dir_watch, 42), Ok(0));

        // watch 跟随同一 VNode：目录内容变化仍照常投递。
        assert_eq!(publish(dir, NotifyKind::Created, b"child"), Ok(1));
        let mut events = [NotifyEvent::empty(); 2];
        assert_eq!(drain_owned(dir_watch, 42, &mut events), Ok(1));
        assert_eq!(events[0].child.as_bytes(), b"child");

        // 清理父目录（例如父目录后来被删除）不会波及子目录上的 watch。
        assert_eq!(invalidate_directory(parent), 1);
        assert_eq!(count(), 1);
        assert_eq!(unwatch_owned(dir_watch, 42), Ok(()));
        assert_eq!(count(), 0);
        clear();
    }
}
