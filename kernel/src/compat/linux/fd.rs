//! Linux file-descriptor table.
//!
//! The table is the Linux personality's **own** numbering space. It never
//! shares numbers, generations or storage with the native `HandleTable`: a
//! Linux fd indexes this table only, and its lifetime is tracked by an
//! independent reference count on the object it points at. `dup` shares the
//! same object (one more reference); `close` drops this descriptor's reference
//! and nothing else.
//!
//! Descriptors start at [`FIRST_FD`] (3); 0/1/2 are the console descriptors
//! installed by [`FdTable::install_console`]. Allocation always takes the
//! lowest free descriptor, which is what Linux programs expect after a
//! `close`/`dup2` pair.

use crate::object::{self, ObjectId};

use super::memory::LinuxMemory;

/// Descriptors 0, 1 and 2 are the console.
pub const CONSOLE_FDS: u32 = 3;
/// First descriptor handed to `open`/`socket`/`accept`.
pub const FIRST_FD: u32 = CONSOLE_FDS;
/// Fixed table capacity (agents.md: bounded, no dynamic growth).
pub const MAX_FDS: usize = 16;

/// One Linux descriptor.
///
/// `object` is the capability the descriptor refers to. The table holds exactly
/// one reference per descriptor, so `dup` acquires another reference and
/// `close` releases one; the object dies only when the last Linux reference
/// (and any native reference) is gone.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FdEntry {
    /// Object this descriptor refers to.
    pub object: ObjectId,
    /// `FD_CLOEXEC`: release this descriptor on `exec`.
    pub cloexec: bool,
    /// Linux address family (`AF_*`) recorded when a socket descriptor was
    /// created; `0` for descriptors that are not sockets or predate the record.
    ///
    /// `getsockname` needs it when the engine has no local address yet: an
    /// unbound socket must report a zeroed address of its **creation** family
    /// (16 bytes for `AF_INET`, 28 for `AF_INET6`, 2 for an anonymous
    /// `AF_UNIX`), and the engine intentionally returns `family = 0` there.
    pub domain: u16,
}

impl FdEntry {
    /// Build a non-socket descriptor entry.
    pub const fn new(object: ObjectId, cloexec: bool) -> Self {
        Self {
            object,
            cloexec,
            domain: 0,
        }
    }

    /// Build a socket descriptor entry, remembering its Linux `AF_*` family.
    pub const fn new_socket(object: ObjectId, cloexec: bool, domain: u16) -> Self {
        Self {
            object,
            cloexec,
            domain,
        }
    }
}

/// Why a descriptor operation failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FdError {
    /// The descriptor is outside the table or empty.
    BadFd,
    /// Every slot at or above [`FIRST_FD`] is taken.
    Full,
    /// The object reference could not be acquired/released.
    Object,
}

/// Per-process Linux file-descriptor table.
///
/// It also carries the Linux memory bookkeeping ([`LinuxMemory`]): the program
/// break and the `mmap` bump pointer are part of the same per-process
/// personality state and are created/destroyed with the table, so they need no
/// process-table entry of their own.
#[derive(Debug)]
pub struct FdTable {
    entries: [Option<FdEntry>; MAX_FDS],
    /// Linux `brk`/`mmap` state (M8a).
    pub memory: LinuxMemory,
    /// Original blocked mask while a `ppoll` temporary mask is installed.
    ///
    /// `ppoll` replaces the process signal mask for the duration of the wait.
    /// The value lives here because the table is the per-process Linux state
    /// that survives a blocking wait and its replay.
    ppoll_mask: Option<u64>,
    /// Mask to restore once the handler delivered by the `ppoll` interruption
    /// returns through `rt_sigreturn` (the delivery itself saves the temporary
    /// mask, so the original one has to be restored by the personality).
    ppoll_restore: Option<u64>,
}

impl FdTable {
    /// An empty table (no console descriptors yet).
    pub const fn new() -> Self {
        Self {
            entries: [None; MAX_FDS],
            memory: LinuxMemory::new(),
            ppoll_mask: None,
            ppoll_restore: None,
        }
    }

    /// Record the real end of the loaded image as the initial program break.
    ///
    /// Called by the process spawn path once the image is mapped; the Linux
    /// personality never guesses this address on its own. Frozen interface name
    /// (M8a contract): `FdTable::set_program_break(initial: u64)`.
    pub fn set_program_break(&mut self, initial: u64) {
        self.memory.set_initial_break(initial);
    }

    /// The current program break, or `None` until the spawn path initialised it.
    pub fn program_break(&self) -> Option<u64> {
        self.memory.program_break()
    }

    /// The original blocked mask while a `ppoll` temporary mask is active.
    pub fn ppoll_mask(&self) -> Option<u64> {
        self.ppoll_mask
    }

    /// Record that `ppoll` installed `original` as the mask to restore.
    ///
    /// Idempotent for a replay: the first pass owns the value and a later pass
    /// must never overwrite it with the temporary mask it observes.
    pub fn begin_ppoll_mask(&mut self, original: u64) {
        if self.ppoll_mask.is_none() {
            self.ppoll_mask = Some(original);
        }
    }

    /// Finish the `ppoll` temporary mask, returning the original mask (if one
    /// was installed) so the caller can put it back.
    pub fn end_ppoll_mask(&mut self) -> Option<u64> {
        self.ppoll_mask.take()
    }

    /// Remember the mask to restore once the delivered handler returns.
    pub fn set_pending_mask_restore(&mut self, mask: u64) {
        self.ppoll_restore = Some(mask);
    }

    /// Take the mask to restore after a handler delivered by `ppoll`.
    pub fn take_pending_mask_restore(&mut self) -> Option<u64> {
        self.ppoll_restore.take()
    }

    /// Install the console object at descriptors 0, 1 and 2.
    ///
    /// Each descriptor takes its own reference, so closing fd 1 does not remove
    /// fd 0 or 2. The table must not already carry console descriptors.
    pub fn install_console(&mut self, console: ObjectId) -> Result<(), FdError> {
        if self.entries[..CONSOLE_FDS as usize]
            .iter()
            .any(|entry| entry.is_some())
        {
            return Err(FdError::BadFd);
        }
        for fd in 0..CONSOLE_FDS as usize {
            if object::acquire_object(console).is_err() {
                // Roll back the references taken so far.
                for slot in 0..fd {
                    if let Some(entry) = self.entries[slot].take() {
                        let _ = object::release_object(entry.object);
                    }
                }
                return Err(FdError::Object);
            }
            self.entries[fd] = Some(FdEntry::new(console, false));
        }
        Ok(())
    }

    /// The console object, when descriptors 0/1/2 are installed.
    pub fn console(&self) -> Option<ObjectId> {
        self.entries[0].map(|entry| entry.object)
    }

    /// Look a descriptor up.
    pub fn get(&self, fd: u32) -> Result<FdEntry, FdError> {
        let index = fd as usize;
        if index >= MAX_FDS {
            return Err(FdError::BadFd);
        }
        self.entries[index].ok_or(FdError::BadFd)
    }

    /// Lowest free descriptor at or above [`FIRST_FD`].
    pub fn lowest_free(&self) -> Option<u32> {
        (FIRST_FD..MAX_FDS as u32).find(|fd| self.entries[*fd as usize].is_none())
    }

    /// Install `entry` in the lowest free descriptor, taking one reference.
    pub fn insert(&mut self, entry: FdEntry) -> Result<u32, FdError> {
        let fd = self.lowest_free().ok_or(FdError::Full)?;
        self.install_at(fd, entry)?;
        Ok(fd)
    }

    /// Install `entry` at an explicit descriptor (`dup2`), replacing any old
    /// entry there and taking one reference for the new one.
    pub fn install_at(&mut self, fd: u32, entry: FdEntry) -> Result<u32, FdError> {
        let index = fd as usize;
        if index >= MAX_FDS {
            return Err(FdError::BadFd);
        }
        if object::acquire_object(entry.object).is_err() {
            return Err(FdError::Object);
        }
        if let Some(old) = self.entries[index].replace(entry) {
            // Release the replaced descriptor's reference. This may drop the
            // object to zero and run its destroy hook; that is the same
            // behaviour as `close` on the overwritten descriptor.
            let _ = object::release_object(old.object);
        }
        Ok(fd)
    }

    /// `dup`: a new descriptor referring to the same object.
    pub fn dup(&mut self, fd: u32) -> Result<u32, FdError> {
        let entry = self.get(fd)?;
        self.insert(entry)
    }

    /// `fcntl(F_DUPFD)`: duplicate `fd` into the lowest free slot at or above
    /// `minimum`, optionally setting `FD_CLOEXEC` on the new descriptor.
    ///
    /// The new descriptor shares the same object (and therefore the same VFS
    /// open description and byte/directory position) as `fd`, which is what
    /// Linux `dup`-family semantics require.
    pub fn duplicate_at_least(
        &mut self,
        fd: u32,
        minimum: u32,
        cloexec: bool,
    ) -> Result<u32, FdError> {
        let entry = self.get(fd)?;
        let first = minimum.max(FIRST_FD);
        if first >= MAX_FDS as u32 {
            return Err(FdError::Full);
        }
        let target = (first..MAX_FDS as u32)
            .find(|candidate| self.entries[*candidate as usize].is_none())
            .ok_or(FdError::Full)?;
        // Keep the recorded socket family: `F_DUPFD` produces another Linux
        // descriptor for the same object, so `getsockname` on the duplicate must
        // report the same creation family as on the original.
        self.install_at(
            target,
            FdEntry {
                object: entry.object,
                cloexec,
                domain: entry.domain,
            },
        )?;
        Ok(target)
    }

    /// `dup2`: put the object of `oldfd` at `newfd`.
    pub fn dup_to(&mut self, oldfd: u32, newfd: u32) -> Result<u32, FdError> {
        if oldfd == newfd {
            self.get(oldfd)?;
            return Ok(newfd);
        }
        let entry = self.get(oldfd)?;
        self.install_at(newfd, entry)
    }

    /// Close one descriptor: drop exactly this descriptor's reference.
    pub fn close(&mut self, fd: u32) -> Result<(), FdError> {
        let index = fd as usize;
        if index >= MAX_FDS {
            return Err(FdError::BadFd);
        }
        let entry = self.entries[index].take().ok_or(FdError::BadFd)?;
        object::release_object(entry.object).map_err(|_| FdError::Object)?;
        Ok(())
    }

    /// Close every `FD_CLOEXEC` descriptor (`exec` behaviour). Returns the
    /// number of descriptors released.
    pub fn close_cloexec(&mut self) -> usize {
        let mut closed = 0;
        for index in 0..MAX_FDS {
            let cloexec = self.entries[index].map(|entry| entry.cloexec) == Some(true);
            if !cloexec {
                continue;
            }
            if let Some(entry) = self.entries[index].take() {
                let _ = object::release_object(entry.object);
                closed += 1;
            }
        }
        closed
    }

    /// Number of installed descriptors.
    pub fn len(&self) -> usize {
        self.entries.iter().filter(|entry| entry.is_some()).count()
    }

    /// Whether any descriptor is installed.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Set/clear `FD_CLOEXEC` on an installed descriptor.
    pub fn set_cloexec(&mut self, fd: u32, cloexec: bool) -> Result<(), FdError> {
        let index = fd as usize;
        if index >= MAX_FDS {
            return Err(FdError::BadFd);
        }
        let entry = self.entries[index].as_mut().ok_or(FdError::BadFd)?;
        entry.cloexec = cloexec;
        Ok(())
    }
}

impl Default for FdTable {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::object::{ObjectKind, test_lock};

    /// Creates a standalone object with `refs == 1` for table tests.
    fn object_of(kind: ObjectKind) -> ObjectId {
        object::create_with_payload(kind, 0).expect("object table has room")
    }

    #[test]
    fn descriptors_start_at_three_and_take_the_lowest_free_slot() {
        let _guard = test_lock();
        let console = object_of(ObjectKind::Console);
        let first = object_of(ObjectKind::Event);
        let second = object_of(ObjectKind::Event);
        let mut table = FdTable::new();
        table.install_console(console).expect("console installs");

        assert_eq!(table.get(0).map(|e| e.object), Ok(console));
        assert_eq!(table.get(2).map(|e| e.object), Ok(console));
        assert_eq!(table.get(3), Err(FdError::BadFd));

        let a = table.insert(FdEntry::new(first, false)).expect("first fd");
        let b = table
            .insert(FdEntry::new(second, false))
            .expect("second fd");
        assert_eq!((a, b), (3, 4));
        assert_eq!(table.lowest_free(), Some(5));

        table.close(4).expect("close the second descriptor");
        assert_eq!(table.lowest_free(), Some(4));
        let c = table
            .insert(FdEntry::new(second, false))
            .expect("reuse the lowest free slot");
        assert_eq!(c, 4);

        table.close(a).expect("close");
        table.close(c).expect("close");
        table.close(0).expect("close console");
        table.close(1).expect("close console");
        table.close(2).expect("close console");
    }

    #[test]
    fn dup_shares_the_object_and_close_releases_only_one_reference() {
        let _guard = test_lock();
        let console = object_of(ObjectKind::Console);
        let event = object_of(ObjectKind::Event);
        let start = object::object_refs(event).expect("object is alive");
        let mut table = FdTable::new();
        table.install_console(console).expect("console installs");
        let fd = table.insert(FdEntry::new(event, false)).expect("fd");
        assert_eq!(object::object_refs(event), Some(start + 1));

        let copy = table.dup(fd).expect("dup");
        assert_eq!(object::object_refs(event), Some(start + 2));

        table.close(fd).expect("close original");
        assert_eq!(object::object_refs(event), Some(start + 1));
        assert_eq!(table.get(copy).map(|e| e.object), Ok(event));

        table.close(copy).expect("close copy");
        assert_eq!(object::object_refs(event), Some(start));
        table.close(0).ok();
        table.close(1).ok();
        table.close(2).ok();
    }

    #[test]
    fn closing_a_missing_descriptor_reports_bad_fd_and_does_not_touch_the_table() {
        let _guard = test_lock();
        let console = object_of(ObjectKind::Console);
        let mut table = FdTable::new();
        table.install_console(console).expect("console installs");
        assert_eq!(table.close(3), Err(FdError::BadFd));
        assert_eq!(table.close(MAX_FDS as u32), Err(FdError::BadFd));
        assert_eq!(table.get(0).map(|e| e.object), Ok(console));
        table.close(0).ok();
        table.close(1).ok();
        table.close(2).ok();
    }

    #[test]
    fn a_full_table_reports_full_and_dup2_replaces_the_target() {
        let _guard = test_lock();
        let console = object_of(ObjectKind::Console);
        let mut table = FdTable::new();
        table.install_console(console).expect("console installs");
        for _ in FIRST_FD..MAX_FDS as u32 {
            let entry = object_of(ObjectKind::Event);
            table.insert(FdEntry::new(entry, false)).expect("fd");
        }
        assert_eq!(table.lowest_free(), None);
        let extra = object_of(ObjectKind::Event);
        assert_eq!(table.insert(FdEntry::new(extra, false)), Err(FdError::Full));

        let target = table.get(3).expect("fd 3 is installed");
        let source = table.get(4).expect("fd 4 is installed");
        table.dup_to(4, 3).expect("dup2 replaces fd 3");
        assert_eq!(table.get(3).map(|e| e.object), Ok(source.object));
        assert_ne!(source.object, target.object);
        assert_eq!(table.len(), MAX_FDS);
    }

    #[test]
    fn cloexec_closes_only_flagged_descriptors() {
        let _guard = test_lock();
        let console = object_of(ObjectKind::Console);
        let mut table = FdTable::new();
        table.install_console(console).expect("console installs");
        let keep = object_of(ObjectKind::Event);
        let drop = object_of(ObjectKind::Event);
        table.insert(FdEntry::new(keep, false)).expect("fd");
        table.insert(FdEntry::new(drop, true)).expect("fd");
        assert_eq!(table.close_cloexec(), 1);
        assert_eq!(table.get(3).map(|e| e.object), Ok(keep));
        assert_eq!(table.get(4), Err(FdError::BadFd));
    }

    #[test]
    fn socket_family_survives_dup_and_dup2() {
        let _guard = test_lock();
        let console = object_of(ObjectKind::Console);
        let socket = object_of(ObjectKind::Event);
        let mut table = FdTable::new();
        table.install_console(console).expect("console installs");
        let fd = table
            .insert(FdEntry::new_socket(
                socket,
                false,
                crate::compat::linux::address::AF_INET6,
            ))
            .expect("socket fd");
        assert_eq!(table.get(fd).map(|entry| entry.domain), Ok(10));

        let copy = table.dup(fd).expect("dup");
        assert_eq!(table.get(copy).map(|entry| entry.domain), Ok(10));

        // `dup2` onto the console descriptor keeps the source's family.
        table.dup_to(fd, 1).expect("dup2 onto fd 1");
        assert_eq!(table.get(1).map(|entry| entry.domain), Ok(10));

        table.close(fd).ok();
        table.close(copy).ok();
        table.close(1).ok();
        table.close(0).ok();
        table.close(2).ok();
    }
}
