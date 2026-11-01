//! Read-only initramfs backing for the boot modules.
//!
//! The M5a rule is that the boot payloads are reached through the VFS and the
//! page cache, but their bytes stay where the loader put them: `bootmod` already
//! mapped each module read-only and owns that window, so this module only copies
//! bytes out of it, page by page, on a cache miss. There is deliberately no
//! second ELF loader and no second copy of the payload.
//!
//! The reader is a `fn` pointer so host tests can substitute their own backing
//! store while production code keeps using `bootmod` (which is unavailable before
//! `bootmod::init` succeeds).

use super::types::VfsError;
use crate::bootmod;

/// Copy `page_start..` of the named module into `page`.
///
/// `page_start` is the byte offset of the page being filled and `page` is always
/// a whole page: the cache zeroed it first, so a tail shorter than the page is
/// already in its final state once the available bytes are copied.
pub type Reader = fn(name: &[u8], page_start: u64, page: &mut [u8]) -> Result<(), VfsError>;

static mut READER: Option<Reader> = None;

/// Install the backing reader used by the VFS (production: [`bootmod_reader`]).
pub fn install_reader(reader: Reader) {
    // SAFETY: single-CPU boot path, called once from `vfs::init` before any file
    // is opened; the installer and readers are serialised by the VFS.
    unsafe { *core::ptr::addr_of_mut!(READER) = Some(reader) };
}

/// Currently installed reader, if any.
pub fn installed_reader() -> Option<Reader> {
    // SAFETY: reading an immutable `fn` pointer; the value is only replaced while
    // the VFS is not yet published.
    unsafe { *core::ptr::addr_of!(READER) }
}

/// Drop the installed reader again (host tests only): a test that installs a
/// fake backing store must not leak it into the next test, which shares the
/// process-wide `static`.
#[cfg(test)]
pub fn clear_reader() {
    // SAFETY: tests hold the VFS test lock, so no reader is running here.
    unsafe { *core::ptr::addr_of_mut!(READER) = None };
}

/// Production reader: stream the module out of the boot module window.
pub fn bootmod_reader(name: &[u8], page_start: u64, page: &mut [u8]) -> Result<(), VfsError> {
    if !bootmod::is_ready() {
        return Err(VfsError::NotSupported);
    }
    let id = bootmod::open(name).map_err(map_bootmod)?;
    let mut copied = 0usize;
    let mut outcome = Ok(());
    while copied < page.len() {
        match bootmod::read(id, page_start + copied as u64, &mut page[copied..]) {
            Ok(0) => break,
            Ok(read) => copied += read,
            Err(error) => {
                outcome = Err(map_bootmod(error));
                break;
            }
        }
    }
    let closed = bootmod::close(id);
    outcome.and(closed.map_err(map_bootmod))
}

/// Fill one page through the installed reader.
pub fn fill(name: &[u8], page_start: u64, page: &mut [u8]) -> Result<(), VfsError> {
    let reader = installed_reader().ok_or(VfsError::NotSupported)?;
    reader(name, page_start, page)
}

/// Fill one page through an explicit reader (used by tests).
#[cfg(test)]
pub fn fill_with(
    reader: Reader,
    name: &[u8],
    page_start: u64,
    page: &mut [u8],
) -> Result<(), VfsError> {
    reader(name, page_start, page)
}

/// Translate a boot-module failure into the closed VFS error set.
fn map_bootmod(error: bootmod::BootModError) -> VfsError {
    match error {
        bootmod::BootModError::NotReady | bootmod::BootModError::BadName => VfsError::NotSupported,
        bootmod::BootModError::NotFound | bootmod::BootModError::BadModuleId => VfsError::NotFound,
        bootmod::BootModError::OutOfRange => VfsError::Corrupt,
        _ => VfsError::Corrupt,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const INIT: &[u8] = b"init-payload-with-more-than-one-page?";

    fn fake_reader(name: &[u8], page_start: u64, page: &mut [u8]) -> Result<(), VfsError> {
        if name != b"init" {
            return Err(VfsError::NotFound);
        }
        let start = page_start as usize;
        if start >= INIT.len() {
            return Ok(());
        }
        let available = (INIT.len() - start).min(page.len());
        page[..available].copy_from_slice(&INIT[start..start + available]);
        Ok(())
    }

    #[test]
    fn reader_copies_only_the_available_bytes() {
        let mut page = [0u8; 64];
        fill_with(fake_reader, b"init", 0, &mut page).unwrap();
        assert_eq!(&page[..INIT.len()], INIT);
        assert!(page[INIT.len()..].iter().all(|&byte| byte == 0));
    }

    #[test]
    fn pages_past_the_end_stay_zero() {
        let mut page = [0u8; 4096];
        fill_with(fake_reader, b"init", 4096, &mut page).unwrap();
        assert!(page.iter().all(|&byte| byte == 0));
    }

    #[test]
    fn unknown_modules_are_not_found() {
        let mut page = [0u8; 16];
        assert_eq!(
            fill_with(fake_reader, b"child", 0, &mut page).unwrap_err(),
            VfsError::NotFound
        );
    }

    #[test]
    fn the_production_reader_is_refused_before_bootmod_is_ready() {
        let mut page = [0u8; 16];
        // `cargo test` runs the kernel library on the host, where no boot module
        // was ever mapped.
        assert_eq!(
            bootmod_reader(b"init", 0, &mut page).unwrap_err(),
            VfsError::NotSupported
        );
    }
}
