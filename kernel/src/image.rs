//! Loads a boot module's ELF image into a fresh user address space (M4/M5a).
//!
//! This is deliberately the *only* image loader: `init` is loaded by the kernel
//! root and `child` is loaded by [`crate::process`] through the same
//! [`load_module`] path, so there is no second, divergent loader. The rules are
//! the ones agents.md §5.6 fixes for boot modules: a fixed set of named
//! payloads, no arbitrary path resolution, read-only input, and the same
//! ELF/permission checks that later milestones will use.
//!
//! Since M5a the payload bytes come from the **VFS** (`/boot/<name>`), which
//! serves the boot modules from the VNode/page-cache path; this module no
//! longer reads `bootmod` directly. That keeps the M4 loader and its validation
//! rules while moving the storage behind the VFS interface required by §5.6.
//!
//! Layout produced for each process:
//!
//! ```text
//!   ELF PT_LOAD segments      at their p_vaddr (low half, W^X enforced)
//!   0x00_7F_F000              user stack guard page (left unmapped)
//!   0x00_80_0000 .. +8 pages  user stack, writable, non-executable
//! ```
//!
//! `LoadedImage::user_stack` is the 16-byte aligned stack top: the ring3 entry
//! ABI (frozen with the scheduler and native-rt) starts user code with
//! `rsp == stack_top`, i.e. `rsp % 16 == 0` at the first instruction, matching
//! the SysV convention for a call target.

use crate::mm::addrspace::{self, AddressSpaceId};
use crate::mm::pmm;
use crate::mm::vm;

/// First page of the user stack (8 MiB, well clear of the 4 MiB image).
pub const USER_STACK_BASE: u64 = 0x0080_0000;
/// Pages of user stack (32 KiB).
pub const USER_STACK_FRAMES: u64 = 8;
/// Guard page directly below the stack: never mapped.
pub const USER_STACK_GUARD: u64 = USER_STACK_BASE - PAGE;
/// One past the last stack byte; this is the ring3 entry `rsp`.
pub const USER_STACK_TOP: u64 = USER_STACK_BASE + USER_STACK_FRAMES * PAGE;

const PAGE: u64 = 4096;

/// Largest boot module the staging path will read, in bytes.
///
/// The payload is staged once into this fixed buffer and then handed to the
/// shared ELF loader, which needs random access to the whole file image (it
/// validates `p_offset + p_filesz` against the file length). The buffer lives in
/// `.bss`, so raising the bound costs no boot-stack and no heap; it is a
/// compile-time ceiling, never an allocation.
///
/// M6a1 raised it from 1 MiB to 2 MiB: the debug `caelum-init` image reached
/// 1,067,776 bytes, which a 1 MiB bound rejected as `ModuleTooLarge` before the
/// ELF was even parsed. A larger module still fails loudly instead of being
/// silently truncated.
pub const MAX_MODULE_BYTES: usize = 2 << 20;

/// VFS path prefix for boot modules: `/boot/<name>`.
const BOOT_PATH_PREFIX: &[u8] = b"/boot/";

/// Longest module name accepted by the path builder.
const MAX_MODULE_NAME: usize = 16;

/// Fixed stack capacity for a `/boot/<name>` path (6 + 16 + slack).
const PATH_CAPACITY: usize = 40;

/// M9d1: VFS path of the dynamic-executable closure's PIE main program.
///
/// FAT is strictly 8.3, so the name has no second hyphen. The root passes this
/// exact path; the loader accepts nothing else.
pub const DYNAMIC_MAIN_PATH: &[u8] = b"/fat/dyn-main";

/// M9d1: VFS path of the program interpreter.
///
/// The main image's `PT_INTERP` record must name this path byte for byte; the
/// kernel uses that string directly as the VFS path (no second mapping table).
pub const DYNAMIC_INTERPRETER_PATH: &[u8] = b"/fat/ldcaelum.so";

/// M9d2: VFS path of the vDSO image.
///
/// The vDSO is a real ET_EXEC ELF linked at [`crate::vdso::VDSO_BASE`]. The
/// kernel maps its read-only/executable segments and then maps the shared,
/// kernel-owned data page in place of the image's writable segment.
pub const DYNAMIC_VDSO_PATH: &[u8] = b"/fat/vdso.so";

/// M9e: VFS path of the single shared library the dynamic closure may request.
///
/// The main program's `DT_NEEDED` list must contain exactly this path (or be
/// empty, which keeps the M9d1/M9d2 closure unchanged).
pub const DYNAMIC_LIBRARY_PATH: &[u8] = b"/fat/m9e.so";

/// M9e: virtual bias at which the shared library is mapped.
pub const DYNAMIC_LIBRARY_BIAS: u64 = 0x0300_0000;

/// M9e: size of the reserved window above [`DYNAMIC_LIBRARY_BIAS`].
pub const DYNAMIC_LIBRARY_WINDOW: u64 = 0x0100_0000;

/// M9e: upper bound on the mapped size of the shared library.
pub const MAX_DYNAMIC_LIBRARY_BYTES: usize = 64 * 1024;

/// M9f: VFS path of the first chained library.
///
/// When the main program requests this path, `/fat/m9f-a.so` must in turn
/// request exactly [`DYNAMIC_LIBRARY_B_PATH`], one level deep and no further.
pub const DYNAMIC_LIBRARY_A_PATH: &[u8] = b"/fat/m9f-a.so";

/// M9f: virtual bias at which the first chained library is mapped.
pub const DYNAMIC_LIBRARY_A_BIAS: u64 = 0x0380_0000;

/// M9f: VFS path of the second chained library (it has no dependencies).
pub const DYNAMIC_LIBRARY_B_PATH: &[u8] = b"/fat/m9f-b.so";

/// M9f: virtual bias at which the second chained library is mapped.
pub const DYNAMIC_LIBRARY_B_BIAS: u64 = 0x0400_0000;

/// M9d1: virtual bias at which the PIE main program is mapped.
pub const DYNAMIC_MAIN_BIAS: u64 = 0x0200_0000;

/// Staging buffer for one module payload.
///
/// Invariants: used only by the image loader, on the boot CPU with interrupts
/// disabled (`spawn_init` from the root and `process_create` from a syscall both
/// run with IF=0) and never recursively.
static mut MODULE_STAGING: [u8; MAX_MODULE_BYTES] = [0; MAX_MODULE_BYTES];

fn staging_base() -> *mut u8 {
    core::ptr::addr_of_mut!(MODULE_STAGING) as *mut u8
}

/// A module mapped into a ready-to-run user address space.
#[derive(Clone, Copy, Debug)]
pub struct LoadedImage {
    /// The process address space holding the image and its stack.
    pub address_space: AddressSpaceId,
    /// ELF entry point (virtual address).
    pub entry: u64,
    /// Initial user stack pointer (16-byte aligned, one past the stack).
    pub user_stack: u64,
    /// One past the last byte the image occupies, rounded up to a page.
    ///
    /// This is the highest page-aligned `p_vaddr + p_memsz` over all `PT_LOAD`
    /// segments, so it covers `.bss` (which carries no file bytes) and every
    /// page the loader mapped. It deliberately does not include the user stack:
    /// it is the initial program break (`brk(2)` starts at the end of the
    /// image, not at the end of the file).
    pub image_end: u64,
}

/// M9d1: a PIE main program plus its interpreter, mapped into one new address
/// space and ready to start at the interpreter's entry point.
///
/// The kernel writes the dynamic auxv from these fields and jumps to `entry`
/// (the interpreter). It never applies the main program's RELA relocations: the
/// interpreter does that in user mode and then jumps to `main_entry`.
#[derive(Clone, Copy, Debug)]
pub struct DynamicImage {
    /// Address space holding both images and the shared user stack.
    pub address_space: AddressSpaceId,
    /// Interpreter entry point: the kernel's ring-3 entry for this process.
    pub entry: u64,
    /// Main program entry in its biased (runtime) address (`AT_ENTRY`).
    pub main_entry: u64,
    /// Initial user stack pointer (16-byte aligned, one past the stack).
    pub user_stack: u64,
    /// Page-aligned end of the main program's image (initial program break).
    pub image_end: u64,
    /// Runtime address of the main program's first program header (`AT_PHDR`).
    pub phdr: u64,
    /// Program header entry size of the main program (`AT_PHENT`).
    pub phent: u32,
    /// Program header count of the main program (`AT_PHNUM`).
    pub phnum: u32,
    /// M9e: bias of the mapped shared library, or 0 when the main program has
    /// no `DT_NEEDED` entry (the M9d1/M9d2 closure).
    pub library_base: u64,
    /// M9f: bias of `/fat/m9f-a.so`, or 0 when it is not needed.
    ///
    /// The interpreter resolves the same address from its own frozen constant;
    /// the kernel only records it for the mapping bookkeeping and tests.
    pub library_a_base: u64,
    /// M9f: bias of `/fat/m9f-b.so`, or 0 when the chain has no second level.
    pub library_b_base: u64,
}

/// Why loading a module failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ImageError {
    /// The boot-module table is not initialised yet.
    NotReady,
    /// No boot module has that name.
    ModuleNotFound,
    /// The payload is not a valid user-mode ELF.
    ElfRejected,
    /// A load segment's range is malformed or overlaps the stack.
    BadSegment,
    /// The image needs more user frames than an address space can hold.
    TooManyFrames,
    /// The physical allocator ran out of frames.
    OutOfFrames,
    /// Mapping a page into the address space failed.
    MapFailed,
    /// Creating the address space failed.
    AddressSpaceFailed,
    /// Address arithmetic overflowed.
    Overflow,
    /// The VFS could not serve the module payload.
    VfsFailed,
    /// The payload is larger than the M5a staging bound.
    ModuleTooLarge,
    /// M9d1: the dynamic main path is not the frozen `/fat/dyn-main`.
    DynamicPath,
    /// M9d1: the main image has no `PT_INTERP` record.
    InterpreterMissing,
    /// M9d1: `PT_INTERP` does not name the frozen interpreter path.
    InterpreterMismatch,
    /// M9d1: the main program's program-header table is not file-backed by a
    /// mapped `PT_LOAD` segment, so `AT_PHDR` cannot be pointed at it.
    PhdrNotMapped,
    /// M9d2: staging, parsing or mapping the vDSO image failed.
    VdsoFailed,
    /// M9e: the main program's `DT_NEEDED` list does not name exactly the one
    /// supported shared library.
    LibraryMismatch,
    /// M9e: the shared library image is malformed, needs its own library, or
    /// falls outside its reserved window.
    LibraryRejected,
}

impl ImageError {
    /// Stable short string for the serial log.
    pub const fn as_str(self) -> &'static str {
        match self {
            ImageError::NotReady => "image-not-ready",
            ImageError::ModuleNotFound => "image-module-not-found",
            ImageError::ElfRejected => "image-elf-rejected",
            ImageError::BadSegment => "image-bad-segment",
            ImageError::TooManyFrames => "image-too-many-frames",
            ImageError::OutOfFrames => "image-out-of-frames",
            ImageError::MapFailed => "image-map-failed",
            ImageError::AddressSpaceFailed => "image-address-space-failed",
            ImageError::Overflow => "image-overflow",
            ImageError::VfsFailed => "image-vfs-failed",
            ImageError::ModuleTooLarge => "image-module-too-large",
            ImageError::DynamicPath => "image-dynamic-path",
            ImageError::InterpreterMissing => "image-interpreter-missing",
            ImageError::InterpreterMismatch => "image-interpreter-mismatch",
            ImageError::PhdrNotMapped => "image-phdr-not-mapped",
            ImageError::VdsoFailed => "image-vdso-failed",
            ImageError::LibraryMismatch => "image-library-mismatch",
            ImageError::LibraryRejected => "image-library-rejected",
        }
    }
}

/// Build the fixed `/boot/<name>` VFS path for a boot module.
///
/// Boot modules live in a fixed, read-only VFS directory (agents.md §5.6): the
/// path is built on the stack from a validated single-component name, so no
/// caller-supplied path can escape `/boot`.
fn module_path(name: &[u8]) -> Result<([u8; PATH_CAPACITY], usize), ImageError> {
    if name.is_empty() || name.len() > MAX_MODULE_NAME {
        return Err(ImageError::ModuleNotFound);
    }
    // A module name is one path component: no separators, no NULs, no traversal.
    if name.iter().any(|&byte| byte == b'/' || byte == 0) || name == b"." || name == b".." {
        return Err(ImageError::ModuleNotFound);
    }
    let len = BOOT_PATH_PREFIX.len() + name.len();
    if len > PATH_CAPACITY {
        return Err(ImageError::ModuleNotFound);
    }
    let mut path = [0u8; PATH_CAPACITY];
    path[..BOOT_PATH_PREFIX.len()].copy_from_slice(BOOT_PATH_PREFIX);
    path[BOOT_PATH_PREFIX.len()..len].copy_from_slice(name);
    Ok((path, len))
}

/// Reclaim the page-cache pages a boot payload left resident.
///
/// The cache budget is 512 pages and the two boot images alone are 293 (`init`)
/// plus 221 (`child`) pages, so a staging pass must not leave its pages behind:
/// the previous module is reclaimed before the read and this one afterwards.
/// The leading call is best effort — a missing module has nothing resident and
/// must still report `ModuleNotFound` — while a failed trailing reclaim is a real
/// error, because the next spawn would no longer fit.
fn release_boot_pages(path: &[u8]) -> bool {
    #[cfg(test)]
    if let Some(forced) = staging_probe::override_result() {
        return forced;
    }
    crate::vfs::release_boot_pages(path).is_ok()
}

/// Combine the read with the trailing reclaim.
///
/// The read error is the primary one: a short or failed read is what the caller
/// must see. A failed reclaim only matters when the payload did arrive, because
/// then the pages are still held and the next spawn can run out of budget.
fn staging_outcome(
    read: Result<usize, crate::vfs::VfsError>,
    expected: usize,
    released: bool,
) -> Result<usize, ImageError> {
    match read {
        Ok(read) if read == expected => {
            if released {
                Ok(expected)
            } else {
                Err(ImageError::VfsFailed)
            }
        }
        Ok(_) | Err(_) => Err(ImageError::VfsFailed),
    }
}

/// Stage the module payload through the VFS and return its length.
///
/// The payload is served by the VFS (VNode + page cache) and staged into
/// [`MODULE_STAGING`] because `elf64` needs random access to the whole file
/// image for its bounds checks. The bound is checked before reading, so a
/// module is never silently truncated.
///
/// Boot payloads are immutable and read once per spawn, so their cache pages are
/// dropped again on the way out: after this returns, `MODULE_STAGING` is the only
/// copy the loader needs, and the 512-page cache must stay free for the next
/// module (`init` and `child` together exceed it).
fn stage_module(path: &[u8]) -> Result<usize, ImageError> {
    // Reclaim whatever the previous module left behind before reading this one.
    let _ = release_boot_pages(path);
    let size = match crate::vfs::stat_path(path) {
        Ok(stat) => stat.size,
        Err(_) => return Err(ImageError::ModuleNotFound),
    };
    if size == 0 {
        return Err(ImageError::ModuleNotFound);
    }
    let size = usize::try_from(size).map_err(|_| ImageError::ModuleTooLarge)?;
    if size > MAX_MODULE_BYTES {
        return Err(ImageError::ModuleTooLarge);
    }
    stage_payload(path, size)
}

/// Read `size` payload bytes into [`MODULE_STAGING`] and drop the cache copy.
///
/// Split out of [`stage_module`] so the trailing reclaim (which must run even
/// when the read fails) is reachable without a live VFS.
fn stage_payload(path: &[u8], size: usize) -> Result<usize, ImageError> {
    let base = staging_base();
    // SAFETY: `base` is the whole staging array; nothing else reads or writes it
    // while the read runs (boot CPU, IF=0, no recursion).
    let staging = unsafe { core::slice::from_raw_parts_mut(base, size) };
    let read = crate::vfs::read_all_path(path, staging);
    // The payload now lives in `MODULE_STAGING`; drop the cache copy so the next
    // module (and every later spawn) still fits in the cache budget.
    let released = release_boot_pages(path);
    staging_outcome(read, size, released)
}

/// Test-only injection point for the boot-cache reclaim.
///
/// The lifecycle assertions (one reclaim before the read, one after, first error
/// wins) need to count the calls and to force a failure without a live VFS.
#[cfg(test)]
mod staging_probe {
    use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    static RELEASES: AtomicUsize = AtomicUsize::new(0);
    static FORCED_FAILURE: AtomicBool = AtomicBool::new(false);

    /// Forget the counters and any forced failure.
    pub fn reset() {
        RELEASES.store(0, Ordering::SeqCst);
        FORCED_FAILURE.store(false, Ordering::SeqCst);
    }

    /// Reclaim attempts counted since [`reset`].
    pub fn releases() -> usize {
        RELEASES.load(Ordering::SeqCst)
    }

    /// Make every reclaim attempt fail.
    pub fn force_failure() {
        FORCED_FAILURE.store(true, Ordering::SeqCst);
    }

    /// Count one attempt and report the forced result, if one is armed.
    pub fn override_result() -> Option<bool> {
        RELEASES.fetch_add(1, Ordering::SeqCst);
        if FORCED_FAILURE.load(Ordering::SeqCst) {
            Some(false)
        } else {
            None
        }
    }
}

/// Load the named boot module into a new user address space.
///
/// The payload is read through the VFS (`/boot/<name>`); on any failure the
/// partially built address space is destroyed, so the caller never has to clean
/// up frames it does not own.
pub fn load_module(name: &[u8]) -> Result<LoadedImage, ImageError> {
    let (path, path_len) = module_path(name)?;
    let path = &path[..path_len];
    let size = stage_module(path)?;
    let base = staging_base();
    // SAFETY: `stage_module` filled exactly `base[..size]` and has returned, so
    // the shared slice no longer aliases the mutable one.
    let bytes = unsafe { core::slice::from_raw_parts(base, size) };
    let elf = elf64::Elf64::parse(bytes).map_err(|_| ImageError::ElfRejected)?;
    elf.validate_for_user()
        .map_err(|_| ImageError::ElfRejected)?;

    // Reject a layout we cannot honour before allocating anything, and learn
    // where the loaded image ends (page aligned, including `.bss`) so callers
    // can seed the Linux program break.
    let image_end = check_layout(&elf)?;

    let address_space = addrspace::create().map_err(|_| ImageError::AddressSpaceFailed)?;
    match load_into(address_space, &elf, bytes) {
        Ok(()) => Ok(LoadedImage {
            address_space,
            entry: elf.entry,
            user_stack: USER_STACK_TOP,
            image_end,
        }),
        Err(error) => {
            let _ = addrspace::destroy(address_space);
            Err(error)
        }
    }
}

/// Verify that a boot module is reachable through the VFS.
///
/// The kernel root calls this to earn the `M5a bootmod via vfs OK` marker: the
/// bytes must arrive through [`crate::vfs::read_path`] (VNode + page cache), not
/// from `bootmod` directly.
pub fn probe_boot_module(name: &[u8]) -> Result<(), ImageError> {
    let (path, path_len) = module_path(name)?;
    let mut magic = [0u8; 4];
    match crate::vfs::read_path(&path[..path_len], 0, &mut magic) {
        Ok(4) if magic == [0x7F, b'E', b'L', b'F'] => Ok(()),
        Ok(_) | Err(_) => Err(ImageError::VfsFailed),
    }
}

/// Stage one fixed `/fat` file through the VFS and return its length.
///
/// Unlike [`stage_module`] this path has no boot-cache reclaim: `/fat` is a disk
/// filesystem and `release_boot_pages` only knows `/boot`. The size bound and
/// the read must still be checked so a payload is never silently truncated.
fn stage_dynamic_file(path: &[u8]) -> Result<usize, ImageError> {
    let stat = crate::vfs::stat_path(path).map_err(|_| ImageError::ModuleNotFound)?;
    let size = usize::try_from(stat.size).map_err(|_| ImageError::ModuleTooLarge)?;
    if size == 0 {
        return Err(ImageError::ModuleNotFound);
    }
    if size > MAX_MODULE_BYTES {
        return Err(ImageError::ModuleTooLarge);
    }
    let base = staging_base();
    // SAFETY: `base` is the whole staging array; nothing else reads or writes it
    // while the read runs (boot CPU, IF=0, no recursion).
    let staging = unsafe { core::slice::from_raw_parts_mut(base, size) };
    match crate::vfs::read_all_path(path, staging) {
        Ok(read) if read == size => Ok(size),
        Ok(_) | Err(_) => Err(ImageError::VfsFailed),
    }
}

/// Whether `[start, end)` is file-backed by some `PT_LOAD` at `bias`.
fn phdr_is_mapped(elf: &elf64::Elf64<'_>, bias: u64, start: u64, end: u64) -> bool {
    if start >= end {
        return false;
    }
    for index in 0..elf.phnum() {
        let header = match elf.phdr(index) {
            Some(header) => header,
            None => return false,
        };
        if header.p_type != elf64::PT_LOAD || header.filesz == 0 {
            continue;
        }
        let seg_start = match bias.checked_add(header.vaddr) {
            Some(value) => value,
            None => continue,
        };
        let seg_end = match seg_start.checked_add(header.filesz) {
            Some(value) => value,
            None => continue,
        };
        if seg_start <= start && end <= seg_end {
            return true;
        }
    }
    false
}

/// Load the dynamic-executable closure (M9d1): `/fat/dyn-main` plus the
/// interpreter named by its `PT_INTERP` record.
///
/// Both images are mapped into the same new address space: the main program at
/// [`DYNAMIC_MAIN_BIAS`] and the interpreter (an `ET_EXEC` image) at its link
/// address. The kernel does not apply the main program's RELA relocations; it
/// records `AT_PHDR`/`AT_PHENT`/`AT_PHNUM`/`AT_ENTRY` from the *main* image and
/// returns the interpreter's entry as the ring-3 entry point.
pub fn load_dynamic(main_path: &[u8]) -> Result<DynamicImage, ImageError> {
    if main_path != DYNAMIC_MAIN_PATH {
        return Err(ImageError::DynamicPath);
    }

    // 1. Validate the main image before touching the PMM: a rejected closure must
    //    not allocate (and then have to release) an address space.
    let (main_entry, image_end, phdr, phent, phnum, libraries) = {
        let size = stage_dynamic_file(DYNAMIC_MAIN_PATH)?;
        // SAFETY: `stage_dynamic_file` filled exactly `staging_base()[..size]`
        // and returned, so the slice no longer aliases the mutable one.
        let bytes = unsafe { core::slice::from_raw_parts(staging_base(), size) };
        let elf = elf64::Elf64::parse(bytes).map_err(|_| ImageError::ElfRejected)?;
        if !elf.is_dynamic() {
            return Err(ImageError::ElfRejected);
        }
        match elf.interpreter() {
            Some(path) if path == DYNAMIC_INTERPRETER_PATH => {}
            Some(_) => return Err(ImageError::InterpreterMismatch),
            None => return Err(ImageError::InterpreterMissing),
        }
        if elf.validate_for_user_dynamic(DYNAMIC_MAIN_BIAS).is_err() {
            return Err(ImageError::ElfRejected);
        }
        let image_end = check_layout_at(&elf, DYNAMIC_MAIN_BIAS)?;
        let phdr = DYNAMIC_MAIN_BIAS
            .checked_add(elf.phoff())
            .ok_or(ImageError::Overflow)?;
        let phdr_end = (elf.phnum() as u64)
            .checked_mul(u64::from(elf.phentsize()))
            .and_then(|len| phdr.checked_add(len))
            .ok_or(ImageError::Overflow)?;
        if !phdr_is_mapped(&elf, DYNAMIC_MAIN_BIAS, phdr, phdr_end) {
            return Err(ImageError::PhdrNotMapped);
        }
        let main_entry = DYNAMIC_MAIN_BIAS
            .checked_add(elf.entry)
            .ok_or(ImageError::Overflow)?;
        // M9e/M9f: resolve the supported `DT_NEEDED` closure. An empty list
        // keeps the M9d1/M9d2 closure exactly as is; `/fat/m9e.so` is the
        // single-library M9e closure; `/fat/m9f-a.so` (optionally together
        // with m9e) adds the B→A chain at its frozen biases.
        let libraries = plan_for_elf(&elf)?;
        (
            main_entry,
            image_end,
            phdr,
            elf.phentsize(),
            elf.phnum(),
            libraries,
        )
    };

    // 1b. Validate the vDSO image before touching the PMM as well. It is a
    //     plain static `ET_EXEC` image linked at [`crate::vdso::VDSO_BASE`];
    //     only its read-only/executable segment is mapped from the file (the
    //     writable segment's address is covered by the kernel's own data page).
    {
        let size = stage_dynamic_file(DYNAMIC_VDSO_PATH).map_err(|_| ImageError::VdsoFailed)?;
        // SAFETY: `stage_dynamic_file` filled exactly `staging_base()[..size]`.
        let bytes = unsafe { core::slice::from_raw_parts(staging_base(), size) };
        let vdso = elf64::Elf64::parse(bytes).map_err(|_| ImageError::VdsoFailed)?;
        if vdso.is_dynamic() || vdso.validate_for_user().is_err() {
            return Err(ImageError::VdsoFailed);
        }
        check_layout(&vdso).map_err(|_| ImageError::VdsoFailed)?;
        if vdso.entry != crate::vdso::VDSO_ENTRY {
            return Err(ImageError::VdsoFailed);
        }
    }

    // 1c. M9e/M9f: validate every requested shared library before allocating
    //     anything. Each is a plain ET_DYN image with no interpreter; m9e and
    //     B have no dependencies, A must need exactly B. The whole chain is
    //     validated here so a rejected closure cannot leak an address space.
    if libraries.m9e_base != 0 {
        validate_shared_library_from_vfs(DYNAMIC_LIBRARY_PATH, DYNAMIC_LIBRARY_BIAS, None)?;
    }
    if libraries.a_base != 0 {
        validate_shared_library_from_vfs(
            DYNAMIC_LIBRARY_A_PATH,
            DYNAMIC_LIBRARY_A_BIAS,
            Some(DYNAMIC_LIBRARY_B_PATH),
        )?;
    }
    if libraries.b_base != 0 {
        validate_shared_library_from_vfs(DYNAMIC_LIBRARY_B_PATH, DYNAMIC_LIBRARY_B_BIAS, None)?;
    }

    // 2. Allocate the address space and map both images. The main image is
    //    mapped before the interpreter is staged, because staging reuses the
    //    single module buffer.
    let address_space = match addrspace::create() {
        Ok(address_space) => address_space,
        Err(_) => return Err(ImageError::AddressSpaceFailed),
    };
    let loaded = (|| -> Result<u64, ImageError> {
        let size = stage_dynamic_file(DYNAMIC_MAIN_PATH)?;
        // SAFETY: the staging buffer is filled and read sequentially on the boot
        // CPU with interrupts disabled; the slice ends before staging is reused.
        let bytes = unsafe { core::slice::from_raw_parts(staging_base(), size) };
        let elf = elf64::Elf64::parse(bytes).map_err(|_| ImageError::ElfRejected)?;
        load_segments_at(address_space, &elf, bytes, DYNAMIC_MAIN_BIAS)?;

        let interp_size = stage_dynamic_file(DYNAMIC_INTERPRETER_PATH)?;
        // SAFETY: the previous staging slice ended with the call above.
        let interp = unsafe { core::slice::from_raw_parts(staging_base(), interp_size) };
        let interp_elf = elf64::Elf64::parse(interp).map_err(|_| ImageError::ElfRejected)?;
        // The interpreter is a plain static ET_EXEC image: it must not need a
        // second loader level and it is mapped at its link address (bias 0).
        if interp_elf.is_dynamic() || interp_elf.validate_for_user().is_err() {
            return Err(ImageError::ElfRejected);
        }
        check_layout(&interp_elf)?;
        load_segments_at(address_space, &interp_elf, interp, 0)?;

        // M9d2: map the read-only/executable half of the vDSO and then its
        // kernel-owned data page. The vDSO image's writable segment is skipped
        // by `load_vdso_segments`; `vdso::map_into` maps the read-only data
        // frame at exactly that address instead.
        let vdso_size =
            stage_dynamic_file(DYNAMIC_VDSO_PATH).map_err(|_| ImageError::VdsoFailed)?;
        // SAFETY: the previous staging slice ended with the call above.
        let vdso_bytes = unsafe { core::slice::from_raw_parts(staging_base(), vdso_size) };
        let vdso = elf64::Elf64::parse(vdso_bytes).map_err(|_| ImageError::VdsoFailed)?;
        load_vdso_segments(address_space, &vdso, vdso_bytes)?;
        crate::vdso::map_into(address_space).map_err(|_| ImageError::VdsoFailed)?;

        // M9e/M9f: map the shared libraries into the same address space at
        // their frozen biases, deepest first (B, then A, then m9e). The kernel
        // never applies relocations; the interpreter does that afterwards.
        if libraries.b_base != 0 {
            let library_size = stage_dynamic_file(DYNAMIC_LIBRARY_B_PATH)?;
            // SAFETY: the previous staging slice ended with the call above.
            let library_bytes =
                unsafe { core::slice::from_raw_parts(staging_base(), library_size) };
            let library =
                elf64::Elf64::parse(library_bytes).map_err(|_| ImageError::LibraryRejected)?;
            load_segments_at(
                address_space,
                &library,
                library_bytes,
                DYNAMIC_LIBRARY_B_BIAS,
            )?;
        }
        if libraries.a_base != 0 {
            let library_size = stage_dynamic_file(DYNAMIC_LIBRARY_A_PATH)?;
            // SAFETY: the previous staging slice ended with the call above.
            let library_bytes =
                unsafe { core::slice::from_raw_parts(staging_base(), library_size) };
            let library =
                elf64::Elf64::parse(library_bytes).map_err(|_| ImageError::LibraryRejected)?;
            load_segments_at(
                address_space,
                &library,
                library_bytes,
                DYNAMIC_LIBRARY_A_BIAS,
            )?;
        }
        if libraries.m9e_base != 0 {
            let library_size = stage_dynamic_file(DYNAMIC_LIBRARY_PATH)?;
            // SAFETY: the previous staging slice ended with the call above.
            let library_bytes =
                unsafe { core::slice::from_raw_parts(staging_base(), library_size) };
            let library =
                elf64::Elf64::parse(library_bytes).map_err(|_| ImageError::LibraryRejected)?;
            load_segments_at(address_space, &library, library_bytes, DYNAMIC_LIBRARY_BIAS)?;
        }
        Ok(interp_elf.entry)
    })();
    let entry = match loaded {
        Ok(entry) => entry,
        Err(error) => {
            let _ = addrspace::destroy(address_space);
            return Err(error);
        }
    };

    if let Err(error) = map_user_stack(address_space) {
        let _ = addrspace::destroy(address_space);
        return Err(error);
    }

    Ok(DynamicImage {
        address_space,
        entry,
        main_entry,
        user_stack: USER_STACK_TOP,
        image_end,
        phdr,
        phent: phent as u32,
        phnum: phnum as u32,
        library_base: libraries.m9e_base,
        library_a_base: libraries.a_base,
        library_b_base: libraries.b_base,
    })
}

/// M10a: fixed load bias of a generic dynamically linked main program.
pub const PROGRAM_MAIN_BIAS: u64 = DYNAMIC_MAIN_BIAS;

/// M10a: fixed load bias of the generic interpreter named by `PT_INTERP`.
///
/// The interpreter is a real `ET_DYN` image (`/lib/ld-musl-x86_64.so.1`), not
/// the self-made static interpreter used by the M9d1/M9d2 closure, so it is
/// mapped at this dedicated bias and reported to the program through
/// `AT_BASE`.
pub const PROGRAM_INTERPRETER_BIAS: u64 = 0x0500_0000;

/// M10a: a generic dynamically linked program loaded for the Linux personality.
///
/// The kernel only maps the main image's `PT_LOAD` segments and the
/// interpreter named by `PT_INTERP`; it never applies relocations. The
/// interpreter runs from `entry`, reads the main image's `AT_PHDR`/`AT_ENTRY`
/// and resolves its own dependencies.
pub struct ProgramImage {
    pub address_space: AddressSpaceId,
    pub entry: u64,
    pub main_entry: u64,
    pub user_stack: u64,
    pub image_end: u64,
    pub phdr: u64,
    pub phent: u32,
    pub phnum: u32,
}

/// Load a generic dynamically linked program and its `PT_INTERP` interpreter
/// from the VFS into one address space (M10a).
///
/// Both images must be `ET_DYN` (position-independent); the main program is
/// placed at [`PROGRAM_MAIN_BIAS`], the interpreter at
/// [`PROGRAM_INTERPRETER_BIAS`]. The kernel maps the main image's `PT_LOAD`
/// segments, the interpreter, and the shared vDSO; it validates everything
/// before the address space exists, so a rejected program cannot leak one.
pub fn load_program(main_path: &[u8], interpreter_path: &[u8]) -> Result<ProgramImage, ImageError> {
    // 1. Validate the main program before touching the PMM.
    let (main_entry, image_end, phdr, phent, phnum) = {
        let size = stage_dynamic_file(main_path)?;
        // SAFETY: `stage_dynamic_file` filled exactly `staging_base()[..size]`
        // and returned, so the slice no longer aliases the mutable one.
        let bytes = unsafe { core::slice::from_raw_parts(staging_base(), size) };
        let elf = elf64::Elf64::parse(bytes).map_err(|_| ImageError::ElfRejected)?;
        if !elf.is_dynamic() {
            return Err(ImageError::ElfRejected);
        }
        match elf.interpreter() {
            Some(path) if path == interpreter_path => {}
            Some(_) => return Err(ImageError::InterpreterMismatch),
            None => return Err(ImageError::InterpreterMissing),
        }
        if elf.validate_for_user_dynamic(PROGRAM_MAIN_BIAS).is_err() {
            return Err(ImageError::ElfRejected);
        }
        let image_end = check_layout_at(&elf, PROGRAM_MAIN_BIAS)?;
        let phdr = PROGRAM_MAIN_BIAS
            .checked_add(elf.phoff())
            .ok_or(ImageError::Overflow)?;
        let phdr_end = (elf.phnum() as u64)
            .checked_mul(u64::from(elf.phentsize()))
            .and_then(|len| phdr.checked_add(len))
            .ok_or(ImageError::Overflow)?;
        if !phdr_is_mapped(&elf, PROGRAM_MAIN_BIAS, phdr, phdr_end) {
            return Err(ImageError::PhdrNotMapped);
        }
        let main_entry = PROGRAM_MAIN_BIAS
            .checked_add(elf.entry)
            .ok_or(ImageError::Overflow)?;
        (
            main_entry,
            image_end,
            phdr,
            elf.phentsize() as u32,
            elf.phnum() as u32,
        )
    };

    // 1b. Validate the interpreter: a real `ET_DYN` loader image with its own
    //     entry, no second `PT_INTERP` level.
    {
        let size = stage_dynamic_file(interpreter_path)?;
        // SAFETY: the previous staging slice ended with the call above.
        let bytes = unsafe { core::slice::from_raw_parts(staging_base(), size) };
        let elf = elf64::Elf64::parse(bytes).map_err(|_| ImageError::ElfRejected)?;
        if !elf.is_dynamic() || elf.interpreter().is_some() {
            return Err(ImageError::InterpreterMismatch);
        }
        if elf
            .validate_for_user_dynamic(PROGRAM_INTERPRETER_BIAS)
            .is_err()
        {
            return Err(ImageError::ElfRejected);
        }
        check_layout_at(&elf, PROGRAM_INTERPRETER_BIAS)?;
    }

    // 2. Allocate the address space and map the images (main, interpreter,
    //    vDSO) before the stack. Failures tear the whole address space down.
    let address_space = match addrspace::create() {
        Ok(address_space) => address_space,
        Err(_) => return Err(ImageError::AddressSpaceFailed),
    };
    let loaded = (|| -> Result<u64, ImageError> {
        let size = stage_dynamic_file(main_path)?;
        // SAFETY: the staging buffer is filled and read sequentially on the boot
        // CPU with interrupts disabled; the slice ends before staging is reused.
        let bytes = unsafe { core::slice::from_raw_parts(staging_base(), size) };
        let elf = elf64::Elf64::parse(bytes).map_err(|_| ImageError::ElfRejected)?;
        load_segments_at(address_space, &elf, bytes, PROGRAM_MAIN_BIAS)?;

        let interp_size = stage_dynamic_file(interpreter_path)?;
        // SAFETY: the previous staging slice ended with the call above.
        let interp_bytes = unsafe { core::slice::from_raw_parts(staging_base(), interp_size) };
        let interp_elf = elf64::Elf64::parse(interp_bytes).map_err(|_| ImageError::ElfRejected)?;
        load_segments_at(
            address_space,
            &interp_elf,
            interp_bytes,
            PROGRAM_INTERPRETER_BIAS,
        )?;

        let vdso_size =
            stage_dynamic_file(DYNAMIC_VDSO_PATH).map_err(|_| ImageError::VdsoFailed)?;
        // SAFETY: the previous staging slice ended with the call above.
        let vdso_bytes = unsafe { core::slice::from_raw_parts(staging_base(), vdso_size) };
        let vdso = elf64::Elf64::parse(vdso_bytes).map_err(|_| ImageError::VdsoFailed)?;
        load_vdso_segments(address_space, &vdso, vdso_bytes)?;
        crate::vdso::map_into(address_space).map_err(|_| ImageError::VdsoFailed)?;

        PROGRAM_INTERPRETER_BIAS
            .checked_add(interp_elf.entry)
            .ok_or(ImageError::Overflow)
    })();
    let entry = match loaded {
        Ok(entry) => entry,
        Err(error) => {
            let _ = addrspace::destroy(address_space);
            return Err(error);
        }
    };

    if let Err(error) = map_user_stack(address_space) {
        let _ = addrspace::destroy(address_space);
        return Err(error);
    }

    Ok(ProgramImage {
        address_space,
        entry,
        main_entry,
        user_stack: USER_STACK_TOP,
        image_end,
        phdr,
        phent,
        phnum,
    })
}

/// M9e/M9f: which shared libraries the dynamic closure needs, and where they go.
///
/// A `0` base means "not needed". The kernel only resolves the frozen closure:
/// main may request `/fat/m9e.so` and/or `/fat/m9f-a.so` (in any order, no
/// duplicates, no unknown paths); A must request exactly `/fat/m9f-b.so`; B
/// must request nothing. Requesting A therefore implies B, which is why the
/// plan fills `b_base` as soon as `a_base` is present.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct LibraryPlan {
    m9e_base: u64,
    a_base: u64,
    b_base: u64,
}

/// Resolve the frozen `DT_NEEDED` closure from library names.
fn plan_libraries(needed: &[&[u8]]) -> Result<LibraryPlan, ImageError> {
    if needed.len() > 2 {
        return Err(ImageError::LibraryMismatch);
    }
    let mut plan = LibraryPlan::default();
    for name in needed {
        if *name == DYNAMIC_LIBRARY_PATH {
            if plan.m9e_base != 0 {
                return Err(ImageError::LibraryMismatch);
            }
            plan.m9e_base = DYNAMIC_LIBRARY_BIAS;
        } else if *name == DYNAMIC_LIBRARY_A_PATH {
            if plan.a_base != 0 {
                return Err(ImageError::LibraryMismatch);
            }
            plan.a_base = DYNAMIC_LIBRARY_A_BIAS;
        } else {
            return Err(ImageError::LibraryMismatch);
        }
    }
    if plan.a_base != 0 {
        plan.b_base = DYNAMIC_LIBRARY_B_BIAS;
    }
    Ok(plan)
}

/// Resolve [`LibraryPlan`] from the main image's `DT_NEEDED` list.
fn plan_for_elf(elf: &elf64::Elf64<'_>) -> Result<LibraryPlan, ImageError> {
    let needed = elf
        .needed_libraries()
        .map_err(|_| ImageError::ElfRejected)?;
    if needed.len() > 2 {
        return Err(ImageError::LibraryMismatch);
    }
    let mut names: [&[u8]; 2] = [b"", b""];
    for index in 0..needed.len() {
        names[index] = needed.get(index).ok_or(ImageError::LibraryMismatch)?;
    }
    plan_libraries(&names[..needed.len()])
}

/// Stage and validate one shared library from the VFS before mapping it.
fn validate_shared_library_from_vfs(
    path: &[u8],
    bias: u64,
    expected_needed: Option<&[u8]>,
) -> Result<(), ImageError> {
    let size = stage_dynamic_file(path).map_err(|_| ImageError::LibraryRejected)?;
    if size > MAX_DYNAMIC_LIBRARY_BYTES {
        return Err(ImageError::LibraryRejected);
    }
    // SAFETY: `stage_dynamic_file` filled exactly `staging_base()[..size]` and
    // returned, so the slice no longer aliases the mutable staging buffer.
    let bytes = unsafe { core::slice::from_raw_parts(staging_base(), size) };
    validate_shared_library_at(bytes, bias, expected_needed)
}

/// Validate one shared library at `bias`.
///
/// It must be `ET_DYN`, must not ask for an interpreter (the kernel never loads
/// a second loader level), its own `DT_NEEDED` list must match
/// `expected_needed` (empty for m9e and B, exactly `/fat/m9f-b.so` for A), and
/// every segment must satisfy the shared-object rules inside the window that
/// starts at `bias`.
fn validate_shared_library_at(
    bytes: &[u8],
    bias: u64,
    expected_needed: Option<&[u8]>,
) -> Result<(), ImageError> {
    let elf = elf64::Elf64::parse(bytes).map_err(|_| ImageError::LibraryRejected)?;
    if !elf.is_dynamic() {
        return Err(ImageError::LibraryRejected);
    }
    if elf.interpreter().is_some() {
        return Err(ImageError::LibraryRejected);
    }
    let needed = elf
        .needed_libraries()
        .map_err(|_| ImageError::LibraryRejected)?;
    let expected = match expected_needed {
        None => needed.is_empty(),
        Some(path) => needed.len() == 1 && needed.get(0) == Some(path),
    };
    if !expected {
        return Err(ImageError::LibraryMismatch);
    }
    elf.validate_for_shared_object(bias)
        .map_err(|_| ImageError::LibraryRejected)?;
    check_layout_at(&elf, bias).map_err(|_| ImageError::LibraryRejected)?;
    if !library_window_contains(&elf, bias) {
        return Err(ImageError::LibraryRejected);
    }
    Ok(())
}

/// Whether every `PT_LOAD` segment of `elf` lands inside the library window
/// `[bias, bias + DYNAMIC_LIBRARY_WINDOW)`.
fn library_window_contains(elf: &elf64::Elf64<'_>, bias: u64) -> bool {
    let window_start = bias;
    let window_end = bias.saturating_add(DYNAMIC_LIBRARY_WINDOW);
    let mut inside = true;
    let walk = elf.for_each_load(|header| {
        let start = match window_start.checked_add(header.vaddr) {
            Some(start) => start,
            None => {
                inside = false;
                return Ok(());
            }
        };
        let end = match start.checked_add(header.memsz) {
            Some(end) => end,
            None => {
                inside = false;
                return Ok(());
            }
        };
        if start < window_start || end > window_end {
            inside = false;
        }
        Ok(())
    });
    walk.is_ok() && inside
}

/// Map every PT_LOAD segment and the user stack into `address_space`.
fn load_into(
    address_space: AddressSpaceId,
    elf: &elf64::Elf64<'_>,
    bytes: &[u8],
) -> Result<(), ImageError> {
    load_segments_at(address_space, elf, bytes, 0)?;
    map_user_stack(address_space)?;
    Ok(())
}

/// Map every PT_LOAD segment of `elf` at `bias` (no user stack).
fn load_segments_at(
    address_space: AddressSpaceId,
    elf: &elf64::Elf64<'_>,
    bytes: &[u8],
    bias: u64,
) -> Result<(), ImageError> {
    let mut segments = 0usize;
    let mut result = Ok(());
    let walk = elf.for_each_load(|header| {
        if result.is_err() {
            return Ok(());
        }
        segments += 1;
        if segments > elf64::MAX_LOAD_SEGMENTS {
            result = Err(ImageError::TooManyFrames);
            return Ok(());
        }
        result = load_segment(address_space, &header, bytes, bias);
        Ok(())
    });
    walk.map_err(|_| ImageError::ElfRejected)?;
    result?;
    if segments == 0 {
        return Err(ImageError::ElfRejected);
    }
    Ok(())
}

/// Map only the read-only/executable load segments of the vDSO image (M9d2).
///
/// The vDSO's writable segment lives at [`crate::vdso::VDSO_DATA_BASE`]; that
/// address is backed by a single kernel-owned read-only frame through
/// [`crate::vdso::map_into`], so mapping the image's RW segment here would
/// overlap it. Every other segment is mapped exactly like a normal load.
fn load_vdso_segments(
    address_space: AddressSpaceId,
    elf: &elf64::Elf64<'_>,
    bytes: &[u8],
) -> Result<(), ImageError> {
    let mut segments = 0usize;
    let mut mapped = 0usize;
    let mut result = Ok(());
    let walk = elf.for_each_load(|header| {
        if result.is_err() {
            return Ok(());
        }
        segments += 1;
        if segments > elf64::MAX_LOAD_SEGMENTS {
            result = Err(ImageError::VdsoFailed);
            return Ok(());
        }
        // The writable segment is replaced by the kernel data page.
        if header.flags & elf64::PF_W != 0 {
            return Ok(());
        }
        result = load_segment(address_space, &header, bytes, 0);
        if result.is_ok() {
            mapped += 1;
        }
        Ok(())
    });
    walk.map_err(|_| ImageError::VdsoFailed)?;
    result?;
    if segments == 0 || mapped == 0 {
        return Err(ImageError::VdsoFailed);
    }
    Ok(())
}

/// Map one PT_LOAD segment at `bias`: zero-filled pages, file bytes where they
/// exist.
fn load_segment(
    address_space: AddressSpaceId,
    header: &elf64::ProgramHeader,
    bytes: &[u8],
    bias: u64,
) -> Result<(), ImageError> {
    let (start, end) = page_range_at(header.vaddr, header.memsz, bias)?;
    let (writable, executable) = segment_permissions(header.flags);
    let mut page_vaddr = start;
    while page_vaddr < end {
        let phys = pmm::alloc_frame().map_err(|_| ImageError::OutOfFrames)?;
        // Zero the frame through the direct map, then copy the file-backed part.
        // A segment with filesz == 0 is pure BSS and stays zero.
        // SAFETY: `phys` is a freshly allocated frame, reachable through the
        // direct map for its whole 4 KiB.
        let page = unsafe {
            core::slice::from_raw_parts_mut(vm::phys_to_virt(phys) as *mut u8, PAGE as usize)
        };
        page.fill(0);
        if let Err(error) = copy_file_bytes_at(page, page_vaddr, header, bytes, bias) {
            let _ = pmm::dealloc_frame(phys);
            return Err(error);
        }
        if addrspace::map_user(address_space, page_vaddr, phys, PAGE, writable, executable).is_err()
        {
            // The frame is not owned by the address space yet.
            let _ = pmm::dealloc_frame(phys);
            return Err(ImageError::MapFailed);
        }
        page_vaddr = page_vaddr.checked_add(PAGE).ok_or(ImageError::Overflow)?;
    }
    Ok(())
}

/// Copy the part of the segment that lives in this page; the rest stays zero.
#[cfg_attr(not(test), allow(dead_code))]
fn copy_file_bytes(
    page: &mut [u8],
    page_vaddr: u64,
    header: &elf64::ProgramHeader,
    bytes: &[u8],
) -> Result<(), ImageError> {
    copy_file_bytes_at(page, page_vaddr, header, bytes, 0)
}

/// Biased variant of [`copy_file_bytes`]: the segment starts at `bias + p_vaddr`
/// and `page_vaddr` is already biased.
fn copy_file_bytes_at(
    page: &mut [u8],
    page_vaddr: u64,
    header: &elf64::ProgramHeader,
    bytes: &[u8],
    bias: u64,
) -> Result<(), ImageError> {
    let seg_start = bias.checked_add(header.vaddr).ok_or(ImageError::Overflow)?;
    let seg_end = seg_start
        .checked_add(header.filesz)
        .ok_or(ImageError::Overflow)?;
    let page_end = page_vaddr.checked_add(PAGE).ok_or(ImageError::Overflow)?;
    let lo = seg_start.max(page_vaddr);
    let hi = seg_end.min(page_end);
    if lo >= hi {
        return Ok(());
    }
    let src_offset = header
        .offset
        .checked_add(lo - seg_start)
        .ok_or(ImageError::Overflow)?;
    let dst_offset = usize::try_from(lo - page_vaddr).map_err(|_| ImageError::Overflow)?;
    let count = usize::try_from(hi - lo).map_err(|_| ImageError::Overflow)?;
    let src_start = usize::try_from(src_offset).map_err(|_| ImageError::Overflow)?;
    let src_end = src_start.checked_add(count).ok_or(ImageError::Overflow)?;
    let src = bytes
        .get(src_start..src_end)
        .ok_or(ImageError::BadSegment)?;
    let dst_end = dst_offset.checked_add(count).ok_or(ImageError::Overflow)?;
    let dst = page
        .get_mut(dst_offset..dst_end)
        .ok_or(ImageError::BadSegment)?;
    dst.copy_from_slice(src);
    Ok(())
}

/// Map the user stack: writable, non-executable, with an unmapped guard below.
fn map_user_stack(address_space: AddressSpaceId) -> Result<(), ImageError> {
    for index in 0..USER_STACK_FRAMES {
        let virt = USER_STACK_BASE + index * PAGE;
        let phys = pmm::alloc_frame().map_err(|_| ImageError::OutOfFrames)?;
        // SAFETY: fresh frame, direct-mapped for 4 KiB.
        unsafe {
            core::ptr::write_bytes(vm::phys_to_virt(phys) as *mut u8, 0, PAGE as usize);
        }
        if addrspace::map_user(address_space, virt, phys, PAGE, true, false).is_err() {
            let _ = pmm::dealloc_frame(phys);
            return Err(ImageError::MapFailed);
        }
    }
    Ok(())
}

/// Page-aligned `[start, end)` covering `[vaddr, vaddr + memsz)`.
#[cfg_attr(not(test), allow(dead_code))]
fn page_range(vaddr: u64, memsz: u64) -> Result<(u64, u64), ImageError> {
    page_range_at(vaddr, memsz, 0)
}

/// Biased variant: the segment is placed at `bias + vaddr`, which must be
/// non-zero and page-aligned after the shift.
fn page_range_at(vaddr: u64, memsz: u64, bias: u64) -> Result<(u64, u64), ImageError> {
    if memsz == 0 {
        return Err(ImageError::BadSegment);
    }
    let start_raw = bias.checked_add(vaddr).ok_or(ImageError::Overflow)?;
    if start_raw == 0 {
        return Err(ImageError::BadSegment);
    }
    let end = start_raw.checked_add(memsz).ok_or(ImageError::Overflow)?;
    let start = start_raw & !(PAGE - 1);
    let end = end.checked_add(PAGE - 1).ok_or(ImageError::Overflow)? & !(PAGE - 1);
    if start >= end {
        return Err(ImageError::BadSegment);
    }
    Ok((start, end))
}

/// `(writable, executable)` from ELF `p_flags`; read-only is the default.
fn segment_permissions(flags: u32) -> (bool, bool) {
    (flags & elf64::PF_W != 0, flags & elf64::PF_X != 0)
}

/// Reject layouts the fixed address plan cannot represent and return the
/// page-aligned end of the loaded image.
///
/// Every segment must stay in the low half, below the stack guard, and clear of
/// the stack. The returned end is the maximum page-aligned `p_vaddr + p_memsz`
/// over all `PT_LOAD` segments, so it covers the `.bss` pages that carry no file
/// bytes and is exactly one past the last byte the loader maps.
fn check_layout(elf: &elf64::Elf64<'_>) -> Result<u64, ImageError> {
    check_layout_at(elf, 0)
}

/// Biased variant of [`check_layout`]: segments are placed at `bias + p_vaddr`.
fn check_layout_at(elf: &elf64::Elf64<'_>, bias: u64) -> Result<u64, ImageError> {
    let mut error = None;
    let mut spans = 0usize;
    let mut image_end = 0u64;
    let walk = elf.for_each_load(|header| {
        spans += 1;
        if error.is_some() {
            return Ok(());
        }
        match page_range_at(header.vaddr, header.memsz, bias) {
            Ok((start, end)) => {
                if end > elf64::USER_ADDR_LIMIT {
                    error = Some(ImageError::BadSegment);
                } else if start < USER_STACK_TOP && end > USER_STACK_GUARD {
                    error = Some(ImageError::BadSegment);
                } else {
                    image_end = image_end.max(end);
                }
            }
            Err(why) => error = Some(why),
        }
        Ok(())
    });
    walk.map_err(|_| ImageError::ElfRejected)?;
    if spans == 0 {
        return Err(ImageError::ElfRejected);
    }
    match error {
        Some(why) => Err(why),
        None => Ok(image_end),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn header(
        vaddr: u64,
        offset: u64,
        filesz: u64,
        memsz: u64,
        flags: u32,
    ) -> elf64::ProgramHeader {
        elf64::ProgramHeader {
            p_type: elf64::PT_LOAD,
            flags,
            offset,
            vaddr,
            paddr: vaddr,
            filesz,
            memsz,
            align: PAGE,
        }
    }

    /// Build a minimal `ET_EXEC` x86-64 ELF with the given program headers.
    ///
    /// Entries are `(p_type, p_vaddr, p_filesz, p_memsz, p_flags)`; the file
    /// bytes for entry `i` live at `p_offset = 0x1000 + i * 0x100`. Sections are
    /// omitted, so the result is meant for [`elf64::Elf64::parse`] plus the
    /// layout checks in this module, not for a full `load_module` run.
    fn synthetic_elf(segments: &[(u32, u64, u64, u64, u32)]) -> [u8; 0x2000] {
        let mut bytes = [0u8; 0x2000];
        bytes[0..4].copy_from_slice(&[0x7F, b'E', b'L', b'F']);
        bytes[4] = 2; // ELFCLASS64
        bytes[5] = 1; // little-endian
        bytes[6] = 1; // EV_CURRENT
        bytes[16..18].copy_from_slice(&elf64::ET_EXEC.to_le_bytes());
        bytes[18..20].copy_from_slice(&elf64::EM_X86_64.to_le_bytes());
        bytes[20..24].copy_from_slice(&1u32.to_le_bytes());
        let entry = segments
            .first()
            .map_or(0x40_0040, |segment| segment.1.saturating_add(0x40));
        bytes[24..32].copy_from_slice(&entry.to_le_bytes());
        bytes[32..40].copy_from_slice(&64u64.to_le_bytes()); // e_phoff
        bytes[52..54].copy_from_slice(&64u16.to_le_bytes()); // e_ehsize
        bytes[54..56].copy_from_slice(&56u16.to_le_bytes()); // e_phentsize
        bytes[56..58].copy_from_slice(&(segments.len() as u16).to_le_bytes());
        for (index, &(p_type, vaddr, filesz, memsz, flags)) in segments.iter().enumerate() {
            let at = 64 + index * 56;
            let offset = 0x1000 + index as u64 * 0x100;
            bytes[at..at + 4].copy_from_slice(&p_type.to_le_bytes());
            bytes[at + 4..at + 8].copy_from_slice(&flags.to_le_bytes());
            bytes[at + 8..at + 16].copy_from_slice(&offset.to_le_bytes());
            bytes[at + 16..at + 24].copy_from_slice(&vaddr.to_le_bytes());
            bytes[at + 24..at + 32].copy_from_slice(&vaddr.to_le_bytes());
            bytes[at + 32..at + 40].copy_from_slice(&filesz.to_le_bytes());
            bytes[at + 40..at + 48].copy_from_slice(&memsz.to_le_bytes());
            bytes[at + 48..at + 56].copy_from_slice(&PAGE.to_le_bytes());
        }
        bytes
    }

    #[test]
    fn page_ranges_cover_the_segment() {
        assert_eq!(page_range(0x40_0000, 0x10), Ok((0x40_0000, 0x40_1000)));
        assert_eq!(page_range(0x40_0FF0, 0x20), Ok((0x40_0000, 0x40_2000)));
        assert_eq!(page_range(0x40_0000, 0x1000), Ok((0x40_0000, 0x40_1000)));
        assert_eq!(page_range(0, 0x10), Err(ImageError::BadSegment));
        assert_eq!(page_range(0x40_0000, 0), Err(ImageError::BadSegment));
        assert_eq!(page_range(u64::MAX - 1, 0x10), Err(ImageError::Overflow));
    }

    #[test]
    fn biased_page_ranges_and_layout_move_with_the_bias() {
        // A PIE segment at p_vaddr 0 is legal once the bias is non-zero.
        assert_eq!(
            page_range_at(0, 0x100, 0x0200_0000),
            Ok((0x0200_0000, 0x0200_1000))
        );
        assert_eq!(page_range_at(0, 0x100, 0), Err(ImageError::BadSegment));
        assert_eq!(
            page_range_at(0x1000, 0x10, 0x0200_0000),
            Ok((0x0200_1000, 0x0200_2000))
        );
        assert_eq!(
            page_range_at(u64::MAX - 1, 0x10, 0x1000),
            Err(ImageError::Overflow)
        );
    }

    #[test]
    fn load_dynamic_only_accepts_the_fixed_main_path() {
        // The path check runs before any VFS or PMM access, so this is a pure
        // host test of the routing contract.
        assert!(matches!(
            load_dynamic(b"/boot/init"),
            Err(ImageError::DynamicPath)
        ));
        assert!(matches!(load_dynamic(b""), Err(ImageError::DynamicPath)));
        assert!(matches!(
            load_dynamic(b"/fat/dyn-main"),
            Err(ImageError::ModuleNotFound) // no VFS in host tests
        ));
    }

    /// Static `ET_DYN` image with one segment and a file-backed phdr table.
    fn dynamic_elf(segment_vaddr: u64, segment_filesz: u64) -> [u8; 0x2000] {
        let mut bytes = synthetic_elf(&[(
            elf64::PT_LOAD,
            segment_vaddr,
            segment_filesz,
            segment_filesz + 0x100,
            elf64::PF_R | elf64::PF_X,
        )]);
        bytes[16..18].copy_from_slice(&elf64::ET_DYN.to_le_bytes());
        bytes
    }

    #[test]
    fn the_program_headers_must_be_file_backed_by_a_segment() {
        let bytes = dynamic_elf(0, 0x200);
        let elf = elf64::Elf64::parse(&bytes).expect("parse");
        let phdr = DYNAMIC_MAIN_BIAS + elf.phoff();
        let end = phdr + elf.phnum() as u64 * u64::from(elf.phentsize());
        assert!(phdr_is_mapped(&elf, DYNAMIC_MAIN_BIAS, phdr, end));

        // Move the only segment past the program headers: AT_PHDR would point
        // into an unmapped page.
        let bytes = dynamic_elf(0x1000, 0x200);
        let elf = elf64::Elf64::parse(&bytes).expect("parse");
        let phdr = DYNAMIC_MAIN_BIAS + elf.phoff();
        let end = phdr + elf.phnum() as u64 * u64::from(elf.phentsize());
        assert!(!phdr_is_mapped(&elf, DYNAMIC_MAIN_BIAS, phdr, end));
        assert!(!phdr_is_mapped(&elf, DYNAMIC_MAIN_BIAS, end, phdr));
    }

    #[test]
    fn permissions_come_from_p_flags() {
        assert_eq!(segment_permissions(elf64::PF_R), (false, false));
        assert_eq!(
            segment_permissions(elf64::PF_R | elf64::PF_X),
            (false, true)
        );
        assert_eq!(
            segment_permissions(elf64::PF_R | elf64::PF_W),
            (true, false)
        );
    }

    #[test]
    fn image_end_covers_every_load_segment_and_bss() {
        let bytes = synthetic_elf(&[
            (
                elf64::PT_LOAD,
                0x40_0000,
                0x100,
                0x100,
                elf64::PF_R | elf64::PF_X,
            ),
            (
                elf64::PT_LOAD,
                0x41_0000,
                0x80,
                0x2100,
                elf64::PF_R | elf64::PF_W,
            ),
        ]);
        let elf = elf64::Elf64::parse(&bytes).expect("synthetic image parses");
        let end = check_layout(&elf).expect("layout is representable");
        // `.bss` runs to 0x41_2100, so the page-aligned end is 0x41_3000. The
        // text segment ends lower and must not win.
        assert_eq!(end, 0x41_3000);
        assert_eq!(end % PAGE, 0, "image_end is page aligned");
    }

    #[test]
    fn image_end_ignores_non_load_program_headers() {
        let bytes = synthetic_elf(&[
            (
                elf64::PT_LOAD,
                0x40_0000,
                0x100,
                0x100,
                elf64::PF_R | elf64::PF_X,
            ),
            // PT_NOTE with a huge address: not loaded, so it cannot extend the
            // image.
            (4, 0x7FFF_FFFF_F000, 0, 0x1000, elf64::PF_R),
            (
                elf64::PT_LOAD,
                0x41_0000,
                0x80,
                0x100,
                elf64::PF_R | elf64::PF_W,
            ),
        ]);
        let elf = elf64::Elf64::parse(&bytes).expect("synthetic image parses");
        assert_eq!(check_layout(&elf), Ok(0x41_1000));
    }

    #[test]
    fn image_end_covers_a_bss_only_segment() {
        let bytes = synthetic_elf(&[(
            elf64::PT_LOAD,
            0x40_0000,
            0,
            0x3000,
            elf64::PF_R | elf64::PF_W,
        )]);
        let elf = elf64::Elf64::parse(&bytes).expect("synthetic image parses");
        assert_eq!(check_layout(&elf), Ok(0x40_3000));
    }

    #[test]
    fn image_end_follows_the_highest_segment_not_the_last_one() {
        // File order is not address order: the high segment comes first.
        let bytes = synthetic_elf(&[
            (
                elf64::PT_LOAD,
                0x40_0000,
                0x100,
                0x100,
                elf64::PF_R | elf64::PF_X,
            ),
            (
                elf64::PT_LOAD,
                0x10_0000,
                0x100,
                0x100,
                elf64::PF_R | elf64::PF_W,
            ),
        ]);
        let elf = elf64::Elf64::parse(&bytes).expect("synthetic image parses");
        assert_eq!(check_layout(&elf), Ok(0x40_1000));
    }

    #[test]
    fn image_layout_still_rejects_unrepresentable_segments() {
        // Running past the low-half limit.
        let bytes = synthetic_elf(&[(
            elf64::PT_LOAD,
            elf64::USER_ADDR_LIMIT,
            0x100,
            0x100,
            elf64::PF_R,
        )]);
        let elf = elf64::Elf64::parse(&bytes).expect("synthetic image parses");
        assert_eq!(check_layout(&elf), Err(ImageError::BadSegment));

        // `vaddr + memsz` overflows.
        let bytes = synthetic_elf(&[(elf64::PT_LOAD, u64::MAX - 0x10, 0, 0x100, elf64::PF_R)]);
        let elf = elf64::Elf64::parse(&bytes).expect("synthetic image parses");
        assert_eq!(check_layout(&elf), Err(ImageError::Overflow));

        // No PT_LOAD at all.
        let bytes = synthetic_elf(&[(4, 0x40_0000, 0, 0x100, elf64::PF_R)]);
        let elf = elf64::Elf64::parse(&bytes).expect("synthetic image parses");
        assert_eq!(check_layout(&elf), Err(ImageError::ElfRejected));

        // Overlapping the user stack guard is still rejected.
        let bytes = synthetic_elf(&[(elf64::PT_LOAD, USER_STACK_GUARD, 0, 0x1000, elf64::PF_R)]);
        let elf = elf64::Elf64::parse(&bytes).expect("synthetic image parses");
        assert_eq!(check_layout(&elf), Err(ImageError::BadSegment));
    }

    #[test]
    fn file_bytes_land_at_the_right_offset_and_the_rest_stays_zero() {
        // Single-page case: the segment starts mid-page at 0xE00 and is 0x200
        // long, so it fills exactly to the page end. (The cross-page case is
        // covered by `segment_spanning_two_pages_is_split`.)
        let bytes = [0xAAu8; 0x1000];
        let header = header(0x40_0E00, 0xE00, 0x200, 0x200, elf64::PF_R);
        let mut page = [0u8; PAGE as usize];
        copy_file_bytes(&mut page, 0x40_0000, &header, &bytes).unwrap();
        assert!(page[..0xE00].iter().all(|&b| b == 0));
        assert!(page[0xE00..].iter().all(|&b| b == 0xAA));
    }

    #[test]
    fn bss_segment_leaves_the_page_zero() {
        // filesz == 0: pure BSS (this is exactly the M4 child's RW segment).
        let header = header(0x40_0000, 0x10, 0, 8, elf64::PF_R | elf64::PF_W);
        let mut page = [0xFFu8; PAGE as usize];
        copy_file_bytes(&mut page, 0x40_0000, &header, &[]).unwrap();
        assert!(
            page.iter().all(|&b| b == 0xFF),
            "BSS pages are zeroed by the caller"
        );
    }

    #[test]
    fn segment_spanning_two_pages_is_split() {
        let bytes = [0x5Au8; 0x2000];
        let header = header(0x40_0000, 0, 0x2000, 0x2000, elf64::PF_R | elf64::PF_X);
        let mut first = [0u8; PAGE as usize];
        let mut second = [0u8; PAGE as usize];
        copy_file_bytes(&mut first, 0x40_0000, &header, &bytes).unwrap();
        copy_file_bytes(&mut second, 0x40_1000, &header, &bytes).unwrap();
        assert!(first.iter().all(|&b| b == 0x5A));
        assert!(second.iter().all(|&b| b == 0x5A));
    }

    #[test]
    fn short_file_payload_is_rejected_not_truncated() {
        let header = header(0x40_0000, 0x10, 0x100, 0x100, elf64::PF_R);
        let mut page = [0u8; PAGE as usize];
        assert_eq!(
            copy_file_bytes(&mut page, 0x40_0000, &header, &[0u8; 4]),
            Err(ImageError::BadSegment)
        );
    }

    #[test]
    fn stack_region_is_clear_of_the_image_and_16_byte_aligned() {
        assert_eq!(USER_STACK_TOP % 16, 0);
        assert_eq!(USER_STACK_TOP, USER_STACK_BASE + 8 * PAGE);
        assert_eq!(USER_STACK_GUARD, USER_STACK_BASE - PAGE);
        // The M4 images sit around 4 MiB, far below the stack.
        assert!(0x40_0000 + 0x10_0000 < USER_STACK_GUARD);
    }

    #[test]
    fn module_bound_covers_the_largest_boot_image() {
        // The bound is a compile-time ceiling on a `.bss` staging buffer: it must
        // stay well above the real images (a 1 MiB bound rejected the debug
        // `caelum-init`, 1,067,776 bytes) and it must be the staging size, so the
        // check in `stage_module` can never disagree with the buffer.
        assert!(MAX_MODULE_BYTES >= 2 * 1024 * 1024);
        assert!(MAX_MODULE_BYTES > 1_067_776);
        assert_eq!(
            core::mem::size_of::<[u8; MAX_MODULE_BYTES]>(),
            MAX_MODULE_BYTES
        );
        // Power of two, so the bound reads as a capacity rather than a guess.
        assert!(MAX_MODULE_BYTES.is_power_of_two());
    }

    /// The previous module is reclaimed *before* the payload is looked up, so a
    /// missing module still reports `ModuleNotFound` (and is reclaimed once).
    #[test]
    fn staging_reclaims_the_previous_module_before_reading() {
        let _guard = crate::vfs::test_lock();
        staging_probe::reset();
        assert_eq!(
            stage_module(b"/boot/definitely-missing"),
            Err(ImageError::ModuleNotFound)
        );
        assert_eq!(
            staging_probe::releases(),
            1,
            "the leading reclaim runs before the stat fails"
        );
        staging_probe::reset();
    }

    /// The trailing reclaim runs even when the read fails, and the read error is
    /// the one the caller sees.
    #[test]
    fn staging_reclaims_this_module_after_a_failed_read() {
        let _guard = crate::vfs::test_lock();
        staging_probe::reset();
        assert_eq!(
            stage_payload(b"/boot/definitely-missing", 24),
            Err(ImageError::VfsFailed)
        );
        assert_eq!(
            staging_probe::releases(),
            1,
            "the trailing reclaim runs after the failed read"
        );
        staging_probe::reset();
    }

    /// A failed reclaim must not mask the read error: the caller still sees
    /// `VfsFailed` for the failed read, not a reclaim-specific status.
    #[test]
    fn a_failed_reclaim_does_not_mask_the_read_error() {
        let _guard = crate::vfs::test_lock();
        staging_probe::reset();
        staging_probe::force_failure();
        assert_eq!(
            stage_payload(b"/boot/definitely-missing", 24),
            Err(ImageError::VfsFailed)
        );
        assert_eq!(staging_probe::releases(), 1);
        staging_probe::reset();
    }

    /// The trailing reclaim only escalates when the payload actually arrived:
    /// a short read or a read error stays `VfsFailed` on its own.
    #[test]
    fn a_reclaimed_payload_succeeds_but_a_failed_reclaim_is_a_vfs_failure() {
        assert_eq!(staging_outcome(Ok(24), 24, true), Ok(24));
        assert_eq!(
            staging_outcome(Ok(24), 24, false),
            Err(ImageError::VfsFailed),
            "pages left resident would starve the next module"
        );
        assert_eq!(
            staging_outcome(Ok(23), 24, true),
            Err(ImageError::VfsFailed),
            "short read"
        );
        assert_eq!(
            staging_outcome(Err(crate::vfs::VfsError::NotFound), 24, true),
            Err(ImageError::VfsFailed),
            "read error wins over a successful reclaim"
        );
    }

    #[test]
    fn error_strings_are_stable() {
        assert_eq!(ImageError::ElfRejected.as_str(), "image-elf-rejected");
        assert_eq!(ImageError::MapFailed.as_str(), "image-map-failed");
        assert_eq!(ImageError::VfsFailed.as_str(), "image-vfs-failed");
        assert_eq!(
            ImageError::ModuleTooLarge.as_str(),
            "image-module-too-large"
        );
    }

    #[test]
    fn module_paths_are_fixed_and_reject_escapes() {
        let (path, len) = module_path(b"init").unwrap();
        assert_eq!(&path[..len], b"/boot/init");
        let (path, len) = module_path(b"child").unwrap();
        assert_eq!(&path[..len], b"/boot/child");
        assert!(len <= PATH_CAPACITY);
        // A 16-byte name is the largest accepted one and still fits.
        let (_, len) = module_path(b"abcdefghijklmnop").unwrap();
        assert_eq!(len, BOOT_PATH_PREFIX.len() + MAX_MODULE_NAME);
        assert!(len <= PATH_CAPACITY);

        // Anything that is not a plain single component is rejected.
        assert_eq!(module_path(b""), Err(ImageError::ModuleNotFound));
        assert_eq!(module_path(b".."), Err(ImageError::ModuleNotFound));
        assert_eq!(module_path(b"."), Err(ImageError::ModuleNotFound));
        assert_eq!(module_path(b"../init"), Err(ImageError::ModuleNotFound));
        assert_eq!(module_path(b"boot/init"), Err(ImageError::ModuleNotFound));
        assert_eq!(module_path(b"init\0"), Err(ImageError::ModuleNotFound));
        assert_eq!(
            module_path(b"abcdefghijklmnopq"),
            Err(ImageError::ModuleNotFound)
        );
    }

    // -----------------------------------------------------------------------
    // M9e/M9f: shared-library loading
    // -----------------------------------------------------------------------

    fn shared_library_elf(segments: &[(u32, u64, u64, u64, u32)]) -> [u8; 0x2000] {
        let mut bytes = synthetic_elf(segments);
        bytes[16..18].copy_from_slice(&elf64::ET_DYN.to_le_bytes());
        bytes
    }

    /// A minimal `ET_DYN` shared object with an optional `DT_NEEDED` list.
    ///
    /// One RX `PT_LOAD` covers file offsets `0x1000..0x1400` at virtual
    /// `0x1000..0x1400`; the string table lives at file/virtual `0x1080` and the
    /// dynamic table at file/virtual `0x1100` (both inside the segment).
    fn shared_object_with_needed(needed: &[&[u8]]) -> [u8; 0x2000] {
        const STRING_OFFSET: usize = 0x1080;
        const STRING_VADDR: u64 = 0x1080;
        const DYNAMIC_OFFSET: usize = 0x1100;

        let mut bytes = synthetic_elf(&[(
            elf64::PT_LOAD,
            0x1000,
            0x400,
            0x400,
            elf64::PF_R | elf64::PF_X,
        )]);
        bytes[16..18].copy_from_slice(&elf64::ET_DYN.to_le_bytes());
        bytes[24..32].copy_from_slice(&0u64.to_le_bytes());

        let mut cursor = 0usize;
        let mut offsets = [0u64; 4];
        for (index, name) in needed.iter().enumerate() {
            offsets[index] = cursor as u64;
            let at = STRING_OFFSET + cursor;
            bytes[at..at + name.len()].copy_from_slice(name);
            cursor += name.len() + 1;
        }
        let string_size = cursor as u64;

        // Second program header: PT_DYNAMIC over the dynamic table.
        let entries = needed.len() + 3; // NEEDED*, STRTAB, STRSZ, NULL
        let table_size = (entries * 16) as u64;
        let phdr = 64 + 56;
        bytes[phdr..phdr + 4].copy_from_slice(&elf64::PT_DYNAMIC.to_le_bytes());
        bytes[phdr + 4..phdr + 8].copy_from_slice(&4u32.to_le_bytes());
        bytes[phdr + 8..phdr + 16].copy_from_slice(&(DYNAMIC_OFFSET as u64).to_le_bytes());
        bytes[phdr + 16..phdr + 24].copy_from_slice(&(DYNAMIC_OFFSET as u64).to_le_bytes());
        bytes[phdr + 24..phdr + 32].copy_from_slice(&(DYNAMIC_OFFSET as u64).to_le_bytes());
        bytes[phdr + 32..phdr + 40].copy_from_slice(&table_size.to_le_bytes());
        bytes[phdr + 40..phdr + 48].copy_from_slice(&table_size.to_le_bytes());
        bytes[phdr + 48..phdr + 56].copy_from_slice(&8u64.to_le_bytes());
        bytes[56..58].copy_from_slice(&2u16.to_le_bytes());

        let mut at = DYNAMIC_OFFSET;
        for index in 0..needed.len() {
            bytes[at..at + 8].copy_from_slice(&elf64::DT_NEEDED.to_le_bytes());
            bytes[at + 8..at + 16].copy_from_slice(&offsets[index].to_le_bytes());
            at += 16;
        }
        bytes[at..at + 8].copy_from_slice(&elf64::DT_STRTAB.to_le_bytes());
        bytes[at + 8..at + 16].copy_from_slice(&STRING_VADDR.to_le_bytes());
        at += 16;
        bytes[at..at + 8].copy_from_slice(&elf64::DT_STRSZ.to_le_bytes());
        bytes[at + 8..at + 16].copy_from_slice(&string_size.to_le_bytes());
        at += 16;
        bytes[at..at + 8].copy_from_slice(&elf64::DT_NULL.to_le_bytes());
        bytes
    }

    fn plan_with_m9e() -> LibraryPlan {
        LibraryPlan {
            m9e_base: DYNAMIC_LIBRARY_BIAS,
            ..LibraryPlan::default()
        }
    }

    fn plan_with_a_and_b() -> LibraryPlan {
        LibraryPlan {
            a_base: DYNAMIC_LIBRARY_A_BIAS,
            b_base: DYNAMIC_LIBRARY_B_BIAS,
            ..LibraryPlan::default()
        }
    }

    fn plan_with_all() -> LibraryPlan {
        LibraryPlan {
            m9e_base: DYNAMIC_LIBRARY_BIAS,
            a_base: DYNAMIC_LIBRARY_A_BIAS,
            b_base: DYNAMIC_LIBRARY_B_BIAS,
        }
    }

    #[test]
    fn library_plans_cover_the_frozen_closures() {
        assert_eq!(plan_libraries(&[]), Ok(LibraryPlan::default()));
        assert_eq!(plan_libraries(&[DYNAMIC_LIBRARY_PATH]), Ok(plan_with_m9e()));
        assert_eq!(
            plan_libraries(&[DYNAMIC_LIBRARY_A_PATH]),
            Ok(plan_with_a_and_b())
        );
        assert_eq!(
            plan_libraries(&[DYNAMIC_LIBRARY_A_PATH, DYNAMIC_LIBRARY_PATH]),
            Ok(plan_with_all())
        );
        assert_eq!(
            plan_libraries(&[DYNAMIC_LIBRARY_PATH, DYNAMIC_LIBRARY_A_PATH]),
            Ok(plan_with_all())
        );

        // Duplicates, unknown names, asking for B directly, and more than two
        // entries are all rejected.
        assert_eq!(
            plan_libraries(&[DYNAMIC_LIBRARY_PATH, DYNAMIC_LIBRARY_PATH]),
            Err(ImageError::LibraryMismatch)
        );
        assert_eq!(
            plan_libraries(&[DYNAMIC_LIBRARY_A_PATH, DYNAMIC_LIBRARY_A_PATH]),
            Err(ImageError::LibraryMismatch)
        );
        assert_eq!(
            plan_libraries(&[DYNAMIC_LIBRARY_B_PATH]),
            Err(ImageError::LibraryMismatch)
        );
        assert_eq!(
            plan_libraries(&[b"/fat/other.so"]),
            Err(ImageError::LibraryMismatch)
        );
        assert_eq!(
            plan_libraries(&[
                DYNAMIC_LIBRARY_PATH,
                DYNAMIC_LIBRARY_A_PATH,
                DYNAMIC_LIBRARY_B_PATH
            ]),
            Err(ImageError::LibraryMismatch)
        );
    }

    #[test]
    fn main_needed_lists_are_parsed_into_the_frozen_closures() {
        let bytes = shared_object_with_needed(&[]);
        let elf = elf64::Elf64::parse(&bytes).expect("parse");
        assert_eq!(plan_for_elf(&elf), Ok(LibraryPlan::default()));

        let bytes = shared_object_with_needed(&[DYNAMIC_LIBRARY_PATH]);
        let elf = elf64::Elf64::parse(&bytes).expect("parse");
        assert_eq!(plan_for_elf(&elf), Ok(plan_with_m9e()));

        let bytes = shared_object_with_needed(&[DYNAMIC_LIBRARY_PATH, DYNAMIC_LIBRARY_A_PATH]);
        let elf = elf64::Elf64::parse(&bytes).expect("parse");
        assert_eq!(plan_for_elf(&elf), Ok(plan_with_all()));

        let bytes = shared_object_with_needed(&[DYNAMIC_LIBRARY_PATH, DYNAMIC_LIBRARY_PATH]);
        let elf = elf64::Elf64::parse(&bytes).expect("parse");
        assert_eq!(plan_for_elf(&elf), Err(ImageError::LibraryMismatch));

        let bytes = shared_object_with_needed(&[b"/fat/other.so"]);
        let elf = elf64::Elf64::parse(&bytes).expect("parse");
        assert_eq!(plan_for_elf(&elf), Err(ImageError::LibraryMismatch));

        // An image without a dynamic table has no dependencies at all (this is
        // the old M9d1/M9d2 closure, which never asked for a library).
        let bytes = shared_library_elf(&[(
            elf64::PT_LOAD,
            0x1000,
            0x400,
            0x400,
            elf64::PF_R | elf64::PF_X,
        )]);
        let elf = elf64::Elf64::parse(&bytes).expect("parse");
        assert_eq!(plan_for_elf(&elf), Ok(LibraryPlan::default()));
    }

    #[test]
    fn a_plain_et_dyn_image_is_a_valid_shared_library() {
        let bytes =
            shared_library_elf(&[(elf64::PT_LOAD, 0, 0x100, 0x100, elf64::PF_R | elf64::PF_X)]);
        let elf = elf64::Elf64::parse(&bytes).expect("parse");
        assert!(elf.is_dynamic());
        validate_shared_library_at(&bytes, DYNAMIC_LIBRARY_BIAS, None).expect("library");
        assert!(library_window_contains(&elf, DYNAMIC_LIBRARY_BIAS));
    }

    #[test]
    fn shared_library_validation_accepts_a_real_library_shaped_entry_zero_image() {
        // Shaped like the real libraries: `e_entry == 0` and separate RX/RW
        // segments; no executable segment contains the biased entry, which is
        // legal for a shared object (the kernel never jumps to it).
        let mut bytes = shared_library_elf(&[
            (
                elf64::PT_LOAD,
                0x1000,
                0x100,
                0x100,
                elf64::PF_R | elf64::PF_X,
            ),
            (
                elf64::PT_LOAD,
                0x2100,
                0x80,
                0x80,
                elf64::PF_R | elf64::PF_W,
            ),
        ]);
        bytes[24..32].copy_from_slice(&0u64.to_le_bytes());
        validate_shared_library_at(&bytes, DYNAMIC_LIBRARY_BIAS, None).expect("entry-zero library");
        validate_shared_library_at(&bytes, DYNAMIC_LIBRARY_A_BIAS, None)
            .expect("entry-zero library at the A bias");
        validate_shared_library_at(&bytes, DYNAMIC_LIBRARY_B_BIAS, None)
            .expect("entry-zero library at the B bias");
    }

    #[test]
    fn shared_library_rejects_et_exec_and_writable_executable() {
        let mut bytes =
            shared_library_elf(&[(elf64::PT_LOAD, 0, 0x100, 0x100, elf64::PF_R | elf64::PF_X)]);
        bytes[16..18].copy_from_slice(&elf64::ET_EXEC.to_le_bytes());
        assert_eq!(
            validate_shared_library_at(&bytes, DYNAMIC_LIBRARY_BIAS, None),
            Err(ImageError::LibraryRejected)
        );

        let flags = elf64::PF_R | elf64::PF_W | elf64::PF_X;
        let bytes = shared_library_elf(&[(elf64::PT_LOAD, 0, 0x100, 0x100, flags)]);
        assert_eq!(
            validate_shared_library_at(&bytes, DYNAMIC_LIBRARY_BIAS, None),
            Err(ImageError::LibraryRejected)
        );
    }

    #[test]
    fn shared_library_must_stay_inside_its_window() {
        let biases = [
            DYNAMIC_LIBRARY_BIAS,
            DYNAMIC_LIBRARY_A_BIAS,
            DYNAMIC_LIBRARY_B_BIAS,
        ];

        // A segment starting at the window's upper bound is outside the window.
        let bytes = shared_library_elf(&[(
            elf64::PT_LOAD,
            DYNAMIC_LIBRARY_WINDOW,
            0x100,
            0x100,
            elf64::PF_R | elf64::PF_X,
        )]);
        for bias in biases {
            assert_eq!(
                validate_shared_library_at(&bytes, bias, None),
                Err(ImageError::LibraryRejected)
            );
        }

        // A segment that ends exactly at the upper bound is still inside.
        let bytes = shared_library_elf(&[(
            elf64::PT_LOAD,
            DYNAMIC_LIBRARY_WINDOW - 0x1000,
            0x100,
            0x100,
            elf64::PF_R | elf64::PF_X,
        )]);
        for bias in biases {
            validate_shared_library_at(&bytes, bias, None).expect("library at the window edge");
        }
    }

    #[test]
    fn shared_library_positions_enforce_the_needed_chain() {
        let m9e = shared_object_with_needed(&[]);
        validate_shared_library_at(&m9e, DYNAMIC_LIBRARY_BIAS, None).expect("m9e");
        assert_eq!(
            validate_shared_library_at(&m9e, DYNAMIC_LIBRARY_BIAS, Some(DYNAMIC_LIBRARY_B_PATH)),
            Err(ImageError::LibraryMismatch)
        );

        let a = shared_object_with_needed(&[DYNAMIC_LIBRARY_B_PATH]);
        validate_shared_library_at(&a, DYNAMIC_LIBRARY_A_BIAS, Some(DYNAMIC_LIBRARY_B_PATH))
            .expect("A needs B");
        assert_eq!(
            validate_shared_library_at(&a, DYNAMIC_LIBRARY_A_BIAS, None),
            Err(ImageError::LibraryMismatch)
        );
        assert_eq!(
            validate_shared_library_at(&a, DYNAMIC_LIBRARY_A_BIAS, Some(DYNAMIC_LIBRARY_A_PATH)),
            Err(ImageError::LibraryMismatch)
        );

        let b = shared_object_with_needed(&[]);
        validate_shared_library_at(&b, DYNAMIC_LIBRARY_B_BIAS, None).expect("B has no deps");
        assert_eq!(
            validate_shared_library_at(&b, DYNAMIC_LIBRARY_B_BIAS, Some(DYNAMIC_LIBRARY_B_PATH)),
            Err(ImageError::LibraryMismatch)
        );

        // A's dependency list can never be accepted at B's position.
        assert_eq!(
            validate_shared_library_at(&a, DYNAMIC_LIBRARY_B_BIAS, None),
            Err(ImageError::LibraryMismatch)
        );
    }

    #[test]
    fn library_error_strings_are_stable() {
        assert_eq!(
            ImageError::LibraryMismatch.as_str(),
            "image-library-mismatch"
        );
        assert_eq!(
            ImageError::LibraryRejected.as_str(),
            "image-library-rejected"
        );
    }
}
