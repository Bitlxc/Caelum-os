//! Read-only backing for the boot modules delivered in `BOOT_MODULES` (M5a).
//!
//! The loader hands the kernel a handful of fixed, named ELF payloads (`init`
//! and `child`).
//!
//! ## M5a role: backing store, not an I/O API
//!
//! Before M5a the image loader read the modules straight out of this window.
//! Since M5a that direct path is retired: the payloads appear as read-only
//! files under `/boot` in the VFS, and the image loader goes through
//! VNode/page cache like every other file. What remains here is the *backing*
//! for that file system: [`crate::vfs::initramfs`] installs
//! [`crate::vfs::initramfs::bootmod_reader`], which pulls page-sized chunks out
//! of this window with the bounded [`open`]/[`read`]/[`close`] shape that
//! agents.md §5.6 asks for. There is deliberately no second copy of the
//! payload and no second ELF loader. Everything is mapped once, read-only and non-executable, into a window
//! in the kernel high half:
//!
//! ```text
//! 0xFFFF_FFFF_8300_0000  .. 0xFFFF_FFFF_8400_0000   (16 MiB, modules 830-840)
//! ```
//!
//! The module bytes live at loader-chosen physical addresses that are *not* in
//! the direct map (only conventional RAM is), so [`init`] maps each one with
//! [`crate::mm::vm::map_physical`] after the VM takeover. A module's physical
//! start need not be page aligned; the mapping covers the whole containing
//! pages and [`Module::data`] starts at the first real byte.
//!
//! [`init`] also re-validates every module as a user-mode ELF with
//! [`elf64::Elf64::validate_for_user`], independently of whatever the loader
//! checked: the Boot Protocol treats module payloads as untrusted input.

use core::ptr;

use bootinfo::{MAX_BOOT_MODULES, MODULE_KIND_ELF, MODULE_NAME_LEN};

use crate::mm::vm;

/// First virtual address of the boot-module window (M4 address plan: 830-840).
pub const MODULE_WINDOW_BASE: u64 = 0xFFFF_FFFF_8300_0000;
/// Size of the boot-module window (16 MiB).
pub const MODULE_WINDOW_LIMIT: u64 = 16 * 1024 * 1024;
/// Maximum number of modules the kernel tracks (the protocol limit).
pub const MAX_MODULES: usize = MAX_BOOT_MODULES;

/// Name of the first user program (spawned by the kernel root).
pub const INIT_MODULE: &[u8] = b"init";
/// Name of the second user program (spawned by `init` through `process_create`).
pub const CHILD_MODULE: &[u8] = b"child";
/// Name of the M6b2 workload: two handle-less instances are spawned by the
/// kernel closeout, one per application processor, to exercise SMP scheduling.
pub const WORKER_MODULE: &[u8] = b"worker";
/// Name of the M6c workload: the `gfx` client receives Display/Input handles
/// and runs the display/input syscall slice on an application processor.
pub const GFX_MODULE: &[u8] = b"gfx";
/// Name of the M7b workload: the `net` parent runs the native socket slice on an
/// application processor and starts its own child through `process_create`.
pub const NET_MODULE: &[u8] = b"net";
/// Name of the M7d workload: the `linux` persona probe runs on an application
/// processor and exercises the six-module metadata wiring (M7d).
pub const LINUX_MODULE: &[u8] = b"linux";

const PAGE: u64 = 4096;
/// ACPI-style read-only mapping: present, never executable, never writable.
const MODULE_FLAGS: u64 = vm::PTE_PRESENT | vm::PTE_NX;

/// Why boot-module setup or access failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BootModError {
    /// [`init`] has not completed yet.
    NotReady,
    /// [`init`] ran twice.
    AlreadyInitialised,
    /// The BootInfo carried no `BOOT_MODULES` TLV.
    NoModules,
    /// The module set does not contain `init`.
    MissingInit,
    /// The module set does not contain `child`.
    MissingChild,
    /// The module set does not contain `worker`.
    MissingWorker,
    /// The module set does not contain `gfx`.
    MissingGfx,
    /// The module set does not contain `net`.
    MissingNet,
    /// The module set does not contain `linux` (M7d).
    MissingLinux,
    /// More modules than [`MAX_MODULES`].
    TooManyModules,
    /// A module is not an ELF payload.
    BadKind,
    /// A module name is empty or malformed.
    BadName,
    /// A module size is zero, overflowing, or larger than the window.
    BadSize,
    /// The module window has no room left.
    WindowExhausted,
    /// Mapping a module read-only failed.
    MapFailed,
    /// A module did not pass user-mode ELF validation.
    ElfRejected,
    /// No module with that name exists.
    NotFound,
    /// A [`ModuleId`] does not refer to an installed module.
    BadModuleId,
    /// A read starts past the end of the module.
    OutOfRange,
}

impl BootModError {
    /// Stable short string for the serial log.
    pub const fn as_str(self) -> &'static str {
        match self {
            BootModError::NotReady => "bootmod-not-ready",
            BootModError::AlreadyInitialised => "bootmod-already-initialised",
            BootModError::NoModules => "bootmod-no-modules",
            BootModError::MissingInit => "bootmod-missing-init",
            BootModError::MissingChild => "bootmod-missing-child",
            BootModError::MissingWorker => "bootmod-missing-worker",
            BootModError::MissingGfx => "bootmod-missing-gfx",
            BootModError::MissingNet => "bootmod-missing-net",
            BootModError::MissingLinux => "bootmod-missing-linux",
            BootModError::TooManyModules => "bootmod-too-many-modules",
            BootModError::BadKind => "bootmod-bad-kind",
            BootModError::BadName => "bootmod-bad-name",
            BootModError::BadSize => "bootmod-bad-size",
            BootModError::WindowExhausted => "bootmod-window-exhausted",
            BootModError::MapFailed => "bootmod-map-failed",
            BootModError::ElfRejected => "bootmod-elf-rejected",
            BootModError::NotFound => "bootmod-not-found",
            BootModError::BadModuleId => "bootmod-bad-module-id",
            BootModError::OutOfRange => "bootmod-out-of-range",
        }
    }
}

/// One installed module: name, window placement and the read-only byte view.
#[derive(Clone, Copy)]
pub struct Module {
    name: [u8; MODULE_NAME_LEN],
    name_len: u32,
    virt: u64,
    size: u64,
    data: &'static [u8],
}

impl Module {
    /// Placeholder used by the static table.
    pub const fn empty() -> Module {
        Module {
            name: [0u8; MODULE_NAME_LEN],
            name_len: 0,
            virt: 0,
            size: 0,
            data: &[],
        }
    }

    /// Module name bytes.
    pub fn name(&self) -> &[u8] {
        let n = (self.name_len as usize).min(self.name.len());
        &self.name[..n]
    }

    pub fn matches(&self, name: &[u8]) -> bool {
        self.name() == name
    }

    /// Virtual address of the module's read-only window mapping.
    pub fn virt(&self) -> u64 {
        self.virt
    }

    /// Module size in bytes (exactly the `BOOT_MODULES` size).
    pub fn size(&self) -> u64 {
        self.size
    }

    /// Read-only view of the module bytes.
    pub fn data(&self) -> &'static [u8] {
        self.data
    }
}

/// Handle to an open module (an index into the fixed table, not a pointer).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ModuleId(u8);

impl ModuleId {
    pub const fn index(self) -> usize {
        self.0 as usize
    }
}

/// The fixed module table. Pure logic, so host tests drive a local instance.
pub struct ModuleTable {
    modules: [Module; MAX_MODULES],
    count: usize,
}

impl ModuleTable {
    pub const fn new() -> ModuleTable {
        ModuleTable {
            modules: [Module::empty(); MAX_MODULES],
            count: 0,
        }
    }

    pub fn len(&self) -> usize {
        self.count
    }

    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    pub fn get(&self, index: usize) -> Option<&Module> {
        if index >= self.count {
            return None;
        }
        Some(&self.modules[index])
    }

    pub fn iter(&self) -> impl Iterator<Item = &Module> + '_ {
        self.modules[..self.count].iter()
    }

    pub fn find(&self, name: &[u8]) -> Option<&Module> {
        self.iter().find(|m| m.matches(name))
    }

    pub fn find_index(&self, name: &[u8]) -> Option<usize> {
        self.modules[..self.count]
            .iter()
            .position(|m| m.matches(name))
    }

    pub fn push(&mut self, module: Module) -> Result<(), BootModError> {
        if self.count >= MAX_MODULES {
            return Err(BootModError::TooManyModules);
        }
        self.modules[self.count] = module;
        self.count += 1;
        Ok(())
    }

    /// Look up a module by exact name and hand back an opaque id.
    pub fn open(&self, name: &[u8]) -> Result<ModuleId, BootModError> {
        let index = self.find_index(name).ok_or(BootModError::NotFound)?;
        Ok(ModuleId(index as u8))
    }

    /// Read up to `out.len()` bytes at `offset`; returns the byte count, which
    /// is short only at end of module.
    pub fn read(&self, id: ModuleId, offset: u64, out: &mut [u8]) -> Result<usize, BootModError> {
        let module = self.get(id.index()).ok_or(BootModError::BadModuleId)?;
        let data = module.data();
        let start = usize::try_from(offset).map_err(|_| BootModError::OutOfRange)?;
        if start > data.len() {
            return Err(BootModError::OutOfRange);
        }
        let n = out.len().min(data.len() - start);
        out[..n].copy_from_slice(&data[start..start + n]);
        Ok(n)
    }

    /// Release an open module id. The table is read-only, so this only checks
    /// that the id is live; the fixed module set is never freed.
    pub fn close(&self, id: ModuleId) -> Result<(), BootModError> {
        self.get(id.index())
            .map(|_| ())
            .ok_or(BootModError::BadModuleId)
    }

    /// Re-validate every module as a user-mode ELF (M4 shares one loader path).
    pub fn validate_elfs(&self) -> Result<(), BootModError> {
        for module in self.iter() {
            let elf = elf64::Elf64::parse(module.data()).map_err(|_| BootModError::ElfRejected)?;
            elf.validate_for_user()
                .map_err(|_| BootModError::ElfRejected)?;
        }
        Ok(())
    }

    /// Validate the fixed module set the kernel root depends on.
    ///
    /// The loader ships `init`, `child`, `worker`, `gfx`, `net` and (since M7d)
    /// `linux`; a missing entry is a boot failure with its own error so the serial
    /// log names the missing module. This is pure table logic, kept separate from
    /// [`init`] so a host test can drive every branch without a real BootInfo.
    fn check_required(&self) -> Result<(), BootModError> {
        if self.find(INIT_MODULE).is_none() {
            return Err(BootModError::MissingInit);
        }
        if self.find(CHILD_MODULE).is_none() {
            return Err(BootModError::MissingChild);
        }
        if self.find(WORKER_MODULE).is_none() {
            return Err(BootModError::MissingWorker);
        }
        if self.find(GFX_MODULE).is_none() {
            return Err(BootModError::MissingGfx);
        }
        if self.find(NET_MODULE).is_none() {
            return Err(BootModError::MissingNet);
        }
        if self.find(LINUX_MODULE).is_none() {
            return Err(BootModError::MissingLinux);
        }
        Ok(())
    }
}

static mut TABLE: ModuleTable = ModuleTable::new();
static mut READY: bool = false;
static mut WINDOW_NEXT: u64 = MODULE_WINDOW_BASE;

/// Map every boot module read-only and validate the fixed set.
///
/// Must run once, after the VM takeover (it calls [`vm::map_physical`]) and
/// before any user process is created. Requires the fixed set `init`, `child`,
/// `worker`, `gfx`, `net` and `linux` to exist; [`ModuleTable::check_required`]
/// names the missing one.
pub fn init() -> Result<(), BootModError> {
    // SAFETY: single CPU; the root context calls this once with interrupts
    // disabled, before user mode, and the table is not otherwise mutated.
    unsafe {
        if ptr::read(ptr::addr_of!(READY)) {
            return Err(BootModError::AlreadyInitialised);
        }
        let state = crate::boot::state();
        let mut table = ModuleTable::new();
        let mut cursor = MODULE_WINDOW_BASE;
        for saved in state.modules() {
            if saved.kind != MODULE_KIND_ELF {
                return Err(BootModError::BadKind);
            }
            let name = saved.name_bytes();
            if name.is_empty() || name.len() > MODULE_NAME_LEN {
                return Err(BootModError::BadName);
            }
            if saved.size == 0 || saved.size > MODULE_WINDOW_LIMIT {
                return Err(BootModError::BadSize);
            }
            saved
                .phys
                .checked_add(saved.size)
                .ok_or(BootModError::BadSize)?;
            // Map the pages that contain [phys, phys + size); a non-page-aligned
            // physical start simply shifts the byte view inside the first page.
            let offset = saved.phys & (PAGE - 1);
            let span = (offset + saved.size + PAGE - 1) & !(PAGE - 1);
            let end = cursor
                .checked_add(span)
                .filter(|&end| end <= MODULE_WINDOW_BASE + MODULE_WINDOW_LIMIT)
                .ok_or(BootModError::WindowExhausted)?;
            let mapped = vm::map_physical(cursor, saved.phys, saved.size, MODULE_FLAGS)
                .map_err(|_| BootModError::MapFailed)?;
            if mapped != cursor + offset {
                return Err(BootModError::MapFailed);
            }
            let data = core::slice::from_raw_parts(mapped as *const u8, saved.size as usize);
            let mut name_buf = [0u8; MODULE_NAME_LEN];
            name_buf[..name.len()].copy_from_slice(name);
            table.push(Module {
                name: name_buf,
                name_len: name.len() as u32,
                virt: cursor,
                size: saved.size,
                data,
            })?;
            cursor = end;
        }
        if table.is_empty() {
            return Err(BootModError::NoModules);
        }
        table.validate_elfs()?;
        table.check_required()?;
        ptr::write(ptr::addr_of_mut!(TABLE), table);
        ptr::write(ptr::addr_of_mut!(WINDOW_NEXT), cursor);
        ptr::write(ptr::addr_of_mut!(READY), true);
    }
    Ok(())
}

/// Whether [`init`] completed.
pub fn is_ready() -> bool {
    // SAFETY: plain read of a `bool` written once before user mode.
    unsafe { ptr::read(ptr::addr_of!(READY)) }
}

/// Installed module table (empty until [`init`]).
fn table() -> &'static ModuleTable {
    // SAFETY: written once by `init` before user mode, then read-only.
    unsafe { &*ptr::addr_of!(TABLE) }
}

/// Number of installed modules.
pub fn count() -> usize {
    table().len()
}

/// Module at `index`.
pub fn module_at(index: usize) -> Option<&'static Module> {
    table().get(index)
}

/// Module with exactly this name.
pub fn find(name: &[u8]) -> Option<&'static Module> {
    table().find(name)
}

/// Reference view of the bytes the loader delivered for `name`.
///
/// This is *not* an I/O path: image loading goes through the VFS since M5a.
/// Only the VFS self-check uses it, to compare what the VNode/page-cache path
/// served against what the loader actually handed the kernel.
pub fn bytes(name: &[u8]) -> Option<&'static [u8]> {
    find(name).map(Module::data)
}

/// Open a module by exact name.
pub fn open(name: &[u8]) -> Result<ModuleId, BootModError> {
    if !is_ready() {
        return Err(BootModError::NotReady);
    }
    table().open(name)
}

/// Read from an open module.
pub fn read(id: ModuleId, offset: u64, out: &mut [u8]) -> Result<usize, BootModError> {
    if !is_ready() {
        return Err(BootModError::NotReady);
    }
    table().read(id, offset, out)
}

/// Close an open module id.
pub fn close(id: ModuleId) -> Result<(), BootModError> {
    if !is_ready() {
        return Err(BootModError::NotReady);
    }
    table().close(id)
}

/// Next free address in the module window (diagnostics).
pub fn window_next() -> u64 {
    // SAFETY: written once by `init`, read-only afterwards.
    unsafe { ptr::read(ptr::addr_of!(WINDOW_NEXT)) }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_module(name: &[u8], data: &'static [u8]) -> Module {
        let mut buf = [0u8; MODULE_NAME_LEN];
        buf[..name.len()].copy_from_slice(name);
        Module {
            name: buf,
            name_len: name.len() as u32,
            virt: 0x1000,
            size: data.len() as u64,
            data,
        }
    }

    fn table_with(mods: &[(&[u8], &'static [u8])]) -> ModuleTable {
        let mut table = ModuleTable::new();
        for &(name, data) in mods {
            table.push(test_module(name, data)).unwrap();
        }
        table
    }

    #[test]
    fn open_find_and_read_are_bounded() {
        static INIT: &[u8] = b"init-bytes";
        static CHILD: &[u8] = b"child-bytes";
        let table = table_with(&[(b"init", INIT), (b"child", CHILD)]);
        assert_eq!(table.len(), 2);
        let id = table.open(b"child").unwrap();
        assert_eq!(table.get(id.index()).unwrap().name(), b"child");
        let mut out = [0u8; 5];
        assert_eq!(table.read(id, 0, &mut out), Ok(5));
        assert_eq!(&out, b"child");
        // Short read at the end, zero bytes exactly at the end.
        assert_eq!(table.read(id, 8, &mut out), Ok(3));
        assert_eq!(&out[..3], b"tes");
        assert_eq!(table.read(id, CHILD.len() as u64, &mut out), Ok(0));
        // Past the end is an error, not a panic.
        assert_eq!(
            table.read(id, CHILD.len() as u64 + 1, &mut out),
            Err(BootModError::OutOfRange)
        );
    }

    #[test]
    fn open_rejects_unknown_and_close_checks_ids() {
        static INIT: &[u8] = b"x";
        let table = table_with(&[(b"init", INIT)]);
        assert_eq!(table.open(b"child"), Err(BootModError::NotFound));
        let id = table.open(b"init").unwrap();
        assert_eq!(table.close(id), Ok(()));
        assert_eq!(
            table.close(ModuleId(MAX_MODULES as u8 - 1)),
            Err(BootModError::BadModuleId)
        );
    }

    #[test]
    fn table_is_bounded_by_the_protocol_limit() {
        static DATA: &[u8] = b"d";
        let mut table = ModuleTable::new();
        for _ in 0..MAX_MODULES {
            table.push(test_module(b"m", DATA)).unwrap();
        }
        assert_eq!(
            table.push(test_module(b"m", DATA)),
            Err(BootModError::TooManyModules)
        );
    }

    #[test]
    fn elf_validation_rejects_garbage() {
        static NOT_ELF: &[u8] = b"not an elf at all";
        let table = table_with(&[(b"init", NOT_ELF)]);
        assert_eq!(table.validate_elfs(), Err(BootModError::ElfRejected));
    }

    #[test]
    fn error_strings_are_stable() {
        assert_eq!(BootModError::NoModules.as_str(), "bootmod-no-modules");
        assert_eq!(BootModError::MissingInit.as_str(), "bootmod-missing-init");
        assert_eq!(BootModError::MissingChild.as_str(), "bootmod-missing-child");
        assert_eq!(
            BootModError::MissingWorker.as_str(),
            "bootmod-missing-worker"
        );
        assert_eq!(BootModError::MissingGfx.as_str(), "bootmod-missing-gfx");
        assert_eq!(BootModError::MissingNet.as_str(), "bootmod-missing-net");
        assert_eq!(BootModError::MissingLinux.as_str(), "bootmod-missing-linux");
        assert_eq!(
            BootModError::WindowExhausted.as_str(),
            "bootmod-window-exhausted"
        );
    }

    #[test]
    fn the_module_names_match_the_loader_entries() {
        // The loader ships `init`/`child`/`worker`/`gfx`/`net`/`linux`; the kernel
        // side must agree on the exact byte strings (no trailing NUL).
        assert_eq!(INIT_MODULE, b"init");
        assert_eq!(CHILD_MODULE, b"child");
        assert_eq!(WORKER_MODULE, b"worker");
        assert_eq!(GFX_MODULE, b"gfx");
        assert_eq!(NET_MODULE, b"net");
        assert_eq!(LINUX_MODULE, b"linux");
    }

    #[test]
    fn the_fixed_module_set_requires_every_entry() {
        static DATA: &[u8] = b"payload";
        let all: [(&[u8], &'static [u8]); 6] = [
            (INIT_MODULE, DATA),
            (CHILD_MODULE, DATA),
            (WORKER_MODULE, DATA),
            (GFX_MODULE, DATA),
            (NET_MODULE, DATA),
            (LINUX_MODULE, DATA),
        ];
        let expected = [
            BootModError::MissingInit,
            BootModError::MissingChild,
            BootModError::MissingWorker,
            BootModError::MissingGfx,
            BootModError::MissingNet,
            BootModError::MissingLinux,
        ];
        // With every entry present the fixed set is complete.
        assert_eq!(table_with(&all).check_required(), Ok(()));
        // Dropping exactly one entry names exactly that module.
        for (missing, error) in expected.iter().enumerate() {
            let mut table = ModuleTable::new();
            for (index, (name, data)) in all.iter().enumerate() {
                if index != missing {
                    table.push(test_module(name, data)).unwrap();
                }
            }
            assert_eq!(table.check_required(), Err(*error));
        }
    }
}
