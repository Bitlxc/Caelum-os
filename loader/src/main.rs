//! CaelumOS UEFI loader.
//!
//! Responsibilities (per agents.md §5, Boot Protocol 1.1):
//! - load `KERNEL.ELF` from the ESP via the Simple File System protocol,
//! - validate the ELF and pre-check the `.caelum.bootreq` metadata *before*
//!   `ExitBootServices` (reject on incompatibility),
//! - load and validate `INITFS.IMG` (M4 boot-module container), handing the
//!   module physical ranges to the kernel through BootInfo TLV 0x7,
//! - query the GOP framebuffer for the optional FB_GOP TLV (M6c; a firmware
//!   without a usable GOP simply gets no TLV, which is not an error),
//! - collect the final memory map, build BootInfo + initial page tables
//!   (covering every kernel PT_LOAD, stack, BootInfo, page tables, loader),
//! - `ExitBootServices` with retry on map-key mismatch,
//! - disable interrupts, switch CR3/stack, jump to the kernel entry with
//!   `rdi = rsi = BootInfo` physical address.

#![no_std]
#![no_main]

mod uefi;

use bootinfo::{
    EarlySerialTlv, FbGopTlv, KernelImageTlv, MemoryMapTlv, PROTOCOL_MAJOR, PROTOCOL_MINOR, Writer,
    tlv_type,
};
use core::arch::asm;
use core::ffi::c_void;
use core::fmt;
use core::ptr;
use uefi::*;

const LOADER_VERSION: &str = "0.2.0";

// Early diagnostic output: 16550 UART at COM1 (QEMU/OVMF baseline).
const SERIAL_PORT: u16 = 0x3F8;
const SERIAL_BAUD: u32 = 115200;

// Sizes.
const STACK_SIZE: u64 = 64 * 1024;
const MMAP_CAP: usize = 256 * 1024;
const BOOTINFO_CAP: usize = 384 * 1024;
const PT_POOL_PAGES: usize = 512;
const MAX_KERNEL_FILE: u64 = 16 * 1024 * 1024;
const MAX_INITFS_FILE: u64 = 8 * 1024 * 1024;
const EBS_MAX_ATTEMPTS: usize = 3;

// ESP paths. Pure 8.3 names so every UEFI SFS implementation can open them.
const KERNEL_PATH: &[u8] = b"\\KERNEL.ELF";
const INITFS_PATH: &[u8] = b"\\INITFS.IMG";

/// Boot modules the kernel requires, in container order (protocol 1.1 §5.1).
///
/// `init`/`child` are the M4 pair; `worker` is the M6b2 handle-less workload
/// (two instances are spawned by init, each packed from `caelum-worker`);
/// `gfx` is the M6c display/input program (`caelum-gfx`); `net` is the M7b
/// native socket self-test (`caelum-net`), parent and child; `linux` is the M7d
/// Linux64 personality self-test (`caelum-linux-net`).
const BOOT_MODULE_NAMES: [&[u8]; 6] = [b"init", b"child", b"worker", b"gfx", b"net", b"linux"];

const LOCATE_HANDLE_BY_PROTOCOL: u32 = 2;

const PAGE: u64 = 4096;

// ---------------------------------------------------------------------------
// Port I/O + logging
// ---------------------------------------------------------------------------

#[inline]
fn outb(port: u16, val: u8) {
    unsafe { asm!("out dx, al", in("dx") port, in("al") val) }
}

#[inline]
fn inb(port: u16) -> u8 {
    let val: u8;
    unsafe { asm!("in al, dx", out("al") val, in("dx") port) };
    val
}

fn serial_putc(c: u8) {
    // Bounded wait: on machines without a COM1 the LSR reads back garbage or
    // 0xFF forever; drop the character after a short spin.
    let mut spins = 0u32;
    while inb(SERIAL_PORT + 5) & 0x20 == 0 {
        spins += 1;
        if spins > 100_000 {
            return;
        }
    }
    outb(SERIAL_PORT, c);
}

static mut CON_OUT: *mut SimpleTextOutput = ptr::null_mut();
static mut POST_EBS: bool = false;

fn con_out_putc(c: u8) {
    // After ExitBootServices the console protocol is no longer usable.
    if unsafe { POST_EBS } {
        return;
    }
    unsafe {
        if CON_OUT.is_null() {
            return;
        }
        let buf = [c as u16, 0];
        ((*CON_OUT).output_string)(CON_OUT, buf.as_ptr());
    }
}

struct LogWriter;

impl fmt::Write for LogWriter {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        let post_ebs = unsafe { POST_EBS };
        for &b in s.as_bytes() {
            if post_ebs {
                serial_putc(b);
            } else {
                // OVMF commonly routes ConOut to both display and serial; writing
                // COM1 as well here would duplicate every pre-EBS line in the
                // serial log. Firmware console is the required pre-EBS channel.
                con_out_putc(b);
            }
        }
        Ok(())
    }
}

/// Emit one log line: `<msg>` followed by a newline on the active sink.
fn log_line(args: fmt::Arguments) {
    use fmt::Write as _;
    let mut w = LogWriter;
    let _ = w.write_fmt(args);
    if unsafe { POST_EBS } {
        serial_putc(b'\r');
        serial_putc(b'\n');
    } else {
        con_out_putc(b'\r');
        con_out_putc(b'\n');
    }
}

macro_rules! log {
    ($($arg:tt)*) => { log_line(format_args!($($arg)*)) };
}

// ---------------------------------------------------------------------------
// Page tables
// ---------------------------------------------------------------------------

const PTE_PRESENT: u64 = 1 << 0;
const PTE_WRITE: u64 = 1 << 1;
const PTE_NX: u64 = 1 << 63;
const ADDR_MASK: u64 = 0x000F_FFFF_FFFF_F000;

fn zero_page(phys: u64) {
    unsafe { ptr::write_bytes(phys as *mut u8, 0, PAGE as usize) };
}

struct PtPool {
    next: u64,
    end: u64,
}

impl PtPool {
    fn take(&mut self) -> Option<u64> {
        if self.next + PAGE <= self.end {
            let frame = self.next;
            self.next += PAGE;
            zero_page(frame);
            Some(frame)
        } else {
            None
        }
    }
}

struct PageTables {
    pml4: u64,
    pool: PtPool,
}

impl PageTables {
    /// Map one 4 KiB page. `leaf_flags` must contain PTE_PRESENT; intermediate
    /// tables are created present+writable. Walks all four levels
    /// (PML4 → PDPT → PD → PT).
    fn map4k(&mut self, vaddr: u64, phys: u64, leaf_flags: u64) -> Result<(), ()> {
        let mut table = self.pml4;
        for level in 0..4u32 {
            let idx = ((vaddr >> (39 - level * 9)) & 0x1FF) as u64;
            let entry_ptr = (table + idx * 8) as *mut u64;
            // SAFETY: page table frames come from our own pool and remain
            // identity-mapped until we switch CR3.
            let entry = unsafe { *entry_ptr };
            if level < 3 {
                if entry & PTE_PRESENT == 0 {
                    let next = self.pool.take().ok_or(())?;
                    unsafe { *entry_ptr = next | PTE_PRESENT | PTE_WRITE };
                    table = next;
                } else {
                    table = entry & ADDR_MASK;
                }
            } else {
                unsafe { *entry_ptr = (phys & ADDR_MASK) | leaf_flags };
            }
        }
        Ok(())
    }

    fn map_range(&mut self, vaddr: u64, phys: u64, size: u64, flags: u64) -> Result<(), ()> {
        let mut off = 0u64;
        while off < size {
            self.map4k(vaddr + off, phys + off, flags)?;
            off += PAGE;
        }
        Ok(())
    }
}

fn align_down(v: u64, a: u64) -> u64 {
    v & !(a - 1)
}

fn align_up(v: u64, a: u64) -> u64 {
    (v + a - 1) & !(a - 1)
}

// ---------------------------------------------------------------------------
// Boot flow
// ---------------------------------------------------------------------------

struct Fail(pub Status);

fn fail(msg: fmt::Arguments) -> Fail {
    log_line(msg);
    Fail(efierr(1))
}

fn alloc_pages(bs: &BootServices, ty: u32, pages: usize) -> Result<u64, Status> {
    let mut addr: u64 = 0;
    let st = (bs.allocate_pages)(ALLOCATE_ANY_PAGES, ty, pages, &mut addr);
    if is_error(st) { Err(st) } else { Ok(addr) }
}

fn handle_protocol<T>(bs: &BootServices, handle: Handle, guid: &Guid) -> Result<*mut T, Status> {
    let mut iface: *mut core::ffi::c_void = ptr::null_mut();
    let st = (bs.handle_protocol)(handle, guid, &mut iface);
    if is_error(st) {
        Err(st)
    } else {
        Ok(iface.cast::<T>())
    }
}

/// Snapshot of the UEFI memory map returned by firmware.
struct Mmap {
    buf: u64,    // MMAP_CAP bytes
    size: usize, // bytes used by descriptors
    key: usize,
    desc_size: usize,
    desc_version: u32,
}

fn get_memory_map(bs: &BootServices, mmap: &mut Mmap) -> Result<(), Status> {
    mmap.size = MMAP_CAP;
    let st = (bs.get_memory_map)(
        &mut mmap.size,
        mmap.buf as *mut u8,
        &mut mmap.key,
        &mut mmap.desc_size,
        &mut mmap.desc_version,
    );
    if is_error(st) { Err(st) } else { Ok(()) }
}

/// Read one ESP file into a freshly allocated `MEMORY_LOADER_DATA` buffer.
///
/// The volume lookup is deliberately robust: we first try the device we were
/// booted from, then enumerate every handle that supports the Simple File
/// System protocol, opening `name` on each volume until one succeeds.
fn load_efi_file(
    bs: &BootServices,
    device_handle: Handle,
    name: &[u8],
    max_size: u64,
) -> Result<(u64, u64), Fail> {
    let label = core::str::from_utf8(name).unwrap_or("<esp path>");
    // Fast path: the ESP device we were booted from.
    if let Ok(sfs) = handle_protocol::<SimpleFileSystem>(
        bs,
        device_handle,
        &EFI_SIMPLE_FILE_SYSTEM_PROTOCOL_GUID,
    ) {
        if let Ok(v) = read_file_from_volume(unsafe { &*sfs }, bs, name, max_size) {
            return Ok(v);
        }
    }
    // Fallback: enumerate SFS volumes.
    let mut buf_size = 0usize;
    let st = (bs.locate_handle)(
        LOCATE_HANDLE_BY_PROTOCOL,
        &EFI_SIMPLE_FILE_SYSTEM_PROTOCOL_GUID,
        ptr::null(),
        &mut buf_size,
        ptr::null_mut(),
    );
    if is_error(st) && st != ERR_BUFFER_TOO_SMALL {
        return Err(fail(format_args!(
            "[CaelumLoader] FAIL: LocateHandle(SFS): status=0x{st:x}"
        )));
    }
    let handles = alloc_pages(
        bs,
        MEMORY_LOADER_DATA,
        (align_up(buf_size as u64, PAGE) / PAGE) as usize,
    )
    .map_err(|st| {
        fail(format_args!(
            "[CaelumLoader] FAIL: allocate SFS handle list: status=0x{st:x}"
        ))
    })?;
    let st = (bs.locate_handle)(
        LOCATE_HANDLE_BY_PROTOCOL,
        &EFI_SIMPLE_FILE_SYSTEM_PROTOCOL_GUID,
        ptr::null(),
        &mut buf_size,
        handles as *mut Handle,
    );
    if is_error(st) {
        return Err(fail(format_args!(
            "[CaelumLoader] FAIL: LocateHandle(SFS) second pass: status=0x{st:x}"
        )));
    }
    let count = buf_size / core::mem::size_of::<Handle>();
    for i in 0..count {
        // SAFETY: `handles` holds `count` EFI handles returned by firmware.
        let h =
            unsafe { *((handles as usize + i * core::mem::size_of::<Handle>()) as *const Handle) };
        if h == device_handle {
            continue; // already tried on the fast path
        }
        let Ok(sfs) =
            handle_protocol::<SimpleFileSystem>(bs, h, &EFI_SIMPLE_FILE_SYSTEM_PROTOCOL_GUID)
        else {
            continue;
        };
        if let Ok(v) = read_file_from_volume(unsafe { &*sfs }, bs, name, max_size) {
            return Ok(v);
        }
    }
    Err(fail(format_args!(
        "[CaelumLoader] FAIL: {label} not found on any SFS volume"
    )))
}

fn load_kernel_file(bs: &BootServices, device_handle: Handle) -> Result<(u64, u64), Fail> {
    load_efi_file(bs, device_handle, KERNEL_PATH, MAX_KERNEL_FILE)
}

fn load_initfs_file(bs: &BootServices, device_handle: Handle) -> Result<(u64, u64), Fail> {
    load_efi_file(bs, device_handle, INITFS_PATH, MAX_INITFS_FILE)
}

fn read_file_from_volume(
    sfs: &SimpleFileSystem,
    bs: &BootServices,
    name: &[u8],
    max_size: u64,
) -> Result<(u64, u64), Fail> {
    let label = core::str::from_utf8(name).unwrap_or("<esp path>");
    let mut root: *mut File = ptr::null_mut();
    let st = (sfs.open_volume)(
        sfs as *const SimpleFileSystem as *mut SimpleFileSystem,
        &mut root,
    );
    if is_error(st) {
        return Err(fail(format_args!(
            "[CaelumLoader] FAIL: OpenVolume: status=0x{st:x}"
        )));
    }
    // UCS-2 path, relative to the volume root; fixed 8.3 names only.
    let mut path = [0u16; 16];
    if name.len() + 1 > path.len() {
        unsafe { ((*root).close)(root) };
        return Err(fail(format_args!(
            "[CaelumLoader] FAIL: ESP path too long: {label}"
        )));
    }
    for (i, &b) in name.iter().enumerate() {
        path[i] = b as u16;
    }
    let mut file: *mut File = ptr::null_mut();
    let st = unsafe { ((*root).open)(root, &mut file, path.as_ptr(), FILE_MODE_READ, 0) };
    unsafe { ((*root).close)(root) };
    if is_error(st) {
        return Err(fail(format_args!(
            "[CaelumLoader] FAIL: open {label}: status=0x{st:x}"
        )));
    }
    // File size via end-seek + GetPosition.
    let st = unsafe { ((*file).set_position)(file, FILE_POSITION_END) };
    if is_error(st) {
        unsafe { ((*file).close)(file) };
        return Err(fail(format_args!(
            "[CaelumLoader] FAIL: {label} seek: status=0x{st:x}"
        )));
    }
    let mut size: u64 = 0;
    let st = unsafe { ((*file).get_position)(file, &mut size) };
    if is_error(st) {
        unsafe { ((*file).close)(file) };
        return Err(fail(format_args!(
            "[CaelumLoader] FAIL: {label} tell: status=0x{st:x}"
        )));
    }
    unsafe { ((*file).set_position)(file, 0) };
    if size == 0 || size > max_size {
        unsafe { ((*file).close)(file) };
        return Err(fail(format_args!(
            "[CaelumLoader] FAIL: {label} size {size} invalid or too large"
        )));
    }
    let pages = align_up(size, PAGE) / PAGE;
    let buf = alloc_pages(bs, MEMORY_LOADER_DATA, pages as usize).map_err(|st| {
        unsafe { ((*file).close)(file) };
        fail(format_args!(
            "[CaelumLoader] FAIL: allocate {pages} pages for {label}: status=0x{st:x}"
        ))
    })?;
    let mut done = 0usize;
    while done < size as usize {
        let mut chunk = (size as usize) - done;
        let st = unsafe { ((*file).read)(file, &mut chunk, (buf as usize + done) as *mut u8) };
        if is_error(st) || chunk == 0 {
            unsafe { ((*file).close)(file) };
            return Err(fail(format_args!(
                "[CaelumLoader] FAIL: read {label} at {done}/{size}: status=0x{st:x}"
            )));
        }
        done += chunk;
    }
    unsafe { ((*file).close)(file) };
    Ok((buf, size))
}

/// Placement decision for the kernel image (physical pages allocated before
/// ExitBootServices).
struct Plan<'a> {
    min_vaddr: u64,
    virt_size: u64,
    /// Physical bytes allocated for the image (`kernel_pages * 4096`). This
    /// is what the KERNEL_IMAGE TLV must report as `image_phys_size`; it is
    /// derived from the physical allocation, never from the virtual span.
    kernel_phys_size: u64,
    kernel_phys: u64,
    entry: u64,
    stack_base: u64,
    page_table_phys: u64,
    rsdp: Option<u64>,
    /// GOP framebuffer description for the optional FB_GOP TLV (M6c). `None`
    /// on firmware without a usable 32-bit linear framebuffer; the TLV is then
    /// omitted and boot proceeds unchanged.
    gop: Option<FbGopTlv>,
    /// Validated `INITFS.IMG` container (M4 boot modules).
    initfs: bootinfo::Initfs<'a>,
    /// Physical base the container was loaded to; TLV 0x7 records are
    /// `initfs_phys + module.offset`.
    initfs_phys: u64,
}

/// Build the complete BootInfo image at `base`. `mmap.buf` must hold the raw
/// descriptor bytes at offset 0; this function shifts them by the 8-byte
/// MEMORY_MAP prefix in place (the buffer is exclusively ours and, on an EBS
/// retry, GetMemoryMap has just refreshed it from offset 0).
fn write_bootinfo(base: u64, cap: usize, mmap: &Mmap, plan: &Plan<'_>) -> Result<u32, Fail> {
    // SAFETY: `base` points to BOOTINFO_CAP writable bytes allocated below.
    let region = unsafe { core::slice::from_raw_parts_mut(base as *mut u8, cap) };
    let mut w = Writer::new(
        region,
        PROTOCOL_MAJOR,
        PROTOCOL_MINOR,
        0,
        bootinfo::ENTRY_ABI,
    );
    let add = |r: Result<(), bootinfo::BuildError>| {
        r.map_err(|_| fail(format_args!("[CaelumLoader] FAIL: BootInfo build error")))
    };
    unsafe {
        let p = mmap.buf as *mut u8;
        ptr::copy(p, p.add(MemoryMapTlv::PREFIX_LEN), mmap.size);
        p.write_bytes(0, MemoryMapTlv::PREFIX_LEN);
        let mm = MemoryMapTlv {
            desc_size: mmap.desc_size as u32,
            desc_version: mmap.desc_version,
        };
        p.copy_from(mm.encode().as_ptr(), MemoryMapTlv::PREFIX_LEN);
    }
    let mm_value = unsafe {
        core::slice::from_raw_parts(mmap.buf as *const u8, MemoryMapTlv::PREFIX_LEN + mmap.size)
    };
    add(w.add_tlv(tlv_type::MEMORY_MAP, mm_value))?;
    add(w.add_tlv(
        tlv_type::KERNEL_IMAGE,
        &KernelImageTlv {
            image_phys_base: plan.kernel_phys,
            image_phys_size: plan.kernel_phys_size,
            image_virt_base: plan.min_vaddr,
            image_virt_size: plan.virt_size,
            entry_virt: plan.entry,
            stack_base: plan.stack_base,
            stack_size: STACK_SIZE,
            page_table_phys: plan.page_table_phys,
        }
        .encode(),
    ))?;
    add(w.add_tlv(
        tlv_type::EARLY_SERIAL,
        &EarlySerialTlv {
            kind: EarlySerialTlv::KIND_IOPORT_16550,
            base: u64::from(SERIAL_PORT),
            baud: SERIAL_BAUD,
            reserved: 0,
        }
        .encode(),
    ))?;
    // M6c: optional GOP framebuffer description (type 4). It must stay strictly
    // after EARLY_SERIAL (3) and before ACPI_RSDP (5) to keep TLV types
    // ascending. When the firmware exposes no linear framebuffer the record is
    // omitted and M1..M6b2 kernels keep booting unchanged.
    if let Some(gop) = plan.gop {
        add(w.add_tlv(tlv_type::FB_GOP, &gop.encode()))?;
    }
    if let Some(rsdp) = plan.rsdp {
        add(w.add_tlv(tlv_type::ACPI_RSDP, &rsdp.to_le_bytes()))?;
    }
    add(w.add_tlv(tlv_type::LOADER_INFO, LOADER_VERSION.as_bytes()))?;
    // Boot Protocol 1.1: optional boot-module list (must stay strictly after
    // LOADER_INFO because TLV types are ascending).
    let mut modules_tlv = [0u8; bootinfo::BOOT_MODULES_PREFIX_LEN
        + bootinfo::MAX_BOOT_MODULES * bootinfo::MODULE_RECORD_LEN];
    let modules_len = plan
        .initfs
        .to_boot_modules(plan.initfs_phys, &mut modules_tlv)
        .ok_or_else(|| fail(format_args!("[CaelumLoader] FAIL: boot module TLV encode")))?;
    add(w.add_tlv(tlv_type::BOOT_MODULES, &modules_tlv[..modules_len]))?;
    w.finish()
        .map_err(|_| fail(format_args!("[CaelumLoader] FAIL: BootInfo finish error")))
}

fn find_acpi_rsdp(st: &SystemTable) -> Option<u64> {
    let entries = st.number_of_table_entries;
    let table = st.configuration_table;
    if table.is_null() {
        return None;
    }
    for i in 0..entries {
        // SAFETY: the firmware-owned configuration table is contiguous with
        // `entries` rows.
        let e = unsafe { &*table.add(i) };
        if e.vendor_guid == EFI_ACPI_20_TABLE_GUID {
            return Some(e.vendor_table as u64);
        }
    }
    None
}

// ---------------------------------------------------------------------------
// GOP (UEFI Graphics Output Protocol) query — optional FB_GOP TLV (M6c)
// ---------------------------------------------------------------------------

/// `EFI_GRAPHICS_OUTPUT_PROTOCOL_GUID` (UEFI 2.10 §12.9).
const EFI_GRAPHICS_OUTPUT_PROTOCOL_GUID: Guid = Guid {
    d1: 0x9042_a9de,
    d2: 0x23dc,
    d3: 0x4a38,
    d4: [0x96, 0xfb, 0x7a, 0xde, 0xd0, 0x80, 0x51, 0x6a],
};

/// `EFI_GRAPHICS_OUTPUT_MODE_INFORMATION` (UEFI 2.10 §12.9), 36 bytes.
#[repr(C)]
#[allow(dead_code)]
struct GraphicsOutputModeInformation {
    version: u32,
    horizontal_resolution: u32,
    vertical_resolution: u32,
    /// `EFI_GRAPHICS_OUTPUT_BLT_PIXEL_FORMAT`: 0 RGBX, 1 BGRX, 2 bit mask,
    /// 3 blt only (no linear framebuffer).
    pixel_format: u32,
    pixel_information: [u32; 4],
    pixels_per_scan_line: u32,
}

/// `EFI_GRAPHICS_OUTPUT_PROTOCOL_MODE` (UEFI 2.10 §12.9), 40 bytes.
#[repr(C)]
#[allow(dead_code)]
struct GraphicsOutputMode {
    max_mode: u32,
    mode: u32,
    info: *mut GraphicsOutputModeInformation,
    size_of_info: u64,
    frame_buffer_base: u64,
    frame_buffer_size: u64,
}

/// `EFI_GRAPHICS_OUTPUT_PROTOCOL` (UEFI 2.10 §12.9); only `mode` is read, the
/// three function pointers exist to keep the C layout exact.
#[repr(C)]
#[allow(dead_code)]
struct GraphicsOutput {
    query_mode: *mut c_void,
    set_mode: *mut c_void,
    blt: *mut c_void,
    mode: *mut GraphicsOutputMode,
}

/// Queries the current GOP mode and converts it to the optional FB_GOP TLV.
///
/// Returns `None` when the firmware has no GOP, exposes no linear framebuffer
/// (BltOnly), reports a pixel format other than 32-bit RGBX/BGRX, or reports
/// dimensions that do not fit the framebuffer. A missing GOP must never fail
/// the boot (M6c requirement: the TLV is simply omitted).
fn query_gop(bs: &BootServices) -> Option<FbGopTlv> {
    let mut interface: *mut c_void = ptr::null_mut();
    let status = (bs.locate_protocol)(
        &EFI_GRAPHICS_OUTPUT_PROTOCOL_GUID,
        ptr::null(),
        &mut interface,
    );
    if status != 0 || interface.is_null() {
        return None;
    }
    // SAFETY: LocateProtocol returned a valid GOP interface for this boot.
    let gop = unsafe { &*(interface as *const GraphicsOutput) };
    if gop.mode.is_null() {
        return None;
    }
    // SAFETY: the firmware owns both structures for the whole boot.
    let mode = unsafe { &*gop.mode };
    if mode.info.is_null() {
        return None;
    }
    let info = unsafe { &*mode.info };
    // Only the two 32-bit formats match the kernel display shadow and the M6c
    // gfx program; other formats are omitted instead of guessed.
    if info.pixel_format > 1
        || info.horizontal_resolution == 0
        || info.vertical_resolution == 0
        || info.pixels_per_scan_line < info.horizontal_resolution
        || mode.frame_buffer_base == 0
    {
        return None;
    }
    let row_bytes = (info.pixels_per_scan_line as u64).checked_mul(4)?;
    let needed = row_bytes.checked_mul(info.vertical_resolution as u64)?;
    if mode.frame_buffer_size < needed {
        return None;
    }
    Some(FbGopTlv {
        base: mode.frame_buffer_base,
        size: mode.frame_buffer_size,
        width: info.horizontal_resolution,
        height: info.vertical_resolution,
        stride: info.pixels_per_scan_line,
        pixel_format: info.pixel_format,
    })
}

/// Disable interrupts, switch to the initial page tables, switch the stack
/// and jump to the kernel entry. Never returns.
fn enter_kernel(entry: u64, cr3: u64, stack_top: u64, bootinfo: u64) -> ! {
    unsafe {
        asm!(
            "cli",
            "mov cr3, {pt}",
            "mov rsp, {stack}",
            "mov rdi, {bi}",
            "mov rsi, {bi}",
            "jmp {entry}",
            pt = in(reg) cr3,
            stack = in(reg) stack_top,
            bi = in(reg) bootinfo,
            entry = in(reg) entry,
            options(noreturn),
        )
    }
}

#[unsafe(no_mangle)]
pub extern "efiapi" fn efi_main(image: Handle, system_table: *mut SystemTable) -> Status {
    if system_table.is_null() {
        return efierr(2);
    }
    let st = unsafe { &*system_table };
    // SAFETY: single-threaded entry; CON_OUT is only touched by our own code.
    unsafe { CON_OUT = st.con_out };
    let bs = unsafe { &*st.boot_services };

    log!(
        "[CaelumLoader] CaelumOS M1 loader v{LOADER_VERSION} (boot protocol {PROTOCOL_MAJOR}.{PROTOCOL_MINOR}, entry_abi {})",
        bootinfo::ENTRY_ABI
    );

    // Disable the 5-minute UEFI watchdog.
    (bs.set_watchdog_timer)(0, 0, 0, ptr::null_mut());

    // 1. Locate our own LoadedImage to find the ESP device.
    let loaded_ptr =
        match handle_protocol::<LoadedImage>(bs, image, &EFI_LOADED_IMAGE_PROTOCOL_GUID) {
            Ok(p) => p,
            Err(st) => {
                log!("[CaelumLoader] FAIL: LoadedImage protocol: status=0x{st:x}");
                return efierr(3);
            }
        };
    let loaded = unsafe { &*loaded_ptr };
    let device_handle = loaded.device_handle;
    let image_base = loaded.image_base as u64;
    let image_size = loaded.image_size;

    // 1b. Query the GOP framebuffer for the optional FB_GOP TLV (M6c). This
    //     must happen before ExitBootServices; absence is not an error and the
    //     TLV is omitted so M1..M6b2 kernels keep booting unchanged.
    let gop = query_gop(bs);
    match gop {
        Some(g) => log!(
            "[CaelumLoader] GOP framebuffer: {}x{} stride {} format {} @ phys 0x{:016x} size 0x{:x}",
            g.width,
            g.height,
            g.stride,
            g.pixel_format,
            g.base,
            g.size
        ),
        None => log!("[CaelumLoader] GOP framebuffer: unavailable (FB_GOP TLV omitted)"),
    }

    // 2. Load KERNEL.ELF from the ESP.
    let (file_buf, file_size) = match load_kernel_file(bs, device_handle) {
        Ok(v) => v,
        Err(Fail(code)) => return code,
    };
    log!("[CaelumLoader] KERNEL.ELF: {file_size} bytes @ phys 0x{file_buf:016x}");

    // 3. Parse + validate the ELF, then pre-check .caelum.bootreq before
    //    ExitBootServices (agents.md §5.3 rule 6).
    let file_slice =
        unsafe { core::slice::from_raw_parts(file_buf as *const u8, file_size as usize) };
    let elf = match elf64::Elf64::parse(file_slice) {
        Ok(e) => e,
        Err(e) => {
            log!("[CaelumLoader] FAIL: KERNEL.ELF invalid: {e:?}");
            return efierr(4);
        }
    };
    if let Err(e) = elf.validate_for_boot() {
        log!("[CaelumLoader] FAIL: KERNEL.ELF boot validation: {e:?}");
        return efierr(4);
    }
    let req = match elf.boot_requirements() {
        Ok(r) => r,
        Err(_) => {
            log!("[CaelumLoader] FAIL: missing/invalid .caelum.bootreq metadata section");
            return efierr(4);
        }
    };
    log!(
        "[CaelumLoader] kernel requests protocol {}.{} entry_abi {}",
        req.major,
        req.minor,
        req.entry_abi
    );
    if !req.is_compatible(PROTOCOL_MAJOR, PROTOCOL_MINOR, bootinfo::ENTRY_ABI) {
        log!(
            "[CaelumLoader] FAIL: kernel Boot Protocol requirements incompatible with loader {PROTOCOL_MAJOR}.{PROTOCOL_MINOR}; refusing to boot"
        );
        return efierr(4);
    }
    log!("[CaelumLoader] bootreq precheck OK");

    // 3b. Load and validate the M4 boot-module container (Boot Protocol 1.1,
    //     agents.md §5.6). All module ELFs (init/child, the M6b2 worker, the
    //     M6c gfx program, the M7b net program and the M7d linux program) are
    //     validated before ExitBootServices; the kernel only receives the
    //     already-allocated LoaderData ranges through TLV 0x7.
    let (initfs_buf, initfs_size) = match load_initfs_file(bs, device_handle) {
        Ok(v) => v,
        Err(Fail(code)) => return code,
    };
    log!("[CaelumLoader] INITFS.IMG: {initfs_size} bytes @ phys 0x{initfs_buf:016x}");
    let initfs_slice =
        unsafe { core::slice::from_raw_parts(initfs_buf as *const u8, initfs_size as usize) };
    let initfs = match bootinfo::Initfs::parse(initfs_slice) {
        Ok(c) => c,
        Err(e) => {
            log!("[CaelumLoader] FAIL: INITFS.IMG container: {e:?}");
            return efierr(4);
        }
    };
    if initfs.count() as usize != BOOT_MODULE_NAMES.len() {
        log!(
            "[CaelumLoader] FAIL: INITFS.IMG must contain exactly {} modules, found {}",
            BOOT_MODULE_NAMES.len(),
            initfs.count()
        );
        return efierr(4);
    }
    for name in BOOT_MODULE_NAMES {
        let label = core::str::from_utf8(name).unwrap_or("<module>");
        let module = match initfs.find(name) {
            Some(m) => m,
            None => {
                log!("[CaelumLoader] FAIL: INITFS.IMG missing module '{label}'");
                return efierr(4);
            }
        };
        if module.kind != bootinfo::MODULE_KIND_ELF {
            log!(
                "[CaelumLoader] FAIL: module '{label}' has unsupported kind {}",
                module.kind
            );
            return efierr(4);
        }
        let bytes = match initfs.data_of(&module) {
            Some(b) => b,
            None => {
                log!("[CaelumLoader] FAIL: module '{label}' payload out of range");
                return efierr(4);
            }
        };
        let module_elf = match elf64::Elf64::parse(bytes) {
            Ok(e) => e,
            Err(e) => {
                log!("[CaelumLoader] FAIL: module '{label}' invalid ELF: {e:?}");
                return efierr(4);
            }
        };
        if let Err(e) = module_elf.validate_for_user() {
            log!("[CaelumLoader] FAIL: module '{label}' user-image validation: {e:?}");
            return efierr(4);
        }
        log!(
            "[CaelumLoader] module {label}: {} bytes @ offset 0x{:x} entry 0x{:016x}",
            module.size,
            module.offset,
            module_elf.entry
        );
    }

    // 4. Decide placement and allocate everything that must survive
    //    ExitBootServices. The authoritative page-aligned virtual span comes
    //    from the ELF itself; the physical allocation is exactly
    //    `kernel_pages` frames, which is what KERNEL_IMAGE.image_phys_size
    //    must report (never the virtual size field).
    let span = match elf.load_span() {
        Ok(s) => s,
        Err(e) => {
            log!("[CaelumLoader] FAIL: KERNEL.ELF load span: {e:?}");
            return efierr(4);
        }
    };
    let min_vaddr = span.min_vaddr;
    let virt_size = span.span_size;
    let kernel_pages = virt_size / PAGE;
    let kernel_phys_size = kernel_pages * PAGE;
    let mut segments = [(0u64, 0u64, 0u64, 0u64, 0u32); elf64::MAX_LOAD_SEGMENTS]; // (vaddr_page, size, file_off, filesz, flags)
    let mut nseg = 0usize;
    let mut layout_err = false;
    let _ = elf.for_each_load(|ph| {
        let vaddr_page = align_down(ph.vaddr, PAGE);
        let end = align_up(ph.vaddr + ph.memsz, PAGE);
        if end - vaddr_page > kernel_phys_size {
            // A segment must fit inside the physical allocation we report.
            layout_err = true;
        }
        if nseg < segments.len() {
            segments[nseg] = (vaddr_page, end - vaddr_page, ph.offset, ph.filesz, ph.flags);
            nseg += 1;
        } else {
            layout_err = true;
        }
        Ok(())
    });
    if layout_err {
        log!("[CaelumLoader] FAIL: kernel segments do not fit the allocated image");
        return efierr(4);
    }
    let kernel_phys = match alloc_pages(bs, MEMORY_LOADER_CODE, kernel_pages as usize) {
        Ok(p) => p,
        Err(st) => {
            log!(
                "[CaelumLoader] FAIL: allocate kernel image ({kernel_pages} pages): status=0x{st:x}"
            );
            return efierr(5);
        }
    };
    let stack_base = match alloc_pages(bs, MEMORY_LOADER_DATA, (STACK_SIZE / PAGE) as usize) {
        Ok(p) => p,
        Err(st) => {
            log!("[CaelumLoader] FAIL: allocate stack: status=0x{st:x}");
            return efierr(5);
        }
    };
    let bootinfo_base = match alloc_pages(
        bs,
        MEMORY_LOADER_DATA,
        (BOOTINFO_CAP as u64 / PAGE) as usize,
    ) {
        Ok(p) => p,
        Err(st) => {
            log!("[CaelumLoader] FAIL: allocate BootInfo region: status=0x{st:x}");
            return efierr(5);
        }
    };
    let mmap_buf = match alloc_pages(bs, MEMORY_LOADER_DATA, (MMAP_CAP as u64 / PAGE) as usize) {
        Ok(p) => p,
        Err(st) => {
            log!("[CaelumLoader] FAIL: allocate memory map buffer: status=0x{st:x}");
            return efierr(5);
        }
    };
    let pt_pool = match alloc_pages(bs, MEMORY_LOADER_DATA, PT_POOL_PAGES) {
        Ok(p) => p,
        Err(st) => {
            log!("[CaelumLoader] FAIL: allocate page table pool: status=0x{st:x}");
            return efierr(5);
        }
    };

    // 5. Copy segments into place (zero first, then file bytes; BSS ends up 0).
    unsafe { ptr::write_bytes(kernel_phys as *mut u8, 0, virt_size as usize) };
    for &(vaddr_page, _size, file_off, filesz, _flags) in &segments[..nseg] {
        let dst = kernel_phys + (vaddr_page - min_vaddr);
        // SAFETY: `dst` lies inside the freshly allocated, zeroed image region;
        // file bounds were validated by validate_for_boot.
        unsafe {
            ptr::copy_nonoverlapping(
                (file_buf as usize + file_off as usize) as *const u8,
                dst as *mut u8,
                filesz as usize,
            )
        };
    }

    let plan = Plan {
        min_vaddr,
        virt_size,
        kernel_phys_size,
        kernel_phys,
        entry: elf.entry,
        stack_base,
        page_table_phys: pt_pool,
        rsdp: find_acpi_rsdp(st),
        gop,
        initfs,
        initfs_phys: initfs_buf,
    };
    log!(
        "[CaelumLoader] kernel image: phys 0x{kernel_phys:016x} size 0x{virt_size:x} -> virt 0x{min_vaddr:016x} entry 0x{:016x}",
        elf.entry
    );
    if let Some(rsdp) = plan.rsdp {
        log!("[CaelumLoader] ACPI RSDP @ 0x{rsdp:016x}");
    }

    // 6. Initial page tables (built before ExitBootServices, used right after).
    //    Must cover: all kernel PT_LOADs (physical and virtual), the initial
    //    stack, the whole BootInfo region, the page tables themselves, and
    //    the loader image (agents.md §5.3 rule 7, §5.5).
    let mut pt = PageTables {
        pml4: pt_pool,
        pool: PtPool {
            next: pt_pool + PAGE,
            end: pt_pool + (PT_POOL_PAGES as u64) * PAGE,
        },
    };
    zero_page(pt.pml4);
    let mut map_failed = false;
    // Kernel image physical range, identity-mapped (NX; execution goes through
    // the per-segment virtual aliases below).
    if pt
        .map_range(
            kernel_phys,
            kernel_phys,
            virt_size,
            PTE_PRESENT | PTE_WRITE | PTE_NX,
        )
        .is_err()
    {
        map_failed = true;
    }
    // Each PT_LOAD at its virtual link address, per-segment W^X permissions.
    for &(vaddr_page, size, _off, _filesz, flags) in &segments[..nseg] {
        let seg_phys = kernel_phys + (vaddr_page - min_vaddr);
        let mut leaf = PTE_PRESENT;
        if flags & elf64::PF_W != 0 {
            leaf |= PTE_WRITE;
        }
        if flags & elf64::PF_X == 0 {
            leaf |= PTE_NX;
        }
        if pt.map_range(vaddr_page, seg_phys, size, leaf).is_err() {
            map_failed = true;
        }
    }
    // The loader image stays executable: our code runs from it after CR3.
    let img_lo = align_down(image_base, PAGE);
    let img_hi = align_up(image_base + image_size, PAGE);
    log!("[CaelumLoader] loader image mapped: 0x{img_lo:016x}..0x{img_hi:016x}");
    if pt
        .map_range(img_lo, img_lo, img_hi - img_lo, PTE_PRESENT | PTE_WRITE)
        .is_err()
    {
        map_failed = true;
    }
    if pt
        .map_range(
            stack_base,
            stack_base,
            STACK_SIZE,
            PTE_PRESENT | PTE_WRITE | PTE_NX,
        )
        .is_err()
    {
        map_failed = true;
    }
    if pt
        .map_range(
            bootinfo_base,
            bootinfo_base,
            BOOTINFO_CAP as u64,
            PTE_PRESENT | PTE_WRITE | PTE_NX,
        )
        .is_err()
    {
        map_failed = true;
    }
    if pt
        .map_range(
            pt_pool,
            pt_pool,
            (PT_POOL_PAGES as u64) * PAGE,
            PTE_PRESENT | PTE_WRITE | PTE_NX,
        )
        .is_err()
    {
        map_failed = true;
    }
    if map_failed {
        log!("[CaelumLoader] FAIL: page table pool exhausted");
        return efierr(6);
    }
    log!("[CaelumLoader] initial page tables @ phys 0x{pt_pool:016x}");

    // 7. Snapshot the memory map and build BootInfo. Crucially, *no* Boot
    //    Service calls — not even ConOut logging, which may allocate pool
    //    memory and invalidate the map key — happen between GetMemoryMap and
    //    ExitBootServices below.
    let mut mmap = Mmap {
        buf: mmap_buf,
        size: 0,
        key: 0,
        desc_size: 0,
        desc_version: 0,
    };
    log!("[CaelumLoader] building BootInfo, then ExitBootServices");
    if let Err(st) = get_memory_map(bs, &mut mmap) {
        log!("[CaelumLoader] FAIL: GetMemoryMap: status=0x{st:x}");
        return efierr(7);
    }
    if let Err(Fail(code)) = write_bootinfo(bootinfo_base, BOOTINFO_CAP, &mmap, &plan) {
        return code;
    }

    // 8. ExitBootServices with retry (agents.md §5.4): on failure re-obtain
    //    the full map — never reusing the old key — rebuild the BootInfo
    //    memory-map TLV, and retry. Logging happens only immediately after a
    //    failed attempt, never between GetMemoryMap and the next attempt.
    let mut attempt = 0usize;
    loop {
        attempt += 1;
        let st = (bs.exit_boot_services)(image, mmap.key);
        if !is_error(st) {
            // From here on, no UEFI protocols are usable.
            unsafe { POST_EBS = true };
            log!("[CaelumLoader] ExitBootServices OK (attempt {attempt})");
            break;
        }
        log!("[CaelumLoader] ExitBootServices attempt {attempt} failed: status=0x{st:x}");
        if attempt >= EBS_MAX_ATTEMPTS {
            log!(
                "[CaelumLoader] FAIL: ExitBootServices did not succeed after {EBS_MAX_ATTEMPTS} attempts"
            );
            return efierr(8);
        }
        if let Err(st2) = get_memory_map(bs, &mut mmap) {
            log!("[CaelumLoader] FAIL: GetMemoryMap retry: status=0x{st2:x}");
            return efierr(8);
        }
        if let Err(Fail(code)) = write_bootinfo(bootinfo_base, BOOTINFO_CAP, &mmap, &plan) {
            return code;
        }
    }
    log!(
        "[CaelumLoader] BootInfo @ phys 0x{bootinfo_base:016x}, {} descriptors handed to kernel",
        mmap.size / mmap.desc_size
    );

    // 9. Interrupts off, new CR3, new stack, jump to the kernel entry with
    //    rdi = rsi = BootInfo physical address. Never returns.
    let entry = plan.entry;
    enter_kernel(entry, pt.pml4, stack_base + STACK_SIZE, bootinfo_base);
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    // Serial-only best effort; the firmware console may not be initialized.
    for &b in b"[CaelumLoader] PANIC\r\n" {
        serial_putc(b);
    }
    loop {}
}
