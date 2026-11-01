//! CaelumOS M9d1 dynamic main program (no libc, no external loader).
//!
//! This binary is a **position-independent ET_DYN** image whose `PT_INTERP`
//! string is exactly `/fat/ldcaelum.so`. The kernel maps it at the frozen load
//! bias `0x0200_0000`, loads the interpreter, and jumps to the *interpreter*
//! first; the interpreter parses this image's program headers, applies the
//! `R_X86_64_RELATIVE` relocations of the `.rela.dyn` array, prints
//! `[CaelumDyn] interp OK`, and finally jumps to `AT_ENTRY` with the initial
//! `rsp` preserved.
//!
//! The main program therefore sees a fully relocated image. It validates:
//!
//! 1. the auxv written by the kernel (`AT_PAGESZ` / `AT_PHDR` / `AT_PHENT` /
//!    `AT_PHNUM` / `AT_ENTRY` / `AT_BASE=0` and the three Caelum entries),
//! 2. its own ELF header at the frozen bias (`ET_DYN`, x86-64, phdr layout),
//! 3. `PT_PHDR` coverage, `PT_LOAD` segmentation and the exact `PT_INTERP`
//!    string,
//! 4. that the interpreter really ran: a `static &u64` and a `static fn()`
//!    pointer must hold their *runtime* (bias-relative) addresses now, not the
//!    link-time offsets,
//! 5. that `AT_ENTRY` is this image's `_start`.
//!
//! It then prints the exact marker `[CaelumLinux] M9d dynamic OK` and exits 0.

#![no_std]
#![no_main]

use core::arch::global_asm;
use core::panic::PanicInfo;

// ---------------------------------------------------------------------------
// ELF entry: keep the initial Linux stack pointer, then run the Rust body.
// ---------------------------------------------------------------------------

global_asm!(
    r#"
    .section .text._start, "ax", @progbits
    .global _start
    .type _start, @function
_start:
    mov rdi, rsp
    and rsp, -16
    call {entry}
    ud2
    .size _start, . - _start
    "#,
    entry = sym dyn_entry,
);

/// Linux x86-64 raw system calls used here (no libc).
const NR_WRITE: u64 = 1;
const NR_EXIT_GROUP: u64 = 231;

// Auxiliary vector types.
const AT_NULL: u64 = 0;
const AT_PHDR: u64 = 3;
const AT_PHENT: u64 = 4;
const AT_PHNUM: u64 = 5;
const AT_PAGESZ: u64 = 6;
const AT_BASE: u64 = 7;
const AT_ENTRY: u64 = 9;
const AT_CAELUM_CHANNEL: u64 = 0xCAE1_0001;
const AT_CAELUM_NETNS: u64 = 0xCAE1_0002;
const AT_CAELUM_ROLE: u64 = 0xCAE1_0003;
/// M9d2: address of the vDSO ELF image mapped by the kernel.
const AT_SYSINFO_EHDR: u64 = 33;

// ELF constants.
const PT_LOAD: u32 = 1;
const PT_DYNAMIC: u32 = 2;
const PT_INTERP: u32 = 3;
const PT_PHDR: u32 = 6;
const ET_DYN: u16 = 3;
const ET_EXEC: u16 = 2;
const EM_X86_64: u16 = 62;
const PHDR_BYTES: u64 = 56;
const PAGE_BYTES: u64 = 4096;

/// Frozen vDSO image layout (M9d2 kernel contract, `services/linux-vdso`).
const VDSO_BASE: u64 = 0x0700_0000;
const VDSO_ENTRY: u64 = 0x0700_1000;
const VDSO_DATA: u64 = 0x0700_2000;
const VDSO_MAGIC: u32 = 0xCAE1_0001;
const VDSO_VERSION: u32 = 1;
const VDSO_MAGIC_OFFSET: usize = 0;
const VDSO_VERSION_OFFSET: usize = 4;
const VDSO_SEQ_OFFSET: usize = 8;
const VDSO_HZ_OFFSET: usize = 12;
const VDSO_TICKS_OFFSET: usize = 16;
const NANOS_PER_SECOND: i64 = 1_000_000_000;
const CLOCK_REALTIME: u64 = 0;
const CLOCK_MONOTONIC: u64 = 1;
const CLOCK_BOOTTIME: u64 = 7;
const VDSO_ENOSYS: i64 = -38;

/// Frozen load bias for this ET_DYN image (M9d1 kernel contract).
const MAIN_BIAS: u64 = 0x0200_0000;

/// The interpreter path the kernel must have mapped (exact string, including
/// the trailing NUL).
const INTERP_PATH: &[u8] = b"/fat/ldcaelum.so\0";

/// Highest number of PT_LOAD segments the checks track.
const MAX_LOADS: usize = 16;

// Exit statuses: one distinct value per failure class.
const EXIT_AUXV: i64 = 0x90;
const EXIT_HEADER: i64 = 0x91;
const EXIT_PROGRAM_HEADERS: i64 = 0x92;
const EXIT_INTERP_STRING: i64 = 0x93;
const EXIT_ENTRY: i64 = 0x94;
const EXIT_RELOCATION: i64 = 0x95;
const EXIT_WRITE: i64 = 0x96;
const EXIT_VDSO_AUXV: i64 = 0x97;
const EXIT_VDSO_HEADER: i64 = 0x98;
const EXIT_VDSO_DATA: i64 = 0x99;
const EXIT_VDSO_CALL: i64 = 0x9a;
const EXIT_LIB_HEADER: i64 = 0x9b;
const EXIT_LIB_NEEDED: i64 = 0x9c;
const EXIT_LIB_VALUE: i64 = 0x9d;
const EXIT_LIB_COUNTER: i64 = 0x9e;
const EXIT_LIB_BYTES: i64 = 0x9f;
const EXIT_M9F_NEEDED: i64 = 0xa0;
const EXIT_M9F_SUM: i64 = 0xa1;
const EXIT_M9F_COUNTER: i64 = 0xa2;
const EXIT_M9F_LIB: i64 = 0xa3;

/// M9e: frozen load bias of the shared library (interpreter/kernel contract).
const LIB_BIAS: u64 = 0x0300_0000;
/// Exact SONAME / DT_NEEDED string (with the trailing NUL).
const LIB_PATH: &[u8] = b"/fat/m9e.so\0";
/// Highest plausible size of the shared library image (sanity bound only).
const LIB_IMAGE_MAX: u64 = 0x0004_0000;
const DT_NEEDED: u64 = 1;
const DT_STRTAB: u64 = 5;
const M9E_VALUE: u64 = 0x4D39_4501_0000_0001;
const M9E_COUNTER_VALUE: u64 = 0x1122_3344_5566_7788;
const M9E_LIB_BYTES: &[u8; 8] = b"M9E-LIB!";

/// M9f: frozen load bias of library A (`/fat/m9f-a.so`).
const M9F_A_BIAS: u64 = 0x0380_0000;
/// M9f: frozen load bias of library B (`/fat/m9f-b.so`).
const M9F_B_BIAS: u64 = 0x0400_0000;
/// M9f: exact SONAME / DT_NEEDED strings (with the trailing NUL).
const M9F_A_PATH: &[u8] = b"/fat/m9f-a.so\0";
const M9F_B_PATH: &[u8] = b"/fat/m9f-b.so\0";
/// M9f: expected results of two `m9f_sum(20, 22)` calls and of the counter.
const M9F_SUM_EXPECTED: u64 = 42;
const M9F_COUNTER_EXPECTED: u64 = 2;
const DT_SONAME: u64 = 14;

// M9e: symbols exported by `/fat/m9e.so`. The interpreter resolves these as
// R_X86_64_GLOB_DAT relocations against the library's dynamic symbol table.
unsafe extern "C" {
    fn m9e_value() -> u64;
    static M9E_COUNTER: u64;
    static M9E_BYTES_PTR: *const u8;
}

// M9f: symbols exported by `/fat/m9f-a.so` (A itself calls B's `m9f_add`).
unsafe extern "C" {
    fn m9f_sum(left: u64, right: u64) -> u64;
    static M9F_COUNTER: u64;
}

// ---------------------------------------------------------------------------
// Raw Linux system calls.
// ---------------------------------------------------------------------------

fn syscall3(nr: u64, arg1: u64, arg2: u64, arg3: u64) -> i64 {
    let result: i64;
    unsafe {
        core::arch::asm!(
            "syscall",
            inlateout("rax") nr as i64 => result,
            in("rdi") arg1,
            in("rsi") arg2,
            in("rdx") arg3,
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack),
        );
    }
    result
}

fn write_fd(fd: i64, buffer: u64, length: u64) -> i64 {
    syscall3(NR_WRITE, fd as u64, buffer, length)
}

fn exit_group(status: i64) -> ! {
    syscall3(NR_EXIT_GROUP, status as u64, 0, 0);
    loop {
        core::hint::spin_loop();
    }
}

// ---------------------------------------------------------------------------
// Console output and failure reporting.
// ---------------------------------------------------------------------------

fn write_line(bytes: &[u8]) {
    for fd in [1i64, 2, 0] {
        let mut offset = 0usize;
        while offset < bytes.len() {
            let result = write_fd(
                fd,
                bytes[offset..].as_ptr() as u64,
                (bytes.len() - offset) as u64,
            );
            if result <= 0 {
                break;
            }
            offset += result as usize;
        }
        if offset == bytes.len() {
            return;
        }
    }
    exit_group(EXIT_WRITE);
}

fn fail(reason: &[u8], status: i64) -> ! {
    write_line(b"[CaelumLinux] FAIL m9d ");
    write_line(reason);
    write_line(b"\n");
    exit_group(status)
}

fn marker() {
    write_line(b"[CaelumLinux] M9d dynamic OK\n");
}

// ---------------------------------------------------------------------------
// Relocation witnesses: `DYN_POINTER` (a data pointer) and `DYN_FN` (a
// function pointer) are initialised with link-time addresses. In a PIE image
// those initial values live in `.data.rel.ro` and require R_X86_64_RELATIVE
// relocations; if the interpreter did not run (or did not apply the relocations)
// the raw values remain the link-time offsets.
// ---------------------------------------------------------------------------

static DYN_VALUE: u64 = 0xC0DE_5EED_1234_5678;
static DYN_POINTER: &u64 = &DYN_VALUE;

fn dyn_dummy() {}

static DYN_FN: fn() = dyn_dummy;

// Main program entry symbol, needed to compare against `AT_ENTRY`.
unsafe extern "C" {
    fn _start();
}

// ---------------------------------------------------------------------------
// Little-endian reads from user addresses.
// ---------------------------------------------------------------------------

fn read_u8(base: *const u8, offset: usize) -> u8 {
    unsafe { core::ptr::read_volatile(base.add(offset)) }
}

fn read_u16(base: *const u8, offset: usize) -> u16 {
    unsafe { core::ptr::read_volatile(base.add(offset) as *const u16) }
}

fn read_u32(base: *const u8, offset: usize) -> u32 {
    unsafe { core::ptr::read_volatile(base.add(offset) as *const u32) }
}

fn read_u64(base: *const u8, offset: usize) -> u64 {
    unsafe { core::ptr::read_volatile(base.add(offset) as *const u64) }
}

#[derive(Clone, Copy)]
struct Load {
    vaddr: u64,
    offset: u64,
    memsz: u64,
}

impl Load {
    const EMPTY: Load = Load {
        vaddr: 0,
        offset: 0,
        memsz: 0,
    };
}

fn load_start(load: Load) -> u64 {
    MAIN_BIAS.wrapping_add(load.vaddr)
}

fn load_end(load: Load) -> u64 {
    load_start(load).wrapping_add(load.memsz)
}

// ---------------------------------------------------------------------------
// M9d2: vDSO data-page snapshot and Linux64 `Timespec`.
// ---------------------------------------------------------------------------

/// Linux64 `struct timespec` written by `__vdso_clock_gettime`.
#[repr(C)]
struct Timespec {
    seconds: i64,
    nanoseconds: i64,
}

impl Timespec {
    const fn zeroed() -> Self {
        Self {
            seconds: 0,
            nanoseconds: 0,
        }
    }
}

/// Sequence-locked snapshot of the vDSO data page.
struct VdsoSnapshot {
    magic: u32,
    version: u32,
    hz: u32,
    ticks: u64,
}

/// Reads the kernel-maintained vDSO data page with the `seq` retry protocol:
/// a snapshot is only accepted when `seq` is even and unchanged across the
/// read, so a torn `(ticks, hz)` pair is never observed.
fn read_vdso_snapshot() -> Option<VdsoSnapshot> {
    let base = VDSO_DATA as *const u8;
    let mut attempts = 0usize;
    while attempts < 64 {
        let first = read_u32(base, VDSO_SEQ_OFFSET);
        if first & 1 != 0 {
            attempts += 1;
            continue;
        }
        let magic = read_u32(base, VDSO_MAGIC_OFFSET);
        let version = read_u32(base, VDSO_VERSION_OFFSET);
        let hz = read_u32(base, VDSO_HZ_OFFSET);
        let ticks = read_u64(base, VDSO_TICKS_OFFSET);
        let second = read_u32(base, VDSO_SEQ_OFFSET);
        if first == second {
            return Some(VdsoSnapshot {
                magic,
                version,
                hz,
                ticks,
            });
        }
        attempts += 1;
    }
    None
}

fn timespec_is_sane(value: &Timespec) -> bool {
    value.seconds >= 0 && value.nanoseconds >= 0 && value.nanoseconds < NANOS_PER_SECOND
}

fn timespec_cmp(left: &Timespec, right: &Timespec) -> core::cmp::Ordering {
    match left.seconds.cmp(&right.seconds) {
        core::cmp::Ordering::Equal => left.nanoseconds.cmp(&right.nanoseconds),
        other => other,
    }
}

// ---------------------------------------------------------------------------
// Main body.
// ---------------------------------------------------------------------------

extern "C" fn dyn_entry(initial_rsp: usize) -> ! {
    let stack = initial_rsp as *const u8;

    // 1. Parse and validate the kernel-written auxv. The order is frozen by the
    //    M9d1 contract but this program matches by tag.
    let mut at_phdr = 0u64;
    let mut at_phent = 0u64;
    let mut at_phnum = 0u64;
    let mut at_pagesz = 0u64;
    let mut at_base = 0u64;
    let mut at_entry = 0u64;
    let mut at_sysinfo = 0u64;
    let mut caelum_channel = 0u64;
    let mut caelum_netns = 0u64;
    let mut caelum_role = 0u64;
    let mut saw_phdr = false;
    let mut saw_phent = false;
    let mut saw_phnum = false;
    let mut saw_pagesz = false;
    let mut saw_base = false;
    let mut saw_entry = false;
    let mut saw_sysinfo = false;
    let mut saw_channel = false;
    let mut saw_netns = false;
    let mut saw_role = false;
    let mut index = 3usize;
    let mut pairs = 0usize;
    while pairs < 64 {
        let kind = read_u64(stack, index * 8);
        if kind == AT_NULL {
            break;
        }
        let value = read_u64(stack, (index + 1) * 8);
        match kind {
            AT_PHDR => {
                at_phdr = value;
                saw_phdr = true;
            }
            AT_PHENT => {
                at_phent = value;
                saw_phent = true;
            }
            AT_PHNUM => {
                at_phnum = value;
                saw_phnum = true;
            }
            AT_PAGESZ => {
                at_pagesz = value;
                saw_pagesz = true;
            }
            AT_BASE => {
                at_base = value;
                saw_base = true;
            }
            AT_ENTRY => {
                at_entry = value;
                saw_entry = true;
            }
            AT_SYSINFO_EHDR => {
                at_sysinfo = value;
                saw_sysinfo = true;
            }
            AT_CAELUM_CHANNEL => {
                caelum_channel = value;
                saw_channel = true;
            }
            AT_CAELUM_NETNS => {
                caelum_netns = value;
                saw_netns = true;
            }
            AT_CAELUM_ROLE => {
                caelum_role = value;
                saw_role = true;
            }
            _ => {}
        }
        index += 2;
        pairs += 1;
    }
    if !(saw_phdr
        && saw_phent
        && saw_phnum
        && saw_pagesz
        && saw_base
        && saw_entry
        && saw_sysinfo
        && saw_channel
        && saw_netns
        && saw_role)
    {
        fail(b"auxv-missing", EXIT_AUXV);
    }
    if at_pagesz != PAGE_BYTES || at_phent != PHDR_BYTES || at_phnum == 0 {
        fail(b"auxv-shape", EXIT_AUXV);
    }
    // The interpreter is a fixed ET_EXEC image, so the frozen AT_BASE is 0.
    if at_base != 0 {
        fail(b"at-base", EXIT_AUXV);
    }
    if caelum_channel != 0 || caelum_netns != 0 || caelum_role != 0 {
        fail(b"caelum-auxv", EXIT_AUXV);
    }
    // M9d2: the kernel must advertise the mapped vDSO image (frozen base).
    if at_sysinfo != VDSO_BASE {
        fail(b"vdso-auxv", EXIT_VDSO_AUXV);
    }

    // 2. Validate this image's ELF header at the frozen bias and cross-check it
    //    against the auxv.
    let elf = MAIN_BIAS as *const u8;
    if read_u8(elf, 0) != 0x7f
        || read_u8(elf, 1) != b'E'
        || read_u8(elf, 2) != b'L'
        || read_u8(elf, 3) != b'F'
    {
        fail(b"ehdr-magic", EXIT_HEADER);
    }
    if read_u8(elf, 4) != 2 || read_u8(elf, 5) != 1 {
        fail(b"ehdr-class", EXIT_HEADER);
    }
    if read_u16(elf, 16) != ET_DYN {
        fail(b"ehdr-type", EXIT_HEADER);
    }
    if read_u16(elf, 18) != EM_X86_64 {
        fail(b"ehdr-machine", EXIT_HEADER);
    }
    let e_entry = read_u64(elf, 24);
    let e_phoff = read_u64(elf, 32);
    let e_phentsize = read_u16(elf, 54) as u64;
    let e_phnum = read_u16(elf, 56) as u64;
    if e_phentsize != at_phent || e_phnum != at_phnum {
        fail(b"ehdr-phdr", EXIT_HEADER);
    }
    if MAIN_BIAS.wrapping_add(e_phoff) != at_phdr {
        fail(b"ehdr-phoff", EXIT_HEADER);
    }
    if MAIN_BIAS.wrapping_add(e_entry) != at_entry {
        fail(b"ehdr-entry", EXIT_HEADER);
    }

    // 3. Walk the program headers: collect PT_LOADs, verify the phdr page range
    //    is covered by a PT_LOAD, check PT_PHDR/PT_DYNAMIC exist and read the
    //    exact PT_INTERP string the kernel used.
    let phdr_base = at_phdr as *const u8;
    let mut load_start_list = [Load::EMPTY; MAX_LOADS];
    let mut load_count = 0usize;
    let mut saw_phdr_segment = false;
    let mut saw_dynamic = false;
    let mut interp_offset = 0u64;
    let mut interp_size = 0u64;
    let mut saw_interp = false;
    let mut saw_writable = false;
    let mut segment = 0u64;
    while segment < at_phnum {
        let base = segment.wrapping_mul(PHDR_BYTES) as usize;
        let p_type = read_u32(phdr_base, base);
        let p_flags = read_u32(phdr_base, base + 4);
        let p_offset = read_u64(phdr_base, base + 8);
        let p_vaddr = read_u64(phdr_base, base + 16);
        let p_filesz = read_u64(phdr_base, base + 32);
        let p_memsz = read_u64(phdr_base, base + 40);
        match p_type {
            PT_LOAD => {
                // The relocation witnesses (`DYN_POINTER` / `DYN_FN`) live in a
                // writable segment; a PIE image must always have one, otherwise
                // the interpreter could not apply the RELATIVE relocations.
                if p_flags & 0x2 != 0 {
                    saw_writable = true;
                }
                if load_count < MAX_LOADS {
                    load_start_list[load_count] = Load {
                        vaddr: p_vaddr,
                        offset: p_offset,
                        memsz: p_memsz,
                    };
                    load_count += 1;
                }
            }
            PT_PHDR => saw_phdr_segment = true,
            PT_DYNAMIC => saw_dynamic = true,
            PT_INTERP => {
                interp_offset = p_vaddr;
                interp_size = p_filesz;
                saw_interp = true;
            }
            _ => {}
        }
        segment += 1;
    }
    if !saw_phdr_segment || !saw_dynamic || !saw_interp {
        fail(b"phdr-types", EXIT_PROGRAM_HEADERS);
    }
    if load_count == 0 || !saw_writable {
        fail(b"no-load", EXIT_PROGRAM_HEADERS);
    }

    let phdr_end = at_phdr.wrapping_add(at_phnum.wrapping_mul(at_phent));
    let mut headers_covered = false;
    let mut index = 0usize;
    while index < load_count {
        let load = load_start_list[index];
        if load.vaddr % PAGE_BYTES != load.offset % PAGE_BYTES {
            fail(b"load-congruence", EXIT_PROGRAM_HEADERS);
        }
        if at_phdr >= load_start(load) && phdr_end <= load_end(load) {
            headers_covered = true;
        }
        index += 1;
    }
    if !headers_covered {
        fail(b"phdr-uncovered", EXIT_PROGRAM_HEADERS);
    }

    let interp_address = MAIN_BIAS.wrapping_add(interp_offset);
    if interp_size != INTERP_PATH.len() as u64 {
        fail(b"interp-length", EXIT_INTERP_STRING);
    }
    let mut byte = 0usize;
    while byte < INTERP_PATH.len() {
        if read_u8(interp_address as *const u8, byte) != INTERP_PATH[byte] {
            fail(b"interp-string", EXIT_INTERP_STRING);
        }
        byte += 1;
    }

    // 4. AT_ENTRY must be this image's `_start` (proves the interpreter jumped
    //    to the entry the kernel computed, not to some other address).
    let start: unsafe extern "C" fn() = _start;
    let start_address = start as usize as u64;
    if at_entry != start_address {
        fail(b"entry-mismatch", EXIT_ENTRY);
    }

    // 5. The interpreter must have applied the RELATIVE relocations: both
    //    witnesses now hold runtime (bias-relative) addresses.
    let pointer = unsafe { core::ptr::read_volatile(core::ptr::addr_of!(DYN_POINTER)) };
    let pointer_address = pointer as *const u64 as usize as u64;
    let value_address = core::ptr::addr_of!(DYN_VALUE) as usize as u64;
    if pointer_address != value_address {
        fail(b"reloc-pointer", EXIT_RELOCATION);
    }
    let function = unsafe { core::ptr::read_volatile(core::ptr::addr_of!(DYN_FN)) };
    let function_address = function as usize as u64;
    let expected_function: fn() = dyn_dummy;
    if function_address != expected_function as usize as u64 {
        fail(b"reloc-function", EXIT_RELOCATION);
    }
    if pointer_address < MAIN_BIAS || value_address < MAIN_BIAS {
        fail(b"reloc-bias", EXIT_RELOCATION);
    }

    marker();

    // 6. M9d2: the vDSO image advertised through AT_SYSINFO_EHDR must be a real
    //    ET_EXEC ELF whose header points at the frozen entry, and the entry must
    //    behave as the frozen `__vdso_clock_gettime`.
    let vdso = at_sysinfo as *const u8;
    if read_u8(vdso, 0) != 0x7f
        || read_u8(vdso, 1) != b'E'
        || read_u8(vdso, 2) != b'L'
        || read_u8(vdso, 3) != b'F'
    {
        fail(b"vdso-magic", EXIT_VDSO_HEADER);
    }
    if read_u8(vdso, 4) != 2 || read_u8(vdso, 5) != 1 {
        fail(b"vdso-class", EXIT_VDSO_HEADER);
    }
    if read_u16(vdso, 16) != ET_EXEC {
        fail(b"vdso-type", EXIT_VDSO_HEADER);
    }
    if read_u16(vdso, 18) != EM_X86_64 {
        fail(b"vdso-machine", EXIT_VDSO_HEADER);
    }
    let vdso_entry = read_u64(vdso, 24);
    if vdso_entry != VDSO_ENTRY {
        fail(b"vdso-entry", EXIT_VDSO_HEADER);
    }

    // Data page: magic/version and one consistent, even-`seq` snapshot.
    let snapshot = match read_vdso_snapshot() {
        Some(snapshot) => snapshot,
        None => fail(b"vdso-seq", EXIT_VDSO_DATA),
    };
    if snapshot.magic != VDSO_MAGIC || snapshot.version != VDSO_VERSION || snapshot.hz == 0 {
        fail(b"vdso-data", EXIT_VDSO_DATA);
    }
    let snapshot_timespec = Timespec {
        seconds: (snapshot.ticks / snapshot.hz as u64) as i64,
        nanoseconds: ((snapshot.ticks % snapshot.hz as u64) * NANOS_PER_SECOND as u64
            / snapshot.hz as u64) as i64,
    };

    // Call the entry directly: no symbol-table parsing, `e_entry` is the frozen
    // `__vdso_clock_gettime`.
    let vdso_clock_gettime: unsafe extern "C" fn(u64, *mut Timespec) -> i64 =
        unsafe { core::mem::transmute(vdso_entry) };

    let mut monotonic = Timespec::zeroed();
    if unsafe { vdso_clock_gettime(CLOCK_MONOTONIC, &mut monotonic) } != 0 {
        fail(b"vdso-monotonic", EXIT_VDSO_CALL);
    }
    if !timespec_is_sane(&monotonic) {
        fail(b"vdso-monotonic-value", EXIT_VDSO_CALL);
    }
    if timespec_cmp(&monotonic, &snapshot_timespec) == core::cmp::Ordering::Less {
        fail(b"vdso-monotonic-behind", EXIT_VDSO_CALL);
    }

    let mut boottime = Timespec::zeroed();
    if unsafe { vdso_clock_gettime(CLOCK_BOOTTIME, &mut boottime) } != 0 {
        fail(b"vdso-boottime", EXIT_VDSO_CALL);
    }
    if !timespec_is_sane(&boottime) {
        fail(b"vdso-boottime-value", EXIT_VDSO_CALL);
    }

    // REALTIME is deliberately not provided by this slice: -ENOSYS, `tp`
    // untouched.
    let mut realtime = Timespec::zeroed();
    if unsafe { vdso_clock_gettime(CLOCK_REALTIME, &mut realtime) } != VDSO_ENOSYS {
        fail(b"vdso-realtime", EXIT_VDSO_CALL);
    }
    if !timespec_is_sane(&realtime) || realtime.seconds != 0 || realtime.nanoseconds != 0 {
        fail(b"vdso-realtime-side-effect", EXIT_VDSO_CALL);
    }

    // A second MONOTONIC call must not go backwards.
    let mut monotonic_second = Timespec::zeroed();
    if unsafe { vdso_clock_gettime(CLOCK_MONOTONIC, &mut monotonic_second) } != 0 {
        fail(b"vdso-monotonic-second", EXIT_VDSO_CALL);
    }
    if timespec_cmp(&monotonic_second, &monotonic) == core::cmp::Ordering::Less {
        fail(b"vdso-monotonic-regress", EXIT_VDSO_CALL);
    }

    write_line(b"[CaelumLinux] M9d vdso OK\n");
    m9e_shared(at_phdr, at_phnum)
}

/// Dynamic-section facts needed by the M9e/M9f checks.
#[derive(Clone, Copy)]
struct DynamicNames {
    strtab: u64,
    needed: [u64; 4],
    needed_count: u64,
    soname: u64,
}

impl DynamicNames {
    const EMPTY: DynamicNames = DynamicNames {
        strtab: 0,
        needed: [0; 4],
        needed_count: 0,
        soname: 0,
    };
}

/// Scans a dynamic array already mapped at `dynamic_addr` and returns
/// STRTAB / the first four NEEDED offsets / SONAME (values are image-relative).
fn read_dynamic_names(dynamic_addr: u64, dynamic_bytes: u64) -> DynamicNames {
    let mut names = DynamicNames::EMPTY;
    let dynamic = dynamic_addr as *const u8;
    let entries = dynamic_bytes / 16;
    let mut index = 0u64;
    while index < entries && index < 256 {
        let offset = (index * 16) as usize;
        let tag = read_u64(dynamic, offset);
        let value = read_u64(dynamic, offset + 8);
        match tag {
            DT_NEEDED => {
                if names.needed_count < 4 {
                    names.needed[names.needed_count as usize] = value;
                }
                names.needed_count += 1;
            }
            DT_STRTAB => names.strtab = value,
            DT_SONAME => names.soname = value,
            _ => {}
        }
        index += 1;
    }
    names
}

/// True when the NUL-terminated string at `address` equals `wanted` exactly.
fn string_equals(address: u64, wanted: &[u8]) -> bool {
    let mut index = 0usize;
    while index < wanted.len() {
        if read_u8(address as *const u8, index) != wanted[index] {
            return false;
        }
        index += 1;
    }
    true
}

/// True when `base` points at an x86-64 ELF64 ET_DYN header.
fn image_header_ok(base: u64) -> bool {
    let elf = base as *const u8;
    read_u8(elf, 0) == 0x7f
        && read_u8(elf, 1) == b'E'
        && read_u8(elf, 2) == b'L'
        && read_u8(elf, 3) == b'F'
        && read_u8(elf, 4) == 2
        && read_u8(elf, 5) == 1
        && read_u16(elf, 16) == ET_DYN
        && read_u16(elf, 18) == EM_X86_64
}

/// Walks the program headers of an ET_DYN image mapped at `bias` and returns
/// `(dynamic_addr, dynamic_bytes, has_interp)`.
fn image_dynamic(bias: u64, phnum: u64, phent: u64) -> (u64, u64, bool) {
    let elf = bias as *const u8;
    let phdr = bias.wrapping_add(read_u64(elf, 32));
    let mut dynamic_addr = 0u64;
    let mut dynamic_bytes = 0u64;
    let mut has_interp = false;
    let mut index = 0u64;
    while index < phnum && index < 64 {
        let entry = phdr.wrapping_add(index.wrapping_mul(phent)) as *const u8;
        match read_u32(entry, 0) {
            PT_DYNAMIC => {
                dynamic_addr = bias.wrapping_add(read_u64(entry, 16));
                dynamic_bytes = read_u64(entry, 40);
            }
            PT_INTERP => has_interp = true,
            _ => {}
        }
        index += 1;
    }
    (dynamic_addr, dynamic_bytes, has_interp)
}

/// M9e: verifies the shared-library wiring end to end and prints the frozen
/// marker. Everything here is read-only inspection plus one exported function
/// call; the relocation work itself was done by the interpreter before entry.
fn m9e_shared(phdr_addr: u64, phnum: u64) -> ! {
    // 1. This program's own PT_DYNAMIC must name exactly the two frozen
    //    dependencies (m9e + m9f-a), each exactly once. DT_* addresses in an
    //    ET_DYN image are image-relative, so add the main bias before use.
    let phdr = phdr_addr as *const u8;
    let mut dynamic_addr = 0u64;
    let mut dynamic_bytes = 0u64;
    let mut saw_dynamic = false;
    let mut index = 0u64;
    while index < phnum {
        let entry = (index * PHDR_BYTES) as usize;
        if read_u32(phdr, entry) == PT_DYNAMIC {
            dynamic_addr = MAIN_BIAS.wrapping_add(read_u64(phdr, entry + 16));
            dynamic_bytes = read_u64(phdr, entry + 40);
            saw_dynamic = true;
            break;
        }
        index += 1;
    }
    if !saw_dynamic || dynamic_bytes < 16 || dynamic_bytes > 0x1000 {
        fail(b"lib-dynamic", EXIT_LIB_HEADER);
    }
    let names = read_dynamic_names(dynamic_addr, dynamic_bytes);
    if names.needed_count != 2 || names.strtab == 0 {
        fail(b"lib-needed-count", EXIT_LIB_NEEDED);
    }
    let strtab = MAIN_BIAS.wrapping_add(names.strtab);
    let mut m9e_seen = 0u32;
    let mut m9f_seen = 0u32;
    let mut index = 0usize;
    while index < (names.needed_count as usize).min(4) {
        let name = strtab.wrapping_add(names.needed[index]);
        if string_equals(name, LIB_PATH) {
            m9e_seen += 1;
        }
        if string_equals(name, M9F_A_PATH) {
            m9f_seen += 1;
        }
        index += 1;
    }
    if m9e_seen != 1 {
        fail(b"lib-needed-name", EXIT_LIB_NEEDED);
    }
    if m9f_seen != 1 {
        fail(b"lib-needed-m9f", EXIT_M9F_NEEDED);
    }

    // 2. The library must be mapped at the frozen bias as a real ET_DYN image.
    let lib = LIB_BIAS as *const u8;
    if read_u8(lib, 0) != 0x7f
        || read_u8(lib, 1) != b'E'
        || read_u8(lib, 2) != b'L'
        || read_u8(lib, 3) != b'F'
        || read_u8(lib, 4) != 2
        || read_u8(lib, 5) != 1
    {
        fail(b"lib-ehdr", EXIT_LIB_HEADER);
    }
    if read_u16(lib, 16) != ET_DYN || read_u16(lib, 18) != EM_X86_64 {
        fail(b"lib-ehdr-shape", EXIT_LIB_HEADER);
    }
    if read_u16(lib, 54) != PHDR_BYTES as u16 || read_u16(lib, 56) == 0 {
        fail(b"lib-ehdr-phdr", EXIT_LIB_HEADER);
    }

    // 3. The interpreter applied the library's own RELATIVE relocation (the
    //    exported pointer must resolve inside the loaded library image) and the
    //    GLOB_DAT relocations for the frozen values.
    let bytes_pointer = unsafe { core::ptr::read_volatile(core::ptr::addr_of!(M9E_BYTES_PTR)) };
    let bytes_address = bytes_pointer as u64;
    if bytes_address < LIB_BIAS || bytes_address >= LIB_BIAS.wrapping_add(LIB_IMAGE_MAX) {
        fail(b"lib-pointer", EXIT_LIB_BYTES);
    }
    let mut index = 0usize;
    while index < M9E_LIB_BYTES.len() {
        if read_u8(bytes_pointer, index) != M9E_LIB_BYTES[index] {
            fail(b"lib-bytes", EXIT_LIB_BYTES);
        }
        index += 1;
    }
    let value = unsafe { m9e_value() };
    if value != M9E_VALUE {
        fail(b"lib-value", EXIT_LIB_VALUE);
    }
    let counter = unsafe { core::ptr::read_volatile(core::ptr::addr_of!(M9E_COUNTER)) };
    if counter != M9E_COUNTER_VALUE {
        fail(b"lib-counter", EXIT_LIB_COUNTER);
    }

    write_line(b"[CaelumLinux] M9e shared OK\n");
    m9f_shared()
}

/// M9f: verifies the two-level shared-library chain and the interpreter's
/// cross-library GLOB_DAT resolution results.
fn m9f_shared() -> ! {
    // 1. Library A must be mapped at its frozen bias, depend on B and expose
    //    the frozen SONAME.
    if !image_header_ok(M9F_A_BIAS) {
        fail(b"m9f-a-ehdr", EXIT_M9F_LIB);
    }
    let a = M9F_A_BIAS as *const u8;
    let a_phent = read_u16(a, 54) as u64;
    let a_phnum = read_u16(a, 56) as u64;
    if a_phent != PHDR_BYTES || a_phnum == 0 || a_phnum > 64 {
        fail(b"m9f-a-phdr", EXIT_M9F_LIB);
    }
    let (a_dynamic, a_bytes, a_interp) = image_dynamic(M9F_A_BIAS, a_phnum, a_phent);
    if a_interp {
        fail(b"m9f-a-interp", EXIT_M9F_LIB);
    }
    if a_dynamic == 0 || a_bytes < 16 {
        fail(b"m9f-a-dynamic", EXIT_M9F_LIB);
    }
    let a_names = read_dynamic_names(a_dynamic, a_bytes);
    if a_names.needed_count != 1 || a_names.strtab == 0 {
        fail(b"m9f-a-needed-count", EXIT_M9F_LIB);
    }
    let a_strtab = M9F_A_BIAS.wrapping_add(a_names.strtab);
    if !string_equals(a_strtab.wrapping_add(a_names.needed[0]), M9F_B_PATH) {
        fail(b"m9f-a-needed-name", EXIT_M9F_LIB);
    }
    if !string_equals(a_strtab.wrapping_add(a_names.soname), M9F_A_PATH) {
        fail(b"m9f-a-soname", EXIT_M9F_LIB);
    }

    // 2. Library B must be mapped at its frozen bias with no dependencies.
    if !image_header_ok(M9F_B_BIAS) {
        fail(b"m9f-b-ehdr", EXIT_M9F_LIB);
    }
    let b = M9F_B_BIAS as *const u8;
    let b_phent = read_u16(b, 54) as u64;
    let b_phnum = read_u16(b, 56) as u64;
    if b_phent != PHDR_BYTES || b_phnum == 0 || b_phnum > 64 {
        fail(b"m9f-b-phdr", EXIT_M9F_LIB);
    }
    let (b_dynamic, b_bytes, b_interp) = image_dynamic(M9F_B_BIAS, b_phnum, b_phent);
    if b_interp {
        fail(b"m9f-b-interp", EXIT_M9F_LIB);
    }
    if b_dynamic == 0 || b_bytes < 16 {
        fail(b"m9f-b-dynamic", EXIT_M9F_LIB);
    }
    let b_names = read_dynamic_names(b_dynamic, b_bytes);
    if b_names.needed_count != 0 {
        fail(b"m9f-b-needed", EXIT_M9F_LIB);
    }

    // 3. Cross-library calls: the interpreter must have resolved A's call into
    //    B (GLOB_DAT) and the main program's call into A. Both calls run twice.
    let first = unsafe { m9f_sum(20, 22) };
    if first != M9F_SUM_EXPECTED {
        fail(b"m9f-sum-first", EXIT_M9F_SUM);
    }
    let second = unsafe { m9f_sum(20, 22) };
    if second != M9F_SUM_EXPECTED {
        fail(b"m9f-sum-second", EXIT_M9F_SUM);
    }
    let counter = unsafe { core::ptr::read_volatile(core::ptr::addr_of!(M9F_COUNTER)) };
    if counter != M9F_COUNTER_EXPECTED {
        fail(b"m9f-counter", EXIT_M9F_COUNTER);
    }

    write_line(b"[CaelumLinux] M9f shared OK\n");
    exit_group(0)
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    write_line(b"[CaelumLinux] FAIL m9d panic\n");
    exit_group(0x7e)
}
