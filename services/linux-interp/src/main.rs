//! CaelumOS M9d1 custom `PT_INTERP` interpreter.
//!
//! This program is the interpreter named by the dynamic main program's
//! `PT_INTERP` string (`/fat/ldcaelum.so`). The kernel loads both images and
//! jumps to *this* program's `_start`, with `rsp` pointing at the Linux initial
//! stack image. The interpreter:
//!
//! 1. parses `argc` / `argv` / `envp` / auxv from the initial stack,
//! 2. takes the main program's program headers from `AT_PHDR` and recovers its
//!    fixed load bias (`0x0200_0000`) from `PT_PHDR`,
//! 3. finds `PT_DYNAMIC`, reads `DT_RELA` / `DT_RELASZ` / `DT_RELAENT`,
//! 4. applies every `R_X86_64_RELATIVE` relocation in user space
//!    (`*(u64 *)(r_offset + bias) = r_addend + bias`) and rejects any other
//!    relocation kind (this main program has no dynamic symbols),
//! 5. prints the exact marker `[CaelumDyn] interp OK`,
//! 6. jumps to `AT_ENTRY` with the original `rsp`, so the main program still
//!    sees the initial stack image.
//!
//! It is a static ET_EXEC image linked at `0x4000_0000`; `AT_BASE` is therefore
//! zero (fixed ET_EXEC load bias), and it never relocates itself.
//!
//! Diagnostics are plain serial writes on the console descriptors; any failure
//! prints a `[CaelumDyn] FAIL ...` line and exits with a non-zero status.

#![no_std]
#![no_main]

use core::arch::{asm, global_asm};
use core::panic::PanicInfo;

// ---------------------------------------------------------------------------
// ELF entry: keep the initial stack pointer, then run the Rust body.
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
    entry = sym interp_entry,
);

// Linux x86-64 system call numbers used here.
const NR_WRITE: u64 = 1;
const NR_EXIT_GROUP: u64 = 231;

// Auxiliary vector types (Linux x86-64).
const AT_NULL: u64 = 0;
const AT_PHDR: u64 = 3;
const AT_PHENT: u64 = 4;
const AT_PHNUM: u64 = 5;
const AT_BASE: u64 = 7;
const AT_ENTRY: u64 = 9;
const AT_PAGESZ: u64 = 6;
const AT_CAELUM_CHANNEL: u64 = 0xCAE1_0001;
const AT_CAELUM_NETNS: u64 = 0xCAE1_0002;
const AT_CAELUM_ROLE: u64 = 0xCAE1_0003;

// ELF constants.
const PT_LOAD: u32 = 1;
const PT_DYNAMIC: u32 = 2;
const PT_INTERP: u32 = 3;
const PT_PHDR: u32 = 6;
const ET_DYN: u16 = 3;
const EM_X86_64: u16 = 62;
const EHDR_BYTES: u64 = 64;
const PHDR_BYTES: u64 = 56;
const PAGE_BYTES: u64 = 4096;

// Dynamic tags / relocation kinds.
const DT_NULL: i64 = 0;
const DT_RELA: i64 = 7;
const DT_RELASZ: i64 = 8;
const DT_RELAENT: i64 = 9;
const DT_REL: i64 = 17;
const R_X86_64_NONE: u32 = 0;
const R_X86_64_64: u32 = 1;
const R_X86_64_RELATIVE: u32 = 8;
const RELA_BYTES: u64 = 24;

/// Fixed load bias the kernel uses for the ET_DYN main program (M9d1 contract).
const MAIN_BIAS: u64 = 0x0200_0000;

/// Exit statuses: one distinct value per failure class.
const EXIT_AUXV: i64 = 0x81;
const EXIT_HEADER: i64 = 0x82;
const EXIT_PROGRAM_HEADERS: i64 = 0x83;
const EXIT_DYNAMIC: i64 = 0x84;
const EXIT_RELA: i64 = 0x85;
const EXIT_RELOC: i64 = 0x86;
const EXIT_WRITE: i64 = 0x87;
const EXIT_NEEDED: i64 = 0x88;
const EXIT_LIB_HEADER: i64 = 0x89;
const EXIT_LIB_DYNAMIC: i64 = 0x8a;
const EXIT_LIB_RELOC: i64 = 0x8b;
const EXIT_LIB_SYMBOL: i64 = 0x8c;
const EXIT_MAIN_RELOC: i64 = 0x8d;
const EXIT_LIB_A: i64 = 0x8e;
const EXIT_LIB_B: i64 = 0x8f;

/// M9e: frozen load bias of the shared library (kernel/interpreter contract).
const LIB_BIAS: u64 = 0x0300_0000;
/// M9f: frozen load biases of the second-level libraries.
const M9F_A_BIAS: u64 = 0x0380_0000;
const M9F_B_BIAS: u64 = 0x0400_0000;
/// Exact DT_NEEDED string the main program must carry (with trailing NUL).
const LIB_PATH: &[u8] = b"/fat/m9e.so\0";
/// M9f: exact paths / SONAMEs of the two additional shared libraries.
const M9F_A_PATH: &[u8] = b"/fat/m9f-a.so\0";
const M9F_B_PATH: &[u8] = b"/fat/m9f-b.so\0";
const DT_NEEDED: i64 = 1;
const DT_HASH: i64 = 4;
const DT_STRTAB: i64 = 5;
const DT_SYMTAB: i64 = 6;
const DT_SYMENT: i64 = 11;
const DT_SONAME: i64 = 14;
const SYM_BYTES: u64 = 24;
const R_X86_64_GLOB_DAT: u32 = 6;
const R_X86_64_JUMP_SLOT: u32 = 7;
const MAX_LIB_SYMBOLS: u64 = 4096;

/// Highest number of PT_LOAD segments tracked for the writability/congruence
/// self-checks.
const MAX_LOADS: usize = 16;

// ---------------------------------------------------------------------------
// Raw Linux system calls.
// ---------------------------------------------------------------------------

fn syscall3(nr: u64, arg1: u64, arg2: u64, arg3: u64) -> i64 {
    let result: i64;
    unsafe {
        asm!(
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

/// Writes one line to the console, trying descriptors 1, 2 and 0 in order.
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

/// Prints `[CaelumDyn] FAIL <reason>` and exits with `status`.
fn fail(reason: &[u8], status: i64) -> ! {
    write_line(b"[CaelumDyn] FAIL ");
    write_line(reason);
    write_line(b"\n");
    exit_group(status)
}

#[inline(never)]
fn push_bytes(buffer: &mut [u8], length: &mut usize, bytes: &[u8]) {
    let mut index = 0usize;
    while index < bytes.len() && *length < buffer.len() {
        buffer[*length] = bytes[index];
        *length += 1;
        index += 1;
    }
}

fn push_decimal(buffer: &mut [u8], length: &mut usize, mut value: u64) {
    if value == 0 {
        push_bytes(buffer, length, b"0");
        return;
    }
    let mut digits = [0u8; 20];
    let mut count = 0usize;
    while value > 0 && count < digits.len() {
        digits[count] = b'0' + (value % 10) as u8;
        value /= 10;
        count += 1;
    }
    while count > 0 {
        count -= 1;
        push_bytes(buffer, length, &digits[count..count + 1]);
    }
}

fn marker(needed: u64, libs: u64, globdat: u64, relative: u64) {
    let mut buffer = [0u8; 128];
    let mut length = 0usize;
    push_bytes(&mut buffer, &mut length, b"[CaelumDyn] interp OK (needed=");
    push_decimal(&mut buffer, &mut length, needed);
    push_bytes(&mut buffer, &mut length, b",libs=");
    push_decimal(&mut buffer, &mut length, libs);
    push_bytes(&mut buffer, &mut length, b",globdat=");
    push_decimal(&mut buffer, &mut length, globdat);
    push_bytes(&mut buffer, &mut length, b",relative=");
    push_decimal(&mut buffer, &mut length, relative);
    push_bytes(&mut buffer, &mut length, b")\n");
    write_line(&buffer[..length]);
}

// ---------------------------------------------------------------------------
// Little-endian reads from arbitrary user addresses (all bounds come from the
// kernel-written auxv / program headers).
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

fn read_i64(base: *const u8, offset: usize) -> i64 {
    unsafe { core::ptr::read_volatile(base.add(offset) as *const i64) }
}

fn write_u64(address: u64, value: u64) {
    unsafe { core::ptr::write_volatile(address as *mut u64, value) }
}

/// One tracked PT_LOAD segment (`vaddr`, `offset`, `memsz`, `flags`).
#[derive(Clone, Copy)]
struct Load {
    vaddr: u64,
    offset: u64,
    memsz: u64,
    #[allow(dead_code)]
    flags: u32,
}

impl Load {
    const EMPTY: Load = Load {
        vaddr: 0,
        offset: 0,
        memsz: 0,
        flags: 0,
    };
}

/// Linear address range covered by a segment for one load bias.
fn load_start(bias: u64, load: Load) -> u64 {
    bias.wrapping_add(load.vaddr)
}

fn load_end(bias: u64, load: Load) -> u64 {
    load_start(bias, load).wrapping_add(load.memsz)
}

fn range_inside(start: u64, end: u64, outer_start: u64, outer_end: u64) -> bool {
    start >= outer_start && end <= outer_end
}

// ---------------------------------------------------------------------------
// Interpreter body.
// ---------------------------------------------------------------------------

/// An already-mapped ET_DYN image plus the dynamic-section facts the
/// interpreter needs (M9e/M9f: main program, m9e, m9f-a and m9f-b).
#[derive(Clone, Copy)]
struct Image {
    bias: u64,
    phdr: u64,
    phnum: u64,
    dynamic: u64,
    dynamic_size: u64,
    rela: u64,
    rela_size: u64,
    rela_ent: u64,
    symtab: u64,
    strtab: u64,
    syment: u64,
    hash: u64,
    needed: [u64; 4],
    needed_count: u64,
    soname: u64,
    saw_rel: bool,
}

impl Image {
    const EMPTY: Image = Image {
        bias: 0,
        phdr: 0,
        phnum: 0,
        dynamic: 0,
        dynamic_size: 0,
        rela: 0,
        rela_size: 0,
        rela_ent: 0,
        symtab: 0,
        strtab: 0,
        syment: 0,
        hash: 0,
        needed: [0; 4],
        needed_count: 0,
        soname: 0,
        saw_rel: false,
    };

    fn symtab_addr(&self) -> u64 {
        self.bias.wrapping_add(self.symtab)
    }

    fn strtab_addr(&self) -> u64 {
        self.bias.wrapping_add(self.strtab)
    }

    fn symbol_count(&self) -> u64 {
        read_u32(self.bias.wrapping_add(self.hash) as *const u8, 4) as u64
    }
}

/// Parses an ET_DYN image mapped at `bias`: header, program headers (PT_DYNAMIC,
/// rejecting PT_INTERP) and the dynamic array.
fn parse_image(bias: u64, fail_code: i64) -> Image {
    let elf = bias as *const u8;
    if read_u32(elf, 0) != 0x464C_457F {
        fail(b"image-ehdr-magic", fail_code);
    }
    if read_u8(elf, 4) != 2 || read_u8(elf, 5) != 1 {
        fail(b"image-ehdr-class", fail_code);
    }
    if read_u16(elf, 16) != ET_DYN {
        fail(b"image-ehdr-type", fail_code);
    }
    if read_u16(elf, 18) != EM_X86_64 {
        fail(b"image-ehdr-machine", fail_code);
    }
    let phent = read_u16(elf, 54) as u64;
    let phnum = read_u16(elf, 56) as u64;
    if phent != PHDR_BYTES || phnum == 0 || phnum > 64 {
        fail(b"image-phdr", fail_code);
    }

    let mut image = Image::EMPTY;
    image.bias = bias;
    image.phdr = bias.wrapping_add(read_u64(elf, 32));
    image.phnum = phnum;
    let mut saw_dynamic = false;
    let mut index = 0u64;
    while index < phnum {
        let header = image.phdr.wrapping_add(index.wrapping_mul(PHDR_BYTES)) as *const u8;
        match read_u32(header, 0) {
            PT_DYNAMIC => {
                image.dynamic = bias.wrapping_add(read_u64(header, 16));
                image.dynamic_size = read_u64(header, 40);
                saw_dynamic = true;
            }
            PT_INTERP => fail(b"image-interp", fail_code),
            _ => {}
        }
        index += 1;
    }
    if !saw_dynamic || image.dynamic_size == 0 {
        fail(b"image-dynamic", fail_code);
    }

    let mut cursor = image.dynamic;
    let end = image.dynamic.wrapping_add(image.dynamic_size);
    while cursor.wrapping_add(16) <= end {
        let tag = read_i64(cursor as *const u8, 0);
        let value = read_u64(cursor as *const u8, 8);
        if tag == DT_NULL {
            break;
        }
        match tag {
            DT_RELA => image.rela = value,
            DT_RELASZ => image.rela_size = value,
            DT_RELAENT => image.rela_ent = value,
            DT_SYMTAB => image.symtab = value,
            DT_STRTAB => image.strtab = value,
            DT_SYMENT => image.syment = value,
            DT_HASH => image.hash = value,
            DT_SONAME => image.soname = value,
            DT_REL => image.saw_rel = true,
            DT_NEEDED => {
                if image.needed_count < 4 {
                    image.needed[image.needed_count as usize] = value;
                }
                image.needed_count += 1;
            }
            _ => {}
        }
        cursor = cursor.wrapping_add(16);
    }
    image
}

/// True when `address` falls inside a writable PT_LOAD of `image`.
fn image_writable(image: &Image, address: u64) -> bool {
    let mut index = 0u64;
    while index < image.phnum {
        let header = image.phdr.wrapping_add(index.wrapping_mul(PHDR_BYTES)) as *const u8;
        let kind = read_u32(header, 0);
        let flags = read_u32(header, 4);
        if kind == PT_LOAD && (flags & 0x2) != 0 {
            let start = image.bias.wrapping_add(read_u64(header, 16));
            let size = read_u64(header, 40);
            if address >= start && address < start.wrapping_add(size) {
                return true;
            }
        }
        index += 1;
    }
    false
}

/// Byte-wise comparison of two NUL-terminated names (bounded to 64 bytes).
fn names_equal(left: *const u8, right: *const u8) -> bool {
    let mut index = 0usize;
    while index < 64 {
        let a = read_u8(left, index);
        let b = read_u8(right, index);
        if a != b {
            return false;
        }
        if a == 0 {
            return true;
        }
        index += 1;
    }
    false
}

/// Looks a symbol name up in `image`'s dynamic symbol table. Defined symbols
/// resolve to `image.bias + st_value`; undefined symbols yield `None` so the
/// caller can continue with the frozen lookup order.
fn find_symbol(image: &Image, wanted: *const u8) -> Option<u64> {
    // The main program has no DT_HASH (it exports nothing); only libraries are
    // enumerable, so an image without a hash defines no symbols here.
    if image.hash == 0 {
        return None;
    }
    let count = image.symbol_count();
    let mut index = 1u64;
    while index < count {
        let symbol = image
            .symtab_addr()
            .wrapping_add(index.wrapping_mul(SYM_BYTES)) as *const u8;
        let name_offset = read_u32(symbol, 0) as u64;
        if name_offset != 0 {
            let name = image.strtab_addr().wrapping_add(name_offset) as *const u8;
            if names_equal(name, wanted) {
                if read_u16(symbol, 6) == 0 {
                    return None;
                }
                return Some(image.bias.wrapping_add(read_u64(symbol, 8)));
            }
        }
        index += 1;
    }
    None
}

/// Applies one image's RELA table: RELATIVE locally, GLOB_DAT / R_X86_64_64 by
/// resolving the symbol in `order` (self first). Returns (relative, globdat).
fn apply_relocations(
    image: &Image,
    order: &[&Image],
    reloc_fail: i64,
    symbol_fail: i64,
) -> (u64, u64) {
    let mut relative = 0u64;
    let mut globdat = 0u64;
    if image.rela_size == 0 {
        return (0, 0);
    }
    if image.rela_ent != RELA_BYTES || image.rela_size % RELA_BYTES != 0 {
        fail(b"image-rela-layout", reloc_fail);
    }
    let count = image.rela_size / RELA_BYTES;
    let base = image.bias.wrapping_add(image.rela);
    let mut slot = 0u64;
    while slot < count {
        let entry = base.wrapping_add(slot.wrapping_mul(RELA_BYTES)) as *const u8;
        let r_info = read_u64(entry, 8);
        let r_addend = read_i64(entry, 16);
        let kind = (r_info & 0xFFFF_FFFF) as u32;
        match kind {
            R_X86_64_NONE => {}
            R_X86_64_RELATIVE => {
                let target = image.bias.wrapping_add(read_u64(entry, 0));
                if !image_writable(image, target) {
                    fail(b"image-rela-not-writable", reloc_fail);
                }
                write_u64(target, (image.bias as i64).wrapping_add(r_addend) as u64);
                relative += 1;
            }
            R_X86_64_GLOB_DAT | R_X86_64_64 => {
                let symbol_index = r_info >> 32;
                if symbol_index == 0 {
                    fail(b"image-reloc-symbol", symbol_fail);
                }
                let symbol = image
                    .symtab_addr()
                    .wrapping_add(symbol_index.wrapping_mul(SYM_BYTES))
                    as *const u8;
                let name_offset = read_u32(symbol, 0) as u64;
                if name_offset == 0 {
                    fail(b"image-reloc-name", symbol_fail);
                }
                let name = image.strtab_addr().wrapping_add(name_offset) as *const u8;
                let mut resolved = find_symbol(image, name);
                if resolved.is_none() {
                    let mut index = 0usize;
                    while index < order.len() {
                        if let Some(value) = find_symbol(order[index], name) {
                            resolved = Some(value);
                            break;
                        }
                        index += 1;
                    }
                }
                let resolved = match resolved {
                    Some(value) => value,
                    None => fail(b"image-symbol-missing", symbol_fail),
                };
                let target = image.bias.wrapping_add(read_u64(entry, 0));
                if !image_writable(image, target) {
                    fail(b"image-reloc-not-writable", symbol_fail);
                }
                let value = if kind == R_X86_64_64 {
                    resolved.wrapping_add(r_addend as u64)
                } else {
                    resolved
                };
                write_u64(target, value);
                globdat += 1;
            }
            R_X86_64_JUMP_SLOT => fail(b"image-jump-slot", symbol_fail),
            _ => fail(b"image-reloc-kind", reloc_fail),
        }
        slot += 1;
    }
    (relative, globdat)
}

/// Validates the dynamic symbol-table layout shared by every image.
fn check_symbols(image: &Image, fail_code: i64) {
    if image.symtab == 0 || image.strtab == 0 || image.syment != SYM_BYTES {
        fail(b"image-symbols", fail_code);
    }
    if image.hash == 0 {
        fail(b"image-hash", fail_code);
    }
    if image.saw_rel {
        fail(b"image-dt-rel", fail_code);
    }
    let count = image.symbol_count();
    if count == 0 || count > MAX_LIB_SYMBOLS {
        fail(b"image-symbol-count", fail_code);
    }
}

extern "C" fn interp_entry(initial_rsp: usize) -> ! {
    let stack = initial_rsp as *const u8;

    // 1. Parse the kernel-written initial stack image (argc / argv / envp / auxv).
    let mut at_phdr = 0u64;
    let mut at_phent = 0u64;
    let mut at_phnum = 0u64;
    let mut at_base = 0u64;
    let mut at_entry = 0u64;
    let mut at_pagesz = 0u64;
    let mut saw_phdr = false;
    let mut saw_phent = false;
    let mut saw_phnum = false;
    let mut saw_base = false;
    let mut saw_entry = false;
    let mut saw_pagesz = false;
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
            AT_BASE => {
                at_base = value;
                saw_base = true;
            }
            AT_ENTRY => {
                at_entry = value;
                saw_entry = true;
            }
            AT_PAGESZ => {
                at_pagesz = value;
                saw_pagesz = true;
            }
            AT_CAELUM_CHANNEL | AT_CAELUM_NETNS | AT_CAELUM_ROLE => {}
            _ => {}
        }
        index += 2;
        pairs += 1;
    }
    if !(saw_phdr && saw_phent && saw_phnum && saw_base && saw_entry && saw_pagesz) {
        fail(b"auxv-missing", EXIT_AUXV);
    }
    if at_pagesz != PAGE_BYTES {
        fail(b"pagesz", EXIT_AUXV);
    }
    if at_phent != PHDR_BYTES {
        fail(b"phent", EXIT_AUXV);
    }
    if at_phnum == 0 || at_phnum > 64 {
        fail(b"phnum", EXIT_AUXV);
    }
    if at_phdr == 0 || at_entry == 0 {
        fail(b"auxv-zero", EXIT_AUXV);
    }
    // The interpreter is a fixed-address ET_EXEC image: fixed load bias is 0.
    if at_base != 0 {
        fail(b"at-base", EXIT_AUXV);
    }

    // 2. Walk the main program's program headers: recover the bias from
    //    `PT_PHDR`, collect PT_LOAD segments and find PT_DYNAMIC.
    let phdr_base = at_phdr as *const u8;
    let mut phdr_vaddr = 0u64;
    let mut saw_phdr_segment = false;
    let mut dynamic_vaddr = 0u64;
    let mut dynamic_memsz = 0u64;
    let mut saw_dynamic = false;
    let mut saw_interp = false;
    let mut loads = [Load::EMPTY; MAX_LOADS];
    let mut load_count = 0usize;
    let mut segment = 0u64;
    while segment < at_phnum {
        let base = segment.wrapping_mul(PHDR_BYTES) as usize;
        let p_type = read_u32(phdr_base, base);
        let p_flags = read_u32(phdr_base, base + 4);
        let p_offset = read_u64(phdr_base, base + 8);
        let p_vaddr = read_u64(phdr_base, base + 16);
        let p_memsz = read_u64(phdr_base, base + 40);
        match p_type {
            PT_PHDR => {
                phdr_vaddr = p_vaddr;
                saw_phdr_segment = true;
            }
            PT_DYNAMIC => {
                dynamic_vaddr = p_vaddr;
                dynamic_memsz = p_memsz;
                saw_dynamic = true;
            }
            PT_INTERP => saw_interp = true,
            PT_LOAD => {
                if load_count < MAX_LOADS {
                    loads[load_count] = Load {
                        vaddr: p_vaddr,
                        offset: p_offset,
                        memsz: p_memsz,
                        flags: p_flags,
                    };
                    load_count += 1;
                }
            }
            _ => {}
        }
        segment += 1;
    }
    if !saw_phdr_segment {
        fail(b"no-pt-phdr", EXIT_PROGRAM_HEADERS);
    }
    if !saw_dynamic {
        fail(b"no-pt-dynamic", EXIT_PROGRAM_HEADERS);
    }
    if !saw_interp {
        fail(b"no-pt-interp", EXIT_PROGRAM_HEADERS);
    }
    if load_count == 0 {
        fail(b"no-pt-load", EXIT_PROGRAM_HEADERS);
    }
    let bias = at_phdr.wrapping_sub(phdr_vaddr);
    if bias & (PAGE_BYTES - 1) != 0 {
        fail(b"bias-align", EXIT_PROGRAM_HEADERS);
    }
    if bias != MAIN_BIAS {
        fail(b"bias-value", EXIT_PROGRAM_HEADERS);
    }
    if at_phdr != bias.wrapping_add(phdr_vaddr) {
        fail(b"phdr-vaddr", EXIT_PROGRAM_HEADERS);
    }

    // Segment congruence and "program headers live inside a PT_LOAD" check.
    let phdr_end = at_phdr.wrapping_add(at_phnum.wrapping_mul(at_phent));
    let mut headers_covered = false;
    let mut valid_loads = 0usize;
    while valid_loads < load_count {
        let load = loads[valid_loads];
        if load.vaddr % PAGE_BYTES != load.offset % PAGE_BYTES {
            fail(b"load-congruence", EXIT_PROGRAM_HEADERS);
        }
        if range_inside(
            at_phdr,
            phdr_end,
            load_start(bias, load),
            load_end(bias, load),
        ) {
            headers_covered = true;
        }
        valid_loads += 1;
    }
    if !headers_covered {
        fail(b"phdr-uncovered", EXIT_PROGRAM_HEADERS);
    }

    // 3. Validate the main program's ELF header against the auxv.
    let elf = bias as *const u8;
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
        fail(b"ehdr-phdr-size", EXIT_HEADER);
    }
    if bias.wrapping_add(e_phoff) != at_phdr {
        fail(b"ehdr-phoff", EXIT_HEADER);
    }
    if bias.wrapping_add(e_entry) != at_entry {
        fail(b"ehdr-entry", EXIT_HEADER);
    }
    if e_phoff < EHDR_BYTES {
        fail(b"ehdr-phoff-low", EXIT_HEADER);
    }

    // 4. Parse the main program's dynamic array and validate its two NEEDED
    //    entries: m9e (M9e regression) and m9f-a (M9f chain head).
    let mut main_image = Image::EMPTY;
    main_image.bias = bias;
    main_image.phdr = at_phdr;
    main_image.phnum = at_phnum;
    main_image.dynamic = bias.wrapping_add(dynamic_vaddr);
    main_image.dynamic_size = dynamic_memsz;
    let mut cursor = main_image.dynamic;
    let dynamic_end = cursor.wrapping_add(main_image.dynamic_size);
    while cursor.wrapping_add(16) <= dynamic_end {
        let tag = read_i64(cursor as *const u8, 0);
        let value = read_u64(cursor as *const u8, 8);
        if tag == DT_NULL {
            break;
        }
        match tag {
            DT_RELA => main_image.rela = value,
            DT_RELASZ => main_image.rela_size = value,
            DT_RELAENT => main_image.rela_ent = value,
            DT_SYMTAB => main_image.symtab = value,
            DT_STRTAB => main_image.strtab = value,
            DT_SYMENT => main_image.syment = value,
            DT_HASH => main_image.hash = value,
            DT_REL => main_image.saw_rel = true,
            DT_NEEDED => {
                if main_image.needed_count < 4 {
                    main_image.needed[main_image.needed_count as usize] = value;
                }
                main_image.needed_count += 1;
            }
            _ => {}
        }
        cursor = cursor.wrapping_add(16);
    }
    if main_image.saw_rel {
        fail(b"dt-rel-unsupported", EXIT_DYNAMIC);
    }
    if main_image.rela_size == 0 {
        fail(b"no-dt-rela", EXIT_DYNAMIC);
    }
    if main_image.rela_ent != RELA_BYTES || main_image.rela_size % RELA_BYTES != 0 {
        fail(b"rela-layout", EXIT_RELA);
    }
    if main_image.symtab == 0 || main_image.strtab == 0 || main_image.syment != SYM_BYTES {
        fail(b"main-symbols", EXIT_DYNAMIC);
    }
    // The main program exports nothing and carries no DT_HASH; only its
    // named relocations are read, so no main symbol enumeration is needed.
    if main_image.needed_count != 2 {
        fail(b"lib-needed-count", EXIT_NEEDED);
    }
    let main_strtab = main_image.strtab_addr();
    let mut m9e_needed = false;
    let mut m9f_needed = false;
    let mut needed_index = 0usize;
    while needed_index < (main_image.needed_count as usize).min(4) {
        let name = main_strtab.wrapping_add(main_image.needed[needed_index]) as *const u8;
        if names_equal(name, LIB_PATH.as_ptr()) {
            m9e_needed = true;
        }
        if names_equal(name, M9F_A_PATH.as_ptr()) {
            m9f_needed = true;
        }
        needed_index += 1;
    }
    if !m9e_needed {
        fail(b"lib-needed-name", EXIT_NEEDED);
    }
    if !m9f_needed {
        fail(b"lib-needed-m9f", EXIT_NEEDED);
    }

    // 5. Parse and relocate the three shared libraries in the frozen order:
    //    m9e, m9f-a, m9f-b. Each library applies its own RELATIVE relocations;
    //    GLOB_DAT entries resolve against itself first, then its dependencies
    //    (a -> b), so m9f_add resolves to the m9f-b mapping.
    let m9e_image = parse_image(LIB_BIAS, EXIT_LIB_HEADER);
    check_symbols(&m9e_image, EXIT_LIB_DYNAMIC);
    if !names_equal(
        m9e_image.strtab_addr().wrapping_add(m9e_image.soname) as *const u8,
        LIB_PATH.as_ptr(),
    ) {
        fail(b"m9e-soname", EXIT_LIB_DYNAMIC);
    }
    if m9e_image.needed_count != 0 {
        fail(b"m9e-needed", EXIT_LIB_DYNAMIC);
    }
    let (m9e_relative, m9e_globdat) =
        apply_relocations(&m9e_image, &[&m9e_image], EXIT_LIB_RELOC, EXIT_LIB_SYMBOL);

    let a_image = parse_image(M9F_A_BIAS, EXIT_LIB_A);
    check_symbols(&a_image, EXIT_LIB_A);
    if !names_equal(
        a_image.strtab_addr().wrapping_add(a_image.soname) as *const u8,
        M9F_A_PATH.as_ptr(),
    ) {
        fail(b"m9f-a-soname", EXIT_LIB_A);
    }
    if a_image.needed_count != 1 {
        fail(b"m9f-a-needed-count", EXIT_LIB_A);
    }
    let a_strtab = a_image.strtab_addr();
    if !names_equal(
        a_strtab.wrapping_add(a_image.needed[0]) as *const u8,
        M9F_B_PATH.as_ptr(),
    ) {
        fail(b"m9f-a-needed-name", EXIT_LIB_A);
    }

    let b_image = parse_image(M9F_B_BIAS, EXIT_LIB_B);
    check_symbols(&b_image, EXIT_LIB_B);
    if !names_equal(
        b_image.strtab_addr().wrapping_add(b_image.soname) as *const u8,
        M9F_B_PATH.as_ptr(),
    ) {
        fail(b"m9f-b-soname", EXIT_LIB_B);
    }
    if b_image.needed_count != 0 {
        fail(b"m9f-b-needed", EXIT_LIB_B);
    }
    let (b_relative, b_globdat) = apply_relocations(&b_image, &[&b_image], EXIT_LIB_B, EXIT_LIB_B);

    let (a_relative, a_globdat) =
        apply_relocations(&a_image, &[&a_image, &b_image], EXIT_LIB_A, EXIT_LIB_A);

    // 6. Apply the main program's relocations. The resolver order is frozen:
    //    self (defines nothing), m9e, m9f-a, m9f-b.
    let (relative, globdat) = apply_relocations(
        &main_image,
        &[&m9e_image, &a_image, &b_image],
        EXIT_RELOC,
        EXIT_MAIN_RELOC,
    );
    let total_globdat = globdat
        .wrapping_add(m9e_globdat)
        .wrapping_add(a_globdat)
        .wrapping_add(b_globdat);
    let total_relative = relative
        .wrapping_add(m9e_relative)
        .wrapping_add(a_relative)
        .wrapping_add(b_relative);
    // 7. Report success and transfer control to the main program entry with the
    //    original initial stack pointer (the main program still reads auxv).
    marker(2, 3, total_globdat, total_relative);
    unsafe {
        asm!(
            "mov rsp, {stack}",
            "jmp {entry}",
            stack = in(reg) initial_rsp as u64,
            entry = in(reg) at_entry,
            options(noreturn),
        );
    }
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    write_line(b"[CaelumDyn] FAIL panic\n");
    exit_group(0x7f)
}
