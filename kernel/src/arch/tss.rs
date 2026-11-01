//! Task State Segments (x86-64, 104 bytes each) with per-CPU IST stacks.
//!
//! The CPU reads the TSS through the GDT descriptor, so its layout is the
//! hardware one, not Rust's natural one (Intel SDM Vol. 3, Figure 7-11):
//!
//! | offset | field |
//! |--------|-------|
//! | 0x00 | reserved |
//! | 0x04 | `RSP0` |
//! | 0x0C | `RSP1` |
//! | 0x14 | `RSP2` |
//! | 0x1C | reserved |
//! | 0x24 | `IST1`..`IST7` (7 x 8 bytes, 0x24..0x5C) |
//! | 0x5C | reserved |
//! | 0x64 | reserved |
//! | 0x66 | I/O permission bitmap base |
//!
//! `RSP0` therefore sits four bytes after the reserved dword, not eight: the
//! leading `u32` shifts every following `u64`. A naturally aligned
//! `#[repr(C, align(16))]` layout puts `RSP0` at 0x08, `IST1` at 0x28 and the
//! I/O map base at 0x6A, which the CPU happily accepts while the kernel stays
//! in ring 0 — M2/M3 never left it. The first ring-3 timer interrupt (M4) made
//! the hardware read `RSP0` from 0x04 — the misaligned non-canonical value the
//! Rust 0x08 layout had left there — so the stack switch failed (`#SS`/`#DF`)
//! and the CPU triple-faulted. `packed(4)` reproduces the hardware offsets
//! exactly; the const assertions below keep them that way.
//!
//! M6b1 makes the TSS **per CPU**: every processor needs its own `RSP0` (the
//! stack a ring3 → ring0 interrupt switches to) and its own IST stacks, because
//! two CPUs can fault at the same time on different stacks. [`MAX_CPUS`] slots
//! exist; slot 0 is the boot processor, the rest belong to the application
//! processors. The boot-processor accessors ([`init`], [`set_rsp0`],
//! [`rsp0`]) keep their M2–M4 signatures so existing call sites are unchanged.
//!
//! Two IST stacks per CPU (agents.md §7.2 kernel-stack guard discipline):
//! - IST1: `#DF` (double fault) gets its own 16 KiB stack so a stack-overflow
//!   fault can still be diagnosed instead of triple-faulting.
//! - IST2: NMI gets a small independent stack.

use super::MAX_CPUS;

/// Hardware size of the 64-bit TSS: exactly 104 bytes. The GDT descriptor
/// limit is `TSS_LEN - 1` (0x67) and the I/O map base is `TSS_LEN` (no bitmap).
pub const TSS_LEN: usize = 0x68;

/// Hardware byte offset of `RSP0`.
pub const TSS_RSP0_OFFSET: usize = 0x04;
/// Hardware byte offset of `IST1` (each IST slot is 8 bytes).
pub const TSS_IST_OFFSET: usize = 0x24;
/// Hardware byte offset of the I/O permission bitmap base.
pub const TSS_IOMAP_BASE_OFFSET: usize = 0x66;

/// CPU reads the TSS through the GDT descriptor; keep them in kernel `.bss`.
///
/// `packed(4)` is what makes the layout the hardware one: with a 4-byte
/// packing bound a `u64` only needs 4-byte alignment, so `rsp0` lands at 0x04
/// instead of 0x08. Never take a reference to a field (E0793); the accessors
/// below use raw unaligned pointers.
#[repr(C, packed(4))]
pub struct Tss {
    reserved0: u32,
    pub rsp0: u64,
    pub rsp1: u64,
    pub rsp2: u64,
    reserved1: u64,
    /// IST1..IST7 live at offsets 0x24..0x5C.
    pub ist: [u64; 7],
    reserved2: u64,
    reserved3: u16,
    /// Byte offset of the I/O permission bitmap; `sizeof(Tss)` = no bitmap.
    pub iomap_base: u16,
}

const _: () = assert!(core::mem::size_of::<Tss>() == TSS_LEN);
const _: () = assert!(core::mem::offset_of!(Tss, rsp0) == TSS_RSP0_OFFSET);
const _: () = assert!(core::mem::offset_of!(Tss, ist) == TSS_IST_OFFSET);
const _: () = assert!(core::mem::offset_of!(Tss, iomap_base) == TSS_IOMAP_BASE_OFFSET);

pub const IST_DF: usize = 0;
pub const IST_NMI: usize = 1;

/// One hardware TSS per CPU; index 0 is the boot processor.
pub static mut TSS: [Tss; MAX_CPUS] = [const {
    Tss {
        reserved0: 0,
        rsp0: 0,
        rsp1: 0,
        rsp2: 0,
        reserved1: 0,
        ist: [0; 7],
        reserved2: 0,
        reserved3: 0,
        iomap_base: 0,
    }
}; MAX_CPUS];

const DF_STACK_SIZE: usize = 16 * 1024;
const NMI_STACK_SIZE: usize = 4 * 1024;

#[repr(C, align(16))]
struct IstStack<const N: usize> {
    bytes: [u8; N],
}

static mut DF_STACKS: [IstStack<DF_STACK_SIZE>; MAX_CPUS] = [const {
    IstStack {
        bytes: [0; DF_STACK_SIZE],
    }
}; MAX_CPUS];
static mut NMI_STACKS: [IstStack<NMI_STACK_SIZE>; MAX_CPUS] = [const {
    IstStack {
        bytes: [0; NMI_STACK_SIZE],
    }
}; MAX_CPUS];

/// Pointer to CPU `cpu`'s TSS inside the `static mut`.
fn tss_ptr(cpu: usize) -> *mut Tss {
    assert!(cpu < MAX_CPUS, "cpu index out of range");
    // SAFETY: `TSS` has `MAX_CPUS` slots and `cpu < MAX_CPUS`; the pointer is
    // only used to read/write plain fields of that slot.
    unsafe { core::ptr::addr_of_mut!(TSS).cast::<Tss>().add(cpu) }
}

/// Physical/link address of CPU `cpu`'s TSS (the GDT descriptor base).
pub fn tss_base(cpu: usize) -> u64 {
    tss_ptr(cpu) as u64
}

/// Write one `u64` into CPU `cpu`'s TSS at a hardware offset.
///
/// # Safety
///
/// `offset` must be an 8-byte field offset inside the TSS; callers pass the
/// constants above.
unsafe fn write_u64(cpu: usize, offset: usize, value: u64) {
    // SAFETY: the TSS slot is owned by this module, and the byte pointer keeps
    // us clear of `static_mut_refs` and of packed-field references.
    // `write_unaligned` because packed `u64`s are only 4-aligned.
    unsafe {
        tss_ptr(cpu)
            .cast::<u8>()
            .add(offset)
            .cast::<u64>()
            .write_unaligned(value)
    };
}

/// Read one `u64` from CPU `cpu`'s TSS at a hardware offset.
///
/// # Safety
///
/// Same contract as [`write_u64`].
unsafe fn read_u64(cpu: usize, offset: usize) -> u64 {
    // SAFETY: see `write_u64`.
    unsafe {
        tss_ptr(cpu)
            .cast::<u8>()
            .add(offset)
            .cast::<u64>()
            .read_unaligned()
    }
}

/// Write one `u16` into CPU `cpu`'s TSS at a hardware offset.
///
/// # Safety
///
/// `offset` must be a 2-byte field offset inside the TSS.
unsafe fn write_u16(cpu: usize, offset: usize, value: u16) {
    // SAFETY: see `write_u64`.
    unsafe {
        tss_ptr(cpu)
            .cast::<u8>()
            .add(offset)
            .cast::<u16>()
            .write_unaligned(value)
    };
}

/// Read one `u16` from CPU `cpu`'s TSS at a hardware offset (host tests only).
///
/// # Safety
///
/// Same contract as [`write_u16`].
#[cfg(test)]
unsafe fn read_u16(cpu: usize, offset: usize) -> u16 {
    // SAFETY: see `write_u64`.
    unsafe {
        tss_ptr(cpu)
            .cast::<u8>()
            .add(offset)
            .cast::<u16>()
            .read_unaligned()
    }
}

fn df_stack_top(cpu: usize) -> u64 {
    assert!(cpu < MAX_CPUS, "cpu index out of range");
    // SAFETY: index checked; the arrays are plain `.bss` statics.
    let base = unsafe {
        core::ptr::addr_of!(DF_STACKS)
            .cast::<IstStack<DF_STACK_SIZE>>()
            .add(cpu)
    } as u64;
    base + DF_STACK_SIZE as u64
}

fn nmi_stack_top(cpu: usize) -> u64 {
    assert!(cpu < MAX_CPUS, "cpu index out of range");
    // SAFETY: index checked; the arrays are plain `.bss` statics.
    let base = unsafe {
        core::ptr::addr_of!(NMI_STACKS)
            .cast::<IstStack<NMI_STACK_SIZE>>()
            .add(cpu)
    } as u64;
    base + NMI_STACK_SIZE as u64
}

/// Program CPU `cpu`'s TSS (IST stacks) before its GDT is loaded (the GDT
/// holds the TSS descriptor pointing at this slot).
pub fn init_cpu(cpu: usize) {
    // SAFETY: plain field writes through the offset accessors; called during
    // early boot for CPU 0 and from the AP entry path for the others.
    unsafe {
        write_u16(cpu, TSS_IOMAP_BASE_OFFSET, TSS_LEN as u16);
        write_u64(cpu, TSS_IST_OFFSET + IST_DF * 8, df_stack_top(cpu));
        write_u64(cpu, TSS_IST_OFFSET + IST_NMI * 8, nmi_stack_top(cpu));
    }
}

/// Boot-processor form of [`init_cpu`] (kept for the M2–M4 call sites).
pub fn init() {
    init_cpu(0);
}

/// Set `TSS.RSP0` of CPU `cpu`, the stack the CPU switches to on a ring3 →
/// ring0 interrupt.
///
/// M4 keeps this per thread: whoever makes a thread current calls this with
/// that thread's kernel stack top (16-byte aligned, top-of-stack convention)
/// right before resuming it in ring 3. Only CPU 0 runs user threads in M4/M5;
/// the AP slots keep a conservative value.
pub fn set_rsp0_for(cpu: usize, top: u64) {
    // SAFETY: plain field write at the hardware offset.
    unsafe { write_u64(cpu, TSS_RSP0_OFFSET, top) };
}

/// Current `TSS.RSP0` of CPU `cpu` (diagnostics/tests).
pub fn rsp0_for(cpu: usize) -> u64 {
    // SAFETY: read-only access to a plain field of the resident TSS.
    unsafe { read_u64(cpu, TSS_RSP0_OFFSET) }
}

/// Boot-processor form of [`set_rsp0_for`].
pub fn set_rsp0(top: u64) {
    set_rsp0_for(0, top);
}

/// Boot-processor form of [`rsp0_for`].
pub fn rsp0() -> u64 {
    rsp0_for(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn layout_matches_the_hardware_tss() {
        assert_eq!(core::mem::size_of::<Tss>(), 104);
        assert_eq!(TSS_LEN, 0x68);
        assert_eq!(core::mem::offset_of!(Tss, rsp0), 0x04);
        assert_eq!(core::mem::offset_of!(Tss, rsp1), 0x0C);
        assert_eq!(core::mem::offset_of!(Tss, rsp2), 0x14);
        assert_eq!(core::mem::offset_of!(Tss, ist), 0x24);
        assert_eq!(core::mem::offset_of!(Tss, iomap_base), 0x66);
        // IST1..IST7 must be seven adjacent qwords ending at 0x5C.
        assert_eq!(TSS_IST_OFFSET + 7 * 8, 0x5C);
        // No I/O bitmap: the base points one past the segment limit.
        assert_eq!(TSS_IOMAP_BASE_OFFSET, TSS_LEN as usize - 2);
        // One hardware TSS per CPU, each exactly the hardware size.
        assert_eq!(core::mem::size_of::<[Tss; MAX_CPUS]>(), TSS_LEN * MAX_CPUS);
    }

    #[test]
    fn set_rsp0_writes_the_hardware_slot() {
        // SAFETY: test-local writes to the resident TSS; the value is restored
        // afterwards so no other test observes a stale RSP0.
        unsafe {
            let saved = read_u64(0, TSS_RSP0_OFFSET);
            set_rsp0(0xFFFF_FFFF_8150_3FF8);
            assert_eq!(rsp0(), 0xFFFF_FFFF_8150_3FF8);
            // Read the raw bytes at 0x04: this is the offset the CPU uses.
            let raw = tss_ptr(0)
                .cast::<u8>()
                .add(TSS_RSP0_OFFSET)
                .cast::<u64>()
                .read_unaligned();
            assert_eq!(raw, 0xFFFF_FFFF_8150_3FF8);
            write_u64(0, TSS_RSP0_OFFSET, saved);
        }
    }

    #[test]
    fn each_cpu_has_its_own_rsp0_and_tss_address() {
        // Slot 1 must not alias slot 0: an AP never sees the BSP's RSP0.
        unsafe {
            let saved0 = read_u64(0, TSS_RSP0_OFFSET);
            let saved1 = read_u64(1, TSS_RSP0_OFFSET);
            set_rsp0(0xAAAA_0000);
            set_rsp0_for(1, 0xBBBB_0000);
            assert_eq!(rsp0(), 0xAAAA_0000);
            assert_eq!(rsp0_for(1), 0xBBBB_0000);
            write_u64(0, TSS_RSP0_OFFSET, saved0);
            write_u64(1, TSS_RSP0_OFFSET, saved1);
        }
        assert_ne!(tss_base(0), tss_base(1));
        assert_eq!(tss_base(1) - tss_base(0), TSS_LEN as u64);
    }

    #[test]
    fn init_programs_the_iomap_base_and_ist_slots() {
        // SAFETY: `init_cpu` only writes reserved/IST/iomap fields and is safe
        // to repeat; host tests never run the CPU on these values.
        unsafe {
            init();
            assert_eq!(read_u16(0, TSS_IOMAP_BASE_OFFSET), TSS_LEN as u16);
            let df = read_u64(0, TSS_IST_OFFSET + IST_DF * 8);
            let nmi = read_u64(0, TSS_IST_OFFSET + IST_NMI * 8);
            assert_eq!(df, df_stack_top(0));
            assert_eq!(nmi, nmi_stack_top(0));
            assert_eq!(df % 16, 0);
            assert_eq!(nmi % 16, 0);

            // Every CPU gets distinct IST stacks of the documented sizes; the
            // per-CPU stacks are adjacent, so the tops differ by exactly one
            // stack (16 KiB for #DF, 4 KiB for NMI).
            init_cpu(1);
            let df1 = read_u64(1, TSS_IST_OFFSET + IST_DF * 8);
            let nmi1 = read_u64(1, TSS_IST_OFFSET + IST_NMI * 8);
            assert_eq!(df1, df_stack_top(1));
            assert_eq!(nmi1, nmi_stack_top(1));
            assert_ne!(df, df1);
            assert_ne!(nmi, nmi1);
            assert_eq!(df1 - df, DF_STACK_SIZE as u64);
            assert_eq!(nmi1 - nmi, NMI_STACK_SIZE as u64);
            assert_eq!(df1 % 16, 0);
            assert_eq!(nmi1 % 16, 0);
        }
    }
}
