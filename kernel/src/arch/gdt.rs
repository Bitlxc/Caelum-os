//! Global Descriptor Table (x86-64, one table per CPU).
//!
//! Long mode effectively ignores the base/limit of the kernel code and data
//! descriptors — they are flat, base 0, 4 GiB — but CS/SS still carry the
//! privilege level and the long-mode (L) bit, and `SS` keeps a writable data
//! segment loaded for the stack. The TSS descriptor in the GDT is what tells
//! the CPU where the current task state segment lives, and that is why the GDT
//! must be **per CPU** in M6b1: every processor needs a TSS descriptor pointing
//! at *its own* TSS (`TSS[i]`), otherwise both CPUs would share one RSP0 and
//! one IST stack set — a stack switch on CPU 1 would land on CPU 0's kernel
//! stack and corrupt it.
//!
//! Layout (7 entries, unchanged since M2 so every selector value is stable):
//!
//! | index | selector | descriptor |
//! |-------|----------|------------|
//! | 0 | 0x00 | null |
//! | 1 | 0x08 | kernel code (DPL0) |
//! | 2 | 0x10 | kernel data (DPL0) |
//! | 3 | 0x1B | user code (DPL3) |
//! | 4 | 0x23 | user data (DPL3) |
//! | 5 | 0x28 | TSS low dword |
//! | 6 | 0x30 | TSS high dword |
//!
//! [`install`] builds the table for one CPU and loads it with `lgdt`,
//! re-loads the segment registers (including CS via a far return, since CS
//! cannot be loaded with `mov` outside ring 0) and executes `ltr` so the CPU
//! knows the TSS. [`init`] is the boot-processor form used by M2–M4 boot code.
//!
//! The trampoline page (see `smp.rs`) additionally needs **32-bit** code and
//! data descriptors whose base is the page's physical address, so that the
//! transition stub can run in protected mode with paging off at its identity
//! address. [`code32_descriptor`] / [`data32_descriptor`] are the only
//! non-flat descriptors the kernel builds, and they are never installed in the
//! kernel's own GDT.

use super::MAX_CPUS;
use super::tss::{TSS_LEN, tss_base};

/// Kernel code selector (index 1).
pub const KERNEL_CS: u16 = 0x08;
/// Kernel data selector (index 2).
pub const KERNEL_DS: u16 = 0x10;
/// User code selector (index 3, RPL 3).
pub const USER_CS: u16 = 0x1B;
/// User data selector (index 4, RPL 3).
pub const USER_DS: u16 = 0x23;
/// TSS selector (index 5).
pub const TSS_SELECTOR: u16 = 0x28;

/// Flat kernel code: base 0, limit 4 GiB, present, DPL0, code, readable,
/// long mode (`L=1`), 4 KiB granularity.
const KERNEL_CODE: u64 = 0x00AF_9A00_0000_FFFF;
/// Flat kernel data: base 0, limit 4 GiB, present, DPL0, writable, 32-bit.
const KERNEL_DATA: u64 = 0x00CF_9200_0000_FFFF;
/// Flat user code: same as kernel code but DPL3.
const USER_CODE: u64 = 0x00AF_FA00_0000_FFFF;
/// Flat user data: same as kernel data but DPL3.
const USER_DATA: u64 = 0x00CF_F200_0000_FFFF;

/// Number of entries in the GDT; the TSS descriptor occupies two.
const GDT_ENTRIES: usize = 7;
const _: () = assert!(GDT_ENTRIES == 7);

#[repr(C, align(16))]
struct Gdt {
    entries: [u64; GDT_ENTRIES],
}

/// One table per CPU: identical bar the TSS descriptor base.
static mut GDT_TABLES: [Gdt; MAX_CPUS] = [const {
    Gdt {
        entries: [0; GDT_ENTRIES],
    }
}; MAX_CPUS];

#[repr(C, packed)]
struct Gdtr {
    limit: u16,
    base: u64,
}

fn gdt_ptr(cpu: usize) -> *mut Gdt {
    assert!(cpu < MAX_CPUS, "cpu index out of range");
    // SAFETY: `cpu` is in range and the table lives in `.bss` for the whole
    // kernel lifetime.
    unsafe { core::ptr::addr_of_mut!(GDT_TABLES).cast::<Gdt>().add(cpu) }
}

/// Pack a descriptor from explicit fields (Intel SDM Vol. 3, Figure 3-8).
///
/// `base`/`limit` are split across the descriptor's three pieces; `flags` is
/// the low nibble of the type/flags byte: `G(1) D/B(1) L(1) AVL(1)`.
const fn descriptor(base: u64, limit: u32, access: u8, flags: u8) -> u64 {
    let limit = limit as u64;
    (limit & 0xFFFF)
        | ((base & 0xFFFF) << 16)
        | (((base >> 16) & 0xFF) << 32)
        | ((access as u64) << 40)
        | (((limit >> 16) & 0xF) << 48)
        | (((flags as u64) & 0xF) << 52)
        | (((base >> 24) & 0xFF) << 56)
}

const _: () = assert!(descriptor(0, 0x000F_FFFF, 0x9A, 0xA) == KERNEL_CODE);
const _: () = assert!(descriptor(0, 0x000F_FFFF, 0x92, 0xC) == KERNEL_DATA);
const _: () = assert!(descriptor(0, 0x000F_FFFF, 0xFA, 0xA) == USER_CODE);
const _: () = assert!(descriptor(0, 0x000F_FFFF, 0xF2, 0xC) == USER_DATA);

/// 32-bit code descriptor for the trampoline page (base = page physical, limit
/// 64 KiB, present, DPL0, code, readable, `G=0 D=1 L=0`).
pub(crate) const fn code32_descriptor(base: u64) -> u64 {
    descriptor(base, 0xFFFF, 0x9A, 0x4)
}

/// 32-bit data descriptor for the trampoline page.
pub(crate) const fn data32_descriptor(base: u64) -> u64 {
    descriptor(base, 0xFFFF, 0x92, 0x4)
}

/// 64-bit kernel code descriptor (the one used by the running kernel).
pub(crate) const fn code64_descriptor() -> u64 {
    KERNEL_CODE
}

/// 64-bit kernel data descriptor.
pub(crate) const fn data64_descriptor() -> u64 {
    KERNEL_DATA
}

/// Two GDT words describing a 64-bit TSS at `base` with segment `limit`.
fn tss_descriptor(base: u64, limit: u64) -> (u64, u64) {
    let lo = (limit & 0xFFFF)
        | ((base & 0xFF_FFFF) << 16)
        | (0x89 << 40) // present, DPL0, 64-bit available TSS
        | (((limit >> 16) & 0xF) << 48)
        | (((base >> 24) & 0xFF) << 56);
    let hi = base >> 32;
    (lo, hi)
}

/// The seven entries CPU `cpu` should load.
pub(crate) fn entries_for(cpu: usize) -> [u64; GDT_ENTRIES] {
    let (tss_lo, tss_hi) = tss_descriptor(tss_base(cpu), TSS_LEN as u64 - 1);
    [
        0,
        KERNEL_CODE,
        KERNEL_DATA,
        USER_CODE,
        USER_DATA,
        tss_lo,
        tss_hi,
    ]
}

/// Build and load CPU `cpu`'s GDT, reload the data segment registers and CS,
/// and point the task register at that CPU's TSS.
///
/// Must run in ring 0 with interrupts disabled (the far return reloads CS).
pub fn install(cpu: usize) {
    // SAFETY: we own the descriptor slots; the GDT/TSS addresses are stable
    // `.bss` statics; `lgdt`, the segment loads and `ltr` are privileged
    // instructions executed here from ring 0.
    unsafe {
        let table = gdt_ptr(cpu);
        let entries = entries_for(cpu);
        for (index, entry) in entries.iter().enumerate() {
            core::ptr::addr_of_mut!((*table).entries)
                .cast::<u64>()
                .add(index)
                .write(*entry);
        }

        let gdtr = Gdtr {
            limit: (GDT_ENTRIES * core::mem::size_of::<u64>() - 1) as u16,
            base: table as u64,
        };
        core::arch::asm!(
            "lgdt [{gdtr}]",
            gdtr = in(reg) &gdtr as *const Gdtr,
            options(readonly, nostack, preserves_flags),
        );

        let kernel_ds = u64::from(KERNEL_DS);
        core::arch::asm!(
            "mov ds, {ds:x}",
            "mov es, {ds:x}",
            "mov ss, {ds:x}",
            ds = in(reg) kernel_ds,
            options(nostack, preserves_flags),
        );

        // CS cannot be loaded with `mov` outside ring 0; reload it with a far
        // return: push the target CS, push the address of the next label.
        let kernel_cs = u64::from(KERNEL_CS);
        core::arch::asm!(
            "lea rax, [rip + 99f]",
            "push {cs}",
            "push rax",
            "retfq",
            "99:",
            cs = in(reg) kernel_cs,
            out("rax") _,
            options(nostack, preserves_flags),
        );

        // `LTR` needs the selector of the TSS descriptor (index 5).
        let tss_selector = u64::from(TSS_SELECTOR);
        core::arch::asm!(
            "ltr {sel:x}",
            sel = in(reg) tss_selector,
            options(nostack, preserves_flags),
        );
    }
}

/// Boot-processor form of [`install`], kept for the M2–M4 boot sequence.
pub fn init() {
    install(0);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn access_byte(entry: u64) -> u8 {
        (entry >> 40) as u8
    }

    fn dpl(entry: u64) -> u8 {
        (access_byte(entry) >> 5) & 0b11
    }

    fn long_mode(entry: u64) -> bool {
        (entry >> 53) & 1 == 1
    }

    fn default_op_size(entry: u64) -> bool {
        (entry >> 54) & 1 == 1
    }

    fn base_of(entry: u64) -> u64 {
        ((entry >> 16) & 0xFFFF) | (((entry >> 32) & 0xFF) << 16) | (((entry >> 56) & 0xFF) << 24)
    }

    fn limit_of(entry: u64) -> u32 {
        ((entry & 0xFFFF) as u32) | (((entry >> 48) & 0xF) as u32) << 16
    }

    #[test]
    fn selectors_match_their_gdt_indices() {
        assert_eq!(KERNEL_CS as usize / 8, 1);
        assert_eq!(KERNEL_DS as usize / 8, 2);
        assert_eq!(USER_CS as usize / 8, 3);
        assert_eq!(USER_CS & 3, 3);
        assert_eq!(USER_DS as usize / 8, 4);
        assert_eq!(USER_DS & 3, 3);
        assert_eq!(TSS_SELECTOR as usize / 8, 5);
        assert_eq!(GDT_ENTRIES, 7);
    }

    #[test]
    fn user_descriptors_are_dpl3_long_mode() {
        assert_eq!(dpl(KERNEL_CODE), 0);
        assert_eq!(dpl(USER_CODE), 3);
        assert_eq!(dpl(USER_DATA), 3);
        assert!(long_mode(KERNEL_CODE));
        assert!(long_mode(USER_CODE));
        // Data descriptors are 32-bit (D/B) and not long mode.
        assert!(default_op_size(KERNEL_DATA));
        assert!(!long_mode(USER_DATA));
    }

    #[test]
    fn descriptor_builder_reproduces_the_static_entries() {
        assert_eq!(descriptor(0, 0x000F_FFFF, 0x9A, 0xA), KERNEL_CODE);
        assert_eq!(descriptor(0, 0x000F_FFFF, 0x92, 0xC), KERNEL_DATA);
        assert_eq!(descriptor(0, 0x000F_FFFF, 0xFA, 0xA), USER_CODE);
        assert_eq!(descriptor(0, 0x000F_FFFF, 0xF2, 0xC), USER_DATA);
    }

    #[test]
    fn each_cpu_describes_its_own_tss() {
        for cpu in 0..MAX_CPUS {
            let entries = entries_for(cpu);
            assert_eq!(entries.len(), GDT_ENTRIES);
            assert_eq!(entries[1], KERNEL_CODE);
            assert_eq!(entries[2], KERNEL_DATA);
            assert_eq!(entries[3], USER_CODE);
            assert_eq!(entries[4], USER_DATA);

            // The TSS descriptor is a two-word 64-bit TSS, present, DPL0.
            let lo = entries[5];
            assert_eq!(access_byte(lo), 0x89);
            assert_eq!(dpl(lo), 0);
            assert_eq!(limit_of(lo) as usize, TSS_LEN - 1);
            let base = base_of(lo) | (entries[6] << 32);
            assert_eq!(base, tss_base(cpu));
        }
        // Slot 0 and slot 1 must not describe the same TSS.
        assert_ne!(entries_for(0)[5], entries_for(1)[5]);
    }

    #[test]
    fn page_descriptors_relocate_to_the_trampoline_page() {
        // The trampoline's 32-bit descriptors carry the page's physical base so
        // the stub runs at its identity address; limit 64 KiB, G=0, D=1.
        let page = 0x0009_0000u64;
        let code = code32_descriptor(page);
        let data = data32_descriptor(page);
        assert_eq!(base_of(code), page);
        assert_eq!(base_of(data), page);
        assert_eq!(limit_of(code), 0xFFFF);
        assert_eq!(access_byte(code), 0x9A);
        assert_eq!(access_byte(data), 0x92);
        assert!(default_op_size(code));
        assert!(!long_mode(code));
        // The 64-bit descriptors installed in the running kernel stay flat.
        assert_eq!(base_of(code64_descriptor()), 0);
        assert!(long_mode(code64_descriptor()));
        assert_eq!(code64_descriptor(), KERNEL_CODE);
        assert_eq!(data64_descriptor(), KERNEL_DATA);
    }
}
