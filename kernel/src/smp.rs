//! Application-processor bring-up (M6b1).
//!
//! # The problem
//!
//! An application processor (AP) wakes up in **16-bit real mode** at the
//! physical address the BSP put in the `SIPI` vector (`vector << 12`), with
//! `CS = vector << 8`, `IP = 0`, `CR0.PE = 0`, paging off and `IF = 0`. The
//! kernel runs in long mode at a high-half virtual address, so the AP has to
//! climb three rungs — real mode → 32-bit protected mode → 64-bit long mode —
//! before it can execute a single line of Rust.
//!
//! # The trampoline page
//!
//! The BSP reserves one low physical page (`pmm::reserve_low_page`) and maps it
//! **identity** (`vm::identity_map_page`), because the real-mode code can only
//! address its own identity address. The page holds [`TEMPLATE_BYTES`] bytes of
//! position-independent stub (assembled below) and a small data area:
//!
//! ```text
//! 0x0000  real-mode stub: set up flat segments, load the page GDT, set PE,
//!         far-jump to the 32-bit stub
//! 0x0030  GDTR: limit 0x27, base = page + 0x80 (patched by the BSP)
//! 0x0040  mailbox (64 bytes): cr3, stack, entry, cpu, page_base, status, apic
//! 0x0080  page GDT: null | 32-bit code | 32-bit data | 64-bit code | 64-bit data
//! 0x0400  32-bit stub: load CR3, PAE/OSFXSR/OSXMMEXCPT, EFER.LME|NXE|SCE,
//!         CR0.PG|WP|PE, then far-jump to the 64-bit stub
//! 0x0600  64-bit stub: load the AP stack, pass cpu + page_base, jump to Rust
//! 0x0F00  scratch stack used by the real-mode and 32-bit stubs
//! ```
//!
//! Every intra-page reference inside the stub is a **label** resolved by the
//! assembler, so the code is fully relocatable: only the GDTR base, the page
//! GDT bases and the mailbox contents are patched after the copy. That is what
//! lets the page live at whatever lowest free frame the BSP found instead of a
//! hard-coded address.
//!
//! # Sequence (one AP at a time)
//!
//! `smp::init` starts the APs strictly one after another; there is a single
//! mailbox and a single trampoline page, so only one AP is ever in flight:
//!
//! 1. BSP patches the mailbox for AP *i* (stack top, Rust entry, cpu index,
//!    page physical) and publishes `status = Pending`.
//! 2. BSP sends `INIT` (level-triggered assert then de-assert), waits one tick
//!    (≥ 10 ms, the architectural INIT delay), sends `SIPI` twice one tick
//!    apart (the second one catches an AP that missed the first APIC delivery).
//! 3. The AP runs the stub and enters [`ap_entry`], which programs its TSS/GDT/
//!    IDT/MSRs, enables its own LAPIC, then stores `status = Online` with
//!    **Release** ordering and idles with `cli; hlt`.
//! 4. BSP polls `status` with **Acquire** ordering for at most
//!    [`ONLINE_WAIT_TICKS`] ticks. All prior AP writes are then visible.
//!
//! BSP waiting must happen with interrupts **enabled**: every wait is
//! `time::wait_for_ticks`, which idles on `sti; hlt`, and the timer tick is what
//! advances `time`. The two short BSP bookkeeping sections (identity map +
//! patch, and unmap + release) run in a `cli` window because the page-table and
//! PMM code require `IF = 0`.
//!
//! # M6b1 boundary
//!
//! An AP ends up online, with its own GDT/TSS/IST stacks/GS block, `IF = 0` and
//! no timer: it never enters the scheduler and owns no run queue. Per-CPU run
//! queues, cross-CPU wakeups and IPIs are M6b2. The boot processor's ring3 and
//! `syscall` paths are untouched: slot 0 of every per-CPU structure stays the
//! BSP's, and [`arch::cpu_index`] returns 0 there.
//!
//! # Failure policy
//!
//! On success the identity mapping is torn down and the page frame returned to
//! the PMM. On any failure the low page is deliberately **left** mapped and
//! reserved so the failure can be inspected in QEMU (its content is the last
//! trampoline state plus the mailbox status), and `Err(reason)` is returned.

use core::sync::atomic::{AtomicU32, AtomicUsize, Ordering};

use crate::arch;
use crate::arch::{gdt, idt, syscall, tss};
use crate::mm::{pmm, vm};
use crate::platform;
use crate::sched;
use crate::sync::IrqSpinLock;
use crate::time;

/// Page size used everywhere in the trampoline (4 KiB, no large pages).
const PAGE_SIZE: u64 = 4096;
/// Size of the copied trampoline image: exactly one page.
const TEMPLATE_BYTES: usize = 0x1000;

// Page layout. The offsets must match the `.org` directives in `TRAMPOLINE_ASM`
// below; `template_labels_match_the_layout` pins them.
const GDTR_OFFSET: usize = 0x0030;
const MAILBOX_OFFSET: usize = 0x0040;
const PAGE_GDT_OFFSET: usize = 0x0080;
#[cfg(test)]
const PM_ENTRY_OFFSET: usize = 0x0400;
#[cfg(test)]
const STUB_ENTRY64_OFFSET: usize = 0x0600;
#[cfg(test)]
const STUB_STACK_TOP: u64 = 0x0F00;

// Mailbox fields (all 8 bytes, `u64`).
const MAILBOX_CR3: usize = 0x00;
const MAILBOX_STACK: usize = 0x08;
const MAILBOX_ENTRY: usize = 0x10;
const MAILBOX_CPU: usize = 0x18;
const MAILBOX_PAGE_BASE: usize = 0x20;
const MAILBOX_STATUS: usize = 0x28;
const MAILBOX_APIC: usize = 0x30;

/// `status` value before the AP has done anything (written by the BSP).
const STATUS_PENDING: u64 = 0;
/// `status` value the AP publishes once every per-CPU structure is ready.
const STATUS_ONLINE: u64 = 1;
/// `status` value the AP publishes if its LAPIC could not be enabled.
const STATUS_FAILED: u64 = 2;

/// Ticks to wait for one AP to come online (100 Hz ⇒ 200 ms).
const ONLINE_WAIT_TICKS: u64 = 20;
/// Ticks to wait after `INIT` before the first `SIPI` (≥ 10 ms).
const INIT_DELAY_TICKS: u64 = 1;
/// Ticks between the two `SIPI`s.
const SIPI_GAP_TICKS: u64 = 1;

// ---------------------------------------------------------------------------
// Entry stub (16-bit → 32-bit → 64-bit)
// ---------------------------------------------------------------------------

// The position-independent trampoline image.
//
// Assembled into its own read-only section so it is never executed in place;
// [`fill_page`] copies it into the reserved low page and patches the
// addresses that cannot be position independent. All internal jumps and
// memory references are assembler labels, so the copy can land anywhere.
//
// The block must stay exactly [`TEMPLATE_BYTES`] long, which is why it ends
// with `.org 0x1000`.
//
// `global_asm!` in x86 targets accepts **Intel** syntax; AT&T registers
// (`%cs`) are rejected by the assembler.
core::arch::global_asm!(
    r#"
    .section .rodata.caelum_ap_trampoline,"a"
    .align 16
    .globl caelum_ap_trampoline
caelum_ap_trampoline:
    .code16
    cli
    mov ax, cs
    mov ds, ax
    mov es, ax
    mov ss, ax
    mov sp, 0x0F00
    lgdt [0x0030]
    mov eax, cr0
    or eax, 1
    mov cr0, eax
    // Explicit far jump (opcode EA, offset16, selector16) instead of
    // push/push/retf: no stack traffic, so a 16-vs-32-bit pop mismatch cannot
    // be the reason the transition fails.
    .byte 0xEA
    .short 0x0400
    .short 0x0008

    .org 0x30
    .globl caelum_ap_gdtr
caelum_ap_gdtr:
    .short 0x0027
    .long 0

    .org 0x40
    .globl caelum_ap_mailbox
caelum_ap_mailbox:
    .quad 0
    .quad 0
    .quad 0
    .quad 0
    .quad 0
    .quad 0
    .quad 0
    .quad 0

    .org 0x80
    .globl caelum_ap_page_gdt
caelum_ap_page_gdt:
    .quad 0
    .quad 0
    .quad 0
    .quad 0
    .quad 0

    .org 0x400
    .code32
    .globl caelum_ap_pm_entry
caelum_ap_pm_entry:
    mov ax, 0x10
    mov ds, ax
    mov es, ax
    mov ss, ax
    mov esp, 0x0F00
    mov eax, [0x0040]
    mov cr3, eax
    mov eax, cr4
    or eax, 0x620
    mov cr4, eax
    mov ecx, 0xC0000080
    rdmsr
    or eax, 0x901
    wrmsr
    mov eax, cr0
    or eax, 0x80010001
    mov cr0, eax
    push 0x0018
    mov eax, [0x0060]
    add eax, 0x0600
    push eax
    retf

    .org 0x600
    .code64
    .globl caelum_ap_entry64
caelum_ap_entry64:
    lea rax, [rip + caelum_ap_mailbox]
    mov rsp, [rax + 0x08]
    mov rsi, [rax + 0x20]
    mov rdi, [rax + 0x18]
    mov rcx, [rax + 0x10]
    sub rsp, 8
    jmp rcx

    .org 0xF00
    .globl caelum_ap_stub_stack
caelum_ap_stub_stack:
    .org 0x1000
"#
);

unsafe extern "C" {
    /// First byte of the trampoline image (its `.rodata` section start).
    static caelum_ap_trampoline: u8;
    /// 16-bit-mode GDTR: `{ limit: u16, base: u32 }` at offset 0x20.
    #[cfg(test)]
    static caelum_ap_gdtr: u8;
    /// Mailbox at offset 0x30.
    #[cfg(test)]
    static caelum_ap_mailbox: u8;
    /// Five-entry page GDT at offset 0x80.
    #[cfg(test)]
    static caelum_ap_page_gdt: u8;
    /// 32-bit protected-mode stub at offset 0x400.
    #[cfg(test)]
    static caelum_ap_pm_entry: u8;
    /// 64-bit stub at offset 0x600.
    #[cfg(test)]
    static caelum_ap_entry64: u8;
    /// Scratch stack top used by the real-mode and 32-bit stubs (offset 0xF00).
    #[cfg(test)]
    static caelum_ap_stub_stack: u8;
}

// ---------------------------------------------------------------------------
// Trampoline page construction
// ---------------------------------------------------------------------------

/// Write one `u64` into the trampoline page at `offset`.
///
/// # Safety
///
/// `page` must point at the (writable) identity-mapped trampoline page and
/// `offset` must leave room for eight bytes inside it.
unsafe fn write_u64(page: *mut u8, offset: usize, value: u64) {
    debug_assert!(offset + 8 <= TEMPLATE_BYTES);
    // SAFETY: caller guarantees the page is writable and the range fits.
    unsafe { page.add(offset).cast::<u64>().write_unaligned(value) };
}

/// Write one `u32` into the trampoline page at `offset`.
///
/// # Safety
///
/// Same contract as [`write_u64`], for four bytes.
unsafe fn write_u32(page: *mut u8, offset: usize, value: u32) {
    debug_assert!(offset + 4 <= TEMPLATE_BYTES);
    // SAFETY: caller guarantees the page is writable and the range fits.
    unsafe { page.add(offset).cast::<u32>().write_unaligned(value) };
}

/// Read one `u64` from the trampoline page at `offset` (host tests only).
///
/// # Safety
///
/// `page` must point at the identity-mapped trampoline page.
#[cfg(test)]
unsafe fn read_u64(page: *mut u8, offset: usize) -> u64 {
    debug_assert!(offset + 8 <= TEMPLATE_BYTES);
    // SAFETY: caller guarantees the range is inside the page.
    unsafe { page.add(offset).cast::<u64>().read_unaligned() }
}

/// Copy the stub into `page` and patch everything that depends on where the
/// page physically is.
///
/// Patched: the GDTR base (16-bit mode cannot load a 32-bit base from a Rust
/// value), the two 32-bit descriptors of the page GDT (their base is the page
/// physical address), and the mailbox's `cr3`/`page_base` fields. Everything
/// else in the stub is position independent.
///
/// # Safety
///
/// `page` must be the identity-mapped trampoline page (writable, `IF = 0`) and
/// `page_phys` must be that page's physical address.
unsafe fn fill_page(page: *mut u8, page_phys: u64, kernel_pml4_phys: u64) {
    // SAFETY: the template is `TEMPLATE_BYTES` long (pinned by a test and by
    // the `.org 0x1000`), the destination is a writable page, and the two
    // ranges do not overlap (one is kernel `.rodata`, the other a PMM frame).
    unsafe {
        core::ptr::copy_nonoverlapping(
            core::ptr::addr_of!(caelum_ap_trampoline),
            page,
            TEMPLATE_BYTES,
        );

        // 16-bit `lgdt` reads GDTR{limit: u16, base: u32}; only the base is
        // dynamic. The base points at the page GDT (offset 0x80), **not** at
        // the page itself: the 16-bit stub reaches its protected-mode entry
        // through a far return whose selector must resolve against that table.
        write_u32(
            page,
            GDTR_OFFSET + 2,
            (page_phys + PAGE_GDT_OFFSET as u64) as u32,
        );

        // Page GDT. Entry 0 **must** be the null descriptor: the 16-bit stub
        // far-returns through selector 0x08 (index 1) and the 32-bit stub jumps
        // with selector 0x18 (index 3), so every descriptor sits at
        // `selector_index * 8` — writing the pair one slot early made the AP
        // load a data descriptor as CS and triple fault.
        write_u64(page, PAGE_GDT_OFFSET, 0);
        write_u64(page, PAGE_GDT_OFFSET + 8, gdt::code32_descriptor(page_phys));
        write_u64(
            page,
            PAGE_GDT_OFFSET + 16,
            gdt::data32_descriptor(page_phys),
        );
        write_u64(page, PAGE_GDT_OFFSET + 24, gdt::code64_descriptor());
        write_u64(page, PAGE_GDT_OFFSET + 32, gdt::data64_descriptor());

        // Mailbox: the AP loads CR3 from it and derives its stack/entry/cpu
        // index from the same block; `page_base` is the address the AP uses to
        // publish its status.
        write_u64(page, MAILBOX_OFFSET + MAILBOX_CR3, kernel_pml4_phys);
        write_u64(page, MAILBOX_OFFSET + MAILBOX_PAGE_BASE, page_phys);
    }
}

/// Mailbox field `offset` of the trampoline page as an atomic pointer.
///
/// # Safety
///
/// `page` must be the identity-mapped trampoline page; every mailbox field is
/// 8-byte aligned inside the page (`0x30 + 0x08 * n`).
fn mailbox_atomic(page: u64, offset: usize) -> *mut core::sync::atomic::AtomicU64 {
    debug_assert!(page % 8 == 0);
    debug_assert!(offset % 8 == 0);
    (page + offset as u64) as *mut core::sync::atomic::AtomicU64
}

fn mailbox_status(page: u64) -> *mut core::sync::atomic::AtomicU64 {
    mailbox_atomic(page, MAILBOX_OFFSET + MAILBOX_STATUS)
}

/// Compute and validate the `SIPI` vector for `trampoline_phys`.
///
/// The 8-bit SIPI vector is a **page number**, not an interrupt vector:
/// `entry page = vector << 12`. The architectural limit is therefore
/// `vector in 1..=255` (page 0 is reserved for the real-mode IVT/BDA, and 255
/// pages is exactly the 1 MiB the real-mode entry can address), which
/// [`vm::SIPI_MAX_PHYS`] encodes. Page 0 is rejected because the project
/// reserves it.
fn startup_vector(trampoline_phys: u64) -> Result<u8, &'static str> {
    if trampoline_phys == 0
        || trampoline_phys % PAGE_SIZE != 0
        || trampoline_phys >= vm::SIPI_MAX_PHYS
    {
        return Err("smp-trampoline-page");
    }
    let vector = (trampoline_phys / PAGE_SIZE) as u8;
    if vector == 0 {
        return Err("smp-trampoline-page");
    }
    Ok(vector)
}

// ---------------------------------------------------------------------------
// AP entry (Rust side)
// ---------------------------------------------------------------------------

/// First Rust code on an application processor.
///
/// Runs with `IF = 0`, the kernel page tables active (shared CR3), the AP's own
/// 16 KiB kernel stack from `vm::map_cpu_stack`, and `rdi = cpu index`,
/// `rsi = trampoline page physical`.
///
/// Order matters: the TSS comes first (the GDT descriptor written next points
/// at it), then the GDT (`ltr` loads the TSS), then the IDT (`lidt` is per-CPU
/// even though the table is shared — some gates use IST1/IST2, which only work
/// with `TR` loaded), then the `syscall` GS block and MSRs, and only then the
/// LAPIC. Publishing `Online` with Release ordering makes every one of those
/// writes visible to the BSP polling the mailbox.
///
/// M6b1 ended here with `cli; hlt`. M6b2 hands the AP to `sched::ap_idle`, which
/// idles with interrupts **enabled** and no timer, so a fixed reschedule IPI can
/// wake it; the per-CPU scheduler only takes over when the root calls
/// `sched::enable_smp_scheduler` and sends vector 0x41.
extern "C" fn ap_entry(cpu_index: u64, trampoline_phys: u64) -> ! {
    let cpu = cpu_index as usize;
    tss::init_cpu(cpu);
    gdt::install(cpu);
    idt::load();
    syscall::init_percpu(cpu);

    let status = match platform::enable_local_apic() {
        Ok(()) => STATUS_ONLINE,
        Err(_) => STATUS_FAILED,
    };
    // SAFETY: the trampoline page is identity mapped until the BSP has seen
    // every AP's final status, and the field is 8-byte aligned.
    unsafe {
        (*mailbox_status(trampoline_phys)).store(status, Ordering::Release);
    }

    // M6b2a: an online AP briefly waits for the BSP's lock self test, takes part
    // if it is asked to, and then goes idle. The wait is bounded by iteration
    // count, so a boot path that never calls `lock_selftest` still parks the AP
    // instead of spinning.
    if status == STATUS_ONLINE {
        ap_run_lock_selftest(cpu);
        // M6b2: M6b1 parked the AP with `cli; hlt`, which a fixed reschedule IPI
        // cannot wake. It now idles with `IF = 1` and **no timer**; the root
        // enables per-CPU scheduling later (`sched::enable_smp_scheduler` +
        // vector 0x41), and only then does `sched::ap_main` install the AP's
        // local LAPIC timer. Spurious interrupts are the only other thing that
        // can arrive: the IOAPIC still routes every device IRQ to the BSP.
        sched::ap_idle(cpu);
    }
    loop {
        arch::halt();
    }
}

// ---------------------------------------------------------------------------
// BSP-side bring-up
// ---------------------------------------------------------------------------

/// Number of application processors that completed bring-up.
static ONLINE_APS: AtomicUsize = AtomicUsize::new(0);

/// How many application processors are online (boot processor excluded).
///
/// After [`init`] returns `Ok`, this is the final value: it equals the number
/// of enabled non-BSP processors in the MADT.
pub fn online_count() -> usize {
    ONLINE_APS.load(Ordering::Acquire)
}

// ---------------------------------------------------------------------------
// Lock self test (M6b2a)
// ---------------------------------------------------------------------------

/// Nothing started yet; APs parked in their bounded wait window.
const SELFTEST_IDLE: u32 = 0;
/// The BSP is running the test; every AP must join now.
const SELFTEST_RUNNING: u32 = 1;
/// The test is over; APs must stop waiting and park.
const SELFTEST_FINISHED: u32 = 2;

/// Increments each participating CPU performs inside the lock.
const SELFTEST_ITERATIONS: u64 = 10_000;
/// Bounded spins an AP waits for the BSP to start the test (a few ms).
const SELFTEST_AP_WAIT_SPINS: u64 = 50_000_000;
/// Bounded spins the BSP waits for every AP to finish its share.
const SELFTEST_DONE_WAIT_SPINS: u64 = 200_000_000;

/// Start mailbox: written by the BSP, polled by the APs with `Acquire`.
static SELFTEST_STATE: AtomicU32 = AtomicU32::new(SELFTEST_IDLE);
/// Done mailbox: incremented by each AP with `Release` after its share.
static SELFTEST_DONE: AtomicU32 = AtomicU32::new(0);
/// The lock under test; the only writer of [`SELFTEST_DATA`].
static SELFTEST_LOCK: IrqSpinLock = IrqSpinLock::new();

/// Payload the lock protects (no atomics inside: the lock is the barrier).
struct SelftestData {
    counter: u64,
    per_cpu: [u64; arch::MAX_CPUS],
}

static mut SELFTEST_DATA: SelftestData = SelftestData {
    counter: 0,
    per_cpu: [0; arch::MAX_CPUS],
};

/// One guarded increment of the shared counter and of the per-CPU tally.
fn selftest_increment(cpu: usize) {
    SELFTEST_LOCK.with(|| {
        // SAFETY: the payload is only ever touched while `SELFTEST_LOCK` is
        // held, and the lock is held on this CPU for the whole update.
        let data = unsafe { &mut *core::ptr::addr_of_mut!(SELFTEST_DATA) };
        data.counter += 1;
        data.per_cpu[cpu] += 1;
    });
}

/// AP side: join the test if the BSP starts it inside the bounded window.
fn ap_run_lock_selftest(cpu: usize) {
    let mut spins = 0u64;
    while SELFTEST_STATE.load(Ordering::Acquire) != SELFTEST_RUNNING {
        if spins >= SELFTEST_AP_WAIT_SPINS {
            // No test was started: go idle exactly as in M6b1.
            return;
        }
        spins += 1;
        core::hint::spin_loop();
    }
    for _ in 0..SELFTEST_ITERATIONS {
        selftest_increment(cpu);
    }
    SELFTEST_DONE.fetch_add(1, Ordering::Release);
}

/// Check the observed totals. Pure, so host tests can cover the state machine.
fn verify_selftest(total: u64, per_cpu: &[u64], aps: usize) -> Result<u64, &'static str> {
    if per_cpu.len() < aps + 1 {
        return Err("sync-counter");
    }
    let expected = SELFTEST_ITERATIONS * (aps as u64 + 1);
    if total != expected {
        return Err("sync-counter");
    }
    let mut sum = 0u64;
    for count in per_cpu.iter().take(aps + 1) {
        if *count == 0 {
            return Err("sync-cpu");
        }
        sum += *count;
    }
    if sum != total {
        return Err("sync-counter");
    }
    Ok(total)
}

/// Stress [`IrqSpinLock`] with every online CPU at once.
///
/// The BSP and each online AP take the same lock [`SELFTEST_ITERATIONS`] times
/// and bump a shared counter plus a per-CPU tally. The BSP publishes
/// `SELFTEST_RUNNING` with `Release`, waits (bounded, spinning) for every AP's
/// `Release` increment of the done mailbox, and then verifies the totals:
/// the counter must be `iterations * (aps + 1)` and **every** participating CPU
/// must show a non-zero tally, which proves all four CPUs really entered the
/// critical section.
///
/// Must be called once, right after [`init`] returned `Ok(())`, with interrupts
/// enabled and before the scheduler starts on any AP. It does not print: the
/// caller owns the diagnostic output. Returns the verified counter value, or a
/// static reason:
///
/// * `sync-not-ready` — no AP is online (M6b1 failed or single-CPU machine);
/// * `sync-selftest-repeated` — the test already ran;
/// * `sync-ap-timeout` — an AP missed the start window or never finished;
/// * `sync-counter` / `sync-cpu` — the totals did not add up.
///
/// Host tests can only cover the pure state machine: a single-threaded host
/// cannot demonstrate mutual exclusion, only the accounting and the bounded
/// failure paths.
pub fn lock_selftest() -> Result<u64, &'static str> {
    let aps = online_count();
    if aps == 0 {
        return Err("sync-not-ready");
    }
    if aps + 1 > arch::MAX_CPUS {
        return Err("sync-counter");
    }
    if SELFTEST_STATE
        .compare_exchange(
            SELFTEST_IDLE,
            SELFTEST_RUNNING,
            Ordering::AcqRel,
            Ordering::Acquire,
        )
        .is_err()
    {
        return Err("sync-selftest-repeated");
    }

    for _ in 0..SELFTEST_ITERATIONS {
        selftest_increment(0);
    }

    let mut spins = 0u64;
    while (SELFTEST_DONE.load(Ordering::Acquire) as usize) < aps {
        if spins >= SELFTEST_DONE_WAIT_SPINS {
            SELFTEST_STATE.store(SELFTEST_FINISHED, Ordering::Release);
            return Err("sync-ap-timeout");
        }
        spins += 1;
        core::hint::spin_loop();
    }

    // Snapshot under the lock, then publish the end of the test.
    let (total, per_cpu) = SELFTEST_LOCK.with(|| {
        // SAFETY: the payload is only read while the lock is held.
        let data = unsafe { &mut *core::ptr::addr_of_mut!(SELFTEST_DATA) };
        (data.counter, data.per_cpu)
    });
    SELFTEST_STATE.store(SELFTEST_FINISHED, Ordering::Release);
    verify_selftest(total, &per_cpu[..=aps], aps)
}

/// Bring every enabled application processor online.
///
/// `trampoline_phys` is a page the caller reserved with
/// `pmm::reserve_low_page(&boot::state().map, vm::SIPI_MAX_PHYS)`; this function
/// identity maps it, fills it, starts the APs and — on success — unmaps it and
/// returns the frame to the PMM. `kernel_pml4_phys` is the physical address of
/// the kernel's PML4 (`VmSummary::pml4_phys`), which every AP loads into CR3 so
/// it shares the kernel address space.
///
/// Returns `Ok(())` when all APs are online; with no APs (single-CPU machine)
/// it releases the page and returns `Ok(())` as well. On failure the low page
/// is left mapped and reserved for post-mortem inspection.
///
/// Interrupts must be enabled: the waits use `time::wait_for_ticks`, which
/// idles on `sti; hlt` and needs timer ticks. The two bookkeeping sections run
/// with interrupts disabled because the page-table and PMM APIs require it.
pub fn init(trampoline_phys: u64, kernel_pml4_phys: u64) -> Result<(), &'static str> {
    let vector = startup_vector(trampoline_phys)?;
    if kernel_pml4_phys == 0 || kernel_pml4_phys % PAGE_SIZE != 0 {
        return Err("smp-kernel-cr3");
    }

    let bsp = platform::bsp_apic_id().ok_or("smp-not-ready")?;
    let entries = platform::cpus();
    if entries.is_empty() {
        return Err("smp-not-ready");
    }

    // Collect the enabled APs in MADT order. Slot 0 of every per-CPU
    // structure is the boot processor, so AP `i` (0-based) uses cpu index
    // `i + 1`.
    let mut apic_ids = [0u8; arch::MAX_CPUS];
    let mut ap_count = 0usize;
    for entry in entries {
        if !entry.enabled || entry.apic_id == bsp {
            continue;
        }
        if ap_count + 1 >= arch::MAX_CPUS {
            return Err("smp-cpu-index");
        }
        apic_ids[ap_count] = entry.apic_id;
        ap_count += 1;
    }

    if ap_count == 0 {
        // Single-CPU machine: nothing to start, give the page back.
        pmm::release_frame(trampoline_phys);
        return Ok(());
    }

    // --- setup window: page tables and PMM want interrupts disabled ---------
    let interrupts_were_enabled = arch::disable_interrupts();
    // SAFETY: CALLER contract; page tables are not shared with another CPU
    // while we hold interrupts off on the only running CPU, and the PMM page
    // was reserved by the caller.
    if unsafe { vm::identity_map_page(trampoline_phys) }.is_err() {
        arch::restore_interrupts(interrupts_were_enabled);
        return Err("smp-identity");
    }
    let page_virt = vm::phys_to_virt(trampoline_phys);
    // SAFETY: the page is identity mapped and writable, and we are the only
    // CPU touching it (APs are not started yet).
    unsafe { fill_page(page_virt as *mut u8, trampoline_phys, kernel_pml4_phys) };

    let mut stacks = [0u64; arch::MAX_CPUS];
    for (index, stack) in stacks.iter_mut().enumerate().take(ap_count) {
        // SAFETY: TAKEOVER_DONE (the kernel owns CR3), interrupts disabled;
        // each AP gets its own high-half stack slot.
        match unsafe { vm::map_cpu_stack(index) } {
            Ok(top) => *stack = top,
            Err(_) => {
                arch::restore_interrupts(interrupts_were_enabled);
                return Err("smp-cpu-stack");
            }
        }
    }
    arch::restore_interrupts(interrupts_were_enabled);
    let rust_entry: extern "C" fn(u64, u64) -> ! = ap_entry;
    for index in 0..ap_count {
        // AP `index` owns cpu slot `index + 1` (slot 0 is the BSP).
        let cpu_slot = index + 1;
        // SAFETY: the page is still identity mapped; writes are plain qwords.
        unsafe {
            write_u64(
                page_virt as *mut u8,
                MAILBOX_OFFSET + MAILBOX_STACK,
                stacks[index],
            );
            write_u64(
                page_virt as *mut u8,
                MAILBOX_OFFSET + MAILBOX_ENTRY,
                rust_entry as usize as u64,
            );
            write_u64(
                page_virt as *mut u8,
                MAILBOX_OFFSET + MAILBOX_CPU,
                cpu_slot as u64,
            );
            write_u64(
                page_virt as *mut u8,
                MAILBOX_OFFSET + MAILBOX_APIC,
                u64::from(apic_ids[index]),
            );
            (*mailbox_status(page_virt)).store(STATUS_PENDING, Ordering::Release);
        }

        platform::send_init_ipi(apic_ids[index]).map_err(|_| "smp-init-ipi")?;
        time::wait_for_ticks(INIT_DELAY_TICKS);
        platform::send_startup_ipi(apic_ids[index], vector).map_err(|_| "smp-sipi")?;
        time::wait_for_ticks(SIPI_GAP_TICKS);
        platform::send_startup_ipi(apic_ids[index], vector).map_err(|_| "smp-sipi")?;

        wait_online(page_virt)?;
        ONLINE_APS.fetch_add(1, Ordering::Release);
    }

    // --- teardown window: drop the identity mapping, return the frame ------
    let interrupts_were_enabled = arch::disable_interrupts();
    // SAFETY: CALLER contract; no AP touches the page any more (each published
    // its final status before the BSP observed it), interrupts disabled.
    let unmap = unsafe { vm::identity_unmap_page(trampoline_phys) };
    arch::restore_interrupts(interrupts_were_enabled);
    unmap.map_err(|_| "smp-identity")?;
    pmm::release_frame(trampoline_phys);
    Ok(())
}

/// Poll the mailbox until the AP publishes its final status.
///
/// Each iteration waits one tick with interrupts enabled, so the AP has time to
/// finish the long part of its bring-up (GDT/IDT/MSR/LAPIC).
fn wait_online(page_virt: u64) -> Result<(), &'static str> {
    for _ in 0..ONLINE_WAIT_TICKS {
        time::wait_for_ticks(1);
        // SAFETY: the page is identity mapped; Acquire pairs with the AP's
        // Release store, making its prior writes visible.
        let status = unsafe { (*mailbox_status(page_virt)).load(Ordering::Acquire) };
        match status {
            STATUS_ONLINE => return Ok(()),
            STATUS_FAILED => return Err("smp-apic-init"),
            _ => {}
        }
    }
    Err("smp-ap-timeout")
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// An aligned buffer standing in for the identity-mapped page.
    #[repr(align(4096))]
    struct Page([u8; TEMPLATE_BYTES]);

    /// Descriptor word the CPU resolves for `selector` from the page GDT.
    fn page_descriptor(page: &[u8], selector: u16) -> u64 {
        let start = PAGE_GDT_OFFSET + usize::from(selector >> 3) * 8;
        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(&page[start..start + 8]);
        u64::from_le_bytes(bytes)
    }

    fn descriptor_present(word: u64) -> bool {
        (word >> 47) & 1 == 1
    }

    fn descriptor_access(word: u64) -> u8 {
        ((word >> 40) & 0xFF) as u8
    }

    fn descriptor_long_mode(word: u64) -> bool {
        (word >> 53) & 1 == 1
    }

    fn descriptor_base(word: u64) -> u64 {
        ((word >> 16) & 0xFFFF) | (((word >> 32) & 0xFF) << 16) | (((word >> 56) & 0xFF) << 24)
    }

    fn descriptor_limit(word: u64) -> u32 {
        ((((word >> 48) & 0xF) << 16) as u32) | ((word & 0xFFFF) as u32)
    }

    #[test]
    fn template_labels_match_the_layout() {
        // SAFETY: these symbols are labels inside the trampoline section; taking
        // their address does not dereference them.
        let base = core::ptr::addr_of!(caelum_ap_trampoline) as usize;
        let gdtr = core::ptr::addr_of!(caelum_ap_gdtr) as usize - base;
        let mailbox = core::ptr::addr_of!(caelum_ap_mailbox) as usize - base;
        let page_gdt = core::ptr::addr_of!(caelum_ap_page_gdt) as usize - base;
        let pm_entry = core::ptr::addr_of!(caelum_ap_pm_entry) as usize - base;
        let entry64 = core::ptr::addr_of!(caelum_ap_entry64) as usize - base;
        let stub_stack = core::ptr::addr_of!(caelum_ap_stub_stack) as usize - base;
        assert_eq!(gdtr, GDTR_OFFSET);
        assert_eq!(mailbox, MAILBOX_OFFSET);
        assert_eq!(page_gdt, PAGE_GDT_OFFSET);
        assert_eq!(pm_entry, PM_ENTRY_OFFSET);
        assert_eq!(entry64, STUB_ENTRY64_OFFSET);
        assert_eq!(stub_stack as u64, STUB_STACK_TOP);
        // The real-mode stub starts with `cli`.
        // SAFETY: the template symbol is a byte array in `.rodata`.
        assert_eq!(unsafe { *core::ptr::addr_of!(caelum_ap_trampoline) }, 0xFA);
    }

    #[test]
    fn page_layout_has_room_for_every_region() {
        assert!(GDTR_OFFSET + 6 <= MAILBOX_OFFSET);
        assert!(MAILBOX_OFFSET + MAILBOX_APIC + 8 <= PAGE_GDT_OFFSET);
        assert!(PAGE_GDT_OFFSET + 5 * 8 <= PM_ENTRY_OFFSET);
        assert!(PM_ENTRY_OFFSET < STUB_ENTRY64_OFFSET);
        assert!(STUB_ENTRY64_OFFSET < STUB_STACK_TOP as usize);
        assert!(STUB_STACK_TOP as usize <= TEMPLATE_BYTES);
        assert_eq!(TEMPLATE_BYTES as u64, PAGE_SIZE);
        // The mailbox must not overlap the GDTR the stub loads.
        assert!(MAILBOX_OFFSET >= GDTR_OFFSET + 6);
    }

    #[test]
    fn fill_page_patches_gdtr_gdt_and_mailbox() {
        let mut page = Page([0u8; TEMPLATE_BYTES]);
        let page_phys = 0x0009_0000u64;
        let cr3 = 0x0012_3000u64;
        // SAFETY: `page` is a 4 KiB aligned, writable, exclusively used buffer.
        unsafe {
            fill_page(page.0.as_mut_ptr(), page_phys, cr3);
            let ptr = page.0.as_mut_ptr();
            // GDTR: limit 0x27, base = page GDT (page + 0x80), not the page.
            assert_eq!(
                read_u64(ptr, GDTR_OFFSET),
                0x0027 | ((page_phys + PAGE_GDT_OFFSET as u64) << 16)
            );
            // Page GDT: entry 0 null, then 32-bit code/data at the page, then
            // the flat 64-bit kernel code/data pair. The stub addresses them by
            // **selector** (index * 8), so a one-slot shift is fatal.
            assert_eq!(read_u64(ptr, PAGE_GDT_OFFSET), 0);
            let code32 = page_descriptor(&page.0, 0x08);
            assert!(descriptor_present(code32));
            assert_eq!(descriptor_access(code32), 0x9A);
            assert_eq!(descriptor_base(code32), page_phys);
            assert_eq!(descriptor_limit(code32), 0xFFFF);
            assert!(!descriptor_long_mode(code32));
            let data32 = page_descriptor(&page.0, 0x10);
            assert_eq!(descriptor_access(data32), 0x92);
            assert_eq!(descriptor_base(data32), page_phys);
            let code64 = page_descriptor(&page.0, 0x18);
            assert!(descriptor_present(code64));
            assert!(descriptor_long_mode(code64));
            assert_eq!(descriptor_base(code64), 0);
            let data64 = page_descriptor(&page.0, 0x20);
            assert_eq!(descriptor_access(data64), 0x92);
            assert_eq!(descriptor_base(data64), 0);
            // Mailbox: CR3 to load and the page base to publish status through.
            assert_eq!(read_u64(ptr, MAILBOX_OFFSET + MAILBOX_CR3), cr3);
            assert_eq!(read_u64(ptr, MAILBOX_OFFSET + MAILBOX_PAGE_BASE), page_phys);
            // The copy really contains the real-mode stub.
            assert_eq!(*ptr, 0xFA);
        }
    }

    /// Every `mov eax, moffs32` immediate (opcode `0xA1`) in `[start, end)`.
    fn moffs32_immediates(page: &[u8], start: usize, end: usize) -> [u32; 4] {
        let mut found = [0u32; 4];
        let mut count = 0;
        let mut i = start;
        while i + 4 < end && count < found.len() {
            if page[i] == 0xA1 {
                found[count] =
                    u32::from_le_bytes([page[i + 1], page[i + 2], page[i + 3], page[i + 4]]);
                count += 1;
                i += 5;
            } else {
                i += 1;
            }
        }
        found
    }

    /// The 32-bit stub must read the two mailbox fields it needs from the
    /// **current** mailbox layout.
    ///
    /// Both bugs this guards against were invisible to the other tests: the
    /// GDTR base once pointed at the page instead of the page GDT, and the
    /// 32-bit stub kept the pre-0x30 mailbox offsets `[0x0030]` / `[0x0050]`
    /// after the mailbox moved to `0x40`. Either one makes the AP triple fault
    /// inside the first three instructions, which the BSP sees only as a frozen
    /// machine (no `M6b FAIL`, no timeout).
    #[test]
    fn protected_mode_stub_reads_the_current_mailbox_layout() {
        let mut page = Page([0u8; TEMPLATE_BYTES]);
        let page_phys = 0x0009_0000u64;
        // SAFETY: `page` is 4 KiB aligned, writable and private to this test.
        unsafe { fill_page(page.0.as_mut_ptr(), page_phys, 0x0012_3000) };
        let imms = moffs32_immediates(&page.0, PM_ENTRY_OFFSET, STUB_ENTRY64_OFFSET);
        assert!(
            imms.contains(&((MAILBOX_OFFSET + MAILBOX_CR3) as u32)),
            "CR3 is not loaded from the mailbox: {imms:?}"
        );
        assert!(
            imms.contains(&((MAILBOX_OFFSET + MAILBOX_PAGE_BASE) as u32)),
            "the page base is not read from the mailbox: {imms:?}"
        );
        // The stale offsets from before the GDTR/mailbox move must not return.
        assert!(
            !imms.contains(&0x0030),
            "stale GDTR offset used as a mail field"
        );
        assert!(
            !imms.contains(&0x0050),
            "stale entry offset used as a mail field"
        );
    }

    #[test]
    fn startup_vector_is_the_page_number() {
        assert_eq!(startup_vector(0x1000), Ok(1));
        assert_eq!(startup_vector(0x9000), Ok(9));
        assert_eq!(startup_vector(0x0F_F000), Ok(0xFF));
        assert_eq!(startup_vector(0x0C_0000), Ok(0xC0));
    }

    #[test]
    fn startup_vector_rejects_invalid_pages() {
        assert_eq!(startup_vector(0), Err("smp-trampoline-page"));
        assert_eq!(startup_vector(0x800), Err("smp-trampoline-page"));
        assert_eq!(startup_vector(0x10_0000), Err("smp-trampoline-page"));
        assert_eq!(startup_vector(0x20_0000), Err("smp-trampoline-page"));
    }

    #[test]
    fn online_count_is_zero_before_bring_up() {
        assert_eq!(online_count(), 0);
    }

    #[test]
    fn verify_selftest_accepts_full_participation() {
        let per_cpu = [SELFTEST_ITERATIONS; 4];
        assert_eq!(
            verify_selftest(SELFTEST_ITERATIONS * 4, &per_cpu, 3),
            Ok(SELFTEST_ITERATIONS * 4)
        );
        assert_eq!(
            verify_selftest(SELFTEST_ITERATIONS * 3, &per_cpu[..3], 2),
            Ok(SELFTEST_ITERATIONS * 3)
        );
    }

    #[test]
    fn verify_selftest_rejects_short_or_over_long_totals() {
        let per_cpu = [SELFTEST_ITERATIONS; 4];
        assert_eq!(
            verify_selftest(SELFTEST_ITERATIONS * 4 - 1, &per_cpu, 3),
            Err("sync-counter")
        );
        assert_eq!(
            verify_selftest(SELFTEST_ITERATIONS * 4 + 1, &per_cpu, 3),
            Err("sync-counter")
        );
        // A slice that does not even cover every participant is a counter error.
        assert_eq!(
            verify_selftest(SELFTEST_ITERATIONS * 4, &per_cpu[..2], 3),
            Err("sync-counter")
        );
    }

    #[test]
    fn verify_selftest_rejects_a_cpu_that_never_ran() {
        let mut per_cpu = [SELFTEST_ITERATIONS; 4];
        per_cpu[2] = 0;
        assert_eq!(
            verify_selftest(SELFTEST_ITERATIONS * 4, &per_cpu, 3),
            Err("sync-cpu")
        );
    }

    #[test]
    fn lock_selftest_requires_online_aps() {
        // The host never brings APs online, so the very first check must fire and
        // leave the one-shot state machine untouched.
        assert_eq!(online_count(), 0);
        assert_eq!(lock_selftest(), Err("sync-not-ready"));
        assert_eq!(
            SELFTEST_STATE.load(Ordering::Acquire),
            SELFTEST_IDLE,
            "a refused test must not consume the one-shot state"
        );
    }
}
