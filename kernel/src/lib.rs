//! CaelumOS kernel library (M4: ring3 processes, capabilities, syscalls).
//!
//! Split into a library (this crate) plus a thin binary (`src/main.rs`) so the
//! pure logic — PMM bookkeeping, heap size classes, page-table index math,
//! BootInfo state extraction, object/handle tables, ELF loading, syscall
//! argument validation — is host-testable (agents.md §21.1, §23.1). No `alloc`
//! crate, no global allocator, no third-party dependencies.
//!
//! M2 baseline (kept as regression): GDT/IDT/TSS, PMM, kernel heap,
//! higher-half VM takeover and deliberate page-fault diagnostics.
//!
//! M3 (kept as regression): ACPI/MADT -> xAPIC/IOAPIC, PIT-calibrated LAPIC
//! timer and a minimal monotonic clock, 8042 keyboard and COM1 RX interrupt
//! paths, and two kernel threads driven by cooperative yield plus timer
//! preemption.
//!
//! M4 scope (agents.md §22): native objects and capability handles, the native
//! `syscall` entry, read-only boot modules, ELF loading into per-process address
//! spaces, and two user processes (`init` spawns `child`) that prove explicit
//! handle transfer. The M3 demo now *returns* to the kernel root instead of
//! replaying the M2 page fault; the root runs the M4 sequence and the deliberate
//! `#PF` becomes the final regression marker once every user process has exited.

#![no_std]

#[cfg(test)]
extern crate std;

pub mod arch;
pub mod boot;
pub mod bootmod;
pub mod compat;
pub mod display;
pub mod futex;
pub mod image;
pub mod input;
pub mod io;
pub mod ipc;
pub mod log;
pub mod mm;
pub mod net;
pub mod object;
pub mod platform;
pub mod process;
pub mod rng;
pub mod sched;
pub mod smp;
pub mod sync;
pub mod syscall;
pub mod time;
pub mod vdso;
pub mod vfs;
pub mod vmobj;

#[cfg(not(test))]
use bootinfo::{efi_desc_pages, efi_desc_type, find_tlv, tlv_type};

/// Kernel semantic version (M7a). Keep in step with `kernel/Cargo.toml`.
pub const KERNEL_VERSION: &str = "0.16.0";

/// Top of the boot stack used by [`after_vm_takeover`].
///
/// [`mm::vm::build_kernel_tables`] puts the guard page at
/// [`mm::vm::KERNEL_STACK_VIRT`] and maps the four frames one page above it, so
/// the top is one page past the last frame (16 KiB usable). Deriving it here
/// keeps the `rsp` handed to [`mm::vm::takeover`] and the startup log line in
/// step with that layout.
pub const BOOT_STACK_TOP: u64 =
    mm::vm::KERNEL_STACK_VIRT + (mm::vm::KERNEL_STACK_FRAMES as u64 + 1) * mm::pmm::FRAME_SIZE;

/// M6b1: the low trampoline page reserved below 1 MiB for the AP bring-up.
///
/// [`mm::pmm::reserve_low_page`] derives it from the saved memory map (never a
/// hard-coded address, agents.md §22 M6b), because the SIPI startup vector is an
/// 8-bit page number and the page therefore has to live under
/// [`mm::vm::SIPI_MAX_PHYS`]. The SMP bring-up maps it identity, hands it to the
/// application processors and releases it again once they are online.
///
/// It is held in a static because [`after_vm_takeover`] is an `extern "C"
/// fn() -> !` entry point without arguments.
#[cfg(not(test))]
static TRAMPOLINE_PHYS: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

/// M6b1: physical address of the kernel PML4, handed to the AP bring-up so every
/// processor runs on the kernel's own page tables.
///
/// Visible to the rest of the crate and also compiled for host tests: the
/// per-CPU scheduling code (`sched`) reads it to decide whether an AP may be
/// started, and that read must compile in the `cfg(test)` build as well. Only
/// the boot path stores to it.
#[cfg_attr(test, allow(dead_code))]
pub(crate) static KERNEL_PML4_PHYS: core::sync::atomic::AtomicU64 =
    core::sync::atomic::AtomicU64::new(0);

/// IRQ vector numbers (agents.md §22 M3/M6b2 design decisions).
///
/// 8259 PICs are masked; all real interrupts arrive via the IOAPIC and are
/// delivered to the LAPIC. `0x40` is the software interrupt used for
/// cooperative yield, `0x41` is the reschedule IPI the boot processor sends to
/// an application processor, `0xFF` is the LAPIC spurious vector.
pub const IRQ_TIMER: u64 = 0x20;
pub const IRQ_KEYBOARD: u64 = 0x21;
pub const IRQ_COM1: u64 = 0x24;
pub const IRQ_YIELD: u64 = 0x40;
pub const IRQ_RESCHED: u64 = arch::VECTOR_RESCHED as u64;
/// Legacy virtio-net MSI-X vector (M7c): configuration, RX and TX entries all
/// deliver on this vector; the boot processor owns the EOI. The number is owned
/// by the driver (`io::VIRTIO_NET_IRQ_VECTOR`) and mirrored by
/// `arch::traps::VECTOR_NET`, which installs the IDT gate.
pub const IRQ_NET: u64 = io::VIRTIO_NET_IRQ_VECTOR as u64;
pub const IRQ_SPURIOUS: u64 = 0xFF;

/// True once an application processor may take its own timer interrupt.
///
/// Until the M6b2 closeout enables AP scheduling, every timer interrupt comes
/// from the boot processor and `arch::cpu_index()` must not be called: it reads
/// the `gs:[16]` per-CPU slot, which the M3 stage has not installed yet (it
/// faults at linear 0x10). The closeout sets this flag immediately before
/// [`sched::enable_smp_scheduler`], by which point the boot processor installed
/// its block in `complete_m4` and the APs arm their timers from `ap_main`.
#[cfg(not(test))]
static SMP_TIMERS_ARMED: core::sync::atomic::AtomicBool =
    core::sync::atomic::AtomicBool::new(false);

/// M7c: set by the virtio-net MSI-X handler when it reaped received frames.
///
/// The handler cannot run the network stack (it must not take the stack lock,
/// allocate or print), so it only records that device work is pending. The
/// thread-context poll wired up in the next M7c slice consumes this flag.
#[cfg(not(test))]
static NET_RX_PENDING: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

#[cfg(not(test))]
fn error_name(e: bootinfo::Error) -> &'static str {
    match e {
        bootinfo::Error::TooSmall => "bad-magic-or-truncated",
        bootinfo::Error::BadMagic => "bad-magic",
        bootinfo::Error::Version => "unsupported-protocol-version",
        bootinfo::Error::Abi => "unsupported-entry-abi",
        bootinfo::Error::Layout => "bad-layout",
        bootinfo::Error::Checksum => "bad-checksum",
        bootinfo::Error::MissingRequiredTlv => "missing-required-tlv",
    }
}

/// Unified IRQ dispatch, called by the arch IRQ stubs (`arch/traps.rs`) with
/// the interrupted [`arch::TrapFrame`].
///
/// Returns the frame the CPU must resume. Timer preemption and cooperative
/// yield switch to another thread's kernel stack, so the returned pointer may
/// differ from `frame`; callers must never discard it.
///
/// Rules (agents.md §22 M3/M6b2):
/// - `0x20`: `time::on_timer()` + IPC timer expiry on the BSP only, then
///   `sched::on_timer_cpu(cpu, frame)` -> EOI, return the (possibly switched)
///   frame;
/// - `0x21`: `input::on_keyboard_irq()` -> EOI;
/// - `0x24`: `input::on_serial_irq()` -> EOI;
/// - `0x40`: `sched::on_yield(frame)`, no EOI (software interrupt);
/// - `0x41`: `sched::on_reschedule(frame)`, which also writes the EOI (the
///   vector must be acknowledged or its in-service bit raises the PPR);
/// - `0xFF`: LAPIC spurious, no EOI, return unchanged;
/// - anything else: EOI and return unchanged.
///
/// Interrupt handlers must not print; logging happens in consumer context.
/// The body is compiled out of host test builds (which never take interrupts),
/// but the symbol stays defined so the exception stubs still link there.
#[unsafe(no_mangle)]
pub extern "C" fn irq_dispatch(frame: *mut arch::TrapFrame) -> *mut arch::TrapFrame {
    #[cfg(not(test))]
    {
        match unsafe { (*frame).vector } {
            IRQ_TIMER => {
                // M6b2: every CPU takes this vector, but only the boot processor
                // owns the global clock and the single-source wake paths (deadline
                // expiry, IPC timers); an application processor just counts its
                // tick and preempts its own ring3 frame.
                //
                // Before the closeout arms the AP timers this stays on the
                // single-CPU path: on the boot processor `arch::cpu_index()`
                // reads `gs:[16]`, and during M3 that per-CPU slot is still zero
                // (it is installed with the syscall MSRs in `complete_m4`).
                let next = if SMP_TIMERS_ARMED.load(core::sync::atomic::Ordering::Acquire) {
                    let cpu = arch::cpu_index();
                    if cpu == 0 {
                        time::on_timer();
                        ipc::timer::on_tick(time::monotonic_ticks());
                        // M9a: expire timerfd instances on the same tick clock.
                        ipc::timerfd::on_tick(time::monotonic_ticks());
                        // M9d2: publish the new tick to the shared vDSO page.
                        vdso::on_tick(time::monotonic_ticks());
                    }
                    sched::on_timer_cpu(cpu, frame)
                } else {
                    time::on_timer();
                    // Expire armed IPC timers on the same tick clock the waiters
                    // use, then let the scheduler account for the tick. `on_tick`
                    // only scans the 16 static timer slots and wakes processes:
                    // no allocation, no printing and no object-table access, so
                    // it is ISR-safe.
                    ipc::timer::on_tick(time::monotonic_ticks());
                    // M9a: expire timerfd instances on the same tick as well.
                    ipc::timerfd::on_tick(time::monotonic_ticks());
                    // M9d2: publish the new tick to the shared vDSO page.
                    vdso::on_tick(time::monotonic_ticks());
                    sched::on_timer(frame)
                };
                platform::eoi();
                next
            }
            IRQ_RESCHED => {
                // `sched::on_reschedule` writes the EOI for this vector itself:
                // the LAPIC leaves a fixed-delivery IPI in service until it is
                // acknowledged, and a missing EOI raises the PPR so every
                // lower-or-equal priority interrupt (the timer included) stays
                // masked. Keeping the EOI there gives the vector exactly one
                // owner and avoids clearing the timer's in-service bit here.
                sched::on_reschedule(frame)
            }
            IRQ_KEYBOARD => {
                input::on_keyboard_irq();
                platform::eoi();
                frame
            }
            IRQ_COM1 => {
                input::on_serial_irq();
                platform::eoi();
                frame
            }
            IRQ_NET => {
                // M7c: the legacy virtio-net device reports its configuration,
                // RX and TX MSI-X entries on this single vector. The handler
                // only drains the driver rings and records that received
                // frames are waiting; protocol work belongs to thread context,
                // so nothing here allocates, prints or takes the network lock.
                if io::on_irq() > 0 {
                    NET_RX_PENDING.store(true, core::sync::atomic::Ordering::Release);
                }
                platform::eoi();
                frame
            }
            IRQ_YIELD => sched::on_yield(frame),
            IRQ_SPURIOUS => frame,
            _ => {
                platform::eoi();
                frame
            }
        }
    }
    #[cfg(test)]
    {
        frame
    }
}

/// Kernel entry orchestration (called by the `_start` shim in `main.rs`).
///
/// Stage order (agents.md M2/M3 decisions):
/// 1. early serial + BootInfo validation (M1 regression),
/// 2. GDT/TSS/IDT + exception/IRQ gate setup,
/// 3. snapshot of BootInfo state (memory map + kernel image) into `.bss`,
/// 4. PMM init (metadata only),
/// 5. VM takeover (kernel W^X mapping + direct map + fresh guarded stack),
/// post-switch: PMM/heap self-tests, `M2 OK`, M3 root init (platform, time,
/// input, controlled `sti`, timer/input wait), then scheduler hand-off; the
/// M2 deliberate page fault is replayed by scheduler thread A after M3 is OK.
#[cfg(not(test))]
pub fn kernel_main(bi: u64) -> ! {
    use arch::{gdt, idt, tss};
    use boot::BootState;
    use mm::{pmm, vm};

    // 1. Earliest diagnostic output (agents.md §5.3 rule 9) + BootInfo check.
    let (port, baud) = boot::early_serial_fallback(bi);
    log::serial_init(port, baud);
    klog!(
        "[CaelumKernel] caelum-kernel v{KERNEL_VERSION} (protocol {}.{}, entry_abi {})",
        bootinfo::PROTOCOL_MAJOR,
        bootinfo::PROTOCOL_MINOR,
        bootinfo::ENTRY_ABI
    );

    let probe = bootinfo::Header::decode(unsafe {
        core::slice::from_raw_parts(bi as *const u8, bootinfo::HEADER_SIZE as usize)
    });
    let Some(probe) = probe else {
        klog!("[CaelumKernel] bootinfo validate FAIL: bad-magic; halting");
        arch::halt();
    };
    let total_size = probe.total_size;
    if total_size < bootinfo::HEADER_SIZE || total_size > bootinfo::MAX_TOTAL_SIZE {
        klog!(
            "[CaelumKernel] bootinfo validate FAIL: bad-layout (total_size {total_size}); halting"
        );
        arch::halt();
    }
    // SAFETY: the loader guarantees the BootInfo's `total_size` bytes are
    // mapped; bounded by MAX_TOTAL_SIZE above.
    let image = unsafe { core::slice::from_raw_parts(bi as *const u8, total_size as usize) };
    let header = match bootinfo::validate(image) {
        Ok(h) => h,
        Err(e) => {
            klog!(
                "[CaelumKernel] bootinfo validate FAIL: {} (header reports protocol {}.{}, loader-provided); halting",
                error_name(e),
                probe.major,
                probe.minor
            );
            arch::halt();
        }
    };
    klog!(
        "[CaelumKernel] bootinfo validate OK (CRC32C, {} TLVs)",
        header.tlv_count
    );

    // M1 informational lines (kept as regression context).
    let loader_version = find_tlv(
        image,
        header.tlv_offset,
        header.total_size,
        tlv_type::LOADER_INFO,
    )
    .map(|v| core::str::from_utf8(v).unwrap_or("?"))
    .unwrap_or("unknown");
    klog!(
        "[CaelumKernel] loader v{loader_version} | kernel v{KERNEL_VERSION} | protocol {}.{} | entry_abi {}",
        header.major,
        header.minor,
        header.entry_abi
    );
    klog!("[CaelumKernel] early serial @ port 0x{port:03x}, {baud} baud");
    if let Some(mm_val) = find_tlv(
        image,
        header.tlv_offset,
        header.total_size,
        tlv_type::MEMORY_MAP,
    ) {
        if let Some(mm) = bootinfo::MemoryMapTlv::decode(mm_val) {
            if let Some(count) = mm.descriptor_count(mm_val.len()) {
                let mut conventional_pages = 0u64;
                let desc_bytes = &mm_val[bootinfo::MemoryMapTlv::PREFIX_LEN..];
                for i in 0..count {
                    let at = i * mm.desc_size as usize;
                    if let Some(desc) = desc_bytes.get(at..at + mm.desc_size as usize) {
                        if efi_desc_type(desc) == Some(bootinfo::efi_desc::TYPE_CONVENTIONAL) {
                            conventional_pages += efi_desc_pages(desc).unwrap_or(0);
                        }
                    }
                }
                klog!(
                    "[CaelumKernel] memory: {count} UEFI descriptors, {} MiB conventional (type 7)",
                    conventional_pages / 256
                );
            }
        }
    }

    // 2. GDT/TSS/IDT (exception gates + M3 IRQ gates).
    tss::init();
    gdt::init();
    idt::init();
    klog!("[CaelumKernel] gdt/tss/idt OK (#UD/#GP/#DF(IST1)/#PF + #DE/NMI(IST2)/#SS/#AC)");

    // 3. Snapshot BootInfo into static storage (pre-takeover).
    if let Err(e) = boot::save(image, &header) {
        klog!("[CaelumKernel] boot state FAIL: {e}; halting");
        arch::halt();
    }
    let st: &BootState = boot::state();

    // 4. PMM init (metadata only; never touches the frames themselves, so it
    //    is safe before the direct map exists).
    let free = pmm::init(&st.map, &st.image);
    klog!(
        "[CaelumKernel] pmm init OK: {} MiB allocatable (conventional only, <= 1 GiB, LoaderCode/Data reserved)",
        free / 256
    );

    // 4b. M6b1: reserve one page below 1 MiB for the AP trampoline. The address
    //     comes from the saved memory map, never from a hard-coded constant, and
    //     stays reserved until the SMP bring-up has handed it to every AP.
    let trampoline_phys = match pmm::reserve_low_page(&st.map, vm::SIPI_MAX_PHYS) {
        Ok(phys) => phys,
        Err(_) => fail_m6b("no-low-page"),
    };
    TRAMPOLINE_PHYS.store(trampoline_phys, core::sync::atomic::Ordering::Relaxed);

    // 5. VM takeover.
    let mut stack_frames = [0u64; vm::KERNEL_STACK_FRAMES];
    for f in stack_frames.iter_mut() {
        match pmm::alloc_frame() {
            Ok(p) => *f = p,
            Err(_) => {
                klog!("[CaelumKernel] vm takeover FAIL: cannot allocate kernel stack; halting");
                arch::halt();
            }
        }
    }
    let summary = unsafe {
        match vm::build_kernel_tables(
            core::ptr::addr_of_mut!(vm::TABLES),
            &st.image,
            &st.map,
            &stack_frames,
        ) {
            Ok(s) => s,
            Err(e) => {
                klog!("[CaelumKernel] vm build FAIL: {e:?}; halting");
                arch::halt();
            }
        }
    };
    klog!(
        "[CaelumKernel] vm tables: kernel {} pages W^X, direct map {} MiB (2M) + {} 4K edge pages, stack {} frames + guard",
        summary.kernel_pages,
        summary.bytes_direct_2m / 1024 / 1024,
        summary.pages_direct_4k,
        summary.stack_pages
    );
    KERNEL_PML4_PHYS.store(summary.pml4_phys, core::sync::atomic::Ordering::Relaxed);
    // The guard page sits at `KERNEL_STACK_VIRT`; `build_kernel_tables` maps the
    // four stack frames one page above it, so the stack top is one page past the
    // last frame. Using `KERNEL_STACK_FRAMES * FRAME_SIZE` would point `rsp` at
    // the start of the last frame instead: the top frame would stay unused and
    // only 12 KiB of the documented 16 KiB boot stack would be reachable, which
    // the M4 `spawn_init` call chain (about 12.2 KiB) already exhausts.
    let new_rsp = BOOT_STACK_TOP;
    unsafe { vm::takeover(summary.pml4_phys, new_rsp, after_vm_takeover) }
}

/// Post-takeover continuation: runs on the fresh kernel stack with the
/// kernel's own page tables active. Never returns.
///
/// M2 regression first (PMM/heap self-tests + `M2 OK`), then the M3 root
/// init sequence in the exact order fixed by agents.md §22: platform (APIC)
/// -> time (clock) -> input -> controlled `sti` -> timer ticks -> injected
/// input events -> scheduler hand-off.
#[cfg(not(test))]
extern "C" fn after_vm_takeover() -> ! {
    use mm::{pmm, selftest};

    klog!(
        "[CaelumKernel] vm takeover OK (high-half W^X, direct map 0xffff800000000000, new stack @ 0x{:016x})",
        BOOT_STACK_TOP
    );

    // PMM poison hooks need the direct map; install them now (debug builds).
    #[cfg(debug_assertions)]
    pmm::set_kernel_debug_hooks();

    match selftest::pmm() {
        Ok(free) => klog!(
            "[CaelumKernel] pmm selftest OK ({} MiB free, alloc/dealloc restored, double-free caught)",
            free / 256
        ),
        Err(e) => {
            klog!("[CaelumKernel] pmm selftest FAIL: {e}; halting");
            arch::halt();
        }
    }
    // The virtio block devices need a contiguous DMA run; it has to be taken
    // from the frame allocator before the heap starts carving frames up.
    if let Err(reason) = io::reserve_dma() {
        fail_m5b(reason);
    }
    // M7c: the virtio-net driver needs its own contiguous DMA run (nine frames:
    // two queue pages, four receive buffers and one transmit bounce). Like the
    // block run it must be claimed from the ordered free list before the heap
    // starts carving frames up; the device itself is probed much later, after
    // the PCI platform state exists.
    if let Err(reason) = io::reserve_net_dma() {
        fail_m7c(reason);
    }
    match selftest::heap() {
        Ok(()) => klog!(
            "[CaelumKernel] heap selftest OK (classes 16..2048, large = whole frames, OOM is an error)"
        ),
        Err(e) => {
            klog!("[CaelumKernel] heap selftest FAIL: {e}; halting");
            arch::halt();
        }
    }

    klog!("[CaelumKernel] M2 OK");

    // ---------------------------------------------------------------------
    // M3 root init. Interrupts stay disabled until the IDT IRQ gates, APIC
    // state, tick source and scheduler stacks are all ready (agents.md §22).
    // ---------------------------------------------------------------------

    // 1. Platform: ACPI RSDP -> XSDT/RSDT -> MADT, xAPIC/IOAPIC with UC device
    //    mappings, 8259 masked, GSI1 = keyboard and GSI4 = COM1 RX routed.
    if let Err(e) = platform::init() {
        klog!("[CaelumKernel] M3 FAIL apic: {e}; halting");
        arch::halt();
    }
    klog!("[CaelumKernel] M3 apic OK");

    // 2. Time: PIT-calibrated LAPIC timer + minimal monotonic clock. Only from
    //    here on do klog lines carry timestamps.
    if time::init().is_err() {
        klog!("[CaelumKernel] M3 FAIL clock; halting");
        arch::halt();
    }
    klog!("[CaelumKernel] M3 clock OK");

    // 3. Input: 8042 keyboard and COM1 RX interrupt paths.
    input::init();
    klog!("[CaelumKernel] M3 input ready");

    // 4. Controlled `sti`: every vector used below now has an IRQ gate.
    arch::enable_interrupts();

    // 5. Three LAPIC timer ticks (0x20 -> time::on_timer).
    time::wait_for_ticks(3);
    klog!("[CaelumKernel] M3 timer OK");

    // 6. Injected keyboard and serial events (0x21 / 0x24).
    input::wait_for_expected();
    klog!("[CaelumKernel] M3 input OK");
    klog!("[CaelumKernel] M3 serial OK");

    // 7. Scheduler: kernel threads A/B on guarded PMM stacks with canaries; A
    //    yields via int 0x40 while the LAPIC timer preempts B. After
    //    `M3 sched OK` / `M3 OK` the demo returns here (M4) instead of replaying
    //    the M2 page fault: the deliberate `#PF` is now the last step of the M4
    //    sequence, once every user process has exited.
    sched::start();

    // =====================================================================
    // M6b1: bring the application processors online.
    //
    // `sched::start` returns with interrupts enabled and the M3 demo no longer
    // scheduled. The bring-up needs the BSP timer for its bounded waits
    // (`time::wait_for_ticks` idles on `sti; hlt`), so it runs here: after the
    // demo, before the root takes the CPU back and disables interrupts.
    //
    // `smp::init` identity maps the low page reserved in `early_init`, fills the
    // relocatable trampoline, sends INIT/SIPI to every enabled MADT processor,
    // waits for each AP to report in on the kernel PML4, then unmaps the page and
    // returns it to the PMM. Nothing below is SMP-aware yet: from here on only
    // the BSP runs and the APs idle with `cli; hlt` (M6b2 adds scheduling).
    // =====================================================================
    let trampoline_phys = TRAMPOLINE_PHYS.load(core::sync::atomic::Ordering::Relaxed);
    let kernel_pml4_phys = KERNEL_PML4_PHYS.load(core::sync::atomic::Ordering::Relaxed);
    if let Err(reason) = smp::init(trampoline_phys, kernel_pml4_phys) {
        fail_m6b(reason);
    }
    let cpus = match platform::cpu_count() {
        Some(count) if count > 0 => count,
        _ => fail_m6b("madt-cpu-count"),
    };
    // `online_count` counts the application processors only: the boot processor
    // is the `+ 1`, so the check scales with `-smp` instead of assuming four.
    if smp::online_count() + 1 != cpus {
        fail_m6b("unexpected-online-count");
    }
    // On success the SMP layer unmaps the identity page and returns the frame to
    // the PMM, so the reserved low page must be allocatable again.
    if pmm::is_reserved(trampoline_phys) {
        fail_m6b("low-page-not-released");
    }
    // The M6b1 acceptance run uses `-smp 4`, so exactly four processors have to
    // report in; the marker text is the literal one required by agents.md §22.
    if cpus != 4 {
        fail_m6b("unexpected-cpu-count");
    }
    klog!("[CaelumKernel] M6b1 online=4");

    // =====================================================================
    // M6b2a: prove the cross-CPU locking state on every online processor.
    //
    // The APs are still parked in `cli; hlt` and never take part in scheduling,
    // but they can be woken by the selftest: every processor (BSP and each AP)
    // increments a shared counter under one `sync::IrqSpinLock`, so a lost
    // update or a lock that cannot be taken on some CPU shows up as a short
    // count. Interrupts are still enabled here (the AP bring-up needs them) and
    // the root disables them further down, so the stress runs now.
    //
    // A failure is fatal on purpose: an unusable lock would make every later
    // SMP step unsound, so the kernel halts instead of continuing degraded.
    // =====================================================================
    let expected_lock_ops = 10_000 * cpus as u64;
    match smp::lock_selftest() {
        Ok(total) if total == expected_lock_ops => klog!("[CaelumKernel] M6b2a locks OK"),
        Ok(_) => fail_m6b("lock-stress"),
        Err(reason) => fail_m6b(reason),
    }

    // =====================================================================
    // M4: the kernel root.
    //
    // `sched::start` returns with interrupts enabled (the M3 demo needs them),
    // so the root takes the CPU back immediately: everything below mutates
    // un-synchronised global state (module window, syscall MSRs, process table)
    // that must not race a timer tick.
    // =====================================================================
    arch::disable_interrupts();

    // 1. Native objects. The object table starts empty: every handle a process
    //    holds is either created for that process (Console/Random) or
    //    transferred explicitly. The CRNG has no entropy source yet, so
    //    `random_read` must report ERR_NO_ENTROPY rather than invent bytes.
    if object::live_objects() != 0 {
        fail_m4("object table is not empty at root start");
    }
    if rng::state() != rng::EntropyState::NoEntropy {
        fail_m4("rng is not in the NoEntropy state");
    }
    klog!(
        "[CaelumKernel] M4 objects OK (object table empty, handles are per-process, rng entropy={:?})",
        rng::state()
    );

    // 2. Boot modules: map the fixed, named ELF payloads read-only/NX into the
    //    830-840 window and validate each one as a user image.
    if let Err(error) = bootmod::init() {
        fail_m4(error.as_str());
    }
    klog!(
        "[CaelumKernel] M4 modules OK ({} boot modules, read-only @ 0xffffffff83000000)",
        bootmod::count()
    );

    // 3. VFS (M5a): mount the ramfs root, attach the boot modules read-only at
    //    `/boot` and run the page-cache/ramfs/lock/notify self-checks. `vfs::init`
    //    is all-or-nothing, so a failure here must stop the boot: the image
    //    loader reads module payloads through the VFS from now on, and falling
    //    back to the retired `bootmod` read path would silently skip M5a.
    if let Err(error) = vfs::init() {
        fail_m5a(error.as_str());
    }
    klog!("[CaelumKernel] M5a vfs OK");
    klog!("[CaelumKernel] M5a pagecache OK");
    klog!("[CaelumKernel] M5a ramfs OK");
    klog!("[CaelumKernel] M5a locks OK");
    klog!("[CaelumKernel] M5a notify OK");
    // The boot modules must be reachable *through* the VFS: fetch the ELF magic
    // of `/boot/init` via VNode + page cache before any image is loaded.
    if let Err(error) = image::probe_boot_module(bootmod::INIT_MODULE) {
        fail_m5a(error.as_str());
    }
    klog!("[CaelumKernel] M5a bootmod via vfs OK");

    // 3b. M5c stage 1: bring up the block devices and mount FAT32/ext2 *before*
    //     the first user process exists, so `init` can open files as soon as it
    //     is spawned. The historical M5b markers stay after `M4 OK` (see
    //     `m5c_persist`) so the acceptance transcript keeps its order.
    #[cfg(not(test))]
    m5c_mounts();

    // 4. `syscall` entry: EFER/STAR/LSTAR/FMASK + dispatch table, plus the
    //    destroy hooks the kernel services need: File/VmObject/Watch here and,
    //    through `ipc::install_destroy_hooks`, Event/EventPair/Timer/Channel/
    //    Port/SharedMemory/EventSubscription. Must be live before the first user
    //    instruction runs, because a released object must reach the module that
    //    owns its payload on every exit path.
    syscall::init();

    // 5. First user process: `init` receives Console (slot 0) and Random (slot
    //    1) as explicit initial handles. `start_user` activates its address
    //    space, points TSS.RSP0 at its kernel stack and iretqs into ring3.
    //
    //    Since M5a the payload comes from `/boot/init` through the VFS, so a
    //    spawn failure is a VFS/boot-module failure: report it as M5a instead of
    //    the M4 exit path.
    let init = match process::spawn_init() {
        Ok(process) => process,
        Err(_) => fail_m5a("spawn_init was rejected (image via vfs)"),
    };
    klog!(
        "[CaelumKernel] M4 init spawned (slot {}, kernel stack top @ 0x{:016x})",
        init.index(),
        process::kernel_stack_top_of(init.index())
    );
    sched::start_user(init);
}

/// Print an M4 failure line and stop.
///
/// Available in host test builds too, because the scheduler and process layers
/// reference [`complete_m4`] unconditionally; nothing calls these on the host.
fn fail_m4(reason: &str) -> ! {
    klog!("[CaelumKernel] M4 FAIL {reason}; halting");
    arch::halt()
}

/// Print an M5a failure line and stop.
///
/// M5a replaces the retired `bootmod` direct-read path with the VFS and page
/// cache: the image loader, `spawn_init` and therefore user mode all depend on
/// it, so a VFS/backing failure must stop the boot instead of falling back.
///
/// Only the boot path calls this (`after_vm_takeover` is `#[cfg(not(test))]`),
/// so the host test build would otherwise flag it as dead code.
#[cfg_attr(test, allow(dead_code))]
fn fail_m5a(reason: &str) -> ! {
    klog!("[CaelumKernel] M5a FAIL {reason}; halting");
    arch::halt()
}

/// Finish M4 once every user process has exited.
///
/// Called by the scheduler when no runnable user process is left. On success it
/// prints the M4 markers and then replays the M2 deliberate page fault, which
/// must be the *last* required marker in the acceptance log (agents.md §22 M4 /
/// xtask `FINAL_MARKER`). A non-zero exit status is a failure.
/// M5b stage failure: print the precise reason and halt.
#[cfg(not(test))]
fn fail_m5b(reason: &str) -> ! {
    klog!("[CaelumKernel] M5b FAIL {reason}; halting");
    arch::halt()
}

/// M5c1 boot invariant failure: print the precise reason and halt.
///
/// The user-visible file calls own their VFS open descriptions through exactly
/// one `File` destroy hook. If that hook cannot be installed every later `open`
/// would leak its description, which is not recoverable at run time, so the
/// boot stops here instead of continuing into user mode.
#[cfg_attr(test, allow(dead_code))]
pub(crate) fn fail_m5c(reason: &str) -> ! {
    klog!("[CaelumKernel] M5c1 FAIL {reason}; halting");
    arch::halt()
}

/// M6a boot invariant failure: print the precise reason and halt.
///
/// The IPC layer owns one destroy hook per waitable kind; a second, conflicting
/// hook means every Event/EventPair/Timer closed afterwards would leak its table
/// slot and never wake its waiters, which cannot be repaired at run time.
#[cfg_attr(test, allow(dead_code))]
pub(crate) fn fail_m6a(reason: &str) -> ! {
    klog!("[CaelumKernel] M6a FAIL {reason}; halting");
    arch::halt()
}

/// M6b boot invariant failure: print the precise reason and halt.
///
/// From M6b1 on the application processors are part of the boot contract: if the
/// low trampoline page cannot be reserved, or any AP never reports in, the kernel
/// stops instead of silently continuing with fewer processors than the machine
/// has. The SMP bring-up owns the identity mapping and releases the page again,
/// so a failure there leaves that state reserved for post-mortem inspection.
#[cfg_attr(test, allow(dead_code))]
pub(crate) fn fail_m6b(reason: &str) -> ! {
    klog!("[CaelumKernel] M6b FAIL {reason}; halting");
    arch::halt()
}

/// M5b state file payload. FAT names must be 8.3 upper case; ext2 names are
/// free-form bytes.
#[cfg(not(test))]
const M5B_STATE_PAYLOAD: &[u8] = b"CAELUM-M5B-V1";
#[cfg(not(test))]
const M5B_DATA_LEN: usize = 8192;
#[cfg(not(test))]
const M5B_APPEND_LEN: usize = 1024;
#[cfg(not(test))]
const M5B_TRUNCATED_LEN: u64 = 4608;
#[cfg(not(test))]
const M5B_FAT_STATE: &[u8] = b"/fat/M5STATE.BIN";
#[cfg(not(test))]
const M5B_FAT_DATA: &[u8] = b"/fat/M5DATA.BIN";
#[cfg(not(test))]
const M5B_FAT_DONE: &[u8] = b"/fat/M5DONE.BIN";
#[cfg(not(test))]
const M5B_EXT2_STATE: &[u8] = b"/ext2/m5state";
#[cfg(not(test))]
const M5B_EXT2_DATA: &[u8] = b"/ext2/m5data";
#[cfg(not(test))]
const M5B_EXT2_DONE: &[u8] = b"/ext2/m5done";

/// The deterministic data byte at file offset `index` (13-step pattern).
#[cfg(not(test))]
fn m5b_pattern(index: usize) -> u8 {
    ((index * 13 + 7) % 251) as u8
}

/// Size of an existing file, or `None` when the path does not exist.
#[cfg(not(test))]
fn m5b_size(path: &[u8]) -> Result<Option<u64>, vfs::VfsError> {
    match vfs::stat_path(path) {
        Ok(stat) => Ok(Some(stat.size)),
        Err(vfs::VfsError::NotFound) => Ok(None),
        Err(error) => Err(error),
    }
}

/// Write `data` at offset 0 of a newly created file.
#[cfg(not(test))]
fn m5b_create_exact(path: &[u8], data: &[u8]) -> Result<(), vfs::VfsError> {
    let open = vfs::open_path(path, vfs::OpenOptions::create_write())?;
    let mut written = 0usize;
    while written < data.len() {
        let written_now = vfs::write(open, &data[written..])?;
        if written_now == 0 {
            vfs::close(open)?;
            return Err(vfs::VfsError::Corrupt);
        }
        written += written_now;
    }
    vfs::close(open)
}

/// Create `path` and fill it with `len` pattern bytes in 256-byte chunks (the
/// boot stack is 16 KiB, so the buffer must stay small).
#[cfg(not(test))]
fn m5b_create_pattern(path: &[u8], len: usize) -> Result<(), vfs::VfsError> {
    let open = vfs::open_path(path, vfs::OpenOptions::create_write())?;
    let mut chunk = [0u8; 256];
    let mut written = 0usize;
    while written < len {
        let take = core::cmp::min(chunk.len(), len - written);
        for (offset, slot) in chunk[..take].iter_mut().enumerate() {
            *slot = m5b_pattern(written + offset);
        }
        let mut done = 0usize;
        while done < take {
            let wrote = vfs::write(open, &chunk[done..take])?;
            if wrote == 0 {
                vfs::close(open)?;
                return Err(vfs::VfsError::Corrupt);
            }
            done += wrote;
        }
        written += take;
    }
    vfs::close(open)
}

/// Append `len` pattern bytes at `offset` of an existing file.
#[cfg(not(test))]
fn m5b_append_pattern(path: &[u8], offset: u64, len: usize) -> Result<(), vfs::VfsError> {
    let open = vfs::open_path(path, vfs::OpenOptions::read_write())?;
    vfs::seek(open, offset)?;
    let mut chunk = [0u8; 256];
    let mut written = 0usize;
    while written < len {
        let take = core::cmp::min(chunk.len(), len - written);
        for (delta, slot) in chunk[..take].iter_mut().enumerate() {
            *slot = m5b_pattern(offset as usize + written + delta);
        }
        let mut done = 0usize;
        while done < take {
            let wrote = vfs::write(open, &chunk[done..take])?;
            if wrote == 0 {
                vfs::close(open)?;
                return Err(vfs::VfsError::Corrupt);
            }
            done += wrote;
        }
        written += take;
    }
    vfs::close(open)
}

/// Read `expected.len()` bytes from offset 0 and compare them with `expected`.
#[cfg(not(test))]
fn m5b_check_exact(path: &[u8], expected: &[u8]) -> Result<(), vfs::VfsError> {
    let open = vfs::open_path(path, vfs::OpenOptions::read_only())?;
    let mut buffer = [0u8; 32];
    if expected.len() > buffer.len() {
        vfs::close(open)?;
        return Err(vfs::VfsError::Corrupt);
    }
    let wanted = &mut buffer[..expected.len()];
    let mut read = 0usize;
    while read < wanted.len() {
        let got = vfs::read(open, &mut wanted[read..])?;
        if got == 0 {
            vfs::close(open)?;
            return Err(vfs::VfsError::Corrupt);
        }
        read += got;
    }
    vfs::close(open)?;
    if read != expected.len() || &wanted[..] != expected {
        return Err(vfs::VfsError::Corrupt);
    }
    Ok(())
}

/// Verify `len` pattern bytes of a file without loading it all at once.
#[cfg(not(test))]
fn m5b_verify_pattern(path: &[u8], len: usize) -> Result<(), vfs::VfsError> {
    let open = vfs::open_path(path, vfs::OpenOptions::read_only())?;
    let mut chunk = [0u8; 256];
    let mut read = 0usize;
    while read < len {
        let take = core::cmp::min(chunk.len(), len - read);
        let mut got = 0usize;
        while got < take {
            let received = vfs::read(open, &mut chunk[got..take])?;
            if received == 0 {
                vfs::close(open)?;
                return Err(vfs::VfsError::Corrupt);
            }
            got += received;
        }
        for (offset, byte) in chunk[..take].iter().enumerate() {
            if *byte != m5b_pattern(read + offset) {
                vfs::close(open)?;
                return Err(vfs::VfsError::Corrupt);
            }
        }
        read += take;
    }
    vfs::close(open)
}

/// Two-phase persistence protocol (M5b).
///
/// First boot: both state files are absent, so create state and data on both
/// mounts and sync. Second boot: both state files exist with the exact payload,
/// so re-verify the data, append 1024 bytes, sync, rename data to done, truncate
/// to 4608 bytes and sync again. Anything in between (one state file only, wrong
/// content, a leftover done file, any I/O error) is a failure, never a guessed
/// phase.
#[cfg(not(test))]
fn m5b_persistence() -> Result<(), vfs::VfsError> {
    let fat_state = m5b_size(M5B_FAT_STATE)?;
    let ext2_state = m5b_size(M5B_EXT2_STATE)?;
    match (fat_state, ext2_state) {
        (None, None) => {
            // A clean first boot must not inherit any half-written leftovers.
            for stale in [M5B_FAT_DATA, M5B_FAT_DONE, M5B_EXT2_DATA, M5B_EXT2_DONE] {
                if m5b_size(stale)?.is_some() {
                    return Err(vfs::VfsError::Corrupt);
                }
            }
            m5b_create_exact(M5B_FAT_STATE, M5B_STATE_PAYLOAD)?;
            m5b_create_exact(M5B_EXT2_STATE, M5B_STATE_PAYLOAD)?;
            m5b_create_pattern(M5B_FAT_DATA, M5B_DATA_LEN)?;
            m5b_create_pattern(M5B_EXT2_DATA, M5B_DATA_LEN)?;
            vfs::sync_path(M5B_FAT_STATE)?;
            vfs::sync_path(M5B_EXT2_STATE)?;
            vfs::sync_path(M5B_FAT_DATA)?;
            vfs::sync_path(M5B_EXT2_DATA)?;
            vfs::sync_all()?;
            klog!("[CaelumKernel] M5b persistence written");
            klog!("[CaelumKernel] M5b first boot OK");
            Ok(())
        }
        (Some(fat_size), Some(ext2_size)) => {
            if m5b_size(M5B_FAT_DONE)?.is_some() || m5b_size(M5B_EXT2_DONE)?.is_some() {
                return Err(vfs::VfsError::Corrupt);
            }
            let want = M5B_STATE_PAYLOAD.len() as u64;
            if fat_size != want || ext2_size != want {
                return Err(vfs::VfsError::Corrupt);
            }
            m5b_check_exact(M5B_FAT_STATE, M5B_STATE_PAYLOAD)?;
            m5b_check_exact(M5B_EXT2_STATE, M5B_STATE_PAYLOAD)?;
            m5b_verify_pattern(M5B_FAT_DATA, M5B_DATA_LEN)?;
            m5b_verify_pattern(M5B_EXT2_DATA, M5B_DATA_LEN)?;
            m5b_append_pattern(M5B_FAT_DATA, M5B_DATA_LEN as u64, M5B_APPEND_LEN)?;
            m5b_append_pattern(M5B_EXT2_DATA, M5B_DATA_LEN as u64, M5B_APPEND_LEN)?;
            vfs::sync_path(M5B_FAT_DATA)?;
            vfs::sync_path(M5B_EXT2_DATA)?;
            // Read the appended data back through the VFS before renaming: the
            // second boot must prove the persisted pattern, not just the calls.
            let appended = (M5B_DATA_LEN + M5B_APPEND_LEN) as u64;
            for path in [M5B_FAT_DATA, M5B_EXT2_DATA] {
                if m5b_size(path)? != Some(appended) {
                    return Err(vfs::VfsError::Corrupt);
                }
                m5b_verify_pattern(path, appended as usize)?;
            }
            vfs::rename_path(M5B_FAT_DATA, M5B_FAT_DONE)?;
            vfs::rename_path(M5B_EXT2_DATA, M5B_EXT2_DONE)?;
            vfs::sync_path(M5B_FAT_DONE)?;
            vfs::sync_path(M5B_EXT2_DONE)?;
            vfs::truncate_path(M5B_FAT_DONE, M5B_TRUNCATED_LEN)?;
            vfs::truncate_path(M5B_EXT2_DONE, M5B_TRUNCATED_LEN)?;
            vfs::sync_path(M5B_FAT_DONE)?;
            vfs::sync_path(M5B_EXT2_DONE)?;
            // Same for the truncated files: size and bytes both come back from
            // stable storage.
            for path in [M5B_FAT_DONE, M5B_EXT2_DONE] {
                if m5b_size(path)? != Some(M5B_TRUNCATED_LEN as u64) {
                    return Err(vfs::VfsError::Corrupt);
                }
                m5b_verify_pattern(path, M5B_TRUNCATED_LEN as usize)?;
            }
            vfs::sync_all()?;
            klog!("[CaelumKernel] M5b persistence OK");
            klog!("[CaelumKernel] M5b OK");
            Ok(())
        }
        _ => Err(vfs::VfsError::Corrupt),
    }
}

/// Map a block-device error onto a stable, short reason string.
#[cfg(not(test))]
fn m5b_block_reason(error: block::BlockError) -> &'static str {
    match error {
        block::BlockError::OutOfBounds => "block out of bounds",
        block::BlockError::BadBuffer => "block bad buffer",
        block::BlockError::Io => "block I/O error",
        block::BlockError::Timeout => "block timeout",
        block::BlockError::ReadOnly => "block read-only",
        block::BlockError::Corrupt => "block corrupt",
        block::BlockError::Unsupported => "block unsupported",
    }
}

/// Sector size of both virtio-blk media (M5c boot-sector capture buffer).
#[cfg(not(test))]
const M5C_SECTOR_SIZE: usize = io::VIRTIO_BLK_SECTOR_SIZE as usize;

/// Sector 0 of the FAT32 medium, as read just before it was mounted.
///
/// M5c stage 2 re-reads sector 0 after `M4 OK` and compares it against this
/// copy: identical bytes prove the medium the VFS mounted is still the medium
/// the persistence protocol is about to write, and that re-borrowing the device
/// through its index handle did not reset the queue.
#[cfg(not(test))]
static mut M5C_FAT_BOOT: [u8; M5C_SECTOR_SIZE] = [0u8; M5C_SECTOR_SIZE];

/// Sector 0 of the ext2 medium, as read just before it was mounted.
#[cfg(not(test))]
static mut M5C_EXT2_BOOT: [u8; M5C_SECTOR_SIZE] = [0u8; M5C_SECTOR_SIZE];

/// Compare a freshly read boot sector against one of the copies captured before
/// mounting, without materialising a second sector on the stack.
///
/// `m5c_persist` runs on the user kernel stack (four pages) in the exit path, so
/// copying the expected sector twice used to cost a kilobyte of headroom for no
/// benefit. The comparison is byte-wise over the same constant-sized region.
#[cfg(not(test))]
#[inline(never)]
fn boot_sector_matches(captured: *const u8, sector: &[u8; M5C_SECTOR_SIZE]) -> bool {
    let mut index = 0;
    while index < M5C_SECTOR_SIZE {
        // SAFETY: `captured` points at one of the two `[u8; M5C_SECTOR_SIZE]`
        // statics and `index` is bounded by that same constant.
        let byte = unsafe { core::ptr::read_volatile(captured.add(index)) };
        if byte != sector[index] {
            return false;
        }
        index += 1;
    }
    true
}

/// M5c stage 1: MCFG/PCI, the two legacy virtio-blk disks, then mount FAT32 and
/// ext2 through the VFS.
///
/// This runs on the boot context with interrupts off, before `syscall::init`
/// and before `spawn_init`, so no scheduler re-entry can observe a half-mounted
/// VFS. Failures reuse the M5b failure line: it is the same storage stack.
///
/// The historical `M5b ... OK` markers are deliberately *not* printed here;
/// they are re-emitted in [`m5c_persist`] at their original position.
#[cfg(not(test))]
fn m5c_mounts() {
    if let Err(reason) = platform::init_pci() {
        fail_m5b(reason);
    }
    let devices = match io::init() {
        Ok(count) => count,
        Err(reason) => fail_m5b(reason),
    };
    if devices < 2 {
        fail_m5b("io::init found fewer than two virtio block devices");
    }
    let mut fat = match io::virtio_block(0) {
        Ok(device) => device,
        Err(reason) => fail_m5b(reason),
    };
    let mut ext2 = match io::virtio_block(1) {
        Ok(device) => device,
        Err(reason) => fail_m5b(reason),
    };
    // Capture each medium's boot sector before mounting. Mounting may update
    // FSInfo (sector 1) or the ext2 superblock, so sector 0 is the stable
    // "same medium" proof for stage 2.
    //
    // SAFETY: the boot context is single-threaded with interrupts off, and the
    // two statics are written only here (stage 2 only reads them). `addr_of_mut!`
    // avoids creating a reference to the whole static.
    unsafe {
        let fat_boot = core::ptr::addr_of_mut!(M5C_FAT_BOOT);
        let ext2_boot = core::ptr::addr_of_mut!(M5C_EXT2_BOOT);
        if let Err(error) = block::BlockDevice::read_blocks(&mut fat, 0, &mut *fat_boot) {
            fail_m5b(m5b_block_reason(error));
        }
        if let Err(error) = block::BlockDevice::read_blocks(&mut ext2, 0, &mut *ext2_boot) {
            fail_m5b(m5b_block_reason(error));
        }
    }
    if let Err(error) = vfs::mount_fat32(fat) {
        fail_m5b(error.as_str());
    }
    if let Err(error) = vfs::mount_ext2(ext2) {
        fail_m5b(error.as_str());
    }
    klog!("[CaelumKernel] M5c mounts ready (fat32 @ /fat, ext2 @ /ext2)");
}

/// M5c stage 2: re-read both boot sectors, re-emit the historical M5b markers in
/// their original order, verify the mounts are still registered, then run the
/// unchanged two-phase persistence protocol.
///
/// Called from [`complete_m4`] after `M4 OK` — the exact point the M5b root used
/// to run — so `M2 #PF caught` stays the last required marker.
#[cfg(not(test))]
fn m5c_persist() {
    // Re-emitted to keep the acceptance transcript byte-identical in order;
    // PCI/MCFG and the devices were already brought up in stage 1.
    klog!("[CaelumKernel] M5b mcfg OK");
    klog!("[CaelumKernel] M5b pci OK");
    // `VirtioBlk` is only an index handle over the slot owned by the mount, so
    // borrowing the device again here is non-destructive and cannot reset the
    // queue the mounted filesystem is using.
    let mut fat = match io::virtio_block(0) {
        Ok(device) => device,
        Err(reason) => fail_m5b(reason),
    };
    let mut ext2 = match io::virtio_block(1) {
        Ok(device) => device,
        Err(reason) => fail_m5b(reason),
    };
    let mut sector = [0u8; M5C_SECTOR_SIZE];
    if let Err(error) = block::BlockDevice::read_blocks(&mut fat, 0, &mut sector) {
        fail_m5b(m5b_block_reason(error));
    }
    // SAFETY: single-threaded boot context; the captured copies are read-only.
    let fat_captured = core::ptr::addr_of!(M5C_FAT_BOOT).cast::<u8>();
    if !boot_sector_matches(fat_captured, &sector) {
        fail_m5b("fat32 sector 0 changed between mount and persistence");
    }
    if let Err(error) = block::BlockDevice::read_blocks(&mut ext2, 0, &mut sector) {
        fail_m5b(m5b_block_reason(error));
    }
    // SAFETY: as above.
    let ext2_captured = core::ptr::addr_of!(M5C_EXT2_BOOT).cast::<u8>();
    if !boot_sector_matches(ext2_captured, &sector) {
        fail_m5b("ext2 sector 0 changed between mount and persistence");
    }
    klog!("[CaelumKernel] M5b virtio OK");
    klog!("[CaelumKernel] M5b block OK");
    // A resolvable mount point is only created by `mount_disk`, so these two
    // stats prove both mounts survived the whole M4 user-mode phase.
    match vfs::stat_path(b"/fat") {
        Ok(stat) if stat.kind == vfs::NodeKind::Directory => {}
        Ok(_) => fail_m5b("/fat is not a directory after mounting"),
        Err(error) => fail_m5b(error.as_str()),
    }
    match vfs::stat_path(b"/ext2") {
        Ok(stat) if stat.kind == vfs::NodeKind::Directory => {}
        Ok(_) => fail_m5b("/ext2 is not a directory after mounting"),
        Err(error) => fail_m5b(error.as_str()),
    }
    klog!("[CaelumKernel] M5b fat32 OK");
    klog!("[CaelumKernel] M5b ext2 OK");
    if let Err(error) = m5b_persistence() {
        fail_m5b(error.as_str());
    }
    klog!("[CaelumKernel] M5c1 OK");
    // Reaching this point means `init` exited with status 0, so every M5c1 file
    // step *and* every M5c2 mapping step in the reference user program passed:
    // `init` reports a non-zero status on the first failure, and a non-zero
    // status never reaches `complete_m4`'s success path. The marker therefore
    // cannot be printed by a run whose user-visible mmap path failed.
    klog!("[CaelumKernel] M5c2 OK");
    // The reference user program deliberately exits with a directory watch still
    // open, so a zero watch count here proves the reaping path released it. Both
    // volumes then take a real injected media fault and must recover on retry.
    m5c3_faults();
}

/// Payload of both M5c3 media-fault files: one 16-byte text line.
#[cfg(not(test))]
const M5C3_FAULT_MARK: &[u8; 16] = b"CAELUM-FAULT-OK\n";

/// One media-fault round trip against one mounted volume.
///
/// The point is honesty: a fault injected into the virtio request path must
/// reach the caller as `Io` (never as a mocked VFS error), must be consumed
/// exactly once, and clearing the sticky media error must let the retry
/// succeed. The `Write` fault is taken while a dirty page is being flushed and
/// the `Flush` fault while only the device flush is outstanding, so both halves
/// of the sync path are exercised.
#[cfg(not(test))]
#[inline(never)]
fn m5c3_fault_round(device: u8, kind: vfs::disk::Kind, path: &[u8]) -> Result<(), &'static str> {
    let open = vfs::open_path(path, vfs::OpenOptions::create_write().truncate())
        .map_err(|error| error.as_str())?;
    let mut written = 0;
    while written < M5C3_FAULT_MARK.len() {
        match vfs::write(open, &M5C3_FAULT_MARK[written..]) {
            Ok(count) if count > 0 => written += count,
            Ok(_) => return Err("fault test write made no progress"),
            Err(error) => return Err(error.as_str()),
        }
    }
    vfs::sync_open(open).map_err(|error| error.as_str())?;

    // 1. A write fault taken while a dirty page is being flushed.
    if let Err(reason) = io::inject_next_fault(device, io::BlockFault::Write) {
        return Err(reason);
    }
    // Rewind first: the loop above left the offset at 16, and `vfs::write` writes
    // *at* the offset. Appending here would grow the file to 32 bytes, which the
    // 16-byte readback below would then reject as a bad offset. Overwriting the
    // same page still dirties it, so the write fault is still taken.
    vfs::seek(open, 0).map_err(|error| error.as_str())?;
    if let Err(error) = vfs::write(open, M5C3_FAULT_MARK) {
        return Err(error.as_str());
    }
    match vfs::sync_open(open) {
        Err(vfs::VfsError::Io) => {}
        _ => return Err("an injected write fault did not reach the caller as io"),
    }
    if io::pending_fault(device).is_some() {
        return Err("the injected write fault was never consumed");
    }
    if vfs::clear_disk_sticky(kind).is_none() {
        return Err("a failed sync did not mark the volume as failed");
    }
    vfs::sync_open(open).map_err(|error| error.as_str())?;

    // 2. A flush fault with no dirty page outstanding: only the device flush is
    //    left in the sync path, so this exercises the second half of it.
    if let Err(reason) = io::inject_next_fault(device, io::BlockFault::Flush) {
        return Err(reason);
    }
    match vfs::sync_open(open) {
        Err(vfs::VfsError::Io) => {}
        _ => return Err("an injected flush fault did not reach the caller as io"),
    }
    if io::pending_fault(device).is_some() {
        return Err("the injected flush fault was never consumed");
    }
    if vfs::clear_disk_sticky(kind).is_none() {
        return Err("a failed flush did not mark the volume as failed");
    }
    vfs::sync_open(open).map_err(|error| error.as_str())?;
    vfs::close(open).map_err(|error| error.as_str())?;

    let mut readback = [0u8; 16];
    let count = vfs::read_all_path(path, &mut readback).map_err(|error| error.as_str())?;
    if count != readback.len() || &readback != M5C3_FAULT_MARK {
        return Err("the fault test file did not survive the retried sync");
    }
    Ok(())
}

/// M5c3 root self-test: resource reaping plus a real, one-shot, recoverable
/// media fault on both mounted volumes.
#[cfg(not(test))]
#[inline(never)]
fn m5c3_faults() {
    if vfs::lock_count() != 0 {
        fail_m5c("a file lock outlived the user process that held it");
    }
    if vfs::watch_count() != 0 {
        fail_m5c("a directory watch outlived the user process that held it");
    }
    if let Err(reason) = m5c3_fault_round(0, vfs::disk::Kind::Fat32, b"/fat/M5FAULT.BIN") {
        fail_m5c(reason);
    }
    if let Err(reason) = m5c3_fault_round(1, vfs::disk::Kind::Ext2, b"/ext2/m5cfault") {
        fail_m5c(reason);
    }
    if io::pending_fault(0).is_some() || io::pending_fault(1).is_some() {
        fail_m5c("an injected media fault was never consumed");
    }
    klog!("[CaelumKernel] M5c3 faults OK");
    klog!("[CaelumKernel] M5c3 OK");
    klog!("[CaelumKernel] M5 OK");
    // M6a: the IPC objects the user programs created are gone by now (the last
    // process released its handle table), so an empty IPC table is the real
    // cleanup acceptance for this stage rather than a claim.
    if ipc::event::count() != 0 || ipc::event::pair_count() != 0 || ipc::timer::count() != 0 {
        fail_m6a("an IPC object outlived the user process that created it");
    }
    klog!("[CaelumKernel] M6a OK");
}

/// M6a2 root closeout: prove that the M6a1/M6a2 waitable objects and the futex
/// state were released by the user processes, and that the futex path really
/// blocked and woke at least once during the user-mode phase.
///
/// Runs after `M6a OK` (the last marker [`m5c3_faults`] prints) and before the
/// closing deliberate page fault, so that fault stays the single final marker.
/// Every number comes from the module that owns it — object destroy hooks, the
/// `ipc::*` counters, [`ipc::shm`] frame accounting and [`futex`] statistics —
/// so this function introduces no accounting of its own.
///
/// Failures reuse the M5c failure line: these are resource-lifetime checks of
/// exactly the kind the M5c stage already reports.
#[cfg(not(test))]
#[inline(never)]
fn m6a2_closeout() {
    // 1. Coverage of the destroy hooks. The root installs them through
    //    `syscall::init` -> `ipc::install_destroy_hooks`, which registers the
    //    three M6a1 kinds (Event/EventPair/Timer, already covered by the M6a
    //    stage) plus the four M6a2 kinds checked here. A hook missing at this
    //    point means the boot order changed, and a released object would then
    //    keep its table slot (and its shared-memory frames) forever.
    if !object::has_destroy_hook(object::ObjectKind::Channel) {
        fail_m5c("M6a2: the Channel destroy hook is not installed");
    }
    if !object::has_destroy_hook(object::ObjectKind::Port) {
        fail_m5c("M6a2: the Port destroy hook is not installed");
    }
    if !object::has_destroy_hook(object::ObjectKind::SharedMemory) {
        fail_m5c("M6a2: the SharedMemory destroy hook is not installed");
    }
    if !object::has_destroy_hook(object::ObjectKind::EventSubscription) {
        fail_m5c("M6a2: the EventSubscription destroy hook is not installed");
    }

    // 2. Every M6a2 object a user program created must be gone: earlier
    //    processes released their handle tables in `process::reap`, and the last
    //    one in `release_last_process_resources`, so a non-zero count is a real
    //    leak rather than a bookkeeping difference. `SharedMemory` additionally
    //    owns physical frames, which are counted separately.
    if ipc::channel::count() != 0 {
        fail_m5c("M6a2: a Channel object outlived the user process that owned it");
    }
    if ipc::port::count() != 0 {
        fail_m5c("M6a2: a Port object outlived the user process that owned it");
    }
    if ipc::shm::live_objects() != 0 {
        fail_m5c("M6a2: a SharedMemory object outlived the user process that owned it");
    }
    if ipc::subscription::count() != 0 {
        fail_m5c("M6a2: an EventSubscription outlived the user process that owned it");
    }
    if ipc::shm::live_frames() != 0 {
        fail_m5c("M6a2: shared-memory frames outlived their SharedMemory object");
    }

    // 3. Futex: no waiter may survive its process, and the reference user
    //    programs must have exercised both halves of the path — a real block and
    //    a real wake — or the marker would claim more than the run did. The
    //    counters come from `futex`; when the deadline path is exercised, the
    //    wake reason is `Timeout` but the counters are the same.
    let (blocked, woken) = futex::stats();
    if futex::waiter_count() != 0 {
        fail_m5c("M6a2: a futex waiter outlived the process that blocked on it");
    }
    if blocked < 1 {
        fail_m5c("M6a2: no futex wait blocked during the user-mode phase");
    }
    if woken < 1 {
        fail_m5c("M6a2: no futex waiter was woken during the user-mode phase");
    }

    klog!("[CaelumKernel] M6a2 OK");
}

/// Release what the *last* exiting user process still owns.
///
/// Every earlier process is cleaned by `process::reap` from a parent's `wait`,
/// but the final one never is: there is no next process to switch to, and its
/// kernel stack and address space must stay mapped until the closing deliberate
/// page fault. Without this step its handle table — and therefore the directory
/// watch `init` deliberately leaves open — would survive into the root checks,
/// so `watch_count()` would report a leak that the reaping path would never have
/// produced. Only the two ownership steps of `reap` are repeated here; the
/// stack and address space are left alone because they are still in use.
#[cfg(not(test))]
fn release_last_process_resources() {
    let Some(pid) = process::current_process_id() else {
        return;
    };
    // Handles first: the `File`/`VmObject`/`Watch` destroy hooks close their VFS
    // descriptions and need this process's address space to still exist. The
    // table is taken out of the process slot first, so every hook runs with the
    // process lock released (`with_current_handles` would hold it) and cannot
    // deadlock against the wake paths the IPC hooks use.
    if let Some(mut guard) = process::take_current_handles() {
        let _ = object::clear_handle_table(guard.table_mut());
    }
    // The destroy hooks park the references they cannot release inside the
    // object table (`EventSubscription` in `ipc`, the `SharedMemory` reference of
    // a released mapping in `vmobj`); drain both queues now, outside the handle
    // table lock and before the address space goes away. Without this the last
    // process's `SharedMemory` would keep its object and frames, and the M6a2
    // closeout would fail on `shm live_objects`.
    let _ = process::drain_pending_object_refs();
    // Then the per-owner leftovers that no description backs: POSIX locks and
    // watches whose handle was dropped without an explicit close.
    let _ = vfs::close_process(pid);
}

/// Tick budget for "both workers reached `Blocked`" (the clock runs at
/// [`time::tick_hz`]; the workers first spin through 100 000 `abi_query`
/// round trips, so the budget is deliberately generous).
#[cfg(not(test))]
const M6B2_BLOCK_TICKS: u64 = 1_000;
/// Tick budget for "both workers exited" after their 20-tick timers expire.
#[cfg(not(test))]
const M6B2_EXIT_TICKS: u64 = 1_000;

/// Initial CPU mask for the two workers: AP1 only, the lowest online AP, so
/// both start in that CPU's run queue. The closeout then widens the mask
/// explicitly before moving them (affinity is a gate, not a preference).
#[cfg(not(test))]
const M6B2_WORKER_AFFINITY: u8 = 1 << 1;

/// Wait until `pid` reaches `want`, or `budget` ticks elapse.
///
/// The monitor runs on the boot processor, which owns the global clock and the
/// IPC timer wheel: idling here (with interrupts enabled) is exactly what
/// expires the workers' timers and publishes the cross-CPU wake IPIs.
#[cfg(not(test))]
fn m6b2_wait_for_state(pid: process::ProcessId, want: process::ProcessState, budget: u64) -> bool {
    let start = time::monotonic_ticks();
    loop {
        if process::process_state(pid) == Some(want) {
            return true;
        }
        if time::monotonic_ticks().saturating_sub(start) >= budget {
            return false;
        }
        arch::idle();
    }
}

/// Report a missing M6b2 scheduling counter and stop: a milestone that cannot
/// prove itself with its own statistics must not print an OK line.
#[cfg(not(test))]
fn fail_m6b2(attribute: &str) -> ! {
    klog!("[CaelumKernel] M6b2 FAIL {attribute}; halting");
    arch::halt()
}

/// Tick budget for the M6c closeout: `gfx` must load, map the shadow buffer,
/// present it, announce input readiness and then block for the five injected
/// events, so this is deliberately generous compared with the M6b2 budgets.
#[cfg(not(test))]
const M6C_GFX_TICKS: u64 = 5_000;
/// Tick budget for every AP to park again after `gfx` exits.
#[cfg(not(test))]
const M6C_PARK_TICKS: u64 = 1_000;
/// Input events the M6c run injects: one PS/2 make/break pair (`d`) and three
/// serial bytes (`m`, `6`, `c`). `gfx` hard-checks the same sequence.
#[cfg(not(test))]
const M6C_EVENTS: u64 = 5;

/// Report a failed M6c step and stop: the display/input milestone must never
/// print an OK line it cannot back with the real objects and event counts.
#[cfg(not(test))]
fn fail_m6c(reason: &str) -> ! {
    klog!("[CaelumKernel] M6c FAIL {reason}; halting");
    arch::halt()
}

/// Report a failed M7a step and stop.
///
/// The loopback self-test reports the protocol that failed (`M7UDP4`,
/// `M7UDP6`, `M7TCP4`, `M7TCP6`); that marker is printed verbatim so a broken
/// datagram or handshake can never be followed by an OK line.
#[cfg(not(test))]
fn fail_m7a(marker: &str) -> ! {
    klog!("[CaelumKernel] M7a FAIL {marker}; halting");
    arch::halt()
}

/// Report a failed M7b step and stop.
///
/// The reason names the exact step (`sockets-leaked`, `netns`, `net-exit`, …),
/// so an M7b failure can never be mistaken for a missing socket marker.
#[cfg_attr(test, allow(dead_code))]
pub(crate) fn fail_m7b(reason: &str) -> ! {
    klog!("[CaelumKernel] M7b FAIL {reason}; halting");
    arch::halt()
}

/// Report a failed M7d step and stop.
///
/// The reason names the exact step (`linux-spawn`, `linux-exit`,
/// `linux-sockets-live`, …), so an M7d failure can never be mistaken for a
/// missing Linux marker.
#[cfg_attr(test, allow(dead_code))]
pub(crate) fn fail_m7d(reason: &str) -> ! {
    klog!("[CaelumKernel] M7d FAIL {reason}; halting");
    arch::halt()
}

/// Report a failed M7c step and stop.
///
/// The reason names the exact step (`no-nic`, `mac-mismatch`, `link-down`, …),
/// so a bad probe can never be mistaken for a reachable network.
#[cfg_attr(test, allow(dead_code))]
pub(crate) fn fail_m7c(reason: &str) -> ! {
    klog!("[CaelumKernel] M7c FAIL {reason}; halting");
    arch::halt()
}

/// `true` once every online application processor is parked on its private idle
/// stack. Reaping `gfx` frees its kernel stack and address space, so the boot
/// processor waits for this handshake first (the same rule the M6b2 closeout
/// follows when it reaps the workers).
#[cfg(not(test))]
fn m6c_aps_parked() -> bool {
    let online = smp::online_count();
    if online == 0 {
        return true;
    }
    let wanted = ((1u64 << (online + 1)) - 1) & !1u64;
    sched::parked_aps() & wanted == wanted
}

/// M6c closeout: probe the firmware framebuffer, run the user-mode `gfx`
/// client on an AP, then verify that the display and input objects are gone and
/// that exactly the injected input events were delivered.
///
/// Runs on the boot processor after the M6b2 closeout, with the root contract
/// of interrupts disabled; the bounded waits below idle (`sti; hlt`) so the
/// input IRQs can fire and the AP timers can run, and interrupts are disabled
/// again before returning to the root.
#[cfg(not(test))]
fn m6c_closeout() {
    // 1. Probe the real GOP: `init` maps the firmware framebuffer into the
    //    kernel's FB window and `probe` paints one magenta corner pixel. This
    //    happens before the display object exists, so the object only ever sees
    //    a ready backend.
    if crate::display::init().is_err() {
        fail_m6c("display-init");
    }
    if crate::display::probe().is_err() {
        fail_m6c("display-probe");
    }
    let info = match crate::display::info() {
        Ok(info) => info,
        Err(_) => fail_m6c("display-info"),
    };
    // The payload is the *real* GOP mode (QEMU/OVMF reports 1280x800); the
    // 320x200 shadow surface is a separate, ABI-fixed size and must not be
    // reported here.
    klog!(
        "[CaelumKernel] M6c display probe OK (w={}, h={}, stride={}, fmt={})",
        info.width,
        info.height,
        info.stride,
        info.pixel_format
    );

    // 2. Build the three capabilities `gfx` starts with. The root keeps no
    //    handle: the child's handle insert takes the only reference each object
    //    needs, so closing them (or exiting) runs the destroy hooks.
    let console = match object::create_console() {
        Ok(object) => object,
        Err(_) => fail_m6c("console-object"),
    };
    let display = match object::create_object(object::ObjectKind::Display) {
        Ok(object) => object,
        Err(_) => {
            let _ = object::destroy_object(console);
            fail_m6c("display-object");
        }
    };
    let input = match object::create_object(object::ObjectKind::Input) {
        Ok(object) => object,
        Err(_) => {
            let _ = object::destroy_object(display);
            let _ = object::destroy_object(console);
            fail_m6c("input-object");
        }
    };
    if ipc::display::create(display).is_err() {
        let _ = object::destroy_object(input);
        let _ = object::destroy_object(display);
        let _ = object::destroy_object(console);
        fail_m6c("display-seat");
    }
    if ipc::input::create(input).is_err() {
        let _ = object::destroy_object(input);
        let _ = object::destroy_object(display);
        let _ = object::destroy_object(console);
        fail_m6c("input-seat");
    }

    // 3. Start `gfx` on AP1 (the lowest online AP). Handles arrive in order as
    //    the entry's rdi/rsi/rdx, exactly as the service expects.
    let handles = [
        (console, object::Rights::WRITE),
        (
            display,
            object::Rights::READ | object::Rights::WRITE | object::Rights::MAP,
        ),
        (input, object::Rights::READ | object::Rights::WAIT),
    ];
    let gfx = match process::spawn_detached_with_handles("gfx", 1 << 1, handles) {
        Ok((pid, _entry)) => pid,
        Err(_) => {
            let _ = object::destroy_object(input);
            let _ = object::destroy_object(display);
            let _ = object::destroy_object(console);
            fail_m6c("gfx-spawn");
        }
    };

    // 4. Wait for `gfx` to finish. The injected key and serial bytes arrive
    //    while it blocks in `wait`, so this loop must keep interrupts open.
    if !m6b2_wait_for_state(gfx, process::ProcessState::Zombie, M6C_GFX_TICKS) {
        fail_m6c("gfx-timeout");
    }
    // `gfx` is `Zombie` but not reaped yet, so its slot still reports the exit
    // status. `init`'s protected zombie slot exists in parallel, which is why
    // the status is read per pid instead of through `last_exit_status`.
    if process::exit_status(gfx) != Some(0) {
        fail_m6c("gfx-exit");
    }

    // 5. Wait for the APs to leave `gfx`'s resources before reaping it, then run
    //    the deferred object-reference drain outside every lock.
    let start = time::monotonic_ticks();
    while !m6c_aps_parked() {
        if time::monotonic_ticks().saturating_sub(start) >= M6C_PARK_TICKS {
            fail_m6c("ap-not-parked");
        }
        arch::idle();
    }
    // Only `gfx` is reaped: `init`'s zombie slot must stay (its address space and
    // kernel stack back the closing deliberate page fault), and `reap_orphan`
    // refuses to touch a process this CPU is still executing.
    if !process::reap_orphan(gfx) {
        fail_m6c("gfx-reap");
    }
    process::drain_pending_object_refs();
    if process::exit_status(gfx).is_some() || process::process_state(gfx).is_some() {
        fail_m6c("gfx-reap");
    }

    // 6. The display seat (and its shadow frames) and the input seat must be
    //    gone, and exactly the injected events must have been delivered.
    if ipc::display::live_objects() != 0 {
        fail_m6c("display-live");
    }
    if ipc::display::live_frames() != 0 {
        fail_m6c("display-frames");
    }
    if ipc::input::live_objects() != 0 {
        fail_m6c("input-live");
    }
    let events = ipc::input::published_count();
    let dropped = ipc::input::dropped_count();
    if events != M6C_EVENTS {
        fail_m6c("input-events");
    }
    if dropped != 0 {
        fail_m6c("input-dropped");
    }
    // The verdict line carries enforced evidence (`events`/`dropped` exact
    // values), so it is framed without the ` [t=N ms]` suffix that `klog!`
    // appends: the harness requires the payload to be the end of the line.
    klog_evidence(format_args!(
        "[CaelumKernel] M6c OK (events={events}, dropped={dropped})"
    ));
    // The root resumes with its contract: interrupts disabled.
    arch::disable_interrupts();
}

/// M7a closeout: run the loopback network self-test and print its evidence.
///
/// [`crate::net::selftest`] resets the stack, sends real IPv4/IPv6 UDP
/// datagrams and drives an IPv4/IPv6 TCP handshake through the loopback path
/// (checksums, parsers and the connection state machine included), then resets
/// the stack again. It returns the failing protocol as a marker, so a lost
/// datagram or a broken handshake halts here instead of letting the run look
/// successful.
///
/// Runs on the boot processor after the M6c closeout with interrupts disabled:
/// the self-test is synchronous (the loopback path is walked inline), so it
/// never needs a timer or an interrupt.
#[cfg(not(test))]
fn m7a_closeout() {
    // Byte counts the self-test sends and verifies. The UDP payloads are the
    // exported `net::UDP4_PAYLOAD`/`net::UDP6_PAYLOAD`; the TCP payload is the
    // literal `m7 tcp payload` inside `net::selftest_tcp` (fourteen bytes).
    // Both UDP payloads carry one marker each, so their lengths must agree with
    // the single `bytes=` field printed below.
    const _: () = assert!(net::UDP4_PAYLOAD.len() == net::UDP6_PAYLOAD.len());
    let udp_bytes = net::UDP4_PAYLOAD.len();
    let tcp_bytes: usize = 14;
    if let Err(marker) = net::selftest() {
        fail_m7a(marker);
    }
    // `selftest` ends with `net::init`, which closes every socket it opened: a
    // non-zero count means a leaked listener or connection.
    let live = net::socket_count();
    if live != 0 {
        fail_m7a("sockets-leaked");
    }
    klog_evidence(format_args!(
        "[CaelumKernel] M7a ipv4 udp OK (bytes={udp_bytes})"
    ));
    klog_evidence(format_args!(
        "[CaelumKernel] M7a ipv4 tcp OK (bytes={tcp_bytes})"
    ));
    klog_evidence(format_args!(
        "[CaelumKernel] M7a ipv6 udp OK (bytes={udp_bytes})"
    ));
    klog_evidence(format_args!(
        "[CaelumKernel] M7a ipv6 tcp OK (bytes={tcp_bytes})"
    ));
    klog_evidence(format_args!("[CaelumKernel] M7a sockets OK (live={live})"));
    klog_evidence(format_args!("[CaelumKernel] M7a OK (suites=4)"));
}

/// Tick budget for the `net` service: it runs twelve phases, including two TCP
/// handshakes and a five-tick timer sleep in the child, so the budget is
/// deliberately wider than the M6c one.
#[cfg(not(test))]
const M7B_NET_TICKS: u64 = 10_000;
/// Tick budget for every AP to park again after `net` exits.
#[cfg(not(test))]
const M7B_PARK_TICKS: u64 = 1_000;

/// Tick budget for the Linux64 service: six suites including two TCP
/// handshakes, a signal-free sleep and several blocking waits.
#[cfg(not(test))]
const M7D_SERVICE_TICKS: u64 = 10_000;
/// Tick budget for every AP to park again after the Linux service exits.
#[cfg(not(test))]
const M7D_PARK_TICKS: u64 = 1_000;

/// Wake hook the network stack calls when a socket's readiness changes.
///
/// Installed for the M7b closeout only and removed once `net` is gone: leaving
/// it installed would let an engine event wake a process that no longer exists.
#[cfg(not(test))]
fn m7b_wake(event: net::WakeEvent) {
    // `object == 0` means the engine socket was never published as an object
    // (the M7a self-test path); there is nothing to wake in that case.
    if event.object != 0 {
        let _ = process::wake_object(event.object, process::WakeReason::Ready);
        // M9a: an epoll instance interested in this socket must be woken too;
        // sockets do not live in the `ipc` tables, so the engine hook is the
        // only place that can fan the readiness out to epoll.
        let _ = ipc::epoll::notify_target(event.object);
    }
}

/// M7b closeout: run the user-mode `net` service on an application processor and
/// verify that its sockets and namespace bindings are all gone afterwards.
///
/// Runs on the boot processor after the M7a self-test, before the deliberate
/// page fault. The `net` parent creates its own channel to its child, so the
/// channel endpoint handed in here is only a placeholder that tells the service
/// "the kernel wired a channel for you"; both endpoints are destroyed by the
/// time this function returns.
#[cfg(not(test))]
fn m7b_closeout() {
    // 1. The engine wakes waiters through this hook. It runs after the net
    //    stack's own lock is released, so taking the process table is safe.
    net::set_wake_hook(Some(m7b_wake));

    // 2. Capabilities `net` starts with: console (write), one channel endpoint,
    //    one network namespace. The root keeps no handle; the child's handle
    //    insert takes the only reference, so closing/exiting runs the hooks.
    let console = match object::create_console() {
        Ok(object) => object,
        Err(_) => fail_m7b("console-object"),
    };
    let channel_out = match object::create_object(object::ObjectKind::Channel) {
        Ok(object) => object,
        Err(_) => fail_m7b("channel-object"),
    };
    let channel_peer = match object::create_object(object::ObjectKind::Channel) {
        Ok(object) => object,
        Err(_) => fail_m7b("channel-peer"),
    };
    if ipc::channel::create(channel_out, channel_peer).is_err() {
        fail_m7b("channel-pair");
    }
    // The root holds one reference on the unused endpoint so it can destroy the
    // link after `net` exits; without it the endpoint would stay allocated.
    if object::acquire_object(channel_peer).is_err() {
        fail_m7b("channel-peer");
    }
    let namespace = match object::create_object(object::ObjectKind::NetNamespace) {
        Ok(object) => object,
        Err(_) => fail_m7b("netns-object"),
    };

    // 3. Start `net` on AP1 with the three documented handles (rdi/rsi/rdx).
    let handles = [
        (console, object::Rights::WRITE),
        (
            channel_out,
            object::Rights::READ | object::Rights::WRITE | object::Rights::WAIT,
        ),
        (namespace, object::Rights::READ | object::Rights::WRITE),
    ];
    let net = match process::spawn_detached_with_handles("net", 1 << 1, handles) {
        Ok((pid, _entry)) => pid,
        Err(_) => fail_m7b("net-spawn"),
    };

    // 4. The service announces its own success with the thirteen `[CaelumNet]`
    //    markers and exits 0; this loop keeps interrupts open (idle = sti; hlt)
    //    so AP timers, socket wake events and the deliberate page fault path are
    //    all still live.
    if !m6b2_wait_for_state(net, process::ProcessState::Zombie, M7B_NET_TICKS) {
        fail_m7b("net-timeout");
    }
    if process::exit_status(net) != Some(0) {
        fail_m7b("net-exit");
    }

    // 5. Reaping frees the service's stacks and address space, so wait until no
    //    AP is still executing it, then run the deferred object-reference drain.
    let start = time::monotonic_ticks();
    while !m6c_aps_parked() {
        if time::monotonic_ticks().saturating_sub(start) >= M7B_PARK_TICKS {
            fail_m7b("ap-not-parked");
        }
        arch::idle();
    }
    if !process::reap_orphan(net) {
        fail_m7b("net-reap");
    }
    process::drain_pending_object_refs();
    if process::exit_status(net).is_some() || process::process_state(net).is_some() {
        fail_m7b("net-reap");
    }

    // 6. Drop the root's reference on the unused channel endpoint: this closes
    //    the link the placeholder channel created.
    let _ = object::release_object(channel_peer);
    process::drain_pending_object_refs();

    // 7. Evidence: no socket survives `net`, and the namespace has no bindings
    //    left. These are the two counters the milestone is judged on.
    let sockets = net::live_count();
    let bindings = net::binding_count(namespace);
    if sockets != 0 {
        fail_m7b("sockets-live");
    }
    if bindings != 0 {
        fail_m7b("bindings-live");
    }
    // The hook outlives its usefulness once the service is gone.
    net::set_wake_hook(None);
    klog_evidence(format_args!(
        "[CaelumKernel] M7b OK (sockets={sockets}, bindings={bindings})"
    ));
    // The root resumes with its contract: interrupts disabled.
    arch::disable_interrupts();
}

/// M7d closeout: run the Linux64 service on an application processor and verify
/// that it left no socket and no namespace binding behind.
///
/// The process is spawned with the Linux personality: the console becomes fds
/// 0/1/2, the channel endpoint and the network namespace become native handles
/// slot 0/1 that the initial stack advertises through auxv, and the service
/// speaks Linux64 syscall numbers through the compat entry. Runs on the boot
/// processor after the M7b closeout, before the deliberate page fault.
#[cfg(not(test))]
fn m7d_closeout() {
    // 0. M8d: remember how many processes exist before this phase instead of
    //    assuming an empty table. The earlier stages reap their own processes,
    //    but the native bootstrap process can still be resident; the two-process
    //    phase only requires the count to return to this baseline once the
    //    parent and its child are gone.
    process::reap_orphans();
    let process_baseline = process::live_count();

    // 1. The engine wakes Linux waiters through the same hook the native
    //    service used; it runs after the net stack's own lock is released.
    net::set_wake_hook(Some(m7b_wake));

    // 2. Capabilities the Linux process starts with. The child's tables take the
    //    references (fd 0/1/2 for the console, native slot 0/1 for the channel
    //    and the namespace); the root keeps the unused channel endpoint so the
    //    link dies when the service is gone.
    let console = match object::create_console() {
        Ok(object) => object,
        Err(_) => fail_m7d("linux-console-object"),
    };
    let channel_out = match object::create_object(object::ObjectKind::Channel) {
        Ok(object) => object,
        Err(_) => fail_m7d("linux-channel-object"),
    };
    let channel_peer = match object::create_object(object::ObjectKind::Channel) {
        Ok(object) => object,
        Err(_) => fail_m7d("linux-channel-peer"),
    };
    if ipc::channel::create(channel_out, channel_peer).is_err() {
        fail_m7d("linux-channel-pair");
    }
    if object::acquire_object(channel_peer).is_err() {
        fail_m7d("linux-channel-peer");
    }
    let namespace = match object::create_object(object::ObjectKind::NetNamespace) {
        Ok(object) => object,
        Err(_) => fail_m7d("linux-netns-object"),
    };

    // 3. Start the Linux personality on AP1. `spawn_detached_linux` owns the
    //    console fd table and the child handles from here on; the initial stack
    //    is built by the compat stack encoder and its `rsp` is 16-byte aligned.
    let channel = Some((
        channel_out,
        object::Rights::READ | object::Rights::WRITE | object::Rights::WAIT,
    ));
    let netns = Some((namespace, object::Rights::READ | object::Rights::WRITE));
    let service = match process::spawn_detached_linux("linux", 1 << 1, console, channel, netns) {
        Ok(pid) => pid,
        Err(_) => fail_m7d("linux-spawn"),
    };

    // 3b. M8d: the same image also runs the two-process closure. The process
    //     above is the detached role-0 parent; spawn its role-1 child now so it
    //     is already parked on the handshake when the parent finishes the
    //     single-process suites. Their Linux pids are index+1 and therefore
    //     depend on the resident baseline, not on fixed slot numbers. Both stay
    //     on AP1: the parent's blocking `wait4` replay relies on the child's
    //     exit wake arriving on the same CPU that runs the parent. The child
    //     only needs the console (it communicates through signals, not
    //     channels), and the parent reaps it through `wait4` — the root only
    //     reaps the parent.
    let child_role = crate::compat::linux::stack::CAELUM_ROLE_CHILD;
    if process::spawn_linux_child(service, "linux", 1 << 1, console, None, None, child_role)
        .is_err()
    {
        fail_m7d("linux-child-spawn");
    }

    // 3c. M9c: a second long-lived child is the file-lock protocol peer. It runs
    //     the same image with role 2, talks to the parent through SIGUSR2/SIGUSR1
    //     broadcasts and exits through the protocol; the parent reaps it before
    //     it prints the M9c marker. The root only reaps the parent.
    let lock_peer_role = crate::compat::linux::stack::CAELUM_ROLE_LOCK_PEER;
    if process::spawn_linux_child(
        service,
        "linux",
        1 << 1,
        console,
        None,
        None,
        lock_peer_role,
    )
    .is_err()
    {
        fail_m7d("linux-lock-peer-spawn");
    }

    // 4. The service runs its suites, prints its own markers and exits 0. The
    //    wait keeps interrupts open so AP timers and socket wake events arrive.
    if !m6b2_wait_for_state(service, process::ProcessState::Zombie, M7D_SERVICE_TICKS) {
        fail_m7d("linux-timeout");
    }
    if process::exit_status(service) != Some(0) {
        fail_m7d("linux-exit");
    }

    // 5. Reaping frees the service's stacks and address space, so wait until no
    //    AP still runs it, then run the deferred object-reference drain.
    let start = time::monotonic_ticks();
    while !m6c_aps_parked() {
        if time::monotonic_ticks().saturating_sub(start) >= M7D_PARK_TICKS {
            fail_m7d("linux-ap-not-parked");
        }
        arch::idle();
    }
    if !process::reap_orphan(service) {
        fail_m7d("linux-reap");
    }
    process::drain_pending_object_refs();
    if process::exit_status(service).is_some() || process::process_state(service).is_some() {
        fail_m7d("linux-reap");
    }
    // The parent must have reaped its child through `wait4` before exiting, and
    // the root then reaps the parent: the process count has to fall back to the
    // baseline measured on entry. A live extra process means the two-process
    // closure did not complete, and treating the parent's exit as success would
    // hide it.
    if process::live_count() != process_baseline {
        fail_m7d("linux-child-not-reaped");
    }

    // 5b. M9d1: run the dynamic-linker closure (`/fat/dyn-main` plus the
    //     `/fat/ldcaelum.so` interpreter named by its PT_INTERP record). It runs
    //     after the socket/lock closure has released its slots, and it needs a
    //     console of its own: the service's console object died with the
    //     service's fds. A fresh console owns one creation reference here; the
    //     installed fds 0/1/2 take their own three, so the creation reference is
    //     dropped immediately after the spawn.
    let dynamic_console = match object::create_with_payload(object::ObjectKind::Console, 0) {
        Ok(object) => object,
        Err(_) => fail_m7d("dyn-console"),
    };
    let dynamic = match process::spawn_detached_linux_dynamic(
        image::DYNAMIC_MAIN_PATH,
        1 << 1,
        dynamic_console,
    ) {
        Ok(pid) => pid,
        Err(_) => fail_m7d("dyn-spawn"),
    };
    let _ = object::release_object(dynamic_console);
    if !m6b2_wait_for_state(dynamic, process::ProcessState::Zombie, M7D_SERVICE_TICKS) {
        fail_m7d("dyn-timeout");
    }
    if process::exit_status(dynamic) != Some(0) {
        fail_m7d("dyn-exit");
    }
    let start = time::monotonic_ticks();
    while !m6c_aps_parked() {
        if time::monotonic_ticks().saturating_sub(start) >= M7D_PARK_TICKS {
            fail_m7d("dyn-ap-not-parked");
        }
        arch::idle();
    }
    if !process::reap_orphan(dynamic) {
        fail_m7d("dyn-reap");
    }
    process::drain_pending_object_refs();
    if process::live_count() != process_baseline {
        fail_m7d("dyn-not-reaped");
    }

    // 5c. M10a: run a real dynamically linked musl program
    //     (`/bin/busybox echo "[CaelumLinux] M10a hello OK"`). The kernel maps
    //     the main image at the frozen program bias and the real `ET_DYN`
    //     interpreter named by `PT_INTERP` at its own bias, and reports it to
    //     the interpreter through `AT_BASE`. The program needs its own console
    //     for fd 1, exactly like the previous dynamic closure.
    let program_console = match object::create_with_payload(object::ObjectKind::Console, 0) {
        Ok(object) => object,
        Err(_) => fail_m7d("prog-console"),
    };
    let program_argv: [&[u8]; 3] = [b"/bin/busybox", b"echo", b"[CaelumLinux] M10a hello OK"];
    let program = match process::spawn_detached_linux_program(
        b"/bin/busybox",
        b"/lib/ld-musl-x86_64.so.1",
        &program_argv,
        1 << 1,
        program_console,
    ) {
        Ok(pid) => pid,
        Err(_) => fail_m7d("prog-spawn"),
    };
    let _ = object::release_object(program_console);
    if !m6b2_wait_for_state(program, process::ProcessState::Zombie, M7D_SERVICE_TICKS) {
        fail_m7d("prog-timeout");
    }
    if process::exit_status(program) != Some(0) {
        fail_m7d("prog-exit");
    }
    let start = time::monotonic_ticks();
    while !m6c_aps_parked() {
        if time::monotonic_ticks().saturating_sub(start) >= M7D_PARK_TICKS {
            fail_m7d("prog-ap-not-parked");
        }
        arch::idle();
    }
    if !process::reap_orphan(program) {
        fail_m7d("prog-reap");
    }
    process::drain_pending_object_refs();
    if process::live_count() != process_baseline {
        fail_m7d("prog-not-reaped");
    }

    // 6. Drop the root's reference on the unused channel endpoint: this closes
    //    the link, and the destroy hook releases the fds/sockets of the service.
    let _ = object::release_object(channel_peer);
    process::drain_pending_object_refs();

    // 7. Evidence: the Linux process left no socket and no namespace binding.
    let sockets = net::live_count();
    let bindings = net::binding_count(namespace);
    if sockets != 0 {
        fail_m7d("linux-sockets-live");
    }
    if bindings != 0 {
        fail_m7d("linux-bindings-live");
    }
    // M9c: both Linux processes are gone, so every POSIX/OFD/flock record they
    // held must have been released by their exits (including the parent's own
    // close of the lock file). A surviving record means the lock teardown is
    // incomplete and would leak into the next stage.
    let locks = vfs::lock_count();
    if locks != 0 {
        fail_m7d("linux-locks-live");
    }
    net::set_wake_hook(None);
    klog_evidence(format_args!(
        "[CaelumKernel] M7d OK (sockets={sockets}, bindings={bindings})"
    ));
    // The root resumes with its contract: interrupts disabled.
    arch::disable_interrupts();
}

/// M7c-1a: probe the legacy virtio-net function and verify its identity.
///
/// The driver supports only the transitional virtio 0.9.5 PCI function and
/// requires the MSI-X capability (it has no INTx fallback), so this slice
/// proves exactly that: one device exists, the MAC and link registers are
/// readable, and the link is up. ARP, the IPv4 address/route configuration and
/// the UDP echo are the next slice and reuse the same device through `io`.
#[cfg(not(test))]
fn m7c_probe_closeout() {
    let count = match io::init_net() {
        Ok(count) => count,
        Err(reason) => fail_m7c(reason),
    };
    if count != 1 {
        fail_m7c("unexpected-nic-count");
    }
    // The acceptance QEMU command line pins this MAC address, so a different
    // value means the guest reached some other function or the command line
    // was not updated for M7c.
    const EXPECTED_MAC: [u8; 6] = [0x52, 0x54, 0x00, 0x12, 0x34, 0x56];
    let mac = match io::mac() {
        Some(mac) => mac,
        None => fail_m7c("mac-missing"),
    };
    if mac != EXPECTED_MAC {
        klog!(
            "[CaelumKernel] M7c mac={:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            mac[0],
            mac[1],
            mac[2],
            mac[3],
            mac[4],
            mac[5]
        );
        fail_m7c("mac-mismatch");
    }
    match io::link_status() {
        Some(link) if link.up => {}
        Some(_) => fail_m7c("link-down"),
        None => fail_m7c("link-unknown"),
    }
    klog!("[CaelumKernel] M7c nic OK (mac=52:54:00:12:34:56, link=up)");
}

/// Write one M6b2 evidence line **without** the ` [t=N ms]` timestamp suffix.
///
/// The acceptance harness parses each of the five M6b2 lines as
/// `marker + " (key=value, ...)"` and requires the payload to be the last thing
/// on the line, so these lines are framed here instead of going through
/// [`klog!`], which appends the timestamp and would put it after the payload.
/// Everything else keeps the normal timestamped form.
#[cfg(not(test))]
fn klog_evidence(args: core::fmt::Arguments<'_>) {
    struct Line<'a> {
        buf: &'a mut [u8],
        len: usize,
    }

    impl core::fmt::Write for Line<'_> {
        fn write_str(&mut self, s: &str) -> core::fmt::Result {
            let end = self.len + s.len();
            if end > self.buf.len() {
                return Err(core::fmt::Error);
            }
            self.buf[self.len..end].copy_from_slice(s.as_bytes());
            self.len = end;
            Ok(())
        }
    }

    // The longest line is the verdict (~130 bytes); 192 leaves headroom for
    // wider counters without ever truncating an acceptance marker.
    let mut storage = [0u8; 192];
    let mut line = Line {
        buf: &mut storage,
        len: 0,
    };
    if core::fmt::write(&mut line, args).is_err() {
        klog!("[CaelumKernel] M6b2 FAIL evidence-line-overflow; halting");
        arch::halt();
    }
    let len = line.len;
    drop(line);
    crate::log::serial_write_bytes(&storage[..len]);
    crate::log::serial_write_bytes(b"\r\n");
}

/// M6b2 closeout: run the two `worker` workloads on the application
/// processors and print the five scheduling-evidence lines.
///
/// Runs on the boot processor after `m6a2_closeout`, before the deliberate M2
/// page fault. Every number below is taken from **one** [`sched::smp_stats`]
/// snapshot: the verdict and the four evidence lines can never disagree.
#[cfg(not(test))]
fn m6b2_closeout() {
    // Reset the per-CPU counters and flags: everything counted from here on
    // describes the M6b2 workers. Interrupts are off here and the APs are still
    // parked in the M6b1 idle loop, so nothing races the reset.
    sched::init_smp();
    // `init`/`child` are gone; collect any zombie they left so the worker slots
    // are free.
    let _ = process::reap_orphans();

    let first = match process::spawn_detached("worker", M6B2_WORKER_AFFINITY) {
        Ok(pid) => pid,
        Err(_) => fail_m6b2("worker-spawn"),
    };
    let second = match process::spawn_detached("worker", M6B2_WORKER_AFFINITY) {
        Ok(pid) => pid,
        Err(_) => fail_m6b2("worker-spawn"),
    };

    // Let the APs leave the M6b1 park loop. They re-check the request flag when
    // something wakes them, so kick every online AP once; a lost IPI only costs
    // latency because the flag is also polled.
    //
    // Flipping the flag first is what moves the timer dispatcher onto the
    // per-CPU path: from the moment an AP arms its timer (`ap_main`) its ticks
    // must no longer be accounted as boot-processor ticks. The boot processor
    // installed its per-CPU block in `complete_m4`, so `arch::cpu_index()` is
    // valid on every CPU from here on.
    SMP_TIMERS_ARMED.store(true, core::sync::atomic::Ordering::Release);
    sched::enable_smp_scheduler();
    let aps = smp::online_count();
    for cpu in 1..=aps {
        let _ = platform::send_reschedule_ipi(cpu);
    }
    sched::publish_resched();

    // A single kick can race the request flag on a busy AP, and an AP that never
    // leaves the M6b1 park loop would never run its worker. Wait (bounded) until
    // every online AP has really armed its timer, re-sending the kick: the flag
    // is polled too, so a lost IPI costs latency rather than the milestone.
    let wanted_aps = ((1u64 << (aps + 1)) - 1) & !1u64;
    let start = time::monotonic_ticks();
    while sched::started_aps() != wanted_aps {
        for cpu in 1..=aps {
            let _ = platform::send_reschedule_ipi(cpu);
        }
        sched::publish_resched();
        if time::monotonic_ticks().saturating_sub(start) >= 100 {
            fail_m6b2("ap-start");
        }
        arch::idle();
    }

    // Both workers spin on `abi_query` (where the AP timers preempt them) and
    // then block on their own 20-tick timer.
    if !m6b2_wait_for_state(first, process::ProcessState::Blocked, M6B2_BLOCK_TICKS)
        || !m6b2_wait_for_state(second, process::ProcessState::Blocked, M6B2_BLOCK_TICKS)
    {
        fail_m6b2("worker-blocked");
    }

    // One affinity-driven move (AP1 -> AP2), then balance the other worker onto
    // the least loaded AP (AP3). Both counters are booked only when the target
    // CPU really resumes the process.
    //
    // The affinity mask has to be widened first: a move cannot leave the
    // allowed set, so the explicit migration would otherwise be refused. The
    // two explicit calls also make the intent unambiguous - the balancer is
    // free to pick any AP, the migration is pinned to AP2.
    if process::set_affinity(first.index(), 1 << 2).is_err() {
        fail_m6b2("affinity");
    }
    if process::migrate(first, 2).is_err() {
        fail_m6b2("migrate");
    }
    if process::set_affinity(second.index(), 0x0F).is_err() {
        fail_m6b2("affinity");
    }
    match process::rebalance(second) {
        Ok(3) => {}
        Ok(_) => fail_m6b2("balance-target"),
        Err(_) => fail_m6b2("balance"),
    }
    sched::publish_resched();

    // The BSP timer expires the workers' timers; each wake targets a different
    // CPU, so the wake path must send a reschedule IPI for it. Both workers then
    // run their final check and exit.
    let first_exited = m6b2_wait_for_state(first, process::ProcessState::Zombie, M6B2_EXIT_TICKS);
    let second_exited = m6b2_wait_for_state(second, process::ProcessState::Zombie, M6B2_EXIT_TICKS);
    if !first_exited || !second_exited {
        fail_m6b2("worker-exit");
    }
    // Wait (bounded) until every AP has really left the process context: parked
    // on its own kernel stack, on the kernel page tables, out of the worker's
    // address space. An AP that is still on a worker's stack or CR3 would take
    // its next timer tick on memory the reap below is about to release, which
    // stops the whole VM (QEMU runs with `-no-reboot -no-shutdown`) and shows up
    // as a BSP that freezes in the middle of a later klog line.
    let ap_mask = sched::started_aps();
    let park_start = time::monotonic_ticks();
    while sched::parked_aps() & ap_mask != ap_mask
        && time::monotonic_ticks().wrapping_sub(park_start) < 20
    {
        time::wait_for_ticks(1);
    }
    if sched::parked_aps() & ap_mask != ap_mask {
        crate::klog!(
            "[CaelumKernel] M6b2 FAIL ap-not-parked (parked={:#x}, started={:#x}); halting",
            sched::parked_aps(),
            ap_mask
        );
        arch::halt();
    }
    let _ = process::reap_orphans();
    // The workers' Timer objects die with their handle tables; the pending
    // reference queues must be drained outside the table locks before the
    // statistics are taken.
    let _ = process::drain_pending_object_refs();

    let stats = sched::smp_stats();
    // Frozen minimums (agents.md §22 M6b2 and xtask); every line is checked
    // before anything is printed so a shortfall can never look like success.
    if stats.runs < 2 {
        fail_m6b2("runs");
    }
    if stats.cpus < 1 {
        fail_m6b2("cpus");
    }
    if stats.preempts < 2 {
        fail_m6b2("preempts");
    }
    if stats.remote_wakes < 1 {
        fail_m6b2("remote_wakes");
    }
    if stats.ipis < 1 {
        fail_m6b2("ipis");
    }
    if stats.migrations < 1 {
        fail_m6b2("migrations");
    }
    if stats.balances < 1 {
        fail_m6b2("balances");
    }
    // The five lines below are the M6b2 acceptance evidence. They are framed
    // without the ` [t=N ms]` suffix so the `(key=value, ...)` payload is the
    // last thing on the line, which is what the acceptance harness parses.
    klog_evidence(format_args!(
        "[CaelumKernel] M6b2 ap user OK (runs={}, cpus={})",
        stats.runs, stats.cpus
    ));
    klog_evidence(format_args!(
        "[CaelumKernel] M6b2 ap preempt OK (preempts={})",
        stats.preempts
    ));
    klog_evidence(format_args!(
        "[CaelumKernel] M6b2 wake ipi OK (remote_wakes={}, ipis={})",
        stats.remote_wakes, stats.ipis
    ));
    klog_evidence(format_args!(
        "[CaelumKernel] M6b2 migrate OK (migrations={}, balances={})",
        stats.migrations, stats.balances
    ));
    klog_evidence(format_args!(
        "[CaelumKernel] M6b2 OK (runs={}, cpus={}, preempts={}, remote_wakes={}, ipis={}, migrations={}, balances={})",
        stats.runs,
        stats.cpus,
        stats.preempts,
        stats.remote_wakes,
        stats.ipis,
        stats.migrations,
        stats.balances
    ));
    // The root below runs with interrupts disabled (it mutates unsynchronised
    // global state) and the deliberate M2 fault must also be taken with IF=0 so
    // the dump is not preempted by a timer. The polling loops above use
    // `arch::idle`, which leaves IF=1, so restore the root's contract here.
    arch::disable_interrupts();
}

/// Probe and install the first real entropy backend, printing one diagnostic line.
///
/// Called from [`complete_m4`] after `M4 OK`: user-mode M4 asserts that the RNG
/// still reports `NoEntropy`, so seeding must not happen earlier. Every later
/// secure consumer (`AT_RANDOM`, `getrandom`, native random handles) depends on
/// this point having run.
#[cfg(not(test))]
fn initialise_rng() {
    let state = rng::initialise();
    klog!(
        "[CaelumKernel] M8h rng state={:?} source={} entropy_bits={}",
        state,
        rng::backend_name(),
        rng::entropy_bits()
    );
}

pub fn complete_m4(status: u64) -> ! {
    if status != 0 {
        klog!("[CaelumKernel] M4 FAIL exit status {status}; halting");
        arch::halt();
    }
    // The process that just exited is the last one, so `on_user_exit` handed
    // control here instead of reaping it. Do the ownership half of reaping now.
    #[cfg(not(test))]
    release_last_process_resources();
    klog!("[CaelumKernel] M4 exit OK (init and child exited, status 0)");
    klog!("[CaelumKernel] M4 OK");
    // M8h: install the real entropy backend before the stages below need secure
    // random bytes (AT_RANDOM in `spawn_linux_child`, `getrandom`, native
    // random handles). The M4 user phase above required `NoEntropy`, so this is
    // the earliest safe point; the marker records the chosen source.
    #[cfg(not(test))]
    initialise_rng();
    // The boot context is still alive with interrupts off; M5c stage 2 runs here
    // so the deliberate #PF below stays the single final marker.
    #[cfg(not(test))]
    m5c_persist();
    // The M6a2 closeout is the last stage check: it runs after the M6a marker
    // (printed at the end of `m5c_persist`) and before the deliberate page fault
    // below, so `M2 #PF caught` remains the single final marker.
    #[cfg(not(test))]
    m6a2_closeout();
    // M6b2 is the scheduling half of SMP: two handle-less `worker` processes
    // prove per-CPU ring3 execution, AP timer preemption, cross-CPU wake IPIs,
    // affinity migration and load balancing. It prints its five evidence lines
    // here, before the deliberate page fault below.
    #[cfg(not(test))]
    m6b2_closeout();
    // M6c is the display/input slice: the kernel probes the GOP, `gfx` maps and
    // presents the shadow buffer and receives the injected input events. It
    // prints its probe/verdict lines here, before the deliberate page fault.
    #[cfg(not(test))]
    m6c_closeout();
    // M7a is the network slice: the loopback self-test exercises IPv4/IPv6 UDP
    // and TCP through the real stack and prints its evidence lines here, before
    // the deliberate page fault.
    #[cfg(not(test))]
    m7a_closeout();
    // M7b is the native socket slice: the user-mode `net` service drives the
    // real local/loopback paths through NR44–53 and prints its thirteen
    // `[CaelumNet]` markers; the kernel only prints the final verdict, after it
    // has verified that no socket and no namespace binding survived.
    #[cfg(not(test))]
    m7b_closeout();
    // M7d is the Linux64 personality slice: the `linux` service speaks Linux
    // syscall numbers (`rax` = number, `rax` = -errno on return) over the same
    // socket engine, and the kernel verifies that it left no socket and no
    // namespace binding before printing the final verdict.
    #[cfg(not(test))]
    m7d_closeout();
    // M7c-1a is the virtio-net hardware slice: it proves that the legacy PCI
    // function exposes MSI-X and reports a usable MAC/link before the final
    // deliberate page fault.
    #[cfg(not(test))]
    m7c_probe_closeout();
    klog!(
        "[CaelumKernel] triggering deliberate page fault: read @ 0x{:016x}",
        arch::traps::DELIBERATE_PF_ADDR
    );
    // SAFETY: deliberately reads an unmapped kernel address; the #PF handler
    // recognises it and reports `M2 #PF caught` as the final marker.
    unsafe {
        core::ptr::read_volatile(arch::traps::DELIBERATE_PF_ADDR as *const u8);
    }
    fail_m4("deliberate page fault did not fire")
}
