//! M5b storage I/O: legacy (transitional) `virtio-blk` block devices.
//!
//! # What this module is
//!
//! A synchronous, polling driver for the **legacy** virtio 0.9.5 PCI interface
//! (`vendor 0x1AF4`, device `0x1001`, I/O BAR0) plus a thin [`VirtioBlk`]
//! handle that implements [`block::BlockDevice`], so the M5b filesystems can
//! borrow a device without knowing anything about virtio.
//!
//! QEMU's `-drive if=virtio` exposes the transitional interface as `0x1001`
//! when the guest programs the legacy interface, which is exactly the contract
//! this driver targets: at most [`MAX_BLOCK_DEVICES`] disks, one legacy queue
//! each, no control queue, no multiqueue, no indirect descriptors, no
//! `VIRTIO_F_EVENT_IDX`, no MSI/MSI-X and **no interrupts at all**.
//!
//! # Deliberate non-goals (M5b)
//!
//! * Modern virtio 1.0/1.1 (`0x1042`, MMIO BAR4, `FEATURES_OK`). A machine that
//!   only exposes `0x1042` is rejected loudly by [`init`] instead of being
//!   silently driven through the wrong register layout.
//! * Interrupt-driven completion: [`init`] never installs an IRQ handler and the
//!   request path never enables device interrupts. Everything is polled with a
//!   bounded timeout, so a stuck device produces [`block::BlockError::Timeout`]
//!   instead of a hang.
//! * Request queues with more than one request in flight. One request drives
//!   three fixed descriptors; concurrency is the filesystem's business.
//!
//! # DMA safety boundary (no IOMMU)
//!
//! There is no IOMMU in M5b, so the device may DMA to any physical address it
//! is given. The safety boundary is therefore **ownership, not translation**:
//!
//! * The only memory the device ever sees is the driver's own DMA region: two
//!   contiguous frames for the virtqueue and one frame for the 4 KiB bounce
//!   buffer, per device. These physical addresses are recorded and never come
//!   from a user pointer, a `VmObject` or a page cache.
//! * The region is reserved early, by [`reserve_dma`], while the physical frame
//!   allocator still hands out contiguous runs (right after `pmm::init` and
//!   before the kernel heap exists). By the time M5b probes the devices the free
//!   list is no longer ordered, so a late two-frame allocation can fail; probing
//!   consumes the reservation and keeps the allocation as a fallback only.
//! * The CPU touches that region only through the direct map
//!   ([`crate::mm::vm::phys_to_virt`]); the device sees the physical addresses
//!   stored in the descriptors. Both aliases must describe the same bytes —
//!   the direct map is built for all conventional RAM before M5b runs.
//! * Every filesystem buffer is copied through the bounce frame, so a request
//!   can never name a page the device does not own.
//!
//! Per-device DMA budget: **3 frames (12 KiB)** for two devices → 6 frames.
//!
//! # Concurrency model
//!
//! M5b is single-CPU and the driver has no locks: each operation runs inside an
//! [`IrqGuard`] that disables interrupts, so a timer tick cannot preempt a
//! half-submitted request. This is also why the handles may be handed to
//! different filesystems: every call is atomic with respect to interrupt
//! context, and one request is in flight at a time. A request is bounded by a
//! timeout, so a disabled-interrupt window is bounded too.
//!
//! # Self-test fault injection (M5c3)
//!
//! A privileged kernel self test can ask for the **next** operation of one kind
//! on one device to fail with [`block::BlockError::Io`] without touching the
//! transport or the hardware: [`inject_next_fault`] only arms a one-shot flag,
//! and the handle consumes it in `read_blocks`/`write_blocks`/`flush` *before*
//! any descriptor is built. The request therefore never reaches the device and
//! the queue, the DMA region and the in-flight state stay exactly as they were,
//! which is what makes the injected failure comparable to a real I/O error
//! instead of a simulated one. This is kernel-only test scaffolding: no user
//! syscall exposes it and the uninjected path is the M5b path unchanged.
//!
//! The table is fixed (`MAX_BLOCK_DEVICES` × three operations, one pending flag
//! each), mutated under [`IrqGuard`], and never allocates or prints. A flag is
//! cleared when the operation consumes it; [`clear_injected_fault`] drops the
//! armed faults of one device so a self test leaves no residue, and
//! [`pending_fault`] lets it assert that nothing is still armed.
//!
//! # Not supported / loud failures
//!
//! A missing device, an MMIO (non-I/O) BAR0, a queue size outside the legacy
//! window or one the per-queue frame budget cannot hold, a device that never
//! completes and a device that reports a failed status all produce an explicit
//! error. None of them is silently ignored and no path fakes success.
//!
//! # M7c networking (`virtio-net`)
//!
//! [`virtio_net`] adds the legacy transitional `virtio-net` device (`0x1000`) on
//! the same transport generation as the block driver above: one RX and one TX
//! legacy queue, a fixed DMA budget, MSI-X delivery on one shared vector and a
//! copied RX ring so the future `kernel/src/net` stack can consume complete
//! Ethernet frames without ever holding a DMA-lifetime reference.
//!
//! The net device has its own early reservation ([`reserve_net_dma`]) because
//! the boot path reserves block frames before this driver can run; both tables
//! are fixed arrays and both are released by their own unconsumed-release call.

mod virtio_blk;
mod virtio_net;
mod virtqueue;

pub use virtio_blk::VirtioBlk;
pub use virtio_net::{
    LinkStatus, NetIoError, NetProbeError, VIRTIO_NET_IRQ_VECTOR, VirtioNet, config_change_count,
    device_count as net_device_count, init as init_net, irq_count, link_status, mac, on_irq,
    rx_count, tx_count,
};

use block::BlockError;
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use crate::mm::{pmm, vm};
use crate::platform;

/// Virtio's PCI vendor id.
pub const VIRTIO_PCI_VENDOR_ID: u16 = 0x1AF4;
/// Legacy/transitional virtio block device (virtio 0.9.5 PCI layout).
pub const VIRTIO_PCI_DEVICE_LEGACY_BLOCK: u16 = 0x1001;
/// Modern (virtio 1.0+) block device; deliberately unsupported in M5b.
pub const VIRTIO_PCI_DEVICE_MODERN_BLOCK: u16 = 0x1042;
/// How many block devices M5b can drive (QEMU gives us at most two).
pub const MAX_BLOCK_DEVICES: usize = 2;
/// Legacy virtio-blk always reports capacity and requests in 512-byte sectors.
pub const VIRTIO_BLK_SECTOR_SIZE: u32 = 512;
/// Device feature bit 9: flush support.
pub const VIRTIO_BLK_F_FLUSH: u32 = 1 << 9;

/// Legacy/transitional virtio network device (virtio 0.9.5 PCI layout).
pub const VIRTIO_PCI_DEVICE_LEGACY_NET: u16 = 0x1000;
/// Modern (virtio 1.0+) network device; the legacy driver refuses it loudly.
pub const VIRTIO_PCI_DEVICE_MODERN_NET: u16 = 0x1041;
/// How many virtio-net devices M7c can drive (QEMU provides one NIC).
pub const MAX_NET_DEVICES: usize = 1;
/// Device feature bit 5: the device config carries a MAC address.
pub const VIRTIO_NET_F_MAC: u32 = 1 << 5;
/// Device feature bit 16: the device config carries a link status word.
pub const VIRTIO_NET_F_STATUS: u32 = 1 << 16;

/// Virtual-queue frames for one net queue.
///
/// QEMU's legacy virtio-net reports 256 descriptors (`rx_queue_size` and
/// `tx_queue_size` cannot be 128) and the used ring must start on a 4096-byte
/// boundary, so the queue occupies 10244 bytes: three frames (descriptors
/// 0..4096, avail 4096..4612, used 8192..10244). The block driver's
/// 128-descriptor queue still needs only two frames ([`QUEUE_FRAMES`]).
pub(crate) const NET_QUEUE_FRAMES: usize = 3;
/// Legacy virtio-net header prepended to every frame the driver transmits.
pub(crate) const NET_HDR_SIZE: usize = 10;
/// Largest Ethernet frame the driver accepts or hands back (FCS excluded).
pub(crate) const NET_MAX_FRAME: usize = 1514;
/// Bytes of one RX buffer posted to the device.
pub(crate) const NET_RX_BUFFER_SIZE: usize = 2048;
/// RX buffers posted up front; the ring depth is part of the fixed budget.
pub(crate) const NET_RX_BUFFERS: usize = 8;
/// Frames backing the RX buffer run (8 × 2048 = 4 pages).
pub(crate) const NET_RX_BUFFER_FRAMES: usize =
    (NET_RX_BUFFERS * NET_RX_BUFFER_SIZE) / pmm::FRAME_SIZE as usize;
/// Frames backing the TX bounce buffer (one 4 KiB frame holds 10 + 1514 bytes).
pub(crate) const NET_TX_BOUNCE_FRAMES: usize = 1;

/// DMA frames for the virtqueue of one device.
const QUEUE_FRAMES: usize = 2;
/// DMA frames for the bounce buffer of one device.
const BOUNCE_FRAMES: usize = 1;
/// Largest contiguous run the reservation code can allocate (RX buffers need 4).
pub(crate) const MAX_CONTIG_FRAMES: usize = 4;

static INITIALISED: AtomicBool = AtomicBool::new(false);
static DEVICE_COUNT: AtomicUsize = AtomicUsize::new(0);

/// The real device state lives here; [`VirtioBlk`] handles only carry an index.
static mut DEVICES: [Option<virtio_blk::Device>; MAX_BLOCK_DEVICES] = [None, None];

/// Disables interrupts for the duration of one driver operation.
///
/// The driver is single-CPU and polled: while it owns the device, a timer tick
/// could otherwise switch away in the middle of a descriptor chain. Nesting is
/// supported because the previous IF state is restored in [`Drop`].
pub(crate) struct IrqGuard {
    was_enabled: bool,
}

impl IrqGuard {
    pub(crate) fn new() -> Self {
        Self {
            was_enabled: crate::arch::disable_interrupts(),
        }
    }
}

impl Drop for IrqGuard {
    fn drop(&mut self) {
        crate::arch::restore_interrupts(self.was_enabled);
    }
}

/// Enumerate the PCI bus and bring up every legacy virtio-blk device.
///
/// Returns the number of block devices that were initialised (0..=
/// [`MAX_BLOCK_DEVICES`]). Idempotent: a second call returns the first result
/// without touching the devices again.
///
/// Errors are strings because the caller (the M5b root) prints them verbatim in
/// its `M5 FAIL` marker; they always name what was expected and what was found.
pub fn init() -> Result<usize, &'static str> {
    if INITIALISED.load(Ordering::SeqCst) {
        return Ok(DEVICE_COUNT.load(Ordering::SeqCst));
    }
    // Initialisation programs the queue and the device status register; a
    // preempting timer between those writes would corrupt the handshake.
    let _guard = IrqGuard::new();
    let outcome = probe_devices();
    // Probing consumes the frames reserved before the heap existed. Anything
    // left over belongs to a device this machine does not have, so it goes back
    // to the frame allocator instead of staying reserved for the whole boot.
    release_unconsumed_reservations();
    let (found, modern_only) = outcome?;

    if found == 0 {
        if modern_only {
            return Err(
                "virtio-blk: only a modern (0x1042) function is present; the legacy 0x1001 \
                 interface is required (NotSupported)",
            );
        }
        return Err("virtio-blk: no legacy (0x1001) block device found");
    }

    DEVICE_COUNT.store(found, Ordering::SeqCst);
    INITIALISED.store(true, Ordering::SeqCst);
    Ok(found)
}

/// Bring up every legacy device; returns `(found, saw_modern_only)`.
fn probe_devices() -> Result<(usize, bool), &'static str> {
    let functions = platform::init_pci()?;
    if functions == 0 {
        return Err("virtio-blk: PCI enumeration found no functions");
    }

    let mut found = 0usize;
    let mut modern_only = false;
    for instance in 0..MAX_BLOCK_DEVICES {
        match virtio_blk::probe(instance) {
            Ok(device) => {
                store_device(found, device);
                found += 1;
            }
            Err(virtio_blk::ProbeError::NotFound) => break,
            Err(virtio_blk::ProbeError::ModernOnly) => {
                modern_only = true;
                break;
            }
            Err(virtio_blk::ProbeError::Failed(reason)) => return Err(reason),
        }
    }
    Ok((found, modern_only))
}

/// Number of block devices [`init`] brought up.
pub fn block_device_count() -> usize {
    DEVICE_COUNT.load(Ordering::SeqCst)
}

/// Borrow block device `index` (0-based, as enumerated by [`init`]).
pub fn virtio_block(index: usize) -> Result<VirtioBlk, &'static str> {
    if index >= DEVICE_COUNT.load(Ordering::SeqCst) {
        return Err("virtio-blk: block device index out of range");
    }
    VirtioBlk::new(index).ok_or("virtio-blk: block device index out of range")
}

/// Run `f` with the device at `index`, with interrupts disabled.
///
/// Returns `None` when the slot is empty (i.e. `index` was never initialised).
pub(crate) fn with_device<R>(
    index: usize,
    f: impl FnOnce(&mut virtio_blk::Device) -> R,
) -> Option<R> {
    if index >= MAX_BLOCK_DEVICES {
        return None;
    }
    let _guard = IrqGuard::new();
    // SAFETY: the caller holds the interrupt guard, so no ISR or other context
    // can touch the slot concurrently; the slot is written only by `init`.
    let slots = core::ptr::addr_of_mut!(DEVICES) as *mut Option<virtio_blk::Device>;
    let slot = unsafe { &mut *slots.add(index) };
    slot.as_mut().map(f)
}

/// Install a successfully probed device in the next free slot.
fn store_device(index: usize, device: virtio_blk::Device) {
    debug_assert!(index < MAX_BLOCK_DEVICES, "device slot out of range");
    // SAFETY: `init` is the only writer and runs once, before any handle exists.
    let slots = core::ptr::addr_of_mut!(DEVICES) as *mut Option<virtio_blk::Device>;
    unsafe {
        *slots.add(index) = Some(device);
    }
}

// --- One-shot self-test fault injection ------------------------------------

/// One operation of one device that the next call must fail.
///
/// The variants mirror the three [`block::BlockDevice`] operations of
/// [`VirtioBlk`], so a self test can pick the exact error path it wants to
/// exercise (`write`/`flush` are the M5c3 targets; `read` is provided for
/// symmetry and negative testing).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BlockFault {
    /// The next `read_blocks` fails with [`BlockError::Io`].
    Read,
    /// The next `write_blocks` fails with [`BlockError::Io`].
    Write,
    /// The next [`block::BlockDevice::flush`] fails with [`BlockError::Io`].
    Flush,
}

impl BlockFault {
    /// Number of injectable operations.
    const KINDS: usize = 3;

    /// Row index inside [`FaultTable`].
    const fn slot(self) -> usize {
        match self {
            Self::Read => 0,
            Self::Write => 1,
            Self::Flush => 2,
        }
    }

    /// The error this fault reports when it is consumed.
    ///
    /// Always [`BlockError::Io`]: the point is to look like a transport
    /// failure, not like the device rejecting the request
    /// (`Unsupported`/`Corrupt`) or taking too long (`Timeout`).
    pub(crate) const fn error(self) -> BlockError {
        BlockError::Io
    }

    /// Stable name for the caller's failure marker.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Read => "read",
            Self::Write => "write",
            Self::Flush => "flush",
        }
    }
}

/// Fixed one-shot pending flags: one per `(device, operation)` pair.
#[derive(Clone, Copy)]
struct FaultTable {
    pending: [[bool; BlockFault::KINDS]; MAX_BLOCK_DEVICES],
}

impl FaultTable {
    const EMPTY: Self = Self {
        pending: [[false; BlockFault::KINDS]; MAX_BLOCK_DEVICES],
    };

    const fn is_pending(&self, device: usize, fault: BlockFault) -> bool {
        self.pending[device][fault.slot()]
    }

    const fn set(&mut self, device: usize, fault: BlockFault) {
        self.pending[device][fault.slot()] = true;
    }

    /// Consume the flag; `true` means the operation must fail this one time.
    const fn take(&mut self, device: usize, fault: BlockFault) -> bool {
        let armed = self.is_pending(device, fault);
        self.pending[device][fault.slot()] = false;
        armed
    }

    const fn clear(&mut self, device: usize) {
        self.pending[device] = [false; BlockFault::KINDS];
    }

    /// Lowest pending fault of `device`, for diagnostics and assertions.
    const fn first(&self, device: usize) -> Option<BlockFault> {
        let mut kind = 0;
        while kind < BlockFault::KINDS {
            if self.pending[device][kind] {
                return Some(match kind {
                    0 => BlockFault::Read,
                    1 => BlockFault::Write,
                    _ => BlockFault::Flush,
                });
            }
            kind += 1;
        }
        None
    }
}

/// Armed one-shot faults, indexed by device.
static mut FAULTS: FaultTable = FaultTable::EMPTY;

/// Validate a caller-supplied device index against the fixed slot count and the
/// number of devices [`init`] actually brought up.
const fn fault_device(device_count: usize, device_index: u8) -> Result<usize, &'static str> {
    let index = device_index as usize;
    if index >= MAX_BLOCK_DEVICES || index >= device_count {
        return Err("fault injection: block device index out of range");
    }
    Ok(index)
}

/// Arm the next `fault` operation of `device_index` to fail once.
///
/// Only a device that [`init`] brought up can be armed, so a self test cannot
/// silently arm a slot that does not exist. Arming the same operation twice
/// without consuming it is rejected instead of overwriting, so a leaked armed
/// flag shows up in the caller's own check rather than distorting a later test.
pub fn inject_next_fault(device_index: u8, fault: BlockFault) -> Result<(), &'static str> {
    let index = fault_device(DEVICE_COUNT.load(Ordering::SeqCst), device_index)?;
    let _guard = IrqGuard::new();
    // SAFETY: the guard keeps every other context out and only this module's
    // fault helpers touch the table; it is a plain fixed array.
    let faults = unsafe { &mut *core::ptr::addr_of_mut!(FAULTS) };
    if faults.is_pending(index, fault) {
        return Err("fault injection: that fault is already pending");
    }
    faults.set(index, fault);
    Ok(())
}

/// Drop every armed fault of `device_index` (armed but never consumed).
///
/// A consumed fault clears itself; this is for the abort path of a self test so
/// no armed flag can leak into the next stage.
pub fn clear_injected_fault(device_index: u8) -> Result<(), &'static str> {
    let index = fault_device(DEVICE_COUNT.load(Ordering::SeqCst), device_index)?;
    let _guard = IrqGuard::new();
    // SAFETY: as in `inject_next_fault`.
    let faults = unsafe { &mut *core::ptr::addr_of_mut!(FAULTS) };
    faults.clear(index);
    Ok(())
}

/// The lowest fault still armed for `device_index`, if any.
pub fn pending_fault(device_index: u8) -> Option<BlockFault> {
    let index = fault_device(DEVICE_COUNT.load(Ordering::SeqCst), device_index).ok()?;
    let _guard = IrqGuard::new();
    // SAFETY: shared access under the guard, same table as the writers above.
    let faults = unsafe { &*core::ptr::addr_of!(FAULTS) };
    faults.first(index)
}

/// Consume one injection (if armed) for `device_index`/`fault`.
///
/// Called by [`VirtioBlk`]'s `block::BlockDevice` methods **before** the device
/// is looked up, so an injected failure never builds a descriptor, never
/// notifies the device and never changes `inflight` or the DMA region.
pub(crate) fn take_fault(device_index: usize, fault: BlockFault) -> bool {
    if device_index >= MAX_BLOCK_DEVICES {
        return false;
    }
    let _guard = IrqGuard::new();
    // SAFETY: as in `inject_next_fault`; the index was range-checked above.
    let faults = unsafe { &mut *core::ptr::addr_of_mut!(FAULTS) };
    faults.take(device_index, fault)
}

/// Source of physical DMA frames used by the reservation code.
///
/// Abstracting the allocator keeps the reservation state machine host-testable:
/// the target uses [`PmmFrames`], the host tests use an in-memory mock.
pub(crate) trait FrameSource {
    fn alloc_frame(&mut self) -> Option<u64>;
    fn dealloc_frame(&mut self, phys: u64);
}

/// [`FrameSource`] backed by the real physical frame allocator.
struct PmmFrames;

impl FrameSource for PmmFrames {
    fn alloc_frame(&mut self) -> Option<u64> {
        pmm::alloc_frame().ok()
    }

    fn dealloc_frame(&mut self, phys: u64) {
        let _ = pmm::dealloc_frame(phys);
    }
}

/// Allocate `count` frames forming one physically contiguous, page-aligned run.
///
/// Legacy virtio needs the whole queue in one contiguous, page-aligned physical
/// range (the queue PFN register can only express pages), but the frame
/// allocator hands out single frames. Its free list is LIFO and was filled in
/// ascending order, so consecutive allocations normally come back **descending**;
/// the run is therefore accepted in either order and returned as its lowest
/// address. When the frames are not contiguous, the partial run is released and
/// the allocation retried a bounded number of times.
pub(crate) fn alloc_contiguous_frames<F: FrameSource>(source: &mut F, count: usize) -> Option<u64> {
    const MAX_ATTEMPTS: u32 = 64;
    if count == 0 || count > MAX_CONTIG_FRAMES {
        return None;
    }
    for _ in 0..MAX_ATTEMPTS {
        let mut frames = [0u64; MAX_CONTIG_FRAMES];
        let mut allocated = 0usize;
        let mut exhausted = false;
        for slot in 0..count {
            match source.alloc_frame() {
                Some(phys) => {
                    frames[slot] = phys;
                    allocated += 1;
                }
                None => {
                    exhausted = true;
                    break;
                }
            }
        }
        if !exhausted {
            let mut low = frames[0];
            let mut high = frames[0];
            for frame in frames.iter().take(allocated) {
                low = low.min(*frame);
                high = high.max(*frame);
            }
            // `count` distinct, page-aligned frames span exactly `count - 1`
            // pages iff they are adjacent; the low end is the queue base.
            if high - low == (count as u64 - 1) * pmm::FRAME_SIZE {
                return Some(low);
            }
        }
        for frame in frames.iter().take(allocated) {
            source.dealloc_frame(*frame);
        }
        if exhausted {
            return None;
        }
    }
    None
}

/// Allocate a contiguous DMA run from the physical frame allocator.
pub(crate) fn allocate_contiguous_frames(count: usize) -> Option<u64> {
    let mut source = PmmFrames;
    alloc_contiguous_frames(&mut source, count)
}

/// Release a contiguous run of DMA frames obtained from
/// [`allocate_contiguous_frames`].
pub(crate) fn release_contiguous_frames(first: u64, count: usize) {
    for i in 0..count {
        let _ = pmm::dealloc_frame(first + i as u64 * pmm::FRAME_SIZE);
    }
}

// --- Early DMA reservation -------------------------------------------------

/// One device's DMA region: the two-frame virtqueue plus its bounce frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct DmaRegion {
    /// Lowest frame of the two-frame, contiguous virtqueue run.
    pub(crate) queue_phys: u64,
    /// Frame used as the 4 KiB bounce buffer.
    pub(crate) bounce_phys: u64,
}

/// Lifecycle of one device's DMA reservation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ReservationState {
    /// No frames are held for this device.
    Empty,
    /// Frames are held for the device; it has not been probed yet.
    Reserved,
    /// The probe path took the frames; the normal ownership rules free them.
    Claimed,
}

const QUEUE_RESERVE_ERRORS: [&str; MAX_BLOCK_DEVICES] = [
    "io: cannot reserve DMA for block device 0: no contiguous virtqueue frames",
    "io: cannot reserve DMA for block device 1: no contiguous virtqueue frames",
];
const BOUNCE_RESERVE_ERRORS: [&str; MAX_BLOCK_DEVICES] = [
    "io: cannot reserve DMA for block device 0: no bounce frame",
    "io: cannot reserve DMA for block device 1: no bounce frame",
];

#[derive(Debug, Clone, Copy)]
struct ReservationSlot {
    state: ReservationState,
    region: DmaRegion,
}

const EMPTY_RESERVATION: ReservationSlot = ReservationSlot {
    state: ReservationState::Empty,
    region: DmaRegion {
        queue_phys: 0,
        bounce_phys: 0,
    },
};

/// Fixed-size table of early DMA reservations, one slot per block device.
///
/// The table is small on purpose (two slots, no allocation): it exists before
/// the kernel heap and lives for the rest of the boot.
pub(crate) struct ReservationTable {
    slots: [ReservationSlot; MAX_BLOCK_DEVICES],
}

impl ReservationTable {
    pub(crate) const fn new() -> Self {
        Self {
            slots: [EMPTY_RESERVATION; MAX_BLOCK_DEVICES],
        }
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn state(&self, instance: usize) -> ReservationState {
        self.slots
            .get(instance)
            .map_or(ReservationState::Empty, |slot| slot.state)
    }

    /// Reserve every slot that holds no frames yet, through `source`.
    ///
    /// Idempotent: a slot that is already [`ReservationState::Reserved`] or
    /// [`ReservationState::Claimed`] is left untouched, so repeating the call
    /// never consumes additional frames. A failure rolls back everything *this
    /// call* allocated and leaves the table as it was.
    pub(crate) fn reserve_all<F: FrameSource>(
        &mut self,
        source: &mut F,
    ) -> Result<(), &'static str> {
        let mut allocated: [bool; MAX_BLOCK_DEVICES] = [false; MAX_BLOCK_DEVICES];
        for instance in 0..MAX_BLOCK_DEVICES {
            if self.slots[instance].state != ReservationState::Empty {
                continue;
            }
            let Some(queue_phys) = alloc_contiguous_frames(source, QUEUE_FRAMES) else {
                self.rollback(source, &allocated);
                return Err(QUEUE_RESERVE_ERRORS[instance]);
            };
            let Some(bounce_phys) = source.alloc_frame() else {
                for i in 0..QUEUE_FRAMES {
                    source.dealloc_frame(queue_phys + i as u64 * pmm::FRAME_SIZE);
                }
                self.rollback(source, &allocated);
                return Err(BOUNCE_RESERVE_ERRORS[instance]);
            };
            self.slots[instance] = ReservationSlot {
                state: ReservationState::Reserved,
                region: DmaRegion {
                    queue_phys,
                    bounce_phys,
                },
            };
            allocated[instance] = true;
        }
        Ok(())
    }

    /// Release the slots reserved by the current `reserve_all` call.
    fn rollback<F: FrameSource>(&mut self, source: &mut F, allocated: &[bool; MAX_BLOCK_DEVICES]) {
        for instance in 0..MAX_BLOCK_DEVICES {
            if !allocated[instance] {
                continue;
            }
            let region = self.slots[instance].region;
            for i in 0..QUEUE_FRAMES {
                source.dealloc_frame(region.queue_phys + i as u64 * pmm::FRAME_SIZE);
            }
            source.dealloc_frame(region.bounce_phys);
            self.slots[instance] = EMPTY_RESERVATION;
        }
    }

    /// Take the frames reserved for `instance`, marking the slot claimed.
    ///
    /// Returns `None` when nothing is reserved, which lets the probe path fall
    /// back to a late allocation.
    pub(crate) fn claim(&mut self, instance: usize) -> Option<DmaRegion> {
        let slot = self.slots.get_mut(instance)?;
        if slot.state != ReservationState::Reserved {
            return None;
        }
        slot.state = ReservationState::Claimed;
        Some(slot.region)
    }

    /// Forget a claimed slot after the error path returned its frames.
    pub(crate) fn abandon(&mut self, instance: usize) {
        if let Some(slot) = self.slots.get_mut(instance) {
            if slot.state == ReservationState::Claimed {
                *slot = EMPTY_RESERVATION;
            }
        }
    }

    /// Release every slot that was never claimed, returning the frames to `source`.
    ///
    /// Called once the set of devices is known, so a machine with a single disk
    /// does not keep the second disk's frames reserved forever. Returns the
    /// number of frames released.
    pub(crate) fn release_unconsumed<F: FrameSource>(&mut self, source: &mut F) -> usize {
        let mut freed = 0usize;
        for instance in 0..MAX_BLOCK_DEVICES {
            if self.slots[instance].state != ReservationState::Reserved {
                continue;
            }
            let region = self.slots[instance].region;
            for i in 0..QUEUE_FRAMES {
                source.dealloc_frame(region.queue_phys + i as u64 * pmm::FRAME_SIZE);
            }
            source.dealloc_frame(region.bounce_phys);
            self.slots[instance] = EMPTY_RESERVATION;
            freed += dma_frames_per_device();
        }
        freed
    }
}

/// Global reservation table; accessed only with interrupts disabled.
static mut RESERVATIONS: ReservationTable = ReservationTable::new();

/// Reserve the DMA region of every block device, before the kernel heap exists.
///
/// Must be called on the boot path after `mm::pmm::init` and before
/// `mm::heap::init`: at that point the frame allocator's free list is still
/// ordered, so the two-frame virtqueue run is contiguous. Probing later consumes
/// the reservation ([`take_reservation`]); whatever is left over is released by
/// [`release_unconsumed_reservations`].
///
/// The byte cost is fixed: [`MAX_BLOCK_DEVICES`] × [`dma_frames_per_device`] =
/// 6 frames (24 KiB). No device register is touched and no direct-map access is
/// performed, so this is safe before the VM takeover.
///
/// Errors are printable strings naming the device and the missing piece.
pub fn reserve_dma() -> Result<(), &'static str> {
    let _guard = IrqGuard::new();
    // SAFETY: single CPU with interrupts disabled; `reserve_dma` runs once on the
    // boot path and `take_reservation`/`abandon_reservation` run under the same
    // guard, so the table has one logical owner at a time.
    let table = unsafe { &mut *core::ptr::addr_of_mut!(RESERVATIONS) };
    let mut source = PmmFrames;
    table.reserve_all(&mut source)
}

/// Take the reserved DMA region of `instance`, if any.
pub(crate) fn take_reservation(instance: usize) -> Option<DmaRegion> {
    let _guard = IrqGuard::new();
    // SAFETY: see `reserve_dma`; the guard serialises access to the table.
    let table = unsafe { &mut *core::ptr::addr_of_mut!(RESERVATIONS) };
    table.claim(instance)
}

/// Forget a claimed reservation after its frames were returned to the allocator.
pub(crate) fn abandon_reservation(instance: usize) {
    let _guard = IrqGuard::new();
    // SAFETY: see `reserve_dma`; the guard serialises access to the table.
    let table = unsafe { &mut *core::ptr::addr_of_mut!(RESERVATIONS) };
    table.abandon(instance);
}

/// Return every still-reserved DMA frame to the allocator; returns frames freed.
pub(crate) fn release_unconsumed_reservations() -> usize {
    let _guard = IrqGuard::new();
    // SAFETY: see `reserve_dma`; the guard serialises access to the table.
    let table = unsafe { &mut *core::ptr::addr_of_mut!(RESERVATIONS) };
    let mut source = PmmFrames;
    table.release_unconsumed(&mut source)
}

/// Zero a DMA range through the direct map (the device sees the same bytes).
///
/// # Safety
///
/// `phys` must be the base of `frames` frames owned by the driver and the
/// direct map must be active; the range must not be concurrently used.
pub(crate) unsafe fn zero_frames(phys: u64, frames: usize) {
    let bytes = frames * pmm::FRAME_SIZE as usize;
    // SAFETY: caller guarantees ownership of the physical range; the direct map
    // is an identity-preserving kernel alias built before M5b runs.
    unsafe {
        core::ptr::write_bytes(vm::phys_to_virt(phys) as *mut u8, 0, bytes);
    }
}

/// DMA budget of one device, for diagnostics and documentation.
pub const fn dma_frames_per_device() -> usize {
    QUEUE_FRAMES + BOUNCE_FRAMES
}

// --- Early DMA reservation for virtio-net ---------------------------------

/// One net device's DMA region: two virtqueue runs, the RX buffer run and the
/// TX bounce frame.
///
/// All four runs are physically contiguous; the queues must be, the RX buffers
/// are one 16 KiB run so the device sees an even descriptor layout, and the
/// bounce frame is single.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct NetDmaRegion {
    /// Lowest frame of the three-frame RX virtqueue run.
    pub(crate) rx_queue_phys: u64,
    /// Lowest frame of the three-frame TX virtqueue run.
    pub(crate) tx_queue_phys: u64,
    /// Lowest frame of the four-frame RX buffer run.
    pub(crate) rx_buffers_phys: u64,
    /// The single TX bounce frame.
    pub(crate) tx_bounce_phys: u64,
}

/// Lifecycle of the net device's DMA reservation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum NetReservationState {
    /// No frames are held.
    Empty,
    /// Frames are held; the driver has not probed yet.
    Reserved,
    /// The probe path took the frames; the normal ownership rules free them.
    Claimed,
}

const EMPTY_NET_REGION: NetDmaRegion = NetDmaRegion {
    rx_queue_phys: 0,
    tx_queue_phys: 0,
    rx_buffers_phys: 0,
    tx_bounce_phys: 0,
};

#[derive(Debug, Clone, Copy)]
struct NetReservationSlot {
    state: NetReservationState,
    region: NetDmaRegion,
}

const EMPTY_NET_SLOT: NetReservationSlot = NetReservationSlot {
    state: NetReservationState::Empty,
    region: EMPTY_NET_REGION,
};

/// Fixed one-slot reservation table for the single M7c network device.
///
/// The boot path reserves the frames before the heap exists, exactly like the
/// block path, but in its own table: `root` calls [`reserve_net_dma`] next to
/// [`reserve_dma`] and releases the leftovers with
/// [`release_unconsumed_net_reservation`] once it knows whether a NIC exists.
pub(crate) struct NetReservationTable {
    slot: NetReservationSlot,
}

impl NetReservationTable {
    pub(crate) const fn new() -> Self {
        Self {
            slot: EMPTY_NET_SLOT,
        }
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn state(&self) -> NetReservationState {
        self.slot.state
    }

    /// Reserve all four runs through `source`.
    ///
    /// Idempotent: a table that already holds frames is left alone. A failure
    /// rolls back everything this call allocated, so the table and the frame
    /// source end up exactly as they were.
    pub(crate) fn reserve<F: FrameSource>(&mut self, source: &mut F) -> Result<(), &'static str> {
        if self.slot.state != NetReservationState::Empty {
            return Ok(());
        }
        let Some(rx_queue_phys) = alloc_contiguous_frames(source, NET_QUEUE_FRAMES) else {
            return Err("io: cannot reserve net DMA: no contiguous RX virtqueue frames");
        };
        let Some(tx_queue_phys) = alloc_contiguous_frames(source, NET_QUEUE_FRAMES) else {
            release_run(source, rx_queue_phys, NET_QUEUE_FRAMES);
            return Err("io: cannot reserve net DMA: no contiguous TX virtqueue frames");
        };
        let Some(rx_buffers_phys) = alloc_contiguous_frames(source, NET_RX_BUFFER_FRAMES) else {
            release_run(source, rx_queue_phys, NET_QUEUE_FRAMES);
            release_run(source, tx_queue_phys, NET_QUEUE_FRAMES);
            return Err("io: cannot reserve net DMA: no contiguous RX buffer frames");
        };
        let Some(tx_bounce_phys) = source.alloc_frame() else {
            release_run(source, rx_queue_phys, NET_QUEUE_FRAMES);
            release_run(source, tx_queue_phys, NET_QUEUE_FRAMES);
            release_run(source, rx_buffers_phys, NET_RX_BUFFER_FRAMES);
            return Err("io: cannot reserve net DMA: no TX bounce frame");
        };
        self.slot = NetReservationSlot {
            state: NetReservationState::Reserved,
            region: NetDmaRegion {
                rx_queue_phys,
                tx_queue_phys,
                rx_buffers_phys,
                tx_bounce_phys,
            },
        };
        Ok(())
    }

    /// Take the reserved frames, marking the slot claimed.
    pub(crate) fn claim(&mut self) -> Option<NetDmaRegion> {
        if self.slot.state != NetReservationState::Reserved {
            return None;
        }
        self.slot.state = NetReservationState::Claimed;
        Some(self.slot.region)
    }

    /// Forget a claimed slot after its frames were returned to the allocator.
    pub(crate) fn abandon(&mut self) {
        if self.slot.state == NetReservationState::Claimed {
            self.slot = EMPTY_NET_SLOT;
        }
    }

    /// Release a still-reserved region back to `source`; returns frames freed.
    pub(crate) fn release_unconsumed<F: FrameSource>(&mut self, source: &mut F) -> usize {
        if self.slot.state != NetReservationState::Reserved {
            return 0;
        }
        let region = self.slot.region;
        release_run(source, region.rx_queue_phys, NET_QUEUE_FRAMES);
        release_run(source, region.tx_queue_phys, NET_QUEUE_FRAMES);
        release_run(source, region.rx_buffers_phys, NET_RX_BUFFER_FRAMES);
        source.dealloc_frame(region.tx_bounce_phys);
        self.slot = EMPTY_NET_SLOT;
        dma_frames_per_net_device()
    }
}

/// Release `count` contiguous frames of `source` starting at `first`.
fn release_run<F: FrameSource>(source: &mut F, first: u64, count: usize) {
    for i in 0..count {
        source.dealloc_frame(first + i as u64 * pmm::FRAME_SIZE);
    }
}

/// Global net reservation table; accessed only with interrupts disabled.
static mut NET_RESERVATION: NetReservationTable = NetReservationTable::new();

/// Reserve the fixed DMA budget of the virtio-net device, before the heap exists.
///
/// Must run on the boot path after `mm::pmm::init` and before `mm::heap::init`,
/// for the same reason as [`reserve_dma`]: the frame allocator's free list is
/// still ordered, so the multi-frame runs come back contiguous. No device
/// register is touched and no direct-map access happens, so this is also safe
/// before the VM takeover. The byte cost is [`dma_frames_per_net_device`] = 11
/// frames (44 KiB).
pub fn reserve_net_dma() -> Result<(), &'static str> {
    let _guard = IrqGuard::new();
    // SAFETY: single CPU with interrupts disabled; `reserve_net_dma` runs once on
    // the boot path and the claim/abandon helpers below use the same guard, so
    // the table has one logical owner at a time.
    let table = unsafe { &mut *core::ptr::addr_of_mut!(NET_RESERVATION) };
    let mut source = PmmFrames;
    table.reserve(&mut source)
}

/// Take the reserved net DMA region, if any.
pub(crate) fn take_net_reservation() -> Option<NetDmaRegion> {
    let _guard = IrqGuard::new();
    // SAFETY: see `reserve_net_dma`; the guard serialises table access.
    let table = unsafe { &mut *core::ptr::addr_of_mut!(NET_RESERVATION) };
    table.claim()
}

/// Forget a claimed net reservation after its frames were returned.
pub(crate) fn abandon_net_reservation() {
    let _guard = IrqGuard::new();
    // SAFETY: see `reserve_net_dma`; the guard serialises table access.
    let table = unsafe { &mut *core::ptr::addr_of_mut!(NET_RESERVATION) };
    table.abandon();
}

/// Return the still-reserved net DMA frames to the allocator; returns the
/// number of frames freed (0 or [`dma_frames_per_net_device`]).
pub fn release_unconsumed_net_reservation() -> usize {
    let _guard = IrqGuard::new();
    // SAFETY: see `reserve_net_dma`; the guard serialises table access.
    let table = unsafe { &mut *core::ptr::addr_of_mut!(NET_RESERVATION) };
    let mut source = PmmFrames;
    table.release_unconsumed(&mut source)
}

/// DMA budget of the net device, for diagnostics and documentation.
pub const fn dma_frames_per_net_device() -> usize {
    NET_QUEUE_FRAMES * 2 + NET_RX_BUFFER_FRAMES + NET_TX_BOUNCE_FRAMES
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dma_budget_is_three_frames_per_device() {
        assert_eq!(dma_frames_per_device(), 3);
        assert_eq!(QUEUE_FRAMES, 2, "the legacy virtqueue needs two frames");
        assert_eq!(BOUNCE_FRAMES, 1);
        assert_eq!(MAX_BLOCK_DEVICES * dma_frames_per_device(), 6);
    }

    #[test]
    fn handles_are_rejected_before_init() {
        // `block_device_count` is read-only state; a fresh test build must not
        // pretend a device exists before `init` succeeded.
        assert_eq!(
            virtio_block(0).err(),
            Some("virtio-blk: block device index out of range")
        );
        assert_eq!(
            virtio_block(MAX_BLOCK_DEVICES).err(),
            Some("virtio-blk: block device index out of range")
        );
    }

    /// In-memory [`FrameSource`]: pops from the end (like a LIFO free list),
    /// pushes releases back on top and counts them.
    struct MockFrames {
        stack: [u64; 16],
        len: usize,
        released_count: usize,
    }

    impl MockFrames {
        fn new(frames: &[u64]) -> Self {
            let mut stack = [0u64; 16];
            stack[..frames.len()].copy_from_slice(frames);
            Self {
                stack,
                len: frames.len(),
                released_count: 0,
            }
        }

        fn remaining(&self) -> usize {
            self.len
        }
    }

    impl FrameSource for MockFrames {
        fn alloc_frame(&mut self) -> Option<u64> {
            if self.len == 0 {
                return None;
            }
            self.len -= 1;
            Some(self.stack[self.len])
        }

        fn dealloc_frame(&mut self, phys: u64) {
            assert!(self.len < self.stack.len(), "mock free list overflow");
            self.stack[self.len] = phys;
            self.len += 1;
            self.released_count += 1;
        }
    }

    #[test]
    fn contiguous_runs_are_accepted_in_either_allocation_order() {
        // The free list is LIFO: the last element is allocated first.
        let mut ascending = MockFrames::new(&[0x3000, 0x2000, 0x1000]);
        assert_eq!(alloc_contiguous_frames(&mut ascending, 2), Some(0x1000));
        assert_eq!(ascending.remaining(), 1);

        // The M2-M4 free list was filled ascending, so consecutive allocations
        // usually descend; the run must still be accepted and normalised.
        let mut descending = MockFrames::new(&[0x1000, 0x2000, 0x3000]);
        assert_eq!(alloc_contiguous_frames(&mut descending, 2), Some(0x2000));
        assert_eq!(descending.remaining(), 1);
    }

    #[test]
    fn non_contiguous_frames_are_released_and_retried() {
        // Two frames are available but never adjacent; every attempt must give
        // its frames back and the call must terminate with `None`.
        let mut source = MockFrames::new(&[0x1000, 0x5000, 0x2000]);
        assert_eq!(alloc_contiguous_frames(&mut source, 2), None);
        assert_eq!(source.remaining(), 3, "all frames must be returned");
        assert_eq!(source.released_count, 2 * 64, "two frames per attempt");
    }

    #[test]
    fn reservation_allocates_three_frames_per_device() {
        // Allocation order: queue0 low frame, queue0 high frame, bounce0,
        // queue1 low, queue1 high, bounce1.
        let mut source = MockFrames::new(&[0x6000, 0x5000, 0x4000, 0x3000, 0x2000, 0x1000]);
        let mut table = ReservationTable::new();
        assert_eq!(table.reserve_all(&mut source), Ok(()));
        assert_eq!(source.remaining(), 0);
        assert_eq!(source.released_count, 0);
        assert_eq!(table.state(0), ReservationState::Reserved);
        assert_eq!(table.state(1), ReservationState::Reserved);
        assert_eq!(
            table.claim(0),
            Some(DmaRegion {
                queue_phys: 0x1000,
                bounce_phys: 0x3000,
            })
        );
        assert_eq!(
            table.claim(1),
            Some(DmaRegion {
                queue_phys: 0x4000,
                bounce_phys: 0x6000,
            })
        );
        assert_eq!(table.state(0), ReservationState::Claimed);
    }

    #[test]
    fn repeated_reservation_does_not_consume_more_frames() {
        let mut source = MockFrames::new(&[0x6000, 0x5000, 0x4000, 0x3000, 0x2000, 0x1000]);
        let mut table = ReservationTable::new();
        assert_eq!(table.reserve_all(&mut source), Ok(()));
        assert_eq!(table.reserve_all(&mut source), Ok(()));
        assert_eq!(source.remaining(), 0, "the second call must alloc nothing");
        assert_eq!(source.released_count, 0);
        assert_eq!(
            table.claim(0),
            Some(DmaRegion {
                queue_phys: 0x1000,
                bounce_phys: 0x3000,
            })
        );
    }

    #[test]
    fn failed_reservation_rolls_back_the_first_device() {
        // Four frames: device 0 can be fully reserved, device 1 has only one
        // frame left, so its two-frame queue run cannot be formed.
        let mut source = MockFrames::new(&[0x4000, 0x3000, 0x2000, 0x1000]);
        let mut table = ReservationTable::new();
        assert_eq!(
            table.reserve_all(&mut source),
            Err("io: cannot reserve DMA for block device 1: no contiguous virtqueue frames")
        );
        assert_eq!(table.state(0), ReservationState::Empty);
        assert_eq!(table.state(1), ReservationState::Empty);
        assert_eq!(source.remaining(), 4, "device 0 frames must come back");
        assert_eq!(
            source.released_count, 4,
            "one partial run plus three frames"
        );
        assert_eq!(table.claim(0), None, "a rolled-back slot is not claimable");
    }

    #[test]
    fn missing_bounce_frame_reports_the_device_and_rolls_back() {
        let mut source = MockFrames::new(&[0x2000, 0x1000]);
        let mut table = ReservationTable::new();
        assert_eq!(
            table.reserve_all(&mut source),
            Err("io: cannot reserve DMA for block device 0: no bounce frame")
        );
        assert_eq!(source.remaining(), 2);
        assert_eq!(source.released_count, 2);
        assert_eq!(table.state(0), ReservationState::Empty);
    }

    #[test]
    fn claim_abandon_and_unconsumed_release() {
        let mut source = MockFrames::new(&[0x6000, 0x5000, 0x4000, 0x3000, 0x2000, 0x1000]);
        let mut table = ReservationTable::new();
        table.reserve_all(&mut source).unwrap();
        assert!(table.claim(0).is_some());
        assert_eq!(table.state(0), ReservationState::Claimed);
        assert_eq!(table.claim(0), None, "a claimed slot is not reusable");
        table.abandon(0);
        assert_eq!(table.state(0), ReservationState::Empty);
        // Device 1 was never probed: its three frames must go back.
        assert_eq!(table.release_unconsumed(&mut source), 3);
        assert_eq!(table.state(1), ReservationState::Empty);
        assert_eq!(source.released_count, 3);
        assert_eq!(source.remaining(), 3);
        assert_eq!(table.release_unconsumed(&mut source), 0);
    }

    #[test]
    fn reserve_all_skips_claimed_slots() {
        let mut source = MockFrames::new(&[0x6000, 0x5000, 0x4000, 0x3000, 0x2000, 0x1000]);
        let mut table = ReservationTable::new();
        table.reserve_all(&mut source).unwrap();
        assert_eq!(
            table.claim(0),
            Some(DmaRegion {
                queue_phys: 0x1000,
                bounce_phys: 0x3000,
            })
        );
        assert_eq!(table.reserve_all(&mut source), Ok(()));
        assert_eq!(
            source.remaining(),
            0,
            "claiming all frames must not allocate"
        );
        assert_eq!(table.state(0), ReservationState::Claimed);
    }

    #[test]
    fn reservation_table_has_a_fixed_small_footprint() {
        // Two slots of (state + queue frame + bounce frame); documented in the
        // module comment so the boot-path byte cost stays reviewable.
        assert_eq!(core::mem::size_of::<DmaRegion>(), 16);
        assert_eq!(core::mem::size_of::<ReservationTable>(), 48);
    }

    // --- Self-test fault injection ---------------------------------------

    #[test]
    fn fault_table_filters_by_device_and_operation() {
        let mut table = FaultTable::EMPTY;
        table.set(0, BlockFault::Write);
        // Another device and the other operations are unaffected.
        assert!(!table.take(1, BlockFault::Write));
        assert!(!table.take(0, BlockFault::Read));
        assert!(!table.take(0, BlockFault::Flush));
        assert!(table.is_pending(0, BlockFault::Write));
        assert_eq!(table.first(0), Some(BlockFault::Write));
        assert_eq!(table.first(1), None);
    }

    #[test]
    fn injected_fault_fires_exactly_once() {
        let mut table = FaultTable::EMPTY;
        table.set(0, BlockFault::Read);
        assert!(
            table.take(0, BlockFault::Read),
            "the armed fault must fire once"
        );
        assert!(
            !table.take(0, BlockFault::Read),
            "a consumed fault must not fire again"
        );
        assert_eq!(table.first(0), None);
        // Re-arming after consumption works, so successive stages can each
        // inject one failure without leaking state.
        table.set(0, BlockFault::Read);
        assert_eq!(table.first(0), Some(BlockFault::Read));
    }

    #[test]
    fn clearing_a_device_drops_every_armed_fault() {
        let mut table = FaultTable::EMPTY;
        table.set(0, BlockFault::Read);
        table.set(0, BlockFault::Flush);
        table.set(1, BlockFault::Write);
        table.clear(0);
        assert_eq!(table.first(0), None);
        assert_eq!(table.first(1), Some(BlockFault::Write));
    }

    #[test]
    fn injected_faults_report_io_errors() {
        // Write/flush injection is what M5c3 uses to prove error propagation
        // through the real VFS → virtio-blk → BlockDevice path; read is provided
        // for symmetry. All three must look like a transport error.
        for fault in [BlockFault::Read, BlockFault::Write, BlockFault::Flush] {
            assert_eq!(fault.error(), BlockError::Io);
        }
        assert_eq!(BlockFault::Read.as_str(), "read");
        assert_eq!(BlockFault::Write.as_str(), "write");
        assert_eq!(BlockFault::Flush.as_str(), "flush");
        // The three kinds must map to distinct rows, otherwise injecting one
        // operation would arm another.
        assert_ne!(BlockFault::Read.slot(), BlockFault::Write.slot());
        assert_ne!(BlockFault::Write.slot(), BlockFault::Flush.slot());
        assert_ne!(BlockFault::Read.slot(), BlockFault::Flush.slot());
    }

    #[test]
    fn fault_device_index_requires_an_initialised_device() {
        // A host test never initialises a device, so arming must be loud
        // instead of quietly succeeding on a slot that does not exist.
        assert_eq!(
            fault_device(0, 0),
            Err("fault injection: block device index out of range")
        );
        assert_eq!(fault_device(2, 0), Ok(0));
        assert_eq!(fault_device(2, 1), Ok(1));
        assert_eq!(
            fault_device(2, 2),
            Err("fault injection: block device index out of range")
        );
        assert_eq!(
            fault_device(1, 1),
            Err("fault injection: block device index out of range")
        );
    }

    /// Ascending frame list; the mock pops from the end, so the runs come back
    /// contiguous exactly like the real LIFO free list on the early boot path.
    const NET_TEST_FRAMES: [u64; 11] = [
        0x10_0000, 0x10_1000, 0x10_2000, 0x10_3000, 0x10_4000, 0x10_5000, 0x10_6000, 0x10_7000,
        0x10_8000, 0x10_9000, 0x10_A000,
    ];

    #[test]
    fn net_dma_budget_is_eleven_frames() {
        assert_eq!(dma_frames_per_net_device(), 11);
        assert_eq!(
            NET_QUEUE_FRAMES, 3,
            "a 256-descriptor net queue occupies three frames"
        );
        assert_eq!(
            NET_RX_BUFFER_FRAMES, 4,
            "8 × 2048 B RX buffers are 4 frames"
        );
        assert_eq!(NET_TX_BOUNCE_FRAMES, 1);
        // The queues and the RX buffer run are contiguous allocations, so all of
        // them must fit the contiguous-run limit the reservation code supports.
        assert!(NET_QUEUE_FRAMES <= MAX_CONTIG_FRAMES);
        assert!(NET_RX_BUFFER_FRAMES <= MAX_CONTIG_FRAMES);
    }

    #[test]
    fn net_reservation_holds_eleven_frames_and_is_idempotent() {
        let mut source = MockFrames::new(&NET_TEST_FRAMES);
        let mut table = NetReservationTable::new();
        assert_eq!(table.state(), NetReservationState::Empty);
        table.reserve(&mut source).unwrap();
        assert_eq!(table.state(), NetReservationState::Reserved);
        assert_eq!(source.remaining(), 0);
        // A second call must not consume more frames.
        table.reserve(&mut source).unwrap();
        assert_eq!(source.remaining(), 0);
        let region = table.claim().unwrap();
        // LIFO order: RX queue takes the three highest frames, TX queue the next
        // three, the RX buffer run the four below them and the bounce the lowest.
        assert_eq!(region.rx_queue_phys, 0x10_8000);
        assert_eq!(region.tx_queue_phys, 0x10_5000);
        assert_eq!(region.rx_buffers_phys, 0x10_1000);
        assert_eq!(region.tx_bounce_phys, 0x10_0000);
        assert_eq!(table.state(), NetReservationState::Claimed);
        assert_eq!(table.claim(), None);
        table.abandon();
        assert_eq!(table.state(), NetReservationState::Empty);
        // The frames were handed to the driver, so nothing is released here.
        assert_eq!(table.release_unconsumed(&mut source), 0);
    }

    #[test]
    fn net_reservation_releases_unconsumed_frames() {
        let mut source = MockFrames::new(&NET_TEST_FRAMES);
        let mut table = NetReservationTable::new();
        table.reserve(&mut source).unwrap();
        assert_eq!(table.release_unconsumed(&mut source), 11);
        assert_eq!(table.state(), NetReservationState::Empty);
        assert_eq!(source.remaining(), 11);
        assert_eq!(table.release_unconsumed(&mut source), 0);
    }

    #[test]
    fn net_reservation_rolls_back_when_a_frame_is_missing() {
        let mut source = MockFrames::new(&[0x20_0000, 0x20_1000, 0x20_2000]);
        let mut table = NetReservationTable::new();
        assert_eq!(
            table.reserve(&mut source),
            Err("io: cannot reserve net DMA: no contiguous TX virtqueue frames")
        );
        assert_eq!(table.state(), NetReservationState::Empty);
        assert_eq!(source.remaining(), 3, "a failed reservation leaks nothing");
        // The RX run of three frames was formed and then rolled back when the TX
        // run could not be formed, so every allocated frame went back exactly
        // once.
        assert_eq!(source.released_count, 3);
    }
}
