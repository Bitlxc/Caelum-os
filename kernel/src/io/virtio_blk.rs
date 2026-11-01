//! Legacy (virtio 0.9.5 / transitional) PCI `virtio-blk` transport.
//!
//! One [`Device`] per disk: the legacy I/O BAR0 register window, the two-frame
//! virtqueue, the 4 KiB bounce frame and the negotiated feature bits. The
//! public surface is [`VirtioBlk`], a `Copy` handle that implements
//! [`block::BlockDevice`] and looks the device up in [`super::DEVICES`].
//!
//! The driver is synchronous: [`Device::read`], [`Device::write`] and
//! [`Device::flush`] submit one descriptor chain, notify the device and poll the
//! used ring until the device publishes exactly that request or the bounded
//! timeout expires. The wait is bounded by a busy counter that advances on every
//! iteration, so it terminates even with interrupts disabled; when the clock's
//! ticks actually advance, [`REQUEST_TIMEOUT_MILLIS`] is an additional, tighter
//! bound. There is no interrupt handler and no allocation here — the only
//! allocation happens once, in [`probe`].

use block::{BlockDevice, BlockError};
use core::sync::atomic::{Ordering, fence};

use crate::mm::{pmm, vm};
use crate::platform::{self, PciFunction};

use super::virtqueue::{self as vq, QueueLayout};
use super::{
    DmaRegion, IrqGuard, MAX_BLOCK_DEVICES, QUEUE_FRAMES, VIRTIO_BLK_F_FLUSH,
    VIRTIO_BLK_SECTOR_SIZE, VIRTIO_PCI_DEVICE_LEGACY_BLOCK, VIRTIO_PCI_DEVICE_MODERN_BLOCK,
    VIRTIO_PCI_VENDOR_ID, allocate_contiguous_frames, release_contiguous_frames,
};

// --- Legacy virtio PCI register window (BAR0, I/O space) -------------------

/// Device feature bits (read-only).
const REG_DEVICE_FEATURES: u16 = 0x00;
/// Guest feature bits (write-only).
const REG_GUEST_FEATURES: u16 = 0x04;
/// Queue page frame number (write-only).
const REG_QUEUE_PFN: u16 = 0x08;
/// Queue size in descriptors (read-only).
const REG_QUEUE_SIZE: u16 = 0x0C;
/// Queue selector (write-only).
const REG_QUEUE_SELECT: u16 = 0x0E;
/// Queue notification doorbell (write-only).
const REG_QUEUE_NOTIFY: u16 = 0x10;
/// Device status (read/write).
const REG_STATUS: u16 = 0x12;
/// Interrupt status; reading returns pending bits, writing any value clears.
const REG_ISR: u16 = 0x13;
/// Device-specific configuration (capacity at +0, little-endian).
const REG_CONFIG: u16 = 0x14;

/// Status bit: driver has noticed the device.
const STATUS_ACKNOWLEDGE: u8 = 1;
/// Status bit: driver knows how to drive the device.
const STATUS_DRIVER: u8 = 2;
/// Status bit: driver is ready to accept requests.
const STATUS_DRIVER_OK: u8 = 4;
/// Status bit: the device has failed and needs a reset.
const STATUS_FAILED: u8 = 0x80;

/// BAR0 must be an I/O BAR (bit 0 set) whose base is not zero.
const BAR_IO_FLAG: u32 = 0x1;
/// The low two bits of an I/O BAR are reserved.
const BAR_IO_MASK: u32 = !0x3;

/// PCI command register and the bits M5b must set: decode I/O and bus-master DMA.
const PCI_COMMAND: u8 = 0x04;
const PCI_COMMAND_IO: u16 = 0x1;
const PCI_COMMAND_BUS_MASTER: u16 = 0x4;

/// Bounded wait for one request: 1 s of timer ticks when the clock advances.
const REQUEST_TIMEOUT_MILLIS: u64 = 1000;
/// Hard iteration bound for one request; always enforced, so a frozen tick
/// counter (interrupts disabled) cannot turn the wait into an endless spin.
const REQUEST_BUSY_BOUND: u64 = 50_000_000;

/// Outcome of a single completion-poll iteration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PollVerdict {
    /// The device may still complete the request; keep polling.
    Continue,
    /// The wait budget is exhausted; the request must be failed loudly.
    Timeout,
}

/// Decide whether the poll loop may continue after one `Pending` iteration.
///
/// The busy bound is counted unconditionally: the loop must terminate even when
/// the clock is "ready" but its tick counter cannot advance (for example in the
/// post-user-mode `complete_m4` context, where interrupts are disabled and no
/// timer IRQ will ever be delivered again). The elapsed-millis check is only an
/// additional, more precise upper bound for the normal interrupt-enabled case;
/// reaching *either* bound fails the request with [`BlockError::Timeout`].
const fn poll_verdict(spins: u64, elapsed_millis: Option<u64>) -> PollVerdict {
    if spins >= REQUEST_BUSY_BOUND {
        return PollVerdict::Timeout;
    }
    if let Some(elapsed) = elapsed_millis {
        if elapsed >= REQUEST_TIMEOUT_MILLIS {
            return PollVerdict::Timeout;
        }
    }
    PollVerdict::Continue
}

/// How many legacy devices were probed (instance index base).
const _: () = assert!(MAX_BLOCK_DEVICES == 2);

// --- Probe -----------------------------------------------------------------

/// Why a device instance could not be brought up.
pub(crate) enum ProbeError {
    /// No legacy function with this instance index exists.
    NotFound,
    /// Only a modern (`0x1042`) function exists; M5b does not drive those.
    ModernOnly,
    /// The function exists but the legacy handshake failed; string is printable.
    Failed(&'static str),
}

/// Extract the I/O port base from BAR0, rejecting MMIO and unmapped BARs.
pub(crate) fn bar0_io_base(bar0: u32) -> Result<u16, ProbeError> {
    if bar0 & BAR_IO_FLAG == 0 {
        return Err(ProbeError::Failed(
            "virtio-blk: BAR0 is not an I/O BAR (MMIO transport is not supported)",
        ));
    }
    let base = bar0 & BAR_IO_MASK;
    if base == 0 {
        return Err(ProbeError::Failed("virtio-blk: BAR0 is not mapped"));
    }
    Ok(base as u16)
}

/// Find and initialise legacy virtio-blk instance `instance` (0-based).
pub(crate) fn probe(instance: usize) -> Result<Device, ProbeError> {
    let Some(pci) = platform::find_pci(
        VIRTIO_PCI_VENDOR_ID,
        VIRTIO_PCI_DEVICE_LEGACY_BLOCK,
        instance,
    ) else {
        // Distinguish "this machine simply has no such disk" from "this machine
        // only has a modern transport", which must be reported, not faked.
        if instance == 0
            && platform::find_pci(VIRTIO_PCI_VENDOR_ID, VIRTIO_PCI_DEVICE_MODERN_BLOCK, 0).is_some()
        {
            return Err(ProbeError::ModernOnly);
        }
        return Err(ProbeError::NotFound);
    };
    init_device(instance, pci)
}

fn rd8(base: u16, reg: u16) -> u8 {
    platform::io_read8(base.wrapping_add(reg))
}

fn rd16(base: u16, reg: u16) -> u16 {
    platform::io_read16(base.wrapping_add(reg))
}

fn rd32(base: u16, reg: u16) -> u32 {
    platform::io_read32(base.wrapping_add(reg))
}

fn wr8(base: u16, reg: u16, value: u8) {
    platform::io_write8(base.wrapping_add(reg), value);
}

fn wr16(base: u16, reg: u16, value: u16) {
    platform::io_write16(base.wrapping_add(reg), value);
}

fn wr32(base: u16, reg: u16, value: u32) {
    platform::io_write32(base.wrapping_add(reg), value);
}

/// Run the legacy 0.9.5 handshake on one function and take its DMA region.
///
/// `instance` is the 0-based probe index: the DMA frames for it were reserved at
/// boot by [`super::reserve_dma`], before the kernel heap fragmented the frame
/// allocator's free list.
fn init_device(instance: usize, pci: PciFunction) -> Result<Device, ProbeError> {
    let io_base = bar0_io_base(pci.bars[0])?;

    // Decode I/O space and allow bus-master DMA before touching the device.
    let command = platform::read_config16(&pci, PCI_COMMAND).map_err(ProbeError::Failed)?;
    let wanted = command | PCI_COMMAND_IO | PCI_COMMAND_BUS_MASTER;
    if wanted != command {
        platform::write_config16(&pci, PCI_COMMAND, wanted).map_err(ProbeError::Failed)?;
    }

    // 1. Reset the device and wait for it to acknowledge the reset.
    wr8(io_base, REG_STATUS, 0);
    let mut spins = 0u32;
    while rd8(io_base, REG_STATUS) != 0 {
        if spins >= 1000 {
            return Err(ProbeError::Failed("virtio-blk: device did not reset"));
        }
        platform::io_delay();
        spins += 1;
    }

    // 2. ACKNOWLEDGE then DRIVER: we know the device and how to drive it.
    wr8(io_base, REG_STATUS, STATUS_ACKNOWLEDGE);
    wr8(io_base, REG_STATUS, STATUS_ACKNOWLEDGE | STATUS_DRIVER);

    // 3. Negotiate features. Only flush is implemented; the legacy interface has
    // no FEATURES_OK step (that is a virtio 1.0 concept).
    let device_features = rd32(io_base, REG_DEVICE_FEATURES);
    let features = device_features & VIRTIO_BLK_F_FLUSH;
    wr32(io_base, REG_GUEST_FEATURES, features);

    // 4. Select queue 0 and read the (device-fixed) queue size.
    wr16(io_base, REG_QUEUE_SELECT, 0);
    let queue_size = rd16(io_base, REG_QUEUE_SIZE);
    let layout = QueueLayout::new(queue_size)
        .map_err(|_| ProbeError::Failed("virtio-blk: queue size is outside 8..=256"))?;
    if layout.bytes() > QUEUE_FRAMES * pmm::FRAME_SIZE as usize {
        return Err(ProbeError::Failed(
            "virtio-blk: the legacy block queue is 128 descriptors and must fit two DMA frames",
        ));
    }

    // 5. DMA region: two contiguous frames for the queue, one bounce frame.
    // The frames were reserved at boot (before the heap existed); the late
    // allocation is a fallback for a boot path without a reservation.
    let reserved = super::take_reservation(instance);
    let used_reservation = reserved.is_some();
    let DmaRegion {
        queue_phys,
        bounce_phys,
    } = match reserved {
        Some(region) => region,
        None => {
            let queue_phys = allocate_contiguous_frames(QUEUE_FRAMES).ok_or(ProbeError::Failed(
                "virtio-blk: no contiguous DMA frames for the virtqueue",
            ))?;
            let bounce_phys = match pmm::alloc_frame() {
                Ok(phys) => phys,
                Err(_) => {
                    release_contiguous_frames(queue_phys, QUEUE_FRAMES);
                    return Err(ProbeError::Failed(
                        "virtio-blk: no DMA frame for the bounce buffer",
                    ));
                }
            };
            DmaRegion {
                queue_phys,
                bounce_phys,
            }
        }
    };
    // SAFETY: both ranges are owned by this driver — reserved at boot or freshly
    // allocated here — and the direct map covers them; nothing else can reach
    // them before the device is told about the queue.
    unsafe {
        super::zero_frames(queue_phys, QUEUE_FRAMES);
        super::zero_frames(bounce_phys, 1);
    }

    // Every error path below hands the frames back to the allocator. A reserved
    // region also drops its reservation slot so it can never be reused.
    let discard_dma = || {
        release_contiguous_frames(queue_phys, QUEUE_FRAMES);
        let _ = pmm::dealloc_frame(bounce_phys);
        if used_reservation {
            super::abandon_reservation(instance);
        }
    };

    // 6. Hand the queue to the device. The legacy interface expresses the queue
    // address as a page frame number.
    let queue_pfn = (queue_phys >> 12) as u32;
    if u64::from(queue_pfn) << 12 != queue_phys {
        discard_dma();
        return Err(ProbeError::Failed(
            "virtio-blk: virtqueue DMA address is not expressible as a legacy PFN",
        ));
    }
    wr32(io_base, REG_QUEUE_PFN, queue_pfn);

    // 7. Capacity is the first little-endian u64 of the device config, read as
    // two 32-bit port accesses (the legacy window has no 64-bit read).
    let capacity = vq::capacity_from_registers(
        rd32(io_base, REG_CONFIG),
        rd32(io_base, REG_CONFIG.wrapping_add(4)),
    );
    if capacity == 0 {
        discard_dma();
        return Err(ProbeError::Failed(
            "virtio-blk: device reports zero capacity",
        ));
    }

    // 8. DRIVER_OK, then make sure the device did not fall over.
    wr8(
        io_base,
        REG_STATUS,
        STATUS_ACKNOWLEDGE | STATUS_DRIVER | STATUS_DRIVER_OK,
    );
    if rd8(io_base, REG_STATUS) & STATUS_FAILED != 0 {
        discard_dma();
        return Err(ProbeError::Failed(
            "virtio-blk: device reported FAILED during initialisation",
        ));
    }

    Ok(Device {
        io_base,
        queue_phys,
        bounce_phys,
        queue_size,
        capacity,
        features,
        inflight: false,
    })
}

// --- Device ----------------------------------------------------------------

/// Real state of one initialised legacy virtio-blk device.
pub(crate) struct Device {
    /// BAR0 I/O port base.
    io_base: u16,
    /// Physical base of the two-frame virtqueue.
    queue_phys: u64,
    /// Physical base of the one-frame bounce buffer.
    bounce_phys: u64,
    /// Device-reported queue size (validated to 8..=256 and to the two-frame
    /// block DMA budget).
    queue_size: u16,
    /// Device capacity in 512-byte sectors.
    capacity: u64,
    /// Negotiated feature bits (guest features actually written).
    features: u32,
    /// Set while a request is between `avail` publish and used completion.
    inflight: bool,
}

impl Device {
    /// Capacity in 512-byte sectors.
    pub(crate) fn capacity(&self) -> u64 {
        self.capacity
    }

    /// Whether the device offered (and we negotiated) flush support.
    pub(crate) fn flush_supported(&self) -> bool {
        self.features & VIRTIO_BLK_F_FLUSH != 0
    }

    /// Read `buf.len()` bytes starting at sector `first` into `buf`.
    pub(crate) fn read(&mut self, first: u64, buf: &mut [u8]) -> Result<(), BlockError> {
        vq::validate_request(first, buf.len(), self.capacity)?;
        let mut done = 0usize;
        while done < buf.len() {
            let chunk = vq::chunk_len(buf.len() - done);
            let sector = first + (done / VIRTIO_BLK_SECTOR_SIZE as usize) as u64;
            self.submit(vq::REQ_IN, sector, chunk)?;
            // SAFETY: the bounce frame is driver-owned, mapped through the direct
            // map for its whole 4 KiB, and the device has finished with it.
            let data = unsafe {
                core::slice::from_raw_parts(
                    (vm::phys_to_virt(self.bounce_phys) as *const u8).add(vq::DATA_OFFSET),
                    chunk,
                )
            };
            buf[done..done + chunk].copy_from_slice(data);
            done += chunk;
        }
        Ok(())
    }

    /// Write `buf` starting at sector `first`.
    pub(crate) fn write(&mut self, first: u64, buf: &[u8]) -> Result<(), BlockError> {
        vq::validate_request(first, buf.len(), self.capacity)?;
        let mut done = 0usize;
        while done < buf.len() {
            let chunk = vq::chunk_len(buf.len() - done);
            let sector = first + (done / VIRTIO_BLK_SECTOR_SIZE as usize) as u64;
            // SAFETY: same ownership argument as in `read`; `chunk <=
            // MAX_DATA_CHUNK` keeps the copy inside the bounce frame.
            unsafe {
                core::ptr::copy_nonoverlapping(
                    buf[done..].as_ptr(),
                    (vm::phys_to_virt(self.bounce_phys) as *mut u8).add(vq::DATA_OFFSET),
                    chunk,
                );
            }
            self.submit(vq::REQ_OUT, sector, chunk)?;
            done += chunk;
        }
        Ok(())
    }

    /// Flush every previously accepted write to stable storage.
    pub(crate) fn flush(&mut self) -> Result<(), BlockError> {
        if !self.flush_supported() {
            return Err(BlockError::Unsupported);
        }
        self.submit(vq::REQ_FLUSH, 0, 0)
    }

    /// Submit one request and poll it to completion (exactly once).
    fn submit(&mut self, kind: u32, sector: u64, data_len: usize) -> Result<(), BlockError> {
        if self.inflight {
            return Err(BlockError::Corrupt);
        }
        self.inflight = true;
        let result = self.submit_inner(kind, sector, data_len);
        self.inflight = false;
        result
    }

    fn submit_inner(&mut self, kind: u32, sector: u64, data_len: usize) -> Result<(), BlockError> {
        let layout = QueueLayout::new(self.queue_size).map_err(|_| BlockError::Unsupported)?;
        let queue = vm::phys_to_virt(self.queue_phys) as *mut u8;
        let bounce = vm::phys_to_virt(self.bounce_phys) as *mut u8;

        // 1. Stage the header and a status byte that only a real device write can
        // change (a stale STATUS_OK must not look like a completion).
        let header = vq::RequestHeader {
            kind,
            reserved: 0,
            sector,
        };
        let header_bytes = vq::encode_header(&header);
        // SAFETY: the bounce frame is driver-owned and wholly mapped.
        unsafe {
            core::ptr::copy_nonoverlapping(header_bytes.as_ptr(), bounce, vq::REQ_HEADER_SIZE);
            core::ptr::write_volatile(bounce.add(vq::STATUS_OFFSET), vq::STATUS_INIT);
        }

        // 2. Build and publish the descriptor chain (fixed indices 0..2).
        let plan = if kind == vq::REQ_FLUSH {
            vq::plan_flush(self.bounce_phys)
        } else {
            vq::plan_data_request(kind, self.bounce_phys, data_len)
                .map_err(|_| BlockError::BadBuffer)?
        };
        // SAFETY: the queue frames are driver-owned and wholly mapped.
        unsafe {
            for (index, desc) in plan.descs().iter().enumerate() {
                vq::write_desc(queue, layout.desc_offset, index, desc);
            }
        }
        debug_assert!(
            plan.len() >= 2,
            "a request needs header + status descriptors"
        );
        fence(Ordering::SeqCst);

        // 3. Remember the used index before the device can advance it, then
        // publish the avail entry.
        // SAFETY: queue memory is driver-owned and mapped.
        let before = unsafe { vq::used_index(queue, &layout) };
        // SAFETY: see above; the interrupt guard held by the caller keeps the
        // device state consistent.
        unsafe {
            vq::push_avail(queue, &layout, plan.head());
        }
        fence(Ordering::SeqCst);

        // 4. Kick the device.
        wr16(self.io_base, REG_QUEUE_NOTIFY, 0);

        // 5. Poll for exactly this completion, with a bounded wait. The busy
        //    counter advances on every iteration; the clock only tightens the
        //    bound when its ticks actually advance.
        let start_millis = if crate::time::is_ready() {
            Some(crate::time::monotonic_millis())
        } else {
            None
        };
        let mut spins: u64 = 0;
        loop {
            fence(Ordering::SeqCst);
            // SAFETY: queue memory is driver-owned; the device updates `idx` and
            // the ring entry, so both are read with volatile loads.
            let now = unsafe { vq::used_index(queue, &layout) };
            match vq::completion(before, now, self.queue_size) {
                Ok(vq::Completion::Pending) => {}
                Ok(vq::Completion::Done { slot }) => {
                    // SAFETY: `slot` was derived from the published index.
                    let (head, _written) = unsafe { vq::used_element(queue, &layout, slot) };
                    self.clear_isr();
                    if head != u32::from(plan.head()) {
                        return Err(BlockError::Corrupt);
                    }
                    if self.device_failed() {
                        return Err(BlockError::Io);
                    }
                    // SAFETY: the status byte lives in the driver-owned bounce frame.
                    let status = unsafe { core::ptr::read_volatile(bounce.add(vq::STATUS_OFFSET)) };
                    return vq::status_to_result(status);
                }
                Err(_) => {
                    self.clear_isr();
                    return Err(BlockError::Corrupt);
                }
            }
            let elapsed =
                start_millis.map(|start| crate::time::monotonic_millis().saturating_sub(start));
            if poll_verdict(spins, elapsed) == PollVerdict::Timeout {
                self.clear_isr();
                return Err(BlockError::Timeout);
            }
            spins += 1;
            core::hint::spin_loop();
        }
    }

    /// Clear the legacy interrupt-status bits so a later poll never sees stale
    /// completion state. Harmless without IRQs enabled.
    fn clear_isr(&self) {
        let pending = rd8(self.io_base, REG_ISR);
        if pending != 0 {
            wr8(self.io_base, REG_ISR, pending);
        }
    }

    /// True when the device status register reports `FAILED`.
    fn device_failed(&self) -> bool {
        rd8(self.io_base, REG_STATUS) & STATUS_FAILED != 0
    }
}

// --- Public handle ---------------------------------------------------------

/// A `Copy` handle to one initialised legacy virtio-blk device.
///
/// The handle is intentionally tiny: the device state lives in a fixed static
/// slot owned by [`super::init`], and every operation looks it up under an
/// interrupt guard. That lets the filesystems each hold their own handle without
/// duplicating the queue or the bounce buffer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VirtioBlk {
    index: u8,
}

impl VirtioBlk {
    /// Construct a handle for `index` if it can address a device slot.
    pub(crate) fn new(index: usize) -> Option<Self> {
        if index < MAX_BLOCK_DEVICES {
            Some(Self { index: index as u8 })
        } else {
            None
        }
    }

    /// Device index (0-based, as returned by [`super::init`]).
    pub fn index(&self) -> usize {
        self.index as usize
    }
}

impl BlockDevice for VirtioBlk {
    fn block_size(&self) -> u32 {
        VIRTIO_BLK_SECTOR_SIZE
    }

    fn block_count(&self) -> u64 {
        super::with_device(self.index(), |device| device.capacity()).unwrap_or(0)
    }

    fn read_blocks(&mut self, first: u64, buf: &mut [u8]) -> Result<(), BlockError> {
        // Consuming an armed self-test fault happens before the device lookup:
        // nothing is staged, the doorbell is not rung and `inflight` is untouched.
        if super::take_fault(self.index(), super::BlockFault::Read) {
            return Err(super::BlockFault::Read.error());
        }
        super::with_device(self.index(), |device| device.read(first, buf))
            .unwrap_or(Err(BlockError::Io))
    }

    fn write_blocks(&mut self, first: u64, buf: &[u8]) -> Result<(), BlockError> {
        if super::take_fault(self.index(), super::BlockFault::Write) {
            return Err(super::BlockFault::Write.error());
        }
        super::with_device(self.index(), |device| device.write(first, buf))
            .unwrap_or(Err(BlockError::Io))
    }

    fn flush(&mut self) -> Result<(), BlockError> {
        if super::take_fault(self.index(), super::BlockFault::Flush) {
            return Err(super::BlockFault::Flush.error());
        }
        super::with_device(self.index(), |device| device.flush()).unwrap_or(Err(BlockError::Io))
    }
}

/// Keep the interrupt guard type referenced from this module's public docs.
const _: fn() = || {
    let guard = IrqGuard::new();
    drop(guard);
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bar0_must_be_an_io_bar_with_a_real_base() {
        // I/O BAR: bit 0 set, low two bits reserved, base in bits 2..16.
        assert_eq!(bar0_io_base(0x0000_C001).ok(), Some(0xC000));
        assert_eq!(bar0_io_base(0x0000_C005).ok(), Some(0xC004));
        // MMIO BAR (bit 0 clear) is the modern transport, which M5b refuses.
        assert!(matches!(
            bar0_io_base(0xFE00_0000),
            Err(ProbeError::Failed(reason)) if reason.contains("not an I/O BAR")
        ));
        // I/O BAR with no base is not mapped.
        assert!(matches!(
            bar0_io_base(0x0000_0001),
            Err(ProbeError::Failed(reason)) if reason.contains("not mapped")
        ));
    }

    #[test]
    fn handle_reports_the_legacy_sector_size() {
        let handle = VirtioBlk::new(0).expect("slot 0 always has a handle");
        assert_eq!(handle.block_size(), VIRTIO_BLK_SECTOR_SIZE);
        assert_eq!(handle.block_size(), 512);
        assert_eq!(handle.index(), 0);
        assert!(VirtioBlk::new(MAX_BLOCK_DEVICES).is_none());
    }

    #[test]
    fn probe_error_variants_are_distinct() {
        assert!(matches!(bar0_io_base(0x0), Err(ProbeError::Failed(_))));
        let not_found = ProbeError::NotFound;
        assert!(matches!(not_found, ProbeError::NotFound));
        let modern = ProbeError::ModernOnly;
        assert!(matches!(modern, ProbeError::ModernOnly));
    }

    #[test]
    fn busy_bound_terminates_the_poll_even_when_the_tick_counter_is_frozen() {
        // After user mode exits, requests run with interrupts disabled: the
        // clock may still report ready while `monotonic_millis` never moves, so
        // the elapsed-time bound can never fire. The busy counter must end the
        // wait on its own.
        assert_eq!(poll_verdict(0, Some(0)), PollVerdict::Continue);
        assert_eq!(
            poll_verdict(REQUEST_BUSY_BOUND - 1, Some(0)),
            PollVerdict::Continue
        );
        assert_eq!(
            poll_verdict(REQUEST_BUSY_BOUND, Some(0)),
            PollVerdict::Timeout
        );
        // The busy bound also wins if the clock advances only slightly.
        assert_eq!(
            poll_verdict(REQUEST_BUSY_BOUND, Some(1)),
            PollVerdict::Timeout
        );
    }

    #[test]
    fn elapsed_millis_only_tightens_the_bound() {
        assert_eq!(
            poll_verdict(0, Some(REQUEST_TIMEOUT_MILLIS - 1)),
            PollVerdict::Continue
        );
        assert_eq!(
            poll_verdict(0, Some(REQUEST_TIMEOUT_MILLIS)),
            PollVerdict::Timeout
        );
        // Without a usable clock the busy bound is the only guard.
        assert_eq!(poll_verdict(0, None), PollVerdict::Continue);
        assert_eq!(
            poll_verdict(REQUEST_BUSY_BOUND - 1, None),
            PollVerdict::Continue
        );
        assert_eq!(poll_verdict(REQUEST_BUSY_BOUND, None), PollVerdict::Timeout);
    }
}
