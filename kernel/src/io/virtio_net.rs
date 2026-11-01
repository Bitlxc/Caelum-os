//! Legacy transitional `virtio-net` driver (virtio 0.9.5 PCI, device id `0x1000`).
//!
//! M7c gives the future `kernel/src/net` stack a real Ethernet device without
//! touching it yet: this module owns the PCI function, the two legacy
//! virtqueues (0 = RX, 1 = RX) and the MSI-X delivery, and exposes complete
//! Ethernet frames through a copied RX ring. Nothing here knows about IP, ARP or
//! the socket layer.
//!
//! # Layout
//!
//! | queue | direction | frames | contents |
//! |---|---|---|---|
//! | 0 | RX | 3 (contiguous) | 256 descriptors, pre-posted to 8 × 2048 B buffers |
//! | 1 | TX | 3 (contiguous) | 256 descriptors, one 10 B header + frame bounce |
//!
//! # Why a copied ring
//!
//! An RX buffer belongs to the device until the driver re-posts it, so handing a
//! slice of it to the caller would let a later receive overwrite live data. The
//! driver therefore copies every completed frame into [`RxRing`] — a fixed array
//! of [`VIRTIO_NET_RX_RING`] frames — and hands out copies from there.
//!
//! # Interrupts
//!
//! Every MSI-X table entry the driver uses carries the same vector
//! ([`VIRTIO_NET_IRQ_VECTOR`]), so [`on_irq`] can drain both queues from one
//! handler. The handler only clears the ISR status, reaps the used rings, copies
//! frames and re-posts RX descriptors: no printing, no allocation, no protocol
//! parsing. The driver **never** sends an EOI; the EOI rule is owned by `root`:
//! its `irq_dispatch` calls [`on_irq`] for [`VIRTIO_NET_IRQ_VECTOR`] and then
//! `platform::eoi()` once, exactly like the other device vectors. Adding an EOI
//! here would double-signal the local APIC.
//!
//! # Errors
//!
//! Probe errors are printable strings (or [`NetProbeError`]) that name what was
//! expected. A missing MSI-X capability is a hard error: there is no INTx
//! fallback, because QEMU/q35 with a modern firmware advertises MSI-X and a
//! silent downgrade would hide a broken platform.

use core::sync::atomic::{AtomicUsize, Ordering, fence};

use crate::mm::{pmm, vm};
use crate::platform::{self, PciFunction};
use crate::sync::IrqSpinLock;

use super::virtqueue::{self as vq, DESC_F_NEXT, DESC_F_WRITE, Desc, QueueLayout};
use super::{
    NET_HDR_SIZE, NET_MAX_FRAME, NET_QUEUE_FRAMES, NET_RX_BUFFER_FRAMES, NET_RX_BUFFER_SIZE,
    NET_RX_BUFFERS, VIRTIO_NET_F_MAC, VIRTIO_NET_F_STATUS, VIRTIO_PCI_DEVICE_LEGACY_NET,
    VIRTIO_PCI_DEVICE_MODERN_NET, VIRTIO_PCI_VENDOR_ID, allocate_contiguous_frames,
    release_contiguous_frames, zero_frames,
};

// --- Fixed configuration ---------------------------------------------------

/// IDT vector the network device raises.
///
/// `0x20` (timer), `0x21` (keyboard), `0x24` (serial), `0x40` (yield) and
/// `0x41` (cross-CPU reschedule) are taken; `0x42` is the next free IRQ-range
/// slot and is used by every MSI-X entry of this device.
pub const VIRTIO_NET_IRQ_VECTOR: u8 = 0x42;

/// Smallest Ethernet frame the driver accepts (two addresses + ethertype).
pub const VIRTIO_NET_MIN_FRAME: usize = 14;

/// Depth of the copied RX ring handed to the network stack.
pub const VIRTIO_NET_RX_RING: usize = 8;

/// Legacy virtio register offsets inside BAR0 (I/O space, byte granularity).
const REG_DEVICE_FEATURES: u16 = 0x00;
const REG_GUEST_FEATURES: u16 = 0x04;
const REG_QUEUE_PFN: u16 = 0x08;
const REG_QUEUE_SIZE: u16 = 0x0C;
const REG_QUEUE_SELECT: u16 = 0x0E;
const REG_QUEUE_NOTIFY: u16 = 0x10;
const REG_STATUS: u16 = 0x12;
const REG_ISR: u16 = 0x13;
/// With MSI-X enabled this register selects the MSI-X table entry of the queue
/// selected through [`REG_QUEUE_SELECT`]; with INTx it is `queue_vector`.
const REG_MSIX_QUEUE_VECTOR: u16 = 0x14;
/// With MSI-X enabled the device configuration starts at `0x16`; the legacy
/// `0x14` location is the `queue_vector` register.
const REG_CONFIG: u16 = 0x16;

const STATUS_ACKNOWLEDGE: u8 = 1;
const STATUS_DRIVER: u8 = 2;
const STATUS_DRIVER_OK: u8 = 4;
const STATUS_FAILED: u8 = 0x80;

const ISR_QUEUE: u8 = 1;
const ISR_CONFIG: u8 = 2;

const PCI_COMMAND: u8 = 0x04;
const PCI_COMMAND_IO: u16 = 0x1;
const PCI_COMMAND_BUS_MASTER: u16 = 0x4;

const RX_QUEUE: u16 = 0;
const TX_QUEUE: u16 = 1;

/// `struct virtio_net_config` (legacy layout): `mac[6]` then `status` (LE16).
const CONFIG_MAC_OFFSET: u16 = 0;
const CONFIG_STATUS_OFFSET: u16 = 6;
const NET_STATUS_LINK_UP: u16 = 1;
const NET_STATUS_ANNOUNCE: u16 = 2;

const MSIX_ENTRY_CONFIG: u16 = 0;
const MSIX_ENTRY_RX: u16 = 1;
const MSIX_ENTRY_TX: u16 = 2;
/// Config (0) + RX (1) + TX (2) are the entries the driver programs.
const MSIX_MIN_VECTORS: u16 = 3;

/// Bounded polls while waiting for the device to acknowledge a reset.
const RESET_SPIN_LIMIT: u32 = 1000;

// The fixed budget must hold the queue and the largest frame the driver copies.
const _: () = assert!(NET_RX_BUFFER_FRAMES <= super::MAX_CONTIG_FRAMES);
const _: () = assert!(NET_HDR_SIZE + NET_MAX_FRAME <= pmm::FRAME_SIZE as usize);
const _: () = assert!(VIRTIO_NET_RX_RING <= NET_RX_BUFFERS);

// --- Errors ----------------------------------------------------------------

/// Why an I/O operation on the network device failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetIoError {
    /// The device was never brought up (no NIC on this machine, or `init` failed).
    NotReady,
    /// The frame is shorter than [`VIRTIO_NET_MIN_FRAME`] or longer than
    /// [`NET_MAX_FRAME`].
    BadLength,
    /// The TX queue still owns the previous frame.
    WouldBlock,
    /// The caller's buffer is smaller than the frame being read.
    BufferTooSmall,
    /// The device does not offer a feature the driver requires.
    Unsupported,
    /// The device state (used ring, descriptor id) does not make sense.
    Corrupted,
    /// A handle was used although [`init_net`](super::init_net) never ran.
    NoDevice,
}

impl NetIoError {
    /// Stable kebab-case name, for the boot markers of the integrating stage.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NotReady => "not-ready",
            Self::BadLength => "bad-length",
            Self::WouldBlock => "would-block",
            Self::BufferTooSmall => "buffer-too-small",
            Self::Unsupported => "unsupported",
            Self::Corrupted => "corrupted",
            Self::NoDevice => "no-device",
        }
    }
}

impl core::fmt::Display for NetIoError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Why the PCI function could not be turned into a device.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetProbeError {
    /// No legacy (`0x1000`) virtio-net function exists.
    NotFound,
    /// Only a modern (`0x1041`) function exists; the legacy transport is required.
    ModernOnly,
    /// A printable reason (wrong vendor, bad BAR, missing MSI-X, ...).
    Failed(&'static str),
}

impl NetProbeError {
    /// The message `root` prints for this failure.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NotFound => "virtio-net: no legacy (0x1000) network device found",
            Self::ModernOnly => {
                "virtio-net: only a modern (0x1041) function is present; the legacy 0x1000 interface is required"
            }
            Self::Failed(reason) => reason,
        }
    }
}

/// Legacy link status word as exposed by the device configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LinkStatus {
    /// The link is up (a cable/QEMU NIC is connected).
    pub up: bool,
    /// A configuration change announcement is pending.
    pub announce: bool,
}

// --- Pure protocol logic (host-tested) -------------------------------------

/// Check that a PCI function is the legacy virtio-net device the driver supports.
///
/// The vendor id alone is not enough: a modern `0x1041` function, a non-legacy
/// revision or a different programming interface must all be rejected loudly
/// instead of being driven through the legacy register layout.
pub fn classify_legacy_function(
    vendor: u16,
    device: u16,
    revision: u8,
    prog_if: u8,
) -> Result<(), NetProbeError> {
    if vendor != VIRTIO_PCI_VENDOR_ID {
        return Err(NetProbeError::Failed(
            "virtio-net: the function is not a virtio device (vendor id mismatch)",
        ));
    }
    if device == VIRTIO_PCI_DEVICE_MODERN_NET {
        return Err(NetProbeError::ModernOnly);
    }
    if device != VIRTIO_PCI_DEVICE_LEGACY_NET {
        return Err(NetProbeError::Failed(
            "virtio-net: the function is not a legacy network device (device id mismatch)",
        ));
    }
    if revision != 0 {
        return Err(NetProbeError::Failed(
            "virtio-net: not a legacy (revision 0) function; the modern transport is unsupported",
        ));
    }
    if prog_if != 0 {
        return Err(NetProbeError::Failed(
            "virtio-net: unexpected programming interface for a legacy function",
        ));
    }
    Ok(())
}

/// Legacy BAR0 must be an I/O BAR with a non-zero base.
pub fn legacy_io_base(bar0: u32) -> Result<u16, NetProbeError> {
    if bar0 & 1 == 0 {
        return Err(NetProbeError::Failed(
            "virtio-net: BAR0 is not an I/O BAR; the legacy register interface is required",
        ));
    }
    let base = (bar0 & !0x3) as u16;
    if base == 0 {
        return Err(NetProbeError::Failed("virtio-net: BAR0 I/O base is zero"));
    }
    Ok(base)
}

/// Negotiate the subset of device features the driver implements.
///
/// Only `VIRTIO_NET_F_MAC` (required) and `VIRTIO_NET_F_STATUS` (optional) are
/// accepted; every other bit the device offers is masked off, so the driver
/// never acknowledges a feature it does not implement.
pub const fn accept_legacy_features(device: u32) -> Result<u32, NetIoError> {
    if device & VIRTIO_NET_F_MAC == 0 {
        return Err(NetIoError::Unsupported);
    }
    Ok(device & (VIRTIO_NET_F_MAC | VIRTIO_NET_F_STATUS))
}

/// Decode the 16-bit link status word.
pub const fn parse_link_status(word: u16) -> LinkStatus {
    LinkStatus {
        up: word & NET_STATUS_LINK_UP != 0,
        announce: word & NET_STATUS_ANNOUNCE != 0,
    }
}

/// Assemble the MAC address from the two little-endian config reads.
///
/// The first read covers bytes 0..4, the second the remaining two bytes at
/// offset 4 (the status word starts at offset 6).
pub const fn mac_from_config(low: u32, high: u16) -> [u8; 6] {
    let low = low.to_le_bytes();
    let high = high.to_le_bytes();
    [low[0], low[1], low[2], low[3], high[0], high[1]]
}

/// The 10-byte legacy virtio-net header every transmitted frame carries.
///
/// The legacy layout has `flags`, `gso_type`, `hdr_len`, `gso_size` and
/// `csum_start`/`csum_offset`; the driver negotiates no offload feature, so every
/// field stays zero.
pub const fn net_header() -> [u8; NET_HDR_SIZE] {
    [0u8; NET_HDR_SIZE]
}

/// Validate an Ethernet frame handed to [`VirtioNet::send_frame`].
pub const fn validate_tx_frame(len: usize) -> Result<(), NetIoError> {
    if len < VIRTIO_NET_MIN_FRAME || len > NET_MAX_FRAME {
        return Err(NetIoError::BadLength);
    }
    Ok(())
}

/// Descriptors for one transmitted frame: header and payload point into the
/// single bounce frame.
pub fn tx_descriptors(bounce_phys: u64, frame_len: usize) -> Result<[Desc; 2], NetIoError> {
    validate_tx_frame(frame_len)?;
    let header_len = (NET_HDR_SIZE + frame_len) as u32;
    Ok([
        Desc {
            addr: bounce_phys,
            len: header_len,
            flags: DESC_F_NEXT,
            next: 1,
        },
        Desc {
            addr: bounce_phys + NET_HDR_SIZE as u64,
            len: frame_len as u32,
            flags: 0,
            next: 0,
        },
    ])
}

/// Descriptor for one pre-posted RX buffer: the device writes the whole buffer.
pub const fn rx_descriptor(buffer_phys: u64) -> Desc {
    Desc {
        addr: buffer_phys,
        len: NET_RX_BUFFER_SIZE as u32,
        flags: DESC_F_WRITE,
        next: 0,
    }
}

/// How a completed RX descriptor is interpreted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RxOutcome {
    /// A complete Ethernet frame starts at `offset` and is `len` bytes long.
    Frame {
        /// Offset of the frame inside the buffer (past the virtio header).
        offset: usize,
        /// Frame length in bytes.
        len: usize,
    },
    /// The device reported fewer bytes than the virtio header plus a minimum frame.
    Short,
    /// The device wrote more than a maximum-sized frame; the buffer is rejected.
    TooLong,
}

/// Classify the `len` the device wrote into one RX buffer.
pub const fn classify_rx(written: u32) -> RxOutcome {
    let written = written as usize;
    if written < NET_HDR_SIZE + VIRTIO_NET_MIN_FRAME {
        return RxOutcome::Short;
    }
    let frame_len = written - NET_HDR_SIZE;
    if frame_len > NET_MAX_FRAME {
        return RxOutcome::TooLong;
    }
    RxOutcome::Frame {
        offset: NET_HDR_SIZE,
        len: frame_len,
    }
}

/// What a used-ring entry means for the single in-flight TX frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TxOutcome {
    /// This completion belongs to the in-flight frame; it is reclaimed once.
    Reclaimed,
    /// Nothing was in flight (or the descriptor id is not the one the driver
    /// posted), so the entry must not be counted as a completed frame.
    Unexpected,
}

/// Decide whether a used-ring entry completes the TX frame.
///
/// The driver posts descriptor head 0, so a completion that arrives with no
/// frame in flight or with a different head is a device glitch, not a success.
pub const fn classify_tx_completion(inflight: bool, head: u32) -> TxOutcome {
    if inflight && head == 0 {
        TxOutcome::Reclaimed
    } else {
        TxOutcome::Unexpected
    }
}

/// Fixed-depth ring of complete Ethernet frames copied out of DMA buffers.
pub struct RxRing {
    frames: [[u8; NET_MAX_FRAME]; VIRTIO_NET_RX_RING],
    lens: [u16; VIRTIO_NET_RX_RING],
    head: usize,
    tail: usize,
    len: usize,
    dropped: u64,
}

impl RxRing {
    pub const fn new() -> Self {
        Self {
            frames: [[0u8; NET_MAX_FRAME]; VIRTIO_NET_RX_RING],
            lens: [0u16; VIRTIO_NET_RX_RING],
            head: 0,
            tail: 0,
            len: 0,
            dropped: 0,
        }
    }

    /// Copy one frame in. Returns `false` when the ring was full: the frame is
    /// dropped and counted, never overwritten.
    pub fn push(&mut self, frame: &[u8]) -> bool {
        debug_assert!(frame.len() <= NET_MAX_FRAME);
        if self.len == VIRTIO_NET_RX_RING {
            self.dropped += 1;
            return false;
        }
        let slot = self.tail;
        let copy = frame.len().min(NET_MAX_FRAME);
        self.frames[slot][..copy].copy_from_slice(&frame[..copy]);
        self.lens[slot] = copy as u16;
        self.tail = (self.tail + 1) % VIRTIO_NET_RX_RING;
        self.len += 1;
        true
    }

    /// Pop the oldest frame into `out`.
    ///
    /// A buffer that is too small is reported with [`NetIoError::BufferTooSmall`]
    /// and the frame **stays** in the ring, so the caller can retry with a larger
    /// buffer without losing the packet.
    pub fn pop(&mut self, out: &mut [u8]) -> Result<usize, NetIoError> {
        if self.len == 0 {
            return Err(NetIoError::NotReady);
        }
        let slot = self.head;
        let len = self.lens[slot] as usize;
        if out.len() < len {
            return Err(NetIoError::BufferTooSmall);
        }
        out[..len].copy_from_slice(&self.frames[slot][..len]);
        self.head = (self.head + 1) % VIRTIO_NET_RX_RING;
        self.len -= 1;
        Ok(len)
    }

    /// Number of frames waiting for the stack.
    pub const fn len(&self) -> usize {
        self.len
    }

    /// Whether the ring is empty.
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }
}

impl Default for RxRing {
    fn default() -> Self {
        Self::new()
    }
}

// --- Device ----------------------------------------------------------------

/// One probed virtio-net device.
struct Device {
    io_base: u16,
    rx_queue_phys: u64,
    tx_queue_phys: u64,
    rx_buffers_phys: u64,
    tx_bounce_phys: u64,
    queue_size: u16,
    features: u32,
    mac: [u8; 6],
    has_status: bool,
    link: LinkStatus,
    ready: bool,
    /// Used-ring index already reaped for RX/TX.
    rx_seen: u16,
    tx_seen: u16,
    tx_inflight: bool,
    irq_count: u64,
    rx_count: u64,
    tx_count: u64,
    config_changes: u64,
    rx_dropped: u64,
    tx_dropped: u64,
}

impl Device {
    fn layout(&self) -> Result<QueueLayout, NetIoError> {
        QueueLayout::new(self.queue_size).map_err(|_| NetIoError::Corrupted)
    }

    /// Program the MSI-X table entry vector of one queue (legacy `queue_vector`).
    fn set_queue_vector(&self, queue: u16, entry: u16) {
        wr16(self.io_base, REG_QUEUE_SELECT, queue);
        wr16(self.io_base, REG_MSIX_QUEUE_VECTOR, entry);
    }

    /// Transmit one Ethernet frame; non-blocking.
    fn send_frame(&mut self, frame: &[u8]) -> Result<(), NetIoError> {
        if !self.ready {
            return Err(NetIoError::NotReady);
        }
        validate_tx_frame(frame.len())?;
        self.collect_tx()?;
        if self.tx_inflight {
            return Err(NetIoError::WouldBlock);
        }
        let layout = self.layout()?;
        let descs = tx_descriptors(self.tx_bounce_phys, frame.len())?;
        let header = net_header();
        let bounce = vm::phys_to_virt(self.tx_bounce_phys) as *mut u8;
        // SAFETY: the bounce frame is owned by this device for its whole
        // lifetime and the descriptor chain points into it; the device reads it
        // only after the available ring is published below.
        unsafe {
            core::ptr::copy_nonoverlapping(header.as_ptr(), bounce, NET_HDR_SIZE);
            core::ptr::copy_nonoverlapping(frame.as_ptr(), bounce.add(NET_HDR_SIZE), frame.len());
        }
        let queue = vm::phys_to_virt(self.tx_queue_phys) as *mut u8;
        for (index, desc) in descs.iter().enumerate() {
            // SAFETY: the queue frames were zeroed and are owned by this driver.
            unsafe { vq::write_desc(queue, layout.desc_offset, index, desc) };
        }
        fence(Ordering::SeqCst);
        // SAFETY: same ownership argument as above.
        unsafe {
            let _ = vq::push_avail(queue, &layout, 0);
        }
        fence(Ordering::SeqCst);
        wr16(self.io_base, REG_QUEUE_NOTIFY, TX_QUEUE);
        self.tx_inflight = true;
        Ok(())
    }

    /// Reap every published TX completion.
    fn collect_tx(&mut self) -> Result<(), NetIoError> {
        let layout = self.layout()?;
        let queue = vm::phys_to_virt(self.tx_queue_phys) as *mut u8;
        // SAFETY: used ring of a queue this driver owns.
        let used = unsafe { vq::used_index(queue, &layout) };
        while self.tx_seen != used {
            let slot = self.tx_seen % self.queue_size;
            // SAFETY: same as above; `slot` is inside the used ring.
            let (head, _len) = unsafe { vq::used_element(queue, &layout, slot) };
            self.tx_seen = self.tx_seen.wrapping_add(1);
            match classify_tx_completion(self.tx_inflight, head) {
                TxOutcome::Reclaimed => {
                    self.tx_inflight = false;
                    self.tx_count += 1;
                }
                TxOutcome::Unexpected => self.tx_dropped += 1,
            }
        }
        Ok(())
    }

    /// Reap every completed RX descriptor, copying frames into the ring and
    /// re-posting the buffer. Returns how many frames were queued.
    fn collect_rx(&mut self) -> Result<usize, NetIoError> {
        let layout = self.layout()?;
        let queue = vm::phys_to_virt(self.rx_queue_phys) as *mut u8;
        // SAFETY: used ring of a queue this driver owns.
        let used = unsafe { vq::used_index(queue, &layout) };
        let mut queued = 0usize;
        while self.rx_seen != used {
            let slot = self.rx_seen % self.queue_size;
            // SAFETY: same as above.
            let (id, written) = unsafe { vq::used_element(queue, &layout, slot) };
            self.rx_seen = self.rx_seen.wrapping_add(1);
            let index = id as usize;
            if index >= NET_RX_BUFFERS {
                // The device returned a descriptor id it never got: do not touch
                // that memory, just count the glitch.
                self.rx_dropped += 1;
                continue;
            }
            let buffer_phys = self.rx_buffers_phys + index as u64 * NET_RX_BUFFER_SIZE as u64;
            match classify_rx(written) {
                RxOutcome::Frame { offset, len } => {
                    // SAFETY: the buffer belongs to this driver and the device is
                    // done with it (it published the used entry); the slice is
                    // exactly NET_RX_BUFFER_SIZE bytes.
                    let source = unsafe {
                        core::slice::from_raw_parts(
                            vm::phys_to_virt(buffer_phys) as *const u8,
                            NET_RX_BUFFER_SIZE,
                        )
                    };
                    if rx_ring().push(&source[offset..offset + len]) {
                        self.rx_count += 1;
                        queued += 1;
                    } else {
                        self.rx_dropped += 1;
                    }
                }
                RxOutcome::Short | RxOutcome::TooLong => self.rx_dropped += 1,
            }
            // SAFETY: publishing the same descriptor id again is the protocol's
            // re-post; the device reads the descriptor table this driver owns.
            unsafe {
                let _ = vq::push_avail(queue, &layout, index as u16);
            }
        }
        Ok(queued)
    }

    /// Refresh the cached link state from the device configuration.
    fn refresh_link(&mut self) {
        if !self.has_status {
            return;
        }
        let word = rd16(self.io_base, REG_CONFIG + CONFIG_STATUS_OFFSET);
        self.link = parse_link_status(word);
    }

    /// MSI-X handler body: clear the ISR, reap both queues, re-post RX.
    fn on_irq(&mut self) -> usize {
        let isr = rd8(self.io_base, REG_ISR);
        if isr & ISR_CONFIG != 0 {
            self.config_changes += 1;
            self.refresh_link();
        }
        // Both queues share one vector, so a used-ring interrupt can come from
        // either; drain both.
        let queue_interrupt = isr & ISR_QUEUE != 0;
        let rx_before = self.rx_count;
        let tx_before = self.tx_count;
        let _ = self.collect_rx();
        let _ = self.collect_tx();
        let work = (self.rx_count - rx_before) as usize + (self.tx_count - tx_before) as usize;
        if queue_interrupt || isr != 0 || work != 0 {
            self.irq_count += 1;
        }
        if work != 0 {
            work
        } else {
            usize::from(isr != 0)
        }
    }

    /// Hand the oldest completed frame to the caller.
    fn pop_frame(&mut self, out: &mut [u8]) -> Result<usize, NetIoError> {
        if !self.ready {
            return Err(NetIoError::NotReady);
        }
        // Opportunistic reap keeps the ring fed even when the caller polls.
        let _ = self.collect_rx();
        rx_ring().pop(out)
    }
}

// --- Register helpers ------------------------------------------------------

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

// --- Module state ----------------------------------------------------------

/// Leaf lock around the device slot.
///
/// The device is touched from two contexts: the MSI-X handler ([`on_irq`]) and
/// task context ([`VirtioNet::send_frame`] / [`VirtioNet::pop_frame`]). The lock
/// disables interrupts locally (so the handler can never interrupt a critical
/// section on the same CPU) and spins against the other CPUs; it is a leaf, so
/// nothing inside the critical sections may take another lock.
static NET_LOCK: IrqSpinLock = IrqSpinLock::new();

static mut NET_DEVICE: Option<Device> = None;
static NET_DEVICE_COUNT: AtomicUsize = AtomicUsize::new(0);

/// The copied RX frame ring.
///
/// It lives in static storage instead of inside [`Device`]: eight 1514-byte
/// frames would make every `Device` value a 12 KiB stack temporary, and the
/// kernel stack is 16 KiB, so constructing/returning a `Device` by value would
/// overflow the stack before the device is usable.
static mut NET_RX_RING: RxRing = RxRing::new();

/// Borrow the one RX ring.
///
/// # Safety
///
/// The caller must already hold [`NET_LOCK`] (every path is inside
/// [`with_device`] or [`init_device`]). That lock serialises the MSI-X handler
/// (which fills the ring) and task context (which drains it), so the `&mut`
/// never aliases another ring access.
fn rx_ring() -> &'static mut RxRing {
    // SAFETY: see the function contract; the static is only reachable through
    // this accessor.
    unsafe { &mut *core::ptr::addr_of_mut!(NET_RX_RING) }
}

/// Run `f` with the device, if [`init_net`](super::init_net) brought one up.
fn with_device<R>(f: impl FnOnce(&mut Device) -> R) -> Option<R> {
    NET_LOCK.with(|| {
        // SAFETY: every access to the slot goes through this lock, and the slot
        // is written once by `init` before any handle exists.
        let slot = unsafe { &mut *core::ptr::addr_of_mut!(NET_DEVICE) };
        slot.as_mut().map(f)
    })
}

// --- Probe ----------------------------------------------------------------

/// Locate the legacy function, or explain why there is none.
fn probe_function() -> Result<PciFunction, NetProbeError> {
    platform::init_pci().map_err(NetProbeError::Failed)?;
    match platform::find_pci(VIRTIO_PCI_VENDOR_ID, VIRTIO_PCI_DEVICE_LEGACY_NET, 0) {
        Some(function) => Ok(function),
        None => {
            if platform::find_pci(VIRTIO_PCI_VENDOR_ID, VIRTIO_PCI_DEVICE_MODERN_NET, 0).is_some() {
                Err(NetProbeError::ModernOnly)
            } else {
                Err(NetProbeError::NotFound)
            }
        }
    }
}

/// Allocate the four DMA runs late (when the early reservation was skipped).
fn allocate_net_dma() -> Result<super::NetDmaRegion, &'static str> {
    let Some(rx_queue_phys) = allocate_contiguous_frames(NET_QUEUE_FRAMES) else {
        return Err("virtio-net: cannot allocate contiguous RX virtqueue frames");
    };
    let Some(tx_queue_phys) = allocate_contiguous_frames(NET_QUEUE_FRAMES) else {
        release_contiguous_frames(rx_queue_phys, NET_QUEUE_FRAMES);
        return Err("virtio-net: cannot allocate contiguous TX virtqueue frames");
    };
    let Some(rx_buffers_phys) = allocate_contiguous_frames(NET_RX_BUFFER_FRAMES) else {
        release_contiguous_frames(rx_queue_phys, NET_QUEUE_FRAMES);
        release_contiguous_frames(tx_queue_phys, NET_QUEUE_FRAMES);
        return Err("virtio-net: cannot allocate contiguous RX buffer frames");
    };
    let bounce = match pmm::alloc_frame() {
        Ok(phys) => phys,
        Err(_) => {
            release_contiguous_frames(rx_queue_phys, NET_QUEUE_FRAMES);
            release_contiguous_frames(tx_queue_phys, NET_QUEUE_FRAMES);
            release_contiguous_frames(rx_buffers_phys, NET_RX_BUFFER_FRAMES);
            return Err("virtio-net: cannot allocate the TX bounce frame");
        }
    };
    Ok(super::NetDmaRegion {
        rx_queue_phys,
        tx_queue_phys,
        rx_buffers_phys: rx_buffers_phys,
        tx_bounce_phys: bounce,
    })
}

/// Return every DMA run of `region`, claiming back the early reservation.
fn release_net_dma(region: &super::NetDmaRegion, from_reservation: bool) {
    if from_reservation {
        super::abandon_net_reservation();
    }
    release_contiguous_frames(region.rx_queue_phys, NET_QUEUE_FRAMES);
    release_contiguous_frames(region.tx_queue_phys, NET_QUEUE_FRAMES);
    release_contiguous_frames(region.rx_buffers_phys, NET_RX_BUFFER_FRAMES);
    let _ = pmm::dealloc_frame(region.tx_bounce_phys);
}

/// Undo the partial handshake: reset the device, release DMA, report `reason`.
fn abort(
    io_base: u16,
    region: &super::NetDmaRegion,
    from_reservation: bool,
    reason: &'static str,
) -> Result<Device, &'static str> {
    wr8(io_base, REG_STATUS, 0);
    release_net_dma(region, from_reservation);
    Err(reason)
}

/// Wait (bounded) for the device to clear its status register after a reset.
fn reset_device(io_base: u16) -> Result<(), &'static str> {
    wr8(io_base, REG_STATUS, 0);
    let mut spins = 0u32;
    while rd8(io_base, REG_STATUS) != 0 {
        if spins >= RESET_SPIN_LIMIT {
            return Err("virtio-net: the device did not acknowledge the reset");
        }
        spins += 1;
        platform::io_delay();
    }
    Ok(())
}

/// Run the legacy handshake on one probed function.
fn init_device(function: PciFunction) -> Result<Device, &'static str> {
    // Everything below can fail; nothing may touch a register before the
    // identity and the legacy layout are established.
    classify_legacy_function(
        function.vendor_id,
        function.device_id,
        function.revision,
        function.prog_if,
    )
    .map_err(|error| error.as_str())?;
    let capability = platform::msix_capability(&function)
        .map_err(|_| "virtio-net: the MSI-X capability is required; there is no INTx fallback")?;
    if capability.vectors < MSIX_MIN_VECTORS {
        return Err("virtio-net: the MSI-X table has fewer than 3 vectors (config + RX + TX)");
    }
    let io_base = legacy_io_base(function.bars[0]).map_err(|error| error.as_str())?;

    // Bus master + I/O decode: both are needed for DMA and for BAR0 access.
    let command = platform::read_config16(&function, PCI_COMMAND)?;
    platform::write_config16(
        &function,
        PCI_COMMAND,
        command | PCI_COMMAND_IO | PCI_COMMAND_BUS_MASTER,
    )?;

    let reserved = super::take_net_reservation();
    let from_reservation = reserved.is_some();
    let region = match reserved {
        Some(region) => region,
        None => match allocate_net_dma() {
            Ok(region) => region,
            Err(reason) => return Err(reason),
        },
    };

    // Clear the queues and buffers before the device can see them.
    // SAFETY: the runs are exclusively owned by this driver from here on.
    unsafe {
        zero_frames(region.rx_queue_phys, NET_QUEUE_FRAMES);
        zero_frames(region.tx_queue_phys, NET_QUEUE_FRAMES);
        zero_frames(region.rx_buffers_phys, NET_RX_BUFFER_FRAMES);
        zero_frames(region.tx_bounce_phys, 1);
    }

    match reset_device(io_base) {
        Ok(()) => {}
        Err(reason) => return abort(io_base, &region, from_reservation, reason),
    }
    wr8(io_base, REG_STATUS, STATUS_ACKNOWLEDGE);
    wr8(io_base, REG_STATUS, STATUS_ACKNOWLEDGE | STATUS_DRIVER);

    let device_features = rd32(io_base, REG_DEVICE_FEATURES);
    let features = match accept_legacy_features(device_features) {
        Ok(features) => features,
        Err(_) => {
            return abort(
                io_base,
                &region,
                from_reservation,
                "virtio-net: the device does not offer VIRTIO_NET_F_MAC",
            );
        }
    };
    wr32(io_base, REG_GUEST_FEATURES, features);

    let mac = mac_from_config(
        rd32(io_base, REG_CONFIG + CONFIG_MAC_OFFSET),
        rd16(io_base, REG_CONFIG + CONFIG_MAC_OFFSET + 4),
    );
    let has_status = features & VIRTIO_NET_F_STATUS != 0;
    let link = if has_status {
        parse_link_status(rd16(io_base, REG_CONFIG + CONFIG_STATUS_OFFSET))
    } else {
        LinkStatus {
            up: true,
            announce: false,
        }
    };

    // Both legacy queues must have the same size to share one layout and the
    // three-frame budget (QEMU reports 256 descriptors for legacy virtio-net).
    wr16(io_base, REG_QUEUE_SELECT, RX_QUEUE);
    let rx_queue_size = rd16(io_base, REG_QUEUE_SIZE);
    wr16(io_base, REG_QUEUE_SELECT, TX_QUEUE);
    let tx_queue_size = rd16(io_base, REG_QUEUE_SIZE);
    if rx_queue_size != tx_queue_size {
        return abort(
            io_base,
            &region,
            from_reservation,
            "virtio-net: the RX and TX queue sizes differ",
        );
    }
    let queue_size = rx_queue_size;
    if queue_size < NET_RX_BUFFERS as u16 {
        return abort(
            io_base,
            &region,
            from_reservation,
            "virtio-net: the queue is smaller than the RX prefetch ring",
        );
    }
    let layout = match QueueLayout::new(queue_size) {
        Ok(layout) => layout,
        Err(_) => {
            return abort(
                io_base,
                &region,
                from_reservation,
                "virtio-net: the legacy queue size is outside 8..=256",
            );
        }
    };
    if layout.bytes() > NET_QUEUE_FRAMES * pmm::FRAME_SIZE as usize {
        return abort(
            io_base,
            &region,
            from_reservation,
            "virtio-net: the queue does not fit the three-frame DMA budget",
        );
    }

    // MSI-X: one shared vector for config, RX and TX.
    let dest_apic = match platform::lapic_id() {
        Some(id) => id,
        None => {
            return abort(
                io_base,
                &region,
                from_reservation,
                "virtio-net: the local APIC id is unknown; cannot program MSI-X",
            );
        }
    };
    for entry in [MSIX_ENTRY_CONFIG, MSIX_ENTRY_RX, MSIX_ENTRY_TX] {
        if let Err(reason) = platform::configure_msix_vector(
            &function,
            &capability,
            entry,
            VIRTIO_NET_IRQ_VECTOR,
            dest_apic,
        ) {
            return abort(io_base, &region, from_reservation, reason);
        }
    }
    if let Err(reason) = platform::set_msix_function_mask(&function, &capability, false) {
        return abort(io_base, &region, from_reservation, reason);
    }
    if let Err(reason) = platform::set_msix_enabled(&function, &capability, true) {
        return abort(io_base, &region, from_reservation, reason);
    }

    // Queue PFNs (page frame number of the contiguous run base).
    let rx_pfn = match u32::try_from(region.rx_queue_phys / pmm::FRAME_SIZE) {
        Ok(pfn) => pfn,
        Err(_) => {
            return abort(
                io_base,
                &region,
                from_reservation,
                "virtio-net: the RX queue address does not fit the PFN register",
            );
        }
    };
    let tx_pfn = match u32::try_from(region.tx_queue_phys / pmm::FRAME_SIZE) {
        Ok(pfn) => pfn,
        Err(_) => {
            return abort(
                io_base,
                &region,
                from_reservation,
                "virtio-net: the TX queue address does not fit the PFN register",
            );
        }
    };
    wr16(io_base, REG_QUEUE_SELECT, RX_QUEUE);
    wr32(io_base, REG_QUEUE_PFN, rx_pfn);
    wr16(io_base, REG_QUEUE_SELECT, TX_QUEUE);
    wr32(io_base, REG_QUEUE_PFN, tx_pfn);

    // The copied RX ring lives in static storage (`NET_RX_RING`); start every
    // bring-up from an empty ring. SAFETY: `init_device` runs once under
    // `NET_LOCK` before the device or its MSI-X handler can observe the ring,
    // and an all-zero image is exactly the ring's empty state.
    unsafe { core::ptr::write_bytes(core::ptr::addr_of_mut!(NET_RX_RING), 0, 1) };

    let mut device = Device {
        io_base,
        rx_queue_phys: region.rx_queue_phys,
        tx_queue_phys: region.tx_queue_phys,
        rx_buffers_phys: region.rx_buffers_phys,
        tx_bounce_phys: region.tx_bounce_phys,
        queue_size,
        features,
        mac,
        has_status,
        link,
        ready: false,
        rx_seen: 0,
        tx_seen: 0,
        tx_inflight: false,
        irq_count: 0,
        rx_count: 0,
        tx_count: 0,
        config_changes: 0,
        rx_dropped: 0,
        tx_dropped: 0,
    };
    // Point each queue at its MSI-X table entry and pre-post the RX buffers.
    device.set_queue_vector(RX_QUEUE, MSIX_ENTRY_RX);
    device.set_queue_vector(TX_QUEUE, MSIX_ENTRY_TX);
    {
        let queue = vm::phys_to_virt(region.rx_queue_phys) as *mut u8;
        for index in 0..NET_RX_BUFFERS {
            let buffer_phys = region.rx_buffers_phys + index as u64 * NET_RX_BUFFER_SIZE as u64;
            let desc = rx_descriptor(buffer_phys);
            // SAFETY: descriptor table of a queue owned by this driver.
            unsafe { vq::write_desc(queue, layout.desc_offset, index, &desc) };
        }
        for index in 0..NET_RX_BUFFERS {
            // SAFETY: same as above.
            unsafe {
                let _ = vq::push_avail(queue, &layout, index as u16);
            }
        }
    }

    wr8(
        io_base,
        REG_STATUS,
        STATUS_ACKNOWLEDGE | STATUS_DRIVER | STATUS_DRIVER_OK,
    );
    if rd8(io_base, REG_STATUS) & STATUS_FAILED != 0 {
        return abort(
            io_base,
            &region,
            from_reservation,
            "virtio-net: the device reported STATUS_FAILED after DRIVER_OK",
        );
    }
    device.ready = true;
    // Tell the device the RX descriptors are there (legacy drivers notify once).
    wr16(io_base, REG_QUEUE_NOTIFY, RX_QUEUE);
    Ok(device)
}

// --- Public entry points ---------------------------------------------------

/// Bring up the single legacy virtio-net device.
///
/// Returns `Ok(1)` once the device is ready, `Ok(0)` is impossible: no device is
/// a loud error, because M7c expects the QEMU/q35 NIC to exist. Idempotent: a
/// second call returns the first result without touching the device again.
pub fn init() -> Result<usize, &'static str> {
    let count = NET_DEVICE_COUNT.load(Ordering::SeqCst);
    if count != 0 {
        return Ok(count);
    }
    let function = probe_function().map_err(|error| error.as_str())?;
    let device = init_device(function)?;
    NET_LOCK.with(|| {
        // SAFETY: `init` is the only writer and runs once; the lock keeps the
        // MSI-X handler from reading a half-installed device.
        unsafe { *core::ptr::addr_of_mut!(NET_DEVICE) = Some(device) };
    });
    NET_DEVICE_COUNT.store(1, Ordering::SeqCst);
    Ok(1)
}

/// Number of network devices [`init`] brought up.
pub fn device_count() -> usize {
    NET_DEVICE_COUNT.load(Ordering::SeqCst)
}

/// MSI-X handler entry point; `root`'s IDT stub calls this and nothing else.
///
/// The handler never sends an EOI: `root`'s `irq_dispatch` owns that and calls
/// `platform::eoi()` right after this returns, like every other device vector.
/// Doing it twice would signal the local APIC twice.
///
/// Returns the number of receive/transmit events it processed (0 when the
/// interrupt was not ours), which the integrating stage may use for tracing.
pub fn on_irq() -> usize {
    with_device(|device| device.on_irq()).unwrap_or(0)
}

/// The MAC address of the device, if one is up.
pub fn mac() -> Option<[u8; 6]> {
    with_device(|device| device.mac)
}

/// The current link status, if a device is up.
pub fn link_status() -> Option<LinkStatus> {
    with_device(|device| device.link)
}

/// MSI-X interrupts handled so far.
pub fn irq_count() -> u64 {
    with_device(|device| device.irq_count).unwrap_or(0)
}

/// Frames copied into the RX ring so far.
pub fn rx_count() -> u64 {
    with_device(|device| device.rx_count).unwrap_or(0)
}

/// Frames completed on the TX queue so far.
pub fn tx_count() -> u64 {
    with_device(|device| device.tx_count).unwrap_or(0)
}

/// Configuration-change interrupts seen so far (link up/down).
pub fn config_change_count() -> u64 {
    with_device(|device| device.config_changes).unwrap_or(0)
}

/// Public handle to the network device.
///
/// The handle carries no state: every method looks the device up under the leaf
/// lock and fails with [`NetIoError::NoDevice`] when nothing was brought up.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VirtioNet {
    index: u8,
}

impl VirtioNet {
    /// Handle to the device, or `None` before a successful [`init`].
    pub fn handle() -> Option<Self> {
        if NET_DEVICE_COUNT.load(Ordering::SeqCst) == 0 {
            return None;
        }
        Some(Self { index: 0 })
    }

    /// 0-based device index (always 0 in M7c).
    pub const fn index(self) -> u8 {
        self.index
    }

    /// Whether the device reached `DRIVER_OK`.
    pub fn ready(self) -> bool {
        with_device(|device| device.ready).unwrap_or(false)
    }

    /// The device MAC address.
    pub fn mac(self) -> Option<[u8; 6]> {
        with_device(|device| device.mac)
    }

    /// Current link state.
    pub fn link_status(self) -> Option<LinkStatus> {
        with_device(|device| device.link)
    }

    /// Whether a received frame is waiting.
    pub fn rx_ready(self) -> bool {
        with_device(|_| !rx_ring().is_empty()).unwrap_or(false)
    }

    /// Number of frames waiting in the copied RX ring.
    pub fn rx_len(self) -> Option<usize> {
        with_device(|_| rx_ring().len())
    }

    /// Transmit one Ethernet frame (non-blocking).
    pub fn send_frame(self, frame: &[u8]) -> Result<(), NetIoError> {
        with_device(|device| device.send_frame(frame)).unwrap_or(Err(NetIoError::NoDevice))
    }

    /// Copy the oldest received frame into `out`; returns its length.
    pub fn pop_frame(self, out: &mut [u8]) -> Result<usize, NetIoError> {
        with_device(|device| device.pop_frame(out)).unwrap_or(Err(NetIoError::NoDevice))
    }

    /// Device features negotiated at probe time (diagnostics).
    pub fn features(self) -> Option<u32> {
        with_device(|device| device.features)
    }
}

// --- Tests -----------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn legacy_classification_rejects_wrong_vendor_modern_and_non_legacy() {
        assert_eq!(
            classify_legacy_function(0x8086, VIRTIO_PCI_DEVICE_LEGACY_NET, 0, 0),
            Err(NetProbeError::Failed(
                "virtio-net: the function is not a virtio device (vendor id mismatch)"
            ))
        );
        assert_eq!(
            classify_legacy_function(VIRTIO_PCI_VENDOR_ID, VIRTIO_PCI_DEVICE_MODERN_NET, 0, 0),
            Err(NetProbeError::ModernOnly)
        );
        assert_eq!(
            classify_legacy_function(VIRTIO_PCI_VENDOR_ID, 0x1001, 0, 0),
            Err(NetProbeError::Failed(
                "virtio-net: the function is not a legacy network device (device id mismatch)"
            ))
        );
        assert_eq!(
            classify_legacy_function(VIRTIO_PCI_VENDOR_ID, VIRTIO_PCI_DEVICE_LEGACY_NET, 1, 0),
            Err(NetProbeError::Failed(
                "virtio-net: not a legacy (revision 0) function; the modern transport is unsupported"
            ))
        );
        assert_eq!(
            classify_legacy_function(VIRTIO_PCI_VENDOR_ID, VIRTIO_PCI_DEVICE_LEGACY_NET, 0, 1),
            Err(NetProbeError::Failed(
                "virtio-net: unexpected programming interface for a legacy function"
            ))
        );
        assert_eq!(
            classify_legacy_function(VIRTIO_PCI_VENDOR_ID, VIRTIO_PCI_DEVICE_LEGACY_NET, 0, 0),
            Ok(())
        );
    }

    #[test]
    fn legacy_io_base_requires_an_io_bar_with_a_base() {
        assert!(
            legacy_io_base(0x0000_C000).is_err(),
            "an MMIO BAR is refused"
        );
        assert!(
            legacy_io_base(0x0000_0001).is_err(),
            "a zero base is refused"
        );
        assert_eq!(legacy_io_base(0x0000_C001), Ok(0xC000));
        // The low two bits are the BAR type/decoder, not part of the address.
        assert_eq!(legacy_io_base(0x0000_C003), Ok(0xC000));
    }

    #[test]
    fn accepts_only_the_features_the_driver_implements() {
        assert_eq!(
            accept_legacy_features(0),
            Err(NetIoError::Unsupported),
            "VIRTIO_NET_F_MAC is mandatory"
        );
        assert_eq!(
            accept_legacy_features(VIRTIO_NET_F_MAC),
            Ok(VIRTIO_NET_F_MAC)
        );
        assert_eq!(
            accept_legacy_features(u32::MAX),
            Ok(VIRTIO_NET_F_MAC | VIRTIO_NET_F_STATUS),
            "everything not implemented is masked off"
        );
        assert_eq!(
            accept_legacy_features(VIRTIO_NET_F_MAC | (1 << 0) | (1 << 20)),
            Ok(VIRTIO_NET_F_MAC),
            "unknown bits are not acknowledged"
        );
    }

    #[test]
    fn link_status_and_mac_decode_from_the_config_space() {
        assert_eq!(
            parse_link_status(0),
            LinkStatus {
                up: false,
                announce: false
            }
        );
        assert_eq!(
            parse_link_status(NET_STATUS_LINK_UP),
            LinkStatus {
                up: true,
                announce: false
            }
        );
        assert_eq!(
            parse_link_status(NET_STATUS_LINK_UP | NET_STATUS_ANNOUNCE),
            LinkStatus {
                up: true,
                announce: true
            }
        );
        // Little-endian: the low dword holds bytes 0..4, the u16 the last two.
        assert_eq!(
            mac_from_config(0x4433_2211, 0x6655),
            [0x11, 0x22, 0x33, 0x44, 0x55, 0x66]
        );
    }

    #[test]
    fn queue_layout_fits_the_three_frame_budget() {
        // QEMU's legacy virtio-net queue is 256 descriptors, ending at 10244
        // bytes because the used ring is 4096-byte aligned.
        let layout = QueueLayout::new(256).unwrap();
        assert_eq!(layout.bytes(), 10_244);
        assert!(layout.bytes() <= NET_QUEUE_FRAMES * pmm::FRAME_SIZE as usize);
        assert_eq!(layout.avail_offset, 256 * 16);
        assert!(QueueLayout::new(7).is_err());
        assert!(QueueLayout::new(257).is_err());
        assert!(QueueLayout::new(8).is_ok());
        assert!(QueueLayout::new(256).is_ok());
    }

    #[test]
    fn virtio_header_is_ten_zero_bytes() {
        let header = net_header();
        assert_eq!(header.len(), 10);
        assert_eq!(NET_HDR_SIZE, 10);
        assert!(header.iter().all(|byte| *byte == 0));
    }

    #[test]
    fn tx_descriptors_cover_header_and_payload() {
        let descs = tx_descriptors(0x1000, 14).unwrap();
        assert_eq!(descs[0].addr, 0x1000);
        assert_eq!(descs[0].len, (NET_HDR_SIZE + 14) as u32);
        assert_eq!(descs[0].flags, DESC_F_NEXT);
        assert_eq!(descs[0].next, 1);
        assert_eq!(descs[1].addr, 0x1000 + NET_HDR_SIZE as u64);
        assert_eq!(descs[1].len, 14);
        assert_eq!(
            descs[1].flags, 0,
            "the payload descriptor is device-readable"
        );
        assert_eq!(descs[1].next, 0);
        // The two descriptors must describe the whole bounce payload exactly.
        assert_eq!(
            descs[1].addr + descs[1].len as u64,
            0x1000 + (NET_HDR_SIZE + 14) as u64
        );

        assert_eq!(tx_descriptors(0x1000, 13), Err(NetIoError::BadLength));
        assert_eq!(tx_descriptors(0x1000, 1515), Err(NetIoError::BadLength));
        assert!(tx_descriptors(0x1000, 1514).is_ok());
    }

    #[test]
    fn rx_descriptor_is_device_writable() {
        let desc = rx_descriptor(0x2000);
        assert_eq!(desc.addr, 0x2000);
        assert_eq!(desc.len, NET_RX_BUFFER_SIZE as u32);
        assert_eq!(desc.flags, DESC_F_WRITE);
        assert_eq!(desc.next, 0);
    }

    #[test]
    fn rx_classification_drops_short_and_oversized_packets() {
        assert_eq!(classify_rx(0), RxOutcome::Short);
        assert_eq!(classify_rx((NET_HDR_SIZE + 13) as u32), RxOutcome::Short);
        assert_eq!(
            classify_rx((NET_HDR_SIZE + 14) as u32),
            RxOutcome::Frame {
                offset: NET_HDR_SIZE,
                len: 14
            }
        );
        assert_eq!(
            classify_rx((NET_HDR_SIZE + NET_MAX_FRAME) as u32),
            RxOutcome::Frame {
                offset: NET_HDR_SIZE,
                len: NET_MAX_FRAME
            }
        );
        assert_eq!(
            classify_rx((NET_HDR_SIZE + NET_MAX_FRAME + 1) as u32),
            RxOutcome::TooLong
        );
    }

    #[test]
    fn rx_ring_preserves_fifo_order_and_reports_overrun() {
        let mut ring = RxRing::new();
        assert!(ring.is_empty());
        assert_eq!(ring.pop(&mut [0u8; 32]), Err(NetIoError::NotReady));

        let first = [0x11u8; 20];
        let second = [0x22u8; 20];
        assert!(ring.push(&first));
        assert!(ring.push(&second));
        assert_eq!(ring.len(), 2);

        let mut out = [0u8; 32];
        assert_eq!(ring.pop(&mut out), Ok(20));
        assert_eq!(&out[..20], &first);
        assert_eq!(ring.pop(&mut out), Ok(20));
        assert_eq!(&out[..20], &second);

        // Fill to capacity, then one more frame is dropped instead of overwriting.
        for _ in 0..VIRTIO_NET_RX_RING {
            assert!(ring.push(&first));
        }
        assert_eq!(ring.len(), VIRTIO_NET_RX_RING);
        assert!(!ring.push(&second));
        assert_eq!(ring.len(), VIRTIO_NET_RX_RING);

        // A short output buffer keeps the frame queued.
        let mut tiny = [0u8; 4];
        assert_eq!(ring.pop(&mut tiny), Err(NetIoError::BufferTooSmall));
        assert_eq!(ring.len(), VIRTIO_NET_RX_RING);
        let mut big = [0u8; NET_MAX_FRAME];
        assert_eq!(ring.pop(&mut big), Ok(20));
    }

    #[test]
    fn tx_completion_is_reclaimed_exactly_once() {
        assert_eq!(classify_tx_completion(true, 0), TxOutcome::Reclaimed);
        assert_eq!(
            classify_tx_completion(false, 0),
            TxOutcome::Unexpected,
            "a duplicate completion has nothing to reclaim"
        );
        assert_eq!(
            classify_tx_completion(true, 3),
            TxOutcome::Unexpected,
            "a completion for a descriptor the driver never posted is not ours"
        );
    }

    #[test]
    fn vector_and_budget_do_not_collide_with_other_irq_users() {
        assert_eq!(VIRTIO_NET_IRQ_VECTOR, 0x42);
        assert_ne!(VIRTIO_NET_IRQ_VECTOR, platform::TIMER_VECTOR);
        assert_ne!(VIRTIO_NET_IRQ_VECTOR, platform::KEYBOARD_VECTOR);
        assert_ne!(VIRTIO_NET_IRQ_VECTOR, platform::SERIAL_VECTOR);
        assert_ne!(VIRTIO_NET_IRQ_VECTOR, platform::RESCHEDULE_VECTOR);
        assert_eq!(super::super::dma_frames_per_net_device(), 11);
    }

    #[test]
    fn error_names_are_stable() {
        assert_eq!(NetIoError::NotReady.as_str(), "not-ready");
        assert_eq!(NetIoError::BadLength.as_str(), "bad-length");
        assert_eq!(NetIoError::WouldBlock.as_str(), "would-block");
        assert_eq!(NetIoError::BufferTooSmall.as_str(), "buffer-too-small");
        assert_eq!(NetIoError::Unsupported.as_str(), "unsupported");
        assert_eq!(NetIoError::Corrupted.as_str(), "corrupted");
        assert_eq!(NetIoError::NoDevice.as_str(), "no-device");
        assert_eq!(
            NetProbeError::NotFound.as_str(),
            "virtio-net: no legacy (0x1000) network device found"
        );
        assert_eq!(
            NetProbeError::ModernOnly.as_str(),
            "virtio-net: only a modern (0x1041) function is present; the legacy 0x1000 interface is required"
        );
        assert_eq!(NetProbeError::Failed("boom").as_str(), "boom");
    }

    #[test]
    fn handles_are_absent_before_init() {
        assert_eq!(device_count(), 0);
        assert_eq!(VirtioNet::handle(), None);
        assert_eq!(mac(), None);
        assert_eq!(link_status(), None);
        assert_eq!(irq_count(), 0);
        assert_eq!(rx_count(), 0);
        assert_eq!(tx_count(), 0);
        assert_eq!(on_irq(), 0);
        let handle = VirtioNet { index: 0 };
        assert!(!handle.ready());
        assert_eq!(handle.rx_len(), None);
        assert_eq!(
            handle.send_frame(&[0u8; 60]),
            Err(NetIoError::NoDevice),
            "no device may mean no MMIO access"
        );
        assert_eq!(handle.pop_frame(&mut [0u8; 64]), Err(NetIoError::NoDevice));
    }
}
