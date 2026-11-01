//! Pure, host-testable pieces of the legacy (virtio 0.9.5) block queue.
//!
//! This module deliberately contains **no port I/O and no hardware access**:
//! everything here is layout arithmetic and request encoding, so it can be
//! unit-tested on the host without a device. [`super::virtio_blk`] is the only
//! module that touches the device.
//!
//! # Legacy queue memory layout
//!
//! A legacy virtqueue lives in one contiguous, page-aligned physical range:
//!
//! ```text
//! offset 0                     descriptor table: queue_size * 16 bytes
//! offset desc_end              available ring:   2 + 2 + 2 * queue_size bytes
//! offset align_up(avail_end)   used ring:        2 + 2 + 8 * queue_size bytes
//! ```
//!
//! The used ring must start on a 4096-byte boundary ([`QUEUE_ALIGN`]). The
//! legacy queue sizes differ per device class: `virtio-blk` reports 128, whose
//! queue ends at 5124 bytes (two frames: descriptors 0..2048, avail
//! 2048..2308, used 4096..5124), while QEMU's `virtio-net` reports 256 (its
//! `rx_queue_size`/`tx_queue_size` minimum is 256), whose queue ends at 10244
//! bytes (three frames: descriptors 0..4096, avail 4096..4612, used
//! 8192..10244). Callers budget the frames for the size they accept, which is
//! why the block queue uses two frames and the net queues use three.
//!
//! # Requests
//!
//! One request is in flight at a time (the driver is synchronous), so the three
//! descriptors are used at fixed indices: 0 = request header (device-readable),
//! 1 = data buffer (device-readable for writes, device-writable for reads),
//! 2 = status byte (device-writable). Flush and barrier requests have no data
//! descriptor; their chain is 0 -> 2.
//!
//! All request payloads are staged in the driver's single 4 KiB bounce frame:
//! a 16-byte header at offset 0, the data at offset 16 and the status byte at
//! offset 4095. That leaves `BOUNCE_SIZE - REQ_HEADER_SIZE - 1` bytes for data,
//! rounded down to whole 512-byte sectors ([`MAX_DATA_CHUNK`] = 3584 = 7
//! sectors), so larger buffers are split into several requests.

use block::BlockError;
use core::sync::atomic::{Ordering, fence};

/// Size of one legacy virtio descriptor.
pub const DESC_SIZE: usize = 16;
/// Bytes before the available ring's `ring` array: `vring_avail { flags: u16,
/// idx: u16 }`.
pub const AVAIL_HEADER_SIZE: usize = 4;
/// Bytes before the used ring's `ring` array: `vring_used { flags: u16,
/// idx: u16 }`.
pub const USED_HEADER_SIZE: usize = 4;
/// Size of one used-ring element (`id: u32, len: u32`).
pub const USED_ELEM_SIZE: usize = 8;
/// Legacy queues must align the used ring to 4096 bytes.
pub const QUEUE_ALIGN: usize = 4096;
/// Smallest legacy queue size this driver can drive (2 data + status descriptors).
pub const MIN_QUEUE_SIZE: u16 = 8;
/// Largest legacy queue size the layout accepts (QEMU's virtio-net reports
/// 256). A 256-descriptor queue needs three frames because the used ring stays
/// 4096-byte aligned; see the module documentation.
pub const MAX_QUEUE_SIZE: u16 = 256;
/// Bytes of the per-device bounce frame.
pub const BOUNCE_SIZE: usize = 4096;
/// Bytes of a `virtio_blk_req` header (`type, reserved, sector`).
pub const REQ_HEADER_SIZE: usize = 16;
/// Offset of the data payload inside the bounce frame.
pub const DATA_OFFSET: usize = REQ_HEADER_SIZE;
/// Offset of the status byte inside the bounce frame.
pub const STATUS_OFFSET: usize = BOUNCE_SIZE - 1;
/// Largest data payload in one request: whole sectors that fit after the
/// 16-byte header and before the status byte (7 * 512 = 3584).
pub const MAX_DATA_CHUNK: usize = ((BOUNCE_SIZE - REQ_HEADER_SIZE - 1) / 512) * 512;

/// Descriptor flag: the next field links to another descriptor.
pub const DESC_F_NEXT: u16 = 0x0001;
/// Descriptor flag: device-writable buffer (read from the device's perspective).
pub const DESC_F_WRITE: u16 = 0x0002;

/// A request header that carries data (`IN` = read, `OUT` = write).
pub const REQ_IN: u32 = 0;
/// A write request (guest -> device).
pub const REQ_OUT: u32 = 1;
/// A flush request (no data).
pub const REQ_FLUSH: u32 = 4;

/// Value the driver pre-fills into the status byte: only a real device write can
/// change it, so a completion never reads a stale `STATUS_OK`.
pub const STATUS_INIT: u8 = 0xFF;
/// Device completed the request successfully.
pub const STATUS_OK: u8 = 0;
/// Device reported an I/O error.
pub const STATUS_IOERR: u8 = 1;
/// Device does not support the request.
pub const STATUS_UNSUPP: u8 = 2;

/// Why a queue size or a planned request does not fit the driver's budget.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QueueError {
    /// `queue_size` is outside `MIN_QUEUE_SIZE..=MAX_QUEUE_SIZE`.
    BadQueueSize,
    /// A data payload is not a whole number of sectors or exceeds
    /// [`MAX_DATA_CHUNK`].
    BadDataLength,
    /// The used ring advanced by more than the single completion expected for
    /// one outstanding request.
    UsedRingOverrun,
}

/// Wire-format descriptor (little-endian in memory).
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Desc {
    /// Physical address of the buffer the device reads or writes.
    pub addr: u64,
    /// Length of the buffer in bytes.
    pub len: u32,
    /// [`DESC_F_NEXT`] / [`DESC_F_WRITE`] bits.
    pub flags: u16,
    /// Index of the next descriptor when [`DESC_F_NEXT`] is set.
    pub next: u16,
}

/// `virtio_blk_req` header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RequestHeader {
    /// [`REQ_IN`], [`REQ_OUT`] or [`REQ_FLUSH`].
    pub kind: u32,
    /// Must be zero.
    pub reserved: u32,
    /// First 512-byte sector (ignored by flush).
    pub sector: u64,
}

/// Computed offsets inside the queue's physical range.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QueueLayout {
    /// Device-reported queue size.
    pub queue_size: u16,
    /// Offset of the descriptor table (always 0).
    pub desc_offset: usize,
    /// Offset of the available ring.
    pub avail_offset: usize,
    /// Offset of the used ring (4096-aligned).
    pub used_offset: usize,
    /// End offset of the used ring; must fit the DMA budget.
    pub end: usize,
}

impl QueueLayout {
    /// Compute the legacy layout for `queue_size`, rejecting sizes outside
    /// `MIN_QUEUE_SIZE..=MAX_QUEUE_SIZE`. Whether `end` fits is the caller's
    /// frame-budget decision (two frames for the block queue, three for a
    /// 256-descriptor net queue).
    pub const fn new(queue_size: u16) -> Result<Self, QueueError> {
        if queue_size < MIN_QUEUE_SIZE || queue_size > MAX_QUEUE_SIZE {
            return Err(QueueError::BadQueueSize);
        }
        let size = queue_size as usize;
        let desc_offset = 0;
        let avail_offset = desc_offset + size * DESC_SIZE;
        let used_offset = align_up(avail_offset + AVAIL_HEADER_SIZE + 2 * size, QUEUE_ALIGN);
        let end = used_offset + USED_HEADER_SIZE + USED_ELEM_SIZE * size;
        Ok(Self {
            queue_size,
            desc_offset,
            avail_offset,
            used_offset,
            end,
        })
    }

    /// Number of bytes the queue occupies (`end` rounded up to pages by the
    /// caller; the caller then checks it against its own frame budget).
    pub const fn bytes(&self) -> usize {
        self.end
    }
}

/// Round `value` up to a multiple of `align` (a power of two).
pub const fn align_up(value: usize, align: usize) -> usize {
    value.div_ceil(align) * align
}

/// Encode a descriptor exactly as the device reads it.
pub fn encode_desc(desc: &Desc) -> [u8; DESC_SIZE] {
    let mut bytes = [0u8; DESC_SIZE];
    bytes[0..8].copy_from_slice(&desc.addr.to_le_bytes());
    bytes[8..12].copy_from_slice(&desc.len.to_le_bytes());
    bytes[12..14].copy_from_slice(&desc.flags.to_le_bytes());
    bytes[14..16].copy_from_slice(&desc.next.to_le_bytes());
    bytes
}

/// Encode a request header for the bounce frame.
pub fn encode_header(header: &RequestHeader) -> [u8; REQ_HEADER_SIZE] {
    let mut bytes = [0u8; REQ_HEADER_SIZE];
    bytes[0..4].copy_from_slice(&header.kind.to_le_bytes());
    bytes[4..8].copy_from_slice(&header.reserved.to_le_bytes());
    bytes[8..16].copy_from_slice(&header.sector.to_le_bytes());
    bytes
}

/// Write descriptor `index` into a descriptor table at `table + desc_offset`.
///
/// # Safety
///
/// `table` must point at at least `desc_offset + (index + 1) * DESC_SIZE` bytes
/// of queue memory that is not concurrently used by the device.
pub unsafe fn write_desc(table: *mut u8, desc_offset: usize, index: usize, desc: &Desc) {
    let target = unsafe { table.add(desc_offset + index * DESC_SIZE) };
    let bytes = encode_desc(desc);
    unsafe { core::ptr::copy_nonoverlapping(bytes.as_ptr(), target, DESC_SIZE) };
}

/// Publish `head` as the next available entry and return the new avail index.
///
/// # Safety
///
/// `queue` must point at the queue memory described by `layout`, and the caller
/// must hold the device lock/interrupt guard.
pub unsafe fn push_avail(queue: *mut u8, layout: &QueueLayout, head: u16) -> u16 {
    let avail = unsafe { queue.add(layout.avail_offset) };
    let idx_ptr = unsafe { avail.add(2) } as *mut u16;
    // The device owns `idx`; read it with a volatile load and republish only
    // after the ring slot is visible.
    let idx = unsafe { core::ptr::read_volatile(idx_ptr) };
    let slot = (idx as usize) % layout.queue_size as usize;
    let ring_ptr = unsafe { avail.add(AVAIL_HEADER_SIZE + 2 * slot) } as *mut u16;
    fence(Ordering::SeqCst);
    unsafe { core::ptr::write_volatile(ring_ptr, head) };
    fence(Ordering::SeqCst);
    let next = idx.wrapping_add(1);
    unsafe { core::ptr::write_volatile(idx_ptr, next) };
    fence(Ordering::SeqCst);
    next
}

/// Read the used ring's published index.
///
/// # Safety
///
/// Same requirements as [`push_avail`].
pub unsafe fn used_index(queue: *mut u8, layout: &QueueLayout) -> u16 {
    let used = unsafe { queue.add(layout.used_offset) };
    unsafe { core::ptr::read_volatile(used.add(2) as *const u16) }
}

/// Result of comparing the used index against the value observed before submit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Completion {
    /// The device has not published this request yet.
    Pending,
    /// The device published exactly this request; `slot` is the used-ring slot.
    Done { slot: u16 },
}

/// Decide whether one outstanding request has completed, exactly once.
pub fn completion(before: u16, now: u16, queue_size: u16) -> Result<Completion, QueueError> {
    match now.wrapping_sub(before) {
        0 => Ok(Completion::Pending),
        1 => Ok(Completion::Done {
            slot: before % queue_size,
        }),
        _ => Err(QueueError::UsedRingOverrun),
    }
}

/// Read used-ring element `slot` as `(descriptor_head, bytes_written)`.
///
/// # Safety
///
/// Same requirements as [`push_avail`]; `slot` must be the value returned by
/// [`completion`].
pub unsafe fn used_element(queue: *mut u8, layout: &QueueLayout, slot: u16) -> (u32, u32) {
    let elem = unsafe {
        queue.add(layout.used_offset + USED_HEADER_SIZE + USED_ELEM_SIZE * slot as usize)
    };
    let id = unsafe { core::ptr::read_volatile(elem as *const u32) };
    let len = unsafe { core::ptr::read_volatile(elem.add(4) as *const u32) };
    (id, len)
}

/// Translate the device status byte into the block layer's vocabulary.
pub fn status_to_result(status: u8) -> Result<(), BlockError> {
    match status {
        STATUS_OK => Ok(()),
        STATUS_IOERR => Err(BlockError::Io),
        STATUS_UNSUPP => Err(BlockError::Unsupported),
        _ => Err(BlockError::Io),
    }
}

/// Combine the two 32-bit config reads of the legacy capacity field into u64.
pub const fn capacity_from_registers(low: u32, high: u32) -> u64 {
    ((high as u64) << 32) | (low as u64)
}

/// Length of the next data chunk for `remaining` bytes of a validated buffer.
///
/// `remaining` must be a whole number of 512-byte sectors; the result is too,
/// and never exceeds [`MAX_DATA_CHUNK`].
pub const fn chunk_len(remaining: usize) -> usize {
    if remaining < MAX_DATA_CHUNK {
        remaining
    } else {
        MAX_DATA_CHUNK
    }
}

/// Validate a request against the block contract before any hardware access.
///
/// Returns the number of 512-byte sectors the buffer covers.
pub fn validate_request(first: u64, buf_len: usize, block_count: u64) -> Result<u64, BlockError> {
    let sectors = block::check_buffer(buf_len, 512)?;
    block::check_range(first, sectors, block_count)?;
    Ok(sectors)
}

/// Planned descriptor chain for one request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RequestPlan {
    descs: [Desc; 3],
    desc_count: usize,
}

impl RequestPlan {
    /// Descriptors in chain order.
    pub fn descs(&self) -> &[Desc] {
        &self.descs[..self.desc_count]
    }

    /// Number of descriptors in the chain.
    pub fn len(&self) -> usize {
        self.desc_count
    }

    /// Index of the chain head (always 0 for this driver).
    pub const fn head(&self) -> u16 {
        0
    }
}

/// Plan a request that carries `data_len` bytes through the bounce frame.
///
/// `bounce_phys` is the physical address of the driver's bounce frame; it is
/// mapped into the kernel through the direct map for the CPU side.
pub fn plan_data_request(
    kind: u32,
    bounce_phys: u64,
    data_len: usize,
) -> Result<RequestPlan, QueueError> {
    if kind != REQ_IN && kind != REQ_OUT {
        return Err(QueueError::BadDataLength);
    }
    if data_len == 0
        || data_len > MAX_DATA_CHUNK
        || !data_len.is_multiple_of(512)
        || DATA_OFFSET + data_len > STATUS_OFFSET
    {
        return Err(QueueError::BadDataLength);
    }
    let data_flags = if kind == REQ_IN {
        DESC_F_NEXT | DESC_F_WRITE
    } else {
        DESC_F_NEXT
    };
    let descs = [
        Desc {
            addr: bounce_phys,
            len: REQ_HEADER_SIZE as u32,
            flags: DESC_F_NEXT,
            next: 1,
        },
        Desc {
            addr: bounce_phys + DATA_OFFSET as u64,
            len: data_len as u32,
            flags: data_flags,
            next: 2,
        },
        Desc {
            addr: bounce_phys + STATUS_OFFSET as u64,
            len: 1,
            flags: DESC_F_WRITE,
            next: 0,
        },
    ];
    Ok(RequestPlan {
        descs,
        desc_count: 3,
    })
}

/// Plan a flush request: header -> status, no data descriptor.
pub fn plan_flush(bounce_phys: u64) -> RequestPlan {
    let descs = [
        Desc {
            addr: bounce_phys,
            len: REQ_HEADER_SIZE as u32,
            flags: DESC_F_NEXT,
            next: 1,
        },
        Desc {
            addr: bounce_phys + STATUS_OFFSET as u64,
            len: 1,
            flags: DESC_F_WRITE,
            next: 0,
        },
        Desc::default(),
    ];
    RequestPlan {
        descs,
        desc_count: 2,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn queue_layout_matches_the_legacy_two_frame_budget() {
        // virtio 0.9.5: `vring_avail`/`vring_used` headers are
        // `flags: u16 + idx: u16` = 4 bytes, not 6.
        assert_eq!(AVAIL_HEADER_SIZE, 4);
        assert_eq!(USED_HEADER_SIZE, 4);
        let layout = QueueLayout::new(128).unwrap();
        assert_eq!(layout.desc_offset, 0);
        assert_eq!(layout.avail_offset, 128 * 16);
        assert_eq!(layout.avail_offset, 2048);
        assert_eq!(layout.used_offset, 4096);
        assert_eq!(layout.used_offset % QUEUE_ALIGN, 0);
        assert_eq!(layout.end, 4096 + 4 + 8 * 128);
        assert_eq!(layout.end, 5124);
        assert!(
            layout.end <= 2 * BOUNCE_SIZE,
            "must fit the two-frame budget"
        );
        assert_eq!(layout.bytes(), 5124);
    }

    #[test]
    fn a_256_descriptor_net_queue_needs_three_frames() {
        // QEMU's legacy virtio-net reports 256 descriptors (`rx_queue_size` and
        // `tx_queue_size` cannot be 128 there). The used ring must still start
        // on a 4096-byte boundary, so the queue ends at 10244 bytes.
        let layout = QueueLayout::new(256).unwrap();
        assert_eq!(layout.avail_offset, 4096);
        assert_eq!(layout.used_offset, 8192);
        assert_eq!(layout.used_offset % QUEUE_ALIGN, 0);
        assert_eq!(layout.end, 8192 + 4 + 8 * 256);
        assert_eq!(layout.end, 10_244);
        assert!(
            layout.end > 2 * BOUNCE_SIZE,
            "two frames cannot hold a 256-descriptor ring"
        );
        assert!(
            layout.end <= 3 * BOUNCE_SIZE,
            "three frames hold the 256-descriptor net queue"
        );
    }

    // The real queue starts at a page boundary; mirror that alignment in host
    // tests so the volatile u16/u32 ring accesses stay aligned.
    #[repr(align(4096))]
    struct AlignedQueue([u8; 2 * BOUNCE_SIZE]);

    #[test]
    fn used_ring_header_and_elements_sit_at_their_spec_offsets() {
        let layout = QueueLayout::new(128).unwrap();
        let mut queue = AlignedQueue([0u8; 2 * BOUNCE_SIZE]);
        let base = queue.0.as_mut_ptr();
        let used = layout.used_offset;
        // Hand-write the spec layout: flags at used+0, idx at used+2, then the
        // first element at used+4 (id at +0, len at +4).
        let id = 0xDEAD_BEEFu32;
        let len = 0x0000_0200u32;
        queue.0[used..used + 2].copy_from_slice(&0x0001u16.to_le_bytes());
        queue.0[used + 2..used + 4].copy_from_slice(&1u16.to_le_bytes());
        queue.0[used + 4..used + 8].copy_from_slice(&id.to_le_bytes());
        queue.0[used + 8..used + 12].copy_from_slice(&len.to_le_bytes());

        // SAFETY: `queue` is a local buffer that outlives the calls and the
        // layout describes it.
        unsafe {
            assert_eq!(used_index(base, &layout), 1);
            assert_eq!(used_element(base, &layout, 0), (id, len));
        }
        // The element must start right after the 4-byte header, never at +6.
        assert_eq!(
            layout.used_offset + USED_HEADER_SIZE,
            layout.used_offset + 4
        );
    }

    #[test]
    fn push_avail_writes_the_ring_slot_after_the_four_byte_header() {
        let layout = QueueLayout::new(128).unwrap();
        let mut queue = AlignedQueue([0u8; 2 * BOUNCE_SIZE]);
        let base = queue.0.as_mut_ptr();
        let avail = layout.avail_offset;

        // SAFETY: local buffer + matching layout; single-threaded test.
        unsafe {
            assert_eq!(push_avail(base, &layout, 7), 1);
            assert_eq!(push_avail(base, &layout, 9), 2);
        }

        let u16_at = |offset: usize| u16::from_le_bytes([queue.0[offset], queue.0[offset + 1]]);
        assert_eq!(u16_at(avail), 0, "flags stay zero");
        assert_eq!(u16_at(avail + 2), 2, "published avail index");
        // Ring slot `n` starts at avail + 4 + 2 * n.
        assert_eq!(u16_at(avail + AVAIL_HEADER_SIZE), 7);
        assert_eq!(u16_at(avail + AVAIL_HEADER_SIZE + 2), 9);
    }

    #[test]
    fn queue_layout_rejects_sizes_outside_the_budget() {
        assert_eq!(QueueLayout::new(0).unwrap_err(), QueueError::BadQueueSize);
        assert_eq!(QueueLayout::new(7).unwrap_err(), QueueError::BadQueueSize);
        assert!(QueueLayout::new(MIN_QUEUE_SIZE).is_ok());
        assert!(QueueLayout::new(MAX_QUEUE_SIZE).is_ok());
        assert_eq!(
            QueueLayout::new(MAX_QUEUE_SIZE + 1).unwrap_err(),
            QueueError::BadQueueSize
        );
        for size in [16u16, 32, 64, 128] {
            let layout = QueueLayout::new(size).unwrap();
            assert!(
                layout.end <= 2 * BOUNCE_SIZE,
                "queue size {size} needs {} bytes",
                layout.end
            );
        }
    }

    #[test]
    fn descriptor_is_sixteen_bytes_little_endian() {
        assert_eq!(core::mem::size_of::<Desc>(), DESC_SIZE);
        let desc = Desc {
            addr: 0x1122_3344_5566_7788,
            len: 0x0102_0304,
            flags: 0x0506,
            next: 0x0708,
        };
        let bytes = encode_desc(&desc);
        assert_eq!(&bytes[0..8], &0x1122_3344_5566_7788u64.to_le_bytes());
        assert_eq!(&bytes[8..12], &0x0102_0304u32.to_le_bytes());
        assert_eq!(&bytes[12..14], &0x0506u16.to_le_bytes());
        assert_eq!(&bytes[14..16], &0x0708u16.to_le_bytes());

        let mut table = [0u8; DESC_SIZE * 3];
        // SAFETY: writes stay inside the local table.
        unsafe { write_desc(table.as_mut_ptr(), 0, 1, &desc) };
        assert_eq!(&table[DESC_SIZE..2 * DESC_SIZE], &bytes[..]);
        assert_eq!(&table[0..DESC_SIZE], &[0u8; DESC_SIZE]);
    }

    #[test]
    fn request_header_encodes_type_and_sector() {
        let header = RequestHeader {
            kind: REQ_OUT,
            reserved: 0,
            sector: 0x0011_2233_4455_6677,
        };
        let bytes = encode_header(&header);
        assert_eq!(&bytes[0..4], &1u32.to_le_bytes());
        assert_eq!(&bytes[4..8], &0u32.to_le_bytes());
        assert_eq!(&bytes[8..16], &0x0011_2233_4455_6677u64.to_le_bytes());
        let flush = encode_header(&RequestHeader {
            kind: REQ_FLUSH,
            reserved: 0,
            sector: 0,
        });
        assert_eq!(&flush[0..4], &4u32.to_le_bytes());
        assert_eq!(REQ_HEADER_SIZE, 16);
    }

    #[test]
    fn read_request_marks_the_data_buffer_writable() {
        let bounce = 0x1234_5000u64;
        let plan = plan_data_request(REQ_IN, bounce, 3584).unwrap();
        assert_eq!(plan.len(), 3);
        assert_eq!(plan.head(), 0);
        let descs = plan.descs();
        assert_eq!(descs[0].addr, bounce);
        assert_eq!(descs[0].len, 16);
        assert_eq!(descs[0].flags, DESC_F_NEXT);
        assert_eq!(descs[0].next, 1);
        assert_eq!(descs[1].addr, bounce + DATA_OFFSET as u64);
        assert_eq!(descs[1].len, 3584);
        assert_eq!(descs[1].flags, DESC_F_NEXT | DESC_F_WRITE);
        assert_eq!(descs[1].next, 2);
        assert_eq!(descs[2].addr, bounce + STATUS_OFFSET as u64);
        assert_eq!(descs[2].len, 1);
        assert_eq!(descs[2].flags, DESC_F_WRITE);
        assert_eq!(descs[2].next, 0);
    }

    #[test]
    fn write_request_marks_the_data_buffer_readable() {
        let plan = plan_data_request(REQ_OUT, 0x1000, 512).unwrap();
        let descs = plan.descs();
        assert_eq!(descs[1].flags, DESC_F_NEXT);
        assert_eq!(descs[1].addr, 0x1000 + DATA_OFFSET as u64);
        assert_eq!(descs[1].len, 512);
        assert_eq!(descs[2].flags, DESC_F_WRITE, "the status byte is writable");
    }

    #[test]
    fn flush_request_has_no_data_descriptor() {
        let plan = plan_flush(0x2000);
        assert_eq!(plan.len(), 2);
        let descs = plan.descs();
        assert_eq!(descs[0].addr, 0x2000);
        assert_eq!(descs[0].len, REQ_HEADER_SIZE as u32);
        assert_eq!(descs[0].flags, DESC_F_NEXT);
        assert_eq!(descs[0].next, 1);
        assert_eq!(descs[1].addr, 0x2000 + STATUS_OFFSET as u64);
        assert_eq!(descs[1].flags, DESC_F_WRITE);
        assert_eq!(descs[1].next, 0);
    }

    #[test]
    fn request_planner_rejects_unrepresentable_payloads() {
        let bounce = 0x3000;
        assert_eq!(
            plan_data_request(REQ_IN, bounce, 0).unwrap_err(),
            QueueError::BadDataLength
        );
        assert_eq!(
            plan_data_request(REQ_IN, bounce, 100).unwrap_err(),
            QueueError::BadDataLength
        );
        assert_eq!(
            plan_data_request(REQ_IN, bounce, MAX_DATA_CHUNK + 512).unwrap_err(),
            QueueError::BadDataLength
        );
        assert_eq!(
            plan_data_request(REQ_FLUSH, bounce, 512).unwrap_err(),
            QueueError::BadDataLength
        );
        assert!(plan_data_request(REQ_IN, bounce, MAX_DATA_CHUNK).is_ok());
        assert_eq!(DATA_OFFSET + MAX_DATA_CHUNK, 3600);
        assert!(STATUS_OFFSET >= DATA_OFFSET + MAX_DATA_CHUNK);
    }

    #[test]
    fn chunk_splitting_covers_any_whole_sector_buffer() {
        assert_eq!(chunk_len(512), 512);
        assert_eq!(chunk_len(1536), 1536);
        assert_eq!(chunk_len(3584), 3584);
        assert_eq!(chunk_len(4096), 3584);
        assert_eq!(chunk_len(8192), 3584);

        for sectors in 1..=32usize {
            let total = sectors * 512;
            let mut remaining = total;
            let mut chunks = 0;
            while remaining > 0 {
                let chunk = chunk_len(remaining);
                assert!(chunk > 0);
                assert!(
                    chunk.is_multiple_of(512),
                    "chunk {chunk} is not sector aligned"
                );
                assert!(chunk <= MAX_DATA_CHUNK);
                assert!(chunk <= remaining);
                remaining -= chunk;
                chunks += 1;
            }
            assert!(chunks >= 1, "{total} bytes produced no chunk");
        }
        let mut remaining = 8 * 512;
        let mut sizes = [0usize; 4];
        let mut chunks = 0;
        while remaining > 0 && chunks < sizes.len() {
            sizes[chunks] = chunk_len(remaining);
            remaining -= sizes[chunks];
            chunks += 1;
        }
        assert_eq!(&sizes[..chunks], &[3584, 512]);
    }

    #[test]
    fn status_byte_maps_to_block_errors() {
        assert_eq!(status_to_result(STATUS_OK), Ok(()));
        assert_eq!(status_to_result(STATUS_IOERR), Err(BlockError::Io));
        assert_eq!(
            status_to_result(STATUS_UNSUPP),
            Err(BlockError::Unsupported)
        );
        assert_eq!(status_to_result(0x7F), Err(BlockError::Io));
        assert_eq!(STATUS_INIT, 0xFF, "status starts un-written");
    }

    #[test]
    fn used_ring_completion_is_exactly_once() {
        assert_eq!(completion(0, 0, 128), Ok(Completion::Pending));
        assert_eq!(completion(0, 1, 128), Ok(Completion::Done { slot: 0 }));
        assert_eq!(
            completion(127, 128, 128),
            Ok(Completion::Done { slot: 127 })
        );
        assert_eq!(
            completion(128, 129, 128),
            Ok(Completion::Done { slot: 0 }),
            "slot wraps around the queue size"
        );
        assert_eq!(
            completion(u16::MAX, 0, 128),
            Ok(Completion::Done { slot: 127 })
        );
        assert_eq!(
            completion(0, 2, 128),
            Err(QueueError::UsedRingOverrun),
            "two completions for one request is corruption, not progress"
        );
    }

    #[test]
    fn capacity_register_pair_is_little_endian_u64() {
        assert_eq!(capacity_from_registers(0x0000_0400, 0), 1024);
        assert_eq!(
            capacity_from_registers(0, 1),
            0x0000_0001_0000_0000,
            "high word shifts up 32 bits"
        );
        assert_eq!(capacity_from_registers(0xFFFF_FFFF, 0xFFFF_FFFF), u64::MAX);
    }

    #[test]
    fn request_validation_rejects_bad_buffers_and_ranges() {
        assert_eq!(
            validate_request(0, 0, 1024),
            Err(BlockError::BadBuffer),
            "empty buffer"
        );
        assert_eq!(
            validate_request(0, 100, 1024),
            Err(BlockError::BadBuffer),
            "not a whole sector"
        );
        assert_eq!(
            validate_request(1024, 512, 1024),
            Err(BlockError::OutOfBounds)
        );
        assert_eq!(
            validate_request(u64::MAX, 512, u64::MAX),
            Err(BlockError::OutOfBounds)
        );
        assert_eq!(validate_request(0, 4096, 1024), Ok(8));
    }
}
