//! M6c GOP framebuffer base: map the firmware framebuffer and push a small
//! user-supplied shadow surface into it.
//!
//! This is deliberately **not** a graphics stack. It owns exactly three jobs:
//!
//! 1. [`init`] copies the boot-time GOP description out of the saved boot state,
//!    validates it strictly, and maps the real linear framebuffer into the
//!    dedicated, uncached window (`platform::FB_WINDOW_BASE`). The mapping is
//!    permanent: there is one display device and no mode switching in M6c.
//! 2. [`probe`] writes a single magenta pixel into the **actual** framebuffer at
//!    its bottom-right corner, so a host-side screendump can prove that the
//!    kernel really reached the physical scanout buffer rather than a shadow.
//! 3. [`present`] blits a fixed 320x200x32 surface from the caller's shadow
//!    frames to framebuffer coordinates `(0, 0)`, honouring the real scanline
//!    stride and the real pixel byte order.
//!
//! # Who owns the shadow frames
//!
//! The 64 physical frames that back the shadow surface belong to the object
//! layer (`ipc::display`, M6c slice C2): it allocates them, exposes their
//! physical addresses, and frees them when the display object is destroyed.
//! This module never allocates or frees frames; it only *reads* them through
//! the direct map. That keeps ownership (and the `live_frames == 0` invariant)
//! in one place, and it means a stale frame number can never leak memory here.
//!
//! # Why the framebuffer is mapped as device memory
//!
//! The GOP framebuffer is MMIO-like: writes can be reordered and cached
//! traffic can be lost, so the mapping uses `PWT | PCD` (PAT is not part of the
//! M2 takeover) and every access inside this module is a volatile access. The
//! shadow frames, by contrast, are ordinary cached RAM read through the M2
//! direct map.
//!
//! # Failure policy
//!
//! Every entry point returns a static reason instead of panicking. Missing GOP
//! support is a **loud** failure at M6c init (`display-no-framebuffer`) rather
//! than a silent no-op: the acceptance run has to notice a loader that forgot
//! the `FB_GOP` TLV.

use core::ptr;

use crate::boot::SavedFramebuffer;
use crate::mm::vm;
use crate::platform;

/// Width of the surface M6c presents, in pixels.
pub const SURFACE_WIDTH: u32 = 320;
/// Height of the surface M6c presents, in pixels.
pub const SURFACE_HEIGHT: u32 = 200;
/// Physical frames backing the shadow surface (64 * 4 KiB = 256 KiB, which is
/// exactly what 320x200x4 bytes needs: 256000 <= 262144).
pub const SURFACE_FRAMES: usize = 64;
/// Bytes of the shadow surface actually used: 320 * 200 * 4.
pub const SURFACE_BYTES: u64 = SURFACE_WIDTH as u64 * SURFACE_HEIGHT as u64 * 4;

/// Shadow pixel layout: `0x00RRGGBB` (red in bits 16..24, green 8..16, blue 0..8).
const SHADOW_MASK: u32 = 0x00FF_FFFF;

const PAGE: u64 = 4096;
const BYTES_PER_PIXEL: u64 = 4;
/// Physical frames are page-aligned addresses below the PMM's 1 GiB ceiling.
const MAX_FRAME_PHYS: u64 = 1 << 30;

/// `EFI_GRAPHICS_PIXEL_FORMAT::PixelRedGreenBlueReserved8BitPerColor`.
pub const PIXEL_FORMAT_RGBX: u32 = 0;
/// `EFI_GRAPHICS_PIXEL_FORMAT::PixelBlueGreenRedReserved8BitPerColor`.
pub const PIXEL_FORMAT_BGRX: u32 = 1;

/// Magenta in both supported byte orders: bytes `[FF, 00, FF, 00]` are
/// `R=FF, G=00, B=FF` for RGBX and `B=FF, G=00, R=FF` for BGRX.
const MAGENTA: u32 = 0x00FF_00FF;

/// Geometry of the mapped framebuffer, as reported to the object layer.
///
/// `stride` is the GOP `PixelsPerScanLine` (**pixels**, not bytes); `size` is
/// the region size in bytes reported by the firmware.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DisplayInfo {
    pub base: u64,
    pub size: u64,
    pub width: u32,
    pub height: u32,
    pub stride: u32,
    pub pixel_format: u32,
}

impl DisplayInfo {
    /// All-zero value used when no display is initialised.
    pub const EMPTY: DisplayInfo = DisplayInfo {
        base: 0,
        size: 0,
        width: 0,
        height: 0,
        stride: 0,
        pixel_format: 0,
    };
}

impl Default for DisplayInfo {
    fn default() -> Self {
        DisplayInfo::EMPTY
    }
}

/// Validated geometry derived from a [`SavedFramebuffer`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Geometry {
    /// Bytes per scanline (`stride * 4`).
    row_bytes: u64,
    /// Bytes the visible mode needs (`row_bytes * height`).
    fb_bytes: u64,
    /// Pages the mapping needs, including the physical base page offset.
    span_pages: u64,
}

/// The one mapped framebuffer. Present once [`init`] succeeded.
#[derive(Clone, Copy, Debug)]
struct Display {
    info: DisplayInfo,
    /// Virtual address of the byte at `info.base` inside the display window.
    virt: u64,
    geometry: Geometry,
}

static mut DISPLAY: Option<Display> = None;

/// Real (non-test) source: the snapshot `boot::save` copied out of BootInfo.
#[cfg(not(test))]
fn saved_framebuffer() -> Option<SavedFramebuffer> {
    crate::boot::state().framebuffer
}

/// Host-test seam: `boot::save` needs a loader-provided image, so host tests
/// inject a framebuffer directly instead of fabricating BootInfo pages.
#[cfg(test)]
fn saved_framebuffer() -> Option<SavedFramebuffer> {
    unsafe { *ptr::addr_of!(TEST_FRAMEBUFFER) }
}

#[cfg(test)]
static mut TEST_FRAMEBUFFER: Option<SavedFramebuffer> = None;

/// Host tests only: set the framebuffer the seam returns.
#[cfg(test)]
pub(crate) fn set_test_framebuffer(fb: Option<SavedFramebuffer>) {
    unsafe { *ptr::addr_of_mut!(TEST_FRAMEBUFFER) = fb };
}

/// Host tests only: clear the mapped display and the seam.
#[cfg(test)]
pub(crate) fn reset_test_state() {
    unsafe { *ptr::addr_of_mut!(DISPLAY) = None };
    set_test_framebuffer(None);
}

fn display_slot() -> *mut Option<Display> {
    ptr::addr_of_mut!(DISPLAY)
}

/// Map the GOP framebuffer and publish its geometry.
///
/// Requirements:
///
/// * the boot state must carry an `FB_GOP` framebuffer (M6c loader change);
/// * the mode must be at least 321x201, which leaves the bottom-right probe
///   pixel outside the presented 320x200 surface;
/// * the pixel format must be 32 bpp RGBX or BGRX;
/// * the mode must fit inside [`platform::FB_WINDOW_LIMIT`].
///
/// Must run on the boot processor with interrupts disabled while the page
/// tables are quiescent (`mm::vm::map_physical`'s contract) and before any
/// display object exists. Idempotent: a second call is a no-op (`Ok(())`).
///
/// This does not touch the timer, the input path, or any M3 state.
pub fn init() -> Result<(), &'static str> {
    // SAFETY: the root calls this once, single-CPU, before user code exists.
    let slot = unsafe { &mut *display_slot() };
    if let Some(display) = slot {
        return if display.info.base == 0 {
            Err("display-not-initialised")
        } else {
            Ok(())
        };
    }

    let fb = saved_framebuffer().ok_or("display-no-framebuffer")?;
    let geometry = checked_geometry(&fb)?;

    // SAFETY: `TAKEOVER_DONE` is true by the time M6c runs; the window is
    // reserved for this module only, and the caller guarantees IF = 0.
    let virt = unsafe {
        vm::map_physical(
            platform::FB_WINDOW_BASE,
            fb.base,
            geometry.fb_bytes,
            vm::PTE_WRITE | vm::PTE_PWT | vm::PTE_PCD,
        )
    }
    .map_err(|_| "display-map-failed")?;

    *slot = Some(Display {
        info: DisplayInfo {
            base: fb.base,
            size: fb.size,
            width: fb.width,
            height: fb.height,
            stride: fb.stride,
            pixel_format: fb.pixel_format,
        },
        virt,
        geometry,
    });
    Ok(())
}

/// Geometry of the mapped framebuffer.
///
/// Returns `display-not-initialised` before [`init`] succeeded; see also
/// [`info_or_empty`] for callers that prefer an all-zero value.
pub fn info() -> Result<DisplayInfo, &'static str> {
    // SAFETY: the mapping is published once by `init` and never mutated again.
    let slot = unsafe { &*display_slot() };
    slot.as_ref()
        .map(|display| display.info)
        .ok_or("display-not-initialised")
}

/// Geometry, or [`DisplayInfo::EMPTY`] when no display is initialised.
pub fn info_or_empty() -> DisplayInfo {
    info().unwrap_or(DisplayInfo::EMPTY)
}

/// Write one magenta pixel into the **real** framebuffer bottom-right corner.
///
/// The probe proves the device mapping, not the shadow: it goes through the
/// same volatile [`Display::virt`] pointer that [`present`] writes through.
pub fn probe() -> Result<(), &'static str> {
    // SAFETY: `init` published a validated geometry and a permanent mapping.
    let slot = unsafe { &*display_slot() };
    let display = slot.as_ref().ok_or("display-not-initialised")?;
    let x = u64::from(display.info.width - 1);
    let y = u64::from(display.info.height - 1);
    let offset = y
        .checked_mul(display.geometry.row_bytes)
        .and_then(|row| row.checked_add(x * BYTES_PER_PIXEL))
        .ok_or("display-bad-size")?;
    if offset + BYTES_PER_PIXEL > display.geometry.fb_bytes {
        return Err("display-bad-size");
    }
    // SAFETY: the offset is inside the mapped framebuffer; MMIO stores are
    // volatile so the write cannot be elided or reordered into another pixel.
    unsafe {
        ptr::write_volatile(
            (display.virt as *mut u8).add(offset as usize) as *mut u32,
            MAGENTA,
        );
    }
    Ok(())
}

/// Copy the caller's shadow surface into framebuffer coordinates `(0, 0)`.
///
/// `frames` are the **physical** addresses of the 64 shadow frames, in order:
/// the surface is laid out linearly across them (frame 0 holds bytes
/// `0..4096`, frame 1 the next 4096, ...). They are read through the M2 direct
/// map, so they must be page-aligned physical frames belonging to the object
/// layer; every frame is validated before the first read.
///
/// Only the first 320x200 pixels of every row are touched: the real stride may
/// be larger, and the rest of the scanline is left as the firmware drew it.
/// Bounded by construction (fixed 200 * 320 pixel loop), no allocation, no
/// user addresses are trusted.
pub fn present(frames: &[u64; SURFACE_FRAMES]) -> Result<(), &'static str> {
    // SAFETY: see `info`; the mapping and geometry do not change after `init`.
    let slot = unsafe { &*display_slot() };
    let display = slot.as_ref().ok_or("display-not-initialised")?;
    validate_frames(frames)?;

    let format = display.info.pixel_format;
    let row_bytes = display.geometry.row_bytes;
    let mut y = 0u32;
    while y < SURFACE_HEIGHT {
        let mut x = 0u32;
        while x < SURFACE_WIDTH {
            let logical = u64::from(y) * u64::from(SURFACE_WIDTH) * BYTES_PER_PIXEL
                + u64::from(x) * BYTES_PER_PIXEL;
            let page = (logical / PAGE) as usize;
            let in_page = (logical % PAGE) as usize;
            // SAFETY: `validate_frames` proved every frame is an aligned
            // physical frame below the PMM ceiling, so the direct map covers
            // it; the read is unaligned-safe and the surface fits in 64 frames.
            let shadow = unsafe {
                ptr::read_unaligned(
                    (vm::phys_to_virt(frames[page]) as *const u8).add(in_page) as *const u32
                )
            };
            let pixel = encode_pixel(shadow, format);
            let dst = u64::from(y) * row_bytes + u64::from(x) * BYTES_PER_PIXEL;
            // SAFETY: `dst + 4 <= fb_bytes` by the validated geometry (width is
            // at most the stride and y < height); MMIO stores are volatile.
            unsafe {
                ptr::write_volatile(
                    (display.virt as *mut u8).add(dst as usize) as *mut u32,
                    pixel,
                );
            }
            x += 1;
        }
        y += 1;
    }
    Ok(())
}

/// Validate a shadow frame array without dereferencing it.
fn validate_frames(frames: &[u64; SURFACE_FRAMES]) -> Result<(), &'static str> {
    for &frame in frames {
        if frame == 0 || frame % PAGE != 0 || frame > MAX_FRAME_PHYS.saturating_sub(PAGE) {
            return Err("display-bad-frame");
        }
    }
    Ok(())
}

/// Translate one `0x00RRGGBB` shadow pixel into the framebuffer's byte order.
fn encode_pixel(shadow: u32, pixel_format: u32) -> u32 {
    let shadow = shadow & SHADOW_MASK;
    match pixel_format {
        // Framebuffer memory is [R, G, B, 0], so the low byte is red.
        PIXEL_FORMAT_RGBX => {
            ((shadow >> 16) & 0xFF) | (shadow & 0x0000_FF00) | ((shadow & 0x0000_00FF) << 16)
        }
        // Framebuffer memory is [B, G, R, 0]: the shadow value already matches.
        _ => shadow,
    }
}

/// Strict geometry validation, kept pure so host tests can exercise it without
/// page tables.
fn checked_geometry(fb: &SavedFramebuffer) -> Result<Geometry, &'static str> {
    if fb.width <= SURFACE_WIDTH || fb.height <= SURFACE_HEIGHT {
        return Err("display-unsupported-size");
    }
    if fb.pixel_format != PIXEL_FORMAT_RGBX && fb.pixel_format != PIXEL_FORMAT_BGRX {
        return Err("display-unsupported-format");
    }
    if fb.base == 0 || fb.base % BYTES_PER_PIXEL != 0 {
        return Err("display-bad-base");
    }
    let width = u64::from(fb.width);
    let height = u64::from(fb.height);
    let stride = u64::from(fb.stride);
    if stride < width {
        return Err("display-bad-stride");
    }
    let row_bytes = stride
        .checked_mul(BYTES_PER_PIXEL)
        .ok_or("display-bad-stride")?;
    let fb_bytes = row_bytes.checked_mul(height).ok_or("display-bad-size")?;
    if fb_bytes == 0 || fb_bytes > fb.size {
        return Err("display-bad-size");
    }
    let end = fb.base.checked_add(fb_bytes).ok_or("display-bad-size")?;
    if end > (1u64 << 52) {
        return Err("display-bad-base");
    }
    let span = (fb.base & (PAGE - 1))
        .checked_add(fb_bytes)
        .ok_or("display-bad-size")?;
    let span_pages = span.div_ceil(PAGE);
    if span_pages.checked_mul(PAGE).ok_or("display-bad-size")? > platform::FB_WINDOW_LIMIT {
        return Err("display-window-too-small");
    }
    Ok(Geometry {
        row_bytes,
        fb_bytes,
        span_pages,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::boot::SavedFramebuffer;

    /// Serialise tests that share `DISPLAY` and the framebuffer seam.
    fn serial() -> std::sync::MutexGuard<'static, ()> {
        crate::object::test_lock()
    }

    fn framebuffer(width: u32, height: u32, stride: u32) -> SavedFramebuffer {
        SavedFramebuffer {
            base: 0xFD00_0000,
            size: u64::from(stride) * u64::from(height) * 4,
            width,
            height,
            stride,
            pixel_format: PIXEL_FORMAT_RGBX,
        }
    }

    #[test]
    fn shadow_surface_fits_the_frame_budget() {
        assert_eq!(SURFACE_FRAMES, 64);
        assert!(SURFACE_BYTES <= SURFACE_FRAMES as u64 * PAGE);
        assert_eq!(
            SURFACE_BYTES,
            SURFACE_WIDTH as u64 * SURFACE_HEIGHT as u64 * 4
        );
        // Every pixel of the surface lands in one of the 64 frames.
        let last = (SURFACE_BYTES - 4) / PAGE;
        assert!(last < SURFACE_FRAMES as u64);
    }

    #[test]
    fn geometry_accepts_rgb_and_bgr_with_a_real_stride() {
        let rgb = checked_geometry(&framebuffer(1280, 800, 1280)).unwrap();
        assert_eq!(rgb.row_bytes, 5120);
        assert_eq!(rgb.fb_bytes, 4_096_000);
        assert_eq!(rgb.span_pages, 1000);
        // A stride wider than the visible width is normal for GOP modes.
        let padded = checked_geometry(&framebuffer(1024, 768, 1280)).unwrap();
        assert_eq!(padded.row_bytes, 5120);
        assert_eq!(padded.fb_bytes, 5120 * 768);
    }

    #[test]
    fn geometry_rejects_small_inconsistent_or_truncated_modes() {
        // The probe needs one pixel outside the presented surface.
        assert_eq!(
            checked_geometry(&framebuffer(320, 200, 320)),
            Err("display-unsupported-size")
        );
        assert_eq!(
            checked_geometry(&framebuffer(321, 200, 321)),
            Err("display-unsupported-size")
        );
        assert_eq!(
            checked_geometry(&framebuffer(321, 201, 300)),
            Err("display-bad-stride")
        );
        let mut bad_format = framebuffer(640, 480, 640);
        bad_format.pixel_format = 2; // PixelBitMask: unsupported in M6c
        assert_eq!(
            checked_geometry(&bad_format),
            Err("display-unsupported-format")
        );
        let mut bad_base = framebuffer(640, 480, 640);
        bad_base.base = 0;
        assert_eq!(checked_geometry(&bad_base), Err("display-bad-base"));
        // The declared region is smaller than the visible mode.
        let mut truncated = framebuffer(640, 480, 640);
        truncated.size -= 4;
        assert_eq!(checked_geometry(&truncated), Err("display-bad-size"));
        // A mode too large for the reserved window is refused, not truncated.
        let mut huge = framebuffer(8192, 8192, 8192);
        huge.size = u64::MAX;
        assert_eq!(checked_geometry(&huge), Err("display-window-too-small"));
    }

    #[test]
    fn shadow_pixels_are_encoded_for_the_framebuffer_byte_order() {
        // Shadow 0x0011_2233 means R=0x11, G=0x22, B=0x33.
        let shadow = 0x0011_2233;
        let bgr = encode_pixel(shadow, PIXEL_FORMAT_BGRX);
        assert_eq!(bgr.to_le_bytes(), [0x33, 0x22, 0x11, 0x00]);
        let rgb = encode_pixel(shadow, PIXEL_FORMAT_RGBX);
        assert_eq!(rgb.to_le_bytes(), [0x11, 0x22, 0x33, 0x00]);
        // The probe colour is magenta in either order.
        assert_eq!(MAGENTA.to_le_bytes(), [0xFF, 0x00, 0xFF, 0x00]);
    }

    #[test]
    fn entries_require_a_mapped_display() {
        let _serial = serial();
        reset_test_state();
        assert_eq!(info(), Err("display-not-initialised"));
        assert_eq!(info_or_empty(), DisplayInfo::EMPTY);
        assert_eq!(probe(), Err("display-not-initialised"));
        assert_eq!(
            present(&[0x20_0000; SURFACE_FRAMES]),
            Err("display-not-initialised")
        );
    }

    #[test]
    fn init_without_a_framebuffer_fails_loudly() {
        let _serial = serial();
        reset_test_state();
        assert_eq!(init(), Err("display-no-framebuffer"));
        assert_eq!(info(), Err("display-not-initialised"));
    }

    #[test]
    fn init_rejects_bad_geometry_before_mapping() {
        let _serial = serial();
        reset_test_state();
        set_test_framebuffer(Some(framebuffer(320, 200, 320)));
        assert_eq!(init(), Err("display-unsupported-size"));
        set_test_framebuffer(Some(framebuffer(640, 480, 640)));
        // Valid geometry, but the host cannot map page tables: the failure is
        // the mapping, never a silent success.
        assert_eq!(init(), Err("display-map-failed"));
        assert_eq!(info(), Err("display-not-initialised"));
        reset_test_state();
    }

    #[test]
    fn frame_array_is_validated_before_any_read() {
        let zero = [0u64; SURFACE_FRAMES];
        assert_eq!(validate_frames(&zero), Err("display-bad-frame"));
        let mut unaligned = [0x20_0000u64; SURFACE_FRAMES];
        unaligned[17] = 0x20_0800;
        assert_eq!(validate_frames(&unaligned), Err("display-bad-frame"));
        let mut far = [0x20_0000u64; SURFACE_FRAMES];
        far[63] = MAX_FRAME_PHYS;
        assert_eq!(validate_frames(&far), Err("display-bad-frame"));
        assert_eq!(validate_frames(&[0x20_0000u64; SURFACE_FRAMES]), Ok(()));
    }
}
