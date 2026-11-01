//! BootInfo access and the pre-takeover boot-state snapshot.
//!
//! The kernel must not depend on the BootInfo pages (or the loader's
//! identity mappings) after the VM takeover, so everything M2 needs is copied
//! into static `.bss` storage *before* the switch: the raw UEFI memory map
//! (for the PMM and the direct map) and the kernel image placement (for W^X
//! mapping and physical↔virtual translation of kernel statics). M3 adds the
//! optional ACPI RSDP so `platform` can map the ACPI tables after the takeover
//! without touching BootInfo again.

use bootinfo::{
    self, BootModules, EarlySerialTlv, FbGopTlv, Header, KernelImageTlv, MAX_BOOT_MODULES,
    MAX_TOTAL_SIZE, MemoryMapTlv, find_tlv, tlv_type,
};

pub const SAVED_MAP_CAP: usize = 128;

/// Capacity of the saved boot-module table.
///
/// This is the *protocol* limit ([`bootinfo::MAX_BOOT_MODULES`]), not the
/// loader's current "init + child" policy: M4 only ever runs two processes, but
/// the kernel must not bake the loader's module count into its ABI.
pub const SAVED_MODULE_CAP: usize = MAX_BOOT_MODULES;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SavedRegion {
    pub base: u64,
    pub pages: u64,
    pub ty: u32,
}

#[derive(Clone, Copy, Debug)]
pub struct SavedMap {
    pub regions: [SavedRegion; SAVED_MAP_CAP],
    pub count: usize,
}

impl SavedMap {
    pub const fn empty() -> Self {
        SavedMap {
            regions: [SavedRegion {
                base: 0,
                pages: 0,
                ty: 0,
            }; SAVED_MAP_CAP],
            count: 0,
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct SavedImage {
    pub phys_base: u64,
    pub phys_size: u64,
    pub virt_base: u64,
    pub virt_size: u64,
    pub entry: u64,
}

/// One boot module (initramfs payload) copied out of the `BOOT_MODULES` TLV.
///
/// The record is a *copy*: after the VM takeover the kernel never reads the
/// BootInfo pages again, so the module table has to live in `.bss`. The bytes
/// themselves stay at `phys` until `bootmod` maps them read-only.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SavedModule {
    pub phys: u64,
    pub size: u64,
    pub kind: u32,
    pub name: [u8; bootinfo::MODULE_NAME_LEN],
    pub name_len: u32,
}

impl SavedModule {
    /// Module name bytes (never longer than [`bootinfo::MODULE_NAME_LEN`]).
    pub fn name_bytes(&self) -> &[u8] {
        let n = (self.name_len as usize).min(self.name.len());
        &self.name[..n]
    }

    pub fn matches(&self, name: &[u8]) -> bool {
        self.name_bytes() == name
    }
}

/// The optional `FB_GOP` framebuffer description (M6c), copied out of BootInfo.
///
/// The loader is not required to publish one (M1 accepts `EARLY_SERIAL` as the
/// early diagnostic output), so this is `None` on every boot that predates the
/// M6c loader change. The fields are copied verbatim: the *display* layer owns
/// the semantic validation (geometry, stride, pixel format), because "what is a
/// usable framebuffer" is a display policy, not a boot-protocol rule.
///
/// `stride` is the GOP `PixelsPerScanLine`, i.e. **pixels**, not bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SavedFramebuffer {
    /// Physical base address of the linear framebuffer.
    pub base: u64,
    /// Size of the framebuffer region in bytes, as reported by GOP.
    pub size: u64,
    pub width: u32,
    pub height: u32,
    /// Pixels per scanline (`PixelsPerScanLine`).
    pub stride: u32,
    /// `EFI_GRAPHICS_PIXEL_FORMAT` value (0 = RGBX, 1 = BGRX).
    pub pixel_format: u32,
}

#[derive(Clone, Copy, Debug)]
pub struct BootState {
    pub map: SavedMap,
    pub image: SavedImage,
    /// Physical address of the ACPI RSDP from the optional `ACPI_RSDP` TLV
    /// (8-byte little-endian payload). `None` when the loader did not provide
    /// one. M3's `platform` maps the ACPI tables through this after the
    /// takeover; the value itself is untrusted until the RSDP signature and
    /// checksum have been verified.
    pub acpi_rsdp: Option<u64>,
    /// Boot modules (M4 `BOOT_MODULES`, protocol 1.1). Empty when the loader
    /// published none — `bootmod::init` turns that into a loud M4 failure.
    pub modules: [Option<SavedModule>; SAVED_MODULE_CAP],
    pub module_count: usize,
    /// Optional GOP framebuffer from the `FB_GOP` TLV (M6c). `None` when the
    /// loader published no framebuffer; M6c's display init then fails loudly
    /// instead of inventing a mode.
    pub framebuffer: Option<SavedFramebuffer>,
}

impl BootState {
    /// Saved boot modules, in loader order.
    pub fn modules(&self) -> impl Iterator<Item = SavedModule> + '_ {
        self.modules
            .iter()
            .take(self.module_count)
            .filter_map(|m| *m)
    }

    /// First saved module with the given name.
    pub fn module(&self, name: &[u8]) -> Option<SavedModule> {
        self.modules().find(|m| m.matches(name))
    }
}

pub static mut BOOT_STATE: BootState = BootState {
    map: SavedMap::empty(),
    image: SavedImage {
        phys_base: 0,
        phys_size: 0,
        virt_base: 0,
        virt_size: 0,
        entry: 0,
    },
    acpi_rsdp: None,
    modules: [None; SAVED_MODULE_CAP],
    module_count: 0,
    framebuffer: None,
};

/// Immutable view of the saved state (callers must run pre-SMP, single CPU).
pub fn state() -> &'static BootState {
    unsafe { &*core::ptr::addr_of!(BOOT_STATE) }
}

/// Validate and copy the MEMORY_MAP and KERNEL_IMAGE TLV payloads, plus the
/// optional ACPI_RSDP address, into the static snapshot. `image` is the
/// *validated* BootInfo (checksum and layout already verified). Runs before
/// the VM takeover.
pub fn save(image: &[u8], header: &Header) -> Result<(), &'static str> {
    let mut saved_map = SavedMap::empty();

    let mm_val = find_tlv(
        image,
        header.tlv_offset,
        header.total_size,
        tlv_type::MEMORY_MAP,
    )
    .ok_or("missing MEMORY_MAP")?;
    let mm = MemoryMapTlv::decode(mm_val).ok_or("bad MEMORY_MAP prefix")?;
    let count = mm
        .descriptor_count(mm_val.len())
        .ok_or("bad descriptor size")?;
    let desc_bytes = &mm_val[MemoryMapTlv::PREFIX_LEN..];
    for i in 0..count {
        let at = i
            .checked_mul(mm.desc_size as usize)
            .ok_or("descriptor overflow")?;
        let desc = desc_bytes
            .get(at..at + mm.desc_size as usize)
            .ok_or("descriptor out of bounds")?;
        let ty = bootinfo::efi_desc_type(desc).ok_or("bad descriptor")?;
        let base = bootinfo::efi_desc_phys(desc).ok_or("bad descriptor")?;
        let pages = bootinfo::efi_desc_pages(desc).ok_or("bad descriptor")?;
        if saved_map.count >= SAVED_MAP_CAP {
            return Err("saved memory map capacity exceeded");
        }
        saved_map.regions[saved_map.count] = SavedRegion { base, pages, ty };
        saved_map.count += 1;
    }

    let ki_val = find_tlv(
        image,
        header.tlv_offset,
        header.total_size,
        tlv_type::KERNEL_IMAGE,
    )
    .ok_or("missing KERNEL_IMAGE")?;
    let ki = KernelImageTlv::decode(ki_val).ok_or("bad KERNEL_IMAGE")?;
    if ki.image_phys_base % 4096 != 0
        || ki.image_phys_size == 0
        || ki.image_phys_size % 4096 != 0
        || ki.image_virt_base % 4096 != 0
        || ki.image_virt_size == 0
        || ki.entry_virt < ki.image_virt_base
        || ki.entry_virt >= ki.image_virt_base + ki.image_virt_size
    {
        return Err("KERNEL_IMAGE placement inconsistent");
    }

    let acpi_rsdp = read_acpi_rsdp(image, header)?;
    let (modules, module_count) = read_modules(image, header)?;
    let framebuffer = read_framebuffer(image, header)?;

    unsafe {
        let st = core::ptr::addr_of_mut!(BOOT_STATE);
        (*st).map = saved_map;
        (*st).image = SavedImage {
            phys_base: ki.image_phys_base,
            phys_size: ki.image_phys_size,
            virt_base: ki.image_virt_base,
            virt_size: ki.image_virt_size,
            entry: ki.entry_virt,
        };
        (*st).acpi_rsdp = acpi_rsdp;
        (*st).modules = modules;
        (*st).module_count = module_count;
        (*st).framebuffer = framebuffer;
    }
    Ok(())
}

/// Copy the optional `BOOT_MODULES` TLV into the static table.
///
/// The TLV is optional in protocol 1.1 (a kernel that does not implement M4 can
/// still boot), so an absent TLV yields an empty table; a *present* but
/// malformed payload is a hard error — the kernel must not silently drop a
/// module list it cannot decode. `bootmod::init` is what requires `init` and
/// `child` to actually exist.
fn read_modules(
    image: &[u8],
    header: &Header,
) -> Result<([Option<SavedModule>; SAVED_MODULE_CAP], usize), &'static str> {
    let mut saved: [Option<SavedModule>; SAVED_MODULE_CAP] = [None; SAVED_MODULE_CAP];
    let Some(val) = find_tlv(
        image,
        header.tlv_offset,
        header.total_size,
        tlv_type::BOOT_MODULES,
    ) else {
        return Ok((saved, 0));
    };
    let modules = BootModules::new(val).ok_or("bad BOOT_MODULES TLV")?;
    let count = modules.count() as usize;
    if count > SAVED_MODULE_CAP {
        return Err("BOOT_MODULES exceeds kernel capacity");
    }
    for i in 0..count {
        let m = modules.get(i as u32).ok_or("bad BOOT_MODULES record")?;
        if m.kind == 0 || m.size == 0 || m.phys.checked_add(m.size).is_none() {
            return Err("bad BOOT_MODULES record");
        }
        match m.name_bytes() {
            Some(n) if !n.is_empty() => {}
            _ => return Err("bad BOOT_MODULES name"),
        }
        saved[i] = Some(SavedModule {
            phys: m.phys,
            size: m.size,
            kind: m.kind,
            name: m.name,
            name_len: m.name_len,
        });
    }
    Ok((saved, count))
}

/// Read the optional `ACPI_RSDP` TLV: an 8-byte little-endian physical address.
///
/// Absent TLV means "loader had no RSDP" (`Ok(None)`); a present but truncated
/// payload is a semantic error even though `validate` does not check per-TLV
/// lengths, because the kernel must not consume a TLV it cannot decode.
fn read_acpi_rsdp(image: &[u8], header: &Header) -> Result<Option<u64>, &'static str> {
    let Some(val) = find_tlv(
        image,
        header.tlv_offset,
        header.total_size,
        tlv_type::ACPI_RSDP,
    ) else {
        return Ok(None);
    };
    if val.len() < 8 {
        return Err("bad ACPI_RSDP TLV");
    }
    let mut raw = [0u8; 8];
    raw.copy_from_slice(&val[..8]);
    Ok(Some(u64::from_le_bytes(raw)))
}

/// Read the optional `FB_GOP` TLV into a [`SavedFramebuffer`].
///
/// Absent TLV means "the loader had no GOP framebuffer" (`Ok(None)`), which is
/// legal for every pre-M6c boot. A *present* but truncated payload is a
/// semantic error: `bootinfo::validate` does not check per-TLV lengths, so a
/// 16-byte record would otherwise be decoded from whatever bytes follow it.
fn read_framebuffer(
    image: &[u8],
    header: &Header,
) -> Result<Option<SavedFramebuffer>, &'static str> {
    let Some(val) = find_tlv(
        image,
        header.tlv_offset,
        header.total_size,
        tlv_type::FB_GOP,
    ) else {
        return Ok(None);
    };
    let fb = FbGopTlv::decode(val).ok_or("bad FB_GOP TLV")?;
    Ok(Some(SavedFramebuffer {
        base: fb.base,
        size: fb.size,
        width: fb.width,
        height: fb.height,
        stride: fb.stride,
        pixel_format: fb.pixel_format,
    }))
}

/// Minimal, defensive extraction of the early serial parameters (agents.md
/// §5.3 rule 9): reads only the header size fields and the EARLY_SERIAL TLV
/// address parameters, with bounds checks that do not depend on the
/// checksum. Falls back to COM1/115200 so a failure message can still be
/// emitted on QEMU.
pub fn early_serial_fallback(bi: u64) -> (u16, u32) {
    let read = |at: usize, n: usize| -> Option<u64> {
        let p = (bi as usize).checked_add(at)? as *const u8;
        let mut v = 0u64;
        for i in 0..n {
            v |= u64::from(unsafe { p.add(i).read() }) << (8 * i);
        }
        Some(v)
    };
    let mut fallback = (0x3F8u16, 115200u32);
    let Some(total_size) = read(16, 4).filter(|&s| s >= 64 && s <= u64::from(MAX_TOTAL_SIZE))
    else {
        return fallback;
    };
    let Some(tlv_offset) = read(36, 4).filter(|&o| o >= 64 && o < total_size) else {
        return fallback;
    };
    let mut off = tlv_offset as usize;
    while (off as u64) + 8 <= total_size {
        let Some(ty) = read(off, 4) else { break };
        let Some(len) = read(off + 4, 4) else { break };
        if len > total_size || (off as u64) + 8 + len > total_size {
            break;
        }
        if ty == u64::from(tlv_type::EARLY_SERIAL) && len >= 24 {
            let Some(kind) = read(off + 8, 4) else { break };
            let Some(base) = read(off + 12, 8) else { break };
            let Some(baud) = read(off + 20, 4) else { break };
            if kind == u64::from(EarlySerialTlv::KIND_IOPORT_16550) && base < 0x1_0000 {
                fallback = (base as u16, baud as u32);
            }
            break;
        }
        off += 8 + len as usize;
        off = (off + 7) & !7;
    }
    fallback
}

// ---------------------------------------------------------------------------
// Tests (host)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use bootinfo::{Writer, tlv_type};
    use std::vec;
    use std::vec::Vec;

    /// Serialise every test that calls `save()` or reads `state()`.
    ///
    /// `save()` writes the shared `static mut BOOT_STATE`, and host tests run
    /// in parallel by default, so two saving tests would otherwise overwrite
    /// each other's snapshot mid-assertion (observed as a flaky module-name
    /// mismatch). A poisoned lock is still usable: the panic belongs to the
    /// test that poisoned it, not to the snapshot.
    fn state_lock() -> std::sync::MutexGuard<'static, ()> {
        static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
        LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Physical RSDP address used by the test images. Asymmetric on the wire so
    /// an endianness mistake cannot read back the same value.
    const TEST_RSDP: u64 = 0x7F5A_3C10;

    /// Build a valid BootInfo image with one conventional descriptor; `acpi`
    /// adds the optional ACPI_RSDP TLV.
    fn build_test_image_with(acpi: bool) -> (Vec<u8>, u32) {
        build_image(acpi, &[])
    }

    /// Same image, plus a `BOOT_MODULES` TLV built from `(name, phys, size)`.
    fn build_image(acpi: bool, modules: &[(&[u8], u64, u64)]) -> (Vec<u8>, u32) {
        build_image_with_fb(acpi, modules, None)
    }

    /// Same image with an optional raw `FB_GOP` payload.
    ///
    /// The framebuffer TLV is inserted between `EARLY_SERIAL` and `ACPI_RSDP`
    /// so the TLV types stay ascending (0x3, 0x4, 0x5) as the protocol lays
    /// them out; `fb` is the *raw* payload so a deliberately short payload can
    /// be exercised.
    fn build_image_with_fb(
        acpi: bool,
        modules: &[(&[u8], u64, u64)],
        fb: Option<&[u8]>,
    ) -> (Vec<u8>, u32) {
        let mut buf = vec![0u8; 4096];
        let mut w = Writer::new(
            &mut buf,
            bootinfo::PROTOCOL_MAJOR,
            bootinfo::PROTOCOL_MINOR,
            0,
            bootinfo::ENTRY_ABI,
        );
        let mut mm_val = Vec::new();
        mm_val.extend_from_slice(
            &MemoryMapTlv {
                desc_size: 48,
                desc_version: 1,
            }
            .encode(),
        );
        let mut desc = [0u8; 48];
        desc[0..4].copy_from_slice(&7u32.to_le_bytes()); // conventional
        desc[8..16].copy_from_slice(&0x20_0000u64.to_le_bytes());
        desc[24..32].copy_from_slice(&1024u64.to_le_bytes()); // 4 MiB
        mm_val.extend_from_slice(&desc);
        w.add_tlv(tlv_type::MEMORY_MAP, &mm_val).unwrap();
        w.add_tlv(
            tlv_type::KERNEL_IMAGE,
            &KernelImageTlv {
                image_phys_base: 0x10_0000,
                image_phys_size: 0x30_0000,
                image_virt_base: 0xFFFF_FFFF_8000_0000,
                image_virt_size: 0x30_0000,
                entry_virt: 0xFFFF_FFFF_8000_1000,
                stack_base: 0x40_0000,
                stack_size: 0x1000,
                page_table_phys: 0x50_0000,
            }
            .encode(),
        )
        .unwrap();
        w.add_tlv(
            tlv_type::EARLY_SERIAL,
            &EarlySerialTlv {
                kind: EarlySerialTlv::KIND_IOPORT_16550,
                base: 0x3F8,
                baud: 115200,
                reserved: 0,
            }
            .encode(),
        )
        .unwrap();
        if let Some(payload) = fb {
            w.add_tlv(tlv_type::FB_GOP, payload).unwrap();
        }
        if acpi {
            w.add_tlv(tlv_type::ACPI_RSDP, &TEST_RSDP.to_le_bytes())
                .unwrap();
        }
        if !modules.is_empty() {
            let mut val = Vec::new();
            val.extend_from_slice(&(modules.len() as u32).to_le_bytes());
            val.extend_from_slice(&0u32.to_le_bytes());
            for &(name, phys, size) in modules {
                val.extend_from_slice(
                    &bootinfo::BootModule::new(name, bootinfo::MODULE_KIND_ELF, phys, size)
                        .unwrap()
                        .encode(),
                );
            }
            w.add_tlv(tlv_type::BOOT_MODULES, &val).unwrap();
        }
        let total = w.finish().unwrap();
        (buf, total)
    }

    fn build_test_image() -> (Vec<u8>, u32) {
        build_test_image_with(true)
    }

    #[test]
    fn save_copies_map_and_image() {
        let _guard = state_lock();
        let (buf, total) = build_test_image();
        let image = &buf[..total as usize];
        let header = bootinfo::validate(image).unwrap();
        save(image, &header).unwrap();
        let st = state();
        assert_eq!(st.map.count, 1);
        assert_eq!(st.map.regions[0].ty, 7);
        assert_eq!(st.map.regions[0].base, 0x20_0000);
        assert_eq!(st.map.regions[0].pages, 1024);
        assert_eq!(st.image.phys_base, 0x10_0000);
        assert_eq!(st.image.phys_size, 0x30_0000);
        assert_eq!(st.image.entry, 0xFFFF_FFFF_8000_1000);
        assert_eq!(st.acpi_rsdp, Some(TEST_RSDP));
    }

    #[test]
    fn save_rejects_bad_image_tlv() {
        let _guard = state_lock();
        let (mut buf, total) = build_test_image();
        // Corrupt the KERNEL_IMAGE entry (outside the covered TLV bytes):
        // flip the entry_virt to point outside the image.
        let image = bootinfo::validate(&buf[..total as usize]).unwrap();
        // entry field lives at TLV offset: find it
        let ki = find_tlv(
            &buf[..total as usize],
            image.tlv_offset,
            image.total_size,
            tlv_type::KERNEL_IMAGE,
        )
        .unwrap();
        let ki_off = ki.as_ptr() as usize - buf.as_ptr() as usize;
        let entry_off = ki_off + 4 * 8; // entry_virt is the 5th u64
        buf[entry_off..entry_off + 8].copy_from_slice(&0xFFFF_FFFF_9000_0000u64.to_le_bytes());
        // Recompute checksum so layout validation passes and only the
        // semantic check in `save` fires.
        let fixed = bootinfo::compute_checksum(&buf[..total as usize]);
        buf[20..24].copy_from_slice(&fixed.to_le_bytes());
        let header = bootinfo::validate(&buf[..total as usize]).unwrap();
        assert_eq!(
            save(&buf[..total as usize], &header),
            Err("KERNEL_IMAGE placement inconsistent")
        );
    }

    #[test]
    fn acpi_rsdp_missing_is_none() {
        // No ACPI_RSDP TLV: the snapshot must record `None`, not zero.
        let (buf, total) = build_test_image_with(false);
        let image = &buf[..total as usize];
        let header = bootinfo::validate(image).unwrap();
        assert_eq!(read_acpi_rsdp(image, &header), Ok(None));
    }

    #[test]
    fn acpi_rsdp_short_payload_is_rejected() {
        // `validate` does not check per-TLV lengths, so a truncated payload
        // reaches `save`; it must be rejected rather than mis-decoded.
        let (mut buf, total) = build_test_image_with(true);
        let val_off = {
            let image = &buf[..total as usize];
            let header = bootinfo::validate(image).unwrap();
            let val = find_tlv(
                image,
                header.tlv_offset,
                header.total_size,
                tlv_type::ACPI_RSDP,
            )
            .unwrap();
            val.as_ptr() as usize - buf.as_ptr() as usize
        };
        // Shrink the declared length from 8 to 4 bytes (the padded record size
        // stays 16 bytes, so the TLV walk is unchanged) and re-checksum.
        buf[val_off - 4..val_off].copy_from_slice(&4u32.to_le_bytes());
        let fixed = bootinfo::compute_checksum(&buf[..total as usize]);
        buf[20..24].copy_from_slice(&fixed.to_le_bytes());
        let image = &buf[..total as usize];
        let header = bootinfo::validate(image).unwrap();
        assert_eq!(read_acpi_rsdp(image, &header), Err("bad ACPI_RSDP TLV"));
    }

    // -- BOOT_MODULES snapshot (M4) ----------------------------------------

    /// Byte offset of a TLV's value inside the image buffer.
    fn tlv_value_offset(buf: &[u8], total: u32, ty: u32) -> usize {
        let image = &buf[..total as usize];
        let header = bootinfo::validate(image).unwrap();
        let value = find_tlv(image, header.tlv_offset, header.total_size, ty).unwrap();
        value.as_ptr() as usize - buf.as_ptr() as usize
    }

    /// Re-checksum an image after a deliberate byte edit.
    fn refresh_checksum(buf: &mut [u8], total: u32) {
        let fixed = bootinfo::compute_checksum(&buf[..total as usize]);
        buf[20..24].copy_from_slice(&fixed.to_le_bytes());
    }

    /// Snapshot helper: save and return the parsed module view.
    fn save_modules(buf: &[u8], total: u32) -> Result<(), &'static str> {
        let image = &buf[..total as usize];
        let header = bootinfo::validate(image).unwrap();
        save(image, &header)
    }

    #[test]
    fn save_copies_boot_modules() {
        let _guard = state_lock();
        // The protocol allows up to 8 modules; the M4 image carries two. The
        // snapshot must keep them in order, with name/kind/phys/size intact.
        let (buf, total) = build_image(
            true,
            &[
                (b"init", 0x60_0000, 0x10_0000),
                (b"child", 0x70_0000, 0x8000),
            ],
        );
        save_modules(&buf, total).unwrap();
        let st = state();
        assert_eq!(st.module_count, 2);
        let names: Vec<Vec<u8>> = st.modules().map(|m| m.name_bytes().to_vec()).collect();
        assert_eq!(names, vec![b"init".to_vec(), b"child".to_vec()]);
        let init = st.module(b"init").unwrap();
        assert_eq!(init.phys, 0x60_0000);
        assert_eq!(init.size, 0x10_0000);
        assert_eq!(init.kind, bootinfo::MODULE_KIND_ELF);
        let child = st.module(b"child").unwrap();
        assert_eq!(child.phys, 0x70_0000);
        assert_eq!(child.size, 0x8000);
        assert!(st.module(b"nope").is_none());
        assert!(init.matches(b"init") && !init.matches(b"inits"));
    }

    #[test]
    fn no_module_tlv_means_no_modules() {
        let _guard = state_lock();
        // BOOT_MODULES is optional in protocol 1.1: a kernel that sees none must
        // record an empty set (the root then fails loudly, not silently).
        let (buf, total) = build_test_image_with(true);
        save_modules(&buf, total).unwrap();
        let st = state();
        assert_eq!(st.module_count, 0);
        assert_eq!(st.modules().count(), 0);
        assert!(st.module(b"init").is_none());
    }

    #[test]
    fn nine_module_records_are_rejected() {
        let _guard = state_lock();
        // The protocol validator caps the set at MAX_BOOT_MODULES (8); a ninth
        // record must be refused before anything is snapshotted.
        let names: [&[u8]; 9] = [
            b"m0", b"m1", b"m2", b"m3", b"m4", b"m5", b"m6", b"m7", b"m8",
        ];
        let modules: Vec<(&[u8], u64, u64)> = names
            .iter()
            .enumerate()
            .map(|(i, name)| (*name, 0x60_0000 + (i as u64) * 0x1000, 0x1000))
            .collect();
        let (buf, total) = build_image(true, &modules);
        assert_eq!(
            save_modules(&buf, total),
            Err("bad BOOT_MODULES TLV"),
            "9 records exceed the protocol limit"
        );
    }

    #[test]
    fn zero_size_module_record_is_rejected() {
        let _guard = state_lock();
        // A zero `size` is refused by `bootinfo::BootModule::decode` (the record
        // is undecodable, so the whole TLV is), before the snapshot sees it.
        let (mut buf, total) = build_image(true, &[(b"init", 0x60_0000, 0x1000)]);
        let value = tlv_value_offset(&buf, total, tlv_type::BOOT_MODULES);
        // Record layout: phys @0, size @8, kind @16, name_len @20, name @24.
        buf[value + 8 + 8..value + 8 + 16].copy_from_slice(&0u64.to_le_bytes());
        refresh_checksum(&mut buf, total);
        assert_eq!(
            save_modules(&buf, total),
            Err("bad BOOT_MODULES TLV"),
            "zero-size module must not be snapshotted"
        );
    }

    #[test]
    fn empty_module_name_record_is_rejected() {
        let _guard = state_lock();
        // Likewise for a name that does not match its declared length: the
        // record fails to decode and the TLV is rejected as a whole.
        let (mut buf, total) = build_image(true, &[(b"init", 0x60_0000, 0x1000)]);
        let value = tlv_value_offset(&buf, total, tlv_type::BOOT_MODULES);
        buf[value + 8 + 24] = 0;
        refresh_checksum(&mut buf, total);
        assert_eq!(
            save_modules(&buf, total),
            Err("bad BOOT_MODULES TLV"),
            "empty module name must not be snapshotted"
        );
    }

    // -- FB_GOP snapshot (M6c) ---------------------------------------------

    /// Framebuffer used by the snapshot tests: asymmetric values so a swapped
    /// field cannot pass by accident.
    const TEST_FB: FbGopTlv = FbGopTlv {
        base: 0xFD00_0000,
        size: 0x7F_0000,
        width: 1280,
        height: 800,
        stride: 1280,
        pixel_format: 0,
    };

    #[test]
    fn framebuffer_snapshot_copies_the_gop_tlv() {
        let _guard = state_lock();
        let payload = TEST_FB.encode();
        let (buf, total) = build_image_with_fb(false, &[], Some(&payload));
        let image = &buf[..total as usize];
        let header = bootinfo::validate(image).unwrap();
        save(image, &header).unwrap();
        assert_eq!(
            state().framebuffer,
            Some(SavedFramebuffer {
                base: 0xFD00_0000,
                size: 0x7F_0000,
                width: 1280,
                height: 800,
                stride: 1280,
                pixel_format: 0,
            })
        );
    }

    #[test]
    fn framebuffer_absent_is_none() {
        let _guard = state_lock();
        // M1 accepts EARLY_SERIAL as the diagnostic output, so a loader without
        // GOP support is a legal boot: the snapshot must record `None`.
        let (buf, total) = build_image_with_fb(false, &[], None);
        let image = &buf[..total as usize];
        let header = bootinfo::validate(image).unwrap();
        assert_eq!(read_framebuffer(image, &header), Ok(None));
        save(image, &header).unwrap();
        assert!(state().framebuffer.is_none());
    }

    #[test]
    fn framebuffer_short_payload_is_rejected() {
        let _guard = state_lock();
        // 16 bytes is shorter than `FbGopTlv::LEN` (32). `validate` only walks
        // the TLVs, so the kernel has to reject the truncated record itself
        // instead of decoding whatever bytes follow it.
        let short = [0u8; 16];
        let (buf, total) = build_image_with_fb(false, &[], Some(&short));
        let image = &buf[..total as usize];
        let header = bootinfo::validate(image).unwrap();
        assert_eq!(read_framebuffer(image, &header), Err("bad FB_GOP TLV"));
        assert_eq!(save(image, &header), Err("bad FB_GOP TLV"));
    }
}
