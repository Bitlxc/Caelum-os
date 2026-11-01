//! M5b persistent-disk images for the two-boot acceptance run.
//!
//! The harness hands the guest two raw volumes as legacy virtio-blk drives:
//!
//! * drive 0 (`index 0`): FAT32, 64 MiB
//! * drive 1 (`index 1`): ext2, 32 MiB
//!
//! Both are formatted **on the host** before every run, using the same
//! `libs/fat32` and `libs/ext2` code the kernel links, and they are re-mounted
//! on the host after each boot to check exactly what the guest wrote. A green
//! run therefore proves on-disk interoperability, not merely that the guest
//! agrees with itself.
//!
//! First boot: write `/M5STATE.BIN` + `/M5DATA.BIN` (FAT32) and `/m5state` +
//! `/m5data` (ext2). Data starts as 8192 bytes of
//! `pattern(i) = ((i * 13 + 7) % 251) as u8`.
//!
//! Second boot: re-read and verify the 13-byte state marker and all 8192 bytes,
//! append 1024 more pattern bytes (offset 8192, length 9216), rename the data
//! file (FAT32 `M5DATA.BIN` -> `M5DONE.BIN`, ext2 `m5data` -> `m5done`),
//! truncate it to 4608 bytes and sync.
//!
//! M5c1 rides on the same volumes: the user programs own
//! `/M5CUSER.BIN` (FAT32) and `/m5cuser` (ext2). After the first boot both must
//! hold exactly `CAELUM-M5C1-V1` (14 bytes), after the second boot exactly
//! `CAELUM-M5C1-V1\nBOOT2` (20 bytes). A file present on only one volume, or
//! with the wrong bytes, fails the run.

use std::fs;
use std::path::{Path, PathBuf};

use block::test_support::MemDisk;
use ext2::Ext2;

use crate::m10a::Samples;
#[cfg(test)]
use ext2::NodeKind as ExtKind;
#[cfg(test)]
use fat32::NodeKind as FatKind;
use fat32::{Fat32, FormatOptions};

/// The FAT32 volume is 64 MiB on purpose: at 32 MiB its cluster count
/// (~64 496) falls below the FAT32 specification's 65 525 minimum, so the
/// image would mount in our own library while being non-conformant on disk.
pub const FAT32_DISK_BYTES: u64 = 64 * 1024 * 1024;

/// The ext2 volume stays at 32 MiB; 1 KiB blocks are fixed by `libs/ext2`.
pub const EXT2_DISK_BYTES: u64 = 32 * 1024 * 1024;

/// Device block size passed to both filesystems on the host.
pub const DEV_BLOCK_SIZE: u32 = 512;

/// The 13-byte marker both filesystems must hold in their state file.
pub const STATE_BYTES: &[u8] = b"CAELUM-M5B-V1";

/// Initial length of the data file, in bytes.
pub const DATA_INITIAL_LEN: usize = 8192;

/// Length the second boot truncates the data file to.
pub const DATA_FINAL_LEN: u64 = 4608;

/// FAT32 state file at the volume root.
pub const FAT_STATE: &str = "M5STATE.BIN";
/// FAT32 data file, before the second boot renames it.
pub const FAT_DATA: &str = "M5DATA.BIN";
/// FAT32 data file name after the second boot's rename.
pub const FAT_DONE: &str = "M5DONE.BIN";

/// ext2 state file at the volume root.
pub const EXT2_STATE: &[u8] = b"m5state";
/// ext2 data file, before the second boot renames it.
pub const EXT2_DATA: &[u8] = b"m5data";
/// ext2 data file name after the second boot's rename.
pub const EXT2_DONE: &[u8] = b"m5done";

/// FAT32 user file the M5c1 user programs create and update.
pub const FAT_USER: &str = "M5CUSER.BIN";
/// ext2 counterpart of [`FAT_USER`].
pub const EXT2_USER: &[u8] = b"m5cuser";

/// Exact content of the M5c user file after the first boot (14 bytes).
pub const M5C1_FIRST_MARKER: &[u8] = b"CAELUM-M5C1-V1";
/// Exact content of the M5c user file after the second boot (20 bytes).
pub const M5C1_SECOND_MARKER: &[u8] = b"CAELUM-M5C1-V1\nBOOT2";

/// FAT32 file the M5c2 user programs map and edit through a shared mapping.
pub const FAT_MAP: &str = "M5MAP.BIN";
/// ext2 counterpart of [`FAT_MAP`].
pub const EXT2_MAP: &[u8] = b"m5cmap";

/// Length of the map file on both volumes.
pub const MAP_LEN: usize = 8192;

/// Byte the shared mapping writes at offset 0.
pub const MAP_SHARED_FIRST: u8 = 0xA5;
/// Offset of the second shared-mapping edit.
pub const MAP_SHARED_SECOND_AT: usize = 4103;
/// Byte the shared mapping writes at [`MAP_SHARED_SECOND_AT`].
pub const MAP_SHARED_SECOND: u8 = 0x5A;
/// Byte the *private* mapping writes; a private write must never reach the disk.
pub const MAP_PRIVATE_BYTE: u8 = 0xFF;

/// Deterministic map-file byte `i`, as the guest lays it down before mmap.
pub fn map_pattern_byte(i: usize) -> u8 {
    ((i * 7 + 3) % 251) as u8
}

/// Map file content the guest lays down before it maps the file.
pub fn map_initial() -> Vec<u8> {
    (0..MAP_LEN).map(map_pattern_byte).collect()
}

/// Map file content both boots must leave on the volume: the initial pattern
/// plus the two shared-mapping edits. The private mapping's `0xFF` at offset 0
/// must *not* be here, so the first byte doubles as the private-write probe.
pub fn map_final() -> Vec<u8> {
    let mut bytes = map_initial();
    bytes[0] = MAP_SHARED_FIRST;
    bytes[MAP_SHARED_SECOND_AT] = MAP_SHARED_SECOND;
    bytes
}

/// FAT32 sparse file the M5c3 user program writes with a hole.
pub const FAT_HOLE: &str = "M5HOLE.BIN";
/// ext2 counterpart of [`FAT_HOLE`].
pub const EXT2_HOLE: &[u8] = b"m5chole";

/// Final size of the sparse file: eight 4 KiB pages plus a four-byte tail.
pub const HOLE_LEN: usize = 32772;
/// Zero bytes the sparse file must read back as zeros (the hole itself).
pub const HOLE_ZEROS: usize = 32768;
/// Tail bytes the sparse file must actually hold after the hole.
pub const HOLE_TAIL: &[u8] = b"HOLE";

/// FAT32 file whose write/flush path is fault-injected by the kernel.
pub const FAT_FAULT: &str = "M5FAULT.BIN";
/// ext2 counterpart of [`FAT_FAULT`].
pub const EXT2_FAULT: &[u8] = b"m5cfault";
/// Exact content the fault-injection file must hold once the driver recovered.
pub const FAULT_MARKER: &[u8] = b"CAELUM-FAULT-OK";

/// Byte length the acceptance contract gives the fault-injection file: the
/// 15-byte literal above plus the trailing newline the writer emits.
pub const FAULT_LEN: usize = 16;

/// Full expected content of the fault-injection file: marker plus newline.
pub fn fault_expected() -> Vec<u8> {
    let mut bytes = FAULT_MARKER.to_vec();
    bytes.push(b'\n');
    bytes
}

/// Full expected content of the sparse file: [`HOLE_ZEROS`] zeros followed by
/// [`HOLE_TAIL`]. Reading the hole back as zeros is the sparse guarantee.
pub fn hole_bytes() -> Vec<u8> {
    let mut bytes = vec![0u8; HOLE_ZEROS];
    bytes.extend_from_slice(HOLE_TAIL);
    bytes
}

/// M9d1: the dynamic ELF main program the harness injects into the FAT volume.
/// The name has to be strict 8.3: the FAT library synthesises no long names and
/// the kernel opens the file by this exact path (`/fat/dyn-main`).
pub const FAT_DYN_MAIN: &str = "dyn-main";

/// M9d1: the interpreter the injected main program names via `PT_INTERP`. Also
/// strict 8.3; the kernel side only accepts `/fat/ldcaelum.so`.
pub const FAT_DYN_INTERP: &str = "ldcaelum.so";

/// M9d2: the vDSO image the dynamic program maps. Strict 8.3 (the kernel side
/// only accepts `/fat/vdso.so`), injected next to the dynamic pair.
pub const FAT_VDSO: &str = "vdso.so";

/// M9e: the shared library the dynamic main links with a real `DT_NEEDED`.
/// Strict 8.3 (the kernel side only accepts `/fat/m9e.so`), injected next to
/// the M9d image set.
pub const FAT_M9E: &str = "m9e.so";

/// M9f: the two chained shared libraries. Both strict 8.3 (the kernel side
/// only accepts `/fat/m9f-a.so` and `/fat/m9f-b.so`), injected next to the
/// M9e library.
pub const FAT_M9F_A: &str = "m9f-a.so";
pub const FAT_M9F_B: &str = "m9f-b.so";

/// M10a: ext2 directory holding the real `busybox` sample, so the guest sees
/// `/ext2/bin/busybox` (the `/` alias itself is delivered by the VFS slice).
pub const EXT2_BIN_DIR: &[u8] = b"bin";
/// M10a: ext2 directory holding the two musl samples (`/ext2/lib/...`).
pub const EXT2_LIB_DIR: &[u8] = b"lib";
/// M10a: the genuine `busybox` binary inside [`EXT2_BIN_DIR`].
pub const EXT2_BUSYBOX: &[u8] = b"busybox";
/// M10a: the musl dynamic loader inside [`EXT2_LIB_DIR`].
pub const EXT2_LD_MUSL: &[u8] = b"ld-musl-x86_64.so.1";
/// M10a: the musl libc inside [`EXT2_LIB_DIR`].
pub const EXT2_LIBC_MUSL: &[u8] = b"libc.musl-x86_64.so.1";

/// Deterministic data byte `i` used by both the guest and the host checks.
pub fn pattern_byte(i: usize) -> u8 {
    ((i * 13 + 7) % 251) as u8
}

/// Deterministic data buffer of `len` bytes.
pub fn pattern(len: usize) -> Vec<u8> {
    (0..len).map(pattern_byte).collect()
}

/// Raw FAT32 image handed to virtio-blk drive 0.
pub fn fat32_image() -> PathBuf {
    crate::target_dir().join("m5b-fat32.img")
}

/// Raw ext2 image handed to virtio-blk drive 1.
pub fn ext2_image() -> PathBuf {
    crate::target_dir().join("m5b-ext2.img")
}

fn io_error(what: &str, error: std::io::Error) -> String {
    format!("{what}: {error}")
}

/// Format both volumes **empty** before an acceptance run.
///
/// The guest owns the first boot: it must observe a clean volume (both state
/// files absent) and create the state/data files itself, so nothing may be
/// pre-seeded here — a seeded image would make the kernel take its second-boot
/// branch on what the harness calls the first boot, and the acceptance would
/// prove nothing. Called before every run so a previous run can never leave the
/// guest with a half-written volume (and so a stale image can never turn the run
/// green).
///
/// M9d/M9e add the injected artifacts: the dynamic ELF main, the interpreter
/// named by its `PT_INTERP`, the vDSO image and the shared library are written
/// into the FAT volume before the guest starts, so every boot sees the exact
/// bytes the harness will check.
///
/// M10a additionally injects the genuine musl samples into the ext2 volume
/// (`/bin/busybox`, `/lib/ld-musl-x86_64.so.1`, `/lib/libc.musl-x86_64.so.1`),
/// creating the two directories; the host re-checks those bytes after each boot.
pub fn format_images_with_injected_elfs(
    dyn_main: &[u8],
    dyn_interp: &[u8],
    vdso: &[u8],
    m9e: &[u8],
    m9f_a: &[u8],
    m9f_b: &[u8],
    m10a: &Samples,
) -> Result<(), String> {
    format_images_into_with_injected(
        &fat32_image(),
        &ext2_image(),
        dyn_main,
        dyn_interp,
        vdso,
        m9e,
        m9f_a,
        m9f_b,
        m10a,
    )
}

/// [`format_images_with_injected_elfs`] with explicit destinations, so tests can
/// format scratch images without clobbering the disks an acceptance run just
/// produced.
#[cfg(test)]
fn format_images_into(fat_path: &Path, ext_path: &Path) -> Result<(), String> {
    format_images_into_with_injected(
        fat_path,
        ext_path,
        &[],
        &[],
        &[],
        &[],
        &[],
        &[],
        &Samples::empty(),
    )
}

/// [`format_images_into`] with the optional M9d/M9e injected ELFs in the FAT
/// volume: the dynamic main and its interpreter have to be supplied together,
/// and the vDSO image and the shared library are written when supplied (the
/// pair alone is still accepted, which keeps the M9d1-only unit tests
/// meaningful).
fn format_images_into_with_injected(
    fat_path: &Path,
    ext_path: &Path,
    dyn_main: &[u8],
    dyn_interp: &[u8],
    vdso: &[u8],
    m9e: &[u8],
    m9f_a: &[u8],
    m9f_b: &[u8],
    m10a: &Samples,
) -> Result<(), String> {
    let fat = format_fat32_with_injected_set(dyn_main, dyn_interp, vdso, m9e, m9f_a, m9f_b)?;
    fs::write(fat_path, &fat)
        .map_err(|e| io_error(&format!("writing {}", fat_path.display()), e))?;
    let ext = format_ext2(m10a)?;
    fs::write(ext_path, &ext)
        .map_err(|e| io_error(&format!("writing {}", ext_path.display()), e))?;
    Ok(())
}

/// Format an empty FAT32 volume: a bootable-but-fileless volume the guest seeds
/// itself on its first boot.
#[cfg(test)]
fn format_fat32() -> Result<Vec<u8>, String> {
    format_fat32_with_injected(&[], &[], &[])
}

/// [`format_fat32_with_injected_set`] without the M9e shared library: the
/// M9d-only shapes the older unit tests exercise.
#[cfg(test)]
fn format_fat32_with_injected(
    dyn_main: &[u8],
    dyn_interp: &[u8],
    vdso: &[u8],
) -> Result<Vec<u8>, String> {
    format_fat32_with_injected_set(dyn_main, dyn_interp, vdso, &[], &[], &[])
}

/// Format the FAT32 volume, optionally seeding the M9d/M9e injected ELFs
/// before unmounting so the guest sees the files from its very first boot.
fn format_fat32_with_injected_set(
    dyn_main: &[u8],
    dyn_interp: &[u8],
    vdso: &[u8],
    m9e: &[u8],
    m9f_a: &[u8],
    m9f_b: &[u8],
) -> Result<Vec<u8>, String> {
    if dyn_main.is_empty() != dyn_interp.is_empty() {
        return Err("M9d: both dynamic ELF images are required together".to_string());
    }
    if !vdso.is_empty() && dyn_main.is_empty() {
        return Err("M9d: the vDSO image requires the dynamic ELF pair".to_string());
    }
    if !m9e.is_empty() && dyn_main.is_empty() {
        return Err("M9e: the shared library requires the dynamic ELF pair".to_string());
    }
    if m9f_a.is_empty() != m9f_b.is_empty() {
        return Err("M9f: both chained shared libraries are required together".to_string());
    }
    if !m9f_a.is_empty() && dyn_main.is_empty() {
        return Err("M9f: the chained shared libraries require the dynamic ELF pair".to_string());
    }
    let mut device = MemDisk::new(FAT32_DISK_BYTES / DEV_BLOCK_SIZE as u64, DEV_BLOCK_SIZE);
    // One-sector clusters on purpose: the library's size-derived default picks
    // 16 sectors/cluster at 64 MiB, which leaves only ~8 k clusters — below the
    // FAT32 specification minimum of 65 525. With one-sector clusters the volume
    // carries ~129 k clusters and stays spec-conformant (the stale on-disk
    // layout that made this impossible was fixed in `libs/fat32`).
    let options = FormatOptions {
        sectors_per_cluster: 1,
        ..FormatOptions::default()
    };
    let mut fs = fat32::format(&mut device, &options)
        .map_err(|e| format!("formatting the FAT32 volume: {e:?}"))?;
    if !dyn_main.is_empty() {
        write_injected_elf(&mut fs, FAT_DYN_MAIN, dyn_main, "main program")?;
        write_injected_elf(&mut fs, FAT_DYN_INTERP, dyn_interp, "interpreter")?;
    }
    if !vdso.is_empty() {
        write_injected_elf(&mut fs, FAT_VDSO, vdso, "vDSO image")?;
    }
    if !m9e.is_empty() {
        write_injected_elf(&mut fs, FAT_M9E, m9e, "shared library")?;
    }
    if !m9f_a.is_empty() {
        write_injected_elf(&mut fs, FAT_M9F_A, m9f_a, "M9f shared library A")?;
        write_injected_elf(&mut fs, FAT_M9F_B, m9f_b, "M9f shared library B")?;
    }
    fs.sync()
        .map_err(|e| format!("sync of the FAT32 volume: {e:?}"))?;
    let device = fs
        .unmount()
        .map_err(|e| format!("unmounting the FAT32 volume: {e:?}"))?;
    Ok(device.data().to_vec())
}

/// Create one M9d injected file on the freshly formatted volume. The error text
/// names the role so a failed injection is not mistaken for a guest fault.
fn write_injected_elf<D: block::BlockDevice>(
    fs: &mut Fat32<D>,
    name: &str,
    bytes: &[u8],
    role: &str,
) -> Result<(), String> {
    let root = fs.root();
    let mut node = fs
        .create(&root, name, fat32::NodeKind::File)
        .map_err(|e| format!("creating the injected {role} {name}: {e:?}"))?;
    fs.write(&mut node, 0, bytes)
        .map_err(|e| format!("writing the injected {role} {name}: {e:?}"))?;
    Ok(())
}

/// Format an ext2 volume: empty by default, or seeded with the M10a samples.
///
/// The guest seeds the M5 state/data files itself, so nothing M5-related may be
/// written here. The M10a samples are different: they are real third-party
/// binaries the host injects before the run and re-checks after each boot.
fn format_ext2(m10a: &Samples) -> Result<Vec<u8>, String> {
    let mut device = MemDisk::new(EXT2_DISK_BYTES / DEV_BLOCK_SIZE as u64, DEV_BLOCK_SIZE);
    ext2::format(&mut device).map_err(|e| format!("formatting the ext2 volume: {e:?}"))?;
    let mut fs = Ext2::mount(device).map_err(|e| format!("mounting the new ext2 volume: {e:?}"))?;
    if !m10a.is_empty() {
        write_ext2_samples(&mut fs, m10a)?;
    }
    fs.sync()
        .map_err(|e| format!("sync of the empty ext2 volume: {e:?}"))?;
    let device = fs.into_device();
    Ok(device.data().to_vec())
}

/// Create `/bin` and `/lib` and write the three M10a samples byte for byte.
fn write_ext2_samples<D: block::BlockDevice>(
    fs: &mut Ext2<D>,
    m10a: &Samples,
) -> Result<(), String> {
    if m10a.busybox.is_empty() || m10a.ld_musl.is_empty() || m10a.libc_musl.is_empty() {
        return Err("M10a: all three samples are required together".to_string());
    }
    let root = fs
        .root()
        .map_err(|e| format!("reading the ext2 root: {e:?}"))?;
    let bin = fs
        .create(root.inode, EXT2_BIN_DIR, ext2::NodeKind::Directory)
        .map_err(|e| format!("creating the ext2 /bin directory: {e:?}"))?;
    let lib = fs
        .create(root.inode, EXT2_LIB_DIR, ext2::NodeKind::Directory)
        .map_err(|e| format!("creating the ext2 /lib directory: {e:?}"))?;
    write_ext2_sample_file(fs, bin.inode, EXT2_BUSYBOX, &m10a.busybox, "/bin/busybox")?;
    write_ext2_sample_file(
        fs,
        lib.inode,
        EXT2_LD_MUSL,
        &m10a.ld_musl,
        "/lib/ld-musl-x86_64.so.1",
    )?;
    write_ext2_sample_file(
        fs,
        lib.inode,
        EXT2_LIBC_MUSL,
        &m10a.libc_musl,
        "/lib/libc.musl-x86_64.so.1",
    )?;
    Ok(())
}

/// Write one M10a sample into a directory of the freshly formatted ext2 volume.
fn write_ext2_sample_file<D: block::BlockDevice>(
    fs: &mut Ext2<D>,
    parent: u32,
    name: &[u8],
    bytes: &[u8],
    path: &str,
) -> Result<(), String> {
    let node = fs
        .create(parent, name, ext2::NodeKind::File)
        .map_err(|e| format!("creating the injected {path}: {e:?}"))?;
    let written = fs
        .write(node.inode, 0, bytes)
        .map_err(|e| format!("writing the injected {path}: {e:?}"))?;
    if written != bytes.len() {
        return Err(format!(
            "writing the injected {path}: wrote {written} of {} bytes",
            bytes.len()
        ));
    }
    Ok(())
}

/// Read one ext2 file by inode, for the host-side byte comparison.
fn read_ext2_node(fs: &mut Ext2<MemDisk>, inode: u32, path: &str) -> Result<Vec<u8>, String> {
    let node = fs
        .stat(inode)
        .map_err(|e| format!("{path}: stat failed ({e:?})"))?;
    let size =
        usize::try_from(node.size).map_err(|_| format!("{path} is too large for the host"))?;
    let mut buf = vec![0u8; size];
    if size != 0 {
        let read = fs
            .read(inode, 0, &mut buf)
            .map_err(|e| format!("reading {path}: {e:?}"))?;
        if read != size {
            return Err(format!("{path} read back {read} of {size} bytes"));
        }
    }
    Ok(buf)
}

/// Compare the three injected M10a samples on the ext2 volume byte for byte.
///
/// Called after each boot: the guest must neither lose nor rewrite the files,
/// and the directories must still be there.
pub fn verify_m10a_samples(image: &[u8], m10a: &Samples) -> Result<(), String> {
    if m10a.is_empty() {
        return Ok(());
    }
    let mut fs = mount_ext2(image)?;
    let root = fs
        .root()
        .map_err(|e| format!("reading the ext2 root: {e:?}"))?;
    let bin = fs
        .lookup(root.inode, EXT2_BIN_DIR)
        .map_err(|e| format!("the injected /bin directory is missing ({e:?})"))?;
    if bin.kind != ext2::NodeKind::Directory {
        return Err("the injected /bin entry is not a directory".to_string());
    }
    let busybox = fs
        .lookup(bin.inode, EXT2_BUSYBOX)
        .map_err(|e| format!("the injected /bin/busybox is missing ({e:?})"))?;
    let bytes = read_ext2_node(&mut fs, busybox.inode, "/bin/busybox")?;
    expect_bytes(&bytes, &m10a.busybox, "/bin/busybox on the ext2 volume")?;

    let lib = fs
        .lookup(root.inode, EXT2_LIB_DIR)
        .map_err(|e| format!("the injected /lib directory is missing ({e:?})"))?;
    if lib.kind != ext2::NodeKind::Directory {
        return Err("the injected /lib entry is not a directory".to_string());
    }
    let loader = fs
        .lookup(lib.inode, EXT2_LD_MUSL)
        .map_err(|e| format!("the injected /lib/ld-musl-x86_64.so.1 is missing ({e:?})"))?;
    let bytes = read_ext2_node(&mut fs, loader.inode, "/lib/ld-musl-x86_64.so.1")?;
    expect_bytes(
        &bytes,
        &m10a.ld_musl,
        "/lib/ld-musl-x86_64.so.1 on the ext2 volume",
    )?;
    let libc = fs
        .lookup(lib.inode, EXT2_LIBC_MUSL)
        .map_err(|e| format!("the injected /lib/libc.musl-x86_64.so.1 is missing ({e:?})"))?;
    let bytes = read_ext2_node(&mut fs, libc.inode, "/lib/libc.musl-x86_64.so.1")?;
    expect_bytes(
        &bytes,
        &m10a.libc_musl,
        "/lib/libc.musl-x86_64.so.1 on the ext2 volume",
    )?;
    Ok(())
}

/// On-disk variant of [`verify_m10a_samples`], reading `target/m5b-ext2.img`.
pub fn verify_m10a_samples_on_disk(m10a: &Samples) -> Result<(), String> {
    if m10a.is_empty() {
        return Ok(());
    }
    let image = read_image(ext2_image(), "ext2", EXT2_DISK_BYTES)?;
    verify_m10a_samples(&image, m10a)
}

/// Read a raw image from disk and check its size.
fn read_image(image: PathBuf, label: &str, expected: u64) -> Result<Vec<u8>, String> {
    let bytes = fs::read(&image)
        .map_err(|e| io_error(&format!("reading the {label} image {}", image.display()), e))?;
    check_image_size(&bytes, label, expected)?;
    Ok(bytes)
}

fn check_image_size(bytes: &[u8], label: &str, expected: u64) -> Result<(), String> {
    if bytes.len() as u64 != expected {
        return Err(format!(
            "the {label} image is {} bytes, expected {expected}",
            bytes.len()
        ));
    }
    Ok(())
}

fn mount_fat32(bytes: &[u8]) -> Result<Fat32<MemDisk>, String> {
    check_image_size(bytes, "FAT32", FAT32_DISK_BYTES)?;
    Fat32::mount(MemDisk::from_bytes(bytes.to_vec(), DEV_BLOCK_SIZE))
        .map_err(|e| format!("mounting the FAT32 image: {e:?}"))
}

fn mount_ext2(bytes: &[u8]) -> Result<Ext2<MemDisk>, String> {
    check_image_size(bytes, "ext2", EXT2_DISK_BYTES)?;
    Ext2::mount(MemDisk::from_bytes(bytes.to_vec(), DEV_BLOCK_SIZE))
        .map_err(|e| format!("mounting the ext2 image: {e:?}"))
}

fn read_fat_file(
    fs: &mut Fat32<MemDisk>,
    node: &fat32::FatNode,
    name: &str,
) -> Result<Vec<u8>, String> {
    let size =
        usize::try_from(node.size).map_err(|_| format!("/{name} is too large for the host"))?;
    let mut buf = vec![0u8; size];
    if size != 0 {
        let read = fs
            .read(node, 0, &mut buf)
            .map_err(|e| format!("reading /{name}: {e:?}"))?;
        if read != size {
            return Err(format!("/{name} read back {read} of {size} bytes"));
        }
    }
    Ok(buf)
}

fn fat_file(fs: &mut Fat32<MemDisk>, name: &str, what: &str) -> Result<Vec<u8>, String> {
    let root = fs.root();
    let node = fs
        .lookup(&root, name)
        .map_err(|e| format!("{what}: /{name} is missing ({e:?})"))?;
    read_fat_file(fs, &node, name)
}

fn expect_bytes(actual: &[u8], expected: &[u8], what: &str) -> Result<(), String> {
    if actual != expected {
        let at = actual
            .iter()
            .zip(expected)
            .position(|(a, b)| a != b)
            .unwrap_or_else(|| actual.len().min(expected.len()));
        return Err(format!(
            "{what}: {} bytes, expected {}; first difference at offset {at}",
            actual.len(),
            expected.len()
        ));
    }
    Ok(())
}

fn ext2_file(fs: &mut Ext2<MemDisk>, name: &[u8], what: &str) -> Result<Vec<u8>, String> {
    let root = fs
        .root()
        .map_err(|e| format!("reading the ext2 root: {e:?}"))?;
    let node = fs.lookup(root.inode, name).map_err(|e| {
        format!(
            "{what}: /{} is missing ({e:?})",
            String::from_utf8_lossy(name)
        )
    })?;
    let size = usize::try_from(node.size).map_err(|_| format!("the ext2 file is too large"))?;
    let mut buf = vec![0u8; size];
    if size != 0 {
        let read = fs
            .read(node.inode, 0, &mut buf)
            .map_err(|e| format!("reading /{}: {e:?}", String::from_utf8_lossy(name)))?;
        if read != size {
            return Err(format!(
                "/{} read back {read} of {size} bytes",
                String::from_utf8_lossy(name)
            ));
        }
    }
    Ok(buf)
}

fn fat32_missing(fs: &mut Fat32<MemDisk>, name: &str, what: &str) -> Result<(), String> {
    let root = fs.root();
    match fs.lookup(&root, name) {
        Err(fat32::Fat32Error::NotFound) => Ok(()),
        Err(e) => Err(format!(
            "{what}: unexpected error looking up /{name} ({e:?})"
        )),
        Ok(_) => Err(format!("{what}: /{name} still exists but should be absent")),
    }
}

fn ext2_missing(fs: &mut Ext2<MemDisk>, name: &[u8], what: &str) -> Result<(), String> {
    let root = fs
        .root()
        .map_err(|e| format!("reading the ext2 root: {e:?}"))?;
    match fs.lookup(root.inode, name) {
        Err(ext2::Error::NotFound) => Ok(()),
        Err(e) => Err(format!(
            "{what}: unexpected error looking up /{} ({e:?})",
            String::from_utf8_lossy(name)
        )),
        Ok(_) => Err(format!(
            "{what}: /{} still exists but should be absent",
            String::from_utf8_lossy(name)
        )),
    }
}

/// Read a FAT32 file and require it to equal `expected` exactly.
fn expect_fat32_file(
    fs: &mut Fat32<MemDisk>,
    name: &str,
    expected: &[u8],
    what: &str,
) -> Result<(), String> {
    let bytes = fat_file(fs, name, what)?;
    expect_bytes(&bytes, expected, what)
}

/// Read an ext2 file and require it to equal `expected` exactly.
fn expect_ext2_file(
    fs: &mut Ext2<MemDisk>,
    name: &[u8],
    expected: &[u8],
    what: &str,
) -> Result<(), String> {
    let bytes = ext2_file(fs, name, what)?;
    expect_bytes(&bytes, expected, what)
}

/// Image-level check of the map file: exactly [`MAP_LEN`] bytes in the final
/// post-mmap state, with only the two shared-mapping edits applied.
fn expect_map_bytes(actual: &[u8], what: &str) -> Result<(), String> {
    if actual.len() != MAP_LEN {
        return Err(format!(
            "{what}: {} bytes, expected {MAP_LEN}",
            actual.len()
        ));
    }
    // The private mapping writes `0xFF` at offset 0 in memory only. If that byte
    // is on disk the private page was written back, which is a semantic failure
    // worth its own message (and would otherwise surface as a diff at offset 0).
    if actual[0] == MAP_PRIVATE_BYTE {
        return Err(format!(
            "{what}: the private mapping's 0x{MAP_PRIVATE_BYTE:02X} at offset 0 reached the volume"
        ));
    }
    expect_bytes(actual, &map_final(), what)
}

/// Read the FAT32 map file and require the final shared-mmap state.
fn expect_fat32_map(fs: &mut Fat32<MemDisk>, what: &str) -> Result<(), String> {
    let bytes = fat_file(fs, FAT_MAP, what)?;
    expect_map_bytes(&bytes, what)
}

/// Read the ext2 map file and require the final shared-mmap state.
fn expect_ext2_map(fs: &mut Ext2<MemDisk>, what: &str) -> Result<(), String> {
    let bytes = ext2_file(fs, EXT2_MAP, what)?;
    expect_map_bytes(&bytes, what)
}

/// Check the M5c3 sparse file on a FAT32 volume: exact final size, zeros across
/// the hole and the `HOLE` tail. A stale block inside the hole shows up as a
/// `first difference at offset N` inside the zero range.
fn expect_fat32_hole(fs: &mut Fat32<MemDisk>, what: &str) -> Result<(), String> {
    let bytes = fat_file(fs, FAT_HOLE, what)?;
    expect_hole_bytes(&bytes, what)
}

/// ext2 counterpart of [`expect_fat32_hole`].
fn expect_ext2_hole(fs: &mut Ext2<MemDisk>, what: &str) -> Result<(), String> {
    let bytes = ext2_file(fs, EXT2_HOLE, what)?;
    expect_hole_bytes(&bytes, what)
}

fn expect_hole_bytes(actual: &[u8], what: &str) -> Result<(), String> {
    if actual.len() != HOLE_LEN {
        return Err(format!(
            "{what}: {} bytes, expected {HOLE_LEN}",
            actual.len()
        ));
    }
    // The acceptance names three probe offsets explicitly; check them first so a
    // failure points at the contract rather than at an arbitrary byte.
    for probe in [0usize, 4096, HOLE_ZEROS - 1] {
        if actual[probe] != 0 {
            return Err(format!(
                "{what}: offset {probe} holds 0x{:02X}, the sparse hole must read back as zero",
                actual[probe]
            ));
        }
    }
    let tail = &actual[HOLE_ZEROS..];
    if tail != HOLE_TAIL {
        return Err(format!("{what}: tail {tail:?} is not {HOLE_TAIL:?}"));
    }
    expect_bytes(actual, &hole_bytes(), what)
}

/// Read the FAT32 fault-injection file and require the recovered content.
fn expect_fat32_fault(fs: &mut Fat32<MemDisk>, what: &str) -> Result<(), String> {
    let bytes = fat_file(fs, FAT_FAULT, what)?;
    expect_fault_bytes(&bytes, what)
}

/// ext2 counterpart of [`expect_fat32_fault`].
fn expect_ext2_fault(fs: &mut Ext2<MemDisk>, what: &str) -> Result<(), String> {
    let bytes = ext2_file(fs, EXT2_FAULT, what)?;
    expect_fault_bytes(&bytes, what)
}

/// The contract names a 16-byte file while the marker literal itself is 15 bytes,
/// so accept exactly the literal or the literal plus its trailing newline. Any
/// other length or content is a failure: a half-recovered write must not pass.
fn expect_fault_bytes(actual: &[u8], what: &str) -> Result<(), String> {
    if actual == FAULT_MARKER || actual == fault_expected() {
        return Ok(());
    }
    let expected = fault_expected();
    let at = actual
        .iter()
        .zip(&expected)
        .position(|(a, b)| a != b)
        .unwrap_or_else(|| actual.len().min(expected.len()));
    Err(format!(
        "{what}: {} bytes {:?}, expected {FAULT_LEN} bytes {expected:?}; first difference at offset {at}",
        actual.len(),
        String::from_utf8_lossy(actual)
    ))
}

/// Host-side check after the first boot: state marker plus the original 8192
/// pattern bytes, in both filesystems, plus the M5c user file and the M5c2 map
/// file in their *final* states (the shared mapping has already run and synced
/// by the time the first boot ends).
pub fn verify_first_boot() -> Result<(), String> {
    verify_first_boot_images(
        &read_image(fat32_image(), "FAT32", FAT32_DISK_BYTES)?,
        &read_image(ext2_image(), "ext2", EXT2_DISK_BYTES)?,
    )
}

/// Image-level form of [`verify_first_boot`], so the host checks themselves are
/// testable without a QEMU run.
fn verify_first_boot_images(fat_image: &[u8], ext_image: &[u8]) -> Result<(), String> {
    let mut fat = mount_fat32(fat_image)?;
    let state = fat_file(&mut fat, FAT_STATE, "first boot")?;
    expect_bytes(&state, STATE_BYTES, "first boot FAT32 state")?;
    let data = fat_file(&mut fat, FAT_DATA, "first boot")?;
    expect_bytes(&data, &pattern(DATA_INITIAL_LEN), "first boot FAT32 data")?;
    // M5c1: the user program created its file on this volume, with the exact
    // first-boot content.
    expect_fat32_file(
        &mut fat,
        FAT_USER,
        M5C1_FIRST_MARKER,
        "first boot FAT32 user file",
    )?;
    // M5c2: by the end of the first boot the shared mapping has already edited
    // the map file and synced, so the *final* state is what the host must see.
    expect_fat32_map(&mut fat, "first boot FAT32 map file")?;
    // M5c3: both boots CREATE|TRUNC the sparse and fault-injection files, so the
    // same final content must be on disk after the first boot as well.
    expect_fat32_hole(&mut fat, "first boot FAT32 sparse file")?;
    expect_fat32_fault(&mut fat, "first boot FAT32 fault file")?;
    fat32_missing(&mut fat, FAT_DONE, "first boot")?;

    let mut ext = mount_ext2(ext_image)?;
    let state = ext2_file(&mut ext, EXT2_STATE, "first boot")?;
    expect_bytes(&state, STATE_BYTES, "first boot ext2 state")?;
    let data = ext2_file(&mut ext, EXT2_DATA, "first boot")?;
    expect_bytes(&data, &pattern(DATA_INITIAL_LEN), "first boot ext2 data")?;
    expect_ext2_file(
        &mut ext,
        EXT2_USER,
        M5C1_FIRST_MARKER,
        "first boot ext2 user file",
    )?;
    expect_ext2_map(&mut ext, "first boot ext2 map file")?;
    expect_ext2_hole(&mut ext, "first boot ext2 sparse file")?;
    expect_ext2_fault(&mut ext, "first boot ext2 fault file")?;
    ext2_missing(&mut ext, EXT2_DONE, "first boot")?;
    Ok(())
}

/// Host-side check after the second boot: state survives the reboot, the data
/// file was renamed, it holds exactly the first 4608 pattern bytes, the M5c user
/// file carries the second-boot marker, and the M5c2 map file still holds exactly
/// the two shared-mapping edits from the first boot.
pub fn verify_second_boot() -> Result<(), String> {
    verify_second_boot_images(
        &read_image(fat32_image(), "FAT32", FAT32_DISK_BYTES)?,
        &read_image(ext2_image(), "ext2", EXT2_DISK_BYTES)?,
    )
}

/// Image-level form of [`verify_second_boot`].
fn verify_second_boot_images(fat_image: &[u8], ext_image: &[u8]) -> Result<(), String> {
    let mut fat = mount_fat32(fat_image)?;
    let state = fat_file(&mut fat, FAT_STATE, "second boot")?;
    expect_bytes(&state, STATE_BYTES, "second boot FAT32 state")?;
    let done = fat_file(&mut fat, FAT_DONE, "second boot")?;
    if done.len() as u64 != DATA_FINAL_LEN {
        return Err(format!(
            "second boot FAT32 data: {} bytes, expected {DATA_FINAL_LEN}",
            done.len()
        ));
    }
    expect_bytes(
        &done,
        &pattern(DATA_FINAL_LEN as usize),
        "second boot FAT32 data",
    )?;
    // M5c1: the second boot rewrote the user file with the appended marker.
    expect_fat32_file(
        &mut fat,
        FAT_USER,
        M5C1_SECOND_MARKER,
        "second boot FAT32 user file",
    )?;
    // M5c2: the second boot only has to re-verify the map (its edits persisted
    // from the first boot), so the final state must still be exact.
    expect_fat32_map(&mut fat, "second boot FAT32 map file")?;
    // M5c3: the second boot recreates both files from scratch (CREATE|TRUNC), so
    // the content must be the same as after the first boot, not stale bytes.
    expect_fat32_hole(&mut fat, "second boot FAT32 sparse file")?;
    expect_fat32_fault(&mut fat, "second boot FAT32 fault file")?;
    fat32_missing(&mut fat, FAT_DATA, "second boot")?;

    let mut ext = mount_ext2(ext_image)?;
    let state = ext2_file(&mut ext, EXT2_STATE, "second boot")?;
    expect_bytes(&state, STATE_BYTES, "second boot ext2 state")?;
    let done = ext2_file(&mut ext, EXT2_DONE, "second boot")?;
    if done.len() as u64 != DATA_FINAL_LEN {
        return Err(format!(
            "second boot ext2 data: {} bytes, expected {DATA_FINAL_LEN}",
            done.len()
        ));
    }
    expect_bytes(
        &done,
        &pattern(DATA_FINAL_LEN as usize),
        "second boot ext2 data",
    )?;
    expect_ext2_file(
        &mut ext,
        EXT2_USER,
        M5C1_SECOND_MARKER,
        "second boot ext2 user file",
    )?;
    expect_ext2_map(&mut ext, "second boot ext2 map file")?;
    expect_ext2_hole(&mut ext, "second boot ext2 sparse file")?;
    expect_ext2_fault(&mut ext, "second boot ext2 fault file")?;
    ext2_missing(&mut ext, EXT2_DATA, "second boot")?;
    Ok(())
}

/// [`verify_injected_elfs_set`] without the M9e shared library: the M9d-only
/// shapes the older unit tests exercise.
#[cfg(test)]
pub fn verify_injected_elfs(
    fat_image: &[u8],
    dyn_main: &[u8],
    dyn_interp: &[u8],
    vdso: &[u8],
) -> Result<(), String> {
    verify_injected_elfs_set(fat_image, dyn_main, dyn_interp, vdso, &[], &[], &[])
}

/// Host-side check for the M9d/M9e injected ELFs: when the acceptance run
/// injected them, they must still be on the FAT volume, byte for byte, on every
/// boot. The M9d1 pair, the M9d2 vDSO image and the M9e shared library are each
/// optional, but the later ones require the pair. Empty slices mean nothing was
/// injected, so the check is skipped (the M5/M6 volumes stay untouched).
pub fn verify_injected_elfs_set(
    fat_image: &[u8],
    dyn_main: &[u8],
    dyn_interp: &[u8],
    vdso: &[u8],
    m9e: &[u8],
    m9f_a: &[u8],
    m9f_b: &[u8],
) -> Result<(), String> {
    if dyn_main.is_empty()
        && dyn_interp.is_empty()
        && vdso.is_empty()
        && m9e.is_empty()
        && m9f_a.is_empty()
        && m9f_b.is_empty()
    {
        return Ok(());
    }
    if dyn_main.is_empty() != dyn_interp.is_empty() {
        return Err("M9d: the host check needs both dynamic ELF images".to_string());
    }
    if !vdso.is_empty() && dyn_main.is_empty() {
        return Err(
            "M9d: the host check needs the dynamic ELF pair for the vDSO image".to_string(),
        );
    }
    if !m9e.is_empty() && dyn_main.is_empty() {
        return Err(
            "M9e: the host check needs the dynamic ELF pair for the shared library".to_string(),
        );
    }
    if m9f_a.is_empty() != m9f_b.is_empty() {
        return Err("M9f: the host check needs both chained shared libraries".to_string());
    }
    if !m9f_a.is_empty() && dyn_main.is_empty() {
        return Err(
            "M9f: the host check needs the dynamic ELF pair for the chained libraries".to_string(),
        );
    }
    let mut fat = mount_fat32(fat_image)?;
    expect_fat32_file(&mut fat, FAT_DYN_MAIN, dyn_main, "M9d dynamic main")?;
    expect_fat32_file(&mut fat, FAT_DYN_INTERP, dyn_interp, "M9d interpreter")?;
    if !vdso.is_empty() {
        expect_fat32_file(&mut fat, FAT_VDSO, vdso, "M9d vDSO image")?;
    }
    if !m9e.is_empty() {
        expect_fat32_file(&mut fat, FAT_M9E, m9e, "M9e shared library")?;
    }
    if !m9f_a.is_empty() {
        expect_fat32_file(&mut fat, FAT_M9F_A, m9f_a, "M9f shared library A")?;
        expect_fat32_file(&mut fat, FAT_M9F_B, m9f_b, "M9f shared library B")?;
    }
    Ok(())
}

/// Read the on-disk FAT volume and verify the M9d injected ELFs against the bytes
/// the run injected. Called after each boot of an M9d acceptance run.
pub fn verify_injected_elfs_on_disk(
    dyn_main: &[u8],
    dyn_interp: &[u8],
    vdso: &[u8],
    m9e: &[u8],
    m9f_a: &[u8],
    m9f_b: &[u8],
) -> Result<(), String> {
    if dyn_main.is_empty()
        && dyn_interp.is_empty()
        && vdso.is_empty()
        && m9e.is_empty()
        && m9f_a.is_empty()
        && m9f_b.is_empty()
    {
        return Ok(());
    }
    let fat = read_image(fat32_image(), "FAT32", FAT32_DISK_BYTES)?;
    verify_injected_elfs_set(&fat, dyn_main, dyn_interp, vdso, m9e, m9f_a, m9f_b)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_fat32_injects_the_injected_elf_set() {
        let dyn_main = b"\x7fELF-main-bytes".to_vec();
        let dyn_interp = b"\x7fELF-interp-bytes".to_vec();
        let vdso = b"\x7fELF-vdso-bytes".to_vec();
        let image = format_fat32_with_injected(&dyn_main, &dyn_interp, &vdso)
            .expect("formatting with the injected ELFs");
        check_image_size(&image, "FAT32", FAT32_DISK_BYTES).expect("image size");
        let mut fat = mount_fat32(&image).expect("mounting the injected volume");
        expect_fat32_file(
            &mut fat,
            FAT_DYN_MAIN,
            &dyn_main,
            "M9d dynamic main readback",
        )
        .expect("dynamic main readback");
        expect_fat32_file(
            &mut fat,
            FAT_DYN_INTERP,
            &dyn_interp,
            "M9d interpreter readback",
        )
        .expect("interpreter readback");
        expect_fat32_file(&mut fat, FAT_VDSO, &vdso, "M9d vDSO readback").expect("vDSO readback");
    }

    #[test]
    fn format_fat32_accepts_the_dynamic_pair_alone() {
        let dyn_main = b"\x7fELF-main".to_vec();
        let dyn_interp = b"\x7fELF-interp".to_vec();
        let image = format_fat32_with_injected(&dyn_main, &dyn_interp, &[])
            .expect("the M9d1 pair alone is still a valid injection");
        let mut fat = mount_fat32(&image).expect("mounting the volume");
        expect_fat32_file(&mut fat, FAT_DYN_MAIN, &dyn_main, "pair-only main")
            .expect("pair-only main");
    }

    #[test]
    fn format_fat32_rejects_a_partial_dynamic_pair() {
        let dyn_main = b"\x7fELF-main".to_vec();
        let error = format_fat32_with_injected(&dyn_main, &[], &[])
            .expect_err("half a pair must be rejected");
        assert!(error.contains("both dynamic ELF images"), "{error}");
        let dyn_interp = b"\x7fELF-interp".to_vec();
        let error = format_fat32_with_injected(&[], &dyn_interp, &[])
            .expect_err("half a pair must be rejected");
        assert!(error.contains("both dynamic ELF images"), "{error}");
    }

    #[test]
    fn format_fat32_rejects_a_vdso_without_the_pair() {
        let vdso = b"\x7fELF-vdso".to_vec();
        let error = format_fat32_with_injected(&[], &[], &vdso)
            .expect_err("a vDSO without the pair must be rejected");
        assert!(error.contains("requires the dynamic ELF pair"), "{error}");
    }

    #[test]
    fn verify_injected_elfs_skips_when_nothing_was_injected() {
        verify_injected_elfs(&[], &[], &[], &[]).expect("an empty check is a no-op");
    }

    #[test]
    fn verify_injected_elfs_rejects_a_missing_pair() {
        let dyn_main = b"\x7fELF-main".to_vec();
        let dyn_interp = b"\x7fELF-interp".to_vec();
        let image = format_fat32_with_injected(&dyn_main, &dyn_interp, &[])
            .expect("formatting with the pair");
        verify_injected_elfs(&image, &dyn_main, &dyn_interp, &[]).expect("pair present");

        let broken = remove_fat32_entry(&image, FAT_DYN_INTERP);
        let error = verify_injected_elfs(&broken, &dyn_main, &dyn_interp, &[])
            .expect_err("a missing interpreter must be rejected");
        assert!(
            error.contains(FAT_DYN_INTERP) || error.contains("interpreter"),
            "{error}"
        );
    }

    #[test]
    fn verify_injected_elfs_rejects_a_missing_vdso() {
        let dyn_main = b"\x7fELF-main".to_vec();
        let dyn_interp = b"\x7fELF-interp".to_vec();
        let vdso = b"\x7fELF-vdso".to_vec();
        let image = format_fat32_with_injected(&dyn_main, &dyn_interp, &vdso)
            .expect("formatting with the injected ELFs");
        verify_injected_elfs(&image, &dyn_main, &dyn_interp, &vdso).expect("all three present");

        let broken = remove_fat32_entry(&image, FAT_VDSO);
        let error = verify_injected_elfs(&broken, &dyn_main, &dyn_interp, &vdso)
            .expect_err("a missing vDSO image must be rejected");
        assert!(
            error.contains(FAT_VDSO) || error.contains("vDSO"),
            "{error}"
        );
    }

    #[test]
    fn format_fat32_injects_the_shared_library() {
        let dyn_main = b"\x7fELF-main-bytes".to_vec();
        let dyn_interp = b"\x7fELF-interp-bytes".to_vec();
        let vdso = b"\x7fELF-vdso-bytes".to_vec();
        let m9e = b"\x7fELF-m9e-bytes".to_vec();
        let image = format_fat32_with_injected_set(&dyn_main, &dyn_interp, &vdso, &m9e, &[], &[])
            .expect("formatting with the injected ELF set");
        check_image_size(&image, "FAT32", FAT32_DISK_BYTES).expect("image size");
        let mut fat = mount_fat32(&image).expect("mounting the injected volume");
        expect_fat32_file(&mut fat, FAT_M9E, &m9e, "M9e shared-library readback")
            .expect("shared-library readback");
    }

    #[test]
    fn format_fat32_rejects_a_shared_library_without_the_pair() {
        let m9e = b"\x7fELF-m9e".to_vec();
        let error = format_fat32_with_injected_set(&[], &[], &[], &m9e, &[], &[])
            .expect_err("a shared library without the pair must be rejected");
        assert!(error.contains("requires the dynamic ELF pair"), "{error}");
    }

    #[test]
    fn verify_injected_elfs_rejects_a_missing_shared_library() {
        let dyn_main = b"\x7fELF-main".to_vec();
        let dyn_interp = b"\x7fELF-interp".to_vec();
        let vdso = b"\x7fELF-vdso".to_vec();
        let m9e = b"\x7fELF-m9e".to_vec();
        let image = format_fat32_with_injected_set(&dyn_main, &dyn_interp, &vdso, &m9e, &[], &[])
            .expect("formatting with the injected ELF set");
        verify_injected_elfs_set(&image, &dyn_main, &dyn_interp, &vdso, &m9e, &[], &[])
            .expect("all four present");

        let broken = remove_fat32_entry(&image, FAT_M9E);
        let error =
            verify_injected_elfs_set(&broken, &dyn_main, &dyn_interp, &vdso, &m9e, &[], &[])
                .expect_err("a missing shared library must be rejected");
        assert!(
            error.contains(FAT_M9E) || error.contains("shared library"),
            "{error}"
        );
    }

    #[test]
    fn format_fat32_injects_the_shared_library_chain() {
        let dyn_main = b"\x7fELF-main-bytes".to_vec();
        let dyn_interp = b"\x7fELF-interp-bytes".to_vec();
        let vdso = b"\x7fELF-vdso-bytes".to_vec();
        let m9e = b"\x7fELF-m9e-bytes".to_vec();
        let m9f_a = b"\x7fELF-m9f-a-bytes".to_vec();
        let m9f_b = b"\x7fELF-m9f-b-bytes".to_vec();
        let image =
            format_fat32_with_injected_set(&dyn_main, &dyn_interp, &vdso, &m9e, &m9f_a, &m9f_b)
                .expect("formatting with the six injected images");
        let mut fat = mount_fat32(&image).expect("mounting the injected volume");
        expect_fat32_file(&mut fat, FAT_M9F_A, &m9f_a, "M9f shared library A readback")
            .expect("A readback");
        expect_fat32_file(&mut fat, FAT_M9F_B, &m9f_b, "M9f shared library B readback")
            .expect("B readback");
    }

    #[test]
    fn format_fat32_rejects_a_partial_shared_library_chain() {
        let dyn_main = b"\x7fELF-main".to_vec();
        let dyn_interp = b"\x7fELF-interp".to_vec();
        let m9f_a = b"\x7fELF-m9f-a".to_vec();
        let m9f_b = b"\x7fELF-m9f-b".to_vec();
        let error = format_fat32_with_injected_set(&dyn_main, &dyn_interp, &[], &[], &m9f_a, &[])
            .expect_err("half the chain must be rejected");
        assert!(error.contains("both chained shared libraries"), "{error}");
        let error = format_fat32_with_injected_set(&dyn_main, &dyn_interp, &[], &[], &[], &m9f_b)
            .expect_err("half the chain must be rejected");
        assert!(error.contains("both chained shared libraries"), "{error}");
    }

    #[test]
    fn verify_injected_elfs_rejects_a_missing_shared_library_chain() {
        let dyn_main = b"\x7fELF-main".to_vec();
        let dyn_interp = b"\x7fELF-interp".to_vec();
        let m9f_a = b"\x7fELF-m9f-a".to_vec();
        let m9f_b = b"\x7fELF-m9f-b".to_vec();
        let image =
            format_fat32_with_injected_set(&dyn_main, &dyn_interp, &[], &[], &m9f_a, &m9f_b)
                .expect("formatting with the chain");
        verify_injected_elfs_set(&image, &dyn_main, &dyn_interp, &[], &[], &m9f_a, &m9f_b)
            .expect("both libraries present");

        let broken = remove_fat32_entry(&image, FAT_M9F_A);
        let error =
            verify_injected_elfs_set(&broken, &dyn_main, &dyn_interp, &[], &[], &m9f_a, &m9f_b)
                .expect_err("a missing A library must be rejected");
        assert!(
            error.contains(FAT_M9F_A) || error.contains("shared library"),
            "{error}"
        );
    }

    #[test]
    fn second_boot_geometry_matches_the_contract() {
        /// Bytes the second boot appends to the data file (guest-side contract).
        const DATA_APPEND_LEN: usize = 1024;
        // The second boot appends 1024 bytes at offset 8192 (length 9216) and
        // then truncates the file to 4608 bytes, so the final file is a strict
        // prefix of the initial pattern.
        assert_eq!(DATA_INITIAL_LEN + DATA_APPEND_LEN, 9216, "append geometry");
        assert_eq!(DATA_FINAL_LEN, 4608, "truncated length");
        assert!(DATA_FINAL_LEN < DATA_INITIAL_LEN as u64);
    }

    #[test]
    fn pattern_is_deterministic_and_matches_the_contract() {
        assert_eq!(pattern(0), Vec::<u8>::new());
        assert_eq!(pattern_byte(0), 7);
        assert_eq!(pattern_byte(1), 20);
        assert_eq!(pattern_byte(250), 245);
        let bytes = pattern(DATA_INITIAL_LEN);
        assert_eq!(bytes.len(), DATA_INITIAL_LEN);
        for (i, byte) in bytes.iter().enumerate() {
            assert_eq!(*byte, ((i * 13 + 7) % 251) as u8, "pattern byte {i}");
        }
    }

    #[test]
    fn state_marker_is_exactly_thirteen_bytes() {
        assert_eq!(STATE_BYTES.len(), 13);
        assert_eq!(STATE_BYTES, b"CAELUM-M5B-V1");
    }

    #[test]
    fn fresh_fat32_volume_has_no_m5b_files() {
        // The harness must hand the guest a clean volume: the first boot is the
        // guest's job to seed, so a fresh image has neither state, data nor done.
        let bytes = format_fat32().expect("formatting FAT32");
        assert_eq!(bytes.len() as u64, FAT32_DISK_BYTES);
        let mut fs = Fat32::mount(MemDisk::from_bytes(bytes, DEV_BLOCK_SIZE)).expect("mounting");
        fat32_missing(&mut fs, FAT_STATE, "fresh FAT32").expect("state must not exist");
        fat32_missing(&mut fs, FAT_DATA, "fresh FAT32").expect("data must not exist");
        fat32_missing(&mut fs, FAT_DONE, "fresh FAT32").expect("done must not exist");
        fat32_missing(&mut fs, FAT_USER, "fresh FAT32").expect("user file must not exist");
        fat32_missing(&mut fs, FAT_MAP, "fresh FAT32").expect("map file must not exist");
        fat32_missing(&mut fs, FAT_HOLE, "fresh FAT32").expect("sparse file must not exist");
        fat32_missing(&mut fs, FAT_FAULT, "fresh FAT32").expect("fault file must not exist");
    }

    #[test]
    fn fresh_ext2_volume_has_no_m5b_files() {
        let bytes = format_ext2(&Samples::empty()).expect("formatting ext2");
        assert_eq!(bytes.len() as u64, EXT2_DISK_BYTES);
        let mut fs = Ext2::mount(MemDisk::from_bytes(bytes, DEV_BLOCK_SIZE)).expect("mounting");
        ext2_missing(&mut fs, EXT2_STATE, "fresh ext2").expect("state must not exist");
        ext2_missing(&mut fs, EXT2_DATA, "fresh ext2").expect("data must not exist");
        ext2_missing(&mut fs, EXT2_DONE, "fresh ext2").expect("done must not exist");
        ext2_missing(&mut fs, EXT2_USER, "fresh ext2").expect("user file must not exist");
        ext2_missing(&mut fs, EXT2_MAP, "fresh ext2").expect("map file must not exist");
        ext2_missing(&mut fs, EXT2_HOLE, "fresh ext2").expect("sparse file must not exist");
        ext2_missing(&mut fs, EXT2_FAULT, "fresh ext2").expect("fault file must not exist");
    }

    #[test]
    fn format_images_writes_empty_volumes() {
        // The exact entry point the QEMU runs use: both on-disk images must be
        // clean, otherwise the guest would take its second-boot branch. Scratch
        // paths on purpose: a unit-test run must not clobber the acceptance disks.
        let dir = crate::target_dir();
        let fat_path = dir.join("m5b-test-fat32.img");
        let ext_path = dir.join("m5b-test-ext2.img");
        format_images_into(&fat_path, &ext_path).expect("formatting scratch disks");
        let fat = fs::read(&fat_path).expect("reading the FAT32 image");
        let ext = fs::read(&ext_path).expect("reading the ext2 image");
        let _ = fs::remove_file(&fat_path);
        let _ = fs::remove_file(&ext_path);
        let mut fat_fs =
            Fat32::mount(MemDisk::from_bytes(fat, DEV_BLOCK_SIZE)).expect("mounting FAT32");
        fat32_missing(&mut fat_fs, FAT_STATE, "format_images").expect("state must not exist");
        fat32_missing(&mut fat_fs, FAT_DATA, "format_images").expect("data must not exist");
        let mut ext_fs =
            Ext2::mount(MemDisk::from_bytes(ext, DEV_BLOCK_SIZE)).expect("mounting ext2");
        ext2_missing(&mut ext_fs, EXT2_STATE, "format_images").expect("state must not exist");
        ext2_missing(&mut ext_fs, EXT2_DATA, "format_images").expect("data must not exist");
    }

    #[test]
    fn first_boot_fixture_holds_the_expected_files() {
        let fat = first_boot_fat32();
        let mut fs =
            Fat32::mount(MemDisk::from_bytes(fat, DEV_BLOCK_SIZE)).expect("mounting FAT32");
        assert_eq!(
            fat_file(&mut fs, FAT_STATE, "test").expect("state"),
            STATE_BYTES
        );
        assert_eq!(
            fat_file(&mut fs, FAT_DATA, "test").expect("data"),
            pattern(DATA_INITIAL_LEN)
        );
        fat32_missing(&mut fs, FAT_DONE, "test").expect("done must not exist yet");
        assert_eq!(
            fat_file(&mut fs, FAT_MAP, "test").expect("map"),
            map_final()
        );
        assert_eq!(
            fat_file(&mut fs, FAT_HOLE, "test").expect("sparse"),
            hole_bytes()
        );
        assert_eq!(
            fat_file(&mut fs, FAT_FAULT, "test").expect("fault"),
            fault_expected()
        );

        let ext = first_boot_ext2();
        let mut fs = Ext2::mount(MemDisk::from_bytes(ext, DEV_BLOCK_SIZE)).expect("mounting ext2");
        assert_eq!(
            ext2_file(&mut fs, EXT2_STATE, "test").expect("state"),
            STATE_BYTES
        );
        assert_eq!(
            ext2_file(&mut fs, EXT2_DATA, "test").expect("data"),
            pattern(DATA_INITIAL_LEN)
        );
        ext2_missing(&mut fs, EXT2_DONE, "test").expect("done must not exist yet");
        assert_eq!(
            ext2_file(&mut fs, EXT2_MAP, "test").expect("map"),
            map_final()
        );
        assert_eq!(
            ext2_file(&mut fs, EXT2_HOLE, "test").expect("sparse"),
            hole_bytes()
        );
        assert_eq!(
            ext2_file(&mut fs, EXT2_FAULT, "test").expect("fault"),
            fault_expected()
        );
    }

    #[test]
    fn formatted_fat32_meets_the_specification_cluster_minimum() {
        // FAT32 requires at least 65525 data clusters; at 64 MiB only
        // one-sector clusters reach the minimum (and the formatter must also
        // write a FAT large enough to address them, which this also covers).
        assert_eq!(FAT32_DISK_BYTES, 64 * 1024 * 1024);
        let bytes = format_fat32().expect("formatting FAT32");
        let fs = Fat32::mount(MemDisk::from_bytes(bytes, DEV_BLOCK_SIZE)).expect("mounting");
        let clusters = fs.layout().cluster_count;
        assert!(
            clusters >= 65_525,
            "cluster count {clusters} is below the FAT32 specification minimum"
        );
    }

    #[test]
    fn first_boot_ext2_fixture_holds_the_expected_files() {
        // The fixture (guest first-boot result), not the empty format, must hold
        // the seeded files; the empty-volume case is covered separately.
        let bytes = first_boot_ext2();
        assert_eq!(bytes.len() as u64, EXT2_DISK_BYTES);
        let mut fs = Ext2::mount(MemDisk::from_bytes(bytes, DEV_BLOCK_SIZE)).expect("mounting");
        assert_eq!(
            ext2_file(&mut fs, EXT2_STATE, "test").expect("state"),
            STATE_BYTES
        );
        assert_eq!(
            ext2_file(&mut fs, EXT2_DATA, "test").expect("data"),
            pattern(DATA_INITIAL_LEN)
        );
        ext2_missing(&mut fs, EXT2_DONE, "test").expect("done must not exist yet");
    }

    #[test]
    fn first_boot_verification_detects_a_missing_file() {
        let mut fat = first_boot_fat32();
        let ext = first_boot_ext2();
        {
            let mut fs =
                Fat32::mount(MemDisk::from_bytes(fat.clone(), DEV_BLOCK_SIZE)).expect("mounting");
            let root = fs.root();
            let state = fs.lookup(&root, FAT_STATE).expect("state node");
            fs.unlink(&state).expect("unlinking state");
            fs.sync().expect("sync");
            fat = fs.unmount().expect("unmounting").data().to_vec();
        }
        let error = verify_first_boot_images(&fat, &ext).expect_err("missing state must fail");
        assert!(error.contains(FAT_STATE), "{error}");
    }

    #[test]
    fn first_boot_result_passes_the_host_check() {
        let fat = first_boot_fat32();
        let ext = first_boot_ext2();
        verify_first_boot_images(&fat, &ext).expect("first boot result");
        // The second boot has not run yet, so its check must fail.
        assert!(verify_second_boot_images(&fat, &ext).is_err());
    }

    #[test]
    fn fresh_images_fail_the_first_boot_check() {
        // A clean volume is what the guest sees *before* the first boot, so the
        // post-first-boot check must reject it (the guest has to create the
        // files itself, never the harness).
        let fat = format_fat32().expect("formatting FAT32");
        let ext = format_ext2(&Samples::empty()).expect("formatting ext2");
        let error = verify_first_boot_images(&fat, &ext).expect_err("fresh images must not pass");
        assert!(error.contains(FAT_STATE), "{error}");
    }

    #[test]
    fn guest_second_boot_is_accepted_by_the_host_check() {
        // Replays exactly what the guest does on its second boot, so the host
        // checks are exercised against the same on-disk result QEMU produces.
        let fat = fat32_second_boot(&first_boot_fat32());
        let ext = ext2_second_boot(&first_boot_ext2());
        verify_second_boot_images(&fat, &ext).expect("second boot images");
        // The data file was renamed away, so the first-boot check must fail.
        assert!(verify_first_boot_images(&fat, &ext).is_err());
    }

    #[test]
    fn host_check_rejects_a_corrupted_pattern_byte() {
        let mut fat = first_boot_fat32();
        let ext = first_boot_ext2();
        {
            let mut fs =
                Fat32::mount(MemDisk::from_bytes(fat.clone(), DEV_BLOCK_SIZE)).expect("mounting");
            let root = fs.root();
            let mut data = fs.lookup(&root, FAT_DATA).expect("data node");
            let last = DATA_INITIAL_LEN - 1;
            let corrupt = [pattern_byte(last) ^ 0xFF];
            fs.write(&mut data, last as u64, &corrupt)
                .expect("corrupting one byte");
            fs.sync().expect("sync");
            fat = fs.unmount().expect("unmounting").data().to_vec();
        }
        let error = verify_first_boot_images(&fat, &ext).expect_err("corruption must be caught");
        assert!(error.contains("first difference"), "{error}");
    }

    #[test]
    fn m5c_user_marker_lengths_match_the_contract() {
        // The kernel checks the exact byte strings, so freeze their geometry.
        assert_eq!(M5C1_FIRST_MARKER.len(), 14);
        assert_eq!(M5C1_SECOND_MARKER.len(), 20);
        assert_eq!(M5C1_FIRST_MARKER, b"CAELUM-M5C1-V1");
        assert_eq!(M5C1_SECOND_MARKER, b"CAELUM-M5C1-V1\nBOOT2");
        assert!(M5C1_SECOND_MARKER.starts_with(M5C1_FIRST_MARKER));
    }

    #[test]
    fn first_boot_fixture_holds_the_m5c_user_file_on_both_volumes() {
        let fat = first_boot_fat32();
        let mut fs = Fat32::mount(MemDisk::from_bytes(fat, DEV_BLOCK_SIZE)).expect("mounting");
        expect_fat32_file(
            &mut fs,
            FAT_USER,
            M5C1_FIRST_MARKER,
            "first boot FAT32 user",
        )
        .expect("FAT32 user file");

        let ext = first_boot_ext2();
        let mut fs = Ext2::mount(MemDisk::from_bytes(ext, DEV_BLOCK_SIZE)).expect("mounting");
        expect_ext2_file(
            &mut fs,
            EXT2_USER,
            M5C1_FIRST_MARKER,
            "first boot ext2 user",
        )
        .expect("ext2 user file");
    }

    #[test]
    fn first_boot_check_rejects_a_user_file_missing_on_one_volume() {
        // Both volumes must carry the file: one disk alone is not enough.
        let fat = remove_fat32_user(&first_boot_fat32());
        let ext = first_boot_ext2();
        let error =
            verify_first_boot_images(&fat, &ext).expect_err("missing FAT32 user file must fail");
        assert!(error.contains(FAT_USER), "{error}");
    }

    #[test]
    fn first_boot_check_rejects_a_wrong_user_marker() {
        let fat = rewrite_fat32_user(&first_boot_fat32(), b"CAELUM-M5C1-VX");
        let ext = first_boot_ext2();
        let error = verify_first_boot_images(&fat, &ext).expect_err("wrong user marker must fail");
        assert!(error.contains("first difference"), "{error}");
    }

    #[test]
    fn second_boot_check_rejects_a_stale_first_boot_user_marker() {
        // The second boot must rewrite the user file; keeping the first-boot
        // content proves the user program did not run its second-boot path.
        let mut fat = first_boot_fat32();
        let mut ext = first_boot_ext2();
        fat = fat_second_boot_data_only(&fat);
        ext = ext2_second_boot_data_only(&ext);
        let error = verify_second_boot_images(&fat, &ext)
            .expect_err("first-boot user marker must not satisfy the second boot");
        assert!(error.contains("FAT32 user"), "{error}");
    }

    #[test]
    fn second_boot_check_rejects_a_second_marker_on_one_volume_only() {
        // A user program that updated only one filesystem must fail.
        let fat = fat32_second_boot(&first_boot_fat32());
        let ext = ext2_second_boot_data_only(&first_boot_ext2());
        let error = verify_second_boot_images(&fat, &ext)
            .expect_err("ext2 still holding the first-boot marker must fail");
        assert!(error.contains("ext2 user"), "{error}");
    }

    #[test]
    fn m5c3_sparse_and_fault_geometry_match_the_contract() {
        assert_eq!(HOLE_LEN, 32772);
        assert_eq!(HOLE_ZEROS, 32768);
        assert_eq!(HOLE_TAIL, b"HOLE");
        // The contract names a 16-byte file; the marker literal is 15 bytes and
        // the file content is the literal plus a newline.
        assert_eq!(FAULT_MARKER, b"CAELUM-FAULT-OK");
        assert_eq!(FAULT_MARKER.len(), 15);
        assert_eq!(FAULT_LEN, 16);
        assert_eq!(fault_expected().len(), FAULT_LEN);
        assert_eq!(fault_expected(), b"CAELUM-FAULT-OK\n");
        let hole = hole_bytes();
        assert_eq!(hole.len(), HOLE_LEN);
        assert!(
            hole[..HOLE_ZEROS].iter().all(|b| *b == 0),
            "the hole must read back as zeros"
        );
        assert_eq!(&hole[HOLE_ZEROS..], HOLE_TAIL);
    }

    #[test]
    fn first_boot_check_rejects_a_sparse_file_missing_on_one_volume() {
        // Both volumes must carry the M5c3 files: one disk alone is not enough.
        let fat = remove_fat32_entry(&first_boot_fat32(), FAT_HOLE);
        let ext = first_boot_ext2();
        let error =
            verify_first_boot_images(&fat, &ext).expect_err("missing FAT32 sparse file must fail");
        assert!(error.contains(FAT_HOLE), "{error}");
    }

    #[test]
    fn first_boot_check_rejects_a_wrong_sparse_length() {
        let fat = rewrite_fat32_entry(&first_boot_fat32(), FAT_HOLE, &hole_bytes()[..100]);
        let ext = first_boot_ext2();
        let error =
            verify_first_boot_images(&fat, &ext).expect_err("truncated sparse file must fail");
        assert!(error.contains("expected 32772"), "{error}");
    }

    #[test]
    fn first_boot_check_rejects_a_nonzero_hole() {
        // A non-sparse implementation that writes stale geometry into the hole
        // shows up as a non-zero byte deep inside the zero range.
        let mut bytes = hole_bytes();
        bytes[4096] = 0x7F;
        let fat = rewrite_fat32_entry(&first_boot_fat32(), FAT_HOLE, &bytes);
        let ext = first_boot_ext2();
        let error = verify_first_boot_images(&fat, &ext).expect_err("non-zero hole must fail");
        assert!(error.contains("offset 4096"), "{error}");
    }

    #[test]
    fn first_boot_check_rejects_a_wrong_sparse_tail() {
        let mut bytes = hole_bytes();
        let last = bytes.len() - 1;
        bytes[last] = b'X';
        let fat = rewrite_fat32_entry(&first_boot_fat32(), FAT_HOLE, &bytes);
        let ext = first_boot_ext2();
        let error = verify_first_boot_images(&fat, &ext).expect_err("wrong tail must fail");
        assert!(error.contains("tail"), "{error}");
    }

    #[test]
    fn first_boot_check_rejects_a_wrong_fault_marker() {
        // The fault-injection file must hold the post-recovery content, not the
        // bytes the failed write tried to store.
        let fat = rewrite_fat32_entry(&first_boot_fat32(), FAT_FAULT, b"CAELUM-FAULT-NO");
        let ext = first_boot_ext2();
        let error = verify_first_boot_images(&fat, &ext).expect_err("wrong fault file must fail");
        assert!(error.contains("first difference"), "{error}");
    }

    #[test]
    fn second_boot_check_rejects_a_corrupted_sparse_file() {
        let fat = fat32_second_boot(&first_boot_fat32());
        let ext = ext2_second_boot(&first_boot_ext2());
        verify_second_boot_images(&fat, &ext).expect("the second-boot fixture must be valid");
        let mut bytes = hole_bytes();
        bytes[8192] = 0x11;
        let fat = rewrite_fat32_entry(&fat, FAT_HOLE, &bytes);
        let error = verify_second_boot_images(&fat, &ext)
            .expect_err("corrupted sparse file after the second boot must fail");
        assert!(error.contains("second boot FAT32 sparse file"), "{error}");
    }

    #[test]
    fn second_boot_check_rejects_a_missing_fault_file() {
        let fat = remove_fat32_entry(&fat32_second_boot(&first_boot_fat32()), FAT_FAULT);
        let ext = ext2_second_boot(&first_boot_ext2());
        let error =
            verify_second_boot_images(&fat, &ext).expect_err("missing FAT32 fault file must fail");
        assert!(error.contains(FAT_FAULT), "{error}");
    }

    /// Re-run the data-file part of the second boot without touching the user
    /// file, so the stale-marker tests keep everything else valid.
    fn fat_second_boot_data_only(image: &[u8]) -> Vec<u8> {
        let mut fs = Fat32::mount(MemDisk::from_bytes(image.to_vec(), DEV_BLOCK_SIZE))
            .expect("mounting FAT32");
        let root = fs.root();
        let mut data = fs.lookup(&root, FAT_DATA).expect("data node");
        fs.write(
            &mut data,
            DATA_INITIAL_LEN as u64,
            &pattern(DATA_APPEND_LEN),
        )
        .expect("appending");
        fs.rename(&mut data, &root, FAT_DONE).expect("renaming");
        fs.truncate(&mut data, DATA_FINAL_LEN).expect("truncating");
        fs.sync().expect("sync");
        fs.unmount().expect("unmounting").data().to_vec()
    }

    /// ext2 counterpart of [`fat_second_boot_data_only`].
    fn ext2_second_boot_data_only(image: &[u8]) -> Vec<u8> {
        let mut fs = Ext2::mount(MemDisk::from_bytes(image.to_vec(), DEV_BLOCK_SIZE))
            .expect("mounting ext2");
        let root = fs.root().expect("root");
        let data = fs.lookup(root.inode, EXT2_DATA).expect("data node");
        fs.write(
            data.inode,
            DATA_INITIAL_LEN as u64,
            &pattern(DATA_APPEND_LEN),
        )
        .expect("appending");
        fs.rename(root.inode, EXT2_DATA, root.inode, EXT2_DONE)
            .expect("renaming");
        fs.truncate(data.inode, DATA_FINAL_LEN).expect("truncating");
        fs.sync().expect("sync");
        fs.into_device().data().to_vec()
    }

    /// Remove the M5c user file from a FAT32 image (test helper).
    fn remove_fat32_user(image: &[u8]) -> Vec<u8> {
        let mut fs = Fat32::mount(MemDisk::from_bytes(image.to_vec(), DEV_BLOCK_SIZE))
            .expect("mounting FAT32");
        let root = fs.root();
        let user = fs.lookup(&root, FAT_USER).expect("user node");
        fs.unlink(&user).expect("unlinking the user file");
        fs.sync().expect("sync");
        fs.unmount().expect("unmounting").data().to_vec()
    }

    /// Replace the M5c user file content on a FAT32 image (test helper).
    fn rewrite_fat32_user(image: &[u8], content: &[u8]) -> Vec<u8> {
        let mut fs = Fat32::mount(MemDisk::from_bytes(image.to_vec(), DEV_BLOCK_SIZE))
            .expect("mounting FAT32");
        let root = fs.root();
        let mut user = fs.lookup(&root, FAT_USER).expect("user node");
        fs.write(&mut user, 0, content)
            .expect("writing the user file");
        fs.truncate(&mut user, content.len() as u64)
            .expect("truncating the user file");
        fs.sync().expect("sync");
        fs.unmount().expect("unmounting").data().to_vec()
    }

    /// Delete an arbitrary FAT32 entry from a host image (test helper).
    fn remove_fat32_entry(image: &[u8], name: &str) -> Vec<u8> {
        let mut fs = Fat32::mount(MemDisk::from_bytes(image.to_vec(), DEV_BLOCK_SIZE))
            .expect("mounting FAT32");
        let root = fs.root();
        let node = fs.lookup(&root, name).expect("entry");
        fs.unlink(&node).expect("unlinking the entry");
        fs.sync().expect("sync");
        fs.unmount().expect("unmounting").data().to_vec()
    }

    /// Replace the content of an arbitrary FAT32 entry on a host image (test
    /// helper); the entry is truncated to the new length.
    fn rewrite_fat32_entry(image: &[u8], name: &str, content: &[u8]) -> Vec<u8> {
        let mut fs = Fat32::mount(MemDisk::from_bytes(image.to_vec(), DEV_BLOCK_SIZE))
            .expect("mounting FAT32");
        let root = fs.root();
        let mut node = fs.lookup(&root, name).expect("entry");
        fs.write(&mut node, 0, content).expect("writing the entry");
        fs.truncate(&mut node, content.len() as u64)
            .expect("truncating the entry");
        fs.sync().expect("sync");
        fs.unmount().expect("unmounting").data().to_vec()
    }

    fn first_boot_fat32() -> Vec<u8> {
        let bytes = format_fat32().expect("formatting FAT32");
        let mut fs = Fat32::mount(MemDisk::from_bytes(bytes, DEV_BLOCK_SIZE)).expect("mounting");
        let root = fs.root();
        let mut state = fs
            .create(&root, FAT_STATE, FatKind::File)
            .expect("creating state");
        fs.write(&mut state, 0, STATE_BYTES).expect("writing state");
        let mut data = fs
            .create(&root, FAT_DATA, FatKind::File)
            .expect("creating data");
        fs.write(&mut data, 0, &pattern(DATA_INITIAL_LEN))
            .expect("writing data");
        let mut user = fs
            .create(&root, FAT_USER, FatKind::File)
            .expect("creating user file");
        fs.write(&mut user, 0, M5C1_FIRST_MARKER)
            .expect("writing user file");
        // M5c2: the guest lays down the map pattern, then the shared mapping
        // edits two bytes and syncs, so the first boot already leaves the final
        // state behind.
        let mut map = fs
            .create(&root, FAT_MAP, FatKind::File)
            .expect("creating map file");
        let final_map = map_final();
        fs.write(&mut map, 0, &final_map).expect("writing map file");
        // M5c3: the sparse file and the fault-injection file are recreated with
        // CREATE|TRUNC on every boot, so they must already exist after the first.
        let mut hole = fs
            .create(&root, FAT_HOLE, FatKind::File)
            .expect("creating sparse file");
        fs.write(&mut hole, 0, &hole_bytes())
            .expect("writing sparse file");
        let mut fault = fs
            .create(&root, FAT_FAULT, FatKind::File)
            .expect("creating fault file");
        fs.write(&mut fault, 0, &fault_expected())
            .expect("writing fault file");
        fs.sync().expect("sync");
        fs.unmount().expect("unmounting").data().to_vec()
    }

    /// ext2 counterpart of [`first_boot_fat32`].
    fn first_boot_ext2() -> Vec<u8> {
        let bytes = format_ext2(&Samples::empty()).expect("formatting ext2");
        let mut fs = Ext2::mount(MemDisk::from_bytes(bytes, DEV_BLOCK_SIZE)).expect("mounting");
        let root = fs.root().expect("root");
        let state = fs
            .create(root.inode, EXT2_STATE, ExtKind::File)
            .expect("creating state");
        fs.write(state.inode, 0, STATE_BYTES)
            .expect("writing state");
        let data = fs
            .create(root.inode, EXT2_DATA, ExtKind::File)
            .expect("creating data");
        fs.write(data.inode, 0, &pattern(DATA_INITIAL_LEN))
            .expect("writing data");
        let user = fs
            .create(root.inode, EXT2_USER, ExtKind::File)
            .expect("creating user file");
        fs.write(user.inode, 0, M5C1_FIRST_MARKER)
            .expect("writing user file");
        let map = fs
            .create(root.inode, EXT2_MAP, ExtKind::File)
            .expect("creating map file");
        fs.write(map.inode, 0, &map_final())
            .expect("writing map file");
        let hole = fs
            .create(root.inode, EXT2_HOLE, ExtKind::File)
            .expect("creating sparse file");
        fs.write(hole.inode, 0, &hole_bytes())
            .expect("writing sparse file");
        let fault = fs
            .create(root.inode, EXT2_FAULT, ExtKind::File)
            .expect("creating fault file");
        fs.write(fault.inode, 0, &fault_expected())
            .expect("writing fault file");
        fs.sync().expect("sync");
        fs.into_device().data().to_vec()
    }

    /// Bytes the second boot appends to the data file (guest-side contract).
    const DATA_APPEND_LEN: usize = 1024;

    /// Simulate the guest's second-boot FAT32 writes on a host image.
    fn fat32_second_boot(image: &[u8]) -> Vec<u8> {
        let mut fs = Fat32::mount(MemDisk::from_bytes(image.to_vec(), DEV_BLOCK_SIZE))
            .expect("mounting FAT32");
        let root = fs.root();
        let mut data = fs.lookup(&root, FAT_DATA).expect("data node");
        fs.write(
            &mut data,
            DATA_INITIAL_LEN as u64,
            &pattern(DATA_APPEND_LEN),
        )
        .expect("appending");
        fs.rename(&mut data, &root, FAT_DONE).expect("renaming");
        fs.truncate(&mut data, DATA_FINAL_LEN).expect("truncating");
        // M5c1: the user program rewrites its file with the second-boot marker.
        let mut user = fs.lookup(&root, FAT_USER).expect("user node");
        fs.write(&mut user, 0, M5C1_SECOND_MARKER)
            .expect("writing the second-boot user marker");
        fs.truncate(&mut user, M5C1_SECOND_MARKER.len() as u64)
            .expect("truncating the user file");
        // M5c3: the guest takes both new files down with CREATE|TRUNC, so the
        // second boot must recreate their content, never keep stale bytes.
        let hole = fs.lookup(&root, FAT_HOLE).expect("sparse node");
        fs.unlink(&hole).expect("removing the sparse file");
        let fault = fs.lookup(&root, FAT_FAULT).expect("fault node");
        fs.unlink(&fault).expect("removing the fault file");
        let mut hole = fs
            .create(&root, FAT_HOLE, FatKind::File)
            .expect("recreating the sparse file");
        fs.write(&mut hole, 0, &hole_bytes())
            .expect("rewriting the sparse file");
        let mut fault = fs
            .create(&root, FAT_FAULT, FatKind::File)
            .expect("recreating the fault file");
        fs.write(&mut fault, 0, &fault_expected())
            .expect("rewriting the fault file");
        fs.sync().expect("sync");
        fs.unmount().expect("unmounting").data().to_vec()
    }

    /// Simulate the guest's second-boot ext2 writes on a host image.
    fn ext2_second_boot(image: &[u8]) -> Vec<u8> {
        let mut fs = Ext2::mount(MemDisk::from_bytes(image.to_vec(), DEV_BLOCK_SIZE))
            .expect("mounting ext2");
        let root = fs.root().expect("root");
        let data = fs.lookup(root.inode, EXT2_DATA).expect("data node");
        fs.write(
            data.inode,
            DATA_INITIAL_LEN as u64,
            &pattern(DATA_APPEND_LEN),
        )
        .expect("appending");
        fs.rename(root.inode, EXT2_DATA, root.inode, EXT2_DONE)
            .expect("renaming");
        fs.truncate(data.inode, DATA_FINAL_LEN).expect("truncating");
        let user = fs.lookup(root.inode, EXT2_USER).expect("user node");
        fs.write(user.inode, 0, M5C1_SECOND_MARKER)
            .expect("writing the second-boot user marker");
        fs.truncate(user.inode, M5C1_SECOND_MARKER.len() as u64)
            .expect("truncating the user file");
        // M5c3: recreate both new files, matching the guest's CREATE|TRUNC.
        fs.unlink(root.inode, EXT2_HOLE)
            .expect("removing the sparse file");
        fs.unlink(root.inode, EXT2_FAULT)
            .expect("removing the fault file");
        let hole = fs
            .create(root.inode, EXT2_HOLE, ExtKind::File)
            .expect("recreating the sparse file");
        fs.write(hole.inode, 0, &hole_bytes())
            .expect("rewriting the sparse file");
        let fault = fs
            .create(root.inode, EXT2_FAULT, ExtKind::File)
            .expect("recreating the fault file");
        fs.write(fault.inode, 0, &fault_expected())
            .expect("rewriting the fault file");
        fs.sync().expect("sync");
        fs.into_device().data().to_vec()
    }

    #[test]
    fn m5c_map_geometry_matches_the_contract() {
        // The guest and both host checks share these literals, so freeze them.
        assert_eq!(MAP_LEN, 8192);
        assert_eq!(MAP_SHARED_FIRST, 0xA5);
        assert_eq!(MAP_SHARED_SECOND_AT, 4103);
        assert_eq!(MAP_SHARED_SECOND, 0x5A);
        assert_eq!(MAP_PRIVATE_BYTE, 0xFF);
        assert_eq!(FAT_MAP, "M5MAP.BIN");
        assert_eq!(EXT2_MAP, b"m5cmap");

        let initial = map_initial();
        let final_map = map_final();
        assert_eq!(initial.len(), MAP_LEN);
        assert_eq!(final_map.len(), MAP_LEN);
        assert_eq!(final_map[0], MAP_SHARED_FIRST);
        assert_eq!(final_map[MAP_SHARED_SECOND_AT], MAP_SHARED_SECOND);
        // Exactly the two shared-mapping edits differ from the pattern.
        let changed: Vec<usize> = initial
            .iter()
            .zip(&final_map)
            .enumerate()
            .filter(|(_, (a, b))| a != b)
            .map(|(i, _)| i)
            .collect();
        assert_eq!(changed, vec![0, MAP_SHARED_SECOND_AT]);
        // The private mapping's byte must never be part of the expected state.
        assert_ne!(final_map[0], MAP_PRIVATE_BYTE);
        assert_ne!(map_pattern_byte(0), MAP_SHARED_FIRST);
    }

    #[test]
    fn fresh_volumes_have_no_map_file() {
        let mut fat = Fat32::mount(MemDisk::from_bytes(
            format_fat32().expect("formatting FAT32"),
            DEV_BLOCK_SIZE,
        ))
        .expect("mounting");
        fat32_missing(&mut fat, FAT_MAP, "fresh").expect("fresh FAT32 must not carry a map");

        let mut ext = Ext2::mount(MemDisk::from_bytes(
            format_ext2(&Samples::empty()).expect("formatting ext2"),
            DEV_BLOCK_SIZE,
        ))
        .expect("mounting");
        ext2_missing(&mut ext, EXT2_MAP, "fresh").expect("fresh ext2 must not carry a map");
    }

    #[test]
    fn first_boot_fixture_holds_the_final_map_on_both_volumes() {
        let mut fat = Fat32::mount(MemDisk::from_bytes(first_boot_fat32(), DEV_BLOCK_SIZE))
            .expect("mounting");
        expect_fat32_map(&mut fat, "first boot FAT32 map").expect("FAT32 map");

        let mut ext =
            Ext2::mount(MemDisk::from_bytes(first_boot_ext2(), DEV_BLOCK_SIZE)).expect("mounting");
        expect_ext2_map(&mut ext, "first boot ext2 map").expect("ext2 map");
    }

    #[test]
    fn first_boot_check_rejects_a_map_missing_on_one_volume() {
        // The map is part of the acceptance surface: one volume alone is not
        // enough, exactly like the M5c user file.
        let fat = remove_fat32_map(&first_boot_fat32());
        let ext = first_boot_ext2();
        let error = verify_first_boot_images(&fat, &ext).expect_err("missing FAT32 map must fail");
        assert!(error.contains(FAT_MAP), "{error}");
    }

    #[test]
    fn first_boot_check_rejects_a_private_mapping_write_back() {
        // The private mapping writes 0xFF at offset 0 in memory only; if that
        // byte reaches the disk the shared/private split is broken.
        let mut leaked = map_final();
        leaked[0] = MAP_PRIVATE_BYTE;
        let fat = rewrite_fat32_map(&first_boot_fat32(), &leaked);
        let ext = first_boot_ext2();
        let error = verify_first_boot_images(&fat, &ext)
            .expect_err("a private-mapping write-back must fail");
        assert!(error.contains("private mapping"), "{error}");
    }

    #[test]
    fn first_boot_check_rejects_a_map_without_the_second_shared_edit() {
        // A shared mapping that only wrote one of its two bytes must fail.
        let mut partial = map_final();
        partial[MAP_SHARED_SECOND_AT] = map_pattern_byte(MAP_SHARED_SECOND_AT);
        assert_ne!(partial[MAP_SHARED_SECOND_AT], MAP_SHARED_SECOND);
        let fat = rewrite_fat32_map(&first_boot_fat32(), &partial);
        let ext = first_boot_ext2();
        let error =
            verify_first_boot_images(&fat, &ext).expect_err("a missing shared edit must fail");
        assert!(error.contains("first difference"), "{error}");
    }

    #[test]
    fn second_boot_check_rejects_a_map_that_lost_the_shared_edit() {
        // The second boot re-verifies the map; if the edits were rolled back it
        // must not pass just because the user/mmap markers were printed.
        let fat = fat32_second_boot(&first_boot_fat32());
        let ext = ext2_second_boot(&first_boot_ext2());
        // Sanity: the untouched pair passes.
        verify_second_boot_images(&fat, &ext).expect("second boot fixture");

        let mut rolled_back = map_final();
        rolled_back[0] = map_pattern_byte(0);
        let fat = rewrite_fat32_map(&fat, &rolled_back);
        let error = verify_second_boot_images(&fat, &ext)
            .expect_err("a rolled-back shared edit must fail after the second boot");
        assert!(error.contains("second boot FAT32 map file"), "{error}");
    }

    /// Remove the M5c2 map file from a FAT32 image (test helper).
    fn remove_fat32_map(image: &[u8]) -> Vec<u8> {
        let mut fs = Fat32::mount(MemDisk::from_bytes(image.to_vec(), DEV_BLOCK_SIZE))
            .expect("mounting FAT32");
        let root = fs.root();
        let map = fs.lookup(&root, FAT_MAP).expect("map node");
        fs.unlink(&map).expect("unlinking the map file");
        fs.sync().expect("sync");
        fs.unmount().expect("unmounting").data().to_vec()
    }

    /// Replace the M5c2 map file content on a FAT32 image (test helper).
    fn rewrite_fat32_map(image: &[u8], content: &[u8]) -> Vec<u8> {
        let mut fs = Fat32::mount(MemDisk::from_bytes(image.to_vec(), DEV_BLOCK_SIZE))
            .expect("mounting FAT32");
        let root = fs.root();
        let mut map = fs.lookup(&root, FAT_MAP).expect("map node");
        fs.write(&mut map, 0, content)
            .expect("writing the map file");
        fs.truncate(&mut map, content.len() as u64)
            .expect("truncating the map file");
        fs.sync().expect("sync");
        fs.unmount().expect("unmounting").data().to_vec()
    }

    /// A small synthetic M10a sample set: the injection tests do not need the
    /// 2 MiB real binaries, only bytes that differ per file.
    fn m10a_fixture() -> Samples {
        Samples {
            busybox: b"\x7fELF-busybox-sample".to_vec(),
            ld_musl: b"\x7fELF-ld-musl-x86_64.so.1-sample".to_vec(),
            libc_musl: b"\x7fELF-libc.musl-x86_64.so.1-sample".to_vec(),
        }
    }

    #[test]
    fn m10a_samples_are_injected_into_ext2_directories() {
        let samples = m10a_fixture();
        let image = format_ext2(&samples).expect("formatting ext2 with samples");
        verify_m10a_samples(&image, &samples).expect("the injected samples verify");

        // The files live in real directories, under the contract names.
        let mut fs = mount_ext2(&image).expect("mounting ext2");
        let root = fs.root().expect("root");
        let bin = fs.lookup(root.inode, EXT2_BIN_DIR).expect("/bin exists");
        assert_eq!(bin.kind, ext2::NodeKind::Directory);
        let busybox = fs
            .lookup(bin.inode, EXT2_BUSYBOX)
            .expect("/bin/busybox exists");
        assert_eq!(busybox.size as usize, samples.busybox.len());
        let lib = fs.lookup(root.inode, EXT2_LIB_DIR).expect("/lib exists");
        assert_eq!(lib.kind, ext2::NodeKind::Directory);
        let loader = fs
            .lookup(lib.inode, EXT2_LD_MUSL)
            .expect("/lib/ld-musl-x86_64.so.1 exists");
        assert_eq!(loader.size as usize, samples.ld_musl.len());
        let libc = fs
            .lookup(lib.inode, EXT2_LIBC_MUSL)
            .expect("/lib/libc.musl-x86_64.so.1 exists");
        assert_eq!(libc.size as usize, samples.libc_musl.len());

        // An empty sample set must not inject the directories at all.
        let empty = format_ext2(&Samples::empty()).expect("formatting empty ext2");
        verify_m10a_samples(&empty, &Samples::empty()).expect("nothing to verify");
        let mut fs = mount_ext2(&empty).expect("mounting the empty ext2");
        let root = fs.root().expect("root");
        fs.lookup(root.inode, EXT2_BIN_DIR)
            .expect_err("an empty volume carries no /bin");
    }

    #[test]
    fn m10a_verification_rejects_corrupted_or_missing_samples() {
        let samples = m10a_fixture();
        let image = format_ext2(&samples).expect("formatting ext2 with samples");

        let mut corrupted = m10a_fixture();
        corrupted.busybox[0] ^= 0xFF;
        let error = verify_m10a_samples(&image, &corrupted)
            .expect_err("a corrupted busybox must fail the host check");
        assert!(error.contains("/bin/busybox"), "{error}");

        let mut short = m10a_fixture();
        short.libc_musl.push(0x42);
        let error = verify_m10a_samples(&image, &short)
            .expect_err("a length mismatch must fail the host check");
        assert!(error.contains("/lib/libc.musl-x86_64.so.1"), "{error}");

        // An image without the injection is rejected, not silently skipped.
        let bare = format_ext2(&Samples::empty()).expect("formatting empty ext2");
        let error = verify_m10a_samples(&bare, &samples)
            .expect_err("an image without the samples must fail");
        assert!(error.contains("/bin"), "{error}");
    }

    #[test]
    fn m10a_injection_requires_all_three_samples() {
        let mut partial = m10a_fixture();
        partial.libc_musl.clear();
        let error = format_ext2(&partial).expect_err("a partial sample set must be rejected");
        assert!(error.contains("all three samples"), "{error}");
    }
}
