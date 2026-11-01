//! Pure-Rust FAT16 ESP (EFI System Partition) image generator.
//!
//! Produces a bootable disk image: protective MBR + one 0xEF partition
//! formatted FAT16 containing the standard UEFI boot path
//! `/EFI/BOOT/BOOTX64.EFI`, `/KERNEL.ELF` and the M4 boot-module container
//! `/INITFS.IMG`. No mtools, no external tools.
//!
//! All names are plain 8.3 (`INITFS.IMG` fits the 8-character base), so no
//! VFAT long-name entries are needed — the image stays readable by the
//! simplest possible FAT reader on the loader side.
//!
//! Geometry (all values within the FAT16 spec, cluster count >= 4085):
//! - 512 bytes/sector, 8 sectors/cluster (4 KiB clusters)
//! - 32 reserved sectors, 2 FATs of 32 sectors, 512 root entries (32 sectors)
//! - partition: 65536 sectors (32 MiB) starting at LBA 2048

const SECTOR: usize = 512;
const BYTES_PER_SECTOR: u16 = 512;
const SECTORS_PER_CLUSTER: u8 = 8;
const CLUSTER: usize = SECTOR * SECTORS_PER_CLUSTER as usize;
const RESERVED_SECTORS: u16 = 32;
const NUM_FATS: u8 = 2;
const ROOT_ENTRIES: u16 = 512;
const ROOT_DIR_SECTORS: u16 = ROOT_ENTRIES * 32 / BYTES_PER_SECTOR;
const SECTORS_PER_FAT: u16 = 32;
const PARTITION_LBA: u32 = 2048;
const PARTITION_SECTORS: u32 = 65536;
const FIRST_DATA_SECTOR: u32 =
    RESERVED_SECTORS as u32 + NUM_FATS as u32 * SECTORS_PER_FAT as u32 + ROOT_DIR_SECTORS as u32;
const MEDIA: u8 = 0xF8;
const ATTR_DIRECTORY: u8 = 0x10;
const ATTR_ARCHIVE: u8 = 0x20;
const ATTR_VOLUME_ID: u8 = 0x08;
const EOC: u16 = 0xFFFF;

pub const ESP_IMG_NAME: &str = "caelum-esp.img";
/// Root-directory name of the initramfs container (pure 8.3 on purpose).
pub const INITFS_NAME: &str = "INITFS.IMG";

fn cluster_to_sector(cluster: u32) -> u32 {
    PARTITION_LBA + FIRST_DATA_SECTOR + (cluster - 2) * SECTORS_PER_CLUSTER as u32
}

fn clusters_for(bytes: usize) -> u32 {
    ((bytes + CLUSTER - 1) / CLUSTER) as u32
}

fn dos_date() -> u16 {
    // 2026-01-01
    (((2026 - 1980) as u16) << 9) | (1 << 5) | 1
}

/// A single FAT16 allocation, laid out contiguously from `first`.
struct Chain {
    first: u32,
    count: u32,
}

struct FatWriter<'a> {
    img: &'a mut [u8],
    next_cluster: u32,
}

impl<'a> FatWriter<'a> {
    fn fat_entry_off(fat_index: u32, cluster: u32) -> usize {
        let fat_base_sector =
            PARTITION_LBA + RESERVED_SECTORS as u32 + fat_index * SECTORS_PER_FAT as u32;
        fat_base_sector as usize * SECTOR + cluster as usize * 2
    }

    fn set_fat(&mut self, cluster: u32, value: u16) {
        for i in 0..NUM_FATS as u32 {
            let off = Self::fat_entry_off(i, cluster);
            self.img[off..off + 2].copy_from_slice(&value.to_le_bytes());
        }
    }

    fn alloc_chain(&mut self, bytes: usize) -> Chain {
        let count = clusters_for(bytes);
        let first = self.next_cluster;
        for i in 0..count {
            let c = first + i;
            let val: u16 = if i + 1 == count { EOC } else { (c + 1) as u16 };
            self.set_fat(c, val);
        }
        self.next_cluster += count;
        Chain { first, count }
    }

    fn write_chain(&mut self, chain: &Chain, data: &[u8]) {
        for i in 0..chain.count {
            let off = cluster_to_sector(chain.first + i) as usize * SECTOR;
            let start = i as usize * CLUSTER;
            let end = (start + CLUSTER).min(data.len());
            self.img[off..off + (end - start)].copy_from_slice(&data[start..end]);
        }
    }

    /// Write one 32-byte directory entry.
    fn dir_entry(
        &mut self,
        dir_cluster: Option<u32>,
        index: usize,
        name11: &[u8; 11],
        attr: u8,
        first_cluster: u32,
        size: u32,
    ) {
        let base = match dir_cluster {
            None => {
                (PARTITION_LBA + RESERVED_SECTORS as u32 + NUM_FATS as u32 * SECTORS_PER_FAT as u32)
                    as usize
                    * SECTOR
            }
            Some(c) => cluster_to_sector(c) as usize * SECTOR,
        } + index * 32;
        self.img[base..base + 11].copy_from_slice(name11);
        self.img[base + 11] = attr;
        self.img[base + 12] = 0;
        self.img[base + 13] = 0;
        self.img[base + 14..base + 16].copy_from_slice(&0u16.to_le_bytes()); // create time
        self.img[base + 16..base + 18].copy_from_slice(&0u16.to_le_bytes()); // create date
        self.img[base + 18..base + 20].copy_from_slice(&0u16.to_le_bytes()); // last access
        self.img[base + 20..base + 22]
            .copy_from_slice(&((first_cluster >> 16) as u16).to_le_bytes());
        self.img[base + 22..base + 24].copy_from_slice(&0u16.to_le_bytes()); // write time
        self.img[base + 24..base + 26].copy_from_slice(&dos_date().to_le_bytes());
        self.img[base + 26..base + 28].copy_from_slice(&(first_cluster as u16).to_le_bytes());
        self.img[base + 28..base + 32].copy_from_slice(&size.to_le_bytes());
    }
}

fn name83(base: &str, ext: &str) -> [u8; 11] {
    let mut n = [b' '; 11];
    for (i, b) in base.as_bytes().iter().take(8).enumerate() {
        n[i] = *b;
    }
    for (i, b) in ext.as_bytes().iter().take(3).enumerate() {
        n[8 + i] = *b;
    }
    n
}

/// Build the full ESP disk image. `initramfs` is the `CAELUMFS` container
/// (`initramfs::build`) stored at the root as `/INITFS.IMG`.
pub fn build_esp(loader_efi: &[u8], kernel_elf: &[u8], initramfs: &[u8]) -> Vec<u8> {
    let total_sectors = PARTITION_LBA + PARTITION_SECTORS;
    let mut img = vec![0u8; total_sectors as usize * SECTOR];
    let mut fat = FatWriter {
        img: &mut img,
        next_cluster: 2,
    };

    // --- MBR (LBA 0) ---
    let mbr = &mut fat.img[..SECTOR];
    mbr[0x1BE] = 0x80; // bootable
    mbr[0x1BF..0x1C2].copy_from_slice(&[0xFF, 0xFF, 0xFF]); // CHS start (unused, large LBA)
    mbr[0x1C2] = 0xEF; // GPT/UEFI system partition type
    mbr[0x1C3..0x1C6].copy_from_slice(&[0xFF, 0xFF, 0xFF]); // CHS end
    mbr[0x1C6..0x1CA].copy_from_slice(&PARTITION_LBA.to_le_bytes());
    mbr[0x1CA..0x1CE].copy_from_slice(&PARTITION_SECTORS.to_le_bytes());
    mbr[510] = 0x55;
    mbr[511] = 0xAA;

    // --- FAT16 boot sector (partition LBA) ---
    let bs_off = PARTITION_LBA as usize * SECTOR;
    {
        let bs = &mut fat.img[bs_off..bs_off + SECTOR];
        bs[0..3].copy_from_slice(&[0xEB, 0x3C, 0x90]);
        bs[3..11].copy_from_slice(b"CAELUM  ");
        bs[11..13].copy_from_slice(&BYTES_PER_SECTOR.to_le_bytes());
        bs[13] = SECTORS_PER_CLUSTER;
        bs[14..16].copy_from_slice(&RESERVED_SECTORS.to_le_bytes());
        bs[16] = NUM_FATS;
        bs[17..19].copy_from_slice(&ROOT_ENTRIES.to_le_bytes());
        bs[19..21].copy_from_slice(&0u16.to_le_bytes()); // total16 (unused)
        bs[21] = MEDIA;
        bs[22..24].copy_from_slice(&SECTORS_PER_FAT.to_le_bytes());
        bs[24..26].copy_from_slice(&32u16.to_le_bytes()); // sectors/track
        bs[26..28].copy_from_slice(&64u16.to_le_bytes()); // heads
        bs[28..32].copy_from_slice(&PARTITION_LBA.to_le_bytes()); // hidden
        bs[32..36].copy_from_slice(&PARTITION_SECTORS.to_le_bytes()); // total32
        bs[36] = 0x80;
        bs[38] = 0x29;
        bs[39..43].copy_from_slice(&0xCAE1_0001u32.to_le_bytes()); // volume ID
        bs[43..54].copy_from_slice(b"CAELUM ESP ");
        bs[54..62].copy_from_slice(b"FAT16   ");
        bs[62] = 0x55;
        bs[63] = 0xAA;
        bs[510] = 0x55;
        bs[511] = 0xAA;
    }

    // --- FAT headers: entry 0 = media, entry 1 = reserved/EOC ---
    for i in 0..NUM_FATS as u32 {
        let off = FatWriter::fat_entry_off(i, 0);
        fat.img[off..off + 4].copy_from_slice(&0xFFFF_FFF8u32.to_le_bytes());
    }

    // --- Allocate: cluster 2 = /EFI, cluster 3 = /EFI/BOOT, then files ---
    let efi_dir = fat.alloc_chain(32);
    let boot_dir = fat.alloc_chain(32);
    let bootx64 = fat.alloc_chain(loader_efi.len());
    let kernel = fat.alloc_chain(kernel_elf.len());
    let initfs = fat.alloc_chain(initramfs.len());

    fat.write_chain(&bootx64, loader_efi);
    fat.write_chain(&kernel, kernel_elf);
    fat.write_chain(&initfs, initramfs);

    // --- Root directory: volume label, EFI dir, KERNEL.ELF, INITFS.IMG ---
    fat.dir_entry(None, 0, b"CAELUM ESP ", ATTR_VOLUME_ID, 0, 0);
    fat.dir_entry(
        None,
        1,
        &name83("EFI", ""),
        ATTR_DIRECTORY,
        efi_dir.first,
        0,
    );
    fat.dir_entry(
        None,
        2,
        &name83("KERNEL", "ELF"),
        ATTR_ARCHIVE,
        kernel.first,
        kernel_elf.len() as u32,
    );
    fat.dir_entry(
        None,
        3,
        &name83("INITFS", "IMG"),
        ATTR_ARCHIVE,
        initfs.first,
        initramfs.len() as u32,
    );

    // --- /EFI: BOOT dir ---
    fat.dir_entry(
        Some(efi_dir.first),
        0,
        &name83("BOOT", ""),
        ATTR_DIRECTORY,
        boot_dir.first,
        0,
    );
    // --- /EFI/BOOT: BOOTX64.EFI ---
    fat.dir_entry(
        Some(boot_dir.first),
        0,
        &name83("BOOTX64", "EFI"),
        ATTR_ARCHIVE,
        bootx64.first,
        loader_efi.len() as u32,
    );

    fat.img.to_vec()
}

/// Read a file back out of an image built by `build_esp` (used by tests and
/// by `xtask image --verify`).
pub fn read_file(img: &[u8], path: &[&str]) -> Option<Vec<u8>> {
    if path.is_empty() {
        return None;
    }
    let mut dir_cluster: Option<u32> = None; // None = root
    for (depth, comp) in path.iter().enumerate() {
        let entries = dir_entries(img, dir_cluster);
        let want = name83(
            comp.rsplit_once('.').map(|(b, _)| b).unwrap_or(comp),
            if comp.contains('.') {
                comp.rsplit_once('.').unwrap().1
            } else {
                ""
            },
        );
        let e = entries
            .into_iter()
            .find(|e| e.name == want && (e.attr & 0x10 != 0 || depth + 1 == path.len()))?;
        if depth + 1 == path.len() {
            return Some(read_chain(img, e.first_cluster, e.size as usize));
        }
        dir_cluster = Some(e.first_cluster);
    }
    None
}

struct DirEntry {
    name: [u8; 11],
    attr: u8,
    first_cluster: u32,
    size: u32,
}

fn dir_entries(img: &[u8], dir_cluster: Option<u32>) -> Vec<DirEntry> {
    let base = match dir_cluster {
        None => {
            (PARTITION_LBA + RESERVED_SECTORS as u32 + NUM_FATS as u32 * SECTORS_PER_FAT as u32)
                as usize
                * SECTOR
        }
        Some(c) => cluster_to_sector(c) as usize * SECTOR,
    };
    let len = match dir_cluster {
        None => ROOT_DIR_SECTORS as usize * SECTOR,
        Some(_) => CLUSTER,
    };
    let mut out = Vec::new();
    for i in 0..len / 32 {
        let o = base + i * 32;
        if img[o] == 0 || img[o] == 0xE5 {
            continue;
        }
        let mut name = [0u8; 11];
        name.copy_from_slice(&img[o..o + 11]);
        out.push(DirEntry {
            name,
            attr: img[o + 11],
            first_cluster: u16::from_le_bytes([img[o + 26], img[o + 27]]) as u32
                | ((u16::from_le_bytes([img[o + 20], img[o + 21]]) as u32) << 16),
            size: u32::from_le_bytes([img[o + 28], img[o + 29], img[o + 30], img[o + 31]]),
        });
    }
    out
}

fn read_chain(img: &[u8], first: u32, size: usize) -> Vec<u8> {
    let mut data = Vec::with_capacity(size);
    let mut c = first;
    loop {
        let off = cluster_to_sector(c) as usize * SECTOR;
        let take = (size - data.len()).min(CLUSTER);
        data.extend_from_slice(&img[off..off + take]);
        if data.len() >= size {
            break;
        }
        let fat_off = FatWriter::fat_entry_off(0, c);
        c = u16::from_le_bytes([img[fat_off], img[fat_off + 1]]) as u32;
        if c < 2 || c == EOC as u32 {
            break;
        }
    }
    data
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_loader() -> Vec<u8> {
        // 80 KiB pseudo-EFI payload.
        let mut v = vec![0u8; 80 * 1024];
        for (i, b) in v.iter_mut().enumerate() {
            *b = (i % 251) as u8;
        }
        v
    }

    #[test]
    fn image_layout_signatures() {
        let img = build_esp(&sample_loader(), b"kernel-bytes", b"initfs-bytes");
        assert_eq!(
            img.len(),
            (PARTITION_LBA + PARTITION_SECTORS) as usize * SECTOR
        );
        // MBR signature + partition type 0xEF.
        assert_eq!(&img[510..512], &[0x55, 0xAA]);
        assert_eq!(img[0x1C2], 0xEF);
        assert_eq!(
            u32::from_le_bytes(img[0x1C6..0x1CA].try_into().unwrap()),
            PARTITION_LBA
        );
        // Boot sector signature and BPB fields.
        let bs = PARTITION_LBA as usize * SECTOR;
        assert_eq!(&img[bs + 510..bs + 512], &[0x55, 0xAA]);
        assert_eq!(&img[bs + 54..bs + 62], b"FAT16   ");
        assert_eq!(
            u16::from_le_bytes(img[bs + 11..bs + 13].try_into().unwrap()),
            512
        );
        assert_eq!(img[bs + 13], 8);
        assert_eq!(
            u32::from_le_bytes(img[bs + 32..bs + 36].try_into().unwrap()),
            PARTITION_SECTORS
        );
        // FAT[0] = 0xFFF8 (media), FAT[1] = 0xFFFF.
        let fat0 = (PARTITION_LBA + RESERVED_SECTORS as u32) as usize * SECTOR;
        assert_eq!(
            u32::from_le_bytes(img[fat0..fat0 + 4].try_into().unwrap()),
            0xFFFF_FFF8
        );
    }

    #[test]
    fn files_roundtrip() {
        let loader = sample_loader();
        let kernel: Vec<u8> = (0..300_000u32).map(|i| (i * 7 % 256) as u8).collect();
        let initramfs: Vec<u8> = (0..5000u32).map(|i| (i * 13 % 256) as u8).collect();
        let img = build_esp(&loader, &kernel, &initramfs);
        assert_eq!(read_file(&img, &["KERNEL.ELF"]).unwrap(), kernel);
        assert_eq!(read_file(&img, &[INITFS_NAME]).unwrap(), initramfs);
        assert_eq!(
            read_file(&img, &["EFI", "BOOT", "BOOTX64.EFI"]).unwrap(),
            loader
        );
        assert!(read_file(&img, &["NOPE.ELF"]).is_none());
        assert!(read_file(&img, &["EFI", "NOPE"]).is_none());
    }

    #[test]
    fn initfs_is_a_plain_83_root_entry() {
        let img = build_esp(b"loader", b"kernel", b"initramfs");
        let root = dir_entries(&img, None);
        let initfs = root
            .iter()
            .find(|e| e.name == name83("INITFS", "IMG"))
            .expect("INITFS.IMG in the root directory");
        assert_eq!(initfs.attr, ATTR_ARCHIVE);
        assert_eq!(initfs.size as usize, b"initramfs".len());
        assert!(
            root.iter().all(|e| e.attr & 0x0F != 0x0F),
            "no VFAT long-name entries should be emitted"
        );
    }

    #[test]
    fn cluster_count_is_fat16() {
        // Recompute the invariant: data clusters must be within [4085, 65525].
        let data_sectors = PARTITION_SECTORS
            - RESERVED_SECTORS as u32
            - NUM_FATS as u32 * SECTORS_PER_FAT as u32
            - ROOT_DIR_SECTORS as u32;
        let clusters = data_sectors / SECTORS_PER_CLUSTER as u32;
        assert!(clusters >= 4085, "too few clusters for FAT16: {clusters}");
        assert!(clusters < 65525, "too many clusters for FAT16: {clusters}");
        // FAT must hold all clusters: (clusters+2)*2 bytes <= FAT size.
        assert!((clusters as u64 + 2) * 2 <= SECTORS_PER_FAT as u64 * BYTES_PER_SECTOR as u64);
    }
}
