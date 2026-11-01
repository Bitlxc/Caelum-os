//! Boot sector (BPB) parsing and construction.
//!
//! Only FAT32 is accepted. The parser is strict: an image whose BPB describes a
//! FAT12/FAT16 layout, a non-512 sector size, non-mirrored FATs or an
//! impossible geometry is rejected with a loud error instead of being guessed
//! at. The builder writes the same layout the parser accepts, so
//! [`crate::Fat32::format`] and [`crate::Fat32::mount`] share one source of
//! truth.

use crate::{FSINFO_LEAD, FSINFO_STRUCT, FSINFO_TRAIL, Fat32Error, Layout, SECTOR_SIZE};

/// FAT32 boot-sector jump instruction (`jmp short +0x58; nop`).
pub(crate) const BOOT_JUMP: [u8; 3] = [0xEB, 0x58, 0x90];
/// OEM name written by [`crate::Fat32::format`].
pub(crate) const OEM_NAME: [u8; 8] = *b"CAELUMOS";
/// Volume id written by [`crate::Fat32::format`] (fixed, for reproducible images).
pub(crate) const VOLUME_ID: u32 = 0xCA1E_0A05;
/// `FSType` string in the extended BPB.
pub(crate) const FS_TYPE: [u8; 8] = *b"FAT32   ";
/// Fat32 BPB field offsets / required values.
const MEDIA_DESCRIPTOR: u8 = 0xF8;
/// Sector where the FSInfo structure lives (and its backup at `+1`).
pub(crate) const FSINFO_SECTOR: u16 = 1;
/// Backup boot sector (BPB copy follows at `+1`).
pub(crate) const BACKUP_BOOT_SECTOR: u16 = 6;
/// Reserved sectors before the first FAT.
pub(crate) const RESERVED_SECTORS: u16 = 32;
/// Number of FAT copies written by format and expected by mount.
pub(crate) const NUM_FATS: u8 = 2;
/// Hard cap on FAT32 clusters (`0x0FFFFFF5` is the spec maximum minus overhead);
/// we stay well below it for 32-bit arithmetic headroom.
pub(crate) const MAX_CLUSTERS: u32 = 0x0FFF_FFE8;

/// Parse a boot sector into a validated [`Layout`].
pub(crate) fn parse(boot: &[u8; SECTOR_SIZE as usize]) -> Result<Layout, Fat32Error> {
    if boot[510] != 0x55 || boot[511] != 0xAA {
        return Err(Fat32Error::BadBpb);
    }
    let bytes_per_sector = u16::from_le_bytes([boot[11], boot[12]]);
    if bytes_per_sector as u32 != SECTOR_SIZE {
        // FAT12/16 and 1024/2048/4096-byte sectors are out of scope for M5b.
        return Err(Fat32Error::Unsupported);
    }
    let sectors_per_cluster = boot[13];
    if sectors_per_cluster == 0
        || !sectors_per_cluster.is_power_of_two()
        || sectors_per_cluster > 128
    {
        return Err(Fat32Error::BadBpb);
    }
    let reserved_sectors = u16::from_le_bytes([boot[14], boot[15]]);
    let num_fats = boot[16];
    let root_entries = u16::from_le_bytes([boot[17], boot[18]]);
    let total_sectors16 = u16::from_le_bytes([boot[19], boot[20]]);
    let fat_sectors16 = u16::from_le_bytes([boot[22], boot[23]]);
    let total_sectors32 = u32::from_le_bytes([boot[32], boot[33], boot[34], boot[35]]);
    let fat_sectors32 = u32::from_le_bytes([boot[36], boot[37], boot[38], boot[39]]);
    let ext_flags = u16::from_le_bytes([boot[40], boot[41]]);
    let root_cluster = u32::from_le_bytes([boot[44], boot[45], boot[46], boot[47]]);
    let fsinfo_sector = u16::from_le_bytes([boot[48], boot[49]]);
    let backup_boot_sector = u16::from_le_bytes([boot[50], boot[51]]);

    // FAT32 signature: the 16-bit fields are zero and the 32-bit ones are not.
    if reserved_sectors == 0
        || num_fats == 0
        || root_entries != 0
        || total_sectors16 != 0
        || fat_sectors16 != 0
        || fat_sectors32 == 0
        || total_sectors32 == 0
    {
        return Err(Fat32Error::BadBpb);
    }
    // "No mirroring / one active FAT" is a FAT32 feature we do not implement.
    if ext_flags & 0x0080 != 0 {
        return Err(Fat32Error::Unsupported);
    }
    let data_start_sector = reserved_sectors as u32 + num_fats as u32 * fat_sectors32;
    if data_start_sector >= total_sectors32 {
        return Err(Fat32Error::BadBpb);
    }
    let cluster_count = (total_sectors32 - data_start_sector) / sectors_per_cluster as u32;
    if cluster_count == 0 || cluster_count > MAX_CLUSTERS {
        return Err(Fat32Error::BadBpb);
    }
    if root_cluster < 2 || root_cluster > cluster_count + 1 {
        return Err(Fat32Error::BadBpb);
    }
    // The FAT must be able to address every cluster plus the two reserved slots.
    let fat_entries = fat_sectors32 as u64 * SECTOR_SIZE as u64 / 4;
    if fat_entries < cluster_count as u64 + 2 {
        return Err(Fat32Error::BadBpb);
    }
    // FSInfo, when present, must live in the reserved area and not overlap the BPB.
    if fsinfo_sector != 0 && (fsinfo_sector < 1 || fsinfo_sector >= reserved_sectors) {
        return Err(Fat32Error::BadBpb);
    }
    if backup_boot_sector != 0 && backup_boot_sector >= reserved_sectors {
        return Err(Fat32Error::BadBpb);
    }

    Ok(Layout {
        bytes_per_sector,
        sectors_per_cluster,
        reserved_sectors,
        num_fats,
        fat_sectors: fat_sectors32,
        total_sectors: total_sectors32,
        root_cluster,
        fsinfo_sector,
        backup_boot_sector,
        cluster_count,
        data_start_sector,
    })
}

/// Build the FAT32 boot sector for the given geometry.
pub(crate) fn build_boot_sector(layout: &Layout, label: &[u8; 11]) -> [u8; SECTOR_SIZE as usize] {
    let mut boot = [0u8; SECTOR_SIZE as usize];
    boot[0..3].copy_from_slice(&BOOT_JUMP);
    boot[3..11].copy_from_slice(&OEM_NAME);
    boot[11..13].copy_from_slice(&(SECTOR_SIZE as u16).to_le_bytes());
    boot[13] = layout.sectors_per_cluster;
    boot[14..16].copy_from_slice(&layout.reserved_sectors.to_le_bytes());
    boot[16] = layout.num_fats;
    boot[17..19].copy_from_slice(&0u16.to_le_bytes()); // root entry count: 0 for FAT32
    boot[19..21].copy_from_slice(&0u16.to_le_bytes()); // total sectors 16: 0 for FAT32
    boot[21] = MEDIA_DESCRIPTOR;
    boot[22..24].copy_from_slice(&0u16.to_le_bytes()); // FAT size 16: 0 for FAT32
    boot[24..26].copy_from_slice(&63u16.to_le_bytes()); // sectors per track (informational)
    boot[26..28].copy_from_slice(&255u16.to_le_bytes()); // heads (informational)
    boot[28..32].copy_from_slice(&0u32.to_le_bytes()); // hidden sectors
    boot[32..36].copy_from_slice(&layout.total_sectors.to_le_bytes());
    boot[36..40].copy_from_slice(&layout.fat_sectors.to_le_bytes());
    boot[40..42].copy_from_slice(&0u16.to_le_bytes()); // ExtFlags: mirrored FATs
    boot[42..44].copy_from_slice(&0u16.to_le_bytes()); // FS version 0.0
    boot[44..48].copy_from_slice(&layout.root_cluster.to_le_bytes());
    boot[48..50].copy_from_slice(&layout.fsinfo_sector.to_le_bytes());
    boot[50..52].copy_from_slice(&layout.backup_boot_sector.to_le_bytes());
    boot[64] = 0x80; // drive number
    boot[66] = 0x29; // extended boot signature
    boot[67..71].copy_from_slice(&VOLUME_ID.to_le_bytes());
    boot[71..82].copy_from_slice(label);
    boot[82..90].copy_from_slice(&FS_TYPE);
    boot[510] = 0x55;
    boot[511] = 0xAA;
    boot
}

/// Build the FSInfo sector.
pub(crate) fn build_fsinfo(free_count: u32, next_free: u32) -> [u8; SECTOR_SIZE as usize] {
    let mut info = [0u8; SECTOR_SIZE as usize];
    info[0..4].copy_from_slice(&FSINFO_LEAD.to_le_bytes());
    info[484..488].copy_from_slice(&FSINFO_STRUCT.to_le_bytes());
    info[488..492].copy_from_slice(&free_count.to_le_bytes());
    info[492..496].copy_from_slice(&next_free.to_le_bytes());
    info[508..512].copy_from_slice(&FSINFO_TRAIL.to_le_bytes());
    info
}

/// Values read back from an FSInfo sector.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct FsInfo {
    pub(crate) free_count: u32,
    pub(crate) next_free: u32,
}

/// Decode an FSInfo sector, or `None` when its signatures do not match.
pub(crate) fn parse_fsinfo(info: &[u8; SECTOR_SIZE as usize]) -> Option<FsInfo> {
    let lead = u32::from_le_bytes([info[0], info[1], info[2], info[3]]);
    let structure = u32::from_le_bytes([info[484], info[485], info[486], info[487]]);
    let trail = u32::from_le_bytes([info[508], info[509], info[510], info[511]]);
    if lead != FSINFO_LEAD || structure != FSINFO_STRUCT || trail != FSINFO_TRAIL {
        return None;
    }
    Some(FsInfo {
        free_count: u32::from_le_bytes([info[488], info[489], info[490], info[491]]),
        next_free: u32::from_le_bytes([info[492], info[493], info[494], info[495]]),
    })
}

/// Pick a sectors-per-cluster value for `total_sectors`.
///
/// Targets roughly 8 000 clusters, which keeps a 32 MiB test image at 4 KiB
/// clusters while staying valid for much larger volumes. The result is always a
/// power of two in `1..=128`, and the cluster count is clamped to
/// [`MAX_CLUSTERS`].
pub(crate) fn choose_sectors_per_cluster(total_sectors: u32) -> u8 {
    let target_clusters = 8192u64;
    let mut spc = 1u32;
    while spc < 128 {
        let clusters = total_sectors as u64 / spc as u64;
        if clusters <= target_clusters {
            break;
        }
        spc *= 2;
    }
    // Keep the cluster count inside the FAT32 limit.
    while (total_sectors as u64 / spc as u64) > MAX_CLUSTERS as u64 && spc < 128 {
        spc *= 2;
    }
    spc as u8
}
