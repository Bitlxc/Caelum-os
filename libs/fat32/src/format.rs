//! Volume creation.
//!
//! `format` builds the same FAT32 layout that `mount` validates: BPB plus backup
//! BPB, both FAT copies zeroed with the three reserved entries initialised, the
//! FSInfo sector and its backup, and a zeroed root directory cluster. The
//! resulting image is deterministic (fixed volume id and timestamps), which
//! makes byte-level regression tests meaningful.

use crate::bpb;
use crate::{BlockDevice, Fat32, Fat32Error, FormatOptions, Layout, SECTOR_SIZE};

/// Create a fresh FAT32 volume on `device` and return it mounted.
///
/// The device must report 512-byte blocks; the volume occupies every block the
/// device reports. `options.sectors_per_cluster` of 0 selects a size derived
/// from the volume.
pub fn format<'a, D: BlockDevice>(
    device: &'a mut D,
    options: &FormatOptions,
) -> Result<Fat32<&'a mut D>, Fat32Error> {
    if device.block_size() != SECTOR_SIZE {
        return Err(Fat32Error::Unsupported);
    }
    let total_u64 = device.block_count();
    if total_u64 < 64 {
        // Far too small to host reserved sectors, two FATs and one cluster.
        return Err(Fat32Error::TooLarge);
    }
    if total_u64 > u32::MAX as u64 {
        return Err(Fat32Error::TooLarge);
    }
    let total_sectors = total_u64 as u32;
    let sectors_per_cluster = match options.sectors_per_cluster {
        0 => bpb::choose_sectors_per_cluster(total_sectors),
        spc if spc.is_power_of_two() && spc <= 128 => spc,
        _ => return Err(Fat32Error::InvalidArgument),
    };

    // Solve fat_sectors -> cluster_count with a monotone iteration: `fat_sectors`
    // only ever grows. A larger FAT shrinks the data area, which can make a
    // *smaller* FAT look sufficient again -- comparing for equality (the old
    // code) therefore oscillated forever between two sizes and could settle on
    // a FAT that cannot address every cluster.
    let mut fat_sectors = 1u32;
    let (data_start_sector, cluster_count) = loop {
        let data_start = bpb::RESERVED_SECTORS as u32 + bpb::NUM_FATS as u32 * fat_sectors;
        if data_start >= total_sectors {
            return Err(Fat32Error::TooLarge);
        }
        let clusters = (total_sectors - data_start) / sectors_per_cluster as u32;
        if clusters == 0 {
            return Err(Fat32Error::TooLarge);
        }
        // FAT entries needed for `clusters` data clusters plus the two reserved
        // entries; one sector holds four entries per 32-bit slot.
        let needed_fat = ((clusters as u64 + 2) * 4).div_ceil(SECTOR_SIZE as u64) as u32;
        if needed_fat <= fat_sectors {
            break (data_start, clusters);
        }
        fat_sectors = needed_fat;
    };
    if cluster_count > bpb::MAX_CLUSTERS {
        return Err(Fat32Error::TooLarge);
    }

    let mut layout = Layout {
        bytes_per_sector: SECTOR_SIZE as u16,
        sectors_per_cluster,
        reserved_sectors: bpb::RESERVED_SECTORS,
        num_fats: bpb::NUM_FATS,
        fat_sectors,
        total_sectors,
        root_cluster: 2,
        fsinfo_sector: bpb::FSINFO_SECTOR,
        backup_boot_sector: bpb::BACKUP_BOOT_SECTOR,
        cluster_count,
        data_start_sector,
    };

    // Belt and braces: verify the solved geometry through the same BPB codec
    // `mount` uses, so solver and on-disk format cannot drift apart. A failure
    // grows the FAT (never shrinks it) and recomputes the data area.
    let mut verified = false;
    for _ in 0..4 {
        let boot = bpb::build_boot_sector(&layout, &options.label);
        if let Ok(parsed) = bpb::parse(&boot) {
            if parsed.fat_sectors == layout.fat_sectors
                && parsed.cluster_count == layout.cluster_count
            {
                verified = true;
                break;
            }
        }
        layout.fat_sectors = layout
            .fat_sectors
            .checked_add(1)
            .ok_or(Fat32Error::TooLarge)?;
        let data_start =
            layout.reserved_sectors as u32 + layout.num_fats as u32 * layout.fat_sectors;
        if data_start >= layout.total_sectors {
            return Err(Fat32Error::TooLarge);
        }
        layout.data_start_sector = data_start;
        layout.cluster_count = (layout.total_sectors - data_start) / sectors_per_cluster as u32;
        if layout.cluster_count == 0 {
            return Err(Fat32Error::TooLarge);
        }
    }
    if !verified {
        return Err(Fat32Error::Corrupt);
    }
    let fat_sectors = layout.fat_sectors;

    let zero = [0u8; SECTOR_SIZE as usize];
    let boot = bpb::build_boot_sector(&layout, &options.label);
    write_sector(device, 0, &boot)?;
    write_sector(device, bpb::BACKUP_BOOT_SECTOR as u32, &boot)?;

    // Zero every FAT copy.
    for copy in 0..bpb::NUM_FATS as u32 {
        let base = layout.reserved_sectors as u32 + copy * fat_sectors;
        for sector in 0..fat_sectors {
            write_sector(device, base + sector, &zero)?;
        }
    }

    // Initialise the three reserved FAT entries in every copy:
    //   FAT[0] = media descriptor (0xF8) with the upper bits set,
    //   FAT[1] = end-of-chain marker for the reserved slot,
    //   FAT[2] = end-of-chain marker: the root directory owns one cluster.
    let mut entries = zero;
    entries[0..4].copy_from_slice(&0x0FFF_FFF8u32.to_le_bytes());
    entries[4..8].copy_from_slice(&0x0FFF_FFFFu32.to_le_bytes());
    entries[8..12].copy_from_slice(&0x0FFF_FFFFu32.to_le_bytes());
    for copy in 0..bpb::NUM_FATS as u32 {
        write_sector(
            device,
            layout.reserved_sectors as u32 + copy * fat_sectors,
            &entries,
        )?;
    }

    // FSInfo and its backup: one cluster (the root) is in use.
    let free_count = layout.cluster_count.saturating_sub(1);
    let next_free = if layout.cluster_count >= 2 { 3 } else { 2 };
    let info = bpb::build_fsinfo(free_count, next_free);
    write_sector(device, layout.fsinfo_sector as u32, &info)?;
    if layout.fsinfo_sector + 1 < layout.reserved_sectors {
        write_sector(device, layout.fsinfo_sector as u32 + 1, &info)?;
    }

    // Zero the root directory cluster.
    let root_lba = layout.data_start_sector;
    for sector in 0..sectors_per_cluster as u32 {
        write_sector(device, root_lba + sector, &zero)?;
    }

    device.flush()?;

    Ok(Fat32 {
        device,
        layout,
        free_count,
        next_free,
        fsinfo_dirty: false,
    })
}

fn write_sector<D: BlockDevice>(
    device: &mut D,
    lba: u32,
    data: &[u8; SECTOR_SIZE as usize],
) -> Result<(), Fat32Error> {
    device.write_exact(lba as u64, data)?;
    Ok(())
}
