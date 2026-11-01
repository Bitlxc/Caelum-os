//! Host tests for the FAT32 implementation.
//!
//! Every test runs against [`block::test_support::MemDisk`], i.e. the real
//! byte-level implementation against an in-memory device: format, mount,
//! directory and file operations, dual-FAT consistency, drop/remount
//! persistence, corrupt chains, read-only devices and injected I/O failures.

use super::*;
use block::test_support::MemDisk;
use std::vec::Vec;

/// 32 MiB at 512-byte sectors, the volume size used by most tests.
const DISK_BLOCKS: u64 = 65_536;

/// Scratch sector for crate-internal helpers that take a caller buffer.
///
/// The production entry points allocate exactly one of these per call; tests
/// that reach for a lower-level helper pass a throwaway one.
fn scratch() -> Sector {
    [0u8; SECTOR_SIZE as usize]
}

fn new_disk() -> MemDisk {
    MemDisk::new(DISK_BLOCKS, SECTOR_SIZE as u32)
}

/// Format a fresh disk and hand it back unmounted.
fn formatted_disk() -> MemDisk {
    let mut disk = new_disk();
    {
        let fs = format(&mut disk, &FormatOptions::default()).unwrap();
        fs.unmount().unwrap();
    }
    disk
}

fn mount(disk: &mut MemDisk) -> Fat32<&mut MemDisk> {
    Fat32::mount(disk).unwrap()
}

fn read_all<D: BlockDevice>(fs: &mut Fat32<D>, node: &FatNode) -> Vec<u8> {
    let mut out = std::vec![0u8; node.size as usize];
    let n = fs.read(node, 0, &mut out).unwrap();
    out.truncate(n);
    out
}

fn fat_copy(disk: &MemDisk, layout: &Layout, copy: u32) -> Vec<u8> {
    let size = layout.fat_sectors as usize * SECTOR_SIZE as usize;
    let start = (layout.reserved_sectors as u32 + copy * layout.fat_sectors) as usize
        * SECTOR_SIZE as usize;
    disk.data()[start..start + size].to_vec()
}

// ---- formatting / geometry ------------------------------------------------

#[test]
fn format_mount_geometry_is_self_consistent() {
    let mut disk = new_disk();
    let fs = format(&mut disk, &FormatOptions::default()).unwrap();
    let layout = *fs.layout();
    assert_eq!(layout.bytes_per_sector, 512);
    assert!(layout.sectors_per_cluster.is_power_of_two());
    assert_eq!(layout.num_fats, 2);
    assert_eq!(layout.root_cluster, 2);
    assert_eq!(layout.total_sectors as u64, DISK_BLOCKS);
    assert!(layout.cluster_count > 1);
    assert_eq!(fs.free_clusters(), Some(layout.cluster_count - 1));
    let root = fs.root();
    assert!(root.is_root());
    assert_eq!(root.kind, NodeKind::Directory);
    fs.unmount().unwrap();
}

#[test]
fn format_is_deterministic() {
    let a = formatted_disk();
    let b = formatted_disk();
    assert_eq!(a.data(), b.data());
}

#[test]
fn format_rejects_non_512_devices() {
    let mut disk = MemDisk::new(1024, 1024);
    assert_eq!(
        format(&mut disk, &FormatOptions::default()).err(),
        Some(Fat32Error::Unsupported)
    );
}

/// The capacity invariant that makes formatter output mountable: every data
/// cluster plus the two reserved entries must have a FAT slot, the data area
/// must start right after the FAT copies and must fit inside the volume.
fn assert_fat_capacity(layout: &Layout) {
    let entries = layout.fat_sectors as u64 * (SECTOR_SIZE as u64 / 4);
    assert!(
        entries >= layout.cluster_count as u64 + 2,
        "FAT holds {entries} entries but {} clusters + 2 reserved need {}",
        layout.cluster_count,
        layout.cluster_count as u64 + 2
    );
    assert_eq!(
        layout.data_start_sector,
        layout.reserved_sectors as u32 + layout.num_fats as u32 * layout.fat_sectors
    );
    assert!(
        layout.data_start_sector as u64
            + layout.cluster_count as u64 * layout.sectors_per_cluster as u64
            <= layout.total_sectors as u64
    );
}

#[test]
fn format_64mib_one_sector_clusters_is_self_consistent() {
    // Regression: 64 MiB with 1-sector clusters used to settle on a FAT one
    // sector too small (the solver oscillated between 1008 and 1009 sectors and
    // stopped at 1008), so `format` produced a BPB that `mount` rejected with
    // BadBpb.
    let mut disk = MemDisk::new(131_072, SECTOR_SIZE as u32); // 64 MiB
    let options = FormatOptions {
        sectors_per_cluster: 1,
        ..Default::default()
    };
    let fs = format(&mut disk, &options).unwrap();
    let layout = *fs.layout();
    assert_eq!(layout.sectors_per_cluster, 1);
    assert!(
        layout.cluster_count >= 65_525,
        "FAT32 geometry needs at least 65525 clusters, got {}",
        layout.cluster_count
    );
    assert_fat_capacity(&layout);
    fs.unmount().unwrap();

    // The volume must mount again after formatting, with identical geometry.
    let mut fs = Fat32::mount(&mut disk).unwrap();
    assert_eq!(*fs.layout(), layout);
    let root = fs.root();
    let mut file = fs.create(&root, "BIG.TXT", NodeKind::File).unwrap();
    fs.write(&mut file, 0, b"64 MiB with 1-sector clusters")
        .unwrap();
    assert_eq!(read_all(&mut fs, &file), b"64 MiB with 1-sector clusters");
    fs.unmount().unwrap();
}

#[test]
fn format_geometry_invariant_holds_across_sizes_and_cluster_sizes() {
    for blocks in [4_096u64, 65_536, 131_072] {
        for spc in [1u8, 2, 8, 64] {
            let mut disk = MemDisk::new(blocks, SECTOR_SIZE as u32);
            let options = FormatOptions {
                sectors_per_cluster: spc,
                ..Default::default()
            };
            let fs = format(&mut disk, &options).unwrap();
            let layout = *fs.layout();
            assert_eq!(layout.total_sectors as u64, blocks);
            assert_eq!(layout.sectors_per_cluster, spc);
            assert_fat_capacity(&layout);
            fs.unmount().unwrap();
            // Remounting must accept exactly the geometry the formatter wrote.
            let fs = Fat32::mount(&mut disk).unwrap();
            assert_eq!(*fs.layout(), layout, "{blocks} blocks spc={spc}");
            fs.unmount().unwrap();
        }
    }
}

// ---- basic file operations ------------------------------------------------

#[test]
fn create_write_read_file() {
    let mut disk = formatted_disk();
    let mut fs = mount(&mut disk);
    let root = fs.root();
    let mut file = fs.create(&root, "HELLO.TXT", NodeKind::File).unwrap();
    assert_eq!(file.size, 0);
    assert_eq!(fs.write(&mut file, 0, b"hello fat32").unwrap(), 11);
    assert_eq!(file.size, 11);
    assert_eq!(read_all(&mut fs, &file), b"hello fat32");
    // The handle in the directory entry knows the new size.
    let again = fs.lookup(&root, "hello.txt").unwrap();
    assert_eq!(again.size, 11);
    assert_eq!(again.kind, NodeKind::File);
    assert_eq!(read_all(&mut fs, &again), b"hello fat32");
}

#[test]
fn create_is_exclusive_and_names_are_case_insensitive() {
    let mut disk = formatted_disk();
    let mut fs = mount(&mut disk);
    let root = fs.root();
    fs.create(&root, "a.txt", NodeKind::File).unwrap();
    assert_eq!(
        fs.create(&root, "A.TXT", NodeKind::File).err(),
        Some(Fat32Error::AlreadyExists)
    );
    assert!(fs.lookup(&root, "A.txt").is_ok());
}

#[test]
fn bad_names_are_rejected_not_truncated() {
    let mut disk = formatted_disk();
    let mut fs = mount(&mut disk);
    let root = fs.root();
    for name in [
        "",
        ".",
        "..",
        "TOOLONGNAME.TXT",
        "A.TXTX",
        "A+B",
        "A,B",
        "A..TXT",
        "NAME.",
    ] {
        assert_eq!(
            fs.create(&root, name, NodeKind::File).err(),
            Some(Fat32Error::BadName),
            "name {name:?} must be rejected"
        );
    }
    // Longest legal names still work.
    fs.create(&root, "ABCDEFGH.IJK", NodeKind::File).unwrap();
    fs.create(&root, "12345678.123", NodeKind::File).unwrap();
}

#[test]
fn read_past_eof_is_short_or_empty() {
    let mut disk = formatted_disk();
    let mut fs = mount(&mut disk);
    let root = fs.root();
    let mut file = fs.create(&root, "DATA.BIN", NodeKind::File).unwrap();
    fs.write(&mut file, 0, b"abcd").unwrap();
    let mut buf = [0u8; 16];
    assert_eq!(fs.read(&file, 0, &mut buf).unwrap(), 4);
    assert_eq!(&buf[..4], b"abcd");
    assert_eq!(fs.read(&file, 4, &mut buf).unwrap(), 0);
    assert_eq!(fs.read(&file, 100, &mut buf).unwrap(), 0);
}

// ---- multi-cluster data / FAT mirroring -----------------------------------

#[test]
fn large_file_spans_clusters_and_mirrors_fat() {
    let mut disk = formatted_disk();
    let layout;
    {
        let mut fs = mount(&mut disk);
        let root = fs.root();
        let mut file = fs.create(&root, "BIG.BIN", NodeKind::File).unwrap();
        let payload: Vec<u8> = (0..6000u32).map(|i| (i % 251) as u8).collect();
        fs.write(&mut file, 0, &payload).unwrap();
        assert_eq!(read_all(&mut fs, &file), payload);
        assert_eq!(file.size, 6000);
        layout = *fs.layout();
        // Both FAT copies must be byte-identical, both while mounted ...
        assert_eq!(
            fat_copy(fs.device(), &layout, 0),
            fat_copy(fs.device(), &layout, 1)
        );
        fs.unmount().unwrap();
    }
    // ... and after the device was handed back.
    assert_eq!(fat_copy(&disk, &layout, 0), fat_copy(&disk, &layout, 1));
}

#[test]
fn drop_then_remount_reads_the_same_data() {
    let mut disk = formatted_disk();
    {
        let mut fs = mount(&mut disk);
        let root = fs.root();
        fs.create(&root, "DIR1", NodeKind::Directory).unwrap();
        let dir = fs.lookup(&root, "DIR1").unwrap();
        let mut file = fs.create(&dir, "LOG.TXT", NodeKind::File).unwrap();
        fs.write(&mut file, 0, b"persisted through remount")
            .unwrap();
        fs.unmount().unwrap();
    }
    {
        let mut fs = mount(&mut disk);
        let root = fs.root();
        let dir = fs.lookup(&root, "DIR1").unwrap();
        assert_eq!(dir.kind, NodeKind::Directory);
        let file = fs.lookup(&dir, "LOG.TXT").unwrap();
        assert_eq!(file.size, 25);
        assert_eq!(read_all(&mut fs, &file), b"persisted through remount");
        fs.unmount().unwrap();
    }
}

#[test]
fn sparse_write_zero_fills_the_gap() {
    let mut disk = formatted_disk();
    let mut fs = mount(&mut disk);
    let root = fs.root();
    let mut file = fs.create(&root, "SPARSE.BIN", NodeKind::File).unwrap();
    fs.write(&mut file, 10_000, b"ABCDE").unwrap();
    assert_eq!(file.size, 10_005);
    let data = read_all(&mut fs, &file);
    assert_eq!(data.len(), 10_005);
    assert!(
        data[..10_000].iter().all(|&b| b == 0),
        "gap must read as zeros"
    );
    assert_eq!(&data[10_000..], b"ABCDE");
}

#[test]
fn truncate_shrinks_and_grows() {
    let mut disk = formatted_disk();
    let mut fs = mount(&mut disk);
    let root = fs.root();
    let mut file = fs.create(&root, "TRUNC.BIN", NodeKind::File).unwrap();
    let payload: Vec<u8> = (0..5000u32).map(|i| (i % 97) as u8).collect();
    fs.write(&mut file, 0, &payload).unwrap();
    let free_before = fs.free_clusters().unwrap();
    fs.truncate(&mut file, 1000).unwrap();
    assert_eq!(file.size, 1000);
    assert_eq!(fs.free_clusters().unwrap(), free_before + 1);
    assert_eq!(read_all(&mut fs, &file), payload[..1000]);
    let mut buf = [0u8; 32];
    assert_eq!(fs.read(&file, 1000, &mut buf).unwrap(), 0);

    fs.truncate(&mut file, 3000).unwrap();
    assert_eq!(file.size, 3000);
    let data = read_all(&mut fs, &file);
    assert_eq!(&data[..1000], &payload[..1000]);
    assert!(
        data[1000..].iter().all(|&b| b == 0),
        "grown region must be zeroed"
    );

    fs.truncate(&mut file, 0).unwrap();
    assert_eq!(file.size, 0);
    assert_eq!(fs.read(&file, 0, &mut buf).unwrap(), 0);
    fs.unmount().unwrap();
}

#[test]
fn truncate_to_fewer_clusters_rewrites_terminator() {
    let mut disk = formatted_disk();
    let mut fs = mount(&mut disk);
    let root = fs.root();
    let mut file = fs.create(&root, "CHAIN.BIN", NodeKind::File).unwrap();
    let payload = std::vec![0x5Au8; 20_000];
    fs.write(&mut file, 0, &payload).unwrap();
    let first = fs.node_first_cluster(&file, &mut scratch()).unwrap();
    let clusters_before = fs.chain_len(first, &mut scratch()).unwrap();
    assert!(clusters_before > 3);
    fs.truncate(&mut file, 5000).unwrap();
    let first = fs.node_first_cluster(&file, &mut scratch()).unwrap();
    let clusters_after = fs.chain_len(first, &mut scratch()).unwrap();
    assert_eq!(clusters_after, 5000u64.div_ceil(4096) as u32);
    // The chain must still terminate and be readable.
    assert_eq!(read_all(&mut fs, &file).len(), 5000);
}

// ---- directories ----------------------------------------------------------

#[test]
fn directories_create_list_and_remove() {
    let mut disk = formatted_disk();
    let mut fs = mount(&mut disk);
    let root = fs.root();
    let sub = fs.create(&root, "SUB", NodeKind::Directory).unwrap();
    let mut inner = fs.create(&sub, "INNER.TXT", NodeKind::File).unwrap();
    fs.write(&mut inner, 0, b"nested").unwrap();

    let mut top = Vec::new();
    fs.readdir(&root, |e| {
        top.push(e.name().to_vec());
        Ok(())
    })
    .unwrap();
    assert_eq!(top, std::vec![b"SUB".to_vec()]);

    let mut children = Vec::new();
    fs.readdir(&sub, |e| {
        children.push(e.name().to_vec());
        Ok(())
    })
    .unwrap();
    assert_eq!(children, std::vec![b"INNER.TXT".to_vec()]);

    // A non-empty directory cannot be removed.
    assert_eq!(fs.unlink(&sub).err(), Some(Fat32Error::NotEmpty));
    fs.unlink(&inner).unwrap();
    fs.unlink(&sub).unwrap();
    assert_eq!(fs.lookup(&root, "SUB").err(), Some(Fat32Error::NotFound));
}

#[test]
fn many_entries_extend_the_directory() {
    let mut disk = formatted_disk();
    let mut fs = mount(&mut disk);
    let root = fs.root();
    // One cluster of a 32 MiB volume holds 16 entries per sector * 8 sectors;
    // create well past that so the directory has to grow.
    for i in 0..40u32 {
        let name = std::format!("F{i:04}");
        fs.create(&root, &name, NodeKind::File).unwrap();
    }
    let mut count = 0usize;
    fs.readdir(&root, |_e| {
        count += 1;
        Ok(())
    })
    .unwrap();
    assert_eq!(count, 40);
}

#[test]
fn rename_file_across_directories() {
    let mut disk = formatted_disk();
    let mut fs = mount(&mut disk);
    let root = fs.root();
    let a = fs.create(&root, "A", NodeKind::Directory).unwrap();
    let b = fs.create(&root, "B", NodeKind::Directory).unwrap();
    let mut file = fs.create(&a, "OLD.TXT", NodeKind::File).unwrap();
    fs.write(&mut file, 0, b"payload").unwrap();

    fs.rename(&mut file, &b, "NEW.TXT").unwrap();
    let b_cluster = fs.dir_cluster_of(&b, &mut scratch()).unwrap();
    assert_eq!(file.parent, b_cluster);
    assert_eq!(fs.lookup(&a, "OLD.TXT").err(), Some(Fat32Error::NotFound));
    let moved = fs.lookup(&b, "NEW.TXT").unwrap();
    assert_eq!(moved.size, 7);
    assert_eq!(read_all(&mut fs, &moved), b"payload");
    assert_eq!(moved.parent, fs.dir_cluster_of(&b, &mut scratch()).unwrap());
}

#[test]
fn rename_directory_updates_dot_dot_link() {
    let mut disk = formatted_disk();
    let mut fs = mount(&mut disk);
    let root = fs.root();
    let parent = fs.create(&root, "PARENT", NodeKind::Directory).unwrap();
    let mut child = fs.create(&parent, "CHILD", NodeKind::Directory).unwrap();
    fs.rename(&mut child, &root, "MOVED").unwrap();
    let moved = fs.lookup(&root, "MOVED").unwrap();
    // A file created inside the moved directory must be reachable, and the
    // directory must be movable again (its ".." link points at the new parent).
    let mut inner = fs.create(&moved, "X.TXT", NodeKind::File).unwrap();
    fs.write(&mut inner, 0, b"x").unwrap();
    let mut again = moved;
    fs.rename(&mut again, &parent, "BACK").unwrap();
    let back = fs.lookup(&parent, "BACK").unwrap();
    assert_eq!(fs.lookup(&back, "X.TXT").unwrap().size, 1);
}

#[test]
fn rename_into_own_subtree_is_rejected() {
    let mut disk = formatted_disk();
    let mut fs = mount(&mut disk);
    let root = fs.root();
    let top = fs.create(&root, "TOP", NodeKind::Directory).unwrap();
    let inner = fs.create(&top, "INNER", NodeKind::Directory).unwrap();
    let mut top_mut = top;
    assert_eq!(
        fs.rename(&mut top_mut, &inner, "OOPS").err(),
        Some(Fat32Error::InvalidArgument)
    );
}

#[test]
fn unlink_rejects_root_and_reports_missing() {
    let mut disk = formatted_disk();
    let mut fs = mount(&mut disk);
    let root = fs.root();
    assert_eq!(fs.unlink(&root).err(), Some(Fat32Error::InvalidArgument));
    let file = fs.create(&root, "GONE.TXT", NodeKind::File).unwrap();
    fs.unlink(&file).unwrap();
    assert_eq!(fs.unlink(&file).err(), Some(Fat32Error::NotFound));
}

#[test]
fn lfn_chunks_are_skipped_not_interpreted() {
    let mut disk = formatted_disk();
    let mut fs = mount(&mut disk);
    let layout = *fs.layout();
    let root_sector = layout.data_start_sector;
    let mut sector = [0u8; SECTOR_SIZE as usize];
    // A long-file-name chunk sits before the short entry.
    sector[0..11].copy_from_slice(b"LONGNAME   ");
    sector[11] = 0x0F;
    sector[13] = 0x41; // last LFN chunk, no checksum verification
    // The short entry itself.
    let at = 32;
    sector[at..at + 11].copy_from_slice(b"HELLO   TXT");
    sector[at + 11] = 0x20;
    fs.device_mut()
        .write_exact(root_sector as u64, &sector)
        .unwrap();
    let root = fs.root();
    let node = fs.lookup(&root, "HELLO.TXT").unwrap();
    assert_eq!(node.kind, NodeKind::File);
    let mut names = Vec::new();
    fs.readdir(&root, |e| {
        names.push(e.name().to_vec());
        Ok(())
    })
    .unwrap();
    assert_eq!(names, std::vec![b"HELLO.TXT".to_vec()]);
}

// ---- error paths ----------------------------------------------------------

#[test]
fn corrupt_boot_sectors_are_rejected() {
    let cases: [(&str, Vec<(usize, u8)>); 4] = [
        ("bytes-per-sector", std::vec![(11usize, 0u8), (12, 4)]),
        ("boot signature", std::vec![(510usize, 0u8)]),
        ("sectors-per-cluster", std::vec![(13usize, 3u8)]),
        ("root-cluster", std::vec![(44usize, 0u8)]),
    ];
    for (label, patches) in cases {
        let mut disk = formatted_disk();
        for (offset, value) in patches {
            disk.data_mut()[offset] = value;
        }
        let err = Fat32::mount(&mut disk).err();
        assert!(
            matches!(
                err,
                Some(Fat32Error::BadBpb) | Some(Fat32Error::Unsupported)
            ),
            "{label}: unexpected {err:?}"
        );
    }
}

#[test]
fn wiped_fat_or_unallocated_root_is_rejected() {
    let mut disk = formatted_disk();
    let layout = *Fat32::mount(&mut disk).unwrap().layout();
    // Wipe FAT[0]: media descriptor gone.
    disk.data_mut()[layout.reserved_sectors as usize * SECTOR_SIZE as usize] = 0;
    assert_eq!(Fat32::mount(&mut disk).err(), Some(Fat32Error::Corrupt));
}

#[test]
fn corrupt_chain_reports_corrupt() {
    let mut disk = formatted_disk();
    let mut fs = mount(&mut disk);
    let root = fs.root();
    let mut file = fs.create(&root, "BAD.BIN", NodeKind::File).unwrap();
    fs.write(&mut file, 0, &std::vec![0x11u8; 6000]).unwrap();
    let layout = *fs.layout();
    let first = fs.node_first_cluster(&file, &mut scratch()).unwrap();
    assert!(first >= 3);
    // Point the first cluster's FAT entry at the free marker: chain is broken.
    let fat_offset = layout.reserved_sectors as usize * SECTOR_SIZE as usize + first as usize * 4;
    fs.device_mut().data_mut()[fat_offset..fat_offset + 4].copy_from_slice(&0u32.to_le_bytes());
    assert_eq!(
        fs.chain_len(first, &mut scratch()).err(),
        Some(Fat32Error::Corrupt)
    );
}

#[test]
fn injected_io_failures_propagate() {
    let mut disk = formatted_disk();
    let mut fs = mount(&mut disk);
    let root = fs.root();
    fs.device_mut().failure = BlockError::Timeout;
    fs.device_mut().fail_next_writes(1);
    assert_eq!(
        fs.create(&root, "FAIL.TXT", NodeKind::File).err(),
        Some(Fat32Error::Block(BlockError::Timeout))
    );
    fs.device_mut().fail_next_reads(1);
    assert_eq!(
        fs.lookup(&root, "FAIL.TXT").err(),
        Some(Fat32Error::Block(BlockError::Timeout))
    );
    fs.device_mut().fail_next_flushes(1);
    assert_eq!(
        fs.sync().err(),
        Some(Fat32Error::Block(BlockError::Timeout))
    );
}

#[test]
fn read_only_device_rejects_metadata_and_data_writes() {
    let mut disk = formatted_disk();
    let mut fs = mount(&mut disk);
    let root = fs.root();
    let mut file = fs.create(&root, "RO.TXT", NodeKind::File).unwrap();
    fs.write(&mut file, 0, b"payload").unwrap();
    fs.device_mut().read_only = true;
    assert_eq!(
        fs.write(&mut file, 0, b"x").err(),
        Some(Fat32Error::Block(BlockError::ReadOnly))
    );
    assert_eq!(
        fs.create(&root, "NEW.TXT", NodeKind::File).err(),
        Some(Fat32Error::Block(BlockError::ReadOnly))
    );
    assert_eq!(
        fs.truncate(&mut file, 1).err(),
        Some(Fat32Error::Block(BlockError::ReadOnly))
    );
}

#[test]
fn offsets_beyond_fat32_limits_are_rejected() {
    let mut disk = formatted_disk();
    let mut fs = mount(&mut disk);
    let root = fs.root();
    let mut file = fs.create(&root, "LIMIT.TXT", NodeKind::File).unwrap();
    assert_eq!(
        fs.write(&mut file, u32::MAX as u64 + 1, b"x").err(),
        Some(Fat32Error::TooLarge)
    );
    assert_eq!(
        fs.truncate(&mut file, u32::MAX as u64 + 1).err(),
        Some(Fat32Error::TooLarge)
    );
    assert_eq!(
        fs.truncate(&mut file, 1 << 40).err(),
        Some(Fat32Error::TooLarge)
    );
}

#[test]
fn volume_full_is_reported() {
    let mut disk = MemDisk::new(4096, SECTOR_SIZE as u32); // 2 MiB
    {
        let fs = format(&mut disk, &FormatOptions::default()).unwrap();
        fs.unmount().unwrap();
    }
    let mut fs = mount(&mut disk);
    let root = fs.root();
    let mut file = fs.create(&root, "BIG.BIN", NodeKind::File).unwrap();
    // One oversized write cannot fit the volume.
    let huge = std::vec![0xAAu8; 3 * 1024 * 1024];
    assert!(matches!(
        fs.write(&mut file, 0, &huge).err(),
        Some(Fat32Error::TooLarge) | Some(Fat32Error::NoSpace)
    ));
    // Filling 512 bytes at a time eventually exhausts free clusters.
    let chunk = [0x55u8; SECTOR_SIZE as usize];
    let mut offset = file.size;
    let mut exhausted = None;
    for _ in 0..8192 {
        match fs.write(&mut file, offset, &chunk) {
            Ok(_) => offset += chunk.len() as u64,
            Err(e) => {
                exhausted = Some(e);
                break;
            }
        }
    }
    assert!(matches!(
        exhausted,
        Some(Fat32Error::NoSpace) | Some(Fat32Error::TooLarge)
    ));
}

#[test]
fn directory_operations_reject_files_as_parents() {
    let mut disk = formatted_disk();
    let mut fs = mount(&mut disk);
    let root = fs.root();
    let mut file = fs.create(&root, "PLAIN.TXT", NodeKind::File).unwrap();
    fs.write(&mut file, 0, b"data").unwrap();
    assert_eq!(
        fs.create(&file, "CHILD.TXT", NodeKind::File).err(),
        Some(Fat32Error::NotADirectory)
    );
    assert_eq!(fs.lookup(&file, "X").err(), Some(Fat32Error::NotADirectory));
    let mut buf = [0u8; 4];
    let _ = fs.read(&root, 0, &mut buf);
    assert_eq!(
        fs.read(&root, 0, &mut buf).err(),
        Some(Fat32Error::IsADirectory)
    );
}

/// Device decorator that records the lowest stack pointer observed inside any
/// block read/write/flush.
///
/// The FAT32 boot path runs on the 16 KiB kernel boot stack; before the sector
/// scrach rework every helper owned one or more 512-byte buffers and the first
/// `create` + `write` chain reached ~15.7 KiB. Keeping a measured budget in the
/// host tests makes that regression impossible to reintroduce silently.
struct StackProbe<'a> {
    inner: &'a mut MemDisk,
    base: usize,
    low: usize,
}

impl<'a> StackProbe<'a> {
    fn new(inner: &'a mut MemDisk) -> Self {
        let base = stack_mark();
        Self {
            inner,
            base,
            low: base,
        }
    }

    fn observe(&mut self) {
        let sp = stack_mark();
        if sp < self.low {
            self.low = sp;
        }
    }

    fn peak(&self) -> usize {
        self.base.saturating_sub(self.low)
    }
}

/// Address of a stack local; the exact value is irrelevant, only its ordering.
#[inline(never)]
fn stack_mark() -> usize {
    let marker = 0u8;
    core::ptr::addr_of!(marker) as usize
}

impl BlockDevice for StackProbe<'_> {
    fn block_size(&self) -> u32 {
        self.inner.block_size()
    }

    fn block_count(&self) -> u64 {
        self.inner.block_count()
    }

    fn read_blocks(&mut self, first: u64, buf: &mut [u8]) -> Result<(), BlockError> {
        self.observe();
        self.inner.read_blocks(first, buf)
    }

    fn write_blocks(&mut self, first: u64, buf: &[u8]) -> Result<(), BlockError> {
        self.observe();
        self.inner.write_blocks(first, buf)
    }

    fn flush(&mut self) -> Result<(), BlockError> {
        self.observe();
        self.inner.flush()
    }
}

/// The first-boot FAT chain (mount -> create -> write -> truncate -> readdir ->
/// sync) must stay far below the 16 KiB boot stack.
#[test]
fn deep_operations_stay_within_fat_stack_budget() {
    let mut disk = formatted_disk();
    let root_marker = stack_mark();
    let probe = StackProbe::new(&mut disk);
    let base = probe.base;
    assert!(root_marker != 0 && base != 0);

    let mut fs = Fat32::mount(probe).unwrap();
    let root = fs.root();
    let mut file = fs.create(&root, "STACK.TXT", NodeKind::File).unwrap();
    fs.write(&mut file, 0, b"stack budget payload").unwrap();
    fs.truncate(&mut file, 3000).unwrap();
    let mut entries = 0u32;
    fs.readdir(&root, |_entry| {
        entries += 1;
        Ok(())
    })
    .unwrap();
    fs.sync().unwrap();
    assert_eq!(entries, 1);

    let peak = fs.device().peak();
    std::eprintln!("fat32 deep chain peak stack: {peak} bytes");
    assert!(
        peak < 8 * 1024,
        "fat32 deep chain used {peak} bytes of stack (budget 8192)"
    );
}

// ---- rename rollback under injected I/O faults ----------------------------

/// A device that fails exactly the `fail_at`-th write (1-based) it sees.
///
/// `fail_at == 0` disables the fault and only counts writes.
struct FailWrites<'a> {
    disk: &'a mut MemDisk,
    fail_at: u32,
    writes: u32,
}

impl<'a> FailWrites<'a> {
    fn new(disk: &'a mut MemDisk, fail_at: u32) -> Self {
        FailWrites {
            disk,
            fail_at,
            writes: 0,
        }
    }
}

impl BlockDevice for FailWrites<'_> {
    fn block_size(&self) -> u32 {
        self.disk.block_size()
    }

    fn block_count(&self) -> u64 {
        self.disk.block_count()
    }

    fn read_blocks(&mut self, first: u64, buf: &mut [u8]) -> Result<(), BlockError> {
        self.disk.read_blocks(first, buf)
    }

    fn write_blocks(&mut self, first: u64, buf: &[u8]) -> Result<(), BlockError> {
        self.writes += 1;
        if self.fail_at != 0 && self.writes == self.fail_at {
            return Err(BlockError::Io);
        }
        self.disk.write_blocks(first, buf)
    }

    fn flush(&mut self) -> Result<(), BlockError> {
        self.disk.flush()
    }
}

/// A device failing two distinct writes, used to make rollback itself fail.
struct FailTwoWrites<'a> {
    disk: &'a mut MemDisk,
    first: u32,
    second: u32,
    writes: u32,
}

impl<'a> FailTwoWrites<'a> {
    fn new(disk: &'a mut MemDisk, first: u32, second: u32) -> Self {
        FailTwoWrites {
            disk,
            first,
            second,
            writes: 0,
        }
    }
}

impl BlockDevice for FailTwoWrites<'_> {
    fn block_size(&self) -> u32 {
        self.disk.block_size()
    }

    fn block_count(&self) -> u64 {
        self.disk.block_count()
    }

    fn read_blocks(&mut self, first: u64, buf: &mut [u8]) -> Result<(), BlockError> {
        self.disk.read_blocks(first, buf)
    }

    fn write_blocks(&mut self, first: u64, buf: &[u8]) -> Result<(), BlockError> {
        self.writes += 1;
        if self.writes == self.first || self.writes == self.second {
            return Err(BlockError::Io);
        }
        self.disk.write_blocks(first, buf)
    }

    fn flush(&mut self) -> Result<(), BlockError> {
        self.disk.flush()
    }
}

/// Build a formatted image, run `setup`, sync, and return the raw bytes.
fn scene<F>(blocks: u64, sectors_per_cluster: u8, setup: F) -> Vec<u8>
where
    F: FnOnce(&mut Fat32<&mut MemDisk>),
{
    let mut disk = MemDisk::new(blocks, SECTOR_SIZE as u32);
    let options = FormatOptions {
        sectors_per_cluster,
        ..FormatOptions::default()
    };
    {
        let mut fs = format(&mut disk, &options).unwrap();
        setup(&mut fs);
        fs.sync().unwrap();
        fs.unmount().unwrap();
    }
    disk.data().to_vec()
}

fn walk<D: BlockDevice>(fs: &mut Fat32<D>, parts: &[&str]) -> Option<FatNode> {
    let mut node = fs.root();
    for part in parts {
        node = fs.lookup(&node, part).ok()?;
    }
    Some(node)
}

fn file_bytes<D: BlockDevice>(fs: &mut Fat32<D>, node: &FatNode) -> Vec<u8> {
    let mut out = std::vec![0u8; node.size as usize];
    let n = fs.read(node, 0, &mut out).unwrap();
    out.truncate(n);
    out
}

fn fat_free_entries(disk: &MemDisk, layout: &Layout) -> u32 {
    let fat_bytes = layout.fat_sectors as usize * SECTOR_SIZE as usize;
    let start = layout.reserved_sectors as usize * SECTOR_SIZE as usize;
    let fat = &disk.data()[start..start + fat_bytes];
    let mut free = 0;
    for cluster in 2..=layout.max_cluster() {
        let at = cluster as usize * 4;
        if at + 4 > fat.len() {
            break;
        }
        let value = u32::from_le_bytes([fat[at], fat[at + 1], fat[at + 2], fat[at + 3]]) & FAT_MASK;
        if value == 0 {
            free += 1;
        }
    }
    free
}

/// Names, contents, free-cluster counts and dual-FAT equality after a remount.
#[derive(Debug, PartialEq, Eq)]
struct TreeState {
    old_present: bool,
    old_data: Vec<u8>,
    new_present: bool,
    new_data: Vec<u8>,
    free: Option<u32>,
    fat_free: u32,
    fat_mirrors_equal: bool,
}

fn tree_state(disk: &mut MemDisk, old: &[&str], new: &[&str]) -> TreeState {
    let mut fs = Fat32::mount(&mut *disk).unwrap();
    let layout = *fs.layout();
    let old_node = walk(&mut fs, old);
    let new_node = walk(&mut fs, new);
    let old_data = match old_node {
        Some(node) if node.kind == NodeKind::File => file_bytes(&mut fs, &node),
        _ => Vec::new(),
    };
    let new_data = match new_node {
        Some(node) if node.kind == NodeKind::File => file_bytes(&mut fs, &node),
        _ => Vec::new(),
    };
    let free = fs.free_clusters();
    fs.unmount().unwrap();
    TreeState {
        old_present: old_node.is_some(),
        old_data,
        new_present: new_node.is_some(),
        new_data,
        free,
        fat_free: fat_free_entries(disk, &layout),
        fat_mirrors_equal: fat_copy(disk, &layout, 0) == fat_copy(disk, &layout, 1),
    }
}

/// Run one rename against a fresh copy of `image`, failing write `fail_at`.
fn attempt_rename(
    image: &[u8],
    fail_at: u32,
    old_path: &[&str],
    new_path: &[&str],
    new_name: &str,
) -> (Result<(), Fat32Error>, MemDisk) {
    let mut disk = MemDisk::from_bytes(image.to_vec(), SECTOR_SIZE as u32);
    let result = {
        let mut fs = Fat32::mount(FailWrites::new(&mut disk, fail_at)).unwrap();
        let mut old = walk(&mut fs, old_path).unwrap();
        let new_parent = walk(&mut fs, new_path).unwrap();
        let result = fs.rename(&mut old, &new_parent, new_name);
        let _ = fs.unmount();
        result
    };
    (result, disk)
}

#[test]
fn rename_across_directories_rolls_back_on_every_write() {
    let image = scene(DISK_BLOCKS, 0, |fs| {
        let root = fs.root();
        let a = fs.create(&root, "A", NodeKind::Directory).unwrap();
        fs.create(&root, "B", NodeKind::Directory).unwrap();
        let mut old = fs.create(&a, "OLD.TXT", NodeKind::File).unwrap();
        fs.write(&mut old, 0, b"payload-A").unwrap();
    });
    let mut probe = MemDisk::from_bytes(image.clone(), SECTOR_SIZE as u32);
    let baseline = tree_state(&mut probe, &["A", "OLD.TXT"], &["B", "NEW.TXT"]);
    assert!(baseline.old_present && !baseline.new_present);
    assert!(baseline.fat_mirrors_equal);

    let mut rollbacks = 0;
    let mut fail_at = 1;
    loop {
        let (result, mut disk) =
            attempt_rename(&image, fail_at, &["A", "OLD.TXT"], &["B"], "NEW.TXT");
        let state = tree_state(&mut disk, &["A", "OLD.TXT"], &["B", "NEW.TXT"]);
        assert!(
            state.fat_mirrors_equal,
            "dual FAT diverged at write #{fail_at}"
        );
        match result {
            Ok(()) => {
                assert!(!state.old_present, "source still present after rename");
                assert!(state.new_present, "target missing after rename");
                assert_eq!(state.new_data, b"payload-A".to_vec());
                break;
            }
            Err(error) => {
                assert_eq!(
                    error,
                    Fat32Error::Block(BlockError::Io),
                    "write #{fail_at} should surface the injected fault"
                );
                assert_eq!(
                    state, baseline,
                    "rollback after write #{fail_at} is asymmetric"
                );
                rollbacks += 1;
            }
        }
        fail_at += 1;
        assert!(fail_at < 40, "rename never succeeded under the fault sweep");
    }
    assert!(
        rollbacks >= 2,
        "fault sweep only exercised {rollbacks} rollbacks"
    );
}

#[test]
fn rename_within_directory_rolls_back_on_every_write() {
    let image = scene(DISK_BLOCKS, 0, |fs| {
        let root = fs.root();
        let a = fs.create(&root, "A", NodeKind::Directory).unwrap();
        let mut old = fs.create(&a, "OLD.TXT", NodeKind::File).unwrap();
        fs.write(&mut old, 0, b"same-dir").unwrap();
    });
    let mut probe = MemDisk::from_bytes(image.clone(), SECTOR_SIZE as u32);
    let baseline = tree_state(&mut probe, &["A", "OLD.TXT"], &["A", "NEW.TXT"]);

    let mut rollbacks = 0;
    let mut fail_at = 1;
    loop {
        let (result, mut disk) =
            attempt_rename(&image, fail_at, &["A", "OLD.TXT"], &["A"], "NEW.TXT");
        let state = tree_state(&mut disk, &["A", "OLD.TXT"], &["A", "NEW.TXT"]);
        match result {
            Ok(()) => {
                assert!(!state.old_present);
                assert!(state.new_present);
                assert_eq!(state.new_data, b"same-dir".to_vec());
                break;
            }
            Err(error) => {
                assert_eq!(error, Fat32Error::Block(BlockError::Io));
                assert_eq!(state, baseline, "rollback after write #{fail_at}");
                rollbacks += 1;
            }
        }
        fail_at += 1;
        assert!(fail_at < 40, "rename never succeeded under the fault sweep");
    }
    assert!(rollbacks >= 1);
}

#[test]
fn rename_directory_cross_directory_restores_dot_dot() {
    let image = scene(DISK_BLOCKS, 0, |fs| {
        let root = fs.root();
        let p1 = fs.create(&root, "P1", NodeKind::Directory).unwrap();
        fs.create(&root, "P2", NodeKind::Directory).unwrap();
        let d = fs.create(&p1, "D", NodeKind::Directory).unwrap();
        let mut inner = fs.create(&d, "IN.BIN", NodeKind::File).unwrap();
        fs.write(&mut inner, 0, b"inside").unwrap();
    });
    let mut probe = MemDisk::from_bytes(image.clone(), SECTOR_SIZE as u32);
    let baseline = tree_state(&mut probe, &["P1", "D"], &["P2", "D2"]);

    let mut rollbacks = 0;
    let mut fail_at = 1;
    loop {
        let (result, mut disk) = attempt_rename(&image, fail_at, &["P1", "D"], &["P2"], "D2");
        let state = tree_state(&mut disk, &["P1", "D"], &["P2", "D2"]);
        match result {
            Ok(()) => break,
            Err(error) => {
                assert_eq!(error, Fat32Error::Block(BlockError::Io));
                assert_eq!(state, baseline, "rollback after write #{fail_at}");
                // `..` must point back at P1: moving P1 into D is a descendant
                // move and has to be rejected. A stale `..` (P2) would let the
                // move through and is exactly the inconsistency being checked.
                let mut fs = Fat32::mount(&mut disk).unwrap();
                let mut p1 = walk(&mut fs, &["P1"]).unwrap();
                let d = walk(&mut fs, &["P1", "D"]).unwrap();
                assert_eq!(
                    fs.rename(&mut p1, &d, "MOVE_P1").err(),
                    Some(Fat32Error::InvalidArgument),
                    "`..` was not restored after write #{fail_at}"
                );
                rollbacks += 1;
            }
        }
        fail_at += 1;
        assert!(fail_at < 40, "rename never succeeded under the fault sweep");
    }
    assert!(
        rollbacks >= 2,
        "only {rollbacks} dot-dot rollbacks exercised"
    );
}

#[test]
fn rename_into_occupied_name_writes_nothing() {
    let image = scene(DISK_BLOCKS, 0, |fs| {
        let root = fs.root();
        let a = fs.create(&root, "A", NodeKind::Directory).unwrap();
        let mut old = fs.create(&a, "OLD.TXT", NodeKind::File).unwrap();
        fs.write(&mut old, 0, b"keep").unwrap();
        let mut taken = fs.create(&a, "TAKEN.TXT", NodeKind::File).unwrap();
        fs.write(&mut taken, 0, b"taken").unwrap();
    });
    let mut disk = MemDisk::from_bytes(image, SECTOR_SIZE as u32);
    let mut fs = Fat32::mount(FailWrites::new(&mut disk, 0)).unwrap();
    let free_before = fs.free_clusters();
    let mut old = walk(&mut fs, &["A", "OLD.TXT"]).unwrap();
    let a = walk(&mut fs, &["A"]).unwrap();
    assert_eq!(
        fs.rename(&mut old, &a, "TAKEN.TXT").err(),
        Some(Fat32Error::AlreadyExists)
    );
    assert_eq!(fs.device().writes, 0, "occupied target must not write");
    assert_eq!(fs.free_clusters(), free_before);
    let mut fs = {
        let _ = fs.unmount();
        Fat32::mount(&mut disk).unwrap()
    };
    assert!(walk(&mut fs, &["A", "OLD.TXT"]).is_some());
    assert!(walk(&mut fs, &["A", "TAKEN.TXT"]).is_some());
}

#[test]
fn rename_into_full_directory_rolls_back_extension() {
    // 2 MiB with one-sector clusters: a cluster holds 16 entries, so a
    // directory with `.`, `..` and 14 files is exactly full and the rename
    // target has to extend the directory by one cluster.
    let image = scene(4096, 1, |fs| {
        let root = fs.root();
        let a = fs.create(&root, "A", NodeKind::Directory).unwrap();
        let full = fs.create(&root, "FULL", NodeKind::Directory).unwrap();
        for i in 0..14 {
            fs.create(&full, &std::format!("F{i:02}"), NodeKind::File)
                .unwrap();
        }
        let mut old = fs.create(&a, "OLD.TXT", NodeKind::File).unwrap();
        fs.write(&mut old, 0, b"moved").unwrap();
    });
    let mut probe = MemDisk::from_bytes(image.clone(), SECTOR_SIZE as u32);
    let baseline = tree_state(&mut probe, &["A", "OLD.TXT"], &["FULL", "NEW.TXT"]);

    let mut rollbacks = 0;
    let mut fail_at = 1;
    loop {
        let (result, mut disk) =
            attempt_rename(&image, fail_at, &["A", "OLD.TXT"], &["FULL"], "NEW.TXT");
        let state = tree_state(&mut disk, &["A", "OLD.TXT"], &["FULL", "NEW.TXT"]);
        match result {
            Ok(()) => {
                assert!(state.new_present);
                assert_eq!(state.new_data, b"moved".to_vec());
                break;
            }
            Err(error) => {
                assert_eq!(error, Fat32Error::Block(BlockError::Io));
                assert_eq!(state, baseline, "extension rollback after write #{fail_at}");
                assert_eq!(
                    state.fat_free, baseline.fat_free,
                    "directory extension leaked a cluster after write #{fail_at}"
                );
                rollbacks += 1;
            }
        }
        fail_at += 1;
        assert!(fail_at < 40, "rename never succeeded under the fault sweep");
    }
    assert!(rollbacks >= 3, "extension rollback not exercised");
}

#[test]
fn rename_reports_no_space_without_losing_the_source() {
    // Fill every cluster, then force the target directory to grow: the rename
    // must fail with NoSpace and leave the source and the free count intact.
    let image = scene(4096, 1, |fs| {
        let root = fs.root();
        let a = fs.create(&root, "A", NodeKind::Directory).unwrap();
        let full = fs.create(&root, "FULL", NodeKind::Directory).unwrap();
        for i in 0..14 {
            fs.create(&full, &std::format!("F{i:02}"), NodeKind::File)
                .unwrap();
        }
        let mut old = fs.create(&a, "OLD.TXT", NodeKind::File).unwrap();
        fs.write(&mut old, 0, b"keep").unwrap();
        let mut big = fs.create(&a, "BIG.BIN", NodeKind::File).unwrap();
        let chunk = [0x33u8; 512];
        let mut at = 0u64;
        while fs.write(&mut big, at, &chunk).is_ok() {
            at += 512;
            assert!(at < 8 * 1024 * 1024, "disk should run out of space");
        }
    });
    let mut probe = MemDisk::from_bytes(image.clone(), SECTOR_SIZE as u32);
    let baseline = tree_state(&mut probe, &["A", "OLD.TXT"], &["FULL", "NEW.TXT"]);
    assert_eq!(baseline.free, Some(0), "fixture must leave no free cluster");

    let (result, mut disk) = attempt_rename(&image, 0, &["A", "OLD.TXT"], &["FULL"], "NEW.TXT");
    assert_eq!(result.err(), Some(Fat32Error::NoSpace));
    let state = tree_state(&mut disk, &["A", "OLD.TXT"], &["FULL", "NEW.TXT"]);
    assert_eq!(state, baseline);
}

#[test]
fn rename_reports_corrupt_when_rollback_itself_fails() {
    let image = scene(DISK_BLOCKS, 0, |fs| {
        let root = fs.root();
        let a = fs.create(&root, "A", NodeKind::Directory).unwrap();
        fs.create(&root, "B", NodeKind::Directory).unwrap();
        let mut old = fs.create(&a, "OLD.TXT", NodeKind::File).unwrap();
        fs.write(&mut old, 0, b"payload").unwrap();
    });
    // Write #1 inserts the new entry, #2 deletes the source, #3 would undo the
    // insertion: failing #2 and #3 makes the rollback itself fail.
    let mut disk = MemDisk::from_bytes(image, SECTOR_SIZE as u32);
    {
        let mut fs = Fat32::mount(FailTwoWrites::new(&mut disk, 2, 3)).unwrap();
        let mut old = walk(&mut fs, &["A", "OLD.TXT"]).unwrap();
        let b = walk(&mut fs, &["B"]).unwrap();
        assert_eq!(
            fs.rename(&mut old, &b, "NEW.TXT").err(),
            Some(Fat32Error::Corrupt),
            "failed rollback must be reported explicitly, never as success"
        );
    }
}
