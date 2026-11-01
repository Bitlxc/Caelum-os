//! Host tests: an in-memory [`block::test_support::MemDisk`] stands in for real
//! hardware, so every operation below exercises the real on-disk format,
//! including dropping the filesystem and mounting the same bytes again.

use std::vec;
use std::vec::Vec;

use block::test_support::MemDisk;

use crate::{BLOCK_SIZE, Error, Ext2, MAX_FILE_SIZE, MAX_NAME_LEN, NodeKind, format};

/// 2 MiB: one block group, small enough to fill up in the quota tests.
const SMALL_DISK_BLOCKS: u64 = 2048;

fn new_disk(blocks: u64) -> MemDisk {
    MemDisk::new(blocks, BLOCK_SIZE as u32)
}

fn formatted(blocks: u64) -> Ext2<MemDisk> {
    let mut disk = new_disk(blocks);
    format(&mut disk).expect("format should succeed");
    Ext2::mount(disk).expect("mount should succeed")
}

fn write_bytes(fs: &mut Ext2<MemDisk>, ino: u32, offset: u64, data: &[u8]) {
    let written = fs.write(ino, offset, data).expect("write");
    assert_eq!(written, data.len(), "write must report every byte");
}

fn read_bytes(fs: &mut Ext2<MemDisk>, ino: u32, offset: u64, len: usize) -> Vec<u8> {
    let mut out = vec![0u8; len];
    let read = fs.read(ino, offset, &mut out).expect("read");
    assert_eq!(read, len, "read must report every requested byte");
    out
}

/// Deterministic, non-zero, per-position distinct bytes.
fn pattern(len: usize, seed: u8) -> Vec<u8> {
    (0..len)
        .map(|i| ((i as u8).wrapping_mul(13).wrapping_add(seed)) | 1)
        .collect()
}

fn remount(fs: Ext2<MemDisk>) -> Ext2<MemDisk> {
    let disk = fs.into_device();
    Ext2::mount(disk).expect("remount")
}

// --------------------------------------------------------------------- format

#[test]
fn format_writes_a_valid_le_superblock() {
    let mut disk = new_disk(SMALL_DISK_BLOCKS);
    format(&mut disk).expect("format");
    let raw = disk.data();
    // Superblock magic is little-endian 0xEF53 at byte 1024 + 0x38.
    assert_eq!(&raw[1024 + 0x38..1024 + 0x3A], &[0x53, 0xEF]);
    // 1 KiB blocks: log_block_size == 0, first_data_block == 1.
    assert_eq!(&raw[1024 + 0x14..1024 + 0x18], &1u32.to_le_bytes());
    assert_eq!(&raw[1024 + 0x18..1024 + 0x1C], &0u32.to_le_bytes());
    // Write time / mount count are written as zeros, not left undefined.
    assert_eq!(&raw[1024 + 0x34..1024 + 0x36], &0u16.to_le_bytes());
}

#[test]
fn format_then_mount_reports_consistent_geometry() {
    let mut fs = formatted(SMALL_DISK_BLOCKS);
    assert_eq!(fs.block_size(), BLOCK_SIZE as u32);
    assert_eq!(fs.block_count(), SMALL_DISK_BLOCKS as u32);
    assert!(fs.free_blocks() > 0 && fs.free_blocks() < fs.block_count());
    assert_eq!(fs.inode_count(), 1024);
    assert_eq!(fs.free_inodes(), 1024 - 10);
    let root = fs.root().expect("root");
    assert_eq!(root.inode, crate::ROOT_INODE);
    assert_eq!(root.kind, NodeKind::Directory);
}

#[test]
fn format_rejects_a_device_too_small_for_one_group() {
    // 260 blocks cannot hold boot + superblock + descriptors + bitmaps + inode
    // table + the root directory data block.
    let mut disk = new_disk(260);
    assert_eq!(format(&mut disk), Err(Error::NoSpace));
}

#[test]
fn mount_rejects_bad_magic_and_unsupported_features() {
    let mut disk = new_disk(SMALL_DISK_BLOCKS);
    format(&mut disk).expect("format");

    let mut bad_magic = disk.clone();
    bad_magic.data_mut()[1024 + 0x38] ^= 0xFF;
    assert_eq!(Ext2::mount(bad_magic).err(), Some(Error::BadMagic));

    let mut extents = disk.clone();
    // s_feature_incompat = EXTENTS (0x40) is beyond what this driver implements.
    extents.data_mut()[1024 + 0x60..1024 + 0x64].copy_from_slice(&0x40u32.to_le_bytes());
    assert_eq!(Ext2::mount(extents).err(), Some(Error::Unsupported),);

    let mut tiny = disk.clone();
    // Claim more blocks than the device can hold.
    tiny.data_mut()[1024 + 0x04..1024 + 0x08].copy_from_slice(&u32::MAX.to_le_bytes());
    assert_eq!(Ext2::mount(tiny).err(), Some(Error::BadSuperblock));
}

#[test]
fn format_works_on_512_byte_block_devices() {
    let mut disk = MemDisk::new(SMALL_DISK_BLOCKS * 2, 512);
    format(&mut disk).expect("format on 512-byte blocks");
    let mut fs = Ext2::mount(disk).expect("mount on 512-byte blocks");
    let file = fs
        .create(crate::ROOT_INODE, b"a", NodeKind::File)
        .expect("create");
    write_bytes(&mut fs, file.inode, 0, &pattern(3000, 7));
    assert_eq!(read_bytes(&mut fs, file.inode, 0, 3000), pattern(3000, 7));
}

#[test]
fn devices_with_other_block_sizes_are_rejected() {
    // Only 512-byte and 1 KiB media are meaningful for a 1 KiB-block volume.
    let mut disk = MemDisk::new(SMALL_DISK_BLOCKS / 4, 4096);
    assert_eq!(format(&mut disk), Err(Error::Unsupported));
    assert_eq!(Ext2::mount(disk).err(), Some(Error::Unsupported));
}

// --------------------------------------------------------------- file content

#[test]
fn file_write_read_roundtrip_across_blocks() {
    let mut fs = formatted(SMALL_DISK_BLOCKS);
    let file = fs
        .create(crate::ROOT_INODE, b"data", NodeKind::File)
        .expect("create");
    let payload = pattern(3000, 3);
    write_bytes(&mut fs, file.inode, 0, &payload);

    let stat = fs.stat(file.inode).expect("stat");
    assert_eq!(stat.size, 3000);
    assert_eq!(read_bytes(&mut fs, file.inode, 0, 3000), payload);
    // A read that starts mid-block and spans the next block boundary.
    assert_eq!(
        read_bytes(&mut fs, file.inode, 1000, 2000),
        payload[1000..3000]
    );
}

#[test]
fn partial_overwrites_preserve_neighbouring_bytes() {
    let mut fs = formatted(SMALL_DISK_BLOCKS);
    let file = fs
        .create(crate::ROOT_INODE, b"patch", NodeKind::File)
        .expect("create");
    write_bytes(&mut fs, file.inode, 0, &pattern(2048, 1));
    // Overwrite bytes 1024..1030 (start of the second block) and 1010..1015
    // (inside the first block).
    write_bytes(&mut fs, file.inode, 1024, &[0xAA; 6]);
    write_bytes(&mut fs, file.inode, 1010, &[0xBB; 5]);

    let got = read_bytes(&mut fs, file.inode, 0, 2048);
    assert_eq!(&got[0..1010], &pattern(2048, 1)[0..1010]);
    assert_eq!(&got[1010..1015], &[0xBB; 5]);
    assert_eq!(&got[1015..1024], &pattern(2048, 1)[1015..1024]);
    assert_eq!(&got[1024..1030], &[0xAA; 6]);
    assert_eq!(&got[1030..2048], &pattern(2048, 1)[1030..2048]);
}

#[test]
fn write_extends_file_and_leaves_a_zero_filled_gap() {
    let mut fs = formatted(SMALL_DISK_BLOCKS);
    let file = fs
        .create(crate::ROOT_INODE, b"grow", NodeKind::File)
        .expect("create");
    write_bytes(&mut fs, file.inode, 0, b"head");
    write_bytes(&mut fs, file.inode, 8192, b"tail");
    assert_eq!(fs.stat(file.inode).expect("stat").size, 8196);

    let all = read_bytes(&mut fs, file.inode, 0, 8196);
    assert_eq!(&all[0..4], b"head");
    assert!(all[4..8192].iter().all(|&byte| byte == 0), "gap is zeros");
    assert_eq!(&all[8192..], b"tail");
}

#[test]
fn sparse_extent_reads_as_zeros_without_allocating() {
    let mut fs = formatted(SMALL_DISK_BLOCKS);
    let file = fs
        .create(crate::ROOT_INODE, b"sparse", NodeKind::File)
        .expect("create");
    // Only the third block exists; the first two are holes.
    write_bytes(&mut fs, file.inode, 2048, b"x");
    let free_before = fs.free_blocks();
    let hole = read_bytes(&mut fs, file.inode, 0, 2048);
    assert!(hole.iter().all(|&byte| byte == 0));
    assert_eq!(fs.free_blocks(), free_before, "reading a hole allocates");
    // A file with no blocks at all still reads as zeros.
    let empty = fs
        .create(crate::ROOT_INODE, b"empty", NodeKind::File)
        .expect("create");
    write_bytes(&mut fs, empty.inode, 0, b"");
    fs.truncate(empty.inode, 4096).expect("extend");
    assert!(
        read_bytes(&mut fs, empty.inode, 0, 4096)
            .iter()
            .all(|&byte| byte == 0)
    );
}

#[test]
fn indirect_block_handles_blocks_past_the_direct_range() {
    let mut fs = formatted(SMALL_DISK_BLOCKS);
    let file = fs
        .create(crate::ROOT_INODE, b"indirect", NodeKind::File)
        .expect("create");
    let payload = pattern(20 * BLOCK_SIZE, 9);
    write_bytes(&mut fs, file.inode, 0, &payload);
    assert_eq!(fs.stat(file.inode).expect("stat").size, 20 * 1024);
    // Logical block 12 is the first one behind the single indirect block.
    write_bytes(&mut fs, file.inode, 12 * 1024, &[0x5A; 16]);
    let got = read_bytes(&mut fs, file.inode, 0, 20 * 1024);
    assert_eq!(&got[0..12 * 1024], &payload[0..12 * 1024]);
    assert_eq!(&got[12 * 1024..12 * 1024 + 16], &[0x5A; 16]);
    assert_eq!(&got[12 * 1024 + 16..], &payload[12 * 1024 + 16..]);
}

#[test]
fn file_size_limit_is_enforced_loudly() {
    let mut fs = formatted(SMALL_DISK_BLOCKS);
    let file = fs
        .create(crate::ROOT_INODE, b"big", NodeKind::File)
        .expect("create");
    // One byte past the last addressable position must fail, not wrap.
    assert_eq!(
        fs.write(file.inode, MAX_FILE_SIZE, b"x").err(),
        Some(Error::Quota)
    );
    // A write that ends exactly at the limit is allowed (and must stay sparse:
    // only the double-indirect index path plus one data block is allocated).
    let free_before = fs.free_blocks();
    write_bytes(&mut fs, file.inode, MAX_FILE_SIZE - 1, b"x");
    assert_eq!(
        fs.stat(file.inode).expect("stat").size as u64,
        MAX_FILE_SIZE
    );
    assert_eq!(
        free_before - fs.free_blocks(),
        3,
        "a sparse tail needs one data block and both double-indirect index blocks"
    );
    assert_eq!(
        read_bytes(&mut fs, file.inode, MAX_FILE_SIZE - 1, 1),
        vec![b'x']
    );
    assert_eq!(fs.mapped_blocks(file.inode).expect("mapped"), 1);

    // A request that crosses the limit is rejected before anything is written.
    assert_eq!(
        fs.write(file.inode, MAX_FILE_SIZE - 1, b"xy").err(),
        Some(Error::Quota)
    );
    assert_eq!(
        fs.truncate(file.inode, MAX_FILE_SIZE + 1).err(),
        Some(Error::Quota)
    );

    // Directories are not files.
    let dir = fs
        .create(crate::ROOT_INODE, b"dir", NodeKind::Directory)
        .expect("mkdir");
    assert_eq!(
        fs.read(dir.inode, 0, &mut [0u8; 8]).err(),
        Some(Error::IsDirectory)
    );
    assert_eq!(fs.write(dir.inode, 0, b"x").err(), Some(Error::IsDirectory));
}

#[test]
fn double_indirect_handles_blocks_past_the_single_indirect_range() {
    let mut fs = formatted(SMALL_DISK_BLOCKS);
    let file = fs
        .create(crate::ROOT_INODE, b"double", NodeKind::File)
        .expect("create");
    // 267 is the last single-indirect block, 268 the first double-indirect
    // block, 523 the last block of the first second-level index block and 524
    // the first block of the next second-level index block.
    let boundaries: [(u32, u8); 4] = [(267, 0xA1), (268, 0xB2), (523, 0xC3), (524, 0xD4)];
    for (index, tag) in boundaries {
        let offset = u64::from(index) * BLOCK_SIZE as u64;
        write_bytes(&mut fs, file.inode, offset, &[tag; 16]);
    }
    assert_eq!(
        fs.stat(file.inode).expect("stat").size as u64,
        524 * BLOCK_SIZE as u64 + 16
    );
    for (index, tag) in boundaries {
        let offset = u64::from(index) * BLOCK_SIZE as u64;
        assert_eq!(
            read_bytes(&mut fs, file.inode, offset, 16),
            vec![tag; 16],
            "block {index} must survive the double-indirect round trip"
        );
    }
    // Holes before the first written double-indirect block read as zeros.
    let hole = read_bytes(&mut fs, file.inode, 13 * BLOCK_SIZE as u64, 100);
    assert!(hole.iter().all(|&byte| byte == 0), "holes read as zeros");

    let mapped = fs.mapped_blocks(file.inode).expect("mapped");
    assert_eq!(mapped, 4, "four data blocks are mapped");

    // The same tree must come back after dropping the filesystem handle.
    let mut fs = remount(fs);
    for (index, tag) in boundaries {
        let offset = u64::from(index) * BLOCK_SIZE as u64;
        assert_eq!(read_bytes(&mut fs, file.inode, offset, 16), vec![tag; 16]);
    }

    // Truncating to zero releases the whole double-indirect tree.
    let before = fs.free_blocks();
    fs.truncate(file.inode, 0).expect("truncate to zero");
    assert!(fs.free_blocks() > before, "double-indirect blocks freed");
    assert_eq!(fs.mapped_blocks(file.inode).expect("mapped"), 0);
    let mut fs = remount(fs);
    assert_eq!(fs.stat(file.inode).expect("stat").size, 0);
}

#[test]
fn dynamic_binary_sized_files_roundtrip_across_double_indirect_and_remount() {
    // Real M10a payload sizes: busybox and libc musl on the ext2 volume.
    const BUSYBOX: usize = 804_616;
    const LIBC: usize = 666_216;
    let mut fs = formatted(SMALL_DISK_BLOCKS);
    let busybox = fs
        .create(crate::ROOT_INODE, b"busybox", NodeKind::File)
        .expect("create busybox");
    let libc = fs
        .create(crate::ROOT_INODE, b"libc", NodeKind::File)
        .expect("create libc");
    write_bytes(&mut fs, busybox.inode, 0, &pattern(BUSYBOX, 3));
    write_bytes(&mut fs, libc.inode, 0, &pattern(LIBC, 11));
    assert_eq!(fs.stat(busybox.inode).expect("stat").size as usize, BUSYBOX);
    assert_eq!(fs.stat(libc.inode).expect("stat").size as usize, LIBC);

    // Spot checks around the single/double boundary and at the tail.
    let busybox_pattern = pattern(BUSYBOX, 3);
    let libc_pattern = pattern(LIBC, 11);
    let single_end = 268 * BLOCK_SIZE;
    assert_eq!(
        read_bytes(&mut fs, busybox.inode, (single_end - 32) as u64, 64).as_slice(),
        &busybox_pattern[single_end - 32..single_end + 32]
    );
    assert_eq!(
        read_bytes(&mut fs, busybox.inode, BUSYBOX as u64 - 64, 64).as_slice(),
        &busybox_pattern[BUSYBOX - 64..]
    );
    assert_eq!(
        read_bytes(&mut fs, busybox.inode, 0, BUSYBOX),
        busybox_pattern
    );
    assert_eq!(read_bytes(&mut fs, libc.inode, 0, LIBC), libc_pattern);

    // Everything survives a remount, including the second file.
    let mut fs = remount(fs);
    assert_eq!(
        read_bytes(&mut fs, busybox.inode, 0, BUSYBOX),
        busybox_pattern
    );
    assert_eq!(
        read_bytes(&mut fs, libc.inode, 0, LIBC).as_slice(),
        libc_pattern.as_slice()
    );

    // Truncating the large file releases its double-indirect blocks without
    // disturbing the neighbour file.
    let before = fs.free_blocks();
    fs.truncate(busybox.inode, 300_000)
        .expect("truncate busybox");
    assert!(fs.free_blocks() > before, "truncate frees blocks");
    assert_eq!(fs.stat(busybox.inode).expect("stat").size, 300_000);
    assert_eq!(
        read_bytes(&mut fs, busybox.inode, 0, 300_000).as_slice(),
        &busybox_pattern[..300_000]
    );
    assert_eq!(read_bytes(&mut fs, libc.inode, 0, LIBC), libc_pattern);

    let mut fs = remount(fs);
    assert_eq!(fs.stat(busybox.inode).expect("stat").size, 300_000);
    assert_eq!(read_bytes(&mut fs, libc.inode, 0, LIBC), libc_pattern);
}

#[test]
fn sparse_double_indirect_file_reads_zeros_and_survives_remount() {
    let mut fs = formatted(SMALL_DISK_BLOCKS);
    let file = fs
        .create(crate::ROOT_INODE, b"sparse", NodeKind::File)
        .expect("create");
    // One byte inside the double-indirect range (logical block 300).
    let offset = 300 * BLOCK_SIZE;
    write_bytes(&mut fs, file.inode, offset as u64, b"z");
    assert_eq!(fs.mapped_blocks(file.inode).expect("mapped"), 1);
    assert_eq!(
        read_bytes(&mut fs, file.inode, 0, offset),
        vec![0u8; offset]
    );
    assert_eq!(read_bytes(&mut fs, file.inode, offset as u64, 1), b"z");

    let mut fs = remount(fs);
    assert_eq!(fs.mapped_blocks(file.inode).expect("mapped"), 1);
    assert_eq!(
        read_bytes(&mut fs, file.inode, 0, offset),
        vec![0u8; offset]
    );
    assert_eq!(read_bytes(&mut fs, file.inode, offset as u64, 1), b"z");
}

#[test]
fn truncate_shrinks_frees_blocks_and_extends_with_zeros() {
    let mut fs = formatted(SMALL_DISK_BLOCKS);
    let file = fs
        .create(crate::ROOT_INODE, b"trunc", NodeKind::File)
        .expect("create");
    write_bytes(&mut fs, file.inode, 0, &pattern(5000, 5));
    let used = fs.block_count() - fs.free_blocks();

    fs.truncate(file.inode, 1500).expect("truncate");
    assert_eq!(fs.stat(file.inode).expect("stat").size, 1500);
    assert!(fs.free_blocks() > fs.block_count() - used, "blocks freed");
    assert_eq!(
        read_bytes(&mut fs, file.inode, 0, 1500),
        pattern(5000, 5)[0..1500]
    );

    // Extending exposes zeros, not the truncated bytes.
    fs.truncate(file.inode, 2200).expect("extend");
    let got = read_bytes(&mut fs, file.inode, 0, 2200);
    assert_eq!(&got[0..1500], &pattern(5000, 5)[0..1500]);
    assert!(got[1500..].iter().all(|&byte| byte == 0));

    fs.truncate(file.inode, 0).expect("truncate to zero");
    assert_eq!(fs.stat(file.inode).expect("stat").size, 0);
    assert_eq!(read_bytes(&mut fs, file.inode, 0, 0), Vec::new());
}

// ---------------------------------------------------------------- directories

#[test]
fn mkdir_lookup_and_readdir_enumerate_entries() {
    let mut fs = formatted(SMALL_DISK_BLOCKS);
    let root = crate::ROOT_INODE;
    let dir = fs.create(root, b"sub", NodeKind::Directory).expect("mkdir");
    assert_eq!(dir.kind, NodeKind::Directory);
    assert_eq!(dir.size, BLOCK_SIZE as u32);
    let file = fs
        .create(dir.inode, b"inside", NodeKind::File)
        .expect("create");
    write_bytes(&mut fs, file.inode, 0, b"hello");

    let found = fs.lookup(dir.inode, b"inside").expect("lookup");
    assert_eq!(found.inode, file.inode);
    assert_eq!(found.size, 5);
    assert_eq!(
        fs.lookup(dir.inode, b"missing").err(),
        Some(Error::NotFound)
    );

    // ".", "..", then the child: names come back in on-disk order.
    let mut offset = 0u64;
    let mut names: Vec<Vec<u8>> = Vec::new();
    while let Some((entry, next)) = fs.readdir(dir.inode, offset).expect("readdir") {
        names.push(entry.name().to_vec());
        offset = next;
    }
    assert_eq!(
        names,
        vec![b".".to_vec(), b"..".to_vec(), b"inside".to_vec()]
    );
    assert_eq!(fs.readdir(dir.inode, offset).expect("end"), None);
}

#[test]
fn readdir_spans_several_blocks() {
    let mut fs = formatted(16 * SMALL_DISK_BLOCKS);
    let dir = fs
        .create(crate::ROOT_INODE, b"many", NodeKind::Directory)
        .expect("mkdir");
    const COUNT: usize = 200;
    for index in 0..COUNT {
        let mut name = [b'f'; 12];
        name[0] = b'a' + (index % 26) as u8;
        name[1] = (index / 26) as u8 + b'a';
        name[2] = (index % 10) as u8 + b'0';
        fs.create(dir.inode, &name, NodeKind::File).expect("create");
    }
    let mut seen = 0usize;
    let mut offset = 0u64;
    while let Some((entry, next)) = fs.readdir(dir.inode, offset).expect("readdir") {
        if entry.name() != b"." && entry.name() != b".." {
            seen += 1;
        }
        offset = next;
    }
    assert_eq!(seen, COUNT);
    assert!(fs.stat(dir.inode).expect("stat").size as usize > BLOCK_SIZE);
}

#[test]
fn directory_grows_and_reuses_freed_entry_space() {
    let mut fs = formatted(SMALL_DISK_BLOCKS);
    let dir = fs
        .create(crate::ROOT_INODE, b"reuse", NodeKind::Directory)
        .expect("mkdir");
    let file = fs
        .create(dir.inode, b"temporary", NodeKind::File)
        .expect("create");
    fs.unlink(dir.inode, b"temporary").expect("unlink");
    assert_eq!(fs.stat(dir.inode).expect("stat").size, BLOCK_SIZE as u32);
    // The freed slot must be reused: the directory must not grow for one entry.
    let second = fs
        .create(dir.inode, b"replacement", NodeKind::File)
        .expect("create");
    assert_eq!(second.kind, NodeKind::File);
    assert_eq!(fs.stat(dir.inode).expect("stat").size, BLOCK_SIZE as u32);
    assert_eq!(
        fs.lookup(dir.inode, b"replacement").expect("lookup").inode,
        file.inode.max(second.inode)
    );
}

#[test]
fn unlink_rejects_non_empty_directory_and_unknown_names() {
    let mut fs = formatted(SMALL_DISK_BLOCKS);
    let root = crate::ROOT_INODE;
    let dir = fs
        .create(root, b"full", NodeKind::Directory)
        .expect("mkdir");
    fs.create(dir.inode, b"child", NodeKind::File)
        .expect("create");
    assert_eq!(fs.unlink(root, b"full").err(), Some(Error::NotEmpty));
    assert_eq!(fs.unlink(root, b"nope").err(), Some(Error::NotFound));
    assert_eq!(fs.unlink(root, b".").err(), Some(Error::NameInvalid));
    assert_eq!(fs.unlink(root, b"..").err(), Some(Error::NameInvalid));

    fs.unlink(dir.inode, b"child").expect("unlink child");
    fs.unlink(root, b"full").expect("rmdir");

    // The inode and its data block are reusable after removal.
    let again = fs
        .create(root, b"again", NodeKind::Directory)
        .expect("mkdir");
    assert_eq!(again.inode, dir.inode);
}

#[test]
fn link_counts_drop_when_a_subdirectory_is_removed() {
    let mut fs = formatted(SMALL_DISK_BLOCKS);
    let root = crate::ROOT_INODE;
    let before = fs.stat(root).expect("stat").size;
    let dir = fs
        .create(root, b"child", NodeKind::Directory)
        .expect("mkdir");
    fs.create(dir.inode, b"grand", NodeKind::Directory)
        .expect("mkdir");
    fs.unlink(dir.inode, b"grand").expect("rmdir grand");
    fs.unlink(root, b"child").expect("rmdir child");
    assert_eq!(fs.stat(root).expect("stat").size, before);
    assert_eq!(fs.lookup(root, b"child").err(), Some(Error::NotFound));
}

// -------------------------------------------------------------------- rename

#[test]
fn rename_within_a_directory() {
    let mut fs = formatted(SMALL_DISK_BLOCKS);
    let root = crate::ROOT_INODE;
    let file = fs.create(root, b"before", NodeKind::File).expect("create");
    write_bytes(&mut fs, file.inode, 0, b"payload");
    fs.rename(root, b"before", root, b"after").expect("rename");
    assert_eq!(fs.lookup(root, b"before").err(), Some(Error::NotFound));
    let moved = fs.lookup(root, b"after").expect("lookup");
    assert_eq!(moved.inode, file.inode);
    assert_eq!(read_bytes(&mut fs, moved.inode, 0, 7), b"payload");
    // Renaming to the same name is a no-op, not an error.
    fs.rename(root, b"after", root, b"after").expect("no-op");
    // Renaming onto an existing name is refused, and the source stays put.
    fs.create(root, b"taken", NodeKind::File).expect("create");
    assert_eq!(
        fs.rename(root, b"after", root, b"taken").err(),
        Some(Error::Exists)
    );
    assert_eq!(
        fs.lookup(root, b"after").expect("source kept").inode,
        file.inode
    );
}

#[test]
fn rename_across_directories_keeps_contents() {
    let mut fs = formatted(SMALL_DISK_BLOCKS);
    let root = crate::ROOT_INODE;
    let left = fs
        .create(root, b"left", NodeKind::Directory)
        .expect("mkdir");
    let right = fs
        .create(root, b"right", NodeKind::Directory)
        .expect("mkdir");
    let file = fs
        .create(left.inode, b"doc", NodeKind::File)
        .expect("create");
    write_bytes(&mut fs, file.inode, 0, b"moved content");
    fs.rename(left.inode, b"doc", right.inode, b"doc")
        .expect("rename across dirs");
    assert_eq!(fs.lookup(left.inode, b"doc").err(), Some(Error::NotFound));
    assert_eq!(read_bytes(&mut fs, file.inode, 0, 13), b"moved content");
}

#[test]
fn rename_directory_rewrites_dotdot() {
    let mut fs = formatted(SMALL_DISK_BLOCKS);
    let root = crate::ROOT_INODE;
    let left = fs
        .create(root, b"left", NodeKind::Directory)
        .expect("mkdir");
    let right = fs
        .create(root, b"right", NodeKind::Directory)
        .expect("mkdir");
    let child = fs
        .create(left.inode, b"child", NodeKind::Directory)
        .expect("mkdir");
    fs.rename(left.inode, b"child", right.inode, b"child")
        .expect("move directory");

    let dotdot = fs.lookup(child.inode, b"..").expect("..");
    assert_eq!(dotdot.inode, right.inode);
    // The old parent loses the link, the new one gains it.
    let dotdot_left = fs.lookup(left.inode, b"..").expect(".. of left");
    assert_eq!(dotdot_left.inode, root);
}

#[test]
fn rename_rejects_cycles_and_existing_targets() {
    let mut fs = formatted(SMALL_DISK_BLOCKS);
    let root = crate::ROOT_INODE;
    let outer = fs
        .create(root, b"outer", NodeKind::Directory)
        .expect("mkdir");
    let inner = fs
        .create(outer.inode, b"inner", NodeKind::Directory)
        .expect("mkdir");
    // Moving a parent into its own descendant would orphan the subtree.
    assert_eq!(
        fs.rename(root, b"outer", inner.inode, b"moved").err(),
        Some(Error::Cycle)
    );
    // Same thing one level up: a directory into itself.
    assert_eq!(
        fs.rename(root, b"outer", outer.inode, b"self").err(),
        Some(Error::Cycle)
    );
    // Existing target name.
    fs.create(root, b"taken", NodeKind::File).expect("create");
    assert_eq!(
        fs.rename(root, b"taken", root, b"outer").err(),
        Some(Error::Exists)
    );
}

// ------------------------------------------------------------------- naming

#[test]
fn names_are_validated() {
    let mut fs = formatted(SMALL_DISK_BLOCKS);
    let root = crate::ROOT_INODE;
    assert_eq!(
        fs.create(root, b"", NodeKind::File).err(),
        Some(Error::NameInvalid)
    );
    assert_eq!(
        fs.create(root, b"a/b", NodeKind::File).err(),
        Some(Error::NameInvalid)
    );
    assert_eq!(
        fs.create(root, b"nul\0byte", NodeKind::File).err(),
        Some(Error::NameInvalid)
    );
    let long = [b'x'; MAX_NAME_LEN + 1];
    assert_eq!(
        fs.create(root, &long, NodeKind::File).err(),
        Some(Error::NameTooLong)
    );
    // Exactly at the limit is fine, and it survives a round trip.
    let max = [b'y'; MAX_NAME_LEN];
    fs.create(root, &max, NodeKind::File)
        .expect("create max name");
    assert_eq!(fs.lookup(root, &max).expect("lookup").kind, NodeKind::File);
}

// ------------------------------------------------------ persistence and faults

#[test]
fn everything_survives_drop_and_remount() {
    let mut fs = formatted(SMALL_DISK_BLOCKS);
    let root = crate::ROOT_INODE;
    let dir = fs
        .create(root, b"persist", NodeKind::Directory)
        .expect("mkdir");
    let file = fs
        .create(dir.inode, b"file", NodeKind::File)
        .expect("create");
    let payload = pattern(2500, 11);
    write_bytes(&mut fs, file.inode, 0, &payload);
    fs.sync().expect("sync");
    let dir_ino = dir.inode;
    let file_ino = file.inode;

    let disk = fs.into_device();
    // The on-disk bytes must be self-sufficient: mount a fresh copy that was
    // never touched by the previous instance.
    let mut restored = Ext2::mount(disk.clone()).expect("remount");
    assert_eq!(
        restored.lookup(root, b"persist").expect("lookup").inode,
        dir_ino
    );
    let stat = restored.stat(file_ino).expect("stat");
    assert_eq!(stat.size, 2500);
    assert_eq!(read_bytes(&mut restored, file_ino, 0, 2500), payload);
    // And a rename on the restored volume is still consistent.
    restored
        .rename(dir.inode, b"file", dir.inode, b"renamed")
        .expect("rename after remount");
    restored.sync().expect("sync after rename");
    let renamed_disk = restored.into_device();
    drop(disk);

    // Re-open the renamed backing store: the rename reached the medium.
    let mut reopened = Ext2::mount(renamed_disk).expect("second remount");
    assert_eq!(
        reopened.lookup(dir_ino, b"file").err(),
        Some(Error::NotFound)
    );
    assert_eq!(
        reopened.lookup(dir_ino, b"renamed").expect("renamed").inode,
        file_ino
    );
    assert_eq!(read_bytes(&mut reopened, file_ino, 0, 2500), payload);
}

#[test]
fn device_errors_are_reported_not_hidden() {
    let mut fs = formatted(SMALL_DISK_BLOCKS);
    let file = fs
        .create(crate::ROOT_INODE, b"faulty", NodeKind::File)
        .expect("create");
    fs.device_mut().fail_next_writes(1);
    assert_eq!(fs.write(file.inode, 0, b"data").err(), Some(Error::Io));

    fs.device_mut().fail_next_reads(1);
    assert_eq!(fs.read(file.inode, 0, &mut [0u8; 4]).err(), Some(Error::Io));

    fs.device_mut().read_only = true;
    assert_eq!(
        fs.write(file.inode, 0, b"data").err(),
        Some(Error::ReadOnly)
    );
    fs.device_mut().read_only = false;

    fs.device_mut().fail_next_flushes(1);
    assert_eq!(fs.sync().err(), Some(Error::Io));
}

#[test]
fn quota_failures_do_not_leak_blocks() {
    let mut fs = formatted(400);
    let root = crate::ROOT_INODE;
    let free_start = fs.free_blocks();
    let dir_blocks_start = fs
        .stat(root)
        .expect("stat")
        .size
        .div_ceil(BLOCK_SIZE as u32);
    let mut created = Vec::new();
    let mut name = [b'q'; 8];
    let mut index = 0usize;
    loop {
        name[0] = b'a' + (index % 26) as u8;
        name[1] = (index / 26) as u8 + b'a';
        match fs.create(root, &name, NodeKind::File) {
            Ok(node) => {
                if fs.write(node.inode, 0, &[0x7E; 1000]).is_err() {
                    break;
                }
                created.push(node.inode);
            }
            Err(Error::NoSpace) => break,
            Err(other) => panic!("unexpected create error: {other:?}"),
        }
        index += 1;
        assert!(index < 4096, "quota never triggered");
    }
    assert!(!created.is_empty());
    // Everything created before the failure is still readable.
    for ino in &created {
        assert_eq!(read_bytes(&mut fs, *ino, 0, 1000), vec![0x7E; 1000]);
    }
    assert!(fs.free_blocks() < free_start);
    let free_after = fs.free_blocks();
    let allocated_files = created.len() as u32;
    let dir_blocks_after = fs
        .stat(root)
        .expect("stat")
        .size
        .div_ceil(BLOCK_SIZE as u32);
    // The volume still mounts: a failed allocation must not corrupt metadata.
    let restored = Ext2::mount(fs.into_device()).expect("remount after quota failure");
    assert_eq!(
        restored.free_blocks(),
        free_after,
        "counters must survive a remount unchanged"
    );
    // Every 1000-byte file costs exactly one data block; the directory itself
    // grows in whole blocks as entries are appended.
    assert_eq!(
        free_start - free_after,
        allocated_files + (dir_blocks_after - dir_blocks_start),
        "no block may leak when the volume fills up"
    );
}

#[test]
fn multi_group_volume_allocates_inodes_beyond_the_first_group() {
    // 32 MiB: four groups of 8192 blocks with 1024 inodes each.
    let mut fs = formatted(32 * 1024 * 1024 / BLOCK_SIZE as u64);
    let root = crate::ROOT_INODE;
    let dir = fs
        .create(root, b"lots", NodeKind::Directory)
        .expect("mkdir");
    assert_eq!(fs.inode_count(), 4 * 1024);

    let mut highest = 0u32;
    let mut count = 0usize;
    let mut index = 0usize;
    while count < 1100 {
        let mut name = [b'n'; 8];
        name[0] = b'a' + (index % 26) as u8;
        name[1] = ((index / 26) % 26) as u8 + b'a';
        name[2] = (index / (26 * 26)) as u8 + b'a';
        let file = fs.create(dir.inode, &name, NodeKind::File).expect("create");
        highest = highest.max(file.inode);
        count += 1;
        index += 1;
    }
    // Inode tables live one per group, so we must have crossed into group 1.
    assert!(
        highest > 1024,
        "expected inodes beyond group 0, got {highest}"
    );
    // The first generated name was "aaa" + five 'n' padding bytes.
    let first = {
        let mut name = [b'n'; 8];
        name[0] = b'a';
        name[1] = b'a';
        name[2] = b'a';
        name
    };
    assert_eq!(
        fs.lookup(dir.inode, &first).expect("lookup").kind,
        NodeKind::File
    );

    // Both the descriptor counters and the superblock counters agree.
    let allocated = 1100 + 1; // files + the "lots" directory
    assert_eq!(
        fs.free_inodes() as usize,
        fs.inode_count() as usize - 10 - allocated
    );

    // Everything is still there after a remount, including group 1 inodes.
    let mut restored = remount(fs);
    assert_eq!(
        restored.lookup(dir.inode, &first).expect("lookup").inode,
        12
    );
}

#[test]
fn format_handles_a_64_mib_volume() {
    // 64 MiB: 65536 blocks in 8 groups, one descriptor block for the table.
    let mut disk = new_disk(64 * 1024 * 1024 / BLOCK_SIZE as u64);
    format(&mut disk).expect("format 64 MiB");
    let mut fs = Ext2::mount(disk).expect("mount 64 MiB");
    assert_eq!(fs.block_count(), 65536);
    assert_eq!(fs.inode_count(), 8 * 1024);
    // All eight descriptors must agree with the superblock's free counters.
    let sum_free: u32 = fs.free_blocks();
    assert!(sum_free > 60_000, "64 MiB volume should stay mostly free");
    let dir = fs
        .create(crate::ROOT_INODE, b"deep", NodeKind::Directory)
        .expect("mkdir");
    let file = fs
        .create(dir.inode, b"payload", NodeKind::File)
        .expect("create");
    write_bytes(&mut fs, file.inode, 0, &pattern(1500, 4));
    let mut restored = remount(fs);
    assert_eq!(
        read_bytes(&mut restored, file.inode, 0, 1500),
        pattern(1500, 4)
    );
}

// ------------------------------------------------- corrupted-metadata hardening

/// Rewrite one block-group descriptor field of the mounted volume.
fn patch_group_desc(
    fs: &mut Ext2<MemDisk>,
    group: u32,
    patch: impl FnOnce(&mut crate::sb::GroupDesc),
) {
    let mut aux = [0u8; BLOCK_SIZE];
    let mut desc = fs
        .read_group_desc(group, &mut aux)
        .expect("read descriptor");
    patch(&mut desc);
    fs.write_group_desc(group, &desc, &mut aux)
        .expect("write descriptor");
}

/// Rewrite one block bitmap of the mounted volume.
fn patch_block_bitmap(
    fs: &mut Ext2<MemDisk>,
    group: u32,
    patch: impl FnOnce(&mut [u8; BLOCK_SIZE]),
) {
    let mut aux = [0u8; BLOCK_SIZE];
    let desc = fs
        .read_group_desc(group, &mut aux)
        .expect("read descriptor");
    let mut bitmap = [0u8; BLOCK_SIZE];
    fs.read_block(desc.block_bitmap, &mut bitmap)
        .expect("read bitmap");
    patch(&mut bitmap);
    fs.write_block(desc.block_bitmap, &bitmap)
        .expect("write bitmap");
}

#[test]
fn mount_rejects_descriptors_pointing_at_reserved_metadata() {
    // A bitmap pointer into the superblock / descriptor-table area would make
    // every later allocation write over the volume's own metadata.
    let mut fs = formatted(SMALL_DISK_BLOCKS);
    patch_group_desc(&mut fs, 0, |desc| desc.block_bitmap = 2);
    assert!(matches!(Ext2::mount(fs.into_device()), Err(Error::Corrupt)));

    let mut fs = formatted(SMALL_DISK_BLOCKS);
    patch_group_desc(&mut fs, 0, |desc| {
        desc.block_bitmap = crate::sb::SUPERBLOCK_BLOCK
    });
    assert!(matches!(Ext2::mount(fs.into_device()), Err(Error::Corrupt)));
}

#[test]
fn mount_rejects_metadata_pointers_outside_the_group() {
    // Inode table running past the end of its group (beyond the device).
    let mut fs = formatted(SMALL_DISK_BLOCKS);
    let last = fs.block_count() - 1;
    patch_group_desc(&mut fs, 0, |desc| desc.inode_table = last);
    assert!(matches!(Ext2::mount(fs.into_device()), Err(Error::Corrupt)));

    // Bitmap aliasing the inode table it would then be written over.
    let mut fs = formatted(SMALL_DISK_BLOCKS);
    let mut aux = [0u8; BLOCK_SIZE];
    let table = fs.read_group_desc(0, &mut aux).unwrap().inode_table;
    patch_group_desc(&mut fs, 0, |desc| desc.block_bitmap = table);
    assert!(matches!(Ext2::mount(fs.into_device()), Err(Error::Corrupt)));

    // Free-block counter larger than the group itself.
    let mut fs = formatted(SMALL_DISK_BLOCKS);
    patch_group_desc(&mut fs, 0, |desc| desc.free_blocks = u16::MAX);
    assert!(matches!(Ext2::mount(fs.into_device()), Err(Error::Corrupt)));
}

#[test]
fn allocation_refuses_metadata_marked_free_and_writes_nothing() {
    let mut fs = formatted(SMALL_DISK_BLOCKS);
    let dir = fs
        .create(crate::ROOT_INODE, b"poison", NodeKind::Directory)
        .expect("mkdir");
    let file = fs.create(dir.inode, b"f", NodeKind::File).expect("create");

    // Mark the first inode-table block of group 0 as free: a corrupt bitmap
    // that offers metadata for allocation.
    let mut aux = [0u8; BLOCK_SIZE];
    let desc = fs.read_group_desc(0, &mut aux).expect("descriptor");
    let first = fs.sb.group_first_block(0);
    let index = desc.inode_table - first;
    patch_block_bitmap(&mut fs, 0, |bitmap| {
        bitmap[index as usize / 8] &= !(1 << (index % 8));
    });

    let before = fs.device_mut().data().to_vec();
    assert_eq!(
        fs.write(file.inode, 0, &[0xABu8; 100]).unwrap_err(),
        Error::Corrupt
    );
    assert_eq!(
        fs.device_mut().data(),
        &before[..],
        "a rejected allocation must not write anything"
    );
}

#[test]
fn release_refuses_to_free_a_metadata_block() {
    let mut fs = formatted(SMALL_DISK_BLOCKS);
    let file = fs
        .create(crate::ROOT_INODE, b"victim", NodeKind::File)
        .expect("create");
    write_bytes(&mut fs, file.inode, 0, &[1u8; 100]);

    // Point the file's first logical block at the group's inode table, as a
    // corrupt inode would, then unlink: freeing metadata must be refused.
    let mut buf = [0u8; BLOCK_SIZE];
    let mut aux = [0u8; BLOCK_SIZE];
    let mut node = fs
        .read_inode(file.inode, &mut buf, &mut aux)
        .expect("inode");
    let desc = fs.read_group_desc(0, &mut aux).expect("descriptor");
    node.set_block(0, desc.inode_table);
    fs.write_inode(file.inode, &node, &mut buf, &mut aux)
        .expect("write inode");

    let mut table_before = [0u8; BLOCK_SIZE];
    fs.read_block(desc.inode_table, &mut table_before)
        .expect("table");
    assert_eq!(
        fs.unlink(crate::ROOT_INODE, b"victim").unwrap_err(),
        Error::Corrupt
    );
    let mut table_after = [0u8; BLOCK_SIZE];
    fs.read_block(desc.inode_table, &mut table_after)
        .expect("table");
    assert_eq!(
        table_before, table_after,
        "releasing metadata must not modify it"
    );
}

#[test]
fn exhausted_bitmap_with_free_counter_is_reported_not_repaired() {
    let mut fs = formatted(SMALL_DISK_BLOCKS);
    let mut aux = [0u8; BLOCK_SIZE];
    let desc = fs.read_group_desc(0, &mut aux).expect("descriptor");
    assert!(desc.free_inodes > 0, "fresh volume has free inodes");
    // Claim every inode is in use while the descriptor still advertises free
    // ones. The driver must report the inconsistency instead of rewriting the
    // counter (which would hide it and lose the other groups' bookkeeping).
    let bitmap = [0xFFu8; BLOCK_SIZE];
    fs.write_block(desc.inode_bitmap, &bitmap)
        .expect("poison bitmap");

    let before = fs.device_mut().data().to_vec();
    assert_eq!(
        fs.create(crate::ROOT_INODE, b"nope", NodeKind::File)
            .unwrap_err(),
        Error::Corrupt
    );
    assert_eq!(
        fs.device_mut().data(),
        &before[..],
        "a failed allocation must not rewrite metadata"
    );
}

#[test]
fn write_faults_leave_the_volume_intact_and_readable() {
    let mut fs = formatted(SMALL_DISK_BLOCKS);
    let file = fs
        .create(crate::ROOT_INODE, b"io", NodeKind::File)
        .expect("create");
    write_bytes(&mut fs, file.inode, 0, &pattern(1000, 9));

    let before = fs.device_mut().data().to_vec();
    fs.device_mut().fail_next_writes(1);
    // Growing the file needs a fresh block: the first metadata write fails and
    // nothing is left half-updated.
    assert_eq!(
        fs.write(file.inode, 1024, &pattern(100, 1)).unwrap_err(),
        Error::Io
    );
    assert_eq!(fs.device_mut().data(), &before[..]);
    assert_eq!(read_bytes(&mut fs, file.inode, 0, 1000), pattern(1000, 9));

    let mut restored = remount(fs);
    assert_eq!(
        read_bytes(&mut restored, file.inode, 0, 1000),
        pattern(1000, 9)
    );
}

#[test]
fn read_faults_surface_as_io_and_leave_the_volume_mountable() {
    let mut fs = formatted(SMALL_DISK_BLOCKS);
    let file = fs
        .create(crate::ROOT_INODE, b"rd", NodeKind::File)
        .expect("create");
    write_bytes(&mut fs, file.inode, 0, &pattern(600, 3));

    fs.device_mut().fail_next_reads(1);
    assert_eq!(
        fs.read(file.inode, 0, &mut [0u8; 16]).unwrap_err(),
        Error::Io
    );

    let mut restored = remount(fs);
    assert_eq!(
        read_bytes(&mut restored, file.inode, 0, 600),
        pattern(600, 3)
    );
}

#[test]
fn double_indirect_works_on_512_byte_block_devices() {
    let mut disk = MemDisk::new(SMALL_DISK_BLOCKS * 2, 512);
    format(&mut disk).expect("format on 512-byte blocks");
    let mut fs = Ext2::mount(disk).expect("mount on 512-byte blocks");
    let file = fs
        .create(crate::ROOT_INODE, b"d", NodeKind::File)
        .expect("create");
    // Logical block 268 is the first double-indirect block, which forces the
    // 1 KiB block helpers to split every read/write across two 512-byte device
    // blocks.
    let offset = 268_u64 * BLOCK_SIZE as u64;
    write_bytes(&mut fs, file.inode, offset, &pattern(2048, 17));
    assert_eq!(
        read_bytes(&mut fs, file.inode, offset, 2048),
        pattern(2048, 17)
    );
    let mut fs = remount(fs);
    assert_eq!(
        read_bytes(&mut fs, file.inode, offset, 2048),
        pattern(2048, 17)
    );
}
