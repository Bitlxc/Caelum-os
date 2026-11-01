//! `CAELUMFS` initramfs container writer (M4).
//!
//! The kernel receives the boot modules as one flat container stored at
//! `/INITFS.IMG` on the ESP (see `fat::INITFS_NAME`). The format is fixed and
//! deliberately small so both sides can be checked byte by byte:
//!
//! ```text
//! header (16 bytes, little endian):
//!   0..8    magic   = b"CAELUMFS"
//!   8..12   version = 1
//!   12..16  count   = number of modules
//!
//! record[i] (40 bytes, little endian), starting at offset 16:
//!   0..16   name    (NUL padded, ASCII)
//!   16..20  kind    (1 = ELF)
//!   20..24  reserved = 0
//!   24..32  offset  (absolute file offset, 16-byte aligned)
//!   32..40  size    (payload length in bytes)
//!
//! payloads: directly after the record table, each starting at a 16-byte
//! aligned offset, in record order.
//! ```
//!
//! `xtask image` is the only writer; the loader/kernel parser is the only
//! reader. Everything here is `std`-only.

/// Container magic, 8 bytes, *not* NUL terminated (the header is fixed size).
pub const MAGIC: &[u8; 8] = b"CAELUMFS";
/// Container format version.
pub const VERSION: u32 = 1;
/// Fixed header size.
pub const HEADER_LEN: usize = 16;
/// Fixed record size (16 name + 4 kind + 4 reserved + 8 offset + 8 size).
pub const RECORD_LEN: usize = 40;
/// Payload alignment.
pub const ALIGN: usize = 16;
/// Host-side file name of the packed container (`target/initramfs.img`).
pub const IMG_NAME: &str = "initramfs.img";
/// Module kind: `x86_64-unknown-none` ELF image.
pub const KIND_ELF: u32 = 1;
/// Highest module count we accept. Kept equal to the kernel-side
/// `bootinfo::MAX_BOOT_MODULES` so `xtask` can never write a container the
/// kernel would reject; M4 needs two modules and M6b2 packs three.
pub const MAX_MODULES: usize = 8;
/// Maximum module name length (`name[16]` must stay NUL terminated).
pub const MAX_NAME: usize = 15;

/// Module names the kernel looks up (matched case-sensitively). M4 shipped
/// `init`/`child`; M6b2 adds `worker`, a user-mode thread that is deliberately
/// scheduled onto an application processor; M6c adds `gfx`, the user-mode
/// display/input program; M7b adds `net`, the user-mode native socket suite;
/// M7d adds `linux`, the user-mode Linux64 personality self-test.
pub const MODULE_INIT: &str = "init";
pub const MODULE_CHILD: &str = "child";
pub const MODULE_WORKER: &str = "worker";
pub const MODULE_GFX: &str = "gfx";
pub const MODULE_NET: &str = "net";
pub const MODULE_LINUX: &str = "linux";

/// One module to pack.
pub struct Module<'a> {
    pub name: &'a str,
    pub kind: u32,
    pub data: &'a [u8],
}

/// One record read back by [`parse`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub name: String,
    pub kind: u32,
    pub offset: usize,
    pub size: usize,
}

fn align_up(n: usize) -> usize {
    (n + ALIGN - 1) & !(ALIGN - 1)
}

fn validate_name(name: &str) -> Result<(), String> {
    if name.is_empty() {
        return Err("module name must not be empty".into());
    }
    if name.len() > MAX_NAME {
        return Err(format!(
            "module name {name:?} is {} bytes, max {MAX_NAME}",
            name.len()
        ));
    }
    // Same character set as `bootinfo::module_name_ok`: short ASCII
    // identifiers, so the kernel-side parser accepts exactly what we write.
    if !name
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
    {
        return Err(format!(
            "module name {name:?} must be ASCII alphanumeric, '.', '_' or '-'"
        ));
    }
    Ok(())
}

/// Build the container image.
pub fn build(modules: &[Module]) -> Result<Vec<u8>, String> {
    if modules.is_empty() {
        return Err("initramfs needs at least one module".into());
    }
    if modules.len() > MAX_MODULES {
        return Err(format!(
            "too many modules: {} (max {MAX_MODULES})",
            modules.len()
        ));
    }
    for (i, m) in modules.iter().enumerate() {
        validate_name(m.name)?;
        if m.data.is_empty() {
            return Err(format!("module {:?} has no payload", m.name));
        }
        if let Some(prev) = modules[..i].iter().find(|p| p.name == m.name) {
            return Err(format!("duplicate module name {:?}", prev.name));
        }
        if m.data.len() > u64::MAX as usize {
            return Err(format!("module {:?} is too large", m.name));
        }
    }

    let table_end = HEADER_LEN + RECORD_LEN * modules.len();
    let mut offsets = Vec::with_capacity(modules.len());
    let mut cursor = align_up(table_end);
    for m in modules {
        offsets.push((cursor, m.data.len()));
        cursor = cursor
            .checked_add(m.data.len())
            .ok_or("initramfs size overflow")?;
        cursor = align_up(cursor);
    }
    let total = offsets
        .last()
        .map(|(off, size)| off + size)
        .ok_or("initramfs has no modules")?;

    let mut out = vec![0u8; total];
    out[0..8].copy_from_slice(MAGIC);
    out[8..12].copy_from_slice(&VERSION.to_le_bytes());
    out[12..16].copy_from_slice(&(modules.len() as u32).to_le_bytes());

    for (i, m) in modules.iter().enumerate() {
        let rec = HEADER_LEN + i * RECORD_LEN;
        let name = m.name.as_bytes();
        out[rec..rec + name.len()].copy_from_slice(name);
        // Remaining name bytes stay NUL (vec was zero-initialised).
        out[rec + 16..rec + 20].copy_from_slice(&m.kind.to_le_bytes());
        out[rec + 20..rec + 24].copy_from_slice(&0u32.to_le_bytes()); // reserved
        let (off, size) = offsets[i];
        out[rec + 24..rec + 32].copy_from_slice(&(off as u64).to_le_bytes());
        out[rec + 32..rec + 40].copy_from_slice(&(size as u64).to_le_bytes());
        out[off..off + size].copy_from_slice(m.data);
    }
    Ok(out)
}

/// Parse a container built by [`build`]. Used by `xtask image` for a
/// self-check, and by unit tests to pin the byte layout.
pub fn parse(bytes: &[u8]) -> Result<Vec<Entry>, String> {
    if bytes.len() < HEADER_LEN {
        return Err(format!(
            "initramfs is {} bytes, shorter than the {HEADER_LEN}-byte header",
            bytes.len()
        ));
    }
    if &bytes[0..8] != MAGIC {
        return Err(format!("bad initramfs magic {:?}", &bytes[0..8]));
    }
    let version = u32::from_le_bytes(bytes[8..12].try_into().unwrap());
    if version != VERSION {
        return Err(format!("unsupported initramfs version {version}"));
    }
    let count = u32::from_le_bytes(bytes[12..16].try_into().unwrap()) as usize;
    if count == 0 || count > MAX_MODULES {
        return Err(format!("implausible initramfs module count {count}"));
    }
    let table_end = HEADER_LEN + RECORD_LEN * count;
    if bytes.len() < table_end {
        return Err(format!(
            "initramfs is {} bytes, too short for {count} records",
            bytes.len()
        ));
    }

    let mut out: Vec<Entry> = Vec::with_capacity(count);
    for i in 0..count {
        let rec = HEADER_LEN + i * RECORD_LEN;
        let raw_name = &bytes[rec..rec + 16];
        let nul = raw_name
            .iter()
            .position(|b| *b == 0)
            .ok_or_else(|| format!("record {i}: name is not NUL terminated"))?;
        let name = std::str::from_utf8(&raw_name[..nul])
            .map_err(|_| format!("record {i}: name is not valid UTF-8"))?
            .to_string();
        validate_name(&name).map_err(|e| format!("record {i}: {e}"))?;
        let kind = u32::from_le_bytes(bytes[rec + 16..rec + 20].try_into().unwrap());
        let offset = u64::from_le_bytes(bytes[rec + 24..rec + 32].try_into().unwrap());
        let size = u64::from_le_bytes(bytes[rec + 32..rec + 40].try_into().unwrap());
        if offset % ALIGN as u64 != 0 {
            return Err(format!(
                "record {i} ({name:?}): offset {offset} is not {ALIGN}-byte aligned"
            ));
        }
        if offset < table_end as u64 {
            return Err(format!(
                "record {i} ({name:?}): offset {offset} overlaps the record table (ends at {table_end})"
            ));
        }
        let end = offset
            .checked_add(size)
            .ok_or_else(|| format!("record {i} ({name:?}): offset+size overflow"))?;
        if end > bytes.len() as u64 {
            return Err(format!(
                "record {i} ({name:?}): payload ends at {end}, past the {}-byte container",
                bytes.len()
            ));
        }
        out.push(Entry {
            name,
            kind,
            offset: offset as usize,
            size: size as usize,
        });
    }
    for (i, e) in out.iter().enumerate() {
        for prev in &out[..i] {
            if prev.name == e.name {
                return Err(format!("duplicate module name {:?}", e.name));
            }
            if prev.offset < e.offset + e.size && e.offset < prev.offset + prev.size {
                return Err(format!("modules {:?} and {:?} overlap", prev.name, e.name));
            }
        }
    }
    Ok(out)
}

/// Payload bytes of `entry` inside `bytes` (must come from the same buffer).
pub fn payload<'a>(bytes: &'a [u8], entry: &Entry) -> &'a [u8] {
    &bytes[entry.offset..entry.offset + entry.size]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_init() -> Vec<u8> {
        (0..37u32).map(|i| (i * 3 % 251) as u8).collect()
    }

    #[test]
    fn container_layout_is_exact() {
        let init = sample_init();
        let child = b"child-bytes".to_vec();
        let img = build(&[
            Module {
                name: MODULE_INIT,
                kind: KIND_ELF,
                data: &init,
            },
            Module {
                name: MODULE_CHILD,
                kind: KIND_ELF,
                data: &child,
            },
        ])
        .expect("build container");

        // header: magic, version, count.
        assert_eq!(&img[0..8], MAGIC);
        assert_eq!(&img[0..8], b"CAELUMFS");
        assert_eq!(u32::from_le_bytes(img[8..12].try_into().unwrap()), VERSION);
        assert_eq!(u32::from_le_bytes(img[12..16].try_into().unwrap()), 2);

        // record table starts at 16, files start at the first aligned offset.
        let table_end = HEADER_LEN + 2 * RECORD_LEN;
        assert_eq!(table_end, 96, "16-byte header + 2 x 40-byte records");
        let init_off = 96usize;
        let child_off = align_up(96 + 37);
        assert_eq!(child_off, 144);
        assert_eq!(init_off % ALIGN, 0);
        assert_eq!(child_off % ALIGN, 0);

        // record 0: init.
        let r0 = HEADER_LEN;
        assert_eq!(&img[r0..r0 + 4], b"init");
        assert_eq!(&img[r0 + 4..r0 + 16], &[0u8; 12], "name is NUL padded");
        assert_eq!(
            u32::from_le_bytes(img[r0 + 16..r0 + 20].try_into().unwrap()),
            KIND_ELF
        );
        assert_eq!(
            u32::from_le_bytes(img[r0 + 20..r0 + 24].try_into().unwrap()),
            0,
            "reserved field must be zero"
        );
        assert_eq!(
            u64::from_le_bytes(img[r0 + 24..r0 + 32].try_into().unwrap()),
            init_off as u64
        );
        assert_eq!(
            u64::from_le_bytes(img[r0 + 32..r0 + 40].try_into().unwrap()),
            37
        );

        // record 1: child.
        let r1 = HEADER_LEN + RECORD_LEN;
        assert_eq!(&img[r1..r1 + 5], b"child");
        assert_eq!(
            u64::from_le_bytes(img[r1 + 24..r1 + 32].try_into().unwrap()),
            child_off as u64
        );
        assert_eq!(
            u64::from_le_bytes(img[r1 + 32..r1 + 40].try_into().unwrap()),
            child.len() as u64
        );

        // payload bytes.
        assert_eq!(&img[init_off..init_off + init.len()], &init[..]);
        assert_eq!(&img[child_off..child_off + child.len()], &child[..]);
        assert_eq!(img.len(), child_off + child.len());
    }

    #[test]
    fn container_parses_back_to_the_same_entries() {
        let init = sample_init();
        let child = b"child-bytes".to_vec();
        let img = build(&[
            Module {
                name: MODULE_INIT,
                kind: KIND_ELF,
                data: &init,
            },
            Module {
                name: MODULE_CHILD,
                kind: KIND_ELF,
                data: &child,
            },
        ])
        .unwrap();
        let entries = parse(&img).expect("parse");
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].name, "init");
        assert_eq!(entries[0].kind, KIND_ELF);
        assert_eq!(entries[0].offset, 96);
        assert_eq!(entries[0].size, 37);
        assert_eq!(payload(&img, &entries[0]), &init[..]);
        assert_eq!(entries[1].name, "child");
        assert_eq!(entries[1].offset, 144);
        assert_eq!(payload(&img, &entries[1]), &child[..]);
        for e in &entries {
            assert_eq!(e.offset % ALIGN, 0);
        }
    }

    #[test]
    fn container_rejects_invalid_inputs() {
        let data = b"x";
        assert!(build(&[]).is_err(), "no modules");
        assert!(
            build(&[Module {
                name: "",
                kind: KIND_ELF,
                data
            }])
            .is_err(),
            "empty name"
        );
        assert!(
            build(&[Module {
                name: "0123456789abcdef",
                kind: KIND_ELF,
                data
            }])
            .is_err(),
            "name longer than 15 bytes"
        );
        assert!(
            build(&[Module {
                name: "in it",
                kind: KIND_ELF,
                data
            }])
            .is_err(),
            "space is not an allowed name byte"
        );
        assert!(
            build(&[
                Module {
                    name: MODULE_INIT,
                    kind: KIND_ELF,
                    data
                },
                Module {
                    name: MODULE_INIT,
                    kind: KIND_ELF,
                    data
                }
            ])
            .is_err(),
            "duplicate names"
        );
        assert!(
            build(&[Module {
                name: MODULE_INIT,
                kind: KIND_ELF,
                data: b""
            }])
            .is_err(),
            "empty payload"
        );
    }

    #[test]
    fn parse_rejects_corruption() {
        let img = build(&[Module {
            name: MODULE_INIT,
            kind: KIND_ELF,
            data: b"hello",
        }])
        .unwrap();
        assert!(parse(&img).is_ok());

        let mut bad = img.clone();
        bad[0] = b'X';
        assert!(parse(&bad).is_err(), "bad magic");

        let mut bad = img.clone();
        bad[8..12].copy_from_slice(&2u32.to_le_bytes());
        assert!(parse(&bad).is_err(), "bad version");

        let mut bad = img.clone();
        bad[12..16].copy_from_slice(&0u32.to_le_bytes());
        assert!(parse(&bad).is_err(), "zero modules");

        assert!(parse(&img[..HEADER_LEN]).is_err(), "truncated table");

        let mut bad = img.clone();
        // record 0 offset field: make it unaligned.
        bad[HEADER_LEN + 24] = 0x61;
        assert!(parse(&bad).is_err(), "unaligned offset");

        let mut bad = img.clone();
        // record 0 size field: claim more bytes than the container holds.
        bad[HEADER_LEN + 32..HEADER_LEN + 40].copy_from_slice(&999u64.to_le_bytes());
        assert!(parse(&bad).is_err(), "payload past the end");
    }

    /// The kernel reads this container with `bootinfo::Initfs`, a completely
    /// separate parser. Run the bytes we write through *that* parser so the two
    /// implementations cannot drift apart without a test failing.
    #[test]
    fn container_matches_the_kernel_side_parser() {
        let init = sample_init();
        let child = b"child-bytes".to_vec();
        let img = build(&[
            Module {
                name: MODULE_INIT,
                kind: KIND_ELF,
                data: &init,
            },
            Module {
                name: MODULE_CHILD,
                kind: KIND_ELF,
                data: &child,
            },
        ])
        .unwrap();

        let parsed = bootinfo::Initfs::parse(&img).expect("kernel parser accepts our container");
        assert_eq!(parsed.count(), 2);

        let first = parsed.module(0).expect("module 0");
        assert_eq!(first.name_bytes(), Some(MODULE_INIT.as_bytes()));
        assert_eq!(first.kind, bootinfo::MODULE_KIND_ELF);
        assert_eq!(first.offset, 96);
        assert_eq!(first.size, init.len() as u64);

        let second = parsed.module(1).expect("module 1");
        assert_eq!(second.name_bytes(), Some(MODULE_CHILD.as_bytes()));
        assert_eq!(second.kind, bootinfo::MODULE_KIND_ELF);
        assert_eq!(second.offset, 144);
        assert_eq!(second.size, child.len() as u64);

        assert!(parsed.module(2).is_none(), "no third module");
    }

    /// M6b2 packs one more module, `worker`, and the loader looks the boot
    /// modules up by name in this exact order. A container that dropped or
    /// renamed it would make the guest stall before it ever printed the
    /// scheduling evidence, so pin the three-module layout on both parsers.
    #[test]
    fn three_module_container_matches_the_kernel_side_parser() {
        assert_eq!(MODULE_WORKER, "worker");
        let init = sample_init();
        let child = b"child-bytes".to_vec();
        let worker = b"worker-bytes".to_vec();
        let img = build(&[
            Module {
                name: MODULE_INIT,
                kind: KIND_ELF,
                data: &init,
            },
            Module {
                name: MODULE_CHILD,
                kind: KIND_ELF,
                data: &child,
            },
            Module {
                name: MODULE_WORKER,
                kind: KIND_ELF,
                data: &worker,
            },
        ])
        .expect("build three-module container");

        // count header and record table size.
        assert_eq!(u32::from_le_bytes(img[12..16].try_into().unwrap()), 3);
        assert_eq!(HEADER_LEN + 3 * RECORD_LEN, 136);

        let entries = parse(&img).expect("our parser accepts the container");
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[0].name, MODULE_INIT);
        assert_eq!(entries[2].name, MODULE_WORKER);
        assert_eq!(payload(&img, &entries[2]), &worker[..]);

        // The kernel's own parser must agree, including the worker's offset.
        let parsed = bootinfo::Initfs::parse(&img).expect("kernel parser accepts our container");
        assert_eq!(parsed.count(), 3);
        // Payloads start after the aligned record table (16 + 3 x 40 = 136 -> 144).
        let init_off = align_up(HEADER_LEN + 3 * RECORD_LEN);
        let child_off = align_up(init_off + init.len());
        let worker_off = align_up(child_off + child.len());
        assert_eq!(init_off, 144);
        assert_eq!(entries[0].offset, init_off);
        assert_eq!(entries[1].offset, child_off);
        assert_eq!(entries[2].offset, worker_off);
        let third = parsed.module(2).expect("module 2 (worker)");
        assert_eq!(third.name_bytes(), Some(MODULE_WORKER.as_bytes()));
        assert_eq!(third.kind, bootinfo::MODULE_KIND_ELF);
        assert_eq!(third.offset, worker_off as u64);
        assert_eq!(third.size, worker.len() as u64);
        assert!(parsed.module(3).is_none(), "no fourth module");
    }

    /// M6c adds the user-mode `gfx` program as a fourth boot module. The
    /// kernel-side parser must agree on the name, the count and the offsets, and
    /// the `gfx` payload must round-trip byte for byte.
    #[test]
    fn four_module_container_matches_the_kernel_side_parser() {
        assert_eq!(MODULE_GFX, "gfx");
        let init = sample_init();
        let child = b"child-bytes".to_vec();
        let worker = b"worker-bytes".to_vec();
        let gfx = b"gfx-bytes".to_vec();
        let img = build(&[
            Module {
                name: MODULE_INIT,
                kind: KIND_ELF,
                data: &init,
            },
            Module {
                name: MODULE_CHILD,
                kind: KIND_ELF,
                data: &child,
            },
            Module {
                name: MODULE_WORKER,
                kind: KIND_ELF,
                data: &worker,
            },
            Module {
                name: MODULE_GFX,
                kind: KIND_ELF,
                data: &gfx,
            },
        ])
        .expect("build four-module container");

        assert_eq!(u32::from_le_bytes(img[12..16].try_into().unwrap()), 4);
        assert_eq!(HEADER_LEN + 4 * RECORD_LEN, 176);

        let entries = parse(&img).expect("our parser accepts the container");
        assert_eq!(entries.len(), 4);
        assert_eq!(entries[3].name, MODULE_GFX);
        assert_eq!(payload(&img, &entries[3]), &gfx[..]);

        let parsed = bootinfo::Initfs::parse(&img).expect("kernel parser accepts our container");
        assert_eq!(parsed.count(), 4);
        // Payloads start after the aligned record table (16 + 4 x 40 = 176, which
        // is already 16-byte aligned).
        let init_off = align_up(HEADER_LEN + 4 * RECORD_LEN);
        let child_off = align_up(init_off + init.len());
        let worker_off = align_up(child_off + child.len());
        let gfx_off = align_up(worker_off + worker.len());
        assert_eq!(init_off, 176);
        assert_eq!(entries[0].offset, init_off);
        assert_eq!(entries[3].offset, gfx_off);
        let fourth = parsed.module(3).expect("module 3 (gfx)");
        assert_eq!(fourth.name_bytes(), Some(MODULE_GFX.as_bytes()));
        assert_eq!(fourth.kind, bootinfo::MODULE_KIND_ELF);
        assert_eq!(fourth.offset, gfx_off as u64);
        assert_eq!(fourth.size, gfx.len() as u64);
        assert!(parsed.module(4).is_none(), "no fifth module");
    }

    /// M7b adds the user-mode `net` program as a fifth boot module. The
    /// kernel-side parser must agree on the name, the count and the offsets, and
    /// the `net` payload must round-trip byte for byte.
    #[test]
    fn five_module_container_matches_the_kernel_side_parser() {
        assert_eq!(MODULE_NET, "net");
        let init = sample_init();
        let child = b"child-bytes".to_vec();
        let worker = b"worker-bytes".to_vec();
        let gfx = b"gfx-bytes".to_vec();
        let net = b"net-bytes".to_vec();
        let img = build(&[
            Module {
                name: MODULE_INIT,
                kind: KIND_ELF,
                data: &init,
            },
            Module {
                name: MODULE_CHILD,
                kind: KIND_ELF,
                data: &child,
            },
            Module {
                name: MODULE_WORKER,
                kind: KIND_ELF,
                data: &worker,
            },
            Module {
                name: MODULE_GFX,
                kind: KIND_ELF,
                data: &gfx,
            },
            Module {
                name: MODULE_NET,
                kind: KIND_ELF,
                data: &net,
            },
        ])
        .expect("build five-module container");

        assert_eq!(u32::from_le_bytes(img[12..16].try_into().unwrap()), 5);
        assert_eq!(HEADER_LEN + 5 * RECORD_LEN, 216);

        let entries = parse(&img).expect("our parser accepts the container");
        assert_eq!(entries.len(), 5);
        assert_eq!(entries[4].name, MODULE_NET);
        assert_eq!(payload(&img, &entries[4]), &net[..]);

        let parsed = bootinfo::Initfs::parse(&img).expect("kernel parser accepts our container");
        assert_eq!(parsed.count(), 5);
        // Payloads start after the aligned record table (16 + 5 x 40 = 216 -> 224).
        let init_off = align_up(HEADER_LEN + 5 * RECORD_LEN);
        let child_off = align_up(init_off + init.len());
        let worker_off = align_up(child_off + child.len());
        let gfx_off = align_up(worker_off + worker.len());
        let net_off = align_up(gfx_off + gfx.len());
        assert_eq!(init_off, 224);
        assert_eq!(entries[0].offset, init_off);
        assert_eq!(entries[4].offset, net_off);
        let fifth = parsed.module(4).expect("module 4 (net)");
        assert_eq!(fifth.name_bytes(), Some(MODULE_NET.as_bytes()));
        assert_eq!(fifth.kind, bootinfo::MODULE_KIND_ELF);
        assert_eq!(fifth.offset, net_off as u64);
        assert_eq!(fifth.size, net.len() as u64);
        assert!(parsed.module(5).is_none(), "no sixth module");
    }

    /// M7d adds the user-mode `linux` program as a sixth boot module. The
    /// kernel-side parser must agree on the name, the count and the offsets, and
    /// the `linux` payload must round-trip byte for byte.
    #[test]
    fn six_module_container_matches_the_kernel_side_parser() {
        assert_eq!(MODULE_LINUX, "linux");
        let init = sample_init();
        let child = b"child-bytes".to_vec();
        let worker = b"worker-bytes".to_vec();
        let gfx = b"gfx-bytes".to_vec();
        let net = b"net-bytes".to_vec();
        let linux = b"linux-bytes".to_vec();
        let img = build(&[
            Module {
                name: MODULE_INIT,
                kind: KIND_ELF,
                data: &init,
            },
            Module {
                name: MODULE_CHILD,
                kind: KIND_ELF,
                data: &child,
            },
            Module {
                name: MODULE_WORKER,
                kind: KIND_ELF,
                data: &worker,
            },
            Module {
                name: MODULE_GFX,
                kind: KIND_ELF,
                data: &gfx,
            },
            Module {
                name: MODULE_NET,
                kind: KIND_ELF,
                data: &net,
            },
            Module {
                name: MODULE_LINUX,
                kind: KIND_ELF,
                data: &linux,
            },
        ])
        .expect("build six-module container");

        assert_eq!(u32::from_le_bytes(img[12..16].try_into().unwrap()), 6);
        assert_eq!(HEADER_LEN + 6 * RECORD_LEN, 256);

        let entries = parse(&img).expect("our parser accepts the container");
        assert_eq!(entries.len(), 6);
        assert_eq!(entries[5].name, MODULE_LINUX);
        assert_eq!(payload(&img, &entries[5]), &linux[..]);

        let parsed = bootinfo::Initfs::parse(&img).expect("kernel parser accepts our container");
        assert_eq!(parsed.count(), 6);
        // The record table is 16 + 6 x 40 = 256 bytes, already 16-byte aligned.
        let init_off = align_up(HEADER_LEN + 6 * RECORD_LEN);
        let child_off = align_up(init_off + init.len());
        let worker_off = align_up(child_off + child.len());
        let gfx_off = align_up(worker_off + worker.len());
        let net_off = align_up(gfx_off + gfx.len());
        let linux_off = align_up(net_off + net.len());
        assert_eq!(init_off, 256);
        assert_eq!(entries[0].offset, init_off);
        assert_eq!(entries[5].offset, linux_off);
        let sixth = parsed.module(5).expect("module 5 (linux)");
        assert_eq!(sixth.name_bytes(), Some(MODULE_LINUX.as_bytes()));
        assert_eq!(sixth.kind, bootinfo::MODULE_KIND_ELF);
        assert_eq!(sixth.offset, linux_off as u64);
        assert_eq!(sixth.size, linux.len() as u64);
        assert!(parsed.module(6).is_none(), "no seventh module");
    }
}
