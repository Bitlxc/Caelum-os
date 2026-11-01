//! Initial stack for a Linux `_start`.
//!
//! A Linux program does not receive its arguments in registers: right after
//! `exec` the kernel has built the following image on the user stack and `rsp`
//! points at it (System V x86-64 psABI, "Process Initialization"):
//!
//! ```text
//! rsp + 0x00   argc                     (0: the personality starts with no argv)
//! rsp + 0x08   argv[0] = NULL
//! rsp + 0x10   envp[0] = NULL
//! rsp + 0x18   auxv[0].a_type, auxv[0].a_val
//! ...
//!              AT_NULL, 0
//! ```
//!
//! The Caelum-specific entries carry the initial native handles the personality
//! needs. They are **auxv entries only**: the Linux ABI registers (`rdi`, `rsi`,
//! `rdx`) stay untouched, and the console is reached through fds 0/1/2 as on
//! Linux.
//!
//! This module only encodes the image. Placing it on the user stack and aligning
//! the initial `rsp` (16-byte alignment, as the SysV ABI requires) is the
//! process layer's job: `spawn_detached_linux` writes it at
//! `(user_stack - written) & !0xF`.

/// `AT_PAGESZ`: page size.
pub const AT_PAGESZ: u64 = 6;
/// `AT_NULL`: end of the auxiliary vector.
pub const AT_NULL: u64 = 0;
/// Caelum: native handle of the initial IPC channel endpoint.
pub const AT_CAELUM_CHANNEL: u64 = 0xCAE1_0001;
/// Caelum: native handle of the process network namespace.
pub const AT_CAELUM_NETNS: u64 = 0xCAE1_0002;
/// Caelum: initial-process role (see [`CAELUM_ROLE_ROOT`] / [`CAELUM_ROLE_CHILD`]).
///
/// M8d runs the same Linux image twice: the detached parent prints the role
/// `0` path and the parented child prints the role `1` path, so the program can
/// tell the two apart without a second auxv handle for its peer pid.
pub const AT_CAELUM_ROLE: u64 = 0xCAE1_0003;

/// Role value for the detached root/parent Linux process.
pub const CAELUM_ROLE_ROOT: u64 = 0;
/// Role value for a parented Linux child.
pub const CAELUM_ROLE_CHILD: u64 = 1;
/// M9c: second long-lived child that only participates in the file-lock
/// protocol and exits through it once the parent has reaped it.
pub const CAELUM_ROLE_LOCK_PEER: u64 = 2;

// System V auxv tags that a dynamically linked program needs before it can run
// its interpreter. M9d1 supplies them from the loaded main image.
/// `AT_PHDR`: user address of the main program's program headers.
pub const AT_PHDR: u64 = 3;
/// `AT_PHENT`: size of one program header entry.
pub const AT_PHENT: u64 = 4;
/// `AT_PHNUM`: number of program header entries.
pub const AT_PHNUM: u64 = 5;
/// `AT_BASE`: load address of the interpreter (0 when the kernel hands one).
pub const AT_BASE: u64 = 7;
/// `AT_ENTRY`: entry point of the main program.
pub const AT_ENTRY: u64 = 9;
/// `AT_SYSINFO_EHDR`: user address of the vDSO ELF image (M9d2).
pub const AT_SYSINFO_EHDR: u64 = 33;
/// `AT_HWCAP`: CPU feature bits (zero: the personality does not advertise any
/// optional ISA extension through this channel).
pub const AT_HWCAP: u64 = 16;
/// `AT_CLKTCK`: clock ticks per second (`_SC_CLK_TCK`).
pub const AT_CLKTCK: u64 = 17;
/// `AT_UID`/`AT_EUID`/`AT_GID`/`AT_EGID`: real/effective identity (M10a: 0).
pub const AT_UID: u64 = 11;
/// See [`AT_UID`].
pub const AT_EUID: u64 = 12;
/// See [`AT_UID`].
pub const AT_GID: u64 = 13;
/// See [`AT_UID`].
pub const AT_EGID: u64 = 14;
/// `AT_SECURE`: 0 for a normal (unprivileged) startup.
pub const AT_SECURE: u64 = 23;
/// `AT_RANDOM`: address of 16 random bytes on the initial stack.
pub const AT_RANDOM: u64 = 25;
/// `AT_EXECFN`: address of the program path string on the initial stack.
pub const AT_EXECFN: u64 = 31;
/// `AT_FLAGS`: ELF header flags (zero for Linux x86-64 user executables).
pub const AT_FLAGS: u64 = 8;

/// Bytes in the initial stack image (all entries are 8-byte aligned).
pub const INITIAL_STACK_BYTES: usize = 8 + // argc
    8 + // argv[0] = NULL
    8 + // envp[0] = NULL
    5 * 16 + // five auxv pairs: PAGESZ, CHANNEL, NETNS, ROLE, AT_NULL
    0;

/// Bytes in the dynamic-linker stack image (M9d1/M9d2): the same three fixed
/// words plus eleven auxv pairs (PAGESZ, PHDR, PHENT, PHNUM, ENTRY, BASE,
/// SYSINFO_EHDR, CHANNEL, NETNS, ROLE, AT_NULL).
pub const DYNAMIC_STACK_BYTES: usize = 8 + // argc
    8 + // argv[0] = NULL
    8 + // envp[0] = NULL
    11 * 16; // the auxv pairs above, ending in AT_NULL

/// Encode the initial Linux stack image into `out`.
///
/// Returns the number of bytes written. The caller places the image at the top
/// of the new user stack and sets `rsp` to the start of the image. `channel_raw`
/// and `netns_raw` are native handle numbers; `0` means "no handle" and is
/// encoded as-is (`HANDLE_NONE`).
///
/// This compatibility entry always encodes [`CAELUM_ROLE_ROOT`]; the M8d child
/// path uses [`encode_initial_stack_with_role`] with [`CAELUM_ROLE_CHILD`].
pub fn encode_initial_stack(
    out: &mut [u8],
    channel_raw: u32,
    netns_raw: u32,
) -> Result<usize, &'static str> {
    encode_initial_stack_with_role(out, channel_raw, netns_raw, CAELUM_ROLE_ROOT)
}

/// Encode the initial Linux stack image with an explicit Caelum role.
///
/// `role` is written as the `AT_CAELUM_ROLE` auxv value: `0` for the detached
/// root process, `1` for a parented child. Unknown values are encoded as given
/// so a future stage can add roles without touching the stack layout.
pub fn encode_initial_stack_with_role(
    out: &mut [u8],
    channel_raw: u32,
    netns_raw: u32,
    role: u64,
) -> Result<usize, &'static str> {
    if out.len() < INITIAL_STACK_BYTES {
        return Err("stack buffer too small");
    }
    let mut cursor = 0usize;

    let push = |out: &mut [u8], value: u64, cursor: &mut usize| {
        out[*cursor..*cursor + 8].copy_from_slice(&value.to_le_bytes());
        *cursor += 8;
    };

    push(out, 0, &mut cursor); // argc = 0
    push(out, 0, &mut cursor); // argv[0] = NULL
    push(out, 0, &mut cursor); // envp[0] = NULL

    push(out, AT_PAGESZ, &mut cursor);
    push(out, 4096, &mut cursor);
    push(out, AT_CAELUM_CHANNEL, &mut cursor);
    push(out, u64::from(channel_raw), &mut cursor);
    push(out, AT_CAELUM_NETNS, &mut cursor);
    push(out, u64::from(netns_raw), &mut cursor);
    push(out, AT_CAELUM_ROLE, &mut cursor);
    push(out, role, &mut cursor);
    push(out, AT_NULL, &mut cursor);
    push(out, 0, &mut cursor);

    Ok(cursor)
}

/// Encode the initial Linux stack image for a **dynamically linked** program.
///
/// The kernel has already mapped the main image at its load bias and the
/// interpreter named by `PT_INTERP`; `phdr`, `phent`, `phnum` and `entry` are
/// the main image's real values (already biased where needed). The interpreter
/// receives control at its own entry and reads this image from `rsp`, exactly
/// as `_start` would.
///
/// The Caelum handle entries stay present but zero: M9d1's dynamic closure is a
/// startup test, not a socket service, so it must not look as if it holds a
/// channel or a network namespace.
pub fn encode_dynamic_stack(
    out: &mut [u8],
    phdr: u64,
    phent: u32,
    phnum: u32,
    entry: u64,
    sysinfo_ehdr: u64,
) -> Result<usize, &'static str> {
    if out.len() < DYNAMIC_STACK_BYTES {
        return Err("stack buffer too small");
    }
    let mut cursor = 0usize;

    let push = |out: &mut [u8], value: u64, cursor: &mut usize| {
        out[*cursor..*cursor + 8].copy_from_slice(&value.to_le_bytes());
        *cursor += 8;
    };

    push(out, 0, &mut cursor); // argc = 0
    push(out, 0, &mut cursor); // argv[0] = NULL
    push(out, 0, &mut cursor); // envp[0] = NULL

    push(out, AT_PAGESZ, &mut cursor);
    push(out, 4096, &mut cursor);
    push(out, AT_PHDR, &mut cursor);
    push(out, phdr, &mut cursor);
    push(out, AT_PHENT, &mut cursor);
    push(out, u64::from(phent), &mut cursor);
    push(out, AT_PHNUM, &mut cursor);
    push(out, u64::from(phnum), &mut cursor);
    push(out, AT_ENTRY, &mut cursor);
    push(out, entry, &mut cursor);
    push(out, AT_BASE, &mut cursor);
    push(out, 0, &mut cursor);
    push(out, AT_SYSINFO_EHDR, &mut cursor);
    push(out, sysinfo_ehdr, &mut cursor);
    push(out, AT_CAELUM_CHANNEL, &mut cursor);
    push(out, 0, &mut cursor);
    push(out, AT_CAELUM_NETNS, &mut cursor);
    push(out, 0, &mut cursor);
    push(out, AT_CAELUM_ROLE, &mut cursor);
    push(out, CAELUM_ROLE_ROOT, &mut cursor);
    push(out, AT_NULL, &mut cursor);
    push(out, 0, &mut cursor);

    Ok(cursor)
}

/// Fixed upper bound for the M10a program start-up image.
///
/// The image holds argc/argv pointers, a NULL envp, the full auxv, the program
/// path and the 16 `AT_RANDOM` bytes: far below this bound. The user stack is
/// 8 pages (32 KiB), so a 1 KiB reservation keeps it safe.
pub const PROGRAM_STACK_BYTES: usize = 1024;

/// Encode the initial stack for a real dynamically linked program (M10a).
///
/// The layout is the Linux `_start` one:
///
/// ```text
/// rsp+0        argc
/// rsp+8        argv[0..argc]
///              NULL
///              NULL            (empty envp)
///              auxv pairs      (ending in AT_NULL/0)
///              strings         (AT_EXECFN path, argv strings, AT_RANDOM bytes)
/// ```
///
/// `execfn` is the program path (`AT_EXECFN`); `argv` starts with the same path
/// by convention. `stack_top` is the top of the mapped user stack: the encoder
/// returns the 16-byte aligned `rsp` it placed the image at. The frozen Caelum
/// handle entries stay zero: this program holds no channel or net namespace.
#[allow(clippy::too_many_arguments)]
pub fn encode_program_stack(
    out: &mut [u8],
    stack_top: u64,
    phdr: u64,
    phent: u32,
    phnum: u32,
    entry: u64,
    interp_base: u64,
    sysinfo_ehdr: u64,
    random: &[u8; 16],
    execfn: &[u8],
    argv: &[&[u8]],
) -> Result<(u64, usize), &'static str> {
    if argv.is_empty() || argv.len() > 8 {
        return Err("unsupported argc");
    }
    // argc + argv pointers + argv NULL + envp NULL.
    let header = 8 + argv.len() * 8 + 8 + 8;
    // PAGESZ, PHDR, PHENT, PHNUM, ENTRY, BASE, FLAGS, SYSINFO, HWCAP, CLKTCK,
    // UID, EUID, GID, EGID, SECURE, RANDOM, EXECFN, CHANNEL, NETNS, ROLE,
    // AT_NULL.
    const AUX_PAIRS: usize = 21;
    let aux = AUX_PAIRS * 16;

    let mut cursor = header + aux;
    let execfn_offset = cursor;
    cursor += execfn.len() + 1;
    let mut argv_offsets = [0usize; 8];
    for (index, arg) in argv.iter().enumerate() {
        argv_offsets[index] = cursor;
        cursor += arg.len() + 1;
    }
    let random_offset = (cursor + 15) & !15;
    let size = random_offset + 16;
    if size > out.len() || size > PROGRAM_STACK_BYTES {
        return Err("stack buffer too small");
    }
    let rsp = (stack_top - size as u64) & !0xF;

    fn put(out: &mut [u8], at: usize, value: u64) {
        out[at..at + 8].copy_from_slice(&value.to_le_bytes());
    }

    put(out, 0, argv.len() as u64);
    for index in 0..argv.len() {
        put(out, 8 + index * 8, rsp + argv_offsets[index] as u64);
    }
    put(out, 8 + argv.len() * 8, 0);
    put(out, 16 + argv.len() * 8, 0);

    let mut at = header;
    let mut pair = |tag: u64, value: u64| {
        put(out, at, tag);
        put(out, at + 8, value);
        at += 16;
    };
    pair(AT_PAGESZ, 4096);
    pair(AT_PHDR, phdr);
    pair(AT_PHENT, u64::from(phent));
    pair(AT_PHNUM, u64::from(phnum));
    pair(AT_ENTRY, entry);
    pair(AT_BASE, interp_base);
    pair(AT_FLAGS, 0);
    pair(AT_SYSINFO_EHDR, sysinfo_ehdr);
    pair(AT_HWCAP, 0);
    pair(AT_CLKTCK, 100);
    pair(AT_UID, 0);
    pair(AT_EUID, 0);
    pair(AT_GID, 0);
    pair(AT_EGID, 0);
    pair(AT_SECURE, 0);
    pair(AT_RANDOM, rsp + random_offset as u64);
    pair(AT_EXECFN, rsp + execfn_offset as u64);
    pair(AT_CAELUM_CHANNEL, 0);
    pair(AT_CAELUM_NETNS, 0);
    pair(AT_CAELUM_ROLE, CAELUM_ROLE_ROOT);
    put(out, at, AT_NULL);
    put(out, at + 8, 0);

    out[execfn_offset..execfn_offset + execfn.len()].copy_from_slice(execfn);
    for (index, arg) in argv.iter().enumerate() {
        let start = argv_offsets[index];
        out[start..start + arg.len()].copy_from_slice(arg);
    }
    out[random_offset..random_offset + 16].copy_from_slice(random);

    Ok((rsp, size))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn word(image: &[u8], index: usize) -> u64 {
        u64::from_le_bytes(image[index * 8..index * 8 + 8].try_into().unwrap())
    }

    #[test]
    fn the_stack_starts_with_argc_zero_and_null_argv_envp() {
        let mut image = [0xAAu8; INITIAL_STACK_BYTES];
        let written = encode_initial_stack(&mut image, 0x0001_0004, 0x0001_0005).unwrap();
        assert_eq!(written, INITIAL_STACK_BYTES);
        assert_eq!(word(&image, 0), 0, "argc");
        assert_eq!(word(&image, 1), 0, "argv[0]");
        assert_eq!(word(&image, 2), 0, "envp[0]");
    }

    #[test]
    fn the_auxiliary_vector_ends_with_at_null_and_carries_the_handles() {
        let mut image = [0u8; INITIAL_STACK_BYTES];
        encode_initial_stack(&mut image, 0x0001_0004, 0x0001_0005).unwrap();
        let auxv = [
            (word(&image, 3), word(&image, 4)),
            (word(&image, 5), word(&image, 6)),
            (word(&image, 7), word(&image, 8)),
            (word(&image, 9), word(&image, 10)),
            (word(&image, 11), word(&image, 12)),
        ];
        assert_eq!(auxv[0], (AT_PAGESZ, 4096));
        assert_eq!(auxv[1], (AT_CAELUM_CHANNEL, 0x0001_0004));
        assert_eq!(auxv[2], (AT_CAELUM_NETNS, 0x0001_0005));
        assert_eq!(auxv[3], (AT_CAELUM_ROLE, CAELUM_ROLE_ROOT));
        assert_eq!(auxv[4], (AT_NULL, 0));
    }

    #[test]
    fn the_role_variant_marks_a_parented_child_without_changing_the_layout() {
        let mut root = [0u8; INITIAL_STACK_BYTES];
        let mut child = [0u8; INITIAL_STACK_BYTES];
        let root_written = encode_initial_stack(&mut root, 3, 4).unwrap();
        let child_written = encode_initial_stack_with_role(&mut child, 3, 4, CAELUM_ROLE_CHILD)
            .expect("role variant writes the same image size");
        assert_eq!(root_written, INITIAL_STACK_BYTES);
        assert_eq!(child_written, root_written);
        assert_eq!(word(&root, 9), AT_CAELUM_ROLE);
        assert_eq!(word(&root, 10), CAELUM_ROLE_ROOT);
        assert_eq!(word(&child, 9), AT_CAELUM_ROLE);
        assert_eq!(word(&child, 10), CAELUM_ROLE_CHILD);
        // Only the role value differs; everything else is byte-identical.
        for index in 0..INITIAL_STACK_BYTES / 8 {
            if index == 10 {
                continue;
            }
            assert_eq!(word(&root, index), word(&child, index), "word {index}");
        }
        assert_eq!(word(&child, 11), AT_NULL);
        assert_eq!(word(&child, 12), 0);
    }

    #[test]
    fn the_role_variant_round_trips_an_arbitrary_role() {
        let mut image = [0u8; INITIAL_STACK_BYTES];
        encode_initial_stack_with_role(&mut image, 0, 0, 7).unwrap();
        assert_eq!(word(&image, 9), AT_CAELUM_ROLE);
        assert_eq!(word(&image, 10), 7);
    }

    #[test]
    fn a_short_buffer_is_rejected_without_writing() {
        let mut image = [0u8; INITIAL_STACK_BYTES - 1];
        assert_eq!(
            encode_initial_stack(&mut image, 1, 2),
            Err("stack buffer too small")
        );
        assert!(image.iter().all(|byte| *byte == 0));
        assert_eq!(
            encode_initial_stack_with_role(&mut image, 1, 2, CAELUM_ROLE_CHILD),
            Err("stack buffer too small")
        );
    }

    #[test]
    fn the_dynamic_stack_carries_real_phdr_entry_values() {
        let mut image = [0u8; DYNAMIC_STACK_BYTES];
        let written =
            encode_dynamic_stack(&mut image, 0x0200_0040, 56, 3, 0x0200_0123, 0x0700_0000)
                .expect("dynamic stack fits");
        assert_eq!(written, DYNAMIC_STACK_BYTES);
        assert_eq!(word(&image, 0), 0, "argc");
        assert_eq!(word(&image, 1), 0, "argv[0]");
        assert_eq!(word(&image, 2), 0, "envp[0]");
        let auxv = [
            (word(&image, 3), word(&image, 4)),
            (word(&image, 5), word(&image, 6)),
            (word(&image, 7), word(&image, 8)),
            (word(&image, 9), word(&image, 10)),
            (word(&image, 11), word(&image, 12)),
            (word(&image, 13), word(&image, 14)),
            (word(&image, 15), word(&image, 16)),
            (word(&image, 17), word(&image, 18)),
            (word(&image, 19), word(&image, 20)),
            (word(&image, 21), word(&image, 22)),
            (word(&image, 23), word(&image, 24)),
        ];
        assert_eq!(auxv[0], (AT_PAGESZ, 4096));
        assert_eq!(auxv[1], (AT_PHDR, 0x0200_0040));
        assert_eq!(auxv[2], (AT_PHENT, 56));
        assert_eq!(auxv[3], (AT_PHNUM, 3));
        assert_eq!(auxv[4], (AT_ENTRY, 0x0200_0123));
        assert_eq!(auxv[5], (AT_BASE, 0));
        assert_eq!(auxv[6], (AT_SYSINFO_EHDR, 0x0700_0000));
        assert_eq!(auxv[7], (AT_CAELUM_CHANNEL, 0));
        assert_eq!(auxv[8], (AT_CAELUM_NETNS, 0));
        assert_eq!(auxv[9], (AT_CAELUM_ROLE, CAELUM_ROLE_ROOT));
        assert_eq!(auxv[10], (AT_NULL, 0));
    }

    #[test]
    fn the_dynamic_stack_rejects_a_short_buffer() {
        let mut image = [0u8; DYNAMIC_STACK_BYTES - 1];
        assert_eq!(
            encode_dynamic_stack(&mut image, 1, 56, 2, 3, 0x0700_0000),
            Err("stack buffer too small")
        );
        assert!(image.iter().all(|byte| *byte == 0));
    }
}
