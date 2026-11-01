//! CaelumOS build automation (`cargo xtask <command>`).
//!
//! Commands:
//! - `build`  — build loader (UEFI), kernel and the M4 user programs
//!              `caelum-init`/`caelum-child` (both `x86_64-unknown-none` ELFs)
//! - `check`  — rustfmt --check + cargo check every target + host unit tests
//! - `image`  — build, pack the `CAELUMFS` initramfs (`target/initramfs.img`),
//!              then generate `target/caelum-esp.img`: a FAT16 ESP containing
//!              `/EFI/BOOT/BOOTX64.EFI`, `/KERNEL.ELF` and `/INITFS.IMG`
//! - `qemu`   — boot the image twice in QEMU/OVMF on fresh FAT32/ext2 disks,
//!              inject M3 keyboard/serial input, verify the serial markers
//!              (M1/M2 regression + M3 + M4 + M5a + M5b) and re-check the
//!              volumes on the host after each boot
//! - `test`   — check + image + qemu (the full acceptance pipeline)
//!
//! QEMU/OVMF are optional: when not installed, `qemu`/`test` print the exact
//! manual command and continue (exit 0). Nothing here installs software.
//!
//! M3 input injection (the reason this file is more than a build script):
//!
//! - The guest serial port is a *bidirectional* TCP chardev
//!   (`-chardev socket,...,server=on,wait=on -serial chardev:ser0`). The
//!   harness connects before QEMU starts the VM (`wait=on`), so nothing is
//!   lost, then both reads the guest output (tee'd to `target/serial.log`) and
//!   writes bytes into the guest UART RX path.
//! - The PS/2 keyboard is driven through QMP on a second loopback TCP socket
//!   (`-qmp tcp:...,server=on,wait=off`): `qmp_capabilities` then `send-key`
//!   with qcode `a`. `-display none` does not remove the emulated i8042.
//! - Injection happens exactly once, and only after the guest prints
//!   `M3 input ready`; acceptance then requires the *guest* to print
//!   `M3 input OK` and `M3 serial OK`, so a successful injection is never
//!   mistaken for a working driver.
//!
//! M4 adds no extra input: the image just has to carry the boot-module
//! container and the guest has to print the M4 markers. The deliberate M2 page
//! fault must still be the *last* required marker, because it proves the whole
//! boot (including the M4 exit path) ran to completion.
//!
//! M5a adds no extra input and no image or QEMU change either: the guest prints
//! six `M5a ... OK` markers (VFS, page cache, ramfs, locks, directory
//! notification, boot modules through the VFS). They must appear *before* the
//! deliberate M2 page fault, which stays last and now also proves the M4 -> M5a
//! boot-module migration path ran to completion.
//!
//! M5b is the first milestone with *persistent storage*, so acceptance becomes
//! a two-boot run. `xtask qemu` formats a 64 MiB FAT32 volume and a 32 MiB
//! ext2 volume on the host
//! (FAT32 and ext2, using the same filesystem crates the kernel links), boots
//! the guest on them as legacy virtio-blk drives (`index 0` = FAT32,
//! `index 1` = ext2), boots it a second time on the *same* images, and
//! re-mounts both volumes on the host after each boot to check exactly what the
//! guest wrote (see `disks.rs`). Each boot has its own marker set, its own
//! serial log (`target/serial-boot1.log`, `target/serial-boot2.log`) and its own
//! timeout; `target/serial.log` keeps a copy of the second boot's transcript.
//! No extra input is injected for M5b.
//!
//! M5c1 adds user-visible file semantics on top of that persistent image, so
//! every boot must also print four `M5c`/`M5c1` markers: the kernel announces
//! its mounts before it spawns `init`, both user programs report their file
//! round trip before `init` exits, and `M5c1 OK` closes the M5b persistence
//! block (still before the deliberate M2 page fault). The host checks grow the
//! same way: after the first boot both volumes must hold the 14-byte
//! `CAELUM-M5C1-V1` file, after the second boot the 20-byte
//! `CAELUM-M5C1-V1\nBOOT2` file. A boot that prints only some of it, or writes
//! the wrong bytes to only one volume, fails.
//!
//! M5c2 adds shared/private `mmap` on the same volumes, so each boot also prints
//! three markers: both user programs report their mmap round trip right after
//! their file round trip (still before `init` exits), and `M5c2 OK` follows the
//! `M5c1` verdict while preceding the deliberate page fault. The host check adds
//! the 8192-byte map file (`/M5MAP.BIN` on FAT32, `/m5cmap` on ext2): both boots
//! must leave it in the *final* state — the deterministic pattern with exactly
//! offset 0 set to `0xA5` and offset 4103 set to `0x5A` by the shared mapping.
//! The private mapping's `0xFF` at offset 0 must never reach the disk; a missing
//! file, wrong length, stale edit, or a write-back of the private page fails.
//!
//! M5c3 adds the volatile semantics (xattr, watches, locks) plus sparse files and
//! fault injection, so each boot also prints eight markers: `init` reports xattr,
//! sparse and watch after its mmap; the child reports locks after its mmap;
//! `init` reports locks after the child's wait; and the kernel reports the fault
//! verdicts (`M5c3 faults OK`, `M5c3 OK`) before `M5 OK` closes the stage. The
//! host check adds two files on each volume: the 32772-byte sparse file
//! (`/M5HOLE.BIN`, `/m5chole` — zeros up to offset 32768 with the trailing
//! `HOLE`), which both boots recreate, and the 16-byte `/M5FAULT.BIN` /
//! `/m5cfault` holding `CAELUM-FAULT-OK` after the driver-level write/flush
//! injection recovered. xattr is volatile on purpose: the host does not check it.
//!
//! M6a1 is the first M6 slice, not M6: it only requires the monotonic timer and
//! user-visible Event objects. Each boot prints four more markers: `init`
//! reports its timer and Event round trips after the M5c3 work and before it
//! exits, the child reports its Event round trip after its locks, and `M6a OK`
//! closes the stage after `M5 OK` while the deliberate M2 page fault stays last.
//! No full-M6 capability (SMP, channels, ports, shared memory) may be required
//! here, and no extra host disk check is added.
//!
//! M6b1 is the first SMP slice, not full SMP: QEMU is started with `-smp 4` and
//! the kernel must print one extra marker per boot, `[CaelumKernel] M6b1
//! online=4`, right after the M3 stage and before the M4 object work. It only
//! proves that the application processors came online; no `M6b OK`, scheduler or
//! IPI verdict may be required, and no host disk check is added.
//!
//! M6b2 is the scheduling half of SMP. The kernel prints five extra lines per
//! boot, all from the boot processor after the M6a2 closeout and before the
//! deliberate M2 page fault: `M6b2 ap user OK`, `M6b2 ap preempt OK`,
//! `M6b2 wake ipi OK`, `M6b2 migrate OK` and the `M6b2 OK` verdict. Each line is
//! emitted only when counters collected *during the user-mode phase* (enabled
//! after a successful `spawn_init`, disabled when `init` exits) reached their
//! frozen minimums: user-mode resumes on an AP, timer preemptions that really
//! switched a user frame away on an AP, cross-CPU wakes that needed a real
//! reschedule IPI, and controlled migrations. This harness parses the
//! `key=value` payload of every line and fails a boot whose counts are missing,
//! non-numeric, below the minimum, or lower than the evidence they summarise —
//! printing a marker line is not enough. No new disk check is added: scheduling
//! evidence exists only in the guest counters, so the host verifies the parsed
//! numbers, not the volumes.
//!
//! M6c is the display/input slice. A fourth boot module, `gfx` (`caelum-gfx`),
//! presents a framed shadow buffer to the physical framebuffer and reports the
//! input events it actually received. Each boot prints five more markers:
//! `M6c display probe OK` (kernel, after the M6b2 closeout) then
//! `M6c display OK`, `M6c input ready`, `M6c input OK` (all `[CaelumGfx]`) and
//! the kernel's `M6c OK`, still before the deliberate M2 page fault. This is not
//! only text: once `M6c display OK` appears the harness asks QEMU for a
//! `screendump` and parses the P6 PPM it writes, verifying that the bottom-right
//! corner of the *physical* framebuffer is magenta and the two rectangles are
//! green/blue (±8 per channel). Once `M6c input ready` appears it injects a
//! *second* input: PS/2 key `d` through QMP and, only after that key's `make`/
//! `break` pair has fully settled (the QMP hold time, plus a guard margin), the
//! serial bytes `m6c` — the guest asserts the order make -> break -> m -> 6 -> c
//! (the M3 injection still happens first). Both `M6c input OK` and `M6c OK` must
//! carry an
//! `(events=5, dropped=0)` payload — two keyboard scancodes plus three serial
//! events, none dropped — which the harness parses and enforces, so a marker with
//! a wrong event count is not acceptance.
//!
//! M7a starts the networking milestone with the in-kernel loopback stack: no
//! NIC is involved, the four suites run inside the kernel after the M6c verdict,
//! and each boot prints six more markers — `M7a ipv4 udp OK (bytes=7)`,
//! `M7a ipv4 tcp OK (bytes=14)`, `M7a ipv6 udp OK (bytes=7)`,
//! `M7a ipv6 tcp OK (bytes=14)`, `M7a sockets OK (live=0)` and
//! `M7a OK (suites=4)` — still before the deliberate M2 page fault. The byte
//! counts and the zero live-socket count are parsed and must match exactly, so a
//! line whose payload does not prove the round trip is not acceptance.
//!
//! M7b is the native socket layer on top of that loopback stack: the `net`
//! program (`caelum-net`, a fifth boot module) and a `process_create`d child
//! exercise UDP/TCP over IPv4 and IPv6, `socketpair`, AF_UNIX stream and
//! datagram sockets with a pathname address, `WAIT` on multiple objects,
//! bounded-queue backpressure (`ERR_WOULD_BLOCK`), `shutdown` EOF, handle-rights
//! rejection and the negative socket faults. Each boot prints fourteen more
//! markers: `[CaelumNet] M7b <suite> OK (<exact payload>)` for the twelve suites,
//! the program's own `[CaelumNet] M7b OK (child=0)` and the kernel's
//! `[CaelumKernel] M7b OK (sockets=0, bindings=0)`; both prefixes are required
//! verbatim and every payload value is checked exactly, still before the
//! deliberate M2 page fault.
//!
//! M7d is the Linux64 personality slice: the `linux` program
//! (`caelum-linux-net`, the sixth boot module) enters through the Linux
//! personality and runs UDP/TCP/UNIX sockets, file descriptors and error
//! mapping. Each boot prints eight more markers: the seven plain
//! `[CaelumLinux] M7d ... OK` lines and the kernel's
//! `[CaelumKernel] M7d OK (sockets=0, bindings=0)` verdict. The user lines are
//! matched as exact text (no payload is appended); the verdict's zero
//! sockets/bindings accounting is parsed and must match exactly. Like every
//! other stage it sits before the deliberate M2 page fault.
//!
//! M8a extends the Linux64 personality slice with the memory and file
//! subsystems. The same `linux` program prints two more plain user-mode lines,
//! `[CaelumLinux] M8a memory OK` and `[CaelumLinux] M8a files OK`, after its
//! `[CaelumLinux] M7d OK` line and before the kernel M7d verdict. There is no new
//! kernel verdict; the M7d verdict still closes the boot, and the two lines carry
//! no payload. Each boot therefore requires 112 markers instead of 110. M8b adds
//! two more plain lines in the same user block — `[CaelumLinux] M8b time OK` and
//! `[CaelumLinux] M8b info OK`, immediately after the M8a pair — so each boot now
//! requires 114 markers. M8c adds one more plain line in that block,
//! `[CaelumLinux] M8c signals OK`, right after the M8b pair; M8d adds
//! `[CaelumLinux] M8d process OK`, printed once by the parent user process after
//! the M8c line (the child never prints it), M8e adds
//! `[CaelumLinux] M8e files OK` right after M8d, and M8f adds
//! `[CaelumLinux] M8f futex OK` plus `[CaelumLinux] M8f tls OK` right after M8e.
//! M8g adds `[CaelumLinux] M8g eventfd OK` and `[CaelumLinux] M8g poll OK` right
//! after the M8f pair, and M8h adds `[CaelumLinux] M8h procfs OK` plus
//! `[CaelumLinux] M8h devfs OK` right after the M8g pair. M9a adds
//! `[CaelumLinux] M9a timerfd OK`, `[CaelumLinux] M9a signalfd OK` and
//! `[CaelumLinux] M9a epoll OK`, and M9b adds `[CaelumLinux] M9b abstract OK`,
//! `[CaelumLinux] M9b rights OK`, `[CaelumLinux] M9b credentials OK` and
//! `[CaelumLinux] M9b epoll-et OK`. M9c adds one more plain user line,
//! `[CaelumLinux] M9c locks OK`, after the M9b pair (same Linux ELF, role 2 lock
//! peer, and the VFS POSIX/OFD/flock lock domains). M9d1 adds the two dynamic-ELF
//! lines `[CaelumDyn] interp OK` and `[CaelumLinux] M9d dynamic OK`: the harness
//! injects `/fat/dyn-main` and its interpreter `/fat/ldcaelum.so` into the FAT
//! test disk before boot, so the two lines prove the guest parsed and ran the
//! injected ELF pair; the host re-reads both files from the FAT image after
//! every boot, so a stale, half-written or locally corrupted copy fails. M9d2
//! adds `[CaelumLinux] M9d vdso OK` for the third injected image, `/fat/vdso.so`,
//! which the host checks byte for byte the same way. M9e adds
//! `[CaelumLinux] M9e shared OK`: the dynamic main is linked against a fourth
//! injected image, the shared library `/fat/m9e.so`, so the line proves the
//! `DT_NEEDED` dependency actually resolved through the custom interpreter. M9f
//! adds `[CaelumLinux] M9f shared OK` for two more injected shared libraries,
//! `/fat/m9f-a.so` and `/fat/m9f-b.so` (B is the `DT_NEEDED` of A), so the line
//! proves a two-step dependency chain resolved through the same interpreter. M10a
//! adds `[CaelumLinux] M10a hello OK`, printed by a *genuine* musl `busybox`
//! injected into the ext2 volume (`/bin/busybox` plus
//! `/lib/ld-musl-x86_64.so.1` and `/lib/libc.musl-x86_64.so.1`); the harness
//! verifies those samples against `tools/m10a/SHA256SUMS` on every build and
//! re-checks the ext2 image byte for byte after each boot, so the line proves a
//! real dynamically linked Linux program ran. M7c-1a adds
//! `[CaelumKernel] M7c nic OK (mac=52:54:00:12:34:56, link=up)`: QEMU attaches
//! a legacy virtio-net device on its `user` backend and the kernel's NIC probe
//! reads back the MAC and link state, so the line proves the device path works
//! end to end. The earlier lines all precede the reused M7d kernel verdict and
//! the NIC probe line is the only required line after it, so the deliberate page
//! fault still stays last. Each boot therefore requires 138 markers.
//!
//! All of this is `std`-only: no crates are added for sockets, QMP, PPM parsing
//! or timing.

mod disks;
mod fat;
mod initramfs;
mod m10a;

use std::env;
use std::fs::File;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const UEFI_TARGET: &str = "x86_64-unknown-uefi";
const NONE_TARGET: &str = "x86_64-unknown-none";

/// M4 user programs, plus the M6b2 worker. All are separate
/// `x86_64-unknown-none` ELF binaries that `xtask image` packs into the
/// initramfs container (see `initramfs.rs`).
const INIT_PKG: &str = "caelum-init";
const CHILD_PKG: &str = "caelum-child";
/// M6b2: a user-mode workload deliberately scheduled onto an application
/// processor. The kernel spawns it; `xtask` only packs it, so a missing
/// `worker` module must fail the image build rather than look green.
const WORKER_PKG: &str = "caelum-worker";
/// M6c: the user-mode display/input program (`gfx` boot module). It draws into
/// the shadow framebuffer and reports the real input events it received; a
/// missing `gfx` module must fail the image build rather than look green.
const GFX_PKG: &str = "caelum-gfx";
/// M7b: the user-mode native socket suite (`net` boot module). It exercises the
/// socket objects on top of the kernel loopback stack; a missing `net` module
/// must fail the image build rather than look green.
const NET_PKG: &str = "caelum-net";
/// M7d: the user-mode Linux64 personality self-test (`linux` boot module). It
/// drives the same socket objects through the Linux personality layer and
/// reports the seven M7d markers; a missing `linux` module must fail the image
/// build rather than look green.
const LINUX_PKG: &str = "caelum-linux-net";
/// M9d1: the dynamic ELF main program (`ET_DYN`, `PT_INTERP=/fat/ldcaelum.so`).
/// It is injected into the FAT test volume, not packed into the initramfs, and
/// only its `release` artifact is accepted.
const LINUX_DYN_PKG: &str = "caelum-linux-dyn";
/// M9d1: the interpreter named by the dynamic main. It is a plain `ET_EXEC`
/// release binary whose *bytes* are injected as `/fat/ldcaelum.so`.
const INTERP_PKG: &str = "caelum-interp";
/// M9d2: the vDSO image handed to the dynamic process. Like the other two M9d
/// artifacts it is injected into the FAT test volume (as `/fat/vdso.so`) and
/// only its `release` artifact is accepted; a missing image must fail the image
/// build rather than look green.
const VDSO_PKG: &str = "caelum-vdso";
/// M9e: the shared library the dynamic main links with a real `DT_NEEDED`.
/// It is built in release with the position-independent relocation model and
/// linked through the custom interpreter, so a line saying it loaded proves a
/// real dependency resolution. Injected as `/fat/m9e.so`.
const M9E_LIB_PKG: &str = "caelum-m9e-lib";
/// M9f: the two shared libraries of the three-library chain. `caelum-m9f-b`
/// is linked into `caelum-m9f-a`, which the dynamic main links next to the M9e
/// library; both are injected as `/fat/m9f-a.so` and `/fat/m9f-b.so`.
const M9F_A_LIB_PKG: &str = "caelum-m9f-a";
const M9F_B_LIB_PKG: &str = "caelum-m9f-b";
/// The marker that must be the *last* one of a successful run: the deliberate
/// M2 page fault only fires after the kernel ran the whole M3 + M4 sequence.
const FINAL_MARKER: &str = "[CaelumKernel] M2 #PF caught";

/// Printed once the kernel stops for good. A halted guest never emits another
/// marker, so a boot that halts with markers still missing must fail
/// immediately instead of idling until the acceptance timeout.
const HALT_MARKER: &str = "[CaelumKernel] halting";

/// M1/M2 regression markers: every acceptance run must still produce them.
const M12_MARKERS: &[&str] = &[
    "[CaelumLoader] ExitBootServices OK",
    "[CaelumKernel] bootinfo validate OK",
    "[CaelumKernel] gdt/tss/idt OK",
    "[CaelumKernel] pmm selftest OK",
    "[CaelumKernel] heap selftest OK",
    "[CaelumKernel] vm takeover OK",
    "[CaelumKernel] M2 OK",
    FINAL_MARKER,
];

/// M3 markers. `M3 input ready` is the injection trigger; the two input
/// acknowledgements must be produced by the guest *after* injection, so they
/// prove the keyboard and serial RX paths actually work.
const M3_MARKERS: &[&str] = &[
    "[CaelumKernel] M3 clock OK",
    "[CaelumKernel] M3 apic OK",
    "[CaelumKernel] M3 timer OK",
    "[CaelumKernel] M3 input ready",
    "[CaelumKernel] M3 input OK",
    "[CaelumKernel] M3 serial OK",
    "[CaelumKernel] M3 stacks OK",
    "[CaelumKernel] M3 sched OK",
    "[CaelumKernel] M3 OK",
];

const M3_INPUT_READY: &str = "[CaelumKernel] M3 input ready";
const M3_INPUT_OK: &str = "[CaelumKernel] M3 input OK";
const M3_SERIAL_OK: &str = "[CaelumKernel] M3 serial OK";
const M3_INPUT_ACK: &[&str] = &[M3_INPUT_OK, M3_SERIAL_OK];

/// M4 markers: objects/handles/syscalls (kernel), the two user programs and
/// the kernel's exit + milestone closure. M4 needs no extra input; these are
/// produced by the guest after it consumed the initramfs container.
const M4_MARKERS: &[&str] = &[
    "[CaelumKernel] M4 objects OK",
    "[CaelumKernel] M4 modules OK",
    "[CaelumInit] M4 init OK",
    "[CaelumInit] M4 spawn OK",
    "[CaelumChild] M4 child OK",
    "[CaelumChild] M4 handles OK",
    "[CaelumInit] M4 wait OK",
    "[CaelumInit] M4 rng OK",
    "[CaelumKernel] M4 exit OK",
    "[CaelumKernel] M4 OK",
];

/// M5a markers: the in-kernel VFS skeleton (VNode/page cache/ramfs), the three
/// lock domains, directory-change notification and the M4 boot-module reads
/// migrated onto VNode + page cache. M5a needs no input and no new device; the
/// markers are printed by the kernel self-tests after the M4 user programs have
/// exited. They are declared in the order the kernel emits them.
const M5A_MARKERS: &[&str] = &[
    "[CaelumKernel] M5a vfs OK",
    "[CaelumKernel] M5a pagecache OK",
    "[CaelumKernel] M5a ramfs OK",
    "[CaelumKernel] M5a locks OK",
    "[CaelumKernel] M5a notify OK",
    "[CaelumKernel] M5a bootmod via vfs OK",
];

/// M5b markers both boots must print: MCFG parsing, PCI enumeration, the two
/// legacy virtio-blk disks, block reads from both, and both filesystems mounted
/// through the VFS.
const M5B_BASE_MARKERS: &[&str] = &[
    "[CaelumKernel] M5b mcfg OK",
    "[CaelumKernel] M5b pci OK",
    "[CaelumKernel] M5b virtio OK",
    "[CaelumKernel] M5b block OK",
    "[CaelumKernel] M5b fat32 OK",
    "[CaelumKernel] M5b ext2 OK",
];

/// Extra markers only the first boot prints: it seeds both volumes.
const M5B_FIRST_MARKERS: &[&str] = &[
    "[CaelumKernel] M5b persistence written",
    "[CaelumKernel] M5b first boot OK",
];

/// Extra markers only the second boot prints: it verifies what survived the
/// reboot, appends 1024 bytes, renames the data file and truncates it.
const M5B_SECOND_MARKERS: &[&str] = &["[CaelumKernel] M5b persistence OK", "[CaelumKernel] M5b OK"];

/// M5c1 markers every boot must print. The placement rules are enforced by
/// [`marker_placement_error`]: the mounts are announced before the kernel spawns
/// `init`, both user programs report their file round trips before `init` exits,
/// and `M5c1 OK` closes the M5b persistence work on both boots (still before the
/// deliberate M2 page fault).
const M5C1_MOUNTS_READY: &str = "[CaelumKernel] M5c mounts ready";
const M5C1_INIT_FILES: &str = "[CaelumInit] M5c files OK";
const M5C1_CHILD_FILES: &str = "[CaelumChild] M5c files OK";
const M5C1_OK: &str = "[CaelumKernel] M5c1 OK";

const M5C1_MARKERS: &[&str] = &[
    M5C1_MOUNTS_READY,
    M5C1_INIT_FILES,
    M5C1_CHILD_FILES,
    M5C1_OK,
];

/// M5c2 markers every boot must print. Placement rules are enforced by
/// [`marker_placement_error`]: both user programs report their mmap round trips
/// after their file markers and before `init` exits, and `M5c2 OK` follows the
/// M5c1 verdict while still preceding the deliberate M2 page fault.
const M5C2_INIT_MMAP: &str = "[CaelumInit] M5c mmap OK";
const M5C2_CHILD_MMAP: &str = "[CaelumChild] M5c mmap OK";
const M5C2_OK: &str = "[CaelumKernel] M5c2 OK";

const M5C2_MARKERS: &[&str] = &[M5C2_INIT_MMAP, M5C2_CHILD_MMAP, M5C2_OK];

/// M5c3 markers every boot must print. Placement rules are enforced by
/// [`marker_placement_error`]: `init` exercises xattr, sparse files and watches
/// after its mmap round trip and before `init` exits; the child checks locks
/// after its own mmap; `init` checks locks after it waits for the child; and the
/// kernel reports the fault-injection verdict after the M5c2 verdict, with
/// `M5 OK` closing the stage right before the deliberate M2 page fault.
const M5C3_INIT_XATTR: &str = "[CaelumInit] M5c xattr OK";
const M5C3_INIT_SPARSE: &str = "[CaelumInit] M5c sparse OK";
const M5C3_INIT_WATCH: &str = "[CaelumInit] M5c watch OK";
const M5C3_CHILD_LOCKS: &str = "[CaelumChild] M5c locks OK";
const M5C3_INIT_LOCKS: &str = "[CaelumInit] M5c locks OK";
const M5C3_FAULTS_OK: &str = "[CaelumKernel] M5c3 faults OK";
const M5C3_OK: &str = "[CaelumKernel] M5c3 OK";
const M5_OK: &str = "[CaelumKernel] M5 OK";

const M5C3_MARKERS: &[&str] = &[
    M5C3_INIT_XATTR,
    M5C3_INIT_SPARSE,
    M5C3_INIT_WATCH,
    M5C3_CHILD_LOCKS,
    M5C3_INIT_LOCKS,
    M5C3_FAULTS_OK,
    M5C3_OK,
    M5_OK,
];

/// M6a1 markers every boot must print. M6a1 is a first slice of M6, not M6:
/// it covers only the monotonic timer and user-visible Event objects, so no
/// `M6 OK`, SMP or IPC-channel marker may be required here. Placement rules are
/// enforced by [`marker_placement_error`]: `init` and the child report their
/// timer/Event round trips before `init` exits, and `M6a OK` closes the stage
/// after `M5 OK`, still before the deliberate M2 page fault.
const M6A_INIT_TIMER: &str = "[CaelumInit] M6a timer OK";
const M6A_INIT_EVENT: &str = "[CaelumInit] M6a event OK";
const M6A_CHILD_EVENT: &str = "[CaelumChild] M6a event OK";
const M6A_OK: &str = "[CaelumKernel] M6a OK";

const M6A_MARKERS: &[&str] = &[M6A_INIT_TIMER, M6A_INIT_EVENT, M6A_CHILD_EVENT, M6A_OK];

/// M6a2 markers every boot must print. M6a2 is the second M6 slice, still not
/// M6: it adds the remaining M6 IPC objects (Channel, Port, SharedMemory,
/// EventSubscription, Futex) on top of M6a1, so no `M6 OK`, SMP or display
/// marker may be required. The nine user-space markers only have to appear
/// before `init` exits; they are deliberately NOT ordered against each other so
/// the kernel and user programs stay free to run the round trips in any order.
/// `M6a2 OK` is the stage verdict: after `M6a OK`, still before the deliberate
/// M2 page fault.
const M6A2_INIT_CHANNEL: &str = "[CaelumInit] M6a channel OK";
const M6A2_CHILD_CHANNEL: &str = "[CaelumChild] M6a channel OK";
const M6A2_INIT_PORT: &str = "[CaelumInit] M6a port OK";
const M6A2_CHILD_PORT: &str = "[CaelumChild] M6a port OK";
const M6A2_INIT_SHM: &str = "[CaelumInit] M6a shm OK";
const M6A2_CHILD_SHM: &str = "[CaelumChild] M6a shm OK";
const M6A2_INIT_FUTEX: &str = "[CaelumInit] M6a futex OK";
const M6A2_CHILD_FUTEX: &str = "[CaelumChild] M6a futex OK";
const M6A2_INIT_SUBSCRIPTION: &str = "[CaelumInit] M6a subscription OK";
const M6A2_OK: &str = "[CaelumKernel] M6a2 OK";

/// The nine M6a2 user-space markers. They share one placement rule (before
/// `init` exits) and are intentionally unordered among themselves. Production
/// code only requires the full [`M6A2_MARKERS`] set, so this slice exists for
/// the tests that pin the user-space half of the contract.
#[cfg(test)]
const M6A2_USER_MARKERS: &[&str] = &[
    M6A2_INIT_CHANNEL,
    M6A2_CHILD_CHANNEL,
    M6A2_INIT_PORT,
    M6A2_CHILD_PORT,
    M6A2_INIT_SHM,
    M6A2_CHILD_SHM,
    M6A2_INIT_FUTEX,
    M6A2_CHILD_FUTEX,
    M6A2_INIT_SUBSCRIPTION,
];

const M6A2_MARKERS: &[&str] = &[
    M6A2_INIT_CHANNEL,
    M6A2_CHILD_CHANNEL,
    M6A2_INIT_PORT,
    M6A2_CHILD_PORT,
    M6A2_INIT_SHM,
    M6A2_CHILD_SHM,
    M6A2_INIT_FUTEX,
    M6A2_CHILD_FUTEX,
    M6A2_INIT_SUBSCRIPTION,
    M6A2_OK,
];

/// M6b1: the kernel started the three application processors, so the `-smp 4`
/// machine really has all four CPUs online. This proves AP startup only: it
/// deliberately adds no `M6b OK`, scheduler or IPI verdict and must not be read
/// as "full SMP done". The marker is emitted right after the M3 stage (early in
/// boot), so its position is enforced by `marker_placement_error`.
const M6B1_ONLINE: &str = "[CaelumKernel] M6b1 online=4";
const M6B1_MARKERS: &[&str] = &[M6B1_ONLINE];

/// M6b2a: the kernel proved that the per-CPU state it needs for cross-CPU
/// locking is really usable on every online CPU. Like M6b1 this is a narrow
/// statement: it adds no `M6b OK`/`M6b2 OK`, no AP scheduling and no IPI
/// verdict, and it must not be read as "full SMP done". It is emitted right
/// after the AP-online marker, so its position is enforced by
/// `marker_placement_error`.
const M6B2A_LOCKS: &str = "[CaelumKernel] M6b2a locks OK";
const M6B2A_MARKERS: &[&str] = &[M6B2A_LOCKS];

/// M6b2: the direct scheduling evidence, all emitted by the boot processor
/// after the M6a2 closeout and before the deliberate M2 page fault. Every line
/// carries the counters behind it and is only printed once those counters
/// reached their frozen minimums, so a missing line means the capability never
/// happened. The payloads are parsed by [`m6b2_stats_error`]; printing the text
/// is not enough.
const M6B2_AP_USER: &str = "[CaelumKernel] M6b2 ap user OK";
const M6B2_AP_PREEMPT: &str = "[CaelumKernel] M6b2 ap preempt OK";
const M6B2_WAKE_IPI: &str = "[CaelumKernel] M6b2 wake ipi OK";
const M6B2_MIGRATE: &str = "[CaelumKernel] M6b2 migrate OK";
const M6B2_OK: &str = "[CaelumKernel] M6b2 OK";

const M6B2_MARKERS: &[&str] = &[
    M6B2_AP_USER,
    M6B2_AP_PREEMPT,
    M6B2_WAKE_IPI,
    M6B2_MIGRATE,
    M6B2_OK,
];

/// M6c: display probe, the user-mode `gfx` program's display/input round trips
/// and the kernel's closing verdict. The kernel-side probe and the gfx input
/// line may carry a trailing `(...)` payload (e.g. `(width=640, height=480)`);
/// acceptance matches these markers as substrings and compares their order by
/// last occurrence, so the payload can never swallow or shadow the M6b2
/// statistics lines above.
const M6C_DISPLAY_PROBE: &str = "[CaelumKernel] M6c display probe OK";
const M6C_DISPLAY: &str = "[CaelumGfx] M6c display OK";
const M6C_INPUT_READY: &str = "[CaelumGfx] M6c input ready";
const M6C_INPUT: &str = "[CaelumGfx] M6c input OK";
const M6C_OK: &str = "[CaelumKernel] M6c OK";

const M6C_MARKERS: &[&str] = &[
    M6C_DISPLAY_PROBE,
    M6C_DISPLAY,
    M6C_INPUT_READY,
    M6C_INPUT,
    M6C_OK,
];

/// M7a: the kernel's loopback self test. These six markers are printed by the
/// boot processor while it drives the in-kernel loopback stack (no NIC involved),
/// after the M6c verdict and still before the deliberate M2 page fault. Every
/// line carries the payload that makes it evidence rather than decoration: the
/// UDP payload is exactly 7 bytes, the TCP payload exactly 14 bytes, and the
/// socket count must be back to zero after the four suites (there are no leaked
/// socket objects). The payloads are enforced by [`m7a_stats_error`].
const M7A_IPV4_UDP: &str = "[CaelumKernel] M7a ipv4 udp OK";
const M7A_IPV4_TCP: &str = "[CaelumKernel] M7a ipv4 tcp OK";
const M7A_IPV6_UDP: &str = "[CaelumKernel] M7a ipv6 udp OK";
const M7A_IPV6_TCP: &str = "[CaelumKernel] M7a ipv6 tcp OK";
const M7A_SOCKETS: &str = "[CaelumKernel] M7a sockets OK";
const M7A_OK: &str = "[CaelumKernel] M7a OK";

const M7A_MARKERS: &[&str] = &[
    M7A_IPV4_UDP,
    M7A_IPV4_TCP,
    M7A_IPV6_UDP,
    M7A_IPV6_TCP,
    M7A_SOCKETS,
    M7A_OK,
];

/// M7b: the `net` user program (fifth boot module) exercises the native socket
/// objects on top of the M7a loopback stack: IPv4/IPv6 UDP and TCP, socketpair,
/// pathname UNIX stream/datagram sockets, wait with timeouts, backpressure,
/// shutdown, handle-rights rejection and input faults. Every line carries the
/// exact evidence in its payload (byte counts, pair counts, would-block count and
/// handshake results); the two `M7b OK` verdicts close the user and kernel sides
/// respectively. All fourteen lines are emitted in the frozen order below, after
/// the M7a verdict and still before the deliberate M2 page fault. The payloads
/// are enforced by [`m7b_stats_error`].
const M7B_UDP4: &str = "[CaelumNet] M7b udp4 OK";
const M7B_UDP6: &str = "[CaelumNet] M7b udp6 OK";
const M7B_TCP4: &str = "[CaelumNet] M7b tcp4 OK";
const M7B_TCP6: &str = "[CaelumNet] M7b tcp6 OK";
const M7B_SOCKETPAIR: &str = "[CaelumNet] M7b socketpair OK";
const M7B_UNIX_STREAM: &str = "[CaelumNet] M7b unix stream OK";
const M7B_UNIX_DGRAM: &str = "[CaelumNet] M7b unix dgram OK";
const M7B_WAIT: &str = "[CaelumNet] M7b wait OK";
const M7B_BACKPRESSURE: &str = "[CaelumNet] M7b backpressure OK";
const M7B_SHUTDOWN: &str = "[CaelumNet] M7b shutdown OK";
const M7B_RIGHTS: &str = "[CaelumNet] M7b rights OK";
const M7B_FAULTS: &str = "[CaelumNet] M7b faults OK";
const M7B_USER_OK: &str = "[CaelumNet] M7b OK";
const M7B_KERNEL_OK: &str = "[CaelumKernel] M7b OK";

const M7B_MARKERS: &[&str] = &[
    M7B_UDP4,
    M7B_UDP6,
    M7B_TCP4,
    M7B_TCP6,
    M7B_SOCKETPAIR,
    M7B_UNIX_STREAM,
    M7B_UNIX_DGRAM,
    M7B_WAIT,
    M7B_BACKPRESSURE,
    M7B_SHUTDOWN,
    M7B_RIGHTS,
    M7B_FAULTS,
    M7B_USER_OK,
    M7B_KERNEL_OK,
];

/// M7d: the Linux64 personality self-test (`linux` boot module, sixth module).
/// Its seven user-mode lines are plain text without payloads; the kernel
/// verdict closes the stage with the exact `sockets=0, bindings=0` accounting,
/// which [`m7d_stats_error`] enforces. The block follows the M7b verdict and
/// still precedes the deliberate M2 page fault.
const M7D_STARTUP: &str = "[CaelumLinux] M7d startup OK";
const M7D_UDP: &str = "[CaelumLinux] M7d udp OK";
const M7D_TCP: &str = "[CaelumLinux] M7d tcp OK";
const M7D_UNIX: &str = "[CaelumLinux] M7d unix OK";
const M7D_FD: &str = "[CaelumLinux] M7d fd OK";
const M7D_ERRORS: &str = "[CaelumLinux] M7d errors OK";
const M7D_USER_OK: &str = "[CaelumLinux] M7d OK";
const M7D_KERNEL_OK: &str = "[CaelumKernel] M7d OK";

const M7D_MARKERS: &[&str] = &[
    M7D_STARTUP,
    M7D_UDP,
    M7D_TCP,
    M7D_UNIX,
    M7D_FD,
    M7D_ERRORS,
    M7D_USER_OK,
    M7D_KERNEL_OK,
];

/// M8a: the Linux64 personality's memory and file slices. The `linux` program
/// prints these two plain-text lines after its `[CaelumLinux] M7d OK` line and
/// before the kernel's M7d verdict; there is no new kernel verdict, so the M7d
/// verdict still closes the boot. Neither line carries a payload.
const M8A_MEMORY: &str = "[CaelumLinux] M8a memory OK";
const M8A_FILES: &str = "[CaelumLinux] M8a files OK";

const M8A_MARKERS: &[&str] = &[M8A_MEMORY, M8A_FILES];

/// M8b: the Linux64 personality's time and system-information slices. These two
/// plain-text lines follow the M8a lines and still precede the kernel's M7d
/// verdict, so the M7d verdict remains the last kernel marker of the boot.
/// Neither line carries a payload and M8b adds no kernel marker.
const M8B_TIME: &str = "[CaelumLinux] M8b time OK";
const M8B_INFO: &str = "[CaelumLinux] M8b info OK";

const M8B_MARKERS: &[&str] = &[M8B_TIME, M8B_INFO];

/// M8c: the Linux64 personality's signal slice. This plain-text line follows the
/// M8b lines and still precedes the kernel's M7d verdict, which remains the last
/// kernel marker of the boot. The line carries no payload and M8c adds no kernel
/// marker of its own.
const M8C_SIGNALS: &str = "[CaelumLinux] M8c signals OK";

const M8C_MARKERS: &[&str] = &[M8C_SIGNALS];

/// M8d: the Linux64 personality's process slice. The parent user process prints
/// this plain-text line once (the child never prints it), after the M8c signal
/// line and still before the kernel's M7d verdict, which remains the last kernel
/// marker of the boot. The line carries no payload and M8d adds no kernel marker.
const M8D_PROCESS: &str = "[CaelumLinux] M8d process OK";

const M8D_MARKERS: &[&str] = &[M8D_PROCESS];

/// M8e: the Linux64 personality's next file-semantics slice. The parent user
/// process prints this plain-text line once, after the M8d process line and still
/// before the kernel's M7d verdict, which remains the last kernel marker of the
/// boot. The line carries no payload and M8e adds no kernel marker.
const M8E_FILES: &str = "[CaelumLinux] M8e files OK";

const M8E_MARKERS: &[&str] = &[M8E_FILES];

/// M8f: the Linux64 personality's futex and TLS slices. The same user program
/// prints these two plain-text lines once, after the M8e files line and still
/// before the kernel's M7d verdict, which remains the last kernel marker of the
/// boot. Neither line carries a payload and M8f adds no kernel marker.
const M8F_FUTEX: &str = "[CaelumLinux] M8f futex OK";

const M8F_TLS: &str = "[CaelumLinux] M8f tls OK";

const M8F_MARKERS: &[&str] = &[M8F_FUTEX, M8F_TLS];

/// M8g: eventfd and poll/ppoll contract (`[CaelumLinux]`, plain lines, parent
/// only).
const M8G_EVENTFD: &str = "[CaelumLinux] M8g eventfd OK";
const M8G_POLL: &str = "[CaelumLinux] M8g poll OK";
const M8G_MARKERS: &[&str] = &[M8G_EVENTFD, M8G_POLL];

/// M8h: procfs/devfs view contract (`[CaelumLinux]`, plain lines, parent
/// only).
const M8H_PROCFS: &str = "[CaelumLinux] M8h procfs OK";
const M8H_DEVFS: &str = "[CaelumLinux] M8h devfs OK";
const M8H_MARKERS: &[&str] = &[M8H_PROCFS, M8H_DEVFS];

/// M9a: the first Linux user-space extension slice (`[CaelumLinux]`, plain
/// lines, parent only). The kernel verdict for this boot is still the M7d one;
/// M9a adds no kernel-side marker of its own.
const M9A_TIMERFD: &str = "[CaelumLinux] M9a timerfd OK";
const M9A_SIGNALFD: &str = "[CaelumLinux] M9a signalfd OK";
const M9A_EPOLL: &str = "[CaelumLinux] M9a epoll OK";
const M9A_MARKERS: &[&str] = &[M9A_TIMERFD, M9A_SIGNALFD, M9A_EPOLL];

/// M9b: the second Linux user-space extension slice (`[CaelumLinux]`, plain
/// lines, parent only). Abstract-namespace sockets, `SCM_RIGHTS`/
/// `SCM_CREDENTIALS` fd passing and edge-triggered epoll; the kernel verdict
/// for this boot is still the M7d one and adds no marker of its own.
const M9B_ABSTRACT: &str = "[CaelumLinux] M9b abstract OK";
const M9B_RIGHTS: &str = "[CaelumLinux] M9b rights OK";
const M9B_CREDENTIALS: &str = "[CaelumLinux] M9b credentials OK";
const M9B_EPOLL_ET: &str = "[CaelumLinux] M9b epoll-et OK";
const M9B_MARKERS: &[&str] = &[M9B_ABSTRACT, M9B_RIGHTS, M9B_CREDENTIALS, M9B_EPOLL_ET];

/// M9c: the third Linux user-space extension slice (`[CaelumLinux]`, plain line,
/// parent only). The same Linux ELF drives a role-2 lock peer and exercises the
/// VFS POSIX/OFD/flock lock domains; like M9a/M9b the boot verdict stays the M7d
/// kernel verdict, so M9c adds no kernel-side marker of its own.
const M9C_LOCKS: &str = "[CaelumLinux] M9c locks OK";
const M9C_MARKERS: &[&str] = &[M9C_LOCKS];

/// M9d1: the dynamic-ELF slice. The harness injects `/fat/dyn-main` (ET_DYN) and
/// the interpreter `/fat/ldcaelum.so` named by its `PT_INTERP` into the FAT test
/// disk before boot; the guest then proves it parsed and ran the injected pair.
/// Both lines are plain text (the second is still a `[CaelumLinux]` line); the
/// boot verdict stays the reused M7d kernel verdict.
const M9D_INTERP: &str = "[CaelumDyn] interp OK";
const M9D_DYNAMIC: &str = "[CaelumLinux] M9d dynamic OK";
/// M9d2: the vDSO slice. `/fat/vdso.so` is injected next to the pair; the
/// dynamic program maps it through the Linux personality and reports that the
/// image it got is the one the loader injected. Plain text like the others.
const M9D_VDSO: &str = "[CaelumLinux] M9d vdso OK";
const M9D_MARKERS: &[&str] = &[M9D_INTERP, M9D_DYNAMIC, M9D_VDSO];
/// M9e: the shared-library slice. `/fat/m9e.so` is injected next to the M9d
/// set; the dynamic main loads it through the custom interpreter and reports
/// that its `DT_NEEDED` dependency resolved. Plain text like the M9d lines.
const M9E_SHARED: &str = "[CaelumLinux] M9e shared OK";
const M9E_MARKERS: &[&str] = &[M9E_SHARED];
/// M9f: the three-library slice. `/fat/m9f-a.so` and `/fat/m9f-b.so` are
/// injected next to the M9e library; the dynamic main reports that the
/// two-step `DT_NEEDED` chain resolved through the custom interpreter.
const M9F_SHARED: &str = "[CaelumLinux] M9f shared OK";
const M9F_MARKERS: &[&str] = &[M9F_SHARED];

/// M10a: the real musl `busybox` sample is injected into the ext2 volume as
/// `/bin/busybox` (with `ld-musl-x86_64.so.1` and `libc.musl-x86_64.so.1` under
/// `/lib`), and the guest runs it through the Linux personality. This line is
/// `busybox`'s *own* output, so the marker proves a genuine, dynamically linked
/// Linux program ran rather than a hand-written no_std stub. Plain text: the
/// boot verdict stays the reused M7d kernel verdict.
const M10A_HELLO: &str = "[CaelumLinux] M10a hello OK";
const M10A_MARKERS: &[&str] = &[M10A_HELLO];

/// M7c-1a: a legacy virtio-net NIC on QEMU's `user` backend. The kernel driver
/// requires the transitional 0x1000 device (`disable-modern=on`) and a 3-entry
/// MSI-X table, so the harness pins both and a fixed MAC; the guest proves it
/// read the MAC and link state back from the device. The ARP/UDP echo and the
/// raw-frame host peer belong to later M7c slices, and the reused M7d kernel
/// verdict stays the last required line.
const M7C_NIC: &str = "[CaelumKernel] M7c nic OK (mac=52:54:00:12:34:56, link=up)";
const M7C_MARKERS: &[&str] = &[M7C_NIC];

/// Which boot of the M5b two-boot acceptance run is being driven.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum BootStage {
    /// Fresh volumes; the guest writes the state marker and 8192 data bytes.
    First,
    /// Reboot on the same volumes; the guest verifies, appends, renames,
    /// truncates and syncs.
    Second,
}

impl BootStage {
    fn label(self) -> &'static str {
        match self {
            BootStage::First => "first boot",
            BootStage::Second => "second boot",
        }
    }

    /// Per-boot serial log. The second boot is also copied to
    /// `target/serial.log`, which remains the full transcript of the latest
    /// boot.
    fn log_path(self) -> PathBuf {
        target_dir().join(match self {
            BootStage::First => "serial-boot1.log",
            BootStage::Second => "serial-boot2.log",
        })
    }

    /// Short per-boot suffix used in artifact names (`...-boot1`, `...-boot2`).
    fn log_stem(self) -> &'static str {
        match self {
            BootStage::First => "boot1",
            BootStage::Second => "boot2",
        }
    }
}

/// QMP press/release hold time for both injected keys, in milliseconds.
///
/// QEMU emits the `make` scancode immediately but the `break` only after this
/// long, so any serial bytes written right after the QMP reply would be
/// delivered *between* make and break. The guest expects a strict
/// make -> break -> serial order.
const KEY_HOLD_MS: u64 = 100;

/// QMP request that presses-and-releases the PS/2 key `a`.
const SEND_KEY_A_JSON: &str = "{\"execute\":\"send-key\",\"arguments\":{\"keys\":[{\"type\":\"qcode\",\"data\":\"a\"}],\"hold-time\":100}}";

/// Byte written into the guest UART RX when the guest announces
/// `M3 input ready`. ASCII `C` (0x43).
const SERIAL_INJECT_BYTE: &[u8] = b"C";

/// QMP request that presses-and-releases the PS/2 key `d` (M6c's second
/// injection: the `gfx` program reports the Keyboard 0x20/0xA0 scancodes).
const SEND_KEY_D_JSON: &str = "{\"execute\":\"send-key\",\"arguments\":{\"keys\":[{\"type\":\"qcode\",\"data\":\"d\"}],\"hold-time\":100}}";

/// Bytes written into the guest UART RX when the guest announces
/// `[CaelumGfx] M6c input ready`: the `gfx` program must receive three serial
/// events for `m`, `6` and `c`.
const M6C_SERIAL_BYTES: &[u8] = b"m6c";

/// Wait after the `send_key_d` QMP reply before writing the serial bytes, so
/// the synthesized `break` (emitted `KEY_HOLD_MS` after `make`) is delivered
/// first. The guest asserts the order make -> break -> `m` -> `6` -> `c`.
const M6C_KEY_SETTLE: Duration = Duration::from_millis(150);

// Guard against silent drift: the settle window must outlast the hold time.
const _: () = assert!(M6C_KEY_SETTLE.as_millis() as u64 > KEY_HOLD_MS);

/// The screenshots are taken shortly after `gfx` presented the shadow buffer,
/// so the display state observed by `screendump` is the presented one.
const SCREEN_CAPTURE_DELAY: Duration = Duration::from_millis(300);
/// Per-channel tolerance for the three checked screenshot pixels.
const SCREEN_CHANNEL_TOLERANCE: u8 = 8;
/// A displayed magenta corner, plus `gfx`'s green and blue rectangles.
const SCREEN_CORNER: [u8; 3] = [255, 0, 255];
const SCREEN_GREEN_AT: (usize, usize) = (48, 48);
const SCREEN_GREEN: [u8; 3] = [0, 255, 0];
const SCREEN_BLUE_AT: (usize, usize) = (128, 48);
const SCREEN_BLUE: [u8; 3] = [0, 0, 255];

const BOOT_TIMEOUT: Duration = Duration::from_secs(90);
const INPUT_TIMEOUT: Duration = Duration::from_secs(30);
const TOTAL_TIMEOUT: Duration = Duration::from_secs(150);

/// After a fatal guest error the kernel usually keeps printing the diagnostic
/// (cr2/rip/register dump) on the serial console. Keep reading for at least
/// this long before QEMU is killed, so the log does not end on a half line.
const FATAL_DRAIN_MIN: Duration = Duration::from_millis(250);
/// Give up on the drain after this long even if the guest never stops talking.
const FATAL_DRAIN_MAX: Duration = Duration::from_millis(1000);
/// ...or once the console has been silent for this long (and the minimum
/// window above has already elapsed).
const FATAL_DRAIN_QUIET: Duration = Duration::from_millis(100);

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("xtask lives in the workspace")
        .to_path_buf()
}

fn target_dir() -> PathBuf {
    root().join("target")
}

fn loader_efi() -> PathBuf {
    target_dir()
        .join(UEFI_TARGET)
        .join("debug")
        .join("loader.efi")
}

fn kernel_elf() -> PathBuf {
    none_binary("kernel")
}

/// Artifact of an `x86_64-unknown-none` binary crate (a plain ELF file).
fn none_binary(name: &str) -> PathBuf {
    target_dir().join(NONE_TARGET).join("debug").join(name)
}

fn init_elf() -> PathBuf {
    none_binary(INIT_PKG)
}

fn child_elf() -> PathBuf {
    none_binary(CHILD_PKG)
}

fn worker_elf() -> PathBuf {
    none_binary(WORKER_PKG)
}

fn gfx_elf() -> PathBuf {
    none_binary(GFX_PKG)
}

fn net_elf() -> PathBuf {
    none_binary(NET_PKG)
}

fn linux_elf() -> PathBuf {
    none_binary(LINUX_PKG)
}

/// Artifact of a *release* `x86_64-unknown-none` binary (M9d1: the dynamic ELF
/// main and its interpreter are injected from the release profile).
fn release_binary(name: &str) -> PathBuf {
    target_dir().join(NONE_TARGET).join("release").join(name)
}

fn linux_dyn_elf() -> PathBuf {
    release_binary(LINUX_DYN_PKG)
}

fn interp_elf() -> PathBuf {
    release_binary(INTERP_PKG)
}

/// M9d2: the vDSO image injected as `/fat/vdso.so`.
fn vdso_elf() -> PathBuf {
    release_binary(VDSO_PKG)
}

/// M9e: the shared library injected as `/fat/m9e.so` and passed to the
/// dynamic main through `CAELUM_M9E_LIB` when it is linked.
fn m9e_lib_elf() -> PathBuf {
    release_binary(M9E_LIB_PKG)
}

/// M9f: the `caelum-m9f-a` shared library, injected as `/fat/m9f-a.so` and
/// linked by the dynamic main through `CAELUM_M9F_A_LIB`.
fn m9f_a_lib_elf() -> PathBuf {
    release_binary(M9F_A_LIB_PKG)
}

/// M9f: the `caelum-m9f-b` shared library, injected as `/fat/m9f-b.so` and
/// linked into `caelum-m9f-a` through `CAELUM_M9F_B_LIB`.
fn m9f_b_lib_elf() -> PathBuf {
    release_binary(M9F_B_LIB_PKG)
}

/// `screendump` target of one boot of the M6c acceptance run.
fn screen_path(stage: BootStage) -> PathBuf {
    target_dir().join(format!("m6c-screen-{}.ppm", stage.log_stem()))
}

/// Host-side copy of the packed `CAELUMFS` container.
fn initramfs_img() -> PathBuf {
    target_dir().join(initramfs::IMG_NAME)
}

fn esp_image() -> PathBuf {
    target_dir().join(fat::ESP_IMG_NAME)
}

/// `target/serial.log` keeps the full transcript of the latest boot of the run
/// (the second boot during an M5b acceptance run).
fn serial_log() -> PathBuf {
    target_dir().join("serial.log")
}

/// The M1—M5a regression markers: every boot of the M5b run must still print
/// all of them.
fn base_markers() -> Vec<&'static str> {
    M12_MARKERS
        .iter()
        .chain(M3_MARKERS.iter())
        .chain(M4_MARKERS.iter())
        .chain(M5A_MARKERS.iter())
        .copied()
        .collect()
}

/// Markers only one boot of the M5b run prints.
fn stage_markers(stage: BootStage) -> &'static [&'static str] {
    match stage {
        BootStage::First => M5B_FIRST_MARKERS,
        BootStage::Second => M5B_SECOND_MARKERS,
    }
}

/// All markers one boot must print, in the order the guest emits them.
fn required_markers(stage: BootStage) -> Vec<&'static str> {
    let mut markers = base_markers();
    // M6b1 emits its AP-online marker right after the M3 stage, inside the
    // regression block, so it is listed here rather than at the end: the M6a2
    // verdict stays the last entry of the required list.
    markers.extend(M6B1_MARKERS);
    // M6b2a checks the per-CPU locking state on every online CPU right after the
    // AP-online line, so it also belongs to the early regression block.
    markers.extend(M6B2A_MARKERS);
    markers.extend(M5B_BASE_MARKERS);
    markers.extend(stage_markers(stage));
    // M5c1's verdict follows the M5b persistence work; M5c2, M5c3, `M5 OK` and
    // the M6a1/M6a2 verdicts follow it. `M5c mounts ready` and the user-space
    // M5c1/M5c3/M6a1/M6a2 markers are emitted earlier during boot, so their
    // placement is enforced by `marker_placement_error` rather than by list
    // position.
    markers.extend(M5C1_MARKERS);
    markers.extend(M5C2_MARKERS);
    markers.extend(M5C3_MARKERS);
    // M6a1 closes the boot: the timer/Event round trips happen inside the user
    // programs (enforced by `marker_placement_error`), while `M6a OK` is the
    // stage verdict that follows `M5 OK`.
    markers.extend(M6A_MARKERS);
    // M6a2 adds the remaining M6 IPC objects. Its nine user-space markers are
    // emitted by the two user programs before `init` exits (also enforced by
    // `marker_placement_error`), and `M6a2 OK` is the final IPC stage verdict.
    markers.extend(M6A2_MARKERS);
    // M6b2 closes the boot: the five scheduling-evidence lines are printed by
    // the boot processor after the M6a2 closeout, so they are the last required
    // words before the deliberate page fault. Their counters are parsed by
    // `m6b2_stats_error`, not merely matched.
    markers.extend(M6B2_MARKERS);
    // M6c's display probe, the `gfx` display/input round trips and the kernel's
    // M6c verdict follow the M6b2 closeout. The probe and the gfx lines may carry
    // a trailing payload, which is why these are matched as substrings; the
    // `input OK` / `M6c OK` payloads are parsed by `m6c_stats_error`.
    markers.extend(M6C_MARKERS);
    // M7a runs its loopback suites after the M6c closeout. Every line carries the
    // exact byte count (or socket count) that proves the round trip happened, so
    // these payloads are parsed by `m7a_stats_error`, not merely matched.
    markers.extend(M7A_MARKERS);
    // M7b closes the boot with the native socket suites exercised by the `net`
    // user program and the kernel-side accounting verdict. The block follows
    // M7a and its payloads are parsed by `m7b_stats_error`.
    markers.extend(M7B_MARKERS);
    // M7d closes the boot with the Linux64 personality slices (startup, UDP, TCP,
    // UNIX sockets, fd table and error mapping) followed by the kernel-side
    // verdict. The user lines are plain text; only the verdict carries a payload
    // (parsed by `m7d_stats_error`). M8a adds two more plain user lines emitted
    // between `M7d OK` and the kernel verdict, so the M7d user half is appended
    // first, then M8a, then the verdict (still the last required marker). M8b's
    // time/info lines, M8c's signal line and M8d's process line extend the same
    // user block between M8a and the verdict.
    markers.extend(M7D_MARKERS[..M7D_MARKERS.len() - 1].iter().copied());
    markers.extend(M8A_MARKERS);
    markers.extend(M8B_MARKERS);
    markers.extend(M8C_MARKERS);
    markers.extend(M8D_MARKERS);
    markers.extend(M8E_MARKERS);
    markers.extend(M8F_MARKERS);
    markers.extend(M8G_MARKERS);
    markers.extend(M8H_MARKERS);
    markers.extend(M9A_MARKERS);
    markers.extend(M9B_MARKERS);
    // M9c's lock line extends the same user block: the M7d verdict stays the last
    // required marker of the boot.
    markers.extend(M9C_MARKERS);
    markers.extend(M9D_MARKERS);
    // M9e: the shared-library line sits between the M9d2 vDSO line and the
    // reused M7d kernel verdict; the deliberate page fault still comes last.
    markers.extend(M9E_MARKERS);
    // M9f: the three-library line sits between the M9e line and the reused M7d
    // kernel verdict; the deliberate page fault still comes last.
    markers.extend(M9F_MARKERS);
    // M10a: the real busybox sample's own output sits between the M9f line and
    // the reused M7d kernel verdict; the deliberate page fault still comes last.
    markers.extend(M10A_MARKERS);
    // M7c-1a: the NIC probe line sits between the busybox line and the reused
    // M7d kernel verdict; the deliberate page fault still comes last.
    markers.extend(M7C_MARKERS);
    markers.push(M7D_KERNEL_OK);
    markers
}

fn missing_markers(text: &str, stage: BootStage) -> Vec<&'static str> {
    required_markers(stage)
        .into_iter()
        .filter(|m| !text.contains(m))
        .collect()
}

/// Placement rules the generic "deliberate fault is last" check cannot express,
/// because M5c1/M5c2/M5c3/M6a1/M6a2 markers are emitted at several different points of
/// a boot: the early mounts, the two user programs (file, mmap, the M5c3 round
/// trips, then the M6a1 timer/Event round trips), and the M5c1 -> M5c2 -> M5c3 ->
/// M5 -> M6a verdict chain. Returns a diagnostic for the first violated rule.
fn marker_placement_error(text: &str, stage: BootStage) -> Option<String> {
    let before = |earlier: &str, later: &str| -> Option<String> {
        match (text.rfind(earlier), text.rfind(later)) {
            (Some(a), Some(b)) if a < b => None,
            (Some(_), Some(_)) => Some(format!("{earlier:?} must appear before {later:?}")),
            // A missing marker is reported by `missing_markers`, not here.
            _ => None,
        }
    };

    let rules = [
        // M6b1: all four CPUs are online by the end of the M3 stage, and the
        // AP-online line must precede the M4 object/syscall work.
        ("[CaelumKernel] M3 OK", M6B1_ONLINE),
        (M6B1_ONLINE, M6B2A_LOCKS),
        (M6B2A_LOCKS, "[CaelumKernel] M4 objects OK"),
        // The mounts are in place before the kernel spawns the first user
        // process (`init` reports itself through its own M4 marker).
        (M5C1_MOUNTS_READY, "[CaelumInit] M4 init OK"),
        // Both user programs finish their file round trips before `init` exits.
        (M5C1_INIT_FILES, "[CaelumKernel] M4 exit OK"),
        (M5C1_CHILD_FILES, "[CaelumKernel] M4 exit OK"),
        // The M5c1 verdict follows that boot's M5b persistence marker (written
        // on the first boot, OK on the second) and precedes the deliberate M2
        // page fault, like every other required marker.
        (stage_markers(stage)[0], M5C1_OK),
        // Both user programs exercise mmap after their file round trips and
        // before `init` exits, one line each.
        (M5C1_INIT_FILES, M5C2_INIT_MMAP),
        (M5C2_INIT_MMAP, "[CaelumKernel] M4 exit OK"),
        (M5C1_CHILD_FILES, M5C2_CHILD_MMAP),
        (M5C2_CHILD_MMAP, "[CaelumKernel] M4 exit OK"),
        // M5c3: `init` walks xattr -> sparse -> watch after its mmap, still
        // before it exits; the child checks locks after its own mmap; `init`
        // checks locks after it observed the child's exit (wait), so the locks
        // marker belongs after the wait marker but before `init` exits.
        (M5C2_INIT_MMAP, M5C3_INIT_XATTR),
        (M5C3_INIT_XATTR, M5C3_INIT_SPARSE),
        (M5C3_INIT_SPARSE, M5C3_INIT_WATCH),
        (M5C3_INIT_WATCH, "[CaelumKernel] M4 exit OK"),
        (M5C2_CHILD_MMAP, M5C3_CHILD_LOCKS),
        (M5C3_CHILD_LOCKS, "[CaelumKernel] M4 exit OK"),
        ("[CaelumInit] M4 wait OK", M5C3_INIT_LOCKS),
        (M5C3_INIT_LOCKS, "[CaelumKernel] M4 exit OK"),
        // The M5c2/M5c3 verdicts and the M5 stage verdict close the boot in
        // order, all before the deliberate page fault.
        (M5C1_OK, M5C2_OK),
        (M5C2_OK, M5C3_FAULTS_OK),
        (M5C3_FAULTS_OK, M5C3_OK),
        (M5C3_OK, M5_OK),
        // M6a1: both user programs report their timer/Event round trips before
        // `init` exits, and the kernel's M6a verdict closes the stage after
        // `M5 OK`, still before the deliberate page fault.
        (M5C3_INIT_WATCH, M6A_INIT_TIMER),
        (M6A_INIT_TIMER, M6A_INIT_EVENT),
        (M6A_INIT_EVENT, "[CaelumKernel] M4 exit OK"),
        (M5C3_CHILD_LOCKS, M6A_CHILD_EVENT),
        (M6A_CHILD_EVENT, "[CaelumKernel] M4 exit OK"),
        (M5_OK, M6A_OK),
        // M6a2: the nine user-space IPC markers belong to the user programs'
        // own round trips, so each must precede `init`'s exit. They are
        // deliberately unordered among themselves (the kernel and user
        // programs may exercise Channel/Port/SharedMemory/Futex/EventSubscription
        // in any order); only uniqueness and the "before exit" rule are
        // enforced. `M6a2 OK` is the stage verdict after `M6a OK`, still before
        // the deliberate page fault.
        (M6A2_INIT_CHANNEL, "[CaelumKernel] M4 exit OK"),
        (M6A2_CHILD_CHANNEL, "[CaelumKernel] M4 exit OK"),
        (M6A2_INIT_PORT, "[CaelumKernel] M4 exit OK"),
        (M6A2_CHILD_PORT, "[CaelumKernel] M4 exit OK"),
        (M6A2_INIT_SHM, "[CaelumKernel] M4 exit OK"),
        (M6A2_CHILD_SHM, "[CaelumKernel] M4 exit OK"),
        (M6A2_INIT_FUTEX, "[CaelumKernel] M4 exit OK"),
        (M6A2_CHILD_FUTEX, "[CaelumKernel] M4 exit OK"),
        (M6A2_INIT_SUBSCRIPTION, "[CaelumKernel] M4 exit OK"),
        (M6A_OK, M6A2_OK),
        // M6b2: the scheduling evidence is one contiguous block printed by the
        // boot processor after the M6a2 closeout. The four evidence lines are
        // ordered user -> preempt -> wake/ipi -> migration and the verdict
        // summarising them comes last, immediately before the deliberate fault.
        (M6A2_OK, M6B2_AP_USER),
        (M6B2_AP_USER, M6B2_AP_PREEMPT),
        (M6B2_AP_PREEMPT, M6B2_WAKE_IPI),
        (M6B2_WAKE_IPI, M6B2_MIGRATE),
        (M6B2_MIGRATE, M6B2_OK),
        // M6c: the kernel probes the GOP, the `gfx` program presents the framed
        // buffer and reports the second injection, and the kernel closes with its
        // verdict. The whole block follows the M6b2 verdict and still precedes the
        // deliberate page fault. The probe/gfx/verdict lines may carry a trailing
        // payload, which `before` tolerates because it compares last occurrences.
        (M6B2_OK, M6C_DISPLAY_PROBE),
        (M6C_DISPLAY_PROBE, M6C_DISPLAY),
        (M6C_DISPLAY, M6C_INPUT_READY),
        (M6C_INPUT_READY, M6C_INPUT),
        (M6C_INPUT, M6C_OK),
        // M7a: the loopback suites run after the M6c verdict, in a fixed order
        // (IPv4 UDP -> IPv4 TCP -> IPv6 UDP -> IPv6 TCP -> socket accounting ->
        // verdict), and the verdict still precedes the deliberate page fault.
        // Their payloads are enforced separately by `m7a_stats_error`.
        (M6C_OK, M7A_IPV4_UDP),
        (M7A_IPV4_UDP, M7A_IPV4_TCP),
        (M7A_IPV4_TCP, M7A_IPV6_UDP),
        (M7A_IPV6_UDP, M7A_IPV6_TCP),
        (M7A_IPV6_TCP, M7A_SOCKETS),
        (M7A_SOCKETS, M7A_OK),
        // M7b: the `net` program's suites follow the M7a verdict in the frozen
        // order, the user verdict closes the program side, the kernel verdict
        // closes the stage, and the deliberate page fault stays last.
        (M7A_OK, M7B_UDP4),
        (M7B_UDP4, M7B_UDP6),
        (M7B_UDP6, M7B_TCP4),
        (M7B_TCP4, M7B_TCP6),
        (M7B_TCP6, M7B_SOCKETPAIR),
        (M7B_SOCKETPAIR, M7B_UNIX_STREAM),
        (M7B_UNIX_STREAM, M7B_UNIX_DGRAM),
        (M7B_UNIX_DGRAM, M7B_WAIT),
        (M7B_WAIT, M7B_BACKPRESSURE),
        (M7B_BACKPRESSURE, M7B_SHUTDOWN),
        (M7B_SHUTDOWN, M7B_RIGHTS),
        (M7B_RIGHTS, M7B_FAULTS),
        (M7B_FAULTS, M7B_USER_OK),
        (M7B_USER_OK, M7B_KERNEL_OK),
        // M7d: the Linux64 personality self-test runs after the native M7b
        // verdict; its seven user lines are ordered, then the kernel verdict,
        // and the deliberate page fault stays last.
        (M7B_KERNEL_OK, M7D_STARTUP),
        (M7D_STARTUP, M7D_UDP),
        (M7D_UDP, M7D_TCP),
        (M7D_TCP, M7D_UNIX),
        (M7D_UNIX, M7D_FD),
        (M7D_FD, M7D_ERRORS),
        (M7D_ERRORS, M7D_USER_OK),
        // M8a: the two user-mode slice lines sit between the M7d user verdict and
        // the kernel M7d verdict; the deliberate page fault still stays last.
        (M7D_USER_OK, M8A_MEMORY),
        (M8A_MEMORY, M8A_FILES),
        // M8b: the time/info lines extend the same user block, still before the
        // kernel M7d verdict.
        (M8A_FILES, M8B_TIME),
        (M8B_TIME, M8B_INFO),
        // M8c: the signal line follows M8b and still precedes the kernel verdict.
        (M8B_INFO, M8C_SIGNALS),
        // M8d: the process line follows M8c, still before the kernel verdict.
        (M8C_SIGNALS, M8D_PROCESS),
        // M8e: the file-semantics line follows M8d, still before the verdict.
        (M8D_PROCESS, M8E_FILES),
        (M8E_FILES, M8F_FUTEX),
        (M8F_FUTEX, M8F_TLS),
        (M8F_TLS, M8G_EVENTFD),
        (M8G_EVENTFD, M8G_POLL),
        (M8G_POLL, M8H_PROCFS),
        (M8H_PROCFS, M8H_DEVFS),
        // M9a: the timerfd/signalfd/epoll lines extend the user block one last
        // time; the kernel verdict (reused from M7d) and the deliberate page
        // fault still come after them.
        (M8H_DEVFS, M9A_TIMERFD),
        (M9A_TIMERFD, M9A_SIGNALFD),
        (M9A_SIGNALFD, M9A_EPOLL),
        // M9b: abstract, rights, credentials and edge-triggered epoll extend
        // the user block; the kernel verdict (reused from M7d) and the
        // deliberate page fault still come after them.
        (M9A_EPOLL, M9B_ABSTRACT),
        (M9B_ABSTRACT, M9B_RIGHTS),
        (M9B_RIGHTS, M9B_CREDENTIALS),
        (M9B_CREDENTIALS, M9B_EPOLL_ET),
        // M9c: the lock-domain line follows the M9b block; the kernel verdict
        // (reused from M7d) and the deliberate page fault still come after it.
        (M9B_EPOLL_ET, M9C_LOCKS),
        // M9d1: the dynamic-ELF pair follows M9c; the reused M7d kernel verdict
        // and the deliberate page fault still stay after them.
        (M9C_LOCKS, M9D_INTERP),
        (M9D_INTERP, M9D_DYNAMIC),
        (M9D_DYNAMIC, M9D_VDSO),
        // M9e: the shared-library line closes the injected-ELF block.
        (M9D_VDSO, M9E_SHARED),
        // M9f: the three-library line closes the injected-ELF block.
        (M9E_SHARED, M9F_SHARED),
        // M10a: the real busybox line follows the three-library line and still
        // precedes the reused M7d kernel verdict.
        (M9F_SHARED, M10A_HELLO),
        (M10A_HELLO, M7D_KERNEL_OK),
        // M7c-1a: the kernel prints the NIC probe line in the closeout after
        // the reused M7d verdict and still before the deliberate page fault.
        (M7D_KERNEL_OK, M7C_NIC),
        (M7C_NIC, FINAL_MARKER),
    ];
    rules
        .into_iter()
        .find_map(|(earlier, later)| before(earlier, later))
}

/// One M6b2 statistics line: the literal prefix the kernel prints, a label for
/// diagnostics, and the frozen minimum of every field the line must report.
struct M6b2Line {
    marker: &'static str,
    label: &'static str,
    fields: &'static [(&'static str, u64)],
}

/// The four M6b2 evidence lines and their frozen minimums. The counters are
/// collected only during the user-mode phase (enabled after a successful
/// `spawn_init`, disabled when `init` exits), so they really describe user
/// processes, not kernel threads or the boot path:
///
/// - `runs` / `cpus`: user-mode resumes on an AP and the number of distinct APs
///   that executed user code;
/// - `preempts`: AP timer ticks that hit a user frame and really switched it
///   away (not a tick that resumed the same frame);
/// - `remote_wakes` / `ipis`: wakes issued from a different CPU than the
///   target's recorded CPU and the reschedule IPIs actually sent for them;
/// - `migrations` / `balances`: affinity-driven moves and load-balancer moves.
///   They are disjoint events and both must happen — one event may not be
///   counted twice.
const M6B2_EVIDENCE: &[M6b2Line] = &[
    M6b2Line {
        marker: M6B2_AP_USER,
        label: "M6b2 ap user",
        fields: &[("runs", 2), ("cpus", 1)],
    },
    M6b2Line {
        marker: M6B2_AP_PREEMPT,
        label: "M6b2 ap preempt",
        fields: &[("preempts", 2)],
    },
    M6b2Line {
        marker: M6B2_WAKE_IPI,
        label: "M6b2 wake ipi",
        fields: &[("remote_wakes", 1), ("ipis", 1)],
    },
    M6b2Line {
        marker: M6B2_MIGRATE,
        label: "M6b2 migrate",
        fields: &[("migrations", 1), ("balances", 1)],
    },
];

/// The `M6b2 OK` verdict summarises every evidence counter and repeats the
/// minimums, so a truncated or stale verdict line fails too.
const M6B2_VERDICT: M6b2Line = M6b2Line {
    marker: M6B2_OK,
    label: "M6b2 OK",
    fields: &[
        ("runs", 2),
        ("cpus", 1),
        ("preempts", 2),
        ("remote_wakes", 1),
        ("ipis", 1),
        ("migrations", 1),
        ("balances", 1),
    ],
};

/// Parse the `(<key>=<value>, ...)` payload of one M6b2 line.
fn m6b2_payload<'a>(line: &'a str, spec: &M6b2Line) -> Result<Vec<(&'a str, u64)>, String> {
    let rest = line[spec.marker.len()..].trim_end();
    let inner = rest
        .strip_prefix(" (")
        .and_then(|payload| payload.strip_suffix(')'))
        .ok_or_else(|| {
            format!(
                "M6b2 stats: the {:?} line must end with a \"(key=value, ...)\" payload",
                spec.label
            )
        })?;
    let mut fields: Vec<(&'a str, u64)> = Vec::new();
    for pair in inner.split(',') {
        let Some((key, value)) = pair.trim().split_once('=') else {
            return Err(format!(
                "M6b2 stats: the {:?} line has a malformed field {:?}",
                spec.label,
                pair.trim()
            ));
        };
        let key = key.trim();
        let value = value.trim();
        if fields.iter().any(|(seen, _)| *seen == key) {
            return Err(format!(
                "M6b2 stats: the {:?} line repeats the field {key:?}",
                spec.label
            ));
        }
        let value: u64 = value.parse().map_err(|_| {
            format!(
                "M6b2 stats: the {:?} line reports {key}={value:?}, which is not a number",
                spec.label
            )
        })?;
        fields.push((key, value));
    }
    Ok(fields)
}

/// Validate one M6b2 line: exact field set, numeric values, frozen minimums.
fn m6b2_line_fields<'a>(line: &'a str, spec: &M6b2Line) -> Result<Vec<(&'a str, u64)>, String> {
    let fields = m6b2_payload(line, spec)?;
    for (key, minimum) in spec.fields {
        match fields.iter().find(|(seen, _)| seen == key) {
            None => {
                return Err(format!(
                    "M6b2 stats: the {:?} line has no {key:?} field",
                    spec.label
                ));
            }
            Some((_, value)) if value < minimum => {
                return Err(format!(
                    "M6b2 stats: the {:?} line reports {key}={value}, below the required minimum {minimum}",
                    spec.label
                ));
            }
            Some(_) => {}
        }
    }
    for (key, _) in &fields {
        if !spec.fields.iter().any(|(expected, _)| expected == key) {
            return Err(format!(
                "M6b2 stats: the {:?} line reports the unexpected field {key:?}",
                spec.label
            ));
        }
    }
    Ok(fields)
}

/// Enforce the M6b2 statistics on a boot transcript.
///
/// Returns `None` when the five lines are absent (missing markers are reported
/// by [`missing_markers`]) or when every count passes; otherwise the first
/// problem, so printing the marker text with bogus numbers still fails. The
/// verdict must be a monotonic upper bound of the evidence: it may have advanced
/// past it (the counters keep running until the line is printed) but never
/// report less.
fn m6b2_stats_error(text: &str) -> Option<String> {
    let mut evidence: Vec<(&'static str, Vec<(&str, u64)>)> = Vec::new();
    for spec in M6B2_EVIDENCE {
        let line = text.lines().find(|line| line.starts_with(spec.marker))?;
        match m6b2_line_fields(line, spec) {
            Ok(fields) => evidence.push((spec.label, fields)),
            Err(error) => return Some(error),
        }
    }
    let line = text.lines().find(|line| line.starts_with(M6B2_OK))?;
    let verdict = match m6b2_line_fields(line, &M6B2_VERDICT) {
        Ok(fields) => fields,
        Err(error) => return Some(error),
    };
    for (label, fields) in &evidence {
        for (key, value) in fields {
            match verdict.iter().find(|(seen, _)| seen == key) {
                Some((_, verdict_value)) if verdict_value >= value => {}
                Some((_, verdict_value)) => {
                    return Some(format!(
                        "M6b2 stats: the verdict reports {key}={verdict_value} but the {label:?} evidence line reports {value}"
                    ));
                }
                None => {
                    return Some(format!(
                        "M6b2 stats: the {label:?} evidence line reports {key}, which the verdict does not summarise"
                    ));
                }
            }
        }
    }
    None
}

/// One M6c line whose payload is evidence, not decoration: the `gfx` program's
/// `M6c input OK` and the kernel's `M6c OK` must both report the exact number of
/// events they consumed and that none were dropped. Printing the marker text
/// with a wrong count (or with no payload at all) is therefore not acceptance.
struct M6cLine {
    marker: &'static str,
    label: &'static str,
    fields: &'static [(&'static str, u64)],
}

/// The two M6c lines whose payload is enforced. `events` is an exact count (two
/// keyboard scancodes, 0x20 press and 0xA0 release, plus the three serial bytes
/// `m6c`), `dropped` must be zero. The other M6c markers (probe/display/input
/// ready) may carry any payload; it is logged but not interpreted.
const M6C_EVIDENCE: &[M6cLine] = &[
    M6cLine {
        marker: M6C_INPUT,
        label: "M6c input",
        fields: &[("events", 5), ("dropped", 0)],
    },
    M6cLine {
        marker: M6C_OK,
        label: "M6c verdict",
        fields: &[("events", 5), ("dropped", 0)],
    },
];

fn m6c_payload<'a>(line: &'a str, spec: &M6cLine) -> Result<Vec<(&'a str, u64)>, String> {
    let rest = line[spec.marker.len()..].trim_end();
    let inner = rest
        .strip_prefix(" (")
        .and_then(|payload| payload.strip_suffix(')'))
        .ok_or_else(|| {
            format!(
                "M6c stats: the {:?} line must end with an \"(events=5, dropped=0)\" payload",
                spec.label
            )
        })?;
    let mut fields: Vec<(&'a str, u64)> = Vec::new();
    for pair in inner.split(',') {
        let Some((key, value)) = pair.trim().split_once('=') else {
            return Err(format!(
                "M6c stats: the {:?} line has a malformed field {:?}",
                spec.label,
                pair.trim()
            ));
        };
        let key = key.trim();
        let value = value.trim();
        if fields.iter().any(|(seen, _)| *seen == key) {
            return Err(format!(
                "M6c stats: the {:?} line repeats the field {key:?}",
                spec.label
            ));
        }
        let value: u64 = value.parse().map_err(|_| {
            format!(
                "M6c stats: the {:?} line reports {key}={value:?}, which is not a number",
                spec.label
            )
        })?;
        fields.push((key, value));
    }
    Ok(fields)
}

/// Validate the payload of both M6c evidence lines: `events` must be exactly 5
/// and `dropped` exactly 0. Extra fields are tolerated (they are only logged);
/// a missing line is left to [`missing_markers`].
fn m6c_stats_error(text: &str) -> Option<String> {
    for spec in M6C_EVIDENCE {
        let line = text.lines().find(|line| line.starts_with(spec.marker))?;
        let fields = match m6c_payload(line, spec) {
            Ok(fields) => fields,
            Err(error) => return Some(error),
        };
        for (key, expected) in spec.fields {
            match fields.iter().find(|(seen, _)| seen == key) {
                None => {
                    return Some(format!(
                        "M6c stats: the {:?} line has no {key:?} field (expected {key}={expected})",
                        spec.label
                    ));
                }
                Some((_, value)) if value != expected => {
                    return Some(format!(
                        "M6c stats: the {:?} line reports {key}={value}, expected exactly {expected} (2 keyboard scancodes + 3 serial events for `events`, none dropped)",
                        spec.label
                    ));
                }
                Some(_) => {}
            }
        }
    }
    None
}

/// One M7a line whose payload is the evidence: the UDP/TCP byte counts the
/// loopback stack really carried, the socket count after the suites, and the
/// number of suites the verdict covers. The values are exact, not minimums.
struct M7aLine {
    marker: &'static str,
    label: &'static str,
    fields: &'static [(&'static str, u64)],
}

/// The four M7a round-trip lines and the socket-accounting line. UDP carried a
/// 7-byte payload and TCP a 14-byte payload in each family; after the four
/// suites no socket object may remain.
const M7A_EVIDENCE: &[M7aLine] = &[
    M7aLine {
        marker: M7A_IPV4_UDP,
        label: "M7a ipv4 udp",
        fields: &[("bytes", 7)],
    },
    M7aLine {
        marker: M7A_IPV4_TCP,
        label: "M7a ipv4 tcp",
        fields: &[("bytes", 14)],
    },
    M7aLine {
        marker: M7A_IPV6_UDP,
        label: "M7a ipv6 udp",
        fields: &[("bytes", 7)],
    },
    M7aLine {
        marker: M7A_IPV6_TCP,
        label: "M7a ipv6 tcp",
        fields: &[("bytes", 14)],
    },
    M7aLine {
        marker: M7A_SOCKETS,
        label: "M7a sockets",
        fields: &[("live", 0)],
    },
];

/// The `M7a OK` verdict must state how many suites it closes (four).
const M7A_VERDICT: M7aLine = M7aLine {
    marker: M7A_OK,
    label: "M7a verdict",
    fields: &[("suites", 4)],
};

fn m7a_payload<'a>(line: &'a str, spec: &M7aLine) -> Result<Vec<(&'a str, u64)>, String> {
    let rest = line[spec.marker.len()..].trim_end();
    let inner = rest
        .strip_prefix(" (")
        .and_then(|payload| payload.strip_suffix(')'))
        .ok_or_else(|| {
            format!(
                "M7a stats: the {:?} line must end with an \"(key=value, ...)\" payload",
                spec.label
            )
        })?;
    let mut fields: Vec<(&'a str, u64)> = Vec::new();
    for pair in inner.split(',') {
        let Some((key, value)) = pair.trim().split_once('=') else {
            return Err(format!(
                "M7a stats: the {:?} line has a malformed field {:?}",
                spec.label,
                pair.trim()
            ));
        };
        let key = key.trim();
        let value = value.trim();
        if fields.iter().any(|(seen, _)| *seen == key) {
            return Err(format!(
                "M7a stats: the {:?} line repeats the field {key:?}",
                spec.label
            ));
        }
        let value: u64 = value.parse().map_err(|_| {
            format!(
                "M7a stats: the {:?} line reports {key}={value:?}, which is not a number",
                spec.label
            )
        })?;
        fields.push((key, value));
    }
    Ok(fields)
}

/// Validate every M7a payload: the byte counts must match exactly (7 for UDP,
/// 14 for TCP), the socket count must be zero and the verdict must cover four
/// suites. Extra fields are tolerated (they are only logged); a missing line is
/// left to [`missing_markers`].
fn m7a_stats_error(text: &str) -> Option<String> {
    let specs = M7A_EVIDENCE.iter().chain(std::iter::once(&M7A_VERDICT));
    for spec in specs {
        let line = match text.lines().find(|line| line.starts_with(spec.marker)) {
            Some(line) => line,
            // A missing line is reported by `missing_markers` (except the
            // verdict, which is a required marker too), so stop checking here.
            None => return None,
        };
        let fields = match m7a_payload(line, spec) {
            Ok(fields) => fields,
            Err(error) => return Some(error),
        };
        for (key, expected) in spec.fields {
            match fields.iter().find(|(seen, _)| seen == key) {
                None => {
                    return Some(format!(
                        "M7a stats: the {:?} line has no {key:?} field (expected {key}={expected})",
                        spec.label
                    ));
                }
                Some((_, value)) if value != expected => {
                    return Some(format!(
                        "M7a stats: the {:?} line reports {key}={value}, expected exactly {expected}",
                        spec.label
                    ));
                }
                Some(_) => {}
            }
        }
    }
    None
}

/// One M7b line whose payload is the evidence. The values are exact, not
/// minimums: the byte counts each round trip carried, the number of pairs and
/// would-blocks the suites observed, and the two verdicts' closing accounting.
struct M7bLine {
    marker: &'static str,
    label: &'static str,
    fields: &'static [(&'static str, u64)],
}

/// The twelve M7b suite lines and the two verdicts, in the frozen emission
/// order. `child=0` closes the `net` program side, then the kernel reports that
/// no socket or pathname binding is left behind.
const M7B_EVIDENCE: &[M7bLine] = &[
    M7bLine {
        marker: M7B_UDP4,
        label: "M7b udp4",
        fields: &[("bytes", 7)],
    },
    M7bLine {
        marker: M7B_UDP6,
        label: "M7b udp6",
        fields: &[("bytes", 7)],
    },
    M7bLine {
        marker: M7B_TCP4,
        label: "M7b tcp4",
        fields: &[("bytes", 14)],
    },
    M7bLine {
        marker: M7B_TCP6,
        label: "M7b tcp6",
        fields: &[("bytes", 14)],
    },
    M7bLine {
        marker: M7B_SOCKETPAIR,
        label: "M7b socketpair",
        fields: &[("pairs", 2), ("bytes", 1024)],
    },
    M7bLine {
        marker: M7B_UNIX_STREAM,
        label: "M7b unix stream",
        fields: &[("bytes", 1024)],
    },
    M7bLine {
        marker: M7B_UNIX_DGRAM,
        label: "M7b unix dgram",
        fields: &[("bytes", 512)],
    },
    M7bLine {
        marker: M7B_WAIT,
        label: "M7b wait",
        fields: &[("ready", 1), ("timeouts", 1)],
    },
    M7bLine {
        marker: M7B_BACKPRESSURE,
        label: "M7b backpressure",
        fields: &[("would_block", 2)],
    },
    M7bLine {
        marker: M7B_SHUTDOWN,
        label: "M7b shutdown",
        fields: &[("eof", 1)],
    },
    M7bLine {
        marker: M7B_RIGHTS,
        label: "M7b rights",
        fields: &[("bad_handle", 1), ("bad_right", 1)],
    },
    M7bLine {
        marker: M7B_FAULTS,
        label: "M7b faults",
        fields: &[
            ("too_large", 1),
            ("not_found", 1),
            ("exists", 1),
            ("peer_closed", 1),
        ],
    },
    M7bLine {
        marker: M7B_USER_OK,
        label: "M7b user verdict",
        fields: &[("child", 0)],
    },
    M7bLine {
        marker: M7B_KERNEL_OK,
        label: "M7b kernel verdict",
        fields: &[("sockets", 0), ("bindings", 0)],
    },
];

fn m7b_payload<'a>(line: &'a str, spec: &M7bLine) -> Result<Vec<(&'a str, u64)>, String> {
    let rest = line[spec.marker.len()..].trim_end();
    let inner = rest
        .strip_prefix(" (")
        .and_then(|payload| payload.strip_suffix(')'))
        .ok_or_else(|| {
            format!(
                "M7b stats: the {:?} line must end with an \"(key=value, ...)\" payload",
                spec.label
            )
        })?;
    let mut fields: Vec<(&'a str, u64)> = Vec::new();
    for pair in inner.split(',') {
        let Some((key, value)) = pair.trim().split_once('=') else {
            return Err(format!(
                "M7b stats: the {:?} line has a malformed field {:?}",
                spec.label,
                pair.trim()
            ));
        };
        let key = key.trim();
        let value = value.trim();
        if fields.iter().any(|(seen, _)| *seen == key) {
            return Err(format!(
                "M7b stats: the {:?} line repeats the field {key:?}",
                spec.label
            ));
        }
        let value: u64 = value.parse().map_err(|_| {
            format!(
                "M7b stats: the {:?} line reports {key}={value:?}, which is not a number",
                spec.label
            )
        })?;
        fields.push((key, value));
    }
    Ok(fields)
}

/// Validate every M7b payload against the exact frozen values. Extra fields are
/// tolerated (they are only logged); a missing line is left to
/// [`missing_markers`].
fn m7b_stats_error(text: &str) -> Option<String> {
    for spec in M7B_EVIDENCE {
        let line = match text.lines().find(|line| line.starts_with(spec.marker)) {
            Some(line) => line,
            None => return None,
        };
        let fields = match m7b_payload(line, spec) {
            Ok(fields) => fields,
            Err(error) => return Some(error),
        };
        for (key, expected) in spec.fields {
            match fields.iter().find(|(seen, _)| seen == key) {
                None => {
                    return Some(format!(
                        "M7b stats: the {:?} line has no {key:?} field (expected {key}={expected})",
                        spec.label
                    ));
                }
                Some((_, value)) if value != expected => {
                    return Some(format!(
                        "M7b stats: the {:?} line reports {key}={value}, expected exactly {expected}",
                        spec.label
                    ));
                }
                Some(_) => {}
            }
        }
    }
    None
}

/// The fields of the one M7d line that carries evidence: the kernel's closing
/// socket accounting after the Linux64 personality test exits.
const M7D_KERNEL_FIELDS: &[(&str, u64)] = &[("sockets", 0), ("bindings", 0)];

/// Validate the M7d kernel verdict's payload against the exact frozen values.
/// The seven user-mode lines are plain exact text and need no parsing; a missing
/// line is left to [`missing_markers`].
fn m7d_stats_error(text: &str) -> Option<String> {
    let label = "M7d kernel verdict";
    let line = match text.lines().find(|line| line.starts_with(M7D_KERNEL_OK)) {
        Some(line) => line,
        None => return None,
    };
    let rest = line[M7D_KERNEL_OK.len()..].trim_end();
    let inner = match rest
        .strip_prefix(" (")
        .and_then(|payload| payload.strip_suffix(')'))
    {
        Some(inner) => inner,
        None => {
            return Some(
                "M7d stats: the \"M7d kernel verdict\" line must end with a \"(key=value, ...)\" payload"
                    .to_string(),
            )
        }
    };
    let mut fields: Vec<(&str, u64)> = Vec::new();
    for pair in inner.split(',') {
        let Some((key, value)) = pair.trim().split_once('=') else {
            return Some(format!(
                "M7d stats: the {label:?} line has a malformed field {:?}",
                pair.trim()
            ));
        };
        let key = key.trim();
        let value = value.trim();
        if fields.iter().any(|(seen, _)| *seen == key) {
            return Some(format!(
                "M7d stats: the {label:?} line repeats the field {key:?}"
            ));
        }
        let value: u64 = match value.parse() {
            Ok(value) => value,
            Err(_) => {
                return Some(format!(
                    "M7d stats: the {label:?} line reports {key}={value:?}, which is not a number"
                ));
            }
        };
        fields.push((key, value));
    }
    for (key, expected) in M7D_KERNEL_FIELDS {
        match fields.iter().find(|(seen, _)| seen == key) {
            None => {
                return Some(format!(
                    "M7d stats: the {label:?} line has no {key:?} field (expected {key}={expected})"
                ));
            }
            Some((_, value)) if value != expected => {
                return Some(format!(
                    "M7d stats: the {label:?} line reports {key}={value}, expected exactly {expected}"
                ));
            }
            Some(_) => {}
        }
    }
    None
}

/// Why this boot is not acceptable yet, or `None` when it is.
fn acceptance_error(text: &str, stage: BootStage) -> Option<String> {
    let missing = missing_markers(text, stage);
    if !missing.is_empty() {
        return Some(format!(
            "{} marker(s) still missing: {missing:?}",
            missing.len()
        ));
    }
    let Some(fault_at) = text.rfind(FINAL_MARKER) else {
        return Some(format!("{FINAL_MARKER:?} never appeared"));
    };
    for marker in required_markers(stage) {
        if marker == FINAL_MARKER {
            continue;
        }
        match text.rfind(marker) {
            Some(at) if at < fault_at => {}
            _ => {
                return Some(format!(
                    "{FINAL_MARKER:?} is not the last marker ({marker:?} follows it)"
                ));
            }
        }
    }
    if let Some(error) = marker_placement_error(text, stage) {
        return Some(error);
    }
    // M6b2 is the one stage whose marker text alone is not evidence: each of its
    // five lines carries the counters behind it, and the numbers must reach the
    // frozen minimums and agree with the verdict that summarises them.
    // M6c's `input OK` / `M6c OK` payloads are evidence too (exactly five events,
    // none dropped), so a marker with a wrong count cannot look green.
    // M7a's loopback lines are evidence by payload as well: the exact UDP/TCP
    // byte counts, a zero live-socket count and a four-suite verdict.
    // M7b's native socket suites carry their exact byte/pair/handshake results
    // and the two closing verdicts' zero accounting. M7d's user lines are exact
    // plain text; its kernel verdict still has to report zero sockets/bindings.
    m6b2_stats_error(text)
        .or_else(|| m6c_stats_error(text))
        .or_else(|| m7a_stats_error(text))
        .or_else(|| m7b_stats_error(text))
        .or_else(|| m7d_stats_error(text))
}

/// True when every marker of this boot is present, correctly placed, and the
/// deliberate M2 page fault is the last one of them. The fault is the final step
/// of the kernel boot, so an M4/M5a/M5b/M5c1 marker after it means the ordering
/// contract is broken (and the run must not be accepted).
///
/// Only the tests use the boolean form; production code reports the reason via
/// `acceptance_error`.
#[cfg(test)]
fn acceptance_reached(text: &str, stage: BootStage) -> bool {
    acceptance_error(text, stage).is_none()
}

/// Error text for a boot that halted before every marker of its stage appeared.
///
/// A halted guest never prints again, so the runner must fail immediately
/// instead of idling until the acceptance timeout. Returns `None` when the
/// guest has not halted yet, or when every marker is already present (the
/// regular success/ordering path handles that case).
fn halted_early(text: &str, stage: BootStage) -> Option<String> {
    if !text.contains(HALT_MARKER) {
        return None;
    }
    let missing = missing_markers(text, stage);
    if missing.is_empty() {
        return None;
    }
    Some(format!(
        "guest halted with {} marker(s) still missing: {:?}",
        missing.len(),
        missing
    ))
}

/// Whole-run timeout, overridable with `CAELUM_QEMU_TIMEOUT=<seconds>`.
fn total_timeout() -> Duration {
    env::var("CAELUM_QEMU_TIMEOUT")
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
        .filter(|s| *s > 0)
        .map(Duration::from_secs)
        .unwrap_or(TOTAL_TIMEOUT)
}

fn run_cargo(args: &[&str]) -> Result<(), String> {
    let cargo = env::var("CARGO").unwrap_or_else(|_| "cargo".into());
    let out = Command::new(cargo)
        .args(args)
        .current_dir(root())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .output()
        .map_err(|e| format!("spawn cargo {args:?}: {e}"))?;
    if out.status.success() {
        Ok(())
    } else {
        Err(format!("cargo {args:?} failed with {}", out.status))
    }
}

/// `run_cargo` with extra environment variables. M9d1's dynamic main must be
/// built with `-C relocation-model=pic`; passing it through `RUSTFLAGS` for the
/// whole cargo invocation is the supported way to do that (using
/// `cargo rustc -- -C relocation-model=pic` is not: w1 saw
/// `R_X86_64_32S cannot be used against local symbol`).
fn run_cargo_env(args: &[&str], envs: &[(&str, &str)]) -> Result<(), String> {
    let cargo = env::var("CARGO").unwrap_or_else(|_| "cargo".into());
    let mut command = Command::new(cargo);
    command
        .args(args)
        .current_dir(root())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());
    for (key, value) in envs {
        command.env(key, value);
    }
    let out = command
        .output()
        .map_err(|e| format!("spawn cargo {args:?}: {e}"))?;
    if out.status.success() {
        Ok(())
    } else {
        Err(format!("cargo {args:?} failed with {}", out.status))
    }
}

fn cmd_build() -> Result<(), String> {
    run_cargo(&["build", "-p", "loader", "--target", UEFI_TARGET])?;
    // The M4 user programs, the M6b2 worker, the M6c display/input program, the
    // M7b native socket suite and the M7d Linux64 personality test are explicit
    // build products: `xtask image` packages them, so a run that silently skipped
    // them would be a false green.
    run_cargo(&[
        "build",
        "-p",
        "kernel",
        "-p",
        INIT_PKG,
        "-p",
        CHILD_PKG,
        "-p",
        WORKER_PKG,
        "-p",
        GFX_PKG,
        "-p",
        NET_PKG,
        "-p",
        LINUX_PKG,
        "--target",
        NONE_TARGET,
    ])?;
    // M9f: the shared-library chain is built bottom-up: B, then A (which links
    // B with a real `DT_NEEDED`), then the M9e library, then the dynamic main
    // that links both A and M9e. Every shared object is position independent.
    run_cargo_env(
        &[
            "build",
            "-p",
            M9F_B_LIB_PKG,
            "--target",
            NONE_TARGET,
            "--release",
            "--offline",
        ],
        &[("RUSTFLAGS", "-C relocation-model=pic")],
    )?;
    let m9f_b_lib = m9f_b_lib_elf();
    let m9f_b_lib_path = m9f_b_lib
        .to_str()
        .ok_or("M9f: the B shared-library artifact path is not valid UTF-8")?
        .to_string();
    run_cargo_env(
        &[
            "build",
            "-p",
            M9F_A_LIB_PKG,
            "--target",
            NONE_TARGET,
            "--release",
            "--offline",
        ],
        &[
            ("RUSTFLAGS", "-C relocation-model=pic"),
            ("CAELUM_M9F_B_LIB", m9f_b_lib_path.as_str()),
        ],
    )?;
    let m9f_a_lib = m9f_a_lib_elf();
    let m9f_a_lib_path = m9f_a_lib
        .to_str()
        .ok_or("M9f: the A shared-library artifact path is not valid UTF-8")?
        .to_string();
    // M9e: the shared library must be built first, because the dynamic main
    // links it with a real `DT_NEEDED` entry. Its linker arguments pin
    // `-shared`, so it needs the same position-independent relocation model.
    run_cargo_env(
        &[
            "build",
            "-p",
            M9E_LIB_PKG,
            "--target",
            NONE_TARGET,
            "--release",
            "--offline",
        ],
        &[("RUSTFLAGS", "-C relocation-model=pic")],
    )?;
    let m9e_lib = m9e_lib_elf();
    let m9e_lib_path = m9e_lib
        .to_str()
        .ok_or("M9e: the shared-library artifact path is not valid UTF-8")?
        .to_string();
    // M9d1: the dynamic ELF main and its interpreter are injected into the FAT
    // test volume instead of the initramfs, and only their `release` artifacts
    // are accepted. The main program is position independent, so its build must
    // override the relocation model for this cargo invocation only; M9e hands it
    // the freshly built shared library explicitly.
    run_cargo_env(
        &[
            "build",
            "-p",
            LINUX_DYN_PKG,
            "--target",
            NONE_TARGET,
            "--release",
            "--offline",
        ],
        &[
            ("RUSTFLAGS", "-C relocation-model=pic"),
            ("CAELUM_M9E_LIB", m9e_lib_path.as_str()),
            ("CAELUM_M9F_A_LIB", m9f_a_lib_path.as_str()),
        ],
    )?;
    run_cargo(&[
        "build",
        "-p",
        INTERP_PKG,
        "--target",
        NONE_TARGET,
        "--release",
    ])?;
    // M9d2: the vDSO image shares the pair's position-independent shape, so it
    // is built with the same relocation model override in release.
    run_cargo_env(
        &[
            "build",
            "-p",
            VDSO_PKG,
            "--target",
            NONE_TARGET,
            "--release",
            "--offline",
        ],
        &[("RUSTFLAGS", "-C relocation-model=pic")],
    )?;
    let artifacts = [
        ("loader", loader_efi()),
        ("kernel", kernel_elf()),
        (INIT_PKG, init_elf()),
        (CHILD_PKG, child_elf()),
        (WORKER_PKG, worker_elf()),
        (GFX_PKG, gfx_elf()),
        (NET_PKG, net_elf()),
        (LINUX_PKG, linux_elf()),
        (LINUX_DYN_PKG, linux_dyn_elf()),
        (INTERP_PKG, interp_elf()),
        (VDSO_PKG, vdso_elf()),
        (M9E_LIB_PKG, m9e_lib_elf()),
        (M9F_A_LIB_PKG, m9f_a_lib_elf()),
        (M9F_B_LIB_PKG, m9f_b_lib_elf()),
    ];
    for (name, path) in &artifacts {
        if !path.is_file() {
            return Err(format!(
                "{name}: expected build artifact missing at {} (the crate must be a workspace member building a binary)",
                path.display()
            ));
        }
    }
    // M10a: the genuine musl samples are third-party bytes nothing here builds,
    // so every build re-verifies them against tools/m10a/SHA256SUMS. A corrupted
    // checkout must fail here rather than turn a two-boot run green.
    let samples = m10a::load_samples()?;
    println!(
        "[xtask] M10a samples OK: {} bytes total (busybox {}, ld-musl {}, libc.musl {}), {} verified",
        samples.total_len(),
        samples.busybox.len(),
        samples.ld_musl.len(),
        samples.libc_musl.len(),
        m10a::SUMS_FILE
    );
    println!("[xtask] build OK:");
    for (name, path) in &artifacts {
        println!("  {name}: {}", path.display());
    }
    Ok(())
}

fn cmd_check() -> Result<(), String> {
    run_cargo(&["fmt", "--all", "--", "--check"])?;
    // Host-side: the kernel library is written to be host-testable (pure PMM
    // /heap/VM-map logic), so exercise it on the host toolchain too.
    run_cargo(&["check", "-p", "kernel", "--lib"])?;
    run_cargo(&["check", "-p", "loader", "--target", UEFI_TARGET])?;
    run_cargo(&["check", "-p", "kernel", "--target", NONE_TARGET])?;
    // The M4 user programs (plus the M6b2 worker, the M6c gfx program, the M7b
    // net program and the M7d Linux64 program) are bare-metal binaries:
    // compile-check them for the real target (they cannot be host-played like the
    // kernel library).
    run_cargo(&[
        "check",
        "-p",
        INIT_PKG,
        "-p",
        CHILD_PKG,
        "-p",
        WORKER_PKG,
        "-p",
        GFX_PKG,
        "-p",
        NET_PKG,
        "-p",
        LINUX_PKG,
        "--target",
        NONE_TARGET,
    ])?;
    // M9d1: the two injected binaries. The dynamic main is checked with the same
    // position-independent relocation model it is built with.
    run_cargo_env(
        &["check", "-p", LINUX_DYN_PKG, "--target", NONE_TARGET],
        &[("RUSTFLAGS", "-C relocation-model=pic")],
    )?;
    run_cargo(&["check", "-p", INTERP_PKG, "--target", NONE_TARGET])?;
    // M9d2: the vDSO image is checked with the same position-independent
    // relocation model it is built with.
    run_cargo_env(
        &["check", "-p", VDSO_PKG, "--target", NONE_TARGET],
        &[("RUSTFLAGS", "-C relocation-model=pic")],
    )?;
    // M9e: the shared library is checked with the same relocation model it is
    // built and linked with.
    run_cargo_env(
        &["check", "-p", M9E_LIB_PKG, "--target", NONE_TARGET],
        &[("RUSTFLAGS", "-C relocation-model=pic")],
    )?;
    // M9f: the two shared libraries are checked with the same relocation model
    // they are built with; `A` only needs `B` at link time, not at check time.
    for package in [M9F_B_LIB_PKG, M9F_A_LIB_PKG] {
        run_cargo_env(
            &["check", "-p", package, "--target", NONE_TARGET],
            &[("RUSTFLAGS", "-C relocation-model=pic")],
        )?;
    }
    run_cargo(&["test", "-p", "bootinfo", "-p", "elf64", "-p", "xtask"])?;
    run_cargo(&["test", "-p", "kernel", "--lib"])?;
    println!("[xtask] check OK");
    Ok(())
}

/// Light-weight sanity check for an M4 user ELF, run before it is packed.
///
/// Deliberately weaker than the kernel image's `validate_for_boot`: a user
/// program may legitimately be linked at a low or (later) randomized base, so
/// the `p_vaddr != 0` rule does not apply. What must hold is that the file
/// parses, has PT_LOAD segments with sane geometry and that `e_entry` lands in
/// one of them — otherwise the kernel would just fail at spawn time.
fn check_user_elf(name: &str, bytes: &[u8]) -> Result<(), String> {
    let elf = elf64::Elf64::parse(bytes).map_err(|e| format!("{name} ELF parse: {e:?}"))?;
    let mut loads = 0usize;
    let mut entry_ok = false;
    elf.for_each_load(|ph| {
        loads += 1;
        if ph.memsz == 0 || ph.filesz > ph.memsz {
            return Err(elf64::Error::BadLoadSegment);
        }
        if elf.entry >= ph.vaddr && elf.entry < ph.vaddr + ph.memsz {
            entry_ok = true;
        }
        Ok(())
    })
    .map_err(|e| format!("{name} ELF segments: {e:?}"))?;
    if loads == 0 {
        return Err(format!("{name} ELF has no PT_LOAD segments"));
    }
    if !entry_ok {
        return Err(format!(
            "{name} ELF entry 0x{:016x} is not covered by a PT_LOAD segment",
            elf.entry
        ));
    }
    println!(
        "[xtask] {name} ELF OK: entry 0x{:016x}, {loads} PT_LOAD segment(s)",
        elf.entry
    );
    Ok(())
}

/// Light-weight sanity check for an injected shared library (M9e): it must
/// parse, be an `ET_DYN` object and have at least one `PT_LOAD` segment. A
/// shared object has no meaningful entry point, so unlike `check_user_elf` the
/// entry is not required to be covered by a load segment.
fn check_shared_elf(name: &str, bytes: &[u8]) -> Result<(), String> {
    let elf = elf64::Elf64::parse(bytes).map_err(|e| format!("{name} ELF parse: {e:?}"))?;
    if !elf.is_dynamic() {
        return Err(format!("{name} must be an ET_DYN shared object"));
    }
    let mut loads = 0usize;
    elf.for_each_load(|ph| {
        if ph.memsz == 0 || ph.filesz > ph.memsz {
            return Err(elf64::Error::BadLoadSegment);
        }
        loads += 1;
        Ok(())
    })
    .map_err(|e| format!("{name} ELF segments: {e:?}"))?;
    if loads == 0 {
        return Err(format!("{name} ELF has no PT_LOAD segments"));
    }
    println!(
        "[xtask] {name} shared ELF OK: ET_DYN, {loads} PT_LOAD segment(s), {} bytes",
        bytes.len()
    );
    Ok(())
}

fn cmd_image() -> Result<(), String> {
    cmd_build()?;
    let loader = std::fs::read(loader_efi()).map_err(|e| format!("read loader.efi: {e}"))?;
    let kernel = std::fs::read(kernel_elf()).map_err(|e| format!("read kernel: {e}"))?;
    let init = std::fs::read(init_elf()).map_err(|e| format!("read {INIT_PKG}: {e}"))?;
    let child = std::fs::read(child_elf()).map_err(|e| format!("read {CHILD_PKG}: {e}"))?;
    let worker = std::fs::read(worker_elf()).map_err(|e| format!("read {WORKER_PKG}: {e}"))?;
    let gfx = std::fs::read(gfx_elf()).map_err(|e| format!("read {GFX_PKG}: {e}"))?;
    let net = std::fs::read(net_elf()).map_err(|e| format!("read {NET_PKG}: {e}"))?;
    let linux = std::fs::read(linux_elf()).map_err(|e| format!("read {LINUX_PKG}: {e}"))?;
    let dyn_main =
        std::fs::read(linux_dyn_elf()).map_err(|e| format!("read {LINUX_DYN_PKG}: {e}"))?;
    let interp = std::fs::read(interp_elf()).map_err(|e| format!("read {INTERP_PKG}: {e}"))?;
    let vdso = std::fs::read(vdso_elf()).map_err(|e| format!("read {VDSO_PKG}: {e}"))?;
    let m9e_lib = std::fs::read(m9e_lib_elf()).map_err(|e| format!("read {M9E_LIB_PKG}: {e}"))?;
    let m9f_a_lib =
        std::fs::read(m9f_a_lib_elf()).map_err(|e| format!("read {M9F_A_LIB_PKG}: {e}"))?;
    let m9f_b_lib =
        std::fs::read(m9f_b_lib_elf()).map_err(|e| format!("read {M9F_B_LIB_PKG}: {e}"))?;
    // Pre-check the kernel ELF with the same code the loader uses.
    let elf = elf64::Elf64::parse(&kernel).map_err(|e| format!("kernel ELF parse: {e:?}"))?;
    elf.validate_for_boot()
        .map_err(|e| format!("kernel ELF boot validation: {e:?}"))?;
    let req = elf
        .boot_requirements()
        .map_err(|_| "kernel missing/invalid .caelum.bootreq".to_string())?;
    println!(
        "[xtask] kernel ELF OK: entry 0x{:016x}, {} program headers, bootreq {}.{} abi {}",
        elf.entry,
        elf.phnum(),
        req.major,
        req.minor,
        req.entry_abi
    );
    check_user_elf(INIT_PKG, &init)?;
    check_user_elf(CHILD_PKG, &child)?;
    check_user_elf(WORKER_PKG, &worker)?;
    check_user_elf(GFX_PKG, &gfx)?;
    check_user_elf(NET_PKG, &net)?;
    check_user_elf(LINUX_PKG, &linux)?;
    // M9d1/M9d2: all three injected binaries must be valid ELFs before the run
    // may start; the kernel reads them back from the FAT volume and the harness
    // checks them byte for byte after each boot.
    check_user_elf(LINUX_DYN_PKG, &dyn_main)?;
    check_user_elf(INTERP_PKG, &interp)?;
    check_user_elf(VDSO_PKG, &vdso)?;
    // M9e: the shared library must be a genuine ET_DYN object with loadable
    // segments before a run may start; the kernel and host read it back byte for
    // byte, but a malformed image must fail the image build first.
    check_shared_elf(M9E_LIB_PKG, &m9e_lib)?;
    // M9f: both libraries of the chain must be genuine ET_DYN objects too.
    check_shared_elf(M9F_A_LIB_PKG, &m9f_a_lib)?;
    check_shared_elf(M9F_B_LIB_PKG, &m9f_b_lib)?;

    // Pack the boot modules and self-check the container before it is written.
    // The kernel looks each module up by name, so the check covers the name,
    // the order and the exact bytes of all six payloads.
    let container = initramfs::build(&[
        initramfs::Module {
            name: initramfs::MODULE_INIT,
            kind: initramfs::KIND_ELF,
            data: &init,
        },
        initramfs::Module {
            name: initramfs::MODULE_CHILD,
            kind: initramfs::KIND_ELF,
            data: &child,
        },
        initramfs::Module {
            name: initramfs::MODULE_WORKER,
            kind: initramfs::KIND_ELF,
            data: &worker,
        },
        initramfs::Module {
            name: initramfs::MODULE_GFX,
            kind: initramfs::KIND_ELF,
            data: &gfx,
        },
        initramfs::Module {
            name: initramfs::MODULE_NET,
            kind: initramfs::KIND_ELF,
            data: &net,
        },
        initramfs::Module {
            name: initramfs::MODULE_LINUX,
            kind: initramfs::KIND_ELF,
            data: &linux,
        },
    ])?;
    let entries = initramfs::parse(&container)?;
    if entries.len() != 6
        || entries[0].name != initramfs::MODULE_INIT
        || initramfs::payload(&container, &entries[0]) != &init[..]
        || entries[1].name != initramfs::MODULE_CHILD
        || initramfs::payload(&container, &entries[1]) != &child[..]
        || entries[2].name != initramfs::MODULE_WORKER
        || initramfs::payload(&container, &entries[2]) != &worker[..]
        || entries[3].name != initramfs::MODULE_GFX
        || initramfs::payload(&container, &entries[3]) != &gfx[..]
        || entries[4].name != initramfs::MODULE_NET
        || initramfs::payload(&container, &entries[4]) != &net[..]
        || entries[5].name != initramfs::MODULE_LINUX
        || initramfs::payload(&container, &entries[5]) != &linux[..]
    {
        return Err("initramfs self-check: module table/content mismatch".into());
    }
    let initfs_path = initramfs_img();
    std::fs::write(&initfs_path, &container)
        .map_err(|e| format!("write {}: {e}", initfs_path.display()))?;

    let img = fat::build_esp(&loader, &kernel, &container);
    // Self-check: read all three files back out of the generated image.
    let back = fat::read_file(&img, &["EFI", "BOOT", "BOOTX64.EFI"])
        .ok_or("ESP self-check: BOOTX64.EFI missing")?;
    if back != loader {
        return Err("ESP self-check: BOOTX64.EFI content mismatch".into());
    }
    if fat::read_file(&img, &["KERNEL.ELF"]).ok_or("ESP self-check: KERNEL.ELF missing")? != kernel
    {
        return Err("ESP self-check: KERNEL.ELF content mismatch".into());
    }
    if fat::read_file(&img, &[fat::INITFS_NAME])
        .ok_or_else(|| format!("ESP self-check: {} missing", fat::INITFS_NAME))?
        != container
    {
        return Err(format!(
            "ESP self-check: {} content mismatch",
            fat::INITFS_NAME
        ));
    }
    let path = esp_image();
    std::fs::write(&path, &img).map_err(|e| format!("write {}: {e}", path.display()))?;
    println!(
        "[xtask] initramfs OK: {} ({} bytes: {} init + {} child + {} worker + {} gfx + {} net + {} linux + {} header/records)",
        initfs_path.display(),
        container.len(),
        init.len(),
        child.len(),
        worker.len(),
        gfx.len(),
        net.len(),
        linux.len(),
        container.len()
            - init.len()
            - child.len()
            - worker.len()
            - gfx.len()
            - net.len()
            - linux.len()
    );
    println!(
        "[xtask] image OK: {} ({} MiB, FAT16 ESP, {} loader / {} kernel / {} initramfs bytes)",
        path.display(),
        img.len() / 1024 / 1024,
        loader.len(),
        kernel.len(),
        container.len()
    );
    Ok(())
}

/// Newest `mtime` of any `*.rs`/`*.toml` file under `dir`, recursively.
fn newest_source_mtime(dir: &Path) -> Option<std::time::SystemTime> {
    let mut newest: Option<std::time::SystemTime> = None;
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&d) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let Ok(meta) = entry.metadata() else { continue };
            if meta.is_dir() {
                // Skip build outputs; only tracked source trees are walked.
                if path.file_name().and_then(|n| n.to_str()) != Some("target") {
                    stack.push(path);
                }
            } else if matches!(
                path.extension().and_then(|e| e.to_str()),
                Some("rs" | "toml")
            ) {
                if let Ok(t) = meta.modified() {
                    newest = Some(match newest {
                        Some(n) if n >= t => n,
                        _ => t,
                    });
                }
            }
        }
    }
    newest
}

/// Rebuild the ESP when it is missing, older than the loader/kernel binaries,
/// or older than the crate *sources*. The source check matters: a source edit
/// whose rebuild failed must not silently run the previously built kernel (that
/// is exactly the "stale image passes" failure mode), and a successful rebuild
/// always bumps the binary mtime, so the artifact comparison still covers it.
fn image_is_stale() -> bool {
    let Ok(img) = std::fs::metadata(esp_image()) else {
        return true;
    };
    let Ok(img_time) = img.modified() else {
        return true;
    };
    // Built artifacts: loader, kernel, the M4 user programs, the M6b2 worker, the
    // M6c gfx program, the M7b net program, the M7d Linux64 program, the M9d1/2
    // release binaries injected into the FAT volume, and the packed initramfs
    // container that was embedded when the image was generated.
    for artifact in [
        loader_efi(),
        kernel_elf(),
        init_elf(),
        child_elf(),
        worker_elf(),
        gfx_elf(),
        net_elf(),
        linux_elf(),
        linux_dyn_elf(),
        interp_elf(),
        vdso_elf(),
        m9e_lib_elf(),
        m9f_a_lib_elf(),
        m9f_b_lib_elf(),
        initramfs_img(),
    ] {
        let Ok(meta) = std::fs::metadata(&artifact) else {
            // Artifact not built yet: the image cannot be trusted.
            return true;
        };
        match meta.modified() {
            Ok(t) if t > img_time => return true,
            Ok(_) => {}
            Err(_) => return true,
        }
    }
    // Sources: any Rust/Toml edit anywhere in the workspace (including the M4
    // user crates and the M6b2 worker) invalidates the image. A source edit
    // whose rebuild failed must not silently run the previously built image —
    // that is exactly the "stale image passes" failure mode.
    if let Some(t) = newest_source_mtime(&root()) {
        if t > img_time {
            return true;
        }
    }
    false
}

fn ensure_image() -> Result<(), String> {
    if image_is_stale() {
        println!("[xtask] ESP image missing or stale — rebuilding");
        cmd_image()
    } else {
        println!("[xtask] ESP image up to date: {}", esp_image().display());
        Ok(())
    }
}

/// Firmware search order: explicit override, then the firmware vendored in the
/// repo (`tools/ovmf/`), then well-known host locations.
fn find_ovmf() -> Option<PathBuf> {
    if let Ok(p) = env::var("CAELUM_OVMF") {
        let p = PathBuf::from(p);
        if p.is_file() {
            return Some(p);
        }
    }
    let vendored = root().join("tools").join("ovmf").join("OVMF_CODE.fd");
    if vendored.is_file() {
        return Some(vendored);
    }
    let candidates = [
        "C:/Program Files/qemu/share/edk2-x86_64-code.fd",
        "C:/Program Files/qemu/share/ovmf/OVMF_CODE.fd",
        "C:/Program Files/OVMF/OVMF_CODE.fd",
        "C:/Program Files (x86)/OVMF/OVMF_CODE.fd",
        "C:/ovmf/OVMF_CODE.fd",
        "C:/tools/ovmf/OVMF_CODE.fd",
        "C:/msys64/usr/share/edk2/x64/OVMF_CODE.fd",
        "C:/msys64/usr/share/ovmf/x64/OVMF_CODE.fd",
        "/usr/share/OVMF/OVMF_CODE.fd",
        "/usr/share/edk2/ovmf/OVMF_CODE.fd",
        "/usr/share/qemu/edk2-x86_64-code.fd",
    ];
    candidates.iter().map(PathBuf::from).find(|p| p.is_file())
}

fn find_qemu() -> Option<PathBuf> {
    // PATH first.
    if let Ok(out) = Command::new("qemu-system-x86_64")
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .output()
    {
        if out.status.success() {
            return Some(PathBuf::from("qemu-system-x86_64"));
        }
    }
    // Well-known install locations (not on PATH by default on Windows).
    [
        "C:/Program Files/qemu/qemu-system-x86_64.exe",
        "C:/Program Files/QEMU/qemu-system-x86_64.exe",
        "C:/Program Files (x86)/qemu/qemu-system-x86_64.exe",
        "C:/qemu/qemu-system-x86_64.exe",
        "C:/tools/qemu/qemu-system-x86_64.exe",
        "C:/msys64/mingw64/bin/qemu-system-x86_64.exe",
    ]
    .iter()
    .map(PathBuf::from)
    .find(|p| p.is_file())
}

fn print_qemu_manual(ovmf: Option<&Path>, why: &str) {
    let bios = ovmf
        .map(|p| {
            format!(
                "-drive if=pflash,format=raw,readonly=on,file=\"{}\" ",
                p.display()
            )
        })
        .unwrap_or_default();
    println!("[xtask] QEMU/OVMF acceptance skipped: {why}");
    println!(
        "[xtask] An M5b run boots the guest TWICE on fresh 64 MiB FAT32 + 32 MiB ext2 disks and"
    );
    println!("[xtask] re-mounts both volumes on the host after each boot. The manual command");
    println!("[xtask] below is the first boot only: no input injection, no host verification.");
    println!(
        "[xtask] `-cpu qemu64,+rdrand,+rdseed` is required from M10a on: the guest's AT_RANDOM"
    );
    println!("[xtask] needs a real hardware entropy source, and the default qemu64 lacks both.");
    println!(
        "[xtask] M7c-1a attaches a legacy virtio-net NIC on QEMU's `user` backend (the `-netdev`/`-device` pair below)."
    );
    println!(
        "  qemu-system-x86_64 -machine q35 -cpu qemu64,+rdrand,+rdseed -smp 4 -m 256M {}-drive file=\"{}\",format=raw,if=ide -drive if=none,id=disk0,format=raw,file=\"{}\" -device virtio-blk-pci,drive=disk0,disable-modern=on,disable-legacy=off,queue-size=128 -drive if=none,id=disk1,format=raw,file=\"{}\" -device virtio-blk-pci,drive=disk1,disable-modern=on,disable-legacy=off,queue-size=128 -netdev user,id=net0 -device virtio-net-pci,netdev=net0,id=nic0,mac=52:54:00:12:34:56,vectors=4,disable-modern=on,disable-legacy=off -serial file:\"{}\" -display none -no-reboot -no-shutdown",
        bios,
        esp_image().display(),
        disks::fat32_image().display(),
        disks::ext2_image().display(),
        BootStage::First.log_path().display()
    );
    println!("[xtask] Expected serial markers for one boot (in order):");
    for m in required_markers(BootStage::First) {
        println!("  {m}");
    }
    println!("[xtask] The second boot replaces the first-boot-only lines with:");
    for m in M5B_SECOND_MARKERS {
        println!("  {m}");
    }
    println!("[xtask] Required final marker (both boots): {FINAL_MARKER}");
    println!("[xtask] M6c needs a second injection (QMP send-key `d` + serial \"m6c\") and a QMP");
    println!(
        "[xtask] `screendump` to {} / {} after `M6c display OK`; the manual command cannot do either.",
        screen_path(BootStage::First).display(),
        screen_path(BootStage::Second).display()
    );
    println!(
        "[xtask] M9d also needs the release dyn/interp/vDSO images injected into the FAT disk as /{}, /{} and /{}; only `cargo xtask qemu` formats that disk.",
        disks::FAT_DYN_MAIN,
        disks::FAT_DYN_INTERP,
        disks::FAT_VDSO
    );
    println!(
        "[xtask] M9e also needs the release shared library injected as /{}; only `cargo xtask qemu` formats that disk.",
        disks::FAT_M9E
    );
    println!(
        "[xtask] M9f also needs the two chained release shared libraries injected as /{} and /{}; only `cargo xtask qemu` formats that disk.",
        disks::FAT_M9F_A,
        disks::FAT_M9F_B
    );
}

fn cmd_qemu() -> Result<(), String> {
    ensure_image()?;
    let Some(qemu) = find_qemu() else {
        print_qemu_manual(
            find_ovmf().as_deref(),
            "qemu-system-x86_64 not found in PATH",
        );
        return Ok(());
    };
    let Some(ovmf) = find_ovmf() else {
        print_qemu_manual(
            None,
            "no OVMF firmware (set CAELUM_OVMF or provide tools/ovmf/OVMF_CODE.fd)",
        );
        return Ok(());
    };

    // M9d1/M9d2: the dynamic ELF pair and the vDSO image are injected into the
    // FAT volume on every run, so a stale copy can never pass. The kernel reads
    // all three files back during its M7d closeout and the host re-checks them
    // after each boot.
    let dyn_main =
        std::fs::read(linux_dyn_elf()).map_err(|e| format!("read {LINUX_DYN_PKG}: {e}"))?;
    let interp = std::fs::read(interp_elf()).map_err(|e| format!("read {INTERP_PKG}: {e}"))?;
    let vdso = std::fs::read(vdso_elf()).map_err(|e| format!("read {VDSO_PKG}: {e}"))?;
    let m9e_lib = std::fs::read(m9e_lib_elf()).map_err(|e| format!("read {M9E_LIB_PKG}: {e}"))?;
    let m9f_a_lib =
        std::fs::read(m9f_a_lib_elf()).map_err(|e| format!("read {M9F_A_LIB_PKG}: {e}"))?;
    let m9f_b_lib =
        std::fs::read(m9f_b_lib_elf()).map_err(|e| format!("read {M9F_B_LIB_PKG}: {e}"))?;
    // M10a: the real musl samples are injected into the ext2 volume on every run
    // (the build already verified them against SHA256SUMS; loading them again is
    // what the host comparison below expects the guest to leave untouched).
    let m10a_samples = m10a::load_samples()?;

    // Fresh volumes for every run: a stale or half-written disk image must never
    // be able to turn the run green.
    disks::format_images_with_injected_elfs(
        &dyn_main,
        &interp,
        &vdso,
        &m9e_lib,
        &m9f_a_lib,
        &m9f_b_lib,
        &m10a_samples,
    )?;
    println!(
        "[xtask] M5b disks: {} (FAT32, drive index 0, {} MiB) and {} (ext2, drive index 1, {} MiB)",
        disks::fat32_image().display(),
        disks::FAT32_DISK_BYTES / (1024 * 1024),
        disks::ext2_image().display(),
        disks::EXT2_DISK_BYTES / (1024 * 1024)
    );
    println!(
        "[xtask] M9d injected /{} ({} bytes), /{} ({} bytes) and /{} ({} bytes), M9e injected /{} ({} bytes), and M9f injected /{} ({} bytes) and /{} ({} bytes), into the FAT volume; the kernel must read them back and the host re-checks them after each boot",
        disks::FAT_DYN_MAIN,
        dyn_main.len(),
        disks::FAT_DYN_INTERP,
        interp.len(),
        disks::FAT_VDSO,
        vdso.len(),
        disks::FAT_M9E,
        m9e_lib.len(),
        disks::FAT_M9F_A,
        m9f_a_lib.len(),
        disks::FAT_M9F_B,
        m9f_b_lib.len()
    );
    println!(
        "[xtask] M10a injected /{}/{} ({} bytes) and /{}/{} + /{}/{} ({} bytes each) into the ext2 volume",
        String::from_utf8_lossy(disks::EXT2_BIN_DIR),
        String::from_utf8_lossy(disks::EXT2_BUSYBOX),
        m10a_samples.busybox.len(),
        String::from_utf8_lossy(disks::EXT2_LIB_DIR),
        String::from_utf8_lossy(disks::EXT2_LD_MUSL),
        String::from_utf8_lossy(disks::EXT2_LIB_DIR),
        String::from_utf8_lossy(disks::EXT2_LIBC_MUSL),
        m10a_samples.ld_musl.len()
    );

    boot_and_accept(&qemu, &ovmf, BootStage::First)?;
    disks::verify_first_boot()
        .map_err(|e| format!("host check after the first boot failed: {e}"))?;
    disks::verify_injected_elfs_on_disk(
        &dyn_main, &interp, &vdso, &m9e_lib, &m9f_a_lib, &m9f_b_lib,
    )
    .map_err(|e| format!("injected-ELF host check after the first boot failed: {e}"))?;
    disks::verify_m10a_samples_on_disk(&m10a_samples)
        .map_err(|e| format!("M10a host check after the first boot failed: {e}"))?;
    println!(
        "[xtask] first boot verified on the host: 13-byte state marker, all {} pattern bytes, the {}-byte M5c user file, the shared-mmap map file, the {}-byte sparse hole file and the {}-byte fault-injection file on both volumes",
        disks::DATA_INITIAL_LEN,
        disks::M5C1_FIRST_MARKER.len(),
        disks::HOLE_LEN,
        disks::FAULT_LEN
    );

    boot_and_accept(&qemu, &ovmf, BootStage::Second)?;
    disks::verify_second_boot()
        .map_err(|e| format!("host check after the second boot failed: {e}"))?;
    disks::verify_injected_elfs_on_disk(
        &dyn_main, &interp, &vdso, &m9e_lib, &m9f_a_lib, &m9f_b_lib,
    )
    .map_err(|e| format!("injected-ELF host check after the second boot failed: {e}"))?;
    // M10a's contract is explicit: the real musl samples must still be on the
    // volume after the *second* boot, byte for byte.
    disks::verify_m10a_samples_on_disk(&m10a_samples)
        .map_err(|e| format!("M10a host check after the second boot failed: {e}"))?;
    println!(
        "[xtask] second boot verified on the host: state survived, data renamed and truncated to {} bytes, the {}-byte second-boot M5c user file, the map file with only the shared-mmap edits, the recreated sparse hole file, the recovered fault-injection file and the untouched M10a /bin,/lib samples on both volumes",
        disks::DATA_FINAL_LEN,
        disks::M5C1_SECOND_MARKER.len()
    );
    println!(
        "[xtask] M5b + M5c1 + M5c2 + M5c3 + M6a1 + M6a2 + M6b1 + M6b2a + M6b2 + M6c + M7a + M7b + M7d + M8a + M8b + M8c + M8d + M8e + M8f + M8g + M8h + M9a + M9b + M9c + M9d1 + M9d2 + M9e + M9f + M10a + M7c-1a acceptance OK (2 boots, {} markers per boot, final marker {FINAL_MARKER})",
        required_markers(BootStage::Second).len()
    );
    Ok(())
}

/// A free loopback port. QEMU is told to listen there immediately afterwards;
/// the bind/drop window is a few microseconds and only this process competes.
fn free_tcp_port() -> Result<u16, String> {
    let listener = TcpListener::bind("127.0.0.1:0").map_err(|e| format!("bind loopback: {e}"))?;
    listener
        .local_addr()
        .map(|a| a.port())
        .map_err(|e| format!("local_addr: {e}"))
}

fn connect_retry(port: u16, timeout: Duration) -> Result<TcpStream, String> {
    let start = Instant::now();
    let mut last;
    loop {
        match TcpStream::connect(("127.0.0.1", port)) {
            Ok(stream) => {
                stream.set_nodelay(true).ok();
                return Ok(stream);
            }
            Err(e) => last = e.to_string(),
        }
        if start.elapsed() >= timeout {
            return Err(format!("127.0.0.1:{port}: {last}"));
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

fn spawn_qemu(
    qemu: &Path,
    ovmf: &Path,
    serial_port: u16,
    qmp_port: u16,
) -> Result<(Child, Arc<Mutex<String>>), String> {
    let mut child = Command::new(qemu)
        // M6b1: four CPUs so the kernel's AP startup path is exercised; the
        // guest must print `M6b1 online=4` (three APs + the BSP).
        //
        // M10a: the dynamically linked musl program (`busybox echo ...`) needs
        // `AT_RANDOM`, and the kernel deliberately refuses to fabricate secure
        // bytes when it has no entropy. QEMU's default `qemu64` CPU does not
        // expose RDRAND/RDSEED, so the kernel's rng probe would find no backend
        // and every secure spawn would fail with `M10a DBG rng`. Enable both
        // instructions explicitly; machine, SMP count, memory, disks and
        // serial wiring are unchanged.
        .args([
            "-machine",
            "q35",
            "-cpu",
            "qemu64,+rdrand,+rdseed",
            "-smp",
            "4",
            "-m",
            "256M",
        ])
        .arg("-drive")
        .arg(format!(
            "if=pflash,format=raw,readonly=on,file={}",
            ovmf.display()
        ))
        .arg("-drive")
        .arg(format!("file={},format=raw,if=ide", esp_image().display()))
        // M5b: two legacy virtio-blk drives. Device order defines the guest's
        // drive index: FAT32 is index 0, ext2 is index 1. `disable-modern=on`
        // keeps the device on the virtio 0.9 (legacy) interface the kernel
        // driver implements; `queue-size=128` matches the driver's two-frame
        // DMA budget instead of QEMU's 256-descriptor default.
        .arg("-drive")
        .arg(format!(
            "if=none,id=disk0,format=raw,file={}",
            disks::fat32_image().display()
        ))
        .arg("-device")
        .arg("virtio-blk-pci,drive=disk0,disable-modern=on,disable-legacy=off,queue-size=128")
        .arg("-drive")
        .arg(format!(
            "if=none,id=disk1,format=raw,file={}",
            disks::ext2_image().display()
        ))
        .arg("-device")
        .arg("virtio-blk-pci,drive=disk1,disable-modern=on,disable-legacy=off,queue-size=128")
        // M7c-1a: legacy virtio-net on QEMU's `user` backend. The kernel driver
        // requires the transitional 0x1000 interface (`disable-modern=on`) and
        // an MSI-X table with at least three vectors; `vectors=4` provides the
        // config/RX/TX entries and the fixed MAC makes the probe line
        // predictable. The raw-frame host peer and ARP/UDP echo come later.
        .arg("-netdev")
        .arg("user,id=net0")
        .arg("-device")
        .arg("virtio-net-pci,netdev=net0,id=nic0,mac=52:54:00:12:34:56,vectors=4,disable-modern=on,disable-legacy=off")
        // Bidirectional guest UART: wait=on guarantees QEMU does not emit a
        // single serial byte before the harness is connected, so no early
        // markers are lost. Explicit host=/port= keys (not the deprecated
        // `tcp:host:port` short form, which QEMU 11 rejects for -chardev).
        .arg("-chardev")
        .arg(format!(
            "socket,id=ser0,host=127.0.0.1,port={serial_port},server=on,wait=on"
        ))
        .arg("-serial")
        .arg("chardev:ser0")
        // QMP for PS/2 keyboard injection. wait=off: the harness connects as
        // soon as the listener is up and completes the QMP greeting handshake.
        .arg("-chardev")
        .arg(format!(
            "socket,id=qmp0,host=127.0.0.1,port={qmp_port},server=on,wait=off"
        ))
        .arg("-qmp")
        .arg("chardev:qmp0")
        .args(["-display", "none", "-no-reboot", "-no-shutdown"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("spawn qemu {}: {e}", qemu.display()))?;

    let stderr_buf = Arc::new(Mutex::new(String::new()));
    if let Some(mut stderr) = child.stderr.take() {
        let buf = stderr_buf.clone();
        std::thread::spawn(move || {
            let mut text = String::new();
            let _ = stderr.read_to_string(&mut text);
            if let Ok(mut guard) = buf.lock() {
                guard.push_str(&text);
            }
        });
    }
    Ok((child, stderr_buf))
}

fn stderr_text(buf: &Arc<Mutex<String>>) -> String {
    match buf.lock() {
        Ok(guard) if !guard.trim().is_empty() => guard.clone(),
        _ => "(empty)".to_string(),
    }
}

fn log_tail(path: &Path, lines: usize) -> String {
    let text = std::fs::read_to_string(path).unwrap_or_default();
    let all: Vec<&str> = text.lines().collect();
    let start = all.len().saturating_sub(lines);
    all[start..].join("\n")
}

/// QMP session over loopback TCP. Only the pieces needed for `send-key` are
/// implemented; responses are matched line-wise (QMP is line-delimited JSON).
struct Qmp {
    out: TcpStream,
    reader: BufReader<TcpStream>,
}

impl Qmp {
    fn connect(port: u16) -> Result<Self, String> {
        let out = connect_retry(port, Duration::from_secs(10))
            .map_err(|e| format!("qmp chardev: {e}"))?;
        out.set_read_timeout(Some(Duration::from_secs(10))).ok();
        let read_half = out
            .try_clone()
            .map_err(|e| format!("qmp duplicate handle: {e}"))?;
        let mut reader = BufReader::new(read_half);
        let mut greeting = String::new();
        reader
            .read_line(&mut greeting)
            .map_err(|e| format!("qmp greeting: {e}"))?;
        if !greeting.contains("\"QMP\"") {
            return Err(format!("unexpected QMP greeting: {greeting:?}"));
        }
        let mut qmp = Qmp { out, reader };
        qmp.command("{\"execute\":\"qmp_capabilities\"}")?;
        Ok(qmp)
    }

    /// Send one QMP command and wait for its `return`/`error` response.
    fn command(&mut self, json: &str) -> Result<(), String> {
        self.out
            .write_all(json.as_bytes())
            .and_then(|_| self.out.write_all(b"\n"))
            .and_then(|_| self.out.flush())
            .map_err(|e| format!("qmp write: {e}"))?;
        let mut line = String::new();
        loop {
            line.clear();
            let n = self
                .reader
                .read_line(&mut line)
                .map_err(|e| format!("qmp read: {e}"))?;
            if n == 0 {
                return Err("qmp connection closed before a response".into());
            }
            if line.contains("\"error\"") {
                return Err(format!("qmp error: {}", line.trim()));
            }
            if line.contains("\"return\"") {
                return Ok(());
            }
        }
    }

    /// Press and release PS/2 key `a` in the guest.
    fn send_key_a(&mut self) -> Result<(), String> {
        self.command(SEND_KEY_A_JSON)
    }

    /// Press and release PS/2 key `d` in the guest (M6c's second injection).
    fn send_key_d(&mut self) -> Result<(), String> {
        self.command(SEND_KEY_D_JSON)
    }

    /// Keep reading (and discarding) QMP events in the background so QEMU can
    /// never block on a full socket buffer while the run continues.
    fn drain(self) {
        std::thread::spawn(move || {
            let Qmp {
                out: _out,
                mut reader,
            } = self;
            let mut line = String::new();
            loop {
                line.clear();
                match reader.read_line(&mut line) {
                    Ok(0) => break,
                    Ok(_) => {}
                    Err(_) => break,
                }
            }
        });
    }
}

/// A binary P6 PPM image, as written by QEMU's `screendump` (8-bit RGB).
#[derive(Debug)]
struct Ppm {
    width: usize,
    height: usize,
    pixels: Vec<u8>,
}

impl Ppm {
    /// Parse a binary `P6` PPM whose maximum value is 255.
    ///
    /// The header is `P6 <width> <height> <maxval>` with arbitrary whitespace
    /// (and `#` comments) between tokens; exactly one whitespace byte separates
    /// the maxval from the raster. Anything else (ASCII `P3`, `maxval != 255`,
    /// a truncated raster) is rejected rather than guessed at.
    fn parse(bytes: &[u8]) -> Result<Self, String> {
        let mut pos = 0usize;
        if next_ppm_token(bytes, &mut pos) != Some(&b"P6"[..]) {
            return Err("not a binary P6 PPM (missing \"P6\" magic)".into());
        }
        let width = parse_ppm_number(bytes, &mut pos, "width")?;
        let height = parse_ppm_number(bytes, &mut pos, "height")?;
        let maxval = parse_ppm_number(bytes, &mut pos, "maxval")?;
        if maxval != 255 {
            return Err(format!("PPM maxval is {maxval}, expected 255"));
        }
        // Exactly one whitespace byte ends the header; a CRLF pair counts as one.
        match bytes.get(pos).copied() {
            Some(b'\r') if bytes.get(pos + 1) == Some(&b'\n') => pos += 2,
            Some(b'\r' | b'\n' | b' ' | b'\t') => pos += 1,
            _ => return Err("PPM header does not end with a whitespace byte".into()),
        }
        let width = usize::try_from(width).map_err(|_| "PPM width is out of range")?;
        let height = usize::try_from(height).map_err(|_| "PPM height is out of range")?;
        let expected = width
            .checked_mul(height)
            .and_then(|pixels| pixels.checked_mul(3))
            .ok_or_else(|| format!("PPM {width}x{height} raster size overflows"))?;
        let raster = &bytes[pos..];
        if raster.len() < expected {
            return Err(format!(
                "PPM raster is truncated: {} bytes, expected {expected} for {width}x{height}",
                raster.len()
            ));
        }
        Ok(Ppm {
            width,
            height,
            pixels: raster[..expected].to_vec(),
        })
    }

    fn pixel(&self, x: usize, y: usize) -> [u8; 3] {
        let base = (y * self.width + x) * 3;
        [
            self.pixels[base],
            self.pixels[base + 1],
            self.pixels[base + 2],
        ]
    }
}

/// Return the next header token of a PPM, skipping whitespace and `#` comments.
fn next_ppm_token<'a>(bytes: &'a [u8], pos: &mut usize) -> Option<&'a [u8]> {
    while *pos < bytes.len() {
        match bytes[*pos] {
            b' ' | b'\t' | b'\r' | b'\n' => *pos += 1,
            b'#' => {
                while *pos < bytes.len() && bytes[*pos] != b'\n' {
                    *pos += 1;
                }
            }
            _ => break,
        }
    }
    let start = *pos;
    while *pos < bytes.len() && !bytes[*pos].is_ascii_whitespace() && bytes[*pos] != b'#' {
        *pos += 1;
    }
    (*pos > start).then(|| &bytes[start..*pos])
}

fn parse_ppm_number(bytes: &[u8], pos: &mut usize, what: &str) -> Result<u32, String> {
    let token = next_ppm_token(bytes, pos)
        .ok_or_else(|| format!("PPM header ends before the {what} field"))?;
    std::str::from_utf8(token)
        .ok()
        .and_then(|text| text.parse::<u32>().ok())
        .ok_or_else(|| format!("PPM {what} field is not a number: {token:?}"))
}

/// Check one screenshot pixel against the expected color, allowing
/// [`SCREEN_CHANNEL_TOLERANCE`] per channel.
fn check_screen_pixel(
    ppm: &Ppm,
    at: (usize, usize),
    expected: [u8; 3],
    what: &str,
) -> Result<(), String> {
    let (x, y) = at;
    if x >= ppm.width || y >= ppm.height {
        return Err(format!(
            "screenshot is {}x{}, too small for the {what} probe at ({x},{y})",
            ppm.width, ppm.height
        ));
    }
    let found = ppm.pixel(x, y);
    let within = found
        .iter()
        .zip(expected.iter())
        .all(|(a, b)| a.abs_diff(*b) <= SCREEN_CHANNEL_TOLERANCE);
    if within {
        Ok(())
    } else {
        Err(format!(
            "screenshot pixel at ({x},{y}) is {found:?}, expected {what} {expected:?} (±{SCREEN_CHANNEL_TOLERANCE})"
        ))
    }
}

/// Validate the three pixels M6c's `gfx` program is required to draw: the
/// displayed (physical) framebuffer's bottom-right corner in magenta, plus the
/// green and blue rectangles at (48,48) and (128,48).
fn validate_screen(ppm: &Ppm) -> Result<(), String> {
    if ppm.width == 0 || ppm.height == 0 {
        return Err("screenshot has a zero dimension".into());
    }
    check_screen_pixel(
        ppm,
        (ppm.width - 1, ppm.height - 1),
        SCREEN_CORNER,
        "corner",
    )?;
    check_screen_pixel(ppm, SCREEN_GREEN_AT, SCREEN_GREEN, "green rectangle")?;
    check_screen_pixel(ppm, SCREEN_BLUE_AT, SCREEN_BLUE, "blue rectangle")?;
    Ok(())
}

/// Build the QMP `screendump` request for `path`: one line of JSON, forward
/// slashes as QEMU expects, quotes/backslashes escaped.
fn screendump_json(path: &Path) -> String {
    let mut name = path.to_string_lossy().replace('\\', "/");
    name = name.replace('"', "\\\"");
    format!("{{\"execute\":\"screendump\",\"arguments\":{{\"filename\":\"{name}\"}}}}")
}

/// Ask QEMU for a screenshot of the current display, parse the P6 PPM it writes
/// and verify the pixels `gfx` must have presented.
fn capture_screen(qmp: &mut Qmp, stage: BootStage) -> Result<(), String> {
    let path = screen_path(stage);
    // screendump overwrites an existing file, but a stale leftover would mask a
    // failed capture, so start from "no file".
    if path.exists() {
        let _ = std::fs::remove_file(&path);
    }
    let request = screendump_json(&path);
    qmp.command(&request)
        .map_err(|e| format!("screendump request failed: {e}"))?;
    let deadline = Instant::now() + Duration::from_secs(5);
    let bytes = loop {
        match std::fs::read(&path) {
            Ok(bytes) if !bytes.is_empty() => break bytes,
            _ if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(50)),
            _ => {
                return Err(format!(
                    "screendump produced no file at {} within 5 s",
                    path.display()
                ));
            }
        }
    };
    let ppm = Ppm::parse(&bytes).map_err(|e| format!("{}: {e}", path.display()))?;
    validate_screen(&ppm).map_err(|e| format!("{}: {e}", path.display()))?;
    println!(
        "[xtask] {} screenshot OK: {} ({}x{}, P6 maxval 255; magenta corner, green (48,48), blue (128,48))",
        stage.label(),
        path.display(),
        ppm.width,
        ppm.height
    );
    Ok(())
}

fn fatal_reason(text: &str) -> Option<String> {
    for pattern in [
        "M3 FAIL",
        "PANIC",
        "panicked at",
        " FAIL",
        "ERROR:",
        // The kernel's trap handler prints this on the *unexpected* #PF branch
        // only; the M2 self-test reaches `M2 #PF caught` instead.
        "unexpected #PF",
    ] {
        if text.contains(pattern) {
            return Some(format!("guest reported {pattern:?}"));
        }
    }
    // The M2 self-test deliberately triggers #PF, so `EXCEPTION #PF` is
    // expected on the success path (the kernel prints it before `M2 #PF
    // caught`). Every other exception vector is unexpected during M3
    // acceptance.
    for code in ["#UD", "#GP", "#DF", "#SS", "#AC", "#DE"] {
        let needle = format!("EXCEPTION {code}");
        if text.contains(&needle) {
            return Some(format!("unexpected exception {code}"));
        }
    }
    None
}

/// Tracks how long the serial console is still drained after a fatal guest
/// error, so the kernel's diagnostic dump is captured before QEMU is killed.
///
/// The drain ends as soon as *all* of these hold:
/// - at least [`FATAL_DRAIN_MIN`] has elapsed since the error was spotted,
/// - the console has been quiet for [`FATAL_DRAIN_QUIET`], or
///   [`FATAL_DRAIN_MAX`] has elapsed (a guest that never stops printing must
///   not stall the run).
///
/// This is deliberately a pure time/state machine so it can be unit tested
/// without QEMU or a socket.
struct FatalDrain {
    since: Instant,
    last_data: Instant,
}

impl FatalDrain {
    fn new(now: Instant) -> Self {
        Self {
            since: now,
            last_data: now,
        }
    }

    fn note_bytes(&mut self, now: Instant) {
        self.last_data = now;
    }

    fn done(&self, now: Instant) -> bool {
        let elapsed = now.saturating_duration_since(self.since);
        if elapsed < FATAL_DRAIN_MIN {
            return false;
        }
        if elapsed >= FATAL_DRAIN_MAX {
            return true;
        }
        now.saturating_duration_since(self.last_data) >= FATAL_DRAIN_QUIET
    }
}

fn boot_and_accept(qemu: &Path, ovmf: &Path, stage: BootStage) -> Result<(), String> {
    let log_path = stage.log_path();
    let mut log =
        File::create(&log_path).map_err(|e| format!("create {}: {e}", log_path.display()))?;
    let serial_port = free_tcp_port()?;
    let qmp_port = free_tcp_port()?;

    println!(
        "[xtask] {}: booting {} under QEMU/OVMF",
        stage.label(),
        esp_image().display()
    );
    println!("[xtask]   firmware: {}", ovmf.display());
    println!(
        "[xtask]   serial:   tcp 127.0.0.1:{serial_port} (bidirectional) -> {}",
        log_path.display()
    );
    println!(
        "[xtask]   keyboard: QMP tcp 127.0.0.1:{qmp_port} (send-key a, then d + serial \"m6c\")"
    );

    let (mut child, stderr_buf) = spawn_qemu(qemu, ovmf, serial_port, qmp_port)?;

    let outcome = (|| -> Result<(), String> {
        let serial = connect_retry(serial_port, Duration::from_secs(10))
            .map_err(|e| format!("serial chardev connect: {e}"))?;
        serial
            .set_read_timeout(Some(Duration::from_millis(100)))
            .map_err(|e| format!("serial read timeout: {e}"))?;
        let qmp = Qmp::connect(qmp_port)?;
        println!("[xtask] QMP handshake OK (qmp_capabilities)");
        run_session(&mut child, serial, qmp, &mut log, &log_path, stage)
    })();

    let _ = child.kill();
    let _ = child.wait();

    // `target/serial.log` always holds a copy of the latest (second) boot's full
    // transcript, on success *and* on failure.
    if stage == BootStage::Second {
        if let Err(e) = std::fs::copy(&log_path, serial_log()) {
            eprintln!(
                "[xtask] warning: could not copy {} to {}: {e}",
                log_path.display(),
                serial_log().display()
            );
        }
    }

    match outcome {
        Ok(()) => {
            let text = std::fs::read_to_string(&log_path).unwrap_or_default();
            println!(
                "[xtask] {} OK — all {} markers present:",
                stage.label(),
                required_markers(stage).len()
            );
            for line in text.lines().filter(|l| l.starts_with("[Caelum")) {
                println!("  {line}");
            }
            Ok(())
        }
        Err(e) => Err(format!(
            "{} failed: {e}\n--- serial log ({}) tail ---\n{}\n--- qemu stderr ---\n{}",
            stage.label(),
            log_path.display(),
            log_tail(&log_path, 60),
            stderr_text(&stderr_buf)
        )),
    }
}

fn run_session(
    child: &mut Child,
    mut serial: TcpStream,
    mut qmp: Qmp,
    log: &mut File,
    log_path: &Path,
    stage: BootStage,
) -> Result<(), String> {
    let total = total_timeout();
    let started = Instant::now();
    let boot_deadline = started + BOOT_TIMEOUT.min(total);
    let total_deadline = started + total;

    // Test-only escape hatch: inject without waiting for `M3 input ready` so
    // the injection plumbing can be smoke-tested against a kernel that does
    // not speak M3 yet.
    let force_inject = env::var_os("CAELUM_TEST_INJECT_NOW").is_some();

    let markers = required_markers(stage);
    let mut announced = vec![false; markers.len()];
    let mut raw: Vec<u8> = Vec::new();
    let mut text = String::new();
    let mut injected = false;
    let mut injected_at: Option<Instant> = None;
    // M6c: one screenshot once `gfx` reports its display round trip, and one
    // second injection (PS/2 `d` + serial `m6c`) once it is ready for input.
    let mut screen_captured = false;
    let mut m6c_injected = false;
    let mut m6c_injected_at: Option<Instant> = None;
    // Once a fatal guest error is seen the run can only fail, but the serial
    // console is drained for a short window first (see [`FatalDrain`]).
    let mut fatal: Option<String> = None;
    let mut fatal_drain: Option<FatalDrain> = None;
    let mut buf = [0u8; 8192];

    loop {
        let mut got_bytes = false;
        match serial.read(&mut buf) {
            Ok(0) => {
                if let Ok(Some(status)) = child.try_wait() {
                    let missing = missing_markers(&text, stage);
                    return Err(match fatal.as_deref() {
                        Some(reason) => format!(
                            "guest failed: {reason} (qemu exited: {status}; missing markers: {:?})",
                            missing
                        ),
                        None => format!(
                            "qemu exited ({status}) while {} marker(s) were still missing: {:?}",
                            missing.len(),
                            missing
                        ),
                    });
                }
                std::thread::sleep(Duration::from_millis(20));
            }
            Ok(n) => {
                log.write_all(&buf[..n])
                    .and_then(|_| log.flush())
                    .map_err(|e| format!("write {}: {e}", log_path.display()))?;
                raw.extend_from_slice(&buf[..n]);
                text = String::from_utf8_lossy(&raw).into_owned();
                got_bytes = true;
            }
            Err(ref e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) => {}
            Err(e) => return Err(format!("serial read: {e}")),
        }

        let now = Instant::now();
        if got_bytes {
            if let Some(drain) = fatal_drain.as_mut() {
                drain.note_bytes(now);
            }
        }

        for (i, marker) in markers.iter().enumerate() {
            if !announced[i] && text.contains(marker) {
                announced[i] = true;
                println!("[serial] {marker}");
            }
        }

        // Fatal handling: stop looking for success, but keep draining the
        // serial console for a short window so the kernel's cr2/rip/register
        // dump reaches the log before QEMU is killed. The failure itself is
        // never swallowed — the original reason is returned either way.
        if let Some(reason) = fatal.as_deref() {
            let drained = fatal_drain.as_ref().map(|d| d.done(now)).unwrap_or(true);
            if drained {
                return Err(format!(
                    "guest failed: {reason} (missing markers: {:?})",
                    missing_markers(&text, stage)
                ));
            }
            continue;
        }
        if let Some(reason) = fatal_reason(&text) {
            println!(
                "[xtask] fatal guest error detected ({reason}); draining serial for up to {:?} to capture the full diagnostic",
                FATAL_DRAIN_MAX
            );
            fatal = Some(reason);
            fatal_drain = Some(FatalDrain::new(now));
            continue;
        }

        // Inject exactly once, only after the guest is ready for it.
        if !injected && (force_inject || text.contains(M3_INPUT_READY)) {
            qmp.send_key_a()
                .map_err(|e| format!("keyboard injection failed: {e}"))?;
            serial
                .write_all(SERIAL_INJECT_BYTE)
                .and_then(|_| serial.flush())
                .map_err(|e| format!("serial injection failed: {e}"))?;
            injected = true;
            injected_at = Some(Instant::now());
            if force_inject {
                println!("[xtask] TEST MODE: injected early (CAELUM_TEST_INJECT_NOW)");
            }
            println!(
                "[xtask] injected PS/2 key 'a' via QMP send-key and serial byte 0x{:02x} '{}'",
                SERIAL_INJECT_BYTE[0], SERIAL_INJECT_BYTE[0] as char
            );
        }

        // M6c: take one screenshot of the presented framebuffer. The pixels are
        // checked, so a display that never presented (or presented the wrong
        // colors) fails immediately instead of hiding behind the marker text.
        if !screen_captured && text.contains(M6C_DISPLAY) {
            std::thread::sleep(SCREEN_CAPTURE_DELAY);
            capture_screen(&mut qmp, stage)?;
            screen_captured = true;
        }

        // M6c: the second injection, only after `gfx` says it is ready for input
        // (and only while it still needs it).
        if !m6c_injected && text.contains(M6C_INPUT_READY) && !text.contains(M6C_INPUT) {
            qmp.send_key_d()
                .map_err(|e| format!("M6c keyboard injection failed: {e}"))?;
            // QMP only synthesizes the `make` at once; the `break` follows after
            // the hold time. Wait it out so the guest observes make -> break ->
            // m -> 6 -> c (its input test asserts exactly that order).
            std::thread::sleep(M6C_KEY_SETTLE);
            serial
                .write_all(M6C_SERIAL_BYTES)
                .and_then(|_| serial.flush())
                .map_err(|e| format!("M6c serial injection failed: {e}"))?;
            m6c_injected = true;
            m6c_injected_at = Some(Instant::now());
            println!(
                "[xtask] injected second PS/2 key 'd' via QMP send-key (settled {} ms) and serial bytes {:?}",
                M6C_KEY_SETTLE.as_millis(),
                String::from_utf8_lossy(M6C_SERIAL_BYTES)
            );
        }

        let missing = missing_markers(&text, stage);
        if missing.is_empty() {
            // A screenshot is part of acceptance, not a bonus: capture it even
            // when the serial markers arrived in one rounded chunk.
            if !screen_captured {
                capture_screen(&mut qmp, stage)?;
            }
            qmp.drain();
            return match acceptance_error(&text, stage) {
                None => {
                    println!(
                        "[xtask] {} completed the milestone: M3 injection acknowledged, M6c display screenshot verified, M6c second injection acknowledged, {} markers present in order and {FINAL_MARKER:?} last",
                        stage.label(),
                        required_markers(stage).len()
                    );
                    Ok(())
                }
                Some(error) => Err(format!(
                    "all markers appeared but the marker order contract is broken: {error}"
                )),
            };
        }

        // A halted guest is never going to print another marker, so report the
        // gap now rather than waiting for the acceptance timeout.
        if let Some(error) = halted_early(&text, stage) {
            return Err(error);
        }

        let now = Instant::now();
        if !injected && now >= boot_deadline {
            return Err(format!(
                "never saw {:?} within {:?} (missing markers: {:?})",
                M3_INPUT_READY,
                now.duration_since(started),
                missing
            ));
        }
        if let Some(at) = injected_at {
            let acked = M3_INPUT_ACK.iter().all(|m| text.contains(m));
            if !acked && now.duration_since(at) >= INPUT_TIMEOUT {
                return Err(format!(
                    "input was injected but the guest produced no input acknowledgement within {:?} (missing: {:?})",
                    INPUT_TIMEOUT, missing
                ));
            }
        }
        if let Some(at) = m6c_injected_at {
            if !text.contains(M6C_INPUT) && now.duration_since(at) >= INPUT_TIMEOUT {
                return Err(format!(
                    "M6c input was injected but the gfx program produced no {:?} within {:?} (missing: {:?})",
                    M6C_INPUT, INPUT_TIMEOUT, missing
                ));
            }
        }
        if now >= total_deadline {
            return Err(format!(
                "acceptance timeout after {:?}; missing markers: {:?}",
                total, missing
            ));
        }
    }
}

fn main() {
    let args: Vec<String> = env::args().skip(1).collect();
    let cmd = args.first().map(String::as_str).unwrap_or("help");
    let result = match cmd {
        "build" => cmd_build(),
        "check" => cmd_check(),
        "image" => cmd_image(),
        "qemu" => cmd_qemu(),
        "test" => cmd_check()
            .and_then(|_| cmd_image())
            .and_then(|_| cmd_qemu()),
        _ => {
            println!("usage: cargo xtask <build|check|image|qemu|test>");
            Ok(())
        }
    };
    if let Err(e) = result {
        eprintln!("[xtask] ERROR: {e}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn m9d1_release_artifacts_live_under_the_release_profile() {
        // The kernel reads these two files back from the FAT volume, so a debug
        // or stale copy must never be accepted: pin the documented release paths.
        assert_eq!(
            linux_dyn_elf(),
            target_dir()
                .join(NONE_TARGET)
                .join("release")
                .join(LINUX_DYN_PKG)
        );
        assert_eq!(
            interp_elf(),
            target_dir()
                .join(NONE_TARGET)
                .join("release")
                .join(INTERP_PKG)
        );
        assert_eq!(
            vdso_elf(),
            target_dir()
                .join(NONE_TARGET)
                .join("release")
                .join(VDSO_PKG)
        );
        assert_ne!(linux_dyn_elf(), none_binary(LINUX_DYN_PKG));
        assert_ne!(interp_elf(), none_binary(INTERP_PKG));
        assert_ne!(vdso_elf(), none_binary(VDSO_PKG));
    }

    #[test]
    fn marker_sets_are_complete_and_unique() {
        // The M1—M5a regression set that every boot of the M5b run must print:
        // 8 M1/M2 + 9 M3 + 10 M4 + 6 M5a markers.
        let base = base_markers();
        assert_eq!(base.len(), 33);
        assert_eq!(*M12_MARKERS.last().unwrap(), FINAL_MARKER);
        assert_eq!(FINAL_MARKER, "[CaelumKernel] M2 #PF caught");
        assert!(base.contains(&FINAL_MARKER));
        assert!(base.contains(&M3_INPUT_READY));
        for m in M12_MARKERS
            .iter()
            .chain(M3_MARKERS.iter())
            .chain(M4_MARKERS.iter())
            .chain(M5A_MARKERS.iter())
        {
            assert!(base.contains(m), "missing regression marker {m:?}");
        }

        // Each boot adds the six M5b base markers, its own stage markers, the
        // four M5c1 markers, the three M5c2 markers, the eight M5c3 markers, the
        // four M6a1 markers, the ten M6a2 markers, the single M6b1 marker, the
        // single M6b2a marker, the five M6b2 scheduling lines, the five M6c
        // display/input lines, the six M7a loopback lines, the fourteen M7b
        // native socket lines, the seven M7d user lines, the two M8a user lines,
        // the two M8b lines, the single M8c line, the single M8d line and the
        // single M7d kernel verdict.
        for stage in [BootStage::First, BootStage::Second] {
            let all = required_markers(stage);
            assert_eq!(
                all.len(),
                base.len()
                    + M6B1_MARKERS.len()
                    + M6B2A_MARKERS.len()
                    + M5B_BASE_MARKERS.len()
                    + stage_markers(stage).len()
                    + M5C1_MARKERS.len()
                    + M5C2_MARKERS.len()
                    + M5C3_MARKERS.len()
                    + M6A_MARKERS.len()
                    + M6A2_MARKERS.len()
                    + M6B2_MARKERS.len()
                    + M6C_MARKERS.len()
                    + M7A_MARKERS.len()
                    + M7B_MARKERS.len()
                    + (M7D_MARKERS.len() - 1)
                    + M8A_MARKERS.len()
                    + M8B_MARKERS.len()
                    + M8C_MARKERS.len()
                    + M8D_MARKERS.len()
                    + M8E_MARKERS.len()
                    + M8F_MARKERS.len()
                    + M8G_MARKERS.len()
                    + M8H_MARKERS.len()
                    + M9A_MARKERS.len()
                    + M9B_MARKERS.len()
                    + M9C_MARKERS.len()
                    + M9D_MARKERS.len()
                    + M9E_MARKERS.len()
                    + M9F_MARKERS.len()
                    + M10A_MARKERS.len()
                    + M7C_MARKERS.len()
                    + 1,
                "unexpected marker count for the {}",
                stage.label()
            );
            for m in M6B1_MARKERS
                .iter()
                .chain(M5B_BASE_MARKERS)
                .chain(stage_markers(stage))
                .chain(M5C1_MARKERS)
                .chain(M5C2_MARKERS)
                .chain(M5C3_MARKERS)
                .chain(M6A_MARKERS)
                .chain(M6A2_MARKERS)
                .chain(M6B2_MARKERS)
                .chain(M6C_MARKERS)
                .chain(M7A_MARKERS)
                .chain(M7B_MARKERS)
                .chain(M7D_MARKERS)
                .chain(M8A_MARKERS)
                .chain(M8B_MARKERS)
                .chain(M8C_MARKERS)
                .chain(M8D_MARKERS)
                .chain(M8E_MARKERS)
                .chain(M8F_MARKERS)
                .chain(M8G_MARKERS)
                .chain(M8H_MARKERS)
                .chain(M9A_MARKERS)
                .chain(M9B_MARKERS)
                .chain(M9C_MARKERS)
                .chain(M9D_MARKERS)
                .chain(M9E_MARKERS)
                .chain(M9F_MARKERS)
                .chain(M10A_MARKERS)
                .chain(M7C_MARKERS)
            {
                assert!(all.contains(m), "missing {} marker {m:?}", stage.label());
            }
            let mut unique = all.clone();
            unique.sort_unstable();
            unique.dedup();
            assert_eq!(
                unique.len(),
                all.len(),
                "duplicate marker entries in the {}",
                stage.label()
            );
        }
        // 138 markers on either boot: 33 regression + one M6b1 AP-online + one
        // M6b2a locking + six M5b base + two stage markers + four M5c1 + three
        // M5c2 + eight M5c3 + four M6a1 + ten M6a2 + five M6b2 scheduling lines +
        // five M6c display/input lines + six M7a loopback lines + fourteen M7b
        // native socket lines + seven M7d user lines + two M8a user lines + two
        // M8b user lines + one M8c user line + one M8d user line + one M8e user
        // line + one M8f futex user line + one M8f tls user line + two M8g user
        // lines + two M8h user lines + three M9a user lines + four M9b user
        // lines + one M9c lock-domain user line + two M9d1 dynamic-ELF user
        // lines + one M9d2 vDSO user line + one M9e shared-library user line + one M9f three-library user line + one
        // M7c NIC probe line + one M7d kernel verdict.
        assert_eq!(required_markers(BootStage::First).len(), 138);
        assert_eq!(required_markers(BootStage::Second).len(), 138);
        // Stage markers are strictly per boot, and M5b OK closes the second one.
        for m in M5B_FIRST_MARKERS {
            assert!(!required_markers(BootStage::Second).contains(m));
        }
        assert_eq!(
            stage_markers(BootStage::Second).last().copied(),
            Some("[CaelumKernel] M5b OK")
        );
        assert!(!required_markers(BootStage::First).contains(&"[CaelumKernel] M5b OK"));
        // `M7d OK` closes the required list on both boots: the Linux64
        // personality test and its verdict are the last words before the
        // deliberate page fault.
        for stage in [BootStage::First, BootStage::Second] {
            assert_eq!(*required_markers(stage).last().unwrap(), M7D_KERNEL_OK);
        }

        // `M3 input ready` must be declared before the acknowledgements so the
        // injection contract stays readable.
        let pos = |needle: &str| M3_MARKERS.iter().position(|m| *m == needle).unwrap();
        assert!(pos(M3_INPUT_READY) < pos(M3_INPUT_OK));
        assert!(pos(M3_INPUT_READY) < pos(M3_SERIAL_OK));
        assert!(M3_INPUT_ACK.iter().all(|m| M3_MARKERS.contains(m)));
    }

    #[test]
    fn missing_markers_tracks_progress() {
        let text = "[CaelumLoader] ExitBootServices OK\n[CaelumKernel] M3 clock OK";
        let missing = missing_markers(text, BootStage::First);
        assert_eq!(missing.len(), 136);
        assert!(!missing.contains(&"[CaelumLoader] ExitBootServices OK"));
        assert!(!missing.contains(&"[CaelumKernel] M3 clock OK"));
        // Both boots require the same number of markers now: one M6b1 marker,
        // one M6b2a marker, six M5b base markers, two stage-specific ones, four
        // M5c1, three M5c2, eight M5c3, four M6a1, ten M6a2, five M6b2, five
        // M6c, six M7a, fourteen M7b, seven M7d user, two M8a, two M8b, one M8c,
        // one M8d, one M8e, two M8f, two M8g, two M8h, three M9a, four M9b, one
        // M9c, two M9d1, one M9d2, one M9e, one M9f, one M7c NIC probe and one M7d kernel verdict on top of the 33 regressions.
        assert_eq!(missing_markers(text, BootStage::Second).len(), 136);
    }

    #[test]
    fn boot_log_paths_are_per_boot() {
        let first = BootStage::First.log_path();
        let second = BootStage::Second.log_path();
        assert_ne!(first, second);
        assert_eq!(first.file_name().unwrap(), "serial-boot1.log");
        assert_eq!(second.file_name().unwrap(), "serial-boot2.log");
        assert_eq!(serial_log().file_name().unwrap(), "serial.log");
        assert_eq!(BootStage::First.label(), "first boot");
        assert_eq!(BootStage::Second.label(), "second boot");
    }

    #[test]
    fn m5b_markers_are_exact() {
        // Frozen strings: they are the contract with the kernel side, so a
        // rename breaks the build instead of silently weakening acceptance.
        let expected: &[&str] = &[
            "[CaelumKernel] M5b mcfg OK",
            "[CaelumKernel] M5b pci OK",
            "[CaelumKernel] M5b virtio OK",
            "[CaelumKernel] M5b block OK",
            "[CaelumKernel] M5b fat32 OK",
            "[CaelumKernel] M5b ext2 OK",
        ];
        assert_eq!(M5B_BASE_MARKERS, expected);
        assert_eq!(
            M5B_FIRST_MARKERS,
            [
                "[CaelumKernel] M5b persistence written",
                "[CaelumKernel] M5b first boot OK",
            ]
        );
        assert_eq!(
            M5B_SECOND_MARKERS,
            ["[CaelumKernel] M5b persistence OK", "[CaelumKernel] M5b OK",]
        );
        for m in M5B_BASE_MARKERS
            .iter()
            .chain(M5B_FIRST_MARKERS)
            .chain(M5B_SECOND_MARKERS)
        {
            assert!(m.starts_with("[CaelumKernel] "), "{m:?} lacks the tag");
            assert_ne!(*m, FINAL_MARKER, "{m:?} must not be the final marker");
        }

        // Both M5b blocks sit after every M5a marker, the M5c1, M5c2 and M5c3
        // blocks follow the stage's own block, and `M5 OK` closes the required
        // list (the deliberate page fault is the last marker *emitted*, which
        // `acceptance_requires_the_final_marker_last` covers).
        for stage in [BootStage::First, BootStage::Second] {
            let all = required_markers(stage);
            let first_m5b = all
                .iter()
                .position(|m| *m == M5B_BASE_MARKERS[0])
                .expect("M5b block missing");
            assert!(first_m5b > all.iter().position(|m| *m == M5A_MARKERS[5]).unwrap());
            let stage_last = *stage_markers(stage).last().unwrap();
            let last_stage = all
                .iter()
                .position(|m| *m == stage_last)
                .expect("stage block missing");
            let first_m5c1 = all
                .iter()
                .position(|m| *m == M5C1_MARKERS[0])
                .expect("M5c1 block missing");
            assert!(
                last_stage < first_m5c1,
                "{}: the M5c1 block must follow the M5b stage block",
                stage.label()
            );
            let first_m5c2 = all
                .iter()
                .position(|m| *m == M5C2_MARKERS[0])
                .expect("M5c2 block missing");
            assert!(
                first_m5c1 + M5C1_MARKERS.len() <= first_m5c2,
                "{}: the M5c2 block must follow the M5c1 block",
                stage.label()
            );
            let first_m5c3 = all
                .iter()
                .position(|m| *m == M5C3_MARKERS[0])
                .expect("M5c3 block missing");
            assert!(
                first_m5c2 + M5C2_MARKERS.len() <= first_m5c3,
                "{}: the M5c3 block must follow the M5c2 block",
                stage.label()
            );
            let first_m6a = all
                .iter()
                .position(|m| *m == M6A_MARKERS[0])
                .expect("M6a1 block missing");
            assert!(
                first_m5c3 + M5C3_MARKERS.len() <= first_m6a,
                "{}: the M6a1 block must follow the M5c3 block",
                stage.label()
            );
            let first_m6a2 = all
                .iter()
                .position(|m| *m == M6A2_MARKERS[0])
                .expect("M6a2 block missing");
            assert!(
                first_m6a + M6A_MARKERS.len() <= first_m6a2,
                "{}: the M6a2 block must follow the M6a1 block",
                stage.label()
            );
            let first_m6b2 = all
                .iter()
                .position(|m| *m == M6B2_MARKERS[0])
                .expect("M6b2 block missing");
            assert!(
                first_m6a2 + M6A2_MARKERS.len() <= first_m6b2,
                "{}: the M6b2 block must follow the M6a2 block",
                stage.label()
            );
            let first_m6c = all
                .iter()
                .position(|m| *m == M6C_MARKERS[0])
                .expect("M6c block missing");
            assert!(
                first_m6b2 + M6B2_MARKERS.len() <= first_m6c,
                "{}: the M6c block must follow the M6b2 block",
                stage.label()
            );
            // `M6c OK` closes the required list, after `M6b2 OK`.
            assert_eq!(*all.last().unwrap(), M7D_KERNEL_OK);
        }
    }

    #[test]
    fn m5c1_markers_are_exact_and_ordered() {
        // Frozen strings and tags: the kernel and both user programs own these
        // lines, so a rename must break the build instead of silently weakening
        // acceptance.
        assert_eq!(M5C1_MOUNTS_READY, "[CaelumKernel] M5c mounts ready");
        assert_eq!(M5C1_INIT_FILES, "[CaelumInit] M5c files OK");
        assert_eq!(M5C1_CHILD_FILES, "[CaelumChild] M5c files OK");
        assert_eq!(M5C1_OK, "[CaelumKernel] M5c1 OK");
        assert_eq!(
            M5C1_MARKERS,
            [
                "[CaelumKernel] M5c mounts ready",
                "[CaelumInit] M5c files OK",
                "[CaelumChild] M5c files OK",
                "[CaelumKernel] M5c1 OK",
            ]
        );
        for m in M5C1_MARKERS {
            assert!(
                m.starts_with("[CaelumKernel] ")
                    || m.starts_with("[CaelumInit] ")
                    || m.starts_with("[CaelumChild] "),
                "{m:?} lacks a kernel/init/child tag"
            );
            assert_ne!(*m, FINAL_MARKER, "{m:?} must not be the final marker");
        }
        let mut unique = M5C1_MARKERS.to_vec();
        unique.sort_unstable();
        unique.dedup();
        assert_eq!(unique.len(), M5C1_MARKERS.len(), "duplicate M5c1 markers");

        // The real emission order (early mounts, user programs, verdict) is
        // accepted on both boots.
        for stage in [BootStage::First, BootStage::Second] {
            let text = complete_transcript(stage);
            assert_eq!(acceptance_error(&text, stage), None, "{}", stage.label());
        }
        let stage = BootStage::First;

        // Dropping one of the four markers still fails.
        let mut lines = boot_lines(stage);
        lines.retain(|m| *m != M5C1_MOUNTS_READY);
        assert_eq!(
            missing_markers(&transcript(&lines), stage),
            vec![M5C1_MOUNTS_READY]
        );

        // `M5c mounts ready` must precede the user programs reporting.
        let mut lines = boot_lines(stage);
        move_marker(&mut lines, M5C1_MOUNTS_READY, M5C1_CHILD_FILES);
        let text = transcript(&lines);
        assert!(missing_markers(&text, stage).is_empty());
        let err = acceptance_error(&text, stage).expect("late mounts marker accepted");
        assert!(err.contains("must appear before"), "{err}");

        // Both user file markers must precede the kernel's `M4 exit OK`.
        let mut lines = boot_lines(stage);
        move_marker(&mut lines, M5C1_INIT_FILES, "[CaelumKernel] M4 OK");
        let text = transcript(&lines);
        let err = acceptance_error(&text, stage).expect("late user file marker accepted");
        assert!(err.contains("must appear before"), "{err}");

        // `M5c1 OK` is the kernel verdict: it must follow the M5b persistence
        // markers and precede the deliberate page fault.
        let mut lines = boot_lines(stage);
        move_marker(&mut lines, M5C1_OK, M5B_BASE_MARKERS[0]);
        let text = transcript(&lines);
        let err = acceptance_error(&text, stage).expect("early verdict accepted");
        assert!(err.contains("must appear before"), "{err}");
        assert!(!acceptance_reached(&text, stage));
    }

    #[test]
    fn m5c2_markers_are_exact_and_ordered() {
        // Frozen strings and tags: the kernel and both user programs own these
        // lines, so a rename must break the build instead of silently weakening
        // acceptance.
        assert_eq!(M5C2_INIT_MMAP, "[CaelumInit] M5c mmap OK");
        assert_eq!(M5C2_CHILD_MMAP, "[CaelumChild] M5c mmap OK");
        assert_eq!(M5C2_OK, "[CaelumKernel] M5c2 OK");
        assert_eq!(
            M5C2_MARKERS,
            [
                "[CaelumInit] M5c mmap OK",
                "[CaelumChild] M5c mmap OK",
                "[CaelumKernel] M5c2 OK",
            ]
        );
        for m in M5C2_MARKERS {
            assert!(
                m.starts_with("[CaelumKernel] ")
                    || m.starts_with("[CaelumInit] ")
                    || m.starts_with("[CaelumChild] "),
                "{m:?} lacks a kernel/init/child tag"
            );
            assert_ne!(*m, FINAL_MARKER, "{m:?} must not be the final marker");
        }
        let mut unique = M5C2_MARKERS.to_vec();
        unique.sort_unstable();
        unique.dedup();
        assert_eq!(unique.len(), M5C2_MARKERS.len(), "duplicate M5c2 markers");

        // The real emission order (user programs, verdict) is accepted on both
        // boots.
        for stage in [BootStage::First, BootStage::Second] {
            let text = complete_transcript(stage);
            assert_eq!(acceptance_error(&text, stage), None, "{}", stage.label());
        }
        let stage = BootStage::First;

        // Dropping one of the three markers still fails.
        let mut lines = boot_lines(stage);
        lines.retain(|m| *m != M5C2_OK);
        assert_eq!(
            missing_markers(&transcript(&lines), stage),
            vec![M5C2_OK],
            "dropping M5c2 OK must be reported"
        );

        // Both mmap markers must follow their file marker and still precede
        // `M4 exit OK` (they are user-space work, not kernel verdicts).
        let mut lines = boot_lines(stage);
        move_marker(&mut lines, M5C2_INIT_MMAP, M5C1_MOUNTS_READY);
        let text = transcript(&lines);
        assert!(missing_markers(&text, stage).is_empty());
        let err = acceptance_error(&text, stage).expect("mmap before the file round trip accepted");
        assert!(err.contains("must appear before"), "{err}");

        let mut lines = boot_lines(stage);
        move_marker(&mut lines, M5C2_CHILD_MMAP, "[CaelumKernel] M4 OK");
        let text = transcript(&lines);
        let err = acceptance_error(&text, stage).expect("late child mmap marker accepted");
        assert!(err.contains("must appear before"), "{err}");

        // `M5c2 OK` is the kernel verdict: it must follow `M5c1 OK` and precede
        // the deliberate page fault.
        let mut lines = boot_lines(stage);
        move_marker(&mut lines, M5C2_OK, M5C1_OK);
        let text = transcript(&lines);
        let err = acceptance_error(&text, stage).expect("early M5c2 verdict accepted");
        assert!(err.contains("must appear before"), "{err}");
        assert!(!acceptance_reached(&text, stage));
    }

    #[test]
    fn m5c3_markers_are_exact_and_ordered() {
        // Frozen strings and tags: the kernel and both user programs own these
        // lines, so a rename must break the build instead of silently weakening
        // acceptance.
        assert_eq!(M5C3_INIT_XATTR, "[CaelumInit] M5c xattr OK");
        assert_eq!(M5C3_INIT_SPARSE, "[CaelumInit] M5c sparse OK");
        assert_eq!(M5C3_INIT_WATCH, "[CaelumInit] M5c watch OK");
        assert_eq!(M5C3_CHILD_LOCKS, "[CaelumChild] M5c locks OK");
        assert_eq!(M5C3_INIT_LOCKS, "[CaelumInit] M5c locks OK");
        assert_eq!(M5C3_FAULTS_OK, "[CaelumKernel] M5c3 faults OK");
        assert_eq!(M5C3_OK, "[CaelumKernel] M5c3 OK");
        assert_eq!(M5_OK, "[CaelumKernel] M5 OK");
        assert_eq!(
            M5C3_MARKERS,
            [
                "[CaelumInit] M5c xattr OK",
                "[CaelumInit] M5c sparse OK",
                "[CaelumInit] M5c watch OK",
                "[CaelumChild] M5c locks OK",
                "[CaelumInit] M5c locks OK",
                "[CaelumKernel] M5c3 faults OK",
                "[CaelumKernel] M5c3 OK",
                "[CaelumKernel] M5 OK",
            ]
        );
        for m in M5C3_MARKERS {
            assert!(
                m.starts_with("[CaelumKernel] ")
                    || m.starts_with("[CaelumInit] ")
                    || m.starts_with("[CaelumChild] "),
                "{m:?} lacks a kernel/init/child tag"
            );
            assert_ne!(*m, FINAL_MARKER, "{m:?} must not be the final marker");
        }
        let mut unique = M5C3_MARKERS.to_vec();
        unique.sort_unstable();
        unique.dedup();
        assert_eq!(unique.len(), M5C3_MARKERS.len(), "duplicate M5c3 markers");

        // The real emission order is accepted on both boots.
        for stage in [BootStage::First, BootStage::Second] {
            let text = complete_transcript(stage);
            assert_eq!(acceptance_error(&text, stage), None, "{}", stage.label());
        }
        let stage = BootStage::First;

        // Dropping the M5 verdict still fails.
        let mut lines = boot_lines(stage);
        lines.retain(|m| *m != M5_OK);
        assert_eq!(
            missing_markers(&transcript(&lines), stage),
            vec![M5_OK],
            "dropping M5 OK must be reported"
        );

        // The `init` walk is files -> mmap -> xattr -> sparse -> watch, and all of
        // it happens before `init` exits.
        let mut lines = boot_lines(stage);
        move_marker(&mut lines, M5C3_INIT_XATTR, M5C2_INIT_MMAP);
        let text = transcript(&lines);
        assert!(missing_markers(&text, stage).is_empty());
        let err = acceptance_error(&text, stage).expect("xattr before mmap accepted");
        assert!(err.contains("must appear before"), "{err}");

        let mut lines = boot_lines(stage);
        move_marker(&mut lines, M5C3_INIT_SPARSE, M5C2_INIT_MMAP);
        let text = transcript(&lines);
        let err = acceptance_error(&text, stage).expect("sparse before xattr accepted");
        assert!(err.contains("must appear before"), "{err}");

        let mut lines = boot_lines(stage);
        move_marker(&mut lines, M5C3_INIT_WATCH, "[CaelumKernel] M4 OK");
        let text = transcript(&lines);
        let err = acceptance_error(&text, stage).expect("watch after init exit accepted");
        assert!(err.contains("must appear before"), "{err}");

        // The child checks locks after its own mmap and still before init exits;
        // init checks locks only after it observed the child (wait marker).
        let mut lines = boot_lines(stage);
        move_marker(&mut lines, M5C3_CHILD_LOCKS, M5C2_CHILD_MMAP);
        let text = transcript(&lines);
        let err = acceptance_error(&text, stage).expect("child locks before mmap accepted");
        assert!(err.contains("must appear before"), "{err}");

        let mut lines = boot_lines(stage);
        move_marker(&mut lines, M5C3_INIT_LOCKS, "[CaelumKernel] M4 OK");
        let text = transcript(&lines);
        let err = acceptance_error(&text, stage).expect("init locks after init exit accepted");
        assert!(err.contains("must appear before"), "{err}");

        let mut lines = boot_lines(stage);
        move_marker(&mut lines, M5C3_INIT_LOCKS, "[CaelumInit] M4 spawn OK");
        let text = transcript(&lines);
        let err =
            acceptance_error(&text, stage).expect("init locks before the child wait accepted");
        assert!(err.contains("must appear before"), "{err}");

        // The verdict chain is M5c1 -> M5c2 -> M5c3 faults -> M5c3 -> M5, and
        // `M5 OK` is the last marker before the deliberate page fault.
        let mut lines = boot_lines(stage);
        move_marker(&mut lines, M5C3_FAULTS_OK, M5C2_OK);
        let text = transcript(&lines);
        let err = acceptance_error(&text, stage).expect("faults verdict before M5c2 accepted");
        assert!(err.contains("must appear before"), "{err}");

        let mut lines = boot_lines(stage);
        move_marker(&mut lines, M5_OK, M5C3_OK);
        let text = transcript(&lines);
        let err = acceptance_error(&text, stage).expect("M5 OK before the M5c3 verdict accepted");
        assert!(err.contains("must appear before"), "{err}");
        assert!(!acceptance_reached(&text, stage));
    }

    #[test]
    fn m6a1_markers_are_exact_and_ordered() {
        // Frozen strings and tags: the kernel and both user programs own these
        // lines, so a rename must break the build instead of silently weakening
        // acceptance.
        assert_eq!(M6A_INIT_TIMER, "[CaelumInit] M6a timer OK");
        assert_eq!(M6A_INIT_EVENT, "[CaelumInit] M6a event OK");
        assert_eq!(M6A_CHILD_EVENT, "[CaelumChild] M6a event OK");
        assert_eq!(M6A_OK, "[CaelumKernel] M6a OK");
        assert_eq!(
            M6A_MARKERS,
            [
                "[CaelumInit] M6a timer OK",
                "[CaelumInit] M6a event OK",
                "[CaelumChild] M6a event OK",
                "[CaelumKernel] M6a OK",
            ]
        );
        for m in M6A_MARKERS {
            assert!(
                m.starts_with("[CaelumKernel] ")
                    || m.starts_with("[CaelumInit] ")
                    || m.starts_with("[CaelumChild] "),
                "{m:?} lacks a kernel/init/child tag"
            );
            assert_ne!(*m, FINAL_MARKER, "{m:?} must not be the final marker");
        }
        let mut unique = M6A_MARKERS.to_vec();
        unique.sort_unstable();
        unique.dedup();
        assert_eq!(unique.len(), M6A_MARKERS.len(), "duplicate M6a1 markers");

        // M6a1 is a slice of M6, not M6: no full-M6 capability may be required
        // by this harness yet.
        for stage in [BootStage::First, BootStage::Second] {
            let all = required_markers(stage);
            for forbidden in [
                "M6 OK",
                "M6 SMP",
                "M6 channel",
                "M6 port",
                "M6 sharedmemory",
            ] {
                assert!(
                    !all.iter().any(|m| m.contains(forbidden)),
                    "{}: M6a1 must not require {forbidden:?}",
                    stage.label()
                );
            }
            // The list now ends with the M6c block; `M5 OK` -> `M6a OK` ->
            // `M6a2 OK` -> `M6b2 OK` -> `M6c OK` stays the verdict order.
            assert_eq!(*all.last().unwrap(), M7D_KERNEL_OK);
            let m5 = all.iter().position(|m| *m == M5_OK).expect("M5 OK missing");
            let m6a = all
                .iter()
                .position(|m| *m == M6A_OK)
                .expect("M6a OK missing");
            let m6a2 = all
                .iter()
                .position(|m| *m == M6A2_OK)
                .expect("M6a2 OK missing");
            let m6b2 = all
                .iter()
                .position(|m| *m == M6B2_OK)
                .expect("M6b2 OK missing");
            let m6c = all
                .iter()
                .position(|m| *m == M7A_MARKERS[0])
                .expect("M6c OK missing");
            assert!(
                m5 < m6a && m6a < m6a2 && m6a2 < m6b2 && m6b2 < m6c,
                "{}: M5 OK -> M6a OK -> M6a2 OK -> M6b2 OK -> M6c OK must stay ordered",
                stage.label()
            );
        }

        // The real emission order is accepted on both boots.
        for stage in [BootStage::First, BootStage::Second] {
            let text = complete_transcript(stage);
            assert_eq!(acceptance_error(&text, stage), None, "{}", stage.label());
        }
        let stage = BootStage::First;

        // Dropping the M6a verdict still fails.
        let mut lines = boot_lines(stage);
        lines.retain(|m| *m != M6A_OK);
        assert_eq!(
            missing_markers(&transcript(&lines), stage),
            vec![M6A_OK],
            "dropping M6a OK must be reported"
        );

        // The user round trips happen after the M5c3 user work and before init
        // exits; reordering them breaks the contract.
        let mut lines = boot_lines(stage);
        move_marker(&mut lines, M6A_INIT_TIMER, M5C3_INIT_WATCH);
        let text = transcript(&lines);
        assert!(missing_markers(&text, stage).is_empty());
        let err = acceptance_error(&text, stage).expect("timer before the sparse walk accepted");
        assert!(err.contains("must appear before"), "{err}");

        let mut lines = boot_lines(stage);
        move_marker(&mut lines, M6A_INIT_EVENT, M6A_INIT_TIMER);
        let text = transcript(&lines);
        let err = acceptance_error(&text, stage).expect("event before the timer accepted");
        assert!(err.contains("must appear before"), "{err}");

        let mut lines = boot_lines(stage);
        move_marker(&mut lines, M6A_CHILD_EVENT, "[CaelumKernel] M4 OK");
        let text = transcript(&lines);
        let err = acceptance_error(&text, stage).expect("child event after init exit accepted");
        assert!(err.contains("must appear before"), "{err}");

        // The M6a verdict closes the stage: it may not precede `M5 OK`.
        let mut lines = boot_lines(stage);
        move_marker(&mut lines, M6A_OK, M5_OK);
        let text = transcript(&lines);
        let err = acceptance_error(&text, stage).expect("M6a OK before M5 OK accepted");
        assert!(err.contains("must appear before"), "{err}");
        assert!(!acceptance_reached(&text, stage));
    }

    #[test]
    fn m6a2_markers_are_exact_and_ordered() {
        // Frozen strings and tags: the kernel and both user programs own these
        // lines, so a rename must break the build instead of silently weakening
        // acceptance.
        assert_eq!(M6A2_INIT_CHANNEL, "[CaelumInit] M6a channel OK");
        assert_eq!(M6A2_CHILD_CHANNEL, "[CaelumChild] M6a channel OK");
        assert_eq!(M6A2_INIT_PORT, "[CaelumInit] M6a port OK");
        assert_eq!(M6A2_CHILD_PORT, "[CaelumChild] M6a port OK");
        assert_eq!(M6A2_INIT_SHM, "[CaelumInit] M6a shm OK");
        assert_eq!(M6A2_CHILD_SHM, "[CaelumChild] M6a shm OK");
        assert_eq!(M6A2_INIT_FUTEX, "[CaelumInit] M6a futex OK");
        assert_eq!(M6A2_CHILD_FUTEX, "[CaelumChild] M6a futex OK");
        assert_eq!(M6A2_INIT_SUBSCRIPTION, "[CaelumInit] M6a subscription OK");
        assert_eq!(M6A2_OK, "[CaelumKernel] M6a2 OK");
        assert_eq!(M6A2_USER_MARKERS.len(), 9, "nine user-space M6a2 markers");
        assert_eq!(M6A2_MARKERS.len(), 10, "nine user markers + M6a2 verdict");
        assert_eq!(&M6A2_MARKERS[..9], M6A2_USER_MARKERS);
        assert_eq!(*M6A2_MARKERS.last().unwrap(), M6A2_OK);
        for m in M6A2_MARKERS {
            assert!(
                m.starts_with("[CaelumKernel] ")
                    || m.starts_with("[CaelumInit] ")
                    || m.starts_with("[CaelumChild] "),
                "{m:?} lacks a kernel/init/child tag"
            );
            assert_ne!(*m, FINAL_MARKER, "{m:?} must not be the final marker");
        }
        let mut unique = M6A2_MARKERS.to_vec();
        unique.sort_unstable();
        unique.dedup();
        assert_eq!(unique.len(), M6A2_MARKERS.len(), "duplicate M6a2 markers");

        // M6a2 is a slice of M6, still not M6: no full-M6 capability may be
        // required yet.
        for stage in [BootStage::First, BootStage::Second] {
            let all = required_markers(stage);
            for forbidden in ["M6 OK", "M6 SMP", "M6 display", "M6a2 OK\nM6 OK"] {
                assert!(
                    !all.iter().any(|m| m.contains(forbidden)),
                    "{}: M6a2 must not require {forbidden:?}",
                    stage.label()
                );
            }
            for m in M6A2_USER_MARKERS {
                assert!(all.contains(m), "{}: missing {m:?}", stage.label());
            }
            assert!(
                all.len() == 138,
                "{}: expected 138 markers, got {}",
                stage.label(),
                all.len()
            );
        }

        // The real emission order is accepted on both boots.
        for stage in [BootStage::First, BootStage::Second] {
            let text = complete_transcript(stage);
            assert_eq!(acceptance_error(&text, stage), None, "{}", stage.label());
        }
        let stage = BootStage::First;

        // The nine user-space markers are explicitly unordered: a different
        // emission order (here: futex before channel, subscription first) must
        // still be accepted as long as every line precedes `init`'s exit.
        let mut lines = boot_lines(stage);
        move_marker(&mut lines, M6A2_INIT_FUTEX, M6A2_INIT_CHANNEL);
        move_marker(&mut lines, M6A2_INIT_SUBSCRIPTION, M6A2_INIT_CHANNEL);
        let text = transcript(&lines);
        assert!(
            missing_markers(&text, stage).is_empty(),
            "reordering user markers must not lose any"
        );
        assert_eq!(
            acceptance_error(&text, stage),
            None,
            "reordering the user-space M6a2 markers must stay acceptable"
        );

        // Dropping the M6a2 verdict still fails.
        let mut lines = boot_lines(stage);
        lines.retain(|m| *m != M6A2_OK);
        assert_eq!(
            missing_markers(&transcript(&lines), stage),
            vec![M6A2_OK],
            "dropping M6a2 OK must be reported"
        );

        // A user marker emitted after `init` exits breaks the placement rule.
        let mut lines = boot_lines(stage);
        lines.retain(|m| *m != M6A2_INIT_PORT);
        let at = lines
            .iter()
            .position(|m| *m == "[CaelumKernel] M4 exit OK")
            .expect("M4 exit OK missing")
            + 1;
        lines.insert(at, M6A2_INIT_PORT);
        let text = transcript(&lines);
        let err = acceptance_error(&text, stage).expect("port OK after init exit accepted");
        assert!(err.contains("must appear before"), "{err}");

        // The M6a2 verdict may not precede the M6a verdict.
        let mut lines = boot_lines(stage);
        move_marker(&mut lines, M6A2_OK, M6A_OK);
        let text = transcript(&lines);
        let err = acceptance_error(&text, stage).expect("M6a2 OK before M6a OK accepted");
        assert!(err.contains("must appear before"), "{err}");
        assert!(!acceptance_reached(&text, stage));
    }

    #[test]
    fn m6b1_marker_is_exact_and_placed() {
        // Frozen string: the kernel prints it verbatim once all four CPUs are up.
        assert_eq!(M6B1_ONLINE, "[CaelumKernel] M6b1 online=4");
        assert_eq!(M6B1_MARKERS, &[M6B1_ONLINE]);

        // One additional marker per boot (70 -> 72 before M6b2, 77 after it, 82
        // once M6c is wired in), unique, on both boots.
        for stage in [BootStage::First, BootStage::Second] {
            let all = required_markers(stage);
            assert_eq!(all.len(), 138, "{}", stage.label());
            assert_eq!(all.iter().filter(|m| **m == M6B1_ONLINE).count(), 1);
            // M6b1 proves AP startup only: no full-SMP scheduler/IPI verdict may
            // become part of the contract.
            for forbidden in [
                "[CaelumKernel] M6b OK",
                "[CaelumKernel] M6b SMP OK",
                "[CaelumKernel] M6b sched OK",
                "[CaelumKernel] M6b ipi OK",
            ] {
                assert!(
                    !all.contains(&forbidden),
                    "{forbidden:?} must not be required by the M6b1 contract"
                );
            }
            // The real emission order of one boot is accepted end to end.
            assert_eq!(
                acceptance_error(&complete_transcript(stage), stage),
                None,
                "{} transcript rejected",
                stage.label()
            );
        }

        let stage = BootStage::First;

        // Dropping the AP-online marker is reported as missing.
        let mut lines = boot_lines(stage);
        lines.retain(|m| *m != M6B1_ONLINE);
        let text = transcript(&lines);
        assert_eq!(missing_markers(&text, stage), vec![M6B1_ONLINE]);
        assert!(!acceptance_reached(&text, stage));

        // It may not appear before the M3 stage completes...
        let mut lines = boot_lines(stage);
        move_marker(&mut lines, M6B1_ONLINE, "[CaelumKernel] M3 sched OK");
        let text = transcript(&lines);
        let err = acceptance_error(&text, stage).expect("M6b1 before M3 OK accepted");
        assert!(err.contains("must appear before"), "{err}");

        // ...and it may not appear after the M4 object work starts.
        let mut lines = boot_lines(stage);
        move_marker(&mut lines, M6B1_ONLINE, "[CaelumKernel] M5a vfs OK");
        let text = transcript(&lines);
        let err = acceptance_error(&text, stage).expect("M6b1 after M4 objects accepted");
        assert!(err.contains("must appear before"), "{err}");
    }

    #[test]
    fn m6b2a_marker_is_exact_and_placed() {
        // Frozen string: the kernel prints it verbatim once the per-CPU locking
        // state is usable on every online CPU.
        assert_eq!(M6B2A_LOCKS, "[CaelumKernel] M6b2a locks OK");
        assert_eq!(M6B2A_MARKERS, &[M6B2A_LOCKS]);

        // M6b2a still contributes exactly one marker of its own; the per-boot
        // total is 77 once the five M6b2 scheduling lines are added. Unique, on
        // both boots.
        for stage in [BootStage::First, BootStage::Second] {
            let all = required_markers(stage);
            assert_eq!(all.len(), 138, "{}", stage.label());
            assert_eq!(all.iter().filter(|m| **m == M6B2A_LOCKS).count(), 1);
            // M6b2a proves cross-CPU locking only: the M6b2 scheduling lines are
            // a separate contract, and no full-M6 verdict may be required.
            for forbidden in ["[CaelumKernel] M6 OK"] {
                assert!(
                    !all.contains(&forbidden),
                    "{forbidden:?} must not be required by the M6b2a contract"
                );
            }
            // The real emission order of one boot is accepted end to end.
            assert_eq!(
                acceptance_error(&complete_transcript(stage), stage),
                None,
                "{} transcript rejected",
                stage.label()
            );
        }

        let stage = BootStage::First;

        // Dropping the locking marker is reported as missing.
        let mut lines = boot_lines(stage);
        lines.retain(|m| *m != M6B2A_LOCKS);
        let text = transcript(&lines);
        assert_eq!(missing_markers(&text, stage), vec![M6B2A_LOCKS]);
        assert!(!acceptance_reached(&text, stage));

        // It may not appear before the AP-online marker...
        let mut lines = boot_lines(stage);
        move_marker(&mut lines, M6B2A_LOCKS, "[CaelumKernel] M3 OK");
        let text = transcript(&lines);
        let err = acceptance_error(&text, stage).expect("M6b2a before M6b1 accepted");
        assert!(err.contains("must appear before"), "{err}");

        // ...and it may not appear after the M4 object work starts.
        let mut lines = boot_lines(stage);
        move_marker(&mut lines, M6B2A_LOCKS, "[CaelumKernel] M5a vfs OK");
        let text = transcript(&lines);
        let err = acceptance_error(&text, stage).expect("M6b2a after M4 objects accepted");
        assert!(err.contains("must appear before"), "{err}");
    }

    #[test]
    fn m6b2_markers_are_exact_and_stats_enforced() {
        // Frozen strings: the kernel owns these five lines, this harness owns the
        // parse, so a rename must break the build instead of silently weakening
        // acceptance.
        assert_eq!(M6B2_AP_USER, "[CaelumKernel] M6b2 ap user OK");
        assert_eq!(M6B2_AP_PREEMPT, "[CaelumKernel] M6b2 ap preempt OK");
        assert_eq!(M6B2_WAKE_IPI, "[CaelumKernel] M6b2 wake ipi OK");
        assert_eq!(M6B2_MIGRATE, "[CaelumKernel] M6b2 migrate OK");
        assert_eq!(M6B2_OK, "[CaelumKernel] M6b2 OK");
        assert_eq!(
            M6B2_MARKERS,
            [
                M6B2_AP_USER,
                M6B2_AP_PREEMPT,
                M6B2_WAKE_IPI,
                M6B2_MIGRATE,
                M6B2_OK,
            ]
        );
        for m in M6B2_MARKERS {
            assert!(m.starts_with("[CaelumKernel] "), "{m:?} lacks a kernel tag");
            assert_ne!(*m, FINAL_MARKER, "{m:?} must not be the final marker");
        }
        // M6b2 is a slice of M6, not M6: no full-M6 verdict may be required.
        assert!(!M6B2_MARKERS.contains(&"[CaelumKernel] M6 OK"));

        // 138 markers on both boots (each later slice appends its block in
        // the frozen user-mode order), and the real emission order is accepted
        // end to end.
        for stage in [BootStage::First, BootStage::Second] {
            assert_eq!(required_markers(stage).len(), 138, "{}", stage.label());
            let last = *required_markers(stage).last().unwrap();
            assert_eq!(last, M7D_KERNEL_OK, "{}", stage.label());
            assert_eq!(
                acceptance_error(&complete_transcript(stage), stage),
                None,
                "{} transcript rejected",
                stage.label()
            );
        }

        let stage = BootStage::First;

        // Dropping the verdict line is reported as missing. The line carries a
        // payload, so match by prefix rather than by exact text.
        let mut lines = boot_lines(stage);
        lines.retain(|m| !m.starts_with(M6B2_OK));
        assert_eq!(missing_markers(&transcript(&lines), stage), vec![M6B2_OK]);

        // The scheduling evidence may not appear before the M6a2 closeout. The
        // sample line carries a payload, so move that exact line.
        let mut lines = boot_lines(stage);
        move_marker(&mut lines, M6B2_AP_USER_SAMPLE, M6A2_OK);
        let text = transcript(&lines);
        let err = acceptance_error(&text, stage).expect("ap user before M6a2 accepted");
        assert!(err.contains("must appear before"), "{err}");

        // Printing the marker text is not acceptance: the parsed counters must
        // reach the frozen minimums. Every case below keeps the marker line and
        // only edits its payload, exactly like a kernel that printed the line
        // before the capability actually happened.
        for (label, sample, replacement) in [
            (
                "runs",
                M6B2_AP_USER_SAMPLE,
                "[CaelumKernel] M6b2 ap user OK (runs=1, cpus=2)",
            ),
            (
                "preempts",
                M6B2_AP_PREEMPT_SAMPLE,
                "[CaelumKernel] M6b2 ap preempt OK (preempts=1)",
            ),
            (
                "ipis",
                M6B2_WAKE_IPI_SAMPLE,
                "[CaelumKernel] M6b2 wake ipi OK (remote_wakes=1, ipis=0)",
            ),
            (
                "balances",
                M6B2_MIGRATE_SAMPLE,
                "[CaelumKernel] M6b2 migrate OK (migrations=1, balances=0)",
            ),
        ] {
            let text = complete_transcript(stage).replace(sample, replacement);
            let err = acceptance_error(&text, stage)
                .unwrap_or_else(|| panic!("{label} below the minimum was accepted"));
            assert!(err.contains("below the required minimum"), "{label}: {err}");
        }

        // A required field may not be omitted...
        let text = complete_transcript(stage).replace(
            M6B2_AP_USER_SAMPLE,
            "[CaelumKernel] M6b2 ap user OK (runs=3)",
        );
        let err = acceptance_error(&text, stage).expect("missing cpus field accepted");
        assert!(err.contains("has no") && err.contains("cpus"), "{err}");

        // ...values must be numbers...
        let text = complete_transcript(stage).replace(
            M6B2_AP_USER_SAMPLE,
            "[CaelumKernel] M6b2 ap user OK (runs=three, cpus=2)",
        );
        let err = acceptance_error(&text, stage).expect("non-numeric field accepted");
        assert!(err.contains("is not a number"), "{err}");

        // ...no unknown fields may smuggle in extra claims...
        let text = complete_transcript(stage).replace(
            M6B2_AP_USER_SAMPLE,
            "[CaelumKernel] M6b2 ap user OK (runs=3, cpus=2, cpu=1)",
        );
        let err = acceptance_error(&text, stage).expect("unknown field accepted");
        assert!(err.contains("unexpected field"), "{err}");

        // ...and the verdict may not report less than the evidence it summarises.
        let text = complete_transcript(stage).replace(
            M6B2_VERDICT_SAMPLE,
            "[CaelumKernel] M6b2 OK (runs=2, cpus=2, preempts=2, remote_wakes=2, ipis=1, migrations=1, balances=1)",
        );
        let err = acceptance_error(&text, stage).expect("verdict rollback accepted");
        assert!(err.contains("verdict reports"), "{err}");
    }

    #[test]
    fn m6c_markers_are_exact_and_placed() {
        // Frozen strings: the kernel owns the probe and the verdict, the `gfx`
        // program owns the two display/input lines. A rename must break the build
        // instead of silently weakening acceptance.
        assert_eq!(M6C_DISPLAY_PROBE, "[CaelumKernel] M6c display probe OK");
        assert_eq!(M6C_DISPLAY, "[CaelumGfx] M6c display OK");
        assert_eq!(M6C_INPUT_READY, "[CaelumGfx] M6c input ready");
        assert_eq!(M6C_INPUT, "[CaelumGfx] M6c input OK");
        assert_eq!(M6C_OK, "[CaelumKernel] M6c OK");
        assert_eq!(
            M6C_MARKERS,
            [
                M6C_DISPLAY_PROBE,
                M6C_DISPLAY,
                M6C_INPUT_READY,
                M6C_INPUT,
                M6C_OK,
            ]
        );
        for m in M6C_MARKERS {
            assert!(
                m.starts_with("[CaelumKernel] ") || m.starts_with("[CaelumGfx] "),
                "{m:?} lacks a kernel/gfx tag"
            );
            assert_ne!(*m, FINAL_MARKER, "{m:?} must not be the final marker");
        }
        let mut unique = M6C_MARKERS.to_vec();
        unique.sort_unstable();
        unique.dedup();
        assert_eq!(unique.len(), M6C_MARKERS.len(), "duplicate M6c markers");

        // M6c is a slice of M6, not M6: no full-M6 verdict may be required.
        for stage in [BootStage::First, BootStage::Second] {
            let all = required_markers(stage);
            for forbidden in ["[CaelumKernel] M6 OK", "M6 SMP", "M6 audio"] {
                assert!(
                    !all.iter().any(|m| m.contains(forbidden)),
                    "{}: M6c must not require {forbidden:?}",
                    stage.label()
                );
            }
            // 138 markers per boot, the M6c block follows the M6b2 block and the
            // M7a loopback block follows M6c, before the deliberate page fault.
            assert_eq!(all.len(), 138, "{}", stage.label());
            let first_m6b2 = all
                .iter()
                .position(|m| *m == M6B2_MARKERS[0])
                .expect("M6b2 block missing");
            let first_m6c = all
                .iter()
                .position(|m| *m == M6C_MARKERS[0])
                .expect("M6c block missing");
            assert!(
                first_m6b2 + M6B2_MARKERS.len() <= first_m6c,
                "{}: the M6c block must follow the M6b2 block",
                stage.label()
            );
            let first_m7a = all
                .iter()
                .position(|m| *m == M7A_MARKERS[0])
                .expect("M7a block missing");
            assert!(
                first_m6c + M6C_MARKERS.len() <= first_m7a,
                "{}: the M7a block must follow the M6c block",
                stage.label()
            );
            assert_eq!(*all.last().unwrap(), M7D_KERNEL_OK);
            assert_eq!(acceptance_error(&complete_transcript(stage), stage), None);
        }

        let stage = BootStage::First;

        // The em dash probe line may carry a payload (it is only logged), or none.
        for probe in [
            "[CaelumKernel] M6c display probe OK (width=1024, height=768, mode=0)",
            "[CaelumKernel] M6c display probe OK",
        ] {
            let text = complete_transcript(stage).replace(M6C_DISPLAY_PROBE_SAMPLE, probe);
            assert_eq!(acceptance_error(&text, stage), None, "{probe:?}");
        }

        // Dropping a marker is reported as missing. The line carries a payload,
        // so match by prefix rather than by exact text.
        let mut lines = boot_lines(stage);
        lines.retain(|m| !m.starts_with(M6C_INPUT));
        assert_eq!(missing_markers(&transcript(&lines), stage), vec![M6C_INPUT]);

        // The probe must precede the gfx display round trip...
        let mut lines = boot_lines(stage);
        move_marker(&mut lines, M6C_DISPLAY_SAMPLE, M6C_DISPLAY_PROBE_SAMPLE);
        let text = transcript(&lines);
        let err = acceptance_error(&text, stage).expect("display before probe accepted");
        assert!(err.contains("must appear before"), "{err}");

        // ...the input round trip follows the display round trip...
        let mut lines = boot_lines(stage);
        move_marker(&mut lines, M6C_INPUT_READY_SAMPLE, M6C_DISPLAY_SAMPLE);
        let text = transcript(&lines);
        let err = acceptance_error(&text, stage).expect("input ready before display accepted");
        assert!(err.contains("must appear before"), "{err}");

        // ...and the kernel verdict is the last word of the block.
        let mut lines = boot_lines(stage);
        move_marker(&mut lines, M6C_VERDICT_SAMPLE, M6C_INPUT_READY_SAMPLE);
        let text = transcript(&lines);
        let err = acceptance_error(&text, stage).expect("M6c OK before input accepted");
        assert!(err.contains("must appear before"), "{err}");
    }

    #[test]
    fn m7a_markers_are_exact_and_payload_enforced() {
        // Frozen strings: the kernel owns these lines, so a rename breaks the
        // build instead of silently weakening acceptance.
        assert_eq!(M7A_IPV4_UDP, "[CaelumKernel] M7a ipv4 udp OK");
        assert_eq!(M7A_IPV4_TCP, "[CaelumKernel] M7a ipv4 tcp OK");
        assert_eq!(M7A_IPV6_UDP, "[CaelumKernel] M7a ipv6 udp OK");
        assert_eq!(M7A_IPV6_TCP, "[CaelumKernel] M7a ipv6 tcp OK");
        assert_eq!(M7A_SOCKETS, "[CaelumKernel] M7a sockets OK");
        assert_eq!(M7A_OK, "[CaelumKernel] M7a OK");
        assert_eq!(
            M7A_MARKERS,
            [
                M7A_IPV4_UDP,
                M7A_IPV4_TCP,
                M7A_IPV6_UDP,
                M7A_IPV6_TCP,
                M7A_SOCKETS,
                M7A_OK,
            ]
        );
        for m in M7A_MARKERS {
            assert!(
                m.starts_with("[CaelumKernel] "),
                "{m:?} lacks the kernel tag"
            );
            assert_ne!(*m, FINAL_MARKER, "{m:?} must not be the final marker");
        }
        let mut unique = M7A_MARKERS.to_vec();
        unique.sort_unstable();
        unique.dedup();
        assert_eq!(unique.len(), M7A_MARKERS.len(), "duplicate M7a markers");

        // M7a proves the loopback stack, not M7: no full-M7 verdict is required.
        for stage in [BootStage::First, BootStage::Second] {
            let all = required_markers(stage);
            for forbidden in ["[CaelumKernel] M7 OK", "M7 network OK", "M7 SMP"] {
                assert!(
                    !all.iter().any(|m| m.contains(forbidden)),
                    "{}: M7a must not require {forbidden:?}",
                    stage.label()
                );
            }
            // The M7a block follows the M6c block and `M7a OK` closes the list.
            assert_eq!(all.len(), 138, "{}", stage.label());
            let first_m6c = all
                .iter()
                .position(|m| *m == M6C_MARKERS[0])
                .expect("M6c block missing");
            let first_m7a = all
                .iter()
                .position(|m| *m == M7A_MARKERS[0])
                .expect("M7a block missing");
            assert!(
                first_m6c + M6C_MARKERS.len() <= first_m7a,
                "{}: the M7a block must follow the M6c block",
                stage.label()
            );
            assert_eq!(*all.last().unwrap(), M7D_KERNEL_OK);
            assert_eq!(acceptance_error(&complete_transcript(stage), stage), None);
        }

        let stage = BootStage::First;
        let mut lines = boot_lines(stage);
        lines.retain(|m| !m.starts_with(M7A_SOCKETS));
        assert_eq!(
            missing_markers(&transcript(&lines), stage),
            vec![M7A_SOCKETS]
        );

        // Every payload is evidence: a wrong byte/socket/suite count must fail,
        // not just a missing line.
        let cases: &[(&str, &str, &str)] = &[
            (
                M7A_IPV4_UDP_SAMPLE,
                "[CaelumKernel] M7a ipv4 udp OK (bytes=8)",
                "expected exactly 7",
            ),
            (
                M7A_IPV4_TCP_SAMPLE,
                "[CaelumKernel] M7a ipv4 tcp OK (bytes=7)",
                "expected exactly 14",
            ),
            (
                M7A_IPV6_UDP_SAMPLE,
                "[CaelumKernel] M7a ipv6 udp OK (bytes=16)",
                "expected exactly 7",
            ),
            (
                M7A_SOCKETS_SAMPLE,
                "[CaelumKernel] M7a sockets OK (live=1)",
                "expected exactly 0",
            ),
            (
                M7A_VERDICT_SAMPLE,
                "[CaelumKernel] M7a OK (suites=3)",
                "expected exactly 4",
            ),
            (M7A_VERDICT_SAMPLE, "[CaelumKernel] M7a OK", "must end with"),
            (
                M7A_VERDICT_SAMPLE,
                "[CaelumKernel] M7a OK (suites=four)",
                "not a number",
            ),
            (
                M7A_VERDICT_SAMPLE,
                "[CaelumKernel] M7a OK (suites=4, suites=4)",
                "repeats the field",
            ),
        ];
        for (sample, replacement, needle) in cases {
            let text = complete_transcript(stage).replace(sample, replacement);
            let error = acceptance_error(&text, stage)
                .unwrap_or_else(|| panic!("{replacement:?} was accepted"));
            assert!(error.contains(needle), "{replacement:?}: {error}");
        }

        // Extra fields are tolerated (they are only logged); the required ones
        // still have to match exactly.
        let text = complete_transcript(stage).replace(
            M7A_IPV6_TCP_SAMPLE,
            "[CaelumKernel] M7a ipv6 tcp OK (bytes=14, interface=1)",
        );
        assert_eq!(acceptance_error(&text, stage), None);

        // The verdict line must not run ahead of the sockets accounting, and the
        // whole block must follow the M6c verdict.
        let mut lines = boot_lines(stage);
        move_marker(&mut lines, M7A_VERDICT_SAMPLE, M7A_IPV6_TCP_SAMPLE);
        let text = transcript(&lines);
        let err = acceptance_error(&text, stage).expect("M7a verdict before sockets accepted");
        assert!(err.contains("must appear before"), "{err}");

        let mut lines = boot_lines(stage);
        move_marker(&mut lines, M7A_IPV6_UDP_SAMPLE, M7A_IPV4_TCP_SAMPLE);
        let text = transcript(&lines);
        let err = acceptance_error(&text, stage).expect("IPv6 before IPv4 TCP accepted");
        assert!(err.contains("must appear before"), "{err}");

        let mut lines = boot_lines(stage);
        move_marker(&mut lines, M7A_IPV4_UDP_SAMPLE, M6C_VERDICT_SAMPLE);
        let text = transcript(&lines);
        let err = acceptance_error(&text, stage).expect("M7a before M6c accepted");
        assert!(err.contains("must appear before"), "{err}");
    }

    #[test]
    fn m7b_markers_are_exact_and_payload_enforced() {
        // Frozen strings: the `net` program owns the suite lines and its verdict,
        // the kernel owns the closing verdict. A rename must break the build.
        assert_eq!(M7B_UDP4, "[CaelumNet] M7b udp4 OK");
        assert_eq!(M7B_UDP6, "[CaelumNet] M7b udp6 OK");
        assert_eq!(M7B_TCP4, "[CaelumNet] M7b tcp4 OK");
        assert_eq!(M7B_TCP6, "[CaelumNet] M7b tcp6 OK");
        assert_eq!(M7B_SOCKETPAIR, "[CaelumNet] M7b socketpair OK");
        assert_eq!(M7B_UNIX_STREAM, "[CaelumNet] M7b unix stream OK");
        assert_eq!(M7B_UNIX_DGRAM, "[CaelumNet] M7b unix dgram OK");
        assert_eq!(M7B_WAIT, "[CaelumNet] M7b wait OK");
        assert_eq!(M7B_BACKPRESSURE, "[CaelumNet] M7b backpressure OK");
        assert_eq!(M7B_SHUTDOWN, "[CaelumNet] M7b shutdown OK");
        assert_eq!(M7B_RIGHTS, "[CaelumNet] M7b rights OK");
        assert_eq!(M7B_FAULTS, "[CaelumNet] M7b faults OK");
        assert_eq!(M7B_USER_OK, "[CaelumNet] M7b OK");
        assert_eq!(M7B_KERNEL_OK, "[CaelumKernel] M7b OK");
        assert_eq!(
            M7B_MARKERS,
            [
                M7B_UDP4,
                M7B_UDP6,
                M7B_TCP4,
                M7B_TCP6,
                M7B_SOCKETPAIR,
                M7B_UNIX_STREAM,
                M7B_UNIX_DGRAM,
                M7B_WAIT,
                M7B_BACKPRESSURE,
                M7B_SHUTDOWN,
                M7B_RIGHTS,
                M7B_FAULTS,
                M7B_USER_OK,
                M7B_KERNEL_OK,
            ]
        );
        for m in M7B_MARKERS {
            assert!(
                m.starts_with("[CaelumNet] ") || m.starts_with("[CaelumKernel] "),
                "{m:?} lacks a net/kernel tag"
            );
            if *m == M7B_KERNEL_OK {
                assert!(m.starts_with("[CaelumKernel] "), "kernel verdict prefix");
            } else {
                assert!(
                    m.starts_with("[CaelumNet] "),
                    "{m:?} must be a [CaelumNet] line"
                );
            }
            assert_ne!(*m, FINAL_MARKER, "{m:?} must not be the final marker");
        }
        let mut unique = M7B_MARKERS.to_vec();
        unique.sort_unstable();
        unique.dedup();
        assert_eq!(unique.len(), M7B_MARKERS.len(), "duplicate M7b markers");

        // M7b proves the native socket objects, not the whole network milestone.
        for stage in [BootStage::First, BootStage::Second] {
            let all = required_markers(stage);
            for forbidden in ["[CaelumKernel] M7 OK", "M7 network OK"] {
                assert!(
                    !all.iter().any(|m| m.contains(forbidden)),
                    "{}: M7b must not require {forbidden:?}",
                    stage.label()
                );
            }
            // 138 markers per boot, the M7b block follows the M7a block, and the
            // kernel verdict closes the list right before the deliberate fault.
            assert_eq!(all.len(), 138, "{}", stage.label());
            let first_m7a = all
                .iter()
                .position(|m| *m == M7A_MARKERS[0])
                .expect("M7a block missing");
            let first_m7b = all
                .iter()
                .position(|m| *m == M7B_MARKERS[0])
                .expect("M7b block missing");
            assert!(
                first_m7a + M7A_MARKERS.len() <= first_m7b,
                "{}: the M7b block must follow the M7a block",
                stage.label()
            );
            assert_eq!(*all.last().unwrap(), M7D_KERNEL_OK);
            assert_eq!(acceptance_error(&complete_transcript(stage), stage), None);
        }

        let stage = BootStage::First;

        // Dropping the faults line is reported as missing (payload line, so
        // match by prefix rather than by exact text).
        let mut lines = boot_lines(stage);
        lines.retain(|m| !m.starts_with(M7B_FAULTS));
        assert_eq!(
            missing_markers(&transcript(&lines), stage),
            vec![M7B_FAULTS]
        );

        // Every payload is evidence: a wrong byte/pair/handshake/accounting value
        // must fail, not just a missing line.
        let cases: &[(&str, &str, &str)] = &[
            (
                M7B_UDP4_SAMPLE,
                "[CaelumNet] M7b udp4 OK (bytes=8)",
                "expected exactly 7",
            ),
            (
                M7B_TCP6_SAMPLE,
                "[CaelumNet] M7b tcp6 OK (bytes=7)",
                "expected exactly 14",
            ),
            (
                M7B_SOCKETPAIR_SAMPLE,
                "[CaelumNet] M7b socketpair OK (pairs=1, bytes=1024)",
                "expected exactly 2",
            ),
            (
                M7B_UNIX_STREAM_SAMPLE,
                "[CaelumNet] M7b unix stream OK (bytes=512)",
                "expected exactly 1024",
            ),
            (
                M7B_UNIX_DGRAM_SAMPLE,
                "[CaelumNet] M7b unix dgram OK (bytes=1024)",
                "expected exactly 512",
            ),
            (
                M7B_WAIT_SAMPLE,
                "[CaelumNet] M7b wait OK (ready=1, timeouts=0)",
                "expected exactly 1",
            ),
            (
                M7B_BACKPRESSURE_SAMPLE,
                "[CaelumNet] M7b backpressure OK (would_block=1)",
                "expected exactly 2",
            ),
            (
                M7B_SHUTDOWN_SAMPLE,
                "[CaelumNet] M7b shutdown OK (eof=0)",
                "expected exactly 1",
            ),
            (
                M7B_RIGHTS_SAMPLE,
                "[CaelumNet] M7b rights OK (bad_handle=0, bad_right=1)",
                "expected exactly 1",
            ),
            (
                M7B_FAULTS_SAMPLE,
                "[CaelumNet] M7b faults OK (too_large=1, not_found=1, exists=1, peer_closed=0)",
                "expected exactly 1",
            ),
            (
                M7B_USER_VERDICT_SAMPLE,
                "[CaelumNet] M7b OK (child=1)",
                "expected exactly 0",
            ),
            (
                M7B_KERNEL_VERDICT_SAMPLE,
                "[CaelumKernel] M7b OK (sockets=1, bindings=0)",
                "expected exactly 0",
            ),
            (
                M7B_KERNEL_VERDICT_SAMPLE,
                "[CaelumKernel] M7b OK (sockets=0)",
                "has no \"bindings\" field",
            ),
            (
                M7B_KERNEL_VERDICT_SAMPLE,
                "[CaelumKernel] M7b OK",
                "must end with",
            ),
            (
                M7B_KERNEL_VERDICT_SAMPLE,
                "[CaelumKernel] M7b OK (sockets=0, bindings=zero)",
                "not a number",
            ),
            (
                M7B_KERNEL_VERDICT_SAMPLE,
                "[CaelumKernel] M7b OK (sockets=0, sockets=0, bindings=0)",
                "repeats the field",
            ),
        ];
        for (sample, replacement, needle) in cases {
            let text = complete_transcript(stage).replace(sample, replacement);
            let error = acceptance_error(&text, stage)
                .unwrap_or_else(|| panic!("{replacement:?} was accepted"));
            assert!(error.contains(needle), "{replacement:?}: {error}");
        }

        // Extra fields are tolerated; the required ones must still match.
        let text = complete_transcript(stage).replace(
            M7B_UDP4_SAMPLE,
            "[CaelumNet] M7b udp4 OK (bytes=7, interface=0)",
        );
        assert_eq!(acceptance_error(&text, stage), None);

        // The kernel verdict must not run ahead of the user verdict, the UDP
        // families must stay in IPv4 -> IPv6 order, and the block must follow the
        // M7a verdict.
        let mut lines = boot_lines(stage);
        move_marker(
            &mut lines,
            M7B_KERNEL_VERDICT_SAMPLE,
            M7B_USER_VERDICT_SAMPLE,
        );
        let text = transcript(&lines);
        let err = acceptance_error(&text, stage).expect("kernel verdict before user verdict");
        assert!(err.contains("must appear before"), "{err}");

        let mut lines = boot_lines(stage);
        move_marker(&mut lines, M7B_UDP6_SAMPLE, M7B_UDP4_SAMPLE);
        let text = transcript(&lines);
        let err = acceptance_error(&text, stage).expect("udp6 before udp4 accepted");
        assert!(err.contains("must appear before"), "{err}");

        let mut lines = boot_lines(stage);
        move_marker(&mut lines, M7B_UDP4_SAMPLE, M7A_VERDICT_SAMPLE);
        let text = transcript(&lines);
        let err = acceptance_error(&text, stage).expect("M7b before M7a accepted");
        assert!(err.contains("must appear before"), "{err}");
    }

    /// A synthetic P6 PPM (maxval 255) with the three pixels `validate_screen`
    /// checks: magenta at the bottom-right corner, green at (48,48), blue at
    /// (128,48). Everything else is black.
    fn sample_ppm(width: usize, height: usize) -> Vec<u8> {
        let mut raster = vec![0u8; width * height * 3];
        let mut put = |x: usize, y: usize, rgb: [u8; 3]| {
            let base = (y * width + x) * 3;
            raster[base..base + 3].copy_from_slice(&rgb);
        };
        put(width - 1, height - 1, SCREEN_CORNER);
        put(SCREEN_GREEN_AT.0, SCREEN_GREEN_AT.1, SCREEN_GREEN);
        put(SCREEN_BLUE_AT.0, SCREEN_BLUE_AT.1, SCREEN_BLUE);
        let mut bytes = format!("P6\n{width} {height}\n255\n").into_bytes();
        bytes.extend_from_slice(&raster);
        bytes
    }

    #[test]
    fn ppm_parser_accepts_p6_and_rejects_bad_input() {
        let bytes = sample_ppm(200, 120);
        let ppm = Ppm::parse(&bytes).expect("valid P6 must parse");
        assert_eq!((ppm.width, ppm.height), (200, 120));
        assert_eq!(ppm.pixel(200 - 1, 120 - 1), SCREEN_CORNER);
        assert_eq!(ppm.pixel(0, 0), [0, 0, 0]);
        assert_eq!(validate_screen(&ppm), Ok(()));

        // Comments and arbitrary header whitespace are allowed.
        let raster = &bytes[bytes.len() - 200 * 120 * 3..];
        let mut commented = b"P6\n# produced by screendump\n200 120\n255\n".to_vec();
        commented.extend_from_slice(raster);
        assert!(Ppm::parse(&commented).is_ok());

        // Trailing garbage after the raster is ignored (screendump writes none,
        // but the parser must not depend on EOF alignment).
        let mut padded = bytes.clone();
        padded.extend_from_slice(b"trailing");
        assert!(Ppm::parse(&padded).is_ok());

        // ASCII P3 is not what screendump writes.
        let err = Ppm::parse(b"P3\n1 1\n255\n0 0 0\n").expect_err("P3 must be rejected");
        assert!(err.contains("P6"), "{err}");

        // A 16-bit maxval would make the raster layout ambiguous.
        let err = Ppm::parse(b"P6\n1 1\n65535\n\0\0\0\0\0\0").expect_err("maxval 65535 rejected");
        assert!(err.contains("maxval"), "{err}");

        // A truncated raster must not be accepted as a partial image.
        let err = Ppm::parse(b"P6\n10 10\n255\nshort").expect_err("truncated raster rejected");
        assert!(err.contains("truncated"), "{err}");

        // The header must end with exactly one whitespace byte after maxval.
        let err = Ppm::parse(b"P6 1 1 255").expect_err("missing raster separator rejected");
        assert!(err.contains("whitespace"), "{err}");
    }

    #[test]
    fn ppm_pixel_check_enforces_the_screenshot_contract() {
        let good = sample_ppm(200, 120);
        let ppm = Ppm::parse(&good).unwrap();
        assert_eq!(validate_screen(&ppm), Ok(()));

        // The tolerance is per channel and inclusive (+-8). `good` is the whole
        // file, so pixel indices are relative to its raster start.
        let header = good.len() - 200 * 120 * 3;
        let mut near = good.clone();
        let at = header + ((120 - 1) * 200 + (200 - 1)) * 3;
        near[at] = 255 - SCREEN_CHANNEL_TOLERANCE;
        let ppm = Ppm::parse(&near).unwrap();
        assert_eq!(validate_screen(&ppm), Ok(()));

        let mut off = near;
        off[at] = 255 - SCREEN_CHANNEL_TOLERANCE - 1;
        let ppm = Ppm::parse(&off).unwrap();
        let err = validate_screen(&ppm).expect_err("out-of-tolerance corner accepted");
        assert!(err.contains("corner"), "{err}");

        // A wrong green rectangle pixel fails with a description naming it.
        let mut wrong = good.clone();
        let green = header + (48 * 200 + 48) * 3;
        wrong[green + 1] = 0;
        let ppm = Ppm::parse(&wrong).unwrap();
        let err = validate_screen(&ppm).expect_err("wrong green accepted");
        assert!(err.contains("green"), "{err}");

        // An image too small for the blue probe is rejected, not skipped.
        let small = sample_ppm(120, 60);
        let ppm = Ppm::parse(&small).unwrap();
        let err = validate_screen(&ppm).expect_err("small screenshot accepted");
        assert!(err.contains("too small"), "{err}");
    }

    #[test]
    fn screendump_command_is_single_line_json() {
        let path = Path::new("E:\\Ai files\\os001\\target\\m6c-screen-boot1.ppm");
        let json = screendump_json(path);
        assert!(!json.contains('\n'), "{json:?} must be one line");
        assert!(json.starts_with("{\"execute\":\"screendump\""), "{json}");
        assert!(json.contains("\"filename\":\"E:/Ai files/os001/target/m6c-screen-boot1.ppm\""));
        assert!(json.ends_with("}}"), "{json}");
    }

    #[test]
    fn m6c_injection_payloads_are_exact() {
        // The second injection: PS/2 `d` (press+release) and the serial bytes
        // `m6c`. The gfx program counts 2 keyboard scancodes + 3 serial events,
        // so these literals are part of the accepted `events=5` contract.
        assert_eq!(
            SEND_KEY_D_JSON,
            "{\"execute\":\"send-key\",\"arguments\":{\"keys\":[{\"type\":\"qcode\",\"data\":\"d\"}],\"hold-time\":100}}"
        );
        assert!(!SEND_KEY_D_JSON.contains('\n'));
        assert_ne!(SEND_KEY_A_JSON, SEND_KEY_D_JSON);
        assert_eq!(M6C_SERIAL_BYTES, b"m6c");
        assert_ne!(SERIAL_INJECT_BYTE, M6C_SERIAL_BYTES);

        // QMP emits `make` immediately but `break` only after the hold time, so
        // the serial bytes must be delayed past it: the guest asserts the order
        // make -> break -> m -> 6 -> c.
        let hold = format!("\"hold-time\":{KEY_HOLD_MS}");
        assert!(SEND_KEY_D_JSON.contains(&hold), "{SEND_KEY_D_JSON}");
        assert!(SEND_KEY_A_JSON.contains(&hold), "{SEND_KEY_A_JSON}");
        assert!(
            M6C_KEY_SETTLE.as_millis() as u64 > KEY_HOLD_MS,
            "settle {} ms must outlast the {} ms hold",
            M6C_KEY_SETTLE.as_millis(),
            KEY_HOLD_MS
        );
        assert!(
            M6C_KEY_SETTLE >= Duration::from_millis(150),
            "settle window regressed below the frozen 150 ms"
        );
    }

    #[test]
    fn m6c_evidence_payload_is_enforced() {
        let stage = BootStage::First;

        // A marker with a wrong event count is not acceptance...
        for (label, sample, replacement) in [
            (
                "events too low",
                M6C_INPUT_SAMPLE,
                "[CaelumGfx] M6c input OK (events=4, dropped=0)",
            ),
            (
                "dropped",
                M6C_INPUT_SAMPLE,
                "[CaelumGfx] M6c input OK (events=5, dropped=1)",
            ),
            (
                "verdict events",
                M6C_VERDICT_SAMPLE,
                "[CaelumKernel] M6c OK (events=6, dropped=0)",
            ),
            (
                "verdict dropped",
                M6C_VERDICT_SAMPLE,
                "[CaelumKernel] M6c OK (events=5, dropped=2)",
            ),
        ] {
            let text = complete_transcript(stage).replace(sample, replacement);
            let err =
                acceptance_error(&text, stage).unwrap_or_else(|| panic!("{label} was accepted"));
            assert!(err.contains("M6c stats:"), "{label}: {err}");
        }

        // ...so a bare marker line without its payload is rejected too.
        let text = complete_transcript(stage).replace(M6C_INPUT_SAMPLE, M6C_INPUT);
        let err = acceptance_error(&text, stage).expect("payload-less input OK accepted");
        assert!(err.contains("payload"), "{err}");

        // Non-numeric and duplicate fields are rejected.
        let text = complete_transcript(stage).replace(
            M6C_INPUT_SAMPLE,
            "[CaelumGfx] M6c input OK (events=five, dropped=0)",
        );
        let err = acceptance_error(&text, stage).expect("non-numeric payload accepted");
        assert!(err.contains("not a number"), "{err}");

        let text = complete_transcript(stage).replace(
            M6C_INPUT_SAMPLE,
            "[CaelumGfx] M6c input OK (events=5, events=5, dropped=0)",
        );
        let err = acceptance_error(&text, stage).expect("duplicate field accepted");
        assert!(err.contains("repeats"), "{err}");

        // Extra fields are tolerated: the contract is the two required counters.
        let text = complete_transcript(stage).replace(
            M6C_INPUT_SAMPLE,
            "[CaelumGfx] M6c input OK (events=5, dropped=0, note=1)",
        );
        assert_eq!(acceptance_error(&text, stage), None);
    }

    #[test]
    fn m5a_markers_are_exact_and_ordered() {
        // Exact, frozen strings and emission order: these are the M5a acceptance
        // contract, so a rename or a missing marker must fail the build.
        let expected: &[&str] = &[
            "[CaelumKernel] M5a vfs OK",
            "[CaelumKernel] M5a pagecache OK",
            "[CaelumKernel] M5a ramfs OK",
            "[CaelumKernel] M5a locks OK",
            "[CaelumKernel] M5a notify OK",
            "[CaelumKernel] M5a bootmod via vfs OK",
        ];
        assert_eq!(M5A_MARKERS, expected);

        for m in M5A_MARKERS {
            assert!(
                m.starts_with("[CaelumKernel] "),
                "{m:?} lacks the kernel tag"
            );
            assert_ne!(*m, FINAL_MARKER, "{m:?} must not be the final marker");
        }
        let mut unique = M5A_MARKERS.to_vec();
        unique.sort_unstable();
        unique.dedup();
        assert_eq!(unique.len(), M5A_MARKERS.len(), "duplicate M5a markers");

        // The M5a block sits after every M4 marker, and the M5b block follows it
        // (before the deliberate M2 page fault) in both boots' required order.
        let all = required_markers(BootStage::Second);
        let first = all
            .iter()
            .position(|m| *m == M5A_MARKERS[0])
            .expect("first M5a marker missing");
        assert_eq!(&all[first..first + M5A_MARKERS.len()], M5A_MARKERS);
        for m in M4_MARKERS {
            let at = all.iter().position(|x| x == m).unwrap();
            assert!(at < first, "M4 marker {m:?} must precede the M5a block");
        }

        // A normal M5a/M5b boot is accepted; an M5a marker after the deliberate
        // page fault breaks the "fault is last" contract.
        let ok = complete_transcript(BootStage::Second);
        assert!(acceptance_reached(&ok, BootStage::Second));
        let mut bad = complete_transcript(BootStage::Second);
        bad.push_str("[CaelumKernel] M5a bootmod via vfs OK\n");
        assert!(missing_markers(&bad, BootStage::Second).is_empty());
        assert!(
            !acceptance_reached(&bad, BootStage::Second),
            "M5a marker after the deliberate page fault"
        );
    }

    /// Move `marker` so it is emitted immediately before `anchor`, which lets a
    /// test build a transcript with a deliberately broken marker order.
    fn move_marker(lines: &mut Vec<&'static str>, marker: &'static str, anchor: &'static str) {
        let pos = lines
            .iter()
            .position(|m| *m == marker)
            .expect("marker to move is missing");
        lines.remove(pos);
        let at = lines
            .iter()
            .position(|m| *m == anchor)
            .expect("anchor marker is missing");
        lines.insert(at, marker);
    }

    /// M6b2 sample evidence lines: the shape the kernel must print once the
    /// counters reached their minimums. They are *parsed* by
    /// `m6b2_stats_error`, not merely matched, so the numbers here matter and
    /// several tests below edit only the payload.
    const M6B2_AP_USER_SAMPLE: &str = "[CaelumKernel] M6b2 ap user OK (runs=3, cpus=2)";
    const M6B2_AP_PREEMPT_SAMPLE: &str = "[CaelumKernel] M6b2 ap preempt OK (preempts=2)";
    const M6B2_WAKE_IPI_SAMPLE: &str = "[CaelumKernel] M6b2 wake ipi OK (remote_wakes=2, ipis=1)";
    const M6B2_MIGRATE_SAMPLE: &str = "[CaelumKernel] M6b2 migrate OK (migrations=1, balances=1)";
    const M6B2_VERDICT_SAMPLE: &str = "[CaelumKernel] M6b2 OK (runs=3, cpus=2, preempts=2, remote_wakes=2, ipis=1, migrations=1, balances=1)";

    /// M6c sample lines. The kernel probe may carry a payload that acceptance
    /// only logs; the `gfx` display/input lines and the kernel verdict carry the
    /// payload `m6c_stats_error` enforces (exactly five events, none dropped), so
    /// several tests below edit only those payloads.
    const M6C_DISPLAY_PROBE_SAMPLE: &str =
        "[CaelumKernel] M6c display probe OK (width=640, height=480)";
    const M6C_DISPLAY_SAMPLE: &str = "[CaelumGfx] M6c display OK";
    const M6C_INPUT_READY_SAMPLE: &str = "[CaelumGfx] M6c input ready";
    const M6C_INPUT_SAMPLE: &str = "[CaelumGfx] M6c input OK (events=5, dropped=0)";
    const M6C_VERDICT_SAMPLE: &str = "[CaelumKernel] M6c OK (events=5, dropped=0)";

    /// M7a sample lines with the exact payloads the kernel is required to print.
    const M7A_IPV4_UDP_SAMPLE: &str = "[CaelumKernel] M7a ipv4 udp OK (bytes=7)";
    const M7A_IPV4_TCP_SAMPLE: &str = "[CaelumKernel] M7a ipv4 tcp OK (bytes=14)";
    const M7A_IPV6_UDP_SAMPLE: &str = "[CaelumKernel] M7a ipv6 udp OK (bytes=7)";
    const M7A_IPV6_TCP_SAMPLE: &str = "[CaelumKernel] M7a ipv6 tcp OK (bytes=14)";
    const M7A_SOCKETS_SAMPLE: &str = "[CaelumKernel] M7a sockets OK (live=0)";
    const M7A_VERDICT_SAMPLE: &str = "[CaelumKernel] M7a OK (suites=4)";

    /// M7b sample lines with the exact payloads the `net` program and the kernel
    /// must print. The two `M7b OK` verdicts carry different prefixes on purpose.
    const M7B_UDP4_SAMPLE: &str = "[CaelumNet] M7b udp4 OK (bytes=7)";
    const M7B_UDP6_SAMPLE: &str = "[CaelumNet] M7b udp6 OK (bytes=7)";
    const M7B_TCP4_SAMPLE: &str = "[CaelumNet] M7b tcp4 OK (bytes=14)";
    const M7B_TCP6_SAMPLE: &str = "[CaelumNet] M7b tcp6 OK (bytes=14)";
    const M7B_SOCKETPAIR_SAMPLE: &str = "[CaelumNet] M7b socketpair OK (pairs=2, bytes=1024)";
    const M7B_UNIX_STREAM_SAMPLE: &str = "[CaelumNet] M7b unix stream OK (bytes=1024)";
    const M7B_UNIX_DGRAM_SAMPLE: &str = "[CaelumNet] M7b unix dgram OK (bytes=512)";
    const M7B_WAIT_SAMPLE: &str = "[CaelumNet] M7b wait OK (ready=1, timeouts=1)";
    const M7B_BACKPRESSURE_SAMPLE: &str = "[CaelumNet] M7b backpressure OK (would_block=2)";
    const M7B_SHUTDOWN_SAMPLE: &str = "[CaelumNet] M7b shutdown OK (eof=1)";
    const M7B_RIGHTS_SAMPLE: &str = "[CaelumNet] M7b rights OK (bad_handle=1, bad_right=1)";
    const M7B_FAULTS_SAMPLE: &str =
        "[CaelumNet] M7b faults OK (too_large=1, not_found=1, exists=1, peer_closed=1)";
    const M7B_USER_VERDICT_SAMPLE: &str = "[CaelumNet] M7b OK (child=0)";
    const M7B_KERNEL_VERDICT_SAMPLE: &str = "[CaelumKernel] M7b OK (sockets=0, bindings=0)";

    /// M7d sample lines: the seven user-mode lines are exact plain text; only
    /// the kernel verdict carries the zero sockets/bindings accounting that
    /// `m7d_stats_error` enforces.
    const M7D_STARTUP_SAMPLE: &str = "[CaelumLinux] M7d startup OK";
    const M7D_UDP_SAMPLE: &str = "[CaelumLinux] M7d udp OK";
    const M7D_TCP_SAMPLE: &str = "[CaelumLinux] M7d tcp OK";
    const M7D_UNIX_SAMPLE: &str = "[CaelumLinux] M7d unix OK";
    const M7D_FD_SAMPLE: &str = "[CaelumLinux] M7d fd OK";
    const M7D_ERRORS_SAMPLE: &str = "[CaelumLinux] M7d errors OK";
    const M7D_USER_VERDICT_SAMPLE: &str = "[CaelumLinux] M7d OK";
    const M7D_KERNEL_VERDICT_SAMPLE: &str = "[CaelumKernel] M7d OK (sockets=0, bindings=0)";

    /// M8a sample lines: both are plain text emitted by the `linux` program after
    /// its `[CaelumLinux] M7d OK` line and before the kernel M7d verdict.
    const M8A_MEMORY_SAMPLE: &str = "[CaelumLinux] M8a memory OK";
    const M8A_FILES_SAMPLE: &str = "[CaelumLinux] M8a files OK";

    /// M8b sample lines: same user block as M8a, immediately after the M8a pair.
    const M8B_TIME_SAMPLE: &str = "[CaelumLinux] M8b time OK";
    const M8B_INFO_SAMPLE: &str = "[CaelumLinux] M8b info OK";
    const M8C_SIGNALS_SAMPLE: &str = "[CaelumLinux] M8c signals OK";
    /// M8d sample line: the process slice follows M8c in the same user block.
    const M8D_PROCESS_SAMPLE: &str = "[CaelumLinux] M8d process OK";
    const M8E_FILES_SAMPLE: &str = "[CaelumLinux] M8e files OK";
    const M8F_FUTEX_SAMPLE: &str = "[CaelumLinux] M8f futex OK";
    const M8F_TLS_SAMPLE: &str = "[CaelumLinux] M8f tls OK";
    const M8G_EVENTFD_SAMPLE: &str = "[CaelumLinux] M8g eventfd OK";
    const M8G_POLL_SAMPLE: &str = "[CaelumLinux] M8g poll OK";
    const M8H_PROCFS_SAMPLE: &str = "[CaelumLinux] M8h procfs OK";
    const M8H_DEVFS_SAMPLE: &str = "[CaelumLinux] M8h devfs OK";
    const M9A_TIMERFD_SAMPLE: &str = "[CaelumLinux] M9a timerfd OK";
    const M9A_SIGNALFD_SAMPLE: &str = "[CaelumLinux] M9a signalfd OK";
    const M9A_EPOLL_SAMPLE: &str = "[CaelumLinux] M9a epoll OK";
    const M9B_ABSTRACT_SAMPLE: &str = "[CaelumLinux] M9b abstract OK";
    const M9B_RIGHTS_SAMPLE: &str = "[CaelumLinux] M9b rights OK";
    const M9B_CREDENTIALS_SAMPLE: &str = "[CaelumLinux] M9b credentials OK";
    const M9B_EPOLL_ET_SAMPLE: &str = "[CaelumLinux] M9b epoll-et OK";
    const M9C_LOCKS_SAMPLE: &str = "[CaelumLinux] M9c locks OK";
    const M9D_INTERP_SAMPLE: &str = "[CaelumDyn] interp OK";
    const M9D_DYNAMIC_SAMPLE: &str = "[CaelumLinux] M9d dynamic OK";
    /// M9d2 sample line: the vDSO slice follows the dynamic line and still
    /// precedes the reused M7d kernel verdict.
    const M9D_VDSO_SAMPLE: &str = "[CaelumLinux] M9d vdso OK";
    /// M9e sample line: the shared-library line follows the vDSO line and
    /// still precedes the reused M7d kernel verdict.
    const M9E_SHARED_SAMPLE: &str = "[CaelumLinux] M9e shared OK";
    /// M9f sample line: the three-library line follows the M9e line and still
    /// precedes the reused M7d kernel verdict.
    const M9F_SHARED_SAMPLE: &str = "[CaelumLinux] M9f shared OK";
    /// M10a: the real musl busybox prints this line itself.
    const M10A_HELLO_SAMPLE: &str = "[CaelumLinux] M10a hello OK";
    /// M7c-1a: the kernel prints the MAC it read from the legacy virtio-net
    /// device together with the link state the device reported.
    const M7C_NIC_SAMPLE: &str = "[CaelumKernel] M7c nic OK (mac=52:54:00:12:34:56, link=up)";

    /// The seven user-mode M7d markers are plain exact text: no payload is
    /// appended, so the frozen strings above must match the guest output
    /// verbatim.
    #[test]
    fn m7d_markers_are_exact_and_placed() {
        assert_eq!(M7D_STARTUP, "[CaelumLinux] M7d startup OK");
        assert_eq!(M7D_UDP, "[CaelumLinux] M7d udp OK");
        assert_eq!(M7D_TCP, "[CaelumLinux] M7d tcp OK");
        assert_eq!(M7D_UNIX, "[CaelumLinux] M7d unix OK");
        assert_eq!(M7D_FD, "[CaelumLinux] M7d fd OK");
        assert_eq!(M7D_ERRORS, "[CaelumLinux] M7d errors OK");
        assert_eq!(M7D_USER_OK, "[CaelumLinux] M7d OK");
        assert_eq!(M7D_KERNEL_OK, "[CaelumKernel] M7d OK");
        assert_eq!(
            M7D_MARKERS,
            &[
                M7D_STARTUP,
                M7D_UDP,
                M7D_TCP,
                M7D_UNIX,
                M7D_FD,
                M7D_ERRORS,
                M7D_USER_OK,
                M7D_KERNEL_OK,
            ]
        );
        // `[CaelumLinux]` user lines and the `[CaelumKernel]` verdict are
        // deliberately different prefixes.
        for m in M7D_MARKERS {
            if *m == M7D_KERNEL_OK {
                assert!(m.starts_with("[CaelumKernel] "), "kernel verdict prefix");
            } else {
                assert!(
                    m.starts_with("[CaelumLinux] "),
                    "{m:?} must be a [CaelumLinux] line"
                );
            }
            assert_ne!(*m, FINAL_MARKER, "{m:?} must not be the final marker");
        }
        // M7d must not smuggle in a broader M7 claim.
        let required = required_markers(BootStage::First);
        for forbidden in ["[CaelumKernel] M7 OK", "[CaelumKernel] M7 network OK"] {
            assert!(
                !required.iter().any(|m| m.contains(forbidden)),
                "M7d must not require {forbidden:?}"
            );
        }
        let mut unique = M7D_MARKERS.to_vec();
        unique.sort_unstable();
        unique.dedup();
        assert_eq!(unique.len(), M7D_MARKERS.len(), "duplicate M7d markers");

        // Both boots accept the real emission order; the M7b block comes first.
        for stage in [BootStage::First, BootStage::Second] {
            let all = required_markers(stage);
            assert_eq!(all.len(), 138, "{}", stage.label());
            for m in M7D_MARKERS {
                assert!(all.contains(m), "{}: missing {m:?}", stage.label());
            }
            assert_eq!(*all.last().unwrap(), M7D_KERNEL_OK);
            let text = complete_transcript(stage);
            assert!(
                acceptance_error(&text, stage).is_none(),
                "{}: {:?}",
                stage.label(),
                acceptance_error(&text, stage)
            );
            let m7b_at = text.rfind(M7B_KERNEL_VERDICT_SAMPLE).unwrap();
            let m7d_at = text.rfind(M7D_KERNEL_VERDICT_SAMPLE).unwrap();
            assert!(m7b_at < m7d_at, "{}: M7d must follow M7b", stage.label());
        }

        // A missing M7d line is reported through `missing_markers`.
        let text = complete_transcript(BootStage::First);
        let without_startup = text.replacen(&format!("{M7D_STARTUP_SAMPLE}\n"), "", 1);
        assert!(
            missing_markers(&without_startup, BootStage::First).contains(&M7D_STARTUP),
            "dropping the startup line must be reported missing"
        );
        let without_verdict = text.replace(M7D_KERNEL_VERDICT_SAMPLE, "");
        assert!(
            missing_markers(&without_verdict, BootStage::First).contains(&M7D_KERNEL_OK),
            "dropping the M7d verdict must be reported missing"
        );

        // The kernel verdict payload is enforced exactly.
        for bad in [
            "[CaelumKernel] M7d OK (sockets=0, bindings=1)",
            "[CaelumKernel] M7d OK (sockets=1, bindings=0)",
            "[CaelumKernel] M7d OK",
            "[CaelumKernel] M7d OK (sockets=zero, bindings=0)",
            "[CaelumKernel] M7d OK (sockets=0)",
        ] {
            let broken =
                complete_transcript(BootStage::First).replace(M7D_KERNEL_VERDICT_SAMPLE, bad);
            let error = acceptance_error(&broken, BootStage::First)
                .expect("a bad M7d verdict payload must fail acceptance");
            assert!(error.starts_with("M7d stats:"), "unexpected error: {error}");
        }

        // Ordering violations are diagnosed by `marker_placement_error`.
        let reordered = complete_transcript(BootStage::First).replace(
            &format!("{M7D_STARTUP_SAMPLE}\n{M7D_UDP_SAMPLE}"),
            &format!("{M7D_UDP_SAMPLE}\n{M7D_STARTUP_SAMPLE}"),
        );
        let error =
            acceptance_error(&reordered, BootStage::First).expect("swapped M7d order must fail");
        assert!(
            error.contains("must appear before"),
            "unexpected error: {error}"
        );

        let verdict_early = complete_transcript(BootStage::First)
            .replace(M7D_KERNEL_VERDICT_SAMPLE, "")
            .replacen(
                &format!("{M7B_KERNEL_VERDICT_SAMPLE}\n"),
                &format!("{M7B_KERNEL_VERDICT_SAMPLE}\n{M7D_KERNEL_VERDICT_SAMPLE}\n"),
                1,
            );
        let error = acceptance_error(&verdict_early, BootStage::First)
            .expect("M7d verdict before the user lines must fail");
        assert!(
            error.contains("must appear before"),
            "unexpected error: {error}"
        );
    }

    /// M8a adds the Linux64 personality's memory and file slices as two plain
    /// user-mode lines. They must sit between `[CaelumLinux] M7d OK` and the
    /// kernel M7d verdict; the M7d verdict still closes the boot before the
    /// deliberate fault, and no new kernel verdict is introduced.
    #[test]
    fn m8a_markers_are_exact_and_placed() {
        assert_eq!(M8A_MEMORY, "[CaelumLinux] M8a memory OK");
        assert_eq!(M8A_FILES, "[CaelumLinux] M8a files OK");
        assert_eq!(M8A_MARKERS, &[M8A_MEMORY, M8A_FILES]);
        for m in M8A_MARKERS {
            assert!(
                m.starts_with("[CaelumLinux] "),
                "{m:?} must be a [CaelumLinux] line"
            );
            assert_ne!(*m, FINAL_MARKER, "{m:?} must not be the final marker");
        }
        let mut unique = M8A_MARKERS.to_vec();
        unique.sort_unstable();
        unique.dedup();
        assert_eq!(unique.len(), M8A_MARKERS.len(), "duplicate M8a markers");

        // No new kernel verdict and no broader M8 claim is required.
        let required = required_markers(BootStage::First);
        for forbidden in [
            "[CaelumKernel] M8a OK",
            "[CaelumKernel] M8 OK",
            "[CaelumLinux] M8 OK",
        ] {
            assert!(
                !required.iter().any(|m| m.contains(forbidden)),
                "M8a must not require {forbidden:?}"
            );
        }

        for stage in [BootStage::First, BootStage::Second] {
            let all = required_markers(stage);
            assert_eq!(all.len(), 138, "{}", stage.label());
            for m in M8A_MARKERS {
                assert!(all.contains(m), "{}: missing {m:?}", stage.label());
            }
            assert_eq!(*all.last().unwrap(), M7D_KERNEL_OK);
            let text = complete_transcript(stage);
            assert!(
                acceptance_error(&text, stage).is_none(),
                "{}: {:?}",
                stage.label(),
                acceptance_error(&text, stage)
            );
            let user_at = text.rfind(M7D_USER_VERDICT_SAMPLE).unwrap();
            let memory_at = text.rfind(M8A_MEMORY_SAMPLE).unwrap();
            let files_at = text.rfind(M8A_FILES_SAMPLE).unwrap();
            let verdict_at = text.rfind(M7D_KERNEL_VERDICT_SAMPLE).unwrap();
            assert!(
                user_at < memory_at && memory_at < files_at && files_at < verdict_at,
                "{}: M8a lines must sit between the M7d user verdict and the kernel verdict",
                stage.label()
            );
        }

        // Missing lines are reported through `missing_markers`.
        let text = complete_transcript(BootStage::First);
        let without_memory = text.replacen(&format!("{M8A_MEMORY_SAMPLE}\n"), "", 1);
        assert!(
            missing_markers(&without_memory, BootStage::First).contains(&M8A_MEMORY),
            "dropping the memory line must be reported missing"
        );
        let without_files = text.replacen(&format!("{M8A_FILES_SAMPLE}\n"), "", 1);
        assert!(
            missing_markers(&without_files, BootStage::First).contains(&M8A_FILES),
            "dropping the files line must be reported missing"
        );

        // Ordering violations are diagnosed by `marker_placement_error`.
        let memory_early = text.replace(
            &format!("{M7D_USER_VERDICT_SAMPLE}\n{M8A_MEMORY_SAMPLE}"),
            &format!("{M8A_MEMORY_SAMPLE}\n{M7D_USER_VERDICT_SAMPLE}"),
        );
        let error = acceptance_error(&memory_early, BootStage::First)
            .expect("M8a memory before the M7d user verdict must fail");
        assert!(
            error.contains("must appear before"),
            "unexpected error: {error}"
        );

        let swapped = text.replace(
            &format!("{M8A_MEMORY_SAMPLE}\n{M8A_FILES_SAMPLE}"),
            &format!("{M8A_FILES_SAMPLE}\n{M8A_MEMORY_SAMPLE}"),
        );
        let error =
            acceptance_error(&swapped, BootStage::First).expect("swapped M8a lines must fail");
        assert!(
            error.contains("must appear before"),
            "unexpected error: {error}"
        );

        let files_after_verdict = text
            .replacen(&format!("{M8A_FILES_SAMPLE}\n"), "", 1)
            .replacen(
                &format!("{M7D_KERNEL_VERDICT_SAMPLE}\n"),
                &format!("{M7D_KERNEL_VERDICT_SAMPLE}\n{M8A_FILES_SAMPLE}\n"),
                1,
            );
        let error = acceptance_error(&files_after_verdict, BootStage::First)
            .expect("M8a files after the M7d verdict must fail");
        assert!(
            error.contains("must appear before"),
            "unexpected error: {error}"
        );
    }

    /// M8b: the time and system-information slices are plain user-mode lines
    /// that extend the M8a block; they carry no payload and add no kernel
    /// verdict, so the M7d verdict still closes the boot.
    #[test]
    fn m8b_markers_are_exact_and_placed() {
        assert_eq!(M8B_TIME, "[CaelumLinux] M8b time OK");
        assert_eq!(M8B_INFO, "[CaelumLinux] M8b info OK");
        assert_eq!(M8B_MARKERS, &[M8B_TIME, M8B_INFO]);
        for m in M8B_MARKERS {
            assert!(
                m.starts_with("[CaelumLinux] "),
                "{m:?} must be a [CaelumLinux] line"
            );
            assert_ne!(*m, FINAL_MARKER, "{m:?} must not be the final marker");
        }
        let mut unique = M8B_MARKERS.to_vec();
        unique.sort_unstable();
        unique.dedup();
        assert_eq!(unique.len(), M8B_MARKERS.len(), "duplicate M8b markers");

        // No new kernel verdict and no broader M8 claim is required.
        let required = required_markers(BootStage::First);
        for forbidden in [
            "[CaelumKernel] M8b OK",
            "[CaelumKernel] M8 OK",
            "[CaelumLinux] M8 OK",
        ] {
            assert!(
                !required.iter().any(|m| m.contains(forbidden)),
                "M8b must not require {forbidden:?}"
            );
        }

        for stage in [BootStage::First, BootStage::Second] {
            let all = required_markers(stage);
            assert_eq!(all.len(), 138, "{}", stage.label());
            for m in M8B_MARKERS {
                assert!(all.contains(m), "{}: missing {m:?}", stage.label());
            }
            assert_eq!(*all.last().unwrap(), M7D_KERNEL_OK);
            let text = complete_transcript(stage);
            assert!(
                acceptance_error(&text, stage).is_none(),
                "{}: {:?}",
                stage.label(),
                acceptance_error(&text, stage)
            );
            let files_at = text.rfind(M8A_FILES_SAMPLE).unwrap();
            let time_at = text.rfind(M8B_TIME_SAMPLE).unwrap();
            let info_at = text.rfind(M8B_INFO_SAMPLE).unwrap();
            let verdict_at = text.rfind(M7D_KERNEL_VERDICT_SAMPLE).unwrap();
            assert!(
                files_at < time_at && time_at < info_at && info_at < verdict_at,
                "{}: M8b lines must sit between the M8a lines and the kernel verdict",
                stage.label()
            );
        }

        // Missing lines are reported through `missing_markers`.
        let text = complete_transcript(BootStage::First);
        let without_time = text.replacen(&format!("{M8B_TIME_SAMPLE}\n"), "", 1);
        assert!(
            missing_markers(&without_time, BootStage::First).contains(&M8B_TIME),
            "dropping the time line must be reported missing"
        );
        let without_info = text.replacen(&format!("{M8B_INFO_SAMPLE}\n"), "", 1);
        assert!(
            missing_markers(&without_info, BootStage::First).contains(&M8B_INFO),
            "dropping the info line must be reported missing"
        );

        // Ordering violations are diagnosed by `marker_placement_error`.
        let time_early = text.replace(
            &format!("{M8A_FILES_SAMPLE}\n{M8B_TIME_SAMPLE}"),
            &format!("{M8B_TIME_SAMPLE}\n{M8A_FILES_SAMPLE}"),
        );
        let error = acceptance_error(&time_early, BootStage::First)
            .expect("M8b time before the M8a files line must fail");
        assert!(
            error.contains("must appear before"),
            "unexpected error: {error}"
        );

        let swapped = text.replace(
            &format!("{M8B_TIME_SAMPLE}\n{M8B_INFO_SAMPLE}"),
            &format!("{M8B_INFO_SAMPLE}\n{M8B_TIME_SAMPLE}"),
        );
        let error =
            acceptance_error(&swapped, BootStage::First).expect("swapped M8b lines must fail");
        assert!(
            error.contains("must appear before"),
            "unexpected error: {error}"
        );

        let info_after_verdict = text.replace(
            &format!(
                "{M8B_INFO_SAMPLE}\n{M8C_SIGNALS_SAMPLE}\n{M8D_PROCESS_SAMPLE}\n{M8E_FILES_SAMPLE}\n{M8F_FUTEX_SAMPLE}\n{M8F_TLS_SAMPLE}\n{M8G_EVENTFD_SAMPLE}\n{M8G_POLL_SAMPLE}\n{M8H_PROCFS_SAMPLE}\n{M8H_DEVFS_SAMPLE}\n{M9A_TIMERFD_SAMPLE}\n{M9A_SIGNALFD_SAMPLE}\n{M9A_EPOLL_SAMPLE}\n{M9B_ABSTRACT_SAMPLE}\n{M9B_RIGHTS_SAMPLE}\n{M9B_CREDENTIALS_SAMPLE}\n{M9B_EPOLL_ET_SAMPLE}\n{M9C_LOCKS_SAMPLE}\n{M9D_INTERP_SAMPLE}\n{M9D_DYNAMIC_SAMPLE}\n{M9D_VDSO_SAMPLE}\n{M9E_SHARED_SAMPLE}\n{M9F_SHARED_SAMPLE}\n{M10A_HELLO_SAMPLE}\n{M7D_KERNEL_VERDICT_SAMPLE}\n{M7C_NIC_SAMPLE}"
            ),
            &format!(
                "{M8C_SIGNALS_SAMPLE}\n{M8D_PROCESS_SAMPLE}\n{M8E_FILES_SAMPLE}\n{M8F_FUTEX_SAMPLE}\n{M8F_TLS_SAMPLE}\n{M8G_EVENTFD_SAMPLE}\n{M8G_POLL_SAMPLE}\n{M8H_PROCFS_SAMPLE}\n{M8H_DEVFS_SAMPLE}\n{M9A_TIMERFD_SAMPLE}\n{M9A_SIGNALFD_SAMPLE}\n{M9A_EPOLL_SAMPLE}\n{M9B_ABSTRACT_SAMPLE}\n{M9B_RIGHTS_SAMPLE}\n{M9B_CREDENTIALS_SAMPLE}\n{M9B_EPOLL_ET_SAMPLE}\n{M9C_LOCKS_SAMPLE}\n{M9D_INTERP_SAMPLE}\n{M9D_DYNAMIC_SAMPLE}\n{M9D_VDSO_SAMPLE}\n{M9E_SHARED_SAMPLE}\n{M9F_SHARED_SAMPLE}\n{M10A_HELLO_SAMPLE}\n{M7D_KERNEL_VERDICT_SAMPLE}\n{M7C_NIC_SAMPLE}\n{M8B_INFO_SAMPLE}"
            ),
        );
        let error = acceptance_error(&info_after_verdict, BootStage::First)
            .expect("M8b info after the M7d verdict must fail");
        assert!(
            error.contains("must appear before"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn m8c_markers_are_exact_and_placed() {
        assert_eq!(M8C_SIGNALS, "[CaelumLinux] M8c signals OK");
        assert_eq!(M8C_MARKERS, &[M8C_SIGNALS]);
        for m in M8C_MARKERS {
            assert!(
                m.starts_with("[CaelumLinux] "),
                "{m:?} must be a [CaelumLinux] line"
            );
            assert_ne!(*m, FINAL_MARKER, "{m:?} must not be the final marker");
        }
        let mut unique = M8C_MARKERS.to_vec();
        unique.sort_unstable();
        unique.dedup();
        assert_eq!(unique.len(), M8C_MARKERS.len(), "duplicate M8c markers");

        // No new kernel verdict and no broader M8 claim is required.
        let required = required_markers(BootStage::First);
        for forbidden in [
            "[CaelumKernel] M8c OK",
            "[CaelumKernel] M8 OK",
            "[CaelumLinux] M8 OK",
        ] {
            assert!(
                !required.iter().any(|m| m.contains(forbidden)),
                "M8c must not require {forbidden:?}"
            );
        }

        for stage in [BootStage::First, BootStage::Second] {
            let all = required_markers(stage);
            assert_eq!(all.len(), 138, "{}", stage.label());
            for m in M8C_MARKERS {
                assert!(all.contains(m), "{}: missing {m:?}", stage.label());
            }
            assert_eq!(*all.last().unwrap(), M7D_KERNEL_OK);
            let text = complete_transcript(stage);
            assert!(
                acceptance_error(&text, stage).is_none(),
                "{}: {:?}",
                stage.label(),
                acceptance_error(&text, stage)
            );
            let info_at = text.rfind(M8B_INFO_SAMPLE).unwrap();
            let signals_at = text.rfind(M8C_SIGNALS_SAMPLE).unwrap();
            let verdict_at = text.rfind(M7D_KERNEL_VERDICT_SAMPLE).unwrap();
            assert!(
                info_at < signals_at && signals_at < verdict_at,
                "{}: the M8c signals line must sit between M8b and the kernel verdict",
                stage.label()
            );
        }

        // The line is a required marker: dropping it is reported missing.
        let text = complete_transcript(BootStage::First);
        let without_signals = text.replacen(&format!("{M8C_SIGNALS_SAMPLE}\n"), "", 1);
        assert!(
            missing_markers(&without_signals, BootStage::First).contains(&M8C_SIGNALS),
            "dropping the signals line must be reported missing"
        );

        // Ordering violations are diagnosed by `marker_placement_error`.
        let signals_early = text.replace(
            &format!("{M8B_INFO_SAMPLE}\n{M8C_SIGNALS_SAMPLE}"),
            &format!("{M8C_SIGNALS_SAMPLE}\n{M8B_INFO_SAMPLE}"),
        );
        let error = acceptance_error(&signals_early, BootStage::First)
            .expect("M8c signals before the M8b info line must fail");
        assert!(
            error.contains("must appear before"),
            "unexpected error: {error}"
        );

        let signals_after_verdict = text.replace(
            &format!(
                "{M8B_INFO_SAMPLE}\n{M8C_SIGNALS_SAMPLE}\n{M8D_PROCESS_SAMPLE}\n{M8E_FILES_SAMPLE}\n{M8F_FUTEX_SAMPLE}\n{M8F_TLS_SAMPLE}\n{M8G_EVENTFD_SAMPLE}\n{M8G_POLL_SAMPLE}\n{M8H_PROCFS_SAMPLE}\n{M8H_DEVFS_SAMPLE}\n{M9A_TIMERFD_SAMPLE}\n{M9A_SIGNALFD_SAMPLE}\n{M9A_EPOLL_SAMPLE}\n{M9B_ABSTRACT_SAMPLE}\n{M9B_RIGHTS_SAMPLE}\n{M9B_CREDENTIALS_SAMPLE}\n{M9B_EPOLL_ET_SAMPLE}\n{M9C_LOCKS_SAMPLE}\n{M9D_INTERP_SAMPLE}\n{M9D_DYNAMIC_SAMPLE}\n{M9D_VDSO_SAMPLE}\n{M9E_SHARED_SAMPLE}\n{M9F_SHARED_SAMPLE}\n{M10A_HELLO_SAMPLE}\n{M7D_KERNEL_VERDICT_SAMPLE}\n{M7C_NIC_SAMPLE}"
            ),
            &format!(
                "{M8B_INFO_SAMPLE}\n{M8D_PROCESS_SAMPLE}\n{M8E_FILES_SAMPLE}\n{M8F_FUTEX_SAMPLE}\n{M8F_TLS_SAMPLE}\n{M8G_EVENTFD_SAMPLE}\n{M8G_POLL_SAMPLE}\n{M8H_PROCFS_SAMPLE}\n{M8H_DEVFS_SAMPLE}\n{M9A_TIMERFD_SAMPLE}\n{M9A_SIGNALFD_SAMPLE}\n{M9A_EPOLL_SAMPLE}\n{M9B_ABSTRACT_SAMPLE}\n{M9B_RIGHTS_SAMPLE}\n{M9B_CREDENTIALS_SAMPLE}\n{M9B_EPOLL_ET_SAMPLE}\n{M9C_LOCKS_SAMPLE}\n{M9D_INTERP_SAMPLE}\n{M9D_DYNAMIC_SAMPLE}\n{M9D_VDSO_SAMPLE}\n{M9E_SHARED_SAMPLE}\n{M9F_SHARED_SAMPLE}\n{M10A_HELLO_SAMPLE}\n{M7D_KERNEL_VERDICT_SAMPLE}\n{M7C_NIC_SAMPLE}\n{M8C_SIGNALS_SAMPLE}"
            ),
        );
        let error = acceptance_error(&signals_after_verdict, BootStage::First)
            .expect("M8c signals after the M7d verdict must fail");
        assert!(
            error.contains("must appear before"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn m8d_markers_are_exact_and_placed() {
        assert_eq!(M8D_PROCESS, "[CaelumLinux] M8d process OK");
        assert_eq!(M8D_MARKERS, &[M8D_PROCESS]);
        for m in M8D_MARKERS {
            assert!(
                m.starts_with("[CaelumLinux] "),
                "{m:?} must be a [CaelumLinux] line"
            );
            assert_ne!(*m, FINAL_MARKER, "{m:?} must not be the final marker");
        }
        let mut unique = M8D_MARKERS.to_vec();
        unique.sort_unstable();
        unique.dedup();
        assert_eq!(unique.len(), M8D_MARKERS.len(), "duplicate M8d markers");

        // No new kernel verdict and no broader M8 claim is required.
        let required = required_markers(BootStage::First);
        for forbidden in [
            "[CaelumKernel] M8d OK",
            "[CaelumKernel] M8 OK",
            "[CaelumLinux] M8 OK",
        ] {
            assert!(
                !required.iter().any(|m| m.contains(forbidden)),
                "M8d must not require {forbidden:?}"
            );
        }

        for stage in [BootStage::First, BootStage::Second] {
            let all = required_markers(stage);
            assert_eq!(all.len(), 138, "{}", stage.label());
            for m in M8D_MARKERS {
                assert!(all.contains(m), "{}: missing {m:?}", stage.label());
            }
            assert_eq!(*all.last().unwrap(), M7D_KERNEL_OK);
            let text = complete_transcript(stage);
            assert!(
                acceptance_error(&text, stage).is_none(),
                "{}: {:?}",
                stage.label(),
                acceptance_error(&text, stage)
            );
            let signals_at = text.rfind(M8C_SIGNALS_SAMPLE).unwrap();
            let process_at = text.rfind(M8D_PROCESS_SAMPLE).unwrap();
            let verdict_at = text.rfind(M7D_KERNEL_VERDICT_SAMPLE).unwrap();
            assert!(
                signals_at < process_at && process_at < verdict_at,
                "{}: the M8d process line must sit between M8c and the kernel verdict",
                stage.label()
            );
        }

        // The line is a required marker: dropping it is reported missing.
        let text = complete_transcript(BootStage::First);
        let without_process = text.replacen(&format!("{M8D_PROCESS_SAMPLE}\n"), "", 1);
        assert!(
            missing_markers(&without_process, BootStage::First).contains(&M8D_PROCESS),
            "dropping the process line must be reported missing"
        );

        // Ordering violations are diagnosed by `marker_placement_error`.
        let process_early = text.replace(
            &format!("{M8B_INFO_SAMPLE}\n{M8C_SIGNALS_SAMPLE}\n{M8D_PROCESS_SAMPLE}"),
            &format!("{M8D_PROCESS_SAMPLE}\n{M8B_INFO_SAMPLE}\n{M8C_SIGNALS_SAMPLE}"),
        );
        let error = acceptance_error(&process_early, BootStage::First)
            .expect("M8d process before the M8b/M8c lines must fail");
        assert!(
            error.contains("must appear before"),
            "unexpected error: {error}"
        );

        let process_after_verdict = text.replace(
            &format!("{M8D_PROCESS_SAMPLE}\n{M8E_FILES_SAMPLE}\n{M8F_FUTEX_SAMPLE}\n{M8F_TLS_SAMPLE}\n{M8G_EVENTFD_SAMPLE}\n{M8G_POLL_SAMPLE}\n{M8H_PROCFS_SAMPLE}\n{M8H_DEVFS_SAMPLE}\n{M9A_TIMERFD_SAMPLE}\n{M9A_SIGNALFD_SAMPLE}\n{M9A_EPOLL_SAMPLE}\n{M9B_ABSTRACT_SAMPLE}\n{M9B_RIGHTS_SAMPLE}\n{M9B_CREDENTIALS_SAMPLE}\n{M9B_EPOLL_ET_SAMPLE}\n{M9C_LOCKS_SAMPLE}\n{M9D_INTERP_SAMPLE}\n{M9D_DYNAMIC_SAMPLE}\n{M9D_VDSO_SAMPLE}\n{M9E_SHARED_SAMPLE}\n{M9F_SHARED_SAMPLE}\n{M10A_HELLO_SAMPLE}\n{M7D_KERNEL_VERDICT_SAMPLE}\n{M7C_NIC_SAMPLE}"),
            &format!("{M8E_FILES_SAMPLE}\n{M8F_FUTEX_SAMPLE}\n{M8F_TLS_SAMPLE}\n{M8G_EVENTFD_SAMPLE}\n{M8G_POLL_SAMPLE}\n{M8H_PROCFS_SAMPLE}\n{M8H_DEVFS_SAMPLE}\n{M9A_TIMERFD_SAMPLE}\n{M9A_SIGNALFD_SAMPLE}\n{M9A_EPOLL_SAMPLE}\n{M9B_ABSTRACT_SAMPLE}\n{M9B_RIGHTS_SAMPLE}\n{M9B_CREDENTIALS_SAMPLE}\n{M9B_EPOLL_ET_SAMPLE}\n{M9C_LOCKS_SAMPLE}\n{M9D_INTERP_SAMPLE}\n{M9D_DYNAMIC_SAMPLE}\n{M9D_VDSO_SAMPLE}\n{M9E_SHARED_SAMPLE}\n{M9F_SHARED_SAMPLE}\n{M10A_HELLO_SAMPLE}\n{M7D_KERNEL_VERDICT_SAMPLE}\n{M7C_NIC_SAMPLE}\n{M8D_PROCESS_SAMPLE}"),
        );
        let error = acceptance_error(&process_after_verdict, BootStage::First)
            .expect("M8d process after the M7d verdict must fail");
        assert!(
            error.contains("must appear before"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn m8e_markers_are_exact_and_placed() {
        assert_eq!(M8E_FILES, "[CaelumLinux] M8e files OK");
        assert_eq!(M8E_MARKERS, &[M8E_FILES]);
        for m in M8E_MARKERS {
            assert!(
                m.starts_with("[CaelumLinux] "),
                "{m:?} must be a [CaelumLinux] line"
            );
            assert_ne!(*m, FINAL_MARKER, "{m:?} must not be the final marker");
        }
        let mut unique = M8E_MARKERS.to_vec();
        unique.sort_unstable();
        unique.dedup();
        assert_eq!(unique.len(), M8E_MARKERS.len(), "duplicate M8e markers");

        // No new kernel verdict and no broader M8 claim is required.
        let required = required_markers(BootStage::First);
        for forbidden in [
            "[CaelumKernel] M8e OK",
            "[CaelumKernel] M8 OK",
            "[CaelumLinux] M8 OK",
        ] {
            assert!(
                !required.iter().any(|m| m.contains(forbidden)),
                "M8e must not require {forbidden:?}"
            );
        }

        for stage in [BootStage::First, BootStage::Second] {
            let all = required_markers(stage);
            assert_eq!(all.len(), 138, "{}", stage.label());
            for m in M8E_MARKERS {
                assert!(all.contains(m), "{}: missing {m:?}", stage.label());
            }
            assert_eq!(*all.last().unwrap(), M7D_KERNEL_OK);
            let text = complete_transcript(stage);
            assert!(
                acceptance_error(&text, stage).is_none(),
                "{}: {:?}",
                stage.label(),
                acceptance_error(&text, stage)
            );
            let process_at = text.rfind(M8D_PROCESS_SAMPLE).unwrap();
            let files_at = text.rfind(M8E_FILES_SAMPLE).unwrap();
            let verdict_at = text.rfind(M7D_KERNEL_VERDICT_SAMPLE).unwrap();
            assert!(
                process_at < files_at && files_at < verdict_at,
                "{}: the M8e files line must sit between M8d and the kernel verdict",
                stage.label()
            );
        }

        // The line is a required marker: dropping it is reported missing.
        let text = complete_transcript(BootStage::First);
        let without_files = text.replacen(&format!("{M8E_FILES_SAMPLE}\n"), "", 1);
        assert!(
            missing_markers(&without_files, BootStage::First).contains(&M8E_FILES),
            "dropping the files line must be reported missing"
        );

        // Ordering violations are diagnosed by `marker_placement_error`.
        let files_early = text.replace(
            &format!("{M8C_SIGNALS_SAMPLE}\n{M8D_PROCESS_SAMPLE}\n{M8E_FILES_SAMPLE}"),
            &format!("{M8E_FILES_SAMPLE}\n{M8C_SIGNALS_SAMPLE}\n{M8D_PROCESS_SAMPLE}"),
        );
        let error = acceptance_error(&files_early, BootStage::First)
            .expect("M8e files before the M8c/M8d lines must fail");
        assert!(
            error.contains("must appear before"),
            "unexpected error: {error}"
        );

        let files_after_verdict = text.replace(
            &format!("{M8D_PROCESS_SAMPLE}\n{M8E_FILES_SAMPLE}\n{M8F_FUTEX_SAMPLE}\n{M8F_TLS_SAMPLE}\n{M8G_EVENTFD_SAMPLE}\n{M8G_POLL_SAMPLE}\n{M8H_PROCFS_SAMPLE}\n{M8H_DEVFS_SAMPLE}\n{M9A_TIMERFD_SAMPLE}\n{M9A_SIGNALFD_SAMPLE}\n{M9A_EPOLL_SAMPLE}\n{M9B_ABSTRACT_SAMPLE}\n{M9B_RIGHTS_SAMPLE}\n{M9B_CREDENTIALS_SAMPLE}\n{M9B_EPOLL_ET_SAMPLE}\n{M9C_LOCKS_SAMPLE}\n{M9D_INTERP_SAMPLE}\n{M9D_DYNAMIC_SAMPLE}\n{M9D_VDSO_SAMPLE}\n{M9E_SHARED_SAMPLE}\n{M9F_SHARED_SAMPLE}\n{M10A_HELLO_SAMPLE}\n{M7D_KERNEL_VERDICT_SAMPLE}\n{M7C_NIC_SAMPLE}"),
            &format!("{M8D_PROCESS_SAMPLE}\n{M8F_FUTEX_SAMPLE}\n{M8F_TLS_SAMPLE}\n{M8G_EVENTFD_SAMPLE}\n{M8G_POLL_SAMPLE}\n{M8H_PROCFS_SAMPLE}\n{M8H_DEVFS_SAMPLE}\n{M9A_TIMERFD_SAMPLE}\n{M9A_SIGNALFD_SAMPLE}\n{M9A_EPOLL_SAMPLE}\n{M9B_ABSTRACT_SAMPLE}\n{M9B_RIGHTS_SAMPLE}\n{M9B_CREDENTIALS_SAMPLE}\n{M9B_EPOLL_ET_SAMPLE}\n{M9C_LOCKS_SAMPLE}\n{M9D_INTERP_SAMPLE}\n{M9D_DYNAMIC_SAMPLE}\n{M9D_VDSO_SAMPLE}\n{M9E_SHARED_SAMPLE}\n{M9F_SHARED_SAMPLE}\n{M10A_HELLO_SAMPLE}\n{M7D_KERNEL_VERDICT_SAMPLE}\n{M7C_NIC_SAMPLE}\n{M8E_FILES_SAMPLE}"),
        );
        let error = acceptance_error(&files_after_verdict, BootStage::First)
            .expect("M8e files after the M7d verdict must fail");
        assert!(
            error.contains("must appear before"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn m8f_markers_are_exact_and_placed() {
        assert_eq!(M8F_FUTEX, "[CaelumLinux] M8f futex OK");
        assert_eq!(M8F_TLS, "[CaelumLinux] M8f tls OK");
        assert_eq!(M8F_MARKERS, &[M8F_FUTEX, M8F_TLS]);
        for m in M8F_MARKERS {
            assert!(
                m.starts_with("[CaelumLinux] "),
                "{m:?} must be a [CaelumLinux] line"
            );
            assert_ne!(*m, FINAL_MARKER, "{m:?} must not be the final marker");
        }
        let mut unique = M8F_MARKERS.to_vec();
        unique.sort_unstable();
        unique.dedup();
        assert_eq!(unique.len(), M8F_MARKERS.len(), "duplicate M8f markers");

        // No new kernel verdict and no broader M8 claim is required.
        let required = required_markers(BootStage::First);
        for forbidden in [
            "[CaelumKernel] M8f OK",
            "[CaelumKernel] M8 OK",
            "[CaelumLinux] M8 OK",
        ] {
            assert!(
                !required.iter().any(|m| m.contains(forbidden)),
                "M8f must not require {forbidden:?}"
            );
        }

        for stage in [BootStage::First, BootStage::Second] {
            let all = required_markers(stage);
            assert_eq!(all.len(), 138, "{}", stage.label());
            for m in M8F_MARKERS {
                assert!(all.contains(m), "{}: missing {m:?}", stage.label());
            }
            assert_eq!(*all.last().unwrap(), M7D_KERNEL_OK);
            let text = complete_transcript(stage);
            assert!(
                acceptance_error(&text, stage).is_none(),
                "{}: {:?}",
                stage.label(),
                acceptance_error(&text, stage)
            );
            let files_at = text.rfind(M8E_FILES_SAMPLE).unwrap();
            let futex_at = text.rfind(M8F_FUTEX_SAMPLE).unwrap();
            let tls_at = text.rfind(M8F_TLS_SAMPLE).unwrap();
            let verdict_at = text.rfind(M7D_KERNEL_VERDICT_SAMPLE).unwrap();
            assert!(
                files_at < futex_at && futex_at < tls_at && tls_at < verdict_at,
                "{}: the M8f lines must sit between M8e and the kernel verdict",
                stage.label()
            );
        }

        // Both lines are required markers: dropping either is reported missing.
        let text = complete_transcript(BootStage::First);
        let without_futex = text.replacen(&format!("{M8F_FUTEX_SAMPLE}\n"), "", 1);
        assert!(
            missing_markers(&without_futex, BootStage::First).contains(&M8F_FUTEX),
            "dropping the futex line must be reported missing"
        );
        let without_tls = text.replacen(&format!("{M8F_TLS_SAMPLE}\n"), "", 1);
        assert!(
            missing_markers(&without_tls, BootStage::First).contains(&M8F_TLS),
            "dropping the tls line must be reported missing"
        );

        // Ordering violations are diagnosed by `marker_placement_error`.
        let futex_before_e = text.replace(
            &format!("{M8E_FILES_SAMPLE}\n{M8F_FUTEX_SAMPLE}"),
            &format!("{M8F_FUTEX_SAMPLE}\n{M8E_FILES_SAMPLE}"),
        );
        let error = acceptance_error(&futex_before_e, BootStage::First)
            .expect("M8f futex before M8e must fail");
        assert!(
            error.contains("must appear before"),
            "unexpected error: {error}"
        );

        let tls_after_verdict = text.replace(
            &format!("{M8F_TLS_SAMPLE}\n{M8G_EVENTFD_SAMPLE}\n{M8G_POLL_SAMPLE}\n{M8H_PROCFS_SAMPLE}\n{M8H_DEVFS_SAMPLE}\n{M9A_TIMERFD_SAMPLE}\n{M9A_SIGNALFD_SAMPLE}\n{M9A_EPOLL_SAMPLE}\n{M9B_ABSTRACT_SAMPLE}\n{M9B_RIGHTS_SAMPLE}\n{M9B_CREDENTIALS_SAMPLE}\n{M9B_EPOLL_ET_SAMPLE}\n{M9C_LOCKS_SAMPLE}\n{M9D_INTERP_SAMPLE}\n{M9D_DYNAMIC_SAMPLE}\n{M9D_VDSO_SAMPLE}\n{M9E_SHARED_SAMPLE}\n{M9F_SHARED_SAMPLE}\n{M10A_HELLO_SAMPLE}\n{M7D_KERNEL_VERDICT_SAMPLE}\n{M7C_NIC_SAMPLE}"),
            &format!("{M8G_EVENTFD_SAMPLE}\n{M8G_POLL_SAMPLE}\n{M8H_PROCFS_SAMPLE}\n{M8H_DEVFS_SAMPLE}\n{M9A_TIMERFD_SAMPLE}\n{M9A_SIGNALFD_SAMPLE}\n{M9A_EPOLL_SAMPLE}\n{M9B_ABSTRACT_SAMPLE}\n{M9B_RIGHTS_SAMPLE}\n{M9B_CREDENTIALS_SAMPLE}\n{M9B_EPOLL_ET_SAMPLE}\n{M9C_LOCKS_SAMPLE}\n{M9D_INTERP_SAMPLE}\n{M9D_DYNAMIC_SAMPLE}\n{M9D_VDSO_SAMPLE}\n{M9E_SHARED_SAMPLE}\n{M9F_SHARED_SAMPLE}\n{M10A_HELLO_SAMPLE}\n{M7D_KERNEL_VERDICT_SAMPLE}\n{M7C_NIC_SAMPLE}\n{M8F_TLS_SAMPLE}"),
        );
        let error = acceptance_error(&tls_after_verdict, BootStage::First)
            .expect("M8f tls after the M7d verdict must fail");
        assert!(
            error.contains("must appear before"),
            "unexpected error: {error}"
        );

        let futex_after_verdict = text.replace(
            &format!("{M8E_FILES_SAMPLE}\n{M8F_FUTEX_SAMPLE}\n{M8F_TLS_SAMPLE}\n{M8G_EVENTFD_SAMPLE}\n{M8G_POLL_SAMPLE}\n{M8H_PROCFS_SAMPLE}\n{M8H_DEVFS_SAMPLE}\n{M9A_TIMERFD_SAMPLE}\n{M9A_SIGNALFD_SAMPLE}\n{M9A_EPOLL_SAMPLE}\n{M9B_ABSTRACT_SAMPLE}\n{M9B_RIGHTS_SAMPLE}\n{M9B_CREDENTIALS_SAMPLE}\n{M9B_EPOLL_ET_SAMPLE}\n{M9C_LOCKS_SAMPLE}\n{M9D_INTERP_SAMPLE}\n{M9D_DYNAMIC_SAMPLE}\n{M9D_VDSO_SAMPLE}\n{M9E_SHARED_SAMPLE}\n{M9F_SHARED_SAMPLE}\n{M10A_HELLO_SAMPLE}\n{M7D_KERNEL_VERDICT_SAMPLE}\n{M7C_NIC_SAMPLE}"),
            &format!("{M8E_FILES_SAMPLE}\n{M8F_TLS_SAMPLE}\n{M8G_EVENTFD_SAMPLE}\n{M8G_POLL_SAMPLE}\n{M8H_PROCFS_SAMPLE}\n{M8H_DEVFS_SAMPLE}\n{M9A_TIMERFD_SAMPLE}\n{M9A_SIGNALFD_SAMPLE}\n{M9A_EPOLL_SAMPLE}\n{M9B_ABSTRACT_SAMPLE}\n{M9B_RIGHTS_SAMPLE}\n{M9B_CREDENTIALS_SAMPLE}\n{M9B_EPOLL_ET_SAMPLE}\n{M9C_LOCKS_SAMPLE}\n{M9D_INTERP_SAMPLE}\n{M9D_DYNAMIC_SAMPLE}\n{M9D_VDSO_SAMPLE}\n{M9E_SHARED_SAMPLE}\n{M9F_SHARED_SAMPLE}\n{M10A_HELLO_SAMPLE}\n{M7D_KERNEL_VERDICT_SAMPLE}\n{M7C_NIC_SAMPLE}\n{M8F_FUTEX_SAMPLE}"),
        );
        let error = acceptance_error(&futex_after_verdict, BootStage::First)
            .expect("M8f futex after the M7d verdict must fail");
        assert!(
            error.contains("must appear before"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn m8g_markers_are_exact_and_placed() {
        assert_eq!(M8G_EVENTFD, "[CaelumLinux] M8g eventfd OK");
        assert_eq!(M8G_POLL, "[CaelumLinux] M8g poll OK");
        assert_eq!(M8G_MARKERS, &[M8G_EVENTFD, M8G_POLL]);
        for m in M8G_MARKERS {
            assert!(
                m.starts_with("[CaelumLinux] "),
                "{m:?} must be a [CaelumLinux] line"
            );
            assert_ne!(*m, FINAL_MARKER, "{m:?} must not be the final marker");
        }
        let mut unique = M8G_MARKERS.to_vec();
        unique.sort_unstable();
        unique.dedup();
        assert_eq!(unique.len(), M8G_MARKERS.len(), "duplicate M8g markers");

        // No new kernel verdict and no broader M8 claim is required.
        let required = required_markers(BootStage::First);
        for forbidden in [
            "[CaelumKernel] M8g OK",
            "[CaelumKernel] M8 OK",
            "[CaelumLinux] M8 OK",
        ] {
            assert!(
                !required.iter().any(|m| m.contains(forbidden)),
                "M8g must not require {forbidden:?}"
            );
        }

        for stage in [BootStage::First, BootStage::Second] {
            let all = required_markers(stage);
            assert_eq!(all.len(), 138, "{}", stage.label());
            for m in M8G_MARKERS {
                assert!(all.contains(m), "{}: missing {m:?}", stage.label());
            }
            assert_eq!(*all.last().unwrap(), M7D_KERNEL_OK);
            let text = complete_transcript(stage);
            assert!(
                acceptance_error(&text, stage).is_none(),
                "{}: {:?}",
                stage.label(),
                acceptance_error(&text, stage)
            );
            let tls_at = text.rfind(M8F_TLS_SAMPLE).unwrap();
            let eventfd_at = text.rfind(M8G_EVENTFD_SAMPLE).unwrap();
            let poll_at = text.rfind(M8G_POLL_SAMPLE).unwrap();
            let verdict_at = text.rfind(M7D_KERNEL_VERDICT_SAMPLE).unwrap();
            assert!(
                tls_at < eventfd_at && eventfd_at < poll_at && poll_at < verdict_at,
                "{}: the M8g lines must sit between M8f and the kernel verdict",
                stage.label()
            );
        }

        // Both lines are required markers: dropping either is reported missing.
        let text = complete_transcript(BootStage::First);
        let without_eventfd = text.replacen(&format!("{M8G_EVENTFD_SAMPLE}\n"), "", 1);
        assert!(
            missing_markers(&without_eventfd, BootStage::First).contains(&M8G_EVENTFD),
            "dropping the eventfd line must be reported missing"
        );
        let without_poll = text.replacen(&format!("{M8G_POLL_SAMPLE}\n"), "", 1);
        assert!(
            missing_markers(&without_poll, BootStage::First).contains(&M8G_POLL),
            "dropping the poll line must be reported missing"
        );

        // Ordering violations are diagnosed by `marker_placement_error`.
        let eventfd_before_tls = text.replace(
            &format!("{M8F_TLS_SAMPLE}\n{M8G_EVENTFD_SAMPLE}"),
            &format!("{M8G_EVENTFD_SAMPLE}\n{M8F_TLS_SAMPLE}"),
        );
        let error = acceptance_error(&eventfd_before_tls, BootStage::First)
            .expect("M8g eventfd before M8f tls must fail");
        assert!(
            error.contains("must appear before"),
            "unexpected error: {error}"
        );

        let poll_before_eventfd = text.replace(
            &format!("{M8G_EVENTFD_SAMPLE}\n{M8G_POLL_SAMPLE}"),
            &format!("{M8G_POLL_SAMPLE}\n{M8G_EVENTFD_SAMPLE}"),
        );
        let error = acceptance_error(&poll_before_eventfd, BootStage::First)
            .expect("M8g poll before eventfd must fail");
        assert!(
            error.contains("must appear before"),
            "unexpected error: {error}"
        );

        let poll_after_verdict = text.replace(
            &format!("{M8G_POLL_SAMPLE}\n{M8H_PROCFS_SAMPLE}\n{M8H_DEVFS_SAMPLE}\n{M9A_TIMERFD_SAMPLE}\n{M9A_SIGNALFD_SAMPLE}\n{M9A_EPOLL_SAMPLE}\n{M9B_ABSTRACT_SAMPLE}\n{M9B_RIGHTS_SAMPLE}\n{M9B_CREDENTIALS_SAMPLE}\n{M9B_EPOLL_ET_SAMPLE}\n{M9C_LOCKS_SAMPLE}\n{M9D_INTERP_SAMPLE}\n{M9D_DYNAMIC_SAMPLE}\n{M9D_VDSO_SAMPLE}\n{M9E_SHARED_SAMPLE}\n{M9F_SHARED_SAMPLE}\n{M10A_HELLO_SAMPLE}\n{M7D_KERNEL_VERDICT_SAMPLE}\n{M7C_NIC_SAMPLE}"),
            &format!("{M8H_PROCFS_SAMPLE}\n{M8H_DEVFS_SAMPLE}\n{M9A_TIMERFD_SAMPLE}\n{M9A_SIGNALFD_SAMPLE}\n{M9A_EPOLL_SAMPLE}\n{M9B_ABSTRACT_SAMPLE}\n{M9B_RIGHTS_SAMPLE}\n{M9B_CREDENTIALS_SAMPLE}\n{M9B_EPOLL_ET_SAMPLE}\n{M9C_LOCKS_SAMPLE}\n{M9D_INTERP_SAMPLE}\n{M9D_DYNAMIC_SAMPLE}\n{M9D_VDSO_SAMPLE}\n{M9E_SHARED_SAMPLE}\n{M9F_SHARED_SAMPLE}\n{M10A_HELLO_SAMPLE}\n{M7D_KERNEL_VERDICT_SAMPLE}\n{M7C_NIC_SAMPLE}\n{M8G_POLL_SAMPLE}"),
        );
        let error = acceptance_error(&poll_after_verdict, BootStage::First)
            .expect("M8g poll after the M7d verdict must fail");
        assert!(
            error.contains("must appear before"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn m8h_markers_are_exact_and_placed() {
        assert_eq!(M8H_PROCFS, "[CaelumLinux] M8h procfs OK");
        assert_eq!(M8H_DEVFS, "[CaelumLinux] M8h devfs OK");
        assert_eq!(M8H_MARKERS, &[M8H_PROCFS, M8H_DEVFS]);
        for m in M8H_MARKERS {
            assert!(
                m.starts_with("[CaelumLinux] "),
                "{m:?} must be a [CaelumLinux] line"
            );
            assert_ne!(*m, FINAL_MARKER, "{m:?} must not be the final marker");
        }
        let mut unique = M8H_MARKERS.to_vec();
        unique.sort_unstable();
        unique.dedup();
        assert_eq!(unique.len(), M8H_MARKERS.len(), "duplicate M8h markers");

        // No new kernel verdict and no broader M8 claim is required.
        let required = required_markers(BootStage::First);
        for forbidden in [
            "[CaelumKernel] M8h OK",
            "[CaelumKernel] M8 OK",
            "[CaelumLinux] M8 OK",
        ] {
            assert!(
                !required.iter().any(|m| m.contains(forbidden)),
                "M8h must not require {forbidden:?}"
            );
        }

        for stage in [BootStage::First, BootStage::Second] {
            let all = required_markers(stage);
            assert_eq!(all.len(), 138, "{}", stage.label());
            for m in M8H_MARKERS {
                assert!(all.contains(m), "{}: missing {m:?}", stage.label());
            }
            assert_eq!(*all.last().unwrap(), M7D_KERNEL_OK);
            let text = complete_transcript(stage);
            assert!(
                acceptance_error(&text, stage).is_none(),
                "{}: {:?}",
                stage.label(),
                acceptance_error(&text, stage)
            );
            let poll_at = text.rfind(M8G_POLL_SAMPLE).unwrap();
            let procfs_at = text.rfind(M8H_PROCFS_SAMPLE).unwrap();
            let devfs_at = text.rfind(M8H_DEVFS_SAMPLE).unwrap();
            let verdict_at = text.rfind(M7D_KERNEL_VERDICT_SAMPLE).unwrap();
            assert!(
                poll_at < procfs_at && procfs_at < devfs_at && devfs_at < verdict_at,
                "{}: the M8h lines must sit between M8g and the kernel verdict",
                stage.label()
            );
        }

        // Both lines are required markers: dropping either is reported missing.
        let text = complete_transcript(BootStage::First);
        let without_procfs = text.replacen(&format!("{M8H_PROCFS_SAMPLE}\n"), "", 1);
        assert!(
            missing_markers(&without_procfs, BootStage::First).contains(&M8H_PROCFS),
            "dropping the procfs line must be reported missing"
        );
        let without_devfs = text.replacen(&format!("{M8H_DEVFS_SAMPLE}\n"), "", 1);
        assert!(
            missing_markers(&without_devfs, BootStage::First).contains(&M8H_DEVFS),
            "dropping the devfs line must be reported missing"
        );

        // Ordering violations are diagnosed by `marker_placement_error`.
        let procfs_before_poll = text.replace(
            &format!("{M8G_POLL_SAMPLE}\n{M8H_PROCFS_SAMPLE}"),
            &format!("{M8H_PROCFS_SAMPLE}\n{M8G_POLL_SAMPLE}"),
        );
        let error = acceptance_error(&procfs_before_poll, BootStage::First)
            .expect("M8h procfs before M8g poll must fail");
        assert!(
            error.contains("must appear before"),
            "unexpected error: {error}"
        );

        let devfs_before_procfs = text.replace(
            &format!("{M8H_PROCFS_SAMPLE}\n{M8H_DEVFS_SAMPLE}"),
            &format!("{M8H_DEVFS_SAMPLE}\n{M8H_PROCFS_SAMPLE}"),
        );
        let error = acceptance_error(&devfs_before_procfs, BootStage::First)
            .expect("M8h devfs before procfs must fail");
        assert!(
            error.contains("must appear before"),
            "unexpected error: {error}"
        );

        let devfs_after_verdict = text.replace(
            &format!("{M8H_DEVFS_SAMPLE}\n{M9A_TIMERFD_SAMPLE}\n{M9A_SIGNALFD_SAMPLE}\n{M9A_EPOLL_SAMPLE}\n{M9B_ABSTRACT_SAMPLE}\n{M9B_RIGHTS_SAMPLE}\n{M9B_CREDENTIALS_SAMPLE}\n{M9B_EPOLL_ET_SAMPLE}\n{M9C_LOCKS_SAMPLE}\n{M9D_INTERP_SAMPLE}\n{M9D_DYNAMIC_SAMPLE}\n{M9D_VDSO_SAMPLE}\n{M9E_SHARED_SAMPLE}\n{M9F_SHARED_SAMPLE}\n{M10A_HELLO_SAMPLE}\n{M7D_KERNEL_VERDICT_SAMPLE}\n{M7C_NIC_SAMPLE}"),
            &format!("{M9A_TIMERFD_SAMPLE}\n{M9A_SIGNALFD_SAMPLE}\n{M9A_EPOLL_SAMPLE}\n{M9B_ABSTRACT_SAMPLE}\n{M9B_RIGHTS_SAMPLE}\n{M9B_CREDENTIALS_SAMPLE}\n{M9B_EPOLL_ET_SAMPLE}\n{M9C_LOCKS_SAMPLE}\n{M9D_INTERP_SAMPLE}\n{M9D_DYNAMIC_SAMPLE}\n{M9D_VDSO_SAMPLE}\n{M9E_SHARED_SAMPLE}\n{M9F_SHARED_SAMPLE}\n{M10A_HELLO_SAMPLE}\n{M7D_KERNEL_VERDICT_SAMPLE}\n{M7C_NIC_SAMPLE}\n{M8H_DEVFS_SAMPLE}"),
        );
        let error = acceptance_error(&devfs_after_verdict, BootStage::First)
            .expect("M8h devfs after the M7d verdict must fail");
        assert!(
            error.contains("must appear before"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn m9a_markers_are_exact_and_placed() {
        assert_eq!(M9A_TIMERFD, "[CaelumLinux] M9a timerfd OK");
        assert_eq!(M9A_SIGNALFD, "[CaelumLinux] M9a signalfd OK");
        assert_eq!(M9A_EPOLL, "[CaelumLinux] M9a epoll OK");
        assert_eq!(M9A_MARKERS, &[M9A_TIMERFD, M9A_SIGNALFD, M9A_EPOLL]);
        for m in M9A_MARKERS {
            assert!(
                m.starts_with("[CaelumLinux] "),
                "{m:?} must be a [CaelumLinux] line"
            );
            assert_ne!(*m, FINAL_MARKER, "{m:?} must not be the final marker");
        }
        let mut unique = M9A_MARKERS.to_vec();
        unique.sort_unstable();
        unique.dedup();
        assert_eq!(unique.len(), M9A_MARKERS.len(), "duplicate M9a markers");

        // M9a reuses the M7d kernel verdict and must not require its own.
        let required = required_markers(BootStage::First);
        for forbidden in [
            "[CaelumKernel] M9a OK",
            "[CaelumKernel] M9 OK",
            "[CaelumLinux] M9 OK",
        ] {
            assert!(
                !required.iter().any(|m| m.contains(forbidden)),
                "M9a must not require {forbidden:?}"
            );
        }

        for stage in [BootStage::First, BootStage::Second] {
            let all = required_markers(stage);
            assert_eq!(all.len(), 138, "{}", stage.label());
            for m in M9A_MARKERS {
                assert!(all.contains(m), "{}: missing {m:?}", stage.label());
            }
            assert_eq!(*all.last().unwrap(), M7D_KERNEL_OK);
            let text = complete_transcript(stage);
            assert!(
                acceptance_error(&text, stage).is_none(),
                "{}: {:?}",
                stage.label(),
                acceptance_error(&text, stage)
            );
            let devfs_at = text.rfind(M8H_DEVFS_SAMPLE).unwrap();
            let timerfd_at = text.rfind(M9A_TIMERFD_SAMPLE).unwrap();
            let signalfd_at = text.rfind(M9A_SIGNALFD_SAMPLE).unwrap();
            let epoll_at = text.rfind(M9A_EPOLL_SAMPLE).unwrap();
            let verdict_at = text.rfind(M7D_KERNEL_VERDICT_SAMPLE).unwrap();
            assert!(
                devfs_at < timerfd_at
                    && timerfd_at < signalfd_at
                    && signalfd_at < epoll_at
                    && epoll_at < verdict_at,
                "{}: the M9a lines must sit between M8h and the kernel verdict",
                stage.label()
            );
        }

        // Each line is a required marker: dropping one is reported missing.
        let text = complete_transcript(BootStage::First);
        for (sample, marker) in [
            (M9A_TIMERFD_SAMPLE, M9A_TIMERFD),
            (M9A_SIGNALFD_SAMPLE, M9A_SIGNALFD),
            (M9A_EPOLL_SAMPLE, M9A_EPOLL),
        ] {
            let without = text.replacen(&format!("{sample}\n"), "", 1);
            assert!(
                missing_markers(&without, BootStage::First).contains(&marker),
                "dropping {marker:?} must be reported missing"
            );
        }

        // Ordering violations are diagnosed by `marker_placement_error`.
        let cases = [
            (
                format!("{M8H_DEVFS_SAMPLE}\n{M9A_TIMERFD_SAMPLE}"),
                format!("{M9A_TIMERFD_SAMPLE}\n{M8H_DEVFS_SAMPLE}"),
                "M9a timerfd before M8h devfs",
            ),
            (
                format!("{M9A_TIMERFD_SAMPLE}\n{M9A_SIGNALFD_SAMPLE}"),
                format!("{M9A_SIGNALFD_SAMPLE}\n{M9A_TIMERFD_SAMPLE}"),
                "M9a signalfd before timerfd",
            ),
            (
                format!("{M9A_SIGNALFD_SAMPLE}\n{M9A_EPOLL_SAMPLE}"),
                format!("{M9A_EPOLL_SAMPLE}\n{M9A_SIGNALFD_SAMPLE}"),
                "M9a epoll before signalfd",
            ),
            (
                format!(
                    "{M9A_EPOLL_SAMPLE}\n{M9B_ABSTRACT_SAMPLE}\n{M9B_RIGHTS_SAMPLE}\n{M9B_CREDENTIALS_SAMPLE}\n{M9B_EPOLL_ET_SAMPLE}\n{M9C_LOCKS_SAMPLE}\n{M9D_INTERP_SAMPLE}\n{M9D_DYNAMIC_SAMPLE}\n{M9D_VDSO_SAMPLE}\n{M9E_SHARED_SAMPLE}\n{M9F_SHARED_SAMPLE}\n{M10A_HELLO_SAMPLE}\n{M7D_KERNEL_VERDICT_SAMPLE}\n{M7C_NIC_SAMPLE}"
                ),
                format!(
                    "{M7D_KERNEL_VERDICT_SAMPLE}\n{M9B_ABSTRACT_SAMPLE}\n{M9B_RIGHTS_SAMPLE}\n{M9B_CREDENTIALS_SAMPLE}\n{M9B_EPOLL_ET_SAMPLE}\n{M9C_LOCKS_SAMPLE}\n{M9D_INTERP_SAMPLE}\n{M9D_DYNAMIC_SAMPLE}\n{M9D_VDSO_SAMPLE}\n{M9E_SHARED_SAMPLE}\n{M9F_SHARED_SAMPLE}\n{M10A_HELLO_SAMPLE}\n{M7C_NIC_SAMPLE}\n{M9A_EPOLL_SAMPLE}"
                ),
                "M9a epoll after the M7d verdict",
            ),
        ];
        for (from, to, what) in cases {
            let broken = text.replace(&from, &to);
            let error = acceptance_error(&broken, BootStage::First)
                .unwrap_or_else(|| panic!("{what} must fail"));
            assert!(
                error.contains("must appear before"),
                "{what}: unexpected error: {error}"
            );
        }
    }

    /// M9b closes the user-mode Linux extension block: abstract-namespace
    /// sockets, `SCM_RIGHTS`/`SCM_CREDENTIALS` fd passing and edge-triggered
    /// epoll. The four lines are plain user-mode text (parent only) and no new
    /// kernel verdict is introduced; the M7d verdict and the deliberate page
    /// fault still stay after them.
    #[test]
    fn m9b_markers_are_exact_and_placed() {
        assert_eq!(M9B_ABSTRACT, "[CaelumLinux] M9b abstract OK");
        assert_eq!(M9B_RIGHTS, "[CaelumLinux] M9b rights OK");
        assert_eq!(M9B_CREDENTIALS, "[CaelumLinux] M9b credentials OK");
        assert_eq!(M9B_EPOLL_ET, "[CaelumLinux] M9b epoll-et OK");
        assert_eq!(
            M9B_MARKERS,
            &[M9B_ABSTRACT, M9B_RIGHTS, M9B_CREDENTIALS, M9B_EPOLL_ET]
        );
        for m in M9B_MARKERS {
            assert!(
                m.starts_with("[CaelumLinux] "),
                "{m:?} must be a [CaelumLinux] line"
            );
            assert_ne!(*m, FINAL_MARKER, "{m:?} must not be the final marker");
        }
        let mut unique = M9B_MARKERS.to_vec();
        unique.sort_unstable();
        unique.dedup();
        assert_eq!(unique.len(), M9B_MARKERS.len(), "duplicate M9b markers");

        // M9b reuses the M7d kernel verdict and must not require its own.
        let required = required_markers(BootStage::First);
        for forbidden in [
            "[CaelumKernel] M9b OK",
            "[CaelumKernel] M9 OK",
            "[CaelumLinux] M9 OK",
        ] {
            assert!(
                !required.iter().any(|m| m.contains(forbidden)),
                "M9b must not require {forbidden:?}"
            );
        }

        for stage in [BootStage::First, BootStage::Second] {
            let all = required_markers(stage);
            assert_eq!(all.len(), 138, "{}", stage.label());
            for m in M9B_MARKERS {
                assert!(all.contains(m), "{}: missing {m:?}", stage.label());
            }
            assert_eq!(*all.last().unwrap(), M7D_KERNEL_OK);
            let text = complete_transcript(stage);
            assert!(
                acceptance_error(&text, stage).is_none(),
                "{}: {:?}",
                stage.label(),
                acceptance_error(&text, stage)
            );
            let epoll_at = text.rfind(M9A_EPOLL_SAMPLE).unwrap();
            let abstract_at = text.rfind(M9B_ABSTRACT_SAMPLE).unwrap();
            let rights_at = text.rfind(M9B_RIGHTS_SAMPLE).unwrap();
            let credentials_at = text.rfind(M9B_CREDENTIALS_SAMPLE).unwrap();
            let epoll_et_at = text.rfind(M9B_EPOLL_ET_SAMPLE).unwrap();
            let verdict_at = text.rfind(M7D_KERNEL_VERDICT_SAMPLE).unwrap();
            assert!(
                epoll_at < abstract_at
                    && abstract_at < rights_at
                    && rights_at < credentials_at
                    && credentials_at < epoll_et_at
                    && epoll_et_at < verdict_at,
                "{}: the M9b lines must sit between M9a and the kernel verdict",
                stage.label()
            );
        }

        // Each line is a required marker: dropping one is reported missing.
        let text = complete_transcript(BootStage::First);
        for (sample, marker) in [
            (M9B_ABSTRACT_SAMPLE, M9B_ABSTRACT),
            (M9B_RIGHTS_SAMPLE, M9B_RIGHTS),
            (M9B_CREDENTIALS_SAMPLE, M9B_CREDENTIALS),
            (M9B_EPOLL_ET_SAMPLE, M9B_EPOLL_ET),
        ] {
            let without = text.replacen(&format!("{sample}\n"), "", 1);
            assert!(
                missing_markers(&without, BootStage::First).contains(&marker),
                "dropping {marker:?} must be reported missing"
            );
        }

        // Ordering violations are diagnosed by `marker_placement_error`.
        let cases = [
            (
                format!("{M9A_EPOLL_SAMPLE}\n{M9B_ABSTRACT_SAMPLE}"),
                format!("{M9B_ABSTRACT_SAMPLE}\n{M9A_EPOLL_SAMPLE}"),
                "M9b abstract before M9a epoll",
            ),
            (
                format!("{M9B_ABSTRACT_SAMPLE}\n{M9B_RIGHTS_SAMPLE}"),
                format!("{M9B_RIGHTS_SAMPLE}\n{M9B_ABSTRACT_SAMPLE}"),
                "M9b rights before abstract",
            ),
            (
                format!("{M9B_RIGHTS_SAMPLE}\n{M9B_CREDENTIALS_SAMPLE}"),
                format!("{M9B_CREDENTIALS_SAMPLE}\n{M9B_RIGHTS_SAMPLE}"),
                "M9b credentials before rights",
            ),
            (
                format!("{M9B_CREDENTIALS_SAMPLE}\n{M9B_EPOLL_ET_SAMPLE}"),
                format!("{M9B_EPOLL_ET_SAMPLE}\n{M9B_CREDENTIALS_SAMPLE}"),
                "M9b epoll-et before credentials",
            ),
        ];
        for (from, to, what) in cases {
            let broken = text.replace(&from, &to);
            let error = acceptance_error(&broken, BootStage::First)
                .unwrap_or_else(|| panic!("{what} must fail"));
            assert!(
                error.contains("must appear before"),
                "{what}: unexpected error: {error}"
            );
        }

        // Moving the last M9b line after the kernel verdict must be rejected.
        let without_et = text.replacen(&format!("{M9B_EPOLL_ET_SAMPLE}\n"), "", 1);
        let after_verdict = without_et.replace(
            M7D_KERNEL_VERDICT_SAMPLE,
            &format!("{M7D_KERNEL_VERDICT_SAMPLE}\n{M9B_EPOLL_ET_SAMPLE}"),
        );
        let error = acceptance_error(&after_verdict, BootStage::First)
            .expect("M9b epoll-et after the M7d verdict must fail");
        assert!(
            error.contains("must appear before"),
            "unexpected error: {error}"
        );
    }

    /// M9c closes the user-mode Linux extension block: one plain line proving the
    /// role-2 lock peer and the VFS POSIX/OFD/flock lock domains ran. The kernel
    /// verdict stays the M7d one and the deliberate fault stays last.
    #[test]
    fn m9c_marker_is_exact_and_placed() {
        assert_eq!(M9C_LOCKS, "[CaelumLinux] M9c locks OK");
        assert_eq!(M9C_MARKERS, &[M9C_LOCKS]);
        for m in M9C_MARKERS {
            assert!(
                m.starts_with("[CaelumLinux] "),
                "{m:?} must be a [CaelumLinux] line"
            );
            assert_ne!(*m, FINAL_MARKER, "{m:?} must not be the final marker");
        }

        // M9c reuses the M7d kernel verdict and must not require its own.
        let required = required_markers(BootStage::First);
        for forbidden in [
            "[CaelumKernel] M9c OK",
            "[CaelumKernel] M9 OK",
            "[CaelumLinux] M9 OK",
        ] {
            assert!(
                !required.iter().any(|m| m.contains(forbidden)),
                "M9c must not require {forbidden:?}"
            );
        }
        assert!(required.iter().any(|m| *m == M9C_LOCKS));

        for stage in [BootStage::First, BootStage::Second] {
            let all = required_markers(stage);
            assert_eq!(all.len(), 138, "{}", stage.label());
            assert!(
                all.contains(&M9C_LOCKS),
                "{}: missing M9c locks",
                stage.label()
            );
            assert_eq!(*all.last().unwrap(), M7D_KERNEL_OK);
            let text = complete_transcript(stage);
            assert!(
                acceptance_error(&text, stage).is_none(),
                "{}: {:?}",
                stage.label(),
                acceptance_error(&text, stage)
            );
            let epoll_et_at = text.rfind(M9B_EPOLL_ET_SAMPLE).unwrap();
            let locks_at = text.rfind(M9C_LOCKS_SAMPLE).unwrap();
            let verdict_at = text.rfind(M7D_KERNEL_VERDICT_SAMPLE).unwrap();
            assert!(
                epoll_et_at < locks_at && locks_at < verdict_at,
                "{}: the M9c line must sit between M9b and the kernel verdict",
                stage.label()
            );
        }

        // The line is a required marker: dropping it is reported missing.
        let text = complete_transcript(BootStage::First);
        let without = text.replacen(&format!("{M9C_LOCKS_SAMPLE}\n"), "", 1);
        assert!(
            missing_markers(&without, BootStage::First).contains(&M9C_LOCKS),
            "dropping the M9c line must be reported missing"
        );

        // Ordering violations are diagnosed by `marker_placement_error`.
        let swapped = text.replace(
            &format!("{M9B_EPOLL_ET_SAMPLE}\n{M9C_LOCKS_SAMPLE}"),
            &format!("{M9C_LOCKS_SAMPLE}\n{M9B_EPOLL_ET_SAMPLE}"),
        );
        let error = acceptance_error(&swapped, BootStage::First)
            .expect("M9c locks before M9b epoll-et must fail");
        assert!(
            error.contains("must appear before"),
            "unexpected error: {error}"
        );

        // Moving the line after the kernel verdict must be rejected too.
        let without_locks = text.replacen(&format!("{M9C_LOCKS_SAMPLE}\n"), "", 1);
        let after_verdict = without_locks.replace(
            M7D_KERNEL_VERDICT_SAMPLE,
            &format!("{M7D_KERNEL_VERDICT_SAMPLE}\n{M9C_LOCKS_SAMPLE}"),
        );
        let error = acceptance_error(&after_verdict, BootStage::First)
            .expect("M9c locks after the M7d verdict must fail");
        assert!(
            error.contains("must appear before"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn m9d1_markers_are_exact_and_placed() {
        assert_eq!(M9D_INTERP, "[CaelumDyn] interp OK");
        assert_eq!(M9D_DYNAMIC, "[CaelumLinux] M9d dynamic OK");
        assert_eq!(M9D_VDSO, "[CaelumLinux] M9d vdso OK");
        assert_eq!(M9D_MARKERS, &[M9D_INTERP, M9D_DYNAMIC, M9D_VDSO]);
        for m in M9D_MARKERS {
            assert_ne!(*m, FINAL_MARKER, "{m:?} must not be the final marker");
        }
        assert!(
            M9D_INTERP.starts_with("[CaelumDyn] "),
            "the interpreter line uses the [CaelumDyn] tag"
        );
        assert!(
            M9D_DYNAMIC.starts_with("[CaelumLinux] "),
            "the dynamic line uses the [CaelumLinux] tag"
        );
        assert!(
            M9D_VDSO.starts_with("[CaelumLinux] "),
            "the vDSO line uses the [CaelumLinux] tag"
        );

        // M9d1/M9d2 reuse the M7d kernel verdict and must not require their own.
        let required = required_markers(BootStage::First);
        for forbidden in [
            "[CaelumKernel] M9d OK",
            "[CaelumKernel] M9d2 OK",
            "[CaelumKernel] M9 OK",
            "[CaelumDyn] M9d OK",
        ] {
            assert!(
                !required.iter().any(|m| m.contains(forbidden)),
                "M9d1 must not require {forbidden:?}"
            );
        }
        for stage in [BootStage::First, BootStage::Second] {
            let all = required_markers(stage);
            assert_eq!(all.len(), 138, "{}", stage.label());
            assert!(
                all.contains(&M9D_INTERP) && all.contains(&M9D_DYNAMIC) && all.contains(&M9D_VDSO),
                "{}: missing an M9d line",
                stage.label()
            );
            assert_eq!(*all.last().unwrap(), M7D_KERNEL_OK);
            let text = complete_transcript(stage);
            assert!(
                acceptance_error(&text, stage).is_none(),
                "{}: {:?}",
                stage.label(),
                acceptance_error(&text, stage)
            );
            let locks_at = text.rfind(M9C_LOCKS_SAMPLE).unwrap();
            let interp_at = text.rfind(M9D_INTERP_SAMPLE).unwrap();
            let dynamic_at = text.rfind(M9D_DYNAMIC_SAMPLE).unwrap();
            let vdso_at = text.rfind(M9D_VDSO_SAMPLE).unwrap();
            let verdict_at = text.rfind(M7D_KERNEL_VERDICT_SAMPLE).unwrap();
            assert!(
                locks_at < interp_at
                    && interp_at < dynamic_at
                    && dynamic_at < vdso_at
                    && vdso_at < verdict_at,
                "{}: the M9d lines must sit between M9c and the kernel verdict",
                stage.label()
            );
        }

        // The lines are required markers: dropping one is reported missing.
        let text = complete_transcript(BootStage::First);
        let without = text.replacen(&format!("{M9D_INTERP_SAMPLE}\n"), "", 1);
        assert!(
            missing_markers(&without, BootStage::First).contains(&M9D_INTERP),
            "dropping the interp line must be reported missing"
        );
        let without_vdso = text.replacen(&format!("{M9D_VDSO_SAMPLE}\n"), "", 1);
        assert!(
            missing_markers(&without_vdso, BootStage::First).contains(&M9D_VDSO),
            "dropping the vDSO line must be reported missing"
        );

        // Ordering violations are diagnosed by `marker_placement_error`.
        let swapped = text.replace(
            &format!("{M9D_INTERP_SAMPLE}\n{M9D_DYNAMIC_SAMPLE}"),
            &format!("{M9D_DYNAMIC_SAMPLE}\n{M9D_INTERP_SAMPLE}"),
        );
        let error = acceptance_error(&swapped, BootStage::First)
            .expect("M9d dynamic before interp must fail");
        assert!(
            error.contains("must appear before"),
            "unexpected error: {error}"
        );
        let vdso_before = text.replace(
            &format!("{M9D_DYNAMIC_SAMPLE}\n{M9D_VDSO_SAMPLE}"),
            &format!("{M9D_VDSO_SAMPLE}\n{M9D_DYNAMIC_SAMPLE}"),
        );
        let error = acceptance_error(&vdso_before, BootStage::First)
            .expect("M9d vDSO before dynamic must fail");
        assert!(
            error.contains("must appear before"),
            "unexpected error: {error}"
        );

        // Moving the block after the kernel verdict must be rejected too.
        let without_all = text.replacen(
            &format!("{M9D_INTERP_SAMPLE}\n{M9D_DYNAMIC_SAMPLE}\n{M9D_VDSO_SAMPLE}\n"),
            "",
            1,
        );
        let after_verdict = without_all.replace(
            M7D_KERNEL_VERDICT_SAMPLE,
            &format!(
                "{M7D_KERNEL_VERDICT_SAMPLE}\n{M9D_INTERP_SAMPLE}\n{M9D_DYNAMIC_SAMPLE}\n{M9D_VDSO_SAMPLE}"
            ),
        );
        let error = acceptance_error(&after_verdict, BootStage::First)
            .expect("M9d lines after the M7d verdict must fail");
        assert!(
            error.contains("must appear before"),
            "unexpected error: {error}"
        );
    }

    /// All marker lines of one boot, in the order the guest emits them. The M5c1
    /// markers are deliberately not contiguous (early mounts, user programs,
    /// verdict), which is exactly what `marker_placement_error` enforces.
    fn boot_lines(stage: BootStage) -> Vec<&'static str> {
        let mut lines: Vec<&'static str> = Vec::new();
        lines.extend(M12_MARKERS.iter().filter(|m| **m != FINAL_MARKER).copied());
        lines.extend(M3_MARKERS.iter().copied());
        // M6b1: the APs join right after the M3 stage, before the M4 object work.
        lines.extend(M6B1_MARKERS.iter().copied());
        // M6b2a: the per-CPU locking check follows immediately.
        lines.extend(M6B2A_MARKERS.iter().copied());
        // objects + modules, then the early mounts, then the user programs.
        lines.extend(M4_MARKERS[..2].iter().copied());
        lines.push(M5C1_MOUNTS_READY);
        // `init` starts and spawns the child before its own round trips.
        lines.extend(M4_MARKERS[2..4].iter().copied());
        // init: files -> mmap -> xattr -> sparse -> watch.
        lines.push(M5C1_INIT_FILES);
        lines.push(M5C2_INIT_MMAP);
        lines.push(M5C3_INIT_XATTR);
        lines.push(M5C3_INIT_SPARSE);
        lines.push(M5C3_INIT_WATCH);
        // M6a1: init then exercises the monotonic timer and an Event round trip.
        lines.push(M6A_INIT_TIMER);
        lines.push(M6A_INIT_EVENT);
        // child: child/handles, then files -> mmap -> locks.
        lines.extend(M4_MARKERS[4..6].iter().copied());
        lines.push(M5C1_CHILD_FILES);
        lines.push(M5C2_CHILD_MMAP);
        lines.push(M5C3_CHILD_LOCKS);
        // M6a1: the child signals and waits on Events after its lock round trip.
        lines.push(M6A_CHILD_EVENT);
        // M6a2: both programs exercise the remaining M6 IPC objects. The order
        // below is only our synthetic emission order; the acceptance rules
        // require nothing more than "before init exits".
        lines.extend(M6A2_USER_MARKERS.iter().copied());
        // init: waits for the child, checks locks, then reports rng and exits.
        lines.push(M4_MARKERS[6]);
        lines.push(M5C3_INIT_LOCKS);
        lines.push(M4_MARKERS[7]);
        lines.extend(M4_MARKERS[8..].iter().copied());
        lines.extend(M5A_MARKERS.iter().copied());
        lines.extend(M5B_BASE_MARKERS.iter().copied());
        lines.extend(stage_markers(stage).iter().copied());
        lines.push(M5C1_OK);
        lines.push(M5C2_OK);
        lines.push(M5C3_FAULTS_OK);
        lines.push(M5C3_OK);
        lines.push(M5_OK);
        // M6a1 stage verdict, after `M5 OK` and before the deliberate fault.
        lines.push(M6A_OK);
        // M6a2 stage verdict, after `M6a OK` and still before the fault.
        lines.push(M6A2_OK);
        // M6b2: the closing scheduling evidence, printed by the boot processor
        // after the M6a2 closeout and immediately before the deliberate fault.
        lines.push(M6B2_AP_USER_SAMPLE);
        lines.push(M6B2_AP_PREEMPT_SAMPLE);
        lines.push(M6B2_WAKE_IPI_SAMPLE);
        lines.push(M6B2_MIGRATE_SAMPLE);
        lines.push(M6B2_VERDICT_SAMPLE);
        // M6c: the kernel probes the real framebuffer, `gfx` presents the framed
        // buffer and round-trips the second injection, then the kernel closes.
        // Printed after the M6b2 verdict and before the deliberate fault.
        lines.push(M6C_DISPLAY_PROBE_SAMPLE);
        lines.push(M6C_DISPLAY_SAMPLE);
        lines.push(M6C_INPUT_READY_SAMPLE);
        lines.push(M6C_INPUT_SAMPLE);
        lines.push(M6C_VERDICT_SAMPLE);
        // M7a: the loopback suites, then the kernel's closing verdict, still
        // before the deliberate fault.
        lines.push(M7A_IPV4_UDP_SAMPLE);
        lines.push(M7A_IPV4_TCP_SAMPLE);
        lines.push(M7A_IPV6_UDP_SAMPLE);
        lines.push(M7A_IPV6_TCP_SAMPLE);
        lines.push(M7A_SOCKETS_SAMPLE);
        lines.push(M7A_VERDICT_SAMPLE);
        // M7b: the native socket suites and the two closing verdicts.
        lines.push(M7B_UDP4_SAMPLE);
        lines.push(M7B_UDP6_SAMPLE);
        lines.push(M7B_TCP4_SAMPLE);
        lines.push(M7B_TCP6_SAMPLE);
        lines.push(M7B_SOCKETPAIR_SAMPLE);
        lines.push(M7B_UNIX_STREAM_SAMPLE);
        lines.push(M7B_UNIX_DGRAM_SAMPLE);
        lines.push(M7B_WAIT_SAMPLE);
        lines.push(M7B_BACKPRESSURE_SAMPLE);
        lines.push(M7B_SHUTDOWN_SAMPLE);
        lines.push(M7B_RIGHTS_SAMPLE);
        lines.push(M7B_FAULTS_SAMPLE);
        lines.push(M7B_USER_VERDICT_SAMPLE);
        lines.push(M7B_KERNEL_VERDICT_SAMPLE);
        // M7d: the Linux64 personality self-test, after the native socket block
        // and still before the deliberate fault. The user lines are plain text;
        // only the kernel verdict carries the socket accounting payload.
        lines.push(M7D_STARTUP_SAMPLE);
        lines.push(M7D_UDP_SAMPLE);
        lines.push(M7D_TCP_SAMPLE);
        lines.push(M7D_UNIX_SAMPLE);
        lines.push(M7D_FD_SAMPLE);
        lines.push(M7D_ERRORS_SAMPLE);
        lines.push(M7D_USER_VERDICT_SAMPLE);
        // M8a: the memory and file slices run after the M7d user verdict and
        // before the kernel M7d verdict; they are plain user-mode lines.
        lines.push(M8A_MEMORY_SAMPLE);
        lines.push(M8A_FILES_SAMPLE);
        // M8b: the time and system-information slices extend the same user block.
        lines.push(M8B_TIME_SAMPLE);
        lines.push(M8B_INFO_SAMPLE);
        // M8c: the signal slice follows M8b, still before the kernel verdict.
        lines.push(M8C_SIGNALS_SAMPLE);
        // M8d: the process slice follows M8c, still before the kernel verdict.
        lines.push(M8D_PROCESS_SAMPLE);
        // M8e: the file-semantics slice follows M8d, still before the verdict.
        lines.push(M8E_FILES_SAMPLE);
        // M8f: the futex and TLS slices close the user block before the verdict.
        lines.push(M8F_FUTEX_SAMPLE);
        lines.push(M8F_TLS_SAMPLE);
        // M8g: eventfd and poll/ppoll close the user block before the verdict.
        lines.push(M8G_EVENTFD_SAMPLE);
        lines.push(M8G_POLL_SAMPLE);
        // M8h: procfs/devfs slices close the user block before the verdict.
        lines.push(M8H_PROCFS_SAMPLE);
        lines.push(M8H_DEVFS_SAMPLE);
        // M9a: timerfd/signalfd/epoll extend the user block one last time; the
        // kernel verdict stays the M7d one and the deliberate fault stays last.
        lines.push(M9A_TIMERFD_SAMPLE);
        lines.push(M9A_SIGNALFD_SAMPLE);
        lines.push(M9A_EPOLL_SAMPLE);
        // M9b: abstract/rights/credentials/epoll-et extend the user block; the
        // kernel verdict stays the M7d one and the deliberate fault stays last.
        lines.push(M9B_ABSTRACT_SAMPLE);
        lines.push(M9B_RIGHTS_SAMPLE);
        lines.push(M9B_CREDENTIALS_SAMPLE);
        lines.push(M9B_EPOLL_ET_SAMPLE);
        // M9c: the lock-domain line is the last user line before the verdict.
        lines.push(M9C_LOCKS_SAMPLE);
        // M9d1/M9d2: the dynamic-ELF pair and the vDSO line follow the lock line,
        // then the reused M7d kernel verdict.
        lines.push(M9D_INTERP_SAMPLE);
        lines.push(M9D_DYNAMIC_SAMPLE);
        lines.push(M9D_VDSO_SAMPLE);
        // M9e: the shared-library line follows the vDSO image and still precedes
        // the reused M7d kernel verdict.
        lines.push(M9E_SHARED_SAMPLE);
        // M9f: the three-library line follows the M9e line and still precedes
        // the reused M7d kernel verdict.
        lines.push(M9F_SHARED_SAMPLE);
        // M10a: the real busybox output follows the shared-library block; the
        // reused M7d kernel verdict is still the last required line.
        lines.push(M10A_HELLO_SAMPLE);
        lines.push(M7D_KERNEL_VERDICT_SAMPLE);
        // M7c-1a: the kernel prints the NIC probe line in the closeout after
        // the reused M7d verdict; only the deliberate page fault follows it.
        lines.push(M7C_NIC_SAMPLE);
        lines
    }

    #[test]
    fn m9e_marker_is_exact_and_placed() {
        // Frozen string: the dynamic main prints it verbatim once the shared
        // library it was linked against has been loaded through the interpreter.
        assert_eq!(M9E_SHARED, "[CaelumLinux] M9e shared OK");
        assert_eq!(M9E_MARKERS, &[M9E_SHARED]);

        for stage in [BootStage::First, BootStage::Second] {
            let all = required_markers(stage);
            assert_eq!(all.len(), 138, "{}", stage.label());
            assert_eq!(all.iter().filter(|m| **m == M9E_SHARED).count(), 1);
            assert_eq!(
                acceptance_error(&complete_transcript(stage), stage),
                None,
                "{} transcript rejected",
                stage.label()
            );
            let text = complete_transcript(stage);
            let vdso_at = text.rfind(M9D_VDSO_SAMPLE).expect("vDSO line missing");
            let shared_at = text.rfind(M9E_SHARED_SAMPLE).expect("shared line missing");
            let verdict_at = text
                .rfind(M7D_KERNEL_VERDICT_SAMPLE)
                .expect("verdict missing");
            assert!(
                vdso_at < shared_at && shared_at < verdict_at,
                "{}: the M9e line must sit between the vDSO line and the kernel verdict",
                stage.label()
            );
        }

        // The line is a required marker: dropping it is reported missing.
        let text = complete_transcript(BootStage::First);
        let without = text.replacen(&format!("{M9E_SHARED_SAMPLE}\n"), "", 1);
        assert!(
            missing_markers(&without, BootStage::First).contains(&M9E_SHARED),
            "dropping the shared-library line must be reported missing"
        );

        // Ordering violations are diagnosed by `marker_placement_error`.
        let before_vdso = text.replace(
            &format!("{M9D_VDSO_SAMPLE}\n{M9E_SHARED_SAMPLE}"),
            &format!("{M9E_SHARED_SAMPLE}\n{M9D_VDSO_SAMPLE}"),
        );
        let error = acceptance_error(&before_vdso, BootStage::First)
            .expect("M9e before the vDSO line must fail");
        assert!(
            error.contains("must appear before"),
            "unexpected error: {error}"
        );

        let after_verdict = text.replace(
            M7D_KERNEL_VERDICT_SAMPLE,
            &format!("{M7D_KERNEL_VERDICT_SAMPLE}\n{M9E_SHARED_SAMPLE}"),
        );
        let error = acceptance_error(&after_verdict, BootStage::First)
            .expect("M9e after the M7d verdict must fail");
        assert!(
            error.contains("must appear before"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn m9f_marker_is_exact_and_placed() {
        // Frozen string: printed verbatim once the two chained shared libraries
        // have been loaded and relocated through the custom interpreter.
        assert_eq!(M9F_SHARED, "[CaelumLinux] M9f shared OK");
        assert_eq!(M9F_MARKERS, &[M9F_SHARED]);

        for stage in [BootStage::First, BootStage::Second] {
            let all = required_markers(stage);
            assert_eq!(all.len(), 138, "{}", stage.label());
            assert_eq!(all.iter().filter(|m| **m == M9F_SHARED).count(), 1);
            assert_eq!(
                acceptance_error(&complete_transcript(stage), stage),
                None,
                "{} transcript rejected",
                stage.label()
            );
            let text = complete_transcript(stage);
            let m9e_at = text.rfind(M9E_SHARED_SAMPLE).expect("M9e line missing");
            let m9f_at = text.rfind(M9F_SHARED_SAMPLE).expect("M9f line missing");
            let verdict_at = text
                .rfind(M7D_KERNEL_VERDICT_SAMPLE)
                .expect("verdict missing");
            assert!(
                m9e_at < m9f_at && m9f_at < verdict_at,
                "{}: the M9f line must sit between the M9e line and the kernel verdict",
                stage.label()
            );
        }

        // The line is a required marker: dropping it is reported missing.
        let text = complete_transcript(BootStage::First);
        let without = text.replacen(&format!("{M9F_SHARED_SAMPLE}\n"), "", 1);
        assert!(
            missing_markers(&without, BootStage::First).contains(&M9F_SHARED),
            "dropping the three-library line must be reported missing"
        );

        // Ordering violations are diagnosed by `marker_placement_error`.
        let before_m9e = text.replace(
            &format!("{M9E_SHARED_SAMPLE}\n{M9F_SHARED_SAMPLE}"),
            &format!("{M9F_SHARED_SAMPLE}\n{M9E_SHARED_SAMPLE}"),
        );
        let error = acceptance_error(&before_m9e, BootStage::First)
            .expect("M9f before the M9e line must fail");
        assert!(
            error.contains("must appear before"),
            "unexpected error: {error}"
        );

        let after_verdict = text.replace(
            M7D_KERNEL_VERDICT_SAMPLE,
            &format!("{M7D_KERNEL_VERDICT_SAMPLE}\n{M9F_SHARED_SAMPLE}"),
        );
        let error = acceptance_error(&after_verdict, BootStage::First)
            .expect("M9f after the M7d verdict must fail");
        assert!(
            error.contains("must appear before"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn m10a_marker_is_exact_and_placed() {
        // Frozen string: this is real `busybox`'s own `echo` output, so the line
        // must match verbatim.
        assert_eq!(M10A_HELLO, "[CaelumLinux] M10a hello OK");
        assert_eq!(M10A_MARKERS, &[M10A_HELLO]);

        for stage in [BootStage::First, BootStage::Second] {
            let all = required_markers(stage);
            assert_eq!(all.len(), 138, "{}", stage.label());
            assert_eq!(all.iter().filter(|m| **m == M10A_HELLO).count(), 1);
            // M10a is a slice, not the whole Wine/M10 milestone: no broader claim
            // may be smuggled into the required set.
            for forbidden in [
                "[CaelumLinux] M10 OK",
                "[CaelumKernel] M10 OK",
                "[CaelumKernel] M10a OK",
                "[CaelumLinux] M10 wine OK",
            ] {
                assert!(
                    !all.contains(&forbidden),
                    "{forbidden:?} must not be required"
                );
            }
            assert_eq!(
                acceptance_error(&complete_transcript(stage), stage),
                None,
                "{} transcript rejected",
                stage.label()
            );
            let text = complete_transcript(stage);
            let m9f_at = text.rfind(M9F_SHARED_SAMPLE).expect("M9f line missing");
            let hello_at = text.rfind(M10A_HELLO_SAMPLE).expect("M10a line missing");
            let verdict_at = text
                .rfind(M7D_KERNEL_VERDICT_SAMPLE)
                .expect("verdict missing");
            assert!(
                m9f_at < hello_at && hello_at < verdict_at,
                "{}: the M10a line must sit between the M9f line and the kernel verdict",
                stage.label()
            );
        }

        // The line is required: dropping it is reported missing.
        let text = complete_transcript(BootStage::First);
        let without = text.replacen(&format!("{M10A_HELLO_SAMPLE}\n"), "", 1);
        assert!(
            missing_markers(&without, BootStage::First).contains(&M10A_HELLO),
            "dropping the busybox line must be reported missing"
        );

        // Ordering violations are diagnosed by `marker_placement_error`.
        let before_m9f = text.replace(
            &format!("{M9F_SHARED_SAMPLE}\n{M10A_HELLO_SAMPLE}"),
            &format!("{M10A_HELLO_SAMPLE}\n{M9F_SHARED_SAMPLE}"),
        );
        let error = acceptance_error(&before_m9f, BootStage::First)
            .expect("M10a before the M9f line must fail");
        assert!(
            error.contains("must appear before"),
            "unexpected error: {error}"
        );

        let after_verdict = text.replace(
            M7D_KERNEL_VERDICT_SAMPLE,
            &format!("{M7D_KERNEL_VERDICT_SAMPLE}\n{M10A_HELLO_SAMPLE}"),
        );
        let error = acceptance_error(&after_verdict, BootStage::First)
            .expect("M10a after the M7d verdict must fail");
        assert!(
            error.contains("must appear before"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn m7c1a_marker_is_exact_and_placed() {
        // Frozen string: the kernel prints the MAC it read from the legacy
        // virtio-net device plus the link state the device reported.
        assert_eq!(
            M7C_NIC,
            "[CaelumKernel] M7c nic OK (mac=52:54:00:12:34:56, link=up)"
        );
        assert_eq!(M7C_MARKERS, &[M7C_NIC]);

        for stage in [BootStage::First, BootStage::Second] {
            let all = required_markers(stage);
            assert_eq!(all.len(), 138, "{}", stage.label());
            assert_eq!(all.iter().filter(|m| **m == M7C_NIC).count(), 1);
            // M7c-1a only proves the NIC probe: no broader M7/M7c claim and no
            // ARP/UDP line from a later slice may be smuggled in yet.
            for forbidden in [
                "[CaelumKernel] M7 OK",
                "[CaelumKernel] M7 network OK",
                "[CaelumKernel] M7c OK",
                "[CaelumKernel] M7c arp OK",
                "[CaelumKernel] M7c udp OK",
            ] {
                assert!(
                    all.iter().all(|m| !m.contains(forbidden)),
                    "{forbidden:?} must not be required"
                );
            }
            assert_eq!(
                acceptance_error(&complete_transcript(stage), stage),
                None,
                "{} transcript rejected",
                stage.label()
            );
            let text = complete_transcript(stage);
            let hello_at = text.rfind(M10A_HELLO_SAMPLE).expect("M10a line missing");
            let nic_at = text.rfind(M7C_NIC_SAMPLE).expect("M7c line missing");
            let verdict_at = text
                .rfind(M7D_KERNEL_VERDICT_SAMPLE)
                .expect("verdict missing");
            assert!(
                hello_at < verdict_at && verdict_at < nic_at,
                "{}: the M7c line must follow the kernel M7d verdict and still precede the deliberate page fault",
                stage.label()
            );
        }

        // The line is required: dropping it is reported missing.
        let text = complete_transcript(BootStage::First);
        let without = text.replacen(&format!("{M7C_NIC_SAMPLE}\n"), "", 1);
        assert!(
            missing_markers(&without, BootStage::First).contains(&M7C_NIC),
            "dropping the NIC probe line must be reported missing"
        );

        // Ordering violations are diagnosed by `marker_placement_error`.
        let before_verdict = text.replace(
            &format!("{M7D_KERNEL_VERDICT_SAMPLE}\n{M7C_NIC_SAMPLE}"),
            &format!("{M7C_NIC_SAMPLE}\n{M7D_KERNEL_VERDICT_SAMPLE}"),
        );
        let error = acceptance_error(&before_verdict, BootStage::First)
            .expect("M7c before the M7d verdict must fail");
        assert!(
            error.contains("must appear before"),
            "unexpected error: {error}"
        );

        // Moving M10a behind the M7d verdict must also fail.
        let m10a_after = text.replace(
            &format!("{M10A_HELLO_SAMPLE}\n{M7D_KERNEL_VERDICT_SAMPLE}\n{M7C_NIC_SAMPLE}"),
            &format!("{M7D_KERNEL_VERDICT_SAMPLE}\n{M10A_HELLO_SAMPLE}\n{M7C_NIC_SAMPLE}"),
        );
        let error = acceptance_error(&m10a_after, BootStage::First)
            .expect("M10a after the M7d verdict must fail");
        assert!(
            error.contains("must appear before"),
            "unexpected error: {error}"
        );
    }

    /// Serial transcript for a list of marker lines, with the deliberate page
    /// fault last (as a real boot prints it).
    fn transcript(lines: &[&str]) -> String {
        let mut text = lines.join("\n");
        text.push('\n');
        text.push_str("[CaelumKernel] EXCEPTION #PF error=0x0000 P=0 W=0 U=0 RSVD=0 ID=0\n");
        text.push_str(FINAL_MARKER);
        text.push('\n');
        text.push_str("[CaelumKernel] halting\n");
        text
    }

    /// Full acceptance transcript for one boot: every marker of that boot, in
    /// emission order, with the deliberate #PF last.
    fn complete_transcript(stage: BootStage) -> String {
        transcript(&boot_lines(stage))
    }

    #[test]
    fn acceptance_requires_the_final_marker_last() {
        for stage in [BootStage::First, BootStage::Second] {
            let text = complete_transcript(stage);
            assert!(missing_markers(&text, stage).is_empty());
            assert!(
                acceptance_reached(&text, stage),
                "{}: {FINAL_MARKER:?} is last",
                stage.label()
            );

            // A milestone marker after the deliberate page fault breaks the
            // contract.
            let mut bad = complete_transcript(stage);
            bad.push_str("[CaelumKernel] M4 OK\n");
            assert!(missing_markers(&bad, stage).is_empty());
            assert!(
                !acceptance_reached(&bad, stage),
                "{}: M4 OK after the page fault",
                stage.label()
            );

            // Missing markers can never be accepted, even with the fault last.
            let mut incomplete = complete_transcript(stage);
            incomplete = incomplete.replace("[CaelumInit] M4 wait OK\n", "");
            assert!(!missing_markers(&incomplete, stage).is_empty());
            assert!(!acceptance_reached(&incomplete, stage));
        }

        // The first boot's set is not enough for the second boot: M5b OK (and
        // the second-boot line) are still missing.
        let first_stage = complete_transcript(BootStage::First);
        assert!(!acceptance_reached(&first_stage, BootStage::Second));
        // ...and vice versa: the second boot's transcript satisfies neither
        // because the first-boot-only marker is absent.
        let second_stage = complete_transcript(BootStage::Second);
        assert!(acceptance_reached(&second_stage, BootStage::Second));
        assert!(!acceptance_reached(&second_stage, BootStage::First));
    }

    #[test]
    fn halted_early_reports_the_gap() {
        // A guest that stopped before M5b prints halts with its markers missing:
        // the runner must report that instead of waiting out the timeout.
        let text = "[CaelumKernel] M4 OK\n[CaelumKernel] halting\n";
        let error = halted_early(text, BootStage::First).expect("halted with missing markers");
        assert!(error.contains("guest halted with"), "{error}");
        assert!(error.contains("M5b"), "{error}");

        // A complete transcript (fault last, then halting) is not "early".
        assert_eq!(
            halted_early(&complete_transcript(BootStage::Second), BootStage::Second),
            None
        );
        // Still running: no verdict.
        assert_eq!(
            halted_early("[CaelumKernel] M4 OK\n", BootStage::Second),
            None
        );
    }

    #[test]
    fn fatal_reason_flags_failures() {
        assert!(fatal_reason("[CaelumKernel] M3 FAIL: no apic").is_some());
        assert!(fatal_reason("PANIC: double fault").is_some());
        assert!(fatal_reason("panicked at 'boom'").is_some());
        assert!(fatal_reason("[CaelumKernel] vm takeover FAIL: nope").is_some());
        assert!(fatal_reason("[CaelumKernel] ERROR: deliberate fault did not fire").is_some());
        assert!(fatal_reason("[CaelumKernel] EXCEPTION #GP error=0x0000").is_some());
        assert!(fatal_reason("[CaelumKernel] EXCEPTION #DF error=0x0008").is_some());
        assert!(fatal_reason("[CaelumKernel] EXCEPTION #UD error=0x0000").is_some());
    }

    #[test]
    fn fatal_reason_allows_the_deliberate_page_fault() {
        // Real M2 regression path: the trap handler prints `EXCEPTION #PF`
        // first, then the deliberate-fault branch prints `M2 #PF caught`.
        // No "triggering deliberate page fault" line is guaranteed, so the
        // runner must not key off it.
        let ok = concat!(
            "[CaelumKernel] M3 OK\n",
            "[CaelumKernel] EXCEPTION #PF error=0x0000 P=0 W=0 U=0 RSVD=0 ID=0\n",
            "[CaelumKernel]   cr2=0x0000400000000000 cs=0x0008 rflags=0x0000000000010092\n",
            "[CaelumKernel]   rip=0xffffffff8000942c rsp=0xffffffff81003ed8\n",
            "[CaelumKernel] M2 #PF caught (deliberate unmapped read)\n",
            "[CaelumKernel] halting\n"
        );
        assert_eq!(fatal_reason(ok), None);
    }

    #[test]
    fn fatal_reason_flags_unexpected_page_fault() {
        // The kernel's non-deliberate #PF branch is fatal on its own.
        let bad = concat!(
            "[CaelumKernel] EXCEPTION #PF error=0x0004 P=1 W=0 U=0 RSVD=0 ID=0\n",
            "[CaelumKernel] unexpected #PF (kernel bug?), halting\n"
        );
        assert_eq!(
            fatal_reason(bad).as_deref(),
            Some("guest reported \"unexpected #PF\"")
        );
        assert!(fatal_reason("[CaelumKernel] unexpected #PF (kernel bug?), halting").is_some());
    }

    #[test]
    fn fatal_drain_captures_the_diagnostic_before_giving_up() {
        let base = Instant::now();

        // Nothing more arrives: hold the console open for the minimum window
        // anyway, so a slow kernel still gets a chance to start dumping.
        let drain = FatalDrain::new(base);
        assert!(!drain.done(base + Duration::from_millis(100)));
        assert!(!drain.done(base + FATAL_DRAIN_MIN - Duration::from_millis(1)));
        assert!(drain.done(base + FATAL_DRAIN_MIN));

        // The kernel keeps printing: stay until the console goes quiet.
        let mut drain = FatalDrain::new(base);
        drain.note_bytes(base + Duration::from_millis(300));
        assert!(
            !drain.done(base + Duration::from_millis(350)),
            "must not cut the guest off while its diagnostic is still streaming"
        );
        assert!(drain.done(base + Duration::from_millis(400)));

        // A guest that never stops printing is cut off by the hard cap.
        let mut drain = FatalDrain::new(base);
        for i in 0..=100u64 {
            drain.note_bytes(base + Duration::from_millis(i * 10));
        }
        assert!(!drain.done(base + FATAL_DRAIN_MAX - Duration::from_millis(1)));
        assert!(drain.done(base + FATAL_DRAIN_MAX));
    }

    #[test]
    fn newest_source_mtime_walks_rust_sources() {
        let dir =
            std::env::temp_dir().join(format!("caelum-xtask-src-scan-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("nested")).expect("create temp tree");
        assert_eq!(newest_source_mtime(&dir), None, "empty tree has no sources");
        std::fs::write(dir.join("notes.txt"), "ignored").unwrap();
        assert_eq!(
            newest_source_mtime(&dir),
            None,
            "non-source extensions are ignored"
        );
        std::fs::write(dir.join("nested").join("mod.rs"), "// x").unwrap();
        assert!(
            newest_source_mtime(&dir).is_some(),
            "nested .rs files count"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn send_key_payload_is_single_json_line() {
        assert!(SEND_KEY_A_JSON.starts_with("{\"execute\":\"send-key\""));
        assert!(SEND_KEY_A_JSON.contains("\"data\":\"a\""));
        assert!(!SEND_KEY_A_JSON.contains('\n'));
    }

    #[test]
    fn serial_injection_byte_is_uppercase_c() {
        assert_eq!(SERIAL_INJECT_BYTE, b"C");
        assert_eq!(SERIAL_INJECT_BYTE[0], 0x43);
    }
}
