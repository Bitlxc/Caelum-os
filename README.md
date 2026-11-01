# Caelum-os

**A from-scratch, 64-bit UEFI operating system kernel written in Rust.**

Caelum-os boots from UEFI firmware on x86-64, brings up symmetric multiprocessing,
runs native user-space services, and provides processes, capability handles, IPC,
a VFS with on-disk filesystems, a framebuffer display path, input devices, and a
growing network stack. It is developed and verified end-to-end in QEMU/OVMF
against a scripted acceptance suite that checks integration markers on every boot.

> Formerly developed under the names *青穹 OS / CaelumOS* (project code `OS001`);
> some design documents still use those names.

---

## Status

Current stage: **M7/M8/M9 slices under active development** (kernel version `0.16.0`).

| Milestone | Scope | State |
|---|---|---|
| M1 | UEFI loader + versioned Boot Protocol (TLV, CRC32C) | accepted |
| M2 | Byte-stream I/O, frame allocator, kernel heap, address spaces | accepted |
| M3 | ACPI/APIC/IOAPIC, LAPIC & PIT clocks, PS/2 + serial input, context switching | accepted |
| M4 | Processes, threads, syscall ABI, capability objects, waits/futex | accepted |
| M5 | VFS, ramfs/initramfs, page cache, FAT32, ext2, locks/notifications/xattrs | accepted |
| M6 | IPC (channel/port/event/subscription/shm/timer), user services, SMP | accepted |
| M7 | Networking: netcore, loopback IPv4/IPv6, native sockets, LocalSocket | M7a/M7b/M7d accepted, **M7c (virtio-net) open** |
| M8 | Linux personality core (ELF, syscalls, signals, /proc, /dev) | slices accepted |
| M9 | Linux user-space extensions (dynamic ELF, vDSO, shared objects, glibc) | slices accepted |

“Accepted” means the tree passes the automated QEMU/OVMF acceptance run:
two consecutive boots, each with the full ordered marker sequence
(currently **136 markers per boot**), exercised through real interrupts,
timers, SMP scheduling and user processes. See
[`tests/qemu/README.md`](tests/qemu/README.md) for the exact acceptance rules.

## Features

- **Boot**: self-contained UEFI loader (`x86_64-unknown-uefi`) hands over a
  versioned, checksummed `BootInfo` (TLV records: memory map, kernel image,
  boot modules, framebuffer, ACPI RSDP, serial, entropy hints); the kernel
  validates it as untrusted input.
- **Kernel**: `#![no_std]` x86-64, long mode, four-level page tables, direct map,
  physical frame allocator, explicit kernel heap, GDT/TSS/IDT with per-CPU
  state, xAPIC + IOAPIC, PIT/LAPIC periodic timers.
- **SMP**: sequential AP bring-up through a relocatable real-mode trampoline,
  per-CPU GDT/TSS/GS blocks, per-CPU run queues with affinity, load stealing,
  reschedule IPIs, preemptive user scheduling on every CPU.
- **Processes & IPC**: process/thread model with wait/wake, futex, deadlines,
  capability handles with rights and generations, channels, ports, events,
  event subscriptions (level/edge readiness), shared memory, timers.
- **Storage & VFS**: mount table, path resolution, page cache, ramfs/initramfs,
  read/write FAT32 and ext2 on virtio-blk, POSIX/OFD/`flock` lock domains,
  directory notifications, extended attributes.
- **Networking**: pure-`no_std` `netcore` library (Ethernet, ARP, IPv4, IPv6,
  ICMP/ICMPv6, UDP, TCP with a deterministic state machine), loopback stack,
  native `Socket`/`LocalSocket` objects, and a Linux socket personality layer.
  A real virtio-net link is the next milestone.
- **Display & input**: GOP framebuffer captured by the loader, mapped by the
  kernel, presented to user-space services through a display object with a
  320×200 shadow surface; PS/2 keyboard and serial input are delivered as
  sequenced events.
- **Linux personality**: ELF loading (ET_EXEC), a self-hosted interpreter for
  ET_DYN + `PT_INTERP`, a real vDSO, ET_DYN shared objects, and a minimal
  Linux64 syscall layer, exercised by small test programs.

## Repository layout

| Path | Contents |
|---|---|
| `loader/` | UEFI boot loader; builds `loader.efi` and constructs `BootInfo` |
| `kernel/` | the kernel: `arch`, `mm`, `platform`, `sched`, `process`, `object`, `ipc`, `vfs`, `net`, `syscall`, `display`, `input`, … |
| `libs/bootinfo` | Boot Protocol encoder/decoder, CRC32C, boot-module container |
| `libs/elf64` | freestanding ELF64 validation and loading helpers |
| `libs/block`, `libs/fat32`, `libs/ext2` | block-device trait and filesystem implementations |
| `libs/netcore` | no_std network protocol library (headers, checksums, TCP state machine) |
| `libs/native-abi`, `libs/native-rt` | native syscall ABI and the freestanding user runtime |
| `services/` | user-space services and test programs (init, workers, gfx, net, Linux programs) |
| `xtask/` | build orchestrator, ESP image builder, QEMU runner and acceptance checks |
| `tests/qemu/` | QEMU/OVMF acceptance procedure and helper scripts |
| `docs/` | boot protocol, native syscall ABI and Linux personality ABI specs |
| `tools/m10a/` | small prebuilt Linux user-space samples used by the Linux tests |

> `tools/ovmf/` (firmware) and `target/` (build output) are git-ignored.

## Building

Prerequisites:

- [Rust](https://rustup.rs/) — the toolchain is pinned by `rust-toolchain.toml`
  (currently 1.97.1, with the `x86_64-unknown-uefi` and `x86_64-unknown-none`
  targets; rustup installs them automatically);
- [QEMU](https://www.qemu.org/) (`qemu-system-x86_64`) for running and testing;
- OVMF firmware: place `OVMF_CODE.fd` and `OVMF_VARS.fd` in `tools/ovmf/`
  (they are not committed to the repository). On common Linux distributions
  they ship in the `OVMF`/`ovmf` package; `OVMF_CODE.fd`/`OVMF_VARS.fd` are
  also available from the [tianocore edk2 releases](https://github.com/tianocore/edk2/releases).

```bash
cargo xtask build   # build loader, kernel and every user program
cargo xtask image   # assemble a bootable EFI system partition image
cargo xtask qemu    # build the image, boot it twice in QEMU/OVMF, verify markers
cargo xtask check   # formatting, compile checks for every target, host tests
cargo xtask test    # alias of `check`
```

`cargo xtask qemu` runs the full acceptance procedure: the emulated serial
console is captured to `target/serial-boot1.log` / `target/serial-boot2.log`,
the QMP socket is used to inject input, and the expected integration markers
must appear in order, with the deliberate page-fault marker last.

## Testing

- **Host unit tests** (`cargo xtask check`): Boot Protocol, ELF validation,
  filesystems, `netcore`, the native ABI, and the kernel's own `--lib` test
  suites (memory, scheduling state machines, VFS, IPC, syscall argument
  handling, …). Most kernel logic is written so its state machines can be
  tested without hardware.
- **QEMU/OVMF acceptance** (`cargo xtask qemu`): two boots over the same image,
  verifying real hardware paths — ACPI, APIC/IOAPIC, timers, PS/2 and serial
  input, SMP scheduling, user processes, VFS on virtio-blk, display probing,
  input events and the Linux user-space samples.

## Documentation

- [`docs/abi/boot-protocol.md`](docs/abi/boot-protocol.md) — loader ↔ kernel Boot Protocol
- [`docs/abi/native-syscall.md`](docs/abi/native-syscall.md) — native system call ABI
- [`docs/linux-personality-abi.md`](docs/linux-personality-abi.md) — Linux personality ABI
- [`tests/qemu/README.md`](tests/qemu/README.md) — acceptance procedure and milestone markers

## License

Caelum-os is licensed under the **GNU General Public License v3.0**.
See [LICENSE](LICENSE) for the full text.

## Contributing / security

This is a research and hobby operating system: interfaces, ABIs and on-disk
layouts are **not stable**, and it is not hardened for production or untrusted
use. The capability model, W^X mappings and user-pointer validation are
work in progress; treat the kernel as experimental code.
