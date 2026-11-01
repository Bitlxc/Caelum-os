# M10a：真实 musl 动态控制台样本（busybox）

本目录存放 M10a（Wine 垂直切片前置）使用的**真实 Linux 动态 ELF 样本**，来源为
本机 WSL `docker-desktop` 发行版（Alpine 系 musl 1.2.5）的文件系统，原样复制、
未做任何修改。用途是让 CaelumOS 的 Linux 人格装载一个“真正的现成 Linux 程序”，
而不是自写 no_std 测试程序。

## 1. 来源与用途

| 项 | 值 |
|---|---|
| 来源环境 | WSL2 `docker-desktop` distro（`uname` 6.18.x-microsoft-standard-WSL2, x86_64） |
| 发行信息 | `/etc/os-release` → `PRETTY_NAME="Docker Desktop"`；musl 1.2.5 |
| bash/busybox | `BusyBox v1.37.0 (2025-12-16 14:19:28 UTC) multi-call binary.` |
| 复制关系 | `/bin/busybox` → `busybox`；`/lib/ld-musl-x86_64.so.1` → `ld-musl-x86_64.so.1`；`/lib/libc.musl-x86_64.so.1` → `libc.musl-x86_64.so.1` |
| 修改情况 | **无**（逐字节复制，SHA256 与 WSL 内一致） |
| 用途 | M10a：内核以真实 musl ldso 作为 `PT_INTERP` 装载 busybox，验证“现成动态 Linux 控制台程序”闭环 |

> 注：`ld-musl-x86_64.so.1` 与 `libc.musl-x86_64.so.1` 在本样本中**字节完全相同**
> （musl 的 libc 同时充当动态链接器），因此 SHA256 相同属预期。

## 2. 文件清单与 SHA256

见同目录 `SHA256SUMS`：

```
f3547b3d78d08a028a4833ddb83b77cf012838c078bfd2b76355f53d1d8bba62  busybox
0ea959387b385d63b7e8730cd4fc7e7f94ee032a61aacabc81e1df3ce4a9344e  ld-musl-x86_64.so.1
0ea959387b385d63b7e8730cd4fc7e7f94ee032a61aacabc81e1df3ce4a9344e  libc.musl-x86_64.so.1
```

大小：`busybox` 804616 B；`ld-musl-x86_64.so.1` 666216 B；`libc.musl-x86_64.so.1` 666216 B。

## 3. WSL 内运行证据（真实性）

在 WSL distro 内直接执行：

```sh
/bin/busybox sha256sum /bin/busybox /lib/ld-musl-x86_64.so.1 /lib/libc.musl-x86_64.so.1
/bin/busybox echo '[CaelumLinux] M10a hello OK'
/bin/busybox sh -c 'head -3 /proc/self/maps'
```

实测结果（2026-11-01）：

- `sha256sum` 输出与 `SHA256SUMS` 的三行一致（本目录副本用 `Get-FileHash` 复核，逐字节一致）。
- `busybox echo` 输出**精确一行**：`[CaelumLinux] M10a hello OK`（27 字符 + 换行，exit 0）。
- `/proc/self/maps` 证明是真实动态装载：`/bin/busybox` 四段 `r--p/r-xp/r--p/rw-p`，
  并且 `/lib/ld-musl-x86_64.so.1` 以 `r--p/r-xp/r--p/rw-p` 映射；紧随 libc 的 `rw-p`
  段之后还有一段匿名 `rw-p`（3 页，`00000000 00:00 0`），即 musl ldso 运行时建立的
  TLS 区（mmap + `arch_prctl(ARCH_SET_FS)` 的结果）。

### 目标 argv 约定

M10a 的预期启动方式（内核需构造 argv，当前内核仍固定 argc=0）：

```
argv = [ "/bin/busybox", "echo", "[CaelumLinux] M10a hello OK" ]
```

对应 busybox 的 applet 选择语义（`argv[0]` 为 busybox 路径、`argv[1]` 为 applet 名），
在 WSL 内等价实测输出即上面那一行。

## 4. ELF 校验（readelf 证据摘要）

工具：WinGet 安装的 MinGW-w64 binutils `readelf`（GNU binutils；WSL distro 内无 readelf）。
在 `C:\temp\m10a` 副本与本目录副本上结果一致。

### busybox（主程序）

- `ELF64`, `Type: DYN (Position-Independent Executable file)`, x86-64, `Entry 0x6ed1`。
- `phnum=12`, `phentsize=56`, 4 个 `LOAD`（R / R E / R / RW），`GNU_STACK`、`GNU_RELRO`、`PT_PHDR`。
- `PT_INTERP`（偏移 0x334，19 字节）：`/lib/ld-musl-x86_64.so.1`。
- 动态项：`NEEDED libc.musl-x86_64.so.1`、`PLTREL RELA`、`PLTRELSZ 24`、`FLAGS BIND_NOW`、
  `FLAGS_1 NOW PIE`、`RELR 0x5a78` / `RELRSZ 200` / `RELRENT 8`；符号哈希只有 `GNU_HASH`（无 `DT_HASH`）。
- 重定位（`.rela.dyn`/`.rela.plt`）：378 × `R_X86_64_GLOB_DAT`、7 × `R_X86_64_COPY`、
  1 × `R_X86_64_JUMP_SLOT`；另有 RELR 隐含相对重定位。
- 入口为 musl crt 形态（`xor ebp; mov rsp,rdi; lea _DYNAMIC,rsi; and rsp,-16; call …`，
  随后 `argc=*(rdi)`、`argv=rdi+8`，`jmp __libc_start_main@plt`）。

### libc.musl / ld-musl（共享库 + 动态链接器，同一文件）

- `ELF64`, `Type: DYN (Shared object file)`, `Entry 0x6b620`（符号 `_dlstart`），`phnum=11`。
- 4 个 `LOAD`（R / R E / R / RW），`SONAME libc.musl-x86_64.so.1`，`INIT 0x41a04`、`FINI 0x4220b`。
- 动态项：`PLTREL RELA`、`PLTRELSZ 144`、`RELR`（48 字节，ENT 8）、`FLAGS BIND_NOW`；无 `NEEDED`。
- 重定位：15 × `GLOB_DAT`、6 × `JUMP_SLOT`、RELR（无 TLS/COPY 项）。
- 已 strip：只有 `.dynsym`（无 `.symtab`），内部符号不可见。

## 5. PT_TLS 最终结论（此前“无 PT_TLS”异常的复核）

**结论：这两个样本确实没有 PT_TLS，也没有 `.tdata`/`.tbss` 段；这不是测量错误。**

三条独立证据：

1. `readelf -lW busybox` / `readelf -lW libc.musl-x86_64.so.1` 的 program header 列表中
   **没有 `TLS` 行**（busybox 12 项、libc 11 项均已逐项列出：LOAD/DYNAMIC/INTERP/NOTE/PHDR/
   GNU_* 等）。
2. `readelf -SW libc.musl-x86_64.so.1` 的 section 表中**没有 `.tdata` / `.tbss`**
   （只有 `.data.rel.ro`、`.got`、`.data`、`.bss` 等）；busybox 同。
3. 自带 phdr 字节解析（读 `e_phoff/e_phentsize/e_phnum` 后逐项取 `p_type`）两次独立执行：
   `p_type == PT_TLS (7)` 出现次数为 **0**（busybox 与 libc 均如此）。

**解释与对 CaelumOS 的含义**：musl 的动态链接器在这套样本上不依赖 ELF 的 TLS 模板段来
启动——WSL 实测 `/proc/self/maps` 在 libc 的 RW 段之后出现一段匿名可写映射（3 页），
即 musl ldso 用 `mmap` 建立 TLS 区并 `arch_prctl(ARCH_SET_FS)` 设置线程指针。对 M10a 来说：

- 内核**不需要**为这个样本处理 `PT_TLS`（没有该段）；
- 内核**必须**允许 musl ldso 的匿名 `mmap` + `mprotect` + `arch_prctl(ARCH_SET_FS)` 成功；
- canary 仍来自 auxv `AT_RANDOM`（musl 在 `__init_libc`/`__init_tls` 路径读取），因此
  `AT_RANDOM` 仍是必需 auxv——不要因为“无 PT_TLS”而认为 TLF/canary 无关。

## 6. 复验命令（本目录内）

```powershell
Get-FileHash -Algorithm SHA256 .\busybox, .\ld-musl-x86_64.so.1, .\libc.musl-x86_64.so.1
# 与 SHA256SUMS 比较，三行一致

# readelf 路径（本机 WinGet MinGW binutils）
readelf -lW .\busybox          | Select-String 'INTERP|TLS|LOAD'
readelf -dW .\busybox          | Select-String 'NEEDED|PLTREL|RELR|BIND_NOW|FLAGS'
readelf -lW .\libc.musl-x86_64.so.1 | Select-String 'INTERP|TLS|LOAD'
readelf -SW .\libc.musl-x86_64.so.1 | Select-String '\.tdata|\.tbss'
```

WSL 侧复验（仅验证来源真实、不参与 CaelumOS 构建）：

```console
wsl.exe -d docker-desktop -- /bin/busybox sha256sum /bin/busybox /lib/ld-musl-x86_64.so.1 /lib/libc.musl-x86_64.so.1
wsl.exe -d docker-desktop -- /bin/busybox echo "[CaelumLinux] M10a hello OK"
wsl.exe -d docker-desktop -- /bin/busybox sh -c 'head -18 /proc/self/maps'
```

## 7. 约束与已知风险

- 本目录只放样本与校验说明；**未改 kernel/xtask**，**未跑本项目 QEMU**。
- 样本为真实 distro 文件（非自写、非 no_std）；禁止用同类自写程序替换。
- 内核侧 M10a 仍需：PT_INTERP 路径按 VFS 解析（不再固定 `/fat/ldcaelum.so`）、
  ET_DYN interpreter + `AT_BASE`、auxv 增补（AT_RANDOM/AT_HWCAP/AT_UID/EUID/GID/EGID/
  AT_SECURE/AT_EXECFN/AT_CLKTCK）、文件映射 mmap 或 musl 的 read 兜底、argv/envp 构造、
  VFS 根布局容纳 `/lib`、`/bin`（ext2 长名）。
- `ld-musl-x86_64.so.1` 与 `libc.musl-x86_64.so.1` 内容相同是 musl 正常形态；
  `PT_INTERP` 字符串必须原样 `/lib/ld-musl-x86_64.so.1`。
