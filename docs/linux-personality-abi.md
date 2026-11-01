# Linux 人格：动态 ELF 装载与解释器契约（M9d1 / M9d2 / M9e / M9f）

> 状态：M9d1（自定义 PT_INTERP 解释器）、M9d2（vDSO 数据页）、M9e（最小共享库）
> 与 M9f（跨库函数调用）的用户侧已实现并通过静态验证；内核侧装载契约由
> `kernel/src/image.rs` 与 `libs/elf64` 实现并已与用户侧逐条对齐，以本文为准联合
> 验收（QEMU 由 Lead 统一执行）。
>
> 本文只描述**最小动态链接闭环**，不承诺 glibc、TLS、DT_INIT/DT_FINI、
> 递归依赖、PLT 懒绑定、RELRO、符号版本或 `LD_LIBRARY_PATH` 语义。

## 1. 产物与固定基址

| 产物 | 类型 | 固定基址 | 入口 | 说明 |
|---|---|---|---|---|
| 主程序 `/fat/dyn-main` | `ET_DYN`（PIE） | `0x0200_0000` | `bias + e_entry` | `PT_INTERP` 精确等于 `/fat/ldcaelum.so\0` |
| 解释器 `/fat/ldcaelum.so` | `ET_EXEC` | `0x4000_0000` | `0x4000_0000` | 自身不得带 `PT_INTERP`/`PT_DYNAMIC` |
| vDSO `/fat/vdso.so` | `ET_EXEC` | `0x0700_0000` | `0x0700_1000` | 数据页固定 `0x0700_2000` |
| 共享库 `/fat/m9e.so` | `ET_DYN` | `0x0300_0000` | — | SONAME 与 `DT_NEEDED` 均精确 `/fat/m9e.so` |
| 库 A `/fat/m9f-a.so` | `ET_DYN` | `0x0380_0000` | — | SONAME 精确；`DT_NEEDED` 恰为 `/fat/m9f-b.so` |
| 库 B `/fat/m9f-b.so` | `ET_DYN` | `0x0400_0000` | — | SONAME 精确；无 `DT_NEEDED` |

主程序与库均以 `-z max-page-size=4096` 构建，每个 `PT_LOAD` 必须满足
`p_vaddr % 4096 == p_offset % 4096`；主程序的 program header 表必须整体落在某个
`PT_LOAD` 内（`AT_PHDR = 0x0200_0000 + e_phoff` 可直接读取）。

## 2. 初始栈与 auxv（内核写，8 字节对齐）

顺序固定为：`argc = 0`、`argv[0] = NULL`、`envp[0] = NULL`，随后：

| tag | 值 |
|---|---|
| `AT_PAGESZ`(6) | `4096` |
| `AT_PHDR`(3) | `0x0200_0000 + e_phoff` |
| `AT_PHENT`(4) | `56` |
| `AT_PHNUM`(5) | `e_phnum` |
| `AT_ENTRY`(9) | `0x0200_0000 + e_entry` |
| `AT_BASE`(7) | `0`（解释器固定 ET_EXEC，无额外偏置） |
| `AT_SYSINFO_EHDR`(33) | `0x0700_0000`（vdso 基址） |
| `AT_CAELUM_CHANNEL` | 通道句柄原始值（动态闭环中为 0，未使用） |
| `AT_CAELUM_NETNS` | `0` |
| `AT_CAELUM_ROLE` | `0` |
| `AT_NULL`(0) | `0` |

主程序在 `dyn_entry` 中按上述 tag 校验；解释器只依赖 `AT_PHDR/AT_PHENT/AT_PHNUM/
AT_ENTRY/AT_BASE/AT_PAGESZ`，并使用 `AT_SYSINFO_EHDR` 之外的固定 vDSO 基址。

## 3. 内核装载职责（w8 实现）

1. 从 VFS 读取主程序 `PT_INTERP` 字符串（必须精确 `/fat/ldcaelum.so`），加载解释器。
2. 为所有映像分配明确的非重叠地址区间：主程序 `0x0200_0000`、m9e 库
   `0x0300_0000`、库 A `0x0380_0000`、库 B `0x0400_0000`、解释器 `0x4000_0000`、
   vDSO `0x0700_0000` 与 vdso 数据页 `0x0700_2000`、用户栈。
3. 按各映像自己的 `PT_LOAD` 权限建立映射；`ET_DYN` 映像统一以固定 bias 装载。
4. **内核不应用任何重定位**（`R_X86_64_RELATIVE`/`GLOB_DAT` 均由解释器处理）。
5. 解释器与 vDSO 均为 `ET_EXEC`，主程序与三个库为 `ET_DYN`；库不得带 `PT_INTERP`、
   不得带自己的 `DT_NEEDED`（A 的 `/fat/m9f-b.so` 依赖由解释器校验/解析，内核只按
   冻结路径把三个库装入同一地址空间）。
6. 按 §2 写初始栈后跳解释器入口（`0x4000_0000`），`rsp` 指向初始栈。
7. 失败必须响亮（返回错误码/停机），不得静默跳过解释器或库。

## 4. 解释器职责（`services/linux-interp`）

1. 校验主程序 `DT_NEEDED` 恰有两条，且逐字节等于 `/fat/m9e.so\0` 与
   `/fat/m9f-a.so\0`（各一条，顺序不限）；`DT_REL` 必须不出现，
   `DT_RELA`/`DT_RELASZ`/`DT_RELAENT=24` 必须齐全。
2. 校验主程序 Ehdr/phdr（`ET_DYN`、x86-64、`e_phnum`、phdr 覆盖、每 `PT_LOAD`
   congruence），bias 必须为 `0x0200_0000`。
3. 依次校验三个库（m9e@`0x0300_0000`、A@`0x0380_0000`、B@`0x0400_0000`）：Ehdr
   （`ET_DYN`、x86-64）、phdr（`PT_LOAD`、恰一个 `PT_DYNAMIC`、不得有 `PT_INTERP`）、
   `DT_SONAME` 逐字节等于各自冻结路径、dynamic 含 `DT_RELA/RELASZ/RELAENT`、
   `DT_SYMTAB/STRTAB/SYMENT=24`、`DT_HASH`（`nchain` 作符号数，上限 4096）。
   m9e 与 B 必须 `DT_NEEDED` 为空；A 必须恰一条 `DT_NEEDED` 等于 `/fat/m9f-b.so\0`。
4. 逐库应用自己的 `R_X86_64_RELATIVE`：`*(u64*)(bias + r_offset) = bias + r_addend`，
   目标必须落在该库的可写 `PT_LOAD`；m9e 与 A 各至少 1 条；其它类型响亮失败。
5. 主程序的 `R_X86_64_RELATIVE`（目标必须落在主程序可写 `PT_LOAD`）。
6. 解析主程序/库的 `R_X86_64_GLOB_DAT`/`R_X86_64_64`：先用符号名在**引用对象自身**
   的 dynsym 查已定义符号（A 的 `M9F_COUNTER` 属此类），再按
   主程序 → `m9e → A → B`、A → `A → B`、B → `B` 的顺序查依赖库的已定义符号；
   `S = 目标对象 bias + st_value`；`GLOB_DAT` 写 `S`、`R_X86_64_64` 写 `S + addend`；
   写入目标必须落在引用对象的可写 `PT_LOAD`。`R_X86_64_JUMP_SLOT` 及其它类型一律
   失败（本闭环无 PLT 懒绑定）。
7. 成功时打印
   `[CaelumDyn] interp OK (needed=2,libs=3,globdat=<实际总>,relative=<实际总>)`；
   本闭环的冻结期望是 `globdat=7`（主程序 5 + A 2）、`relative=5`（主程序 4 + m9e 1）；
   计数必须是实际处理数量，不得写死掩盖偏差。随后保持原 `rsp` 跳 `AT_ENTRY`。失败
   打印 `[CaelumDyn] FAIL <reason>` 并以 `0x81`–`0x8f` 退出。

## 5. 主程序职责（`services/linux-dyn`）

1. 校验 §2 的 auxv（缺项/值不符响亮失败）；校验自身 Ehdr/phdr 与 bias。
2. 校验 PT_INTERP 字符串 `b"/fat/ldcaelum.so\0"` 逐字节一致。
3. 打印 `[CaelumLinux] M9d dynamic OK` 后校验 vdso（§6），再校验库：
   - `DT_NEEDED` 恰两条且各一条 `/fat/m9e.so` 与 `/fat/m9f-a.so`；
   - m9e：lib Ehdr@`0x0300_0000`、`m9e_value() == 0x4D39_4501_0000_0001`、
     `M9E_COUNTER == 0x1122_3344_5566_7788`、`M9E_BYTES_PTR` 指向库内
     `b"M9E-LIB!"`（8 字节），全部通过后打印 `[CaelumLinux] M9e shared OK`；
   - M9f：A@`0x0380_0000` 的 Ehdr 且无 `PT_INTERP`、A 的 SONAME
     `/fat/m9f-a.so`、A 的 `DT_NEEDED` 恰 `/fat/m9f-b.so`；B@`0x0400_0000`
     的 Ehdr 且无 `PT_INTERP`、B 的 SONAME `/fat/m9f-b.so`、B 无 `DT_NEEDED`；
     `m9f_sum(20, 22) == 42` 连续两次、`M9F_COUNTER == 2`，全部通过后打印
     `[CaelumLinux] M9f shared OK` 并 `exit_group(0)`。
4. 失败打印 `[CaelumLinux] FAIL m9d <reason>` 并以 `0x90`–`0xa3` 退出（M9f 段用
   `0xa0`–`0xa3`）。

## 6. vDSO 契约（M9d2）

- 基址 `0x0700_0000`、入口 `0x0700_1000`（`__vdso_clock_gettime`）、数据页
  `0x0700_2000`；两页均可读，数据页可写由内核维护。
- 数据页布局（24 字节）：`magic = 0xCAE1_0001`、`version = 1`、`seq`、`hz`、
  `ticks`（单调 tick）。写者必须用偶数 `seq` + 两次递增，读者按 seq 重试。
- `hz` 的运行时值由内核以真实 tick 频率写入（当前 `time::tick_hz() = 100`）；ELF
  镜像里的 `hz` 初始值只是骨架数据、不生效。解释器与主程序一律从数据页读取 `hz`，
  不得假设 1000 或其他固定值。
- `__vdso_clock_gettime(clock: u64, tp: *mut Timespec) -> i64`：
  `CLOCK_MONOTONIC`(1)/`CLOCK_BOOTTIME`(7) 返回 0 并写 `{sec, nsec}`；其它 clock
  （含 `CLOCK_REALTIME`=0）返回 `-ENOSYS`(-38)，不得伪造。
- 内核负责把 vdso 映射到固定基址、写 `AT_SYSINFO_EHDR = 0x0700_0000`，并维护
  `seq/ticks` 与 `hz`（取真实 `time::tick_hz()`，当前 100）；主程序不得解析符号表。

## 7. 共享库契约（M9e + M9f）

- 三个库均为 `ET_DYN`、固定 bias、内核不提供 `AT_CAELUM_LIB` 之类第二来源：
  m9e@`0x0300_0000`（SONAME 与主程序 `DT_NEEDED` 都精确 `/fat/m9e.so`）、
  A@`0x0380_0000`（SONAME `/fat/m9f-a.so`，`DT_NEEDED` 恰 `/fat/m9f-b.so`）、
  B@`0x0400_0000`（SONAME `/fat/m9f-b.so`，无 `DT_NEEDED`）。
- 主程序 `DT_NEEDED` 恰两条：`/fat/m9e.so` 与 `/fat/m9f-a.so`；依赖链固定为
  主程序 → m9e、主程序 → A → B，**仅支持这一条两级链**，不支持任意依赖图、递归
  依赖或 `DT_NEEDED` 数量变化。
- m9e 导出 `m9e_value`、`M9E_COUNTER`、`M9E_BYTES_PTR`；A 导出 `m9f_sum` 与
  `M9F_COUNTER`（A 内部经 `m9f_add` 调 B，且每次调用 `M9F_COUNTER += 1`）；B 导出
  `m9f_add`。库内可含 `R_X86_64_RELATIVE`，由解释器应用；库不得有 `PT_INTERP`、
  不得执行 `DT_INIT`、不得使用 TLS/IFUNC/PLT 懒绑定。
- 各对象的未定义符号解析顺序：先自身已定义符号，再按依赖方向查
  （主程序：m9e → A → B；A：A → B；B：B）；解析不到必须响亮失败。

## 8. 阶段标记

| 标记 | 阶段 |
|---|---|
| `[CaelumDyn] interp OK (needed=2,libs=3,globdat=7,relative=5)` | M9d1 + M9e + M9f 解释器（计数为实际值） |
| `[CaelumLinux] M9d dynamic OK` | M9d1 主程序 |
| `[CaelumLinux] M9d vdso OK` | M9d2 |
| `[CaelumLinux] M9e shared OK` | M9e |
| `[CaelumLinux] M9f shared OK` | M9f |

M9f 完成后每次启动合计 136 条集成标记（M9e 为 135）。

## 9. 明确不支持（本闭环边界）

- glibc/ld.so 语义、TLS、`DT_INIT`/`DT_FINI`、递归依赖、任意依赖图、`PLT` 懒绑定、
  `RELRO`、符号版本、`DT_GNU_HASH` 查询（仅用 `DT_HASH` 的 `nchain`）、
  `LD_PRELOAD`/`LD_LIBRARY_PATH`、`dlopen`。
- 任何形式的内核侧重定位：重定位只允许解释器在用户态应用。
