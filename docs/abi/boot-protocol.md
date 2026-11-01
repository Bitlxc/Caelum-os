# 青穹 OS / CaelumOS Boot Protocol 规范 v1.1

> 状态：M1 基线 + M4 启动模块扩展（对应 `agents.md` §5 启动协议；M0 已关闭）  
> 适用范围：自研 UEFI Loader（`x86_64-unknown-uefi`）与内核入口
> （`x86_64-unknown-none`）之间的启动交接。  
> 实现参考：`libs/bootinfo`（共享编解码 + CRC32C + 启动模块容器，宿主单测覆盖）、
> `libs/elf64`（ELF 校验，宿主单测覆盖）、`loader/`（构造方）、`kernel/`（接收方）。

## 1. 通用约定

- 所有多字节整数为**小端**、固定位宽；不使用 Rust 原生布局传输数据。
- BootInfo 由 Loader 构造，内核必须将其视为**不可信输入**校验。
- Loader 与内核各自输出自身版本与协议版本（见 §10 日志标记）。

## 2. BootInfo 固定头（64 字节）

| 偏移 | 大小 | 字段 | 说明 |
|---|---|---|---|
| 0 | 8 | `magic` | `u64`，ASCII `CAELUM01` |
| 8 | 2 | `major` | 协议主版本，当前 `1` |
| 10 | 2 | `minor` | 协议次版本，当前 `1` |
| 12 | 4 | `header_size` | 固定头大小，当前 `64` |
| 16 | 4 | `total_size` | 整个 BootInfo 大小（含 TLV），≤ 1 MiB |
| 20 | 4 | `checksum` | CRC32C，见 §3 |
| 24 | 8 | `flags` | bit0 = 调试日志；其余保留为 0 |
| 32 | 4 | `entry_abi` | 内核入口 ABI 版本，当前 `1` |
| 36 | 4 | `tlv_offset` | 第一个 TLV 的偏移，当前 `64` |
| 40 | 4 | `tlv_count` | TLV 记录条数 |
| 44 | 20 | `reserved` | 必须为 0 |

## 3. 校验值（checksum）

- 算法：CRC32C（Castagnoli），反射形式，多项式 `0x1EDC6F41`，
  初值 `0xFFFFFFFF`，结果异或 `0xFFFFFFFF`。
- 参与校验的字节范围：整个 BootInfo `[0, total_size)`，其中
  checksum 字段（`[20..24)`）**按 0 处理**。
- 校验失败的 BootInfo 必须被拒绝（内核侧失败类别 `bad-checksum`）。

## 4. TLV 规则

- 记录头 8 字节：`type u32`、`length u32`（值长度，不含头与填充）。
- 每个记录从 BootInfo 起始处 8 字节对齐；值按 8 字节零填充。
- `type` 必须**严格升序**、不得重复；未知类型的可选 TLV 必须被忽略。
- 新增可选 TLV 只能在 `minor` 版本中引入；既有可选 TLV 不得在无
  `major` 升级时升为必需。
- 因此 v1.1 可以新增可选 TLV `0x7`（§5.1），而 v1.0 内核（`major=1`）
  仍必须接受并忽略它。

## 5. TLV 类型

| type | 名称 | 必需性 | 值布局 |
|---|---|---|---|
| 0x1 | `MEMORY_MAP` | 必需 | 8 字节前缀（`desc_size u32`、`desc_version u32`）+ N 个原始 UEFI 内存描述符（每个 48 字节：`Type u32 @0`、`PhysicalStart u64 @8`、`VirtualStart u64 @16`、`NumberOfPages u64 @24`、`Attribute u64 @32`） |
| 0x2 | `KERNEL_IMAGE` | 必需 | 64 字节，8 个 u64：`image_phys_base`、`image_phys_size`、`image_virt_base`、`image_virt_size`、`entry_virt`、`stack_base`、`stack_size`、`page_table_phys`（初始 PML4 物理地址） |
| 0x3 | `EARLY_SERIAL` | 必需（若 0x4 缺失） | 24 字节：`kind u32`（1 = I/O 端口 16550）、`base u64`、`baud u32`、`reserved u32` |
| 0x4 | `FB_GOP` | 可选 | 32 字节：`base u64`、`size u64`、`width u32`、`height u32`、`stride u32`、`pixel_format u32` |
| 0x5 | `ACPI_RSDP` | 可选 | 8 字节：RSDP 物理地址 |
| 0x6 | `LOADER_INFO` | 可选 | UTF-8 版本字符串（无 NUL） |
| 0x7 | `BOOT_MODULES` | 可选（v1.1 新增；M4 内核要求存在） | 启动模块列表，见 §5.1 |

必需 TLV 集合：`0x1`、`0x2`，以及 `0x3` 与 `0x4` 至少一项。缺少任一
必需项必须按协议规则明确拒绝启动。`0x7` 在协议层是可选项：v1.0 内核
忽略它，v1.1 内核在需要启动模块（M4 init）时若缺失必须明确失败，
不得静默以“无模块”继续。

### 5.1 TLV 0x7 `BOOT_MODULES` 值布局（v1.1）

```text
count      u32   @0    模块数量（1..=8）
reserved   u32   @4    必须为 0
records    count × 40 字节，紧接前缀
```

每个 40 字节记录（全部小端）：

| 偏移 | 大小 | 字段 | 说明 |
|---|---|---|---|
| 0 | 8 | `phys` | 模块字节的**物理**起始地址，必须是 16 的倍数 |
| 8 | 8 | `size` | 模块字节长度，> 0；`phys + size` 不得溢出 |
| 16 | 4 | `kind` | 模块类型：`1` = ELF64 可执行映像 |
| 20 | 4 | `name_len` | 名称长度，`1..=16` |
| 24 | 16 | `name` | ASCII 名称，NUL 填充；允许 `[A-Za-z0-9._-]` |

约束：

- 名称必须唯一（内核按名称定位，重名即非法）。
- 记录必须与 `count` 严格对应（无多余/缺失字节），否则整条 TLV 非法。
- 模块字节本身由内核在页表接管后按需映射为只读、不可执行（NX）；
  协议不要求 Loader 把模块页放进初始页表，但要求这些物理页在
  `ExitBootServices` 后仍然有效（本实现分配为 `MEMORY_LOADER_DATA`，
  在 `MEMORY_MAP` 中不会被当作可分配常规内存）。
- 模块映像必须通过 `libs/elf64::Elf64::validate_for_user`：`ET_EXEC`、
  x86-64、PT_LOAD ≤ 8、文件/溢出/低半地址检查、W^X、entry 位于可执行段、
  `filesz ≤ memsz`、`(vaddr % 4096) == (offset % 4096)`、段页范围不重叠。

### 5.2 `INITFS.IMG` 容器格式（ESP 侧，v1.1）

Loader 从 ESP 根目录读取纯 8.3 文件名 `\INITFS.IMG`（大写、11 字符上限），
其格式冻结如下：

```text
magic      u64   @0     ASCII `CAELUMFS`
version    u32   @8     容器格式版本 = 1
count      u32   @12    模块数量（1..=8）
records    count × 40 字节，紧接 16 字节固定头
payloads   从 16 + count*40 起，按 16 字节对齐分布
```

每个 40 字节记录（全部小端，**显式 `reserved`，不使用自然 padding**）：

| 偏移 | 大小 | 字段 | 说明 |
|---|---|---|---|
| 0 | 16 | `name` | ASCII 名称，NUL 填充 |
| 16 | 4 | `kind` | 模块类型，当前仅 `1` = ELF |
| 20 | 4 | `reserved` | 必须为 0 |
| 24 | 8 | `offset` | 相对容器起始的文件偏移，必须是 16 的倍数 |
| 32 | 8 | `size` | 模块字节长度，> 0；`offset + size ≤ 文件大小` |

约束：模块负载不得与固定头/记录表或彼此重叠；名称必须唯一；
M4 要求容器恰好包含 `init`、`child` 两个模块（顺序不限），两模块均为
通过 `validate_for_user` 的 ELF；Loader 必须在 `ExitBootServices` 前完成
上述全部校验并拒绝启动。

## 6. 内核入口 ABI（`entry_abi = 1`）

- `rdi` = BootInfo 物理地址；`rsi` = BootInfo 在初始页表中的虚拟地址。
- M1：BootInfo 恒等映射，`rsi == rdi`。
- 入口时保证：有效且 16 字节对齐的栈、中断关闭、内核镜像全部 PT_LOAD
  段（含入口代码）、初始栈、完整 BootInfo 以及被声明用于早期失败输出
  的早期诊断资源均已映射。
- 入口不返回，不依赖 Rust ABI；对外使用 C 调用约定。

## 7. 内核镜像元数据 `.caelum.bootreq`

内核镜像必须携带名为 `.caelum.bootreq` 的节（16 字节）：

| 偏移 | 大小 | 字段 |
|---|---|---|
| 0 | 8 | magic，ASCII `CBTREQ01` |
| 8 | 2 | 所需协议 `major` |
| 10 | 2 | 所需协议 `minor` |
| 12 | 4 | 所需 `entry_abi` |

Loader 在**进入 `ExitBootServices` 之前**预检该元数据（`agents.md`
§5.3 规则 6），兼容判据为：

```text
req.major == loader.major  &&  req.entry_abi == loader.entry_abi
                            &&  req.minor <= loader.minor
```

即 `minor` 是**下界**而不是等值：Loader 实现更高 `minor` 时可以启动只
要求较低 `minor` 的内核。magic 不符、`major` 不一致、`entry_abi` 不受
支持、或内核所需 `minor` 高于 Loader 所实现版本时，必须通过固件输出
明确报错并拒绝启动，不得进入 `ExitBootServices`。

## 8. 校验分工与失败路径

- **Loader 构造期校验**（`ExitBootServices` 前）：BootInfo 自身一致性、
  TLV 内部一致性、内核 ELF 合法性、`.caelum.bootreq` 预检、`INITFS.IMG`
  容器合法性与每个模块 ELF 的 `validate_for_user`。失败时通过固件输出
  报错并拒绝启动。
- **内核接收期校验**：按 §2–§5 检查 magic、版本、`entry_abi`、
  `header_size`、`total_size`（64..=1 MiB）、TLV 边界/对齐/升序/计数、
  必需 TLV 集合与 checksum；`0x7` 存在时按 §5.1 完整复核（不能只信
  Loader）。失败后不得继续初始化。
- **内核最小失败输出**（`agents.md` §5.3 规则 9）：校验失败时，内核仅
  依赖入口 ABI 保证的已映射早期诊断资源（EARLY_SERIAL 的地址参数，
  做最小范围检查），直接输出最小失败信息（协议版本 + 失败类别），
  随后停机。

## 9. 初始页表与启动服务退出

- 初始页表（4 级）必须覆盖：内核镜像全部 PT_LOAD 的**对齐后物理范围**
  及其**虚拟链接地址**（按段权限 W^X）、初始栈、BootInfo 完整对齐范围、
  页表自身、Loader 镜像（CR3 切换后 Loader 代码继续运行所需）。
- `INITFS.IMG` 及其模块负载**不需要**初始页表映射：它们以
  `MEMORY_LOADER_DATA` 保留在最终 `MEMORY_MAP` 中，内核在页表接管后
  通过自有映射（只读 + NX）访问。
- `GetMemoryMap` 与 `ExitBootServices` 之间不得发生会改变映射键的分配。
- `ExitBootServices` 失败必须**重新获取完整内存映射**后重试，不得复用
  旧 key；本实现最多重试 3 次，每次重试都重建 BootInfo 中的
  `MEMORY_MAP` TLV 并重新计算 checksum（`BOOT_MODULES` TLV 内容不变）。

## 10. 日志标记（验收口径）

- Loader 每行以 `[CaelumLoader] ` 开头；关键行：
  `bootreq precheck OK`、`INITFS.IMG: <n> bytes @ phys 0x…`、
  `module <name>: <n> bytes @ offset 0x… entry 0x…`、
  `ExitBootServices OK`。
- 内核每行以 `[CaelumKernel] ` 开头；成功路径关键行：
  `bootinfo validate OK`（含 TLV 数）、双方版本与协议版本行、
  内存摘要行、`M1 OK`、后续里程碑行。
- 失败路径关键行：`bootinfo validate FAIL: <类别>`、
  `FAIL: INITFS.IMG …`、`FAIL: module '<name>' …`。

## 11. 实现说明（与规范的已知偏差）

- 本实现只产生 `EARLY_SERIAL`（kind=1，I/O 端口 `0x3F8`，115200），
  不产生 `FB_GOP`；`ACPI_RSDP`、`LOADER_INFO`、`BOOT_MODULES` 可选产生。
- 早期串口硬编码 COM1 属于 M1 的 QEMU/OVMF 验证基线；真实硬件需按
  平台探测后再声明（规范要求不假定所有平台都有 COM1）。
- M4 固定要求 `INITFS.IMG` 恰好包含 `init`、`child` 两个模块；多模块
  容器格式本身允许 1..=8 个，作为后续阶段扩展点。

## 12. 变更记录

- v1.0（M1）：首版。`entry_abi=1`；必需 TLV 集合见 §5；CRC32C 校验。
- v1.1（M4）：新增可选 TLV `0x7 BOOT_MODULES`（§5.1）与 ESP 侧
  `INITFS.IMG` 容器格式（§5.2）；`minor` 由 `0` 升为 `1`。
  `major`、`header_size`、`entry_abi`、必需 TLV 集合均不变。

### 迁移说明（1.0 → 1.1）

1. Loader 升级到 1.1 后写入 `minor=1` 并附带 `0x7`。
2. v1.0 内核（`major=1`）继续工作：`minor` 不参与 BootInfo 等值校验，
   未知可选 TLV `0x7` 被忽略（内核只要求 CPU 满足必需 TLV 集合）。
3. v1.1 内核的 `.caelum.bootreq` 写 `minor=1`，因此只能由实现
   `minor >= 1` 的 Loader 启动；旧 Loader 会按 §7 规则明确拒绝。
4. 需要启动模块的阶段（M4 起）在内核侧检查 `0x7` 是否存在并在缺失时
   明确失败；M1–M3 内核不依赖该 TLV。
5. `INITFS.IMG` 由构建工具（`xtask`）打包，Loader 只读不写；容器与
   TLV 两个格式的 40 字节记录**不同**（§5.1 vs §5.2），实现时不得混用。
