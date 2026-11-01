# 青穹 OS / CaelumOS 原生系统调用 ABI（M7b，版本 0.6）

> 文档状态：0.2 在 M5c1 冻结文件/目录语义、由 M5c2/M5c3 启用 18–25；0.3 在 M6a1 启用 27/28/29/33；0.4 在 M6a2 启用 30/31/32/34/35 与 37/38/39（`ipc_send`/`ipc_recv`/`shm_map`/`subscribe`/`unsubscribe`/`futex_wait`/`futex_wake`/`subscription_read`）；0.5 在 M6c 新增 40–43（`display_info`/`display_map`/`display_present`/`input_read`），交付显示 RAM shadow 与输入事件队列；**0.6 在 M7b 冻结 44–53（socket/bind/listen/accept/connect/send/recv/shutdown/socketpair/socket_address）的调用号、寄存器约定、请求布局与错误码，socket 内核实现随 M7 交付**（0.1 为 M4 冻结版本）。适用于 x86-64 参考实现；其它架构（arm64 预留）保持相同语义，寄存器与入口指令另行定义。
> 本文是原生 ABI 0.6 的规范文本。`libs/native-abi` 中的常量与 `repr(C)` 结构与本文一一对应；两者冲突时以本文为准，并必须同步修正代码。
> 本文不定义内核内部数据结构、调度策略或对象生命周期实现，只约束用户态可观察的契约。
> 0.6 只新增调用、结构与错误码，不改变 0.5 已冻结的调用号、错误码、句柄编码与既有请求布局；0.5 的程序不改即可运行（调用 44–53 除外——它们由本版本首次定义）。

## 1. 范围

ABI 0.1（M4）只交付"能跑起第一个原生用户进程并验证能力句柄不隐式继承"的最小闭环；ABI 0.2（M5c1）在此之上加入**用户可见的真实文件/目录语义**，并把后续 mmap/锁/xattr/目录通知的调用号一并冻结；M5c2 启用其中 18–20（`mmap`/`munmap`/`mprotect`），M5c3 启用 21–25（`lock`/`xattr_set`/`xattr_get`/`watch`/`watch_drain`）；ABI 0.3（M6a1）启用 27/28/29/33，交付 Event / EventPair / Timer 三类最小可等待对象与统一阻塞等待；**ABI 0.4（M6a2）启用 30/31/32/34/35/37/38/39**，交付 Channel / Port / 共享内存 / 事件订阅与 futex 等待，并让 `ipc_create` 覆盖全部七种 IPC 种类。

0.1 已交付的调用：

| 系统调用号 | 名称 | 用途 |
|---:|---|---|
| 0 | `abi_query` | 查询 ABI 版本 |
| 1 | `write` | 经能力句柄写字节流（0.2 起为控制台或打开的文件） |
| 2 | `process_create` | 由启动模块创建子进程并传递句柄 |
| 3 | `process_wait` | 非阻塞查询子进程退出状态 |
| 4 | `process_exit` | 终止当前进程 |
| 5 | `random_read` | 经能力句柄读取随机字节 |
| 6 | `handle_close` | 关闭当前进程的一个句柄 |

0.2 新增并在 M5c1 实现的调用：

| 系统调用号 | 名称 | 用途 |
|---:|---|---|
| 7 | `open` | 以绝对路径打开/创建文件或目录，得到句柄 |
| 8 | `read` | 从文件/目录句柄读取字节 |
| 9 | `stat` | 查询句柄对应的节点属性 |
| 10 | `readdir` | 按序号枚举目录项 |
| 11 | `mkdir` | 创建目录 |
| 12 | `rmdir` | 删除空目录 |
| 13 | `unlink` | 删除文件 |
| 14 | `rename` | 重命名/移动（同一挂载点内） |
| 15 | `sync` | 把该句柄的脏数据写回底层存储 |
| 16 | `seek` | 设置/查询文件偏移 |
| 17 | `dup` | 复制句柄（可缩减 rights，共享文件偏移） |
| 26 | `truncate` | 把文件截断/扩展到指定长度 |

0.2 由 M5c2 实现（此前只冻结编号）的调用（18–20，详见 §6.19–§6.21，不得再返回 `NOT_SUPPORTED`）：

| 系统调用号 | 名称 | 用途 |
|---:|---|---|
| 18 | `mmap` | 把文件的一部分急切映射进进程地址空间，返回映射句柄 |
| 19 | `munmap` | 解除映射并关闭对应映射句柄 |
| 20 | `mprotect` | 修改已有映射的保护位 |

0.2 由 M5c3 实现的调用（21–25，详见 §6.22–§6.26；不得再返回 `NOT_SUPPORTED`）：

| 系统调用号 | 名称 | 用途 |
|---:|---|---|
| 21 | `lock` | 文件锁：POSIX / OFD / `flock` 三个独立域，非阻塞 |
| 22 | `xattr_set` | 写扩展属性（仅 `user.*` 命名空间） |
| 23 | `xattr_get` | 读扩展属性 |
| 24 | `watch` | 订阅目录变更，返回 Watch 句柄 |
| 25 | `watch_drain` | 取走已排队的变更事件 |

0.3 由 M6a1 实现的调用（27/28/29/33，详见 §6.27–§6.30；不得再返回 `NOT_SUPPORTED`）：

| 系统调用号 | 名称 | 用途 |
|---:|---|---|
| 27 | `ipc_create` | 创建可等待对象（0.4 起支持 Event / EventPair / Channel / Port / SharedMemory / Timer / Subscription） |
| 28 | `ipc_signal` | 对可等待对象置位/复位（EventPair 需指定端点） |
| 29 | `wait` | 在最多 4 个可等待对象上阻塞，带超时与唤醒原因 |
| 33 | `timer_arm` | 为 Timer 对象装载一次性到期时间（调度 tick） |

0.4 由 M6a2 实现的调用（30/31/32/34/35/37/38/39，详见 §6.31–§6.39；不得再返回 `NOT_SUPPORTED`）：
| 系统调用号 | 名称 | 用途 |
|---:|---|---|
| 30 | `ipc_send` | 向 Channel/Port 发送一条内联消息，可传递最多 2 个句柄（附 rights） |
| 31 | `ipc_recv` | 从 Channel/Port 收取一条消息与随附句柄/元数据，可带超时 |
| 32 | `shm_map` | 把共享内存对象映射进当前进程，返回映射句柄与用户地址 |
| 34 | `subscribe` | 给已有订阅对象增加 interest（可等待对象 + LT/ET 模式 + key） |
| 35 | `unsubscribe` | 从订阅对象移除某个可等待对象的 interest |
| 37 | `futex_wait` | 在用户态 `u32` 上阻塞，直到值变化 + `futex_wake` 或超时 |
| 38 | `futex_wake` | 唤醒在给定用户地址上阻塞的至多 `max` 个等待者 |
| 39 | `subscription_read` | 读走订阅对象上已就绪的事件（LT/ET 各自的语义见 §6.39） |

0.5 由 M6c 实现的调用（40–43，详见 §6.40–§6.43；不得再返回 `NOT_SUPPORTED`）：

| 系统调用号 | 名称 | 用途 |
|---:|---|---|
| 40 | `display_info` | 查询显示 RAM shadow 的宽/高/stride/像素格式/字节数 |
| 41 | `display_map` | 把整块显示 RAM shadow 映射进当前进程（RW），返回映射句柄与用户地址 |
| 42 | `display_present` | 把 shadow 中的一整帧提交到 framebuffer（M6c 只接受全屏 320×200） |
| 43 | `input_read` | 非阻塞读取输入事件队列（kind/code/sequence/timestamp） |

0.6 由 M7b **冻结**的调用（44–53，详见 §6.44–§6.53；本切片只落调用号、寄存器约定、请求布局与用户运行库 wrapper，socket 内核实现随 M7 交付，在此之前返回 `NOT_SUPPORTED` 是预期状态）：

| 系统调用号 | 名称 | 用途 |
|---:|---|---|
| 44 | `socket` | 创建 socket（UNIX/INET/INET6 × STREAM/DGRAM），返回句柄 |
| 45 | `bind` | 把 socket 绑定到 `SocketAddrWire` 描述的地址 |
| 46 | `listen` | 把 stream socket 置为监听态（`rsi` = backlog） |
| 47 | `accept` | 非阻塞接受一个连接，返回新句柄并 copy_out |
| 48 | `connect` | 非阻塞发起连接（`WOULD_BLOCK` 表示进行中） |
| 49 | `send` | 非阻塞发送，返回接受字节数 |
| 50 | `recv` | 非阻塞接收，返回收到字节数与可选源地址 |
| 51 | `shutdown` | 关闭读/写/双向（`rsi` = how） |
| 52 | `socketpair` | 创建匿名已连接 socket 对，输出两个句柄 |
| 53 | `socket_address` | 读取 socket 的本地或对端地址 |

0.6 的首个用户侧使用方是第五启动模块 `net`（M7b 自检程序，父/子进程都走真实 NR44–53 与 Channel 句柄传递）；它的入口句柄与父/子角色模型见 §8.3。

0.4 仍只冻结编号、本阶段未实现的调用：36 `ipc_transfer`（句柄传递统一走 `ipc_send`，该编号保留不复用）。**单个切片完成不等于 M6 完成**：M6a2/M6b/M6c 各自只是 M6 的一部分。

不在本次范围内的能力（线程、信号、`poll/epoll`、fd 传递、Linux socket ABI 与 errno 映射、`SCM_RIGHTS`/`SCM_CREDENTIALS`）不预留占位调用号；新增调用一律使用新编号，不复用本表数值。0.3 不引入 Linux fd 语义：`open` 返回的是能力句柄，不是进程全局最小整数编号，也没有 `O_*` 标志位到 Linux 标志的映射承诺。M7b 同样只定义**原生** socket 状态码（见 §4 的 `CONNECTION_REFUSED`/`CONNECTION_RESET`/`NOT_CONNECTED`）；Linux errno 视图属后续 M7d 的 compat 层。

## 2. 术语

- **进程（Process）**：拥有独立句柄表与地址空间的执行主体。M4 每个进程单线程。
- **句柄（Handle）**：进程局部的、不可伪造的 32 位能力引用，见第 5 节。句柄不是内核地址。
- **rights**：句柄携带的权限位，见第 5.3 节。
- **状态码（status）**：系统调用的统一返回码，`0` 表示成功，非 `0` 见第 4 节。
- **结果（result）**：系统调用成功时的附加返回值（字节数、句柄、退出码等）。

## 3. 调用约定（x86-64）

原生 ABI 使用 `syscall` 指令进入内核（不使用 `int 0x80` / `sysenter`；32 位与兼容模式入口不属于原生 ABI）。

| 寄存器 | 输入 | 输出 |
|---|---|---|
| `rax` | 系统调用号 | 状态码（`0` = 成功） |
| `rdi` | 参数 1 | 不变 |
| `rsi` | 参数 2 | 不变 |
| `rdx` | 参数 3 | 结果 |
| `r10` | 参数 4 | 不变 |
| `r8` | 参数 5 | 不变 |
| `r9` | 参数 6 | 不变 |
| `rcx` | 由硬件写入返回 RIP | 破坏，调用者不得依赖 |
| `r11` | 由硬件写入 RFLAGS | 破坏，调用者不得依赖 |

规则：

1. 参数与返回值均为 64 位；小整数不做符号扩展，高位按值零扩展。
2. `rcx`/`r11` 是 `syscall` 指令的硬件副作用，任何参数都不得放在这两个寄存器中。
3. 成功与否只看 `rax`：`rax == 0` 时 `rdx` 为结果；`rax != 0` 时 `rdx` 无定义，调用者必须忽略。
4. 用户缓冲区（`write` 的源、`random_read` 的目标、`process_create` 的请求结构）必须由内核按 copy-in/copy-out 规则访问；内核不得直接解引用用户指针，指针不可读/不可写/越界时返回 `BAD_POINTER`。
5. 控制结构（`ProcessCreateRequest`）由内核完整复制为内核快照后校验与使用，校验与执行不得在复制后再次读取用户内存。
6. 内核对 `size`/`version`/`reserved` 等字段做严格校验，不使用"忽略未知字段"策略；ABI 0.1 的结构布局是精确契约。
7. 结构里的 `version` 是**布局版本**，与 ABI 版本相互独立：0.2 的全部请求结构布局版本恒为 `REQUEST_VERSION = 1`。ABI 版本由 `abi_query` 单独报告，不能从结构布局版本推断。
8. 0.2 的路径参数是"用户指针 + 字节长度"的裸字节序列，不要求 NUL 结尾、不解析 UTF-8；必须是绝对路径（`/` 开头），相对路径不引入（0.2 没有工作目录概念）。路径长度上限由内核按实现给出并在超限时返回 `BAD_POINTER`。

## 4. 状态码与错误码

`rax` 的取值表（冻结，用户程序按常量比较，不得依赖数字含义的猜测）：

| 值 | 名称 | 含义 |
|---:|---|---|
| 0 | `OK` | 成功 |
| 1 | `BAD_HANDLE` | 句柄在调用者句柄表中不存在（含代次不符、已关闭、从未传递） |
| 2 | `BAD_RIGHT` | 句柄存在但缺少所需 rights |
| 3 | `BAD_POINTER` | 用户缓冲区/请求指针不可访问、越界或长度非法 |
| 4 | `BAD_REQUEST` | 请求结构内容非法（`size`/`version`/`reserved`/`handle_count`/模块名等） |
| 5 | `NO_ENTROPY` | CRNG 尚未就绪，安全用途随机数暂不可用 |
| 6 | `WOULD_BLOCK` | 操作当前无法完成，但重试可能成功（`process_wait` 与 M5c3 的非阻塞 `lock` 使用） |
| 7 | `NOT_FOUND` | 请求的对象不存在（如 `process_create` 指定的启动模块名不存在） |
| 8 | `QUOTA` | 超出调用者的配额（进程数、句柄数等） |
| 9 | `NOT_SUPPORTED` | 本版本明确不支持该操作 |
| 10 | `EXISTS` | 目标已存在（`open` 未带 `CREATE` 却要求创建、`mkdir` 同名、`rename` 目标已占用） |
| 11 | `NOT_DIR` | 路径中间组件或父节点不是目录（`ENOTDIR`） |
| 12 | `IS_DIR` | 对象是目录但操作要求文件（`read`/`write`/`truncate` 于目录句柄） |
| 13 | `READ_ONLY` | 对象只读（启动模块等只读文件系统上的节点） |
| 14 | `NO_SPACE` | 底层存储空间不足 |
| 15 | `TOO_LARGE` | 长度/偏移超出该文件系统或本实现的表示能力 |
| 16 | `BUSY` | 对象正被占用，当前不能执行该操作（如目录仍有打开的引用） |
| 17 | `IO` | 底层存储/设备 I/O 失败 |
| 18 | `TIMEOUT` | 底层操作超时 |
| 19 | `CORRUPT` | 底层数据结构损坏或校验失败 |
| 20 | `NOT_EMPTY` | 目录非空，不能 `rmdir` |
| 21 | `CROSS_DEVICE` | 两个路径不在同一挂载点，操作不允许跨挂载点（如 `rename`） |
| 22 | `CANCELLED` | 等待被取消（对象销毁/调用者退出等路径）；0.3 冻结，M6a1 不主动产生 |
| 23 | `PEER_CLOSED` | 事件/通道/socket 的对端已全部关闭；0.3 冻结，M6a1 不主动产生 |
| 24 | `CONNECTION_REFUSED` | 连接被对端拒绝（`connect`：端口无监听、UNIX 路径无监听端）；0.6 与 M7b 起使用，**不是** Linux errno 111 |
| 25 | `CONNECTION_RESET` | 已建立的连接被对端重置；0.6 与 M7b 起使用，**不是** Linux errno 104 |
| 26 | `NOT_CONNECTED` | socket 尚未建立连接（或本端已 `shutdown` 相应方向），操作当前无有效对端；0.6 与 M7b 起使用 |

0.4 不新增错误码：`ipc_recv` 队列为空且 `timeout_ticks = 0` 复用 `WOULD_BLOCK`，有超时未就绪复用 `TIMEOUT`，对端全部关闭返回 `PEER_CLOSED`；`futex_wait` 的"值不匹配"复用 `WOULD_BLOCK`、超时复用 `TIMEOUT`、`max`/地址非法返回 `BAD_POINTER`；`subscribe`/`subscription_read` 的参数错误复用 `BAD_REQUEST`、句柄能力不足复用 `BAD_RIGHT`。

0.5 同样不新增错误码：`display_info`/`display_map`/`display_present` 的请求结构非法（`size`/`version`/`reserved`/矩形不是全屏/`prot` 含 `PROT_EXEC`）复用 `BAD_REQUEST`，句柄类型或 rights 不足复用 `BAD_HANDLE`/`BAD_RIGHT`，内核尚未提供显示对象时返回 `NOT_SUPPORTED`；`input_read` 的 `max_events` 越界或 `out_events_ptr` 不可写复用 `BAD_REQUEST`/`BAD_POINTER`，空队列返回 `OK` + `rdx = 0`（不是 `WOULD_BLOCK`）。

0.6 新增错误码 24–26 并冻结其原生语义：`CONNECTION_REFUSED`（`connect` 被拒绝：端口无监听、UNIX 路径无监听端）、`CONNECTION_RESET`（已建立连接被重置）、`NOT_CONNECTED`（尚未连接或本端已 `shutdown` 该方向）。其余 socket 错误复用既有码：请求结构非法 → `BAD_REQUEST`；句柄/rights 不足 → `BAD_HANDLE`/`BAD_RIGHT`；缓冲区或地址指针不可写 → `BAD_POINTER`；非阻塞操作当前不能完成 → `WOULD_BLOCK`；对端全部关闭 → `PEER_CLOSED`；地址/端口冲突 → `BUSY`、路径已存在 → `EXISTS`；socket 实现尚未交付 → `NOT_SUPPORTED`。**原生状态码不得直接暴露 Linux errno 数值**（如 refused 不得返回 111、reset 不得返回 104）：Linux 人格在 M7d 的 compat 层单独映射。

约定：

- 错误码只增不改；同一编号的含义在 0.x 阶段也视为冻结。
- 不允许用 `OK` + 空结果伪装"未实现"；未实现的调用返回 `NOT_SUPPORTED`（或按第 1 节不存在的调用号触发内核诊断）。
- `NO_ENTROPY` 与 `WOULD_BLOCK` 是"M4 下可被程序当作正常答案"的两种非成功状态，参见第 6.5、6.3 节。

## 5. 句柄与权限

### 5.1 编码

句柄是 32 位不透明值，内核编码为：

```text
handle = (generation << 16) | (slot + 1)
```

- `slot`：进程句柄表中的 0 基下标；
- `generation`：该表项的代次，从 1 开始，表项复用时递增；
- 因此 `handle == 0` 永远无效（`HANDLE_NONE`），`0x0001_0001` 是代次 1、槽 0 的第一个句柄，`0x0001_0002` 是代次 1、槽 1。

用户程序：

- 只允许把句柄当作不透明值保存与传递，不得自行拼装或推测含义；
- 收到已关闭/代次过期的句柄时按 `BAD_HANDLE` 处理，不得假定槽位复用后指向同一对象；
- 测试代码需要构造固定值时使用 `native_abi::handle(generation, slot)`。

### 5.2 进程局部性

- 句柄只在所属进程的句柄表内有效；同一对象在不同进程可以有不同句柄值。
- 句柄不会隐式继承：`process_create` 只把请求中列出的句柄复制给子进程，其余句柄（含调用者的全部其它能力）在子进程中不可见、不可用，访问时返回 `BAD_HANDLE`。
- 该规则是 M4 的核心安全验收点：子进程必须无法通过固定句柄值访问父进程的 Random 能力。

### 5.3 rights 位

| 位 | 名称 | 值 | 含义 |
|---|---|---|---|
| 0 | `READ` | 1 | 读取内容（如 `random_read`） |
| 1 | `WRITE` | 2 | 写入内容（如 `write` 到控制台） |
| 2 | `WAIT` | 4 | 等待对象状态变化（如 `process_wait`） |
| 3 | `DUPLICATE` | 8 | 允许在 `process_create` 中把该句柄再传给第三方 |
| 4 | `MAP` | 16 | 允许把该对象（共享内存）映射进当前进程（0.4 引入） |

规则：

- 传递只能保留或缩减权限，不能提权：子进程得到的 rights 必须是调用者在该句柄上的 rights 的非空子集，否则 `BAD_RIGHT`。
- 句柄表项同时记录 rights；调用系统调用时按所需 rights 检查，缺失返回 `BAD_RIGHT`。
- `handle_close` 只关闭调用者的表项，不影响子进程持有的副本；对象销毁由引用计数在最后一个句柄关闭后决定。

### 5.4 节点类型、打开标志与 stat 标志（0.2）

`stat`/`readdir` 报告的节点类型（`kind`）：

| 值 | 名称 | 含义 |
|---:|---|---|
| 1 | `NODE_FILE` | 普通文件 |
| 2 | `NODE_DIRECTORY` | 目录 |

`open` 的 `flags` 位（其余位在 0.2 为保留位，置位返回 `BAD_REQUEST`）：

| 位 | 名称 | 值 | 含义 |
|---|---|---:|---|
| 0 | `OPEN_READ` | 1 | 允许读 |
| 1 | `OPEN_WRITE` | 2 | 允许写 |
| 2 | `OPEN_CREATE` | 4 | 目标不存在时创建 |
| 3 | `OPEN_TRUNC` | 8 | 打开后把文件截断为 0（仅对可写文件有效） |
| 4 | `OPEN_DIRECTORY` | 16 | 必须以目录打开；不是目录返回 `NOT_DIR` |

- `flags & (READ|WRITE) == 0` 返回 `BAD_REQUEST`；只读文件系统上的写打开返回 `READ_ONLY`。
- **`OPEN_READ` 与 `OPEN_WRITE` 完全独立，任何一方都不隐含另一方**：既不"写隐含读"，也不"读隐含写"。需要同时读写的调用者必须同时置位（例如先写后读同一句柄、或要对某句柄 `dup(..., RIGHT_READ)`）；只置 `OPEN_WRITE` 的句柄没有 `RIGHT_READ`，对其实施 `read` 或带 `RIGHT_READ` 的 `dup` 一律返回 `BAD_RIGHT`，而不是被内核悄悄放行。
- `stat` 的 `flags` 位：位 0 = `STAT_FLAG_READ_ONLY`，表示该节点不可写（例如启动模块）。
- 0.2 没有"文件描述符编号"概念，`dup` 复制的是句柄表项并共享**同一个**打开描述（偏移与截断状态共享）；`dup` 的 `rights` 必须是原句柄 rights 的子集，否则 `BAD_RIGHT`。

## 6. 系统调用

### 6.0 `abi_query`（0）

```text
abi_query() -> status = OK, result = (major << 16) | minor
```

- 0.1 返回 `(0 << 16) | 1 = 1`。
- 无错误码。内核不得让该调用阻塞；早期启动阶段即可用。
- 程序应把它作为 ABI 存在性与版本的第一步校验（M4 init 在版本不符时以非零状态退出）。

### 6.1 `write`（1）

```text
write(handle: Handle, buffer: user_ptr, len: u64) -> status, result = 已写字节数
```

- `handle` 需要 `WRITE`：M4 为控制台能力（启动时传给 init/child 的 Console 句柄）。
- 内核从用户 `buffer` 复制 `len` 字节到内核缓冲后写出；M4 控制台写入是完整写入，`result == len`。
- 错误：`BAD_HANDLE`、`BAD_RIGHT`、`BAD_POINTER`（含 `len` 过大导致 `buffer + len` 溢出）。
- 不允许内核在复制前信任 `len`；`buffer + len` 必须做溢出检查。
- M4 用户程序的所有可见输出都必须经该调用，不允许直接写串口端口。

### 6.2 `process_create`（2）

```text
process_create(request: user_ptr) -> status, result = 子进程 process 句柄
```

- `request` 指向第 7 节的 `ProcessCreateRequest`，由内核完整复制后校验。
- 模块名：`module_name` 为 NUL 填充的 16 字节；内核按"到第一个 0 为止"的有效长度匹配启动模块集合（M4 只有 `child`）。名字不存在返回 `NOT_FOUND`，为空返回 `BAD_REQUEST`。
- 句柄传递：`handles[0..handle_count]` 顺序即子进程的初始句柄顺序。内核为每个 `source` 在子进程句柄表中创建新表项，rights 取 `rights` 字段；调用者自己的表项**保持不变**（复制语义，不是移动语义），因此 init 传完 Console 后仍可继续用它输出。
- **同一请求内 `source` 不得重复**：每个源句柄在 `handles[0..handle_count]` 中最多出现一次，重复出现返回 `BAD_REQUEST`。复制语义下同一对象会在子进程句柄表中产生两个表项，但只对应**一次**引用传递；两个表项先后关闭会把该对象的引用计数多减一次（提前释放）。`HANDLE_NONE`（`0`）不受此限：它不是有效句柄，按 `BAD_HANDLE` 报告。
- 子进程初始入口：第 1 个传递句柄放 `rdi`，第 2 个放 `rsi`，更后面的句柄只存在于句柄表中、不进入寄存器；不足两个时对应寄存器为 `0`。
- 子进程地址空间、栈与入口按第 8 节建立；子进程从 `_start` 开始执行，父进程在 `process_create` 返回后继续运行。
- 错误：`BAD_POINTER`、`BAD_REQUEST`（`size != 64`、`version` 不匹配、`reserved != 0`、`handle_count > 4`、名字非法、同一 `source` 重复）、`BAD_HANDLE`（`source` 无效）、`BAD_RIGHT`（rights 非法或超出调用者权限、缺少 `DUPLICATE`）、`NOT_FOUND`（模块名不存在）、`QUOTA`。
- `source`/`rights`/模块名任一不合法时整个调用失败，不产生半创建的子进程。

### 6.3 `process_wait`（3）

```text
process_wait(child: Handle) -> status = OK, result = 退出状态；或 status = WOULD_BLOCK
```

- `child` 需要 `WAIT` rights。
- **内核语义是严格非阻塞的**：子进程仍在运行时立即返回 `WOULD_BLOCK`，内核内部不睡眠、不阻塞、不让出调用线程。
- 子进程已退出时返回 `OK` 与退出状态（`process_exit` 传入的值，正常为 0）；同一子进程可重复查询，退出状态保持有效直到句柄关闭。
- 错误：`BAD_HANDLE`、`BAD_RIGHT`、`NOT_FOUND`（不是子进程或已回收）。
- 由于内核不阻塞，用户运行库（`libs/native-rt::wait`）负责重试循环：

```rust
loop {
    match process_wait(child) {
        Ok(status) => return Ok(status),
        Err(ERR_WOULD_BLOCK) => pause(),
        Err(other) => return Err(other),
    }
}
```

`pause` 是 `pause` 指令，不关中断；循环期间定时器中断仍可抢占本进程，因此这既不忙等死循环，也不占用内核等待队列。M4 不做等待队列/timerfd，阻塞式等待属后续阶段。

### 6.4 `process_exit`（4）

```text
process_exit(status: u64) -> 不返回
```

- 终止当前进程，`status` 成为父进程 `process_wait` 观察到的退出状态；0 表示成功。
- 该调用不返回；若内核错误地返回，用户运行库执行 `ud2` 视为致命错误。
- 进程退出时其全部句柄表项自动关闭，引用计数相应递减；子进程不因父进程退出而被隐式杀死（M4 无孤儿移交，仅要求不悬空）。

### 6.5 `random_read`（5）

```text
random_read(handle: Handle, buffer: user_ptr, len: u64) -> status, result = 已写字节数
```

- `handle` 需要 `READ`：M4 的 Random 能力。
- CRNG 未就绪（M4 早期启动即是此状态）时，**不得返回伪造随机数**，必须返回 `NO_ENTROPY`，且不写用户缓冲区。
- CRNG 就绪时填充 `len` 字节并返回 `OK`、`result == len`。
- 错误：`BAD_HANDLE`、`BAD_RIGHT`、`BAD_POINTER`、`NO_ENTROPY`。
- 安全用途（ASLR 种子、密钥、`AT_RANDOM`）在 `NO_ENTROPY` 时必须失败或阻塞到就绪，不得降级为非密码学随机（见总体设计 9.5 节）。
- M4 init 把 `NO_ENTROPY` 当作预期答案（打印 `rng OK`），这验证的是"三态随机源"的状态而不是随机数质量。

### 6.6 `handle_close`（6）

```text
handle_close(handle: Handle) -> status = OK
```

- 关闭调用者句柄表中的表项；重复关闭或传入无效值返回 `BAD_HANDLE`。
- 关闭不影响其他进程/子进程持有的副本。
- 错误：`BAD_HANDLE`。

### 6.7 `open`（7）

```text
open(request: user_ptr) -> status, result = 文件/目录句柄
```

- `request` 指向第 7.3 节的 `OpenRequest`；内核 copy-in 快照后解析路径。
- 路径必须是绝对路径，由 VFS 逐组件解析；父目录不存在返回 `NOT_FOUND`，中间组件不是目录返回 `NOT_DIR`。
- `CREATE` 只在目标不存在时创建文件；未带 `CREATE` 而目标不存在返回 `NOT_FOUND`；目标已存在且未要求截断时正常打开（`CREATE` 不因已存在而报错，除非与 `DIRECTORY` 期望冲突）。
- `TRUNC` 必须与 `WRITE` 同时出现，否则 `BAD_REQUEST`；截断发生在打开成功后。
- `DIRECTORY` 要求目标是目录：目标存在但不是目录返回 `NOT_DIR`。
- 权限：新句柄的 rights 由内核按 flags 推导（`READ`→`RIGHT_READ`，`WRITE`→`RIGHT_WRITE`），不引入额外 rights 参数；两个方向的映射互相独立、互不隐含（见第 5.4 节）。
- 错误：`BAD_POINTER`（请求或路径不可读、`path_len` 非法/溢出）、`BAD_REQUEST`（`size`/`version`/`reserved`/非法 flags）、`NOT_FOUND`、`NOT_DIR`、`IS_DIR`（未带 `DIRECTORY` 却打开目录；0.2 允许显式 `DIRECTORY` 打开）、`EXISTS`、`READ_ONLY`、`NO_SPACE`、`IO`、`CORRUPT`、`QUOTA`。

### 6.8 `read`（8）

```text
read(handle: Handle, buffer: user_ptr, len: u64) -> status, result = 读取字节数
```

- 需要 `RIGHT_READ`；从当前文件偏移读取，成功后偏移前进 `result`。
- 到文件末尾返回 `OK` 且 `result == 0`（不是错误）。
- 目录句柄返回 `IS_DIR`；`len` 为 0 时返回 `OK` 且不触碰缓冲区。
- 错误：`BAD_HANDLE`、`BAD_RIGHT`、`BAD_POINTER`、`IS_DIR`、`IO`、`TIMEOUT`、`CORRUPT`。

### 6.9 `stat`（9）

```text
stat(handle: Handle, out: user_ptr) -> status
```

- 把第 7.4 节的 `StatOut` 写入用户缓冲区；`out.size` 必须等于 32、`out.version` 必须为 1（由调用者预填）。
- 任一字段与内部记录不一致时以内部记录为准（大小从目录项/索引节点读取）。
- 错误：`BAD_HANDLE`、`BAD_POINTER`、`BAD_REQUEST`（`size`/`version` 不符）、`IO`、`CORRUPT`。

### 6.10 `readdir`（10）

```text
readdir(handle: Handle, index: u64, out: user_ptr) -> status
```

- 需要 `RIGHT_READ`，句柄必须以 `DIRECTORY` 打开；按目录内部顺序取第 `index` 个项目写入第 7.5 节的 `DirEntryOut`。
- 跳过 `.`、`..`、卷标与长文件名（LFN）辅助项——用户只看到真实节点项。
- `index` 超出末尾返回 `NOT_FOUND`（枚举终止条件，不是 I/O 错误）。
- `out.size` 必须等于 56、`out.version` 必须为 1。
- 错误：`BAD_HANDLE`、`BAD_RIGHT`、`BAD_POINTER`、`BAD_REQUEST`、`NOT_DIR`、`NOT_FOUND`、`IO`、`CORRUPT`。

### 6.11 `mkdir`（11）

```text
mkdir(path: user_ptr, path_len: u64) -> status
```

- 创建单个目录（不创建中间组件）；父目录必须存在，否则 `NOT_FOUND`；父不是目录返回 `NOT_DIR`。
- 目标已存在返回 `EXISTS`；只读文件系统返回 `READ_ONLY`；空间不足返回 `NO_SPACE`。
- 错误：`BAD_POINTER`、`BAD_REQUEST`（空路径/相对路径）、`NOT_FOUND`、`NOT_DIR`、`EXISTS`、`READ_ONLY`、`NO_SPACE`、`IO`、`CORRUPT`。

### 6.12 `rmdir`（12）

```text
rmdir(path: user_ptr, path_len: u64) -> status
```

- 目标必须是目录且为空；非空返回 `NOT_EMPTY`；目标不是目录返回 `NOT_DIR`；不存在返回 `NOT_FOUND`。
- 该目录仍被其它句柄引用时内核可以返回 `BUSY`（0.2 允许 `NOT_EMPTY` 与 `BUSY` 之一，二者都表示"当前不能删除"）。
- 错误：`BAD_POINTER`、`BAD_REQUEST`、`NOT_FOUND`、`NOT_DIR`、`NOT_EMPTY`、`BUSY`、`READ_ONLY`、`IO`、`CORRUPT`。

### 6.13 `unlink`（13）

```text
unlink(path: user_ptr, path_len: u64) -> status
```

- 删除普通文件；目标是目录返回 `IS_DIR`（删除目录必须用 `rmdir`）；不存在返回 `NOT_FOUND`。
- 已被打开的文件可以删除（最后一个句柄关闭后空间释放），这点与 0.2 的句柄引用计数一致。
- 错误：`BAD_POINTER`、`BAD_REQUEST`、`NOT_FOUND`、`IS_DIR`、`READ_ONLY`、`BUSY`、`IO`、`CORRUPT`。

### 6.14 `rename`（14）

```text
rename(request: user_ptr) -> status
```

- `request` 指向第 7.6 节的 `RenameRequest`；把 `old_path` 重命名/移动到 `new_path`。
- 两个路径必须位于同一挂载点，否则 `CROSS_DEVICE`；不在同一目录时执行移动。
- 目标已存在返回 `EXISTS`（0.2 不做替换语义）。
- 把目录移动到自身子树内返回 `BAD_REQUEST`；源不存在返回 `NOT_FOUND`；父目录非法返回 `NOT_DIR`。
- 错误：`BAD_POINTER`、`BAD_REQUEST`、`NOT_FOUND`、`NOT_DIR`、`EXISTS`、`CROSS_DEVICE`、`READ_ONLY`、`NO_SPACE`、`IO`、`CORRUPT`。

### 6.15 `sync`（15）

```text
sync(handle: Handle) -> status
```

- 需要 `RIGHT_WRITE`（只有写过数据才可能需要写回）；把该打开描述的脏数据提交到下层块设备并等待完成。
- 内核不得只把数据留在页缓存里就返回成功；块设备错误必须传播为 `IO`/`TIMEOUT`/`CORRUPT`。
- 错误：`BAD_HANDLE`、`BAD_RIGHT`、`IO`、`TIMEOUT`、`CORRUPT`。

### 6.16 `seek`（16）

```text
seek(handle: Handle, offset: i64, whence: u32) -> status, result = 新偏移
```

- `whence`：`0 = SET`（绝对）、`1 = CUR`（相对当前）、`2 = END`（相对文件大小）；非法值返回 `BAD_REQUEST`。
- 计算出的偏移为负或超过文件系统的表示上限时返回 `BAD_REQUEST`/`TOO_LARGE`，且不改变当前偏移。
- `seek` 允许越过文件末尾，超出部分在下次写入时补零（稀疏语义由阶段内实现决定，0.2 只保证读回为零）。
- 错误：`BAD_HANDLE`、`BAD_REQUEST`、`TOO_LARGE`、`IS_DIR`、`IO`。

### 6.17 `dup`（17）

```text
dup(handle: Handle, rights: u32) -> status, result = 新句柄
```

- 复制句柄表项并**共享同一个打开描述**：两个句柄共享文件偏移与截断状态，但各有独立 rights。
- `rights` 必须是原句柄 rights 的非空子集，否则 `BAD_RIGHT`；原句柄不受影响。
- 新句柄的代次由内核分配，不复用原值；`dup` 不要求 `DUPLICATE` rights（那是 `process_create` 传递第三方所需的权限）。
- 错误：`BAD_HANDLE`、`BAD_RIGHT`、`QUOTA`。

### 6.18 `truncate`（26）

```text
truncate(handle: Handle, len: u64) -> status
```

- 需要 `RIGHT_WRITE`；把文件截断（缩小）或扩展（补零）到 `len`，并更新目录项/索引节点记录的大小。
- 目录句柄返回 `IS_DIR`；`len` 超过文件系统表示上限返回 `TOO_LARGE`；只读节点返回 `READ_ONLY`。
- 错误：`BAD_HANDLE`、`BAD_RIGHT`、`IS_DIR`、`TOO_LARGE`、`READ_ONLY`、`NO_SPACE`、`IO`、`CORRUPT`。

### 6.19 `mmap`（18）

```text
mmap(file: Handle, request: *const MmapRequest) -> status, result = 映射对象句柄
```

- `file` 需要 `RIGHT_READ`；当 `request.flags == MMAP_SHARED` 且 `request.prot` 含 `PROT_WRITE` 时还需要 `RIGHT_WRITE`，否则 `BAD_RIGHT`。只读文件（如 `/boot` 挂载下的启动模块）永远不能得到可写映射。
- `request` 必须是可读的 [`MmapRequest`](#77-mmaprequestmmap-的请求)（`size` = 48、`version` = 1），否则 `BAD_REQUEST`；`out_address` 必须指向调用者的一段可写 8 字节，否则 `BAD_POINTER`。
- 成功时内核把映射基地址写入 `out_address` 指向的 `u64`，并通过结果寄存器 `rdx` 返回一个新的**映射对象句柄**。该句柄只用于生命周期管理（关闭即解除映射），不参与文件 I/O，也不能传给子进程。
- 映射是**急切**的：调用返回时整段已经建立，M5c2 没有按需缺页路径，也不会因为后续访问而扩展文件。
- `len` 与 `offset` 必须非零且页对齐（4 KiB），`len` ≤ 256 KiB，`offset + len` 不得越过文件末尾；否则 `BAD_REQUEST`。映射不隐式扩展文件，调用前应先用 `stat` 确认大小。
- `prot` 只支持 `PROT_READ` 与 `PROT_READ|PROT_WRITE`；含 `PROT_EXEC`（无论是否与 `PROT_WRITE` 同置）一律 `NOT_SUPPORTED`，W^X 组合 `PROT_WRITE|PROT_EXEC` 也不得被静默接受；含未定义位返回 `BAD_REQUEST`。
- `flags` 必须恰好是 `MMAP_SHARED` 或 `MMAP_PRIVATE` 之一，其它组合（含两者同时置位、0）返回 `BAD_REQUEST`。
- **shared** 映射直接反映页缓存：写入使页变脏。**只有文件句柄上的 `sync`（或显式缓存回写/写回调用）才保证脏页落到下层存储**；解除映射（`munmap` 或关闭映射句柄）与进程退出只把脏页标记为待回写并解除页固定（mark dirty + unpin），**不做隐式 flush**，因此在 `sync` 之前掉电或复位可能丢失这些写入；同一文件的其他 shared 映射与 `read` 在页缓存层面立即看到一致内容。
- **private** 映射是 `mmap` 时刻的快照（急切复制）：写入只对当前进程可见，不回写文件，也不影响 shared 映射。
- 错误：`BAD_HANDLE`、`BAD_RIGHT`、`BAD_REQUEST`、`BAD_POINTER`、`NOT_SUPPORTED`、`NO_SPACE`、`QUOTA`、`TOO_LARGE`、`IO`。

### 6.20 `munmap`（19）

```text
munmap(address: u64, len: u64) -> status
```

- `address` 与 `len` 必须页对齐且非零，且必须精确覆盖一个仍然存在的映射（M5c2 不支持部分解除或拆分映射），否则 `BAD_REQUEST`。
- 成功时解除该映射并**关闭对应的映射句柄**（`munmap` 与 `handle_close` 对映射句柄等价）；之后再 `munmap` 同一范围返回 `NOT_FOUND`（范围已不存在）或 `BAD_REQUEST`（范围未知）。
- shared 映射的脏页在解除时**不**隐式回写：只标记为脏并解除映射（unpin），落盘仍由文件句柄上的 `sync` 或显式回写负责；private 映射的内容直接丢弃。
- 不需要 rights：映射句柄本身不可 I/O，调用者用地址表达范围。
- 错误：`BAD_REQUEST`、`NOT_FOUND`、`IO`。

### 6.21 `mprotect`（20）

```text
mprotect(address: u64, len: u64, prot: u32) -> status
```

- 只允许在 `PROT_READ` 与 `PROT_READ|PROT_WRITE` 之间切换；`prot` 含 `PROT_EXEC` 返回 `NOT_SUPPORTED`，含未定义位或 0 返回 `BAD_REQUEST`。
- `address`/`len` 必须页对齐非零，且范围必须完整落在一个仍存在的映射内，否则 `BAD_REQUEST`/`NOT_FOUND`。
- 权限变化不影响内容：private 页上的未回写修改在降为只读再恢复可写后仍然保留。
- 错误：`BAD_REQUEST`、`NOT_FOUND`、`NOT_SUPPORTED`。

### 6.22 `lock`（21）

```text
lock(handle: Handle, request: *const LockRequest) -> status
```

- `request` 必须是可读的 [`LockRequest`](#78-lockrequestlock-的请求)（`size` = 32、`version` = 1），否则 `BAD_REQUEST`。
- 三个**互不冲突**的锁域：`LOCK_DOMAIN_POSIX`（1，按进程所有，同进程任意句柄重入不冲突）、`LOCK_DOMAIN_OFD`（2，绑定打开文件描述，`dup` 共享同一描述因此不冲突，不同 `open` 冲突）、`LOCK_DOMAIN_FLOCK`（3，整文件，独立于前两者）。域或操作值未定义返回 `BAD_REQUEST`。
- 操作：`LOCK_OP_SHARED` / `LOCK_OP_EXCLUSIVE` / `LOCK_OP_UNLOCK`。
- rights：`SHARED` 需要句柄有 `RIGHT_READ`，`EXCLUSIVE` 需要 `RIGHT_WRITE`，`UNLOCK` 需要二者之一，否则 `BAD_RIGHT`。
- **非阻塞**：冲突时立即返回 `WOULD_BLOCK`，不睡眠、不排队、不做部分加锁。
- 范围：POSIX/OFD 中 `len = 0` 表示"到文件末尾"；`flock` 只接受 `offset = 0, len = 0`，其它参数返回 `BAD_REQUEST`。锁不隐式扩展文件。
- 释放：`UNLOCK` 覆盖范围内的锁、关闭该打开描述上最后一个引用、关闭该文件上的任一句柄（POSIX 域按进程语义）、进程退出都会被内核释放。`flock` 随打开描述关闭释放。
- 错误：`BAD_HANDLE`、`BAD_RIGHT`、`BAD_REQUEST`、`WOULD_BLOCK`、`NOT_SUPPORTED`、`IO`、`CORRUPT`。

### 6.23 `xattr_set`（22）

```text
xattr_set(handle: Handle, request: *const XattrRequest) -> status
```

- 需要句柄有 `RIGHT_WRITE`，否则 `BAD_RIGHT`；`request` 必须是可读的 [`XattrRequest`](#79-xattrrequestxattr_setxattr_get-的请求)（`size` = 40、`version` = 1），否则 `BAD_REQUEST`。
- 名字必须以 `user.` 开头；其它命名空间返回 `NOT_SUPPORTED`（不静默截断、不降级）。`name_len` 超出 1..=16 或名字含 NUL 返回 `BAD_REQUEST`。
- `value_len` 超过 64 返回 `TOO_LARGE`；值从用户内存复制进来（copy-in），之后调用者缓冲区可复用。
- 每文件 `user.*` 属性数量有配额（M5c3 实现允许两个）：超出返回 `QUOTA`。同名属性覆盖旧值，不占新配额。
- 属性在 M5c3 中是**易失**的：只存在于该挂载实例的内存状态，重启后不保留；不要求跨启动一致，也不写入 FAT/ext2 磁盘格式。
- 文件系统不支持属性时返回 `NOT_SUPPORTED`。
- 错误：`BAD_HANDLE`、`BAD_RIGHT`、`BAD_REQUEST`、`BAD_POINTER`、`NOT_SUPPORTED`、`QUOTA`、`TOO_LARGE`、`IO`、`CORRUPT`。

### 6.24 `xattr_get`（23）

```text
xattr_get(handle: Handle, request: *const XattrRequest) -> status, result = 属性实际字节长度
```

- 需要句柄有 `RIGHT_READ`，否则 `BAD_RIGHT`；请求头校验同 `xattr_set`。
- `value_ptr`/`value_len` 描述**输出缓冲区**；成功时写入 `min(value_len, 实际长度)` 字节并在 `rdx` 返回实际长度。
- 缓冲区不足时返回 `TOO_LARGE`，且**不得部分写入**（缓冲区保持调用前内容）。
- 名字不存在返回 `NOT_FOUND`；非 `user.*` 返回 `NOT_SUPPORTED`；名字/长度非法返回 `BAD_REQUEST`。
- 错误：`BAD_HANDLE`、`BAD_RIGHT`、`BAD_REQUEST`、`BAD_POINTER`、`NOT_FOUND`、`NOT_SUPPORTED`、`TOO_LARGE`、`IO`、`CORRUPT`。

### 6.25 `watch`（24）

```text
watch(path_ptr: u64, path_len: u64) -> status, result = Watch 句柄
```

- 路径按 `open` 的同一套绝对路径规则解析，必须指向一个目录，否则 `NOT_DIR`/`NOT_FOUND`；参数非法返回 `BAD_POINTER`/`BAD_REQUEST`。
- 成功返回一个新的 Watch 句柄（`rdx`）。Watch 句柄只用于 `watch_drain`，不能用于文件 I/O，也不能传给子进程。
- 订阅绑定**目录身份**而不是路径：目录被 rename 后事件继续有效；目录被删除后该 watch 进入静默（drain 返回 0 事件）。
- 事件种类：`WATCH_EVENT_CREATED`（1）、`WATCH_EVENT_DELETED`（2）、`WATCH_EVENT_RENAMED`（3，携带新名字）。
- 队列有界：溢出时丢弃最旧事件并累加该 watch 的 `dropped` 计数，调用者可通过事件里的 `dropped` 观察丢失。
- 关闭 Watch 句柄即停止订阅并丢弃未取事件；进程退出时内核必须回收全部 watch（不得泄漏）。
- 错误：`BAD_POINTER`、`BAD_REQUEST`、`NOT_FOUND`、`NOT_DIR`、`IO`、`NOT_SUPPORTED`。

### 6.26 `watch_drain`（25）

```text
watch_drain(watch: Handle, request: *const WatchDrainRequest) -> status, result = 事件数
```

- `request` 必须是可读的 [`WatchDrainRequest`](#711-watchdrainrequestwatch_drain-的请求)（`size` = 24、`version` = 1），`max_events` 在 1..=16，否则 `BAD_REQUEST`。
- `events_ptr` 必须指向 `max_events × 48` 字节的可写用户内存，否则 `BAD_POINTER`。
- 按产生顺序取走至多 `max_events` 个事件（先进先出），返回实际写入数量（0 表示当前无事件，仍为成功）。
- 每个 [`WatchEventOut`](#710-watcheventoutwatch_drain-的事件) 的 `name` 为 NUL 填充的目录项名字，`dropped` 为该 watch 累计溢出数。
- Watch 句柄无效返回 `BAD_HANDLE`；对非 Watch 句柄调用返回 `BAD_HANDLE` 或 `BAD_RIGHT`。
- 错误：`BAD_HANDLE`、`BAD_RIGHT`、`BAD_REQUEST`、`BAD_POINTER`、`IO`。

### 6.27 `ipc_create`（27）

```text
ipc_create(request: *const IpcCreateRequest) -> status, result = 新对象句柄（rdx）
```

- `request` 必须是可读的 [`IpcCreateRequest`](#712-ipccreaterequestipc_create-的请求)（`size` = 32、`version` = 1），否则 `BAD_POINTER` / `BAD_REQUEST`。
- `kind` 取 `IPC_KIND_EVENT`(1)、`EVENT_PAIR`(2)、`TIMER`(6) 时创建成功；其余冻结种类（3/4/5/7）在本切片返回 `NOT_SUPPORTED`，未知数值返回 `BAD_REQUEST`。
- `flags`：仅 Event 允许 `EVENT_FLAG_MANUAL_RESET`(1)；EventPair/Timer 必须为 0；未定义位返回 `BAD_REQUEST`。
- `arg0`/`arg1` 在本切片必须为 0（预留；非 0 返回 `BAD_REQUEST`）。
- 成功时新句柄进入调用者句柄表并获得该对象种类的完整 rights，返回在 `rdx`；句柄关闭或进程退出时内核回收对象。
- 错误：`BAD_POINTER`、`BAD_REQUEST`、`QUOTA`、`NOT_SUPPORTED`。

### 6.28 `ipc_signal`（28）

```text
ipc_signal(object: Handle, operation: u32, endpoint: u32) -> status
```

- `rdi` = 句柄，`rsi` = `SIGNAL_OP_RESET`(0) 或 `SIGNAL_OP_SIGNAL`(1)，`rdx` = `endpoint`（仅 EventPair 使用；Event/Timer 必须为 0）。该调用的 `rdx` 是输入，不返回结果值。
- Event：
  - `SIGNAL` 置位。auto-reset（无 `MANUAL_RESET`）的置位被下一次**成功**的 `wait` 消费；manual-reset 的置位保持，直到显式 `RESET`。
  - `RESET` 清除置位；对 auto-reset 对象无副作用。
- EventPair：`endpoint` 取 `EVENT_PAIR_ENDPOINT_A`(0)/`B`(1)。对端点 X 执行 `SIGNAL` 使**对端 Y** 的等待就绪（一次性锁存，被一次成功的 `wait` 消费）；`RESET` 清除该锁存。`endpoint` 越界返回 `BAD_REQUEST`。
- Timer：本切片 Timer 只通过 `timer_arm` 就绪，`ipc_signal` 返回 `NOT_SUPPORTED`。
- 对端销毁：EventPair 一端的所有句柄都已关闭后，对另一端的 `wait` 在就绪时报告 `PEER_CLOSED`（见 6.29），不得永久阻塞。
- 错误：`BAD_HANDLE`、`BAD_RIGHT`、`BAD_REQUEST`、`NOT_SUPPORTED`。

### 6.29 `wait`（29）

```text
wait(request: *const WaitRequest) -> status, result = 就绪数量（rdx）
```

- `request` 必须是可读的 [`WaitRequest`](#713-waitrequestwait-的请求)（`size` = 96、`version` = 1），`count` 在 1..=`WAIT_MAX_ITEMS`(4)，`flags` 与每项 `flags` 必须为 0，`out_ptr` 必须指向至少 16 字节的可写用户内存（[`WaitOut`](#714-waitoutwait-的输出)）。
- 每项 `handle` 的低 32 位是句柄、高 32 位必须为 0；持有该句柄需具备 `RIGHT_WAIT`，否则 `BAD_RIGHT`；`key` 对 EventPair 必须为 0/1，对 Event/Timer 必须为 0，否则 `BAD_REQUEST`。
- `timeout_ticks`：`WAIT_TIMEOUT_IMMEDIATE`(0) 表示不阻塞、无就绪对象时返回 `WOULD_BLOCK`；`WAIT_TIMEOUT_INFINITE`(0xFFFF_FFFF) 表示无限等待；其它值为调度 tick（100 Hz）上限。
- 返回值：
  - 有就绪项：`OK`，`rdx` = 就绪数量，`WaitOut.ready_mask` 的 bit i 对应 `items[i]`（至少一位）、`wake_reason` = `WAKE_READY`、`ready_key` = 首个就绪项的 `key`。**只有本次就绪的项**被消费：auto-reset Event 的置位、EventPair 的锁存在此清除；未就绪项不受影响。
  - 超时：`TIMEOUT`，`rdx` = 0，`wake_reason` = `WAKE_TIMEOUT`，不消费任何对象状态。
  - 对端销毁：`OK`，对应项 bit 置位且 `wake_reason` = `WAKE_PEER_CLOSED`；该句柄本身的有效性仍按 `BAD_HANDLE` 检查。
- 重放语义：内核不修改调用者的 `WaitRequest`；`WOULD_BLOCK`/`TIMEOUT` 返回后可直接用同一请求再次 `wait`；`OK` 返回后剩下的未就绪项同样可以重放。
- 本切片一次成功的 `wait` 只报告单个就绪项，但 `ready_mask` 的位定义已冻结，允许后续实现一次返回多项；`wake_reason` 的取值是冻结集合（见 `native-abi`）。
- 错误：`BAD_POINTER`、`BAD_REQUEST`、`BAD_HANDLE`、`BAD_RIGHT`、`WOULD_BLOCK`、`TIMEOUT`、`CANCELLED`（冻结）。

### 6.30 `timer_arm`（33）

```text
timer_arm(timer: Handle, ticks: u32, flags: u32) -> status
```

- `rdi` = Timer 句柄，`rsi` = 相对调度 tick 数，`rdx` = `flags` 必须为 0。
- 一次性：到期后 Timer 变为就绪一次，被一次成功的 `wait` 消费；再次 `arm` 覆盖尚未到期的装载；`ticks` = 0 返回 `BAD_REQUEST`。
- 错误：`BAD_HANDLE`、`BAD_RIGHT`、`BAD_REQUEST`、`NOT_SUPPORTED`。

### 6.31 `ipc_create`（27，0.4 扩展）

```text
ipc_create(request: *const IpcCreateRequest) -> status; rdx = handle（Channel/Port 另有第二句柄）
```

- `rdi` = `IpcCreateRequest` 指针（40 字节，见 §7.12）；`kind` 决定对象类型：
  - Event（1）：`flags` bit0 = `EVENT_FLAG_MANUAL_RESET`；`arg0`/`arg1` 必须为 0。
  - EventPair（2）：`arg0`/`arg1` 必须为 0，`rdx` 返回端点 A 的句柄，`out_second_ptr` 收到端点 B。
  - Channel（3）：`arg0` = 建议队列容量（0 表示使用内核默认值，内核可上调/下调并以实际值为准，用户不得依赖精确容量）；`rdx` = A 端，`out_second_ptr` = B 端。
  - Port（4）：同 Channel，`rdx` = 接收端、`out_second_ptr` = 发送端。
  - SharedMemory（5）：`arg0` = 字节长度（页对齐、上限由内核能力决定，`0` 或非对齐返回 `BAD_REQUEST`），`out_second_ptr` 忽略。
  - Timer（6）：`arg0`/`arg1` 必须为 0，创建后未装载。
  - Subscription（7）：`arg0`/`arg1` 必须为 0，创建后无 interest。
- `out_second_ptr`：`kind` 需要两个句柄时（Channel/Port）必须是非零且可写 8 字节；其它 `kind` 必须为 0。第二句柄与 `rdx` 返回的句柄属于同一对象的两端，权限由内核按端点语义裁剪（见 §5.3）。
- 一条消息的内联数据上限 `IPC_DATA_MAX` = 64 字节、随附句柄上限 `IPC_HANDLES_MAX` = 2；共享内存是跨进程大块数据的唯一推荐路径。
- 错误：`BAD_POINTER`、`BAD_REQUEST`、`QUOTA`、`NOT_SUPPORTED`（未知 `kind`）。

### 6.32 `ipc_send`（30）

```text
ipc_send(channel: Handle, request: *const IpcSendRequest) -> status; rdx = 接受的数据字节数（= data_len）
```

- `rdi` = Channel/Port 的发送端句柄，`rsi` = `IpcSendRequest` 指针（64 字节，见 §7.15）。
- 发送是拷贝：内核在返回前把 `data_ptr[0..data_len]` 与句柄/rights 数组复制走，调用者可以立刻复用缓冲区。成功时 `rdx` 恒等于本次接受的内联负载长度 `data_len`，不暴露队列序号/消息 id 等内部状态；失败时 `rdx` 无意义。
- `data_len ≤ IPC_DATA_MAX`；`handle_count ≤ IPC_HANDLES_MAX`，每个被传句柄必须是调用者句柄表内的有效句柄且请求的 rights 是其现有 rights 的子集（否则 `BAD_RIGHT`），并扣减一次引用所有权（发送方若还要用必须自行 `dup`）。
- 队列满时返回 `WOULD_BLOCK` 且不消费任何数据/句柄；`handle_count`/`data_len` 越界返回 `BAD_REQUEST`（不得截断）。
- 本次发送携带的句柄不得与发送端句柄指向同一个对象（即消息所携对象 == 本次调用的 `rdi` 所指 Channel/Port 端点对象）：该情形返回 `BAD_REQUEST`。这是 0.4 的受控限制，不表示通用禁止句柄传递；需要端点自传时由后续 ABI 扩展定义。
- 错误：`BAD_POINTER`、`BAD_REQUEST`、`BAD_HANDLE`、`BAD_RIGHT`、`WOULD_BLOCK`、`PEER_CLOSED`、`IO`（Port 接收端已销毁但发送端仍持有的实现相关路径）。

### 6.33 `ipc_recv`（31）

```text
ipc_recv(channel: Handle, request: *const IpcReceiveRequest) -> status; rdx = 收到的数据字节数
```

- `rdi` = Channel/Port 的接收端句柄，`rsi` = `IpcReceiveRequest` 指针（64 字节，见 §7.16）。
- 数据与句柄分别拷出到 `data_ptr`、`out_handles_ptr`/`out_rights_ptr`；`data_capacity`/`handle_capacity` 都足够时才消费消息，否则：
  - 数据不足：返回 `TOO_LARGE` **且不消费消息**（用户可用更大的 `data_capacity` 重试）；
  - 句柄容量不足：返回 `QUOTA`/`TOO_LARGE` 且不消费消息。
- `out_meta_ptr` 可为零（不取元数据）；非零时必须可写 32 字节 `IpcMessageMeta`（见 §7.17），用于暴露 protocol/version/transaction/句柄数/发送方 pid。
- `timeout_ticks`：`WAIT_TIMEOUT_IMMEDIATE`(0) 无消息时返回 `WOULD_BLOCK`；`WAIT_TIMEOUT_INFINITE` 无限等待；其它值为 tick 上限，超时返回 `TIMEOUT`。
- 消息按 FIFO 顺序交付；channel 的对端全部关闭且队列已空时返回 `PEER_CLOSED`。
- 错误：`BAD_POINTER`、`BAD_REQUEST`、`BAD_HANDLE`、`BAD_RIGHT`、`TOO_LARGE`、`QUOTA`、`WOULD_BLOCK`、`TIMEOUT`、`PEER_CLOSED`。

### 6.34 `shm_map`（32）

```text
shm_map(shm: Handle, request: *const ShmMapRequest) -> status; rdx = 映射句柄
```

- `rdi` = SharedMemory 句柄（需要 `RIGHT_MAP`），`rsi` = `ShmMapRequest` 指针（32 字节，见 §7.18）。
- 急切映射整个对象；`prot` 至少含 `PROT_READ`，可含 `PROT_WRITE`（要求句柄有 `RIGHT_WRITE`）；`PROT_EXEC` 返回 `NOT_SUPPORTED`。
- 成功后把用户地址写入 `out_address`，`rdx` 返回映射句柄。同一对象可被映射多次（每次地址不同、互为别名）；映射句柄只用于 `munmap`/`mprotect`，不能当文件句柄做 I/O，也不能传给子进程。
- 关闭映射句柄即解除该次映射；关闭共享内存对象句柄不影响已有映射的存活（映射持有对象引用）。
- 错误：`BAD_POINTER`、`BAD_REQUEST`、`BAD_HANDLE`、`BAD_RIGHT`、`NOT_SUPPORTED`、`QUOTA`。

### 6.35 `subscribe`（34）

```text
subscribe(subscription: Handle, request: *const SubscribeRequest) -> status; rdx = 添加的 interest 数
```

- `rdi` = Subscription 句柄，`rsi` = `SubscribeRequest` 指针（24 字节，见 §7.19）。
- `entries_ptr` 指向 `count` 个 16 字节 `SubscriptionEntry`（§7.20）：`handle` 是被等待对象、`mode` = `SUBSCRIPTION_MODE_LEVEL`(1)/`EDGE`(2)、`key` 作为事件里回传的标识（EventPair 用端点号，其它对象用 0）。
- 同一订阅内 `(handle, mode, key)` 重复 registration 返回 `EXISTS`；`count` 为 0 返回 `BAD_REQUEST`；条目数受 `SUBSCRIBE_MAX_ENTRIES`/对象配额限制，超出返回 `QUOTA`。
- 订阅对象本身可被 `wait` 等待：只要任一 interest 的目标就绪，订阅就处于 ready 状态（LT/ET 只影响 `subscription_read` 的事件消费语义，见 §6.39）。
- 错误：`BAD_POINTER`、`BAD_REQUEST`、`BAD_HANDLE`、`BAD_RIGHT`、`EXISTS`、`QUOTA`。

### 6.36 `unsubscribe`（35）

```text
unsubscribe(subscription: Handle, target: Handle) -> status; rdx = 移除的 interest 数
```

- 移除该订阅中所有 target 句柄对应的 interest（不区分 mode/key）；不存在时返回成功的 0。
- 被观察对象本身不受影响；订阅对象若已无 interest 则不再因该对象就绪。
- 错误：`BAD_HANDLE`、`BAD_RIGHT`。

### 6.37 `futex_wait`（37）

```text
futex_wait(address: *const u32, expected: u32, timeout_ticks: u64) -> status
```

- `rdi` = 4 字节对齐的用户地址（映射在共享内存上才具有跨进程意义），`rsi` = 期望值，`rdx` = `WAIT_TIMEOUT_IMMEDIATE`(0)/`WAIT_TIMEOUT_INFINITE`(0xFFFF_FFFF)/其它 tick 上限。
- **首次进入**时若 `*address != expected`，立即返回 `WOULD_BLOCK`（不睡眠）；相等则阻塞。
- 被 `futex_wake` 唤醒后返回 `OK`——**允许 spurious wake**（即使此时值仍等于 expected，甚至已被改成别的值）；调用者必须自行重读并循环判断。
- 超时返回 `TIMEOUT`；地址不可读/非对齐返回 `BAD_POINTER`（不得视为"值不匹配"）。
- 同一地址的多个等待者由内核维护，唤醒顺序不作承诺；`futex_wait` 不消费内存内容、不修改用户内存。
- 错误：`BAD_POINTER`、`WOULD_BLOCK`、`TIMEOUT`。

### 6.38 `futex_wake`（38）

```text
futex_wake(address: *const u32, max: u32) -> status; rdx = 实际唤醒数
```

- 唤醒至多 `max` 个在该地址上阻塞的等待者；`max` = 0 视为无操作并返回 0。
- 返回值 `rdx` = 实际唤醒数（可能少于请求数）；不修改用户内存。
- 错误：`BAD_POINTER`。

### 6.39 `subscription_read`（39）

```text
subscription_read(subscription: Handle, request: *const SubscriptionReadRequest) -> status; rdx = 事件数
```

- `rdi` = Subscription 句柄，`rsi` = `SubscriptionReadRequest` 指针（24 字节，见 §7.21）。
- 每次最多返回 `max_events`（1..=`SUBSCRIPTION_EVENTS_MAX`=16）个 `SubscriptionEvent`（16 字节：`object_key` u64 + `mode` u32 + reserved u32）。
- `object_key` 编码冻结为 `(object_raw << 32) | key`：高 32 位为目标对象的原始 ObjectId（用户不可解释、只能比较相等），低 32 位为 registration 时的 key。
- LT（level）语义：只要目标仍处于就绪状态，重复读会继续返回事件；ET（edge）语义：一次就绪只产生一次事件，重复读返回 0，直到目标再次发生状态变化。
- 无事件时返回 `OK` 且 `rdx` = 0（不是 `WOULD_BLOCK`）。
- 错误：`BAD_POINTER`、`BAD_REQUEST`、`BAD_HANDLE`、`BAD_RIGHT`。

### 6.40 `display_info`（40）

```text
display_info(display: Handle, request: *const DisplayInfoRequest) -> status
```

- `rdi` = Display 句柄（需 `READ`），`rsi` = `DisplayInfoRequest` 指针（24 字节，见 §7.22）。
- 成功时把 `DisplayInfoWire`（32 字节，见 §7.23）写入请求的 `out_info_ptr`；输出描述的是 **RAM shadow** 而不是 framebuffer：`shadow_bytes` 是本帧按像素打包后的精确字节数（M6c 为 `320 × 200 × 4 = 256000`）。
- `pixel_format` 沿用 UEFI GOP 枚举（0 RGBX、1 BGRX、2 bit mask、3 blt only）；`stride` 是每行像素数（不是字节数），且 `stride ≥ width`。
- shadow 是普通映射内存：内核不得把 framebuffer 物理地址或 MMIO 窗口暴露给用户，用户只能经 `display_map` 得到 shadow 的映射。
- 错误：`BAD_HANDLE`、`BAD_RIGHT`、`BAD_POINTER`、`BAD_REQUEST`、`NOT_SUPPORTED`（内核未提供显示对象）。

### 6.41 `display_map`（41）

```text
display_map(display: Handle, request: *const ShmMapRequest) -> status; rdx = 映射句柄
```

- `DisplayMapRequest` **就是** `ShmMapRequest`（32 字节，见 §7.18），本调用不新增布局；参数语义与 `shm_map`（§6.34）一致。
- `rdi` = Display 句柄（需 `MAP` + `READ`，要写 shadow 还需 `WRITE`），`rsi` = 请求，`rdx` = 新映射句柄；映射基址由内核写入 `out_address`。
- 映射整块 shadow（`shadow_bytes`，按页向上取整），急切建立；同一 Display 对象多次映射得到不同用户地址且互为别名。
- `prot` 必须含 `PROT_READ`、可含 `PROT_WRITE`、不得含 `PROT_EXEC`（返回 `NOT_SUPPORTED`）。写 shadow 只改 RAM，不触碰 framebuffer；只有 `display_present` 才提交。
- 映射句柄不是 I/O 句柄：不能用于 `read`/`write`/`mmap`，也不能传给子进程；关闭映射句柄即解除映射。
- 错误：`BAD_HANDLE`、`BAD_RIGHT`、`BAD_POINTER`、`BAD_REQUEST`、`NOT_SUPPORTED`。

### 6.42 `display_present`（42）

```text
display_present(display: Handle, request: *const DisplayPresentRequest) -> status
```

- `rdi` = Display 句柄（需 `WRITE`），`rsi` = `DisplayPresentRequest`（24 字节，见 §7.24）。
- M6c 只接受**全屏**矩形：`x = 0`、`y = 0`、`w = DISPLAY_WIDTH(320)`、`h = DISPLAY_HEIGHT(200)`；其它子矩形返回 `NOT_SUPPORTED`（留给后续切片），越界矩形返回 `BAD_REQUEST`。
- 语义：把 shadow 中该矩形的像素按行拷到 framebuffer（行 pitch 用 `display_info` 返回的 `stride`），返回时提交完成；M6c 不提供异步 fence/垂直同步对象。
- 错误：`BAD_HANDLE`、`BAD_RIGHT`、`BAD_POINTER`、`BAD_REQUEST`、`NOT_SUPPORTED`。

### 6.43 `input_read`（43）

```text
input_read(input: Handle, request: *const InputReadRequest) -> status; rdx = 事件数
```

- `rdi` = Input 句柄（需 `READ`），`rsi` = `InputReadRequest`（24 字节，见 §7.25），`max_events` 在 1..=`INPUT_EVENTS_MAX`(16)。
- **非阻塞**：队列为空立即返回 `OK` 且 `rdx = 0`；需要阻塞时先 `wait` 该 Input 句柄（§6.29），醒来后再读。
- 事件按产生顺序 FIFO 出队，一次最多拷出 `max_events` 个 `InputEventWire`（24 字节，见 §7.26）；`rdx` = 实际事件数。
- `sequence` 从 1 起单调递增，不因多次 `input_read` 重置；`timestamp_ms` 单调非降。内核若因队列满丢弃事件，必须通过累计丢弃计数暴露、不得静默跳号：M6c 用例中读到 `sequence = 1..5` 连续即证明无丢弃。
- `kind`：`INPUT_EVENT_KIND_KEYBOARD`(1)、`INPUT_EVENT_KIND_SERIAL`(2)。Keyboard 的 `code` 是扫描码（bit7 为释放位，例如 `0x20` 按下、`0xA0` 释放）；Serial 的 `code` 是收到的字节值。
- 事件队列绑定 Input 对象生命周期：关闭最后一个句柄后队列销毁，正在 `wait` 的线程以 `PEER_CLOSED` 醒来。
- 错误：`BAD_HANDLE`、`BAD_RIGHT`、`BAD_POINTER`、`BAD_REQUEST`、`NOT_SUPPORTED`。

### 6.44 `socket`（44）

`rdi = *const SocketCreateRequest`（该调用**没有输入句柄**，请求指针放 `rdi`，与 `process_create`/`ipc_create` 的单请求惯例一致；`rsi` 未使用，置 0）；成功 `rdx` = 新 socket 句柄（`READ | WRITE`）。

- `domain` ∈ `SOCKET_DOMAIN_UNIX`(1) / `_INET`(2) / `_INET6`(10)；`kind` ∈ `SOCKET_KIND_STREAM`(1) / `_DGRAM`(2)。
- `protocol`、`flags` 在 0.6 必须为 0；非 0 返回 `BAD_REQUEST`（不静默映射到 Linux 选项）。
- `namespace_handle`：UNIX **命名** socket 必须给出有效 NetworkNamespace 句柄；INET/INET6 与匿名 socket 该字段必须为 `HANDLE_NONE`。网络命名空间对象本身随 M7 内核交付，在此之前 socket 调用返回 `NOT_SUPPORTED`。
- 失败：`BAD_POINTER`/`BAD_REQUEST`/`BAD_RIGHT`/`QUOTA`/`NOT_SUPPORTED`。

### 6.45 `bind`（45）

`rdi` = socket 句柄（需 `WRITE`），`rsi = *const SocketAddrRequest`；`addr_len` 必须为 `SOCKET_ADDR_WIRE`（144），地址由 `addr_ptr` 处的 `SocketAddrWire` 提供；成功 `rdx = 0`。

- `SocketAddrWire.family` 必须与 socket 的 domain 对应，`path_len ≤ 107`；UNIX 的 `addr`/`port` 必须为 0，IP 的 `path_len` 必须为 0。
- INET/INET6 的本地地址 `port = 0` 表示请求内核分配一个**非零临时端口**：bind 成功后实际分配结果通过 `socket_address` 查询（`which = SOCKET_ADDR_LOCAL`）；分配不到可用端口时按 `QUOTA`/`BUSY` 返回。`port = 0` 不等于绑定 0 号端口，也不改变下一行“非零端口冲突 → `BUSY`”的规则；UNIX 不适用临时端口语义（其 `port` 必须为 0）。该临时端口语义仅适用于 `bind` 的本地地址，`connect` 的远端地址不按临时端口处理。
- 端口/路径被占用 → `BUSY`/`EXISTS`；无 netns 授权的命名 socket → `BAD_RIGHT`；对已 bind 的 socket 再次 bind → `BAD_REQUEST`。

### 6.46 `listen`（46）

`rdi` = stream socket 句柄，`rsi` = backlog（1..=64）；无请求结构；成功 `rdx = 0`。

- 非 `SOCKET_KIND_STREAM` 或 backlog 越界 → `BAD_REQUEST`；未 bind 的 INET socket 允许隐式绑定临时端口（UNIX 不允许）。

### 6.47 `accept`（47）

`rdi` = 监听 socket 句柄（需 `READ`，建议同时持 `WAIT`），`rsi = *const SocketAcceptRequest`；成功 `rdx` = 新连接句柄（`READ | WRITE`），并写入 `out_handle_ptr`（`out_handle_ptr = 0` → `BAD_POINTER`）。

- 非阻塞：无可接受连接 → `WOULD_BLOCK`，调用方应 `wait` 该 socket 后重试；0.6 的 socket 不内嵌 accept 超时。
- 监听 socket 已 `shutdown`/对端消失 → 相应地返回 `NOT_CONNECTED`/`PEER_CLOSED`；未监听 → `BAD_REQUEST`。

### 6.48 `connect`（48）

`rdi` = socket 句柄（需 `WRITE`），`rsi = *const SocketAddrRequest`；成功 `rdx = 0`。

- 非阻塞：连接进行中 → `WOULD_BLOCK`（调用方 `wait` 后重试 `connect` 或查询 `socket_address`）；被拒绝 → `CONNECTION_REFUSED`；被重置 → `CONNECTION_RESET`；`shutdown` 后 → `NOT_CONNECTED`。
- datagram socket 的 `connect` 只设置默认对端并立即成功；对已连接的 stream socket 再次 `connect` → `BAD_REQUEST`。
- UNIX 路径目标不存在 → `NOT_FOUND`；路径存在但没有监听 socket → `CONNECTION_REFUSED`（两者不得混同，也不得映射成 Linux errno）。

### 6.49 `send`（49）

`rdi` = socket 句柄（需 `WRITE`），`rsi = *const SocketSendRequest`；成功 `rdx` = 接受字节数（≤ `data_len`，stream 允许部分写）。

- 队列满 → `WOULD_BLOCK` 且不消费数据；未连接（stream）→ `NOT_CONNECTED`；对端已关闭 → `PEER_CLOSED`；本端已 `shutdown(WRITE)` → `NOT_CONNECTED`。
- `data_len = 0` 是合法空消息（datagram 会排入一个零长报文）。

### 6.50 `recv`（50）

`rdi` = socket 句柄（需 `READ`），`rsi = *const SocketRecvRequest`；成功 `rdx` = 收到字节数。

- 非阻塞：队列空 → `WOULD_BLOCK`（`rdx` 无意义）；`rdx = 0` 只表示收到一个零长 datagram（stream 不会返回 0，除非长度参数为 0）。
- `out_source_ptr` 非 0 时写入源 `SocketAddrWire`（datagram 源地址 / stream 对端地址）；为 0 则不写。
- 容量不足：datagram 返回 `TOO_LARGE` 且**不消费**该报文；stream 允许部分读。`out_source_ptr` 不可写 → `BAD_POINTER`。

### 6.51 `shutdown`（51）

`rdi` = socket 句柄，`rsi` = how：`SOCKET_SHUTDOWN_READ`(0) / `_WRITE`(1) / `_BOTH`(2)；成功 `rdx = 0`。

- 其它 how → `BAD_REQUEST`；重复 `shutdown` 幂等（返回成功）；未连接 socket 的 `shutdown` 允许但只置本地状态；对已 `shutdown` 方向再 `send`/`recv` 分别返回 `NOT_CONNECTED`。

### 6.52 `socketpair`（52）

`rdi = *const SocketPairRequest`（**没有输入句柄**，请求指针放 `rdi`；`rsi` 未使用，置 0）；成功 `rdx = 0`，两个 u32 raw handle 写入 `out_handles_ptr`（两端均为 `READ | WRITE | WAIT`）。

- 0.6 只支持 `SOCKET_DOMAIN_UNIX` + STREAM/DGRAM；其它 domain → `BAD_REQUEST`。`out_handles_ptr = 0` → `BAD_POINTER`。
- 失败必须**全回滚**：不得只创建一个端点或泄漏半个句柄。socketpair 不经过网络命名空间。

### 6.53 `socket_address`（53）

`rdi` = socket 句柄（需 `READ`），`rsi = *const SocketAddressRequest`；成功 `rdx = 0` 并写入 `out_addr_ptr` 处的 `SocketAddrWire`。

- `which` ∈ `SOCKET_ADDR_LOCAL`(0) / `_PEER`(1)，其它 → `BAD_REQUEST`；本地地址未绑定 → 返回 `family = 0` 的空地址（不是错误）；未连接时查对端 → `NOT_CONNECTED`。

## 7. 请求结构

### 7.1 `HandleTransfer`

| 偏移 | 大小 | 字段 | 说明 |
|---:|---:|---|---|
| 0 | 4 | `source` | 调用者句柄表中的句柄 |
| 4 | 4 | `rights` | 传给子进程的权限位（子集，非空） |

```c
typedef struct { uint32_t source; uint32_t rights; } HandleTransfer; // size 8, align 4
```

- 同一 `ProcessCreateRequest` 中 `source` 必须两两不同（`HANDLE_NONE` 除外）；内核在 copy-in 完成后、解析任何句柄之前查重，重复即 `BAD_REQUEST`。该约束使"每个表项对应一次引用传递"保持一一对应，避免子进程关闭两个表项时把同一引用减两次。

### 7.2 `ProcessCreateRequest`

| 偏移 | 大小 | 字段 | 校验 |
|---:|---:|---|---|
| 0 | 4 | `size` | 必须等于 64 |
| 4 | 4 | `version` | 必须等于 `REQUEST_VERSION`（0.2 起为 1；0.1 曾等于 `ABI_VERSION`，数值同为 1） |
| 8 | 16 | `module_name` | NUL 填充；有效长度 = 到第一个 0；不得为空 |
| 24 | 4 | `handle_count` | 0..=4 |
| 28 | 4 | `reserved` | 必须为 0 |
| 32 | 32 | `handles[4]` | 每项 `HandleTransfer`，只读前 `handle_count` 项 |

```c
typedef struct {
    uint32_t size;            // 64
    uint32_t version;         // 1 (布局版本 REQUEST_VERSION，与 ABI 版本独立)
    uint8_t  module_name[16]; // NUL padded
    uint32_t handle_count;    // <= 4
    uint32_t reserved;        // 0
    HandleTransfer handles[4];
} ProcessCreateRequest;      // size 64, align 4
```

布局约束：全部小端、`repr(C)` 等价布局、无隐式填充（字段偏移如上表，`size_of` 必须为 64）。`libs/native-abi` 的宿主测试校验这些偏移与大小，布局变化视为 ABI 破坏。

### 7.3 `OpenRequest`（`open` 的请求）

| 偏移 | 大小 | 字段 | 校验 |
|---:|---:|---|---|
| 0 | 4 | `size` | 必须等于 32 |
| 4 | 4 | `version` | 必须等于 1 |
| 8 | 8 | `path_ptr` | 用户绝对路径指针 |
| 16 | 4 | `path_len` | 字节长度，1..=4096 |
| 20 | 4 | `flags` | 第 5.4 节的 `OPEN_*` 位；保留位必须为 0 |
| 24 | 8 | `reserved` | 必须为 0 |

```c
typedef struct {
    uint32_t size;      // 32
    uint32_t version;   // 1
    uint64_t path_ptr;
    uint32_t path_len;
    uint32_t flags;
    uint64_t reserved;  // 0
} OpenRequest;          // size 32, align 8
```

### 7.4 `StatOut`（`stat` 的输出）

| 偏移 | 大小 | 字段 | 说明 |
|---:|---:|---|---|
| 0 | 4 | `size` | 必须等于 32 |
| 4 | 4 | `version` | 必须等于 1 |
| 8 | 4 | `kind` | `NODE_FILE` / `NODE_DIRECTORY` |
| 12 | 4 | `flags` | 位 0 = `STAT_FLAG_READ_ONLY` |
| 16 | 8 | `file_size` | 文件字节数；目录为 0 |
| 24 | 8 | `reserved` | 内核写 0 |

```c
typedef struct {
    uint32_t size;       // 32
    uint32_t version;    // 1
    uint32_t kind;
    uint32_t flags;
    uint64_t file_size;
    uint64_t reserved;   // 0
} StatOut;               // size 32, align 8
```

### 7.5 `DirEntryOut`（`readdir` 的输出）

| 偏移 | 大小 | 字段 | 说明 |
|---:|---:|---|---|
| 0 | 4 | `size` | 必须等于 56 |
| 4 | 4 | `version` | 必须等于 1 |
| 8 | 4 | `kind` | `NODE_FILE` / `NODE_DIRECTORY` |
| 12 | 4 | `name_len` | 有效名长度 1..=32 |
| 16 | 32 | `name` | 非 NUL 结尾；`name[..name_len]` 有效，其余由内核写 0 |
| 48 | 8 | `file_size` | 文件字节数；目录为 0 |

```c
typedef struct {
    uint32_t size;        // 56
    uint32_t version;     // 1
    uint32_t kind;
    uint32_t name_len;
    uint8_t  name[32];
    uint64_t file_size;
} DirEntryOut;            // size 56, align 8
```

- 0.2 只保证短文件名（FAT32 的 8.3 名）与 ext2 的原始字节名；FAT32 上的大小写由文件系统决定，调用者比较名字时应做 ASCII 大小写不敏感处理。

### 7.6 `RenameRequest`（`rename` 的请求）

| 偏移 | 大小 | 字段 | 校验 |
|---:|---:|---|---|
| 0 | 4 | `size` | 必须等于 40 |
| 4 | 4 | `version` | 必须等于 1 |
| 8 | 8 | `old_ptr` | 原路径指针 |
| 16 | 4 | `old_len` | 1..=4096 |
| 20 | 4 | `new_len` | 1..=4096 |
| 24 | 8 | `new_ptr` | 新路径指针 |
| 32 | 8 | `reserved` | 必须为 0 |

```c
typedef struct {
    uint32_t size;      // 40
    uint32_t version;   // 1
    uint64_t old_ptr;
    uint32_t old_len;
    uint32_t new_len;
    uint64_t new_ptr;
    uint64_t reserved;  // 0
} RenameRequest;        // size 40, align 8
```

### 7.7 `MmapRequest`（`mmap` 的请求）

| 偏移 | 大小 | 字段 | 说明 |
|---:|---:|---|---|
| 0 | 4 | `size` | 固定 48 |
| 4 | 4 | `version` | 固定 1（布局版本，独立于 ABI 版本） |
| 8 | 8 | `len` | 映射字节长度，页对齐、非零、≤ 256 KiB |
| 16 | 8 | `offset` | 文件内起始偏移，页对齐 |
| 24 | 4 | `prot` | `PROT_READ` / `PROT_WRITE`（`PROT_EXEC` 保留但被拒绝） |
| 28 | 4 | `flags` | 恰好 `MMAP_SHARED`（1）或 `MMAP_PRIVATE`（2）之一 |
| 32 | 8 | `out_address` | 用户指针：内核成功后把映射基地址（u64）写到这里 |
| 40 | 8 | `reserved` | 0 |

```c
typedef struct {
    uint32_t size;         // 48
    uint32_t version;      // 1
    uint64_t len;
    uint64_t offset;
    uint32_t prot;         // PROT_READ=1, PROT_WRITE=2, PROT_EXEC=4（拒绝）
    uint32_t flags;        // MMAP_SHARED=1, MMAP_PRIVATE=2
    uint64_t out_address;  // user pointer to a writable u64
    uint64_t reserved;     // 0
} MmapRequest;             // size 48, align 8
```

- `out_address` 只用于输出基地址，不是返回值寄存器；映射句柄仍由 `rdx` 返回。
- `libs/native-rt` 的 `mmap(file, &mut request)` 自动填 `size`/`version`/`out_address`，并把 `(映射句柄, 基地址)` 作为返回值交给调用者。
- 释放：`munmap`、关闭映射句柄或进程退出任一发生都会解除映射，并把 shared 脏页留在页缓存中标记为待回写（**不隐式 flush**）；`munmap` 与关闭句柄等价。需要保证落到下层存储时，必须对文件句柄调用 `sync` 或显式执行缓存回写。

### 7.8 `LockRequest`（`lock` 的请求）

| 偏移 | 大小 | 字段 | 说明 |
|---:|---:|---|---|
| 0 | 4 | `size` | 固定 32 |
| 4 | 4 | `version` | 固定 1（布局版本） |
| 8 | 4 | `domain` | `POSIX`=1 / `OFD`=2 / `FLOCK`=3 |
| 12 | 4 | `operation` | `SHARED`=1 / `EXCLUSIVE`=2 / `UNLOCK`=3 |
| 16 | 8 | `offset` | 起始字节偏移 |
| 24 | 8 | `len` | 锁定字节数，`0` = 到 EOF（POSIX/OFD）；`flock` 必须为 0 |

```c
typedef struct {
    uint32_t size;         // 32
    uint32_t version;      // 1
    uint32_t domain;       // LOCK_DOMAIN_POSIX=1, OFD=2, FLOCK=3
    uint32_t operation;    // LOCK_OP_SHARED=1, EXCLUSIVE=2, UNLOCK=3
    uint64_t offset;
    uint64_t len;          // 0 = to EOF (POSIX/OFD); flock requires 0
} LockRequest;             // size 32, align 8
```

- `libs/native-rt` 的 `lock(handle, &mut request)` 自动填 `size`/`version`，冲突映射为 `Ok`/`Err(WOULD_BLOCK)`，不重试、不睡眠。

### 7.9 `XattrRequest`（`xattr_set`/`xattr_get` 的请求）

| 偏移 | 大小 | 字段 | 说明 |
|---:|---:|---|---|
| 0 | 4 | `size` | 固定 40 |
| 4 | 4 | `version` | 固定 1 |
| 8 | 8 | `name_ptr` | 用户指针：属性名（`user.*`） |
| 16 | 8 | `name_len` | 名字字节数，1..=16 |
| 24 | 8 | `value_ptr` | 用户指针：值缓冲区 |
| 32 | 8 | `value_len` | `set` 为值长度（≤64）；`get` 为缓冲区容量 |

```c
typedef struct {
    uint32_t size;         // 40
    uint32_t version;      // 1
    uint64_t name_ptr;
    uint64_t name_len;     // 1..XATTR_NAME_MAX (16)
    uint64_t value_ptr;
    uint64_t value_len;    // set: <=XATTR_VALUE_MAX (64); get: buffer capacity
} XattrRequest;            // size 40, align 8
```

- `libs/native-rt` 的 `xattr_set` 返回 `Result<(), u64>`；`xattr_get` 返回 `Result<usize, u64>`（`rdx` 里的实际长度）。
- 属性是易失的（见 §6.23），只保证同一挂载实例内可见；不得据此实现需要跨启动持久的安全语义。

### 7.10 `WatchEventOut`（`watch_drain` 的事件）

| 偏移 | 大小 | 字段 | 说明 |
|---:|---:|---|---|
| 0 | 4 | `kind` | `WATCH_EVENT_CREATED`=1 / `DELETED`=2 / `RENAMED`=3 |
| 4 | 4 | `name_len` | `name` 中有效字节数 |
| 8 | 32 | `name` | 目录项名字，NUL 填充 |
| 40 | 8 | `dropped` | 该 watch 至今累计丢弃的事件数 |

```c
typedef struct {
    uint32_t kind;         // 1=created, 2=deleted, 3=renamed
    uint32_t name_len;     // significant bytes in name
    uint8_t  name[32];     // NUL padded
    uint64_t dropped;      // cumulative overflow count for this watch
} WatchEventOut;           // size 48, align 8
```

- `renamed` 事件携带**新名字**；旧名字不在同一事件里，调用者需要自己保存映射。
- `dropped` 是累计值而不是本次增量：调用者应用差值判断本次 drain 期间是否有丢失。

### 7.11 `WatchDrainRequest`（`watch_drain` 的请求）

| 偏移 | 大小 | 字段 | 说明 |
|---:|---:|---|---|
| 0 | 4 | `size` | 固定 24 |
| 4 | 4 | `version` | 固定 1 |
| 8 | 8 | `events_ptr` | 用户指针：`max_events` 个 `WatchEventOut` 输出数组 |
| 16 | 8 | `max_events` | 本次最多取走的事件数，1..=16 |

```c
typedef struct {
    uint32_t size;         // 24
    uint32_t version;      // 1
    uint64_t events_ptr;
    uint64_t max_events;   // 1..WATCH_MAX_BATCH (16)
} WatchDrainRequest;       // size 24, align 8
```

- `libs/native-rt` 的 `watch_drain(watch, &mut [WatchEventOut])` 自动填 `events_ptr`/`max_events`，返回实际事件数。
- 数组按事件产生顺序填充；队列为空时返回 0 且状态为 `OK`。

### 7.12 `IpcCreateRequest`（`ipc_create` 的请求）

| 偏移 | 大小 | 字段 | 说明 |
|---:|---:|---|---|
| 0 | 4 | `size` | 固定 32 |
| 4 | 4 | `version` | 固定 1 |
| 8 | 4 | `kind` | `IPC_KIND_EVENT`=1、`EVENT_PAIR`=2、`TIMER`=6（本切片）；3/4/5/7 冻结未实现 |
| 12 | 4 | `flags` | 仅 Event 允许 `EVENT_FLAG_MANUAL_RESET`(1)，其余必须 0 |
| 16 | 8 | `arg0` | 本切片必须 0（预留） |
| 24 | 8 | `arg1` | 本切片必须 0（预留） |

```c
typedef struct {
    uint32_t size;      // 32
    uint32_t version;   // 1
    uint32_t kind;
    uint32_t flags;
    uint64_t arg0;
    uint64_t arg1;
} IpcCreateRequest;     // size 32, align 8
```

- `libs/native-rt` 的 `ipc_create(&IpcCreateRequest)` / `ipc_create_kind(kind, flags, arg0, arg1)` 自动填 `size`/`version`，成功时返回新句柄。

### 7.13 `WaitRequest`（`wait` 的请求）

| 偏移 | 大小 | 字段 | 说明 |
|---:|---:|---|---|
| 0 | 4 | `size` | 固定 96 |
| 4 | 4 | `version` | 固定 1 |
| 8 | 4 | `flags` | 必须 0（预留） |
| 12 | 4 | `timeout_ticks` | 0=立即、0xFFFF_FFFF=无限，其余为调度 tick |
| 16 | 4 | `count` | 1..=`WAIT_MAX_ITEMS`(4) |
| 20 | 4 | `reserved` | 必须 0 |
| 24 | 8 | `out_ptr` | 用户指针：1 个 `WaitOut`（16 字节输出） |
| 32 | 64 | `items[4]` | 每项 16 字节，见下 |

```c
typedef struct {
    uint64_t handle;    // 低 32 位句柄，高 32 位必须 0
    uint32_t flags;     // 必须 0
    uint32_t key;       // EventPair 端点 0/1；Event/Timer 必须 0
} WaitItem;             // size 16, align 8

typedef struct {
    uint32_t size;          // 96
    uint32_t version;       // 1
    uint32_t flags;         // 0
    uint32_t timeout_ticks; // 0 = immediate, UINT32_MAX = infinite
    uint32_t count;         // 1..=4
    uint32_t reserved;      // 0
    uint64_t out_ptr;       // -> WaitOut
    WaitItem items[4];
} WaitRequest;              // size 96, align 8
```

- `libs/native-rt` 的 `wait_objects(&mut WaitRequest, &mut WaitOut)` 自动填 `size`/`version`/`out_ptr` 并返回就绪数量；`wait_one(object, key, timeout_ticks)` 是单对象封装。为避免与 0.1 的 `wait(child)`（`process_wait` 别名）重名，`wait_objects` 是统一等待的公开入口。

### 7.14 `WaitOut`（`wait` 的输出）

| 偏移 | 大小 | 字段 | 说明 |
|---:|---:|---|---|
| 0 | 4 | `ready_mask` | bit i 对应 `WaitRequest.items[i]` |
| 4 | 4 | `wake_reason` | `WAKE_NONE`=0、`READY`=1、`TIMEOUT`=2、`DESTROYED`=3、`CANCELLED`=4、`PEER_CLOSED`=5 |
| 8 | 4 | `ready_key` | 首个就绪项的 `key` |
| 12 | 4 | `reserved` | 0 |

```c
typedef struct {
    uint32_t ready_mask;
    uint32_t wake_reason;
    uint32_t ready_key;
    uint32_t reserved;
} WaitOut;              // size 16, align 4
```

- `native-rt::WaitOut::is_ready(i)` 只是 `ready_mask & (1 << i)` 的便捷判断；`wake_reason` 取值集合冻结，本切片只会产生 `READY`/`TIMEOUT`/`PEER_CLOSED`。

### 7.15 `IpcSendRequest`（`ipc_send` 的请求，0.4）

| 偏移 | 大小 | 字段 | 校验 |
|---:|---:|---|---|
| 0 | 4 | `size` | 必须等于 64 |
| 4 | 4 | `version` | 必须等于 `REQUEST_VERSION`（1） |
| 8 | 4 | `protocol` | 调用者自定义协议号（原样回传给接收方） |
| 12 | 4 | `msg_version` | 调用者自定义消息版本（原样回传） |
| 16 | 8 | `transaction` | 调用者自定义事务号（原样回传） |
| 24 | 8 | `data_ptr` | 内联数据用户地址；`data_len > 0` 时必须非零 |
| 32 | 4 | `data_len` | ≤ `IPC_DATA_MAX`（64） |
| 36 | 4 | `handle_count` | ≤ `IPC_HANDLES_MAX`（2） |
| 40 | 8 | `handles_ptr` | `handle_count` 个 `uint32` 句柄 |
| 48 | 8 | `rights_ptr` | `handle_count` 个 `uint32` rights（各自非空子集） |
| 56 | 8 | `reserved` | 0 |

```c
typedef struct {
    uint32_t size, version, protocol, msg_version;
    uint64_t transaction;
    uint64_t data_ptr;
    uint32_t data_len, handle_count;
    uint64_t handles_ptr, rights_ptr, reserved;
} IpcSendRequest;       // size 64, align 8
```

### 7.16 `IpcReceiveRequest`（`ipc_recv` 的请求，0.4）

| 偏移 | 大小 | 字段 | 校验 |
|---:|---:|---|---|
| 0 | 4 | `size` | 必须等于 64 |
| 4 | 4 | `version` | 必须等于 `REQUEST_VERSION`（1） |
| 8 | 8 | `data_ptr` | `data_capacity > 0` 时必须可写 |
| 16 | 4 | `data_capacity` | 数据缓冲容量（字节） |
| 20 | 4 | `handle_capacity` | 句柄数组容量（最多 `IPC_HANDLES_MAX`） |
| 24 | 8 | `out_handles_ptr` | `handle_capacity` 个 `uint32` 的输出地址；可为 0 |
| 32 | 8 | `out_rights_ptr` | 同上，rights 输出；可为 0 |
| 40 | 8 | `out_meta_ptr` | 可写 32 字节 `IpcMessageMeta` 的地址；可为 0 |
| 48 | 8 | `timeout_ticks` | `WAIT_TIMEOUT_*` 语义，按 tick 计 |
| 56 | 8 | `reserved` | 0 |

```c
typedef struct {
    uint32_t size, version;
    uint64_t data_ptr;
    uint32_t data_capacity, handle_capacity;
    uint64_t out_handles_ptr, out_rights_ptr, out_meta_ptr, timeout_ticks;
    uint64_t reserved;
} IpcReceiveRequest;   // size 64, align 8
```

### 7.17 `IpcMessageMeta`（`ipc_recv` 的输出，0.4）

| 偏移 | 大小 | 字段 | 说明 |
|---:|---:|---|---|
| 0 | 4 | `protocol` | 发送方填写的协议号 |
| 4 | 4 | `version` | 发送方填写的消息版本 |
| 8 | 8 | `transaction` | 发送方填写的事务号 |
| 16 | 4 | `data_len` | 本条消息实际数据长度 |
| 20 | 4 | `handle_count` | 随附句柄数 |
| 24 | 4 | `sender_pid` | 发送方进程 id（内核填写） |
| 28 | 4 | `reserved` | 0 |

```c
typedef struct {
    uint32_t protocol, version;
    uint64_t transaction;
    uint32_t data_len, handle_count, sender_pid, reserved;
} IpcMessageMeta;       // size 32, align 8
```

### 7.18 `ShmMapRequest`（`shm_map` 与 `display_map` 的请求，0.4/0.5）

| 偏移 | 大小 | 字段 | 校验 |
|---:|---:|---|---|
| 0 | 4 | `size` | 必须等于 32 |
| 4 | 4 | `version` | 必须等于 `REQUEST_VERSION`（1） |
| 8 | 4 | `prot` | `PROT_*` 组合，必须含 `READ`、可含 `WRITE`，不得含 `EXEC` |
| 12 | 4 | `reserved` | 0 |
| 16 | 8 | `out_address` | 可写 8 字节的用户地址（内核写入映射基址） |
| 24 | 8 | `reserved_high` | 0 |

```c
typedef struct {
    uint32_t size, version, prot, reserved;
    uint64_t out_address, reserved_high;
} ShmMapRequest;        // size 32, align 8
```

### 7.19 `SubscribeRequest`（`subscribe` 的请求，0.4）

| 偏移 | 大小 | 字段 | 校验 |
|---:|---:|---|---|
| 0 | 4 | `size` | 必须等于 24 |
| 4 | 4 | `version` | 必须等于 `REQUEST_VERSION`（1） |
| 8 | 4 | `count` | 1..=`SUBSCRIBE_MAX_ENTRIES`（4） |
| 12 | 4 | `reserved` | 0 |
| 16 | 8 | `entries_ptr` | `count` 个 16 字节 `SubscriptionEntry` |

```c
typedef struct {
    uint32_t size, version, count, reserved;
    uint64_t entries_ptr;
} SubscribeRequest;     // size 24, align 8
```

### 7.20 `SubscriptionEntry` / `SubscriptionEvent`（0.4）

```c
typedef struct { uint32_t handle; uint32_t mode; uint64_t key; } SubscriptionEntry; // size 16, align 8
typedef struct { uint64_t object_key; uint32_t mode; uint32_t reserved; } SubscriptionEvent; // size 16, align 8
```

- `mode` = `SUBSCRIPTION_MODE_LEVEL`(1) / `SUBSCRIPTION_MODE_EDGE`(2)。
- `SubscriptionEvent.object_key` = `(object_raw << 32) | key`（§6.39）；`native-abi` 提供 `subscription_object_key/object_raw/key` 便于编解码。

### 7.21 `SubscriptionReadRequest`（`subscription_read` 的请求，0.4）

| 偏移 | 大小 | 字段 | 校验 |
|---:|---:|---|---|
| 0 | 4 | `size` | 必须等于 24 |
| 4 | 4 | `version` | 必须等于 `REQUEST_VERSION`（1） |
| 8 | 4 | `max_events` | 1..=`SUBSCRIPTION_EVENTS_MAX`（16） |
| 12 | 4 | `reserved` | 0 |
| 16 | 8 | `out_events_ptr` | 可写 `max_events × 16` 字节的地址 |

```c
typedef struct {
    uint32_t size, version, max_events, reserved;
    uint64_t out_events_ptr;
} SubscriptionReadRequest;  // size 24, align 8
```

### 7.22 `DisplayInfoRequest`（`display_info` 的请求，0.5）

| 偏移 | 大小 | 字段 | 校验 |
|---:|---:|---|---|
| 0 | 4 | `size` | 必须等于 24 |
| 4 | 4 | `version` | 必须等于 `REQUEST_VERSION`（1） |
| 8 | 8 | `out_info_ptr` | 可写 32 字节 `DisplayInfoWire` 的用户地址 |
| 16 | 8 | `reserved` | 0 |

```c
typedef struct {
    uint32_t size, version;
    uint64_t out_info_ptr, reserved;
} DisplayInfoRequest;   // size 24, align 8
```

### 7.23 `DisplayInfoWire`（`display_info` 的输出，0.5）

| 偏移 | 大小 | 字段 | 说明 |
|---:|---:|---|---|
| 0 | 4 | `width` | shadow 宽（像素） |
| 4 | 4 | `height` | shadow 高（像素） |
| 8 | 4 | `stride` | 每行像素数（非字节数） |
| 12 | 4 | `pixel_format` | UEFI GOP 枚举：0 RGBX、1 BGRX、2 bit mask、3 blt only |
| 16 | 8 | `shadow_bytes` | RAM shadow 字节数（M6c 为 256000） |
| 24 | 8 | `reserved` | 0 |

```c
typedef struct {
    uint32_t width, height, stride, pixel_format;
    uint64_t shadow_bytes, reserved;
} DisplayInfoWire;      // size 32, align 8
```

像素在 shadow 中按 `pixel_format` 的小端 32 位字存放：`0` 的内存字节序为 R,G,B,X，`1` 为 B,G,R,X。`stride` 只描述 shadow 行距，framebuffer 行距由内核在 present 时按其自身 pitch 处理。

### 7.24 `DisplayPresentRequest`（`display_present` 的请求，0.5）

| 偏移 | 大小 | 字段 | 校验 |
|---:|---:|---|---|
| 0 | 4 | `size` | 必须等于 24 |
| 4 | 4 | `version` | 必须等于 `REQUEST_VERSION`（1） |
| 8 | 4 | `x` | 必须为 0（M6c 仅全屏） |
| 12 | 4 | `y` | 必须为 0（M6c 仅全屏） |
| 16 | 4 | `w` | 必须等于 `DISPLAY_WIDTH`（320） |
| 20 | 4 | `h` | 必须等于 `DISPLAY_HEIGHT`（200） |

```c
typedef struct {
    uint32_t size, version, x, y, w, h;
} DisplayPresentRequest;    // size 24, align 4
```

### 7.25 `InputReadRequest`（`input_read` 的请求，0.5）

| 偏移 | 大小 | 字段 | 校验 |
|---:|---:|---|---|
| 0 | 4 | `size` | 必须等于 24 |
| 4 | 4 | `version` | 必须等于 `REQUEST_VERSION`（1） |
| 8 | 4 | `max_events` | 1..=`INPUT_EVENTS_MAX`（16） |
| 12 | 4 | `reserved` | 0 |
| 16 | 8 | `out_events_ptr` | 可写 `max_events × 24` 字节的地址 |

```c
typedef struct {
    uint32_t size, version, max_events, reserved;
    uint64_t out_events_ptr;
} InputReadRequest;     // size 24, align 8
```

### 7.26 `InputEventWire`（`input_read` 的输出事件，0.5）

| 偏移 | 大小 | 字段 | 说明 |
|---:|---:|---|---|
| 0 | 4 | `kind` | `INPUT_EVENT_KIND_KEYBOARD`(1) / `INPUT_EVENT_KIND_SERIAL`(2) |
| 4 | 4 | `code` | Keyboard：扫描码（bit7 为释放位）；Serial：字节值 |
| 8 | 4 | `sequence` | 从 1 起的连续序号 |
| 12 | 4 | `reserved` | 0 |
| 16 | 8 | `timestamp_ms` | 单调非降的毫秒时间戳 |

```c
typedef struct {
    uint32_t kind, code, sequence, reserved;
    uint64_t timestamp_ms;
} InputEventWire;       // size 24, align 8
```

M6c 冻结的显示常量：`DISPLAY_WIDTH = 320`、`DISPLAY_HEIGHT = 200`、`DISPLAY_FRAME_BYTES = 256000`；输入常量：`INPUT_EVENTS_MAX = 16`、`INPUT_EVENT_KIND_KEYBOARD = 1`、`INPUT_EVENT_KIND_SERIAL = 2`。

### 7.27 `SocketAddrWire`（0.6，所有 socket 地址的 wire 形式）

| 偏移 | 大小 | 字段 | 说明 |
|---:|---:|---|---|
| 0 | 4 | `family` | `SOCKET_FAMILY_UNIX`(1)/`_INET`(2)/`_INET6`(10)；0 表示"未绑定/未知" |
| 4 | 4 | `port` | 端口，ABI 整数（主机字节序），不是网络序 |
| 8 | 4 | `flags` | 0（0.6 保留） |
| 12 | 16 | `addr` | IP 地址原始字节：IPv4 用前 4 字节（网络序）、IPv6 用全部 16 字节；UNIX 必须清零 |
| 28 | 4 | `scope` | IPv6 link-local scope id；其它情况必须为 0 |
| 32 | 4 | `path_len` | UNIX 路径字节数，`≤ SOCKET_PATH_MAX`(107)；IP 必须为 0 |
| 36 | 108 | `path` | UNIX 路径字节（不要求 NUL 结尾）；IP 必须清零 |

`SocketAddrWire` 固定 144 字节、align 4，**没有末尾 reserved**。`path_len > 107` 时请求非法（`BAD_REQUEST`）；`family` 与 socket 的 domain 不一致同样非法。地址字节按网络序，`port` 是 ABI 整数——两者不要混用。

### 7.28 `SocketCreateRequest`（`socket` 的请求，0.6，32B）

| 偏移 | 大小 | 字段 | 说明 |
|---:|---:|---|---|
| 0 | 4 | `size` | 32 |
| 4 | 4 | `version` | `REQUEST_VERSION` |
| 8 | 4 | `domain` | `SOCKET_DOMAIN_*` |
| 12 | 4 | `kind` | `SOCKET_KIND_*` |
| 16 | 4 | `protocol` | 0（0.6） |
| 20 | 4 | `flags` | 0（0.6） |
| 24 | 4 | `namespace_handle` | NetworkNamespace 句柄；匿名 socket/INET 用 `HANDLE_NONE` |
| 28 | 4 | `reserved` | 0 |

### 7.29 `SocketAddrRequest`（`bind`/`connect` 的请求，0.6，24B）

| 偏移 | 大小 | 字段 | 校验 |
|---:|---:|---|---|
| 0 | 4 | `size` | 24 |
| 4 | 4 | `version` | `REQUEST_VERSION` |
| 8 | 4 | `addr_len` | 必须等于 `SOCKET_ADDR_WIRE`(144) |
| 12 | 4 | `reserved` | 0 |
| 16 | 8 | `addr_ptr` | 指向 144 字节 `SocketAddrWire` 的地址 |

`libs/native-abi` 同时导出 `pub type BindConnectRequest = SocketAddrRequest;` 只是可读别名，wire 布局完全相同。

### 7.30 `SocketAcceptRequest`（`accept` 的请求，0.6，16B）

| 偏移 | 大小 | 字段 | 校验 |
|---:|---:|---|---|
| 0 | 4 | `size` | 16 |
| 4 | 4 | `version` | `REQUEST_VERSION` |
| 8 | 8 | `out_handle_ptr` | 可写 4 字节的地址；0 → `BAD_POINTER` |

### 7.31 `SocketSendRequest`（`send` 的请求，0.6，24B）

| 偏移 | 大小 | 字段 | 校验 |
|---:|---:|---|---|
| 0 | 4 | `size` | 24 |
| 4 | 4 | `version` | `REQUEST_VERSION` |
| 8 | 4 | `flags` | 0（0.6） |
| 12 | 4 | `data_len` | 负载字节数 |
| 16 | 8 | `data_ptr` | 用户负载地址；`data_len > 0` 时必须可读 |

### 7.32 `SocketRecvRequest`（`recv` 的请求，0.6，32B）

| 偏移 | 大小 | 字段 | 校验 |
|---:|---:|---|---|
| 0 | 4 | `size` | 32 |
| 4 | 4 | `version` | `REQUEST_VERSION` |
| 8 | 4 | `flags` | 0（0.6） |
| 12 | 4 | `data_capacity` | 接收缓冲区字节数 |
| 16 | 8 | `data_ptr` | 可写缓冲区地址；容量 > 0 时必须可写 |
| 24 | 8 | `out_source_ptr` | 可选：可写 144 字节 `SocketAddrWire`；0 表示不取源地址 |

### 7.33 `SocketPairRequest`（`socketpair` 的请求，0.6，24B）

| 偏移 | 大小 | 字段 | 校验 |
|---:|---:|---|---|
| 0 | 4 | `size` | 24 |
| 4 | 4 | `version` | `REQUEST_VERSION` |
| 8 | 4 | `domain` | 0.6 只接受 `SOCKET_DOMAIN_UNIX`(1) |
| 12 | 4 | `kind` | `SOCKET_KIND_STREAM`/`_DGRAM` |
| 16 | 8 | `out_handles_ptr` | 可写 8 字节（两个 u32 raw handle）；0 → `BAD_POINTER` |

### 7.34 `SocketAddressRequest`（`socket_address` 的请求，0.6，24B）

| 偏移 | 大小 | 字段 | 校验 |
|---:|---:|---|---|
| 0 | 4 | `size` | 24 |
| 4 | 4 | `version` | `REQUEST_VERSION` |
| 8 | 4 | `which` | `SOCKET_ADDR_LOCAL`(0) / `_PEER`(1) |
| 12 | 4 | `reserved` | 0 |
| 16 | 8 | `out_addr_ptr` | 可写 144 字节 `SocketAddrWire`；0 → `BAD_POINTER` |

M7b 冻结的 socket 常量：`SOCKET_DOMAIN_UNIX = 1`、`SOCKET_DOMAIN_INET = 2`、`SOCKET_DOMAIN_INET6 = 10`；`SOCKET_FAMILY_*` 与对应 domain 同值；`SOCKET_KIND_STREAM = 1`、`SOCKET_KIND_DGRAM = 2`；`SOCKET_SHUTDOWN_READ = 0`、`_WRITE = 1`、`_BOTH = 2`；`SOCKET_ADDR_LOCAL = 0`、`SOCKET_ADDR_PEER = 1`；`SOCKET_PATH_MAX = 107`、`SOCKET_PATH_BYTES = 108`、`SOCKET_ADDR_WIRE = 144`。

## 8. 用户程序映像与启动 ABI

### 8.1 映像格式（M4）

- 类型：静态 `ET_EXEC`，不依赖解释器/动态链接，无重定位在装载后处理的需求（`relocation-model=static`）。
- 架构：`EM_X86_64`，只映射低半地址；链接基址 `0x400000`。
- 段布局：三个 `PT_LOAD`，段起点页对齐（4 KiB），段权限严格分离：

| 段 | 权限 | 内容 |
|---|---|---|
| text | `R + X` | 入口与代码 |
| rodata | `R` | 只读常量、只读重定位数据 |
| data | `R + W` | 可写数据与 `.bss`（`p_filesz` 可为 0，`p_memsz` 需清零） |

- 不允许任何段同时可写可执行（W^X）；不允许把 `.bss` 放在只读段。
- 映像由 `services/user.ld` 统一链接；装载器按 `PT_LOAD` 的 `p_flags` 建映射，并把 `p_filesz..p_memsz` 清零。
- 启动模块集合随切片扩展，当前为五个：`init`、`child`（M4）、`worker`（M6b2）、`gfx`（M6c，显示/输入程序）、`net`（M7b，原生 socket 自检程序，父进程与 `process_create("net")` 子进程共用同一 ELF）；全部由 BootInfo 的启动模块记录通过只读模块接口提供（总体设计 5.6 节），不由 VFS 路径解析。

### 8.2 入口 ABI

```text
_start(rdi = 第 1 个初始句柄, rsi = 第 2 个初始句柄, rdx = 第 3 个初始句柄) -> 不返回
```

- 三个句柄以 64 位寄存器值传入，取值是第 5.1 节的 32 位编码零扩展；无对应句柄时为 0（只有两个初始句柄的程序忽略 `rdx` 即可）。
- `rcx`、`r8`、`r9`、`r10`、`r11` 无定义，用户入口不得依赖其内容。
- 栈由内核建立：16 字节对齐、位于用户低半、可写、至少一页，栈顶以下按需增长不在 M4 范围。
- 入口不得返回；结束进程必须调用 `process_exit`。
- 中断/系统调用状态：用户态执行期间中断开启（定时器抢占依赖它），系统调用入口由内核负责切换栈与保存寄存器。
- M4 不传参数向量、环境变量、auxv、TLS；需要时由后续阶段以新的启动协议引入，不改变本节的寄存器约定。

### 8.3 参考程序的句柄约定

| 程序 | `rdi` | `rsi` | `rdx` |
|---|---|---|---|
| init | Console（`WRITE`） | Random（`READ`） | — |
| child（0.4 起） | Console（init 显式传递，`WRITE`） | EventPair 端点 B（`WAIT`/`WRITE`） | Channel B（`READ`/`WRITE`） |
| worker（M6b2） | — | — | — |
| gfx（0.5 起） | Console（`WRITE`） | Display（`READ`/`WRITE`/`MAP`） | Input（`READ`/`WAIT`） |
| net（0.6 起） | Console（`WRITE`） | Channel B（`READ`/`WRITE`/`WAIT`） | NetNamespace（`READ`/`WRITE`） |

child 证明不隐式继承：它用 init 的 Random 固定句柄 `0x0001_0002`（代次 1、槽 1）调用 `random_read`，必须得到 `BAD_HANDLE`。0.4 起 child 的第三个初始句柄是 M6a2 握手的 channel 端；Port 发送端、共享内存对象与订阅 channel 端都经 `ipc_send` 在运行期传递，不再占用启动寄存器。

worker 是 M6b2 的无句柄负载：两个实例都拿不到任何初始句柄（`rdi`/`rsi`/`rdx` 全为 0），因此它不打印、也不做任何 I/O。

gfx 由内核在 AP1 上启动（M6c），三个初始句柄都是内核创建的新对象而非从 init 继承；它用 `display_info`/`display_map`/`display_present` 画一帧并用 `wait` + `input_read` 收满 5 个输入事件，然后关闭句柄并退出。

net（M7b）的父进程拿到 Console / Channel B / NetNamespace 三个初始句柄后：自己用 `ipc_create(CHANNEL)` 建一对进程内 Channel，把 **A 端** 经 `process_create` 显式传给子进程（Console 与 NetNamespace 一并传递），父进程保留 B 端；然后在自己的 B 端先 `ipc_send` 一条 32B `OP_ROLE` 控制消息（`arg0 = 2`），再创建子进程——子进程的 A 端队列里已有一条角色消息，因此同一 ELF 用「启动后立即 `ipc_recv` 收到 `OP_ROLE(2)` ⇒ 作为 connector/child；`WOULD_BLOCK`/`TIMEOUT` ⇒ 作为 listener/parent」判别角色。内核传给父进程的 Channel B 只是能力占位（父进程不使用也不向其发送），启动路径不得预置消息，否则会破坏该判别。后续每个阶段（socketpair 端、drain/resume 等）与句柄传递都走这条自建 Channel，netns 路径绑定也由 NetNamespace 授权，不引入全局路径或共享状态绕过能力模型。

## 9. 验收标记与失败退出码

用户程序不直接访问串口，全部输出经 `write` 系统调用：

| 程序 | 正常输出顺序 | 含义 |
|---|---|---|
| init | `[CaelumInit] M4 init OK` | abi_query 通过且版本为 `ABI_VERSION`（0.3 为 3） |
| init | `[CaelumInit] M5c files OK` | 两个挂载点上文件/目录语义闭环通过（M5c1） |
| init | `[CaelumInit] M5c mmap OK` | 两个挂载点上 shared/private `mmap`、`mprotect`/`munmap`、close-hook 与拒绝路径全部通过（M5c2） |
| init | `[CaelumInit] M5c xattr OK` | 两个挂载点上扩展属性：读写、配额、`user.*` 命名空间、短缓冲与句柄 rights（M5c3） |
| init | `[CaelumInit] M5c sparse OK` | 两个挂载点上稀疏写：`SEEK 32768` 后写 4 字节、size 32772、空洞读 0、`sync` 后重开一致（M5c3） |
| init | `[CaelumInit] M5c watch OK` | 监视一个 FAT32 目录：create/rename/unlink 三个事件按序 drain 校验，watch 句柄故意留到退出（M5c3） |
| init | `[CaelumInit] M4 spawn OK` | process_create(child) 成功 |
| init | `[CaelumInit] M4 wait OK` | 子进程以状态 0 退出 |
| init | `[CaelumInit] M5c locks OK` | 子进程退出后释放跨 spawn 持有的 POSIX 排他锁并关闭句柄（M5c3） |
| init | `[CaelumInit] M6a timer OK` | 一次性 Timer 装载 5 tick 并在无限等待中醒来；此前 auto-reset Event 的 signal/wait/reset 负路径与 2 tick `TIMEOUT` 已通过（M6a1） |
| init | `[CaelumInit] M6a event OK` | 向子进程等待的 EventPair 端点 0 发信号成功（M6a1） |
| init | `[CaelumInit] M6a channel OK` | Channel 双端自持测试：FIFO 3 条、64 字节内联边界、空消息、队满 `WOULD_BLOCK` 后 drain，且与 child 的握手/A3 边界消息校验通过（M6a2） |
| init | `[CaelumInit] M6a port OK` | Port 接收端收到 child 经 write-only 发送端发出的消息，child 的 channel ack 随后到达（M6a2） |
| init | `[CaelumInit] M6a shm OK` | 共享内存经第二个别名看到 child 写入的 response（M6a2） |
| init | `[CaelumInit] M6a futex OK` | futex 唤醒 child（`futex_wake` 返回 1），child 回 ack 后经别名读到新值（M6a2） |
| init | `[CaelumInit] M6a subscription OK` | LT/ET 两个订阅的 ready/事件数/`object_key` 编码、drain 后 LT 归零、unsubscribe/close 后 channel 仍可用（M6a2） |
| init | `[CaelumInit] M4 rng OK` | Random 返回 `NO_ENTROPY`（符合预期） |
| child | `[CaelumChild] M4 child OK` | 入口与 Console 写路径正常 |
| child | `[CaelumChild] M5c files OK` | 两盘文件逐字节验证通过（M5c1） |
| child | `[CaelumChild] M5c mmap OK` | 两盘 shared 映射内容为 init 的 A5/5A、private 的 0xFF 未落盘、只读文件可写映射被拒（M5c2） |
| child | `[CaelumChild] M5c locks OK` | 与 init 持有的 POSIX 锁冲突为 `WOULD_BLOCK`、OFD/flock 独立域可用，且退出时遗留自己的 POSIX 锁交由内核回收（M5c3） |
| child | `[CaelumChild] M6a channel OK` | 收到两条带句柄的握手（Port 发送端仅 `WRITE`、shm 带 `MAP|READ|WRITE`、订阅端仅 `WRITE`），并对 write-only 端 `ipc_recv` 得到 `BAD_RIGHT`（M6a2） |
| child | `[CaelumChild] M6a port OK` | 经传递来的发送端成功发送 port 消息（M6a2） |
| child | `[CaelumChild] M6a shm OK` | 映射共享内存、逐字节验证 init 的 pattern 并写入 response（M6a2） |
| child | `[CaelumChild] M6a futex OK` | 在 futex 上真正阻塞后被 init 唤醒，读到新值 1（M6a2） |
| child | `[CaelumChild] M6a event OK` | 在 EventPair 端点 1 上无限等待，被 init 信号唤醒且 `wake_reason` = `READY`（M6a1） |
| child | `[CaelumChild] M4 handles OK` | Random 句柄返回 `BAD_HANDLE`，无隐式继承 |
| gfx | `[CaelumGfx] M6c display OK` | `abi_query` = 0.5、`display_info` 报告 `shadow_bytes = 256000`/320×200、`display_map` 成功并在 shadow 上画出两个 64×64 方块、`display_present` 全屏提交成功（M6c） |
| gfx | `[CaelumGfx] M6c input ready` | 显示半通过后开始等待输入（M6c） |
| gfx | `[CaelumGfx] M6c input OK (events=5, dropped=0)` | 收满 5 个事件且依次为 Keyboard `0x20`/`0xA0`、Serial `m`/`6`/`c`，`sequence` = 1..5、`timestamp_ms` 非降，随后关闭 mapping/input/display/console 并退出 0（M6c） |
| net | `[CaelumNet] M7b udp4 OK (bytes=7)` | 原生 UDP/IPv4 loopback：bind/connect/send/recv 7 字节 pattern 逐字节校验通过（M7b） |
| net | `[CaelumNet] M7b udp6 OK (bytes=7)` | 原生 UDP/IPv6 loopback 同上（M7b） |
| net | `[CaelumNet] M7b tcp4 OK (bytes=14)` | 原生 TCP/IPv4 真实 listen/connect/accept + 双向 14 字节收发（M7b） |
| net | `[CaelumNet] M7b tcp6 OK (bytes=14)` | 原生 TCP/IPv6 真实握手与 14 字节收发（M7b） |
| net | `[CaelumNet] M7b socketpair OK (pairs=2,bytes=1024)` | UNIX stream + dgram 两对匿名 socketpair；其中一对的一端经 Channel 传给子进程，跨进程合计收发 1024 字节（M7b） |
| net | `[CaelumNet] M7b unix stream OK (bytes=1024)` | netns 路径 UNIX stream：父 bind/listen、子 connect、父 accept，跨进程流式 1024 字节（M7b） |
| net | `[CaelumNet] M7b unix dgram OK (bytes=512)` | netns 路径 UNIX datagram 跨进程 512 字节且消息边界正确（M7b） |
| net | `[CaelumNet] M7b wait OK (ready=1,timeouts=1)` | 统一 `wait` 观察到真实 readiness 一次，空 socket 的 deadline 超时一次（M7b） |
| net | `[CaelumNet] M7b backpressure OK (would_block=2)` | UDP 队列满与 Local stream 缓冲满各返回一次 `WOULD_BLOCK`，drain 后可恢复（M7b） |
| net | `[CaelumNet] M7b shutdown OK (eof=1)` | half-close 后 `recv` 以 0 表示 EOF，另一个方向按约定报错（M7b） |
| net | `[CaelumNet] M7b rights OK (bad_handle=1,bad_right=1)` | 非法 socket 句柄（`BAD_HANDLE`）与命名 UNIX socket 缺少 NetNamespace 授权（`BAD_RIGHT`）各一次（M7b） |
| net | `[CaelumNet] M7b faults OK (too_large=1,not_found=1,exists=1,peer_closed=1)` | datagram 短缓冲 `TOO_LARGE` 且不消费、路径不存在 `NOT_FOUND`、同名 `EXISTS`、对端关闭 `PEER_CLOSED` 各一次（M7b） |
| net | `[CaelumNet] M7b OK (child=0)` | 父进程确认 `process_wait(child)` 返回 0 后打印（第 13 条，M7b） |

失败时以非零退出码区分步骤（init：`0x01` 写失败、`0x10` abi_query 失败、`0x11` 版本不符、`0x12` 创建失败、`0x13` wait 错误、`0x14` 子进程非零退出、`0x15` 随机源状态不符；M5c1 文件步骤 `0x30`–`0x34`、目录步骤 `0x35`–`0x3b`、只读/跨挂载/失效句柄/dup/seek/trunc 步骤 `0x3c`–`0x41`；M5c2 映射步骤 `0x50`–`0x5c`；M5c3 属性步骤 `0x60`–`0x66`、稀疏步骤 `0x70`–`0x75`、watch 步骤 `0x80`–`0x88`、锁步骤 `0x90`–`0x95`；M6a1 IPC 步骤 `0xa0` 创建对象、`0xa1` Event 语义、`0xa2` 超时、`0xa3` Timer、`0xa4` EventPair；**M6a2 IPC 步骤 `0xb0`–`0xbb`（创建/send/recv/payload/句柄/队满/shm/futex/port/订阅/取回句柄/关闭）**；child：`0x01` 写失败、`0x20` 返回非 `BAD_HANDLE` 的其他错误、`0x21` 意外拿到继承句柄、`0x22` 文件内容/大小不符、`0x23` 两盘启动代次不一致、`0x24`–`0x27` 映射打开/内容/munmap/权限检查失败、`0x30`–`0x34` 锁打开/POSIX 冲突/OFD/flock/退出回收准备失败、`0x40` EventPair `wait` 失败、`0x41` 唤醒原因/就绪位不符、**`0x42`–`0x4a` M6a2 接收/载荷/句柄/rigths/port/shm/futex/send/关闭失败**；**gfx（M6c）：`0x70` `abi_query` 版本不符、`0x71` `abi_query` 失败、`0x72` 显示信息/几何不符、`0x73` `shadow_bytes` 不符、`0x74` `display_map` 或映射基址失败、`0x75` `display_present` 失败、`0x76` input `wait` 失败、`0x77` `input_read` 失败、`0x78` 事件 kind/code 不符、`0x79` `sequence` 不符、`0x7a` `timestamp_ms` 回退**；**net（M7b）：`0x80` 初始化/建 Channel/abi_query 失败、`0x81` 角色判别失败、`0x82` 子进程创建或 `process_wait` 失败、`0x83` 控制消息协议不符、`0x84` 数据 pattern/长度/边界校验失败、`0x91`–`0x9c` 父进程 12 个相位失败（udp4/udp6/tcp4/tcp6/socketpair/unix stream/unix dgram/wait/backpressure/shutdown/rights/faults 依次）、`0xa1`–`0xac` 子进程对应相位失败**），并尽量先输出一行 `... FAIL ...` 便于串口定位。

用户程序使用的精确文件与目录路径（这些是用户可见契约的一部分，串口验收依赖它们）：

| 路径 | 用途 |
|---|---|
| `/fat/M5CUSER.BIN`、`/ext2/m5cuser` | 跨启动持久文件：首启 14 字节，二启追加到 20 字节；M5c3 在其上做扩展属性（`user.caelum`=`m5c3`，`user.boot`=`one`/`two`） |
| `/fat/M5CDIR`、`/ext2/m5cdir` | 目录测试（测试结束会改名为 `M5CDIR2`/`m5cdir2`、清理并删除） |
| `/fat/M5CDIR/INNER.TXT`、`/ext2/m5cdir/inner.txt` | 目录内文件（内容 `inner`） |
| `/fat/M5CTMP.BIN` | dup/seek/truncate 临时文件（测试结束删除） |
| `/boot/init` | 只读启动模块（VFS 启动挂载 `/boot` 下的 `init`），以写方式打开必须返回 `READ_ONLY` |
| `/fat/M5MAP.BIN`、`/ext2/m5cmap` | M5c2 映射文件：8192 字节 pattern；shared 写入把偏移 0/4103 改为 `A5`/`5A` 并 `sync`，private 的 `0xFF` 不得落盘 |
| `/fat/M5HOLE.BIN`、`/ext2/m5chole` | M5c3 稀疏文件：`SEEK 32768` 写 `HOLE`，size 32772，0/4096/32767 读回 0 |
| `/fat/M5WATCH`（`A.BIN`→`B.BIN`） | M5c3 被监视目录：watch 后 create/rename/unlink，drain 校验三类事件 |
| `/fat/M5LOCK.BIN` | M5c3 锁文件：init 持有 POSIX 排他锁跨 spawn，child 必须得到 `WOULD_BLOCK` |
| `/ext2/m5clock` | M5c3 锁文件：child 持有 POSIX 排他锁直到退出，验证内核退出路径回收锁与句柄 |
| `/fat/M5CUSER.BIN`、`/ext2/m5cuser` 的扩展属性 | M6a2 仍沿用 M5c3 的 `user.caelum`/`user.boot` 属性；channel/port/shm 测试不新增持久路径 |

## 10. 版本与兼容

- 当前 `major = 0`、`minor = 6`，`abi_query` 返回 `0x0000_0006`。
- 1.0 前按总体设计 10.5 节允许受控破坏，但每次破坏必须有迁移说明与同步更新的用户运行库；0.1 的 syscall 号、错误码数值、句柄编码与结构布局在下一次文档化变更前视为冻结。
- 0.1 → 0.2 是**向后兼容的新增**：未改动任何 0.1 调用号、错误码、句柄编码与 `ProcessCreateRequest` 布局；0.1 程序无需改动即可在 0.2 内核上运行（`abi_query` 版本号会从 1 变为 2，依赖等值比较的程序应按"主版本相同、次版本不低于需求"判断）。
- 0.2 → 0.3 同样是**向后兼容的新增**：27/28/29/33 四个新调用、`IpcCreateRequest`/`WaitRequest`/`WaitItem`/`WaitOut` 四个新布局、`IPC_KIND_*`/`WAIT_*`/`WAKE_*`/`SIGNAL_OP_*`/`EVENT_FLAG_*` 常量与错误码 22/23；既有调用号、错误码、句柄编码与全部 0.2 请求布局不变。0.2 程序只会在 `abi_query` 看到次版本 3，按"次版本不低于需求"判断即可继续运行。
- 0.3 → 0.4 是**新增调用 + 一处受控布局扩展**：30/31/32/34/35/37/38/39 八个新调用、`IpcSendRequest`/`IpcReceiveRequest`/`IpcMessageMeta`/`ShmMapRequest`/`SubscribeRequest`/`SubscriptionEntry`/`SubscriptionReadRequest`/`SubscriptionEvent` 八个新布局、`RIGHT_MAP`/`IPC_DATA_MAX`/`IPC_HANDLES_MAX`/`SUBSCRIBE_*`/`SUBSCRIPTION_*` 常量，`ipc_create` 支持全部七种 `IPC_KIND_*`。**`IpcCreateRequest` 由 32 字节扩为 40 字节**（末尾追加 `out_second_ptr`），按 §10 的"末尾追加 + 提升 size"规则演进：0.3 程序构造 32 字节请求会被内核按 `size` 校验拒绝（`BAD_REQUEST`），必须重编——这是 0.3→0.4 唯一的源码级迁移点；`Channel`/`Port` 需要第二句柄时填 `out_second_ptr`，其余类型必须置 0。既有调用号、错误码、句柄编码与其余布局不变。
- 0.4 → 0.5 是**纯新增**：40/41/42/43 四个新调用、`DisplayInfoRequest`/`DisplayInfoWire`/`DisplayPresentRequest`/`InputReadRequest`/`InputEventWire` 五个新布局、`DISPLAY_WIDTH`/`DISPLAY_HEIGHT`/`DISPLAY_FRAME_BYTES`/`INPUT_EVENTS_MAX`/`INPUT_EVENT_KIND_*` 常量；`display_map` 复用已有的 `ShmMapRequest`（§7.18），因此不新增 `DisplayMapRequest` 布局。既有调用号、错误码、句柄编码与 0.4 的全部请求布局不变，0.4 程序只会在 `abi_query` 看到次版本 5。入口 ABI 的第三个初始句柄（`rdx`）在 0.5 起有定义，0.4 程序忽略它即可继续运行。36 `ipc_transfer` 仅冻结编号，本阶段必须返回 `NOT_SUPPORTED`（句柄传递走 `ipc_send`）。
- 0.5 → 0.6 是**纯新增**：44–53 十个新调用、`SocketAddrWire`（144B）与 `SocketCreateRequest`/`SocketAddrRequest`/`SocketAcceptRequest`/`SocketSendRequest`/`SocketRecvRequest`/`SocketPairRequest`/`SocketAddressRequest` 七个新请求/地址布局、`BindConnectRequest` 别名、`SOCKET_DOMAIN_*`/`SOCKET_FAMILY_*`/`SOCKET_KIND_*`/`SOCKET_SHUTDOWN_*`/`SOCKET_ADDR_*`/`SOCKET_PATH_*`/`SOCKET_ADDR_WIRE` 常量与错误码 24–26（`CONNECTION_REFUSED`/`CONNECTION_RESET`/`NOT_CONNECTED`）。既有调用号、错误码、句柄编码与 0.5 的全部布局不变，0.5 程序只会在 `abi_query` 看到次版本 6。**本版本只冻结 wire 与用户运行库 wrapper**：socket 内核实现在 M7 内核切片交付，在此之前 44–53 返回 `NOT_SUPPORTED` 是预期状态，不是 ABI 缺陷；Linux socket ABI/errno 映射属后续 M7d。
- 新增调用使用新编号；已冻结编号不复用、不改语义。18–20 已由 M5c2 启用（见 6.19–6.21），21–25 已由 M5c3 启用（见 6.22–6.26），27/28/29/33 已由 M6a1 启用（见 6.27–6.30），30/31/32/34/35/37/38/39 已由 M6a2 启用（见 6.31–6.39），40–43 已由 M6c 启用（见 6.40–6.43），44–53 已由 M7b 冻结 wire（见 6.44–6.53，内核实现在 M7 交付）；0–43 返回 `NOT_SUPPORTED` 属实现缺陷，44–53 在 M7 内核交付前属预期状态。
- 结构演进只在末尾追加字段并提升 `size`；布局版本独立于 ABI 版本（0.2/0.3 全部请求结构为 `version = 1`）。不采用"忽略未知字段"的松散解析。

## 11. 与内核实现的边界

内核侧必须满足（本文的可验证义务）：

1. `abi_query` 返回 `(major << 16) | minor`，0.6 为 `0x0000_0006`。
2. 所有用户指针经 copy-in/copy-out 与范围/溢出校验；校验失败返回 `BAD_POINTER`。
3. `process_create` 复制（而非移动）调用者句柄；子进程只看到请求中列出的句柄。
4. `process_wait` 永不睡眠：运行中返回 `WOULD_BLOCK`。
5. `random_read` 在 CRNG 未就绪时返回 `NO_ENTROPY`，不写缓冲区、不返回伪随机。
6. 用户映像按 `PT_LOAD` 权限映射，遵守 W^X，`.bss` 清零，入口 `0x400000` 映射为可执行。
7. 未实现/未定义的调用号不得静默成功；产生可统计诊断并按 `NOT_SUPPORTED` 或内核自身错误路径处理（总体设计 10.3 节）。
8. `process_create` 拒绝同一请求中重复出现的 `source`（返回 `BAD_REQUEST`）：子进程不得因复制语义而获得两个共享同一引用传递的句柄。

0.2 追加的可验证义务：

9. `open`/`mkdir`/`rmdir`/`unlink`/`rename` 的路径参数只接受绝对路径，逐组件解析；`..` 不得逃出挂载根；路径长度与 `path_ptr + path_len` 必须溢出检查，失败返回 `BAD_POINTER`。
10. `readdir` 跳过 `.`、`..`、卷标与 LFN 辅助项；耗尽时返回 `NOT_FOUND`，不得把"没有更多项"伪装成 `OK + 空项`。
11. `rename` 跨挂载点必须返回 `CROSS_DEVICE`，不得静默降级为"复制后删除"。
12. `dup` 产生的两个句柄共享同一打开描述的偏移与截断状态；关闭任一句柄不影响另一个。
13. 启动模块等只读节点以写方式打开必须返回 `READ_ONLY`（不是 `NOT_FOUND`）；只读文件系统上的元数据修改一律 `READ_ONLY`。
14. 已冻结编号 18–25 不得静默成功、不得挪作他用：M5c2 前 18–20、M5c3 前 21–25 必须返回 `NOT_SUPPORTED`。
15. `OPEN_WRITE` 不得隐含 `RIGHT_READ`（反之亦然）：`open` 只置 `WRITE` 的句柄上 `read`/`dup(RIGHT_READ)` 必须返回 `BAD_RIGHT`；内核不得为了适配某个用户程序而放宽这条能力检查。

M5c2 追加的可验证义务：

16. `mmap` 是急切的，返回时整段已建立且可访问；`len`/`offset` 非零、页对齐、`len ≤ 256 KiB`、`offset + len` 不越过文件末尾，否则 `BAD_REQUEST`；不做隐式文件扩展。
17. `mmap` 不得静默忽略 `PROT_EXEC`：含 `PROT_EXEC` 返回 `NOT_SUPPORTED`，W^X 组合绝不允许成功；只读文件请求 `MMAP_SHARED` + `PROT_WRITE` 返回 `BAD_RIGHT`。
18. shared 映射的脏页必须能被文件句柄上的 `sync` 写回，随后同一文件的 `read` 可见；private 映射的写入不得改变文件内容，也不得影响其他映射。
19. 关闭映射句柄必须解除映射；`munmap` 等价于"解除并关闭映射句柄"；对已解除范围再 `munmap` 返回 `NOT_FOUND`/`BAD_REQUEST`；映射句柄不能用于文件 I/O，也不能传给子进程。

M5c3 追加的可验证义务：

20. `lock` 必须非阻塞：冲突返回 `WOULD_BLOCK` 而不是睡眠/排队；POSIX 锁按进程所有（同进程任意句柄重入不冲突）、OFD 锁按打开文件描述（`dup` 共享）、`flock` 为独立域，三者互不冲突；`flock` 只接受 `offset = len = 0`。
21. 锁的所有权必须可回收：关闭句柄/打开描述、进程退出都要释放相应锁；不得因崩溃路径泄漏锁而永久阻塞后续进程。
22. `xattr_set`/`xattr_get` 只接受 `user.*` 命名空间，名字 ≤16、值 ≤64；超出每文件属性配额返回 `QUOTA`；同一属性覆盖旧值。实现可以是易失的（不写入磁盘格式），但内核不得宣称跨启动持久。
23. `xattr_get` 缓冲区不足必须返回 `TOO_LARGE` 且不部分写入；只置 `WRITE` 的句柄读属性、只置 `READ` 的句柄写属性都返回 `BAD_RIGHT`。
24. `watch` 订阅目录身份而非路径；事件按产生顺序先进先出，溢出时必须通过事件里的累计 `dropped` 暴露丢失，不得静默丢；关闭 Watch 句柄或进程退出必须回收订阅（`watch_count` 归零）。
25. `watch_drain` 的 `max_events` 必须在 1..=16，`events_ptr` 必须能容纳 `max_events × 48` 字节；空队列返回 0 个事件且状态成功；非 Watch 句柄返回 `BAD_HANDLE`/`BAD_RIGHT`。

M6a1 追加的可验证义务：

26. `ipc_create` 只实现 Event / EventPair / Timer；Channel/Port/Shm/Subscription 与 30–32/34–36 必须返回 `NOT_SUPPORTED`，不得用空对象冒充实现。
27. `wait` 的 `size` 必须恰为 96、`count` 在 1..=4、`out_ptr` 可写 16 字节；`timeout_ticks = 0` 且无就绪项返回 `WOULD_BLOCK` 且不消费任何对象状态；超时返回 `TIMEOUT`；只有成功返回时才消费 auto-reset Event 置位/EventPair 锁存。
28. `wait` 的可观察结果必须与 `wake_reason` 一致：就绪为 `READY` 且 `ready_mask` 至少一位；超时为 `TIMEOUT`；对端销毁为 `PEER_CLOSED`；不得在超时时也报告某一就绪位。
29. 内核不得修改调用者的 `WaitRequest`，同一请求可重放（超时/`WOULD_BLOCK` 后可直接再次 `wait`）。
30. `timer_arm` 是一次性到期：装载后到期一次、被一次成功 `wait` 消费；再次装载覆盖未到期装载；`ticks = 0` 或 `flags != 0` 返回 `BAD_REQUEST`。
31. 全部等待路径必须与调度器协作：当所有用户线程都阻塞在内核时，内核必须进入 idle 并在 tick/Timer 到期后恢复，不得忙等或永久挂起（M6a1 用 init 的 Timer 等待覆盖此路径）。
32. 句柄与对象回收：关闭最后一个句柄或进程退出必须销毁对象；EventPair 对端全部关闭后，剩余一端的 `wait` 必须以 `PEER_CLOSED` 醒来而不是永久阻塞。

M6a2 追加的可验证义务：

33. `ipc_send` 必须在返回前完成数据与句柄的拷贝；队列满返回 `WOULD_BLOCK` 且不消费任何数据/句柄引用；`data_len`/`handle_count` 越界返回 `BAD_REQUEST`，不得截断或丢弃。该调用另有 0.4 的受控限制：消息携带的对象等于本次发送端 `rdi` 所指对象时返回 `BAD_REQUEST`（不视为通用禁止句柄传递，端点自传由后续 ABI 扩展定义）。
34. 句柄传递必须经 rights 子集校验：只置 `WRITE` 的 channel 端 `ipc_recv` 返回 `BAD_RIGHT`；传递后发送方无法再引用同一引用（除自行 `dup`），接收方关闭不影响其他持有者。
35. `ipc_recv` 在容量不足时必须返回 `TOO_LARGE`/`QUOTA` **且不消费消息**，不得部分拷出或丢弃句柄；`out_meta_ptr`/`out_handles_ptr` 为 0 表示不取该项。
36. `channel` 的 FIFO 顺序、内联数据边界（64 字节）、空消息与 `PEER_CLOSED`（接收端在队列耗尽后由对端全关触发）必须可观察；接收端句柄关闭后发送端写入路径应得到 `PEER_CLOSED` 而不是静默丢弃。
37. `shm_map` 急切映射整个对象；同一对象多次映射得到不同用户地址且互为别名；`PROT_EXEC` 返回 `NOT_SUPPORTED`；映射句柄不能做文件 I/O、不能传给子进程；关闭映射句柄解除映射、关闭对象句柄不影响已有映射。
38. `futex_wait` 必须先比较再阻塞：首次进入 `*address != expected` 立即 `WOULD_BLOCK`；被 `futex_wake` 唤醒后返回 `OK` 且允许 spurious wake（内核不得承诺值的相等性）；超时 `TIMEOUT`；`futex_wake` 返回实际唤醒数且不修改用户内存。
39. `subscribe` 的 interest 必须绑定对象身份而不是路径/句柄值；`subscription_read` 的 LT/ET 语义必须稳定：LT 在目标仍就绪时重复读到事件、ET 一次就绪只报一次；`object_key` 必须按 `(object_raw << 32) | key` 编码；drain 目标后 LT 归零；`unsubscribe`/关闭订阅后被观察对象仍可正常收发。
40. `IpcCreateRequest.size` 必须恰为 40；`Channel`/`Port` 需要 `out_second_ptr` 可写 8 字节，其它 kind 必须为 0；共享内存 `arg0` 必须页对齐且非 0，否则 `BAD_REQUEST`。
41. `display_info`/`display_map`/`display_present` 只能操作内核拥有的显示对象；内核不得把 framebuffer 物理地址或 MMIO 窗口暴露给用户态，用户只能经 `display_map` 得到 RAM shadow 的普通映射；无显示设备时返回 `NOT_SUPPORTED`，不得伪造尺寸。
42. `display_info` 必须报告 `shadow_bytes == width × height × 4`（M6c 为 256000）、`stride ≥ width`，且 `pixel_format` 只能是 UEFI GOP 已定义的 32 位格式之一；同一显示模式下重复查询的结果必须一致。
43. `display_map` 急切映射整块 shadow，同一对象多次映射互为别名；`PROT_EXEC` 返回 `NOT_SUPPORTED`；映射句柄不能做文件 I/O、不能传给子进程；关闭映射句柄解除映射且不影响 Display 对象，关闭 Display 句柄也不影响已有映射。
44. `display_present` 只接受全屏 320×200（子矩形 `NOT_SUPPORTED`、越界 `BAD_REQUEST`）；提交必须使用 shadow 的当前内容，返回时已完整拷贝到 framebuffer；不得把未初始化的 shadow 页或内核指针内容写进显存。
45. `input_read` 必须非阻塞：空队列返回 `OK` + 0 事件；事件按 FIFO 顺序、`sequence` 从 1 连续递增、`timestamp_ms` 非降；内核丢弃事件必须可观察（累计计数），不得静默跳号。
46. 输入事件只能由持有对应 Input 句柄（`READ`/`WAIT`）的进程读取；关闭最后一个句柄销毁队列并以 `PEER_CLOSED` 唤醒等待者；M6c 的 gfx 在内核创建的 AP 上运行，其阻塞等待路径必须与普通等待一致（可被 timer/IPI 抢占）。

M7b（0.6）冻结、随 M7 内核交付验收的 socket 契约：

47. 44–53 的寄存器、请求布局与字段校验必须严格按 §6.44–§6.53 与 §7.27–§7.34 执行；`size`/`version` 不符返回 `BAD_REQUEST`，且不得读取越界字段。原生 socket 状态码不得使用 Linux errno 数值（`CONNECTION_REFUSED = 24`、`CONNECTION_RESET = 25`、`NOT_CONNECTED = 26` 是原生值，compat 层在 M7d 单独映射）。
48. `SocketAddrWire` 的 `family` 必须与 socket 的 domain 一致，`path_len ≤ 107`，`path` 不要求 NUL 结尾；IP 地址只占 `addr`（IPv4 放前 4 字节、其余清零），UNIX 的 `addr`/`port` 必须为 0；`scope` 只用于 IPv6 link-local。`addr_len` 必须为 144。
49. socket 的等待必须接入统一 `wait`（`EventSubscription`/就绪位同一机制），不得内嵌 `SO_RCVTIMEO` 一类超时；`accept`/`recv`/`connect` 首次调用不得睡眠，而是返回 `WOULD_BLOCK` 并让对象就绪。对同一 socket 的并发调用必须有确定的串行化语义。
50. socket 句柄权限：新 socket 与 `accept` 派生的连接为 `READ | WRITE`；监听端另需 `WAIT`；`socketpair` 两端为 `READ | WRITE | WAIT`；权限不足一律 `BAD_RIGHT`，不得在内部放宽。
51. `send` 满队列返回 `WOULD_BLOCK` 且不消费数据；`recv` 对 datagram 容量不足返回 `TOO_LARGE` 且不消费该报文、对 stream 允许部分读；`recv` 返回 0 只表示零长 datagram，空队列必须是 `WOULD_BLOCK`。`send`/`recv` 在 `shutdown` 相应方向后返回 `NOT_CONNECTED`，对端关闭返回 `PEER_CLOSED`。
52. 关闭最后一个 socket 句柄必须释放其队列与连接资源；对端随后可观察到 `PEER_CLOSED`；`shutdown` 幂等，且不得因重复 `shutdown`/关闭而重复唤醒或访问已释放对象。
53. UNIX 命名 socket 的 `bind` 必须受 NetworkNamespace 授权约束：只有持有该 netns 能力句柄的进程可以创建/解析命名 socket，路径在 netns 内解析，netns 销毁或最后一个持有者退出时必须清理，不得泄漏路径或监听项。匿名 socketpair 不经过 netns。
54. `socketpair` 失败必须全回滚（不创建半个端点、不泄漏句柄/对象），成功时两端是独立句柄、独立对象；`socket_address` 对未绑定 socket 返回空地址（`family = 0`）而不是错误。
55. Linux socket ABI（`AF_UNIX` abstract、`SCM_RIGHTS`/`SCM_CREDENTIALS`、errno 映射、`poll/epoll` 视图）属 M7d/M9，不在 0.6 承诺范围内；M7 内核不得让原生调用提前返回 Linux errno 或伪装成功。
56. M7b 的 `net` 自检程序契约：父进程只通过**自建** Channel 把 A 端与两个 socketpair 端传给子进程，ns 授权只经 NetNamespace 句柄；同一 ELF 以启动后首条 `ipc_recv` 是否收到 `OP_ROLE(2)` 判别 parent/child，因此启动路径不得向父进程的 Channel B 预置消息，父进程也不使用该初始句柄（只作为能力占位）。13 条标记按 §9 顺序产生，任何依赖成功前提的标记不得在前提未验证时打印；失败一律打印不含 `OK` 的诊断并以非零码退出。

## 12. 变更日志

| 版本 | 日期 | 变更 |
|---|---|---|
| 0.1（M4） | — | 首个冻结版本：7 个系统调用、9 个错误码、句柄编码、`ProcessCreateRequest`、用户映像与入口 ABI、非阻塞 `process_wait` 语义。 |
| 0.2（M5c1） | — | 新增调用 7–17 与 26（`open/read/stat/readdir/mkdir/rmdir/unlink/rename/sync/seek/dup/truncate`），冻结预留 18–25（mmap/锁/xattr/目录通知）；错误码扩到 10–21（`EXISTS`…`CROSS_DEVICE`）；新增 `OpenRequest`/`StatOut`/`DirEntryOut`/`RenameRequest` 四个布局与 `OPEN_*`/`NODE_*`/`STAT_FLAG_*`/`SEEK_*` 常量；请求结构 `version` 改为独立的布局版本（恒为 1）；`write` 语义扩展到文件句柄。 |
| 0.2（M5c2） | — | 启用 18–20（`mmap`/`munmap`/`mprotect`）：新增 `MmapRequest`（48 字节）与 `PROT_*`/`MMAP_*`/`MMAP_MAX_LEN` 常量，急切映射（无按需缺页）、shared 经 `sync` 回写、private 为快照不回写、关闭映射句柄即解除映射、`munmap` 同时关闭映射句柄；`PROT_EXEC` 保留但返回 `NOT_SUPPORTED`；新增用户标记 `[CaelumInit] M5c mmap OK`/`[CaelumChild] M5c mmap OK` 与映射文件路径契约。 |
| 0.2（M5c3） | — | 启用 21–25：`lock`（POSIX/OFD/flock 三域、非阻塞、`WOULD_BLOCK`）、`xattr_set`/`xattr_get`（仅 `user.*`、名字 ≤16/值 ≤64、每文件配额、短缓冲 `TOO_LARGE` 不部分写、易失）、`watch`/`watch_drain`（目录身份订阅、FIFO 有界队列、累计 `dropped`、退出回收）。新增 `LockRequest`（32B）/`XattrRequest`（40B）/`WatchEventOut`（48B）/`WatchDrainRequest`（24B）四个布局与 `LOCK_DOMAIN_*`/`LOCK_OP_*`/`XATTR_*`/`WATCH_EVENT_*`/`WATCH_MAX_BATCH` 常量；新增用户标记 `[CaelumInit] M5c xattr/sparse/watch/locks OK` 与 `[CaelumChild] M5c locks OK`，以及稀疏文件、被监视目录、锁文件路径契约。 |
| 0.3（M6a1） | — | 启用 27/28/29/33（`ipc_create`/`ipc_signal`/`wait`/`timer_arm`）：交付 Event（auto/manual reset）、EventPair（两端点）、一次性 Timer 三类最小可等待对象与统一阻塞等待；新增 `IpcCreateRequest`（32B）/`WaitRequest`（96B，含 4×`WaitItem` 16B）/`WaitOut`（16B）三个布局与 `IPC_KIND_*`/`EVENT_FLAG_MANUAL_RESET`/`EVENT_PAIR_ENDPOINT_*`/`SIGNAL_OP_*`/`WAIT_TIMEOUT_*`/`WAIT_MAX_ITEMS`/`WAKE_*` 常量；错误码 22 `CANCELLED`/23 `PEER_CLOSED` 冻结（本切片不主动产生）；30–32/34–36 与其余 IPC 种类只冻结编号、返回 `NOT_SUPPORTED`；新增用户标记 `[CaelumInit] M6a timer OK`/`[CaelumInit] M6a event OK`/`[CaelumChild] M6a event OK`，初始句柄改为 Console + EventPair 两个。 |
| 0.4（M6a2） | — | 启用 30/31/32/34/35 与 37/38/39（`ipc_send`/`ipc_recv`/`shm_map`/`subscribe`/`unsubscribe`/`futex_wait`/`futex_wake`/`subscription_read`）：交付 Channel（FIFO、64B 内联、有界队列 `WOULD_BLOCK`）、Port（接收/发送端）、SharedMemory（急切映射、多别名、`RIGHT_MAP`）、EventSubscription（LT/ET、`object_key` 编码）与 futex 阻塞唤醒；`ipc_create` 支持全部七种 `IPC_KIND_*`，`IpcCreateRequest` 扩为 40B（追加 `out_second_ptr`，0.3 程序需重编）；新增 `IpcSendRequest`（64B）/`IpcReceiveRequest`（64B）/`IpcMessageMeta`（32B）/`ShmMapRequest`（32B）/`SubscribeRequest`（24B）/`SubscriptionEntry`（16B）/`SubscriptionReadRequest`（24B）/`SubscriptionEvent`（16B）八个布局与 `RIGHT_MAP`/`IPC_DATA_MAX`/`IPC_HANDLES_MAX`/`SUBSCRIBE_MAX_ENTRIES`/`SUBSCRIPTION_EVENTS_MAX`/`SUBSCRIPTION_MODE_*` 常量；36 `ipc_transfer` 继续保留未实现（句柄传递走 `ipc_send`）；新增用户标记 `[CaelumInit] M6a channel/port/shm/futex/subscription OK` 与 `[CaelumChild] M6a channel/port/shm/futex OK`，child 初始句柄增至 Console + EventPair + Channel B 三个。 |
| 0.5（M6c） | — | 启用 40–43（`display_info`/`display_map`/`display_present`/`input_read`）：交付基础显示 RAM shadow（`display_info` 描述、`display_map` 复用 `ShmMapRequest` 映射、全屏 `display_present` 提交）与输入事件队列（FIFO、`sequence`/`timestamp_ms`、非阻塞 `input_read`）；新增 `DisplayInfoRequest`（24B）/`DisplayInfoWire`（32B）/`DisplayPresentRequest`（24B）/`InputReadRequest`（24B）/`InputEventWire`（24B）五个布局与 `DISPLAY_WIDTH`/`DISPLAY_HEIGHT`/`DISPLAY_FRAME_BYTES`/`INPUT_EVENTS_MAX`/`INPUT_EVENT_KIND_*` 常量；不新增 IPC kind、不新增错误码、不改既有布局；新增 `caelum-gfx` 第四启动模块与标记 `[CaelumGfx] M6c display OK`/`[CaelumGfx] M6c input ready`/`[CaelumGfx] M6c input OK (events=5, dropped=0)`；入口 ABI 的第三个初始句柄（`rdx`）由本版本定义。 |
| 0.6（M7b） | — | **冻结** 44–53（`socket`/`bind`/`listen`/`accept`/`connect`/`send`/`recv`/`shutdown`/`socketpair`/`socket_address`）：新增 `SocketAddrWire`（144B，family/port/flags/addr[16]/scope/path_len/path[108]，无末尾 reserved）与 `SocketCreateRequest`（32B）/`SocketAddrRequest`（24B，别名 `BindConnectRequest`）/`SocketAcceptRequest`（16B）/`SocketSendRequest`（24B）/`SocketRecvRequest`（32B）/`SocketPairRequest`（24B）/`SocketAddressRequest`（24B）七个布局与 `SOCKET_*` 常量；错误码扩到 24–26（`CONNECTION_REFUSED`/`CONNECTION_RESET`/`NOT_CONNECTED`，均为原生状态，Linux errno 映射留 M7d）；`libs/native-rt` 新增十个 wrapper（`socket_create`/`socket_bind`/`socket_connect`/`socket_listen`/`socket_accept`/`socket_send`/`socket_recv`/`socket_shutdown`/`socketpair`/`socket_address`）；用户侧新增第五启动模块 `net`（父进程 + `process_create("net")` 子进程共用同一 ELF，入口三句柄见 §8.3）与 `services/net` 自检程序、13 条 `[CaelumNet]` 标记（§9）；**本切片不实现内核行为**，44–53 在 M7 内核交付前返回 `NOT_SUPPORTED`。 |
