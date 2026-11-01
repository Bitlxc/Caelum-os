# 青穹 OS / CaelumOS 项目进度记录

> 记录时间：2026-10-30 起，最近更新 2026-11-01（Asia/Shanghai）  
> 当前状态：**M0 已正式关闭；M1～M6 全部已完成并在真实 QEMU/OVMF 中验收通过（完整 M5 与完整 M6 均已关闭）；M7 已完成 M7a（内核 loopback IPv4/IPv6 UDP/TCP 自检）、M7b（原生 Socket/LocalSocket）与 M7d（Linux64 socket 人格核心），三者均通过两启动 QEMU/OVMF 验收；M7c（真实 virtio-net 链路）尚未实施，完整 M7 未关闭；M8 已完成 M8a～M8h 八个 Linux64 基础人格切片并通过两启动验收；M9a（timerfd/signalfd/epoll level-triggered 基础语义）、M9b（AF_UNIX abstract 命名空间、`SCM_RIGHTS`/`SCM_CREDENTIALS` fd 传递、`EPOLLET` 边沿触发）、M9c（文件锁/fcntl：同 ELF role2 锁对端、VFS POSIX/OFD/flock 三锁域）、M9d1（Linux64 动态 ELF/PT_INTERP 最小闭环）、M9d2（真实 ET_EXEC vDSO：全局只读数据页 + 直接入口调用）以及 M9e（真实 ET_DYN 共享库：`DT_NEEDED` 单依赖 `/fat/m9e.so`，库内 RELATIVE 与主程序 GLOB_DAT 由自研解释器应用）与 M9f（真实链式三库闭包：`/fat/m9e.so` + `/fat/m9f-a.so` → `/fat/m9f-b.so` 两级 `DT_NEEDED`、跨库 GLOB_DAT 与解释器冻结顺序解析，三库映射同一地址空间、无 PLT 懒绑定）均已完成并通过两启动验收（M9f 完成后每启动 **136** 个集成标记；M9e 时为 135、M9d2 时为 134）；完整 M8 未完成；完整 M9 未关闭（完整共享库/PLT/GOT 重定位与 Linux 工具运行等切片未完成）**
> 当前范围：M1～M6 已完成并验收、作为回归保留；M7 已完成 M7a/M7b/M7d，M7c（真实 virtio-net 设备链路、QEMU user-net 连通与异常恢复）尚未实施，完整 M7 不关闭；M8 已完成 M8a～M8h 八个 Linux64 基础人格切片并通过两启动验收（M8h 时点每启动 123 个集成标记），M8 其余切片（fork/clone 完整共享矩阵、线程组、完整 siginfo、任意进程/线程组信号等）未完成（vDSO 与动态 ELF 的最小闭环已由 M9d1/M9d2 交付、共享库最小 `DT_NEEDED` 单依赖已由 M9e 交付，完整共享库/重定位与 Linux 工具运行仍未完成）；M9a/M9b/M9c 已完成并通过两启动验收（M9c 时点每启动 131 个集成标记）；M9d1（Linux64 动态 ELF/PT_INTERP：ET_DYN 主程序 + 自研 ET_EXEC 解释器 `ldcaelum`、RELATIVE 重定位与 auxv AT_PHDR/AT_ENTRY 注入）与 M9d2（真实 ET_EXEC vDSO：全局只读数据页含 magic/version/seq/hz/ticks，用户按 `AT_SYSINFO_EHDR` + ELF `e_entry` 直接调用、无符号表解析；CLOCK_MONOTONIC/BOOTTIME 由 hz/ticks 计算，CLOCK_REALTIME 明确返回 -ENOSYS）以及 M9e（真实 ET_DYN 共享库：`caelum-m9e-lib` 产出 2392 B ET_DYN，`caelum-linux-dyn` 仅以 `DT_NEEDED=/fat/m9e.so` 依赖它，库内 RELATIVE 与主程序 GLOB_DAT 由自研解释器应用；共享库无进程入口，用 `validate_for_shared_object` 校验）与 M9f（`caelum-m9f-a` 2336 B 与 `caelum-m9f-b` 1800 B 均 ET_DYN，A 的 `DT_NEEDED` 为 B、dyn 的 `DT_NEEDED` 为 m9e→A；内核把三库映射进同一地址空间，自研解释器按冻结顺序解析）已完成并通过两启动验收（每启动 **136** 个集成标记）；完整 M8 与完整 M9 未关闭，M9 其余切片（完整共享库/PLT/GOT 延迟绑定与符号解析、glibc/musl 工作负载、Linux 工具运行与设备视图等）与 M8 其余切片未完成。
> 当前切片：M9f 已完成并两启动验收（每启动 **136** 个标记；M9d1/M9d2/M9e 历史保留）；下一步为 M9 其余切片（完整共享库 PLT/GOT 延迟绑定与符号解析、glibc/musl 工作负载、Linux 工具运行）与 M8 其余切片，以及 M7c（真实 virtio-net 链路）；完整 M7/M8/M9 均未关闭。
> 本文件只记录真实进度，不代表新增设计决策。

---

## 1. 进度摘要

| 项目项 | 当前状态 |
|---|---|
| 项目名称 | 青穹 OS / CaelumOS（`OS001` 为历史代号） |
| 项目定位 | 个人开源、长期迭代的 64 位通用桌面操作系统 |
| 当前阶段 | M0 已正式关闭；M1～M6 全部已完成并验收（完整 M5、完整 M6 已关闭）；M7 已完成 M7a（内核 loopback IPv4/IPv6 UDP/TCP 自检）、M7b（原生 Socket/LocalSocket）与 M7d（Linux64 socket 人格核心）并通过两启动验收；M7c（真实 virtio-net 链路）尚未实施，完整 M7 未关闭；M8 已完成 M8a～M8h 八个切片并通过两启动验收（M8h 时点每启动 123 个集成标记）；M9a/M9b/M9c 已完成并通过两启动验收（M9c 时点每启动 131 个标记）；M9d1（Linux64 动态 ELF/PT_INTERP）、M9d2（真实 ET_EXEC vDSO）、M9e（真实 ET_DYN 共享库、`DT_NEEDED` 单依赖）与 M9f（链式三库闭包）已完成并通过两启动验收（每启动 **136** 个集成标记）；完整 M8 未完成；完整 M9 未关闭（完整共享库 PLT/GOT 重定位与工具运行未完成） |
| 设计文档 | [`agents.md`](agents.md)，架构基线 v0.2.1；S-01～S-15 已写回 |
| 架构审阅 | 人工两轮审阅、R-01～R-14 合并修订、四路智能体复核和 v0.2.1 修订均已完成；**M0 已正式关闭** |
| 实现进度 | M1～M4 + M5（M5a + M5b + M5c）+ M6（M6a1 + M6a2 + M6b1 + M6b2 + M6c）已验收；M3 落地 ACPI/MADT + xAPIC/IOAPIC、LAPIC 100 Hz 单调时钟、PS/2 键盘与 COM1 RX、双内核栈/双 canary、协作 yield 与定时抢占；M4 落地原生对象与每进程句柄表、syscall 与原生 ABI 0.1、Boot Protocol 1.1 启动模块（`/INITFS.IMG` 内 `init`/`child` 两个 ELF）、统一 ELF 装载器、init/child 用户进程；M5a 落地内核 VFS 骨架（挂载/VNode/打开文件描述）、页缓存、ramfs、三类锁域、目录变更通知，并把 M4 启动模块读取迁移到 VNode + 页缓存；M5b 落地 MCFG/ECAM 配置空间枚举与 PCI 设备发现、2 个 legacy `virtio-blk-pci`（`queue-size=128`，早期连续 DMA 预留）、FAT32（64 MiB 镜像）与 ext2（32 MiB 镜像）持久化路径，VFS 磁盘 backing 与页缓存 writeback 接通，两启动持久化数据在重启后仍可读且由 host 侧用同一套 FS 库复核；M5c 落地用户文件与目录语义（创建/读写/rename/truncate/目录枚举）、共享与私有 `mmap` 及其回写、文件锁（含关闭/进程退出释放）、扩展属性（易失，不跨重启）、稀疏文件（洞不占块，host 侧复核 32772 字节形态）、目录监视（watch）与对象销毁钩子、一次性写入/刷盘故障注入与重试/回读验证，以及进程 reap 后锁/监视/映射资源清理；M6a1 落地原生 Event 与 EventPair（manual/auto reset、`consume` 语义、`signal_pair(X)` 置对端 `X^1` 的对端端点模型）、单调时钟 Timer（绑定对象 + 绝对 deadline，时钟中断扫描到期项并唤醒 `WakeReason::Timeout`）、统一等待入口，并把 `Blocked` 做成真实进程状态（阻塞时保存 syscall 帧、唤醒后重放同一帧），init/child 各以 timer 与 event 两个标记验证，原生 ABI 升至 0.3；M6a2 落地 Channel 与 Port（有界消息队列 + 阻塞/超时接收、消息元数据与 `ERR_WOULD_BLOCK` 背压）、SharedMemory（多页共享 + 双别名映射）、EventSubscription（level/edge 触发与 readiness 重读）、Futex（wait/wake 与超时），init/child 各以 channel/port/shm/futex/subscription 五个标记交叉验证，原生 ABI 升至 0.4；M6b1 落地 SMP AP bring-up：`-smp 4` 下内核经 ACPI MADT 找到 3 个 AP，用低地址 trampoline（16→32→64 位三段）拉起 AP，AP 完成 per-CPU 初始化（GDT/IDT/TSS、per-CPU 数据、栈）后进入 IF=0 idle 循环，启动完成后释放临时低页，全部 CPU 上线后打印 `[CaelumKernel] M6b1 online=4`；M6b2 落地 SMP 调度：每 CPU 运行队列 + 受控 worker 调度（`caelum-worker` 为第三个启动模块，`MAX_PROCESSES`/`MAX_SPACES` 扩到 3）、AP 定时抢占、BSP 跨 CPU 唤醒与 reschedule IPI、受控亲和迁移与负载均衡迁移各一次，worker 阻塞/退出后 park、BSP 等待后 reap，每启动在 `M6a2 OK` 之后追加四条证据行 + 一条汇总行（runs/cpus/preempts/remote_wakes/ipis/migrations/balances），宿主侧强制阈值；M6c 落地输入和基础显示共享缓冲：内核探测真实 GOP framebuffer（`M6c display probe OK (w=…, h=…, stride=…, fmt=…)`，并在物理 FB 右下角写 magenta 探针像素），新增第四个启动模块 `gfx`（`caelum-gfx`，由内核在 AP1 上启动、接收 display/input 两个能力句柄），把 320x200 阴影（绿/蓝矩形）present 到 framebuffer 原点，随后在真实 PS/2 `d`（make 0x20 → break 0xA0）与串口 `m6c` 三个字节之后退出并打印 `M6c input OK (events=5, dropped=0)`，内核 reap 后打印 `M6c OK (events=5, dropped=0)`；宿主侧对两次启动都做 QMP `screendump`，校验右下角 magenta、`(48,48)` 绿、`(128,48)` 蓝三个真实像素（每通道 ±8），并强制 payload `events=5`/`dropped=0`；原生 ABI 升至 0.5；M7a 落地内核 loopback（基于 `libs/netcore` 的 IPv4/IPv6 UDP/TCP 自检，四条套件 + sockets live=0）；M7b 落地原生 Socket/LocalSocket（udp4/udp6/tcp4/tcp6、匿名 socketpair、路径名 unix stream/dgram、统一等待、背压/半关闭/句柄权限/错误语义，第五启动模块 `net`）；M7d 落地 Linux64 socket 人格核心（Linux syscall 入口、System V 启动栈与 auxv、IPv4/IPv6 UDP/TCP、UNIX socketpair 与命名 datagram、fd 分配/dup/close、ENOSYS/EBADF/ENOTSOCK/EMSGSIZE 负路径，第六启动模块 `linux`）；M8a 落地 Linux64 内存与文件语义（mmap/mprotect/munmap 共享与私有映射、保护位切换与读回、文件读取路径），M8b 落地时间与系统信息（`clock_gettime`/`clock_nanosleep`/`getppid`/`uname`），M8c 落地单线程/单进程信号（`rt_sigaction`/`rt_sigprocmask`、`kill`/`tgkill` self、SA_RESTORER 用户帧与 `rt_sigreturn`），M8d 落地 parent/child 双进程处理闭环（父进程与子进程经 `kill(-1)`/`tgkill` 双向信号握手，子进程恢复 `SIG_DFL` 后被 `SIGUSR1` 默认动作终止，父进程用阻塞 `wait4` 回收并校验 `WIFSIGNALED`/`WTERMSIG`，随后 `wait4(WNOHANG)` 返回 `ECHILD`；内核在 `M7d closeout` 中按进入时进程数基线校验子进程已被回收），四者均由 `services/linux-net` 打印并在内核 `M7d OK` 之前完成，每启动 116 个标记（110 + 2 + 2 + 1 + 1）；M8e 落地 Linux64 扩展文件语义（`lseek` 的 SEEK_SET/CUR/END 与负路径、`dup` 共享打开文件描述偏移、`fstat`/`statx` 一致性、`getdents64` 分片目录枚举、`fcntl` 的 FD_CLOEXEC/F_DUPFD/F_DUPFD_CLOEXEC 与未知请求负路径），打印 `[CaelumLinux] M8e files OK`；M8f 落地 futex 基础契约（值匹配/不匹配、零与短相对超时、无等待者 wake、PRIVATE 变体）与 TLS（`arch_prctl(ARCH_GET_FS/ARCH_SET_FS)` 安装/读回匿名页、FS 区与普通内存互见、恢复旧基）及 `set_tid_address`（返回 tid、`clear_child_tid` 哨兵、重复注册幂等），分别打印 `[CaelumLinux] M8f futex OK` 与 `M8f tls OK`；六个切片均在 `M7d OK` 之前完成，每启动 121 个标记（110 + 2 + 2 + 1 + 1 + 1 + 2 + 2 + 1）；M8g 落地 eventfd2 计数、poll/ppoll 就绪与超时、临时 sigmask 与信号中断返回 `EINTR`（`EINTR` 不重放），内核并把 Process 用户内核栈从 4 帧扩到 8 帧（32 KiB，`Process`=2144）以消除深层 TCP 回环投递击穿内核栈的 #DF；M8h 落地真实 `Backing::Generated` VFS 文件与 `CharDevice` 节点（`/proc/self/status` 按当前 owner 渲染 `Name: linux`/`State`/`Pid`/`PPid`/`Uid`/`Gid`/`Threads: 1`，`/proc/uptime` 输出“秒.百分秒”两字段，`/dev/null`(1,3) 与 `/dev/zero`(1,5)），并让 `/proc` 目录经 `getdents64` 列出子项；每启动 123 个标记（121 + 2）；M9a 落地 Linux 用户态扩展第一切片：timerfd（到期 read 返回计数，含超时与取消负路径）、signalfd（待处理信号转 fd 可读、sigmask 过滤）、epoll 基础 level-triggered 语义（create1/ctl/wait、EPOLLIN/EPOLLOUT 就绪报告、零/正超时），全部经真实 Linux64 syscall 入口与错误路径，分别打印 `[CaelumLinux] M9a timerfd OK`、`M9a signalfd OK`、`M9a epoll OK`；每启动 126 个标记（123 + 3）；M9b 落地 AF_UNIX abstract 命名空间（NUL 开头 abstract 地址与路径名地址并存）、`SCM_RIGHTS` fd 传递（发送方 fd → 内核对象引用 → 接收方新 fd）、`SCM_CREDENTIALS` 校验与 `EPOLLET` 边沿触发/drain，分别打印 `[CaelumLinux] M9b abstract OK`、`M9b rights OK`、`M9b credentials OK`、`M9b epoll-et OK`；每启动 131 个标记（126 + 4 + 1）；M9c 落地用户态文件锁（Linux64 人格）：同一 `linux` ELF 的 role2 锁对端，以及 VFS 三类锁域——POSIX `fcntl`（按线程组持有与关闭释放）、OFD 锁（按打开文件描述）、`flock`（独立锁域），含冲突/释放/继承负路径；打印 `[CaelumLinux] M9c locks OK`。另为 M9c 扩容 `MAX_PROCESSES = MAX_SPACES = 4`、新增第 4 个内核栈基址 `0xFFFF_FFFF_8120_0000`（812 槽 + 812 guard，复用既有页表）；M9d（Linux64 动态 ELF/PT_INTERP 与 vDSO 最小闭环）设计中；M9e 落地真实 ET_DYN 共享库：`caelum-m9e-lib`（2392 B ET_DYN，无进程入口 `e_entry=0`）与 `caelum-linux-dyn` 的 `DT_NEEDED=/fat/m9e.so` 单依赖，共享库由 `xtask` 作为第四件逐字节注入 FAT 测试盘并在两启动后复核，内核用 `validate_for_shared_object`（不要求 e_entry 在可执行段）校验、映射到冻结 bias，库内 RELATIVE 与主程序 GLOB_DAT 由自研解释器应用；M9f 落地真实链式三库闭包：`caelum-m9f-a`（2336 B ET_DYN，SONAME `/fat/m9f-a.so`，自身 `DT_NEEDED=/fat/m9f-b.so`）与 `caelum-m9f-b`（1800 B ET_DYN，SONAME `/fat/m9f-b.so`，无依赖），`caelum-linux-dyn` 的 `DT_NEEDED` 固定为 `/fat/m9e.so`→`/fat/m9f-a.so`；内核在 `m7d_closeout` 经 VFS 把三库映射进同一地址空间（冻结 bias `0x0300_0000`/`0x0380_0000`/`0x0400_0000`），自研解释器按 m9e→A→B 冻结顺序解析 SONAME（校验地址为 `bias + DT_STRTAB + soname`，首启 `m9e-soname` 失败的关键返工），A→B 的函数调用与库内自身 counter 均由 GLOB_DAT 解析，无 PLT 懒绑定/`JUMP_SLOT`；`xtask` 把 m9f-a/m9f-b 作为第五、六件逐字节注入 FAT 测试盘并在两启动后复核，用户打印 `[CaelumLinux] M9f shared OK` 于 M9e 之后、`M7d OK` 之前 |
| 构建与测试 | M1～M6、M7a/M7b/M7d、M8a～M8h 与 M9a/M9b/M9c、M9d1/M9d2 的 `cargo xtask check` 通过并保持回归（宿主单测 **1230** 个：bootinfo 24、elf64 **35**、xtask **107**、kernel lib **1064**；另有共享库独立测试 native-abi 35、block 8、fat32 37、ext2 35；`cargo fmt --all -- --check` 通过）；`cargo xtask image` 生成六模块 initramfs、含 `/INITFS.IMG` 的 ESP，并构建六个 release 注入产物（dyn 13312 B ET_DYN、interp 19256 B ET_EXEC、vdso 8808 B ET_EXEC、m9e-lib 2392 B、m9f-a 2336 B、m9f-b 1800 B，后三者均 ET_DYN 共享库），验收时逐字节注入 FAT 测试盘（initramfs 5864624 B，ESP 33 MiB，loader 116736 / kernel 10233800）；`cargo xtask test` 两启动 QEMU/OVMF 验收通过（两启动各 **136** 个标记、host 侧两阶段磁盘复核与动态 ELF/vDSO/三库六文件逐字节复核、M6b2 统计阈值校验、M7a/M7b/M7d 载荷校验、M8a～M8h 与 M9a/M9b/M9c/M9d 标记校验、两次注入与两次 screendump 像素校验；两启动日志 `target/serial-boot1.log` 10:49:39、`serial-boot2.log` 10:49:46，各 136/136 标记、`M2 #PF caught` 最后）。M4/M5/M6/M7/M8/M9 各子阶段时点的旧计数保留在 §10 与 §12/§13 的历史记录里，不回头改写 |
| Git 状态 | 项目目录尚未初始化 Git 仓库 |
| 当前目录内容 | 架构/进度文档、`docs/`、`libs/`、`loader/`、`kernel/`、`xtask/`、`tests/`、`services/`（含 `gfx`）、`tools/ovmf/`、`target/` 等工程文件 |
| 当前限制 | M1～M6 交付到“能启动、运行原生用户进程、在内存文件系统与 VFS 上用完整文件/目录语义读写，已通过 PCI/virtio-blk 在 FAT32 与 ext2 上完成跨重启持久化，具备 Event/EventPair/Timer、Channel/Port/SharedMemory/EventSubscription/Futex 与真实进程阻塞/唤醒，能在 `-smp 4` 下把全部 AP 拉起并参与受控调度（每 CPU 运行队列、定时抢占、跨 CPU 唤醒/IPI、受控亲和与负载均衡迁移），并具备真实 GOP 探测、共享缓冲 present 与键盘/串口输入闭环”的最小纵切：SMP 调度只用 3 个 AP + 2 个受控 worker 验证，**不是通用公平调度或任意进程压力验证**；M6c 只验证一个 `gfx` 受控进程与三条像素契约，**不是完整图形栈或输入子系统**；网络只有 loopback（M7a）与本地 Socket（M7b 原生、M7d Linux64 人格），无真实 virtio-net 链路（M7c 未实施）、无 DHCP/DNS/TLS，亦无完整用户态；持久化只覆盖两条最小路径与最小 VFS 语义；扩展属性为易失语义；M8 已完成 M8a～M8h 八个基础人格切片（含 procfs/devfs 最小视图），M8 其余切片（fork/clone 完整共享矩阵、线程组、完整 siginfo、任意进程/线程组信号）未完成；M9 已完成 M9a/M9b/M9c 与 M9d1/M9d2：M9d1 只覆盖 ET_DYN 主程序 + 自研 ET_EXEC 解释器的最小 `PT_INTERP`/RELATIVE 闭环（不是完整共享库/PLT/GOT/glibc 重定位；单依赖由 M9e 补最小闭环），M9d2 只覆盖真实 ET_EXEC vDSO 的入口 + 全局只读数据页（CLOCK_MONOTONIC/BOOTTIME 由 hz/ticks 计算，CLOCK_REALTIME 明确返回 -ENOSYS，不是完整 vDSO），M9e 只覆盖 `DT_NEEDED` 单依赖共享库、M9f 只覆盖链式三库闭包（两级 `DT_NEEDED`、冻结 bias/顺序、GLOB_DAT 解析；无 PLT/GOT 延迟绑定、无符号解析、无 dlopen/dlsym 与 glibc/musl）；M9 其余切片（完整共享库 PLT/GOT 重定位、glibc/musl 工作负载与 Linux 工具运行、Linux 设备视图等）未完成；M7c 未实施；完整 M7/M8/M9 均未关闭 |

**一句话结论：** M1～M6 全部已完成，M7 已完成 M7a/M7b/M7d，M8 已完成 M8a～M8h，M9 已完成 M9a/M9b/M9c、M9d1/M9d2、M9e 与 M9f，均在真实 QEMU/OVMF 中通过两启动验收（每次两启动、**每启动 136 个集成标记** = M1～M5 的 56 个 + M6a1 4 个 + M6a2 10 个 + M6b1 1 个 + M6b2a 1 个 + M6b2 5 个 + M6c 5 个 + M7a 6 个 + M7b 14 个 + M7d 8 个 + M8a 2 个 + M8b 2 个 + M8c 1 个 + M8d 1 个 + M8e 1 个 + M8f 2 个 + M8g 2 个 + M8h 2 个 + M9a 3 个 + M9b 4 个 + M9c 1 个 + M9d1 2 个 + M9d2 1 个 + M9e 1 个 + M9f 1 个；`M2 #PF caught` 最后；磁盘两阶段复核、统计阈值、载荷校验、动态 ELF 六文件（dyn/interp/vdso 与三库 `/fat/m9e.so`、`/fat/m9f-a.so`、`/fat/m9f-b.so`）的宿主逐字节复核全部保留）；M7c（真实 virtio-net 链路）尚未实施，完整 M7 未关闭；完整 M8 与完整 M9 未关闭（M9 其余切片：完整共享库 PLT/GOT 重定位、glibc/musl 工作负载与 Linux 工具运行、Linux 设备视图等未完成）。本文档末尾已给出可直接交给下一个 Agent 的 M9/M8 其余切片与 M7c 接手 Prompt。

---

## 2. 已完成的工作

### 2.1 需求与关键决策确认

已通过两轮提问确认产品定位、内核形态、语言、兼容路线、驱动模型、引导方式、文件系统策略和 ABI 演进策略。所有决策均记录在 [`agents.md`](agents.md) 第 1 节的决策表中。

### 2.2 内核总体设计初稿

已完成 [`agents.md`](agents.md)，覆盖：

- 设计目标、非目标与“轻量化”的可度量定义。
- 务实混合内核的内核态/用户态边界与强制依赖方向。
- 自研 UEFI Loader、版本化 `BootInfo` 和启动交接协议。
- x86-64 优先、arm64 预留的 arch/platform/machine 分层。
- 物理内存、虚拟内存、地址空间、DMA 与共享内存。
- 进程、线程、SMP 调度、同步原语和等待机制。
- 能力句柄对象模型、权限、身份、安全与资源配额。
- 原生 syscall ABI、人格分发、vDSO 和版本策略。
- IPC（Channel、Port、Event、共享内存）。
- 内核态 VFS、页缓存、文件系统插件接口和存储栈。
- 设备模型、版本化驱动 DDI、I/O 请求、中断、DMA 和用户态驱动预留。
- 网络协议栈边界、图形/输入/音频的内核边界。
- Linux x86-64 ELF 人格层、Wine 路线和 IA-32/WoW64 预留。
- 安全、隔离、电源、诊断、仓库结构和工程约束。
- M0～M13 分阶段路线、测试体系、风险对策和架构验收清单。

### 2.3 技能检查与安装

- 检查了本地新增技能。
- 安装了 `os-dev-scratch`，用于后续核查 x86-64 启动、长模式、页表、IDT、APIC 和帧分配路线。
- 本地 `nt5x-*` 技能已检查，它们面向既有 NT 5.2 源码树，只适合作为对象管理和驱动分层的对照资料，不是本项目的实现指南。

### 2.4 第一遍架构初审

已完成一次针对以下方面的静态审阅：

- 启动交接和 Boot Protocol 的自洽性。
- 内存、对象、ABI 和模块边界。
- Linux/Wine 实际依赖。
- arm64 和 32 位兼容预留。
- 阶段依赖与验收顺序。

审阅结论：**没有发现必须推翻已确认关键决策的问题**；发现的问题属于接口细化、兼容依赖补充和实现安全边界，详见第 4 节。

### 2.5 第二遍架构交叉审阅

已重新通读 `agents.md`，重点交叉检查：

- 里程碑交付物与验收标准的前置依赖。
- 原生进程/对象模型对 Linux `clone`、信号和 `epoll` 语义的承载能力。
- 用户缓冲区 ABI 的取得、验证与使用顺序。
- VFS 文件锁、Linux 图形/音频/Wine 路线和 M0 验收口径。

第二遍新增 R-07～R-14，详见第 4.2 节。该轮只做静态审阅和进度记录，没有修改 `agents.md`，也没有产生实现或测试结论。

### 2.6 架构 v0.2 修订

在项目所有者允许进入设计修订后，已将 R-01～R-14 合并到 `agents.md`，并把文档更新为 **v0.2 审阅修订稿**。本轮仍然只修改设计文档和进度记录，没有进入实现。

主要修订：

- 补全 BootInfo 校验、内核镜像协议需求元数据、双地址入口 ABI 和初始页表覆盖规则。
- 明确 M4 的初始句柄传递范围，以及早期启动模块到 M5 VFS 的迁移边界。
- 引入线程、线程组和可共享资源的显式模型，为 Linux `clone` 预留共享矩阵。
- 增加输入快照、输出原子 copy-out 和零复制 pin 规则，关闭 double fetch 漏洞。
- 增加时间子系统、随机数与熵子系统、EventSubscription、本地 Socket 和 `SCM_RIGHTS`/`SCM_CREDENTIALS`。
- 补充驱动卸载静默、模块资源归属和跨模块 panic 边界。
- 明确 Wine 前置依赖、`epoll` 就绪语义和 POSIX/OFD/`flock` 文件锁差异。
- 将第 27 节改为“架构覆盖清单”，新增 M0 关闭条件，并更新 M1～M10 验收口径。

### 2.7 架构 v0.2.1 修订

在项目所有者许可后，使用四个并行代理完成 v0.2.1 修订（其中三路分别修改启动链路、核心对象/服务范围并同步进度，另一路做只读复核），将智能体并行复核发现的 S-01～S-15 全部写回 `agents.md`，文档更新为 **v0.2.1**。本轮只做澄清、归属和验收口径修订，没有改变第 1 节任何已确认关键决策，也没有进入实现。

主要修订：

- 明确初始页表覆盖内核镜像全部装载段、BootInfo 校验失败的最小报告路径和必需 TLV/校验算法定义责任。
- 明确 GOP framebuffer 与 MMIO 串口的早期映射责任。
- 补充 Process/ThreadGroup/Job 映射、exec 线程组规则、线程组级信号 pending 和每线程人格规则。
- 明确 FdTable 双编号空间、`CLONE_FILES` 共享范围和 Credentials/Token 术语映射。
- 统一 LocalSocket 归属、POSIX/OFD/`flock` 锁的确定语义和冲突规则。
- 为时间子系统、`rng` 子系统和 IPC 原语补充分阶段里程碑归属。
- 同步风险表、核心需求、仓库树说明和测试矩阵的编辑性缺口。

---

## 3. 已确认的关键决策快照

| 决策点 | 已确认方案 |
|---|---|
| 系统定位 | 通用桌面操作系统 |
| 位数 | 64 位内核与原生 64 位用户态 |
| 首选架构 | x86-64 |
| 后续架构 | arm64，仅预留 |
| 内核形态 | 务实混合内核 |
| 内核态服务 | 核心机制、VFS、存储、网络、基础驱动 |
| 用户态服务 | 会话、图形、软件包、系统管理及多数服务 |
| 实现语言 | Rust + 少量汇编 |
| 资源模型 | 能力句柄 |
| 原生 ABI | 独立、版本化；1.0 前允许受控破坏 |
| 引导方式 | 自研 UEFI Loader，不以 Legacy BIOS 为主线 |
| Linux 兼容 | Linux 人格层，直接运行 x86-64 Linux ELF |
| Windows 兼容 | Wine，运行在 Linux 用户态兼容层上 |
| Windows 内核子系统 | 不实现原生 NT/Win32 子系统 |
| 32 位软件 | 当前不实现，预留 IA-32 与 Wine WoW64 |
| 驱动路线 | 内核模块先行，预留用户态驱动 |
| 文件系统 | VFS + 现有文件系统先行 |
| 验证环境 | QEMU/OVMF 先行，后续真实 UEFI 硬件 |

这些决策如需修改，必须先取得项目所有者明确同意，并记录 ADR。

---

## 4. 审阅发现与修订状态

R-01～R-06 来自第一遍初审，R-07～R-14 来自第二遍交叉审阅。以下保留原始问题和建议作为审阅历史；**这些问题均已合并到 `agents.md` v0.2，并经 v0.2.1 进一步澄清**，后续处理口径见第 4.3 节。

| 编号 | 优先级 | 问题 | 影响 | 建议处理 |
|---|---|---|---|---|
| R-01 | P1，进入 M1 前必须解决 | 启动交接只说明通过寄存器传入 BootInfo 物理地址，但未完整定义内核入口时该结构如何被虚拟映射和访问 | Loader 与内核可能对同一地址产生不同解释，造成早期启动故障 | 在入口 ABI 中明确 BootInfo 物理地址与早期虚拟地址的双参数或固定映射约定；明确初始页表必须覆盖的结构；增加内核所需 Boot Protocol 版本的镜像元数据供 Loader 预检 |
| R-02 | P1，进入 Linux GUI/Wine 前必须解决 | 未明确列出本地 Socket、`socketpair`、`AF_UNIX`、`SCM_RIGHTS` fd 传递和 `SCM_CREDENTIALS` | Linux 图形栈、显示服务以及 Wine/wineserver 的关键进程间通信缺少基础，后期补会导致对象和 IPC 接口返工 | 在 IPC/网络章节明确本地 Socket 与 fd 传递；把它列为 Linux 用户态和 Wine 的关键验收依赖 |
| R-03 | P2 | 时间管理只有零散提及，没有独立的 clocksource、单调/实时时钟、per-CPU timer、tickless 和 vDSO 一致性设计 | 调度、超时、文件时间戳、Wine QPC 和 Linux `clock_gettime` 的语义容易不一致 | 补充时间子系统接口与不变量，明确 TSC 检测、时钟源切换和用户态读取一致性；协调“第一阶段日志带时间戳”与 M3 才建立时钟路线的先后关系 |
| R-04 | P2 | 随机数与熵子系统没有独立设计位置，Linux `getrandom` 与 `AT_RANDOM` 只被间接提到 | 安全启动随机化、ASLR、TLS、Wine 和用户态密码学可能缺少可靠熵来源 | 增加 CRNG/熵源、早期熵不足时的行为、`getrandom` 语义和硬件随机数接口 |
| R-05 | P2 | 驱动 DDI 缺少卸载静默、内存分配归属和跨模块 panic 边界的明确规则 | 模块卸载或 panic 可能留下 IRQ/DMA/回调，导致释放后使用或内核崩溃 | 规定卸载前必须停止设备、注销 IRQ、完成 DMA 和排空回调；分配与释放必须使用成对 DDI；禁止展开跨模块边界 |
| R-06 | P3 | 存在少量术语和排版问题，例如“能力句柄”与 Linux capabilities 可能混淆、局部多余空格和措辞不一致 | 降低文档可读性，增加后续代理误解概率 | 做一次编辑性整理，不改变任何已确认决策 |
| R-07 | P1，M4 设计定形前解决 | M4 验收要求用户进程“传句柄”，但 Channel 到 M6 才交付，M4 使用何种传递机制没有定义 | 可能提前实现一套临时 IPC，或在 M6 重写 M4 的对象/消息路径 | 明确 M4 只允许进程创建时传递初始句柄，还是把最小 Channel 提前；同步调整 M4/M6 交付与验收 |
| R-08 | P1，M4 设计定形前解决 | M4 要从 initramfs 加载 ELF，但完整 VFS 到 M5 才交付，早期只读启动模块接口与后续 VFS 的边界不清 | 容易形成两套路径解析、文件读取或 ELF 加载实现 | 规定 M4 的最小只读 initramfs/启动模块接口，并复用同一 ELF 装载器；明确 M5 如何演进为挂载、VNode 和页缓存模型 |
| R-09 | P1，最迟 M8 前解决，宜在 M4 对象模型定形时预留 | 进程把地址空间、fd、凭据、命名空间和线程组集中为一个整体，未说明 Linux `clone` 各标志所需的独立共享关系；凭据和信号 pending 的归属也未完整展开 | 难以准确表达 `CLONE_VM`、`CLONE_FILES`、`CLONE_SIGHAND`、线程组及每线程凭据，后期可能重构核心进程模型 | 将可共享资源建模为有独立生命周期的引用对象，明确 thread/thread-group/process 的关系、每线程凭据及进程/线程定向信号；建立 `clone/fork/exec` 共享矩阵 |
| R-10 | P1，M4 原生 ABI 实现前解决 | “只读取调用者声明且内核支持的字段，避免双取”不足以防止 double fetch；用户仍可在校验后修改原缓冲区 | 校验值与实际使用值不一致，可能造成越界、权限绕过或内核内存破坏 | 输入结构必须一次复制到内核拥有的快照，随后只验证和使用该快照；零复制路径必须另行定义 pin、生命周期和并发访问规则 |
| R-11 | P1，进入 M10 前解决 | M6 只承诺基础输入和简单用户显示，M10 却要求 Wine GUI/网络及显示/音频集成；DRM/evdev/ALSA、显示服务和音频服务的前置阶段未明确 | M10 实际范围远大于一个垂直切片，依赖容易在 Wine 调试时集中暴露 | 将本地 IPC、Linux 设备视图、共享缓冲/fence、用户显示与音频服务拆成明确前置交付；控制台、软件渲染 GUI、音频和硬件加速分别验收 |
| R-12 | P2，M9 前解决 | “等待多对象”不足以完整表达 `epoll`；持久订阅、就绪状态、水平/边沿触发及 `dup` 后兴趣列表语义未定义 | Linux 事件循环可能出现丢事件、重复唤醒或与打开文件描述生命周期不一致 | 明确等待原语与事件订阅对象的边界，规定 readiness 缓存、注册/注销、触发模式及打开文件描述共享语义，并添加回归测试 |
| R-13 | P2，M9/M10 前解决 | VFS 只笼统列出文件锁，没有区分 POSIX `fcntl` 锁、OFD 锁和 `flock` 的所有权及冲突语义 | Linux 应用和 Wine 可能出现锁丢失、错误继承或关闭 fd 时意外释放锁 | 明确三类锁的归属、继承、冲突、关闭释放和打开文件描述关系，纳入兼容测试 |
| R-14 | P2，关闭 M0 前解决 | 第 27 节验收清单全部标记为已完成，但 R-01 仍指出 BootInfo 入口约定不完整，且 M0 尚未关闭 | “已覆盖”“已明确”和“审阅通过”被混为一体，进度判断相互矛盾 | 将第 27 节改为架构覆盖清单，或在问题关闭前取消相应勾选；为 M0 增加可核对的审阅通过条件 |

### 4.1 初审判断

- 混合内核边界、原生 ABI + Linux 人格层、Wine 复用 Linux 用户态这三条主线相互一致。
- x86-64 先行、arm64 预留的方式在架构上成立，但必须持续防止 x86 细节渗入通用层。
- IA-32/WoW64 预留点的方向正确；当前没有实现承诺。
- 自研 UEFI Loader 是当前最关键的技术风险点，M1 必须严格控制范围。
- 现有 Linux 兼容清单足以支撑基础人格开发，但本地 IPC/fd 传递是明显缺口。
- 上述问题均不需要改变已确认的产品或架构方向。

### 4.2 第二遍审阅判断

- 新增问题主要是阶段边界和语义承载能力缺口，不要求改变已确认的产品方向、内核形态或兼容路线。
- R-01 是进入 M1 的直接阻塞项；R-07～R-10 虽不一定阻塞 M1，但应在相应核心对象和 ABI 定形前解决，避免后续返工。
- R-09 不表示当前模型无法实现 Linux，而是表示共享关系和所有权尚未被明确到可验证的程度。
- R-11 与 R-02 共同表明，Wine 里程碑需要把用户态服务和本地 IPC 前置依赖显式化。
- 第二遍仍未发现必须推翻关键决策的问题；M0 不能在这些问题未修订或未明确接受前视为正式关闭。

### 4.3 v0.2 修订状态

| 编号 | v0.2 处理位置 | 状态 |
|---|---|---|
| R-01 | `agents.md` 第 5.3、5.4、5.5 节 | 已合并：BootInfo 校验、镜像协议需求元数据、双地址入口 ABI、初始页表覆盖和 CPU 特性复核规则 |
| R-02 | `agents.md` 第 11、14、17.2 节 | 已合并：本地 Socket、`socketpair`、`AF_UNIX`、`SCM_RIGHTS` 和 `SCM_CREDENTIALS` |
| R-03 | `agents.md` 第 8.4、20.1 节 | 已合并：时钟域、clocksource、per-CPU 定时器、tickless、vDSO 一致性和早期时间戳策略 |
| R-04 | `agents.md` 第 9.5 节 | 已合并：熵状态、CRNG、安全随机阻塞/失败策略和硬件随机数健康检查 |
| R-05 | `agents.md` 第 13.2 节 | 已合并：卸载静默、资源成对释放、卸载失败回滚和跨模块 panic 边界 |
| R-06 | `agents.md` 第 9.4 节及全文编辑 | 已合并：区分能力句柄与 Linux capabilities，并清理术语和排版 |
| R-07 | `agents.md` 第 8.1 节及 M4/M6 验收 | 已合并：M4 仅使用进程创建参数传递初始句柄，Channel 仍到 M6 |
| R-08 | `agents.md` 第 5.6 节及 M4/M5 验收 | 已合并：最小只读启动模块、同一 ELF 装载器和 M5 到 VFS 的迁移要求 |
| R-09 | `agents.md` 第 8.1 节 | 已合并：线程组、线程和可共享资源模型及 Linux `clone` 映射要求 |
| R-10 | `agents.md` 第 10.1 节 | 已合并：输入一次快照、输出原子 copy-out、零复制 pin 和生命周期规则 |
| R-11 | `agents.md` 第 17.2 节及 M9/M10 验收 | 已合并：Wine 前置依赖拆分，控制台、软件渲染 GUI、网络和音频分步验收 |
| R-12 | `agents.md` 第 11.1、11.2 节 | 已合并：EventSubscription、readiness 缓存、触发模式及对象生命周期语义 |
| R-13 | `agents.md` 第 12.1 节 | 已合并：POSIX `fcntl`、OFD 和 `flock` 的所有权、继承、冲突与关闭释放规则 |
| R-14 | `agents.md` 第 27、27.1 节 | 已合并：改为覆盖清单并新增 M0 关闭条件 |

### 4.4 智能体团队并行复核发现（已写回 v0.2.1）

项目所有者开启 swarm mode 后，使用四路并行审阅代理分别检查启动链路、核心对象与 ABI、服务与兼容、阶段与验收范围。四路复核均已恢复并完成；其中一路曾因额度暂时失败，恢复后已完成。总体结论：**未发现 M0 关闭阻塞项，也未发现需要改变已确认关键决策的问题**。

以下 15 项为新增细化建议，**均已写回 `agents.md` v0.2.1**：

| 编号 | 建议级别 | 问题 | 建议处理 | 状态 |
|---|---|---|---|---|
| S-01 | P1，M1 设计定形前 | 初始页表覆盖规则中的“入口代码”可能被窄读为只映射入口桩函数 | 改为覆盖内核镜像全部装载段（含入口代码），或明确引用内核范围 TLV | 已写回 v0.2.1 |
| S-02 | P1，M1 设计定形前 | BootInfo 校验失败时，内核侧失败信息依赖尚未验证的串口 TLV，报告路径存在自举矛盾 | 定义最小失败输出能力，并区分 Loader 侧失败与内核侧失败职责 | 已写回 v0.2.1 |
| S-03 | P2，M1 规范阶段 | “必需 TLV”集合、必需性随版本/标志变化规则和校验和算法尚未具体定义 | 在 Boot Protocol 规范中列出必需 TLV 表并固定校验算法 | 已写回 v0.2.1 |
| S-04 | P2，M1/M11 前 | GOP framebuffer 和 MMIO 串口是否由 Loader 纳入初始页表，或由内核早期自建映射尚未明确 | 明确早期诊断显示的映射责任与最小硬件前提 | 已写回 v0.2.1 |
| S-05 | P2，M0 关闭前建议处理 | Process 与 ThreadGroup 的对应关系、exec 时线程组语义仍未显式定义 | 增加 Process/ThreadGroup/Job 映射和 exec 线程组规则 | 已写回 v0.2.1 |
| S-06 | P2，M0 关闭前建议处理 | 线程组级信号 pending 队列归属未定义，只写了线程私有 pending | 补充分组定向信号的 pending、递交和唤醒规则 | 已写回 v0.2.1 |
| S-07 | P2，M0 关闭前建议处理 | 人格绑定被列为线程组资源，但每线程人格和 exec 重定人格之间存在表述张力 | 统一“人格默认随线程组、exec 时重定、生效值为每线程属性”等明确规则 | 已写回 v0.2.1 |
| S-08 | P3 | FdTable 同时容纳原生句柄代次和 Linux fd 最小可用编号，二者共存规则未说明；Credentials/Token 命名也需对应 | 明确双编号空间、`CLONE_FILES` 共享范围和术语映射 | 已写回 v0.2.1 |
| S-09 | P2，M0 关闭前建议处理 | LocalSocket 在 `net` 模块和 IPC 原语列表中的归属不一致 | 明确“由 `net` 实现、作为可等待对象接入 IPC”或等价边界 | 已写回 v0.2.1 |
| S-10 | P2，M0 关闭前建议处理 | POSIX 锁关闭释放仍写“可能触发”，且 `flock` 与其他锁族的冲突规则只是元要求 | 改成确定语义，并补齐 `flock` 冲突规则或明确暂缓 | 已写回 v0.2.1 |
| S-11 | P2，M0 关闭前建议处理 | 时间子系统没有明确里程碑归属；RPC 超时依赖的单调时钟和原生 Timer 在 M3～M8 间无人认领 | 明确 M3 是否交付最小单调时钟/Timer，以及 vDSO 之外的阶段边界 | 已写回 v0.2.1 |
| S-12 | P2，M0 关闭前建议处理 | `rng` 子系统没有里程碑归属；BootInfo 熵 TLV、ASLR、`AT_RANDOM` 和 getrandom 的实现阶段不清 | 把最小熵状态、CRNG 和 Linux getrandom 分阶段挂到 M1～M8 | 已写回 v0.2.1 |
| S-13 | P2，M0 关闭前建议处理 | Port、EventPair、原生 SharedMemory、原生 LocalSocket 与 Linux AF_UNIX 的交付归属不完整 | 为 11.1 的原语列表补充分阶段交付矩阵 | 已写回 v0.2.1 |
| S-14 | P3 | 风险表、26.2 核心需求、仓库树粒度说明和 27.1 的“本文档中的审阅发现问题”指代未完全同步 v0.2 | 做编辑性同步，点名 R/S 问题所在文件并补 user-driver 预留占位说明 | 已写回 v0.2.1 |
| S-15 | P3 | 安全与网络测试矩阵仍有小缺口，如 KPTI/返回用户态缓解、seccomp 有界执行、loopback、AF_UNIX abstract 命名空间和 16.3 syscall 阶段标注 | 在测试矩阵和对应章节补充明确项；不阻塞 M0 | 已写回 v0.2.1 |

处置说明：S-01～S-15 已通过 v0.2.1 修订全部写回 `agents.md`；本轮只做澄清、归属和验收口径修订，没有改变第 1 节任何已确认关键决策。现等待项目所有者确认 v0.2.1 并正式关闭 M0。

---

## 5. 阶段状态

| 阶段 | 状态 | 说明 |
|---|---|---|
| 需求澄清 | 已完成 | 关键选择已由项目所有者确认 |
| 总体架构设计 | v0.2.1 修订完成 | [`agents.md`](agents.md) v0.2.1；R-01～R-14 和 S-01～S-15 均已写回 |
| 架构审阅 | 人工审阅、四路智能体复核和 v0.2.1 修订均已完成 | R-01～R-14、S-01～S-15 均已写回 `agents.md` |
| 设计定稿 | 已冻结 | v0.2.1 已由项目所有者确认 |
| M0 架构基线 | **已正式关闭** | `agents.md` 第 27.1 节条件已由项目所有者确认 |
| M1 UEFI 启动闭环 | **已完成并验收** | QEMU/OVMF 成功路径、`bootreq` 拒启负例和 BootInfo 校验失败负例均已复验 |
| M2 异常与内存 | **已完成并验收** | GDT/IDT/TSS、PMM、内核堆、高半核 VM 和故意缺页诊断均通过 `cargo xtask test` |
| M3 中断与线程 | **已完成并验收** | ACPI/MADT + xAPIC/IOAPIC、PIT 校准的 LAPIC 100 Hz 单调时钟、PS/2 键盘与 COM1 RX、双内核栈/双 canary、A 协作 yield + B 定时抢占；`cargo xtask test` 自动注入 PS/2 `a` 与串口 `C` 并通过 17 个标记 |
| M4 原生对象与首个用户进程 | **已完成并验收** | 原生对象与每进程句柄表、syscall 入口与原生 ABI 0.1、Boot Protocol 1.1 启动模块、统一 ELF 装载器、init/child 用户进程；M4 时点 `cargo xtask test` 27 个标记全绿，末尾仍为 M2 故意 #PF（当期总计 33 个） |
| M5a VFS/页缓存/ramfs 与启动模块迁移 | **已完成并验收** | 内核 VFS 骨架（挂载/VNode/打开文件描述）、页缓存、ramfs、三类锁域与目录变更通知；`image.rs` 经 VFS 装载 init/child，M4 启动模块读取路径迁移到 VNode + 页缓存（无并行装载路径）；`cargo xtask test` 33 个标记全绿（含 6 个 M5a 标记），末尾仍为 M2 故意 #PF |
| M5b 持久化与块设备（MCFG/PCI/virtio-blk/FAT32/ext2） | **已完成并验收** | MCFG/ECAM 配置空间枚举与 PCI 设备发现、2 个 legacy `virtio-blk-pci`（`queue-size=128`，早期连续 DMA 预留 2 帧）、FAT32（64 MiB 空盘，spc=1 ≈129k clusters，满足规范下限）与 ext2（32 MiB）持久化、VFS 磁盘 backing + 页缓存 writeback；`cargo xtask test` 两启动各 41 个标记全绿（33 回归 + 8 M5b，M5b 时点；M5c 完成后为每启动 56 个），host 侧两阶段复核磁盘内容，末尾仍为 M2 故意 #PF |
| M5c 用户文件/目录语义与故障注入 | **已完成并验收** | 用户态文件与目录语义（create/read/write/rename/truncate/目录枚举）、共享与私有 `mmap`（含回写与私有页不落盘）、文件锁（含关闭/进程退出释放）、扩展属性（易失）、稀疏文件（洞不占块）、目录监视（watch）与对象销毁钩子、一次性写入/刷盘故障注入与重试/回读、进程 reap 后锁/监视/映射资源清理；`cargo xtask test` 两启动各 **56** 个标记全绿（48 回归 + 8 M5c3），host 侧在首启与二启后都复核 32772 字节稀疏文件与 16 字节故障回读文件，末尾仍为 M2 故意 #PF |
| M6a1 原生 Event/EventPair/Timer 与真实阻塞 | **已完成并验收** | 原生 Event（manual/auto reset、`signal`/`reset`/`consume`）与 EventPair（`signal_pair(X)` 置对端 `X^1` 的对端端点语义）、单调时钟 Timer（绑定对象 + 绝对 deadline，时钟中断扫描到期项并 `wake_object(WakeReason::Timeout)`）；`Blocked` 成为真实进程状态（阻塞时保存 syscall 帧、唤醒后重放同一帧），统一等待入口接通对象唤醒；原生 ABI 升至 0.3；`cargo xtask test` 两启动各 **60** 个标记全绿（56 回归 + 4 M6a1：init `timer OK`/`event OK`、child `event OK`、kernel `M6a1 OK`），末尾仍为 M2 故意 #PF |
| M6a2 Channel/Port/SharedMemory/EventSubscription/Futex | **已完成并验收** | 有界消息 Channel 与 Port 端点（阻塞/超时接收、消息元数据、队列满返回 `ERR_WOULD_BLOCK` 背压）、SharedMemory（多页共享 + 双别名映射）、EventSubscription（level/edge 触发、readiness 重读与 drain 后复位）、Futex（wait/wake 与超时）；init/child 两侧交叉验证；原生 ABI 升至 0.4；`cargo xtask test` 两启动各 **70** 个标记全绿（60 回归 + 10 M6a2：init/child 各自的 channel/port/shm/futex/subscription 共九条 + kernel `M6a2 OK`），末尾仍为 M2 故意 #PF |
| M6b1 SMP AP bring-up 与每 CPU 初始化 | **已完成并验收** | `-smp 4` 下内核经 ACPI MADT 识别 3 个 AP，用低地址 trampoline（16→32→64 位三段、GDT/页表补丁）拉起 AP；每个 AP 完成 per-CPU 初始化（GDT/IDT/TSS、per-CPU 数据与栈）后进入 IF=0 idle 循环，启动完成后释放临时低页；全部 CPU 上线后打印 `[CaelumKernel] M6b1 online=4`（位于 `M3 OK` 之后、`M4 objects OK` 之前，只证明 AP 上线，**不包含**每 CPU 运行队列、负载均衡、CPU 亲和性、IPI 与 AP 调度）；`cargo xtask test` 两启动各 **71** 个标记全绿（70 回归 + 1 条 M6b1），host 侧 M5b/M5c 两阶段复核全部保留，末尾仍为 M2 故意 #PF |
| M6b2 每 CPU 运行队列、定时抢占与跨 CPU 唤醒 IPI | **已完成并验收** | 在 M6b1 已上线的多核之上实现每 CPU 运行队列与受控 worker 调度（`caelum-worker` 第三个启动模块、`MAX_PROCESSES`/`MAX_SPACES`=3）、AP 定时抢占、BSP 跨 CPU 唤醒与 reschedule IPI、受控亲和迁移与负载均衡迁移（两次独立事件）；worker 阻塞/退出后 park，BSP 等待后 reap；`cargo xtask test` 两启动各 **77** 个标记全绿（71 回归 + M6b2a 1 + M6b2 5），宿主强制统计阈值，末尾仍为 M2 故意 #PF |
| M6c 输入和基础显示共享缓冲 | **已完成并验收** | 内核探测真实 GOP framebuffer（`M6c display probe OK (w=1280, h=800, stride=1280, fmt=1)`），在物理 framebuffer 右下角写 magenta 探针像素；新增第四个启动模块 `gfx`（`caelum-gfx`），由内核在 AP1 上启动并接收 display/input 两个能力句柄，把 320x200 阴影（绿/蓝矩形）present 到 framebuffer 原点并打印 `M6c display OK`；收到真实 PS/2 `d`（make 0x20 → break 0xA0）与串口 `m6c` 三个字节后退出并打印 `M6c input OK (events=5, dropped=0)`，内核 reap 后打印 `M6c OK (events=5, dropped=0)`；宿主对两次启动各做 QMP `screendump` 并校验三个真实像素（右下角 magenta、`(48,48)` 绿、`(128,48)` 蓝，±8），强制 payload `events=5`/`dropped=0`；`cargo xtask test` 两启动各 **82** 个标记全绿（77 回归 + 5 M6c），原生 ABI 升至 0.5，末尾仍为 M2 故意 #PF |
| M7a 内核 loopback | **已完成并验收** | 基于 `libs/netcore` 的内核 loopback IPv4/IPv6 UDP/TCP 自检（4 条套件，往返字节数分别 7/14），`M7a sockets OK (live=0)` 证明套件退出后无存活 Socket；`M7a OK (suites=4)` 收尾；两启动各 **88** 标记（82 回归 + 6 M7a），末尾仍为 M2 故意 #PF |
| M7b 原生 Socket/LocalSocket | **已完成并验收** | 原生 Socket 与 LocalSocket：IPv4/IPv6 UDP/TCP、匿名 `socketpair`、路径名 unix stream/dgram、统一等待（ready/timeout）、`ERR_WOULD_BLOCK` 背压、半关闭 EOF、句柄权限与错误语义（too_large/not_found/exists/peer_closed）；第五个启动模块 `net`（`caelum-net`）；两启动各 **102** 标记（88 + 14 M7b），内核 verdict `[CaelumKernel] M7b OK (sockets=0, bindings=0)`；末尾仍为 M2 故意 #PF |
| M7d Linux64 socket 人格核心 | **已完成并验收** | Linux64 人格：Linux `syscall` 入口与 `-errno`、System V 启动栈与 auxv（`AT_CAELUM_CHANNEL`/`AT_CAELUM_NETNS`）、IPv4/IPv6 UDP/TCP、UNIX stream/datagram `socketpair` 与命名 datagram、fd 最低可用分配/`dup` 共享/`close` 释放、负路径 `ENOSYS`/`EBADF`/`ENOTSOCK`/`EMSGSIZE`；第六个启动模块 `linux`（`caelum-linux-net`）；两启动各 **110** 标记（102 + 8 M7d），内核 verdict `[CaelumKernel] M7d OK (sockets=0, bindings=0)`；末尾仍为 M2 故意 #PF |
| M7c 真实网络链路 | **尚未实施** | 真实 `virtio-net` 设备链路（legacy 设备 + 中断路径）、QEMU user-net 连通与异常恢复（link down/up）尚未实现；M7a/M7b/M7d 的 loopback 与本地 Socket 验收**不能**替代真实 NIC 链路验收，完整 M7 未关闭 |
| M8a Linux64 内存与文件语义 | **已完成并验收** | Linux64 人格的 mmap/mprotect/munmap（共享与私有映射、保护位切换与读回）与文件读取路径；用户程序打印 `[CaelumLinux] M8a memory OK` 与 `M8a files OK`；两启动各 **112** 标记（110 + 2），末尾仍为 M2 故意 #PF |
| M8b Linux64 时间与系统信息 | **已完成并验收** | Linux64 人格的 `clock_gettime`、`clock_nanosleep`、`getppid`、`uname`；用户程序打印 `[CaelumLinux] M8b time OK` 与 `M8b info OK`；两启动各 **114** 标记（112 + 2），末尾仍为 M2 故意 #PF |
| M8c Linux64 信号（单线程/自信号） | **已完成并验收** | Linux64 人格的 `rt_sigaction`/`rt_sigprocmask`、`kill`/`tgkill` self、SA_RESTORER 用户帧与 `rt_sigreturn`；用户程序打印 `[CaelumLinux] M8c signals OK`；两启动各 **115** 标记（114 + 1）；只覆盖单线程/单进程自信号，跨进程/跨线程投递与完整 siginfo 未实现 |
| M8d Linux64 parent/child 双进程处理闭环 | **已完成并验收** | parent（detached 测试根，`getppid()==0`）与 child（内核 `spawn_linux_child` 创建、与 parent 同在 AP1）经 `kill(-1)`/`tgkill` 完成双向信号握手；child 恢复 `SIG_DFL` 后被 `SIGUSR1` 默认动作终止，parent 用阻塞 `wait4` 回收并校验 `WIFSIGNALED`/`WTERMSIG==SIGUSR1`，随后 `wait4(WNOHANG)` 返回 `ECHILD`；内核在 `M7d closeout` 中按进入时进程数基线校验子进程已被回收。仅 parent 打印一次 `[CaelumLinux] M8d process OK`；两启动各 **116** 标记（115 + 1）。边界：只覆盖受控 parent/child 双进程闭环与 `kill/tgkill/wait4`，不是任意进程/线程组或完整信号语义 |
| M8e Linux64 扩展文件语义 | **已完成并验收** | `services/linux-net` stage 13（`STAGE_FILES_EXTRA`）：lseek SEEK_SET/CUR/END 与负路径、dup 共享打开文件描述偏移、fstat/statx、getdents64 分片目录枚举、fcntl FD_CLOEXEC/F_DUPFD/F_DUPFD_CLOEXEC 与未知请求负路径；打印 `[CaelumLinux] M8e files OK`，每启动 119 个集成标记 |
| M8f futex 与 TLS | **已完成并验收** | `services/linux-net` stage 14/15：futex 值匹配/不匹配、零与短相对超时、无等待者 wake 与 PRIVATE 变体；TLS 经 arch_prctl(ARCH_GET_FS/ARCH_SET_FS) 安装匿名页、FS 区与普通内存互见、恢复旧基；set_tid_address 返回 tid、`clear_child_tid` 哨兵与重复注册幂等；分别打印 `[CaelumLinux] M8f futex OK`/`M8f tls OK`，每启动 119 个集成标记 |
| M8g eventfd 与 poll/ppoll | **已完成并验收** | `services/linux-net` stage 16/17：eventfd2 计数与读写、poll/ppoll 就绪/超时、临时 sigmask（`ppoll` 的 sigmask 仅在调用期间生效）与信号中断返回 `EINTR`（`EINTR` 不重放）；内核同时把 Process 用户内核栈从 4 帧扩到 8 帧（32 KiB，`Process`=2144），消除深层 TCP 回环投递击穿内核栈导致的 #DF；每启动 121 个集成标记 |
| M8h procfs/devfs 视图 | **已完成并验收** | 真实 `Backing::Generated` VFS 文件与 `CharDevice` 设备节点：`/proc/self/status` 按当前 owner 现场渲染 `Name: linux`/`State`/`Pid`/`PPid`/`Uid`/`Gid`/`Threads: 1`（size 0、不进页缓存），`/proc/uptime` 按单调时钟输出“秒.百分秒”两字段（uptime 与 idle 相同），`/dev/null`(1,3) 读 EOF/写丢弃、`/dev/zero`(1,5) 无限零字节/写丢弃；`/proc` 目录可经 `getdents64` 列出 `self`/`uptime`；`services/linux-net` 打印 `[CaelumLinux] M8h procfs OK` 与 `M8h devfs OK`（仅 parent 各一次，无 payload），位置在内核 `[CaelumKernel] M7d OK` 之前；两启动各 **123** 个标记（121 + 2） |
| M9a Linux 用户态扩展第一切片 | **已完成并验收** | Linux64 用户态可见面：timerfd（到期 read 返回计数、超时/取消负路径）、signalfd（待处理信号转 fd 可读、sigmask 过滤）、epoll 基础 level-triggered 语义（create1/ctl/wait、EPOLLIN/EPOLLOUT 就绪报告、零/正超时）；用户程序打印 `[CaelumLinux] M9a timerfd OK`/`M9a signalfd OK`/`M9a epoll OK`；两启动各 **126** 个标记（123 + 3）；M9b 完成后总数为 **130**（126 + 4） |
| M9b Linux 用户态扩展第二切片 | **已完成并验收** | AF_UNIX abstract 命名空间（NUL 开头 abstract 地址与路径名地址并存）、`SCM_RIGHTS` fd 传递（fd → 内核对象引用 → 接收方新 fd）、`SCM_CREDENTIALS` 校验、epoll `EPOLLET` 边沿触发与 drain；用户程序打印 `[CaelumLinux] M9b abstract OK`/`M9b rights OK`/`M9b credentials OK`/`M9b epoll-et OK`；两启动各 **130** 个标记（126 + 4） |
| M9c 文件锁/fcntl | **已完成并验收** | 同一 `linux` ELF 的 role2 锁对端；VFS POSIX `fcntl`（按线程组）/OFD（按打开文件描述）/`flock`（独立域）三锁域与冲突/关闭释放负路径；打印 `[CaelumLinux] M9c locks OK`；同时 `MAX_PROCESSES = MAX_SPACES = 4`、第 4 内核栈基址 `0xFFFF_FFFF_8120_0000`、`MAX_CHILDREN = 2`；xtask 标记总数 131/启动 |
| M9d1 Linux64 动态 ELF/PT_INTERP | **已完成并验收** | ET_DYN 主程序（`caelum-linux-dyn`，注入 FAT 为 `/fat/dyn-main`，含 `PT_INTERP=/fat/ldcaelum.so`、4 条 RELATIVE、无 DT_NEEDED）由自研 ET_EXEC 解释器 `ldcaelum`（`caelum-interp`，`/fat/ldcaelum.so`，基址 0x40000000、无 PT_INTERP）加载；内核在 `m7d_closeout` 经 VFS 读取两条路径并注入 auxv `AT_PHDR`/`AT_ENTRY`；打印 `[CaelumDyn] interp OK`、`[CaelumLinux] M9d dynamic OK`；两启动各 **133** 标记（131 + 2） |
| M9d2 真实 ET_EXEC vDSO | **已完成并验收** | `caelum-vdso` 产出 8808 B ET_EXEC（entry `0x7001000`）+ 全局只读数据页（magic/version/seq/hz/ticks，序号校验保证一致快照）；内核映射并以 `AT_SYSINFO_EHDR` 暴露，用户按 ELF `e_entry` 直接调用、不做符号表解析；CLOCK_MONOTONIC/BOOTTIME 由 hz/ticks 计算，CLOCK_REALTIME 明确返回 `-ENOSYS`；打印 `[CaelumLinux] M9d vdso OK`；两启动各 **134** 标记（133 + 1）；完整 vDSO（REALTIME 时钟源、符号表与完整语义）未做 |
| M9e 真实 ET_DYN 共享库 | **已完成并验收** | `caelum-m9e-lib` 产出 2392 B ET_DYN 共享库（无进程入口，`e_entry=0`），`caelum-linux-dyn` 仅以 `DT_NEEDED=/fat/m9e.so` 依赖它；`xtask` 先把 lib 以 pic release 构建、再经 `CAELUM_M9E_LIB` 构建 dyn，并把共享库作为第四件注入 FAT 测试盘（`/fat/m9e.so`）；内核在 `m7d_closeout` 经 VFS 读取、以 `validate_for_shared_object` 校验（要求 ET_DYN，但不要求 e_entry 落在可执行段；段/地址上限/权限/偏移同余/重叠规则仍适用）、映射到冻结 bias，由自研解释器应用库内 RELATIVE 与主程序 GLOB_DAT；打印 `[CaelumLinux] M9e shared OK`；两启动各 **135** 标记（134 + 1）；PLT/GOT 延迟绑定、符号解析与 glibc/musl 未做 |
| M9f 真实链式三库共享库闭包 | **已完成并验收** | `caelum-m9f-a` 2336 B 与 `caelum-m9f-b` 1800 B 均 ET_DYN（A 的 NEEDED 为 B、dyn 的 NEEDED 为 `/fat/m9e.so`→`/fat/m9f-a.so`）；`xtask` 依次 pic release 构建 B→A→m9e→dyn（A 用 `CAELUM_M9F_B_LIB`、dyn 用 `CAELUM_M9E_LIB`+`CAELUM_M9F_A_LIB`），把两库作为第五、六件注入 FAT 并在两启动后逐字节复核；内核在 `m7d_closeout` 经 VFS 读取、校验并映射三库到冻结 bias（0x0300_0000/0x0380_0000/0x0400_0000），自研解释器按 m9e→A→B 解析 SONAME（`bias + DT_STRTAB + soname`）并由 GLOB_DAT 解析 A→B 调用与库内自身 counter，无 PLT 懒绑定/JUMP_SLOT；打印 `[CaelumLinux] M9f shared OK`；两启动各 **136** 标记（135 + 1）；dlopen/dlsym/符号版本/glibc 未做 |
| M9 其余切片、M8 其余切片与 M7c | 未开始/未实施 | M9 其余：完整共享库/重定位（PLT/GOT 延迟绑定与符号解析、glibc/musl 工作负载与 Linux 工具运行；M9e/M9f 已交付最小单依赖与链式三库闭包）、完整 Linux 设备视图；M8 其余：fork/clone 完整共享矩阵、线程组、完整 siginfo、任意进程/线程组信号；M7c（真实 virtio-net 链路）未实施；完整 M7/M8/M9 通过前不得宣称完成 |

---

## 6. 尚未决定、但不阻塞当前阶段的事项

这些事项在 [`agents.md`](agents.md) 中也已列出，当前不做选择：

- GitHub 组织/仓库名和开源许可证；项目正式名称已确定为 **青穹 OS / CaelumOS**，`OS001` 仅保留为历史代号。
- 最终长期使用的现代根文件系统。
- 用户态显示协议、桌面环境及主题：过渡期方向已确认（软件渲染 + 简洁亮色 UI、原生版本化 Surface/Present/Input 三段协议，见 §7.1 与 `agents.md` 第 15.1.1 节）；最终桌面协议、主题系统与视觉细节仍待后续设计决定。全部尚未实现。
- 原生软件包格式、系统更新和回滚策略。
- Secure Boot 密钥与模块签名发布策略。
- 网络协议栈采用自研还是经审计的现有 `no_std` 实现。
- arm64 的首台目标设备和 32 位兼容的实际启动时间。

---

## 7. 后续建议顺序

M0～M6 已按顺序完成并验收；M7 已完成 M7a/M7b/M7d；M8 已完成 M8a～M8h；M9a（timerfd/signalfd/epoll level-triggered 基础语义）、M9b（AF_UNIX abstract 命名空间、`SCM_RIGHTS`/`SCM_CREDENTIALS` fd 传递、`EPOLLET` 边沿触发）、M9c（文件锁/fcntl）与 M9d1（Linux64 动态 ELF/PT_INTERP）、M9d2（真实 ET_EXEC vDSO）、M9e（真实 ET_DYN 共享库、`DT_NEEDED` 单依赖）与 M9f（链式三库闭包）已完成并两启动验收（**136** 标记）；M7c（真实 virtio-net 链路）未实施、M9 其余切片与 M8 其余切片未完成。下一步按以下顺序执行：

1. **保持 M1～M6、M7a/M7b/M7d、M8a～M8h 与 M9a～M9c、M9d1/M9d2/M9e 回归**：任何改动前后都运行 `cargo fmt --all`、`cargo xtask check`、`cargo xtask test`，两启动各 **136 个集成标记**不得减少，`[CaelumKernel] M2 #PF caught` 必须仍是最后一个；M6b2 五条统计行阈值、M6c 的两次 screendump 像素校验与 payload `events=5`/`dropped=0`、M7a/M7b/M7d 的载荷、动态 ELF 六文件（dyn/interp/vdso 与 `/fat/m9e.so`、`/fat/m9f-a.so`、`/fat/m9f-b.so`）的宿主逐字节复核必须仍精确匹配。
2. **推进 M9 其余切片与 M8 其余切片**：按 `agents.md` 第 22 节 M8/M9/M7 行推进完整共享库/重定位（PLT/GOT 延迟绑定与符号解析；M9e/M9f 已交付最小单依赖与链式三库闭包）与 glibc/musl 工作负载、Linux 工具运行、Linux 设备视图，以及 fork/clone 共享矩阵、线程组、跨进程/线程信号与完整信号语义；完整 M8 与完整 M9 通过前不得宣称完成。
3. **实施 M7c（真实网络链路）**：按 `agents.md` 第 22 节 M7 行完成真实 `virtio-net` 设备链路、QEMU user-net 连通与异常恢复（link down/up）的验收；M7a/M7b/M7d 的 loopback/本地 Socket 验收不能替代它。M7c 通过前不得宣称完整 M7 完成。
4. **保持回归纪律**：每个子任务都必须提供可重复构建、可观察日志、失败现象和已知限制；不得把“已规划/实现中”写成“已验收”。
5. **工程基线补齐（可选）**：Git 仓库仍未初始化，是否建立由项目所有者明确决定。

### 7.1 图形与桌面过渡方案（方向已确认，尚未实现）

图形过渡阶段采用**软件渲染 + 简洁亮色 UI**（用户明确偏好浅色；详细视觉设计后续补充）。用户态分工：

- `displayd`：显示设备与显示会话管理、模式选择与帧提交；
- `composerd`：合成器，负责层/表面合成与亮色基础主题绘制；
- `inputd`：输入事件路由与向焦点会话投递；
- `shell`：桌面壳（面板、启动器、会话管理），仅是 `composerd` 的客户端。

原生接口采用版本化 **Surface/Present/Input** 三段协议（Surface 创建/尺寸/格式/共享帧；Present 提交与同步；Input 事件投递），与具体合成器或桌面解耦。内核只负责显示设备与输出、输入事件、共享帧映射与权限校验，不实现窗口策略、布局、主题或动画。后续经**用户态 X11 兼容桥**承载 Wine 等 Linux GUI，X11 语义不进入内核；该方向与 `agents.md` 的“原生主线与兼容层边界（约束 v1.0）”一致。以上均为过渡期方向，**尚未实现**；当前 M6c 的显示探测与受控 `gfx` 只是最小机制验证，不等于本方案已交付。

---

## 8. 当前工作约束

后续接手者应遵守：

- 先读 [`agents.md`](agents.md) 第 1 节的关键决策和第 26 节的实施约束。
- 不得自行改变内核形态、主语言、引导器、原生 ABI 或 Windows 兼容路线。
- 第 4 节的“建议处理”是审阅历史；当前设计口径以 `agents.md` v0.2.1 为准。
- 不得把 [`agents.md`](agents.md) 中的“预留接口”描述为“已经实现”。
- 不得在未获明确许可时跳阶段推进，也不得把某阶段的规划、部分实现或未跑通的验收写成“已完成”。
- 后续设计变更必须保持文档版本、修订说明和进度记录同步；不得把设计变更和实现混在同一轮。
- 内核 boot 栈是 guard 页 + 仅 4 个映射帧（不是 loader 的 64 KiB 启动栈）；栈顶必须是 `base + (4 + 1) * FRAME`，当前正确值为 `0xffffffff81005000`。写成 `base + 4 * FRAME` 会把“最后一帧的起点”当成栈顶，实际只有约 12 KiB 可用，继续执行 spawn 路径就会 `#DF`（M7d 首启的根因）。
- AP 上 parented spawn 的初始 placement 必须随创建 CPU：进程创建时记录/使用创建它的 CPU 的队列与迁移信息，不能一律落到 BSP 队列或沿用旧 last CPU，否则会在 AP 恢复用户帧前出现错误放置（M7d 修复项之一）。

### 8.1 质量、压力与验收约束（与 `agents.md` 同步）

以下为长期约束与验收要求，**当前尚未全部实现**；已验收里程碑（M1～M6、M7a/M7b/M7d、M8a～M8h、M9a～M9c、M9d1/M9d2、M9e/M9f）尚未引入专门的压力切片与风险清单，按本节要求逐步补齐：

1. 每个 `unsafe` 块就近写 `// SAFETY:` 注释（不变量/边界/生命周期），高风险模块另设风险清单；压力测试按风险分级，不做机械重复。
2. 并发压力 marker 分阶段：当前用 spawn/reap、SMP、信号、并发文件/IPC/锁；`fork`/`clone` 与线程组落地后再加循环 fork 与线程组并发压力。marker 必须携带次数、耗时、失败数与资源基线，区分短压力（每次验收）与定期长压力（周期性回归）。
3. 虚拟机验收与裸机验收分开：QEMU/OVMF 结果只代表该虚拟环境；M11 起驱动验收需记录 q35、virt/OVMF 与真实主板/固件/设备矩阵。单个 q35 通过不构成“兼容”，对外结论必须写明测试范围。
4. 卡死/死锁/活锁/饥饿/长期屏蔽中断都属缺陷：必须有超时 watchdog、最后进度与现场诊断，不允许以“重启后通过”销项，也不得把无进展等待当作通过。
5. ext2 仅作工程验证；长期换日志/CoW 前必须验证断电恢复、`fsync`、`rename` 原子性/顺序、`fsck` 一致性与故障注入。

核心口径：不允许 panic、静默错误、无进展卡死与资源泄漏；兼容性结论必须同时给出测试范围与覆盖矩阵，未覆盖部分明确标注。

---

## 9. 当前目录与产物清单

| 路径 | 类型 | 状态 |
|---|---|---|
| [`agents.md`](agents.md) | 架构设计基线 | v0.2.1，R-01～R-14、S-01～S-15 均已写回；状态行已同步到 M1～M6、M7a/M7b/M7d、M8a～M8h 与 M9a/M9b/M9c、M9d1/M9d2、M9e 与 M9f 完成并验收；M7c（真实 virtio-net 链路）尚未实施，完整 M7/M8/M9 未关闭 |
| [`PROJECT_PROGRESS.md`](PROJECT_PROGRESS.md) | 项目进度记录 | 本文件，M9f 双启动验收后的准确快照（M7c 未实施、完整 M8/M9 未完成） |
| `docs/abi/boot-protocol.md` | Boot Protocol 规范 | v1.1（M4 起新增启动模块 TLV，`entry_abi` 仍为 1；M5/M6/M7a/M7b/M7d 期间均未改动） |
| `docs/abi/native-syscall.md` | 原生 syscall ABI 规范 | 原生 ABI **0.6**（M7b 定稿：0.1 为 M4 版本，0.2 在 M5c1 冻结文件/目录语义、M5c2 启用 mmap/munmap/mprotect、M5c3 启用 lock/xattr/watch，0.3 在 M6a1 增加 Event/EventPair/Timer 与统一等待，0.4 在 M6a2 增加 Channel/Port/SharedMemory/EventSubscription/Futex，0.5 在 M6c 增加显示探测/present 与输入事件，0.6 在 M7b 增加 Socket/LocalSocket 原生面；M7d 的 Linux64 人格不新增原生 ABI） |
| `loader/`、`kernel/`、`libs/`、`services/` | 源码目录 | loader 自报版本 0.2.0、kernel 0.16.0；kernel 含 `net/`（`libs/netcore` 绑定、loopback、Socket/LocalSocket）与 `compat/linux/`（Linux64 人格：syscall、errno、启动栈、fd、地址转换、poll/eventfd、信号、动态 ELF 装载与 auxv、vDSO 映射）；kernel 含 `arch/`、`mm/`、`platform/`、`io/`、`ipc/`、`vfs/`（含 `pseudo.rs`）、`display/`、`vdso.rs`（M9d2：真实 ET_EXEC 映射与 AT_SYSINFO_EHDR）以及 `object`/`process`/`syscall`/`bootmod`/`image`/`rng` 等；`services/init`、`services/child`、`services/worker`、`services/gfx`、`services/net`、`services/linux-net`、`services/linux-dyn`（M9d1 ET_DYN 主程序）、`services/linux-interp`（M9d1 自研解释器 `ldcaelum`）、`services/linux-vdso`（M9d2 ET_EXEC vDSO）、`services/linux-m9e-lib`（M9e ET_DYN 共享库）、`services/linux-m9f-a` 与 `services/linux-m9f-b`（M9f 链式共享库）为用户程序；M9d1/M9d2/M9e/M9f 的六份 release 产物由 `xtask` 逐字节注入 FAT 测试盘（`/fat/dyn-main`、`/fat/ldcaelum.so`、`/fat/vdso.so`、`/fat/m9e.so`、`/fat/m9f-a.so`、`/fat/m9f-b.so`），不新增 boot module、loader 模块表仍为六项 |
| `libs/block`、`libs/fat32`、`libs/ext2` | 块设备与文件系统库 | 内核与 host 侧共用：`block` 提供 `BlockDevice`/`BlockError` 与内存盘测试支持，`fat32` 提供格式化/挂载/文件操作，`ext2` 提供格式化/挂载/文件操作；M5b 的 host 两阶段复核直接用同一套库解析 QEMU 写出的镜像 |
| `libs/native-abi`、`libs/native-rt` | 原生 ABI 与用户运行库 | 原生 ABI 0.6 常量/`repr(C)` 结构与 `docs/abi/native-syscall.md` 对应 |
| `xtask/` | 构建与验收工具 | `build` / `check` / `image` / `qemu` / `test` 均已实现；`image` 生成 `target/initramfs.img`（六个模块 init/child/worker/gfx/net/linux）与含 `/INITFS.IMG` 的 ESP，并构建六个 release 注入产物；`qemu`/`test` 为两启动验收：格式化两个 raw 磁盘（`target/m5b-fat32.img` 64 MiB、`target/m5b-ext2.img` 32 MiB）时把 `caelum-linux-dyn`/`caelum-interp`/`caelum-vdso`/`caelum-m9e-lib`/`caelum-m9f-a`/`caelum-m9f-b` 逐字节写入 FAT 根（`dyn-main`、`ldcaelum.so`、`vdso.so`、`m9e.so`、`m9f-a.so`、`m9f-b.so`）→ 启动 1（双向串口 + QMP 键盘注入 + **136 标记** + 统计/载荷校验 + `screendump` 三像素校验）→ host 首启复核（M5b/M5c 内容 + 动态 ELF/vDSO/共享库四文件逐字节）→ 启动 2（同 136 标记 + 第二次 `screendump` + 第二次注入）→ host 二启复核（含再次逐字节比对）；日志 `target/serial-boot1.log`、`target/serial-boot2.log`，第二启动副本写回 `target/serial.log` |
| `tests/qemu/` | 验收脚本与说明 | 薄壳脚本 + M9a～M9f 验收说明（两启动、`-smp 4`、每启动 **136** 个标记、M9d1/M9d2/M9e/M9f 动态 ELF/vDSO/三库注入与逐字节复核契约、M6c 截图/像素与注入顺序、M7a/M7b/M7d 载荷契约都只在 `xtask` 维护，README 只说明不重复清单） |
| `tools/ovmf/` | OVMF 固件副本 | `edk2-stable202605-r1`，`xtask` 默认优先使用 |
| Git 仓库 | 无 | 尚未初始化 |

---

## 10. 工作记录

### 2026-10-30

1. 通过两轮关键问题确认系统定位、内核架构、语言、兼容、驱动、引导和 ABI 策略。
2. 形成完整内核总体设计并写入 `agents.md`。
3. 检索并安装 `os-dev-scratch` 技能；核查本地新增的 NT 5.2 相关技能。
4. 开始架构审阅，完成第一遍静态检查。
5. 发现启动交接、本地 Socket/fd 传递、时间、随机数、驱动生命周期和文档质量问题。
6. 项目所有者要求暂停项目，仅记录当前进度，不继续审阅、不修改设计、不进入实现。
7. 创建本进度文件。
8. 项目所有者恢复架构审阅，明确暂不开始正式实现。
9. 完成第二遍交叉审阅，新增 R-07～R-14；未改变任何已确认关键决策。
10. 仅更新本进度记录；`agents.md` 保持 v0.1 不变，未进入 M1。
11. 项目所有者允许进入设计修订阶段，但仍不授权实现。
12. 将 R-01～R-14 合并到 `agents.md`，更新为 v0.2 审阅修订稿，并同步本文档。
13. 项目所有者开启 swarm mode；主代理验证可调度多个并行审阅子智能体。
14. 四路智能体并行复核完成并记录 S-01～S-15；`agents.md` 未再修改。
15. 仍未创建源码、构建系统、测试或 Git 仓库；M1 仍未启动。
16. 项目所有者许可后，使用四个并行代理完成 v0.2.1 修订（三路修改/同步、一路只读复核）：S-01～S-15 全部写回 `agents.md`，文档更新为 v0.2.1。修订只涉及澄清、归属和验收口径，未改变第 1 节任何已确认关键决策；无实现、无测试产物，M1 仍未启动。
17. 项目所有者确认正式名称为 **青穹 OS / CaelumOS**；`OS001` 保留为历史代号，并同步到 `agents.md` 与本文档。
18. 项目所有者正式关闭 M0，并授权启动 M1；`agents.md` 与本文档已同步为 M0 关闭、M1 启动。
19. M1 工程实现完成并通过主代理复验：成功路径、`bootreq` 拒启负例和 BootInfo `bad-checksum` 负例均在真实 QEMU/OVMF 中通过；正常源码和镜像已恢复。
20. M2 工程实现完成并通过主代理复验：57 个宿主单元测试、QEMU/OVMF 成功路径、GDT/TSS/IDT、PMM、内核堆、高半核 VM 接管和故意 #PF 诊断均通过；修复 KERNEL_IMAGE TLV 物理 size 语义并清理编译警告。
21. 项目所有者授权：M2 完成后直接进入 M3；M3 完成后继续进入 M4；若未明确终止，则按后续里程碑持续构建。
22. M3 四路规划代理完成，形成 ACPI/APIC/时钟、双线程调度、验收和 xtask 注入方案；随后 M3 实施代理批被用户中断，未产出 M3 代码。交接前再次运行 `cargo xtask check`，确认当前仍是 M2 已验收基线。

### 2026-10-31

23. M3 工程实现完成：ACPI/MADT → xAPIC/IOAPIC（GSI1 键盘、GSI4 COM1 RX）、PIT 校准的 LAPIC 100 Hz 单调时钟、8042 PS/2 键盘与串口 RX 中断、两个内核线程 A/B（独立内核栈、守卫页、双 canary）、`int 0x40` 协作 yield 与定时抢占；M2 故意 #PF 保留为最终回归点。
24. `xtask` 验收升级：双向串口 chardev（同时写 `target/serial.log`）+ QMP `send-key a`，仅在 `M3 input ready` 后注入一次，且必须由内核回报 `M3 input OK`/`M3 serial OK`；标记总数 8 → 17；出现 fatal 后先 drain 串口 250 ms～1 s 再终止 QEMU（保留 cr2/rip/寄存器转储）；ESP 缺失或过期自动重建；`tests/qemu` 两个脚本改为薄壳。
25. 主代理亲自运行 `cargo xtask test` 全流程通过（exit 0）：宿主单测 117 个（bootinfo 15、elf64 15、xtask 12、kernel lib 75）；串口实测 `M3 stacks OK` → `M3 sched OK (switches=9, a_yields=4, a_timer_preempts=0, b_timer_preempts=4, b_iterations=372982)` → `M3 OK` → `M2 #PF caught`。
26. M4 工程实现完成：原生对象表与每进程句柄表、`syscall` 入口与原生 ABI 0.1（`docs/abi/native-syscall.md`）、Boot Protocol 1.1 启动模块 TLV、统一 ELF 装载器、`caelum-init`/`caelum-child` 两个用户程序（init 创建 child 仅经进程创建参数传初始句柄，等待 status 0，查询 `rng` 得 `NoEntropy`，双方正常退出）；资源回滚与重复源句柄等负路径由宿主回归覆盖。
27. `xtask` 验收升级：`image` 生成 `target/initramfs.img`（16 B `CAELUMFS` 头 + 2×40 B 记录，载荷 16 B 对齐）并放入 ESP 根 `/INITFS.IMG`（纯 8.3，无 LFN）；`build`/`check` 显式构建 `caelum-init`/`caelum-child`；标记总数 17 → 27，并强制 `[CaelumKernel] M2 #PF caught` 必须最后出现；容器线格式有跨解析器单测（用 `bootinfo::Initfs` 解析 `xtask` 写出的容器）。
28. 主代理亲自运行 `cargo xtask test` 全流程通过（后台 job `pwsh-2395166c05ea49eb`，exit 0）：宿主单测 bootinfo 24、elf64 22、xtask 19、kernel lib 172 全绿（另有 native-abi 9 项此前单包验证）；真实 QEMU/OVMF 27/27 标记通过，顺序为 M4 init → spawn child → child handles → wait status 0 → `Random NO_ENTROPY` → init/child exit → `M4 OK` → deliberate `M2 #PF caught`（最后）。
29. 版本快照：loader 0.2.0、kernel 0.4.0、Boot Protocol 1.1、native ABI 0.1；`docs/abi/boot-protocol.md` 与 `docs/abi/native-syscall.md` 已定稿，本轮文档收口不再改动。
30. M5a 工程实现完成：内核 VFS 骨架（挂载表、VNode、打开文件描述、路径解析与边界）、页缓存最小实现、ramfs、三类锁域（含关闭/继承语义）、目录变更通知；`bootmod`/`image.rs` 的启动模块读取迁移到 VNode + 页缓存，init/child 经 VFS 装载，M4 完整链仍通过。
31. M5a 关键返工（栈与内存）：VFS 改为静态原位 `State`，消除 92 KiB 临时缓冲；路径解析改用 out-param 携带结果，消除 `parse_parent` 的 7.4 KiB 栈帧；**未扩大 16 KiB boot stack**。
32. `xtask` 标记总数 27 → 33（新增 6 个 M5a 标记，M5a 不需要额外输入），顺序契约不变：M5a 六标记在 M4 标记之后、deliberate M2 #PF 之前。
33. 主代理亲自运行 `cargo xtask test` 全流程通过（后台 job `pwsh-12b9ba1387c842d5`，exit 0）：宿主单测 bootinfo 24、elf64 22、xtask 20、kernel lib 250 全绿（另有 native-abi 9 项此前单包验证）；build/image/QEMU 全过，真实 QEMU/OVMF 33/33 标记通过且 `M2 #PF caught` 最后；`M5a vfs/pagecache/ramfs/locks/notify/bootmod via vfs` 六个标记按序出现，`M4 init` 之后仍完整通过。状态：M1–M4 + M5a 完成并验收，M5b 已授权未验收，无 Git 仓库。
34. M5b 工程实现完成：ACPI MCFG/ECAM 配置空间枚举与 PCI 设备发现、2 个 legacy `virtio-blk-pci`（`queue-size=128`，落在内核两帧 DMA 预算内）、早期连续 DMA 预留（2 帧 8 KiB，w6）、FAT32 与 ext2 持久化路径、VFS 磁盘 backing 与页缓存 writeback；同时修复栈 scratch 与挂载 root 保护（M5a 遗留项）。
35. `xtask` 验收升级为两启动 + host 两阶段复核：每次运行前把 `target/m5b-fat32.img`（FAT32，64 MiB）与 `target/m5b-ext2.img`（ext2，32 MiB）格式化为**空盘**；启动 1 由 guest 创建 `/M5STATE.BIN`+`/m5state`（精确 13 字节 `CAELUM-M5B-V1`）与 `/M5DATA.BIN`+`/m5data`（8192 字节 pattern `((i*13+7)%251)`）并 sync，host 复核；启动 2 读回后再追加 1024 字节（总 9216）、改名 `M5DONE.BIN`/`m5done`、截断到 4608 并读回，host 复核 state/done 存在且旧名已删除；每启动 41 个标记（33 回归 + 8 M5b，`M2 #PF caught` 仍最后），日志 `target/serial-boot1.log`/`serial-boot2.log`，第二启动完整副本写回 `target/serial.log`。
36. M5b 关键返工：harness 不得给 guest 预写 state/data（否则内核首启即走二启分支、验收失去意义）；`virtio-blk-pci` 默认 `queue-size=256` 超出驱动预算，改为 `queue-size=128`；单元测试原先复用验收镜像会被测试运行重置，改为 scratch 路径（`target/m5b-test-*.img`）；FAT32 64 MiB 用 spc=1 以满足规范 65525 cluster 下限（w1 同步修 `libs/fat32` formatter 的 FAT 尺寸不动点）。
37. 主代理亲自运行 `cargo xtask test` 全流程通过（后台 job `pwsh-25056bebb2784485`，exit 0）：宿主单测 bootinfo 24、elf64 22、xtask 37、kernel lib 307 全绿；独立单包验证 `block` 8、`fat32` 30、`ext2` 28 全绿；build/image/fmt/QEMU 全过，两启动各 41/41 标记通过且 `M2 #PF caught` 最后，host 两阶段磁盘复核通过。状态：M1–M4 + M5a + M5b 完成并验收，M5c 已授权未完成，无 Git 仓库。
38. 版本快照：loader 0.2.0、kernel 0.6.0、Boot Protocol 1.1、native ABI 0.1；M5b 未改动 `docs/abi/boot-protocol.md` 与 `docs/abi/native-syscall.md`（本轮无协议变化）。
39. M5c1 工程实现完成：早期挂载 FAT32（`/fat`）与 ext2（`/ext2`）并打印 `M5c mounts ready`；用户态文件与目录语义（create/read/write/rename/truncate/目录枚举）落地，init 与 child 各自在两条挂载点上创建并回读 14 字节用户文件（`M5c files OK`）；`xtask` 标记 41 → 45（每启动），host 首启复核 14 字节、二启复核 20 字节（`CAELUM-M5C1-V1` / `CAELUM-M5C1-V1\nBOOT2`）。
40. M5c2 工程实现完成：共享与私有 `mmap`（8192 字节，初始 pattern `((i*7+3)%251)`；shared 写回后位置 0 = `0xA5`、4103 = `0x5A`，private 页写入 `0xFF` 不得落盘）落地，`M5c mmap OK` 由 init/child 各自打印；标记 45 → 48；host 在**首启与二启之后都**按最终态校验两盘 map 文件（存在、8192 字节、内容精确、且首字节不是 `0xFF`）。
41. M5c3 工程实现完成：文件锁（fcntl/OFD/flock 语义含关闭与进程退出释放）、扩展属性（易失，不跨重启）、稀疏文件（`/M5HOLE.BIN`/`/m5chole` 32772 字节，洞内全零、尾部 `HOLE`，不占实际块）、目录监视（watch）与对象销毁钩子、一次性 Write/Flush 故障注入与重试/回读（`/M5FAULT.BIN`/`/m5cfault` = `CAELUM-FAULT-OK`）、进程 reap 后锁/监视/映射资源清理；标记 48 → **56**（每启动）。
42. M5c 阶段关键返工：`addrspace::init_space` 与 `bootinfo` 单态化处 4 KiB 级栈帧撑爆 16 KiB boot 栈（`#DF`），按 M5a 既定风格改静态原位/out-param，未扩大 boot stack；`services/init` 的启动模块路径由 `/init` 修正为 `/boot/init`（内核把启动模块挂在 `/boot` 下，只读打开才返回 `ReadOnly`）；`xtask` 侧保持空盘首启、`queue-size=128`、单测 scratch 盘不覆盖验收现场、稀疏/故障文件由 guest 每次 `CREATE|TRUNC` 重建。
43. 主代理亲自运行 `cargo xtask test` 全流程通过（后台 job `pwsh-4cb1cab0c7064929`，exit 0）：宿主单测 bootinfo 24、elf64 22、xtask 61、kernel lib 432 全绿（合计 **539**），另有 `native-abi` 23、`block` 8、`fat32` 37、`ext2` 35 个共享库独立测试全绿；build/ESP/FAT32/ext2 镜像/fmt 全过（仅旧 LNK4044 宿主链接 warning）；真实 QEMU/OVMF **两启动各 56/56 标记**通过，顺序含 M5c mounts、用户 files/mmap/xattr/sparse/watch/locks、M5b 持久化、M5c1/M5c2、`M5c3 faults OK` → `M5c3 OK` → `M5 OK`，末尾仍为 deliberate `M2 #PF caught`；host 首/二启复核 M5b state/done、14→20 字节用户文件、shared mmap、32772 字节稀疏文件、16 字节故障回读文件全部通过。状态：**M1～M5 全部完成并验收，M6 已授权未实施，无 Git 仓库**。
44. 版本快照：loader 0.2.0、kernel 0.8.0、Boot Protocol 1.1、native ABI **0.2**；M5c 期间 `docs/abi/native-syscall.md` 由 M4 的 0.1 升到 0.2（M5c1 冻结文件/目录语义、M5c2 启用 mmap/munmap/mprotect、M5c3 启用 lock/xattr/watch），`docs/abi/boot-protocol.md` 保持 v1.1 未变。
45. M6a1 工程实现完成：`kernel/src/ipc/event.rs` 的 Event（manual/auto reset；`signal` 置位、`reset` 清位、`consume` 在 auto-reset 下观察到置位即清）与 EventPair（`signal_pair(X)` 置对端 `X^1`，`ready_pair`/`consume_pair` 操作调用方等待的端点）、`kernel/src/ipc/timer.rs` 的单调时钟 Timer（绑定对象 + 截止 tick，`arm` 设截止，时钟中断 `on_tick` 扫描到期项并 `wake_object(WakeReason::Timeout)`，对象销毁先 `Destroyed` 唤醒再释放槽）落地；`kernel/src/process.rs` 把 `Blocked` 做成真实进程状态，阻塞时把 `syscall` 帧复制到固定槽、唤醒后重放同一帧，`deadline: Option<u64>` 是 `monotonic_ticks` 上的绝对截止（`WakeTrigger::Deadline(now)` 使所有 `deadline <= now` 到期）；init/child 各以 timer 与 event 验证对端唤醒；原生 ABI 升至 0.3。
46. `xtask` 验收升级：标记总数 56 → **60**（每启动），新增四条 `[CaelumInit] M6a timer OK`、`[CaelumInit] M6a event OK`、`[CaelumChild] M6a event OK`、`[CaelumKernel] M6a OK`，并加入顺序契约（mounts ready → timer → event → `M4 exit OK`；child locks → `M6a event OK` → `M4 exit OK`；`M5 OK` → `M6a OK` → 最终 `M2 #PF caught`）；M6a1 不需要额外输入、不新增磁盘复核；测试同步 60 = 56 + 4 与"`M6a OK` 在 `M5 OK` 之后、`M2 #PF caught` 最后"。
47. M6a1 阶段关键返工：内核侧先出现 `M5a FAIL spawn_init was rejected (image via vfs)` 与 EventPair 唤醒挂起（首启卡在 `M6a timer/event OK` 之后），由内核修复；`xtask` 侧按契约快速失败并准确列出缺失标记，未改动验收口径；`docs/abi/native-syscall.md` 升到 0.3，`docs/abi/boot-protocol.md` 保持 v1.1。
48. 主代理亲自运行 `cargo xtask test` 全流程通过（后台 job `pwsh-7cb83f5acdec4f73`，exit 0）：宿主单测 bootinfo 24、elf64 22、xtask 62、kernel lib 480 全绿（合计 **588**）；build/ESP/两镜像/fmt 全过；真实 QEMU/OVMF **两启动各 60/60 标记**通过，顺序为 M5c mounts → 用户 files/mmap/xattr/sparse/watch/locks → M5b 持久化 → M5c1/M5c2/M5c3 → `M6a timer OK`/`M6a event OK`/`[CaelumChild] M6a event OK` → `M5 OK` → `M6a1 OK` → deliberate `M2 #PF caught`（最后）；host 首/二启磁盘复核与 M5 相同且全部通过。状态：**M1～M5 与 M6a1 全部完成并验收；M6a2（Channel/Port/SharedMemory/EventSubscription/Futex）已授权未验收，M6b（SMP）/M6c 后续，完整 M6 未完成；无 Git 仓库**。
49. 版本快照：loader 0.2.0、kernel 0.9.0、Boot Protocol 1.1、native ABI **0.3**；M6a1 期间 `docs/abi/native-syscall.md` 由 0.2 升到 0.3（Event/EventPair/Timer 与统一等待），`docs/abi/boot-protocol.md` 保持 v1.1 未变。
50. M6a2 工程实现完成：Channel 与 Port（有界消息队列、阻塞/超时接收、消息元数据、队列满返回 `ERR_WOULD_BLOCK` 背压）、SharedMemory（多页共享 + 双别名映射）、EventSubscription（level/edge 触发、readiness 重读与 drain 后复位、unsubscribe）、Futex（wait/wake 与超时），全部建立在 M6a1 的真实 `Blocked` 状态与 syscall 帧重放之上；init/child 两侧交叉验证；原生 ABI 升至 0.4。
51. `xtask` 验收升级：标记总数 60 → **70**（每启动），新增 10 条 —— 9 条用户标记 `[CaelumInit] M6a channel/port/shm/futex/subscription OK`、`[CaelumChild] M6a channel/port/shm/futex OK`，加内核 `[CaelumKernel] M6a2 OK`；位置契约：9 条用户标记都在 `[CaelumKernel] M4 exit OK` 之前且**彼此之间不硬编码顺序**（只靠唯一性 + 位置规则），`M6a OK` → `M6a2 OK` → 最终 deliberate `M2 #PF caught`；测试断言 First/Second 各 70、末项 `M6a2 OK`、且"用户标记乱序仍通过"。
52. M6a2 阶段关键返工（均为内核/用户态侧，`xtask` 口径未放宽）：`exit 178`（`EXIT_M6A2_RECV`，recv 把所有错误吞成超时）、`exit 181`（`EXIT_M6A2_QUEUE`，队列满判定永远为假）、`exit 182`（`EXIT_M6A2_SHM`，`shm_map` 查不到页槽 `NoSuchObject`）、child 映像加载被拒（页缓存 512 槽耗尽）、`child FAIL m6a2 shm 0x47`（init 在 offset 64 写 futex 字覆盖了 pattern，属测试协议冲突，child 校验跳过该字后修复）、`init FAIL m6a2 subscription`（订阅 readiness/唤醒路径修复）。
53. 主代理亲自运行 `cargo xtask test` 全流程通过（后台 job `pwsh-3b324537696540b9`，exit 0）：宿主单测 bootinfo 24、elf64 22、xtask 63、kernel lib 566 全绿（合计 **675**）；build/ESP/两镜像/fmt 全过；真实 QEMU/OVMF **两启动各 70/70 标记**通过，`[CaelumKernel] M6a2 OK` 在最后 deliberate `M2 #PF caught` 之前；host 首/二启磁盘复核（M5b state/done、M5c1 14→20 字节、M5c2 mmap、M5c3 稀疏与故障）全部通过。状态：**M1～M5、M6a1 与 M6a2 全部完成并验收；M6b（SMP）已授权未验收，M6c 后续，完整 M6 未完成；无 Git 仓库**。
54. 版本快照：loader 0.2.0、kernel **0.10.0**、Boot Protocol 1.1、native ABI **0.4**；M6a2 期间 `docs/abi/native-syscall.md` 由 0.3 升到 0.4（Channel/Port/SharedMemory/EventSubscription/Futex），`docs/abi/boot-protocol.md` 保持 v1.1 未变。
55. M6b1 工程实现完成（SMP AP bring-up）：`-smp 4` 下内核经 ACPI MADT 识别 3 个 AP，用低地址 trampoline（16→32→64 位三段，含 GDT/页表基址补丁）拉起 AP；每个 AP 完成 per-CPU 初始化（GDT/IDT/TSS、per-CPU 数据与栈）后进入 IF=0 idle 循环；启动完成后释放临时低页；全部 CPU 上线后打印 `[CaelumKernel] M6b1 online=4`。本阶段**只交付 AP 上线与每 CPU 初始化**，不含每 CPU 运行队列、负载均衡、CPU 亲和性、跨 CPU 唤醒 IPI 或 AP 调度。
56. `xtask` 验收升级：QEMU 参数加 `-smp 4`（`spawn_qemu` 与 `print_qemu_manual` 同步），标记总数 70 → **71**（每启动），新增 1 条 `[CaelumKernel] M6b1 online=4`；位置契约 `M3 OK` → `M6b1 online=4` → `M4 objects OK`；显式禁止把 `M6b OK`/`M6b SMP OK`/`M6b sched OK`/`M6b ipi OK` 纳入契约（测试断言 required 列表不含这些字符串）。
57. M6b1 阶段关键返工（内核侧，`xtask` 口径未放宽）：AP bring-up 曾停在 `[dbg] smp phase=ap0 init` 之后无任何输出（定位为 `smp::init` 内 `time::wait_for_ticks` 依赖 `sti; hlt` 等待 tick，在 AP 启动路径上不可用；改为不依赖 tick 的短延迟后 AP 全部上线），另有 trampoline 的保护模式段基址/GDT 基址补丁问题一并修正。
58. 主代理亲自运行 `cargo xtask test` 全流程通过（后台 job `pwsh-63590d9ca2354f38`，exit 0）：宿主单测 bootinfo 24、elf64 22、xtask 64、kernel lib 601 全绿（合计 **711**）；build/ESP/两镜像/fmt 全过；真实 QEMU/OVMF **两启动各 71/71 标记**通过，顺序为 `M3 OK` → `M6b1 online=4` → 完整 M4/M5/M6a1/M6a2 → 最后 deliberate `M2 #PF caught`；host 首/二启的 M5b/M5c 磁盘复核全部通过。状态：**M1～M5、M6a1、M6a2 与 M6b1 全部完成并验收；M6b2（每 CPU 运行队列/定时抢占/跨 CPU 唤醒 IPI）已授权未验收，M6c 后续，完整 M6 未完成；无 Git 仓库**。
59. 版本快照：loader 0.2.0、kernel **0.11.0**、Boot Protocol 1.1、native ABI **0.4**；M6b1 期间 `docs/abi/boot-protocol.md` 与 `docs/abi/native-syscall.md` 均未改动（无协议变化）。
60. M6b2 工程实现完成（SMP 调度）：每 CPU 运行队列与受控 worker 调度（`caelum-worker` 为第三个启动模块，`MAX_PROCESSES`/`MAX_SPACES` 扩到 3）、AP timer 定时抢占、BSP 跨 CPU 唤醒与 reschedule IPI、受控亲和迁移与负载均衡迁移（两个独立事件，不重复计数）；worker 阻塞/退出后 park，BSP 等待后 reap；每启动在 `M6a2 OK` 之后由 BSP 打印四条证据行 + 一条汇总行，AP 不直接写串口。
61. `xtask` 验收升级：标记总数 72 → **77**（每启动），新增 `[CaelumKernel] M6b2 ap user OK (runs=…, cpus=…)`、`[CaelumKernel] M6b2 ap preempt OK (preempts=…)`、`[CaelumKernel] M6b2 wake ipi OK (remote_wakes=…, ipis=…)`、`[CaelumKernel] M6b2 migrate OK (migrations=…, balances=…)` 与汇总 `[CaelumKernel] M6b2 OK (...)`；位置契约 `M6a2 OK` → 四条证据行（ap user → ap preempt → wake ipi → migrate）→ `M6b2 OK` → deliberate `M2 #PF caught`；宿主解析每行载荷并强制 runs>=2、cpus>=1、preempts>=2、remote_wakes>=1、ipis>=1、migrations>=1、balances>=1，缺字段/非数字/未知字段/汇总低于证据值均失败；三个启动模块（init/child/worker）打包与回读自检同步升级。
62. M6b2 阶段关键返工（内核侧，`xtask` 口径未放宽）：早期 `unexpected #PF`（BSP GS.base 未初始化时调用 `cpu_index`）、worker-spawn `NoFreeSlot`（进程槽不足）、`process table lock taken twice` 误报（跨 CPU 持锁被 `is_locked()` 误判为同 CPU 重入）、worker-exit 超时（AP timer 中断未送达/`ticks=0`）、`sched::setup_thread` 栈溢出引发的 `#DF` 与跳入数据符号等，均已逐项修复；最终两启动各 77 标记全绿。
63. 主代理亲自运行 `cargo xtask test` 全流程通过（后台 job `pwsh-3f22f85336be47ff`，exit 0）：宿主单测 bootinfo 24、elf64 22、xtask 67、kernel lib 653 全绿（合计 **766**）；build/ESP/两镜像/fmt 全过；真实 QEMU/OVMF **两启动各 77/77 标记**通过，M6b2 五条证据行首启与二启均为 `runs=4, cpus=14, preempts=12, remote_wakes=2, ipis=14, migrations=1, balances=1`，`M6b2 OK` 之后仍以 deliberate `M2 #PF caught` 收尾；host 首/二启的 M5b/M5c 磁盘复核全部通过。
64. 版本快照：loader 0.2.0、kernel **0.13.0**、Boot Protocol 1.1、native ABI **0.4**；M6b2 期间 `docs/abi/boot-protocol.md` 与 `docs/abi/native-syscall.md` 均未改动（无协议变化，迁移由内核受控路径驱动，不新增用户亲和性 syscall）。
65. M6c 工程实现完成（输入和基础显示共享缓冲）：内核 `display::probe` 读回真实 GOP framebuffer（1280x800、stride 1280、fmt 1）并在物理 FB 右下角写 magenta 探针像素，`display::present` 把 320x200x32 阴影 blit 到 FB 原点；新增第四个启动模块 `gfx`（`caelum-gfx`，loader `BOOT_MODULE_NAMES` 扩为四个并硬校验 count），由内核在 AP1 上以 display/input 两个能力句柄启动、退出后被 reap；`gfx` 收到真实 PS/2 `d`（make 0x20 → break 0xA0）与串口 `m6c` 三个字节共五个事件后打印 `M6c input OK (events=5, dropped=0)`，内核打印 `M6c OK (events=5, dropped=0)`；原生 ABI 升至 0.5。
66. `xtask` 验收升级：标记总数 77 → **82**（每启动），新增 `[CaelumKernel] M6c display probe OK`、`[CaelumGfx] M6c display OK`、`[CaelumGfx] M6c input ready`、`[CaelumGfx] M6c input OK`、`[CaelumKernel] M6c OK`；位置契约 `M6b2 OK` → 五条 M6c（probe → display → input ready → input OK → M6c OK）→ deliberate `M2 #PF caught`；构建/打包从三模块扩到四模块（init/child/worker/gfx），`cmd_image` 回读自检 `len()==4` 并逐字节核对；新增 QMP `screendump` → P6 PPM 解析与三点像素校验（右下角 magenta、`(48,48)` 绿、`(128,48)` 蓝，每通道 ±8），以及第二次注入（QMP `send-key` `d` + 串口 `m6c`）与 `M6c input OK`/`M6c OK` 的 payload 强制（`events=5`、`dropped=0` 精确相等）。
67. M6c 阶段关键返工：第二次注入顺序错误——QMP `send-key` 的 `hold-time=100` 使 `break`(0xA0) 在 100 ms 后才到，若紧接着写串口 `m6c`，guest 观察到 make→m/6/c→break 的错序，`gfx` 报 `FAIL input event index=1 kind=0x2 code=0x6d`；修复为 `KEY_HOLD_MS=100` + `M6C_KEY_SETTLE=150 ms`（编译期断言 settle>hold），注入后先等 150 ms 再写串口；另修复初始化期容器测试的 padding 起点（四模块 payload 起点 176 而非 192）与截图测试的 PPM 头偏移。
68. 主代理亲自运行 `cargo xtask test` 全流程通过（后台 job `pwsh-d430deecb20c4cf5`，exit 0）：宿主单测 bootinfo 24、elf64 22、xtask 74、kernel lib 696 全绿（合计 **816**）；build/ESP/两镜像/fmt 全过；真实 QEMU/OVMF **两启动各 82/82 标记**通过，两次启动的 QMP `screendump` 均验证右下角 magenta、`(48,48)` 绿、`(128,48)` 蓝，第二次注入（`d` 的 make/break + 串口 `m6c`，150 ms settle 之后）被接受，`M6c input OK` 与 `M6c OK` 均 `events=5, dropped=0`，`M6c OK` 之后仍以 deliberate `M2 #PF caught` 收尾；host 首/二启的 M5b/M5c 磁盘复核全部通过。状态：**M1～M6 全部完成并验收，M7（网络）已授权未实施；无 Git 仓库**。
69. 版本快照：loader 0.2.0、kernel **0.14.0**、Boot Protocol 1.1、native ABI **0.5**；M6c 期间 `docs/abi/boot-protocol.md` 未改动（仍 v1.1），`docs/abi/native-syscall.md` 由 0.4 升到 0.5（属 M6c 的 ABI 增量）。
70. M7a 工程实现完成（内核 loopback）：在 kernel `net` 模块中基于 `libs/netcore` 完成 IPv4/IPv6 UDP/TCP 自检，四条套件分别往返 7/14 字节，套件退出后打印 `M7a sockets OK (live=0)`，`M7a OK (suites=4)` 收尾；全部在内核内完成，不依赖真实 NIC。
71. M7b 工程实现完成（原生 Socket/LocalSocket）：新增原生 Socket 与 LocalSocket 对象及统一等待语义，覆盖 IPv4/IPv6 UDP/TCP、匿名 `socketpair`、路径名 unix stream/dgram、统一等待（ready/timeout）、`ERR_WOULD_BLOCK` 背压、半关闭 EOF、句柄权限与错误语义；第五个启动模块 `net`（`caelum-net`）在用户态驱动全套件，内核 reap 后打印 `[CaelumKernel] M7b OK (sockets=0, bindings=0)`；每启动 102 标记（88 + 14 M7b）。
72. M7d 工程实现完成（Linux64 socket 人格核心）：新增 Linux64 人格入口（Linux `syscall` 编号与 `-errno` 返回、System V 启动栈与 auxv `AT_CAELUM_CHANNEL`/`AT_CAELUM_NETNS`），覆盖 IPv4/IPv6 UDP/TCP、UNIX stream/datagram `socketpair` 与命名 datagram、fd 最低可用分配/`dup` 共享/`close` 释放，以及 `ENOSYS`/`EBADF`/`ENOTSOCK`/`EMSGSIZE` 负路径；第六个启动模块 `linux`（`caelum-linux-net`），内核 reap 后打印 `[CaelumKernel] M7d OK (sockets=0, bindings=0)`；每启动 110 标记（102 + 8 M7d）。
73. M7 受控验收证据：主代理运行两启动 QEMU/OVMF 通过——`target/serial-boot1.log`（7973 B，01:26:57）与 `serial-boot2.log`（7957 B，01:27:03）各 **110/110 标记**，顺序为 `M6c OK` → M7a 六条（`M7a ipv4 udp OK (bytes=7)` … `M7a OK (suites=4)`）→ M7b 十四条（`[CaelumNet]` 前缀，含 `M7b OK (child=0)` 与 `[CaelumKernel] M7b OK (sockets=0, bindings=0)`）→ M7d 七条 `[CaelumLinux]` 用户标记 + `[CaelumKernel] M7d OK (sockets=0, bindings=0)` → deliberate `M2 #PF caught`（最后）→ `halting`；六启动模块 `init/child/worker/gfx/net/linux` 由 loader 硬校验 count，kernel 打印 `M4 modules OK (6 boot modules, …)`；host 侧 M5b/M5c 两阶段磁盘复核全部保留通过。
74. M7 阶段关键返工与工程约束：M7d 首启曾在 `M5c mounts ready` 后 `#DF`，定位为内核 boot 栈 `new_rsp` 少算一帧（guard + 4 个映射帧，实际可用约 12 KiB），改为 `base + (4 + 1) * FRAME = 0xffffffff81005000` 后通过；同时把 Process 发布闭包改为锁内 `Option::take` 再省约 2.6 KiB；AP 上 parented spawn 的初始 placement 必须随创建 CPU。两启动随即各 110 标记全绿。loader 的 64 KiB 栈是另一个栈，不能与本约束混用。
75. 版本快照：loader 0.2.0、kernel **0.16.0**、Boot Protocol 1.1、native ABI **0.6**；M7a/M7d 未改动 `docs/abi/boot-protocol.md`；`docs/abi/native-syscall.md` 在 M7b 由 0.5 升到 0.6（Socket/LocalSocket 原生面），M7d 的 Linux64 人格不新增原生 ABI。
76. M7 当前边界：M7c（真实 `virtio-net` 链路、QEMU user-net 连通与 link down/up 异常恢复）尚未实施；M7a/M7b/M7d 的 loopback/本地 Socket 验收不能替代真实 NIC 链路验收，完整 M7 未关闭。
77. M8a/M8b/M8c 工程实现完成（Linux64 基础人格切片）：M8a 落地内存与文件语义（mmap/mprotect/munmap 共享与私有映射、保护位切换与读回、文件读取路径），M8b 落地时间与系统信息（`clock_gettime`/`clock_nanosleep`/`getppid`/`uname`），M8c 落地单线程/单进程信号（`rt_sigaction`/`rt_sigprocmask`、`kill`/`tgkill` self、SA_RESTORER 用户帧与 `rt_sigreturn`）；三个切片均由 `services/linux-net` 在 `[CaelumKernel] M7d OK (sockets=0, bindings=0)` 之前打印 `[CaelumLinux] M8a memory OK`/`M8a files OK`/`M8b time OK`/`M8b info OK`/`M8c signals OK`；每启动 115 标记（110 + 2 + 2 + 1），原生 ABI 仍 0.6（M8 切片不新增原生 ABI）。
78. M8 阶段验收证据：主代理两启动 QEMU/OVMF 通过——`target/serial-boot1.log`（8039 B，03:15:12）与 `serial-boot2.log`（8093 B，03:15:19）各 **115/115 标记**，顺序为 `M6c OK` → M7a 六条 → M7b 十四条 → M7d 七条用户标记 → M8a 两条 → M8b 两条 → M8c 一条 → `[CaelumKernel] M7d OK (sockets=0, bindings=0)` → deliberate `M2 #PF caught`（最后）→ `halting`；宿主单测 1037（bootinfo 24、elf64 22、xtask 82、kernel lib 909），共享库 native-abi 35/block 8/fat32 37/ext2 35 全绿；host 两阶段磁盘复核、M6c 两次截图像素与 payload 强制、M7a/M7b/M7d 载荷精确校验全部保留。
79. M8 阶段关键返工与边界：M8a 首启曾 #PF，根因是内核 mprotect/protect 路径把页标记为 not-present（`cr2=0x900000`、`rip=0x40542c`），修复后通过；M8c 首启曾 `[CaelumLinux] FAIL stage=9 step=4 rc=-38`（`-ENOSYS`，`clock_nanosleep` 的 Linux 兼容回归，非用户侧），修复后通过；M8c 的 Wait 重放 rax 回归已修复。边界：M8c 只覆盖单线程/单进程自信号（M8d 另行覆盖受控 parent/child 双进程信号与回收），任意进程/线程组投递、信号排队与完整 siginfo 仍未实现；M7c 未实施、完整 M7 未关闭；M8e 已在进行，完整 M8 未完成。
80. M8d 工程实现完成（Linux64 parent/child 双进程处理闭环）：`services/linux-net` 增加 `STAGE_PROCESS=12` 的 parent/child 角色——parent 是 detached 测试根（`getppid()==0`），child 由内核 `spawn_linux_child` 创建且与 parent 同在 AP1（parent 的阻塞 `wait4` 重放依赖同 CPU 的 child 退出唤醒）；父进程用 `kill(-1, SIGWINCH)` 广播握手、child 用 `tgkill(parent, SIGUSR1)` 回送并确认 handler 恰跑一次；child 恢复 `SIG_DFL` 后，父进程第二次 `SIGUSR1` 触发默认动作终止 child，父进程用阻塞 `wait4` 回收（校验 `WIFSIGNALED`、`WTERMSIG==SIGUSR1`、回收 pid 自洽），随后 `wait4(WNOHANG)` 返回 `ECHILD`；内核 `m7d_closeout` 记录进入时进程数基线，回收 parent 后校验 `live_count()` 回到基线，失败即 `linux-child-not-reaped`。
81. `xtask` 验收升级：标记总数 115 → **116**（每启动），新增 `[CaelumLinux] M8d process OK`（纯文本、无 payload，**仅 parent 打印一次**、child 不打印）；位置契约 `M8C_SIGNALS → M8D_PROCESS → M7D_KERNEL_OK → M2 #PF caught`；`required_markers`、顺序/缺失/提前停机测试与 116 条计数断言同步，M1～M8c 回归全部保留。
82. 主代理两启动 QEMU/OVMF 验收通过：`target/serial-boot1.log`（8111 B，03:54:42）与 `serial-boot2.log`（8058 B，03:54:47）各 **116/116 标记**，`[CaelumLinux] M8d process OK` 每启动恰好出现 1 次且位于 M8c 之后、`[CaelumKernel] M7d OK` 之前，`M2 #PF caught` 仍最后；宿主单测 **1053**（bootinfo 24、elf64 22、xtask 83、kernel lib 924），`cargo xtask check`/`cargo xtask image` 均 exit 0（六模块 init/child/worker/gfx/net/linux + 280 B 头 = 5742224 B；ESP 33 MiB，loader 116736 / kernel 8957544）；版本：loader 0.2.0、kernel 0.16.0、Boot Protocol 1.1、native ABI 0.6（M8d 不新增原生 ABI）。状态：M8a/M8b/M8c/M8d 已完成并验收，M8e 已在进行，完整 M8 未完成；M7c 未实施，完整 M7 未关闭。
83. M8e 工程实现完成：Linux64 扩展文件语义切片（`lseek` 三种 whence 与负路径、`dup` 共享打开文件描述偏移、`fstat`/`statx`、`getdents64` 分片目录枚举、`fcntl` 的 FD_CLOEXEC/F_DUPFD/F_DUPFD_CLOEXEC 与未知请求负路径）落在 `services/linux-net` stage 13 与 kernel `compat/linux` 的文件 syscall 上；成功打印 `[CaelumLinux] M8e files OK`，每启动 119 个集成标记。
84. M8f 工程实现完成：futex 基础契约（值匹配/不匹配、零与短相对超时、无等待者 wake、PRIVATE 变体）与 TLS/线程身份（`arch_prctl` 安装/读回匿名 TLS 页、FS 区与普通内存互见、恢复旧基；`set_tid_address` 返回 tid、`clear_child_tid` 哨兵与重复注册幂等）落在 `services/linux-net` stage 14/15 与 kernel `compat/linux`/`process`；分别打印 `[CaelumLinux] M8f futex OK` 与 `M8f tls OK`，每启动 119 个集成标记。
85. 主代理两启动 QEMU/OVMF 验收通过：`target/serial-boot1.log`（8158 B，04:45:22）与 `serial-boot2.log`（8197 B，04:45:27）各 **119/119** 标记，顺序 `… M8c signals OK → [CaelumLinux] M8d process OK → [CaelumLinux] M8e files OK → `[CaelumLinux] M8f futex OK → [CaelumLinux] M8f tls OK → [CaelumLinux] M8g eventfd OK → [CaelumLinux] M8g poll OK → [CaelumKernel] M7d OK (sockets=0, bindings=0) → [CaelumKernel] M2 #PF caught`（最后）；宿主单测 **1075**（bootinfo 24 / elf64 22 / xtask 85 / kernel lib 944）、`cargo xtask check` 与 `cargo xtask image` 通过；版本快照 kernel 0.16.0、loader 0.2.0、Boot Protocol 1.1、native ABI 0.6（M8e/M8f 属 Linux64 人格，不新增原生 ABI）。此后状态为：M1～M6、M7a/M7b/M7d 与 M8a～M8f 已完成并验收，M7c 未实施、完整 M7 未关闭，M8g 已在进行、完整 M8 未完成。
86. M8g 工程实现完成：eventfd2（计数与读写、非阻塞/负路径）与 poll/ppoll（就绪、超时、临时 sigmask）落在 `services/linux-net` stage 16/17 与 kernel `compat/linux` 的 poll/select 路径；`ppoll` 的临时 sigmask 只在调用期间生效、被信号中断时返回 `-EINTR` 且内核不重放该等待（等待帧的 rax 重放回归已修）。内核另把 Process 用户内核栈从 `KERNEL_STACK_FRAMES=4`（16 KiB）扩到 8 帧（32 KiB，`Process`=2144），根因是 M8g 首启 #DF：深层 TCP 回环投递把最坏路径帧和推到 16304 B 超过 16 KiB 栈、在 `netcore::tcp::TcpConnection::on_segment_synchronized+7` 踩 guard；`services/linux-net` 打印 `[CaelumLinux] M8g eventfd OK` 与 `M8g poll OK`。
87. `xtask` 验收升级：标记总数 119 → **121**（每启动），新增 `[CaelumLinux] M8g eventfd OK`、`M8g poll OK`（纯文本、仅 parent 各打印一次、无 payload）；位置契约 `M8F_TLS → M8G_EVENTFD → M8G_POLL → M7D_KERNEL_OK → M2 #PF caught`；required/顺序/缺失/提前停机测试与 121 条计数断言同步，M1～M8f 回归全部保留。
88. 主代理两启动 QEMU/OVMF 验收通过：`target/serial-boot1.log`（8272 B，05:49:31）与 `serial-boot2.log`（8256 B，05:49:37）各 **121/121 标记**，顺序 `… M8f tls OK → [CaelumLinux] M8g eventfd OK → [CaelumLinux] M8g poll OK → [CaelumKernel] M7d OK (sockets=0, bindings=0) → [CaelumKernel] M2 #PF caught`（最后）；宿主单测 **1097**（bootinfo 24、elf64 22、xtask 86、kernel lib 965），`cargo xtask check` 与 `cargo xtask image` 均 exit 0（六模块 initramfs 5785968 B = 1218936 init + 934224 child + 831560 worker + 872144 gfx + 1007624 net + 921200 linux + 280 头；ESP 33 MiB，loader 116736 / kernel 9337648）。
89. 版本快照：loader 0.2.0、kernel 0.16.0、Boot Protocol 1.1、native ABI 0.6（M8g 属 Linux64 人格，不新增原生 ABI；`docs/abi` 本轮未改）。状态：M1～M6、M7a/M7b/M7d 与 M8a～M8g 已完成并验收；M7c 未实施、完整 M7 未关闭；M8h 已在进行、完整 M8 未完成。
90. M8h 工程实现完成（procfs/devfs 视图）：`kernel/src/vfs/pseudo.rs` 用真实 `Backing::Generated` 文件与 `CharDevice` 节点安装 `/proc`、`/proc/self`、`/proc/self/status`、`/proc/uptime`、`/dev/null`、`/dev/zero`；`/proc/self/status` 每次 read 按当前 owner 现场渲染 `Name: linux`/`State`（running/sleeping/zombie）/`Pid`/`PPid`/`Uid`/`Gid`/`Threads: 1`（size 0、不进页缓存），`/proc/uptime` 由单调时钟输出“秒.百分秒”两字段（uptime 与 idle 相同），`/dev/null`(1,3) 读 EOF/写丢弃、`/dev/zero`(1,5) 无限零字节/写丢弃；`/proc` 目录经 `getdents64` 可列出 `self`/`uptime`；`services/linux-net` 打印 `[CaelumLinux] M8h procfs OK` 与 `M8h devfs OK`（仅 parent 各一次、无 payload），位置在内核 `[CaelumKernel] M7d OK` 之前。
91. `xtask` 验收升级：标记总数 121 → **123**（每启动），新增 `[CaelumLinux] M8h procfs OK`、`[CaelumLinux] M8h devfs OK`（纯文本、仅 parent 各打印一次、无 payload）；位置契约 `M8G_POLL → M8H_PROCFS → M8H_DEVFS → M7D_KERNEL_OK → M2 #PF caught`；required/顺序/缺失/提前停机测试与 123 条计数断言同步，M1～M8g 回归全部保留。
92. 主代理两启动 QEMU/OVMF 验收通过：`target/serial-boot1.log`（8327 B，06:34:44）与 `serial-boot2.log`（8311 B，06:34:50）各 **123/123 标记**，顺序为 `… M8f tls OK → [CaelumLinux] M8g eventfd OK → [CaelumLinux] M8g poll OK → [CaelumLinux] M8h procfs OK → [CaelumLinux] M8h devfs OK → [CaelumKernel] M7d OK (sockets=0, bindings=0) → deliberate #PF → [CaelumKernel] M2 #PF caught`（最后）→ `halting`；无 FAIL/PANIC/unexpected（仅 UEFI BdsDxe 固件提示）。宿主单测 **1106**（bootinfo 24、elf64 22、xtask 87、kernel lib 973），`cargo xtask check`/`cargo xtask image` 均 exit 0（六模块 initramfs 5805592 B = 1218936 init + 934224 child + 831560 worker + 872144 gfx + 1007624 net + 940824 linux + 280 头；ESP 33 MiB，loader 116736 / kernel 9370520）。
93. 版本快照：loader 0.2.0、kernel 0.16.0、Boot Protocol 1.1、native ABI 0.6（M8h 属 Linux64 人格，不新增原生 ABI；`docs/abi` 本轮未改）。状态：M1～M6、M7a/M7b/M7d 与 M8a～M8h 已完成并验收；M7c 未实施、完整 M7 未关闭；M9a（Linux 用户态扩展第一切片）已在进行，完整 M8 与完整 M9 未关闭。
94. M9a 工程实现完成（Linux 用户态扩展第一切片）：`services/linux-net` 新增 timerfd、signalfd、epoll 三个用户态可见面，落在 kernel `compat/linux` 的 Linux64 syscall 入口与错误路径上——timerfd 到期 read 返回 8 字节计数（含超时/取消负路径）、signalfd 把待处理信号转为 fd 可读并受 sigmask 过滤、epoll 以基础 level-triggered 语义报告 EPOLLIN/EPOLLOUT 就绪（零/正超时）；分别打印 `[CaelumLinux] M9a timerfd OK`、`M9a signalfd OK`、`M9a epoll OK`；每启动 126 个集成标记（123 + 3）；原生 ABI 仍 0.6（M9 系列属 Linux64 人格，不新增原生 ABI）。
95. `xtask` 验收升级：标记总数 123 → **126**（每启动），新增三条无 payload 用户标记 `[CaelumLinux] M9a timerfd OK`、`M9a signalfd OK`、`M9a epoll OK`；位置契约 `M8H_DEVFS → M9A_TIMERFD → M9A_SIGNALFD → M9A_EPOLL → M7D_KERNEL_OK → M2 #PF caught`；required/顺序/缺失/提前停机测试与 126 条计数断言同步，M1～M8h 回归全部保留。
96. 主代理两启动 QEMU/OVMF 验收通过：`target/serial-boot1.log`（8396 B，07:17:04）与 `target/serial-boot2.log`（8397 B，07:17:10）各 **126/126 标记**，顺序为 `… M8h devfs OK → [CaelumLinux] M9a timerfd OK → M9a signalfd OK → M9a epoll OK → [CaelumKernel] M7d OK (sockets=0, bindings=0) → deliberate #PF → [CaelumKernel] M2 #PF caught`（最后）→ `halting`；宿主单测 **1134**（bootinfo 24、elf64 22、xtask 88、kernel lib 1000），`cargo xtask check` 与 `cargo xtask image` 均 exit 0（六模块 initramfs 5826696 B；ESP 33 MiB，loader 116736 / kernel 9691832）。
97. 版本快照：loader 0.2.0、kernel 0.16.0、Boot Protocol 1.1、native ABI 0.6（M9a 属 Linux64 人格，不新增原生 ABI；`docs/abi` 本轮未改）。状态：M1～M6、M7a/M7b/M7d 与 M8a～M8h、M9a 已完成并验收；M7c 未实施、完整 M7 未关闭；M9b（AF_UNIX abstract 命名空间、`SCM_RIGHTS`/`SCM_CREDENTIALS` fd 传递、epoll 边沿触发）已在进行，完整 M8 与完整 M9 未关闭。

98. M9b 工程实现完成（Linux 用户态扩展第二切片）：`services/linux-net` 新增 AF_UNIX abstract 命名空间（NUL 开头 abstract 地址与路径名地址并存）、`SCM_RIGHTS` fd 传递（发送方 fd → 内核对象引用 → 接收方新 fd，权限只保留/缩减）、`SCM_CREDENTIALS` 校验与 epoll `EPOLLET` 边沿触发/drain，四套件分别打印 `[CaelumLinux] M9b abstract OK`/`M9b rights OK`/`M9b credentials OK`/`M9b epoll-et OK`。
99. `xtask` 验收升级：标记总数 126 → **130**（每启动），新增四条无 payload 用户标记 `[CaelumLinux] M9b abstract OK`、`M9b rights OK`、`M9b credentials OK`、`M9b epoll-et OK`；位置契约 `M9A_EPOLL → M9B_ABSTRACT → M9B_RIGHTS → M9B_CREDENTIALS → M9B_EPOLL_ET → M7D_KERNEL_OK → M2 #PF caught`，复用 `[CaelumKernel] M7d OK (sockets=0, bindings=0)` 内核 verdict，不新增内核标记。
100. 主代理两启动 QEMU/OVMF 验收通过：`target/serial-boot1.log`（8534 B，08:09:16）与 `target/serial-boot2.log`（8518 B，08:09:22）各 **130/130 标记**，顺序为 `… M9a epoll OK → M9b abstract OK → M9b rights OK → M9b credentials OK → M9b epoll-et OK → [CaelumKernel] M7d OK (sockets=0, bindings=0) → deliberate #PF → M2 #PF caught`；宿主 1164 = 24 + 22 + 89 + 1029，initramfs 5849712 B / kernel 9920680。
101. 版本快照：loader 0.2.0、kernel 0.16.0、Boot Protocol 1.1、native ABI 0.6（M9b 属 Linux64 人格，不新增原生 ABI；`docs/abi` 本轮未改）。状态：M1～M6、M7a/M7b/M7d 与 M8a～M8h、M9a/M9b 已完成并验收；M7c 未实施、M9c 已在进行；完整 M7/M8/M9 均未关闭。
102. M9c xtask 验收接线（已随 M9c 验收关闭）：新增无 payload 用户标记 `[CaelumLinux] M9c locks OK`（位置 `M9B_EPOLL_ET → M9C_LOCKS → M7D_KERNEL_OK → M2 #PF caught`），每启动标记总数 130 → **131**，复用 `[CaelumKernel] M7d OK (sockets=0, bindings=0)` 内核 verdict、不新增内核标记；required/顺序/缺失/提前停机测试与计数断言同步。`cargo test -p xtask` 90 passed、`cargo xtask check`（含 fmt --all 与全部单测）与 `cargo xtask image` 均通过。

103. M9c 工程实现完成（Linux64 文件锁/fcntl）：同一 `linux` ELF 的 role2 锁对端（父进程与 role2 子进程互相持有同一文件并验证冲突/释放），VFS 三类锁域——POSIX `fcntl` 锁按线程组持有、OFD 锁按打开文件描述、`flock` 独立域，含冲突检测、关闭/进程退出释放与继承负路径；修复 M8g 遗留的 SIGUSR1 blocked mask（进入锁测试前清空屏蔽字并恢复 disposition）与 peer EXIT ack/收割顺序；`MAX_PROCESSES = MAX_SPACES = 4`（新增第 4 个内核栈基址 `0xFFFF_FFFF_8120_0000`，812 槽 + 812 guard，复用既有页表）；`MAX_CHILDREN = 2` 以支持同 ELF 双角色；打印 `[CaelumLinux] M9c locks OK`。

104. 主代理两启动 QEMU/OVMF 验收通过（M9c）：kernel host 单测 1047/0、no_std 0 warning、`cargo fmt --all -- --check` 通过、`cargo xtask check` 与 `cargo xtask image` 通过；`cargo xtask qemu --offline` 两启动各 **131/131** 标记，`[CaelumLinux] M9c locks OK` 在 `[CaelumKernel] M7d OK (sockets=0, bindings=0)` 之前、`[CaelumKernel] M2 #PF caught` 最后，无诊断残留。两启动日志 `target/serial-boot1.log`（8562 B，08:54:59）与 `target/serial-boot2.log`（8546 B，08:55:05）。

105. 宿主单测基线（M9c 验收后）：**1183** = bootinfo 24 + elf64 22 + xtask 90 + kernel lib 1047；共享库独立测试 native-abi 35、block 8、fat32 37、ext2 35；六模块 initramfs **5864624 B**（init 1218936 + child 934224 + worker 831560 + gfx 872144 + net 1007624 + linux 999856 + 280 头）、ESP 33 MiB（loader 116736 / kernel 10055112）；版本 loader 0.2.0、kernel 0.16.0、Boot Protocol 1.1、原生 ABI 0.6（M9c 属 Linux64 人格，不新增原生 ABI；`docs/abi` 本轮未改）。

106. M9d 立项（M9d1/M9d2 已验收）：M9d 拆成 M9d1（Linux64 动态 ELF/PT_INTERP 最小闭环）与 M9d2（真实 ET_EXEC vDSO）两个验收切片；两者均在 `xtask` 标记链中实现并通过两启动验收，见第 107～112 条。

107. M9d1 工程实现完成（Linux64 动态 ELF/PT_INTERP 最小闭环）：`services/linux-dyn`（ET_DYN 主程序，`PT_INTERP=/fat/ldcaelum.so`，4 条 RELATIVE、无 DT_NEEDED）与 `services/linux-interp`（自研 ET_EXEC 解释器 `ldcaelum`，基址 0x40000000、无 PT_INTERP）；内核在 `m7d_closeout` 中经 VFS 读取 `/fat/dyn-main` 与 `/fat/ldcaelum.so`（只接受这两条路径）并通过 auxv 注入 `AT_PHDR`/`AT_ENTRY`；用户打印 `[CaelumDyn] interp OK` 与 `[CaelumLinux] M9d dynamic OK`。

108. M9d2 工程实现完成（真实 ET_EXEC vDSO）：`services/linux-vdso` 产出 8808 B ET_EXEC（entry `0x7001000`）与全局只读数据页（magic/version/seq/hz/ticks，序号校验保证一致快照）；内核映射并以 `AT_SYSINFO_EHDR` 暴露，用户按 ELF `e_entry` 直接调用（不做符号表解析）；CLOCK_MONOTONIC/BOOTTIME 由 hz/ticks 计算，CLOCK_REALTIME 显式返回 `-ENOSYS`；打印 `[CaelumLinux] M9d vdso OK`。

109. `xtask` 验收升级（M9d）：新增三条用户标记 `[CaelumDyn] interp OK`、`[CaelumLinux] M9d dynamic OK`、`[CaelumLinux] M9d vdso OK`（当时均无 payload；interp 行后在 M9e/M9f 阶段带上 `(needed=…, libs=…, globdat=…, relative=…)` 计数 payload，harness 仍按前缀匹配），顺序 `M9C_LOCKS → M9D_INTERP → M9D_DYNAMIC → M9D_VDSO → M7D_KERNEL_OK → M2 #PF caught`，标记总数 131 → **134**；`cmd_build` 增加三个 release 产物构建（dyn 需 `RUSTFLAGS=-C relocation-model=pic`，interp/vdso 由各自 build.rs 保证 ET_EXEC/ET_DYN 形态），`cmd_qemu` 把三文件逐字节注入 FAT 测试盘（`/fat/dyn-main`、`/fat/ldcaelum.so`、`/fat/vdso.so`），两次启动后用共享 fat32 库逐字节复核；`cargo test -p xtask` 99 passed。

110. M9d 阶段关键返工：M9d2 首启 `[CaelumLinux] FAIL m9d vdso-realtime` → `[CaelumKernel] M7d FAIL dyn-exit`，根因是用户 vDSO 入口用 `mov eax,-38`（32 位写零扩展，返回值不是 -38），改为 `mov rax,-38` 后通过；另 vDSO 构建必须保证镜像仍为 ET_EXEC 且 entry 不变（`-no-pie`），PIC 只用于 M9d1 的 dyn 主程序。

111. 主代理两启动 QEMU/OVMF 验收通过（M9d2）：两启动各 **134/134** 个标记，顺序 `… [CaelumLinux] M9c locks OK → [CaelumDyn] interp OK → [CaelumLinux] M9d dynamic OK → [CaelumLinux] M9d vdso OK → [CaelumKernel] M7d OK (sockets=0, bindings=0) → deliberate #PF → [CaelumKernel] M2 #PF caught`，末位 #PF；宿主 1201 = 24 + 22 + 99 + 1056，initramfs 5864624 B / kernel 10145344；两启动日志 8639 B（09:43:12）/ 8623 B（09:43:19）。

112. 版本快照：loader 0.2.0、kernel 0.16.0、Boot Protocol 1.1、native ABI 0.6（M9d 属 Linux64 人格，不新增原生 ABI；`docs/abi` 本轮未改）。状态：M1～M6、M7a/M7b/M7d、M8a～M8h、M9a/M9b/M9c、M9d1/M9d2 已完成并验收；M7c 未实施、完整 M7 未关闭；完整 M8 与完整 M9 未关闭（M9 其余切片：完整共享库/重定位与 Linux 工具运行等）。

113. M9e 工程实现完成（真实 ET_DYN 共享库）：`services/linux-m9e-lib`（`caelum-m9e-lib`）产出 2392 B ET_DYN 共享库（无进程入口、`e_entry=0`），`caelum-linux-dyn` 仅以 `DT_NEEDED=/fat/m9e.so` 单依赖它；内核在 `m7d_closeout` 经 VFS 读取 `/fat/m9e.so`，以新增的 `validate_for_shared_object` 校验（要求 ET_DYN，但不要求 e_entry 落在可执行段；段/地址上限/权限/偏移同余/重叠规则仍适用），把库映射到冻结 bias，并由自研解释器应用库内 RELATIVE 与主程序 GLOB_DAT；用户打印 `[CaelumLinux] M9e shared OK`。

114. `xtask` 验收升级（M9e）：四份 release 注入产物（dyn 主程序、interp、vdso 与 `/fat/m9e.so`），lib 先以 `RUSTFLAGS=-C relocation-model=pic` release 构建，dyn 再用 `CAELUM_M9E_LIB=<abs lib>` + pic 构建；新增纯文本标记 `[CaelumLinux] M9e shared OK` 与位置 `M9D_VDSO → M9E_SHARED → M7D_KERNEL_OK → M2 #PF caught`，标记总数 134 → **135**；`cargo test -p xtask` 103 passed。

115. M9e 阶段关键返工：共享库 `e_entry=0`，不能沿用 M9d1 主程序的“入口必须落在可执行 PT_LOAD 内”校验；`libs/elf64` 新增 `validate_for_shared_object(bias)`（与 `validate_for_user_dynamic` 共用段校验，仅关闭入口段要求），内核装载路径改用它，否则 `/fat/m9e.so` 会被误判为坏 ELF。

116. 主代理两启动 QEMU/OVMF 验收通过（M9e）：两启动各 **135/135** 个标记，顺序 `… [CaelumLinux] M9d dynamic OK → [CaelumLinux] M9d vdso OK → [CaelumLinux] M9e shared OK → [CaelumKernel] M7d OK (sockets=0, bindings=0) → deliberate #PF → [CaelumKernel] M2 #PF caught`，末位 #PF；两启动日志 8828 B（10:17:35）/ 8812 B（10:17:41）。

117. 版本快照：loader 0.2.0、kernel 0.16.0、Boot Protocol 1.1、native ABI 0.6（M9e 属 Linux64 人格，不新增原生 ABI；`docs/abi` 本轮未改）。状态：M1～M6、M7a/M7b/M7d、M8a～M8h、M9a/M9b/M9c、M9d1/M9d2/M9e 已完成并验收；M7c 未实施、完整 M7 未关闭；完整 M8 与完整 M9 未关闭（M9 其余切片：完整共享库 PLT/GOT 重定位与 Linux 工具运行等）。

118. M9f 工程实现完成（真实链式三库共享库闭包）：`services/linux-m9f-a`（`caelum-m9f-a`，2336 B ET_DYN，SONAME `/fat/m9f-a.so`，自身 `DT_NEEDED=/fat/m9f-b.so`）与 `services/linux-m9f-b`（`caelum-m9f-b`，1800 B ET_DYN，SONAME `/fat/m9f-b.so`，无依赖）；`caelum-linux-dyn` 的 `DT_NEEDED` 固定为 `/fat/m9e.so`→`/fat/m9f-a.so`。内核在 `m7d_closeout` 经 VFS 读取三库、用 `validate_for_shared_object` 校验后映射进同一地址空间（冻结 bias `0x0300_0000`/`0x0380_0000`/`0x0400_0000`），自研解释器按 m9e→A→B 冻结顺序解析 SONAME（`bias + DT_STRTAB + soname`）并由 GLOB_DAT 解析 A→B 的函数调用与库内自身 counter，无 PLT 懒绑定/`JUMP_SLOT`；用户打印 `[CaelumLinux] M9f shared OK`。
119. `xtask` 验收升级（M9f）：release 注入产物从四个扩展到六个（新增 `caelum-m9f-a` 2336 B、`caelum-m9f-b` 1800 B，均 ET_DYN）；构建顺序 B→A→m9e→dyn（B/A 用 pic，A 构建时以 `CAELUM_M9F_B_LIB` 指定 B，dyn 以 `CAELUM_M9E_LIB`+`CAELUM_M9F_A_LIB` 指定 m9e 与 A），`cmd_check`/`cmd_image`/`image_is_stale`/FAT 注入与双启逐字节复核全部同步；新增纯文本标记 `[CaelumLinux] M9f shared OK`，位置 `M9D_VDSO → M9E_SHARED → M9F_SHARED → M7D_KERNEL_OK → M2 #PF caught`，标记总数 135 → **136**；`cargo test -p xtask` 107 passed。
120. M9f 阶段关键返工：自研解释器最初以 `bias + DT_SONAME` 校验三库 SONAME，漏了 `DT_STRTAB` 间接层，首启失败于 `[CaelumDyn] FAIL m9e-soname`；改为 `bias + DT_STRTAB + soname` 后两启动通过（校验未放宽，kernel/xtask 契约不变）。
121. 主代理两启动 QEMU/OVMF 验收通过（M9f）：两启动各 **136/136** 个标记，顺序 `… [CaelumLinux] M9d dynamic OK → [CaelumLinux] M9d vdso OK → [CaelumLinux] M9e shared OK → [CaelumLinux] M9f shared OK → [CaelumKernel] M7d OK (sockets=0, bindings=0) → deliberate #PF → [CaelumKernel] M2 #PF caught`，末位 #PF；两启动日志 8734 B（10:49:39）/ 8718 B（10:49:46）。
122. 版本快照：loader 0.2.0、kernel 0.16.0、Boot Protocol 1.1、native ABI 0.6（M9f 属 Linux64 人格，不新增原生 ABI；`docs/abi` 本轮未改）。状态：M1～M6、M7a/M7b/M7d、M8a～M8h、M9a/M9b/M9c、M9d1/M9d2、M9e 与 M9f 已完成并验收；M7c 未实施、完整 M7 未关闭；完整 M8 与完整 M9 未关闭。

---

## 11. 当前阶段的完成定义

M0 设计审阅与修订阶段已经正式关闭：

- [x] R-01～R-14 已合并到 `agents.md` v0.2。
- [x] S-01～S-15 已写回设计文档 v0.2.1。
- [x] `agents.md` 版本、修订摘要和受影响章节已更新。
- [x] 本文档已同步反映 v0.2.1 修订状态和智能体复核结果。
- [x] 项目所有者已明确确认设计基线并正式关闭 `agents.md` 第 27.1 节的 M0 条件。
- [x] 没有产生任何伪装成已验证能力的实现或测试结论。

M1 启动闭环已经完成并验收：

- [x] Loader、BootInfo、内核入口、早期串口和 FAT16 ESP 镜像生成已实现。
- [x] `cargo xtask test` 可重复执行并通过。
- [x] M1 时点 29 个宿主单元测试通过（当前计数见 §13.1）。
- [x] QEMU/OVMF 成功路径输出 Loader/内核版本、协议版本和内存摘要。
- [x] `.caelum.bootreq` 不兼容时 Loader 在 `ExitBootServices` 前拒启。
- [x] BootInfo 校验和损坏时内核输出最小失败信息并停机。

M2 异常与内存已经完成并验收：

- [x] GDT/TSS/IDT 重建，`#UD/#GP/#DF(IST1)/#PF` 与 `#DE/NMI(IST2)/#SS/#AC` 可用。
- [x] PMM、内核堆、高半核 VM 接管与 W^X 映射完成。
- [x] 故意缺页被捕获并打印完整寄存器转储。

M3 中断与线程已经完成并验收：

- [x] ACPI/MADT → xAPIC/IOAPIC，GSI1 键盘与 GSI4 COM1 RX 路由，EOI 与 spurious 处理。
- [x] PIT 校准的 LAPIC 100 Hz 单调时钟；初始化前后的日志时间策略可观察。
- [x] PS/2 键盘与串口 RX 中断路径由外部注入触发，并由内核打印确认标记。
- [x] 两个内核线程 A/B 使用独立内核栈、守卫页、双 canary；A 协作 yield、B 由 timer 抢占推进。
- [x] `cargo xtask test` 自动注入并通过全部 17 个标记；M1/M2 回归标记全部保留。

M4 原生对象与首个用户进程已经完成并验收：

- [x] 内核原生对象表与每进程句柄表；句柄不隐式继承，关闭只释放表项（负路径由宿主回归覆盖）。
- [x] `syscall` 入口与原生 ABI 0.1 落地；参数边界与 copy-in/copy-out 有宿主单测。
- [x] Boot Protocol 1.1 启动模块 TLV；Loader 载入 ESP 根 `/INITFS.IMG` 并交给内核，内核只读映射。
- [x] 统一 ELF 装载器装载 init/child 到用户地址空间，首次 `iretq` 进入 ring 3。
- [x] init 创建 child（仅经创建参数传初始句柄）、等待 status 0、查询 `rng`（`NoEntropy`），init/child 正常退出。
- [x] 验收时点 `cargo xtask test` 通过全部 27 个标记（M4 时点；当前总计 33 个），`[CaelumKernel] M2 #PF caught` 为最后一个标记；M1～M3 回归标记全部保留。

M5a VFS/页缓存/ramfs 与启动模块迁移已经完成并验收：

- [x] 内核 VFS 骨架：挂载表、VNode、打开文件描述与路径解析（含边界与深度限制）。
- [x] 页缓存最小实现；ramfs 支持创建/读写/删除/目录枚举。
- [x] 三类锁域与目录变更通知的最小可验证实现。
- [x] M4 启动模块读取迁移到 VNode + 页缓存，`image.rs` 经 VFS 装载 init/child，无并行装载路径。
- [x] 栈/内存返工：VFS 静态原位 `State` 消除 92 KiB 临时缓冲，路径 out-param 消除 `parse_parent` 的 7.4 KiB 栈帧，未扩大 16 KiB boot stack。
- [x] `cargo xtask test` 通过全部 33 个标记（8 M1/M2 + 9 M3 + 10 M4 + 6 M5a），`[CaelumKernel] M2 #PF caught` 为最后一个标记；M4 用户态链仍完整通过。

M5b 持久化与块设备已经完成并验收：

- [x] ACPI MCFG/ECAM 配置空间枚举与 PCI 设备发现（总线/设备/功能、BAR 与 capability 读取）。
- [x] legacy `virtio-blk-pci` ×2（`queue-size=128`）、virtqueue 与读写请求路径，早期连续 DMA 预留 2 帧。
- [x] FAT32 持久化（64 MiB 空盘、spc=1 ≈129k clusters，满足规范 65525 下限）与 ext2 持久化（32 MiB）。
- [x] 持久化真实经过“块设备 → 文件系统 → VFS → 页缓存”：首启由 guest 建文件并 sync，二启读回、追加、rename、truncate，跨重启数据仍在。
- [x] host 两阶段复核：启动 1 后校验 state/8192 字节 pattern/旧文件名；启动 2 后校验 state、done、旧名删除、最终 4608 字节与前 4608 pattern。
- [x] `cargo xtask test` 两启动各 41 个标记（8 M1/M2 + 9 M3 + 10 M4 + 6 M5a + 8 M5b；M5b 时点，M5c 后为 56 个），`[CaelumKernel] M2 #PF caught` 为最后一个标记；M4/M5a 链全部保留。

M5c 用户文件/目录语义、mmap、同步、锁、xattr、稀疏文件、目录通知与故障注入已经完成并验收：

- [x] 早期挂载 FAT32（`/fat`）与 ext2（`/ext2`）成功，`M5c mounts ready` 在 `M4 init spawned` 之前出现。
- [x] 用户态文件与目录语义：init/child 在两条挂载点上创建、写入、回读、改名、截断与目录枚举，分别打印 `M5c files OK`。
- [x] 共享与私有 `mmap`：shared 写回后位置 0 = `0xA5`、4103 = `0x5A`，private `0xFF` 不落盘；init/child 各打印 `M5c mmap OK`。
- [x] 文件锁（含关闭/进程退出释放）、扩展属性（易失）、稀疏文件（32772 字节，洞不占块）、目录监视（watch）与对象销毁钩子、一次性 Write/Flush 故障注入与重试/回读、进程 reap 后资源清理，分别输出 `M5c locks OK`（init/child）、`M5c xattr OK`、`M5c sparse OK`、`M5c watch OK`、`M5c3 faults OK`。
- [x] `cargo xtask test` 两启动各 **56 个标记**（48 回归 + 8 M5c3），`[CaelumKernel] M2 #PF caught` 为最后一个标记；`M5c1 OK`/`M5c2 OK`/`M5c3 OK`/`M5 OK` 顺序受断言保护。
- [x] host 两阶段复核覆盖 M5b state/done、M5c1 14→20 字节用户文件、M5c2 shared/private mmap 最终态、M5c3 32772 字节稀疏文件与 16 字节故障回读文件；任一不符即失败。

M6a1 原生 Event/EventPair/Timer 与真实阻塞已完成并验收：

- [x] 原生 Event（manual/auto reset、`signal`/`reset`/`consume`）与 EventPair（`signal_pair(X)` 置对端 `X^1`；`ready_pair`/`consume_pair` 操作调用方等待的端点）。
- [x] 单调时钟 Timer（绑定对象 + 绝对 deadline；时钟中断 `on_tick` 扫描到期项并 `wake_object(WakeReason::Timeout)`，`consume` 读清就绪位；对象销毁先 `Destroyed` 唤醒再释放槽）。
- [x] 统一等待入口：`Blocked` 成为真实进程状态，阻塞时保存 syscall 帧、唤醒后重放同一帧；`deadline: Option<u64>` 为 `monotonic_ticks` 上的绝对截止。
- [x] init 打印 `M6a timer OK`、`M6a event OK`，child 打印 `M6a event OK`（验证对端唤醒），内核打印 `M6a OK`；原生 ABI 升至 0.3。
- [x] `cargo xtask test` 两启动各 **60 个标记**（56 回归 + 4 M6a1），`[CaelumKernel] M2 #PF caught` 为最后一个标记；顺序契约断言 `M5 OK` → `M6a OK` → 最终 #PF。
- [x] M6a1 不新增磁盘复核项；M5b/M5c 的 host 两阶段复核全部保留并通过。

M6a2 Channel/Port/SharedMemory/EventSubscription/Futex 已完成并验收：

- [x] Channel 与 Port：有界消息队列、阻塞/超时接收、消息元数据与 `ERR_WOULD_BLOCK` 背压；init/child 各打印 `M6a channel OK`、`M6a port OK`。
- [x] SharedMemory：多页共享 + 双别名映射，两别名看到同一物理页；init/child 各打印 `M6a shm OK`。
- [x] EventSubscription：level/edge 两种触发、readiness 重读、drain 后复位与 `unsubscribe`；init 打印 `M6a subscription OK`。
- [x] Futex：wait/wake 与超时，建立在 M6a1 的真实 `Blocked` 状态与 syscall 帧重放之上；init/child 各打印 `M6a futex OK`；原生 ABI 升至 0.4。
- [x] `cargo xtask test` 两启动各 **70 个标记**（60 回归 + 10 M6a2），`[CaelumKernel] M2 #PF caught` 为最后一个标记；顺序契约断言 `M6a OK` → `M6a2 OK` → 最终 #PF，且 9 条用户标记只要求位置不要求相互顺序。
- [x] M6a2 不新增磁盘复核项；M5b/M5c 的 host 两阶段复核全部保留并通过。

M6b1 SMP AP bring-up 与每 CPU 初始化已完成并验收：

- [x] `-smp 4` 下经 ACPI MADT 识别 3 个 AP，用低地址 trampoline（16→32→64 位三段）拉起 AP。
- [x] 每个 AP 完成 per-CPU 初始化（GDT/IDT/TSS、per-CPU 数据与栈）后进入 IF=0 idle 循环；启动完成后释放临时低页。
- [x] 全部 CPU 上线后打印 `[CaelumKernel] M6b1 online=4`，位置在 `[CaelumKernel] M3 OK` 之后、`[CaelumKernel] M4 objects OK` 之前。
- [x] `cargo xtask test` 两启动各 **71 个标记**（70 回归 + 1 M6b1），`[CaelumKernel] M2 #PF caught` 仍为最后一个标记。
- [x] M6b1 不新增磁盘复核项；M5b/M5c 的 host 两阶段复核全部保留并通过。
- [x] 明确未交付：每 CPU 运行队列、负载均衡、CPU 亲和性、跨 CPU 唤醒 IPI、AP 调度（属 M6b2）。

M6b2 每 CPU 运行队列、定时抢占与跨 CPU 唤醒 IPI 已完成并验收：

- [x] 每 CPU 运行队列与受控 worker 调度：`caelum-worker` 为第三个启动模块，`MAX_PROCESSES`/`MAX_SPACES` 扩到 3，3 个 AP 均参与调度。
- [x] AP timer 定时抢占：AP 上命中用户帧并真切走，宿主强制 `preempts>=2`。
- [x] BSP 跨 CPU 唤醒与 reschedule IPI：唤醒来自与目标 last CPU 不同的 CPU，IPI 实际发出，宿主强制 `remote_wakes>=1`、`ipis>=1`。
- [x] 受控亲和迁移与负载均衡迁移各至少一次（两个独立事件，不得重复计数），宿主强制 `migrations>=1`、`balances>=1`。
- [x] worker 阻塞/退出后 park，BSP 等待后 reap；`cargo xtask test` 两启动各 **77 个标记**（71 回归 + M6b2a 1 + M6b2 5），`M6b2 OK` 之后仍以 deliberate `M2 #PF caught` 收尾。
- [x] 明确未交付：通用公平调度、任意进程压力下的调度正确性（本阶段只用 2 个受控 worker 验证）。

M6c 输入和基础显示共享缓冲已完成并验收（完整 M6 由此关闭）：

- [x] 真实显示探测：内核读回 GOP framebuffer 几何并打印 `[CaelumKernel] M6c display probe OK (w=1280, h=800, stride=1280, fmt=1)`，同时在物理 framebuffer 右下角写入 magenta 探针像素。
- [x] 第四个启动模块 `gfx`（`caelum-gfx`）：由内核在 AP1 上以 display/input 两个能力句柄启动，把 320x200 阴影（绿色 `(16,16,64,64)`、蓝色 `(96,16,64,64)`）present 到 framebuffer 原点并打印 `[CaelumGfx] M6c display OK`；退出后由内核 reap。
- [x] 真实输入闭环：harness 在 `M6c input ready` 后先注入 PS/2 `d`（make 0x20 → break 0xA0，`hold-time=100`），等待 150 ms 后再写串口 `m6c`；`gfx` 对五个事件的顺序/kind/code/时间戳逐项断言后打印 `M6c input OK (events=5, dropped=0)`，内核 reap 后打印 `M6c OK (events=5, dropped=0)`，宿主强制 payload 精确为 `events=5`、`dropped=0`。
- [x] 截图像素证据：两次启动各做一次 QMP `screendump`（`target/m6c-screen-boot1.ppm`/`m6c-screen-boot2.ppm`，P6、maxval=255），校验右下角 magenta、`(48,48)` 绿、`(128,48)` 蓝（每通道 ±8）——是真实物理 framebuffer 像素，不是标记文本。
- [x] `cargo xtask test` 两启动各 **82 个标记**（77 回归 + 5 M6c），`M6c OK` 之后仍以 deliberate `M2 #PF caught` 收尾；M5b/M5c 的 host 两阶段磁盘复核与 M6b2 统计阈值全部保留通过。
- [x] 能力边界：只验证一个受控 `gfx` 进程与三条像素契约，**不是完整图形栈、窗口系统或输入子系统**；原生 ABI 升至 0.5。

M7a 内核 loopback 已完成并验收：

- [x] 基于 `libs/netcore` 的 IPv4/IPv6 UDP/TCP 自检在内核内完成（四条套件，往返 7/14 字节）。
- [x] 套件退出后无存活 Socket：`[CaelumKernel] M7a sockets OK (live=0)`、`[CaelumKernel] M7a OK (suites=4)`。
- [x] `cargo xtask test` 两启动各 **88 个标记**（82 回归 + 6 M7a），`[CaelumKernel] M2 #PF caught` 仍为最后一个标记。

M7b 原生 Socket/LocalSocket 已完成并验收：

- [x] 原生 Socket 与 LocalSocket：IPv4/IPv6 UDP/TCP、匿名 `socketpair`、路径名 unix stream/dgram、统一等待（ready/timeout）、`ERR_WOULD_BLOCK` 背压、半关闭 EOF、句柄权限与错误语义。
- [x] 第五个启动模块 `net`（`caelum-net`），loader `BOOT_MODULE_NAMES` 扩为五个并硬校验 count；内核 verdict `[CaelumKernel] M7b OK (sockets=0, bindings=0)`。
- [x] `cargo xtask test` 两启动各 **102 个标记**（88 + 14 M7b），`M7b OK` 之后仍以 deliberate `M2 #PF caught` 收尾。

M7d Linux64 socket 人格核心已完成并验收：

- [x] Linux64 人格：Linux `syscall` 入口与 `-errno`、System V 启动栈与 auxv `AT_CAELUM_CHANNEL`/`AT_CAELUM_NETNS`。
- [x] IPv4/IPv6 UDP/TCP、UNIX stream/datagram `socketpair` 与命名 datagram、fd 最低可用分配/`dup`/`close`、负路径 `ENOSYS`/`EBADF`/`ENOTSOCK`/`EMSGSIZE`。
- [x] 第六个启动模块 `linux`（`caelum-linux-net`）；内核 verdict `[CaelumKernel] M7d OK (sockets=0, bindings=0)`；`cargo xtask test` 两启动各 **110 个标记**，`M2 #PF caught` 仍最后。
- [x] 明确未交付：真实 `virtio-net` 链路（M7c）未实施；M7a/M7b/M7d 的能力边界是 loopback 与本地 Socket，不是完整网络栈或真实网卡。

M8a/M8b/M8c/M8d/M8e/M8f/M8g/M8h（Linux64 基础人格切片）已完成并验收：

- [x] M8a：Linux64 内存与文件语义（mmap/mprotect/munmap、保护位切换与读回、文件读取路径），打印 `[CaelumLinux] M8a memory OK` 与 `M8a files OK`。
- [x] M8b：时间与系统信息（`clock_gettime`/`clock_nanosleep`/`getppid`/`uname`），打印 `[CaelumLinux] M8b time OK` 与 `M8b info OK`。
- [x] M8c：单线程/单进程信号（`rt_sigaction`/`rt_sigprocmask`、`kill`/`tgkill` self、SA_RESTORER 用户帧与 `rt_sigreturn`），打印 `[CaelumLinux] M8c signals OK`；跨进程/跨线程投递与完整 siginfo 未实现（跨进程部分由 M8d 的受控双进程闭环补充）。
- [x] M8d：Linux64 parent/child 双进程处理闭环（同一 `linux` 映像的 parent/child，`kill(-1)`/`tgkill` 双向信号握手、`wait4` 阻塞回收与 `WIFSIGNALED`/`WTERMSIG` 校验、`ECHILD` 与内核进程数基线校验），打印 `[CaelumLinux] M8d process OK`。
- [x] M8e：Linux64 扩展文件语义（lseek/dup/fstat/statx/getdents64/fcntl 与负路径），打印 `[CaelumLinux] M8e files OK`。
- [x] M8f：futex 基础契约（值匹配/不匹配、零与短相对超时、无等待者 wake、PRIVATE 变体）与 TLS（arch_prctl 安装/读回、FS 与普通内存互见、恢复旧基）及 set_tid_address（tid、clear_child_tid 哨兵、幂等），打印 `[CaelumLinux] M8f futex OK` 与 `M8f tls OK`。
- [x] M8g：eventfd 与 poll/ppoll（含临时 sigmask 与 `EINTR`）、Process 用户内核栈 4→8 帧（32 KiB，`Process`=2144）；打印 `[CaelumLinux] M8g eventfd OK` 与 `M8g poll OK`。
- [x] M8h：procfs/devfs 视图（真实 Generated 文件与 CharDevice 节点、`/proc` 目录可枚举、`/dev/null`(1,3)、`/dev/zero`(1,5)），打印 `[CaelumLinux] M8h procfs OK` 与 `M8h devfs OK`。
- [x] `cargo xtask test` 两启动各 **123 个标记**（M8h 时点；M9a 完成并验收后为 126 个），`[CaelumKernel] M2 #PF caught` 仍最后；host 两阶段磁盘复核与 M6c/M7a/M7b/M7d 证据校验全部保留。

M9a Linux 用户态扩展第一切片已完成并验收：

- [x] timerfd：到期 read 返回 8 字节计数，超时/取消负路径正确；用户程序打印 `[CaelumLinux] M9a timerfd OK`。
- [x] signalfd：待处理信号转为 fd 可读，sigmask 过滤生效；打印 `[CaelumLinux] M9a signalfd OK`。
- [x] epoll 基础 level-triggered 语义：`epoll_create1`/`epoll_ctl`/`epoll_wait`、EPOLLIN/EPOLLOUT 就绪报告与零/正超时；打印 `[CaelumLinux] M9a epoll OK`。
- [x] `cargo xtask test` 两启动各 **126 个标记**（123 回归 + 3 M9a），`[CaelumKernel] M2 #PF caught` 仍最后。
- [x] 能力边界：只交付 timerfd/signalfd/epoll 的 level-triggered 基础语义；AF_UNIX abstract 命名空间、`SCM_RIGHTS`/`SCM_CREDENTIALS` fd 传递与 epoll 边沿触发属 M9b，完整 M9 未关闭。

M9b Linux 用户态扩展第二切片已完成并验收：

- [x] AF_UNIX abstract 命名空间：NUL 开头 abstract 地址与路径名地址并存，bind/connect 均可寻址；打印 `[CaelumLinux] M9b abstract OK`。
- [x] `SCM_RIGHTS` fd 传递：发送方 fd 经内核对象引用在接收方生成新 fd，权限只保留/缩减；打印 `[CaelumLinux] M9b rights OK`。
- [x] `SCM_CREDENTIALS` 校验：凭据结构经命名空间与权限规则验证；打印 `[CaelumLinux] M9b credentials OK`。
- [x] epoll `EPOLLET` 边沿触发：一次就绪只报告一次，drain 后需新事件才再次就绪；打印 `[CaelumLinux] M9b epoll-et OK`。
- [x] `cargo xtask test` 两启动各 **130 个标记**（126 回归 + 4 M9b），`[CaelumKernel] M2 #PF caught` 仍最后。
- [x] 能力边界：M9b 只交付 abstract 命名空间、SCM_RIGHTS/SCM_CREDENTIALS 与 epoll ET；完整文件锁/fcntl 属 M9c，完整 M9 未关闭。

M9c（文件锁/fcntl）已完成并验收：

- [x] 同一 `linux` ELF 的 role2 锁对端：父进程与 role2 子进程互相持有同一文件并验证冲突/释放，覆盖 POSIX `fcntl` 与 `flock` 的跨进程互斥。
- [x] VFS 三类锁域：POSIX `fcntl` 锁按线程组持有（关闭任一引用同一文件的 fd 即释放该线程组全部 POSIX 锁）；OFD 锁按打开文件描述，`dup` 不冲突；`flock` 独立锁域，不与前两者互斥。
- [x] 负路径：冲突返回预期错误、关闭/进程退出释放、fork/exec 不继承（由 role2 场景覆盖）。
- [x] 用户态 mask/handler 修复：进入锁套件前清空 M8g 遗留的 SIGUSR1 blocked mask 并恢复 disposition；role2 的 EXIT 分支在退出前发送 ack，父进程按命令顺序收割。
- [x] 内核资源：`MAX_PROCESSES = MAX_SPACES = 4`、新增第 4 个内核栈基址 `0xFFFF_FFFF_8120_0000`（812 槽 + 812 guard，复用既有页表）、`MAX_CHILDREN = 2`。
- [x] `cargo xtask test` 两启动各 **131 个标记**（130 回归 + 1 M9c），`[CaelumKernel] M2 #PF caught` 仍最后。
- [x] 能力边界：M9c 只覆盖同 ELF role2 锁对端与 VFS 三类锁域的最小冲突/释放/继承契约；全 fcntl 命令集、锁等待/死锁边界与跨命名空间场景未覆盖，完整 M9 未关闭。

M9d1（Linux64 动态 ELF/PT_INTERP）已完成并验收：

- [x] ET_DYN 主程序（`caelum-linux-dyn`）由自研 ET_EXEC 解释器 `ldcaelum`（`caelum-interp`，基址 0x40000000）加载；主程序含 `PT_INTERP=/fat/ldcaelum.so`、4 条 RELATIVE、无 DT_NEEDED，解释器无 PT_INTERP。
- [x] 内核在 `m7d_closeout` 中经 VFS 读取 `/fat/dyn-main` 与 `/fat/ldcaelum.so`（只接受这两条路径），并通过 auxv 注入 `AT_PHDR`/`AT_ENTRY`；用户打印 `[CaelumDyn] interp OK` 与 `[CaelumLinux] M9d dynamic OK`（仅 parent 各一次，无 payload）。
- [x] 三份 release ELF 由 `xtask` 逐字节注入 FAT 测试盘，两次启动后 host 侧用共享 fat32 库逐字节复核；`cargo xtask test` 两启动各 **133 个标记**（131 + 2），`M2 #PF caught` 仍最后。

M9d2（真实 ET_EXEC vDSO）已完成并验收：

- [x] `caelum-vdso` 产出 8808 B ET_EXEC（entry `0x7001000`）+ 全局只读数据页（magic/version/seq/hz/ticks，序号校验保证一致快照）；内核映射并以 `AT_SYSINFO_EHDR` 暴露，用户按 ELF `e_entry` 直接调用、无需符号表解析。
- [x] CLOCK_MONOTONIC/BOOTTIME 由 hz/ticks 现场计算，CLOCK_REALTIME 明确返回 `-ENOSYS`；打印 `[CaelumLinux] M9d vdso OK`（仅 parent 一次，无 payload）。
- [x] 两启动各 **134 个标记**（133 + 1），`[CaelumKernel] M2 #PF caught` 仍最后；完整 vDSO（REALTIME 时钟源、符号表与完整语义）未做，完整 M9 未关闭。

M9e（真实 ET_DYN 共享库、`DT_NEEDED` 单依赖）已完成并验收：

- [x] `caelum-m9e-lib` 产出 2392 B ET_DYN 共享库（无进程入口、`e_entry=0`）；`caelum-linux-dyn` 仅以 `DT_NEEDED=/fat/m9e.so` 依赖它（无其他依赖、`PT_INTERP` 契约不变）。
- [x] 内核经 VFS 读取 `/fat/m9e.so`，以 `validate_for_shared_object` 校验后映射到冻结 bias；库内 RELATIVE 与主程序 GLOB_DAT 由自研解释器应用；用户打印 `[CaelumLinux] M9e shared OK`（仅 parent 一次，无 payload）。
- [x] `xtask` 构建四份 release 注入产物并逐字节注入 FAT 测试盘（`/fat/dyn-main`、`/fat/ldcaelum.so`、`/fat/vdso.so`、`/fat/m9e.so`），两次启动后 host 侧逐字节复核。
- [x] 两启动各 **135 个标记**（134 + 1），`[CaelumKernel] M2 #PF caught` 仍最后；PLT/GOT 延迟绑定、符号解析与 glibc/musl 工作负载未做，完整 M9 未关闭。

M9f（真实链式三库共享库闭包）已完成并验收：

- [x] `caelum-m9f-a`（2336 B ET_DYN，SONAME `/fat/m9f-a.so`，`DT_NEEDED=/fat/m9f-b.so`）与 `caelum-m9f-b`（1800 B ET_DYN，SONAME `/fat/m9f-b.so`，无依赖）；`caelum-linux-dyn` 的 `DT_NEEDED` 为 `/fat/m9e.so`→`/fat/m9f-a.so`。
- [x] 内核在 `m7d_closeout` 经 VFS 读取三库并映射进同一地址空间（冻结 bias 0x0300_0000/0x0380_0000/0x0400_0000），自研解释器按 m9e→A→B 解析 SONAME（`bias + DT_STRTAB + soname`）并由 GLOB_DAT 解析 A→B 调用与库内自身 counter，无 PLT 懒绑定/JUMP_SLOT；用户打印 `[CaelumLinux] M9f shared OK`。
- [x] `xtask` 依次 pic release 构建 B→A→m9e→dyn（A 用 `CAELUM_M9F_B_LIB`、dyn 用 `CAELUM_M9E_LIB`+`CAELUM_M9F_A_LIB`），把两库作为第五、六件注入 FAT 并在两启动后逐字节复核。
- [x] 两启动各 **136 个标记**（135 + 1），`[CaelumKernel] M2 #PF caught` 仍最后；dlopen/dlsym、符号版本与 glibc/musl 未做，完整 M9 未关闭。

M8 其余切片、M9 其余切片与 M7c（真实网络链路）尚未完成：

- [ ] M8 其余：fork/clone 完整共享矩阵、线程组、完整 siginfo、任意进程/线程组信号；通过前不得宣称完整 M8 完成。
- [ ] M9 其余切片：完整共享库/重定位（PLT/GOT 延迟绑定与符号解析；M9e/M9f 已交付最小单依赖与链式三库闭包）、glibc/musl 工作负载与 Linux 工具运行、完整 Linux 设备视图等；完整 M9 通过前不得宣称完成。
- [ ] M7c：真实 `virtio-net` 设备链路（legacy 设备 + 中断路径）、QEMU user-net 连通与 link down/up 异常恢复；通过前不得宣称完整 M7 完成。

当前项目状态为：**M0 已关闭，M1～M6 全部已完成并验收（完整 M5、完整 M6 均已关闭）；M7 已完成 M7a/M7b/M7d 并通过两启动验收，M7c（真实 virtio-net 链路）尚未实施，完整 M7 未关闭；M8 已完成 M8a～M8h 八个 Linux64 基础人格切片并通过两启动验收，M8 其余切片未完成；M9a/M9b/M9c、M9d1/M9d2、M9e 与 M9f 均已完成并通过两启动验收（每启动 **136** 个集成标记），完整 M9 仍未关闭（完整共享库 PLT/GOT 重定位与 Linux 工具运行、Linux 设备视图等其余切片未完成）；完整 M8 与完整 M9 均未完成。**

---

## 12. M1 实施与验收记录

### 12.1 工程产物（M1 时点记录，当前计数见 §13.1）

- `rust-toolchain.toml`、`.cargo/config.toml`、workspace `Cargo.toml`。
- `docs/abi/boot-protocol.md`：当时为 Boot Protocol 1.0（现为 v1.1），固定头、TLV、CRC32C、`.caelum.bootreq` 和失败路径规范。
- `libs/bootinfo`：BootInfo 编解码、TLV 校验和 CRC32C，14 个宿主单测。
- `libs/elf64`：ELF64 解析和启动校验，12 个宿主单测。
- `loader/`：`x86_64-unknown-uefi`，手写最小 UEFI 绑定、ESP 文件读取、ELF/元数据预检、初始页表、BootInfo、`ExitBootServices` 重试和内核跳转。
- `kernel/`：`x86_64-unknown-none`，入口、16550 串口、BootInfo 校验、成功路径和最小失败输出。
- `xtask/`：构建、检查、纯 Rust FAT16 ESP 镜像生成和 QEMU 验收，3 个 FAT 镜像单测。
- `tests/qemu/`：PowerShell/Git Bash 验收脚本与说明。
- `tools/ovmf/`：`edk2-stable202605-r1` OVMF_CODE/VARS 固件副本。

### 12.2 环境

- Rust：1.97.1 stable MSVC。
- QEMU：11.1.0，经 winget 安装，路径 `C:\Program Files\QEMU\qemu-system-x86_64.exe`。
- OVMF：`edk2-stable202605-r1`，项目副本位于 `tools/ovmf/`。
- 注意：QEMU 安装器未自动修改当前 shell 的 PATH；`xtask` 会直接探测已知安装路径。

### 12.3 复验命令与结果（M1 时点记录）

已亲自运行：

```bash
cargo fmt --all
cargo xtask test
```

结果：

- `bootinfo` 14/14 通过；
- `elf64` 12/12 通过；
- `xtask` FAT 镜像 3/3 通过；
- Loader 与 kernel 构建通过；
- `target/caelum-esp.img` 生成并读回自检通过；
- QEMU/OVMF 成功路径出现 `[CaelumLoader] ExitBootServices OK`、`[CaelumKernel] bootinfo validate OK`、`[CaelumKernel] memory: ...`、`[CaelumKernel] M1 OK`。

负例也已亲自运行：

- 将 kernel `.caelum.bootreq` 的 major 从 1 改为 2 后，Loader 输出
  `FAIL: kernel Boot Protocol requirements incompatible with loader 1.0; refusing to boot`，
  且未进入 `ExitBootServices`。
- 临时破坏 BootInfo CRC32C 后，内核输出
  `bootinfo validate FAIL: bad-checksum ...; halting`，且未输出 `M1 OK`。
- 两项临时修改均已恢复，最终 `cargo xtask test` 重新通过。

### 12.4 M1 已知限制

- M1 串口基线硬编码为 COM1 / I/O 端口 `0x3F8` / 115200；真实硬件诊断资源探测属于 M11 范围。
- 未生成或使用 `FB_GOP` TLV；图形诊断路径未验收。
- 内核尚未重建 GDT/IDT/TSS，未实现异常、PMM、堆或内核页表接管；这些属于 M2。
- `ExitBootServices` 重试路径已实现，但当前 OVMF 首次引导未触发重试。
- 裸 `cargo build` 在 workspace 根目录不适合直接构建 freestanding loader/kernel；标准命令是 `cargo xtask build`、`cargo xtask test` 或带显式 `--target`。

---

## 13. M1～M6、M7a/M7b/M7d、M8a～M8h 与 M9a～M9c、M9d1/M9d2、M9e 与 M9f 复验摘要与后续交接状态

### 13.1 当前已验证基线（M9f 双启动验收后）

- 验收方式：主代理串行运行 `cargo xtask test`（两启动 QEMU/OVMF、`-smp 4`、双向串口 + QMP、两块 virtio-blk `queue-size=128`）；两启动各 **136/136** 个集成标记，`[CaelumKernel] M2 #PF caught` 仍最后。
- 两启动日志：`target/serial-boot1.log`（8828 B，10:17:35）与 `target/serial-boot2.log`（8812 B，10:17:41）；boot1 t=3010 ms、boot2 t=3040 ms 后 deliberate #PF → `halting`。
- 两启动 M8/M9 段顺序：`M8b info OK → M8c signals OK → [CaelumLinux] M8d process OK → [CaelumLinux] M8e files OK → [CaelumLinux] M8f futex OK → [CaelumLinux] M8f tls OK → [CaelumLinux] M8g eventfd OK → [CaelumLinux] M8g poll OK → [CaelumLinux] M8h procfs OK → [CaelumLinux] M8h devfs OK → [CaelumLinux] M9a timerfd OK → [CaelumLinux] M9a signalfd OK → [CaelumLinux] M9a epoll OK → [CaelumLinux] M9b abstract OK → [CaelumLinux] M9b rights OK → [CaelumLinux] M9b credentials OK → [CaelumLinux] M9b epoll-et OK → [CaelumLinux] M9c locks OK → [CaelumDyn] interp OK → [CaelumLinux] M9d dynamic OK → [CaelumLinux] M9d vdso OK → [CaelumLinux] M9e shared OK → [CaelumLinux] M9f shared OK → [CaelumKernel] M7d OK (sockets=0, bindings=0) → deliberate #PF → [CaelumKernel] M2 #PF caught`。
- 宿主单测：**1223** = bootinfo 24 + elf64 **35** + xtask **103** + kernel lib **1061**；共享库独立测试 native-abi 35、block 8、fat32 37、ext2 35；`cargo fmt --all -- --check` 通过；`cargo xtask check`（末行 `[xtask] check OK`）与 `cargo xtask image` 通过。
- `cargo xtask image`：六模块 initramfs（`1218936 init + 934224 child + 831560 worker + 872144 gfx + 1007624 net + 999856 linux + 280 头 = 5864624 B`），ESP 33 MiB（loader 116736 / kernel **10233800**）；另构建六个 release 注入产物：dyn 13312 B（ET_DYN，`DT_NEEDED=/fat/m9e.so`→`/fat/m9f-a.so`）、interp 19256 B（ET_EXEC）、vdso 8808 B（ET_EXEC entry 0x7001000）、m9e-lib 2392 B、m9f-a 2336 B、m9f-b 1800 B（三者均 ET_DYN 共享库，`e_entry=0`）。
- 136 = 131（M9c 完成时）+ M9d1 2（interp + dynamic）+ M9d2 1（vdso）+ M9e 1（shared）+ M9f 1（shared）；M6b2 统计阈值、M7a/M7b/M7d 载荷、M6c 像素与 payload、M5 两阶段磁盘复核、动态 ELF/vDSO/共享库四文件逐字节复核全部保留。
- 版本：kernel 0.16.0、loader 0.2.0、Boot Protocol 1.1、原生 ABI 0.6（M8e～M9c 属 Linux64 人格，不新增原生 ABI）。
- 仍生效的三条工程约束：内核 boot 栈 = guard + 4 映射帧，栈顶 `0xffffffff81005000`（写错会 #DF）；Process 用户内核栈 = 8 帧 32 KiB（`KERNEL_STACK_FRAMES=8`、`Process`=2144），坏帧会先踩 8 B canary/trap 区；AP 上 parented spawn 的初始 placement 必须随创建 CPU。
- M9c 新增约束：`MAX_PROCESSES = MAX_SPACES = 4`；第 4 个内核栈基址 `0xFFFF_FFFF_8120_0000`（812 槽 + 812 guard，复用既有页表）；`MAX_CHILDREN = 2`（同 ELF 双 role 锁对端）。
- M9d1/M9d2/M9e 已完成并验收：`[CaelumDyn] interp OK`、`[CaelumLinux] M9d dynamic OK`、`[CaelumLinux] M9d vdso OK` 与 `[CaelumLinux] M9e shared OK` 位于 `[CaelumLinux] M9c locks OK` 之后、`[CaelumKernel] M7d OK (sockets=0, bindings=0)` 之前，每启动 **136** 个标记；M9e 与 M9f 交付真实 ET_DYN 共享库的最小单依赖与链式三库闭包（`/fat/m9e.so`，`e_entry=0` 用 `validate_for_shared_object`，库内 RELATIVE 与主程序 GLOB_DAT 由解释器应用）；完整 M9 未关闭（完整共享库 PLT/GOT 重定位、glibc/musl 与 Linux 工具运行等切片未完成）。

### 13.2 M5、M6、M7a/M7b/M7d、M8a～M8h、M9a～M9c 与 M9d1/M9d2、M9e 与 M9f 已实现并验收

M5（M5a VFS/页缓存/ramfs 与启动模块迁移、M5b PCI/virtio-blk/FAT32/ext2 持久化、M5c 用户文件/目录语义、mmap、同步、锁、xattr、稀疏文件、目录通知与故障注入）与 M6（M6a1 Event/EventPair/Timer、M6a2 Channel/Port/SharedMemory/EventSubscription/Futex、M6b1 SMP AP bring-up、M6b2 每 CPU 运行队列/负载均衡/受控迁移/定时抢占/跨 CPU 唤醒与 IPI、M6c GOP 显示探测与 gfx 用户呈现/输入）均已完成并在真实 QEMU/OVMF 中验收；M7a（内核 loopback IPv4/IPv6 UDP/TCP）、M7b（原生 Socket/LocalSocket）、M7d（Linux64 socket 人格核心与 6 模块启动链）已完成并验收；M7c（真实 virtio-net 链路）未实施，完整 M7 未关闭。M8 已落地的切片：

- M8a（Linux64 内存与文件语义）：mmap/mprotect/munmap、保护位切换与读回、文件读取路径；打印 `[CaelumLinux] M8a memory OK` 与 `M8a files OK`。
- M8b（时间与系统信息）：`clock_gettime`/`clock_nanosleep`/`getppid`/`uname`；打印 `[CaelumLinux] M8b time OK` 与 `M8b info OK`。
- M8c（信号基础）：单线程/单进程 `rt_sigaction`/`rt_sigprocmask`、`kill`/`tgkill` self、SA_RESTORER 用户帧与 `rt_sigreturn`；打印 `[CaelumLinux] M8c signals OK`；跨进程/跨线程投递与完整 siginfo 未实现。
- M8d（parent/child 双进程处理闭环）：同一 `linux` 映像的 parent/child 双进程、`kill(-1)`/`tgkill` 双向信号握手、`wait4` 阻塞回收与 `WIFSIGNALED`/`WTERMSIG` 校验、`ECHILD` 与内核进程数基线校验；打印 `[CaelumLinux] M8d process OK`。
- M8e（扩展文件语义）：`lseek` SEEK_SET/CUR/END 与负路径、`dup` 共享打开文件描述偏移、`fstat`/`statx`、`getdents64` 分片目录枚举、`fcntl` FD_CLOEXEC/F_DUPFD/F_DUPFD_CLOEXEC 与未知请求负路径；打印 `[CaelumLinux] M8e files OK`。
- M8f（futex 与 TLS）：futex 值匹配/不匹配、零与短相对超时、无等待者 wake、PRIVATE 变体；TLS 经 `arch_prctl(ARCH_GET_FS/ARCH_SET_FS)` 安装/读回匿名页、FS 区与普通内存互见、恢复旧基；`set_tid_address` 返回 tid、`clear_child_tid` 哨兵与重复注册幂等；打印 `[CaelumLinux] M8f futex OK` 与 `M8f tls OK`。
- M8g（eventfd 与 poll/ppoll）：eventfd2 计数与读写/非阻塞负路径；poll/ppoll 就绪、超时、临时 sigmask（仅调用期间生效）、信号中断返回 `-EINTR` 且内核不重放等待；打印 `[CaelumLinux] M8g eventfd OK` 与 `M8g poll OK`。内核同时把 Process 用户内核栈由 4 帧扩到 8 帧（32 KiB，`Process`=2144）：M8g 首启 #DF 的根因是深层 TCP 回环投递把最坏路径推到 16304 B 超过 16 KiB 栈并踩 guard，栈扩容后消除。
- M8h（procfs/devfs 视图）：`kernel/src/vfs/pseudo.rs` 以真实 `Backing::Generated` 文件与 `CharDevice` 节点安装 `/proc`、`/proc/self`、`/proc/self/status`、`/proc/uptime`、`/dev/null`、`/dev/zero`；`/proc/self/status` 每次 read 按当前 owner 现场渲染 `Name: linux`/`State`（running/sleeping/zombie）/`Pid`/`PPid`/`Uid`/`Gid`/`Threads: 1`（size 0、不进页缓存），`/proc/uptime` 由单调时钟输出“秒.百分秒”两字段（uptime 与 idle 相同），`/dev/null`(1,3) 读 EOF/写丢弃、`/dev/zero`(1,5) 无限零字节/写丢弃；`/proc` 目录经 `getdents64` 可列出 `self`/`uptime`；打印 `[CaelumLinux] M8h procfs OK` 与 `M8h devfs OK`（仅 parent 各一次、无 payload）。
- M9a（Linux 用户态扩展第一切片）：timerfd（到期 read 返回 8 字节计数，超时/取消负路径）、signalfd（待处理信号转 fd 可读、sigmask 过滤）、epoll 基础 level-triggered 语义（`epoll_create1`/`epoll_ctl`/`epoll_wait`、EPOLLIN/EPOLLOUT 就绪报告、零与正超时）；打印 `[CaelumLinux] M9a timerfd OK`/`M9a signalfd OK`/`M9a epoll OK`；AF_UNIX abstract 命名空间、`SCM_RIGHTS`/`SCM_CREDENTIALS` fd 传递与 epoll 边沿触发属 M9b（M9b 已完成并验收）。
- M9b（Linux 用户态扩展第二切片）：AF_UNIX abstract 命名空间（NUL 开头 abstract 地址与路径名地址并存）、`SCM_RIGHTS` fd 传递（fd → 内核对象引用 → 接收方新 fd）、`SCM_CREDENTIALS` 校验、epoll `EPOLLET` 边沿触发与 drain；打印 `[CaelumLinux] M9b abstract OK`/`M9b rights OK`/`M9b credentials OK`/`M9b epoll-et OK`；完整文件锁/fcntl 由 M9c 交付（已完成并验收）。
- M9c（Linux 用户态扩展第三切片）：同一 `linux` ELF 的 role2 锁对端；VFS 三类锁域——POSIX `fcntl` 按线程组、OFD 锁按打开文件描述、`flock` 独立域，含冲突/关闭释放/继承负路径；修复 M8g 遗留 SIGUSR1 blocked mask 与 peer EXIT ack/收割顺序；`MAX_PROCESSES = MAX_SPACES = 4`、第 4 个内核栈基址 `0xFFFF_FFFF_8120_0000`、`MAX_CHILDREN = 2`；打印 `[CaelumLinux] M9c locks OK`。
- M9d1（Linux64 动态 ELF/PT_INTERP）：ET_DYN 主程序（`services/linux-dyn`，`/fat/dyn-main`，含 `PT_INTERP=/fat/ldcaelum.so`、4 条 RELATIVE、无 DT_NEEDED）由自研 ET_EXEC 解释器 `ldcaelum`（`services/linux-interp`，`/fat/ldcaelum.so`）加载；内核在 `m7d_closeout` 经 VFS 读取两条路径并注入 auxv `AT_PHDR`/`AT_ENTRY`；打印 `[CaelumDyn] interp OK` 与 `[CaelumLinux] M9d dynamic OK`（仅 parent 各一次，无 payload）。
- M9d2（真实 ET_EXEC vDSO）：`services/linux-vdso` 产出 8808 B ET_EXEC（entry `0x7001000`）+ 全局只读数据页（magic/version/seq/hz/ticks，序号校验保证一致快照），内核映射并以 `AT_SYSINFO_EHDR` 暴露；用户按 ELF `e_entry` 直接调用、无需符号表解析，CLOCK_MONOTONIC/BOOTTIME 由 hz/ticks 计算，CLOCK_REALTIME 明确返回 `-ENOSYS`；打印 `[CaelumLinux] M9d vdso OK`（仅 parent 一次，无 payload）。
- M9e（真实 ET_DYN 共享库）：`services/linux-m9e-lib`（`caelum-m9e-lib`）产出 2392 B ET_DYN（无进程入口、`e_entry=0`），`caelum-linux-dyn` 仅以 `DT_NEEDED=/fat/m9e.so` 依赖它；内核在 `m7d_closeout` 经 VFS 读取 `/fat/m9e.so`、以 `validate_for_shared_object` 校验（ET_DYN 且不要求 e_entry 落在可执行段）后映射到冻结 bias，打印 `[CaelumLinux] M9e shared OK`（仅 parent 一次，无 payload）。
- M9f（真实链式三库闭包）：`services/linux-m9f-a`（2336 B ET_DYN，SONAME `/fat/m9f-a.so`，`DT_NEEDED=/fat/m9f-b.so`）与 `services/linux-m9f-b`（1800 B ET_DYN，SONAME `/fat/m9f-b.so`，无依赖）由 `caelum-linux-dyn` 以 `DT_NEEDED=/fat/m9e.so`→`/fat/m9f-a.so` 依赖；内核把三库映射进同一地址空间（冻结 bias），自研解释器按 m9e→A→B 顺序解析 SONAME（`bias + DT_STRTAB + soname`）并用 GLOB_DAT 解析 A→B 调用与库内自身 counter，无 PLT 懒绑定；打印 `[CaelumLinux] M9f shared OK`（parent 一次，无 payload）。

未改动：`docs/abi/boot-protocol.md` 保持 v1.1；`docs/abi/native-syscall.md` 在 M6c 期间升到 0.5、M7b 升到 0.6；M7d/M8a～M8h/M9a～M9e 均属 Linux64 人格，不新增原生 ABI。M9d 的验收修正：M9d2 首启 `[CaelumLinux] FAIL m9d vdso-realtime`（vDSO 入口用 `mov eax,-38`，32 位写零扩展导致返回值不是 -38）→ 改 `mov rax,-38` 后两启动通过；隔离点仍是用户镜像汇编，xtask 与内核映射契约无放宽。M9f 的验收修正：自研解释器最初用 `bias + DT_SONAME` 校验三库 SONAME，漏了 `DT_STRTAB` 间接层，首启失败于 `[CaelumDyn] FAIL m9e-soname`；改为 `bias + DT_STRTAB + soname` 后两启动通过（校验未放宽，内核/xtask 契约不变）。M9e 的验收修正：共享库没有进程入口（`e_entry=0`），不能套用主程序“入口必须落在可执行 PT_LOAD 内”的校验；`libs/elf64` 新增 `validate_for_shared_object(bias)`（与 `validate_for_user_dynamic` 共用段/地址上限/权限/偏移同余/重叠规则，仅关闭入口段要求），内核装载路径改用它，否则 `/fat/m9e.so` 会被误判为坏 ELF。

注意：以上全部是 **QEMU/OVMF 软件环境验证**；真实 UEFI 硬件验证属于 M11，不能据此宣称硬件可用。

### 13.3 下一个 Agent 的第一优先级

1. 保持 M1～M6、M7a/M7b/M7d、M8a～M8h 与 M9a～M9c、M9d1/M9d2/M9e 回归：两启动各 **136 标记**不得减少，`M2 #PF caught` 必须最后。
2. 第一优先级是 **M9 其余切片（完整共享库 PLT/GOT 重定位与 Linux 工具运行、glibc/musl 工作负载、Linux 设备视图；M9e/M9f 只交付最小单依赖与链式三库闭包）** 与 **M8 其余切片**（fork/clone 完整共享矩阵、线程组、完整 siginfo、任意进程/线程组信号等）；每片新增验收契约由主代理冻结后实现；完整 M8 与完整 M9 通过前不得宣称完成。
3. M7c（真实网络链路）仍未实施：完整 M7 通过前不得宣称完成；M7a/M7b/M7d 的 loopback/本地 Socket 验收不能替代它。
4. 保持回归纪律：每个子任务都必须提供可重复构建、可观察日志、失败现象和已知限制；不得把“已规划/实现中”写成“已验收”。
5. 工程基线（可选）：Git 仓库仍未初始化，是否建立由项目所有者明确决定；M9f 验收后三文档已收口。

---
## 14. 给下一个 Agent 的接手 Prompt（M9 其余切片 / M8 其余切片 / M7c 交接）
```text
你是接手青穹 OS / CaelumOS 的下一个 Agent。当前项目已关闭 M0，完成并验收 M1～M6（完整 M5/M6 均已关闭），
M7 完成 M7a/M7b/M7d，M8 完成 M8a～M8h，M9 完成 M9a/M9b/M9c、M9d1/M9d2、M9e 与 M9f（动态 ELF/PT_INTERP、真实 vDSO、真实 ET_DYN 单依赖与链式三库闭包最小闭环，每启动 136 个标记）；M7c（真实 virtio-net 链路）未实施、完整 M7 未关闭；
M8 其余切片与 M9 其余切片（完整共享库/重定位、glibc/musl 工作负载、Linux 工具运行与设备视图等）未完成；完整 M8/M9 未关闭。
当前第一优先级：M9 其余切片（完整共享库/重定位与 Linux 工具运行）与 M8 其余切片的设计与验收契约冻结（由主代理确认新增标记、位置与载荷后）再实现；不得在契约冻结前自行实现或宣称完成。
- 目标：在 Linux64 人格上继续推进剩余切片（完整共享库/重定位与 Linux 工具运行、M8 其余切片），用真实 syscall/加载路径与错误路径证明，而不是只返回成功；
  新增用户可见标记需由主代理冻结后再实现，不得自行宣称完成。
- 边界：M8h 只交付 procfs/devfs 的最小视图；M8c 只有单线程/单进程自信号（M8d 补受控 parent/child 双进程）；任意进程/线程组投递、信号排队与完整 siginfo、fork/clone 完整共享矩阵、线程组仍未实现；
  M9a/M9b/M9c 只交付 timerfd/signalfd/epoll level-triggered、abstract 命名空间/SCM/EPOLLET、文件锁三锁域的最小契约；
  M9d1/M9d2/M9e/M9f 只交付“动态 ELF/PT_INTERP 最小闭环 + 真实 ET_EXEC vDSO（CLOCK_REALTIME 返回 -ENOSYS）+ 真实 ET_DYN 共享库的最小单依赖与链式三库闭包（`/fat/m9e.so`、`/fat/m9f-a.so`、`/fat/m9f-b.so`）”，不含 PLT/GOT 延迟绑定/符号解析、glibc/musl 重定位与工具运行；完整 M9 仍未关闭；
  M7c 未实施，M7a/M7b/M7d 的 loopback 与本地 Socket 验收不能替代真实 NIC 链路。
必读：
1. E:/Ai files/os001/agents.md（第 22 节 M8/M9/M7 行、最新状态行）
2. E:/Ai files/os001/PROJECT_PROGRESS.md（§1、§5、§8、§10 第 90～117 条、§13、本 Prompt）
3. E:/Ai files/os001/tests/qemu/README.md（每启动 136 个标记、两阶段流程、注入/截图/载荷/动态 ELF/三库契约）
4. E:/Ai files/os001/docs/abi/native-syscall.md（原生 ABI 0.6）与 boot-protocol.md（v1.1）
M9f 验收后基线（必须保持）：
- 两启动各 **136** 个集成标记，`[CaelumKernel] M2 #PF caught` 必须最后；
  尾段顺序为 `… [CaelumLinux] M9c locks OK → [CaelumDyn] interp OK → [CaelumLinux] M9d dynamic OK → [CaelumLinux] M9d vdso OK → [CaelumLinux] M9e shared OK → [CaelumLinux] M9f shared OK → [CaelumKernel] M7d OK (sockets=0, bindings=0) → #PF`。
- 宿主单测 1223 = bootinfo 24 + elf64 35 + xtask 103 + kernel lib 1061；两启动日志 8828/8812 B（10:17:35/10:17:41）。
- 版本：loader 0.2.0、kernel 0.16.0、Boot Protocol 1.1、原生 ABI 0.6；六模块 initramfs 5864624 B、ESP 33 MiB（kernel 10233800）；六个 release 注入产物 dyn 13312 B / interp 19256 B / vdso 8808 B / m9e-lib 2392 B / m9f-a 2336 B / m9f-b 1800 B。
- 工程约束：内核 boot 栈 = guard + 4 映射帧（栈顶 `0xffffffff81005000`，写错会 #DF）；Process 用户内核栈 = 8 帧 32 KiB（`KERNEL_STACK_FRAMES=8`，`Process`=2144）；AP 上 parented spawn 的初始 placement 必须随创建 CPU；`MAX_PROCESSES = MAX_SPACES = 4`、第 4 个内核栈基址 `0xFFFF_FFFF_8120_0000`、`MAX_CHILDREN = 2`；动态 ELF/vDSO/共享库六文件路径（`/fat/dyn-main`、`/fat/ldcaelum.so`、`/fat/vdso.so`、`/fat/m9e.so`、`/fat/m9f-a.so`、`/fat/m9f-b.so`）与 FAT 注入/逐字节复核契约不得放宽；共享库无进程入口（`e_entry=0`），加载校验必须用 `validate_for_shared_object`。
硬约束：
- 不改 Boot Protocol 1.1、不改原生 ABI 0.6，除非有明确证据并先记录理由与 ADR。
- xtask 的标记契约、位置规则、payload 阈值、host 两阶段磁盘复核与动态 ELF/vDSO 逐字节复核不得降级或删除；新增标记由主代理冻结后再实现。
- 不得把“已规划/设计中”写成“已验收”；未通过两启动 QEMU/OVMF 不得宣称任何切片完成。
- QEMU 验收由主代理串行执行（避免并发 QEMU）；日志写入 target/serial-boot1.log、target/serial-boot2.log。
验收要求（每个切片）：
1. `cargo fmt --all -- --check` 通过；
2. `cargo xtask check` 通过（含 bootinfo/elf64/xtask/kernel lib 单测）；
3. `cargo xtask image` 通过（六模块 initramfs、ESP 与四个 release 注入产物；若新增模块需同步 loader/xtask）；
4. `cargo xtask test` 两启动各 136 个集成标记，`#PF` 最后；
5. 完成后按“该切片完成”口径收口三文档（PROJECT_PROGRESS.md、tests/qemu/README.md、agents.md），历史计数保留时点。
完成后把结论、证据（文件:行号、命令输出）和风险写清；M9 其余切片与 M8 其余切片按契约推进，M7c 仍按项目所有者授权另行安排。
```
