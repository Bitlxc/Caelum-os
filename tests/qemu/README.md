# CaelumOS M9f — QEMU/OVMF 集成验收说明

> 本文件说明**当前**阶段的验收口径：M1～M6、M7a/M7b/M7d、M8a～M8h、M9a/M9b/M9c 与
> M9d1/M9d2/M9e/M9f（Linux 用户态扩展第四/第五/第六/第七切片：动态 ELF/`PT_INTERP` 最小闭环、真实
> ET_EXEC vDSO、真实 ET_DYN 单依赖共享库与链式三库共享库闭包）已完成并在真实 QEMU/OVMF 中通过两启动验收（每启动
> **136** 个集成标记）；**M7c（真实 virtio-net 链路）尚未实施，完整 M7 未关闭；M8 其余切片与
> M9 其余切片（完整共享库 PLT/GOT 重定位与 Linux 工具运行、glibc/musl 工作负载、Linux 设备
> 视图等）未完成，完整 M8 与完整 M9 未完成。**
>
> **M9d1 已验收**：`caelum-linux-dyn`（ET_DYN 主程序，`PT_INTERP=/fat/ldcaelum.so`）由自研
> ET_EXEC 解释器 `ldcaelum`（`caelum-interp`，基址 0x40000000）加载；内核在 `M7d` closeout 经
> VFS 读取 `/fat/dyn-main` 与 `/fat/ldcaelum.so` 并注入 `AT_PHDR`/`AT_ENTRY`；用户打印
> `[CaelumDyn] interp OK` 与 `[CaelumLinux] M9d dynamic OK`。
>
> **M9d2 已验收**：`caelum-vdso` 为真实 ET_EXEC（entry `0x7001000`）+ 全局只读数据页
> （magic/version/seq/hz/ticks），内核映射并以 `AT_SYSINFO_EHDR` 暴露，用户按 ELF `e_entry`
> 直接调用；CLOCK_MONOTONIC/BOOTTIME 由 hz/ticks 计算，CLOCK_REALTIME 明确返回 `-ENOSYS`；
> 用户打印 `[CaelumLinux] M9d vdso OK`。
>
> **M9e 已验收**：`caelum-m9e-lib` 为真实 ET_DYN 共享库（2392 B，无进程入口、`e_entry=0`），
> `caelum-linux-dyn` 仅以 `DT_NEEDED=/fat/m9e.so` 依赖它；内核经 VFS 读取 `/fat/m9e.so`、以
> `validate_for_shared_object` 校验（要求 ET_DYN，但不要求入口落在可执行段）后映射到冻结
> bias，库内 RELATIVE 与主程序 GLOB_DAT 由自研解释器应用；用户打印
> `[CaelumLinux] M9e shared OK`。
>
> **M9f 已验收**：`caelum-m9f-a`（2336 B ET_DYN，SONAME `/fat/m9f-a.so`，`DT_NEEDED=/fat/m9f-b.so`）与
> `caelum-m9f-b`（1800 B ET_DYN，SONAME `/fat/m9f-b.so`，无依赖）构成链式三库闭包；`caelum-linux-dyn` 的
> `DT_NEEDED` 固定为 `/fat/m9e.so`→`/fat/m9f-a.so`。内核在 `m7d_closeout` 经 VFS 读取、`validate_for_shared_object`
> 校验后把三库映射进同一地址空间（冻结 bias `0x0300_0000`/`0x0380_0000`/`0x0400_0000`），自研解释器按
> m9e→A→B 顺序解析 SONAME（`bias + DT_STRTAB + soname`），并用 GLOB_DAT 解析 A→B 函数调用与库内
> 自身 counter，无 PLT 懒绑定/`JUMP_SLOT`；用户打印 `[CaelumLinux] M9f shared OK`。
>
> `tests/qemu/run-qemu.ps1` 与 `run-qemu.sh` 现在只是薄壳：真正逻辑、标记清单、QEMU 参数、
> 超时、截图与注入都在 `xtask/` 内维护；改验收契约只改 `xtask/src/main.rs`，不要让脚本与
> xtask 出现两份清单。

## 这一阶段验证什么

- M8a：Linux64 人格的内存与文件语义——`mmap`/`mprotect`/`munmap` 共享与私有映射、
  保护位切换与读回、文件读取路径；用户程序打印 `[CaelumLinux] M8a memory OK` 与
  `[CaelumLinux] M8a files OK`。
- M8b：时间与系统信息——`clock_gettime`（monotonic/realtime）、`clock_nanosleep`、
  `getppid`、`uname`；打印 `[CaelumLinux] M8b time OK` 与 `[CaelumLinux] M8b info OK`。
- M8c：单线程/单进程自信号——`rt_sigaction`/`rt_sigprocmask`、`kill`/`tgkill` self、
  SA_RESTORER 用户帧与 `rt_sigreturn`；打印 `[CaelumLinux] M8c signals OK`。
  **能力边界：本切片只覆盖单线程/单进程自信号；跨进程投递由 M8d 的受控闭环补充，但任意
  进程/线程组投递、信号排队与完整 siginfo 仍未实现，不得写成已完成。**
- M8d：parent/child 双进程处理闭环——同一 `linux` 映像的 parent（detached 测试根）与
  child（内核创建、同 CPU 驻留）通过 `kill(-1)`/`tgkill` 完成双向信号握手；child 恢复
  `SIG_DFL` 后被 `SIGUSR1` 默认动作终止，parent 用阻塞 `wait4` 回收并校验
  `WIFSIGNALED`/`WTERMSIG`，随后 `wait4(WNOHANG)` 返回 `ECHILD`；内核按进入时进程数基线
  校验子进程已被回收。仅 parent 打印一次 `[CaelumLinux] M8d process OK`。
  **能力边界：只覆盖受控 parent/child 双进程闭环与 `kill/tgkill/wait4`，不是任意进程/
  线程组或完整信号语义。**
- M8e：Linux64 扩展文件语义——`lseek` 的 SEEK_SET/CUR/END 与负路径、`dup` 共享打开文件
  描述偏移、`fstat`/`statx` 一致性、`getdents64` 分片目录枚举、`fcntl` 的 FD_CLOEXEC/
  F_DUPFD/F_DUPFD_CLOEXEC 与未知请求负路径；打印 `[CaelumLinux] M8e files OK`。
- M8f：futex 基础契约与 TLS——futex 值匹配/不匹配、零与短相对超时、无等待者 wake 与
  PRIVATE 变体；TLS 经 `arch_prctl(ARCH_GET_FS/ARCH_SET_FS)` 安装/读回匿名页、FS 区与
  普通内存互见、恢复旧基；`set_tid_address` 返回 tid、`clear_child_tid` 哨兵与重复注册
  幂等；分别打印 `[CaelumLinux] M8f futex OK` 与 `M8f tls OK`。
- M8g：eventfd 与 I/O 多路复用——eventfd 计数器读写与阻塞唤醒、`poll`/`ppoll` 就绪与超时、临时 sigmask 与信号中断返回 `EINTR`、同一 fd 的重复就绪；分别打印 `[CaelumLinux] M8g eventfd OK` 与 `M8g poll OK`。**能力边界：本切片只覆盖 eventfd 与 poll/ppoll 的基础语义；epoll、signalfd、timerfd 与完整多对象语义仍未实现。** 该切片同时把内核 Process 用户内核栈由 4 帧扩到 8 帧（32 KiB，`Process`=2144），修掉深层 TCP 回环投递踩 guard 的 #DF。
- M8h：procfs/devfs 视图——`kernel/src/vfs/pseudo.rs` 以真实 `Backing::Generated` 文件与 `CharDevice` 节点安装 `/proc`、`/proc/self`、`/proc/self/status`、`/proc/uptime`、`/dev/null`、`/dev/zero`；`/proc/self/status` 每次读取按当前 owner 现场渲染 `Name: linux`/`State`/`Pid`/`PPid`/`Uid`/`Gid`/`Threads: 1`（size 0、不进页缓存），`/proc/uptime` 按单调时钟输出“秒.百分秒”两字段（uptime 与 idle 相同），`/dev/null`(1,3) 读 EOF/写丢弃、`/dev/zero`(1,5) 无限零字节/写丢弃，`/proc` 目录可经 `getdents64` 列出子项；打印 `[CaelumLinux] M8h procfs OK` 与 `M8h devfs OK`（仅 parent 各一次）。**能力边界：这是最小只读视图，不含 cgroup/sysfs、可写 proc 接口或完整 Linux /proc 语义。**
- M9a：Linux 用户态扩展第一切片——timerfd 到期 `read` 返回 8 字节计数（含超时/取消负路径）、signalfd 把待处理信号转为 fd 可读（受 sigmask 过滤）、epoll 基础 level-triggered 语义（`epoll_create1`/`epoll_ctl`/`epoll_wait`、EPOLLIN/EPOLLOUT 就绪报告、零/正超时）；打印 `[CaelumLinux] M9a timerfd OK`、`M9a signalfd OK`、`M9a epoll OK`（仅 parent 各一次）。**能力边界：本切片只交付 timerfd/signalfd/epoll 的 level-triggered 基础语义；AF_UNIX abstract 命名空间、`SCM_RIGHTS`/`SCM_CREDENTIALS` fd 传递与 epoll 边沿触发属 M9b，完整 M9 未关闭。**
- M9b：Linux 用户态扩展第二切片——AF_UNIX abstract 命名空间地址（绑定/连接不写入文件系统路径）、`SCM_RIGHTS` 把 fd 转为内核对象引用并在接收方生成新 fd、`SCM_CREDENTIALS` 经凭据与命名空间规则校验、epoll `EPOLLET` 边沿触发（边沿只报告一次、drain 后复位）；打印 `[CaelumLinux] M9b abstract OK`、`M9b rights OK`、`M9b credentials OK`、`M9b epoll-et OK`（仅 parent 各一次，无 payload）；不包含完整 abstract 命名空间生命周期、完整 SCM 组合/配额与完整 ET 语义。
- M9c：Linux 用户态扩展第三切片——同一 `linux` ELF 的 role2 锁对端（父进程与 role2 子进程互测冲突/释放）；VFS 三类锁域：POSIX `fcntl` 锁按线程组持有（关闭任一引用同一文件的 fd 即释放该线程组全部 POSIX 锁）、OFD 锁按打开文件描述（`dup` 不冲突）、`flock` 独立锁域；进入锁测试前清空 M8g 遗留的 SIGUSR1 blocked mask 并恢复 disposition，role2 的 EXIT 分支在退出前发送 ack，父进程按命令顺序收割；打印 `[CaelumLinux] M9c locks OK`（仅 parent 打印一次，无 payload）；`MAX_PROCESSES = MAX_SPACES = 4`、第 4 个内核栈基址 `0xFFFF_FFFF_8120_0000`、`MAX_CHILDREN = 2`。**能力边界：只覆盖同 ELF role2 锁对端与 VFS 三类锁域的冲突/释放/继承最小契约；全 fcntl 命令集、锁等待/死锁边界与跨命名空间场景未覆盖，完整 M9 未关闭。**
- M1～M6、M7a/M7b/M7d、M8a～M8h、M9a、M9b、M9c、M9d1/M9d2、M9e 与 M9f 作为回归保留：磁盘两阶段复核、M6b2 调度统计阈值、
  M6c 截图像素与 payload、M7a/M7b/M7d 载荷校验、六份 release ELF（dyn/interp/vdso/m9e/m9f-a/m9f-b）的 FAT 注入与逐字节复核都必须继续通过。

## 前置条件

- Windows 10/11 + PowerShell 5.1 或 Git Bash；QEMU 在 `PATH` 中（或 `CAELUM_QEMU` 指定）。
- OVMF：优先使用仓库内 `tools/ovmf/OVMF_CODE.fd`；`CAELUM_OVMF` 环境变量优先。
- 首次运行或镜像过期时 `xtask` 会自动重新构建：loader（UEFI）、kernel、六个用户程序
  （init/child/worker/gfx/net/linux）与六模块 initramfs，然后重新生成 ESP；同时以 release 构建
  六个注入产物（`caelum-linux-dyn`、`caelum-interp`、`caelum-vdso`、`caelum-m9e-lib`、`caelum-m9f-a`、`caelum-m9f-b`）；磁盘镜像每次验收都会重新
  格式化（`target/m5b-fat32.img` 64 MiB、`target/m5b-ext2.img` 32 MiB），并把六份 ELF 逐字节
  写入 FAT 根（`dyn-main`、`ldcaelum.so`、`vdso.so`、`m9e.so`、`m9f-a.so`、`m9f-b.so`）。

## 一键验收

```powershell
cargo xtask check     # 格式 + 宿主单测（含 xtask 自身 107 项）
cargo xtask test      # check + image + 两启动 QEMU/OVMF 全流程
# 或镜像已就绪时只跑验收：
cargo xtask qemu
```

`cargo xtask test` 退出码 0 表示两启动都拿到了全部 **136 个必需标记**、顺序契约成立、
宿主两阶段磁盘复核与像素/载荷校验全部通过。日志：

- `target/serial-boot1.log`：第一启动完整串口日志；
- `target/serial-boot2.log`：第二启动完整串口日志；
- `target/serial.log`：第二启动日志的副本（兼容旧习惯）；
- `target/m6c-screen-boot1.ppm`、`target/m6c-screen-boot2.ppm`：两次启动的 QMP 截图。

## 自动注入、截图与载荷校验

本轮 M9f（与 M8a～M9e 一样）是用户态自检，**不需要额外注入**；动态 ELF、vDSO 与三个共享库由验收框架
在格式化 FAT 盘时逐字节注入，并在两次启动后由 host 用共享 fat32 库逐字节复核：

- M3 输入注入：看到 `[CaelumKernel] M3 input ready` 后，用 QMP `send-key` 注入 PS/2 `a`，
  并向串口写字节 `C`（0x43）；内核必须随后打印 `M3 input OK` / `M3 serial OK`。
- M6c 显示与输入：看到 `[CaelumGfx] M6c display OK` 后 delay 300 ms，用同一 QMP 连接执行
  `screendump`，解析 P6 PPM 并校验三个真实像素：物理 framebuffer 右下角 magenta
  （255,0,255）、`(48,48)` 绿（0,255,0）、`(128,48)` 蓝（0,0,255），每通道容差 ±8。
  看到 `[CaelumGfx] M6c input ready` 后做**第二次注入**：QMP `send-key` qcode `d`
  （hold-time 100 ms），sleep 150 ms（`M6C_KEY_SETTLE`，必须大于 `KEY_HOLD_MS=100`），
  再向串口写 `m6c` 三个字节；必须等到 `M6c input OK`。
- payload 强制：`M6b2` 五条统计行必须带 `(k=v, ...)` 且满足阈值
  （runs>=2、cpus>=1、preempts>=2、remote_wakes>=1、ipis>=1、migrations>=1、balances>=1）；
  `M6c input OK`/`M6c OK` 必须精确 `events=5, dropped=0`；M7a/M7b/M7d 的字节数、pairs、
  verdict `sockets=0, bindings=0` 等都必须精确匹配。**只包含标记文本、字段缺失或数值不对，
  一律判失败，不会假绿。**
- M8a～M8h、M9a、M9b、M9c、M9d2、M9e 与 M9f 是纯文本标记（无 payload），与 M7d 用户标记一样按前缀精确匹配；M9d1 的 `[CaelumDyn] interp OK` 现在带 `(needed=…, libs=…, globdat=…, relative=…)` 计数 payload，harness 仍按前缀匹配且不校验该 payload；
  M8d/M8e/M8f/M8g/M8h/M9a/M9b/M9c 与 M9d/M9e/M9f 都只允许 parent 各打印一次，child 不得打印。

## 两阶段（两次启动）流程

1. 格式化两块空盘：FAT32（`target/m5b-fat32.img`，64 MiB，drive index 0）与 ext2
   （`target/m5b-ext2.img`，32 MiB，drive index 1），二者都以 legacy `virtio-blk-pci` 暴露
   （`disable-modern=on,disable-legacy=off,queue-size=128`）。
2. 启动 1：空盘启动，guest 自己写 13 字节 state、8192 字节 pattern、M5c 用户文件、mmap
   文件、稀疏文件与故障注入回读文件；xtask 检查 136 个标记后用 QMP `screendump` 截图，
   再用共享 FAT32/ext2 库做 host 首启复核。
3. 启动 2：重启后 guest 读回并追加/改名/截断数据、重做 M6c、M7、M8 与 M9 系列自检，xtask 检查
   136 个标记并再次截图，host 二启复核。
4. 任一启动失败都会立即终止，不会继续下一次启动；`M6b2 FAIL`/`M6c FAIL`/`M8… FAIL`/
   `[CaelumLinux] FAIL`/`PANIC`/`unexpected #PF` 等都会触发快速失败并打印串口尾部。

## 薄壳脚本

```powershell
tests\qemu\run-qemu.ps1 [-Ovmf C:\path\OVMF_CODE.fd] [-Timeout 600]
```

```bash
tests/qemu/run-qemu.sh   # CAELUM_OVMF / CAELUM_QEMU_TIMEOUT 环境变量；兼容 --timeout
```

脚本只负责设置环境变量并调用 `cargo xtask qemu`；失败退出码 1，缺少 QEMU/OVMF 时打印手工
命令并以 0 退出。`-Image`/`-Log` 等旧参数会给出忽略提示。

## 等价手工命令（不能完成注入/截图，仅供观察）

```powershell
cargo xtask image
qemu-system-x86_64 -machine q35 -smp 4 -m 256M `
  -drive if=pflash,format=raw,readonly=on,file=tools/ovmf/OVMF_CODE.fd `
  -drive file=target/caelum-esp.img,format=raw,if=ide `
  -drive if=none,id=disk0,format=raw,file=target/m5b-fat32.img `
  -device virtio-blk-pci,drive=disk0,disable-modern=on,disable-legacy=off,queue-size=128 `
  -drive if=none,id=disk1,format=raw,file=target/m5b-ext2.img `
  -device virtio-blk-pci,drive=disk1,disable-modern=on,disable-legacy=off,queue-size=128 `
  -serial file:target/serial-manual.log -display none -no-reboot -no-shutdown
```

手工命令不会自动注入键盘/串口、不会 screendump、不会做 host 磁盘复核；要完整验收请用
`cargo xtask test`。

## 预期串口输出（节选，M9 段）

```text
[CaelumKernel] M6c OK (events=5, dropped=0) [t=... ms]
[CaelumKernel] M7a ipv4 udp OK (bytes=7)
...
[CaelumKernel] M7a OK (suites=4)
[CaelumNet] M7b udp4 OK (bytes=7)
...
[CaelumNet] M7b OK (child=0)
[CaelumKernel] M7b OK (sockets=0, bindings=0)
[CaelumLinux] M7d startup OK
...
[CaelumLinux] M7d OK
[CaelumLinux] M8a memory OK
[CaelumLinux] M8a files OK
[CaelumLinux] M8b time OK
[CaelumLinux] M8b info OK
[CaelumLinux] M8c signals OK
[CaelumLinux] M8d process OK
[CaelumLinux] M8e files OK
[CaelumLinux] M8f futex OK
[CaelumLinux] M8f tls OK
[CaelumLinux] M8g eventfd OK
[CaelumLinux] M8g poll OK
[CaelumLinux] M8h procfs OK
[CaelumLinux] M8h devfs OK
[CaelumLinux] M9a timerfd OK
[CaelumLinux] M9a signalfd OK
[CaelumLinux] M9a epoll OK
[CaelumLinux] M9b abstract OK
[CaelumLinux] M9b rights OK
[CaelumLinux] M9b credentials OK
[CaelumLinux] M9b epoll-et OK
[CaelumLinux] M9c locks OK
[CaelumDyn] interp OK (needed=2,libs=3,globdat=7,relative=5)
[CaelumLinux] M9d dynamic OK
[CaelumLinux] M9d vdso OK
[CaelumLinux] M9e shared OK
[CaelumLinux] M9f shared OK
[CaelumKernel] M7d OK (sockets=0, bindings=0)
[CaelumKernel] M2 #PF caught (deliberate unmapped read) [t=... ms]
[CaelumKernel] halting
```

内核版本行为 `caelum-kernel v0.16.0`；loader 行为 `CaelumOS M1 loader v0.2.0 (boot
protocol 1.1, entry_abi 1)`。启动最初两行可能是 UEFI BdsDxe 的 `failed to load ...` 固件
提示，与本项目无关。

## 必需标记：每次启动 136 个

| 阶段 | 个数 | 说明 |
|---|---:|---|
| M1/M2 | 8 | Loader/内核早期 + deliberate `M2 #PF caught`（最后） |
| M3 | 9 | APIC/时钟/输入/串口/调度等 |
| M4 | 10 | 对象/模块/init/child/exit 等 |
| M5a | 6 | VFS/页缓存/ramfs/锁/通知/启动模块迁移 |
| M5b | 8 | 6 基础 + 本启动 2（首启 persistence/first boot OK；二启 persistence/M5b OK） |
| M5c1 | 4 | 挂载 + init/child 文件 + M5c1 OK |
| M5c2 | 3 | init/child mmap + M5c2 OK |
| M5c3 | 8 | xattr/sparse/watch/locks/faults 等 |
| M6a1 | 4 | init timer/event、child event、M6a1 OK |
| M6a2 | 10 | channel/port/shm/futex/subscription + M6a2 OK |
| M6b1 | 1 | `[CaelumKernel] M6b1 online=4` |
| M6b2a | 1 | `[CaelumKernel] M6b2a locks OK` |
| M6b2 | 5 | ap user/ap preempt/wake ipi/migrate + M6b2 OK（带统计 payload） |
| M6c | 5 | display probe/display/input ready/input OK/M6c OK |
| M7a | 6 | ipv4/ipv6 udp/tcp + sockets + M7a OK |
| M7b | 14 | 12 条 suite + `[CaelumNet] M7b OK` + `[CaelumKernel] M7b OK` |
| M7d | 8 | 7 条 `[CaelumLinux]` + `[CaelumKernel] M7d OK`（verdict 带 sockets/bindings） |
| M8a | 2 | `[CaelumLinux] M8a memory OK`、`M8a files OK` |
| M8b | 2 | `[CaelumLinux] M8b time OK`、`M8b info OK` |
| M8c | 1 | `[CaelumLinux] M8c signals OK` |
| M8d | 1 | `[CaelumLinux] M8d process OK`（仅 parent 打印一次，无 payload） |
| M8e | 1 | `[CaelumLinux] M8e files OK`（仅 parent 打印一次，无 payload） |
| M8f | 2 | `[CaelumLinux] M8f futex OK`、`M8f tls OK`（仅 parent 打印一次，无 payload） |
| M8g | 2 | `[CaelumLinux] M8g eventfd OK`、`M8g poll OK`（仅 parent 打印一次，无 payload） |
| M8h | 2 | `[CaelumLinux] M8h procfs OK`、`M8h devfs OK`（仅 parent 打印一次，无 payload） |
| M9a | 3 | `[CaelumLinux] M9a timerfd OK`、`M9a signalfd OK`、`M9a epoll OK`（仅 parent 各打印一次，无 payload） |
| M9b | 4 | `[CaelumLinux] M9b abstract OK`、`M9b rights OK`、`M9b credentials OK`、`M9b epoll-et OK`（仅 parent 各打印一次，无 payload） |
| M9c | 1 | `[CaelumLinux] M9c locks OK`（仅 parent 打印一次，无 payload） |
| M9d1 | 2 | `[CaelumDyn] interp OK`（带计数 payload，harness 按前缀匹配）、`[CaelumLinux] M9d dynamic OK`（纯文本，仅 parent 各打印一次） |
| M9d2 | 1 | `[CaelumLinux] M9d vdso OK`（纯文本，仅 parent 打印一次，无 payload） |
| M9e | 1 | `[CaelumLinux] M9e shared OK`（纯文本，仅 parent 打印一次，无 payload） |
| M9f | 1 | `[CaelumLinux] M9f shared OK`（纯文本，仅 parent 打印一次，无 payload） |

前缀与 payload 规则：M1/M2 用 `[CaelumLoader]`/`[CaelumKernel]`；M6c 的 gfx 行用
`[CaelumGfx]`；M7b 用户行用 `[CaelumNet]`、内核 verdict 用 `[CaelumKernel]`；M7d/M8/M9a/M9b/M9c/M9d/M9e/M9f 行用
`[CaelumLinux]`（M8d/M8e/M8f/M8g/M8h/M9a/M9b/M9c 与 M9d/M9e/M9f 的文本行为纯文本、仅 parent 各一次；
M9d1 的 interp 行用 `[CaelumDyn]`）、内核 verdict 用 `[CaelumKernel]`。
同一前缀不可混用；payload 规则见上。

## 顺序契约

- M8/M9a～M9f 段固定在 M7d 用户七条之后、内核 `[CaelumKernel] M7d OK` 之前：
  `[CaelumLinux] M7d OK` → `M8a memory OK` → `M8a files OK` → `M8b time OK` →
  `M8b info OK` → `M8c signals OK` → `[CaelumLinux] M8d process OK` →
  `[CaelumLinux] M8e files OK` → `[CaelumLinux] M8f futex OK` → `[CaelumLinux] M8f tls OK` → `[CaelumLinux] M8g eventfd OK` → `[CaelumLinux] M8g poll OK` →
  `[CaelumLinux] M8h procfs OK` → `[CaelumLinux] M8h devfs OK` →
  `[CaelumLinux] M9a timerfd OK` → `[CaelumLinux] M9a signalfd OK` → `[CaelumLinux] M9a epoll OK` →
  `[CaelumLinux] M9b abstract OK` → `[CaelumLinux] M9b rights OK` → `[CaelumLinux] M9b credentials OK` →
  `[CaelumLinux] M9b epoll-et OK` →
  `[CaelumLinux] M9c locks OK` →
  `[CaelumDyn] interp OK` → `[CaelumLinux] M9d dynamic OK` → `[CaelumLinux] M9d vdso OK` →
  `[CaelumLinux] M9e shared OK` → `[CaelumLinux] M9f shared OK` → `[CaelumKernel] M7d OK (sockets=0, bindings=0)`。
- `[CaelumKernel] M2 #PF caught` 必须是**最后一个**必需标记，之后只允许 `halting` 等收尾行。
- M6b1/M6b2a 的位置固定在 `M3 OK` 之后、`M4 objects OK` 之前；M6c 五条固定在 M6b2 OK 之后；
  M7a/M7b 与 M7d 内部的顺序见 `xtask/src/main.rs` 的位置规则表。
- 顺序错但标记齐全时，报告 `all markers appeared but the marker order contract is broken`.

## 常见失败路径

- 缺 marker：报告缺哪几条并附串口尾部 60 行与 QEMU stderr。
- 提前停机：看到 `halting` 而仍有缺标记，立即失败并列出缺口。
- 数值错：`M6b2 stats:`/`M6c stats:`/`M7a stats:`/`M7b stats:`/`M7d stats:` 前缀的错误会
  指出具体字段与期望值。
- host 复核失败：报 `first difference at offset N`（pattern/文件内容）或文件缺失/长度不符。
- 动态 ELF/vDSO/共享库复核失败：报告 `M9d host check after the first/second boot failed` 或 `M9e/M9f shared library ...`（缺文件、长度或字节差异；
  `/fat/dyn-main`、`/fat/ldcaelum.so`、`/fat/vdso.so`、`/fat/m9e.so`、`/fat/m9f-a.so`、`/fat/m9f-b.so` 不得改名或走别名）。
- 截图失败：缺 PPM、非 P6、maxval 不是 255、截断或像素超差（±8）都会失败。
- 超时：默认单启动 90 s 引导、30 s 输入确认、150 s 总时长；可用
  `CAELUM_QEMU_TIMEOUT`（秒）整体放宽。

## 故障排查

| 现象 | 先检查 |
|---|---|
| 启动即停、无本阶段标记 | loader 模块数是否 6；ESP 是否过期；`cargo xtask image` 是否通过 |
| 缺 M8a～M8h/M9a/M9b/M9c/M9d/M9e/M9f | `services/linux-net`/`services/linux-dyn`/`services/linux-vdso`/`services/linux-m9e-lib`/`services/linux-m9f-a`/`services/linux-m9f-b` 是否打印对应行（M8d/M8e/M8f/M8g/M8h/M9a/M9b/M9c/M9d/M9e 只允许 parent 各打印一次）；内核 Linux64 兼容是否回归（`[CaelumLinux] FAIL ...`/`FAIL dyn-exit` 会给出阶段/步骤码）；`M9d host check ... failed`/`M9e shared library ...` 表示四份注入 ELF 的 FAT 复核失败 |
| 缺 M8d、或 M8d 打印两次 | 检查 parent 的 `wait4` 回收与子进程退出；内核 `m7d_closeout` 的进程数基线校验（失败为 `linux-child-not-reaped`） |
| 缺 M8e/M8f/M8g/M8h/M9b | 检查 `services/linux-net` stage 13（扩展文件语义）、stage 14/15（futex/TLS）、eventfd/poll 阶段、stage 18/19（procfs/devfs）、stage 20/21/22（timerfd/signalfd/epoll）与 M9b 套件（abstract/rights/credentials/epoll-et）；M9c 锁套件 stage 27（role2 锁对端 + VFS 三锁域，失败会带 stage/step 码）；`-EFAULT`/`-EINVAL`/`-EINTR` 等会带 stage/step 码 |
| 缺 M9d1/M9d2/M9e/M9f | `caelum-linux-dyn`/`caelum-interp`/`caelum-vdso`/`caelum-m9e-lib`/`caelum-m9f-a`/`caelum-m9f-b` 是否 release 构建并注入（`dyn-main`/`ldcaelum.so`/`vdso.so`/`m9e.so`/`m9f-a.so`/`m9f-b.so`）；`/fat` 是否可读；`M9d host check ... failed` 或 `M9e/M9f shared library ...` 说明注入文件缺失或字节不符 |
| `M8c` 前后失败、rc=-38 | `-ENOSYS` 表示某个 Linux syscall 兼容缺失（例如 `clock_nanosleep`），查 kernel `compat/linux` |
| 缺 M7d 用户标记 | `services/linux-net` 的 M7d 自检；`AT_CAELUM_CHANNEL`/`AT_CAELUM_NETNS` auxv |
| 缺 M7a/M7b | 内核 `net` 模块 / `services/net`；`M7c` 未实施，真实网卡相关按预期不存在 |
| 缺 M6c 或像素失败 | `kernel/src/display.rs` 探测/present；`services/gfx` 几何与 `events=5`；screendump 路径 |
| 缺 M6b2 或统计失败 | AP 定时器与跨 CPU IPI；统计阈值 payload |
| 缺 M5 磁盘复核 | 是否重新格式化了两个 raw 镜像；FAT32 需 1 扇区/簇满足 65525 簇下限 |

## 质量、压力与验收口径（约束，尚未引入专门压力切片）

以下为验收口径约束，**当前 136 标记链不包含专门的压力切片**，相关能力按约束逐步补齐；不得把约束写成已实现，也不得用单个 QEMU 环境的通过宣称更广兼容：

- **unsafe 与风险分级**：每个 `unsafe` 块就近 `// SAFETY:` 注释（不变量/边界/生命周期），高风险模块另设风险清单；压力测试按风险分级，避免机械重复。
- **压力 marker（后续切片）**：并发压力分阶段（当前 spawn/reap、SMP、信号、并发文件/IPC/锁；`fork`/`clone` 与线程组落地后再加循环 fork/线程组），marker 必须携带次数、耗时、失败数与资源基线，并区分短压力（每次验收）与定期长压力（周期性回归）。这类 marker 尚未加入现有标记表。
- **VM 与裸机分开**：本目录全部结果仅为 QEMU/OVMF 软件环境验证；M11 起驱动验收需记录 q35、virt/OVMF 与真实主板/固件/设备矩阵，单个 q35 通过不叫兼容。
- **卡死类缺陷**：卡死/死锁/活锁/饥饿/长期屏蔽中断都属缺陷；harness 必须给出超时 watchdog、最后进度与现场诊断，不允许“重启后通过”销项，也不得把无进展等待当作通过。
- **ext2 仅工程验证**：长期换日志/CoW 前须验证断电恢复、`fsync`、`rename` 原子性/顺序、`fsck` 一致性与故障注入。

核心口径：不允许 panic、静默错误、无进展卡死与资源泄漏；兼容性/兼容层结论必须附测试范围与覆盖矩阵，未覆盖部分明确标注。

## 图形与桌面过渡方案（尚未纳入本阶段验收）

图形过渡阶段的方向已确认，但**尚未实现**，本阶段的 harness 不验证它：软件渲染 + 简洁亮色 UI（用户明确偏好浅色，详细视觉设计后续补充），不追求完整桌面。用户态分工为 `displayd`（显示设备与会话管理、模式与帧提交）、`composerd`（合成器：层/表面合成与亮色基础主题绘制）、`inputd`（输入事件路由与焦点会话投递）与 `shell`（桌面壳：面板/启动器/会话管理，仅是 `composerd` 的客户端）；原生接口采用版本化 Surface/Present/Input 三段协议（Surface 创建/尺寸/格式/共享帧；Present 提交与同步；Input 事件投递）。内核只负责显示设备与输出、输入事件、共享帧映射和权限校验，不实现窗口策略、布局、主题或动画；后续经用户态 X11 兼容桥承载 Wine 等 Linux GUI，X11 语义不进入内核。该方向与 `agents.md` 的“原生主线与兼容层边界（约束 v1.0）”一致。

本阶段实际验证的只是 M6c 的最小机制：`[CaelumKernel] M6c display probe OK`、`services/gfx`（受控 `gfx` 用户进程）的 present 与输入事件、两次 screendump 的三个像素契约以及 `events=5, dropped=0`；验收标记链中**没有** `displayd`/`composerd`/`inputd`/`shell` 或 Surface/Present/Input 协议的任何标记，不能据此宣称过渡方案已实现。

## 与真实硬件的关系

以上全部是 **QEMU/OVMF 软件环境验证**：M11 才验证真实 UEFI 硬件（ACPI/PCIe/NVMe/输入/
固件差异）。本阶段结论不能用于宣称真实硬件可用。M7c（真实 virtio-net 链路）、M8 其余切片（fork/clone 完整
共享矩阵、线程组、完整 siginfo、任意进程/线程组信号）与 M9 其余切片（完整共享库 PLT/GOT 重定位与 Linux 工具运行、
glibc/musl 工作负载、Linux 设备视图）都仍未完成；M8d 只交付受控 parent/child 双进程闭环，
M8e/M8f/M8g 只交付扩展文件语义、futex/TLS 基础契约与 eventfd/poll，M8h 只交付 procfs/devfs 最小视图，
M9a/M9b/M9c 只交付 timerfd/signalfd/epoll level-triggered、abstract/SCM/EPOLLET 与文件锁三锁域的最小契约，
M9d1 只交付最小动态 ELF/PT_INTERP 闭环，M9d2 只交付真实 ET_EXEC vDSO 的入口 + 只读数据页
（CLOCK_REALTIME 明确 -ENOSYS，不是完整 vDSO），M9e 只交付真实 ET_DYN 共享库的 `DT_NEEDED`
单依赖，M9f 只交付链式三库闭包（固定两级 `DT_NEEDED`、冻结 bias 与顺序、GLOB_DAT 解析；不含 PLT/GOT 延迟绑定、符号解析、dlopen/dlsym 与 glibc/musl 重定位）；这些都不构成完整信号/线程/进程、
完整 M8/M9 或 Linux 工具链语义。
