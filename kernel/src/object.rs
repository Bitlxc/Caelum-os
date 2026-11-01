//! 原生对象表与能力句柄表（M4 最小实现）。
//!
//! 设计约束来自 `agents.md` 第 9 节与 M4 里程碑：
//!
//! - 固定容量、无堆：全局对象表 [`MAX_OBJECTS`] 项，每进程句柄表
//!   [`MAX_HANDLE_TABLE_ENTRIES`] 项；所有容器都是 `no_std` 数组。
//! - 用户句柄是不可伪造的进程局部编号，不是内核地址。编码由 Lead 冻结为
//!   `handle = (generation << 16) | (slot + 1)`：低 16 位是 1-based 槽位号
//!   （0 表示非法句柄），高 16 位是该槽位当前代次。新表每个槽位初始代次为 1，
//!   因此 init 的第一个 Console 句柄是 `0x0001_0001`，第二个 Random 句柄是
//!   `0x0001_0002`。
//! - 表项包含对象引用、权限位、继承/exec 标志和代次。解析必须校验代次与权限；
//!   关闭只释放当前表项（对象在最后一个引用释放后销毁）。
//! - 权限数值由 Lead 冻结为 `READ = 1`、`WRITE = 2`、`WAIT = 4`、`DUPLICATE = 8`；
//!   M4 的最小集合就是这四种。复制/传递只能保留或缩减权限，不能隐式提权。
//! - 每表配额与全局对象配额都返回明确错误，不 panic、不静默失败。
//! - 纯逻辑（[`ObjectTable`]、[`HandleTable`]）可在宿主单测；内核中的全局对象表
//!   由 [`IrqCell`] 保护，它从 M6b2b 起用 [`IrqSpinLock`]（关本 CPU 中断并跨 CPU
//!   自旋）。句柄表每进程一份，由 process 模块持有，不需要全局锁。
//! - 销毁钩子**不在**对象表锁内执行：引用归零时表项只登记一个
//!   [`PendingDestroy`]，由全局包装函数在锁释放后运行钩子，因此钩子可以再次
//!   进入对象表或钩子表。

use crate::sync::IrqSpinLock;
use core::cell::UnsafeCell;

/// 全局对象表容量（所有进程共享的固定对象配额）。
///
/// M5c 从 32 提升到 64：引入 `File` 对象后，init 与 child 各自持有控制台、
/// 随机数与若干文件句柄，32 项在“每个打开文件一个对象”的模型下过紧。
pub const MAX_OBJECTS: usize = 64;

/// 每进程句柄表容量（每表配额）。
///
/// M5c 从 8 提升到 32：文件句柄与 Console/Random/Process 共用同一张表，
/// 8 项在用户态开始打开文件后立刻成为瓶颈。
pub const MAX_HANDLE_TABLE_ENTRIES: usize = 32;

/// 对象标识：对象表中的槽位下标。它只在进程与内核之间传递，不暴露给用户态。
pub type ObjectId = u16;

/// 对象类型。
///
/// M4 只有这三种；M5c 追加 [`ObjectKind::File`]（负载是 VFS `OpenId` 的原始值）。
/// 判别值只用于内部索引与诊断，**不得**被 ABI 或测试按数字硬编码。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ObjectKind {
    /// 控制台对象：init 的输入/输出目标。
    Console,
    /// 随机数对象：M4 只暴露句柄，熵源状态见 `crate::rng`。
    Random,
    /// 进程对象：由 process 模块创建并登记，object 只负责类型与句柄。
    Process,
    /// 文件对象：负载是 VFS 打开描述的原始编号；关闭最后一个句柄时由
    /// 注册的销毁钩子调用 `vfs::close`。object 本身不依赖 vfs。
    File,
    /// 内存映射对象（M5c2）：负载是用户态映射编号，`munmap` 通过
    /// [`close_payload`] 反向关闭对应句柄。object 层只保存负载，不解释语义。
    VmObject,
    /// 目录监视对象（M5c3）：负载按 [`watch_payload`] 打包为
    /// `(owner: u32) << 32 | watch_id: u32`，高 32 位是创建进程的
    /// `ProcessId`，低 32 位是 `vfs::notify::WatchId`。关闭最后一个句柄时
    /// 钩子按原 owner 调用 `notify::unwatch_owned`，因此非当前进程 reap
    /// 也能关掉它遗留的监视。object 层不依赖 vfs。
    Watch,
    /// 事件对象（M6a1）：负载是 `ipc::event` 表槽位 + 1，`0` 表示未绑定 IPC 表。
    /// 事件状态（manual/auto reset、signaled）由 `ipc` 模块维护，object 层只
    /// 负责句柄、代次、权限与销毁钩子。
    Event,
    /// 事件对对象（M6a1）：一个对象带两个 signal 位（endpoint 0/1），负载是
    /// `ipc::event` 事件对表槽位 + 1；两个句柄可以 `dup` 同一对象，M6a1 不建
    /// 端点对象。
    EventPair,
    /// 定时器对象（M6a1）：负载是 `ipc::timer` 表槽位 + 1；定时器表项内部保存
    /// 本对象自己的 [`ObjectId`]，到期时按该 ID 唤醒等待者。
    Timer,
    /// 通道端点对象（M6a2）：一个 `ipc::channel` 通道由两个端点对象组成，
    /// 两个方向各自 depth 4；负载不承载槽位（状态表按 ObjectId 认端点），
    /// 关闭一个端点时由销毁钩子丢弃其入队并唤醒对端 `PeerClosed`。
    Channel,
    /// 端口端点对象（M6a2）：一个 `ipc::port` 端口由 receiver 与 sender 两个
    /// 对象链接同一状态表项；receiver 只收、sender 只发，多发送者共享同一
    /// sender 对象（`dup`/传递），关闭 sender 不影响已排队消息。
    Port,
    /// 共享内存对象（M6a2）：由 `ipc`/`mm` 后续实现填充，object 层只负责类型、
    /// 权限（`READ | WRITE | MAP | DUPLICATE`）与生命周期。
    SharedMemory,
    /// 事件订阅对象（M6a2）：对可等待对象的持久兴趣登记，具体语义由
    /// `ipc` 的事件订阅实现提供（M6a2 由 w3 的独立文件落地）。
    EventSubscription,
    /// 显示对象（M6c）：一个已打开的显示设备/共享 framebuffer。负载不承载
    /// 槽位（显示状态表按 [`ObjectId`] 认对象，由 `ipc::display` 维护），
    /// object 层只负责类型、权限（`READ | WRITE | MAP | DUPLICATE`）与生命周期；
    /// 用户态通过 VmObject 的 `map_display` 把它映射进地址空间。
    Display,
    /// 输入对象（M6c）：一个已授权的输入设备事件源。负载不承载槽位（输入
    /// 状态表按 [`ObjectId`] 认对象，由 `ipc::input` 维护），object 层只负责
    /// 类型、权限（`READ | WAIT | DUPLICATE`）与生命周期。
    Input,
    /// 套接字对象（M7b）：负载是 `net::SocketId` 的原始 `u32` 值（存放在负载的
    /// 低 32 位）；object 层不引用 `net`，只保存负载、权限
    /// （`READ | WRITE | WAIT | DUPLICATE`，不允许 `MAP`）与生命周期。接收/发送
    /// 与就绪语义由 `net` 实现，等待接入统一等待机制。
    Socket,
    /// 网络命名空间对象（M7b）：本阶段负载固定为 `0`，命名空间内容由 `net`
    /// 维护；object 层只负责类型、权限（`READ | WRITE | DUPLICATE`，不允许
    /// `WAIT`/`MAP`）与生命周期。
    NetNamespace,
    /// 事件计数器对象（M8g）：负载是 `ipc::eventfd` 表槽位 + 1，`0` 表示未绑定
    /// IPC 表。64 位计数、semaphore/nonblocking 标志与就绪语义由
    /// `ipc::eventfd` 维护；object 层只负责类型、权限
    /// （`READ | WRITE | WAIT | DUPLICATE`）与销毁钩子。
    EventFd,
    /// 高精度定时器 fd 对象（M9a）：负载是 `ipc::timerfd` 表槽位 + 1，`0`
    /// 表示未绑定；定时器状态由 `ipc::timerfd` 维护，object 层只负责类型、
    /// 权限（`READ | WRITE | WAIT | DUPLICATE`）与销毁钩子。
    TimerFd,
    /// 信号 fd 对象（M9a）：负载是 `ipc::signalfd` 表槽位 + 1，`0` 表示未
    /// 绑定；等待信号与归属进程由 `ipc::signalfd` 维护，object 层只负责类型、
    /// 权限（`READ | WRITE | WAIT | DUPLICATE`）与销毁钩子。
    SignalFd,
    /// epoll 实例对象（M9a）：负载是 `ipc::epoll` 表槽位 + 1，`0` 表示未
    /// 绑定；兴趣集合与就绪唤醒由 `ipc::epoll` 维护，object 层只负责类型、
    /// 权限（`READ | WRITE | WAIT | DUPLICATE`）与销毁钩子。
    Epoll,
}

impl ObjectKind {
    /// 对象类型总数（固定表长度用）。
    pub const COUNT: usize = 21;

    /// 类型在固定表中的下标；只用于本模块的钩子表。
    const fn index(self) -> usize {
        match self {
            ObjectKind::Console => 0,
            ObjectKind::Random => 1,
            ObjectKind::Process => 2,
            ObjectKind::File => 3,
            ObjectKind::VmObject => 4,
            ObjectKind::Watch => 5,
            ObjectKind::Event => 6,
            ObjectKind::EventPair => 7,
            ObjectKind::Timer => 8,
            ObjectKind::Channel => 9,
            ObjectKind::Port => 10,
            ObjectKind::SharedMemory => 11,
            ObjectKind::EventSubscription => 12,
            ObjectKind::Display => 13,
            ObjectKind::Input => 14,
            ObjectKind::Socket => 15,
            ObjectKind::NetNamespace => 16,
            ObjectKind::EventFd => 17,
            ObjectKind::TimerFd => 18,
            ObjectKind::SignalFd => 19,
            ObjectKind::Epoll => 20,
        }
    }

    /// 稳定名称，只用于诊断输出。
    pub const fn name(self) -> &'static str {
        match self {
            ObjectKind::Console => "console",
            ObjectKind::Random => "random",
            ObjectKind::Process => "process",
            ObjectKind::File => "file",
            ObjectKind::VmObject => "vm-object",
            ObjectKind::Watch => "watch",
            ObjectKind::Event => "event",
            ObjectKind::EventPair => "event-pair",
            ObjectKind::Timer => "timer",
            ObjectKind::Channel => "channel",
            ObjectKind::Port => "port",
            ObjectKind::SharedMemory => "shared-memory",
            ObjectKind::EventSubscription => "event-subscription",
            ObjectKind::Display => "display",
            ObjectKind::Input => "input",
            ObjectKind::Socket => "socket",
            ObjectKind::NetNamespace => "net-namespace",
            ObjectKind::EventFd => "event-fd",
            ObjectKind::TimerFd => "timer-fd",
            ObjectKind::SignalFd => "signal-fd",
            ObjectKind::Epoll => "epoll",
        }
    }
}

/// [`ObjectKind::Watch`] 负载中 owner 字段（高 32 位）的位移。
pub const WATCH_PAYLOAD_OWNER_SHIFT: u32 = 32;

/// 把 `Watch` 对象的负载打包为 `(owner: u32) << 32 | watch_id: u32`。
///
/// `owner` 是创建该监视的进程 `ProcessId` 原始值；`watch_id` 是
/// `vfs::notify::WatchId` 的原始值。两者都按位打包，不经过 vfs 类型，
/// 因此 object 层不需要依赖 vfs。
pub const fn watch_payload(owner: u32, watch_id: u32) -> u64 {
    ((owner as u64) << WATCH_PAYLOAD_OWNER_SHIFT) | (watch_id as u64)
}

/// 从 `Watch` 负载解出创建进程的 `ProcessId` 原始值。
pub const fn watch_payload_owner(payload: u64) -> u32 {
    (payload >> WATCH_PAYLOAD_OWNER_SHIFT) as u32
}

/// 从 `Watch` 负载解出 `WatchId` 原始值。
pub const fn watch_payload_id(payload: u64) -> u32 {
    payload as u32
}

/// 一个待执行的销毁钩子。
///
/// 对象表/句柄表在持锁期间只做引用计数记账，把“该对象的钩子还要跑一次”记成
/// 这个结构；锁释放后由全局包装函数（见 [`destroy_object`]、[`close_handle`]
/// 等）调用 [`run_destroy`] 真正执行钩子。`payload` 是对象创建时的负载，`object`
/// 是刚失效的 [`ObjectId`]。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct PendingDestroy {
    /// 对象类型（钩子按类型查找）。
    pub kind: ObjectKind,
    /// 对象的原始负载。
    pub payload: u64,
    /// 刚失效的对象编号。
    pub object: ObjectId,
}

/// 固定容量的待执行销毁钩子批次（无堆）。
///
/// 容量取 [`MAX_HANDLE_TABLE_ENTRIES`]：一次 [`HandleTable::clear`] 最多关闭
/// 这么多句柄，因此单个 `clear_handle_table` 调用收集的钩子不可能溢出。批次按
/// 登记顺序逐个执行，保持“先关闭的句柄先触发钩子”的既有可观察顺序。
#[derive(Clone, Copy, Debug)]
pub struct PendingDestroys {
    items: [Option<PendingDestroy>; MAX_HANDLE_TABLE_ENTRIES],
    len: usize,
}

impl PendingDestroys {
    /// 新建空批次。
    pub const fn new() -> Self {
        Self {
            items: [None; MAX_HANDLE_TABLE_ENTRIES],
            len: 0,
        }
    }

    /// 已登记的钩子数。
    pub const fn len(&self) -> usize {
        self.len
    }

    /// 是否没有待执行钩子。
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// 登记一个待执行钩子；容量由句柄表容量保证，超出只在 debug 构建中暴露。
    fn push(&mut self, pending: PendingDestroy) {
        debug_assert!(
            self.len < MAX_HANDLE_TABLE_ENTRIES,
            "pending destroy batch overflow"
        );
        if self.len < MAX_HANDLE_TABLE_ENTRIES {
            self.items[self.len] = Some(pending);
            self.len += 1;
        }
    }

    /// 按登记顺序迭代。
    fn iter(&self) -> impl Iterator<Item = PendingDestroy> + '_ {
        self.items[..self.len].iter().filter_map(|item| *item)
    }
}

impl Default for PendingDestroys {
    fn default() -> Self {
        Self::new()
    }
}

/// [`ObjectTable::release`] 的结果：释放后的引用计数，以及需要锁外执行的钩子。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Released {
    /// 释放后的引用计数（0 表示对象已失效）。
    pub refs: u32,
    /// 对象在本次释放中失效时，需要在对象表锁之外执行的销毁钩子。
    pub pending: Option<PendingDestroy>,
}

/// 对象/句柄操作的错误类型。
///
/// 错误是显式的，不 panic：配额不足、代次耗尽、句柄伪造和无权限都各自可区分，
/// 便于 process/syscall 层映射为原生状态码与诊断统计。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ObjectError {
    /// 全局对象表已满（[`MAX_OBJECTS`]）。
    ObjectTableFull,
    /// 句柄表已满（[`MAX_HANDLE_TABLE_ENTRIES`]）。
    HandleTableFull,
    /// 对象编号不存在或已被销毁。
    InvalidObject,
    /// 句柄无法解析：槽位为空、代次不匹配或编号超出表容量。
    BadHandle,
    /// 句柄指向的对象类型与请求不符。
    WrongObjectKind,
    /// 句柄权限不足以完成请求的操作。
    MissingRights,
    /// 创建对象时请求的初始权限非法：为空、含未知位，或超出该类型允许的
    /// 初始权限上界（见 [`check_initial_rights`]）。
    InvalidRights,
    /// 复制/传递请求的权限超出源句柄，属于隐式提权。
    RightsEscalation,
    /// 该槽位的代次已耗尽，为避免 ABA 问题不再复用。
    GenerationExhausted,
    /// 对象仍被引用，不能直接销毁。
    ObjectStillReferenced,
    /// 对象引用计数溢出。
    RefcountOverflow,
    /// 该类型已注册了另一个销毁钩子；同一钩子重复注册是幂等的。
    HookConflict,
}

/// 能力权限位集合。
///
/// 取值由 Lead 冻结：`READ = 1`、`WRITE = 2`、`WAIT = 4`、`DUPLICATE = 8`；
/// M5c 追加保留位 `MAP = 0x10`、`STAT = 0x20`、`LIST = 0x40`（文件/目录相关对象
/// 会用到，但 `object` 层只负责位运算，不解释其语义）。
/// `agents.md` 第 9.2 节还列出 EXECUTE/SIGNAL/TRANSFER/MANAGE，属于后续阶段。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Rights(u32);

impl Rights {
    /// 不授予任何权限（句柄存在但不可用）。
    pub const NONE: Rights = Rights(0);
    /// 读取对象数据（如控制台读、随机数读）。
    pub const READ: Rights = Rights(0x1);
    /// 写入对象（如控制台写）。
    pub const WRITE: Rights = Rights(0x2);
    /// 等待对象（如等待子进程退出）。
    pub const WAIT: Rights = Rights(0x4);
    /// 允许复制该句柄。
    pub const DUPLICATE: Rights = Rights(0x8);
    /// 允许映射对象（M5c 保留位，`object` 层只透传）。
    pub const MAP: Rights = Rights(0x10);
    /// 允许查询对象元数据（M5c 保留位）。
    pub const STAT: Rights = Rights(0x20);
    /// 允许枚举对象内容（M5c 保留位，例如目录列举）。
    pub const LIST: Rights = Rights(0x40);
    /// 当前定义支持的全部权限位。
    pub const ALL: Rights = Rights(0x7F);

    /// 原始位值。
    pub const fn bits(self) -> u32 {
        self.0
    }

    /// 是否为空权限。
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }

    /// 是否包含 `other` 的全部权限位。
    pub const fn contains(self, other: Rights) -> bool {
        (self.0 & other.0) == other.0
    }

    /// 并集。
    pub const fn union(self, other: Rights) -> Rights {
        Rights(self.0 | other.0)
    }

    /// 交集。
    pub const fn intersection(self, other: Rights) -> Rights {
        Rights(self.0 & other.0)
    }

    /// 从原始位构造，含未知位时返回 `None`。
    pub const fn from_bits(bits: u32) -> Option<Rights> {
        if bits & !Self::ALL.0 == 0 {
            Some(Rights(bits))
        } else {
            None
        }
    }

    /// 从原始位构造并丢弃未知位。
    pub const fn from_bits_truncate(bits: u32) -> Rights {
        Rights(bits & Self::ALL.0)
    }
}

/// 每种对象类型在**创建路径**上允许授予的初始权限上界。
///
/// `object` 层只做位集合策略，不解释权限语义。旧类型（Console/Random/Process/
/// File/VmObject/Watch）保持 M4/M5 的历史行为：上界为 [`Rights::ALL`]，由创建方
/// 自行约束，因此既有调用语义完全不变。M6a 的 Event/EventPair/Timer/Channel/
/// Port/EventSubscription 只允许 `READ | WRITE | WAIT | DUPLICATE`；M6a2 的
/// SharedMemory 允许 `READ | WRITE | MAP | DUPLICATE`（映射需要 `MAP`，不需要
/// 等待位）。M6c 的 Display 允许 `READ | WRITE | MAP | DUPLICATE`（帧缓冲要能
/// 映射进用户地址空间），Input 允许 `READ | WAIT | DUPLICATE`（事件流只读、
/// 可等待；不给 WRITE/MAP）。M7b 的 Socket 允许
/// `READ | WRITE | WAIT | DUPLICATE`（收发 + 等待就绪，不可映射），
/// NetNamespace 允许 `READ | WRITE | DUPLICATE`（可等待/可映射均无意义）。
/// `STAT/LIST` 保留位与空权限都不接受。
pub const fn initial_rights_bound(kind: ObjectKind) -> Rights {
    match kind {
        ObjectKind::Event
        | ObjectKind::EventPair
        | ObjectKind::Timer
        | ObjectKind::Channel
        | ObjectKind::Port
        | ObjectKind::EventSubscription
        | ObjectKind::Socket
        | ObjectKind::EventFd
        | ObjectKind::TimerFd
        | ObjectKind::SignalFd
        | ObjectKind::Epoll => Rights::READ
            .union(Rights::WRITE)
            .union(Rights::WAIT)
            .union(Rights::DUPLICATE),
        ObjectKind::SharedMemory | ObjectKind::Display => Rights::READ
            .union(Rights::WRITE)
            .union(Rights::MAP)
            .union(Rights::DUPLICATE),
        ObjectKind::Input => Rights::READ.union(Rights::WAIT).union(Rights::DUPLICATE),
        ObjectKind::NetNamespace => Rights::READ.union(Rights::WRITE).union(Rights::DUPLICATE),
        ObjectKind::Console
        | ObjectKind::Random
        | ObjectKind::Process
        | ObjectKind::File
        | ObjectKind::VmObject
        | ObjectKind::Watch => Rights::ALL,
    }
}

/// 校验创建对象时请求的初始权限。
///
/// 规则：必须非空、只含已知权限位（[`Rights::ALL`] 的位），且不超过
/// [`initial_rights_bound`]。旧类型的上界就是 `ALL`，所以这条策略只对
/// Event/EventPair/Timer 生效；Console/Random/Process/File/VmObject/Watch
/// 的既有创建路径行为不变。
pub const fn check_initial_rights(kind: ObjectKind, rights: Rights) -> Result<(), ObjectError> {
    let known = rights.bits() & !Rights::ALL.bits() == 0;
    if !known || rights.is_empty() {
        return Err(ObjectError::InvalidRights);
    }
    if !initial_rights_bound(kind).contains(rights) {
        return Err(ObjectError::InvalidRights);
    }
    Ok(())
}

impl core::ops::BitOr for Rights {
    type Output = Rights;

    fn bitor(self, rhs: Rights) -> Rights {
        self.union(rhs)
    }
}

impl core::ops::BitOrAssign for Rights {
    fn bitor_assign(&mut self, rhs: Rights) {
        self.0 |= rhs.0;
    }
}

/// 句柄创建参数：权限 + 继承/exec 标志。
///
/// `inheritable` 表示子进程创建时是否隐式继承；`exec` 表示 exec 后是否保留。
/// M4 只要求把标志记录在表项中并可查询，具体继承/exec 语义由 process 层使用
/// 显式创建参数（`spawn` 的 transfers）实现，不依赖这里的隐式继承。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct CreateHandleParams {
    rights: Rights,
    inheritable: bool,
    exec: bool,
}

impl CreateHandleParams {
    /// 默认不继承、exec 后不保留。
    pub const fn new(rights: Rights) -> Self {
        Self {
            rights,
            inheritable: false,
            exec: false,
        }
    }

    /// 设置继承标志。
    pub const fn with_inheritable(mut self, inheritable: bool) -> Self {
        self.inheritable = inheritable;
        self
    }

    /// 设置 exec 保留标志。
    pub const fn with_exec(mut self, exec: bool) -> Self {
        self.exec = exec;
        self
    }

    /// 权限。
    pub const fn rights(self) -> Rights {
        self.rights
    }

    /// 是否可继承。
    pub const fn inheritable(self) -> bool {
        self.inheritable
    }

    /// exec 后是否保留。
    pub const fn exec(self) -> bool {
        self.exec
    }
}

/// 用户可见能力句柄（进程局部编号）。
///
/// 编码（Lead 冻结）：`(generation << 16) | (slot + 1)`。原始值 `0` 是
/// [`Handle::INVALID`]，因为槽位号是 1-based 且代次从 1 开始。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Handle(u32);

impl Handle {
    /// 非法句柄（原始值 0）。
    pub const INVALID: Handle = Handle(0);

    const SLOT_MASK: u32 = 0xFFFF;

    /// 由槽位下标与代次打包句柄。
    const fn pack(slot: usize, generation: u16) -> Handle {
        Handle(((generation as u32) << 16) | (slot as u32 + 1))
    }

    /// 从原始 32 位值构造（syscall 层解码用户句柄用）。
    pub const fn from_raw(raw: u32) -> Handle {
        Handle(raw)
    }

    /// 原始 32 位值。
    pub const fn raw(self) -> u32 {
        self.0
    }

    /// 是否为非法句柄。
    pub const fn is_invalid(self) -> bool {
        self.0 == 0
    }

    /// 代次（高 16 位）。
    pub const fn generation(self) -> u16 {
        (self.0 >> 16) as u16
    }

    /// 1-based 槽位号（低 16 位）。
    pub const fn slot_plus_one(self) -> u16 {
        (self.0 & Self::SLOT_MASK) as u16
    }

    /// 槽位下标；非法句柄返回 `None`。
    pub const fn slot_index(self) -> Option<usize> {
        let low = self.0 & Self::SLOT_MASK;
        if low == 0 {
            None
        } else {
            Some((low - 1) as usize)
        }
    }
}

/// 句柄表项的继承/exec 标志查询结果。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct HandleFlags {
    /// 子进程创建时是否隐式继承。
    pub inheritable: bool,
    /// exec 后是否保留。
    pub exec: bool,
}

/// 成功解析出的句柄信息。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct ResolvedHandle {
    /// 对象编号。
    pub object: ObjectId,
    /// 对象类型。
    pub kind: ObjectKind,
    /// 该句柄拥有的权限。
    pub rights: Rights,
    /// 解析时校验过的代次。
    pub generation: u16,
}

/// 全局对象表项。
#[derive(Clone, Copy)]
struct ObjectEntry {
    live: bool,
    kind: ObjectKind,
    refs: u32,
    /// 不透明负载：`File` 对象存放 VFS 打开描述的原始编号，其余类型为 0。
    payload: u64,
    /// 该对象的销毁钩子是否已经执行过（保证恰好一次）。
    hooked: bool,
}

impl ObjectEntry {
    const DEAD: ObjectEntry = ObjectEntry {
        live: false,
        kind: ObjectKind::Console,
        refs: 0,
        payload: 0,
        hooked: false,
    };
}

/// 固定容量对象表（无堆）。
///
/// `create` 返回一个引用计数为 0 的存活对象；对象靠句柄引用存活：插入句柄时
/// 获取一个引用，关闭句柄时释放一个引用，引用归零即销毁。也可以在插入前用
/// [`ObjectTable::destroy`] 丢弃刚创建、尚未插入的对象（失败路径用）。
///
/// [`ObjectTable::create_with_payload`] 返回引用计数为 1 的存活对象，用于
/// 「对象必须先于句柄存在」的场景（如 `File` 对象在插入句柄前就要持有打开的
/// 描述引用）：调用方插入句柄（引用 2）后释放这次初始引用（回到 1）。
///
/// 引用归零或 `destroy` 成功时，如果该类型注册过销毁钩子，该类型会以对象的
/// `payload` 调用钩子一次（见 [`register_destroy_hook`]）。但**钩子不在表锁内
/// 执行**：[`ObjectTable::release`]/[`destroy`] 只返回 [`PendingDestroy`] 记录，
/// 由全局包装函数在释放表锁后调用 [`run_destroy`]。因此钩子可以安全地再次进入
/// 对象表（例如 `File` 钩子里关闭 VFS 打开描述时又释放别的对象引用）。
pub struct ObjectTable {
    entries: [ObjectEntry; MAX_OBJECTS],
}

impl ObjectTable {
    /// 创建空对象表。
    pub const fn new() -> Self {
        Self {
            entries: [ObjectEntry::DEAD; MAX_OBJECTS],
        }
    }

    /// 创建对象，返回编号；对象表满时返回 [`ObjectError::ObjectTableFull`]。
    ///
    /// 引用计数为 0，负载为 0（M4 兼容路径：Console/Random/Process）。
    pub fn create(&mut self, kind: ObjectKind) -> Result<ObjectId, ObjectError> {
        self.create_entry(kind, 0, 0)
    }

    /// 创建带不透明负载的对象，返回引用计数为 **1** 的存活对象。
    ///
    /// 负载由创建者解释（`File` 用 VFS `OpenId` 原始值）；对象表本身不依赖 vfs。
    pub fn create_with_payload(
        &mut self,
        kind: ObjectKind,
        payload: u64,
    ) -> Result<ObjectId, ObjectError> {
        self.create_entry(kind, payload, 1)
    }

    fn create_entry(
        &mut self,
        kind: ObjectKind,
        payload: u64,
        refs: u32,
    ) -> Result<ObjectId, ObjectError> {
        let slot = self
            .entries
            .iter()
            .position(|entry| !entry.live)
            .ok_or(ObjectError::ObjectTableFull)?;
        self.entries[slot] = ObjectEntry {
            live: true,
            kind,
            refs,
            payload,
            hooked: false,
        };
        Ok(slot as ObjectId)
    }

    /// 对象类型；不存在或已销毁时返回 `None`。
    pub fn kind(&self, object: ObjectId) -> Option<ObjectKind> {
        self.entries
            .get(object as usize)
            .filter(|entry| entry.live)
            .map(|entry| entry.kind)
    }

    /// 对象是否存活。
    pub fn is_live(&self, object: ObjectId) -> bool {
        self.kind(object).is_some()
    }

    /// 对象当前引用计数；不存在时返回 `None`。
    pub fn refs(&self, object: ObjectId) -> Option<u32> {
        self.entries
            .get(object as usize)
            .filter(|entry| entry.live)
            .map(|entry| entry.refs)
    }

    /// 对象的不透明负载；不存在或已销毁时返回 `None`。
    pub fn payload(&self, object: ObjectId) -> Option<u64> {
        self.entries
            .get(object as usize)
            .filter(|entry| entry.live)
            .map(|entry| entry.payload)
    }

    /// 增加一个对象引用，返回新的引用计数。
    pub fn acquire(&mut self, object: ObjectId) -> Result<u32, ObjectError> {
        let entry = self.entry_mut(object)?;
        let refs = entry
            .refs
            .checked_add(1)
            .ok_or(ObjectError::RefcountOverflow)?;
        entry.refs = refs;
        Ok(refs)
    }

    /// 释放一个对象引用，返回新的引用计数与待执行的销毁钩子。
    ///
    /// 本方法只在表锁内记账：引用归零时把表项标记失效，并把「该跑一次钩子」
    /// 打包进 [`Released::pending`]，**不**在这里调用钩子（M6b2b 起钩子在锁外
    /// 执行，见模块文档）。调用方必须在释放表锁后把 `pending` 交给
    /// [`run_destroy`]。
    ///
    /// 钩子以 `(kind, payload, object)` 调用，`object` 是刚失效的对象 ID，
    /// 让 IPC 等待方可以把「对象销毁」转成一次唤醒（M6a1）。
    pub fn release(&mut self, object: ObjectId) -> Result<Released, ObjectError> {
        let entry = self.entry_mut(object)?;
        if entry.refs == 0 {
            return Err(ObjectError::InvalidObject);
        }
        entry.refs -= 1;
        let refs = entry.refs;
        if refs != 0 {
            return Ok(Released {
                refs,
                pending: None,
            });
        }
        // 最后一个引用：对象表项立即失效；钩子在锁外执行。
        entry.live = false;
        let fire = !entry.hooked;
        let (kind, payload) = (entry.kind, entry.payload);
        if fire {
            entry.hooked = true;
        }
        let pending = if fire {
            Some(PendingDestroy {
                kind,
                payload,
                object,
            })
        } else {
            None
        };
        Ok(Released { refs, pending })
    }

    /// 销毁一个引用计数为 0 的对象（用于创建后插入失败的清理路径）。
    ///
    /// 与引用归零共用「钩子恰好一次」逻辑；本方法只返回待执行的钩子，调用方
    /// 必须在释放表锁后用 [`run_destroy`] 执行它。
    pub fn destroy(&mut self, object: ObjectId) -> Result<Option<PendingDestroy>, ObjectError> {
        let entry = self.entry_mut(object)?;
        if entry.refs != 0 {
            return Err(ObjectError::ObjectStillReferenced);
        }
        entry.live = false;
        let fire = !entry.hooked;
        let (kind, payload) = (entry.kind, entry.payload);
        if fire {
            entry.hooked = true;
        }
        Ok(if fire {
            Some(PendingDestroy {
                kind,
                payload,
                object,
            })
        } else {
            None
        })
    }

    /// 当前存活对象数。
    pub fn live_count(&self) -> usize {
        self.entries.iter().filter(|entry| entry.live).count()
    }

    fn entry_mut(&mut self, object: ObjectId) -> Result<&mut ObjectEntry, ObjectError> {
        let entry = self
            .entries
            .get_mut(object as usize)
            .ok_or(ObjectError::InvalidObject)?;
        if !entry.live {
            return Err(ObjectError::InvalidObject);
        }
        Ok(entry)
    }
}

impl Default for ObjectTable {
    fn default() -> Self {
        Self::new()
    }
}

/// 句柄表项。
#[derive(Clone, Copy)]
struct HandleEntry {
    live: bool,
    object: ObjectId,
    kind: ObjectKind,
    rights: Rights,
    inheritable: bool,
    exec: bool,
    /// 该槽位下一个句柄使用的代次；0 表示代次耗尽、永不复用。
    generation: u16,
}

impl HandleEntry {
    const EMPTY: HandleEntry = HandleEntry {
        live: false,
        object: 0,
        kind: ObjectKind::Console,
        rights: Rights::NONE,
        inheritable: false,
        exec: false,
        generation: 1,
    };
}

/// 每进程能力句柄表（固定 8 项，无堆）。
///
/// 句柄编号是进程局部的：同样的数字在不同进程里指向不同对象（或直接非法）。
/// 解析会校验槽位是否存活、代次是否匹配、以及所需权限；关闭只清空当前表项。
pub struct HandleTable {
    entries: [HandleEntry; MAX_HANDLE_TABLE_ENTRIES],
}

impl HandleTable {
    /// 新建空句柄表；每个槽位初始代次为 1。
    pub const fn new() -> Self {
        Self {
            entries: [HandleEntry::EMPTY; MAX_HANDLE_TABLE_ENTRIES],
        }
    }

    /// 表容量。
    pub const fn capacity(&self) -> usize {
        MAX_HANDLE_TABLE_ENTRIES
    }

    /// 当前存活句柄数。
    pub fn len(&self) -> usize {
        self.entries.iter().filter(|entry| entry.live).count()
    }

    /// 是否没有句柄。
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// 为新对象插入句柄。
    pub fn insert(
        &mut self,
        objects: &mut ObjectTable,
        object: ObjectId,
        rights: Rights,
    ) -> Result<Handle, ObjectError> {
        self.insert_params(objects, object, CreateHandleParams::new(rights))
    }

    /// 按创建参数插入句柄（带继承/exec 标志）。
    pub fn insert_params(
        &mut self,
        objects: &mut ObjectTable,
        object: ObjectId,
        params: CreateHandleParams,
    ) -> Result<Handle, ObjectError> {
        let kind = objects.kind(object).ok_or(ObjectError::InvalidObject)?;
        let slot = self.free_slot()?;
        let generation = self.entries[slot].generation;
        objects.acquire(object)?;
        self.entries[slot] = HandleEntry {
            live: true,
            object,
            kind,
            rights: params.rights(),
            inheritable: params.inheritable(),
            exec: params.exec(),
            generation,
        };
        Ok(Handle::pack(slot, generation))
    }

    /// 解析句柄并校验权限；不校验对象类型。
    pub fn resolve(&self, handle: Handle, required: Rights) -> Result<ResolvedHandle, ObjectError> {
        let entry = self.entry(handle)?;
        if !entry.rights.contains(required) {
            return Err(ObjectError::MissingRights);
        }
        Ok(ResolvedHandle {
            object: entry.object,
            kind: entry.kind,
            rights: entry.rights,
            generation: entry.generation,
        })
    }

    /// 解析句柄并校验对象类型与权限。
    pub fn resolve_as(
        &self,
        handle: Handle,
        expected: ObjectKind,
        required: Rights,
    ) -> Result<ResolvedHandle, ObjectError> {
        let entry = self.entry(handle)?;
        if entry.kind != expected {
            return Err(ObjectError::WrongObjectKind);
        }
        if !entry.rights.contains(required) {
            return Err(ObjectError::MissingRights);
        }
        Ok(ResolvedHandle {
            object: entry.object,
            kind: entry.kind,
            rights: entry.rights,
            generation: entry.generation,
        })
    }

    /// 查询句柄表项的继承/exec 标志。
    pub fn flags(&self, handle: Handle) -> Result<HandleFlags, ObjectError> {
        let entry = self.entry(handle)?;
        Ok(HandleFlags {
            inheritable: entry.inheritable,
            exec: entry.exec,
        })
    }

    /// 关闭句柄：只释放当前表项并让代次递增，返回原对象编号与待执行钩子。
    ///
    /// 对象只在最后一个引用释放后销毁；同对象上的其他句柄不受影响。销毁钩子
    /// 不在表锁内运行（M6b2b 起），调用方必须在释放对象表锁后执行
    /// [`PendingDestroy`]。
    pub fn close(
        &mut self,
        objects: &mut ObjectTable,
        handle: Handle,
    ) -> Result<(ObjectId, Option<PendingDestroy>), ObjectError> {
        let slot = self.slot_of(handle)?;
        let object = self.entries[slot].object;
        self.entries[slot].live = false;
        let next = next_generation(self.entries[slot].generation);
        self.entries[slot].generation = next;
        let released = objects.release(object)?;
        Ok((object, released.pending))
    }

    /// 在同一张表内复制句柄（权限只能保留或缩减）。
    pub fn duplicate(
        &mut self,
        objects: &mut ObjectTable,
        source: Handle,
        rights: Rights,
    ) -> Result<Handle, ObjectError> {
        self.duplicate_params(objects, source, CreateHandleParams::new(rights))
    }

    /// 在同一张表内按创建参数复制句柄（权限只能保留或缩减）。
    pub fn duplicate_params(
        &mut self,
        objects: &mut ObjectTable,
        source: Handle,
        params: CreateHandleParams,
    ) -> Result<Handle, ObjectError> {
        let source_entry = *self.entry(source)?;
        if !source_entry.rights.contains(params.rights()) {
            return Err(ObjectError::RightsEscalation);
        }
        self.insert_params(objects, source_entry.object, params)
    }

    /// 把句柄复制到另一张表（进程创建时传递初始句柄）；权限只能保留或缩减。
    pub fn duplicate_to(
        &self,
        objects: &mut ObjectTable,
        destination: &mut HandleTable,
        source: Handle,
        rights: Rights,
    ) -> Result<Handle, ObjectError> {
        self.duplicate_to_params(
            objects,
            destination,
            source,
            CreateHandleParams::new(rights),
        )
    }

    /// 把句柄按创建参数复制到另一张表；权限只能保留或缩减。
    pub fn duplicate_to_params(
        &self,
        objects: &mut ObjectTable,
        destination: &mut HandleTable,
        source: Handle,
        params: CreateHandleParams,
    ) -> Result<Handle, ObjectError> {
        let source_entry = *self.entry(source)?;
        if !source_entry.rights.contains(params.rights()) {
            return Err(ObjectError::RightsEscalation);
        }
        destination.insert_params(objects, source_entry.object, params)
    }

    /// 清空整张表（进程退出）；返回关闭的句柄数。
    ///
    /// 待执行的销毁钩子按关闭顺序收集进 `pending`（固定容量、无堆），由调用方
    /// 在释放对象表锁后逐个执行（见 [`run_pending_destroys`]）。
    pub fn clear(&mut self, objects: &mut ObjectTable, pending: &mut PendingDestroys) -> usize {
        let mut closed = 0;
        for slot in 0..MAX_HANDLE_TABLE_ENTRIES {
            if !self.entries[slot].live {
                continue;
            }
            let object = self.entries[slot].object;
            self.entries[slot].live = false;
            let next = next_generation(self.entries[slot].generation);
            self.entries[slot].generation = next;
            if let Ok(released) = objects.release(object)
                && let Some(destroy) = released.pending
            {
                pending.push(destroy);
            }
            closed += 1;
        }
        closed
    }

    fn entry(&self, handle: Handle) -> Result<&HandleEntry, ObjectError> {
        let slot = self.slot_of(handle)?;
        Ok(&self.entries[slot])
    }

    fn slot_of(&self, handle: Handle) -> Result<usize, ObjectError> {
        let slot = handle.slot_index().ok_or(ObjectError::BadHandle)?;
        if slot >= MAX_HANDLE_TABLE_ENTRIES {
            return Err(ObjectError::BadHandle);
        }
        let entry = &self.entries[slot];
        if !entry.live || entry.generation != handle.generation() {
            return Err(ObjectError::BadHandle);
        }
        Ok(slot)
    }

    fn free_slot(&self) -> Result<usize, ObjectError> {
        let mut any_free = false;
        for (slot, entry) in self.entries.iter().enumerate() {
            if entry.live {
                continue;
            }
            any_free = true;
            if entry.generation != 0 {
                return Ok(slot);
            }
        }
        if any_free {
            Err(ObjectError::GenerationExhausted)
        } else {
            Err(ObjectError::HandleTableFull)
        }
    }
}

impl Default for HandleTable {
    fn default() -> Self {
        Self::new()
    }
}

/// 计算槽位下一次可用的代次；`0` 是“代次耗尽、永不复用”的哨兵值。
const fn next_generation(current: u16) -> u16 {
    if current == u16::MAX { 0 } else { current + 1 }
}

// ---------------------------------------------------------------------------
// 内核全局对象表：关中断自旋锁保护，逻辑与宿主单测共用同一实现。
// ---------------------------------------------------------------------------

/// 关中断自旋锁保护的表单元。
///
/// M6b2a 起内核有多 CPU，只关本 CPU 中断已经不够：还需要跨 CPU 互斥。这里把
/// [`IrqSpinLock`] 与 `UnsafeCell` 组合，并保留原来的 `with(f)` 形状，使表访问
/// 调用点不需要改动。自旋锁不可重入：闭包内**不得**再次进入同一单元或任何
/// 访问全局对象表的包装函数（否则会死锁）。
struct IrqCell<T> {
    lock: IrqSpinLock,
    value: UnsafeCell<T>,
}

// SAFETY: 所有访问都经 `with`：它先取 [`IrqSpinLock`]（关本 CPU 中断并跨 CPU
// 自旋），取得后再独占借用 `value`。
unsafe impl<T> Sync for IrqCell<T> {}

impl<T> IrqCell<T> {
    const fn new(value: T) -> Self {
        Self {
            lock: IrqSpinLock::new(),
            value: UnsafeCell::new(value),
        }
    }

    fn with<R>(&self, f: impl FnOnce(&mut T) -> R) -> R {
        self.lock.with(|| {
            // SAFETY: 自旋锁保证同一时刻只有一个 CPU 持有 `value` 的独占借用；
            // 关中断保证本 CPU 的中断处理路径不会插进来。
            f(unsafe { &mut *self.value.get() })
        })
    }
}

// ---------------------------------------------------------------------------
// 销毁钩子：按对象类型注册，每种类型至多一个（固定表，无堆）。
//
// 用途：`File` 对象携带 VFS `OpenId` 作为负载，最后一个引用释放时必须关闭
// 对应的打开描述。object 层不依赖 vfs，改由拥有者（vfs/root）在初始化时注册
// `fn(u64)` 钩子。
//
// M6b2b 起钩子**在对象表锁与钩子表锁都释放之后**执行：表内只登记
// `PendingDestroy`，由全局包装函数调用 `run_destroy`。因此钩子可以再次进入
// 对象表（例如 `File` 钩子关闭 VFS 打开描述时又释放别的对象引用）。钩子仍在
// 关中断上下文中运行，所以必须短小、不得阻塞。
// ---------------------------------------------------------------------------

/// 销毁钩子的三种签名，按注册入口区分；同一类型只保留一个钩子。
///
/// - [`DestroyHook::Payload`]：M5c1 形态 `fn(payload)`（File 的 VFS `OpenId`）。
/// - [`DestroyHook::KindAware`]：M5c3 形态 `fn(kind, payload)`（Watch 等）。
/// - [`DestroyHook::ObjectAware`]：M6a1 形态 `fn(kind, payload, object)`，第三参
///   是刚失效对象的 [`ObjectId`]，IPC 的 Event/EventPair/Timer 用它把「对象
///   销毁」转成按对象 ID 的等待唤醒（`process::wake_object`）。
///
/// 钩子在对象表锁与钩子表锁之外执行（见 [`run_destroy`]），因此**可以**再次
/// 进入对象表；但仍在关中断上下文中运行，必须短小、不得阻塞。
#[derive(Clone, Copy)]
enum DestroyHook {
    /// M5c1 形态：只接收负载。
    Payload(fn(u64)),
    /// M5c3 形态：同时接收对象类型与负载。
    KindAware(fn(ObjectKind, u64)),
    /// M6a1 形态：接收类型、负载与对象 ID。
    ObjectAware(fn(ObjectKind, u64, ObjectId)),
}

impl DestroyHook {
    /// 执行钩子。调用点保证此时既没有对象表锁也没有钩子表锁。
    fn run(self, kind: ObjectKind, payload: u64, object: ObjectId) {
        match self {
            DestroyHook::Payload(hook) => hook(payload),
            DestroyHook::KindAware(hook) => hook(kind, payload),
            DestroyHook::ObjectAware(hook) => hook(kind, payload, object),
        }
    }
}

/// 每种对象类型一个钩子槽位。
struct HookTable {
    hooks: [Option<DestroyHook>; ObjectKind::COUNT],
}

impl HookTable {
    const fn new() -> Self {
        Self {
            hooks: [None; ObjectKind::COUNT],
        }
    }
}

static HOOKS: IrqCell<HookTable> = IrqCell::new(HookTable::new());

/// 为某种对象类型注册只接收负载的销毁钩子（M5c1 形态）。
///
/// 同一类型 + 同一个函数指针重复注册是幂等的（返回 `Ok(())`）；
/// 已存在另一个钩子（含不同签名）时返回 [`ObjectError::HookConflict`]，不覆盖。
pub fn register_destroy_hook(kind: ObjectKind, hook: fn(u64)) -> Result<(), ObjectError> {
    HOOKS.with(|hooks| {
        let slot = &mut hooks.hooks[kind.index()];
        match *slot {
            // 函数指针按地址比较（`fn` 的 `==` 在新版 Rust 里已不推荐/无意义）。
            Some(DestroyHook::Payload(existing)) if core::ptr::fn_addr_eq(existing, hook) => Ok(()),
            Some(_) => Err(ObjectError::HookConflict),
            None => {
                *slot = Some(DestroyHook::Payload(hook));
                Ok(())
            }
        }
    })
}

/// 为某种对象类型注册接收 `(kind, payload)` 的销毁钩子（M5c3 形态）。
///
/// 语义与 [`register_destroy_hook`] 相同：同类型同函数幂等，不同钩子或不同
/// 签名返回 [`ObjectError::HookConflict`]。
pub fn register_destroy_hook_with_kind(
    kind: ObjectKind,
    hook: fn(ObjectKind, u64),
) -> Result<(), ObjectError> {
    HOOKS.with(|hooks| {
        let slot = &mut hooks.hooks[kind.index()];
        match *slot {
            Some(DestroyHook::KindAware(existing)) if core::ptr::fn_addr_eq(existing, hook) => {
                Ok(())
            }
            Some(_) => Err(ObjectError::HookConflict),
            None => {
                *slot = Some(DestroyHook::KindAware(hook));
                Ok(())
            }
        }
    })
}

/// 为某种对象类型注册接收 `(kind, payload, object)` 的销毁钩子（M6a1 形态）。
///
/// M6a1 起只有 IPC 的 Event/EventPair/Timer 使用该形态；第三参是刚失效对象
/// 的 [`ObjectId`]（对象表项已标记失效，但 ID 本身可用于唤醒记录）。
/// 同类型同函数幂等，不同钩子或不同签名返回 [`ObjectError::HookConflict`]。
pub fn register_destroy_hook_with_object(
    kind: ObjectKind,
    hook: fn(ObjectKind, u64, ObjectId),
) -> Result<(), ObjectError> {
    HOOKS.with(|hooks| {
        let slot = &mut hooks.hooks[kind.index()];
        match *slot {
            Some(DestroyHook::ObjectAware(existing)) if core::ptr::fn_addr_eq(existing, hook) => {
                Ok(())
            }
            Some(_) => Err(ObjectError::HookConflict),
            None => {
                *slot = Some(DestroyHook::ObjectAware(hook));
                Ok(())
            }
        }
    })
}

/// 查询某种类型是否已注册销毁钩子（诊断/测试用）。
pub fn has_destroy_hook(kind: ObjectKind) -> bool {
    HOOKS.with(|hooks| hooks.hooks[kind.index()].is_some())
}

/// 取出钩子后立即释放钩子表，钩子在对象表借用之外调用。
fn destroy_hook(kind: ObjectKind) -> Option<DestroyHook> {
    HOOKS.with(|hooks| hooks.hooks[kind.index()])
}

/// 在对象表锁之外执行一个待处理的销毁钩子。
///
/// 调用前必须已经释放对象表锁：本函数会经 [`destroy_hook`] 取一次钩子表锁，
/// 取到 `Copy` 的函数指针后立即释放，然后才运行钩子。因此钩子执行时没有任何
/// 表锁持有，可以安全地再次进入 [`release_object`]、[`live_objects`] 等包装。
fn run_destroy(pending: Option<PendingDestroy>) {
    let Some(PendingDestroy {
        kind,
        payload,
        object,
    }) = pending
    else {
        return;
    };
    if let Some(hook) = destroy_hook(kind) {
        hook.run(kind, payload, object);
    }
}

/// 按登记顺序执行一批待处理钩子（每次进入都确认表锁已释放）。
fn run_pending_destroys(batch: PendingDestroys) {
    for pending in batch.iter() {
        run_destroy(Some(pending));
    }
}

static OBJECTS: IrqCell<ObjectTable> = IrqCell::new(ObjectTable::new());

/// 在关中断自旋锁的保护下访问全局对象表。
///
/// 闭包内不得再次调用本函数或任何同样访问全局对象表的包装函数：锁不可重入，
/// 重入会自死锁。需要在锁内产生、锁外执行的工作（例如销毁钩子）用
/// [`PendingDestroy`] 带出闭包。
pub fn with_object_table<R>(f: impl FnOnce(&mut ObjectTable) -> R) -> R {
    OBJECTS.with(f)
}

/// 全局对象表：创建对象。
pub fn create_object(kind: ObjectKind) -> Result<ObjectId, ObjectError> {
    with_object_table(|objects| objects.create(kind))
}

/// 全局对象表：创建带不透明负载的对象（引用计数为 1）。
pub fn create_with_payload(kind: ObjectKind, payload: u64) -> Result<ObjectId, ObjectError> {
    with_object_table(|objects| objects.create_with_payload(kind, payload))
}

/// 全局对象表：创建一个 Console 对象。
pub fn create_console() -> Result<ObjectId, ObjectError> {
    create_object(ObjectKind::Console)
}

/// 全局对象表：创建一个 Random 对象。
pub fn create_random() -> Result<ObjectId, ObjectError> {
    create_object(ObjectKind::Random)
}

/// 全局对象表：创建一个 Process 对象（具体进程状态由 process 模块登记）。
pub fn create_process_object() -> Result<ObjectId, ObjectError> {
    create_object(ObjectKind::Process)
}

/// 全局对象表：销毁未被引用的对象。
pub fn destroy_object(object: ObjectId) -> Result<(), ObjectError> {
    match with_object_table(|objects| objects.destroy(object)) {
        Ok(pending) => {
            run_destroy(pending);
            Ok(())
        }
        Err(error) => Err(error),
    }
}

/// 全局对象表：增加对象引用。
pub fn acquire_object(object: ObjectId) -> Result<u32, ObjectError> {
    with_object_table(|objects| objects.acquire(object))
}

/// 全局对象表：释放对象引用。
pub fn release_object(object: ObjectId) -> Result<u32, ObjectError> {
    match with_object_table(|objects| objects.release(object)) {
        Ok(released) => {
            run_destroy(released.pending);
            Ok(released.refs)
        }
        Err(error) => Err(error),
    }
}

/// 全局对象表：查询对象类型。
pub fn object_kind(object: ObjectId) -> Option<ObjectKind> {
    with_object_table(|objects| objects.kind(object))
}

/// 全局对象表：查询对象引用计数。
pub fn object_refs(object: ObjectId) -> Option<u32> {
    with_object_table(|objects| objects.refs(object))
}

/// 全局对象表：查询对象的不透明负载。
pub fn payload(object: ObjectId) -> Option<u64> {
    with_object_table(|objects| objects.payload(object))
}

/// 全局对象表：当前存活对象数。
pub fn live_objects() -> usize {
    with_object_table(|objects| objects.live_count())
}

/// 给已存在的对象插入句柄。
pub fn insert_handle(
    table: &mut HandleTable,
    object: ObjectId,
    rights: Rights,
) -> Result<Handle, ObjectError> {
    with_object_table(|objects| table.insert(objects, object, rights))
}

/// 给已存在的对象按创建参数插入句柄。
pub fn insert_handle_params(
    table: &mut HandleTable,
    object: ObjectId,
    params: CreateHandleParams,
) -> Result<Handle, ObjectError> {
    with_object_table(|objects| table.insert_params(objects, object, params))
}

/// 创建对象并立即插入句柄（失败时回收刚创建的对象）。
///
/// 这是 process 层最常用的入口，例如：
/// `object::insert_new(&mut init_handles, ObjectKind::Console, Rights::READ | Rights::WRITE)`。
pub fn insert_new(
    table: &mut HandleTable,
    kind: ObjectKind,
    rights: Rights,
) -> Result<Handle, ObjectError> {
    insert_new_params(table, kind, CreateHandleParams::new(rights))
}

/// 创建对象并按创建参数插入句柄（失败时回收刚创建的对象）。
pub fn insert_new_params(
    table: &mut HandleTable,
    kind: ObjectKind,
    params: CreateHandleParams,
) -> Result<Handle, ObjectError> {
    // 创建路径的初始权限策略：旧类型上界为 ALL（行为不变），IPC 类型有更严格集合。
    check_initial_rights(kind, params.rights())?;
    let (result, pending) = with_object_table(|objects| {
        let object = match objects.create(kind) {
            Ok(object) => object,
            Err(error) => return (Err(error), None),
        };
        match table.insert_params(objects, object, params) {
            Ok(handle) => (Ok(handle), None),
            Err(error) => {
                // 插入失败时对象引用数为 0，必须回收，避免对象表泄漏。
                (Err(error), objects.destroy(object).ok().flatten())
            }
        }
    });
    run_destroy(pending);
    result
}

/// 创建带负载的对象并按创建参数插入句柄。
///
/// 成功时对象引用计数为 1（仅由新句柄持有）：`create_with_payload` 的初始引用
/// 在插入后立即释放。失败时同样释放初始引用，使引用归零并触发该类型的销毁
/// 钩子——调用方已创建的底层资源（例如 `File` 的 VFS 打开描述）因此被正确关闭。
pub fn insert_new_with_payload(
    table: &mut HandleTable,
    kind: ObjectKind,
    payload: u64,
    rights: Rights,
) -> Result<Handle, ObjectError> {
    insert_new_with_payload_params(table, kind, payload, CreateHandleParams::new(rights))
}

/// [`insert_new_with_payload`] 的带创建参数版本。
pub fn insert_new_with_payload_params(
    table: &mut HandleTable,
    kind: ObjectKind,
    payload: u64,
    params: CreateHandleParams,
) -> Result<Handle, ObjectError> {
    // 与 `insert_new_params` 同一策略点：IPC 类型拒绝空权限/未知位/保留位。
    check_initial_rights(kind, params.rights())?;
    let (result, pending) = with_object_table(|objects| {
        let object = match objects.create_with_payload(kind, payload) {
            Ok(object) => object,
            Err(error) => return (Err(error), None),
        };
        match table.insert_params(objects, object, params) {
            Ok(handle) => {
                // 插入已获取第 2 个引用；释放初始引用后只剩句柄持有的那一个，
                // 引用计数仍为 1，因此这里不会产生待执行钩子。
                let _ = objects.release(object);
                (Ok(handle), None)
            }
            Err(error) => {
                // 释放初始引用即归零，钩子（关闭负载指向的资源）留到锁外执行。
                let pending = objects
                    .release(object)
                    .ok()
                    .and_then(|released| released.pending);
                (Err(error), pending)
            }
        }
    });
    run_destroy(pending);
    result
}

/// 跨表复制句柄（进程创建时传递初始句柄）；权限只能保留或缩减。
pub fn duplicate_handle(
    source: &HandleTable,
    destination: &mut HandleTable,
    handle: Handle,
    rights: Rights,
) -> Result<Handle, ObjectError> {
    with_object_table(|objects| source.duplicate_to(objects, destination, handle, rights))
}

/// 关闭句柄。
pub fn close_handle(table: &mut HandleTable, handle: Handle) -> Result<ObjectId, ObjectError> {
    match with_object_table(|objects| table.close(objects, handle)) {
        Ok((object, pending)) => {
            run_destroy(pending);
            Ok(object)
        }
        Err(error) => Err(error),
    }
}

/// 解析句柄并校验权限。
pub fn resolve_handle(
    table: &HandleTable,
    handle: Handle,
    required: Rights,
) -> Result<ResolvedHandle, ObjectError> {
    table.resolve(handle, required)
}

/// 解析句柄并校验对象类型与权限。
pub fn resolve_as_handle(
    table: &HandleTable,
    handle: Handle,
    expected: ObjectKind,
    required: Rights,
) -> Result<ResolvedHandle, ObjectError> {
    table.resolve_as(handle, expected, required)
}

/// 清空整张句柄表（进程退出）；返回关闭的句柄数。
///
/// 所有待执行销毁钩子在对象表锁释放之后才运行，顺序与关闭顺序一致。
pub fn clear_handle_table(table: &mut HandleTable) -> usize {
    let (closed, batch) = with_object_table(|objects| {
        let mut batch = PendingDestroys::new();
        let closed = table.clear(objects, &mut batch);
        (closed, batch)
    });
    run_pending_destroys(batch);
    closed
}

/// 按 `(kind, payload)` 在当前表中查找活跃句柄并关闭它。
///
/// 这是给 `munmap(addr, len)` 一类“只知道映射身份、不知道句柄编号”的路径用的
/// 反向关闭入口：调用方持有 `VmObject` 的负载编号，本函数在表里找完全匹配
/// `kind` + `payload` 的活跃句柄，然后走**既有**的 [`HandleTable::close`] ——
/// 权限校验、代次递增、引用计数归零与销毁钩子规则全部不变，因此不会跳过钩子
/// 或留下悬空对象；句柄表里同对象的其他句柄不受影响。
///
/// `payload` 接受 `u32` 或 `u64`：`VmObject` 用 32 位编号，`Watch` 的负载是
/// [`watch_payload`] 打出的 64 位 `(owner, watch_id)`。关闭动作本身**不受**
/// 句柄 `rights` 影响（与显式 `close` 一致）；`READ` 只用于 `drain` 之类的读操作。
///
/// 返回值：找到并成功关闭 ⇒ `Ok(true)`；当前表中没有匹配的活跃句柄 ⇒
/// `Ok(false)`，表不变；关闭过程出错 ⇒ 错误原样上传（不吞掉）。
pub fn close_payload(
    table: &mut HandleTable,
    kind: ObjectKind,
    payload: u32,
) -> Result<bool, ObjectError> {
    close_payload_wide(table, kind, u64::from(payload))
}

/// 与 [`close_payload`] 相同，但接受完整 64 位负载（`Watch` 的打包负载用）。
pub fn close_payload_wide(
    table: &mut HandleTable,
    kind: ObjectKind,
    payload: u64,
) -> Result<bool, ObjectError> {
    let (result, pending) = with_object_table(|objects| {
        let wanted = payload;
        let mut target: Option<Handle> = None;
        for slot in 0..MAX_HANDLE_TABLE_ENTRIES {
            let entry = table.entries[slot];
            if !entry.live || entry.kind != kind {
                continue;
            }
            if objects.payload(entry.object) != Some(wanted) {
                continue;
            }
            // 用表项当前代次重建句柄，保证 close 的代次校验必然通过。
            target = Some(Handle::pack(slot, entry.generation));
            break;
        }
        match target {
            Some(handle) => match table.close(objects, handle) {
                Ok((_, pending)) => (Ok(true), pending),
                Err(error) => (Err(error), None),
            },
            None => (Ok(false), None),
        }
    });
    run_destroy(pending);
    result
}

/// 全局对象表的测试串行锁。
///
/// 对象表与句柄表是 crate 级全局状态：本文件的测试以及 `process`/`syscall`
/// 的测试都会触碰它。所有这类 `#[cfg(test)]` 代码**必须**先取这把锁，否则并行
/// 执行时会出现槽位复用/计数竞争（表现为偶发的句柄失效、对象被提前回收或
/// 存活计数不符）。生产代码不经过这里。
#[cfg(test)]
pub(crate) fn test_lock() -> std::sync::MutexGuard<'static, ()> {
    static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// 清空所有类型的销毁钩子（仅测试用）。
///
/// 钩子注册是全局且持久的，测试之间会互相影响；需要独享钩子表的测试先调用本
/// 函数，并同样在 `test_lock()` 保护下执行。生产代码不经过这里。
#[cfg(test)]
pub(crate) fn reset_destroy_hooks() {
    HOOKS.with(|hooks| hooks.hooks = [None; ObjectKind::COUNT]);
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 串行化触碰全局对象表的测试（宿主测试默认并行执行）。
    ///
    /// 与其他模块的测试共用同一把 crate 级锁，见 [`super::test_lock`]。
    fn global_lock() -> std::sync::MutexGuard<'static, ()> {
        super::test_lock()
    }

    #[test]
    fn rights_bits_are_frozen() {
        assert_eq!(Rights::READ.bits(), 1);
        assert_eq!(Rights::WRITE.bits(), 2);
        assert_eq!(Rights::WAIT.bits(), 4);
        assert_eq!(Rights::DUPLICATE.bits(), 8);
        // M5c 保留位：object 层只透传，不在这里解释语义。
        assert_eq!(Rights::MAP.bits(), 0x10);
        assert_eq!(Rights::STAT.bits(), 0x20);
        assert_eq!(Rights::LIST.bits(), 0x40);
        assert_eq!(Rights::ALL.bits(), 0x7F);
        assert_eq!(Rights::NONE.bits(), 0);
        assert!(Rights::READ.contains(Rights::READ));
        assert!(!Rights::READ.contains(Rights::READ | Rights::WRITE));
        assert_eq!(Rights::from_bits(0x10), Some(Rights::MAP));
        assert_eq!(Rights::from_bits(0x80), None);
        assert_eq!(Rights::from_bits_truncate(0xFF), Rights::ALL);
        assert_eq!((Rights::READ | Rights::WRITE).bits(), 3);
    }

    #[test]
    fn object_kinds_and_quota() {
        // M5c 容量冻结：对象表 64，句柄表 32。
        assert_eq!(MAX_OBJECTS, 64);
        assert_eq!(MAX_HANDLE_TABLE_ENTRIES, 32);

        let mut objects = ObjectTable::new();
        assert_eq!(objects.live_count(), 0);

        let console = objects.create(ObjectKind::Console).unwrap();
        let random = objects.create(ObjectKind::Random).unwrap();
        let process = objects.create(ObjectKind::Process).unwrap();
        let file = objects.create(ObjectKind::File).unwrap();
        let vm_object = objects.create(ObjectKind::VmObject).unwrap();
        let watch = objects.create(ObjectKind::Watch).unwrap();
        let event = objects.create(ObjectKind::Event).unwrap();
        let event_pair = objects.create(ObjectKind::EventPair).unwrap();
        let timer = objects.create(ObjectKind::Timer).unwrap();
        let channel = objects.create(ObjectKind::Channel).unwrap();
        let port = objects.create(ObjectKind::Port).unwrap();
        let shared = objects.create(ObjectKind::SharedMemory).unwrap();
        let subscription = objects.create(ObjectKind::EventSubscription).unwrap();
        let display = objects.create(ObjectKind::Display).unwrap();
        let input = objects.create(ObjectKind::Input).unwrap();
        let socket = objects.create(ObjectKind::Socket).unwrap();
        let net_namespace = objects.create(ObjectKind::NetNamespace).unwrap();
        assert_eq!(objects.kind(console), Some(ObjectKind::Console));
        assert_eq!(objects.kind(random), Some(ObjectKind::Random));
        assert_eq!(objects.kind(process), Some(ObjectKind::Process));
        assert_eq!(objects.kind(file), Some(ObjectKind::File));
        assert_eq!(objects.kind(vm_object), Some(ObjectKind::VmObject));
        assert_eq!(objects.kind(watch), Some(ObjectKind::Watch));
        assert_eq!(objects.kind(event), Some(ObjectKind::Event));
        assert_eq!(objects.kind(event_pair), Some(ObjectKind::EventPair));
        assert_eq!(objects.kind(timer), Some(ObjectKind::Timer));
        assert_eq!(objects.kind(channel), Some(ObjectKind::Channel));
        assert_eq!(objects.kind(port), Some(ObjectKind::Port));
        assert_eq!(objects.kind(shared), Some(ObjectKind::SharedMemory));
        assert_eq!(
            objects.kind(subscription),
            Some(ObjectKind::EventSubscription)
        );
        assert_eq!(objects.kind(display), Some(ObjectKind::Display));
        assert_eq!(objects.kind(input), Some(ObjectKind::Input));
        assert_eq!(objects.kind(socket), Some(ObjectKind::Socket));
        assert_eq!(objects.kind(net_namespace), Some(ObjectKind::NetNamespace));
        assert_eq!(objects.refs(console), Some(0));
        assert_eq!(ObjectKind::Console.name(), "console");
        assert_eq!(ObjectKind::File.name(), "file");
        assert_eq!(ObjectKind::VmObject.name(), "vm-object");
        assert_eq!(ObjectKind::Watch.name(), "watch");
        assert_eq!(ObjectKind::Event.name(), "event");
        assert_eq!(ObjectKind::EventPair.name(), "event-pair");
        assert_eq!(ObjectKind::Timer.name(), "timer");
        assert_eq!(ObjectKind::Channel.name(), "channel");
        assert_eq!(ObjectKind::Port.name(), "port");
        assert_eq!(ObjectKind::SharedMemory.name(), "shared-memory");
        assert_eq!(ObjectKind::EventSubscription.name(), "event-subscription");
        assert_eq!(ObjectKind::Display.name(), "display");
        assert_eq!(ObjectKind::Input.name(), "input");
        assert_eq!(ObjectKind::Socket.name(), "socket");
        assert_eq!(ObjectKind::NetNamespace.name(), "net-namespace");
        assert_eq!(ObjectKind::EventFd.name(), "event-fd");
        assert_eq!(ObjectKind::TimerFd.name(), "timer-fd");
        assert_eq!(ObjectKind::SignalFd.name(), "signal-fd");
        assert_eq!(ObjectKind::Epoll.name(), "epoll");
        // M6a1 追加 Event/EventPair/Timer（9），M6a2 追加 Channel/Port/
        // SharedMemory/EventSubscription（13），M6c 追加 Display/Input（15），
        // M7b 追加 Socket/NetNamespace（17），M8g 追加 EventFd（18）；
        // 已有判别值不变。
        assert_eq!(ObjectKind::COUNT, 21);

        // 填满全局配额，第 MAX_OBJECTS+1 个必须明确报错。
        while objects.live_count() < MAX_OBJECTS {
            objects.create(ObjectKind::Console).unwrap();
        }
        assert_eq!(
            objects.create(ObjectKind::Console),
            Err(ObjectError::ObjectTableFull)
        );

        // 销毁一个后可复用。
        assert_eq!(
            objects.create(ObjectKind::Console),
            Err(ObjectError::ObjectTableFull)
        );
        objects.destroy(console).unwrap();
        assert_eq!(objects.kind(console), None);
        let reused = objects.create(ObjectKind::Random).unwrap();
        assert_eq!(objects.kind(reused), Some(ObjectKind::Random));
        assert_eq!(objects.live_count(), MAX_OBJECTS);
    }

    #[test]
    fn frozen_handle_encoding_matches_init_and_child() {
        let mut objects = ObjectTable::new();
        let console = objects.create(ObjectKind::Console).unwrap();
        let random = objects.create(ObjectKind::Random).unwrap();

        let mut init = HandleTable::new();
        let init_console = init
            .insert(&mut objects, console, Rights::READ | Rights::WRITE)
            .unwrap();
        let init_random = init.insert(&mut objects, random, Rights::READ).unwrap();

        // Lead 冻结值：init slot0 Console = 0x0001_0001，slot1 Random = 0x0001_0002。
        assert_eq!(init_console.raw(), 0x0001_0001);
        assert_eq!(init_random.raw(), 0x0001_0002);
        assert_eq!(init_console.generation(), 1);
        assert_eq!(init_console.slot_plus_one(), 1);
        assert_eq!(init_random.slot_plus_one(), 2);

        // 父进程只把显式列出的 Console 句柄传给 child。
        let mut child = HandleTable::new();
        let child_console = init
            .duplicate_to(&mut objects, &mut child, init_console, Rights::READ)
            .unwrap();
        assert_eq!(child_console.raw(), 0x0001_0001);

        // child 自己的 slot0 可用；父进程的 Random 句柄在 child 上是非法句柄。
        assert!(
            child
                .resolve_as(child_console, ObjectKind::Console, Rights::READ)
                .is_ok()
        );
        assert_eq!(
            child.resolve(init_random, Rights::READ),
            Err(ObjectError::BadHandle)
        );
        assert_eq!(
            child.resolve_as(init_random, ObjectKind::Random, Rights::READ),
            Err(ObjectError::BadHandle)
        );

        // 父进程的 Random 句柄在父进程里仍然有效。
        assert_eq!(
            init.resolve_as(init_random, ObjectKind::Random, Rights::READ)
                .unwrap()
                .object,
            random
        );
        // 两边都持有 Console 引用：2。
        assert_eq!(objects.refs(console), Some(2));
    }

    #[test]
    fn stale_handle_is_rejected_after_close_and_reuse() {
        let mut objects = ObjectTable::new();
        let first = objects.create(ObjectKind::Console).unwrap();
        let second = objects.create(ObjectKind::Random).unwrap();

        let mut table = HandleTable::new();
        let stale = table.insert(&mut objects, first, Rights::READ).unwrap();
        assert_eq!(stale.raw(), 0x0001_0001);

        table.close(&mut objects, stale).unwrap();
        assert_eq!(table.len(), 0);

        // 同一槽位复用后代次递增，旧句柄必须失效（防 ABA / 编号复用误引用）。
        let fresh = table.insert(&mut objects, second, Rights::READ).unwrap();
        assert_eq!(fresh.raw(), 0x0002_0001);
        assert_eq!(
            table.resolve(stale, Rights::READ),
            Err(ObjectError::BadHandle)
        );
        assert_eq!(table.resolve(fresh, Rights::READ).unwrap().object, second);
    }

    #[test]
    fn invalid_handle_values_are_rejected() {
        let mut objects = ObjectTable::new();
        let object = objects.create(ObjectKind::Console).unwrap();
        let mut table = HandleTable::new();
        let handle = table.insert(&mut objects, object, Rights::ALL).unwrap();
        assert_eq!(handle.raw(), 0x0001_0001);

        assert_eq!(
            table.resolve(Handle::INVALID, Rights::READ),
            Err(ObjectError::BadHandle)
        );
        // 槽位号越界。
        assert_eq!(
            table.resolve(Handle::from_raw(0x0001_0009), Rights::READ),
            Err(ObjectError::BadHandle)
        );
        // 代次不匹配。
        assert_eq!(
            table.resolve(Handle::from_raw(0x0002_0001), Rights::READ),
            Err(ObjectError::BadHandle)
        );
        // 代次为 0 的编号永远非法。
        assert_eq!(
            table.resolve(Handle::from_raw(0x0000_0001), Rights::READ),
            Err(ObjectError::BadHandle)
        );
        // 空槽位。
        assert_eq!(
            table.resolve(Handle::from_raw(0x0001_0002), Rights::READ),
            Err(ObjectError::BadHandle)
        );
        assert!(Handle::INVALID.is_invalid());
        assert_eq!(Handle::from_raw(0x0001_0001).slot_index(), Some(0));
        assert_eq!(Handle::INVALID.slot_index(), None);
    }

    #[test]
    fn resolve_checks_rights() {
        let mut objects = ObjectTable::new();
        let object = objects.create(ObjectKind::Random).unwrap();
        let mut table = HandleTable::new();
        let handle = table.insert(&mut objects, object, Rights::READ).unwrap();

        assert!(table.resolve(handle, Rights::READ).is_ok());
        assert_eq!(
            table.resolve(handle, Rights::WRITE),
            Err(ObjectError::MissingRights)
        );
        assert_eq!(
            table.resolve(handle, Rights::READ | Rights::WAIT),
            Err(ObjectError::MissingRights)
        );
        assert_eq!(
            table.resolve_as(handle, ObjectKind::Console, Rights::READ),
            Err(ObjectError::WrongObjectKind)
        );
        assert_eq!(
            table.resolve_as(handle, ObjectKind::Random, Rights::WRITE),
            Err(ObjectError::MissingRights)
        );
    }

    #[test]
    fn duplicate_can_only_shrink_rights() {
        let mut objects = ObjectTable::new();
        let object = objects.create(ObjectKind::Console).unwrap();
        let mut table = HandleTable::new();
        let source = table
            .insert(&mut objects, object, Rights::READ | Rights::WRITE)
            .unwrap();

        // 提权必须被拒绝。
        assert_eq!(
            table.duplicate(&mut objects, source, Rights::READ | Rights::WAIT),
            Err(ObjectError::RightsEscalation)
        );
        assert_eq!(
            table.duplicate_to(
                &mut objects,
                &mut HandleTable::new(),
                source,
                Rights::READ | Rights::DUPLICATE
            ),
            Err(ObjectError::RightsEscalation)
        );

        // 等权与缩减都允许，且指向同一对象。
        let same = table
            .duplicate(&mut objects, source, Rights::READ | Rights::WRITE)
            .unwrap();
        let shrunk = table.duplicate(&mut objects, source, Rights::READ).unwrap();
        assert_eq!(table.resolve(same, Rights::WRITE).unwrap().object, object);
        assert_eq!(table.resolve(shrunk, Rights::READ).unwrap().object, object);
        assert_eq!(
            table.resolve(shrunk, Rights::WRITE),
            Err(ObjectError::MissingRights)
        );
        assert_eq!(objects.refs(object), Some(3));
    }

    #[test]
    fn close_only_releases_that_entry() {
        let mut objects = ObjectTable::new();
        let object = objects.create(ObjectKind::Console).unwrap();
        let mut table = HandleTable::new();
        let first = table.insert(&mut objects, object, Rights::READ).unwrap();
        let second = table
            .insert(&mut objects, object, Rights::READ | Rights::WRITE)
            .unwrap();
        assert_eq!(objects.refs(object), Some(2));
        assert_eq!(table.len(), 2);

        // 关闭第一个句柄：只影响当前表项，同对象第二个句柄仍有效。
        assert_eq!(table.close(&mut objects, first).unwrap().0, object);
        assert_eq!(objects.refs(object), Some(1));
        assert_eq!(objects.kind(object), Some(ObjectKind::Console));
        assert!(table.resolve(second, Rights::READ).is_ok());
        assert_eq!(
            table.resolve(first, Rights::READ),
            Err(ObjectError::BadHandle)
        );
        assert_eq!(
            table.close(&mut objects, first),
            Err(ObjectError::BadHandle)
        );

        // 关闭最后一个句柄：对象引用归零并销毁。
        assert_eq!(table.close(&mut objects, second).unwrap().0, object);
        assert_eq!(objects.kind(object), None);
        assert_eq!(table.len(), 0);
    }

    #[test]
    fn handle_table_quota_and_failed_insert_does_not_leak() {
        let mut objects = ObjectTable::new();
        let mut table = HandleTable::new();
        for _ in 0..MAX_HANDLE_TABLE_ENTRIES {
            let object = objects.create(ObjectKind::Console).unwrap();
            table.insert(&mut objects, object, Rights::READ).unwrap();
        }
        assert_eq!(table.len(), MAX_HANDLE_TABLE_ENTRIES);

        let overflow = objects.create(ObjectKind::Random).unwrap();
        assert_eq!(
            table.insert(&mut objects, overflow, Rights::READ),
            Err(ObjectError::HandleTableFull)
        );
        // 失败路径不能泄漏对象引用：overflow 仍然引用计数为 0。
        assert_eq!(objects.refs(overflow), Some(0));

        // 关闭一项后可以重新插入。
        let first = Handle::from_raw(0x0001_0001);
        table.close(&mut objects, first).unwrap();
        let handle = table.insert(&mut objects, overflow, Rights::READ).unwrap();
        assert_eq!(handle.raw(), 0x0002_0001);
    }

    #[test]
    fn generation_exhaustion_is_reported() {
        let mut objects = ObjectTable::new();
        let mut table = HandleTable::new();
        for _ in 0..MAX_HANDLE_TABLE_ENTRIES {
            let object = objects.create(ObjectKind::Console).unwrap();
            table.insert(&mut objects, object, Rights::READ).unwrap();
        }
        // 人为把每个槽位推进到最后一个代次，然后正常关闭，使槽位进入“耗尽”状态。
        for slot in 0..MAX_HANDLE_TABLE_ENTRIES {
            table.entries[slot].generation = u16::MAX;
        }
        for slot in 0..MAX_HANDLE_TABLE_ENTRIES {
            let handle = Handle::from_raw(((u16::MAX as u32) << 16) | (slot as u32 + 1));
            table.close(&mut objects, handle).unwrap();
        }
        assert_eq!(table.len(), 0);

        let object = objects.create(ObjectKind::Random).unwrap();
        assert_eq!(
            table.insert(&mut objects, object, Rights::READ),
            Err(ObjectError::GenerationExhausted)
        );
    }

    #[test]
    fn flags_are_recorded_and_queryable() {
        let mut objects = ObjectTable::new();
        let object = objects.create(ObjectKind::Console).unwrap();
        let mut table = HandleTable::new();
        let inherit = table
            .insert_params(
                &mut objects,
                object,
                CreateHandleParams::new(Rights::READ).with_inheritable(true),
            )
            .unwrap();
        let exec = table
            .insert_params(
                &mut objects,
                object,
                CreateHandleParams::new(Rights::READ).with_exec(true),
            )
            .unwrap();

        assert_eq!(
            table.flags(inherit),
            Ok(HandleFlags {
                inheritable: true,
                exec: false
            })
        );
        assert_eq!(
            table.flags(exec),
            Ok(HandleFlags {
                inheritable: false,
                exec: true
            })
        );
        // 复制默认不继承、不跨 exec；flags 需要显式给出。
        let copy = table
            .duplicate(&mut objects, inherit, Rights::READ)
            .unwrap();
        assert_eq!(
            table.flags(copy),
            Ok(HandleFlags {
                inheritable: false,
                exec: false
            })
        );
        assert_eq!(
            table
                .duplicate_to_params(
                    &mut objects,
                    &mut HandleTable::new(),
                    inherit,
                    CreateHandleParams::new(Rights::READ)
                        .with_inheritable(true)
                        .with_exec(true),
                )
                .and_then(|handle| Ok(handle.raw())),
            Ok(0x0001_0001)
        );
        assert_eq!(table.capacity(), MAX_HANDLE_TABLE_ENTRIES);
    }

    #[test]
    fn clear_releases_every_handle() {
        let mut objects = ObjectTable::new();
        let first = objects.create(ObjectKind::Console).unwrap();
        let second = objects.create(ObjectKind::Random).unwrap();
        let mut table = HandleTable::new();
        table.insert(&mut objects, first, Rights::READ).unwrap();
        table.insert(&mut objects, first, Rights::READ).unwrap();
        table.insert(&mut objects, second, Rights::READ).unwrap();
        assert_eq!(objects.refs(first), Some(2));

        let mut batch = PendingDestroys::new();
        assert_eq!(table.clear(&mut objects, &mut batch), 3);
        // Console/Random 没有注册钩子，但引用归零的两个对象仍要记成候选；
        // `run_destroy` 在锁外查钩子表时找不到钩子，因此不会执行任何回调。
        assert_eq!(batch.len(), 2);
        assert!(batch.iter().all(|pending| !has_destroy_hook(pending.kind)));
        let pending: [ObjectId; 2] = std::array::from_fn(|slot| {
            batch
                .iter()
                .nth(slot)
                .map(|pending| pending.object)
                .unwrap()
        });
        assert_eq!(pending, [first, second]);
        run_pending_destroys(batch);
        assert_eq!(table.len(), 0);
        assert_eq!(objects.kind(first), None);
        assert_eq!(objects.kind(second), None);
        assert_eq!(objects.live_count(), 0);
    }

    #[test]
    fn object_destroy_requires_no_references() {
        let mut objects = ObjectTable::new();
        let object = objects.create(ObjectKind::Process).unwrap();
        objects.destroy(object).unwrap();
        assert_eq!(objects.kind(object), None);
        assert_eq!(objects.destroy(object), Err(ObjectError::InvalidObject));

        let live = objects.create(ObjectKind::Process).unwrap();
        let mut table = HandleTable::new();
        table.insert(&mut objects, live, Rights::WAIT).unwrap();
        assert_eq!(
            objects.destroy(live),
            Err(ObjectError::ObjectStillReferenced)
        );
        assert_eq!(objects.acquire(live).unwrap(), 2);
        assert_eq!(objects.release(live).unwrap().refs, 1);
        assert_eq!(objects.release(live).unwrap().refs, 0);
        assert_eq!(objects.kind(live), None);
    }

    #[test]
    fn global_table_wiring_works() {
        let _guard = global_lock();
        let start = live_objects();

        let mut init = HandleTable::new();
        let console =
            insert_new(&mut init, ObjectKind::Console, Rights::READ | Rights::WRITE).unwrap();
        let random = insert_new(&mut init, ObjectKind::Random, Rights::READ).unwrap();
        assert_eq!(console.raw(), 0x0001_0001);
        assert_eq!(random.raw(), 0x0001_0002);
        assert_eq!(live_objects(), start + 2);

        let resolved =
            resolve_as_handle(&init, console, ObjectKind::Console, Rights::WRITE).unwrap();
        assert_eq!(resolved.kind, ObjectKind::Console);
        assert_eq!(object_kind(resolved.object), Some(ObjectKind::Console));
        assert_eq!(object_refs(resolved.object), Some(1));

        // spawn 场景：child 只拿到显式列出的 Console 句柄。
        let mut child = HandleTable::new();
        let child_console = duplicate_handle(&mut init, &mut child, console, Rights::READ).unwrap();
        assert_eq!(child_console.raw(), 0x0001_0001);
        assert_eq!(
            resolve_handle(&child, random, Rights::READ),
            Err(ObjectError::BadHandle)
        );

        assert_eq!(clear_handle_table(&mut child), 1);
        let random_object = resolve_handle(&init, random, Rights::READ).unwrap().object;
        assert_eq!(close_handle(&mut init, random).unwrap(), random_object);
        // init 的 Console 句柄仍在：先清空它，累计存活对象数才回到起点。
        assert_eq!(clear_handle_table(&mut init), 1);
        assert_eq!(live_objects(), start);
    }

    #[test]
    fn insert_new_recovers_object_when_insert_fails() {
        let _guard = global_lock();
        let start = live_objects();
        let mut table = HandleTable::new();
        for _ in 0..MAX_HANDLE_TABLE_ENTRIES {
            insert_new(&mut table, ObjectKind::Console, Rights::READ).unwrap();
        }
        let before = live_objects();
        assert_eq!(
            insert_new(&mut table, ObjectKind::Random, Rights::READ),
            Err(ObjectError::HandleTableFull)
        );
        assert_eq!(live_objects(), before);
        assert_eq!(clear_handle_table(&mut table), MAX_HANDLE_TABLE_ENTRIES);
        assert_eq!(live_objects(), start);
    }

    // -- M5c1：File 负载 + 销毁钩子 ----------------------------------------

    static HOOK_CALLS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    static LAST_PAYLOAD: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(u64::MAX);

    fn record_file_destroy(payload: u64) {
        HOOK_CALLS.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        LAST_PAYLOAD.store(payload, std::sync::atomic::Ordering::SeqCst);
    }

    fn noop_hook(_payload: u64) {}

    /// 注册 File 钩子并清零计数器；调用方必须已经持有 `global_lock()`。
    fn arm_file_hook() {
        register_destroy_hook(ObjectKind::File, record_file_destroy).unwrap();
        HOOK_CALLS.store(0, std::sync::atomic::Ordering::SeqCst);
        LAST_PAYLOAD.store(u64::MAX, std::sync::atomic::Ordering::SeqCst);
    }

    fn hook_calls() -> usize {
        HOOK_CALLS.load(std::sync::atomic::Ordering::SeqCst)
    }

    fn last_payload() -> u64 {
        LAST_PAYLOAD.load(std::sync::atomic::Ordering::SeqCst)
    }

    #[test]
    fn file_objects_carry_payload_and_kind() {
        let mut objects = ObjectTable::new();
        let file = objects
            .create_with_payload(ObjectKind::File, 0x0042)
            .unwrap();
        assert_eq!(objects.kind(file), Some(ObjectKind::File));
        assert_eq!(objects.payload(file), Some(0x0042));
        // create_with_payload 返回引用计数为 1 的存活对象。
        assert_eq!(objects.refs(file), Some(1));
        assert_eq!(objects.live_count(), 1);

        // 普通 create 的负载恒为 0。
        let console = objects.create(ObjectKind::Console).unwrap();
        assert_eq!(objects.payload(console), Some(0));
        assert_eq!(objects.refs(console), Some(0));
    }

    #[test]
    fn destroyed_object_has_no_payload() {
        let mut objects = ObjectTable::new();
        let file = objects
            .create_with_payload(ObjectKind::File, 0x7ABC)
            .unwrap();
        objects.release(file).unwrap();
        assert_eq!(objects.kind(file), None);
        assert_eq!(objects.payload(file), None);
    }

    #[test]
    fn destroy_hook_runs_once_at_last_release() {
        let _guard = global_lock();
        let start = live_objects();
        arm_file_hook();

        let mut table = HandleTable::new();
        let object = create_with_payload(ObjectKind::File, 0x1234).unwrap();
        let handle = with_object_table(|objects| {
            table.insert_params(objects, object, CreateHandleParams::new(Rights::READ))
        })
        .unwrap();
        // 句柄持有 2 个引用中的 1 个：释放创建时的初始引用。
        assert_eq!(object_refs(object), Some(2));
        release_object(object).unwrap();
        assert_eq!(object_refs(object), Some(1));
        assert_eq!(hook_calls(), 0);

        // 关闭最后一个句柄 ⇒ 钩子恰好执行一次，payload 原样传入。
        assert_eq!(close_handle(&mut table, handle).unwrap(), object);
        assert_eq!(hook_calls(), 1);
        assert_eq!(last_payload(), 0x1234);
        assert_eq!(object_kind(object), None);

        // 重复关闭是非法句柄，不会再次触发钩子。
        assert_eq!(
            close_handle(&mut table, handle),
            Err(ObjectError::BadHandle)
        );
        assert_eq!(hook_calls(), 1);
        assert_eq!(live_objects(), start);
    }

    #[test]
    fn destroy_hook_runs_for_uninserted_object() {
        let _guard = global_lock();
        let start = live_objects();
        arm_file_hook();

        let object = create_with_payload(ObjectKind::File, 0x0BAD).unwrap();
        assert_eq!(object_refs(object), Some(1));
        release_object(object).unwrap();
        assert_eq!(hook_calls(), 1);
        assert_eq!(last_payload(), 0x0BAD);
        assert_eq!(object_kind(object), None);
        assert_eq!(live_objects(), start);
    }

    #[test]
    fn clear_handle_table_runs_hooks() {
        let _guard = global_lock();
        let start = live_objects();
        arm_file_hook();

        let mut table = HandleTable::new();
        let first =
            insert_new_with_payload(&mut table, ObjectKind::File, 0x00AA, Rights::READ).unwrap();
        let second =
            insert_new_with_payload(&mut table, ObjectKind::File, 0x00BB, Rights::READ).unwrap();
        let objects = [
            resolve_handle(&table, first, Rights::READ).unwrap().object,
            resolve_handle(&table, second, Rights::READ).unwrap().object,
        ];
        assert_eq!(hook_calls(), 0);

        assert_eq!(clear_handle_table(&mut table), 2);
        assert_eq!(hook_calls(), 2);
        assert!(last_payload() == 0x00AA || last_payload() == 0x00BB);
        for object in objects {
            assert_eq!(object_kind(object), None);
        }
        assert_eq!(live_objects(), start);
    }

    // -- M6b2b：销毁钩子在对象表锁之外执行、且可以重入对象表 ----------------

    static REENTRANT_HOOK_CALLS: std::sync::atomic::AtomicUsize =
        std::sync::atomic::AtomicUsize::new(0);
    static REENTRANT_TARGET: std::sync::atomic::AtomicU16 =
        std::sync::atomic::AtomicU16::new(u16::MAX);

    /// 钩子内断言对象表锁已释放，然后重入对象表并释放另一个对象。
    ///
    /// 若钩子仍在对象表锁内执行，第一条断言立即失败（而不是在后面重入
    /// `live_objects()` 时死锁）；若锁已释放，两次释放的钩子各执行一次。
    fn reentrant_destroy_hook(_kind: ObjectKind, _payload: u64, _object: ObjectId) {
        assert!(
            !OBJECTS.lock.is_locked(),
            "destroy hook ran while the object table lock was held"
        );
        REENTRANT_HOOK_CALLS.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        // 重入全局对象表：这本是旧实现会自死锁的路径。
        let _ = live_objects();
        let target = REENTRANT_TARGET.swap(u16::MAX, std::sync::atomic::Ordering::SeqCst);
        if target != u16::MAX {
            // 在钩子里再释放一个对象：它的钩子也会重入对象表。
            let _ = release_object(target);
        }
    }

    #[test]
    fn destroy_hook_runs_outside_the_lock_and_may_reenter_release() {
        let _guard = global_lock();
        let start = live_objects();
        reset_destroy_hooks();
        register_destroy_hook_with_object(ObjectKind::SharedMemory, reentrant_destroy_hook)
            .unwrap();
        REENTRANT_HOOK_CALLS.store(0, std::sync::atomic::Ordering::SeqCst);
        REENTRANT_TARGET.store(u16::MAX, std::sync::atomic::Ordering::SeqCst);

        let first = create_with_payload(ObjectKind::SharedMemory, 0x5151).unwrap();
        let second = create_with_payload(ObjectKind::SharedMemory, 0x5252).unwrap();
        REENTRANT_TARGET.store(first, std::sync::atomic::Ordering::SeqCst);

        // 释放 second ⇒ 钩子在锁外运行并释放 first ⇒ first 的钩子也运行。
        assert_eq!(release_object(second).unwrap(), 0);
        assert_eq!(
            REENTRANT_HOOK_CALLS.load(std::sync::atomic::Ordering::SeqCst),
            2
        );
        assert_eq!(object_kind(first), None);
        assert_eq!(object_kind(second), None);
        assert_eq!(live_objects(), start);
        reset_destroy_hooks();
    }

    static CLEAR_HOOK_CALLS: std::sync::atomic::AtomicUsize =
        std::sync::atomic::AtomicUsize::new(0);

    fn clear_batch_destroy_hook(_kind: ObjectKind, _payload: u64, _object: ObjectId) {
        assert!(
            !OBJECTS.lock.is_locked(),
            "destroy hook ran while the object table lock was held"
        );
        CLEAR_HOOK_CALLS.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        // 每个钩子都重入全局对象表：锁内执行会立刻失败或死锁。
        let _ = live_objects();
    }

    #[test]
    fn clear_handle_table_runs_every_hook_outside_the_lock() {
        let _guard = global_lock();
        let start = live_objects();
        reset_destroy_hooks();
        register_destroy_hook_with_object(ObjectKind::EventSubscription, clear_batch_destroy_hook)
            .unwrap();
        CLEAR_HOOK_CALLS.store(0, std::sync::atomic::Ordering::SeqCst);

        let mut table = HandleTable::new();
        for payload in 0..4u64 {
            insert_new_with_payload(
                &mut table,
                ObjectKind::EventSubscription,
                payload,
                Rights::READ,
            )
            .unwrap();
        }
        let objects_in_table: [ObjectId; 4] = std::array::from_fn(|slot| {
            table
                .entries
                .iter()
                .filter(|entry| entry.live)
                .nth(slot)
                .map(|entry| entry.object)
                .unwrap()
        });

        // 一次 clear 关闭 4 个句柄 ⇒ 4 个钩子都必须在锁释放之后执行。
        assert_eq!(clear_handle_table(&mut table), 4);
        assert_eq!(
            CLEAR_HOOK_CALLS.load(std::sync::atomic::Ordering::SeqCst),
            4
        );
        for object in objects_in_table {
            assert_eq!(object_kind(object), None);
        }
        assert_eq!(live_objects(), start);
        reset_destroy_hooks();
    }

    #[test]
    fn register_destroy_hook_conflict_and_idempotence() {
        let _guard = global_lock();
        // 同类型 + 同函数指针：幂等。
        register_destroy_hook(ObjectKind::Process, noop_hook).unwrap();
        register_destroy_hook(ObjectKind::Process, noop_hook).unwrap();
        assert!(has_destroy_hook(ObjectKind::Process));

        // 同类型 + 不同函数：明确拒绝，不覆盖原钩子。
        assert_eq!(
            register_destroy_hook(ObjectKind::Process, record_file_destroy),
            Err(ObjectError::HookConflict)
        );
        // 其他类型不受影响。
        assert!(!has_destroy_hook(ObjectKind::Console));
    }

    #[test]
    fn insert_new_with_payload_releases_initial_reference() {
        let _guard = global_lock();
        let start = live_objects();
        arm_file_hook();

        let mut table = HandleTable::new();
        let handle =
            insert_new_with_payload(&mut table, ObjectKind::File, 0x0055, Rights::READ).unwrap();
        let object = resolve_handle(&table, handle, Rights::READ).unwrap().object;
        // 只有句柄持有引用（初始引用已释放）。
        assert_eq!(object_refs(object), Some(1));
        assert_eq!(payload(object), Some(0x0055));

        assert_eq!(close_handle(&mut table, handle).unwrap(), object);
        assert_eq!(hook_calls(), 1);
        assert_eq!(last_payload(), 0x0055);
        assert_eq!(live_objects(), start);
    }

    #[test]
    fn insert_new_with_payload_closes_payload_when_handle_insert_fails() {
        let _guard = global_lock();
        let start = live_objects();
        arm_file_hook();

        let mut table = HandleTable::new();
        for _ in 0..MAX_HANDLE_TABLE_ENTRIES {
            insert_new(&mut table, ObjectKind::Console, Rights::READ).unwrap();
        }
        let before = live_objects();
        assert_eq!(
            insert_new_with_payload(&mut table, ObjectKind::File, 0x00CC, Rights::READ),
            Err(ObjectError::HandleTableFull)
        );
        // 插入失败时初始引用被释放，钩子关闭负载对应的资源。
        assert_eq!(hook_calls(), 1);
        assert_eq!(last_payload(), 0x00CC);
        assert_eq!(live_objects(), before);
        assert_eq!(clear_handle_table(&mut table), MAX_HANDLE_TABLE_ENTRIES);
        assert_eq!(live_objects(), start);
    }

    #[test]
    fn dup_shares_payload_and_object_identity() {
        let _guard = global_lock();
        let start = live_objects();
        arm_file_hook();

        let mut parent = HandleTable::new();
        let handle = insert_new_with_payload(
            &mut parent,
            ObjectKind::File,
            0x0900,
            Rights::READ | Rights::DUPLICATE,
        )
        .unwrap();
        let object = resolve_handle(&parent, handle, Rights::READ)
            .unwrap()
            .object;

        let mut child = HandleTable::new();
        let child_handle = duplicate_handle(&mut parent, &mut child, handle, Rights::READ).unwrap();
        assert_eq!(child_handle.raw(), 0x0001_0001);
        let child_object = resolve_handle(&child, child_handle, Rights::READ)
            .unwrap()
            .object;
        // dup/传递共享同一个对象与同一个负载，只增加对象引用。
        assert_eq!(child_object, object);
        assert_eq!(payload(child_object), Some(0x0900));
        assert_eq!(object_refs(object), Some(2));

        // 关闭其中一个句柄不触发钩子。
        assert_eq!(close_handle(&mut child, child_handle).unwrap(), object);
        assert_eq!(hook_calls(), 0);
        assert_eq!(object_refs(object), Some(1));

        // 最后一个句柄关闭才触发。
        assert_eq!(close_handle(&mut parent, handle).unwrap(), object);
        assert_eq!(hook_calls(), 1);
        assert_eq!(last_payload(), 0x0900);
        assert_eq!(live_objects(), start);
    }

    // -- M5c2：按 payload 反向关闭（munmap 路径） ----------------------------

    #[test]
    fn close_payload_closes_the_matching_handle() {
        let _guard = global_lock();
        let start = live_objects();
        arm_file_hook();

        let mut table = HandleTable::new();
        let handle =
            insert_new_with_payload(&mut table, ObjectKind::File, 0x2200, Rights::READ).unwrap();
        let object = resolve_handle(&table, handle, Rights::READ).unwrap().object;

        // 找到并关闭 ⇒ Ok(true)，并且走的是正常关闭路径：钩子触发一次。
        assert_eq!(
            close_payload(&mut table, ObjectKind::File, 0x2200),
            Ok(true)
        );
        assert_eq!(hook_calls(), 1);
        assert_eq!(last_payload(), 0x2200);
        assert_eq!(object_kind(object), None);
        assert!(table.is_empty());
        // 旧句柄已失效，不会留下悬空对象。
        assert_eq!(
            resolve_handle(&table, handle, Rights::READ),
            Err(ObjectError::BadHandle)
        );
        assert_eq!(live_objects(), start);
    }

    #[test]
    fn close_payload_closes_a_vm_object_handle() {
        let _guard = global_lock();
        let start = live_objects();
        arm_file_hook();

        let mut table = HandleTable::new();
        let handle = insert_new_with_payload(
            &mut table,
            ObjectKind::VmObject,
            0x5500,
            Rights::READ | Rights::MAP,
        )
        .unwrap();
        let object = resolve_handle(&table, handle, Rights::READ).unwrap().object;
        assert_eq!(payload(object), Some(0x5500));

        assert_eq!(
            close_payload(&mut table, ObjectKind::VmObject, 0x5500),
            Ok(true)
        );
        assert_eq!(object_kind(object), None);
        // 没有注册 VmObject 的钩子，File 钩子不得被误触发。
        assert!(!has_destroy_hook(ObjectKind::VmObject));
        assert_eq!(hook_calls(), 0);
        assert_eq!(live_objects(), start);
    }

    #[test]
    fn close_payload_reports_missing_match_without_changing_the_table() {
        let _guard = global_lock();
        let start = live_objects();
        arm_file_hook();

        let mut table = HandleTable::new();
        let handle =
            insert_new_with_payload(&mut table, ObjectKind::File, 0x2300, Rights::READ).unwrap();
        let object = resolve_handle(&table, handle, Rights::READ).unwrap().object;

        // payload 不匹配 ⇒ Ok(false)，表与对象保持不变。
        assert_eq!(
            close_payload(&mut table, ObjectKind::File, 0x2301),
            Ok(false)
        );
        // kind 不匹配 ⇒ Ok(false)。
        assert_eq!(
            close_payload(&mut table, ObjectKind::Random, 0x2300),
            Ok(false)
        );
        assert_eq!(hook_calls(), 0);
        assert_eq!(table.len(), 1);
        assert_eq!(object_kind(object), Some(ObjectKind::File));

        // 真正匹配时才关闭并清理。
        assert_eq!(
            close_payload(&mut table, ObjectKind::File, 0x2300),
            Ok(true)
        );
        assert_eq!(hook_calls(), 1);
        assert_eq!(live_objects(), start);
    }

    #[test]
    fn close_payload_ignores_stale_handles() {
        let _guard = global_lock();
        let start = live_objects();
        arm_file_hook();

        let mut table = HandleTable::new();
        let stale =
            insert_new_with_payload(&mut table, ObjectKind::File, 0x3300, Rights::READ).unwrap();
        let object = resolve_handle(&table, stale, Rights::READ).unwrap().object;
        assert_eq!(close_handle(&mut table, stale).unwrap(), object);
        assert_eq!(hook_calls(), 1);

        // 槽位已空且代次递增：旧负载不应再匹配到任何活跃句柄。
        assert_eq!(
            close_payload(&mut table, ObjectKind::File, 0x3300),
            Ok(false)
        );
        assert_eq!(hook_calls(), 1);

        // 槽位被新对象复用后，旧 payload 仍然匹配不到；代次由 close 校验。
        let _fresh =
            insert_new_with_payload(&mut table, ObjectKind::File, 0x3301, Rights::READ).unwrap();
        assert_eq!(
            close_payload(&mut table, ObjectKind::File, 0x3300),
            Ok(false)
        );
        assert_eq!(hook_calls(), 1);
        // 新 payload 可以正常关闭。
        assert_eq!(
            close_payload(&mut table, ObjectKind::File, 0x3301),
            Ok(true)
        );
        assert_eq!(hook_calls(), 2);
        assert_eq!(live_objects(), start);
    }

    #[test]
    fn close_payload_shares_the_last_reference_with_dup() {
        let _guard = global_lock();
        let start = live_objects();
        arm_file_hook();

        let mut parent = HandleTable::new();
        let handle = insert_new_with_payload(
            &mut parent,
            ObjectKind::File,
            0x4400,
            Rights::READ | Rights::DUPLICATE,
        )
        .unwrap();
        let object = resolve_handle(&parent, handle, Rights::READ)
            .unwrap()
            .object;

        let mut child = HandleTable::new();
        let child_handle = duplicate_handle(&mut parent, &mut child, handle, Rights::READ).unwrap();
        // dup 落在子表槽位 0、代次 1（冻结编码）；两张表各持一个句柄。
        assert_eq!(child_handle.raw(), 0x0001_0001);
        assert_eq!(child.len(), 1);
        assert_eq!(parent.len(), 1);
        assert_eq!(object_refs(object), Some(2));

        // 先按 payload 关闭子表里的副本：引用还剩 1，钩子不触发。
        assert_eq!(
            close_payload(&mut child, ObjectKind::File, 0x4400),
            Ok(true)
        );
        assert_eq!(hook_calls(), 0);
        assert_eq!(object_refs(object), Some(1));
        // 子表里已没有匹配句柄。
        assert_eq!(
            close_payload(&mut child, ObjectKind::File, 0x4400),
            Ok(false)
        );

        // 最后一份引用被关闭时才触发钩子一次。
        assert_eq!(
            close_payload(&mut parent, ObjectKind::File, 0x4400),
            Ok(true)
        );
        assert_eq!(hook_calls(), 1);
        assert_eq!(last_payload(), 0x4400);
        assert_eq!(object_kind(object), None);
        assert_eq!(live_objects(), start);
    }

    // -- M5c3：目录监视对象（Watch） ----------------------------------------

    static WATCH_HOOK_CALLS: std::sync::atomic::AtomicUsize =
        std::sync::atomic::AtomicUsize::new(0);
    static WATCH_HOOK_KIND: std::sync::atomic::AtomicU8 = std::sync::atomic::AtomicU8::new(0);
    static WATCH_HOOK_PAYLOAD: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

    /// 记录 Watch 销毁钩子的 `(kind, payload)`；调用方必须持有 `global_lock()`。
    fn record_watch_destroy(kind: ObjectKind, payload: u64) {
        WATCH_HOOK_CALLS.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        WATCH_HOOK_KIND.store(kind as u8, std::sync::atomic::Ordering::SeqCst);
        WATCH_HOOK_PAYLOAD.store(payload, std::sync::atomic::Ordering::SeqCst);
    }

    fn watch_hook_calls() -> usize {
        WATCH_HOOK_CALLS.load(std::sync::atomic::Ordering::SeqCst)
    }

    fn watch_hook_kind() -> u8 {
        WATCH_HOOK_KIND.load(std::sync::atomic::Ordering::SeqCst)
    }

    fn watch_hook_payload() -> u64 {
        WATCH_HOOK_PAYLOAD.load(std::sync::atomic::Ordering::SeqCst)
    }

    /// 注册 Watch 的类型感知钩子并清零计数；调用方必须持有 `global_lock()`。
    fn arm_watch_hook() {
        reset_destroy_hooks();
        register_destroy_hook_with_kind(ObjectKind::Watch, record_watch_destroy).unwrap();
        WATCH_HOOK_CALLS.store(0, std::sync::atomic::Ordering::SeqCst);
        WATCH_HOOK_KIND.store(0, std::sync::atomic::Ordering::SeqCst);
        WATCH_HOOK_PAYLOAD.store(0, std::sync::atomic::Ordering::SeqCst);
    }

    #[test]
    fn watch_payload_packs_owner_and_id_exactly() {
        assert_eq!(WATCH_PAYLOAD_OWNER_SHIFT, 32);
        assert_eq!(watch_payload(0, 0), 0);
        assert_eq!(watch_payload(0, 7), 7);
        assert_eq!(watch_payload(7, 0), 7u64 << WATCH_PAYLOAD_OWNER_SHIFT);
        let packed = watch_payload(0x1234_5678, 0x9ABC_DEF0);
        assert_eq!(packed >> WATCH_PAYLOAD_OWNER_SHIFT, 0x1234_5678);
        assert_eq!(packed as u32, 0x9ABC_DEF0);
        assert_eq!(watch_payload_owner(packed), 0x1234_5678);
        assert_eq!(watch_payload_id(packed), 0x9ABC_DEF0);
        // 字段相互独立，不串位。
        assert_eq!(watch_payload_owner(u64::MAX), u32::MAX);
        assert_eq!(watch_payload_id(u64::MAX), u32::MAX);
    }

    #[test]
    fn watch_objects_carry_owner_and_id() {
        let mut objects = ObjectTable::new();
        let payload = watch_payload(3, 11);
        let watch = objects
            .create_with_payload(ObjectKind::Watch, payload)
            .unwrap();
        assert_eq!(objects.kind(watch), Some(ObjectKind::Watch));
        assert_eq!(objects.payload(watch), Some(payload));
        assert_eq!(objects.refs(watch), Some(1));
        assert_eq!(watch_payload_owner(payload), 3);
        assert_eq!(watch_payload_id(payload), 11);
    }

    #[test]
    fn watch_destroy_hook_receives_kind_and_payload_once() {
        let _guard = global_lock();
        let start = live_objects();
        arm_watch_hook();

        let mut table = HandleTable::new();
        let payload = watch_payload(5, 12);
        let handle =
            insert_new_with_payload(&mut table, ObjectKind::Watch, payload, Rights::READ).unwrap();
        let object = resolve_handle(&table, handle, Rights::READ).unwrap().object;
        assert_eq!(object_refs(object), Some(1));
        assert_eq!(watch_hook_calls(), 0);

        // 最后一个句柄关闭：钩子收到 (Watch, payload) 恰好一次。
        assert_eq!(close_handle(&mut table, handle).unwrap(), object);
        assert_eq!(watch_hook_calls(), 1);
        assert_eq!(watch_hook_kind(), ObjectKind::Watch as u8);
        assert_eq!(watch_hook_payload(), payload);
        assert_eq!(object_kind(object), None);

        // 重复关闭是非法句柄，不会再次触发钩子。
        assert_eq!(
            close_handle(&mut table, handle),
            Err(ObjectError::BadHandle)
        );
        assert_eq!(watch_hook_calls(), 1);
        assert_eq!(live_objects(), start);
    }

    #[test]
    fn watch_dup_shares_the_last_reference() {
        let _guard = global_lock();
        let start = live_objects();
        arm_watch_hook();

        let payload = watch_payload(9, 4);
        let mut parent = HandleTable::new();
        let handle = insert_new_with_payload(
            &mut parent,
            ObjectKind::Watch,
            payload,
            Rights::READ | Rights::DUPLICATE,
        )
        .unwrap();
        let object = resolve_handle(&parent, handle, Rights::READ)
            .unwrap()
            .object;

        let mut child = HandleTable::new();
        let child_handle = duplicate_handle(&mut parent, &mut child, handle, Rights::READ).unwrap();
        assert_eq!(
            resolve_handle(&child, child_handle, Rights::READ)
                .unwrap()
                .object,
            object
        );
        assert_eq!(object_refs(object), Some(2));

        // dup 只增加对象引用；关闭副本不触发钩子。
        assert_eq!(close_handle(&mut child, child_handle).unwrap(), object);
        assert_eq!(watch_hook_calls(), 0);
        assert_eq!(object_refs(object), Some(1));

        // 按 payload 关闭最后一份引用：钩子恰好一次，payload 原样传入。
        assert_eq!(
            close_payload_wide(&mut parent, ObjectKind::Watch, payload),
            Ok(true)
        );
        assert_eq!(watch_hook_calls(), 1);
        assert_eq!(watch_hook_kind(), ObjectKind::Watch as u8);
        assert_eq!(watch_hook_payload(), payload);
        assert_eq!(live_objects(), start);
    }

    #[test]
    fn watch_close_payload_ignores_stale_handles() {
        let _guard = global_lock();
        let start = live_objects();
        arm_watch_hook();

        let mut table = HandleTable::new();
        let stale_payload = watch_payload(2, 1);
        let stale =
            insert_new_with_payload(&mut table, ObjectKind::Watch, stale_payload, Rights::READ)
                .unwrap();
        let object = resolve_handle(&table, stale, Rights::READ).unwrap().object;
        assert_eq!(close_handle(&mut table, stale).unwrap(), object);
        assert_eq!(watch_hook_calls(), 1);

        // 已关闭的负载不能再被反向关闭。
        assert_eq!(
            close_payload_wide(&mut table, ObjectKind::Watch, stale_payload),
            Ok(false)
        );
        assert_eq!(watch_hook_calls(), 1);

        // 槽位复用后旧负载仍匹配不到；新负载可以正常关闭。
        let fresh_payload = watch_payload(2, 2);
        let _fresh =
            insert_new_with_payload(&mut table, ObjectKind::Watch, fresh_payload, Rights::READ)
                .unwrap();
        assert_eq!(
            close_payload_wide(&mut table, ObjectKind::Watch, stale_payload),
            Ok(false)
        );
        assert_eq!(watch_hook_calls(), 1);
        assert_eq!(
            close_payload_wide(&mut table, ObjectKind::Watch, fresh_payload),
            Ok(true)
        );
        assert_eq!(watch_hook_calls(), 2);
        assert_eq!(live_objects(), start);
    }

    #[test]
    fn watch_insert_failure_fires_the_hook_and_keeps_counts() {
        let _guard = global_lock();
        let start = live_objects();
        arm_watch_hook();

        let mut table = HandleTable::new();
        for _ in 0..MAX_HANDLE_TABLE_ENTRIES {
            insert_new(&mut table, ObjectKind::Console, Rights::READ).unwrap();
        }
        let before = live_objects();
        let payload = watch_payload(6, 8);
        assert_eq!(
            insert_new_with_payload(&mut table, ObjectKind::Watch, payload, Rights::READ),
            Err(ObjectError::HandleTableFull)
        );
        // 插入失败时初始引用被释放，钩子关闭负载对应的资源，对象不泄漏。
        assert_eq!(watch_hook_calls(), 1);
        assert_eq!(watch_hook_kind(), ObjectKind::Watch as u8);
        assert_eq!(watch_hook_payload(), payload);
        assert_eq!(live_objects(), before);

        assert_eq!(clear_handle_table(&mut table), MAX_HANDLE_TABLE_ENTRIES);
        assert_eq!(live_objects(), start);
    }

    #[test]
    fn watch_hook_signatures_do_not_mix() {
        let _guard = global_lock();
        reset_destroy_hooks();

        // 同类型 + 同签名 + 同函数：幂等。
        register_destroy_hook_with_kind(ObjectKind::Watch, record_watch_destroy).unwrap();
        register_destroy_hook_with_kind(ObjectKind::Watch, record_watch_destroy).unwrap();
        assert!(has_destroy_hook(ObjectKind::Watch));
        // 同类型换用 fn(u64) 签名：明确拒绝，不覆盖。
        assert_eq!(
            register_destroy_hook(ObjectKind::Watch, record_file_destroy),
            Err(ObjectError::HookConflict)
        );
        // 同类型换用三参签名同样被拒绝。
        assert_eq!(
            register_destroy_hook_with_object(ObjectKind::Watch, record_object_destroy),
            Err(ObjectError::HookConflict)
        );

        // 反向：先注册 fn(u64)，再换类型感知签名同样被拒绝。
        reset_destroy_hooks();
        register_destroy_hook(ObjectKind::Watch, record_file_destroy).unwrap();
        assert_eq!(
            register_destroy_hook_with_kind(ObjectKind::Watch, record_watch_destroy),
            Err(ObjectError::HookConflict)
        );
        reset_destroy_hooks();
    }

    /// M6a1 三参钩子：记录 `(kind, payload, object)`，供 ObjectAware 测试使用。
    fn record_object_destroy(kind: ObjectKind, payload: u64, object: ObjectId) {
        OBJECT_HOOK_CALLS.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        OBJECT_HOOK_KIND.store(kind as u8, std::sync::atomic::Ordering::SeqCst);
        OBJECT_HOOK_PAYLOAD.store(payload, std::sync::atomic::Ordering::SeqCst);
        OBJECT_HOOK_ID.store(object, std::sync::atomic::Ordering::SeqCst);
    }

    static OBJECT_HOOK_CALLS: std::sync::atomic::AtomicUsize =
        std::sync::atomic::AtomicUsize::new(0);
    static OBJECT_HOOK_KIND: std::sync::atomic::AtomicU8 = std::sync::atomic::AtomicU8::new(0);
    static OBJECT_HOOK_PAYLOAD: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    static OBJECT_HOOK_ID: std::sync::atomic::AtomicU16 = std::sync::atomic::AtomicU16::new(0);

    #[test]
    fn object_aware_hook_receives_the_destroyed_object_id() {
        let _guard = global_lock();
        let start = live_objects();
        reset_destroy_hooks();
        register_destroy_hook_with_object(ObjectKind::Event, record_object_destroy).unwrap();
        OBJECT_HOOK_CALLS.store(0, std::sync::atomic::Ordering::SeqCst);

        let mut table = HandleTable::new();
        let payload = 7;
        let handle = insert_new_with_payload(
            &mut table,
            ObjectKind::Event,
            payload,
            Rights::READ | Rights::WAIT,
        )
        .unwrap();
        let object = resolve_handle(&table, handle, Rights::READ).unwrap().object;

        // 最后一个句柄关闭：三参钩子拿到类型、负载与**同一个**对象 ID。
        assert_eq!(close_handle(&mut table, handle).unwrap(), object);
        assert_eq!(
            OBJECT_HOOK_CALLS.load(std::sync::atomic::Ordering::SeqCst),
            1
        );
        assert_eq!(
            OBJECT_HOOK_KIND.load(std::sync::atomic::Ordering::SeqCst),
            ObjectKind::Event as u8
        );
        assert_eq!(
            OBJECT_HOOK_PAYLOAD.load(std::sync::atomic::Ordering::SeqCst),
            payload
        );
        assert_eq!(
            OBJECT_HOOK_ID.load(std::sync::atomic::Ordering::SeqCst),
            object
        );
        assert_eq!(live_objects(), start);
        reset_destroy_hooks();
    }

    /// M7b：Socket/NetNamespace 的负载、引用计数与对象感知销毁钩子语义。
    ///
    /// object 层不引用 `net`：Socket 负载按 `net::SocketId` 的原始 `u32` 值
    /// 存放（低 32 位），NetNamespace 本阶段固定为 `0`。两者都必须能走
    /// `create_with_payload` / `insert_new_with_payload` / `acquire`/`release`
    /// 与 `ObjectAware` 钩子，且钩子拿到的是**同一个** [`ObjectId`]。
    #[test]
    fn socket_and_net_namespace_payloads_round_trip_through_the_object_layer() {
        let _guard = global_lock();
        let start = live_objects();
        reset_destroy_hooks();
        register_destroy_hook_with_object(ObjectKind::Socket, record_object_destroy).unwrap();
        register_destroy_hook_with_object(ObjectKind::NetNamespace, record_object_destroy).unwrap();

        // -- Socket：负载是 net::SocketId 的原始 u32 值 ---------------------
        let raw_socket: u32 = 0x4D37_0001;
        let mut table = HandleTable::new();
        let handle = insert_new_with_payload(
            &mut table,
            ObjectKind::Socket,
            u64::from(raw_socket),
            Rights::READ | Rights::WRITE | Rights::WAIT,
        )
        .unwrap();
        let socket = resolve_handle(&table, handle, Rights::READ).unwrap().object;
        assert_eq!(payload(socket), Some(u64::from(raw_socket)));
        // 插入后只剩句柄那一份引用：acquire/release 一进一出。
        assert_eq!(acquire_object(socket), Ok(2));
        assert_eq!(release_object(socket), Ok(1));

        OBJECT_HOOK_CALLS.store(0, std::sync::atomic::Ordering::SeqCst);
        assert_eq!(close_handle(&mut table, handle).unwrap(), socket);
        assert_eq!(
            OBJECT_HOOK_CALLS.load(std::sync::atomic::Ordering::SeqCst),
            1
        );
        assert_eq!(
            OBJECT_HOOK_KIND.load(std::sync::atomic::Ordering::SeqCst),
            ObjectKind::Socket as u8
        );
        assert_eq!(
            OBJECT_HOOK_PAYLOAD.load(std::sync::atomic::Ordering::SeqCst),
            u64::from(raw_socket)
        );
        assert_eq!(
            OBJECT_HOOK_ID.load(std::sync::atomic::Ordering::SeqCst),
            socket
        );
        assert_eq!(live_objects(), start);

        // -- NetNamespace：本阶段负载固定 0，权限不含 WAIT/MAP --------------
        let namespace = create_with_payload(ObjectKind::NetNamespace, 0).unwrap();
        assert_eq!(payload(namespace), Some(0));
        assert_eq!(acquire_object(namespace), Ok(2));
        assert_eq!(release_object(namespace), Ok(1));
        OBJECT_HOOK_CALLS.store(0, std::sync::atomic::Ordering::SeqCst);
        assert_eq!(release_object(namespace), Ok(0));
        assert_eq!(
            OBJECT_HOOK_CALLS.load(std::sync::atomic::Ordering::SeqCst),
            1
        );
        assert_eq!(
            OBJECT_HOOK_KIND.load(std::sync::atomic::Ordering::SeqCst),
            ObjectKind::NetNamespace as u8
        );
        assert_eq!(
            OBJECT_HOOK_PAYLOAD.load(std::sync::atomic::Ordering::SeqCst),
            0
        );
        assert_eq!(
            OBJECT_HOOK_ID.load(std::sync::atomic::Ordering::SeqCst),
            namespace
        );
        assert_eq!(live_objects(), start);
        reset_destroy_hooks();
    }

    // -- M6a：对象创建的初始权限策略 -----------------------------------------

    /// M6a/M6a2 的可等待 IPC 类型只允许其文档化的初始权限集合。
    #[test]
    fn ipc_kinds_allow_only_their_documented_initial_rights() {
        let standard = Rights::READ | Rights::WRITE | Rights::WAIT | Rights::DUPLICATE;
        for kind in [
            ObjectKind::Event,
            ObjectKind::EventPair,
            ObjectKind::Timer,
            ObjectKind::Channel,
            ObjectKind::Port,
            ObjectKind::EventSubscription,
        ] {
            assert_eq!(initial_rights_bound(kind), standard);
            assert_eq!(
                check_initial_rights(kind, Rights::WAIT | Rights::WRITE),
                Ok(())
            );
            assert_eq!(check_initial_rights(kind, standard), Ok(()));
            for invalid in [
                Rights::NONE,
                Rights::ALL,
                Rights::MAP,
                Rights(0x80),
                Rights(0xC0),
            ] {
                assert_eq!(
                    check_initial_rights(kind, invalid),
                    Err(ObjectError::InvalidRights),
                    "{:?}",
                    kind
                );
            }
        }

        // SharedMemory 需要 MAP 而不是 WAIT。
        let shared_bound = Rights::READ | Rights::WRITE | Rights::MAP | Rights::DUPLICATE;
        assert_eq!(initial_rights_bound(ObjectKind::SharedMemory), shared_bound);
        assert_eq!(
            check_initial_rights(ObjectKind::SharedMemory, shared_bound),
            Ok(())
        );
        assert_eq!(
            check_initial_rights(
                ObjectKind::SharedMemory,
                Rights::READ | Rights::WRITE | Rights::MAP
            ),
            Ok(())
        );
        for invalid in [
            Rights::NONE,
            Rights::ALL,
            Rights::WAIT,
            Rights::READ | Rights::WAIT,
            Rights(0x80),
        ] {
            assert_eq!(
                check_initial_rights(ObjectKind::SharedMemory, invalid),
                Err(ObjectError::InvalidRights)
            );
        }

        // M6c Display 与 SharedMemory 同界：映射需要 MAP，不需要 WAIT。
        assert_eq!(initial_rights_bound(ObjectKind::Display), shared_bound);
        assert_eq!(
            check_initial_rights(ObjectKind::Display, shared_bound),
            Ok(())
        );
        for invalid in [
            Rights::NONE,
            Rights::ALL,
            Rights::WAIT,
            Rights::READ | Rights::WAIT,
            Rights(0x80),
        ] {
            assert_eq!(
                check_initial_rights(ObjectKind::Display, invalid),
                Err(ObjectError::InvalidRights)
            );
        }

        // M6c Input 只读、可等待：不允许 WRITE/MAP。
        let input_bound = Rights::READ | Rights::WAIT | Rights::DUPLICATE;
        assert_eq!(initial_rights_bound(ObjectKind::Input), input_bound);
        assert_eq!(check_initial_rights(ObjectKind::Input, input_bound), Ok(()));
        assert_eq!(
            check_initial_rights(ObjectKind::Input, Rights::READ | Rights::WAIT),
            Ok(())
        );
        for invalid in [
            Rights::NONE,
            Rights::ALL,
            Rights::WRITE,
            Rights::MAP,
            Rights::READ | Rights::WRITE,
            Rights(0x80),
        ] {
            assert_eq!(
                check_initial_rights(ObjectKind::Input, invalid),
                Err(ObjectError::InvalidRights)
            );
        }

        // M7b Socket 与标准可等待 IPC 同界：收发 + WAIT，不允许 MAP。
        assert_eq!(initial_rights_bound(ObjectKind::Socket), standard);
        assert_eq!(
            check_initial_rights(ObjectKind::Socket, Rights::READ | Rights::WRITE),
            Ok(())
        );
        assert_eq!(check_initial_rights(ObjectKind::Socket, standard), Ok(()));
        for invalid in [
            Rights::NONE,
            Rights::ALL,
            Rights::MAP,
            Rights::READ | Rights::MAP,
            Rights(0x80),
        ] {
            assert_eq!(
                check_initial_rights(ObjectKind::Socket, invalid),
                Err(ObjectError::InvalidRights)
            );
        }

        // M7b NetNamespace：读写 + 复制，不允许 WAIT/MAP。
        let namespace_bound = Rights::READ | Rights::WRITE | Rights::DUPLICATE;
        assert_eq!(
            initial_rights_bound(ObjectKind::NetNamespace),
            namespace_bound
        );
        assert_eq!(
            check_initial_rights(ObjectKind::NetNamespace, namespace_bound),
            Ok(())
        );
        assert_eq!(
            check_initial_rights(ObjectKind::NetNamespace, Rights::READ | Rights::WRITE),
            Ok(())
        );
        for invalid in [
            Rights::NONE,
            Rights::ALL,
            Rights::WAIT,
            Rights::READ | Rights::WAIT,
            Rights::MAP,
            Rights(0x80),
        ] {
            assert_eq!(
                check_initial_rights(ObjectKind::NetNamespace, invalid),
                Err(ObjectError::InvalidRights)
            );
        }
    }

    /// 旧类型（M4/M5）的初始权限上界仍是 ALL：既有成功调用不受影响。
    #[test]
    fn legacy_kinds_keep_their_unrestricted_initial_rights() {
        for kind in [
            ObjectKind::Console,
            ObjectKind::Random,
            ObjectKind::Process,
            ObjectKind::File,
            ObjectKind::VmObject,
            ObjectKind::Watch,
        ] {
            assert_eq!(initial_rights_bound(kind), Rights::ALL);
            assert_eq!(check_initial_rights(kind, Rights::ALL), Ok(()));
            assert_eq!(
                check_initial_rights(kind, Rights::READ | Rights::WRITE),
                Ok(())
            );
            // 空权限与未知位对旧类型同样非法；这不改变任何既有成功调用。
            assert_eq!(
                check_initial_rights(kind, Rights::NONE),
                Err(ObjectError::InvalidRights)
            );
            assert_eq!(
                check_initial_rights(kind, Rights(0x80)),
                Err(ObjectError::InvalidRights)
            );
        }
    }

    /// 创建路径的端到端回归：合法 IPC 权限可建，非法权限在创建前被拒。
    #[test]
    fn insert_new_accepts_legacy_rights_and_rejects_invalid_ipc_rights() {
        let _guard = global_lock();
        let start = live_objects();
        let mut table = HandleTable::new();

        insert_new(
            &mut table,
            ObjectKind::Console,
            Rights::READ | Rights::WRITE,
        )
        .unwrap();
        insert_new(&mut table, ObjectKind::File, Rights::ALL).unwrap();
        insert_new_with_payload(
            &mut table,
            ObjectKind::Event,
            1,
            Rights::WAIT | Rights::WRITE,
        )
        .unwrap();
        assert_eq!(
            insert_new_with_payload(&mut table, ObjectKind::Event, 2, Rights::NONE),
            Err(ObjectError::InvalidRights)
        );
        assert_eq!(
            insert_new_with_payload(&mut table, ObjectKind::Timer, 3, Rights::MAP),
            Err(ObjectError::InvalidRights)
        );
        // 合法的 IPC 集合仍可继续创建（策略没有误伤）。
        insert_new_with_payload(
            &mut table,
            ObjectKind::EventPair,
            4,
            Rights::READ | Rights::WAIT,
        )
        .unwrap();
        assert_eq!(table.len(), 4);

        clear_handle_table(&mut table);
        assert_eq!(live_objects(), start);
    }
}
