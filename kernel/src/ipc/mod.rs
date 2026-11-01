//! 原生 IPC 内核对象：Event、EventPair、Timer（M6a1）与 Channel、Port（M6a2）。
//!
//! 设计约束（与 `object` 层一致）：
//!
//! - **固定容量、无堆**：每种对象一张固定大小的静态表，容量见各子模块常量。
//!   创建失败返回 [`IpcError::TableFull`]，不尝试扩容、不回退到堆。
//! - **对象表只保存不透明负载**：`object::ObjectKind::{Event, EventPair, Timer}`
//!   的 payload 是本模块表的 `slot + 1`（0 保留为非法值）。Channel/Port 的端点
//!   对象不编码槽位，状态表按 [`object::ObjectId`] 认端点（见各子模块）。
//! - **IF=0 单 CPU 串行化**：所有表访问都经过 [`IrqCell`]，在目标平台上于关中断
//!   区间内完成；宿主测试下不做中断屏蔽，因此测试必须自行串行化（见
//!   `crate::object::test_lock`）。
//! - **销毁钩子**：对象最后一个引用归零时，对象层调用以
//!   [`object::register_destroy_hook_with_object`] 注册的钩子，本模块据此先唤醒
//!   等待者（`WakeReason::Destroyed`/`PeerClosed`）再释放表槽。钩子在对象表锁内
//!   执行，**不得**回调对象表；因此队列里被转移对象的引用释放统一安排在本模块的
//!   关中断区间之外（见 [`release_message_objects`]）。
//! - **消息队列引用所有权**：`send` 的 objects 引用由调用者先 acquire（句柄持有
//!   的引用之外额外一份）；入队后归队列所有。`peek` 不弹出也不释放，`commit`
//!   按 sequence 移除并释放队列自己那份引用；队列被丢弃（对端关闭/销毁）时同样
//!   释放。接收方为插入句柄需要再次 acquire，因此接收者最终拥有自己的引用。
//!
//! 中断上下文约束：只有 [`timer::on_tick`] 允许在硬中断顶半调用；它不分配、
//! 不打印、不访问对象表，只更新 Timer 表并调用 `process::wake_object`。

use core::cell::UnsafeCell;

use crate::object::{self, Handle, HandleTable, ObjectError, ObjectId, ObjectKind, Rights};
use crate::sync::IrqSpinLock;

pub mod channel;
pub mod display;
pub mod epoll;
pub mod event;
pub mod eventfd;
pub mod input;
pub mod port;
pub mod shm;
pub mod signalfd;
pub mod subscription;
pub mod timer;
pub mod timerfd;

/// IPC 层的统一错误。
///
/// syscall 层负责把它映射到 `native_abi` 的稳定状态码（例如 `TableFull` →
/// `QUOTA`、`WrongKind` → `BAD_HANDLE`、`WouldBlock` → `WOULD_BLOCK`、
/// 其余参数类错误 → `INVALID_ARGUMENT`）。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum IpcError {
    /// 固定表已满（Event 32 / EventPair 16 / Timer 16 / Channel 2 / Port 1）。
    TableFull,
    /// 负载不是本模块分配的值（0、越界或对应槽未使用）。
    InvalidPayload,
    /// EventPair 端点不是 0 或 1。
    InvalidEndpoint,
    /// Timer 已经绑定过对象；重复 bind 视为调用方错误。
    AlreadyBound,
    /// Timer 尚未绑定对象就尝试 arm。
    NotBound,
    /// Timer 未处于 armed 状态却要求取消/等待（仅显式 API 使用）。
    NotArmed,
    /// 对象类型不是本模块管理的类型。
    WrongKind,
    /// 计数或时间运算溢出（保留给后续 multi-shot 语义）。
    Overflow,
    /// 消息队列已满：非阻塞发送返回它，调用方稍后重试。
    WouldBlock,
    /// 对端已经关闭：发送或无消息接收都会返回它。
    PeerClosed,
    /// 该对象不是通道/端口的接收端。
    NotReceiver,
    /// 该对象不是端口的发送端。
    NotSender,
    /// 端点对象已经注册到另一个通道/端口，不能重复链接。
    AlreadyLinked,
    /// `commit` 给出的 sequence 不在该接收队列里。
    InvalidSequence,
    /// 消息数据超过固定上限（64 字节）。
    MessageTooLarge,
    /// 消息携带的句柄超过固定上限（2 个）。
    TooManyHandles,
    /// 该能力尚未实现（例如 M6a2 的 EventSubscription 轮询占位）。
    NotSupported,
    /// 对象层返回的错误（句柄/配额/权限等）。
    Object(ObjectError),
}

impl IpcError {
    /// 稳定字符串，供诊断输出使用（不得用于 ABI 判定）。
    pub const fn as_str(self) -> &'static str {
        match self {
            IpcError::TableFull => "ipc-table-full",
            IpcError::InvalidPayload => "ipc-invalid-payload",
            IpcError::InvalidEndpoint => "ipc-invalid-endpoint",
            IpcError::AlreadyBound => "ipc-already-bound",
            IpcError::NotBound => "ipc-not-bound",
            IpcError::NotArmed => "ipc-not-armed",
            IpcError::WrongKind => "ipc-wrong-kind",
            IpcError::Overflow => "ipc-overflow",
            IpcError::WouldBlock => "ipc-would-block",
            IpcError::PeerClosed => "ipc-peer-closed",
            IpcError::NotReceiver => "ipc-not-receiver",
            IpcError::NotSender => "ipc-not-sender",
            IpcError::AlreadyLinked => "ipc-already-linked",
            IpcError::InvalidSequence => "ipc-invalid-sequence",
            IpcError::MessageTooLarge => "ipc-message-too-large",
            IpcError::TooManyHandles => "ipc-too-many-handles",
            IpcError::NotSupported => "ipc-not-supported",
            IpcError::Object(_) => "ipc-object-error",
        }
    }
}

/// 跨表安全的静态单元：`sync::IrqSpinLock` + `UnsafeCell` 负载。
///
/// 目标平台与宿主测试都真正互斥：`sync::IrqSpinLock` 先关本地中断再自旋 CAS，因此
/// SMP 上第二个 CPU 会等待锁释放，而不是把 `&mut T` 别名成未定义行为；宿主测试下
/// 关中断是空操作，但自旋仍然生效。**不得**在同一 `IrqCell` 的闭包内再次进入同一个
/// `IrqCell`（会自旋死锁，且在死锁前先触发下面的测试断言）；也**不得**在持有某个
/// `IrqCell` 时调用会读取其它 IPC 表或对象表/进程表的函数（见各模块的锁外唤醒约定）。
pub(crate) struct IrqCell<T> {
    value: UnsafeCell<T>,
    lock: IrqSpinLock,
    #[cfg(test)]
    busy: core::sync::atomic::AtomicBool,
}

// 安全性：所有访问都通过 `with`，锁保证任意时刻只有一个 `&mut T` 生效。
unsafe impl<T> Sync for IrqCell<T> {}

impl<T> IrqCell<T> {
    pub(crate) const fn new(value: T) -> Self {
        IrqCell {
            value: UnsafeCell::new(value),
            lock: IrqSpinLock::new(),
            #[cfg(test)]
            busy: core::sync::atomic::AtomicBool::new(false),
        }
    }

    pub(crate) fn with<R>(&self, f: impl FnOnce(&mut T) -> R) -> R {
        #[cfg(test)]
        {
            use core::sync::atomic::Ordering;
            assert!(
                !self.busy.swap(true, Ordering::AcqRel),
                "IPC table re-entered while its lock was held"
            );
            // 跨表嵌套检测：持有任一 IPC 表锁时不得进入另一张 IPC 表（否则 SMP/中断下
            // 会出现锁序反转）。默认只在显式开启时断言（`NestingGuard`），因为宿主测试
            // 的注入缝（假帧池等）也复用 `IrqCell`，并非 IPC 表。
            IPC_LOCK_DEPTH.with(|depth| {
                if IPC_NESTING_CHECK.with(|flag| flag.get()) {
                    assert_eq!(
                        depth.get(),
                        0,
                        "IPC table locked while another IPC table was held"
                    );
                }
                depth.set(depth.get() + 1);
            });
        }

        let guard = self.lock.lock();
        // 安全性：见上面的 Sync 说明；这里不跨调用保留该可变引用。
        let result = f(unsafe { &mut *self.value.get() });
        drop(guard);

        #[cfg(test)]
        {
            IPC_LOCK_DEPTH.with(|depth| depth.set(depth.get().saturating_sub(1)));
            self.busy
                .store(false, core::sync::atomic::Ordering::Release);
        }

        result
    }
}

// 宿主测试专用：当前线程已持有的 IPC 表锁层数（正常应回到 0）。
#[cfg(test)]
std::thread_local! {
    static IPC_LOCK_DEPTH: core::cell::Cell<usize> = const { core::cell::Cell::new(0) };
    static IPC_NESTING_CHECK: core::cell::Cell<bool> = const { core::cell::Cell::new(false) };
}

/// 宿主测试专用 guard：存活期间对“跨 IPC 表嵌套加锁”断言失败。
///
/// 注入缝（如 shm 的假帧池）本身也用 [`IrqCell`]，属于测试替身而非 IPC 表，因此检测
/// 必须显式开启，而不是对所有用例常开。
#[cfg(test)]
pub(crate) struct NestingGuard;

#[cfg(test)]
impl NestingGuard {
    pub(crate) fn new() -> Self {
        IPC_NESTING_CHECK.with(|flag| flag.set(true));
        Self
    }
}

#[cfg(test)]
impl Drop for NestingGuard {
    fn drop(&mut self) {
        IPC_NESTING_CHECK.with(|flag| flag.set(false));
        IPC_LOCK_DEPTH.with(|depth| depth.set(0));
    }
}

/// 表槽编号到对象负载的编码：`slot + 1`。
pub const fn payload_for_slot(slot: usize) -> u64 {
    slot as u64 + 1
}

/// 对象负载到表槽编号的解码；非法负载一律 [`IpcError::InvalidPayload`]。
pub(crate) fn slot_from_payload(payload: u64, capacity: usize) -> Result<usize, IpcError> {
    let slot = payload.checked_sub(1).ok_or(IpcError::InvalidPayload)?;
    if slot >= capacity as u64 {
        return Err(IpcError::InvalidPayload);
    }
    // 目标平台是 64 位，此转换不会截断；显式检查以防未来 32 位宿主机测试。
    let slot = usize::try_from(slot).map_err(|_| IpcError::InvalidPayload)?;
    Ok(slot)
}

/// 单条消息的数据上限（字节）。
pub const MESSAGE_DATA_MAX: usize = 64;

/// 单条消息可传递的句柄上限。
pub const MESSAGE_MAX_HANDLES: usize = 2;

/// 无对象的哨兵编号（`objects` 中未使用的槽位）。
const NO_OBJECT: ObjectId = ObjectId::MAX;

/// 队列中的消息：固定大小、`Copy`、无堆。
///
/// `sequence` 由队列在入队时分配（从 1 开始单调递增），`objects`/`rights` 记录
/// 本次传递的句柄对象与（只减不增的）权限位。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Message {
    /// 队列内单调递增的序号，`commit` 用它定位消息。
    pub sequence: u64,
    /// 上层协议编号。
    pub protocol: u32,
    /// 协议版本。
    pub version: u32,
    /// 可选事务编号（RPC 用）。
    pub transaction: u64,
    /// 发送进程的原始 `ProcessId` 值。
    pub sender_pid: u32,
    /// 有效数据长度（≤ [`MESSAGE_DATA_MAX`]）。
    pub data_len: u8,
    /// 内联数据。
    pub data: [u8; MESSAGE_DATA_MAX],
    /// 有效句柄数量（≤ [`MESSAGE_MAX_HANDLES`]）。
    pub handle_count: u8,
    /// 传递的对象编号。
    pub objects: [ObjectId; MESSAGE_MAX_HANDLES],
    /// 每个对象对应的权限位（只能保留或缩减）。
    pub rights: [u32; MESSAGE_MAX_HANDLES],
}

impl Message {
    /// 空消息（内部初始化用）。
    pub const EMPTY: Message = Message {
        sequence: 0,
        protocol: 0,
        version: 0,
        transaction: 0,
        sender_pid: 0,
        data_len: 0,
        data: [0; MESSAGE_DATA_MAX],
        handle_count: 0,
        objects: [NO_OBJECT; MESSAGE_MAX_HANDLES],
        rights: [0; MESSAGE_MAX_HANDLES],
    };

    /// 有效数据切片。
    pub fn data(&self) -> &[u8] {
        &self.data[..usize::from(self.data_len).min(MESSAGE_DATA_MAX)]
    }

    /// 有效对象切片。
    pub fn objects(&self) -> &[ObjectId] {
        &self.objects[..usize::from(self.handle_count).min(MESSAGE_MAX_HANDLES)]
    }

    /// 有效权限切片。
    pub fn rights(&self) -> &[u32] {
        &self.rights[..usize::from(self.handle_count).min(MESSAGE_MAX_HANDLES)]
    }

    /// 是否携带了对象。
    pub fn has_objects(&self) -> bool {
        self.handle_count != 0
    }
}

/// 发送方构造的消息：除 `sequence` 外与 [`Message`] 同构，由队列补序号。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct OutMessage {
    /// 上层协议编号。
    pub protocol: u32,
    /// 协议版本。
    pub version: u32,
    /// 可选事务编号（RPC 用）。
    pub transaction: u64,
    /// 发送进程的原始 `ProcessId` 值。
    pub sender_pid: u32,
    /// 有效数据长度（≤ [`MESSAGE_DATA_MAX`]）。
    pub data_len: u8,
    /// 内联数据。
    pub data: [u8; MESSAGE_DATA_MAX],
    /// 有效句柄数量（≤ [`MESSAGE_MAX_HANDLES`]）。
    pub handle_count: u8,
    /// 传递的对象编号（发送方必须先为每个对象 acquire 一份引用）。
    pub objects: [ObjectId; MESSAGE_MAX_HANDLES],
    /// 每个对象对应的权限位（只能保留或缩减）。
    pub rights: [u32; MESSAGE_MAX_HANDLES],
}

impl OutMessage {
    /// 空消息。
    pub const EMPTY: OutMessage = OutMessage {
        protocol: 0,
        version: 0,
        transaction: 0,
        sender_pid: 0,
        data_len: 0,
        data: [0; MESSAGE_DATA_MAX],
        handle_count: 0,
        objects: [NO_OBJECT; MESSAGE_MAX_HANDLES],
        rights: [0; MESSAGE_MAX_HANDLES],
    };

    /// 从字节切片构造（超长返回 [`IpcError::MessageTooLarge`]）。
    pub fn with_data(data: &[u8]) -> Result<OutMessage, IpcError> {
        if data.len() > MESSAGE_DATA_MAX {
            return Err(IpcError::MessageTooLarge);
        }
        let mut message = OutMessage::EMPTY;
        message.data_len = data.len() as u8;
        message.data[..data.len()].copy_from_slice(data);
        Ok(message)
    }

    /// 追加一个传递句柄（超过上限返回 [`IpcError::TooManyHandles`]）。
    ///
    /// `rights` 必须非空且只含已知权限位；调用方负责先 `acquire` 该对象引用。
    pub fn with_handle(mut self, object: ObjectId, rights: Rights) -> Result<OutMessage, IpcError> {
        if usize::from(self.handle_count) >= MESSAGE_MAX_HANDLES {
            return Err(IpcError::TooManyHandles);
        }
        if rights.is_empty() || rights.bits() & !Rights::ALL.bits() != 0 {
            return Err(IpcError::Object(ObjectError::InvalidRights));
        }
        let index = usize::from(self.handle_count);
        self.objects[index] = object;
        self.rights[index] = rights.bits();
        self.handle_count += 1;
        Ok(self)
    }

    /// 校验长度、句柄字段与句柄指向的对象是否仍然存活；非阻塞发送在入队前调用它，
    /// 因此校验失败不改变队列。
    ///
    /// 存活检查是必须的：对象编号会随槽位回收被复用，失效编号一旦入队，之后
    /// `commit`/队列丢弃时的 `release_object` 会误伤复用该槽的新对象。
    pub fn validate(&self) -> Result<(), IpcError> {
        if usize::from(self.data_len) > MESSAGE_DATA_MAX {
            return Err(IpcError::MessageTooLarge);
        }
        if usize::from(self.handle_count) > MESSAGE_MAX_HANDLES {
            return Err(IpcError::TooManyHandles);
        }
        for index in 0..usize::from(self.handle_count) {
            let object = self.objects[index];
            if object == NO_OBJECT || object::object_kind(object).is_none() {
                return Err(IpcError::Object(ObjectError::InvalidObject));
            }
            let rights = self.rights[index];
            if rights == 0 || rights & !Rights::ALL.bits() != 0 {
                return Err(IpcError::Object(ObjectError::InvalidRights));
            }
        }
        Ok(())
    }

    /// 补齐序号，变成队列里的 [`Message`]。
    pub(crate) fn into_message(self, sequence: u64) -> Message {
        Message {
            sequence,
            protocol: self.protocol,
            version: self.version,
            transaction: self.transaction,
            sender_pid: self.sender_pid,
            data_len: self.data_len,
            data: self.data,
            handle_count: self.handle_count,
            objects: self.objects,
            rights: self.rights,
        }
    }
}

/// 固定深度 FIFO 消息队列（无堆，头/长度索引）。
#[derive(Clone, Copy)]
pub(crate) struct MessageQueue<const N: usize> {
    entries: [Message; N],
    head: usize,
    len: usize,
}

impl<const N: usize> MessageQueue<N> {
    pub(crate) const EMPTY: MessageQueue<N> = MessageQueue {
        entries: [Message::EMPTY; N],
        head: 0,
        len: 0,
    };

    pub(crate) const fn len(&self) -> usize {
        self.len
    }

    pub(crate) const fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub(crate) const fn is_full(&self) -> bool {
        self.len() == N
    }

    pub(crate) fn front(&self) -> Option<&Message> {
        if self.len == 0 {
            None
        } else {
            Some(&self.entries[self.head])
        }
    }

    /// 入队；队列满时把消息所有权原样退回调用者（`WouldBlock`），且不改变队列。
    ///
    /// 退回所有权是刻意的：消息携带对象引用，若在满队列路径上直接丢弃会泄漏或
    /// 触发错误的引用计数。调用者必须在 IPC 表闭包**之外**释放退回消息的引用。
    pub(crate) fn push(&mut self, message: Message) -> Result<(), (IpcError, Message)> {
        if self.is_full() {
            return Err((IpcError::WouldBlock, message));
        }
        let index = (self.head + self.len) % N;
        self.entries[index] = message;
        self.len += 1;
        Ok(())
    }

    /// 弹出队首。
    pub(crate) fn pop(&mut self) -> Option<Message> {
        if self.len == 0 {
            return None;
        }
        let message = self.entries[self.head];
        self.entries[self.head] = Message::EMPTY;
        self.head = (self.head + 1) % N;
        self.len -= 1;
        Some(message)
    }

    /// 按 `sequence` 移除（FIFO 顺序扫描；找到后把后续元素前移以保持顺序）。
    pub(crate) fn remove_sequence(&mut self, sequence: u64) -> Option<Message> {
        for offset in 0..self.len {
            let index = (self.head + offset) % N;
            if self.entries[index].sequence != sequence {
                continue;
            }
            let removed = self.entries[index];
            // 把 index 之后（到队尾）的元素整体前移一格。
            let mut cursor = index;
            for _ in offset..(self.len - 1) {
                let next = (cursor + 1) % N;
                self.entries[cursor] = self.entries[next];
                cursor = next;
            }
            self.entries[cursor] = Message::EMPTY;
            self.len -= 1;
            return Some(removed);
        }
        None
    }

    /// 清空队列，并把每条消息交给 `sink`（用于在锁外释放引用）。
    pub(crate) fn drain_into<const M: usize>(&mut self, sink: &mut [Option<Message>; M]) -> usize {
        let mut count = 0;
        while count < M {
            match self.pop() {
                Some(message) => {
                    sink[count] = Some(message);
                    count += 1;
                }
                None => break,
            }
        }
        count
    }
}

/// 释放一条消息占用的对象引用（队列拥有的那一份）。
///
/// 必须在持有 IPC 表 `IrqCell` 的闭包**之外**调用：释放可能归零对象引用并触发
/// 销毁钩子，而钩子会回调本模块的 `destroy`，同一 `IrqCell` 重入是未定义行为。
pub(crate) fn release_message_objects(message: &Message) {
    for index in 0..usize::from(message.handle_count).min(MESSAGE_MAX_HANDLES) {
        let object = message.objects[index];
        if object != NO_OBJECT {
            let _ = object::release_object(object);
        }
    }
}

/// 统一可等待对象轮询（非阻塞）：只报告是否就绪，不返回 `PeerClosed`。
///
/// `take` **只**对信号类对象生效，队列/订阅类一律不消费：
/// - Event / Timer：`take` 为真时按各自 reset 语义清除信号；
/// - EventPair：`take` 为真时消费端点 0（需要端点时用 [`poll_waitable_keyed`]）；
/// - Channel / Port：只接受接收端对象，只报告队列非空，**`take` 被忽略**——消息只能
///   经 `IPC_RECV` 的 `peek` → `commit` 取走，WAIT 绝不允许丢弃消息或引用；
/// - EventSubscription：只报告是否有事件就绪（[`subscription::ready`]），不取走事件、
///   不消费消息/auto-reset 信号，订阅对象本身不可 `take`；实际事件由
///   `subscription::poll/read` 取出。注意 `ready` 会**清掉已失效的边沿触发缓存**
///   （observed），使 ET 重新武装，因此该分支不是纯只读——但返回值契约不变；
/// - Input：只报告事件队列非空（[`input::poll`]），`take` 被忽略——事件只能经
///   `INPUT_READ` 的 [`input::read`] 取走，WAIT 不允许丢弃事件。
pub fn poll_waitable(object: ObjectId, take: bool) -> Result<bool, IpcError> {
    poll_waitable_keyed(object, 0, take)
}

/// 带等待 key 的轮询（EventPair 用端点 0/1；其余类型 key 必须为 0）。
///
/// EventSubscription 分支可能清 ET 的 observed 缓存（重新武装），其余分支只查询或按
/// `take` 清理信号；任何分支都不会消费 Channel/Port 队列消息。
pub fn poll_waitable_keyed(object: ObjectId, key: u8, take: bool) -> Result<bool, IpcError> {
    let kind = object::object_kind(object).ok_or(IpcError::Object(ObjectError::InvalidObject))?;
    let payload = object::payload(object).unwrap_or(0);
    match kind {
        ObjectKind::Event | ObjectKind::EventPair | ObjectKind::Timer => {
            let ready = is_ready(kind, payload, key)?;
            if take && ready {
                let _ = consume(kind, payload, key)?;
            }
            Ok(ready)
        }
        ObjectKind::Channel => channel::poll(object, take),
        ObjectKind::Port => port::poll(object, take),
        ObjectKind::EventSubscription => {
            subscription::ready(object).map_err(|_| IpcError::WrongKind)
        }
        // Input keeps its events until `INPUT_READ` drains them: waiting must not
        // lose a keystroke, so `take` is deliberately ignored here as well.
        ObjectKind::Input => Ok(input::poll(object)),
        // EventFd readiness is "counter is non-zero". The counter is only
        // consumed by an actual `read` through the syscall layer, so `take` is
        // ignored here too (a poll must never drain the eventfd).
        ObjectKind::EventFd => {
            if key != 0 {
                return Err(IpcError::InvalidEndpoint);
            }
            eventfd::readable(object).map_err(|_| IpcError::WrongKind)
        }
        // TimerFd / SignalFd / Epoll：就绪分别是"有未读到期的次数"、"有可消费
        // 的阻塞信号"、"至少一个兴趣就绪"。与 EventFd 一样忽略 `take`：只有
        // compat 的 read/ctl 路径会消费它们。
        ObjectKind::TimerFd => {
            if key != 0 {
                return Err(IpcError::InvalidEndpoint);
            }
            timerfd::readable(object).map_err(|_| IpcError::WrongKind)
        }
        ObjectKind::SignalFd => {
            if key != 0 {
                return Err(IpcError::InvalidEndpoint);
            }
            signalfd::readable(object).map_err(|_| IpcError::WrongKind)
        }
        ObjectKind::Epoll => {
            if key != 0 {
                return Err(IpcError::InvalidEndpoint);
            }
            epoll::any_ready(object).map_err(|_| IpcError::WrongKind)
        }
        _ => Err(IpcError::WrongKind),
    }
}

/// 统一销毁入口（按对象编号）：Channel/Port 端点会先唤醒对端再释放状态。
///
/// 这是对象层销毁钩子的落点；Event/EventPair/Timer 由 [`destroy_bound`] 处理。
pub fn destroy(object: ObjectId) -> Result<(), IpcError> {
    if channel::destroy_endpoint(object)? {
        return Ok(());
    }
    if port::destroy_endpoint(object)? {
        return Ok(());
    }
    Err(IpcError::WrongKind)
}

/// 统一就绪查询：`key` 对 EventPair 表示端点（0/1），对 Event/Timer 必须为 0。
///
/// 只查询、不消费；等待路径在 `WAKE` 成功后应调用 [`consume`]。
pub fn is_ready(kind: ObjectKind, payload: u64, key: u8) -> Result<bool, IpcError> {
    match kind {
        ObjectKind::Event => {
            if key != 0 {
                return Err(IpcError::InvalidEndpoint);
            }
            event::ready(payload)
        }
        ObjectKind::EventPair => event::ready_pair(payload, key),
        ObjectKind::Timer => {
            if key != 0 {
                return Err(IpcError::InvalidEndpoint);
            }
            timer::ready(payload)
        }
        _ => Err(IpcError::WrongKind),
    }
}

/// 统一消费查询：返回是否观察到就绪，并按各自的 reset 语义清除信号。
pub fn consume(kind: ObjectKind, payload: u64, key: u8) -> Result<bool, IpcError> {
    match kind {
        ObjectKind::Event => {
            if key != 0 {
                return Err(IpcError::InvalidEndpoint);
            }
            event::consume(payload)
        }
        ObjectKind::EventPair => event::consume_pair(payload, key),
        ObjectKind::Timer => {
            if key != 0 {
                return Err(IpcError::InvalidEndpoint);
            }
            timer::consume(payload)
        }
        _ => Err(IpcError::WrongKind),
    }
}

/// 按 kind 统一销毁槽位对象（Event/EventPair/Timer 的销毁钩子入口）。
///
/// 与按对象编号分派的 [`destroy`] 不同，这里只处理“负载编码表槽”的三类对象；
/// 也允许 syscall 在只创建了表槽、对象创建失败时用于清理（此时 `object` 传一个
/// 从不存活的取值即可，唤醒是无害的空操作）。
pub(crate) fn destroy_bound(
    kind: ObjectKind,
    payload: u64,
    object: ObjectId,
) -> Result<(), IpcError> {
    match kind {
        ObjectKind::Event => event::destroy(payload, object),
        ObjectKind::EventPair => event::destroy_pair(payload, object),
        ObjectKind::Timer => timer::destroy(payload, object),
        _ => Err(IpcError::WrongKind),
    }
}

/// 注册全部 IPC 类型的销毁钩子；由 root / vfs 初始化路径调用一次，重复调用幂等。
pub fn install_destroy_hooks() -> Result<(), ObjectError> {
    object::register_destroy_hook_with_object(ObjectKind::Event, destroy_hook)?;
    object::register_destroy_hook_with_object(ObjectKind::EventPair, destroy_hook)?;
    object::register_destroy_hook_with_object(ObjectKind::Timer, destroy_hook)?;
    object::register_destroy_hook_with_object(ObjectKind::Channel, endpoint_destroy_hook)?;
    object::register_destroy_hook_with_object(ObjectKind::Port, endpoint_destroy_hook)?;
    object::register_destroy_hook_with_object(ObjectKind::SharedMemory, shm_hook)?;
    object::register_destroy_hook_with_object(ObjectKind::EventSubscription, subscription_hook)?;
    object::register_destroy_hook_with_object(ObjectKind::Input, input_hook)?;
    object::register_destroy_hook_with_object(ObjectKind::Display, display_hook)?;
    object::register_destroy_hook_with_object(ObjectKind::EventFd, eventfd_hook)?;
    object::register_destroy_hook_with_object(ObjectKind::TimerFd, timerfd_hook)?;
    object::register_destroy_hook_with_object(ObjectKind::SignalFd, signalfd_hook)?;
    object::register_destroy_hook_with_object(ObjectKind::Epoll, epoll_hook)?;
    Ok(())
}

/// 目标对象变为就绪：通知订阅者，并唤醒所有用 epoll 观察它的实例。
///
/// 调用点必须已释放目标表的锁（本函数会重新进入 `poll_waitable_keyed` 与
/// epoll 表）；可重入、不访问对象表。
pub(crate) fn notify_target_ready(target: ObjectId) {
    let _ = subscription::on_target_ready(target);
    let _ = epoll::notify_target(target);
}

/// 目标对象变为非就绪：清掉订阅边沿并唤醒 epoll 观察者，让 LT 重新探测。
pub(crate) fn notify_target_not_ready(target: ObjectId) {
    let _ = subscription::on_target_not_ready(target);
    let _ = epoll::notify_target(target);
}
/// 对象层销毁钩子的适配器：忽略分发错误（对象已经失效，无处上报）。
fn destroy_hook(kind: ObjectKind, payload: u64, object: ObjectId) {
    let _ = epoll::on_target_destroy(object);
    let _ = destroy_bound(kind, payload, object);
}

/// Channel/Port 端点对象的销毁钩子：按对象编号分派给各自的状态表。
fn endpoint_destroy_hook(_kind: ObjectKind, _payload: u64, object: ObjectId) {
    let _ = epoll::on_target_destroy(object);
    let _ = destroy(object);
}

/// SharedMemory 的销毁钩子：释放物理帧表槽（不回调对象表）。
fn shm_hook(_kind: ObjectKind, _payload: u64, object: ObjectId) {
    let _ = epoll::on_target_destroy(object);
    shm::on_destroy(object);
}

/// EventSubscription 的销毁钩子：只把待释放的目标引用入队，绝不回调对象表。
///
/// 真正的 `release_object` 必须由调用方在对象表锁与关中断区间之外通过
/// [`release_subscription_pending`] 排空，避免重入。
fn subscription_hook(_kind: ObjectKind, _payload: u64, object: ObjectId) {
    let _ = epoll::on_target_destroy(object);
    subscription::on_destroy(object);
}

/// Input 的销毁钩子：清掉该对象的 seat 槽并唤醒等待者（不回调对象表）。
fn input_hook(_kind: ObjectKind, _payload: u64, object: ObjectId) {
    let _ = epoll::on_target_destroy(object);
    input::on_destroy(object);
}

/// Display 的销毁钩子：释放 shadow 状态槽（不回调对象表；帧的归属由
/// `ipc::display` 自己记账，`live_frames` 在对象销毁后必须归零）。
fn display_hook(_kind: ObjectKind, _payload: u64, object: ObjectId) {
    let _ = epoll::on_target_destroy(object);
    display::on_destroy(object);
}

/// EventFd 的销毁钩子：清掉计数槽并唤醒等待者（不回调对象表）。
fn eventfd_hook(_kind: ObjectKind, _payload: u64, object: ObjectId) {
    let _ = epoll::on_target_destroy(object);
    eventfd::on_destroy(object);
}

/// TimerFd 的销毁钩子：清掉定时器槽并唤醒等待者（不回调对象表）。
fn timerfd_hook(_kind: ObjectKind, _payload: u64, object: ObjectId) {
    let _ = epoll::on_target_destroy(object);
    timerfd::on_destroy(object);
}

/// SignalFd 的销毁钩子：清掉信号槽并唤醒等待者（不回调对象表）。
fn signalfd_hook(_kind: ObjectKind, _payload: u64, object: ObjectId) {
    let _ = epoll::on_target_destroy(object);
    signalfd::on_destroy(object);
}

/// Epoll 的销毁钩子：清掉兴趣集合并唤醒等待者（不回调对象表）。
fn epoll_hook(_kind: ObjectKind, _payload: u64, object: ObjectId) {
    let _ = epoll::on_target_destroy(object);
    epoll::on_destroy(object);
}

/// 排空 EventSubscription 延迟释放队列，返回实际释放的目标引用数。
///
/// 必须在对象表 `IrqCell` 闭包之外调用：句柄关闭/进程退出路径在 `close` 成功后
/// 调用一次即可（句柄关闭、进程退出各调一次，幂等）。
pub fn release_subscription_pending() -> usize {
    subscription::release_pending()
}

/// 创建 Event 表槽 + 对象 + 句柄，并完成 payload→ObjectId 绑定。
///
/// 绑定是订阅唤醒的前提：`signal`/`reset` 之后只凭对象编号就能找到关心的订阅。
/// 任何一步失败都会回收已占用的表槽与对象引用，不留半成品。
pub fn insert_event(
    table: &mut HandleTable,
    manual_reset: bool,
    rights: Rights,
) -> Result<Handle, IpcError> {
    // 与 Timer 相同：手动的 create_with_payload + insert_params 绕过了
    // `insert_new_*` 的校验点，因此这里显式复用同一初始权限策略。
    object::check_initial_rights(ObjectKind::Event, rights).map_err(IpcError::Object)?;
    let payload = event::create(manual_reset)?;

    let object = match object::create_with_payload(ObjectKind::Event, payload) {
        Ok(object) => object,
        Err(error) => {
            let _ = event::discard(payload);
            return Err(IpcError::Object(error));
        }
    };

    if let Err(error) = event::bind(payload, object) {
        let _ = event::discard(payload);
        let _ = object::release_object(object);
        let _ = object::destroy_object(object);
        return Err(error);
    }

    let inserted = object::with_object_table(|objects| {
        table.insert_params(objects, object, object::CreateHandleParams::new(rights))
    });

    match inserted {
        Ok(handle) => {
            // 对象初始引用交给句柄持有。
            let _ = object::release_object(object);
            Ok(handle)
        }
        Err(error) => {
            let _ = object::release_object(object);
            let _ = object::destroy_object(object);
            Err(IpcError::Object(error))
        }
    }
}

/// 创建 EventPair 表槽 + 对象 + 句柄，并完成 payload→ObjectId 绑定。
pub fn insert_event_pair(table: &mut HandleTable, rights: Rights) -> Result<Handle, IpcError> {
    object::check_initial_rights(ObjectKind::EventPair, rights).map_err(IpcError::Object)?;
    let payload = event::create_pair()?;

    let object = match object::create_with_payload(ObjectKind::EventPair, payload) {
        Ok(object) => object,
        Err(error) => {
            let _ = event::discard_pair(payload);
            return Err(IpcError::Object(error));
        }
    };

    if let Err(error) = event::bind_pair(payload, object) {
        let _ = event::discard_pair(payload);
        let _ = object::release_object(object);
        let _ = object::destroy_object(object);
        return Err(error);
    }

    let inserted = object::with_object_table(|objects| {
        table.insert_params(objects, object, object::CreateHandleParams::new(rights))
    });

    match inserted {
        Ok(handle) => {
            let _ = object::release_object(object);
            Ok(handle)
        }
        Err(error) => {
            let _ = object::release_object(object);
            let _ = object::destroy_object(object);
            Err(IpcError::Object(error))
        }
    }
}

/// 创建 Timer 表槽 + 对象 + 句柄，并完成 payload→ObjectId 绑定。
///
/// 任何一步失败都会回收已占用的表槽与对象引用，不留半成品。
pub fn insert_timer(table: &mut HandleTable, rights: Rights) -> Result<Handle, IpcError> {
    // Timer 走手动的 create_with_payload + insert_params，绕过了 object 的
    // `insert_new_*` 校验点，因此这里显式复用同一初始权限策略。
    object::check_initial_rights(ObjectKind::Timer, rights).map_err(IpcError::Object)?;
    let payload = timer::create()?;

    let object = match object::create_with_payload(ObjectKind::Timer, payload) {
        Ok(object) => object,
        Err(error) => {
            let _ = timer::discard(payload);
            return Err(IpcError::Object(error));
        }
    };

    if let Err(error) = timer::bind(payload, object) {
        let _ = timer::discard(payload);
        let _ = object::release_object(object);
        let _ = object::destroy_object(object);
        return Err(error);
    }

    let inserted = object::with_object_table(|objects| {
        table.insert_params(objects, object, object::CreateHandleParams::new(rights))
    });

    match inserted {
        Ok(handle) => {
            // 对象初始引用交给句柄持有。
            let _ = object::release_object(object);
            Ok(handle)
        }
        Err(error) => {
            // 释放初始引用会触发销毁钩子（Timer::destroy 唤醒并清槽）。
            let _ = object::release_object(object);
            let _ = object::destroy_object(object);
            Err(IpcError::Object(error))
        }
    }
}

/// 创建 EventFd 表槽 + 对象 + 句柄，并完成 payload→ObjectId 绑定。
///
/// 任何一步失败都会回收已占用的表槽与对象引用，不留半成品。
pub fn insert_eventfd(
    table: &mut HandleTable,
    initval: u64,
    flags: u32,
    rights: Rights,
) -> Result<Handle, IpcError> {
    // EventFd 走手动的 create_with_payload + insert_params，绕过了 object 的
    // `insert_new_*` 校验点，因此这里显式复用同一初始权限策略。
    object::check_initial_rights(ObjectKind::EventFd, rights).map_err(IpcError::Object)?;
    let payload = eventfd::create(initval, flags).map_err(eventfd_status)?;

    let object = match object::create_with_payload(ObjectKind::EventFd, payload) {
        Ok(object) => object,
        Err(error) => {
            let _ = eventfd::discard(payload);
            return Err(IpcError::Object(error));
        }
    };

    if let Err(error) = eventfd::bind(payload, object) {
        let _ = eventfd::discard(payload);
        let _ = object::release_object(object);
        let _ = object::destroy_object(object);
        return Err(eventfd_status(error));
    }

    let inserted = object::with_object_table(|objects| {
        table.insert_params(objects, object, object::CreateHandleParams::new(rights))
    });

    match inserted {
        Ok(handle) => {
            // 对象初始引用交给句柄持有。
            let _ = object::release_object(object);
            Ok(handle)
        }
        Err(error) => {
            // 释放初始引用会触发销毁钩子（EventFd::on_destroy 唤醒并清槽）。
            let _ = object::release_object(object);
            let _ = object::destroy_object(object);
            Err(IpcError::Object(error))
        }
    }
}

/// `eventfd::EventFdError` → IPC 层错误；syscall 层再按 [`IpcError`] 映射到 errno。
fn eventfd_status(error: eventfd::EventFdError) -> IpcError {
    match error {
        eventfd::EventFdError::TableFull => IpcError::TableFull,
        eventfd::EventFdError::BadValue => IpcError::InvalidPayload,
        _ => IpcError::WrongKind,
    }
}

/// 失败清理：释放单个尚未链接的端点对象。
fn discard_endpoint(object: ObjectId) {
    let _ = object::release_object(object);
    let _ = channel::destroy_endpoint(object);
    let _ = port::destroy_endpoint(object);
}

/// 失败清理：释放两个端点对象的初始引用并释放 Channel 状态槽。
fn discard_channel_pair(a: ObjectId, b: ObjectId) {
    let _ = object::release_object(a);
    let _ = object::release_object(b);
    let _ = channel::destroy_endpoint(a);
    let _ = channel::destroy_endpoint(b);
}

/// 失败清理：释放两个端点对象的初始引用并释放 Port 状态槽。
fn discard_port_pair(receiver: ObjectId, sender: ObjectId) {
    let _ = object::release_object(receiver);
    let _ = object::release_object(sender);
    let _ = port::destroy_endpoint(receiver);
    let _ = port::destroy_endpoint(sender);
}

/// 创建 Channel 的两个端点对象 + 状态槽 + 两个句柄，失败时不泄漏任何资源。
///
/// `rights_a`/`rights_b` 分别是端点 A、B 的初始权限；两者都必须落在
/// `initial_rights_bound(ObjectKind::Channel)` 内。返回 `(A, B)` 两个句柄。
pub fn insert_channel(
    table: &mut HandleTable,
    rights_a: Rights,
    rights_b: Rights,
) -> Result<(Handle, Handle), IpcError> {
    object::check_initial_rights(ObjectKind::Channel, rights_a).map_err(IpcError::Object)?;
    object::check_initial_rights(ObjectKind::Channel, rights_b).map_err(IpcError::Object)?;

    let a = object::create_with_payload(ObjectKind::Channel, 0).map_err(IpcError::Object)?;
    let b = match object::create_with_payload(ObjectKind::Channel, 0) {
        Ok(b) => b,
        Err(error) => {
            discard_endpoint(a);
            return Err(IpcError::Object(error));
        }
    };
    if let Err(error) = channel::create(a, b) {
        // 两个端点对象都已存在但未链接：释放初始引用（销毁钩子按未链接端点处理）。
        discard_channel_pair(a, b);
        return Err(error);
    }

    let handle_a = match object::with_object_table(|objects| {
        table.insert_params(objects, a, object::CreateHandleParams::new(rights_a))
    }) {
        Ok(handle) => handle,
        Err(error) => {
            discard_channel_pair(a, b);
            return Err(IpcError::Object(error));
        }
    };
    let handle_b = match object::with_object_table(|objects| {
        table.insert_params(objects, b, object::CreateHandleParams::new(rights_b))
    }) {
        Ok(handle) => handle,
        Err(error) => {
            let _ = object::close_handle(table, handle_a);
            discard_channel_pair(a, b);
            return Err(IpcError::Object(error));
        }
    };
    // 对象初始引用交给两个句柄持有。
    let _ = object::release_object(a);
    let _ = object::release_object(b);
    Ok((handle_a, handle_b))
}

/// 创建 Port 的 receiver/sender 端点对象 + 状态槽 + 两个句柄，失败不泄漏资源。
///
/// `receiver_rights` 应当是接收侧权限（READ/WAIT 等），`sender_rights` 是发送侧
/// 权限（WRITE 等）；两者都必须落在 `initial_rights_bound(ObjectKind::Port)` 内。
pub fn insert_port(
    table: &mut HandleTable,
    receiver_rights: Rights,
    sender_rights: Rights,
) -> Result<(Handle, Handle), IpcError> {
    object::check_initial_rights(ObjectKind::Port, receiver_rights).map_err(IpcError::Object)?;
    object::check_initial_rights(ObjectKind::Port, sender_rights).map_err(IpcError::Object)?;

    let receiver = object::create_with_payload(ObjectKind::Port, 0).map_err(IpcError::Object)?;
    let sender = match object::create_with_payload(ObjectKind::Port, 0) {
        Ok(sender) => sender,
        Err(error) => {
            discard_endpoint(receiver);
            return Err(IpcError::Object(error));
        }
    };
    if let Err(error) = port::create(receiver, sender) {
        discard_port_pair(receiver, sender);
        return Err(error);
    }

    let receiver_handle = match object::with_object_table(|objects| {
        table.insert_params(
            objects,
            receiver,
            object::CreateHandleParams::new(receiver_rights),
        )
    }) {
        Ok(handle) => handle,
        Err(error) => {
            discard_port_pair(receiver, sender);
            return Err(IpcError::Object(error));
        }
    };
    let sender_handle = match object::with_object_table(|objects| {
        table.insert_params(
            objects,
            sender,
            object::CreateHandleParams::new(sender_rights),
        )
    }) {
        Ok(handle) => handle,
        Err(error) => {
            let _ = object::close_handle(table, receiver_handle);
            discard_port_pair(receiver, sender);
            return Err(IpcError::Object(error));
        }
    };
    let _ = object::release_object(receiver);
    let _ = object::release_object(sender);
    Ok((receiver_handle, sender_handle))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 触碰全局表（IPC 表 + 对象表）的测试必须与 object 测试共用同一把锁。
    fn lock() -> std::sync::MutexGuard<'static, ()> {
        crate::object::test_lock()
    }

    /// 把全部全局 IPC 表与销毁钩子恢复成干净起点。
    ///
    /// 全量测试里同一进程内其它模块（shm/subscription/channel/port…）的用例会留下
    /// 表槽或改写钩子表，而本模块的断言用绝对计数，所以每个用例先自清。
    fn prepare() {
        event::reset_for_test();
        timer::reset_for_test();
        channel::reset_for_test();
        port::reset_for_test();
        eventfd::reset_for_test();
        timerfd::reset_for_test();
        signalfd::reset_for_test();
        epoll::reset_for_test();
        crate::object::reset_destroy_hooks();
        install_destroy_hooks().expect("destroy hooks install");
    }

    /// P0-2/P0-3 回归：任何 IPC 入口都不得在持有某张 IPC 表锁时进入另一张 IPC 表。
    ///
    /// 用 [`NestingGuard`] 显式开启检测：宿主测试的注入缝（如 shm 的假帧池）也复用
    /// `IrqCell`，属于测试替身而非 IPC 表，不能对全部用例常开。
    #[test]
    fn no_ipc_table_is_locked_while_another_is_accessed() {
        let _guard = lock();
        prepare();
        let _nesting = NestingGuard::new();

        // Event：signal / consume / reset 都是“单表加锁 → 锁外通知订阅”。
        let payload = event::create(false).unwrap();
        event::signal(payload).unwrap();
        assert!(event::consume(payload).unwrap());
        event::reset(payload).unwrap();
        event::discard(payload).unwrap();

        // Timer：bind / arm / on_tick（arm 需要已绑定对象）。
        let timer_payload = timer::create().unwrap();
        let timer_object = object::create_with_payload(ObjectKind::Timer, timer_payload).unwrap();
        timer::bind(timer_payload, timer_object).unwrap();
        timer::arm(timer_payload, Some(0)).unwrap();
        assert_eq!(timer::on_tick(0), 1);
        timer::destroy(timer_payload, timer_object).unwrap();
        let _ = object::release_object(timer_object);

        // Channel：本端 send 落到对端队列，接收端 peek/commit。
        let a = object::create_with_payload(ObjectKind::Channel, 0).unwrap();
        let b = object::create_with_payload(ObjectKind::Channel, 0).unwrap();
        channel::create(a, b).unwrap();
        channel::send(a, OutMessage::with_data(b"ping").unwrap()).unwrap();
        // 订阅的 ready/poll/read 必须在订阅表锁之外探测目标源表（这里的源表是 channel）。
        let sub = object::create_with_payload(ObjectKind::EventSubscription, 0).unwrap();
        subscription::create(sub).unwrap();
        subscription::register(sub, b, subscription::MODE_LEVEL, 0).unwrap();
        assert_eq!(subscription::ready(sub), Ok(true));
        let mut events = [subscription::SubscriptionEvent {
            object_key: 0,
            mode: 0,
        }; 4];
        assert_eq!(subscription::poll(sub, &mut events), Ok(1));
        assert_eq!(subscription::read(sub, &mut events), Ok(1));
        let message = channel::peek(b).unwrap();
        channel::commit(b, message.sequence).unwrap();
        assert_eq!(subscription::ready(sub), Ok(false));
        subscription::destroy(sub).unwrap();
        let _ = subscription::release_pending();
        let _ = object::release_object(sub);
        assert!(channel::destroy_endpoint(a).unwrap());
        assert!(channel::destroy_endpoint(b).unwrap());
        let _ = object::release_object(a);
        let _ = object::release_object(b);

        // Port：sender 投递、receiver peek/commit。
        let receiver = object::create_with_payload(ObjectKind::Port, 0).unwrap();
        let sender = object::create_with_payload(ObjectKind::Port, 0).unwrap();
        port::create(receiver, sender).unwrap();
        port::send(sender, OutMessage::with_data(b"req").unwrap()).unwrap();
        let request = port::peek(receiver).unwrap();
        port::commit(receiver, request.sequence).unwrap();
        assert!(port::destroy_endpoint(receiver).unwrap());
        assert!(port::destroy_endpoint(sender).unwrap());
        let _ = object::release_object(receiver);
        let _ = object::release_object(sender);
    }

    /// 反向自检：确认 [`NestingGuard`] 的检测器**确实生效**，否则上一个用例可能只是
    /// “检测没打开”而假绿。这里故意把两个 `IrqCell` 嵌套加锁，必须 panic。
    #[test]
    #[should_panic(expected = "IPC table locked while another IPC table was held")]
    fn nesting_detector_rejects_nested_ipc_table_locks() {
        let _guard = lock();
        prepare();
        let _nesting = NestingGuard::new();
        let outer = IrqCell::new(0u32);
        let inner = IrqCell::new(0u32);
        outer.with(|_| {
            inner.with(|_| 1);
        });
    }

    #[test]
    fn payload_encoding_round_trips() {
        assert_eq!(payload_for_slot(0), 1);
        assert_eq!(payload_for_slot(31), 32);
        assert_eq!(slot_from_payload(1, 32), Ok(0));
        assert_eq!(slot_from_payload(32, 32), Ok(31));
    }

    #[test]
    fn payload_decoding_rejects_impossible_values() {
        assert_eq!(slot_from_payload(0, 32), Err(IpcError::InvalidPayload));
        assert_eq!(slot_from_payload(33, 32), Err(IpcError::InvalidPayload));
        assert_eq!(
            slot_from_payload(u64::MAX, 16),
            Err(IpcError::InvalidPayload)
        );
    }

    #[test]
    fn unified_queries_reject_foreign_kinds() {
        let _guard = lock();
        assert_eq!(is_ready(ObjectKind::File, 1, 0), Err(IpcError::WrongKind));
        assert_eq!(consume(ObjectKind::Console, 1, 0), Err(IpcError::WrongKind));
        assert_eq!(
            destroy_bound(ObjectKind::Process, 1, 0),
            Err(IpcError::WrongKind)
        );
    }

    #[test]
    fn unified_event_queries_route_by_kind() {
        let _guard = lock();
        prepare();

        let payload = event::create(true).unwrap();
        event::signal(payload).unwrap();
        assert_eq!(is_ready(ObjectKind::Event, payload, 0), Ok(true));
        // Event 没有端点概念。
        assert_eq!(
            is_ready(ObjectKind::Event, payload, 1),
            Err(IpcError::InvalidEndpoint)
        );
        assert_eq!(consume(ObjectKind::Event, payload, 0), Ok(true));
        // manual-reset：消费后仍保持置位。
        assert_eq!(is_ready(ObjectKind::Event, payload, 0), Ok(true));
        event::reset(payload).unwrap();
        assert_eq!(is_ready(ObjectKind::Event, payload, 0), Ok(false));
        event::discard(payload).unwrap();
    }

    #[test]
    fn insert_helpers_create_bound_objects_with_expected_payloads() {
        let _guard = lock();
        prepare();

        let before = object::live_objects();
        let mut table = HandleTable::new();

        let event_handle = insert_event(&mut table, false, Rights::READ | Rights::WAIT).unwrap();
        let pair_handle = insert_event_pair(&mut table, Rights::READ | Rights::WAIT).unwrap();
        let timer_handle = insert_timer(&mut table, Rights::READ | Rights::WAIT).unwrap();
        assert_eq!(table.len(), 3);

        for (handle, kind) in [
            (event_handle, ObjectKind::Event),
            (pair_handle, ObjectKind::EventPair),
            (timer_handle, ObjectKind::Timer),
        ] {
            let resolved = table.resolve_as(handle, kind, Rights::NONE).unwrap();
            let payload = object::payload(resolved.object).unwrap();
            assert!(payload >= 1);
        }

        // 关闭句柄触发销毁钩子，表槽必须被释放；对象表回到初始计数。
        for handle in [event_handle, pair_handle, timer_handle] {
            object::close_handle(&mut table, handle).unwrap();
        }
        assert_eq!(table.len(), 0);
        assert_eq!(object::live_objects(), before);
        assert_eq!(event::count(), 0);
        assert_eq!(event::pair_count(), 0);
        assert_eq!(timer::count(), 0);

        crate::object::reset_destroy_hooks();
    }

    #[test]
    fn destroyed_objects_release_their_ipc_slots_once() {
        let _guard = lock();
        prepare();

        let mut table = HandleTable::new();
        let event_handle = insert_event(&mut table, true, Rights::READ).unwrap();
        let pair_handle = insert_event_pair(&mut table, Rights::READ).unwrap();
        let timer_handle = insert_timer(&mut table, Rights::READ).unwrap();

        object::close_handle(&mut table, event_handle).unwrap();
        object::close_handle(&mut table, pair_handle).unwrap();
        object::close_handle(&mut table, timer_handle).unwrap();

        assert_eq!(event::count(), 0);
        assert_eq!(event::pair_count(), 0);
        assert_eq!(timer::count(), 0);
        assert_eq!(table.len(), 0);

        crate::object::reset_destroy_hooks();
    }

    /// 创建路径的初始权限策略对三个 IPC 类型都生效，且失败不留半成品。
    #[test]
    fn insert_helpers_reject_invalid_initial_rights_without_leaking_slots() {
        let _guard = lock();
        prepare();

        let before_objects = object::live_objects();
        let mut table = HandleTable::new();
        let invalid = Rights::NONE;
        let expected = Err(IpcError::Object(object::ObjectError::InvalidRights));
        assert_eq!(insert_event(&mut table, false, invalid), expected);
        assert_eq!(insert_event_pair(&mut table, invalid), expected);
        assert_eq!(insert_timer(&mut table, invalid), expected);
        // 保留位同样非法（MAP 属于 Rights::ALL，但不在 IPC 的初始权限集合内）。
        assert_eq!(
            insert_timer(&mut table, Rights::MAP),
            Err(IpcError::Object(object::ObjectError::InvalidRights))
        );

        // 非法请求不占用句柄表、对象表或 IPC 表槽。
        assert_eq!(table.len(), 0);
        assert_eq!(object::live_objects(), before_objects);
        assert_eq!(event::count(), 0);
        assert_eq!(event::pair_count(), 0);
        assert_eq!(timer::count(), 0);

        // 合法集合仍可创建，关闭后完整回收（回归“策略不误伤”）。
        insert_event(
            &mut table,
            false,
            Rights::READ | Rights::WRITE | Rights::WAIT,
        )
        .unwrap();
        insert_event_pair(&mut table, Rights::WAIT).unwrap();
        insert_timer(&mut table, Rights::WRITE | Rights::DUPLICATE).unwrap();
        assert_eq!(table.len(), 3);
        object::clear_handle_table(&mut table);
        assert_eq!(object::live_objects(), before_objects);
        assert_eq!(event::count(), 0);
        assert_eq!(event::pair_count(), 0);
        assert_eq!(timer::count(), 0);

        crate::object::reset_destroy_hooks();
    }
}
