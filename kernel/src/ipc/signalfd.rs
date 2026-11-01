//! 信号 fd（M9a）：Linux `signalfd` 的内核侧状态。
//!
//! 每个 signalfd 绑定一个 `crate::object::ObjectKind::SignalFd` 对象，负载是本表
//! 槽位 + 1（`0` 表示未绑定）。实例记录归属进程与屏蔽字，就绪信号由
//! `process::signal_pending_for`（真实 pending & 屏蔽字 & blocked）查询，
//! `read` 通过 `process::signal_take_pending_for` 原子取走一个命中信号。
//!
//! 唤醒契约（与 `process` 侧约定）：`process` 在真正把信号写入 pending 之后、
//! 释放进程表锁之后调用 [`on_signal_pending`]；本模块随后锁外唤醒等待对象并
//! 通知 epoll（[`super::epoll::notify_target`]）与订阅者。
//!
//! 最小 siginfo：只保证 `signo`，`sender_pid` 暂固定为 0（完整 siginfo 留给
//! 后续切片）。
//!
//! 锁纪律：本表锁内只改本表状态；`process::*`、`epoll::notify_target` 与
//! `subscription::on_target_ready/not_ready` 必须在本表锁释放后调用。

use crate::object::ObjectId;
use crate::process::{self, ProcessId, WakeReason};

use super::{IrqCell, payload_for_slot, slot_from_payload};

/// 同时存在的 signalfd 数量上限。
pub const MAX_SIGNALFDS: usize = 8;
/// `SFD_NONBLOCK`（与 Linux ABI 一致，供 compat 使用）。
pub const SFD_NONBLOCK: u32 = 0o0004000;
/// `SFD_CLOEXEC`（与 Linux ABI 一致，供 compat 使用）。
pub const SFD_CLOEXEC: u32 = 0o2000000;
/// 本表接受的 flags 掩码。
pub const SFD_FLAGS: u32 = SFD_NONBLOCK | SFD_CLOEXEC;
/// 支持的信号位：signo 1..=31 ↔ bit0..30（bit31 保留）。
pub const SIGNAL_MASK: u64 = (1u64 << 31) - 1;

/// 未绑定槽位的对象 ID。
const NO_OBJECT: ObjectId = ObjectId::MAX;

/// signalfd 操作错误。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SignalFdError {
    /// 表已满。
    TableFull,
    /// 对象没有绑定 signalfd。
    NoSuchObject,
    /// 对象类型不是 `SignalFd`。
    WrongKind,
    /// 参数非法（未知 flags、mask 含 bit31 等）。
    BadValue,
    /// 当前没有可读信号。
    WouldBlock,
}

impl SignalFdError {
    /// 稳定字符串。
    pub const fn as_str(self) -> &'static str {
        match self {
            SignalFdError::TableFull => "signalfd-table-full",
            SignalFdError::NoSuchObject => "signalfd-no-such-object",
            SignalFdError::WrongKind => "signalfd-wrong-kind",
            SignalFdError::BadValue => "signalfd-bad-value",
            SignalFdError::WouldBlock => "signalfd-would-block",
        }
    }

    /// 是否表示“本刻不可读”。
    pub const fn is_would_block(self) -> bool {
        matches!(self, SignalFdError::WouldBlock)
    }
}

/// 最小 siginfo。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SignalRecord {
    /// 信号编号（1..=31）。
    pub signo: u32,
    /// 发送者进程号；最小实现固定为 0。
    pub sender_pid: u32,
}

/// 单个 signalfd 槽位。
#[derive(Clone, Copy)]
struct SignalFdSlot {
    live: bool,
    object: ObjectId,
    owner: Option<ProcessId>,
    mask: u64,
    nonblock: bool,
}

impl SignalFdSlot {
    const EMPTY: SignalFdSlot = SignalFdSlot {
        live: false,
        object: NO_OBJECT,
        owner: None,
        mask: 0,
        nonblock: false,
    };
}

/// signalfd 状态表。
struct SignalFdTable {
    slots: [SignalFdSlot; MAX_SIGNALFDS],
    live: usize,
}

impl SignalFdTable {
    const fn new() -> Self {
        Self {
            slots: [SignalFdSlot::EMPTY; MAX_SIGNALFDS],
            live: 0,
        }
    }
}

static TABLE: IrqCell<SignalFdTable> = IrqCell::new(SignalFdTable::new());

/// 由 payload 计算槽位下标。
fn slot_of(payload: u64) -> Result<usize, SignalFdError> {
    slot_from_payload(payload, MAX_SIGNALFDS).map_err(|_| SignalFdError::NoSuchObject)
}

/// 由对象 ID 反查槽位下标。
fn slot_for_object(object: ObjectId) -> Result<usize, SignalFdError> {
    TABLE.with(|table| {
        let mut index = 0;
        while index < MAX_SIGNALFDS {
            let entry = &table.slots[index];
            if entry.live && entry.object == object {
                return Ok(index);
            }
            index += 1;
        }
        Err(SignalFdError::NoSuchObject)
    })
}

/// 规范化屏蔽字：只保留支持信号位。
fn normalize_mask(mask: u64) -> Result<u64, SignalFdError> {
    if mask & !SIGNAL_MASK != 0 {
        return Err(SignalFdError::BadValue);
    }
    Ok(mask & SIGNAL_MASK)
}

/// 创建 signalfd 状态，返回对象负载（槽位 + 1）。
pub fn create(owner: ProcessId, mask: u64, flags: u32) -> Result<u64, SignalFdError> {
    if flags & !SFD_FLAGS != 0 {
        return Err(SignalFdError::BadValue);
    }
    let mask = normalize_mask(mask)?;
    let nonblock = flags & SFD_NONBLOCK != 0;
    TABLE.with(|table| {
        let mut index = 0;
        while index < MAX_SIGNALFDS {
            if !table.slots[index].live {
                table.slots[index] = SignalFdSlot {
                    live: true,
                    object: NO_OBJECT,
                    owner: Some(owner),
                    mask,
                    nonblock,
                };
                table.live += 1;
                return Ok(payload_for_slot(index));
            }
            index += 1;
        }
        Err(SignalFdError::TableFull)
    })
}

/// 把 signalfd 状态绑定到对象。
pub fn bind(payload: u64, object: ObjectId) -> Result<(), SignalFdError> {
    let slot = slot_of(payload)?;
    TABLE.with(|table| {
        let entry = &mut table.slots[slot];
        if !entry.live {
            return Err(SignalFdError::NoSuchObject);
        }
        if entry.object != NO_OBJECT && entry.object != object {
            return Err(SignalFdError::BadValue);
        }
        entry.object = object;
        Ok(())
    })
}

/// 释放槽位（仅测试路径使用；对象销毁走 [`on_destroy`]）。
#[cfg(test)]
pub(crate) fn discard(payload: u64) {
    if let Ok(slot) = slot_of(payload) {
        TABLE.with(|table| {
            let entry = &mut table.slots[slot];
            if entry.live {
                entry.live = false;
                entry.object = NO_OBJECT;
                entry.mask = 0;
                table.live = table.live.saturating_sub(1);
            }
        });
    }
}

/// 更新信号屏蔽字；就绪状态变化后锁外通知 epoll/订阅者。
pub fn update_mask(object: ObjectId, mask: u64) -> Result<(), SignalFdError> {
    let mask = normalize_mask(mask)?;
    let slot = slot_for_object(object)?;
    let owner = TABLE.with(|table| table.slots[slot].owner);
    let Some(owner) = owner else {
        return Err(SignalFdError::NoSuchObject);
    };
    TABLE.with(|table| table.slots[slot].mask = mask);
    finish_notify(object, owner, mask);
    Ok(())
}

/// 读取一个就绪信号；`WouldBlock` 由 compat 按 `SFD_NONBLOCK` 转 `-EAGAIN`
/// 或阻塞等待。
pub fn read(object: ObjectId) -> Result<SignalRecord, SignalFdError> {
    let slot = slot_for_object(object)?;
    let (owner, mask) = TABLE.with(|table| {
        let entry = &table.slots[slot];
        (entry.owner, entry.mask)
    });
    let Some(owner) = owner else {
        return Err(SignalFdError::NoSuchObject);
    };
    match process::signal_take_pending_for(owner, mask) {
        Some(signo) => {
            finish_notify(object, owner, mask);
            Ok(SignalRecord {
                signo,
                sender_pid: 0,
            })
        }
        None => Err(SignalFdError::WouldBlock),
    }
}

/// 是否可读。
pub fn readable(object: ObjectId) -> Result<bool, SignalFdError> {
    let slot = slot_for_object(object)?;
    let (owner, mask) = TABLE.with(|table| {
        let entry = &table.slots[slot];
        (entry.owner, entry.mask)
    });
    let Some(owner) = owner else {
        return Err(SignalFdError::NoSuchObject);
    };
    Ok(process::signal_pending_for(owner, mask) != 0)
}

/// 是否处于非阻塞模式（创建时 `SFD_NONBLOCK`）。
pub fn nonblocking(object: ObjectId) -> Result<bool, SignalFdError> {
    let slot = slot_for_object(object)?;
    Ok(TABLE.with(|table| table.slots[slot].nonblock))
}

/// 存活 signalfd 数量。
pub fn live_count() -> usize {
    TABLE.with(|table| table.live)
}

/// `process` 在 pending 位图变化后调用：唤醒该进程的所有 signalfd 对象。
///
/// 调用点保证不持进程表锁；本函数锁外唤醒，可重入。
pub fn on_signal_pending(owner: ProcessId) -> usize {
    let mut woken = 0;
    let mut index = 0;
    while index < MAX_SIGNALFDS {
        let object = TABLE.with(|table| {
            let entry = &table.slots[index];
            (entry.live && entry.object != NO_OBJECT && entry.owner == Some(owner))
                .then_some(entry.object)
        });
        if let Some(object) = object {
            let _ = process::wake_object(object, WakeReason::Ready);
            let _ = super::epoll::notify_target(object);
            woken += 1;
        }
        index += 1;
    }
    woken
}

/// 就绪状态变化后，锁外通知 epoll 与订阅者。
fn finish_notify(object: ObjectId, owner: ProcessId, mask: u64) {
    let ready = process::signal_pending_for(owner, mask) != 0;
    let _ = super::epoll::notify_target(object);
    if ready {
        let _ = super::subscription::on_target_ready(object);
    } else {
        let _ = super::subscription::on_target_not_ready(object);
    }
}

/// 对象销毁钩子：清槽并锁外唤醒/通知。
pub fn on_destroy(object: ObjectId) {
    TABLE.with(|table| {
        let mut index = 0;
        while index < MAX_SIGNALFDS {
            let entry = &mut table.slots[index];
            if entry.live && entry.object == object {
                entry.live = false;
                entry.object = NO_OBJECT;
                entry.mask = 0;
                table.live = table.live.saturating_sub(1);
            }
            index += 1;
        }
    });
    let _ = process::wake_object(object, WakeReason::Destroyed);
    let _ = super::epoll::notify_target(object);
    let _ = super::subscription::on_target_destroy(object);
}

/// 测试用：清空表。
#[cfg(test)]
pub(crate) fn reset_for_test() {
    TABLE.with(|table| {
        *table = SignalFdTable::new();
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lock() -> std::sync::MutexGuard<'static, ()> {
        crate::object::test_lock()
    }

    fn setup() -> std::sync::MutexGuard<'static, ()> {
        let guard = lock();
        reset_for_test();
        guard
    }

    fn owner() -> Option<ProcessId> {
        process::current()
    }

    #[test]
    fn invalid_flags_and_mask_are_rejected() {
        let _guard = setup();
        let Some(owner) = owner() else {
            return;
        };
        assert_eq!(create(owner, 0, 0xdead), Err(SignalFdError::BadValue));
        assert_eq!(create(owner, 1u64 << 40, 0), Err(SignalFdError::BadValue));
        assert_eq!(create(owner, 1u64 << 31, 0), Err(SignalFdError::BadValue));
    }

    #[test]
    fn create_bind_update_and_destroy() {
        let _guard = setup();
        let Some(owner) = owner() else {
            return;
        };
        let object = 0x0701u16;
        assert_eq!(live_count(), 0);
        let payload = create(owner, 0x0100, SFD_NONBLOCK).expect("create");
        bind(payload, object).expect("bind");
        assert_eq!(live_count(), 1);
        assert!(nonblocking(object).unwrap());
        update_mask(object, 0x0004).expect("update");
        on_destroy(object);
        assert_eq!(live_count(), 0);
        discard(payload);
    }

    #[test]
    fn unbound_objects_report_no_such_object() {
        let _guard = setup();
        assert_eq!(readable(0x0777), Err(SignalFdError::NoSuchObject));
        assert_eq!(read(0x0777), Err(SignalFdError::NoSuchObject));
    }
}
