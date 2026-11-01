//! 定时器 fd（M9a）：Linux `timerfd` 的内核侧状态。
//!
//! 每个 timerfd 绑定一个 `crate::object::ObjectKind::TimerFd` 对象，负载是本表
//! 槽位 + 1（`0` 表示未绑定）。计时复用 [`super::timer`] 的单调 deadline 与
//! 唤醒通道：`settime` 把绝对 tick deadline 交给 timer 表；tick 处理路径除调用
//! `timer::on_tick` 外**还必须调用 [`on_tick`]**，由本模块追平周期、累计未读
//! `expirations` 并唤醒等待者。
//!
//! 语义要点（Linux）：
//! - `read` 返回并清零自上次读取以来的到期次数；计数为 0 返回
//!   [`TimerFdError::WouldBlock`]，由 compat 按 `TFD_NONBLOCK` 转 `-EAGAIN` 或
//!   阻塞等待。
//! - `settime` 的 `it_value=0` 只停表，不清零尚未读取的到期次数；重新设置
//!   计时也不清。
//! - 周期定时器按绝对 deadline 追平：一次 tick 跨过多个周期时 `expirations`
//!   一次性累加，且不丢周期。
//! - 只接受 `CLOCK_MONOTONIC` / `CLOCK_BOOTTIME`；`CLOCK_REALTIME` 由 compat
//!   返回 `ENOSYS`。
//!
//! 锁纪律：本表锁内只改本表状态；`process::wake_object`、`epoll::notify_target`
//! 与 `subscription::on_target_ready/not_ready` 必须在本表锁释放后调用。

use crate::object::ObjectId;
use crate::process::{self, WakeReason};
use crate::time::monotonic_ticks;

use super::{IrqCell, payload_for_slot, slot_from_payload};

/// 同时存在的 timerfd 数量上限。
pub const MAX_TIMERFDS: usize = 8;
/// `TFD_NONBLOCK`（与 Linux ABI 一致，供 compat 使用）。
pub const TFD_NONBLOCK: u32 = 0o0004000;
/// `TFD_CLOEXEC`（与 Linux ABI 一致，供 compat 使用）。
pub const TFD_CLOEXEC: u32 = 0o2000000;
/// 本表接受的 flags 掩码。
pub const TFD_FLAGS: u32 = TFD_NONBLOCK | TFD_CLOEXEC;

/// 未绑定槽位的对象 ID。
const NO_OBJECT: ObjectId = ObjectId::MAX;

/// timerfd 支持的时钟。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TimerFdClock {
    /// `CLOCK_MONOTONIC`。
    Monotonic,
    /// `CLOCK_BOOTTIME`。
    Boottime,
}

impl TimerFdClock {
    /// 稳定调试名。
    pub const fn as_str(self) -> &'static str {
        match self {
            TimerFdClock::Monotonic => "monotonic",
            TimerFdClock::Boottime => "boottime",
        }
    }
}

/// timerfd 操作错误。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TimerFdError {
    /// 表已满。
    TableFull,
    /// 对象没有绑定 timerfd。
    NoSuchObject,
    /// 对象类型不是 `TimerFd`。
    WrongKind,
    /// 参数非法（未知 flags、周期为 0 等）。
    BadValue,
    /// 当前没有可读的到期次数。
    WouldBlock,
}

impl TimerFdError {
    /// 稳定字符串。
    pub const fn as_str(self) -> &'static str {
        match self {
            TimerFdError::TableFull => "timerfd-table-full",
            TimerFdError::NoSuchObject => "timerfd-no-such-object",
            TimerFdError::WrongKind => "timerfd-wrong-kind",
            TimerFdError::BadValue => "timerfd-bad-value",
            TimerFdError::WouldBlock => "timerfd-would-block",
        }
    }

    /// 是否表示“本刻不可读”。
    pub const fn is_would_block(self) -> bool {
        matches!(self, TimerFdError::WouldBlock)
    }
}

/// 单个 timerfd 槽位。
#[derive(Clone, Copy)]
struct TimerFdSlot {
    live: bool,
    object: ObjectId,
    timer: u64,
    clock: TimerFdClock,
    /// 当前生效的绝对 deadline（tick）；`None` 表示未武装。
    deadline: Option<u64>,
    /// 周期（tick）；`None` 表示单次。
    interval: Option<u64>,
    /// 已到期但尚未被 `read` 取走的次数。
    expirations: u64,
    nonblock: bool,
}

impl TimerFdSlot {
    const EMPTY: TimerFdSlot = TimerFdSlot {
        live: false,
        object: NO_OBJECT,
        timer: 0,
        clock: TimerFdClock::Monotonic,
        deadline: None,
        interval: None,
        expirations: 0,
        nonblock: false,
    };
}

/// timerfd 状态表。
struct TimerFdTable {
    slots: [TimerFdSlot; MAX_TIMERFDS],
    live: usize,
}

impl TimerFdTable {
    const fn new() -> Self {
        Self {
            slots: [TimerFdSlot::EMPTY; MAX_TIMERFDS],
            live: 0,
        }
    }
}

static TABLE: IrqCell<TimerFdTable> = IrqCell::new(TimerFdTable::new());

/// 由 payload 计算槽位下标。
fn slot_of(payload: u64) -> Result<usize, TimerFdError> {
    slot_from_payload(payload, MAX_TIMERFDS).map_err(|_| TimerFdError::NoSuchObject)
}

/// 由对象 ID 反查槽位下标。
fn slot_for_object(object: ObjectId) -> Result<usize, TimerFdError> {
    TABLE.with(|table| {
        let mut index = 0;
        while index < MAX_TIMERFDS {
            let entry = &table.slots[index];
            if entry.live && entry.object == object {
                return Ok(index);
            }
            index += 1;
        }
        Err(TimerFdError::NoSuchObject)
    })
}

/// 创建 timerfd 状态，返回对象负载（槽位 + 1）。
pub fn create(clock: TimerFdClock, flags: u32) -> Result<u64, TimerFdError> {
    if flags & !TFD_FLAGS != 0 {
        return Err(TimerFdError::BadValue);
    }
    let timer = super::timer::create().map_err(|_| TimerFdError::TableFull)?;
    let nonblock = flags & TFD_NONBLOCK != 0;
    let created = TABLE.with(|table| {
        let mut index = 0;
        while index < MAX_TIMERFDS {
            if !table.slots[index].live {
                table.slots[index] = TimerFdSlot {
                    live: true,
                    object: NO_OBJECT,
                    timer,
                    clock,
                    deadline: None,
                    interval: None,
                    expirations: 0,
                    nonblock,
                };
                table.live += 1;
                return Some(payload_for_slot(index));
            }
            index += 1;
        }
        None
    });
    match created {
        Some(payload) => Ok(payload),
        None => {
            let _ = super::timer::discard(timer);
            Err(TimerFdError::TableFull)
        }
    }
}

/// 把 timerfd 状态绑定到对象，并让 timer 表也指向同一对象。
pub fn bind(payload: u64, object: ObjectId) -> Result<(), TimerFdError> {
    let slot = slot_of(payload)?;
    let timer = TABLE.with(|table| table.slots[slot].timer);
    let slot_live = TABLE.with(|table| table.slots[slot].live);
    if !slot_live {
        return Err(TimerFdError::NoSuchObject);
    }
    super::timer::bind(timer, object).map_err(|_| TimerFdError::BadValue)?;
    TABLE.with(|table| table.slots[slot].object = object);
    Ok(())
}

/// 释放槽位（仅测试路径使用；对象销毁走 [`on_destroy`]）。
#[cfg(test)]
pub(crate) fn discard(payload: u64) {
    if let Ok(slot) = slot_of(payload) {
        let timer = TABLE.with(|table| {
            let entry = &mut table.slots[slot];
            if !entry.live {
                return None;
            }
            entry.live = false;
            entry.object = NO_OBJECT;
            entry.deadline = None;
            entry.interval = None;
            entry.expirations = 0;
            table.live = table.live.saturating_sub(1);
            Some(entry.timer)
        });
        if let Some(timer) = timer {
            let _ = super::timer::discard(timer);
        }
    }
}

/// 设置绝对 tick deadline 与周期；`deadline=None` 停表但保留未读计数。
pub fn settime(
    object: ObjectId,
    deadline: Option<u64>,
    interval: Option<u64>,
) -> Result<(), TimerFdError> {
    if matches!(interval, Some(0)) {
        return Err(TimerFdError::BadValue);
    }
    let slot = slot_for_object(object)?;
    let timer = TABLE.with(|table| table.slots[slot].timer);
    TABLE.with(|table| {
        let entry = &mut table.slots[slot];
        entry.deadline = deadline;
        entry.interval = interval;
    });
    super::timer::arm(timer, deadline).map_err(|_| TimerFdError::BadValue)?;
    Ok(())
}

/// 返回 `(剩余 tick, 周期 tick)`；未武装时剩余为 `None`。
pub fn gettime(object: ObjectId) -> Result<(Option<u64>, Option<u64>), TimerFdError> {
    let slot = slot_for_object(object)?;
    let clock = TABLE.with(|table| table.slots[slot].clock);
    let now = now_ticks(clock);
    Ok(TABLE.with(|table| {
        let entry = &table.slots[slot];
        let remaining = entry.deadline.map(|deadline| deadline.saturating_sub(now));
        (remaining, entry.interval)
    }))
}

/// 当前 tick 时刻。
pub fn now_ticks(_clock: TimerFdClock) -> u64 {
    monotonic_ticks()
}

/// 一次性读取并清零到期次数。
pub fn read(object: ObjectId) -> Result<u64, TimerFdError> {
    let slot = slot_for_object(object)?;
    let count = TABLE.with(|table| {
        let entry = &mut table.slots[slot];
        if entry.expirations == 0 {
            return Err(TimerFdError::WouldBlock);
        }
        let count = entry.expirations;
        entry.expirations = 0;
        Ok(count)
    })?;
    // 锁外：读空意味着不再可读，通知 epoll/subscription 重新探测。
    let _ = super::epoll::notify_target(object);
    let _ = super::subscription::on_target_not_ready(object);
    Ok(count)
}

/// 是否可读（存在未读到期次数）。
pub fn readable(object: ObjectId) -> Result<bool, TimerFdError> {
    let slot = slot_for_object(object)?;
    Ok(TABLE.with(|table| table.slots[slot].expirations != 0))
}

/// 是否处于非阻塞模式（创建时 `TFD_NONBLOCK`）。
pub fn nonblocking(object: ObjectId) -> Result<bool, TimerFdError> {
    let slot = slot_for_object(object)?;
    Ok(TABLE.with(|table| table.slots[slot].nonblock))
}

/// 存活 timerfd 数量。
pub fn live_count() -> usize {
    TABLE.with(|table| table.live)
}

/// tick 处理：追平到期、累计次数、重武装并锁外唤醒等待者。
///
/// 返回本 tick 内实际到期的 timerfd 数量。
pub fn on_tick(now: u64) -> usize {
    let mut fired = 0;
    let mut index = 0;
    while index < MAX_TIMERFDS {
        let mut wake: Option<(ObjectId, Option<u64>, u64)> = None;
        TABLE.with(|table| {
            let entry = &mut table.slots[index];
            if !entry.live {
                return;
            }
            let Some(deadline) = entry.deadline else {
                return;
            };
            if deadline > now {
                return;
            }
            let timer = entry.timer;
            let next = match entry.interval {
                Some(interval) if interval != 0 => {
                    let elapsed = now.saturating_sub(deadline);
                    let periods = 1 + elapsed / interval;
                    entry.expirations = entry.expirations.saturating_add(periods);
                    let next = deadline.saturating_add(periods.saturating_mul(interval));
                    entry.deadline = Some(next);
                    Some(next)
                }
                _ => {
                    entry.expirations = entry.expirations.saturating_add(1);
                    entry.deadline = None;
                    None
                }
            };
            wake = Some((entry.object, next, timer));
            fired += 1;
        });
        if let Some((object, next, timer)) = wake {
            let _ = super::timer::arm(timer, next);
            if object != NO_OBJECT {
                let _ = process::wake_object(object, WakeReason::Ready);
                let _ = super::epoll::notify_target(object);
                let _ = super::subscription::on_target_ready(object);
            }
        }
        index += 1;
    }
    fired
}

/// 对象销毁钩子：清槽并锁外唤醒/通知。
pub fn on_destroy(object: ObjectId) {
    let timer = TABLE.with(|table| {
        let mut timer = None;
        let mut index = 0;
        while index < MAX_TIMERFDS {
            let entry = &mut table.slots[index];
            if entry.live && entry.object == object {
                timer = Some(entry.timer);
                entry.live = false;
                entry.object = NO_OBJECT;
                entry.deadline = None;
                entry.interval = None;
                entry.expirations = 0;
                table.live = table.live.saturating_sub(1);
            }
            index += 1;
        }
        timer
    });
    if let Some(timer) = timer {
        let _ = super::timer::discard(timer);
    }
    let _ = process::wake_object(object, WakeReason::Destroyed);
    let _ = super::epoll::notify_target(object);
    let _ = super::subscription::on_target_destroy(object);
}

/// 测试用：清空表。
#[cfg(test)]
pub(crate) fn reset_for_test() {
    TABLE.with(|table| {
        *table = TimerFdTable::new();
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
        super::super::timer::reset_for_test();
        guard
    }

    fn bound(clock: TimerFdClock, flags: u32, object: ObjectId) -> u64 {
        let payload = create(clock, flags).expect("create");
        bind(payload, object).expect("bind");
        payload
    }

    #[test]
    fn read_returns_and_clears_expirations() {
        let _guard = setup();
        let object = 0x0301;
        bound(TimerFdClock::Monotonic, 0, object);
        settime(object, Some(monotonic_ticks() + 2), None).expect("settime");
        on_tick(monotonic_ticks() + 2);
        assert_eq!(read(object), Ok(1));
        assert_eq!(read(object), Err(TimerFdError::WouldBlock));
        assert_eq!(readable(object), Ok(false));
    }

    #[test]
    fn periodic_expirations_accumulate_without_loss() {
        let _guard = setup();
        let object = 0x0302;
        bound(TimerFdClock::Monotonic, 0, object);
        let base = monotonic_ticks();
        settime(object, Some(base + 3), Some(2)).expect("settime");
        on_tick(base + 3);
        assert_eq!(read(object), Ok(1));
        on_tick(base + 30);
        assert!(read(object).unwrap() >= 1);
    }

    #[test]
    fn disarm_keeps_pending_expirations() {
        let _guard = setup();
        let object = 0x0303;
        bound(TimerFdClock::Monotonic, 0, object);
        let now = monotonic_ticks();
        settime(object, Some(now + 1), None).expect("settime");
        on_tick(now + 1);
        settime(object, None, None).expect("disarm");
        assert_eq!(read(object), Ok(1));
    }

    #[test]
    fn invalid_flags_and_interval_are_rejected() {
        let _guard = setup();
        assert_eq!(
            create(TimerFdClock::Monotonic, 0xdead),
            Err(TimerFdError::BadValue)
        );
        let object = 0x0304;
        bound(TimerFdClock::Boottime, TFD_NONBLOCK, object);
        assert_eq!(settime(object, None, Some(0)), Err(TimerFdError::BadValue));
        assert!(nonblocking(object).unwrap());
    }

    #[test]
    fn destroy_releases_the_slot() {
        let _guard = setup();
        let object = 0x0305;
        let payload = bound(TimerFdClock::Monotonic, 0, object);
        assert_eq!(live_count(), 1);
        on_destroy(object);
        assert_eq!(live_count(), 0);
        discard(payload);
    }
}
