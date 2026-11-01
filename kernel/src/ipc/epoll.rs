//! epoll 实例（M9a）：Linux `epoll_create1/ctl/wait` 的内核侧兴趣集合。
//!
//! 每个 epoll 实例绑定一个 `crate::object::ObjectKind::Epoll` 对象，负载是本表
//! 槽位 + 1（`0` 表示未绑定）。一个实例最多登记 [`MAX_EPOLL_INTERESTS`] 个
//! 目标对象；每个兴趣记录目标 `ObjectId`、用户事件掩码与用户数据。兴趣集合
//! 不持有目标对象引用（Linux 的自动移除语义由 compat 的 close 路径负责）。
//!
//! 就绪与唤醒：
//! - 每个可等待对象在就绪状态变化处调用 [`notify_target`]；本模块找到登记了
//!   该目标的实例、清空其 ET 边沿缓存并锁外 `process::wake_object` 唤醒等待者。
//! - LT 用 [`snapshot`] 每次重新计算全部就绪项；ET（`EPOLLET`）用 [`scan`] 或
//!   [`scan_with`]，内核为每个兴趣维护 `observed` 边沿缓存，只报告新出现的
//!   就绪位。探测函数由调用方提供（Socket 用 compat 的 `net::poll` 映射）。
//! - Socket 目标由 `net` 的 wake hook 统一通知（`eventfd`/`timerfd`/`signalfd`
//!   等模块直接调用本模块），就绪掩码由 compat 对 Socket 另行查询 `net::poll`。
//! - `EPOLLONESHOT` 的 disarm 仍由 compat 在取走事件后经 `ctl_mod`/`ctl_del`
//!   完成；本模块只保证这两个入口重置边沿缓存。
//!
//! 锁纪律：本表锁内只改本表状态；`process::wake_object` 与跨表就绪探测必须在
//! 释放本表锁之后进行，禁止持本表锁读取其它 IPC 表。

use crate::object::ObjectId;
use crate::process::{self, WakeReason};

use super::{IrqCell, payload_for_slot, slot_from_payload};

/// 同时存在的 epoll 实例数量上限。
pub const MAX_EPOLLS: usize = 2;
/// 单个实例的兴趣数量上限。
pub const MAX_EPOLL_INTERESTS: usize = 8;

/// `EPOLLIN`。
pub const EPOLLIN: u32 = 0x1;
/// `EPOLLOUT`。
pub const EPOLLOUT: u32 = 0x4;
/// `EPOLLERR`。
pub const EPOLLERR: u32 = 0x8;
/// `EPOLLHUP`。
pub const EPOLLHUP: u32 = 0x10;
/// `EPOLLRDHUP`。
pub const EPOLLRDHUP: u32 = 0x2000;
/// `EPOLLONESHOT`。
pub const EPOLLONESHOT: u32 = 1 << 30;
/// `EPOLLET`。
pub const EPOLLET: u32 = 1 << 31;

/// 未绑定槽位的对象 ID。
const NO_OBJECT: ObjectId = ObjectId::MAX;

/// epoll 操作错误。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EpollError {
    /// 实例表已满。
    TableFull,
    /// 对象没有绑定 epoll 实例。
    NoSuchObject,
    /// 对象类型不是 `Epoll`。
    WrongKind,
    /// 目标已登记（`EEXIST`）。
    AlreadyExists,
    /// 目标未登记（`ENOENT`）。
    NotFound,
    /// 兴趣表已满（`ENOSPC`）。
    NoSpace,
    /// 参数非法。
    BadValue,
}

impl EpollError {
    /// 稳定字符串。
    pub const fn as_str(self) -> &'static str {
        match self {
            EpollError::TableFull => "epoll-table-full",
            EpollError::NoSuchObject => "epoll-no-such-object",
            EpollError::WrongKind => "epoll-wrong-kind",
            EpollError::AlreadyExists => "epoll-already-exists",
            EpollError::NotFound => "epoll-not-found",
            EpollError::NoSpace => "epoll-no-space",
            EpollError::BadValue => "epoll-bad-value",
        }
    }
}

/// 单个兴趣项。
#[derive(Clone, Copy)]
struct EpollInterest {
    target: ObjectId,
    events: u32,
    data: u64,
    /// ET 边沿缓存：上次扫描已报告过的就绪掩码。
    ///
    /// 只有带 `EPOLLET` 的兴趣使用它；不带 `EPOLLET` 时恒为 0。目标完全不再
    /// 就绪、`notify_target` 通知有新活动、`ctl_mod`/`ctl_del` 都会清零。
    observed: u32,
}

/// 单个 epoll 实例槽位。
struct EpollSlot {
    live: bool,
    object: ObjectId,
    interests: [Option<EpollInterest>; MAX_EPOLL_INTERESTS],
    count: usize,
}

impl EpollSlot {
    const EMPTY: EpollSlot = EpollSlot {
        live: false,
        object: NO_OBJECT,
        interests: [None; MAX_EPOLL_INTERESTS],
        count: 0,
    };
}

/// epoll 实例表。
struct EpollTable {
    slots: [EpollSlot; MAX_EPOLLS],
    live: usize,
}

impl EpollTable {
    const fn new() -> Self {
        Self {
            slots: [EpollSlot::EMPTY; MAX_EPOLLS],
            live: 0,
        }
    }
}

static TABLE: IrqCell<EpollTable> = IrqCell::new(EpollTable::new());

/// 由 payload 计算槽位下标。
fn slot_of(payload: u64) -> Result<usize, EpollError> {
    slot_from_payload(payload, MAX_EPOLLS).map_err(|_| EpollError::NoSuchObject)
}

/// 由对象 ID 反查槽位下标。
fn slot_for_object(object: ObjectId) -> Result<usize, EpollError> {
    TABLE.with(|table| {
        let mut index = 0;
        while index < MAX_EPOLLS {
            let entry = &table.slots[index];
            if entry.live && entry.object == object {
                return Ok(index);
            }
            index += 1;
        }
        Err(EpollError::NoSuchObject)
    })
}

/// 创建 epoll 实例状态，返回对象负载（槽位 + 1）。
pub fn create() -> Result<u64, EpollError> {
    TABLE.with(|table| {
        let mut index = 0;
        while index < MAX_EPOLLS {
            if !table.slots[index].live {
                table.slots[index] = EpollSlot::EMPTY;
                table.slots[index].live = true;
                table.live += 1;
                return Ok(payload_for_slot(index));
            }
            index += 1;
        }
        Err(EpollError::TableFull)
    })
}

/// 把实例状态绑定到对象。
pub fn bind(payload: u64, object: ObjectId) -> Result<(), EpollError> {
    let slot = slot_of(payload)?;
    TABLE.with(|table| {
        let entry = &mut table.slots[slot];
        if !entry.live {
            return Err(EpollError::NoSuchObject);
        }
        if entry.object != NO_OBJECT && entry.object != object {
            return Err(EpollError::BadValue);
        }
        entry.object = object;
        Ok(())
    })
}

/// 登记兴趣（ADD）；目标已存在返回 [`EpollError::AlreadyExists`]。
pub fn ctl_add(
    object: ObjectId,
    target: ObjectId,
    events: u32,
    data: u64,
) -> Result<(), EpollError> {
    ctl_edit(object, target, events, data, false)
}

/// 修改兴趣（MOD）；目标不存在返回 [`EpollError::NotFound`]。
pub fn ctl_mod(
    object: ObjectId,
    target: ObjectId,
    events: u32,
    data: u64,
) -> Result<(), EpollError> {
    ctl_edit(object, target, events, data, true)
}

fn ctl_edit(
    object: ObjectId,
    target: ObjectId,
    events: u32,
    data: u64,
    modify: bool,
) -> Result<(), EpollError> {
    let slot = slot_for_object(object)?;
    TABLE.with(|table| {
        let entry = &mut table.slots[slot];
        let mut index = 0;
        while index < MAX_EPOLL_INTERESTS {
            if let Some(interest) = entry.interests[index] {
                if interest.target == target {
                    if !modify {
                        return Err(EpollError::AlreadyExists);
                    }
                    // MOD 重新武装：边沿缓存清零，下一次扫描重新报告当前就绪。
                    entry.interests[index] = Some(EpollInterest {
                        target,
                        events,
                        data,
                        observed: 0,
                    });
                    return Ok(());
                }
            }
            index += 1;
        }
        if modify {
            return Err(EpollError::NotFound);
        }
        if entry.count >= MAX_EPOLL_INTERESTS {
            return Err(EpollError::NoSpace);
        }
        index = 0;
        while index < MAX_EPOLL_INTERESTS {
            if entry.interests[index].is_none() {
                entry.interests[index] = Some(EpollInterest {
                    target,
                    events,
                    data,
                    observed: 0,
                });
                entry.count += 1;
                return Ok(());
            }
            index += 1;
        }
        Err(EpollError::NoSpace)
    })
}

/// 删除兴趣（DEL）。
pub fn ctl_del(object: ObjectId, target: ObjectId) -> Result<(), EpollError> {
    let slot = slot_for_object(object)?;
    TABLE.with(|table| {
        let entry = &mut table.slots[slot];
        let mut index = 0;
        while index < MAX_EPOLL_INTERESTS {
            if let Some(interest) = entry.interests[index] {
                if interest.target == target {
                    entry.interests[index] = None;
                    entry.count = entry.count.saturating_sub(1);
                    return Ok(());
                }
            }
            index += 1;
        }
        Err(EpollError::NotFound)
    })
}

/// 目标状态变化：清空 ET 边沿缓存并唤醒登记了该目标的实例，返回被唤醒的实例数。
pub fn notify_target(target: ObjectId) -> usize {
    let mut notified = 0;
    let mut index = 0;
    while index < MAX_EPOLLS {
        let object = TABLE.with(|table| {
            let entry = &mut table.slots[index];
            if !entry.live {
                return None;
            }
            let mut registered = false;
            for interest in entry.interests.iter_mut().flatten() {
                if interest.target == target {
                    // 目标出现新活动：清空 ET latch，下一次扫描重新报告边沿。
                    interest.observed = 0;
                    registered = true;
                }
            }
            registered.then_some(entry.object)
        });
        if let Some(object) = object {
            let _ = process::wake_object(object, WakeReason::Ready);
            notified += 1;
        }
        index += 1;
    }
    notified
}

/// 单个目标的当前就绪掩码（仅限 IPC 对象；Socket 由 compat 查询 `net`）。
pub fn target_readiness(target: ObjectId) -> u32 {
    let mut mask = 0;
    if let Ok(readable) = super::eventfd::readable(target) {
        if readable {
            mask |= EPOLLIN;
        }
        if matches!(super::eventfd::writable(target), Ok(true)) {
            mask |= EPOLLOUT;
        }
        return mask;
    }
    if let Ok(readable) = super::timerfd::readable(target) {
        return if readable { EPOLLIN } else { 0 };
    }
    if let Ok(readable) = super::signalfd::readable(target) {
        return if readable { EPOLLIN } else { 0 };
    }
    if matches!(super::poll_waitable_keyed(target, 0, false), Ok(true)) {
        mask |= EPOLLIN;
    }
    mask
}

/// 就绪事件输出（`object_key` 编码目标低 32 位 + key，`events` 为掩码）。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReadyEvent {
    /// 目标对象 ID。
    pub target: ObjectId,
    /// 用户数据。
    pub data: u64,
    /// 就绪掩码（`EPOLLIN`/`EPOLLOUT`/...）。
    pub events: u32,
}

/// 收集当前就绪的兴趣，写入 `out`，返回写入数量。
///
/// 先在锁内复制兴趣，再在锁外探测目标就绪，避免持本表锁读其它表。
pub fn snapshot(object: ObjectId, out: &mut [ReadyEvent]) -> Result<usize, EpollError> {
    let slot = slot_for_object(object)?;
    let mut interests = [None; MAX_EPOLL_INTERESTS];
    let mut count = 0;
    TABLE.with(|table| {
        interests = table.slots[slot].interests;
        count = table.slots[slot].count;
    });
    let mut written = 0;
    let mut index = 0;
    while index < MAX_EPOLL_INTERESTS && written < out.len() {
        if let Some(interest) = interests[index] {
            let ready = target_readiness(interest.target) & interest.events;
            if ready != 0 {
                out[written] = ReadyEvent {
                    target: interest.target,
                    data: interest.data,
                    events: ready,
                };
                written += 1;
            }
        }
        index += 1;
    }
    let _ = count;
    Ok(written)
}

/// 用调用方提供的 `probe` 扫描一次就绪（M9b：按兴趣的 `EPOLLET` 位区分 ET/LT）。
///
/// `probe` 返回目标对象的当前就绪掩码；compat 用它对 Socket 调 `net::poll` 并
/// 映射为 `EPOLLIN`/`EPOLLOUT`/`EPOLLERR`（本模块不依赖 `net`）。带 `EPOLLET`
/// 的兴趣只有相对 `observed` 的新比特才产生事件，目标完全不再就绪时清空缓存；
/// 不带 `EPOLLET` 的兴趣按 LT 每次就绪都报告。探测在表锁外进行，回锁后只更新
/// 边沿缓存并组装输出，避免持本表锁读其它表。
///
/// `EPOLLONESHOT` 的 disarm 由 compat 在取走事件后经 `ctl_mod`/`ctl_del` 完成。
pub fn scan_with(
    object: ObjectId,
    out: &mut [ReadyEvent],
    probe: fn(ObjectId) -> u32,
) -> Result<usize, EpollError> {
    let slot = slot_for_object(object)?;
    let mut interests = [None; MAX_EPOLL_INTERESTS];
    TABLE.with(|table| {
        interests = table.slots[slot].interests;
    });
    let mut probed = [0u32; MAX_EPOLL_INTERESTS];
    let mut index = 0;
    while index < MAX_EPOLL_INTERESTS {
        if let Some(interest) = interests[index] {
            probed[index] = probe(interest.target) & interest.events;
        }
        index += 1;
    }
    let mut written = 0;
    TABLE.with(|table| {
        let entry = &mut table.slots[slot];
        let mut index = 0;
        while index < MAX_EPOLL_INTERESTS && written < out.len() {
            if let Some(interest) = entry.interests[index].as_mut() {
                let mut ready = 0;
                let mut snap = 0;
                while snap < MAX_EPOLL_INTERESTS {
                    if let Some(candidate) = interests[snap] {
                        if candidate.target == interest.target {
                            ready = probed[snap];
                            break;
                        }
                    }
                    snap += 1;
                }
                if interest.events & EPOLLET != 0 {
                    let new_bits = ready & !interest.observed;
                    interest.observed = ready;
                    if new_bits != 0 {
                        out[written] = ReadyEvent {
                            target: interest.target,
                            data: interest.data,
                            events: ready,
                        };
                        written += 1;
                    }
                } else if ready != 0 {
                    out[written] = ReadyEvent {
                        target: interest.target,
                        data: interest.data,
                        events: ready,
                    };
                    written += 1;
                }
            }
            index += 1;
        }
    });
    Ok(written)
}

/// 用内置 [`target_readiness`] 探测的 [`scan_with`] 包装（非 Socket 目标）。
pub fn scan(object: ObjectId, out: &mut [ReadyEvent]) -> Result<usize, EpollError> {
    scan_with(object, out, target_readiness)
}

/// 是否至少有一个兴趣就绪。
pub fn any_ready(object: ObjectId) -> Result<bool, EpollError> {
    let slot = slot_for_object(object)?;
    let mut interests = [None; MAX_EPOLL_INTERESTS];
    TABLE.with(|table| {
        interests = table.slots[slot].interests;
    });
    for interest in interests.iter().flatten() {
        if target_readiness(interest.target) & interest.events != 0 {
            return Ok(true);
        }
    }
    Ok(false)
}

/// 兴趣数量。
pub fn interest_count(object: ObjectId) -> Result<usize, EpollError> {
    let slot = slot_for_object(object)?;
    Ok(TABLE.with(|table| table.slots[slot].count))
}

/// 存活实例数量。
pub fn live_count() -> usize {
    TABLE.with(|table| table.live)
}

/// 对象销毁钩子：清槽并锁外唤醒等待者/通知订阅者。
pub fn on_destroy(object: ObjectId) {
    TABLE.with(|table| {
        let mut index = 0;
        while index < MAX_EPOLLS {
            let entry = &mut table.slots[index];
            if entry.live && entry.object == object {
                entry.live = false;
                entry.object = NO_OBJECT;
                entry.interests = [None; MAX_EPOLL_INTERESTS];
                entry.count = 0;
                table.live = table.live.saturating_sub(1);
            }
            index += 1;
        }
    });
    let _ = process::wake_object(object, WakeReason::Destroyed);
    let _ = super::subscription::on_target_destroy(object);
}

/// 把登记的兴趣**原样**复制到 `out`，返回写入条数（不探测就绪）。
///
/// `ReadyEvent.events` 是登记时的原始掩码，`data` 是用户数据。compat 拿到这份
/// 原始列表后自行计算就绪（Socket 用 `net::poll` 映射 IN/OUT/ERR，其它对象用
/// [`target_readiness`]），再与掩码求交，因此 `ipc` 层不必依赖 `net`。
pub fn interests(object: ObjectId, out: &mut [ReadyEvent]) -> Result<usize, EpollError> {
    let slot = slot_for_object(object)?;
    let mut written = 0;
    TABLE.with(|table| {
        let entry = &table.slots[slot];
        let mut index = 0;
        while index < MAX_EPOLL_INTERESTS && written < out.len() {
            if let Some(interest) = entry.interests[index] {
                out[written] = ReadyEvent {
                    target: interest.target,
                    data: interest.data,
                    events: interest.events,
                };
                written += 1;
            }
            index += 1;
        }
    });
    Ok(written)
}

/// 目标对象被销毁：从所有实例中移除指向它的兴趣，并唤醒受影响实例的等待者。
///
/// 返回移除的兴趣总数。对象层销毁钩子在对象表锁外调用本函数；本函数在本表锁
/// 释放后才 `wake_object`，可重入且不回调对象表。ObjectId 会复用，因此销毁
/// 路径必须走到这里，compat 的 close 兜底只是补充而非必需。
pub fn on_target_destroy(target: ObjectId) -> usize {
    let mut removed = 0;
    let mut index = 0;
    while index < MAX_EPOLLS {
        let mut affected = None;
        TABLE.with(|table| {
            let entry = &mut table.slots[index];
            if !entry.live {
                return;
            }
            let mut interest_index = 0;
            let mut local = 0;
            while interest_index < MAX_EPOLL_INTERESTS {
                if let Some(interest) = entry.interests[interest_index] {
                    if interest.target == target {
                        entry.interests[interest_index] = None;
                        entry.count = entry.count.saturating_sub(1);
                        local += 1;
                    }
                }
                interest_index += 1;
            }
            if local > 0 {
                affected = Some(entry.object);
                removed += local;
            }
        });
        if let Some(object) = affected {
            let _ = process::wake_object(object, WakeReason::Ready);
        }
        index += 1;
    }
    removed
}
/// 测试用：清空表。
#[cfg(test)]
pub(crate) fn reset_for_test() {
    TABLE.with(|table| {
        *table = EpollTable::new();
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
        super::super::eventfd::reset_for_test();
        super::super::timerfd::reset_for_test();
        super::super::signalfd::reset_for_test();
        guard
    }

    fn bound_set() -> ObjectId {
        let object = 0x0501;
        let payload = create().expect("create");
        bind(payload, object).expect("bind");
        object
    }

    #[test]
    fn add_mod_del_and_duplicate_errors() {
        let _guard = setup();
        let epoll = bound_set();
        let target = 0x0502;
        assert_eq!(ctl_add(epoll, target, EPOLLIN, 7), Ok(()));
        assert_eq!(
            ctl_add(epoll, target, EPOLLIN, 7),
            Err(EpollError::AlreadyExists)
        );
        assert_eq!(interest_count(epoll), Ok(1));
        assert_eq!(ctl_mod(epoll, target, EPOLLIN | EPOLLOUT, 9), Ok(()));
        assert_eq!(ctl_del(epoll, target), Ok(()));
        assert_eq!(ctl_del(epoll, target), Err(EpollError::NotFound));
    }

    #[test]
    fn interest_capacity_is_enforced() {
        let _guard = setup();
        let epoll = bound_set();
        let mut index = 0;
        while index < MAX_EPOLL_INTERESTS {
            let target = 0x0600 + index as ObjectId;
            assert_eq!(ctl_add(epoll, target, EPOLLIN, index as u64), Ok(()));
            index += 1;
        }
        assert_eq!(ctl_add(epoll, 0x0680, EPOLLIN, 0), Err(EpollError::NoSpace));
    }

    #[test]
    fn snapshot_reports_ready_eventfds() {
        let _guard = setup();
        let epoll = bound_set();
        let target = 0x0503;
        let payload = super::super::eventfd::create(0, 0).expect("eventfd");
        super::super::eventfd::bind(payload, target).expect("bind");
        super::super::eventfd::write(target, 1).expect("write");
        ctl_add(epoll, target, EPOLLIN, 42).expect("add");
        let mut out = [ReadyEvent {
            target: 0,
            data: 0,
            events: 0,
        }; MAX_EPOLL_INTERESTS];
        assert_eq!(snapshot(epoll, &mut out), Ok(1));
        assert_eq!(out[0].data, 42);
        assert_eq!(out[0].events & EPOLLIN, EPOLLIN);
    }

    #[test]
    fn notify_target_counts_registered_sets() {
        let _guard = setup();
        let epoll = bound_set();
        let target = 0x0504;
        assert_eq!(notify_target(target), 0);
        ctl_add(epoll, target, EPOLLIN, 0).expect("add");
        assert_eq!(notify_target(target), 1);
        ctl_del(epoll, target).expect("del");
        assert_eq!(notify_target(target), 0);
    }
}

#[cfg(test)]
mod m9a_followup_tests {
    use super::*;

    fn lock() -> std::sync::MutexGuard<'static, ()> {
        crate::object::test_lock()
    }

    fn setup() -> std::sync::MutexGuard<'static, ()> {
        let guard = lock();
        reset_for_test();
        super::super::eventfd::reset_for_test();
        super::super::timerfd::reset_for_test();
        super::super::signalfd::reset_for_test();
        guard
    }

    fn new_set() -> ObjectId {
        let object = 0x0a01;
        let payload = create().expect("create");
        bind(payload, object).expect("bind");
        object
    }

    #[test]
    fn interests_returns_raw_registered_entries() {
        let _guard = setup();
        let set = new_set();
        ctl_add(set, 0x0b01, EPOLLIN | EPOLLOUT, 11).expect("add");
        ctl_add(set, 0x0b02, EPOLLIN, 22).expect("add");
        let mut out = [ReadyEvent {
            target: 0,
            data: 0,
            events: 0,
        }; MAX_EPOLL_INTERESTS];
        assert_eq!(interests(set, &mut out), Ok(2));
        assert_eq!(out[0].target, 0x0b01);
        assert_eq!(out[0].events, EPOLLIN | EPOLLOUT);
        assert_eq!(out[0].data, 11);
        assert_eq!(out[1].target, 0x0b02);
        assert_eq!(out[1].data, 22);
    }

    #[test]
    fn interests_respects_the_output_buffer() {
        let _guard = setup();
        let set = new_set();
        ctl_add(set, 0x0b03, EPOLLIN, 0).expect("add");
        ctl_add(set, 0x0b04, EPOLLIN, 0).expect("add");
        let mut out = [ReadyEvent {
            target: 0,
            data: 0,
            events: 0,
        }; 1];
        assert_eq!(interests(set, &mut out), Ok(1));
    }

    #[test]
    fn on_target_destroy_removes_interests_and_keeps_others() {
        let _guard = setup();
        let set = new_set();
        ctl_add(set, 0x0b05, EPOLLIN, 1).expect("add");
        ctl_add(set, 0x0b06, EPOLLIN, 2).expect("add");
        assert_eq!(on_target_destroy(0x0b05), 1);
        assert_eq!(on_target_destroy(0x0b05), 0);
        assert_eq!(interest_count(set), Ok(1));
        let mut out = [ReadyEvent {
            target: 0,
            data: 0,
            events: 0,
        }; MAX_EPOLL_INTERESTS];
        assert_eq!(interests(set, &mut out), Ok(1));
        assert_eq!(out[0].target, 0x0b06);
    }

    #[test]
    fn destroyed_set_stops_matching_interest_cleanup() {
        let _guard = setup();
        let set = new_set();
        ctl_add(set, 0x0b07, EPOLLIN, 0).expect("add");
        on_destroy(set);
        assert_eq!(on_target_destroy(0x0b07), 0);
    }
}

/// M9b：ET 边沿缓存（`observed`）与 `scan_with` 的回归。
#[cfg(test)]
mod m9b_followup_tests {
    use super::*;
    use core::sync::atomic::{AtomicU32, AtomicUsize, Ordering};

    static PROBE: AtomicU32 = AtomicU32::new(0);
    static PROBE_CALLS: AtomicUsize = AtomicUsize::new(0);

    fn probe(_target: ObjectId) -> u32 {
        PROBE_CALLS.fetch_add(1, Ordering::Relaxed);
        PROBE.load(Ordering::Relaxed)
    }

    fn setup() -> std::sync::MutexGuard<'static, ()> {
        let guard = crate::object::test_lock();
        reset_for_test();
        super::super::eventfd::reset_for_test();
        super::super::timerfd::reset_for_test();
        super::super::signalfd::reset_for_test();
        PROBE.store(0, Ordering::Relaxed);
        PROBE_CALLS.store(0, Ordering::Relaxed);
        guard
    }

    fn new_set() -> ObjectId {
        let object = 0x0c01;
        let payload = create().expect("create");
        bind(payload, object).expect("bind");
        object
    }

    fn empty_out() -> [ReadyEvent; MAX_EPOLL_INTERESTS] {
        [ReadyEvent {
            target: 0,
            data: 0,
            events: 0,
        }; MAX_EPOLL_INTERESTS]
    }

    #[test]
    fn et_reports_a_continuous_readable_edge_once() {
        let _guard = setup();
        let set = new_set();
        let target = 0x0c02;
        ctl_add(set, target, EPOLLIN | EPOLLET, 5).expect("add");
        let mut out = empty_out();
        PROBE.store(EPOLLIN, Ordering::Relaxed);
        assert_eq!(scan_with(set, &mut out, probe), Ok(1));
        assert_eq!(out[0].target, target);
        assert_eq!(out[0].events, EPOLLIN);
        assert_eq!(out[0].data, 5);
        // 连续可读：第二次扫描没有新边沿。
        assert_eq!(scan_with(set, &mut out, probe), Ok(0));
        // notify_target 清 latch 后，同一可读位重新成为边沿。
        assert_eq!(notify_target(target), 1);
        assert_eq!(scan_with(set, &mut out, probe), Ok(1));
    }

    #[test]
    fn lt_reports_every_scan() {
        let _guard = setup();
        let set = new_set();
        ctl_add(set, 0x0c03, EPOLLIN, 0).expect("add");
        let mut out = empty_out();
        PROBE.store(EPOLLIN, Ordering::Relaxed);
        assert_eq!(scan_with(set, &mut out, probe), Ok(1));
        assert_eq!(scan_with(set, &mut out, probe), Ok(1));
        assert_eq!(out[0].events, EPOLLIN);
    }

    #[test]
    fn newly_ready_bit_is_a_new_edge() {
        let _guard = setup();
        let set = new_set();
        ctl_add(set, 0x0c04, EPOLLIN | EPOLLOUT | EPOLLET, 7).expect("add");
        let mut out = empty_out();
        PROBE.store(EPOLLIN, Ordering::Relaxed);
        assert_eq!(scan_with(set, &mut out, probe), Ok(1));
        assert_eq!(out[0].events, EPOLLIN);
        // 可读仍为真，但新增了可写位：按新事件位再报一次。
        PROBE.store(EPOLLIN | EPOLLOUT, Ordering::Relaxed);
        assert_eq!(scan_with(set, &mut out, probe), Ok(1));
        assert_eq!(out[0].events, EPOLLIN | EPOLLOUT);
        // 掩码不变则不再有边沿。
        assert_eq!(scan_with(set, &mut out, probe), Ok(0));
    }

    #[test]
    fn not_ready_target_clears_the_edge_latch() {
        let _guard = setup();
        let set = new_set();
        ctl_add(set, 0x0c05, EPOLLIN | EPOLLET, 0).expect("add");
        let mut out = empty_out();
        PROBE.store(EPOLLIN, Ordering::Relaxed);
        assert_eq!(scan_with(set, &mut out, probe), Ok(1));
        // 目标不再就绪：清空 latch，之后再次变为就绪算新边沿。
        PROBE.store(0, Ordering::Relaxed);
        assert_eq!(scan_with(set, &mut out, probe), Ok(0));
        PROBE.store(EPOLLIN, Ordering::Relaxed);
        assert_eq!(scan_with(set, &mut out, probe), Ok(1));
    }

    #[test]
    fn ctl_mod_rearms_the_edge() {
        let _guard = setup();
        let set = new_set();
        let target = 0x0c06;
        ctl_add(set, target, EPOLLIN | EPOLLET, 0).expect("add");
        let mut out = empty_out();
        PROBE.store(EPOLLIN, Ordering::Relaxed);
        assert_eq!(scan_with(set, &mut out, probe), Ok(1));
        assert_eq!(scan_with(set, &mut out, probe), Ok(0));
        // MOD 重新武装：即使就绪位不变也再报一次。
        assert_eq!(ctl_mod(set, target, EPOLLIN | EPOLLET, 0), Ok(()));
        assert_eq!(scan_with(set, &mut out, probe), Ok(1));
    }

    #[test]
    fn ctl_del_then_add_rearms_the_edge() {
        let _guard = setup();
        let set = new_set();
        let target = 0x0c07;
        ctl_add(set, target, EPOLLIN | EPOLLET, 0).expect("add");
        let mut out = empty_out();
        PROBE.store(EPOLLIN, Ordering::Relaxed);
        assert_eq!(scan_with(set, &mut out, probe), Ok(1));
        assert_eq!(scan_with(set, &mut out, probe), Ok(0));
        assert_eq!(ctl_del(set, target), Ok(()));
        ctl_add(set, target, EPOLLIN | EPOLLET, 0).expect("re-add");
        assert_eq!(scan_with(set, &mut out, probe), Ok(1));
    }

    #[test]
    fn probe_supplies_the_readiness_mask() {
        let _guard = setup();
        let set = new_set();
        // Socket 风格：probe 由 compat 提供；这里验证 probe 被调用且结果被采用。
        ctl_add(set, 0x0c08, EPOLLIN | EPOLLOUT | EPOLLET, 11).expect("add");
        let mut out = empty_out();
        PROBE.store(EPOLLIN | EPOLLOUT, Ordering::Relaxed);
        assert_eq!(scan_with(set, &mut out, probe), Ok(1));
        assert_eq!(out[0].events, EPOLLIN | EPOLLOUT);
        assert!(PROBE_CALLS.load(Ordering::Relaxed) >= 1);
    }

    #[test]
    fn probe_readiness_is_masked_by_requested_bits() {
        let _guard = setup();
        let set = new_set();
        ctl_add(set, 0x0c09, EPOLLIN | EPOLLET, 0).expect("add");
        let mut out = empty_out();
        PROBE.store(EPOLLIN | EPOLLOUT, Ordering::Relaxed);
        assert_eq!(scan_with(set, &mut out, probe), Ok(1));
        // 未请求的 EPOLLOUT 不在输出里。
        assert_eq!(out[0].events, EPOLLIN);
    }

    #[test]
    fn et_and_lt_interests_coexist() {
        let _guard = setup();
        let set = new_set();
        ctl_add(set, 0x0c0a, EPOLLIN | EPOLLET, 1).expect("add");
        ctl_add(set, 0x0c0b, EPOLLIN, 2).expect("add");
        let mut out = empty_out();
        PROBE.store(EPOLLIN, Ordering::Relaxed);
        assert_eq!(scan_with(set, &mut out, probe), Ok(2));
        // 第二次：ET 项无新边沿，LT 项仍报告。
        assert_eq!(scan_with(set, &mut out, probe), Ok(1));
        assert_eq!(out[0].target, 0x0c0b);
    }

    #[test]
    fn scan_uses_target_readiness_for_ipc_objects() {
        let _guard = setup();
        let set = new_set();
        let target = 0x0c0c;
        let payload = super::super::eventfd::create(0, 0).expect("eventfd");
        super::super::eventfd::bind(payload, target).expect("bind");
        ctl_add(set, target, EPOLLIN | EPOLLET, 0).expect("add");
        let mut out = empty_out();
        super::super::eventfd::write(target, 1).expect("write");
        assert_eq!(scan(set, &mut out), Ok(1));
        assert_eq!(out[0].events, EPOLLIN);
        assert_eq!(scan(set, &mut out), Ok(0));
        // 读空后不再就绪：latch 清零；再次写入产生新边沿。
        let _ = super::super::eventfd::read(target);
        assert_eq!(scan(set, &mut out), Ok(0));
        super::super::eventfd::write(target, 1).expect("write");
        assert_eq!(scan(set, &mut out), Ok(1));
    }
}
