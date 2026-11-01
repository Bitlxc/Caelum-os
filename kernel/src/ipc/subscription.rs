//! EventSubscription 内核对象（M6a2，C）。
//!
//! 一个 `EventSubscription` 对象保存一组对**可等待对象**的持久兴趣登记：每个
//! interest 记录目标对象编号、就绪模式（电平 [`MODE_LEVEL`] / 边沿 [`MODE_EDGE`]）
//! 和一个 kind 相关的 key（EventPair 端点，其它对象为 0）。`poll`/`read` 把当前就绪
//! 的目标以 [`SubscriptionEvent`] 报告给用户态，`read` 还负责边沿模式的“已报告”
//! 缓存，避免同一次边沿被重复报告。
//!
//! 语义约定：
//!
//! - **LT**：目标仍就绪，每次 `read` 都报告；
//! - **ET**：目标就绪且 `observed == false` 时报告一次；`read` 真正返回该事件时才把
//!   `observed` 置 true；目标回到未就绪时清 `observed`，下一次就绪再报告一次；
//! - `poll` 只查看，不消费边沿、不消费 auto-reset 事件；目标**未就绪**时无论 `poll` 还是
//!   `read` 都无条件清除该 interest 的 `observed`（重新武装），所以“读走一条边沿、再抽干
//!   一次、目标重新就绪”仍会上报第二次边沿；目标仍就绪时 `poll` 不改 `observed`；
//! - 目标就绪变化后，事件源在 IPC 表锁之外调用 [`on_target_ready`] 唤醒关心它的订阅；
//!   [`on_target_ready`] 只做固定上限遍历、不分配不打印，可由中断上下文调用；
//! - 目标**失去就绪**时（源侧 `reset`/`consume`/队列被抽干），源在释放自身表锁后调用
//!   [`on_target_not_ready`]：只清该目标相关 ET interest 的 `observed`（不唤醒、不消费），
//!   补齐“抽干后无人 poll/ready，下一次 signal 前”的重新武装窗口；
//! - [`ready`] 会顺带对未就绪的 ET interest 做同样的重新武装（副作用仅限订阅模块内部的
//!   `observed` 缓存），但仍不消费消息/auto-reset 事件；
//! - 状态按**对象编号**保存，因此 `dup` 出来的句柄共享同一份 `observed`
//!   （`dup` 不产生新对象）；订阅比被观察的句柄活得久，unsubscribe/close 之后不再
//!   报告，而目标对象本身照常可用；
//! - 注册时 acquire 目标对象的一个引用：只要 interest 还在，目标对象就不会被销毁，
//!   因此 `poll`/`read` 看到的目标编号在 interest 存续期间始终有效。
//!
//! 释放目标引用绝不发生在对象表的销毁钩子内（钩子持有对象表的 `IrqCell`）：钩子
//! 路径 [`on_destroy`] 只把引用塞进延迟释放队列，由 [`release_pending`] 在对象锁
//! 之外真正释放。句柄关闭路径（`close_handle` → 销毁钩子）之后必须调用一次
//! [`release_pending`]。

use super::{IrqCell, poll_waitable_keyed};
use crate::object::{self, ObjectError, ObjectId, ObjectKind};
use crate::process::{self, WakeReason};

/// 固定容量：同时存在的 `EventSubscription` 对象上限。
pub const MAX_SUBSCRIPTIONS: usize = 2;

/// 每个订阅最多登记的 interest 数。
pub const MAX_INTERESTS: usize = 4;

/// 一次 `read` 最多返回的事件数（等于 interest 上限）。
pub const MAX_EVENTS: usize = MAX_INTERESTS;

/// 延迟释放队列容量：最多 `MAX_SUBSCRIPTIONS * MAX_INTERESTS` 个目标引用。
const MAX_PENDING: usize = MAX_SUBSCRIPTIONS * MAX_INTERESTS;

/// 电平触发：目标仍就绪就持续报告。
pub const MODE_LEVEL: u32 = 1;

/// 边沿触发：每次就绪边沿只报告一次（`read` 后失效）。
pub const MODE_EDGE: u32 = 2;

/// 订阅操作的错误；`as_str` 供 syscall 层映射到 ABI 错误码。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SubscriptionError {
    /// 固定表已满（已有 [`MAX_SUBSCRIPTIONS`] 个订阅）或 interest 表已满。
    TableFull,
    /// 请求非法：空注册、重复目标、未知模式、该 kind 不允许的 key、递归订阅。
    BadRequest,
    /// 订阅对象或 interest 不存在。
    NotFound,
    /// 目标对象存活但 kind 不可订阅（或对象编号不是订阅对象）。
    WrongKind,
    /// 对象层操作失败（例如 acquire 引用失败）。
    Object(ObjectError),
}

impl SubscriptionError {
    /// 稳定的诊断字符串。
    pub const fn as_str(self) -> &'static str {
        match self {
            SubscriptionError::TableFull => "subscription-table-full",
            SubscriptionError::BadRequest => "subscription-bad-request",
            SubscriptionError::NotFound => "subscription-not-found",
            SubscriptionError::WrongKind => "subscription-wrong-kind",
            SubscriptionError::Object(_) => "subscription-object",
        }
    }
}

/// 一条返回事件的编码：`object_key = (object << 32) | key`。
///
/// 高 32 位是目标 `ObjectId` 的原始值，低 32 位是 EventPair 端点或 0；LT/ET 一致。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct SubscriptionEvent {
    /// 目标对象编号（高 32 位）与 kind 相关 key（低 32 位）。
    pub object_key: u64,
    /// 登记时的模式（[`MODE_LEVEL`] / [`MODE_EDGE`]）。
    pub mode: u32,
}

impl SubscriptionEvent {
    const fn encode(target: ObjectId, key: u64, mode: u32) -> Self {
        Self {
            object_key: ((target as u64) << 32) | (key & 0xffff_ffff),
            mode,
        }
    }

    /// 编码中的目标对象编号。
    pub const fn object(self) -> ObjectId {
        (self.object_key >> 32) as ObjectId
    }

    /// 编码中的 kind 相关 key。
    pub const fn key(self) -> u64 {
        self.object_key & 0xffff_ffff
    }
}

/// 调用者给出的 interest（用于 [`replace`]）。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Interest {
    /// 被观察对象编号。
    pub target: ObjectId,
    /// [`MODE_LEVEL`] 或 [`MODE_EDGE`]。
    pub mode: u32,
    /// EventPair 端点（0/1），其它 kind 必须为 0。
    pub key: u64,
}

/// 已登记的 interest（含边沿观察缓存）。
#[derive(Clone, Copy)]
struct Registered {
    target: ObjectId,
    mode: u32,
    key: u64,
    observed: bool,
}

const EMPTY_REGISTERED: Registered = Registered {
    target: ObjectId::MAX,
    mode: 0,
    key: 0,
    observed: false,
};

/// 一个订阅对象占用的表项。
#[derive(Clone, Copy)]
struct Slot {
    live: bool,
    object: ObjectId,
    count: usize,
    entries: [Registered; MAX_INTERESTS],
}

const EMPTY_SLOT: Slot = Slot {
    live: false,
    object: ObjectId::MAX,
    count: 0,
    entries: [EMPTY_REGISTERED; MAX_INTERESTS],
};

/// 订阅固定表 + 延迟释放队列。
struct SubscriptionTable {
    slots: [Slot; MAX_SUBSCRIPTIONS],
    pending: [ObjectId; MAX_PENDING],
    pending_len: usize,
}

impl SubscriptionTable {
    const fn new() -> Self {
        Self {
            slots: [EMPTY_SLOT; MAX_SUBSCRIPTIONS],
            pending: [ObjectId::MAX; MAX_PENDING],
            pending_len: 0,
        }
    }

    fn count(&self) -> usize {
        self.slots.iter().filter(|slot| slot.live).count()
    }

    fn slot_of(&self, object: ObjectId) -> Option<usize> {
        self.slots
            .iter()
            .position(|slot| slot.live && slot.object == object)
    }

    fn push_pending(&mut self, target: ObjectId) {
        if self.pending_len < MAX_PENDING {
            self.pending[self.pending_len] = target;
            self.pending_len += 1;
        }
    }
}

static SUBSCRIPTIONS: IrqCell<SubscriptionTable> = IrqCell::new(SubscriptionTable::new());

/// 目标 kind 是否允许被订阅。
fn subscribable(kind: ObjectKind) -> bool {
    matches!(
        kind,
        ObjectKind::Event
            | ObjectKind::EventPair
            | ObjectKind::Timer
            | ObjectKind::Channel
            | ObjectKind::Port
    )
}

/// 校验一条 interest 的目标与 key；返回目标 kind。
fn validate_target(target: ObjectId, key: u64) -> Result<ObjectKind, SubscriptionError> {
    let kind = object::object_kind(target).ok_or(SubscriptionError::NotFound)?;
    if kind == ObjectKind::EventSubscription {
        // 不允许递归订阅订阅对象：既无必要，也会让唤醒依赖链无限延伸。
        return Err(SubscriptionError::BadRequest);
    }
    if !subscribable(kind) {
        return Err(SubscriptionError::WrongKind);
    }
    if kind == ObjectKind::EventPair {
        if key > 1 {
            return Err(SubscriptionError::BadRequest);
        }
    } else if key != 0 {
        return Err(SubscriptionError::BadRequest);
    }
    Ok(kind)
}

/// 校验模式。
fn validate_mode(mode: u32) -> Result<(), SubscriptionError> {
    if mode == MODE_LEVEL || mode == MODE_EDGE {
        Ok(())
    } else {
        Err(SubscriptionError::BadRequest)
    }
}

/// 目标当前是否就绪（不消费事件）。
///
/// **会读取目标所在的源表**（Event/EventPair/Timer/Channel/Port），因此只允许在任何
/// IPC 表锁之外调用；订阅表自身的锁内只做快照，不做就绪查询。
fn target_ready(target: ObjectId, key: u64) -> bool {
    matches!(poll_waitable_keyed(target, key as u8, false), Ok(true))
}

/// 锁内快照：只复制 interest 的标识字段，不查询任何其它表。
#[derive(Clone, Copy)]
struct InterestSnapshot {
    target: ObjectId,
    key: u64,
    mode: u32,
    observed: bool,
}

impl InterestSnapshot {
    const EMPTY: Self = Self {
        target: ObjectId::MAX,
        key: 0,
        mode: 0,
        observed: false,
    };
}

/// 在 `SUBSCRIPTIONS` 锁内把某个槽的 interest 复制出来；返回 `(count, snapshots)`。
fn snapshot_slot(
    table: &SubscriptionTable,
    slot: usize,
) -> (usize, [InterestSnapshot; MAX_INTERESTS]) {
    let mut snapshots = [InterestSnapshot::EMPTY; MAX_INTERESTS];
    if !table.slots[slot].live {
        return (0, snapshots);
    }
    let count = table.slots[slot].count.min(MAX_INTERESTS);
    for (index, snapshot) in snapshots.iter_mut().enumerate().take(count) {
        let entry = table.slots[slot].entries[index];
        *snapshot = InterestSnapshot {
            target: entry.target,
            key: entry.key,
            mode: entry.mode,
            observed: entry.observed,
        };
    }
    (count, snapshots)
}

/// 锁外就绪探测：对快照逐条查询目标状态（必须在不持有订阅表锁时调用）。
fn probe_snapshots(
    snapshots: &[InterestSnapshot; MAX_INTERESTS],
    count: usize,
) -> [bool; MAX_INTERESTS] {
    let mut ready = [false; MAX_INTERESTS];
    for index in 0..count {
        ready[index] = target_ready(snapshots[index].target, snapshots[index].key);
    }
    ready
}

/// 回锁合并：表项未被并发修改时才写回 `observed`，返回该 interest 当前是否可报告。
///
/// `at_ready == false` 时清 `observed`——这就是“目标确已回到未就绪”的重新武装点。
fn merge(entry: &mut Registered, snapshot: &InterestSnapshot, at_ready: bool) -> bool {
    if entry.target != snapshot.target || entry.key != snapshot.key || entry.mode != snapshot.mode {
        return false;
    }
    if !at_ready {
        entry.observed = false;
        return false;
    }
    entry.mode == MODE_LEVEL || !entry.observed
}

/// 为一个已经创建的 `EventSubscription` 对象初始化表项。
pub fn create(object: ObjectId) -> Result<(), SubscriptionError> {
    match object::object_kind(object) {
        None => return Err(SubscriptionError::NotFound),
        Some(kind) if kind != ObjectKind::EventSubscription => {
            return Err(SubscriptionError::WrongKind);
        }
        Some(_) => {}
    }
    SUBSCRIPTIONS.with(|table| {
        let Some(slot) = table.slots.iter().position(|slot| !slot.live) else {
            return Err(SubscriptionError::TableFull);
        };
        table.slots[slot] = Slot {
            live: true,
            object,
            count: 0,
            entries: [EMPTY_REGISTERED; MAX_INTERESTS],
        };
        Ok(())
    })
}

/// 追加一个 interest（注册时 acquire 目标引用）。
pub fn register(
    object: ObjectId,
    target: ObjectId,
    mode: u32,
    key: u64,
) -> Result<(), SubscriptionError> {
    validate_mode(mode)?;
    validate_target(target, key)?;

    // 先在表内做幂等检查，再 acquire，避免失败路径多一次引用抖动。
    SUBSCRIPTIONS.with(|table| {
        let slot = table.slot_of(object).ok_or(SubscriptionError::NotFound)?;
        if table.slots[slot].count >= MAX_INTERESTS {
            return Err(SubscriptionError::TableFull);
        }
        if table.slots[slot].entries[..table.slots[slot].count]
            .iter()
            .any(|entry| entry.target == target)
        {
            return Err(SubscriptionError::BadRequest);
        }
        Ok(())
    })?;

    object::acquire_object(target).map_err(SubscriptionError::Object)?;

    let inserted = SUBSCRIPTIONS.with(|table| {
        let slot = table.slot_of(object).ok_or(SubscriptionError::NotFound)?;
        if table.slots[slot].count >= MAX_INTERESTS {
            return Err(SubscriptionError::TableFull);
        }
        let count = table.slots[slot].count;
        table.slots[slot].entries[count] = Registered {
            target,
            mode,
            key,
            observed: false,
        };
        table.slots[slot].count = count + 1;
        Ok(())
    });
    if inserted.is_err() {
        let _ = object::release_object(target);
    }
    inserted
}

/// 原子替换该订阅的全部 interest：先 acquire 新的，再换表，最后释放旧的。
pub fn replace(object: ObjectId, entries: &[Interest]) -> Result<(), SubscriptionError> {
    if entries.is_empty() || entries.len() > MAX_INTERESTS {
        return Err(SubscriptionError::BadRequest);
    }
    for (index, entry) in entries.iter().enumerate() {
        validate_mode(entry.mode)?;
        validate_target(entry.target, entry.key)?;
        if entries[..index]
            .iter()
            .any(|other| other.target == entry.target)
        {
            return Err(SubscriptionError::BadRequest);
        }
    }

    SUBSCRIPTIONS.with(|table| {
        table
            .slot_of(object)
            .map(|_| ())
            .ok_or(SubscriptionError::NotFound)
    })?;

    // 先把新引用全部拿到手，任一失败就整体回滚（此时表还没动）。
    let mut acquired = [ObjectId::MAX; MAX_INTERESTS];
    for (index, entry) in entries.iter().enumerate() {
        match object::acquire_object(entry.target) {
            Ok(_) => acquired[index] = entry.target,
            Err(error) => {
                for target in acquired.iter().take(index) {
                    let _ = object::release_object(*target);
                }
                return Err(SubscriptionError::Object(error));
            }
        }
    }

    let mut old = [ObjectId::MAX; MAX_INTERESTS];
    let mut old_count = 0;
    let swapped = SUBSCRIPTIONS.with(|table| {
        let Some(slot) = table.slot_of(object) else {
            return Err(SubscriptionError::NotFound);
        };
        old_count = table.slots[slot].count;
        old = table.slots[slot].entries.map(|entry| entry.target);
        table.slots[slot].entries = [EMPTY_REGISTERED; MAX_INTERESTS];
        for (index, entry) in entries.iter().enumerate() {
            table.slots[slot].entries[index] = Registered {
                target: entry.target,
                mode: entry.mode,
                key: entry.key,
                observed: false,
            };
        }
        table.slots[slot].count = entries.len();
        Ok(())
    });

    if swapped.is_err() {
        for target in acquired.iter().take(entries.len()) {
            let _ = object::release_object(*target);
        }
        return swapped;
    }

    for target in old.iter().take(old_count) {
        if *target != ObjectId::MAX {
            let _ = object::release_object(*target);
        }
    }
    Ok(())
}

/// 移除一个 interest 并立即释放目标引用（缺失返回 `NotFound`）。
pub fn unsubscribe(object: ObjectId, target: ObjectId) -> Result<(), SubscriptionError> {
    SUBSCRIPTIONS.with(|table| {
        let slot = table.slot_of(object).ok_or(SubscriptionError::NotFound)?;
        let count = table.slots[slot].count;
        let position = table.slots[slot].entries[..count]
            .iter()
            .position(|entry| entry.target == target)
            .ok_or(SubscriptionError::NotFound)?;
        for index in position..count - 1 {
            table.slots[slot].entries[index] = table.slots[slot].entries[index + 1];
        }
        table.slots[slot].entries[count - 1] = EMPTY_REGISTERED;
        table.slots[slot].count = count - 1;
        Ok(())
    })?;
    let _ = object::release_object(target);
    Ok(())
}

/// 清空表项并返回其目标（供本模块内部与 `destroy` 使用）。
fn take_targets(
    object: ObjectId,
    defer: bool,
) -> Result<[ObjectId; MAX_INTERESTS], SubscriptionError> {
    let mut taken = [ObjectId::MAX; MAX_INTERESTS];
    SUBSCRIPTIONS.with(|table| {
        let slot = table.slot_of(object).ok_or(SubscriptionError::NotFound)?;
        let count = table.slots[slot].count;
        for (index, target) in taken.iter_mut().enumerate().take(count) {
            *target = table.slots[slot].entries[index].target;
        }
        if defer {
            for target in taken.iter().take(count) {
                table.push_pending(*target);
            }
        }
        table.slots[slot] = EMPTY_SLOT;
        Ok(())
    })?;
    Ok(taken)
}

/// 销毁订阅对象：清表、唤醒等待者、释放全部目标引用（可在对象锁外调用）。
pub fn destroy(object: ObjectId) -> Result<(), SubscriptionError> {
    let targets = take_targets(object, false)?;
    let _ = process::wake_object(object, WakeReason::Destroyed);
    for target in targets {
        if target != ObjectId::MAX {
            let _ = object::release_object(target);
        }
    }
    Ok(())
}

/// 对象销毁钩子入口：**在对象表关中断区间内调用**。
///
/// 只清本模块表项、把目标引用塞进延迟释放队列并唤醒等待者；不回调对象表，因此不会
/// 重入对象表的 `IrqCell`。真正的释放由 [`release_pending`] 完成。
pub fn on_destroy(object: ObjectId) {
    if take_targets(object, true).is_err() {
        return;
    }
    let _ = process::wake_object(object, WakeReason::Destroyed);
}

/// 在对象锁之外释放 [`on_destroy`] 延迟下来的目标引用，返回释放条数。
///
/// 句柄关闭/进程退出路径在销毁钩子之后必须调用一次；重复调用是幂等的。
pub fn release_pending() -> usize {
    let mut targets = [ObjectId::MAX; MAX_PENDING];
    let mut count = 0;
    SUBSCRIPTIONS.with(|table| {
        count = table.pending_len;
        targets[..count].copy_from_slice(&table.pending[..count]);
        table.pending_len = 0;
    });
    for target in targets.iter().take(count) {
        let _ = object::release_object(*target);
    }
    count
}

/// 目标对象被销毁时的裁剪入口：移除所有指向它的 interest 并唤醒对应订阅。
///
/// 返回被裁剪的 interest 数。正常路径下不会走到这里（interest 持有目标引用，
/// 目标无法先于 interest 销毁），保留给对象层显式销毁/回收路径兜底。
pub fn on_target_destroy(target: ObjectId) -> usize {
    let mut removed = 0;
    let mut wake = [ObjectId::MAX; MAX_SUBSCRIPTIONS];
    let mut wake_count = 0;
    SUBSCRIPTIONS.with(|table| {
        for slot in 0..MAX_SUBSCRIPTIONS {
            if !table.slots[slot].live {
                continue;
            }
            let count = table.slots[slot].count;
            let mut write = 0;
            let mut touched = false;
            for read in 0..count {
                let entry = table.slots[slot].entries[read];
                if entry.target == target {
                    removed += 1;
                    touched = true;
                    table.push_pending(target);
                    continue;
                }
                table.slots[slot].entries[write] = entry;
                write += 1;
            }
            if touched {
                for index in write..count {
                    table.slots[slot].entries[index] = EMPTY_REGISTERED;
                }
                table.slots[slot].count = write;
                if wake_count < MAX_SUBSCRIPTIONS {
                    wake[wake_count] = table.slots[slot].object;
                    wake_count += 1;
                }
            }
        }
    });
    for object in wake.iter().take(wake_count) {
        let _ = process::wake_object(*object, WakeReason::Ready);
    }
    removed
}

/// 目标对象就绪状态变化时的唤醒入口：唤醒所有“该目标当前可报告”的订阅对象。
///
/// 事件源（Event/EventPair/Timer/Channel/Port 的 signal/post/tick 路径）在完成自身的
/// 就绪更新后、**在 IPC 表锁之外**调用一次；本函数只做固定上限遍历（
/// `MAX_SUBSCRIPTIONS * MAX_INTERESTS`），不分配、不打印，可由中断上下文调用。
/// 不消费边沿、不消费消息/auto-reset 事件 —— 是否上报仍由 `poll`/`read` 决定，这里只负责
/// 唤醒等待订阅对象的线程；顺带对指向该目标的、此刻未就绪的边沿清除 `observed`
/// （重新武装，避免目标侧抽干后没有 `poll` 时永久停在已消费状态）。返回被唤醒的订阅数。
pub fn on_target_ready(target: ObjectId) -> usize {
    // 阶段 1：锁内只快照，不查询任何目标表。
    let mut counts = [0usize; MAX_SUBSCRIPTIONS];
    let mut snapshots = [[InterestSnapshot::EMPTY; MAX_INTERESTS]; MAX_SUBSCRIPTIONS];
    let mut objects = [ObjectId::MAX; MAX_SUBSCRIPTIONS];
    SUBSCRIPTIONS.with(|table| {
        for slot in 0..MAX_SUBSCRIPTIONS {
            if !table.slots[slot].live {
                continue;
            }
            objects[slot] = table.slots[slot].object;
            let (count, snapshot) = snapshot_slot(table, slot);
            counts[slot] = count;
            snapshots[slot] = snapshot;
        }
    });

    // 阶段 2：锁外只探测指向该目标的 interest。
    let mut at_ready = [[false; MAX_INTERESTS]; MAX_SUBSCRIPTIONS];
    for slot in 0..MAX_SUBSCRIPTIONS {
        for index in 0..counts[slot] {
            let snapshot = snapshots[slot][index];
            if snapshot.target == target {
                at_ready[slot][index] = target_ready(snapshot.target, snapshot.key);
            }
        }
    }

    // 阶段 3：回锁合并边沿缓存，收集需要唤醒的订阅对象。
    let mut wake = [ObjectId::MAX; MAX_SUBSCRIPTIONS];
    let mut wake_count = 0;
    SUBSCRIPTIONS.with(|table| {
        for slot in 0..MAX_SUBSCRIPTIONS {
            if !table.slots[slot].live || table.slots[slot].object != objects[slot] {
                continue;
            }
            let limit = counts[slot].min(table.slots[slot].count);
            let mut hit = false;
            for index in 0..limit {
                if snapshots[slot][index].target != target {
                    continue;
                }
                if merge(
                    &mut table.slots[slot].entries[index],
                    &snapshots[slot][index],
                    at_ready[slot][index],
                ) {
                    hit = true;
                }
            }
            if hit && wake_count < MAX_SUBSCRIPTIONS {
                wake[wake_count] = objects[slot];
                wake_count += 1;
            }
        }
    });

    // 阶段 4：锁外唤醒（对象/进程锁在订阅表锁之外获取）。
    for object in wake.iter().take(wake_count) {
        let _ = process::wake_object(*object, WakeReason::Ready);
    }
    wake_count
}

/// 目标对象**失去就绪**时的重新武装入口：清除指向该目标的 ET interest 的 `observed`。
///
/// 事件源（Event 的 reset/consume、Channel/Port 被接收方抽干、Timer 超时后被取走等）
/// 一旦确定目标不再就绪，就应在**释放自身表锁之后**调用一次。若这条路径缺失，就会出现
/// “`read` 消费边沿 → 目标侧抽干 → 订阅侧既没 `poll` 也没 `ready` → 下一次 signal 时
/// `observed` 仍是 true”的窗口，第二次边沿既不唤醒也不上报。
///
/// 只清边沿缓存：**不唤醒**等待者、不消费消息/auto-reset 事件、不改变 LT 语义；对
/// `target` 当前仍就绪的 interest 不做任何修改（防止源误调导致已经上报过的边沿被重复
/// 上报）。固定上限遍历、不分配、不打印，可由中断上下文调用。返回被重新武装的 interest 数。
pub fn on_target_not_ready(target: ObjectId) -> usize {
    // 阶段 1：锁内只快照。
    let mut counts = [0usize; MAX_SUBSCRIPTIONS];
    let mut snapshots = [[InterestSnapshot::EMPTY; MAX_INTERESTS]; MAX_SUBSCRIPTIONS];
    SUBSCRIPTIONS.with(|table| {
        for slot in 0..MAX_SUBSCRIPTIONS {
            let (count, snapshot) = snapshot_slot(table, slot);
            counts[slot] = count;
            snapshots[slot] = snapshot;
        }
    });

    // 阶段 2：锁外用目标自身状态确认一次，误调用不得清掉有效边沿。
    let mut cleared = [[false; MAX_INTERESTS]; MAX_SUBSCRIPTIONS];
    for slot in 0..MAX_SUBSCRIPTIONS {
        for index in 0..counts[slot] {
            let snapshot = snapshots[slot][index];
            if snapshot.target == target
                && snapshot.mode == MODE_EDGE
                && snapshot.observed
                && !target_ready(snapshot.target, snapshot.key)
            {
                cleared[slot][index] = true;
            }
        }
    }

    // 阶段 3：回锁，标识仍一致才清 `observed`。
    let mut cleared_count = 0;
    SUBSCRIPTIONS.with(|table| {
        for slot in 0..MAX_SUBSCRIPTIONS {
            let limit = counts[slot].min(table.slots[slot].count);
            for index in 0..limit {
                if !cleared[slot][index] {
                    continue;
                }
                let snapshot = snapshots[slot][index];
                let entry = &mut table.slots[slot].entries[index];
                if entry.target != target
                    || entry.key != snapshot.key
                    || entry.mode != MODE_EDGE
                    || !entry.observed
                {
                    continue;
                }
                entry.observed = false;
                cleared_count += 1;
            }
        }
    });
    cleared_count
}

/// 该订阅是否已存在。
pub fn exists(object: ObjectId) -> bool {
    SUBSCRIPTIONS.with(|table| table.slot_of(object).is_some())
}

/// 该订阅当前的 interest 数。
pub fn interest_count(object: ObjectId) -> Result<usize, SubscriptionError> {
    SUBSCRIPTIONS.with(|table| {
        let slot = table.slot_of(object).ok_or(SubscriptionError::NotFound)?;
        Ok(table.slots[slot].count)
    })
}

/// 当前存活的订阅对象数。
pub fn count() -> usize {
    SUBSCRIPTIONS.with(|table| table.count())
}

/// 延迟释放队列当前积压条数（供诊断/测试）。
pub fn pending_count() -> usize {
    SUBSCRIPTIONS.with(|table| table.pending_len)
}

/// 是否有任何 interest 当前可被报告（供 `poll_waitable` 判定订阅对象是否就绪）。
///
/// 不消费边沿、不消费消息/auto-reset 事件；唯一的副作用是边沿重新武装：目标未就绪的
/// interest 会清掉 `observed`（见 [`merge`]）。因此 WAIT/`ready` 本身就能让“目标侧已
/// 抽干、订阅侧没 poll 过”的 ET interest 恢复为下一次就绪可上报。
pub fn ready(object: ObjectId) -> Result<bool, SubscriptionError> {
    // 阶段 1：锁内快照（不查询任何目标表）。
    let (count, snapshots) = SUBSCRIPTIONS.with(|table| {
        let slot = table.slot_of(object).ok_or(SubscriptionError::NotFound)?;
        Ok::<_, SubscriptionError>(snapshot_slot(table, slot))
    })?;

    // 阶段 2：锁外探测目标就绪（`target_ready` 会读取目标所在源表）。
    let at_ready = probe_snapshots(&snapshots, count);

    // 阶段 3：回锁合并 `observed`。
    SUBSCRIPTIONS.with(|table| {
        let Some(slot) = table.slot_of(object) else {
            return Ok(false);
        };
        let mut any = false;
        let limit = count.min(table.slots[slot].count);
        for index in 0..limit {
            if merge(
                &mut table.slots[slot].entries[index],
                &snapshots[index],
                at_ready[index],
            ) {
                any = true;
            }
        }
        Ok(any)
    })
}

/// 收集当前可报告事件，返回写入条数；`mark` 为真时把本次报告的边沿标记为已消费。
///
/// 无论 `mark` 与否，目标**未就绪**时都会清除该 interest 的 `observed`：边沿的重新武装
/// 只依赖“目标确实回到未就绪”，不依赖调用者是否在 `read` 路径上，否则先 `poll` 抽干
/// 再等目标重新就绪的 ET 场景会漏掉第二次边沿。
fn collect(
    object: ObjectId,
    out: &mut [SubscriptionEvent],
    mark: bool,
) -> Result<usize, SubscriptionError> {
    // 阶段 1：锁内只快照，不查询任何目标表。
    let (count, snapshots) = SUBSCRIPTIONS.with(|table| {
        let slot = table.slot_of(object).ok_or(SubscriptionError::NotFound)?;
        Ok::<_, SubscriptionError>(snapshot_slot(table, slot))
    })?;

    // 阶段 2：锁外逐个探测目标就绪。
    let at_ready = probe_snapshots(&snapshots, count);

    // 阶段 3：回锁上报 / 重新武装。边沿判定用快照值，标识仍一致才写回。
    SUBSCRIPTIONS.with(|table| {
        let Some(slot) = table.slot_of(object) else {
            return Ok(0);
        };
        let limit = count.min(table.slots[slot].count);
        let mut written = 0;
        for index in 0..limit {
            let snapshot = snapshots[index];
            if !at_ready[index] {
                // 目标回到未就绪：下一次就绪重新算作一次新边沿。必须在 `poll` 路径上也清，
                // 否则“read 一次 → poll 抽干 → 目标重新就绪”会永久停在 observed=true。
                table.slots[slot].entries[index].observed = false;
                continue;
            }
            let entry = &mut table.slots[slot].entries[index];
            if entry.target != snapshot.target
                || entry.key != snapshot.key
                || entry.mode != snapshot.mode
            {
                continue;
            }
            let edge_pending = snapshot.mode == MODE_EDGE && !snapshot.observed;
            if (snapshot.mode == MODE_LEVEL || edge_pending) && written < out.len() {
                out[written] =
                    SubscriptionEvent::encode(snapshot.target, snapshot.key, snapshot.mode);
                written += 1;
                if mark && snapshot.mode == MODE_EDGE {
                    entry.observed = true;
                }
            }
        }
        Ok(written)
    })
}

/// 查看当前可报告事件：不消费边沿、不消费 auto-reset 事件、目标仍就绪时不改 `observed`；
/// 唯一的状态变化是目标未就绪时清除该边沿的 `observed`（重新武装）。
pub fn poll(object: ObjectId, out: &mut [SubscriptionEvent]) -> Result<usize, SubscriptionError> {
    collect(object, out, false)
}

/// 读取事件：返回写入条数；对边沿模式在此真正消费（标记 `observed`）。
pub fn read(object: ObjectId, out: &mut [SubscriptionEvent]) -> Result<usize, SubscriptionError> {
    collect(object, out, true)
}

/// 清空表与延迟队列（仅供宿主测试）。
#[cfg(test)]
pub(crate) fn reset() {
    SUBSCRIPTIONS.with(|table| *table = SubscriptionTable::new());
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ipc::event;

    fn lock() -> std::sync::MutexGuard<'static, ()> {
        crate::object::test_lock()
    }

    fn prepare() {
        object::reset_destroy_hooks();
        reset();
    }

    fn new_subscription() -> ObjectId {
        // `create_object` 是 M4 兼容路径（引用计数 0）；测试必须用带负载版本拿到
        // 引用计数 1 的对象，否则 release 会因 refs==0 失败、对象永不销毁。
        let object = object::create_with_payload(ObjectKind::EventSubscription, 0)
            .expect("subscription object");
        create(object).expect("subscription table entry");
        object
    }

    /// 建立一个可选通/复位的 auto-reset Event 对象。
    fn new_event() -> (ObjectId, u64) {
        let payload = event::create(false).expect("event payload");
        let object = object::create_with_payload(ObjectKind::Event, payload).expect("event object");
        (object, payload)
    }

    fn drop_event(object: ObjectId, payload: u64) {
        let _ = object::release_object(object);
        let _ = event::destroy(payload, object);
    }

    fn drop_subscription(object: ObjectId) {
        let _ = destroy(object);
        release_pending();
        let _ = object::release_object(object);
    }

    fn empty_events() -> [SubscriptionEvent; MAX_EVENTS] {
        [SubscriptionEvent {
            object_key: 0,
            mode: 0,
        }; MAX_EVENTS]
    }

    #[test]
    fn create_requires_a_live_event_subscription_object() {
        let _guard = lock();
        prepare();

        let event_object = object::create_with_payload(ObjectKind::Event, 0).expect("event");
        assert_eq!(create(event_object), Err(SubscriptionError::WrongKind));
        let _ = object::release_object(event_object);

        let dead =
            object::create_with_payload(ObjectKind::EventSubscription, 0).expect("subscription");
        let _ = object::release_object(dead);
        assert_eq!(create(dead), Err(SubscriptionError::NotFound));

        let first = new_subscription();
        let second = new_subscription();
        let third =
            object::create_with_payload(ObjectKind::EventSubscription, 0).expect("subscription");
        assert_eq!(create(third), Err(SubscriptionError::TableFull));
        assert_eq!(count(), 2);

        drop_subscription(first);
        drop_subscription(second);
        let _ = object::release_object(third);
        prepare();
    }

    #[test]
    fn register_validates_mode_key_kind_and_duplicates() {
        let _guard = lock();
        prepare();
        let subscription = new_subscription();
        let (first, first_payload) = new_event();
        let (second, second_payload) = new_event();

        assert_eq!(
            register(subscription, first, 0, 0),
            Err(SubscriptionError::BadRequest)
        );
        assert_eq!(
            register(subscription, first, 3, 0),
            Err(SubscriptionError::BadRequest)
        );
        assert_eq!(
            register(subscription, first, MODE_LEVEL, 1),
            Err(SubscriptionError::BadRequest)
        );

        assert_eq!(register(subscription, first, MODE_LEVEL, 0), Ok(()));
        assert_eq!(
            register(subscription, first, MODE_EDGE, 0),
            Err(SubscriptionError::BadRequest)
        );

        // 不可订阅的 kind：Console。
        let console = object::create_with_payload(ObjectKind::Console, 0).expect("console");
        assert_eq!(
            register(subscription, console, MODE_LEVEL, 0),
            Err(SubscriptionError::WrongKind)
        );
        let _ = object::release_object(console);

        // 递归订阅：另一个订阅对象。
        let other = new_subscription();
        assert_eq!(
            register(subscription, other, MODE_LEVEL, 0),
            Err(SubscriptionError::BadRequest)
        );

        // 填满到 interest 容量上限 4。
        assert_eq!(register(subscription, second, MODE_LEVEL, 0), Ok(()));
        let (third, third_payload) = new_event();
        let (fourth, fourth_payload) = new_event();
        assert_eq!(register(subscription, third, MODE_LEVEL, 0), Ok(()));
        assert_eq!(register(subscription, fourth, MODE_LEVEL, 0), Ok(()));
        assert_eq!(interest_count(subscription), Ok(MAX_INTERESTS));

        let (overflow, overflow_payload) = new_event();
        assert_eq!(
            register(subscription, overflow, MODE_LEVEL, 0),
            Err(SubscriptionError::TableFull)
        );

        drop_subscription(other);
        drop_subscription(subscription);
        drop_event(first, first_payload);
        drop_event(second, second_payload);
        drop_event(third, third_payload);
        drop_event(fourth, fourth_payload);
        drop_event(overflow, overflow_payload);
        prepare();
    }

    #[test]
    fn level_mode_reports_while_still_ready() {
        let _guard = lock();
        prepare();
        let subscription = new_subscription();
        let (target, payload) = new_event();
        assert_eq!(register(subscription, target, MODE_LEVEL, 0), Ok(()));

        assert_eq!(ready(subscription), Ok(false));
        let mut events = empty_events();
        assert_eq!(read(subscription, &mut events), Ok(0));

        event::signal(payload).expect("signal");
        assert_eq!(ready(subscription), Ok(true));

        assert_eq!(read(subscription, &mut events), Ok(1));
        assert_eq!(events[0].object(), target);
        assert_eq!(events[0].key(), 0);
        assert_eq!(events[0].mode, MODE_LEVEL);
        // 电平：仍就绪就继续报告，且 auto-reset 事件没有被消费。
        assert_eq!(read(subscription, &mut events), Ok(1));
        assert!(event::ready(payload).expect("event ready"));

        event::reset(payload).expect("reset");
        assert_eq!(ready(subscription), Ok(false));
        assert_eq!(read(subscription, &mut events), Ok(0));

        drop_subscription(subscription);
        drop_event(target, payload);
        prepare();
    }

    #[test]
    fn edge_mode_reports_once_until_read_then_rearms() {
        let _guard = lock();
        prepare();
        let subscription = new_subscription();
        let (target, payload) = new_event();
        assert_eq!(register(subscription, target, MODE_EDGE, 0), Ok(()));

        event::signal(payload).expect("signal");
        let mut events = empty_events();
        // poll 会反复看到它，但不消费边沿。
        assert_eq!(poll(subscription, &mut events), Ok(1));
        assert_eq!(poll(subscription, &mut events), Ok(1));
        assert_eq!(ready(subscription), Ok(true));

        // read 才消费边沿。
        assert_eq!(read(subscription, &mut events), Ok(1));
        assert_eq!(read(subscription, &mut events), Ok(0));
        assert_eq!(ready(subscription), Ok(false));

        // 目标回落到未就绪后重新就绪 → 新的边沿。
        event::reset(payload).expect("reset");
        assert_eq!(read(subscription, &mut events), Ok(0));
        event::signal(payload).expect("signal");
        assert_eq!(read(subscription, &mut events), Ok(1));

        drop_subscription(subscription);
        drop_event(target, payload);
        prepare();
    }

    #[test]
    fn event_pair_interests_use_the_endpoint_key() {
        let _guard = lock();
        prepare();
        let subscription = new_subscription();
        let payload = event::create_pair().expect("pair payload");
        let target =
            object::create_with_payload(ObjectKind::EventPair, payload).expect("pair object");

        assert_eq!(
            register(subscription, target, MODE_LEVEL, 2),
            Err(SubscriptionError::BadRequest)
        );
        assert_eq!(register(subscription, target, MODE_LEVEL, 1), Ok(()));

        // endpoint 0 的 signal 点亮对端 1。
        event::signal_pair(payload, 0).expect("signal pair");
        let mut events = empty_events();
        assert_eq!(read(subscription, &mut events), Ok(1));
        assert_eq!(events[0].object(), target);
        assert_eq!(events[0].key(), 1);
        assert_eq!(events[0].object_key, ((target as u64) << 32) | 1);

        drop_subscription(subscription);
        let _ = object::release_object(target);
        let _ = event::destroy_pair(payload, target);
        prepare();
    }

    #[test]
    fn unsubscribe_and_destroy_release_target_references() {
        let _guard = lock();
        prepare();
        let subscription = new_subscription();
        let (target, payload) = new_event();
        let baseline = object::object_refs(target).expect("refs");
        assert_eq!(register(subscription, target, MODE_LEVEL, 0), Ok(()));
        assert_eq!(object::object_refs(target), Some(baseline + 1));
        assert_eq!(interest_count(subscription), Ok(1));

        assert_eq!(unsubscribe(subscription, target), Ok(()));
        assert_eq!(object::object_refs(target), Some(baseline));
        assert_eq!(interest_count(subscription), Ok(0));
        assert_eq!(
            unsubscribe(subscription, target),
            Err(SubscriptionError::NotFound)
        );

        assert_eq!(register(subscription, target, MODE_LEVEL, 0), Ok(()));
        assert_eq!(object::object_refs(target), Some(baseline + 1));
        drop_subscription(subscription);
        assert_eq!(object::object_refs(target), Some(baseline));

        drop_event(target, payload);
        prepare();
    }

    #[test]
    fn replace_swaps_interests_atomically() {
        let _guard = lock();
        prepare();
        let subscription = new_subscription();
        let (first, first_payload) = new_event();
        let (second, second_payload) = new_event();
        assert_eq!(register(subscription, first, MODE_LEVEL, 0), Ok(()));

        let replacement = [
            Interest {
                target: second,
                mode: MODE_EDGE,
                key: 0,
            },
            Interest {
                target: first,
                mode: MODE_LEVEL,
                key: 0,
            },
        ];
        assert_eq!(replace(subscription, &replacement), Ok(()));
        assert_eq!(interest_count(subscription), Ok(2));

        // 重复目标的替换整批拒绝，不动已有 interest。
        let duplicated = [
            Interest {
                target: second,
                mode: MODE_LEVEL,
                key: 0,
            },
            Interest {
                target: second,
                mode: MODE_LEVEL,
                key: 0,
            },
        ];
        assert_eq!(
            replace(subscription, &duplicated),
            Err(SubscriptionError::BadRequest)
        );
        assert_eq!(interest_count(subscription), Ok(2));
        assert_eq!(
            replace(subscription, &[]),
            Err(SubscriptionError::BadRequest)
        );

        drop_subscription(subscription);
        drop_event(first, first_payload);
        drop_event(second, second_payload);
        prepare();
    }

    #[test]
    fn destroy_hook_defers_target_releases_until_release_pending() {
        let _guard = lock();
        prepare();
        object::register_destroy_hook_with_object(
            ObjectKind::EventSubscription,
            |kind, _payload, object| {
                if kind == ObjectKind::EventSubscription {
                    on_destroy(object);
                }
            },
        )
        .expect("hook");

        let subscription = new_subscription();
        let (target, payload) = new_event();
        let baseline = object::object_refs(target).expect("refs");
        assert_eq!(register(subscription, target, MODE_LEVEL, 0), Ok(()));
        assert_eq!(object::object_refs(target), Some(baseline + 1));

        // 释放订阅对象的最后一个引用 → 销毁钩子内只入队、不释放。
        assert!(object::release_object(subscription).is_ok());
        assert_eq!(count(), 0);
        assert_eq!(pending_count(), 1);
        assert_eq!(object::object_refs(target), Some(baseline + 1));

        assert_eq!(release_pending(), 1);
        assert_eq!(pending_count(), 0);
        assert_eq!(object::object_refs(target), Some(baseline));

        drop_event(target, payload);
        prepare();
    }

    #[test]
    fn edge_rearms_after_poll_while_not_ready() {
        let _guard = lock();
        prepare();
        let subscription = new_subscription();
        let (target, payload) = new_event();
        assert_eq!(register(subscription, target, MODE_EDGE, 0), Ok(()));
        let mut events = empty_events();

        // 第一次边沿：read 消费。
        event::signal(payload).expect("signal");
        assert_eq!(read(subscription, &mut events), Ok(1));
        assert_eq!(read(subscription, &mut events), Ok(0));

        // 目标回落未就绪后用 **poll** 抽干（以前只有 read 路径才清 observed）。
        event::reset(payload).expect("reset");
        assert_eq!(poll(subscription, &mut events), Ok(0));

        // 目标再次就绪 → 第二次边沿必须仍然上报。
        event::signal(payload).expect("signal");
        assert_eq!(poll(subscription, &mut events), Ok(1));
        assert_eq!(read(subscription, &mut events), Ok(1));
        assert_eq!(events[0].object(), target);
        assert_eq!(events[0].mode, MODE_EDGE);
        assert_eq!(read(subscription, &mut events), Ok(0));

        drop_subscription(subscription);
        drop_event(target, payload);
        prepare();
    }

    #[test]
    fn on_target_ready_wakes_only_reportable_subscriptions() {
        let _guard = lock();
        prepare();
        let first = new_subscription();
        let second = new_subscription();
        let (ready_target, ready_payload) = new_event();
        let (idle_target, idle_payload) = new_event();
        let (other_target, other_payload) = new_event();

        assert_eq!(register(first, ready_target, MODE_EDGE, 0), Ok(()));
        assert_eq!(register(second, idle_target, MODE_LEVEL, 0), Ok(()));

        // 未就绪：无可报告 interest → 不唤醒。
        assert_eq!(on_target_ready(ready_target), 0);
        assert_eq!(on_target_ready(idle_target), 0);
        // 没有任何订阅观察的目标 → 不唤醒。
        assert_eq!(on_target_ready(other_target), 0);

        // 就绪后两个订阅各自被唤醒一次；重复调用是幂等上报（不消费边沿）。
        event::signal(ready_payload).expect("signal");
        event::signal(idle_payload).expect("signal");
        assert_eq!(on_target_ready(ready_target), 1);
        assert_eq!(on_target_ready(ready_target), 1);
        assert_eq!(on_target_ready(idle_target), 1);

        // 唤醒不消费边沿：read 仍然能拿到事件。
        let mut events = empty_events();
        assert_eq!(read(first, &mut events), Ok(1));
        assert_eq!(events[0].object(), ready_target);
        // 已消费的边沿不再算“可报告”，不再唤醒。
        assert_eq!(on_target_ready(ready_target), 0);

        drop_subscription(first);
        drop_subscription(second);
        drop_event(ready_target, ready_payload);
        drop_event(idle_target, idle_payload);
        drop_event(other_target, other_payload);
        prepare();
    }

    /// w7 复核残余窗口：read 消费边沿后，目标侧自己把事件抽干（等价 `recv` 取走最后
    /// 一条消息），订阅侧没有 `poll`；随后 WAIT/`ready` 必须重新武装，下一次 signal 才能
    /// 再次唤醒并上报。
    #[test]
    fn ready_rearms_edge_drained_by_the_target_side() {
        let _guard = lock();
        prepare();
        let subscription = new_subscription();
        let (target, payload) = new_event();
        assert_eq!(register(subscription, target, MODE_EDGE, 0), Ok(()));
        let mut events = empty_events();

        // 第一轮：signal → read 消费边沿（observed=true）。
        event::signal(payload).expect("signal");
        assert_eq!(read(subscription, &mut events), Ok(1));
        assert_eq!(read(subscription, &mut events), Ok(0));

        // 目标侧自己抽干（不经订阅侧 poll）：目标是 auto-reset，consume 后不再就绪。
        assert!(event::consume(payload).expect("consume"));
        assert_eq!(event::ready(payload), Ok(false));

        // WAIT 路径（ready）必须观察到“未就绪”并重新武装，本次返回 false 且不消费任何东西。
        assert_eq!(ready(subscription), Ok(false));
        assert_eq!(ready(subscription), Ok(false));

        // 第二次 signal：唤醒必须是 1，read 必须重新上报该边沿。
        event::signal(payload).expect("signal");
        assert_eq!(on_target_ready(target), 1);
        assert_eq!(read(subscription, &mut events), Ok(1));
        assert_eq!(events[0].object(), target);
        assert_eq!(events[0].mode, MODE_EDGE);
        assert_eq!(read(subscription, &mut events), Ok(0));

        // 同样的窗口再走一遍，但这次用 on_target_ready 完成重新武装。
        assert!(event::consume(payload).expect("consume"));
        assert_eq!(on_target_ready(target), 0);
        event::signal(payload).expect("signal");
        assert_eq!(on_target_ready(target), 1);
        assert_eq!(read(subscription, &mut events), Ok(1));

        drop_subscription(subscription);
        drop_event(target, payload);
        prepare();
    }

    /// 最后一段 ET 窗口：read → 目标侧抽干 → 订阅侧**不调用** ready/poll → 源在抽干时
    /// 调用 `on_target_not_ready` → 源再次就绪 → 必须重新唤醒并上报第二次边沿。
    #[test]
    fn on_target_not_ready_rearms_before_the_next_signal() {
        let _guard = lock();
        prepare();
        let subscription = new_subscription();
        let (target, payload) = new_event();
        let (level_target, level_payload) = new_event();
        assert_eq!(register(subscription, target, MODE_EDGE, 0), Ok(()));
        assert_eq!(register(subscription, level_target, MODE_LEVEL, 0), Ok(()));
        let mut events = empty_events();

        // 第一轮边沿：read 消费。
        event::signal(payload).expect("signal");
        assert_eq!(read(subscription, &mut events), Ok(1));
        assert_eq!(read(subscription, &mut events), Ok(0));

        // 目标侧抽干后立刻通知；不经过订阅侧任何 ready/poll。
        assert!(event::consume(payload).expect("consume"));
        assert_eq!(on_target_not_ready(target), 1);
        // 幂等：已重新武装，再调不重复计数。
        assert_eq!(on_target_not_ready(target), 0);
        // 只动该目标的 ET：LT interest 与其它目标完全不受影响。
        assert_eq!(on_target_not_ready(level_target), 0);

        // 源再次就绪 → 唤醒且能重新上报。
        event::signal(payload).expect("signal");
        assert_eq!(on_target_ready(target), 1);
        assert_eq!(read(subscription, &mut events), Ok(1));
        assert_eq!(events[0].object(), target);
        assert_eq!(events[0].mode, MODE_EDGE);
        assert_eq!(read(subscription, &mut events), Ok(0));

        // 误调用保护：目标仍就绪时 on_target_not_ready 不得清掉已上报的边沿，
        // 否则同一条边沿会被重复上报。
        assert_eq!(on_target_not_ready(target), 0);
        assert_eq!(read(subscription, &mut events), Ok(0));

        drop_subscription(subscription);
        drop_event(target, payload);
        drop_event(level_target, level_payload);
        prepare();
    }
}
