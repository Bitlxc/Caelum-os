//! 事件计数器对象（eventfd）的内核实现（M8g）。
//!
//! 一个 eventfd 是一个 64 位无符号计数器加两个标志：
//!
//! - `EFD_SEMAPHORE`：`read` 每次消耗 1（返回 1），而不是读走整值并清零；
//! - `EFD_NONBLOCK`：只作为查询状态保存，阻塞/`EAGAIN` 的判定由 syscall 层按
//!   Linux 语义决定（本模块永远返回 [`EventFdError::WouldBlock`] 而不是 `EAGAIN`）。
//!
//! 语义（与 Linux 对齐）：
//!
//! - `write` **累加**计数，绝不覆盖旧值；`value == u64::MAX` 是非法参数
//!   （Linux 用它表示“无限制”），累加溢出返回 `WouldBlock`；
//! - `read` 在计数为 0 时返回 `WouldBlock`；否则返回 `u64` 值（普通模式清零，
//!   semaphore 模式减 1 并返回 1）；
//! - 可读 = 计数非 0；可写 = 计数 `< u64::MAX`；
//! - `dup` 出来的句柄共享同一个对象负载，因此天然共享计数器；
//! - 对象销毁（最后一个引用释放）时清槽，并给等待者 `Destroyed` 唤醒。
//!
//! 唤醒纪律：计数在 0↔非 0 之间变化后，**必须在释放本表锁之后**调用
//! `process::wake_object` 与 `subscription::on_target_ready/not_ready`：前者会拿
//! 进程表锁，后者会重新进入 `ipc::poll_waitable_keyed`（本模块表锁）。
//!
//! 本模块不分配、不打印、不访问对象表，因此可从阻塞等待的唤醒路径调用。

use crate::object::ObjectId;
use crate::process::{self, WakeReason};

use super::{IrqCell, payload_for_slot, slot_from_payload};

/// 同时存在的 eventfd 上限（固定静态表，无堆）。
pub const MAX_EVENTFDS: usize = 8;

/// `EFD_SEMAPHORE`：`read` 消耗 1 而不是整值。
pub const EFD_SEMAPHORE: u32 = 0x0_0001;
/// `EFD_NONBLOCK`：创建时记录为非阻塞状态，供 syscall 层查询。
pub const EFD_NONBLOCK: u32 = 0o0004000;
/// `EFD_CLOEXEC`：exec 时关闭；由 Linux 人格层的 fd 表处理，本模块只接受该位。
pub const EFD_CLOEXEC: u32 = 0o2000000;

/// eventfd 操作错误。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum EventFdError {
    /// 固定表已满（Linux 对应 `EMFILE`）。
    TableFull,
    /// 对象没有对应的 eventfd 槽（已销毁或类型不符，Linux 对应 `EBADF`）。
    NoSuchObject,
    /// 负载/对象类型不匹配。
    WrongKind,
    /// 参数非法（flags 越界、`write(u64::MAX)`，Linux 对应 `EINVAL`）。
    BadValue,
    /// 当前无法完成（计数为 0 的读、累加溢出、非阻塞读；Linux 对应 `EAGAIN`
    /// 或“应阻塞等待”）。
    WouldBlock,
    /// payload 无法解析成表槽。
    InvalidPayload,
}

impl EventFdError {
    /// 稳定诊断串（不得用于 ABI 判断）。
    pub const fn as_str(self) -> &'static str {
        match self {
            EventFdError::TableFull => "eventfd-table-full",
            EventFdError::NoSuchObject => "eventfd-no-such-object",
            EventFdError::WrongKind => "eventfd-wrong-kind",
            EventFdError::BadValue => "eventfd-bad-value",
            EventFdError::WouldBlock => "eventfd-would-block",
            EventFdError::InvalidPayload => "eventfd-invalid-payload",
        }
    }

    /// 是否为“现在无法完成、调用方应等待或返回 `EAGAIN`”的类错误。
    pub const fn is_would_block(self) -> bool {
        matches!(self, EventFdError::WouldBlock)
    }
}

/// 表槽绑定的“无对象”哨兵（`ObjectId::MAX` 不会被对象表分配）。
const NO_OBJECT: ObjectId = ObjectId::MAX;

/// 一个 eventfd 槽。
#[derive(Clone, Copy)]
struct EventFdSlot {
    live: bool,
    object: ObjectId,
    counter: u64,
    semaphore: bool,
    nonblock: bool,
}

impl EventFdSlot {
    const EMPTY: EventFdSlot = EventFdSlot {
        live: false,
        object: NO_OBJECT,
        counter: 0,
        semaphore: false,
        nonblock: false,
    };
}

/// 固定容量的 eventfd 表。
struct EventFdTable {
    slots: [EventFdSlot; MAX_EVENTFDS],
    live: usize,
}

impl EventFdTable {
    const fn new() -> EventFdTable {
        EventFdTable {
            slots: [EventFdSlot::EMPTY; MAX_EVENTFDS],
            live: 0,
        }
    }

    /// 槽下标（不要求 live；调用方自行判断）。
    fn index_of(&self, object: ObjectId) -> Option<usize> {
        self.slots
            .iter()
            .position(|slot| slot.live && slot.object == object)
    }

    fn slot_mut(&mut self, object: ObjectId) -> Option<&mut EventFdSlot> {
        let index = self.index_of(object)?;
        self.slots.get_mut(index)
    }
}

static TABLE: IrqCell<EventFdTable> = IrqCell::new(EventFdTable::new());

/// payload → 表槽（不做对象查找）。
fn slot_of(payload: u64) -> Result<usize, EventFdError> {
    slot_from_payload(payload, MAX_EVENTFDS).map_err(|_| EventFdError::InvalidPayload)
}

/// 创建一个 eventfd，返回它的对象负载（尚未绑定 `ObjectId`）。
///
/// `initval` 是初始计数；`flags` 只接受 `EFD_SEMAPHORE`/`EFD_NONBLOCK`/`EFD_CLOEXEC`。
pub fn create(initval: u64, flags: u32) -> Result<u64, EventFdError> {
    let known = EFD_SEMAPHORE | EFD_NONBLOCK | EFD_CLOEXEC;
    if flags & !known != 0 {
        return Err(EventFdError::BadValue);
    }
    TABLE.with(|table| {
        let slot = table
            .slots
            .iter()
            .position(|slot| !slot.live)
            .ok_or(EventFdError::TableFull)?;
        table.slots[slot] = EventFdSlot {
            live: true,
            object: NO_OBJECT,
            counter: initval,
            semaphore: flags & EFD_SEMAPHORE != 0,
            nonblock: flags & EFD_NONBLOCK != 0,
        };
        table.live += 1;
        Ok(payload_for_slot(slot))
    })
}

/// 把 eventfd 槽绑定到它的对象编号（由 `ipc::insert_eventfd` 在对象创建后调用）。
///
/// 绑定只服务于唤醒路由；对象生命周期仍由对象表与销毁钩子负责。
pub fn bind(payload: u64, object: ObjectId) -> Result<(), EventFdError> {
    let slot = slot_of(payload)?;
    TABLE.with(|table| match table.slots.get_mut(slot) {
        Some(entry) if entry.live => {
            entry.object = object;
            Ok(())
        }
        _ => Err(EventFdError::InvalidPayload),
    })
}

/// 创建失败/未发布对象的清理：只释放槽，不唤醒（没有对象可唤醒）。
///
/// 槽已经释放时视为成功，方便调用方统一写清理路径。
pub(crate) fn discard(payload: u64) -> Result<(), EventFdError> {
    let slot = slot_of(payload)?;
    TABLE.with(|table| match table.slots.get_mut(slot) {
        Some(entry) if entry.live => {
            *entry = EventFdSlot::EMPTY;
            table.live = table.live.saturating_sub(1);
            Ok(())
        }
        _ => Ok(()),
    })
}

/// 读取计数，返回读到的值并消费之。
///
/// - 普通模式：返回整值并把计数清零；
/// - `EFD_SEMAPHORE`：计数减 1 并返回 1；
/// - 计数为 0 时返回 [`EventFdError::WouldBlock`]（由 syscall 层决定阻塞或 `EAGAIN`）。
///
/// 计数被抽干后会在锁外唤醒写等待者，并通知订阅侧“不再可读”。
pub fn read(object: ObjectId) -> Result<u64, EventFdError> {
    let (value, drained, became_zero) = TABLE.with(|table| {
        let entry = table.slot_mut(object).ok_or(EventFdError::NoSuchObject)?;
        if entry.counter == 0 {
            return Err(EventFdError::WouldBlock);
        }
        let (value, drained) = if entry.semaphore {
            entry.counter -= 1;
            (1, entry.counter == 0)
        } else {
            let consumed = entry.counter;
            entry.counter = 0;
            (consumed, true)
        };
        Ok((value, drained, true))
    })?;
    if drained {
        // 抽干后写方向重新可写：唤醒阻塞在“写溢出”上的等待者。
        let _ = process::wake_object(object, WakeReason::Ready);
        let _ = super::epoll::notify_target(object);
        // 0 → 就绪态消失，订阅侧需要清掉边沿缓存后才能重新武装。
        let _ = super::subscription::on_target_not_ready(object);
    }
    let _ = became_zero;
    Ok(value)
}

/// 累加计数；`value == u64::MAX` 非法，累加超过内核上限 `u64::MAX - 1` 返回
/// `WouldBlock`（Linux 语义：计数器最大合法值为 `u64::MAX - 1`）。
///
/// 每次成功写入都会在锁外通知 epoll：按 M9b 的 ET 语义，写入本身就是目标的
/// 新活动，必须清空 ET 边沿缓存；计数从 0 变为非 0 时还会额外唤醒读等待者
/// 并通知订阅侧可读。
pub fn write(object: ObjectId, value: u64) -> Result<(), EventFdError> {
    if value == u64::MAX {
        return Err(EventFdError::BadValue);
    }
    let became_readable = TABLE.with(|table| {
        let entry = table.slot_mut(object).ok_or(EventFdError::NoSuchObject)?;
        // Linux caps an eventfd counter at `u64::MAX - 1`: a write that would
        // reach `u64::MAX` is refused so the value can never saturate at the
        // illegal maximum.
        debug_assert!(
            entry.counter <= u64::MAX - 1,
            "eventfd counter above its cap"
        );
        if value > (u64::MAX - 1) - entry.counter {
            return Err(EventFdError::WouldBlock);
        }
        let was_zero = entry.counter == 0;
        entry.counter += value;
        Ok(was_zero && entry.counter != 0)
    })?;
    // ET：每次成功写入都是新活动，清空 epoll 的边沿缓存，使未 drain 的再次
    // 写入也能在下一次 epoll_wait 产生新边沿；读等待者与订阅侧仍只关心 0→非 0。
    let _ = super::epoll::notify_target(object);
    if became_readable {
        let _ = process::wake_object(object, WakeReason::Ready);
        let _ = super::subscription::on_target_ready(object);
    }
    Ok(())
}

/// 是否可读（计数非 0）；对象不存在返回 `NoSuchObject`。
pub fn readable(object: ObjectId) -> Result<bool, EventFdError> {
    TABLE.with(|table| {
        table
            .slot_mut(object)
            .map(|entry| entry.counter > 0)
            .ok_or(EventFdError::NoSuchObject)
    })
}

/// 是否可写（计数 `< u64::MAX - 1`，即还没到 Linux 的合法上限）；对象不存在
/// 返回 `NoSuchObject`。
pub fn writable(object: ObjectId) -> Result<bool, EventFdError> {
    TABLE.with(|table| {
        table
            .slot_mut(object)
            .map(|entry| entry.counter < u64::MAX - 1)
            .ok_or(EventFdError::NoSuchObject)
    })
}

/// 创建时是否带 `EFD_NONBLOCK`。
pub fn nonblocking(object: ObjectId) -> Result<bool, EventFdError> {
    TABLE.with(|table| {
        table
            .slot_mut(object)
            .map(|entry| entry.nonblock)
            .ok_or(EventFdError::NoSuchObject)
    })
}

/// 当前存活的 eventfd 数量（诊断/关闭期自检）。
pub fn live_count() -> usize {
    TABLE.with(|table| table.live)
}

/// 对象销毁钩子：清槽并在锁外唤醒等待者、通知订阅清理。
///
/// 允许重复调用（槽已清则只做唤醒），因此“释放初始引用 + 显式销毁”两条
/// 失败路径可以都走这里。
pub fn on_destroy(object: ObjectId) {
    TABLE.with(|table| {
        if let Some(slot) = table.index_of(object) {
            table.slots[slot] = EventFdSlot::EMPTY;
            table.live = table.live.saturating_sub(1);
        }
    });
    // 对象已经失效：等待者必须收到明确原因，订阅侧必须清掉目标引用。
    let _ = process::wake_object(object, WakeReason::Destroyed);
    let _ = super::epoll::notify_target(object);
    let _ = super::subscription::on_target_destroy(object);
}

/// 清空所有槽（仅测试）。
#[cfg(test)]
pub(crate) fn reset_for_test() {
    TABLE.with(|table| *table = EventFdTable::new());
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::object::{HandleTable, ObjectKind, Rights};

    fn lock() -> std::sync::MutexGuard<'static, ()> {
        crate::object::test_lock()
    }

    /// 建一个已绑定对象编号的 eventfd（测试专用，绕开对象/句柄表）。
    fn bound(initval: u64, flags: u32, object: ObjectId) -> u64 {
        let payload = create(initval, flags).expect("create");
        bind(payload, object).expect("bind");
        payload
    }

    #[test]
    fn read_returns_the_whole_counter_and_clears_it() {
        let _guard = lock();
        reset_for_test();
        let payload = bound(5, 0, 0x0101);
        assert_eq!(read(0x0101), Ok(5));
        assert_eq!(read(0x0101), Err(EventFdError::WouldBlock));
        assert_eq!(readable(0x0101), Ok(false));
        discard(payload).expect("discard");
    }

    #[test]
    fn write_accumulates_instead_of_overwriting() {
        let _guard = lock();
        reset_for_test();
        let payload = bound(2, 0, 0x0202);
        assert_eq!(write(0x0202, 3), Ok(()));
        assert_eq!(write(0x0202, 0), Ok(()));
        assert_eq!(read(0x0202), Ok(5));
        discard(payload).expect("discard");
    }

    #[test]
    fn semaphore_reads_consume_one_at_a_time() {
        let _guard = lock();
        reset_for_test();
        let payload = bound(3, EFD_SEMAPHORE, 0x0303);
        assert_eq!(read(0x0303), Ok(1));
        assert_eq!(read(0x0303), Ok(1));
        assert_eq!(read(0x0303), Ok(1));
        assert_eq!(read(0x0303), Err(EventFdError::WouldBlock));
        assert_eq!(readable(0x0303), Ok(false));
        discard(payload).expect("discard");
    }

    #[test]
    fn overflow_and_impossible_values_are_rejected() {
        let _guard = lock();
        reset_for_test();
        // Linux caps the counter at `u64::MAX - 1`: the last legal write lands
        // exactly on the cap, and one more byte must be refused instead of
        // saturating at the illegal `u64::MAX`.
        let payload = bound(u64::MAX - 2, 0, 0x0404);
        assert_eq!(writable(0x0404), Ok(true));
        assert_eq!(write(0x0404, 1), Ok(()));
        assert_eq!(writable(0x0404), Ok(false));
        assert_eq!(write(0x0404, 1), Err(EventFdError::WouldBlock));
        assert_eq!(write(0x0404, u64::MAX), Err(EventFdError::BadValue));
        // The counter is exactly at the cap, never at `u64::MAX`.
        assert_eq!(read(0x0404), Ok(u64::MAX - 1));
        assert_eq!(readable(0x0404), Ok(false));
        assert_eq!(writable(0x0404), Ok(true));
        discard(payload).expect("discard");
    }

    #[test]
    fn unknown_flags_are_rejected_and_nonblock_is_reported() {
        let _guard = lock();
        reset_for_test();
        assert_eq!(create(0, 0x8000_0000), Err(EventFdError::BadValue));
        let payload = create(0, EFD_NONBLOCK | EFD_CLOEXEC).expect("create");
        bind(payload, 0x0505).expect("bind");
        assert_eq!(nonblocking(0x0505), Ok(true));
        assert_eq!(readable(0x0505), Ok(false));
        assert_eq!(writable(0x0505), Ok(true));
        discard(payload).expect("discard");
    }

    #[test]
    fn table_capacity_and_destroy_release_the_slot() {
        let _guard = lock();
        reset_for_test();
        let mut payloads = [0u64; MAX_EVENTFDS];
        for (index, payload) in payloads.iter_mut().enumerate() {
            *payload = create(0, 0).expect("create within capacity");
            bind(*payload, 0x1000 + index as ObjectId).expect("bind");
        }
        assert_eq!(create(0, 0), Err(EventFdError::TableFull));
        assert_eq!(live_count(), MAX_EVENTFDS);
        for payload in payloads {
            discard(payload).expect("discard");
        }
        assert_eq!(live_count(), 0);
        assert_eq!(create(0, 0).is_ok(), true);
        reset_for_test();
    }

    #[test]
    fn unknown_object_reports_no_such_object() {
        let _guard = lock();
        reset_for_test();
        assert_eq!(read(0x2222), Err(EventFdError::NoSuchObject));
        assert_eq!(readable(0x2222), Err(EventFdError::NoSuchObject));
        assert_eq!(write(0x2222, 1), Err(EventFdError::NoSuchObject));
        assert_eq!(nonblocking(0x2222), Err(EventFdError::NoSuchObject));
    }

    #[test]
    fn insertion_through_ipc_registers_a_waitable_object() {
        let _guard = lock();
        reset_for_test();
        let _ = crate::object::reset_destroy_hooks();
        super::super::install_destroy_hooks().expect("hooks");
        let mut table = HandleTable::new();
        let handle = super::super::insert_eventfd(
            &mut table,
            3,
            0,
            Rights::READ.union(Rights::WRITE).union(Rights::WAIT),
        )
        .expect("insert eventfd");
        let resolved =
            crate::object::resolve_handle(&table, handle, Rights::READ).expect("resolve");
        let object = resolved.object;
        assert_eq!(ObjectKind::EventFd.name(), "event-fd");
        assert_eq!(
            super::super::poll_waitable_keyed(object, 0, false),
            Ok(true)
        );
        assert_eq!(
            super::super::poll_waitable_keyed(object, 1, false),
            Err(super::super::IpcError::InvalidEndpoint)
        );
        assert_eq!(read(object), Ok(3));
        assert_eq!(
            super::super::poll_waitable_keyed(object, 0, false),
            Ok(false)
        );
        assert_eq!(write(object, 2), Ok(()));
        assert_eq!(
            super::super::poll_waitable_keyed(object, 0, false),
            Ok(true)
        );
        assert_eq!(read(object), Ok(2));
        assert_eq!(live_count(), 1);
        let cleared = crate::object::clear_handle_table(&mut table);
        assert!(cleared >= 1);
        assert_eq!(live_count(), 0);
        reset_for_test();
    }

    #[test]
    fn every_successful_write_rearms_the_epoll_edge() {
        let _guard = lock();
        reset_for_test();
        super::super::epoll::reset_for_test();
        let payload = bound(0, 0, 0x0606);
        let set = 0x0607;
        let epoll_payload = super::super::epoll::create().expect("epoll create");
        super::super::epoll::bind(epoll_payload, set).expect("epoll bind");
        super::super::epoll::ctl_add(
            set,
            0x0606,
            super::super::epoll::EPOLLIN | super::super::epoll::EPOLLET,
            0,
        )
        .expect("ctl add");
        let mut out = [super::super::epoll::ReadyEvent {
            target: 0,
            data: 0,
            events: 0,
        }; super::super::epoll::MAX_EPOLL_INTERESTS];
        write(0x0606, 1).expect("first write");
        assert_eq!(super::super::epoll::scan(set, &mut out), Ok(1));
        assert_eq!(
            out[0].events & super::super::epoll::EPOLLIN,
            super::super::epoll::EPOLLIN
        );
        // 连续可读且没有新写入：ET 不重复报告。
        assert_eq!(super::super::epoll::scan(set, &mut out), Ok(0));
        // 不 drain 直接再写：每次成功 write 都是新活动，必须重新产生边沿。
        write(0x0606, 1).expect("second write");
        assert_eq!(super::super::epoll::scan(set, &mut out), Ok(1));
        // 计数仍是累加值，直到被读取。
        assert_eq!(read(0x0606), Ok(2));
        discard(payload).expect("discard");
        super::super::epoll::reset_for_test();
    }
}
