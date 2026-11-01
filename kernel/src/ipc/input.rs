//! Console-seat input table（M6c，B1）。
//!
//! M6c 的输入路径由两部分组成：
//!
//! - `crate::input`（M3 遗留）从 8042 键盘与 16550 UART 读出原始字节；
//! - 本模块把其中**真正被记录**的键盘 make/break 与串口字节发布成一条标准化的
//!   `InputEventWire`，放在一个固定容量的 ring 里，供一个 console seat 对象读取。
//!
//! 本模块只做“单 seat × 64 项 ring”的簿记，不做用户态映射，也不做权限/座位策略：
//! 谁创建 seat、谁能读，属于对象层与 syscall 层。设计约束与既有 IPC 表一致：
//!
//! - 固定容量、无堆：同一时刻最多一个 seat，ring 固定 [`RING_CAPACITY`] 项；
//! - 表访问经 [`IrqCell`]（关本 CPU 中断 + 跨 CPU 自旋）；闭包内只改本表、
//!   只抄出需要唤醒的对象编号，唤醒（`process::wake_object`）在锁外完成，
//!   以免在 IPC 表锁内进入进程表；
//! - `publish_*` 运行在中断上下文（键盘/串口 IRQ）：不打印、不分配、不睡眠；
//! - 没有 seat 时 `publish_*` 是**零副作用**的空操作（M3 阶段不会创建 seat，
//!   输入路径必须保持和 M3 完全一致的行为与计数）。
//!
//! ring 满时丢弃**最旧**的一条并累加 [`dropped_count`]：输入流宁可丢旧事件，也
//! 不能让新事件排队等待，否则键盘会越用越滞后。
//!
//! 宿主测试用 `object::test_lock` 串行化全局表，并用注入缝记录“应当发生的唤醒”
//! （宿主上没有当前进程，真实的 `process::wake_object` 返回 0）。

use core::mem::size_of;

use crate::object::{self, ObjectId, ObjectKind};
use crate::process::{self, WakeReason};
use crate::time;

use super::IrqCell;

/// 同时存在的 console seat 上限（M6c 只有单 seat）。
pub const MAX_SEATS: usize = 1;

/// 输入 ring 容量（固定，丢最旧）。
pub const RING_CAPACITY: usize = 64;

/// 事件种类：键盘（make/break 已解码）。
pub const KIND_KEYBOARD: u8 = 1;

/// 事件种类：串口接收字节。
pub const KIND_SERIAL: u8 = 2;

/// 发布到 ring 的标准化输入事件（线上布局，24 字节）。
///
/// 布局由 Lead 冻结：`kind:u8, code:u8, sequence:u32, reserved:u32,
/// timestamp_ms:u64`，按 `repr(C)` 自然对齐后正好 24 字节。`reserved` 必须写 0，
/// 为将来（例如 seat 编号或压力值）保留。
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct InputEventWire {
    /// [`KIND_KEYBOARD`] 或 [`KIND_SERIAL`]。
    pub kind: u8,
    /// 键盘：原始 set-1 扫描码——按下（make）是扫描码本身，松开（break）保留
    /// `0x80` 位（即 `scancode | 0x80`）；串口：原始字节。
    pub code: u8,
    /// 事件序号，从 1 起单调递增（按 `u32` 回绕）。
    pub sequence: u32,
    /// 保留字段，恒为 0。
    pub reserved: u32,
    /// 发布时刻的单调毫秒时间戳（`time::monotonic_millis`）。
    pub timestamp_ms: u64,
}

impl InputEventWire {
    /// 零值事件（ring 初值与测试用）。
    pub const EMPTY: Self = Self {
        kind: 0,
        code: 0,
        sequence: 0,
        reserved: 0,
        timestamp_ms: 0,
    };
}

impl Default for InputEventWire {
    fn default() -> Self {
        Self::EMPTY
    }
}

// 线上布局必须与 Lead 冻结的 24 字节一致（防字段顺序/对齐漂移）。
const _: () = assert!(size_of::<InputEventWire>() == 24);

/// 输入表操作的错误；`as_str` 供 syscall 层诊断与 ABI 错误码映射使用。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum InputError {
    /// 已经有另一个存活的 seat（[`MAX_SEATS`] = 1）。
    TableFull,
    /// 对象编号不是存活对象（已销毁或编号无效）。
    NoSuchObject,
    /// 对象存活但不是输入对象。
    WrongKind,
}

impl InputError {
    /// 稳定的诊断字符串。
    pub const fn as_str(self) -> &'static str {
        match self {
            InputError::TableFull => "input-table-full",
            InputError::NoSuchObject => "input-no-such-object",
            InputError::WrongKind => "input-wrong-kind",
        }
    }
}

/// 一个 seat 的 ring 状态。
#[derive(Clone, Copy)]
struct Seat {
    /// 槽是否在用。
    live: bool,
    /// 对应的对象编号。
    object: ObjectId,
    /// ring 存储。
    ring: [InputEventWire; RING_CAPACITY],
    /// 下一次写入位置。
    head: usize,
    /// 下一次读取位置。
    tail: usize,
    /// 当前条目数。
    len: usize,
}

/// 空闲槽的初值。
const EMPTY_SEAT: Seat = Seat {
    live: false,
    object: ObjectId::MAX,
    ring: [InputEventWire::EMPTY; RING_CAPACITY],
    head: 0,
    tail: 0,
    len: 0,
};

/// 输入固定表。
struct InputTable {
    seats: [Seat; MAX_SEATS],
    /// 下一条事件使用的序号（从 1 起，按 `u32` 回绕）。
    next_sequence: u32,
    /// 自本次启动以来成功发布的事件数（跨 seat 累计）。
    published: u64,
    /// 自本次启动以来因 ring 满被丢弃的事件数（跨 seat 累计）。
    dropped: u64,
}

impl InputTable {
    const fn new() -> Self {
        Self {
            seats: [EMPTY_SEAT; MAX_SEATS],
            next_sequence: 1,
            published: 0,
            dropped: 0,
        }
    }

    /// 存活 seat 数。
    fn count(&self) -> usize {
        self.seats.iter().filter(|seat| seat.live).count()
    }

    /// 按对象编号找 seat 下标。
    fn seat_of(&self, object: ObjectId) -> Option<usize> {
        self.seats
            .iter()
            .position(|seat| seat.live && seat.object == object)
    }
}

static TABLE: IrqCell<InputTable> = IrqCell::new(InputTable::new());

/// 把一个已经创建的对象登记为 console seat。
///
/// `object` 必须是一个存活的输入对象。重复登记同一个对象是幂等的（返回 `Ok`）；
/// 已有别的存活 seat 时返回 [`InputError::TableFull`]。失败不占用槽位。
pub fn create(object: ObjectId) -> Result<(), InputError> {
    match object::object_kind(object) {
        None => return Err(InputError::NoSuchObject),
        Some(kind) if kind != ObjectKind::Input => return Err(InputError::WrongKind),
        Some(_) => {}
    }
    TABLE.with(|table| {
        if let Some(index) = table.seat_of(object) {
            let _ = index;
            return Ok(());
        }
        let Some(slot) = table.seats.iter().position(|seat| !seat.live) else {
            return Err(InputError::TableFull);
        };
        table.seats[slot] = Seat {
            live: true,
            object,
            ..EMPTY_SEAT
        };
        Ok(())
    })
}

/// 解除 seat 登记并唤醒它的拥有者（`WakeReason::Destroyed`）。
///
/// 返回是否真的回收了一个 seat。幂等：对象没有登记时返回 `false`，且不会唤醒。
/// 可以在对象销毁钩子内调用：闭包只改本表，唤醒在锁外进行，不回调对象表。
pub fn destroy(object: ObjectId) -> bool {
    let live = TABLE.with(|table| {
        let Some(slot) = table.seat_of(object) else {
            return false;
        };
        // 只解除登记：ring 内容随槽一起丢弃，不再发布路由。
        table.seats[slot] = EMPTY_SEAT;
        true
    });
    if live {
        wake(object, WakeReason::Destroyed, WAKE_DESTROYED);
    }
    live
}

/// 对象销毁钩子入口（在对象层销毁钩子内调用，不回调对象表）。
pub fn on_destroy(object: ObjectId) {
    let _ = destroy(object);
}

/// 发布一条键盘事件（IRQ 上下文，不打印、不分配）。
///
/// `code` 是**原始扫描码**：按键按下（make）传扫描码本身，松开（break）传
/// `scancode | 0x80`。调用方（`crate::input::record_scancode`）负责把解码器已经在
/// break 上剥掉的 0x80 放回去，用户态据此区分按下与松开。
/// 没有存活 seat 时是空操作，不改变任何计数。
pub fn publish_keyboard(code: u8) {
    publish(KIND_KEYBOARD, code);
}

/// 发布一条串口接收事件（IRQ 上下文，不打印、不分配）。
pub fn publish_serial(byte: u8) {
    publish(KIND_SERIAL, byte);
}

/// 发布一条事件：写 ring（满则丢最旧），并唤醒 seat 拥有者。
fn publish(kind: u8, code: u8) {
    let timestamp_ms = time::monotonic_millis();
    let pending_wake = TABLE.with(|table| {
        let Some(slot) = table.seats.iter().position(|seat| seat.live) else {
            // 没有 seat：零副作用（M3 阶段就是这种情况）。
            return None;
        };
        let sequence = table.next_sequence;
        table.next_sequence = table.next_sequence.wrapping_add(1);
        let owner = table.seats[slot].object;
        let mut dropped = false;
        {
            let seat = &mut table.seats[slot];
            if seat.len == RING_CAPACITY {
                // 满：丢最旧，让 ring 始终保留最新的输入。
                seat.tail = (seat.tail + 1) % RING_CAPACITY;
                seat.len -= 1;
                dropped = true;
            }
            seat.ring[seat.head] = InputEventWire {
                kind,
                code,
                sequence,
                reserved: 0,
                timestamp_ms,
            };
            seat.head = (seat.head + 1) % RING_CAPACITY;
            seat.len += 1;
        }
        table.published = table.published.saturating_add(1);
        if dropped {
            table.dropped = table.dropped.saturating_add(1);
        }
        Some(owner)
    });
    if let Some(owner) = pending_wake {
        wake(owner, WakeReason::Ready, WAKE_READY);
    }
}

/// 读取最多 `out.len()` 条事件（从最旧开始），返回实际复制条数。
///
/// 对象没有登记（已销毁/编号无效/不是本模块的 seat）时返回 0，不产生副作用。
/// 读走的事件会从 ring 移除；剩余事件保留给下一次读取。
pub fn read(object: ObjectId, out: &mut [InputEventWire]) -> usize {
    TABLE.with(|table| {
        let Some(slot) = table.seat_of(object) else {
            return 0;
        };
        let seat = &mut table.seats[slot];
        let count = core::cmp::min(seat.len, out.len());
        for item in out.iter_mut().take(count) {
            *item = seat.ring[seat.tail];
            seat.tail = (seat.tail + 1) % RING_CAPACITY;
            seat.len -= 1;
        }
        count
    })
}

/// 是否还有可读事件（不消费）。
pub fn poll(object: ObjectId) -> bool {
    TABLE.with(|table| {
        table
            .seat_of(object)
            .is_some_and(|slot| table.seats[slot].len > 0)
    })
}

/// 当前存活的 seat 数。
pub fn live_objects() -> usize {
    TABLE.with(|table| table.count())
}

/// 自本次启动以来成功发布的事件数（跨 seat 累计）。
pub fn published_count() -> u64 {
    TABLE.with(|table| table.published)
}

/// 自本次启动以来因 ring 满被丢弃的事件数（跨 seat 累计）。
pub fn dropped_count() -> u64 {
    TABLE.with(|table| table.dropped)
}

/// 清空表与计数（仅供宿主测试；正常路径由对象销毁钩子清槽）。
#[cfg(test)]
pub(crate) fn reset() {
    TABLE.with(|table| *table = InputTable::new());
    wake_seam::reset();
}

// -- 唤醒注入缝 ------------------------------------------------------------
//
// 宿主测试没有“当前进程”，`process::wake_object` 会返回 0；为了仍然能验证
// “destroy 唤醒 Destroyed、publish 唤醒 Ready”，这里记录最近一次唤醒意图。
// 生产构建只有 `process::wake_object` 一次调用。

/// 唤醒原因编码：就绪。
const WAKE_READY: u8 = 1;
/// 唤醒原因编码：对象已销毁。
const WAKE_DESTROYED: u8 = 2;

/// 锁外唤醒：先记录测试意图，再调用真实的进程层唤醒。
fn wake(object: ObjectId, reason: WakeReason, reason_code: u8) {
    #[cfg(test)]
    wake_seam::record(object, reason_code);
    #[cfg(not(test))]
    let _ = reason_code;
    let _ = process::wake_object(object, reason);
}

#[cfg(test)]
mod wake_seam {
    use super::ObjectId;
    use core::sync::atomic::{AtomicU8, AtomicU16, AtomicU32, Ordering};

    /// 最近一次唤醒的对象编号（`u16::MAX` 表示“没有”）。
    static LAST_OBJECT: AtomicU32 = AtomicU32::new(u32::MAX);
    /// 最近一次唤醒的原因编码（0 表示“没有”）。
    static LAST_REASON: AtomicU8 = AtomicU8::new(0);
    /// `Ready` 唤醒次数。
    static READY_WAKES: AtomicU16 = AtomicU16::new(0);
    /// `Destroyed` 唤醒次数。
    static DESTROYED_WAKES: AtomicU16 = AtomicU16::new(0);

    pub(super) fn record(object: ObjectId, reason_code: u8) {
        LAST_OBJECT.store(u32::from(object), Ordering::SeqCst);
        LAST_REASON.store(reason_code, Ordering::SeqCst);
        match reason_code {
            super::WAKE_READY => {
                READY_WAKES.fetch_add(1, Ordering::SeqCst);
            }
            super::WAKE_DESTROYED => {
                DESTROYED_WAKES.fetch_add(1, Ordering::SeqCst);
            }
            _ => {}
        }
    }

    pub(super) fn last() -> Option<(ObjectId, u8)> {
        let object = LAST_OBJECT.load(Ordering::SeqCst);
        let reason = LAST_REASON.load(Ordering::SeqCst);
        if object == u32::MAX || reason == 0 {
            None
        } else {
            Some((object as ObjectId, reason))
        }
    }

    pub(super) fn ready_wakes() -> u16 {
        READY_WAKES.load(Ordering::SeqCst)
    }

    pub(super) fn destroyed_wakes() -> u16 {
        DESTROYED_WAKES.load(Ordering::SeqCst)
    }

    pub(super) fn reset() {
        LAST_OBJECT.store(u32::MAX, Ordering::SeqCst);
        LAST_REASON.store(0, Ordering::SeqCst);
        READY_WAKES.store(0, Ordering::SeqCst);
        DESTROYED_WAKES.store(0, Ordering::SeqCst);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::object::{self, ObjectKind};

    /// 共享静态表的测试在本 crate 内串行执行。
    fn lock() -> std::sync::MutexGuard<'static, ()> {
        crate::object::test_lock()
    }

    /// 建立一个干净的起点：清空本模块表、对象层钩子与唤醒注入缝。
    fn prepare() {
        object::reset_destroy_hooks();
        reset();
    }

    fn new_input_object() -> ObjectId {
        object::create_with_payload(ObjectKind::Input, 0).expect("input object")
    }

    fn wire(kind: u8, code: u8, sequence: u32, timestamp_ms: u64) -> InputEventWire {
        InputEventWire {
            kind,
            code,
            sequence,
            reserved: 0,
            timestamp_ms,
        }
    }

    #[test]
    fn wire_layout_matches_the_frozen_abi() {
        assert_eq!(size_of::<InputEventWire>(), 24);
        assert_eq!(KIND_KEYBOARD, 1);
        assert_eq!(KIND_SERIAL, 2);
        assert_eq!(InputEventWire::EMPTY, wire(0, 0, 0, 0));
    }

    #[test]
    fn create_binds_one_seat_and_rejects_a_second() {
        let _guard = lock();
        prepare();
        let first = new_input_object();
        let second = new_input_object();
        assert_eq!(create(first), Ok(()));
        // 同一对象重复登记幂等。
        assert_eq!(create(first), Ok(()));
        assert_eq!(live_objects(), 1);
        // 第二个存活 seat 被拒绝，且不影响第一个。
        assert_eq!(create(second), Err(InputError::TableFull));
        assert_eq!(live_objects(), 1);
        assert!(!poll(first));
        assert!(!poll(second));

        let _ = object::release_object(first);
        let _ = object::release_object(second);
        prepare();
    }

    #[test]
    fn create_rejects_dead_and_foreign_objects() {
        let _guard = lock();
        prepare();
        assert_eq!(create(ObjectId::MAX), Err(InputError::NoSuchObject));
        let console = object::create_with_payload(ObjectKind::Console, 0).expect("console");
        assert_eq!(create(console), Err(InputError::WrongKind));
        assert_eq!(live_objects(), 0);
        assert_eq!(published_count(), 0);
        let _ = object::release_object(console);
        prepare();
    }

    #[test]
    fn publish_records_sequence_and_timestamp() {
        let _guard = lock();
        prepare();
        let seat = new_input_object();
        // 没有 seat 之前发布是零副作用。
        publish_keyboard(0x1E);
        assert_eq!(published_count(), 0);
        assert_eq!(wake_seam::ready_wakes(), 0);

        assert_eq!(create(seat), Ok(()));
        let before = time::monotonic_millis();
        publish_keyboard(0x1E);
        let mut out = [InputEventWire::EMPTY; 4];
        assert_eq!(read(seat, &mut out), 1);
        assert_eq!(out[0].kind, KIND_KEYBOARD);
        assert_eq!(out[0].code, 0x1E);
        assert_eq!(out[0].sequence, 1);
        assert_eq!(out[0].reserved, 0);
        assert!(out[0].timestamp_ms >= before);

        publish_serial(b'C');
        assert_eq!(read(seat, &mut out), 1);
        assert_eq!(out[0].kind, KIND_SERIAL);
        assert_eq!(out[0].code, b'C');
        assert_eq!(out[0].sequence, 2);
        assert_eq!(published_count(), 2);
        assert_eq!(dropped_count(), 0);
        // 每次发布都唤醒 Ready。
        assert_eq!(wake_seam::ready_wakes(), 2);
        assert_eq!(wake_seam::last(), Some((seat, WAKE_READY)));

        let _ = object::release_object(seat);
        prepare();
    }

    #[test]
    fn publish_without_a_seat_has_zero_side_effects() {
        let _guard = lock();
        prepare();
        publish_keyboard(0x1E);
        publish_serial(b'C');
        assert_eq!(published_count(), 0);
        assert_eq!(dropped_count(), 0);
        assert_eq!(wake_seam::ready_wakes(), 0);
        assert_eq!(live_objects(), 0);
        prepare();
    }

    #[test]
    fn ring_is_fifo_and_read_returns_available_events() {
        let _guard = lock();
        prepare();
        let seat = new_input_object();
        assert_eq!(create(seat), Ok(()));
        for code in 1..=5u8 {
            publish_keyboard(code);
        }
        assert!(poll(seat));
        let mut out = [InputEventWire::EMPTY; 3];
        assert_eq!(read(seat, &mut out), 3);
        assert_eq!(out.map(|event| event.code), [1, 2, 3]);
        assert!(poll(seat));
        let mut rest = [InputEventWire::EMPTY; 8];
        assert_eq!(read(seat, &mut rest), 2);
        assert_eq!(rest[0].code, 4);
        assert_eq!(rest[1].code, 5);
        assert!(!poll(seat));
        assert_eq!(read(seat, &mut rest), 0);
        assert_eq!(published_count(), 5);

        let _ = object::release_object(seat);
        prepare();
    }

    #[test]
    fn full_ring_drops_the_oldest_event_and_counts_it() {
        let _guard = lock();
        prepare();
        let seat = new_input_object();
        assert_eq!(create(seat), Ok(()));
        for code in 0..(RING_CAPACITY as u8 + 3) {
            publish_serial(code);
        }
        assert_eq!(published_count(), (RING_CAPACITY + 3) as u64);
        assert_eq!(dropped_count(), 3);
        let mut out = [InputEventWire::EMPTY; RING_CAPACITY];
        assert_eq!(read(seat, &mut out), RING_CAPACITY);
        // 丢的是最旧的 0,1,2；剩下 3..=66。
        assert_eq!(out[0].code, 3);
        assert_eq!(out[RING_CAPACITY - 1].code, RING_CAPACITY as u8 + 2);
        // 序号连续、不受丢弃影响。
        assert_eq!(out[0].sequence, 4);
        assert_eq!(out[RING_CAPACITY - 1].sequence, (RING_CAPACITY + 3) as u32);

        let _ = object::release_object(seat);
        prepare();
    }

    #[test]
    fn destroy_wakes_destroyed_and_stops_routing() {
        let _guard = lock();
        prepare();
        let seat = new_input_object();
        assert_eq!(create(seat), Ok(()));
        publish_keyboard(0x1E);
        assert_eq!(wake_seam::last(), Some((seat, WAKE_READY)));

        assert!(destroy(seat));
        assert_eq!(wake_seam::last(), Some((seat, WAKE_DESTROYED)));
        assert_eq!(wake_seam::destroyed_wakes(), 1);
        assert_eq!(live_objects(), 0);
        // 幂等：再销毁一次不唤醒。
        assert!(!destroy(seat));
        assert_eq!(wake_seam::destroyed_wakes(), 1);

        // destroy 之后不再路由：ring 不再接收，read 返回 0。
        publish_keyboard(0x1F);
        assert_eq!(published_count(), 1);
        let mut out = [InputEventWire::EMPTY; 4];
        assert_eq!(read(seat, &mut out), 0);
        assert!(!poll(seat));

        let _ = object::release_object(seat);
        prepare();
    }

    #[test]
    fn a_fresh_seat_starts_with_an_empty_ring() {
        let _guard = lock();
        prepare();
        let first = new_input_object();
        assert_eq!(create(first), Ok(()));
        publish_keyboard(0x1E);
        assert!(destroy(first));
        let second = new_input_object();
        assert_eq!(create(second), Ok(()));
        assert!(!poll(second));
        let mut out = [InputEventWire::EMPTY; 4];
        assert_eq!(read(second, &mut out), 0);
        // 计数器跨 seat 累计（诊断语义），序号继续递增。
        assert_eq!(published_count(), 1);
        publish_serial(b'X');
        assert_eq!(read(second, &mut out), 1);
        assert_eq!(out[0].sequence, 2);
        let _ = object::release_object(first);
        let _ = object::release_object(second);
        prepare();
    }
}
