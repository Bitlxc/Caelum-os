//! Event 与 EventPair 内核对象（M6a1）。
//!
//! 语义（对齐第 11.1 节的事件原语，但不承诺 Linux `eventfd` 细节）：
//!
//! - **Event**：单一信号位，创建时决定 manual-reset 还是 auto-reset。
//!   - `signal` 置位；`reset` 清位。
//!   - `consume`：auto-reset 在观察到置位时清位；manual-reset 只报告观察到
//!     置位，必须显式 `reset` 才清除。
//! - **EventPair**：一个对象带两个独立信号位（端点 0/1），采用**对端语义**：
//!   `signal_pair`/`reset_pair` 的参数 `X` 表示“操作自己这一端 X”，实际产生/清除
//!   的是对端 `X ^ 1` 的 ready 位；而 `ready_pair`/`consume_pair` 仍然操作调用方
//!   自己等待的端点 key。因此 init 在端点 A 上 signal、child 在端点 B 上 wait，
//!   才是正确的跨进程通知用法；`consume` 读取并清除该端点。允许同一对象被 `dup`
//!   到多处（对象层引用计数），不存在端点子对象。
//!
//! 两种对象都由对象层持有：payload = 本文件表槽 `+ 1`。对象失效时对象层调用
//! 销毁钩子，本模块先 `wake_object(object, WakeReason::Destroyed)` 再释放槽。

use crate::object::ObjectId;

use super::{IpcError, IrqCell, payload_for_slot, slot_from_payload};

/// Event 固定容量。
pub const MAX_EVENTS: usize = 32;

/// EventPair 固定容量。
pub const MAX_EVENT_PAIRS: usize = 16;

/// EventPair 的合法端点。
pub const ENDPOINTS: u8 = 2;

/// 未绑定对象时的占位编号（直接调用 `create*` 的测试路径）。
const UNBOUND: ObjectId = ObjectId::MAX;

#[derive(Clone, Copy)]
struct EventSlot {
    live: bool,
    manual: bool,
    signaled: bool,
    /// 对象层在创建时绑定的对象编号；仅用于就绪变化后唤醒订阅，不参与生命周期。
    object: ObjectId,
}

const EMPTY_EVENT: EventSlot = EventSlot {
    live: false,
    manual: false,
    signaled: false,
    object: UNBOUND,
};

#[derive(Clone, Copy)]
struct PairSlot {
    live: bool,
    bits: u8,
    /// 同 [`EventSlot::object`]：EventPair 只有一个对象，端点靠 key 区分。
    object: ObjectId,
}

const EMPTY_PAIR: PairSlot = PairSlot {
    live: false,
    bits: 0,
    object: UNBOUND,
};

struct EventTable {
    slots: [EventSlot; MAX_EVENTS],
}

impl EventTable {
    const fn new() -> Self {
        EventTable {
            slots: [EMPTY_EVENT; MAX_EVENTS],
        }
    }

    fn count(&self) -> usize {
        self.slots.iter().filter(|slot| slot.live).count()
    }
}

struct PairTable {
    slots: [PairSlot; MAX_EVENT_PAIRS],
}

impl PairTable {
    const fn new() -> Self {
        PairTable {
            slots: [EMPTY_PAIR; MAX_EVENT_PAIRS],
        }
    }

    fn count(&self) -> usize {
        self.slots.iter().filter(|slot| slot.live).count()
    }
}

static EVENTS: IrqCell<EventTable> = IrqCell::new(EventTable::new());
static PAIRS: IrqCell<PairTable> = IrqCell::new(PairTable::new());

/// 槽编号 + 1 的负载（与对象 payload 一致）。
fn event_payload(slots: &EventTable, slot: usize) -> u64 {
    debug_assert!(slots.slots[slot].live);
    payload_for_slot(slot)
}

fn event_slot(payload: u64) -> Result<usize, IpcError> {
    slot_from_payload(payload, MAX_EVENTS)
}

fn pair_slot(payload: u64) -> Result<usize, IpcError> {
    slot_from_payload(payload, MAX_EVENT_PAIRS)
}

fn endpoint(endpoint: u8) -> Result<u8, IpcError> {
    if endpoint >= ENDPOINTS {
        return Err(IpcError::InvalidEndpoint);
    }
    Ok(endpoint)
}

fn endpoint_bit(raw: u8) -> Result<u8, IpcError> {
    let endpoint = endpoint(raw)?;
    Ok(1u8 << endpoint)
}

/// `signal_pair`/`reset_pair` 实际作用在对端：本端 `X` ⇒ 对端 `X ^ 1`。
fn peer_bit(raw: u8) -> Result<u8, IpcError> {
    let endpoint = endpoint(raw)?;
    Ok(1u8 << (endpoint ^ 1))
}

/// 本对象就绪状态变化后唤醒关心它的订阅。
///
/// **必须在释放本模块表锁之后调用**：`on_target_ready` 会经
/// [`super::poll_waitable_keyed`] 读取目标就绪状态（对 Event/EventPair 而言会再次
/// 进入本模块的表锁）。该遍历有固定上限、不分配、不打印，因此也能从 Timer 的
/// ISR 路径调用；未绑定对象（直接走 `create*` 的测试路径）直接跳过。
fn notify_ready(object: ObjectId) {
    if object == UNBOUND {
        return;
    }
    super::notify_target_ready(object);
}

/// 本对象就绪状态**变为 false** 之后通知订阅：只清已失效的边沿缓存（observed），
/// 不唤醒、不消费事件。
///
/// 与 [`notify_ready`] 一样**必须在释放本模块表锁之后调用**；未绑定对象直接跳过。
/// 每一次 reset/consume 都调用它，订阅侧才能“read 之后无人 poll 也能重新武装”，
/// 不会把后续 signal 的边沿漏掉。
fn notify_not_ready(object: ObjectId) {
    if object == UNBOUND {
        return;
    }
    super::notify_target_not_ready(object);
}

/// 把 Event 表槽绑定到它的对象编号（由 `ipc::insert_event` 在对象创建后调用）。
///
/// 绑定只服务于订阅唤醒，不改变 Event 自身的语义；对象生命周期仍由对象表与销毁
/// 钩子负责。
pub fn bind(payload: u64, object: ObjectId) -> Result<(), IpcError> {
    let slot = event_slot(payload)?;
    EVENTS.with(|table| match table.slots.get_mut(slot) {
        Some(entry) if entry.live => {
            entry.object = object;
            Ok(())
        }
        _ => Err(IpcError::InvalidPayload),
    })
}

/// 创建一个 Event，返回它的对象负载；`manual_reset` 决定清除语义。
pub fn create(manual_reset: bool) -> Result<u64, IpcError> {
    EVENTS.with(|table| {
        let slot = table
            .slots
            .iter()
            .position(|slot| !slot.live)
            .ok_or(IpcError::TableFull)?;
        table.slots[slot] = EventSlot {
            live: true,
            manual: manual_reset,
            signaled: false,
            object: UNBOUND,
        };
        Ok(event_payload(table, slot))
    })
}

/// 该 Event 是否为 manual-reset。
pub fn is_manual(payload: u64) -> Result<bool, IpcError> {
    let slot = event_slot(payload)?;
    EVENTS.with(|table| {
        let entry = table.slots.get(slot).filter(|slot| slot.live);
        entry
            .map(|slot| slot.manual)
            .ok_or(IpcError::InvalidPayload)
    })
}

/// 置位（可重复调用，保持置位）。
///
/// 置位后若已绑定对象，则在释放表锁之后唤醒关心该对象的订阅。
pub fn signal(payload: u64) -> Result<(), IpcError> {
    let slot = event_slot(payload)?;
    let object = EVENTS.with(|table| match table.slots.get_mut(slot) {
        Some(entry) if entry.live => {
            entry.signaled = true;
            Ok(entry.object)
        }
        _ => Err(IpcError::InvalidPayload),
    })?;
    notify_ready(object);
    Ok(())
}

/// 清位（manual-reset 的主要清除路径；auto-reset 也允许显式清）。
pub fn reset(payload: u64) -> Result<(), IpcError> {
    let slot = event_slot(payload)?;
    let object = EVENTS.with(|table| match table.slots.get_mut(slot) {
        Some(entry) if entry.live => {
            entry.signaled = false;
            Ok(entry.object)
        }
        _ => Err(IpcError::InvalidPayload),
    })?;
    notify_not_ready(object);
    Ok(())
}

/// 只查询是否置位，不改变状态。
pub fn ready(payload: u64) -> Result<bool, IpcError> {
    let slot = event_slot(payload)?;
    EVENTS.with(|table| match table.slots.get(slot) {
        Some(entry) if entry.live => Ok(entry.signaled),
        _ => Err(IpcError::InvalidPayload),
    })
}

/// 消费一次：返回是否观察到置位。
///
/// auto-reset 在返回 `true` 时清位；manual-reset 保持置位直到显式 `reset`。
/// auto-reset 清位后就绪变为 false，因此在释放表锁之后通知订阅重新武装边沿。
pub fn consume(payload: u64) -> Result<bool, IpcError> {
    let slot = event_slot(payload)?;
    let (observed, cleared, object) = EVENTS.with(|table| match table.slots.get_mut(slot) {
        Some(entry) if entry.live => {
            let observed = entry.signaled;
            let cleared = observed && !entry.manual;
            if cleared {
                entry.signaled = false;
            }
            Ok((observed, cleared, entry.object))
        }
        _ => Err(IpcError::InvalidPayload),
    })?;
    if cleared {
        notify_not_ready(object);
    }
    Ok(observed)
}

/// 已创建的 Event 数量（诊断/测试）。
pub fn count() -> usize {
    EVENTS.with(|table| table.count())
}

/// 创建一个 EventPair，返回它的对象负载。
pub fn create_pair() -> Result<u64, IpcError> {
    PAIRS.with(|table| {
        let slot = table
            .slots
            .iter()
            .position(|slot| !slot.live)
            .ok_or(IpcError::TableFull)?;
        table.slots[slot] = PairSlot {
            live: true,
            bits: 0,
            object: UNBOUND,
        };
        Ok(payload_for_slot(slot))
    })
}

/// 把 EventPair 表槽绑定到它的对象编号（由 `ipc::insert_event_pair` 调用）。
///
/// 一个 EventPair 只有一个对象，两个端点靠等待 key 区分；订阅唤醒只看对象编号。
pub fn bind_pair(payload: u64, object: ObjectId) -> Result<(), IpcError> {
    let slot = pair_slot(payload)?;
    PAIRS.with(|table| match table.slots.get_mut(slot) {
        Some(entry) if entry.live => {
            entry.object = object;
            Ok(())
        }
        _ => Err(IpcError::InvalidPayload),
    })
}

/// 置位**对端**：参数 `endpoint` 是发送方自己的一端 `X`，置位的是 `X ^ 1`。
/// 这样 init 在 A 上 signal，child 在 B 上 wait 才能看到 ready。
pub fn signal_pair(payload: u64, endpoint: u8) -> Result<(), IpcError> {
    let bit = peer_bit(endpoint)?;
    let slot = pair_slot(payload)?;
    let object = PAIRS.with(|table| match table.slots.get_mut(slot) {
        Some(entry) if entry.live => {
            entry.bits |= bit;
            Ok(entry.object)
        }
        _ => Err(IpcError::InvalidPayload),
    })?;
    notify_ready(object);
    Ok(())
}

/// 清除**对端**：参数 `endpoint` 是发送方自己的一端 `X`，清除的是 `X ^ 1`。
pub fn reset_pair(payload: u64, endpoint: u8) -> Result<(), IpcError> {
    let bit = peer_bit(endpoint)?;
    let slot = pair_slot(payload)?;
    let object = PAIRS.with(|table| match table.slots.get_mut(slot) {
        Some(entry) if entry.live => {
            entry.bits &= !bit;
            Ok(entry.object)
        }
        _ => Err(IpcError::InvalidPayload),
    })?;
    // 被清的那一端就绪变为 false：清该端（未就绪）订阅的边沿缓存，不清仍就绪的另一端。
    notify_not_ready(object);
    Ok(())
}

/// 只查询**本端**（等待方自己的 key）是否置位，不改变状态。
pub fn ready_pair(payload: u64, endpoint: u8) -> Result<bool, IpcError> {
    let bit = endpoint_bit(endpoint)?;
    let slot = pair_slot(payload)?;
    PAIRS.with(|table| match table.slots.get(slot) {
        Some(entry) if entry.live => Ok(entry.bits & bit != 0),
        _ => Err(IpcError::InvalidPayload),
    })
}

/// 消费**本端**（等待方自己的 key）：返回是否观察到置位，并在观察到时清除它。
///
/// 清除后该 key 就绪变为 false，因此在释放表锁之后通知订阅重新武装该端边沿。
pub fn consume_pair(payload: u64, endpoint: u8) -> Result<bool, IpcError> {
    let bit = endpoint_bit(endpoint)?;
    let slot = pair_slot(payload)?;
    let (observed, object) = PAIRS.with(|table| match table.slots.get_mut(slot) {
        Some(entry) if entry.live => {
            let observed = entry.bits & bit != 0;
            if observed {
                entry.bits &= !bit;
            }
            Ok((observed, entry.object))
        }
        _ => Err(IpcError::InvalidPayload),
    })?;
    if observed {
        notify_not_ready(object);
    }
    Ok(observed)
}

/// 已创建的 EventPair 数量（诊断/测试）。
pub fn pair_count() -> usize {
    PAIRS.with(|table| table.count())
}

/// 销毁 Event：先唤醒等待者，再释放槽。可由对象层销毁钩子调用。
pub fn destroy(payload: u64, object: ObjectId) -> Result<(), IpcError> {
    let slot = event_slot(payload)?;
    let live = EVENTS.with(|table| match table.slots.get(slot) {
        Some(entry) if entry.live => true,
        _ => false,
    });
    if !live {
        return Err(IpcError::InvalidPayload);
    }
    // 对象已经失效，等待者必须得到明确的 Destroyed 而不是永远挂起。
    let _ = crate::process::wake_object(object, crate::process::WakeReason::Destroyed);
    EVENTS.with(|table| {
        table.slots[slot] = EMPTY_EVENT;
    });
    Ok(())
}

/// 销毁 EventPair：先唤醒等待者，再释放槽。
pub fn destroy_pair(payload: u64, object: ObjectId) -> Result<(), IpcError> {
    let slot = pair_slot(payload)?;
    let live = PAIRS.with(|table| match table.slots.get(slot) {
        Some(entry) if entry.live => true,
        _ => false,
    });
    if !live {
        return Err(IpcError::InvalidPayload);
    }
    let _ = crate::process::wake_object(object, crate::process::WakeReason::Destroyed);
    PAIRS.with(|table| {
        table.slots[slot] = EMPTY_PAIR;
    });
    Ok(())
}

/// 创建失败/未发布对象的清理：只释放槽，不唤醒（没有对象可唤醒）。
///
/// 槽已经释放时视为成功，方便调用方统一写清理路径。
pub(crate) fn discard(payload: u64) -> Result<(), IpcError> {
    let slot = event_slot(payload)?;
    EVENTS.with(|table| match table.slots.get_mut(slot) {
        Some(entry) if entry.live => {
            *entry = EMPTY_EVENT;
            Ok(())
        }
        _ => Ok(()),
    })
}

/// EventPair 的创建失败清理（无唤醒）。
pub(crate) fn discard_pair(payload: u64) -> Result<(), IpcError> {
    let slot = pair_slot(payload)?;
    PAIRS.with(|table| match table.slots.get_mut(slot) {
        Some(entry) if entry.live => {
            *entry = EMPTY_PAIR;
            Ok(())
        }
        _ => Ok(()),
    })
}

/// 清空所有 Event/EventPair 槽（仅测试）。
#[cfg(test)]
pub(crate) fn reset_for_test() {
    EVENTS.with(|table| table.slots = [EMPTY_EVENT; MAX_EVENTS]);
    PAIRS.with(|table| table.slots = [EMPTY_PAIR; MAX_EVENT_PAIRS]);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lock() -> std::sync::MutexGuard<'static, ()> {
        crate::object::test_lock()
    }

    #[test]
    fn auto_reset_event_consumes_once() {
        let _guard = lock();
        reset_for_test();

        let payload = create(false).unwrap();
        assert_eq!(ready(payload), Ok(false));
        assert_eq!(consume(payload), Ok(false));

        signal(payload).unwrap();
        assert_eq!(ready(payload), Ok(true));
        // 只查询不消费。
        assert_eq!(ready(payload), Ok(true));
        assert_eq!(consume(payload), Ok(true));
        assert_eq!(ready(payload), Ok(false));
        assert_eq!(consume(payload), Ok(false));

        discard(payload).unwrap();
        assert_eq!(count(), 0);
    }

    #[test]
    fn manual_reset_event_stays_signaled_until_reset() {
        let _guard = lock();
        reset_for_test();

        let payload = create(true).unwrap();
        assert_eq!(is_manual(payload), Ok(true));
        signal(payload).unwrap();
        assert_eq!(consume(payload), Ok(true));
        assert_eq!(ready(payload), Ok(true));
        reset(payload).unwrap();
        assert_eq!(ready(payload), Ok(false));
        // 重复 reset 无害。
        reset(payload).unwrap();

        discard(payload).unwrap();
        // 释放后所有入口都报非法负载。
        assert_eq!(ready(payload), Err(IpcError::InvalidPayload));
        assert_eq!(signal(payload), Err(IpcError::InvalidPayload));
    }

    #[test]
    fn event_table_quota_is_fixed() {
        let _guard = lock();
        reset_for_test();

        let mut payloads = [0u64; MAX_EVENTS];
        for payload in &mut payloads {
            *payload = create(false).unwrap();
        }
        assert_eq!(count(), MAX_EVENTS);
        assert_eq!(create(false), Err(IpcError::TableFull));

        discard(payloads[3]).unwrap();
        let reused = create(true).unwrap();
        // 释放出的槽会被复用，负载编码仍满足 slot + 1。
        assert!(reused >= 1 && reused <= MAX_EVENTS as u64);
        assert_eq!(count(), MAX_EVENTS);

        for payload in payloads {
            let _ = discard(payload);
        }
        let _ = discard(reused);
        assert_eq!(count(), 0);
    }

    /// 对端语义的既有回归：端点互相独立，但 signal/reset 作用于对端。
    #[test]
    fn event_pair_endpoints_are_independent() {
        let _guard = lock();
        reset_for_test();

        let payload = create_pair().unwrap();
        assert_eq!(ready_pair(payload, 0), Ok(false));
        assert_eq!(ready_pair(payload, 1), Ok(false));

        // signal 端点 0 ⇒ 置位对端 1。
        signal_pair(payload, 0).unwrap();
        assert_eq!(ready_pair(payload, 0), Ok(false));
        assert_eq!(ready_pair(payload, 1), Ok(true));

        // signal 端点 1 ⇒ 置位对端 0。
        signal_pair(payload, 1).unwrap();
        assert_eq!(ready_pair(payload, 0), Ok(true));
        assert_eq!(ready_pair(payload, 1), Ok(true));

        // 消费本端 0 只清 bit0，端点 1 保持 ready。
        assert_eq!(consume_pair(payload, 0), Ok(true));
        assert_eq!(consume_pair(payload, 0), Ok(false));
        assert_eq!(ready_pair(payload, 1), Ok(true));
        assert_eq!(consume_pair(payload, 1), Ok(true));
        assert_eq!(ready_pair(payload, 1), Ok(false));

        // reset 端点 0 ⇒ 清对端 1；重新置位后验证只清对端。
        signal_pair(payload, 0).unwrap();
        reset_pair(payload, 0).unwrap();
        assert_eq!(ready_pair(payload, 1), Ok(false));

        assert_eq!(ready_pair(payload, 2), Err(IpcError::InvalidEndpoint));
        assert_eq!(signal_pair(payload, 255), Err(IpcError::InvalidEndpoint));

        discard_pair(payload).unwrap();
        assert_eq!(pair_count(), 0);
    }

    /// init 在 A 上 signal，child 在 B 上 wait：B ready，A 不被误置。
    #[test]
    fn signal_from_a_marks_only_b_ready() {
        let _guard = lock();
        reset_for_test();

        const A: u8 = 0;
        const B: u8 = 1;
        let payload = create_pair().unwrap();

        signal_pair(payload, A).unwrap();
        assert_eq!(ready_pair(payload, B), Ok(true));
        assert_eq!(ready_pair(payload, A), Ok(false));
        // 同端消费看不到信号（信号在对端）；对端消费一次即清。
        assert_eq!(consume_pair(payload, A), Ok(false));
        assert_eq!(consume_pair(payload, B), Ok(true));
        assert_eq!(ready_pair(payload, B), Ok(false));

        discard_pair(payload).unwrap();
    }

    /// child 在 B 上 signal，init 在 A 上 wait：A ready，B 不被误置。
    #[test]
    fn signal_from_b_marks_only_a_ready() {
        let _guard = lock();
        reset_for_test();

        const A: u8 = 0;
        const B: u8 = 1;
        let payload = create_pair().unwrap();

        signal_pair(payload, B).unwrap();
        assert_eq!(ready_pair(payload, A), Ok(true));
        assert_eq!(ready_pair(payload, B), Ok(false));
        assert_eq!(consume_pair(payload, B), Ok(false));
        assert_eq!(consume_pair(payload, A), Ok(true));

        discard_pair(payload).unwrap();
    }

    /// reset 只清对端：本端 ready、对端置位时 reset 不会误清本端。
    #[test]
    fn reset_from_one_end_clears_only_the_peer() {
        let _guard = lock();
        reset_for_test();

        const A: u8 = 0;
        const B: u8 = 1;
        let payload = create_pair().unwrap();

        // A signal ⇒ B ready；B signal ⇒ A ready。两端都置位。
        signal_pair(payload, A).unwrap();
        signal_pair(payload, B).unwrap();
        assert_eq!(ready_pair(payload, A), Ok(true));
        assert_eq!(ready_pair(payload, B), Ok(true));

        // 从 A 端 reset ⇒ 只清对端 B，本端 A 仍 ready。
        reset_pair(payload, A).unwrap();
        assert_eq!(ready_pair(payload, B), Ok(false));
        assert_eq!(ready_pair(payload, A), Ok(true));
        // 再次 reset 幂等。
        reset_pair(payload, A).unwrap();
        assert_eq!(ready_pair(payload, A), Ok(true));

        reset_pair(payload, B).unwrap();
        assert_eq!(ready_pair(payload, A), Ok(false));
        assert_eq!(pair_count(), 1);
        discard_pair(payload).unwrap();
        assert_eq!(pair_count(), 0);
    }

    #[test]
    fn event_pair_quota_is_fixed() {
        let _guard = lock();
        reset_for_test();

        let mut payloads = [0u64; MAX_EVENT_PAIRS];
        for payload in &mut payloads {
            *payload = create_pair().unwrap();
        }
        assert_eq!(create_pair(), Err(IpcError::TableFull));
        for payload in payloads {
            discard_pair(payload).unwrap();
        }
        assert_eq!(pair_count(), 0);
        // 表满后释放，仍可继续创建。
        assert!(create_pair().is_ok());
        reset_for_test();
    }

    #[test]
    fn event_destroy_releases_the_slot() {
        let _guard = lock();
        reset_for_test();

        let payload = create(false).unwrap();
        // 用不存在的对象 ID 调用 destroy：唤醒是空操作，槽必须释放。
        destroy(payload, 0xFFFF).unwrap();
        assert_eq!(count(), 0);
        assert_eq!(destroy(payload, 0xFFFF), Err(IpcError::InvalidPayload));
    }

    /// M7：Event 的 signal/reset 在表锁之外唤醒注册过的订阅。
    #[test]
    fn signal_and_reset_wake_a_registered_subscription() {
        use crate::ipc::{poll_waitable_keyed, subscription};
        use crate::object::{self, ObjectKind};

        let _guard = lock();
        reset_for_test();
        crate::ipc::install_destroy_hooks().expect("destroy hooks install");
        subscription::reset();

        let payload = create(true).unwrap();
        let target = object::create_with_payload(ObjectKind::Event, payload).expect("event object");
        bind(payload, target).expect("bind event object");

        let watched =
            object::create_with_payload(ObjectKind::EventSubscription, 0).expect("subscription");
        subscription::create(watched).expect("create subscription");
        subscription::register(watched, target, subscription::MODE_LEVEL, 0).expect("register");

        // 未置位 ⇒ 统一 WAIT 路径不就绪。
        assert_eq!(poll_waitable_keyed(watched, 0, false), Ok(false));

        signal(payload).expect("signal");
        assert_eq!(subscription::ready(watched), Ok(true));
        assert_eq!(poll_waitable_keyed(watched, 0, false), Ok(true));

        reset(payload).expect("reset");
        assert_eq!(subscription::ready(watched), Ok(false));

        // 清理：销毁订阅会延迟释放目标引用，再释放两个对象（钩子清表）。
        subscription::destroy(watched).expect("destroy subscription");
        let _ = crate::ipc::release_subscription_pending();
        let _ = object::release_object(watched);
        let _ = object::release_object(target);
        assert_eq!(count(), 0);
    }

    /// ET 闭环：`read` 消费边沿后，源侧 `consume`/`reset` 必须重新武装 `observed`，
    /// 否则“源自己抽干、订阅侧没有 poll”的窗口会漏掉下一次 signal 的边沿。
    #[test]
    fn consume_and_reset_rearm_the_edge_before_the_next_signal() {
        use crate::ipc::{poll_waitable_keyed, subscription};
        use crate::object::{self, ObjectKind};

        let _guard = lock();
        reset_for_test();
        crate::ipc::install_destroy_hooks().expect("destroy hooks install");
        subscription::reset();

        let payload = create(false).unwrap();
        let target = object::create_with_payload(ObjectKind::Event, payload).expect("event object");
        bind(payload, target).expect("bind event object");
        let watched =
            object::create_with_payload(ObjectKind::EventSubscription, 0).expect("subscription");
        subscription::create(watched).expect("create subscription");
        subscription::register(watched, target, subscription::MODE_EDGE, 0).expect("register");
        let mut events = [subscription::SubscriptionEvent {
            object_key: 0,
            mode: 0,
        }; subscription::MAX_EVENTS];

        signal(payload).expect("first signal");
        assert_eq!(subscription::read(watched, &mut events).unwrap(), 1);
        // 仍置位但边沿已消费：重复 read 不重复上报。
        assert_eq!(subscription::read(watched, &mut events).unwrap(), 0);

        // 源侧取走 auto-reset 事件（目标变为未就绪）；订阅侧没有 poll。
        assert_eq!(consume(payload), Ok(true));
        signal(payload).expect("second signal");
        // 源侧通知已重新武装：新的边沿必须可 WAIT、可 read。
        assert_eq!(poll_waitable_keyed(watched, 0, false), Ok(true));
        assert_eq!(subscription::read(watched, &mut events).unwrap(), 1);

        // 显式 reset 路径同样重新武装。
        assert_eq!(reset(payload), Ok(()));
        signal(payload).expect("third signal");
        assert_eq!(subscription::read(watched, &mut events).unwrap(), 1);

        subscription::destroy(watched).expect("destroy subscription");
        let _ = crate::ipc::release_subscription_pending();
        let _ = object::release_object(watched);
        let _ = object::release_object(target);
        assert_eq!(count(), 0);
    }

    /// ET 闭环（EventPair）：对应 endpoint 被 consume/reset 后也重新武装。
    #[test]
    fn pair_consume_rearms_the_edge_before_the_next_signal() {
        use crate::ipc::{poll_waitable_keyed, subscription};
        use crate::object::{self, ObjectKind};

        let _guard = lock();
        reset_for_test();
        crate::ipc::install_destroy_hooks().expect("destroy hooks install");
        subscription::reset();

        let payload = create_pair().unwrap();
        let target =
            object::create_with_payload(ObjectKind::EventPair, payload).expect("pair object");
        bind_pair(payload, target).expect("bind pair object");
        let watched =
            object::create_with_payload(ObjectKind::EventSubscription, 0).expect("subscription");
        subscription::create(watched).expect("create subscription");
        subscription::register(watched, target, subscription::MODE_EDGE, 1).expect("register");
        let mut events = [subscription::SubscriptionEvent {
            object_key: 0,
            mode: 0,
        }; subscription::MAX_EVENTS];

        signal_pair(payload, 0).expect("first signal from a");
        assert_eq!(subscription::read(watched, &mut events).unwrap(), 1);
        assert_eq!(consume_pair(payload, 1), Ok(true));
        signal_pair(payload, 0).expect("second signal from a");
        assert_eq!(poll_waitable_keyed(watched, 0, false), Ok(true));
        assert_eq!(subscription::read(watched, &mut events).unwrap(), 1);

        subscription::destroy(watched).expect("destroy subscription");
        let _ = crate::ipc::release_subscription_pending();
        let _ = object::release_object(watched);
        let _ = object::release_object(target);
        assert_eq!(pair_count(), 0);
    }

    /// M7：EventPair 按**对端** key 唤醒订阅（A 端 signal ⇒ key=B 的订阅读到就绪）。
    #[test]
    fn pair_signal_wakes_subscription_on_the_peer_key_only() {
        use crate::ipc::{poll_waitable_keyed, subscription};
        use crate::object::{self, ObjectKind};

        let _guard = lock();
        reset_for_test();
        crate::ipc::install_destroy_hooks().expect("destroy hooks install");
        subscription::reset();

        let payload = create_pair().unwrap();
        let target =
            object::create_with_payload(ObjectKind::EventPair, payload).expect("pair object");
        bind_pair(payload, target).expect("bind pair object");

        let watched =
            object::create_with_payload(ObjectKind::EventSubscription, 0).expect("subscription");
        subscription::create(watched).expect("create subscription");
        // 等待端点是 1：A（0）端 signal 后只应唤醒 key=1。
        subscription::register(watched, target, subscription::MODE_LEVEL, 1).expect("register");
        assert_eq!(poll_waitable_keyed(watched, 0, false), Ok(false));

        signal_pair(payload, 0).expect("signal from a");
        assert_eq!(subscription::ready(watched), Ok(true));
        assert_eq!(poll_waitable_keyed(watched, 0, false), Ok(true));

        // B 端自己 signal 会置 A（0）为就绪，不应再让 key=1 的订阅读到新状态。
        consume_pair(payload, 1).expect("consume b");
        reset_pair(payload, 0).expect("reset from a");
        assert_eq!(subscription::ready(watched), Ok(false));

        subscription::destroy(watched).expect("destroy subscription");
        let _ = crate::ipc::release_subscription_pending();
        let _ = object::release_object(watched);
        let _ = object::release_object(target);
        assert_eq!(pair_count(), 0);
    }
}
