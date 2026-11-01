//! 单调时钟 Timer 内核对象（M6a1）。
//!
//! Timer 是等待机制的一部分，不是独立的时钟子系统：它只保存“绑定对象 + 截止
//! 时间（单调 tick）”，由时钟中断路径的 [`on_tick`] 扫描到期项并唤醒绑定对象。
//!
//! 生命周期：
//!
//! 1. [`create`] 占用一个表槽并返回对象负载（slot + 1）；
//! 2. 对象层用该负载创建 `ObjectKind::Timer`；
//! 3. [`bind`] 把负载与对象 ID 关联（重复绑定视为调用方错误）；
//! 4. [`arm`] 设置截止时间；到期后 [`on_tick`] 置就绪、解除 armed，并通过
//!    `process::wake_object(object, WakeReason::Timeout)` 唤醒一次；
//! 5. 等待方 [`consume`] 读取并清除就绪位；对象释放时 [`destroy`] 先唤醒
//!    `WakeReason::Destroyed` 再释放槽。
//!
//! 中断约束：[`on_tick`] 允许在硬中断顶半调用，不分配、不打印、不访问对象表，
//! 只更新本表并调用 `process::wake_object`（该函数同样要求 ISR 安全）。
//! 到期是 one-shot：触发后 `armed` 清零，重新 [`arm`] 会覆盖截止时间并清除就绪位。

use crate::object::ObjectId;

use super::{IpcError, IrqCell, payload_for_slot, slot_from_payload};

/// Timer 固定容量。
pub const MAX_TIMERS: usize = 16;

#[derive(Clone, Copy)]
struct TimerSlot {
    live: bool,
    armed: bool,
    signaled: bool,
    deadline: Option<u64>,
    object: Option<ObjectId>,
}

const EMPTY_TIMER: TimerSlot = TimerSlot {
    live: false,
    armed: false,
    signaled: false,
    deadline: None,
    object: None,
};

struct TimerTable {
    slots: [TimerSlot; MAX_TIMERS],
}

impl TimerTable {
    const fn new() -> Self {
        TimerTable {
            slots: [EMPTY_TIMER; MAX_TIMERS],
        }
    }

    fn count(&self) -> usize {
        self.slots.iter().filter(|slot| slot.live).count()
    }
}

static TIMERS: IrqCell<TimerTable> = IrqCell::new(TimerTable::new());

fn timer_slot(payload: u64) -> Result<usize, IpcError> {
    slot_from_payload(payload, MAX_TIMERS)
}

/// 占用一个表槽并返回对象负载；此时 Timer 尚未绑定对象。
pub fn create() -> Result<u64, IpcError> {
    TIMERS.with(|table| {
        let slot = table
            .slots
            .iter()
            .position(|slot| !slot.live)
            .ok_or(IpcError::TableFull)?;
        table.slots[slot] = TimerSlot {
            live: true,
            ..EMPTY_TIMER
        };
        Ok(payload_for_slot(slot))
    })
}

/// 把表槽绑定到对象；`object` 必须是持有该 payload 的 `ObjectKind::Timer`。
///
/// 重复绑定（即使指向同一对象）返回 [`IpcError::AlreadyBound`]，避免静默改写
/// 唤醒目标。
pub fn bind(payload: u64, object: ObjectId) -> Result<(), IpcError> {
    let slot = timer_slot(payload)?;
    TIMERS.with(|table| match table.slots.get_mut(slot) {
        Some(entry) if entry.live => {
            if entry.object.is_some() {
                return Err(IpcError::AlreadyBound);
            }
            entry.object = Some(object);
            Ok(())
        }
        _ => Err(IpcError::InvalidPayload),
    })
}

/// 绑定的对象 ID（未绑定为 `None`）。
pub fn bound_object(payload: u64) -> Result<Option<ObjectId>, IpcError> {
    let slot = timer_slot(payload)?;
    TIMERS.with(|table| match table.slots.get(slot) {
        Some(entry) if entry.live => Ok(entry.object),
        _ => Err(IpcError::InvalidPayload),
    })
}

/// 当前截止时间；未 armed 为 `None`。
pub fn deadline(payload: u64) -> Result<Option<u64>, IpcError> {
    let slot = timer_slot(payload)?;
    TIMERS.with(|table| match table.slots.get(slot) {
        Some(entry) if entry.live => Ok(if entry.armed { entry.deadline } else { None }),
        _ => Err(IpcError::InvalidPayload),
    })
}

/// 设置/覆盖截止时间并解除就绪位。
///
/// `deadline = None` 表示“已 arm 但没有时间上限”（仅等待对象就绪，不会被
/// [`on_tick`] 触发）。未绑定对象的 Timer 不能 arm。
pub fn arm(payload: u64, deadline: Option<u64>) -> Result<(), IpcError> {
    let slot = timer_slot(payload)?;
    let object = TIMERS.with(|table| match table.slots.get_mut(slot) {
        Some(entry) if entry.live => {
            if entry.object.is_none() {
                return Err(IpcError::NotBound);
            }
            entry.armed = true;
            entry.signaled = false;
            entry.deadline = deadline;
            Ok(entry.object)
        }
        _ => Err(IpcError::InvalidPayload),
    })?;
    // 重新 arm 会清掉就绪位：就绪由 true 变 false，释放表锁后通知订阅重新武装边沿。
    if let Some(object) = object {
        let _ = super::subscription::on_target_not_ready(object);
    }
    Ok(())
}

/// 取消 arm；重复取消视为成功（幂等），仅释放等待语义。
pub fn disarm(payload: u64) -> Result<(), IpcError> {
    let slot = timer_slot(payload)?;
    TIMERS.with(|table| match table.slots.get_mut(slot) {
        Some(entry) if entry.live => {
            entry.armed = false;
            entry.deadline = None;
            Ok(())
        }
        _ => Err(IpcError::InvalidPayload),
    })
}

/// 只查询是否已到期（不消费）。
pub fn ready(payload: u64) -> Result<bool, IpcError> {
    let slot = timer_slot(payload)?;
    TIMERS.with(|table| match table.slots.get(slot) {
        Some(entry) if entry.live => Ok(entry.signaled),
        _ => Err(IpcError::InvalidPayload),
    })
}

/// 消费一次到期信号：返回是否观察到到期，并清除就绪位。
///
/// 观察到就绪时会清位，就绪由 true 变 false，因此在释放表锁之后通知订阅重新武装。
pub fn consume(payload: u64) -> Result<bool, IpcError> {
    let slot = timer_slot(payload)?;
    let (observed, object) = TIMERS.with(|table| match table.slots.get_mut(slot) {
        Some(entry) if entry.live => {
            let observed = entry.signaled;
            entry.signaled = false;
            Ok((observed, entry.object))
        }
        _ => Err(IpcError::InvalidPayload),
    })?;
    if observed {
        if let Some(object) = object {
            let _ = super::subscription::on_target_not_ready(object);
        }
    }
    Ok(observed)
}

/// 时钟中断路径：触发所有 `deadline <= now` 的 armed Timer。
///
/// 返回本次触发数量（不是被唤醒进程数）。每个 Timer 最多触发一次，触发后
/// `armed = false`、`signaled = true`，并调用 `wake_object(object, Timeout)`；
/// 释放本表锁后再唤醒关心该对象的订阅。
///
/// 可在硬中断顶半调用：不分配、不打印、不访问对象表；只写本表并调用
/// `process::wake_object` 与 `subscription::on_target_ready`（两者均为 ISR 安全）。
pub fn on_tick(now: u64) -> usize {
    let mut fired = 0usize;
    let mut ready: [ObjectId; MAX_TIMERS] = [ObjectId::MAX; MAX_TIMERS];
    let mut ready_count = 0usize;

    TIMERS.with(|table| {
        let mut slot = 0usize;
        while slot < MAX_TIMERS {
            let entry = &mut table.slots[slot];
            slot += 1;

            if !entry.live || !entry.armed {
                continue;
            }
            let Some(deadline) = entry.deadline else {
                continue;
            };
            if deadline > now {
                continue;
            }

            entry.armed = false;
            entry.signaled = true;
            fired += 1;

            if let Some(object) = entry.object {
                // 唤醒动作由本函数在表锁之外执行（不得在 IPC 表锁内取进程表锁）。
                if ready_count < MAX_TIMERS {
                    ready[ready_count] = object;
                    ready_count += 1;
                }
            }
        }
    });

    // 唤醒与订阅通知都必须在释放 Timer 表锁之后：`wake_object` 取进程表锁，
    // `on_target_ready` 会经 `poll_waitable_keyed` 重新读取本表（以及其它源表）。
    for object in ready.iter().take(ready_count) {
        let _ = crate::process::wake_object(*object, crate::process::WakeReason::Timeout);
    }
    for object in ready.iter().take(ready_count) {
        super::notify_target_ready(*object);
    }

    fired
}

/// 已创建的 Timer 数量（诊断/测试）。
pub fn count() -> usize {
    TIMERS.with(|table| table.count())
}

/// 销毁 Timer：若已绑定对象则先唤醒等待者，再释放槽。
pub fn destroy(payload: u64, object: ObjectId) -> Result<(), IpcError> {
    let slot = timer_slot(payload)?;
    let bound = TIMERS.with(|table| match table.slots.get(slot) {
        Some(entry) if entry.live => Some(entry.object),
        _ => None,
    });
    let Some(bound) = bound else {
        return Err(IpcError::InvalidPayload);
    };

    let target = bound.unwrap_or(object);
    let _ = crate::process::wake_object(target, crate::process::WakeReason::Destroyed);

    TIMERS.with(|table| {
        table.slots[slot] = EMPTY_TIMER;
    });
    Ok(())
}

/// 创建失败/未绑定对象的清理：只释放槽，不唤醒。
pub(crate) fn discard(payload: u64) -> Result<(), IpcError> {
    let slot = timer_slot(payload)?;
    TIMERS.with(|table| match table.slots.get_mut(slot) {
        Some(entry) if entry.live => {
            *entry = EMPTY_TIMER;
            Ok(())
        }
        _ => Ok(()),
    })
}

/// 清空所有 Timer 槽（仅测试）。
#[cfg(test)]
pub(crate) fn reset_for_test() {
    TIMERS.with(|table| table.slots = [EMPTY_TIMER; MAX_TIMERS]);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lock() -> std::sync::MutexGuard<'static, ()> {
        crate::object::test_lock()
    }

    /// 创建一个绑定好对象 ID 的 Timer（宿主测试不经过对象表）。
    fn bound_timer(object: ObjectId) -> u64 {
        let payload = create().unwrap();
        bind(payload, object).unwrap();
        payload
    }

    #[test]
    fn timer_requires_a_binding_before_arming() {
        let _guard = lock();
        reset_for_test();

        let payload = create().unwrap();
        assert_eq!(bound_object(payload), Ok(None));
        assert_eq!(arm(payload, None), Err(IpcError::NotBound));

        bind(payload, 7).unwrap();
        assert_eq!(bound_object(payload), Ok(Some(7)));
        assert_eq!(bind(payload, 7), Err(IpcError::AlreadyBound));
        assert_eq!(bind(payload, 8), Err(IpcError::AlreadyBound));

        // arm(None) 是“无期限等待”，不会被 on_tick 触发。
        arm(payload, None).unwrap();
        assert_eq!(deadline(payload), Ok(None));
        assert_eq!(on_tick(u64::MAX), 0);
        assert_eq!(ready(payload), Ok(false));

        disarm(payload).unwrap();
        disarm(payload).unwrap();
        discard(payload).unwrap();
        assert_eq!(count(), 0);
    }

    #[test]
    fn armed_timer_fires_exactly_once_at_its_deadline() {
        let _guard = lock();
        reset_for_test();

        let payload = bound_timer(9);
        arm(payload, Some(100)).unwrap();
        assert_eq!(deadline(payload), Ok(Some(100)));

        // 未到期不触发。
        assert_eq!(on_tick(99), 0);
        assert_eq!(ready(payload), Ok(false));

        // 到期触发一次：置就绪并解除 armed。
        assert_eq!(on_tick(100), 1);
        assert_eq!(ready(payload), Ok(true));
        assert_eq!(deadline(payload), Ok(None));

        // 同一个 Timer 不会二次触发。
        assert_eq!(on_tick(1_000), 0);
        assert_eq!(ready(payload), Ok(true));

        // 消费清除就绪位。
        assert_eq!(consume(payload), Ok(true));
        assert_eq!(consume(payload), Ok(false));
        assert_eq!(ready(payload), Ok(false));

        discard(payload).unwrap();
    }

    #[test]
    fn rearming_clears_readiness_and_uses_the_new_deadline() {
        let _guard = lock();
        reset_for_test();

        let payload = bound_timer(11);
        arm(payload, Some(10)).unwrap();
        assert_eq!(on_tick(10), 1);
        assert_eq!(ready(payload), Ok(true));

        // 重新 arm：清就绪位、覆盖截止时间。
        arm(payload, Some(50)).unwrap();
        assert_eq!(ready(payload), Ok(false));
        assert_eq!(on_tick(10), 0);
        assert_eq!(on_tick(50), 1);
        assert_eq!(ready(payload), Ok(true));

        discard(payload).unwrap();
    }

    #[test]
    fn disarmed_timer_never_fires() {
        let _guard = lock();
        reset_for_test();

        let payload = bound_timer(13);
        arm(payload, Some(5)).unwrap();
        disarm(payload).unwrap();
        assert_eq!(on_tick(u64::MAX), 0);
        assert_eq!(ready(payload), Ok(false));

        discard(payload).unwrap();
    }

    #[test]
    fn timer_table_quota_is_fixed() {
        let _guard = lock();
        reset_for_test();

        let mut payloads = [0u64; MAX_TIMERS];
        for (index, payload) in payloads.iter_mut().enumerate() {
            *payload = create().unwrap();
            bind(*payload, index as ObjectId).unwrap();
        }
        assert_eq!(create(), Err(IpcError::TableFull));

        let _ = destroy(payloads[5], 5).unwrap();
        assert_eq!(count(), MAX_TIMERS - 1);
        assert!(create().is_ok());
        assert_eq!(count(), MAX_TIMERS);

        reset_for_test();
        assert_eq!(count(), 0);
    }

    #[test]
    fn destroying_a_timer_releases_its_slot() {
        let _guard = lock();
        reset_for_test();

        let payload = bound_timer(21);
        arm(payload, Some(1)).unwrap();
        destroy(payload, 21).unwrap();
        assert_eq!(count(), 0);
        assert_eq!(destroy(payload, 21), Err(IpcError::InvalidPayload));
        assert_eq!(ready(payload), Err(IpcError::InvalidPayload));
        assert_eq!(on_tick(u64::MAX), 0);
    }

    /// M7：timer 到期后（在表锁之外）唤醒注册过的订阅。
    #[test]
    fn expiry_wakes_a_registered_subscription() {
        use crate::ipc::{poll_waitable_keyed, subscription};
        use crate::object::{self, ObjectKind};

        let _guard = lock();
        reset_for_test();
        crate::ipc::install_destroy_hooks().expect("destroy hooks install");
        subscription::reset();

        let payload = create().unwrap();
        let target = object::create_with_payload(ObjectKind::Timer, payload).expect("timer object");
        bind(payload, target).expect("bind timer object");

        let watched =
            object::create_with_payload(ObjectKind::EventSubscription, 0).expect("subscription");
        subscription::create(watched).expect("create subscription");
        subscription::register(watched, target, subscription::MODE_LEVEL, 0).expect("register");

        arm(payload, Some(100)).unwrap();
        assert_eq!(poll_waitable_keyed(watched, 0, false), Ok(false));
        assert_eq!(on_tick(99), 0);
        assert_eq!(poll_waitable_keyed(watched, 0, false), Ok(false));

        assert_eq!(on_tick(100), 1);
        assert_eq!(poll_waitable_keyed(watched, 0, false), Ok(true));

        // 清理：销毁订阅会延迟释放目标引用，再释放两个对象（钩子清表）。
        subscription::destroy(watched).expect("destroy subscription");
        let _ = crate::ipc::release_subscription_pending();
        let _ = object::release_object(watched);
        let _ = object::release_object(target);
        assert_eq!(count(), 0);
    }

    /// ET 闭环：到期边沿被 read 消费后，`consume`/rearm 必须重新武装 observed，
    /// 否则“源自己抽干、订阅侧没有 poll”的窗口会漏掉下一次到期。
    #[test]
    fn consume_and_rearm_rearm_the_edge_before_the_next_expiry() {
        use crate::ipc::{poll_waitable_keyed, subscription};
        use crate::object::{self, ObjectKind};

        let _guard = lock();
        reset_for_test();
        crate::ipc::install_destroy_hooks().expect("destroy hooks install");
        subscription::reset();

        let payload = create().unwrap();
        let target = object::create_with_payload(ObjectKind::Timer, payload).expect("timer object");
        bind(payload, target).expect("bind timer object");
        let watched =
            object::create_with_payload(ObjectKind::EventSubscription, 0).expect("subscription");
        subscription::create(watched).expect("create subscription");
        subscription::register(watched, target, subscription::MODE_EDGE, 0).expect("register");
        let mut events = [subscription::SubscriptionEvent {
            object_key: 0,
            mode: 0,
        }; subscription::MAX_EVENTS];

        arm(payload, Some(100)).unwrap();
        assert_eq!(on_tick(100), 1);
        assert_eq!(subscription::read(watched, &mut events).unwrap(), 1);
        // 仍就绪但边沿已消费：重复 read 不重复上报。
        assert_eq!(subscription::read(watched, &mut events).unwrap(), 0);

        // 源侧取走到期事件（目标变为未就绪），订阅侧没有 poll：必须重新武装。
        assert_eq!(consume(payload), Ok(true));
        arm(payload, Some(200)).unwrap();
        assert_eq!(on_tick(200), 1);
        assert_eq!(poll_waitable_keyed(watched, 0, false), Ok(true));
        assert_eq!(subscription::read(watched, &mut events).unwrap(), 1);

        // 重新 arm（未到期即清就绪）同样重新武装。
        arm(payload, Some(300)).unwrap();
        assert_eq!(on_tick(300), 1);
        assert_eq!(subscription::read(watched, &mut events).unwrap(), 1);
        arm(payload, Some(400)).unwrap();
        assert_eq!(on_tick(400), 1);
        assert_eq!(poll_waitable_keyed(watched, 0, false), Ok(true));

        subscription::destroy(watched).expect("destroy subscription");
        let _ = crate::ipc::release_subscription_pending();
        let _ = object::release_object(watched);
        let _ = object::release_object(target);
        assert_eq!(count(), 0);
    }
}
