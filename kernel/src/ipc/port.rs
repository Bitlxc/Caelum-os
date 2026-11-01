//! 原生 Port 对象（M6a2）：多发送者 / 单接收者的服务请求队列。
//!
//! 模型：
//!
//! - 一个 Port 由**两个端点对象**组成：`receiver` 与 `sender`。二者只是身份，
//!   状态表按 [`ObjectId`] 认角色；`sender` 可用 `dup`/句柄传递在多个发送者之间
//!   共享，因此“多个 sender”在运行时共享同一个 sender 对象（接口矩阵不假装存在
//!   两个相互独立的 sender 进程）。
//! - 只有 receiver 能 `peek`/`commit`/`poll`；只有 sender 能 `send`。角色不符
//!   分别返回 [`IpcError::NotReceiver`] / [`IpcError::NotSender`]。
//! - **receiver 最后引用被销毁**：队列连同消息里的句柄引用一起释放，此后的
//!   `send` 永远返回 [`IpcError::PeerClosed`]（消息不可能再被接收）。
//! - **sender 关闭**：只表示不再有新请求进入，队列中**已排队**的消息保持可用，
//!   接收方仍可 drain；队列排空后 `peek` 返回 `PeerClosed`。
//! - 队列深度固定为 [`PORT_DEPTH`]，堆上不分配；满时 `send`（非阻塞）返回
//!   [`IpcError::WouldBlock`]，不部分入队。
//! - 队列持有 `send` 传入的对象引用，`commit` 或销毁时释放（释放动作在
//!   [`IrqCell`] 闭包之外执行，避免销毁钩子重入本表）。

use crate::object::{self, ObjectId, ObjectKind};
use crate::process::WakeReason;

use super::{IpcError, Message, MessageQueue, OutMessage, release_message_objects};

/// Port 固定容量（一个 Port 占一个槽位，含 receiver 与 sender 两个端点对象）。
pub const MAX_PORTS: usize = 1;

/// 请求队列深度。
pub const PORT_DEPTH: usize = 8;

/// 一个 Port 的运行时状态。
#[derive(Clone, Copy)]
struct PortSlot {
    live: bool,
    receiver: ObjectId,
    sender: ObjectId,
    queue: MessageQueue<PORT_DEPTH>,
    receiver_closed: bool,
    sender_closed: bool,
    next_sequence: u64,
}

impl PortSlot {
    const EMPTY: PortSlot = PortSlot {
        live: false,
        receiver: ObjectId::MAX,
        sender: ObjectId::MAX,
        queue: MessageQueue::EMPTY,
        receiver_closed: false,
        sender_closed: false,
        next_sequence: 1,
    };
}

#[derive(Clone, Copy)]
struct PortTable {
    slots: [PortSlot; MAX_PORTS],
}

impl PortTable {
    const EMPTY: PortTable = PortTable {
        slots: [PortSlot::EMPTY; MAX_PORTS],
    };
}

static PORTS: super::IrqCell<PortTable> = super::IrqCell::new(PortTable::EMPTY);

/// 在表中定位端点 `object` 所属的 Port 槽位与角色（`true` = receiver）。
fn locate(table: &PortTable, object: ObjectId) -> Option<(usize, bool)> {
    for (index, slot) in table.slots.iter().enumerate() {
        if !slot.live {
            continue;
        }
        if slot.receiver == object {
            return Some((index, true));
        }
        if slot.sender == object {
            return Some((index, false));
        }
    }
    None
}

/// 校验对象确实是 `ObjectKind::Port` 端点。
fn check_endpoint(object: ObjectId) -> Result<(), IpcError> {
    match object::object_kind(object) {
        Some(ObjectKind::Port) => Ok(()),
        Some(_) => Err(IpcError::WrongKind),
        None => Err(IpcError::Object(object::ObjectError::InvalidObject)),
    }
}

/// 把一个新建的 Port 端点对象对登记到状态表。
///
/// 两个对象必须已由调用者创建（`create_with_payload(ObjectKind::Port, 0)`），
/// 不能相同、不能已属于其它 Port。状态表不额外持有对象引用。
pub fn create(receiver: ObjectId, sender: ObjectId) -> Result<(), IpcError> {
    if receiver == sender {
        return Err(IpcError::InvalidEndpoint);
    }
    check_endpoint(receiver)?;
    check_endpoint(sender)?;
    PORTS.with(|table| {
        if locate(table, receiver).is_some() || locate(table, sender).is_some() {
            return Err(IpcError::AlreadyLinked);
        }
        for slot in table.slots.iter_mut() {
            if slot.live {
                continue;
            }
            *slot = PortSlot::EMPTY;
            slot.live = true;
            slot.receiver = receiver;
            slot.sender = sender;
            return Ok(());
        }
        Err(IpcError::TableFull)
    })
}

/// 由发送端 `sender` 投递一条请求。返回入队分配的 sequence。
///
/// - 对象不是本 Port 的 sender ⇒ [`IpcError::NotSender`]；
/// - receiver 已关闭或 sender 已关闭 ⇒ [`IpcError::PeerClosed`]；
/// - 队列满 ⇒ [`IpcError::WouldBlock`]；失败时队列不变。
///
/// **引用所有权**：**任何**失败路径都会释放消息携带的对象引用（含 validate、身份
/// 校验、`PeerClosed`、`WouldBlock`），调用方不得再释放同一批引用。成功时引用归
/// 队列所有；成功入队后还会在表锁之外唤醒关心 receiver 的订阅。
pub fn send(sender: ObjectId, message: OutMessage) -> Result<u64, IpcError> {
    let carried = message.into_message(0);
    match enqueue(sender, message) {
        Ok((sequence, receiver)) => {
            // receiver 队列刚刚变为非空：**在本表锁之外**唤醒等待者与订阅。
            let _ = crate::process::wake_object(receiver, WakeReason::Ready);
            super::notify_target_ready(receiver);
            Ok(sequence)
        }
        Err(error) => {
            // 锁外释放：归零引用可能触发销毁钩子并重入本表。
            release_message_objects(&carried);
            Err(error)
        }
    }
}

/// `send` 的入队部分：校验、角色/关闭状态检查、入队，返回 `(sequence, receiver)`。
/// **不**释放消息引用。
fn enqueue(sender: ObjectId, message: OutMessage) -> Result<(u64, ObjectId), IpcError> {
    message.validate()?;
    PORTS.with(|table| -> Result<(u64, ObjectId), IpcError> {
        let (index, is_receiver) =
            locate(table, sender).ok_or(IpcError::Object(object::ObjectError::InvalidObject))?;
        if is_receiver {
            return Err(IpcError::NotSender);
        }
        let slot = &mut table.slots[index];
        if slot.receiver_closed || slot.sender_closed {
            return Err(IpcError::PeerClosed);
        }
        let receiver = slot.receiver;
        let sequence = slot.next_sequence;
        slot.queue
            .push(message.into_message(sequence))
            // 退回的消息副本由 `send` 在锁外用 `carried` 释放，此处不再处理。
            .map_err(|(error, _returned)| error)?;
        slot.next_sequence = sequence.wrapping_add(1);
        // 唤醒动作由调用方在表锁之外执行（不得在 IPC 表锁内取进程表锁）。
        Ok((sequence, receiver))
    })
}

/// 查看接收端队首消息（不弹出、不释放引用）。
///
/// 对象不是 receiver ⇒ [`IpcError::NotReceiver`]；队列空且 sender 已关 ⇒
/// [`IpcError::PeerClosed`]；否则 [`IpcError::WouldBlock`]。
pub fn peek(receiver: ObjectId) -> Result<Message, IpcError> {
    PORTS.with(|table| {
        let (index, is_receiver) =
            locate(table, receiver).ok_or(IpcError::Object(object::ObjectError::InvalidObject))?;
        if !is_receiver {
            return Err(IpcError::NotReceiver);
        }
        let slot = &table.slots[index];
        if let Some(message) = slot.queue.front() {
            return Ok(*message);
        }
        if slot.sender_closed {
            return Err(IpcError::PeerClosed);
        }
        Err(IpcError::WouldBlock)
    })
}

/// 确认接收端队首/指定 `sequence` 的请求：移除并释放队列持有的句柄引用。
///
/// 抽到空之后在释放表锁之后通知订阅重新武装边沿（覆盖“订阅侧没有 poll，源自己抽干”）。
pub fn commit(receiver: ObjectId, sequence: u64) -> Result<(), IpcError> {
    let (removed, empty) = PORTS.with(|table| {
        let (index, is_receiver) =
            locate(table, receiver).ok_or(IpcError::Object(object::ObjectError::InvalidObject))?;
        if !is_receiver {
            return Err(IpcError::NotReceiver);
        }
        let slot = &mut table.slots[index];
        let removed = slot
            .queue
            .remove_sequence(sequence)
            .ok_or(IpcError::InvalidSequence)?;
        Ok::<_, IpcError>((removed, slot.queue.is_empty()))
    })?;
    release_message_objects(&removed);
    // 队列由非空变空：就绪变为 false，释放表锁后通知订阅重新武装边沿。
    if empty {
        let _ = super::subscription::on_target_not_ready(receiver);
    }
    Ok(())
}

/// 轮询：receiver 队列非空即就绪。
///
/// `take` 被**刻意忽略**：统一 WAIT/ready 语义只报告就绪、绝不消费队列；真正取走
/// 请求只走 `IPC_RECV` 的 `peek` → `commit`，`commit` 才释放队列持有的引用。
///
/// sender 端点永远报告“未就绪”（写路径本身就是非阻塞的，满即 `WouldBlock`）；
/// 这样统一事件循环可以直接把任意保障/端点放进 poll 而不必先判角色。
pub fn poll(object: ObjectId, _take: bool) -> Result<bool, IpcError> {
    PORTS.with(|table| {
        let (index, is_receiver) =
            locate(table, object).ok_or(IpcError::Object(object::ObjectError::InvalidObject))?;
        if !is_receiver {
            return Ok(false);
        }
        Ok(table.slots[index].queue.front().is_some())
    })
}

/// 销毁一个 Port 端点（对象层销毁钩子的落点）。
///
/// 返回 `Ok(false)` 表示该对象不是 Port 端点。
pub fn destroy_endpoint(object: ObjectId) -> Result<bool, IpcError> {
    let mut dropped: [Option<Message>; PORT_DEPTH] = [None; PORT_DEPTH];
    // 表锁内只收集唤醒动作，锁外统一执行（不得在 IPC 表锁内取进程表锁）。
    let mut wakes: [(ObjectId, WakeReason); 2] = [(ObjectId::MAX, WakeReason::None); 2];
    let mut wake_count = 0usize;
    let handled = PORTS.with(|table| {
        let Some((index, is_receiver)) = locate(table, object) else {
            return Ok(false);
        };
        let slot = &mut table.slots[index];
        let mut dropped_count = 0usize;
        if is_receiver {
            if !slot.receiver_closed {
                slot.receiver_closed = true;
                // receiver 消失：所有已排队请求都不可能被接收，连引用一起释放。
                dropped_count = slot.queue.drain_into(&mut dropped);
            }
        } else if !slot.sender_closed {
            slot.sender_closed = true;
        }
        wakes[wake_count] = (object, WakeReason::Destroyed);
        wake_count += 1;
        let peer_object = if is_receiver {
            slot.sender
        } else {
            slot.receiver
        };
        let peer_alive = if is_receiver {
            !slot.sender_closed
        } else {
            !slot.receiver_closed
        };
        if peer_alive {
            // receiver 关闭：sender 侧不再有接收者 ⇒ PeerClosed。
            // sender 关闭：receiver 侧已排队消息仍可读 ⇒ Ready，否则 PeerClosed。
            let reason = if is_receiver {
                WakeReason::PeerClosed
            } else if slot.queue.is_empty() {
                WakeReason::PeerClosed
            } else {
                WakeReason::Ready
            };
            wakes[wake_count] = (peer_object, reason);
            wake_count += 1;
        } else {
            *slot = PortSlot::EMPTY;
        }
        let _ = dropped_count;
        Ok(true)
    })?;
    for slot in dropped.iter_mut() {
        if let Some(message) = slot.take() {
            release_message_objects(&message);
        }
    }
    for (target, reason) in wakes.iter().take(wake_count) {
        let _ = crate::process::wake_object(*target, *reason);
    }
    Ok(handled)
}

/// 当前活跃 Port 数量。
pub fn count() -> usize {
    PORTS.with(|table| table.slots.iter().filter(|slot| slot.live).count())
}

/// 清空状态表（仅测试用）。
#[cfg(test)]
pub(crate) fn reset_for_test() {
    PORTS.with(|table| {
        for slot in table.slots.iter_mut() {
            *slot = PortSlot::EMPTY;
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ipc;
    use crate::ipc::timer;

    fn lock() -> std::sync::MutexGuard<'static, ()> {
        crate::object::test_lock()
    }

    fn install_hooks() {
        ipc::install_destroy_hooks().expect("destroy hooks install");
    }

    fn endpoint() -> ObjectId {
        object::create_with_payload(ObjectKind::Port, 0).expect("create port endpoint")
    }

    fn pair() -> (ObjectId, ObjectId) {
        let receiver = endpoint();
        let sender = endpoint();
        create(receiver, sender).expect("link port");
        (receiver, sender)
    }

    fn message(data: &[u8]) -> OutMessage {
        OutMessage::with_data(data).expect("message data")
    }

    fn reset() {
        reset_for_test();
        timer::reset_for_test();
        crate::object::reset_destroy_hooks();
        install_hooks();
    }

    fn release(receiver: ObjectId, sender: ObjectId) {
        let _ = object::release_object(receiver);
        let _ = object::release_object(sender);
    }

    #[test]
    fn requests_are_fifo_and_commit_uses_sequence() {
        let _guard = lock();
        reset();
        let (receiver, sender) = pair();
        let first = send(sender, message(b"one")).expect("send");
        send(sender, message(b"two")).expect("send");
        assert_eq!(peek(receiver).expect("peek").data(), b"one");
        commit(receiver, first).expect("commit");
        assert_eq!(peek(receiver).expect("peek").data(), b"two");
        assert_eq!(commit(receiver, first), Err(IpcError::InvalidSequence));
        release(receiver, sender);
    }

    #[test]
    fn full_queue_returns_would_block() {
        let _guard = lock();
        reset();
        let (receiver, sender) = pair();
        for index in 0..PORT_DEPTH {
            send(sender, message(&[index as u8])).expect("send");
        }
        assert_eq!(
            send(sender, message(b"overflow")),
            Err(IpcError::WouldBlock)
        );
        assert_eq!(peek(receiver).expect("peek").data(), &[0]);
        release(receiver, sender);
    }

    #[test]
    fn role_mismatch_is_reported() {
        let _guard = lock();
        reset();
        let (receiver, sender) = pair();
        assert_eq!(send(receiver, message(b"x")), Err(IpcError::NotSender));
        assert_eq!(peek(sender), Err(IpcError::NotReceiver));
        assert_eq!(commit(sender, 1), Err(IpcError::NotReceiver));
        // sender 端点轮询永远未就绪。
        assert_eq!(poll(sender, false), Ok(false));
        release(receiver, sender);
    }

    #[test]
    fn receiver_close_makes_send_fail_and_releases_queue() {
        let _guard = lock();
        reset();
        let (receiver, sender) = pair();
        let payload = timer::create().expect("timer slot");
        let object = object::create_with_payload(ObjectKind::Timer, payload).expect("timer object");
        let carried = message(b"handle")
            .with_handle(object, crate::object::Rights::WAIT)
            .expect("attach");
        send(sender, carried).expect("send");
        // 发送方把对象引用转移给队列：对象仍然存活。
        assert_eq!(timer::count(), 1);
        assert!(destroy_endpoint(receiver).expect("destroy receiver"));
        // receiver 关闭：队列连同句柄引用一起释放。
        assert_eq!(timer::count(), 0);
        assert_eq!(send(sender, message(b"late")), Err(IpcError::PeerClosed));
        release(receiver, sender);
        assert_eq!(count(), 0);
    }

    #[test]
    fn sender_close_keeps_queued_requests_drainable() {
        let _guard = lock();
        reset();
        let (receiver, sender) = pair();
        send(sender, message(b"queued")).expect("send");
        assert!(destroy_endpoint(sender).expect("destroy sender"));
        // 已排队消息仍可读，排空后才报告 PeerClosed。
        assert_eq!(peek(receiver).expect("peek").data(), b"queued");
        let sequence = peek(receiver).expect("peek").sequence;
        commit(receiver, sequence).expect("commit");
        assert_eq!(peek(receiver), Err(IpcError::PeerClosed));
        assert_eq!(send(sender, message(b"late")), Err(IpcError::PeerClosed));
        release(receiver, sender);
        assert_eq!(count(), 0);
    }

    #[test]
    fn quota_is_fixed_and_relink_rejected() {
        let _guard = lock();
        reset();
        let (receiver, sender) = pair();
        let extra_receiver = endpoint();
        let extra_sender = endpoint();
        assert_eq!(
            create(extra_receiver, extra_sender),
            Err(IpcError::TableFull)
        );
        let second_receiver = endpoint();
        assert_eq!(
            create(second_receiver, sender),
            Err(IpcError::AlreadyLinked)
        );
        release(receiver, sender);
        create(second_receiver, extra_sender).expect("relink after free");
        release(second_receiver, extra_sender);
        object::release_object(extra_receiver).expect("release extra receiver");
    }

    #[test]
    fn sender_object_shared_by_two_handles_still_sends() {
        let _guard = lock();
        reset();
        let (receiver, sender) = pair();
        // 模拟两个发送者共享同一 sender 对象（对象层 dup 语义）：同一 ObjectId 再取一份引用。
        object::acquire_object(sender).expect("dup sender ref");
        send(sender, message(b"from-any")).expect("send via shared sender");
        assert_eq!(peek(receiver).expect("peek").data(), b"from-any");
        release(receiver, sender);
        let _ = object::release_object(sender);
    }

    #[test]
    fn pending_requests_survive_unrelated_polling() {
        let _guard = lock();
        reset();
        let (receiver, sender) = pair();
        send(sender, message(b"keep")).expect("send");
        assert_eq!(poll(receiver, false), Ok(true));
        assert_eq!(peek(receiver).expect("peek").data(), b"keep");
        // WAIT/ready 永远不消费队列：take=true 也只报告就绪，消息必须保留到 commit。
        assert_eq!(poll(receiver, true), Ok(true));
        assert_eq!(peek(receiver).expect("peek").data(), b"keep");
        let sequence = peek(receiver).expect("peek").sequence;
        commit(receiver, sequence).expect("commit");
        assert_eq!(peek(receiver), Err(IpcError::WouldBlock));
        assert_eq!(poll(receiver, true), Ok(false));
        release(receiver, sender);
    }

    /// 构造一个可转移引用的对象（引用计数 1），用于验证失败路径是否释放。
    fn transferable() -> ObjectId {
        let payload = timer::create().expect("timer slot");
        object::create_with_payload(ObjectKind::Timer, payload).expect("timer object")
    }

    /// M8：`send` 的**所有**早退路径（NotSender/PeerClosed/InvalidObject/校验失败）
    /// 都必须释放消息携带的对象引用，而不是只处理 `WouldBlock`。
    #[test]
    fn early_send_failures_release_the_message_references() {
        let _guard = lock();
        reset();
        let (receiver, sender) = pair();

        // NotSender：用 receiver 端点投递。
        let first = transferable();
        assert_eq!(
            send(
                receiver,
                message(b"role")
                    .with_handle(first, crate::object::Rights::WAIT)
                    .unwrap()
            ),
            Err(IpcError::NotSender)
        );
        assert_eq!(timer::count(), 0);

        // PeerClosed：receiver 关闭后请求永远无人接收。
        let second = transferable();
        assert!(destroy_endpoint(receiver).expect("close receiver"));
        assert_eq!(
            send(
                sender,
                message(b"closed")
                    .with_handle(second, crate::object::Rights::WAIT)
                    .unwrap()
            ),
            Err(IpcError::PeerClosed)
        );
        assert_eq!(timer::count(), 0);

        // InvalidObject：目标不是任何 Port 端点。
        let third = transferable();
        assert_eq!(
            send(
                ObjectId::MAX,
                message(b"bad-target")
                    .with_handle(third, crate::object::Rights::WAIT)
                    .unwrap()
            ),
            Err(IpcError::Object(object::ObjectError::InvalidObject))
        );
        assert_eq!(timer::count(), 0);

        // 校验失败（rights 为空）同样释放。
        let fourth = transferable();
        let mut bad = message(b"bad-rights");
        bad.handle_count = 1;
        bad.objects[0] = fourth;
        assert_eq!(
            send(sender, bad),
            Err(IpcError::Object(object::ObjectError::InvalidRights))
        );
        assert_eq!(timer::count(), 0);

        release(receiver, sender);
        assert_eq!(count(), 0);
    }

    /// M7：成功投递后在表锁之外唤醒关心 receiver 的订阅。
    #[test]
    fn successful_send_wakes_a_port_subscription() {
        use crate::ipc::subscription;

        let _guard = lock();
        reset();
        subscription::reset();
        let (receiver, sender) = pair();
        let watched = object::create_with_payload(ObjectKind::EventSubscription, 0).unwrap();
        subscription::create(watched).unwrap();
        subscription::register(watched, receiver, subscription::MODE_LEVEL, 0).unwrap();

        assert_eq!(
            crate::ipc::poll_waitable_keyed(watched, 0, false),
            Ok(false)
        );
        send(sender, message(b"ready")).expect("send");
        assert_eq!(crate::ipc::poll_waitable_keyed(watched, 0, false), Ok(true));

        subscription::destroy(watched).unwrap();
        let _ = crate::ipc::release_subscription_pending();
        let _ = object::release_object(watched);
        release(receiver, sender);
        assert_eq!(count(), 0);
    }

    /// ET 闭环：`commit` 把队列抽空后必须重新武装 observed，
    /// 否则“源自己抽干、订阅侧没有 poll”的窗口会漏掉下一次投递边沿。
    #[test]
    fn commit_draining_the_queue_rearms_the_edge() {
        use crate::ipc::subscription;

        let _guard = lock();
        reset();
        subscription::reset();
        let (receiver, sender) = pair();
        let watched = object::create_with_payload(ObjectKind::EventSubscription, 0).unwrap();
        subscription::create(watched).unwrap();
        subscription::register(watched, receiver, subscription::MODE_EDGE, 0).unwrap();
        let mut events = [subscription::SubscriptionEvent {
            object_key: 0,
            mode: 0,
        }; subscription::MAX_EVENTS];

        let first = send(sender, message(b"one")).expect("send");
        assert_eq!(subscription::read(watched, &mut events).unwrap(), 1);
        assert_eq!(commit(receiver, first).expect("commit"), ());
        send(sender, message(b"two")).expect("send after drain");
        assert_eq!(crate::ipc::poll_waitable_keyed(watched, 0, false), Ok(true));
        assert_eq!(subscription::read(watched, &mut events).unwrap(), 1);

        subscription::destroy(watched).unwrap();
        let _ = crate::ipc::release_subscription_pending();
        let _ = object::release_object(watched);
        release(receiver, sender);
        assert_eq!(count(), 0);
    }
}
