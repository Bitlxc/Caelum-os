//! 原生 Channel 对象（M6a2）：一条双向、有序、带边界且可传句柄的消息通道。
//!
//! 模型：
//!
//! - 一个 Channel 由**两个端点对象**组成（`ObjectKind::Channel`），对象本身只
//!   是身份，不编码槽位；Channel 状态表按 `ObjectId` 认端点。
//! - 每个端点有一条**入站队列**（`queues[i]` 是发给端点 `i` 的消息）。A 发给 B
//!   的消息进入 B 的入站队列，因此“A 的入队就是 B 的可接收队列”。
//! - 关闭端点 `i` 时：丢弃 `i` 的入站队列（连同其中句柄引用）、标记 `closed[i]`、
//!   唤醒 `i` 自身 `Destroyed`；对端 `i^1` 若入站队列为空则唤醒 `PeerClosed`，
//!   否则唤醒 `Ready`（对端仍可把已排队消息 drain 完）。两端都关闭后释放槽位。
//! - 队列深度固定为 [`CHANNEL_DEPTH`]，堆上不分配；满时 `send` 返回
//!   [`IpcError::WouldBlock`]，不阻塞、不部分入队。
//! - 队列持有 `send` 时传入的对象引用；`peek` 不弹出也不释放，`commit` 按
//!   sequence 移除并释放队列那一份引用（释放动作在 [`IrqCell`] 闭包之外执行）。

use crate::object::{self, ObjectId, ObjectKind};
use crate::process::WakeReason;

use super::{IpcError, Message, MessageQueue, OutMessage, release_message_objects};

/// Channel 固定容量（一个 Channel 占一个槽位，含两个端点对象）。
pub const MAX_CHANNELS: usize = 2;

/// 每条入站队列的深度。
pub const CHANNEL_DEPTH: usize = 4;

/// 每个 Channel 的端点数量。
const ENDPOINTS: usize = 2;

/// 一个 Channel 的运行时状态。
#[derive(Clone, Copy)]
struct ChannelSlot {
    live: bool,
    endpoints: [ObjectId; ENDPOINTS],
    closed: [bool; ENDPOINTS],
    /// `queues[i]` 是发给端点 `i` 的消息（入站队列）。
    queues: [MessageQueue<CHANNEL_DEPTH>; ENDPOINTS],
    /// 每个入站队列的下一序号（从 1 开始单调递增）。
    next_sequence: [u64; ENDPOINTS],
}

impl ChannelSlot {
    const EMPTY: ChannelSlot = ChannelSlot {
        live: false,
        endpoints: [ObjectId::MAX; ENDPOINTS],
        closed: [false; ENDPOINTS],
        queues: [MessageQueue::EMPTY; ENDPOINTS],
        next_sequence: [1; ENDPOINTS],
    };
}

#[derive(Clone, Copy)]
struct ChannelTable {
    slots: [ChannelSlot; MAX_CHANNELS],
}

impl ChannelTable {
    const EMPTY: ChannelTable = ChannelTable {
        slots: [ChannelSlot::EMPTY; MAX_CHANNELS],
    };
}

static CHANNELS: super::IrqCell<ChannelTable> = super::IrqCell::new(ChannelTable::EMPTY);

/// 在表中定位端点 `object` 所属的 Channel 槽位与端点索引。
fn locate(table: &ChannelTable, object: ObjectId) -> Option<(usize, usize)> {
    for (index, slot) in table.slots.iter().enumerate() {
        if !slot.live {
            continue;
        }
        for endpoint in 0..ENDPOINTS {
            if slot.endpoints[endpoint] == object {
                return Some((index, endpoint));
            }
        }
    }
    None
}

/// 端点对象是否已经属于某个 Channel。
fn linked(table: &ChannelTable, object: ObjectId) -> bool {
    locate(table, object).is_some()
}

/// 校验对象确实是 `ObjectKind::Channel` 端点。
fn check_endpoint(object: ObjectId) -> Result<(), IpcError> {
    match object::object_kind(object) {
        Some(ObjectKind::Channel) => Ok(()),
        Some(_) => Err(IpcError::WrongKind),
        None => Err(IpcError::Object(object::ObjectError::InvalidObject)),
    }
}

/// 把一个新建的 Channel 端点对象登记到状态表。
///
/// 两个对象必须已由调用者创建（`create_with_payload(ObjectKind::Channel, 0)`），
/// 且不能相同、不能已属于其它 Channel。调用者负责对象引用的最终释放；成功时
/// 状态表不额外持有对象引用（Channel 状态按 `ObjectId` 查询）。
pub fn create(a: ObjectId, b: ObjectId) -> Result<(), IpcError> {
    if a == b {
        return Err(IpcError::InvalidEndpoint);
    }
    check_endpoint(a)?;
    check_endpoint(b)?;
    CHANNELS.with(|table| {
        if linked(table, a) || linked(table, b) {
            return Err(IpcError::AlreadyLinked);
        }
        for slot in table.slots.iter_mut() {
            if slot.live {
                continue;
            }
            *slot = ChannelSlot::EMPTY;
            slot.live = true;
            slot.endpoints = [a, b];
            return Ok(());
        }
        Err(IpcError::TableFull)
    })
}

/// 从端点 `destination`（**发送方自己这一端**）发送消息。
///
/// 消息写入**对端**的入站队列，因此跨进程时发送方无需持有对端句柄：双方都只在
/// 自己的端点 `send`、在自己的端点 `peek`/`commit`。返回入队分配到的 sequence
/// （按接收端队列单调递增，供接收方 `commit` 匹配）。失败时不改变队列：
///
/// - 消息字段非法 / 句柄指向不存在的对象 ⇒ `MessageTooLarge`/`TooManyHandles`/`InvalidRights`/`InvalidObject`；
/// - `destination` 不是 Channel 端点 ⇒ `WrongKind`/`InvalidObject`；
/// - 任一端点已关闭（消息永不可能被接收）⇒ `PeerClosed`；
/// - 对端队列已满 ⇒ `WouldBlock`。
///
/// **引用所有权**：**任何**失败路径都会释放消息携带的对象引用（含 validate、身份
/// 校验、`PeerClosed`、`WouldBlock`），调用方不得再释放同一批引用。成功时引用归
/// 队列所有；成功入队后还会在表锁之外唤醒关心该**对端**（队列刚变为非空）的订阅。
pub fn send(destination: ObjectId, message: OutMessage) -> Result<u64, IpcError> {
    let carried = message.into_message(0);
    match enqueue(destination, message) {
        Ok((sequence, peer)) => {
            // 对端队列刚刚变为可接收：**在本表锁之外**唤醒等待者与订阅
            // （`wake_object` 取进程表锁、`on_target_ready` 会重新读取目标就绪）。
            let _ = crate::process::wake_object(peer, WakeReason::Ready);
            super::notify_target_ready(peer);
            Ok(sequence)
        }
        Err(error) => {
            // 锁外释放：归零引用可能触发销毁钩子并重入本表。
            release_message_objects(&carried);
            Err(error)
        }
    }
}

/// `send` 的入队部分：校验、角色/关闭状态检查、入队到**对端**队列。
/// **不**释放消息引用；成功时返回 `(sequence, peer)`，`peer` 是队列刚变为非空的端点。
fn enqueue(destination: ObjectId, message: OutMessage) -> Result<(u64, ObjectId), IpcError> {
    message.validate()?;
    CHANNELS.with(|table| -> Result<(u64, ObjectId), IpcError> {
        let (index, endpoint) = locate(table, destination)
            .ok_or(IpcError::Object(object::ObjectError::InvalidObject))?;
        let slot = &mut table.slots[index];
        if slot.closed[endpoint] || slot.closed[endpoint ^ 1] {
            return Err(IpcError::PeerClosed);
        }
        // `queues[i]` 是「发给端点 i」的入站队列：在本端发送 ⇒ 投递到对端 `endpoint ^ 1`。
        let receiver = endpoint ^ 1;
        let sequence = slot.next_sequence[receiver];
        slot.queues[receiver]
            .push(message.into_message(sequence))
            // 退回的消息副本由 `send` 在锁外用 `carried` 释放，此处不再处理。
            .map_err(|(error, _returned)| error)?;
        slot.next_sequence[receiver] = sequence.wrapping_add(1);
        // 唤醒动作由调用方在表锁之外执行（不得在 IPC 表锁内取进程表锁）。
        let peer = slot.endpoints[receiver];
        Ok((sequence, peer))
    })
}

/// 查看接收端 `receiver` 队首消息（不弹出、不释放引用）。
///
/// 空且对端仍开：`WouldBlock`；空且对端已关：`PeerClosed`（不会再有新消息）。
pub fn peek(receiver: ObjectId) -> Result<Message, IpcError> {
    CHANNELS.with(|table| {
        let (index, endpoint) =
            locate(table, receiver).ok_or(IpcError::Object(object::ObjectError::InvalidObject))?;
        let slot = &table.slots[index];
        if let Some(message) = slot.queues[endpoint].front() {
            return Ok(*message);
        }
        if slot.closed[endpoint ^ 1] {
            return Err(IpcError::PeerClosed);
        }
        Err(IpcError::WouldBlock)
    })
}

/// 确认接收端队首/指定 `sequence` 的消息：移除它并释放队列持有的句柄引用。
///
/// 未找到（已被 commit 或从未入队）⇒ [`IpcError::InvalidSequence`]。抽到空之后在
/// 释放表锁之后通知订阅重新武装边沿（覆盖“订阅侧没有 poll，源自己抽干”的窗口）。
pub fn commit(receiver: ObjectId, sequence: u64) -> Result<(), IpcError> {
    let (removed, empty) = CHANNELS.with(|table| {
        let (index, endpoint) =
            locate(table, receiver).ok_or(IpcError::Object(object::ObjectError::InvalidObject))?;
        let slot = &mut table.slots[index];
        let removed = slot.queues[endpoint]
            .remove_sequence(sequence)
            .ok_or(IpcError::InvalidSequence)?;
        Ok::<_, IpcError>((removed, slot.queues[endpoint].is_empty()))
    })?;
    // 句柄引用必须在 IPC 表闭包外释放：归零可能触发销毁钩子并重入本表。
    release_message_objects(&removed);
    // 队列由非空变空：就绪变为 false，释放表锁后通知订阅重新武装边沿。
    if empty {
        let _ = super::subscription::on_target_not_ready(receiver);
    }
    Ok(())
}

/// 轮询端点是否可接收。
///
/// `take` 被**刻意忽略**：统一 WAIT/ready 语义只报告就绪、绝不消费队列。真正取走
/// 消息只走 `IPC_RECV` 的 `peek` → `commit`，`commit` 才释放队列持有的引用。
pub fn poll(object: ObjectId, _take: bool) -> Result<bool, IpcError> {
    CHANNELS.with(|table| {
        let (index, endpoint) =
            locate(table, object).ok_or(IpcError::Object(object::ObjectError::InvalidObject))?;
        Ok(table.slots[index].queues[endpoint].front().is_some())
    })
}

/// 销毁一个 Channel 端点（对象层销毁钩子的落点）。
///
/// 返回 `Ok(false)` 表示该对象不是 Channel 端点（不是错误，交给其它销毁路径）。
pub fn destroy_endpoint(object: ObjectId) -> Result<bool, IpcError> {
    let mut dropped: [Option<Message>; CHANNEL_DEPTH] = [None; CHANNEL_DEPTH];
    let mut dropped_count = 0usize;
    // 表锁内只收集唤醒动作，锁外统一执行（不得在 IPC 表锁内取进程表锁）。
    let mut wakes: [(ObjectId, WakeReason); 2] = [(ObjectId::MAX, WakeReason::None); 2];
    let mut wake_count = 0usize;
    let handled = CHANNELS.with(|table| {
        let Some((index, endpoint)) = locate(table, object) else {
            return Ok(false);
        };
        let slot = &mut table.slots[index];
        if !slot.closed[endpoint] {
            slot.closed[endpoint] = true;
            // 丢弃发给被关闭端点的入站消息（它们永远不会被接收）。
            dropped_count = slot.queues[endpoint].drain_into(&mut dropped);
        }
        let peer = endpoint ^ 1;
        // 关闭端自身可能仍有其它句柄引用（dup/转移），唤醒它的等待者为 Destroyed；
        // 对端若队列为空则等不到更多消息，唤醒 PeerClosed，否则唤醒 Ready。
        wakes[wake_count] = (object, WakeReason::Destroyed);
        wake_count += 1;
        let peer_object = slot.endpoints[peer];
        let peer_live = !slot.closed[peer];
        if peer_live {
            let reason = if slot.queues[peer].is_empty() {
                WakeReason::PeerClosed
            } else {
                WakeReason::Ready
            };
            wakes[wake_count] = (peer_object, reason);
            wake_count += 1;
        } else {
            // 两端都已关闭：释放槽位。
            *slot = ChannelSlot::EMPTY;
        }
        Ok(true)
    })?;
    // 引用释放放到表锁闭包之外，避免销毁钩子重入本表。
    for slot in dropped.iter_mut() {
        if let Some(message) = slot.take() {
            release_message_objects(&message);
        }
    }
    for (target, reason) in wakes.iter().take(wake_count) {
        let _ = crate::process::wake_object(*target, *reason);
    }
    let _ = dropped_count;
    Ok(handled)
}

/// 只读诊断：接收端 `receiver` 的入站队列当前长度。
///
/// `None` 表示该对象不是 Channel 端点；不消费、不改变任何状态，可安全地在
/// 失败排查中打印（含在 QEMU 内置自检里）。队列深度上限是 [`CHANNEL_DEPTH`]。
pub fn queued_len(receiver: ObjectId) -> Option<usize> {
    CHANNELS.with(|table| {
        let (index, endpoint) = locate(table, receiver)?;
        Some(table.slots[index].queues[endpoint].len())
    })
}

/// 当前活跃 Channel 数量。
pub fn count() -> usize {
    CHANNELS.with(|table| table.slots.iter().filter(|slot| slot.live).count())
}

/// 清空状态表（仅测试用；不释放队列中消息的对象引用以保持幂等，测试应先行 commit）。
#[cfg(test)]
pub(crate) fn reset_for_test() {
    CHANNELS.with(|table| {
        for slot in table.slots.iter_mut() {
            *slot = ChannelSlot::EMPTY;
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

    /// 创建一个未持有的 Channel 端点对象（引用计数 1，测试结束时释放）。
    fn endpoint() -> ObjectId {
        object::create_with_payload(ObjectKind::Channel, 0).expect("create channel endpoint")
    }

    fn pair() -> (ObjectId, ObjectId) {
        let a = endpoint();
        let b = endpoint();
        create(a, b).expect("link channel");
        (a, b)
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

    fn drain(a: ObjectId, b: ObjectId) {
        let _ = object::release_object(a);
        let _ = object::release_object(b);
    }

    #[test]
    fn channel_messages_are_fifo_in_both_directions() {
        let _guard = lock();
        reset();
        let (a, b) = pair();
        for payload in [b"one".as_slice(), b"two".as_slice(), b"three".as_slice()] {
            send(b, message(payload)).expect("send b->a");
        }
        // b 在自己的端点发送 ⇒ 消息落到 a 的入站队列，只有 a 能接收。
        assert_eq!(peek(a).expect("peek a").data(), b"one");
        let first = peek(a).expect("peek a").sequence;
        commit(a, first).expect("commit first");
        assert_eq!(peek(a).expect("peek a").data(), b"two");
        send(a, message(b"reply")).expect("send a->b");
        assert_eq!(peek(b).expect("peek b").data(), b"reply");
        drain(a, b);
    }

    /// 方向回归：本端发送的消息只出现在对端入站队列，发送方自己的队列保持为空。
    #[test]
    fn send_from_one_end_reaches_the_peer_only() {
        let _guard = lock();
        reset();
        let (a, b) = pair();
        let sequence = send(a, message(b"a-to-b")).expect("send a->b");
        assert_eq!(peek(b).expect("peek b").data(), b"a-to-b");
        assert_eq!(peek(a), Err(IpcError::WouldBlock));
        assert_eq!(poll(a, false), Ok(false));
        assert_eq!(poll(b, false), Ok(true));
        commit(b, sequence).expect("commit");
        send(b, message(b"b-to-a")).expect("send b->a");
        assert_eq!(peek(a).expect("peek a").data(), b"b-to-a");
        assert_eq!(peek(b), Err(IpcError::WouldBlock));
        drain(a, b);
    }

    #[test]
    fn full_queue_returns_would_block_without_blocking() {
        let _guard = lock();
        reset();
        let (a, b) = pair();
        for index in 0..CHANNEL_DEPTH {
            send(b, message(&[index as u8])).expect("send");
        }
        // 对端 a 的入站队列已满。
        assert_eq!(send(b, message(b"overflow")), Err(IpcError::WouldBlock));
        // 队列内容未变：仍可 peek 到第一条并逐条 commit。
        assert_eq!(peek(a).expect("peek").data(), &[0]);
        drain(a, b);
    }

    #[test]
    fn oversized_message_is_rejected_and_queue_is_untouched() {
        let _guard = lock();
        reset();
        let (a, b) = pair();
        send(b, message(b"kept")).expect("send");
        let mut bad = OutMessage::EMPTY;
        bad.data_len = (super::super::MESSAGE_DATA_MAX + 1) as u8;
        assert_eq!(send(b, bad), Err(IpcError::MessageTooLarge));
        assert_eq!(peek(a).expect("peek").data(), b"kept");
        let mut too_many = OutMessage::EMPTY;
        too_many.handle_count = (super::super::MESSAGE_MAX_HANDLES + 1) as u8;
        assert_eq!(send(b, too_many), Err(IpcError::TooManyHandles));
        assert_eq!(peek(a).expect("peek").data(), b"kept");
        drain(a, b);
    }

    #[test]
    fn commit_uses_sequence_and_rejects_unknown_sequences() {
        let _guard = lock();
        reset();
        let (a, b) = pair();
        let sequence = send(b, message(b"x")).expect("send");
        assert_eq!(commit(a, sequence + 1), Err(IpcError::InvalidSequence));
        assert_eq!(peek(a).expect("peek").data(), b"x");
        commit(a, sequence).expect("commit");
        assert_eq!(peek(a), Err(IpcError::WouldBlock));
        assert_eq!(commit(a, sequence), Err(IpcError::InvalidSequence));
        drain(a, b);
    }

    #[test]
    fn queue_holds_object_reference_until_commit() {
        let _guard = lock();
        reset();
        let (a, b) = pair();
        let payload = timer::create().expect("timer slot");
        let object = object::create_with_payload(ObjectKind::Timer, payload).expect("timer object");
        assert_eq!(timer::count(), 1);
        let message = message(b"handle")
            .with_handle(object, crate::object::Rights::WAIT)
            .expect("attach handle");
        let sequence = send(b, message).expect("send with handle");
        // 发送方把自己那份对象引用转移给对端队列：对象仍然存活（Timer 槽未被销毁）。
        assert_eq!(timer::count(), 1);
        commit(a, sequence).expect("commit");
        // commit 释放队列引用 ⇒ 引用归零 ⇒ 销毁钩子释放 Timer 槽。
        assert_eq!(timer::count(), 0);
        drain(a, b);
    }

    #[test]
    fn carried_rights_are_recorded_as_requested() {
        let _guard = lock();
        reset();
        let (a, b) = pair();
        let payload = timer::create().expect("timer slot");
        let object = object::create_with_payload(ObjectKind::Timer, payload).expect("timer object");
        let message = message(b"rights")
            .with_handle(object, crate::object::Rights::READ)
            .expect("attach handle");
        let sequence = send(b, message).expect("send");
        let carried = peek(a).expect("peek");
        assert_eq!(carried.handle_count, 1);
        assert_eq!(carried.objects(), &[object]);
        assert_eq!(carried.rights(), &[crate::object::Rights::READ.bits()]);
        commit(a, sequence).expect("commit");
        assert_eq!(timer::count(), 0);
        drain(a, b);
    }

    #[test]
    fn closed_endpoint_discards_its_inbox_and_peer_can_still_drain() {
        let _guard = lock();
        reset();
        let (a, b) = pair();
        send(b, message(b"for-a")).expect("send b->a");
        send(a, message(b"for-b")).expect("send a->b");
        // 关闭 a：丢弃 a 的入站队列（"for-a"），唤醒 b（b 队列非空 ⇒ Ready）。
        assert!(destroy_endpoint(a).expect("destroy a"));
        assert_eq!(count(), 1);
        // b 仍可 drain 自己队列里的消息。
        assert_eq!(peek(b).expect("peek b").data(), b"for-b");
        // a 的入站消息已被丢弃：b 在自己的端点发送 ⇒ PeerClosed。
        assert_eq!(send(b, message(b"after")), Err(IpcError::PeerClosed));
        drain(b, a);
        assert_eq!(count(), 0);
    }

    #[test]
    fn quota_and_relink_are_enforced() {
        let _guard = lock();
        reset();
        let first = pair();
        let second = pair();
        let extra_a = endpoint();
        let extra_b = endpoint();
        assert_eq!(create(extra_a, extra_b), Err(IpcError::TableFull));
        let reloaded_a = endpoint();
        let reloaded_b = endpoint();
        assert_eq!(create(first.0, reloaded_b), Err(IpcError::AlreadyLinked));
        // 释放第二对后可以再建。
        drain(second.0, second.1);
        create(reloaded_a, reloaded_b).expect("relink after free");
        drain(reloaded_a, reloaded_b);
        object::release_object(extra_a).expect("release extra a");
        object::release_object(extra_b).expect("release extra b");
        drain(first.0, first.1);
    }

    /// M2：统一 WAIT/ready 永不消费队列，只有 `commit` 取走消息。
    #[test]
    fn poll_reports_readiness_without_consuming_queued_messages() {
        let _guard = lock();
        reset();
        let (a, b) = pair();
        send(b, message(b"still-here")).expect("send");
        assert_eq!(poll(a, false).expect("poll"), true);
        assert_eq!(poll(a, true).expect("poll take"), true);
        // take=true 也不得丢弃消息。
        assert_eq!(peek(a).expect("peek").data(), b"still-here");
        assert_eq!(poll(b, true).expect("poll empty"), false);
        let sequence = peek(a).expect("peek").sequence;
        commit(a, sequence).expect("commit");
        assert_eq!(poll(a, true).expect("poll after commit"), false);
        drain(a, b);
    }

    /// M6：队列满时消息所有权被退回，其对象引用由 `send` 在锁外释放。
    #[test]
    fn would_block_releases_the_rejected_message_references() {
        let _guard = lock();
        reset();
        let (a, b) = pair();
        for index in 0..CHANNEL_DEPTH {
            send(b, message(&[index as u8])).expect("fill queue");
        }
        let payload = timer::create().expect("timer slot");
        let object = object::create_with_payload(ObjectKind::Timer, payload).expect("timer object");
        assert_eq!(timer::count(), 1);
        let overflow = message(b"overflow")
            .with_handle(object, crate::object::Rights::WAIT)
            .expect("attach handle");
        assert_eq!(send(b, overflow), Err(IpcError::WouldBlock));
        // 被退回消息携带的引用已被释放 ⇒ Timer 槽归零销毁；队列内容不变。
        assert_eq!(timer::count(), 0);
        assert_eq!(peek(a).expect("peek").data(), &[0]);
        drain(a, b);
    }

    /// M3：消息携带已失效的对象编号必须在入队前被拒绝。
    #[test]
    fn dead_object_ids_are_rejected_before_queueing() {
        let _guard = lock();
        reset();
        let (a, b) = pair();
        let payload = timer::create().expect("timer slot");
        let dead = object::create_with_payload(ObjectKind::Timer, payload).expect("timer object");
        object::release_object(dead).expect("release last reference");
        assert_eq!(timer::count(), 0);
        let bad = message(b"dead-handle")
            .with_handle(dead, crate::object::Rights::WAIT)
            .expect("attach handle");
        assert_eq!(
            send(b, bad),
            Err(IpcError::Object(object::ObjectError::InvalidObject))
        );
        assert_eq!(peek(a), Err(IpcError::WouldBlock));
        drain(a, b);
    }

    /// 构造一个可转移引用的对象（引用计数 1），用于验证失败路径是否释放。
    fn transferable() -> ObjectId {
        let payload = timer::create().expect("timer slot");
        object::create_with_payload(ObjectKind::Timer, payload).expect("timer object")
    }

    /// M8：`send` 的**所有**早退路径（InvalidObject/PeerClosed/校验失败）都必须
    /// 释放消息携带的对象引用，而不是只处理 `WouldBlock`。
    #[test]
    fn early_send_failures_release_the_message_references() {
        let _guard = lock();
        reset();
        let (a, b) = pair();

        // InvalidObject：发送端点不是任何 Channel 端点。
        let first = transferable();
        assert_eq!(
            send(
                ObjectId::MAX,
                message(b"bad-target")
                    .with_handle(first, crate::object::Rights::WAIT)
                    .unwrap()
            ),
            Err(IpcError::Object(object::ObjectError::InvalidObject))
        );
        assert_eq!(timer::count(), 0);

        // PeerClosed：对端关闭后再从本端发送，消息永远无人接收。
        let second = transferable();
        assert!(destroy_endpoint(b).expect("close b"));
        assert_eq!(
            send(
                a,
                message(b"closed")
                    .with_handle(second, crate::object::Rights::WAIT)
                    .unwrap()
            ),
            Err(IpcError::PeerClosed)
        );
        assert_eq!(timer::count(), 0);

        // 校验失败（rights 为空）同样释放。
        let third = transferable();
        let mut bad = message(b"bad-rights");
        bad.handle_count = 1;
        bad.objects[0] = third;
        assert_eq!(
            send(a, bad),
            Err(IpcError::Object(object::ObjectError::InvalidRights))
        );
        assert_eq!(timer::count(), 0);

        drain(a, b);
    }

    /// M7：成功 send 后在表锁之外唤醒关心**接收端**（对端）的订阅。
    #[test]
    fn successful_send_wakes_a_channel_subscription() {
        use crate::ipc::subscription;

        let _guard = lock();
        reset();
        subscription::reset();
        let (a, b) = pair();
        let watched = object::create_with_payload(ObjectKind::EventSubscription, 0).unwrap();
        subscription::create(watched).unwrap();
        subscription::register(watched, b, subscription::MODE_LEVEL, 0).unwrap();

        assert_eq!(
            crate::ipc::poll_waitable_keyed(watched, 0, false),
            Ok(false)
        );
        // 从 a 发送 ⇒ 消息进入 b 的入站队列 ⇒ 关心 b 的订阅被唤醒。
        send(a, message(b"ready")).expect("send");
        assert_eq!(crate::ipc::poll_waitable_keyed(watched, 0, false), Ok(true));

        subscription::destroy(watched).unwrap();
        let _ = crate::ipc::release_subscription_pending();
        let _ = object::release_object(watched);
        drain(a, b);
    }

    /// Lead 要求的方向/容量回归：同一方向反复 `send(a)` + `peek`/`commit(b)` 5 次后
    /// 队列不得退化（仍能再入 4 条、第 5 条 `WouldBlock`），drain 后为空；顺带验证
    /// 抽空后源侧通知确实重新武装了 ET 边沿（下一次 send 仍可 WAIT/read）。
    #[test]
    fn repeated_send_and_commit_never_degrades_the_queue() {
        use crate::ipc::subscription;

        let _guard = lock();
        reset();
        subscription::reset();
        let (a, b) = pair();
        let watched = object::create_with_payload(ObjectKind::EventSubscription, 0).unwrap();
        subscription::create(watched).unwrap();
        subscription::register(watched, b, subscription::MODE_EDGE, 0).unwrap();
        let mut events = [subscription::SubscriptionEvent {
            object_key: 0,
            mode: 0,
        }; subscription::MAX_EVENTS];

        // 同一方向 5 次完整的 send → peek → commit 往返。
        for round in 0..5u8 {
            let sequence = send(a, message(&[round])).expect("round-trip send");
            let received = peek(b).expect("peer sees the round-trip message");
            assert_eq!(received.sequence, sequence);
            assert_eq!(received.data(), &[round]);
            commit(b, sequence).expect("round-trip commit");
            assert_eq!(
                poll(b, false),
                Ok(false),
                "queue must be empty after commit"
            );
        }

        // 抽空 → 再就绪的 ET 闭环：先消费一条边沿（observed=true），commit 抽空必须
        // 重新武装，否则下一次 send 既不唤醒也不上报。
        let sequence = send(a, message(b"edge")).expect("edge send");
        assert_eq!(subscription::read(watched, &mut events).unwrap(), 1);
        commit(b, sequence).expect("edge commit");
        send(a, message(b"rearmed")).expect("rearmed send");
        assert_eq!(crate::ipc::poll_waitable_keyed(watched, 0, false), Ok(true));
        assert_eq!(subscription::read(watched, &mut events).unwrap(), 1);
        let sequence = peek(b).expect("peek rearmed").sequence;
        commit(b, sequence).expect("commit rearmed");

        // 仍然可以填满：4 条入队、第 5 条 WouldBlock。
        let mut sequences = [0u64; 4];
        for (index, byte) in [10u8, 11, 12, 13].iter().enumerate() {
            sequences[index] = send(a, message(&[*byte])).expect("fill the peer queue");
        }
        assert_eq!(send(a, message(b"overflow")), Err(IpcError::WouldBlock));
        for (index, sequence) in sequences.iter().enumerate() {
            let received = peek(b).expect("peek during drain");
            assert_eq!(received.data(), &[10 + index as u8]);
            commit(b, *sequence).expect("drain commit");
        }
        assert_eq!(peek(b), Err(IpcError::WouldBlock));
        assert_eq!(poll(b, false), Ok(false));

        subscription::destroy(watched).unwrap();
        let _ = crate::ipc::release_subscription_pending();
        let _ = object::release_object(watched);
        drain(a, b);
    }

    /// 只读诊断接口必须准确：空 ⇒ 0，入队/commit 与 peek 看到的队列一致。
    #[test]
    fn queued_len_tracks_push_and_commit() {
        let _guard = lock();
        reset();
        let (a, b) = pair();
        assert_eq!(queued_len(b), Some(0));
        let first = send(a, message(b"one")).expect("send one");
        let second = send(a, message(b"two")).expect("send two");
        assert_eq!(queued_len(b), Some(2));
        // 发送端自己的入站队列不受影响（方向：本端发送 ⇒ 对端队列）。
        assert_eq!(queued_len(a), Some(0));
        commit(b, first).expect("commit one");
        assert_eq!(queued_len(b), Some(1));
        assert_eq!(peek(b).expect("peek two").sequence, second);
        commit(b, second).expect("commit two");
        assert_eq!(queued_len(b), Some(0));
        assert_eq!(queued_len(ObjectId::MAX), None);
        drain(a, b);
    }
}
