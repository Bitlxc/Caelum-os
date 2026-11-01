//! SharedMemory 内核对象（M6a2，B1）。
//!
//! 一个 `SharedMemory` 对象持有一小段**物理帧**（1..=4 页，按请求长度向上取整），
//! 由对象层用 `ObjectKind::SharedMemory` 的对象编号标识。本模块只负责帧的分配、
//! 查询与释放，不做映射：
//!
//! - 映射（`vmobj` 的 `shm_map`）用 [`frames`] 给出的物理地址建立用户映射，并在
//!   映射生命周期内持有该 `SharedMemory` 对象的一个引用；
//! - 因此 [`destroy`]（对象最后一个引用归零时由销毁钩子调用）一定发生在所有映射
//!   都已解除之后：owner 关闭句柄而映射仍活着时，物理帧不会被提前回收；
//! - 本模块不经过页缓存、没有脏页/回写语义：共享内存是裸帧，数据一致性只由映射
//!   方自己保证。
//!
//! 固定容量（无堆）：同时最多 [`MAX_SHM`] 个对象，每个对象最多 [`MAX_SHM_PAGES`]
//! 页。表访问经 [`IrqCell`]，目标平台关中断；宿主测试由 `object::test_lock` 串行化，
//! 并用假的帧池（`frame_seam`）替代 PMM —— 宿主上全局 PMM 未初始化，记账逻辑仍可
//! 完整覆盖，PMM 自身的语义由 `mm::pmm` 的测试覆盖。

use core::slice;

use crate::object::{self, ObjectId, ObjectKind};

use super::IrqCell;

/// 固定容量：同时存在的 `SharedMemory` 对象上限。
pub const MAX_SHM: usize = 2;

/// 页大小（与 PMM、VFS 页缓存一致）。
pub const SHM_PAGE_SIZE: u64 = 4096;

/// 单个对象的最大页数。
pub const MAX_SHM_PAGES: usize = 4;

/// 单个对象的最大字节数。
pub const MAX_SHM_BYTES: u64 = SHM_PAGE_SIZE * MAX_SHM_PAGES as u64;

/// 共享内存操作的错误；`as_str` 供 syscall 层诊断与 ABI 错误码映射使用。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ShmError {
    /// 固定表已满（已有 [`MAX_SHM`] 个对象）。
    TableFull,
    /// 长度非法：0 或超过 [`MAX_SHM_BYTES`]。
    BadLength,
    /// 对象编号不是存活的 `SharedMemory`（已销毁或编号无效）。
    NoSuchObject,
    /// 对象存活但不是 `SharedMemory`。
    WrongKind,
    /// 物理帧分配失败（内存不足），不会占用表槽。
    NoMemory,
}

impl ShmError {
    /// 稳定的诊断字符串。
    pub const fn as_str(self) -> &'static str {
        match self {
            ShmError::TableFull => "shm-table-full",
            ShmError::BadLength => "shm-bad-length",
            ShmError::NoSuchObject => "shm-no-such-object",
            ShmError::WrongKind => "shm-wrong-kind",
            ShmError::NoMemory => "shm-no-memory",
        }
    }
}

/// 未分配帧的哨兵值（PMM 不会返回物理地址 0）。
const NO_FRAME: u64 = 0;

/// 一个 `SharedMemory` 对象占用的帧表项。
#[derive(Clone, Copy)]
struct ShmSlot {
    /// 槽是否在用。
    live: bool,
    /// 对应的对象编号。
    object: ObjectId,
    /// 实际页数（1..=[`MAX_SHM_PAGES`]）。
    pages: usize,
    /// 页对齐的物理帧地址，前 `pages` 项有效。
    frames: [u64; MAX_SHM_PAGES],
}

/// 空闲槽的初值。
const EMPTY_SLOT: ShmSlot = ShmSlot {
    live: false,
    object: ObjectId::MAX,
    pages: 0,
    frames: [NO_FRAME; MAX_SHM_PAGES],
};

/// 共享内存固定表。
struct ShmTable {
    slots: [ShmSlot; MAX_SHM],
}

impl ShmTable {
    const fn new() -> Self {
        Self {
            slots: [EMPTY_SLOT; MAX_SHM],
        }
    }

    /// 存活对象数。
    fn count(&self) -> usize {
        self.slots.iter().filter(|slot| slot.live).count()
    }

    /// 存活对象占用的总帧数。
    fn frames(&self) -> usize {
        self.slots
            .iter()
            .filter(|slot| slot.live)
            .map(|slot| slot.pages)
            .sum()
    }

    /// 按对象编号找槽下标。
    fn slot_of(&self, object: ObjectId) -> Option<usize> {
        self.slots
            .iter()
            .position(|slot| slot.live && slot.object == object)
    }
}

static SHM: IrqCell<ShmTable> = IrqCell::new(ShmTable::new());

/// 分配一个页对齐物理帧（生产环境走 PMM，宿主测试走假帧池）。
#[cfg(not(test))]
fn alloc_phys() -> Option<u64> {
    crate::mm::pmm::alloc_frame().ok()
}

/// 分配一个页对齐物理帧（宿主测试：见 [`frame_seam`]）。
#[cfg(test)]
fn alloc_phys() -> Option<u64> {
    frame_seam::alloc()
}

/// 释放一个物理帧；返回帧是否被真正回收（幂等，重复释放返回 false）。
#[cfg(not(test))]
fn free_phys(phys: u64) -> bool {
    crate::mm::pmm::free_frame(phys)
}

/// 释放一个物理帧（宿主测试：只记账，见 [`frame_seam`]）。
#[cfg(test)]
fn free_phys(phys: u64) -> bool {
    frame_seam::free(phys)
}

/// 请求长度换算为页数：0 或超过上限一律 `BadLength`，否则向上取整。
pub fn pages_for(length: u64) -> Result<usize, ShmError> {
    if length == 0 || length > MAX_SHM_BYTES {
        return Err(ShmError::BadLength);
    }
    Ok(length.div_ceil(SHM_PAGE_SIZE) as usize)
}

/// 为一个已经创建的 `SharedMemory` 对象分配帧。
///
/// `object` 必须是一个存活的 `SharedMemory` 对象（由调用者先用对象层创建，再把本
/// 函数返回的页数交给映射层）。返回实际页数；失败时不占用表槽，也不会泄漏帧。
pub fn create(object: ObjectId, length: u64) -> Result<usize, ShmError> {
    let page_count = pages_for(length)?;
    match object::object_kind(object) {
        None => return Err(ShmError::NoSuchObject),
        Some(kind) if kind != ObjectKind::SharedMemory => return Err(ShmError::WrongKind),
        Some(_) => {}
    }

    // 同一对象重复创建是幂等的：直接返回已登记的页数，避免重复占槽或泄漏帧。
    if let Ok(existing) = pages(object) {
        return Ok(existing);
    }

    // 占槽与逐帧分配在同一个关中断区间内完成，避免失败路径留下半登记状态。
    let mut allocated = [NO_FRAME; MAX_SHM_PAGES];
    let result = SHM.with(|table| {
        let Some(slot) = table.slots.iter().position(|slot| !slot.live) else {
            return Err(ShmError::TableFull);
        };
        for page in 0..page_count {
            match alloc_phys() {
                Some(phys) => allocated[page] = phys,
                None => return Err(ShmError::NoMemory),
            }
        }
        table.slots[slot] = ShmSlot {
            live: true,
            object,
            pages: page_count,
            frames: allocated,
        };
        Ok(page_count)
    });

    if result.is_err() {
        // 关中断区间外回滚已分配的帧（PMM 自身的加锁与钩子都在区间外完成）。
        for frame in allocated.iter().take(page_count) {
            if *frame != NO_FRAME {
                let _ = free_phys(*frame);
            }
        }
    }
    result
}

/// 查询对象拥有的页数。
pub fn pages(object: ObjectId) -> Result<usize, ShmError> {
    SHM.with(|table| {
        let slot = table.slot_of(object).ok_or(ShmError::NoSuchObject)?;
        Ok(table.slots[slot].pages)
    })
}

/// 查询对象拥有的物理帧（只读）。
///
/// 返回的切片在对象存续期间稳定不变；调用方必须持有该对象的一个引用（映射层正是
/// 这样做的），否则对象被销毁后切片会悬空。
pub fn frames(object: ObjectId) -> Result<&'static [u64], ShmError> {
    SHM.with(|table| {
        let slot = table.slot_of(object).ok_or(ShmError::NoSuchObject)?;
        let entry = &table.slots[slot];
        // SAFETY: `entry.frames` 位于静态表内，地址在整个内核生命周期内稳定；切片长度
        // 受 `entry.pages <= MAX_SHM_PAGES` 约束，且在对象销毁前不允许改动这些帧。
        Ok(unsafe { slice::from_raw_parts(entry.frames.as_ptr(), entry.pages) })
    })
}

/// 销毁对象的帧登记并逐帧释放，返回释放的帧数。
///
/// 幂等：对象没有登记时返回 0。可以在对象销毁钩子内调用（不触碰对象表），但句柄
/// 关闭路径必须在对象最后一个引用归零后才会走到这里。
pub fn destroy(object: ObjectId) -> usize {
    let mut frames = [NO_FRAME; MAX_SHM_PAGES];
    let mut pages = 0;
    SHM.with(|table| {
        let Some(slot) = table.slot_of(object) else {
            return;
        };
        frames = table.slots[slot].frames;
        pages = table.slots[slot].pages;
        table.slots[slot] = EMPTY_SLOT;
    });

    let mut freed = 0;
    for frame in frames.iter().take(pages) {
        if free_phys(*frame) {
            freed += 1;
        }
    }
    freed
}

/// 对象销毁钩子入口（在对象层关中断区间内调用）。
///
/// 只释放本模块持有的帧，不回调对象表 —— 这样不会重入对象表的 `IrqCell`。
pub fn on_destroy(object: ObjectId) {
    let _ = destroy(object);
}

/// 当前登记的 `SharedMemory` 对象数。
pub fn live_objects() -> usize {
    SHM.with(|table| table.count())
}

/// 当前登记的物理帧总数。
pub fn live_frames() -> usize {
    SHM.with(|table| table.frames())
}

/// 清空表（仅供宿主测试；正常路径由对象销毁钩子清槽）。
#[cfg(test)]
pub(crate) fn reset() {
    SHM.with(|table| *table = ShmTable::new());
    frame_seam::reset();
}

/// 宿主测试用的假帧池：全局 PMM 在 `cargo test` 里没有初始化，这里提供确定性帧。
#[cfg(test)]
mod frame_seam {
    use super::{IrqCell, SHM_PAGE_SIZE};

    /// 假帧基址（与真实 PMM 分配的地址不重叠）。
    pub(super) const TEST_FRAME_BASE: u64 = 0x2000_0000;
    /// 假帧容量：足够覆盖 [`super::MAX_SHM`] × [`super::MAX_SHM_PAGES`] 再留余量。
    pub(super) const TEST_FRAME_CAP: usize = 16;

    struct Pool {
        next: usize,
        freed: usize,
        double_free: usize,
        allocated: [bool; TEST_FRAME_CAP],
    }

    static POOL: IrqCell<Pool> = IrqCell::new(Pool {
        next: 0,
        freed: 0,
        double_free: 0,
        allocated: [false; TEST_FRAME_CAP],
    });

    pub(super) fn alloc() -> Option<u64> {
        POOL.with(|pool| {
            if pool.next >= TEST_FRAME_CAP {
                return None;
            }
            let index = pool.next;
            pool.next += 1;
            pool.allocated[index] = true;
            Some(TEST_FRAME_BASE + index as u64 * SHM_PAGE_SIZE)
        })
    }

    pub(super) fn free(phys: u64) -> bool {
        POOL.with(|pool| {
            let offset = phys.wrapping_sub(TEST_FRAME_BASE);
            if phys < TEST_FRAME_BASE || offset % SHM_PAGE_SIZE != 0 {
                return false;
            }
            let index = (offset / SHM_PAGE_SIZE) as usize;
            if index >= TEST_FRAME_CAP || !pool.allocated[index] {
                pool.double_free += 1;
                return false;
            }
            pool.allocated[index] = false;
            pool.freed += 1;
            true
        })
    }

    pub(super) fn reset() {
        POOL.with(|pool| {
            pool.next = 0;
            pool.freed = 0;
            pool.double_free = 0;
            pool.allocated = [false; TEST_FRAME_CAP];
        })
    }

    /// 已成功释放的帧数。
    pub(super) fn freed() -> usize {
        POOL.with(|pool| pool.freed)
    }

    /// 重复释放/非法释放的尝试次数（应为 0）。
    pub(super) fn double_free() -> usize {
        POOL.with(|pool| pool.double_free)
    }

    /// 把假帧池耗尽，用来验证 `NoMemory` 回滚路径。
    pub(super) fn exhaust() {
        POOL.with(|pool| pool.next = TEST_FRAME_CAP);
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

    /// 建立一个干净的起点：清空本模块表与对象层钩子。
    fn prepare() {
        object::reset_destroy_hooks();
        reset();
    }

    fn new_shm_object() -> ObjectId {
        // `create_object` 是 M4 兼容路径（引用计数 0）；这里必须用带负载版本拿到
        // 引用计数 1 的对象，否则 release 会因 refs==0 直接失败、对象永不销毁。
        object::create_with_payload(ObjectKind::SharedMemory, 0).expect("shared-memory object")
    }

    #[test]
    fn bad_lengths_are_rejected_before_anything_is_allocated() {
        let _guard = lock();
        prepare();
        let object = new_shm_object();
        assert_eq!(create(object, 0), Err(ShmError::BadLength));
        assert_eq!(create(object, MAX_SHM_BYTES + 1), Err(ShmError::BadLength));
        assert_eq!(live_objects(), 0);
        assert_eq!(live_frames(), 0);
        assert_eq!(frame_seam::freed(), 0);
        let _ = object::release_object(object);
        prepare();
    }

    #[test]
    fn create_rounds_up_and_reports_page_count() {
        let _guard = lock();
        prepare();
        let object = new_shm_object();
        assert_eq!(create(object, 1), Ok(1));
        assert_eq!(pages(object), Ok(1));
        // 同一个对象重复创建是幂等的：返回已登记页数，不叠加、不泄漏帧。
        assert_eq!(create(object, MAX_SHM_BYTES), Ok(1));
        assert_eq!(pages(object), Ok(1));
        assert_eq!(live_frames(), 1);
        let _ = destroy(object);
        let _ = object::release_object(object);
        prepare();

        for (length, expected) in [(4096u64, 1usize), (4097, 2), (8192, 2), (16384, 4)] {
            let object = new_shm_object();
            assert_eq!(create(object, length), Ok(expected));
            assert_eq!(live_frames(), expected);
            let _ = destroy(object);
            let _ = object::release_object(object);
        }
        prepare();
    }

    #[test]
    fn capacity_is_bounded_and_errors_do_not_leak_slots() {
        let _guard = lock();
        prepare();
        let first = new_shm_object();
        let second = new_shm_object();
        assert_eq!(create(first, 4096), Ok(1));
        assert_eq!(create(second, 4096), Ok(1));

        let third = new_shm_object();
        assert_eq!(create(third, 4096), Err(ShmError::TableFull));
        assert_eq!(live_objects(), 2);
        assert_eq!(live_frames(), 2);

        // 表满时错误路径不能分配任何帧。
        assert_eq!(frame_seam::freed(), 0);

        let _ = destroy(first);
        assert_eq!(live_objects(), 1);
        // 腾出槽位后可以继续创建。
        assert_eq!(create(third, 8192), Ok(2));

        for object in [second, third] {
            let _ = destroy(object);
            let _ = object::release_object(object);
        }
        prepare();
    }

    #[test]
    fn frames_are_aligned_and_distinct() {
        let _guard = lock();
        prepare();
        let object = new_shm_object();
        assert_eq!(create(object, MAX_SHM_BYTES), Ok(MAX_SHM_PAGES));
        let frames = frames(object).expect("frames");
        assert_eq!(frames.len(), MAX_SHM_PAGES);
        for (index, frame) in frames.iter().enumerate() {
            assert_eq!(*frame % SHM_PAGE_SIZE, 0);
            for other in frames.iter().skip(index + 1) {
                assert_ne!(*frame, *other);
            }
        }
        let _ = destroy(object);
        let _ = object::release_object(object);
        prepare();
    }

    #[test]
    fn destroy_frees_each_frame_once_and_is_idempotent() {
        let _guard = lock();
        prepare();
        let object = new_shm_object();
        assert_eq!(create(object, 8192), Ok(2));
        assert_eq!(live_frames(), 2);

        assert_eq!(destroy(object), 2);
        assert_eq!(live_objects(), 0);
        assert_eq!(live_frames(), 0);
        assert_eq!(frame_seam::freed(), 2);
        assert_eq!(frame_seam::double_free(), 0);

        // 第二次销毁不重复释放。
        assert_eq!(destroy(object), 0);
        assert_eq!(frame_seam::freed(), 2);
        assert_eq!(frame_seam::double_free(), 0);

        let _ = object::release_object(object);
        prepare();
    }

    #[test]
    fn last_reference_release_fires_the_destroy_hook() {
        let _guard = lock();
        prepare();
        object::register_destroy_hook_with_object(
            ObjectKind::SharedMemory,
            |kind, _payload, object| {
                if kind == ObjectKind::SharedMemory {
                    on_destroy(object);
                }
            },
        )
        .expect("hook");

        let object = new_shm_object();
        assert_eq!(create(object, 4096), Ok(1));
        assert_eq!(live_frames(), 1);

        // 增加一个引用（模拟映射层持有对象），关闭第一个引用后帧必须还在。
        assert!(object::acquire_object(object).is_ok());
        assert!(object::release_object(object).is_ok());
        assert_eq!(live_frames(), 1);
        assert_eq!(live_objects(), 1);
        assert_eq!(frame_seam::freed(), 0);

        // 最后一个引用归零 → 对象层调用钩子 → 帧被释放。
        assert!(object::release_object(object).is_ok());
        assert_eq!(live_frames(), 0);
        assert_eq!(live_objects(), 0);
        assert_eq!(frame_seam::freed(), 1);
        assert_eq!(frame_seam::double_free(), 0);
        prepare();
    }

    #[test]
    fn wrong_kind_and_dead_objects_are_rejected() {
        let _guard = lock();
        prepare();
        let event = object::create_with_payload(ObjectKind::Event, 0).expect("event");
        assert_eq!(create(event, 4096), Err(ShmError::WrongKind));
        let _ = object::release_object(event);

        let object = new_shm_object();
        let _ = object::release_object(object);
        assert_eq!(create(object, 4096), Err(ShmError::NoSuchObject));
        assert_eq!(frames(object), Err(ShmError::NoSuchObject));
        assert_eq!(pages(object), Err(ShmError::NoSuchObject));
        prepare();
    }

    #[test]
    fn allocation_failure_rolls_back_without_occupying_a_slot() {
        let _guard = lock();
        prepare();
        let object = new_shm_object();
        frame_seam::exhaust();
        assert_eq!(create(object, MAX_SHM_BYTES), Err(ShmError::NoMemory));
        assert_eq!(live_objects(), 0);
        assert_eq!(live_frames(), 0);
        let _ = object::release_object(object);

        // 恢复帧池后同一个槽仍然可用。
        frame_seam::reset();
        let object = new_shm_object();
        assert_eq!(create(object, 4096), Ok(1));
        assert_eq!(live_objects(), 1);
        let _ = destroy(object);
        let _ = object::release_object(object);
        prepare();
    }
}
