//! 基础显示共享缓冲对象（M6c，B1）。
//!
//! 一个 `Display` 对象持有一块**固定 64 帧 × 4 KiB = 256 KiB** 的 shadow 缓冲。缓冲
//! 由对象层用 `ObjectKind::Display` 的对象编号标识；本模块负责帧的分配、清零、
//! 映射记账、present 前置检查与销毁回收，真正的显示设备（GOP/扫描输出）由
//! `crate::display` 拥有：
//!
//! - [`map_pages`] 把 64 个帧物理地址抄给调用者（`vmobj` 用
//!   `addrspace::map_user_borrowed` 逐页映射到用户地址空间），并 `map_count += 1`；
//! - [`unmap`] 对称地 `map_count -= 1`，只在映射全部解除后才允许 [`destroy`] 回收帧；
//! - [`present`] 要求当前至少有一个映射，然后调用 `crate::display::present`；
//! - [`destroy`]（对象最后一个引用归零时由对象销毁钩子调用）逐帧 `pmm::free_frame`。
//!
//! 固定容量（无堆）：同一时刻最多 [`MAX_DISPLAY_OBJECTS`] 个对象。表访问经
//! [`IrqCell`]（关本 CPU 中断 + 跨 CPU 自旋），闭包内只改本表；分配与清零在
//! 锁外完成，避免长时间关中断：先用 `live && !ready` 预留槽位，再分配 64 帧并
//! 清零，最后在锁内提交（任一失败都回滚，不留半登记槽位、不泄漏帧）。
//!
//! 宿主测试用 `object::test_lock` 串行化全局表，并用假帧池替代 PMM——宿主上全局
//! PMM 未初始化，而记账逻辑仍可被完整覆盖（PMM 语义由 `mm::pmm` 的测试覆盖）。

use crate::display::{self, DisplayInfo};
#[cfg(not(test))]
use crate::mm::{pmm, vm};
use crate::object::{self, ObjectId, ObjectKind};

use super::IrqCell;

/// shadow 缓冲的帧数（固定 64 帧 = 256 KiB）。
pub const DISPLAY_FRAMES: usize = 64;

/// 一帧的字节数（与 PMM、页缓存一致）。
pub const FRAME_SIZE: u64 = 4096;

/// shadow 缓冲总字节数（64 × 4 KiB = 262144 B）。
pub const DISPLAY_BYTES: u64 = DISPLAY_FRAMES as u64 * FRAME_SIZE;

/// 同时存在的 `Display` 对象上限（M6c 只有单显示）。
pub const MAX_DISPLAY_OBJECTS: usize = 1;

/// 显示对象操作的错误；`as_str` 供 syscall 层诊断与 ABI 错误码映射使用。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum DisplayError {
    /// 已经有另一个存活的显示对象（[`MAX_DISPLAY_OBJECTS`] = 1）。
    TableFull,
    /// 对象编号不是存活对象（已销毁或编号无效）。
    NoSuchObject,
    /// 对象存活但不是显示对象。
    WrongKind,
    /// 物理帧分配失败（内存不足）；不占用槽位、不泄漏帧。
    NoMemory,
    /// 当前没有映射（`unmap`/`present` 的前置条件不满足）。
    NotMapped,
    /// 参数或状态不可能成立（防御性分支，正常路径不会返回）。
    BadBuffer,
}

impl DisplayError {
    /// 稳定的诊断字符串。
    pub const fn as_str(self) -> &'static str {
        match self {
            DisplayError::TableFull => "display-table-full",
            DisplayError::NoSuchObject => "display-no-such-object",
            DisplayError::WrongKind => "display-wrong-kind",
            DisplayError::NoMemory => "display-no-memory",
            DisplayError::NotMapped => "display-not-mapped",
            DisplayError::BadBuffer => "display-bad-buffer",
        }
    }
}

/// 未分配帧的哨兵值（PMM 不会返回物理地址 0）。
const NO_FRAME: u64 = 0;

/// 一个 `Display` 对象的帧表项。
#[derive(Clone, Copy)]
struct DisplaySlot {
    /// 槽是否被占用（含“正在分配”状态）。
    live: bool,
    /// 64 帧是否都已分配并清零（提交完成）。
    ready: bool,
    /// 对应的对象编号。
    object: ObjectId,
    /// 页对齐的物理帧地址。
    frames: [u64; DISPLAY_FRAMES],
    /// 当前映射次数（每次 [`map_pages`] +1，[`unmap`] -1）。
    map_count: u32,
}

/// 空闲槽的初值。
const EMPTY_SLOT: DisplaySlot = DisplaySlot {
    live: false,
    ready: false,
    object: ObjectId::MAX,
    frames: [NO_FRAME; DISPLAY_FRAMES],
    map_count: 0,
};

/// 显示固定表。
struct DisplayTable {
    slots: [DisplaySlot; MAX_DISPLAY_OBJECTS],
}

impl DisplayTable {
    const fn new() -> Self {
        Self {
            slots: [EMPTY_SLOT; MAX_DISPLAY_OBJECTS],
        }
    }

    /// 存活（含正在分配）对象数。
    fn count(&self) -> usize {
        self.slots.iter().filter(|slot| slot.live).count()
    }

    /// 已提交对象的帧总数（正在分配的槽位不计）。
    fn frames(&self) -> usize {
        self.slots
            .iter()
            .filter(|slot| slot.live && slot.ready)
            .map(|slot| {
                slot.frames
                    .iter()
                    .filter(|frame| **frame != NO_FRAME)
                    .count()
            })
            .sum()
    }

    /// 按对象编号找槽下标。
    fn slot_of(&self, object: ObjectId) -> Option<usize> {
        self.slots
            .iter()
            .position(|slot| slot.live && slot.object == object)
    }
}

static DISPLAY: IrqCell<DisplayTable> = IrqCell::new(DisplayTable::new());

/// 分配一个页对齐物理帧（生产环境走 PMM，宿主测试走假帧池）。
#[cfg(not(test))]
fn alloc_phys() -> Option<u64> {
    pmm::alloc_frame().ok()
}

/// 分配一个页对齐物理帧（宿主测试：见 [`frame_seam`]）。
#[cfg(test)]
fn alloc_phys() -> Option<u64> {
    frame_seam::alloc()
}

/// 释放一个物理帧；返回帧是否被真正回收（幂等，重复释放返回 false）。
#[cfg(not(test))]
fn free_phys(phys: u64) -> bool {
    pmm::free_frame(phys)
}

/// 释放一个物理帧（宿主测试：只记账，见 [`frame_seam`]）。
#[cfg(test)]
fn free_phys(phys: u64) -> bool {
    frame_seam::free(phys)
}

/// 把一个新分配的帧清零，保证用户态不会读到上一任主人的数据。
#[cfg(not(test))]
fn zero_frame(phys: u64) {
    // SAFETY: `phys` 是 PMM 刚分配、尚未交给任何其它路径的常规帧（< 1 GiB），
    // 通过内核直接映射区访问；本函数独占该帧，直到 [`map_pages`] 或 [`destroy`]。
    unsafe {
        core::ptr::write_bytes(vm::phys_to_virt(phys) as *mut u8, 0, FRAME_SIZE as usize);
    }
}

/// 宿主测试没有直接映射，也不真的访问帧内容。
#[cfg(test)]
fn zero_frame(_phys: u64) {}

/// 显示设备几何（`crate::display` 拥有；显示未初始化时返回
/// [`DisplayInfo::EMPTY`]，root 在 M6c 启动时保证已初始化）。
fn device_info() -> DisplayInfo {
    display::info_or_empty()
}

/// 把 shadow 帧交给显示设备扫描输出（`crate::display` 拥有）。
///
/// 设备层的错误（未初始化、帧参数非法）统一映射为 [`DisplayError::BadBuffer`]：
/// 对调用者而言这总是"当前不能呈现"的同一类失败。
#[cfg(not(test))]
fn present_frames(frames: &[u64; DISPLAY_FRAMES]) -> Result<(), DisplayError> {
    display::present(frames).map_err(|_| DisplayError::BadBuffer)
}

/// 宿主测试不碰真实显示设备，只记录 present 被调用了几次。
#[cfg(test)]
fn present_frames(_frames: &[u64; DISPLAY_FRAMES]) -> Result<(), DisplayError> {
    present_seam::record();
    Ok(())
}

/// 为一个已经创建的 `Display` 对象分配并清零 64 帧。
///
/// `object` 必须是一个存活的 `Display` 对象。重复创建同一个对象是幂等的（返回
/// `Ok`）；已有别的存活对象时返回 [`DisplayError::TableFull`]。失败路径完整回滚：
/// 不占用槽位、不泄漏帧。
pub fn create(object: ObjectId) -> Result<(), DisplayError> {
    match object::object_kind(object) {
        None => return Err(DisplayError::NoSuchObject),
        Some(kind) if kind != ObjectKind::Display => return Err(DisplayError::WrongKind),
        Some(_) => {}
    }

    // 阶段 1（持锁）：预留槽位。
    //
    // `Ok(true)` = 这个对象已经完整创建（幂等返回，绝不能再去分配帧）；
    // `Ok(false)` = 槽位刚刚预留，需要进入分配阶段；`Err` = 不能创建。
    let already_ready = DISPLAY.with(|table| {
        if let Some(slot) = table.slot_of(object) {
            if table.slots[slot].ready {
                return Ok(true);
            }
            return Err(DisplayError::TableFull);
        }
        let Some(slot) = table.slots.iter().position(|slot| !slot.live) else {
            return Err(DisplayError::TableFull);
        };
        table.slots[slot] = DisplaySlot {
            live: true,
            ready: false,
            object,
            frames: [NO_FRAME; DISPLAY_FRAMES],
            map_count: 0,
        };
        Ok(false)
    })?;
    if already_ready {
        return Ok(());
    }

    // 阶段 2（锁外）：分配并清零 64 帧；失败则回滚已分配帧并清掉预留槽位。
    let mut frames = [NO_FRAME; DISPLAY_FRAMES];
    for (index, frame) in frames.iter_mut().enumerate() {
        match alloc_phys() {
            Some(phys) => *frame = phys,
            None => {
                release_frames(&frames[..index]);
                clear_slot(object);
                return Err(DisplayError::NoMemory);
            }
        }
    }
    for frame in frames {
        zero_frame(frame);
    }

    // 阶段 3（持锁）：提交。槽位在预留后一直被本对象占用，这里必定还在。
    let committed = DISPLAY.with(|table| {
        if let Some(slot) = table.slot_of(object) {
            table.slots[slot].frames = frames;
            table.slots[slot].ready = true;
            Ok(())
        } else {
            Err(DisplayError::BadBuffer)
        }
    });
    if committed.is_err() {
        release_frames(&frames);
    }
    committed
}

/// 解除对象的帧登记并逐帧释放，返回释放的帧数。
///
/// 幂等：对象没有登记时返回 0。若当前仍有映射（`map_count > 0`）则拒绝释放并返回
/// 0——最后一个对象引用归零意味着所有映射都已解除，这个分支只是防御。
/// 可以在对象销毁钩子内调用（不回调对象表）。
pub fn destroy(object: ObjectId) -> usize {
    let frames = DISPLAY.with(|table| {
        let Some(slot) = table.slot_of(object) else {
            return [NO_FRAME; DISPLAY_FRAMES];
        };
        if !table.slots[slot].ready || table.slots[slot].map_count > 0 {
            return [NO_FRAME; DISPLAY_FRAMES];
        }
        let frames = table.slots[slot].frames;
        table.slots[slot] = EMPTY_SLOT;
        frames
    });
    release_frames(&frames)
}

/// 对象销毁钩子入口（在对象层销毁钩子内调用，不回调对象表）。
pub fn on_destroy(object: ObjectId) {
    let _ = destroy(object);
}

/// 把 64 个 shadow 帧交给调用者映射，并登记一次映射。
///
/// 调用者必须已经持有该对象的一个引用；失败（未创建/已销毁/正在分配）不修改输出
/// 数组、不改变映射计数。
pub fn map_pages(
    object: ObjectId,
    frames: &mut [u64; DISPLAY_FRAMES],
) -> Result<DisplayInfo, DisplayError> {
    DISPLAY.with(|table| {
        let Some(slot) = table.slot_of(object) else {
            return Err(DisplayError::NoSuchObject);
        };
        let entry = &mut table.slots[slot];
        if !entry.ready {
            return Err(DisplayError::BadBuffer);
        }
        let Some(next) = entry.map_count.checked_add(1) else {
            return Err(DisplayError::BadBuffer);
        };
        *frames = entry.frames;
        entry.map_count = next;
        Ok(device_info())
    })
}

/// 登记一次映射解除（与 [`map_pages`] 配对）。没有映射时返回
/// [`DisplayError::NotMapped`]，计数不会下溢。
pub fn unmap(object: ObjectId) -> Result<(), DisplayError> {
    DISPLAY.with(|table| {
        let Some(slot) = table.slot_of(object) else {
            return Err(DisplayError::NoSuchObject);
        };
        let entry = &mut table.slots[slot];
        if entry.map_count == 0 {
            return Err(DisplayError::NotMapped);
        }
        entry.map_count -= 1;
        Ok(())
    })
}

/// 当前映射次数（诊断与测试用）。
pub fn map_count(object: ObjectId) -> Option<u32> {
    DISPLAY.with(|table| {
        table
            .slot_of(object)
            .filter(|slot| table.slots[*slot].ready)
            .map(|slot| table.slots[slot].map_count)
    })
}

/// 把 shadow 缓冲提交给显示设备。
///
/// 要求至少存在一次映射（`map_count > 0`）：没有映射说明没有任何用户地址空间在看
/// 这块缓冲，present 没有意义。复制帧数组到局部变量后在锁外调用设备层，避免在
/// IPC 表锁内做 MMIO。调用者持有对象引用，因此帧不会在 present 期间被回收。
pub fn present(object: ObjectId) -> Result<(), DisplayError> {
    let frames = DISPLAY.with(|table| {
        let Some(slot) = table.slot_of(object) else {
            return Err(DisplayError::NoSuchObject);
        };
        let entry = &table.slots[slot];
        if !entry.ready {
            return Err(DisplayError::BadBuffer);
        }
        if entry.map_count == 0 {
            return Err(DisplayError::NotMapped);
        }
        Ok(entry.frames)
    })?;
    present_frames(&frames)?;
    Ok(())
}

/// 查询显示设备几何（不改变状态）。
pub fn info(object: ObjectId) -> Result<DisplayInfo, DisplayError> {
    DISPLAY.with(|table| {
        let Some(slot) = table.slot_of(object) else {
            return Err(DisplayError::NoSuchObject);
        };
        if !table.slots[slot].ready {
            return Err(DisplayError::BadBuffer);
        }
        Ok(device_info())
    })
}

/// 当前存活的显示对象数。
pub fn live_objects() -> usize {
    DISPLAY.with(|table| table.count())
}

/// 当前登记的 shadow 帧总数（≤ [`DISPLAY_FRAMES`] × [`MAX_DISPLAY_OBJECTS`]）。
pub fn live_frames() -> usize {
    DISPLAY.with(|table| table.frames())
}

/// 清空表（仅供宿主测试；正常路径由对象销毁钩子清槽）。
#[cfg(test)]
pub(crate) fn reset() {
    DISPLAY.with(|table| *table = DisplayTable::new());
    frame_seam::reset();
}

/// 释放一组帧，返回成功回收的帧数。
fn release_frames(frames: &[u64]) -> usize {
    let mut freed = 0;
    for frame in frames.iter().copied() {
        if frame != NO_FRAME && free_phys(frame) {
            freed += 1;
        }
    }
    freed
}

/// 清掉指定对象的槽位（create 的失败回滚用）。
fn clear_slot(object: ObjectId) {
    DISPLAY.with(|table| {
        if let Some(slot) = table.slot_of(object) {
            // 只清“仍在分配”的槽位，绝不误清已提交的对象。
            if !table.slots[slot].ready {
                table.slots[slot] = EMPTY_SLOT;
            }
        }
    });
}

/// 宿主测试用的假帧池：全局 PMM 在 `cargo test` 里没有初始化，这里提供确定性帧。
#[cfg(test)]
mod frame_seam {
    use super::{FRAME_SIZE, IrqCell};

    /// 假帧基址（与真实 PMM、shm 假帧池的地址不重叠）。
    pub(super) const TEST_FRAME_BASE: u64 = 0x3000_0000;
    /// 假帧容量：覆盖一个显示对象的 64 帧再留余量，便于回滚测试。
    pub(super) const TEST_FRAME_CAP: usize = 96;

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
            Some(TEST_FRAME_BASE + index as u64 * FRAME_SIZE)
        })
    }

    pub(super) fn free(phys: u64) -> bool {
        POOL.with(|pool| {
            let offset = phys.wrapping_sub(TEST_FRAME_BASE);
            if phys < TEST_FRAME_BASE || offset % FRAME_SIZE != 0 {
                return false;
            }
            let index = (offset / FRAME_SIZE) as usize;
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

    /// 把假帧池剩余容量压到 `free` 帧，用来验证 `NoMemory` 回滚路径。
    pub(super) fn leave_room(free: usize) {
        POOL.with(|pool| pool.next = TEST_FRAME_CAP - free);
    }
}

/// 宿主测试用的 present 记录器（真实设备由 `crate::display` 拥有）。
#[cfg(test)]
mod present_seam {
    use super::IrqCell;

    static COUNT: IrqCell<u64> = IrqCell::new(0);

    pub(super) fn record() {
        COUNT.with(|count| *count += 1);
    }

    pub(super) fn count() -> u64 {
        COUNT.with(|count| *count)
    }

    pub(super) fn reset() {
        COUNT.with(|count| *count = 0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::object::{self, ObjectKind};
    fn lock() -> std::sync::MutexGuard<'static, ()> {
        object::test_lock()
    }

    fn prepare() {
        object::reset_destroy_hooks();
        reset();
        present_seam::reset();
    }

    fn new_display_object() -> ObjectId {
        object::create_with_payload(ObjectKind::Display, 0).expect("display object")
    }

    fn drop_object(object: ObjectId) {
        let _ = object::release_object(object);
    }

    #[test]
    fn geometry_matches_the_m6c_contract() {
        assert_eq!(DISPLAY_FRAMES, 64);
        assert_eq!(FRAME_SIZE, 4096);
        assert_eq!(DISPLAY_BYTES, 262_144);
        assert_eq!(MAX_DISPLAY_OBJECTS, 1);
    }

    #[test]
    fn create_allocates_a_zeroed_shadow_buffer() {
        let _guard = lock();
        prepare();
        let display = new_display_object();

        assert_eq!(create(display), Ok(()));
        assert_eq!(live_objects(), 1);
        assert_eq!(live_frames(), DISPLAY_FRAMES);

        let mut frames = [0u64; DISPLAY_FRAMES];
        assert!(map_pages(display, &mut frames).is_ok());
        assert_eq!(map_count(display), Some(1));
        for (index, frame) in frames.iter().enumerate() {
            assert_ne!(*frame, 0, "frame {index} must be allocated");
            assert_eq!(*frame % FRAME_SIZE, 0, "frame {index} must be page aligned");
            assert_eq!(
                *frame,
                frame_seam::TEST_FRAME_BASE + index as u64 * FRAME_SIZE,
                "frames must come from the seam pool in order"
            );
        }

        assert_eq!(unmap(display), Ok(()));
        assert_eq!(destroy(display), DISPLAY_FRAMES);
        assert_eq!(live_objects(), 0);
        assert_eq!(live_frames(), 0);
        assert_eq!(frame_seam::double_free(), 0);
        drop_object(display);
    }

    #[test]
    fn create_is_idempotent_and_refuses_a_second_object() {
        let _guard = lock();
        prepare();
        let first = new_display_object();
        assert_eq!(create(first), Ok(()));
        assert_eq!(create(first), Ok(()), "same object must not allocate again");
        assert_eq!(live_frames(), DISPLAY_FRAMES);

        let second = new_display_object();
        assert_eq!(create(second), Err(DisplayError::TableFull));
        assert_eq!(live_objects(), 1);
        assert_eq!(live_frames(), DISPLAY_FRAMES);

        assert_eq!(destroy(first), DISPLAY_FRAMES);
        drop_object(first);
        drop_object(second);
    }

    #[test]
    fn create_validates_kind_and_rolls_back_when_frames_run_out() {
        let _guard = lock();
        prepare();

        let not_a_display =
            object::create_with_payload(ObjectKind::SharedMemory, 0).expect("shm object");
        assert_eq!(create(not_a_display), Err(DisplayError::WrongKind));
        assert_eq!(
            create(object::ObjectId::MAX),
            Err(DisplayError::NoSuchObject)
        );
        drop_object(not_a_display);

        // 只留 63 帧：第 64 帧分配失败，必须完整回滚。
        frame_seam::leave_room(DISPLAY_FRAMES - 1);
        let display = new_display_object();
        assert_eq!(create(display), Err(DisplayError::NoMemory));
        assert_eq!(live_objects(), 0, "failed create must not leak a slot");
        assert_eq!(live_frames(), 0);
        assert_eq!(frame_seam::freed(), DISPLAY_FRAMES - 1);
        assert_eq!(frame_seam::double_free(), 0);

        // 恢复容量后同一个对象可以正常创建。
        reset();
        assert_eq!(create(display), Ok(()));
        assert_eq!(live_frames(), DISPLAY_FRAMES);
        assert_eq!(destroy(display), DISPLAY_FRAMES);
        drop_object(display);
    }

    #[test]
    fn unmap_is_symmetric_and_reports_not_mapped() {
        let _guard = lock();
        prepare();
        let display = new_display_object();
        assert_eq!(create(display), Ok(()));

        let mut frames = [0u64; DISPLAY_FRAMES];
        assert_eq!(map_count(display), Some(0));
        assert_eq!(unmap(display), Err(DisplayError::NotMapped));
        assert!(map_pages(display, &mut frames).is_ok());
        assert!(map_pages(display, &mut frames).is_ok());
        assert_eq!(map_count(display), Some(2));
        assert_eq!(unmap(display), Ok(()));
        assert_eq!(unmap(display), Ok(()));
        assert_eq!(unmap(display), Err(DisplayError::NotMapped));

        assert_eq!(destroy(display), DISPLAY_FRAMES);
        drop_object(display);
    }

    #[test]
    fn present_requires_a_mapped_shadow() {
        let _guard = lock();
        prepare();
        let display = new_display_object();
        assert_eq!(create(display), Ok(()));

        assert_eq!(present(display), Err(DisplayError::NotMapped));
        assert_eq!(present_seam::count(), 0);

        let mut frames = [0u64; DISPLAY_FRAMES];
        assert!(map_pages(display, &mut frames).is_ok());
        assert_eq!(present(display), Ok(()));
        assert_eq!(present_seam::count(), 1);

        assert_eq!(unmap(display), Ok(()));
        assert_eq!(present(display), Err(DisplayError::NotMapped));
        assert_eq!(present_seam::count(), 1);

        assert_eq!(destroy(display), DISPLAY_FRAMES);
        drop_object(display);
    }

    #[test]
    fn destroy_refuses_while_mapped_and_frees_exactly_once() {
        let _guard = lock();
        prepare();
        let display = new_display_object();
        assert_eq!(create(display), Ok(()));

        let mut frames = [0u64; DISPLAY_FRAMES];
        assert!(map_pages(display, &mut frames).is_ok());
        assert_eq!(destroy(display), 0, "mapped shadow must not be reclaimed");
        assert_eq!(live_objects(), 1);
        assert_eq!(live_frames(), DISPLAY_FRAMES);

        assert_eq!(unmap(display), Ok(()));
        assert_eq!(destroy(display), DISPLAY_FRAMES);
        assert_eq!(live_objects(), 0);
        assert_eq!(live_frames(), 0);
        assert_eq!(destroy(display), 0, "destroy must be idempotent");
        assert_eq!(frame_seam::double_free(), 0);
        assert_eq!(frame_seam::freed(), DISPLAY_FRAMES);
        drop_object(display);
    }

    #[test]
    fn stale_handles_report_missing_objects() {
        let _guard = lock();
        prepare();
        let display = new_display_object();
        assert_eq!(create(display), Ok(()));
        assert_eq!(destroy(display), DISPLAY_FRAMES);
        drop_object(display);

        let mut frames = [0u64; DISPLAY_FRAMES];
        assert_eq!(
            map_pages(display, &mut frames),
            Err(DisplayError::NoSuchObject)
        );
        assert_eq!(unmap(display), Err(DisplayError::NoSuchObject));
        assert_eq!(present(display), Err(DisplayError::NoSuchObject));
        assert_eq!(map_count(display), None);
    }

    #[test]
    fn on_destroy_reclaims_the_shadow_without_touching_the_object_table() {
        let _guard = lock();
        prepare();
        let display = new_display_object();
        assert_eq!(create(display), Ok(()));
        let mut frames = [0u64; DISPLAY_FRAMES];
        assert!(map_pages(display, &mut frames).is_ok());
        assert_eq!(unmap(display), Ok(()));

        on_destroy(display);
        assert_eq!(live_objects(), 0);
        assert_eq!(live_frames(), 0);
        drop_object(display);
    }
}
