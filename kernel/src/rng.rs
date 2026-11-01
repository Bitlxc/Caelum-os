//! 随机数与熵子系统（M4 状态机 + M8h 真实熵后端）。
//!
//! `agents.md` 第 9.5 节要求把随机数明确分成三种状态：**有可用熵**、
//! **熵不足（只有非密码学随机）**、**非密码学随机**。
//!
//! M4 只有状态机：没有熵源时状态固定为 [`EntropyState::NoEntropy`]，
//! [`read_secure`] 返回 [`RngError::NoEntropy`]，绝不用时间戳、固定种子或
//! “空操作成功”伪装安全随机。
//!
//! M8h 起接入真实熵后端：启动时用 CPUID 探测硬件 RNG（RDSEED 优先，其次
//! RDRAND），采集 16 个样本做健康检查（退化检测：连续重复、全零、区分度），
//! 通过后才把状态推进到 [`EntropyState::Ready`] 并记录后端。就绪后
//! [`read_secure`] 直接从后端读取字节，硬件读取持续失败时返回明确错误
//! [`RngError::BackendUnavailable`]，不降级为伪随机。
//!
//! 错误返回时尽最大努力不改写调用者缓冲区：硬件故障发生在一段 256 字节
//! 暂存区生成中途时，该段不会写回；跨段故障可能已写出前面完整的段，
//! 调用者拿到错误后必须丢弃缓冲区内容。

/// 进入 [`EntropyState::Ready`] 所需的最低熵估计（bit）。
///
/// 128 位对称安全强度通常对应 256 bit 熵；具体阈值属于策略，M8 验收时可调整，
/// 但“达到阈值”只是必要条件，不是充分条件（还必须通过健康检查）。
pub const MIN_SECURE_ENTROPY_BITS: u32 = 256;

/// 单次硬件读取的最大重试次数。
const MAX_RETRIES: u32 = 10;

/// 健康检查采样个数（每个样本 64 bit）。
const HEALTH_SAMPLES: usize = 16;

/// 后端每次批量生成的暂存区大小。
const STAGE_BYTES: usize = 256;

/// 随机子系统的三态：熵状态只允许单调前进，且不会仅凭时间推进。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum EntropyState {
    /// 没有任何可用熵：安全随机必须失败或阻塞，非密码学随机也不可得。
    NoEntropy,
    /// 已收集到若干熵，但只允许明确标记的非密码学用途。
    NonCryptographic,
    /// CRNG 已就绪（达到最低熵且健康检查通过），可提供安全随机。
    Ready,
}

/// 随机数读取错误。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum RngError {
    /// 当前没有任何熵源，安全随机不可用。
    NoEntropy,
    /// 只有非密码学随机可用，安全用途被拒绝。
    NotCryptographic,
    /// 状态宣称已就绪，但后端缺失或硬件读取失败。
    BackendUnavailable,
}

/// 真实熵后端。`None` 表示本机没有（或未安装）可用后端。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Backend {
    /// 尚未接入任何后端（M4 语义）。
    None,
    /// RDSEED（若 CPUID 报告支持）。
    Rdseed,
    /// RDRAND（若 CPUID 报告支持）。
    Rdrand,
    /// 宿主测试注入的确定性字节源，仅 `cfg(test)` 使用。
    #[cfg(test)]
    Test,
}

impl Backend {
    const fn name(self) -> &'static str {
        match self {
            Backend::None => "none",
            Backend::Rdseed => "rdseed",
            Backend::Rdrand => "rdrand",
            #[cfg(test)]
            Backend::Test => "test",
        }
    }
}

/// 随机子系统状态。纯逻辑，可在宿主单测。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct RngState {
    state: EntropyState,
    entropy_bits: u32,
    backend: Backend,
}

impl RngState {
    /// 新状态：无熵、无后端。
    pub const fn new() -> Self {
        Self {
            state: EntropyState::NoEntropy,
            entropy_bits: 0,
            backend: Backend::None,
        }
    }

    /// 当前熵状态。
    pub const fn state(&self) -> EntropyState {
        self.state
    }

    /// 当前累计熵估计（bit）。
    pub const fn entropy_bits(&self) -> u32 {
        self.entropy_bits
    }

    /// 密码学安全随机是否可用。
    pub const fn is_secure_ready(&self) -> bool {
        matches!(self.state, EntropyState::Ready)
    }

    /// 当前真实后端名（诊断用）。
    pub const fn backend_name(&self) -> &'static str {
        self.backend.name()
    }

    /// 记录熵源贡献的熵估计（bit），返回新状态。
    ///
    /// 只会把 `NoEntropy` 推进到 `NonCryptographic`；**不会**仅凭熵计数把状态
    /// 推进到 `Ready`——那需要真实后端与健康检查（[`RngState::mark_crng_ready`]）。
    /// 熵计数饱和累加，不会回绕成 0。
    pub fn add_entropy(&mut self, bits: u32) -> EntropyState {
        self.entropy_bits = self.entropy_bits.saturating_add(bits);
        if self.state == EntropyState::NoEntropy && self.entropy_bits > 0 {
            self.state = EntropyState::NonCryptographic;
        }
        self.state
    }

    /// 由真实熵后端调用：只有已收集到足够熵、且健康检查通过、且后端可用时
    /// 才进入 `Ready`。
    pub fn mark_crng_ready(&mut self) -> bool {
        if self.state == EntropyState::NonCryptographic
            && self.entropy_bits >= MIN_SECURE_ENTROPY_BITS
            && self.backend != Backend::None
        {
            self.state = EntropyState::Ready;
            true
        } else {
            false
        }
    }

    /// 安装真实后端并计入健康检查通过的熵，然后尝试进入 `Ready`。
    ///
    /// 只应由 `initialise`（或宿主测试）在健康检查通过后调用；`bits` 是保守
    /// 估计的熵下界，低于阈值时不会就绪。
    fn seed_with_backend(&mut self, backend: Backend, bits: u32) -> bool {
        if backend == Backend::None || bits < MIN_SECURE_ENTROPY_BITS {
            return false;
        }
        self.backend = backend;
        self.add_entropy(bits);
        self.mark_crng_ready()
    }

    /// 读取安全随机字节。
    ///
    /// 在 CRNG 就绪前返回明确错误，且**不写缓冲区**。就绪后从真实后端取字节；
    /// 硬件读取失败返回 [`RngError::BackendUnavailable`]，绝不伪造字节。
    /// 零长度请求视为成功，因为它不产生任何随机数据。
    pub fn read_secure(&mut self, out: &mut [u8]) -> Result<(), RngError> {
        if out.is_empty() {
            return Ok(());
        }
        match self.state {
            EntropyState::NoEntropy => Err(RngError::NoEntropy),
            EntropyState::NonCryptographic => Err(RngError::NotCryptographic),
            EntropyState::Ready => backend_fill(self.backend, out),
        }
    }

    /// 读取明确标记为非密码学的随机字节。
    ///
    /// 只有收集到熵之后才可能成功；本构建的非密码学路径仍不提供字节源，
    /// 因此返回 [`RngError::BackendUnavailable`]。调用者不得把它用于 ASLR、
    /// 密钥、`getrandom` 或 `AT_RANDOM`。
    pub fn read_noncryptographic(&mut self, out: &mut [u8]) -> Result<(), RngError> {
        if out.is_empty() {
            return Ok(());
        }
        match self.state {
            EntropyState::NoEntropy => Err(RngError::NoEntropy),
            EntropyState::NonCryptographic | EntropyState::Ready => {
                Err(RngError::BackendUnavailable)
            }
        }
    }

    /// 宿主测试：安装确定性测试后端（仅 `cfg(test)`）。
    #[cfg(test)]
    pub fn install_test_backend(&mut self) {
        self.backend = Backend::Test;
    }
}

impl Default for RngState {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// 真实熵后端：硬件采样、健康检查与字节生成。
// ---------------------------------------------------------------------------

/// 对一个 64 bit 硬件随机源做退化检测。
///
/// 规则（保守、固定上限、无分配）：
/// - 至少 8 个样本；
/// - 不允许连续 4 个及以上相同值；
/// - 至少 4 个不同取值；
/// - 不允许全部为 0。
pub(crate) fn health_check(samples: &[u64]) -> bool {
    if samples.len() < 8 {
        return false;
    }
    let mut previous: Option<u64> = None;
    let mut repeats = 0u32;
    let mut all_zero = true;
    for &sample in samples {
        if sample != 0 {
            all_zero = false;
        }
        if Some(sample) == previous {
            repeats += 1;
            if repeats >= 4 {
                return false;
            }
        } else {
            repeats = 0;
            previous = Some(sample);
        }
    }
    // 简单去重（样本固定 16 项，O(n^2) 可接受）：区分度太低视为退化。
    let mut distinct = 0u32;
    for (index, &sample) in samples.iter().enumerate() {
        if !samples[..index].contains(&sample) {
            distinct += 1;
        }
    }
    !all_zero && distinct >= 4
}

/// 从硬件源采集固定数量样本；任何一次样本在重试耗尽后仍失败则返回 `None`。
fn gather_samples<F: FnMut() -> Option<u64>>(mut read: F) -> Option<[u64; HEALTH_SAMPLES]> {
    let mut samples = [0u64; HEALTH_SAMPLES];
    for sample in &mut samples {
        let mut retries = 0u32;
        loop {
            match read() {
                Some(value) => {
                    *sample = value;
                    break;
                }
                None => {
                    retries += 1;
                    if retries >= MAX_RETRIES {
                        return None;
                    }
                    core::hint::spin_loop();
                }
            }
        }
    }
    Some(samples)
}

/// 硬件读取的通用字节填充：每段先在栈上生成完整内容，再写回调用者缓冲区。
fn fill_hardware<F: FnMut() -> Option<u64>>(out: &mut [u8], mut read: F) -> Result<(), RngError> {
    let mut offset = 0usize;
    while offset < out.len() {
        let take = (out.len() - offset).min(STAGE_BYTES);
        let mut stage = [0u8; STAGE_BYTES];
        let mut words = take.div_ceil(8);
        let mut previous: Option<u64> = None;
        let mut repeats = 0u32;
        while words > 0 {
            let mut retries = 0u32;
            let word = loop {
                match read() {
                    Some(value) => break value,
                    None => {
                        retries += 1;
                        if retries >= MAX_RETRIES {
                            return Err(RngError::BackendUnavailable);
                        }
                        core::hint::spin_loop();
                    }
                }
            };
            // 运行期退化检测：连续 4 个相同输出视为硬件故障。
            if Some(word) == previous {
                repeats += 1;
                if repeats >= 4 {
                    return Err(RngError::BackendUnavailable);
                }
            } else {
                repeats = 0;
                previous = Some(word);
            }
            let start = (take.div_ceil(8) - words) * 8;
            stage[start..start + 8].copy_from_slice(&word.to_le_bytes());
            words -= 1;
        }
        out[offset..offset + take].copy_from_slice(&stage[..take]);
        offset += take;
    }
    Ok(())
}

/// 按后端生成字节；`None`/硬件失败都返回明确错误。
fn backend_fill(backend: Backend, out: &mut [u8]) -> Result<(), RngError> {
    match backend {
        Backend::None => Err(RngError::BackendUnavailable),
        Backend::Rdseed => fill_hardware(out, crate::arch::rdseed64),
        Backend::Rdrand => fill_hardware(out, crate::arch::rdrand64),
        #[cfg(test)]
        Backend::Test => {
            // 测试后端：确定性递增字节 + 每次调用计数，用来断言“就绪后能产出
            // 字节且不同调用不会重复同一串”。
            static CALLS: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);
            let call = CALLS.fetch_add(1, core::sync::atomic::Ordering::Relaxed) as u8;
            for (index, byte) in out.iter_mut().enumerate() {
                *byte = (index as u8).wrapping_mul(37).wrapping_add(11) ^ call;
            }
            Ok(())
        }
    }
}

/// 选定并初始化真实熵后端；返回初始化后的状态。
///
/// 优先 RDSEED（真随机指令），其次 RDRAND（DRBG 输出，软件仍视为真实后端）；
/// 二者都不可用时保持 `NoEntropy`，绝不降级为伪随机或固定种子。
pub fn initialise() -> EntropyState {
    let backend = if crate::arch::has_rdseed() {
        Backend::Rdseed
    } else if crate::arch::has_rdrand() {
        Backend::Rdrand
    } else {
        Backend::None
    };
    if backend == Backend::None {
        return state();
    }
    let reader: fn() -> Option<u64> = match backend {
        Backend::Rdseed => crate::arch::rdseed64,
        Backend::Rdrand => crate::arch::rdrand64,
        _ => return state(),
    };
    let Some(samples) = gather_samples(reader) else {
        return state();
    };
    if !health_check(&samples) {
        return state();
    }
    with_state(|rng| {
        rng.seed_with_backend(backend, MIN_SECURE_ENTROPY_BITS);
        rng.state()
    })
}

/// 当前真实后端名（诊断用；未初始化时为 `"none"`）。
pub fn backend_name() -> &'static str {
    with_state(|rng| rng.backend_name())
}

// ---------------------------------------------------------------------------
// 内核全局状态：`sync::IrqSpinLock` 叶锁保护（M6b2b 起跨 CPU）；宿主测试用
// Mutex 串行化。
// ---------------------------------------------------------------------------

/// 保护 [`RNG_STATE`] 的叶锁：本地关中断并排斥其它 CPU。
static RNG: crate::sync::IrqSpinLock = crate::sync::IrqSpinLock::new();

static mut RNG_STATE: RngState = RngState::new();

/// 在叶锁保护下访问全局随机子系统状态。
///
/// 锁是叶锁：闭包只能读写 `RngState`，不得调用 object/ipc/VFS，也不得再次
/// 进入 [`with_state`]（自旋锁不可重入、guard 不得跨 CPU）。
pub fn with_state<R>(f: impl FnOnce(&mut RngState) -> R) -> R {
    RNG.with(|| {
        // SAFETY: `RNG_STATE` 只在持有 `RNG` 叶锁时被访问，因而同一时刻只有
        // 一个闭包能拿到 `&mut`；它位于 .bss，生命周期等同内核。
        f(unsafe { &mut *core::ptr::addr_of_mut!(RNG_STATE) })
    })
}

/// 当前熵状态。
pub fn state() -> EntropyState {
    with_state(|rng| rng.state())
}

/// 当前累计熵估计（bit）。
pub fn entropy_bits() -> u32 {
    with_state(|rng| rng.entropy_bits())
}

/// 密码学安全随机是否可用。
pub fn is_secure_ready() -> bool {
    with_state(|rng| rng.is_secure_ready())
}

/// 记录熵源贡献的熵估计（bit），返回新状态。
pub fn add_entropy(bits: u32) -> EntropyState {
    with_state(|rng| rng.add_entropy(bits))
}

/// 读取安全随机字节；未就绪时返回明确错误且不写缓冲区。
pub fn read_secure(out: &mut [u8]) -> Result<(), RngError> {
    with_state(|rng| rng.read_secure(out))
}

/// 读取非密码学随机字节（本构建没有字节源，返回明确错误）。
pub fn read_noncryptographic(out: &mut [u8]) -> Result<(), RngError> {
    with_state(|rng| rng.read_noncryptographic(out))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn global_lock() -> std::sync::MutexGuard<'static, ()> {
        static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
        LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    #[test]
    fn initial_state_has_no_entropy() {
        let rng = RngState::new();
        assert_eq!(rng.state(), EntropyState::NoEntropy);
        assert_eq!(rng.entropy_bits(), 0);
        assert!(!rng.is_secure_ready());
        assert_eq!(rng.backend_name(), "none");
    }

    #[test]
    fn secure_read_fails_without_entropy_and_does_not_touch_buffer() {
        let mut rng = RngState::new();
        let mut buffer = [0xAA_u8; 32];
        assert_eq!(rng.read_secure(&mut buffer), Err(RngError::NoEntropy));
        assert_eq!(buffer, [0xAA_u8; 32]);

        // 明确标记为非密码学的读取同样不可用。
        assert_eq!(
            rng.read_noncryptographic(&mut buffer),
            Err(RngError::NoEntropy)
        );
        assert_eq!(buffer, [0xAA_u8; 32]);

        // 零长度请求不产生随机数据，视为成功。
        assert_eq!(rng.read_secure(&mut []), Ok(()));
    }

    #[test]
    fn entropy_moves_to_noncryptographic_but_never_to_ready() {
        let mut rng = RngState::new();
        // 0 bit 不算熵。
        assert_eq!(rng.add_entropy(0), EntropyState::NoEntropy);
        assert_eq!(rng.read_secure(&mut [0u8; 4]), Err(RngError::NoEntropy));

        assert_eq!(rng.add_entropy(64), EntropyState::NonCryptographic);
        assert_eq!(rng.entropy_bits(), 64);
        assert!(!rng.is_secure_ready());
        // 非密码学状态不能提供安全随机。
        let mut buffer = [0u8; 8];
        assert_eq!(
            rng.read_secure(&mut buffer),
            Err(RngError::NotCryptographic)
        );
        assert_eq!(buffer, [0u8; 8]);

        // 仅靠累加熵不会把状态推进到 Ready。
        assert_eq!(rng.add_entropy(1024), EntropyState::NonCryptographic);
        assert!(!rng.is_secure_ready());
    }

    #[test]
    fn entropy_counter_saturates() {
        let mut rng = RngState::new();
        rng.add_entropy(u32::MAX - 1);
        rng.add_entropy(1024);
        assert_eq!(rng.entropy_bits(), u32::MAX);
    }

    #[test]
    fn crng_ready_requires_threshold_backend_and_health_check() {
        let mut rng = RngState::new();
        // 没有熵证据时不能就绪。
        assert!(!rng.mark_crng_ready());
        assert_eq!(rng.state(), EntropyState::NoEntropy);

        // 熵不足时不能就绪。
        rng.add_entropy(MIN_SECURE_ENTROPY_BITS - 1);
        assert!(!rng.mark_crng_ready());
        assert_eq!(rng.state(), EntropyState::NonCryptographic);

        // 达到阈值但没有真实后端：仍不能就绪（不再伪造 Ready）。
        rng.add_entropy(1);
        assert!(!rng.mark_crng_ready());
        assert_eq!(rng.state(), EntropyState::NonCryptographic);
        assert_eq!(
            rng.read_secure(&mut [0u8; 16]),
            Err(RngError::NotCryptographic)
        );

        // 安装后端后才能就绪，并且能产出字节。
        rng.install_test_backend();
        assert!(rng.mark_crng_ready());
        assert!(rng.is_secure_ready());
        let mut first = [0u8; 16];
        let mut second = [0u8; 16];
        assert_eq!(rng.read_secure(&mut first), Ok(()));
        assert_eq!(rng.read_secure(&mut second), Ok(()));
        assert!(first.iter().any(|byte| *byte != 0));
        assert_ne!(first, second);
    }

    #[test]
    fn health_check_rejects_degenerate_samples() {
        // 全部相同。
        assert!(!health_check(&[7u64; HEALTH_SAMPLES]));
        // 全部为零。
        assert!(!health_check(&[0u64; HEALTH_SAMPLES]));
        // 只有两个取值。
        let mut alternating = [0u64; HEALTH_SAMPLES];
        for (index, sample) in alternating.iter_mut().enumerate() {
            *sample = (index % 2) as u64;
        }
        assert!(!health_check(&alternating));
        // 样本太少。
        assert!(!health_check(&[1, 2, 3, 4]));
        // 正常样本（16 个不同值）。
        let mut good = [0u64; HEALTH_SAMPLES];
        for (index, sample) in good.iter_mut().enumerate() {
            *sample = 0x9E37_79B9_7F4A_7C15_u64.wrapping_mul(index as u64 + 1);
        }
        assert!(health_check(&good));
    }

    #[test]
    fn hardware_gather_retries_failures_with_a_bounded_budget() {
        let mut reads = 0;
        let samples = gather_samples(|| {
            reads += 1;
            if reads % 2 == 0 {
                Some(0x1111_2222_3333_4444)
            } else {
                None
            }
        });
        assert!(samples.is_some());

        // 永远失败：重试预算耗尽后返回 None。
        let mut always_failing_reads = 0;
        let failed = gather_samples(|| {
            always_failing_reads += 1;
            None::<u64>
        });
        assert!(failed.is_none());
        assert_eq!(always_failing_reads, MAX_RETRIES);
    }

    #[test]
    fn fill_hardware_reports_unavailable_without_touching_the_buffer() {
        let mut buffer = [0x5A_u8; 32];
        let result = fill_hardware(&mut buffer, || None::<u64>);
        assert_eq!(result, Err(RngError::BackendUnavailable));
        assert_eq!(buffer, [0x5A_u8; 32]);
    }

    #[test]
    fn fill_hardware_rejects_a_stuck_source() {
        // 同一个值连续出现：运行期退化检测必须拒绝。
        let mut buffer = [0u8; 64];
        let result = fill_hardware(&mut buffer, || Some(0xA5A5_A5A5_A5A5_A5A5));
        assert_eq!(result, Err(RngError::BackendUnavailable));
    }

    #[test]
    fn global_state_starts_empty_and_reports_explicit_errors() {
        let _guard = global_lock();
        with_state(|rng| {
            *rng = RngState::new();
        });

        assert_eq!(state(), EntropyState::NoEntropy);
        assert_eq!(entropy_bits(), 0);
        assert!(!is_secure_ready());
        assert_eq!(read_secure(&mut [0u8; 16]), Err(RngError::NoEntropy));

        assert_eq!(add_entropy(32), EntropyState::NonCryptographic);
        assert_eq!(state(), EntropyState::NonCryptographic);
        assert_eq!(read_secure(&mut [0u8; 16]), Err(RngError::NotCryptographic));

        // 复位，避免影响同一进程内后续测试。
        with_state(|rng| {
            *rng = RngState::new();
        });
        assert_eq!(state(), EntropyState::NoEntropy);
    }
}
