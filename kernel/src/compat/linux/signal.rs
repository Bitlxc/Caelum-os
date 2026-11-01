//! Linux64 signal wire formats and the user-stack `rt_sigframe` (M8c).
//!
//! This module owns **only** the ABI-visible parts of signals:
//!
//! - `rt_sigaction`'s 32-byte kernel `sigaction` layout and its validation.
//! - `rt_sigprocmask`'s 8-byte `sigset_t` and the `how` selectors.
//! - The minimal `rt_sigframe` this personality pushes on the user stack, the
//!   stack layout that makes the user `sa_restorer` end up calling
//!   `rt_sigreturn` with `rsp` pointing at the frame, and the user-memory
//!   access helpers used to write/validate it.
//!
//! The per-process state machine (dispositions, blocked mask, pending mask and
//! the saved context taken during a delivery) lives in [`crate::process`]
//! (`SignalState`, `signal_*`, [`crate::process::PendingSignal`]). The process
//! side deliberately does **not** build the user frame or touch `rip`/`rsp`;
//! that is this module's job, because only the personality knows the Linux
//! signal-frame ABI.
//!
//! # The user stack frame
//!
//! [`SIGFRAME_BYTES`] bytes, 8-byte aligned, laid out as:
//!
//! ```text
//! offset 0    r15 r14 r13 r12 rbp rbx r11 r10 r9 r8 rax rcx rdx rsi rdi   (15 words)
//! offset 120  rip
//! offset 128  cs
//! offset 136  rflags
//! offset 144  user_rsp
//! offset 152  user_ss
//! offset 160  saved blocked mask
//! offset 168  magic
//! ```
//!
//! The handler is entered as if it had been called (System V AMD64:
//! `rsp % 16 == 8` at entry), so the delivery code places the user
//! `sa_restorer` at `frame_start - 8` and sets `rsp` there. A `ret` in the
//! handler pops the restorer and leaves `rsp == frame_start`, so the restorer's
//! `syscall` (number 15) makes `rt_sigreturn` read the frame at the syscall-time
//! `rsp` — the ABI the user programs expect.
//!
//! This is deliberately **not** a full Linux `rt_sigframe` (no siginfo, no
//! ucontext, no floating-point state); M8c only promises a minimal handler
//! entry/return round trip.

use crate::arch::TrapFrame;
use crate::process::{SIG_DFL, SIG_IGN, SIGKILL, SIGNAL_MAX, SIGSTOP, SigAction, UserContext};

/// `SA_RESTORER`: the `restorer` field is valid (required on x86-64 to return
/// from a handler through `rt_sigreturn`).
pub const SA_RESTORER: u64 = 0x0400_0000;
/// `SA_SIGINFO`: not implemented (documented out of scope for M8c).
pub const SA_SIGINFO: u64 = 0x0000_0004;
/// Flags this personality accepts in `rt_sigaction`.
pub const SUPPORTED_ACTION_FLAGS: u64 = SA_RESTORER;

/// `SIG_BLOCK` for `rt_sigprocmask`.
pub const SIG_BLOCK: u64 = 0;
/// `SIG_UNBLOCK` for `rt_sigprocmask`.
pub const SIG_UNBLOCK: u64 = 1;
/// `SIG_SETMASK` for `rt_sigprocmask`.
pub const SIG_SETMASK: u64 = 2;

/// `sigsetsize` the kernel expects (`sizeof(sigset_t)` on Linux x86-64).
pub const SIGSET_SIZE: u64 = 8;
/// Size of the kernel's `struct sigaction` (`handler/flags/restorer/mask`).
pub const SIGACTION_BYTES: usize = 32;

/// Number of user-visible registers saved in the frame (TrapFrame order).
pub const SAVED_REGS: usize = 15;
/// The frame is 22 qwords: 15 registers + rip/cs/rflags/user_rsp/user_ss +
/// saved mask + magic.
pub const SIGFRAME_QWORDS: usize = SAVED_REGS + 5 + 1 + 1;
/// Byte size of the frame (176).
pub const SIGFRAME_BYTES: usize = SIGFRAME_QWORDS * 8;
/// Magic at the end of the frame, so `rt_sigreturn` can reject a bogus pointer.
pub const SIGFRAME_MAGIC: u64 = 0x5349_4746_5241_4D45;

/// A default action (`SIG_DFL`, no flags/restorer/mask).
pub const fn default_action() -> SigAction {
    SigAction {
        handler: SIG_DFL,
        flags: 0,
        restorer: 0,
        mask: 0,
    }
}

/// A custom handler with the required `SA_RESTORER`.
pub const fn custom_action(handler: u64, restorer: u64, mask: u64) -> SigAction {
    SigAction {
        handler,
        flags: SA_RESTORER,
        restorer,
        mask,
    }
}

/// Whether `action` is `SIG_DFL`.
pub const fn is_default(action: &SigAction) -> bool {
    action.handler == SIG_DFL
}

/// Whether `action` is `SIG_IGN`.
pub const fn is_ignore(action: &SigAction) -> bool {
    action.handler == SIG_IGN
}

/// Whether `signum` cannot be caught or blocked (`SIGKILL`/`SIGSTOP`).
pub const fn is_uncatchable(signum: u32) -> bool {
    signum == SIGKILL || signum == SIGSTOP
}

/// Bit for `signum` in a signal mask.
pub const fn mask_bit(signum: u32) -> u64 {
    1u64 << (signum - 1)
}

/// Encode a [`SigAction`] into the 32-byte user/kernel wire layout.
pub fn encode_action(action: &SigAction) -> [u8; SIGACTION_BYTES] {
    let mut wire = [0u8; SIGACTION_BYTES];
    wire[0..8].copy_from_slice(&action.handler.to_le_bytes());
    wire[8..16].copy_from_slice(&action.flags.to_le_bytes());
    wire[16..24].copy_from_slice(&action.restorer.to_le_bytes());
    wire[24..32].copy_from_slice(&action.mask.to_le_bytes());
    wire
}

/// Decode the 32-byte `sigaction` layout.
pub fn decode_action(wire: &[u8; SIGACTION_BYTES]) -> SigAction {
    let mut handler = [0u8; 8];
    let mut flags = [0u8; 8];
    let mut restorer = [0u8; 8];
    let mut mask = [0u8; 8];
    handler.copy_from_slice(&wire[0..8]);
    flags.copy_from_slice(&wire[8..16]);
    restorer.copy_from_slice(&wire[16..24]);
    mask.copy_from_slice(&wire[24..32]);
    SigAction {
        handler: u64::from_le_bytes(handler),
        flags: u64::from_le_bytes(flags),
        restorer: u64::from_le_bytes(restorer),
        mask: u64::from_le_bytes(mask),
    }
}

/// Validate a signal number supplied by user space.
///
/// Returns the number on success and `EINVAL` for 0/`> SIGNAL_MAX`.
pub fn validate_signal(signum: u64) -> Result<u32, i64> {
    let signum = u32::try_from(signum).map_err(|_| super::errno::EINVAL)?;
    if signum == 0 || signum > SIGNAL_MAX {
        return Err(super::errno::EINVAL);
    }
    Ok(signum)
}

/// Validate a user `sigaction` for `signum`.
///
/// - `SIGKILL`/`SIGSTOP` cannot be changed (`EINVAL`).
/// - Only [`SA_RESTORER`] is accepted as a flag; `SA_SIGINFO`, `SA_RESTART`,
///   `SA_NODEFER`, ... are `EINVAL` because M8c does not implement them.
/// - A custom handler needs `SA_RESTORER` and a non-zero restorer: the kernel
///   must not fabricate a trampoline (`EINVAL`).
pub fn validate_action(signum: u32, action: &SigAction) -> Result<(), i64> {
    if is_uncatchable(signum) {
        return Err(super::errno::EINVAL);
    }
    if action.flags & !SUPPORTED_ACTION_FLAGS != 0 {
        return Err(super::errno::EINVAL);
    }
    if action.handler == SIG_DFL || action.handler == SIG_IGN {
        return Ok(());
    }
    if action.flags & SA_RESTORER == 0 || action.restorer == 0 {
        return Err(super::errno::EINVAL);
    }
    Ok(())
}

/// Size of a Linux `sigset_t` on x86-64 (`rt_sigprocmask`'s `sigsetsize`).
pub const SIGSET_BYTES: usize = SIGSET_SIZE as usize;

/// Decode an 8-byte signal set image.
pub fn decode_sigset(wire: &[u8; SIGSET_BYTES]) -> u64 {
    u64::from_le_bytes(*wire)
}

/// Encode a signal set image.
pub fn encode_sigset(mask: u64) -> [u8; SIGSET_BYTES] {
    mask.to_le_bytes()
}

/// Validate `rt_sigprocmask`'s `how` and return the raw selector.
///
/// The three documented selectors are accepted; anything else is `EINVAL`.
pub fn validate_mask_how(how: u64) -> Result<u64, i64> {
    match how {
        SIG_BLOCK | SIG_UNBLOCK | SIG_SETMASK => Ok(how),
        _ => Err(super::errno::EINVAL),
    }
}

/// A decoded user-stack `rt_sigframe`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SignalFrame {
    /// Interrupted register state and stack pointer.
    pub context: UserContext,
    /// Interrupted code selector (informational; ring 3 always uses `USER_CS`).
    pub cs: u64,
    /// Blocked mask at delivery time.
    pub mask: u64,
}

/// Encode the user-stack frame image.
pub fn encode_frame(context: &UserContext, cs: u64, mask: u64) -> [u8; SIGFRAME_BYTES] {
    let mut image = [0u8; SIGFRAME_BYTES];
    let mut cursor = 0usize;
    for value in context.regs {
        image[cursor..cursor + 8].copy_from_slice(&value.to_le_bytes());
        cursor += 8;
    }
    for value in [
        context.rip,
        cs,
        context.rflags,
        context.rsp,
        context.ss,
        mask,
        SIGFRAME_MAGIC,
    ] {
        image[cursor..cursor + 8].copy_from_slice(&value.to_le_bytes());
        cursor += 8;
    }
    image
}

/// Decode the user-stack frame image stored by [`encode_frame`].
///
/// A wrong magic means the pointer did not come from this personality's
/// delivery path (or the user corrupted it); `EINVAL` is returned instead of
/// restoring garbage.
pub fn decode_frame(image: &[u8; SIGFRAME_BYTES]) -> Result<SignalFrame, i64> {
    let mut cursor = 0usize;
    let mut regs = [0u64; SAVED_REGS];
    for value in regs.iter_mut() {
        let mut word = [0u8; 8];
        word.copy_from_slice(&image[cursor..cursor + 8]);
        *value = u64::from_le_bytes(word);
        cursor += 8;
    }
    let mut words = [0u64; 7];
    for value in words.iter_mut() {
        let mut word = [0u8; 8];
        word.copy_from_slice(&image[cursor..cursor + 8]);
        *value = u64::from_le_bytes(word);
        cursor += 8;
    }
    if words[6] != SIGFRAME_MAGIC {
        return Err(super::errno::EINVAL);
    }
    Ok(SignalFrame {
        context: UserContext {
            regs,
            rip: words[0],
            rflags: words[2],
            rsp: words[3],
            ss: words[4],
        },
        cs: words[1],
        mask: words[5],
    })
}

/// The user-stack layout for one delivery.
///
/// Given the interrupted user `rsp`, returns `(restorer_slot, frame_start,
/// frame_end)`:
///
/// - `frame_end = rsp & !0xF` — the top of the frame.
/// - `frame_start = frame_end - SIGFRAME_BYTES` (16-byte aligned, because the
///   frame size is a multiple of 16 bytes).
/// - `restorer_slot = frame_start - 8`, so the handler is entered with
///   `rsp % 16 == 8` and a `ret` there lands on the frame start.
pub fn frame_layout(trap_rsp: u64) -> Result<(u64, u64, u64), i64> {
    let frame_end = trap_rsp & !0xF;
    let frame_start = frame_end
        .checked_sub(SIGFRAME_BYTES as u64)
        .ok_or(super::errno::EINVAL)?;
    let restorer_slot = frame_start.checked_sub(8).ok_or(super::errno::EINVAL)?;
    Ok((restorer_slot, frame_start, frame_end))
}

/// A prepared delivery: the user-stack frame plus the handler entry values.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DeliveryPlan {
    /// Slot the handler's `ret` will pop: the handler entry `rsp`.
    pub restorer_slot: u64,
    /// Start of the frame (`rsp` seen by the restorer's `rt_sigreturn`).
    pub frame_start: u64,
    /// End of the frame (16-byte aligned top below the interrupted `rsp`).
    pub frame_end: u64,
    /// The frame image to copy to `frame_start`.
    pub frame: [u8; SIGFRAME_BYTES],
    /// Value to write at `restorer_slot`.
    pub restorer: u64,
    /// Handler entry point (`rip`).
    pub handler: u64,
    /// Signal number passed in `rdi`.
    pub signo: u32,
}

/// Build the delivery plan for one custom handler.
///
/// Only custom handlers have a user frame: `SIG_DFL`/`SIG_IGN` are handled by
/// the process state machine before this function is called, so they are
/// rejected here. The caller writes `frame` to `frame_start`, `restorer` to
/// `restorer_slot`, and then rewrites the trap frame (`rip = handler`,
/// `user_rsp = restorer_slot`, `rdi = signo`).
pub fn delivery_plan(
    context: &UserContext,
    cs: u64,
    action: &SigAction,
    signo: u32,
    saved_mask: u64,
) -> Result<DeliveryPlan, i64> {
    if action.handler == SIG_DFL || action.handler == SIG_IGN || action.restorer == 0 {
        return Err(super::errno::EINVAL);
    }
    let (restorer_slot, frame_start, frame_end) = frame_layout(context.rsp)?;
    Ok(DeliveryPlan {
        restorer_slot,
        frame_start,
        frame_end,
        frame: encode_frame(context, cs, saved_mask),
        restorer: action.restorer,
        handler: action.handler,
        signo,
    })
}

/// User-memory access used by the delivery/restore paths.
///
/// Implemented by the syscall entry over `addrspace` (production) and by an
/// in-memory fake in host tests, so the frame arithmetic above is testable
/// without a real address space.
pub trait SignalMemory {
    /// Verify that `len` bytes at `user` are writable before any write happens.
    fn validate_write(&self, user: u64, len: u64) -> Result<(), i64>;
    /// Write `bytes` at `user`.
    fn write(&mut self, user: u64, bytes: &[u8]) -> Result<(), i64>;
    /// Read `out.len()` bytes from `user`.
    fn read(&mut self, user: u64, out: &mut [u8]) -> Result<(), i64>;
}

/// Write the frame + restorer slot and rewrite `trap` to enter the handler.
///
/// The whole write range is validated first, so a bad user stack fails with
/// `EFAULT` before any frame byte or trap-frame field changes. The caller must
/// treat an `Err` as "not delivered" (re-pend the signal or terminate); an
/// `Ok` means the handler will run when the syscall returns to ring 3.
pub fn deliver_handler(
    trap: &mut TrapFrame,
    action: &SigAction,
    signo: u32,
    saved: &UserContext,
    saved_mask: u64,
    memory: &mut dyn SignalMemory,
) -> Result<(), i64> {
    let plan = delivery_plan(saved, trap.cs, action, signo, saved_mask)?;
    let span = plan
        .frame_end
        .checked_sub(plan.restorer_slot)
        .ok_or(super::errno::EINVAL)?;
    memory.validate_write(plan.restorer_slot, span)?;
    memory.write(plan.restorer_slot, &plan.restorer.to_le_bytes())?;
    memory.write(plan.frame_start, &plan.frame)?;
    trap.rip = plan.handler;
    trap.user_rsp = plan.restorer_slot;
    trap.rdi = u64::from(plan.signo);
    trap.rsi = 0;
    trap.rdx = 0;
    trap.rax = 0;
    Ok(())
}

/// Validate the frame `rt_sigreturn` is about to restore.
///
/// Reads the frame at the syscall-time user `rsp` and checks its magic. The
/// actual register/mask restore is done by
/// [`crate::process::signal_restore_context`], which owns the trusted copy taken
/// at delivery; the user frame is validated so a bogus `rsp` cannot silently
/// "restore" garbage.
pub fn validate_user_frame(trap: &TrapFrame, memory: &mut dyn SignalMemory) -> Result<(), i64> {
    let mut image = [0u8; SIGFRAME_BYTES];
    memory.read(trap.user_rsp, &mut image)?;
    decode_frame(&image).map(|_| ())
}

#[cfg(test)]
mod tests {
    use super::super::errno;
    use super::*;

    /// In-memory stand-in for the user stack: one 4 KiB window at `BASE`.
    struct FakeMemory {
        bytes: [u8; 4096],
        writable_until: u64,
    }

    const BASE: u64 = 0x0080_0000;

    impl FakeMemory {
        fn new() -> Self {
            Self {
                bytes: [0u8; 4096],
                writable_until: BASE + 4096,
            }
        }

        fn offset(user: u64) -> Option<usize> {
            if user < BASE || user >= BASE + 4096 {
                return None;
            }
            Some((user - BASE) as usize)
        }
    }

    impl SignalMemory for FakeMemory {
        fn validate_write(&self, user: u64, len: u64) -> Result<(), i64> {
            let end = user.checked_add(len).ok_or(errno::EFAULT)?;
            if user < BASE || end > self.writable_until {
                return Err(errno::EFAULT);
            }
            Ok(())
        }

        fn write(&mut self, user: u64, bytes: &[u8]) -> Result<(), i64> {
            let offset = Self::offset(user).ok_or(errno::EFAULT)?;
            self.bytes[offset..offset + bytes.len()].copy_from_slice(bytes);
            Ok(())
        }

        fn read(&mut self, user: u64, out: &mut [u8]) -> Result<(), i64> {
            let offset = Self::offset(user).ok_or(errno::EFAULT)?;
            out.copy_from_slice(&self.bytes[offset..offset + out.len()]);
            Ok(())
        }
    }

    fn sample_context() -> UserContext {
        UserContext {
            regs: [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
            rip: 0x0040_1234,
            rflags: 0x202,
            rsp: BASE + 0x800,
            ss: 0x002B,
        }
    }

    fn queued_trap() -> TrapFrame {
        TrapFrame {
            r15: 0,
            r14: 0,
            r13: 0,
            r12: 0,
            rbp: 0,
            rbx: 0,
            r11: 0,
            r10: 0,
            r9: 0,
            r8: 0,
            rax: 0,
            rcx: 0,
            rdx: 0,
            rsi: 0,
            rdi: 0,
            vector: 0x60,
            error_code: 0,
            rip: 0x0040_1234,
            cs: 0x0033,
            rflags: 0x202,
            user_rsp: BASE + 0x800,
            user_ss: 0x002B,
        }
    }

    #[test]
    fn the_sigaction_wire_layout_is_thirty_two_bytes_and_round_trips() {
        let action = SigAction {
            handler: 0x0040_1234,
            flags: SA_RESTORER,
            restorer: 0x0040_5678,
            mask: 0x0000_0102,
        };
        let wire = encode_action(&action);
        assert_eq!(wire.len(), SIGACTION_BYTES);
        assert_eq!(decode_action(&wire), action);
        assert_eq!(&wire[0..8], &0x0040_1234u64.to_le_bytes());
        assert_eq!(&wire[8..16], &SA_RESTORER.to_le_bytes());
        assert_eq!(&wire[16..24], &0x0040_5678u64.to_le_bytes());
        assert_eq!(&wire[24..32], &0x0000_0102u64.to_le_bytes());
    }

    #[test]
    fn only_restorer_is_an_accepted_action_flag() {
        let custom = custom_action(0x1000, 0x2000, 0);
        assert_eq!(validate_action(10, &custom), Ok(()));
        for flag in [SA_SIGINFO, 0x1000_0000, 0x4000_0000] {
            let action = SigAction {
                flags: SA_RESTORER | flag,
                ..custom
            };
            assert_eq!(validate_action(10, &action), Err(errno::EINVAL));
        }
        assert_eq!(validate_action(10, &default_action()), Ok(()));
        let ignored = SigAction {
            handler: SIG_IGN,
            ..default_action()
        };
        assert_eq!(validate_action(10, &ignored), Ok(()));
    }

    #[test]
    fn a_custom_handler_needs_a_restorer() {
        let no_flag = SigAction {
            handler: 0x1000,
            flags: 0,
            restorer: 0x2000,
            mask: 0,
        };
        assert_eq!(validate_action(10, &no_flag), Err(errno::EINVAL));
        let no_restorer = SigAction {
            handler: 0x1000,
            flags: SA_RESTORER,
            restorer: 0,
            mask: 0,
        };
        assert_eq!(validate_action(10, &no_restorer), Err(errno::EINVAL));
    }

    #[test]
    fn kill_and_stop_cannot_be_caught() {
        let custom = custom_action(0x1000, 0x2000, 0);
        assert_eq!(validate_action(SIGKILL, &custom), Err(errno::EINVAL));
        assert_eq!(validate_action(SIGSTOP, &custom), Err(errno::EINVAL));
        assert_eq!(
            validate_action(SIGKILL, &default_action()),
            Err(errno::EINVAL)
        );
    }

    #[test]
    fn signal_numbers_are_standard_range_only() {
        assert_eq!(validate_signal(1), Ok(1));
        assert_eq!(validate_signal(31), Ok(31));
        assert_eq!(validate_signal(0), Err(errno::EINVAL));
        assert_eq!(validate_signal(32), Err(errno::EINVAL));
        assert_eq!(validate_signal(64), Err(errno::EINVAL));
        assert_eq!(validate_signal(u64::MAX), Err(errno::EINVAL));
    }

    #[test]
    fn signal_sets_round_trip_through_their_eight_byte_layout() {
        let mask = mask_bit(2) | mask_bit(15);
        let wire = encode_sigset(mask);
        assert_eq!(wire.len(), SIGSET_BYTES);
        assert_eq!(decode_sigset(&wire), mask);
    }

    #[test]
    fn sigprocmask_how_accepts_only_the_three_documented_selectors() {
        assert_eq!(validate_mask_how(SIG_BLOCK), Ok(SIG_BLOCK));
        assert_eq!(validate_mask_how(SIG_UNBLOCK), Ok(SIG_UNBLOCK));
        assert_eq!(validate_mask_how(SIG_SETMASK), Ok(SIG_SETMASK));
        assert_eq!(validate_mask_how(3), Err(errno::EINVAL));
        assert_eq!(validate_mask_how(u64::MAX), Err(errno::EINVAL));
    }

    #[test]
    fn the_saved_frame_round_trips_and_rejects_a_bad_magic() {
        let context = sample_context();
        let image = encode_frame(&context, 0x0033, mask_bit(2));
        assert_eq!(image.len(), SIGFRAME_BYTES);
        let frame = decode_frame(&image).expect("frame decodes");
        assert_eq!(frame.context, context);
        assert_eq!(frame.cs, 0x0033);
        assert_eq!(frame.mask, mask_bit(2));

        let mut broken = image;
        broken[168..176].copy_from_slice(&0u64.to_le_bytes());
        assert_eq!(decode_frame(&broken), Err(errno::EINVAL));
    }

    #[test]
    fn frame_layout_aligns_the_handler_stack_and_the_restorer_slot() {
        let (slot, start, end) = frame_layout(BASE + 0x800).expect("layout");
        assert_eq!(end, BASE + 0x800);
        assert_eq!(start, BASE + 0x800 - SIGFRAME_BYTES as u64);
        assert_eq!(slot, start - 8);
        assert_eq!(start % 16, 0);
        assert_eq!(slot % 16, 8);
        assert_eq!(slot + 8, start);
        assert_eq!(start + SIGFRAME_BYTES as u64, end);

        let (slot2, start2, end2) = frame_layout(BASE + 0x7FC).expect("layout");
        assert_eq!(end2, BASE + 0x7F0);
        assert_eq!(start2, BASE + 0x7F0 - SIGFRAME_BYTES as u64);
        assert_eq!(slot2, start2 - 8);
        assert_eq!(frame_layout(64), Err(errno::EINVAL));
    }

    #[test]
    fn a_delivery_plan_points_at_the_handler_and_keeps_the_restorer_reachable() {
        let context = sample_context();
        let action = custom_action(0x0040_4000, 0x0040_5000, mask_bit(15));
        let plan = delivery_plan(&context, 0x0033, &action, 10, mask_bit(2)).expect("plan");
        assert_eq!(plan.handler, 0x0040_4000);
        assert_eq!(plan.restorer, 0x0040_5000);
        assert_eq!(plan.signo, 10);
        assert_eq!(plan.restorer_slot % 16, 8);
        assert_eq!(plan.restorer_slot + 8, plan.frame_start);
        assert_eq!(plan.frame_start + SIGFRAME_BYTES as u64, plan.frame_end);
        let decoded = decode_frame(&plan.frame).expect("frame decodes");
        assert_eq!(decoded.context, context);
        assert_eq!(decoded.mask, mask_bit(2));
    }

    #[test]
    fn a_delivery_plan_rejects_non_custom_handlers_and_missing_restorers() {
        let context = sample_context();
        assert_eq!(
            delivery_plan(&context, 0x33, &default_action(), 10, 0),
            Err(errno::EINVAL)
        );
        let ignored = SigAction {
            handler: SIG_IGN,
            ..default_action()
        };
        assert_eq!(
            delivery_plan(&context, 0x33, &ignored, 10, 0),
            Err(errno::EINVAL)
        );
        let no_restorer = SigAction {
            handler: 0x1000,
            flags: SA_RESTORER,
            restorer: 0,
            mask: 0,
        };
        assert_eq!(
            delivery_plan(&context, 0x33, &no_restorer, 10, 0),
            Err(errno::EINVAL)
        );
    }

    #[test]
    fn delivering_a_handler_writes_the_frame_and_rewrites_the_trap_frame() {
        let mut memory = FakeMemory::new();
        let mut trap = queued_trap();
        let context = sample_context();
        let action = custom_action(0x0040_4000, 0x0040_5000, 0);

        deliver_handler(&mut trap, &action, 10, &context, mask_bit(2), &mut memory)
            .expect("delivery");

        let (slot, start, _) = frame_layout(BASE + 0x800).expect("layout");
        assert_eq!(trap.rip, 0x0040_4000);
        assert_eq!(trap.user_rsp, slot);
        assert_eq!(trap.rdi, 10);
        assert_eq!(trap.rsi, 0);
        assert_eq!(trap.rdx, 0);
        assert_eq!(trap.rax, 0);
        assert_eq!(trap.cs, 0x0033);

        let mut restorer = [0u8; 8];
        memory.read(slot, &mut restorer).expect("restorer slot");
        assert_eq!(u64::from_le_bytes(restorer), 0x0040_5000);
        let mut image = [0u8; SIGFRAME_BYTES];
        memory.read(start, &mut image).expect("frame");
        let decoded = decode_frame(&image).expect("frame decodes");
        assert_eq!(decoded.context, context);
        assert_eq!(decoded.mask, mask_bit(2));
    }

    #[test]
    fn a_delivery_that_cannot_write_the_stack_leaves_the_trap_frame_alone() {
        let mut memory = FakeMemory::new();
        let mut trap = queued_trap();
        // Move the interrupted stack below the fake window: the frame range is
        // unwritable and delivery must fail before touching anything.
        trap.user_rsp = BASE - 0x1000;
        let mut context = sample_context();
        context.rsp = BASE - 0x1000;
        let action = custom_action(0x0040_4000, 0x0040_5000, 0);
        assert_eq!(
            deliver_handler(&mut trap, &action, 10, &context, 0, &mut memory),
            Err(errno::EFAULT)
        );
        assert_eq!(trap.rip, 0x0040_1234);
        assert_eq!(trap.user_rsp, BASE - 0x1000);
        assert_eq!(trap.rdi, 0);
    }

    #[test]
    fn rt_sigreturn_validates_the_frame_at_the_syscall_time_rsp() {
        let mut memory = FakeMemory::new();
        let mut trap = queued_trap();
        let context = sample_context();
        let action = custom_action(0x0040_4000, 0x0040_5000, 0);
        deliver_handler(&mut trap, &action, 10, &context, 0, &mut memory).expect("delivery");
        // The handler ran and the restorer's `syscall` executes with `rsp` at
        // the frame start: the `ret` from the handler popped the restorer slot.
        trap.user_rsp += 8;
        assert_eq!(validate_user_frame(&trap, &mut memory), Ok(()));

        // A syscall whose rsp does not point at a frame is rejected.
        let mut bad = queued_trap();
        bad.user_rsp = BASE + 0x400;
        assert_eq!(validate_user_frame(&bad, &mut memory), Err(errno::EINVAL));
    }
}
