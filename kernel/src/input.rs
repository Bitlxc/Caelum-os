//! M3 input: 8042 PS/2 keyboard (IRQ1 -> vector `0x21`) and 16550 UART RX
//! (IRQ4 -> vector `0x24`).
//!
//! The platform module owns IOAPIC routing and EOI; the root dispatcher in
//! `lib.rs` calls [`on_keyboard_irq`] / [`on_serial_irq`] and then
//! `platform::eoi()`. Both handlers are deliberately short: read the device,
//! decode/record one event into a fixed-size ring buffer, return. They never
//! format, print, allocate, or take a sleeping lock (agents.md §22).
//!
//! The thread side calls [`wait_for_expected`], which consumes the ring and
//! halts until both injected events have really arrived: the QEMU `send-key a`
//! make scan code `0x1E` and the serial byte `C` (`0x43`). Success therefore
//! always comes from bytes actually read off the devices, never from a flag
//! that has been made up.
//!
//! Pure logic (scan-code decoding and the ring) is host-testable; all hardware
//! access is confined to the `hw_*` helpers and to `crate::log`'s serial
//! register accessors, so `cargo test -p kernel --lib` exercises the logic
//! without touching ports.

#[cfg(not(test))]
use core::arch::asm;
use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

/// 8042 controller status port (bit 0 = output buffer full).
pub const PS2_STATUS_PORT: u16 = 0x64;
/// 8042 controller data port (scan codes from the keyboard).
pub const PS2_DATA_PORT: u16 = 0x60;

/// Keyboard IRQ vector (GSI1 -> `0x21`, shared with `lib.rs`'s table).
pub const KEYBOARD_VECTOR: u8 = crate::IRQ_KEYBOARD as u8;
/// COM1 RX IRQ vector (GSI4 -> `0x24`).
pub const SERIAL_RX_VECTOR: u8 = crate::IRQ_COM1 as u8;

/// Set-1 make code sent by QEMU `send-key a`.
pub const SCANCODE_A_MAKE: u8 = 0x1E;
/// Byte written into the guest UART RX by the M3 acceptance harness.
pub const SERIAL_EXPECTED_BYTE: u8 = b'C';

/// Ring capacity (power of two, enough for the M3 bootstrap: 2 keyboard bytes
/// plus 1 serial byte, with room for autoprint traffic).
pub const RING_CAPACITY: usize = 64;

/// A decoded input event, as kept in the ring between IRQ and thread context.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum InputEvent {
    /// Ordinary (non-extended) set-1 make code, e.g. `0x1E` for `a`.
    KeyPress(u8),
    /// Set-1 break code with the `0x80` bit stripped, e.g. `0x1E` for `a` up.
    KeyRelease(u8),
    /// Raw byte received on the UART.
    Serial(u8),
}

/// Set-1 scan-code decoder.
///
/// The 8042 sends an `0xE0`/`0xE1` prefix *before* the code it extends, so the
/// prefix state has to survive across two interrupt reads. M3 only needs
/// ordinary keys; extended codes are consumed and dropped, and the controller
/// ack/echo bytes are not key events.
#[derive(Clone, Copy, Debug, Default)]
pub struct ScanDecoder {
    extended: bool,
}

impl ScanDecoder {
    pub const fn new() -> Self {
        Self { extended: false }
    }

    /// Feed one byte read from port 0x60.
    pub fn feed(&mut self, byte: u8) -> Option<InputEvent> {
        let prefix = byte == 0xE0 || byte == 0xE1;
        let was_extended = core::mem::replace(&mut self.extended, prefix);
        if prefix || was_extended {
            return None;
        }
        // 0xFA = controller ACK, 0xEE = echo: not key events.
        if byte == 0xFA || byte == 0xEE {
            return None;
        }
        if byte & 0x80 != 0 {
            Some(InputEvent::KeyRelease(byte & 0x7F))
        } else {
            Some(InputEvent::KeyPress(byte))
        }
    }
}

/// Fixed-capacity event ring. Pure data structure: the IRQ side pushes, the
/// thread side pops; a full ring drops the newest event and counts it.
pub struct EventRing {
    slots: [Option<InputEvent>; RING_CAPACITY],
    head: usize,
    tail: usize,
    len: usize,
    dropped: u32,
}

impl EventRing {
    pub const fn new() -> Self {
        Self {
            slots: [None; RING_CAPACITY],
            head: 0,
            tail: 0,
            len: 0,
            dropped: 0,
        }
    }

    pub fn push(&mut self, event: InputEvent) -> bool {
        if self.len == RING_CAPACITY {
            self.dropped = self.dropped.saturating_add(1);
            return false;
        }
        self.slots[self.head] = Some(event);
        self.head = (self.head + 1) % RING_CAPACITY;
        self.len += 1;
        true
    }

    pub fn pop(&mut self) -> Option<InputEvent> {
        if self.len == 0 {
            return None;
        }
        let event = self.slots[self.tail].take();
        self.tail = (self.tail + 1) % RING_CAPACITY;
        self.len -= 1;
        event
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn dropped(&self) -> u32 {
        self.dropped
    }
}

impl Default for EventRing {
    fn default() -> Self {
        Self::new()
    }
}

/// Ring shared between the IRQ handlers and thread context.
///
/// The M3 target is single-CPU, so no lock is needed: every access happens
/// with interrupts disabled (irqsave), which makes the ISR-vs-thread update
/// atomic and keeps a panic inside the section from deadlocking.
struct SharedRing {
    inner: UnsafeCell<EventRing>,
}

// SAFETY: `EventRing` is only ever reached through `SharedRing::with`, which
// runs with maskable interrupts disabled on the single M3 CPU, so at most one
// context touches the ring at a time.
unsafe impl Sync for SharedRing {}

impl SharedRing {
    const fn new() -> Self {
        Self {
            inner: UnsafeCell::new(EventRing::new()),
        }
    }

    fn with<R>(&self, f: impl FnOnce(&mut EventRing) -> R) -> R {
        #[cfg(not(test))]
        let was_enabled = crate::arch::disable_interrupts();
        // SAFETY: see the `Sync` comment above; the borrow ends before
        // interrupts are restored.
        let result = unsafe { f(&mut *self.inner.get()) };
        #[cfg(not(test))]
        crate::arch::restore_interrupts(was_enabled);
        result
    }
}

static RING: SharedRing = SharedRing::new();

/// `0xE0`/`0xE1` prefix seen, waiting for the extended code byte.
static EXTENDED_PREFIX: AtomicBool = AtomicBool::new(false);
static KEY_EVENTS: AtomicU32 = AtomicU32::new(0);
static SERIAL_BYTES: AtomicU32 = AtomicU32::new(0);
static KEY_A_SEEN: AtomicBool = AtomicBool::new(false);
static SERIAL_C_SEEN: AtomicBool = AtomicBool::new(false);
static EXPECTED_RECEIVED: AtomicBool = AtomicBool::new(false);

#[cfg(not(test))]
#[inline]
fn hw_inb(port: u16) -> u8 {
    let value: u8;
    // SAFETY: fixed, documented controller port; no memory is touched.
    unsafe { asm!("in al, dx", out("al") value, in("dx") port) };
    value
}

/// Host stub: there is no 8042 behind the host test build.
#[cfg(test)]
fn hw_inb(_port: u16) -> u8 {
    0x00
}

/// Read and decode one byte from the keyboard data port.
fn record_scancode(byte: u8) -> Option<InputEvent> {
    // `swap` returns the previous prefix state, which is exactly the state the
    // decoder needs before this byte; the new state is "this byte is a prefix".
    let was_extended = EXTENDED_PREFIX.swap(byte == 0xE0 || byte == 0xE1, Ordering::SeqCst);
    let mut decoder = ScanDecoder {
        extended: was_extended,
    };
    let event = decoder.feed(byte);
    EXTENDED_PREFIX.store(decoder.extended, Ordering::SeqCst);
    let Some(event) = event else {
        return None;
    };
    KEY_EVENTS.fetch_add(1, Ordering::SeqCst);
    if event == InputEvent::KeyPress(SCANCODE_A_MAKE) {
        KEY_A_SEEN.store(true, Ordering::SeqCst);
    }
    // M6c：把同一批 make/break 事件路由到 console seat 的对象侧 ring。没有 seat
    // （M3 阶段、或会话尚未建立）时这是零副作用的空操作，ISR 里也不分配、不打印。
    //
    // wire 编码固定为"原始扫描码"：make 就是 scancode；break 必须把解码器剥掉的
    // 0x80 放回去（`KeyRelease(0x20)` → wire `0xA0`），否则用户态无法区分 'd' 的
    // 按下与松开。M3 自己的 ring 保持旧语义（`InputEvent::KeyRelease(code)` 不带
    // 0x80），两套表示互不影响。
    match event {
        InputEvent::KeyPress(code) => {
            crate::ipc::input::publish_keyboard(code);
        }
        InputEvent::KeyRelease(code) => {
            crate::ipc::input::publish_keyboard(code | 0x80);
        }
        InputEvent::Serial(_) => {}
    }
    RING.with(|ring| {
        ring.push(event);
    });
    Some(event)
}

/// PS/2 keyboard IRQ handler. Called by the root dispatcher before EOI.
///
/// Short and allocation-free: only the 8042 output buffer is drained (one
/// byte, as the controller asserts IRQ1 per byte).
pub fn on_keyboard_irq() {
    // The status byte must be read before the data port; bit 0 tells whether
    // the byte came from the keyboard or the (unused-in-M3) auxiliary port.
    if hw_inb(PS2_STATUS_PORT) & 0x01 == 0 {
        return;
    }
    let byte = hw_inb(PS2_DATA_PORT);
    let _ = record_scancode(byte);
}

/// COM1 RX IRQ handler. Called by the root dispatcher before EOI.
///
/// Drains at most one FIFO's worth of bytes so the handler stays short; any
/// remainder keeps the UART line asserted and is collected by the next IRQ.
pub fn on_serial_irq() {
    for _ in 0..16 {
        // LSR bit 0 = RBR/FIFO not empty.
        if !crate::log::serial_rx_ready() {
            return;
        }
        let byte = crate::log::serial_read_rx();
        SERIAL_BYTES.fetch_add(1, Ordering::SeqCst);
        if byte == SERIAL_EXPECTED_BYTE {
            SERIAL_C_SEEN.store(true, Ordering::SeqCst);
        }
        // M6c：每个真实收到的串口字节同时进入 console seat 的对象侧 ring。
        crate::ipc::input::publish_serial(byte);
        RING.with(|ring| {
            ring.push(InputEvent::Serial(byte));
        });
    }
}

/// Initialize the M3 input paths.
///
/// - enable the 16550 "received data available" interrupt (IER bit 0) without
///   touching the polled TX path that `log.rs` owns;
/// - drop bytes already sitting in the UART RX FIFO and stale bytes in the
///   8042 output buffer, so the M3 checks cannot pass on firmware leftovers;
/// - reset the ring and the observation counters for this boot.
///
/// IOAPIC routing (GSI1 -> `0x21`, GSI4 -> `0x24`) belongs to `platform::init`
/// and is deliberately not reprogrammed here.
pub fn init() {
    RING.with(|ring| *ring = EventRing::new());
    EXTENDED_PREFIX.store(false, Ordering::SeqCst);
    KEY_EVENTS.store(0, Ordering::SeqCst);
    SERIAL_BYTES.store(0, Ordering::SeqCst);
    KEY_A_SEEN.store(false, Ordering::SeqCst);
    SERIAL_C_SEEN.store(false, Ordering::SeqCst);
    EXPECTED_RECEIVED.store(false, Ordering::SeqCst);

    // 16550: OR in the RX interrupt bit only; the TX behavior set up by
    // `log::serial_init` (polled THR-empty) stays exactly as it was.
    let ier = crate::log::serial_read_reg(crate::log::REG_IER);
    crate::log::serial_write_reg(crate::log::REG_IER, ier | crate::log::IER_RX_AVAILABLE);

    // Stale UART RX bytes.
    for _ in 0..RING_CAPACITY {
        if !crate::log::serial_rx_ready() {
            break;
        }
        let _ = crate::log::serial_read_rx();
    }

    // Stale 8042 output. A floating bus reads 0xFF (no data): stop rather than
    // spin on it forever.
    for _ in 0..RING_CAPACITY {
        let status = hw_inb(PS2_STATUS_PORT);
        if status & 0x01 == 0 || status == 0xFF {
            break;
        }
        let _ = hw_inb(PS2_DATA_PORT);
    }
}

/// Pop the oldest recorded event, if any.
pub fn pop_event() -> Option<InputEvent> {
    RING.with(|ring| ring.pop())
}

/// Number of keyboard bytes that produced a decoded event.
pub fn keyboard_event_count() -> u32 {
    KEY_EVENTS.load(Ordering::SeqCst)
}

/// Number of bytes received on the UART.
pub fn serial_byte_count() -> u32 {
    SERIAL_BYTES.load(Ordering::SeqCst)
}

/// Events dropped because the ring was full.
pub fn dropped_events() -> u32 {
    RING.with(|ring| ring.dropped())
}

/// `true` once a real `a` make scan code (`0x1E`) has been read.
pub fn keyboard_a_seen() -> bool {
    KEY_A_SEEN.load(Ordering::SeqCst)
}

/// `true` once a real `C` (`0x43`) byte has been read from the UART.
pub fn serial_c_seen() -> bool {
    SERIAL_C_SEEN.load(Ordering::SeqCst)
}

/// `true` once [`wait_for_expected`] observed both injected events.
pub fn expected_received() -> bool {
    EXPECTED_RECEIVED.load(Ordering::SeqCst)
}

/// Block until both injected events have been received.
///
/// Runs in thread context with interrupts enabled (the M3 bootstrap enables
/// them right before this call). The wait is an atomic check-then-`sti; hlt`,
/// so a wakeup cannot be lost between seeing an empty ring and halting, and no
/// CPU is burned spinning. Returns `true` when the keyboard `a` make code and
/// the serial `C` byte were both actually observed in this boot.
pub fn wait_for_expected() -> bool {
    let mut saw_a = false;
    let mut saw_c = false;
    loop {
        // The check and the halt must be one atomic step with respect to
        // interrupts; otherwise an IRQ landing in between would be missed.
        #[cfg(not(test))]
        let was_enabled = crate::arch::disable_interrupts();

        while let Some(event) = pop_event() {
            match event {
                InputEvent::KeyPress(SCANCODE_A_MAKE) => saw_a = true,
                InputEvent::Serial(SERIAL_EXPECTED_BYTE) => saw_c = true,
                _ => {}
            }
        }
        // These flags are only ever set by the handlers from bytes read off the
        // devices; they cover events already consumed by another pop.
        saw_a |= KEY_A_SEEN.load(Ordering::SeqCst);
        saw_c |= SERIAL_C_SEEN.load(Ordering::SeqCst);

        if saw_a && saw_c {
            EXPECTED_RECEIVED.store(true, Ordering::SeqCst);
            #[cfg(not(test))]
            crate::arch::restore_interrupts(was_enabled);
            return true;
        }

        #[cfg(not(test))]
        {
            // `sti; hlt` with the architectural interrupt shadow: the pending
            // IRQ wakes the CPU after `hlt` and is then serviced. If the caller
            // entered with interrupts disabled, enabling them here is what
            // makes this wait progress at all.
            unsafe { asm!("sti; hlt") };
        }
        #[cfg(test)]
        {
            // Host builds have no interrupts: fail instead of hanging.
            return false;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constants_match_the_acceptance_injection() {
        // QEMU `send-key a` make code and the serial byte the harness writes.
        assert_eq!(SCANCODE_A_MAKE, 0x1E);
        assert_eq!(SERIAL_EXPECTED_BYTE, 0x43);
        assert_eq!(SERIAL_EXPECTED_BYTE, b'C');
        assert_eq!(KEYBOARD_VECTOR, 0x21);
        assert_eq!(SERIAL_RX_VECTOR, 0x24);
    }

    #[test]
    fn send_key_a_make_and_break_codes_decode() {
        let mut decoder = ScanDecoder::new();
        assert_eq!(
            decoder.feed(0x1E),
            Some(InputEvent::KeyPress(SCANCODE_A_MAKE))
        );
        // QEMU holds the key for 100 ms, then releases it: 0x80 | 0x1E.
        assert_eq!(
            decoder.feed(0x9E),
            Some(InputEvent::KeyRelease(SCANCODE_A_MAKE))
        );
    }

    #[test]
    fn other_ordinary_keys_decode_too() {
        let mut decoder = ScanDecoder::new();
        assert_eq!(decoder.feed(0x1F), Some(InputEvent::KeyPress(0x1F))); // s
        assert_eq!(decoder.feed(0x39), Some(InputEvent::KeyPress(0x39))); // space
    }

    #[test]
    fn extended_prefix_is_consumed_across_two_reads() {
        let mut decoder = ScanDecoder::new();
        assert_eq!(decoder.feed(0xE0), None);
        assert_eq!(decoder.feed(0x48), None); // up arrow: not needed in M3
        assert_eq!(decoder.feed(0x1E), Some(InputEvent::KeyPress(0x1E)));
    }

    #[test]
    fn controller_ack_and_echo_are_not_keys() {
        let mut decoder = ScanDecoder::new();
        assert_eq!(decoder.feed(0xFA), None); // ACK
        assert_eq!(decoder.feed(0xEE), None); // echo
        assert_eq!(decoder.feed(0x1E), Some(InputEvent::KeyPress(0x1E)));
    }

    #[test]
    fn ring_is_fifo_and_reports_full() {
        let mut ring = EventRing::new();
        assert!(ring.is_empty());
        for i in 0..RING_CAPACITY {
            assert!(ring.push(InputEvent::Serial(i as u8)));
        }
        assert_eq!(ring.len(), RING_CAPACITY);
        assert!(!ring.push(InputEvent::Serial(0xFF)));
        assert_eq!(ring.dropped(), 1);
        assert_eq!(ring.len(), RING_CAPACITY);
        for i in 0..RING_CAPACITY {
            assert_eq!(ring.pop(), Some(InputEvent::Serial(i as u8)));
        }
        assert!(ring.is_empty());
        assert_eq!(ring.pop(), None);
    }

    #[test]
    fn ring_wraps_without_losing_event_order() {
        let mut ring = EventRing::new();
        // Fill, then drain half so head/tail wrap around the array.
        for i in 0..RING_CAPACITY {
            assert!(ring.push(InputEvent::KeyPress(i as u8)));
        }
        for i in 0..RING_CAPACITY / 2 {
            assert_eq!(ring.pop(), Some(InputEvent::KeyPress(i as u8)));
        }
        for i in 0..RING_CAPACITY / 2 {
            assert!(ring.push(InputEvent::Serial(0x80 | i as u8)));
        }
        for i in RING_CAPACITY / 2..RING_CAPACITY {
            assert_eq!(ring.pop(), Some(InputEvent::KeyPress(i as u8)));
        }
        for i in 0..RING_CAPACITY / 2 {
            assert_eq!(ring.pop(), Some(InputEvent::Serial(0x80 | i as u8)));
        }
        assert!(ring.is_empty());
    }

    #[test]
    fn mixed_keyboard_and_serial_events_keep_order() {
        let mut ring = EventRing::new();
        assert!(ring.push(InputEvent::KeyPress(0x1E)));
        assert!(ring.push(InputEvent::Serial(b'C')));
        assert!(ring.push(InputEvent::KeyRelease(0x1E)));
        assert_eq!(ring.pop(), Some(InputEvent::KeyPress(0x1E)));
        assert_eq!(ring.pop(), Some(InputEvent::Serial(b'C')));
        assert_eq!(ring.pop(), Some(InputEvent::KeyRelease(0x1E)));
        assert_eq!(ring.pop(), None);
    }

    /// M6c 回归：console seat 的 wire 事件必须保留 break 位。
    ///
    /// 'd' 的 make 扫描码是 0x20，break 是 0xA0。解码器在 break 上剥掉 0x80，
    /// 所以 `record_scancode(0xA0)` 得到 `KeyRelease(0x20)`；把它转发到对象侧
    /// ring 时必须还原成 0xA0，否则用户态会把 'd' 的松开误当成又一次按下
    /// （0x20）。同时 M3 自己的 ring 语义保持不变（仍是 `KeyRelease(0x20)`）。
    #[test]
    fn keyboard_break_publishes_the_release_bit_to_the_console_seat() {
        // 共享全局 seat 表与对象销毁钩子，必须与 ipc::input 的测试串行化。
        let _guard = crate::object::test_lock();
        crate::object::reset_destroy_hooks();
        crate::ipc::input::reset();

        let seat = crate::object::create_with_payload(crate::object::ObjectKind::Input, 0)
            .expect("input object");
        assert!(crate::ipc::input::create(seat).is_ok());

        // make → break，两次都真实经过 ISR 解码路径。
        assert_eq!(record_scancode(0x20), Some(InputEvent::KeyPress(0x20)));
        assert_eq!(record_scancode(0xA0), Some(InputEvent::KeyRelease(0x20)));

        let mut out = [crate::ipc::input::InputEventWire::EMPTY; 4];
        assert_eq!(crate::ipc::input::read(seat, &mut out), 2);
        assert_eq!(out[0].kind, crate::ipc::input::KIND_KEYBOARD);
        assert_eq!(out[0].code, 0x20, "make must keep the raw scancode");
        assert_eq!(out[0].sequence, 1);
        assert_eq!(out[1].kind, crate::ipc::input::KIND_KEYBOARD);
        assert_eq!(out[1].code, 0xA0, "break must carry the release bit");
        assert_eq!(out[1].sequence, 2);
        assert_ne!(out[0].code, out[1].code, "press and release must differ");

        // M3 旧 ring 语义不变：KeyRelease 仍是不带 0x80 的原始键码。
        assert_eq!(pop_event(), Some(InputEvent::KeyPress(0x20)));
        assert_eq!(pop_event(), Some(InputEvent::KeyRelease(0x20)));
        assert_eq!(pop_event(), None);

        let _ = crate::object::release_object(seat);
        crate::ipc::input::reset();
    }
}
