//! CaelumOS `gfx`: the M6c display + input program.
//!
//! The kernel starts exactly one instance on AP1 and hands it three initial
//! handles: `console` (write-only Console), `display` (the display object) and
//! `input` (the input object). The program only uses the syscalls M6c allows
//! (write, abi_query, wait, handle_close, process_exit and NR 40..43); the
//! kernel-side allow-list is owned by the syscall layer.
//!
//! Sequence:
//!
//! 1. `abi_query` must report the ABI this binary was built against
//!    ([`native_abi::ABI_VERSION`]); a mismatch exits before touching display or
//!    input.
//! 2. `display_info` must report a 256000-byte RAM shadow (320x200x4; the
//!    shadow is ordinary mapped RAM, never a register/MMIO window).
//! 3. `display_map` maps the whole shadow read-write; clear it, draw a 64x64
//!    green square at (16,16) and a 64x64 blue square at (96,16), then
//!    `display_present` publishes the full 320x200 frame to the framebuffer.
//! 4. Block on `input` and drain it until the five expected events arrive:
//!    Keyboard 0x20/0xA0 then Serial `m`/`6`/`c`, with `sequence` 1..=5 and a
//!    non-decreasing `timestamp_ms`. Because the kernel hands events out in
//!    queue order with contiguous sequence numbers, observing 1..=5 is also the
//!    proof that nothing was dropped.
//! 5. Close the mapping and the three handles, then exit 0.
//!
//! Failures print one diagnostic line (the program owns `console`) and exit
//! with a non-zero code so the kernel-side log is enough to locate the step.

#![no_std]
#![no_main]

use core::ptr;
use native_abi::{
    ABI_VERSION, DISPLAY_FRAME_BYTES, Handle, INPUT_EVENT_KIND_KEYBOARD, INPUT_EVENT_KIND_SERIAL,
    INPUT_EVENTS_MAX, InputEventWire, PROT_READ, PROT_WRITE, ShmMapRequest, WAIT_TIMEOUT_INFINITE,
};
use native_rt as rt;

/// M6c frame geometry (the shadow is `320 * 200 * 4` bytes).
const FRAME_WIDTH: u32 = 320;
const FRAME_HEIGHT: u32 = 200;

/// Squares drawn by this program: (x, y, width, height).
const GREEN_RECT: (u32, u32, u32, u32) = (16, 16, 64, 64);
const BLUE_RECT: (u32, u32, u32, u32) = (96, 16, 64, 64);

/// Green as stored in the shadow. The shadow uses the fixed logical layout
/// `0x00RRGGBB` for both 32-bit GOP formats; the kernel converts to the
/// framebuffer's byte order when it presents, so the program must not
/// pre-swap channels.
const GREEN_PIXEL: u32 = 0x0000_FF00;

/// Blue in the same fixed logical layout (`0x00RRGGBB`): red=none, green=none,
/// blue=0xFF. Derived purely from the logical value, never from `pixel_format`.
const BLUE_PIXEL: u32 = 0x0000_00FF;

/// The five input events M6c expects, in delivery order.
///
/// `Keyboard 0x20` is the `d` key down and `0xA0` is the `d` key up (the release
/// bit is bit 7); the three serial events are the characters `m`, `6`, `c` that
/// the acceptance boot feeds through the serial input port.
const EXPECTED_EVENTS: [(u32, u32); 5] = [
    (INPUT_EVENT_KIND_KEYBOARD, 0x20),
    (INPUT_EVENT_KIND_KEYBOARD, 0xA0),
    (INPUT_EVENT_KIND_SERIAL, b'm' as u32),
    (INPUT_EVENT_KIND_SERIAL, b'6' as u32),
    (INPUT_EVENT_KIND_SERIAL, b'c' as u32),
];

/// Exit codes (0 is success). Each failing step has its own code so the
/// kernel-side exit diagnostic identifies the step.
const EXIT_ABI_VERSION: u64 = 0x70;
const EXIT_ABI_STATUS: u64 = 0x71;
const EXIT_DISPLAY_INFO: u64 = 0x72;
const EXIT_SHADOW_BYTES: u64 = 0x73;
const EXIT_DISPLAY_MAP: u64 = 0x74;
const EXIT_DISPLAY_PRESENT: u64 = 0x75;
const EXIT_INPUT_WAIT: u64 = 0x76;
const EXIT_INPUT_READ: u64 = 0x77;
const EXIT_INPUT_EVENT: u64 = 0x78;
const EXIT_INPUT_SEQUENCE: u64 = 0x79;
const EXIT_INPUT_TIMESTAMP: u64 = 0x7a;

/// Best-effort console write; diagnostics must never panic.
fn print(console: Handle, bytes: &[u8]) {
    let _ = rt::write_all(console, bytes);
}

/// Appends `bytes` to a small fixed line buffer (truncating on overflow).
fn push_bytes(line: &mut [u8; 64], len: &mut usize, bytes: &[u8]) {
    for byte in bytes {
        if *len < line.len() {
            line[*len] = *byte;
            *len += 1;
        }
    }
}

/// Appends a lowercase hex number without leading zeros.
fn push_hex(line: &mut [u8; 64], len: &mut usize, value: u64) {
    let mut digits = [0u8; 16];
    let mut count = 0;
    let mut rest = value;
    loop {
        digits[count] = b"0123456789abcdef"[(rest & 0xf) as usize];
        count += 1;
        rest >>= 4;
        if rest == 0 {
            break;
        }
    }
    push_bytes(line, len, b"0x");
    while count > 0 {
        count -= 1;
        push_bytes(line, len, &[digits[count]]);
    }
}

/// Appends a decimal number.
fn push_dec(line: &mut [u8; 64], len: &mut usize, value: u64) {
    let mut digits = [0u8; 20];
    let mut count = 0;
    let mut rest = value;
    loop {
        digits[count] = b'0' + (rest % 10) as u8;
        count += 1;
        rest /= 10;
        if rest == 0 {
            break;
        }
    }
    while count > 0 {
        count -= 1;
        push_bytes(line, len, &[digits[count]]);
    }
}

/// Prints one diagnostic line with an observed value and exits non-zero.
///
/// Used for the numeric failures (event properties) where the raw value is
/// what makes the kernel-side log actionable.
fn fail_hex(console: Handle, message: &[u8], label: &[u8], value: u64, code: u64) -> ! {
    let mut line = [0u8; 64];
    let mut len = 0;
    push_bytes(&mut line, &mut len, message);
    push_bytes(&mut line, &mut len, label);
    push_hex(&mut line, &mut len, value);
    push_bytes(&mut line, &mut len, b"\n");
    print(console, &line[..len]);
    rt::process_exit(code)
}

/// Fills an axis-aligned rectangle in the shadow.
///
/// # Safety
///
/// The shadow is mapped read-write for [`DISPLAY_FRAME_BYTES`] bytes and the
/// rectangle lies inside `stride x height`, which is checked by the caller.
unsafe fn fill_rect(base: *mut u32, stride: u32, rect: (u32, u32, u32, u32), color: u32) {
    let (x, y, width, height) = rect;
    for row in 0..height {
        // SAFETY: see the function contract; the base pointer only moves to
        // rows/columns inside the shadow validated by the caller.
        let start = unsafe { base.add(((y + row) * stride + x) as usize) };
        for column in 0..width {
            // SAFETY: see the function contract; every write stays inside the
            // shadow because the caller validated the rectangle fits.
            unsafe { ptr::write(start.add(column as usize), color) };
        }
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn _start(console: Handle, display: Handle, input: Handle) -> ! {
    // Phase 0: the ABI this binary was built against must be the one running.
    // `ABI_VERSION` comes from the shared crate, so an ABI bump can never leave
    // this binary hard-coding a stale version word.
    match rt::abi_query() {
        Ok(version) if version == ABI_VERSION => {}
        Ok(_) => rt::process_exit(EXIT_ABI_VERSION),
        Err(_) => rt::process_exit(EXIT_ABI_STATUS),
    }

    // Phase 1: display info. M6c uses a RAM shadow, so the byte count is the
    // contract; a mismatch means the kernel and this program disagree on the
    // format, which is reported instead of drawing into an unknown layout.
    let mut info = native_abi::DisplayInfoWire::empty();
    if rt::display_info(display, &mut info).is_err() {
        print(console, b"[CaelumGfx] FAIL display info\n");
        rt::process_exit(EXIT_DISPLAY_INFO);
    }
    if info.shadow_bytes != u64::from(DISPLAY_FRAME_BYTES) {
        fail_hex(
            console,
            b"[CaelumGfx] FAIL shadow bytes ",
            b"observed=",
            info.shadow_bytes,
            EXIT_SHADOW_BYTES,
        );
    }
    // The squares and the full-frame present are placed for exactly 320x200;
    // refuse to draw into any other geometry instead of writing at guessed
    // offsets.
    if info.width != FRAME_WIDTH || info.height != FRAME_HEIGHT {
        fail_hex(
            console,
            b"[CaelumGfx] FAIL frame size ",
            b"width=",
            u64::from(info.width),
            EXIT_DISPLAY_INFO,
        );
    }

    // Phase 2: map the shadow read-write and paint the two squares.
    let mut map_request = ShmMapRequest::new(PROT_READ | PROT_WRITE, 0);
    let (mapping, base) = match rt::display_map(display, &mut map_request) {
        Ok(mapped) => mapped,
        Err(_) => {
            print(console, b"[CaelumGfx] FAIL display map\n");
            rt::process_exit(EXIT_DISPLAY_MAP);
        }
    };
    if base == 0 {
        print(console, b"[CaelumGfx] FAIL display map base 0x0\n");
        rt::process_exit(EXIT_DISPLAY_MAP);
    }
    // SAFETY: `display_map` mapped exactly DISPLAY_FRAME_BYTES read-write at
    // `base`; the rectangles were validated against width/height above, and
    // stride >= width is part of the reported layout.
    unsafe {
        ptr::write_bytes(base as *mut u8, 0, DISPLAY_FRAME_BYTES as usize);
        fill_rect(base as *mut u32, info.stride, GREEN_RECT, GREEN_PIXEL);
        fill_rect(base as *mut u32, info.stride, BLUE_RECT, BLUE_PIXEL);
    }

    // Phase 3: publish the whole frame and announce the display half.
    if rt::display_present(display).is_err() {
        print(console, b"[CaelumGfx] FAIL display present\n");
        rt::process_exit(EXIT_DISPLAY_PRESENT);
    }
    print(console, b"[CaelumGfx] M6c display OK\n");
    print(console, b"[CaelumGfx] M6c input ready\n");

    // Phase 4: drain the input queue. `input_read` never blocks: an empty
    // queue returns 0 and we then block in `wait` until more events arrive.
    let mut events = [InputEventWire::empty(); INPUT_EVENTS_MAX as usize];
    let mut collected = 0usize;
    let mut last_timestamp = 0u64;
    while collected < EXPECTED_EVENTS.len() {
        let remaining = EXPECTED_EVENTS.len() - collected;
        let count = match rt::input_read(input, &mut events[..remaining]) {
            Ok(0) => {
                if rt::wait_one(input, 0, WAIT_TIMEOUT_INFINITE).is_err() {
                    print(console, b"[CaelumGfx] FAIL input wait\n");
                    rt::process_exit(EXIT_INPUT_WAIT);
                }
                continue;
            }
            Ok(count) => count,
            Err(_) => {
                print(console, b"[CaelumGfx] FAIL input read\n");
                rt::process_exit(EXIT_INPUT_READ);
            }
        };
        for offset in 0..count {
            let event = events[offset];
            let index = collected + offset;
            let expected = EXPECTED_EVENTS[index];
            if event.kind != expected.0 || event.code != expected.1 {
                let mut line = [0u8; 64];
                let mut len = 0;
                push_bytes(&mut line, &mut len, b"[CaelumGfx] FAIL input event index=");
                push_dec(&mut line, &mut len, index as u64);
                push_bytes(&mut line, &mut len, b" kind=");
                push_hex(&mut line, &mut len, u64::from(event.kind));
                push_bytes(&mut line, &mut len, b" code=");
                push_hex(&mut line, &mut len, u64::from(event.code));
                push_bytes(&mut line, &mut len, b"\n");
                print(console, &line[..len]);
                rt::process_exit(EXIT_INPUT_EVENT);
            }
            // The kernel numbers events from 1 in queue order; a contiguous
            // 1..=5 run is the M6c "no event was dropped" proof.
            let expected_sequence = (index + 1) as u32;
            if event.sequence != expected_sequence {
                fail_hex(
                    console,
                    b"[CaelumGfx] FAIL input sequence ",
                    b"observed=",
                    u64::from(event.sequence),
                    EXIT_INPUT_SEQUENCE,
                );
            }
            if event.timestamp_ms < last_timestamp {
                fail_hex(
                    console,
                    b"[CaelumGfx] FAIL input timestamp ",
                    b"observed=",
                    event.timestamp_ms,
                    EXIT_INPUT_TIMESTAMP,
                );
            }
            last_timestamp = event.timestamp_ms;
        }
        collected += count;
    }
    print(console, b"[CaelumGfx] M6c input OK (events=5, dropped=0)\n");

    // Phase 5: release everything this program owns. Close failures are
    // ignored: the process-exit path reaps any handle that is still open.
    let _ = rt::handle_close(mapping);
    let _ = rt::handle_close(input);
    let _ = rt::handle_close(display);
    let _ = rt::handle_close(console);
    rt::process_exit(0);
}
