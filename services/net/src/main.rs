//! CaelumOS M7b native socket self-test (`caelum-net`, fifth boot module).
//!
//! One ELF runs twice: the first instance is the parent (role 1), which creates
//! a child process from the same module (`process_create("net")`) and drives a
//! twelve-phase protocol over an `ipc` channel. The child (role 2) is the
//! connector/client side; the parent is the listener/server side. Every control
//! message and the two socketpair endpoints travel through the channel; no
//! global path is used to bypass the capability model.
//!
//! The parent prints thirteen `[CaelumNet] M7b ... OK` markers in order and then
//! exits 0 after `process_wait(child) == 0`. The child prints nothing on the
//! happy path. Any failure prints a diagnostic line that does not contain "OK"
//! and exits non-zero.
//!
//! Byte-exact payloads use [`pattern_byte`]: byte `i` of a chunk is
//! `(i * 37 + seed) & 0xff`.

#![no_std]
#![no_main]

use native_abi::{
    ABI_VERSION, ERR_BAD_HANDLE, ERR_BAD_RIGHT, ERR_EXISTS, ERR_NOT_CONNECTED, ERR_NOT_FOUND,
    ERR_PEER_CLOSED, ERR_TIMEOUT, ERR_TOO_LARGE, ERR_WOULD_BLOCK, HANDLE_NONE, Handle,
    IPC_KIND_CHANNEL, IPC_KIND_TIMER, IpcMessageMeta, IpcSendRequest, ProcessCreateRequest,
    RIGHT_READ, RIGHT_WAIT, RIGHT_WRITE, SOCKET_ADDR_LOCAL, SOCKET_DOMAIN_INET,
    SOCKET_DOMAIN_INET6, SOCKET_DOMAIN_UNIX, SOCKET_FAMILY_INET, SOCKET_FAMILY_INET6,
    SOCKET_FAMILY_UNIX, SOCKET_KIND_DGRAM, SOCKET_KIND_STREAM, SOCKET_PATH_MAX,
    SOCKET_SHUTDOWN_WRITE, SocketAddrWire, WAIT_TIMEOUT_IMMEDIATE, WAIT_TIMEOUT_INFINITE,
    WAKE_READY, WAKE_TIMEOUT,
};
use native_rt as rt;

// ---------------------------------------------------------------------------
// Protocol constants
// ---------------------------------------------------------------------------

/// Channel routing id for every message of this self-test.
const PROTOCOL: u32 = 0x4E45_5432;
/// Channel message version echoed in `IpcMessageMeta::version`.
const MSG_VERSION: u32 = 1;
/// Inline control message length.
const MSG_LEN: usize = 32;

const OP_ROLE: u32 = 1;
const OP_GO: u32 = 2;
const OP_DONE: u32 = 3;
const OP_PAIR: u32 = 4;
const OP_DRAIN: u32 = 5;
const OP_RESUME: u32 = 6;
const OP_FAULT_NEXT: u32 = 7;
/// Phase 9 handshake: the child reports that the stream is filled (it saw its
/// second `WOULD_BLOCK`), so the parent may safely start draining.
const OP_FILLED: u32 = 8;

const ROLE_CHILD: u32 = 2;

/// Ticks used for one bounded wait before retrying a non-blocking call.
const WAIT_TICKS: u32 = 10;
/// Upper bound on retries for a single non-blocking operation.
const ATTEMPTS: u32 = 200;
/// Upper bound on messages drained from one queue.
const DRAIN_LIMIT: usize = 4096;
/// Upper bound on `process_wait` polls before declaring the child stuck.
const WAIT_POLLS: usize = 100_000;
/// Phase 9: bytes the child fills into the UNIX stream before blocking.
const BACKPRESSURE_STREAM_FILL: usize = 4096;
/// Phase 9: single recovery chunk the child sends once the parent frees space.
const BACKPRESSURE_RECOVERY: usize = 64;
/// Phase 9: exact total the parent must receive (fill + recovery).
const BACKPRESSURE_TOTAL: usize = BACKPRESSURE_STREAM_FILL + BACKPRESSURE_RECOVERY;

/// Channel messages are 32 bytes: `op | phase | arg0 | arg1 | status | extra`.
const MSG_DATA_MAX: usize = 64;

// Parent exit codes (the child uses `0xa0 + phase`).
const EXIT_SETUP: u64 = 0x80;
const EXIT_ROLE: u64 = 0x81;
const EXIT_CHILD: u64 = 0x82;
const EXIT_PROTOCOL: u64 = 0x83;
const EXIT_DATA: u64 = 0x84;
const EXIT_PHASE_BASE: u64 = 0x90;
const EXIT_CHILD_PHASE_BASE: u64 = 0xa0;

// Named UNIX paths bound inside the caller's NetNamespace.
const PATH_STREAM: &[u8] = b"/net-m7b-stream";
const PATH_DGRAM: &[u8] = b"/net-m7b-dgram";
const PATH_DUP: &[u8] = b"/net-m7b-dup";
const PATH_MISSING: &[u8] = b"/net-m7b-missing";

// Payload seeds: every direction uses its own seed so a mixed-up transfer is
// detected instead of accidentally matching.
const SEED_UDP4_UP: u8 = 0x11;
const SEED_UDP4_DOWN: u8 = 0x12;
const SEED_UDP6_UP: u8 = 0x13;
const SEED_UDP6_DOWN: u8 = 0x14;
const SEED_TCP4_UP: u8 = 0x21;
const SEED_TCP4_DOWN: u8 = 0x22;
const SEED_TCP6_UP: u8 = 0x23;
const SEED_TCP6_DOWN: u8 = 0x24;
const SEED_PAIR_SEND_STREAM: u8 = 0x51;
const SEED_PAIR_SEND_DGRAM: u8 = 0x52;
const SEED_PAIR_RECV_STREAM: u8 = 0x53;
const SEED_PAIR_RECV_DGRAM: u8 = 0x54;
const SEED_UNIX_STREAM: u8 = 0x61;
const SEED_UNIX_DGRAM: u8 = 0x71;
const SEED_WAIT: u8 = 0x81;
const SEED_SHUTDOWN: u8 = 0xa1;
const SEED_FAULT_DGRAM: u8 = 0xb1;
/// One-byte acknowledgement of the UNIX stream phase.
const UNIX_STREAM_ACK: u8 = 0xa5;

// The thirteen markers, in the order they must appear on the console.
const MARKER_UDP4: &[u8] = b"[CaelumNet] M7b udp4 OK (bytes=7)\n";
const MARKER_UDP6: &[u8] = b"[CaelumNet] M7b udp6 OK (bytes=7)\n";
const MARKER_TCP4: &[u8] = b"[CaelumNet] M7b tcp4 OK (bytes=14)\n";
const MARKER_TCP6: &[u8] = b"[CaelumNet] M7b tcp6 OK (bytes=14)\n";
const MARKER_SOCKETPAIR: &[u8] = b"[CaelumNet] M7b socketpair OK (pairs=2,bytes=1024)\n";
const MARKER_UNIX_STREAM: &[u8] = b"[CaelumNet] M7b unix stream OK (bytes=1024)\n";
const MARKER_UNIX_DGRAM: &[u8] = b"[CaelumNet] M7b unix dgram OK (bytes=512)\n";
const MARKER_WAIT: &[u8] = b"[CaelumNet] M7b wait OK (ready=1,timeouts=1)\n";
const MARKER_BACKPRESSURE: &[u8] = b"[CaelumNet] M7b backpressure OK (would_block=2)\n";
const MARKER_SHUTDOWN: &[u8] = b"[CaelumNet] M7b shutdown OK (eof=1)\n";
const MARKER_RIGHTS: &[u8] = b"[CaelumNet] M7b rights OK (bad_handle=1,bad_right=1)\n";
const MARKER_FAULTS: &[u8] =
    b"[CaelumNet] M7b faults OK (too_large=1,not_found=1,exists=1,peer_closed=1)\n";
const MARKER_DONE: &[u8] = b"[CaelumNet] M7b OK (child=0)\n";

// ---------------------------------------------------------------------------
// Control message wire format
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct Msg {
    op: u32,
    phase: u32,
    arg0: u64,
    arg1: u64,
    status: u32,
    extra: u32,
}

fn encode(msg: Msg) -> [u8; MSG_LEN] {
    let mut out = [0u8; MSG_LEN];
    out[0..4].copy_from_slice(&msg.op.to_le_bytes());
    out[4..8].copy_from_slice(&msg.phase.to_le_bytes());
    out[8..16].copy_from_slice(&msg.arg0.to_le_bytes());
    out[16..24].copy_from_slice(&msg.arg1.to_le_bytes());
    out[24..28].copy_from_slice(&msg.status.to_le_bytes());
    out[28..32].copy_from_slice(&msg.extra.to_le_bytes());
    out
}

fn decode(data: &[u8]) -> Option<Msg> {
    if data.len() < MSG_LEN {
        return None;
    }
    Some(Msg {
        op: u32::from_le_bytes([data[0], data[1], data[2], data[3]]),
        phase: u32::from_le_bytes([data[4], data[5], data[6], data[7]]),
        arg0: u64::from_le_bytes([
            data[8], data[9], data[10], data[11], data[12], data[13], data[14], data[15],
        ]),
        arg1: u64::from_le_bytes([
            data[16], data[17], data[18], data[19], data[20], data[21], data[22], data[23],
        ]),
        status: u32::from_le_bytes([data[24], data[25], data[26], data[27]]),
        extra: u32::from_le_bytes([data[28], data[29], data[30], data[31]]),
    })
}

fn send_msg(chan: Handle, msg: Msg) -> Result<(), u64> {
    send_msg_handles(chan, msg, &[], &[])
}

fn send_msg_handles(chan: Handle, msg: Msg, handles: &[Handle], rights: &[u32]) -> Result<(), u64> {
    let data = encode(msg);
    let mut request = IpcSendRequest::new(PROTOCOL, MSG_VERSION, msg.phase as u64);
    request.data_ptr = data.as_ptr() as u64;
    request.data_len = MSG_LEN as u32;
    request.handle_count = handles.len() as u32;
    request.handles_ptr = handles.as_ptr() as u64;
    request.rights_ptr = rights.as_ptr() as u64;
    rt::ipc_send(chan, &mut request)?;
    Ok(())
}

fn recv_msg(
    chan: Handle,
    handles: &mut [Handle],
    rights: &mut [u32],
    timeout_ticks: u64,
) -> Result<(Msg, usize), u64> {
    let mut data = [0u8; MSG_DATA_MAX];
    let mut meta = IpcMessageMeta::empty();
    let len = rt::ipc_recv(chan, &mut data, handles, rights, &mut meta, timeout_ticks)?;
    if meta.protocol != PROTOCOL || meta.version != MSG_VERSION {
        return Err(EXIT_PROTOCOL);
    }
    let msg = decode(&data[..len]).ok_or(EXIT_PROTOCOL)?;
    Ok((msg, meta.handle_count as usize))
}

/// Receives until a message with `(op, phase)` arrives, tolerating timeouts.
fn recv_expect(chan: Handle, op: u32, phase: u32) -> Result<Msg, u64> {
    let mut handles = [HANDLE_NONE; 2];
    let mut rights = [0u32; 2];
    for _ in 0..ATTEMPTS {
        match recv_msg(chan, &mut handles, &mut rights, u64::from(WAIT_TICKS)) {
            Ok((msg, _)) => {
                if msg.op == op && msg.phase == phase {
                    return Ok(msg);
                }
                return Err(EXIT_PROTOCOL);
            }
            Err(ERR_WOULD_BLOCK) | Err(ERR_TIMEOUT) => continue,
            Err(error) => return Err(error),
        }
    }
    Err(ERR_TIMEOUT)
}

// ---------------------------------------------------------------------------
// Console diagnostics
// ---------------------------------------------------------------------------

fn push(out: &mut [u8], len: &mut usize, bytes: &[u8]) {
    for byte in bytes {
        if *len < out.len() {
            out[*len] = *byte;
            *len += 1;
        }
    }
}

fn push_dec(out: &mut [u8], len: &mut usize, mut value: u64) {
    let mut digits = [0u8; 20];
    let mut count = 0;
    if value == 0 {
        digits[0] = b'0';
        count = 1;
    } else {
        while value > 0 {
            digits[count] = b'0' + (value % 10) as u8;
            value /= 10;
            count += 1;
        }
    }
    while count > 0 {
        count -= 1;
        if *len < out.len() {
            out[*len] = digits[count];
            *len += 1;
        }
    }
}

fn write_marker(console: Handle, marker: &[u8]) -> Result<(), u64> {
    rt::write_all(console, marker)
}

fn print_fail(console: Handle, phase: u32, code: u64) {
    let mut line = [0u8; 72];
    let mut len = 0;
    push(&mut line, &mut len, b"[CaelumNet] FAIL phase=");
    push_dec(&mut line, &mut len, u64::from(phase));
    push(&mut line, &mut len, b" status=");
    push_dec(&mut line, &mut len, code);
    push(&mut line, &mut len, b"\n");
    let _ = rt::write_all(console, &line[..len]);
}

fn print_child_fail(console: Handle, phase: u32, code: u64) {
    let mut line = [0u8; 80];
    let mut len = 0;
    push(&mut line, &mut len, b"[CaelumNet] child FAIL phase=");
    push_dec(&mut line, &mut len, u64::from(phase));
    push(&mut line, &mut len, b" status=");
    push_dec(&mut line, &mut len, code);
    push(&mut line, &mut len, b"\n");
    let _ = rt::write_all(console, &line[..len]);
}

// ---------------------------------------------------------------------------
// Payload patterns and address builders
// ---------------------------------------------------------------------------

fn pattern_byte(index: usize, seed: u8) -> u8 {
    (index.wrapping_mul(37).wrapping_add(seed as usize) & 0xff) as u8
}

fn fill_pattern(out: &mut [u8], seed: u8) {
    for (index, byte) in out.iter_mut().enumerate() {
        *byte = pattern_byte(index, seed);
    }
}

fn pattern_matches(data: &[u8], seed: u8) -> bool {
    data.iter()
        .enumerate()
        .all(|(index, byte)| *byte == pattern_byte(index, seed))
}

fn any_address(family: u32) -> SocketAddrWire {
    let mut address = SocketAddrWire::empty();
    address.family = family;
    address.port = 0;
    if family == SOCKET_FAMILY_INET {
        address.addr[0] = 127;
        address.addr[3] = 1;
    } else {
        address.addr[15] = 1;
    }
    address
}

fn loopback_address(family: u32, port: u32) -> SocketAddrWire {
    let mut address = any_address(family);
    address.port = port;
    address
}

fn unix_address(path: &[u8]) -> Result<SocketAddrWire, u64> {
    if path.is_empty() || path.len() > SOCKET_PATH_MAX as usize {
        return Err(EXIT_PROTOCOL);
    }
    let mut address = SocketAddrWire::empty();
    address.family = SOCKET_FAMILY_UNIX;
    address.path_len = path.len() as u32;
    address.path[..path.len()].copy_from_slice(path);
    Ok(address)
}

// ---------------------------------------------------------------------------
// Non-blocking socket helpers (bounded retries; never spin forever)
// ---------------------------------------------------------------------------

fn wait_ready(object: Handle, ticks: u32) -> Result<u32, u64> {
    match rt::wait_one(object, 0, ticks) {
        Ok(out) => Ok(out.wake_reason),
        // A bounded wait that expires is a normal outcome, not an error: `wait`
        // reports it through `ERR_TIMEOUT`. Turn it back into the `WAKE_TIMEOUT`
        // reason so a caller can tell "the wait ended because the tick budget
        // ran out" (phase 8 asserts exactly that) from a real failure; the
        // retry helpers simply use that reason to try again within their own
        // bounded attempt count. Every other error is still propagated.
        Err(ERR_TIMEOUT) => Ok(WAKE_TIMEOUT),
        Err(error) => Err(error),
    }
}

fn connect_retry(socket: Handle, address: &SocketAddrWire) -> Result<(), u64> {
    let mut tries = 0u32;
    loop {
        match rt::socket_connect(socket, address) {
            Ok(()) => return Ok(()),
            Err(ERR_WOULD_BLOCK) if tries < ATTEMPTS => {
                tries += 1;
                let _ = wait_ready(socket, WAIT_TICKS)?;
            }
            Err(error) => return Err(error),
        }
    }
}

fn accept_retry(listener: Handle) -> Result<Handle, u64> {
    let mut tries = 0u32;
    loop {
        match rt::socket_accept(listener) {
            Ok(peer) => return Ok(peer),
            Err(ERR_WOULD_BLOCK) if tries < ATTEMPTS => {
                tries += 1;
                let _ = wait_ready(listener, WAIT_TICKS)?;
            }
            Err(error) => return Err(error),
        }
    }
}

fn send_all(socket: Handle, data: &[u8]) -> Result<(), u64> {
    let mut sent = 0usize;
    let mut tries = 0u32;
    while sent < data.len() {
        match rt::socket_send(socket, &data[sent..]) {
            Ok(0) => return Err(EXIT_PROTOCOL),
            Ok(count) => {
                sent += count;
                tries = 0;
            }
            Err(ERR_WOULD_BLOCK) if tries < ATTEMPTS => {
                tries += 1;
                let _ = wait_ready(socket, WAIT_TICKS)?;
            }
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

fn recv_retry(socket: Handle, buffer: &mut [u8]) -> Result<usize, u64> {
    let mut tries = 0u32;
    loop {
        match rt::socket_recv(socket, buffer, None) {
            Ok(count) => return Ok(count),
            Err(ERR_WOULD_BLOCK) if tries < ATTEMPTS => {
                tries += 1;
                let _ = wait_ready(socket, WAIT_TICKS)?;
            }
            Err(error) => return Err(error),
        }
    }
}

fn recv_source_retry(
    socket: Handle,
    buffer: &mut [u8],
    source: &mut SocketAddrWire,
) -> Result<usize, u64> {
    let mut tries = 0u32;
    loop {
        match rt::socket_recv(socket, buffer, Some(&mut *source)) {
            Ok(count) => return Ok(count),
            Err(ERR_WOULD_BLOCK) if tries < ATTEMPTS => {
                tries += 1;
                let _ = wait_ready(socket, WAIT_TICKS)?;
            }
            Err(error) => return Err(error),
        }
    }
}

fn recv_exact(socket: Handle, buffer: &mut [u8]) -> Result<usize, u64> {
    let mut got = 0usize;
    let mut tries = 0u32;
    while got < buffer.len() {
        match rt::socket_recv(socket, &mut buffer[got..], None) {
            Ok(0) => return Err(EXIT_DATA),
            Ok(count) => {
                got += count;
                tries = 0;
            }
            Err(ERR_WOULD_BLOCK) if tries < ATTEMPTS => {
                tries += 1;
                let _ = wait_ready(socket, WAIT_TICKS)?;
            }
            Err(error) => return Err(error),
        }
    }
    Ok(got)
}

/// Drains everything currently queued on `socket`; returns the number of reads.
fn drain(socket: Handle, buffer: &mut [u8]) -> Result<usize, u64> {
    let mut reads = 0usize;
    loop {
        match rt::socket_recv(socket, buffer, None) {
            Ok(_) => {
                reads += 1;
                if reads > DRAIN_LIMIT {
                    return Err(EXIT_PROTOCOL);
                }
            }
            Err(ERR_WOULD_BLOCK) => return Ok(reads),
            Err(error) => return Err(error),
        }
    }
}

// ---------------------------------------------------------------------------
// Parent phases
// ---------------------------------------------------------------------------

fn phase_udp(
    console: Handle,
    chan: Handle,
    domain: u32,
    family: u32,
    phase: u32,
    seed_up: u8,
    seed_down: u8,
    bytes: usize,
    marker: &[u8],
) -> Result<(), u64> {
    let server = rt::socket_create(domain, SOCKET_KIND_DGRAM, HANDLE_NONE)?;
    rt::socket_bind(server, &any_address(family))?;
    let mut local = SocketAddrWire::empty();
    rt::socket_address(server, SOCKET_ADDR_LOCAL, &mut local)?;

    send_msg(
        chan,
        Msg {
            op: OP_GO,
            phase,
            arg0: u64::from(local.port),
            ..Msg::default()
        },
    )?;

    let mut buffer = [0u8; 64];
    let mut source = SocketAddrWire::empty();
    let received = recv_source_retry(server, &mut buffer, &mut source)?;
    if received != bytes || !pattern_matches(&buffer[..received], seed_up) {
        let _ = rt::handle_close(server);
        return Err(EXIT_DATA);
    }
    connect_retry(server, &source)?;
    let mut reply = [0u8; 64];
    fill_pattern(&mut reply[..bytes], seed_down);
    send_all(server, &reply[..bytes])?;

    let done = recv_expect(chan, OP_DONE, phase)?;
    let _ = rt::handle_close(server);
    if done.status != 0 || done.arg0 as usize != bytes {
        return Err(EXIT_PROTOCOL);
    }
    write_marker(console, marker)
}

fn phase_tcp(
    console: Handle,
    chan: Handle,
    domain: u32,
    family: u32,
    phase: u32,
    seed_up: u8,
    seed_down: u8,
    bytes: usize,
    marker: &[u8],
) -> Result<(), u64> {
    let listener = rt::socket_create(domain, SOCKET_KIND_STREAM, HANDLE_NONE)?;
    rt::socket_bind(listener, &any_address(family))?;
    rt::socket_listen(listener, 2)?;
    let mut local = SocketAddrWire::empty();
    rt::socket_address(listener, SOCKET_ADDR_LOCAL, &mut local)?;

    send_msg(
        chan,
        Msg {
            op: OP_GO,
            phase,
            arg0: u64::from(local.port),
            ..Msg::default()
        },
    )?;

    let connection = accept_retry(listener)?;
    let mut buffer = [0u8; 64];
    let received = recv_exact(connection, &mut buffer[..bytes])?;
    if received != bytes || !pattern_matches(&buffer[..bytes], seed_up) {
        let _ = rt::handle_close(connection);
        let _ = rt::handle_close(listener);
        return Err(EXIT_DATA);
    }
    let mut reply = [0u8; 64];
    fill_pattern(&mut reply[..bytes], seed_down);
    send_all(connection, &reply[..bytes])?;

    let done = recv_expect(chan, OP_DONE, phase)?;
    let _ = rt::handle_close(connection);
    let _ = rt::handle_close(listener);
    if done.status != 0 || done.arg0 as usize != bytes {
        return Err(EXIT_PROTOCOL);
    }
    write_marker(console, marker)
}

/// Phase 5: two socketpairs, one end of each transferred to the child over the
/// channel; 1024 bytes cross the two pairs in both directions.
fn phase_socketpair(console: Handle, chan: Handle) -> Result<(Handle, Handle), u64> {
    let (stream_a, stream_b) = rt::socketpair(SOCKET_DOMAIN_UNIX, SOCKET_KIND_STREAM)?;
    let (dgram_a, dgram_b) = rt::socketpair(SOCKET_DOMAIN_UNIX, SOCKET_KIND_DGRAM)?;
    let handles = [stream_b, dgram_b];
    // WAIT is required by the unified `wait` call: phase 9 parks on the stream
    // endpoint while the kernel buffer drains, so the transferred duplicates must
    // keep WAIT as well (a legal subset of the pair's READ|WRITE|WAIT rights).
    let rights = [
        RIGHT_READ | RIGHT_WRITE | RIGHT_WAIT,
        RIGHT_READ | RIGHT_WRITE | RIGHT_WAIT,
    ];
    send_msg_handles(
        chan,
        Msg {
            op: OP_PAIR,
            phase: 5,
            ..Msg::default()
        },
        &handles,
        &rights,
    )?;
    send_msg(
        chan,
        Msg {
            op: OP_GO,
            phase: 5,
            ..Msg::default()
        },
    )?;
    // The child owns duplicates of both endpoints now.
    let _ = rt::handle_close(stream_b);
    let _ = rt::handle_close(dgram_b);

    let mut out = [0u8; 256];
    fill_pattern(&mut out, SEED_PAIR_SEND_STREAM);
    send_all(stream_a, &out)?;
    fill_pattern(&mut out, SEED_PAIR_SEND_DGRAM);
    send_all(dgram_a, &out)?;

    let mut incoming = [0u8; 256];
    recv_exact(stream_a, &mut incoming)?;
    if !pattern_matches(&incoming, SEED_PAIR_RECV_STREAM) {
        return Err(EXIT_DATA);
    }
    let count = recv_retry(dgram_a, &mut incoming)?;
    if count != incoming.len() || !pattern_matches(&incoming, SEED_PAIR_RECV_DGRAM) {
        return Err(EXIT_DATA);
    }

    let done = recv_expect(chan, OP_DONE, 5)?;
    if done.status != 0 || done.arg0 != 1024 {
        return Err(EXIT_PROTOCOL);
    }
    write_marker(console, MARKER_SOCKETPAIR)?;
    Ok((stream_a, dgram_a))
}

/// Phase 6: named UNIX stream socket under the NetNamespace; 1024 bytes flow
/// parent -> child, followed by a one-byte acknowledgement.
fn phase_unix_stream(console: Handle, chan: Handle, netns: Handle) -> Result<(), u64> {
    let listener = rt::socket_create(SOCKET_DOMAIN_UNIX, SOCKET_KIND_STREAM, netns)?;
    rt::socket_bind(listener, &unix_address(PATH_STREAM)?)?;
    rt::socket_listen(listener, 2)?;
    send_msg(
        chan,
        Msg {
            op: OP_GO,
            phase: 6,
            ..Msg::default()
        },
    )?;

    let connection = accept_retry(listener)?;
    let mut data = [0u8; 1024];
    fill_pattern(&mut data, SEED_UNIX_STREAM);
    send_all(connection, &data)?;
    let mut ack = [0u8; 1];
    let received = recv_retry(connection, &mut ack)?;
    if received != 1 || ack[0] != UNIX_STREAM_ACK {
        let _ = rt::handle_close(connection);
        let _ = rt::handle_close(listener);
        return Err(EXIT_DATA);
    }

    let done = recv_expect(chan, OP_DONE, 6)?;
    let _ = rt::handle_close(connection);
    let _ = rt::handle_close(listener);
    if done.status != 0 || done.arg0 != 1024 {
        return Err(EXIT_PROTOCOL);
    }
    write_marker(console, MARKER_UNIX_STREAM)
}

/// Phase 7: named UNIX datagram socket; one 512-byte message, boundary intact.
fn phase_unix_dgram(console: Handle, chan: Handle, netns: Handle) -> Result<(), u64> {
    let socket = rt::socket_create(SOCKET_DOMAIN_UNIX, SOCKET_KIND_DGRAM, netns)?;
    rt::socket_bind(socket, &unix_address(PATH_DGRAM)?)?;
    send_msg(
        chan,
        Msg {
            op: OP_GO,
            phase: 7,
            ..Msg::default()
        },
    )?;

    let mut buffer = [0u8; 600];
    let received = recv_retry(socket, &mut buffer)?;
    if received != 512 || !pattern_matches(&buffer[..512], SEED_UNIX_DGRAM) {
        let _ = rt::handle_close(socket);
        return Err(EXIT_DATA);
    }

    let done = recv_expect(chan, OP_DONE, 7)?;
    let _ = rt::handle_close(socket);
    if done.status != 0 || done.arg0 != 512 {
        return Err(EXIT_PROTOCOL);
    }
    write_marker(console, MARKER_UNIX_DGRAM)
}

/// Phase 8: a wait that times out once on an idle socket and then reports real
/// readiness once the child (after a short timer sleep) sends a datagram.
fn phase_wait(console: Handle, chan: Handle) -> Result<(), u64> {
    let socket = rt::socket_create(SOCKET_DOMAIN_INET, SOCKET_KIND_DGRAM, HANDLE_NONE)?;
    rt::socket_bind(socket, &any_address(SOCKET_FAMILY_INET))?;
    let mut local = SocketAddrWire::empty();
    rt::socket_address(socket, SOCKET_ADDR_LOCAL, &mut local)?;
    send_msg(
        chan,
        Msg {
            op: OP_GO,
            phase: 8,
            arg0: u64::from(local.port),
            ..Msg::default()
        },
    )?;

    let timeout_reason = wait_ready(socket, 3)?;
    if timeout_reason != WAKE_TIMEOUT {
        let _ = rt::handle_close(socket);
        return Err(EXIT_DATA);
    }
    let ready_reason = wait_ready(socket, WAIT_TIMEOUT_INFINITE)?;
    if ready_reason != WAKE_READY {
        let _ = rt::handle_close(socket);
        return Err(EXIT_DATA);
    }
    let mut byte = [0u8; 8];
    let received = recv_retry(socket, &mut byte)?;
    if received != 1 || byte[0] != pattern_byte(0, SEED_WAIT) {
        let _ = rt::handle_close(socket);
        return Err(EXIT_DATA);
    }

    let done = recv_expect(chan, OP_DONE, 8)?;
    let _ = rt::handle_close(socket);
    if done.status != 0 || done.arg0 != 1 {
        return Err(EXIT_PROTOCOL);
    }
    write_marker(console, MARKER_WAIT)
}

/// Phase 9: fill a UDP receive queue and a UNIX stream buffer; both senders see
/// `WOULD_BLOCK`, and both recover after the parent drains.
fn phase_backpressure(console: Handle, chan: Handle, stream: Handle) -> Result<(), u64> {
    let udp = rt::socket_create(SOCKET_DOMAIN_INET, SOCKET_KIND_DGRAM, HANDLE_NONE)?;
    rt::socket_bind(udp, &any_address(SOCKET_FAMILY_INET))?;
    let mut local = SocketAddrWire::empty();
    rt::socket_address(udp, SOCKET_ADDR_LOCAL, &mut local)?;
    send_msg(
        chan,
        Msg {
            op: OP_GO,
            phase: 9,
            arg0: u64::from(local.port),
            ..Msg::default()
        },
    )?;

    let mut buffer = [0u8; 256];
    drain(udp, &mut buffer)?;
    send_msg(
        chan,
        Msg {
            op: OP_DRAIN,
            phase: 9,
            ..Msg::default()
        },
    )?;
    // Deterministic handshake: wait until the child reports that the stream hit
    // its full capacity (the second WOULD_BLOCK) before releasing it. Reading
    // earlier raced with the fill loop, so the child might never see the full
    // buffer and the total could drift past fill+recovery.
    recv_expect(chan, OP_FILLED, 9)?;
    send_msg(
        chan,
        Msg {
            op: OP_RESUME,
            phase: 9,
            ..Msg::default()
        },
    )?;
    // Deterministic drain: the child filled the stream's 4096-byte buffer and
    // now blocks waiting for space to send its recovery chunk. Reading the
    // exact fill+recovery total is what frees that space, guarantees the
    // recovery bytes land here, and leaves phase 10 on an empty buffer. Any
    // extra data means the backpressure protocol diverged.
    let mut drained = 0usize;
    loop {
        let received = recv_retry(stream, &mut buffer)?;
        if received == 0 || drained + received > BACKPRESSURE_TOTAL {
            return Err(EXIT_PROTOCOL);
        }
        drained += received;
        if drained == BACKPRESSURE_TOTAL {
            break;
        }
    }

    let done = recv_expect(chan, OP_DONE, 9)?;
    let _ = rt::handle_close(udp);
    if done.status != 0 || done.arg0 != 2 {
        return Err(EXIT_PROTOCOL);
    }
    write_marker(console, MARKER_BACKPRESSURE)
}

/// Phase 10: half-close. The child writes 16 bytes and shuts down its write
/// side; the parent reads the data and then observes EOF (a 0-byte read).
fn phase_shutdown(console: Handle, chan: Handle, stream: Handle) -> Result<(), u64> {
    send_msg(
        chan,
        Msg {
            op: OP_GO,
            phase: 10,
            ..Msg::default()
        },
    )?;

    let mut data = [0u8; 16];
    let received = recv_exact(stream, &mut data)?;
    if received != 16 || !pattern_matches(&data, SEED_SHUTDOWN) {
        return Err(EXIT_DATA);
    }

    // After the peer's write shutdown the next read must report EOF.
    let mut tries = 0u32;
    let mut byte = [0u8; 8];
    let eof = loop {
        match rt::socket_recv(stream, &mut byte, None) {
            Ok(0) => break 1u32,
            Ok(_) => return Err(EXIT_DATA),
            Err(ERR_WOULD_BLOCK) if tries < ATTEMPTS => {
                tries += 1;
                let _ = wait_ready(stream, WAIT_TICKS)?;
            }
            Err(error) => return Err(error),
        }
    };

    let done = recv_expect(chan, OP_DONE, 10)?;
    if done.status != 0 || done.arg0 != 16 || eof != 1 {
        return Err(EXIT_PROTOCOL);
    }
    write_marker(console, MARKER_SHUTDOWN)
}

/// Phase 11: an unknown socket handle is rejected with `BAD_HANDLE`, and a
/// named UNIX socket created without a NetNamespace is rejected with
/// `BAD_RIGHT`.
fn phase_rights(console: Handle, chan: Handle) -> Result<(), u64> {
    send_msg(
        chan,
        Msg {
            op: OP_GO,
            phase: 11,
            ..Msg::default()
        },
    )?;

    let mut byte = [0u8; 8];
    let bad_handle = matches!(
        rt::socket_recv(0x0000_FFFF, &mut byte, None),
        Err(ERR_BAD_HANDLE)
    );

    let bad_right = match rt::socket_create(SOCKET_DOMAIN_UNIX, SOCKET_KIND_STREAM, HANDLE_NONE) {
        Ok(socket) => {
            let rejected = matches!(
                rt::socket_bind(socket, &unix_address(PATH_STREAM)?),
                Err(ERR_BAD_RIGHT)
            );
            let _ = rt::handle_close(socket);
            rejected
        }
        Err(ERR_BAD_RIGHT) => true,
        Err(error) => return Err(error),
    };

    let done = recv_expect(chan, OP_DONE, 11)?;
    if done.status != 0 || !bad_handle || !bad_right {
        return Err(EXIT_PROTOCOL);
    }
    write_marker(console, MARKER_RIGHTS)
}

/// Phase 12: four fault paths — an oversized datagram is not consumed, a
/// missing path reports `NOT_FOUND`, a duplicate bind reports `EXISTS`, and a
/// send to a closed peer reports `PEER_CLOSED`.
fn phase_faults(console: Handle, chan: Handle, netns: Handle, dgram: Handle) -> Result<(), u64> {
    send_msg(
        chan,
        Msg {
            op: OP_GO,
            phase: 12,
            ..Msg::default()
        },
    )?;

    // (a) 16-byte datagram into an 8-byte buffer: TOO_LARGE, message kept.
    // Wait for real readability first: the child only sends its datagram after
    // receiving GO, so probing with the short buffer before that arrives would
    // just report WOULD_BLOCK and misread the fault as missing.
    if wait_ready(dgram, WAIT_TIMEOUT_INFINITE)? != WAKE_READY {
        return Err(EXIT_DATA);
    }
    let mut small = [0u8; 8];
    let too_large = matches!(rt::socket_recv(dgram, &mut small, None), Err(ERR_TOO_LARGE));
    let mut full = [0u8; 32];
    let received = recv_retry(dgram, &mut full)?;
    let too_large_intact = received == 16 && pattern_matches(&full[..16], SEED_FAULT_DGRAM);

    // (b) duplicate bind on the same named path: EXISTS.
    let duplicate = rt::socket_create(SOCKET_DOMAIN_UNIX, SOCKET_KIND_DGRAM, netns)?;
    rt::socket_bind(duplicate, &unix_address(PATH_DUP)?)?;
    let exists = matches!(
        rt::socket_bind(duplicate, &unix_address(PATH_DUP)?),
        Err(ERR_EXISTS)
    );
    let _ = rt::handle_close(duplicate);

    // Ask the child to connect to a missing path and then close its datagram
    // endpoint so the peer-closed check below becomes observable.
    send_msg(
        chan,
        Msg {
            op: OP_FAULT_NEXT,
            phase: 12,
            ..Msg::default()
        },
    )?;

    let mut sentinel = [0u8; 1];
    sentinel[0] = 0xee;
    let mut peer_closed = false;
    let mut tries = 0u32;
    while tries < ATTEMPTS {
        match rt::socket_send(dgram, &sentinel) {
            Err(ERR_PEER_CLOSED) => {
                peer_closed = true;
                break;
            }
            Err(ERR_WOULD_BLOCK) => {
                tries += 1;
                let _ = wait_ready(dgram, WAIT_TICKS)?;
            }
            Ok(_) => {
                tries += 1;
                let _ = wait_ready(dgram, WAIT_TICKS)?;
            }
            Err(error) => return Err(error),
        }
    }

    let done = recv_expect(chan, OP_DONE, 12)?;
    if done.status != 0
        || done.arg0 != 1
        || !too_large
        || !too_large_intact
        || !exists
        || !peer_closed
    {
        return Err(EXIT_PROTOCOL);
    }
    write_marker(console, MARKER_FAULTS)
}

/// Phase 13: reaps the child and requires exit status 0.
fn phase_reap(console: Handle, child: Handle) -> Result<(), u64> {
    let mut polls = 0usize;
    loop {
        match rt::process_wait(child) {
            Ok(status) => {
                if status != 0 {
                    return Err(EXIT_CHILD);
                }
                break;
            }
            Err(ERR_WOULD_BLOCK) if polls < WAIT_POLLS => {
                polls += 1;
                rt::pause();
            }
            Err(error) => return Err(error),
        }
    }
    write_marker(console, MARKER_DONE)
}

// ---------------------------------------------------------------------------
// Parent
// ---------------------------------------------------------------------------

macro_rules! phase_step {
    ($console:expr, $phase:expr, $call:expr) => {
        match $call {
            Ok(value) => value,
            Err(code) => {
                print_fail($console, $phase, code);
                rt::process_exit(EXIT_PHASE_BASE + ($phase) as u64);
            }
        }
    };
}

fn run_parent(console: Handle, root_channel: Handle, netns: Handle) -> ! {
    if rt::abi_query().ok() != Some(ABI_VERSION) {
        print_fail(console, 0, EXIT_SETUP);
        rt::process_exit(EXIT_SETUP);
    }

    // The parent keeps role 1 and drives every phase; a private channel pair
    // carries control messages and the transferred socketpair endpoints.
    let (channel_child, channel_parent) =
        phase_step!(console, 0, rt::ipc_create_pair(IPC_KIND_CHANNEL, 0));

    // Seed the child's role before it starts, so the first thing the child sees
    // on its endpoint is the role message (its own start-up discriminator).
    phase_step!(
        console,
        0,
        send_msg(
            channel_parent,
            Msg {
                op: OP_ROLE,
                arg0: u64::from(ROLE_CHILD),
                ..Msg::default()
            }
        )
    );

    let mut request = ProcessCreateRequest::with_module_name(b"net");
    if !request.push_handle(console, RIGHT_WRITE)
        || !request.push_handle(channel_child, RIGHT_READ | RIGHT_WRITE)
        || !request.push_handle(netns, RIGHT_READ | RIGHT_WRITE)
    {
        print_fail(console, 0, EXIT_SETUP);
        rt::process_exit(EXIT_SETUP);
    }
    let child = phase_step!(console, 0, rt::process_create(&request));
    let _ = rt::handle_close(channel_child);

    phase_step!(
        console,
        1,
        phase_udp(
            console,
            channel_parent,
            SOCKET_DOMAIN_INET,
            SOCKET_FAMILY_INET,
            1,
            SEED_UDP4_UP,
            SEED_UDP4_DOWN,
            7,
            MARKER_UDP4
        )
    );
    phase_step!(
        console,
        2,
        phase_udp(
            console,
            channel_parent,
            SOCKET_DOMAIN_INET6,
            SOCKET_FAMILY_INET6,
            2,
            SEED_UDP6_UP,
            SEED_UDP6_DOWN,
            7,
            MARKER_UDP6
        )
    );
    phase_step!(
        console,
        3,
        phase_tcp(
            console,
            channel_parent,
            SOCKET_DOMAIN_INET,
            SOCKET_FAMILY_INET,
            3,
            SEED_TCP4_UP,
            SEED_TCP4_DOWN,
            14,
            MARKER_TCP4
        )
    );
    phase_step!(
        console,
        4,
        phase_tcp(
            console,
            channel_parent,
            SOCKET_DOMAIN_INET6,
            SOCKET_FAMILY_INET6,
            4,
            SEED_TCP6_UP,
            SEED_TCP6_DOWN,
            14,
            MARKER_TCP6
        )
    );
    let (stream_a, dgram_a) = phase_step!(console, 5, phase_socketpair(console, channel_parent));
    phase_step!(
        console,
        6,
        phase_unix_stream(console, channel_parent, netns)
    );
    phase_step!(console, 7, phase_unix_dgram(console, channel_parent, netns));
    phase_step!(console, 8, phase_wait(console, channel_parent));
    phase_step!(
        console,
        9,
        phase_backpressure(console, channel_parent, stream_a)
    );
    phase_step!(
        console,
        10,
        phase_shutdown(console, channel_parent, stream_a)
    );
    phase_step!(console, 11, phase_rights(console, channel_parent));
    phase_step!(
        console,
        12,
        phase_faults(console, channel_parent, netns, dgram_a)
    );
    phase_step!(console, 13, phase_reap(console, child));

    let _ = rt::handle_close(stream_a);
    let _ = rt::handle_close(dgram_a);
    let _ = rt::handle_close(child);
    let _ = rt::handle_close(channel_parent);
    let _ = rt::handle_close(root_channel);
    rt::process_exit(0)
}

// ---------------------------------------------------------------------------
// Child phases
// ---------------------------------------------------------------------------

/// Waits for `GO(phase)`, consuming any interleaved `PAIR` message first.
fn wait_go(chan: Handle, phase: u32, stream: &mut Handle, dgram: &mut Handle) -> Result<Msg, u64> {
    for _ in 0..ATTEMPTS {
        let mut handles = [HANDLE_NONE; 2];
        let mut rights = [0u32; 2];
        match recv_msg(chan, &mut handles, &mut rights, u64::from(WAIT_TICKS)) {
            Ok((msg, count)) => {
                if msg.op == OP_PAIR {
                    if count != 2 || handles[0] == HANDLE_NONE || handles[1] == HANDLE_NONE {
                        return Err(EXIT_PROTOCOL);
                    }
                    let wanted = RIGHT_READ | RIGHT_WRITE;
                    if rights[0] & wanted != wanted || rights[1] & wanted != wanted {
                        return Err(EXIT_PROTOCOL);
                    }
                    *stream = handles[0];
                    *dgram = handles[1];
                    continue;
                }
                if msg.op == OP_GO && msg.phase == phase {
                    return Ok(msg);
                }
                return Err(EXIT_PROTOCOL);
            }
            Err(ERR_WOULD_BLOCK) | Err(ERR_TIMEOUT) => continue,
            Err(error) => return Err(error),
        }
    }
    Err(ERR_TIMEOUT)
}

fn child_phase_udp(
    chan: Handle,
    phase: u32,
    port: u32,
    domain: u32,
    family: u32,
    seed_up: u8,
    seed_down: u8,
    bytes: usize,
) -> Result<u64, u64> {
    let socket = rt::socket_create(domain, SOCKET_KIND_DGRAM, HANDLE_NONE)?;
    connect_retry(socket, &loopback_address(family, port))?;

    let mut data = [0u8; 64];
    fill_pattern(&mut data[..bytes], seed_up);
    send_all(socket, &data[..bytes])?;

    let mut reply = [0u8; 64];
    let received = recv_exact(socket, &mut reply[..bytes])?;
    let _ = rt::handle_close(socket);
    if received != bytes || !pattern_matches(&reply[..bytes], seed_down) {
        return Err(EXIT_DATA);
    }
    let _ = chan;
    let _ = phase;
    Ok(bytes as u64)
}

fn child_phase_tcp(
    chan: Handle,
    phase: u32,
    port: u32,
    domain: u32,
    family: u32,
    seed_up: u8,
    seed_down: u8,
    bytes: usize,
) -> Result<u64, u64> {
    let socket = rt::socket_create(domain, SOCKET_KIND_STREAM, HANDLE_NONE)?;
    connect_retry(socket, &loopback_address(family, port))?;

    let mut data = [0u8; 64];
    fill_pattern(&mut data[..bytes], seed_up);
    send_all(socket, &data[..bytes])?;

    let mut reply = [0u8; 64];
    let received = recv_exact(socket, &mut reply[..bytes])?;
    let _ = rt::handle_close(socket);
    if received != bytes || !pattern_matches(&reply[..bytes], seed_down) {
        return Err(EXIT_DATA);
    }
    let _ = chan;
    let _ = phase;
    Ok(bytes as u64)
}

fn child_phase_socketpair(stream: Handle, dgram: Handle) -> Result<u64, u64> {
    let mut out = [0u8; 256];
    fill_pattern(&mut out, SEED_PAIR_RECV_STREAM);
    send_all(stream, &out)?;
    fill_pattern(&mut out, SEED_PAIR_RECV_DGRAM);
    send_all(dgram, &out)?;

    let mut incoming = [0u8; 256];
    recv_exact(stream, &mut incoming)?;
    if !pattern_matches(&incoming, SEED_PAIR_SEND_STREAM) {
        return Err(EXIT_DATA);
    }
    let count = recv_retry(dgram, &mut incoming)?;
    if count != incoming.len() || !pattern_matches(&incoming, SEED_PAIR_SEND_DGRAM) {
        return Err(EXIT_DATA);
    }
    Ok(1024)
}

fn child_phase_unix_stream(netns: Handle) -> Result<u64, u64> {
    let socket = rt::socket_create(SOCKET_DOMAIN_UNIX, SOCKET_KIND_STREAM, netns)?;
    connect_retry(socket, &unix_address(PATH_STREAM)?)?;
    let mut data = [0u8; 1024];
    recv_exact(socket, &mut data)?;
    if !pattern_matches(&data, SEED_UNIX_STREAM) {
        let _ = rt::handle_close(socket);
        return Err(EXIT_DATA);
    }
    send_all(socket, &[UNIX_STREAM_ACK])?;
    let _ = rt::handle_close(socket);
    Ok(1024)
}

fn child_phase_unix_dgram(netns: Handle) -> Result<u64, u64> {
    let socket = rt::socket_create(SOCKET_DOMAIN_UNIX, SOCKET_KIND_DGRAM, netns)?;
    connect_retry(socket, &unix_address(PATH_DGRAM)?)?;
    let mut data = [0u8; 512];
    fill_pattern(&mut data, SEED_UNIX_DGRAM);
    send_all(socket, &data)?;
    let _ = rt::handle_close(socket);
    Ok(512)
}

fn child_phase_wait(port: u32) -> Result<u64, u64> {
    // Sleep long enough that the parent's first (timeout) wait expires first.
    let timer = rt::ipc_create_kind(IPC_KIND_TIMER, 0, 0, 0)?;
    rt::timer_arm(timer, 5, 0)?;
    let _ = rt::wait_one(timer, 0, WAIT_TIMEOUT_INFINITE)?;
    let _ = rt::handle_close(timer);

    let socket = rt::socket_create(SOCKET_DOMAIN_INET, SOCKET_KIND_DGRAM, HANDLE_NONE)?;
    connect_retry(socket, &loopback_address(SOCKET_FAMILY_INET, port))?;
    let byte = [pattern_byte(0, SEED_WAIT)];
    send_all(socket, &byte)?;
    let _ = rt::handle_close(socket);
    Ok(1)
}

fn child_phase_backpressure(chan: Handle, port: u32, stream: Handle) -> Result<u64, u64> {
    let socket = rt::socket_create(SOCKET_DOMAIN_INET, SOCKET_KIND_DGRAM, HANDLE_NONE)?;
    connect_retry(socket, &loopback_address(SOCKET_FAMILY_INET, port))?;

    let chunk = [0u8; 64];
    let mut would_block = 0u64;
    let mut filled = false;
    for _ in 0..DRAIN_LIMIT {
        match rt::socket_send(socket, &chunk) {
            Ok(_) => continue,
            Err(ERR_WOULD_BLOCK) => {
                would_block += 1;
                filled = true;
                break;
            }
            Err(error) => return Err(error),
        }
    }
    if !filled {
        let _ = rt::handle_close(socket);
        return Err(EXIT_DATA);
    }
    recv_expect(chan, OP_DRAIN, 9)?;

    let mut stream_filled = false;
    for _ in 0..DRAIN_LIMIT {
        match rt::socket_send(stream, &chunk) {
            Ok(_) => continue,
            Err(ERR_WOULD_BLOCK) => {
                would_block += 1;
                stream_filled = true;
                break;
            }
            Err(error) => return Err(error),
        }
    }
    if !stream_filled {
        let _ = rt::handle_close(socket);
        return Err(EXIT_DATA);
    }
    // Report the deterministically filled buffer so the parent only starts
    // draining after our second WOULD_BLOCK; it then frees space for the
    // recovery chunk below.
    send_msg(
        chan,
        Msg {
            op: OP_FILLED,
            phase: 9,
            ..Msg::default()
        },
    )?;
    recv_expect(chan, OP_RESUME, 9)?;
    // One more send must succeed after the parent drained the stream.
    let mut sent = false;
    let mut tries = 0u32;
    while tries < ATTEMPTS {
        match rt::socket_send(stream, &chunk) {
            Ok(_) => {
                sent = true;
                break;
            }
            Err(ERR_WOULD_BLOCK) => {
                tries += 1;
                let _ = wait_ready(stream, WAIT_TICKS)?;
            }
            Err(error) => return Err(error),
        }
    }
    let _ = rt::handle_close(socket);
    if !sent {
        return Err(EXIT_DATA);
    }
    Ok(would_block)
}

fn child_phase_shutdown(stream: Handle) -> Result<u64, u64> {
    let mut data = [0u8; 16];
    fill_pattern(&mut data, SEED_SHUTDOWN);
    send_all(stream, &data)?;
    rt::socket_shutdown(stream, SOCKET_SHUTDOWN_WRITE)?;
    // Writing after the local write shutdown must be refused by the kernel.
    let refused = matches!(
        rt::socket_send(stream, &[0x5a]),
        Err(ERR_NOT_CONNECTED) | Err(ERR_PEER_CLOSED)
    );
    if !refused {
        return Err(EXIT_DATA);
    }
    Ok(16)
}

fn child_phase_rights() -> Result<u64, u64> {
    Ok(0)
}

fn child_phase_faults(chan: Handle, netns: Handle, dgram: Handle) -> Result<u64, u64> {
    let mut data = [0u8; 16];
    fill_pattern(&mut data, SEED_FAULT_DGRAM);
    send_all(dgram, &data)?;

    recv_expect(chan, OP_FAULT_NEXT, 12)?;

    // Connecting to a path that does not exist reports NOT_FOUND; a path that
    // exists without a listener would report CONNECTION_REFUSED (not used here).
    let socket = rt::socket_create(SOCKET_DOMAIN_UNIX, SOCKET_KIND_STREAM, netns)?;
    let missing = matches!(
        connect_retry(socket, &unix_address(PATH_MISSING)?),
        Err(ERR_NOT_FOUND)
    );
    let _ = rt::handle_close(socket);

    // Closing the datagram endpoint makes the parent's later send fail with
    // PEER_CLOSED.
    let _ = rt::handle_close(dgram);

    if !missing {
        return Err(EXIT_DATA);
    }
    Ok(1)
}

// ---------------------------------------------------------------------------
// Child
// ---------------------------------------------------------------------------

fn run_child(console: Handle, chan: Handle, netns: Handle) -> ! {
    if rt::abi_query().ok() != Some(ABI_VERSION) {
        print_child_fail(console, 0, EXIT_SETUP);
        rt::process_exit(EXIT_CHILD_PHASE_BASE);
    }

    let mut stream = HANDLE_NONE;
    let mut dgram = HANDLE_NONE;

    macro_rules! child_step {
        ($phase:expr, $call:expr) => {
            match $call {
                Ok(value) => value,
                Err(code) => {
                    print_child_fail(console, $phase, code);
                    rt::process_exit(EXIT_CHILD_PHASE_BASE + ($phase) as u64);
                }
            }
        };
    }

    for phase in 1u32..=12 {
        let go = child_step!(phase, wait_go(chan, phase, &mut stream, &mut dgram));
        let result = match phase {
            1 => child_phase_udp(
                chan,
                phase,
                go.arg0 as u32,
                SOCKET_DOMAIN_INET,
                SOCKET_FAMILY_INET,
                SEED_UDP4_UP,
                SEED_UDP4_DOWN,
                7,
            ),
            2 => child_phase_udp(
                chan,
                phase,
                go.arg0 as u32,
                SOCKET_DOMAIN_INET6,
                SOCKET_FAMILY_INET6,
                SEED_UDP6_UP,
                SEED_UDP6_DOWN,
                7,
            ),
            3 => child_phase_tcp(
                chan,
                phase,
                go.arg0 as u32,
                SOCKET_DOMAIN_INET,
                SOCKET_FAMILY_INET,
                SEED_TCP4_UP,
                SEED_TCP4_DOWN,
                14,
            ),
            4 => child_phase_tcp(
                chan,
                phase,
                go.arg0 as u32,
                SOCKET_DOMAIN_INET6,
                SOCKET_FAMILY_INET6,
                SEED_TCP6_UP,
                SEED_TCP6_DOWN,
                14,
            ),
            5 => child_phase_socketpair(stream, dgram),
            6 => child_phase_unix_stream(netns),
            7 => child_phase_unix_dgram(netns),
            8 => child_phase_wait(go.arg0 as u32),
            9 => child_phase_backpressure(chan, go.arg0 as u32, stream),
            10 => child_phase_shutdown(stream),
            11 => child_phase_rights(),
            12 => child_phase_faults(chan, netns, dgram),
            _ => Err(EXIT_PROTOCOL),
        };
        let bytes = child_step!(phase, result);
        child_step!(
            phase,
            send_msg(
                chan,
                Msg {
                    op: OP_DONE,
                    phase,
                    arg0: bytes,
                    ..Msg::default()
                }
            )
        );
    }

    if stream != HANDLE_NONE {
        let _ = rt::handle_close(stream);
    }
    let _ = rt::handle_close(chan);
    rt::process_exit(0)
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

/// Role discriminator: the parent queues `ROLE_CHILD` on the child's endpoint
/// before creating the child, so an immediate receive succeeds only in the
/// child; the parent's own endpoint has no message and reports `WOULD_BLOCK`.
#[unsafe(no_mangle)]
pub extern "C" fn _start(console: Handle, channel_endpoint: Handle, netns: Handle) -> ! {
    let mut handles = [HANDLE_NONE; 2];
    let mut rights = [0u32; 2];
    match recv_msg(
        channel_endpoint,
        &mut handles,
        &mut rights,
        u64::from(WAIT_TIMEOUT_IMMEDIATE),
    ) {
        Ok((msg, _)) if msg.op == OP_ROLE && msg.arg0 == u64::from(ROLE_CHILD) => {
            run_child(console, channel_endpoint, netns)
        }
        Ok(_) => {
            print_fail(console, 0, EXIT_ROLE);
            rt::process_exit(EXIT_ROLE)
        }
        Err(ERR_WOULD_BLOCK) | Err(ERR_TIMEOUT) => run_parent(console, channel_endpoint, netns),
        Err(code) => {
            print_fail(console, 0, code);
            rt::process_exit(EXIT_ROLE)
        }
    }
}
