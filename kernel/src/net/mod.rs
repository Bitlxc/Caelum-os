//! Minimal IPv4/IPv6 loopback network stack (M7a).
//!
//! M7a delivers a *real* loopback path for UDP and TCP without any NIC: a
//! transmitted frame is built with the `netcore` headers (and real checksums),
//! then re-injected into this same stack's receive path, where it is parsed and
//! verified again before it reaches the destination socket. That keeps the
//! protocol work honest and lets M7b wrap these in kernel objects without
//! changing the transport core.
//!
//! # Fixed budgets (no heap)
//!
//! | table | capacity |
//! |---|---|
//! | socket ids | [`MAX_SOCKETS`] = 16 |
//! | TCP connections / listeners | [`MAX_TCP_CONNECTIONS`] = 8 |
//! | UDP datagrams per socket | [`UDP_QUEUE_DEPTH`] = 4, each ≤ [`UDP_DGRAM_MAX`] |
//! | TCP receive ring per connection | [`TCP_RX_BYTES`] = 4 KiB |
//! | unacknowledged TCP segment per connection | [`TCP_TX_SEG_MAX`] = 1 KiB |
//! | listener backlog | [`TCP_BACKLOG`] = 2 |
//!
//! Everything lives in `static` storage; an overflow reports
//! [`NetError::Quota`]/[`NetError::WouldBlock`] instead of growing.
//!
//! # Locking
//!
//! One [`IrqSpinLock`] guards the whole stack. The lock only ever covers table
//! work and bounded copies: readiness notifications are buffered inside the
//! critical section and delivered by the wake hook **after** the lock is
//! released, so a hook may call back into this module (or into `process`) without
//! re-entrancy. Interrupt context does not call into `net` in M7a; `on_tick` is
//! expected to run from a thread context.
//!
//! # Not in M7a
//!
//! No fragmentation, no reassembly, no congestion control, no TIME_WAIT linger
//! timer, no data accepted before `accept`, and no syscall/object wiring (that
//! is M7b). Sequence and acknowledgment numbers, retransmission and the TCP
//! state machine come from `netcore`; the socket layer only moves the bytes.

mod socket;

pub use socket::*;

use core::mem;
use core::sync::atomic::{AtomicUsize, Ordering};

use netcore::tcp::{self, TcpEvent, TcpSegment, TcpState};
use netcore::{PROTOCOL_TCP, PROTOCOL_UDP, PacketError, ipv4, ipv6, udp};

use crate::object::{ObjectId, release_object};
use crate::sync::IrqSpinLock;

// ---------------------------------------------------------------------------
// Public constants
// ---------------------------------------------------------------------------

/// IPv4 UDP self-test payload (7 bytes, marker `M7UDP4`).
pub const UDP4_PAYLOAD: &[u8] = b"M7UDP4!";
/// IPv6 UDP self-test payload (7 bytes, marker `M7UDP6`).
pub const UDP6_PAYLOAD: &[u8] = b"M7UDP6!";

/// UDP self-test ports (both families).
const UDP_TEST_A_PORT: u16 = 7_001;
const UDP_TEST_B_PORT: u16 = 7_002;
/// TCP self-test port (both families).
const TCP_TEST_PORT: u16 = 7_101;

/// Loopback TTL / hop limit used on every generated frame.
const LOOPBACK_TTL: u8 = 64;

/// Advertised TCP window (matches [`TCP_RX_BYTES`]).
const TCP_WINDOW: u16 = tcp::DEFAULT_WINDOW;

/// How many frame buffers the recursive loopback injection may nest.
const SCRATCH_DEPTH: usize = 4;

// ---------------------------------------------------------------------------
// Statistics
// ---------------------------------------------------------------------------

/// Counters exposed for diagnostics and the M7a self-test.
#[derive(Clone, Copy, Debug, Default)]
pub struct NetStats {
    /// Frames built and injected.
    pub tx_frames: u64,
    /// Frames parsed by the receive path.
    pub rx_frames: u64,
    /// Frames rejected by a parser or a checksum.
    pub rx_malformed: u64,
    /// Frames dropped because no socket wanted them.
    pub rx_dropped: u64,
    /// UDP datagrams delivered to a socket.
    pub udp_datagrams: u64,
    /// UDP datagrams dropped because the receive queue was full.
    pub udp_queue_dropped: u64,
    /// TCP segments processed.
    pub tcp_segments: u64,
    /// TCP segments retransmitted after an RTO.
    pub retransmits: u64,
    /// TCP segments that reset a connection.
    pub resets: u64,
}

// ---------------------------------------------------------------------------
// Stack storage
// ---------------------------------------------------------------------------

/// One pre-allocated loopback frame buffer.
#[repr(C, align(8))]
struct ScratchFrame {
    data: [u8; MAX_FRAME_BYTES],
}

impl ScratchFrame {
    const fn new() -> ScratchFrame {
        ScratchFrame {
            data: [0; MAX_FRAME_BYTES],
        }
    }
}

/// Buffered readiness notifications, delivered after the stack lock is dropped.
#[derive(Clone, Copy)]
struct WakeBatch {
    len: u8,
    events: [WakeEvent; MAX_WAKE_EVENTS],
}

impl WakeBatch {
    const EMPTY: WakeBatch = WakeBatch {
        len: 0,
        events: [WakeEvent::new(SocketId::INVALID, ReadyEvent::Read); MAX_WAKE_EVENTS],
    };

    fn push(&mut self, event: WakeEvent) {
        if (self.len as usize) < MAX_WAKE_EVENTS {
            self.events[self.len as usize] = event;
            self.len += 1;
        }
    }

    fn clear(&mut self) {
        self.len = 0;
    }

    fn as_slice(&self) -> &[WakeEvent] {
        &self.events[..self.len as usize]
    }
}

/// Object references to release after the stack lock is dropped (M9b).
///
/// Queued UNIX messages own one reference per transferred descriptor. Dropping
/// such a message while the stack lock is held (plain `read`, socket close,
/// namespace teardown) must not run the object destroy hook under [`NET`], so
/// the ids are buffered here and released by [`with_stack`] afterwards.
const MAX_OBJECT_RELEASES: usize =
    MAX_SOCKETS * (LOCAL_DGRAM_DEPTH * MAX_SCM_FDS + LOCAL_ANCILLARY_DEPTH * MAX_SCM_FDS);

#[derive(Clone, Copy)]
struct ObjectReleaseBatch {
    len: u16,
    objects: [ObjectId; MAX_OBJECT_RELEASES],
}

impl ObjectReleaseBatch {
    const EMPTY: ObjectReleaseBatch = ObjectReleaseBatch {
        len: 0,
        objects: [0; MAX_OBJECT_RELEASES],
    };

    fn push(&mut self, object: ObjectId) {
        if usize::from(self.len) < MAX_OBJECT_RELEASES {
            self.objects[usize::from(self.len)] = object;
            self.len += 1;
        }
    }

    fn clear(&mut self) {
        self.len = 0;
    }

    fn as_slice(&self) -> &[ObjectId] {
        &self.objects[..usize::from(self.len)]
    }
}

/// Release the buffered object references outside the stack lock.
fn release_objects(batch: &ObjectReleaseBatch) {
    for object in batch.as_slice() {
        let _ = release_object(*object);
    }
}

/// Where a parsed segment belongs.
#[derive(Clone, Copy)]
enum Route {
    /// An established (or connecting) socket.
    Existing(usize),
    /// A pending handshake on the listener's backlog.
    Backlog(usize, usize),
    /// A new handshake on a listener.
    NewConnection(usize),
}

/// The whole stack: this is the single owner of every table.
struct NetStack {
    slots: [SocketSlot; MAX_SOCKETS],
    udp: [Option<UdpSocket>; MAX_SOCKETS],
    tcp: [Option<TcpSocket>; MAX_TCP_CONNECTIONS],
    /// Listener backlog storage lives outside `TcpSocket`: embedding 64 entries
    /// made every constructor a >10 KiB stack temporary in debug builds.
    tcp_backlogs: [[Option<BacklogEntry>; TCP_BACKLOG]; MAX_TCP_CONNECTIONS],
    /// Receive ring per TCP connection, outside `TcpSocket` for the same reason
    /// (a 4 KiB inline ring made every constructor and reset a several-KiB
    /// stack temporary in debug builds).
    tcp_receive: [TcpReceiveBuffer; MAX_TCP_CONNECTIONS],
    /// Outstanding-segment buffer per TCP connection, outside `TcpSocket`.
    tcp_send: [TcpSendBuffer; MAX_TCP_CONNECTIONS],
    /// Receive queue per UDP socket, outside `UdpSocket` for the same reason.
    udp_queues: [DatagramQueue; MAX_SOCKETS],
    /// Unix stream states, indexed by the socket slot.
    local_streams: [Option<LocalStream>; MAX_SOCKETS],
    /// Receive ring per local stream, outside `LocalStream` for the same reason.
    local_stream_rx: [TcpReceiveBuffer; MAX_SOCKETS],
    /// Unix datagram states, indexed by the socket slot.
    local_dgrams: [Option<LocalDatagram>; MAX_SOCKETS],
    /// Receive queue per local datagram socket, outside `LocalDatagram`.
    local_dgram_queues: [LocalQueue; MAX_SOCKETS],
    /// Bound address of a local socket (INVALID when unnamed).
    local_addrs: [SocketAddress; MAX_SOCKETS],
    /// Connected peer of an INET datagram socket.
    udp_peers: [Option<Endpoint>; MAX_SOCKETS],
    /// Path namespaces (M7b); entries are created on first bind.
    namespaces: [Option<NamespaceEntry>; MAX_NAMESPACES],
    /// Path binding rows, outside `NamespaceEntry` so the entry — and every
    /// reset temporary — stays small.
    namespace_bindings: [[Option<PathBinding>; MAX_BINDINGS_PER_NAMESPACE]; MAX_NAMESPACES],
    now: u64,
    next_ephemeral: u16,
    next_isn: u32,
    initialized: bool,
    stats: NetStats,
    wakes: WakeBatch,
    /// Object references dropped by the last stack operation (M9b), released
    /// after the lock is dropped by [`with_stack`].
    releases: ObjectReleaseBatch,
}

impl NetStack {
    const fn new() -> NetStack {
        NetStack {
            slots: [const { SocketSlot::free() }; MAX_SOCKETS],
            udp: [const { None }; MAX_SOCKETS],
            tcp: [const { None }; MAX_TCP_CONNECTIONS],
            tcp_backlogs: [const { [const { None }; TCP_BACKLOG] }; MAX_TCP_CONNECTIONS],
            tcp_receive: [const { TcpReceiveBuffer::new() }; MAX_TCP_CONNECTIONS],
            tcp_send: [const { TcpSendBuffer::new() }; MAX_TCP_CONNECTIONS],
            udp_queues: [const { DatagramQueue::new() }; MAX_SOCKETS],
            local_streams: [const { None }; MAX_SOCKETS],
            local_stream_rx: [const { TcpReceiveBuffer::new() }; MAX_SOCKETS],
            local_dgrams: [const { None }; MAX_SOCKETS],
            local_dgram_queues: [const { LocalQueue::new() }; MAX_SOCKETS],
            local_addrs: [SocketAddress::INVALID; MAX_SOCKETS],
            udp_peers: [const { None }; MAX_SOCKETS],
            namespaces: [const { None }; MAX_NAMESPACES],
            namespace_bindings: [const { [const { None }; MAX_BINDINGS_PER_NAMESPACE] };
                MAX_NAMESPACES],
            now: 0,
            next_ephemeral: EPHEMERAL_PORT_FIRST,
            next_isn: 0,
            initialized: false,
            stats: NetStats {
                tx_frames: 0,
                rx_frames: 0,
                rx_malformed: 0,
                rx_dropped: 0,
                udp_datagrams: 0,
                udp_queue_dropped: 0,
                tcp_segments: 0,
                retransmits: 0,
                resets: 0,
            },
            wakes: WakeBatch::EMPTY,
            releases: ObjectReleaseBatch::EMPTY,
        }
    }

    /// Clear a table entry without letting debug drop glue move a large inline
    /// value into a stack temporary. These tables contain only plain inline
    /// data: no `Drop` implementation, heap allocation, or externally owned
    /// resource is discarded. Raw object/socket ids are invalidated by reset.
    ///
    /// Every payload that used to be large (TCP receive/send rings, UDP/local
    /// queues, listener backlogs, path binding rows) now lives in the plain
    /// pools above, so the `Option` values here are small and this write no
    /// longer builds a several-KiB temporary.
    fn clear_inline_option<T>(slot: &mut Option<T>) {
        // SAFETY: The caller is restricted to the plain inline tables above.
        // Forgetting those bytes is the intended reset; no destructor may run.
        unsafe { core::ptr::write(slot, None) }
    }

    /// Drop every socket and reset the counters. Slot generations are kept so
    /// ids issued before the reset stay invalid.
    fn reset(&mut self) {
        for slot in self.slots.iter_mut() {
            // Keep the generation stamp: an id issued before the reset must stay
            // stale after it (M7a review fix 3, no ABA).
            slot.clear();
        }
        // Drain queued ancillary/transferred object references into `releases`
        // so the caller drops them after the stack lock is released (M9b).
        for index in 0..MAX_SOCKETS {
            let mut objects = [0; LOCAL_ANCILLARY_DEPTH * MAX_SCM_FDS];
            let mut count = 0;
            if let Some(stream) = self.local_streams[index].as_mut() {
                while let Some(record) = stream.pop_ancillary() {
                    for object in record.objects.iter().take(record.len()) {
                        objects[count] = *object;
                        count += 1;
                    }
                }
            }
            for object in objects.into_iter().take(count) {
                self.releases.push(object);
            }
            let mut datagram_objects = [0; LOCAL_DGRAM_DEPTH * MAX_SCM_FDS];
            let datagram_count =
                self.local_dgram_queues[index].drain_objects(&mut datagram_objects);
            for object in datagram_objects.into_iter().take(datagram_count) {
                self.releases.push(object);
            }
        }
        for socket in self.udp.iter_mut() {
            Self::clear_inline_option(socket);
        }
        for socket in self.tcp.iter_mut() {
            Self::clear_inline_option(socket);
        }
        for backlog in self.tcp_backlogs.iter_mut() {
            for entry in backlog.iter_mut() {
                Self::clear_inline_option(entry);
            }
        }
        // Clear the external payload pools in place: each element is a plain
        // inline value and `clear`/`None` writes no stack temporary.
        for buffer in self.tcp_receive.iter_mut() {
            buffer.clear();
        }
        for buffer in self.tcp_send.iter_mut() {
            buffer.clear();
        }
        for queue in self.udp_queues.iter_mut() {
            queue.clear();
        }
        for stream in self.local_streams.iter_mut() {
            Self::clear_inline_option(stream);
        }
        for buffer in self.local_stream_rx.iter_mut() {
            buffer.clear();
        }
        for dgram in self.local_dgrams.iter_mut() {
            Self::clear_inline_option(dgram);
        }
        for queue in self.local_dgram_queues.iter_mut() {
            queue.clear();
        }
        for addr in self.local_addrs.iter_mut() {
            *addr = SocketAddress::INVALID;
        }
        for peer in self.udp_peers.iter_mut() {
            *peer = None;
        }
        for entry in self.namespaces.iter_mut() {
            Self::clear_inline_option(entry);
        }
        for bindings in self.namespace_bindings.iter_mut() {
            for binding in bindings.iter_mut() {
                *binding = None;
            }
        }
        self.now = 0;
        self.next_ephemeral = EPHEMERAL_PORT_FIRST;
        self.next_isn = 0;
        self.initialized = false;
        self.stats = NetStats::default();
        self.wakes.clear();
    }

    fn take_wakes(&mut self) -> WakeBatch {
        let batch = self.wakes;
        self.wakes.clear();
        batch
    }

    fn push_wake(&mut self, socket: SocketId, event: ReadyEvent) {
        let object = socket
            .slot()
            .and_then(|index| self.slots.get(index))
            .map(|slot| slot.object)
            .unwrap_or(0);
        self.wakes.push(WakeEvent {
            socket,
            event,
            object,
        });
    }

    fn take_releases(&mut self) -> ObjectReleaseBatch {
        let batch = self.releases;
        self.releases.clear();
        batch
    }

    fn push_release(&mut self, object: ObjectId) {
        self.releases.push(object);
    }

    fn sockets_used(&self) -> usize {
        self.slots.iter().filter(|slot| !slot.is_free()).count()
    }

    // -- id table ----------------------------------------------------------

    fn slot_kind(&self, id: SocketId) -> Result<SlotKind, NetError> {
        let index = id.slot().ok_or(NetError::InvalidSocket)?;
        let slot = self.slots.get(index).ok_or(NetError::InvalidSocket)?;
        if slot.is_free() || slot.generation != id.generation() {
            return Err(NetError::InvalidSocket);
        }
        Ok(slot.kind)
    }

    fn udp_index(&self, id: SocketId) -> Result<usize, NetError> {
        match self.slot_kind(id)? {
            SlotKind::Udp(index) => Ok(usize::from(index)),
            _ => Err(NetError::InvalidSocket),
        }
    }

    fn tcp_index(&self, id: SocketId) -> Result<usize, NetError> {
        match self.slot_kind(id)? {
            SlotKind::Tcp(index) => Ok(usize::from(index)),
            _ => Err(NetError::InvalidSocket),
        }
    }

    fn udp_id_for(&self, index: usize) -> Option<SocketId> {
        self.slots.iter().enumerate().find_map(|(slot, entry)| {
            if entry.kind == SlotKind::Udp(index as u8) && !entry.is_free() {
                Some(SocketId::new(slot, entry.generation))
            } else {
                None
            }
        })
    }

    fn tcp_id_for(&self, index: usize) -> Option<SocketId> {
        self.slots.iter().enumerate().find_map(|(slot, entry)| {
            if entry.kind == SlotKind::Tcp(index as u8) && !entry.is_free() {
                Some(SocketId::new(slot, entry.generation))
            } else {
                None
            }
        })
    }

    fn alloc_slot(&mut self, kind: SlotKind) -> Result<SocketId, NetError> {
        for index in 0..MAX_SOCKETS {
            if !self.slots[index].is_free() {
                continue;
            }
            let generation = self.slots[index].generation.wrapping_add(1).max(1);
            self.slots[index] = SocketSlot {
                generation,
                kind,
                ..SocketSlot::free()
            };
            return Ok(SocketId::new(index, generation));
        }
        Err(NetError::Quota)
    }

    fn free_slot(&mut self, id: SocketId) {
        if let Some(index) = id.slot() {
            if let Some(slot) = self.slots.get_mut(index) {
                if slot.generation == id.generation() {
                    // Keep the generation, drop the payload/object/domain.
                    slot.clear();
                }
            }
        }
    }

    // -- allocation helpers ------------------------------------------------

    fn alloc_udp(&mut self, local: Endpoint) -> Result<SocketId, NetError> {
        if self
            .udp
            .iter()
            .flatten()
            .any(|socket| socket.local() == local)
        {
            return Err(NetError::AddressInUse);
        }
        let index = self
            .udp
            .iter()
            .position(Option::is_none)
            .ok_or(NetError::Quota)?;
        let id = self.alloc_slot(SlotKind::Udp(index as u8))?;
        let queue = core::ptr::addr_of_mut!(self.udp_queues[index]);
        self.udp[index] = Some(UdpSocket::new(local, queue));
        Ok(id)
    }

    fn alloc_tcp_in_place<R>(
        &mut self,
        listener_local: Option<Endpoint>,
        initialise: impl FnOnce(
            &mut Option<TcpSocket>,
            *mut Option<BacklogEntry>,
            *mut TcpReceiveBuffer,
            *mut TcpSendBuffer,
        ) -> R,
    ) -> Result<(SocketId, R), NetError> {
        // Only a second *listener* on the same local endpoint is a conflict:
        // accepted connections share that endpoint but differ by remote peer.
        if let Some(local) = listener_local {
            if self
                .tcp
                .iter()
                .flatten()
                .any(|entry| entry.is_listener() && entry.local() == local)
            {
                return Err(NetError::AddressInUse);
            }
        }
        let index = self
            .tcp
            .iter()
            .position(Option::is_none)
            .ok_or(NetError::Quota)?;
        let id = self.alloc_slot(SlotKind::Tcp(index as u8))?;
        // Construct directly in the static slot. Returning a `TcpSocket` by
        // value would put a >10 KiB temporary on the 16 KiB boot stack; the
        // receive/send rings live in the static pools for the same reason.
        let backlog = self.tcp_backlogs[index].as_mut_ptr();
        let receive = core::ptr::addr_of_mut!(self.tcp_receive[index]);
        let send = core::ptr::addr_of_mut!(self.tcp_send[index]);
        let result = initialise(&mut self.tcp[index], backlog, receive, send);
        Ok((id, result))
    }

    fn tcp_local_in_use(&self, local: Endpoint) -> bool {
        self.tcp
            .iter()
            .flatten()
            .any(|socket| socket.local() == local)
    }

    /// Whether `local` talks to `remote` over a connection that is still
    /// waiting in a local listener's backlog (i.e. not handed to userspace by
    /// `accept` yet).
    ///
    /// `handle_backlog` deliberately drops payload that arrives before
    /// `accept`; until the connection is accepted there is nowhere to buffer
    /// it, so `send` must back off and the socket must not report writable.
    fn peer_awaits_accept(&self, local: Endpoint, remote: Endpoint) -> bool {
        self.tcp.iter().flatten().any(|listener| {
            listener.is_listener()
                && listener.local() == remote
                && (0..listener.backlog_len()).any(|entry| {
                    listener
                        .backlog(entry)
                        .map(|pending| pending.remote == local)
                        .unwrap_or(false)
                })
        })
    }

    /// The live socket of the peer whose connection `(local -> remote)` is
    /// blocked on `accept`; `None` once the accepted socket exists or the
    /// backlog entry is gone.
    fn peer_awaiting_accept(&self, local: Endpoint, remote: Endpoint) -> Option<SocketId> {
        self.tcp
            .iter()
            .enumerate()
            .find(|(_, slot)| {
                slot.as_ref().is_some_and(|peer| {
                    !peer.is_listener() && peer.local() == local && peer.remote() == Some(remote)
                })
            })
            .and_then(|(index, _)| self.tcp_id_for(index))
    }

    /// Choose a free ephemeral local port for `addr`.
    ///
    /// Used by an active TCP open (`tcp_connect_locked`) and, since M7b, by an
    /// INET/INET6 `bind` that asked for port 0 (`bind_locked`). A port is only
    /// handed out when no live TCP **or** UDP socket already owns the same
    /// loopback endpoint; the scan is bounded and reports
    /// [`NetError::Quota`] when the window is exhausted.
    fn alloc_ephemeral(&mut self, addr: IpAddr) -> Result<u16, NetError> {
        for _ in 0..1_024 {
            let port = self.next_ephemeral;
            self.next_ephemeral = if port == u16::MAX {
                EPHEMERAL_PORT_FIRST
            } else {
                port + 1
            };
            let local = Endpoint::new(addr, port);
            let tcp_taken = self.tcp_local_in_use(local);
            let udp_taken = self
                .udp
                .iter()
                .flatten()
                .any(|socket| socket.local() == local);
            if !tcp_taken && !udp_taken {
                return Ok(port);
            }
        }
        Err(NetError::Quota)
    }

    fn next_isn(&mut self) -> u32 {
        self.next_isn = self.next_isn.wrapping_add(0x0001_0000);
        0x1000_0000 ^ self.next_isn
    }

    // -- receive path ------------------------------------------------------

    fn inject_locked(&mut self, frame: &[u8], depth: usize) -> Result<(), NetError> {
        if frame.is_empty() {
            return Err(NetError::Malformed);
        }
        self.stats.rx_frames += 1;
        let result = match frame[0] >> 4 {
            4 => self.inject_ipv4(frame, depth),
            6 => self.inject_ipv6(frame, depth),
            _ => Err(NetError::Malformed),
        };
        if matches!(result, Err(NetError::Malformed)) {
            self.stats.rx_malformed += 1;
        }
        result
    }

    fn inject_ipv4(&mut self, frame: &[u8], depth: usize) -> Result<(), NetError> {
        let header = ipv4::parse_checked(frame).map_err(|_| NetError::Malformed)?;
        if header.is_fragmented() {
            return Err(NetError::Malformed);
        }
        let src = IpAddr::V4(header.src);
        let dst = IpAddr::V4(header.dst);
        match header.protocol {
            PROTOCOL_UDP => {
                let datagram = udp::parse_checked_v4(header.payload, header.src, header.dst)
                    .map_err(|_| NetError::Malformed)?;
                let source = Endpoint::new(src, datagram.src_port);
                self.deliver_udp(source, dst, datagram.dst_port, datagram.payload)
            }
            PROTOCOL_TCP => {
                let segment = tcp::parse_checked_v4(header.payload, header.src, header.dst)
                    .map_err(|_| NetError::Malformed)?;
                let source = Endpoint::new(src, segment.src_port);
                self.deliver_tcp(source, dst, segment.dst_port, &segment, depth)
            }
            _ => {
                self.stats.rx_dropped += 1;
                Ok(())
            }
        }
    }

    fn inject_ipv6(&mut self, frame: &[u8], depth: usize) -> Result<(), NetError> {
        let header = ipv6::parse(frame).map_err(|_| NetError::Malformed)?;
        let upper = ipv6::upper_layer(&header).map_err(|_| NetError::Malformed)?;
        if upper.fragmented {
            return Err(NetError::Malformed);
        }
        let src = IpAddr::V6(header.src);
        let dst = IpAddr::V6(header.dst);
        let payload = upper.payload;
        match upper.protocol {
            ipv6::NEXT_UDP => {
                let datagram = udp::parse_checked_v6(payload, header.src, header.dst)
                    .map_err(|_| NetError::Malformed)?;
                let source = Endpoint::new(src, datagram.src_port);
                self.deliver_udp(source, dst, datagram.dst_port, datagram.payload)
            }
            ipv6::NEXT_TCP => {
                let segment = tcp::parse_checked_v6(payload, header.src, header.dst)
                    .map_err(|_| NetError::Malformed)?;
                let source = Endpoint::new(src, segment.src_port);
                self.deliver_tcp(source, dst, segment.dst_port, &segment, depth)
            }
            _ => {
                self.stats.rx_dropped += 1;
                Ok(())
            }
        }
    }

    fn deliver_udp(
        &mut self,
        source: Endpoint,
        dst: IpAddr,
        dst_port: u16,
        payload: &[u8],
    ) -> Result<(), NetError> {
        let Some(index) = self.udp.iter().position(|socket| {
            socket
                .as_ref()
                .is_some_and(|entry| entry.local() == Endpoint::new(dst, dst_port))
        }) else {
            self.stats.rx_dropped += 1;
            return Ok(());
        };
        let accepted = {
            let socket = self.udp[index].as_mut().ok_or(NetError::Malformed)?;
            socket.queue_mut().push(payload, source)
        };
        if !accepted {
            // Backpressure (Lead m01303): a full receive queue rejects the
            // datagram instead of dropping an already queued one; the sender
            // observes `WouldBlock` and retries later.
            return Err(NetError::WouldBlock);
        }
        self.stats.udp_datagrams += 1;
        if let Some(id) = self.udp_id_for(index) {
            self.push_wake(id, ReadyEvent::Read);
        }
        Ok(())
    }

    fn deliver_tcp(
        &mut self,
        source: Endpoint,
        dst: IpAddr,
        dst_port: u16,
        segment: &TcpSegment<'_>,
        depth: usize,
    ) -> Result<(), NetError> {
        self.stats.tcp_segments += 1;
        let mut route = None;
        for index in 0..MAX_TCP_CONNECTIONS {
            let Some(socket) = self.tcp[index].as_ref() else {
                continue;
            };
            let local = socket.local();
            if local.port != dst_port || local.addr != dst {
                continue;
            }
            if socket.is_listener() {
                let mut found = false;
                for entry in 0..socket.backlog_len() {
                    if socket.backlog(entry).map(|pending| pending.remote) == Some(source) {
                        route = Some(Route::Backlog(index, entry));
                        found = true;
                        break;
                    }
                }
                if found {
                    break;
                }
                if segment.syn() && !segment.ack() {
                    route = Some(Route::NewConnection(index));
                    break;
                }
                continue;
            }
            if socket.remote() == Some(source) {
                route = Some(Route::Existing(index));
                break;
            }
        }

        match route {
            Some(Route::Existing(index)) => self.handle_segment(index, source, segment, depth),
            Some(Route::Backlog(listener, entry)) => {
                self.handle_backlog(listener, entry, source, segment, depth)
            }
            Some(Route::NewConnection(listener)) => {
                self.handle_new_connection(listener, source, segment, depth)
            }
            None => {
                self.stats.rx_dropped += 1;
                // No socket owns this port. An active opener is sitting in
                // SYN-SENT retransmitting; answer it with RST|ACK (acknowledging
                // everything it sent) so it reaches the refusal path instead of
                // waiting for the retransmit budget to run out (review N6).
                // RST segments are never answered, so two closed ports cannot
                // ping-pong resets forever.
                if !segment.rst() {
                    let mut ack = segment.seq;
                    if segment.syn() {
                        ack = ack.wrapping_add(1);
                    }
                    if segment.fin() {
                        ack = ack.wrapping_add(1);
                    }
                    ack = ack.wrapping_add(segment.payload.len() as u32);
                    let fields = SegmentFields {
                        flags: tcp::FLAG_RST | tcp::FLAG_ACK,
                        seq: segment.ack,
                        ack,
                        window: 0,
                    };
                    let destination = Endpoint {
                        addr: dst,
                        port: dst_port,
                    };
                    let _ = self.transmit_tcp(destination, source, fields, &[], depth + 1);
                }
                Ok(())
            }
        }
    }

    fn handle_segment(
        &mut self,
        index: usize,
        source: Endpoint,
        segment: &TcpSegment<'_>,
        depth: usize,
    ) -> Result<(), NetError> {
        let now = self.now;
        let socket_id = self.tcp_id_for(index).ok_or(NetError::InvalidSocket)?;
        let mut readable = false;
        let mut writable = false;
        let mut failed = false;
        let mut overflow = false;
        let (response, local, window) = {
            let socket = self
                .tcp
                .get_mut(index)
                .and_then(|slot| slot.as_mut())
                .ok_or(NetError::InvalidSocket)?;
            let was_syn_sent = socket.connection().state() == TcpState::SynSent;
            let response = socket.connection_mut().on_segment(segment, now);
            let local = socket.local();
            if response.accepted && !segment.payload.is_empty() {
                if socket.receive_mut().push(segment.payload) {
                    readable = true;
                } else {
                    socket.set_error();
                    overflow = true;
                }
            }
            if !socket.connection().retransmit_pending() {
                socket.send_mut().clear();
            }
            match response.event {
                TcpEvent::PeerFin => {
                    socket.set_peer_fin();
                    readable = true;
                }
                TcpEvent::Reset => {
                    // A RST while the handshake was in flight is a refusal, not
                    // a reset of an established connection (review N6).
                    if was_syn_sent {
                        socket.set_refused();
                    } else {
                        socket.set_error();
                    }
                    failed = true;
                }
                TcpEvent::Connected | TcpEvent::DataAcknowledged => {
                    writable = true;
                }
                TcpEvent::None | TcpEvent::Data(_) => {}
            }
            // Advertise only the space actually left in the receive ring
            // (M7a review fix 4): a full ring advertises a zero window, and a
            // window update is sent once `recv` drains it.
            let window = socket.receive().free().min(usize::from(u16::MAX)) as u16;
            if window == 0 {
                socket.set_zero_window();
            }
            (response, local, window)
        };

        if response.drop {
            return Ok(());
        }
        if overflow {
            let fields = SegmentFields {
                flags: tcp::FLAG_RST | tcp::FLAG_ACK,
                seq: 0,
                ack: segment.seq.wrapping_add(segment.payload.len() as u32),
                window: 0,
            };
            self.stats.rx_dropped += 1;
            self.transmit_tcp(local, source, fields, &[], depth + 1)?;
            self.push_wake(socket_id, ReadyEvent::Error);
            return Ok(());
        }
        if readable {
            self.push_wake(socket_id, ReadyEvent::Read);
        }
        if writable {
            self.push_wake(socket_id, ReadyEvent::Write);
        }
        if failed {
            self.stats.resets += 1;
            self.push_wake(socket_id, ReadyEvent::Error);
        }
        // Never answer a pure ACK with a pure ACK: the state machine returns an
        // ACK for every in-window segment, which would echo forever on loopback.
        if segment.payload.is_empty() && !segment.fin() && !segment.syn() {
            return Ok(());
        }
        if let Some(send) = response.send {
            let mut fields = SegmentFields::from(send);
            fields.window = window;
            self.transmit_tcp(local, source, fields, &[], depth + 1)?;
        }
        Ok(())
    }

    fn handle_backlog(
        &mut self,
        listener_index: usize,
        entry_index: usize,
        source: Endpoint,
        segment: &TcpSegment<'_>,
        depth: usize,
    ) -> Result<(), NetError> {
        let now = self.now;
        let (local, syn_seq, syn_ack, duplicated_syn) = {
            let listener = self
                .tcp
                .get_mut(listener_index)
                .and_then(|slot| slot.as_mut())
                .ok_or(NetError::InvalidSocket)?;
            let local = listener.local();
            let entry = listener
                .backlog_mut(entry_index)
                .ok_or(NetError::InvalidSocket)?;
            if segment.syn() && !segment.ack() {
                // A retransmitted SYN must be answered again with SYN|ACK, but
                // feeding it to the synchronized handler would produce a RST.
                let fields = SegmentFields {
                    flags: tcp::FLAG_SYN | tcp::FLAG_ACK,
                    seq: entry.connection.snd_nxt().wrapping_sub(1),
                    ack: entry.connection.rcv_nxt(),
                    window: TCP_WINDOW,
                };
                (local, fields.seq, fields.ack, Some(fields))
            } else {
                (local, 0, 0, None)
            }
        };
        if let Some(fields) = duplicated_syn {
            let _ = (syn_seq, syn_ack);
            return self.transmit_tcp(local, source, fields, &[], depth + 1);
        }
        if !segment.payload.is_empty() {
            // M7a accepts data only after `accept`; drop it so the peer retries
            // once the connection is handed to userspace.
            self.stats.rx_dropped += 1;
            return Ok(());
        }

        let (response, established, was_established) = {
            let listener = self
                .tcp
                .get_mut(listener_index)
                .and_then(|slot| slot.as_mut())
                .ok_or(NetError::InvalidSocket)?;
            let entry = listener
                .backlog_mut(entry_index)
                .ok_or(NetError::InvalidSocket)?;
            let was_established = entry.established;
            let response = entry.connection.on_segment(segment, now);
            if entry.connection.state() == TcpState::Established {
                entry.established = true;
            }
            (response, entry.established, was_established)
        };
        // A backlog entry that just became established makes the listener
        // readable for an `accept` waiter (M7a review fix 5).
        if established && !was_established {
            if let Some(listener) = self.tcp_id_for(listener_index) {
                self.push_wake(listener, ReadyEvent::Read);
            }
        }
        if response.drop {
            return Ok(());
        }
        if segment.payload.is_empty() && !segment.fin() && !segment.syn() {
            return Ok(());
        }
        if let Some(send) = response.send {
            self.transmit_tcp(local, source, SegmentFields::from(send), &[], depth + 1)?;
        }
        Ok(())
    }

    fn handle_new_connection(
        &mut self,
        listener_index: usize,
        source: Endpoint,
        segment: &TcpSegment<'_>,
        depth: usize,
    ) -> Result<(), NetError> {
        let now = self.now;
        let (response, local, connection) = {
            let listener = self
                .tcp
                .get_mut(listener_index)
                .and_then(|slot| slot.as_mut())
                .ok_or(NetError::InvalidSocket)?;
            let local = listener.local();
            let mut connection = listener.connection().clone();
            let response = connection.on_segment(segment, now);
            (response, local, connection)
        };
        if response.drop {
            return Ok(());
        }
        let pushed = self
            .tcp
            .get_mut(listener_index)
            .and_then(|slot| slot.as_mut())
            .map(|listener| {
                listener.push_backlog(BacklogEntry {
                    connection,
                    remote: source,
                    established: false,
                })
            })
            .unwrap_or(false);
        if !pushed {
            // Backlog full: refuse the handshake instead of leaving the peer
            // hanging on a SYN|ACK we will never accept.
            let fields = SegmentFields {
                flags: tcp::FLAG_RST | tcp::FLAG_ACK,
                seq: 0,
                ack: segment.seq.wrapping_add(1),
                window: 0,
            };
            self.stats.rx_dropped += 1;
            return self.transmit_tcp(local, source, fields, &[], depth + 1);
        }
        // A newly pending connection makes the listener readable for `accept`
        // (M7a review fix 5); the wake is buffered and delivered off-lock.
        if let Some(listener) = self.tcp_id_for(listener_index) {
            self.push_wake(listener, ReadyEvent::Read);
        }
        if let Some(send) = response.send {
            self.transmit_tcp(local, source, SegmentFields::from(send), &[], depth + 1)?;
        }
        Ok(())
    }

    // -- transmit path -----------------------------------------------------

    fn transmit_tcp(
        &mut self,
        src: Endpoint,
        dst: Endpoint,
        segment: SegmentFields,
        payload: &[u8],
        depth: usize,
    ) -> Result<(), NetError> {
        let frame = scratch_frame(depth)?;
        let len = build_tcp_frame(frame, src, dst, segment, payload)?;
        self.transmit_locked(&frame[..len], depth)
    }

    fn transmit_locked(&mut self, frame: &[u8], depth: usize) -> Result<(), NetError> {
        if depth >= SCRATCH_DEPTH {
            return Err(NetError::Quota);
        }
        self.stats.tx_frames += 1;
        #[cfg(test)]
        {
            let pending = TX_DROP.load(Ordering::Relaxed);
            if pending != 0 {
                TX_DROP.store(pending - 1, Ordering::Relaxed);
                return Ok(());
            }
        }
        self.inject_locked(frame, depth)
    }

    fn retransmit_tcp(&mut self, index: usize, depth: usize) -> Result<(), NetError> {
        let frame = scratch_frame(depth)?;
        let len = {
            let socket = self
                .tcp
                .get(index)
                .and_then(|slot| slot.as_ref())
                .ok_or(NetError::InvalidSocket)?;
            let buffer = socket.send();
            if buffer.flags() == 0 {
                return Ok(());
            }
            let local = socket.local();
            let remote = socket.remote().ok_or(NetError::NotConnected)?;
            // Retransmissions and fresh data both advertise the live receive
            // window instead of a constant (M7a review fix 4).
            let window = socket.receive().free().min(usize::from(u16::MAX)) as u16;
            let fields = SegmentFields {
                flags: buffer.flags(),
                seq: buffer.seq(),
                ack: socket.connection().rcv_nxt(),
                window,
            };
            build_tcp_frame(frame, local, remote, fields, buffer.payload())?
        };
        self.transmit_locked(&frame[..len], depth)
    }

    // -- public operations (called under the lock) -------------------------

    fn udp_bind_locked(&mut self, key: SocketKey) -> Result<SocketId, NetError> {
        if key.protocol != Protocol::Udp || key.remote.is_some() {
            return Err(NetError::Unsupported);
        }
        let local = key.local.ok_or(NetError::BadAddress)?;
        validate_local(local)?;
        self.alloc_udp(local)
    }

    fn udp_send_locked(
        &mut self,
        id: SocketId,
        dst: Endpoint,
        payload: &[u8],
    ) -> Result<usize, NetError> {
        let index = self.udp_index(id)?;
        if payload.len() > UDP_DGRAM_MAX {
            return Err(NetError::TooLarge);
        }
        let local = self
            .udp
            .get(index)
            .and_then(|slot| slot.as_ref())
            .map(UdpSocket::local)
            .ok_or(NetError::InvalidSocket)?;
        validate_remote(local, dst)?;
        // Backpressure (Lead m01303): when the loopback destination exists and
        // its receive queue is full, refuse the datagram up front so nothing
        // already queued is dropped and the caller can retry.
        if let Some(destination) = self
            .udp
            .iter()
            .flatten()
            .find(|socket| socket.local() == dst)
        {
            if destination.queue().len() >= UDP_QUEUE_DEPTH {
                return Err(NetError::WouldBlock);
            }
        }
        let frame = scratch_frame(0)?;
        let len = build_udp_frame(frame, local, dst, payload)?;
        if let Err(error) = self.transmit_locked(&frame[..len], 0) {
            return Err(error);
        }
        Ok(payload.len())
    }

    fn udp_recv_locked(
        &mut self,
        id: SocketId,
        out: &mut [u8],
    ) -> Result<(usize, Endpoint), NetError> {
        let index = self.udp_index(id)?;
        let socket = self
            .udp
            .get_mut(index)
            .and_then(|slot| slot.as_mut())
            .ok_or(NetError::InvalidSocket)?;
        socket.queue_mut().pop(out)
    }

    fn tcp_listen_locked(&mut self, key: SocketKey) -> Result<SocketId, NetError> {
        if key.protocol != Protocol::Tcp || key.remote.is_some() {
            return Err(NetError::Unsupported);
        }
        let local = key.local.ok_or(NetError::BadAddress)?;
        validate_local(local)?;
        self.alloc_tcp_in_place(Some(local), |slot, backlog, receive, send| {
            TcpSocket::listener_into(slot, backlog, receive, send, local)
        })
        .map(|(id, ())| id)
    }

    fn tcp_connect_locked(&mut self, key: SocketKey) -> Result<SocketId, NetError> {
        if key.protocol != Protocol::Tcp {
            return Err(NetError::Unsupported);
        }
        let remote = key.remote.ok_or(NetError::BadAddress)?;
        if !remote.addr.is_loopback() || remote.port == 0 {
            return Err(NetError::BadAddress);
        }
        let local = match key.local {
            Some(local) => {
                if local.addr != remote.addr || local.port == 0 {
                    return Err(NetError::BadAddress);
                }
                if self.tcp_local_in_use(local) {
                    return Err(NetError::AddressInUse);
                }
                local
            }
            None => {
                let port = self.alloc_ephemeral(remote.addr)?;
                Endpoint::new(remote.addr, port)
            }
        };
        let isn = self.next_isn();
        let (id, syn) = self.alloc_tcp_in_place(None, |slot, backlog, receive, send| {
            TcpSocket::connecting_into(slot, backlog, receive, send, local, remote, isn)
        })?;
        let index = self.tcp_index(id)?;
        let sent = {
            let socket = self
                .tcp
                .get_mut(index)
                .and_then(|slot| slot.as_mut())
                .ok_or(NetError::InvalidSocket)?;
            socket.send_mut().set_control(syn.flags, syn.seq);
            SegmentFields::from(syn)
        };
        if let Err(error) = self.transmit_tcp(local, remote, sent, &[], 0) {
            self.tcp[index] = None;
            self.free_slot(id);
            return Err(error);
        }
        Ok(id)
    }

    fn tcp_accept_locked(&mut self, listener: SocketId) -> Result<SocketId, NetError> {
        let index = self.tcp_index(listener)?;
        let entry_index = {
            let socket = self
                .tcp
                .get(index)
                .and_then(|slot| slot.as_ref())
                .ok_or(NetError::InvalidSocket)?;
            if !socket.is_listener() {
                return Err(NetError::NotConnected);
            }
            (0..socket.backlog_len()).find(|entry| {
                socket
                    .backlog(*entry)
                    .map(|pending| pending.established)
                    .unwrap_or(false)
            })
        };
        let Some(entry_index) = entry_index else {
            return Err(NetError::WouldBlock);
        };
        // Budget check *before* taking the entry: an established connection must
        // not be lost when a table is full (M7a review fix 1).
        if self.slots.iter().all(|slot| !slot.is_free())
            || self.tcp.iter().all(|slot| slot.is_some())
        {
            return Err(NetError::Quota);
        }
        let (local, entry) = {
            let socket = self
                .tcp
                .get_mut(index)
                .and_then(|slot| slot.as_mut())
                .ok_or(NetError::InvalidSocket)?;
            let local = socket.local();
            let taken = socket.take_backlog(entry_index);
            let entry = taken.ok_or(NetError::WouldBlock)?;
            (local, entry)
        };
        let allocated = self.alloc_tcp_in_place(None, |slot, backlog, receive, send| {
            TcpSocket::accepted_into(
                slot,
                backlog,
                receive,
                send,
                local,
                entry.remote,
                entry.connection.clone(),
            )
        });
        match allocated {
            Ok((id, ())) => {
                // An accepted connection inherits the listener's address family
                // and stream hint. Without this the accepted slot keeps the
                // zeroed family from `alloc_slot`, and Linux `getsockname` on
                // the accepted fd fails with EINVAL (w7 cross-review finding).
                let domain = self.slots[index].domain;
                if let Some(accepted_index) = id.slot() {
                    self.slots[accepted_index].domain = domain;
                    self.slots[accepted_index].hint = SOCK_STREAM as u8;
                }
                // The connection now belongs to an accepted socket; a sender
                // that backed off in `tcp_send_locked` (peer still in the
                // backlog) can retry immediately instead of waiting for RTO.
                if let Some(peer) = self.peer_awaiting_accept(entry.remote, local) {
                    self.push_wake(peer, ReadyEvent::Write);
                }
                Ok(id)
            }
            Err(error) => {
                // Defensive rollback: put the established connection back so the
                // peer is not left hanging on a connection nobody accepts.
                if let Some(listener) = self.tcp.get_mut(index).and_then(|slot| slot.as_mut()) {
                    let _ = listener.push_backlog(entry);
                }
                Err(error)
            }
        }
    }

    fn tcp_send_locked(&mut self, id: SocketId, payload: &[u8]) -> Result<usize, NetError> {
        let index = self.tcp_index(id)?;
        if payload.is_empty() {
            return Ok(0);
        }
        if payload.len() > TCP_TX_SEG_MAX {
            return Err(NetError::TooLarge);
        }
        // Loopback back-pressure: refuse a segment the peer's receive ring
        // cannot hold. Without this the peer would have to answer with RST and
        // the connection would die instead of applying the advertised zero
        // window (M7a review fix 4).
        {
            let (local, remote) = {
                let socket = self
                    .tcp
                    .get(index)
                    .and_then(|slot| slot.as_ref())
                    .ok_or(NetError::InvalidSocket)?;
                if socket.is_listener() {
                    return Err(NetError::NotConnected);
                }
                let local = socket.local();
                let remote = match socket.remote() {
                    Some(remote) => remote,
                    None => {
                        return Err(NetError::NotConnected);
                    }
                };
                (local, remote)
            };
            let free = self
                .tcp
                .iter()
                .flatten()
                .find(|peer| {
                    !peer.is_listener() && peer.local() == remote && peer.remote() == Some(local)
                })
                .map(|peer| peer.receive().free());
            let awaits_accept = self.peer_awaits_accept(local, remote);
            match free {
                Some(free) if free < payload.len() => {
                    return Err(NetError::WouldBlock);
                }
                // The connection is established but still waits in a listener
                // backlog: `handle_backlog` would drop this payload, so back
                // off until `accept` hands the socket to userspace.
                None if awaits_accept => {
                    return Err(NetError::WouldBlock);
                }
                _ => {}
            }
        }
        let now = self.now;
        let (local, remote, seq, ack, window) = {
            let socket = self
                .tcp
                .get_mut(index)
                .and_then(|slot| slot.as_mut())
                .ok_or(NetError::InvalidSocket)?;
            if socket.is_listener() {
                return Err(NetError::NotConnected);
            }
            if socket.write_shut() || socket.closing() {
                return Err(NetError::NotConnected);
            }
            if socket.refused() {
                return Err(NetError::Refused);
            }
            if socket.error() {
                return Err(NetError::Reset);
            }
            let local = socket.local();
            let remote = match socket.remote() {
                Some(remote) => remote,
                None => {
                    return Err(NetError::NotConnected);
                }
            };
            let seq = match socket.connection_mut().send(payload.len() as u32, now) {
                Ok(seq) => seq,
                Err(error) => {
                    let error = map_packet_error(error);
                    return Err(error);
                }
            };
            let ack = socket.connection().rcv_nxt();
            // Advertise the space actually left in the receive ring.
            let window = socket.receive().free().min(usize::from(u16::MAX)) as u16;
            socket
                .send_mut()
                .set_data(tcp::FLAG_ACK | tcp::FLAG_PSH, seq, payload)?;
            (local, remote, seq, ack, window)
        };
        let fields = SegmentFields {
            flags: tcp::FLAG_ACK | tcp::FLAG_PSH,
            seq,
            ack,
            window,
        };
        match self.transmit_tcp(local, remote, fields, payload, 0) {
            Ok(()) => Ok(payload.len()),
            Err(error) => Err(error),
        }
    }

    fn tcp_recv_locked(&mut self, id: SocketId, out: &mut [u8]) -> Result<usize, NetError> {
        let index = self.tcp_index(id)?;
        if out.is_empty() {
            return Ok(0);
        }
        let (received, update, local, remote, seq, ack, window) = {
            let socket = self
                .tcp
                .get_mut(index)
                .and_then(|slot| slot.as_mut())
                .ok_or(NetError::InvalidSocket)?;
            if socket.is_listener() {
                return Err(NetError::NotConnected);
            }
            if socket.read_shut() {
                return Err(NetError::NotConnected);
            }
            if socket.refused() {
                return Err(NetError::Refused);
            }
            let received = socket.receive_mut().pop(out);
            // If the last segment advertised a zero window and the reader just
            // drained some space, announce the reopened window (M7a fix 4).
            let mut update = false;
            let window = socket.receive().free().min(usize::from(u16::MAX)) as u16;
            if received > 0 && socket.zero_window() && window > 0 {
                socket.clear_zero_window();
                update = true;
            }
            let local = socket.local();
            let remote = socket.remote();
            let seq = socket.connection().snd_nxt();
            let ack = socket.connection().rcv_nxt();
            (received, update, local, remote, seq, ack, window)
        };
        if received > 0 {
            if update {
                if let Some(remote) = remote {
                    let fields = SegmentFields {
                        flags: tcp::FLAG_ACK,
                        seq,
                        ack,
                        window,
                    };
                    self.transmit_tcp(local, remote, fields, &[], 0)?;
                }
            }
            return Ok(received);
        }
        let socket = self
            .tcp
            .get(index)
            .and_then(|slot| slot.as_ref())
            .ok_or(NetError::InvalidSocket)?;
        if socket.error() {
            return Err(NetError::Reset);
        }
        if socket.peer_fin() {
            return Ok(0);
        }
        Err(NetError::WouldBlock)
    }

    /// Half-close the write direction with FIN while keeping the socket alive
    /// for the peer's remaining data (review N2/N3).
    fn tcp_shutdown_write_locked(&mut self, id: SocketId) -> Result<(), NetError> {
        let index = self.tcp_index(id)?;
        let now = self.now;
        let (local, remote, fin) = {
            let socket = self
                .tcp
                .get_mut(index)
                .and_then(|slot| slot.as_mut())
                .ok_or(NetError::InvalidSocket)?;
            if socket.is_listener() {
                return Err(NetError::NotConnected);
            }
            if socket.write_shut() {
                return Ok(());
            }
            socket.set_write_shut();
            let local = socket.local();
            let Some(remote) = socket.remote() else {
                return Ok(());
            };
            let fin = socket.connection_mut().close(now);
            if let Some(segment) = fin {
                socket.send_mut().set_control(segment.flags, segment.seq);
                socket.set_closing();
            }
            (local, remote, fin)
        };
        if let Some(segment) = fin {
            self.transmit_tcp(local, remote, SegmentFields::from(segment), &[], 0)?;
        }
        Ok(())
    }

    fn tcp_close_locked(&mut self, id: SocketId) -> Result<(), NetError> {
        let index = self.tcp_index(id)?;
        let now = self.now;
        let listener = self
            .tcp
            .get(index)
            .and_then(|slot| slot.as_ref())
            .map(TcpSocket::is_listener)
            .ok_or(NetError::InvalidSocket)?;
        if listener {
            // Refuse every pending handshake explicitly instead of dropping it
            // silently: each backlog connection gets `RST|ACK` and the close
            // wakes waiters so they can observe the error (review N7).
            let mut refused = 0usize;
            loop {
                let pending = {
                    let Some(socket) = self.tcp.get_mut(index).and_then(|slot| slot.as_mut())
                    else {
                        break;
                    };
                    if socket.backlog_len() == 0 {
                        break;
                    }
                    let Some(entry) = socket.take_backlog(0) else {
                        break;
                    };
                    let local = socket.local();
                    let remote = entry.remote;
                    let seq = entry.connection.snd_nxt();
                    let ack = entry.connection.rcv_nxt();
                    (local, remote, seq, ack)
                };
                let (local, remote, seq, ack) = pending;
                let fields = SegmentFields {
                    flags: tcp::FLAG_RST | tcp::FLAG_ACK,
                    seq,
                    ack,
                    window: 0,
                };
                let _ = self.transmit_tcp(local, remote, fields, &[], 0);
                refused += 1;
            }
            if refused > 0 {
                self.push_wake(id, ReadyEvent::Error);
            }
            self.tcp[index] = None;
            self.free_slot(id);
            return Ok(());
        }
        let (local, remote, fin) = {
            let socket = self
                .tcp
                .get_mut(index)
                .and_then(|slot| slot.as_mut())
                .ok_or(NetError::InvalidSocket)?;
            let local = socket.local();
            let remote = socket.remote().ok_or(NetError::NotConnected)?;
            let fin = socket.connection_mut().close(now);
            if let Some(segment) = fin {
                socket.send_mut().set_control(segment.flags, segment.seq);
                socket.set_closing();
            }
            (local, remote, fin)
        };
        if let Some(segment) = fin {
            self.transmit_tcp(local, remote, SegmentFields::from(segment), &[], 0)?;
        }
        let settled = self
            .tcp
            .get(index)
            .and_then(|slot| slot.as_ref())
            .map(|socket| {
                let state = socket.connection().state();
                !socket.connection().retransmit_pending()
                    || matches!(
                        state,
                        TcpState::Closed
                            | TcpState::FinWait2
                            | TcpState::TimeWait
                            | TcpState::LastAck
                    )
            })
            .unwrap_or(true);
        if settled {
            self.tcp[index] = None;
            self.free_slot(id);
        }
        Ok(())
    }

    fn close_locked(&mut self, id: SocketId) -> Result<(), NetError> {
        match self.slot_kind(id)? {
            SlotKind::Udp(index) => {
                self.udp[usize::from(index)] = None;
                self.udp_peers[usize::from(index)] = None;
                self.free_slot(id);
                Ok(())
            }
            SlotKind::Tcp(_) => self.tcp_close_locked(id),
            // Local sockets release their peer link, path binding and payload.
            SlotKind::Unbound | SlotKind::LocalStream | SlotKind::LocalDatagram => {
                let index = self.slot_index(id)?;
                self.local_close_locked(index)
            }
            SlotKind::Free => Err(NetError::InvalidSocket),
        }
    }

    fn poll_locked(&self, id: SocketId) -> Result<PollMask, NetError> {
        match self.slot_kind(id)? {
            SlotKind::Udp(index) => {
                let socket = self
                    .udp
                    .get(usize::from(index))
                    .and_then(|slot| slot.as_ref())
                    .ok_or(NetError::InvalidSocket)?;
                let mut mask = PollMask::EMPTY.union(PollMask::WRITE);
                if !socket.queue().is_empty() {
                    mask = mask.union(PollMask::READ);
                }
                Ok(mask)
            }
            SlotKind::Tcp(index) => {
                let socket = self
                    .tcp
                    .get(usize::from(index))
                    .and_then(|slot| slot.as_ref())
                    .ok_or(NetError::InvalidSocket)?;
                if socket.is_listener() {
                    let ready = (0..socket.backlog_len()).any(|entry| {
                        socket
                            .backlog(entry)
                            .map(|pending| pending.established)
                            .unwrap_or(false)
                    });
                    return Ok(if ready {
                        PollMask::READ
                    } else {
                        PollMask::EMPTY
                    });
                }
                let mut mask = PollMask::EMPTY;
                if !socket.receive().is_empty() || socket.peer_fin() {
                    mask = mask.union(PollMask::READ);
                }
                if socket.error() || socket.refused() {
                    mask = mask.union(PollMask::ERROR);
                }
                // While the matching connection is still an unaccepted backlog
                // entry, `send` backs off; hide writability so a WOULD_BLOCK
                // retry sleeps until `accept` wakes it with `ReadyEvent::Write`.
                let awaiting_accept = socket
                    .remote()
                    .map(|remote| self.peer_awaits_accept(socket.local(), remote))
                    .unwrap_or(false);
                let state = socket.connection().state();
                if matches!(state, TcpState::Established | TcpState::CloseWait)
                    && !socket.connection().retransmit_pending()
                    && !socket.write_shut()
                    && !socket.closing()
                    && !awaiting_accept
                {
                    mask = mask.union(PollMask::WRITE);
                }
                Ok(mask)
            }
            // Created-but-unbound and local sockets: report the readiness the
            // local engine can produce without any INET traffic.
            SlotKind::Unbound | SlotKind::LocalStream | SlotKind::LocalDatagram => {
                let index = id.slot().ok_or(NetError::InvalidSocket)?;
                match self.slots[index].kind {
                    SlotKind::LocalStream => {
                        let stream = self.local_streams[index]
                            .as_ref()
                            .ok_or(NetError::InvalidSocket)?;
                        let mut mask = PollMask::EMPTY;
                        if stream.state == LocalState::Listening {
                            if stream.accept_len() > 0 {
                                mask = mask.union(PollMask::READ);
                            }
                        } else {
                            if !stream.read_shut
                                && (!stream.rx().is_empty() || stream.peer_write_shut)
                            {
                                mask = mask.union(PollMask::READ);
                            }
                            // Local stream writes are backpressured by the
                            // peer's receive ring: a full peer buffer must hide
                            // WRITE so a blocked writer actually sleeps until
                            // the reader drains (M7b phase 9 regression).
                            if let Some(peer_index) = stream.peer.slot() {
                                let peer_alive = self.slot_index(stream.peer).is_ok();
                                let peer_has_space = peer_alive
                                    && self.local_streams[peer_index]
                                        .as_ref()
                                        .map(|peer| peer.rx().free() > 0)
                                        .unwrap_or(false);
                                if stream.has_peer() && !stream.write_shut && peer_has_space {
                                    mask = mask.union(PollMask::WRITE);
                                }
                            }
                        }
                        Ok(mask)
                    }
                    SlotKind::LocalDatagram => {
                        let dgram = self.local_dgrams[index]
                            .as_ref()
                            .ok_or(NetError::InvalidSocket)?;
                        let mut mask = PollMask::EMPTY;
                        // Readiness covers queued datagrams (drainable) and a
                        // closed peer's EOF; an explicit local read shutdown
                        // keeps READ hidden.
                        if !dgram.read_shut && (!dgram.queue().is_empty() || dgram.peer_write_shut)
                        {
                            mask = mask.union(PollMask::READ);
                        }
                        if dgram.has_peer()
                            && !dgram.write_shut
                            && self.slot_index(dgram.connected).is_ok()
                        {
                            mask = mask.union(PollMask::WRITE);
                        }
                        Ok(mask)
                    }
                    _ => Ok(PollMask::EMPTY),
                }
            }
            SlotKind::Free => Err(NetError::InvalidSocket),
        }
    }

    fn on_tick_locked(&mut self, now: u64) -> usize {
        self.now = now;
        let mut retransmitted = 0;
        for index in 0..MAX_TCP_CONNECTIONS {
            let (give_up, retransmit) = {
                let Some(socket) = self.tcp[index].as_mut() else {
                    continue;
                };
                if socket.is_listener() || socket.error() {
                    continue;
                }
                let tick = socket.connection_mut().on_tick(now);
                if tick.give_up {
                    socket.set_error();
                    socket.send_mut().clear();
                }
                (tick.give_up, tick.retransmit)
            };
            if give_up {
                if let Some(id) = self.tcp_id_for(index) {
                    self.push_wake(id, ReadyEvent::Error);
                }
                continue;
            }
            if retransmit {
                self.stats.retransmits += 1;
                retransmitted += 1;
                let _ = self.retransmit_tcp(index, 0);
            }
        }
        retransmitted
    }
}

// ---------------------------------------------------------------------------
// Global stack instance
// ---------------------------------------------------------------------------

static NET: IrqSpinLock = IrqSpinLock::new();
static mut STACK: NetStack = NetStack::new();
static mut SCRATCH: [ScratchFrame; SCRATCH_DEPTH] = [const { ScratchFrame::new() }; SCRATCH_DEPTH];

/// Set by the tests to drop the next N transmitted frames (loss simulation).
#[cfg(test)]
static TX_DROP: AtomicUsize = AtomicUsize::new(0);

/// Wake hook; stored as a raw pointer-sized value so it can live in an atomic.
static WAKE_HOOK: AtomicUsize = AtomicUsize::new(0);

/// The only path to [`STACK`]; the caller must hold [`NET`].
fn stack_mut() -> &'static mut NetStack {
    // SAFETY: `STACK` is only reachable through this accessor, which every
    // caller invokes with `NET` held; the returned borrow never outlives the
    // critical section.
    unsafe { &mut *core::ptr::addr_of_mut!(STACK) }
}

/// One frame buffer per recursion depth of the loopback injection.
fn scratch_frame(depth: usize) -> Result<&'static mut [u8; MAX_FRAME_BYTES], NetError> {
    if depth >= SCRATCH_DEPTH {
        return Err(NetError::Quota);
    }
    // SAFETY: the recursion budget keeps every live frame on a distinct slot;
    // no two callers use the same depth at the same time.
    Ok(unsafe { &mut (*core::ptr::addr_of_mut!(SCRATCH))[depth].data })
}

fn map_packet_error(error: PacketError) -> NetError {
    match error {
        PacketError::OutOfRange => NetError::WouldBlock,
        PacketError::Unsupported => NetError::NotConnected,
        PacketError::Truncated | PacketError::BadLength => NetError::TooLarge,
        _ => NetError::Malformed,
    }
}

/// Run `f` under the stack lock, then deliver buffered wakes and release any
/// buffered object references after the lock is dropped.
fn with_stack<R>(f: impl FnOnce(&mut NetStack) -> R) -> R {
    let (result, wakes, releases) = {
        let _guard = NET.lock();
        let stack = stack_mut();
        let result = f(stack);
        (result, stack.take_wakes(), stack.take_releases())
    };
    dispatch_wakes(&wakes);
    release_objects(&releases);
    result
}

fn dispatch_wakes(batch: &WakeBatch) {
    if batch.len == 0 {
        return;
    }
    let raw = WAKE_HOOK.load(Ordering::Acquire);
    if raw == 0 {
        return;
    }
    // SAFETY: `set_wake_hook` only stores values converted from `WakeHook`
    // function pointers, and the load above observed a non-zero value.
    let hook: WakeHook = unsafe { mem::transmute::<usize, WakeHook>(raw) };
    for event in batch.as_slice() {
        hook(*event);
    }
}

// ---------------------------------------------------------------------------
// Frame construction
// ---------------------------------------------------------------------------

/// The fields of an outgoing TCP segment.
#[derive(Clone, Copy)]
struct SegmentFields {
    flags: u8,
    seq: u32,
    ack: u32,
    window: u16,
}

impl From<netcore::tcp::OutgoingSegment> for SegmentFields {
    fn from(segment: netcore::tcp::OutgoingSegment) -> SegmentFields {
        SegmentFields {
            flags: segment.flags,
            seq: segment.seq,
            ack: segment.ack,
            window: segment.window,
        }
    }
}

fn frame_error(error: PacketError) -> NetError {
    match error {
        PacketError::Truncated | PacketError::OutOfRange => NetError::TooLarge,
        _ => NetError::Malformed,
    }
}

fn build_udp_frame(
    out: &mut [u8],
    src: Endpoint,
    dst: Endpoint,
    payload: &[u8],
) -> Result<usize, NetError> {
    match (src.addr, dst.addr) {
        (IpAddr::V4(src_addr), IpAddr::V4(dst_addr)) => {
            if out.len() < ipv4::MIN_HEADER_LEN {
                return Err(NetError::TooLarge);
            }
            let upper = udp::write_v4(
                &mut out[ipv4::MIN_HEADER_LEN..],
                src.port,
                dst.port,
                src_addr,
                dst_addr,
                payload,
                true,
            )
            .map_err(frame_error)?;
            let header = ipv4::write_header(
                out,
                src_addr,
                dst_addr,
                PROTOCOL_UDP,
                LOOPBACK_TTL,
                0,
                0,
                0,
                upper,
            )
            .map_err(frame_error)?;
            Ok(header + upper)
        }
        (IpAddr::V6(src_addr), IpAddr::V6(dst_addr)) => {
            if out.len() < ipv6::HEADER_LEN {
                return Err(NetError::TooLarge);
            }
            let upper = udp::write_v6(
                &mut out[ipv6::HEADER_LEN..],
                src.port,
                dst.port,
                src_addr,
                dst_addr,
                payload,
            )
            .map_err(frame_error)?;
            let header = ipv6::write_header(
                out,
                src_addr,
                dst_addr,
                ipv6::NEXT_UDP,
                LOOPBACK_TTL,
                0,
                0,
                upper,
            )
            .map_err(frame_error)?;
            Ok(header + upper)
        }
        _ => Err(NetError::BadAddress),
    }
}

fn build_tcp_frame(
    out: &mut [u8],
    src: Endpoint,
    dst: Endpoint,
    segment: SegmentFields,
    payload: &[u8],
) -> Result<usize, NetError> {
    let mss_option = if segment.flags & tcp::FLAG_SYN != 0 {
        // MSS = TCP_TX_SEG_MAX, so a peer never sends more than one segment's
        // worth before waiting for our ACK.
        Some([
            tcp::OPTION_MSS,
            4,
            (TCP_TX_SEG_MAX >> 8) as u8,
            (TCP_TX_SEG_MAX & 0xFF) as u8,
        ])
    } else {
        None
    };
    let options: &[u8] = match &mss_option {
        Some(bytes) => &bytes[..],
        None => &[],
    };
    match (src.addr, dst.addr) {
        (IpAddr::V4(src_addr), IpAddr::V4(dst_addr)) => {
            if out.len() < ipv4::MIN_HEADER_LEN {
                return Err(NetError::TooLarge);
            }
            let upper = tcp::write_segment(
                &mut out[ipv4::MIN_HEADER_LEN..],
                src.port,
                dst.port,
                segment.seq,
                segment.ack,
                segment.flags,
                segment.window,
                options,
                payload,
            )
            .map_err(frame_error)?;
            tcp::fill_checksum_v4(&mut out[ipv4::MIN_HEADER_LEN..], upper, src_addr, dst_addr)
                .map_err(frame_error)?;
            let header = ipv4::write_header(
                out,
                src_addr,
                dst_addr,
                PROTOCOL_TCP,
                LOOPBACK_TTL,
                0,
                0,
                0,
                upper,
            )
            .map_err(frame_error)?;
            Ok(header + upper)
        }
        (IpAddr::V6(src_addr), IpAddr::V6(dst_addr)) => {
            if out.len() < ipv6::HEADER_LEN {
                return Err(NetError::TooLarge);
            }
            let upper = tcp::write_segment(
                &mut out[ipv6::HEADER_LEN..],
                src.port,
                dst.port,
                segment.seq,
                segment.ack,
                segment.flags,
                segment.window,
                options,
                payload,
            )
            .map_err(frame_error)?;
            tcp::fill_checksum_v6(&mut out[ipv6::HEADER_LEN..], upper, src_addr, dst_addr)
                .map_err(frame_error)?;
            let header = ipv6::write_header(
                out,
                src_addr,
                dst_addr,
                ipv6::NEXT_TCP,
                LOOPBACK_TTL,
                0,
                0,
                upper,
            )
            .map_err(frame_error)?;
            Ok(header + upper)
        }
        _ => Err(NetError::BadAddress),
    }
}

// ---------------------------------------------------------------------------
// Argument validation
// ---------------------------------------------------------------------------

fn validate_local(local: Endpoint) -> Result<(), NetError> {
    if local.port == 0 || !local.addr.is_loopback() {
        return Err(NetError::BadAddress);
    }
    Ok(())
}

fn validate_remote(local: Endpoint, remote: Endpoint) -> Result<(), NetError> {
    if remote.port == 0 || !remote.addr.is_loopback() || !local.addr.same_family(remote.addr) {
        return Err(NetError::BadAddress);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Reset the stack and mark it ready. Idempotent; closes every socket.
pub fn init() {
    with_stack(|stack| {
        stack.reset();
        stack.initialized = true;
    });
}

/// Whether [`init`] ran since the last reset.
pub fn is_initialized() -> bool {
    with_stack(|stack| stack.initialized)
}

/// Install (or clear) the readiness wake hook.
///
/// The hook runs on the caller's thread after the stack lock is released, once
/// per buffered event. M7b will point it at `process::wake_object`.
pub fn set_wake_hook(hook: Option<WakeHook>) {
    let raw = match hook {
        Some(hook) => hook as usize,
        None => 0,
    };
    WAKE_HOOK.store(raw, Ordering::Release);
}

/// Snapshot of the counters.
pub fn stats() -> NetStats {
    with_stack(|stack| stack.stats)
}

/// Number of sockets (including listeners) currently allocated.
pub fn socket_count() -> usize {
    with_stack(|stack| stack.sockets_used())
}

/// Create a UDP socket bound to `key.local`.
pub fn udp_bind(key: SocketKey) -> Result<SocketId, NetError> {
    with_stack(|stack| stack.udp_bind_locked(key))
}

/// Send `payload` from `id` to `dst` over loopback.
pub fn udp_send(id: SocketId, dst: Endpoint, payload: &[u8]) -> Result<usize, NetError> {
    with_stack(|stack| stack.udp_send_locked(id, dst, payload))
}

/// Receive one datagram, or [`NetError::WouldBlock`] when the queue is empty.
pub fn udp_recv(id: SocketId, out: &mut [u8]) -> Result<(usize, Endpoint), NetError> {
    with_stack(|stack| stack.udp_recv_locked(id, out))
}

/// Create a TCP listener bound to `key.local`.
pub fn tcp_listen(key: SocketKey) -> Result<SocketId, NetError> {
    with_stack(|stack| stack.tcp_listen_locked(key))
}

/// Open a TCP connection; the loopback handshake completes synchronously.
pub fn tcp_connect(key: SocketKey) -> Result<SocketId, NetError> {
    with_stack(|stack| stack.tcp_connect_locked(key))
}

/// Accept one completed handshake, or [`NetError::WouldBlock`].
pub fn tcp_accept(listener: SocketId) -> Result<SocketId, NetError> {
    with_stack(|stack| stack.tcp_accept_locked(listener))
}

/// Send `payload` on a connected socket.
pub fn tcp_send(id: SocketId, payload: &[u8]) -> Result<usize, NetError> {
    with_stack(|stack| stack.tcp_send_locked(id, payload))
}

/// Receive buffered bytes; `Ok(0)` means the peer half-closed.
pub fn tcp_recv(id: SocketId, out: &mut [u8]) -> Result<usize, NetError> {
    with_stack(|stack| stack.tcp_recv_locked(id, out))
}

/// Close a socket (UDP: drop the queue; TCP: FIN where possible).
pub fn close(id: SocketId) -> Result<(), NetError> {
    with_stack(|stack| stack.close_locked(id))
}

/// Close a TCP socket.
pub fn tcp_close(id: SocketId) -> Result<(), NetError> {
    with_stack(|stack| stack.tcp_close_locked(id))
}

/// Current readiness mask.
pub fn poll(id: SocketId) -> Result<PollMask, NetError> {
    with_stack(|stack| stack.poll_locked(id))
}

/// Local endpoint of a socket.
pub fn local_endpoint(id: SocketId) -> Result<Endpoint, NetError> {
    with_stack(|stack| match stack.slot_kind(id)? {
        SlotKind::Udp(index) => stack
            .udp
            .get(usize::from(index))
            .and_then(|slot| slot.as_ref())
            .map(UdpSocket::local)
            .ok_or(NetError::InvalidSocket),
        SlotKind::Tcp(index) => stack
            .tcp
            .get(usize::from(index))
            .and_then(|slot| slot.as_ref())
            .map(TcpSocket::local)
            .ok_or(NetError::InvalidSocket),
        SlotKind::Unbound => Err(NetError::BadAddress),
        SlotKind::LocalStream | SlotKind::LocalDatagram => Err(NetError::Unsupported),
        SlotKind::Free => Err(NetError::InvalidSocket),
    })
}

/// Remote endpoint of a connected socket.
pub fn remote_endpoint(id: SocketId) -> Result<Option<Endpoint>, NetError> {
    with_stack(|stack| match stack.slot_kind(id)? {
        SlotKind::Udp(_) => Ok(None),
        SlotKind::Tcp(index) => stack
            .tcp
            .get(usize::from(index))
            .and_then(|slot| slot.as_ref())
            .map(TcpSocket::remote)
            .ok_or(NetError::InvalidSocket),
        SlotKind::Unbound | SlotKind::LocalStream | SlotKind::LocalDatagram => Ok(None),
        SlotKind::Free => Err(NetError::InvalidSocket),
    })
}

/// Advance the stack clock and run retransmission timers; returns the number of
/// segments retransmitted.
pub fn on_tick(now: u64) -> usize {
    with_stack(|stack| stack.on_tick_locked(now))
}

/// Run the M7a loopback self-test.
///
/// Exercises IPv4 UDP, IPv6 UDP, IPv4 TCP and IPv6 TCP through the real
/// checksum/parser path, then resets the stack. The markers are `M7UDP4`,
/// `M7UDP6`, `M7TCP4` and `M7TCP6`.
pub fn selftest() -> Result<(), &'static str> {
    init();
    selftest_udp(
        Endpoint::v4(UDP_TEST_A_PORT),
        Endpoint::v4(UDP_TEST_B_PORT),
        UDP4_PAYLOAD,
    )
    .map_err(|_| "M7UDP4")?;
    selftest_udp(
        Endpoint::v6(UDP_TEST_A_PORT),
        Endpoint::v6(UDP_TEST_B_PORT),
        UDP6_PAYLOAD,
    )
    .map_err(|_| "M7UDP6")?;
    selftest_tcp(IpAddr::LOOPBACK_V4, TCP_TEST_PORT).map_err(|_| "M7TCP4")?;
    selftest_tcp(IpAddr::LOOPBACK_V6, TCP_TEST_PORT).map_err(|_| "M7TCP6")?;
    init();
    Ok(())
}

fn selftest_udp(a: Endpoint, b: Endpoint, payload: &[u8]) -> Result<(), ()> {
    let sender = udp_bind(SocketKey::bind(a, Protocol::Udp)).map_err(|_| ())?;
    let receiver = udp_bind(SocketKey::bind(b, Protocol::Udp)).map_err(|_| ())?;
    udp_send(sender, b, payload).map_err(|_| ())?;
    let mut buffer = [0u8; 32];
    let (len, source) = udp_recv(receiver, &mut buffer).map_err(|_| ())?;
    if len != payload.len() || &buffer[..len] != payload {
        return Err(());
    }
    if source != a {
        return Err(());
    }
    close(sender).map_err(|_| ())?;
    close(receiver).map_err(|_| ())?;
    Ok(())
}

fn selftest_tcp(addr: IpAddr, port: u16) -> Result<(), ()> {
    let listener =
        tcp_listen(SocketKey::bind(Endpoint::new(addr, port), Protocol::Tcp)).map_err(|_| ())?;
    let client = tcp_connect(SocketKey::connect(Endpoint::new(addr, port))).map_err(|_| ())?;
    let server = tcp_accept(listener).map_err(|_| ())?;
    let payload = b"m7 tcp payload";
    if tcp_send(client, payload).map_err(|_| ())? != payload.len() {
        return Err(());
    }
    let mut buffer = [0u8; 64];
    let len = tcp_recv(server, &mut buffer).map_err(|_| ())?;
    if len != payload.len() || &buffer[..len] != payload {
        return Err(());
    }
    let reply = b"ok";
    tcp_send(server, reply).map_err(|_| ())?;
    let len = tcp_recv(client, &mut buffer).map_err(|_| ())?;
    if len != reply.len() || &buffer[..len] != reply {
        return Err(());
    }
    tcp_close(client).map_err(|_| ())?;
    let eof = tcp_recv(server, &mut buffer).map_err(|_| ())?;
    if eof != 0 {
        return Err(());
    }
    tcp_close(server).map_err(|_| ())?;
    tcp_close(listener).map_err(|_| ())?;
    Ok(())
}

// ---------------------------------------------------------------------------
// M7b: generic socket front-end
// ---------------------------------------------------------------------------

/// Create an unbound socket for `domain`/`kind`.
///
/// The returned id stays the caller's handle for the whole lifetime: `bind`,
/// `listen` and `connect` upgrade the same slot in place.
pub fn create(domain: u32, kind: u32) -> Result<SocketId, NetError> {
    with_stack(|stack| stack.create_locked(domain, kind))
}

/// Bind a socket to `local` inside `namespace` (`0` is only valid for INET).
pub fn bind(id: SocketId, namespace: ObjectId, local: SocketAddress) -> Result<(), NetError> {
    with_stack(|stack| stack.bind_locked(id, namespace, local))
}

/// Start listening; for an INET stream this is where the TCP listener is
/// allocated (a plain `bind` only remembers the local address).
pub fn listen(id: SocketId, backlog: u32) -> Result<(), NetError> {
    with_stack(|stack| stack.listen_locked(id, backlog))
}

/// Connect to `remote`; for INET UDP this only remembers the peer.
pub fn connect(id: SocketId, namespace: ObjectId, remote: SocketAddress) -> Result<(), NetError> {
    with_stack(|stack| stack.connect_locked(id, namespace, remote))
}

/// Accept one pending connection of a listening socket.
pub fn accept(id: SocketId) -> Result<SocketId, NetError> {
    with_stack(|stack| stack.accept_locked(id))
}

/// Send `payload`, honouring the per-kind back-pressure rules.
pub fn send(id: SocketId, payload: &[u8]) -> Result<usize, NetError> {
    with_stack(|stack| stack.send_locked(id, payload))
}

/// Receive into `out`; stream `Ok(0)` means the peer half-closed.
pub fn recv(id: SocketId, out: &mut [u8]) -> Result<Received, NetError> {
    with_stack(|stack| stack.recv_locked(id, out))
}

/// Send one message with optional transferred object references (M9b).
///
/// `objects` are fd-object ids the caller acquired one reference for each. On
/// success this function takes ownership of those references (the peer's queue
/// or the stream ancillary record owns them until they are received/dropped);
/// on any error nothing is consumed or released, so the caller still owns them.
///
/// `cred` attaches `SCM_CREDENTIALS` to the carrying message. A stream send
/// cannot carry ancillary data without a payload byte to bind it to
/// ([`NetError::Unsupported`]).
pub fn send_msg(
    id: SocketId,
    payload: &[u8],
    objects: &[ObjectId],
    cred: Option<Credential>,
) -> Result<usize, NetError> {
    with_stack(|stack| stack.send_msg_locked(id, payload, objects, cred))
}

/// Receive one message, transferring its object references to the caller (M9b).
///
/// On success the caller owns one reference per `objects[..object_count]` of
/// the returned [`ReceivedMessage`] and must install or release them; `cred`
/// holds the credentials the carrying send attached (if any). A stream `Ok`
/// with `len == 0` and no objects means the peer half-closed.
pub fn recv_msg(
    id: SocketId,
    out: &mut [u8],
    objects_out: &mut [ObjectId; MAX_SCM_FDS],
) -> Result<ReceivedMessage, NetError> {
    with_stack(|stack| stack.recv_msg_locked(id, out, objects_out))
}

/// Remember the credentials of the process owning `id` (M9b).
pub fn set_cred(id: SocketId, cred: Credential) -> Result<(), NetError> {
    with_stack(|stack| {
        let index = stack.slot_index(id)?;
        stack.slots[index].cred = cred;
        Ok(())
    })
}

/// `SO_PASSCRED`: attach sender credentials to every received message.
pub fn set_passcred(id: SocketId, enabled: bool) -> Result<(), NetError> {
    with_stack(|stack| {
        let index = stack.slot_index(id)?;
        stack.slots[index].passcred = enabled;
        Ok(())
    })
}

/// Current `SO_PASSCRED` state of a socket.
pub fn passcred(id: SocketId) -> Result<bool, NetError> {
    with_stack(|stack| {
        let index = stack.slot_index(id)?;
        Ok(stack.slots[index].passcred)
    })
}

/// Credentials of the connected peer (`SO_PEERCRED`), if one is known.
pub fn peer_cred(id: SocketId) -> Result<Option<Credential>, NetError> {
    with_stack(|stack| {
        let index = stack.slot_index(id)?;
        if let Some(cred) = stack.slots[index].peer_cred {
            return Ok(Some(cred));
        }
        let peer = match stack.slots[index].kind {
            SlotKind::LocalStream => stack.local_streams[index]
                .as_ref()
                .map(|stream| stream.peer),
            SlotKind::LocalDatagram => stack.local_dgrams[index]
                .as_ref()
                .map(|dgram| dgram.connected),
            _ => None,
        };
        Ok(peer
            .and_then(|peer_id| stack.slot_index(peer_id).ok())
            .map(|peer_index| stack.slots[peer_index].cred)
            .filter(|cred| cred.is_set()))
    })
}

/// Close one direction (local sockets) or the write side (TCP FIN).
pub fn shutdown(id: SocketId, how: ShutdownHow) -> Result<(), NetError> {
    with_stack(|stack| stack.shutdown_locked(id, how))
}

/// Release a socket and wake its peer.
pub fn destroy(id: SocketId) -> Result<(), NetError> {
    close(id)
}

/// Anonymous connected pair (UNIX stream or datagram).
pub fn socket_pair(domain: u32, kind: u32) -> Result<(SocketId, SocketId), NetError> {
    with_stack(|stack| stack.socket_pair_locked(domain, kind))
}

/// Remember the object that owns `id`, so wake events can be routed to it.
pub fn attach_object(id: SocketId, object: ObjectId) -> Result<(), NetError> {
    with_stack(|stack| {
        let index = stack.slot_index(id)?;
        stack.slots[index].object = object;
        Ok(())
    })
}

/// Owning object of a live socket, if one was attached.
pub fn object_of(id: SocketId) -> Option<ObjectId> {
    with_stack(|stack| {
        let index = stack.slot_index(id).ok()?;
        let object = stack.slots[index].object;
        if object == 0 { None } else { Some(object) }
    })
}

/// Drop every path binding of `namespace` and close the sockets behind them.
pub fn destroy_namespace(namespace: ObjectId) -> usize {
    with_stack(|stack| stack.destroy_namespace_locked(namespace))
}

/// Live sockets (any kind).
pub fn live_count() -> usize {
    with_stack(|stack| stack.sockets_used())
}

/// Path bindings currently installed in `namespace`.
pub fn binding_count(namespace: ObjectId) -> usize {
    with_stack(|stack| {
        stack
            .namespaces
            .iter()
            .flatten()
            .find(|entry| entry.id == namespace)
            .map(NamespaceEntry::binding_count)
            .unwrap_or(0)
    })
}

/// Live local (UNIX) sockets.
pub fn local_count() -> usize {
    with_stack(|stack| {
        stack
            .slots
            .iter()
            .filter(|slot| matches!(slot.kind, SlotKind::LocalStream | SlotKind::LocalDatagram))
            .count()
    })
}

/// Local address of a socket (`BadAddress` when it was never bound).
pub fn local_address(id: SocketId) -> Result<SocketAddress, NetError> {
    with_stack(|stack| stack.address_locked(id, false))
}

/// Peer address of a socket; `SocketAddress::INVALID` when there is no peer
/// (unconnected, or an anonymous socketpair).
pub fn remote_address(id: SocketId) -> Result<SocketAddress, NetError> {
    with_stack(|stack| match stack.address_locked(id, true) {
        Ok(address) => Ok(address),
        Err(NetError::NotConnected) => Ok(SocketAddress::INVALID),
        Err(other) => Err(other),
    })
}

/// Local or peer address of a socket (`peer = false` → local).
pub fn address(id: SocketId, peer: bool) -> Result<SocketAddress, NetError> {
    with_stack(|stack| stack.address_locked(id, peer))
}

impl NetStack {
    fn address_locked(&self, id: SocketId, peer: bool) -> Result<SocketAddress, NetError> {
        let index = self.slot_index(id)?;
        let family = self.slots[index].domain as u32;
        match self.slots[index].kind {
            SlotKind::Unbound => {
                if peer {
                    return Err(NetError::NotConnected);
                }
                match self.slots[index].local {
                    Some(local) => Ok(SocketAddress::from_endpoint(local, family)),
                    // An unbound socket has no address yet; the ABI reports the
                    // all-zero address instead of an error (Lead M7b review N4).
                    None => Ok(SocketAddress::INVALID),
                }
            }
            SlotKind::Udp(udp_index) => {
                let socket = self
                    .udp
                    .get(usize::from(udp_index))
                    .and_then(|slot| slot.as_ref())
                    .ok_or(NetError::InvalidSocket)?;
                if peer {
                    self.udp_peers[index]
                        .map(|remote| SocketAddress::from_endpoint(remote, family))
                        .ok_or(NetError::NotConnected)
                } else {
                    Ok(SocketAddress::from_endpoint(socket.local(), family))
                }
            }
            SlotKind::Tcp(tcp_index) => {
                let socket = self
                    .tcp
                    .get(usize::from(tcp_index))
                    .and_then(|slot| slot.as_ref())
                    .ok_or(NetError::InvalidSocket)?;
                if peer {
                    socket
                        .remote()
                        .map(|remote| SocketAddress::from_endpoint(remote, family))
                        .ok_or(NetError::NotConnected)
                } else {
                    Ok(SocketAddress::from_endpoint(socket.local(), family))
                }
            }
            SlotKind::LocalStream => {
                let stream = self.local_streams[index]
                    .as_ref()
                    .ok_or(NetError::InvalidSocket)?;
                if peer {
                    let peer_index = stream
                        .peer
                        .slot()
                        .filter(|_| self.slot_index(stream.peer).is_ok())
                        .ok_or(NetError::NotConnected)?;
                    Ok(self.local_addrs[peer_index])
                } else {
                    Ok(self.local_addrs[index])
                }
            }
            SlotKind::LocalDatagram => {
                let dgram = self.local_dgrams[index]
                    .as_ref()
                    .ok_or(NetError::InvalidSocket)?;
                if peer {
                    let peer_index = dgram
                        .connected
                        .slot()
                        .filter(|_| self.slot_index(dgram.connected).is_ok())
                        .ok_or(NetError::NotConnected)?;
                    Ok(self.local_addrs[peer_index])
                } else {
                    Ok(self.local_addrs[index])
                }
            }
            SlotKind::Free => Err(NetError::InvalidSocket),
        }
    }
}

impl NetStack {
    /// Slot index of a live, current id.
    fn slot_index(&self, id: SocketId) -> Result<usize, NetError> {
        let index = id.slot().ok_or(NetError::InvalidSocket)?;
        let slot = self.slots.get(index).ok_or(NetError::InvalidSocket)?;
        if slot.is_free() || slot.generation != id.generation() {
            return Err(NetError::InvalidSocket);
        }
        Ok(index)
    }

    /// Id that names `index` right now.
    fn local_id(&self, index: usize) -> Result<SocketId, NetError> {
        let slot = self.slots.get(index).ok_or(NetError::InvalidSocket)?;
        if slot.is_free() {
            return Err(NetError::InvalidSocket);
        }
        Ok(SocketId::new(index, slot.generation))
    }

    fn create_locked(&mut self, domain: u32, kind: u32) -> Result<SocketId, NetError> {
        if kind != SOCK_STREAM && kind != SOCK_DGRAM {
            return Err(NetError::Unsupported);
        }
        if domain != DOMAIN_UNIX && domain != DOMAIN_INET && domain != DOMAIN_INET6 {
            return Err(NetError::Unsupported);
        }
        let id = self.alloc_slot(SlotKind::Unbound)?;
        if let Some(index) = id.slot() {
            self.slots[index].domain = domain as u8;
            self.slots[index].hint = kind as u8;
        }
        Ok(id)
    }

    /// Move an already allocated INET socket into the caller's slot, so the id
    /// returned by [`create`] stays the handle.
    ///
    /// The freshly allocated engine usually already sits at the adopted index
    /// (`create` -> `bind`); in that case only the temporary id slot is freed.
    /// If a different live engine occupies the target index, the fresh
    /// allocation is dropped and `AddressInUse` is reported instead of silently
    /// overwriting a live socket (review M6).
    fn adopt_udp(&mut self, slot: usize, inner: SocketId) -> Result<(), NetError> {
        if slot >= self.udp.len() {
            return Err(NetError::InvalidSocket);
        }
        let inner_index = self.udp_index(inner)?;
        if inner_index == slot {
            // The freshly bound engine already lives at the adopted index (the
            // common `create` -> `bind` shape): nothing to move, only the
            // temporary socket slot of `inner` has to go.
            self.free_slot(inner);
            self.slots[slot].kind = SlotKind::Udp(slot as u8);
            return Ok(());
        }
        if self.udp[slot].is_some() {
            // A different socket lives at the adopted index: reject and drop the
            // engine the caller just allocated, leaving no half-adopted state.
            self.udp[inner_index] = None;
            self.free_slot(inner);
            return Err(NetError::AddressInUse);
        }
        let mut socket = self
            .udp
            .get_mut(inner_index)
            .and_then(Option::take)
            .ok_or(NetError::InvalidSocket)?;
        self.free_slot(inner);
        // The socket's queue pointer must follow it into the adopted slot; the
        // old slot's pool element is no longer owned by this socket.
        let queue = core::ptr::addr_of_mut!(self.udp_queues[slot]);
        socket.set_queue(queue);
        self.udp[slot] = Some(socket);
        self.slots[slot].kind = SlotKind::Udp(slot as u8);
        Ok(())
    }

    fn adopt_tcp(&mut self, slot: usize, inner: SocketId) -> Result<(), NetError> {
        if slot >= self.tcp.len() {
            return Err(NetError::InvalidSocket);
        }
        let inner_index = self.tcp_index(inner)?;
        if inner_index == slot {
            // See `adopt_udp`: the engine already sits at the adopted index.
            self.free_slot(inner);
            self.slots[slot].kind = SlotKind::Tcp(slot as u8);
            return Ok(());
        }
        if self.tcp[slot].is_some() {
            self.tcp[inner_index] = None;
            self.free_slot(inner);
            return Err(NetError::AddressInUse);
        }
        let mut socket = self
            .tcp
            .get_mut(inner_index)
            .and_then(Option::take)
            .ok_or(NetError::InvalidSocket)?;
        self.free_slot(inner);
        // Same as `adopt_udp`: the storage pointers must follow the socket into
        // its adopted slot.
        let backlog = self.tcp_backlogs[slot].as_mut_ptr();
        let receive = core::ptr::addr_of_mut!(self.tcp_receive[slot]);
        let send = core::ptr::addr_of_mut!(self.tcp_send[slot]);
        socket.retarget_storage(backlog, receive, send);
        self.tcp[slot] = Some(socket);
        self.slots[slot].kind = SlotKind::Tcp(slot as u8);
        Ok(())
    }

    fn namespace_slot_or_create(&mut self, namespace: ObjectId) -> Result<usize, NetError> {
        if namespace == 0 {
            return Err(NetError::BadAddress);
        }
        if let Some(index) = self
            .namespaces
            .iter()
            .position(|entry| entry.as_ref().is_some_and(|entry| entry.id == namespace))
        {
            return Ok(index);
        }
        let free = self
            .namespaces
            .iter()
            .position(Option::is_none)
            .ok_or(NetError::Quota)?;
        let bindings = core::ptr::addr_of_mut!(self.namespace_bindings[free]);
        self.namespaces[free] = Some(NamespaceEntry::new(namespace, bindings));
        Ok(free)
    }

    fn find_binding(&self, namespace: ObjectId, path: &[u8]) -> Option<PathBinding> {
        self.namespaces
            .iter()
            .flatten()
            .find(|entry| entry.id == namespace)
            .and_then(|entry| {
                entry
                    .bindings()
                    .iter()
                    .flatten()
                    .find(|binding| binding.path_bytes() == path)
                    .copied()
            })
    }

    fn bind_locked(
        &mut self,
        id: SocketId,
        namespace: ObjectId,
        local: SocketAddress,
    ) -> Result<(), NetError> {
        let index = self.slot_index(id)?;
        let (domain, hint) = (self.slots[index].domain, self.slots[index].hint);
        if !matches!(self.slots[index].kind, SlotKind::Unbound) {
            return Err(NetError::AddressInUse);
        }
        if domain == DOMAIN_UNIX as u8 {
            if !local.is_unix() {
                return Err(NetError::BadAddress);
            }
            let path_len = local.path_len as usize;
            // `SOCKET_PATH_MAX` is the longest accepted path; the array itself
            // has `SOCKET_PATH_BYTES` bytes (review N8). Abstract names carry a
            // leading NUL byte, so their stored length can reach the full array
            // (107 name bytes + the NUL).
            let max_len = if local.is_abstract() {
                SOCKET_PATH_BYTES
            } else {
                SOCKET_PATH_MAX
            };
            if path_len == 0 || path_len > max_len {
                return Err(NetError::BadAddress);
            }
            let ns_index = self.namespace_slot_or_create(namespace)?;
            let mut binding = PathBinding::empty();
            binding.path_len = path_len as u8;
            binding.path[..path_len].copy_from_slice(local.path_bytes());
            binding.slot = index as u8;
            binding.stream = hint == SOCK_STREAM as u8;
            let entry = self.namespaces[ns_index].as_mut().ok_or(NetError::Quota)?;
            let bindings = entry.bindings_mut();
            if bindings
                .iter()
                .flatten()
                .any(|existing| existing.path_bytes() == local.path_bytes())
            {
                return Err(NetError::AddressInUse);
            }
            let free = bindings
                .iter()
                .position(Option::is_none)
                .ok_or(NetError::Quota)?;
            bindings[free] = Some(binding);
            self.local_addrs[index] = local;
            if hint == SOCK_STREAM as u8 {
                let rx = core::ptr::addr_of_mut!(self.local_stream_rx[index]);
                self.local_streams[index] = Some(LocalStream::new(namespace, rx));
                self.slots[index].kind = SlotKind::LocalStream;
            } else {
                let queue = core::ptr::addr_of_mut!(self.local_dgram_queues[index]);
                self.local_dgrams[index] = Some(LocalDatagram::new(namespace, queue));
                self.slots[index].kind = SlotKind::LocalDatagram;
            }
            return Ok(());
        }
        let mut endpoint = local.as_endpoint().ok_or(NetError::BadAddress)?;
        let want_v6 = domain == DOMAIN_INET6 as u8;
        if want_v6 != matches!(endpoint.addr, IpAddr::V6(_)) {
            return Err(NetError::BadAddress);
        }
        // INET/INET6 bind with port 0 asks the stack to pick a free local port
        // (`services/net` binds its UDP phases this way). `validate_local`
        // rejects port 0, so the real port has to be chosen here, before the
        // socket adopts its engine object; the allocated endpoint is stored on
        // this slot (stream) or in the UDP socket (datagram) so that
        // `local_address`/`socket_address` report the assigned port.
        if endpoint.port == 0 {
            let port = self.alloc_ephemeral(endpoint.addr)?;
            endpoint = Endpoint::new(endpoint.addr, port);
        }
        if hint == SOCK_DGRAM as u8 {
            let inner = self.udp_bind_locked(SocketKey::bind(endpoint, Protocol::Udp))?;
            return self.adopt_udp(index, inner);
        }
        if self.slots[index].local.is_some() {
            return Err(NetError::AddressInUse);
        }
        self.slots[index].local = Some(endpoint);
        Ok(())
    }

    fn listen_locked(&mut self, id: SocketId, backlog: u32) -> Result<(), NetError> {
        let index = self.slot_index(id)?;
        if self.slots[index].hint != SOCK_STREAM as u8 {
            return Err(NetError::Unsupported);
        }
        // The ABI validates 1..=64; keep the kernel side bounded by the static
        // queue and remember the requested limit (review M4).
        let limit = backlog.clamp(1, MAX_BACKLOG as u32) as u16;
        match self.slots[index].kind {
            SlotKind::Unbound => {
                let local = self.slots[index].local.ok_or(NetError::BadAddress)?;
                let inner = self.tcp_listen_locked(SocketKey::bind(local, Protocol::Tcp))?;
                self.adopt_tcp(index, inner)?;
                if let Some(socket) = self.tcp[index].as_mut() {
                    socket.set_backlog_limit(limit);
                }
                Ok(())
            }
            SlotKind::LocalStream => {
                let stream = self.local_streams[index]
                    .as_mut()
                    .ok_or(NetError::InvalidSocket)?;
                if stream.state != LocalState::Bound {
                    return Err(NetError::AddressInUse);
                }
                stream.state = LocalState::Listening;
                stream.set_backlog_limit(limit);
                Ok(())
            }
            _ => Err(NetError::Unsupported),
        }
    }

    fn connect_locked(
        &mut self,
        id: SocketId,
        namespace: ObjectId,
        remote: SocketAddress,
    ) -> Result<(), NetError> {
        let index = self.slot_index(id)?;
        let (domain, hint) = (self.slots[index].domain, self.slots[index].hint);
        if domain == DOMAIN_UNIX as u8 {
            if !remote.is_unix() {
                return Err(NetError::BadAddress);
            }
            return match hint {
                value if value == SOCK_STREAM as u8 => {
                    // A UNIX stream client may connect before bind; the client
                    // side of the connection is implicit, like `socket()` +
                    // `connect()` on Linux.
                    if matches!(self.slots[index].kind, SlotKind::Unbound) {
                        let rx = core::ptr::addr_of_mut!(self.local_stream_rx[index]);
                        let mut stream = LocalStream::new(namespace, rx);
                        stream.state = LocalState::Bound;
                        self.local_streams[index] = Some(stream);
                        self.slots[index].kind = SlotKind::LocalStream;
                    }
                    self.local_connect_stream(index, namespace, &remote)
                }
                _ => {
                    if matches!(self.slots[index].kind, SlotKind::Unbound) {
                        let queue = core::ptr::addr_of_mut!(self.local_dgram_queues[index]);
                        self.local_dgrams[index] = Some(LocalDatagram::new(namespace, queue));
                        self.slots[index].kind = SlotKind::LocalDatagram;
                    }
                    self.local_connect_datagram(index, namespace, &remote)
                }
            };
        }
        let endpoint = remote.as_endpoint().ok_or(NetError::BadAddress)?;
        if !endpoint.addr.is_loopback() || endpoint.port == 0 {
            return Err(NetError::BadAddress);
        }
        let want_v6 = domain == DOMAIN_INET6 as u8;
        if want_v6 != matches!(endpoint.addr, IpAddr::V6(_)) {
            return Err(NetError::BadAddress);
        }
        if hint == SOCK_DGRAM as u8 {
            match self.slots[index].kind {
                SlotKind::Udp(_) => {}
                SlotKind::Unbound => {
                    // `connect` on a datagram socket only records the default
                    // peer (docs/abi/native-syscall.md 6.48). Linux also gives
                    // the socket an ephemeral local port at that point, which
                    // the datagram needs before it can `send` or report a
                    // local address, so bind it implicitly here.
                    let port = self.alloc_ephemeral(endpoint.addr)?;
                    let local = Endpoint::new(endpoint.addr, port);
                    let inner = self.udp_bind_locked(SocketKey::bind(local, Protocol::Udp))?;
                    self.adopt_udp(index, inner)?;
                }
                _ => return Err(NetError::NotConnected),
            }
            self.udp_peers[index] = Some(endpoint);
            return Ok(());
        }
        let key = match self.slots[index].local {
            Some(local) => SocketKey::connect_from(local, endpoint),
            None => SocketKey::connect(endpoint),
        };
        let inner = self.tcp_connect_locked(key)?;
        self.adopt_tcp(index, inner)
    }

    fn local_connect_stream(
        &mut self,
        index: usize,
        namespace: ObjectId,
        remote: &SocketAddress,
    ) -> Result<(), NetError> {
        let binding = self
            .find_binding(namespace, remote.path_bytes())
            .ok_or(NetError::NotFound)?;
        // A path bound by a datagram socket exists but cannot accept streams:
        // that is a refusal, not an unsupported operation (review N6).
        if !binding.stream {
            return Err(NetError::Refused);
        }
        let target_index = usize::from(binding.slot);
        {
            let listener = self
                .local_streams
                .get(target_index)
                .and_then(|slot| slot.as_ref())
                .ok_or(NetError::Refused)?;
            if listener.state != LocalState::Listening {
                return Err(NetError::Refused);
            }
            if listener.accept_full() {
                return Err(NetError::WouldBlock);
            }
        }
        if !matches!(self.slots[index].kind, SlotKind::LocalStream) {
            return Err(NetError::NotConnected);
        }
        if self.local_streams[index]
            .as_ref()
            .is_some_and(|stream| stream.state != LocalState::Bound)
        {
            return Err(NetError::AddressInUse);
        }
        let client_id = self.local_id(index)?;
        let peer_index = {
            let peer = self.alloc_slot(SlotKind::LocalStream)?;
            let peer_index = peer.slot().ok_or(NetError::Quota)?;
            self.slots[peer_index].domain = self.slots[index].domain;
            self.slots[peer_index].hint = self.slots[index].hint;
            self.local_addrs[peer_index] = SocketAddress::INVALID;
            let rx = core::ptr::addr_of_mut!(self.local_stream_rx[peer_index]);
            let mut peer_stream = LocalStream::new(namespace, rx);
            peer_stream.state = LocalState::Connected;
            peer_stream.set_peer(client_id);
            self.local_streams[peer_index] = Some(peer_stream);
            peer_index
        };
        let peer_id = self.local_id(peer_index)?;
        {
            let stream = self.local_streams[index]
                .as_mut()
                .ok_or(NetError::InvalidSocket)?;
            stream.state = LocalState::Connected;
            stream.set_peer(peer_id);
        }
        // Both ends learn each other's identity: the accepted side sees the
        // connecting process, the client sees the listener's process.
        self.slots[peer_index].cred = self.slots[index].cred;
        self.slots[peer_index].peer_cred = Some(self.slots[index].cred);
        self.slots[index].peer_cred = Some(self.slots[target_index].cred);
        {
            let listener = self.local_streams[target_index]
                .as_mut()
                .ok_or(NetError::Refused)?;
            debug_assert!(
                listener.accept_push(peer_id),
                "accept queue overran its limit"
            );
        }
        let listener_id = self.local_id(target_index)?;
        self.push_wake(listener_id, ReadyEvent::Read);
        Ok(())
    }

    fn local_connect_datagram(
        &mut self,
        index: usize,
        namespace: ObjectId,
        remote: &SocketAddress,
    ) -> Result<(), NetError> {
        let binding = self
            .find_binding(namespace, remote.path_bytes())
            .ok_or(NetError::NotFound)?;
        if binding.stream {
            return Err(NetError::Refused);
        }
        let peer_index = usize::from(binding.slot);
        if !matches!(
            self.slots.get(peer_index).map(|slot| slot.kind),
            Some(SlotKind::LocalDatagram)
        ) {
            return Err(NetError::Refused);
        }
        let peer_id = self.local_id(peer_index)?;
        let peer_cred = self.slots[peer_index].cred;
        let dgram = self.local_dgrams[index]
            .as_mut()
            .ok_or(NetError::InvalidSocket)?;
        dgram.connected = peer_id;
        // Re-connecting a datagram socket to a live path clears the EOF
        // marker left by a previously closed peer (Linux allows connect() on a
        // datagram socket to replace the default peer).
        dgram.peer_write_shut = false;
        self.slots[index].peer_cred = Some(peer_cred);
        Ok(())
    }

    fn accept_locked(&mut self, id: SocketId) -> Result<SocketId, NetError> {
        let index = self.slot_index(id)?;
        match self.slots[index].kind {
            SlotKind::Tcp(_) => self.tcp_accept_locked(id),
            SlotKind::LocalStream => loop {
                let taken = {
                    let stream = self.local_streams[index]
                        .as_mut()
                        .ok_or(NetError::InvalidSocket)?;
                    if stream.state != LocalState::Listening {
                        return Err(NetError::NotConnected);
                    }
                    match stream.accept_take() {
                        Some(taken) => taken,
                        None => return Err(NetError::WouldBlock),
                    }
                };
                if self.slot_index(taken).is_ok() {
                    return Ok(taken);
                }
                // The queued peer was closed before it could be accepted:
                // drop the stale entry and try the next one (review M1).
            },
            _ => Err(NetError::Unsupported),
        }
    }

    fn send_locked(&mut self, id: SocketId, payload: &[u8]) -> Result<usize, NetError> {
        let index = self.slot_index(id)?;
        match self.slots[index].kind {
            SlotKind::Udp(_) => {
                let dst = self.udp_peers[index].ok_or(NetError::NotConnected)?;
                self.udp_send_locked(id, dst, payload)
            }
            SlotKind::Tcp(_) => self.tcp_send_locked(id, payload),
            SlotKind::LocalStream | SlotKind::LocalDatagram => {
                self.send_msg_locked(id, payload, &[], None)
            }
            SlotKind::Unbound | SlotKind::Free => Err(NetError::NotConnected),
        }
    }

    fn recv_locked(&mut self, id: SocketId, out: &mut [u8]) -> Result<Received, NetError> {
        let mut objects = [0; MAX_SCM_FDS];
        let message = self.recv_msg_locked(id, out, &mut objects)?;
        // Plain `recv`/`read` has no ancillary buffer: descriptors that were
        // attached to the consumed bytes are dropped here (Linux does the
        // same). The net table lock is held, so only queue them for release;
        // `with_stack` runs the actual `release_object` calls after the lock
        // is dropped.
        for object in message
            .objects
            .iter()
            .take(usize::from(message.object_count))
        {
            self.push_release(*object);
        }
        Ok(Received {
            len: message.len,
            source: message.source,
        })
    }

    /// Send one message with optional transferred objects and credentials.
    fn send_msg_locked(
        &mut self,
        id: SocketId,
        payload: &[u8],
        objects: &[ObjectId],
        cred: Option<Credential>,
    ) -> Result<usize, NetError> {
        if objects.len() > MAX_SCM_FDS {
            return Err(NetError::Unsupported);
        }
        let index = self.slot_index(id)?;
        // Plain streaming kinds keep their M7b behaviour when no ancillary data
        // is attached; only UNIX sockets can carry objects/credentials.
        if objects.is_empty() && cred.is_none() {
            match self.slots[index].kind {
                SlotKind::Udp(_) | SlotKind::Tcp(_) => return self.send_locked(id, payload),
                _ => {}
            }
        }
        match self.slots[index].kind {
            SlotKind::LocalStream => {
                if payload.is_empty() {
                    return Err(NetError::Unsupported);
                }
                let (peer, write_shut) = match self.local_streams[index].as_ref() {
                    Some(stream) => (stream.peer, stream.write_shut),
                    None => return Err(NetError::InvalidSocket),
                };
                if write_shut {
                    return Err(NetError::NotConnected);
                }
                let peer_index = peer.slot().ok_or(NetError::NotConnected)?;
                if self.slot_index(peer).is_err() {
                    return Err(NetError::NotConnected);
                }
                if payload.len() > LOCAL_STREAM_BYTES {
                    return Err(NetError::TooLarge);
                }
                let carries = !objects.is_empty() || cred.is_some();
                {
                    let stream = self.local_streams[peer_index]
                        .as_mut()
                        .ok_or(NetError::PeerClosed)?;
                    if stream.state == LocalState::Closed || stream.read_shut {
                        return Err(NetError::PeerClosed);
                    }
                    if stream.rx().len() + payload.len() > LOCAL_STREAM_BYTES {
                        return Err(NetError::WouldBlock);
                    }
                    if carries && stream.ancillary_len() >= LOCAL_ANCILLARY_DEPTH {
                        return Err(NetError::WouldBlock);
                    }
                    if !stream.rx_mut().push(payload) {
                        return Err(NetError::WouldBlock);
                    }
                    if carries {
                        let mut record = StreamAncillary::empty();
                        record.at = stream.rx_received;
                        record.count = objects.len() as u8;
                        record.objects[..objects.len()].copy_from_slice(objects);
                        record.cred = cred;
                        let queued = stream.push_ancillary(record);
                        debug_assert!(queued, "ancillary depth was checked above");
                    }
                    stream.rx_received += payload.len() as u64;
                }
                self.push_wake(peer, ReadyEvent::Read);
                Ok(payload.len())
            }
            SlotKind::LocalDatagram => {
                let (connected, write_shut) = match self.local_dgrams[index].as_ref() {
                    Some(dgram) => (dgram.connected, dgram.write_shut),
                    None => return Err(NetError::InvalidSocket),
                };
                if write_shut {
                    return Err(NetError::NotConnected);
                }
                let peer_index = connected.slot().ok_or(NetError::NotConnected)?;
                if self.slot_index(connected).is_err() {
                    let peer_closed = self.local_dgrams[index]
                        .as_ref()
                        .map(|dgram| dgram.peer_write_shut)
                        .unwrap_or(false);
                    return Err(if peer_closed {
                        NetError::PeerClosed
                    } else {
                        NetError::NotConnected
                    });
                }
                let source = self.local_addrs[index];
                {
                    let target = self.local_dgrams[peer_index]
                        .as_mut()
                        .ok_or(NetError::NotConnected)?;
                    if target.read_shut {
                        return Err(NetError::PeerClosed);
                    }
                    target
                        .queue_mut()
                        .push_msg(payload, source, objects, cred)?;
                }
                self.push_wake(connected, ReadyEvent::Read);
                Ok(payload.len())
            }
            _ => Err(NetError::Unsupported),
        }
    }

    /// Receive one message, transferring object references to the caller.
    fn recv_msg_locked(
        &mut self,
        id: SocketId,
        out: &mut [u8],
        objects_out: &mut [ObjectId; MAX_SCM_FDS],
    ) -> Result<ReceivedMessage, NetError> {
        let index = self.slot_index(id)?;
        let message = match self.slots[index].kind {
            SlotKind::Udp(_) => {
                let (len, source) = self.udp_recv_locked(id, out)?;
                ReceivedMessage {
                    len,
                    source: Some(SocketAddress::from_endpoint(
                        source,
                        self.slots[index].domain as u32,
                    )),
                    objects: [0; MAX_SCM_FDS],
                    object_count: 0,
                    cred: None,
                }
            }
            SlotKind::Tcp(_) => ReceivedMessage {
                len: self.tcp_recv_locked(id, out)?,
                source: None,
                objects: [0; MAX_SCM_FDS],
                object_count: 0,
                cred: None,
            },
            SlotKind::LocalStream => {
                if out.is_empty() {
                    return Ok(ReceivedMessage::empty());
                }
                let (len, peer, record) = {
                    let stream = self.local_streams[index]
                        .as_mut()
                        .ok_or(NetError::InvalidSocket)?;
                    if stream.read_shut {
                        return Err(NetError::NotConnected);
                    }
                    if stream.rx().is_empty() {
                        if stream.peer_write_shut || stream.state == LocalState::Closed {
                            return Ok(ReceivedMessage::empty());
                        }
                        return Err(NetError::WouldBlock);
                    }
                    let len = stream.rx_mut().pop(out);
                    if len == 0 {
                        return Err(NetError::WouldBlock);
                    }
                    stream.rx_consumed += len as u64;
                    let record = match stream.peek_ancillary() {
                        Some(record) if record.at < stream.rx_consumed => stream.pop_ancillary(),
                        _ => None,
                    };
                    (len, stream.peer, record)
                };
                if len > 0 && peer.slot().is_some() && self.slot_index(peer).is_ok() {
                    self.push_wake(peer, ReadyEvent::Write);
                }
                match record {
                    Some(record) => ReceivedMessage {
                        len,
                        source: None,
                        objects: record.objects,
                        object_count: record.count,
                        cred: record.cred,
                    },
                    None => ReceivedMessage {
                        len,
                        source: None,
                        objects: [0; MAX_SCM_FDS],
                        object_count: 0,
                        cred: None,
                    },
                }
            }
            SlotKind::LocalDatagram => {
                let dgram = self.local_dgrams[index]
                    .as_mut()
                    .ok_or(NetError::InvalidSocket)?;
                if dgram.read_shut {
                    return Err(NetError::NotConnected);
                }
                if dgram.queue().is_empty() {
                    if dgram.peer_write_shut {
                        return Ok(ReceivedMessage::empty());
                    }
                    return Err(NetError::WouldBlock);
                }
                dgram.queue_mut().pop_msg(out)?
            }
            SlotKind::Unbound | SlotKind::Free => return Err(NetError::NotConnected),
        };
        *objects_out = message.objects;
        Ok(message)
    }

    fn shutdown_locked(&mut self, id: SocketId, how: ShutdownHow) -> Result<(), NetError> {
        let index = self.slot_index(id)?;
        match self.slots[index].kind {
            SlotKind::Tcp(_) => {
                {
                    let socket = self.tcp[index].as_mut().ok_or(NetError::InvalidSocket)?;
                    if how.closes_read() {
                        socket.set_read_shut();
                    }
                    // The write direction is closed by the helper below so it
                    // can decide whether to send FIN (review N2/N3).
                }
                if how.closes_write() {
                    // A write shutdown sends FIN but keeps the socket alive so
                    // the read direction can still drain the peer's data; only
                    // an explicit close releases it (review N2/N3).
                    self.tcp_shutdown_write_locked(id)
                } else {
                    // A read-only shutdown is legal and only blocks further
                    // receives; the write direction keeps working (review N2).
                    Ok(())
                }
            }
            SlotKind::LocalStream => {
                let peer = {
                    let stream = self.local_streams[index]
                        .as_mut()
                        .ok_or(NetError::InvalidSocket)?;
                    if how.closes_read() {
                        stream.read_shut = true;
                    }
                    if how.closes_write() {
                        stream.write_shut = true;
                    }
                    stream.peer
                };
                if how.closes_write() {
                    if let Some(peer_index) = peer.slot().filter(|_| self.slot_index(peer).is_ok())
                    {
                        if let Some(target) = self.local_streams[peer_index].as_mut() {
                            target.peer_write_shut = true;
                        }
                        self.push_wake(peer, ReadyEvent::Read);
                    }
                }
                Ok(())
            }
            SlotKind::LocalDatagram => {
                let dgram = self.local_dgrams[index]
                    .as_mut()
                    .ok_or(NetError::InvalidSocket)?;
                if how.closes_read() {
                    dgram.read_shut = true;
                }
                if how.closes_write() {
                    dgram.write_shut = true;
                }
                Ok(())
            }
            _ => Err(NetError::Unsupported),
        }
    }

    /// Close a local (or unbound) socket, waking the peer where one exists.
    /// Move every queued ancillary descriptor of stream `index` into the
    /// release batch. Called on close so unused SCM_RIGHTS references do not
    /// leak; the caller must not hold a borrow of the stream while calling.
    fn drain_stream_ancillary(&mut self, index: usize) {
        let mut objects = [0; LOCAL_ANCILLARY_DEPTH * MAX_SCM_FDS];
        let mut count = 0;
        if let Some(stream) = self.local_streams[index].as_mut() {
            while let Some(record) = stream.pop_ancillary() {
                for object in record.objects.iter().take(record.len()) {
                    objects[count] = *object;
                    count += 1;
                }
            }
        }
        for object in objects.iter().take(count) {
            self.push_release(*object);
        }
    }

    /// Move every queued datagram's descriptors addressed to `index` into the
    /// release batch (same lifetime rule as [`Self::drain_stream_ancillary`]).
    fn drain_datagram_objects(&mut self, index: usize) {
        let mut objects = [0; LOCAL_DGRAM_DEPTH * MAX_SCM_FDS];
        let count = self.local_dgram_queues[index].drain_objects(&mut objects);
        for object in objects.iter().take(count) {
            self.push_release(*object);
        }
    }

    fn local_close_locked(&mut self, index: usize) -> Result<(), NetError> {
        match self.slots[index].kind {
            SlotKind::LocalStream => {
                let (peer, queued) = match self.local_streams[index].as_ref() {
                    Some(stream) => (stream.peer, stream.accept_queue),
                    None => (SocketId::INVALID, [SocketId::INVALID; LOCAL_BACKLOG]),
                };
                if let Some(peer_index) = peer.slot().filter(|_| self.slot_index(peer).is_ok()) {
                    if let Some(target) = self.local_streams[peer_index].as_mut() {
                        target.peer_write_shut = true;
                    }
                    self.push_wake(peer, ReadyEvent::Read);
                }
                self.drain_stream_ancillary(index);
                self.local_streams[index] = None;
                self.local_addrs[index] = SocketAddress::INVALID;
                // Connections already queued for `accept` must not be dropped
                // silently: closing the listener hands each *client* EOF and a
                // wake so it can observe the shutdown, and releases the
                // never-accepted server end (review N7/M2).
                for queued_id in queued {
                    let Some(queued_index) = queued_id
                        .slot()
                        .filter(|_| self.slot_index(queued_id).is_ok())
                    else {
                        continue;
                    };
                    let client = self.local_streams[queued_index]
                        .as_ref()
                        .map(|stream| stream.peer)
                        .unwrap_or(SocketId::INVALID);
                    self.drain_stream_ancillary(queued_index);
                    self.local_streams[queued_index] = None;
                    self.local_addrs[queued_index] = SocketAddress::INVALID;
                    self.release_bindings_of_slot(queued_index);
                    let _ = self.free_slot(queued_id);
                    if let Some(client_index) =
                        client.slot().filter(|_| self.slot_index(client).is_ok())
                    {
                        if let Some(target) = self.local_streams[client_index].as_mut() {
                            target.peer_write_shut = true;
                        }
                        self.push_wake(client, ReadyEvent::Read);
                    }
                }
            }
            SlotKind::LocalDatagram => {
                // Mirror the LocalStream close notification: a still-live
                // connected peer learns that this end is gone. The dedicated
                // `peer_write_shut` marker (not `read_shut`, which is an
                // explicit local shutdown) lets the survivor drain already
                // queued datagrams, then read EOF and report `PeerClosed` on
                // later sends (M7b phase 12 / phase 7 regression).
                let connected = self.local_dgrams[index]
                    .as_ref()
                    .map(|dgram| dgram.connected);
                if let Some(peer) = connected {
                    if let Some(peer_index) = peer.slot().filter(|_| self.slot_index(peer).is_ok())
                    {
                        if let Some(target) = self.local_dgrams[peer_index].as_mut() {
                            target.peer_write_shut = true;
                        }
                        self.push_wake(peer, ReadyEvent::Read);
                    }
                }
                self.drain_datagram_objects(index);
                self.local_dgrams[index] = None;
                self.local_addrs[index] = SocketAddress::INVALID;
            }
            _ => {}
        }
        self.release_bindings_of_slot(index);
        self.udp_peers[index] = None;
        self.free_slot(self.local_id(index)?);
        Ok(())
    }

    /// Drop every namespace binding that points at `index`.
    fn release_bindings_of_slot(&mut self, index: usize) {
        for entry in self.namespaces.iter_mut().flatten() {
            for binding in entry.bindings_mut().iter_mut() {
                if binding.is_some_and(|binding| usize::from(binding.slot) == index) {
                    *binding = None;
                }
            }
        }
    }

    fn socket_pair_locked(
        &mut self,
        domain: u32,
        kind: u32,
    ) -> Result<(SocketId, SocketId), NetError> {
        if domain != DOMAIN_UNIX {
            return Err(NetError::Unsupported);
        }
        if kind != SOCK_STREAM && kind != SOCK_DGRAM {
            return Err(NetError::Unsupported);
        }
        let first = self.alloc_slot(SlotKind::Unbound)?;
        let first_index = first.slot().ok_or(NetError::Quota)?;
        let second = self.alloc_slot(SlotKind::Unbound)?;
        let second_index = second.slot().ok_or(NetError::Quota)?;
        self.slots[first_index].domain = DOMAIN_UNIX as u8;
        self.slots[first_index].hint = kind as u8;
        self.slots[second_index].domain = DOMAIN_UNIX as u8;
        self.slots[second_index].hint = kind as u8;
        let first_id = self.local_id(first_index)?;
        let second_id = self.local_id(second_index)?;
        if kind == SOCK_STREAM {
            let first_rx = core::ptr::addr_of_mut!(self.local_stream_rx[first_index]);
            let second_rx = core::ptr::addr_of_mut!(self.local_stream_rx[second_index]);
            let mut a = LocalStream::new(0, first_rx);
            a.state = LocalState::Connected;
            a.set_peer(second_id);
            let mut b = LocalStream::new(0, second_rx);
            b.state = LocalState::Connected;
            b.set_peer(first_id);
            self.local_streams[first_index] = Some(a);
            self.local_streams[second_index] = Some(b);
            self.slots[first_index].kind = SlotKind::LocalStream;
            self.slots[second_index].kind = SlotKind::LocalStream;
        } else {
            let first_queue = core::ptr::addr_of_mut!(self.local_dgram_queues[first_index]);
            let second_queue = core::ptr::addr_of_mut!(self.local_dgram_queues[second_index]);
            let mut a = LocalDatagram::new(0, first_queue);
            a.connected = second_id;
            let mut b = LocalDatagram::new(0, second_queue);
            b.connected = first_id;
            self.local_dgrams[first_index] = Some(a);
            self.local_dgrams[second_index] = Some(b);
            self.slots[first_index].kind = SlotKind::LocalDatagram;
            self.slots[second_index].kind = SlotKind::LocalDatagram;
        }
        Ok((first_id, second_id))
    }

    fn destroy_namespace_locked(&mut self, namespace: ObjectId) -> usize {
        let mut closed = 0;
        let mut slots = [0usize; MAX_SOCKETS];
        let mut count = 0;
        for entry in self.namespaces.iter_mut() {
            if entry.as_ref().is_none_or(|entry| entry.id != namespace) {
                continue;
            }
            if let Some(entry) = entry.as_mut() {
                for binding in entry.bindings_mut().iter_mut() {
                    if let Some(binding) = binding.take() {
                        slots[count] = usize::from(binding.slot);
                        count += 1;
                    }
                }
            }
            *entry = None;
        }
        for index in slots.into_iter().take(count) {
            if let Ok(id) = self.local_id(index) {
                if self.close_locked(id).is_ok() {
                    closed += 1;
                }
            }
        }
        closed
    }
}

/// Inject a raw frame into the receive path (tests only).
#[cfg(test)]
pub(crate) fn inject_frame(frame: &[u8]) -> Result<(), NetError> {
    with_stack(|stack| stack.inject_locked(frame, 0))
}

/// Drop the next `count` transmitted frames to simulate loss (tests only).
#[cfg(test)]
pub(crate) fn test_drop_next_tx(count: usize) {
    TX_DROP.store(count, Ordering::SeqCst);
}

/// The TCP sequence state `(snd_nxt, rcv_nxt)` of a socket (tests only).
#[cfg(test)]
pub(crate) fn test_tcp_seq(id: SocketId) -> Option<(u32, u32)> {
    with_stack(|stack| {
        let index = stack.tcp_index(id).ok()?;
        let socket = stack.tcp[index].as_ref()?;
        Some((socket.connection().snd_nxt(), socket.connection().rcv_nxt()))
    })
}

// ---------------------------------------------------------------------------
// Host tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    static TEST_SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn serial() -> std::sync::MutexGuard<'static, ()> {
        TEST_SERIAL
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
    }

    fn setup() -> std::sync::MutexGuard<'static, ()> {
        let guard = serial();
        set_wake_hook(None);
        init();
        tx_drop_reset();
        guard
    }

    fn tx_drop_reset() {
        TX_DROP.store(0, Ordering::SeqCst);
    }

    fn udp_socket(port: u16) -> SocketId {
        udp_bind(SocketKey::bind(Endpoint::v4(port), Protocol::Udp)).expect("udp bind")
    }

    fn tcp_pair() -> (SocketId, SocketId, SocketId) {
        let listener =
            tcp_listen(SocketKey::bind(Endpoint::v4(9_001), Protocol::Tcp)).expect("tcp listen");
        let client = tcp_connect(SocketKey::connect(Endpoint::v4(9_001))).expect("tcp connect");
        let server = tcp_accept(listener).expect("tcp accept");
        (listener, client, server)
    }

    #[test]
    fn udp_ipv4_round_trip_through_loopback() {
        let _guard = setup();
        let a = udp_socket(UDP_TEST_A_PORT);
        let b = udp_socket(UDP_TEST_B_PORT);
        let sent = udp_send(a, Endpoint::v4(UDP_TEST_B_PORT), UDP4_PAYLOAD).expect("send");
        assert_eq!(sent, UDP4_PAYLOAD.len());
        let mut buffer = [0u8; 32];
        let (len, source) = udp_recv(b, &mut buffer).expect("receive");
        assert_eq!(&buffer[..len], UDP4_PAYLOAD);
        assert_eq!(source, Endpoint::v4(UDP_TEST_A_PORT));
        assert!(stats().udp_datagrams >= 1);
    }

    #[test]
    fn udp_ipv6_round_trip_through_loopback() {
        let _guard = setup();
        let a = udp_bind(SocketKey::bind(
            Endpoint::v6(UDP_TEST_A_PORT),
            Protocol::Udp,
        ))
        .expect("bind v6");
        let b = udp_bind(SocketKey::bind(
            Endpoint::v6(UDP_TEST_B_PORT),
            Protocol::Udp,
        ))
        .expect("bind v6");
        udp_send(a, Endpoint::v6(UDP_TEST_B_PORT), UDP6_PAYLOAD).expect("send");
        let mut buffer = [0u8; 32];
        let (len, source) = udp_recv(b, &mut buffer).expect("receive");
        assert_eq!(&buffer[..len], UDP6_PAYLOAD);
        assert_eq!(source, Endpoint::v6(UDP_TEST_A_PORT));
    }

    #[test]
    fn tcp_ipv4_handshake_data_and_fin() {
        let _guard = setup();
        let (listener, client, server) = tcp_pair();
        assert!(poll(client).unwrap().contains(PollMask::WRITE));
        assert!(poll(server).unwrap().contains(PollMask::WRITE));

        let payload = b"m7 tcp payload";
        assert_eq!(tcp_send(client, payload).unwrap(), payload.len());
        let mut buffer = [0u8; 64];
        let len = tcp_recv(server, &mut buffer).unwrap();
        assert_eq!(&buffer[..len], payload);

        tcp_send(server, b"ok").unwrap();
        let len = tcp_recv(client, &mut buffer).unwrap();
        assert_eq!(&buffer[..len], b"ok");

        tcp_close(client).unwrap();
        assert_eq!(tcp_recv(server, &mut buffer).unwrap(), 0);

        tcp_close(server).unwrap();
        tcp_close(listener).unwrap();
        assert_eq!(socket_count(), 0);
    }

    #[test]
    fn tcp_ipv6_handshake_data_and_fin() {
        let _guard = setup();
        let listener = tcp_listen(SocketKey::bind(Endpoint::v6(9_002), Protocol::Tcp)).unwrap();
        let client = tcp_connect(SocketKey::connect(Endpoint::v6(9_002))).unwrap();
        let server = tcp_accept(listener).unwrap();
        let payload = b"v6 payload";
        tcp_send(client, payload).unwrap();
        let mut buffer = [0u8; 64];
        let len = tcp_recv(server, &mut buffer).unwrap();
        assert_eq!(&buffer[..len], payload);
        tcp_close(client).unwrap();
        assert_eq!(tcp_recv(server, &mut buffer).unwrap(), 0);
    }

    #[test]
    fn corrupted_udp_checksum_is_dropped() {
        let _guard = setup();
        let b = udp_socket(UDP_TEST_B_PORT);
        let frame = build_udp_frame(
            scratch_frame(0).unwrap(),
            Endpoint::v4(UDP_TEST_A_PORT),
            Endpoint::v4(UDP_TEST_B_PORT),
            b"corrupt",
        )
        .unwrap();
        let mut buffer = [0u8; MAX_FRAME_BYTES];
        buffer[..frame].copy_from_slice(&scratch_frame(0).unwrap()[..frame]);
        buffer[ipv4::MIN_HEADER_LEN + udp::HEADER_LEN] ^= 0xFF;
        assert_eq!(inject_frame(&buffer[..frame]), Err(NetError::Malformed));
        assert_eq!(
            udp_recv(b, &mut [0u8; 32]).unwrap_err(),
            NetError::WouldBlock
        );
        assert!(stats().rx_malformed >= 1);
    }

    #[test]
    fn corrupted_tcp_checksum_is_dropped() {
        let _guard = setup();
        let (_listener, client, server) = tcp_pair();
        let (snd_nxt, rcv_nxt) = test_tcp_seq(client).unwrap();
        let local = local_endpoint(client).unwrap();
        let remote = local_endpoint(server).unwrap();
        let mut segment = [0u8; 128];
        let len = build_tcp_frame(
            &mut segment,
            local,
            remote,
            SegmentFields {
                flags: tcp::FLAG_ACK | tcp::FLAG_PSH,
                seq: snd_nxt,
                ack: rcv_nxt,
                window: TCP_WINDOW,
            },
            b"payload",
        )
        .unwrap();
        segment[ipv4::MIN_HEADER_LEN + tcp::HEADER_LEN] ^= 0xFF;
        assert_eq!(inject_frame(&segment[..len]), Err(NetError::Malformed));
        assert_eq!(
            tcp_recv(server, &mut [0u8; 32]).unwrap_err(),
            NetError::WouldBlock
        );
    }

    #[test]
    fn duplicate_tcp_segment_is_acked_without_redelivery() {
        let _guard = setup();
        let (_listener, client, server) = tcp_pair();
        let (snd_nxt, rcv_nxt) = test_tcp_seq(client).unwrap();
        let local = local_endpoint(client).unwrap();
        let remote = local_endpoint(server).unwrap();
        let mut buffer = [0u8; 128];
        let fields = SegmentFields {
            flags: tcp::FLAG_ACK | tcp::FLAG_PSH,
            seq: snd_nxt,
            ack: rcv_nxt,
            window: TCP_WINDOW,
        };
        let len = build_tcp_frame(&mut buffer, local, remote, fields, b"xy").unwrap();
        let before = stats().tcp_segments;
        inject_frame(&buffer[..len]).unwrap();
        assert_eq!(tcp_recv(server, &mut [0u8; 8]).unwrap(), 2);
        inject_frame(&buffer[..len]).unwrap();
        assert_eq!(
            tcp_recv(server, &mut [0u8; 8]).unwrap_err(),
            NetError::WouldBlock
        );
        // Both injections were parsed (the duplicate is acknowledged but never
        // handed to the socket again).
        assert!(stats().tcp_segments >= before + 2);
    }

    #[test]
    fn tcp_reset_is_reported_as_an_error() {
        let _guard = setup();
        let (_listener, client, server) = tcp_pair();
        let (snd_nxt, rcv_nxt) = test_tcp_seq(client).unwrap();
        let local = local_endpoint(client).unwrap();
        let remote = local_endpoint(server).unwrap();
        let mut buffer = [0u8; 128];
        let len = build_tcp_frame(
            &mut buffer,
            local,
            remote,
            SegmentFields {
                flags: tcp::FLAG_RST,
                seq: snd_nxt,
                ack: rcv_nxt,
                window: 0,
            },
            &[],
        )
        .unwrap();
        inject_frame(&buffer[..len]).unwrap();
        assert!(poll(server).unwrap().contains(PollMask::ERROR));
        assert_eq!(tcp_recv(server, &mut [0u8; 8]), Err(NetError::Reset));
        assert!(stats().resets >= 1);
    }

    #[test]
    fn tcp_retransmits_once_after_the_rto() {
        let _guard = setup();
        let (_listener, client, server) = tcp_pair();
        test_drop_next_tx(1);
        assert_eq!(tcp_send(client, b"abc").unwrap(), 3);
        assert_eq!(
            tcp_recv(server, &mut [0u8; 8]).unwrap_err(),
            NetError::WouldBlock
        );
        assert_eq!(on_tick(tcp::INITIAL_RTO_TICKS + 1), 1);
        let mut buffer = [0u8; 8];
        assert_eq!(tcp_recv(server, &mut buffer).unwrap(), 3);
        assert_eq!(&buffer[..3], b"abc");
        assert!(stats().retransmits >= 1);
        // The retransmitted payload was acknowledged, so the socket can send again.
        assert_eq!(tcp_send(client, b"de").unwrap(), 2);
        tx_drop_reset();
    }

    #[test]
    fn a_full_udp_queue_applies_backpressure_without_dropping() {
        let _guard = setup();
        let sender = udp_socket(9_101);
        let receiver = udp_socket(9_102);
        for _ in 0..UDP_QUEUE_DEPTH {
            udp_send(sender, Endpoint::v4(9_102), b"d").unwrap();
        }
        assert_eq!(
            udp_send(sender, Endpoint::v4(9_102), b"d").unwrap_err(),
            NetError::WouldBlock
        );
        let mut buffer = [0u8; 4];
        for _ in 0..UDP_QUEUE_DEPTH {
            assert_eq!(udp_recv(receiver, &mut buffer).unwrap().0, 1);
        }
        assert_eq!(
            udp_recv(receiver, &mut buffer).unwrap_err(),
            NetError::WouldBlock
        );
        assert_eq!(stats().udp_queue_dropped, 0);
        // The failed datagram is gone but nothing queued was dropped, and the
        // sender may retry once space exists.
        udp_send(sender, Endpoint::v4(9_102), b"e").unwrap();
        assert_eq!(udp_recv(receiver, &mut buffer).unwrap().0, 1);
    }

    #[test]
    fn an_undersized_receive_buffer_never_consumes_the_datagram() {
        let _guard = setup();
        let sender = udp_socket(9_111);
        let receiver = udp_socket(9_112);
        udp_send(sender, Endpoint::v4(9_112), b"seven!!").unwrap();
        let mut small = [0u8; 3];
        assert_eq!(
            udp_recv(receiver, &mut small).unwrap_err(),
            NetError::TooLarge
        );
        let mut big = [0u8; 16];
        let (len, source) = udp_recv(receiver, &mut big).unwrap();
        assert_eq!(&big[..len], b"seven!!");
        assert_eq!(source, Endpoint::v4(9_111));
        assert_eq!(
            udp_recv(receiver, &mut big).unwrap_err(),
            NetError::WouldBlock
        );
    }

    #[test]
    fn an_oversized_datagram_is_rejected_without_queueing() {
        let _guard = setup();
        let sender = udp_socket(9_121);
        let receiver = udp_socket(9_122);
        let payload = [0xABu8; UDP_DGRAM_MAX + 1];
        assert_eq!(
            udp_send(sender, Endpoint::v4(9_122), &payload).unwrap_err(),
            NetError::TooLarge
        );
        assert_eq!(
            udp_recv(receiver, &mut [0u8; 4]).unwrap_err(),
            NetError::WouldBlock
        );
    }

    #[test]
    fn datagram_queue_peek_keeps_the_datagram_on_a_short_buffer() {
        let mut queue = DatagramQueue::new();
        assert!(queue.push(b"abc", Endpoint::v4(1)));
        let mut small = [0u8; 2];
        assert_eq!(queue.pop(&mut small).unwrap_err(), NetError::TooLarge);
        assert_eq!(queue.len(), 1);
        assert_eq!(queue.peek_len(), Some(3));
        let mut big = [0u8; 8];
        let (len, source) = queue.pop(&mut big).unwrap();
        assert_eq!(len, 3);
        assert_eq!(&big[..len], b"abc");
        assert_eq!(source, Endpoint::v4(1));
        assert_eq!(queue.len(), 0);
    }

    #[test]
    fn closed_socket_ids_are_stale() {
        let _guard = setup();
        let id = udp_socket(9_201);
        close(id).unwrap();
        assert_eq!(udp_recv(id, &mut [0u8; 4]), Err(NetError::InvalidSocket));
        let rebound = udp_socket(9_201);
        assert_ne!(id, rebound);
        assert!(poll(rebound).unwrap().contains(PollMask::WRITE));
    }

    #[test]
    fn rebound_socket_does_not_inherit_old_datagrams() {
        let _guard = setup();
        let sender = udp_socket(9_301);
        let receiver = udp_socket(9_302);
        udp_send(sender, Endpoint::v4(9_302), b"first").unwrap();
        close(receiver).unwrap();
        let rebound = udp_socket(9_302);
        udp_send(sender, Endpoint::v4(9_302), b"second").unwrap();
        let mut buffer = [0u8; 16];
        let (len, _source) = udp_recv(rebound, &mut buffer).unwrap();
        assert_eq!(&buffer[..len], b"second");
        assert_eq!(
            udp_recv(rebound, &mut buffer).unwrap_err(),
            NetError::WouldBlock
        );
    }

    #[test]
    fn poll_tracks_readiness_on_both_transports() {
        let _guard = setup();
        let sender = udp_socket(9_401);
        let receiver = udp_socket(9_402);
        assert!(poll(receiver).unwrap().contains(PollMask::WRITE));
        assert!(!poll(receiver).unwrap().contains(PollMask::READ));
        udp_send(sender, Endpoint::v4(9_402), b"x").unwrap();
        assert!(poll(receiver).unwrap().contains(PollMask::READ));

        let listener = tcp_listen(SocketKey::bind(Endpoint::v4(9_403), Protocol::Tcp)).unwrap();
        assert!(poll(listener).unwrap().is_empty());
        let client = tcp_connect(SocketKey::connect(Endpoint::v4(9_403))).unwrap();
        assert!(poll(listener).unwrap().contains(PollMask::READ));
        let server = tcp_accept(listener).unwrap();
        let mut buffer = [0u8; 8];
        tcp_send(client, b"xy").unwrap();
        assert!(poll(server).unwrap().contains(PollMask::READ));
        assert_eq!(tcp_recv(server, &mut buffer).unwrap(), 2);
        assert!(!poll(server).unwrap().contains(PollMask::READ));
    }

    static HOOK_CALLS: AtomicUsize = AtomicUsize::new(0);
    static HOOK_SAW_LOCK: AtomicUsize = AtomicUsize::new(0);

    fn probe_hook(_event: WakeEvent) {
        HOOK_CALLS.fetch_add(1, Ordering::SeqCst);
        if NET.is_locked() {
            HOOK_SAW_LOCK.store(1, Ordering::SeqCst);
        }
    }

    #[test]
    fn wake_hook_runs_after_the_stack_lock_is_released() {
        let _guard = setup();
        HOOK_CALLS.store(0, Ordering::SeqCst);
        HOOK_SAW_LOCK.store(0, Ordering::SeqCst);
        set_wake_hook(Some(probe_hook));
        let sender = udp_socket(9_501);
        let _receiver = udp_socket(9_502);
        udp_send(sender, Endpoint::v4(9_502), b"x").unwrap();
        set_wake_hook(None);
        assert!(HOOK_CALLS.load(Ordering::SeqCst) >= 1);
        assert_eq!(HOOK_SAW_LOCK.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn init_is_idempotent_and_clears_every_table() {
        let _guard = setup();
        let id = udp_socket(9_601);
        assert_eq!(socket_count(), 1);
        init();
        init();
        assert_eq!(socket_count(), 0);
        assert_eq!(udp_recv(id, &mut [0u8; 4]), Err(NetError::InvalidSocket));
        assert_eq!(stats().udp_datagrams, 0);
    }

    #[test]
    fn selftest_covers_all_four_loopback_paths() {
        let _guard = setup();
        assert_eq!(selftest(), Ok(()));
        assert_eq!(socket_count(), 0);
    }

    #[test]
    fn selftest_is_repeatable() {
        let _guard = setup();
        assert_eq!(selftest(), Ok(()));
        assert_eq!(selftest(), Ok(()));
    }

    // -- M7b front-end -----------------------------------------------------

    static WAKE_COUNT: AtomicUsize = AtomicUsize::new(0);
    static WAKE_OBJECT: AtomicUsize = AtomicUsize::new(0);

    fn record_wake(event: WakeEvent) {
        WAKE_COUNT.fetch_add(1, Ordering::SeqCst);
        WAKE_OBJECT.store(usize::from(event.object), Ordering::SeqCst);
    }

    fn local_namespace() -> ObjectId {
        7
    }

    fn unix_path(path: &[u8]) -> SocketAddress {
        SocketAddress::unix_path(path).expect("valid unix path")
    }

    #[test]
    fn an_unix_stream_connection_round_trips_and_reports_eof() {
        let _guard = setup();
        let listener = create(DOMAIN_UNIX, SOCK_STREAM).expect("listener");
        assert_eq!(
            bind(listener, local_namespace(), unix_path(b"/tmp/svc")),
            Ok(())
        );
        assert_eq!(listen(listener, 2), Ok(()));
        let client = create(DOMAIN_UNIX, SOCK_STREAM).expect("client");
        assert_eq!(
            connect(client, local_namespace(), unix_path(b"/tmp/svc")),
            Ok(())
        );
        let server = accept(listener).expect("accept");
        // Accepting alone does not produce data.
        assert!(!poll(server).expect("poll").contains(PollMask::READ));
        assert_eq!(send(client, b"hello"), Ok(5));
        let mut buffer = [0u8; 8];
        let received = recv(server, &mut buffer).expect("recv");
        assert_eq!(received.len, 5);
        assert_eq!(&buffer[..5], b"hello");
        assert!(received.source.is_none());
        assert_eq!(shutdown(client, ShutdownHow::Write), Ok(()));
        assert_eq!(recv(server, &mut buffer).expect("eof").len, 0);
        assert_eq!(recv(server, &mut buffer).expect("still eof").len, 0);
        assert_eq!(destroy(server), Ok(()));
        assert_eq!(destroy(client), Ok(()));
        assert_eq!(destroy(listener), Ok(()));
        assert_eq!(live_count(), 0);
    }

    #[test]
    fn an_unix_datagram_pair_keeps_message_boundaries_and_sources() {
        let _guard = setup();
        let first = create(DOMAIN_UNIX, SOCK_DGRAM).expect("first");
        let second = create(DOMAIN_UNIX, SOCK_DGRAM).expect("second");
        assert_eq!(bind(first, local_namespace(), unix_path(b"/tmp/a")), Ok(()));
        assert_eq!(
            bind(second, local_namespace(), unix_path(b"/tmp/b")),
            Ok(())
        );
        assert_eq!(
            connect(first, local_namespace(), unix_path(b"/tmp/b")),
            Ok(())
        );
        assert_eq!(send(first, b"one"), Ok(3));
        assert_eq!(send(first, b"two"), Ok(3));
        // A short buffer must not consume the datagram.
        assert_eq!(recv(second, &mut [0u8; 1]), Err(NetError::TooLarge));
        let mut buffer = [0u8; 8];
        let received = recv(second, &mut buffer).expect("recv");
        assert_eq!(&buffer[..received.len], b"one");
        assert_eq!(received.source, Some(unix_path(b"/tmp/a")));
        assert_eq!(send(first, b"three"), Ok(5));
        let received = recv(second, &mut buffer).expect("recv");
        assert_eq!(&buffer[..received.len], b"two");
        assert_eq!(destroy(first), Ok(()));
        assert_eq!(destroy(second), Ok(()));
    }

    #[test]
    fn namespaces_isolate_paths_and_report_duplicates() {
        let _guard = setup();
        let first = create(DOMAIN_UNIX, SOCK_STREAM).expect("first");
        assert_eq!(bind(first, 1, unix_path(b"/tmp/ns")), Ok(()));
        let duplicate = create(DOMAIN_UNIX, SOCK_DGRAM).expect("duplicate");
        assert_eq!(
            bind(duplicate, 1, unix_path(b"/tmp/ns")),
            Err(NetError::AddressInUse)
        );
        // Same path in another namespace is independent.
        assert_eq!(bind(duplicate, 2, unix_path(b"/tmp/ns")), Ok(()));
        assert_eq!(binding_count(1), 1);
        assert_eq!(binding_count(2), 1);
        // A missing binding is reported as NotFound.
        let missing = create(DOMAIN_UNIX, SOCK_STREAM).expect("missing");
        assert_eq!(
            connect(missing, 1, unix_path(b"/tmp/absent")),
            Err(NetError::NotFound)
        );
        assert_eq!(destroy(missing), Ok(()));
        // Destroying a namespace closes its sockets and drops its bindings.
        assert_eq!(destroy_namespace(1), 1);
        assert_eq!(binding_count(1), 0);
        assert_eq!(poll(first), Err(NetError::InvalidSocket));
        assert_eq!(binding_count(2), 1);
        assert_eq!(destroy_namespace(2), 1);
        assert_eq!(destroy(duplicate), Err(NetError::InvalidSocket));
        assert_eq!(live_count(), 0);
    }

    #[test]
    fn socketpairs_connect_both_kinds_anonymously() {
        let _guard = setup();
        let (a, b) = socket_pair(DOMAIN_UNIX, SOCK_STREAM).expect("stream pair");
        assert_eq!(send(a, b"ping"), Ok(4));
        let mut buffer = [0u8; 8];
        assert_eq!(recv(b, &mut buffer).expect("recv").len, 4);
        assert_eq!(remote_address(a), Ok(SocketAddress::INVALID));
        assert_eq!(destroy(a), Ok(()));
        assert_eq!(destroy(b), Ok(()));
        let (c, d) = socket_pair(DOMAIN_UNIX, SOCK_DGRAM).expect("dgram pair");
        assert_eq!(send(c, b"datagram"), Ok(8));
        let received = recv(d, &mut buffer).expect("recv dgram");
        assert_eq!(&buffer[..received.len], b"datagram");
        assert_eq!(destroy(c), Ok(()));
        assert_eq!(destroy(d), Ok(()));
        assert_eq!(live_count(), 0);
    }

    #[test]
    fn closing_a_unix_datagram_peer_reports_peer_closed_and_wakes_the_survivor() {
        let _guard = setup();
        WAKE_COUNT.store(0, Ordering::SeqCst);
        WAKE_OBJECT.store(0, Ordering::SeqCst);
        set_wake_hook(Some(record_wake));
        let (first, second) = socket_pair(DOMAIN_UNIX, SOCK_DGRAM).expect("dgram pair");
        assert_eq!(attach_object(second, 77), Ok(()));
        // Queue one datagram before the peer disappears.
        let payload = [0x5au8; 512];
        assert_eq!(send(first, &payload), Ok(payload.len()));
        // Closing one end notifies the still-live peer.
        assert_eq!(destroy(first), Ok(()));
        assert!(WAKE_COUNT.load(Ordering::SeqCst) >= 1);
        assert_eq!(WAKE_OBJECT.load(Ordering::SeqCst), 77);
        // Readiness must not stay empty forever after the close.
        assert!(poll(second).expect("readiness").contains(PollMask::READ));
        // The survivor drains what was queued before the close...
        let mut buffer = [0u8; 512];
        let received = recv(second, &mut buffer).expect("drain queued datagram");
        assert_eq!(received.len, payload.len());
        assert_eq!(&buffer[..received.len], &payload);
        // ...then observes EOF, and the readiness bit remains for it.
        assert_eq!(recv(second, &mut buffer).expect("eof").len, 0);
        assert!(
            poll(second)
                .expect("eof readiness")
                .contains(PollMask::READ)
        );
        // Further sends observe the closed peer, not a missing connection.
        assert_eq!(send(second, b"late"), Err(NetError::PeerClosed));
        // The survivor can still be closed; the close path releases it once.
        assert_eq!(destroy(second), Ok(()));
        assert_eq!(live_count(), 0);
        set_wake_hook(None);
    }

    #[test]
    fn a_named_unix_datagram_receiver_drains_after_the_sender_closes() {
        let _guard = setup();
        let receiver = create(DOMAIN_UNIX, SOCK_DGRAM).expect("receiver");
        assert_eq!(
            bind(receiver, local_namespace(), unix_path(b"/tmp/phase7-recv")),
            Ok(())
        );
        let sender = create(DOMAIN_UNIX, SOCK_DGRAM).expect("sender");
        assert_eq!(
            connect(sender, local_namespace(), unix_path(b"/tmp/phase7-recv")),
            Ok(())
        );
        let payload = [0x33u8; 512];
        assert_eq!(send(sender, &payload), Ok(payload.len()));
        assert_eq!(destroy(sender), Ok(()));
        // The bound receiver must still report readiness and drain its queue.
        assert!(poll(receiver).expect("readiness").contains(PollMask::READ));
        let mut buffer = [0u8; 512];
        let received = recv(receiver, &mut buffer).expect("drain queued datagram");
        assert_eq!(received.len, payload.len());
        assert_eq!(&buffer[..received.len], &payload);
        assert_eq!(recv(receiver, &mut buffer).expect("eof").len, 0);
        assert_eq!(destroy(receiver), Ok(()));
        assert_eq!(live_count(), 0);
    }

    #[test]
    fn explicit_datagram_read_shutdown_still_blocks_queued_drains() {
        let _guard = setup();
        let (first, second) = socket_pair(DOMAIN_UNIX, SOCK_DGRAM).expect("dgram pair");
        assert_eq!(send(first, b"queued"), Ok(6));
        assert_eq!(shutdown(second, ShutdownHow::Read), Ok(()));
        let mut buffer = [0u8; 16];
        // A local read shutdown keeps refusing receives even with datagrams
        // queued; it must not be confused with a closed peer.
        assert_eq!(recv(second, &mut buffer), Err(NetError::NotConnected));
        assert_eq!(send(second, b"still-writable"), Ok(14));
        assert_eq!(destroy(first), Ok(()));
        assert_eq!(destroy(second), Ok(()));
        assert_eq!(live_count(), 0);
    }

    #[test]
    fn attaching_an_object_routes_local_wakes_to_it() {
        let _guard = setup();
        WAKE_COUNT.store(0, Ordering::SeqCst);
        WAKE_OBJECT.store(0, Ordering::SeqCst);
        set_wake_hook(Some(record_wake));
        let listener = create(DOMAIN_UNIX, SOCK_STREAM).expect("listener");
        assert_eq!(
            bind(listener, local_namespace(), unix_path(b"/tmp/wake")),
            Ok(())
        );
        assert_eq!(listen(listener, 1), Ok(()));
        assert_eq!(attach_object(listener, 42), Ok(()));
        assert_eq!(object_of(listener), Some(42));
        let client = create(DOMAIN_UNIX, SOCK_STREAM).expect("client");
        assert_eq!(
            connect(client, local_namespace(), unix_path(b"/tmp/wake")),
            Ok(())
        );
        assert!(WAKE_COUNT.load(Ordering::SeqCst) >= 1);
        assert_eq!(WAKE_OBJECT.load(Ordering::SeqCst), 42);
        set_wake_hook(None);
        assert_eq!(destroy(client), Ok(()));
        assert_eq!(destroy(listener), Ok(()));
    }

    #[test]
    fn unbound_and_unnamed_sockets_report_addresses_as_documented() {
        let _guard = setup();
        let socket = create(DOMAIN_INET, SOCK_DGRAM).expect("socket");
        assert_eq!(local_address(socket), Ok(SocketAddress::INVALID));
        assert_eq!(remote_address(socket), Ok(SocketAddress::INVALID));
        assert_eq!(poll(socket), Ok(PollMask::EMPTY));
        assert_eq!(destroy(socket), Ok(()));
        // A stale id never hits a reused slot.
        assert_eq!(local_address(socket), Err(NetError::InvalidSocket));
    }

    // -- M7a review regressions --------------------------------------------

    #[test]
    fn reset_keeps_generations_so_old_ids_stay_stale() {
        let _guard = setup();
        let first = create(DOMAIN_UNIX, SOCK_DGRAM).expect("first");
        assert_eq!(
            bind(first, local_namespace(), unix_path(b"/tmp/stale")),
            Ok(())
        );
        init();
        assert_eq!(poll(first), Err(NetError::InvalidSocket));
        let second = create(DOMAIN_UNIX, SOCK_DGRAM).expect("second");
        assert_eq!(
            bind(second, local_namespace(), unix_path(b"/tmp/stale")),
            Ok(())
        );
        assert_ne!(first.raw(), second.raw());
        assert_eq!(destroy(second), Ok(()));
    }

    #[test]
    fn accepting_after_the_peer_fin_still_reports_eof() {
        let _guard = setup();
        let listener =
            tcp_listen(SocketKey::bind(Endpoint::v4(7_201), Protocol::Tcp)).expect("listener");
        let client = tcp_connect(SocketKey::connect(Endpoint::v4(7_201))).expect("client");
        // The peer closes before the listener is accepted.
        assert_eq!(tcp_close(client), Ok(()));
        let server = tcp_accept(listener).expect("accept");
        let mut buffer = [0u8; 4];
        assert_eq!(tcp_recv(server, &mut buffer), Ok(0));
        assert_eq!(tcp_close(server), Ok(()));
        assert_eq!(tcp_close(listener), Ok(()));
    }

    #[test]
    fn a_full_receive_ring_applies_backpressure_then_recovers() {
        let _guard = setup();
        let listener =
            tcp_listen(SocketKey::bind(Endpoint::v4(7_202), Protocol::Tcp)).expect("listener");
        let client = tcp_connect(SocketKey::connect(Endpoint::v4(7_202))).expect("client");
        let server = tcp_accept(listener).expect("accept");
        let block = [0x5au8; TCP_TX_SEG_MAX];
        for _ in 0..4 {
            assert_eq!(tcp_send(client, &block), Ok(TCP_TX_SEG_MAX));
        }
        // The ring is full: no more data may be put on the loopback wire.
        assert_eq!(tcp_send(client, &block), Err(NetError::WouldBlock));
        let mut sink = [0u8; 1_000];
        assert_eq!(tcp_recv(server, &mut sink), Ok(1_000));
        assert_eq!(tcp_send(client, &block[..1_000]), Ok(1_000));
        assert_eq!(tcp_close(client), Ok(()));
        assert_eq!(tcp_close(server), Ok(()));
        assert_eq!(tcp_close(listener), Ok(()));
    }

    #[test]
    fn a_new_backlog_entry_wakes_the_listener() {
        let _guard = setup();
        WAKE_COUNT.store(0, Ordering::SeqCst);
        WAKE_OBJECT.store(0, Ordering::SeqCst);
        set_wake_hook(Some(record_wake));
        let listener =
            tcp_listen(SocketKey::bind(Endpoint::v4(7_203), Protocol::Tcp)).expect("listener");
        let listener_id = SocketId::new(0, 0);
        let _ = listener_id;
        let object = 77;
        attach_object(listener, object).expect("attach");
        let client = tcp_connect(SocketKey::connect(Endpoint::v4(7_203))).expect("client");
        assert!(WAKE_COUNT.load(Ordering::SeqCst) >= 1);
        assert_eq!(WAKE_OBJECT.load(Ordering::SeqCst), usize::from(object));
        set_wake_hook(None);
        assert_eq!(tcp_close(client), Ok(()));
        assert_eq!(tcp_close(listener), Ok(()));
    }

    #[test]
    fn a_full_socket_table_never_drops_a_finished_handshake() {
        let _guard = setup();
        let listener =
            tcp_listen(SocketKey::bind(Endpoint::v4(7_204), Protocol::Tcp)).expect("listener");
        let client = tcp_connect(SocketKey::connect(Endpoint::v4(7_204))).expect("client");
        // Fill every remaining slot so a hand-out slot is unavailable. The
        // finished handshake must stay queued instead of being discarded.
        let mut fillers: [Option<SocketId>; MAX_SOCKETS] = [None; MAX_SOCKETS];
        while socket_count() < MAX_SOCKETS {
            let filler = create(DOMAIN_UNIX, SOCK_DGRAM).expect("filler");
            let free = fillers
                .iter()
                .position(Option::is_none)
                .expect("filler bookkeeping");
            fillers[free] = Some(filler);
        }
        assert_eq!(tcp_accept(listener), Err(NetError::Quota));
        for filler in fillers.iter_mut() {
            if let Some(filler) = filler.take() {
                assert_eq!(destroy(filler), Ok(()));
            }
        }
        let server = tcp_accept(listener).expect("accept after freeing a slot");
        assert_eq!(tcp_close(server), Ok(()));
        assert_eq!(tcp_close(client), Ok(()));
        assert_eq!(tcp_close(listener), Ok(()));
    }

    // -- M7b review round 1 (N2-N8, M1/M2/M4/M6/M7) ------------------------

    #[test]
    fn tcp_read_shutdown_only_blocks_receives() {
        let _guard = setup();
        let (listener, client, server) = tcp_pair();
        assert_eq!(tcp_send(server, b"ping"), Ok(4));
        assert_eq!(shutdown(client, ShutdownHow::Read), Ok(()));
        let mut buffer = [0u8; 8];
        assert_eq!(recv(client, &mut buffer), Err(NetError::NotConnected));
        // A half-closed reader must still be able to write.
        assert_eq!(send(client, b"pong"), Ok(4));
        assert_eq!(recv(server, &mut buffer).expect("pong").len, 4);
        assert_eq!(tcp_close(server), Ok(()));
        assert_eq!(tcp_close(client), Ok(()));
        assert_eq!(tcp_close(listener), Ok(()));
    }

    #[test]
    fn tcp_write_shutdown_blocks_sends_and_the_peer_sees_eof() {
        let _guard = setup();
        let (listener, client, server) = tcp_pair();
        assert_eq!(shutdown(client, ShutdownHow::Write), Ok(()));
        assert_eq!(send(client, b"late"), Err(NetError::NotConnected));
        let mut buffer = [0u8; 8];
        assert_eq!(recv(server, &mut buffer).expect("eof").len, 0);
        assert_eq!(tcp_close(server), Ok(()));
        assert_eq!(tcp_close(client), Ok(()));
        assert_eq!(tcp_close(listener), Ok(()));
    }

    #[test]
    fn an_existing_unix_path_without_a_listener_is_refused() {
        let _guard = setup();
        let bound = create(DOMAIN_UNIX, SOCK_STREAM).expect("bound");
        assert_eq!(
            bind(bound, local_namespace(), unix_path(b"/tmp/not-listening")),
            Ok(())
        );
        let client = create(DOMAIN_UNIX, SOCK_STREAM).expect("client");
        assert_eq!(
            connect(client, local_namespace(), unix_path(b"/tmp/not-listening")),
            Err(NetError::Refused)
        );
        assert_eq!(
            connect(client, local_namespace(), unix_path(b"/tmp/absent")),
            Err(NetError::NotFound)
        );
        assert_eq!(destroy(client), Ok(()));
        assert_eq!(destroy(bound), Ok(()));
    }

    #[test]
    fn a_tcp_connection_to_a_port_without_a_listener_is_refused() {
        let _guard = setup();
        let client = tcp_connect(SocketKey::connect(Endpoint::v4(7_404))).expect("connect");
        // The loopback RST is delivered synchronously, while `connect` runs.
        assert!(poll(client).expect("poll").contains(PollMask::ERROR));
        assert_eq!(tcp_send(client, b"x"), Err(NetError::Refused));
        let mut buffer = [0u8; 4];
        assert_eq!(tcp_recv(client, &mut buffer), Err(NetError::Refused));
        assert_eq!(tcp_close(client), Ok(()));
    }

    #[test]
    fn closing_a_tcp_listener_refuses_queued_handshakes() {
        let _guard = setup();
        let listener =
            tcp_listen(SocketKey::bind(Endpoint::v4(7_405), Protocol::Tcp)).expect("listener");
        let client = tcp_connect(SocketKey::connect(Endpoint::v4(7_405))).expect("client");
        assert_eq!(tcp_close(listener), Ok(()));
        assert!(poll(client).expect("poll").contains(PollMask::ERROR));
        assert_eq!(tcp_send(client, b"x"), Err(NetError::Reset));
        assert_eq!(tcp_close(client), Ok(()));
    }

    #[test]
    fn closing_a_unix_listener_hands_queued_clients_an_eof() {
        let _guard = setup();
        let listener = create(DOMAIN_UNIX, SOCK_STREAM).expect("listener");
        assert_eq!(
            bind(listener, local_namespace(), unix_path(b"/tmp/pending")),
            Ok(())
        );
        assert_eq!(listen(listener, 2), Ok(()));
        let first = create(DOMAIN_UNIX, SOCK_STREAM).expect("first");
        let second = create(DOMAIN_UNIX, SOCK_STREAM).expect("second");
        assert_eq!(
            connect(first, local_namespace(), unix_path(b"/tmp/pending")),
            Ok(())
        );
        assert_eq!(
            connect(second, local_namespace(), unix_path(b"/tmp/pending")),
            Ok(())
        );
        assert_eq!(destroy(listener), Ok(()));
        for client in [first, second] {
            assert!(poll(client).expect("poll").contains(PollMask::READ));
            let mut buffer = [0u8; 4];
            assert_eq!(recv(client, &mut buffer).expect("eof").len, 0);
            assert_eq!(destroy(client), Ok(()));
        }
        assert_eq!(live_count(), 0);
    }

    #[test]
    fn unix_paths_are_limited_to_107_bytes() {
        let _guard = setup();
        let long = [b'a'; 108];
        assert_eq!(SocketAddress::unix_path(&long), Err(NetError::BadAddress));
        let longest = [b'b'; SOCKET_PATH_MAX];
        let address = SocketAddress::unix_path(&longest).expect("107 bytes are legal");
        assert_eq!(address.path_len, SOCKET_PATH_MAX as u32);
        let socket = create(DOMAIN_UNIX, SOCK_STREAM).expect("socket");
        assert_eq!(bind(socket, local_namespace(), address), Ok(()));
        assert_eq!(destroy(socket), Ok(()));
    }

    #[test]
    fn a_recycled_slot_never_reaches_the_old_peer() {
        let _guard = setup();
        let (first, second) = socket_pair(DOMAIN_UNIX, SOCK_STREAM).expect("pair");
        assert_eq!(send(first, b"a"), Ok(1));
        assert_eq!(destroy(first), Ok(()));
        // `create` takes the lowest free slot, so this reuses `first`'s slot
        // with a bumped generation.
        let recycled = create(DOMAIN_UNIX, SOCK_STREAM).expect("recycled");
        assert_eq!(recycled.slot(), first.slot());
        assert_eq!(
            send(second, b"b"),
            Err(NetError::NotConnected),
            "the stale peer id must not resolve to the recycled socket"
        );
        assert_eq!(address(second, true), Err(NetError::NotConnected));
        assert_eq!(destroy(second), Ok(()));
        assert_eq!(destroy(recycled), Ok(()));
    }

    #[test]
    fn a_listener_honours_its_backlog_limit() {
        let _guard = setup();
        let listener = create(DOMAIN_UNIX, SOCK_STREAM).expect("listener");
        assert_eq!(
            bind(listener, local_namespace(), unix_path(b"/tmp/backlog")),
            Ok(())
        );
        assert_eq!(listen(listener, 1), Ok(()));
        let first = create(DOMAIN_UNIX, SOCK_STREAM).expect("first");
        let second = create(DOMAIN_UNIX, SOCK_STREAM).expect("second");
        assert_eq!(
            connect(first, local_namespace(), unix_path(b"/tmp/backlog")),
            Ok(())
        );
        assert_eq!(
            connect(second, local_namespace(), unix_path(b"/tmp/backlog")),
            Err(NetError::WouldBlock)
        );
        let accepted = accept(listener).expect("accept first");
        assert_eq!(
            connect(second, local_namespace(), unix_path(b"/tmp/backlog")),
            Ok(())
        );
        let second_accepted = accept(listener).expect("accept second");
        assert_eq!(destroy(second_accepted), Ok(()));
        assert_eq!(destroy(accepted), Ok(()));
        assert_eq!(destroy(first), Ok(()));
        assert_eq!(destroy(second), Ok(()));
        assert_eq!(destroy(listener), Ok(()));

        for (path, limit) in [(&b"/tmp/backlog2"[..], 2u32), (b"/tmp/backlog64", 64)] {
            let other = create(DOMAIN_UNIX, SOCK_STREAM).expect("listener");
            assert_eq!(bind(other, local_namespace(), unix_path(path)), Ok(()));
            assert_eq!(listen(other, limit), Ok(()));
            assert_eq!(destroy(other), Ok(()));
        }
    }

    #[test]
    fn adopting_into_an_occupied_inner_slot_is_rejected() {
        let _guard = setup();
        let occupant = udp_socket(7_501);
        let slot = occupant.slot().expect("slot");
        let (result, inner_alive) = with_stack(|stack| {
            let inner = stack
                .udp_bind_locked(SocketKey::bind(Endpoint::v4(7_503), Protocol::Udp))
                .expect("inner");
            let result = stack.adopt_udp(slot, inner);
            (result, stack.udp_index(inner).is_ok())
        });
        assert_eq!(result, Err(NetError::AddressInUse));
        assert!(
            !inner_alive,
            "the rejected inner socket is released instead of leaking"
        );
        assert_eq!(destroy(occupant), Ok(()));
    }

    #[test]
    fn destroying_a_namespace_releases_its_bindings() {
        let _guard = setup();
        let stream = create(DOMAIN_UNIX, SOCK_STREAM).expect("stream");
        let datagram = create(DOMAIN_UNIX, SOCK_DGRAM).expect("datagram");
        assert_eq!(
            bind(stream, local_namespace(), unix_path(b"/tmp/ns-stream")),
            Ok(())
        );
        assert_eq!(
            bind(datagram, local_namespace(), unix_path(b"/tmp/ns-dgram")),
            Ok(())
        );
        assert_eq!(binding_count(local_namespace()), 2);
        assert_eq!(destroy_namespace(local_namespace()), 2);
        assert_eq!(binding_count(local_namespace()), 0);
        assert_eq!(local_address(stream), Err(NetError::InvalidSocket));
        assert_eq!(local_address(datagram), Err(NetError::InvalidSocket));
        assert_eq!(destroy_namespace(local_namespace()), 0);
    }

    /// M7b: an INET/INET6 `bind` with port 0 must pick a real ephemeral port
    /// instead of failing in `validate_local`, and `local_address` must report
    /// the port that was actually assigned.
    #[test]
    fn inet_bind_with_port_zero_allocates_distinct_ephemeral_ports() {
        let _guard = setup();
        let wildcard_v4 = SocketAddress::from_endpoint(Endpoint::v4(0), DOMAIN_INET);
        let wildcard_v6 = SocketAddress::from_endpoint(Endpoint::v6(0), DOMAIN_INET6);

        let first = create(DOMAIN_INET, SOCK_DGRAM).expect("udp v4");
        assert_eq!(bind(first, 0, wildcard_v4), Ok(()));
        let first_port = local_address(first)
            .expect("local v4")
            .as_endpoint()
            .expect("inet endpoint")
            .port;
        assert_ne!(first_port, 0, "the stack must assign a port");

        let second = create(DOMAIN_INET6, SOCK_DGRAM).expect("udp v6");
        assert_eq!(bind(second, 0, wildcard_v6), Ok(()));
        let second_port = local_address(second)
            .expect("local v6")
            .as_endpoint()
            .expect("inet endpoint")
            .port;
        assert_ne!(second_port, 0);
        assert_ne!(
            first_port, second_port,
            "two port-0 binds must not share an ephemeral port"
        );

        assert_eq!(destroy(first), Ok(()));
        assert_eq!(destroy(second), Ok(()));
        assert_eq!(socket_count(), 0);
    }

    /// M7b: a stream socket bound with port 0 keeps the assigned port through
    /// `listen`, and the resulting listener is reachable on that real port.
    #[test]
    fn inet_stream_bind_with_port_zero_can_listen() {
        let _guard = setup();
        let listener = create(DOMAIN_INET, SOCK_STREAM).expect("listener");
        assert_eq!(
            bind(
                listener,
                0,
                SocketAddress::from_endpoint(Endpoint::v4(0), DOMAIN_INET)
            ),
            Ok(())
        );
        let port = local_address(listener)
            .expect("bound address")
            .as_endpoint()
            .expect("inet endpoint")
            .port;
        assert_ne!(port, 0, "bind must expose the allocated port before listen");
        assert_eq!(listen(listener, 2), Ok(()));
        assert_eq!(
            local_address(listener)
                .expect("listener address")
                .as_endpoint()
                .expect("inet endpoint")
                .port,
            port,
            "listen keeps the port assigned by bind"
        );

        let client = tcp_connect(SocketKey::connect(Endpoint::v4(port))).expect("connect");
        let server = tcp_accept(listener).expect("accept");
        assert_eq!(tcp_send(client, b"ephemeral"), Ok(9));
        let mut buffer = [0u8; 16];
        let received = tcp_recv(server, &mut buffer).expect("receive");
        assert_eq!(&buffer[..received], b"ephemeral");

        assert_eq!(tcp_close(client), Ok(()));
        assert_eq!(tcp_close(server), Ok(()));
        assert_eq!(tcp_close(listener), Ok(()));
        assert_eq!(socket_count(), 0);
    }

    /// M7b: the ephemeral scan must skip ports already owned by a UDP socket,
    /// while an explicit bind conflict still reports `AddressInUse`.
    #[test]
    fn ephemeral_allocation_skips_udp_locals_and_explicit_conflicts_stay_in_use() {
        let _guard = setup();
        let wildcard = SocketAddress::from_endpoint(Endpoint::v4(0), DOMAIN_INET);
        let occupied = udp_socket(EPHEMERAL_PORT_FIRST);
        let ephemeral = create(DOMAIN_INET, SOCK_DGRAM).expect("ephemeral");
        assert_eq!(bind(ephemeral, 0, wildcard), Ok(()));
        let allocated = local_address(ephemeral)
            .expect("local")
            .as_endpoint()
            .expect("endpoint")
            .port;
        assert_ne!(
            allocated, EPHEMERAL_PORT_FIRST,
            "a port owned by an explicit UDP bind must not be handed out again"
        );

        let explicit = SocketAddress::from_endpoint(Endpoint::v4(7_511), DOMAIN_INET);
        let first = create(DOMAIN_INET, SOCK_DGRAM).expect("first explicit");
        assert_eq!(bind(first, 0, explicit), Ok(()));
        let clash = create(DOMAIN_INET, SOCK_DGRAM).expect("clash");
        assert_eq!(bind(clash, 0, explicit), Err(NetError::AddressInUse));

        assert_eq!(destroy(occupied), Ok(()));
        assert_eq!(destroy(ephemeral), Ok(()));
        assert_eq!(destroy(first), Ok(()));
        assert_eq!(destroy(clash), Ok(()));
    }

    /// M7b: only a *local* port 0 means "pick a port"; a zero remote port is
    /// still an invalid address and must never be auto-assigned.
    #[test]
    fn remote_port_zero_is_not_an_ephemeral_request() {
        let _guard = setup();
        let sender = create(DOMAIN_INET, SOCK_DGRAM).expect("sender");
        assert_eq!(
            bind(
                sender,
                0,
                SocketAddress::from_endpoint(Endpoint::v4(0), DOMAIN_INET)
            ),
            Ok(())
        );
        assert_eq!(
            udp_send(sender, Endpoint::v4(0), b"no"),
            Err(NetError::BadAddress),
            "a zero destination port is a bad address, not an allocation request"
        );
        assert_eq!(
            tcp_connect(SocketKey::connect(Endpoint::v4(0))),
            Err(NetError::BadAddress)
        );
        assert_eq!(
            tcp_connect(SocketKey::connect_from(Endpoint::v4(0), Endpoint::v4(0))),
            Err(NetError::BadAddress)
        );
        assert_eq!(destroy(sender), Ok(()));
    }

    /// M7b phase 1: the user program calls `socket(DGRAM)` + `connect` without
    /// binding first. That must give the socket an ephemeral local port (ABI
    /// 6.48 says connect only records the peer, but a datagram then needs a
    /// source address to send from and to report via `socket_address`).
    #[test]
    fn datagram_connect_auto_binds_an_ephemeral_local_port() {
        let _guard = setup();
        let receiver = create(DOMAIN_INET, SOCK_DGRAM).expect("receiver");
        assert_eq!(
            bind(
                receiver,
                0,
                SocketAddress::from_endpoint(Endpoint::v4(UDP_TEST_B_PORT), DOMAIN_INET)
            ),
            Ok(())
        );
        let sender = create(DOMAIN_INET, SOCK_DGRAM).expect("sender");
        let remote = SocketAddress::from_endpoint(Endpoint::v4(UDP_TEST_B_PORT), DOMAIN_INET);
        assert_eq!(connect(sender, 0, remote), Ok(()));

        let local = local_address(sender)
            .expect("local address")
            .as_endpoint()
            .expect("ipv4 endpoint");
        assert_ne!(local.port, 0, "connect must allocate a real local port");
        assert_eq!(local, Endpoint::v4(local.port));
        assert_eq!(remote_address(sender), Ok(remote));

        let payload = b"auto-bound datagram";
        assert_eq!(send(sender, payload), Ok(payload.len()));
        let mut buffer = [0u8; 64];
        let received = recv(receiver, &mut buffer).expect("receive");
        assert_eq!(&buffer[..received.len], payload);
        assert_eq!(
            received.source,
            Some(SocketAddress::from_endpoint(local, DOMAIN_INET))
        );

        // A second connect only refreshes the peer; the local port is stable.
        assert_eq!(connect(sender, 0, remote), Ok(()));
        assert_eq!(
            local_address(sender)
                .expect("local address")
                .as_endpoint()
                .expect("ipv4 endpoint"),
            local
        );

        assert_eq!(destroy(sender), Ok(()));
        assert_eq!(destroy(receiver), Ok(()));
        assert_eq!(socket_count(), 0);
    }

    /// The implicit bind must honour the socket family; otherwise an IPv6
    /// datagram would be given an IPv4 source address.
    #[test]
    fn datagram_connect_auto_binds_an_ipv6_local_port() {
        let _guard = setup();
        let receiver = create(DOMAIN_INET6, SOCK_DGRAM).expect("receiver");
        assert_eq!(
            bind(
                receiver,
                0,
                SocketAddress::from_endpoint(Endpoint::v6(UDP_TEST_B_PORT), DOMAIN_INET6)
            ),
            Ok(())
        );
        let sender = create(DOMAIN_INET6, SOCK_DGRAM).expect("sender");
        let remote = SocketAddress::from_endpoint(Endpoint::v6(UDP_TEST_B_PORT), DOMAIN_INET6);
        assert_eq!(connect(sender, 0, remote), Ok(()));

        let local = local_address(sender)
            .expect("local address")
            .as_endpoint()
            .expect("ipv6 endpoint");
        assert_ne!(local.port, 0);
        assert_eq!(local, Endpoint::v6(local.port));

        let payload = b"v6 auto-bound";
        assert_eq!(send(sender, payload), Ok(payload.len()));
        let mut buffer = [0u8; 32];
        let received = recv(receiver, &mut buffer).expect("receive");
        assert_eq!(&buffer[..received.len], payload);

        assert_eq!(destroy(sender), Ok(()));
        assert_eq!(destroy(receiver), Ok(()));
        assert_eq!(socket_count(), 0);
    }

    /// An explicitly bound datagram socket keeps its port across `connect`;
    /// only an unbound socket gets an ephemeral one.
    #[test]
    fn datagram_connect_keeps_an_explicit_local_port() {
        let _guard = setup();
        let receiver = create(DOMAIN_INET, SOCK_DGRAM).expect("receiver");
        assert_eq!(
            bind(
                receiver,
                0,
                SocketAddress::from_endpoint(Endpoint::v4(UDP_TEST_B_PORT), DOMAIN_INET)
            ),
            Ok(())
        );
        let sender = create(DOMAIN_INET, SOCK_DGRAM).expect("sender");
        let explicit = SocketAddress::from_endpoint(Endpoint::v4(7_321), DOMAIN_INET);
        assert_eq!(bind(sender, 0, explicit), Ok(()));

        let remote = SocketAddress::from_endpoint(Endpoint::v4(UDP_TEST_B_PORT), DOMAIN_INET);
        assert_eq!(connect(sender, 0, remote), Ok(()));
        let local = local_address(sender)
            .expect("local address")
            .as_endpoint()
            .expect("ipv4 endpoint");
        assert_eq!(local, Endpoint::v4(7_321));

        assert_eq!(send(sender, b"explicit"), Ok(8));
        let mut buffer = [0u8; 16];
        let received = recv(receiver, &mut buffer).expect("receive");
        assert_eq!(&buffer[..received.len], b"explicit");
        assert_eq!(
            received.source,
            Some(SocketAddress::from_endpoint(
                Endpoint::v4(7_321),
                DOMAIN_INET
            ))
        );

        assert_eq!(destroy(sender), Ok(()));
        assert_eq!(destroy(receiver), Ok(()));
        assert_eq!(socket_count(), 0);
    }

    /// M7b phase-1 shape on the host: the parent binds an ephemeral UDP port,
    /// the child connects *without* binding first, sends one datagram up, and
    /// the parent replies to the datagram source. Mirrors `services/net` phase 1
    /// so the engine path can be checked without QEMU.
    #[test]
    fn datagram_phase_one_exchange_matches_the_qemu_udp_round_trip() {
        let _guard = setup();
        let parent = create(DOMAIN_INET, SOCK_DGRAM).expect("parent dgram");
        assert_eq!(
            bind(
                parent,
                0,
                SocketAddress::from_endpoint(Endpoint::v4(0), DOMAIN_INET)
            ),
            Ok(())
        );
        let parent_local = local_address(parent)
            .expect("parent local")
            .as_endpoint()
            .expect("ipv4 endpoint");
        assert_ne!(parent_local.port, 0, "bind(port 0) must allocate");

        let child = create(DOMAIN_INET, SOCK_DGRAM).expect("child dgram");
        assert_eq!(
            connect(
                child,
                0,
                SocketAddress::from_endpoint(Endpoint::v4(parent_local.port), DOMAIN_INET)
            ),
            Ok(())
        );
        let child_local = local_address(child)
            .expect("child local")
            .as_endpoint()
            .expect("ipv4 endpoint");
        assert_ne!(child_local.port, 0, "connect must auto-bind a local port");

        let up = [0x11u8; 7];
        assert_eq!(send(child, &up), Ok(7));
        let mut buffer = [0u8; 16];
        let received = recv(parent, &mut buffer).expect("parent receive");
        assert_eq!(received.len, 7);
        assert_eq!(&buffer[..received.len], &up);
        let source = received.source.expect("datagram source");
        assert_eq!(
            source,
            SocketAddress::from_endpoint(Endpoint::v4(child_local.port), DOMAIN_INET)
        );

        assert_eq!(connect(parent, 0, source), Ok(()));
        let down = [0x22u8; 7];
        assert_eq!(send(parent, &down), Ok(7));
        let mut reply = [0u8; 16];
        let got = recv(child, &mut reply).expect("child receive");
        assert_eq!(got.len, 7);
        assert_eq!(&reply[..got.len], &down);

        assert_eq!(destroy(child), Ok(()));
        assert_eq!(destroy(parent), Ok(()));
        assert_eq!(socket_count(), 0);
    }

    /// M7b phase-4 race: a `send` after `connect` but before `accept` used to
    /// reach `handle_backlog`, which drops payload it cannot buffer. The sender
    /// must back off (`WouldBlock`, no writability) and `accept` must wake it so
    /// the payload still arrives exactly once.
    fn pre_accept_stream_send_backs_off_until_accept(domain: u32, wildcard: SocketAddress) {
        let listener = create(domain, SOCK_STREAM).expect("listener");
        assert_eq!(bind(listener, 0, wildcard), Ok(()));
        assert_eq!(listen(listener, 2), Ok(()));
        let port = local_address(listener)
            .expect("listener address")
            .as_endpoint()
            .expect("inet endpoint")
            .port;
        assert_ne!(port, 0, "bind(port 0) must allocate");

        let client = create(domain, SOCK_STREAM).expect("client");
        let remote = if domain == DOMAIN_INET6 {
            Endpoint::v6(port)
        } else {
            Endpoint::v4(port)
        };
        assert_eq!(
            connect(client, 0, SocketAddress::from_endpoint(remote, domain)),
            Ok(())
        );

        let payload = b"early seed";
        assert_eq!(send(client, payload), Err(NetError::WouldBlock));
        assert!(
            !poll(client).expect("poll").contains(PollMask::WRITE),
            "a connection waiting in the backlog must not report writable"
        );

        let server = accept(listener).expect("accept");
        assert!(
            poll(client).expect("poll").contains(PollMask::WRITE),
            "accept must wake the blocked sender"
        );
        assert_eq!(send(client, payload), Ok(payload.len()));
        let mut buffer = [0u8; 32];
        let received = recv(server, &mut buffer).expect("receive");
        assert_eq!(received.len, payload.len());
        assert_eq!(&buffer[..received.len], payload);

        assert_eq!(destroy(client), Ok(()));
        assert_eq!(destroy(server), Ok(()));
        assert_eq!(destroy(listener), Ok(()));
        assert_eq!(socket_count(), 0);
    }

    #[test]
    fn pre_accept_stream_send_backs_off_until_accept_v4() {
        let _guard = setup();
        pre_accept_stream_send_backs_off_until_accept(
            DOMAIN_INET,
            SocketAddress::from_endpoint(Endpoint::v4(0), DOMAIN_INET),
        );
    }

    #[test]
    fn pre_accept_stream_send_backs_off_until_accept_v6() {
        let _guard = setup();
        pre_accept_stream_send_backs_off_until_accept(
            DOMAIN_INET6,
            SocketAddress::from_endpoint(Endpoint::v6(0), DOMAIN_INET6),
        );
    }

    // M7b phase 9: local stream write backpressure. A full peer receive ring
    // must hide WRITE (so a blocked writer sleeps), and draining the ring must
    // wake that writer with `ReadyEvent::Write`.
    static WRITE_WAKE_COUNT: AtomicUsize = AtomicUsize::new(0);
    static LAST_WAKE_SOCKET: AtomicUsize = AtomicUsize::new(0);

    fn record_write_wake(event: WakeEvent) {
        if event.event == ReadyEvent::Write {
            WRITE_WAKE_COUNT.fetch_add(1, Ordering::SeqCst);
            LAST_WAKE_SOCKET.store(event.socket.raw() as usize, Ordering::SeqCst);
        }
    }

    #[test]
    fn unix_stream_write_readiness_tracks_peer_receive_space() {
        let _guard = setup();
        let (sender, receiver) = socket_pair(DOMAIN_UNIX, SOCK_STREAM).expect("stream pair");

        // Fill the peer's receive ring exactly, then the next byte must not fit.
        let full = [0x55u8; LOCAL_STREAM_BYTES];
        assert_eq!(send(sender, &full), Ok(LOCAL_STREAM_BYTES));
        assert_eq!(send(sender, b"x"), Err(NetError::WouldBlock));
        assert!(
            !poll(sender).expect("poll").contains(PollMask::WRITE),
            "a full peer receive ring must hide WRITE"
        );

        // Draining frees space and must wake the blocked writer with Write.
        WRITE_WAKE_COUNT.store(0, Ordering::SeqCst);
        LAST_WAKE_SOCKET.store(0, Ordering::SeqCst);
        set_wake_hook(Some(record_write_wake));
        let mut buffer = [0u8; 512];
        let drained = recv(receiver, &mut buffer).expect("drain");
        set_wake_hook(None);
        assert_eq!(drained.len, 512);
        assert!(
            WRITE_WAKE_COUNT.load(Ordering::SeqCst) >= 1,
            "draining must wake the writer"
        );
        assert_eq!(
            LAST_WAKE_SOCKET.load(Ordering::SeqCst),
            sender.raw() as usize,
            "the wake must target the blocked sender"
        );

        // Readiness is restored and the retry succeeds.
        assert!(
            poll(sender).expect("poll").contains(PollMask::WRITE),
            "free peer space must report WRITE"
        );
        assert_eq!(send(sender, b"x"), Ok(1));

        assert_eq!(destroy(sender), Ok(()));
        assert_eq!(destroy(receiver), Ok(()));
        assert_eq!(socket_count(), 0);
    }

    // w7 cross-review: `alloc_tcp_in_place` used to leave the accepted slot's
    // `domain`/`hint` zeroed, so Linux `getsockname` on an accepted fd saw
    // family 0 and had to fail with EINVAL. The accept path must inherit the
    // listener's family and the stream hint.
    fn accept_inherits_the_listener_family(domain: u32, any: SocketAddress, v6: bool) {
        let _guard = setup();
        let listener = create(domain, SOCK_STREAM).expect("listener");
        assert_eq!(bind(listener, 0, any), Ok(()));
        assert_eq!(listen(listener, 2), Ok(()));
        let listener_local = local_address(listener).expect("listener address");
        assert_eq!(
            listener_local.family, domain,
            "a bound listener reports its own family"
        );
        let port = listener_local.as_endpoint().expect("inet endpoint").port;

        let client = create(domain, SOCK_STREAM).expect("client");
        let remote = if v6 {
            SocketAddress::from_endpoint(Endpoint::v6(port), domain)
        } else {
            SocketAddress::from_endpoint(Endpoint::v4(port), domain)
        };
        assert_eq!(connect(client, 0, remote), Ok(()));

        let accepted = accept(listener).expect("accept");
        let accepted_local = local_address(accepted).expect("accepted local address");
        assert_eq!(
            accepted_local.family, domain,
            "an accepted stream keeps the listener family for getsockname"
        );
        assert_eq!(
            accepted_local.as_endpoint().expect("accepted endpoint"),
            listener_local.as_endpoint().expect("listener endpoint"),
            "the accepted local address is the listener's bound address"
        );
        let accepted_peer = address(accepted, true).expect("accepted peer address");
        assert_eq!(
            accepted_peer.family, domain,
            "an accepted stream keeps the family for getpeername"
        );
        let client_local = local_address(client).expect("client local address");
        assert_eq!(
            accepted_peer.as_endpoint().expect("peer endpoint"),
            client_local.as_endpoint().expect("client endpoint"),
            "the accepted peer address is the connecting client's address"
        );

        assert_eq!(destroy(client), Ok(()));
        assert_eq!(destroy(accepted), Ok(()));
        assert_eq!(destroy(listener), Ok(()));
        assert_eq!(socket_count(), 0);
    }

    #[test]
    fn accepted_inet_stream_reports_the_listener_family() {
        accept_inherits_the_listener_family(
            DOMAIN_INET,
            SocketAddress::from_endpoint(Endpoint::v4(0), DOMAIN_INET),
            false,
        );
    }

    #[test]
    fn accepted_inet6_stream_reports_the_listener_family() {
        accept_inherits_the_listener_family(
            DOMAIN_INET6,
            SocketAddress::from_endpoint(Endpoint::v6(0), DOMAIN_INET6),
            true,
        );
    }

    // -- M9b: abstract addresses, SCM_RIGHTS and credentials ----------------

    fn fresh_object(tag: u64) -> ObjectId {
        crate::object::create_with_payload(crate::object::ObjectKind::SharedMemory, tag)
            .expect("object")
    }

    fn release(object: ObjectId) {
        crate::object::release_object(object).expect("release object");
    }

    fn refs(object: ObjectId) -> Option<u32> {
        crate::object::object_refs(object)
    }

    #[test]
    fn abstract_unix_names_bind_connect_and_do_not_collide_with_pathnames() {
        let _guard = setup();
        let name = b"caelum-m9b-svc";
        let address = SocketAddress::unix_abstract(name).expect("abstract address");
        assert!(address.is_abstract());
        assert!(!address.is_pathname());
        assert_eq!(address.path_len as usize, name.len() + 1);
        assert_eq!(address.path[0], 0);

        let listener = create(DOMAIN_UNIX, SOCK_STREAM).expect("listener");
        assert_eq!(bind(listener, local_namespace(), address), Ok(()));
        assert_eq!(listen(listener, 2), Ok(()));
        let client = create(DOMAIN_UNIX, SOCK_STREAM).expect("client");
        assert_eq!(connect(client, local_namespace(), address), Ok(()));
        let server = accept(listener).expect("accept");
        assert_eq!(send(client, b"hello"), Ok(5));
        let mut buffer = [0u8; 8];
        let received = recv(server, &mut buffer).expect("recv");
        assert_eq!(&buffer[..received.len], b"hello");
        assert_eq!(
            local_address(listener).expect("bound address").path_bytes(),
            address.path_bytes()
        );

        // A pathname with the same visible bytes is a different address.
        let pathname = create(DOMAIN_UNIX, SOCK_STREAM).expect("pathname");
        assert_eq!(bind(pathname, local_namespace(), unix_path(name)), Ok(()));
        // The abstract name is still unique.
        let duplicate = create(DOMAIN_UNIX, SOCK_STREAM).expect("duplicate");
        assert_eq!(
            bind(duplicate, local_namespace(), address),
            Err(NetError::AddressInUse)
        );

        // Abstract names may fill the whole sun_path array (107 bytes + NUL);
        // pathnames stop at 107 bytes.
        let longest_abstract =
            SocketAddress::unix_abstract(&[b'a'; SOCKET_PATH_MAX]).expect("108-byte abstract");
        assert_eq!(longest_abstract.path_len as usize, SOCKET_PATH_BYTES);
        assert!(SocketAddress::unix_abstract(&[b'a'; SOCKET_PATH_BYTES]).is_err());
        assert!(SocketAddress::unix_path(&[b'a'; SOCKET_PATH_MAX]).is_ok());
        assert!(SocketAddress::unix_path(&[b'a'; SOCKET_PATH_BYTES]).is_err());
        let long_listener = create(DOMAIN_UNIX, SOCK_DGRAM).expect("long listener");
        assert_eq!(
            bind(long_listener, local_namespace(), longest_abstract),
            Ok(())
        );

        assert_eq!(destroy(long_listener), Ok(()));
        assert_eq!(destroy(duplicate), Ok(()));
        assert_eq!(destroy(pathname), Ok(()));
        assert_eq!(destroy(server), Ok(()));
        assert_eq!(destroy(client), Ok(()));
        assert_eq!(destroy(listener), Ok(()));
        assert_eq!(live_count(), 0);
    }

    #[test]
    fn datagram_send_msg_transfers_objects_and_releases_discarded_references() {
        let _objects = crate::object::test_lock();
        let _guard = setup();
        let receiver = create(DOMAIN_UNIX, SOCK_DGRAM).expect("receiver");
        let sender = create(DOMAIN_UNIX, SOCK_DGRAM).expect("sender");
        assert_eq!(
            bind(receiver, local_namespace(), unix_path(b"/tmp/m9b-rights")),
            Ok(())
        );
        assert_eq!(
            connect(sender, local_namespace(), unix_path(b"/tmp/m9b-rights")),
            Ok(())
        );

        let objects = [
            fresh_object(1),
            fresh_object(2),
            fresh_object(3),
            fresh_object(4),
        ];
        for object in objects {
            assert_eq!(refs(object), Some(1));
        }
        assert_eq!(
            send_msg(
                sender,
                b"payload",
                &objects,
                Some(Credential::new(77, 0, 0))
            ),
            Ok(7)
        );
        for object in objects {
            assert_eq!(refs(object), Some(1), "the queue owns one reference");
        }

        // More than the frozen four-descriptor budget is rejected without
        // consuming any reference.
        let overflow = [
            fresh_object(5),
            fresh_object(6),
            fresh_object(7),
            fresh_object(8),
            fresh_object(9),
        ];
        assert_eq!(
            send_msg(sender, b"x", &overflow, None),
            Err(NetError::Unsupported)
        );
        for object in overflow {
            assert_eq!(refs(object), Some(1));
            release(object);
        }

        let mut buffer = [0u8; 16];
        let mut objects_out = [0u16; MAX_SCM_FDS];
        let message = recv_msg(receiver, &mut buffer, &mut objects_out).expect("recv_msg");
        assert_eq!(&buffer[..message.len], b"payload");
        assert_eq!(usize::from(message.object_count), MAX_SCM_FDS);
        assert_eq!(message.cred, Some(Credential::new(77, 0, 0)));
        for (index, object) in message.objects.iter().take(MAX_SCM_FDS).enumerate() {
            assert_eq!(*object, objects[index]);
            assert_eq!(refs(*object), Some(1));
            // No fd table here: drop the transferred reference explicitly.
            release(*object);
        }
        for object in objects {
            assert_eq!(refs(object), None);
        }

        // A plain `recv` has no ancillary buffer: the reference is dropped.
        let discarded = fresh_object(10);
        assert_eq!(send_msg(sender, b"drop", &[discarded], None), Ok(4));
        assert_eq!(refs(discarded), Some(1));
        let received = recv(receiver, &mut buffer).expect("plain recv");
        assert_eq!(&buffer[..received.len], b"drop");
        assert_eq!(
            refs(discarded),
            None,
            "plain recv releases the transferred reference"
        );

        // Closing the receiver drains references that were never received.
        let queued = fresh_object(11);
        assert_eq!(send_msg(sender, b"queued", &[queued], None), Ok(6));
        assert_eq!(refs(queued), Some(1));
        assert_eq!(destroy(receiver), Ok(()));
        assert_eq!(refs(queued), None, "close drains queued references");

        assert_eq!(destroy(sender), Ok(()));
        assert_eq!(live_count(), 0);
    }

    #[test]
    fn stream_send_msg_attaches_ancillary_to_the_read_offset() {
        let _objects = crate::object::test_lock();
        let _guard = setup();
        let (a, b) = socket_pair(DOMAIN_UNIX, SOCK_STREAM).expect("stream pair");
        let first = fresh_object(21);
        assert_eq!(send_msg(a, b"xy", &[], None), Ok(2));
        assert_eq!(
            send_msg(a, b"abcdef", &[first], Some(Credential::new(9, 0, 0))),
            Ok(6)
        );
        assert_eq!(refs(first), Some(1));

        // Consume the byte before the ancillary offset: the descriptor stays
        // queued until a read crosses the byte it is attached to.
        let mut one = [0u8; 1];
        assert_eq!(recv(b, &mut one).expect("first byte").len, 1);
        assert_eq!(one, *b"x");
        assert_eq!(
            refs(first),
            Some(1),
            "ancillary is not visible before its offset"
        );

        let mut buffer = [0u8; 8];
        let mut objects_out = [0u16; MAX_SCM_FDS];
        let message = recv_msg(b, &mut buffer[..3], &mut objects_out).expect("recv_msg");
        assert_eq!(&buffer[..message.len], b"yab");
        assert_eq!(usize::from(message.object_count), 1);
        assert_eq!(message.objects[0], first);
        assert_eq!(message.cred, Some(Credential::new(9, 0, 0)));
        assert_eq!(refs(first), Some(1));
        release(message.objects[0]);
        assert_eq!(refs(first), None);

        // Crossing the offset of a later record with a plain read drops it.
        let second = fresh_object(22);
        assert_eq!(send_msg(a, b"zz", &[second], None), Ok(2));
        assert_eq!(refs(second), Some(1));
        let mut tail = [0u8; 4];
        assert_eq!(recv(b, &mut tail).expect("stream tail").len, 4);
        assert_eq!(&tail, b"cdef");
        assert_eq!(refs(second), Some(1), "still queued at its offset");
        assert_eq!(recv(b, &mut one).expect("crossing byte").len, 1);
        assert_eq!(one, *b"z");
        assert_eq!(refs(second), None, "plain read drops the crossing record");

        assert_eq!(destroy(a), Ok(()));
        assert_eq!(destroy(b), Ok(()));
        assert_eq!(refs(first), None);
        assert_eq!(live_count(), 0);
    }

    #[test]
    fn closing_a_local_stream_drains_pending_ancillary_references() {
        let _objects = crate::object::test_lock();
        let _guard = setup();
        let (a, b) = socket_pair(DOMAIN_UNIX, SOCK_STREAM).expect("stream pair");
        let pending = fresh_object(31);
        assert_eq!(send_msg(a, b"body", &[pending], None), Ok(4));
        assert_eq!(refs(pending), Some(1));
        assert_eq!(destroy(b), Ok(()));
        assert_eq!(
            refs(pending),
            None,
            "closing the receiver drains queued ancillary references"
        );
        assert_eq!(destroy(a), Ok(()));
        assert_eq!(live_count(), 0);
    }

    #[test]
    fn credentials_flow_through_connect_accept_and_messages() {
        let _objects = crate::object::test_lock();
        let _guard = setup();
        let listener = create(DOMAIN_UNIX, SOCK_STREAM).expect("listener");
        let client = create(DOMAIN_UNIX, SOCK_STREAM).expect("client");
        set_cred(listener, Credential::new(11, 0, 0)).expect("listener cred");
        set_cred(client, Credential::new(22, 0, 0)).expect("client cred");
        assert_eq!(
            bind(listener, local_namespace(), unix_path(b"/tmp/m9b-cred")),
            Ok(())
        );
        assert_eq!(listen(listener, 1), Ok(()));
        assert_eq!(
            connect(client, local_namespace(), unix_path(b"/tmp/m9b-cred")),
            Ok(())
        );
        let server = accept(listener).expect("accept");
        assert_eq!(
            peer_cred(client).expect("client peer"),
            Some(Credential::new(11, 0, 0))
        );
        assert_eq!(
            peer_cred(server).expect("server peer"),
            Some(Credential::new(22, 0, 0))
        );

        assert_eq!(passcred(server), Ok(false));
        assert_eq!(set_passcred(server, true), Ok(()));
        assert_eq!(passcred(server), Ok(true));

        let mut buffer = [0u8; 8];
        let mut objects_out = [0u16; MAX_SCM_FDS];
        assert_eq!(
            send_msg(client, b"hello", &[], Some(Credential::new(22, 0, 0))),
            Ok(5)
        );
        let message = recv_msg(server, &mut buffer, &mut objects_out).expect("recv_msg");
        assert_eq!(&buffer[..message.len], b"hello");
        assert_eq!(message.cred, Some(Credential::new(22, 0, 0)));

        // Connected datagrams learn the peer identity at connect() time too.
        let datagram_a = create(DOMAIN_UNIX, SOCK_DGRAM).expect("datagram a");
        let datagram_b = create(DOMAIN_UNIX, SOCK_DGRAM).expect("datagram b");
        set_cred(datagram_a, Credential::new(31, 0, 0)).expect("a cred");
        set_cred(datagram_b, Credential::new(32, 0, 0)).expect("b cred");
        assert_eq!(
            bind(
                datagram_a,
                local_namespace(),
                unix_path(b"/tmp/m9b-cred-dgram")
            ),
            Ok(())
        );
        assert_eq!(
            connect(
                datagram_b,
                local_namespace(),
                unix_path(b"/tmp/m9b-cred-dgram")
            ),
            Ok(())
        );
        assert_eq!(
            peer_cred(datagram_b).expect("datagram peer"),
            Some(Credential::new(31, 0, 0))
        );

        assert_eq!(destroy(datagram_b), Ok(()));
        assert_eq!(destroy(datagram_a), Ok(()));
        assert_eq!(destroy(server), Ok(()));
        assert_eq!(destroy(client), Ok(()));
        assert_eq!(destroy(listener), Ok(()));
        assert_eq!(live_count(), 0);
    }
}
