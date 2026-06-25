//! RTSP server runtime — the socket-driving half of the RTSP server. Owns the `TcpListener` accept loop, per-connection request dispatch (`handle_client`), the per-session RTP pump (`run_pump`), the `PacketSink` transport abstraction (TCP-interleaved + UDP + in-memory test sink), keyframe pacing, and the per-session SSRC/sequence-number seeding. The pure request/response protocol, session registry, and method handlers live in `rtsp_protocol`; this module imports them privately for its own dispatch needs and exposes only the runtime surface (`RtspServer`, `pump_frame_into`, the `PacketSink` trait and its sinks) that the integration tests and `app` consume.
//!
//! Codec parameters for DESCRIBE are pulled from the shared `StreamState` (cloned cheaply into each connection thread), which is the point where the camera pipeline meets the RTSP layer — matching the boundary drawn in `PROJECT.md`. The session registry is owned per connection: RTSP sessions do not span TCP connections, so each `handle_client` thread holds its own `RtspSessions` and there is no cross-connection shared mutable session state.

use crate::rtsp_protocol::{handle_request, parse_request, response, session_id, Method, RtspError, RtspRequest, RtspResponse, RtspSessions, Transport, SESSION_TIMEOUT_SECS, STATUS_BAD_REQUEST, STATUS_OK, STATUS_SERVICE_UNAVAILABLE, STATUS_UNSUPPORTED_TRANSPORT};

use std::collections::HashMap;

// --------------------------------------------------------------------------- Runtime half: accept loop, per-connection handling, RTP pump. ---------------------------------------------------------------------------

use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::mpsc::{Receiver, RecvTimeoutError};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::accept_loop::accept_loop;
use crate::logging::{Level, Logger};
use crate::rtp::RtpPacketizer;
use crate::stream_state::{ClientId, Frame, StreamState};

/// Relaxed ordering suffices for the shutdown flag and client counter: they are advisory signals, not synchronization that establishes happens-before for other data (the `StreamState` mutex carries that burden).
const RELAXED: Ordering = Ordering::Relaxed;

/// Per-connection read timeout. The control read loop blocks on `read` for at most this long before returning `TimedOut`, which lets the loop re-check the `shutdown` flag and tear down an idle connection promptly on stop. A playing-but-silent session is unaffected: the pump streams on the writer while the control loop spins cheaply on read timeouts.
const READ_TIMEOUT_MS: u64 = 500;

/// Per-connection write timeout, bounding how long the shared send mutex can be held across a `write_all`. A stuck client that stops draining its TCP receive buffer yields a write error after this, tearing the session down rather than blocking the pump or control thread indefinitely.
const WRITE_TIMEOUT_MS: u64 = 5_000;

const READ_CHUNK_BYTES: usize = 8192;

/// Cap on the per-connection request buffer. A client that streams request bytes without ever completing a `\r\n\r\n`-terminated header block would otherwise grow the buffer unbounded; exceeding this closes the connection. Named per the resource-bounds quality gate.
const MAX_READ_BUFFER_BYTES: usize = 64 * 1024;

/// Maximum simultaneously-connected RTSP clients. New connections beyond this are answered with `503 Service Unavailable` so a client flood cannot exhaust threads/memory. Exposed so tests can drive the cap boundary exactly.
pub const MAX_RTSP_CLIENTS: usize = 32;

/// `$` byte prefixing an interleaved RTP/RTCP frame on the RTSP TCP connection, per RFC 2326 §12.39 and `PROJECT.md` → "TCP Interleaved RTP".
const INTERLEAVED_FRAME_MARKER: u8 = 0x24;

/// Number of framing bytes preceding an interleaved RTP packet: `[$][channel][len_hi][len_lo]`, per RFC 2326 §12.39.
const INTERLEAVED_FRAMING_BYTES: usize = 4;

/// Pump channel poll interval, so the `shutdown` flag is checked promptly between frames rather than blocking indefinitely on `recv`.
const PUMP_POLL_TIMEOUT_MS: u64 = 200;

/// Frames larger than this are sent with inter-chunk pacing so the burst does not overflow a receiver's initial RTP reorder buffer. P-frames from the G5 Bullet are 20–50 KB; keyframes are ~1 MB. The threshold sits between the two so only keyframes are paced.
const PACING_FRAME_THRESHOLD_BYTES: usize = 64 * 1024;

/// Number of RTP packets sent before a pacing sleep. ~35 packets × ~1400 bytes ≈ 49 KB per chunk, small enough that the receiver's reorder buffer absorbs it without loss between sleeps.
const PACING_CHUNK_PACKETS: usize = 35;

/// Sleep between paced chunks. A 1.2 MB keyframe (889 packets / 25 chunks) paced at 5 ms/chunk spreads the send over ~125 ms instead of ~12 ms, giving live555 (VLC) time to grow its initial ~500 KB reorder buffer past the ~475 KB it would otherwise drop. On Windows the default timer resolution may round this up to ~15 ms, which yields ~375 ms total — still well under the 5 s keyframe interval and far better than the alternative (dropped keyframe → 5 s wait for the next one).
const PACING_CHUNK_SLEEP: Duration = Duration::from_millis(5);

/// Multiplier and increment of the tiny splitmix64-style mixer used to derive per-session SSRC / sequence-number seeds from wall-clock nanos and a process-wide counter, avoiding a crate dependency. Values from Knuth's MMIX constants.
const SPLITMIX_MULTIPLIER: u64 = 6_364_136_223_846_793_005;
const SPLITMIX_INCREMENT: u64 = 14_426_950_408_889_634_077;

/// 64-bit golden-ratio fractional constant (`(√5−1)/2`), used to mix the process counter into the session seed so successive sessions diverge even when wall-clock nanos collide.
const GOLDEN_RATIO_64: u64 = 0x9E37_79B9_7F4A_7C15;

/// Shutdown handle and bound-port surface for the RTSP accept loop. Clone is not provided: a single instance owns the accept thread's shared flags; tests and the future Windows service entry point drive one instance per process.
pub struct RtspServer {
    state: StreamState,
    rtsp_port: u16,
    server_ip: String,
    shutdown: Arc<AtomicBool>,
    active_clients: Arc<AtomicUsize>,
    logger: Option<Arc<Logger>>,
}

impl RtspServer {
    /// Creates a server that will bind `0.0.0.0:rtsp_port` for RTSP clients and advertise `server_ip` in SDP origins. `state` is the shared hub the camera pipeline publishes frames and codec parameters to. No logger is attached; tests use this path.
    pub fn new(state: StreamState, rtsp_port: u16, server_ip: String) -> RtspServer {
        RtspServer { state, rtsp_port, server_ip, shutdown: Arc::new(AtomicBool::new(false)), active_clients: Arc::new(AtomicUsize::new(0)), logger: None }
    }

    /// Creates a server with an attached logger so RTSP client connect/disconnect events are written to `flvproxy.log`. `console_main` uses this so an operator sees when an NVR opens or closes the RTSP stream.
    pub fn with_logger(state: StreamState, rtsp_port: u16, server_ip: String, logger: Arc<Logger>) -> RtspServer {
        RtspServer { state, rtsp_port, server_ip, shutdown: Arc::new(AtomicBool::new(false)), active_clients: Arc::new(AtomicUsize::new(0)), logger: Some(logger) }
    }

    /// Binds the RTSP listener on `0.0.0.0:rtsp_port` and runs the accept loop until `shutdown()` is called. Each accepted connection is handled on its own thread.
    pub fn run(&self) -> io::Result<()> {
        let listener = TcpListener::bind(("0.0.0.0", self.rtsp_port))?;
        self.run_on(listener)
    }

    /// Runs the accept loop on a caller-supplied listener. Tests use this with an ephemeral loopback listener so they know the bound port; production `run()` delegates here after binding.
    /// Runs the accept loop on a caller-supplied listener. Tests use this with an ephemeral loopback listener so they know the bound port; production `run()` delegates here after binding. The non-blocking/poll/shutdown mechanics live in `accept_loop::accept_loop`; this body is just the per-connection policy: enforce the client cap (rejecting floods with a bare `503`), then spawn a handler thread that decrements the live-client counter on exit.
    pub fn run_on(&self, listener: TcpListener) -> io::Result<()> {
        let shutdown = self.shutdown.clone();
        let shutdown_for_closure = shutdown.clone();
        let active_clients = self.active_clients.clone();
        let state = self.state.clone();
        let server_ip = self.server_ip.clone();
        let logger = self.logger.clone();
        accept_loop(listener, &shutdown, move |stream| {
            if active_clients.load(RELAXED) >= MAX_RTSP_CLIENTS {
                // At the cap: answer with a bare `503 Service Unavailable` and close, so a flood of clients is rejected cleanly rather than silently dropped. The response carries no `CSeq` because the rejected peer has not yet sent a request.
                if let Some(logger) = &logger {
                    logger.log(Level::Warn, &format!("rtsp: rejecting {peer}: client cap ({MAX_RTSP_CLIENTS}) reached", peer = stream.peer_addr().map(|a| a.to_string()).unwrap_or_else(|_| "<unknown>".to_string())));
                }
                let _ = stream.set_write_timeout(Some(Duration::from_millis(WRITE_TIMEOUT_MS)));
                let resp = response(STATUS_SERVICE_UNAVAILABLE, None, None, Vec::new(), Vec::new());
                let _ = (&stream).write_all(&resp.to_bytes());
                drop(stream);
                return;
            }
            active_clients.fetch_add(1, RELAXED);
            let state = state.clone();
            let server_ip = server_ip.clone();
            let shutdown = shutdown_for_closure.clone();
            let logger = logger.clone();
            let active = active_clients.clone();
            thread::spawn(move || {
                handle_client(stream, state, server_ip, shutdown, logger);
                active.fetch_sub(1, RELAXED);
            });
        })
    }

    /// Signals the accept loop and all pumps to exit. Idempotent.
    pub fn shutdown(&self) {
        self.shutdown.store(true, RELAXED);
    }

    /// Returns a clone of the shutdown flag so external code (`console_main`, the Windows service wrapper, or tests) can stop the accept loop without holding a reference to the `RtspServer`. Setting the flag stops the accept loop on its next poll; existing pumps exit on their next poll cycle. Mirrors `CameraListener::shutdown_signal`.
    pub fn shutdown_signal(&self) -> Arc<AtomicBool> {
        self.shutdown.clone()
    }

    /// Number of client connections currently being handled. Intended for diagnostics and tests; not used in the hot path.
    pub fn active_clients(&self) -> usize {
        self.active_clients.load(RELAXED)
    }

    /// Returns a clone of the active-clients counter so external code (tests) can observe the live connection count without holding a reference to the `RtspServer` (which is moved into the accept thread). Mirrors `shutdown_signal`.
    pub fn active_clients_signal(&self) -> Arc<AtomicUsize> {
        self.active_clients.clone()
    }
}

/// One RTSP session's runtime bookkeeping, local to a single connection. `receiver` is `Some` between SETUP and PLAY; the pump takes it on PLAY. `udp_sock` is the server-side RTP socket bound at SETUP for UDP transports (held here so a PLAY can hand it to the pump without rebinding).
struct SessionRegistration {
    client_id: ClientId,
    receiver: Option<Receiver<Frame>>,
    transport: Transport,
    udp_sock: Option<UdpSocket>,
}

/// Discards any `$`-framed interleaved frames the client sent on the RTSP TCP connection (e.g. RTCP receiver reports on channel 1, which VLC and ffprobe emit under TCP transport). The proxy only sends RTP and never reads RTCP, so these frames carry no actionable data; draining them keeps the control buffer from filling until `MAX_READ_BUFFER_BYTES` breaks long interleaved sessions. A partial frame at the buffer head is left for the next read to complete. Per RFC 2326 §12.39 the `$` byte (`0x24`) cannot start an RTSP request line, so a frame at the head is unambiguous.
fn drain_client_interleaved_frames(buf: &mut Vec<u8>) {
    loop {
        if buf.first() != Some(&INTERLEAVED_FRAME_MARKER) {
            break;
        }
        if buf.len() < INTERLEAVED_FRAMING_BYTES {
            break;
        }
        let len = u16::from_be_bytes([buf[2], buf[3]]) as usize;
        let frame_end = INTERLEAVED_FRAMING_BYTES + len;
        if buf.len() < frame_end {
            break;
        }
        buf.drain(..frame_end);
    }
}

/// Handles a single RTSP TCP connection to completion: reads and dispatches requests, wires SETUP/PLAY/TEARDOWN to the shared `StreamState`, and spawns the RTP pump on PLAY. Returns when the peer closes, the shutdown flag is set, or a write fails; in every case registered clients are removed from the hub so their pumps drain and exit.
fn handle_client(stream: TcpStream, state: StreamState, server_ip: String, shutdown: Arc<AtomicBool>, logger: Option<Arc<Logger>>) {
    let peer = match stream.peer_addr() {
        Ok(p) => p,
        Err(_) => return,
    };
    if let Some(logger) = &logger {
        logger.log(Level::Info, &format!("rtsp client connected: {peer}"));
    }
    let mut read_half = match stream.try_clone() {
        Ok(s) => s,
        Err(_) => return,
    };
    let _ = read_half.set_nodelay(true);
    let _ = read_half.set_read_timeout(Some(Duration::from_millis(READ_TIMEOUT_MS)));
    let _ = read_half.set_write_timeout(Some(Duration::from_millis(WRITE_TIMEOUT_MS)));
    let writer = Arc::new(Mutex::new(stream));

    let mut ctx = ConnectionCtx { state, server_ip, writer, peer, shutdown, sessions: RtspSessions::new(), registrations: HashMap::new(), logger: logger.clone() };

    let mut buf: Vec<u8> = Vec::new();
    let mut chunk = [0u8; READ_CHUNK_BYTES];
    // Last time bytes arrived on the RTSP control socket. Used by the idle-timeout reaper: a connection with no playing session that goes silent for `SESSION_TIMEOUT_SECS` is torn down, keeping the advertised timeout and its enforcement in agreement. A playing session is exempt — RTP is one-way, so a healthy streaming client sends nothing on the control socket after `PLAY`.
    let mut last_activity = Instant::now();

    loop {
        if ctx.shutdown.load(RELAXED) {
            break;
        }
        let n = match read_half.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                if reap_if_idle(&ctx.sessions, last_activity) {
                    break;
                }
                continue;
            }
            Err(e) if e.kind() == io::ErrorKind::TimedOut => {
                if reap_if_idle(&ctx.sessions, last_activity) {
                    break;
                }
                continue;
            }
            Err(_) => break,
        };
        last_activity = Instant::now();
        buf.extend_from_slice(&chunk[..n]);
        if buf.len() > MAX_READ_BUFFER_BYTES {
            break;
        }
        drain_client_interleaved_frames(&mut buf);
        loop {
            let parsed = parse_request(&buf);
            match parsed {
                Ok(Some((req, consumed))) => {
                    let codec = ctx.state.codec();
                    let mut resp = handle_request(&req, &mut ctx.sessions, &ctx.server_ip, codec.as_ref());
                    ctx.wire(&req, &mut resp);
                    if let Some(logger) = &logger {
                        if resp.status == STATUS_UNSUPPORTED_TRANSPORT || resp.status == STATUS_SERVICE_UNAVAILABLE {
                            logger.log(Level::Warn, &format!("rtsp: {peer} {:?} -> {}", req.method, resp.status));
                        }
                    }
                    if write_all_locked(&ctx.writer, &resp.to_bytes()).is_err() {
                        buf.clear();
                        break;
                    }
                    buf.drain(..consumed);
                }
                Ok(None) => break,
                Err(e) => {
                    let (level, msg) = match e {
                        // An HTTP request landing on the RTSP port: common NVR behaviour — a connectivity probe against the stream URI or an attempt to fetch a snapshot over HTTP (some NVRs misread GetSnapshotUri's rtsp:// URL as an HTTP snapshot endpoint). Not a proxy defect; log quietly and close.
                        RtspError::NonRtspVersion(v) => (Level::Info, format!("rtsp: non-RTSP request (likely HTTP probe) from {peer}: {v}, closing")),
                        // A genuinely mis-framed request: close rather than keep, because the byte stream is at an unknown offset.
                        _ => (Level::Warn, format!("rtsp: malformed request from {peer}, closing")),
                    };
                    if let Some(logger) = &logger {
                        logger.log(level, &msg);
                    }
                    let resp = response(STATUS_BAD_REQUEST, None, None, Vec::new(), Vec::new());
                    let _ = write_all_locked(&ctx.writer, &resp.to_bytes());
                    buf.clear();
                    break;
                }
            }
        }
    }

    ctx.cleanup();
    if let Some(logger) = &logger {
        logger.log(Level::Info, &format!("rtsp client disconnected: {peer}"));
    }
}

/// Idle-timeout reaper. Returns `true` (signalling the caller to tear the connection down) when no session on this connection is `playing` AND the control socket has been silent for at least `SESSION_TIMEOUT_SECS`. A `playing` session is never reaped on control-channel silence: RTP is one-way, so a healthy streaming client sends nothing on the control socket after `PLAY`, and the RTP pump's own broken-pipe path handles a genuinely-gone player. The timeout honors the `SESSION: <id>;timeout=60` value advertised in SETUP responses, keeping advertisement and enforcement in agreement. RTCP-based keepalive for playing sessions is intentionally not implemented.
fn reap_if_idle(sessions: &RtspSessions, last_activity: Instant) -> bool {
    if sessions.any_playing() {
        return false;
    }
    last_activity.elapsed() >= Duration::from_secs(u64::from(SESSION_TIMEOUT_SECS))
}

/// Per-connection mutable state: the shared hub handle, the connection's send mutex and peer address, the per-connection session registry, and the `StreamState` client registrations created by SETUP. Grouping these into one struct keeps the wiring methods focused and avoids passing a long chain of borrows through every helper.
struct ConnectionCtx {
    state: StreamState,
    server_ip: String,
    writer: Arc<Mutex<TcpStream>>,
    peer: SocketAddr,
    shutdown: Arc<AtomicBool>,
    sessions: RtspSessions,
    registrations: HashMap<String, SessionRegistration>,
    logger: Option<Arc<Logger>>,
}

impl ConnectionCtx {
    /// Applies the side effects that follow a dispatched request: registering a `StreamState` client at SETUP, spawning the RTP pump at PLAY, and tearing one down at TEARDOWN. May replace `resp` (e.g. with `503` if a UDP server socket could not be bound at SETUP).
    fn wire(&mut self, req: &RtspRequest, resp: &mut RtspResponse) {
        match (&req.method, resp.status) {
            (Method::Setup, STATUS_OK) => self.wire_setup(resp),
            (Method::Play, STATUS_OK) => self.wire_play(req),
            (Method::Teardown, STATUS_OK) => {
                if let Some(sid) = &req.session {
                    if let Some(reg) = self.registrations.remove(sid) {
                        self.state.remove_client(reg.client_id);
                    }
                }
            }
            _ => {}
        }
    }

    /// SETUP wiring: registers a `StreamState` client and (for UDP) binds the server RTP socket. On UDP bind failure the session is rolled back and the response becomes `503 Service Unavailable`.
    fn wire_setup(&mut self, resp: &mut RtspResponse) {
        let Some(session_header) = resp.session.clone() else {
            return;
        };
        let sid = session_id(&session_header);
        let Some(session) = self.sessions.get(&sid) else {
            return;
        };
        let transport = session.transport.clone();
        let (client_id, receiver) = self.state.add_client();
        let mut reg = SessionRegistration { client_id, receiver: Some(receiver), transport: transport.clone(), udp_sock: None };
        if let Transport::Udp { server_rtp, .. } = transport {
            match UdpSocket::bind(("0.0.0.0", server_rtp)) {
                Ok(sock) => reg.udp_sock = Some(sock),
                Err(_) => {
                    self.sessions.remove(&sid);
                    self.state.remove_client(client_id);
                    *resp = response(STATUS_SERVICE_UNAVAILABLE, resp.cseq, None, Vec::new(), Vec::new());
                    return;
                }
            }
        }
        self.registrations.insert(sid, reg);
    }

    /// PLAY wiring: takes the session's buffered receiver, builds the matching `PacketSink`, and spawns the per-session RTP pump.
    fn wire_play(&mut self, req: &RtspRequest) {
        let Some(sid) = &req.session else {
            return;
        };
        let Some(reg) = self.registrations.get_mut(sid) else {
            return;
        };
        let Some(receiver) = reg.receiver.take() else {
            return;
        };
        let sink = match &reg.transport {
            Transport::Interleaved { rtp_ch, .. } => Box::new(TcpInterleavedSink::new(self.writer.clone(), *rtp_ch)) as Box<dyn PacketSink + Send>,
            Transport::Udp { client_rtp, .. } => {
                let Some(sock) = reg.udp_sock.take() else {
                    return;
                };
                Box::new(UdpSink::new(sock, SocketAddr::new(self.peer.ip(), *client_rtp))) as Box<dyn PacketSink + Send>
            }
        };
        let client_id = reg.client_id;
        let state = self.state.clone();
        let shutdown = self.shutdown.clone();
        let logger = self.logger.clone();
        let peer = self.peer;
        thread::spawn(move || run_pump(receiver, sink, state, client_id, shutdown, logger.as_deref(), peer));
    }

    /// Removes every still-registered client for this connection from the hub, dropping their senders so any running pumps drain and exit.
    fn cleanup(&mut self) {
        for (_, reg) in self.registrations.drain() {
            self.state.remove_client(reg.client_id);
        }
    }
}

/// Writes `bytes` to the connection under the shared send mutex so control responses and interleaved RTP frames never interleave corruptly.
fn write_all_locked(writer: &Arc<Mutex<TcpStream>>, bytes: &[u8]) -> io::Result<()> {
    let guard = writer.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    write_all_retry(&guard, bytes)
}

/// Like `write_all` but retries on `WouldBlock`/`TimedOut` (Windows `WSAEWOULDBLOCK` / `WSAETIMEDOUT`) instead of treating them as fatal. On these errors the socket's send buffer is full; a short sleep lets the OS drain it, then the write resumes.
fn write_all_retry(stream: &TcpStream, mut bytes: &[u8]) -> io::Result<()> {
    // TcpStream's Write impl requires &mut, but we only hold a shared ref through the Mutex guard. TcpStream is internally synchronized by the OS, so taking a &mut via the guard's DerefMut is safe — the Mutex provides the exclusive access the compiler needs.
    let mut s: &TcpStream = stream;
    while !bytes.is_empty() {
        match s.write(bytes) {
            Ok(0) => {
                return Err(io::Error::new(io::ErrorKind::WriteZero, "wrote zero bytes"));
            }
            Ok(n) => {
                bytes = &bytes[n..];
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(1));
                continue;
            }
            Err(e) if e.kind() == io::ErrorKind::TimedOut => {
                thread::sleep(Duration::from_millis(1));
                continue;
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

/// Per-session RTP pump: pulls `Frame`s from the session's `StreamState` receiver, packetizes each per RFC 6184, and sends every RTP packet through the sink. Large frames (keyframes) are paced so the burst does not overflow a receiver's initial RTP reorder buffer — a 1.2 MB keyframe packetized into ~900 RTP packets and sent in ~12 ms causes live555 (VLC) to drop ~475 KB and wait for the next keyframe. Pacing spreads the send over ~100 ms by sleeping between chunk boundaries, giving the receiver time to grow its buffer. Exits on channel disconnect (TEARDOWN / client gone), a sink write error (broken pipe), or the shutdown flag, then removes the client from the hub so the camera thread never blocks on a dead session. A sink write error is logged at WARN (when a logger is attached) so a vanished player is visible in `flvproxy.log`.
fn run_pump(receiver: Receiver<Frame>, mut sink: Box<dyn PacketSink + Send>, state: StreamState, client_id: ClientId, shutdown: Arc<AtomicBool>, logger: Option<&Logger>, peer: SocketAddr) {
    let mut packetizer = RtpPacketizer::new(random_ssrc(), random_seq());
    while !shutdown.load(RELAXED) {
        match receiver.recv_timeout(Duration::from_millis(PUMP_POLL_TIMEOUT_MS)) {
            Ok(frame) => {
                if pump_frame_into_paced(&mut *sink, &mut packetizer, &frame).is_err() {
                    if let Some(logger) = &logger {
                        logger.log(Level::Warn, &format!("rtsp: pump write failed for {peer}; tearing down session"));
                    }
                    let _ = state.remove_client(client_id);
                    return;
                }
            }
            Err(RecvTimeoutError::Timeout) => continue,
            Err(RecvTimeoutError::Disconnected) => break,
        }
    }
    let _ = state.remove_client(client_id);
}

/// Sink abstraction letting the pump send RTP packets to a real socket in production and an in-memory `Vec` in tests, sharing one code path. The `Send` bound is required so a boxed sink can move into the pump thread.
pub trait PacketSink {
    /// Sends one complete RTP packet. An error signals a broken transport (e.g. peer closed); the pump treats it as terminal.
    fn send(&mut self, pkt: &[u8]) -> io::Result<()>;
}

/// `PacketSink` writing RTP as `$`-framed interleaved data on the RTSP TCP connection, per RFC 2326 §12.39. Shares the connection's send mutex with control-response writes so bytes never interleave.
pub struct TcpInterleavedSink {
    writer: Arc<Mutex<TcpStream>>,
    rtp_ch: u8,
}

impl TcpInterleavedSink {
    pub fn new(writer: Arc<Mutex<TcpStream>>, rtp_ch: u8) -> TcpInterleavedSink {
        TcpInterleavedSink { writer, rtp_ch }
    }
}

impl PacketSink for TcpInterleavedSink {
    fn send(&mut self, pkt: &[u8]) -> io::Result<()> {
        let mut frame = Vec::with_capacity(INTERLEAVED_FRAMING_BYTES + pkt.len());
        frame.push(INTERLEAVED_FRAME_MARKER);
        frame.push(self.rtp_ch);
        let len = u16::try_from(pkt.len()).map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "RTP packet exceeds 65535 bytes"))?;
        frame.extend_from_slice(&len.to_be_bytes());
        frame.extend_from_slice(pkt);
        let guard = self.writer.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        // On Windows, a TcpStream with a write timeout can return WSAEWOULDBLOCK (os error 10035) when the TCP send buffer is full (e.g. bursting ~900 RTP packets for a 1.2 MB keyframe). `write_all` treats that as fatal; retry on WouldBlock/TimedOut instead so the pump drains the buffer over multiple writes.
        write_all_retry(&guard, &frame)
    }
}

/// `PacketSink` sending RTP as UDP datagrams to the client's negotiated RTP port, per RFC 2326 §12.39 (`client_port`). The socket is bound to the server RTP port advertised in SETUP so the client can correlate source and advertised ports.
pub struct UdpSink {
    sock: UdpSocket,
    dst: SocketAddr,
}

impl UdpSink {
    pub fn new(sock: UdpSocket, dst: SocketAddr) -> UdpSink {
        UdpSink { sock, dst }
    }
}

impl PacketSink for UdpSink {
    fn send(&mut self, pkt: &[u8]) -> io::Result<()> {
        self.sock.send_to(pkt, self.dst).map(|_| ())
    }
}

/// In-memory `PacketSink` recording every packet for assertion in tests. Shares the exact pump code path with the production sinks.
pub struct VecSink {
    packets: Vec<Vec<u8>>,
}

impl VecSink {
    pub fn new() -> VecSink {
        VecSink { packets: Vec::new() }
    }

    pub fn packets(&self) -> &[Vec<u8>] {
        &self.packets
    }

    pub fn into_packets(self) -> Vec<Vec<u8>> {
        self.packets
    }
}

impl Default for VecSink {
    fn default() -> VecSink {
        VecSink::new()
    }
}

impl PacketSink for VecSink {
    fn send(&mut self, pkt: &[u8]) -> io::Result<()> {
        self.packets.push(pkt.to_vec());
        Ok(())
    }
}

/// Drives one frame through the pump core: packetizes `frame` and sends every resulting RTP packet via `sink`, advancing `packetizer`'s sequence number. This is the single shared send path — `run_pump` calls it for each live frame over a real `TcpInterleavedSink` / `UdpSink`, and tests call it over a `VecSink` to assert byte-for-byte parity with `RtpPacketizer::packetize_frame`. A send error (broken transport) propagates as `Err` so the caller can tear the session down.
pub fn pump_frame_into(sink: &mut dyn PacketSink, packetizer: &mut RtpPacketizer, frame: &Frame) -> io::Result<()> {
    for packet in packetizer.packetize_frame(frame) {
        sink.send(&packet)?;
    }
    Ok(())
}

/// Production send path used by `run_pump`: packetizes `frame` and sends every resulting RTP packet via `sink`, pacing large frames (keyframes) by sleeping `PACING_CHUNK_SLEEP` every `PACING_CHUNK_PACKETS` so the burst does not overflow a receiver's initial RTP reorder buffer. Small frames (P-frames) are sent without pacing — they arrive at 33 ms intervals and never approach the buffer's capacity. A send error propagates as `Err` so the caller can tear the session down. This mirrors `pump_frame_into` exactly for the unpaced case, so tests that assert byte-for-byte parity via `pump_frame_into` over a `VecSink` cover the same packetization.
fn pump_frame_into_paced(sink: &mut dyn PacketSink, packetizer: &mut RtpPacketizer, frame: &Frame) -> io::Result<()> {
    let frame_bytes: usize = frame.nalus.iter().map(|n| n.len()).sum();
    let packets = packetizer.packetize_frame(frame);
    let pacing = frame_bytes > PACING_FRAME_THRESHOLD_BYTES;
    for (i, packet) in packets.iter().enumerate() {
        sink.send(packet)?;
        if pacing && (i + 1) % PACING_CHUNK_PACKETS == 0 {
            thread::sleep(PACING_CHUNK_SLEEP);
        }
    }
    Ok(())
}

/// Derives a per-session SSRC from wall-clock nanos xor'd with a process-wide counter, then mixed via splitmix64. Avoids a randomness crate; uniqueness across sessions is provided by the counter, not by cryptographic strength (RTP SSRCs need only be locally unique, per RFC 3550 §3).
fn random_ssrc() -> u32 {
    (splitmix64(session_seed()) >> 32) as u32
}

/// Derives a per-session initial RTP sequence number from the same seed, per RFC 3550 §5.1's recommendation to start at a random offset.
fn random_seq() -> u16 {
    (splitmix64(session_seed()) >> 16) as u16
}

/// Per-call entropy: wall-clock nanos since the Unix epoch xor'd with a monotonic process counter. `unwrap_or_default` keeps it panic-free if the clock is before the epoch.
fn session_seed() -> u64 {
    static COUNTER: AtomicUsize = AtomicUsize::new(0);
    let nanos = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_nanos() as u64;
    let c = COUNTER.fetch_add(1, RELAXED) as u64;
    nanos ^ c.wrapping_mul(GOLDEN_RATIO_64)
}

/// One splitmix64 round (Knuth MMIX), used to diffuse `session_seed`'s raw entropy across the 32-bit SSRC and 16-bit sequence fields.
fn splitmix64(mut z: u64) -> u64 {
    z = z.wrapping_add(SPLITMIX_INCREMENT);
    let mut x = z;
    x ^= x >> 30;
    x = x.wrapping_mul(SPLITMIX_MULTIPLIER);
    x ^= x >> 27;
    x = x.wrapping_mul(SPLITMIX_MULTIPLIER);
    x ^= x >> 31;
    x
}
