//! RTSP server runtime — the socket-driving half of the RTSP server. Owns the `TcpListener` accept loop, per-connection request dispatch (`handle_client`), and the SETUP→PLAY→TEARDOWN wiring to the shared `StreamState` and the per-session RTP pump. The pure request/response protocol, session registry, and method handlers live in `rtsp_protocol`; the `PacketSink` transport abstraction (TCP-interleaved + UDP + in-memory test sink), the RTP pump itself, keyframe pacing, and the per-session SSRC/sequence-number seeding live in `rtsp_pump`. This module imports them privately for its own dispatch needs and exposes only the runtime surface (`RtspServer`) that the integration tests and `app` consume.
//!
//! The dependency graph is a clean DAG: `rtsp_server` depends on `rtsp_protocol` and `rtsp_pump`; neither depends back on `rtsp_server` (the shared `write_all_retry` TCP-write helper lives in `rtsp_pump` for that reason — it is the pump's `TcpInterleavedSink` that needs it, and hosting it there keeps the edge one-directional).
//!
//! Codec parameters for DESCRIBE are pulled from the shared `StreamState` (cloned cheaply into each connection thread), which is the point where the camera pipeline meets the RTSP layer. The session registry is owned per connection: RTSP sessions do not span TCP connections, so each `handle_client` thread holds its own `RtspSessions` and there is no cross-connection shared mutable session state.

use crate::rtsp_protocol::{handle_request, parse_request, response, session_id, Method, RtspError, RtspRequest, RtspResponse, RtspSessions, Transport, SESSION_TIMEOUT_SECS, STATUS_BAD_REQUEST, STATUS_OK, STATUS_SERVICE_UNAVAILABLE, STATUS_UNSUPPORTED_TRANSPORT};
use crate::rtsp_pump::{run_pump, write_all_retry, PacketSink, TcpInterleavedSink, UdpSink, INTERLEAVED_FRAME_MARKER, INTERLEAVED_FRAMING_BYTES};

use std::collections::HashMap;

// --------------------------------------------------------------------------- Runtime half: accept loop, per-connection handling, RTP pump. ---------------------------------------------------------------------------

use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::mpsc::Receiver;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use crate::accept_loop::accept_loop;
use crate::logging::{Level, Logger};
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
