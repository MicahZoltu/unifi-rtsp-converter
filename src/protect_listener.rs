//! Production Protect-controller 7442 listener (build-plan step 21). Binds `0.0.0.0:7442`, accepts the camera's TLS WebSocket AVClient handshake (hand-rolled `tls_schannel::TlsStream` from step 17 + `ws::WsHandshake` from step 18), and drives an `AvClientSession` (step 19) that answers `hello`/`paramAgreement`/`timeSync` and sends the one-shot `ChangeVideoSettings` pointing the camera at this proxy's 7550 plain-TCP FLV listener. Once the camera acks, it dials 7550 and pushes bare FLV — handled by the shared `CameraListener` (step 14/20), which publishes into the same `StreamState` the RTSP server (step 12) serves.
//!
//! Windows-only (`#[cfg(windows)]`): it links `tls_schannel` which FFI's `crypt32`/`secur32`. The Linux build host never compiles this module; the Linux `console_main` path uses the plain-TCP `CameraListener` directly as the test ingress (per step 21 task 3).

#![cfg(windows)]

use std::io::{self, Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use crate::logging::{Level, Logger};
use crate::protect_controller::AvClientSession;
use crate::tls_schannel::{HandshakeError, TlsAcceptor, TlsStream};
use crate::ws::WsHandshake;

/// Relaxed ordering suffices for the shutdown flag: it is an advisory signal, not synchronization that establishes happens-before for other data. Mirrors `camera_listener`/`rtsp_server`'s convention.
const RELAXED: Ordering = Ordering::Relaxed;

/// UniFi Protect AVClient handshake port (stage 3 of the 5-stage flow), per `plan/16-protect-recon.md` → "Background". The production listener always binds here.
pub const PROTECT_AVCLIENT_PORT: u16 = 7442;

/// Accept-loop poll interval (non-blocking `TcpListener`), so the shutdown flag is checked promptly rather than blocking on the next connection. Mirrors `camera_listener`'s `ACCEPT_POLL_MS`.
const ACCEPT_POLL_MS: u64 = 50;

/// Per-read timeout on an accepted (post-TLS) 7442 connection. The hand-rolled `TlsStream` surfaces the underlying socket's timeout as `WouldBlock`/`TimedOut`, which the AVClient retry reader tolerates (see `AVCLIENT_SESSION_DEADLINE_SECS`). Keeps a stuck camera from blocking the handler thread forever so shutdown can interrupt it.
const READ_TIMEOUT_MS: u64 = 1000;

/// Upper bound on how long the AVClient session keeps retrying a `WouldBlock`/`TimedOut` read before giving up. Mirrors the recon tool's `CAPTURE_READ_DEADLINE_SECS`: if the camera has not sent the next AVClient frame (or closed) within this window, the session is logged and ended so the accept loop can handle the camera's inevitable 7442 retry rather than accumulating stuck handler threads. Ctrl+C still terminates promptly — the retry loop checks `shutdown` every `AVCLIENT_RETRY_SLEEP_MS`.
const AVCLIENT_SESSION_DEADLINE_SECS: u64 = 30;

/// Sleep between `WouldBlock`/`TimedOut` retries in the AVClient read loop. Mirrors `camera_listener`'s read-timeout cadence so the spin stays cheap.
const AVCLIENT_RETRY_SLEEP_MS: u64 = 20;

/// Cap on the buffered HTTP upgrade request (headers only — RFC 6455 §4.1 implementations must reject requests with absurdly long headers). 8 KiB is well above any legitimate `Sec-WebSocket-*` header set. Mirrors the recon tool's `MAX_HANDSHAKE_HEADER_BYTES`.
const MAX_HANDSHAKE_HEADER_BYTES: usize = 8 * 1024;

/// Scratch-buffer size for one raw-tap read of the pre-upgrade HTTP request. Bounds per-iteration granularity; the upgrade request is reassembled across reads until `\r\n\r\n` is seen.
const UPGRADE_READ_CHUNK: usize = 4096;

/// Sleep between `WouldBlock`/`TimedOut` retries in the pre-upgrade raw-tap loop. Mirrors the recon tool's `RAW_RETRY_SLEEP_MS`.
const UPGRADE_RETRY_SLEEP_MS: u64 = 20;

/// `ChangeVideoSettings` destination URI query suffix appended to `tcp://<controller_ip>:7550`. `retryInterval=1` makes the camera retry the 7550 dial every 1 s if the proxy is briefly unavailable; `connectTimeout=5` bounds each dial attempt to 5 s. Matches the redalert baseline and the step-20 interim recon's confirmed shape.
const STREAM_DESTINATION_QUERY: &str = "retryInterval=1&connectTimeout=5";

/// Holds the raw socket of the currently-active 7442 connection so a new connection can force-close it (one active AVClient session at a time, mirroring `camera_listener`'s `ConnectionSlot`). A `shutdown(Both)` on the clone interrupts the active handler's blocked read on shutdown.
#[derive(Clone)]
struct ConnectionSlot {
    current: Arc<Mutex<Option<TcpStream>>>,
}

impl ConnectionSlot {
    fn new() -> ConnectionSlot {
        ConnectionSlot { current: Arc::new(Mutex::new(None)) }
    }

    /// Stores `clone` as the active connection, force-closing whatever connection was active before.
    fn swap(&self, clone: TcpStream) {
        let old = {
            let mut guard = self.current.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
            guard.replace(clone)
        };
        if let Some(old) = old {
            let _ = old.shutdown(Shutdown::Both);
        }
    }

    /// Force-closes and drops the active connection, if any. Used on listener shutdown so the active handler's blocked read returns promptly.
    fn force_close(&self) {
        let old = {
            let mut guard = self.current.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
            guard.take()
        };
        if let Some(old) = old {
            let _ = old.shutdown(Shutdown::Both);
        }
    }
}

/// Production Protect-controller 7442 listener. Owns the TLS acceptor built from the configured PFX and the shutdown flag. The AVClient session this listener runs only drives adoption (it does not publish frames — the 7550 `CameraListener` owns the shared `StreamState` and publishes the FLV bytes the camera pushes after adoption), so this listener holds no `StreamState` reference.
pub struct ProtectListener {
    avclient_port: u16,
    advertised_ip: String,
    acceptor: TlsAcceptor,
    logger: Arc<Logger>,
    shutdown: Arc<AtomicBool>,
    active: ConnectionSlot,
}

impl ProtectListener {
    /// Creates a listener that will bind `0.0.0.0:avclient_port` (7442) for the camera's AVClient TLS WebSocket handshake. `advertised_ip` is the fallback controller IP used in the `ChangeVideoSettings` destination URI when the camera's `Host` header is absent. `acceptor` is the shared, clone-cheap TLS credential built from the configured PFX.
    pub fn new(avclient_port: u16, advertised_ip: String, acceptor: TlsAcceptor, logger: Arc<Logger>) -> ProtectListener {
        ProtectListener { avclient_port, advertised_ip, acceptor, logger, shutdown: Arc::new(AtomicBool::new(false)), active: ConnectionSlot::new() }
    }

    /// Binds `0.0.0.0:avclient_port` and runs the accept loop until `shutdown()` is called.
    pub fn run(&self) -> io::Result<()> {
        let listener = TcpListener::bind(("0.0.0.0", self.avclient_port))?;
        listener.set_nonblocking(true)?;
        for incoming in listener.incoming() {
            if self.shutdown.load(RELAXED) {
                break;
            }
            match incoming {
                Ok(stream) => self.spawn_handler(stream),
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(ACCEPT_POLL_MS));
                }
                Err(_) => {
                    thread::sleep(Duration::from_millis(ACCEPT_POLL_MS));
                }
            }
        }
        Ok(())
    }

    /// Accepts a fresh 7442 connection: stores a clone in the active slot (so the next accept can force-close it), force-closes whatever connection was active before, and spawns a handler thread that completes the TLS + WS handshake and runs the AVClient session.
    fn spawn_handler(&self, stream: TcpStream) {
        let peer = stream.peer_addr().ok();
        let clone = match stream.try_clone() {
            Ok(c) => c,
            Err(_) => {
                self.logger.log(Level::Warn, "7442 connection: could not clone stream; dropping");
                return;
            }
        };
        self.active.swap(clone);
        let peer_str = peer.map(|p| p.to_string()).unwrap_or_else(|| "<unknown>".to_string());
        let logger = self.logger.clone();
        let shutdown = self.shutdown.clone();
        let acceptor = self.acceptor.clone();
        let advertised_ip = self.advertised_ip.clone();
        thread::spawn(move || {
            handle_avclient_connection(stream, peer_str, logger, shutdown, acceptor, advertised_ip);
        });
    }

    /// Signals the accept loop and the active handler to exit, and force-closes the active connection so its blocked read returns immediately. Idempotent.
    pub fn shutdown(&self) {
        self.shutdown.store(true, RELAXED);
        self.active.force_close();
    }

    /// Returns a clone of the shutdown flag so external code (the Windows service wrapper, or `console_main`) can stop the listener without holding a reference to the `ProtectListener`.
    pub fn shutdown_signal(&self) -> Arc<AtomicBool> {
        self.shutdown.clone()
    }
}

/// Handles one accepted 7442 TCP connection to completion: applies socket options, completes the TLS handshake (tolerating the camera's benign zero-byte TCP liveness probe as `PeerClosedBeforeData`), raw-taps the HTTP WS upgrade request, sends the `101`, extracts the camera's `Device-ID` / `Camera-MAC` / `Host` headers for the adoption context, and runs the `AvClientSession` to completion. Every error path simply closes the connection so the accept loop keeps running for the next retry.
fn handle_avclient_connection(stream: TcpStream, peer: String, logger: Arc<Logger>, shutdown: Arc<AtomicBool>, acceptor: TlsAcceptor, advertised_ip: String) {
    // Capture the local IP the camera reached us on BEFORE the stream is moved into the TLS acceptor. This is the single most reliable source for the `ChangeVideoSettings` destination IP: it is the exact address the camera's TCP stack routed to, so it is guaranteed reachable from the camera's network. `local_ip_v4()` auto-detection (used for the advertised_ip fallback) can pick the wrong interface on a multi-homed host (e.g. a build-host NIC the camera's subnet can't route to), which causes the camera to ack `ChangeVideoSettings` but then fail the 7550 dial and reset 7442 — observed in the step-21 human test.
    let local_ip = stream.local_addr().ok().map(|a| a.ip().to_string());

    let _ = stream.set_nodelay(true);
    let _ = stream.set_read_timeout(Some(Duration::from_millis(READ_TIMEOUT_MS)));

    let mut tls = match acceptor.accept(stream) {
        Ok(t) => t,
        Err(HandshakeError::PeerClosedBeforeData) => {
            return;
        }
        Err(e) => {
            logger.log(Level::Warn, &format!("7442 {peer}: TLS handshake failed: {e}"));
            return;
        }
    };

    let (request, leftover) = match raw_tap_until_upgrade(&mut tls, &logger, &peer, &shutdown) {
        RawTapOutcome::Upgraded { request, leftover } => (request, leftover),
        RawTapOutcome::Closed => return,
        RawTapOutcome::NoData => return,
        RawTapOutcome::Error => return,
    };

    let device_id = extract_header_value(&request, "Device-ID").unwrap_or_else(|| "<unknown>".to_string());
    let camera_mac = extract_header_value(&request, "Camera-MAC").unwrap_or_default().to_uppercase().replace(':', "");
    let stream_name = if camera_mac.is_empty() { None } else { Some(format!("{camera_mac}_0")) };
    // The controller IP the camera must dial for 7550. Prefer the TCP local_addr (the exact IP the camera reached us on — guaranteed reachable), then the WS upgrade Host header (the camera's own view of the controller address), then the advertised_ip fallback (`local_ip_v4()` — only used if both prior sources are unavailable).
    let controller_ip = local_ip.clone().or_else(|| extract_header_value(&request, "Host").and_then(|h| h.rsplit_once(':').map(|(ip, _)| ip.to_string()))).unwrap_or_else(|| advertised_ip.clone());
    let stream_destination = format!("tcp://{controller_ip}:7550?{STREAM_DESTINATION_QUERY}");

    let inner = ChainedReader::new(leftover, tls);
    let mut retry = RetryReader::new(inner, shutdown.clone());
    let mut session = AvClientSession::new(&mut retry, device_id.clone()).with_stream_destination(stream_destination, stream_name);
    match session.run() {
        Ok(()) => {}
        Err(e) => logger.log(Level::Warn, &format!("7442 {peer}: AVClient session error: {e}")),
    }
}

/// Outcome of the pre-upgrade raw-tap loop. `Upgraded` carries the full HTTP upgrade request bytes (so the handler can parse `Device-ID`/`Camera-MAC`/`Host` for the AVClient session) plus any bytes the camera sent after the `\r\n\r\n` terminator (the start of the first WS frame); the post-upgrade session consumes the leftover via `ChainedReader` before reading fresh bytes off the TLS stream.
enum RawTapOutcome {
    Upgraded { request: Vec<u8>, leftover: Vec<u8> },
    Closed,
    NoData,
    Error,
}

/// Reads bytes from `tls` until either a complete RFC 6455 §4.1 HTTP Upgrade request is buffered (then sends the `101` and returns `Upgraded`) or the peer closes / times out / shutdown is signalled. Tolerates the `WouldBlock`/`TimedOut` errors the timed socket surfaces: the first-byte wait is bounded by `AVCLIENT_SESSION_DEADLINE_SECS`; subsequent reads retry until the upgrade completes or the peer closes. Stops buffering (and stops checking for an upgrade) once `MAX_HANDSHAKE_HEADER_BYTES` is exceeded without a `\r\n\r\n` terminator — the camera's request is always small.
fn raw_tap_until_upgrade(tls: &mut TlsStream<TcpStream>, logger: &Logger, peer: &str, shutdown: &AtomicBool) -> RawTapOutcome {
    let deadline = Instant::now() + Duration::from_secs(AVCLIENT_SESSION_DEADLINE_SECS);
    let mut buf: Vec<u8> = Vec::new();
    let mut scratch = [0u8; UPGRADE_READ_CHUNK];
    let mut first_byte_seen = false;
    let mut stop_upgrade_check = false;

    loop {
        if shutdown.load(RELAXED) {
            return RawTapOutcome::Closed;
        }
        match tls.read(&mut scratch) {
            Ok(0) => return RawTapOutcome::Closed,
            Ok(n) => {
                first_byte_seen = true;
                if !stop_upgrade_check {
                    buf.extend_from_slice(&scratch[..n]);
                    if let Some(outcome) = try_upgrade_from_buffer(tls, &buf, logger, peer) {
                        return outcome;
                    }
                    if buf.len() > MAX_HANDSHAKE_HEADER_BYTES {
                        logger.log(Level::Warn, &format!("7442 {peer}: buffered {len} bytes with no \\r\\n\\r\\n; not an HTTP upgrade", len = buf.len()));
                        stop_upgrade_check = true;
                    }
                }
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) if e.kind() == io::ErrorKind::WouldBlock || e.kind() == io::ErrorKind::TimedOut => {
                if !first_byte_seen && Instant::now() >= deadline {
                    return RawTapOutcome::NoData;
                }
                thread::sleep(Duration::from_millis(UPGRADE_RETRY_SLEEP_MS));
            }
            Err(_) => return RawTapOutcome::Error,
        }
    }
}

/// Inspects the accumulated pre-upgrade buffer for a complete RFC 6455 §4.1 HTTP Upgrade request. When found, validates it via `ws::WsHandshake::parse` (which enforces the `Sec-WebSocket-Key`/`Version` requirements and yields the `101` response bytes that echo the camera's offered subprotocol), writes the `101`, and returns `Some(Upgraded { leftover })` where `leftover` is any bytes the camera sent past the `\r\n\r\n` terminator. Returns `None` when no complete header terminator is present yet (the caller keeps reading). A complete-but-unparseable request logs and returns `None` (raw tap continues briefly until the size cap aborts it).
fn try_upgrade_from_buffer(tls: &mut TlsStream<TcpStream>, buf: &[u8], logger: &Logger, peer: &str) -> Option<RawTapOutcome> {
    let term = b"\r\n\r\n";
    let header_end = buf.windows(term.len()).position(|w| w == term)? + term.len();
    let request = &buf[..header_end];
    let handshake = match WsHandshake::parse(request) {
        Ok(h) => h,
        Err(e) => {
            logger.log(Level::Warn, &format!("7442 {peer}: WS upgrade parse failed ({e}); raw tap continues"));
            return None;
        }
    };
    let response = handshake.response();
    if tls.write_all(&response).is_err() {
        return Some(RawTapOutcome::Error);
    }
    let _ = tls.flush();
    let leftover = buf[header_end..].to_vec();
    Some(RawTapOutcome::Upgraded { request: request.to_vec(), leftover })
}

/// Extracts the value of HTTP header `name` (case-insensitive) from a textual HTTP request, returning the trimmed value. Used to pull `Device-ID`, `Camera-MAC`, and `Host` from the buffered upgrade request as the adoption context for the AVClient session. Mirrors the recon tool's `extract_header_value`.
fn extract_header_value(request: &[u8], name: &str) -> Option<String> {
    let text = std::str::from_utf8(request).ok()?;
    for line in text.split("\r\n") {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let Some((hdr, value)) = line.split_once(':') else {
            continue;
        };
        if hdr.trim().eq_ignore_ascii_case(name) {
            return Some(value.trim().to_string());
        }
    }
    None
}

/// Reader that drains a leftover byte buffer first, then delegates to an inner `Read`. Used after the WS upgrade to feed any bytes the camera sent past the `\r\n\r\n` terminator into the AVClient session before pulling fresh bytes off the TLS stream. Mirrors the recon tool's `ChainedReader`.
struct ChainedReader<S: Read> {
    pre: std::io::Cursor<Vec<u8>>,
    stream: S,
}

impl<S: Read> ChainedReader<S> {
    fn new(leftover: Vec<u8>, stream: S) -> ChainedReader<S> {
        ChainedReader { pre: std::io::Cursor::new(leftover), stream }
    }
}

impl<S: Read> Read for ChainedReader<S> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.pre.position() < self.pre.get_ref().len() as u64 {
            self.pre.read(buf)
        } else {
            self.stream.read(buf)
        }
    }
}

impl<S: Read + Write> Write for ChainedReader<S> {
    /// Writes go straight to the inner stream — the leftover buffer is a read-only prefix, not a write buffer.
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.stream.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.stream.flush()
    }
}

/// Wraps an inner `Read + Write` and converts the `WouldBlock`/`TimedOut` errors a timed TLS socket surfaces into a bounded sleep+retry, so the AVClient session (which treats those as fatal) sees only real data, real EOF, or real fatal errors. Stops retrying when `shutdown` is set or the per-session deadline elapses. Mirrors the recon tool's `RetryReader`.
struct RetryReader<S> {
    inner: S,
    shutdown: Arc<AtomicBool>,
    deadline: Instant,
}

impl<S> RetryReader<S> {
    fn new(inner: S, shutdown: Arc<AtomicBool>) -> RetryReader<S> {
        RetryReader { inner, shutdown, deadline: Instant::now() + Duration::from_secs(AVCLIENT_SESSION_DEADLINE_SECS) }
    }
}

impl<S: Read> Read for RetryReader<S> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        loop {
            match self.inner.read(out) {
                Ok(n) => return Ok(n),
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) if e.kind() == io::ErrorKind::WouldBlock || e.kind() == io::ErrorKind::TimedOut => {
                    if self.shutdown.load(RELAXED) {
                        return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "shutdown signalled during AVClient read"));
                    }
                    if Instant::now() >= self.deadline {
                        return Err(io::Error::new(io::ErrorKind::TimedOut, format!("AVClient read stalled beyond {AVCLIENT_SESSION_DEADLINE_SECS}s")));
                    }
                    thread::sleep(Duration::from_millis(AVCLIENT_RETRY_SLEEP_MS));
                    continue;
                }
                Err(e) => return Err(e),
            }
        }
    }
}

impl<S: Write> Write for RetryReader<S> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.inner.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}
