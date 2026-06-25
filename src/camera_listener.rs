//! Camera listener and FLV pipeline. Binds the camera push port (7550 in production), accepts a single active connection at a time (force-closing the prior one when a new one arrives, per `PROJECT.md` → "TCP Listener"), optionally strips the uPFLV prefix (absent on 7550 — the production transport is bare FLV), parses the FLV header, frames the tag stream, and dispatches video/script tags into the shared `StreamState`.
//!
//! The real 7550 transport is **plain TCP, bare FLV** — no TLS, no WebSocket, no uPFLV prefix. The camera sends `FLV\x01\x07\x00\x00\x00\x09` (the standard FLV header) directly over a raw TCP socket. `run_connection` drives this: it sets the per-connection socket options (nodelay + bounded read timeout so the shutdown flag is polled promptly), calls `detect_and_strip_prefix` (a no-op when the stream starts with `FLV` instead of the uPFLV prefix), and feeds the bare FLV bytes directly to `FlvParser`. An earlier revision factored the read loop behind a `CamByteSource` trait to share the pipeline with a since-abandoned WSS-over-7550 transport; real-camera testing confirmed 7550 is plain TCP, so the second transport never shipped and the trait was collapsed back into `run_connection` to remove a single-implementation abstraction.
//!
//! Pure networking + pipeline glue — all byte parsing lives in `flv_parser`, `avc`, and `amf`. The listener never panics: every error path is logged and either recovers via the FLV resync scan or drops the connection, keeping the listener bound for a fresh camera connection. A per-connection `catch_unwind` safety net ensures an unexpected panic in the pipeline closes only that connection — the listener stays bound. Cross-platform `std::net` so it builds and tests on Linux.

use std::io::{self, Read};
use std::net::{TcpListener, TcpStream};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use crate::accept_loop::accept_loop;
use crate::active_slot::ConnectionSlot;
use crate::amf::{is_metadata_tag, parse_on_metadata, StreamMetadata};
use crate::avc::AvcDecoderConfig;
use crate::flv_parser::{detect_and_strip_prefix, parse_header, FlvParser, ParseError, TagEvent, UPFLV_PREFIX};
use crate::flv_video::{parse_video_tag, VideoTagEvent};
use crate::logging::{Level, Logger};
use crate::stream_state::{CodecParams, Frame, StreamState};

/// Relaxed ordering suffices for the shutdown flag and connection counter: they are advisory signals, not synchronization that establishes happens-before for other data (the `StreamState` mutex carries that burden). Mirrors `rtsp_server`'s convention.
const RELAXED: Ordering = Ordering::Relaxed;

/// Per-read timeout on the camera connection. The read loop blocks on `read` for at most this long before returning `TimedOut`, which lets the loop re-check the `shutdown` flag and lets a force-closed connection's handler exit promptly. The camera pushes continuously, so a healthy stream never hits the timeout.
const READ_TIMEOUT_MS: u64 = 500;

/// Size of the per-read scratch buffer feeding the FLV framer. Bounds per-read granularity only; the FLV framer reassembles tags across reads.
const READ_CHUNK_BYTES: usize = 8192;

// --------------------------------------------------------------------------- CameraListener — plain-TCP ingress ---------------------------------------------------------------------------

/// Shutdown handle and shared-data surface for the camera accept loop. A single instance owns the accept thread's flags and the slot holding the currently-active connection (so a new connection can force-close it). The camera thread and each RTSP session thread share the `StreamState` via a cheap `Arc` clone.
pub struct CameraListener {
    state: StreamState,
    listen_port: u16,
    shutdown: Arc<AtomicBool>,
    logger: Arc<Logger>,
    active: ConnectionSlot,
    /// Monotonic per-listener connection counter so camera flapping is visible in the log: each accepted connection logs `camera connected (#N)`, and a rapidly-climbing N is the diagnostic for a flapping camera.
    connection_counter: Arc<AtomicU64>,
}

impl CameraListener {
    /// Creates a listener that will bind `0.0.0.0:listen_port` for the camera and publish decoded config/frames into `state`. `logger` receives connection, SPS/PPS, frame-count, and parse-error lines.
    pub fn new(state: StreamState, listen_port: u16, logger: Arc<Logger>) -> CameraListener {
        CameraListener { state, listen_port, shutdown: Arc::new(AtomicBool::new(false)), logger, active: ConnectionSlot::new(), connection_counter: Arc::new(AtomicU64::new(0)) }
    }

    /// Binds the camera listener on `0.0.0.0:listen_port` and runs the accept loop until `shutdown()` is called.
    pub fn run(&self) -> io::Result<()> {
        let listener = TcpListener::bind(("0.0.0.0", self.listen_port))?;
        self.run_on(listener)
    }

    /// Runs the accept loop on a caller-supplied listener. Tests use this with an ephemeral loopback listener so they know the bound port; production `run()` delegates here after binding.
    pub fn run_on(&self, listener: TcpListener) -> io::Result<()> {
        accept_loop(listener, &self.shutdown, move |stream| self.spawn_handler(stream))
    }

    /// Accepts a fresh camera connection: stores a clone in the active slot (so the next accept can force-close it), force-closes whatever connection was active before, and spawns a handler thread that runs the shared FLV pipeline over the accepted `TcpStream`. The handler body is wrapped in `catch_unwind` so an unexpected panic in the pipeline closes only this connection — the listener stays bound and accepts the next one.
    fn spawn_handler(&self, stream: TcpStream) {
        let peer = stream.peer_addr().ok();
        let clone = match stream.try_clone() {
            Ok(c) => c,
            Err(_) => {
                self.logger.log(Level::Warn, "camera connection: could not clone stream; dropping");
                return;
            }
        };
        self.active.swap(clone);
        let conn_number = self.connection_counter.fetch_add(1, RELAXED) + 1;
        let peer_str = peer.map(|p| p.to_string()).unwrap_or_else(|| "<unknown>".to_string());
        self.logger.log(Level::Info, &format!("camera connected from {peer_str} (#{conn_number})"));
        let state = self.state.clone();
        let logger = self.logger.clone();
        let shutdown = self.shutdown.clone();
        thread::spawn(move || {
            // The `catch_unwind` safety net: an unexpected panic in `run_connection` is logged as `ERROR` with the peer so the operator sees it, then the connection is simply dropped — the listener stays bound for the next camera dial. `AssertUnwindSafe` is sound because the captured `StreamState`/`Logger`/`shutdown` are all `Send` + internally synchronized, and a panic does not leave them in a state observable to other threads (the hub's own mutex recovers from poison via `lock_hub`).
            let result = catch_unwind(AssertUnwindSafe(|| {
                run_connection(stream, peer_str.clone(), state, logger.clone(), shutdown);
            }));
            if let Err(payload) = result {
                let msg = payload.downcast_ref::<&'static str>().copied().or_else(|| payload.downcast_ref::<String>().map(String::as_str)).unwrap_or("<non-string panic payload>");
                logger.log(Level::Error, &format!("camera pipeline panicked (#{conn_number} {peer_str}): {msg}"));
            }
        });
    }

    /// Signals the accept loop and the active handler to exit, and force-closes the active connection so its blocked read returns immediately. Idempotent.
    pub fn shutdown(&self) {
        self.shutdown.store(true, RELAXED);
        self.active.force_close();
    }

    /// Returns a clone of the shutdown flag so external code (the Windows service wrapper, or tests) can stop the listener without holding a reference to the `CameraListener`. Setting the flag stops the accept loop on its next poll; the active handler exits on its next read timeout.
    pub fn shutdown_signal(&self) -> Arc<AtomicBool> {
        self.shutdown.clone()
    }
}

// --------------------------------------------------------------------------- run_connection — the FLV pipeline (steps 12 + 20) ---------------------------------------------------------------------------

/// Drives one camera connection to completion over a plain `TcpStream`: applies the per-connection socket options (nodelay + bounded read timeout so the `shutdown` flag is polled promptly), strips the uPFLV prefix (absent on 7550 — a no-op when the stream starts with `FLV`), parses the FLV header, frames the tag stream, and dispatches video/script tags into `StreamState`. Returns when the stream hits EOF, the `shutdown` flag is set, or a read fails; in every case the connection is simply dropped — the listener stays bound for a fresh camera connection.
pub fn run_connection(stream: TcpStream, peer: String, state: StreamState, logger: Arc<Logger>, shutdown: Arc<AtomicBool>) {
    let _ = stream.set_nodelay(true);
    let _ = stream.set_read_timeout(Some(Duration::from_millis(READ_TIMEOUT_MS)));
    let mut stream = stream;
    let mut scratch = [0u8; READ_CHUNK_BYTES];
    let start = Instant::now();
    let mut buf: Vec<u8> = Vec::new();
    let mut prefix_checked = false;
    let mut parser: Option<FlvParser> = None;
    let mut pending_metadata: Option<StreamMetadata> = None;
    let mut counts = FrameCounts { keyframes: 0, interframes: 0 };

    loop {
        if shutdown.load(RELAXED) {
            break;
        }
        let chunk: &[u8] = match stream.read(&mut scratch) {
            Ok(0) => break,
            Ok(n) => &scratch[..n],
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => continue,
            Err(e) if e.kind() == io::ErrorKind::TimedOut => continue,
            Err(_) => break,
        };

        if let Some(ref mut p) = parser {
            match p.push(chunk) {
                Ok(events) => {
                    dispatch_events(events, &state, &logger, &mut pending_metadata, &mut counts);
                    // After an empty `Ok` the framer may be parked in `Resyncing` awaiting a `resync()` attempt (the prior push returned `Err` and resync found no boundary yet; more bytes have now arrived). Drive it here so recovery is prompt rather than waiting for the next error.
                    if p.is_resyncing() {
                        attempt_resync(p, &state, &logger, &mut pending_metadata, &mut counts);
                    }
                }
                Err(ParseError::ResyncBufferOverflow { len, cap }) => {
                    logger.log(Level::Warn, &format!("FLV resync buffer overflow ({len} > {cap}); dropping connection"));
                    break;
                }
                Err(err) => {
                    logger.log(Level::Warn, &format!("FLV framing error, resyncing: {err:?}"));
                    attempt_resync(p, &state, &logger, &mut pending_metadata, &mut counts);
                }
            }
            continue;
        }

        buf.extend_from_slice(chunk);

        if !prefix_checked {
            if buf.len() < UPFLV_PREFIX.len() {
                continue;
            }
            let consumed = buf.len() - detect_and_strip_prefix(&buf).len();
            buf.drain(..consumed);
            prefix_checked = true;
        }

        match parse_header(&buf) {
            Err(ParseError::Truncated) => continue,
            Err(err) => {
                logger.log(Level::Warn, &format!("FLV header parse error, dropping connection: {err:?}"));
                break;
            }
            Ok((remaining, _header)) => {
                let consumed = buf.len() - remaining.len();
                buf.drain(..consumed);
                let mut p = FlvParser::new();
                let events = match p.push(&buf) {
                    Ok(events) => events,
                    Err(ParseError::ResyncBufferOverflow { len, cap }) => {
                        logger.log(Level::Warn, &format!("FLV resync buffer overflow ({len} > {cap}); dropping connection"));
                        buf.clear();
                        break;
                    }
                    Err(err) => {
                        logger.log(Level::Warn, &format!("FLV framing error, resyncing: {err:?}"));
                        attempt_resync(&mut p, &state, &logger, &mut pending_metadata, &mut counts);
                        Vec::new()
                    }
                };
                buf.clear();
                dispatch_events(events, &state, &logger, &mut pending_metadata, &mut counts);
                parser = Some(p);
            }
        }
    }

    let elapsed = start.elapsed();
    let secs = elapsed.as_secs();
    logger.log(Level::Info, &format!("camera disconnected: {peer} ({secs}s, {} keyframes, {} interframes)", counts.keyframes, counts.interframes));
}

/// Drives one `FlvParser::resync` attempt and, on success, drains any buffered body the resync left ready for framing. The skipped-byte count is logged at `WARN` so a flapping or corrupting camera is visible in `flvproxy.log`; a `None` result (no plausible boundary yet) is silent — the caller feeds more bytes and retries on the next chunk. Never panics: `resync` and `push` are pure byte logic.
fn attempt_resync(p: &mut FlvParser, state: &StreamState, logger: &Logger, pending_metadata: &mut Option<StreamMetadata>, counts: &mut FrameCounts) {
    if let Some(skipped) = p.resync() {
        logger.log(Level::Warn, &format!("FLV resync: skipped {skipped} bytes"));
        if let Ok(extra) = p.push(&[]) {
            dispatch_events(extra, state, logger, pending_metadata, counts);
        }
    }
}

/// Per-connection running keyframe/inter-frame counters plus the count of frames since the last stats log line. Grouped so the dispatch helpers can borrow them together.
struct FrameCounts {
    keyframes: usize,
    interframes: usize,
}

/// Dispatches a batch of framed `TagEvent`s into `StreamState`. Video tags route through the video-tag dispatcher; `onMetaData` script tags merge their width/height/fps into the published codec (buffered ahead of the config if it has not arrived yet); audio and unknown tags are ignored.
fn dispatch_events(events: Vec<TagEvent>, state: &StreamState, logger: &Logger, pending_metadata: &mut Option<StreamMetadata>, counts: &mut FrameCounts) {
    for event in events {
        match event {
            TagEvent::Video { timestamp_ms, body } => dispatch_video(&body, timestamp_ms, state, logger, pending_metadata, counts),
            TagEvent::Script { body, .. } => {
                if is_metadata_tag(&body) {
                    if let Some(meta) = parse_on_metadata(&body) {
                        apply_metadata(state, logger, meta, pending_metadata);
                    }
                }
            }
            TagEvent::Audio { .. } | TagEvent::Unknown { .. } => {}
        }
    }
}

/// Dispatches one video-tag body through the standard/extended dispatcher and publishes the result: a `Config` updates the stream's codec parameters (merging any pending `onMetaData`); a `Frame` is published to all clients and counted. Sequence-end, metadata, and ignored tags are no-ops; a dispatcher `Codec` error is logged and the tag skipped — the framer stays aligned (the body was already framed), so the connection continues without resync.
fn dispatch_video(body: &[u8], timestamp_ms: u32, state: &StreamState, logger: &Logger, pending_metadata: &mut Option<StreamMetadata>, counts: &mut FrameCounts) {
    match parse_video_tag(body) {
        Ok(VideoTagEvent::Config(cfg)) => {
            let params = build_codec_params(&cfg, pending_metadata);
            state.publish_config(params);
        }
        Ok(VideoTagEvent::Frame(nalu_frame)) => {
            let frame = Frame { is_keyframe: nalu_frame.is_keyframe, timestamp_ms, nalus: nalu_frame.nalus };
            state.publish_frame(frame);
            if nalu_frame.is_keyframe {
                counts.keyframes += 1;
            } else {
                counts.interframes += 1;
            }
        }
        Ok(VideoTagEvent::SequenceEnd) | Ok(VideoTagEvent::Metadata) | Ok(VideoTagEvent::Ignored(_)) => {}
        Err(ParseError::Truncated) => {
            // Empty-body video tags (type=0x00 extendedFlv heartbeat/telemetry frames with dsize=0) hit this path. Silently skip — the parser already handled the trailer, and logging per-heartbeat spams the console.
        }
        Err(err) => logger.log(Level::Warn, &format!("video tag parse error, skipping tag: {err:?}")),
    }
}

/// Builds `CodecParams` from a decoded AVC config record, merging any `onMetaData`-derived width/height/fps that arrived ahead of the config.
fn build_codec_params(cfg: &AvcDecoderConfig, pending_metadata: &Option<StreamMetadata>) -> CodecParams {
    let (width, height, fps) = match pending_metadata {
        Some(meta) => (meta.width, meta.height, meta.fps),
        None => (None, None, None),
    };
    CodecParams { sps: cfg.sps.clone(), pps: cfg.pps.clone(), profile_indication: cfg.profile_indication, profile_compat: cfg.profile_compat, level_indication: cfg.level_indication, width, height, fps }
}

fn apply_metadata(state: &StreamState, _logger: &Logger, meta: StreamMetadata, pending: &mut Option<StreamMetadata>) {
    if let Some(identity) = crate::camera_identity::from_metadata(&meta) {
        state.publish_camera_identity(identity);
    }
    if let Some(codec) = state.codec() {
        let merged = merge_metadata_into_codec(codec, &meta);
        state.publish_config(merged);
    }
    *pending = Some(meta);
}

/// Returns `codec` with its width/height/fps replaced by `meta`'s values where `meta` declares one, keeping `codec`'s prior value otherwise.
fn merge_metadata_into_codec(mut codec: CodecParams, meta: &StreamMetadata) -> CodecParams {
    codec.width = meta.width.or(codec.width);
    codec.height = meta.height.or(codec.height);
    codec.fps = meta.fps.or(codec.fps);
    codec
}

// --------------------------------------------------------------------------- Production 7550 path ---------------------------------------------------------------------------

// The real 7550 camera-stream listener is just `CameraListener` itself: real-camera testing confirmed 7550 is plain TCP + bare FLV (no TLS, no WebSocket, no uPFLV prefix). `CameraListener::new(state, 7550, logger)` binds the production port; `run_connection` applies the socket options, calls `detect_and_strip_prefix` (a no-op when the stream starts with `FLV` instead of the uPFLV prefix), and feeds the bare FLV bytes directly to `FlvParser`. No separate Windows-only listener is needed — the cross-platform `CameraListener` handles both the SSH-bypass ingress path (uPFLV prefix) and the production 7550 path (bare FLV) with the same code.
