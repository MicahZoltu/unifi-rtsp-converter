//! Camera TCP listener and FLV pipeline (step 12). Binds the camera push
//! port, accepts a single active connection at a time (force-closing the
//! prior one when a new one arrives, per `PROJECT.md` → "TCP Listener"),
//! strips the uPFLV prefix, parses the FLV header, frames the tag stream, and
//! dispatches video/script tags into the shared `StreamState`.
//!
//! Pure networking + pipeline glue — all byte parsing lives in `flv_parser`,
//! `avc`, and `amf`. The listener never panics: every error path is logged
//! and either continues (resync is step 17) or drops the connection, keeping
//! the listener bound for a fresh camera connection. Cross-platform `std::net`
//! so it builds and tests on Linux.

use std::io::{self, Read};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use crate::amf::{is_metadata_tag, parse_on_metadata, StreamMetadata};
use crate::avc::AvcDecoderConfig;
use crate::flv_parser::{
    detect_and_strip_prefix, parse_header, parse_video_tag, FlvParser, ParseError, TagEvent,
    VideoTagEvent, UPFLV_PREFIX,
};
use crate::logging::{Level, Logger};
use crate::stream_state::{CodecParams, Frame, StreamState};

/// Relaxed ordering suffices for the shutdown flag: it is an advisory signal,
/// not synchronization that establishes happens-before for other data (the
/// `StreamState` mutex carries that burden). Mirrors `rtsp_server`'s
/// convention.
const RELAXED: Ordering = Ordering::Relaxed;

/// Poll interval for the non-blocking accept loop, so the `shutdown` flag is
/// checked promptly rather than blocking until the next connection. Matches
/// `rtsp_server`'s accept poll cadence.
const ACCEPT_POLL_MS: u64 = 50;

/// Per-read timeout on the camera connection. The read loop blocks on `read`
/// for at most this long before returning `TimedOut`, which lets the loop
/// re-check the `shutdown` flag and lets a force-closed connection's handler
/// exit promptly. The camera pushes continuously, so a healthy stream never
/// hits the timeout.
const READ_TIMEOUT_MS: u64 = 500;

/// Size of the per-read scratch buffer feeding the FLV framer.
const READ_CHUNK_BYTES: usize = 8192;

/// Frame-count logging interval: every Nth published frame logs the running
/// keyframe/inter totals, per `plan/12-tcp-listener-and-flv-pipeline.md` →
/// "Logging hooks".
const FRAME_STATS_LOG_INTERVAL: usize = 64;

/// Shutdown handle and shared-state surface for the camera accept loop. A
/// single instance owns the accept thread's flags and the slot holding the
/// currently-active connection (so a new connection can force-close it). The
/// camera thread and each RTSP session thread share the `StreamState` via a
/// cheap `Arc` clone.
pub struct CameraListener {
    state: StreamState,
    listen_port: u16,
    shutdown: Arc<AtomicBool>,
    logger: Arc<Logger>,
    current: Arc<Mutex<Option<TcpStream>>>,
}

impl CameraListener {
    /// Creates a listener that will bind `0.0.0.0:listen_port` for the camera
    /// and publish decoded config/frames into `state`. `logger` receives
    /// connection, SPS/PPS, frame-count, and parse-error lines.
    pub fn new(state: StreamState, listen_port: u16, logger: Arc<Logger>) -> CameraListener {
        CameraListener {
            state,
            listen_port,
            shutdown: Arc::new(AtomicBool::new(false)),
            logger,
            current: Arc::new(Mutex::new(None)),
        }
    }

    /// Binds the camera listener on `0.0.0.0:listen_port` and runs the accept
    /// loop until `shutdown()` is called.
    pub fn run(&self) -> io::Result<()> {
        let listener = TcpListener::bind(("0.0.0.0", self.listen_port))?;
        self.run_on(listener)
    }

    /// Runs the accept loop on a caller-supplied listener. Tests use this
    /// with an ephemeral loopback listener so they know the bound port;
    /// production `run()` delegates here after binding.
    pub fn run_on(&self, listener: TcpListener) -> io::Result<()> {
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

    /// Accepts a fresh camera connection: stores a clone in the active slot
    /// (so the next accept can force-close it), force-closes whatever
    /// connection was active before, and spawns a handler thread.
    fn spawn_handler(&self, stream: TcpStream) {
        let peer = stream.peer_addr().ok();
        let clone = match stream.try_clone() {
            Ok(c) => c,
            Err(_) => {
                self.logger.log(
                    Level::Warn,
                    "camera connection: could not clone stream; dropping",
                );
                return;
            }
        };
        let old = {
            let mut guard = self
                .current
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            guard.replace(clone)
        };
        if let Some(old) = old {
            let _ = old.shutdown(Shutdown::Both);
        }
        let peer_str = peer
            .map(|p| p.to_string())
            .unwrap_or_else(|| "<unknown>".to_string());
        self.logger
            .log(Level::Info, &format!("camera connected from {peer_str}"));
        let state = self.state.clone();
        let logger = self.logger.clone();
        let shutdown = self.shutdown.clone();
        thread::spawn(move || {
            handle_connection(stream, peer_str, state, logger, shutdown);
        });
    }

    /// Signals the accept loop and the active handler to exit, and
    /// force-closes the active connection so its blocked read returns
    /// immediately. Idempotent.
    pub fn shutdown(&self) {
        self.shutdown.store(true, RELAXED);
        let old = {
            let mut guard = self
                .current
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            guard.take()
        };
        if let Some(old) = old {
            let _ = old.shutdown(Shutdown::Both);
        }
    }

    /// Returns a clone of the shutdown flag so external code (the service
    /// wrapper in step 18, or tests) can stop the listener without holding a
    /// reference to the `CameraListener`. Setting the flag stops the accept
    /// loop on its next poll; the active handler exits on its next read
    /// timeout.
    pub fn shutdown_signal(&self) -> Arc<AtomicBool> {
        self.shutdown.clone()
    }
}

/// Per-connection running keyframe/inter-frame counters plus the count of
/// frames since the last stats log line. Grouped so the dispatch helpers can
/// borrow them together.
struct FrameCounts {
    keyframes: usize,
    interframes: usize,
    since_log: usize,
}

/// Handles one camera TCP connection to completion: strips the uPFLV prefix,
/// parses the FLV header, frames the tag stream, and dispatches video/script
/// tags into `StreamState`. Returns when the peer closes, the `shutdown` flag
/// is set, or a read fails; in every case the connection is simply dropped —
/// the listener stays bound for a fresh camera connection.
fn handle_connection(
    mut stream: TcpStream,
    peer: String,
    state: StreamState,
    logger: Arc<Logger>,
    shutdown: Arc<AtomicBool>,
) {
    let _ = stream.set_nodelay(true);
    let _ = stream.set_read_timeout(Some(Duration::from_millis(READ_TIMEOUT_MS)));

    let mut buf: Vec<u8> = Vec::new();
    let mut chunk = [0u8; READ_CHUNK_BYTES];
    let mut prefix_checked = false;
    let mut parser: Option<FlvParser> = None;
    let mut pending_metadata: Option<StreamMetadata> = None;
    let mut counts = FrameCounts {
        keyframes: 0,
        interframes: 0,
        since_log: 0,
    };

    loop {
        if shutdown.load(RELAXED) {
            break;
        }
        let n = match stream.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => continue,
            Err(e) if e.kind() == io::ErrorKind::TimedOut => continue,
            Err(_) => break,
        };

        if let Some(ref mut p) = parser {
            match p.push(&chunk[..n]) {
                Ok(events) => {
                    dispatch_events(events, &state, &logger, &mut pending_metadata, &mut counts)
                }
                Err(err) => logger.log(
                    Level::Warn,
                    &format!("FLV framing error, continuing: {err:?}"),
                ),
            }
            continue;
        }

        buf.extend_from_slice(&chunk[..n]);

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
                logger.log(
                    Level::Warn,
                    &format!("FLV header parse error, dropping connection: {err:?}"),
                );
                break;
            }
            Ok((remaining, _header)) => {
                let consumed = buf.len() - remaining.len();
                buf.drain(..consumed);
                let mut p = FlvParser::new();
                let events = match p.push(&buf) {
                    Ok(events) => events,
                    Err(err) => {
                        logger.log(
                            Level::Warn,
                            &format!("FLV framing error, continuing: {err:?}"),
                        );
                        Vec::new()
                    }
                };
                buf.clear();
                dispatch_events(events, &state, &logger, &mut pending_metadata, &mut counts);
                parser = Some(p);
            }
        }
    }

    logger.log(Level::Info, &format!("camera connection closed: {peer}"));
}

/// Dispatches a batch of framed `TagEvent`s into `StreamState`. Video tags
/// route through the step-05 dispatcher; `onMetaData` script tags merge their
/// width/height/fps into the published codec (buffered ahead of the config if
/// it has not arrived yet); audio and unknown tags are ignored.
fn dispatch_events(
    events: Vec<TagEvent>,
    state: &StreamState,
    logger: &Logger,
    pending_metadata: &mut Option<StreamMetadata>,
    counts: &mut FrameCounts,
) {
    for event in events {
        match event {
            TagEvent::Video { timestamp_ms, body } => {
                dispatch_video(&body, timestamp_ms, state, logger, pending_metadata, counts)
            }
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

/// Dispatches one video-tag body through the standard/extended dispatcher and
/// publishes the result: a `Config` updates the stream's codec parameters
/// (merging any pending `onMetaData`); a `Frame` is published to all clients
/// and counted. Sequence-end, metadata, and ignored tags are no-ops; a
/// dispatcher error is logged and the connection is left intact (full resync
/// is step 17).
fn dispatch_video(
    body: &[u8],
    timestamp_ms: u32,
    state: &StreamState,
    logger: &Logger,
    pending_metadata: &mut Option<StreamMetadata>,
    counts: &mut FrameCounts,
) {
    match parse_video_tag(body) {
        Ok(VideoTagEvent::Config(cfg)) => {
            log_sps_pps(logger, &cfg);
            let params = build_codec_params(&cfg, pending_metadata);
            state.publish_config(params);
        }
        Ok(VideoTagEvent::Frame(nalu_frame)) => {
            let frame = Frame {
                is_keyframe: nalu_frame.is_keyframe,
                timestamp_ms,
                nalus: nalu_frame.nalus,
            };
            state.publish_frame(frame);
            if nalu_frame.is_keyframe {
                counts.keyframes += 1;
            } else {
                counts.interframes += 1;
            }
            counts.since_log += 1;
            if counts.since_log >= FRAME_STATS_LOG_INTERVAL {
                counts.since_log = 0;
                logger.log(
                    Level::Info,
                    &format!(
                        "frame stats: keyframes={} interframes={}",
                        counts.keyframes, counts.interframes
                    ),
                );
            }
        }
        Ok(VideoTagEvent::SequenceEnd)
        | Ok(VideoTagEvent::Metadata)
        | Ok(VideoTagEvent::Ignored(_)) => {}
        Err(err) => logger.log(
            Level::Warn,
            &format!("video tag parse error, skipping tag: {err:?}"),
        ),
    }
}

/// Builds `CodecParams` from a decoded AVC config record, merging any
/// `onMetaData`-derived width/height/fps that arrived ahead of the config.
fn build_codec_params(
    cfg: &AvcDecoderConfig,
    pending_metadata: &Option<StreamMetadata>,
) -> CodecParams {
    let (width, height, fps) = match pending_metadata {
        Some(meta) => (meta.width, meta.height, meta.fps),
        None => (None, None, None),
    };
    CodecParams {
        sps: cfg.sps.clone(),
        pps: cfg.pps.clone(),
        profile_indication: cfg.profile_indication,
        profile_compat: cfg.profile_compat,
        level_indication: cfg.level_indication,
        width,
        height,
        fps,
    }
}

/// Records `meta` as the latest `onMetaData` and, if a codec is already
/// published, republishes it with the metadata merged in (metadata takes
/// precedence over any prior value). If no config has arrived yet, the
/// metadata is buffered and applied when the config arrives.
fn apply_metadata(
    state: &StreamState,
    logger: &Logger,
    meta: StreamMetadata,
    pending: &mut Option<StreamMetadata>,
) {
    *pending = Some(meta);
    if let Some(codec) = state.codec() {
        let merged = merge_metadata_into_codec(codec, &meta);
        logger.log(
            Level::Info,
            &format!(
                "onMetaData: width={:?} height={:?} fps={:?}",
                merged.width, merged.height, merged.fps
            ),
        );
        state.publish_config(merged);
    }
}

/// Returns `codec` with its width/height/fps replaced by `meta`'s values
/// where `meta` declares one, keeping `codec`'s prior value otherwise.
fn merge_metadata_into_codec(mut codec: CodecParams, meta: &StreamMetadata) -> CodecParams {
    codec.width = meta.width.or(codec.width);
    codec.height = meta.height.or(codec.height);
    codec.fps = meta.fps.or(codec.fps);
    codec
}

/// Logs SPS/PPS arrival with profile and level, per
/// `plan/12-tcp-listener-and-flv-pipeline.md` → "Logging hooks" and the
/// step-12 human-test pass criteria (`SPS received: profile=4D level=1F`).
fn log_sps_pps(logger: &Logger, cfg: &AvcDecoderConfig) {
    logger.log(
        Level::Info,
        &format!(
            "SPS received: profile={:02X} level={:02X}",
            cfg.profile_indication, cfg.level_indication
        ),
    );
    logger.log(
        Level::Info,
        &format!("PPS received: {} bytes", cfg.pps.len()),
    );
}
