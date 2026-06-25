//! UniFi Protect AVClient JSON protocol over the 7442 WebSocket channel. This is stage 3–4 of the Protect flow: after the camera completes the RFC 6455 + TLS handshake, it speaks a JSON-over-binary-WS-frame protocol with a `from`/`to`/`functionName`/`messageId`/`inResponseTo`/`payload`/`responseExpected`/`timestamp` envelope.
//!
//! What this module owns:
//! - A minimal, hand-rolled JSON parser/emitter (private `json` submodule) covering only the shapes the AVClient protocol uses (objects, arrays, strings, integers, floats, bools, null). Per the project's zero-crates constraint, no `serde_json`. The subset is bounded to this protocol's shapes and is not silently expanded by pulling a crate.
//! - `ControllerMessage`: the parsed envelope, plus accessors for the fields handlers and tests need.
//! - `AvClientSession<RW>`: a post-handshake session that loops `ws::parse_frame` → dispatch → `ws::encode_frame` until a clean close, answering each camera message with a controller reply and answering the UniFi `ping-<N>` keepalive with a `pong-<N>` text frame.
//!
//! What this module does **not** own (by design):
//! - The 7550 uPFLV ingestion.
//! - Wiring into `console_main`.
//! - The TLS transport or the WS opening handshake — `AvClientSession` is constructed on an already-upgraded stream.
//! - UDP 10001 discovery (out of scope per project decision; the proxy is camera-push-driven, not discovered).
//!
//! # Why `AvClientSession` uses `ws::parse_frame`/`ws::encode_frame` directly
//!
//! The camera's UniFi keepalive is a WS **Ping** control frame (opcode `0x9`) carrying the text payload `ping-<N>`, and it must be answered with a WS **Text** frame `pong-<N>` — *not* a WS Pong control frame (real-camera recon ground truth). `ws::WsConnection::read_frame` auto-replies to a Ping with a Pong and swallows the Ping, which would both answer incorrectly and hide the keepalive from this layer. The lower-level `pub` `ws::parse_frame` / `ws::encode_frame` functions are the intended escape hatch and give this session full control of control-frame handling, so `AvClientSession` calls them directly instead of owning a `WsConnection`. This is the settled design (confirmed at the ONVIF cluster review): growing a "surface Pings / custom-pong" mode onto `WsConnection` would push one protocol's keepalive quirk into the general framing layer for no other caller's benefit.

use std::io::{Read, Write};
use std::sync::Arc;

use crate::calendar::civil_from_days;
use crate::json;
use crate::logging::{Level, Logger};
use crate::ws::{encode_frame, parse_frame, Opcode, WsError, WsFrame};

/// One observed frame for diagnostic tracing (recon / debugging). `AvClientSession::with_tracer` installs a callback that receives one of these for every frame read from or written to the wire, so the recon tool can hex-dump / log the exact AVClient exchange without touching the session's dispatch logic. Production code passes `None` (no overhead).
#[derive(Debug, Clone)]
pub struct FrameTrace {
    /// `In` = read from the peer; `Out` = written by the session.
    pub direction: FrameDirection,
    /// The WS opcode of the frame (Binary = JSON AVClient message, Ping/Pong = keepalive, Text = `ping-<N>`/`pong-<N>`, Close = shutdown).
    pub opcode: Opcode,
    /// The frame payload bytes (unmasked, as the session sees them).
    pub payload: Vec<u8>,
}

/// Direction of a traced frame.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum FrameDirection {
    /// Read from the peer (camera → controller).
    In,
    /// Written by the session (controller → camera).
    Out,
}

/// `from` field the controller advertises in its replies. The camera addresses its messages `to: "UniFiVideo"` (real-camera recon), so the controller's `from` is the same token.
const CONTROLLER_FROM: &str = "UniFiVideo";

/// `to` field the controller addresses its replies to — the camera's own `from` token (real-camera recon).
const AVCLIENT_TO: &str = "ubnt_avclient";

/// First `messageId` the controller emits for its own replies. Mono tonic from here; the camera's `messageId` is echoed only via `inResponseTo`.
const FIRST_CONTROLLER_MESSAGE_ID: u64 = 1;

/// `status` text carried in a generic ok reply payload.
const OK_STATUS_TEXT: &str = "ok";

/// `statusCode` value carried in a generic ok reply payload (0 = success).
const OK_STATUS_CODE: u64 = 0;

/// `protocolVersion` echoed back in a `hello` reply when the camera's hello payload omits the field. The real Protect controller echoes the camera's own `protocolVersion` verbatim (`service.js` `ubntAvclientHello`: `t.respond(r, { protocolVersion: g.protocolVersion, ... })`); this default only covers a hello payload that lacks the field, which the G5 camera does not send in practice. Confirmed against the Protect 7.1.77 Node.js source (extracted from the public `.deb`).
pub const HELLO_PROTOCOL_VERSION: u64 = 67;

/// JSON envelope field names, used by both the parser and the emitter so the two directions cannot drift apart.
const FIELD_FROM: &str = "from";
const FIELD_TO: &str = "to";
const FIELD_FUNCTION_NAME: &str = "functionName";
const FIELD_MESSAGE_ID: &str = "messageId";
const FIELD_IN_RESPONSE_TO: &str = "inResponseTo";
const FIELD_PAYLOAD: &str = "payload";
const FIELD_RESPONSE_EXPECTED: &str = "responseExpected";
const FIELD_TIMESTAMP: &str = "timeStamp";

/// `timeSync` reply payload field: the controller's current time.
const FIELD_T1: &str = "t1";
/// `timeSync` reply payload field: the controller's current time.
const FIELD_T2: &str = "t2";

/// Generic ok reply payload fields.
const FIELD_STATUS_CODE: &str = "statusCode";
const FIELD_STATUS: &str = "status";
const FIELD_DEVICE_ID: &str = "deviceID";

/// `hello` reply payload fields. The real Protect controller's `hello` reply carries the controller identity (`controllerName`/`controllerUuid`/`controllerVersion`) plus an echoed `protocolVersion` and `overrideUuid: true` — NOT a `features` map (ground truth (Protect 7.1.77 source): `service.js` `ubntAvclientHello` → `t.respond(r, {protocolVersion: g.protocolVersion, controllerName, controllerUuid, controllerVersion, overrideUuid: true}, false)`). The prior `features`-map shape was a redalert-baseline guess that left the camera's adoption state machine incomplete, causing the ~7-10s reconnect cycle.
const FIELD_PROTOCOL_VERSION: &str = "protocolVersion";
const FIELD_CONTROLLER_NAME: &str = "controllerName";
const FIELD_CONTROLLER_UUID: &str = "controllerUuid";
const FIELD_CONTROLLER_VERSION: &str = "controllerVersion";
const FIELD_OVERRIDE_UUID: &str = "overrideUuid";

/// Default controller identity advertised in the `hello` reply when no override is configured. The real Protect controller sources these from the NVR record (`a.name`, `a.anonymousDeviceId`, `a.version`); these defaults give the proxy a well-formed identity so the camera's adoption completes without operator configuration. `DEFAULT_CONTROLLER_UUID` is a fixed valid RFC-4122 v4 UUID (the real controller generates a per-install `anonymousDeviceId`; a fixed default is fine because the camera stores it rather than validating uniqueness). `DEFAULT_CONTROLLER_VERSION` matches the Protect package version confirmed against the Protect 7.1.77 Node.js source.
pub const DEFAULT_CONTROLLER_NAME: &str = "UniFi Protect";
pub const DEFAULT_CONTROLLER_UUID: &str = "716dd84e-a640-45d7-9c17-2b9b4b8a7000";
pub const DEFAULT_CONTROLLER_VERSION: &str = "7.1.77";

/// `ChangeVideoSettings` payload field names (ground truth (Protect 7.1.77 source): `service.js` `pushStream` non-UCP4 path). The controller sends this controller-initiated command to tell the camera where to push its extendedFlv stream; the camera dials the `avSerializer.destinations` URI only for streams whose `avSerializer.type == "extendedFlv"` and whose `destinations` is a non-empty list.
const FIELD_VIDEO: &str = "video";
const FIELD_AV_SERIALIZER: &str = "avSerializer";
const FIELD_DESTINATIONS: &str = "destinations";
const FIELD_PARAMETERS: &str = "parameters";
const FIELD_STREAM_NAME: &str = "streamName";
const FIELD_WITH_OPUS: &str = "withOpus";
const FIELD_OPUS_SAMPLE_RATE: &str = "opusSampleRate";
const FIELD_TYPE: &str = "type";

/// Video codec label the controller advertises on each `ChangeVideoSettings` video channel (`type` field). Ground truth (Protect 7.1.77 source): `service.js` uses `VideoCodecLabel.H264 = "h264"`. The proxy only supports H.264 (per `PROJECT.md` — audio is ignored, no other codec is parsed), so this is a fixed constant rather than per-camera state.
const VIDEO_CODEC_H264: &str = "h264";

/// Opus sample rate (Hz) the controller advertises in `ChangeVideoSettings` `avSerializer.parameters.opusSampleRate`. Ground truth (Protect 7.1.77 source): `service.js` `OPUS_SAMPLE_RATE_HZ = { DEFAULT: 24e3, EDGE: 16e3 }`, and `getOpusSampleRate` returns `DEFAULT` for non-Edge cameras (the G5 Bullet is not an Edge model). Audio is ignored downstream (FLV audio tags are skipped per `PROJECT.md`), but the field is sent to match the real controller's payload so the camera's adoption state machine completes.
const OPUS_SAMPLE_RATE_HZ_DEFAULT: u64 = 24_000;

/// AVClient `functionName` values this module dispatches specifically. All other names fall through to the generic ok reply. The `ubnt_avclient_` prefixed forms are the camera-confirmed shapes (real-camera recon); the bare forms are accepted defensively (redalert baseline).
const FN_TIMESYNC: &str = "timeSync";
const FN_TIMESYNC_FULL: &str = "ubnt_avclient_timeSync";
const FN_HELLO: &str = "hello";
const FN_HELLO_FULL: &str = "ubnt_avclient_hello";

/// Controller→camera command that configures the camera's video stream destinations. The payload shape is reverse-engineered from the redalert reference implementation, not yet confirmed against a live camera capture. Sending it with an `extendedFlv` `avSerializer` whose `destinations` points at `tcp://<controller>:7550` is what makes the camera open the 7550 streaming channel.
const FN_CHANGE_VIDEO_SETTINGS: &str = "ChangeVideoSettings";

/// Controller→camera parameter-agreement command (redalert baseline). The controller sends this to negotiate protocol features (status codes, heartbeats) before driving adoption forward. Real-camera testing showed the camera ignores `ChangeVideoSettings` sent immediately after `timeSync` and stays in a `timeSync` liveness loop; the redalert sequence sends `paramAgreement` ahead of `ChangeVideoSettings`, so the adoption driver now sends `paramAgreement` first.
const FN_PARAM_AGREEMENT: &str = "ubnt_avclient_paramAgreement";

/// `paramAgreement` payload field: whether the controller uses numeric status codes in replies (redalert baseline).
const FIELD_ENABLE_STATUS_CODES: &str = "enableStatusCodes";
/// `paramAgreement` payload field: whether to use WS-level heartbeats (redalert baseline; the camera's `ping-0` keepalive is handled separately).
const FIELD_USE_HEARTBEATS: &str = "useHeartbeats";
/// `paramAgreement` payload field: heartbeat timeout in milliseconds (ground truth (Protect 7.1.77 source): `service.js` sends `heartbeatsTimeoutMs: 6e4` — 60000 ms — alongside `useHeartbeats: false`).
const FIELD_HEARTBEATS_TIMEOUT_MS: &str = "heartbeatsTimeoutMs";

/// `paramAgreement` `heartbeatsTimeoutMs` value the controller advertises. Ground truth (Protect 7.1.77 source): the real Protect controller sends `60000` (not the prior redalert-baseline `10000`); with `useHeartbeats: false` the camera does not run a 10s AVClient-application watchdog, so the prior `10000` was both wrong and the basis for the failed 2s `timeSync` heartbeat experiments. The real liveness mechanism is the controller's 15s WS Ping (see [`build_heartbeat_frame`]).
const HEARTBEATS_TIMEOUT_MS: u64 = 60_000;

/// The extendedFlv serializer type label, per redalert's `DEFAULT_CHANGE_VIDEO_PAYLOAD` (`avSerializer.type == "extendedFlv"`). Only streams with this type and a non-empty `destinations` are pushed.
const SERIALIZER_TYPE_EXTFLV: &str = "extendedFlv";

/// Failures that can abort an [`AvClientSession::run`]. A malformed JSON frame is **not** fatal — the session skips it and continues; only WebSocket-level errors and a peer reset propagate.
#[derive(Debug)]
pub enum AvClientError {
    /// A WebSocket framing / I/O error from the underlying stream.
    Ws(WsError),
    /// A frame's payload was not valid JSON. Surfaced only by [`ControllerMessage::parse`]; `run` skips such frames instead of propagating this.
    MalformedJson,
}

impl From<WsError> for AvClientError {
    fn from(e: WsError) -> AvClientError {
        AvClientError::Ws(e)
    }
}

impl std::fmt::Display for AvClientError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AvClientError::Ws(e) => write!(f, "WebSocket error in AVClient session: {e}"),
            AvClientError::MalformedJson => f.write_str("malformed AVClient JSON frame"),
        }
    }
}

impl std::error::Error for AvClientError {}

/// A monotonic wall-clock used to stamp replies (`timestamp`, `t1`, `t2`). Injected so unit/integration tests can pin the clock for byte-exact replies; the production path supplies `system_now_ms`.
pub type Clock = Box<dyn Fn() -> u64 + Send + Sync>;

/// Returns the current Unix time in milliseconds. The default clock for [`AvClientSession::new`]; falls back to `0` if the system clock is before the epoch (cannot happen in practice).
fn system_now_ms() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0)
}

/// A parsed AVClient envelope. The payload is retained as a [`json::Json`] value so handlers and tests can read nested fields; the envelope fields the dispatcher needs are extracted eagerly.
#[derive(Debug)]
pub struct ControllerMessage {
    from: String,
    to: String,
    function_name: String,
    message_id: u64,
    in_response_to: u64,
    response_expected: bool,
    payload: json::Json,
}

impl ControllerMessage {
    /// Parses one AVClient JSON frame payload into a [`ControllerMessage`]. Missing fields default to empty/zero/false so a partial-but-valid JSON object never aborts the session; only syntactically invalid JSON yields [`AvClientError::MalformedJson`].
    pub fn parse(bytes: &[u8]) -> Result<ControllerMessage, AvClientError> {
        let value = json::parse(bytes).map_err(|_| AvClientError::MalformedJson)?;
        Ok(Self::from_json(&value))
    }

    /// Builds a [`ControllerMessage`] from a parsed JSON value, applying per-field defaults for anything absent or the wrong type.
    fn from_json(value: &json::Json) -> ControllerMessage {
        let string_field = |key: &str| value.get(key).and_then(json::Json::as_str).unwrap_or("").to_string();
        let number_field = |key: &str| value.get(key).and_then(json::Json::as_u64).unwrap_or(0);
        let bool_field = |key: &str| value.get(key).and_then(json::Json::as_bool).unwrap_or(false);
        let payload = value.get(FIELD_PAYLOAD).cloned().unwrap_or(json::Json::Null);
        ControllerMessage { from: string_field(FIELD_FROM), to: string_field(FIELD_TO), function_name: string_field(FIELD_FUNCTION_NAME), message_id: number_field(FIELD_MESSAGE_ID), in_response_to: number_field(FIELD_IN_RESPONSE_TO), response_expected: bool_field(FIELD_RESPONSE_EXPECTED), payload }
    }

    pub fn function_name(&self) -> &str {
        &self.function_name
    }

    /// The sender's `from` token (e.g. `ubnt_avclient`).
    pub fn from(&self) -> &str {
        &self.from
    }

    /// The `to` token the message was addressed to (e.g. `UniFiVideo`).
    pub fn to(&self) -> &str {
        &self.to
    }

    /// The camera's `messageId`; echoed as `inResponseTo` in the reply.
    pub fn message_id(&self) -> u64 {
        self.message_id
    }

    pub fn in_response_to(&self) -> u64 {
        self.in_response_to
    }

    pub fn response_expected(&self) -> bool {
        self.response_expected
    }

    pub fn payload_u64(&self, key: &str) -> Option<u64> {
        self.payload.get(key).and_then(json::Json::as_u64)
    }

    pub fn payload_str(&self, key: &str) -> Option<&str> {
        self.payload.get(key).and_then(json::Json::as_str)
    }
}

/// Sequential adoption state machine. The real Protect controller sends adoption messages one at a time, waiting for each camera ack before sending the next. Blasting all messages in one burst (the prior implementation) caused the camera to process them out of order and close the session after ~7s — the camera's state machine never reached steady state. Sequential adoption respects the camera's expected request→ack→request→ack cadence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AdoptionState {
    /// No stream destination configured; the session is purely reactive and never drives adoption.
    NotConfigured,
    /// Stream destination is set but `hello` has not been received yet. The adoption sequence cannot start until the camera completes the timeSync exchange and sends `hello`.
    WaitingForHello,
    /// `paramAgreement` has been sent; waiting for the camera's ack (carrying `authToken`, `responseExpected: false`, `inResponseTo` = our `paramAgreement` messageId). On receipt, send `ChangeVideoSettings`.
    WaitingForParamAgreementAck,
    /// Adoption complete. The session is in steady state; only heartbeats and reactive replies are sent. `ChangeVideoSettings` is sent fire-and-forget (`responseExpected: false`, ground truth (Protect 7.1.77 source)), so adoption is marked complete immediately after sending it — the controller does not wait for a camera ack.
    Adopted,
}

/// A post-handshake AVClient session over any `Read + Write` stream. Loops reading WS frames, dispatching JSON messages to handlers, and writing reply frames until the peer closes cleanly or a WebSocket-level error occurs.
///
/// On Linux the stream is a plain `TcpStream` (the loopback test path); on Windows the production listener substitutes the hand-rolled `tls_schannel::TlsStream` — the `Read + Write` bound is the only seam.
pub struct AvClientSession<RW> {
    rw: RW,
    device_id: String,
    next_message_id: u64,
    now_ms: Clock,
    ready: bool,
    /// Optional 7550 stream destination URI (`tcp://<controller_ip>:7550?retryInterval=1&connectTimeout=5`). When set, the session drives a sequential adoption sequence (`paramAgreement` → wait for ack → `ChangeVideoSettings` → wait for ack → adopted) after `hello`. `None` ⇒ the session is purely reactive.
    stream_destination: Option<String>,
    /// Optional `streamName` for the `ChangeVideoSettings` payload, conventionally `<MAC_NO_COLONS>_<idx>` (redalert `_apply_camera_identity_to_video_payload`). `None` ⇒ `DEFAULT_0`.
    stream_name: Option<String>,
    /// Sequential adoption state machine. Replaces the prior `stream_announced: bool` which blasted all adoption messages in one burst.
    adoption_state: AdoptionState,
    /// The `messageId` of the last controller-initiated adoption message we sent, so we can match the camera's ack by `inResponseTo`. Used by the adoption ack interceptor to confirm which ack we're waiting for before advancing the state machine.
    pending_adoption_msg_id: u64,
    /// True once the camera has sent `hello` (the post-timeSync handshake advancement). The adoption driver fires after this, not after `timeSync` — confirmed by real-camera testing: sending the adoption sequence right after `timeSync` caused the camera to reset, while waiting for `hello` let the handshake complete.
    hello_received: bool,
    /// Controller identity advertised in the `hello` reply payload (`controllerName`/`controllerUuid`/`controllerVersion`). The real Protect controller sends these from the NVR record (`service.js` `ubntAvclientHello`: `controllerName: a.name`, `controllerUuid: a.anonymousDeviceId`, `controllerVersion: a.version`); without them the camera's adoption state machine never completes and it tears down the 7442 session every ~7-10s. Defaults match the real controller's shape so a session constructed without [`with_controller_identity`] still produces a well-formed hello reply.
    controller_name: String,
    controller_uuid: String,
    controller_version: String,
    /// Optional frame tracer (recon / debugging). `None` in production.
    tracer: Option<Box<dyn FnMut(FrameTrace) + Send>>,
    /// Optional logger. When `Some`, swallowed events (malformed JSON frames, unhandled `functionName` values) are logged so they are visible to the operator rather than silently dropped. `None` in tests that assert byte-exact output without log side effects.
    logger: Option<Arc<Logger>>,
}

impl<RW: Read + Write> AvClientSession<RW> {
    /// Creates a session with the real wall-clock and `messageId` starting at [`FIRST_CONTROLLER_MESSAGE_ID`]. The production listener constructs the session on an already-upgraded TLS+WS stream.
    pub fn new(rw: RW, device_id: String) -> AvClientSession<RW> {
        Self::with_start_and_clock(rw, device_id, FIRST_CONTROLLER_MESSAGE_ID, Box::new(system_now_ms))
    }

    /// Creates a session with an explicit starting `messageId` and an injected clock. The test entry point: tests pin both for byte-exact replies.
    pub fn with_start_and_clock(rw: RW, device_id: String, start_message_id: u64, now_ms: Clock) -> AvClientSession<RW> {
        AvClientSession { rw, device_id, next_message_id: start_message_id, now_ms, ready: false, stream_destination: None, stream_name: None, adoption_state: AdoptionState::NotConfigured, pending_adoption_msg_id: 0, hello_received: false, controller_name: DEFAULT_CONTROLLER_NAME.to_string(), controller_uuid: DEFAULT_CONTROLLER_UUID.to_string(), controller_version: DEFAULT_CONTROLLER_VERSION.to_string(), tracer: None, logger: None }
    }

    /// Sets the controller identity (`controllerName`/`controllerUuid`/`controllerVersion`) advertised in the `hello` reply. The real Protect controller sources these from the NVR record; the production listener passes the configured identity through here so the camera's adoption state machine completes and the 7442 session stays alive. Builder-style; returns `self` for chaining off `new`.
    pub fn with_controller_identity(mut self, name: String, uuid: String, version: String) -> AvClientSession<RW> {
        self.controller_name = name;
        self.controller_uuid = uuid;
        self.controller_version = version;
        self
    }

    /// Installs a frame tracer that receives every frame read from or written to the wire. Builder-style; returns `self` for chaining. Used by the recon tool to log the exact AVClient exchange for diagnosis; production code leaves it unset (zero overhead — the `Option` is never read).
    pub fn with_tracer<F>(mut self, tracer: F) -> AvClientSession<RW>
    where
        F: FnMut(FrameTrace) + Send + 'static,
    {
        self.tracer = Some(Box::new(tracer));
        self
    }

    /// Installs a logger so swallowed events (malformed JSON frames, unhandled `functionName` values) are emitted to `flvproxy.log` rather than dropped silently. Builder-style; returns `self` for chaining off `new`. The production listener passes its logger through here; tests leave it unset to assert byte-exact output with no log side effects.
    pub fn with_logger(mut self, logger: Arc<Logger>) -> AvClientSession<RW> {
        self.logger = Some(logger);
        self
    }

    fn trace_out(&mut self, frame: &WsFrame) {
        if let Some(t) = self.tracer.as_mut() {
            t(FrameTrace { direction: FrameDirection::Out, opcode: frame.opcode, payload: frame.payload.clone() });
        }
    }

    fn trace_in(&mut self, frame: &WsFrame) {
        if let Some(t) = self.tracer.as_mut() {
            t(FrameTrace { direction: FrameDirection::In, opcode: frame.opcode, payload: frame.payload.clone() });
        }
    }

    /// Logs `msg` at `level` when a logger is attached; a no-op otherwise so tests pay no log overhead.
    fn log(&self, level: Level, msg: &str) {
        if let Some(logger) = &self.logger {
            logger.log(level, msg);
        }
    }

    /// Configures the 7550 stream destination so the session sends a controller-initiated `ChangeVideoSettings` (telling the camera to push extendedFlv to `stream_destination`) once the `timeSync` exchange completes. `stream_name` is the `avSerializer.parameters.streamName` (conventionally `<MAC_NO_COLONS>_<idx>`). Builder-style; returns `self` for chaining off `new`. The payload shape is reverse-engineered from the redalert reference, not yet confirmed against a live camera capture.
    pub fn with_stream_destination(mut self, stream_destination: String, stream_name: Option<String>) -> AvClientSession<RW> {
        self.stream_destination = Some(stream_destination);
        self.stream_name = stream_name;
        self.adoption_state = AdoptionState::WaitingForHello;
        self
    }

    /// True once the session has answered a `timeSync` exchange — the recon-confirmed signal that the camera considers the handshake complete. Stays true for the life of the session.
    pub fn is_ready(&self) -> bool {
        self.ready
    }

    /// True once the `ChangeVideoSettings` command has been sent (or skipped because no stream destination was configured). Used by the recon log to confirm adoption-driving actually fired.
    pub fn change_video_settings_sent(&self) -> bool {
        matches!(self.adoption_state, AdoptionState::Adopted)
    }

    /// Runs the session until a clean peer close (returns `Ok(())`) or a WebSocket-level error (returns `Err`). Malformed JSON frames and unknown `functionName` values are skipped / best-effort-answered and never abort the loop.
    pub fn run(&mut self) -> Result<(), AvClientError> {
        loop {
            let frame = match parse_frame(&mut self.rw)? {
                Some(frame) => frame,
                None => return Ok(()),
            };
            self.trace_in(&frame);
            match frame.opcode {
                Opcode::Ping => self.handle_ping(frame.payload)?,
                Opcode::Pong => continue,
                Opcode::Close => {
                    let echo = WsFrame { fin: true, opcode: Opcode::Close, payload: frame.payload };
                    self.send_frame(&echo)?;
                    return Ok(());
                }
                Opcode::Text | Opcode::Binary => self.handle_data(frame.payload)?,
                Opcode::Continuation => continue,
            }
        }
    }

    /// Traces (if a tracer is installed) then encodes `frame` to the wire. Centralizes the trace-out + encode pattern so every outgoing frame is visible to the recon without each call site repeating the trace call.
    fn send_frame(&mut self, frame: &WsFrame) -> Result<(), AvClientError> {
        self.trace_out(frame);
        encode_frame(&mut self.rw, frame).map_err(AvClientError::from)
    }

    /// Answers a WS Ping with a WS Pong control frame echoing the payload, per RFC 6455 §5.5.2. Ground truth (Protect 7.1.77 source): the real Protect controller (using the `ws` npm library) auto-replies to WS Pings with a WS Pong only — it does NOT send a text `pong-<N>` frame (zero occurrences of `pong-` in the Protect 7.1.77 source). The prior text `pong-<N>` reply was a redalert-baseline invention: the camera received it as a Text data frame, tried to parse `pong-0` as AVClient JSON, failed, and tore down the 7442 session ~2s later — the root cause of the ~7s reconnect cycle observed in real-camera testing.
    fn handle_ping(&mut self, payload: Vec<u8>) -> Result<(), AvClientError> {
        let pong = WsFrame { fin: true, opcode: Opcode::Pong, payload };
        self.send_frame(&pong)
    }

    /// Handles a Text/Binary data frame. The payload is parsed as an AVClient JSON message and dispatched; unparseable JSON (or a non-JSON Text frame) is skipped (no reply, no crash).
    ///
    /// Sequential adoption: the adoption ack interceptor runs **before** the ack-skip filter. When we're waiting for the `paramAgreement` ack and the incoming message's `inResponseTo` matches the pending adoption messageId, we send `ChangeVideoSettings` (fire-and-forget, `responseExpected: false` per ground truth (Protect 7.1.77 source)) and mark adoption complete — all without replying to the ack (the ack has `responseExpected: false`, so no reply is needed). This respects the camera's request→ack→request cadence instead of blasting all adoption messages in one burst.
    fn handle_data(&mut self, payload: Vec<u8>) -> Result<(), AvClientError> {
        let request = match ControllerMessage::parse(&payload) {
            Ok(msg) => msg,
            Err(_) => {
                self.log(Level::Warn, "avclient: malformed json frame, skipping");
                return Ok(());
            }
        };

        // Sequential adoption ack interception: check if this message is the paramAgreement ack we're waiting for BEFORE the ack-skip filter drops it. The ack carries `responseExpected: false` and `inResponseTo` = our pending adoption messageId. Matching by `inResponseTo` is sufficient — the camera's messageIds are in a different counter space, so collision is impossible.
        if matches!(self.adoption_state, AdoptionState::WaitingForParamAgreementAck) && request.in_response_to == self.pending_adoption_msg_id {
            self.send_change_video_settings()?;
            self.adoption_state = AdoptionState::Adopted;
            return Ok(());
        }

        // Skip replying to pure acks: camera responses to our commands that carry `responseExpected: false` AND `inResponseTo != 0` (e.g. the `paramAgreement` ack with an `authToken`, a stray `ChangeVideoSettings` ack). Replying to those creates an infinite loop — the camera treats an incoming `paramAgreement` ok as a new negotiation and responds with a fresh authToken, which we ack again, ~5×/s until the session dies.
        //
        // New requests (`timeSync`, `hello`) and unsolicited events (`EventPoorNetwork`, `EventStreamChanged`, …) are still replied to: `timeSync` carries `responseExpected: true` (it is a request that happens to chain on our previous reply's messageId, so its `inResponseTo` is nonzero but it still demands an answer), and events carry `inResponseTo: 0`. The redalert baseline acks events and the prior human test confirmed that is harmless.
        if !request.response_expected && request.in_response_to != 0 {
            return Ok(());
        }
        let reply = self.dispatch(&request);
        let reply_bytes = json::emit(&reply).into_bytes();
        let reply_frame = WsFrame { fin: true, opcode: Opcode::Binary, payload: reply_bytes };
        self.send_frame(&reply_frame)?;

        // Drive sequential adoption: when `hello` is received and we're in `WaitingForHello` state, send `paramAgreement` and transition to `WaitingForParamAgreementAck`. The `ChangeVideoSettings` will be sent when the `paramAgreement` ack arrives (intercepted above).
        if self.hello_received && matches!(self.adoption_state, AdoptionState::WaitingForHello) {
            self.send_param_agreement()?;
            self.adoption_state = AdoptionState::WaitingForParamAgreementAck;
        }
        Ok(())
    }

    /// Sends a controller-initiated `paramAgreement` command (not a reply — `inResponseTo: 0`, fresh `messageId`, `responseExpected: true`) that negotiates protocol features with the camera. Real-camera testing showed the camera ignores `ChangeVideoSettings` when sent immediately after `timeSync` (it keeps looping on timeSync); the redalert sequence sends `paramAgreement` first, so the adoption driver sends it before `ChangeVideoSettings`. Payload (`enableStatusCodes: true`, `useHeartbeats: false`, `heartbeatsTimeoutMs: 60000`) is ground truth (Protect 7.1.77 source) (`service.js`: `e.send("ubnt_avclient_paramAgreement", {enableStatusCodes: true, useHeartbeats: false, heartbeatsTimeoutMs: 6e4}, ...)`); the prior `10000` was a redalert-baseline guess.
    fn send_param_agreement(&mut self) -> Result<(), AvClientError> {
        self.send_controller_message(FN_PARAM_AGREEMENT, json::obj(&[(FIELD_ENABLE_STATUS_CODES, json::bool_v(true)), (FIELD_USE_HEARTBEATS, json::bool_v(false)), (FIELD_HEARTBEATS_TIMEOUT_MS, json::uint(HEARTBEATS_TIMEOUT_MS))]), true)
    }

    /// Sends a controller-initiated `ChangeVideoSettings` command (not a reply — `inResponseTo: 0`, fresh `messageId`, `responseExpected: false` per ground truth (Protect 7.1.77 source): `service.js` `pushStream` publishes with `!1`) whose payload contains one `extendedFlv` H.264 video stream pointing at the configured 7550 destination. This is the message that makes the camera dial 7550 and push uPFLV. Payload shape is ground truth (Protect 7.1.77 source) (`service.js` `pushStream` non-UCP4 path): the video channel carries `avSerializer` plus a top-level `type: "h264"` (the codec), and `avSerializer.parameters` carries `streamName`/`withOpus`/`opusSampleRate` (not the prior redalert-baseline `withTalkback`).
    fn send_change_video_settings(&mut self) -> Result<(), AvClientError> {
        let destination = self.stream_destination.clone().unwrap_or_default();
        let stream_name = self.stream_name.clone().unwrap_or_else(|| "DEFAULT_0".to_string());
        // { "video": { "video1": { "avSerializer": { "type": "extendedFlv", "parameters": { "streamName": "<name>", "withOpus": true, "opusSampleRate": 24000 }, "destinations": [ "<uri>" ] }, "type": "h264" } } }
        let av_serializer = json::obj(&[(FIELD_TYPE, json::str_v(SERIALIZER_TYPE_EXTFLV)), (FIELD_PARAMETERS, json::obj(&[(FIELD_STREAM_NAME, json::str_v(stream_name.as_str())), (FIELD_WITH_OPUS, json::bool_v(true)), (FIELD_OPUS_SAMPLE_RATE, json::uint(OPUS_SAMPLE_RATE_HZ_DEFAULT))])), (FIELD_DESTINATIONS, json::array(vec![json::str_v(destination.as_str())]))]);
        let video1 = json::obj(&[(FIELD_AV_SERIALIZER, av_serializer), (FIELD_TYPE, json::str_v(VIDEO_CODEC_H264))]);
        let payload = json::obj(&[(FIELD_VIDEO, json::obj(&[("video1", video1)]))]);
        self.send_controller_message(FN_CHANGE_VIDEO_SETTINGS, payload, false)
    }

    /// Sends one controller-initiated (unsolicited) AVClient command: builds the full envelope (`from`/`to`/`functionName`/`inResponseTo:0`/fresh `messageId`/`payload`/`responseExpected`/`timestamp`) around `payload`, emits it as a Binary WS frame, and writes it to the wire. `response_expected` is `true` for `paramAgreement` (the camera acks with an `authToken`) and `false` for `ChangeVideoSettings` (fire-and-forget, ground truth (Protect 7.1.77 source)). Stores the messageId in `pending_adoption_msg_id` so the sequential adoption ack interceptor can match the camera's reply by `inResponseTo`.
    fn send_controller_message(&mut self, function_name: &str, payload: json::Json, response_expected: bool) -> Result<(), AvClientError> {
        let message_id = self.next_message_id;
        self.next_message_id = self.next_message_id.wrapping_add(1);
        self.pending_adoption_msg_id = message_id;
        let now = (self.now_ms)();
        let message = json::obj(&[(FIELD_FROM, json::str_v(CONTROLLER_FROM)), (FIELD_FUNCTION_NAME, json::str_v(function_name)), (FIELD_IN_RESPONSE_TO, json::uint(0)), (FIELD_MESSAGE_ID, json::uint(message_id)), (FIELD_PAYLOAD, payload), (FIELD_RESPONSE_EXPECTED, json::bool_v(response_expected)), (FIELD_TIMESTAMP, json::str_v(&format_iso8601_utc(now))), (FIELD_TO, json::str_v(AVCLIENT_TO))]);
        let frame = WsFrame { fin: true, opcode: Opcode::Binary, payload: json::emit(&message).into_bytes() };
        self.send_frame(&frame)
    }

    /// Builds the full reply envelope for `request`: the handler-specific `payload` wrapped in the `from`/`to`/`functionName`/`messageId`/`inResponseTo`/`responseExpected`/`timestamp` envelope, with `inResponseTo` echoing the request's `messageId` and a fresh mono tonic `messageId`.
    fn dispatch(&mut self, request: &ControllerMessage) -> json::Json {
        let payload = self.handler_payload(request);
        let message_id = self.next_message_id;
        self.next_message_id = self.next_message_id.wrapping_add(1);
        let now = (self.now_ms)();
        json::obj(&[(FIELD_FROM, json::str_v(CONTROLLER_FROM)), (FIELD_FUNCTION_NAME, json::str_v(request.function_name.as_str())), (FIELD_IN_RESPONSE_TO, json::uint(request.message_id)), (FIELD_MESSAGE_ID, json::uint(message_id)), (FIELD_PAYLOAD, payload), (FIELD_RESPONSE_EXPECTED, json::bool_v(false)), (FIELD_TIMESTAMP, json::str_v(&format_iso8601_utc(now))), (FIELD_TO, json::str_v(AVCLIENT_TO))])
    }

    /// Selects the handler-specific payload for `request` and updates session state (e.g. `ready`). `timeSync` is the only camera-confirmed handler; `hello` returns the controller-identity payload (ground truth (Protect 7.1.77 source)); every other name — including the redalert-baseline `paramAgreement` / `getSystemStats` / `updateFirmwareRequest` / `stopService` / `enableLogging` — falls through to a uniform generic ok reply.
    fn handler_payload(&mut self, request: &ControllerMessage) -> json::Json {
        match request.function_name.as_str() {
            FN_TIMESYNC | FN_TIMESYNC_FULL => {
                self.ready = true;
                let now = (self.now_ms)();
                json::obj(&[(FIELD_T1, json::uint(now)), (FIELD_T2, json::uint(now))])
            }
            FN_HELLO | FN_HELLO_FULL => {
                self.hello_received = true;
                self.hello_payload(request)
            }
            _ => self.ok_payload(),
        }
    }

    /// The generic ok reply payload (`statusCode: 0, status: "ok", deviceID`). Uniform across all non-`timeSync`/non-`hello` handlers; the per-handler payload shapes are reverse-engineered from the redalert reference, not yet confirmed against a live camera capture.
    fn ok_payload(&self) -> json::Json {
        json::obj(&[(FIELD_STATUS_CODE, json::uint(OK_STATUS_CODE)), (FIELD_STATUS, json::str_v(OK_STATUS_TEXT)), (FIELD_DEVICE_ID, json::str_v(self.device_id.as_str()))])
    }

    /// The `hello` reply payload: the controller identity (`controllerName`/`controllerUuid`/`controllerVersion`), an echoed `protocolVersion` (the camera's own value from its hello payload, falling back to [`HELLO_PROTOCOL_VERSION`] if absent), and `overrideUuid: true`. Ground truth (Protect 7.1.77 source) (`service.js` `ubntAvclientHello`: `t.respond(r, {protocolVersion: g.protocolVersion, controllerName: a.name || "", controllerUuid: a.anonymousDeviceId, controllerVersion: a.version, overrideUuid: true}, false)`). The prior `features`-map shape was a redalert-baseline guess that left the camera's adoption state machine incomplete — the root cause of the ~7-10s reconnect cycle.
    fn hello_payload(&self, request: &ControllerMessage) -> json::Json {
        let protocol_version = request.payload_u64(FIELD_PROTOCOL_VERSION).unwrap_or(HELLO_PROTOCOL_VERSION);
        json::obj(&[(FIELD_PROTOCOL_VERSION, json::uint(protocol_version)), (FIELD_CONTROLLER_NAME, json::str_v(self.controller_name.as_str())), (FIELD_CONTROLLER_UUID, json::str_v(self.controller_uuid.as_str())), (FIELD_CONTROLLER_VERSION, json::str_v(self.controller_version.as_str())), (FIELD_OVERRIDE_UUID, json::bool_v(true))])
    }
}

/// Formats `ms` (Unix milliseconds) as an ISO 8601 UTC string with millisecond precision and an explicit `+00:00` offset, matching the timestamp shape the camera sends (real-camera recon: `2026-06-19T15:52:59.817+00:00`). The date triple comes from the shared `calendar::civil_from_days`; the time-of-day and millisecond fields are computed inline from the intra-day millisecond remainder.
fn format_iso8601_utc(ms: u64) -> String {
    const MS_PER_SEC: u64 = 1_000;
    const MS_PER_MINUTE: u64 = 60 * MS_PER_SEC;
    const MS_PER_HOUR: u64 = 60 * MS_PER_MINUTE;
    const MS_PER_DAY: u64 = 24 * MS_PER_HOUR;

    let days = (ms / MS_PER_DAY) as i64;
    let rem = ms % MS_PER_DAY;
    let (year, month, day) = civil_from_days(days);
    let hour = rem / MS_PER_HOUR;
    let minute = (rem / MS_PER_MINUTE) % 60;
    let second = (rem / MS_PER_SEC) % 60;
    let millis = rem % MS_PER_SEC;
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}.{millis:03}+00:00")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hello_protocol_version_fallback_is_the_redalert_baseline() {
        assert_eq!(HELLO_PROTOCOL_VERSION, 67);
    }

    #[test]
    fn heartbeats_timeout_ms_matches_protect_source() {
        assert_eq!(HEARTBEATS_TIMEOUT_MS, 60_000);
    }

    #[test]
    fn controller_message_defaults_missing_fields_without_failing() {
        let msg = ControllerMessage::parse(b"{}").expect("empty object is structurally valid JSON");
        assert_eq!(msg.function_name(), "");
        assert_eq!(msg.message_id(), 0);
        assert!(!msg.response_expected());
        assert_eq!(msg.payload_u64("anything"), None);
    }

    #[test]
    fn controller_message_extracts_recon_envelope_fields() {
        let input = br#"{"from":"ubnt_avclient","functionName":"ubnt_avclient_timeSync","inResponseTo":0,"messageId":79364096,"payload":{"timeDelta":0},"responseExpected":true,"timeStamp":"2026-06-19T15:52:59.817+00:00","to":"UniFiVideo"}"#;
        let msg = ControllerMessage::parse(input).expect("valid");
        assert_eq!(msg.function_name(), "ubnt_avclient_timeSync");
        assert_eq!(msg.message_id(), 79_364_096);
        assert!(msg.response_expected());
        assert_eq!(msg.payload_u64("timeDelta"), Some(0));
    }

    #[test]
    fn controller_message_rejects_malformed_json() {
        let result = ControllerMessage::parse(b"{not json");
        assert!(matches!(result, Err(AvClientError::MalformedJson)), "expected MalformedJson, got {result:?}");
    }

    #[test]
    fn format_iso8601_utc_at_epoch_is_1970_start() {
        assert_eq!(format_iso8601_utc(0), "1970-01-01T00:00:00.000+00:00");
    }

    #[test]
    fn format_iso8601_utc_advances_one_second_and_one_day() {
        assert_eq!(format_iso8601_utc(1000), "1970-01-01T00:00:01.000+00:00");
        assert_eq!(format_iso8601_utc(86_400_000), "1970-01-02T00:00:00.000+00:00");
    }

    #[test]
    fn format_iso8601_utc_at_2025_new_year() {
        // 2025-01-01T00:00:00 UTC = 1_735_689_600_000 ms (verified by hand: 55 years * 365 days + 14 leap days = 20089 days since epoch).
        assert_eq!(format_iso8601_utc(1_735_689_600_000), "2025-01-01T00:00:00.000+00:00");
    }
}
