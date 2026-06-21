//! UniFi Protect AVClient JSON protocol over the 7442 WebSocket channel
//! (build-plan step 19). This is stage 3–4 of the Protect flow: after the
//! camera completes the RFC 6455 + TLS handshake (step 17 + step 18), it speaks
//! a JSON-over-binary-WS-frame protocol with a `from`/`to`/`functionName`/
//! `messageId`/`inResponseTo`/`payload`/`responseExpected`/`timestamp` envelope
//! (confirmed by the step-16 recon capture, recorded in `DEBT.md`).
//!
//! What this module owns:
//! - A minimal, hand-rolled JSON parser/emitter (private `json` submodule)
//!   covering only the shapes the AVClient protocol uses (objects, arrays,
//!   strings, integers, floats, bools, null). Per the project's zero-crates
//!   constraint, no `serde_json`. The subset is bounded; if it proves too small
//!   it is logged in `DEBT.md`, not silently expanded by pulling a crate.
//! - `ControllerMessage`: the parsed envelope, plus accessors for the fields
//!   handlers and tests need.
//! - `AvClientSession<RW>`: a post-handshake session that loops
//!   `ws::parse_frame` → dispatch → `ws::encode_frame` until a clean close,
//!   answering each camera message with a controller reply and answering the
//!   UniFi `ping-<N>` keepalive with a `pong-<N>` text frame.
//!
//! What this module does **not** own (by design — see `plan/19-protect-avclient-7442.md`
//! "Do not"):
//! - The 7550 uPFLV ingestion (step 20).
//! - Wiring into `console_main` (step 21).
//! - The TLS transport or the WS opening handshake — those are step 17 / step
//!   18's job; `AvClientSession` is constructed on an already-upgraded stream.
//! - UDP 10001 discovery (deferred per project decision).
//!
//! # Why `AvClientSession` uses `ws::parse_frame`/`ws::encode_frame` directly
//!
//! The camera's UniFi keepalive is a WS **Ping** control frame (opcode `0x9`)
//! carrying the text payload `ping-<N>`, and it must be answered with a WS
//! **Text** frame `pong-<N>` — *not* a WS Pong control frame (step-16 recon
//! ground truth in `DEBT.md`). `ws::WsConnection::read_frame` auto-replies to a
//! Ping with a Pong and swallows the Ping, which would both answer incorrectly
//! and hide the keepalive from this layer. The lower-level `pub`
//! `ws::parse_frame` / `ws::encode_frame` functions are the intended escape
//! hatch and give this session full control of control-frame handling. This
//! deviation from the plan's literal "owning a `WsConnection`" is recorded in
//! `DEBT.md`.

use std::io::{Read, Write};

use crate::ws::{encode_frame, parse_frame, Opcode, WsError, WsFrame};

/// One observed frame for diagnostic tracing (recon / step-21 debugging).
/// `AvClientSession::with_tracer` installs a callback that receives one of
/// these for every frame read from or written to the wire, so the recon tool
/// can hex-dump / log the exact AVClient exchange without touching the
/// session's dispatch logic. Production code passes `None` (no overhead).
#[derive(Debug, Clone)]
pub struct FrameTrace {
    /// `In` = read from the peer; `Out` = written by the session.
    pub direction: FrameDirection,
    /// The WS opcode of the frame (Binary = JSON AVClient message, Ping/Pong
    /// = keepalive, Text = `ping-<N>`/`pong-<N>`, Close = shutdown).
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

/// `from` field the controller advertises in its replies. The camera addresses
/// its messages `to: "UniFiVideo"` (step-16 recon), so the controller's `from`
/// is the same token.
const CONTROLLER_FROM: &str = "UniFiVideo";

/// `to` field the controller addresses its replies to — the camera's own `from`
/// token (step-16 recon).
const AVCLIENT_TO: &str = "ubnt_avclient";

/// First `messageId` the controller emits for its own replies. Mono tonic from
/// here; the camera's `messageId` is echoed only via `inResponseTo`.
const FIRST_CONTROLLER_MESSAGE_ID: u64 = 1;

/// `status` text carried in a generic ok reply payload, per
/// `plan/19-protect-avclient-7442.md` task 4.
const OK_STATUS_TEXT: &str = "ok";

/// `statusCode` value carried in a generic ok reply payload (0 = success), per
/// `plan/19-protect-avclient-7442.md` task 4.
const OK_STATUS_CODE: u64 = 0;

/// Prefix of the UniFi keepalive the camera sends as a WS Ping payload
/// (`ping-<N>`), per step-16 recon.
const KEEPALIVE_PING_PREFIX: &str = "ping";

/// Prefix of the UniFi keepalive reply the controller sends as a WS Text frame
/// (`pong-<N>`), per step-16 recon.
const KEEPALIVE_PONG_PREFIX: &str = "pong";

/// AVClient protocol `HELLO_PROTOCOL_VERSION` the controller advertises in a
/// `hello` reply, per `plan/19-protect-avclient-7442.md` task 1 (redalert
/// baseline; not yet camera-confirmed — see `DEBT.md`).
pub const HELLO_PROTOCOL_VERSION: u32 = 67;

/// Feature flag advertised in a `hello` reply: accelerometer support (redalert
/// baseline; not yet camera-confirmed — see `DEBT.md`).
pub const FEATURE_ACCELEROMETER: bool = true;

/// Feature flag advertised in a `hello` reply: adjustable IR (redalert baseline;
/// not yet camera-confirmed — see `DEBT.md`).
pub const FEATURE_ADJUSTABLE_IR: bool = true;

/// Feature flag advertised in a `hello` reply: HDR support (redalert baseline;
/// not yet camera-confirmed — see `DEBT.md`).
pub const FEATURE_HDR: bool = false;

/// Feature flag advertised in a `hello` reply: motion-zone support (redalert
/// baseline; not yet camera-confirmed — see `DEBT.md`).
pub const FEATURE_MOTION_ZONES: bool = true;

/// JSON envelope field names, used by both the parser and the emitter so the
/// two directions cannot drift apart.
const FIELD_FROM: &str = "from";
const FIELD_TO: &str = "to";
const FIELD_FUNCTION_NAME: &str = "functionName";
const FIELD_MESSAGE_ID: &str = "messageId";
const FIELD_IN_RESPONSE_TO: &str = "inResponseTo";
const FIELD_PAYLOAD: &str = "payload";
const FIELD_RESPONSE_EXPECTED: &str = "responseExpected";
const FIELD_TIMESTAMP: &str = "timeStamp";

/// `timeSync` reply payload field: the controller's current time, per
/// `plan/19-protect-avclient-7442.md` task 4.
const FIELD_T1: &str = "t1";
/// `timeSync` reply payload field: the controller's current time, per
/// `plan/19-protect-avclient-7442.md` task 4.
const FIELD_T2: &str = "t2";

/// Generic ok reply payload fields.
const FIELD_STATUS_CODE: &str = "statusCode";
const FIELD_STATUS: &str = "status";
const FIELD_DEVICE_ID: &str = "deviceID";

/// `hello` reply payload fields.
const FIELD_PROTOCOL_VERSION: &str = "protocolVersion";
const FIELD_FEATURES: &str = "features";

/// `ChangeVideoSettings` payload field names (redalert baseline
/// `DEFAULT_CHANGE_VIDEO_PAYLOAD`, `Unifi/wss_manager.py`; not yet
/// camera-confirmed — see `DEBT.md`). The controller sends this
/// controller-initiated command to tell the camera where to push its
/// extendedFlv stream; the camera dials the `avSerializer.destinations`
/// URI (e.g. `tcp://<controller>:7550?...`) only for streams whose
/// `avSerializer.type == "extendedFlv"` and whose `destinations` is a
/// non-empty list (redalert's pushability check).
const FIELD_VIDEO: &str = "video";
const FIELD_AV_SERIALIZER: &str = "avSerializer";
const FIELD_DESTINATIONS: &str = "destinations";
const FIELD_PARAMETERS: &str = "parameters";
const FIELD_STREAM_NAME: &str = "streamName";
const FIELD_WITH_TALKBACK: &str = "withTalkback";
const FIELD_TYPE: &str = "type";

/// AVClient `functionName` values this module dispatches specifically. All
/// other names fall through to the generic ok reply. The `ubnt_avclient_`
/// prefixed forms are the camera-confirmed shapes (step-16 recon); the bare
/// forms are accepted defensively (redalert baseline).
const FN_TIMESYNC: &str = "timeSync";
const FN_TIMESYNC_FULL: &str = "ubnt_avclient_timeSync";
const FN_HELLO: &str = "hello";
const FN_HELLO_FULL: &str = "ubnt_avclient_hello";

/// Controller→camera command that configures the camera's video stream
/// destinations (redalert baseline; not yet camera-confirmed — see
/// `DEBT.md`). Sending it with an `extendedFlv` `avSerializer` whose
/// `destinations` points at `tcp://<controller>:7550` is what makes the
/// camera open the 7550 streaming channel.
const FN_CHANGE_VIDEO_SETTINGS: &str = "ChangeVideoSettings";

/// Controller→camera parameter-agreement command (redalert baseline). The
/// controller sends this to negotiate protocol features (status codes,
/// heartbeats) before driving adoption forward. Real-camera testing (step-20
/// interim recon) showed the camera ignores `ChangeVideoSettings` sent
/// immediately after `timeSync` and stays in a `timeSync` liveness loop; the
/// redalert sequence sends `paramAgreement` ahead of `ChangeVideoSettings`,
/// so the adoption driver now sends `paramAgreement` first.
const FN_PARAM_AGREEMENT: &str = "ubnt_avclient_paramAgreement";

/// `paramAgreement` payload field: whether the controller uses numeric
/// status codes in replies (redalert baseline).
const FIELD_ENABLE_STATUS_CODES: &str = "enableStatusCodes";
/// `paramAgreement` payload field: whether to use WS-level heartbeats
/// (redalert baseline; the camera's `ping-0` keepalive is handled separately).
const FIELD_USE_HEARTBEATS: &str = "useHeartbeats";
/// `paramAgreement` payload field: heartbeat timeout in milliseconds
/// (redalert baseline).
const FIELD_HEARTBEATS_TIMEOUT_MS: &str = "heartbeatsTimeoutMs";

/// The extendedFlv serializer type label, per redalert's
/// `DEFAULT_CHANGE_VIDEO_PAYLOAD` (`avSerializer.type == "extendedFlv"`).
/// Only streams with this type and a non-empty `destinations` are pushed.
const SERIALIZER_TYPE_EXTFLV: &str = "extendedFlv";

/// Failures that can abort an [`AvClientSession::run`]. A malformed JSON frame
/// is **not** fatal — the session skips it and continues (per the plan's
/// "Malformed JSON frame → logged, frame skipped, session continues"); only
/// WebSocket-level errors and a peer reset propagate.
#[derive(Debug)]
pub enum AvClientError {
    /// A WebSocket framing / I/O error from the underlying stream.
    Ws(WsError),
    /// A frame's payload was not valid JSON. Surfaced only by
    /// [`ControllerMessage::parse`]; `run` skips such frames instead of
    /// propagating this.
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

/// A monotonic wall-clock used to stamp replies (`timestamp`, `t1`, `t2`).
/// Injected so unit/integration tests can pin the clock for byte-exact replies;
/// the production path supplies `system_now_ms`.
pub type Clock = Box<dyn Fn() -> u64 + Send + Sync>;

/// Returns the current Unix time in milliseconds. The default clock for
/// [`AvClientSession::new`]; falls back to `0` if the system clock is before
/// the epoch (cannot happen in practice).
fn system_now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// A parsed AVClient envelope. The payload is retained as a [`json::Json`]
/// value so handlers and tests can read nested fields; the envelope fields the
/// dispatcher needs are extracted eagerly.
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
    /// Parses one AVClient JSON frame payload into a [`ControllerMessage`].
    /// Missing fields default to empty/zero/false so a partial-but-valid JSON
    /// object never aborts the session; only syntactically invalid JSON yields
    /// [`AvClientError::MalformedJson`].
    pub fn parse(bytes: &[u8]) -> Result<ControllerMessage, AvClientError> {
        let value = json::parse(bytes).map_err(|_| AvClientError::MalformedJson)?;
        Ok(Self::from_json(&value))
    }

    /// Builds a [`ControllerMessage`] from a parsed JSON value, applying
    /// per-field defaults for anything absent or the wrong type.
    fn from_json(value: &json::Json) -> ControllerMessage {
        let string_field = |key: &str| {
            value
                .get(key)
                .and_then(json::Json::as_str)
                .unwrap_or("")
                .to_string()
        };
        let number_field = |key: &str| value.get(key).and_then(json::Json::as_u64).unwrap_or(0);
        let bool_field = |key: &str| {
            value
                .get(key)
                .and_then(json::Json::as_bool)
                .unwrap_or(false)
        };
        let payload = value
            .get(FIELD_PAYLOAD)
            .cloned()
            .unwrap_or(json::Json::Null);
        ControllerMessage {
            from: string_field(FIELD_FROM),
            to: string_field(FIELD_TO),
            function_name: string_field(FIELD_FUNCTION_NAME),
            message_id: number_field(FIELD_MESSAGE_ID),
            in_response_to: number_field(FIELD_IN_RESPONSE_TO),
            response_expected: bool_field(FIELD_RESPONSE_EXPECTED),
            payload,
        }
    }

    /// The `functionName` of the message (used by the dispatcher).
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

    /// The message's `inResponseTo` field.
    pub fn in_response_to(&self) -> u64 {
        self.in_response_to
    }

    /// Whether the camera set `responseExpected: true`.
    pub fn response_expected(&self) -> bool {
        self.response_expected
    }

    /// Reads a `u64` field from the `payload` object, if present.
    pub fn payload_u64(&self, key: &str) -> Option<u64> {
        self.payload.get(key).and_then(json::Json::as_u64)
    }

    /// Reads a string field from the `payload` object, if present.
    pub fn payload_str(&self, key: &str) -> Option<&str> {
        self.payload.get(key).and_then(json::Json::as_str)
    }
}

/// A post-handshake AVClient session over any `Read + Write` stream. Loops
/// reading WS frames, dispatching JSON messages to handlers, and writing reply
/// frames until the peer closes cleanly or a WebSocket-level error occurs.
///
/// On Linux the stream is a plain `TcpStream` (the loopback test path); on
/// Windows step 21 substitutes the hand-rolled `tls_schannel::TlsStream` — the
/// `Read + Write` bound is the only seam.
pub struct AvClientSession<RW> {
    rw: RW,
    device_id: String,
    next_message_id: u64,
    now_ms: Clock,
    ready: bool,
    /// Optional 7550 stream destination URI
    /// (`tcp://<controller_ip>:7550?retryInterval=1&connectTimeout=5`). When
    /// set, the session sends a controller-initiated `ChangeVideoSettings`
    /// command pointing the camera at this URI once the `timeSync` exchange
    /// completes, so the camera opens the 7550 streaming channel (step 20/21).
    /// `None` ⇒ the session is purely reactive (the step-19 test behavior).
    stream_destination: Option<String>,
    /// Optional `streamName` for the `ChangeVideoSettings` payload, conventionally
    /// `<MAC_NO_COLONS>_<idx>` (redalert `_apply_camera_identity_to_video_payload`).
    /// `None` ⇒ `DEFAULT_0`.
    stream_name: Option<String>,
    /// Guards the one-shot `ChangeVideoSettings` send so it fires exactly once
    /// after `hello` is received from the camera.
    stream_announced: bool,
    /// True once the camera has sent `hello` (the post-timeSync handshake
    /// advancement). The adoption driver (`paramAgreement` +
    /// `ChangeVideoSettings`) fires after this, not after `timeSync` —
    /// confirmed by the step-20 interim recon: sending the adoption sequence
    /// right after `timeSync` caused the camera to reset, while waiting for
    /// `hello` let the handshake complete.
    hello_received: bool,
    /// Optional frame tracer (recon / debugging). `None` in production.
    tracer: Option<Box<dyn FnMut(FrameTrace) + Send>>,
}

impl<RW: Read + Write> AvClientSession<RW> {
    /// Creates a session with the real wall-clock and `messageId` starting at
    /// [`FIRST_CONTROLLER_MESSAGE_ID`]. The production entry point (step 21).
    pub fn new(rw: RW, device_id: String) -> AvClientSession<RW> {
        Self::with_start_and_clock(
            rw,
            device_id,
            FIRST_CONTROLLER_MESSAGE_ID,
            Box::new(system_now_ms),
        )
    }

    /// Creates a session with an explicit starting `messageId` and an injected
    /// clock. The test entry point: tests pin both for byte-exact replies.
    pub fn with_start_and_clock(
        rw: RW,
        device_id: String,
        start_message_id: u64,
        now_ms: Clock,
    ) -> AvClientSession<RW> {
        AvClientSession {
            rw,
            device_id,
            next_message_id: start_message_id,
            now_ms,
            ready: false,
            stream_destination: None,
            stream_name: None,
            stream_announced: false,
            hello_received: false,
            tracer: None,
        }
    }

    /// Installs a frame tracer that receives every frame read from or written
    /// to the wire. Builder-style; returns `self` for chaining. Used by the
    /// recon tool to log the exact AVClient exchange for diagnosis; production
    /// code leaves it unset (zero overhead — the `Option` is never read).
    pub fn with_tracer<F>(mut self, tracer: F) -> AvClientSession<RW>
    where
        F: FnMut(FrameTrace) + Send + 'static,
    {
        self.tracer = Some(Box::new(tracer));
        self
    }

    /// Emits an `Out` trace for `frame` if a tracer is installed.
    fn trace_out(&mut self, frame: &WsFrame) {
        if let Some(t) = self.tracer.as_mut() {
            t(FrameTrace {
                direction: FrameDirection::Out,
                opcode: frame.opcode,
                payload: frame.payload.clone(),
            });
        }
    }

    /// Emits an `In` trace for `frame` if a tracer is installed.
    fn trace_in(&mut self, frame: &WsFrame) {
        if let Some(t) = self.tracer.as_mut() {
            t(FrameTrace {
                direction: FrameDirection::In,
                opcode: frame.opcode,
                payload: frame.payload.clone(),
            });
        }
    }

    /// Configures the 7550 stream destination so the session sends a
    /// controller-initiated `ChangeVideoSettings` (telling the camera to push
    /// extendedFlv to `stream_destination`) once the `timeSync` exchange
    /// completes. `stream_name` is the `avSerializer.parameters.streamName`
    /// (conventionally `<MAC_NO_COLONS>_<idx>`). Builder-style; returns `self`
    /// for chaining off `new`. Redalert-baseline payload shape, not yet
    /// camera-confirmed (see `DEBT.md`).
    pub fn with_stream_destination(
        mut self,
        stream_destination: String,
        stream_name: Option<String>,
    ) -> AvClientSession<RW> {
        self.stream_destination = Some(stream_destination);
        self.stream_name = stream_name;
        self
    }

    /// True once the session has answered a `timeSync` exchange — the
    /// recon-confirmed signal that the camera considers the handshake
    /// complete. Stays true for the life of the session.
    pub fn is_ready(&self) -> bool {
        self.ready
    }

    /// True once the one-shot `ChangeVideoSettings` command has been sent (or
    /// skipped because no stream destination was configured). Used by the recon
    /// log to confirm adoption-driving actually fired.
    pub fn change_video_settings_sent(&self) -> bool {
        self.stream_announced
    }

    /// Runs the session until a clean peer close (returns `Ok(())`) or a
    /// WebSocket-level error (returns `Err`). Malformed JSON frames and unknown
    /// `functionName` values are skipped / best-effort-answered and never abort
    /// the loop.
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
                    let echo = WsFrame {
                        fin: true,
                        opcode: Opcode::Close,
                        payload: frame.payload,
                    };
                    self.send_frame(&echo)?;
                    return Ok(());
                }
                Opcode::Text | Opcode::Binary => self.handle_data(frame.payload)?,
                Opcode::Continuation => continue,
            }
        }
    }

    /// Traces (if a tracer is installed) then encodes `frame` to the wire.
    /// Centralizes the trace-out + encode pattern so every outgoing frame is
    /// visible to the recon without each call site repeating the trace call.
    fn send_frame(&mut self, frame: &WsFrame) -> Result<(), AvClientError> {
        self.trace_out(frame);
        encode_frame(&mut self.rw, frame).map_err(AvClientError::from)
    }

    /// Answers a WS Ping. A UniFi `ping-<N>` keepalive is answered with a Text
    /// `pong-<N>` frame (step-16 recon ground truth); any other Ping is
    /// answered with a standard WS Pong echoing the payload (RFC 6455 §5.5).
    fn handle_ping(&mut self, payload: Vec<u8>) -> Result<(), AvClientError> {
        if let Some(pong) = text_pong_for(&payload) {
            return self.send_frame(&pong);
        }
        let std_pong = WsFrame {
            fin: true,
            opcode: Opcode::Pong,
            payload,
        };
        self.send_frame(&std_pong)
    }

    /// Handles a Text/Binary data frame. A `ping-<N>` text payload is answered
    /// with a `pong-<N>` text frame (covers the "text ping" interpretation in
    /// `DEBT.md`); otherwise the payload is parsed as an AVClient JSON message
    /// and dispatched. Unparseable JSON is skipped (no reply, no crash). After
    /// replying, if the `timeSync` exchange just completed and a stream
    /// destination is configured, sends the one-shot `ChangeVideoSettings`
    /// command that tells the camera to open the 7550 streaming channel.
    fn handle_data(&mut self, payload: Vec<u8>) -> Result<(), AvClientError> {
        if let Some(pong) = text_pong_for(&payload) {
            return self.send_frame(&pong);
        }
        let request = match ControllerMessage::parse(&payload) {
            Ok(msg) => msg,
            Err(_) => return Ok(()),
        };
        let reply = self.dispatch(&request);
        let reply_bytes = json::emit(&reply).into_bytes();
        let reply_frame = WsFrame {
            fin: true,
            opcode: Opcode::Binary,
            payload: reply_bytes,
        };
        self.send_frame(&reply_frame)?;
        // Drive adoption: once the camera sends `hello` (the post-timeSync
        // handshake advancement), send the one-shot controller-initiated
        // adoption sequence — `paramAgreement` then `ChangeVideoSettings` —
        // that tells the camera where to push its extendedFlv stream.
        //
        // The step-20 interim recon proved the sequence: the camera sends
        // ~10 timeSync requests, then sends `hello` (with full features
        // payload). Sending `paramAgreement`/`ChangeVideoSettings` before
        // `hello` caused the camera to reset (it wasn't ready for commands
        // yet). After `hello`, the camera is ready to accept stream config.
        //
        // Only fires when a stream destination is configured; otherwise the
        // session stays purely reactive.
        if self.hello_received && !self.stream_announced && self.stream_destination.is_some() {
            self.send_param_agreement()?;
            self.send_change_video_settings()?;
            self.stream_announced = true;
        }
        Ok(())
    }

    /// Sends a controller-initiated `paramAgreement` command (not a reply —
    /// `inResponseTo: 0`, fresh `messageId`, `responseExpected: true`) that
    /// negotiates protocol features with the camera. Real-camera testing
    /// showed the camera ignores `ChangeVideoSettings` when sent immediately
    /// after `timeSync` (it keeps looping on timeSync); the redalert sequence
    /// sends `paramAgreement` first, so the adoption driver sends it before
    /// `ChangeVideoSettings`. Redalert-baseline payload (`enableStatusCodes`,
    /// `useHeartbeats`, `heartbeatsTimeoutMs`); not yet camera-confirmed.
    fn send_param_agreement(&mut self) -> Result<(), AvClientError> {
        self.send_controller_message(
            FN_PARAM_AGREEMENT,
            json::obj(&[
                (FIELD_ENABLE_STATUS_CODES, json::bool_v(true)),
                (FIELD_USE_HEARTBEATS, json::bool_v(false)),
                (FIELD_HEARTBEATS_TIMEOUT_MS, json::uint(10000)),
            ]),
        )
    }

    /// Sends a controller-initiated `ChangeVideoSettings` command (not a reply
    /// — `inResponseTo: 0`, fresh `messageId`, `responseExpected: true` so the
    /// camera acks) whose payload contains one `extendedFlv` video stream
    /// pointing at the configured 7550 destination. This is the message that
    /// makes the camera dial 7550 and push uPFLV. Payload shape is redalert
    /// baseline (`Unifi/wss_manager.py` `DEFAULT_CHANGE_VIDEO_PAYLOAD` +
    /// pushability rule: `avSerializer.type == "extendedFlv"` and non-empty
    /// `destinations`); not yet camera-confirmed (see `DEBT.md`).
    fn send_change_video_settings(&mut self) -> Result<(), AvClientError> {
        let destination = self.stream_destination.clone().unwrap_or_default();
        let stream_name = self
            .stream_name
            .clone()
            .unwrap_or_else(|| "DEFAULT_0".to_string());
        // { "video": { "video1": { "avSerializer": {
        //     "destinations": [ "<uri>" ],
        //     "parameters": { "streamName": "<name>", "withTalkback": false },
        //     "type": "extendedFlv" } } } }
        let av_serializer = json::obj(&[
            (
                FIELD_DESTINATIONS,
                json::array(vec![json::str_v(destination.as_str())]),
            ),
            (
                FIELD_PARAMETERS,
                json::obj(&[
                    (FIELD_STREAM_NAME, json::str_v(stream_name.as_str())),
                    (FIELD_WITH_TALKBACK, json::bool_v(false)),
                ]),
            ),
            (FIELD_TYPE, json::str_v(SERIALIZER_TYPE_EXTFLV)),
        ]);
        let video1 = json::obj(&[(FIELD_AV_SERIALIZER, av_serializer)]);
        let payload = json::obj(&[(FIELD_VIDEO, json::obj(&[("video1", video1)]))]);
        self.send_controller_message(FN_CHANGE_VIDEO_SETTINGS, payload)
    }

    /// Sends one controller-initiated (unsolicited) AVClient command: builds
    /// the full envelope (`from`/`to`/`functionName`/`inResponseTo:0`/fresh
    /// `messageId`/`payload`/`responseExpected:true`/`timestamp`) around
    /// `payload`, emits it as a Binary WS frame, and writes it to the wire.
    /// Shared by `send_param_agreement` and `send_change_video_settings` so
    /// the envelope is built exactly once.
    fn send_controller_message(
        &mut self,
        function_name: &str,
        payload: json::Json,
    ) -> Result<(), AvClientError> {
        let message_id = self.next_message_id;
        self.next_message_id = self.next_message_id.wrapping_add(1);
        let now = (self.now_ms)();
        let message = json::obj(&[
            (FIELD_FROM, json::str_v(CONTROLLER_FROM)),
            (FIELD_FUNCTION_NAME, json::str_v(function_name)),
            (FIELD_IN_RESPONSE_TO, json::uint(0)),
            (FIELD_MESSAGE_ID, json::uint(message_id)),
            (FIELD_PAYLOAD, payload),
            (FIELD_RESPONSE_EXPECTED, json::bool_v(true)),
            (FIELD_TIMESTAMP, json::str_v(&format_iso8601_utc(now))),
            (FIELD_TO, json::str_v(AVCLIENT_TO)),
        ]);
        let frame = WsFrame {
            fin: true,
            opcode: Opcode::Binary,
            payload: json::emit(&message).into_bytes(),
        };
        self.send_frame(&frame)
    }

    /// Builds the full reply envelope for `request`: the handler-specific
    /// `payload` wrapped in the `from`/`to`/`functionName`/`messageId`/
    /// `inResponseTo`/`responseExpected`/`timestamp` envelope, with
    /// `inResponseTo` echoing the request's `messageId` and a fresh
    /// mono tonic `messageId`.
    fn dispatch(&mut self, request: &ControllerMessage) -> json::Json {
        let payload = self.handler_payload(request);
        let message_id = self.next_message_id;
        self.next_message_id = self.next_message_id.wrapping_add(1);
        let now = (self.now_ms)();
        json::obj(&[
            (FIELD_FROM, json::str_v(CONTROLLER_FROM)),
            (
                FIELD_FUNCTION_NAME,
                json::str_v(request.function_name.as_str()),
            ),
            (FIELD_IN_RESPONSE_TO, json::uint(request.message_id)),
            (FIELD_MESSAGE_ID, json::uint(message_id)),
            (FIELD_PAYLOAD, payload),
            (FIELD_RESPONSE_EXPECTED, json::bool_v(false)),
            (FIELD_TIMESTAMP, json::str_v(&format_iso8601_utc(now))),
            (FIELD_TO, json::str_v(AVCLIENT_TO)),
        ])
    }

    /// Selects the handler-specific payload for `request` and updates session
    /// state (e.g. `ready`). `timeSync` is the only camera-confirmed handler;
    /// `hello` returns the controller features map (redalert baseline); every
    /// other name — including the redalert-baseline `paramAgreement` /
    /// `getSystemStats` / `updateFirmwareRequest` / `stopService` /
    /// `enableLogging` — falls through to a uniform generic ok reply.
    fn handler_payload(&mut self, request: &ControllerMessage) -> json::Json {
        match request.function_name.as_str() {
            FN_TIMESYNC | FN_TIMESYNC_FULL => {
                self.ready = true;
                let now = (self.now_ms)();
                json::obj(&[(FIELD_T1, json::uint(now)), (FIELD_T2, json::uint(now))])
            }
            FN_HELLO | FN_HELLO_FULL => {
                self.hello_received = true;
                self.hello_payload()
            }
            _ => self.ok_payload(),
        }
    }

    /// The generic ok reply payload (`statusCode: 0, status: "ok", deviceID`).
    /// Uniform across all non-`timeSync`/non-`hello` handlers; the redalert
    /// baseline gives per-handler shapes that are not yet camera-confirmed (see
    /// `DEBT.md`).
    fn ok_payload(&self) -> json::Json {
        json::obj(&[
            (FIELD_STATUS_CODE, json::uint(OK_STATUS_CODE)),
            (FIELD_STATUS, json::str_v(OK_STATUS_TEXT)),
            (FIELD_DEVICE_ID, json::str_v(self.device_id.as_str())),
        ])
    }

    /// The `hello` reply payload: the controller's protocol version plus its
    /// advertised feature flags. Redalert baseline; not yet camera-confirmed
    /// (see `DEBT.md`).
    fn hello_payload(&self) -> json::Json {
        json::obj(&[
            (
                FIELD_PROTOCOL_VERSION,
                json::uint(HELLO_PROTOCOL_VERSION as u64),
            ),
            (FIELD_FEATURES, self.features_object()),
        ])
    }

    /// The `features` object assembled from the named feature-flag consts so
    /// no flag is a magic literal.
    fn features_object(&self) -> json::Json {
        json::obj(&[
            ("accelerometer", json::bool_v(FEATURE_ACCELEROMETER)),
            ("adjustableIR", json::bool_v(FEATURE_ADJUSTABLE_IR)),
            ("hdr", json::bool_v(FEATURE_HDR)),
            ("motionZones", json::bool_v(FEATURE_MOTION_ZONES)),
        ])
    }
}

/// If `payload` is a UniFi `ping<suffix>` keepalive (e.g. `ping-0`), returns
/// the matching `pong<suffix>` Text frame; otherwise `None`. Used for both WS
/// Ping control frames and Text/Binary data frames so the session tolerates
/// either keepalive encoding the camera picks (the recon captured a Ping
/// control frame; `DEBT.md`'s summary also describes "text pings").
fn text_pong_for(payload: &[u8]) -> Option<WsFrame> {
    let text = std::str::from_utf8(payload).ok()?;
    let suffix = text.strip_prefix(KEEPALIVE_PING_PREFIX)?;
    let mut pong = String::with_capacity(KEEPALIVE_PONG_PREFIX.len() + suffix.len());
    pong.push_str(KEEPALIVE_PONG_PREFIX);
    pong.push_str(suffix);
    Some(WsFrame {
        fin: true,
        opcode: Opcode::Text,
        payload: pong.into_bytes(),
    })
}

/// Formats `ms` (Unix milliseconds) as an ISO 8601 UTC string with millisecond
/// precision and an explicit `+00:00` offset, matching the timestamp shape the
/// camera sends (step-16 recon: `2026-06-19T15:52:59.817+00:00`). Hand-rolled
/// (zero-crates) via Howard Hinnant's civil-from-days algorithm.
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

/// Converts days-since-Unix-epoch (1970-01-01) to a proleptic-Gregorian
/// `(year, month, day)`. Howard Hinnant's `civil_from_days` algorithm
/// (`http://howardhinnant.github.io/date_algorithms.html`), valid for any
/// non-negative day count.
fn civil_from_days(z_in: i64) -> (i64, u32, u32) {
    let z = z_in + 719_468;
    let era = (if z >= 0 { z } else { z - 146_096 }) / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if m <= 2 { y + 1 } else { y };
    (year, m as u32, d as u32)
}

/// Minimal hand-rolled JSON parser/emitter covering only the shapes the
/// AVClient protocol uses. Private to this module; if step 22 (ONVIF SOAP)
/// also needs JSON-ish parsing, step 25's review decides whether to promote
/// this to a shared `src/json.rs` (see `DEBT.md`). Not a general-purpose JSON
/// library: it parses a single value with no trailing tokens, emits compact
/// JSON preserving object key insertion order, and rejects unescaped control
/// bytes in strings.
mod json {
    /// A JSON number, kept as the narrowest exact integer/float kind so
    /// `messageId`/`inResponseTo`/`t1`/`t2` round-trip without f64 precision
    /// loss.
    #[derive(Debug, Clone, PartialEq)]
    pub(super) enum JsonNumber {
        /// A non-negative integer lexeme (the common case for AVClient numbers).
        UInt(u64),
        /// A negative integer lexeme.
        Int(i64),
        /// A lexeme containing `.` or an exponent.
        Float(f64),
    }

    /// A decoded JSON value. Object key order is preserved as-inserted so the
    /// emitter produces deterministic, byte-exact output for tests.
    #[derive(Debug, Clone, PartialEq)]
    pub(super) enum Json {
        Null,
        Bool(bool),
        Num(JsonNumber),
        Str(String),
        Array(Vec<Json>),
        Object(Vec<(String, Json)>),
    }

    /// Parser failure modes. Kept `Debug + PartialEq` so unit tests can assert
    /// the exact variant.
    #[derive(Debug, Clone, PartialEq)]
    pub(super) enum JsonError {
        /// Input ended before a complete value.
        Eof,
        /// An unexpected byte was encountered (carries the byte).
        UnexpectedByte(u8),
        /// A number lexeme did not parse.
        InvalidNumber,
        /// An invalid `\uXXXX` / surrogate pair / escape sequence.
        InvalidEscape,
        /// A string contained invalid UTF-8 (cannot happen for well-formed
        /// escapes, but `String::from_utf8` is the final authority).
        InvalidUtf8String,
    }

    impl Json {
        /// Looks up a key in an object, returning `None` for non-objects or
        /// missing keys.
        pub(super) fn get(&self, key: &str) -> Option<&Json> {
            match self {
                Json::Object(entries) => entries.iter().find(|(k, _)| k == key).map(|(_, v)| v),
                _ => None,
            }
        }

        /// Coerces a number value to `u64` (truncating floats); `None` for
        /// non-numbers.
        pub(super) fn as_u64(&self) -> Option<u64> {
            match self {
                Json::Num(JsonNumber::UInt(n)) => Some(*n),
                Json::Num(JsonNumber::Int(n)) => u64::try_from(*n).ok(),
                Json::Num(JsonNumber::Float(f)) => Some(*f as u64),
                _ => None,
            }
        }

        /// Returns the string value if this is a `Str`.
        pub(super) fn as_str(&self) -> Option<&str> {
            match self {
                Json::Str(s) => Some(s),
                _ => None,
            }
        }

        /// Returns the bool value if this is a `Bool`.
        pub(super) fn as_bool(&self) -> Option<bool> {
            match self {
                Json::Bool(b) => Some(*b),
                _ => None,
            }
        }
    }

    /// Parses `input` as exactly one JSON value (with optional surrounding
    /// whitespace). Trailing non-whitespace bytes are an error.
    pub(super) fn parse(input: &[u8]) -> Result<Json, JsonError> {
        let mut parser = Parser {
            bytes: input,
            pos: 0,
        };
        parser.skip_ws();
        let value = parser.value()?;
        parser.skip_ws();
        if parser.pos != parser.bytes.len() {
            return Err(JsonError::UnexpectedByte(parser.bytes[parser.pos]));
        }
        Ok(value)
    }

    /// Emits `value` as compact JSON (no whitespace), preserving object key
    /// insertion order.
    pub(super) fn emit(value: &Json) -> String {
        let mut out = String::new();
        emit_into(value, &mut out);
        out
    }

    /// Builds a `Json::Object` from ordered key/value pairs.
    pub(super) fn obj(pairs: &[(&str, Json)]) -> Json {
        Json::Object(
            pairs
                .iter()
                .map(|(key, value)| ((*key).to_string(), value.clone()))
                .collect(),
        )
    }

    /// `Json::Num(UInt(n))`.
    pub(super) fn uint(n: u64) -> Json {
        Json::Num(JsonNumber::UInt(n))
    }

    /// `Json::Str(s.to_string())`.
    pub(super) fn str_v(s: &str) -> Json {
        Json::Str(s.to_string())
    }

    /// `Json::Bool(b)`.
    pub(super) fn bool_v(b: bool) -> Json {
        Json::Bool(b)
    }

    /// Builds a `Json::Array` from the given items in order.
    pub(super) fn array(items: Vec<Json>) -> Json {
        Json::Array(items)
    }

    fn emit_into(value: &Json, out: &mut String) {
        match value {
            Json::Null => out.push_str("null"),
            Json::Bool(true) => out.push_str("true"),
            Json::Bool(false) => out.push_str("false"),
            Json::Num(JsonNumber::UInt(n)) => out.push_str(&n.to_string()),
            Json::Num(JsonNumber::Int(n)) => out.push_str(&n.to_string()),
            Json::Num(JsonNumber::Float(n)) => out.push_str(&n.to_string()),
            Json::Str(s) => emit_str(s, out),
            Json::Array(items) => {
                out.push('[');
                for (i, item) in items.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    emit_into(item, out);
                }
                out.push(']');
            }
            Json::Object(entries) => {
                out.push('{');
                for (i, (key, value)) in entries.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    emit_str(key, out);
                    out.push(':');
                    emit_into(value, out);
                }
                out.push('}');
            }
        }
    }

    /// Emits a JSON string with mandatory escaping of `"`, `\`, the short
    /// escapes, and any control byte `< 0x20` as `\uXXXX`.
    fn emit_str(s: &str, out: &mut String) {
        out.push('"');
        for c in s.chars() {
            match c {
                '"' => out.push_str("\\\""),
                '\\' => out.push_str("\\\\"),
                '\n' => out.push_str("\\n"),
                '\r' => out.push_str("\\r"),
                '\t' => out.push_str("\\t"),
                '\u{08}' => out.push_str("\\b"),
                '\u{0C}' => out.push_str("\\f"),
                c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
                c => out.push(c),
            }
        }
        out.push('"');
    }

    /// Recursive-descent parser cursor over the input byte slice.
    struct Parser<'a> {
        bytes: &'a [u8],
        pos: usize,
    }

    impl<'a> Parser<'a> {
        fn peek(&self) -> Option<u8> {
            self.bytes.get(self.pos).copied()
        }

        fn bump(&mut self) -> Option<u8> {
            let byte = self.peek();
            if byte.is_some() {
                self.pos += 1;
            }
            byte
        }

        fn skip_ws(&mut self) {
            while let Some(byte) = self.peek() {
                if matches!(byte, b' ' | b'\n' | b'\r' | b'\t') {
                    self.pos += 1;
                } else {
                    break;
                }
            }
        }

        fn value(&mut self) -> Result<Json, JsonError> {
            self.skip_ws();
            match self.peek() {
                None => Err(JsonError::Eof),
                Some(b'{') => self.object(),
                Some(b'[') => self.array(),
                Some(b'"') => self.string().map(Json::Str),
                Some(b't') => self.literal(b"true", Json::Bool(true)),
                Some(b'f') => self.literal(b"false", Json::Bool(false)),
                Some(b'n') => self.literal(b"null", Json::Null),
                Some(byte) if byte == b'-' || byte.is_ascii_digit() => self.number(),
                Some(byte) => Err(JsonError::UnexpectedByte(byte)),
            }
        }

        fn literal(&mut self, lit: &[u8], value: Json) -> Result<Json, JsonError> {
            if self.bytes.get(self.pos..self.pos + lit.len()) == Some(lit) {
                self.pos += lit.len();
                Ok(value)
            } else {
                Err(JsonError::UnexpectedByte(self.peek().unwrap_or(0)))
            }
        }

        fn number(&mut self) -> Result<Json, JsonError> {
            let start = self.pos;
            if self.peek() == Some(b'-') {
                self.pos += 1;
            }
            while let Some(byte) = self.peek() {
                if byte.is_ascii_digit() {
                    self.pos += 1;
                } else {
                    break;
                }
            }
            let mut is_float = false;
            if self.peek() == Some(b'.') {
                is_float = true;
                self.pos += 1;
                while let Some(byte) = self.peek() {
                    if byte.is_ascii_digit() {
                        self.pos += 1;
                    } else {
                        break;
                    }
                }
            }
            if matches!(self.peek(), Some(b'e') | Some(b'E')) {
                is_float = true;
                self.pos += 1;
                if matches!(self.peek(), Some(b'+') | Some(b'-')) {
                    self.pos += 1;
                }
                while let Some(byte) = self.peek() {
                    if byte.is_ascii_digit() {
                        self.pos += 1;
                    } else {
                        break;
                    }
                }
            }
            let lexeme = std::str::from_utf8(&self.bytes[start..self.pos])
                .map_err(|_| JsonError::InvalidNumber)?;
            if is_float {
                let parsed: f64 = lexeme.parse().map_err(|_| JsonError::InvalidNumber)?;
                Ok(Json::Num(JsonNumber::Float(parsed)))
            } else if let Some(digits) = lexeme.strip_prefix('-') {
                let magnitude: u64 = digits.parse().map_err(|_| JsonError::InvalidNumber)?;
                let signed = i64::try_from(magnitude)
                    .ok()
                    .and_then(|m| m.checked_neg())
                    .ok_or(JsonError::InvalidNumber)?;
                Ok(Json::Num(JsonNumber::Int(signed)))
            } else {
                let parsed: u64 = lexeme.parse().map_err(|_| JsonError::InvalidNumber)?;
                Ok(Json::Num(JsonNumber::UInt(parsed)))
            }
        }

        fn string(&mut self) -> Result<String, JsonError> {
            self.pos += 1; // opening quote
            let mut out: Vec<u8> = Vec::new();
            loop {
                let byte = self.bump().ok_or(JsonError::Eof)?;
                match byte {
                    b'"' => {
                        return String::from_utf8(out).map_err(|_| JsonError::InvalidUtf8String)
                    }
                    b'\\' => {
                        let escape = self.bump().ok_or(JsonError::Eof)?;
                        match escape {
                            b'"' => out.push(b'"'),
                            b'\\' => out.push(b'\\'),
                            b'/' => out.push(b'/'),
                            b'n' => out.push(b'\n'),
                            b't' => out.push(b'\t'),
                            b'r' => out.push(b'\r'),
                            b'b' => out.push(0x08),
                            b'f' => out.push(0x0C),
                            b'u' => {
                                let code = self.read_hex4()?;
                                if (0xD800..=0xDBFF).contains(&code) {
                                    if self.bump() != Some(b'\\') || self.bump() != Some(b'u') {
                                        return Err(JsonError::InvalidEscape);
                                    }
                                    let low = self.read_hex4()?;
                                    if !(0xDC00..=0xDFFF).contains(&low) {
                                        return Err(JsonError::InvalidEscape);
                                    }
                                    let combined =
                                        0x10000 + ((code - 0xD800) << 10) + (low - 0xDC00);
                                    push_codepoint(&mut out, combined)?;
                                } else {
                                    push_codepoint(&mut out, code)?;
                                }
                            }
                            _ => return Err(JsonError::InvalidEscape),
                        }
                    }
                    byte if byte < 0x20 => return Err(JsonError::UnexpectedByte(byte)),
                    byte => out.push(byte),
                }
            }
        }

        fn read_hex4(&mut self) -> Result<u32, JsonError> {
            let mut code = 0u32;
            for _ in 0..4 {
                let hex = self.bump().ok_or(JsonError::Eof)?;
                let digit = (hex as char).to_digit(16).ok_or(JsonError::InvalidEscape)?;
                code = code * 16 + digit;
            }
            Ok(code)
        }

        fn object(&mut self) -> Result<Json, JsonError> {
            self.pos += 1; // '{'
            let mut entries = Vec::new();
            self.skip_ws();
            if self.peek() == Some(b'}') {
                self.pos += 1;
                return Ok(Json::Object(entries));
            }
            loop {
                self.skip_ws();
                if self.peek() != Some(b'"') {
                    return Err(JsonError::UnexpectedByte(self.peek().unwrap_or(0)));
                }
                let key = self.string()?;
                self.skip_ws();
                if self.peek() != Some(b':') {
                    return Err(JsonError::UnexpectedByte(self.peek().unwrap_or(0)));
                }
                self.pos += 1;
                let value = self.value()?;
                entries.push((key, value));
                self.skip_ws();
                match self.peek() {
                    Some(b',') => self.pos += 1,
                    Some(b'}') => {
                        self.pos += 1;
                        return Ok(Json::Object(entries));
                    }
                    _ => return Err(JsonError::UnexpectedByte(self.peek().unwrap_or(0))),
                }
            }
        }

        fn array(&mut self) -> Result<Json, JsonError> {
            self.pos += 1; // '['
            let mut items = Vec::new();
            self.skip_ws();
            if self.peek() == Some(b']') {
                self.pos += 1;
                return Ok(Json::Array(items));
            }
            loop {
                let value = self.value()?;
                items.push(value);
                self.skip_ws();
                match self.peek() {
                    Some(b',') => self.pos += 1,
                    Some(b']') => {
                        self.pos += 1;
                        return Ok(Json::Array(items));
                    }
                    _ => return Err(JsonError::UnexpectedByte(self.peek().unwrap_or(0))),
                }
            }
        }
    }

    /// UTF-8 encodes `code` into `out`. Returns `InvalidEscape` for code points
    /// that are not valid scalar values (lone surrogates reaching here).
    fn push_codepoint(out: &mut Vec<u8>, code: u32) -> Result<(), JsonError> {
        let mut buf = [0u8; 4];
        let c = char::from_u32(code).ok_or(JsonError::InvalidEscape)?;
        out.extend_from_slice(c.encode_utf8(&mut buf).as_bytes());
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hello_protocol_version_is_the_redalert_baseline() {
        assert_eq!(HELLO_PROTOCOL_VERSION, 67);
    }

    #[test]
    fn feature_flags_have_their_declared_baseline_values() {
        const { assert!(FEATURE_ACCELEROMETER) };
        const { assert!(FEATURE_ADJUSTABLE_IR) };
        const { assert!(!FEATURE_HDR) };
        const { assert!(FEATURE_MOTION_ZONES) };
    }

    #[test]
    fn json_round_trips_avclient_envelope() {
        let input = br#"{"from":"ubnt_avclient","functionName":"ubnt_avclient_timeSync","inResponseTo":0,"messageId":79364096,"payload":{"timeDelta":0},"responseExpected":true,"timeStamp":"2026-06-19T15:52:59.817+00:00","to":"UniFiVideo"}"#;
        let value = json::parse(input).expect("valid JSON");
        let emitted = json::emit(&value);
        assert_eq!(emitted.as_bytes(), input);
    }

    #[test]
    fn json_parses_uint_without_precision_loss() {
        let value = json::parse(b"9007199254740993").expect("big uint"); // 2^53 + 1
        assert_eq!(value.as_u64(), Some(9_007_199_254_740_993));
    }

    #[test]
    fn json_rejects_trailing_garbage() {
        // After `{}` the parser skips the space, then fails on the `t`.
        assert_eq!(
            json::parse(b"{} trailing"),
            Err(json::JsonError::UnexpectedByte(b't'))
        );
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
        assert!(
            matches!(result, Err(AvClientError::MalformedJson)),
            "expected MalformedJson, got {result:?}"
        );
    }

    #[test]
    fn text_pong_for_rewrites_ping_prefix_only() {
        let pong = text_pong_for(b"ping-0").expect("ping-0 -> pong-0");
        assert_eq!(pong.opcode, Opcode::Text);
        assert_eq!(pong.payload, b"pong-0".to_vec());

        let pong = text_pong_for(b"ping-42").expect("ping-42 -> pong-42");
        assert_eq!(pong.payload, b"pong-42".to_vec());
    }

    #[test]
    fn text_pong_for_returns_none_for_non_ping_payloads() {
        assert!(text_pong_for(b"hello").is_none());
        assert!(text_pong_for(b"\x80\x81 not utf8").is_none());
    }

    #[test]
    fn format_iso8601_utc_at_epoch_is_1970_start() {
        assert_eq!(format_iso8601_utc(0), "1970-01-01T00:00:00.000+00:00");
    }

    #[test]
    fn format_iso8601_utc_advances_one_second_and_one_day() {
        assert_eq!(format_iso8601_utc(1000), "1970-01-01T00:00:01.000+00:00");
        assert_eq!(
            format_iso8601_utc(86_400_000),
            "1970-01-02T00:00:00.000+00:00"
        );
    }

    #[test]
    fn format_iso8601_utc_at_2025_new_year() {
        // 2025-01-01T00:00:00 UTC = 1_735_689_600_000 ms (verified by hand: 55
        // years * 365 days + 14 leap days = 20089 days since epoch).
        assert_eq!(
            format_iso8601_utc(1_735_689_600_000),
            "2025-01-01T00:00:00.000+00:00"
        );
    }
}
