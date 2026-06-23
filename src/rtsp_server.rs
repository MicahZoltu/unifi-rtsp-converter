//! RTSP server: the text-protocol half (step 10) and the runtime half (step 11). The protocol half parses/builds RTSP requests and responses, handles the five mandatory methods (OPTIONS, DESCRIBE, SETUP, PLAY, TEARDOWN), and negotiates TCP-interleaved vs UDP RTP transports — pure string/byte logic with no sockets. The runtime half (`RtspServer`, `handle_client`, the per-session RTP pump, and the `PacketSink` test seam) drives that protocol over a real `TcpListener`, feeds it frames from `StreamState`, and ships RTP via `RtpPacketizer`.
//!
//! The session registry (`RtspSessions`) is owned per connection: RTSP sessions do not span TCP connections, so each `handle_client` thread holds its own registry and there is no cross-connection shared mutable session state. Codec parameters for DESCRIBE are pulled from the shared `StreamState` (cloned cheaply into each connection thread), which is the point where the camera pipeline (step 12) meets the RTSP layer — matching the boundary drawn in `PROJECT.md`.

use std::collections::HashMap;

use crate::sdp::build_sdp;
use crate::stream_state::CodecParams;

/// RTSP version string emitted in every response status line, per RFC 2326 §A.1 (`RTSP/1.0`).
const RTSP_VERSION: &str = "RTSP/1.0";

/// Header-block terminator separating RTSP headers from an optional body, per RFC 2326 §A.1.
const HEADER_TERMINATOR: &[u8] = b"\r\n\r\n";

/// Length in bytes of the header-block terminator (two CRLFs).
const HEADER_TERMINATOR_LEN: usize = 4;

/// `Public:` header value advertising the methods this server implements, per RFC 2326 §10.4 and `plan/10-rtsp-protocol.md`.
const SUPPORTED_METHODS: &str = "OPTIONS, DESCRIBE, SETUP, PLAY, TEARDOWN";

/// SDP content type returned by DESCRIBE, per `PROJECT.md` → "DESCRIBE".
const SDP_CONTENT_TYPE: &str = "application/sdp";

/// Session timeout advertised on SETUP responses, per `plan/10-rtsp-protocol.md` (`Session: <id>;timeout=60`). In seconds, per RFC 2326 §12.37.
const SESSION_TIMEOUT_SECS: u32 = 60;

/// `Range:` header value echoed by PLAY, per `plan/10-rtsp-protocol.md`.
const PLAY_RANGE: &str = "npt=0.000-";

/// First ephemeral server port the registry hands out for UDP transport, per `plan/10-rtsp-protocol.md`. Chosen as the bottom of the IANA dynamic port range (49152–65535) so the values are plausibly bindable; actual UDP sockets are bound in step 11.
const SERVER_PORT_BASE: u16 = 49_152;

/// Stride between consecutive UDP server-port pairs: each SETUP consumes two ports (RTP + RTCP), so the next pair starts two ports higher.
const SERVER_PORT_STRIDE: u16 = 2;

/// Width in hex digits of a generated session id. Eight hex digits gives a 32-bit opaque token — enough to be unguessable on a LAN while staying deterministic for tests.
const SESSION_ID_HEX_WIDTH: usize = 8;

/// First session id handed out by `RtspSessions::allocate`. Starts above zero so a sentinel of `0` is never produced.
const FIRST_SESSION_ID: u64 = 1;

/// RTSP status code `200 OK`, per RFC 2326 §A.1.
const STATUS_OK: u16 = 200;
/// RTSP status code `400 Bad Request`, per RFC 2326 §17.4.1.
const STATUS_BAD_REQUEST: u16 = 400;
/// RTSP status code `454 Session Not Found`, per RFC 2326 §17.3.7.
const STATUS_SESSION_NOT_FOUND: u16 = 454;
/// RTSP status code `461 Unsupported transport`, per RFC 2326 §17.4.16.
const STATUS_UNSUPPORTED_TRANSPORT: u16 = 461;
/// RTSP status code `501 Not Implemented`, per RFC 2326 §17.4.5.
const STATUS_NOT_IMPLEMENTED: u16 = 501;
/// RTSP status code `503 Service Unavailable`, per RFC 2326 §17.4.17.
const STATUS_SERVICE_UNAVAILABLE: u16 = 503;

/// Canonical reason phrase for `code`, per RFC 2326 §A.1 / RFC 7231 §6. Unknown codes map to `"Unknown"` rather than panic.
fn status_text(code: u16) -> &'static str {
    match code {
        STATUS_OK => "OK",
        STATUS_BAD_REQUEST => "Bad Request",
        STATUS_SESSION_NOT_FOUND => "Session Not Found",
        STATUS_UNSUPPORTED_TRANSPORT => "Unsupported transport",
        STATUS_NOT_IMPLEMENTED => "Not Implemented",
        STATUS_SERVICE_UNAVAILABLE => "Service Unavailable",
        _ => "Unknown",
    }
}

/// One RTSP request method. `Other` preserves an unrecognized method token so the dispatcher can answer `501 Not Implemented` without losing the name.
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum Method {
    /// `OPTIONS` — advertise supported methods.
    Options,
    /// `DESCRIBE` — return the SDP describing the stream.
    Describe,
    /// `SETUP` — negotiate transport and allocate a session.
    Setup,
    /// `PLAY` — begin streaming RTP for an existing session.
    Play,
    /// `TEARDOWN` — end a session and free its transport.
    Teardown,
    /// Any method outside the supported set; carries the raw token.
    Other(String),
}

/// A parsed RTSP request. Header values the proxy cares about are lifted into dedicated `Option` fields; the raw `body` (if any) is kept as bytes so a future request with a binary body is not corrupted by a UTF-8 round-trip.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct RtspRequest {
    /// Parsed request method (or `Other` for unrecognized tokens).
    pub method: Method,
    /// Request-URI exactly as it appeared on the request line.
    pub uri: String,
    /// `CSeq` sequence number, per RFC 2326 §12.18. Mandatory per spec; absent here only when the client omitted it (the dispatcher then returns `400 Bad Request`).
    pub cseq: Option<u32>,
    /// Session id from the `Session:` header, with any `;params` stripped, per RFC 2326 §12.37.
    pub session: Option<String>,
    /// Raw `Transport:` header value, per RFC 2326 §12.39. Parsed by `handle_setup` rather than here so the parser stays schema-agnostic.
    pub transport: Option<String>,
    /// `Accept:` header value, per RFC 2326 §12.1.
    pub accept: Option<String>,
    /// `Range:` header value, per RFC 2326 §12.29.
    pub range: Option<String>,
    /// Request body bytes following the header terminator (zero-length when no `Content-Length` was present).
    pub body: Vec<u8>,
}

/// Failures that can occur while framing/parsing an RTSP request. Each names a distinct structural defect so the caller (step 11) can log it and close the connection without crashing.
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum RtspError {
    /// The header block was not valid UTF-8. RTSP headers are ASCII (RFC 2326 §A.1); a non-UTF-8 block cannot be salvaged by reading more bytes.
    InvalidUtf8,
    /// The request line did not contain exactly three whitespace-separated tokens (method, URI, version).
    MalformedRequestLine,
    /// The request line's version token does not begin with `RTSP/`; carries the offending token so a non-RTSP request (e.g. HTTP) is diagnosable.
    NonRtspVersion(String),
}

/// Parses one complete RTSP request from `buf` if present.
///
/// Returns `Ok(None)` when the buffer does not yet contain a full request — either the `\r\n\r\n` header terminator is missing, or a declared `Content-Length` body has not been fully received. The caller should read more bytes and retry. Returns `Ok(Some((req, consumed)))` on success, where `consumed` is the number of bytes making up this request (header block + terminator + body); the caller advances the buffer by that amount.
///
/// Header parsing is tolerant: header names match case-insensitively, unknown headers are ignored, lines without a `:` separator are skipped, and a non-numeric `CSeq` / `Content-Length` is treated as absent rather than fatal. A missing `CSeq` parses successfully; the dispatcher enforces the `400 Bad Request` rule later, per `plan/10-rtsp-protocol.md`.
pub fn parse_request(buf: &[u8]) -> Result<Option<(RtspRequest, usize)>, RtspError> {
    let Some(header_end) = find_header_terminator(buf) else {
        return Ok(None);
    };
    let header_str = match std::str::from_utf8(&buf[..header_end]) {
        Ok(s) => s,
        Err(_) => return Err(RtspError::InvalidUtf8),
    };
    let (method, uri) = parse_request_line(header_str)?;

    let mut cseq = None;
    let mut session = None;
    let mut transport = None;
    let mut accept = None;
    let mut range = None;
    let mut content_length: usize = 0;
    for line in header_str.split("\r\n").skip(1) {
        if line.is_empty() {
            continue;
        }
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let value = value.trim();
        match name.trim().to_ascii_lowercase().as_str() {
            "cseq" => cseq = value.parse::<u32>().ok(),
            "session" => session = Some(session_id(value)),
            "transport" => transport = Some(value.to_string()),
            "accept" => accept = Some(value.to_string()),
            "range" => range = Some(value.to_string()),
            "content-length" => content_length = value.parse::<usize>().unwrap_or(0),
            _ => {}
        }
    }

    let body_start = header_end + HEADER_TERMINATOR_LEN;
    let Some(total) = body_start.checked_add(content_length) else {
        return Ok(None);
    };
    if buf.len() < total {
        return Ok(None);
    }
    let body = buf[body_start..total].to_vec();
    Ok(Some((RtspRequest { method, uri, cseq, session, transport, accept, range, body }, total)))
}

fn find_header_terminator(buf: &[u8]) -> Option<usize> {
    buf.windows(HEADER_TERMINATOR_LEN).position(|w| w == HEADER_TERMINATOR)
}

/// Splits the first line of the header block into method and URI, validating the version token begins with `RTSP/`.
fn parse_request_line(header_str: &str) -> Result<(Method, String), RtspError> {
    let request_line = header_str.split("\r\n").next().ok_or(RtspError::MalformedRequestLine)?;
    let mut tokens = request_line.split_ascii_whitespace();
    let method_token = tokens.next().ok_or(RtspError::MalformedRequestLine)?;
    let uri = tokens.next().ok_or(RtspError::MalformedRequestLine)?;
    let version = tokens.next().ok_or(RtspError::MalformedRequestLine)?;
    if tokens.next().is_some() {
        return Err(RtspError::MalformedRequestLine);
    }
    if !version.starts_with("RTSP/") {
        return Err(RtspError::NonRtspVersion(version.to_string()));
    }
    Ok((parse_method(method_token), uri.to_string()))
}

fn parse_method(token: &str) -> Method {
    match token {
        "OPTIONS" => Method::Options,
        "DESCRIBE" => Method::Describe,
        "SETUP" => Method::Setup,
        "PLAY" => Method::Play,
        "TEARDOWN" => Method::Teardown,
        other => Method::Other(other.to_string()),
    }
}

/// Extracts the session id (the token before any `;` parameter) from a `Session:` header value, per RFC 2326 §12.37.
fn session_id(value: &str) -> String {
    value.split_once(';').map(|(id, _)| id.trim()).unwrap_or(value.trim()).to_string()
}

/// An RTSP response ready to be serialized to the wire.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct RtspResponse {
    pub status: u16,
    pub status_text: String,
    /// `CSeq` echoed from the request, if present.
    pub cseq: Option<u32>,
    /// `Session:` header value, if the response carries one.
    pub session: Option<String>,
    /// Additional headers, in insertion order. `Content-Length` is added by `to_bytes` when a body is present and must not be set here.
    pub headers: Vec<(String, String)>,
    /// Optional body bytes appended after the blank line.
    pub body: Vec<u8>,
}

impl RtspResponse {
    /// Serializes the response to canonical RTSP wire bytes: status line, `CSeq`, `Session`, caller headers, `Content-Length` (iff a body is present), a blank line, then the body. Line endings are `\r\n` per RFC 2326 §A.1.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = String::new();
        out.push_str(&format!("{} {} {}\r\n", RTSP_VERSION, self.status, self.status_text));
        if let Some(cseq) = self.cseq {
            out.push_str(&format!("CSeq: {cseq}\r\n"));
        }
        if let Some(session) = &self.session {
            out.push_str(&format!("Session: {session}\r\n"));
        }
        for (name, value) in &self.headers {
            out.push_str(&format!("{}: {}\r\n", name, value));
        }
        if !self.body.is_empty() {
            out.push_str(&format!("Content-Length: {}\r\n", self.body.len()));
        }
        out.push_str("\r\n");
        let mut bytes = out.into_bytes();
        bytes.extend_from_slice(&self.body);
        bytes
    }
}

/// Builds a response with the canonical reason phrase for `code`.
fn response(code: u16, cseq: Option<u32>, session: Option<String>, headers: Vec<(String, String)>, body: Vec<u8>) -> RtspResponse {
    RtspResponse { status: code, status_text: status_text(code).to_string(), cseq, session, headers, body }
}

/// Negotiated transport for an RTSP session.
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum Transport {
    /// RTP/RTCP interleaved on the RTSP TCP connection using the given channel ids, per RFC 2326 §12.39 (`interleaved=A-B`: A=RTP, B=RTCP).
    Interleaved { rtp_ch: u8, rtcp_ch: u8 },
    /// RTP/RTCP over UDP to the client's port pair, with the server's chosen port pair. Actual UDP sockets are bound in step 11.
    Udp {
        /// Client RTP port, from `client_port=X-Y`.
        client_rtp: u16,
        /// Client RTCP port, from `client_port=X-Y`.
        client_rtcp: u16,
        /// Server RTP port allocated by the registry.
        server_rtp: u16,
        /// Server RTCP port allocated by the registry.
        server_rtcp: u16,
    },
}

/// One RTSP session: its id, negotiated transport, and play state. Fields are public so the server (step 11) and tests can inspect them directly.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct RtspSession {
    /// Opaque session id echoed in the `Session:` header.
    pub id: String,
    /// Negotiated transport for this session.
    pub transport: Transport,
    /// True once `PLAY` has been issued; the RTP pump (step 11) gates on it.
    pub playing: bool,
}

/// In-memory session registry the handlers borrow. Owns session-id and server-port allocation so handlers stay pure and deterministic.
pub struct RtspSessions {
    sessions: HashMap<String, RtspSession>,
    next_session_id: u64,
    next_server_port: u16,
}

impl RtspSessions {
    /// Creates an empty registry with no sessions and the port allocator primed at `SERVER_PORT_BASE`.
    pub fn new() -> RtspSessions {
        RtspSessions { sessions: HashMap::new(), next_session_id: FIRST_SESSION_ID, next_server_port: SERVER_PORT_BASE }
    }

    pub fn get(&self, id: &str) -> Option<&RtspSession> {
        self.sessions.get(id)
    }

    /// Removes the session with `id`, returning `true` iff one was removed. No-op for an unknown id.
    pub fn remove(&mut self, id: &str) -> bool {
        self.sessions.remove(id).is_some()
    }

    /// Allocates a fresh session id, stores `transport` under it, and returns the id.
    fn allocate(&mut self, transport: Transport) -> String {
        let id = format!("{:0width$X}", self.next_session_id, width = SESSION_ID_HEX_WIDTH);
        self.next_session_id = self.next_session_id.wrapping_add(1);
        self.sessions.insert(id.clone(), RtspSession { id: id.clone(), transport, playing: false });
        id
    }

    /// Borrows a session mutably for state changes such as setting `playing`.
    fn get_mut(&mut self, id: &str) -> Option<&mut RtspSession> {
        self.sessions.get_mut(id)
    }

    /// Returns the next RTP/RTCP server-port pair, advancing the allocator by two ports so each session gets a distinct pair. Wraps at `u16::MAX`.
    fn next_server_port_pair(&mut self) -> (u16, u16) {
        let rtp = self.next_server_port;
        let rtcp = self.next_server_port.wrapping_add(1);
        self.next_server_port = self.next_server_port.wrapping_add(SERVER_PORT_STRIDE);
        (rtp, rtcp)
    }
}

impl Default for RtspSessions {
    fn default() -> RtspSessions {
        RtspSessions::new()
    }
}

/// Outcome of parsing a `Transport:` header — the transport the server will use, or `Unsupported` when no recognizable mode was offered.
#[derive(Debug)]
enum ParsedTransport {
    /// TCP-interleaved transport with the offered channel pair.
    Interleaved { rtp_ch: u8, rtcp_ch: u8 },
    /// UDP transport with the offered client port pair.
    Udp { client_rtp: u16, client_rtcp: u16 },
    /// No `interleaved=` and no `client_port=` (or values that failed to parse), so the server cannot accept the request.
    Unsupported,
}

/// Parses a `Transport:` header value into a `ParsedTransport`, matching the cases in `plan/10-rtsp-protocol.md`.
fn parse_transport(raw: &str) -> ParsedTransport {
    let parts: Vec<&str> = raw.split(';').map(str::trim).collect();
    if let Some(value) = find_param(&parts, "interleaved") {
        return match parse_port_range(value) {
            Some((a, b)) if a <= u8::MAX as u16 && b <= u8::MAX as u16 => ParsedTransport::Interleaved { rtp_ch: a as u8, rtcp_ch: b as u8 },
            _ => ParsedTransport::Unsupported,
        };
    }
    if let Some(value) = find_param(&parts, "client_port") {
        return match parse_port_range(value) {
            Some((client_rtp, client_rtcp)) => ParsedTransport::Udp { client_rtp, client_rtcp },
            None => ParsedTransport::Unsupported,
        };
    }
    ParsedTransport::Unsupported
}

/// Finds the value of parameter `key` (case-insensitive) among `parts`, each of the form `name=value`.
fn find_param<'a>(parts: &[&'a str], key: &str) -> Option<&'a str> {
    for part in parts {
        if let Some((name, value)) = part.split_once('=') {
            if name.trim().eq_ignore_ascii_case(key) {
                return Some(value.trim());
            }
        }
    }
    None
}

fn parse_port_range(value: &str) -> Option<(u16, u16)> {
    let (a, b) = value.split_once('-')?;
    Some((a.trim().parse().ok()?, b.trim().parse().ok()?))
}

pub fn handle_options(req: &RtspRequest) -> RtspResponse {
    response(STATUS_OK, req.cseq, None, vec![("Public".to_string(), SUPPORTED_METHODS.to_string())], Vec::new())
}

/// Handles `DESCRIBE`: builds the SDP from the published codec and returns it with `Content-Type: application/sdp`. If no codec has been published yet, returns `503 Service Unavailable` (the camera is not connected).
pub fn handle_describe(req: &RtspRequest, server_ip: &str, codec: Option<&CodecParams>) -> RtspResponse {
    let Some(codec) = codec else {
        return response(STATUS_SERVICE_UNAVAILABLE, req.cseq, None, Vec::new(), Vec::new());
    };
    let body = build_sdp(codec, server_ip, codec.fps).into_bytes();
    response(STATUS_OK, req.cseq, None, vec![("Content-Type".to_string(), SDP_CONTENT_TYPE.to_string())], body)
}

/// Handles `SETUP`: parses the `Transport:` header, allocates a session, and echoes the negotiated transport. TCP-interleaved and UDP `client_port=` modes are supported; anything else yields `461 Unsupported transport`.
pub fn handle_setup(req: &RtspRequest, sessions: &mut RtspSessions) -> RtspResponse {
    let Some(transport_str) = &req.transport else {
        return response(STATUS_UNSUPPORTED_TRANSPORT, req.cseq, None, Vec::new(), Vec::new());
    };
    match parse_transport(transport_str) {
        ParsedTransport::Interleaved { rtp_ch, rtcp_ch } => {
            let id = sessions.allocate(Transport::Interleaved { rtp_ch, rtcp_ch });
            let echoed = format!("RTP/AVP/TCP;unicast;interleaved={rtp_ch}-{rtcp_ch}");
            setup_ok(req, &id, &echoed)
        }
        ParsedTransport::Udp { client_rtp, client_rtcp } => {
            let (server_rtp, server_rtcp) = sessions.next_server_port_pair();
            let id = sessions.allocate(Transport::Udp { client_rtp, client_rtcp, server_rtp, server_rtcp });
            let echoed = format!("RTP/AVP;unicast;client_port={client_rtp}-{client_rtcp};server_port={server_rtp}-{server_rtcp}");
            setup_ok(req, &id, &echoed)
        }
        ParsedTransport::Unsupported => response(STATUS_UNSUPPORTED_TRANSPORT, req.cseq, None, Vec::new(), Vec::new()),
    }
}

fn setup_ok(req: &RtspRequest, id: &str, transport: &str) -> RtspResponse {
    response(STATUS_OK, req.cseq, Some(format!("{id};timeout={SESSION_TIMEOUT_SECS}")), vec![("Transport".to_string(), transport.to_string())], Vec::new())
}

/// Handles `PLAY`: requires an existing session, marks it playing, and returns `200 OK` with `Range: npt=0.000-`. A missing or unknown session yields `454 Session Not Found`.
pub fn handle_play(req: &RtspRequest, sessions: &mut RtspSessions) -> RtspResponse {
    let Some(id) = &req.session else {
        return response(STATUS_SESSION_NOT_FOUND, req.cseq, None, Vec::new(), Vec::new());
    };
    let Some(session) = sessions.get_mut(id) else {
        return response(STATUS_SESSION_NOT_FOUND, req.cseq, None, Vec::new(), Vec::new());
    };
    session.playing = true;
    response(STATUS_OK, req.cseq, Some(format!("{id};timeout={SESSION_TIMEOUT_SECS}")), vec![("Range".to_string(), PLAY_RANGE.to_string())], Vec::new())
}

/// Handles `TEARDOWN`: removes the session and returns `200 OK`. A missing or unknown session yields `454 Session Not Found`, consistent with `PLAY`.
pub fn handle_teardown(req: &RtspRequest, sessions: &mut RtspSessions) -> RtspResponse {
    let Some(id) = &req.session else {
        return response(STATUS_SESSION_NOT_FOUND, req.cseq, None, Vec::new(), Vec::new());
    };
    if sessions.remove(id) {
        response(STATUS_OK, req.cseq, None, Vec::new(), Vec::new())
    } else {
        response(STATUS_SESSION_NOT_FOUND, req.cseq, None, Vec::new(), Vec::new())
    }
}

/// Dispatches a parsed request to the matching handler, enforcing the mandatory-`CSeq` rule (RFC 2326 §12.18) up front: a request with no `CSeq` returns `400 Bad Request`. Unrecognized methods return `501 Not Implemented`. Step 11 calls this from its accept loop.
pub fn handle_request(req: &RtspRequest, sessions: &mut RtspSessions, server_ip: &str, codec: Option<&CodecParams>) -> RtspResponse {
    let Some(cseq) = req.cseq else {
        return response(STATUS_BAD_REQUEST, None, None, Vec::new(), Vec::new());
    };
    let cseq = Some(cseq);
    match req.method {
        Method::Options => handle_options(req),
        Method::Describe => handle_describe(req, server_ip, codec),
        Method::Setup => handle_setup(req, sessions),
        Method::Play => handle_play(req, sessions),
        Method::Teardown => handle_teardown(req, sessions),
        Method::Other(_) => response(STATUS_NOT_IMPLEMENTED, cseq, None, Vec::new(), Vec::new()),
    }
}

// --------------------------------------------------------------------------- Runtime half (step 11): accept loop, per-connection handling, RTP pump. ---------------------------------------------------------------------------

use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::mpsc::{Receiver, RecvTimeoutError};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::logging::{Level, Logger};
use crate::rtp::RtpPacketizer;
use crate::stream_state::{ClientId, Frame, StreamState};

/// Relaxed ordering suffices for the shutdown flag and client counter: they are advisory signals, not synchronization that establishes happens-before for other data (the `StreamState` mutex carries that burden).
const RELAXED: Ordering = Ordering::Relaxed;

/// Poll interval for the non-blocking accept loop, so the `shutdown` flag is checked promptly rather than blocking until the next connection.
const ACCEPT_POLL_MS: u64 = 50;

/// Per-connection read timeout. The control read loop blocks on `read` for at most this long before returning `TimedOut`, which lets the loop re-check the `shutdown` flag and tear down an idle connection promptly on stop. A playing-but-silent session is unaffected: the pump streams on the writer while the control loop spins cheaply on read timeouts.
const READ_TIMEOUT_MS: u64 = 500;

/// Per-connection write timeout, bounding how long the shared send mutex can be held across a `write_all`. A stuck client that stops draining its TCP receive buffer yields a write error after this, tearing the session down rather than blocking the pump or control thread indefinitely.
const WRITE_TIMEOUT_MS: u64 = 5_000;

const READ_CHUNK_BYTES: usize = 8192;

/// Cap on the per-connection request buffer. A client that streams request bytes without ever completing a `\r\n\r\n`-terminated header block would otherwise grow the buffer unbounded; exceeding this closes the connection. Named per the resource-bounds quality gate.
const MAX_READ_BUFFER_BYTES: usize = 64 * 1024;

/// Maximum simultaneously-connected RTSP clients. New connections beyond this are refused so a client flood cannot exhaust threads/memory. Named per the resource-bounds quality gate; fuller admission control lands in the resync/hardening step.
const MAX_RTSP_CLIENTS: usize = 64;

/// `$` byte prefixing an interleaved RTP/RTCP frame on the RTSP TCP connection, per RFC 2326 §12.39 and `PROJECT.md` → "TCP Interleaved RTP".
const INTERLEAVED_FRAME_MARKER: u8 = 0x24;

/// Number of framing bytes preceding an interleaved RTP packet: `[$][channel][len_hi][len_lo]`, per RFC 2326 §12.39.
const INTERLEAVED_FRAMING_BYTES: usize = 4;

/// Pump channel poll interval, so the `shutdown` flag is checked promptly between frames rather than blocking indefinitely on `recv`.
const PUMP_POLL_TIMEOUT_MS: u64 = 200;

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

    /// Creates a server with an attached logger so RTSP client connect/disconnect events are written to `flvproxy.log`. `console_main` (step 24) uses this so an operator sees when an NVR opens or closes the RTSP stream.
    pub fn with_logger(state: StreamState, rtsp_port: u16, server_ip: String, logger: Arc<Logger>) -> RtspServer {
        RtspServer { state, rtsp_port, server_ip, shutdown: Arc::new(AtomicBool::new(false)), active_clients: Arc::new(AtomicUsize::new(0)), logger: Some(logger) }
    }

    /// Binds the RTSP listener on `0.0.0.0:rtsp_port` and runs the accept loop until `shutdown()` is called. Each accepted connection is handled on its own thread.
    pub fn run(&self) -> io::Result<()> {
        let listener = TcpListener::bind(("0.0.0.0", self.rtsp_port))?;
        self.run_on(listener)
    }

    /// Runs the accept loop on a caller-supplied listener. Tests use this with an ephemeral loopback listener so they know the bound port; production `run()` delegates here after binding.
    pub fn run_on(&self, listener: TcpListener) -> io::Result<()> {
        listener.set_nonblocking(true)?;
        for incoming in listener.incoming() {
            if self.shutdown.load(RELAXED) {
                break;
            }
            match incoming {
                Ok(stream) => {
                    if self.active_clients.load(RELAXED) >= MAX_RTSP_CLIENTS {
                        drop(stream);
                        thread::sleep(Duration::from_millis(ACCEPT_POLL_MS));
                        continue;
                    }
                    self.active_clients.fetch_add(1, RELAXED);
                    let state = self.state.clone();
                    let server_ip = self.server_ip.clone();
                    let shutdown = self.shutdown.clone();
                    let active = self.active_clients.clone();
                    let logger = self.logger.clone();
                    thread::spawn(move || {
                        handle_client(stream, state, server_ip, shutdown, logger.as_deref());
                        active.fetch_sub(1, RELAXED);
                    });
                }
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

    /// Signals the accept loop and all pumps to exit. Idempotent.
    pub fn shutdown(&self) {
        self.shutdown.store(true, RELAXED);
    }

    /// Returns a clone of the shutdown flag so external code (`console_main` in step 13, the Windows service wrapper, or tests) can stop the accept loop without holding a reference to the `RtspServer`. Setting the flag stops the accept loop on its next poll; existing pumps exit on their next poll cycle. Mirrors `CameraListener::shutdown_signal`.
    pub fn shutdown_signal(&self) -> Arc<AtomicBool> {
        self.shutdown.clone()
    }

    /// Number of client connections currently being handled. Intended for diagnostics and tests; not used in the hot path.
    pub fn active_clients(&self) -> usize {
        self.active_clients.load(RELAXED)
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
fn handle_client(stream: TcpStream, state: StreamState, server_ip: String, shutdown: Arc<AtomicBool>, logger: Option<&Logger>) {
    let peer = match stream.peer_addr() {
        Ok(p) => p,
        Err(_) => return,
    };
    if let Some(logger) = logger {
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

    let mut ctx = ConnectionCtx { state, server_ip, writer, peer, shutdown, sessions: RtspSessions::new(), registrations: HashMap::new() };

    let mut buf: Vec<u8> = Vec::new();
    let mut chunk = [0u8; READ_CHUNK_BYTES];

    loop {
        if ctx.shutdown.load(RELAXED) {
            break;
        }
        let n = match read_half.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => continue,
            Err(e) if e.kind() == io::ErrorKind::TimedOut => continue,
            Err(_) => break,
        };
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
                    if write_all_locked(&ctx.writer, &resp.to_bytes()).is_err() {
                        buf.clear();
                        break;
                    }
                    buf.drain(..consumed);
                }
                Ok(None) => break,
                Err(_) => {
                    buf.clear();
                    break;
                }
            }
        }
    }

    ctx.cleanup();
    if let Some(logger) = logger {
        logger.log(Level::Info, &format!("rtsp client disconnected: {peer}"));
    }
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
        thread::spawn(move || run_pump(receiver, sink, state, client_id, shutdown));
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

/// Per-session RTP pump: pulls `Frame`s from the session's `StreamState` receiver, packetizes each per RFC 6184, and sends every RTP packet through the sink. Exits on channel disconnect (TEARDOWN / client gone), a sink write error (broken pipe), or the shutdown flag, then removes the client from the hub so the camera thread never blocks on a dead session.
fn run_pump(receiver: Receiver<Frame>, mut sink: Box<dyn PacketSink + Send>, state: StreamState, client_id: ClientId, shutdown: Arc<AtomicBool>) {
    let mut packetizer = RtpPacketizer::new(random_ssrc(), random_seq());
    let pump_start = SystemTime::now();
    while !shutdown.load(RELAXED) {
        match receiver.recv_timeout(Duration::from_millis(PUMP_POLL_TIMEOUT_MS)) {
            Ok(mut frame) => {
                let elapsed_ms = pump_start.elapsed().unwrap_or_default().as_millis() as u32;
                frame.timestamp_ms = elapsed_ms;
                if pump_frame_into(&mut *sink, &mut packetizer, &frame).is_err() {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_text_known_codes_have_canonical_phrases() {
        assert_eq!(status_text(STATUS_OK), "OK");
        assert_eq!(status_text(STATUS_BAD_REQUEST), "Bad Request");
        assert_eq!(status_text(STATUS_SESSION_NOT_FOUND), "Session Not Found");
        assert_eq!(status_text(STATUS_UNSUPPORTED_TRANSPORT), "Unsupported transport");
        assert_eq!(status_text(STATUS_SERVICE_UNAVAILABLE), "Service Unavailable");
        assert_eq!(status_text(0), "Unknown");
    }

    #[test]
    fn session_id_strips_params_after_semicolon() {
        assert_eq!(session_id("ABC;timeout=60"), "ABC");
        assert_eq!(session_id("  ABC  "), "ABC");
        assert_eq!(session_id("PLAIN"), "PLAIN");
    }

    #[test]
    fn parse_port_range_parses_two_u16s() {
        assert_eq!(parse_port_range("4588-4589"), Some((4588, 4589)));
        assert_eq!(parse_port_range("0-1"), Some((0, 1)));
        assert_eq!(parse_port_range("4588"), None);
        assert_eq!(parse_port_range("a-b"), None);
    }

    #[test]
    fn parse_transport_interleaved_selects_tcp() {
        match parse_transport("RTP/AVP/TCP;unicast;interleaved=0-1") {
            ParsedTransport::Interleaved { rtp_ch, rtcp_ch } => {
                assert_eq!((rtp_ch, rtcp_ch), (0, 1));
            }
            other => panic!("expected Interleaved, got {other:?}"),
        }
    }

    #[test]
    fn parse_transport_client_port_selects_udp() {
        match parse_transport("RTP/AVP;unicast;client_port=4588-4589") {
            ParsedTransport::Udp { client_rtp, client_rtcp } => {
                assert_eq!((client_rtp, client_rtcp), (4588, 4589));
            }
            other => panic!("expected Udp, got {other:?}"),
        }
    }

    #[test]
    fn parse_transport_unknown_yields_unsupported() {
        assert!(matches!(parse_transport("RTP/AVP;unicast;mode=PLAY"), ParsedTransport::Unsupported));
        assert!(matches!(parse_transport("RTP/AVP;unicast;interleaved=300-301"), ParsedTransport::Unsupported));
    }

    #[test]
    fn next_server_port_pair_advances_in_strides_of_two() {
        let mut s = RtspSessions::new();
        assert_eq!(s.next_server_port_pair(), (49_152, 49_153));
        assert_eq!(s.next_server_port_pair(), (49_154, 49_155));
    }

    #[test]
    fn allocate_stores_session_retrievable_by_id() {
        let mut s = RtspSessions::new();
        let id = s.allocate(Transport::Interleaved { rtp_ch: 0, rtcp_ch: 1 });
        let session = s.get(&id).expect("session was allocated");
        assert_eq!(session.transport, Transport::Interleaved { rtp_ch: 0, rtcp_ch: 1 });
        assert!(!session.playing);
    }
}
