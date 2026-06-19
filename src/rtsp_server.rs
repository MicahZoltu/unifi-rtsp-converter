//! RTSP request parser and response builder (step 10) — the text-protocol
//! half of the RTSP server. Handles the five mandatory methods (OPTIONS,
//! DESCRIBE, SETUP, PLAY, TEARDOWN) and negotiates TCP-interleaved vs UDP
//! RTP transports. Pure string/byte logic with no sockets and no threads:
//! the accept loop and RTP pump land in step 11.
//!
//! The session registry (`RtspSessions`) is an owned, in-memory map the
//! handlers borrow mutably; tests pass one in directly so the handlers stay
//! pure and deterministic. Codec parameters for DESCRIBE are supplied by the
//! caller (`Option<&CodecParams>`) rather than pulled from `StreamState`
//! here, so step 11 — not this module — wires the camera pipeline to the
//! RTSP layer (matching the boundary drawn in `PROJECT.md`).

use std::collections::HashMap;

use crate::sdp::build_sdp;
use crate::stream_state::CodecParams;

/// RTSP version string emitted in every response status line, per RFC 2326
/// §A.1 (`RTSP/1.0`).
const RTSP_VERSION: &str = "RTSP/1.0";

/// Header-block terminator separating RTSP headers from an optional body,
/// per RFC 2326 §A.1.
const HEADER_TERMINATOR: &[u8] = b"\r\n\r\n";

/// Length in bytes of the header-block terminator (two CRLFs).
const HEADER_TERMINATOR_LEN: usize = 4;

/// `Public:` header value advertising the methods this server implements,
/// per RFC 2326 §10.4 and `plan/10-rtsp-protocol.md`.
const SUPPORTED_METHODS: &str = "OPTIONS, DESCRIBE, SETUP, PLAY, TEARDOWN";

/// SDP content type returned by DESCRIBE, per `PROJECT.md` → "DESCRIBE".
const SDP_CONTENT_TYPE: &str = "application/sdp";

/// Session timeout advertised on SETUP responses, per
/// `plan/10-rtsp-protocol.md` (`Session: <id>;timeout=60`). In seconds, per
/// RFC 2326 §12.37.
const SESSION_TIMEOUT_SECS: u32 = 60;

/// `Range:` header value echoed by PLAY, per `plan/10-rtsp-protocol.md`.
const PLAY_RANGE: &str = "npt=0.000-";

/// First ephemeral server port the registry hands out for UDP transport,
/// per `plan/10-rtsp-protocol.md`. Chosen as the bottom of the IANA dynamic
/// port range (49152–65535) so the values are plausibly bindable; actual UDP
/// sockets are bound in step 11.
const SERVER_PORT_BASE: u16 = 49_152;

/// Stride between consecutive UDP server-port pairs: each SETUP consumes two
/// ports (RTP + RTCP), so the next pair starts two ports higher.
const SERVER_PORT_STRIDE: u16 = 2;

/// Width in hex digits of a generated session id. Eight hex digits gives a
/// 32-bit opaque token — enough to be unguessable on a LAN while staying
/// deterministic for tests.
const SESSION_ID_HEX_WIDTH: usize = 8;

/// First session id handed out by `RtspSessions::allocate`. Starts above
/// zero so a sentinel of `0` is never produced.
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

/// Canonical reason phrase for `code`, per RFC 2326 §A.1 / RFC 7231 §6.
/// Unknown codes map to `"Unknown"` rather than panic.
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

/// One RTSP request method. `Other` preserves an unrecognized method token so
/// the dispatcher can answer `501 Not Implemented` without losing the name.
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

/// A parsed RTSP request. Header values the proxy cares about are lifted into
/// dedicated `Option` fields; the raw `body` (if any) is kept as bytes so a
/// future request with a binary body is not corrupted by a UTF-8 round-trip.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct RtspRequest {
    /// Parsed request method (or `Other` for unrecognized tokens).
    pub method: Method,
    /// Request-URI exactly as it appeared on the request line.
    pub uri: String,
    /// `CSeq` sequence number, per RFC 2326 §12.18. Mandatory per spec; absent
    /// here only when the client omitted it (the dispatcher then returns
    /// `400 Bad Request`).
    pub cseq: Option<u32>,
    /// Session id from the `Session:` header, with any `;params` stripped,
    /// per RFC 2326 §12.37.
    pub session: Option<String>,
    /// Raw `Transport:` header value, per RFC 2326 §12.39. Parsed by
    /// `handle_setup` rather than here so the parser stays schema-agnostic.
    pub transport: Option<String>,
    /// `Accept:` header value, per RFC 2326 §12.1.
    pub accept: Option<String>,
    /// `Range:` header value, per RFC 2326 §12.29.
    pub range: Option<String>,
    /// Request body bytes following the header terminator (zero-length when
    /// no `Content-Length` was present).
    pub body: Vec<u8>,
}

/// Failures that can occur while framing/parsing an RTSP request. Each names
/// a distinct structural defect so the caller (step 11) can log it and close
/// the connection without crashing.
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum RtspError {
    /// The header block was not valid UTF-8. RTSP headers are ASCII (RFC 2326
    /// §A.1); a non-UTF-8 block cannot be salvaged by reading more bytes.
    InvalidUtf8,
    /// The request line did not contain exactly three whitespace-separated
    /// tokens (method, URI, version).
    MalformedRequestLine,
    /// The request line's version token does not begin with `RTSP/`; carries
    /// the offending token so a non-RTSP request (e.g. HTTP) is diagnosable.
    NonRtspVersion(String),
}

/// Parses one complete RTSP request from `buf` if present.
///
/// Returns `Ok(None)` when the buffer does not yet contain a full request —
/// either the `\r\n\r\n` header terminator is missing, or a declared
/// `Content-Length` body has not been fully received. The caller should read
/// more bytes and retry. Returns `Ok(Some((req, consumed)))` on success, where
/// `consumed` is the number of bytes making up this request (header block +
/// terminator + body); the caller advances the buffer by that amount.
///
/// Header parsing is tolerant: header names match case-insensitively, unknown
/// headers are ignored, lines without a `:` separator are skipped, and a
/// non-numeric `CSeq` / `Content-Length` is treated as absent rather than
/// fatal. A missing `CSeq` parses successfully; the dispatcher enforces the
/// `400 Bad Request` rule later, per `plan/10-rtsp-protocol.md`.
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
    Ok(Some((
        RtspRequest {
            method,
            uri,
            cseq,
            session,
            transport,
            accept,
            range,
            body,
        },
        total,
    )))
}

/// Locates the index of the first byte of the `\r\n\r\n` header terminator, or
/// `None` if it has not arrived yet.
fn find_header_terminator(buf: &[u8]) -> Option<usize> {
    buf.windows(HEADER_TERMINATOR_LEN)
        .position(|w| w == HEADER_TERMINATOR)
}

/// Splits the first line of the header block into method and URI, validating
/// the version token begins with `RTSP/`.
fn parse_request_line(header_str: &str) -> Result<(Method, String), RtspError> {
    let request_line = header_str
        .split("\r\n")
        .next()
        .ok_or(RtspError::MalformedRequestLine)?;
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

/// Maps a raw method token to a `Method`.
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

/// Extracts the session id (the token before any `;` parameter) from a
/// `Session:` header value, per RFC 2326 §12.37.
fn session_id(value: &str) -> String {
    value
        .split_once(';')
        .map(|(id, _)| id.trim())
        .unwrap_or(value.trim())
        .to_string()
}

/// An RTSP response ready to be serialized to the wire.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct RtspResponse {
    /// Numeric status code, e.g. `200`.
    pub status: u16,
    /// Reason phrase, e.g. `"OK"`.
    pub status_text: String,
    /// `CSeq` echoed from the request, if present.
    pub cseq: Option<u32>,
    /// `Session:` header value, if the response carries one.
    pub session: Option<String>,
    /// Additional headers, in insertion order. `Content-Length` is added by
    /// `to_bytes` when a body is present and must not be set here.
    pub headers: Vec<(String, String)>,
    /// Optional body bytes appended after the blank line.
    pub body: Vec<u8>,
}

impl RtspResponse {
    /// Serializes the response to canonical RTSP wire bytes: status line,
    /// `CSeq`, `Session`, caller headers, `Content-Length` (iff a body is
    /// present), a blank line, then the body. Line endings are `\r\n` per
    /// RFC 2326 §A.1.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = String::new();
        out.push_str(&format!(
            "{} {} {}\r\n",
            RTSP_VERSION, self.status, self.status_text
        ));
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
fn response(
    code: u16,
    cseq: Option<u32>,
    session: Option<String>,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
) -> RtspResponse {
    RtspResponse {
        status: code,
        status_text: status_text(code).to_string(),
        cseq,
        session,
        headers,
        body,
    }
}

/// Negotiated transport for an RTSP session.
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum Transport {
    /// RTP/RTCP interleaved on the RTSP TCP connection using the given channel
    /// ids, per RFC 2326 §12.39 (`interleaved=A-B`: A=RTP, B=RTCP).
    Interleaved {
        /// RTP channel id.
        rtp_ch: u8,
        /// RTCP channel id.
        rtcp_ch: u8,
    },
    /// RTP/RTCP over UDP to the client's port pair, with the server's chosen
    /// port pair. Actual UDP sockets are bound in step 11.
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

/// One RTSP session: its id, negotiated transport, and play state. Fields are
/// public so the server (step 11) and tests can inspect them directly.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct RtspSession {
    /// Opaque session id echoed in the `Session:` header.
    pub id: String,
    /// Negotiated transport for this session.
    pub transport: Transport,
    /// True once `PLAY` has been issued; the RTP pump (step 11) gates on it.
    pub playing: bool,
}

/// In-memory session registry the handlers borrow. Owns session-id and
/// server-port allocation so handlers stay pure and deterministic.
pub struct RtspSessions {
    sessions: HashMap<String, RtspSession>,
    next_session_id: u64,
    next_server_port: u16,
}

impl RtspSessions {
    /// Creates an empty registry with no sessions and the port allocator
    /// primed at `SERVER_PORT_BASE`.
    pub fn new() -> RtspSessions {
        RtspSessions {
            sessions: HashMap::new(),
            next_session_id: FIRST_SESSION_ID,
            next_server_port: SERVER_PORT_BASE,
        }
    }

    /// Returns the session with `id`, if any.
    pub fn get(&self, id: &str) -> Option<&RtspSession> {
        self.sessions.get(id)
    }

    /// Removes the session with `id`, returning `true` iff one was removed.
    /// No-op for an unknown id.
    pub fn remove(&mut self, id: &str) -> bool {
        self.sessions.remove(id).is_some()
    }

    /// Allocates a fresh session id, stores `transport` under it, and returns
    /// the id.
    fn allocate(&mut self, transport: Transport) -> String {
        let id = format!(
            "{:0width$X}",
            self.next_session_id,
            width = SESSION_ID_HEX_WIDTH
        );
        self.next_session_id = self.next_session_id.wrapping_add(1);
        self.sessions.insert(
            id.clone(),
            RtspSession {
                id: id.clone(),
                transport,
                playing: false,
            },
        );
        id
    }

    /// Borrows a session mutably for state changes such as setting `playing`.
    fn get_mut(&mut self, id: &str) -> Option<&mut RtspSession> {
        self.sessions.get_mut(id)
    }

    /// Returns the next RTP/RTCP server-port pair, advancing the allocator by
    /// two ports so each session gets a distinct pair. Wraps at `u16::MAX`.
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

/// Outcome of parsing a `Transport:` header — the transport the server will
/// use, or `Unsupported` when no recognizable mode was offered.
#[derive(Debug)]
enum ParsedTransport {
    /// TCP-interleaved transport with the offered channel pair.
    Interleaved { rtp_ch: u8, rtcp_ch: u8 },
    /// UDP transport with the offered client port pair.
    Udp { client_rtp: u16, client_rtcp: u16 },
    /// No `interleaved=` and no `client_port=` (or values that failed to
    /// parse), so the server cannot accept the request.
    Unsupported,
}

/// Parses a `Transport:` header value into a `ParsedTransport`, matching the
/// cases in `plan/10-rtsp-protocol.md`.
fn parse_transport(raw: &str) -> ParsedTransport {
    let parts: Vec<&str> = raw.split(';').map(str::trim).collect();
    if let Some(value) = find_param(&parts, "interleaved") {
        return match parse_port_range(value) {
            Some((a, b)) if a <= u8::MAX as u16 && b <= u8::MAX as u16 => {
                ParsedTransport::Interleaved {
                    rtp_ch: a as u8,
                    rtcp_ch: b as u8,
                }
            }
            _ => ParsedTransport::Unsupported,
        };
    }
    if let Some(value) = find_param(&parts, "client_port") {
        return match parse_port_range(value) {
            Some((client_rtp, client_rtcp)) => ParsedTransport::Udp {
                client_rtp,
                client_rtcp,
            },
            None => ParsedTransport::Unsupported,
        };
    }
    ParsedTransport::Unsupported
}

/// Finds the value of parameter `key` (case-insensitive) among `parts`, each
/// of the form `name=value`.
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

/// Parses an `A-B` port range into a `(low, high)` pair.
fn parse_port_range(value: &str) -> Option<(u16, u16)> {
    let (a, b) = value.split_once('-')?;
    Some((a.trim().parse().ok()?, b.trim().parse().ok()?))
}

/// Handles `OPTIONS`: returns `200 OK` with the supported-methods list.
pub fn handle_options(req: &RtspRequest) -> RtspResponse {
    response(
        STATUS_OK,
        req.cseq,
        None,
        vec![("Public".to_string(), SUPPORTED_METHODS.to_string())],
        Vec::new(),
    )
}

/// Handles `DESCRIBE`: builds the SDP from the published codec and returns it
/// with `Content-Type: application/sdp`. If no codec has been published yet,
/// returns `503 Service Unavailable` (the camera is not connected).
pub fn handle_describe(
    req: &RtspRequest,
    server_ip: &str,
    codec: Option<&CodecParams>,
) -> RtspResponse {
    let Some(codec) = codec else {
        return response(
            STATUS_SERVICE_UNAVAILABLE,
            req.cseq,
            None,
            Vec::new(),
            Vec::new(),
        );
    };
    let body = build_sdp(codec, server_ip, codec.fps).into_bytes();
    response(
        STATUS_OK,
        req.cseq,
        None,
        vec![("Content-Type".to_string(), SDP_CONTENT_TYPE.to_string())],
        body,
    )
}

/// Handles `SETUP`: parses the `Transport:` header, allocates a session, and
/// echoes the negotiated transport. TCP-interleaved and UDP `client_port=`
/// modes are supported; anything else yields `461 Unsupported transport`.
pub fn handle_setup(req: &RtspRequest, sessions: &mut RtspSessions) -> RtspResponse {
    let Some(transport_str) = &req.transport else {
        return response(
            STATUS_UNSUPPORTED_TRANSPORT,
            req.cseq,
            None,
            Vec::new(),
            Vec::new(),
        );
    };
    match parse_transport(transport_str) {
        ParsedTransport::Interleaved { rtp_ch, rtcp_ch } => {
            let id = sessions.allocate(Transport::Interleaved { rtp_ch, rtcp_ch });
            let echoed = format!("RTP/AVP/TCP;unicast;interleaved={rtp_ch}-{rtcp_ch}");
            setup_ok(req, &id, &echoed)
        }
        ParsedTransport::Udp {
            client_rtp,
            client_rtcp,
        } => {
            let (server_rtp, server_rtcp) = sessions.next_server_port_pair();
            let id = sessions.allocate(Transport::Udp {
                client_rtp,
                client_rtcp,
                server_rtp,
                server_rtcp,
            });
            let echoed = format!(
                "RTP/AVP;unicast;client_port={client_rtp}-{client_rtcp};server_port={server_rtp}-{server_rtcp}"
            );
            setup_ok(req, &id, &echoed)
        }
        ParsedTransport::Unsupported => response(
            STATUS_UNSUPPORTED_TRANSPORT,
            req.cseq,
            None,
            Vec::new(),
            Vec::new(),
        ),
    }
}

/// Builds the `200 OK` SETUP response with the session and echoed transport.
fn setup_ok(req: &RtspRequest, id: &str, transport: &str) -> RtspResponse {
    response(
        STATUS_OK,
        req.cseq,
        Some(format!("{id};timeout={SESSION_TIMEOUT_SECS}")),
        vec![("Transport".to_string(), transport.to_string())],
        Vec::new(),
    )
}

/// Handles `PLAY`: requires an existing session, marks it playing, and
/// returns `200 OK` with `Range: npt=0.000-`. A missing or unknown session
/// yields `454 Session Not Found`.
pub fn handle_play(req: &RtspRequest, sessions: &mut RtspSessions) -> RtspResponse {
    let Some(id) = &req.session else {
        return response(
            STATUS_SESSION_NOT_FOUND,
            req.cseq,
            None,
            Vec::new(),
            Vec::new(),
        );
    };
    let Some(session) = sessions.get_mut(id) else {
        return response(
            STATUS_SESSION_NOT_FOUND,
            req.cseq,
            None,
            Vec::new(),
            Vec::new(),
        );
    };
    session.playing = true;
    response(
        STATUS_OK,
        req.cseq,
        Some(format!("{id};timeout={SESSION_TIMEOUT_SECS}")),
        vec![("Range".to_string(), PLAY_RANGE.to_string())],
        Vec::new(),
    )
}

/// Handles `TEARDOWN`: removes the session and returns `200 OK`. A missing or
/// unknown session yields `454 Session Not Found`, consistent with `PLAY`.
pub fn handle_teardown(req: &RtspRequest, sessions: &mut RtspSessions) -> RtspResponse {
    let Some(id) = &req.session else {
        return response(
            STATUS_SESSION_NOT_FOUND,
            req.cseq,
            None,
            Vec::new(),
            Vec::new(),
        );
    };
    if sessions.remove(id) {
        response(STATUS_OK, req.cseq, None, Vec::new(), Vec::new())
    } else {
        response(
            STATUS_SESSION_NOT_FOUND,
            req.cseq,
            None,
            Vec::new(),
            Vec::new(),
        )
    }
}

/// Dispatches a parsed request to the matching handler, enforcing the
/// mandatory-`CSeq` rule (RFC 2326 §12.18) up front: a request with no `CSeq`
/// returns `400 Bad Request`. Unrecognized methods return `501 Not
/// Implemented`. Step 11 calls this from its accept loop.
pub fn handle_request(
    req: &RtspRequest,
    sessions: &mut RtspSessions,
    server_ip: &str,
    codec: Option<&CodecParams>,
) -> RtspResponse {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_text_known_codes_have_canonical_phrases() {
        assert_eq!(status_text(STATUS_OK), "OK");
        assert_eq!(status_text(STATUS_BAD_REQUEST), "Bad Request");
        assert_eq!(status_text(STATUS_SESSION_NOT_FOUND), "Session Not Found");
        assert_eq!(
            status_text(STATUS_UNSUPPORTED_TRANSPORT),
            "Unsupported transport"
        );
        assert_eq!(
            status_text(STATUS_SERVICE_UNAVAILABLE),
            "Service Unavailable"
        );
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
            ParsedTransport::Udp {
                client_rtp,
                client_rtcp,
            } => {
                assert_eq!((client_rtp, client_rtcp), (4588, 4589));
            }
            other => panic!("expected Udp, got {other:?}"),
        }
    }

    #[test]
    fn parse_transport_unknown_yields_unsupported() {
        assert!(matches!(
            parse_transport("RTP/AVP;unicast;mode=PLAY"),
            ParsedTransport::Unsupported
        ));
        assert!(matches!(
            parse_transport("RTP/AVP;unicast;interleaved=300-301"),
            ParsedTransport::Unsupported
        ));
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
        let id = s.allocate(Transport::Interleaved {
            rtp_ch: 0,
            rtcp_ch: 1,
        });
        let session = s.get(&id).expect("session was allocated");
        assert_eq!(
            session.transport,
            Transport::Interleaved {
                rtp_ch: 0,
                rtcp_ch: 1
            }
        );
        assert!(!session.playing);
    }
}
