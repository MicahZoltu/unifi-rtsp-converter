//! Hand-rolled, zero-crates, TLS-agnostic RFC 6455 WebSocket **server** framing layer. This is the reusable substrate that the AVClient JSON-over-7442 and uPFLV binary-over-7550 paths both build on top of.
//!
//! The layer is deliberately TLS-agnostic: it operates over any `Read + Write` stream. On Linux that is a plain `TcpStream` (used by the unit/integration tests here); on Windows the Protect listener wraps the hand-rolled `tls_schannel::TlsStream<TcpStream>` at the outermost socket boundary. The `Read + Write` bound is the only seam between this module and the transport, so 100% of the code here is zero-crates and `cargo test`-able on Linux without touching TLS or a Windows host.
//!
//! What this module owns:
//! - The opening handshake: parse the client's HTTP `Upgrade` request and build the `101 Switching Protocols` response, computing `Sec-WebSocket-Accept` from a hand-rolled SHA-1 (RFC 3174) and the existing `sdp::base64_encode`.
//! - The frame parser/encoder (RFC 6455 §5.2/§5.3): opcodes, masking, the three payload-length encodings, control frames, and fragmentation reassembly.
//! - `WsConnection<RW>`: a connection over a `Read + Write` stream that reads whole (reassembled) messages, replies to `Ping` with `Pong` inline, and surfaces `Close` as a clean `None`.
//!
//! What this module does **not** own (by design):
//! - The AVClient JSON protocol.
//! - The 7550 uPFLV ingestion.
//! - The TLS transport (the wrap is the Protect listener's outer seam only).
//!
//! Decoder mask policy: RFC 6455 §5.1 mandates that client→server frames be masked and server→client frames be unmasked. This decoder is **lenient**: it unmasks a frame iff the mask bit is set and accepts an unmasked frame otherwise. Strict rejection of unmasked client frames would break the loopback round-trip tests (where the server encoder's own unmasked output is read back) and buys nothing on the production path, where the camera always masks. The server encoder (§5.3) never masks, as required.

use std::io::{self, Read, Write};

use crate::sdp::base64_encode;

/// RFC 6455 §1.3 magic GUID appended to the client's `Sec-WebSocket-Key` before SHA-1 hashing to derive `Sec-WebSocket-Accept`.
const WS_MAGIC_GUID: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

/// Required `Sec-WebSocket-Version` value, per RFC 6455 §4.1.
const WS_VERSION_13: u8 = 13;

/// HTTP version token the handshake parser requires on the request line, per RFC 6455 §4.1 (the opening handshake is an HTTP/1.1 request).
const HTTP_VERSION_PREFIX: &str = "HTTP/";

/// Status line of the `101 Switching Protocols` response, per RFC 6455 §4.2.2.
const STATUS_LINE_101: &str = "HTTP/1.1 101 Switching Protocols";

/// Header-block terminator separating HTTP-style headers from the body, per RFC 7230 §3 and RFC 6455 §4.1.
const HEADER_TERMINATOR: &[u8] = b"\r\n\r\n";

/// `FIN` bit (bit 0 of the first frame byte), per RFC 6455 §5.2.
const FIN_BIT: u8 = 0x80;

/// Reserved bits (bits 1–3 of the first frame byte); MUST be zero per RFC 6455 §5.2. A non-zero value is a protocol error.
const RSV_BITS: u8 = 0x70;

/// Mask bit (bit 0 of the second frame byte), per RFC 6455 §5.2.
const MASK_BIT: u8 = 0x80;

/// Payload-length low-7 mask of the second frame byte, per RFC 6455 §5.2.
const PAYLOAD_LEN_LOW_MASK: u8 = 0x7F;

/// Opcode low-nibble mask of the first frame byte, per RFC 6455 §5.2.
const OPCODE_MASK: u8 = 0x0F;

/// 7-bit payload-length value that signals a 16-bit extended length follows, per RFC 6455 §5.2.
const LENGTH_16_BIT_MARKER: u8 = 126;

/// 7-bit payload-length value that signals a 64-bit extended length follows, per RFC 6455 §5.2.
const LENGTH_64_BIT_MARKER: u8 = 127;

/// Largest 7-bit payload length that fits inline in the second frame byte, per RFC 6455 §5.2.
const LENGTH_INLINE_MAX: usize = 125;

/// Largest payload that fits in the 16-bit extended length, per RFC 6455 §5.2.
const LENGTH_16_BIT_MAX: usize = u16::MAX as usize;

/// Masking-key width in bytes, per RFC 6455 §5.3.
const MASK_KEY_LEN: usize = 4;

/// Maximum payload of a control frame, per RFC 6455 §5.5 (control frames are never fragmented and must carry ≤ 125 bytes).
const MAX_CONTROL_FRAME_PAYLOAD: usize = 125;

/// Hard cap on a single frame's payload. Generous enough for the largest uPFLV chunk the 7550 path emits while bounding per-frame allocation.
const MAX_FRAME_PAYLOAD: usize = 16 * 1024 * 1024;

/// Hard cap on a reassembled fragmented message. The Protect protocols the camera speaks (AVClient JSON, uPFLV) send whole, unfragmented frames, so fragmentation is not expected on the wire; this bound exists only to make an unsolicited fragment stream fail closed instead of growing unbounded.
const MAX_FRAGMENTED_MESSAGE_BYTES: usize = 64 * 1024;

/// `Continuation` opcode, per RFC 6455 §5.2.
pub const OPCODE_CONTINUATION: u8 = 0x0;
/// `Text` opcode, per RFC 6455 §5.2.
pub const OPCODE_TEXT: u8 = 0x1;
/// `Binary` opcode, per RFC 6455 §5.2.
pub const OPCODE_BINARY: u8 = 0x2;
/// `Close` opcode, per RFC 6455 §5.5.1.
pub const OPCODE_CLOSE: u8 = 0x8;
/// `Ping` opcode, per RFC 6455 §5.5.2.
pub const OPCODE_PING: u8 = 0x9;
/// `Pong` opcode, per RFC 6455 §5.5.3.
pub const OPCODE_PONG: u8 = 0xA;

/// Failures that can occur during the WebSocket handshake or frame I/O. The three handshake variants are asserted by `tests/ws.rs`; the I/O and protocol variants cover the frame path. Carries `io::ErrorKind` (not `io::Error`) so the type stays `Clone + Eq` for test assertions.
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum WsError {
    /// The opening handshake request was structurally malformed: not a valid HTTP request line, non-UTF-8 bytes, or missing the `\r\n\r\n` header terminator.
    MalformedRequest,
    /// The request lacked a `Sec-WebSocket-Key` header, per RFC 6455 §4.1.
    MissingKey,
    /// `Sec-WebSocket-Version` was absent or not `13`, per RFC 6455 §4.1.
    BadVersion,
    /// An I/O error on the underlying stream, classified by `ErrorKind`.
    Io(io::ErrorKind),
    /// A frame violated RFC 6455 §5: reserved opcode, non-zero RSV bits, a control frame that was fragmented or oversized, or a continuation frame outside a fragmented message.
    Protocol(&'static str),
    /// A single frame or reassembled message exceeded the configured cap, so no unbounded allocation is performed.
    MessageTooLarge,
    /// The stream ended partway through a frame's header or payload.
    UnexpectedEof,
}

impl From<io::Error> for WsError {
    fn from(e: io::Error) -> WsError {
        WsError::Io(e.kind())
    }
}

impl std::fmt::Display for WsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WsError::MalformedRequest => f.write_str("malformed WebSocket handshake request"),
            WsError::MissingKey => f.write_str("missing Sec-WebSocket-Key header"),
            WsError::BadVersion => f.write_str("Sec-WebSocket-Version must be 13"),
            WsError::Io(kind) => write!(f, "stream I/O error: {kind}"),
            WsError::Protocol(msg) => write!(f, "WebSocket protocol error: {msg}"),
            WsError::MessageTooLarge => {
                write!(f, "WebSocket frame or message exceeds the configured cap")
            }
            WsError::UnexpectedEof => f.write_str("stream ended mid-frame"),
        }
    }
}

impl std::error::Error for WsError {}

/// Computes the RFC 6455 §1.3 `Sec-WebSocket-Accept` value: `base64(SHA1(client_key + MAGIC_GUID))`. The base64 step reuses the existing `sdp::base64_encode` so there is one Base64 implementation in the tree.
pub fn accept_key(client_key: &str) -> String {
    let mut input = Vec::with_capacity(client_key.len() + WS_MAGIC_GUID.len());
    input.extend_from_slice(client_key.as_bytes());
    input.extend_from_slice(WS_MAGIC_GUID.as_bytes());
    let digest = sha1(&input);
    base64_encode(&digest)
}

/// Computes SHA-1 (FIPS 180-4 / RFC 3174) over `data`, returning the 20-byte digest.
///
/// **Scope:** this is a hand-rolled implementation used **only** to derive the WebSocket `Sec-WebSocket-Accept` value. It is not a general-purpose crypto primitive and must not be reused for any security-sensitive purpose — that path goes through Windows SChannel in production. Kept private so no caller outside this module can reach it; the public surface is [`accept_key`].
fn sha1(data: &[u8]) -> [u8; 20] {
    let mut h0: u32 = 0x6745_2301;
    let mut h1: u32 = 0xEFCD_AB89;
    let mut h2: u32 = 0x98BA_DCFE;
    let mut h3: u32 = 0x1032_5476;
    let mut h4: u32 = 0xC3D2_E1F0;

    let bit_len: u64 = (data.len() as u64).wrapping_mul(8);
    let mut msg = Vec::with_capacity(data.len() + 72);
    msg.extend_from_slice(data);
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bit_len.to_be_bytes());

    for chunk in msg.chunks_exact(64) {
        let mut w = [0u32; 80];
        for (i, word) in chunk.chunks_exact(4).enumerate().take(16) {
            w[i] = u32::from_be_bytes([word[0], word[1], word[2], word[3]]);
        }
        for i in 16..80 {
            w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
        }

        let (mut a, mut b, mut c, mut d, mut e) = (h0, h1, h2, h3, h4);
        for (i, &wi) in w.iter().enumerate() {
            let (f, k) = match i {
                0..=19 => ((b & c) | ((!b) & d), 0x5A82_7999u32),
                20..=39 => (b ^ c ^ d, 0x6ED9_EBA1),
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8F1B_BCDC),
                _ => (b ^ c ^ d, 0xCA62_C1D6),
            };
            let temp = a.rotate_left(5).wrapping_add(f).wrapping_add(e).wrapping_add(k).wrapping_add(wi);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = temp;
        }
        h0 = h0.wrapping_add(a);
        h1 = h1.wrapping_add(b);
        h2 = h2.wrapping_add(c);
        h3 = h3.wrapping_add(d);
        h4 = h4.wrapping_add(e);
    }

    let mut out = [0u8; 20];
    out[0..4].copy_from_slice(&h0.to_be_bytes());
    out[4..8].copy_from_slice(&h1.to_be_bytes());
    out[8..12].copy_from_slice(&h2.to_be_bytes());
    out[12..16].copy_from_slice(&h3.to_be_bytes());
    out[16..20].copy_from_slice(&h4.to_be_bytes());
    out
}

/// One WebSocket opcode, per RFC 6455 §5.2. Reserved opcodes (3–7, B–F) map to `None` from [`Opcode::from_u8`] and yield `WsError::Protocol` in the framer.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum Opcode {
    /// `0x0` — continuation of a fragmented message.
    Continuation,
    /// `0x1` — UTF-8 text message.
    Text,
    /// `0x2` — binary message.
    Binary,
    /// `0x8` — connection close.
    Close,
    /// `0x9` — ping.
    Ping,
    /// `0xA` — pong.
    Pong,
}

impl Opcode {
    /// Maps a raw 4-bit opcode to its enum value, or `None` for a reserved opcode per RFC 6455 §5.2.
    pub fn from_u8(value: u8) -> Option<Opcode> {
        match value {
            OPCODE_CONTINUATION => Some(Opcode::Continuation),
            OPCODE_TEXT => Some(Opcode::Text),
            OPCODE_BINARY => Some(Opcode::Binary),
            OPCODE_CLOSE => Some(Opcode::Close),
            OPCODE_PING => Some(Opcode::Ping),
            OPCODE_PONG => Some(Opcode::Pong),
            _ => None,
        }
    }

    /// Maps the enum value back to its raw 4-bit opcode, per RFC 6455 §5.2.
    pub fn to_u8(self) -> u8 {
        match self {
            Opcode::Continuation => OPCODE_CONTINUATION,
            Opcode::Text => OPCODE_TEXT,
            Opcode::Binary => OPCODE_BINARY,
            Opcode::Close => OPCODE_CLOSE,
            Opcode::Ping => OPCODE_PING,
            Opcode::Pong => OPCODE_PONG,
        }
    }

    /// True for the control opcodes `Close`, `Ping`, `Pong`, per RFC 6455 §5.5.
    fn is_control(self) -> bool {
        matches!(self, Opcode::Close | Opcode::Ping | Opcode::Pong)
    }
}

/// A parsed WebSocket frame: the `FIN` bit, opcode, and (unmasked) payload.
///
/// For frames returned by [`WsConnection::read_frame`] the `FIN` bit and opcode describe the *whole reassembled message*: a fragmented message is returned as a single `WsFrame` with `fin == true`, the original data opcode, and the concatenated payload.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct WsFrame {
    /// True when the message is complete in this frame (RFC 6455 §5.2 `FIN`).
    pub fin: bool,
    /// Frame opcode. Control frames are handled inline by `WsConnection` and never returned to the caller; only data opcodes (`Text`/`Binary`) appear here, carrying the start opcode of a reassembled message.
    pub opcode: Opcode,
    /// Unmasked payload bytes.
    pub payload: Vec<u8>,
}

/// The parsed client-side opening handshake (RFC 6455 §4.1). Carries the fields the proxy needs to validate the request and build the `101` response.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct WsHandshake {
    /// HTTP method token from the request line (normally `GET`).
    pub method: String,
    /// `Host:` header value, if present.
    pub host: Option<String>,
    /// `Sec-WebSocket-Key:` header value.
    pub key: String,
    /// `Sec-WebSocket-Version:` value; enforced to be `13` by [`parse`].
    pub version: u8,
    /// Subprotocols offered in `Sec-WebSocket-Protocol:`, in order, lowercased. The `101` response echoes the first one per RFC 6455 §4.2.2 (the proxy accepts whichever the camera offers, which is `secure_transfer`).
    pub protocols: Vec<String>,
}

impl WsHandshake {
    /// Parses a complete HTTP `Upgrade` request (header block through the `\r\n\r\n` terminator) into a [`WsHandshake`].
    ///
    /// Validation, per RFC 6455 §4.1:
    /// - The request line must be three whitespace-separated tokens with an `HTTP/` version, else [`WsError::MalformedRequest`].
    /// - `Sec-WebSocket-Key` must be present, else [`WsError::MissingKey`].
    /// - `Sec-WebSocket-Version` must be `13`, else [`WsError::BadVersion`].
    /// - Extra headers (e.g. the camera's `Camera-MAC`, `Origin`) are ignored.
    pub fn parse(request: &[u8]) -> Result<WsHandshake, WsError> {
        if !request.ends_with(HEADER_TERMINATOR) {
            return Err(WsError::MalformedRequest);
        }
        let text = std::str::from_utf8(request).map_err(|_| WsError::MalformedRequest)?;
        let header_block = &text[..text.len() - HEADER_TERMINATOR.len()];
        let mut lines = header_block.split("\r\n");
        let request_line = lines.next().ok_or(WsError::MalformedRequest)?;
        let mut tokens = request_line.split_ascii_whitespace();
        let method = tokens.next().ok_or(WsError::MalformedRequest)?;
        let _uri = tokens.next().ok_or(WsError::MalformedRequest)?;
        let version_token = tokens.next().ok_or(WsError::MalformedRequest)?;
        if !version_token.starts_with(HTTP_VERSION_PREFIX) {
            return Err(WsError::MalformedRequest);
        }

        let mut host = None;
        let mut key = None;
        let mut version: Option<u8> = None;
        let mut protocols = Vec::new();
        for line in lines {
            if line.is_empty() {
                continue;
            }
            let Some((name, value)) = line.split_once(':') else {
                continue;
            };
            let value = value.trim();
            match name.trim().to_ascii_lowercase().as_str() {
                "host" => host = Some(value.to_string()),
                "sec-websocket-key" => key = Some(value.to_string()),
                "sec-websocket-version" => version = value.parse::<u8>().ok(),
                "sec-websocket-protocol" => {
                    protocols = value.split(',').map(|t| t.trim().to_ascii_lowercase()).filter(|t| !t.is_empty()).collect();
                }
                _ => {}
            }
        }

        let key = key.ok_or(WsError::MissingKey)?;
        if version != Some(WS_VERSION_13) {
            return Err(WsError::BadVersion);
        }

        Ok(WsHandshake { method: method.to_string(), host, key, version: WS_VERSION_13, protocols })
    }

    /// Builds the exact `101 Switching Protocols` response bytes for this handshake, per RFC 6455 §4.2.2: `Upgrade: websocket`, `Connection: Upgrade`, `Sec-WebSocket-Accept: <accept>`, and — when the client offered a subprotocol — `Sec-WebSocket-Protocol: <first offered>`.
    pub fn response(&self) -> Vec<u8> {
        let accept = accept_key(&self.key);
        let mut out = String::new();
        out.push_str(STATUS_LINE_101);
        out.push_str("\r\n");
        out.push_str("Upgrade: websocket\r\n");
        out.push_str("Connection: Upgrade\r\n");
        out.push_str(&format!("Sec-WebSocket-Accept: {accept}\r\n"));
        if let Some(chosen) = self.protocols.first() {
            out.push_str(&format!("Sec-WebSocket-Protocol: {chosen}\r\n"));
        }
        out.push_str("\r\n");
        out.into_bytes()
    }
}

/// Reads exactly `buf.len()` bytes from `r`. Returns `Ok(None)` if the stream returned EOF before **any** byte was read into `buf` (a clean close at a frame boundary); `Ok(Some(()))` once filled; or `Err(UnexpectedEof)` if the stream ended partway through. I/O errors propagate as [`WsError::Io`].
fn fill_exact<R: Read>(r: &mut R, buf: &mut [u8]) -> Result<Option<()>, WsError> {
    let mut filled = 0;
    while filled < buf.len() {
        match r.read(&mut buf[filled..]) {
            Ok(0) => {
                if filled == 0 {
                    return Ok(None);
                }
                return Err(WsError::UnexpectedEof);
            }
            Ok(n) => filled += n,
            Err(e) => return Err(WsError::from(e)),
        }
    }
    Ok(Some(()))
}

/// Parses one RFC 6455 §5.2 frame from `r` (client→server, masked or unmasked). Returns `Ok(None)` on a clean peer close before the next frame's first byte.
///
/// Enforces: zero RSV bits, a known opcode, control frames carrying ≤ 125 bytes with `FIN` set, and the per-frame payload cap. The payload is returned already unmasked when the mask bit was set.
pub fn parse_frame<R: Read>(r: &mut R) -> Result<Option<WsFrame>, WsError> {
    let mut header = [0u8; 2];
    if fill_exact(r, &mut header)?.is_none() {
        return Ok(None);
    }
    let fin = header[0] & FIN_BIT != 0;
    if header[0] & RSV_BITS != 0 {
        return Err(WsError::Protocol("non-zero RSV bits"));
    }
    let opcode_raw = header[0] & OPCODE_MASK;
    let opcode = Opcode::from_u8(opcode_raw).ok_or(WsError::Protocol("reserved opcode"))?;
    let masked = header[1] & MASK_BIT != 0;
    let mut len = (header[1] & PAYLOAD_LEN_LOW_MASK) as usize;
    if len == LENGTH_16_BIT_MARKER as usize {
        let mut ext = [0u8; 2];
        fill_exact(r, &mut ext)?;
        len = u16::from_be_bytes(ext) as usize;
    } else if len == LENGTH_64_BIT_MARKER as usize {
        let mut ext = [0u8; 8];
        fill_exact(r, &mut ext)?;
        let big = u64::from_be_bytes(ext);
        if big > MAX_FRAME_PAYLOAD as u64 {
            return Err(WsError::MessageTooLarge);
        }
        len = big as usize;
    }
    if len > MAX_FRAME_PAYLOAD {
        return Err(WsError::MessageTooLarge);
    }
    if opcode.is_control() {
        if !fin {
            return Err(WsError::Protocol("control frame must not be fragmented"));
        }
        if len > MAX_CONTROL_FRAME_PAYLOAD {
            return Err(WsError::Protocol("control frame payload exceeds 125 bytes"));
        }
    }

    let mut mask_key = [0u8; MASK_KEY_LEN];
    if masked {
        fill_exact(r, &mut mask_key)?;
    }

    let mut payload = vec![0u8; len];
    if len > 0 {
        fill_exact(r, &mut payload)?;
    }
    if masked {
        for (i, b) in payload.iter_mut().enumerate() {
            *b ^= mask_key[i & 3];
        }
    }

    Ok(Some(WsFrame { fin, opcode, payload }))
}

/// Encodes one RFC 6455 §5.2/§5.3 **server** frame (never masked) and writes it to `w`. Selects the inline / 16-bit / 64-bit length encoding per §5.2 and flushes so the frame is on the wire before returning.
pub fn encode_frame<W: Write>(w: &mut W, frame: &WsFrame) -> Result<(), WsError> {
    let b0 = opcode_raw_with_fin(frame);
    let mut header = Vec::with_capacity(10);
    let len = frame.payload.len();
    if len <= LENGTH_INLINE_MAX {
        header.push(b0);
        header.push(len as u8);
    } else if len <= LENGTH_16_BIT_MAX {
        header.push(b0);
        header.push(LENGTH_16_BIT_MARKER);
        header.extend_from_slice(&(len as u16).to_be_bytes());
    } else {
        header.push(b0);
        header.push(LENGTH_64_BIT_MARKER);
        header.extend_from_slice(&(len as u64).to_be_bytes());
    }
    w.write_all(&header)?;
    w.write_all(&frame.payload)?;
    w.flush()?;
    Ok(())
}

fn opcode_raw_with_fin(frame: &WsFrame) -> u8 {
    let mut b0 = frame.opcode.to_u8();
    if frame.fin {
        b0 |= FIN_BIT;
    }
    b0
}

/// In-progress fragmented-message accumulator owned by [`WsConnection`].
struct FragmentAccum {
    /// Opcode of the starting data frame (`Text` or `Binary`).
    opcode: Opcode,
    /// Concatenated (unmasked) payload bytes accumulated so far.
    buf: Vec<u8>,
}

/// A WebSocket connection over any `Read + Write` stream. Reads whole reassembled messages, replies to `Ping` with `Pong` inline, and surfaces a clean peer `Close` as `Ok(None)`.
///
/// On Linux the stream is a plain `std::net::TcpStream` (the loopback test path); on Windows the Protect listener substitutes the hand-rolled `tls_schannel::TlsStream<TcpStream>` — the `Read + Write` bound is the only seam, so this struct is identical on both targets.
pub struct WsConnection<RW> {
    rw: RW,
    fragment: Option<FragmentAccum>,
}

impl<RW: Read + Write> WsConnection<RW> {
    pub fn new(rw: RW) -> WsConnection<RW> {
        WsConnection { rw, fragment: None }
    }

    pub fn into_inner(self) -> RW {
        self.rw
    }

    /// Reads the next complete message from the stream.
    ///
    /// - `Ok(Some(frame))`: a whole data message (`Text` or `Binary`), reassembled across `Continuation` frames if it was fragmented. `fin` is `true` and `opcode` is the message's start opcode.
    /// - `Ok(None)`: the peer sent a `Close` frame (a best-effort `Close` echo is written back first) or closed the TCP side cleanly.
    /// - `Err(_)`: a protocol violation, an oversized frame/message, or an I/O error on the underlying stream.
    ///
    /// Control frames are handled inline: a `Ping` is answered with a `Pong` carrying the same payload and does not surface to the caller; a `Pong` is ignored. Interleaved control frames within a fragmented message are handled without breaking reassembly, per RFC 6455 §5.4.
    pub fn read_frame(&mut self) -> Result<Option<WsFrame>, WsError> {
        loop {
            let Some(frame) = parse_frame(&mut self.rw)? else {
                return Ok(None);
            };
            match frame.opcode {
                Opcode::Ping => {
                    let pong = WsFrame { fin: true, opcode: Opcode::Pong, payload: frame.payload };
                    self.write_frame(&pong)?;
                    continue;
                }
                Opcode::Pong => continue,
                Opcode::Close => {
                    let echo = WsFrame { fin: true, opcode: Opcode::Close, payload: frame.payload };
                    let _ = self.write_frame(&echo);
                    return Ok(None);
                }
                Opcode::Continuation => {
                    let Some(acc) = self.fragment.as_mut() else {
                        return Err(WsError::Protocol("continuation frame outside a fragmented message"));
                    };
                    acc.buf.extend_from_slice(&frame.payload);
                    if acc.buf.len() > MAX_FRAGMENTED_MESSAGE_BYTES {
                        self.fragment = None;
                        return Err(WsError::MessageTooLarge);
                    }
                    if frame.fin {
                        let opcode = acc.opcode;
                        let payload = std::mem::take(&mut acc.buf);
                        self.fragment = None;
                        return Ok(Some(WsFrame { fin: true, opcode, payload }));
                    }
                    continue;
                }
                Opcode::Text | Opcode::Binary => {
                    if frame.fin {
                        return Ok(Some(frame));
                    }
                    if self.fragment.is_some() {
                        return Err(WsError::Protocol("new data frame started before the previous fragment finished"));
                    }
                    if frame.payload.len() > MAX_FRAGMENTED_MESSAGE_BYTES {
                        return Err(WsError::MessageTooLarge);
                    }
                    self.fragment = Some(FragmentAccum { opcode: frame.opcode, buf: frame.payload });
                    continue;
                }
            }
        }
    }

    /// Writes one **server** frame (unmasked, per RFC 6455 §5.3) to the stream.
    pub fn write_frame(&mut self, frame: &WsFrame) -> Result<(), WsError> {
        encode_frame(&mut self.rw, frame)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 3174 §A §B test vector: SHA-1 of the empty string.
    const SHA1_EMPTY: &str = "da39a3ee5e6b4b0d3255bfef95601890afd80709";

    /// RFC 3174 §A §B test vector: SHA-1 of `"abc"`.
    const SHA1_ABC: &str = "a9993e364706816aba3e25717850c26c9cd0d89d";

    /// RFC 3174 §A §B test vector: SHA-1 of the long string `"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"`.
    const SHA1_LONG: &str = "84983e441c3bd26ebaae4aa1f95129e5e54670f1";

    fn hex_of(digest: &[u8]) -> String {
        let mut s = String::with_capacity(digest.len() * 2);
        for b in digest {
            s.push_str(&format!("{b:02x}"));
        }
        s
    }

    #[test]
    fn sha1_empty_string_matches_rfc3174_vector() {
        assert_eq!(hex_of(&sha1(b"")), SHA1_EMPTY);
    }

    #[test]
    fn sha1_abc_matches_rfc3174_vector() {
        assert_eq!(hex_of(&sha1(b"abc")), SHA1_ABC);
    }

    #[test]
    fn sha1_long_vector_matches_rfc3174_vector() {
        let input = b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
        assert_eq!(hex_of(&sha1(input)), SHA1_LONG);
    }

    #[test]
    fn accept_key_matches_rfc6455_worked_example() {
        assert_eq!(accept_key("dGhlIHNhbXBsZSBub25jZQ=="), "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=");
    }

    #[test]
    fn opcode_round_trips_through_u8_for_all_defined_values() {
        for raw in [OPCODE_CONTINUATION, OPCODE_TEXT, OPCODE_BINARY, OPCODE_CLOSE, OPCODE_PING, OPCODE_PONG] {
            let op = Opcode::from_u8(raw).expect("defined opcode");
            assert_eq!(op.to_u8(), raw);
        }
        assert!(Opcode::from_u8(0x3).is_none());
        assert!(Opcode::from_u8(0xB).is_none());
    }

    #[test]
    fn handshake_response_without_subprotocol_is_byte_exact() {
        let request = b"GET /stream HTTP/1.1\r\n\
                        Host: example:7442\r\n\
                        Upgrade: websocket\r\n\
                        Connection: Upgrade\r\n\
                        Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
                        Sec-WebSocket-Version: 13\r\n\
                        \r\n\r\n";
        let hs = WsHandshake::parse(request).expect("valid handshake");
        let resp = hs.response();
        let expected = b"HTTP/1.1 101 Switching Protocols\r\n\
                         Upgrade: websocket\r\n\
                         Connection: Upgrade\r\n\
                         Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\
                         \r\n";
        assert_eq!(resp, expected);
        assert_eq!(hs.method, "GET");
        assert_eq!(hs.host.as_deref(), Some("example:7442"));
        assert_eq!(hs.version, WS_VERSION_13);
        assert!(hs.protocols.is_empty());
    }

    #[test]
    fn handshake_response_echoes_first_offered_subprotocol() {
        let request = b"GET /camera/1.0/ws HTTP/1.1\r\n\
                        Host: 192.168.1.20:7442\r\n\
                        Upgrade: websocket\r\n\
                        Connection: close, Upgrade\r\n\
                        Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
                        Sec-WebSocket-Protocol: secure_transfer\r\n\
                        Sec-WebSocket-Version: 13\r\n\
                        Camera-MAC: 28704E11B531\r\n\
                        \r\n\r\n";
        let hs = WsHandshake::parse(request).expect("valid handshake");
        let resp = hs.response();
        let expected = b"HTTP/1.1 101 Switching Protocols\r\n\
                         Upgrade: websocket\r\n\
                         Connection: Upgrade\r\n\
                         Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\
                         Sec-WebSocket-Protocol: secure_transfer\r\n\
                         \r\n";
        assert_eq!(resp, expected);
        assert_eq!(hs.protocols, vec!["secure_transfer"]);
    }

    #[test]
    fn handshake_missing_key_yields_missing_key_error() {
        let request = b"GET /stream HTTP/1.1\r\n\
                        Host: example:7442\r\n\
                        Upgrade: websocket\r\n\
                        Sec-WebSocket-Version: 13\r\n\
                        \r\n\r\n";
        assert_eq!(WsHandshake::parse(request), Err(WsError::MissingKey));
    }

    #[test]
    fn handshake_wrong_version_yields_bad_version_error() {
        let request = b"GET /stream HTTP/1.1\r\n\
                        Host: example:7442\r\n\
                        Upgrade: websocket\r\n\
                        Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
                        Sec-WebSocket-Version: 12\r\n\
                        \r\n\r\n";
        assert_eq!(WsHandshake::parse(request), Err(WsError::BadVersion));
    }

    #[test]
    fn handshake_garbage_yields_malformed_request_error() {
        assert_eq!(WsHandshake::parse(b"not an http request\r\n\r\n"), Err(WsError::MalformedRequest));
        assert_eq!(WsHandshake::parse(b"GET\r\n\r\n"), Err(WsError::MalformedRequest));
        assert_eq!(WsHandshake::parse(b"GET /x NOTHTTP/1.1\r\n\r\n"), Err(WsError::MalformedRequest));
    }
}
