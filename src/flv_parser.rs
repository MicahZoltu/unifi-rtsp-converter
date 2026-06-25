//! FLV stream framer. Detects the uPFLV magic prefix emitted by Ubiquiti's `ubnt_streamer`, validates the 9-byte FLV header, and frames the subsequent tag stream into `TagEvent`s via a push-based state machine (`FlvParser`). The video-tag payload dispatcher (standard vs `ExVideoTagHeader` extended paths, converging on the `avc` codec helpers) lives in `flv_video`; this module owns only the byte framer and the `ParseError` type both modules share. Pure byte logic — no I/O, no logging — so it builds and tests on any platform.

use crate::avc::AvcError;

/// uPFLV magic prefix sent by Ubiquiti's `ubnt_streamer` before the FLV body. 11 bytes; strip when the first 11 stream bytes match exactly.
pub const UPFLV_PREFIX: [u8; 11] = [0xDE, 0x19, 0x16, 0x15, 0x47, 0x17, 0xDE, 0x19, 0x16, 0x75, 0x50];

/// FLV file signature "FLV" (header bytes 0-2). Used to validate the start of the body.
pub const FLV_SIGNATURE: [u8; 3] = *b"FLV";

/// Minimum FLV header length in bytes: 3 signature + 1 version + 1 flags + 4 header-size.
const FLV_HEADER_SIZE: usize = 9;

/// FLV tag type for audio data (`0x08 = audio`).
pub const TAG_TYPE_AUDIO: u8 = 0x08;

/// FLV tag type for video data (`0x09 = video`).
pub const TAG_TYPE_VIDEO: u8 = 0x09;

/// FLV tag type for script data (`0x12 = script`).
pub const TAG_TYPE_SCRIPT: u8 = 0x12;

/// Size of the 4-byte previous-tag-size field that precedes every FLV tag. Read and discarded by the framer.
const PREV_TAG_SIZE_BYTES: usize = 4;

/// Fixed size of an FLV tag header: 1 type + 3 data-size + 3 timestamp-low + 1 timestamp-ext + 3 stream-id.
const TAG_HEADER_BYTES: usize = 11;

/// Number of low bits in the FLV tag timestamp (the 3-byte field); the 4th byte supplies the high 8 bits.
const TIMESTAMP_LOW_BITS: u32 = 24;

/// Upper bound on a single tag's payload. The FLV `data_size` field is a 3-byte u24 (max 16,777,215), so the cap must sit below that ceiling to be reachable; 8 MiB is well above any real camera video frame (even a 4K keyframe is a few MiB) while still rejecting a corrupt header claiming the full u24 range, avoiding a needless 16 MiB allocation. Exposed so callers can compare against the `cap` field of `ParseError::OversizedTag`.
pub const MAX_TAG_DATA_SIZE: u32 = 8 * 1024 * 1024;

/// Upper bound on the bytes the framer accumulates while in the `Resyncing` state. A healthy stream resyncs within a tag or two; a peer streaming pure garbage would otherwise grow the buffer without limit. 4 MiB is well above any plausible resync distance (a single oversized tag header plus the next valid tag) while bounding memory under a malicious sender. Crossing it yields `ParseError::ResyncBufferOverflow` so the caller drops the connection.
pub const MAX_RESYNC_BUFFER_BYTES: usize = 4 * 1024 * 1024;

/// The only FLV version this parser supports (`version byte 0x01`).
const SUPPORTED_FLV_VERSION: u8 = 1;

/// Bit mask for the audio-present flag in the FLV header flags byte (bit 0).
const FLAG_AUDIO: u8 = 0b0000_0001;

/// Bit mask for the video-present flag in the FLV header flags byte (bit 2).
const FLAG_VIDEO: u8 = 0b0000_0100;

/// Failures that can occur while parsing the FLV stream. Each variant names the exact structural defect so the caller can log a meaningful message without re-deriving the cause; none of them represent a crash. `Codec` is the only variant produced outside this module — by `flv_video::parse_video_tag` when the `avc` codec layer rejects a config record or NALU stream — so the enum lives here (the framer) rather than the dispatcher, keeping one error type for the whole FLV parse path.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum ParseError {
    /// The buffer does not yet contain a full header (or the header-declared size when it exceeds 9). Reading more bytes from the camera and retrying is the only remediation.
    Truncated,
    /// Bytes 0-2 are not the ASCII `FLV` signature, so this is not an FLV stream at the current offset. A resync scan is required.
    BadSignature,
    /// The FLV version byte is not `1`, the only version this parser supports. Returned rather than panicking so the caller can log and resync.
    UnsupportedVersion,
    /// A tag's declared `data_size` exceeds `MAX_TAG_DATA_SIZE`. The framer has retained its buffered bytes and entered the `Resyncing` state; the caller should call [`FlvParser::resync`] to scan for the next plausible tag boundary, or drop the connection.
    OversizedTag {
        /// The tag-type byte from the offending tag header.
        tag_type: u8,
        /// The declared payload size that exceeded the cap.
        data_size: u32,
        /// The cap the declared size exceeded (`MAX_TAG_DATA_SIZE`).
        cap: u32,
    },
    /// While in the `Resyncing` state the buffered bytes exceeded `MAX_RESYNC_BUFFER_BYTES` without a plausible tag boundary being found. The framer retains the buffer; the caller should drop the connection rather than keep accumulating.
    ResyncBufferOverflow {
        /// The buffer length at the time of the overflow check.
        len: usize,
        /// The cap that was exceeded (`MAX_RESYNC_BUFFER_BYTES`).
        cap: usize,
    },
    /// A video-tag payload routed into the codec layer (`avc`) returned a non-truncation error (e.g. a malformed AVCDecoderConfigurationRecord). Truncation is lifted to `ParseError::Truncated` by the dispatcher so the caller's resync logic need only watch one truncation variant; every other `AvcError` surfaces here unchanged.
    Codec(AvcError),
}

/// Parsed FLV header. The remaining stream bytes (after the header and any declared skip) are returned alongside this struct by `parse_header`.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct FlvHeader {
    /// FLV container version byte. Always `1` for streams this parser accepts; stored verbatim for diagnostics.
    pub version: u8,
    /// True iff the flags byte's audio bit is set.
    pub has_audio: bool,
    /// True iff the flags byte's video bit is set.
    pub has_video: bool,
    /// Header-size field from bytes 5-8 (big-endian u32). Per spec it is 9; larger values declare extra skip bytes that `parse_header` consumes.
    pub header_size: u32,
}

/// Returns the FLV body slice with the 11-byte uPFLV magic prefix stripped, or `buf` unchanged when no prefix is present. A mismatched first 11 bytes are treated as no prefix (not an error): the camera may omit the prefix in some configurations, and random 11 bytes must never be mistaken for it.
pub fn detect_and_strip_prefix(buf: &[u8]) -> &[u8] {
    if buf.len() >= UPFLV_PREFIX.len() && buf[..UPFLV_PREFIX.len()] == UPFLV_PREFIX {
        &buf[UPFLV_PREFIX.len()..]
    } else {
        buf
    }
}

/// Parses the FLV header from the start of `buf` and returns the parsed `FlvHeader` plus the remaining stream bytes (after the 9-byte header and any declared skip when the header-size field exceeds 9).
///
/// Errors are returned as structured `ParseError` variants rather than panicking, so the caller can log and resync. The signature bytes are validated first, then the version, then the declared size.
pub fn parse_header(buf: &[u8]) -> Result<(&[u8], FlvHeader), ParseError> {
    if buf.len() < FLV_HEADER_SIZE {
        return Err(ParseError::Truncated);
    }
    if buf[..FLV_SIGNATURE.len()] != FLV_SIGNATURE {
        return Err(ParseError::BadSignature);
    }
    let version = buf[3];
    if version != SUPPORTED_FLV_VERSION {
        return Err(ParseError::UnsupportedVersion);
    }
    let flags = buf[4];
    let has_audio = (flags & FLAG_AUDIO) != 0;
    let has_video = (flags & FLAG_VIDEO) != 0;
    let header_size = u32::from_be_bytes([buf[5], buf[6], buf[7], buf[8]]);
    let skip = (header_size as usize).saturating_sub(FLV_HEADER_SIZE);
    let end = FLV_HEADER_SIZE + skip;
    if buf.len() < end {
        return Err(ParseError::Truncated);
    }
    Ok((&buf[end..], FlvHeader { version, has_audio, has_video, header_size }))
}

/// One fully-framed FLV tag emitted by `FlvParser::push`. The payload is opaque at this stage — steps 04-06 decode video/audio/script bodies — so only the tag type, timestamp, and raw body are reported.
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum TagEvent {
    /// Script-data tag (type `0x12`), e.g. `onMetaData` / `onMpma` / `onClockSync`.
    Script { timestamp_ms: u32, body: Vec<u8> },
    /// Audio tag (type `0x08`). Audio is not served by this proxy but is still framed so the caller can count or skip it.
    Audio { timestamp_ms: u32, body: Vec<u8> },
    /// Video tag (type `0x09`).
    Video { timestamp_ms: u32, body: Vec<u8> },
    /// Any tag whose type byte is not `0x08` / `0x09` / `0x12`. Reported rather than dropped so the caller can log unexpected types.
    Unknown { tag_type: u8, timestamp_ms: u32, body: Vec<u8> },
}

/// Internal framer state. The parser starts in `PrevTagSize` because `parse_header` consumes the FLV header; the body that follows begins with the leading 4-byte previous-tag-size (zero on a fresh stream).
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum State {
    /// Waiting for the 4-byte previous-tag-size field (read and discarded).
    PrevTagSize,
    /// Waiting for the 11-byte tag header. Used after a type=0x00 extendedFlv video tag — the extendedFlv format omits the prev_tag_size field after these tags, so the parser jumps straight to the next tag header.
    TagHeaderNoPrevSize,
    /// Skipping a fixed 5-byte trailer that follows type=0x00 extendedFlv video tags with dsize=0 (heartbeat/telemetry frames). The trailer is 1 byte (flags?) + 4 bytes (metadata, possibly FPS as IEEE 754 float). After skipping, the parser reads the next tag header directly.
    SkipExtFlvTrailer,
    /// Waiting for the 11-byte tag header.
    TagHeader,
    /// Waiting for `data_size` payload bytes, carrying the just-decoded header fields so the completed `TagEvent` can be emitted.
    TagBody { tag_type: u8, data_size: u32, timestamp_ms: u32 },
    /// Resyncing after a framing error. The framer retains buffered bytes verbatim and emits no events; the caller drives recovery by calling [`FlvParser::resync`], which scans for the next plausible tag boundary and, on success, drains the garbage plus the matched 11-byte header and transitions straight to `TagBody`. More bytes can be fed via `push` while this state is active — they are appended and the caller re-attempts `resync`.
    Resyncing,
}

/// Size of the 5-byte trailer after a type=0x00 extendedFlv video tag with dsize=0 (heartbeat/telemetry frame): 1 flag byte + 4 metadata bytes.
const EXTFLV_TRAILER_BYTES: usize = 5;

/// Push-based, incremental FLV tag framer. The caller runs `parse_header` once up-front (after `detect_and_strip_prefix`), then feeds every subsequent byte chunk here. Partial trailing bytes stay buffered across `push` calls, so the parser handles arbitrary TCP read boundaries without panicking.
#[derive(Debug, Clone)]
pub struct FlvParser {
    state: State,
    buf: Vec<u8>,
}

impl FlvParser {
    /// Creates a framer in the `PrevTagSize` state with an empty buffer. Feed it the bytes that follow the FLV header.
    pub fn new() -> FlvParser {
        FlvParser { state: State::PrevTagSize, buf: Vec::new() }
    }

    /// Appends `chunk` to the internal buffer and drains as many complete tags as possible, returning their events in stream order. Partial trailing bytes stay buffered for the next call.
    ///
    /// A tag whose declared `data_size` exceeds `MAX_TAG_DATA_SIZE` yields `Err(ParseError::OversizedTag)` — the framer resets to the `PrevTagSize` state and drops its buffer so no multi-GiB allocation occurs; the caller must resync (handled in the resync step).
    pub fn push(&mut self, chunk: &[u8]) -> Result<Vec<TagEvent>, ParseError> {
        self.buf.extend_from_slice(chunk);
        let mut events = Vec::new();
        loop {
            match self.state {
                State::PrevTagSize => {
                    if self.buf.len() < PREV_TAG_SIZE_BYTES {
                        break;
                    }
                    self.buf.drain(..PREV_TAG_SIZE_BYTES);
                    self.state = State::TagHeader;
                }
                State::TagHeaderNoPrevSize => {
                    self.state = State::TagHeader;
                }
                State::SkipExtFlvTrailer => {
                    if self.buf.len() < EXTFLV_TRAILER_BYTES {
                        break;
                    }
                    self.buf.drain(..EXTFLV_TRAILER_BYTES);
                    self.state = State::TagHeader;
                }
                State::TagHeader => {
                    if self.buf.len() < TAG_HEADER_BYTES {
                        break;
                    }
                    let h = &self.buf[..TAG_HEADER_BYTES];
                    let tag_type = h[0];
                    // UniFi's extendedFlv format (signaled by `extendedFormat: true` in the onMetaData script tag) uses a non-standard tag header for video frames: the timestamp field comes BEFORE the data-size field (swapped relative to standard FLV). The tag type byte is 0x00 (instead of 0x09) for these video tags.
                    //
                    // Standard FLV:  type(1) + dsize(3) + ts_low(3) + ts_ext(1) + sid(3) extendedFlv:   type(1) + ts_low(3) + ts_ext(1) + dsize(3) + sid(3)
                    //
                    // The camera sends type 0x00 with a 4-byte timestamp where the standard parser reads data_size, causing a misparse (e.g. timestamp 90000 read as dsize 90000).
                    let (data_size, timestamp_ms) = if tag_type == 0x00 {
                        let ts_low = u32::from_be_bytes([0, h[1], h[2], h[3]]);
                        let ts_ext = u32::from(h[4]);
                        let dsize = u32::from_be_bytes([0, h[5], h[6], h[7]]);
                        let ts = (ts_ext << TIMESTAMP_LOW_BITS) | ts_low;
                        (dsize, ts)
                    } else {
                        let dsize = u32::from_be_bytes([0, h[1], h[2], h[3]]);
                        let ts_low = u32::from_be_bytes([0, h[4], h[5], h[6]]);
                        let ts_ext = u32::from(h[7]);
                        (dsize, (ts_ext << TIMESTAMP_LOW_BITS) | ts_low)
                    };
                    if data_size > MAX_TAG_DATA_SIZE {
                        self.state = State::Resyncing;
                        return Err(ParseError::OversizedTag { tag_type, data_size, cap: MAX_TAG_DATA_SIZE });
                    }
                    self.buf.drain(..TAG_HEADER_BYTES);
                    self.state = State::TagBody { tag_type, data_size, timestamp_ms };
                }
                State::TagBody { tag_type, data_size, timestamp_ms } => {
                    let need = data_size as usize;
                    if self.buf.len() < need {
                        break;
                    }
                    let body: Vec<u8> = self.buf.drain(..need).collect();
                    events.push(make_event(tag_type, timestamp_ms, body));
                    // UniFi's extendedFlv format omits the prev_tag_size field after type=0x00 video tags. For heartbeat/telemetry tags (dsize=0), a 5-byte trailer follows the empty body (1 flag + 4 metadata bytes). For real video frames (dsize>0), no trailer or prevtagsize follows — the next tag header starts immediately after the body.
                    self.state = if tag_type == 0x00 {
                        if data_size == 0 {
                            State::SkipExtFlvTrailer
                        } else {
                            State::TagHeaderNoPrevSize
                        }
                    } else {
                        State::PrevTagSize
                    };
                }
                State::Resyncing => {
                    // Append-only while the caller drives `resync()`. Bound the buffer so a peer streaming pure garbage cannot exhaust memory; a healthy stream resyncs within a tag or two.
                    if self.buf.len() > MAX_RESYNC_BUFFER_BYTES {
                        return Err(ParseError::ResyncBufferOverflow { len: self.buf.len(), cap: MAX_RESYNC_BUFFER_BYTES });
                    }
                    break;
                }
            }
        }
        Ok(events)
    }

    /// Scans the buffered bytes for the next plausible FLV tag boundary and, on success, recovers framing without dropping the connection. Both FLV header layouts this parser decodes are accepted: the standard layout (type bytes `{0x08, 0x09, 0x12}` with `data_size` in `h[1..4]` and the timestamp in `h[4..8]`) and UniFi's extendedFlv `0x00` swapped layout (timestamp in `h[1..5]` and `data_size` in `h[5..8]`, see `State::TagHeader`). For each candidate the 10 trailing bytes must look like a sane header of the matching layout — `data_size ≤ MAX_TAG_DATA_SIZE` and stream-id (`h[8..11]`) == 0 — and the boundary is decoded with the layout the type byte implies. On a match the garbage before the boundary plus the 11-byte header are drained, state transitions straight to `TagBody` carrying the decoded header fields, and the number of garbage bytes skipped is returned so the caller can log it. Returns `None` (leaving the buffer and `Resyncing` state untouched) when no plausible boundary is present yet — the caller feeds more bytes via `push` and retries.
    ///
    /// `0x00` candidates are validated with a two-level consistency check: after decoding the candidate's swapped header, the byte at `offset + 11 + data_size` (the start of the next tag, since extendedFlv `0x00` video tags carry no trailing previous-tag-size) must itself be a plausible tag start — either another `0x00` with a valid swapped header or a standard type `{0x08, 0x09, 0x12}` with a valid standard header. This is required because `0x00` is a common byte (it appears in timestamps, previous-tag-size fields, and stream-ids), so a single-level check would false-positive on coincidental zero runs and resync onto the middle of a tag. The two-level check demands the body's declared length land exactly on a second valid tag boundary, which a misaligned candidate does not. When the buffer does not yet contain the candidate's body plus the next 11-byte header, `None` is returned so the caller feeds more bytes and retries — resync waits for enough data to validate rather than guessing.
    pub fn resync(&mut self) -> Option<usize> {
        let mut i = 0;
        while i + TAG_HEADER_BYTES <= self.buf.len() {
            let t = self.buf[i];
            if t == TAG_TYPE_AUDIO || t == TAG_TYPE_VIDEO || t == TAG_TYPE_SCRIPT {
                let h = &self.buf[i..i + TAG_HEADER_BYTES];
                let dsize = u32::from_be_bytes([0, h[1], h[2], h[3]]);
                let sid = [h[8], h[9], h[10]];
                if dsize <= MAX_TAG_DATA_SIZE && sid == [0, 0, 0] {
                    let skipped = i;
                    let tag_type = t;
                    let ts_low = u32::from_be_bytes([0, h[4], h[5], h[6]]);
                    let ts_ext = u32::from(h[7]);
                    let timestamp_ms = (ts_ext << TIMESTAMP_LOW_BITS) | ts_low;
                    self.buf.drain(..i + TAG_HEADER_BYTES);
                    self.state = State::TagBody { tag_type, data_size: dsize, timestamp_ms };
                    return Some(skipped);
                }
            } else if t == 0x00 {
                let h = &self.buf[i..i + TAG_HEADER_BYTES];
                let ts_low = u32::from_be_bytes([0, h[1], h[2], h[3]]);
                let ts_ext = u32::from(h[4]);
                let dsize = u32::from_be_bytes([0, h[5], h[6], h[7]]);
                let sid = [h[8], h[9], h[10]];
                // `dsize > 0` excludes heartbeat/telemetry `0x00` frames (which carry a 5-byte trailer, not another tag, so the two-level check would not apply) and the common coincidental `0x00`-followed-by-zeros run whose swapped decode yields `dsize == 0`. Real video frames — the resync anchors that matter — always have `dsize > 0`.
                if dsize > 0 && dsize <= MAX_TAG_DATA_SIZE && sid == [0, 0, 0] {
                    // Two-level consistency: the byte after this tag's body (extendedFlv `0x00` video tags carry no trailing previous-tag-size) must be a plausible next-tag start. Without this, `0x00`'s ubiquity in timestamps/prev_tag_size/stream-id fields would resync onto the middle of a tag.
                    let next_start = i + TAG_HEADER_BYTES + dsize as usize;
                    if next_start + TAG_HEADER_BYTES > self.buf.len() {
                        // Not enough bytes buffered to validate the next tag; wait for more rather than guessing. The caller re-feeds and retries.
                        i += 1;
                        continue;
                    }
                    if plausible_next_tag_start(&self.buf[next_start..next_start + TAG_HEADER_BYTES]) {
                        let skipped = i;
                        let timestamp_ms = (ts_ext << TIMESTAMP_LOW_BITS) | ts_low;
                        self.buf.drain(..i + TAG_HEADER_BYTES);
                        self.state = State::TagBody { tag_type: 0x00, data_size: dsize, timestamp_ms };
                        return Some(skipped);
                    }
                }
            }
            i += 1;
        }
        None
    }

    /// True iff the framer is parked in the `Resyncing` state awaiting a successful `resync()`. The camera pipeline checks this after every `push` so it knows to drive `resync()` rather than treat an empty `Ok` as healthy silence.
    pub fn is_resyncing(&self) -> bool {
        matches!(self.state, State::Resyncing)
    }
}

impl Default for FlvParser {
    fn default() -> FlvParser {
        FlvParser::new()
    }
}

/// Validates whether an 11-byte slice at the start of the next tag (after a candidate `0x00` extendedFlv tag's body) is itself a plausible tag header, in either layout. Used by `FlvParser::resync` for the two-level consistency check that distinguishes a real `0x00` boundary from a coincidental zero run: a genuine extendedFlv tag is followed by another tag whose header validates in one of the two layouts this parser decodes.
fn plausible_next_tag_start(h: &[u8]) -> bool {
    let t = h[0];
    let sid = [h[8], h[9], h[10]];
    if sid != [0, 0, 0] {
        return false;
    }
    if t == TAG_TYPE_AUDIO || t == TAG_TYPE_VIDEO || t == TAG_TYPE_SCRIPT {
        let dsize = u32::from_be_bytes([0, h[1], h[2], h[3]]);
        dsize <= MAX_TAG_DATA_SIZE
    } else if t == 0x00 {
        let dsize = u32::from_be_bytes([0, h[5], h[6], h[7]]);
        dsize <= MAX_TAG_DATA_SIZE
    } else {
        false
    }
}

/// Maps a decoded tag header plus its payload onto the matching `TagEvent` variant. Unknown type bytes become `TagEvent::Unknown` rather than being dropped so callers can surface them.
fn make_event(tag_type: u8, timestamp_ms: u32, body: Vec<u8>) -> TagEvent {
    match tag_type {
        TAG_TYPE_AUDIO => TagEvent::Audio { timestamp_ms, body },
        // UniFi's extendedFlv uses type 0x00 for video frames (swapped-header layout — see `State::TagHeader`). Treat 0x00 as video so the video dispatcher decodes its body.
        0x00 | TAG_TYPE_VIDEO => TagEvent::Video { timestamp_ms, body },
        TAG_TYPE_SCRIPT => TagEvent::Script { timestamp_ms, body },
        other => TagEvent::Unknown { tag_type: other, timestamp_ms, body },
    }
}
