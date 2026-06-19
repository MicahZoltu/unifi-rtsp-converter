//! FLV stream parser. Detects the uPFLV magic prefix emitted by Ubiquiti's
//! `ubnt_streamer`, validates the 9-byte FLV header, and frames the
//! subsequent tag stream into `TagEvent`s via a push-based state machine
//! (`FlvParser`). Pure byte logic — no I/O, no logging — so it builds and
//! tests on any platform.

/// uPFLV magic prefix sent by Ubiquiti's `ubnt_streamer` before the FLV body,
/// per `PROJECT.md` → "Layer 1: uPFLV Magic Prefix". 11 bytes; strip when the
/// first 11 stream bytes match exactly.
pub const UPFLV_PREFIX: [u8; 11] = [
    0xDE, 0x19, 0x16, 0x15, 0x47, 0x17, 0xDE, 0x19, 0x16, 0x75, 0x50,
];

/// FLV file signature "FLV", per `PROJECT.md` → "Layer 2: Standard FLV
/// Container" (header bytes 0-2). Used to validate the start of the body.
pub const FLV_SIGNATURE: [u8; 3] = *b"FLV";

/// Minimum FLV header length in bytes: 3 signature + 1 version + 1 flags +
/// 4 header-size, per `PROJECT.md` → "FLV Header (9 bytes)".
const FLV_HEADER_SIZE: usize = 9;

/// FLV tag type for audio data, per `PROJECT.md` → "FLV Tag Structure"
/// (`0x08 = audio`).
pub const TAG_TYPE_AUDIO: u8 = 0x08;

/// FLV tag type for video data, per `PROJECT.md` → "FLV Tag Structure"
/// (`0x09 = video`).
pub const TAG_TYPE_VIDEO: u8 = 0x09;

/// FLV tag type for script data, per `PROJECT.md` → "FLV Tag Structure"
/// (`0x12 = script`).
pub const TAG_TYPE_SCRIPT: u8 = 0x12;

/// Size of the 4-byte previous-tag-size field that precedes every FLV tag,
/// per `PROJECT.md` → "FLV Tag Structure". Read and discarded by the framer.
const PREV_TAG_SIZE_BYTES: usize = 4;

/// Fixed size of an FLV tag header, per `PROJECT.md` → "FLV Tag Structure":
/// 1 type + 3 data-size + 3 timestamp-low + 1 timestamp-ext + 3 stream-id.
const TAG_HEADER_BYTES: usize = 11;

/// Number of low bits in the FLV tag timestamp (the 3-byte field); the 4th
/// byte supplies the high 8 bits, per `PROJECT.md` → "FLV Tag Structure".
const TIMESTAMP_LOW_BITS: u32 = 24;

/// Upper bound on a single tag's payload. The FLV `data_size` field is a
/// 3-byte u24 (max 16,777,215), so the cap must sit below that ceiling to be
/// reachable; 8 MiB is well above any real camera video frame (even a 4K
/// keyframe is a few MiB) while still rejecting a corrupt header claiming the
/// full u24 range, avoiding a needless 16 MiB allocation. Per
/// `plan/03-flv-tag-state-machine.md` → "Defensive Limits" (the plan's 32 MiB
/// example is adjusted here because it would exceed the u24 ceiling and never
/// fire). Exposed so callers can compare against the `cap` field of
/// `ParseError::OversizedTag`.
pub const MAX_TAG_DATA_SIZE: u32 = 8 * 1024 * 1024;

/// The only FLV version this parser supports, per `PROJECT.md` → "FLV Header"
/// (`version byte (0x01)`).
const SUPPORTED_FLV_VERSION: u8 = 1;

/// Bit mask for the audio-present flag in the FLV header flags byte (bit 0),
/// per `PROJECT.md` → "FLV Header" (`flags byte (0x07 = audio+video)`).
const FLAG_AUDIO: u8 = 0b0000_0001;

/// Bit mask for the video-present flag in the FLV header flags byte (bit 2),
/// per `PROJECT.md` → "FLV Header" (`flags byte (0x07 = audio+video)`).
const FLAG_VIDEO: u8 = 0b0000_0100;

/// Failures that can occur while parsing the FLV stream. Each variant names
/// the exact structural defect so the caller can log a meaningful message
/// without re-deriving the cause; none of them represent a crash.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum ParseError {
    /// The buffer does not yet contain a full header (or the header-declared
    /// size when it exceeds 9). Reading more bytes from the camera and
    /// retrying is the only remediation.
    Truncated,
    /// Bytes 0-2 are not the ASCII `FLV` signature, so this is not an FLV
    /// stream at the current offset. A resync scan is required.
    BadSignature,
    /// The FLV version byte is not `1`, the only version this parser
    /// supports. Returned rather than panicking so the caller can log and
    /// resync.
    UnsupportedVersion,
    /// A tag's declared `data_size` exceeds `MAX_TAG_DATA_SIZE`. The framer
    /// has dropped its buffered bytes and returned to the
    /// `PrevTagSize` state; the caller must resync the stream (see
    /// step 17). Per `plan/03-flv-tag-state-machine.md` → "Defensive Limits".
    OversizedTag {
        /// The tag-type byte from the offending tag header.
        tag_type: u8,
        /// The declared payload size that exceeded the cap.
        data_size: u32,
        /// The cap the declared size exceeded (`MAX_TAG_DATA_SIZE`).
        cap: u32,
    },
}

/// Parsed FLV header. The remaining stream bytes (after the header and any
/// declared skip) are returned alongside this struct by `parse_header`.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct FlvHeader {
    /// FLV container version byte. Always `1` for streams this parser
    /// accepts; stored verbatim for diagnostics.
    pub version: u8,
    /// True iff the flags byte's audio bit is set.
    pub has_audio: bool,
    /// True iff the flags byte's video bit is set.
    pub has_video: bool,
    /// Header-size field from bytes 5-8 (big-endian u32). Per spec it is 9;
    /// larger values declare extra skip bytes that `parse_header` consumes.
    pub header_size: u32,
}

/// Returns the FLV body slice with the 11-byte uPFLV magic prefix stripped,
/// or `buf` unchanged when no prefix is present. Per `PROJECT.md` → "Layer
/// 1", a mismatched first 11 bytes are treated as no prefix (not an error):
/// the camera may omit the prefix in some configurations, and random 11
/// bytes must never be mistaken for it.
pub fn detect_and_strip_prefix(buf: &[u8]) -> &[u8] {
    if buf.len() >= UPFLV_PREFIX.len() && buf[..UPFLV_PREFIX.len()] == UPFLV_PREFIX {
        &buf[UPFLV_PREFIX.len()..]
    } else {
        buf
    }
}

/// Parses the FLV header from the start of `buf` and returns the parsed
/// `FlvHeader` plus the remaining stream bytes (after the 9-byte header and
/// any declared skip when the header-size field exceeds 9).
///
/// Errors are returned as structured `ParseError` variants rather than
/// panicking, so the caller can log and resync. The signature bytes are
/// validated first, then the version, then the declared size.
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
    Ok((
        &buf[end..],
        FlvHeader {
            version,
            has_audio,
            has_video,
            header_size,
        },
    ))
}

/// One fully-framed FLV tag emitted by `FlvParser::push`. The payload is
/// opaque at this stage — steps 04-06 decode video/audio/script bodies — so
/// only the tag type, timestamp, and raw body are reported.
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum TagEvent {
    /// Script-data tag (type `0x12`), e.g. `onMetaData` / `onMpma` /
    /// `onClockSync` per `PROJECT.md` → "Script Data Tags".
    Script {
        /// 32-bit FLV tag timestamp in milliseconds.
        timestamp_ms: u32,
        /// Raw tag payload, undecoded.
        body: Vec<u8>,
    },
    /// Audio tag (type `0x08`). Audio is not served by this proxy but is
    /// still framed so the caller can count or skip it.
    Audio {
        /// 32-bit FLV tag timestamp in milliseconds.
        timestamp_ms: u32,
        /// Raw tag payload, undecoded.
        body: Vec<u8>,
    },
    /// Video tag (type `0x09`).
    Video {
        /// 32-bit FLV tag timestamp in milliseconds.
        timestamp_ms: u32,
        /// Raw tag payload, undecoded.
        body: Vec<u8>,
    },
    /// Any tag whose type byte is not `0x08` / `0x09` / `0x12`. Reported
    /// rather than dropped so the caller can log unexpected types.
    Unknown {
        /// The raw tag-type byte.
        tag_type: u8,
        /// 32-bit FLV tag timestamp in milliseconds.
        timestamp_ms: u32,
        /// Raw tag payload, undecoded.
        body: Vec<u8>,
    },
}

/// Internal framer state. The parser starts in `PrevTagSize` because
/// `parse_header` consumes the FLV header; the body that follows begins with
/// the leading 4-byte previous-tag-size (zero on a fresh stream).
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum State {
    /// Waiting for the 4-byte previous-tag-size field (read and discarded).
    PrevTagSize,
    /// Waiting for the 11-byte tag header.
    TagHeader,
    /// Waiting for `data_size` payload bytes, carrying the just-decoded
    /// header fields so the completed `TagEvent` can be emitted.
    TagBody {
        tag_type: u8,
        data_size: u32,
        timestamp_ms: u32,
    },
}

/// Push-based, incremental FLV tag framer. The caller runs `parse_header`
/// once up-front (after `detect_and_strip_prefix`), then feeds every
/// subsequent byte chunk here. Partial trailing bytes stay buffered across
/// `push` calls, so the parser handles arbitrary TCP read boundaries without
/// panicking.
#[derive(Debug, Clone)]
pub struct FlvParser {
    state: State,
    buf: Vec<u8>,
}

impl FlvParser {
    /// Creates a framer in the `PrevTagSize` state with an empty
    /// buffer. Feed it the bytes that follow the FLV header.
    pub fn new() -> FlvParser {
        FlvParser {
            state: State::PrevTagSize,
            buf: Vec::new(),
        }
    }

    /// Appends `chunk` to the internal buffer and drains as many complete
    /// tags as possible, returning their events in stream order. Partial
    /// trailing bytes stay buffered for the next call.
    ///
    /// A tag whose declared `data_size` exceeds `MAX_TAG_DATA_SIZE` yields
    /// `Err(ParseError::OversizedTag)` — the framer resets to the
    /// `PrevTagSize` state and drops its buffer so no multi-GiB
    /// allocation occurs; the caller must resync (step 17).
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
                State::TagHeader => {
                    if self.buf.len() < TAG_HEADER_BYTES {
                        break;
                    }
                    let h = &self.buf[..TAG_HEADER_BYTES];
                    let tag_type = h[0];
                    let data_size = u32::from_be_bytes([0, h[1], h[2], h[3]]);
                    let ts_low = u32::from_be_bytes([0, h[4], h[5], h[6]]);
                    let ts_ext = u32::from(h[7]);
                    let timestamp_ms = (ts_ext << TIMESTAMP_LOW_BITS) | ts_low;
                    if data_size > MAX_TAG_DATA_SIZE {
                        self.buf.clear();
                        self.state = State::PrevTagSize;
                        return Err(ParseError::OversizedTag {
                            tag_type,
                            data_size,
                            cap: MAX_TAG_DATA_SIZE,
                        });
                    }
                    self.buf.drain(..TAG_HEADER_BYTES);
                    self.state = State::TagBody {
                        tag_type,
                        data_size,
                        timestamp_ms,
                    };
                }
                State::TagBody {
                    tag_type,
                    data_size,
                    timestamp_ms,
                } => {
                    let need = data_size as usize;
                    if self.buf.len() < need {
                        break;
                    }
                    let body: Vec<u8> = self.buf.drain(..need).collect();
                    events.push(make_event(tag_type, timestamp_ms, body));
                    self.state = State::PrevTagSize;
                }
            }
        }
        Ok(events)
    }
}

impl Default for FlvParser {
    fn default() -> FlvParser {
        FlvParser::new()
    }
}

/// Maps a decoded tag header plus its payload onto the matching `TagEvent`
/// variant. Unknown type bytes become `TagEvent::Unknown` rather than being
/// dropped so callers can surface them.
fn make_event(tag_type: u8, timestamp_ms: u32, body: Vec<u8>) -> TagEvent {
    match tag_type {
        TAG_TYPE_AUDIO => TagEvent::Audio { timestamp_ms, body },
        TAG_TYPE_VIDEO => TagEvent::Video { timestamp_ms, body },
        TAG_TYPE_SCRIPT => TagEvent::Script { timestamp_ms, body },
        other => TagEvent::Unknown {
            tag_type: other,
            timestamp_ms,
            body,
        },
    }
}
