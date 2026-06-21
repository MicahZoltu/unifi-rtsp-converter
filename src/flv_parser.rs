//! FLV stream parser. Detects the uPFLV magic prefix emitted by Ubiquiti's
//! `ubnt_streamer`, validates the 9-byte FLV header, frames the
//! subsequent tag stream into `TagEvent`s via a push-based state machine
//! (`FlvParser`), and dispatches each video-tag payload through the standard
//! or `ExVideoTagHeader` (extended) path. Pure byte logic — no I/O, no
//! logging — so it builds and tests on any platform.

use crate::avc::{
    parse_avc_config, split_length_prefixed_nalus, AvcDecoderConfig, AvcError, AvcPacketType,
    NaluFrame, AVC_NALU_PREAMBLE_BYTES,
};

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

// --- ExVideoTagHeader / standard video-tag first-byte layout ---
//
// The first byte of a `0x09` video-tag payload selects one of two layouts,
// per `PROJECT.md` → "Layer 3: Extended FLV Video Tags". Bit 7 is
// `IsExHeader`: clear ⇒ standard (`[FrameType:4][CodecID:4]`), set ⇒
// extended (`[1][FrameType:3][PacketType:4]` + 4-byte FourCC).

/// Bit 7 of the video-tag first byte: set iff the tag uses the
/// ExVideoTagHeader layout.
const EX_HEADER_FLAG: u8 = 0x80;

/// Mask for the FrameType nibble (bits 4-7) of a standard video-tag first
/// byte, per `PROJECT.md` → "Video tag parsing (standard path)".
const STD_FRAME_TYPE_MASK: u8 = 0xF0;

/// Shift placing the standard FrameType nibble into the low bits.
const STD_FRAME_TYPE_SHIFT: u32 = 4;

/// Mask for the CodecID nibble (bits 0-3) of a standard video-tag first
/// byte, per `PROJECT.md` → "Video tag parsing (standard path)".
const STD_CODEC_ID_MASK: u8 = 0x0F;

/// CodecID for H.264 / AVC in a standard video tag, the only video codec
/// this proxy serves. Declared at the FLV layer (not imported from `avc`)
/// so the dispatcher's CodecID routing stays self-contained and `avc` keeps
/// no FLV tag-header knowledge.
const STD_CODEC_ID_AVC: u8 = 7;

/// FrameType value meaning a keyframe, shared by the standard and extended
/// paths, per `PROJECT.md` → "Video tag parsing" (`1=keyframe`).
const FRAME_TYPE_KEYFRAME: u8 = 1;

/// Mask for the FrameType field (bits 4-6) of an ExVideoTagHeader first
/// byte, per `PROJECT.md` → "Video tag parsing (extended path)".
const EXT_FRAME_TYPE_MASK: u8 = 0x70;

/// Shift placing the extended FrameType field into the low bits.
const EXT_FRAME_TYPE_SHIFT: u32 = 4;

/// Mask for the PacketType field (bits 0-3) of an ExVideoTagHeader first
/// byte, per `PROJECT.md` → "PacketType values".
const EXT_PACKET_TYPE_MASK: u8 = 0x0F;

/// Offset of the 4-byte FourCC in an extended video tag (immediately after
/// the first byte), per `PROJECT.md` → "Extended FLV Video Tag".
const EXT_FOURCC_OFFSET: usize = 1;

/// Length of the FourCC field (bytes 1-4) in an extended video tag.
const EXT_FOURCC_BYTES: usize = 4;

/// Offset of the PacketType-specific body in an extended video tag: first
/// byte + 4-byte FourCC = 5 bytes.
const EXT_BODY_OFFSET: usize = EXT_FOURCC_OFFSET + EXT_FOURCC_BYTES;

/// Size of the composition-time SI24 field that follows the ExVideoTagHeader
/// in a CodedFrames (PacketType 1) tag, per `PROJECT.md` → "Extended FLV
/// Video Tag".
const EXT_COMP_TIME_BYTES: usize = 3;

/// ExVideoTagHeader PacketType 0 = SequenceStart (codec config record
/// follows), per `PROJECT.md` → "PacketType values".
const PKT_TYPE_SEQUENCE_START: u8 = 0;
/// ExVideoTagHeader PacketType 1 = CodedFrames (composition time + NALUs).
const PKT_TYPE_CODED_FRAMES: u8 = 1;
/// ExVideoTagHeader PacketType 2 = SequenceEnd.
const PKT_TYPE_SEQUENCE_END: u8 = 2;
/// ExVideoTagHeader PacketType 3 = CodedFramesX (NALUs, no composition time).
const PKT_TYPE_CODED_FRAMES_X: u8 = 3;
/// ExVideoTagHeader PacketType 4 = Metadata.
const PKT_TYPE_METADATA: u8 = 4;

/// FourCC identifying an H.264 / AVC extended video tag, per the Enhanced
/// RTMP spec referenced by `PROJECT.md` → "Extended FLV Video Tag".
const FOURCC_AVC1: [u8; EXT_FOURCC_BYTES] = *b"avc1";

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
    /// `PrevTagSize` state; the caller must resync the stream (handled in the
    /// resync step). Per `plan/03-flv-tag-state-machine.md` → "Defensive Limits".
    OversizedTag {
        /// The tag-type byte from the offending tag header.
        tag_type: u8,
        /// The declared payload size that exceeded the cap.
        data_size: u32,
        /// The cap the declared size exceeded (`MAX_TAG_DATA_SIZE`).
        cap: u32,
    },
    /// A video-tag payload routed into the codec layer (`avc`) returned a
    /// non-truncation error (e.g. a malformed AVCDecoderConfigurationRecord).
    /// Truncation is lifted to `ParseError::Truncated` by the dispatcher so
    /// the caller's resync logic need only watch one truncation variant;
    /// every other `AvcError` surfaces here unchanged.
    Codec(AvcError),
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
    /// Waiting for the 11-byte tag header. Used after a type=0x00 extendedFlv
    /// video tag — the extendedFlv format omits the prev_tag_size field after
    /// these tags, so the parser jumps straight to the next tag header.
    TagHeaderNoPrevSize,
    /// Skipping a fixed 5-byte trailer that follows type=0x00 extendedFlv
    /// video tags with dsize=0 (heartbeat/telemetry frames). The trailer is
    /// 1 byte (flags?) + 4 bytes (metadata, possibly FPS as IEEE 754 float).
    /// After skipping, the parser reads the next tag header directly.
    SkipExtFlvTrailer,
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

/// Size of the 5-byte trailer after a type=0x00 extendedFlv video tag with
/// dsize=0 (heartbeat/telemetry frame): 1 flag byte + 4 metadata bytes.
const EXTFLV_TRAILER_BYTES: usize = 5;

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
    /// allocation occurs; the caller must resync (handled in the resync step).
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
                    // UniFi's extendedFlv format (signaled by `extendedFormat: true`
                    // in the onMetaData script tag) uses a non-standard tag header
                    // for video frames: the timestamp field comes BEFORE the
                    // data-size field (swapped relative to standard FLV). The tag
                    // type byte is 0x00 (instead of 0x09) for these video tags.
                    // Standard FLV: type(1) + dsize(3) + ts_low(3) + ts_ext(1) + sid(3)
                    // extendedFlv:  type(1) + ts_low(3) + ts_ext(1) + dsize(3) + sid(3)
                    // Discovered via step-21 human test against a UVC G5 Bullet
                    // (fw 4.73.112) — the camera sends type 0x00 with a 4-byte
                    // timestamp where the standard parser reads data_size, causing
                    // a misparse (e.g. timestamp 90000 read as dsize 90000).
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
                    // UniFi's extendedFlv format omits the prev_tag_size field
                    // after type=0x00 video tags. For heartbeat/telemetry tags
                    // (dsize=0), a 5-byte trailer follows the empty body
                    // (1 flag + 4 metadata bytes). For real video frames
                    // (dsize>0), no trailer or prevtagsize follows — the next
                    // tag header starts immediately after the body.
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

/// Which video-tag layout the first payload byte selects, per
/// `PROJECT.md` → "Layer 3": bit 7 clear ⇒ `Standard`
/// (`[FrameType:4][CodecID:4]`), bit 7 set ⇒ `Extended`
/// (`[1][FrameType:3][PacketType:4]` + FourCC).
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum VideoTagKind {
    /// Standard FLV video tag (no ExVideoTagHeader).
    Standard,
    /// Extended FLV video tag (ExVideoTagHeader set).
    Extended,
}

/// Classifies the video-tag layout from its first byte, mirroring the
/// `is_ex_header` test in `PROJECT.md` → "Layer 3".
pub fn video_tag_kind(first_byte: u8) -> VideoTagKind {
    if (first_byte & EX_HEADER_FLAG) != 0 {
        VideoTagKind::Extended
    } else {
        VideoTagKind::Standard
    }
}

/// Reason a structurally-valid video tag was skipped rather than decoded.
/// Carried by `VideoTagEvent::Ignored` so the caller can log a specific
/// cause without re-deriving it.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum IgnoreReason {
    /// Standard-path CodecID nibble was not `7` (AVC); carries the offending
    /// CodecID so non-AVC codecs (e.g. ScreenVideo) are logged precisely.
    NotAvcCodec(u8),
    /// Extended-path FourCC was not `avc1` (e.g. `hvc1` for H.265/HEVC, which
    /// this proxy does not serve); carries the offending 4 bytes.
    NotAvcFourCC([u8; EXT_FOURCC_BYTES]),
    /// The standard AVCPacketType or extended PacketType held an unknown
    /// value not covered by the spec; carries the offending byte.
    UnknownPacketType(u8),
}

/// Outcome of dispatching an FLV video-tag payload. Both the standard and
/// extended paths converge on the shared `AvcDecoderConfig` / `NaluFrame`
/// types from `avc`, so downstream consumers (stream state, RTP) need not
/// distinguish the source layout.
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum VideoTagEvent {
    /// AVCDecoderConfigurationRecord decoded from either a standard
    /// AVCPacketType=0 tag or an extended PacketType=0 (SequenceStart) tag.
    Config(AvcDecoderConfig),
    /// One or more length-prefixed H.264 NALUs decoded into a `NaluFrame`,
    /// from either a standard AVCPacketType=1 tag or an extended
    /// PacketType=1/3 (CodedFrames/CodedFramesX) tag.
    Frame(NaluFrame),
    /// End-of-sequence marker (standard AVCPacketType=2 or extended
    /// PacketType=2). No payload of interest.
    SequenceEnd,
    /// Extended PacketType=4 Metadata tag; payload discarded, not retained.
    Metadata,
    /// Tag was structurally valid but not consumable by this proxy (non-AVC
    /// codec, unsupported FourCC, or unknown packet type). See
    /// `IgnoreReason` for the specific cause.
    Ignored(IgnoreReason),
}

/// Dispatches an FLV video-tag payload through the standard or extended path
/// selected by bit 7 of its first byte, per `PROJECT.md` → "Layer 3" and
/// `plan/05-extended-video-tags.md`. Both paths strip their FLV preamble in
/// this module and converge on the pure `avc` codec helpers
/// (`parse_avc_config`, `split_length_prefixed_nalus`).
///
/// The payload is the raw `body` that the framer emits for a `0x09` video
/// tag — no FLV tag header, no previous-tag-size. Truncation detected
/// anywhere (dispatcher preamble checks or codec-level NALU/config reads)
/// collapses to `ParseError::Truncated` so the caller's resync logic need
/// only watch one variant; other codec failures surface as
/// `ParseError::Codec`.
pub fn parse_video_tag(payload: &[u8]) -> Result<VideoTagEvent, ParseError> {
    let first = payload.first().copied().ok_or(ParseError::Truncated)?;
    match video_tag_kind(first) {
        VideoTagKind::Standard => parse_standard_video_tag(payload),
        VideoTagKind::Extended => parse_extended_video_tag(payload),
    }
}

/// Standard-path dispatcher: bit 7 clear. Strips the standard AVC preamble
/// (frame/codec byte, `AVCPacketType`, composition-time SI24) here and routes
/// the codec body to `parse_avc_config` for sequence headers or
/// `split_length_prefixed_nalus` for NALU payloads — mirroring the extended
/// path's preamble-then-codec split. Non-AVC codecs and unknown packet types
/// become `Ignored` rather than errors so the caller can log and continue.
fn parse_standard_video_tag(payload: &[u8]) -> Result<VideoTagEvent, ParseError> {
    let frame_codec = payload.first().copied().ok_or(ParseError::Truncated)?;
    if payload.len() < 2 {
        return Err(ParseError::Truncated);
    }
    let frame_type = (frame_codec & STD_FRAME_TYPE_MASK) >> STD_FRAME_TYPE_SHIFT;
    let codec_id = frame_codec & STD_CODEC_ID_MASK;
    if codec_id != STD_CODEC_ID_AVC {
        return Ok(VideoTagEvent::Ignored(IgnoreReason::NotAvcCodec(codec_id)));
    }
    let packet_type_byte = payload[1];
    let is_keyframe = frame_type == FRAME_TYPE_KEYFRAME;
    match AvcPacketType::from_byte(packet_type_byte) {
        Some(AvcPacketType::SeqHeader) => {
            if payload.len() < AVC_NALU_PREAMBLE_BYTES {
                return Err(ParseError::Truncated);
            }
            let cfg =
                parse_avc_config(&payload[AVC_NALU_PREAMBLE_BYTES..]).map_err(lift_avc_err)?;
            Ok(VideoTagEvent::Config(cfg))
        }
        Some(AvcPacketType::Nalu) => {
            if payload.len() < AVC_NALU_PREAMBLE_BYTES {
                return Err(ParseError::Truncated);
            }
            let nalus = split_length_prefixed_nalus(&payload[AVC_NALU_PREAMBLE_BYTES..])
                .map_err(lift_avc_err)?;
            Ok(VideoTagEvent::Frame(NaluFrame { is_keyframe, nalus }))
        }
        Some(AvcPacketType::End) => Ok(VideoTagEvent::SequenceEnd),
        None => Ok(VideoTagEvent::Ignored(IgnoreReason::UnknownPacketType(
            packet_type_byte,
        ))),
    }
}

/// Extended-path dispatcher: bit 7 set (ExVideoTagHeader). Parses the FourCC
/// and PacketType, then routes to the same `avc` codec helpers as the
/// standard path. Non-`avc1` FourCCs (e.g. `hvc1`) become `Ignored` before
/// any NALU parse is attempted, per `plan/05-extended-video-tags.md`.
fn parse_extended_video_tag(payload: &[u8]) -> Result<VideoTagEvent, ParseError> {
    if payload.len() < EXT_BODY_OFFSET {
        return Err(ParseError::Truncated);
    }
    let header_byte = payload[0];
    let frame_type = (header_byte & EXT_FRAME_TYPE_MASK) >> EXT_FRAME_TYPE_SHIFT;
    let packet_type = header_byte & EXT_PACKET_TYPE_MASK;
    let fourcc = [
        payload[EXT_FOURCC_OFFSET],
        payload[EXT_FOURCC_OFFSET + 1],
        payload[EXT_FOURCC_OFFSET + 2],
        payload[EXT_FOURCC_OFFSET + 3],
    ];
    if fourcc != FOURCC_AVC1 {
        return Ok(VideoTagEvent::Ignored(IgnoreReason::NotAvcFourCC(fourcc)));
    }
    let is_keyframe = frame_type == FRAME_TYPE_KEYFRAME;
    match packet_type {
        PKT_TYPE_SEQUENCE_START => {
            let cfg = parse_avc_config(&payload[EXT_BODY_OFFSET..]).map_err(lift_avc_err)?;
            Ok(VideoTagEvent::Config(cfg))
        }
        PKT_TYPE_CODED_FRAMES => {
            let comp_end = EXT_BODY_OFFSET + EXT_COMP_TIME_BYTES;
            if payload.len() < comp_end {
                return Err(ParseError::Truncated);
            }
            let nalus = split_length_prefixed_nalus(&payload[comp_end..]).map_err(lift_avc_err)?;
            Ok(VideoTagEvent::Frame(NaluFrame { is_keyframe, nalus }))
        }
        PKT_TYPE_CODED_FRAMES_X => {
            let nalus =
                split_length_prefixed_nalus(&payload[EXT_BODY_OFFSET..]).map_err(lift_avc_err)?;
            Ok(VideoTagEvent::Frame(NaluFrame { is_keyframe, nalus }))
        }
        PKT_TYPE_SEQUENCE_END => Ok(VideoTagEvent::SequenceEnd),
        PKT_TYPE_METADATA => Ok(VideoTagEvent::Metadata),
        other => Ok(VideoTagEvent::Ignored(IgnoreReason::UnknownPacketType(
            other,
        ))),
    }
}

/// Lifts an `AvcError` into a `ParseError`: truncation collapses to
/// `ParseError::Truncated` (uniform with the dispatcher's own preamble
/// checks); every other codec failure wraps as `ParseError::Codec` so the
/// caller still sees a structured, loggable cause.
fn lift_avc_err(err: AvcError) -> ParseError {
    match err {
        AvcError::Truncated => ParseError::Truncated,
        other => ParseError::Codec(other),
    }
}

/// Maps a decoded tag header plus its payload onto the matching `TagEvent`
/// variant. Unknown type bytes become `TagEvent::Unknown` rather than being
/// dropped so callers can surface them.
fn make_event(tag_type: u8, timestamp_ms: u32, body: Vec<u8>) -> TagEvent {
    match tag_type {
        TAG_TYPE_AUDIO => TagEvent::Audio { timestamp_ms, body },
        // UniFi's extendedFlv uses type 0x00 for video frames (swapped-header
        // layout — see `State::TagHeader`). Treat 0x00 as video so the video
        // dispatcher decodes its body.
        0x00 | TAG_TYPE_VIDEO => TagEvent::Video { timestamp_ms, body },
        TAG_TYPE_SCRIPT => TagEvent::Script { timestamp_ms, body },
        other => TagEvent::Unknown {
            tag_type: other,
            timestamp_ms,
            body,
        },
    }
}
