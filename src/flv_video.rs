//! FLV video-tag dispatcher: routes a framed `0x09` (or UniFi `0x00`) video-tag payload through the standard or `ExVideoTagHeader` (extended) path selected by bit 7 of its first byte, per `PROJECT.md` → "Layer 3". Both paths strip their FLV preamble here and converge on the pure `avc` codec helpers (`parse_avc_config`, `split_length_prefixed_nalus`), so downstream consumers (stream state, RTP) need not distinguish the source layout. Pure byte logic — no I/O, no logging, no framer state — so it builds and tests on any platform. Split from `flv_parser` so the byte framer and the video-tag codec routing each have one reason to change.

use crate::avc::{parse_avc_config, split_length_prefixed_nalus, AvcDecoderConfig, AvcError, AvcPacketType, NaluFrame};
use crate::flv_parser::ParseError;

// --- ExVideoTagHeader / standard video-tag first-byte layout ---
//
// The first byte of a `0x09` video-tag payload selects one of two layouts, per `PROJECT.md` → "Layer 3: Extended FLV Video Tags". Bit 7 is `IsExHeader`: clear ⇒ standard (`[FrameType:4][CodecID:4]`), set ⇒ extended (`[1][FrameType:3][PacketType:4]` + 4-byte FourCC).

/// Bit 7 of the video-tag first byte: set iff the tag uses the ExVideoTagHeader layout.
const EX_HEADER_FLAG: u8 = 0x80;

/// Mask for the FrameType nibble (bits 4-7) of a standard video-tag first byte, per `PROJECT.md` → "Video tag parsing (standard path)".
const STD_FRAME_TYPE_MASK: u8 = 0xF0;

/// Number of bytes in the fixed AVC video-tag preamble that precede either an AVCDecoderConfigurationRecord (AVCPacketType=0) or a length-prefixed NALU list (AVCPacketType=1): frame/codec byte + AVCPacketType byte + 3-byte composition-time SI24, per `PROJECT.md` → "Standard FLV Video Tag (CodecID=7, AVC)". An FLV-tag-layer concept owned here (not in `avc`) so the codec module keeps no FLV tag-header knowledge — `avc` parses only the codec body this dispatcher hands it.
const AVC_NALU_PREAMBLE_BYTES: usize = 5;

/// Shift placing the standard FrameType nibble into the low bits.
const STD_FRAME_TYPE_SHIFT: u32 = 4;

/// Mask for the CodecID nibble (bits 0-3) of a standard video-tag first byte, per `PROJECT.md` → "Video tag parsing (standard path)".
const STD_CODEC_ID_MASK: u8 = 0x0F;

/// CodecID for H.264 / AVC in a standard video tag, the only video codec this proxy serves. Declared at the FLV layer (not imported from `avc`) so the dispatcher's CodecID routing stays self-contained and `avc` keeps no FLV tag-header knowledge.
const STD_CODEC_ID_AVC: u8 = 7;

/// FrameType value meaning a keyframe, shared by the standard and extended paths, per `PROJECT.md` → "Video tag parsing" (`1=keyframe`).
const FRAME_TYPE_KEYFRAME: u8 = 1;

/// Mask for the FrameType field (bits 4-6) of an ExVideoTagHeader first byte, per `PROJECT.md` → "Video tag parsing (extended path)".
const EXT_FRAME_TYPE_MASK: u8 = 0x70;

/// Shift placing the extended FrameType field into the low bits.
const EXT_FRAME_TYPE_SHIFT: u32 = 4;

/// Mask for the PacketType field (bits 0-3) of an ExVideoTagHeader first byte, per `PROJECT.md` → "PacketType values".
const EXT_PACKET_TYPE_MASK: u8 = 0x0F;

/// Offset of the 4-byte FourCC in an extended video tag (immediately after the first byte), per `PROJECT.md` → "Extended FLV Video Tag".
const EXT_FOURCC_OFFSET: usize = 1;

/// Length of the FourCC field (bytes 1-4) in an extended video tag.
const EXT_FOURCC_BYTES: usize = 4;

/// Offset of the PacketType-specific body in an extended video tag: first byte + 4-byte FourCC = 5 bytes.
const EXT_BODY_OFFSET: usize = EXT_FOURCC_OFFSET + EXT_FOURCC_BYTES;

/// Size of the composition-time SI24 field that follows the ExVideoTagHeader in a CodedFrames (PacketType 1) tag, per `PROJECT.md` → "Extended FLV Video Tag".
const EXT_COMP_TIME_BYTES: usize = 3;

/// ExVideoTagHeader PacketType 0 = SequenceStart (codec config record follows), per `PROJECT.md` → "PacketType values".
const PKT_TYPE_SEQUENCE_START: u8 = 0;
/// ExVideoTagHeader PacketType 1 = CodedFrames (composition time + NALUs).
const PKT_TYPE_CODED_FRAMES: u8 = 1;
/// ExVideoTagHeader PacketType 2 = SequenceEnd.
const PKT_TYPE_SEQUENCE_END: u8 = 2;
/// ExVideoTagHeader PacketType 3 = CodedFramesX (NALUs, no composition time).
const PKT_TYPE_CODED_FRAMES_X: u8 = 3;
/// ExVideoTagHeader PacketType 4 = Metadata.
const PKT_TYPE_METADATA: u8 = 4;

/// FourCC identifying an H.264 / AVC extended video tag, per the Enhanced RTMP spec referenced by `PROJECT.md` → "Extended FLV Video Tag".
const FOURCC_AVC1: [u8; EXT_FOURCC_BYTES] = *b"avc1";

/// Which video-tag layout the first payload byte selects, per `PROJECT.md` → "Layer 3": bit 7 clear ⇒ `Standard` (`[FrameType:4][CodecID:4]`), bit 7 set ⇒ `Extended` (`[1][FrameType:3][PacketType:4]` + FourCC).
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum VideoTagKind {
    /// Standard FLV video tag (no ExVideoTagHeader).
    Standard,
    /// Extended FLV video tag (ExVideoTagHeader set).
    Extended,
}

/// Classifies the video-tag layout from its first byte, mirroring the `is_ex_header` test in `PROJECT.md` → "Layer 3".
pub fn video_tag_kind(first_byte: u8) -> VideoTagKind {
    if (first_byte & EX_HEADER_FLAG) != 0 {
        VideoTagKind::Extended
    } else {
        VideoTagKind::Standard
    }
}

/// Reason a structurally-valid video tag was skipped rather than decoded. Carried by `VideoTagEvent::Ignored` so the caller can log a specific cause without re-deriving it.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum IgnoreReason {
    /// Standard-path CodecID nibble was not `7` (AVC); carries the offending CodecID so non-AVC codecs (e.g. ScreenVideo) are logged precisely.
    NotAvcCodec(u8),
    /// Extended-path FourCC was not `avc1` (e.g. `hvc1` for H.265/HEVC, which this proxy does not serve); carries the offending 4 bytes.
    NotAvcFourCC([u8; EXT_FOURCC_BYTES]),
    /// The standard AVCPacketType or extended PacketType held an unknown value not covered by the spec; carries the offending byte.
    UnknownPacketType(u8),
}

/// Outcome of dispatching an FLV video-tag payload. Both the standard and extended paths converge on the shared `AvcDecoderConfig` / `NaluFrame` types from `avc`, so downstream consumers (stream state, RTP) need not distinguish the source layout.
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum VideoTagEvent {
    /// AVCDecoderConfigurationRecord decoded from either a standard AVCPacketType=0 tag or an extended PacketType=0 (SequenceStart) tag.
    Config(AvcDecoderConfig),
    /// One or more length-prefixed H.264 NALUs decoded into a `NaluFrame`, from either a standard AVCPacketType=1 tag or an extended PacketType=1/3 (CodedFrames/CodedFramesX) tag.
    Frame(NaluFrame),
    /// End-of-sequence marker (standard AVCPacketType=2 or extended PacketType=2). No payload of interest.
    SequenceEnd,
    /// Extended PacketType=4 Metadata tag; payload discarded, not retained.
    Metadata,
    /// Tag was structurally valid but not consumable by this proxy (non-AVC codec, unsupported FourCC, or unknown packet type). See `IgnoreReason` for the specific cause.
    Ignored(IgnoreReason),
}

/// Dispatches an FLV video-tag payload through the standard or extended path selected by bit 7 of its first byte, per `PROJECT.md` → "Layer 3". Both paths strip their FLV preamble in this module and converge on the pure `avc` codec helpers (`parse_avc_config`, `split_length_prefixed_nalus`).
///
/// The payload is the raw `body` that the framer emits for a `0x09` video tag — no FLV tag header, no previous-tag-size. Truncation detected anywhere (dispatcher preamble checks or codec-level NALU/config reads) collapses to `ParseError::Truncated` so the caller's resync logic need only watch one variant; other codec failures surface as `ParseError::Codec`.
pub fn parse_video_tag(payload: &[u8]) -> Result<VideoTagEvent, ParseError> {
    let first = payload.first().copied().ok_or(ParseError::Truncated)?;
    match video_tag_kind(first) {
        VideoTagKind::Standard => parse_standard_video_tag(payload),
        VideoTagKind::Extended => parse_extended_video_tag(payload),
    }
}

/// Standard-path dispatcher: bit 7 clear. Strips the standard AVC preamble (frame/codec byte, `AVCPacketType`, composition-time SI24) here and routes the codec body to `parse_avc_config` for sequence headers or `split_length_prefixed_nalus` for NALU payloads — mirroring the extended path's preamble-then-codec split. Non-AVC codecs and unknown packet types become `Ignored` rather than errors so the caller can log and continue.
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
            let cfg = parse_avc_config(&payload[AVC_NALU_PREAMBLE_BYTES..]).map_err(lift_avc_err)?;
            Ok(VideoTagEvent::Config(cfg))
        }
        Some(AvcPacketType::Nalu) => {
            if payload.len() < AVC_NALU_PREAMBLE_BYTES {
                return Err(ParseError::Truncated);
            }
            let nalus = split_length_prefixed_nalus(&payload[AVC_NALU_PREAMBLE_BYTES..]).map_err(lift_avc_err)?;
            Ok(VideoTagEvent::Frame(NaluFrame { is_keyframe, nalus }))
        }
        Some(AvcPacketType::End) => Ok(VideoTagEvent::SequenceEnd),
        None => Ok(VideoTagEvent::Ignored(IgnoreReason::UnknownPacketType(packet_type_byte))),
    }
}

/// Extended-path dispatcher: bit 7 set (ExVideoTagHeader). Parses the FourCC and PacketType, then routes to the same `avc` codec helpers as the standard path. Non-`avc1` FourCCs (e.g. `hvc1`) become `Ignored` before any NALU parse is attempted.
fn parse_extended_video_tag(payload: &[u8]) -> Result<VideoTagEvent, ParseError> {
    if payload.len() < EXT_BODY_OFFSET {
        return Err(ParseError::Truncated);
    }
    let header_byte = payload[0];
    let frame_type = (header_byte & EXT_FRAME_TYPE_MASK) >> EXT_FRAME_TYPE_SHIFT;
    let packet_type = header_byte & EXT_PACKET_TYPE_MASK;
    let fourcc = [payload[EXT_FOURCC_OFFSET], payload[EXT_FOURCC_OFFSET + 1], payload[EXT_FOURCC_OFFSET + 2], payload[EXT_FOURCC_OFFSET + 3]];
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
            let nalus = split_length_prefixed_nalus(&payload[EXT_BODY_OFFSET..]).map_err(lift_avc_err)?;
            Ok(VideoTagEvent::Frame(NaluFrame { is_keyframe, nalus }))
        }
        PKT_TYPE_SEQUENCE_END => Ok(VideoTagEvent::SequenceEnd),
        PKT_TYPE_METADATA => Ok(VideoTagEvent::Metadata),
        other => Ok(VideoTagEvent::Ignored(IgnoreReason::UnknownPacketType(other))),
    }
}

/// Lifts an `AvcError` into a `ParseError`: truncation collapses to `ParseError::Truncated` (uniform with the dispatcher's own preamble checks); every other codec failure wraps as `ParseError::Codec` so the caller still sees a structured, loggable cause.
fn lift_avc_err(err: AvcError) -> ParseError {
    match err {
        AvcError::Truncated => ParseError::Truncated,
        other => ParseError::Codec(other),
    }
}
