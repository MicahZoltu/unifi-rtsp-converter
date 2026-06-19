//! FLV stream parser. Detects the uPFLV magic prefix emitted by Ubiquiti's
//! `ubnt_streamer`, validates the 9-byte FLV header, and returns the remaining
//! stream bytes for the tag-framing state machine (which lands in a later
//! step). Pure byte logic — no I/O, no logging — so it builds and tests on
//! any platform.

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

/// The only FLV version this parser supports, per `PROJECT.md` → "FLV Header"
/// (`version byte (0x01)`).
const SUPPORTED_FLV_VERSION: u8 = 1;

/// Bit mask for the audio-present flag in the FLV header flags byte (bit 0),
/// per `PROJECT.md` → "FLV Header" (`flags byte (0x07 = audio+video)`).
const FLAG_AUDIO: u8 = 0b0000_0001;

/// Bit mask for the video-present flag in the FLV header flags byte (bit 2),
/// per `PROJECT.md` → "FLV Header" (`flags byte (0x07 = audio+video)`).
const FLAG_VIDEO: u8 = 0b0000_0100;

/// Failures that can occur while parsing the FLV header. Each variant names
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
