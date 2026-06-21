//! AVC (H.264) bitstream helpers. Parses the AVCDecoderConfigurationRecord to extract SPS/PPS and splits length-prefixed NALU streams into individual NALUs. Pure codec decoding — no FLV tag-header knowledge lives here: the FLV video-tag dispatcher (`flv_parser::parse_video_tag`) strips the standard and `ExVideoTagHeader` preambles and hands this module only the codec body (a config record or a length-prefixed NALU stream).
//!
//! Pure byte logic — no I/O, no logging — so it builds and tests on any platform. Structures and field layouts follow `PROJECT.md` → "AVCDecoderConfigurationRecord".

/// `configurationVersion` value mandated by ISO/IEC 14496-15 for an AVCDecoderConfigurationRecord. Byte 0 of the record must equal this.
const AVC_CONFIG_VERSION: u8 = 1;

/// Mask isolating the `numSPS` count from byte 5 of the config record (the low 3 bits; the high 3 bits are reserved, per the spec layout in `PROJECT.md`).
const NUM_SPS_MASK: u8 = 0x07;

/// Number of bytes in the fixed AVC video-tag preamble that precede either an AVCDecoderConfigurationRecord (AVCPacketType=0) or a length-prefixed NALU list (AVCPacketType=1): frame/codec byte + AVCPacketType byte + 3-byte composition-time SI24, per `PROJECT.md` → "Standard FLV Video Tag (CodecID=7, AVC)". Exposed so the FLV video-tag dispatcher (`flv_parser::parse_video_tag`) can locate the codec body without re-declaring the offset.
pub const AVC_NALU_PREAMBLE_BYTES: usize = 5;

/// Number of bytes in the big-endian length prefix preceding each NALU in an AVC NALU payload, per `PROJECT.md` → "Standard FLV Video Tag" (`4-byte big-endian length prefix`).
const NALU_LENGTH_PREFIX_BYTES: usize = 4;

/// `AVCPacketType` byte from a standard FLV video tag, per `PROJECT.md` → "Standard FLV Video Tag (CodecID=7, AVC)": 0 = sequence header (AVCDecoderConfigurationRecord), 1 = NALU payload, 2 = end of sequence.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum AvcPacketType {
    /// AVCDecoderConfigurationRecord follows — route to `parse_avc_config`.
    SeqHeader = 0,
    /// Length-prefixed NALU stream follows — route to NALU extraction.
    Nalu = 1,
    /// End-of-sequence marker — no payload of interest.
    End = 2,
}

impl AvcPacketType {
    /// Decodes the `AVCPacketType` byte. Unknown values map to `None` so the caller can reject defensively rather than mis-route the payload.
    pub fn from_byte(byte: u8) -> Option<AvcPacketType> {
        match byte {
            0 => Some(AvcPacketType::SeqHeader),
            1 => Some(AvcPacketType::Nalu),
            2 => Some(AvcPacketType::End),
            _ => None,
        }
    }
}

/// Failures that can occur while parsing AVC config records or NALU payloads. Each variant names the exact structural defect so the caller can log a meaningful message; none represent a crash.
///
/// `Copy` so the FLV video-tag dispatcher can wrap a non-truncation failure in `flv_parser::ParseError::Codec` without taking ownership — every variant carries only `Copy` scalars.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum AvcError {
    /// The buffer ended before a complete structure could be read. Reading more bytes and retrying is the only remediation.
    Truncated,
    /// Byte 0 of the AVCDecoderConfigurationRecord is not the mandated `configurationVersion = 1`; carries the offending byte for diagnostics.
    BadConfigVersion(u8),
}

/// Parsed AVCDecoderConfigurationRecord. SPS and PPS are stored **without** the Annex-B start code and **without** the length prefix — exactly the raw NALU bytes the record carried — so they can be fed directly to RTP packetization and SDP `sprop-parameter-sets` generation.
///
/// Only the first SPS and first PPS are retained: real-world UniFi camera streams carry exactly one of each, and the RTP/SDP path consumes a single parameter set pair. Extra SPS/PPS entries in the record are skipped but still walked past so the parse pointer lands cleanly after the record.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct AvcDecoderConfig {
    /// AVCProfileIndication (record byte 1), e.g. `0x4D` for Main profile.
    pub profile_indication: u8,
    /// profile_compatibility (record byte 2).
    pub profile_compat: u8,
    /// AVCLevelIndication (record byte 3), e.g. `0x1F` for level 3.1.
    pub level_indication: u8,
    /// First SPS NALU bytes from the record, without start code or length prefix. Empty iff the record declared `numSPS = 0`.
    pub sps: Vec<u8>,
    /// First PPS NALU bytes from the record, without start code or length prefix. Empty iff the record declared `numPPS = 0`.
    pub pps: Vec<u8>,
}

/// A decoded H.264 frame: its keyframe status plus the length-prefix-stripped NALUs it carries. Each `Vec<u8>` is one NALU without its length prefix or start code, ready for RTP packetization.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct NaluFrame {
    /// True iff the originating FLV video tag's FrameType nibble was 1 (keyframe). Passed in by the caller, which splits it from byte 0.
    pub is_keyframe: bool,
    /// The NALUs in this frame, in stream order.
    pub nalus: Vec<Vec<u8>>,
}

/// Parses an AVCDecoderConfigurationRecord into an `AvcDecoderConfig`.
///
/// Walks the layout from `PROJECT.md` → "AVCDecoderConfigurationRecord": version byte, profile/compat/level, the `0xFF` reserved/lengthSize byte (validated by the spec but tolerated here), the `numSPS` count, each SPS entry (length-prefixed u16), then the `numPPS` count and each PPS entry. Only the first SPS and first PPS are retained, but all entries are traversed so the parse pointer ends exactly at the record's tail.
///
/// Errors are structured `AvcError` variants rather than panics; a truncated record yields `Truncated` and a bad version yields `BadConfigVersion`.
pub fn parse_avc_config(payload: &[u8]) -> Result<AvcDecoderConfig, AvcError> {
    if payload.len() < 2 {
        return Err(AvcError::Truncated);
    }
    let version = payload[0];
    if version != AVC_CONFIG_VERSION {
        return Err(AvcError::BadConfigVersion(version));
    }
    // Bytes 1-3 profile/compat/level, byte 4 reserved+lengthSizeMinusOne (nominally 0xFF), byte 5 reserved+numSPS. Need through byte 5 inclusive.
    if payload.len() < 6 {
        return Err(AvcError::Truncated);
    }
    let profile_indication = payload[1];
    let profile_compat = payload[2];
    let level_indication = payload[3];

    let num_sps = payload[5] & NUM_SPS_MASK;
    let mut pos = 6;
    let mut sps = Vec::new();
    for index in 0..num_sps {
        let (consumed, bytes) = read_u16_length_entry(&payload[pos..])?;
        pos += consumed;
        if index == 0 {
            sps = bytes;
        }
    }

    let num_pps = payload.get(pos).copied().ok_or(AvcError::Truncated)?;
    pos += 1;
    let mut pps = Vec::new();
    for index in 0..num_pps {
        let (consumed, bytes) = read_u16_length_entry(&payload[pos..])?;
        pos += consumed;
        if index == 0 {
            pps = bytes;
        }
    }

    Ok(AvcDecoderConfig { profile_indication, profile_compat, level_indication, sps, pps })
}

/// Splits a stream of `[u32 BE length][NALU bytes]` records into individual NALUs, each returned without its length prefix. Stops cleanly when the input is exhausted; a length prefix that is truncated or that exceeds the remaining bytes yields `AvcError::Truncated`. A zero-length NALU is skipped (its 4-byte length prefix is consumed, no entry is emitted).
pub fn split_length_prefixed_nalus(data: &[u8]) -> Result<Vec<Vec<u8>>, AvcError> {
    let mut nalus = Vec::new();
    let mut pos = 0;
    while pos < data.len() {
        let prefix_end = pos.checked_add(NALU_LENGTH_PREFIX_BYTES).ok_or(AvcError::Truncated)?;
        if prefix_end > data.len() {
            return Err(AvcError::Truncated);
        }
        let len = u32::from_be_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]]) as usize;
        pos = prefix_end;
        let nalu_end = pos.checked_add(len).ok_or(AvcError::Truncated)?;
        if nalu_end > data.len() {
            return Err(AvcError::Truncated);
        }
        if len > 0 {
            nalus.push(data[pos..nalu_end].to_vec());
        }
        pos = nalu_end;
    }
    Ok(nalus)
}

/// Reads one `[u16 BE length][entry bytes]` record from `buf`, returning the total number of bytes consumed (2 length bytes + the entry length) and the entry bytes. Used for both SPS and PPS entries in the config record.
fn read_u16_length_entry(buf: &[u8]) -> Result<(usize, Vec<u8>), AvcError> {
    if buf.len() < 2 {
        return Err(AvcError::Truncated);
    }
    let len = u16::from_be_bytes([buf[0], buf[1]]) as usize;
    if buf.len() < 2 + len {
        return Err(AvcError::Truncated);
    }
    Ok((2 + len, buf[2..2 + len].to_vec()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn avc_packet_type_decodes_known_values_only() {
        assert_eq!(AvcPacketType::from_byte(0), Some(AvcPacketType::SeqHeader));
        assert_eq!(AvcPacketType::from_byte(1), Some(AvcPacketType::Nalu));
        assert_eq!(AvcPacketType::from_byte(2), Some(AvcPacketType::End));
        assert_eq!(AvcPacketType::from_byte(3), None);
        assert_eq!(AvcPacketType::from_byte(0xFF), None);
    }

    #[test]
    fn split_empty_input_returns_empty_vec() {
        assert_eq!(split_length_prefixed_nalus(&[]), Ok(Vec::new()));
    }

    #[test]
    fn split_zero_length_nalu_is_skipped() {
        let data = [0, 0, 0, 0];
        assert_eq!(split_length_prefixed_nalus(&data), Ok(Vec::new()));
    }

    #[test]
    fn split_truncated_length_prefix_is_truncated_error() {
        let data = [0, 0, 1];
        assert_eq!(split_length_prefixed_nalus(&data), Err(AvcError::Truncated));
    }

    #[test]
    fn split_length_exceeding_remaining_is_truncated_error() {
        let mut data = vec![0, 0, 0, 3];
        data.extend_from_slice(&[0xAA, 0xBB]);
        assert_eq!(split_length_prefixed_nalus(&data), Err(AvcError::Truncated));
    }
}
