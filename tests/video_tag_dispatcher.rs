//! Integration tests for `flvproxy::flv_parser` step 05: the ExVideoTagHeader
//! video-tag dispatcher (`parse_video_tag`) and its standard/extended paths.
//! Covers the cases enumerated in `plan/05-extended-video-tags.md`, asserting
//! byte-for-byte `VideoTagEvent` payloads.
//!
//! Header-byte annotations follow the ExVideoTagHeader layout from
//! `PROJECT.md` → "Layer 3": bit 7 = IsExHeader, bits 6-4 = FrameType,
//! bits 3-0 = PacketType. So `[ex=1, ftype=N, ptype=P]` encodes as
//! `0x80 | (N << 4) | P`.

use flvproxy::avc::{parse_avc_config, AvcDecoderConfig};
use flvproxy::flv_parser::{
    parse_video_tag, video_tag_kind, IgnoreReason, ParseError, VideoTagEvent, VideoTagKind,
};

/// Minimal AVCDecoderConfigurationRecord from `plan/04-avc-config-and-nalus.md`:
/// version 1, profile 0x4D, compat 0x40, level 0x1F, one SPS `[0x67, 0xAB]`,
/// one PPS `[0x68]`.
fn minimal_config_bytes() -> Vec<u8> {
    let mut v = vec![0x01, 0x4D, 0x40, 0x1F, 0xFF, 0xE1];
    v.extend_from_slice(&2u16.to_be_bytes());
    v.extend_from_slice(&[0x67, 0xAB]);
    v.push(0x01);
    v.extend_from_slice(&1u16.to_be_bytes());
    v.push(0x68);
    v
}

/// Builds the AVCDecoderConfigurationRecord's expected parsed form by feeding
/// the same bytes through `parse_avc_config`, so the dispatcher and the codec
/// helper are proven to agree byte-for-byte.
fn expected_config() -> AvcDecoderConfig {
    parse_avc_config(&minimal_config_bytes()).expect("minimal config parses")
}

/// Encodes a 4-byte big-endian length prefix + NALU bytes.
fn length_prefixed(nalu: &[u8]) -> Vec<u8> {
    let mut v = (nalu.len() as u32).to_be_bytes().to_vec();
    v.extend_from_slice(nalu);
    v
}

/// Standard-path video-tag payload: frame/codec byte, AVCPacketType, 3-byte
/// composition time, then the supplied raw bytes (length-prefixed NALU stream
/// or a config record, depending on `packet_type`).
fn std_payload(frame_codec_byte: u8, packet_type: u8, body: &[u8]) -> Vec<u8> {
    let mut v = vec![frame_codec_byte, packet_type, 0x00, 0x00, 0x00];
    v.extend_from_slice(body);
    v
}

/// Extended-path video-tag payload: ExVideoTagHeader byte, 4-byte FourCC,
/// then the supplied body (config record, composition-time + NALUs, NALUs,
/// or nothing, depending on PacketType).
fn ext_payload(header_byte: u8, fourcc: &[u8; 4], body: &[u8]) -> Vec<u8> {
    let mut v = vec![header_byte];
    v.extend_from_slice(fourcc);
    v.extend_from_slice(body);
    v
}

const AVC1: [u8; 4] = *b"avc1";
const HVC1: [u8; 4] = *b"hvc1";

#[test]
fn video_tag_kind_classifies_by_bit_seven() {
    assert_eq!(video_tag_kind(0x17), VideoTagKind::Standard);
    assert_eq!(video_tag_kind(0x27), VideoTagKind::Standard);
    assert_eq!(video_tag_kind(0x90), VideoTagKind::Extended);
    assert_eq!(video_tag_kind(0xA3), VideoTagKind::Extended);
}

#[test]
fn empty_payload_is_truncated() {
    assert_eq!(parse_video_tag(&[]), Err(ParseError::Truncated));
}

#[test]
fn standard_keyframe_nalu_tag_yields_frame_with_one_nalu() {
    let body = length_prefixed(&[0xFF]);
    let payload = std_payload(0x17, 0x01, &body);
    assert_eq!(
        parse_video_tag(&payload),
        Ok(VideoTagEvent::Frame(flvproxy::avc::NaluFrame {
            is_keyframe: true,
            nalus: vec![vec![0xFF]],
        }))
    );
}

#[test]
fn standard_seq_header_yields_config_matching_parse_avc_config() {
    let payload = std_payload(0x17, 0x00, &minimal_config_bytes());
    assert_eq!(
        parse_video_tag(&payload),
        Ok(VideoTagEvent::Config(expected_config()))
    );
}

#[test]
fn standard_interframe_nalu_tag_is_not_keyframe() {
    let body = length_prefixed(&[0xAA]);
    let payload = std_payload(0x27, 0x01, &body);
    assert_eq!(
        parse_video_tag(&payload),
        Ok(VideoTagEvent::Frame(flvproxy::avc::NaluFrame {
            is_keyframe: false,
            nalus: vec![vec![0xAA]],
        }))
    );
}

#[test]
fn standard_seq_end_yields_sequence_end() {
    let payload = std_payload(0x17, 0x02, &[]);
    assert_eq!(parse_video_tag(&payload), Ok(VideoTagEvent::SequenceEnd));
}

#[test]
fn standard_non_avc_codec_yields_ignored() {
    // 0x12 = frame_type 1, CodecID 2 (non-AVC).
    let payload = std_payload(0x12, 0x01, &length_prefixed(&[0xFF]));
    assert_eq!(
        parse_video_tag(&payload),
        Ok(VideoTagEvent::Ignored(IgnoreReason::NotAvcCodec(2)))
    );
}

#[test]
fn standard_unknown_packet_type_yields_ignored() {
    let payload = std_payload(0x17, 0x09, &[]);
    assert_eq!(
        parse_video_tag(&payload),
        Ok(VideoTagEvent::Ignored(IgnoreReason::UnknownPacketType(
            0x09
        )))
    );
}

#[test]
fn standard_seq_header_below_preamble_is_truncated() {
    // Only byte 0 + AVCPacketType present; no room for the preamble.
    let payload = [0x17, 0x00];
    assert_eq!(parse_video_tag(&payload), Err(ParseError::Truncated));
}

#[test]
fn standard_nalu_below_preamble_is_truncated() {
    // AVCPacketType=1 (NALU) but only 4 of the 5 preamble bytes present.
    let payload = [0x17, 0x01, 0x00, 0x00];
    assert_eq!(parse_video_tag(&payload), Err(ParseError::Truncated));
}

#[test]
fn extended_sequence_start_yields_config_identical_to_standard() {
    // [ex=1, ftype=1, ptype=0] = 0x80 | (1 << 4) | 0 = 0x90.
    let payload = ext_payload(0x90, &AVC1, &minimal_config_bytes());
    assert_eq!(
        parse_video_tag(&payload),
        Ok(VideoTagEvent::Config(expected_config()))
    );
}

#[test]
fn extended_coded_frames_yields_keyframe_frame_with_one_nalu() {
    // [ex=1, ftype=1, ptype=1] = 0x80 | (1 << 4) | 1 = 0x91.
    let mut body = vec![0x00, 0x00, 0x00]; // 3-byte composition time SI24.
    body.extend_from_slice(&length_prefixed(&[0xEE]));
    let payload = ext_payload(0x91, &AVC1, &body);
    assert_eq!(
        parse_video_tag(&payload),
        Ok(VideoTagEvent::Frame(flvproxy::avc::NaluFrame {
            is_keyframe: true,
            nalus: vec![vec![0xEE]],
        }))
    );
}

#[test]
fn extended_coded_frames_x_yields_frame_with_two_nalus_not_keyframe() {
    // [ex=1, ftype=2, ptype=3] = 0x80 | (2 << 4) | 3 = 0xA3. No comp time.
    let mut body = length_prefixed(&[0xAA, 0xBB]);
    body.extend_from_slice(&length_prefixed(&[0xCC]));
    let payload = ext_payload(0xA3, &AVC1, &body);
    assert_eq!(
        parse_video_tag(&payload),
        Ok(VideoTagEvent::Frame(flvproxy::avc::NaluFrame {
            is_keyframe: false,
            nalus: vec![vec![0xAA, 0xBB], vec![0xCC]],
        }))
    );
}

#[test]
fn extended_sequence_end_yields_sequence_end() {
    // [ex=1, ftype=1, ptype=2] = 0x80 | (1 << 4) | 2 = 0x92.
    let payload = ext_payload(0x92, &AVC1, &[]);
    assert_eq!(parse_video_tag(&payload), Ok(VideoTagEvent::SequenceEnd));
}

#[test]
fn extended_metadata_yields_metadata() {
    // [ex=1, ftype=1, ptype=4] = 0x80 | (1 << 4) | 4 = 0x94.
    let payload = ext_payload(0x94, &AVC1, &[0x02, 0x00, 0x04, b'o', b'n', b'_', b'!']);
    assert_eq!(parse_video_tag(&payload), Ok(VideoTagEvent::Metadata));
}

#[test]
fn extended_hevc_fourcc_yields_ignored_without_nalu_parse() {
    // CodedFrames with hvc1 FourCC must not reach the NALU splitter.
    let mut body = vec![0x00, 0x00, 0x00];
    body.extend_from_slice(&length_prefixed(&[0xEE]));
    let payload = ext_payload(0x91, &HVC1, &body);
    assert_eq!(
        parse_video_tag(&payload),
        Ok(VideoTagEvent::Ignored(IgnoreReason::NotAvcFourCC(HVC1)))
    );
}

#[test]
fn extended_unknown_packet_type_yields_ignored() {
    // [ex=1, ftype=1, ptype=0xF] = 0x9F — PacketType 15 is unspecified.
    let payload = ext_payload(0x9F, &AVC1, &[]);
    assert_eq!(
        parse_video_tag(&payload),
        Ok(VideoTagEvent::Ignored(IgnoreReason::UnknownPacketType(
            0x0F
        )))
    );
}

#[test]
fn extended_coded_frames_truncated_comp_time_is_truncated() {
    // Only 2 of the 3 composition-time bytes present.
    let payload = [0x91, b'a', b'v', b'c', b'1', 0x00, 0x00];
    assert_eq!(parse_video_tag(&payload), Err(ParseError::Truncated));
}

#[test]
fn extended_header_below_five_bytes_is_truncated() {
    // FourCC truncated to 3 bytes.
    let payload = [0x90, b'a', b'v', b'c'];
    assert_eq!(parse_video_tag(&payload), Err(ParseError::Truncated));
}

#[test]
fn extended_coded_frames_x_truncated_nalu_is_truncated() {
    // Length prefix declares 3 bytes but only 2 follow.
    let body = [0x00, 0x00, 0x00, 0x03, 0xAA, 0xBB];
    let payload = ext_payload(0xA3, &AVC1, &body);
    assert_eq!(parse_video_tag(&payload), Err(ParseError::Truncated));
}

#[test]
fn extended_sequence_start_bad_config_version_surfaces_as_codec_error() {
    let mut bad_config = minimal_config_bytes();
    bad_config[0] = 0x02; // configurationVersion != 1.
    let payload = ext_payload(0x90, &AVC1, &bad_config);
    assert_eq!(
        parse_video_tag(&payload),
        Err(ParseError::Codec(
            flvproxy::avc::AvcError::BadConfigVersion(0x02)
        ))
    );
}
