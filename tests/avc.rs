//! Integration tests for `flvproxy::avc` step 04: AVCDecoderConfigurationRecord
//! parsing and length-prefixed NALU extraction. Covers the exact cases
//! enumerated in `plan/04-avc-config-and-nalus.md`, asserting byte-for-byte
//! SPS/PPS bytes and NALU contents.

use flvproxy::avc::{
    parse_avc_config, parse_avc_nalu_payload, split_length_prefixed_nalus, AvcDecoderConfig,
    AvcError, AvcPacketType, NaluFrame,
};

/// Builds the minimal AVCDecoderConfigurationRecord from
/// `plan/04-avc-config-and-nalus.md`: version 1, profile 0x4D, compat 0x40,
/// level 0x1F, one SPS of length 2 `[0x67, 0xAB]`, one PPS of length 1
/// `[0x68]`.
fn minimal_config_bytes() -> Vec<u8> {
    let mut v = vec![0x01, 0x4D, 0x40, 0x1F, 0xFF, 0xE1];
    v.extend_from_slice(&2u16.to_be_bytes());
    v.extend_from_slice(&[0x67, 0xAB]);
    v.push(0x01);
    v.extend_from_slice(&1u16.to_be_bytes());
    v.push(0x68);
    v
}

/// Builds a NALU-payload preamble for the standard AVC video tag: frame/codec
/// byte, AVCPacketType, 3-byte composition time, then the supplied NALU
/// records (each a 4-byte BE length prefix + NALU bytes).
fn nalu_payload(frame_codec_byte: u8, nalus: &[&[u8]]) -> Vec<u8> {
    let mut v = vec![frame_codec_byte, 0x01, 0x00, 0x00, 0x00];
    for nalu in nalus {
        v.extend_from_slice(&(nalu.len() as u32).to_be_bytes());
        v.extend_from_slice(nalu);
    }
    v
}

#[test]
fn parse_avc_config_returns_exact_fields_and_sps_pps_bytes() {
    let bytes = minimal_config_bytes();
    let cfg = parse_avc_config(&bytes).expect("minimal config");
    assert_eq!(
        cfg,
        AvcDecoderConfig {
            profile_indication: 0x4D,
            profile_compat: 0x40,
            level_indication: 0x1F,
            sps: vec![0x67, 0xAB],
            pps: vec![0x68],
        }
    );
}

#[test]
fn parse_avc_config_bad_version_returns_bad_config_version() {
    let mut bytes = minimal_config_bytes();
    bytes[0] = 0x02;
    assert_eq!(
        parse_avc_config(&bytes),
        Err(AvcError::BadConfigVersion(0x02))
    );
}

#[test]
fn parse_avc_config_truncated_below_six_bytes_is_truncated() {
    let bytes = [0x01, 0x4D, 0x40, 0x1F, 0xFF];
    assert_eq!(parse_avc_config(&bytes), Err(AvcError::Truncated));
}

#[test]
fn parse_avc_config_truncated_sps_is_truncated() {
    let mut bytes = minimal_config_bytes();
    bytes.truncate(8);
    assert_eq!(parse_avc_config(&bytes), Err(AvcError::Truncated));
}

#[test]
fn parse_avc_config_truncated_pps_length_is_truncated() {
    let mut bytes = minimal_config_bytes();
    bytes.pop();
    assert_eq!(parse_avc_config(&bytes), Err(AvcError::Truncated));
}

#[test]
fn parse_avc_config_with_two_sps_keeps_first_and_parses_pps_cleanly() {
    let mut v = vec![0x01, 0x4D, 0x40, 0x1F, 0xFF, 0xE2];
    v.extend_from_slice(&2u16.to_be_bytes());
    v.extend_from_slice(&[0x67, 0xAB]);
    v.extend_from_slice(&3u16.to_be_bytes());
    v.extend_from_slice(&[0x67, 0xCD, 0xEF]);
    v.push(0x01);
    v.extend_from_slice(&1u16.to_be_bytes());
    v.push(0x68);

    let cfg = parse_avc_config(&v).expect("two-sps config");
    assert_eq!(cfg.sps, vec![0x67, 0xAB]);
    assert_eq!(cfg.pps, vec![0x68]);
}

#[test]
fn parse_avc_nalu_payload_keyframe_yields_frame_with_two_nalus() {
    let payload = nalu_payload(0x17, &[&[0xAA, 0xBB, 0xCC], &[0xDD]]);
    let frame = parse_avc_nalu_payload(&payload, true).expect("keyframe nalus");
    assert_eq!(
        frame,
        NaluFrame {
            is_keyframe: true,
            nalus: vec![vec![0xAA, 0xBB, 0xCC], vec![0xDD]],
        }
    );
}

#[test]
fn parse_avc_nalu_payload_interframe_is_not_keyframe() {
    let payload = nalu_payload(0x27, &[&[0xAA]]);
    let frame = parse_avc_nalu_payload(&payload, false).expect("interframe nalus");
    assert_eq!(
        frame,
        NaluFrame {
            is_keyframe: false,
            nalus: vec![vec![0xAA]],
        }
    );
}

#[test]
fn parse_avc_nalu_payload_truncated_nalu_is_truncated_error() {
    let mut payload = nalu_payload(0x17, &[&[0xAA, 0xBB]]);
    payload.pop();
    assert_eq!(
        parse_avc_nalu_payload(&payload, true),
        Err(AvcError::Truncated)
    );
}

#[test]
fn parse_avc_nalu_payload_seq_header_routes_to_not_nalu_payload() {
    let mut payload = vec![0x17, 0x00, 0x00, 0x00, 0x00];
    payload.extend(minimal_config_bytes());
    assert_eq!(
        parse_avc_nalu_payload(&payload, true),
        Err(AvcError::NotNaluPayload(AvcPacketType::SeqHeader))
    );
}

#[test]
fn parse_avc_nalu_payload_end_routes_to_not_nalu_payload() {
    let payload = vec![0x17, 0x02, 0x00, 0x00, 0x00];
    assert_eq!(
        parse_avc_nalu_payload(&payload, true),
        Err(AvcError::NotNaluPayload(AvcPacketType::End))
    );
}

#[test]
fn parse_avc_nalu_payload_unknown_packet_type_is_unknown_error() {
    let payload = vec![0x17, 0x09, 0x00, 0x00, 0x00];
    assert_eq!(
        parse_avc_nalu_payload(&payload, true),
        Err(AvcError::UnknownPacketType(0x09))
    );
}

#[test]
fn parse_avc_nalu_payload_non_avc_codec_is_not_avc_error() {
    let payload = vec![0x12, 0x01, 0x00, 0x00, 0x00, 0, 0, 0, 1, 0xFF];
    assert_eq!(
        parse_avc_nalu_payload(&payload, false),
        Err(AvcError::NotAvc { codec_id: 0x02 })
    );
}

#[test]
fn parse_avc_nalu_payload_too_short_for_preamble_is_truncated() {
    let payload = vec![0x17, 0x01, 0x00, 0x00];
    assert_eq!(
        parse_avc_nalu_payload(&payload, true),
        Err(AvcError::Truncated)
    );
}

#[test]
fn split_length_prefixed_nalus_empty_returns_empty_vec() {
    assert_eq!(split_length_prefixed_nalus(&[]), Ok(Vec::new()));
}

#[test]
fn split_length_prefixed_nalus_zero_length_skipped() {
    let data = vec![0, 0, 0, 0, 0, 0, 0, 1, 0xEE];
    assert_eq!(split_length_prefixed_nalus(&data), Ok(vec![vec![0xEE]]));
}
