//! Shared synthetic-stream builders for the integration tests.
//!
//! Several test files (`camera_pipeline.rs`, `ws_upflv.rs`, and historically
//! `amf.rs`/`flv_tag_sm.rs`/`wiring.rs`) need to construct the same FLV +
//! AMF0 + AVC byte layouts. This module collects the canonical builders;
//! new tests use `mod common;` to reach them. Migrating the pre-existing
//! duplicated copies in the older test files is tracked in `DEBT.md`
//! (TRIGGER: step 25 / 28 review) so this step's diff stays focused.
//!
//! Layouts mirror `PROJECT.md` → "FLV Tag Structure",
//! "AVCDecoderConfigurationRecord", and the standard/extended video-tag
//! shapes; byte-for-byte parity with `tests/camera_pipeline.rs` is required
//! so the WS-uPFLV path asserts the same `codec()`/frame delivery as step 14.
//
// `dead_code` is allowed because this is the shared test-helper module: each
// test file uses a different subset of the canonical builder set, so some
// helpers are unused by any one file. This is the standard Rust idiom for
// `tests/common/mod.rs` and is tracked in `DEBT.md` (step 20) — the allow is
// removed once every test file is consolidated onto this module.
#![allow(dead_code)]

use flvproxy::flv_parser::UPFLV_PREFIX;

/// FLV header from `PROJECT.md` → "Layer 2": `FLV`, version 1, audio+video
/// flags, header size 9.
pub const FLV_HEADER: [u8; 9] = [0x46, 0x4C, 0x56, 0x01, 0x07, 0x00, 0x00, 0x00, 0x09];

/// SPS with NALU header `0x67` and profile/compat/level `4D 40 1F` (Main
/// profile, level 3.1), matching the SDP/RTSP tests for cross-test parity.
pub const SPS_MAIN: &[u8] = &[0x67, 0x4D, 0x40, 0x1F, 0x96, 0x35, 0x40, 0x1E];

/// PPS with NALU header `0x68`, matching the SDP/RTSP tests.
pub const PPS: &[u8] = &[0x68, 0xCE, 0x31, 0x12];

/// IDR slice NALU (keyframe) used in the synthetic video NALU tags.
pub const KEYFRAME_NALU: &[u8] = &[0x65, 0xAA, 0xBB];

/// Non-IDR slice NALU (inter frame) used in the synthetic video NALU tags.
pub const INTER_NALU: &[u8] = &[0x61, 0xCC];

/// AMF0 object end marker: empty key (u16 length 0) + `0x09`.
pub const OBJECT_END: [u8; 3] = [0x00, 0x00, 0x09];

/// AMF0 long-string marker for `amf_string` (type `0x02` + u16 length + bytes).
pub fn amf_string(s: &str) -> Vec<u8> {
    let bytes = s.as_bytes();
    let mut v = vec![0x02];
    v.extend_from_slice(&(bytes.len() as u16).to_be_bytes());
    v.extend_from_slice(bytes);
    v
}

/// AMF0 number marker (type `0x00` + 8-byte big-endian f64).
pub fn amf_number(n: f64) -> Vec<u8> {
    let mut v = vec![0x00];
    v.extend_from_slice(&n.to_be_bytes());
    v
}

/// AMF0 ECMA-array property key (u16 length + UTF-8 bytes).
pub fn amf_key(s: &str) -> Vec<u8> {
    let bytes = s.as_bytes();
    let mut v = (bytes.len() as u16).to_be_bytes().to_vec();
    v.extend_from_slice(bytes);
    v
}

/// AMF0 property pair: key + value bytes.
pub fn amf_pair(key: &str, value: &[u8]) -> Vec<u8> {
    let mut v = amf_key(key);
    v.extend_from_slice(value);
    v
}

/// AMF0 ECMA-array header: type `0x08` + u32 count.
pub fn ecma_array_header(count: u32) -> Vec<u8> {
    let mut v = vec![0x08];
    v.extend_from_slice(&count.to_be_bytes());
    v
}

/// Builds an `onMetaData` script-tag body declaring `width`/`height`/`fps`.
pub fn on_metadata_body(width: u32, height: u32, fps: f64) -> Vec<u8> {
    let mut v = amf_string("onMetaData");
    v.extend(ecma_array_header(3));
    v.extend(amf_pair("videoWidth", &amf_number(width as f64)));
    v.extend(amf_pair("videoHeight", &amf_number(height as f64)));
    v.extend(amf_pair("videoFps", &amf_number(fps)));
    v.extend_from_slice(&OBJECT_END);
    v
}

/// Appends one FLV tag (11-byte header + `body` + 4-byte previous-tag-size)
/// to `out`.
pub fn push_tag(out: &mut Vec<u8>, tag_type: u8, timestamp_ms: u32, body: &[u8]) {
    out.push(tag_type);
    let n = body.len() as u32;
    out.extend_from_slice(&[(n >> 16) as u8, (n >> 8) as u8, n as u8]);
    let lo = timestamp_ms & 0x00FF_FFFF;
    let ext = (timestamp_ms >> 24) & 0xFF;
    out.extend_from_slice(&[(lo >> 16) as u8, (lo >> 8) as u8, lo as u8]);
    out.push(ext as u8);
    out.extend_from_slice(&[0, 0, 0]);
    out.extend_from_slice(body);
    let prev = 11u32 + n;
    out.extend_from_slice(&prev.to_be_bytes());
}

/// Encodes a 4-byte big-endian length prefix + NALU bytes.
pub fn length_prefixed(nalu: &[u8]) -> Vec<u8> {
    let mut v = (nalu.len() as u32).to_be_bytes().to_vec();
    v.extend_from_slice(nalu);
    v
}

/// Builds an AVCDecoderConfigurationRecord carrying `sps` and `pps`.
pub fn avc_config_record(sps: &[u8], pps: &[u8]) -> Vec<u8> {
    let mut v = vec![0x01, sps[1], sps[2], sps[3], 0xFF, 0xE1];
    v.extend_from_slice(&(sps.len() as u16).to_be_bytes());
    v.extend_from_slice(sps);
    v.push(0x01);
    v.extend_from_slice(&(pps.len() as u16).to_be_bytes());
    v.extend_from_slice(pps);
    v
}

/// Standard-path video seq-header tag body: `0x17` (keyframe+AVC),
/// AVCPacketType 0 (seq header), 3-byte composition time, then the config
/// record.
pub fn std_seq_header_body(sps: &[u8], pps: &[u8]) -> Vec<u8> {
    let mut v = vec![0x17, 0x00, 0x00, 0x00, 0x00];
    v.extend(avc_config_record(sps, pps));
    v
}

/// Standard-path video NALU tag body: `frame_byte` (keyframe `0x17` or inter
/// `0x27`), AVCPacketType 1 (NALU), 3-byte composition time, then
/// length-prefixed NALUs.
pub fn std_nalu_body(frame_byte: u8, nalus: &[&[u8]]) -> Vec<u8> {
    let mut v = vec![frame_byte, 0x01, 0x00, 0x00, 0x00];
    for nalu in nalus {
        v.extend(length_prefixed(nalu));
    }
    v
}

/// Extended-path video SequenceStart tag body: ExVideoTagHeader `0x90`
/// (ex=1, ftype=1, ptype=0) + FourCC `avc1` + config record.
pub fn ext_seq_header_body(sps: &[u8], pps: &[u8]) -> Vec<u8> {
    let mut v = vec![0x90];
    v.extend_from_slice(b"avc1");
    v.extend(avc_config_record(sps, pps));
    v
}

/// Extended-path video CodedFramesX tag body: ExVideoTagHeader
/// (keyframe `0x93` or inter `0xA3`, both ptype=3) + FourCC `avc1` +
/// length-prefixed NALUs (no composition time).
pub fn ext_nalu_body(header_byte: u8, nalus: &[&[u8]]) -> Vec<u8> {
    let mut v = vec![header_byte];
    v.extend_from_slice(b"avc1");
    for nalu in nalus {
        v.extend(length_prefixed(nalu));
    }
    v
}

/// The FLV header + leading previous-tag-size (0x00000000) that precedes the
/// first tag, with the uPFLV prefix prepended when `with_prefix` is set.
/// Returned separately so a multi-message test can split header from tags.
pub fn flv_prelude(with_prefix: bool) -> Vec<u8> {
    let mut s = Vec::new();
    if with_prefix {
        s.extend_from_slice(&UPFLV_PREFIX);
    }
    s.extend_from_slice(&FLV_HEADER);
    s.extend_from_slice(&[0, 0, 0, 0]);
    s
}

/// Builds a synthetic extendedFlv stream. `with_prefix` toggles the uPFLV
/// prefix. `seq_header`/`keyframe_body`/`inter_body` are the video-tag
/// payloads (standard or extended path); `metadata` optionally prepends an
/// `onMetaData` script tag.
pub fn build_stream(
    with_prefix: bool,
    metadata: Option<(u32, u32, f64)>,
    seq_header: Vec<u8>,
    keyframe_body: Vec<u8>,
    inter_body: Vec<u8>,
) -> Vec<u8> {
    let mut s = flv_prelude(with_prefix);
    if let Some((w, h, fps)) = metadata {
        push_tag(&mut s, 0x12, 0, &on_metadata_body(w, h, fps));
    }
    push_tag(&mut s, 0x09, 1000, &seq_header);
    push_tag(&mut s, 0x09, 1000, &keyframe_body);
    push_tag(&mut s, 0x09, 1033, &inter_body);
    s
}
