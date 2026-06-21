//! Integration tests for `flvproxy::sdp` (step 09): the hand-rolled Base64 encoder, `profile-level-id` derivation, and the full `build_sdp` body. Covers the exact cases enumerated in `plan/09-sdp-generation.md`, asserting byte-for-byte / string-for-string output. Expected SDP bodies are built from independent string literals — only `sprop-parameter-sets` and `profile-level-id` are computed via the module's own public helpers, so the tests stay self-consistent without hard-coding magic.

use flvproxy::sdp::{base64_encode, build_sdp, profile_level_id};
use flvproxy::stream_state::CodecParams;

/// Server IP used across the SDP tests so the origin line is predictable.
const SERVER_IP: &str = "192.168.1.100";

/// Realistic-ish SPS with NALU header `0x67` and profile/compat/level `4D 40 1F` (Main profile, level 3.1), matching the plan's example.
const SPS: &[u8] = &[0x67, 0x4D, 0x40, 0x1F, 0x96, 0x35, 0x40, 0x1E];

/// Realistic-ish PPS with NALU header `0x68`, matching the plan's example.
const PPS: &[u8] = &[0x68, 0xCE, 0x31, 0x12];

/// Builds `CodecParams` carrying `SPS`/`PPS` and the given advertised frame rate. Width/height are left unknown since the SDP does not encode them.
fn codec_with_fps(fps: Option<f32>) -> CodecParams {
    CodecParams { sps: SPS.to_vec(), pps: PPS.to_vec(), profile_indication: SPS[1], profile_compat: SPS[2], level_indication: SPS[3], width: None, height: None, fps }
}

/// Asserts every line of `sdp` is `\r\n`-terminated and the body ends with a final `\r\n` (no bare `\n`, no trailing partial line).
fn assert_crlf_well_formed(sdp: &str) {
    assert!(sdp.ends_with("\r\n"), "SDP body must end with \\r\\n");
    for line in sdp.split("\r\n") {
        assert!(!line.contains('\r') && !line.contains('\n'), "line contains a stray CR/LF: {line:?}",);
    }
}

#[test]
fn base64_rfc4648_empty_is_empty() {
    assert_eq!(base64_encode(b""), "");
}

#[test]
fn base64_rfc4648_single_byte_f() {
    assert_eq!(base64_encode(b"f"), "Zg==");
}

#[test]
fn base64_rfc4648_two_bytes_fo() {
    assert_eq!(base64_encode(b"fo"), "Zm8=");
}

#[test]
fn base64_rfc4648_three_bytes_foo() {
    assert_eq!(base64_encode(b"foo"), "Zm9v");
}

#[test]
fn base64_rfc4648_four_bytes_foob() {
    assert_eq!(base64_encode(b"foob"), "Zm9vYg==");
}

#[test]
fn base64_rfc4648_five_bytes_fooba() {
    assert_eq!(base64_encode(b"fooba"), "Zm9vYmE=");
}

#[test]
fn base64_rfc4648_six_bytes_foobar() {
    assert_eq!(base64_encode(b"foobar"), "Zm9vYmFy");
}

#[test]
fn base64_three_byte_vector_deadbe() {
    assert_eq!(base64_encode(&[0xDE, 0xAD, 0xBE]), "3q2+");
}

#[test]
fn profile_level_id_derives_six_hex_digits_from_sps_one_to_three() {
    assert_eq!(profile_level_id(SPS), Some("4D401F".to_string()));
}

#[test]
fn profile_level_id_is_none_for_short_sps() {
    assert_eq!(profile_level_id(&[0x67, 0x4D]), None);
}

#[test]
fn profile_level_id_is_none_for_empty_sps() {
    assert_eq!(profile_level_id(&[]), None);
}

#[test]
fn build_sdp_with_fps_matches_reference_body_byte_for_byte() {
    let fps = 30.0_f32;
    let codec = codec_with_fps(Some(fps));
    let sdp = build_sdp(&codec, SERVER_IP, Some(fps));

    let pli = profile_level_id(&codec.sps).expect("SPS is long enough");
    let sprop = format!("{},{}", base64_encode(&codec.sps), base64_encode(&codec.pps));
    let expected = format!(
        "v=0\r\n\
         o=- 0 0 IN IP4 {server_ip}\r\n\
         s=UniFi Camera Stream\r\n\
         t=0 0\r\n\
         m=video 0 RTP/AVP 96\r\n\
         a=control:streamid=0\r\n\
         a=rtpmap:96 H264/90000\r\n\
         a=fmtp:96 packetization-mode=1;profile-level-id={pli};sprop-parameter-sets={sprop}\r\n\
         a=framerate:{fps}\r\n",
        server_ip = SERVER_IP,
        pli = pli,
        sprop = sprop,
        fps = fps,
    );

    assert_eq!(sdp, expected);
    assert_crlf_well_formed(&sdp);
    assert_eq!(sprop, format!("{},{}", base64_encode(SPS), base64_encode(PPS)),);
}

#[test]
fn build_sdp_without_fps_omits_framerate_line() {
    let codec = codec_with_fps(None);
    let sdp = build_sdp(&codec, SERVER_IP, None);

    let pli = profile_level_id(&codec.sps).expect("SPS is long enough");
    let sprop = format!("{},{}", base64_encode(&codec.sps), base64_encode(&codec.pps));
    let expected = format!(
        "v=0\r\n\
         o=- 0 0 IN IP4 {server_ip}\r\n\
         s=UniFi Camera Stream\r\n\
         t=0 0\r\n\
         m=video 0 RTP/AVP 96\r\n\
         a=control:streamid=0\r\n\
         a=rtpmap:96 H264/90000\r\n\
         a=fmtp:96 packetization-mode=1;profile-level-id={pli};sprop-parameter-sets={sprop}\r\n",
        server_ip = SERVER_IP,
        pli = pli,
        sprop = sprop,
    );

    assert_eq!(sdp, expected);
    assert!(!sdp.contains("a=framerate"), "no framerate line when fps is None");
    assert_crlf_well_formed(&sdp);
}

#[test]
fn build_sdp_falls_back_to_baseline_profile_level_id_for_short_sps() {
    let mut codec = codec_with_fps(Some(30.0));
    codec.sps = vec![0x67, 0x4D];
    let sdp = build_sdp(&codec, SERVER_IP, Some(30.0));

    assert!(sdp.contains("profile-level-id=42001E"), "short SPS must advertise the fallback profile-level-id: {sdp}",);
    assert!(!sdp.contains("profile-level-id=4D401F"));
}

#[test]
fn build_sdp_sprop_parameter_sets_equals_base64_sps_comma_base64_pps() {
    let codec = codec_with_fps(Some(30.0));
    let sdp = build_sdp(&codec, SERVER_IP, Some(30.0));
    let expected_sprop = format!("sprop-parameter-sets={},{}", base64_encode(SPS), base64_encode(PPS));
    assert!(sdp.contains(&expected_sprop));
}
