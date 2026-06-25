//! SDP generation for the RTSP DESCRIBE response. Computes `profile-level-id` from SPS and `sprop-parameter-sets` from base64-encoded SPS/PPS.
//!
//! Pure string logic — no I/O, no networking — so it builds and tests on any platform. The RTSP server calls `build_sdp` with the codec parameters published to `stream_state` and the server's IP. The payload type and clock rate in the `m=`/`a=rtpmap` lines are read from `rtp` so the SDP cannot drift from the RTP packetizer.
//!
//! SDP line endings are `\r\n` per RFC 4566 §5; the body terminates with a final `\r\n`.

use crate::rtp::{PAYLOAD_TYPE_H264, RTP_CLOCK_RATE_HZ};
use crate::stream_state::CodecParams;

/// Standard Base64 alphabet, per RFC 4648 §4.
const BASE64_ALPHABET: [u8; 64] = *b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Base64 padding character, per RFC 4648 §4.
const BASE64_PAD: u8 = b'=';

/// Uppercase hex digits for `profile-level-id` formatting.
const HEX_DIGITS_UPPER: [u8; 16] = *b"0123456789ABCDEF";

/// Minimum SPS length carrying a NALU header byte plus the three profile/compat/level bytes (`sps[1..4]`) needed to derive `profile-level-id`, per RFC 6184 §8.1.
const PROFILE_LEVEL_ID_SPS_MIN_LEN: usize = 4;

/// Number of hex digits in a `profile-level-id` (one per byte of `sps[1..4]`), per RFC 6184 §8.1.
const PROFILE_LEVEL_ID_HEX_DIGITS: usize = 6;

/// Safe baseline `profile-level-id` (Constrained Baseline, level 3.0) used when the SPS is too short to derive one.
const FALLBACK_PROFILE_LEVEL_ID: &str = "42001E";

/// SDP `s=` session name, per `PROJECT.md` → "SDP for DESCRIBE".
const SDP_SESSION_NAME: &str = "UniFi Camera Stream";

/// SDP line terminator, per RFC 4566 §5.
const SDP_LINE_END: &str = "\r\n";

/// Encodes `input` as standard Base64 (RFC 4648 §4) with `=` padding.
///
/// Implemented by hand per the project's zero-crates constraint. Output is the shortest correct encoding; an empty input yields an empty string.
pub fn base64_encode(input: &[u8]) -> String {
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    let mut i = 0;
    while i + 3 <= input.len() {
        let triplet = ((input[i] as u32) << 16) | ((input[i + 1] as u32) << 8) | input[i + 2] as u32;
        push_base64_quartet(&mut out, triplet);
        i += 3;
    }
    let remainder = input.len() - i;
    if remainder == 1 {
        let triplet = (input[i] as u32) << 16;
        out.push(char_from_alphabet((triplet >> 18) & 0x3F));
        out.push(char_from_alphabet((triplet >> 12) & 0x3F));
        out.push(BASE64_PAD as char);
        out.push(BASE64_PAD as char);
    } else if remainder == 2 {
        let triplet = ((input[i] as u32) << 16) | ((input[i + 1] as u32) << 8);
        out.push(char_from_alphabet((triplet >> 18) & 0x3F));
        out.push(char_from_alphabet((triplet >> 12) & 0x3F));
        out.push(char_from_alphabet((triplet >> 6) & 0x3F));
        out.push(BASE64_PAD as char);
    }
    out
}

/// Derives the SDP `profile-level-id` (RFC 6184 §8.1) from an SPS NALU as six uppercase hex digits formed from `sps[1..4]` — `AVCProfileIndication`, `profile_compatibility`, `AVCLevelIndication` per ITU-T H.264 §7.4.2.1.1. Returns `None` if the SPS is shorter than the NALU header plus those three bytes; the caller then advertises `FALLBACK_PROFILE_LEVEL_ID`.
pub fn profile_level_id(sps: &[u8]) -> Option<String> {
    if sps.len() < PROFILE_LEVEL_ID_SPS_MIN_LEN {
        return None;
    }
    let mut out = String::with_capacity(PROFILE_LEVEL_ID_HEX_DIGITS);
    for byte in &sps[1..4] {
        out.push(char_from_hex(byte >> 4));
        out.push(char_from_hex(byte & 0x0F));
    }
    Some(out)
}

/// Builds the SDP body returned by RTSP `DESCRIBE`, matching the format in `PROJECT.md` → "SDP for DESCRIBE" with `\r\n` line endings.
///
/// `profile-level-id` is derived from `codec.sps`; if the SPS is too short, `FALLBACK_PROFILE_LEVEL_ID` is advertised. `sprop-parameter-sets` is `base64(sps),base64(pps)`. `fps` is taken explicitly (rather than read from `codec.fps`) so the RTSP server controls the advertised frame rate independently of the `onMetaData`-derived value; when `None`, the `a=framerate:` line is omitted entirely. `server_ip` populates the SDP origin address.
pub fn build_sdp(codec: &CodecParams, server_ip: &str, fps: Option<f32>) -> String {
    let profile_level = profile_level_id(&codec.sps).unwrap_or_else(|| FALLBACK_PROFILE_LEVEL_ID.to_string());
    let sprop_parameter_sets = format!("{},{}", base64_encode(&codec.sps), base64_encode(&codec.pps));

    let mut s = String::new();
    s.push_str("v=0");
    s.push_str(SDP_LINE_END);
    s.push_str(&format!("o=- 0 0 IN IP4 {server_ip}"));
    s.push_str(SDP_LINE_END);
    s.push_str(&format!("s={SDP_SESSION_NAME}"));
    s.push_str(SDP_LINE_END);
    s.push_str("t=0 0");
    s.push_str(SDP_LINE_END);
    s.push_str(&format!("m=video 0 RTP/AVP {PAYLOAD_TYPE_H264}"));
    s.push_str(SDP_LINE_END);
    s.push_str("a=control:streamid=0");
    s.push_str(SDP_LINE_END);
    s.push_str(&format!("a=rtpmap:{PAYLOAD_TYPE_H264} H264/{RTP_CLOCK_RATE_HZ}"));
    s.push_str(SDP_LINE_END);
    s.push_str(&format!("a=fmtp:{PAYLOAD_TYPE_H264} packetization-mode=1;profile-level-id={profile_level};sprop-parameter-sets={sprop_parameter_sets}"));
    s.push_str(SDP_LINE_END);
    if let Some(framerate) = fps {
        s.push_str(&format!("a=framerate:{framerate}"));
        s.push_str(SDP_LINE_END);
    }
    s
}

/// Appends one 24-bit triplet as four Base64 characters to `out`.
fn push_base64_quartet(out: &mut String, triplet: u32) {
    out.push(char_from_alphabet((triplet >> 18) & 0x3F));
    out.push(char_from_alphabet((triplet >> 12) & 0x3F));
    out.push(char_from_alphabet((triplet >> 6) & 0x3F));
    out.push(char_from_alphabet(triplet & 0x3F));
}

fn char_from_alphabet(value: u32) -> char {
    BASE64_ALPHABET[value as usize] as char
}

fn char_from_hex(value: u8) -> char {
    HEX_DIGITS_UPPER[value as usize] as char
}
