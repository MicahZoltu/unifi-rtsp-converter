//! Integration tests for `flvproxy::flv_parser` step 02: uPFLV prefix detection and FLV header parsing. Covers the exact cases enumerated in `plan/02-flv-prefix-and-header.md`, asserting byte-for-byte values.

use flvproxy::flv_parser::{detect_and_strip_prefix, parse_header, FlvHeader, ParseError, FLV_SIGNATURE, UPFLV_PREFIX};

/// Canonical FLV header from `PROJECT.md` → "Layer 2": `46 4C 56 01 07 00 00 00 09` — version 1, audio+video flags, size 9.
const CANONICAL_HEADER: [u8; 9] = [0x46, 0x4C, 0x56, 0x01, 0x07, 0x00, 0x00, 0x00, 0x09];

#[test]
fn prefix_is_stripped_and_body_returned() {
    let mut buf = Vec::from(UPFLV_PREFIX);
    buf.extend_from_slice(&CANONICAL_HEADER);
    let body = detect_and_strip_prefix(&buf);
    assert_eq!(body, &CANONICAL_HEADER[..]);
}

#[test]
fn buffer_starting_with_flv_is_returned_unchanged() {
    let buf = Vec::from(&CANONICAL_HEADER[..]);
    let body = detect_and_strip_prefix(&buf);
    assert_eq!(body, &buf[..]);
}

#[test]
fn buffer_shorter_than_prefix_is_returned_unchanged() {
    let buf = [0xDEu8, 0x19, 0x16];
    let body = detect_and_strip_prefix(&buf[..]);
    assert_eq!(body, &buf[..]);
}

#[test]
fn eleven_non_matching_bytes_are_returned_unchanged() {
    // Eleven bytes that are NOT the uPFLV prefix must not be stripped.
    let buf = [0x46u8, 0x4C, 0x56, 0x01, 0x07, 0x00, 0x00, 0x00, 0x09, 0x00, 0x00];
    assert_eq!(buf.len(), UPFLV_PREFIX.len());
    let body = detect_and_strip_prefix(&buf[..]);
    assert_eq!(body, &buf[..]);
}

#[test]
fn canonical_header_parses_with_empty_remaining_slice() {
    let (remaining, header) = parse_header(&CANONICAL_HEADER).expect("canonical header");
    assert!(remaining.is_empty(), "remaining must be empty");
    assert_eq!(header, FlvHeader { version: 1, has_audio: true, has_video: true, header_size: 9 });
}

#[test]
fn truncated_buffer_returns_truncated_error() {
    let buf = [0x46u8, 0x4C, 0x56, 0x01, 0x07, 0x00, 0x00, 0x00];
    assert_eq!(parse_header(&buf[..]), Err(ParseError::Truncated));
}

#[test]
fn bad_signature_returns_bad_signature_error() {
    let mut buf = Vec::from(&CANONICAL_HEADER[..]);
    buf[2] = b'X';
    assert_eq!(parse_header(&buf), Err(ParseError::BadSignature));
}

#[test]
fn unsupported_version_returns_unsupported_version_error() {
    let mut buf = Vec::from(&CANONICAL_HEADER[..]);
    buf[3] = 0x02;
    assert_eq!(parse_header(&buf), Err(ParseError::UnsupportedVersion));
}

#[test]
fn header_size_above_nine_skips_trailing_bytes() {
    // Same canonical header but with header-size field = 12, followed by 3 skip bytes and a single marker byte that must remain in the slice.
    let mut buf = Vec::with_capacity(13);
    buf.extend_from_slice(&[0x46, 0x4C, 0x56, 0x01, 0x07, 0x00, 0x00, 0x00, 0x0C]);
    buf.extend_from_slice(&[0xAA, 0xAA, 0xAA]);
    buf.push(0x42);
    let (remaining, header) = parse_header(&buf).expect("extended header");
    assert_eq!(remaining, &[0x42]);
    assert_eq!(header.header_size, 12);
}

#[test]
fn prefix_then_header_chains_into_successful_parse() {
    let mut buf = Vec::from(UPFLV_PREFIX);
    buf.extend_from_slice(&CANONICAL_HEADER);
    let body = detect_and_strip_prefix(&buf);
    let (remaining, header) = parse_header(body).expect("parse after strip");
    assert!(remaining.is_empty());
    assert_eq!(header.version, 1);
    assert!(header.has_audio);
    assert!(header.has_video);
    assert_eq!(header.header_size, 9);
}

#[test]
fn audio_only_flags_parse_correctly() {
    // flags = 0x01 → audio bit set, video bit clear.
    let buf = [0x46, 0x4C, 0x56, 0x01, 0x01, 0x00, 0x00, 0x00, 0x09];
    let (_, header) = parse_header(&buf).expect("audio-only header");
    assert!(header.has_audio);
    assert!(!header.has_video);
}

#[test]
fn flv_signature_constant_is_ascii_flv() {
    assert_eq!(&FLV_SIGNATURE, b"FLV");
}
