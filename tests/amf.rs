//! Integration tests for `flvproxy::amf` step 06: the minimal AMF0 reader and
//! the `onMetaData` → `StreamMetadata` extractor. Covers every case enumerated
//! in `plan/06-script-metadata.md`, asserting byte-for-byte parsed values.
//!
//! `onMetaData` is 10 ASCII bytes, so its AMF0 string-length field is `10`
//! (0x000A). The plan's hand-encode example wrote `u16(11)`, which is an
//! off-by-one in the plan text: a length of 11 would swallow the next byte
//! (the `0x08` ECMA-array marker) and corrupt the parse. These tests use the
//! spec-correct length `10`.

use flvproxy::amf::{is_metadata_tag, parse_on_metadata, StreamMetadata};

/// Encodes an AMF0 string value: `0x02` marker + u16 big-endian length + bytes.
fn amf_string(s: &str) -> Vec<u8> {
    let bytes = s.as_bytes();
    let mut v = vec![0x02];
    v.extend_from_slice(&(bytes.len() as u16).to_be_bytes());
    v.extend_from_slice(bytes);
    v
}

/// Encodes an AMF0 number value: `0x00` marker + 8-byte big-endian f64.
fn amf_number(n: f64) -> Vec<u8> {
    let mut v = vec![0x00];
    v.extend_from_slice(&n.to_be_bytes());
    v
}

/// Encodes an AMF0 object key as it appears inside an object/ECMA array: u16
/// big-endian length + bytes, **no** marker byte (keys are untyped strings).
fn amf_key(s: &str) -> Vec<u8> {
    let bytes = s.as_bytes();
    let mut v = (bytes.len() as u16).to_be_bytes().to_vec();
    v.extend_from_slice(bytes);
    v
}

/// Encodes one object pair: key bytes immediately followed by the value's
/// full AMF0 encoding (marker + payload).
fn amf_pair(key: &str, value: &[u8]) -> Vec<u8> {
    let mut v = amf_key(key);
    v.extend_from_slice(value);
    v
}

/// Encodes an ECMA-array header: `0x08` marker + u32 big-endian count hint.
fn ecma_array_header(count: u32) -> Vec<u8> {
    let mut v = vec![0x08];
    v.extend_from_slice(&count.to_be_bytes());
    v
}

/// The AMF0 object end marker: empty key (u16 length 0) + `0x09`.
const OBJECT_END: [u8; 3] = [0x00, 0x00, 0x09];

/// Builds the canonical `onMetaData` body used by the happy-path tests: name
/// string, ECMA array with three pairs (videoWidth/Height/Fps), end marker.
fn full_metadata_body() -> Vec<u8> {
    let mut v = amf_string("onMetaData");
    v.extend(ecma_array_header(3));
    v.extend(amf_pair("videoWidth", &amf_number(1920.0)));
    v.extend(amf_pair("videoHeight", &amf_number(1080.0)));
    v.extend(amf_pair("videoFps", &amf_number(30.0)));
    v.extend_from_slice(&OBJECT_END);
    v
}

#[test]
fn on_metadata_body_yields_width_height_and_fps() {
    let body = full_metadata_body();
    assert_eq!(
        parse_on_metadata(&body),
        Some(StreamMetadata {
            width: Some(1920),
            height: Some(1080),
            fps: Some(30.0),
        })
    );
}

#[test]
fn missing_video_fps_leaves_fps_none_but_keeps_dimensions() {
    let mut body = amf_string("onMetaData");
    body.extend(ecma_array_header(2));
    body.extend(amf_pair("videoWidth", &amf_number(1920.0)));
    body.extend(amf_pair("videoHeight", &amf_number(1080.0)));
    body.extend_from_slice(&OBJECT_END);
    assert_eq!(
        parse_on_metadata(&body),
        Some(StreamMetadata {
            width: Some(1920),
            height: Some(1080),
            fps: None,
        })
    );
}

#[test]
fn missing_all_three_fields_yields_all_none() {
    let mut body = amf_string("onMetaData");
    body.extend(ecma_array_header(0));
    body.extend_from_slice(&OBJECT_END);
    assert_eq!(
        parse_on_metadata(&body),
        Some(StreamMetadata {
            width: None,
            height: None,
            fps: None,
        })
    );
}

#[test]
fn object_form_of_properties_is_accepted_alongside_ecma_array() {
    // Same payload but with the Object marker (0x03) instead of ECMA array
    // (0x08): no count hint, pairs then end marker.
    let mut body = amf_string("onMetaData");
    body.push(0x03);
    body.extend(amf_pair("videoWidth", &amf_number(1920.0)));
    body.extend(amf_pair("videoHeight", &amf_number(1080.0)));
    body.extend(amf_pair("videoFps", &amf_number(30.0)));
    body.extend_from_slice(&OBJECT_END);
    assert_eq!(
        parse_on_metadata(&body),
        Some(StreamMetadata {
            width: Some(1920),
            height: Some(1080),
            fps: Some(30.0),
        })
    );
}

#[test]
fn wrong_first_string_on_mpma_yields_none() {
    let mut body = amf_string("onMpma");
    body.extend(ecma_array_header(0));
    body.extend_from_slice(&OBJECT_END);
    assert_eq!(parse_on_metadata(&body), None);
}

#[test]
fn on_clock_sync_string_followed_by_garbage_yields_none() {
    let mut body = amf_string("onClockSync");
    body.extend_from_slice(&[0xFF, 0xEE, 0x01]);
    assert_eq!(parse_on_metadata(&body), None);
}

#[test]
fn second_value_not_an_object_or_ecma_array_yields_none() {
    // First value is onMetaData, second is a bare Number — not a properties
    // container.
    let mut body = amf_string("onMetaData");
    body.extend(amf_number(42.0));
    assert_eq!(parse_on_metadata(&body), None);
}

#[test]
fn truncated_body_mid_number_yields_none_without_panic() {
    let mut body = amf_string("onMetaData");
    body.extend(ecma_array_header(1));
    body.extend(amf_key("videoWidth"));
    body.push(0x00); // Number marker
    body.extend_from_slice(&[0x40, 0x00, 0x00, 0x00]); // only 4 of 8 payload bytes
    assert_eq!(parse_on_metadata(&body), None);
}

#[test]
fn truncated_ecma_array_count_yields_none() {
    let mut body = amf_string("onMetaData");
    body.push(0x08);
    body.extend_from_slice(&[0x00, 0x00]); // only 2 of 4 count bytes
    assert_eq!(parse_on_metadata(&body), None);
}

#[test]
fn empty_body_yields_none() {
    assert_eq!(parse_on_metadata(&[]), None);
}

#[test]
fn unknown_amf_marker_as_a_value_returns_fields_read_so_far_without_panic() {
    // videoWidth and videoHeight come before a property whose value carries
    // marker 0x0D, which this reader does not decode. The walk stops at that
    // marker (its body length is unknowable), so videoFps after it is never
    // reached. The two fields already read are returned; nothing panics.
    let mut body = amf_string("onMetaData");
    body.extend(ecma_array_header(3));
    body.extend(amf_pair("videoWidth", &amf_number(1920.0)));
    body.extend(amf_pair("videoHeight", &amf_number(1080.0)));
    body.extend(amf_key("weirdProperty"));
    body.push(0x0D); // unknown marker, no body
    body.extend(amf_pair("videoFps", &amf_number(30.0))); // never reached
    body.extend_from_slice(&OBJECT_END); // never reached
    assert_eq!(
        parse_on_metadata(&body),
        Some(StreamMetadata {
            width: Some(1920),
            height: Some(1080),
            fps: None,
        })
    );
}

#[test]
fn negative_width_clamps_to_zero() {
    let mut body = amf_string("onMetaData");
    body.extend(ecma_array_header(1));
    body.extend(amf_pair("videoWidth", &amf_number(-42.0)));
    body.extend_from_slice(&OBJECT_END);
    assert_eq!(
        parse_on_metadata(&body),
        Some(StreamMetadata {
            width: Some(0),
            height: None,
            fps: None,
        })
    );
}

#[test]
fn extra_unknown_properties_before_the_three_fields_yield_nothing() {
    // An unknown marker appears as the very first property value, before any
    // of the three fields: the walk stops immediately and all three stay None.
    let mut body = amf_string("onMetaData");
    body.extend(ecma_array_header(2));
    body.extend(amf_key("firstProp"));
    body.push(0x0D); // unknown marker
    body.extend(amf_pair("videoWidth", &amf_number(1920.0))); // never reached
    body.extend_from_slice(&OBJECT_END); // never reached
    assert_eq!(
        parse_on_metadata(&body),
        Some(StreamMetadata {
            width: None,
            height: None,
            fps: None,
        })
    );
}

#[test]
fn is_metadata_tag_recognizes_on_metadata_preamble() {
    let body = full_metadata_body();
    assert!(is_metadata_tag(&body));
}

#[test]
fn is_metadata_tag_rejects_on_mpma_preamble() {
    let body = amf_string("onMpma");
    assert!(!is_metadata_tag(&body));
}

#[test]
fn is_metadata_tag_rejects_empty_body() {
    assert!(!is_metadata_tag(&[]));
}

#[test]
fn is_metadata_tag_rejects_body_starting_with_a_non_string_marker() {
    // ECMA-array marker first, not a string marker.
    let mut body = ecma_array_header(0);
    body.extend_from_slice(&OBJECT_END);
    assert!(!is_metadata_tag(&body));
}

#[test]
fn is_metadata_tag_rejects_a_truncated_preamble() {
    // Only the marker + one length byte + 3 name bytes — short of the full
    // 13-byte preamble.
    let body = [0x02, 0x00, 0x0A, b'o', b'n', b'M'];
    assert!(!is_metadata_tag(&body));
}

#[test]
fn is_metadata_tag_rejects_a_wrong_length_field_for_the_same_name_bytes() {
    // Marker + length 0x00 + name bytes — length field says zero but name
    // bytes follow; the preamble check requires the length to equal the name
    // byte count.
    let mut body = vec![0x02, 0x00, 0x00];
    body.extend_from_slice(b"onMetaData");
    assert!(!is_metadata_tag(&body));
}
