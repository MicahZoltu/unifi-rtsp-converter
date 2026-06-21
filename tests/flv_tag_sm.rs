//! Integration tests for `flvproxy::flv_parser` step 03: the push-based FLV tag framing state machine. Covers the exact cases enumerated in `plan/03-flv-tag-state-machine.md`, asserting byte-for-byte event bodies and exact timestamp values.

use flvproxy::flv_parser::MAX_TAG_DATA_SIZE;
use flvproxy::flv_parser::{FlvParser, ParseError, TagEvent};

mod common;
use common::*;

/// Script-tag (`0x12`) payload: a minimal AMF0 `onMetaData` string marker. Exact bytes are arbitrary; the framer treats the body as opaque.
const SCRIPT_BODY: [u8; 5] = [0x02, 0x00, 0x03, b'o', b'n'];

/// Video-tag (`0x09`) payload: a minimal standard AVC keyframe header (`0x17` = keyframe + AVC, `0x01` = NALU, composition time 0) plus a single filler NALU byte. Opaque to the framer.
const VIDEO_BODY: [u8; 6] = [0x17, 0x01, 0x00, 0x00, 0x00, 0xFF];

/// Builds the canonical two-tag stream used by most tests: a leading previous-tag-size of zero, one script tag, then one video tag.
fn two_tag_stream() -> Vec<u8> {
    let mut s = vec![0, 0, 0, 0];
    push_tag(&mut s, 0x12, 1000, &SCRIPT_BODY);
    push_tag(&mut s, 0x09, 2000, &VIDEO_BODY);
    s
}

/// Drains a complete stream through a fresh parser and collects all events.
fn collect_events(stream: &[u8]) -> Vec<TagEvent> {
    let mut p = FlvParser::new();
    p.push(stream).expect("one-shot push")
}

#[test]
fn one_shot_push_emits_both_tags_with_exact_bodies_and_timestamps() {
    let stream = two_tag_stream();
    let events = collect_events(&stream);
    assert_eq!(events.len(), 2);
    assert_eq!(events[0], TagEvent::Script { timestamp_ms: 1000, body: SCRIPT_BODY.to_vec() });
    assert_eq!(events[1], TagEvent::Video { timestamp_ms: 2000, body: VIDEO_BODY.to_vec() });
}

#[test]
fn byte_by_byte_push_emits_the_same_two_events() {
    let stream = two_tag_stream();
    let mut p = FlvParser::new();
    let mut all = Vec::new();
    for byte in &stream {
        let evs = p.push(std::slice::from_ref(byte)).expect("single-byte push");
        all.extend(evs);
    }
    assert_eq!(all.len(), 2);
    assert_eq!(all[0], TagEvent::Script { timestamp_ms: 1000, body: SCRIPT_BODY.to_vec() });
    assert_eq!(all[1], TagEvent::Video { timestamp_ms: 2000, body: VIDEO_BODY.to_vec() });
}

#[test]
fn every_split_boundary_yields_the_same_events_as_one_shot() {
    let stream = two_tag_stream();
    let reference = collect_events(&stream);
    assert_eq!(reference.len(), 2);
    for split in 0..=stream.len() {
        let mut p = FlvParser::new();
        let mut all = p.push(&stream[..split]).expect("first half");
        all.extend(p.push(&stream[split..]).expect("second half"));
        assert_eq!(all, reference, "events differ at split {split}");
    }
}

#[test]
fn timestamp_extended_field_combines_into_full_u32_with_rollover() {
    // First tag: low 24 bits all set, ext 0 → 0x00FFFFFF. Second tag: low 0, ext 1 → 0x01000000 (the rollover point).
    let mut s = vec![0, 0, 0, 0];
    push_tag(&mut s, 0x09, 0x00FF_FFFF, &VIDEO_BODY);
    push_tag(&mut s, 0x09, 0x0100_0000, &VIDEO_BODY);
    let events = collect_events(&s);
    assert_eq!(events.len(), 2);
    assert_eq!(events[0], TagEvent::Video { timestamp_ms: 0x00FF_FFFF, body: VIDEO_BODY.to_vec() });
    assert_eq!(events[1], TagEvent::Video { timestamp_ms: 0x0100_0000, body: VIDEO_BODY.to_vec() });
}

#[test]
fn oversized_data_size_returns_error_without_allocating_body() {
    // 12 MiB declared payload — above the 8 MiB cap, and a valid u24 (0xC00000 ≤ 0xFFFFFF) since the FLV `data_size` field is only 3 bytes. No body bytes are appended, so the only way this could allocate the body is if the framer ignored the cap; the error must fire first.
    let oversized: u32 = 0x00C0_0000;
    assert!(oversized > MAX_TAG_DATA_SIZE);
    assert!(oversized <= 0x00FF_FFFF);
    let mut s = vec![0, 0, 0, 0]; // leading previous-tag-size
    s.push(0x09); // video tag type
    s.extend_from_slice(&[(oversized >> 16) as u8, (oversized >> 8) as u8, oversized as u8]);
    s.extend_from_slice(&[0, 0, 0]); // timestamp low 24
    s.push(0); // timestamp extended
    s.extend_from_slice(&[0, 0, 0]); // stream id

    let mut p = FlvParser::new();
    let err = p.push(&s).expect_err("oversized tag must error");
    assert_eq!(err, ParseError::OversizedTag { tag_type: 0x09, data_size: oversized, cap: MAX_TAG_DATA_SIZE });
}

#[test]
fn empty_payload_emits_event_with_empty_body_and_consumes_following_prev_size() {
    // A zero-length script tag followed by a normal video tag. Producing the second event proves the previous-tag-size after the empty tag was read and the framer advanced correctly.
    let mut s = vec![0, 0, 0, 0];
    push_tag(&mut s, 0x12, 500, &[]);
    push_tag(&mut s, 0x09, 600, &VIDEO_BODY);
    let events = collect_events(&s);
    assert_eq!(events.len(), 2);
    assert_eq!(events[0], TagEvent::Script { timestamp_ms: 500, body: Vec::new() });
    assert_eq!(events[1], TagEvent::Video { timestamp_ms: 600, body: VIDEO_BODY.to_vec() });
}

#[test]
fn unknown_tag_type_is_reported_not_dropped() {
    let mut s = vec![0, 0, 0, 0];
    push_tag(&mut s, 0x42, 1234, &VIDEO_BODY);
    let events = collect_events(&s);
    assert_eq!(events.len(), 1);
    assert_eq!(events[0], TagEvent::Unknown { tag_type: 0x42, timestamp_ms: 1234, body: VIDEO_BODY.to_vec() });
}

#[test]
fn partial_push_across_three_chunks_emits_events_in_order() {
    let stream = two_tag_stream();
    let cut_a = 5;
    let cut_b = stream.len() / 2;
    let mut p = FlvParser::new();
    let mut all = p.push(&stream[..cut_a]).expect("chunk a");
    all.extend(p.push(&stream[cut_a..cut_b]).expect("chunk b"));
    all.extend(p.push(&stream[cut_b..]).expect("chunk c"));
    assert_eq!(all.len(), 2);
    assert_eq!(all[0], TagEvent::Script { timestamp_ms: 1000, body: SCRIPT_BODY.to_vec() });
    assert_eq!(all[1], TagEvent::Video { timestamp_ms: 2000, body: VIDEO_BODY.to_vec() });
}
