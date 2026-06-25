//! Integration tests for `flvproxy::flv_parser`: the resync scan. Covers resync finds the next valid tag after garbage, returns `None` for pure garbage without panicking, recovers once a valid tag arrives, rejects an oversized header at the scan start, and surfaces `ResyncBufferOverflow` when a peer streams pure garbage past the cap.

use flvproxy::flv_parser::{FlvParser, ParseError, TagEvent, MAX_RESYNC_BUFFER_BYTES, MAX_TAG_DATA_SIZE};

mod common;
use common::*;

/// Minimal standard video-tag body (keyframe + AVC, NALU, composition time 0, one filler NALU byte). Opaque to the framer; used to build valid tags the resync scan must land on.
const VIDEO_BODY: [u8; 6] = [0x17, 0x01, 0x00, 0x00, 0x00, 0xFF];

/// Minimal script-tag body (AMF0 `onMetaData` string marker). Opaque to the framer.
const SCRIPT_BODY: [u8; 5] = [0x02, 0x00, 0x03, b'o', b'n'];

/// An `OversizedTag` data-size (12 MiB) that exceeds the 8 MiB cap yet stays within the 3-byte u24 range, so the framer's cap fires before any body allocation.
const OVERSIZED_DATA_SIZE: u32 = 0x00C0_0000;

/// A four-byte FLV previous-tag-size of zero, the field the framer reads and discards between tags. Prepended so a fresh parser (which starts in `PrevTagSize`) reaches the following oversized header and errors into the `Resyncing` state.
const LEADING_PREV_TAG_SIZE: [u8; 4] = [0, 0, 0, 0];

/// Appends one bare 11-byte FLV tag header with the given type, data-size, and a zero timestamp/stream-id, with NO trailing previous-tag-size and NO body. The framer rejects it as `OversizedTag` (when `data_size` exceeds the cap) and retains it in the buffer for the resync scan to skip past.
fn push_bare_header(out: &mut Vec<u8>, tag_type: u8, data_size: u32) {
    out.push(tag_type);
    out.extend_from_slice(&[(data_size >> 16) as u8, (data_size >> 8) as u8, data_size as u8]);
    out.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0]);
}

/// Appends one bare 11-byte extendedFlv `0x00` swapped-layout tag header with the given timestamp and data-size, NO trailing previous-tag-size (extendedFlv omits it after `0x00` video tags), and NO body. Layout: type(1) + ts_low(3) + ts_ext(1) + dsize(3) + sid(3), per `flv_parser::State::TagHeader`.
fn push_bare_extflv_header(out: &mut Vec<u8>, timestamp_ms: u32, data_size: u32) {
    out.push(0x00);
    let lo = timestamp_ms & 0x00FF_FFFF;
    let ext = (timestamp_ms >> 24) & 0xFF;
    out.extend_from_slice(&[(lo >> 16) as u8, (lo >> 8) as u8, lo as u8]);
    out.push(ext as u8);
    out.extend_from_slice(&[(data_size >> 16) as u8, (data_size >> 8) as u8, data_size as u8]);
    out.extend_from_slice(&[0, 0, 0]);
}

/// Appends a complete extendedFlv `0x00` video tag (11-byte swapped header + `body`, no trailing previous-tag-size) to `out`. Mirrors the production format where `0x00` video tags carry no prev_tag_size after the body.
fn push_extflv_tag(out: &mut Vec<u8>, timestamp_ms: u32, body: &[u8]) {
    let n = body.len() as u32;
    push_bare_extflv_header(out, timestamp_ms, n);
    out.extend_from_slice(body);
}

#[test]
fn resync_finds_next_valid_tag_after_oversized_garbage() {
    let mut s = Vec::new();
    s.extend_from_slice(&LEADING_PREV_TAG_SIZE);
    push_bare_header(&mut s, 0x09, OVERSIZED_DATA_SIZE);
    push_tag(&mut s, 0x09, 2000, &VIDEO_BODY);

    let mut p = FlvParser::new();
    let err = p.push(&s).expect_err("oversized garbage must error");
    assert_eq!(err, ParseError::OversizedTag { tag_type: 0x09, data_size: OVERSIZED_DATA_SIZE, cap: MAX_TAG_DATA_SIZE });
    assert!(p.is_resyncing());

    // The retained oversized header is 11 bytes; the valid tag's type byte follows immediately at offset 11 (its own leading previous-tag-size was consumed as the next tag's prev, but the framer never reached it — resync scans the raw buffer and lands on the type byte directly).
    let skipped = p.resync().expect("resync must locate the valid tag");
    assert_eq!(skipped, 11);
    assert!(!p.is_resyncing());

    let events = p.push(&[]).expect("drain the recovered tag body");
    assert_eq!(events.len(), 1);
    assert_eq!(events[0], TagEvent::Video { timestamp_ms: 2000, body: VIDEO_BODY.to_vec() });
}

#[test]
fn resync_returns_none_for_pure_garbage_then_recovers_when_bytes_arrive() {
    let mut s = Vec::new();
    s.extend_from_slice(&LEADING_PREV_TAG_SIZE);
    push_bare_header(&mut s, 0x09, OVERSIZED_DATA_SIZE);
    s.extend_from_slice(&[0xAA; 20]);

    let mut p = FlvParser::new();
    let err = p.push(&s).expect_err("oversized garbage must error");
    assert!(matches!(err, ParseError::OversizedTag { .. }));
    assert!(p.is_resyncing());
    assert!(p.resync().is_none(), "no valid boundary in pure garbage");
    assert!(p.is_resyncing(), "parser stays in Resyncing after a None resync");

    // Buffer now holds the 31 retained bytes (11 oversized header + 20 filler). Feed a fresh previous-tag-size plus a valid script tag; the type byte lands at offset 31 + 4 = 35.
    let mut more = vec![0, 0, 0, 0];
    push_tag(&mut more, 0x12, 4242, &SCRIPT_BODY);
    let events = p.push(&more).expect("buffering in Resyncing state returns Ok(empty)");
    assert!(events.is_empty(), "no events until resync is driven");
    assert!(p.is_resyncing());

    let skipped = p.resync().expect("resync must locate the script tag once its bytes arrive");
    assert_eq!(skipped, 35);
    let events = p.push(&[]).expect("drain the recovered script body");
    assert_eq!(events.len(), 1);
    match &events[0] {
        TagEvent::Script { timestamp_ms, body } => {
            assert_eq!(*timestamp_ms, 4242);
            assert_eq!(*body, SCRIPT_BODY.to_vec());
        }
        other => panic!("expected Script, got {other:?}"),
    }
}

#[test]
fn resync_ignores_oversized_header_at_offset_zero_and_finds_later_valid_tag() {
    // The first plausible byte (0x09) is an oversized header — resync must reject it (data_size > cap) and keep scanning, not latch onto it.
    let mut s = Vec::new();
    s.extend_from_slice(&LEADING_PREV_TAG_SIZE);
    push_bare_header(&mut s, 0x09, OVERSIZED_DATA_SIZE);
    s.extend_from_slice(&[0, 0, 0, 0]);
    push_tag(&mut s, 0x08, 7000, &VIDEO_BODY);

    let mut p = FlvParser::new();
    let _ = p.push(&s).expect_err("oversized garbage must error");
    // Retained oversized header is 11 bytes; then a 4-byte previous-tag-size (0x00, not a tag type); the audio tag's type byte is at offset 15.
    let skipped = p.resync().expect("resync must skip the oversized header and find the audio tag");
    assert_eq!(skipped, 15);
    let events = p.push(&[]).expect("drain the recovered audio body");
    assert_eq!(events.len(), 1);
    assert_eq!(events[0], TagEvent::Audio { timestamp_ms: 7000, body: VIDEO_BODY.to_vec() });
}

#[test]
fn resync_buffer_overflow_errors_without_panic() {
    let mut s = Vec::new();
    s.extend_from_slice(&LEADING_PREV_TAG_SIZE);
    push_bare_header(&mut s, 0x09, OVERSIZED_DATA_SIZE);
    let mut p = FlvParser::new();
    let _ = p.push(&s).expect_err("oversized garbage must error");
    assert!(p.is_resyncing());

    // Stream pure non-tag garbage past the cap. None of these bytes is a plausible tag-type byte, so resync never recovers; the buffer-cap check fires instead.
    let garbage = vec![0xAAu8; MAX_RESYNC_BUFFER_BYTES + 1];
    let err = p.push(&garbage).expect_err("buffer overflow must error rather than grow unbounded");
    match err {
        ParseError::ResyncBufferOverflow { len, cap } => {
            assert!(len > cap);
            assert_eq!(cap, MAX_RESYNC_BUFFER_BYTES);
        }
        other => panic!("expected ResyncBufferOverflow, got {other:?}"),
    }
}

#[test]
fn resync_recovers_at_extflv_0x00_tag() {
    // The production 7550 path is extendedFlv `0x00` (swapped-header layout). Resync must recognise a `0x00` boundary and decode it with the swapped layout (timestamp in h[1..5], data-size in h[5..8]), not the standard layout. A second `0x00` tag follows so the two-level consistency check (which requires the next tag's header to validate) can confirm the boundary; extendedFlv `0x00` video tags carry no trailing previous-tag-size, so the tags pack back-to-back.
    let mut s = Vec::new();
    s.extend_from_slice(&LEADING_PREV_TAG_SIZE);
    push_bare_header(&mut s, 0x09, OVERSIZED_DATA_SIZE);
    push_extflv_tag(&mut s, 90000, &VIDEO_BODY);
    push_extflv_tag(&mut s, 93333, &VIDEO_BODY);

    let mut p = FlvParser::new();
    let err = p.push(&s).expect_err("oversized garbage must error");
    assert_eq!(err, ParseError::OversizedTag { tag_type: 0x09, data_size: OVERSIZED_DATA_SIZE, cap: MAX_TAG_DATA_SIZE });
    assert!(p.is_resyncing());

    // The retained oversized standard-layout header is 11 bytes; the first valid `0x00` tag's type byte follows immediately at offset 11.
    let skipped = p.resync().expect("resync must locate the extendedFlv 0x00 tag");
    assert_eq!(skipped, 11);
    assert!(!p.is_resyncing());

    let events = p.push(&[]).expect("drain the recovered 0x00 tag bodies");
    // Both `0x00` tags are fully buffered, so both drain: the first at ts=90000, the second at ts=93333.
    assert_eq!(events.len(), 2);
    assert_eq!(events[0], TagEvent::Video { timestamp_ms: 90000, body: VIDEO_BODY.to_vec() });
    assert_eq!(events[1], TagEvent::Video { timestamp_ms: 93333, body: VIDEO_BODY.to_vec() });
}

#[test]
fn resync_rejects_oversized_extflv_0x00_header_and_keeps_scanning() {
    // A `0x00` candidate whose swapped-layout data-size exceeds the cap must be rejected, not latched onto; resync keeps scanning for a later valid tag. The oversized `0x00` header is followed by a valid standard-layout `0x09` tag (with its leading previous-tag-size) so a standard candidate exists to land on.
    let mut s = Vec::new();
    s.extend_from_slice(&LEADING_PREV_TAG_SIZE);
    push_bare_header(&mut s, 0x09, OVERSIZED_DATA_SIZE);
    // An oversized `0x00` header (dsize > cap), then a 4-byte prev_tag_size, then a valid standard video tag.
    push_bare_extflv_header(&mut s, 1234, OVERSIZED_DATA_SIZE);
    s.extend_from_slice(&[0, 0, 0, 0]);
    push_tag(&mut s, 0x09, 2000, &VIDEO_BODY);

    let mut p = FlvParser::new();
    let _ = p.push(&s).expect_err("oversized garbage must error");
    assert!(p.is_resyncing());

    let skipped = p.resync().expect("resync must skip the oversized 0x00 header and find the later valid tag");
    // Retained oversized standard header (11) + oversized 0x00 header (11) + prev_tag_size (4) = 26 bytes of garbage before the valid tag's type byte.
    assert_eq!(skipped, 26);
    let events = p.push(&[]).expect("drain the recovered tag body");
    assert_eq!(events.len(), 1);
    assert_eq!(events[0], TagEvent::Video { timestamp_ms: 2000, body: VIDEO_BODY.to_vec() });
}
