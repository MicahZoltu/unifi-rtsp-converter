//! Integration tests for `flvproxy::flv_parser` step 26: the resync scan. Covers the cases enumerated in `plan/26-error-handling-and-resync.md` task 1 and "Validation (automated)" — resync finds the next valid tag after garbage, returns `None` for pure garbage without panicking, recovers once a valid tag arrives, rejects an oversized header at the scan start, and surfaces `ResyncBufferOverflow` when a peer streams pure garbage past the cap.

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
