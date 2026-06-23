# 01 — FLV resync for extendedFlv `0x00` tags

## Goal

Make `FlvParser::resync()` able to recover framing for the production stream format (UniFi extendedFlv `0x00` video tags), not just the standard-FLV `{0x08,0x09,0x12}` tag types. Today the resync feature is effectively dead code for the production 7550 path, because the camera pushes `0x00` swapped-header tags and `resync()` explicitly skips them (`flv_parser.rs:314`), so a desync on the production stream drops the connection via `ResyncBufferOverflow` instead of recovering.

## Context

The production 7550 ingestion is extendedFlv: the onMetaData script tag carries `extendedFormat: true`, and video frames arrive as type `0x00` with a non-standard header layout where the timestamp field precedes the data-size field (swapped relative to standard FLV). `State::TagHeader` already decodes both layouts correctly (`flv_parser.rs:258-274`). But `resync()` (`flv_parser.rs:315`) only matches `{0x08,0x09,0x12}` candidates, so after an oversized-tag error sends the parser into `State::Resyncing`, a production stream can never find a valid boundary and the buffer grows until `MAX_RESYNC_BUFFER_BYTES` is exceeded and the connection is dropped. The never-crash guarantee (the whole point of step 26) therefore does not hold for the production format.

## Scope

In: extend `resync()` to recognise `0x00` candidates using the swapped-header layout; add a unit test mirroring the existing standard-layout resync test but with a `0x00` tag; update the `resync()` doc comment to drop the "cannot recover extendedFlv" caveat.

Out: changing the standard-layout path; changing `State::TagHeader` decoding; changing `MAX_RESYNC_BUFFER_BYTES`; any change to how `0x00` heartbeat/telemetry trailers (`SkipExtFlvTrailer`) are handled after resync (resync transitions straight to `TagBody`, which already routes `0x00`/`dsize==0` correctly on the next iteration).

## Approach

1. In `resync()`, after the existing `t == TAG_TYPE_AUDIO || t == TAG_TYPE_VIDEO || t == TAG_TYPE_SCRIPT` branch, add a branch for `t == 0x00`. For a `0x00` candidate at offset `i`, decode the swapped header exactly as `State::TagHeader` does: `ts_low = u32::from_be_bytes([0, h[1], h[2], h[3]])`, `ts_ext = u32::from(h[4])`, `dsize = u32::from_be_bytes([0, h[5], h[6], h[7]])`, `sid = [h[8], h[9], h[10]]`. Accept the boundary iff `dsize <= MAX_TAG_DATA_SIZE && sid == [0,0,0]`.
2. On acceptance, drain `..i + TAG_HEADER_BYTES`, set `state = State::TagBody { tag_type: 0x00, data_size: dsize, timestamp_ms: (ts_ext << TIMESTAMP_LOW_BITS) | ts_low }`, and return `Some(i)` (the garbage bytes skipped), matching the standard branch's return shape.
3. Reuse a small private helper or inline the decode — the existing code inlines in `State::TagHeader`; mirroring that inline is fine and avoids a premature abstraction. If the two `0x00` decode sites would drift, a private `fn decode_extflv_header(h: &[u8]) -> (data_size, timestamp_ms)` is acceptable, but only if `State::TagHeader` is refactored to call it too (single source of truth). Prefer the inline mirror unless the diff is clearly cleaner with the helper.
4. Update the `resync()` doc comment: remove the sentence "Only the three standard tag types are matched … A real extendedFlv stream that desyncs cannot be recovered …" and replace with a one-paragraph note that both the standard layout (`{0x08,0x09,0x12}`) and the extendedFlv swapped layout (`0x00`) are matched, each decoded with its respective header layout, so resync covers the production format.
5. Update the `State::Resyncing` comment if it implies production streams cannot resync.

## Test

Add `resync_recovers_at_extflv_0x00_tag` in `flv_parser.rs`'s `#[cfg(test)]` module, mirroring the existing standard-layout resync test: feed garbage bytes followed by a valid `0x00` swapped-header tag (with a small body), call `resync()` after the oversized-tag error puts the parser in `Resyncing`, assert `Some(skipped)` is returned with the right skip count, then `push` the body and `drain` an event whose `tag_type`/`timestamp`/`data_size` match the `0x00` header. Add a negative case: a `0x00` candidate with `dsize > MAX_TAG_DATA_SIZE` is not accepted (returns `None`).

## Files

- `src/flv_parser.rs` — `resync()` body, doc comment, `State::Resyncing` comment, new tests.

## Acceptance

- `resync()` returns `Some(n)` for a valid `0x00` swapped-header boundary and transitions to `TagBody` carrying the swapped-decoded fields.
- `resync()` returns `None` for an oversized `0x00` candidate.
- Existing standard-layout resync test still passes unchanged.
- New test passes; host build, clippy `-D warnings`, `cargo test`, and `cargo build --target x86_64-pc-windows-gnu` all green.
