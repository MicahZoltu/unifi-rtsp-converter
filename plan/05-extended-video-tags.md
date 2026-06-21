# Step 05 — Extended Video Tags (ExVideoTagHeader)

**Depends on:** Step 04.

## Goal

Implement the `extendedFlv` extended path: `is_ex_header == true` video tags with PacketType = SequenceStart / CodedFrames / CodedFramesX / Metadata. Reuse the AVC config + NALU helpers from step 04 so both paths converge on the same `AvcDecoderConfig` / `NaluFrame` types.

## Tasks — `src/flv_parser.rs` (video dispatcher) + `src/avc.rs` (extend)

1. `enum VideoTagKind { Standard, Extended }` and a top-level dispatcher:
   ```
   fn parse_video_tag(payload: &[u8]) -> Result<VideoTagEvent, ParseError>
   ```
   where the first byte's bit 7 selects the path. The dispatcher is what the tag state machine (step 03) will call once wired together (wiring happens later; here expose and test the function directly).
2. `enum VideoTagEvent`:
   - `Config(AvcDecoderConfig)`             // both standard seq header & ext SequenceStart
   - `Frame(NaluFrame)`                      // both NALU & ext CodedFrames/CodedFramesX
   - `SequenceEnd`
   - `Metadata`                              // skipped, no payload retained
   - `Ignored`                               // audio-style skip / unknown
3. Standard path (bit 7 == 0): reuse step 04 logic, map results to the enum.
4. Extended path (bit 7 == 1):
   - `frame_type = (byte0 >> 4) & 0x07`
   - `packet_type = byte0 & 0x0F`
   - bytes 1-4 = FourCC (ASCII). For this project only `"avc1"`/`"hvc1"`? — Actually H.264 only: accept FourCC `b"avc1"`; for `b"hvc1"` (H.265) return `Ignored` with a clear log hook (don't crash; we don't support HEVC).
   - `PacketType 0 SequenceStart`: remaining bytes = AVCDecoderConfigurationRecord → reuse `parse_avc_config` → `VideoTagEvent::Config`.
   - `PacketType 1 CodedFrames`: bytes 5-7 = composition time SI24 (consume & discard), rest = length-prefixed NALUs → `split_length_prefixed_nalus` → `VideoTagEvent::Frame`.
   - `PacketType 3 CodedFramesX`: no composition time; rest = length-prefixed NALUs → `VideoTagEvent::Frame`.
   - `PacketType 2 SequenceEnd` → `VideoTagEvent::SequenceEnd`.
   - `PacketType 4 Metadata` → `VideoTagEvent::Metadata`.
   - Other packet types → `Ignored` (defensive).
5. `is_keyframe` for extended frames = `frame_type == 1`.

## Validation (automated) — `tests/video_tag_dispatcher.rs`

For each scenario build the raw video tag payload (the `body` that step 03 would emit) and assert the dispatcher output.

- Standard keyframe NALU tag (`0x17,0x01,0,0,0, len,NALU…`) → `Frame` with `is_keyframe=true`, one NALU.
- Standard seq header (`0x17,0x00,0,0,0, <config>`) → `Config` with parsed SPS/PPS equal to what `parse_avc_config` returns on the same config bytes.
- Extended SequenceStart (`0x90` [ex=1,ftype=1,ptype=0], `b"avc1"`, <config>) → `Config` identical to the standard seq header case.
- Extended CodedFramesX (`0x20` [ex=1,ftype=2,ptype=3], `b"avc1"`, two length-prefixed NALUs) → `Frame`, `is_keyframe=false`, 2 NALUs.
- Extended CodedFrames (`0x10` [ex=1,ftype=1,ptype=1], `b"avc1"`, `0,0,0` comp time, one NALU) → `Frame`, `is_keyframe=true`.
- Extended SequenceEnd (`0x?2` with ex=1, ptype=2) → `SequenceEnd`.
- Extended Metadata (`0x?4`) → `Metadata`.
- Extended with FourCC `b"hvc1"` → `Ignored` (no panic, no NALU parse attempt).
- Truncated CodedFrames (comp time only 2 bytes) → `Err(Truncated)`.

## Quality Gate (mandatory — step is not complete until this passes)

Run the **Standard Quality Gate** from `plan/README.md`. Then **step back and review the whole codebase**, not just the diff:

- Does this change respect the module boundaries in `PROJECT.md`, or did you bend them? If bent, refactor now.
- Did consuming this step reveal that an earlier module's API is awkward, mis-named, or leaky? Go back and fix that module — do not paper over it here.
- Any new duplication across modules? Extract a shared helper into the owning module.
- Are logging, error, and test styles consistent with the conventions established by earlier steps?
- Did you introduce a `// TODO` / `// FIXME` / `// HACK`, commented-out code, or a magic number? Remove it, name it as a constant, or log it in `DEBT.md`.

**Hard rules:**
- If the gate fails, you do **not** proceed to the next step.
- If passing it properly requires reworking an earlier step, do that rework now — **iterating or redoing is preferred over hacking to move on.**
- A step that "works but feels hacky" is a failed step. Reopen it.

## Debt notes

If anything was deferred (a workaround, a "good enough for now", an unclear decision), append a line to `DEBT.md` at the repo root (create the file if absent — see `plan/README.md` for the format):

`step NN | <file>:<area> | <what> | <FIX NOW | TRIGGER: ...>`

- `FIX NOW` items must be resolved before the next dedicated review (`07` / `13` / `24` / `27`).
- `TRIGGER:` items must name the concrete future event that forces revisiting them.
- No silent hacks: if you hacked it, log it. If you can fix it now, fix it now and don't log it.

## Do not

- Do not emit RTP or touch stream state yet. Do not handle audio.
