# Step 04 — AVC Config Record + Length-Prefixed NALU Extraction

**Depends on:** Step 03.

## Goal

Parse the **standard-path** FLV video tag payload (CodecID=7, AVC) into either
an `AvcDecoderConfig` (SPS+PPS) or a list of NALUs (a frame). This is the core
codec glue; the extended path is step 05.

## Tasks — `src/avc.rs`

1. `struct AvcDecoderConfig { profile_indication: u8, profile_compat: u8,
   level_indication: u8, sps: Vec<u8>, pps: Vec<u8> }`
   (SPS/PPS stored **without** start code or length prefix).
2. `fn parse_avc_config(payload: &[u8]) -> Result<AvcDecoderConfig, AvcError>`
   per the layout in `PROJECT.md`:
   - byte 0 = configurationVersion (must be 1)
   - bytes 1-3 = profile/compat/level
   - byte 4 = `0xFF` (validate, but tolerate)
   - byte 5 = `numSPS` low 3 bits (expect 1; if >1, take the first, ignore rest)
   - 2-byte SPS length (BE u16) + SPS bytes
   - 1-byte numPPS (loop), 2-byte PPS length + PPS bytes (take all, but for
     this project keep the first PPS in the struct; store extras if easy)
3. `enum AvcPacketType { SeqHeader = 0, Nalu = 1, End = 2 }`.
4. `struct NaluFrame { is_keyframe: bool, nalus: Vec<Vec<u8>> }` (each NALU
   without length prefix).
5. `fn parse_avc_nalu_payload(payload: &[u8], is_keyframe: bool)
   -> Result<NaluFrame, AvcError>`:
   - byte 0 = `[FrameType:4][CodecID:4]` (caller already split; re-validate
     codec==7)
   - byte 1 = AVCPacketType (1 = NALU expected here; 0/2 → distinct return)
   - bytes 2-4 = composition time SI24 (ignored, but must be consumed)
   - rest = sequence of `[u32 BE length][NALU bytes]` until exhausted
   - Truncated length / length exceeding remaining → `AvcError::Truncated`.
   - Zero-length NALU → skip (or error — pick one, test it).
6. `fn split_length_prefixed_nalus(data: &[u8]) -> Result<Vec<Vec<u8>>, AvcError>`
   — the shared helper used above, factored out for direct testing.

## Validation (automated) — `tests/avc.rs`

- Hand-build a minimal `AvcDecoderConfig` byte blob (version 1, profile 0x4D,
   compat 0x40, level 0x1F, one SPS of length 2 `[0x67,0xAB]`, one PPS of
   length 1 `[0x68]`) → assert parsed fields match exactly, SPS/PPS bytes
   equal inputs.
- Build a NALU payload: `0x17` (keyframe+AVC), `0x01` (NALU), comp time
   `0x000000`, then two length-prefixed NALUs `[len=3][AA BB CC]` and
   `[len=1][DD]` → frame has `is_keyframe=true` and NALUs `[[AA,BB,CC],[DD]]`.
- Inter-frame: `0x27` → `is_keyframe=false`.
- Truncated: drop the last byte of the second NALU → `Err(Truncated)`.
- AVCPacketType=0 (seq header) passed to `parse_avc_nalu_payload` → returns a
   distinct variant / error so the caller routes it to `parse_avc_config`.
- `split_length_prefixed_nalus` on empty input → `Ok(vec![])`.
- Multiple SPS in config (numSPS=2) → returns first SPS, does not panic, and
   the parse pointer ends at the PPS section correctly (verify by checking PPS
   parses cleanly afterward).

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

- Do not handle the ExVideoTagHeader path yet (step 05). Do not emit RTP.
