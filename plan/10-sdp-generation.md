# Step 10 — SDP Generation

**Depends on:** Step 08 (CodecParams shape).

## Goal

Generate the SDP body returned by RTSP `DESCRIBE`. Includes correct
`profile-level-id` (from SPS bytes 1-3) and `sprop-parameter-sets`
(base64 of SPS,PPS). Implement a tiny base64 encoder (no crates).

## Tasks — `src/sdp.rs`

1. `fn base64_encode(input: &[u8]) -> String` — standard alphabet
   `A-Za-z0-9+/`, padding `=`. (Verify against known vectors.)
2. `fn profile_level_id(sps: &[u8]) -> Option<String>`:
   - Requires `sps.len() >= 4` (NALU header byte + 3 profile/compat/level).
   - Returns 6 uppercase hex digits from `sps[1..4]` (e.g. `4D401F`).
   - `None` if SPS too short.
3. `fn build_sdp(codec: &CodecParams, server_ip: &str, fps: Option<f32>)
   -> String` producing exactly the format in `PROJECT.md`:
   ```
   v=0
   o=- 0 0 IN IP4 0.0.0.0
   s=UniFi Camera Stream
   t=0 0
   m=video 0 RTP/AVP 96
   a=control:streamid=0
   a=rtpmap:96 H264/90000
   a=fmtp:96 packetization-mode=1;profile-level-id=<PLI>;sprop-parameter-sets=<b64(SPS)>,<b64(PPS)>
   a=framerate:<fps>
   ```
   - Line endings: `\r\n` (SDP spec) — confirm and test.
   - If `fps` is `None`, omit the `a=framerate:` line entirely (don't emit a
     dangling empty value).
   - If `profile_level_id` returns `None`, emit `profile-level-id=42001E`
     (a safe baseline default) — document this fallback.
4. Use `codec.width`/`height`/`fps` to optionally add nothing extra for now
   (the spec SDP doesn't include image size). Keep it minimal and matching the
   reference exactly.

## Validation (automated) — `tests/sdp.rs`

Base64 (RFC 4648 §10 test vectors, all 4):
- `""` → `""`
- `"f"` → `"Zg=="`
- `"fo"` → `"Zm8="`
- `"foo"` → `"Zm9v"`
- `"foob"` → `"Zm9vYg=="`
- `"fooba"` → `"Zm9vYmE="`
- `"foobar"` → `"Zm9vYmFy"`
- A 3-byte vector `[0xDE,0xAD,0xBE]` → `"3q2+"`.

profile_level_id:
- SPS `[0x67,0x4D,0x40,0x1F,...]` → `"4D401F"`.
- SPS of length 2 → `None`.

SDP:
- Build a `CodecParams` with SPS `[0x67,0x4D,0x40,0x1F,0x...]`, PPS
   `[0x68,0xCE,...]`, fps `Some(30.0)` → assert the full string equals the
   expected literal (compute expected `sprop-parameter-sets` by calling your
   own `base64_encode` — tests should be self-consistent, not hard-coded magic).
- fps `None` → no `a=framerate:` line.
- All lines end with `\r\n`; the body ends with `\r\n`.
- Assert `sprop-parameter-sets` = `base64(sps) + "," + base64(pps)`.

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

- Do not serve SDP over RTSP yet (step 11/11). Do not add audio lines.
