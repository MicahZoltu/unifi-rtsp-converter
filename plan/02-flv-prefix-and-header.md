# Step 02 — uPFLV Prefix Detection + FLV Header Parsing

**Depends on:** Step 00.

## Goal

The first slice of the FLV parser: detect/strip the 11-byte uPFLV magic prefix
and parse the 9-byte FLV header. Pure byte logic, no I/O.

## Tasks — `src/flv_parser.rs`

1. Constants:
   - `UPFLV_PREFIX: [u8; 11] = [0xDE,0x19,0x16,0x15,0x47,0x17,0xDE,0x19,0x16,0x75,0x50]`
   - `FLV_SIGNATURE: [u8; 3] = *b"FLV"`
2. `fn detect_and_strip_prefix(buf: &[u8]) -> &[u8]`
   - If `buf.len() >= 11 && buf[..11] == UPFLV_PREFIX`, return `&buf[11..]`.
   - Otherwise return `buf` unchanged (per spec: assume no prefix if mismatch).
3. `struct FlvHeader { version: u8, has_audio: bool, has_video: bool,
   header_size: u32 }` and a `ParseError` enum (`Truncated`, `BadSignature`,
   `UnsupportedVersion`, ...).
4. `fn parse_header(buf: &[u8]) -> Result<(&[u8], FlvHeader), ParseError>`
   - Requires `>= 9` bytes.
   - Bytes 0-2 must be `FLV`.
   - Byte 3 = version (accept 1; treat others as `UnsupportedVersion` but still
     return — log only, don't fail hard; pick one behavior and test it).
   - Byte 4 flags: bit 0 = audio, bit 2 = video.
   - Bytes 5-8 = header size (big-endian u32); per spec it's 9. If it's > 9,
     skip the extra bytes (return a slice starting after `header_size`).
   - Returns the remaining slice (after the header, including any skip) plus
     the parsed struct.

## Validation (automated) — `tests/flv_prefix_header.rs`

Prefix:
- `detect_and_strip_prefix(&UPFLV_PREFIX[..])` followed by `b"FLV..."` returns
   the `FLV...` portion.
- A buffer that starts with `b"FLV"` (no prefix) is returned unchanged.
- A buffer < 11 bytes that doesn't match is returned unchanged.
- A buffer with 11 bytes that **don't** match the prefix is returned unchanged
   (per spec — don't treat random 11 bytes as prefix).

Header:
- Construct the canonical 9-byte header
   `46 4C 56 01 07 00 00 00 09` → `version=1`, `has_audio=true`,
   `has_video=true`, `header_size=9`, remaining slice empty.
- Truncated buffer (< 9 bytes) → `Err(Truncated)`.
- Bad signature (`b"FLX"...`) → `Err(BadSignature)`.
- `header_size = 12` with 3 trailing bytes → remaining slice starts after byte
   12 (i.e. those 3 bytes are skipped).

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

- `FIX NOW` items must be resolved before the next dedicated review (`06r` / `11r` / `16r` / `19`).
- `TRIGGER:` items must name the concrete future event that forces revisiting them.
- No silent hacks: if you hacked it, log it. If you can fix it now, fix it now and don't log it.

## Do not

- Do not implement tag parsing yet (step 03). Do not touch `std::net`.
