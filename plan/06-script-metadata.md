# Step 06 — Script Data Metadata (AMF0 onMetaData)

**Depends on:** Step 03.

## Goal

A **minimal** AMF0 reader sufficient to extract `videoWidth`, `videoHeight`,
`videoFps` from `onMetaData` script tags. Other script tags (`onMpma`,
`onClockSync`) are skipped without parsing. The parser only needs to handle
the value types that actually appear in those fields (number, string, boolean,
ECMA array / object end). Robustness over completeness: anything unknown is
skipped safely.

## Tasks — new `src/amf.rs`

1. A small recursive-descent AMF0 reader over a `&[u8]` cursor:
   - `0x00 Number` → 8-byte big-endian f64
   - `0x01 Boolean` → 1 byte
   - `0x02 String` → u16 BE length + UTF-8 bytes (lossy to `String`)
   - `0x03 Object` → key/value pairs until `0x00 0x00 0x09` end marker
   - `0x08 ECMA Array` → u32 count (treat as hint, ignore) then object-style
     pairs until end marker
   - `0x09 ObjectEnd` marker
   - `0x0A StrictArray` → u32 count + values
   - `0x0B Date` → f64 + i16 (skip)
   - `0x0C LongString` → u32 length + bytes (lossy)
   - Any other marker → return a `Skip`/`Unknown` value; do not panic.
2. `fn parse_on_metadata(body: &[u8]) -> Option<StreamMetadata>`:
   - Expect first value = string `"onMetaData"`.
   - Second value = ECMA array (or object) of properties.
   - Walk pairs, capture `videoWidth`, `videoHeight` (Number → u32, clamp
     negatives to 0), `videoFps` (Number → f32). Ignore everything else.
   - Return `None` if the first string isn't `"onMetaData"` or the body is
     malformed.
3. `struct StreamMetadata { width: Option<u32>, height: Option<u32>,
   fps: Option<f32> }`.
4. `fn is_metadata_tag(body: &[u8]) -> bool` — cheap peek: does the body begin
   with the AMF0 string marker for `"onMetaData"`? Used by the pipeline to
   decide whether to parse vs. skip.

## Validation (automated) — `tests/amf.rs`

- Hand-encode an `onMetaData` body: `0x02` + u16(11) + `"onMetaData"` +
   `0x08` + u32(3) + (key `"videoWidth"` `0x02...`, `0x00`, 8-byte f64
   `1920.0`) + (`"videoHeight"`, `1080.0`) + (`"videoFps"`,
   `30.0`) + end marker `0x00 0x00 0x09` → `Some(StreamMetadata{
   width:Some(1920), height:Some(1080), fps:Some(30.0)})`.
- Missing fields: omit `videoFps` → `fps: None`, others still present.
- Wrong first string (`"onMpma"`) → `None`.
- Truncated body mid-number → `None` (no panic).
- Body with an unknown AMF0 marker (e.g. `0x0D`) as a value → parser skips
   safely, returns the fields it could read, doesn't panic.
- A body that is just the `onClockSync` string + garbage → `None`.

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

- Do not implement full AMF0 round-tripping/serialization. Read-only, minimal.
- Do not yet wire this into the FLV pipeline; that happens when stream state
   (step 08) consumes metadata.
