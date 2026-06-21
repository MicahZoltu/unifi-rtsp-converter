# Step 03 — FLV Tag Framing State Machine

**Depends on:** Step 02.

## Goal

A push-based, incremental state machine that consumes an arbitrary byte buffer and emits high-level tag events. It must handle partial data (the parser is fed in chunks as bytes arrive from TCP) and never panic on truncation.

## Tasks — `src/flv_parser.rs` (extend)

1. Enum of parser states:
   ```
   ReadingPrevTagSize   // 4 bytes (ignored)
   ReadingTagHeader     // 11 bytes
   ReadingTagBody       // data_size bytes
   ```
   (Header parsing from step 02 happens once up-front; the SM below runs after.)
2. `enum TagEvent`:
   - `Script { timestamp_ms: u32, body: Vec<u8> }`      // type 0x12
   - `Audio { timestamp_ms: u32, body: Vec<u8> }`       // type 0x08
   - `Video { timestamp_ms: u32, body: Vec<u8> }`       // type 0x09
   - `Unknown { tag_type: u8, timestamp_ms: u32, body: Vec<u8> }`
3. `struct FlvParser { state, buf: Vec<u8>, ... }` with:
   - `FlvParser::new()` starts in `ReadingPrevTagSize` (caller runs `parse_header` first, then feeds remaining bytes here).
   - `fn push(&mut self, chunk: &[u8]) -> Vec<TagEvent>` — appends to internal buffer and drains as many complete tags as possible. Returns events in order. Partial trailing bytes stay buffered for the next `push`.
4. Tag header decoding (11 bytes):
   - byte 0 = tag type
   - bytes 1-3 = data size (big-endian u24)
   - bytes 4-6 = timestamp low 24
   - byte 7 = timestamp extended (high 8) → combine to u32
   - bytes 8-10 = stream id (ignored)
5. After `ReadingTagBody`, emit the appropriate `TagEvent` and return to `ReadingPrevTagSize`. The 4-byte prev-tag-size is read and discarded.
6. Defensive limits: reject a tag whose `data_size` exceeds a sane cap (e.g. 32 MiB) → emit a recoverable error event or return an `Err` variant so the caller (step 26) can resync. Pick one shape and test it.

## Validation (automated) — `tests/flv_tag_sm.rs`

- Build a synthetic stream of 2 tags (one script `0x12`, one video `0x09`) with known payloads. Feed it in **one** `push` → expect exactly 2 events with correct types, timestamps, and bodies.
- Feed the same stream **byte-by-byte** (256 pushes) → same 2 events emitted at the same logical points (events may arrive across pushes; collect all).
- Feed it split at every possible boundary (lengths 0..N) → final collected events identical to the one-shot case. (Parametric loop test.)
- Timestamp rollover: a tag with timestamp low=0xFFFFFF, ext=0x00 followed by one with low=0x000000, ext=0x01 → second timestamp == 0x01000000.
- Oversized data_size (> cap) → returns the agreed error/None and does not allocate 4 GiB.
- Empty payload (data_size = 0) → emits an event with empty body, then correctly consumes the following prev-tag-size.

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

- Do not parse video/audio/script *payloads* yet (steps 04-06). The bodies are opaque `Vec<u8>` at this stage.
