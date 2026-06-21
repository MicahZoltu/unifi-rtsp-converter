# Step 26 — Error Handling, Resync, Reconnection, Never-Crash

**Depends on:** Steps 14, 15.

## Goal

Harden the data path so the proxy survives real-world ugliness: camera disconnects/reconnects, mid-stream garbage, oversized tags, partial writes, and rogue RTSP clients. Add a deterministic **resync scan** to the FLV parser and guarantee the camera thread never panics or blocks.

## Tasks

1. **Resync scan** in `src/flv_parser.rs`:
   - When the tag state machine hits an impossible state (data_size beyond cap, or a tag type not in `{0x08,0x09,0x12}` at the expected position), expose `FlvParser::resync() -> Option<usize>` that scans the buffered bytes for the next plausible tag boundary: a byte in `{0x08,0x09,0x12}` followed by 10 bytes that look like a sane tag header (data size ≤ cap, stream id == 0). Reset state to `ReadingTagBody` at that offset.
   - The camera listener (step 14) calls `resync()` on parse error, logs a `WARN` with the number of bytes skipped, and continues. **Never panics.**
2. **Camera thread safety net:** wrap the entire per-connection loop in a `catch_unwind`-equivalent (or simply ensure every `?`/`Result` is logged and the loop continues). On any unexpected error, log `ERROR`, close the current connection, and keep the listener bound.
3. **Reconnect backoff:** when the camera disconnects, the listener immediately returns to `accept` (no sleep needed — it's an inbound listener). Add a startup log line per connection with a monotonic connection counter so flapping is visible in the log.
4. **RTSP client cleanup:** step 12 already removes dead clients; add an idle-timeout (e.g. 30s with no traffic / no KEEP-ALIVE) that tears down a session whose RTSP socket is closed. Log `INFO` on teardown. The reaper must **not** kill a `playing` session that is silent on the RTSP control channel — RTP is one-way, so a healthy streaming client sends nothing on the control socket after `PLAY`. Gate reaping on sessions not in `playing` state, and decide separately whether to use RTCP receiver-report arrival as the keepalive signal for `playing` sessions. The advertised `SESSION_TIMEOUT_SECS` (60, already sent in SETUP `Session:` headers) is the value the reaper must honor — keep the advertisement and the enforcement in agreement.
5. **Backpressure:** re-affirm (and add an explicit test) that a saturated RTSP client cannot stall the camera thread — `try_send` drops the client, the camera thread's `publish_frame` returns in bounded time.
6. **Resource caps:** limit max concurrent RTSP clients (e.g. 32); reject beyond that with `503`. Limit the per-connection read buffer to a sane max (e.g. 4 MiB) to prevent a malicious client from exhausting memory.

## Validation (automated) — `tests/resync.rs`, `tests/robustness.rs`

- Resync: build a clean tag sequence, then inject 5 garbage bytes at a tag boundary, then a valid tag. After the parse error, the parser's `resync` finds the next valid tag and emits it correctly. Assert the emitted event payload matches and the log would show skipped bytes (test via a callback or by checking `resync()`'s returned offset).
- Resync not finding a valid boundary (pure garbage) → returns `None`, no panic, parser state remains recoverable once more bytes arrive.
- Camera thread survival: a test TCP sender writes a valid header+config, then abruptly closes the socket mid-tag → camera listener logs, returns to `accept`, no panic; a second connection immediately works.
- Oversized tag: a tag header claiming data_size = 50,000,000 → parser returns the agreed error without allocating; listener calls `resync` and continues from the next plausible boundary (or drops the connection — pick one, test it).
- Backpressure: 1 slow RTSP consumer (channel cap N), camera publishes 5×N frames rapidly → camera thread's `publish_frame` returns within a small bounded time (assert < 50ms); the slow client is dropped.
- Max-clients cap: open 33 RTSP connections; the 33rd gets `503`. Earlier clients unaffected.
- Malformed RTSP request (e.g. `GARBAGE\r\n\r\n`) → server responds `400` and keeps the connection (or closes cleanly); no panic; next valid request on a new connection works.
- Partial RTSP request then disconnect → no leaked thread, no panic (best effort: assert client count returns to baseline within 2s).

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

- Don't add retry logic for *outbound* connections (we don't make any). Don't implement RTCP-based congestion control. Keep it simple and bulletproof.
