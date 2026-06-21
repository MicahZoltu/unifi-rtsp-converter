# Step 11 — RTSP Protocol: Request Parser + Response Builder

**Depends on:** Step 10.

## Goal

Pure text-protocol logic: parse an RTSP request from a byte buffer, and build RTSP responses. Implement the five methods (OPTIONS, DESCRIBE, SETUP, PLAY, TEARDOWN) and transport negotiation (TCP interleaved vs UDP). No sockets yet — that's step 12.

## Tasks — `src/rtsp_server.rs` (protocol half)

1. `struct RtspRequest { method: Method, uri: String, cseq: Option<u32>, session: Option<String>, transport: Option<String>, accept: Option<String>, range: Option<String>, body: Vec<u8> }` and `enum Method { Options, Describe, Setup, Play, Teardown, Other(String) }`.
2. `fn parse_request(buf: &[u8]) -> Result<Option<(RtspRequest, usize)>, RtspError>`:
   - Returns `Ok(None)` if the buffer doesn't yet contain a complete request (no `\r\n\r\n` terminator, or `Content-Length` body not fully received).
   - Returns `Ok(Some((req, consumed_bytes)))` on success.
   - Tolerant header parsing: case-insensitive header names, ignore unknown headers, missing CSeq is allowed (response still echoes `None`? — no: per spec CSeq is mandatory; treat missing as a `400 Bad Request` later, but parse without erroring).
3. `struct RtspResponse { status: u16, status_text: String, cseq: Option<u32>, session: Option<String>, headers: Vec<(String,String)>, body: Vec<u8> }` with `fn to_bytes(&self) -> Vec<u8>` producing canonical wire format.
4. Method handlers as pure functions taking `(request, session_state_ref) -> RtspResponse` (the session/transport state is a small owned struct passed in/out — keep handlers pure & testable):
   - `handle_options` → `200 OK`, `Public: OPTIONS, DESCRIBE, SETUP, PLAY, TEARDOWN`.
   - `handle_describe` → builds SDP via step 10; `Content-Type: application/sdp`; `Content-Length` set. If no codec params yet → `503 Service Unavailable` (camera not connected).
   - `handle_setup` → parse `Transport:` header:
     - `RTP/AVP/TCP;unicast;interleaved=A-B` → choose TCP, echo `Transport: RTP/AVP/TCP;unicast;interleaved=A-B`, allocate session id, remember interleaved channels.
     - `RTP/AVP;unicast;client_port=X-Y` → choose UDP, echo `Transport: RTP/AVP;unicast;client_port=X-Y;server_port=P-Q` (P/Q are the server's chosen RTP/RTCP ports — for now pick a fixed pair from a counter; actual UDP sockets are step 12).
     - Otherwise → `461 Unsupported transport`.
     - Always set `Session: <id>;timeout=60`.
   - `handle_play` → requires existing session; `200 OK`, `Range: npt=0.000-`, `Session:` echoed. Marks the session as "playing".
   - `handle_teardown` → `200 OK`, session ended.
5. A small `RtspSession { id: String, transport: Transport, playing: bool }` and `enum Transport { Interleaved { rtp_ch: u8, rtcp_ch: u8 }, Udp { client_rtp: u16, client_rtcp: u16, server_rtp: u16, server_rtcp: u16 } }`.

## Validation (automated) — `tests/rtsp_protocol.rs`

- Parse a complete `OPTIONS` request (with CSeq) → method, cseq, uri correct, `consumed_bytes` == buffer length.
- Parse a request **without** the terminating `\r\n\r\n` → `Ok(None)` (needs more data).
- Parse `DESCRIBE` with `Accept: application/sdp` → `accept` populated.
- Parse `SETUP` with TCP interleaved transport → `transport` string captured; `handle_setup` returns `200`, `Session:` present, echoed `Transport` contains `interleaved=0-1`, and the produced `RtspSession.transport` is `Interleaved{0,1}`.
- Parse `SETUP` with UDP `client_port=4588-4589` → response `Transport` contains `server_port=` and `client_port=4588-4589`.
- Bogus transport (no `interleaved=` and no `client_port=`) → `461`.
- `PLAY` on a known session id → `200`, `Range: npt=0.000-`, session echoed.
- `PLAY` with unknown/missing session → `454 Session not found`.
- `TEARDOWN` → `200`; subsequent `PLAY` on same id → `454`.
- Response serialization: build a known response, call `to_bytes()`, assert the exact byte string (including `\r\n` line endings and trailing `\r\n`).
- DESCRIBE before any codec published → `503`.

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

- No sockets, no threads, no real RTP sending. The session "playing" flag is just a flag here; the RTP pump lands in step 12.
