# Step 07 — Stream State, Ring Buffer, and Client Registry

**Depends on:** Steps 04, 05, 06.

## Goal

The shared in-memory hub that the camera pipeline writes to and RTSP clients
read from. Pure concurrency logic — `Arc<Mutex<_>>` + `mpsc` — fully testable
with synthetic frames, no network.

## Tasks — `src/stream_state.rs`

1. `struct Frame { is_keyframe: bool, timestamp_ms: u32, nalus: Vec<Vec<u8>> }`
   (NALUs without start code or length prefix — matches step 04's `NaluFrame`
    plus a timestamp).
2. `struct CodecParams { sps: Vec<u8>, pps: Vec<u8>, profile_indication: u8,
   profile_compat: u8, level_indication: u8, width: Option<u32>,
   height: Option<u32>, fps: Option<f32> }`.
3. `struct StreamState` (the shared hub), behind `Arc<Mutex<StreamStateInner>>`:
   - `codec: Option<CodecParams>` — updated when a `Config` event arrives.
   - `last_keyframe: Option<Frame>` — most recent keyframe (cheap "GOP of 1"
     cache; enough for new clients to start decoding).
   - `clients: Vec<ClientHandle>` where each `ClientHandle` owns an
     `mpsc::Sender<Frame>` (bounded, e.g. capacity 64) and a session id.
4. `StreamState::publish_frame(frame: Frame)`:
   - If `is_keyframe`, store in `last_keyframe`.
   - For each client, `try_send` the frame; if the channel is full or
     disconnected, **drop the client** (remove from `clients`) and log — never
     block the camera thread.
5. `StreamState::publish_config(config: CodecParams)` — replace `codec`.
6. `StreamState::add_client() -> (ClientId, mpsc::Receiver<Frame>)`:
   - Register a new client with a fresh bounded channel.
   - If `last_keyframe` is present, immediately `try_send` it on the new
     channel so the client has an instant decode point. (SPS/PPS are sent
     separately by the RTSP layer via SDP; do not duplicate them here.)
7. `StreamState::remove_client(ClientId)`.
8. `StreamState::codec() -> Option<CodecParams>` (clone) — for SDP generation.
9. `StreamState::snapshot_metadata()` for ONVIF `GetProfiles`.

## Validation (automated) — `tests/stream_state.rs`

- Publish a `Config` then a keyframe + 3 inter frames; `add_client` *after*
   publishing → receiver yields the stored keyframe first (the 3 inter frames
   are gone, that's fine). Assert ordering and content.
- `add_client` *before* any frames → receiver yields frames in publish order.
- Two clients in parallel: publish 10 frames, both receive all 10 in order.
- Slow client: bounded channel cap N; publish N+5 frames rapidly → client
   receives the first N, the rest are dropped silently by `try_send`, and the
   client is **removed** once a send fails. Assert `clients.len()` drops.
   (Camera thread must never block — verify by timing the publish call returns
   promptly even with a dead consumer.)
- `remove_client` cleans up; subsequent `publish_frame` doesn't try to send to
   it (no panic, no leak).
- `last_keyframe` is overwritten by each new keyframe, not appended.
- `codec()` returns `None` before any `publish_config`, `Some` after.

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

- No networking. No RTP. No RTSP. The hub is transport-agnostic.
- Do not buffer an entire GOP — only `last_keyframe` is kept (sufficient for
  new-client bootstrapping; full GOP buffering is out of scope).
