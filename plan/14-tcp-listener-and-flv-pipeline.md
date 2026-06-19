# Step 14 — TCP Listener + FLV Pipeline (Camera Input)

**Depends on:** Steps 02, 03, 04, 05, 06, 08.

## Goal

Accept the camera's inbound TCP connection, feed bytes through the uPFLV/FLV/
AVC pipeline, and publish `Config`/`Frame`s into `StreamState`. This is the
first half of the real data path. The RTSP server (step 12) is already
consuming from `StreamState`, but here we *also* need it running — however, the
**camera** is a real external device, so the wiring tests use a synthetic TCP
sender that replays a hand-crafted extendedFlv byte stream.

## Tasks — `src/camera_listener.rs` (new module)

1. `struct CameraListener { state: Arc<Mutex<StreamStateInner>>,
   listen_port: u16, shutdown: Arc<AtomicBool> }`.
2. `CameraListener::run()`:
   - Bind `TcpListener` on `0.0.0.0:listen_port`.
   - Loop `accept`. Maintain `current: Option<TcpStream>`; if a new connection
     arrives while one is active, **close the old one** (per spec) and replace.
   - Per connection: read into a buffer in a loop; on the **first** read, run
     `detect_and_strip_prefix` on the accumulated bytes (only once per
     connection — track a `prefix_checked: bool`).
   - Then `parse_header` once; on success, create an `FlvParser` and feed the
     remaining bytes via `parser.push(chunk)`, collecting `TagEvent`s.
   - For each `Video` event: call the step-05 dispatcher → on `Config`,
     `state.publish_config(...)`; on `Frame`, `state.publish_frame(...)`.
   - For each `Script` event: if `is_metadata_tag`, parse via step 06 and merge
     width/height/fps into the current `CodecParams` (publish a refreshed
     `Config` with updated metadata, or a dedicated `publish_metadata` — pick
     one and test it).
   - `Audio` / `Unknown` events: ignore (log at debug/info).
   - On read error / EOF: log, drop the connection, keep the listener bound for
     a new camera connection. **Never panic.**
3. Logging hooks: log connection accepted/closed, SPS/PPS arrival (hex of first
   4 bytes), keyframe vs inter frame counts every N frames, parse errors.
4. Shutdown: `shutdown` flag stops the accept loop (use a non-blocking accept
   or a self-connect trick; simplest is `set_nonblocking(true)` + short sleep
   poll).

## Validation (automated) — `tests/camera_pipeline.rs`

All tests use an in-process `TcpListener` on an ephemeral port and a test
thread that opens a `TcpStream` to it and writes a **synthetic** extendedFlv
stream built by the test (no real camera).

- Build a synthetic stream: uPFLV prefix + FLV header + one script `onMetaData`
  tag (with width/height/fps) + one video seq-header tag (standard AVC config
  with SPS `[0x67,0x4D,0x40,0x1F,...]` + PPS) + one video keyframe NALU tag +
  one video inter NALU tag. Connect a test `TcpStream`, write the bytes, then
  assert via the shared `StreamState` that:
  - `codec()` returns `Some` with the right SPS/PPS and metadata width/height/fps.
  - A client registered via `add_client()` receives the keyframe then the inter
    frame in order.
- **No prefix** variant: same stream without the uPFLV prefix → still parses
  (step-02 tolerance), same assertions pass.
- **Extended path** variant: build the seq header and keyframe using
  ExVideoTagHeader (SequenceStart + CodedFramesX) → same assertions.
- **Reconnect** test: open conn A, write header+config, close A; open conn B,
  write a fresh header+config+frame. Assert the listener swapped connections
  without crashing and the new config is live.
- **Malformed mid-stream**: write a valid header+config, then garbage bytes
  that don't form a valid tag. Assert the listener logs a parse error, does
  **not** panic, and (best-effort) keeps the connection open. Full resync
   behavior is step 26; here just assert no panic.
- Read the log file produced during the test: assert it contains a line about
  SPS/PPS arrival and a line about the connection.

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

## 🛑 STOP AND HUMAN TEST 1 — Real camera → proxy → log

After the automated tests pass, do a quick manual smoke against a real camera.
This is the first time real hardware is involved; keep it tiny.

**Setup:**
1. Build: `cargo build --release --target x86_64-pc-windows-gnu` (on the Linux
   build host) — produces a self-contained `flvproxy.exe` needing nothing
   installed on the Windows host. Copy it to the Windows proxy machine.
2. Run in console mode: `flvproxy.exe --console` (the service wrapper isn't
   built yet; `--console` should run the listener + RTSP server directly — if
   `--console` isn't wired to actually start servers yet, wire a minimal
   `console_main()` that spawns `CameraListener::run` + `RtspServer::run` for
   this test).
3. Configure the camera to push to the proxy per `PROJECT.md` "Camera Setup":
   edit `/usr/etc/ubnt_streamer_sysid_a591.json` destinations to
   `tcp://<proxy_ip>:7550`, `killall ubnt_streamer`.

**Pass criteria (all must be true):**
- `flvproxy.log` shows a line "camera connected" from `127.x`/camera IP.
- Within ~5 seconds the log shows SPS/PPS arrival (e.g.
  `SPS received: profile=4D level=1F`).
- Frame counters increment (keyframes + inter frames) at roughly the camera's
  configured FPS.
- No panic / no crash over a 60-second soak.

**If it fails:** capture the first ~2 KB of raw bytes the camera sent (add a
temporary debug log that hex-dumps the first 256 bytes of a new connection),
save it, and use it to harden the parser. Do **not** proceed to step 15 until
the camera's stream parses cleanly for a full minute.

**Expected duration:** ~5 minutes once the camera is pointed at the proxy.
