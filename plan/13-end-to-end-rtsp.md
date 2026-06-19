# Step 13 — End-to-End RTSP (Real Camera → RTSP Client)

**Depends on:** Step 12 (camera pipeline verified against real hardware).

## Goal

The camera pipeline and the RTSP server now share the same `StreamState`
instance in one process. This step just **wires them together** in
`main`/`console_main` and verifies the full path with a real RTSP client.
There is very little new code; the work is integration + a quick human check.

## Tasks

1. In `console_main()` (and later the service body in step 18), construct a
   single `Arc<Mutex<StreamStateInner>>` and pass clones to:
   - `CameraListener { state, listen_port, ... }` (step 12)
   - `RtspServer { state, rtsp_port, server_ip, ... }` (step 11)
   - (ONVIF servers will attach in step 16.)
2. Determine `server_ip` for SDP/ONVIF URLs: pick the first non-loopback IPv4
   on the default interface. A tiny helper `local_ip_v4()` using
   `UdpSocket` "connect" to `8.8.8.8:80` then `local_addr()` is a crate-free
   trick — implement and unit-test it (assert it returns a non-loopback IPv4
   on a machine with a real interface; skip assertion if none).
3. Spawn each server on its own thread; main thread waits on a shutdown signal
   (Ctrl+C in console mode → set the shared `AtomicBool`).
4. Add a startup log line summarizing: `listening camera=:7550 rtsp=:8554
   onvif=:8080 ip=192.168.x.y`.
5. Smoke-check the RTSP server against a **loopback mock producer** one more
   time as a regression test now that wiring changed (reuse step 11's test
   harness).

## Validation (automated) — `tests/wiring.rs`

- `console_main`-equivalent helper that builds the shared `StreamState`,
  spawns `CameraListener` + `RtspServer` on ephemeral ports, feeds a synthetic
  extendedFlv stream via a test TCP sender, then acts as an RTSP client:
  `OPTIONS` → `DESCRIBE` (assert SDP non-empty, `sprop-parameter-sets`
  present) → `SETUP` interleaved → `PLAY` → receive ≥1 RTP packet → `TEARDOWN`.
  This is essentially a combined regression of steps 11+12; assert it still
  passes end-to-end in one process.
- `local_ip_v4()` returns `Some` non-loopback on the CI host (or `None`
  gracefully if no external interface — test must tolerate both).

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

## 🛑 STOP AND HUMAN TEST 2 — Real camera → VLC/ffprobe

**Setup:**
1. Build release; run `flvproxy.exe --console` on the proxy host.
2. Confirm camera is connected and frames are flowing (HUMAN TEST 1 pass
   state).
3. On another machine, open **VLC** → Media → Open Network Stream →
   `rtsp://<proxy_ip>:8554/stream` → Play.
4. Also run: `ffprobe -rtsp_transport tcp rtsp://<proxy_ip>:8554/stream` and
   `ffprobe -rtsp_transport udp rtsp://<proxy_ip>:8554/stream`.

**Pass criteria (all must be true):**
- VLC shows live video within ~5 seconds (a couple of seconds of latency is
  acceptable; it must be moving, not a frozen first frame).
- `ffprobe` (both TCP and UDP transports) reports a video stream: codec
  `h264`, a sane resolution (e.g. `1920x1080`), a sane fps, and
  `packets`/`duration` incrementing.
- Let it run 60 seconds; reconnect VLC mid-stream → new client gets a
  keyframe quickly and resumes video (verifies the `last_keyframe` bootstrap
  from step 07).
- Proxy log shows RTSP client connect/setup/play/teardown lines; no errors.

**If it fails (common culprits):**
- Frozen/black video → SPS/PPS wrong in SDP, or marker bit not set on last
  NALU (re-check step 08), or FU-A reassembly broken (a client like VLC will
  still decode single-NALU frames; large IDR slices failing points to FU-A).
- `ffprobe` TCP works but UDP doesn't → `server_port` in SETUP response and
  the actual `UdpSocket` bind mismatch, or firewall.
- No video at all → DESCRIBE returned 503 (camera not connected) or SDP
  malformed.

**Expected duration:** ~5 minutes.
