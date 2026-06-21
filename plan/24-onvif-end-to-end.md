# Step 24 — ONVIF End-to-End Wiring

**Depends on:** Steps 15, 22, 23.

## Goal

Wire the ONVIF HTTP server (14) and WS-Discovery (15) into the running process alongside the camera listener and RTSP server. `GetStreamUri` returns the live RTSP URL; discovery advertises it. Very little new code — integration + a human check with a real ONVIF client.

## Tasks

1. In `console_main()` (and the service body in step 27), alongside the camera/RTSP threads, spawn:
   - `OnvifServer` on `onvif_port`, sharing `StreamState` (for `GetProfiles` resolution/fps) + `OnvifConfig { server_ip, rtsp_port, onvif_port, ... }`.
   - `Discovery { xaddr: format!("http://{server_ip}:{onvif_port}/onvif/device_service"), ... }`.
2. Make sure `server_ip` (from step 15's `local_ip_v4()`) is used consistently across SDP, ONVIF XAddrs, and `GetStreamUri`. Add a startup log line listing all four endpoints.
3. Regression test: extend the step-13 wiring test to also bring up the ONVIF HTTP server on an ephemeral port and assert:
   - `GetStreamUri` returns `rtsp://<server_ip>:<rtsp_port>/stream`.
   - `GetCapabilities` XAddrs match the bound port.
4. Optional: gate WS-Discovery behind the `onvif_discovery` config flag (step
   01) — if false, don't spawn the `Discovery` thread.
## Validation (automated) — extend `tests/wiring.rs`

- Full-stack in-process test (no real camera): mock producer feeding `StreamState`; bring up `CameraListener` (ephemeral), `RtspServer` (ephemeral), `OnvifServer` (ephemeral). As an HTTP client, POST `GetStreamUri` → assert returned URI == `rtsp://<server_ip>:<rtsp_port>/stream`. Then as an RTSP client, `DESCRIBE` that URI → assert 200 + SDP. (No real ONVIF client used.)
- Config flag: with `onvif_discovery = false`, the discovery thread is not started (assert via a counter or by attempting a Probe and expecting no reply within a short timeout — keep this test lenient/flaky-tolerant or skip on CI).

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

This step ends the ONVIF cluster — after it (and human test 3) passes, run the **step 25 cluster review** before moving to step 26.

## Debt notes

If anything was deferred (a workaround, a "good enough for now", an unclear decision), append a line to `DEBT.md` at the repo root (create the file if absent — see `plan/README.md` for the format):

`step NN | <file>:<area> | <what> | <FIX NOW | TRIGGER: ...>`

- `FIX NOW` items must be resolved before the next dedicated review (`07` / `13` / `24` / `27`).
- `TRIGGER:` items must name the concrete future event that forces revisiting them.
- No silent hacks: if you hacked it, log it. If you can fix it now, fix it now and don't log it.

## 🛑 STOP AND HUMAN TEST 3 — ONVIF Device Manager / NVR discovery

**Setup:**
1. Build release; run `flvproxy.exe --console` on the proxy host (Windows, since ONVIF Device Manager is Windows software).
2. Camera connected and RTSP already verified (HUMAN TEST 2 pass state).
3. On a Windows machine on the same LAN, open **ONVIF Device Manager** (or your NVR's "Add ONVIF device" flow).

**Pass criteria (all must be true):**
- ODM's discovery view lists the device within ~10 seconds (manufacturer "Ubiquiti", model "UVC-G5-Bullet").
- Clicking it → `GetCapabilities` and `GetDeviceInformation` succeed; firmware and serial populate.
- The device shows one media profile (`Profile_1`) with H.264.
- `GetStreamUri` returns `rtsp://<proxy_ip>:8554/stream`; ODM's live-view pane shows the same video VLC showed in HUMAN TEST 2.
- Adding the device to a real NVR (e.g. Blue Iris / Shinobi / Synology Surveillance) succeeds and pulls a live feed. (Pick whichever NVR you have; this is the actual integration goal.)

**If it fails (common culprits):**
- Not discovered → multicast `Hello` not sent, or Windows firewall blocking UDP 3702, or `d:Scopes` missing the `onvif://www.onvif.org/Profile/Streaming` scope (some clients filter on it).
- Discovered but `GetCapabilities` fails → XAddrs point at wrong IP/port, or the HTTP server bound to `0.0.0.0` but XAddrs advertise `127.0.0.1`.
- `GetStreamUri` returns a URL the NVR can't open → wrong `server_ip` (e.g. loopback). Verify `local_ip_v4()`.
- Live view in ODM shows nothing but VLC worked → ONVIF profile resolution/ fps mismatch, or `GetProfiles` returned an incomplete `VideoEncoderConfiguration`.

**Expected duration:** ~10 minutes.
