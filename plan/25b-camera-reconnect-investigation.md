# Step 25b — Investigate and Resolve the ~7-10s Camera Reconnect Cycle

**Depends on:** Step 21 (Protect controller + 7550 upflv pipeline), Step 24 (ONVIF end-to-end). **Type:** Investigation + fix.

## Goal

The camera (Ubiquiti UVC G5 Bullet) connects to the proxy's 7442 AVClient WebSocket, completes the adoption handshake, pushes FLV video on 7550, then tears down both connections every ~7-10 seconds and immediately reconnects. Video flows (2 keyframes + ~270 interframes per cycle), ONVIF/RTSP works, and `StreamState` persists across reconnects — but the cycle is a stability and log-noise problem. This step resolves it so the 7442 session stays alive indefinitely.

## Symptoms

- 7442 TLS WebSocket connects, completes `timeSync` × ~10 + `hello` + `paramAgreement` + `ChangeVideoSettings`, then the camera sends a TCP RST (or WS Close) after ~7-10s.
- 7550 FLV stream connects as a downstream of the 7442 adoption epoch; when 7442 tears down, 7550 tears down too.
- The camera immediately redials 7442 (reconnect gap < 50ms), restarting the cycle.
- `flvproxy.log` shows `7442 avclient connected` / `7442 avclient disconnected: ... connection reset` / `camera connected from` / `camera disconnected` pairs every ~9s.

## What has already been tried (do NOT repeat)

All of these were implemented, tested against the real camera, and **failed** to stop the reconnect cycle:

1. **`GetSystemStats` heartbeat** — sent a controller→camera `GetSystemStats` AVClient message every 3s. Camera replied with CPU/memory stats but still reset at ~7s.
2. **WS Ping heartbeat** — flipped `paramAgreement` to `useHeartbeats: true` and sent WS Ping control frames (`ping-N`) every 3s. Camera replied with `pong-N` but still reset at ~7s.
3. **`ubnt_avclient_time` heartbeat** — sent a controller→camera `ubnt_avclient_time` AVClient message (the keshavdv camera emulator handles this). Camera replied with `{monotonicMs, wallMs, features}` but still reset.
4. **`ubnt_avclient_timeSync` heartbeat** — sent a controller→camera `ubnt_avclient_timeSync` (the redalert baseline registers a handler for this). Still reset.
5. **Full adoption sequence (7 messages)** — added `ChangeDeviceSettings`, `ChangeOsdSettings`, `NetworkStatus`, `ChangeSoundLedSettings`, `ChangeIspSettings` after `paramAgreement` + `ChangeVideoSettings`. Camera replied to all 7 (with `statusCode: 1` on `ChangeDeviceSettings`, likely a rejection of our `name` value). Still reset.
6. **Sequential adoption** — restructured the adoption driver to send messages one at a time, waiting for each camera ack before sending the next (instead of blasting all at once). Still reset.
7. **WS Pong control frame** — added a standard WS Pong (opcode 0xA) in addition to the Text `pong-0` reply for the camera's `ping-0`. Still reset.

## Current state of the code

- `useHeartbeats: false` (reverted to redalert baseline value)
- Sequential adoption (`AdoptionState` enum: `WaitingForHello → WaitingForParamAgreementAck → WaitingForChangeVideoSettingsAck → Adopted`)
- Heartbeat: `ubnt_avclient_timeSync` every 2s via `RetryReader` (still in place but not solving the problem)
- The 5 extra adoption messages have been removed; only `paramAgreement` + `ChangeVideoSettings` are sent

## Why we are not running the Protect Docker container

The `dciancu/unifi-protect-unvr-docker-arm64` project runs a real UniFi Protect controller in Docker, but its `docker-compose.yml` requires `privileged: true`, `cap_add: [dac_read_search, sys_admin]`, `security_opt: [apparmor=unconfined, seccomp=unconfined]`, and `cgroup: host` — all because Protect runs systemd as PID 1 inside the container. These flags are unacceptable for running on a trusted host in the network. Additionally, the image is ARM64-only (no x86 Protect binaries exist), requiring either ARM64 hardware or extremely slow QEMU emulation.

## Next course of action: read the Protect source code

UniFi Protect is a Node.js application shipped as a `.deb` package. The JavaScript inside (even if minified/webpacked) is extractable and readable — string literals like `ubnt_avclient_time`, `heartbeatsTimeoutMs`, `paramAgreement` are preserved. This is the ground truth we've been missing: instead of guessing what the real controller sends, we read the actual source.

### Steps

1. Download the latest Protect `.deb` from Ubiquiti's public firmware CDN (no authentication, no Docker, no privileges):
   ```
   wget -O /tmp/unifi-protect.deb "https://fw-download.ubnt.com/data/unifi-protect/eafa-uos-deb11-arm64-7.1.77-ff61d0b8-a9a9-4be0-a8cf-951d6d9af811.deb"
   ```

2. Extract the `.deb` (it's `ar` + `tar.gz`):
   ```
   cd /tmp && ar x unifi-protect.deb && tar xzf data.tar.gz
   ```
   The Protect JavaScript lives under `/tmp/usr/share/unifi-protect/`.

3. Search the extracted JavaScript for the 7442 protocol implementation. Specifically grep for:
   - `ubnt_avclient_time` and `ubnt_avclient_timeSync` — which one does the controller send periodically? Is there a timer/interval?
   - `heartbeatsTimeoutMs` — what does the camera actually do with this field? Is it a watchdog, or just config the controller acknowledges?
   - `paramAgreement` — what fields does the real payload carry that ours doesn't?
   - `ChangeVideoSettings` — what does the real payload look like? Is our minimal `{video: {video1: {avSerializer: {...}}}}` complete?
   - `ping` / `pong` / `heartbeat` / `keepalive` / `setInterval` / `setTimeout` — any periodic timer the controller runs.
   - `close` / `disconnect` / `reset` / `reconnect` — any session-lifetime limit or forced-close logic.

4. Compare findings against our `src/protect_controller.rs` and identify the divergence(s).

5. Implement the fix in `src/protect_controller.rs` (and `src/protect_listener.rs` if the heartbeat mechanism changes).

6. Update `tests/protect_controller.rs` to match any payload/behavior changes.

7. Run the full Quality Gate: `cargo build`, `cargo clippy --all-targets -- -D warnings`, `cargo test`, `cargo fmt --check`, `cargo build --release --target x86_64-pc-windows-gnu`.

8. Human test: restart the proxy on the Windows host, let it run for 60s, confirm no `7442 avclient disconnected` or `camera disconnected` lines after the initial adoption.

## Validation

This step passes when:

- The 7442 AVClient session stays alive indefinitely (no reconnect cycle) after the camera completes adoption.
- `flvproxy.log` shows one `7442 avclient connected` and one `camera connected from` with no subsequent disconnect lines during a 60s observation window.
- All Quality Gate checks are green.
- `DEBT.md` step-21 entry is updated to mark the reconnect issue resolved (or to document the remaining limitation if a full fix is not possible without a real controller capture).
