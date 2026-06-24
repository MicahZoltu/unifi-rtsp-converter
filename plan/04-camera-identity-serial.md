# 04 — Camera identity → ONVIF serial

## Goal

Replace the placeholder serial `000000000000` advertised by ONVIF `GetDeviceInformation` with the real per-camera identifier the proxy already extracts from the 7442 Protect upgrade headers (`Camera-MAC`). This closes the most visible interop wart in `GetDeviceInformation` without needing a new camera capture. Firmware stays as an overridable config default (the camera's real firmware is not available from any current channel).

## Context

`protect_listener.rs:203-204` extracts `Device-ID` and `Camera-MAC` from the 7442 WebSocket upgrade request, upper-cases the MAC and strips colons, and uses it to build the `streamName` — then discards it. `OnvifConfig::defaults_for` (`onvif_server.rs:124`) builds the ONVIF config once at `App::spawn` time with `DEFAULT_SERIAL` (`000000000000`), so ONVIF never sees the camera's real identifier. The cleanest vehicle to carry the MAC from the camera pipeline to the ONVIF server is the already-shared `StreamState` hub (`stream_state.rs`), which `CameraListener`/`ProtectListener` publish to and `OnvifServer` already reads (`snapshot_metadata`).

## Scope

In: a small camera-identity field on `StreamState` (MAC-derived serial + optionally model), published by the 7550/7442 pipeline when a connection establishes, read by `GetDeviceInformation` when answering. The `OnvifConfig` `serial` becomes the fallback used until a camera publishes its identity.

Out: learning the real firmware (no channel exists; stays defaulted and overridable via `flvproxy.ini`); learning the real hardware serial (the MAC is the best available proxy and is what UniFi cameras present as their identifier); any change to `Device-ID` usage; per-camera model detection (stays the configured/default `MODEL`).

## Approach

1. Add a `CameraIdentity` struct to `stream_state.rs`: `{ serial: String, model: String }` (model included so the pipeline can override the default model later if a capture reveals it; for now only `serial` is populated). Add `camera_identity: Option<CameraIdentity>` to `StreamStateInner`. Add `StreamState::publish_camera_identity(&self, id: CameraIdentity)` and `StreamState::camera_identity(&self) -> Option<CameraIdentity>`, mirroring `publish_config`/`codec`. Poison-recovery via the existing `lock_hub` helper applies.
2. In the 7550 pipeline (`camera_listener.rs` — the plain-TCP test ingress on Linux and the Windows 7550 path), there is no MAC header available, so do not publish there. In the Windows 7442 path (`protect_listener.rs`), after extracting `camera_mac` (already computed at line 204), publish a `CameraIdentity` with `serial = camera_mac` (the colon-stripped uppercased MAC is a reasonable ONVIF serial — UniFi cameras present their MAC as the serial) onto the shared `StreamState`. This requires `ProtectListener` to hold a `StreamState` clone; check whether it already does — if not, thread one through (it is cheap, one `Arc`). Use the MAC unchanged as the serial; do not prefix or format it.
3. In `onvif_server.rs`, `build_get_device_information` currently reads `cfg.serial`. Change `route()`'s `GetDeviceInformation` arm to prefer the live camera identity: `build_get_device_information(cfg, state)`, where the builder uses `state.camera_identity().map(|i| i.serial).unwrap_or_else(|| cfg.serial.clone())` for the serial, and `state.camera_identity().map(|i| i.model).filter(|m| !m.is_empty()).unwrap_or(MODEL)` for the model. Keep `cfg.firmware` as-is. `OnvifConfig::serial` remains the operator override fallback (set via `firmware`/`serial` ini keys — note: today the ini has no `serial` key; see below).
4. Config: the ini currently has `firmware`/`serial`? Check `config.rs` `apply_pair` — it has neither. Add `firmware` and `serial` keys to `Config` and `apply_pair` so an operator can override the advertised firmware and the serial *fallback*. Defaults: `firmware = DEFAULT_FIRMWARE`, `serial = DEFAULT_SERIAL`. Wire these into `OnvifConfig::defaults_for` (the `firmware`/`serial` fields already exist on `OnvifConfig`; just populate them from config instead of the const defaults). Add a `controller_*`-style test for the two new keys.
5. Update doc comments: `onvif_server.rs:57-61` (the `DEFAULT_FIRMWARE`/`DEFAULT_SERIAL` comments that say "tracked in `DEBT.md`") and the `OnvifConfig` field docs to describe the live-identity-preferred, config-fallback behaviour. Remove the "tracked in `DEBT.md`" phrasing (DEBT.md is being deleted in step 10).

## Test

- `stream_state.rs`: add a test that `publish_camera_identity` then `camera_identity()` round-trips, and that a fresh hub returns `None`.
- `onvif_server.rs`: add a `route()` test where `state` has a published `CameraIdentity { serial: "28704E11B531", model: "" }` and assert `GetDeviceInformation`'s response contains `28704E11B531` (not `000000000000`) and the default model. Add a second test with no published identity asserting the `cfg.serial` fallback is used.
- `config.rs`: add a test that `firmware`/`serial` ini keys parse.

## Files

- `src/stream_state.rs` — `CameraIdentity`, hub field, publish/read methods, test.
- `src/protect_listener.rs` — publish identity after MAC extraction (Windows path).
- `src/onvif_server.rs` — `build_get_device_information` signature/behaviour, `route()` arm, doc comments.
- `src/config.rs` — `firmware`/`serial` fields, `apply_pair`, defaults, test.
- `src/app.rs` — thread `firmware`/`serial` from `Config` into `OnvifConfig::defaults_for` (or extend `defaults_for` to accept them).

## Acceptance

- With a camera connected on Windows, `GetDeviceInformation` returns the camera's MAC-derived serial instead of `000000000000`.
- With no camera connected (or on Linux with the plain-TCP path), the configured/default serial fallback is returned.
- `firmware`/`serial` ini overrides take effect as the fallback.
- Host build, clippy `-D warnings`, `cargo test`, and `cargo build --target x86_64-pc-windows-gnu` green.

## Notes

- If `ProtectListener` does not currently hold a `StreamState`, threading one in is the bulk of the change — budget for it. The `CameraListener` (7550) already holds one; the 7442 listener is separate.
- Do not block ONVIF responses on the lock: `camera_identity()` clones under the lock and returns, same as `snapshot_metadata`.
- The model override path is left wired but unused (publishes `model: ""`); a future capture can populate it. This is not a deferred-debt marker — it is a struct field with a sensible default, and the comment should say so without `TODO`.
