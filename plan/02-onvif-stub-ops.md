# 02 — ONVIF stub operations

## Goal

Implement the three ONVIF operations that currently return a SOAP Fault (`wsa:ActionNotSupported`) so a stricter NVR does not abort device-add: `GetSnapshotUri`, `GetAudioOutputConfigurations`, and `SetSynchronizationPoint`. Each returns a minimal, spec-shaped success response.

## Context

`onvif_server.rs` routes known actions via `KNOWN_ACTIONS` and `route()`; any Media op not matched falls through to `build_fault()` (`onvif_server.rs:145`). A lenient NVR (Onvier) tolerates the fault, but a strict one (Blue Iris, Synology Surveillance) may treat `ActionNotSupported` as a fatal device-incompatibility and refuse to add the camera. The three ops are cheap, well-defined stubs:

- `GetSnapshotUri` (Media) — returns a URI for a JPEG snapshot. The proxy does not produce snapshots, so it returns the RTSP stream URI with a `PT60S` timeout (the same shape `GetStreamUri` uses); an NVR that pulls it gets the RTSP stream, which is acceptable. Alternatively an empty `tt:Uri` with a clear "snapshot not supported" is fine — pick the RTSP-URI shape so a snapshot-polling NVR keeps streaming.
- `GetAudioOutputConfigurations` (Media) — returns an empty `Configurations` list (the proxy has no audio output), which is the spec-correct "none configured" answer.
- `SetSynchronizationPoint` (Device) — a no-op that returns success (`tt:SetSynchronizationPointResponse` is empty). ONVIF uses it to flush server-side state; the proxy has nothing to flush.

## Scope

In: three new action entries in `KNOWN_ACTIONS`; three match arms in `route()`; three small response builders; unit tests for each response shape.

Out: actually implementing snapshot JPEG capture; audio output; any state-flushing behaviour. The stubs are deliberately empty/echoing success — that is the production answer, not a placeholder.

## Approach

1. Add to `KNOWN_ACTIONS` (`onvif_server.rs:89`): `("http://www.onvif.org/ver10/media/wsdl/GetSnapshotUri", Service::Media, "GetSnapshotUri")`, `("http://www.onvif.org/ver10/media/wsdl/GetAudioOutputConfigurations", Service::Media, "GetAudioOutputConfigurations")`, `("http://www.onvif.org/ver10/device/wsdl/SetSynchronizationPoint", Service::Device, "SetSynchronizationPoint")`.
2. In the `Service::Media` match in `route()`, add arms: `"GetSnapshotUri" => (STATUS_OK, build_get_snapshot_uri(cfg))` and `"GetAudioOutputConfigurations" => (STATUS_OK, build_get_audio_output_configurations())`. In the `Service::Device` match, add `"SetSynchronizationPoint" => (STATUS_OK, build_set_synchronization_point())`.
3. Write three builders following the existing template style (`format!` with XML-escaped dynamic values where needed):
   - `build_get_snapshot_uri(cfg)`: a `GetSnapshotUriResponse` wrapping a `tt:Uri` set to `rtsp://<server_ip>:<rtsp_port>/stream` and a `tt:Timeout` of `PT60S`. Reuse `STREAM_URI_TIMEOUT` and the stream-URI formatting already in `build_get_stream_uri`.
   - `build_get_audio_output_configurations()`: a `GetAudioOutputConfigurationsResponse` with an empty `Configurations` element (no `AudioOutputConfiguration` children).
   - `build_set_synchronization_point()`: an empty `SetSynchronizationPointResponse`.
4. Verify each response's SOAP 1.2 envelope shape against the ONVIF Core Spec section for that op (the body element local name matches the op + `Response`, namespaces match `NS_MEDIA`/`NS_DEVICE`/`NS_SCHEMA`). Keep the envelope wrapper consistent with existing builders — factor a shared envelope helper only if one already exists; otherwise inline as the other builders do.
5. Update the module doc comment (`onvif_server.rs:1`) to list the three new ops among the served operations.

## Test

Add three tests in the `#[cfg(test)]` module asserting each builder's output contains the right action/body element and (for `GetSnapshotUri`) the escaped RTSP URI. Add a `route()` test that a request whose `SOAPAction` is the `GetSnapshotUri` URI returns `200` (not a fault) and contains `GetSnapshotUriResponse`.

## Files

- `src/onvif_server.rs` — `KNOWN_ACTIONS`, `route()`, three builders, module doc, tests.

## Acceptance

- All three ops return `200` with a well-formed success body, not a fault.
- Existing `route()` tests still pass; the fault path still fires for genuinely unknown ops.
- Host build, clippy `-D warnings`, `cargo test`, and `cargo build --target x86_64-pc-windows-gnu` green.

## Notes

- This step and step 04 both touch `onvif_server.rs`. Do them in sequence (either order); the touched regions (action table/builders vs `GetDeviceInformation`/`OnvifConfig`) do not overlap.
