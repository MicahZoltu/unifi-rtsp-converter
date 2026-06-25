//! Single-sourced default values shared across the proxy: the ONVIF device-information defaults (`firmware`/`serial`) and the AVClient controller-identity defaults (`controller_name`/`controller_uuid`/`controller_version`). Owned here so the dependency graph points downward — `config` (a leaf-ish module), `onvif_responses` (via `OnvifConfig::defaults_for`), and `protect_controller` each reference these from one place instead of `config` reaching up into two consumer modules for its `Default` impl (the prior shape, which left the leaf depending on the consumers and let two copies drift). The values themselves are unchanged; only the owning module moves.
//!
//! Consumers import these constants directly from this module (their owner) rather than through re-exports on `onvif_server` / `protect_controller`, so a reader of either consumer sees ownership honestly and the constants have one unambiguous path.

/// Default firmware version advertised by ONVIF `GetDeviceInformation` when the operator has not overridden it via `flvproxy.ini`. The camera's real firmware is not available from any current channel, so this sensible UVC G5 value is the fallback (config-overridable via the `firmware` ini key). Single-sourced here so `config`'s default references the same value rather than mirroring a copy that can drift.
pub const DEFAULT_FIRMWARE: &str = "4.73.112";

/// Default serial number advertised by ONVIF `GetDeviceInformation` when the operator has not overridden it and no camera identity has been published yet. Before the camera's first `onMetaData` tag (or on a stream that omits `streamName`) the live identity is absent, so this non-empty default keeps `GetDeviceInformation` well-formed (config-overridable via the `serial` ini key). Single-sourced here so `config`'s default references the same value rather than mirroring a copy that can drift.
pub const DEFAULT_SERIAL: &str = "000000000000";

/// Default controller name advertised in the AVClient `hello` reply when no override is configured. The real Protect controller sources this from the NVR record (`a.name`); this default gives the proxy a well-formed identity so the camera's adoption completes without operator configuration. Single-sourced here so `config`'s default references the same value rather than mirroring a copy that can drift.
pub const DEFAULT_CONTROLLER_NAME: &str = "UniFi Protect";

/// Default controller UUID advertised in the AVClient `hello` reply when no override is configured. A fixed valid RFC-4122 v4 UUID (the real controller generates a per-install `anonymousDeviceId`; a fixed default is fine because the camera stores it rather than validating uniqueness). Single-sourced here so `config`'s default references the same value rather than mirroring a copy that can drift.
pub const DEFAULT_CONTROLLER_UUID: &str = "716dd84e-a640-45d7-9c17-2b9b4b8a7000";

/// Default controller version advertised in the AVClient `hello` reply when no override is configured. Matches the Protect package version confirmed against the Protect 7.1.77 Node.js source. Single-sourced here so `config`'s default references the same value rather than mirroring a copy that can drift.
pub const DEFAULT_CONTROLLER_VERSION: &str = "7.1.77";
